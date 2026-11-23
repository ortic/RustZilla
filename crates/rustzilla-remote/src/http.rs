//! HTTP for WebDAV and S3: blocking ureq on rustls with ring, its
//! certificates checked against the system's roots (or Mozilla's).

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use ureq::http::{Request, Response};
use ureq::tls::{RootCerts, TlsConfig, TlsProvider};
use ureq::{Agent, Body, SendBody};

use crate::error::{Error, ErrorKind};

pub(crate) fn agent() -> Agent {
    Agent::config_builder()
        .http_status_as_error(false)
        // PROPFIND, MKCOL, MOVE…
        .allow_non_standard_methods(true)
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_recv_response(Some(Duration::from_secs(60)))
        .timeout_recv_body(Some(Duration::from_secs(60)))
        .timeout_send_body(Some(Duration::from_secs(60)))
        // Redirects of WebDAV and S3 point elsewhere on purpose (another
        // region, a folder's trailing slash): the caller sees them.
        .max_redirects(0)
        .tls_config(
            TlsConfig::builder()
                .provider(TlsProvider::Rustls)
                .root_certs(roots())
                .build(),
        )
        .user_agent(concat!("RustZilla/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

/// The system's roots (they include company CAs), or Mozilla's where
/// there are none.
fn roots() -> RootCerts {
    static ROOTS: OnceLock<RootCerts> = OnceLock::new();
    ROOTS
        .get_or_init(|| {
            let certs: Vec<ureq::tls::Certificate<'static>> =
                rustls_native_certs::load_native_certs()
                    .certs
                    .iter()
                    .map(|cert| ureq::tls::Certificate::from_der(cert.as_ref()).to_owned())
                    .collect();
            if certs.is_empty() {
                RootCerts::WebPki
            } else {
                RootCerts::Specific(Arc::new(certs))
            }
        })
        .clone()
}

/// Whether a request failed because the connection dropped before the
/// answer: a server closing a kept-alive connection, or answering early
/// (a 401 before the body) and resetting. A repeatable request may be sent
/// again.
pub(crate) fn dropped(e: &ureq::Error) -> bool {
    matches!(e, ureq::Error::Io(_) | ureq::Error::ConnectionFailed)
}

/// Runs a request that can be sent twice (`make` builds it again), once
/// more if the connection dropped.
pub(crate) fn send_repeatable(
    agent: &Agent,
    server: &str,
    make: impl Fn() -> Result<Request<SendBody<'static>>, Error>,
) -> Result<Response<Body>, Error> {
    match agent.run(make()?) {
        Ok(response) => Ok(response),
        Err(e) if dropped(&e) => {
            tracing::debug!("{server}: {e}; sending the request again");
            agent.run(make()?).map_err(|e| network_error(server, &e))
        }
        Err(e) => Err(network_error(server, &e)),
    }
}

/// Runs a request; network failures say what couldn't be reached.
pub(crate) fn send(
    agent: &Agent,
    request: Request<SendBody<'_>>,
    server: &str,
) -> Result<Response<Body>, Error> {
    agent.run(request).map_err(|e| network_error(server, &e))
}

pub(crate) fn network_error(server: &str, e: &ureq::Error) -> Error {
    use ureq::Error as E;
    match e {
        E::HostNotFound => Error::new(format!("can't find {server}")),
        E::Tls(_) | E::Rustls(_) => Error::new(format!(
            "the TLS connection to {server} failed (is its certificate valid?): {e}"
        )),
        E::Timeout(_) | E::Io(_) | E::ConnectionFailed => Error::with_kind(
            format!("can't reach {server}: {e}"),
            ErrorKind::Disconnected,
        ),
        e => Error::new(format!("{server}: {e}")),
    }
}

/// The text of an error response, e.g. S3's `<Message>`.
pub(crate) fn error_text(response: &mut Response<Body>) -> String {
    let status = response.status();
    let body = response
        .body_mut()
        .with_config()
        .limit(64 * 1024)
        .read_to_string()
        .unwrap_or_default();
    let message = roxmltree::Document::parse(&body).ok().and_then(|doc| {
        doc.descendants()
            .find(|n| n.has_tag_name("Message") || n.has_tag_name("message"))
            .and_then(|n| n.text())
            .map(str::to_owned)
    });
    match (status.as_u16(), message) {
        (_, Some(message)) if !message.trim().is_empty() => message.trim().to_owned(),
        (401, _) => "the user name or password isn't accepted".into(),
        (403, _) => "access denied".into(),
        (404, _) => "not found".into(),
        (405, _) => "the server doesn't allow that here".into(),
        (409, _) => "the parent directory doesn't exist".into(),
        (507, _) => "the server is out of space".into(),
        (code, _) => format!(
            "the server answered {code} {}",
            status.canonical_reason().unwrap_or("")
        ),
    }
}
