//! TLS for FTPS: certificates are checked against the system's and
//! Mozilla's roots. One that doesn't pass (self-signed, an unknown issuer,
//! another name, expired) fails the connect with a [`Certificate`] the user
//! can trust, as SSH's host keys: its SHA-256 fingerprint goes to
//! RustZilla's trusted certificates, for that host and port.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use ring::digest::{SHA256, digest};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

use crate::error::Error;

/// A server certificate that isn't trusted yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub host: String,
    pub port: u16,
    /// SHA-256 of the certificate, as `AB:CD:…`.
    pub fingerprint: String,
    pub subject: String,
    pub issuer: String,
    pub valid_from: String,
    pub valid_until: String,
    /// Why it isn't trusted, in words.
    pub problem: String,
    trusted_file: PathBuf,
}

impl Certificate {
    /// Adds the certificate to RustZilla's trusted ones for its host.
    pub fn trust(&self) -> Result<(), Error> {
        let append = || -> std::io::Result<()> {
            if let Some(dir) = self.trusted_file.parent() {
                fs::create_dir_all(dir)?;
            }
            let mut text = fs::read_to_string(&self.trusted_file).unwrap_or_default();
            if !text.is_empty() && !text.ends_with('\n') {
                text.push('\n');
            }
            text.push_str(&format!(
                "{}:{} {}\n",
                self.host,
                self.port,
                self.fingerprint.replace(':', "").to_ascii_lowercase()
            ));
            fs::write(&self.trusted_file, text)
        };
        append().map_err(|e| {
            Error::new(format!(
                "saving the certificate in {}: {e}",
                self.trusted_file.display()
            ))
        })
    }
}

/// The fingerprints trusted for `host:port` in `file`.
fn trusted(file: &Path, host: &str, port: u16) -> Vec<String> {
    let key = format!("{host}:{port}");
    fs::read_to_string(file)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let (h, fp) = line.trim().split_once(' ')?;
            (h == key).then(|| fp.trim().to_owned())
        })
        .collect()
}

fn sha256_hex(der: &[u8]) -> String {
    digest(&SHA256, der)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn roots() -> Arc<RootCertStore> {
    static ROOTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    ROOTS
        .get_or_init(|| {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            // The system's too: company CAs.
            let native = rustls_native_certs::load_native_certs();
            for cert in native.certs {
                let _ = roots.add(cert);
            }
            Arc::new(roots)
        })
        .clone()
}

/// A TLS configuration for `host:port`: rejected certificates land in
/// `rejected`.
pub(crate) fn client_config(
    host: &str,
    port: u16,
    trusted_file: &Path,
    rejected: Arc<Mutex<Option<Certificate>>>,
) -> Result<Arc<ClientConfig>, Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let webpki = WebPkiServerVerifier::builder_with_provider(roots(), provider.clone())
        .build()
        .map_err(|e| Error::new(format!("TLS: {e}")))?;
    let verifier = Verifier {
        webpki,
        trusted: trusted(trusted_file, host, port),
        host: host.to_owned(),
        port,
        trusted_file: trusted_file.to_owned(),
        rejected,
    };
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::new(format!("TLS: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

#[derive(Debug)]
struct Verifier {
    webpki: Arc<WebPkiServerVerifier>,
    trusted: Vec<String>,
    host: String,
    port: u16,
    trusted_file: PathBuf,
    rejected: Arc<Mutex<Option<Certificate>>>,
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let error = match self.webpki.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(verified) => return Ok(verified),
            Err(e) => e,
        };
        let fingerprint = sha256_hex(end_entity);
        if self.trusted.contains(&fingerprint) {
            return Ok(ServerCertVerified::assertion());
        }
        *self.rejected.lock().expect("rejected mutex") = Some(describe(
            end_entity,
            &fingerprint,
            &error,
            &self.host,
            self.port,
            &self.trusted_file,
        ));
        Err(error)
    }

    // The handshake's signatures are checked whatever the certificate.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}

fn describe(
    der: &[u8],
    fingerprint: &str,
    error: &rustls::Error,
    host: &str,
    port: u16,
    trusted_file: &Path,
) -> Certificate {
    use x509_parser::prelude::*;
    let (subject, issuer, valid_from, valid_until, self_signed) =
        match X509Certificate::from_der(der) {
            Ok((_, cert)) => {
                let date = |t: ASN1Time| t.to_string();
                (
                    cert.subject().to_string(),
                    cert.issuer().to_string(),
                    date(cert.validity().not_before),
                    date(cert.validity().not_after),
                    cert.subject() == cert.issuer(),
                )
            }
            Err(_) => Default::default(),
        };
    use rustls::CertificateError as C;
    let problem = match error {
        rustls::Error::InvalidCertificate(C::UnknownIssuer) if self_signed => {
            "it is self-signed".to_owned()
        }
        rustls::Error::InvalidCertificate(C::UnknownIssuer) => {
            "its issuer isn't a known certificate authority".to_owned()
        }
        rustls::Error::InvalidCertificate(C::Expired | C::ExpiredContext { .. }) => {
            "it has expired".to_owned()
        }
        rustls::Error::InvalidCertificate(C::NotValidYet | C::NotValidYetContext { .. }) => {
            "it isn't valid yet".to_owned()
        }
        rustls::Error::InvalidCertificate(
            C::NotValidForName | C::NotValidForNameContext { .. },
        ) => format!("it isn't made out to {host}"),
        e => e.to_string(),
    };
    let fingerprint = fingerprint
        .as_bytes()
        .chunks(2)
        .map(|c| String::from_utf8_lossy(c).to_ascii_uppercase())
        .collect::<Vec<_>>()
        .join(":");
    Certificate {
        host: host.to_owned(),
        port,
        fingerprint,
        subject,
        issuer,
        valid_from,
        valid_until,
        problem,
        trusted_file: trusted_file.to_owned(),
    }
}
