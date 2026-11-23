//! WebDAV (RFC 4918) over HTTP or HTTPS: Nextcloud, ownCloud, Apache
//! mod_dav, IIS, NAS boxes. PROPFIND lists, GET (with a range, to resume)
//! downloads, PUT uploads, MKCOL, DELETE and MOVE change.

use std::fmt;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ureq::http::{Request, Response, StatusCode};
use ureq::{Agent, Body, SendBody};

use crate::error::Error;
use crate::http;
use crate::path;
use crate::remote::{Security, Server, Session};
use crate::sftp::{EntryKind, Progress, RemoteEntry};
use crate::util;

const CHUNK: usize = 256 * 1024;

const PROPFIND: &str = r#"<?xml version="1.0" encoding="utf-8"?><d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/><d:getcontentlength/><d:getlastmodified/></d:prop></d:propfind>"#;

/// How to reach and log in to the WebDAV server.
#[derive(Clone)]
pub struct WebDavParams {
    pub host: String,
    pub port: u16,
    /// HTTPS; plain HTTP otherwise.
    pub tls: bool,
    pub username: String,
    pub password: String,
    /// The WebDAV folder, e.g. `/remote.php/dav/files/me` on Nextcloud.
    pub root: String,
}

impl fmt::Debug for WebDavParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebDavParams")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tls", &self.tls)
            .field("username", &self.username)
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

struct Dav {
    agent: Agent,
    /// `https://host:port`
    base: String,
    authorization: Option<String>,
    name: String,
    tls: bool,
    root: String,
    closed: AtomicBool,
}

pub struct WebDavServer {
    dav: Arc<Dav>,
}

impl WebDavServer {
    /// Checks the folder is there and the login is accepted.
    pub fn open(params: &WebDavParams) -> Result<Self, Error> {
        let host = params.host.trim();
        if host.is_empty() {
            return Err(Error::new("enter the server to connect to"));
        }
        let scheme = if params.tls { "https" } else { "http" };
        let default_port = if params.tls { 443 } else { 80 };
        let port = if params.port == 0 {
            default_port
        } else {
            params.port
        };
        let authority = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let shown = if port == default_port {
            host.to_owned()
        } else {
            authority.clone()
        };
        let name = format!("{}://{shown}", if params.tls { "davs" } else { "dav" });
        let root = match params.root.trim().trim_end_matches('/') {
            "" => "/".to_owned(),
            r if r.starts_with('/') => r.to_owned(),
            r => format!("/{r}"),
        };
        let authorization = (!params.username.is_empty()).then(|| {
            format!(
                "Basic {}",
                util::base64(format!("{}:{}", params.username, params.password).as_bytes())
            )
        });
        let dav = Dav {
            agent: http::agent(),
            base: format!("{scheme}://{authority}"),
            authorization,
            name,
            tls: params.tls,
            root,
            closed: AtomicBool::new(false),
        };
        let mut response = dav.propfind(&dav.root, "0")?;
        match response.status().as_u16() {
            207 => {}
            401 => {
                return Err(Error::new(format!(
                    "{} didn't accept the user and password",
                    dav.name
                )));
            }
            404 => {
                return Err(Error::new(format!(
                    "there is no WebDAV folder {} on {}",
                    dav.root, dav.name
                )));
            }
            405 | 501 => {
                return Err(Error::new(format!(
                    "{} doesn't speak WebDAV at {} (enter the WebDAV folder as the remote \
                     directory)",
                    dav.name, dav.root
                )));
            }
            _ => {
                return Err(Error::new(format!(
                    "{}: {}",
                    dav.name,
                    http::error_text(&mut response)
                )));
            }
        }
        Ok(Self { dav: Arc::new(dav) })
    }
}

impl Server for WebDavServer {
    fn name(&self) -> &str {
        &self.dav.name
    }

    fn security(&self) -> Security {
        if self.dav.tls {
            Security::Tls
        } else {
            Security::Plain
        }
    }

    fn open(&self) -> Result<Box<dyn Session>, Error> {
        Ok(Box::new(WebDavSession {
            dav: self.dav.clone(),
        }))
    }

    fn is_closed(&self) -> bool {
        self.dav.closed.load(Ordering::SeqCst)
    }

    fn disconnect(&self) {
        self.dav.closed.store(true, Ordering::SeqCst);
    }
}

impl Dav {
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, util::encode_path(path))
    }

    fn request(&self, method: &str, path: &str) -> ureq::http::request::Builder {
        let mut builder = Request::builder().method(method).uri(self.url(path));
        if let Some(auth) = &self.authorization {
            builder = builder.header("Authorization", auth);
        }
        builder
    }

    fn send(
        &self,
        builder: ureq::http::request::Builder,
        body: SendBody<'_>,
    ) -> Result<Response<Body>, Error> {
        let request = builder
            .body(body)
            .map_err(|e| Error::new(format!("{}: {e}", self.name)))?;
        http::send(&self.agent, request, &self.name)
    }

    /// Sends a request built by `make` with `body`, once more if the
    /// connection dropped: everything but PUT can be sent twice.
    fn send_repeatable(
        &self,
        make: impl Fn() -> ureq::http::request::Builder,
        body: Option<&'static [u8]>,
    ) -> Result<Response<Body>, Error> {
        http::send_repeatable(&self.agent, &self.name, || {
            let body = match body {
                Some(bytes) => SendBody::from_owned_reader(bytes),
                None => SendBody::none(),
            };
            make()
                .body(body)
                .map_err(|e| Error::new(format!("{}: {e}", self.name)))
        })
    }

    fn propfind(&self, path: &str, depth: &str) -> Result<Response<Body>, Error> {
        self.send_repeatable(
            || {
                self.request("PROPFIND", path)
                    .header("Depth", depth)
                    .header("Content-Type", "application/xml; charset=utf-8")
            },
            Some(PROPFIND.as_bytes()),
        )
    }

    /// The entries of a PROPFIND reply, by their decoded paths.
    fn parse(&self, xml: &str) -> Vec<(String, RemoteEntry)> {
        let Ok(doc) = roxmltree::Document::parse(xml) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for response in doc
            .descendants()
            .filter(|n| n.tag_name().name() == "response")
        {
            let Some(href) = response
                .children()
                .find(|n| n.tag_name().name() == "href")
                .and_then(|n| n.text())
            else {
                continue;
            };
            // A full URL or a path.
            let href = href.trim();
            let href = match href.find("://") {
                Some(i) => href[i + 3..].find('/').map_or("/", |j| &href[i + 3 + j..]),
                None => href,
            };
            let decoded = util::decode(href);
            let path = match decoded.trim_end_matches('/') {
                "" => "/".to_owned(),
                p => p.to_owned(),
            };
            // The properties found (status 200).
            let props: Vec<_> = response
                .descendants()
                .filter(|n| n.tag_name().name() == "propstat")
                .filter(|ps| {
                    ps.children()
                        .find(|n| n.tag_name().name() == "status")
                        .and_then(|n| n.text())
                        .is_none_or(|s| s.contains(" 200"))
                })
                .flat_map(|ps| ps.descendants())
                .collect();
            let find = |name: &str| props.iter().find(|n| n.tag_name().name() == name);
            let dir = find("resourcetype")
                .is_some_and(|rt| rt.children().any(|c| c.tag_name().name() == "collection"));
            let size = find("getcontentlength")
                .and_then(|n| n.text())
                .and_then(|t| t.trim().parse().ok())
                .unwrap_or(0);
            let modified = find("getlastmodified")
                .and_then(|n| n.text())
                .and_then(util::parse_http_date);
            out.push((
                path.clone(),
                RemoteEntry {
                    name: path::file_name(&path).to_owned(),
                    kind: if dir { EntryKind::Dir } else { EntryKind::File },
                    symlink: false,
                    size: if dir { 0 } else { size },
                    modified,
                    permissions: None,
                    owner: String::new(),
                    group: String::new(),
                },
            ));
        }
        out
    }

    fn fail(&self, what: &str, path: &str, response: &mut Response<Body>) -> Error {
        Error::new(format!("{what} {path}: {}", http::error_text(response)))
    }
}

pub struct WebDavSession {
    dav: Arc<Dav>,
}

fn ok(status: StatusCode) -> bool {
    status.is_success()
}

impl Session for WebDavSession {
    fn canonicalize(&mut self, path: &str) -> Result<String, Error> {
        let path = path.trim();
        if path.is_empty() || path == "." {
            return Ok(self.dav.root.clone());
        }
        let absolute = if path.starts_with('/') {
            path.to_owned()
        } else {
            path::join(&self.dav.root, path)
        };
        let mut parts: Vec<&str> = Vec::new();
        for part in absolute.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                p => parts.push(p),
            }
        }
        Ok(format!("/{}", parts.join("/")))
    }

    fn list(&mut self, dir: &str) -> Result<Vec<RemoteEntry>, Error> {
        // Collections are asked for with their slash; some servers
        // redirect otherwise.
        let asked = if dir.ends_with('/') {
            dir.to_owned()
        } else {
            format!("{dir}/")
        };
        let mut response = self.dav.propfind(&asked, "1")?;
        if response.status().as_u16() != 207 {
            return Err(self.dav.fail("listing", dir, &mut response));
        }
        let xml = response
            .body_mut()
            .with_config()
            .limit(64 * 1024 * 1024)
            .read_to_string()
            .map_err(|e| Error::new(format!("listing {dir}: {e}")))?;
        let own = match dir.trim_end_matches('/') {
            "" => "/".to_owned(),
            d => d.to_owned(),
        };
        Ok(self
            .dav
            .parse(&xml)
            .into_iter()
            .filter(|(path, _)| *path != own)
            .map(|(_, entry)| entry)
            .filter(|e| !e.name.is_empty())
            .collect())
    }

    fn stat(&mut self, path: &str) -> Result<Option<RemoteEntry>, Error> {
        let mut response = self.dav.propfind(path, "0")?;
        match response.status().as_u16() {
            207 => {}
            404 => return Ok(None),
            _ => return Err(self.dav.fail("reading", path, &mut response)),
        }
        let xml = response.body_mut().read_to_string().unwrap_or_default();
        Ok(self.dav.parse(&xml).into_iter().next().map(|(_, mut e)| {
            e.name = path::file_name(path).to_owned();
            e
        }))
    }

    fn mkdir(&mut self, path: &str) -> Result<(), Error> {
        let mut response = self
            .dav
            .send_repeatable(|| self.dav.request("MKCOL", path), None)?;
        if ok(response.status()) {
            Ok(())
        } else {
            Err(self.dav.fail("creating the directory", path, &mut response))
        }
    }

    fn remove_file(&mut self, path: &str) -> Result<(), Error> {
        let mut response = self
            .dav
            .send_repeatable(|| self.dav.request("DELETE", path), None)?;
        if ok(response.status()) {
            Ok(())
        } else {
            Err(self.dav.fail("deleting", path, &mut response))
        }
    }

    fn remove_dir(&mut self, path: &str) -> Result<(), Error> {
        self.remove_file(&format!("{}/", path.trim_end_matches('/')))
    }

    /// DELETE of a collection deletes what it holds too.
    fn remove_all(&mut self, path: &str, _cancel: &dyn Fn() -> bool) -> Result<(), Error> {
        self.remove_dir(path)
    }

    fn rename(&mut self, from: &str, to: &str) -> Result<(), Error> {
        let mut response = self.dav.send_repeatable(
            || {
                self.dav
                    .request("MOVE", from)
                    .header("Destination", self.dav.url(to))
                    .header("Overwrite", "F")
            },
            None,
        )?;
        if ok(response.status()) {
            Ok(())
        } else {
            Err(self.dav.fail("renaming", from, &mut response))
        }
    }

    fn chmod(&mut self, path: &str, _mode: u32) -> Result<(), Error> {
        Err(Error::new(format!(
            "changing the permissions of {path}: WebDAV has no permissions"
        )))
    }

    fn download(
        &mut self,
        remote: &str,
        local: &Path,
        offset: u64,
        progress: Progress,
    ) -> Result<u64, Error> {
        let local_error =
            |what: &str, e: io::Error| Error::new(format!("{what} {}: {e}", local.display()));
        let mut response = self.dav.send_repeatable(
            || {
                let builder = self.dav.request("GET", remote);
                if offset > 0 {
                    builder.header("Range", format!("bytes={offset}-"))
                } else {
                    builder
                }
            },
            None,
        )?;
        let status = response.status().as_u16();
        if status == 416 {
            // Nothing after `offset`: the file is complete.
            return Ok(offset);
        }
        if !(200..300).contains(&status) {
            return Err(self.dav.fail("opening", remote, &mut response));
        }
        // 200 to a range: the server sends all of it.
        let offset = if status == 206 { offset } else { 0 };
        let modified = response
            .headers()
            .get("Last-Modified")
            .and_then(|v| v.to_str().ok())
            .and_then(util::parse_http_date);
        let mut out = if offset > 0 {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .open(local)
                .map_err(|e| local_error("opening", e))?;
            file.set_len(offset)
                .and_then(|()| file.seek(SeekFrom::Start(offset)))
                .map_err(|e| local_error("resuming", e))?;
            file
        } else {
            fs::File::create(local).map_err(|e| local_error("creating", e))?
        };
        let mut reader = response.into_body().into_reader();
        let mut buffer = vec![0; CHUNK];
        let mut done = offset;
        loop {
            let n = reader
                .read(&mut buffer)
                .map_err(|e| Error::new(format!("reading {remote}: {e}")))?;
            if n == 0 {
                break;
            }
            out.write_all(&buffer[..n])
                .map_err(|e| local_error("writing", e))?;
            done += n as u64;
            if !progress(done) {
                return Err(Error::cancelled());
            }
        }
        out.flush().map_err(|e| local_error("writing", e))?;
        if let Some(time) = modified {
            let _ = out.set_modified(time);
        }
        Ok(done)
    }

    /// WebDAV can't append: the file goes up whole, whatever `offset`.
    fn upload(
        &mut self,
        local: &Path,
        remote: &str,
        _offset: u64,
        progress: Progress,
    ) -> Result<u64, Error> {
        let file = fs::File::open(local)
            .map_err(|e| Error::new(format!("opening {}: {e}", local.display())))?;
        let meta = file
            .metadata()
            .map_err(|e| Error::new(format!("reading {}: {e}", local.display())))?;
        let mut builder = self
            .dav
            .request("PUT", remote)
            .header("Content-Length", meta.len());
        // Nextcloud and ownCloud keep this as the file's time.
        if let Ok(modified) = meta.modified() {
            builder = builder.header("X-OC-Mtime", util::secs(modified));
        }
        let mut reader = Counting::new(file, progress);
        let result = self.dav.send(builder, SendBody::from_reader(&mut reader));
        if reader.cancelled {
            return Err(Error::cancelled());
        }
        let mut response = result?;
        if ok(response.status()) {
            Ok(reader.done)
        } else {
            Err(self.dav.fail("writing", remote, &mut response))
        }
    }
}

/// A reader that tells `progress` how far it got, and stops when that
/// says so.
pub(crate) struct Counting<'a, R> {
    inner: R,
    progress: Progress<'a>,
    pub done: u64,
    pub cancelled: bool,
}

impl<'a, R: Read> Counting<'a, R> {
    pub fn new(inner: R, progress: Progress<'a>) -> Self {
        Self {
            inner,
            progress,
            done: 0,
            cancelled: false,
        }
    }
}

impl<R: Read> Read for Counting<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.done += n as u64;
        if !(self.progress)(self.done) {
            self.cancelled = true;
            return Err(io::Error::other("cancelled"));
        }
        Ok(n)
    }
}
