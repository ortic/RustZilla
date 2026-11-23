//! FTP and FTPS (explicit and implicit TLS), on suppaftp with rustls.
//!
//! Every session is a control connection of its own, logged in, as
//! FileZilla opens one for each parallel transfer. A session whose control
//! connection the server dropped (idle timeouts are common) connects and
//! logs in again before its next command.

use std::fmt;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use suppaftp::list::{File, ListParser, PosixPexQuery};
use suppaftp::types::FileType;
use suppaftp::{FtpError, RustlsConnector, RustlsFtpStream, Status};
use tracing::{info, warn};

use crate::error::{Error, ErrorKind};
use crate::path;
use crate::remote::{FtpEncryption, Security, Server, Session};
use crate::sftp::{EntryKind, Progress, RemoteEntry};
use crate::tls::{self, Certificate};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// For each reply, and for data that stops flowing.
const IO_TIMEOUT: Duration = Duration::from_secs(60);
const CHUNK: usize = 256 * 1024;

type Stream = RustlsFtpStream;

/// How to reach and log in to the FTP server.
#[derive(Clone)]
pub struct FtpParams {
    pub host: String,
    pub port: u16,
    /// Empty for anonymous FTP.
    pub username: String,
    pub password: String,
    pub encryption: FtpEncryption,
    /// Certificates trusted in RustZilla, by host.
    pub trusted_certs: PathBuf,
}

impl fmt::Debug for FtpParams {
    // Never the password.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FtpParams")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("encryption", &self.encryption)
            .finish_non_exhaustive()
    }
}

/// What the sessions of a server share.
struct Shared {
    params: FtpParams,
    name: String,
    /// Whether the login secured the connection: later sessions require it.
    tls: bool,
    mlsd: bool,
    mlst: bool,
    mfmt: bool,
}

pub struct FtpServer {
    shared: Arc<Shared>,
    /// The first login's connection, for the first session.
    first: Mutex<Option<Stream>>,
    closed: AtomicBool,
}

impl FtpServer {
    /// Connects and logs in. Blocks.
    pub fn open(params: &FtpParams) -> Result<Self, Error> {
        let (mut stream, tls) = login(params, params.encryption)?;
        let features = stream.feat().unwrap_or_default();
        let has = |f: &str| features.keys().any(|k| k.eq_ignore_ascii_case(f));
        let default_port = crate::Protocol::Ftp.default_port(params.encryption);
        let scheme = if params.encryption == FtpEncryption::Implicit {
            "ftps"
        } else {
            "ftp"
        };
        let name = if params.port == default_port {
            format!("{scheme}://{}", params.host)
        } else {
            format!("{scheme}://{}:{}", params.host, params.port)
        };
        info!(%name, tls, "logged in over FTP");
        Ok(Self {
            shared: Arc::new(Shared {
                params: params.clone(),
                name,
                tls,
                mlsd: has("MLSD") || has("MLST"),
                mlst: has("MLST"),
                mfmt: has("MFMT"),
            }),
            first: Mutex::new(Some(stream)),
            closed: AtomicBool::new(false),
        })
    }
}

impl Server for FtpServer {
    fn name(&self) -> &str {
        &self.shared.name
    }

    fn security(&self) -> Security {
        if self.shared.tls {
            Security::Tls
        } else {
            Security::Plain
        }
    }

    fn open(&self) -> Result<Box<dyn Session>, Error> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::with_kind(
                "the connection is closed",
                ErrorKind::Disconnected,
            ));
        }
        let stream = match self.first.lock().expect("first mutex").take() {
            Some(stream) => stream,
            None => relogin(&self.shared)?,
        };
        Ok(Box::new(FtpSession {
            stream: Some(stream),
            shared: self.shared.clone(),
        }))
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn disconnect(&self) {
        self.closed.store(true, Ordering::SeqCst);
        if let Some(mut stream) = self.first.lock().expect("first mutex").take() {
            let _ = stream.quit();
        }
    }
}

/// Logs in again as the first login did: with TLS if it got TLS.
fn relogin(shared: &Shared) -> Result<Stream, Error> {
    let encryption = match (shared.params.encryption, shared.tls) {
        (FtpEncryption::Implicit, _) => FtpEncryption::Implicit,
        (_, true) => FtpEncryption::Explicit,
        (_, false) => FtpEncryption::Plain,
    };
    login(&shared.params, encryption).map(|(stream, _)| stream)
}

fn server_text(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Connects, secures and logs in; whether it's TLS.
fn login(p: &FtpParams, encryption: FtpEncryption) -> Result<(Stream, bool), Error> {
    let host = p.host.trim().trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err(Error::new("enter the server to connect to"));
    }
    let port = if p.port == 0 {
        crate::Protocol::Ftp.default_port(encryption)
    } else {
        p.port
    };
    let server = server_text(host, port);
    let addr = resolve(host, port)?;
    let rejected = Arc::new(Mutex::new(None::<Certificate>));
    let tls_error = |e: FtpError| match rejected.lock().expect("rejected mutex").take() {
        Some(cert) => Error::with_kind(
            format!(
                "the certificate of {server} isn't trusted: {}",
                cert.problem
            ),
            ErrorKind::UnknownCertificate(Box::new(cert)),
        ),
        None => Error::new(format!("TLS with {server}: {}", ftp_text(&e))),
    };
    let connector = || -> Result<RustlsConnector, Error> {
        Ok(RustlsConnector::from(tls::client_config(
            host,
            port,
            &p.trusted_certs,
            rejected.clone(),
        )?))
    };
    let connect_tcp = || -> Result<TcpStream, Error> {
        let tcp = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
            .map_err(|e| Error::new(format!("can't connect to {server}: {e}")))?;
        let _ = tcp.set_read_timeout(Some(IO_TIMEOUT));
        let _ = tcp.set_write_timeout(Some(IO_TIMEOUT));
        let _ = tcp.set_nodelay(true);
        Ok(tcp)
    };
    let greeting = |e: FtpError| {
        Error::new(format!(
            "{server} didn't greet as an FTP server: {}",
            ftp_text(&e)
        ))
    };
    let (mut stream, tls) = match encryption {
        FtpEncryption::Implicit => {
            // A first connect for its timeout: suppaftp's has none.
            drop(connect_tcp()?);
            let stream =
                Stream::connect_secure_implicit(addr, connector()?, host).map_err(|e| match e {
                    FtpError::SecureError(_) => tls_error(e),
                    e => greeting(e),
                })?;
            (stream, true)
        }
        FtpEncryption::Plain => (
            Stream::connect_with_stream(connect_tcp()?).map_err(greeting)?,
            false,
        ),
        FtpEncryption::Explicit | FtpEncryption::ExplicitIfAvailable => {
            let plain = Stream::connect_with_stream(connect_tcp()?).map_err(greeting)?;
            match plain.into_secure(connector()?, host) {
                Ok(stream) => (stream, true),
                // The server doesn't do TLS: plain, if that's allowed.
                Err(FtpError::UnexpectedResponse(r))
                    if encryption == FtpEncryption::ExplicitIfAvailable
                        && matches!(r.status as u32, 500 | 502 | 504 | 534) =>
                {
                    warn!("{server} doesn't offer TLS: logging in over plain FTP");
                    (
                        Stream::connect_with_stream(connect_tcp()?).map_err(greeting)?,
                        false,
                    )
                }
                Err(e @ FtpError::UnexpectedResponse(_)) => {
                    return Err(Error::new(format!(
                        "{server} doesn't offer FTP over TLS: {}",
                        ftp_text(&e)
                    )));
                }
                Err(e) => return Err(tls_error(e)),
            }
        }
    };
    // Servers behind NAT answer PASV with their inner address: use the
    // control connection's.
    stream.set_passive_nat_workaround(true);
    let (user, password) = if p.username.trim().is_empty() {
        ("anonymous", "anonymous@")
    } else {
        (p.username.trim(), p.password.as_str())
    };
    stream.login(user, password).map_err(|e| match &e {
        FtpError::UnexpectedResponse(r) if r.status == Status::NotLoggedIn => {
            Error::new(format!("{server} didn't accept the password for {user}"))
        }
        _ => Error::new(format!("logging in to {server}: {}", ftp_text(&e))),
    })?;
    stream
        .transfer_type(FileType::Binary)
        .map_err(|e| Error::new(format!("{server}: {}", ftp_text(&e))))?;
    Ok((stream, tls))
}

fn resolve(host: &str, port: u16) -> Result<SocketAddr, Error> {
    (host, port)
        .to_socket_addrs()
        .map_err(|e| Error::new(format!("can't find {host}: {e}")))?
        .next()
        .ok_or_else(|| Error::new(format!("can't find {host}")))
}

/// An FTP error in words: the server's reply, without its code.
fn ftp_text(e: &FtpError) -> String {
    match e {
        FtpError::UnexpectedResponse(r) => {
            let text = String::from_utf8_lossy(&r.body).trim().to_owned();
            let text = text
                .get(..3)
                .filter(|code| code.bytes().all(|b| b.is_ascii_digit()))
                .map_or(text.as_str(), |_| text[3..].trim_start_matches(['-', ' ']));
            if text.is_empty() {
                format!("the server answered {}", r.status as u32)
            } else {
                text.to_owned()
            }
        }
        e => e.to_string(),
    }
}

fn is_lost(e: &FtpError) -> bool {
    match e {
        FtpError::ConnectionError(_) | FtpError::BadResponse => true,
        // 421: the server is closing the connection (e.g. idle timeout).
        FtpError::UnexpectedResponse(r) => r.status as u32 == 421,
        _ => false,
    }
}

fn not_found(e: &FtpError) -> bool {
    matches!(e, FtpError::UnexpectedResponse(r) if matches!(r.status as u32, 550 | 450 | 553))
}

pub struct FtpSession {
    /// `None` while reconnecting failed.
    stream: Option<Stream>,
    shared: Arc<Shared>,
}

impl FtpSession {
    /// Runs `op`; if the control connection turns out lost, logs in again
    /// and runs it once more.
    fn run<T>(
        &mut self,
        what: &str,
        path: &str,
        mut op: impl FnMut(&mut Stream) -> Result<T, FtpError>,
    ) -> Result<T, Error> {
        let first = match &mut self.stream {
            Some(stream) => op(stream),
            None => Err(FtpError::BadResponse),
        };
        let error = match first {
            Ok(value) => return Ok(value),
            Err(e) if is_lost(&e) => e,
            Err(e) => return Err(self.error(what, path, e)),
        };
        info!("FTP: the control connection is lost ({error}); logging in again");
        self.stream = None;
        let mut stream = relogin(&self.shared).map_err(|e| {
            Error::with_kind(
                format!("the connection to {} is lost: {e}", self.shared.name),
                ErrorKind::Disconnected,
            )
        })?;
        let result = op(&mut stream);
        self.stream = Some(stream);
        result.map_err(|e| self.error(what, path, e))
    }

    fn error(&self, what: &str, path: &str, e: FtpError) -> Error {
        let kind = if is_lost(&e) {
            ErrorKind::Disconnected
        } else {
            ErrorKind::Other
        };
        Error::with_kind(format!("{what} {path}: {}", ftp_text(&e)), kind)
    }

    fn stream(&mut self) -> Result<&mut Stream, Error> {
        if self.stream.is_none() {
            self.stream = Some(relogin(&self.shared)?);
        }
        Ok(self.stream.as_mut().expect("a stream"))
    }

    /// Whether `path` is a directory one can change into.
    fn is_dir(&mut self, path: &str) -> bool {
        self.run("", path, |s| s.cwd(path)).is_ok()
    }

    fn modified(&mut self, path: &str) -> Option<SystemTime> {
        let time = self.run("", path, |s| s.mdtm(path)).ok()?;
        // MDTM is in UTC.
        let days = days_from_civil(
            i64::from(time.year()),
            i64::from(time.month()),
            i64::from(time.day()),
        );
        let seconds = days * 86_400
            + i64::from(time.hour()) * 3600
            + i64::from(time.minute()) * 60
            + i64::from(time.second());
        UNIX_EPOCH.checked_add(Duration::from_secs(u64::try_from(seconds).ok()?))
    }
}

/// `/a/./b/../c` as `/a/c`.
fn normalize(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    format!("/{}", parts.join("/"))
}

fn entry(file: &File) -> RemoteEntry {
    let kind = if file.is_directory() {
        EntryKind::Dir
    } else if file.is_file() {
        EntryKind::File
    } else {
        // A link; its target is looked up by the listing.
        EntryKind::Other
    };
    let mut mode = 0;
    for (who, shift) in [
        (PosixPexQuery::Owner, 6),
        (PosixPexQuery::Group, 3),
        (PosixPexQuery::Others, 0),
    ] {
        mode |= (u32::from(file.can_read(who)) << 2
            | u32::from(file.can_write(who)) << 1
            | u32::from(file.can_execute(who)))
            << shift;
    }
    let modified = Some(file.modified()).filter(|t| *t != UNIX_EPOCH);
    RemoteEntry {
        name: file.name().to_owned(),
        kind,
        symlink: file.is_symlink(),
        size: if file.is_directory() {
            0
        } else {
            file.size() as u64
        },
        modified,
        // No bits at all: the listing had none (DOS, MLSD without them).
        permissions: (mode != 0).then_some(mode),
        owner: file.uid().map(|u| u.to_string()).unwrap_or_default(),
        group: file.gid().map(|g| g.to_string()).unwrap_or_default(),
    }
}

impl Session for FtpSession {
    fn canonicalize(&mut self, path: &str) -> Result<String, Error> {
        let path = path.trim();
        if path.starts_with('/') {
            return Ok(normalize(path));
        }
        let current = self.run("resolving", path, |s| s.pwd())?;
        if path.is_empty() || path == "." {
            return Ok(current);
        }
        Ok(normalize(&path::join(&current, path)))
    }

    fn list(&mut self, dir: &str) -> Result<Vec<RemoteEntry>, Error> {
        let lines = if self.shared.mlsd {
            self.run("listing", dir, |s| s.mlsd(Some(dir)))?
        } else {
            // LIST of a path is ambiguous with spaces and options: list
            // the working directory.
            self.run("listing", dir, |s| {
                s.cwd(dir)?;
                s.list(None)
            })?
        };
        let mut out = Vec::new();
        for line in lines {
            let parsed = if self.shared.mlsd {
                ListParser::parse_mlsd(&line)
            } else {
                File::try_from(line.as_str())
            };
            let Ok(file) = parsed else { continue };
            let name = file.name();
            if name.is_empty() || name == "." || name == ".." {
                continue;
            }
            let mut entry = entry(&file);
            if entry.symlink {
                // As FileZilla: a link that opens as a directory is one.
                entry.kind = if self.is_dir(&path::join(dir, name)) {
                    EntryKind::Dir
                } else {
                    EntryKind::File
                };
            }
            out.push(entry);
        }
        Ok(out)
    }

    fn stat(&mut self, path: &str) -> Result<Option<RemoteEntry>, Error> {
        if self.shared.mlst {
            match self.stream()?.mlst(Some(path)) {
                Ok(line) => {
                    if let Ok(file) = ListParser::parse_mlst(&line) {
                        let mut entry = entry(&file);
                        entry.name = path::file_name(path).to_owned();
                        return Ok(Some(entry));
                    }
                }
                Err(e) if not_found(&e) => return Ok(None),
                Err(e) if is_lost(&e) => {
                    self.stream = None;
                    return self.stat(path);
                }
                Err(_) => {}
            }
        }
        // Without MLST: a file has a size, a directory can be entered.
        match self.stream()?.size(path) {
            Ok(size) => {
                let modified = self.modified(path);
                return Ok(Some(RemoteEntry {
                    name: path::file_name(path).to_owned(),
                    kind: EntryKind::File,
                    symlink: false,
                    size: size as u64,
                    modified,
                    permissions: None,
                    owner: String::new(),
                    group: String::new(),
                }));
            }
            Err(e) if is_lost(&e) => {
                self.stream = None;
                return Err(self.error("reading", path, e));
            }
            Err(_) => {}
        }
        if self.is_dir(path) {
            return Ok(Some(RemoteEntry {
                name: path::file_name(path).to_owned(),
                kind: EntryKind::Dir,
                symlink: false,
                size: 0,
                modified: None,
                permissions: None,
                owner: String::new(),
                group: String::new(),
            }));
        }
        Ok(None)
    }

    fn mkdir(&mut self, path: &str) -> Result<(), Error> {
        self.run("creating the directory", path, |s| s.mkdir(path))
    }

    fn remove_file(&mut self, path: &str) -> Result<(), Error> {
        self.run("deleting", path, |s| s.rm(path))
    }

    fn remove_dir(&mut self, path: &str) -> Result<(), Error> {
        self.run("deleting the directory", path, |s| s.rmdir(path))
    }

    fn rename(&mut self, from: &str, to: &str) -> Result<(), Error> {
        self.run("renaming", from, |s| s.rename(from, to))
    }

    fn chmod(&mut self, path: &str, mode: u32) -> Result<(), Error> {
        let command = format!("CHMOD {:o} {path}", mode & 0o7777);
        self.run("changing the permissions of", path, |s| s.site(&command))
            .map(drop)
    }

    fn download(
        &mut self,
        remote: &str,
        local: &Path,
        offset: u64,
        progress: Progress,
    ) -> Result<u64, Error> {
        let local_error =
            |what: &str, e: std::io::Error| Error::new(format!("{what} {}: {e}", local.display()));
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
        let mut transfer = self.run("opening", remote, |s| {
            s.resume_transfer(offset as usize)?;
            s.retr_as_stream(remote)
        })?;
        let mut done = offset;
        let mut buffer = vec![0; CHUNK];
        loop {
            let n = match transfer.read(&mut buffer) {
                Ok(n) => n,
                Err(e) => {
                    self.stream = None;
                    return Err(Error::new(format!("reading {remote}: {e}")));
                }
            };
            if n == 0 {
                break;
            }
            out.write_all(&buffer[..n])
                .map_err(|e| local_error("writing", e))?;
            done += n as u64;
            if !progress(done) {
                // Servers answer an ABOR in different orders, some late:
                // the control connection isn't trusted after it. The next
                // command logs in again.
                drop(transfer);
                self.stream = None;
                return Err(Error::cancelled());
            }
        }
        transfer
            .finish()
            .map_err(|e| self.error("reading", remote, e))?;
        out.flush().map_err(|e| local_error("writing", e))?;
        if let Some(time) = self.modified(remote) {
            let _ = out.set_modified(time);
        }
        Ok(done)
    }

    fn upload(
        &mut self,
        local: &Path,
        remote: &str,
        offset: u64,
        progress: Progress,
    ) -> Result<u64, Error> {
        let local_error =
            |what: &str, e: std::io::Error| Error::new(format!("{what} {}: {e}", local.display()));
        let mut input = fs::File::open(local).map_err(|e| local_error("opening", e))?;
        let modified = input.metadata().ok().and_then(|m| m.modified().ok());
        if offset > 0 {
            input
                .seek(SeekFrom::Start(offset))
                .map_err(|e| local_error("resuming", e))?;
        }
        let mut transfer = self.run("creating", remote, |s| {
            if offset > 0 {
                s.append_with_stream(remote)
            } else {
                s.put_with_stream(remote)
            }
        })?;
        let mut done = offset;
        let mut buffer = vec![0; CHUNK];
        loop {
            let n = input
                .read(&mut buffer)
                .map_err(|e| local_error("reading", e))?;
            if n == 0 {
                break;
            }
            if let Err(e) = transfer.write_all(&buffer[..n]) {
                self.stream = None;
                return Err(Error::new(format!("writing {remote}: {e}")));
            }
            done += n as u64;
            if !progress(done) {
                // Servers answer an ABOR in different orders, some late:
                // the control connection isn't trusted after it. The next
                // command logs in again.
                drop(transfer);
                self.stream = None;
                return Err(Error::cancelled());
            }
        }
        transfer
            .finish()
            .map_err(|e| self.error("writing", remote, e))?;
        // The local file's time, where the server lets it be set.
        if self.shared.mfmt
            && let Some(time) = modified.and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        {
            let command = format!("MFMT {} {remote}", mdtm_format(time.as_secs()));
            if let Err(e) = self.stream()?.custom_command(command, &[Status::File]) {
                tracing::debug!("setting the time of {remote}: {e}");
            }
        }
        Ok(done)
    }
}

/// Days since 1970-01-01 of a date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `YYYYMMDDHHMMSS` in UTC, as MDTM and MFMT write times.
fn mdtm_format(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rest = secs % 86_400;
    // Civil from days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}{:02}{:02}{:02}",
        rest / 3600,
        rest / 60 % 60,
        rest % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_and_times() {
        assert_eq!(normalize("/a/./b/../c/"), "/a/c");
        assert_eq!(normalize("/.."), "/");
        assert_eq!(mdtm_format(0), "19700101000000");
        assert_eq!(mdtm_format(1_795_000_000), "20261118110640");
        assert_eq!(
            days_from_civil(2026, 11, 18) * 86_400 + 11 * 3600 + 6 * 60 + 40,
            1_795_000_000
        );
    }
}
