//! What every protocol offers the app: a [`Server`] logged in to, which
//! opens [`Session`]s that list and change files and transfer them.
//!
//! SFTP opens its sessions as channels of the one SSH connection; FTP opens
//! a control connection for each (and logs in on each), as FileZilla does
//! for parallel transfers.

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::ftp::FtpParams;
use crate::path;
use crate::s3::S3Params;
use crate::sftp::{EntryKind, Progress, RemoteEntry};
use crate::ssh::SshParams;
use crate::webdav::WebDavParams;

/// The protocols RustZilla speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    /// SSH File Transfer Protocol.
    #[default]
    Sftp,
    /// FTP, with or without TLS (see [`FtpEncryption`]).
    Ftp,
    /// WebDAV over HTTPS (or HTTP).
    #[serde(rename = "webdav")]
    WebDav,
    /// Amazon S3 and compatible object stores.
    S3,
}

impl Protocol {
    pub const ALL: [Protocol; 4] = [
        Protocol::Sftp,
        Protocol::Ftp,
        Protocol::WebDav,
        Protocol::S3,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Protocol::Sftp => "SFTP – SSH File Transfer Protocol",
            Protocol::Ftp => "FTP – File Transfer Protocol",
            Protocol::WebDav => "WebDAV",
            Protocol::S3 => "S3 – Amazon S3 and compatible storage",
        }
    }

    pub fn default_port(self, encryption: FtpEncryption) -> u16 {
        match (self, encryption) {
            (Protocol::Sftp, _) => 22,
            (Protocol::Ftp, FtpEncryption::Implicit) => 990,
            (Protocol::Ftp, _) => 21,
            (Protocol::WebDav | Protocol::S3, FtpEncryption::Plain) => 80,
            (Protocol::WebDav | Protocol::S3, _) => 443,
        }
    }

    /// The encryptions to choose from; HTTP protocols have HTTPS or not.
    pub fn encryptions(self) -> &'static [FtpEncryption] {
        match self {
            Protocol::Sftp => &[],
            Protocol::Ftp => &FtpEncryption::ALL,
            Protocol::WebDav | Protocol::S3 => &[FtpEncryption::Explicit, FtpEncryption::Plain],
        }
    }

    /// Whether `encryption` means TLS for this protocol.
    pub fn uses_tls(self, encryption: FtpEncryption) -> bool {
        encryption != FtpEncryption::Plain
    }
}

/// How FTP is encrypted, as FileZilla offers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FtpEncryption {
    /// TLS (`AUTH TLS`) if the server offers it, plain FTP if it doesn't.
    #[default]
    ExplicitIfAvailable,
    /// Explicit FTP over TLS, required.
    Explicit,
    /// Implicit FTP over TLS (port 990).
    Implicit,
    /// Plain FTP: password and files travel unencrypted.
    Plain,
}

impl FtpEncryption {
    pub const ALL: [FtpEncryption; 4] = [
        FtpEncryption::ExplicitIfAvailable,
        FtpEncryption::Explicit,
        FtpEncryption::Implicit,
        FtpEncryption::Plain,
    ];

    /// How the encryption is called for `protocol`.
    pub fn label_for(self, protocol: Protocol) -> &'static str {
        match (protocol, self) {
            (Protocol::WebDav | Protocol::S3, FtpEncryption::Plain) => "HTTP (insecure)",
            (Protocol::WebDav | Protocol::S3, _) => "HTTPS",
            _ => self.label(),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            FtpEncryption::ExplicitIfAvailable => "Use explicit FTP over TLS if available",
            FtpEncryption::Explicit => "Require explicit FTP over TLS",
            FtpEncryption::Implicit => "Require implicit FTP over TLS",
            FtpEncryption::Plain => "Only use plain FTP (insecure)",
        }
    }
}

/// Where and how to log in, by protocol.
#[derive(Clone, Debug)]
pub enum Params {
    Sftp(SshParams),
    Ftp(FtpParams),
    WebDav(WebDavParams),
    S3(S3Params),
}

impl Params {
    pub fn host(&self) -> &str {
        match self {
            Params::Sftp(p) => &p.host,
            Params::Ftp(p) => &p.host,
            Params::WebDav(p) => &p.host,
            Params::S3(p) => &p.host,
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Params::Sftp(p) => p.port,
            Params::Ftp(p) => p.port,
            Params::WebDav(p) => p.port,
            Params::S3(p) => p.port,
        }
    }

    pub fn username(&self) -> &str {
        match self {
            Params::Sftp(p) => &p.username,
            Params::Ftp(p) => &p.username,
            Params::WebDav(p) => &p.username,
            Params::S3(p) => &p.access_key,
        }
    }

    /// The protocol, as the status bar and the queue show it.
    pub fn protocol(&self) -> Protocol {
        match self {
            Params::Sftp(_) => Protocol::Sftp,
            Params::Ftp(_) => Protocol::Ftp,
            Params::WebDav(_) => Protocol::WebDav,
            Params::S3(_) => Protocol::S3,
        }
    }

    /// Sets the password the user typed in.
    pub fn set_password(&mut self, password: String) {
        match self {
            Params::Sftp(p) => p.auth = crate::Auth::Password(password),
            Params::Ftp(p) => p.password = password,
            Params::WebDav(p) => p.password = password,
            Params::S3(p) => p.secret_key = password,
        }
    }
}

/// Connects and logs in. Blocks.
pub fn connect(params: &Params) -> Result<Arc<dyn Server>, Error> {
    match params {
        Params::Sftp(p) => Ok(Arc::new(crate::Connection::open(p)?)),
        Params::Ftp(p) => Ok(Arc::new(crate::ftp::FtpServer::open(p)?)),
        Params::WebDav(p) => Ok(Arc::new(crate::webdav::WebDavServer::open(p)?)),
        Params::S3(p) => Ok(Arc::new(crate::s3::S3Server::open(p)?)),
    }
}

/// A server logged in to.
pub trait Server: Send + Sync {
    /// How the queue and the status bar name it: `host` or `host:port`,
    /// `ftp://` before FTP servers.
    fn name(&self) -> &str;

    /// How the connection is secured, for the status bar: "SFTP", "FTP over
    /// TLS", "FTP (not encrypted)".
    fn security(&self) -> Security;

    /// Opens a session: a channel (SFTP) or a connection (FTP) of its own.
    fn open(&self) -> Result<Box<dyn Session>, Error>;

    fn is_closed(&self) -> bool;

    /// Ends the connection, telling the server.
    fn disconnect(&self);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    Ssh,
    Tls,
    /// Nothing is encrypted.
    Plain,
}

/// The file operations of one session. Blocking.
pub trait Session: Send {
    /// The absolute form of `path` (`.` is the starting directory).
    fn canonicalize(&mut self, path: &str) -> Result<String, Error>;

    /// The entries of the directory `dir`, without `.` and `..`.
    fn list(&mut self, dir: &str) -> Result<Vec<RemoteEntry>, Error>;

    /// What `path` is; `None` if there is nothing there.
    fn stat(&mut self, path: &str) -> Result<Option<RemoteEntry>, Error>;

    fn mkdir(&mut self, path: &str) -> Result<(), Error>;
    fn remove_file(&mut self, path: &str) -> Result<(), Error>;
    fn remove_dir(&mut self, path: &str) -> Result<(), Error>;
    fn rename(&mut self, from: &str, to: &str) -> Result<(), Error>;

    /// Sets the mode bits of `path`, `0o644` and the like.
    fn chmod(&mut self, path: &str, mode: u32) -> Result<(), Error>;

    /// Downloads `remote` to `local` from `offset` on (0: a new file; more:
    /// appends to the part there).
    fn download(
        &mut self,
        remote: &str,
        local: &Path,
        offset: u64,
        progress: Progress,
    ) -> Result<u64, Error>;

    /// Uploads `local` to `remote` from `offset` on.
    fn upload(
        &mut self,
        local: &Path,
        remote: &str,
        offset: u64,
        progress: Progress,
    ) -> Result<u64, Error>;

    /// Creates `path` and the directories above it that are missing.
    fn mkdir_all(&mut self, path: &str) -> Result<(), Error> {
        if path.is_empty() || path == "/" || path == "." {
            return Ok(());
        }
        match self.stat(path)? {
            Some(e) if e.is_dir() => Ok(()),
            Some(_) => Err(Error::new(format!(
                "creating the directory {path}: a file is in the way"
            ))),
            None => {
                self.mkdir_all(&path::parent(path))?;
                self.mkdir(path)
            }
        }
    }

    /// Deletes the directory `path` with everything in it. Links are
    /// deleted, not followed.
    fn remove_all(&mut self, path: &str, cancel: &dyn Fn() -> bool) -> Result<(), Error> {
        for entry in self.list(path)? {
            if cancel() {
                return Err(Error::cancelled());
            }
            let child = path::join(path, &entry.name);
            if entry.is_dir() && !entry.symlink {
                self.remove_all(&child, cancel)?;
            } else {
                self.remove_file(&child)?;
            }
        }
        self.remove_dir(path)
    }

    /// The files and directories under `dir`, as paths relative to it,
    /// directories before what they hold. Links to directories aren't
    /// followed (they could lead in a circle).
    fn walk(
        &mut self,
        dir: &str,
        cancel: &dyn Fn() -> bool,
    ) -> Result<Vec<(String, RemoteEntry)>, Error> {
        let mut out = Vec::new();
        let mut pending = vec![String::new()];
        while let Some(relative) = pending.pop() {
            if cancel() {
                return Err(Error::cancelled());
            }
            let absolute = if relative.is_empty() {
                dir.to_owned()
            } else {
                path::join(dir, &relative)
            };
            for entry in self.list(&absolute)? {
                let child = path::join(&relative, &entry.name);
                if entry.is_dir() && !entry.symlink {
                    pending.push(child.clone());
                }
                if entry.kind != EntryKind::Other || entry.is_dir() {
                    out.push((child, entry));
                }
            }
        }
        Ok(out)
    }
}
