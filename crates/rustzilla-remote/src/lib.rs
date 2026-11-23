//! The protocols of RustZilla: SFTP (logging in with a password, a key
//! file, the SSH agent, or the key file of a FIDO security key such as a
//! YubiKey), FTP/FTPS, WebDAV and S3, behind one interface ([`Server`],
//! [`Session`]).
//!
//! The API is blocking: a [`Connection`] runs its SSH connection on a tokio
//! runtime of its own, and the app calls it from worker threads. Each
//! [`Sftp`] session is a channel of the connection, so browsing and
//! transfers share one login (and one touch of a security key).

mod error;
pub mod fido;
mod ftp;
mod http;
pub mod path;
mod remote;
mod s3;
mod sftp;
mod ssh;
#[cfg(feature = "test-server")]
pub mod testserver;
mod tls;
mod util;
mod webdav;

pub use error::{Error, ErrorKind};
pub use ftp::{FtpParams, FtpServer};
pub use remote::{FtpEncryption, Params, Protocol, Security, Server, Session, connect};
pub use s3::S3Params;
pub use sftp::{EntryKind, Progress, RemoteEntry, Sftp};
pub use ssh::{
    Auth, Connection, HostKey, Jump, OnPrompt, Prompt, Prompts, SshParams, is_encrypted_key,
    is_security_key,
};
pub use tls::Certificate;
pub use webdav::WebDavParams;

pub type Result<T, E = Error> = std::result::Result<T, E>;
