//! The protocols of RustZilla: SFTP (logging in with a password, a key
//! file, the SSH agent, or the key file of a FIDO security key such as a
//! YubiKey) and FTP/FTPS, behind one interface ([`Server`], [`Session`]).
//!
//! The API is blocking: a [`Connection`] runs its SSH connection on a tokio
//! runtime of its own, and the app calls it from worker threads. Each
//! [`Sftp`] session is a channel of the connection, so browsing and
//! transfers share one login (and one touch of a security key).

mod error;
pub mod fido;
mod ftp;
pub mod path;
mod remote;
mod sftp;
mod ssh;
#[cfg(feature = "test-server")]
pub mod testserver;
mod tls;

pub use error::{Error, ErrorKind};
pub use ftp::{FtpParams, FtpServer};
pub use remote::{FtpEncryption, Params, Protocol, Security, Server, Session, connect};
pub use sftp::{EntryKind, Progress, RemoteEntry, Sftp};
pub use ssh::{Auth, Connection, HostKey, SshParams, is_encrypted_key, is_security_key};
pub use tls::Certificate;

pub type Result<T, E = Error> = std::result::Result<T, E>;
