//! SSH and SFTP for RustZilla: logging in (password, key file, the SSH
//! agent, or the key file of a FIDO security key such as a YubiKey) and the
//! file operations of an SFTP session.
//!
//! The API is blocking: a [`Connection`] runs its SSH connection on a tokio
//! runtime of its own, and the app calls it from worker threads. Each
//! [`Sftp`] session is a channel of the connection, so browsing and
//! transfers share one login (and one touch of a security key).

mod error;
pub mod fido;
pub mod path;
mod sftp;
mod ssh;
#[cfg(feature = "test-server")]
pub mod testserver;

pub use error::{Error, ErrorKind};
pub use sftp::{EntryKind, Progress, RemoteEntry, Sftp};
pub use ssh::{Auth, Connection, HostKey, SshParams, is_encrypted_key, is_security_key};

pub type Result<T, E = Error> = std::result::Result<T, E>;
