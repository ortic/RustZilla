use std::fmt;

use crate::ssh::HostKey;

/// What went wrong, in words for the user, and what the app can do about it.
#[derive(Debug, Clone)]
pub struct Error {
    pub message: String,
    pub kind: ErrorKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorKind {
    Other,
    /// The server's host key isn't known yet: the user may trust it and
    /// connect again.
    UnknownHostKey(Box<HostKey>),
    /// The server's TLS certificate isn't trusted (self-signed, unknown
    /// issuer…): the user may trust it and connect again.
    UnknownCertificate(Box<crate::tls::Certificate>),
    /// The security key needs its PIN, or refused the one given: the app
    /// asks for it and connects again.
    Pin,
    /// The key file needs its passphrase, or it was wrong.
    Passphrase,
    /// The transfer was cancelled, or the login (by the user).
    Cancelled,
    /// The SSH connection is gone: connect again.
    Disconnected,
}

impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: ErrorKind::Other,
        }
    }

    pub fn with_kind(message: impl Into<String>, kind: ErrorKind) -> Self {
        Self {
            message: message.into(),
            kind,
        }
    }

    pub fn cancelled() -> Self {
        Self::with_kind("cancelled", ErrorKind::Cancelled)
    }

    pub fn host_key(&self) -> Option<&HostKey> {
        match &self.kind {
            ErrorKind::UnknownHostKey(key) => Some(key),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}
