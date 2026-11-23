//! The file operations of an SFTP session, blocking.

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use russh_sftp::client::SftpSession;
use russh_sftp::client::error::Error as SftpError;
use russh_sftp::protocol::{FileAttributes, FileType, OpenFlags, StatusCode};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::error::{Error, ErrorKind};
use crate::path;
use crate::ssh::Connection;

/// The size of the chunks transfers read and write; the SFTP session
/// pipelines the requests of each.
const CHUNK: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EntryKind {
    Dir,
    File,
    Other,
}

/// A file or directory on the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteEntry {
    pub name: String,
    /// A symbolic link's is its target's kind (`Other` if it dangles).
    pub kind: EntryKind,
    pub symlink: bool,
    pub size: u64,
    pub modified: Option<SystemTime>,
    /// The mode bits, `0o755` and the like (without the file type).
    pub permissions: Option<u32>,
    pub owner: String,
    pub group: String,
}

impl RemoteEntry {
    fn new(name: String, attrs: &FileAttributes, target: Option<&FileAttributes>) -> Self {
        let symlink = attrs.file_type() == FileType::Symlink;
        let kind_of = |a: &FileAttributes| match a.file_type() {
            FileType::Dir => EntryKind::Dir,
            FileType::File => EntryKind::File,
            _ => EntryKind::Other,
        };
        let shown = if symlink { target } else { Some(attrs) };
        Self {
            name,
            kind: shown.map_or(EntryKind::Other, kind_of),
            symlink,
            size: shown.and_then(|a| a.size).unwrap_or(0),
            modified: attrs.mtime.map(time),
            permissions: attrs.permissions.map(|p| p & 0o7777),
            owner: attrs
                .user
                .clone()
                .or(attrs.uid.map(|u| u.to_string()))
                .unwrap_or_default(),
            group: attrs
                .group
                .clone()
                .or(attrs.gid.map(|g| g.to_string()))
                .unwrap_or_default(),
        }
    }

    pub fn is_dir(&self) -> bool {
        self.kind == EntryKind::Dir
    }
}

fn time(secs: u32) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(u64::from(secs))
}

fn secs(time: SystemTime) -> Option<u32> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u32::try_from(d.as_secs()).ok())
}

/// Told how many bytes of a file are done; returns false to cancel.
pub type Progress<'a> = &'a mut dyn FnMut(u64) -> bool;

/// An SFTP session on a [`Connection`].
pub struct Sftp {
    connection: Connection,
    session: SftpSession,
}

impl Sftp {
    pub(crate) fn new(connection: Connection, session: SftpSession) -> Self {
        Self {
            connection,
            session,
        }
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    fn error(&self, what: &str, path: &str, e: SftpError) -> Error {
        let kind = match &e {
            SftpError::Status(s) if s.status_code == StatusCode::ConnectionLost => {
                ErrorKind::Disconnected
            }
            SftpError::IO(_) if self.connection.is_closed() => ErrorKind::Disconnected,
            _ => ErrorKind::Other,
        };
        let reason = match &e {
            SftpError::Status(s) if !s.error_message.is_empty() => s.error_message.clone(),
            SftpError::Status(s) => s.status_code.to_string(),
            _ if self.connection.is_closed() => "the connection is lost".to_owned(),
            e => e.to_string(),
        };
        Error::with_kind(format!("{what} {path}: {reason}"), kind)
    }

    /// The absolute form of `path` (`.` is the home directory).
    pub fn canonicalize(&self, path: &str) -> Result<String, Error> {
        self.connection
            .block_on(self.session.canonicalize(path))
            .map_err(|e| self.error("resolving", path, e))
    }

    /// The entries of the directory `dir`, without `.` and `..`.
    pub fn list(&self, dir: &str) -> Result<Vec<RemoteEntry>, Error> {
        self.connection.block_on(async {
            let entries = self
                .session
                .read_dir(dir)
                .await
                .map_err(|e| self.error("listing", dir, e))?;
            let mut out = Vec::new();
            for entry in entries {
                let name = entry.file_name();
                if name == "." || name == ".." {
                    continue;
                }
                let attrs = entry.metadata();
                // A link shows what it leads to, as FileZilla does.
                let target = if attrs.file_type() == FileType::Symlink {
                    self.session.metadata(path::join(dir, &name)).await.ok()
                } else {
                    None
                };
                out.push(RemoteEntry::new(name, &attrs, target.as_ref()));
            }
            Ok(out)
        })
    }

    /// What `path` is, following a link; `None` if there is nothing there.
    pub fn stat(&self, path: &str) -> Result<Option<RemoteEntry>, Error> {
        match self.connection.block_on(self.session.metadata(path)) {
            Ok(attrs) => Ok(Some(RemoteEntry::new(
                path::file_name(path).to_owned(),
                &attrs,
                None,
            ))),
            Err(SftpError::Status(s)) if s.status_code == StatusCode::NoSuchFile => Ok(None),
            Err(e) => Err(self.error("reading", path, e)),
        }
    }

    pub fn mkdir(&self, path: &str) -> Result<(), Error> {
        self.connection
            .block_on(self.session.create_dir(path))
            .map_err(|e| self.error("creating the directory", path, e))
    }

    /// Creates `path` and the directories above it that are missing.
    pub fn mkdir_all(&self, path: &str) -> Result<(), Error> {
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

    pub fn remove_file(&self, path: &str) -> Result<(), Error> {
        self.connection
            .block_on(self.session.remove_file(path))
            .map_err(|e| self.error("deleting", path, e))
    }

    pub fn remove_dir(&self, path: &str) -> Result<(), Error> {
        self.connection
            .block_on(self.session.remove_dir(path))
            .map_err(|e| self.error("deleting the directory", path, e))
    }

    /// Deletes the directory `path` with everything in it. Links are
    /// deleted, not followed.
    pub fn remove_all(&self, path: &str, cancel: &dyn Fn() -> bool) -> Result<(), Error> {
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

    pub fn rename(&self, from: &str, to: &str) -> Result<(), Error> {
        self.connection
            .block_on(self.session.rename(from, to))
            .map_err(|e| self.error("renaming", from, e))
    }

    /// Sets the mode bits of `path`, `0o644` and the like.
    pub fn chmod(&self, path: &str, mode: u32) -> Result<(), Error> {
        let attrs = FileAttributes {
            permissions: Some(mode & 0o7777),
            ..FileAttributes::empty()
        };
        self.connection
            .block_on(self.session.set_metadata(path, attrs))
            .map_err(|e| self.error("changing the permissions of", path, e))
    }

    /// The files and directories under `dir`, as paths relative to it,
    /// directories before what they hold. Links to directories aren't
    /// followed (they could lead in a circle).
    pub fn walk(
        &self,
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
                out.push((child, entry));
            }
        }
        Ok(out)
    }

    /// Downloads `remote` to `local`, from `offset` on: 0 writes a new file,
    /// more appends to the part already there. Gives the file the server's
    /// time.
    pub fn download(
        &self,
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
        let modified = self.connection.block_on(async {
            let mut file = self
                .session
                .open(remote)
                .await
                .map_err(|e| self.error("opening", remote, e))?;
            let modified = file.metadata().await.ok().and_then(|a| a.mtime);
            if offset > 0 {
                file.seek(SeekFrom::Start(offset))
                    .await
                    .map_err(|e| self.error("resuming", remote, e.into()))?;
            }
            let mut done = offset;
            let mut buffer = vec![0; CHUNK];
            loop {
                let n = file
                    .read(&mut buffer)
                    .await
                    .map_err(|e| self.error("reading", remote, e.into()))?;
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
            let _ = file.shutdown().await;
            Ok(modified)
        })?;
        out.flush().map_err(|e| local_error("writing", e))?;
        if let Some(mtime) = modified {
            let _ = out.set_modified(time(mtime));
        }
        out.metadata()
            .map(|m| m.len())
            .map_err(|e| local_error("reading", e))
    }

    /// Uploads `local` to `remote`, from `offset` on: 0 writes a new file,
    /// more appends to the part already there. Gives the file the local
    /// file's time.
    pub fn upload(
        &self,
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
        let done = self.connection.block_on(async {
            let flags = if offset > 0 {
                OpenFlags::WRITE
            } else {
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE
            };
            let mut file = self
                .session
                .open_with_flags(remote, flags)
                .await
                .map_err(|e| self.error("creating", remote, e))?;
            if offset > 0 {
                file.seek(SeekFrom::Start(offset))
                    .await
                    .map_err(|e| self.error("resuming", remote, e.into()))?;
            }
            let mut done = offset;
            let mut buffer = vec![0; CHUNK];
            loop {
                let n = input
                    .read(&mut buffer)
                    .map_err(|e| local_error("reading", e))?;
                if n == 0 {
                    break;
                }
                file.write_all(&buffer[..n])
                    .await
                    .map_err(|e| self.error("writing", remote, e.into()))?;
                done += n as u64;
                if !progress(done) {
                    let _ = file.shutdown().await;
                    return Err(Error::cancelled());
                }
            }
            file.shutdown()
                .await
                .map_err(|e| self.error("writing", remote, e.into()))?;
            Ok(done)
        })?;
        if let Some(mtime) = modified.and_then(secs) {
            let attrs = FileAttributes {
                mtime: Some(mtime),
                atime: Some(mtime),
                ..FileAttributes::empty()
            };
            // Not every server lets the time be set; the file is there.
            if let Err(e) = self
                .connection
                .block_on(self.session.set_metadata(remote, attrs))
            {
                tracing::debug!("setting the time of {remote}: {e}");
            }
        }
        Ok(done)
    }
}
