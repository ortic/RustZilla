//! The local file system side.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::pane::Row;

/// The entries of `dir`.
pub fn list(dir: &Path) -> io::Result<Vec<Row>> {
    let mut rows = Vec::new();
    for entry in fs::read_dir(dir)? {
        let Ok(entry) = entry else { continue };
        let symlink = entry.file_type().is_ok_and(|t| t.is_symlink());
        // A link shows what it leads to.
        let meta = fs::metadata(entry.path()).or_else(|_| entry.metadata());
        let Ok(meta) = meta else { continue };
        rows.push(Row {
            name: entry.file_name().to_string_lossy().into_owned(),
            is_dir: meta.is_dir(),
            symlink,
            size: if meta.is_dir() { 0 } else { meta.len() },
            modified: meta.modified().ok(),
            permissions: permissions(&meta),
            owner: String::new(),
        });
    }
    Ok(rows)
}

#[cfg(unix)]
fn permissions(meta: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(meta.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn permissions(_: &fs::Metadata) -> Option<u32> {
    None
}

/// The files under `dir`, with their paths relative to it, and the
/// directories (`true`) before what they hold.
pub fn walk(dir: &Path) -> io::Result<Vec<(PathBuf, bool)>> {
    let mut out = Vec::new();
    let mut pending = vec![PathBuf::new()];
    while let Some(relative) = pending.pop() {
        for entry in fs::read_dir(dir.join(&relative))? {
            let entry = entry?;
            let child = relative.join(entry.file_name());
            // Links to directories aren't followed: they could lead in a
            // circle.
            let kind = entry.file_type()?;
            let is_dir = kind.is_dir();
            if is_dir {
                pending.push(child.clone());
            }
            if is_dir || kind.is_file() || fs::metadata(dir.join(&child)).is_ok_and(|m| m.is_file())
            {
                out.push((child, is_dir));
            }
        }
    }
    Ok(out)
}

/// Deletes files and directories, with everything in them.
pub fn delete(path: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
}

/// The user's home directory, or the current one.
pub fn home() -> PathBuf {
    std::env::home_dir()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_and_walks() {
        let dir = std::env::temp_dir().join(format!("rustzilla-local-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("a/b")).unwrap();
        fs::write(dir.join("a/b/f.txt"), "hello").unwrap();
        fs::write(dir.join("top.txt"), "x").unwrap();
        let mut rows = list(&dir).unwrap();
        rows.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(rows.len(), 2);
        assert!(rows[0].is_dir && rows[0].name == "a");
        assert_eq!((rows[1].name.as_str(), rows[1].size), ("top.txt", 1));
        let mut walked = walk(&dir.join("a")).unwrap();
        walked.sort();
        assert_eq!(
            walked,
            vec![
                (PathBuf::from("b"), true),
                (PathBuf::from("b/f.txt"), false)
            ]
        );
        delete(&dir.join("a")).unwrap();
        assert!(!dir.join("a").exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
