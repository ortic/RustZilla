//! Directory comparison, as FileZilla's: what's only on one side, what's
//! newer, and what differs in size.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::pane::Row;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    /// Not on the other side.
    Only,
    /// Newer than the other side's.
    Newer,
    /// Of another size than the other side's (or a file there, a
    /// directory here).
    Different,
}

/// The marks of the local and of the remote rows.
pub fn compare(local: &[Row], remote: &[Row]) -> (HashMap<String, Mark>, HashMap<String, Mark>) {
    let by_name = |rows: &[Row]| -> HashMap<String, Row> {
        rows.iter().map(|r| (r.name.clone(), r.clone())).collect()
    };
    let (l, r) = (by_name(local), by_name(remote));
    let mut local_marks = HashMap::new();
    let mut remote_marks = HashMap::new();
    for (name, here) in &l {
        let Some(there) = r.get(name) else {
            local_marks.insert(name.clone(), Mark::Only);
            continue;
        };
        if here.is_dir && there.is_dir {
            continue;
        }
        if here.is_dir != there.is_dir || here.size != there.size {
            local_marks.insert(name.clone(), Mark::Different);
            remote_marks.insert(name.clone(), Mark::Different);
            continue;
        }
        match newer(here.modified, there.modified) {
            Some(true) => {
                local_marks.insert(name.clone(), Mark::Newer);
            }
            Some(false) => {
                remote_marks.insert(name.clone(), Mark::Newer);
            }
            None => {}
        }
    }
    for name in r.keys() {
        if !l.contains_key(name) {
            remote_marks.insert(name.clone(), Mark::Only);
        }
    }
    (local_marks, remote_marks)
}

/// Whether the local time is the newer one; `None` when they're the same
/// as far as both sides tell. Listings with whole minutes (FTP's `LIST`)
/// are compared by the minute.
fn newer(local: Option<SystemTime>, remote: Option<SystemTime>) -> Option<bool> {
    let secs = |t: SystemTime| t.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs());
    let (mut l, mut r) = (secs(local?)?, secs(remote?)?);
    if r % 60 == 0 {
        (l, r) = (l / 60, r / 60);
    }
    match l.cmp(&r) {
        std::cmp::Ordering::Greater => Some(true),
        std::cmp::Ordering::Less => Some(false),
        std::cmp::Ordering::Equal => None,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn row(name: &str, is_dir: bool, size: u64, secs: u64) -> Row {
        Row {
            name: name.into(),
            is_dir,
            symlink: false,
            size,
            modified: Some(UNIX_EPOCH + Duration::from_secs(secs)),
            permissions: None,
            owner: String::new(),
        }
    }

    #[test]
    fn marks_both_sides() {
        let local = [
            row("only-local", false, 1, 1000),
            row("same", false, 5, 1000),
            row("bigger", false, 9, 1000),
            row("newer-here", false, 5, 2000),
            row("dir", true, 0, 1000),
            row("kind", true, 0, 1000),
            // Seconds against a minute-precise listing: the same minute.
            row("minute", false, 5, 6_005),
        ];
        let remote = [
            row("only-remote", false, 1, 1000),
            row("same", false, 5, 1000),
            row("bigger", false, 7, 1000),
            row("newer-here", false, 5, 1000),
            row("dir", true, 0, 5000),
            row("kind", false, 0, 1000),
            row("minute", false, 5, 6_000),
        ];
        let (l, r) = compare(&local, &remote);
        assert_eq!(l.get("only-local"), Some(&Mark::Only));
        assert_eq!(r.get("only-remote"), Some(&Mark::Only));
        assert_eq!(l.get("same"), None);
        assert_eq!(r.get("same"), None);
        assert_eq!(l.get("bigger"), Some(&Mark::Different));
        assert_eq!(r.get("bigger"), Some(&Mark::Different));
        assert_eq!(l.get("newer-here"), Some(&Mark::Newer));
        assert_eq!(r.get("newer-here"), None);
        assert_eq!((l.get("dir"), r.get("dir")), (None, None));
        assert_eq!(l.get("kind"), Some(&Mark::Different));
        assert_eq!((l.get("minute"), r.get("minute")), (None, None));
    }
}
