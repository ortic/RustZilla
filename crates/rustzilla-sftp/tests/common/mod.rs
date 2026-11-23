//! The round trip the tests run against each server.

use std::fs;
use std::path::Path;
use std::time::UNIX_EPOCH;

use rustzilla_sftp::{Connection, EntryKind, ErrorKind, SshParams, path};

/// Logs in with `params`, then works in `upload` of the home directory;
/// `dir` is a local directory of the test's own.
pub fn round_trip(params: SshParams, dir: &Path) {
    // Unknown at first; trusted, it connects.
    let connection = match Connection::open(&params) {
        Ok(c) => c,
        Err(e) => {
            let ErrorKind::UnknownHostKey(key) = e.kind else {
                panic!("{e}")
            };
            key.trust().unwrap();
            Connection::open(&params).unwrap()
        }
    };
    let sftp = connection.sftp().unwrap();
    let home = sftp.canonicalize(".").unwrap();
    let base = path::join(
        &path::join(&home, "upload"),
        &format!("it-{}", std::process::id()),
    );
    let never = || false;
    sftp.mkdir_all(&path::join(&base, "a/b")).unwrap();

    // Upload, then download in two parts (resume).
    let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
    let local = dir.join("data.bin");
    fs::write(&local, &data).unwrap();
    let remote = path::join(&base, "a/b/data.bin");
    let mut last = 0;
    let sent = sftp
        .upload(&local, &remote, 0, &mut |done| {
            last = done;
            true
        })
        .unwrap();
    assert_eq!((sent, last), (data.len() as u64, data.len() as u64));
    let entry = sftp.stat(&remote).unwrap().unwrap();
    assert_eq!(
        (entry.kind, entry.size),
        (EntryKind::File, data.len() as u64)
    );

    let back = dir.join("back.bin");
    fs::write(&back, &data[..1000]).unwrap();
    sftp.download(&remote, &back, 1000, &mut |_| true).unwrap();
    assert_eq!(fs::read(&back).unwrap(), data);
    // The time goes up with the file and comes back with it, in seconds.
    let seconds = |p: &std::path::Path| {
        fs::metadata(p)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    };
    assert_eq!(seconds(&back), seconds(&local));

    // A cancelled download stops.
    let error = sftp
        .download(&remote, &dir.join("cut.bin"), 0, &mut |_| false)
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Cancelled);

    // Rename, chmod, list, walk.
    let renamed = path::join(&base, "a/renamed.bin");
    sftp.rename(&remote, &renamed).unwrap();
    sftp.chmod(&renamed, 0o600).unwrap();
    let listing = sftp.list(&path::join(&base, "a")).unwrap();
    let names: Vec<_> = listing.iter().map(|e| e.name.as_str()).collect();
    assert!(
        names.contains(&"b") && names.contains(&"renamed.bin"),
        "{names:?}"
    );
    let file = listing.iter().find(|e| e.name == "renamed.bin").unwrap();
    assert_eq!(file.permissions, Some(0o600));
    let walked: Vec<_> = sftp
        .walk(&base, &never)
        .unwrap()
        .into_iter()
        .map(|(p, _)| p)
        .collect();
    assert!(
        walked.contains(&"a/b".to_owned()) && walked.contains(&"a/renamed.bin".to_owned()),
        "{walked:?}"
    );

    // Errors say what and where.
    let error = sftp.list(&path::join(&base, "missing")).unwrap_err();
    assert!(error.message.contains("missing"), "{error}");

    sftp.remove_all(&base, &never).unwrap();
    assert!(sftp.stat(&base).unwrap().is_none());
    connection.disconnect();
}
