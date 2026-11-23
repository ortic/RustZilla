//! The round trip the tests run against each server.

use std::fs;
use std::path::Path;
use std::time::UNIX_EPOCH;

use rustzilla_remote::{EntryKind, ErrorKind, Params, Server, connect, path};

/// Connects; trusts an unknown host key or certificate first.
pub fn trusting_connect(params: &Params) -> std::sync::Arc<dyn Server> {
    match connect(params) {
        Ok(c) => c,
        Err(e) => {
            match e.kind {
                ErrorKind::UnknownHostKey(key) => key.trust().unwrap(),
                ErrorKind::UnknownCertificate(cert) => cert.trust().unwrap(),
                _ => panic!("{e}"),
            }
            connect(params).unwrap()
        }
    }
}

/// What a server can do beyond the basics.
#[derive(Clone, Copy)]
pub struct Caps {
    /// Changes permissions and keeps file times (SFTP).
    pub chmod: bool,
    /// Lists empty folders (S3 test servers without folder markers don't).
    pub empty_dirs: bool,
}

#[allow(dead_code)]
pub const ALL: Caps = Caps {
    // The test server keeps Unix modes only on Unix.
    chmod: cfg!(unix),
    empty_dirs: true,
};
#[allow(dead_code)]
pub const BASIC: Caps = Caps {
    chmod: false,
    empty_dirs: true,
};

/// Logs in with `params`, then works in `upload` of the home directory;
/// `dir` is a local directory of the test's own.
pub fn round_trip(params: Params, dir: &Path, caps: Caps) {
    let chmod = caps.chmod;
    let connection = trusting_connect(&params);
    let mut sftp = connection.open().unwrap();
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
    if chmod {
        assert_eq!(seconds(&back), seconds(&local));
    }

    // A cancelled download stops.
    let error = sftp
        .download(&remote, &dir.join("cut.bin"), 0, &mut |_| false)
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Cancelled);

    // Rename, chmod, list, walk.
    let renamed = path::join(&base, "a/renamed.bin");
    sftp.rename(&remote, &renamed).unwrap();
    if chmod {
        sftp.chmod(&renamed, 0o600).unwrap();
    }
    let listing = sftp.list(&path::join(&base, "a")).unwrap();
    let names: Vec<_> = listing.iter().map(|e| e.name.as_str()).collect();
    assert!(
        (names.contains(&"b") || !caps.empty_dirs) && names.contains(&"renamed.bin"),
        "{names:?}"
    );
    let file = listing.iter().find(|e| e.name == "renamed.bin").unwrap();
    if chmod {
        assert_eq!(file.permissions, Some(0o600));
    }
    // A second session works alongside.
    let mut other = connection.open().unwrap();
    assert!(other.stat(&renamed).unwrap().is_some());
    let walked: Vec<_> = sftp
        .walk(&base, &never)
        .unwrap()
        .into_iter()
        .map(|(p, _)| p)
        .collect();
    assert!(
        (walked.contains(&"a/b".to_owned()) || !caps.empty_dirs)
            && walked.contains(&"a/renamed.bin".to_owned()),
        "{walked:?}"
    );

    // Errors say what and where.
    let error = sftp.list(&path::join(&base, "missing")).unwrap_err();
    assert!(error.message.contains("missing"), "{error}");

    sftp.remove_all(&base, &never).unwrap();
    assert!(sftp.stat(&base).unwrap().is_none());
    connection.disconnect();
}
