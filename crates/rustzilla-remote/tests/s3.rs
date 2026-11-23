//! S3's multipart uploads, their resume, and session tokens, against the
//! S3 server in the process (testserver.rs). A binary of its own: the
//! part size is set for the whole process.

use std::fs;
use std::path::{Path, PathBuf};

use rustzilla_remote::testserver::{S3TestServer, set_s3_part_size};
use rustzilla_remote::{ErrorKind, Params, Session};

const MIB: u64 = 1024 * 1024;

fn setup(name: &str) -> PathBuf {
    // 5 MiB parts (S3's least): 11 MiB go up in three.
    set_s3_part_size(5 * MIB);
    let dir = std::env::temp_dir().join(format!("rustzilla-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("served/bucket")).unwrap();
    dir
}

fn write_data(dir: &Path, len: u64) -> (PathBuf, Vec<u8>) {
    let data: Vec<u8> = (0..len)
        .map(|i| (i % 251) as u8 ^ (i >> 20) as u8)
        .collect();
    let file = dir.join("big.bin");
    fs::write(&file, &data).unwrap();
    (file, data)
}

fn download(session: &mut Box<dyn Session>, dir: &Path, remote: &str) -> Vec<u8> {
    let local = dir.join("down.bin");
    session.download(remote, &local, 0, &mut |_| true).unwrap();
    fs::read(local).unwrap()
}

#[test]
fn multipart_upload_cancel_and_resume() {
    let dir = setup("s3mp");
    let server = S3TestServer::start(&dir.join("served"));
    let connection = rustzilla_remote::connect(&Params::S3(server.params())).unwrap();
    let mut session = connection.open().unwrap();
    let len = 11 * MIB + 123;
    let (file, data) = write_data(&dir, len);

    // Whole, in three parts.
    assert_eq!(session.stat("/bucket/whole.bin").unwrap(), None);
    let done = session
        .upload(&file, "/bucket/whole.bin", 0, &mut |_| true)
        .unwrap();
    assert_eq!(done, len);
    assert_eq!(server.parts_uploaded(), 3);
    assert_eq!(
        session.stat("/bucket/whole.bin").unwrap().unwrap().size,
        len
    );
    assert!(download(&mut session, &dir, "/bucket/whole.bin") == data);

    // Cancelled in the second part: the first one stays, and the key
    // shows as a file of its size.
    let error = session
        .upload(&file, "/bucket/resumed.bin", 0, &mut |done| done < 7 * MIB)
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Cancelled);
    assert_eq!(server.parts_uploaded(), 4);
    let partial = session.stat("/bucket/resumed.bin").unwrap().unwrap();
    assert!(!partial.is_dir());
    assert_eq!(partial.size, 5 * MIB);
    // Not in the listing: it isn't an object yet.
    let names: Vec<_> = session
        .list("/bucket")
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, ["whole.bin"]);

    // Resumed: the first part is kept, two more go up.
    let mut first = None;
    let done = session
        .upload(&file, "/bucket/resumed.bin", partial.size, &mut |done| {
            first.get_or_insert(done);
            true
        })
        .unwrap();
    assert_eq!(done, len);
    assert_eq!(first, Some(5 * MIB));
    assert_eq!(server.parts_uploaded(), 6);
    assert_eq!(
        session.stat("/bucket/resumed.bin").unwrap().unwrap().size,
        len
    );
    assert!(download(&mut session, &dir, "/bucket/resumed.bin") == data);

    // Cancelled, then uploaded from the start (overwrite): the unfinished
    // upload is aborted, all three parts go up again.
    session
        .upload(&file, "/bucket/again.bin", 0, &mut |done| done < 2 * MIB)
        .unwrap_err();
    assert_eq!(server.parts_uploaded(), 6);
    session
        .upload(&file, "/bucket/again.bin", 0, &mut |done| done < 6 * MIB)
        .unwrap_err();
    assert_eq!(
        session.stat("/bucket/again.bin").unwrap().unwrap().size,
        5 * MIB
    );
    session
        .upload(&file, "/bucket/again.bin", 0, &mut |_| true)
        .unwrap();
    assert_eq!(server.parts_uploaded(), 10);
    assert!(download(&mut session, &dir, "/bucket/again.bin") == data);
    session.remove_file("/bucket/again.bin").unwrap();
    // Nothing unfinished is left of it.
    assert_eq!(session.stat("/bucket/again.bin").unwrap(), None);

    // A resume of a file that changed size keeps no part that doesn't
    // fit: here the first part does, the rest goes up again.
    session
        .upload(&file, "/bucket/changed.bin", 0, &mut |done| done < 11 * MIB)
        .unwrap_err();
    assert_eq!(server.parts_uploaded(), 12);
    let (file, data) = write_data(&dir, 7 * MIB);
    session
        .upload(&file, "/bucket/changed.bin", 10 * MIB, &mut |_| true)
        .unwrap();
    assert_eq!(server.parts_uploaded(), 13);
    assert!(download(&mut session, &dir, "/bucket/changed.bin") == data);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn session_token() {
    let dir = setup("s3token");
    let server = S3TestServer::start_with_token(&dir.join("served"), Some("TOKEN/123+abc=="));
    let connection = rustzilla_remote::connect(&Params::S3(server.params())).unwrap();
    let mut session = connection.open().unwrap();
    // A small file in one PUT, a big one in parts: all with the token.
    fs::write(dir.join("small.txt"), b"small").unwrap();
    session
        .upload(&dir.join("small.txt"), "/bucket/small.txt", 0, &mut |_| {
            true
        })
        .unwrap();
    let (file, data) = write_data(&dir, 6 * MIB);
    session
        .upload(&file, "/bucket/big.bin", 0, &mut |_| true)
        .unwrap();
    assert_eq!(server.parts_uploaded(), 2);
    assert!(download(&mut session, &dir, "/bucket/big.bin") == data);

    // Without the token, or with another: no.
    for token in [None, Some("other".to_owned())] {
        let mut params = server.params();
        params.session_token = token;
        let error = rustzilla_remote::connect(&Params::S3(params))
            .err()
            .unwrap();
        assert!(error.message.contains("session token"), "{error}");
    }
    let _ = fs::remove_dir_all(&dir);
}
