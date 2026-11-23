//! Against the SFTP server in the process (testserver.rs).

mod common;

use std::fs;

use rustzilla_sftp::testserver::TestServer;
use rustzilla_sftp::{Auth, Connection};

#[test]
fn test_server_round_trip() {
    let dir = std::env::temp_dir().join(format!("rustzilla-ts-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("served/upload")).unwrap();
    let server = TestServer::start(&dir.join("served"), &dir.join("known_hosts"));
    common::round_trip(server.params(), &dir);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn wrong_password_and_unknown_host() {
    let dir = std::env::temp_dir().join(format!("rustzilla-ts2-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let server = TestServer::start(&dir.join("served"), &dir.join("known_hosts"));
    let mut params = server.params();
    params.auth = Auth::Password("wrong".into());
    let error = Connection::open(&params).unwrap_err();
    assert!(
        error.message.contains("didn't accept the password"),
        "{error}"
    );

    let mut params = server.params();
    params.known_hosts = dir.join("other_known_hosts");
    let error = Connection::open(&params).unwrap_err();
    let key = error.host_key().expect("an unknown host key").clone();
    assert!(
        key.fingerprint.starts_with("ssh-ed25519 SHA256:"),
        "{}",
        key.fingerprint
    );
    key.trust().unwrap();
    Connection::open(&params).unwrap().disconnect();
    let _ = fs::remove_dir_all(&dir);
}
