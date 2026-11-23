//! Against the SFTP server in the process (testserver.rs).

mod common;

use std::fs;

use rustzilla_remote::testserver::FtpTestServer;
use rustzilla_remote::testserver::TestServer;
use rustzilla_remote::{Auth, Connection, ErrorKind, FtpEncryption, Params, Security};

#[test]
fn test_server_round_trip() {
    let dir = std::env::temp_dir().join(format!("rustzilla-ts-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("served/upload")).unwrap();
    let server = TestServer::start(&dir.join("served"), &dir.join("known_hosts"));
    common::round_trip(Params::Sftp(server.params()), &dir, common::ALL);
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

#[test]
fn ftp_round_trip() {
    let dir = std::env::temp_dir().join(format!("rustzilla-ftp-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("served/upload")).unwrap();
    let server = FtpTestServer::start(&dir.join("served"), false);
    let params = server.params(FtpEncryption::Plain, &dir.join("certs"));
    let connection = common::trusting_connect(&Params::Ftp(params.clone()));
    assert_eq!(connection.security(), Security::Plain);
    assert!(connection.name().starts_with("ftp://127.0.0.1:"));
    // "If available" on a server without TLS: plain.
    let mut maybe = params.clone();
    maybe.encryption = FtpEncryption::ExplicitIfAvailable;
    let plain = rustzilla_remote::connect(&Params::Ftp(maybe)).unwrap();
    assert_eq!(plain.security(), Security::Plain);
    // Required TLS from a server without: no.
    let mut required = params.clone();
    required.encryption = FtpEncryption::Explicit;
    let error = rustzilla_remote::connect(&Params::Ftp(required))
        .err()
        .unwrap();
    assert!(
        error.message.contains("doesn't offer FTP over TLS"),
        "{error}"
    );
    common::round_trip(Params::Ftp(params), &dir, common::BASIC);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn ftps_with_a_self_signed_certificate() {
    let dir = std::env::temp_dir().join(format!("rustzilla-ftps-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("served/upload")).unwrap();
    let server = FtpTestServer::start(&dir.join("served"), true);
    let params = server.params(FtpEncryption::Explicit, &dir.join("certs"));
    // Not trusted at first: the user sees what it is.
    let error = rustzilla_remote::connect(&Params::Ftp(params.clone()))
        .err()
        .unwrap();
    let ErrorKind::UnknownCertificate(cert) = &error.kind else {
        panic!("{error}")
    };
    assert_eq!(cert.problem, "it is self-signed");
    assert_eq!(cert.fingerprint.len(), 32 * 3 - 1);
    cert.trust().unwrap();
    let connection = rustzilla_remote::connect(&Params::Ftp(params.clone())).unwrap();
    assert_eq!(connection.security(), Security::Tls);
    drop(connection);
    common::round_trip(Params::Ftp(params), &dir, common::BASIC);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn webdav_round_trip() {
    use rustzilla_remote::testserver::WebDavTestServer;
    let dir = std::env::temp_dir().join(format!("rustzilla-dav-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("served/upload")).unwrap();
    let server = WebDavTestServer::start(&dir.join("served"));
    let mut wrong = server.params();
    wrong.password = "nope".into();
    let error = rustzilla_remote::connect(&Params::WebDav(wrong))
        .err()
        .unwrap();
    assert!(error.message.contains("didn't accept"), "{error}");
    let connection = rustzilla_remote::connect(&Params::WebDav(server.params())).unwrap();
    assert!(connection.name().starts_with("dav://127.0.0.1:"));
    assert_eq!(connection.security(), Security::Plain);
    common::round_trip(Params::WebDav(server.params()), &dir, common::BASIC);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn s3_round_trip() {
    use rustzilla_remote::testserver::S3TestServer;
    let dir = std::env::temp_dir().join(format!("rustzilla-s3-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("served/upload")).unwrap();
    let server = S3TestServer::start(&dir.join("served"));
    let mut wrong = server.params();
    wrong.secret_key = "nope".into();
    let error = rustzilla_remote::connect(&Params::S3(wrong)).err().unwrap();
    assert!(error.message.contains("didn't accept the keys"), "{error}");
    // The root lists the buckets.
    let connection = rustzilla_remote::connect(&Params::S3(server.params())).unwrap();
    let mut session = connection.open().unwrap();
    let buckets: Vec<_> = session
        .list("/")
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(buckets, ["upload"]);
    common::round_trip(
        Params::S3(server.params()),
        &dir,
        common::Caps {
            chmod: false,
            empty_dirs: false,
        },
    );
    let _ = fs::remove_dir_all(&dir);
}
