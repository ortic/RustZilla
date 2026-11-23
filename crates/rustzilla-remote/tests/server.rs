//! Against the SFTP server in the process (testserver.rs).

mod common;

use std::fs;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use rustzilla_remote::testserver::FtpTestServer;
use rustzilla_remote::testserver::{self, OTP, TestServer};
use rustzilla_remote::{
    Auth, Connection, ErrorKind, FtpEncryption, Jump, Params, Prompt, Prompts, Security,
};

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
fn webdav_digest_round_trip() {
    use rustzilla_remote::testserver::{DavAuth, WebDavTestServer};
    for (i, algorithms) in [&["MD5"][..], &["SHA-256-sess", "MD5"][..]]
        .into_iter()
        .enumerate()
    {
        let dir =
            std::env::temp_dir().join(format!("rustzilla-dav-digest{i}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("served/upload")).unwrap();
        let server = WebDavTestServer::start_with(&dir.join("served"), DavAuth::Digest(algorithms));
        let mut wrong = server.params();
        wrong.password = "nope".into();
        let error = rustzilla_remote::connect(&Params::WebDav(wrong))
            .err()
            .unwrap();
        assert!(error.message.contains("didn't accept"), "{error}");

        let connection = rustzilla_remote::connect(&Params::WebDav(server.params())).unwrap();
        let mut session = connection.open().unwrap();
        // A nonce that runs out: a listing and an upload go again.
        server.expire_nonce();
        session.list("/").unwrap();
        server.expire_nonce();
        let local = dir.join("small.txt");
        fs::write(&local, b"digest").unwrap();
        let sent = session
            .upload(&local, "/upload/small.txt", 0, &mut |_| true)
            .unwrap();
        assert_eq!(sent, 6);
        assert_eq!(
            fs::read(dir.join("served/upload/small.txt")).unwrap(),
            b"digest"
        );
        session.remove_file("/upload/small.txt").unwrap();
        connection.disconnect();

        common::round_trip(Params::WebDav(server.params()), &dir, common::BASIC);
        // The password never went in the clear.
        assert!(!server.saw_basic());
        let _ = fs::remove_dir_all(&dir);
    }
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

/// Answers what the server asks with `answers`, one per round, recording
/// the questions; cancels when they run out.
fn answering(
    answers: &'static [&'static str],
    asked: &Arc<Mutex<Vec<Prompts>>>,
) -> rustzilla_remote::OnPrompt {
    let asked = asked.clone();
    Arc::new(move |prompts: Prompts| {
        let count = prompts.prompts.len();
        let round = {
            let mut asked = asked.lock().unwrap();
            asked.push(prompts);
            asked.len() - 1
        };
        let answer = answers.get(round)?;
        Some(vec![(*answer).to_owned(); count])
    })
}

#[test]
fn keyboard_interactive_with_a_one_time_code() {
    let dir = std::env::temp_dir().join(format!("rustzilla-kbd-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("served/upload")).unwrap();
    let server = TestServer::start(&dir.join("served"), &dir.join("known_hosts"));
    let mut params = server.params();
    params.username = "otp".into();

    // The password answers "Password:"; the user the code.
    let asked = Arc::new(Mutex::new(Vec::new()));
    params.on_prompt = Some(answering(&[OTP], &asked));
    Connection::open(&params).unwrap().disconnect();
    let asked = asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert_eq!(asked[0].name, "Two-factor authentication");
    assert_eq!(
        asked[0].prompts,
        [Prompt {
            text: "Verification code: ".into(),
            echo: true
        }]
    );
    assert_eq!(asked[0].server, format!("127.0.0.1:{}", server.port));

    // A wrong code.
    let wrong = Arc::new(Mutex::new(Vec::new()));
    params.on_prompt = Some(answering(&["999999"], &wrong));
    let error = Connection::open(&params).unwrap_err();
    assert!(
        error
            .message
            .contains("didn't accept the password and the answers"),
        "{error}"
    );

    // Cancelled.
    let cancelled = Arc::new(Mutex::new(Vec::new()));
    params.on_prompt = Some(answering(&[], &cancelled));
    let error = Connection::open(&params).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Cancelled, "{error}");

    // Nobody to ask.
    params.on_prompt = None;
    let error = Connection::open(&params).unwrap_err();
    assert!(error.message.contains("Verification code"), "{error}");

    // A wrong password: asked again, the user answers it.
    let retried = Arc::new(Mutex::new(Vec::new()));
    params.auth = Auth::Password("wrong".into());
    params.on_prompt = Some(answering(&["test", OTP], &retried));
    common::round_trip(Params::Sftp(params), &dir, common::BASIC);
    let retried = retried.lock().unwrap();
    assert!(!retried.is_empty());
    assert_eq!(retried[0].prompts[0].text, "Password: ");
    assert!(!retried[0].prompts[0].echo);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn key_then_one_time_code() {
    let dir = std::env::temp_dir().join(format!("rustzilla-keyotp-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let server = TestServer::start(&dir.join("served"), &dir.join("known_hosts"));
    let key = dir.join("id_ed25519");
    testserver::write_client_key(&key);
    let mut params = server.params();
    params.username = "keyotp".into();
    params.auth = Auth::KeyFile {
        path: key,
        passphrase: String::new(),
    };
    let asked = Arc::new(Mutex::new(Vec::new()));
    params.on_prompt = Some(answering(&[OTP], &asked));
    Connection::open(&params).unwrap().disconnect();
    assert_eq!(asked.lock().unwrap().len(), 1);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn openssh_certificates() {
    let dir = std::env::temp_dir().join(format!("rustzilla-cert-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("served/upload")).unwrap();
    let server = TestServer::start(&dir.join("served"), &dir.join("known_hosts"));
    let key = dir.join("id_ed25519");
    testserver::write_client_key(&key);
    let mut params = server.params();
    params.username = "cert".into();
    params.auth = Auth::KeyFile {
        path: key.clone(),
        passphrase: String::new(),
    };
    // `cert` takes only the certificate.
    let error = Connection::open(&params).unwrap_err();
    assert!(
        error.message.contains("didn't accept the key file"),
        "{error}"
    );
    testserver::write_certificate(&key, "cert", true);
    common::round_trip(Params::Sftp(params.clone()), &dir, common::BASIC);

    // A certificate the server doesn't take: the key alone.
    testserver::write_certificate(&key, "test", false);
    let error = Connection::open(&params).unwrap_err();
    assert!(
        error.message.contains("didn't accept the key file"),
        "{error}"
    );
    params.username = "test".into();
    Connection::open(&params).unwrap().disconnect();
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn through_a_jump_host() {
    let dir = std::env::temp_dir().join(format!("rustzilla-jump-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("served/upload")).unwrap();
    let server = TestServer::start(&dir.join("served"), &dir.join("known_hosts"));
    // The jump host's key isn't known yet.
    let jump = TestServer::start(&dir.join("jump"), &dir.join("jump_known_hosts"));
    let mut params = server.params();
    params.jump = Jump::parse(&format!("test@127.0.0.1:{}", jump.port)).unwrap();
    let error = Connection::open(&params).unwrap_err();
    assert!(
        error.message.contains("the jump host 127.0.0.1:"),
        "{error}"
    );
    let key = error.host_key().expect("an unknown host key").clone();
    assert_eq!(key.port, jump.port);
    key.trust().unwrap();

    let connection = Connection::open(&params).unwrap();
    assert_eq!(connection.server(), format!("127.0.0.1:{}", server.port));
    assert_eq!(jump.tunnels.load(Ordering::SeqCst), 1);
    connection.disconnect();
    common::round_trip(Params::Sftp(params.clone()), &dir, common::ALL);

    // The user of the server for the jump host, too.
    params.jump = Jump::parse(&format!("127.0.0.1:{}", jump.port)).unwrap();
    Connection::open(&params).unwrap().disconnect();
    // A wrong password fails on the jump host first.
    params.auth = Auth::Password("wrong".into());
    let error = Connection::open(&params).unwrap_err();
    assert!(
        error.message.contains("the jump host 127.0.0.1:")
            && error.message.contains("didn't accept"),
        "{error}"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn jump_hosts_parsed() {
    let parse = |s: &str| Jump::parse(s).unwrap().unwrap();
    assert_eq!(
        parse("bastion"),
        Jump {
            host: "bastion".into(),
            port: 22,
            username: String::new()
        }
    );
    let jump = parse(" admin@bastion.example.com:2222 ");
    assert_eq!(
        (jump.username.as_str(), jump.host.as_str(), jump.port),
        ("admin", "bastion.example.com", 2222)
    );
    assert_eq!(jump.to_string(), "admin@bastion.example.com:2222");
    let jump = parse("[::1]:2200");
    assert_eq!((jump.host.as_str(), jump.port), ("::1", 2200));
    assert_eq!(jump.to_string(), "[::1]:2200");
    assert_eq!(parse("fe80::1").host, "fe80::1");
    assert_eq!(Jump::parse("  ").unwrap(), None);
    assert!(Jump::parse("host:port").is_err());
    assert!(Jump::parse("user@").is_err());
    assert!(Jump::parse("[::1").is_err());
}
