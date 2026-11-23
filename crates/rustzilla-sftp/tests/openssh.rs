//! Against a real OpenSSH server: `docker compose up -d`, then
//! `RUSTZILLA_TEST_SFTP=1 cargo test -p rustzilla-sftp --test openssh`.
//! `RUSTZILLA_TEST_SFTP=host:port:user:password` points elsewhere; the user
//! needs to be able to write in `upload` in its home directory.

mod common;

use std::fs;

use rustzilla_sftp::{Auth, SshParams};

fn params(dir: &std::path::Path) -> Option<SshParams> {
    let setting = std::env::var("RUSTZILLA_TEST_SFTP").ok()?;
    let parts: Vec<&str> = setting.splitn(4, ':').collect();
    let (host, port, user, password) = match parts[..] {
        [h, p, u, pw] => (h, p.parse().expect("a port"), u, pw),
        _ => ("127.0.0.1", 2222, "rustzilla", "rustzilla"),
    };
    Some(SshParams {
        host: host.into(),
        port,
        username: user.into(),
        auth: Auth::Password(password.into()),
        pin: None,
        known_hosts: dir.join("known_hosts"),
        on_touch: None,
    })
}

#[test]
fn openssh_round_trip() {
    let dir = std::env::temp_dir().join(format!("rustzilla-it-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let Some(params) = params(&dir) else {
        eprintln!("RUSTZILLA_TEST_SFTP isn't set: skipped");
        return;
    };
    common::round_trip(params, &dir);
    let _ = fs::remove_dir_all(&dir);
}
