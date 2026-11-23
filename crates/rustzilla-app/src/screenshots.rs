//! The main scenes of the UI, driven against the SFTP server in the
//! process. With `RUSTZILLA_SCREENSHOTS=<dir>` they are rendered (wgpu)
//! and saved as PNGs there; without, they run headless as UI tests.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use rustzilla_sftp::testserver::{self, TestServer};

use super::*;

fn out_dir() -> Option<PathBuf> {
    std::env::var_os("RUSTZILLA_SCREENSHOTS").map(PathBuf::from)
}

/// Rendering takes the GPU: one scene at a time.
static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn harness(dark: bool) -> Harness<'static, App> {
    let builder = Harness::builder()
        .with_size(egui::vec2(1280.0, 800.0))
        .with_pixels_per_point(1.5);
    let builder = if out_dir().is_some() {
        builder.wgpu()
    } else {
        builder
    };
    let harness = builder.build_eframe(|cc| App::new(cc, None));
    harness.ctx.set_theme(if dark {
        egui::Theme::Dark
    } else {
        egui::Theme::Light
    });
    harness
}

fn save(harness: &mut Harness<'_, App>, name: &str) {
    harness.run_steps(4);
    let Some(dir) = out_dir() else { return };
    fs::create_dir_all(&dir).unwrap();
    let image = harness.render().expect("render");
    let path = dir.join(format!("{name}.png"));
    image.save(&path).unwrap();
    eprintln!("wrote {}", path.display());
}

/// Steps the UI until `done`, for what worker threads deliver.
fn wait(harness: &mut Harness<'_, App>, what: &str, done: impl Fn(&App) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !done(harness.state()) {
        assert!(Instant::now() < deadline, "waiting for {what}");
        harness.step();
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rustzilla-ui-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// A local and a served directory with some files.
fn fill(local: &Path, served: &Path) {
    fs::create_dir_all(local.join("photos")).unwrap();
    fs::create_dir_all(local.join("site")).unwrap();
    fs::write(local.join("notes.md"), "# Notes\n").unwrap();
    fs::write(local.join("report-2026.pdf"), vec![0u8; 1_234_567]).unwrap();
    fs::write(local.join("backup.tar.gz"), vec![0u8; 4_800_000]).unwrap();
    fs::write(local.join("site/index.html"), "<h1>hi</h1>").unwrap();
    for dir in ["public_html", "logs", "upload"] {
        fs::create_dir_all(served.join(dir)).unwrap();
    }
    fs::write(served.join(".bashrc"), "export EDITOR=vi\n").unwrap();
    fs::write(served.join("deploy.sh"), "#!/bin/sh\n").unwrap();
    fs::write(served.join("database.sql.gz"), vec![1u8; 2_500_000]).unwrap();
    fs::write(served.join("public_html/index.php"), "<?php").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(served.join("deploy.sh"), fs::Permissions::from_mode(0o755)).unwrap();
    }
}

/// Connects the app to `server`, waiting for the remote listing.
fn connect(harness: &mut Harness<'_, App>, server: &TestServer) {
    let ctx = harness.ctx.clone();
    harness.state_mut().connect(
        &ctx,
        Attempt {
            params: server.params(),
            remote_dir: String::new(),
        },
    );
    wait(harness, "the remote listing", |app| {
        app.state == ConnState::Connected && !app.remote.rows.is_empty()
    });
}

#[test]
fn connected_with_transfers() {
    let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = scratch("main");
    let (local, served) = (dir.join("local"), dir.join("served"));
    fill(&local, &served);
    let server = TestServer::start(&served, &dir.join("known_hosts"));
    let mut harness = harness(true);
    harness.state_mut().list_local(&local);
    harness.state_mut().settings.quick_host = "sftp://test@127.0.0.1".into();
    connect(&mut harness, &server);
    {
        let app = harness.state();
        let names: Vec<&str> = app.remote.rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "logs",
                "public_html",
                "upload",
                ".bashrc",
                "database.sql.gz",
                "deploy.sh"
            ]
        );
        let deploy = app.remote.row("deploy.sh").unwrap();
        assert_eq!(format::permissions(deploy), "-rwxr-xr-x");
    }

    // Upload a file and a directory, download one: as the panes do it.
    harness
        .state_mut()
        .remote_action(Action::Open("upload".into()));
    wait(&mut harness, "the upload directory", |app| {
        app.remote.path == "/upload" && !app.remote.busy
    });
    harness.state_mut().local_action(Action::Transfer(vec![
        "report-2026.pdf".into(),
        "site".into(),
    ]));
    wait(&mut harness, "the uploads", |app| {
        app.transfers
            .queue()
            .items
            .iter()
            .filter(|i| !i.is_dir && i.state == State::Done)
            .count()
            == 2
    });
    assert_eq!(
        fs::read(served.join("upload/site/index.html")).unwrap(),
        b"<h1>hi</h1>"
    );
    // The remote pane shows what arrived.
    wait(&mut harness, "the refreshed listing", |app| {
        app.remote.row("report-2026.pdf").is_some() && app.remote.row("site").is_some()
    });
    // Queued for a server that isn't connected: they wait.
    harness.state().transfers.add(
        "backup.example.com",
        vec![NewItem {
            direction: Direction::Upload,
            local: local.join("backup.tar.gz"),
            remote: "/srv/backups/backup.tar.gz".into(),
            is_dir: false,
            size: 4_800_000,
        }],
    );
    harness.state_mut().queue_tab = QueueTab::Queued;
    save(&mut harness, "main-dark");
    harness.state_mut().queue_tab = QueueTab::Done;
    harness.ctx.set_theme(egui::Theme::Light);
    save(&mut harness, "main-light");

    // Mkdir, rename and delete on the server, through the dialogs' actions.
    harness.state_mut().mkdir(Side::Remote, "new-dir");
    wait(&mut harness, "the new directory", |app| {
        app.remote.row("new-dir").is_some()
    });
    harness
        .state_mut()
        .rename(Side::Remote, "new-dir", "renamed");
    wait(&mut harness, "the rename", |app| {
        app.remote.row("renamed").is_some()
    });
    harness
        .state_mut()
        .delete(Side::Remote, &["renamed".into(), "site".into()]);
    wait(&mut harness, "the deletes", |app| {
        app.remote.row("renamed").is_none() && app.remote.row("site").is_none()
    });
    assert!(!served.join("upload/site").exists());
    harness
        .state_mut()
        .chmod(&["report-2026.pdf".into()], 0o600);
    wait(&mut harness, "the permissions", |app| {
        app.remote
            .row("report-2026.pdf")
            .is_some_and(|r| r.permissions == Some(0o600))
    });

    harness.state_mut().disconnect();
    harness.step();
    assert!(harness.state().remote.rows.is_empty());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn target_exists_asks() {
    let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = scratch("exists");
    let (local, served) = (dir.join("local"), dir.join("served"));
    fill(&local, &served);
    fs::write(local.join("database.sql.gz"), vec![1u8; 1_000_000]).unwrap();
    let server = TestServer::start(&served, &dir.join("known_hosts"));
    let mut harness = harness(true);
    harness.state_mut().list_local(&local);
    connect(&mut harness, &server);
    harness
        .state_mut()
        .remote_action(Action::Transfer(vec!["database.sql.gz".into()]));
    wait(&mut harness, "the question", |app| {
        app.transfers
            .queue()
            .items
            .iter()
            .any(|i| matches!(i.state, State::Asking(_)))
    });
    harness.state_mut().exists_choice = Exists::Resume;
    save(&mut harness, "exists");
    harness.get_by_label("OK").click();
    wait(&mut harness, "the resumed download", |app| {
        app.transfers
            .queue()
            .items
            .iter()
            .any(|i| i.state == State::Done)
    });
    assert_eq!(
        fs::read(local.join("database.sql.gz")).unwrap().len(),
        2_500_000
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn unknown_host_key_then_trusted() {
    let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = scratch("hostkey");
    let served = dir.join("served");
    fs::create_dir_all(served.join("www")).unwrap();
    let server = TestServer::start(&served, &dir.join("trusted_by_server"));
    let mut harness = harness(false);
    let mut params = server.params();
    params.known_hosts = dir.join("known_hosts");
    let ctx = harness.ctx.clone();
    harness.state_mut().connect(
        &ctx,
        Attempt {
            params,
            remote_dir: String::new(),
        },
    );
    wait(&mut harness, "the host key question", |app| {
        matches!(app.dialog, Some(Dialog::HostKey(..)))
    });
    save(&mut harness, "host-key");
    harness.get_by_label("Trust and connect").click();
    wait(&mut harness, "the listing", |app| {
        app.remote.row("www").is_some()
    });
    assert!(
        fs::read_to_string(dir.join("known_hosts"))
            .unwrap()
            .contains("[127.0.0.1]:")
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn security_key_prompts() {
    let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = scratch("sk");
    let key_file = dir.join("id_ecdsa_sk");
    testserver::write_security_key_file(&key_file);
    assert!(rustzilla_sftp::is_security_key(&key_file));
    let mut harness = harness(false);
    harness.state_mut().list_local(&dir);
    save(&mut harness, "not-connected");
    harness.ctx.set_theme(egui::Theme::Dark);
    let site = Site {
        name: "Production (YubiKey)".into(),
        host: "web01.example.com".into(),
        user: "deploy".into(),
        logon: Logon::KeyFile,
        key_file: key_file.display().to_string(),
        remote_dir: "/var/www".into(),
        ..Site::default()
    };
    let id = site.id.clone();
    harness.state_mut().sites = vec![
        site,
        Site {
            name: "Backup server".into(),
            host: "backup.example.com".into(),
            user: "backup".into(),
            logon: Logon::Agent,
            ..Site::default()
        },
    ];
    harness.state_mut().open_site_manager(Some(&id));
    save(&mut harness, "site-manager");
    harness.get_by_label("Cancel").click();
    harness.step();
    assert!(harness.state().site_manager.is_none());

    // Waiting for the touch.
    harness.state_mut().state = ConnState::Connecting { touch: true };
    save(&mut harness, "touch");
    harness.get_by_label("Cancel").click();
    harness.step();
    assert!(harness.state().state == ConnState::Idle);

    // The key wants its PIN: asked, then used for the next attempt.
    let attempt = Attempt {
        params: SshParams {
            host: "web01.example.com".into(),
            port: 22,
            username: "deploy".into(),
            auth: Auth::KeyFile {
                path: key_file.clone(),
                passphrase: String::new(),
            },
            pin: None,
            known_hosts: dir.join("known_hosts"),
            on_touch: None,
        },
        remote_dir: String::new(),
    };
    harness.state_mut().dialog = Some(Dialog::Secret {
        kind: SecretKind::Pin,
        message: "logging in to web01.example.com: the security key didn't sign: it needs its PIN"
            .into(),
        value: String::new(),
        attempt: Box::new(attempt),
    });
    save(&mut harness, "pin");
    harness.state_mut().dialog = Some(Dialog::About);
    save(&mut harness, "about");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn hovering_another_menu_switches_to_it() {
    let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut harness = harness(true);
    harness.get_by_label("File").click();
    harness.run_steps(2);
    assert!(harness.query_by_label("Site Manager…").is_some());
    harness.get_by_label("Help").hover();
    harness.run_steps(3);
    assert!(harness.query_by_label("About RustZilla").is_some());
    assert!(harness.query_by_label("Site Manager…").is_none());
    // Without a menu open, hovering opens nothing.
    harness.key_press(egui::Key::Escape);
    harness.run_steps(2);
    harness.get_by_label("View").hover();
    harness.run_steps(3);
    assert!(harness.query_by_label("Message log").is_none());
}
