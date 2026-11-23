//! The main window, laid out as FileZilla's: the Quickconnect bar, the
//! message log, the local and the remote side, and the transfer queue.

use std::path::{Path, PathBuf};

use egui::{Color32, RichText, Ui};
use egui_extras::{Column, TableBuilder};
use std::sync::Arc;

use rustzilla_remote::{
    Auth, Certificate, ErrorKind, FtpEncryption, FtpParams, HostKey, Params, Protocol, RemoteEntry,
    S3Params, Security, Server, SshParams, WebDavParams, path,
};
use serde::{Deserialize, Serialize};

use crate::config::{self, Logon, Paths, Site};
use crate::format;
use crate::icons::{self, Icon};
use crate::local;
use crate::pane::{Action, Pane, Row, Side};
use crate::session::{Command, Event, LogKind, Session};
use crate::site_manager::{self, SiteManager};
use crate::theme;
use crate::transfers::{Direction, Exists, Item, NewItem, State, Transfers};

const MAX_LOG: usize = 2000;

/// What a dialog's button does once the dialog is gone.
type Then = Box<dyn FnOnce(&mut App)>;

/// What's kept between runs (in eframe's storage).
#[derive(Serialize, Deserialize)]
#[serde(default)]
struct Settings {
    local_dir: String,
    exists: Exists,
    parallel: usize,
    show_log: bool,
    quick_host: String,
    quick_user: String,
    quick_port: String,
    theme: ThemePref,
    /// Speed limits in KiB/s; 0 for none.
    limit_down: u64,
    limit_up: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
enum ThemePref {
    #[default]
    System,
    Dark,
    Light,
}

impl ThemePref {
    fn egui(self) -> egui::ThemePreference {
        match self {
            ThemePref::System => egui::ThemePreference::System,
            ThemePref::Dark => egui::ThemePreference::Dark,
            ThemePref::Light => egui::ThemePreference::Light,
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            local_dir: String::new(),
            exists: Exists::Ask,
            parallel: 2,
            show_log: true,
            quick_host: String::new(),
            quick_user: String::new(),
            quick_port: String::new(),
            theme: ThemePref::System,
            limit_down: 0,
            limit_up: 0,
        }
    }
}

struct LogLine {
    time: String,
    kind: LogKind,
    text: String,
}

/// What a login needs, whatever the protocol.
struct Login {
    protocol: Protocol,
    encryption: FtpEncryption,
    host: String,
    port: u16,
    username: String,
    auth: Auth,
    /// WebDAV's folder.
    folder: String,
    /// S3's region.
    region: String,
}

/// A connect, kept to try again with what the user adds (a trusted host
/// key, a PIN, a passphrase).
#[derive(Clone)]
struct Attempt {
    params: Params,
    remote_dir: String,
}

#[derive(PartialEq, Eq)]
enum ConnState {
    Idle,
    Connecting { touch: bool },
    Connected,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SecretKind {
    Pin,
    Passphrase,
    Password,
}

enum Dialog {
    HostKey(Box<HostKey>, Box<Attempt>),
    Certificate(Box<Certificate>, Box<Attempt>),
    Secret {
        kind: SecretKind,
        message: String,
        value: String,
        attempt: Box<Attempt>,
    },
    Mkdir {
        side: Side,
        name: String,
    },
    Rename {
        side: Side,
        from: String,
        to: String,
    },
    Delete {
        side: Side,
        names: Vec<String>,
    },
    Chmod {
        names: Vec<String>,
        mode: u32,
        recursive_note: bool,
    },
    Message(String),
    About,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum QueueTab {
    Queued,
    Failed,
    Done,
}

/// One connection's side of the window: its panes, its session and its
/// transfers. The window shows one tab at a time; the others go on.
pub struct Tab {
    local: Pane,
    remote: Pane,
    session: Option<Session>,
    connection: Option<Arc<dyn Server>>,
    state: ConnState,
    attempt: Option<Attempt>,
    transfers: Transfers,
    /// The pane keys act on.
    focus: Side,
    /// The server's home directory, for the Home button.
    remote_home: String,
    /// Whether the connection logged in with a security key.
    security_key_login: bool,
    /// The saved site connected to, for its bookmarks.
    site: Option<Site>,
}

impl Tab {
    fn new(exists: Exists) -> Self {
        let mut remote = Pane::new(Side::Remote);
        remote.clear("Not connected to any server");
        Self {
            local: Pane::new(Side::Local),
            remote,
            session: None,
            connection: None,
            state: ConnState::Idle,
            attempt: None,
            transfers: Transfers::new(exists),
            focus: Side::Local,
            remote_home: String::new(),
            security_key_login: false,
            site: None,
        }
    }

    /// What the tab is called: the site, the server, or "New tab".
    fn title(&self) -> String {
        if let Some(site) = &self.site {
            return site.name.clone();
        }
        match (&self.connection, &self.attempt) {
            (Some(c), _) => c.name().to_owned(),
            (None, Some(a)) => a.params.host().to_owned(),
            _ => "New tab".to_owned(),
        }
    }
}

pub struct App {
    ctx: egui::Context,
    paths: Option<Paths>,
    sites: Vec<Site>,
    settings: Settings,
    quick_password: String,
    log: Vec<LogLine>,
    /// The tab shown.
    tab: Tab,
    /// All tabs, in order; at `active` a stand-in while `tab` is out.
    tabs: Vec<Tab>,
    active: usize,
    dialog: Option<Dialog>,
    site_manager: Option<SiteManager>,
    queue_tab: QueueTab,
    /// The exists dialog's choice.
    exists_choice: Exists,
    exists_all: bool,
}

impl App {
    pub fn new(cc: &eframe::CreationContext, paths: Option<Paths>) -> Self {
        let settings: Settings = cc
            .storage
            .and_then(|s| eframe::get_value(s, "settings"))
            .unwrap_or_default();
        let mut problems = Vec::new();
        let sites = match &paths {
            Some(paths) => config::load_sites(paths).unwrap_or_else(|e| {
                problems.push(e);
                Vec::new()
            }),
            None => Vec::new(),
        };
        let mut app = Self {
            ctx: cc.egui_ctx.clone(),
            paths,
            sites,
            tab: Tab::new(settings.exists),
            tabs: vec![Tab::new(settings.exists)],
            active: 0,
            settings,
            quick_password: String::new(),
            log: Vec::new(),
            dialog: None,
            site_manager: None,
            queue_tab: QueueTab::Queued,
            exists_choice: Exists::Overwrite,
            exists_all: false,
        };
        icons::install(&cc.egui_ctx);
        theme::install(&cc.egui_ctx);
        cc.egui_ctx.set_theme(app.settings.theme.egui());
        let start = Some(PathBuf::from(&app.settings.local_dir))
            .filter(|p| p.is_dir())
            .unwrap_or_else(local::home);
        app.list_local(&start);
        app.apply_limits();
        // What the last run left in the queue waits for its server.
        if let Some(paths) = &app.paths {
            match config::load_queue(paths) {
                Ok(saved) if !saved.is_empty() => {
                    let n = saved.len();
                    for transfer in saved {
                        app.tab.transfers.add(&transfer.server, vec![transfer.item]);
                    }
                    app.log(
                        LogKind::Status,
                        format!(
                            "{n} transfers are left from the last time; they start when you \
                             connect to their server"
                        ),
                    );
                }
                Ok(_) => {}
                Err(e) => problems.push(e),
            }
        }
        for problem in problems {
            app.log(LogKind::Error, problem);
        }
        app
    }

    fn apply_limits(&self) {
        crate::transfers::set_limit(Direction::Download, self.settings.limit_down * 1024);
        crate::transfers::set_limit(Direction::Upload, self.settings.limit_up * 1024);
    }

    fn log(&mut self, kind: LogKind, text: String) {
        if kind == LogKind::Error {
            tracing::warn!("{text}");
        } else {
            tracing::info!("{text}");
        }
        self.log.push(LogLine {
            time: chrono::Local::now().format("%H:%M:%S").to_string(),
            kind,
            text,
        });
        if self.log.len() > MAX_LOG {
            self.log.drain(..self.log.len() - MAX_LOG);
        }
    }

    fn known_hosts(&self) -> PathBuf {
        self.paths
            .as_ref()
            .map(Paths::known_hosts)
            .unwrap_or_else(|| std::env::temp_dir().join("rustzilla_known_hosts"))
    }

    fn trusted_certs(&self) -> PathBuf {
        self.paths
            .as_ref()
            .map(Paths::trusted_certs)
            .unwrap_or_else(|| std::env::temp_dir().join("rustzilla_trusted_certificates"))
    }

    fn server(&self) -> Option<String> {
        self.tab.connection.as_ref().map(|c| c.name().to_owned())
    }

    /// The parameters of a login, by protocol.
    fn params(&self, login: Login) -> Params {
        let Login {
            protocol,
            encryption,
            host,
            port,
            username,
            auth,
            folder,
            region,
        } = login;
        let password = match &auth {
            Auth::Password(p) => p.clone(),
            _ => String::new(),
        };
        let tls = protocol.uses_tls(encryption);
        match protocol {
            Protocol::Sftp => Params::Sftp(SshParams {
                host,
                port,
                username,
                auth,
                pin: None,
                known_hosts: self.known_hosts(),
                on_touch: None,
            }),
            Protocol::Ftp => Params::Ftp(FtpParams {
                host,
                port,
                username,
                password,
                encryption,
                trusted_certs: self.trusted_certs(),
            }),
            Protocol::WebDav => Params::WebDav(WebDavParams {
                host,
                port,
                tls,
                username,
                password,
                root: folder,
            }),
            Protocol::S3 => Params::S3(S3Params {
                host,
                port,
                tls,
                region,
                access_key: username,
                secret_key: password,
            }),
        }
    }

    // Connecting.

    fn quickconnect(&mut self, ctx: &egui::Context) {
        let input = self.settings.quick_host.trim().to_owned();
        let Some(target) = parse_host(&input) else {
            self.dialog = Some(Dialog::Message("Enter the server to connect to.".into()));
            return;
        };
        // A tab with a connection keeps it: the new one gets a tab.
        if self.busy() {
            self.new_tab();
        }
        self.tab.site = None;
        let user = target
            .user
            .clone()
            .unwrap_or_else(|| self.settings.quick_user.trim().to_owned());
        let typed_port: Option<u16> = self.settings.quick_port.trim().parse().ok();
        let port = typed_port.or(target.port);
        // The scheme says the protocol; without one the port does, as
        // FileZilla: 21 FTP, 990 FTPS, anything else SFTP.
        let (protocol, encryption) = target.scheme.unwrap_or(match port {
            Some(21) => (Protocol::Ftp, FtpEncryption::ExplicitIfAvailable),
            Some(990) => (Protocol::Ftp, FtpEncryption::Implicit),
            _ => (Protocol::Sftp, FtpEncryption::ExplicitIfAvailable),
        });
        let port = port.unwrap_or(protocol.default_port(encryption));
        // Without a password: SFTP the SSH agent's keys, as FileZilla does.
        let auth = match (protocol, self.quick_password.is_empty()) {
            (Protocol::Sftp, true) => Auth::Agent,
            _ => Auth::Password(self.quick_password.clone()),
        };
        let folder = target.path.clone().unwrap_or_default();
        let params = self.params(Login {
            protocol,
            encryption,
            host: target.host,
            port,
            username: user,
            auth,
            folder,
            region: String::new(),
        });
        self.connect(
            ctx,
            Attempt {
                params,
                remote_dir: target.path.unwrap_or_default(),
            },
        );
    }

    fn connect_site(&mut self, ctx: &egui::Context, site: &Site, secret: Option<String>) {
        if self.busy() {
            self.new_tab();
        }
        self.tab.site = Some(site.clone());
        if !site.local_dir.trim().is_empty() {
            let dir = site_manager::expand_home(&site.local_dir);
            self.list_local(&dir);
        }
        let secret = secret.or_else(|| crate::secrets::load(&site.id));
        let auth = match site.logon {
            Logon::Normal => Auth::Password(secret.unwrap_or_default()),
            Logon::AskPassword | Logon::Anonymous => Auth::Password(String::new()),
            Logon::KeyFile => Auth::KeyFile {
                path: site_manager::expand_home(&site.key_file),
                passphrase: secret.unwrap_or_default(),
            },
            Logon::Agent => Auth::Agent,
        };
        let user = if site.logon == Logon::Anonymous {
            String::new()
        } else {
            site.user.trim().to_owned()
        };
        let attempt = Attempt {
            params: self.params(Login {
                protocol: site.protocol,
                encryption: site.encryption,
                host: site.host.trim().to_owned(),
                port: site.port,
                username: user,
                auth,
                folder: site.remote_dir.trim().to_owned(),
                region: site.region.trim().to_owned(),
            }),
            remote_dir: site.remote_dir.clone(),
        };
        if site.logon == Logon::AskPassword {
            self.dialog = Some(Dialog::Secret {
                kind: SecretKind::Password,
                message: format!("The password of {} on {}:", site.user, site.host),
                value: String::new(),
                attempt: Box::new(attempt),
            });
            return;
        }
        self.connect(ctx, attempt);
    }

    fn connect(&mut self, ctx: &egui::Context, attempt: Attempt) {
        self.disconnect();
        if let Params::Sftp(SshParams {
            auth: Auth::KeyFile { path, .. },
            ..
        }) = &attempt.params
            && rustzilla_remote::is_security_key(path)
        {
            self.log(
                LogKind::Status,
                format!(
                    "Logging in with the security key of {}: touch it when it blinks",
                    path.display()
                ),
            );
        }
        self.tab.state = ConnState::Connecting { touch: false };
        self.tab.remote.clear("Connecting...");
        self.tab.remote.busy = true;
        self.tab.session = Some(Session::start(
            attempt.params.clone(),
            attempt.remote_dir.clone(),
            ctx.clone(),
        ));
        self.tab.attempt = Some(attempt);
    }

    fn disconnect(&mut self) {
        if let Some(session) = self.tab.session.take() {
            session.send(Command::Disconnect);
        }
        self.tab.transfers.stop();
        self.tab.connection = None;
        if self.tab.state != ConnState::Idle {
            self.tab.state = ConnState::Idle;
            self.tab.remote.clear("Not connected to any server");
        }
    }

    fn poll_session(&mut self, ctx: &egui::Context) {
        let Some(session) = &self.tab.session else {
            return;
        };
        let events: Vec<Event> = session.rx.try_iter().collect();
        for event in events {
            match event {
                Event::Log(kind, text) => self.log(kind, text),
                Event::Touch => {
                    self.tab.state = ConnState::Connecting { touch: true };
                    self.log(LogKind::Status, "Touch your security key".into());
                }
                Event::Connected { connection, home } => {
                    self.log(
                        LogKind::Status,
                        format!("Connected to {}, home directory {home}", connection.name()),
                    );
                    self.tab.transfers.start(
                        connection.clone(),
                        self.settings.parallel,
                        ctx.clone(),
                    );
                    // Transfers for this server waiting in other tabs (or
                    // left from the last run) run here.
                    let name = connection.name().to_owned();
                    let mut moved = Vec::new();
                    for index in (0..self.tabs.len()).filter(|&i| i != self.active) {
                        let other = self.tab_at(index);
                        let served = other.state == ConnState::Connected
                            && other.connection.as_ref().is_some_and(|c| c.name() == name);
                        if !served {
                            moved.extend(other.transfers.take_waiting(&name));
                        }
                    }
                    if !moved.is_empty() {
                        self.tab.transfers.add(&name, moved);
                    }
                    self.tab.connection = Some(connection);
                    self.tab.state = ConnState::Connected;
                    self.tab.remote_home = home;
                    self.tab.security_key_login = matches!(
                        self.tab.attempt.as_ref().map(|a| &a.params),
                        Some(Params::Sftp(SshParams { auth: Auth::KeyFile { path, .. }, .. }))
                            if rustzilla_remote::is_security_key(path)
                    );
                }
                Event::Failed(error) => {
                    self.tab.session = None;
                    self.tab.state = ConnState::Idle;
                    self.tab.remote.clear("Not connected to any server");
                    let attempt = self.tab.attempt.clone().map(Box::new);
                    match (error.kind.clone(), attempt) {
                        (ErrorKind::UnknownHostKey(key), Some(attempt)) => {
                            self.log(LogKind::Status, error.message.clone());
                            self.dialog = Some(Dialog::HostKey(key, attempt));
                        }
                        (ErrorKind::UnknownCertificate(cert), Some(attempt)) => {
                            self.log(LogKind::Status, error.message.clone());
                            self.dialog = Some(Dialog::Certificate(cert, attempt));
                        }
                        (ErrorKind::Pin, Some(attempt)) => {
                            self.log(LogKind::Status, error.message.clone());
                            self.dialog = Some(Dialog::Secret {
                                kind: SecretKind::Pin,
                                message: error.message.clone(),
                                value: String::new(),
                                attempt,
                            });
                        }
                        (ErrorKind::Passphrase, Some(attempt)) => {
                            self.log(LogKind::Status, error.message.clone());
                            self.dialog = Some(Dialog::Secret {
                                kind: SecretKind::Passphrase,
                                message: error.message.clone(),
                                value: String::new(),
                                attempt,
                            });
                        }
                        _ => {
                            self.log(LogKind::Error, format!("Could not connect: {error}"));
                            self.tab.remote.clear(format!("Could not connect: {error}"));
                        }
                    }
                }
                Event::Listing { path, entries } => {
                    let rows = entries.into_iter().map(remote_row).collect();
                    self.tab.remote.set_listing(path, rows);
                }
                Event::ListFailed { path } => {
                    self.tab.remote.busy = false;
                    if self.tab.remote.path.is_empty() {
                        // The start directory isn't there: the home one.
                        self.log(
                            LogKind::Status,
                            format!("{path} can't be listed; showing the home directory"),
                        );
                        if let Some(session) = &self.tab.session {
                            session.send(Command::List(".".into()));
                            self.tab.remote.busy = true;
                        }
                    }
                }
                Event::Changed(dir) => {
                    if dir == self.tab.remote.path {
                        self.list_remote(dir);
                    }
                }
                Event::Disconnected(reason) => {
                    if let Some(reason) = reason {
                        self.log(LogKind::Error, format!("Disconnected: {reason}"));
                    }
                    self.tab.session = None;
                    self.disconnect();
                }
            }
        }
        // A connection that died while idle.
        if self.tab.state == ConnState::Connected
            && self.tab.connection.as_ref().is_some_and(|c| c.is_closed())
        {
            self.log(
                LogKind::Error,
                "The connection to the server is lost".into(),
            );
            self.tab.session = None;
            self.disconnect();
        }
    }

    fn poll_transfers(&mut self) {
        let (local, remote, log) = {
            let mut queue = self.tab.transfers.queue();
            (
                std::mem::take(&mut queue.changed_local),
                std::mem::take(&mut queue.changed_remote),
                std::mem::take(&mut queue.log),
            )
        };
        for (kind, text) in log {
            self.log(kind, text);
        }
        if local.iter().any(|d| Path::new(&self.tab.local.path) == d) {
            let dir = PathBuf::from(&self.tab.local.path);
            self.list_local(&dir);
        }
        if remote.contains(&self.tab.remote.path) {
            self.list_remote(self.tab.remote.path.clone());
        }
    }

    // The panes.

    fn list_local(&mut self, dir: &Path) {
        let dir = dir.canonicalize().unwrap_or_else(|_| dir.to_owned());
        match local::list(&dir) {
            Ok(rows) => {
                self.settings.local_dir = dir.display().to_string();
                self.tab.local.set_listing(dir.display().to_string(), rows);
            }
            Err(e) => {
                self.log(LogKind::Error, format!("Listing {}: {e}", dir.display()));
            }
        }
    }

    fn list_remote(&mut self, dir: String) {
        if let Some(session) = &self.tab.session
            && self.tab.state == ConnState::Connected
        {
            self.tab.remote.busy = true;
            session.send(Command::List(dir));
        }
    }

    fn local_action(&mut self, action: Action) {
        let dir = PathBuf::from(&self.tab.local.path);
        match action {
            Action::Open(name) => self.list_local(&dir.join(name)),
            Action::Up => {
                if let Some(parent) = dir.parent() {
                    self.list_local(parent);
                }
            }
            Action::Navigate(path) => self.list_local(&site_manager::expand_home(&path)),
            Action::Home => self.list_local(&local::home()),
            Action::SiteManager => self.open_site_manager(None),
            Action::Refresh => self.list_local(&dir),
            Action::Transfer(names) => self.upload(&names),
            Action::Dropped(names) => self.download(&names),
            Action::Mkdir => {
                self.dialog = Some(Dialog::Mkdir {
                    side: Side::Local,
                    name: String::new(),
                })
            }
            Action::Rename(name) => {
                self.dialog = Some(Dialog::Rename {
                    side: Side::Local,
                    to: name.clone(),
                    from: name,
                })
            }
            Action::Delete(names) => {
                self.dialog = Some(Dialog::Delete {
                    side: Side::Local,
                    names,
                })
            }
            Action::Permissions(_) => {}
        }
    }

    fn remote_action(&mut self, action: Action) {
        let dir = self.tab.remote.path.clone();
        match action {
            Action::Open(name) => self.list_remote(path::join(&dir, &name)),
            Action::Up => self.list_remote(path::parent(&dir)),
            Action::Navigate(path) => self.list_remote(path),
            Action::Home => self.list_remote(self.tab.remote_home.clone()),
            Action::SiteManager => self.open_site_manager(None),
            Action::Refresh => self.list_remote(dir),
            Action::Transfer(names) => self.download(&names),
            Action::Dropped(names) => self.upload(&names),
            Action::Mkdir => {
                self.dialog = Some(Dialog::Mkdir {
                    side: Side::Remote,
                    name: String::new(),
                })
            }
            Action::Rename(name) => {
                self.dialog = Some(Dialog::Rename {
                    side: Side::Remote,
                    to: name.clone(),
                    from: name,
                })
            }
            Action::Delete(names) => {
                self.dialog = Some(Dialog::Delete {
                    side: Side::Remote,
                    names,
                })
            }
            Action::Permissions(names) => {
                let mode = names
                    .first()
                    .and_then(|n| self.tab.remote.row(n))
                    .and_then(|r| r.permissions)
                    .unwrap_or(0o644);
                let recursive_note = names
                    .iter()
                    .any(|n| self.tab.remote.row(n).is_some_and(|r| r.is_dir));
                self.dialog = Some(Dialog::Chmod {
                    names,
                    mode,
                    recursive_note,
                });
            }
        }
    }

    /// Queues the local entries `names` for upload to the remote directory.
    fn upload(&mut self, names: &[String]) {
        let Some(server) = self.server() else {
            self.log(LogKind::Error, "Connect to a server to upload".into());
            return;
        };
        let dir = PathBuf::from(&self.tab.local.path);
        let items = names
            .iter()
            .filter_map(|name| {
                let row = self.tab.local.row(name)?;
                Some(NewItem {
                    direction: Direction::Upload,
                    local: dir.join(name),
                    remote: path::join(&self.tab.remote.path, name),
                    is_dir: row.is_dir,
                    size: row.size,
                })
            })
            .collect();
        self.tab.transfers.add(&server, items);
        self.queue_tab = QueueTab::Queued;
    }

    /// Uploads files dropped on the window from the desktop.
    fn upload_paths(&mut self, paths: Vec<PathBuf>) {
        let Some(server) = self.server() else {
            self.log(LogKind::Error, "Connect to a server to upload".into());
            return;
        };
        let items = paths
            .into_iter()
            .filter_map(|local| {
                let meta = std::fs::metadata(&local).ok()?;
                let name = local.file_name()?.to_string_lossy().into_owned();
                Some(NewItem {
                    direction: Direction::Upload,
                    remote: path::join(&self.tab.remote.path, &name),
                    local,
                    is_dir: meta.is_dir(),
                    size: if meta.is_dir() { 0 } else { meta.len() },
                })
            })
            .collect();
        self.tab.transfers.add(&server, items);
    }

    /// Queues the remote entries `names` for download to the local
    /// directory.
    fn download(&mut self, names: &[String]) {
        let Some(server) = self.server() else {
            return;
        };
        let dir = PathBuf::from(&self.tab.local.path);
        let items = names
            .iter()
            .filter_map(|name| {
                let row = self.tab.remote.row(name)?;
                Some(NewItem {
                    direction: Direction::Download,
                    local: dir.join(name),
                    remote: path::join(&self.tab.remote.path, name),
                    is_dir: row.is_dir,
                    size: row.size,
                })
            })
            .collect();
        self.tab.transfers.add(&server, items);
        self.queue_tab = QueueTab::Queued;
    }

    // Drawing.

    fn menu_bar(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        egui::MenuBar::new().ui(ui, |ui| {
            let mut menus = Vec::new();
            let file = ui.menu_button("File", |ui| {
                ui.set_min_width(200.0);
                if icons::menu_item(ui, Icon::Server, "Site Manager…", true) {
                    self.open_site_manager(None);
                    ui.close();
                }
                if icons::menu_item(ui, Icon::Plus, "New tab   Ctrl+T", true) {
                    self.new_tab();
                    ui.close();
                }
                if icons::menu_item(ui, Icon::Close, "Close tab   Ctrl+W", true) {
                    self.close_tab(self.active);
                    ui.close();
                }
                ui.separator();
                let connected = self.tab.state != ConnState::Idle;
                if icons::menu_item(ui, Icon::Reconnect, "Reconnect", self.tab.attempt.is_some()) {
                    self.reconnect(ctx);
                    ui.close();
                }
                if icons::menu_item(ui, Icon::Disconnect, "Disconnect", connected) {
                    self.disconnect();
                    ui.close();
                }
                if !self.sites.is_empty() {
                    ui.separator();
                    if let Some(site) = self.sites_menu(ui) {
                        self.connect_site(ctx, &site, None);
                    }
                }
                ui.separator();
                if icons::menu_item(ui, Icon::Quit, "Quit", true) {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
            menus.push(file.response);
            let transfer = ui.menu_button("Transfer", |ui| {
                ui.set_min_width(220.0);
                ui.weak("If the target file exists:");
                let mut policy = self.settings.exists;
                for option in Exists::ALL {
                    if ui
                        .radio_value(&mut policy, option, option.label())
                        .clicked()
                    {
                        ui.close();
                    }
                }
                if policy != self.settings.exists {
                    self.set_policy(policy);
                }
                ui.separator();
                if icons::menu_item(ui, Icon::Stop, "Cancel all transfers", true) {
                    self.each_transfers(Transfers::cancel_all);
                    ui.close();
                }
                if icons::menu_item(ui, Icon::Trash, "Clear finished transfers", true) {
                    self.each_transfers(Transfers::remove_finished);
                    ui.close();
                }
                if icons::menu_item(ui, Icon::Refresh, "Retry failed transfers", true) {
                    self.each_transfers(Transfers::retry_failed);
                    ui.close();
                }
                ui.separator();
                ui.weak("Speed limits (0: none)");
                let before = (self.settings.limit_down, self.settings.limit_up);
                egui::Grid::new("limits").num_columns(3).show(ui, |ui| {
                    for (icon, label, value) in [
                        (Icon::Download, "Downloads", &mut self.settings.limit_down),
                        (Icon::Upload, "Uploads", &mut self.settings.limit_up),
                    ] {
                        ui.add(icon.sized(ui, 14.0));
                        ui.label(label);
                        ui.add(
                            egui::DragValue::new(value)
                                .range(0..=1_000_000)
                                .speed(10)
                                .suffix(" KiB/s"),
                        );
                        ui.end_row();
                    }
                });
                if before != (self.settings.limit_down, self.settings.limit_up) {
                    self.apply_limits();
                }
            });
            menus.push(transfer.response);
            let view = ui.menu_button("View", |ui| {
                ui.set_min_width(200.0);
                ui.checkbox(&mut self.settings.show_log, "Message log");
                ui.separator();
                ui.weak("Theme");
                for (pref, label) in [
                    (ThemePref::System, "Follow the system"),
                    (ThemePref::Dark, "Dark"),
                    (ThemePref::Light, "Light"),
                ] {
                    if ui
                        .radio_value(&mut self.settings.theme, pref, label)
                        .clicked()
                    {
                        ctx.set_theme(pref.egui());
                    }
                }
                ui.separator();
                if icons::menu_item(ui, Icon::Refresh, "Refresh both sides", true) {
                    self.refresh_both();
                    ui.close();
                }
            });
            menus.push(view.response);
            let help = ui.menu_button("Help", |ui| {
                if icons::menu_item(ui, Icon::Info, "About RustZilla", true) {
                    self.dialog = Some(Dialog::About);
                    ui.close();
                }
            });
            menus.push(help.response);
            switch_menus_on_hover(ctx, &menus);
        });
    }

    /// The saved sites as menu entries; the one clicked.
    fn sites_menu(&self, ui: &mut Ui) -> Option<Site> {
        let mut chosen = None;
        for site in &self.sites {
            let icon = match site.logon {
                Logon::KeyFile
                    if rustzilla_remote::is_security_key(&site_manager::expand_home(
                        &site.key_file,
                    )) =>
                {
                    Icon::SecurityKey
                }
                Logon::KeyFile => Icon::Key,
                _ => Icon::Server,
            };
            if icons::menu_item(ui, icon, &site.name, true) {
                chosen = Some(site.clone());
                ui.close();
            }
        }
        chosen
    }

    fn refresh_both(&mut self) {
        let dir = PathBuf::from(&self.tab.local.path);
        self.list_local(&dir);
        self.list_remote(self.tab.remote.path.clone());
    }

    fn reconnect(&mut self, ctx: &egui::Context) {
        if let Some(attempt) = self.tab.attempt.clone() {
            self.connect(ctx, attempt);
        }
    }

    fn open_site_manager(&mut self, select: Option<&str>) {
        self.site_manager = Some(SiteManager::new(self.sites.clone(), select));
    }

    /// The toolbar, then the Quickconnect bar.
    fn toolbar(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 2.0;
            if icons::icon_text_button(ui, Icon::Server, "Site Manager")
                .on_hover_text("Saved sites and how to log in to them")
                .clicked()
            {
                self.open_site_manager(None);
            }
            let mut chosen = None;
            ui.add_enabled_ui(!self.sites.is_empty(), |ui| {
                egui::containers::menu::MenuButton::from_button(
                    egui::Button::image(Icon::ChevronDown.mono(Color32::WHITE))
                        .frame_when_inactive(false)
                        .image_tint_follows_text_color(true)
                        .min_size(egui::vec2(18.0, 26.0)),
                )
                .ui(ui, |ui| chosen = self.sites_menu(ui))
                .0
                .on_hover_text("Connect to a saved site");
            });
            if let Some(site) = chosen {
                self.connect_site(ctx, &site, None);
            }
            ui.separator();
            let connected = self.tab.state == ConnState::Connected;
            if icons::icon_button(ui, Icon::Refresh, "Refresh both sides (F5)").clicked() {
                self.refresh_both();
            }
            let log_tip = if self.settings.show_log {
                "Hide the message log"
            } else {
                "Show the message log"
            };
            if ui
                .add(
                    egui::Button::image(Icon::Log.mono(Color32::WHITE))
                        .selected(self.settings.show_log)
                        .frame_when_inactive(false)
                        .image_tint_follows_text_color(true)
                        .min_size(egui::vec2(26.0, 26.0)),
                )
                .on_hover_text(log_tip)
                .clicked()
            {
                self.settings.show_log = !self.settings.show_log;
            }
            if icons::icon_button(ui, Icon::Stop, "Cancel all transfers").clicked() {
                self.each_transfers(Transfers::cancel_all);
            }
            ui.separator();
            ui.add_enabled_ui(self.tab.state != ConnState::Idle, |ui| {
                if icons::icon_button(ui, Icon::Disconnect, "Disconnect").clicked() {
                    self.disconnect();
                }
            });
            ui.add_enabled_ui(self.tab.attempt.is_some() && !connected, |ui| {
                if icons::icon_button(ui, Icon::Reconnect, "Reconnect").clicked() {
                    self.reconnect(ctx);
                }
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let dark = ui.visuals().dark_mode;
                let (icon, tip) = if dark {
                    (Icon::Sun, "Light theme")
                } else {
                    (Icon::Moon, "Dark theme")
                };
                if icons::icon_button(ui, icon, tip).clicked() {
                    self.settings.theme = if dark {
                        ThemePref::Light
                    } else {
                        ThemePref::Dark
                    };
                    ctx.set_theme(self.settings.theme.egui());
                }
            });
        });
        ui.add_space(2.0);
        self.quickconnect_bar(ui, ctx);
    }

    fn quickconnect_bar(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            let field = |ui: &mut Ui, label: &str, text: &mut String, hint: &str, width: f32| {
                ui.label(RichText::new(label).color(ui.visuals().weak_text_color()));
                ui.add(
                    egui::TextEdit::singleline(text)
                        .hint_text(hint)
                        .margin(egui::Margin::symmetric(6, 4))
                        .desired_width(width),
                )
            };
            let host = field(
                ui,
                "Host",
                &mut self.settings.quick_host,
                "sftp://example.com",
                200.0,
            )
            .on_hover_text(
                "sftp://host  ·  ftp://host (TLS if available)  ·  ftpes://host (explicit TLS)  ·  \
                 ftps://host (implicit TLS)  ·  davs://host/folder (WebDAV)  ·  \
                 s3://endpoint (S3; access key as user, secret key as password)\n\
                 Without a scheme: port 21 is FTP, 990 FTPS, anything else SFTP.",
            );
            let user = field(ui, "Username", &mut self.settings.quick_user, "", 120.0);
            ui.label(RichText::new("Password").color(ui.visuals().weak_text_color()));
            let password = ui.add(
                egui::TextEdit::singleline(&mut self.quick_password)
                    .password(true)
                    .hint_text("SSH agent if empty")
                    .margin(egui::Margin::symmetric(6, 4))
                    .desired_width(130.0),
            );
            let port = field(ui, "Port", &mut self.settings.quick_port, "22", 44.0);
            let enter = [host, user, password, port].iter().any(|r| r.lost_focus())
                && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if ui.add(theme::primary_button("Quickconnect")).clicked() || enter {
                self.quickconnect(ctx);
            }
        });
    }

    fn log_ui(&mut self, ui: &mut Ui) {
        egui::ScrollArea::vertical()
            .auto_shrink(false)
            .stick_to_bottom(true)
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 1.0;
                for line in &self.log {
                    let (icon, color) = log_style(ui, line.kind);
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(&line.time)
                                .monospace()
                                .color(ui.visuals().weak_text_color()),
                        );
                        ui.add(icon.sized(ui, 14.0));
                        ui.add(egui::Label::new(RichText::new(&line.text).color(color)).wrap());
                    });
                }
                if self.log.is_empty() {
                    ui.weak("Messages about connections and transfers appear here.");
                }
            });
    }

    /// The transfers of every tab, with the tab's index.
    fn all_items(&self) -> Vec<(usize, Item)> {
        (0..self.tabs.len())
            .flat_map(|t| {
                self.tab_at(t)
                    .transfers
                    .queue()
                    .items
                    .iter()
                    .map(|i| (t, i.clone()))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    fn each_transfers(&self, f: impl Fn(&Transfers)) {
        for t in 0..self.tabs.len() {
            f(&self.tab_at(t).transfers);
        }
    }

    fn set_policy(&mut self, policy: Exists) {
        self.each_transfers(|t| t.queue().policy = policy);
        self.settings.exists = policy;
    }

    fn queue_ui(&mut self, ui: &mut Ui) {
        let items = self.all_items();
        let queued: Vec<&(usize, Item)> = items
            .iter()
            .filter(|(_, i)| matches!(i.state, State::Queued | State::Active | State::Asking(_)))
            .collect();
        let failed: Vec<&(usize, Item)> = items
            .iter()
            .filter(|(_, i)| {
                matches!(
                    i.state,
                    State::Failed(_) | State::Cancelled | State::Skipped(_)
                )
            })
            .collect();
        let done: Vec<&(usize, Item)> = items
            .iter()
            .filter(|(_, i)| i.state == State::Done && !i.is_dir)
            .collect();
        ui.horizontal(|ui| {
            ui.set_min_height(28.0);
            for (tab, icon, label, n) in [
                (QueueTab::Queued, Icon::Queue, "Queued files", queued.len()),
                (
                    QueueTab::Failed,
                    Icon::Error,
                    "Failed transfers",
                    failed.len(),
                ),
                (
                    QueueTab::Done,
                    Icon::Success,
                    "Successful transfers",
                    done.len(),
                ),
            ] {
                let image = if icon.is_colored() && n > 0 {
                    icon.sized(ui, 14.0)
                } else {
                    icon.mono(ui.visuals().text_color())
                        .fit_to_exact_size(egui::vec2(14.0, 14.0))
                };
                let text = format!("{label}  {n}");
                let button = egui::Button::image_and_text(image, text)
                    .selected(self.queue_tab == tab)
                    .frame_when_inactive(false)
                    .corner_radius(13)
                    .min_size(egui::vec2(0.0, 26.0));
                if ui.add(button).clicked() {
                    self.queue_tab = tab;
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.queue_tab == QueueTab::Failed
                    && icons::icon_button(ui, Icon::Refresh, "Retry all failed transfers").clicked()
                {
                    self.each_transfers(Transfers::retry_failed);
                }
                if icons::icon_button(ui, Icon::Trash, "Clear finished transfers").clicked() {
                    self.each_transfers(Transfers::remove_finished);
                }
                if icons::icon_button(ui, Icon::Stop, "Cancel all transfers").clicked() {
                    self.each_transfers(Transfers::cancel_all);
                }
                ui.separator();
                let before = self.settings.parallel;
                ui.add(
                    egui::DragValue::new(&mut self.settings.parallel)
                        .range(1..=10)
                        .speed(0.05),
                )
                .on_hover_text("How many files transfer at the same time");
                ui.label(RichText::new("Parallel").color(ui.visuals().weak_text_color()));
                if before != self.settings.parallel
                    && let Some(connection) = self.tab.connection.clone()
                {
                    self.tab
                        .transfers
                        .start(connection, self.settings.parallel, ui.ctx().clone());
                }
                ui.separator();
                let mut policy = self.settings.exists;
                egui::ComboBox::from_id_salt("exists-policy")
                    .selected_text(policy.label())
                    .width(170.0)
                    .show_ui(ui, |ui| {
                        for option in Exists::ALL {
                            ui.selectable_value(&mut policy, option, option.label());
                        }
                    });
                if policy != self.settings.exists {
                    self.set_policy(policy);
                }
                ui.label(RichText::new("If the file exists").color(ui.visuals().weak_text_color()));
            });
        });
        let shown = match self.queue_tab {
            QueueTab::Queued => queued,
            QueueTab::Failed => failed,
            QueueTab::Done => done,
        };
        let frame = egui::Frame::NONE
            .fill(ui.visuals().extreme_bg_color)
            .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
            .corner_radius(6)
            .inner_margin(egui::Margin::same(1));
        frame.show(ui, |ui| {
            ui.set_min_size(ui.available_size());
            if shown.is_empty() {
                ui.vertical_centered(|ui| {
                    ui.add_space((ui.available_height() / 2.0 - 24.0).max(4.0));
                    ui.add(
                        Icon::Queue
                            .mono(ui.visuals().weak_text_color())
                            .fit_to_exact_size(egui::vec2(24.0, 24.0)),
                    );
                    ui.weak(match self.queue_tab {
                        QueueTab::Queued => {
                            "No transfers. Drag files between the sides, or double-click a file."
                        }
                        QueueTab::Failed => "No failed transfers.",
                        QueueTab::Done => "No finished transfers yet.",
                    });
                });
                return;
            }
            self.queue_table(ui, &shown);
        });
    }

    fn queue_table(&mut self, ui: &mut Ui, shown: &[&(usize, Item)]) {
        let row_height = ui.text_style_height(&egui::TextStyle::Body) + 10.0;
        let mut cancel = None;
        let mut retry = None;
        let mut remove = None;
        // The servers a tab is connected to: the others' transfers wait.
        let connected: Vec<String> = (0..self.tabs.len())
            .filter_map(|t| {
                let tab = self.tab_at(t);
                let c = tab.connection.as_ref()?;
                (tab.state == ConnState::Connected).then(|| c.name().to_owned())
            })
            .collect();
        TableBuilder::new(ui)
            .id_salt("queue")
            .striped(true)
            .resizable(true)
            .auto_shrink(false)
            .sense(egui::Sense::click())
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::exact(28.0))
            .column(Column::initial(280.0).clip(true))
            .column(Column::initial(300.0).clip(true))
            .column(Column::initial(80.0))
            .column(Column::initial(250.0))
            .column(Column::remainder().clip(true))
            .header(row_height, |mut h| {
                for title in [
                    "",
                    "Local file",
                    "Remote file",
                    "Size",
                    "Progress",
                    "Status",
                ] {
                    h.col(|ui| {
                        ui.strong(title);
                    });
                }
            })
            .body(|body| {
                body.rows(row_height, shown.len(), |mut row| {
                    let (tab, item) = shown[row.index()];
                    let tab = *tab;
                    row.col(|ui| {
                        let (icon, tip) = match item.direction {
                            Direction::Upload => (Icon::Upload, "Upload"),
                            Direction::Download => (Icon::Download, "Download"),
                        };
                        ui.add(icon.image(ui)).on_hover_text(tip);
                    });
                    let file_icon = if item.is_dir {
                        Icon::Folder
                    } else {
                        Icon::for_file(path::file_name(&item.remote))
                    };
                    row.col(|ui| {
                        ui.add(file_icon.sized(ui, 14.0));
                        ui.label(item.local.display().to_string());
                    });
                    row.col(|ui| {
                        ui.add(file_icon.sized(ui, 14.0));
                        ui.label(
                            RichText::new(format!("{}:", item.server))
                                .color(ui.visuals().weak_text_color()),
                        );
                        ui.label(&item.remote);
                    });
                    row.col(|ui| {
                        if !item.is_dir {
                            ui.label(format::size(item.size));
                        }
                    });
                    row.col(|ui| {
                        progress_ui(ui, item);
                    });
                    row.col(|ui| {
                        let (icon, text, color) =
                            if item.state == State::Queued && !connected.contains(&item.server) {
                                (
                                    Some(Icon::Clock),
                                    format!("Waiting for a connection to {}", item.server),
                                    ui.visuals().weak_text_color(),
                                )
                            } else {
                                status(ui, item)
                            };
                        if let Some(icon) = icon {
                            ui.add(icon.sized(ui, 14.0));
                        }
                        ui.label(RichText::new(text).color(color));
                    });
                    row.response().context_menu(|ui| {
                        if icons::menu_item(ui, Icon::Stop, "Cancel", !item.state.finished()) {
                            cancel = Some((tab, item.id));
                            ui.close();
                        }
                        let failed = matches!(item.state, State::Failed(_) | State::Cancelled);
                        if icons::menu_item(ui, Icon::Refresh, "Retry", failed) {
                            retry = Some((tab, item.id));
                            ui.close();
                        }
                        if icons::menu_item(ui, Icon::Trash, "Remove", item.state != State::Active)
                        {
                            remove = Some((tab, item.id));
                            ui.close();
                        }
                    });
                });
            });
        if let Some((tab, id)) = cancel {
            self.tab_at(tab).transfers.cancel(id);
        }
        if let Some((tab, id)) = retry {
            self.tab_at(tab).transfers.retry(id);
        }
        if let Some((tab, id)) = remove {
            self.tab_at(tab).transfers.remove(id);
        }
    }

    fn status_bar(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            match (&self.tab.state, &self.tab.connection) {
                (ConnState::Connected, Some(c)) => {
                    let protocol = self
                        .tab
                        .attempt
                        .as_ref()
                        .map_or(Protocol::Sftp, |a| a.params.protocol());
                    let (secure, kind) = match (c.security(), protocol) {
                        (Security::Ssh, _) => (true, "SFTP"),
                        (Security::Tls, Protocol::Ftp) => (true, "FTP over TLS"),
                        (Security::Tls, Protocol::WebDav) => (true, "WebDAV over HTTPS"),
                        (Security::Tls, _) => (true, "S3 over HTTPS"),
                        (Security::Plain, Protocol::Ftp) => (false, "FTP, not encrypted"),
                        (Security::Plain, Protocol::WebDav) => {
                            (false, "WebDAV over HTTP, not encrypted")
                        }
                        (Security::Plain, _) => (false, "S3 over HTTP, not encrypted"),
                    };
                    if secure {
                        ui.add(
                            Icon::Lock
                                .mono(theme::SUCCESS)
                                .fit_to_exact_size(egui::vec2(14.0, 14.0)),
                        );
                    } else {
                        ui.add(Icon::Warning.sized(ui, 14.0))
                            .on_hover_text("Passwords and files travel unencrypted");
                    }
                    ui.label(format!("Connected to {}", c.name()));
                    ui.weak(kind);
                    if self.tab.security_key_login {
                        ui.separator();
                        ui.add(Icon::SecurityKey.sized(ui, 14.0));
                        ui.weak("Logged in with a security key");
                    }
                }
                (ConnState::Connecting { touch: true }, _) => {
                    ui.spinner();
                    ui.label("Waiting for the security key: touch it");
                }
                (ConnState::Connecting { .. }, _) => {
                    ui.spinner();
                    ui.label("Connecting…");
                }
                _ => {
                    ui.add(
                        Icon::Disconnect
                            .mono(ui.visuals().weak_text_color())
                            .fit_to_exact_size(egui::vec2(14.0, 14.0)),
                    );
                    ui.weak("Not connected");
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let items = self.all_items();
                let pending: Vec<&Item> = items
                    .iter()
                    .map(|(_, i)| i)
                    .filter(|i| !i.state.finished() && !i.is_dir)
                    .collect();
                if pending.is_empty() {
                    ui.weak("Queue empty");
                    return;
                }
                let remaining: u64 = pending.iter().map(|i| i.size.saturating_sub(i.done)).sum();
                for (direction, icon) in [
                    (Direction::Download, Icon::Download),
                    (Direction::Upload, Icon::Upload),
                ] {
                    let speed: f64 = pending
                        .iter()
                        .filter(|i| i.state == State::Active && i.direction == direction)
                        .filter_map(|i| i.speed())
                        .sum();
                    if speed > 0.0 {
                        ui.label(format!("{}/s", format::size(speed as u64)));
                        ui.add(icon.sized(ui, 14.0));
                    }
                }
                ui.label(format!(
                    "{} {} in the queue, {}",
                    pending.len(),
                    if pending.len() == 1 { "file" } else { "files" },
                    format::size(remaining)
                ));
            });
        });
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        let Some(mut dialog) = self.dialog.take() else {
            self.exists_dialog(ctx);
            return;
        };
        let mut keep = true;
        let mut then: Option<Then> = None;
        let modal = egui::Modal::new(egui::Id::new("dialog")).show(ctx, |ui| {
            ui.set_width(460.0);
            let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
            match &mut dialog {
                Dialog::HostKey(key, attempt) => {
                    let host = if key.port == 22 {
                        key.host.clone()
                    } else {
                        format!("{}:{}", key.host, key.port)
                    };
                    header(
                        ui,
                        Icon::Fingerprint,
                        "Unknown host key",
                        &format!("{host} hasn't been seen before."),
                    );
                    let (kind, fingerprint) = key
                        .fingerprint
                        .split_once(' ')
                        .unwrap_or(("", &key.fingerprint));
                    theme::card(ui.style()).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        egui::Grid::new("hostkey")
                            .num_columns(2)
                            .spacing([12.0, 6.0])
                            .show(ui, |ui| {
                                ui.weak("Host");
                                ui.strong(&host);
                                ui.end_row();
                                ui.weak("Key type");
                                ui.label(kind);
                                ui.end_row();
                                ui.weak("Fingerprint");
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(fingerprint).monospace());
                                    if icons::icon_button(ui, Icon::Copy, "Copy the fingerprint")
                                        .clicked()
                                    {
                                        ui.ctx().copy_text(key.fingerprint.clone());
                                    }
                                });
                                ui.end_row();
                            });
                    });
                    ui.add_space(8.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.add(Icon::Warning.sized(ui, 14.0));
                        ui.label(
                            "There's no guarantee that the server is the computer you think it \
                             is. Compare the fingerprint with the one the server's administrator \
                             gave you.",
                        );
                    });
                    buttons(ui, |ui| {
                        if ui.add(theme::primary_button("Trust and connect")).clicked() {
                            let (key, attempt) = (key.clone(), attempt.clone());
                            then = Some(Box::new(move |app: &mut Self| match key.trust() {
                                Ok(()) => {
                                    app.log(
                                        LogKind::Status,
                                        format!("Trusted the host key of {}", key.host),
                                    );
                                    let ctx = app.ctx.clone();
                                    app.connect(&ctx, *attempt);
                                }
                                Err(e) => app.dialog = Some(Dialog::Message(e.message)),
                            }));
                            keep = false;
                        }
                        if ui.add(theme::secondary_button("Cancel")).clicked() {
                            keep = false;
                        }
                    });
                }
                Dialog::Certificate(cert, attempt) => {
                    let host = format!("{}:{}", cert.host, cert.port);
                    header(
                        ui,
                        Icon::Shield,
                        "Unknown certificate",
                        &format!(
                            "The TLS certificate of {host} isn't trusted: {}.",
                            cert.problem
                        ),
                    );
                    theme::card(ui.style()).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        egui::Grid::new("certificate")
                            .num_columns(2)
                            .spacing([12.0, 6.0])
                            .show(ui, |ui| {
                                for (label, value) in [
                                    ("Subject", &cert.subject),
                                    ("Issuer", &cert.issuer),
                                    ("Valid from", &cert.valid_from),
                                    ("Valid until", &cert.valid_until),
                                ] {
                                    ui.weak(label);
                                    ui.add(egui::Label::new(value.as_str()).wrap());
                                    ui.end_row();
                                }
                                ui.weak("SHA-256");
                                ui.horizontal(|ui| {
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(&cert.fingerprint).monospace().small(),
                                        )
                                        .wrap(),
                                    );
                                    if icons::icon_button(ui, Icon::Copy, "Copy the fingerprint")
                                        .clicked()
                                    {
                                        ui.ctx().copy_text(cert.fingerprint.clone());
                                    }
                                });
                                ui.end_row();
                            });
                    });
                    ui.add_space(8.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.add(Icon::Warning.sized(ui, 14.0));
                        ui.label(
                            "Trust it only if you know the server uses this certificate, e.g. \
                             because its administrator gave you the fingerprint.",
                        );
                    });
                    buttons(ui, |ui| {
                        if ui.add(theme::primary_button("Trust and connect")).clicked() {
                            let (cert, attempt) = (cert.clone(), attempt.clone());
                            then = Some(Box::new(move |app: &mut Self| match cert.trust() {
                                Ok(()) => {
                                    app.log(
                                        LogKind::Status,
                                        format!("Trusted the certificate of {}", cert.host),
                                    );
                                    let ctx = app.ctx.clone();
                                    app.connect(&ctx, *attempt);
                                }
                                Err(e) => app.dialog = Some(Dialog::Message(e.message)),
                            }));
                            keep = false;
                        }
                        if ui.add(theme::secondary_button("Cancel")).clicked() {
                            keep = false;
                        }
                    });
                }
                Dialog::Secret {
                    kind,
                    message,
                    value,
                    attempt,
                } => {
                    let server = attempt.params.host().to_owned();
                    match kind {
                        SecretKind::Pin => {
                            header(
                                ui,
                                Icon::SecurityKey,
                                "Security key PIN",
                                "Your security key verifies who you are. Enter its PIN, then \
                                 touch the key when it blinks.",
                            );
                            // Asked again: a wrong PIN, and the tries left.
                            if message.contains(rustzilla_remote::fido::PIN_WRONG) {
                                ui.horizontal_wrapped(|ui| {
                                    ui.add(Icon::Error.sized(ui, 14.0));
                                    let text = message
                                        .rsplit_once(": ")
                                        .map_or(message.as_str(), |(_, m)| m);
                                    ui.colored_label(ui.visuals().error_fg_color, text);
                                });
                            }
                        }
                        SecretKind::Passphrase => header(
                            ui,
                            Icon::Key,
                            "Key file passphrase",
                            message.as_str(),
                        ),
                        SecretKind::Password => header(
                            ui,
                            Icon::Lock,
                            "Password",
                            &format!("Log in as {} on {server}.", attempt.params.username()),
                        ),
                    }
                    ui.add_space(6.0);
                    let hint = match kind {
                        SecretKind::Pin => "PIN",
                        SecretKind::Passphrase => "Passphrase",
                        SecretKind::Password => "Password",
                    };
                    ui.add(
                        egui::TextEdit::singleline(value)
                            .password(true)
                            .hint_text(hint)
                            .margin(egui::Margin::symmetric(8, 6))
                            .desired_width(f32::INFINITY),
                    )
                    .request_focus();
                    buttons(ui, |ui| {
                        let ok = if *kind == SecretKind::Pin {
                            "Continue"
                        } else {
                            "Connect"
                        };
                        if ui.add(theme::primary_button(ok)).clicked() || enter {
                            let mut attempt = (**attempt).clone();
                            let value = std::mem::take(value);
                            match kind {
                                SecretKind::Pin => {
                                    if let Params::Sftp(ssh) = &mut attempt.params {
                                        ssh.pin = Some(value);
                                    }
                                }
                                SecretKind::Passphrase => {
                                    if let Params::Sftp(SshParams {
                                        auth: Auth::KeyFile { passphrase, .. },
                                        ..
                                    }) = &mut attempt.params
                                    {
                                        *passphrase = value;
                                    }
                                }
                                SecretKind::Password => attempt.params.set_password(value),
                            }
                            then = Some(Box::new(move |app: &mut Self| {
                                let ctx = app.ctx.clone();
                                app.connect(&ctx, attempt)
                            }));
                            keep = false;
                        }
                        if ui.add(theme::secondary_button("Cancel")).clicked() {
                            keep = false;
                        }
                    });
                }
                Dialog::Mkdir { side, name } => {
                    let place = match side {
                        Side::Local => self.tab.local.path.clone(),
                        Side::Remote => self.tab.remote.path.clone(),
                    };
                    header(ui, Icon::NewFolder, "Create directory", &format!("In {place}"));
                    ui.add(
                        egui::TextEdit::singleline(name)
                            .hint_text("Name of the new directory")
                            .margin(egui::Margin::symmetric(8, 6))
                            .desired_width(f32::INFINITY),
                    )
                    .request_focus();
                    buttons(ui, |ui| {
                        let ready = !name.trim().is_empty();
                        if ui.add_enabled(ready, theme::primary_button("Create")).clicked()
                            || (enter && ready)
                        {
                            let (side, name) = (*side, name.trim().to_owned());
                            then = Some(Box::new(move |app: &mut Self| app.mkdir(side, &name)));
                            keep = false;
                        }
                        if ui.add(theme::secondary_button("Cancel")).clicked() {
                            keep = false;
                        }
                    });
                }
                Dialog::Rename { side, from, to } => {
                    header(ui, Icon::Edit, "Rename", &format!("New name for {from}"));
                    ui.add(
                        egui::TextEdit::singleline(to)
                            .margin(egui::Margin::symmetric(8, 6))
                            .desired_width(f32::INFINITY),
                    )
                    .request_focus();
                    buttons(ui, |ui| {
                        let ready = !to.trim().is_empty();
                        if ui.add_enabled(ready, theme::primary_button("Rename")).clicked()
                            || (enter && ready)
                        {
                            let (side, from, to) = (*side, from.clone(), to.trim().to_owned());
                            then = Some(Box::new(move |app: &mut Self| {
                                app.rename(side, &from, &to)
                            }));
                            keep = false;
                        }
                        if ui.add(theme::secondary_button("Cancel")).clicked() {
                            keep = false;
                        }
                    });
                }
                Dialog::Delete { side, names } => {
                    let what = if names.len() == 1 {
                        format!("“{}”", names[0])
                    } else {
                        format!("these {} entries", names.len())
                    };
                    let where_ = match side {
                        Side::Local => "from this computer",
                        Side::Remote => "from the server",
                    };
                    header(
                        ui,
                        Icon::Trash,
                        "Delete",
                        &format!("Delete {what} {where_}? Directories go with everything in them. This can't be undone."),
                    );
                    if names.len() > 1 {
                        theme::card(ui.style()).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            egui::ScrollArea::vertical().max_height(140.0).show(ui, |ui| {
                                let pane = match side {
                                    Side::Local => &self.tab.local,
                                    Side::Remote => &self.tab.remote,
                                };
                                for name in names.iter() {
                                    ui.horizontal(|ui| {
                                        let icon = if pane.row(name).is_some_and(|r| r.is_dir) {
                                            Icon::Folder
                                        } else {
                                            Icon::for_file(name)
                                        };
                                        ui.add(icon.sized(ui, 14.0));
                                        ui.label(name);
                                    });
                                }
                            });
                        });
                    }
                    buttons(ui, |ui| {
                        if ui.add(theme::danger_button("Delete")).clicked() || enter {
                            let (side, names) = (*side, names.clone());
                            then = Some(Box::new(move |app: &mut Self| app.delete(side, &names)));
                            keep = false;
                        }
                        if ui.add(theme::secondary_button("Cancel")).clicked() {
                            keep = false;
                        }
                    });
                }
                Dialog::Chmod {
                    names,
                    mode,
                    recursive_note,
                } => {
                    let of = if names.len() == 1 {
                        names[0].clone()
                    } else {
                        format!("{} entries", names.len())
                    };
                    header(ui, Icon::Lock, "File permissions", &format!("Of {of}"));
                    theme::card(ui.style()).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        egui::Grid::new("chmod")
                            .num_columns(4)
                            .spacing([28.0, 8.0])
                            .show(ui, |ui| {
                                ui.label("");
                                for title in ["Read", "Write", "Execute"] {
                                    ui.weak(title);
                                }
                                ui.end_row();
                                for (who, shift) in [("Owner", 6), ("Group", 3), ("Public", 0)] {
                                    ui.label(who);
                                    for bit in [4, 2, 1] {
                                        let mask = bit << shift;
                                        let mut on = *mode & mask != 0;
                                        if ui.checkbox(&mut on, "").changed() {
                                            *mode = if on { *mode | mask } else { *mode & !mask };
                                        }
                                    }
                                    ui.end_row();
                                }
                            });
                    });
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.label("Numeric value");
                        let mut text = format!("{:03o}", *mode & 0o7777);
                        if ui
                            .add(
                                egui::TextEdit::singleline(&mut text)
                                    .font(egui::TextStyle::Monospace)
                                    .desired_width(50.0),
                            )
                            .changed()
                            && let Ok(value) = u32::from_str_radix(text.trim(), 8)
                            && value <= 0o7777
                        {
                            *mode = value;
                        }
                        ui.label(
                            RichText::new(format::mode_string(*mode))
                                .monospace()
                                .color(ui.visuals().weak_text_color()),
                        );
                    });
                    if *recursive_note {
                        ui.weak("Directories get these permissions themselves, not their contents.");
                    }
                    buttons(ui, |ui| {
                        if ui.add(theme::primary_button("Apply")).clicked() || enter {
                            let (names, mode) = (names.clone(), *mode);
                            then = Some(Box::new(move |app: &mut Self| app.chmod(&names, mode)));
                            keep = false;
                        }
                        if ui.add(theme::secondary_button("Cancel")).clicked() {
                            keep = false;
                        }
                    });
                }
                Dialog::Message(text) => {
                    header(ui, Icon::Info, "RustZilla", text.as_str());
                    buttons(ui, |ui| {
                        if ui.add(theme::primary_button("OK")).clicked() || enter {
                            keep = false;
                        }
                    });
                }
                Dialog::About => {
                    ui.vertical_centered(|ui| {
                        ui.add(
                            egui::Image::new(egui::ImageSource::Bytes {
                                uri: "bytes://rustzilla-app-icon.svg".into(),
                                bytes: egui::load::Bytes::Static(crate::APP_ICON.as_bytes()),
                            })
                            .fit_to_exact_size(egui::vec2(88.0, 88.0)),
                        );
                        ui.add_space(4.0);
                        ui.heading("RustZilla");
                        ui.weak(format!("Version {}", env!("CARGO_PKG_VERSION")));
                        ui.add_space(6.0);
                        ui.label("A fast, native SFTP client.");
                        ui.label(
                            "Logs in with passwords, key files, the SSH agent and FIDO \
                             security keys such as YubiKeys.",
                        );
                    });
                    if let Some(paths) = &self.paths {
                        ui.add_space(8.0);
                        theme::card(ui.style()).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            egui::Grid::new("about-paths").num_columns(2).show(ui, |ui| {
                                for (label, path) in [
                                    ("Sites", paths.config_dir.clone()),
                                    ("Known hosts", paths.known_hosts()),
                                    ("Certificates", paths.trusted_certs()),
                                    ("Logs", paths.log_dir()),
                                ] {
                                    ui.weak(label);
                                    ui.label(RichText::new(path.display().to_string()).small());
                                    ui.end_row();
                                }
                            });
                        });
                    }
                    buttons(ui, |ui| {
                        if ui.add(theme::primary_button("Close")).clicked() || enter {
                            keep = false;
                        }
                    });
                }
            }
        });
        if modal.should_close() {
            keep = false;
        }
        if keep {
            self.dialog = Some(dialog);
        }
        if let Some(then) = then {
            then(self);
        }
    }

    /// Asks what to do about the first transfer whose target exists.
    fn exists_dialog(&mut self, ctx: &egui::Context) {
        let items = self.all_items();
        let asking = items.iter().find_map(|(t, i)| match &i.state {
            State::Asking(conflict) => Some((*t, i.clone(), conflict.clone())),
            _ => None,
        });
        let Some((tab, item, conflict)) = asking else {
            return;
        };
        let waiting = items
            .iter()
            .filter(|(t, i)| *t == tab && matches!(i.state, State::Asking(_)))
            .count();
        let mut decided = None;
        let mut cancel = false;
        egui::Modal::new(egui::Id::new("exists")).show(ctx, |ui| {
            ui.set_width(560.0);
            let name = path::file_name(&item.remote).to_owned();
            header(
                ui,
                Icon::Warning,
                "The file already exists",
                &format!("“{name}” is there already. What should happen to it?"),
            );
            let (source, target, source_side, target_side) = match item.direction {
                Direction::Download => (
                    item.remote.clone(),
                    item.local.display().to_string(),
                    "On the server",
                    "On this computer",
                ),
                Direction::Upload => (
                    item.local.display().to_string(),
                    item.remote.clone(),
                    "On this computer",
                    "On the server",
                ),
            };
            let card = |ui: &mut Ui, title: &str, side: &str, path: &str, size: u64, time| {
                theme::card(ui.style()).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.add(Icon::for_file(&name).sized(ui, 28.0));
                        ui.vertical(|ui| {
                            ui.horizontal(|ui| {
                                ui.strong(title);
                                ui.weak(side);
                            });
                            ui.add(egui::Label::new(RichText::new(path).small()).truncate());
                            ui.label(format!(
                                "{} bytes · {}",
                                format::size_exact(size),
                                format::time(time)
                            ));
                        });
                    });
                });
            };
            card(
                ui,
                "Source",
                source_side,
                &source,
                conflict.source_size,
                conflict.source_modified,
            );
            ui.add_space(4.0);
            card(
                ui,
                "Target",
                target_side,
                &target,
                conflict.target_size,
                conflict.target_modified,
            );
            ui.add_space(8.0);
            for option in [
                Exists::Overwrite,
                Exists::OverwriteIfNewer,
                Exists::Resume,
                Exists::Skip,
            ] {
                ui.radio_value(&mut self.exists_choice, option, option.label());
            }
            ui.add_space(4.0);
            let all = if waiting > 1 {
                format!("Do this for the other {} files too", waiting - 1)
            } else {
                "Do this for the next files too".to_owned()
            };
            ui.checkbox(&mut self.exists_all, all);
            buttons(ui, |ui| {
                if ui.add(theme::primary_button("OK")).clicked() {
                    decided = Some(self.exists_choice);
                }
                if ui.add(theme::secondary_button("Cancel transfer")).clicked() {
                    cancel = true;
                }
            });
        });
        if let Some(action) = decided {
            self.tab_at(tab)
                .transfers
                .decide(item.id, action, self.exists_all);
            if self.exists_all {
                self.settings.exists = action;
                self.exists_all = false;
            }
        } else if cancel {
            self.tab_at(tab).transfers.cancel(item.id);
        }
    }

    /// Over everything while the security key waits to be touched.
    fn touch_overlay(&mut self, ctx: &egui::Context) {
        if self.tab.state != (ConnState::Connecting { touch: true }) || self.dialog.is_some() {
            return;
        }
        let mut cancel = false;
        egui::Modal::new(egui::Id::new("touch")).show(ctx, |ui| {
            ui.set_width(380.0);
            ui.vertical_centered(|ui| {
                ui.add_space(8.0);
                // The key, with rings pulsing out of it as the key blinks.
                let size = 64.0;
                let (rect, _) = ui
                    .allocate_exact_size(egui::vec2(size * 2.2, size * 1.6), egui::Sense::hover());
                let t = ui.input(|i| i.time) as f32;
                let center = rect.center();
                for k in 0..2 {
                    let phase = (t * 0.8 + k as f32 * 0.5).fract();
                    let alpha = ((1.0 - phase) * 120.0) as u8;
                    ui.painter().circle_stroke(
                        center,
                        size * 0.45 + phase * size * 0.4,
                        egui::Stroke::new(
                            2.0,
                            Color32::from_rgba_unmultiplied(0xe0, 0xaa, 0x1c, alpha),
                        ),
                    );
                }
                Icon::SecurityKey.sized(ui, size).paint_at(
                    ui,
                    egui::Rect::from_center_size(center, egui::vec2(size, size)),
                );
                ui.ctx().request_repaint();
                ui.add_space(6.0);
                ui.heading("Touch your security key");
                ui.add_space(2.0);
                ui.label("Your security key (e.g. a YubiKey) is blinking: touch it to log in.");
                ui.add_space(12.0);
                if ui.add(theme::secondary_button("Cancel")).clicked() {
                    cancel = true;
                }
                ui.add_space(4.0);
            });
        });
        if cancel {
            self.log(LogKind::Status, "Cancelled the login".into());
            self.tab.session = None;
            self.disconnect();
        }
    }

    // Changes.

    fn mkdir(&mut self, side: Side, name: &str) {
        match side {
            Side::Local => {
                let dir = PathBuf::from(&self.tab.local.path).join(name);
                if let Err(e) = std::fs::create_dir(&dir) {
                    self.log(LogKind::Error, format!("Creating {}: {e}", dir.display()));
                }
                let current = PathBuf::from(&self.tab.local.path);
                self.list_local(&current);
            }
            Side::Remote => {
                if let Some(session) = &self.tab.session {
                    session.send(Command::Mkdir(path::join(&self.tab.remote.path, name)));
                }
            }
        }
    }

    fn rename(&mut self, side: Side, from: &str, to: &str) {
        if from == to {
            return;
        }
        match side {
            Side::Local => {
                let dir = PathBuf::from(&self.tab.local.path);
                if let Err(e) = std::fs::rename(dir.join(from), dir.join(to)) {
                    self.log(LogKind::Error, format!("Renaming {from}: {e}"));
                }
                self.list_local(&dir);
            }
            Side::Remote => {
                if let Some(session) = &self.tab.session {
                    let target = if to.starts_with('/') {
                        to.to_owned()
                    } else {
                        path::join(&self.tab.remote.path, to)
                    };
                    session.send(Command::Rename {
                        from: path::join(&self.tab.remote.path, from),
                        to: target,
                    });
                }
            }
        }
    }

    fn delete(&mut self, side: Side, names: &[String]) {
        match side {
            Side::Local => {
                let dir = PathBuf::from(&self.tab.local.path);
                for name in names {
                    if let Err(e) = local::delete(&dir.join(name)) {
                        self.log(LogKind::Error, format!("Deleting {name}: {e}"));
                    }
                }
                self.list_local(&dir);
            }
            Side::Remote => {
                let targets = names
                    .iter()
                    .map(|name| {
                        let row = self.tab.remote.row(name);
                        let is_dir = row.is_some_and(|r| r.is_dir && !r.symlink);
                        (path::join(&self.tab.remote.path, name), is_dir)
                    })
                    .collect();
                if let Some(session) = &self.tab.session {
                    session.send(Command::Delete(targets));
                }
            }
        }
    }

    fn chmod(&mut self, names: &[String], mode: u32) {
        if let Some(session) = &self.tab.session {
            session.send(Command::Chmod {
                paths: names
                    .iter()
                    .map(|n| path::join(&self.tab.remote.path, n))
                    .collect(),
                mode,
            });
        }
    }

    fn keys(&mut self, ctx: &egui::Context) {
        if ctx.egui_wants_keyboard_input() || self.dialog.is_some() {
            return;
        }
        let pane = match self.tab.focus {
            Side::Local => &mut self.tab.local,
            Side::Remote => &mut self.tab.remote,
        };
        let selection = pane.selected();
        let mut actions = Vec::new();
        ctx.input(|i| {
            if i.key_pressed(egui::Key::F5) {
                actions.push(Action::Refresh);
            }
            if i.key_pressed(egui::Key::Backspace) {
                actions.push(Action::Up);
            }
            if i.key_pressed(egui::Key::Delete) && !selection.is_empty() {
                actions.push(Action::Delete(selection.clone()));
            }
            if i.key_pressed(egui::Key::F2) && selection.len() == 1 {
                actions.push(Action::Rename(selection[0].clone()));
            }
        });
        if ctx.input(|i| i.modifiers.command && i.key_pressed(egui::Key::A)) {
            pane.select_all();
        }
        let connected = self.tab.state == ConnState::Connected;
        for action in actions {
            match self.tab.focus {
                Side::Local => self.local_action(action),
                Side::Remote if connected => self.remote_action(action),
                Side::Remote => {}
            }
        }
    }

    fn site_manager_ui(&mut self, ctx: &egui::Context) {
        let Some(manager) = &mut self.site_manager else {
            return;
        };
        let Some(outcome) = manager.ui(ctx) else {
            return;
        };
        let save = |app: &mut Self, sites: Vec<Site>| {
            app.sites = sites;
            if let Some(paths) = &app.paths
                && let Err(e) = config::save_sites(paths, &app.sites)
            {
                app.log(LogKind::Error, e);
            }
        };
        match outcome {
            site_manager::Outcome::Save(sites) => {
                save(self, sites);
                self.site_manager = None;
            }
            site_manager::Outcome::SaveAndConnect(sites, site, secret) => {
                save(self, sites);
                self.site_manager = None;
                self.connect_site(ctx, &site, secret);
            }
            site_manager::Outcome::Close => self.site_manager = None,
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.poll_background(&ctx);
        self.poll_session(&ctx);
        self.poll_transfers();

        // Files dropped from the desktop go up to the remote directory.
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .map(|f| f.path().to_owned())
                .filter(|p| !p.as_os_str().is_empty())
                .collect()
        });
        if !dropped.is_empty() {
            self.upload_paths(dropped);
        }
        // Repaint while transfers run, for their progress.
        if self
            .all_items()
            .iter()
            .any(|(_, i)| i.state == State::Active)
        {
            ctx.request_repaint_after(std::time::Duration::from_millis(250));
        }

        egui::Panel::top("menu").show(ui, |ui| self.menu_bar(ui, &ctx));
        egui::Panel::top("toolbar")
            .frame(theme::toolbar_frame(ui.style()))
            .show(ui, |ui| self.toolbar(ui, &ctx));
        if self.settings.show_log {
            egui::Panel::top("log")
                .resizable(true)
                .default_size(120.0)
                .size_range(40.0..=600.0)
                .frame(
                    egui::Frame::NONE
                        .fill(ui.visuals().extreme_bg_color)
                        .inner_margin(egui::Margin::symmetric(10, 6)),
                )
                .show(ui, |ui| self.log_ui(ui));
        }
        egui::Panel::bottom("status")
            .frame(theme::status_frame(ui.style()))
            .show(ui, |ui| self.status_bar(ui));
        egui::Panel::bottom("queue")
            .resizable(true)
            .default_size(200.0)
            .size_range(80.0..=600.0)
            .frame(egui::Frame::side_top_panel(ui.style()).inner_margin(egui::Margin::same(8)))
            .show(ui, |ui| self.queue_ui(ui));
        egui::Panel::top("tabs")
            .frame(
                egui::Frame::side_top_panel(ui.style()).inner_margin(egui::Margin {
                    left: 8,
                    right: 8,
                    top: 4,
                    bottom: 0,
                }),
            )
            .show_separator_line(false)
            .show(ui, |ui| self.tab_bar(ui));
        let width = ui.available_width();
        let pane_frame =
            egui::Frame::side_top_panel(ui.style()).inner_margin(egui::Margin::same(8));
        let local = egui::Panel::left("local")
            .resizable(true)
            .default_size(width / 2.0)
            .size_range(260.0..=(width - 260.0).max(260.0))
            .frame(pane_frame)
            .show(ui, |ui| self.tab.local.ui(ui, "Local site", true));
        let connected = self.tab.state == ConnState::Connected;
        // Framed as the local side, so both line up.
        let remote = egui::CentralPanel::default()
            .frame(pane_frame)
            .show(ui, |ui| self.tab.remote.ui(ui, "Remote site", connected));
        let pressed = ctx.input(|i| i.pointer.any_pressed());
        if pressed && local.response.contains_pointer() {
            self.tab.focus = Side::Local;
        } else if pressed && remote.response.contains_pointer() {
            self.tab.focus = Side::Remote;
        }
        for action in local.inner {
            self.tab.focus = Side::Local;
            self.local_action(action);
        }
        for action in remote.inner {
            self.tab.focus = Side::Remote;
            self.remote_action(action);
        }

        self.tab_keys(&ctx);
        self.keys(&ctx);
        self.site_manager_ui(&ctx);
        self.touch_overlay(&ctx);
        self.dialogs(&ctx);
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        if let Some(paths) = &self.paths {
            let saved = (0..self.tabs.len())
                .flat_map(|t| self.tab_at(t).transfers.unfinished())
                .map(|(server, item)| config::SavedTransfer { server, item })
                .collect();
            if let Err(e) = config::save_queue(paths, saved) {
                tracing::warn!("{e}");
            }
        }
        if !self.tab.local.path.is_empty() {
            self.settings.local_dir = self.tab.local.path.clone();
        }
        eframe::set_value(storage, "settings", &self.settings);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        for index in 0..self.tabs.len() {
            self.with_tab(index, Self::disconnect);
        }
    }
}

fn remote_row(entry: RemoteEntry) -> Row {
    let owner = match (entry.owner.is_empty(), entry.group.is_empty()) {
        (true, true) => String::new(),
        _ => format!("{} {}", entry.owner, entry.group),
    };
    Row {
        is_dir: entry.is_dir(),
        name: entry.name,
        symlink: entry.symlink,
        size: entry.size,
        modified: entry.modified,
        permissions: entry.permissions,
        owner,
    }
}

fn progress_ui(ui: &mut Ui, item: &Item) {
    match &item.state {
        State::Active if !item.is_dir => {
            let fraction = if item.size == 0 {
                0.0
            } else {
                item.done as f32 / item.size as f32
            };
            let mut text = format!("{:.0}%", fraction * 100.0);
            if let Some(speed) = item.speed() {
                text.push_str(&format!("  ·  {}/s", format::size(speed as u64)));
                if speed > 0.0 && item.size > item.done {
                    let left = (item.size - item.done) as f64 / speed;
                    text.push_str(&format!(
                        "  ·  {}",
                        format::duration(std::time::Duration::from_secs_f64(left))
                    ));
                }
            }
            let fill = match item.direction {
                Direction::Upload => theme::UPLOAD,
                Direction::Download => theme::DOWNLOAD,
            };
            ui.add(
                egui::ProgressBar::new(fraction)
                    .text(RichText::new(text).color(Color32::WHITE).small())
                    .fill(fill)
                    .corner_radius(4)
                    .desired_height(16.0),
            );
        }
        State::Active => {
            ui.spinner();
        }
        State::Done => {
            if let (Some(started), Some(finished)) = (item.started, item.finished_at) {
                ui.weak(format!(
                    "{} in {}",
                    format::size(item.done),
                    format::duration(finished.duration_since(started))
                ));
            }
        }
        _ => {}
    }
}

fn status(ui: &Ui, item: &Item) -> (Option<Icon>, String, Color32) {
    let normal = ui.visuals().text_color();
    let weak = ui.visuals().weak_text_color();
    match &item.state {
        State::Queued => (Some(Icon::Clock), "Queued".into(), weak),
        State::Active if item.is_dir => (None, "Listing the directory…".into(), normal),
        State::Active => (None, "Transferring".into(), normal),
        State::Asking(_) => (
            Some(Icon::Warning),
            "Exists already: waiting for you".into(),
            ui.visuals().warn_fg_color,
        ),
        State::Done => (Some(Icon::Success), "Done".into(), normal),
        State::Skipped(why) => (Some(Icon::Skip), format!("Skipped: {why}"), weak),
        State::Failed(e) => (Some(Icon::Error), e.clone(), ui.visuals().error_fg_color),
        State::Cancelled => (
            Some(Icon::Stop),
            "Cancelled".into(),
            ui.visuals().warn_fg_color,
        ),
    }
}

/// A log line's icon and color.
fn log_style(ui: &Ui, kind: LogKind) -> (Icon, Color32) {
    let dark = ui.visuals().dark_mode;
    match kind {
        LogKind::Status => (Icon::Info, ui.visuals().text_color()),
        LogKind::Command => (
            Icon::Command,
            if dark {
                Color32::from_rgb(0x8c, 0xb4, 0xff)
            } else {
                Color32::from_rgb(0x1d, 0x5f, 0xd6)
            },
        ),
        LogKind::Response => (
            Icon::Success,
            if dark {
                Color32::from_rgb(0x7c, 0xc8, 0x8f)
            } else {
                Color32::from_rgb(0x1f, 0x7a, 0x3d)
            },
        ),
        LogKind::Error => (Icon::Error, ui.visuals().error_fg_color),
    }
}

/// While one of the menu bar's menus is open, hovering another one opens
/// that instead, as in desktop menu bars (egui only opens them on click).
fn switch_menus_on_hover(ctx: &egui::Context, menus: &[egui::Response]) {
    use egui::containers::Popup;
    let id = |r: &egui::Response| Popup::default_response_id(r);
    if !menus.iter().any(|r| Popup::is_id_open(ctx, id(r))) {
        return;
    }
    if let Some(hovered) = menus
        .iter()
        .find(|r| r.hovered() && !Popup::is_id_open(ctx, id(r)))
    {
        Popup::open_id(ctx, id(hovered));
        ctx.request_repaint();
    }
}

/// A dialog's head: a big icon, the title, and what it's about.
fn header(ui: &mut Ui, icon: Icon, title: &str, text: &str) {
    ui.horizontal(|ui| {
        ui.add(icon.sized(ui, 36.0));
        ui.add_space(4.0);
        ui.vertical(|ui| {
            ui.label(RichText::new(title).heading());
            if !text.is_empty() {
                ui.add(egui::Label::new(text).wrap());
            }
        });
    });
    ui.add_space(10.0);
}

/// A dialog's buttons, at its right: the first one added is rightmost.
fn buttons(ui: &mut Ui, add: impl FnOnce(&mut Ui)) {
    ui.add_space(12.0);
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), add);
}

/// What the Quickconnect host field holds: `host`, `host:port`,
/// `sftp://user@host:port/path`.
#[derive(Debug, PartialEq, Eq)]
struct Target {
    /// From the scheme: `sftp://`, `ftp://`, `ftps://` (implicit TLS),
    /// `ftpes://` (explicit TLS).
    scheme: Option<(Protocol, FtpEncryption)>,
    host: String,
    port: Option<u16>,
    user: Option<String>,
    path: Option<String>,
}

fn parse_host(input: &str) -> Option<Target> {
    let mut rest = input.trim();
    let mut scheme = None;
    for (prefix, protocol, encryption) in [
        (
            "sftp://",
            Protocol::Sftp,
            FtpEncryption::ExplicitIfAvailable,
        ),
        ("ftp://", Protocol::Ftp, FtpEncryption::ExplicitIfAvailable),
        ("ftps://", Protocol::Ftp, FtpEncryption::Implicit),
        ("ftpes://", Protocol::Ftp, FtpEncryption::Explicit),
        ("davs://", Protocol::WebDav, FtpEncryption::Explicit),
        ("dav://", Protocol::WebDav, FtpEncryption::Plain),
        ("webdavs://", Protocol::WebDav, FtpEncryption::Explicit),
        ("webdav://", Protocol::WebDav, FtpEncryption::Plain),
        ("s3://", Protocol::S3, FtpEncryption::Explicit),
    ] {
        if let Some(stripped) = rest.strip_prefix(prefix) {
            rest = stripped;
            scheme = Some((protocol, encryption));
        }
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], Some(rest[i..].to_owned())),
        None => (rest, None),
    };
    let (user, hostport) = match authority.rsplit_once('@') {
        Some((user, host)) => (Some(user.to_owned()).filter(|u| !u.is_empty()), host),
        None => (None, authority),
    };
    let (host, port) = if let Some(inner) = hostport.strip_prefix('[') {
        let (host, after) = inner.split_once(']')?;
        (host, after.strip_prefix(':').and_then(|p| p.parse().ok()))
    } else {
        match hostport.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (host, port.parse().ok()),
            _ => (hostport, None),
        }
    };
    if host.is_empty() {
        return None;
    }
    Some(Target {
        scheme,
        host: host.to_owned(),
        port,
        user,
        path: path.filter(|p| p != "/" || rest.ends_with('/')),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quickconnect_hosts() {
        let t = parse_host("example.com").unwrap();
        assert_eq!(
            (t.scheme, t.host.as_str(), t.port, t.user, t.path),
            (None, "example.com", None, None, None)
        );
        let t = parse_host("sftp://deploy@example.com:2222/var/www").unwrap();
        assert_eq!(t.scheme.map(|s| s.0), Some(Protocol::Sftp));
        assert_eq!((t.host.as_str(), t.port), ("example.com", Some(2222)));
        assert_eq!(
            (t.user.as_deref(), t.path.as_deref()),
            (Some("deploy"), Some("/var/www"))
        );
        for (input, protocol, encryption) in [
            (
                "ftp://example.com",
                Protocol::Ftp,
                FtpEncryption::ExplicitIfAvailable,
            ),
            ("ftps://example.com", Protocol::Ftp, FtpEncryption::Implicit),
            (
                "ftpes://example.com",
                Protocol::Ftp,
                FtpEncryption::Explicit,
            ),
            (
                "davs://example.com",
                Protocol::WebDav,
                FtpEncryption::Explicit,
            ),
            ("dav://example.com", Protocol::WebDav, FtpEncryption::Plain),
            (
                "s3://s3.amazonaws.com",
                Protocol::S3,
                FtpEncryption::Explicit,
            ),
        ] {
            assert_eq!(
                parse_host(input).unwrap().scheme,
                Some((protocol, encryption))
            );
        }
        let ipv6 = parse_host("[::1]:22").unwrap();
        assert_eq!((ipv6.host.as_str(), ipv6.port), ("::1", Some(22)));
        assert!(parse_host("  ").is_none());
    }
}

#[path = "tabs.rs"]
mod tabs;

#[cfg(test)]
#[path = "screenshots.rs"]
mod screenshots;
