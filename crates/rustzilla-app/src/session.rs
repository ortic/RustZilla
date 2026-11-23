//! A connection to a server: a worker thread logs in, then lists and
//! changes the remote side on the UI's commands. Transfers run on workers of
//! their own on the same SSH connection (transfers.rs).

use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

use rustzilla_remote::{Error, ErrorKind, Params, RemoteEntry, Server, Session as Remote, path};

/// What the UI asks of the session.
pub enum Command {
    List(String),
    Mkdir(String),
    Rename {
        from: String,
        to: String,
    },
    /// Paths, and whether each is a directory (deleted with its contents).
    Delete(Vec<(String, bool)>),
    Chmod {
        paths: Vec<String>,
        mode: u32,
    },
    Disconnect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogKind {
    Status,
    Command,
    Response,
    Error,
}

/// What the session tells the UI.
pub enum Event {
    Log(LogKind, String),
    /// The security key waits to be touched.
    Touch,
    Connected {
        connection: Arc<dyn Server>,
        home: String,
    },
    /// Logging in failed.
    Failed(Error),
    Listing {
        path: String,
        entries: Vec<RemoteEntry>,
    },
    ListFailed {
        path: String,
    },
    /// Something in the directory changed: list it again.
    Changed(String),
    Disconnected(Option<String>),
}

pub struct Session {
    tx: Sender<Command>,
    pub rx: Receiver<Event>,
}

impl Session {
    /// Logs in on a thread of its own, then lists `start_dir` (the home
    /// directory if empty).
    pub fn start(mut params: Params, start_dir: String, ctx: egui::Context) -> Self {
        let (tx, commands) = mpsc::channel();
        let (events, rx) = mpsc::channel();
        let emit = {
            let events = events.clone();
            let ctx = ctx.clone();
            move |event| {
                let _ = events.send(event);
                ctx.request_repaint();
            }
        };
        let touch = {
            let events = std::sync::Mutex::new(events.clone());
            let ctx = ctx.clone();
            Arc::new(move || {
                if let Ok(events) = events.lock() {
                    let _ = events.send(Event::Touch);
                }
                ctx.request_repaint();
            })
        };
        if let Params::Sftp(ssh) = &mut params {
            ssh.on_touch = Some(touch);
        }
        thread::Builder::new()
            .name("session".into())
            .spawn(move || run(params, start_dir, commands, emit))
            .expect("spawning the session thread");
        Self { tx, rx }
    }

    pub fn send(&self, command: Command) {
        let _ = self.tx.send(command);
    }
}

fn run(params: Params, start_dir: String, commands: Receiver<Command>, emit: impl Fn(Event)) {
    let log = |kind, text: String| emit(Event::Log(kind, text));
    let server = format!("{}:{}", params.host(), params.port());
    log(LogKind::Status, format!("Connecting to {server}..."));
    let connection = match rustzilla_remote::connect(&params) {
        Ok(connection) => connection,
        Err(e) => return emit(Event::Failed(e)),
    };
    log(
        LogKind::Status,
        format!(
            "Logged in to {} as {}",
            connection.name(),
            if params.username().is_empty() {
                "anonymous"
            } else {
                params.username()
            }
        ),
    );
    let mut sftp = match connection.open() {
        Ok(sftp) => sftp,
        Err(e) => return emit(Event::Failed(e)),
    };
    let home = match sftp.canonicalize(".") {
        Ok(home) => home,
        Err(e) => return emit(Event::Failed(e)),
    };
    emit(Event::Connected {
        connection: connection.clone(),
        home: home.clone(),
    });
    let start = if start_dir.trim().is_empty() {
        home
    } else {
        start_dir.trim().to_owned()
    };
    let mut worker = Worker { sftp, emit: &emit };
    if !worker.list(&start) {
        return;
    }
    for command in commands {
        let alive = match command {
            Command::List(dir) => worker.list(&dir),
            Command::Mkdir(dir) => {
                log(LogKind::Command, format!("mkdir {dir}"));
                {
                    let result = worker.sftp.mkdir(&dir);
                    worker.change(&path::parent(&dir), result)
                }
            }
            Command::Rename { from, to } => {
                log(LogKind::Command, format!("rename {from} -> {to}"));
                let result = worker.sftp.rename(&from, &to);
                let alive = worker.change(&path::parent(&from), result);
                if alive && path::parent(&from) != path::parent(&to) {
                    emit(Event::Changed(path::parent(&to)));
                }
                alive
            }
            Command::Delete(targets) => {
                let mut alive = true;
                let mut dirs = Vec::new();
                for (target, is_dir) in targets {
                    log(LogKind::Command, format!("delete {target}"));
                    let result = if is_dir {
                        worker.sftp.remove_all(&target, &|| false)
                    } else {
                        worker.sftp.remove_file(&target)
                    };
                    if !worker.check(result) {
                        alive = false;
                        break;
                    }
                    let parent = path::parent(&target);
                    if !dirs.contains(&parent) {
                        dirs.push(parent);
                    }
                }
                for dir in dirs {
                    emit(Event::Changed(dir));
                }
                alive
            }
            Command::Chmod { paths, mode } => {
                let mut alive = true;
                for target in &paths {
                    log(LogKind::Command, format!("chmod {mode:o} {target}"));
                    let result = worker.sftp.chmod(target, mode);
                    if !worker.check(result) {
                        alive = false;
                        break;
                    }
                }
                if let Some(first) = paths.first() {
                    emit(Event::Changed(path::parent(first)));
                }
                alive
            }
            Command::Disconnect => {
                connection.disconnect();
                emit(Event::Log(
                    LogKind::Status,
                    format!("Disconnected from {server}"),
                ));
                emit(Event::Disconnected(None));
                return;
            }
        };
        if !alive {
            return;
        }
    }
    // The UI dropped the session.
    connection.disconnect();
}

struct Worker<'a, E: Fn(Event)> {
    sftp: Box<dyn Remote>,
    emit: &'a E,
}

impl<E: Fn(Event)> Worker<'_, E> {
    /// Lists `dir`; false when the connection is gone.
    fn list(&mut self, dir: &str) -> bool {
        (self.emit)(Event::Log(LogKind::Command, format!("ls {dir}")));
        let result = self.sftp.canonicalize(dir).and_then(|dir| {
            let entries = self.sftp.list(&dir)?;
            Ok((dir, entries))
        });
        match result {
            Ok((path, entries)) => {
                (self.emit)(Event::Log(
                    LogKind::Response,
                    format!("Listed {path}: {} entries", entries.len()),
                ));
                (self.emit)(Event::Listing { path, entries });
                true
            }
            Err(e) => {
                let alive = self.check(Err(e));
                (self.emit)(Event::ListFailed {
                    path: dir.to_owned(),
                });
                alive
            }
        }
    }

    /// Logs the result of a change and has `dir` listed again.
    fn change(&mut self, dir: &str, result: Result<(), Error>) -> bool {
        let ok = result.is_ok();
        let alive = self.check(result);
        if ok {
            (self.emit)(Event::Changed(dir.to_owned()));
        }
        alive
    }

    /// Logs an error; false when the connection is gone.
    fn check(&mut self, result: Result<(), Error>) -> bool {
        match result {
            Ok(()) => true,
            Err(e) if e.kind == ErrorKind::Disconnected => {
                (self.emit)(Event::Log(LogKind::Error, e.message.clone()));
                (self.emit)(Event::Disconnected(Some(e.message)));
                false
            }
            Err(e) => {
                (self.emit)(Event::Log(LogKind::Error, e.message));
                true
            }
        }
    }
}
