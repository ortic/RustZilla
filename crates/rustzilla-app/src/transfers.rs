//! The transfer queue: workers take the queued files one by one, each on an
//! SFTP session of its own over the connection's one SSH login. A queued
//! directory is expanded into its files by the worker that takes it.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use rustzilla_remote::{ErrorKind, Server, Session, path};
use serde::{Deserialize, Serialize};

use crate::local;
use crate::session::LogKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction {
    Upload,
    Download,
}

/// What to do when the target file exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Exists {
    #[default]
    Ask,
    Overwrite,
    OverwriteIfNewer,
    /// Continue a partial file: appends what's missing.
    Resume,
    Skip,
}

impl Exists {
    pub const ALL: [Exists; 5] = [
        Exists::Ask,
        Exists::Overwrite,
        Exists::OverwriteIfNewer,
        Exists::Resume,
        Exists::Skip,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Exists::Ask => "Ask",
            Exists::Overwrite => "Overwrite",
            Exists::OverwriteIfNewer => "Overwrite if source newer",
            Exists::Resume => "Resume",
            Exists::Skip => "Skip",
        }
    }
}

/// Both sides of a file that exists already, for the user to decide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    pub source_size: u64,
    pub source_modified: Option<SystemTime>,
    pub target_size: u64,
    pub target_modified: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    Queued,
    Active,
    /// Waits for the user: the target exists.
    Asking(Conflict),
    Done,
    Skipped(String),
    Failed(String),
    Cancelled,
}

impl State {
    pub fn finished(&self) -> bool {
        matches!(
            self,
            State::Done | State::Skipped(_) | State::Failed(_) | State::Cancelled
        )
    }
}

#[derive(Debug, Clone)]
pub struct Item {
    pub id: u64,
    pub direction: Direction,
    /// The server the remote path is on, as the connection names it.
    pub server: String,
    pub local: PathBuf,
    pub remote: String,
    pub is_dir: bool,
    /// The size of the source, as far as known.
    pub size: u64,
    pub done: u64,
    pub state: State,
    /// How to treat an existing target, if the user decided for this file.
    pub exists: Option<Exists>,
    pub started: Option<Instant>,
    /// Where the transfer started, for the speed of a resumed one.
    pub resumed_from: u64,
    pub finished_at: Option<Instant>,
    cancel: Arc<AtomicBool>,
}

impl Item {
    /// Bytes per second.
    pub fn speed(&self) -> Option<f64> {
        let started = self.started?;
        let elapsed = self
            .finished_at
            .unwrap_or_else(Instant::now)
            .duration_since(started)
            .as_secs_f64();
        (elapsed > 0.2).then(|| (self.done - self.resumed_from) as f64 / elapsed)
    }
}

#[derive(Default)]
pub struct Queue {
    pub items: Vec<Item>,
    next_id: u64,
    pub policy: Exists,
    /// Directories whose listing changed, for the UI to refresh.
    pub changed_local: Vec<PathBuf>,
    pub changed_remote: Vec<String>,
    /// For the message log.
    pub log: Vec<(LogKind, String)>,
    generation: u64,
}

impl Queue {
    fn item(&mut self, id: u64) -> Option<&mut Item> {
        self.items.iter_mut().find(|i| i.id == id)
    }
}

struct Shared {
    queue: Mutex<Queue>,
    wake: Condvar,
}

pub struct Transfers {
    shared: Arc<Shared>,
    workers: Vec<JoinHandle<()>>,
}

/// A transfer to add to the queue; what's saved of the queue between runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewItem {
    pub direction: Direction,
    pub local: PathBuf,
    pub remote: String,
    pub is_dir: bool,
    pub size: u64,
}

impl Transfers {
    pub fn new(policy: Exists) -> Self {
        Self {
            shared: Arc::new(Shared {
                queue: Mutex::new(Queue {
                    policy,
                    ..Queue::default()
                }),
                wake: Condvar::new(),
            }),
            workers: Vec::new(),
        }
    }

    pub fn queue(&self) -> MutexGuard<'_, Queue> {
        self.shared.queue.lock().expect("queue mutex")
    }

    /// Starts `count` workers on `connection`.
    pub fn start(&mut self, connection: Arc<dyn Server>, count: usize, ctx: egui::Context) {
        self.stop();
        let generation = self.queue().generation;
        for n in 0..count.max(1) {
            let shared = self.shared.clone();
            let connection = connection.clone();
            let ctx = ctx.clone();
            let handle = thread::Builder::new()
                .name(format!("transfer-{n}"))
                .spawn(move || worker(shared, connection, generation, ctx))
                .expect("spawning a transfer thread");
            self.workers.push(handle);
        }
    }

    /// Ends the workers; what they transfer fails, the rest stays queued.
    pub fn stop(&mut self) {
        {
            let mut queue = self.queue();
            queue.generation += 1;
            for item in &queue.items {
                if item.state == State::Active {
                    item.cancel.store(true, Ordering::SeqCst);
                }
            }
        }
        self.shared.wake.notify_all();
        // Not joined: a worker may be inside a blocking call; it notices
        // the new generation when it returns.
        self.workers.clear();
    }

    pub fn add(&self, server: &str, items: Vec<NewItem>) {
        self.add_with(server, items, None);
    }

    /// Adds transfers that treat an existing target as `exists` says, not
    /// as the policy does. Returns their ids.
    pub fn add_with(&self, server: &str, items: Vec<NewItem>, exists: Option<Exists>) -> Vec<u64> {
        let mut queue = self.queue();
        let mut ids = Vec::new();
        for new in items {
            let id = queue.next_id;
            queue.next_id += 1;
            let mut item = item(id, server, new);
            item.exists = exists;
            queue.items.push(item);
            ids.push(id);
        }
        drop(queue);
        self.shared.wake.notify_all();
        ids
    }

    /// The state of the transfer `id`, if it's still in the queue.
    pub fn state_of(&self, id: u64) -> Option<State> {
        self.queue()
            .items
            .iter()
            .find(|i| i.id == id)
            .map(|i| i.state.clone())
    }

    pub fn cancel(&self, id: u64) {
        let mut queue = self.queue();
        if let Some(item) = queue.item(id) {
            match item.state {
                State::Active => item.cancel.store(true, Ordering::SeqCst),
                State::Queued | State::Asking(_) => item.state = State::Cancelled,
                _ => {}
            }
        }
    }

    pub fn cancel_all(&self) {
        let mut queue = self.queue();
        for item in &mut queue.items {
            match item.state {
                State::Active => item.cancel.store(true, Ordering::SeqCst),
                State::Queued | State::Asking(_) => item.state = State::Cancelled,
                _ => {}
            }
        }
    }

    /// Queues every failed or cancelled transfer again.
    pub fn retry_failed(&self) {
        let ids: Vec<u64> = self
            .queue()
            .items
            .iter()
            .filter(|i| matches!(i.state, State::Failed(_) | State::Cancelled))
            .map(|i| i.id)
            .collect();
        for id in ids {
            self.retry(id);
        }
    }

    /// Takes the transfers that wait for `server` out of the queue, for a
    /// tab connected to it to run them.
    pub fn take_waiting(&self, server: &str) -> Vec<NewItem> {
        let mut queue = self.queue();
        let mut taken = Vec::new();
        queue.items.retain(|i| {
            let waiting = i.state == State::Queued && i.server == server;
            if waiting {
                taken.push(NewItem {
                    direction: i.direction,
                    local: i.local.clone(),
                    remote: i.remote.clone(),
                    is_dir: i.is_dir,
                    size: i.size,
                });
            }
            !waiting
        });
        taken
    }

    /// What's still to do, to keep for the next run: with the server.
    pub fn unfinished(&self) -> Vec<(String, NewItem)> {
        self.queue()
            .items
            .iter()
            .filter(|i| matches!(i.state, State::Queued | State::Active | State::Asking(_)))
            .map(|i| {
                (
                    i.server.clone(),
                    NewItem {
                        direction: i.direction,
                        local: i.local.clone(),
                        remote: i.remote.clone(),
                        is_dir: i.is_dir,
                        size: i.size,
                    },
                )
            })
            .collect()
    }

    /// Queues a failed or cancelled transfer again.
    pub fn retry(&self, id: u64) {
        let mut queue = self.queue();
        if let Some(item) = queue.item(id)
            && matches!(item.state, State::Failed(_) | State::Cancelled)
        {
            item.state = State::Queued;
            item.cancel = Arc::new(AtomicBool::new(false));
            item.done = 0;
        }
        drop(queue);
        self.shared.wake.notify_all();
    }

    pub fn remove_finished(&self) {
        self.queue().items.retain(|i| !i.state.finished());
    }

    pub fn remove(&self, id: u64) {
        let mut queue = self.queue();
        if let Some(item) = queue.item(id) {
            item.cancel.store(true, Ordering::SeqCst);
        }
        queue
            .items
            .retain(|i| i.id != id || i.state == State::Active);
    }

    /// The user's answer for a file that exists; with `all`, for the others
    /// that wait and the ones to come.
    pub fn decide(&self, id: u64, action: Exists, all: bool) {
        let mut queue = self.queue();
        if all {
            queue.policy = action;
            for item in &mut queue.items {
                if matches!(item.state, State::Asking(_)) {
                    item.exists = Some(action);
                    item.state = State::Queued;
                }
            }
        } else if let Some(item) = queue.item(id) {
            item.exists = Some(action);
            item.state = State::Queued;
        }
        drop(queue);
        self.shared.wake.notify_all();
    }
}

impl Drop for Transfers {
    fn drop(&mut self) {
        self.stop();
    }
}

fn item(id: u64, server: &str, new: NewItem) -> Item {
    Item {
        id,
        direction: new.direction,
        server: server.to_owned(),
        local: new.local,
        remote: new.remote,
        is_dir: new.is_dir,
        size: new.size,
        done: 0,
        state: State::Queued,
        exists: None,
        started: None,
        resumed_from: 0,
        finished_at: None,
        cancel: Arc::new(AtomicBool::new(false)),
    }
}

/// How a transfer ended.
enum Outcome {
    Done,
    Skipped(String),
    Ask(Conflict),
    /// A directory, and what it holds.
    Expanded(Vec<NewItem>),
    Failed(String),
    Cancelled,
    /// The connection is gone: the item goes back to the queue.
    Lost(String),
}

fn worker(shared: Arc<Shared>, connection: Arc<dyn Server>, generation: u64, ctx: egui::Context) {
    let server = connection.name().to_owned();
    let log = |kind, text: String| {
        shared
            .queue
            .lock()
            .expect("queue mutex")
            .log
            .push((kind, text));
        ctx.request_repaint();
    };
    let mut sftp: Option<Box<dyn Session>> = None;
    loop {
        let job = {
            let mut queue = shared.queue.lock().expect("queue mutex");
            loop {
                if queue.generation != generation {
                    return;
                }
                let next = queue
                    .items
                    .iter_mut()
                    .find(|i| i.state == State::Queued && i.server == server);
                if let Some(item) = next {
                    item.state = State::Active;
                    item.started = Some(Instant::now());
                    item.finished_at = None;
                    item.done = 0;
                    item.resumed_from = 0;
                    break item.clone();
                }
                queue = shared.wake.wait(queue).expect("queue mutex");
            }
        };
        ctx.request_repaint();
        // The session opens with the first transfer.
        let session = match &mut sftp {
            Some(session) => session,
            None => match connection.open() {
                Ok(session) => sftp.insert(session),
                Err(e) => {
                    log(LogKind::Error, e.message.clone());
                    finish(&shared, job.id, Outcome::Lost(e.message));
                    return;
                }
            },
        };
        let policy = shared.queue.lock().expect("queue mutex").policy;
        let outcome = run(session, &shared, &job, policy, &ctx);
        let what = match job.direction {
            Direction::Upload => format!("{} -> {}", job.local.display(), job.remote),
            Direction::Download => format!("{} -> {}", job.remote, job.local.display()),
        };
        match &outcome {
            Outcome::Done if !job.is_dir => {
                log(LogKind::Response, format!("Transferred {what}"));
            }
            Outcome::Failed(e) | Outcome::Lost(e) => {
                log(LogKind::Error, format!("Transferring {what}: {e}"));
            }
            _ => {}
        }
        let lost = matches!(outcome, Outcome::Lost(_));
        finish(&shared, job.id, outcome);
        ctx.request_repaint();
        if lost {
            return;
        }
    }
}

fn finish(shared: &Shared, id: u64, outcome: Outcome) {
    let mut queue = shared.queue.lock().expect("queue mutex");
    let Some(index) = queue.items.iter().position(|i| i.id == id) else {
        return;
    };
    let item = &mut queue.items[index];
    item.finished_at = Some(Instant::now());
    let (direction, local, remote) = (item.direction, item.local.clone(), item.remote.clone());
    let server = item.server.clone();
    match outcome {
        Outcome::Done => item.state = State::Done,
        Outcome::Skipped(why) => item.state = State::Skipped(why),
        Outcome::Ask(conflict) => item.state = State::Asking(conflict),
        Outcome::Failed(e) => item.state = State::Failed(e),
        Outcome::Cancelled => item.state = State::Cancelled,
        // Back to the queue, for when the connection is back.
        Outcome::Lost(_) => {
            item.state = State::Queued;
            item.started = None;
        }
        Outcome::Expanded(children) => {
            item.state = State::Done;
            for (position, new) in (index + 1..).zip(children) {
                let id = queue.next_id;
                queue.next_id += 1;
                queue.items.insert(position, self::item(id, &server, new));
            }
        }
    }
    let finished = queue.items[index].state == State::Done;
    if finished {
        match direction {
            Direction::Download => {
                if let Some(parent) = local.parent() {
                    queue.changed_local.push(parent.to_owned());
                }
            }
            Direction::Upload => queue.changed_remote.push(path::parent(&remote)),
        }
    }
    drop(queue);
    shared.wake.notify_all();
}

fn run(
    sftp: &mut Box<dyn Session>,
    shared: &Shared,
    job: &Item,
    policy: Exists,
    ctx: &egui::Context,
) -> Outcome {
    let lost_or_failed = |e: rustzilla_remote::Error| match e.kind {
        ErrorKind::Cancelled => Outcome::Cancelled,
        ErrorKind::Disconnected => Outcome::Lost(e.message),
        _ => Outcome::Failed(e.message),
    };
    let cancelled = || job.cancel.load(Ordering::SeqCst);
    let action = job.exists.unwrap_or(policy);
    match (job.direction, job.is_dir) {
        (Direction::Download, true) => {
            if let Err(e) = fs::create_dir_all(&job.local) {
                return Outcome::Failed(format!("creating {}: {e}", job.local.display()));
            }
            let entries = match sftp.walk(&job.remote, &cancelled) {
                Ok(entries) => entries,
                Err(e) => return lost_or_failed(e),
            };
            let mut children = Vec::new();
            for (relative, entry) in entries {
                let local = relative
                    .split('/')
                    .fold(job.local.clone(), |p, part| p.join(part));
                if entry.is_dir() && !entry.symlink {
                    if let Err(e) = fs::create_dir_all(&local) {
                        return Outcome::Failed(format!("creating {}: {e}", local.display()));
                    }
                } else if entry.kind == rustzilla_remote::EntryKind::File {
                    children.push(NewItem {
                        direction: Direction::Download,
                        local,
                        remote: path::join(&job.remote, &relative),
                        is_dir: false,
                        size: entry.size,
                    });
                }
            }
            Outcome::Expanded(children)
        }
        (Direction::Upload, true) => {
            if let Err(e) = sftp.mkdir_all(&job.remote) {
                return lost_or_failed(e);
            }
            let entries = match local::walk(&job.local) {
                Ok(entries) => entries,
                Err(e) => return Outcome::Failed(format!("reading {}: {e}", job.local.display())),
            };
            let mut children = Vec::new();
            for (relative, is_dir) in entries {
                if cancelled() {
                    return Outcome::Cancelled;
                }
                let remote = relative.components().fold(job.remote.clone(), |p, c| {
                    path::join(&p, &c.as_os_str().to_string_lossy())
                });
                let local = job.local.join(&relative);
                if is_dir {
                    if let Err(e) = sftp.mkdir_all(&remote) {
                        return lost_or_failed(e);
                    }
                } else {
                    let size = fs::metadata(&local).map_or(0, |m| m.len());
                    children.push(NewItem {
                        direction: Direction::Upload,
                        local,
                        remote,
                        is_dir: false,
                        size,
                    });
                }
            }
            Outcome::Expanded(children)
        }
        (direction, false) => {
            // The source, and the target if it exists.
            let remote = match sftp.stat(&job.remote) {
                Ok(remote) => remote,
                Err(e) => return lost_or_failed(e),
            };
            let local = fs::metadata(&job.local).ok();
            let (source, target) = match direction {
                Direction::Download => {
                    let Some(remote) = remote else {
                        return Outcome::Failed("the file is gone".into());
                    };
                    let source = (remote.size, remote.modified);
                    let target = local.map(|m| (m.len(), m.modified().ok()));
                    (source, target)
                }
                Direction::Upload => {
                    let Some(local) = local else {
                        return Outcome::Failed("the file is gone".into());
                    };
                    let source = (local.len(), local.modified().ok());
                    let target = remote.map(|r| (r.size, r.modified));
                    (source, target)
                }
            };
            set_size(shared, job.id, source.0);
            let offset = match target {
                None => 0,
                Some((target_size, target_modified)) => match action {
                    Exists::Ask => {
                        return Outcome::Ask(Conflict {
                            source_size: source.0,
                            source_modified: source.1,
                            target_size,
                            target_modified,
                        });
                    }
                    Exists::Overwrite => 0,
                    Exists::Skip => return Outcome::Skipped("the file exists".into()),
                    Exists::OverwriteIfNewer => {
                        // In whole seconds: SFTP has no more.
                        let secs = |t: Option<SystemTime>| {
                            t.and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                                .map(|d| d.as_secs())
                        };
                        if secs(source.1) > secs(target_modified) {
                            0
                        } else {
                            return Outcome::Skipped("the target isn't older".into());
                        }
                    }
                    Exists::Resume if target_size < source.0 => target_size,
                    Exists::Resume if target_size == source.0 => {
                        return Outcome::Skipped("the file is complete".into());
                    }
                    // Bigger than the source: no part of it.
                    Exists::Resume => 0,
                },
            };
            let mut last = Instant::now();
            let mut counted = offset;
            let mut progress = |done: u64| {
                throttle(direction, done.saturating_sub(counted));
                counted = done;
                if last.elapsed().as_millis() >= 100 {
                    last = Instant::now();
                    if let Some(item) = shared.queue.lock().expect("queue mutex").item(job.id) {
                        item.done = done;
                    }
                    ctx.request_repaint();
                }
                !cancelled()
            };
            {
                let mut queue = shared.queue.lock().expect("queue mutex");
                if let Some(item) = queue.item(job.id) {
                    item.done = offset;
                    item.resumed_from = offset;
                }
            }
            let result = match direction {
                Direction::Download => {
                    if let Some(parent) = job.local.parent()
                        && let Err(e) = fs::create_dir_all(parent)
                    {
                        return Outcome::Failed(format!("creating {}: {e}", parent.display()));
                    }
                    sftp.download(&job.remote, &job.local, offset, &mut progress)
                }
                Direction::Upload => sftp.upload(&job.local, &job.remote, offset, &mut progress),
            };
            match result {
                Ok(done) => {
                    if let Some(item) = shared.queue.lock().expect("queue mutex").item(job.id) {
                        item.done = done;
                    }
                    Outcome::Done
                }
                Err(e) => lost_or_failed(e),
            }
        }
    }
}

/// The speed limits, in bytes per second (0: none), downloads and uploads,
/// for all transfers together.
static LIMITS: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

/// When the bytes counted so far may have gone, by the limit: a transfer
/// that's ahead of it waits.
static PACE: Mutex<[Option<Instant>; 2]> = Mutex::new([None, None]);

fn slot(direction: Direction) -> usize {
    match direction {
        Direction::Download => 0,
        Direction::Upload => 1,
    }
}

/// Sets the speed limit of `direction` in bytes per second; 0 for none.
pub fn set_limit(direction: Direction, bytes_per_second: u64) {
    LIMITS[slot(direction)].store(bytes_per_second, Ordering::Relaxed);
}

/// Waits as long as `bytes` more take at the speed limit, less what's left
/// of the time before: transfers share the limit.
fn throttle(direction: Direction, bytes: u64) {
    let limit = LIMITS[slot(direction)].load(Ordering::Relaxed);
    if limit == 0 || bytes == 0 {
        return;
    }
    let wait = {
        let mut pace = PACE.lock().expect("pace mutex");
        pace_for(&mut pace[slot(direction)], Instant::now(), bytes, limit)
    };
    if !wait.is_zero() {
        thread::sleep(wait);
    }
}

/// How long to wait after `bytes` at `limit` bytes per second, `at` being
/// when what went before may have gone. A pause doesn't save up: at most a
/// quarter second of credit.
fn pace_for(at: &mut Option<Instant>, now: Instant, bytes: u64, limit: u64) -> Duration {
    let credit = now.checked_sub(Duration::from_millis(250)).unwrap_or(now);
    let from = at.unwrap_or(now).max(credit);
    let next = from + Duration::from_secs_f64(bytes as f64 / limit as f64);
    *at = Some(next);
    next.saturating_duration_since(now)
}

fn set_size(shared: &Shared, id: u64, size: u64) {
    if let Some(item) = shared.queue.lock().expect("queue mutex").item(id) {
        item.size = size;
    }
}

#[cfg(test)]
mod tests {
    use rustzilla_remote::testserver::TestServer;

    use super::*;

    /// Waits until no transfer is queued or active.
    fn settle(transfers: &Transfers) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let busy = transfers
                .queue()
                .items
                .iter()
                .any(|i| matches!(i.state, State::Queued | State::Active));
            if !busy {
                return;
            }
            assert!(Instant::now() < deadline, "transfers didn't finish");
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn states(transfers: &Transfers) -> Vec<(String, State)> {
        transfers
            .queue()
            .items
            .iter()
            .filter(|i| !i.is_dir)
            .map(|i| (i.remote.clone(), i.state.clone()))
            .collect()
    }

    #[test]
    fn speed_limit_paces() {
        let start = Instant::now() + Duration::from_secs(1);
        let mut at = None;
        // 1000 bytes/s: 500 bytes are half a second ahead.
        assert_eq!(
            pace_for(&mut at, start, 500, 1000),
            Duration::from_millis(500)
        );
        // Another 500 at once: a second ahead.
        assert_eq!(pace_for(&mut at, start, 500, 1000), Duration::from_secs(1));
        // After a long pause only a quarter second counts as credit.
        let later = start + Duration::from_secs(10);
        assert_eq!(
            pace_for(&mut at, later, 500, 1000),
            Duration::from_millis(250)
        );
    }

    #[test]
    fn waiting_transfers_move_and_are_kept() {
        let transfers = Transfers::new(Exists::Ask);
        let item = |name: &str| NewItem {
            direction: Direction::Upload,
            local: PathBuf::from(name),
            remote: format!("/{name}"),
            is_dir: false,
            size: 1,
        };
        transfers.add("a", vec![item("1"), item("2")]);
        transfers.add("b", vec![item("3")]);
        assert_eq!(transfers.unfinished().len(), 3);
        let taken = transfers.take_waiting("a");
        assert_eq!(taken, vec![item("1"), item("2")]);
        assert_eq!(transfers.unfinished(), vec![("b".to_owned(), item("3"))]);
    }

    #[test]
    fn directories_up_and_down_with_conflicts() {
        let dir = std::env::temp_dir().join(format!("rustzilla-tq-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let server = TestServer::start(&dir.join("served"), &dir.join("known_hosts"));
        let connection =
            rustzilla_remote::connect(&rustzilla_remote::Params::Sftp(server.params())).unwrap();
        let name = connection.name().to_owned();

        // A tree to upload.
        let source = dir.join("source");
        fs::create_dir_all(source.join("sub/deeper")).unwrap();
        fs::write(source.join("a.txt"), "alpha").unwrap();
        fs::write(source.join("sub/b.txt"), vec![7u8; 300_000]).unwrap();
        fs::write(source.join("sub/deeper/c.txt"), "gamma").unwrap();

        let mut transfers = Transfers::new(Exists::Ask);
        transfers.start(connection.clone(), 2, egui::Context::default());
        transfers.add(
            &name,
            vec![NewItem {
                direction: Direction::Upload,
                local: source.clone(),
                remote: "/tree".into(),
                is_dir: true,
                size: 0,
            }],
        );
        settle(&transfers);
        assert!(
            states(&transfers).iter().all(|(_, s)| *s == State::Done),
            "{:?}",
            states(&transfers)
        );
        let served = dir.join("served/tree");
        assert_eq!(
            fs::read(served.join("sub/b.txt")).unwrap(),
            vec![7u8; 300_000]
        );
        assert_eq!(
            fs::read_to_string(served.join("sub/deeper/c.txt")).unwrap(),
            "gamma"
        );
        assert!(
            transfers
                .queue()
                .changed_remote
                .contains(&"/tree/sub".to_owned())
        );

        // Down again into a fresh directory, where one file is half there.
        let target = dir.join("target");
        fs::create_dir_all(target.join("sub")).unwrap();
        fs::write(target.join("sub/b.txt"), vec![7u8; 1000]).unwrap();
        transfers.remove_finished();
        transfers.add(
            &name,
            vec![NewItem {
                direction: Direction::Download,
                local: target.clone(),
                remote: "/tree".into(),
                is_dir: true,
                size: 0,
            }],
        );
        settle(&transfers);
        // The half file waits for the user; the others are done.
        let asking: Vec<_> = transfers
            .queue()
            .items
            .iter()
            .filter(|i| matches!(i.state, State::Asking(_)))
            .map(|i| (i.id, i.remote.clone()))
            .collect();
        assert_eq!(asking.len(), 1, "{:?}", states(&transfers));
        assert_eq!(asking[0].1, "/tree/sub/b.txt");
        assert_eq!(
            fs::read_to_string(target.join("sub/deeper/c.txt")).unwrap(),
            "gamma"
        );
        transfers.decide(asking[0].0, Exists::Resume, false);
        settle(&transfers);
        assert_eq!(
            fs::read(target.join("sub/b.txt")).unwrap(),
            vec![7u8; 300_000]
        );
        let resumed = transfers
            .queue()
            .items
            .iter()
            .find(|i| i.id == asking[0].0)
            .map(|i| (i.resumed_from, i.done, i.state.clone()))
            .unwrap();
        assert_eq!(resumed, (1000, 300_000, State::Done));

        // Skip and overwrite-if-newer as the policy.
        transfers.remove_finished();
        transfers.queue().policy = Exists::Skip;
        let item = || NewItem {
            direction: Direction::Download,
            local: target.join("a.txt"),
            remote: "/tree/a.txt".into(),
            is_dir: false,
            size: 5,
        };
        transfers.add(&name, vec![item()]);
        settle(&transfers);
        assert!(matches!(states(&transfers)[0].1, State::Skipped(_)));
        transfers.remove_finished();
        transfers.queue().policy = Exists::OverwriteIfNewer;
        transfers.add(&name, vec![item()]);
        settle(&transfers);
        // Same time (the download kept the server's): not newer.
        assert!(
            matches!(states(&transfers)[0].1, State::Skipped(_)),
            "{:?}",
            states(&transfers)
        );

        // A missing source fails; retry is possible.
        transfers.remove_finished();
        transfers.add(
            &name,
            vec![NewItem {
                direction: Direction::Download,
                local: target.join("nope"),
                remote: "/tree/nope".into(),
                is_dir: false,
                size: 0,
            }],
        );
        settle(&transfers);
        assert!(matches!(states(&transfers)[0].1, State::Failed(_)));

        // Items of another server wait for it.
        transfers.remove_finished();
        transfers.add("elsewhere", vec![item()]);
        thread::sleep(Duration::from_millis(200));
        assert_eq!(states(&transfers)[0].1, State::Queued);

        transfers.stop();
        connection.disconnect();
        let _ = fs::remove_dir_all(&dir);
    }
}
