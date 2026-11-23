//! View/Edit, as FileZilla's: a remote file is downloaded to a directory
//! of its own, opened with the system's app for it, and watched; when it's
//! saved, RustZilla offers to upload it back.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use rustzilla_remote::path;

use super::{App, Dialog, LogKind};
use crate::transfers::{Direction, Exists, NewItem, State};

/// A remote file being edited here.
pub(super) struct Edited {
    pub remote: String,
    pub local: PathBuf,
    /// The download, then the upload, of the file.
    transfer: Option<u64>,
    /// When the file was last downloaded or uploaded, as the disk has it.
    synced: Option<SystemTime>,
    /// A change seen once: asked about when it stays (the editor is done
    /// writing).
    pending: Option<SystemTime>,
    /// The user was asked and hasn't answered.
    asking: bool,
}

/// Where edited files go: a directory each, so names don't clash.
fn edit_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir()
        .join("rustzilla-edit")
        .join(format!("{}-{nanos:x}", std::process::id()))
}

fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Opens `path` with the app the system has for it.
#[cfg(not(test))]
pub(super) fn open_with_system(path: &Path) -> std::io::Result<()> {
    use std::process::Command;
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut c = Command::new("cmd");
        c.args(["/C", "start", ""]).arg(path);
        c
    };
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut c = Command::new("open");
        c.arg(path);
        c
    };
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let mut command = {
        let mut c = Command::new("xdg-open");
        c.arg(path);
        c
    };
    command.spawn().map(|_| ())
}

/// Tests don't start apps: they see what would have been opened.
#[cfg(test)]
pub(super) static OPENED: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());

#[cfg(test)]
pub(super) fn open_with_system(path: &Path) -> std::io::Result<()> {
    OPENED.lock().unwrap().push(path.to_owned());
    Ok(())
}

impl App {
    /// Downloads the remote file `name` of the shown directory and opens
    /// it once it's here.
    pub(super) fn edit(&mut self, name: &str) {
        let Some(server) = self.server() else { return };
        let remote = path::join(&self.tab.remote.path, name);
        if let Some(edited) = self.tab.edits.iter().find(|e| e.remote == remote) {
            // Already here: opened again.
            if let Err(e) = open_with_system(&edited.local) {
                self.log(LogKind::Error, format!("Opening {name}: {e}"));
            }
            return;
        }
        let local = edit_dir().join(name);
        let size = self.tab.remote.row(name).map_or(0, |r| r.size);
        let ids = self.tab.transfers.add_with(
            &server,
            vec![NewItem {
                direction: Direction::Download,
                local: local.clone(),
                remote: remote.clone(),
                is_dir: false,
                size,
            }],
            Some(Exists::Overwrite),
        );
        self.log(
            LogKind::Status,
            format!("Opening {remote} to view or edit it"),
        );
        self.tab.edits.push(Edited {
            remote,
            local,
            transfer: ids.first().copied(),
            synced: None,
            pending: None,
            asking: false,
        });
    }

    /// Follows the shown tab's edited files: opens the downloaded ones,
    /// and asks about the ones saved since.
    pub(super) fn poll_edits(&mut self) {
        let mut log = Vec::new();
        let mut ask = None;
        let transfers = &self.tab.transfers;
        self.tab.edits.retain_mut(|edited| {
            if let Some(id) = edited.transfer {
                match transfers.state_of(id) {
                    Some(State::Done) => {
                        edited.transfer = None;
                        let first = edited.synced.is_none();
                        edited.synced = modified(&edited.local);
                        edited.pending = None;
                        if first && let Err(e) = open_with_system(&edited.local) {
                            log.push((LogKind::Error, format!("Opening {}: {e}", edited.remote)));
                        }
                    }
                    Some(State::Failed(e)) => {
                        log.push((LogKind::Error, format!("{}: {e}", edited.remote)));
                        edited.transfer = None;
                        // A failed download leaves nothing to edit.
                        return edited.synced.is_some();
                    }
                    Some(State::Cancelled) | None => {
                        edited.transfer = None;
                        return edited.synced.is_some();
                    }
                    Some(_) => {}
                }
                return true;
            }
            if edited.asking || edited.synced.is_none() {
                return true;
            }
            let now = modified(&edited.local);
            if now.is_none() {
                // Deleted (or moved away): nothing to upload any more.
                return false;
            }
            if now != edited.synced {
                if edited.pending == now && ask.is_none() {
                    edited.asking = true;
                    ask = Some(edited.remote.clone());
                } else {
                    edited.pending = now;
                }
            }
            true
        });
        for (kind, text) in log {
            self.log(kind, text);
        }
        if let Some(remote) = ask {
            self.dialog = Some(Dialog::EditChanged { remote });
        }
    }

    /// The user's answer about a changed file: upload it, or not (`keep`
    /// false stops editing it).
    pub(super) fn edit_changed(&mut self, remote: &str, upload: bool, keep: bool) {
        let server = self.server();
        let Some(index) = self.tab.edits.iter().position(|e| e.remote == remote) else {
            return;
        };
        let edited = &mut self.tab.edits[index];
        edited.asking = false;
        edited.synced = modified(&edited.local);
        edited.pending = None;
        if upload {
            match server {
                Some(server) => {
                    let size = std::fs::metadata(&edited.local).map_or(0, |m| m.len());
                    let ids = self.tab.transfers.add_with(
                        &server,
                        vec![NewItem {
                            direction: Direction::Upload,
                            local: edited.local.clone(),
                            remote: edited.remote.clone(),
                            is_dir: false,
                            size,
                        }],
                        Some(Exists::Overwrite),
                    );
                    edited.transfer = ids.first().copied();
                }
                None => {
                    self.log(
                        LogKind::Error,
                        format!("Not connected: {remote} wasn't uploaded"),
                    );
                }
            }
        }
        if !keep {
            self.stop_editing(remote);
        }
    }

    /// Forgets an edited file, and removes its copy unless it's still to
    /// be uploaded.
    pub(super) fn stop_editing(&mut self, remote: &str) {
        let Some(index) = self.tab.edits.iter().position(|e| e.remote == remote) else {
            return;
        };
        if self.tab.edits[index].transfer.is_some() {
            // The upload runs; the copy goes with the app's exit.
            self.tab.edits.remove(index);
            return;
        }
        let edited = self.tab.edits.remove(index);
        if let Some(dir) = edited.local.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// Whether files of the shown tab are being edited, to look at them
    /// again shortly.
    pub(super) fn editing(&self) -> bool {
        !self.tab.edits.is_empty()
    }
}

/// Removes the copies of edited files left by this run.
pub fn clean_up() {
    let mine = format!("{}-", std::process::id());
    let root = std::env::temp_dir().join("rustzilla-edit");
    if let Ok(entries) = std::fs::read_dir(&root) {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with(&mine) {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
    }
}
