//! Finding files by name under a directory, on this computer or on the
//! server, as FileZilla's "Search remote files". Runs on a thread of its
//! own (on a session of its own for the server); results come in as found.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::SystemTime;

use egui::RichText;
use egui_extras::{Column, TableBuilder};
use rustzilla_remote::{Server, path};

use super::{App, ConnState, LogKind};
use crate::format;
use crate::icons::Icon;
use crate::pane::Side;
use crate::theme;
use crate::transfers::{Direction, NewItem};

pub(super) struct Search {
    side: Side,
    dir: String,
    pattern: String,
    results: Vec<Found>,
    selected: BTreeSet<usize>,
    running: Option<Running>,
    status: String,
}

struct Running {
    rx: Receiver<Found>,
    cancel: Arc<AtomicBool>,
}

/// A match, or (with `name` empty) the end of the search and how it went.
struct Found {
    path: String,
    name: String,
    is_dir: bool,
    size: u64,
    modified: Option<SystemTime>,
    error: Option<String>,
}

impl Search {
    pub(super) fn new(side: Side, dir: String) -> Self {
        Self {
            side,
            dir,
            pattern: String::new(),
            results: Vec::new(),
            selected: BTreeSet::new(),
            running: None,
            status: String::new(),
        }
    }
}

/// Whether `name` matches `pattern`: `*` and `?` wildcards if it has any,
/// otherwise a part of the name; case aside.
pub fn matches(pattern: &str, name: &str) -> bool {
    let (pattern, name) = (pattern.to_lowercase(), name.to_lowercase());
    if !pattern.contains(['*', '?']) {
        return name.contains(&pattern);
    }
    let (p, n): (Vec<char>, Vec<char>) = (pattern.chars().collect(), name.chars().collect());
    // Wildcard matching with backtracking to the last star.
    let (mut i, mut j) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while j < n.len() {
        if i < p.len() && (p[i] == '?' || p[i] == n[j]) {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == '*' {
            star = Some((i, j));
            i += 1;
        } else if let Some((si, sj)) = star {
            i = si + 1;
            j = sj + 1;
            star = Some((si, sj + 1));
        } else {
            return false;
        }
    }
    p[i..].iter().all(|&c| c == '*')
}

fn end(error: Option<String>) -> Found {
    Found {
        path: String::new(),
        name: String::new(),
        is_dir: false,
        size: 0,
        modified: None,
        error,
    }
}

fn search_local(dir: PathBuf, pattern: String, tx: Sender<Found>, cancel: Arc<AtomicBool>) {
    let mut pending = vec![dir];
    while let Some(dir) = pending.pop() {
        if cancel.load(Ordering::SeqCst) {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            let name = entry.file_name().to_string_lossy().into_owned();
            let full = entry.path();
            // Links to directories aren't followed: they could go round.
            let is_dir = meta.is_dir() && !entry.file_type().is_ok_and(|t| t.is_symlink());
            if is_dir {
                pending.push(full.clone());
            }
            if matches(&pattern, &name) {
                let found = Found {
                    path: full.display().to_string(),
                    name,
                    is_dir: meta.is_dir(),
                    size: if meta.is_dir() { 0 } else { meta.len() },
                    modified: meta.modified().ok(),
                    error: None,
                };
                if tx.send(found).is_err() {
                    return;
                }
            }
        }
    }
    let _ = tx.send(end(None));
}

fn search_remote(
    server: Arc<dyn Server>,
    dir: String,
    pattern: String,
    tx: Sender<Found>,
    cancel: Arc<AtomicBool>,
) {
    let mut session = match server.open() {
        Ok(session) => session,
        Err(e) => {
            let _ = tx.send(end(Some(e.message)));
            return;
        }
    };
    let mut pending = vec![dir];
    let mut error = None;
    while let Some(dir) = pending.pop() {
        if cancel.load(Ordering::SeqCst) {
            break;
        }
        let entries = match session.list(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind == rustzilla_remote::ErrorKind::Disconnected => {
                error = Some(e.message);
                break;
            }
            // A directory that can't be read: the others still can.
            Err(_) => continue,
        };
        for entry in entries {
            let full = path::join(&dir, &entry.name);
            if entry.is_dir() && !entry.symlink {
                pending.push(full.clone());
            }
            if matches(&pattern, &entry.name) {
                let found = Found {
                    path: full,
                    is_dir: entry.is_dir(),
                    size: entry.size,
                    modified: entry.modified,
                    name: entry.name,
                    error: None,
                };
                if tx.send(found).is_err() {
                    return;
                }
            }
        }
    }
    let _ = tx.send(end(error));
}

impl App {
    pub(super) fn open_search(&mut self) {
        let side = self.tab.focus;
        let dir = match side {
            Side::Local => self.tab.local.path.clone(),
            Side::Remote => self.tab.remote.path.clone(),
        };
        self.search = Some(Search::new(side, dir));
    }

    fn start_search(&mut self) {
        let Some(search) = &mut self.search else {
            return;
        };
        if let Some(running) = search.running.take() {
            running.cancel.store(true, Ordering::SeqCst);
        }
        search.results.clear();
        search.selected.clear();
        let (tx, rx) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let (dir, pattern) = (
            search.dir.trim().to_owned(),
            search.pattern.trim().to_owned(),
        );
        let flag = cancel.clone();
        let ctx = self.ctx.clone();
        match search.side {
            Side::Local => {
                std::thread::spawn(move || {
                    search_local(PathBuf::from(dir), pattern, tx, flag);
                    ctx.request_repaint();
                });
            }
            Side::Remote => {
                let Some(server) = self.tab.connection.clone() else {
                    search.status = "Connect to a server to search it.".into();
                    return;
                };
                std::thread::spawn(move || {
                    search_remote(server, dir, pattern, tx, flag);
                    ctx.request_repaint();
                });
            }
        }
        search.status = "Searching…".into();
        search.running = Some(Running { rx, cancel });
    }

    pub(super) fn search_ui(&mut self, ctx: &egui::Context) {
        let Some(search) = &mut self.search else {
            return;
        };
        // What came in.
        if let Some(running) = &search.running {
            let mut finished = None;
            for found in running.rx.try_iter() {
                if found.name.is_empty() {
                    finished = Some(found.error);
                    break;
                }
                search.results.push(found);
            }
            if let Some(error) = finished {
                search.running = None;
                search.status = match error {
                    Some(e) => format!("The search stopped: {e}"),
                    None => format!("Found {}", search.results.len()),
                };
            } else {
                ctx.request_repaint_after(std::time::Duration::from_millis(100));
            }
        }
        let connected = self.tab.state == ConnState::Connected;
        let mut open = true;
        let mut start = false;
        let mut stop = false;
        let mut show: Option<usize> = None;
        let mut transfer = false;
        egui::Window::new("Find files")
            .open(&mut open)
            .default_size([680.0, 420.0])
            .collapsible(false)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut search.side, Side::Local, "This computer");
                    ui.add_enabled_ui(connected, |ui| {
                        ui.selectable_value(&mut search.side, Side::Remote, "The server");
                    });
                });
                egui::Grid::new("search-form")
                    .num_columns(2)
                    .spacing([10.0, 6.0])
                    .show(ui, |ui| {
                        ui.label("In");
                        ui.add(
                            egui::TextEdit::singleline(&mut search.dir)
                                .desired_width(f32::INFINITY),
                        );
                        ui.end_row();
                        ui.label("Name");
                        let field = ui.add(
                            egui::TextEdit::singleline(&mut search.pattern)
                                .hint_text("part of the name, or *.log, report-202?.pdf")
                                .desired_width(f32::INFINITY),
                        );
                        if field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                            start = true;
                        }
                        ui.end_row();
                    });
                ui.horizontal(|ui| {
                    let ready = !search.pattern.trim().is_empty();
                    if search.running.is_some() {
                        ui.spinner();
                        if ui.add(theme::secondary_button("Stop")).clicked() {
                            stop = true;
                        }
                    } else if ui
                        .add_enabled(ready, theme::primary_button("Search"))
                        .clicked()
                    {
                        start = true;
                    }
                    ui.weak(&search.status);
                });
                ui.add_space(4.0);
                let row_height = ui.text_style_height(&egui::TextStyle::Body) + 8.0;
                let available = ui.available_height() - 40.0;
                TableBuilder::new(ui)
                    .id_salt("search-results")
                    .striped(true)
                    .resizable(true)
                    .auto_shrink(false)
                    .max_scroll_height(available.max(80.0))
                    .sense(egui::Sense::click())
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .column(Column::initial(200.0).clip(true))
                    .column(Column::initial(260.0).clip(true))
                    .column(Column::initial(80.0))
                    .column(Column::remainder())
                    .header(row_height, |mut h| {
                        for title in ["Name", "Directory", "Size", "Modified"] {
                            h.col(|ui| {
                                ui.strong(title);
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(row_height, search.results.len(), |mut row| {
                            let index = row.index();
                            let found = &search.results[index];
                            row.set_selected(search.selected.contains(&index));
                            row.col(|ui| {
                                let icon = if found.is_dir {
                                    Icon::Folder
                                } else {
                                    Icon::for_file(&found.name)
                                };
                                ui.add(icon.sized(ui, 14.0));
                                ui.add(egui::Label::new(&found.name).selectable(false).truncate());
                            });
                            row.col(|ui| {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(parent(search.side, &found.path))
                                            .color(ui.visuals().weak_text_color()),
                                    )
                                    .selectable(false)
                                    .truncate(),
                                );
                            });
                            row.col(|ui| {
                                if !found.is_dir {
                                    ui.label(format::size(found.size));
                                }
                            });
                            row.col(|ui| {
                                ui.label(format::time(found.modified));
                            });
                            let response = row.response();
                            if response.double_clicked() {
                                show = Some(index);
                            } else if response.clicked() {
                                let multi = ui_modifiers(&response).command;
                                if !multi {
                                    search.selected.clear();
                                }
                                if !search.selected.remove(&index) || !multi {
                                    search.selected.insert(index);
                                }
                            }
                        });
                    });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let one = search.selected.len() == 1;
                    if ui
                        .add_enabled(one, theme::secondary_button("Show in the list"))
                        .clicked()
                    {
                        show = search.selected.first().copied();
                    }
                    let (icon, label) = match search.side {
                        Side::Remote => (Icon::Download, "Download here"),
                        Side::Local => (Icon::Upload, "Upload here"),
                    };
                    let can = !search.selected.is_empty() && connected;
                    if ui
                        .add_enabled(
                            can,
                            egui::Button::image_and_text(icon.sized(ui, 14.0), label),
                        )
                        .on_hover_text("To the directory shown on the other side")
                        .clicked()
                    {
                        transfer = true;
                    }
                });
            });
        if start {
            self.start_search();
        }
        let Some(search) = &mut self.search else {
            return;
        };
        if (stop || !open)
            && let Some(running) = search.running.take()
        {
            running.cancel.store(true, Ordering::SeqCst);
            search.status = format!("Stopped; found {}", search.results.len());
        }
        if !open {
            self.search = None;
            return;
        }
        if let Some(index) = show {
            let (side, full) = (search.side, search.results[index].path.clone());
            self.show_found(side, &full);
        }
        if transfer {
            self.transfer_found();
        }
    }

    /// Opens the directory of `full` on its side and selects it there.
    fn show_found(&mut self, side: Side, full: &str) {
        match side {
            Side::Local => {
                let path = Path::new(full);
                if let (Some(dir), Some(name)) = (path.parent(), path.file_name()) {
                    self.tab.local.select_after = Some(name.to_string_lossy().into_owned());
                    let dir = dir.to_owned();
                    self.list_local(&dir);
                }
                self.tab.focus = Side::Local;
            }
            Side::Remote => {
                self.tab.remote.select_after = Some(path::file_name(full).to_owned());
                self.list_remote(path::parent(full));
                self.tab.focus = Side::Remote;
            }
        }
    }

    /// Transfers the selected results to the directory of the other side.
    fn transfer_found(&mut self) {
        let Some(search) = &self.search else { return };
        let Some(server) = self.server() else { return };
        let items: Vec<NewItem> = search
            .selected
            .iter()
            .map(|&i| &search.results[i])
            .map(|found| match search.side {
                Side::Remote => NewItem {
                    direction: Direction::Download,
                    local: PathBuf::from(&self.tab.local.path).join(&found.name),
                    remote: found.path.clone(),
                    is_dir: found.is_dir,
                    size: found.size,
                },
                Side::Local => NewItem {
                    direction: Direction::Upload,
                    local: PathBuf::from(&found.path),
                    remote: path::join(&self.tab.remote.path, &found.name),
                    is_dir: found.is_dir,
                    size: found.size,
                },
            })
            .collect();
        let n = items.len();
        self.tab.transfers.add(&server, items);
        self.log(LogKind::Status, format!("Queued {n} found entries"));
    }
}

fn ui_modifiers(response: &egui::Response) -> egui::Modifiers {
    response.ctx.input(|i| i.modifiers)
}

/// The directory of a found entry, as shown.
fn parent(side: Side, full: &str) -> String {
    match side {
        Side::Local => Path::new(full)
            .parent()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        Side::Remote => path::parent(full),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards_and_parts() {
        assert!(matches("report", "Annual-Report.pdf"));
        assert!(matches("*.log", "server.LOG"));
        assert!(!matches("*.log", "server.log.gz"));
        assert!(matches("*.log*", "server.log.gz"));
        assert!(matches("report-202?.pdf", "report-2026.pdf"));
        assert!(!matches("report-202?.pdf", "report-20266.pdf"));
        assert!(matches("a*b*c", "aXXbYYc"));
        assert!(!matches("a*b*c", "aXXbYY"));
        assert!(matches("*", "anything"));
    }

    #[test]
    fn finds_local_files() {
        let dir = std::env::temp_dir().join(format!("rustzilla-search-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("a/b")).unwrap();
        std::fs::write(dir.join("a/b/notes.log"), "x").unwrap();
        std::fs::write(dir.join("top.log"), "x").unwrap();
        std::fs::write(dir.join("a/other.txt"), "x").unwrap();
        let (tx, rx) = mpsc::channel();
        search_local(
            dir.clone(),
            "*.log".into(),
            tx,
            Arc::new(AtomicBool::new(false)),
        );
        let mut names: Vec<String> = rx
            .iter()
            .filter(|f| !f.name.is_empty())
            .map(|f| f.name)
            .collect();
        names.sort();
        assert_eq!(names, ["notes.log", "top.log"]);
        let _ = std::fs::remove_dir_all(dir);
    }
}
