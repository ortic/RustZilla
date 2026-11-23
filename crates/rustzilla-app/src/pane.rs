//! A file list, as FileZilla's local and remote panes: the directory's
//! path, then its entries in a table, sortable, with a selection, a context
//! menu, and dragging to the other side.

use std::collections::{BTreeSet, HashMap};
use std::time::SystemTime;

use egui::{Align, Layout, RichText, Sense, Ui};
use egui_extras::{Column, TableBuilder};

use crate::compare::Mark;
use crate::format;
use crate::icons::{self, Icon};
use crate::theme;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub name: String,
    pub is_dir: bool,
    pub symlink: bool,
    pub size: u64,
    pub modified: Option<SystemTime>,
    pub permissions: Option<u32>,
    pub owner: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Local,
    Remote,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortBy {
    Name,
    Size,
    Modified,
    Permissions,
    Owner,
    Type,
}

/// What dragging carries: entries of a pane's directory, by name.
#[derive(Debug, Clone)]
pub struct DragPayload {
    pub side: Side,
    pub names: Vec<String>,
}

/// What the user asked of a pane.
#[derive(Debug, Clone)]
pub enum Action {
    /// Into a subdirectory.
    Open(String),
    Up,
    Home,
    /// Asks for the Site Manager (from the empty remote side).
    SiteManager,
    /// To a path typed in.
    Navigate(String),
    Refresh,
    /// To the other side.
    Transfer(Vec<String>),
    /// Entries dragged here from the other side.
    Dropped(Vec<String>),
    Mkdir,
    Rename(String),
    Delete(Vec<String>),
    Permissions(Vec<String>),
    /// Opens a file with the system's app for it; a remote one is
    /// downloaded first and uploaded again when it's saved.
    Edit(String),
}

pub struct Pane {
    pub side: Side,
    /// The directory shown, as text: a local path or a remote one.
    pub path: String,
    /// What the path field holds while it's edited.
    path_edit: String,
    pub rows: Vec<Row>,
    /// Shown instead of the rows, e.g. "Not connected".
    pub message: Option<String>,
    pub busy: bool,
    selected: BTreeSet<String>,
    /// Where a shift-click selection starts.
    anchor: Option<usize>,
    sort: SortBy,
    ascending: bool,
    pub filter: String,
    /// Directory comparison's marks, by name; empty when not comparing.
    pub marks: HashMap<String, Mark>,
    /// Whether keys act on this pane.
    pub focused: bool,
    /// The row to scroll to, after moving with keys.
    scroll_to: Option<usize>,
    /// What's been typed to find an entry, and when.
    typed: String,
    typed_at: f64,
    /// Selected once the listing of the directory comes in.
    pub select_after: Option<String>,
}

impl Pane {
    pub fn new(side: Side) -> Self {
        Self {
            side,
            path: String::new(),
            path_edit: String::new(),
            rows: Vec::new(),
            message: None,
            busy: false,
            selected: BTreeSet::new(),
            anchor: None,
            sort: SortBy::Name,
            ascending: true,
            filter: String::new(),
            marks: HashMap::new(),
            focused: false,
            scroll_to: None,
            typed: String::new(),
            typed_at: 0.0,
            select_after: None,
        }
    }

    /// Shows `rows` of `path`. The selection stays for entries still there
    /// in the same directory.
    pub fn set_listing(&mut self, path: String, rows: Vec<Row>) {
        if path != self.path {
            self.selected.clear();
            self.anchor = None;
            self.filter.clear();
        } else {
            self.selected
                .retain(|name| rows.iter().any(|r| &r.name == name));
        }
        self.path_edit = path.clone();
        self.path = path;
        self.rows = rows;
        self.message = None;
        self.busy = false;
        self.sort_rows();
        if let Some(name) = self.select_after.take() {
            self.select(&name);
        }
    }

    /// Selects the entry `name` alone and scrolls to it.
    pub fn select(&mut self, name: &str) {
        let visible = self.visible();
        if let Some(position) = visible.iter().position(|&i| self.rows[i].name == name) {
            self.selected.clear();
            self.selected.insert(name.to_owned());
            self.anchor = Some(position);
            self.scroll_to = Some(position);
        }
    }

    /// The keys of a file list: arrows, Page Up/Down, Home/End (Shift
    /// extends the selection), Enter, and typing a name's start.
    pub fn keys(&mut self, ctx: &egui::Context) -> Vec<Action> {
        use egui::Key;
        let visible = self.visible();
        let mut actions = Vec::new();
        if visible.is_empty() || self.message.is_some() {
            return actions;
        }
        let (moves, enter, typed, shift, command, time) = ctx.input(|i| {
            let mut moves: Vec<isize> = Vec::new();
            for (key, step) in [
                (Key::ArrowDown, 1),
                (Key::ArrowUp, -1),
                (Key::PageDown, 15),
                (Key::PageUp, -15),
                (Key::End, isize::MAX / 2),
                (Key::Home, -isize::MAX / 2),
            ] {
                if i.key_pressed(key) {
                    moves.push(step);
                }
            }
            let typed: String = i
                .events
                .iter()
                .filter_map(|e| match e {
                    egui::Event::Text(t) => Some(t.clone()),
                    _ => None,
                })
                .collect();
            (
                moves,
                i.key_pressed(Key::Enter),
                typed,
                i.modifiers.shift,
                i.modifiers.command,
                i.time,
            )
        });
        let last = visible.len() as isize - 1;
        for step in moves {
            let from = self.anchor.map_or(-1, |a| a as isize);
            let to = if from < 0 && step > 0 {
                0
            } else {
                (from + step).clamp(0, last)
            } as usize;
            if shift {
                let start = self.anchor.unwrap_or(to);
                if !command {
                    self.selected.clear();
                }
                let (a, b) = (start.min(to), start.max(to));
                for &i in &visible[a..=b] {
                    self.selected.insert(self.rows[i].name.clone());
                }
                // The selection grows from where it started.
                self.anchor = Some(to);
            } else {
                self.selected.clear();
                self.selected.insert(self.rows[visible[to]].name.clone());
                self.anchor = Some(to);
            }
            self.scroll_to = Some(to);
        }
        let typed: String = typed.chars().filter(|c| !c.is_control()).collect();
        if !typed.is_empty() && !command {
            if time - self.typed_at > 1.0 {
                self.typed.clear();
            }
            self.typed_at = time;
            self.typed.push_str(&typed.to_lowercase());
            let found = visible
                .iter()
                .position(|&i| self.rows[i].name.to_lowercase().starts_with(&self.typed));
            if let Some(position) = found {
                let name = self.rows[visible[position]].name.clone();
                self.select(&name);
            }
        }
        if enter && self.selected.len() == 1 {
            let name = self.selected().remove(0);
            match self.row(&name) {
                Some(row) if row.is_dir => actions.push(Action::Open(name)),
                Some(_) => actions.push(Action::Transfer(vec![name])),
                None => {}
            }
        } else if enter && self.selected.len() > 1 {
            actions.push(Action::Transfer(self.selected()));
        }
        actions
    }

    pub fn clear(&mut self, message: impl Into<String>) {
        self.rows.clear();
        self.selected.clear();
        self.message = Some(message.into());
        self.busy = false;
    }

    pub fn selected(&self) -> Vec<String> {
        self.selected.iter().cloned().collect()
    }

    pub fn row(&self, name: &str) -> Option<&Row> {
        self.rows.iter().find(|r| r.name == name)
    }

    fn sort_rows(&mut self) {
        let (sort, ascending) = (self.sort, self.ascending);
        self.rows.sort_by(|a, b| {
            // Directories first, whichever way.
            let order = match sort {
                SortBy::Name => natural(&a.name, &b.name),
                SortBy::Size => a.size.cmp(&b.size),
                SortBy::Modified => a.modified.cmp(&b.modified),
                SortBy::Permissions => a.permissions.cmp(&b.permissions),
                SortBy::Owner => a.owner.cmp(&b.owner),
                SortBy::Type => icons::file_type(&a.name).cmp(&icons::file_type(&b.name)),
            }
            .then_with(|| natural(&a.name, &b.name));
            b.is_dir
                .cmp(&a.is_dir)
                .then(if ascending { order } else { order.reverse() })
        });
    }

    fn visible(&self) -> Vec<usize> {
        let filter = self.filter.to_lowercase();
        (0..self.rows.len())
            .filter(|&i| filter.is_empty() || self.rows[i].name.to_lowercase().contains(&filter))
            .collect()
    }

    /// Draws the pane. `enabled` is false for the remote side while not
    /// connected; `empty` is then shown: a big icon, a message and maybe a
    /// button.
    pub fn ui(&mut self, ui: &mut Ui, title: &str, enabled: bool) -> Vec<Action> {
        let mut actions = Vec::new();
        let remote = self.side == Side::Remote;
        // Title and tools.
        ui.horizontal(|ui| {
            ui.set_min_height(28.0);
            let icon = if remote { Icon::Server } else { Icon::Computer };
            ui.add(icon.image(ui));
            ui.label(RichText::new(title).strong());
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.add_enabled_ui(enabled, |ui| {
                    ui.spacing_mut().item_spacing.x = 2.0;
                    let selection = self.selected();
                    let (transfer, tip) = if remote {
                        (Icon::Download, "Download the selection")
                    } else {
                        (Icon::Upload, "Upload the selection")
                    };
                    if ui
                        .add_enabled_ui(!selection.is_empty(), |ui| {
                            icons::icon_button(ui, transfer, tip)
                        })
                        .inner
                        .clicked()
                    {
                        actions.push(Action::Transfer(selection.clone()));
                    }
                    if ui
                        .add_enabled_ui(!selection.is_empty(), |ui| {
                            icons::icon_button(ui, Icon::Trash, "Delete the selection (Del)")
                        })
                        .inner
                        .clicked()
                    {
                        actions.push(Action::Delete(selection));
                    }
                    if icons::icon_button(ui, Icon::NewFolder, "Create directory").clicked() {
                        actions.push(Action::Mkdir);
                    }
                    ui.separator();
                    if icons::icon_button(ui, Icon::Refresh, "Refresh (F5)").clicked() {
                        actions.push(Action::Refresh);
                    }
                    if icons::icon_button(ui, Icon::Home, "Home directory").clicked() {
                        actions.push(Action::Home);
                    }
                    if icons::icon_button(ui, Icon::ArrowUp, "Parent directory (Backspace)")
                        .clicked()
                    {
                        actions.push(Action::Up);
                    }
                });
            });
        });
        // The path.
        ui.add_enabled_ui(enabled, |ui| {
            let edit = ui.add(
                egui::TextEdit::singleline(&mut self.path_edit)
                    .desired_width(f32::INFINITY)
                    .margin(egui::Margin::symmetric(8, 4))
                    .hint_text(if remote { "Remote path" } else { "Local path" }),
            );
            if edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                actions.push(Action::Navigate(self.path_edit.trim().to_owned()));
            } else if !edit.has_focus() && self.path_edit != self.path {
                self.path_edit = self.path.clone();
            }
        });
        ui.add_space(4.0);

        let footer_id = egui::Id::new(("pane-footer", remote));
        egui::Panel::bottom(footer_id)
            .frame(egui::Frame::NONE.inner_margin(egui::Margin::symmetric(0, 4)))
            .show_separator_line(false)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.add_enabled_ui(enabled && self.message.is_none(), |ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.filter)
                                .hint_text("🔍 Filter")
                                .desired_width(140.0),
                        );
                    });
                    if self.busy {
                        ui.spinner();
                    }
                    if self.message.is_none() {
                        ui.weak(self.summary());
                    }
                    if !self.marks.is_empty() {
                        ui.with_layout(Layout::right_to_left(Align::Center), legend);
                    }
                });
            });

        let stroke = if self.focused && enabled {
            egui::Stroke::new(1.0, theme::ACCENT.gamma_multiply(0.7))
        } else {
            ui.visuals().widgets.noninteractive.bg_stroke
        };
        let frame = egui::Frame::NONE
            .fill(ui.visuals().extreme_bg_color)
            .stroke(stroke)
            .corner_radius(6)
            .inner_margin(egui::Margin::same(1));
        // A drop zone of our own: egui's paints over the frame's fill.
        let zone = frame.show(ui, |ui| {
            ui.set_min_size(ui.available_size());
            if let Some(message) = self.message.clone() {
                self.empty_state(ui, &message, enabled, &mut actions);
                return;
            }
            self.table(ui, enabled, &mut actions);
        });
        let from_other_side = egui::DragAndDrop::payload::<DragPayload>(ui.ctx())
            .is_some_and(|p| p.side != self.side);
        if from_other_side && enabled && zone.response.contains_pointer() {
            ui.painter().rect_stroke(
                zone.response.rect,
                6,
                egui::Stroke::new(2.0, theme::ACCENT),
                egui::StrokeKind::Inside,
            );
        }
        let dropped = zone.response.dnd_release_payload::<DragPayload>();
        if let Some(payload) = dropped
            && payload.side != self.side
            && enabled
        {
            actions.push(Action::Dropped(payload.names.clone()));
        }
        actions
    }

    /// Instead of the rows: why there are none.
    fn empty_state(&self, ui: &mut Ui, message: &str, enabled: bool, actions: &mut Vec<Action>) {
        let remote = self.side == Side::Remote;
        ui.vertical_centered(|ui| {
            ui.add_space((ui.available_height() / 2.0 - 70.0).max(8.0));
            let icon = if remote { Icon::Server } else { Icon::Computer };
            ui.add(
                icon.mono(ui.visuals().weak_text_color())
                    .fit_to_exact_size(egui::vec2(48.0, 48.0)),
            );
            ui.add_space(8.0);
            if self.busy {
                ui.horizontal(|ui| {
                    ui.add_space((ui.available_width() / 2.0 - 60.0).max(0.0));
                    ui.spinner();
                    ui.label(RichText::new(message).size(15.0));
                });
            } else {
                ui.label(RichText::new(message).size(15.0));
            }
            if remote && !enabled && !self.busy {
                ui.add_space(4.0);
                ui.weak("Connect with Quickconnect above, or open a saved site.");
                ui.add_space(10.0);
                if ui
                    .add(
                        theme::primary_button("Open Site Manager")
                            .min_size(egui::vec2(160.0, 28.0)),
                    )
                    .clicked()
                {
                    actions.push(Action::SiteManager);
                }
            }
        });
    }

    fn summary(&self) -> String {
        if !self.selected.is_empty() {
            let (files, dirs, size) = self.count(|r| self.selected.contains(&r.name));
            return format!(
                "Selected {}. Total size: {}",
                format::counts(files, dirs),
                format::size(size)
            );
        }
        let (files, dirs, size) = self.count(|_| true);
        format!(
            "{}. Total size: {}",
            format::counts(files, dirs),
            format::size(size)
        )
    }

    fn count(&self, include: impl Fn(&Row) -> bool) -> (usize, usize, u64) {
        self.rows
            .iter()
            .filter(|r| include(r))
            .fold((0, 0, 0), |(f, d, s), r| {
                if r.is_dir {
                    (f, d + 1, s)
                } else {
                    (f + 1, d, s + r.size)
                }
            })
    }

    fn table(&mut self, ui: &mut Ui, enabled: bool, actions: &mut Vec<Action>) {
        let visible = self.visible();
        let row_height = ui.text_style_height(&egui::TextStyle::Body) + 8.0;
        let remote = self.side == Side::Remote;
        let mut table = TableBuilder::new(ui).id_salt(("pane", remote));
        if let Some(position) = self.scroll_to.take() {
            // Row 0 is "..".
            table = table.scroll_to_row(position + 1, None);
        }
        let mut table = table
            .striped(true)
            .resizable(true)
            .auto_shrink(false)
            .sense(Sense::click_and_drag())
            .cell_layout(Layout::left_to_right(Align::Center))
            .column(Column::initial(230.0).at_least(90.0).clip(true))
            .column(Column::initial(80.0).at_least(40.0))
            .column(Column::initial(100.0).at_least(40.0).clip(true))
            .column(Column::initial(122.0).at_least(60.0).clip(true));
        if remote {
            table = table
                .column(Column::initial(88.0).at_least(40.0))
                .column(Column::remainder().at_least(40.0).clip(true));
        } else {
            table = table.column(Column::remainder().at_least(40.0).clip(true));
        }
        let mut sort_clicked = None;
        let headers: &[(&str, SortBy)] = if remote {
            &[
                ("Name", SortBy::Name),
                ("Size", SortBy::Size),
                ("Type", SortBy::Type),
                ("Modified", SortBy::Modified),
                ("Permissions", SortBy::Permissions),
                ("Owner/Group", SortBy::Owner),
            ]
        } else {
            &[
                ("Name", SortBy::Name),
                ("Size", SortBy::Size),
                ("Type", SortBy::Type),
                ("Modified", SortBy::Modified),
                ("Permissions", SortBy::Permissions),
            ]
        };
        let (sort, ascending) = (self.sort, self.ascending);
        let mut clicked: Option<(usize, egui::Modifiers)> = None;
        let mut double: Option<usize> = None;
        let mut context: Option<usize> = None;
        let mut up = false;
        let mut dragged: Option<(usize, egui::Response)> = None;
        let selected = &self.selected;
        let rows = &self.rows;
        let marks = &self.marks;
        let side = self.side;
        table
            .header(row_height + 2.0, |mut header| {
                for (title, by) in headers {
                    header.col(|ui| {
                        let response = ui.add(
                            egui::Label::new(RichText::new(*title).strong())
                                .sense(Sense::click())
                                .selectable(false),
                        );
                        if sort == *by {
                            // A small triangle after the title.
                            let r = response.rect;
                            let c = egui::pos2(r.right() + 8.0, r.center().y);
                            let (dy, w) = (if ascending { -2.5 } else { 2.5 }, 3.5);
                            ui.painter().add(egui::Shape::convex_polygon(
                                vec![
                                    egui::pos2(c.x - w, c.y - dy),
                                    egui::pos2(c.x + w, c.y - dy),
                                    egui::pos2(c.x, c.y + dy),
                                ],
                                ui.visuals().text_color(),
                                egui::Stroke::NONE,
                            ));
                        }
                        if response.clicked() {
                            sort_clicked = Some(*by);
                        }
                    });
                }
            })
            .body(|body| {
                // ".." first, as FileZilla shows it; its menu is the
                // directory's.
                body.rows(row_height, visible.len() + 1, |mut row| {
                    if row.index() == 0 {
                        row.col(|ui| {
                            ui.add(Icon::FolderUp.image(ui));
                            ui.add(egui::Label::new("..").selectable(false));
                        });
                        for _ in 1..headers.len() {
                            row.col(|_| {});
                        }
                        let response = row.response();
                        if response.double_clicked() {
                            up = true;
                        }
                        if enabled {
                            response.context_menu(|ui| {
                                menu(ui, side, &[], false, actions);
                            });
                        }
                        return;
                    }
                    let index = visible[row.index() - 1];
                    let entry = &rows[index];
                    let mark = marks.get(&entry.name).copied();
                    row.set_selected(selected.contains(&entry.name));
                    row.col(|ui| {
                        tint(ui, mark);
                        let icon = if entry.is_dir {
                            Icon::Folder
                        } else {
                            Icon::for_file(&entry.name)
                        };
                        let image = ui.add(icon.image(ui));
                        if entry.symlink {
                            icons::paint_link_badge(ui, image.rect);
                        }
                        let mut name = RichText::new(&entry.name);
                        if entry.name.starts_with('.') {
                            name = name.color(ui.visuals().weak_text_color());
                        }
                        ui.add(egui::Label::new(name).selectable(false).truncate());
                    });
                    row.col(|ui| {
                        tint(ui, mark);
                        if !entry.is_dir {
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                ui.add(
                                    egui::Label::new(format::size_exact(entry.size))
                                        .selectable(false),
                                );
                            });
                        }
                    });
                    row.col(|ui| {
                        tint(ui, mark);
                        let kind = if entry.is_dir {
                            "Directory".to_owned()
                        } else {
                            icons::file_type(&entry.name)
                        };
                        ui.add(
                            egui::Label::new(
                                RichText::new(kind).color(ui.visuals().weak_text_color()),
                            )
                            .selectable(false),
                        );
                    });
                    row.col(|ui| {
                        tint(ui, mark);
                        ui.add(egui::Label::new(format::time(entry.modified)).selectable(false));
                    });
                    row.col(|ui| {
                        tint(ui, mark);
                        ui.add(
                            egui::Label::new(
                                RichText::new(format::permissions(entry))
                                    .monospace()
                                    .color(ui.visuals().weak_text_color()),
                            )
                            .selectable(false),
                        );
                    });
                    if remote {
                        row.col(|ui| {
                            tint(ui, mark);
                            ui.add(egui::Label::new(&entry.owner).selectable(false));
                        });
                    }
                    let response = row.response();
                    if response.double_clicked() {
                        double = Some(index);
                    } else if response.clicked() {
                        clicked = Some((index, response.ctx.input(|i| i.modifiers)));
                    }
                    if response.secondary_clicked() {
                        context = Some(index);
                    }
                    if enabled {
                        // The selection, or this entry if it isn't in it.
                        let targets = if selected.contains(&entry.name) {
                            selected.iter().cloned().collect()
                        } else {
                            vec![entry.name.clone()]
                        };
                        let opens = targets.len() == 1 && entry.is_dir;
                        response.context_menu(|ui| {
                            menu(ui, side, &targets, opens, actions);
                        });
                    }
                    if response.drag_started() || response.dragged() {
                        dragged = Some((index, response));
                    }
                });
            });

        if let Some(by) = sort_clicked {
            if self.sort == by {
                self.ascending = !self.ascending;
            } else {
                self.sort = by;
                self.ascending = true;
            }
            self.sort_rows();
        }
        if !enabled {
            return;
        }
        if up {
            actions.push(Action::Up);
        }
        if let Some((index, modifiers)) = clicked {
            self.click(index, modifiers, &visible);
        }
        // A right click or a drag on an entry outside the selection is on
        // that entry alone.
        for index in context.into_iter().chain(dragged.as_ref().map(|(i, _)| *i)) {
            if !self.selected.contains(&self.rows[index].name) {
                self.selected.clear();
                self.selected.insert(self.rows[index].name.clone());
                self.anchor = visible.iter().position(|&i| i == index);
            }
        }
        if let Some((_, response)) = dragged {
            response.dnd_set_drag_payload(DragPayload {
                side: self.side,
                names: self.selected(),
            });
        }
        if let Some(index) = double {
            let row = &self.rows[index];
            if row.is_dir {
                actions.push(Action::Open(row.name.clone()));
            } else {
                actions.push(Action::Transfer(vec![row.name.clone()]));
            }
        }
    }

    fn click(&mut self, index: usize, modifiers: egui::Modifiers, visible: &[usize]) {
        let position = visible.iter().position(|&i| i == index);
        let name = self.rows[index].name.clone();
        if modifiers.shift
            && let (Some(anchor), Some(position)) = (self.anchor, position)
        {
            if !modifiers.command {
                self.selected.clear();
            }
            let (from, to) = (anchor.min(position), anchor.max(position));
            for &i in &visible[from..=to.min(visible.len() - 1)] {
                self.selected.insert(self.rows[i].name.clone());
            }
            return;
        }
        if modifiers.command {
            if !self.selected.remove(&name) {
                self.selected.insert(name);
            }
        } else {
            self.selected.clear();
            self.selected.insert(name);
        }
        self.anchor = position;
    }

    pub fn select_all(&mut self) {
        let visible = self.visible();
        self.selected = visible.iter().map(|&i| self.rows[i].name.clone()).collect();
    }
}

/// The background of a compared entry.
fn tint(ui: &Ui, mark: Option<Mark>) {
    let Some(mark) = mark else { return };
    let (r, g, b) = mark_rgb(mark);
    let rect = ui.max_rect().expand2(egui::vec2(4.0, 2.0));
    ui.painter()
        .rect_filled(rect, 0, egui::Color32::from_rgba_unmultiplied(r, g, b, 48));
}

fn mark_rgb(mark: Mark) -> (u8, u8, u8) {
    match mark {
        Mark::Only => (0xe0, 0xaa, 0x1c),
        Mark::Newer => (0x36, 0xa8, 0x5f),
        Mark::Different => (0xe2, 0x50, 0x4a),
    }
}

/// What comparison's colors mean.
fn legend(ui: &mut Ui) {
    for (mark, label) in [
        (Mark::Different, "Other size"),
        (Mark::Newer, "Newer"),
        (Mark::Only, "Only here"),
    ] {
        ui.weak(label);
        let (rect, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), Sense::hover());
        let (r, g, b) = mark_rgb(mark);
        ui.painter()
            .rect_filled(rect, 2, egui::Color32::from_rgb(r, g, b));
    }
}

/// The context menu of entries (`targets`), or of the directory when
/// there are none.
fn menu(ui: &mut Ui, side: Side, targets: &[String], opens: bool, actions: &mut Vec<Action>) {
    let any = !targets.is_empty();
    let (transfer_icon, transfer) = match side {
        Side::Local => (Icon::Upload, "Upload"),
        Side::Remote => (Icon::Download, "Download"),
    };
    let mut item = |ui: &mut Ui, icon: Icon, label: &str, on: bool, action: Action| {
        if icons::menu_item(ui, icon, label, on) {
            actions.push(action);
            ui.close();
        }
    };
    ui.set_min_width(190.0);
    item(
        ui,
        transfer_icon,
        transfer,
        any,
        Action::Transfer(targets.to_vec()),
    );
    if opens {
        item(
            ui,
            Icon::Folder,
            "Open",
            true,
            Action::Open(targets[0].clone()),
        );
    } else if targets.len() == 1 {
        let label = match side {
            Side::Local => "Open with the system's app",
            Side::Remote => "View/Edit",
        };
        item(
            ui,
            Icon::External,
            label,
            true,
            Action::Edit(targets[0].clone()),
        );
    }
    ui.separator();
    item(ui, Icon::NewFolder, "Create directory", true, Action::Mkdir);
    item(ui, Icon::Refresh, "Refresh", true, Action::Refresh);
    ui.separator();
    let rename = targets.first().cloned().unwrap_or_default();
    item(
        ui,
        Icon::Edit,
        "Rename",
        targets.len() == 1,
        Action::Rename(rename),
    );
    if side == Side::Remote {
        item(
            ui,
            Icon::Lock,
            "File permissions…",
            any,
            Action::Permissions(targets.to_vec()),
        );
    }
    item(
        ui,
        Icon::Trash,
        "Delete",
        any,
        Action::Delete(targets.to_vec()),
    );
}

/// Names in "natural" order: `file2` before `file10`, case aside.
fn natural(a: &str, b: &str) -> std::cmp::Ordering {
    let (mut a, mut b) = (a.chars().peekable(), b.chars().peekable());
    loop {
        match (a.peek(), b.peek()) {
            (None, None) => return std::cmp::Ordering::Equal,
            (None, _) => return std::cmp::Ordering::Less,
            (_, None) => return std::cmp::Ordering::Greater,
            (Some(x), Some(y)) if x.is_ascii_digit() && y.is_ascii_digit() => {
                let number = |it: &mut std::iter::Peekable<std::str::Chars>| {
                    let mut n = String::new();
                    while let Some(c) = it.peek().filter(|c| c.is_ascii_digit()) {
                        n.push(*c);
                        it.next();
                    }
                    n
                };
                let (x, y) = (number(&mut a), number(&mut b));
                let (xt, yt) = (x.trim_start_matches('0'), y.trim_start_matches('0'));
                let order = xt.len().cmp(&yt.len()).then_with(|| xt.cmp(yt));
                if order != std::cmp::Ordering::Equal {
                    return order;
                }
            }
            (Some(x), Some(y)) => {
                let order = x
                    .to_lowercase()
                    .cmp(y.to_lowercase())
                    .then_with(|| x.cmp(y));
                if order != std::cmp::Ordering::Equal {
                    return order;
                }
                a.next();
                b.next();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, is_dir: bool, size: u64) -> Row {
        Row {
            name: name.into(),
            is_dir,
            symlink: false,
            size,
            modified: None,
            permissions: None,
            owner: String::new(),
        }
    }

    #[test]
    fn sorts_directories_first_naturally() {
        let mut pane = Pane::new(Side::Local);
        pane.set_listing(
            "/x".into(),
            vec![
                row("file10", false, 1),
                row("b", true, 0),
                row("File2", false, 5),
                row("A", true, 0),
            ],
        );
        let names: Vec<_> = pane.rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["A", "b", "File2", "file10"]);
        pane.sort = SortBy::Size;
        pane.ascending = false;
        pane.sort_rows();
        let names: Vec<_> = pane.rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["b", "A", "File2", "file10"]);
    }

    #[test]
    fn selection_survives_a_refresh() {
        let mut pane = Pane::new(Side::Remote);
        pane.set_listing("/x".into(), vec![row("a", false, 1), row("b", false, 1)]);
        let visible = pane.visible();
        pane.click(0, egui::Modifiers::NONE, &visible);
        pane.click(1, egui::Modifiers::SHIFT, &visible);
        assert_eq!(pane.selected(), ["a", "b"]);
        pane.set_listing("/x".into(), vec![row("b", false, 1)]);
        assert_eq!(pane.selected(), ["b"]);
        pane.set_listing("/y".into(), vec![row("b", false, 1)]);
        assert!(pane.selected().is_empty());
    }
}
