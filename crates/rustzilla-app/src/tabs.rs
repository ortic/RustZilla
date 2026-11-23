//! Tabs: a connection each, as in FileZilla. The window shows one; the
//! others keep their sessions and transfers going and are polled each frame.

use egui::{Color32, RichText, Ui};

use super::{App, ConnState, Tab};
use crate::icons::{self, Icon};
use crate::theme;

impl App {
    /// The tab at `index`, shown or not.
    pub(super) fn tab_at(&self, index: usize) -> &Tab {
        if index == self.active {
            &self.tab
        } else {
            &self.tabs[index]
        }
    }

    /// Shows the tab at `index`.
    pub(super) fn switch_to(&mut self, index: usize) {
        if index == self.active || index >= self.tabs.len() {
            return;
        }
        std::mem::swap(&mut self.tab, &mut self.tabs[self.active]);
        std::mem::swap(&mut self.tab, &mut self.tabs[index]);
        self.active = index;
    }

    /// Runs `f` with the tab at `index` as the shown one, then shows the
    /// one shown before again.
    pub(super) fn with_tab<R>(&mut self, index: usize, f: impl FnOnce(&mut Self) -> R) -> R {
        let before = self.active;
        self.switch_to(index);
        let result = f(self);
        self.switch_to(before);
        result
    }

    /// Opens a tab, on the local directory of the shown one, and shows it.
    pub(super) fn new_tab(&mut self) {
        let dir = std::path::PathBuf::from(&self.tab.local.path);
        self.tabs.push(Tab::new(self.settings.exists));
        self.switch_to(self.tabs.len() - 1);
        self.list_local(&dir);
    }

    /// Closes the tab at `index`, disconnecting it; the last one is
    /// emptied instead.
    pub(super) fn close_tab(&mut self, index: usize) {
        self.with_tab(index, |app| {
            app.disconnect();
            app.tab.site = None;
            app.tab.attempt = None;
        });
        if self.tabs.len() == 1 {
            return;
        }
        // Show another one, then take this one out.
        let next = if index + 1 < self.tabs.len() {
            index + 1
        } else {
            index - 1
        };
        if index == self.active {
            self.switch_to(next);
        }
        self.tabs.remove(index);
        if self.active > index {
            self.active -= 1;
        }
    }

    /// Takes in what the sessions and transfers of the tabs not shown
    /// reported. One that needs the user (a host key, a password) comes to
    /// the front, unless a dialog is open; then it waits.
    pub(super) fn poll_background(&mut self, ctx: &egui::Context) {
        for index in 0..self.tabs.len() {
            if index == self.active {
                continue;
            }
            let free = self.dialog.is_none();
            self.with_tab(index, |app| {
                if free {
                    app.poll_session(ctx);
                }
                app.poll_transfers();
                if free && app.dialog.is_none() {
                    app.poll_edits();
                }
            });
            if free && self.dialog.is_some() {
                self.switch_to(index);
            }
        }
    }

    /// Whether a connection is open, or opening, in the shown tab.
    pub(super) fn busy(&self) -> bool {
        self.tab.state != ConnState::Idle
    }

    pub(super) fn tab_bar(&mut self, ui: &mut Ui) {
        let mut show = None;
        let mut close = None;
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            for index in 0..self.tabs.len() {
                let tab = self.tab_at(index);
                let selected = index == self.active;
                let title = tab.title();
                let (dot, tip) = match tab.state {
                    ConnState::Connected => (theme::SUCCESS, "Connected"),
                    ConnState::Connecting { .. } => (theme::ACCENT, "Connecting"),
                    ConnState::Idle => (ui.visuals().weak_text_color(), "Not connected"),
                };
                let frame = egui::Frame::NONE
                    .fill(if selected {
                        ui.visuals().widgets.active.weak_bg_fill
                    } else {
                        Color32::TRANSPARENT
                    })
                    .corner_radius(6)
                    .inner_margin(egui::Margin::symmetric(8, 3));
                let response = frame
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            let (rect, _) =
                                ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
                            ui.painter().circle_filled(rect.center(), 4.0, dot);
                            let text = RichText::new(&title);
                            ui.add(
                                egui::Label::new(if selected { text.strong() } else { text })
                                    .selectable(false)
                                    .truncate(),
                            );
                            if ui
                                .add(
                                    egui::Button::image(
                                        Icon::Close
                                            .mono(ui.visuals().text_color())
                                            .fit_to_exact_size(egui::vec2(10.0, 10.0)),
                                    )
                                    .frame_when_inactive(false)
                                    .min_size(egui::vec2(16.0, 16.0)),
                                )
                                .on_hover_text("Close the tab (Ctrl+W)")
                                .clicked()
                            {
                                close = Some(index);
                            }
                        });
                    })
                    .response
                    .interact(egui::Sense::click())
                    .on_hover_text(tip);
                if response.clicked() {
                    show = Some(index);
                }
                if response.middle_clicked() {
                    close = Some(index);
                }
            }
            if icons::icon_button(ui, Icon::Plus, "New tab (Ctrl+T)").clicked() {
                self.new_tab();
            }
        });
        if let Some(index) = close {
            self.close_tab(index);
        } else if let Some(index) = show {
            self.switch_to(index);
        }
    }

    /// Ctrl+T, Ctrl+W, Ctrl+Tab and Ctrl+Shift+Tab.
    pub(super) fn tab_keys(&mut self, ctx: &egui::Context) {
        if self.dialog.is_some() || self.site_manager.is_some() {
            return;
        }
        let (new, close, previous, next) = ctx.input_mut(|i| {
            use egui::{Key, KeyboardShortcut, Modifiers};
            // Ctrl+Shift+Tab first: Ctrl+Tab's shortcut would take it too.
            let previous = i.consume_shortcut(&KeyboardShortcut::new(
                Modifiers::CTRL | Modifiers::SHIFT,
                Key::Tab,
            ));
            (
                i.consume_shortcut(&KeyboardShortcut::new(Modifiers::COMMAND, Key::T)),
                i.consume_shortcut(&KeyboardShortcut::new(Modifiers::COMMAND, Key::W)),
                previous,
                i.consume_shortcut(&KeyboardShortcut::new(Modifiers::CTRL, Key::Tab)),
            )
        });
        let n = self.tabs.len();
        if new {
            self.new_tab();
        } else if close {
            self.close_tab(self.active);
        } else if previous {
            self.switch_to((self.active + n - 1) % n);
        } else if next {
            self.switch_to((self.active + 1) % n);
        }
    }
}
