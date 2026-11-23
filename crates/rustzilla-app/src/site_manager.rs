//! The Site Manager: saved servers, how to log in to them, and where to
//! start. Passwords and passphrases are kept in the OS keychain.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use egui::{RichText, Ui};

use rustzilla_remote::{FtpEncryption, Protocol};

use crate::config::{DavPreset, Logon, Site};
use crate::icons::{self, Icon};
use crate::secrets;
use crate::theme;

pub enum Outcome {
    /// Save the sites (and close, unless also connecting).
    Save(Vec<Site>),
    /// Save, then connect to the site.
    SaveAndConnect(Vec<Site>, Box<Site>, Option<String>),
    Close,
}

pub struct SiteManager {
    sites: Vec<Site>,
    selected: Option<usize>,
    /// Passwords or passphrases by site id, as loaded or edited.
    secrets: HashMap<String, String>,
    /// Sites deleted: their secrets go too.
    deleted: Vec<String>,
    /// Whether a key file is a security key's, by path.
    key_kinds: HashMap<String, KeyKind>,
    error: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    SecurityKey,
    Encrypted,
    Plain,
    Unreadable,
}

impl SiteManager {
    pub fn new(sites: Vec<Site>, select: Option<&str>) -> Self {
        let selected = select
            .and_then(|id| sites.iter().position(|s| s.id == id))
            .or((!sites.is_empty()).then_some(0));
        let key_kinds = sites
            .iter()
            .filter(|s| s.logon == Logon::KeyFile)
            .map(|s| (s.key_file.clone(), key_kind(&expand_home(&s.key_file))))
            .collect();
        Self {
            sites,
            selected,
            secrets: HashMap::new(),
            deleted: Vec::new(),
            key_kinds,
            error: None,
        }
    }

    fn secret(&mut self, id: &str) -> &mut String {
        self.secrets
            .entry(id.to_owned())
            .or_insert_with(|| secrets::load(id).unwrap_or_default())
    }

    /// Stores the secrets of the sites, forgets the deleted ones'.
    fn save_secrets(&mut self) -> Result<(), String> {
        for id in self.deleted.drain(..) {
            secrets::forget(&id);
        }
        let mut problem = None;
        for site in &self.sites {
            let Some(secret) = self.secrets.get(&site.id) else {
                continue;
            };
            let keep = match site.logon {
                Logon::Normal | Logon::KeyFile => secret.as_str(),
                Logon::AskPassword | Logon::Agent | Logon::Anonymous => "",
            };
            if let Err(e) = secrets::store(&site.id, keep) {
                problem = Some(e);
            }
        }
        problem.map_or(Ok(()), Err)
    }

    pub fn ui(&mut self, ctx: &egui::Context) -> Option<Outcome> {
        let mut outcome = None;
        let mut open = true;
        egui::Window::new("Site Manager")
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_size([760.0, 470.0])
            .show(ctx, |ui| {
                outcome = self.contents(ui);
            });
        if !open {
            return Some(Outcome::Close);
        }
        outcome
    }

    fn contents(&mut self, ui: &mut Ui) -> Option<Outcome> {
        let mut outcome = None;
        egui::Panel::bottom("site-manager-buttons")
            .frame(egui::Frame::NONE.inner_margin(egui::Margin::symmetric(0, 8)))
            .show(ui, |ui| {
                if let Some(error) = &self.error {
                    ui.colored_label(ui.visuals().error_fg_color, error);
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let can_connect = self
                        .selected
                        .and_then(|i| self.sites.get(i))
                        .is_some_and(|s| !s.host.trim().is_empty());
                    if ui.add(theme::secondary_button("Cancel")).clicked() {
                        outcome = Some(Outcome::Close);
                    }
                    if ui.add(theme::secondary_button("Save")).clicked() {
                        match self.save_secrets() {
                            Ok(()) => outcome = Some(Outcome::Save(self.sites.clone())),
                            Err(e) => {
                                self.error = Some(e);
                                outcome = Some(Outcome::Save(self.sites.clone()));
                            }
                        }
                    }
                    if ui
                        .add_enabled(can_connect, theme::primary_button("Connect"))
                        .clicked()
                    {
                        let site = self.sites[self.selected.expect("a site")].clone();
                        let secret = match site.logon {
                            Logon::Normal | Logon::KeyFile => Some(self.secret(&site.id).clone()),
                            _ => None,
                        };
                        if let Err(e) = self.save_secrets() {
                            tracing::warn!("{e}");
                        }
                        outcome = Some(Outcome::SaveAndConnect(
                            self.sites.clone(),
                            Box::new(site),
                            secret,
                        ));
                    }
                });
            });
        egui::Panel::left("site-manager-list")
            .default_size(220.0)
            .frame(egui::Frame::NONE.inner_margin(egui::Margin {
                left: 0,
                right: 10,
                top: 0,
                bottom: 0,
            }))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 2.0;
                    if icons::icon_text_button(ui, Icon::Plus, "New site").clicked() {
                        self.sites.push(Site::default());
                        self.selected = Some(self.sites.len() - 1);
                    }
                    let any = self.selected.is_some();
                    if ui
                        .add_enabled_ui(any, |ui| {
                            icons::icon_button(ui, Icon::Copy, "Duplicate the site")
                        })
                        .inner
                        .clicked()
                        && let Some(i) = self.selected
                    {
                        let mut copy = self.sites[i].clone();
                        let secret = self.secret(&copy.id).clone();
                        copy.id = crate::config::new_id();
                        copy.name = format!("Copy of {}", copy.name);
                        self.secrets.insert(copy.id.clone(), secret);
                        self.sites.insert(i + 1, copy);
                        self.selected = Some(i + 1);
                    }
                    if ui
                        .add_enabled_ui(any, |ui| {
                            icons::icon_button(ui, Icon::Trash, "Delete the site")
                        })
                        .inner
                        .clicked()
                        && let Some(i) = self.selected
                    {
                        let site = self.sites.remove(i);
                        self.deleted.push(site.id);
                        self.selected = if self.sites.is_empty() {
                            None
                        } else {
                            Some(i.min(self.sites.len() - 1))
                        };
                    }
                });
                ui.separator();
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for (i, site) in self.sites.iter().enumerate() {
                        let label = if site.name.trim().is_empty() {
                            "(unnamed)"
                        } else {
                            site.name.as_str()
                        };
                        let icon = match site.logon {
                            Logon::KeyFile
                                if self.key_kinds.get(&site.key_file)
                                    == Some(&KeyKind::SecurityKey) =>
                            {
                                Icon::SecurityKey
                            }
                            Logon::KeyFile => Icon::Key,
                            _ => Icon::Server,
                        };
                        let text = RichText::new(format!(
                            "{label}\n{}",
                            if site.host.is_empty() {
                                "no host"
                            } else {
                                &site.host
                            }
                        ));
                        let button = egui::Button::image_and_text(icon.sized(ui, 20.0), text)
                            .selected(self.selected == Some(i))
                            .frame_when_inactive(false)
                            .min_size(egui::vec2(ui.available_width(), 38.0));
                        if ui.add(button).clicked() {
                            self.selected = Some(i);
                        }
                    }
                    if self.sites.is_empty() {
                        ui.weak("No sites yet: add one with New site.");
                    }
                });
            });
        egui::CentralPanel::default().show(ui, |ui| {
            let Some(index) = self.selected else {
                ui.weak("Select a site, or add one.");
                return;
            };
            self.form(ui, index);
        });
        outcome
    }

    fn form(&mut self, ui: &mut Ui, index: usize) {
        let id = self.sites[index].id.clone();
        let logon = self.sites[index].logon;
        let key_kind = (logon == Logon::KeyFile).then(|| {
            let path = self.sites[index].key_file.clone();
            *self
                .key_kinds
                .entry(path.clone())
                .or_insert_with(|| key_kind(&expand_home(&path)))
        });
        let mut secret = self.secret(&id).clone();
        let site = &mut self.sites[index];
        let user_before = site.user.clone();
        egui::Grid::new("site-form")
            .num_columns(2)
            .spacing([12.0, 8.0])
            .show(ui, |ui| {
                ui.label("Name:");
                ui.add(egui::TextEdit::singleline(&mut site.name).desired_width(f32::INFINITY));
                ui.end_row();

                ui.label("Protocol:");
                let before = (site.protocol, site.encryption);
                egui::ComboBox::from_id_salt("protocol")
                    .selected_text(site.protocol.label())
                    .width(300.0)
                    .show_ui(ui, |ui| {
                        for protocol in Protocol::ALL {
                            ui.selectable_value(&mut site.protocol, protocol, protocol.label());
                        }
                    });
                ui.end_row();
                if !site.protocol.encryptions().is_empty() {
                    // HTTP protocols choose between HTTPS and HTTP.
                    if !site.protocol.encryptions().contains(&site.encryption) {
                        site.encryption = site.protocol.encryptions()[0];
                    }
                    ui.label("Encryption:");
                    egui::ComboBox::from_id_salt("encryption")
                        .selected_text(site.encryption.label_for(site.protocol))
                        .width(300.0)
                        .show_ui(ui, |ui| {
                            for &encryption in site.protocol.encryptions() {
                                ui.selectable_value(
                                    &mut site.encryption,
                                    encryption,
                                    encryption.label_for(site.protocol),
                                );
                            }
                        });
                    ui.end_row();
                    if site.encryption == FtpEncryption::Plain {
                        ui.label("");
                        ui.horizontal_wrapped(|ui| {
                            ui.add(Icon::Warning.sized(ui, 14.0));
                            ui.colored_label(
                                ui.visuals().warn_fg_color,
                                "The password and the files travel unencrypted.",
                            );
                        });
                        ui.end_row();
                    }
                }
                if site.protocol == Protocol::WebDav {
                    ui.label("Preset:");
                    let preset = site.preset;
                    egui::ComboBox::from_id_salt("preset")
                        .selected_text(site.preset.label())
                        .width(300.0)
                        .show_ui(ui, |ui| {
                            for preset in DavPreset::ALL {
                                ui.selectable_value(&mut site.preset, preset, preset.label());
                            }
                        });
                    ui.end_row();
                    // Nextcloud and ownCloud: HTTPS, and their folder.
                    if site.preset != preset
                        && let Some(folder) = site.preset.folder(&site.user)
                    {
                        site.encryption = FtpEncryption::Explicit;
                        site.port = 443;
                        site.remote_dir = folder;
                    }
                }
                // The default port follows the protocol, unless one was set.
                if before != (site.protocol, site.encryption) {
                    let old_default = before.0.default_port(before.1);
                    if site.port == old_default || site.port == 0 {
                        site.port = site.protocol.default_port(site.encryption);
                    }
                    if !Logon::of(site.protocol).contains(&site.logon) {
                        site.logon = Logon::Normal;
                    }
                }

                ui.label("Host:");
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut site.host)
                            .hint_text("example.com")
                            .desired_width(220.0),
                    );
                    ui.label("Port:");
                    ui.add(egui::DragValue::new(&mut site.port).range(1..=65535));
                });
                ui.end_row();

                ui.label("Logon type:");
                egui::ComboBox::from_id_salt("logon")
                    .selected_text(site.logon.label())
                    .width(220.0)
                    .show_ui(ui, |ui| {
                        for &logon in Logon::of(site.protocol) {
                            ui.selectable_value(&mut site.logon, logon, logon.label());
                        }
                    });
                ui.end_row();

                if site.protocol == Protocol::S3 {
                    ui.label("Region:");
                    ui.add(
                        egui::TextEdit::singleline(&mut site.region)
                            .hint_text("us-east-1")
                            .desired_width(220.0),
                    );
                    ui.end_row();
                }

                let s3 = site.protocol == Protocol::S3;
                if site.logon != Logon::Anonymous {
                    ui.label(if s3 { "Access key ID:" } else { "User:" });
                    ui.add(egui::TextEdit::singleline(&mut site.user).desired_width(220.0));
                    ui.end_row();
                }

                match site.logon {
                    Logon::Normal => {
                        ui.label(if s3 { "Secret key:" } else { "Password:" });
                        ui.add(
                            egui::TextEdit::singleline(&mut secret)
                                .password(true)
                                .desired_width(220.0),
                        );
                        ui.end_row();
                    }
                    Logon::KeyFile => {
                        ui.label("Key file:");
                        ui.horizontal(|ui| {
                            let edit = ui.add(
                                egui::TextEdit::singleline(&mut site.key_file)
                                    .hint_text("~/.ssh/id_ed25519_sk")
                                    .desired_width(260.0),
                            );
                            if edit.changed() {
                                self.key_kinds.remove(&site.key_file);
                            }
                            if ui.button("Browse...").clicked() {
                                let mut dialog = rfd::FileDialog::new().set_title("Key file");
                                if let Some(ssh) = std::env::home_dir().map(|h| h.join(".ssh"))
                                    && ssh.is_dir()
                                {
                                    dialog = dialog.set_directory(ssh);
                                }
                                if let Some(path) = dialog.pick_file() {
                                    site.key_file = path.display().to_string();
                                }
                            }
                        });
                        ui.end_row();
                        ui.label("");
                        match key_kind {
                            Some(KeyKind::SecurityKey) => {
                                ui.horizontal_wrapped(|ui| {
                                    ui.add(Icon::SecurityKey.image(ui));
                                    ui.label(
                                        RichText::new(
                                            "Security key (FIDO / YubiKey): asks for its touch and PIN",
                                        )
                                        .color(ui.visuals().hyperlink_color),
                                    );
                                });
                            }
                            Some(KeyKind::Unreadable) if !site.key_file.is_empty() => {
                                ui.colored_label(
                                    ui.visuals().warn_fg_color,
                                    "Can't read this key file.",
                                );
                            }
                            _ => {
                                ui.weak(
                                    "OpenSSH, PEM or PuTTY key, or the key file of a security \
                                     key (ssh-keygen -t ed25519-sk).",
                                );
                            }
                        }
                        ui.end_row();
                        ui.label("Passphrase:");
                        let hint = if key_kind == Some(KeyKind::Encrypted) {
                            "asked for when empty"
                        } else {
                            "if the key file has one"
                        };
                        ui.add(
                            egui::TextEdit::singleline(&mut secret)
                                .password(true)
                                .desired_width(220.0)
                                .hint_text(hint),
                        );
                        ui.end_row();
                    }
                    Logon::Agent => {
                        ui.label("");
                        ui.weak(
                            "Uses the keys of the SSH agent (ssh-agent, Pageant); security keys \
                             in it sign there.",
                        );
                        ui.end_row();
                    }
                    Logon::AskPassword | Logon::Anonymous => {}
                }

                // Nextcloud's folder follows the user, unless changed.
                if site.protocol == Protocol::WebDav
                    && site.user != user_before
                    && let Some(old) = site.preset.folder(&user_before)
                    && site.remote_dir == old
                    && let Some(folder) = site.preset.folder(&site.user)
                {
                    site.remote_dir = folder;
                }
                let (label, hint) = match site.protocol {
                    Protocol::WebDav => ("WebDAV folder:", "/remote.php/dav/files/USER (Nextcloud)"),
                    Protocol::S3 => ("Remote directory:", "/bucket/folder (empty: all buckets)"),
                    _ => ("Remote directory:", "home directory"),
                };
                ui.label(label);
                ui.add(
                    egui::TextEdit::singleline(&mut site.remote_dir)
                        .hint_text(hint)
                        .desired_width(f32::INFINITY),
                );
                ui.end_row();

                ui.label("Local directory:");
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut site.local_dir)
                            .hint_text("unchanged")
                            .desired_width(260.0),
                    );
                    if ui.button("Browse...").clicked()
                        && let Some(dir) = rfd::FileDialog::new().pick_folder()
                    {
                        site.local_dir = dir.display().to_string();
                    }
                });
                ui.end_row();
            });
        if *self.secrets.get(&id).unwrap_or(&String::new()) != secret {
            self.secrets.insert(id, secret);
        }
    }
}

fn key_kind(path: &Path) -> KeyKind {
    if !path.is_file() {
        KeyKind::Unreadable
    } else if rustzilla_remote::is_security_key(path) {
        KeyKind::SecurityKey
    } else if rustzilla_remote::is_encrypted_key(path) {
        KeyKind::Encrypted
    } else {
        KeyKind::Plain
    }
}

/// `~/x` as the path under the home directory.
pub fn expand_home(path: &str) -> PathBuf {
    let path = path.trim();
    if let Some(rest) = path.strip_prefix("~/").or(path.strip_prefix("~\\"))
        && let Some(home) = std::env::home_dir()
    {
        return home.join(rest);
    }
    PathBuf::from(path)
}
