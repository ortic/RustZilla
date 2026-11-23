//! RustZilla's icons: hand-drawn 16×16 SVGs, crisp at any zoom, as
//! DbCraft's icon set (whose machinery and some shapes this is).
//!
//! Icons come in two variants:
//! - **color**: semantic hues (folders amber, uploads blue, downloads green,
//!   file types by kind).
//! - **mono**: white, tinted at draw time, e.g. to the text color.
//!
//! [`install`] registers egui's SVG loader; then use [`Icon::image`] or the
//! button helpers.

mod defs;

use std::borrow::Cow;
use std::sync::OnceLock;

use egui::load::Bytes;
use egui::{Color32, Image, ImageSource, Rect, Response, Ui, Vec2, WidgetText, vec2};

pub fn install(ctx: &egui::Context) {
    egui_extras::install_image_loaders(ctx);
}

macro_rules! icons {
    ($($name:ident),* $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Icon { $($name),* }

        impl Icon {
            pub const ALL: &[Icon] = &[$(Icon::$name),*];
        }
    };
}

icons! {
    // connections
    Server, Computer, Connect, Disconnect, Reconnect, SecurityKey, Key,
    Fingerprint, Shield,
    // files
    Folder, FolderUp, NewFolder, Home, File, FileText, FileCode, FileImage,
    FileArchive, FileAudio, FileVideo, FilePdf, FileSheet, FileExec, FileKey,
    // transfers
    Upload, Download, ArrowUp, Queue, Clock, Skip, Stop,
    // status
    Error, Warning, Info, Success, Lock, Command,
    // generic ui
    Refresh, Filter, Edit, Trash, Copy, Log, Close, ChevronDown, Plus, Sun,
    Moon, Quit,
}

struct Rendered {
    color_uri: String,
    color_svg: String,
    mono_uri: String,
    mono_svg: String,
    colored: bool,
}

fn rendered(icon: Icon) -> &'static Rendered {
    static CACHE: OnceLock<Vec<Rendered>> = OnceLock::new();
    let all = CACHE.get_or_init(|| {
        Icon::ALL
            .iter()
            .map(|&icon| {
                let def = defs::def(icon);
                let (a, b) = def.colors.unwrap_or(("#ffffff", "#ffffff"));
                Rendered {
                    color_uri: format!("bytes://rustzilla-icon/{}.svg", def.name),
                    color_svg: svg_document(def.body, a, b),
                    mono_uri: format!("bytes://rustzilla-icon/{}-mono.svg", def.name),
                    mono_svg: svg_document(def.body, "#ffffff", "#ffffff"),
                    colored: def.colors.is_some(),
                }
            })
            .collect()
    });
    &all[icon as usize]
}

fn svg_document(body: &str, a: &str, b: &str) -> String {
    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">{}</svg>"#,
        body.replace("$A", a).replace("$B", b)
    )
}

impl Icon {
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn name(self) -> &'static str {
        defs::def(self).name
    }

    pub fn is_colored(self) -> bool {
        rendered(self).colored
    }

    /// The SVG document of the color (`mono = false`) or white variant.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn svg(self, mono: bool) -> &'static str {
        let r = rendered(self);
        if mono { &r.mono_svg } else { &r.color_svg }
    }

    pub fn source(self, mono: bool) -> ImageSource<'static> {
        let r = rendered(self);
        let (uri, svg) = if mono {
            (&r.mono_uri, &r.mono_svg)
        } else {
            (&r.color_uri, &r.color_svg)
        };
        ImageSource::Bytes {
            uri: Cow::Borrowed(uri.as_str()),
            bytes: Bytes::Static(svg.as_bytes()),
        }
    }

    /// In its colors, or tinted with the text color. 16pt.
    pub fn image(self, ui: &Ui) -> Image<'static> {
        self.sized(ui, 16.0)
    }

    pub fn sized(self, ui: &Ui, size: f32) -> Image<'static> {
        if self.is_colored() {
            Image::new(self.source(false)).fit_to_exact_size(Vec2::splat(size))
        } else {
            self.mono(ui.visuals().text_color())
                .fit_to_exact_size(Vec2::splat(size))
        }
    }

    /// The white variant tinted with `color`. 16pt.
    pub fn mono(self, color: Color32) -> Image<'static> {
        Image::new(self.source(true))
            .tint(color)
            .fit_to_exact_size(Vec2::splat(16.0))
    }

    /// The icon of a file, by its name's extension.
    pub fn for_file(name: &str) -> Icon {
        let lower = name.to_ascii_lowercase();
        let ext = lower.rsplit_once('.').map_or("", |(_, e)| e);
        // Dot files: shell and tool settings.
        if ext.is_empty() || lower.starts_with('.') && !lower[1..].contains('.') {
            return match lower.as_str() {
                "makefile" | "dockerfile" | "jenkinsfile" => Icon::FileCode,
                "readme" | "license" | "changelog" => Icon::FileText,
                "authorized_keys" | "known_hosts" => Icon::FileKey,
                n if n.starts_with("id_") => Icon::FileKey,
                n if n.starts_with('.') => Icon::FileText,
                _ => Icon::File,
            };
        }
        match ext {
            "txt" | "md" | "rst" | "log" | "ini" | "cfg" | "conf" | "toml" | "yaml" | "yml"
            | "env" | "properties" | "csv" | "tsv" | "doc" | "docx" | "odt" | "rtf" => {
                Icon::FileText
            }
            "rs" | "c" | "h" | "cpp" | "hpp" | "cs" | "java" | "kt" | "go" | "py" | "rb"
            | "php" | "js" | "mjs" | "ts" | "tsx" | "jsx" | "html" | "htm" | "css" | "scss"
            | "json" | "xml" | "sql" | "vue" | "svelte" | "lua" | "pl" | "swift" | "dart" => {
                Icon::FileCode
            }
            "png" | "jpg" | "jpeg" | "gif" | "webp" | "svg" | "bmp" | "ico" | "tif" | "tiff"
            | "heic" | "avif" | "psd" => Icon::FileImage,
            "zip" | "gz" | "tgz" | "tar" | "bz2" | "xz" | "zst" | "7z" | "rar" | "jar" | "war"
            | "deb" | "rpm" | "iso" | "dmg" => Icon::FileArchive,
            "mp3" | "wav" | "flac" | "ogg" | "m4a" | "aac" | "opus" => Icon::FileAudio,
            "mp4" | "mkv" | "mov" | "avi" | "webm" | "wmv" | "m4v" => Icon::FileVideo,
            "pdf" => Icon::FilePdf,
            "xls" | "xlsx" | "ods" | "numbers" => Icon::FileSheet,
            "sh" | "bash" | "zsh" | "fish" | "ps1" | "bat" | "cmd" | "exe" | "bin" | "run"
            | "appimage" | "msi" => Icon::FileExec,
            "pem" | "key" | "pub" | "crt" | "cer" | "p12" | "pfx" | "ppk" | "gpg" | "asc" => {
                Icon::FileKey
            }
            _ => Icon::File,
        }
    }
}

/// What kind of file a name is, as the panes' type column says.
pub fn file_type(name: &str) -> String {
    let ext = name
        .rsplit_once('.')
        .filter(|(stem, _)| !stem.is_empty())
        .map(|(_, e)| e.to_ascii_lowercase());
    let Some(ext) = ext else {
        return "File".into();
    };
    let known = match ext.as_str() {
        "txt" => "Text file",
        "md" => "Markdown",
        "pdf" => "PDF document",
        "zip" => "ZIP archive",
        "gz" | "tgz" => "Gzip archive",
        "tar" => "Tar archive",
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp" => "Image",
        "svg" => "SVG image",
        "html" | "htm" => "HTML document",
        "php" => "PHP script",
        "js" | "mjs" => "JavaScript",
        "ts" => "TypeScript",
        "rs" => "Rust source",
        "py" => "Python script",
        "sh" | "bash" => "Shell script",
        "json" => "JSON",
        "xml" => "XML document",
        "sql" => "SQL script",
        "css" => "Stylesheet",
        "mp3" | "wav" | "flac" | "ogg" => "Audio",
        "mp4" | "mkv" | "mov" | "webm" => "Video",
        "log" => "Log file",
        "pem" | "crt" | "cer" => "Certificate",
        "pub" => "Public key",
        _ => "",
    };
    if known.is_empty() {
        format!("{}-file", ext.to_ascii_uppercase())
    } else {
        known.into()
    }
}

/// Flat icon-only button: 16pt icon in a 24pt hit area, background on hover.
pub fn icon_button(ui: &mut Ui, icon: Icon, tooltip: &str) -> Response {
    let button = egui::Button::image(for_button(icon))
        .frame_when_inactive(false)
        .image_tint_follows_text_color(!icon.is_colored())
        .min_size(vec2(26.0, 26.0));
    let response = ui.add(button);
    if tooltip.is_empty() {
        response
    } else {
        response.on_hover_text(tooltip)
    }
}

/// Flat button with an icon and a label.
pub fn icon_text_button(ui: &mut Ui, icon: Icon, text: impl Into<WidgetText>) -> Response {
    let button = egui::Button::image_and_text(for_button(icon), text)
        .frame_when_inactive(false)
        .image_tint_follows_text_color(!icon.is_colored())
        .min_size(vec2(0.0, 26.0));
    ui.add(button)
}

/// A menu entry with an icon.
pub fn menu_item(ui: &mut Ui, icon: Icon, text: &str, enabled: bool) -> bool {
    let button = egui::Button::image_and_text(for_button(icon), text)
        .image_tint_follows_text_color(!icon.is_colored());
    ui.add_enabled(enabled, button).clicked()
}

/// Mono icons in buttons are white and tinted by the button's text color.
fn for_button(icon: Icon) -> Image<'static> {
    if icon.is_colored() {
        Image::new(icon.source(false)).fit_to_exact_size(Vec2::splat(16.0))
    } else {
        icon.mono(Color32::WHITE)
    }
}

/// A small link arrow in the bottom-left corner of an icon `rect`, for
/// symbolic links.
pub fn paint_link_badge(ui: &Ui, rect: Rect) {
    let size = rect.width() * 0.55;
    let corner = Rect::from_min_size(
        egui::pos2(rect.left() - 1.0, rect.bottom() - size + 1.0),
        Vec2::splat(size),
    );
    let painter = ui.painter();
    painter.rect_filled(corner, 2.0, ui.visuals().extreme_bg_color);
    let stroke = egui::Stroke::new(1.3, ui.visuals().hyperlink_color);
    let (a, b) = (
        egui::pos2(corner.left() + 2.0, corner.bottom() - 2.0),
        egui::pos2(corner.right() - 2.0, corner.top() + 2.0),
    );
    let head = size * 0.38;
    painter.line_segment([a, b], stroke);
    painter.line_segment([b, egui::pos2(b.x - head, b.y)], stroke);
    painter.line_segment([b, egui::pos2(b.x, b.y + head)], stroke);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_icon_draws_something() {
        use resvg::{tiny_skia, usvg};
        for &icon in Icon::ALL {
            for mono in [false, true] {
                let tree = usvg::Tree::from_str(icon.svg(mono), &usvg::Options::default())
                    .unwrap_or_else(|e| panic!("{}: {e}", icon.name()));
                let mut pixmap = tiny_skia::Pixmap::new(32, 32).unwrap();
                resvg::render(
                    &tree,
                    tiny_skia::Transform::from_scale(2.0, 2.0),
                    &mut pixmap.as_mut(),
                );
                let painted = pixmap.pixels().iter().filter(|p| p.alpha() > 0).count();
                assert!(painted > 20, "{} is nearly empty", icon.name());
            }
        }
    }

    #[test]
    fn file_icons_and_types() {
        assert_eq!(Icon::for_file("report.PDF"), Icon::FilePdf);
        assert_eq!(Icon::for_file("backup.tar.gz"), Icon::FileArchive);
        assert_eq!(Icon::for_file(".bashrc"), Icon::FileText);
        assert_eq!(Icon::for_file("id_ed25519_sk"), Icon::FileKey);
        assert_eq!(Icon::for_file("deploy.sh"), Icon::FileExec);
        assert_eq!(Icon::for_file("mystery"), Icon::File);
        assert_eq!(file_type("a.pdf"), "PDF document");
        assert_eq!(file_type("a.xyz"), "XYZ-file");
        assert_eq!(file_type(".bashrc"), "File");
    }
}
