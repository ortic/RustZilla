//! SVG sources of all icons, drawn on a 16×16 grid, in DbCraft's style.
//!
//! Conventions: 1.5px strokes with round caps and joins, content kept inside
//! 1.5..14.5, soft fills at 15–45% opacity for surfaces and solid fills only
//! for status glyphs. `$A` is the primary and `$B` the secondary color; both
//! become white in the monochrome variant, which is tinted at draw time.
//! Status glyphs cut their mark out with a mask so they work in both.

use super::Icon;

/// Semantic palette: mid lightness so every hue reads on dark and light
/// backgrounds (DbCraft's).
pub mod palette {
    pub const BLUE: &str = "#3d8fe0";
    pub const TEAL: &str = "#1fa596";
    pub const PURPLE: &str = "#9b6ce3";
    pub const ORANGE: &str = "#e8793a";
    pub const AMBER: &str = "#d99a1a";
    pub const PINK: &str = "#de5b93";
    pub const GRAY: &str = "#8a919b";
    pub const CYAN: &str = "#159fc2";
    pub const GREEN: &str = "#36a85f";
    pub const RED: &str = "#e2504a";
    pub const GOLD: &str = "#e0aa1c";
    pub const STEEL: &str = "#6d97cf";
    pub const SLATE: &str = "#8090a8";
    pub const FOLDER: &str = "#d7a23a";
}

pub struct Def {
    pub name: &'static str,
    pub body: &'static str,
    /// Semantic colors (`$A`, `$B`); `None` for monochrome-only icons.
    pub colors: Option<(&'static str, &'static str)>,
}

const fn mono(name: &'static str, body: &'static str) -> Def {
    Def {
        name,
        body,
        colors: None,
    }
}

const fn color(name: &'static str, a: &'static str, b: &'static str, body: &'static str) -> Def {
    Def {
        name,
        body,
        colors: Some((a, b)),
    }
}

/// A page with a folded corner, its glyph drawn in `$B` below the fold.
macro_rules! page {
    ($glyph:literal) => {
        concat!(
            r#"<path d="M9.25 1.75h-5a1 1 0 0 0-1 1v10.5a1 1 0 0 0 1 1h7.5a1 1 0 0 0 1-1v-8z" stroke="$A" fill="$A" fill-opacity=".16"/><path d="M9.25 1.75v2.5a1 1 0 0 0 1 1h2.5" stroke="$A"/>"#,
            $glyph
        )
    };
}
macro_rules! folder {
    ($opacity:literal) => {
        concat!(
            r#"<path d="M1.75 4a1.25 1.25 0 0 1 1.25-1.25h3l1.5 1.5h5.5A1.25 1.25 0 0 1 14.25 5.5v6.75a1.25 1.25 0 0 1-1.25 1.25H3a1.25 1.25 0 0 1-1.25-1.25z" stroke="$A" fill="$A" fill-opacity=""#,
            $opacity,
            r#""/><path d="M1.75 6.75h12.5" stroke="$A"/>"#
        )
    };
}
macro_rules! tray {
    () => {
        r#"<path d="M13.75 9.75v2.5a1.5 1.5 0 0 1-1.5 1.5h-8.5a1.5 1.5 0 0 1-1.5-1.5v-2.5" stroke="$A"/>"#
    };
}
macro_rules! key_shape {
    () => {
        r#"<circle cx="5" cy="8" r="2.75" stroke="$A" fill="$A" fill-opacity=".25"/><path d="M7.75 8h6.25M12.5 8v2.5M10.25 8v1.75" stroke="$A"/>"#
    };
}

use palette::*;

pub fn def(icon: Icon) -> Def {
    match icon {
        // ----- connections ------------------------------------------------------
        Icon::Server => color(
            "server",
            STEEL,
            GREEN,
            r#"<rect x="2" y="2.25" width="12" height="5" rx="1.5" stroke="$A" fill="$A" fill-opacity=".25"/><rect x="2" y="8.75" width="12" height="5" rx="1.5" stroke="$A" fill="$A" fill-opacity=".25"/><circle cx="4.75" cy="4.75" r=".8" fill="$B"/><circle cx="4.75" cy="11.25" r=".8" fill="$B"/><path d="M8 4.75h3.5M8 11.25h3.5" stroke="$A"/>"#,
        ),
        Icon::Computer => color(
            "computer",
            SLATE,
            SLATE,
            r#"<rect x="1.75" y="2.25" width="12.5" height="8.5" rx="1.5" stroke="$A" fill="$A" fill-opacity=".2"/><path d="M8 10.75v2.75M5 13.75h6" stroke="$A"/>"#,
        ),
        Icon::Connect => color(
            "connect",
            GREEN,
            GREEN,
            r#"<path d="M6.25 2v3.75M9.75 2v3.75" stroke="$A"/><path d="M4.25 5.75h7.5v2.5a3.75 3.75 0 0 1-7.5 0z" stroke="$A" fill="$A" fill-opacity=".25"/><path d="M8 12v2.25" stroke="$A"/>"#,
        ),
        Icon::Disconnect => color(
            "disconnect",
            GRAY,
            RED,
            r#"<path d="M5.25 1.75v3.5M8.25 1.75v3.5" stroke="$A"/><path d="M3.25 5.25h7v2.25a3.5 3.5 0 0 1-7 0z" stroke="$A" fill="$A" fill-opacity=".2"/><path d="M6.75 11v3.25" stroke="$A"/><path d="M10.5 10.5l3.25 3.25M13.75 10.5l-3.25 3.25" stroke="$B"/>"#,
        ),
        Icon::Reconnect => color(
            "reconnect",
            BLUE,
            BLUE,
            r#"<path d="M13.25 8a5.25 5.25 0 1 1-1.54-3.71" stroke="$A"/><path d="M12.25 1.75v3h-3" stroke="$A"/><path d="M6.75 6.25v1.5M9.25 6.25v1.5M5.75 7.75h4.5v.75a2.25 2.25 0 0 1-4.5 0z" stroke="$A" stroke-width="1.1"/>"#,
        ),
        Icon::SecurityKey => color(
            "security-key",
            SLATE,
            GOLD,
            r#"<path d="M1.5 6.25h2.25v3.5H1.5z" stroke="$A" stroke-width="1.1"/><rect x="3.75" y="4" width="10.75" height="8" rx="2.25" stroke="$A" fill="$A" fill-opacity=".35"/><circle cx="10" cy="8" r="2.1" fill="$B"/><circle cx="10" cy="8" r="2.1" stroke="$B" stroke-opacity=".6"/>"#,
        ),
        Icon::Key => color("key", GOLD, GOLD, key_shape!()),
        Icon::Fingerprint => color(
            "fingerprint",
            TEAL,
            TEAL,
            r#"<path d="M3.25 6.25a5 5 0 0 1 9.5 0M2.5 9.25v-.5M13.5 9.75V8.5" stroke="$A"/><path d="M4.75 12.25c.6-1 .75-2.25.75-3.75a2.5 2.5 0 0 1 5 0c0 1.5-.15 3.25-.75 4.75" stroke="$A"/><path d="M8 8.5c0 2.2-.35 3.95-1.25 5.5M12.25 11.75c.15-.6.25-1.25.25-2" stroke="$A"/>"#,
        ),
        Icon::Shield => color(
            "shield",
            GREEN,
            GREEN,
            r#"<path d="M8 1.75l5.25 2v4c0 3.1-2.2 5.4-5.25 6.5-3.05-1.1-5.25-3.4-5.25-6.5v-4z" stroke="$A" fill="$A" fill-opacity=".18"/><path d="M5.6 8l1.65 1.65L10.4 6.5" stroke="$A"/>"#,
        ),
        // ----- files ------------------------------------------------------------
        Icon::Folder => color("folder", FOLDER, FOLDER, folder!(".45")),
        Icon::FolderUp => color(
            "folder-up",
            FOLDER,
            FOLDER,
            concat!(
                folder!(".25"),
                r#"<path d="M8 12V8.75M6.5 10.25 8 8.75l1.5 1.5" stroke="$A"/>"#
            ),
        ),
        Icon::NewFolder => color(
            "new-folder",
            FOLDER,
            GREEN,
            r#"<path d="M8 13.5H3a1.25 1.25 0 0 1-1.25-1.25V4A1.25 1.25 0 0 1 3 2.75h3l1.5 1.5h5.5A1.25 1.25 0 0 1 14.25 5.5V8" stroke="$A" fill="$A" fill-opacity=".35"/><path d="M1.75 6.75h12.5" stroke="$A"/><path d="M12.25 9.75v4.5M10 12h4.5" stroke="$B"/>"#,
        ),
        Icon::Home => mono(
            "home",
            r#"<path d="M2 7.5 8 2.25l6 5.25" stroke="$A"/><path d="M3.75 6.25v6.5a1 1 0 0 0 1 1h6.5a1 1 0 0 0 1-1v-6.5" stroke="$A" fill="$A" fill-opacity=".15"/><path d="M6.5 13.75v-3.5h3v3.5" stroke="$A"/>"#,
        ),
        Icon::File => color("file", GRAY, GRAY, page!("")),
        Icon::FileText => color(
            "file-text",
            STEEL,
            STEEL,
            page!(r#"<path d="M5.5 8h5M5.5 10.25h5M5.5 12.25h3" stroke="$B" stroke-width="1.2"/>"#),
        ),
        Icon::FileCode => color(
            "file-code",
            PURPLE,
            PURPLE,
            page!(
                r#"<path d="M6.5 8.25 5 9.9l1.5 1.65M9.5 8.25 11 9.9l-1.5 1.65" stroke="$B" stroke-width="1.3"/>"#
            ),
        ),
        Icon::FileImage => color(
            "file-image",
            TEAL,
            TEAL,
            page!(
                r#"<circle cx="6.4" cy="8.1" r="1" fill="$B"/><path d="M4.75 12.75l2.25-2.5 1.5 1.5 1.25-1.25 1.5 2.25" stroke="$B" stroke-width="1.2"/>"#
            ),
        ),
        Icon::FileArchive => color(
            "file-archive",
            AMBER,
            AMBER,
            page!(
                r#"<path d="M7 2.5v1M8.25 3.5v1M7 4.5v1M8.25 5.5v1" stroke="$B" stroke-width="1.1"/><rect x="6.5" y="8" width="2.5" height="3" rx=".6" stroke="$B" stroke-width="1.1" fill="$B" fill-opacity=".35"/>"#
            ),
        ),
        Icon::FileAudio => color(
            "file-audio",
            PINK,
            PINK,
            page!(
                r#"<path d="M9.5 7.5v4" stroke="$B" stroke-width="1.2"/><path d="M9.5 7.5l1.5.6" stroke="$B" stroke-width="1.2"/><circle cx="8.15" cy="11.5" r="1.35" fill="$B"/>"#
            ),
        ),
        Icon::FileVideo => color(
            "file-video",
            ORANGE,
            ORANGE,
            page!(
                r#"<path d="M6.5 8.25v3.75l3.25-1.9z" stroke="$B" stroke-width="1.1" fill="$B"/>"#
            ),
        ),
        Icon::FilePdf => color(
            "file-pdf",
            RED,
            RED,
            page!(
                r#"<rect x="4.75" y="8.25" width="6.5" height="3.5" rx=".8" fill="$B" fill-opacity=".85"/>"#
            ),
        ),
        Icon::FileSheet => color(
            "file-sheet",
            GREEN,
            GREEN,
            page!(
                r#"<path d="M5.25 8.25h5.5v4h-5.5zM5.25 10.25h5.5M8 8.25v4" stroke="$B" stroke-width="1.1"/>"#
            ),
        ),
        Icon::FileExec => color(
            "file-exec",
            CYAN,
            CYAN,
            page!(
                r#"<path d="M5.25 8.25 6.9 9.75l-1.65 1.5M8.25 12h2.5" stroke="$B" stroke-width="1.3"/>"#
            ),
        ),
        Icon::FileKey => color(
            "file-key",
            GOLD,
            GOLD,
            page!(
                r#"<circle cx="6.4" cy="10" r="1.3" stroke="$B" stroke-width="1.2"/><path d="M7.7 10h3.05M10 10v1.3" stroke="$B" stroke-width="1.2"/>"#
            ),
        ),
        // ----- transfers --------------------------------------------------------
        Icon::Upload => color(
            "upload",
            BLUE,
            BLUE,
            concat!(
                tray!(),
                r#"<path d="M8 10.5V2.5M4.75 5.5 8 2.25l3.25 3.25" stroke="$A"/>"#
            ),
        ),
        Icon::Download => color(
            "download",
            GREEN,
            GREEN,
            concat!(
                tray!(),
                r#"<path d="M8 2.25v8M4.75 7.25 8 10.5l3.25-3.25" stroke="$A"/>"#
            ),
        ),
        Icon::ArrowUp => mono(
            "arrow-up",
            r#"<path d="M8 13.25V3M3.75 7.25 8 3l4.25 4.25" stroke="$A"/>"#,
        ),
        Icon::Queue => mono(
            "queue",
            r#"<path d="M2.25 3.5h7.5M2.25 7h7.5M2.25 10.5h4.5" stroke="$A"/><circle cx="11.5" cy="11" r="3" stroke="$A" fill="$A" fill-opacity=".2"/><path d="M11.5 9.6v1.5l.9.7" stroke="$A" stroke-width="1.1"/>"#,
        ),
        Icon::Clock => mono(
            "clock",
            r#"<circle cx="8" cy="8" r="5.75" stroke="$A" fill="$A" fill-opacity=".12"/><path d="M8 4.75V8l2.25 1.5" stroke="$A"/>"#,
        ),
        Icon::Skip => mono(
            "skip",
            r#"<path d="M2.75 8h7.5M7.25 4.75 10.5 8l-3.25 3.25M13.25 3.5v9" stroke="$A"/>"#,
        ),
        Icon::Stop => color(
            "stop",
            RED,
            RED,
            r#"<rect x="3.25" y="3.25" width="9.5" height="9.5" rx="2.25" fill="$A"/>"#,
        ),
        // ----- status -----------------------------------------------------------
        Icon::Error => color(
            "error",
            RED,
            RED,
            r##"<mask id="m"><rect width="16" height="16" fill="#fff"/><path d="M5.9 5.9l4.2 4.2M10.1 5.9l-4.2 4.2" stroke="#000"/></mask><circle cx="8" cy="8" r="6.5" fill="$A" mask="url(#m)"/>"##,
        ),
        Icon::Warning => color(
            "warning",
            AMBER,
            AMBER,
            r##"<mask id="m"><rect width="16" height="16" fill="#fff"/><path d="M8 6v3.25" stroke="#000"/><circle cx="8" cy="11.6" r=".95" fill="#000"/></mask><path d="M6.84 2.55a1.33 1.33 0 0 1 2.32 0l5.6 9.8a1.33 1.33 0 0 1-1.16 2H2.4a1.33 1.33 0 0 1-1.16-2z" fill="$A" mask="url(#m)"/>"##,
        ),
        Icon::Info => color(
            "info",
            BLUE,
            BLUE,
            r##"<mask id="m"><rect width="16" height="16" fill="#fff"/><path d="M8 7.25v4" stroke="#000"/><circle cx="8" cy="4.9" r=".95" fill="#000"/></mask><circle cx="8" cy="8" r="6.5" fill="$A" mask="url(#m)"/>"##,
        ),
        Icon::Success => color(
            "success",
            GREEN,
            GREEN,
            r##"<mask id="m"><rect width="16" height="16" fill="#fff"/><path d="M5.1 8.2l2 2 3.8-4.1" stroke="#000"/></mask><circle cx="8" cy="8" r="6.5" fill="$A" mask="url(#m)"/>"##,
        ),
        Icon::Lock => mono(
            "lock",
            r#"<rect x="3" y="7" width="10" height="7.25" rx="1.75" stroke="$A" fill="$A" fill-opacity=".2"/><path d="M5.25 7V5.25a2.75 2.75 0 0 1 5.5 0V7" stroke="$A"/><path d="M8 10v1.5" stroke="$A"/>"#,
        ),
        Icon::Command => mono(
            "command",
            r#"<path d="M4.25 4.5 7.75 8l-3.5 3.5M9 11.75h3.5" stroke="$A"/>"#,
        ),
        // ----- generic ui -------------------------------------------------------
        Icon::Refresh => mono(
            "refresh",
            r#"<path d="M13.25 8a5.25 5.25 0 1 1-1.54-3.71" stroke="$A"/><path d="M12.25 1.75v3h-3" stroke="$A"/>"#,
        ),
        Icon::Filter => mono(
            "filter",
            r#"<path d="M2.25 2.75h11.5l-4.5 5.5v4.5l-2.5 1.5v-6z" stroke="$A" fill="$A" fill-opacity=".15"/>"#,
        ),
        Icon::Edit => mono(
            "edit",
            r#"<path d="M10.5 2.75a1.77 1.77 0 0 1 2.5 2.5L5.5 12.75 2.25 13.75l1-3.25z" stroke="$A" fill="$A" fill-opacity=".15"/><path d="M9.25 4l2.75 2.75" stroke="$A"/>"#,
        ),
        Icon::Trash => mono(
            "trash",
            r#"<path d="M2.25 4.25h11.5M6.25 4.25V2.75h3.5v1.5" stroke="$A"/><path d="M3.75 4.25l.7 8.6a1.25 1.25 0 0 0 1.25 1.15h4.6a1.25 1.25 0 0 0 1.25-1.15l.7-8.6" stroke="$A" fill="$A" fill-opacity=".15"/><path d="M6.6 7v4M9.4 7v4" stroke="$A"/>"#,
        ),
        Icon::Copy => mono(
            "copy",
            r#"<rect x="5.25" y="5.25" width="8.5" height="8.5" rx="1.5" stroke="$A" fill="$A" fill-opacity=".15"/><path d="M10.75 5V3.75a1.5 1.5 0 0 0-1.5-1.5h-5.5a1.5 1.5 0 0 0-1.5 1.5v5.5a1.5 1.5 0 0 0 1.5 1.5H5" stroke="$A"/>"#,
        ),
        Icon::Log => mono(
            "log",
            r#"<circle cx="2.9" cy="4" r="1" fill="$A"/><circle cx="2.9" cy="8" r="1" fill="$A"/><circle cx="2.9" cy="12" r="1" fill="$A"/><path d="M6 4h7.75M6 8h7.75M6 12h5" stroke="$A"/>"#,
        ),
        Icon::Close => mono(
            "close",
            r#"<path d="M4.25 4.25l7.5 7.5M11.75 4.25l-7.5 7.5" stroke="$A"/>"#,
        ),
        Icon::ChevronDown => mono(
            "chevron-down",
            r#"<path d="M3.5 6.25 8 10.75l4.5-4.5" stroke="$A"/>"#,
        ),
        Icon::Plus => mono("plus", r#"<path d="M8 3v10M3 8h10" stroke="$A"/>"#),
        Icon::Sun => mono(
            "sun",
            r#"<circle cx="8" cy="8" r="2.75" stroke="$A" fill="$A" fill-opacity=".25"/><path d="M12.60 8.00L14.25 8.00M11.25 11.25L12.42 12.42M8.00 12.60L8.00 14.25M4.75 11.25L3.58 12.42M3.40 8.00L1.75 8.00M4.75 4.75L3.58 3.58M8.00 3.40L8.00 1.75M11.25 4.75L12.42 3.58" stroke="$A"/>"#,
        ),
        Icon::Moon => mono(
            "moon",
            r#"<path d="M13.5 9.75A5.75 5.75 0 1 1 6.25 2.5a4.6 4.6 0 0 0 7.25 7.25z" stroke="$A" fill="$A" fill-opacity=".2"/>"#,
        ),
        Icon::Quit => mono(
            "quit",
            r#"<path d="M6.25 2.25h-2.5a1.5 1.5 0 0 0-1.5 1.5v8.5a1.5 1.5 0 0 0 1.5 1.5h2.5" stroke="$A"/><path d="M6.5 8h7.25M10.75 5l3 3-3 3" stroke="$A"/>"#,
        ),
    }
}
