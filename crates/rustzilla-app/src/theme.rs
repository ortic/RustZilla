//! Visual design: DbCraft's palettes for dark and light mode, spacing and
//! rounding. Both themes are installed; egui follows the system's unless
//! the user picks one.

use egui::style::{Selection, WidgetVisuals};
use egui::{Color32, CornerRadius, Frame, Margin, Shadow, Stroke, Style, Theme, Vec2};

pub const ACCENT: Color32 = Color32::from_rgb(0x3b, 0x82, 0xf6);
pub const DANGER: Color32 = Color32::from_rgb(0xe5, 0x48, 0x4d);
pub const SUCCESS: Color32 = Color32::from_rgb(0x36, 0xa8, 0x5f);
pub const UPLOAD: Color32 = Color32::from_rgb(0x3d, 0x8f, 0xe0);
pub const DOWNLOAD: Color32 = Color32::from_rgb(0x36, 0xa8, 0x5f);

struct Palette {
    panel: Color32,
    surface: Color32,
    raised: Color32,
    field: Color32,
    border: Color32,
    text: Color32,
    text_weak: Color32,
    hover: Color32,
    active: Color32,
    selection: Color32,
    stripe: Color32,
    error: Color32,
    warn: Color32,
    link: Color32,
}

const DARK: Palette = Palette {
    panel: Color32::from_rgb(0x1e, 0x1f, 0x23),
    surface: Color32::from_rgb(0x1a, 0x1b, 0x1e),
    raised: Color32::from_rgb(0x27, 0x29, 0x2e),
    field: Color32::from_rgb(0x16, 0x17, 0x1a),
    border: Color32::from_rgb(0x32, 0x35, 0x3b),
    text: Color32::from_rgb(0xdc, 0xde, 0xe3),
    text_weak: Color32::from_rgb(0x8b, 0x90, 0x9a),
    hover: Color32::from_rgb(0x2c, 0x2f, 0x35),
    active: Color32::from_rgb(0x35, 0x39, 0x41),
    selection: Color32::from_rgba_premultiplied(0x23, 0x4e, 0x94, 0xb0),
    stripe: Color32::from_rgb(0x1f, 0x20, 0x24),
    error: Color32::from_rgb(0xf2, 0x6d, 0x6d),
    warn: Color32::from_rgb(0xe8, 0xb3, 0x4a),
    link: Color32::from_rgb(0x6c, 0xa6, 0xff),
};

const LIGHT: Palette = Palette {
    panel: Color32::from_rgb(0xf4, 0xf5, 0xf7),
    surface: Color32::from_rgb(0xff, 0xff, 0xff),
    raised: Color32::from_rgb(0xff, 0xff, 0xff),
    field: Color32::from_rgb(0xec, 0xee, 0xf2),
    border: Color32::from_rgb(0xd9, 0xdc, 0xe1),
    text: Color32::from_rgb(0x1f, 0x23, 0x28),
    text_weak: Color32::from_rgb(0x6a, 0x71, 0x7c),
    hover: Color32::from_rgb(0xe6, 0xe8, 0xec),
    active: Color32::from_rgb(0xd8, 0xdc, 0xe3),
    selection: Color32::from_rgba_unmultiplied_const(0xa6, 0xc8, 0xff, 0xc0),
    stripe: Color32::from_rgb(0xf7, 0xf8, 0xfa),
    error: Color32::from_rgb(0xc8, 0x2b, 0x2b),
    warn: Color32::from_rgb(0xa8, 0x62, 0x00),
    link: Color32::from_rgb(0x1d, 0x5f, 0xd6),
};

/// Installs the dark and the light style.
pub fn install(ctx: &egui::Context) {
    for (theme, palette) in [(Theme::Dark, &DARK), (Theme::Light, &LIGHT)] {
        ctx.style_mut_of(theme, |style| apply(style, palette));
    }
}

fn apply(style: &mut Style, p: &Palette) {
    use egui::{FontId, TextStyle};
    for (text_style, font) in [
        (TextStyle::Small, FontId::proportional(10.0)),
        (TextStyle::Body, FontId::proportional(13.5)),
        (TextStyle::Button, FontId::proportional(13.5)),
        (TextStyle::Heading, FontId::proportional(18.0)),
        (TextStyle::Monospace, FontId::monospace(12.5)),
    ] {
        style.text_styles.insert(text_style, font);
    }
    let radius = CornerRadius::same;
    let spacing = &mut style.spacing;
    spacing.item_spacing = Vec2::new(7.0, 4.0);
    spacing.button_padding = Vec2::new(8.0, 3.0);
    spacing.interact_size = Vec2::new(36.0, 22.0);
    spacing.menu_margin = Margin::same(5);
    spacing.window_margin = Margin::same(14);
    spacing.scroll = egui::style::ScrollStyle::floating();
    spacing.scroll.bar_width = 8.0;

    let v = &mut style.visuals;
    v.panel_fill = p.panel;
    v.window_fill = p.raised;
    v.extreme_bg_color = p.surface;
    v.text_edit_bg_color = Some(p.field);
    v.code_bg_color = p.surface;
    v.faint_bg_color = p.stripe;
    v.window_stroke = Stroke::new(1.0, p.border);
    v.window_corner_radius = radius(10);
    v.menu_corner_radius = radius(8);
    let shadow_alpha = if v.dark_mode { 110 } else { 40 };
    v.window_shadow = Shadow {
        offset: [0, 8],
        blur: 28,
        spread: 0,
        color: Color32::from_black_alpha(shadow_alpha),
    };
    v.popup_shadow = Shadow {
        offset: [0, 4],
        blur: 16,
        spread: 0,
        color: Color32::from_black_alpha(shadow_alpha),
    };
    v.selection = Selection {
        bg_fill: p.selection,
        stroke: Stroke::new(1.0, p.text),
    };
    v.hyperlink_color = p.link;
    v.error_fg_color = p.error;
    v.warn_fg_color = p.warn;
    v.striped = true;
    v.text_cursor.stroke = Stroke::new(2.0, ACCENT);
    v.weak_text_color = Some(p.text_weak);

    let widget = |bg: Color32, stroke: Color32, fg: Color32| WidgetVisuals {
        bg_fill: bg,
        weak_bg_fill: bg,
        bg_stroke: Stroke::new(1.0, stroke),
        corner_radius: radius(5),
        fg_stroke: Stroke::new(1.0, fg),
        expansion: 0.0,
    };
    let w = &mut v.widgets;
    w.noninteractive = widget(p.panel, p.border, p.text);
    w.inactive = widget(p.hover, Color32::TRANSPARENT, p.text);
    // No stroke rather than a transparent one: icon buttons only draw it on
    // hover and would grow by it.
    w.inactive.bg_stroke = Stroke::NONE;
    w.hovered = widget(p.active, p.border, p.text);
    w.active = widget(p.active, ACCENT, p.text);
    w.open = widget(p.active, p.border, p.text);
}

/// The toolbar strip below the menu.
pub fn toolbar_frame(style: &Style) -> Frame {
    Frame::new()
        .fill(style.visuals.panel_fill)
        .inner_margin(Margin::symmetric(8, 4))
}

/// The status bar.
pub fn status_frame(style: &Style) -> Frame {
    Frame::new()
        .fill(style.visuals.window_fill)
        .inner_margin(Margin::symmetric(10, 3))
        .stroke(Stroke::new(
            1.0,
            style.visuals.widgets.noninteractive.bg_stroke.color,
        ))
}

/// A card: a raised, rounded frame, e.g. around a fingerprint.
pub fn card(style: &Style) -> Frame {
    Frame::new()
        .fill(style.visuals.extreme_bg_color)
        .stroke(Stroke::new(
            1.0,
            style.visuals.widgets.noninteractive.bg_stroke.color,
        ))
        .corner_radius(8)
        .inner_margin(Margin::same(10))
}

/// The main action of a dialog: filled with the accent.
pub fn primary_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text.to_owned()).color(Color32::WHITE))
        .fill(ACCENT)
        .min_size(Vec2::new(84.0, 26.0))
}

/// A destructive action: filled red.
pub fn danger_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text.to_owned()).color(Color32::WHITE))
        .fill(DANGER)
        .min_size(Vec2::new(84.0, 26.0))
}

pub fn secondary_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(text.to_owned()).min_size(Vec2::new(84.0, 26.0))
}
