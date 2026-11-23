//! RustZilla – a fast, native SFTP, FTP(S), WebDAV and S3 client.

// Release builds are GUI programs on Windows, without a console window;
// debug builds keep it for development.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod config;
mod format;
mod icons;
mod local;
mod pane;
mod secrets;
mod session;
mod site_manager;
mod theme;
mod transfers;

use std::fs::{self, File};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use config::Paths;
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

fn main() -> anyhow::Result<()> {
    let paths = Paths::detect();
    init_logging(paths.as_ref());
    info!(version = env!("CARGO_PKG_VERSION"), "starting RustZilla");
    let started = Arc::new(AtomicBool::new(false));
    let result = run(eframe::Renderer::Wgpu, paths.clone(), &started).or_else(|e| {
        if started.load(Ordering::SeqCst) {
            return Err(e);
        }
        warn!("wgpu renderer failed ({e}), falling back to OpenGL");
        run(eframe::Renderer::Glow, paths.clone(), &started)
    });
    if let Err(e) = &result {
        report_error(&format!("RustZilla could not open its window: {e}"));
    }
    result.map_err(|e| anyhow::anyhow!("{e}"))
}

fn report_error(text: &str) {
    error!("{text}");
    eprintln!("rustzilla: {text}");
    let _ = rfd::MessageDialog::new()
        .set_level(rfd::MessageLevel::Error)
        .set_title("RustZilla")
        .set_description(text)
        .set_buttons(rfd::MessageButtons::Ok)
        .show();
}

fn run(
    renderer: eframe::Renderer,
    paths: Option<Paths>,
    started: &Arc<AtomicBool>,
) -> eframe::Result {
    let started = started.clone();
    let options = eframe::NativeOptions {
        renderer,
        viewport: egui::ViewportBuilder::default()
            .with_title("RustZilla")
            .with_app_id("rustzilla")
            .with_inner_size([1280.0, 860.0])
            .with_min_inner_size([760.0, 480.0])
            .with_drag_and_drop(true)
            .with_icon(window_icon()),
        persistence_path: paths.as_ref().map(|p| p.data_dir.join("ui.ron")),
        event_loop_builder: x11_on_wslg(),
        ..Default::default()
    };
    eframe::run_native(
        "rustzilla",
        options,
        Box::new(move |cc| {
            started.store(true, Ordering::SeqCst);
            Ok(Box::new(app::App::new(cc, paths)))
        }),
    )
}

/// Under WSLg the window opens through X11 (Xwayland), as in DbCraft: WSLg's
/// compositor crashes when winit's cursor theme grows its shm pool
/// (microsoft/wslg#1386). `RUSTZILLA_WAYLAND=1` keeps Wayland.
#[cfg(target_os = "linux")]
fn x11_on_wslg() -> Option<eframe::EventLoopBuilderHook> {
    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let set = |name: &str| std::env::var_os(name).is_some_and(|v| !v.is_empty());
    if !(kernel.to_ascii_lowercase().contains("microsoft")
        && set("WAYLAND_DISPLAY")
        && set("DISPLAY")
        && !set("RUSTZILLA_WAYLAND"))
    {
        return None;
    }
    info!("WSLg: opening the window through X11 (RUSTZILLA_WAYLAND=1 keeps Wayland)");
    Some(Box::new(|builder| {
        use winit::platform::x11::EventLoopBuilderExtX11;
        builder.with_x11();
    }))
}

#[cfg(not(target_os = "linux"))]
fn x11_on_wslg() -> Option<eframe::EventLoopBuilderHook> {
    None
}

/// The application icon, drawn from its SVG.
pub fn window_icon() -> egui::IconData {
    use resvg::{tiny_skia, usvg};
    const SIZE: u32 = 256;
    let tree = usvg::Tree::from_str(APP_ICON, &usvg::Options::default())
        .expect("the app icon is valid SVG");
    let mut pixmap = tiny_skia::Pixmap::new(SIZE, SIZE).expect("a pixmap");
    let scale = SIZE as f32 / tree.size().width();
    resvg::render(
        &tree,
        tiny_skia::Transform::from_scale(scale, scale),
        &mut pixmap.as_mut(),
    );
    // tiny-skia's pixels are premultiplied.
    let rgba = pixmap
        .pixels()
        .iter()
        .flat_map(|p| {
            let c = p.demultiply();
            [c.red(), c.green(), c.blue(), c.alpha()]
        })
        .collect();
    egui::IconData {
        rgba,
        width: SIZE,
        height: SIZE,
    }
}

pub const APP_ICON: &str = include_str!("../../../assets/icon/rustzilla.svg");

/// Logs to stderr and to `<data dir>/logs/rustzilla.log`. `RUST_LOG`
/// overrides the filter.
fn init_logging(paths: Option<&Paths>) {
    let filter = || {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::new("info,wgpu=warn,naga=warn,eframe=warn,russh=warn,russh_sftp=warn")
        })
    };
    let file = paths.and_then(|p| {
        let dir = p.log_dir();
        fs::create_dir_all(&dir).ok()?;
        File::create(dir.join("rustzilla.log")).ok()
    });
    let file_layer = file.map(|f| {
        fmt::layer()
            .with_ansi(false)
            .with_writer(Mutex::new(f))
            .with_filter(filter())
    });
    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_writer(std::io::stderr)
                .with_filter(filter()),
        )
        .with(file_layer)
        .init();
}

/// Writes the icons of the packages from `assets/icon/rustzilla.svg`:
/// `RUSTZILLA_WRITE_ICONS=1 cargo test -p rustzilla-app write_icons`.
#[cfg(test)]
mod icon_files {
    use resvg::{tiny_skia, usvg};

    fn png(size: u32) -> Vec<u8> {
        let tree = usvg::Tree::from_str(super::APP_ICON, &usvg::Options::default()).unwrap();
        let mut pixmap = tiny_skia::Pixmap::new(size, size).unwrap();
        let scale = size as f32 / tree.size().width();
        resvg::render(
            &tree,
            tiny_skia::Transform::from_scale(scale, scale),
            &mut pixmap.as_mut(),
        );
        pixmap.encode_png().unwrap()
    }

    /// An .ico of PNG images (Windows Vista and later read them).
    fn ico(sizes: &[u32]) -> Vec<u8> {
        let images: Vec<Vec<u8>> = sizes.iter().map(|&s| png(s)).collect();
        let mut out = vec![0, 0, 1, 0];
        out.extend((sizes.len() as u16).to_le_bytes());
        let mut offset = 6 + 16 * sizes.len() as u32;
        for (size, image) in sizes.iter().zip(&images) {
            let dim = if *size >= 256 { 0 } else { *size as u8 };
            out.extend([dim, dim, 0, 0]);
            out.extend(1u16.to_le_bytes());
            out.extend(32u16.to_le_bytes());
            out.extend((image.len() as u32).to_le_bytes());
            out.extend(offset.to_le_bytes());
            offset += image.len() as u32;
        }
        for image in images {
            out.extend(image);
        }
        out
    }

    /// An .icns of PNG images.
    fn icns() -> Vec<u8> {
        let mut body = Vec::new();
        for (kind, size) in [
            (b"icp4", 16),
            (b"icp5", 32),
            (b"ic07", 128),
            (b"ic08", 256),
            (b"ic09", 512),
            (b"ic10", 1024),
        ] {
            let image = png(size);
            body.extend(kind);
            body.extend(((image.len() + 8) as u32).to_be_bytes());
            body.extend(image);
        }
        let mut out = b"icns".to_vec();
        out.extend(((body.len() + 8) as u32).to_be_bytes());
        out.extend(body);
        out
    }

    #[test]
    fn write_icons() {
        // Always: the icon renders.
        assert!(png(32).starts_with(b"\x89PNG"));
        if std::env::var_os("RUSTZILLA_WRITE_ICONS").is_none() {
            return;
        }
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../assets/icon");
        for size in [16, 24, 32, 48, 64, 128, 256, 512, 1024] {
            std::fs::write(dir.join(format!("rustzilla-{size}.png")), png(size)).unwrap();
        }
        std::fs::write(dir.join("rustzilla.ico"), ico(&[16, 24, 32, 48, 64, 256])).unwrap();
        std::fs::write(dir.join("rustzilla.icns"), icns()).unwrap();
    }
}
