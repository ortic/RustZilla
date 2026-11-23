//! Embeds the icon and version information in rustzilla.exe
//! (`rustzilla.rc`), as DbCraft does: Explorer, shortcuts and the taskbar
//! take the icon from the exe.

fn main() {
    println!("cargo:rerun-if-changed=rustzilla.rc");
    println!("cargo:rerun-if-changed=../../assets/icon/rustzilla.ico");
    let macros = [
        concat!("RUSTZILLA_VERSION=\"", env!("CARGO_PKG_VERSION"), "\""),
        concat!("RUSTZILLA_VERSION_MAJOR=", env!("CARGO_PKG_VERSION_MAJOR")),
        concat!("RUSTZILLA_VERSION_MINOR=", env!("CARGO_PKG_VERSION_MINOR")),
        concat!("RUSTZILLA_VERSION_PATCH=", env!("CARGO_PKG_VERSION_PATCH")),
    ];
    // Not built for Windows: nothing to do. A cross build without a
    // resource compiler only warns.
    let result = embed_resource::compile("rustzilla.rc", macros);
    if let embed_resource::CompilationResult::NotAttempted(missing) = &result {
        println!("cargo:warning=rustzilla.exe is built without its icon: no {missing}");
    }
    result.manifest_optional().unwrap();
}
