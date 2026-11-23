# RustZilla

A FileZilla-like file transfer client on DbCraft's stack (eframe/egui,
russh, rustls on ring). `cargo test --workspace` runs every protocol against
servers in the process; keep `cargo fmt --all --check` and
`cargo clippy --workspace --all-targets -- -D warnings` clean.

## Releases

A release is a commit and a tag on master. `.github/workflows/release.yml`
builds the packages for the tag and leaves a **draft** release whose body is
only GitHub's generated "Full Changelog" link. The release isn't done until
its body says what changed. Never publish the generated body alone.

1. Commit `Release X.Y.Z` on master:
   - `version` in the workspace `Cargo.toml`, then `cargo update -w` for
     `Cargo.lock`;
   - in `CHANGELOG.md`, `## [X.Y.Z] - YYYY-MM-DD` under `## [Unreleased]`,
     and the links at the bottom;
   - `<release version="X.Y.Z" date="YYYY-MM-DD"/>` first among the
     releases in `assets/linux/com.ortic.rustzilla.metainfo.xml`.
2. Push master, then `git tag -a vX.Y.Z -m "RustZilla X.Y.Z"` and push the
   tag.
3. While the workflow runs (`gh run watch <id>`), write the release notes
   from the version's CHANGELOG section: `## Highlights`, then `## Added`,
   `## Changed`, `## Fixed` with a bold lead each, then
   `**Full Changelog**: https://github.com/ortic/RustZilla/compare/vPREV...vX.Y.Z`.
4. Once every job succeeded: `gh release edit vX.Y.Z --notes-file notes.md
   --draft=false --latest`, and check with `gh release view vX.Y.Z` that the
   body is the notes and the packages are attached.

Icons: `assets/icon/rustzilla.svg` is the source;
`RUSTZILLA_WRITE_ICONS=1 cargo test -p rustzilla-app write_icons` writes the
PNG, ICO and ICNS files from it.
