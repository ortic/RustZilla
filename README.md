# RustZilla

[![CI](https://github.com/ortic/RustZilla/actions/workflows/ci.yml/badge.svg)](https://github.com/ortic/RustZilla/actions/workflows/ci.yml)

A fast, native file transfer client in the spirit of FileZilla, written in
Rust on the same stack as [DbCraft](https://github.com/ortic/dbcraft):
eframe/egui 0.36 for the UI, russh (pure Rust, on ring) for SSH, rustls for
TLS, and DbCraft's own FIDO code for security keys such as YubiKeys.

Protocols: **SFTP**, **FTP**, **FTPS** (explicit and implicit TLS),
**WebDAV** (HTTP and HTTPS) and **Amazon S3** and compatible object stores
(MinIO, Cloudflare R2, Wasabi, Backblaze B2, DigitalOcean Spaces…).

![RustZilla, connected, with the transfer queue](docs/main.png)

## Features

- **SFTP** over SSH: browse, upload, download, create directories, rename,
  delete (recursively), change permissions.
- **FTP and FTPS**: TLS if the server offers it (as FileZilla's default),
  required explicit or implicit TLS, or plain FTP with a warning. MLSD/MLST
  or LIST, resume (REST/APPE), file times (MDTM/MFMT), SITE CHMOD, passive
  mode that works behind NAT, a reconnect when the server dropped an idle
  connection. Certificates that don't verify (self-signed, unknown issuer,
  expired) are shown with subject, issuer, validity and SHA-256 fingerprint
  to trust, as SSH host keys.
- **WebDAV** (Nextcloud, ownCloud, Apache, IIS, NAS boxes): PROPFIND
  listings, resumed downloads (ranges), uploads that keep file times on
  Nextcloud/ownCloud, MKCOL, MOVE, DELETE.
- **S3**: buckets at the root, folders as prefixes, Signature V4 signing,
  resumed downloads, uploads up to 5 GiB, copy-and-delete renames, the
  bucket's region found by itself.
- **FileZilla's layout**: Quickconnect bar, message log, local and remote
  panes side by side, transfer queue with queued, failed and successful
  transfers, status bar.
- **Transfers**: whole directories, several in parallel (each on its own
  SFTP channel over the one SSH login), progress, speed and time left,
  cancel and retry, resume. When the target exists: ask, overwrite,
  overwrite if the source is newer, resume, or skip. File times are kept.
- **Drag and drop** between the panes, and files from the desktop onto the
  window to upload them.
- **Site Manager**: saved servers in `sites.toml`; passwords and passphrases
  in the OS keychain, never in files.
- **Logins**: password (and keyboard-interactive), key files (OpenSSH, PEM,
  PuTTY `.ppk`), the SSH agent (ssh-agent, Pageant, Windows' OpenSSH agent).
- **Security keys** (YubiKey and other FIDO2/U2F keys): the key files of
  `ecdsa-sk` and `ed25519-sk` keys (`ssh-keygen -t ed25519-sk`) sign with the
  key, as in DbCraft:
  - Linux (hidraw) and macOS (hidapi): CTAP2 over USB HID, PIN protocols one
    and two, U2F for older keys. When the key needs its PIN
    (`-O verify-required`), RustZilla asks for it; then it asks you to touch
    the key.
  - Windows: the WebAuthn API, with Windows' own dialog for touch and PIN.
  - With several keys plugged in, the one that holds the credential signs.
- **Polished UI**: hand-drawn SVG icons in DbCraft's style (file types,
  folders, transfer directions, security keys), DbCraft's dark and light
  themes (following the system, or chosen), a toolbar, empty states and
  clear dialogs.
- **Host keys** are checked against `~/.ssh/known_hosts` and RustZilla's own
  file; an unknown key is shown with its fingerprint to trust, a changed key
  stops the connect.

![Touching a security key to log in](docs/security-key.png)

## Download

Packages for Linux (`.deb`, AppImage), Windows (`.msi`, setup `.exe`) and
macOS (`.dmg`, Apple Silicon and Intel) are on the
[releases page](https://github.com/ortic/RustZilla/releases).

## Building

```sh
cargo run -p rustzilla-app            # debug
cargo run --profile fast -p rustzilla-app
cargo build --release -p rustzilla-app
```

On Linux the security key is read from `/dev/hidraw*`: your user needs
access, which the udev rules of `libfido2` (package `libfido2-1` or
`fido2-tools`) or `yubikey-manager` grant.

## Using it

- **Quickconnect**: `sftp://`, `ftp://` (TLS if available), `ftpes://`
  (explicit TLS), `ftps://` (implicit TLS), `davs://` / `dav://` (WebDAV, the
  path is the WebDAV folder), `s3://endpoint` (access key as the user, secret
  key as the password), each as `scheme://user@host:port/path`. Without a
  scheme, port 21 is FTP, 990 FTPS, anything else SFTP. For SFTP without a
  password the SSH agent's keys are used.
- **Site Manager** (File → Site Manager): for key files and security keys
  choose the logon type *Key file / security key* and pick the key file
  (e.g. `~/.ssh/id_ed25519_sk`). The passphrase field is for encrypted key
  files; a security key's PIN is asked for when it's needed.
- Keys: F5 refresh, Backspace parent directory, Delete, F2 rename, Ctrl+A
  select all, on the pane last clicked.

Files: sites in the config directory (`~/.config/rustzilla/sites.toml` on
Linux), trusted host keys and logs in the data directory
(`~/.local/share/rustzilla/`). Help → About shows where.

## Tests

```sh
cargo test --workspace
```

runs everything, including a round trip of every protocol against servers
in the process (`rustzilla-remote`'s `test-server` feature: russh-sftp,
libunftp with a self-signed certificate for FTPS, dav-server, s3s-fs), the
transfer queue, the login with a security key emulated in software, and the UI
scenes headless. With `RUSTZILLA_SCREENSHOTS=<dir>` the UI scenes are
rendered as PNGs there (the ones in `docs/` are made that way).

Against a real OpenSSH server:

```sh
docker compose up -d
RUSTZILLA_TEST_SFTP=1 cargo test -p rustzilla-remote --test openssh
```

## Layout

- `crates/rustzilla-remote`: the protocols behind one blocking interface
  (`remote.rs`: a `Server` opens `Session`s): SSH login (`ssh.rs`, from
  DbCraft's tunnels), security keys (`fido/`, `ssh/security_key.rs`, from
  DbCraft), SFTP (`sftp.rs`), FTP/FTPS (`ftp.rs`, `tls.rs`), WebDAV
  (`webdav.rs`), S3 (`s3.rs`) over ureq (`http.rs`).
- `crates/rustzilla-app`: the egui app: panes (`pane.rs`), the session
  worker (`session.rs`), the transfer queue (`transfers.rs`), the Site
  Manager, dialogs.

## License

MIT or Apache-2.0, at your option.
