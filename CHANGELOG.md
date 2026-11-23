# Changelog

All notable changes to RustZilla are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **S3 multipart uploads** for files over 16 MiB, up to 5 TiB, that
  **resume** after a cancel or a dropped connection from the parts already
  up; failed ones are aborted.
- **S3 session tokens** (temporary credentials), and the logon type
  **AWS profile**: keys, token and region from `~/.aws/credentials` and
  `~/.aws/config`, or from the `AWS_*` environment variables with the
  profile `env`.

### Changed

- S3 on AWS uses **virtual-hosted addressing** (`bucket.s3.amazonaws.com`)
  for DNS-compatible bucket names; other stores stay path-style.

## [0.1.0] - 2026-11-23

The first release: a FileZilla-like file transfer client on DbCraft's stack.

### Added

- **SFTP** over SSH, with logins by password (and keyboard-interactive),
  key file (OpenSSH, PEM, PuTTY), the SSH agent (ssh-agent, Pageant,
  Windows' OpenSSH agent) and **FIDO security keys** such as YubiKeys
  (`ecdsa-sk`, `ed25519-sk` key files): CTAP2 and U2F over USB HID on Linux
  and macOS with PIN protocols one and two, WebAuthn on Windows. RustZilla
  asks for the key's PIN when it needs one and for the touch.
- **FTP and FTPS**: TLS if the server offers it, explicit or implicit TLS
  required, or plain FTP with a warning; MLSD/MLST or LIST, resume, file
  times, SITE CHMOD, NAT-proof passive mode, reconnects after idle timeouts.
- **WebDAV** over HTTP(S) (Nextcloud, ownCloud, Apache, IIS, NAS boxes).
- **Amazon S3** and compatible stores (MinIO, Cloudflare R2, Wasabi,
  Backblaze B2, DigitalOcean Spaces), with Signature V4 and regions found
  by themselves.
- **Trust on first use**: unknown SSH host keys and TLS certificates that
  don't verify are shown with their fingerprints to trust; a changed host
  key stops the connect.
- **FileZilla's layout**: Quickconnect (`sftp://`, `ftp://`, `ftpes://`,
  `ftps://`, `davs://`, `s3://`), message log, local and remote panes,
  transfer queue and status bar; a menu bar whose menus switch on hover.
- **Transfers** of files and folders, several at once, with progress,
  speed and time left, cancel, retry and resume, and a choice when the
  target exists (ask, overwrite, overwrite if newer, resume, skip).
- **Drag and drop** between the panes and from the desktop.
- **Site Manager** with protocols, encryption, logon types and start
  folders; passwords in the system's keychain.
- **Polished UI**: hand-drawn SVG icons (file types, folders, transfers,
  security keys), dark and light themes, empty states, clear dialogs.

[Unreleased]: https://github.com/ortic/RustZilla/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ortic/RustZilla/releases/tag/v0.1.0
