# Changelog

All notable changes to RustZilla are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-11-23

### Added

- **Tabs**: a connection each, with its own sides and transfers; the queue
  shows every tab's (Ctrl+T, Ctrl+W, Ctrl+Tab).
- **View/Edit**: a remote file opens in the system's app for it and is
  uploaded again, when you say so, after it's saved.
- **Import sites** from FileZilla's Site Manager (folders, passwords stored
  in base64, key files, remote directories) and from `~/.ssh/config`
  (with `ProxyJump` as the jump host).
- **Bookmarks** of a local and a remote directory, for every connection or
  one site.
- **Directory comparison** colors what's only on one side, newer, or of
  another size; **synchronized browsing** follows into directories on the
  other side.
- **Find files**: searches a directory tree by name (`*.log`, a part of the
  name) on this computer or the server, and transfers what it finds.
- **Keyboard navigation** in the file lists: arrows, Page Up/Down,
  Home/End, Shift to extend the selection, Enter, and typing a name.
- **The queue is kept**: what's unfinished at exit is queued again at the
  next start and runs when you connect to its server. Failed transfers can
  all be retried at once.
- **Speed limits** for downloads and uploads.
- **Two-factor SSH logins**: keyboard-interactive (PAM, one-time codes).
  RustZilla answers the "Password:" prompt with the password and asks for
  the rest, e.g. a verification code, also after a key as the first factor.
- **Jump hosts** (ProxyJump, `ssh -J`): an SFTP site can connect through
  `[user@]host[:port]`, logging in there with the same credentials; its
  host key is checked like the server's.
- **OpenSSH certificates**: a key file's `<key file>-cert.pub` logs in when
  the server takes it (the key alone otherwise), and so do certificates in
  the SSH agent.
- **WebDAV with HTTP Digest authentication** (RFC 7616: MD5, SHA-256 and
  their `-sess` variants, `qop=auth`), switched to when the server asks for
  it, with fresh nonces taken up as they run out.
- **WebDAV presets** in the Site Manager: Nextcloud and ownCloud fill in
  HTTPS and their WebDAV folder (Nextcloud's follows the user name).
- Quickconnect takes a pasted WebDAV URL, such as the one Nextcloud shows
  (`https://cloud.example.com/remote.php/dav/files/alice/`).
- **S3 multipart uploads** for files over 16 MiB, up to 5 TiB, that
  **resume** after a cancel or a dropped connection from the parts already
  up; failed ones are aborted.
- **S3 session tokens** (temporary credentials), and the logon type
  **AWS profile**: keys, token and region from `~/.aws/credentials` and
  `~/.aws/config`, or from the `AWS_*` environment variables with the
  profile `env`.

### Changed

- WebDAV over plain HTTP sends the password with Basic only when the server
  asks for Basic.
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

[Unreleased]: https://github.com/ortic/RustZilla/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ortic/RustZilla/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ortic/RustZilla/releases/tag/v0.1.0
