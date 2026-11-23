//! An SFTP server in the process, for tests: russh's SSH server with
//! russh-sftp's server side, serving a directory. Logs in `test` with the
//! password `test`. Remote paths are absolute under the directory.

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use russh::keys::PrivateKey;
use russh::server::{Auth, Msg, Session};
use russh::{Channel, ChannelId};
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
};
use tokio::runtime::Runtime;

use crate::ssh::{Auth as LoginAuth, HostKey, SshParams};

const HOST_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACClEhoSIagwuB36qjpnnthtjKcuq3+bXd9hkstg8x23vQAAAIi5usgHubrI
BwAAAAtzc2gtZWQyNTUxOQAAACClEhoSIagwuB36qjpnnthtjKcuq3+bXd9hkstg8x23vQ
AAAEBNRdzTUJqyUfuM1ubN9qtwRxGXCiHQmKchWlpyrvnjLKUSGhIhqDC4HfqqOmee2G2M
py6rf5td32GSy2DzHbe9AAAABWhvc3Qx
-----END OPENSSH PRIVATE KEY-----
";

pub struct TestServer {
    pub port: u16,
    pub root: PathBuf,
    known_hosts: PathBuf,
    _runtime: Runtime,
}

impl TestServer {
    /// Serves `root`; its host key is trusted in `known_hosts`.
    pub fn start(root: &Path, known_hosts: &Path) -> Self {
        fs::create_dir_all(root).expect("creating the server's directory");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a runtime");
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .expect("a port");
        let port = listener.local_addr().expect("its address").port();
        let key = PrivateKey::from_openssh(HOST_KEY).expect("the host key");
        HostKey::new("127.0.0.1", port, key.public_key(), known_hosts)
            .trust()
            .expect("trusting the host key");
        let config = Arc::new(russh::server::Config {
            keys: vec![key],
            auth_rejection_time: Duration::from_millis(10),
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..Default::default()
        });
        let served = root.to_owned();
        runtime.spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let config = config.clone();
                let handler = SshHandler {
                    root: served.clone(),
                    channels: HashMap::new(),
                };
                tokio::spawn(async move {
                    if let Ok(running) = russh::server::run_stream(config, stream, handler).await {
                        let _ = running.await;
                    }
                });
            }
        });
        Self {
            port,
            root: root.to_owned(),
            known_hosts: known_hosts.to_owned(),
            _runtime: runtime,
        }
    }

    pub fn params(&self) -> SshParams {
        SshParams {
            host: "127.0.0.1".into(),
            port: self.port,
            username: "test".into(),
            auth: LoginAuth::Password("test".into()),
            pin: None,
            known_hosts: self.known_hosts.clone(),
            on_touch: None,
        }
    }
}

/// Writes the key file of an `ecdsa-sk` security key, as `ssh-keygen -t
/// ecdsa-sk` does (with a made-up credential).
pub fn write_security_key_file(path: &Path) {
    use russh::keys::ssh_key::private::{KeypairData, SkEcdsaSha2NistP256};
    use russh::keys::ssh_key::public::SkEcdsaSha2NistP256 as Public;
    // A point on P-256 (the generator), uncompressed.
    let point = [
        "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    ]
    .concat();
    let bytes: Vec<u8> = (0..point.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&point[i..i + 2], 16).expect("hex"))
        .collect();
    let encoded =
        russh::keys::ssh_key::sec1::EncodedPoint::<russh::keys::ssh_key::sec1::consts::U32>::from_bytes(
            &bytes,
        )
        .expect("a point");
    let public = Public::new(encoded, "ssh:");
    let sk = SkEcdsaSha2NistP256::new(public, 0x01, vec![1; 64]).expect("a key");
    let private = PrivateKey::new(KeypairData::SkEcdsaSha2NistP256(sk), "yubikey").expect("a key");
    fs::write(
        path,
        private
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("encoding the key"),
    )
    .expect("writing the key file");
}

struct SshHandler {
    root: PathBuf,
    channels: HashMap<ChannelId, Channel<Msg>>,
}

impl russh::server::Handler for SshHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(if user == "test" && password == "test" {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.close(channel)?;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        match self.channels.remove(&channel_id) {
            Some(channel) if name == "sftp" => {
                session.channel_success(channel_id)?;
                let sftp = SftpHandler {
                    root: self.root.clone(),
                    handles: HashMap::new(),
                    next: 0,
                };
                tokio::spawn(russh_sftp::server::run(channel.into_stream(), sftp));
            }
            _ => session.channel_failure(channel_id)?,
        }
        Ok(())
    }
}

enum Open {
    File(fs::File),
    Dir(Option<Vec<File>>),
}

struct SftpHandler {
    root: PathBuf,
    handles: HashMap<String, Open>,
    next: u64,
}

fn ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".into(),
        language_tag: "en-US".into(),
    }
}

fn code(e: std::io::Error) -> StatusCode {
    match e.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        std::io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

impl SftpHandler {
    /// The local path of an absolute remote one.
    fn local(&self, path: &str) -> PathBuf {
        let mut out = self.root.clone();
        for part in path.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    if out != self.root {
                        out.pop();
                    }
                }
                part => out.push(part),
            }
        }
        out
    }

    fn handle(&mut self, open: Open) -> String {
        self.next += 1;
        let handle = format!("h{}", self.next);
        self.handles.insert(handle.clone(), open);
        handle
    }
}

impl russh_sftp::server::Handler for SftpHandler {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn open(
        &mut self,
        id: u32,
        filename: russh_sftp::protocol::SftpString,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let path = self.local(&filename.to_string());
        let file = fs::OpenOptions::new()
            .read(pflags.contains(OpenFlags::READ))
            .write(pflags.contains(OpenFlags::WRITE))
            .create(pflags.contains(OpenFlags::CREATE))
            .truncate(pflags.contains(OpenFlags::TRUNCATE))
            .open(path)
            .map_err(code)?;
        let handle = self.handle(Open::File(file));
        Ok(Handle {
            id,
            handle: handle.into(),
        })
    }

    async fn close(
        &mut self,
        id: u32,
        handle: russh_sftp::protocol::SftpHandle,
    ) -> Result<Status, Self::Error> {
        let key = String::from_utf8_lossy(handle.as_bytes()).into_owned();
        self.handles.remove(&key);
        Ok(ok(id))
    }

    async fn read(
        &mut self,
        id: u32,
        handle: russh_sftp::protocol::SftpHandle,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let key = String::from_utf8_lossy(handle.as_bytes()).into_owned();
        let Some(Open::File(file)) = self.handles.get_mut(&key) else {
            return Err(StatusCode::Failure);
        };
        file.seek(SeekFrom::Start(offset)).map_err(code)?;
        let mut data = vec![0; len as usize];
        let n = file.read(&mut data).map_err(code)?;
        if n == 0 {
            return Err(StatusCode::Eof);
        }
        data.truncate(n);
        Ok(Data { id, data })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: russh_sftp::protocol::SftpHandle,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let key = String::from_utf8_lossy(handle.as_bytes()).into_owned();
        let Some(Open::File(file)) = self.handles.get_mut(&key) else {
            return Err(StatusCode::Failure);
        };
        file.seek(SeekFrom::Start(offset))
            .and_then(|_| file.write_all(&data))
            .map_err(code)?;
        Ok(ok(id))
    }

    async fn lstat(
        &mut self,
        id: u32,
        path: russh_sftp::protocol::SftpString,
    ) -> Result<Attrs, Self::Error> {
        let meta = fs::symlink_metadata(self.local(&path.to_string())).map_err(code)?;
        Ok(Attrs {
            id,
            attrs: (&meta).into(),
        })
    }

    async fn stat(
        &mut self,
        id: u32,
        path: russh_sftp::protocol::SftpString,
    ) -> Result<Attrs, Self::Error> {
        let meta = fs::metadata(self.local(&path.to_string())).map_err(code)?;
        Ok(Attrs {
            id,
            attrs: (&meta).into(),
        })
    }

    async fn fstat(
        &mut self,
        id: u32,
        handle: russh_sftp::protocol::SftpHandle,
    ) -> Result<Attrs, Self::Error> {
        let key = String::from_utf8_lossy(handle.as_bytes()).into_owned();
        let Some(Open::File(file)) = self.handles.get(&key) else {
            return Err(StatusCode::Failure);
        };
        let meta = file.metadata().map_err(code)?;
        Ok(Attrs {
            id,
            attrs: (&meta).into(),
        })
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: russh_sftp::protocol::SftpString,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let path = self.local(&path.to_string());
        if let Some(mtime) = attrs.mtime {
            let file = fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .or_else(|_| fs::File::open(&path))
                .map_err(code)?;
            file.set_modified(UNIX_EPOCH + Duration::from_secs(u64::from(mtime)))
                .map_err(code)?;
        }
        #[cfg(unix)]
        if let Some(mode) = attrs.permissions {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(mode & 0o7777)).map_err(code)?;
        }
        Ok(ok(id))
    }

    async fn opendir(
        &mut self,
        id: u32,
        path: russh_sftp::protocol::SftpString,
    ) -> Result<Handle, Self::Error> {
        let dir = self.local(&path.to_string());
        let mut files = Vec::new();
        for entry in fs::read_dir(dir).map_err(code)? {
            let entry = entry.map_err(code)?;
            let meta = entry.metadata().map_err(code)?;
            files.push(File::new(
                entry.file_name().to_string_lossy().into_owned(),
                (&meta).into(),
            ));
        }
        let handle = self.handle(Open::Dir(Some(files)));
        Ok(Handle {
            id,
            handle: handle.into(),
        })
    }

    async fn readdir(
        &mut self,
        id: u32,
        handle: russh_sftp::protocol::SftpHandle,
    ) -> Result<Name, Self::Error> {
        let key = String::from_utf8_lossy(handle.as_bytes()).into_owned();
        match self.handles.get_mut(&key) {
            Some(Open::Dir(files)) => match files.take() {
                Some(files) => Ok(Name { id, files }),
                None => Err(StatusCode::Eof),
            },
            _ => Err(StatusCode::Failure),
        }
    }

    async fn remove(
        &mut self,
        id: u32,
        filename: russh_sftp::protocol::SftpString,
    ) -> Result<Status, Self::Error> {
        fs::remove_file(self.local(&filename.to_string())).map_err(code)?;
        Ok(ok(id))
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: russh_sftp::protocol::SftpString,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        fs::create_dir(self.local(&path.to_string())).map_err(code)?;
        Ok(ok(id))
    }

    async fn rmdir(
        &mut self,
        id: u32,
        path: russh_sftp::protocol::SftpString,
    ) -> Result<Status, Self::Error> {
        fs::remove_dir(self.local(&path.to_string())).map_err(code)?;
        Ok(ok(id))
    }

    async fn realpath(
        &mut self,
        id: u32,
        path: russh_sftp::protocol::SftpString,
    ) -> Result<Name, Self::Error> {
        // Normalized as the server sees it: `.` is the root, its home.
        let mut parts: Vec<&str> = Vec::new();
        let text = path.to_string();
        for part in text.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                part => parts.push(part),
            }
        }
        Ok(Name {
            id,
            files: vec![File::dummy(format!("/{}", parts.join("/")))],
        })
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: russh_sftp::protocol::SftpString,
        newpath: russh_sftp::protocol::SftpString,
    ) -> Result<Status, Self::Error> {
        fs::rename(
            self.local(&oldpath.to_string()),
            self.local(&newpath.to_string()),
        )
        .map_err(code)?;
        Ok(ok(id))
    }
}

/// An FTP server in the process (libunftp), serving a directory to any
/// user and password, with explicit TLS on a self-signed certificate when
/// asked.
pub struct FtpTestServer {
    pub port: u16,
    pub root: PathBuf,
    _runtime: Runtime,
}

impl FtpTestServer {
    pub fn start(root: &Path, tls: bool) -> Self {
        fs::create_dir_all(root).expect("creating the server's directory");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a runtime");
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .expect("a free port")
            .port();
        let served = root.to_owned();
        let mut builder = libunftp::ServerBuilder::new(Box::new(move || {
            unftp_sbe_fs::Filesystem::new(served.clone()).expect("the served directory")
        }))
        .greeting("RustZilla test server")
        .passive_ports(50000..=60000);
        if tls {
            let dir = root.with_extension("tls");
            fs::create_dir_all(&dir).expect("a directory for the certificate");
            let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()])
                .expect("a certificate");
            fs::write(dir.join("cert.pem"), cert.cert.pem()).expect("writing it");
            fs::write(dir.join("key.pem"), cert.signing_key.serialize_pem()).expect("writing it");
            builder = builder.ftps(dir.join("cert.pem"), dir.join("key.pem"));
        }
        let server = builder.build().expect("the FTP server");
        runtime.spawn(async move {
            let _ = server.listen(format!("127.0.0.1:{port}")).await;
        });
        // Until it listens.
        for _ in 0..100 {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Self {
            port,
            root: root.to_owned(),
            _runtime: runtime,
        }
    }

    pub fn params(
        &self,
        encryption: crate::FtpEncryption,
        trusted_certs: &Path,
    ) -> crate::FtpParams {
        crate::FtpParams {
            host: "127.0.0.1".into(),
            port: self.port,
            username: "test".into(),
            password: "test".into(),
            encryption,
            trusted_certs: trusted_certs.to_owned(),
        }
    }
}
