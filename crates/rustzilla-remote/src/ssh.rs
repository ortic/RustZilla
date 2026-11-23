//! Logging in over SSH, as DbCraft's tunnels do: password (and
//! keyboard-interactive with it, asking the user for anything else such as
//! a one-time code), a key file (OpenSSH, PEM or PuTTY; with its OpenSSH
//! certificate if there is one), the key file of a security key, or the SSH
//! agent's keys and certificates. Optionally through a jump host, as
//! `ssh -J`.
//!
//! The server's host key has to be known, from `~/.ssh/known_hosts` or
//! RustZilla's own file. An unknown key fails the connect with an
//! [`ErrorKind::UnknownHostKey`] the user can trust; a changed key just
//! fails.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client::{self, AuthResult, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::agent::AgentIdentity;
use russh::keys::agent::client::{AgentClient, AgentStream};
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use russh::{Disconnect, MethodKind, MethodSet};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tracing::{info, warn};

use crate::error::{Error, ErrorKind};
use crate::sftp::Sftp;

mod security_key;

use security_key::SecurityKey;

pub(crate) const DEFAULT_PORT: u16 = 22;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// For the whole login: connecting, key exchange and authentication.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(30);
/// For the user to answer what the server asks (a one-time code); servers
/// give up sooner (OpenSSH's LoginGraceTime is 2 minutes).
const PROMPT_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// How to log in.
#[derive(Clone, PartialEq, Eq)]
pub enum Auth {
    Password(String),
    /// A private key file and its passphrase (empty if it has none). The key
    /// file of a security key (`ecdsa-sk`, `ed25519-sk`) signs with the key.
    KeyFile {
        path: PathBuf,
        passphrase: String,
    },
    /// The keys of the SSH agent (Pageant or OpenSSH's on Windows).
    Agent,
}

/// How to reach and log in to the SSH server.
#[derive(Clone)]
pub struct SshParams {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: Auth,
    /// The security key's PIN, for keys that verify the user (`ssh-keygen
    /// -O verify-required`). Not used on Windows, which asks itself.
    pub pin: Option<String>,
    /// Host keys trusted in RustZilla; `~/.ssh/known_hosts` is read as well.
    pub known_hosts: PathBuf,
    /// Called when the security key waits to be touched.
    pub on_touch: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Asks the user what a keyboard-interactive login asks (a one-time
    /// code, say); blocks until answered. A single hidden "Password:" is
    /// answered with the password without asking.
    pub on_prompt: Option<OnPrompt>,
    /// The jump host to connect through (`ssh -J`), logged in to with the
    /// same credentials.
    pub jump: Option<Jump>,
}

/// Answers the prompts, one answer each; `None` when the user cancelled.
pub type OnPrompt = Arc<dyn Fn(Prompts) -> Option<Vec<String>> + Send + Sync>;

/// What a keyboard-interactive login asks the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompts {
    /// The server asking, as `host` or `host:port` (or "the jump host …").
    pub server: String,
    pub name: String,
    pub instructions: String,
    pub prompts: Vec<Prompt>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompt {
    pub text: String,
    /// Whether the answer may be shown while typed (not a secret).
    pub echo: bool,
}

/// A jump host (OpenSSH's ProxyJump): the connection to the server is
/// tunnelled through an SSH connection to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jump {
    pub host: String,
    pub port: u16,
    /// Empty for the user of the server.
    pub username: String,
}

impl Jump {
    /// Reads `[user@]host[:port]` (`[::1]:2222` for IPv6), as `ssh -J`
    /// takes it. `None` if empty.
    pub fn parse(text: &str) -> Result<Option<Self>, String> {
        let text = text.trim();
        if text.is_empty() {
            return Ok(None);
        }
        let (username, rest) = match text.rsplit_once('@') {
            Some((user, rest)) => (user.trim(), rest.trim()),
            None => ("", text),
        };
        let (host, port) = if let Some(bracketed) = rest.strip_prefix('[') {
            let (host, after) = bracketed
                .split_once(']')
                .ok_or_else(|| format!("the jump host {text} lacks its closing ]"))?;
            (host, after.strip_prefix(':'))
        } else {
            match rest.split_once(':') {
                // An IPv6 address without brackets has no port.
                Some((host, port)) if !port.contains(':') => (host, Some(port)),
                _ => (rest, None),
            }
        };
        let port = match port {
            Some(port) => port
                .trim()
                .parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| format!("the port of the jump host {text} isn't a port"))?,
            None => DEFAULT_PORT,
        };
        if host.trim().is_empty() {
            return Err(format!("the jump host {text} lacks the host"));
        }
        Ok(Some(Self {
            host: host.trim().to_owned(),
            port,
            username: username.to_owned(),
        }))
    }
}

impl fmt::Display for Jump {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.username.is_empty() {
            write!(f, "{}@", self.username)?;
        }
        if self.host.contains(':') {
            write!(f, "[{}]", self.host)?;
        } else {
            f.write_str(&self.host)?;
        }
        if self.port != DEFAULT_PORT {
            write!(f, ":{}", self.port)?;
        }
        Ok(())
    }
}

impl fmt::Debug for SshParams {
    // Never print the password, not even in debug logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let auth = match &self.auth {
            Auth::Password(_) => "password".to_owned(),
            Auth::KeyFile { path, .. } => format!("key file {}", path.display()),
            Auth::Agent => "agent".to_owned(),
        };
        f.debug_struct("SshParams")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("auth", &auth)
            .field("jump", &self.jump)
            .finish_non_exhaustive()
    }
}

/// Whether `path` is a security key's key file, encrypted or not.
pub fn is_security_key(path: &Path) -> bool {
    security_key::is_security_key(path)
}

/// Whether the key file at `path` is protected by a passphrase.
pub fn is_encrypted_key(path: &Path) -> bool {
    security_key::is_encrypted(path)
}

/// A server's host key that isn't known yet. Connecting fails with it until
/// the user trusts it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKey {
    pub host: String,
    pub port: u16,
    /// The key type and its SHA-256 fingerprint, as `ssh` shows them.
    pub fingerprint: String,
    key: PublicKey,
    known_hosts: PathBuf,
}

impl HostKey {
    pub(crate) fn new(host: &str, port: u16, key: &PublicKey, known_hosts: &Path) -> Self {
        Self {
            host: host.to_owned(),
            port,
            fingerprint: format!(
                "{} {}",
                key.algorithm().as_str(),
                key.fingerprint(HashAlg::Sha256)
            ),
            key: key.clone(),
            known_hosts: known_hosts.to_owned(),
        }
    }

    /// Adds the key to RustZilla's known hosts, so it is accepted from now on.
    pub fn trust(&self) -> Result<(), Error> {
        self.append().map_err(|e| {
            Error::new(format!(
                "Saving the host key in {}: {e}",
                self.known_hosts.display()
            ))
        })
    }

    fn append(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(dir) = self.known_hosts.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut text = fs::read_to_string(&self.known_hosts).unwrap_or_default();
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        let host = if self.port == DEFAULT_PORT {
            self.host.clone()
        } else {
            format!("[{}]:{}", self.host, self.port)
        };
        // Without the key's comment, like `ssh` writes it.
        let key = PublicKey::from(self.key.key_data().clone()).to_openssh()?;
        text.push_str(&format!("{host} {key}\n"));
        fs::write(&self.known_hosts, text)?;
        Ok(())
    }
}

/// A logged-in SSH connection. Cheap to clone; the connection ends when the
/// last clone (and the last [`Sftp`] on it) is dropped, or on
/// [`disconnect`](Self::disconnect).
#[derive(Clone)]
pub struct Connection {
    inner: Arc<Inner>,
}

struct Inner {
    runtime: Option<Runtime>,
    ssh: Handle<Client>,
    /// The connection to the jump host that `ssh` runs through: kept as
    /// long as it.
    jump: Option<Handle<Client>>,
    server: String,
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Connection")
            .field(&self.inner.server)
            .finish()
    }
}

impl Connection {
    /// Connects and logs in. Blocks, with a security key until it is
    /// touched.
    pub fn open(params: &SshParams) -> Result<Self, Error> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("ssh")
            .enable_all()
            .build()
            .map_err(|e| Error::new(format!("starting the SSH runtime: {e}")))?;
        let server = Server::new(&params.host, params.port)?;
        info!(?params, "logging in over SSH");
        // A security key waits for its touch as well, on the jump host too.
        let touch = match &params.auth {
            Auth::KeyFile { path, .. } => is_security_key(path),
            Auth::Agent => true,
            Auth::Password(_) => false,
        };
        let logins = if params.jump.is_some() { 2 } else { 1 };
        let timeout = if touch {
            (LOGIN_TIMEOUT + crate::fido::TOUCH_TIMEOUT) * logins
        } else {
            LOGIN_TIMEOUT * logins
        };
        // The time the user takes to answer prompts doesn't count.
        let deadline = Deadline::new(timeout);
        let result = runtime
            .block_on(deadline.run(login(&server, params, &deadline)))
            .ok_or_else(|| {
                Error::new(format!(
                    "{server} didn't complete the login within {} seconds",
                    timeout.as_secs()
                ))
            })
            .flatten();
        let logged_in = match result {
            Ok(logged_in) => logged_in,
            Err(e) => {
                // Without waiting for a prompt still open (dropping the
                // runtime would).
                runtime.shutdown_background();
                return Err(e);
            }
        };
        Ok(Self {
            inner: Arc::new(Inner {
                runtime: Some(runtime),
                ssh: logged_in.ssh,
                jump: logged_in.jump,
                server: server.to_string(),
            }),
        })
    }

    /// The server, as `host` or `host:port`.
    pub fn server(&self) -> &str {
        &self.inner.server
    }

    pub fn is_closed(&self) -> bool {
        self.inner.ssh.is_closed() || self.inner.jump.as_ref().is_some_and(Handle::is_closed)
    }

    /// Opens an SFTP session on a channel of its own.
    pub fn sftp(&self) -> Result<Sftp, Error> {
        let session = self.block_on(async {
            let channel = self
                .inner
                .ssh
                .channel_open_session()
                .await
                .map_err(|e| self.lost(e))?;
            channel
                .request_subsystem(true, "sftp")
                .await
                .map_err(|e| Error::new(format!("SFTP: requesting the subsystem: {e}")))?;
            let config = russh_sftp::client::Config {
                request_timeout_secs: 60,
                ..Default::default()
            };
            russh_sftp::client::SftpSession::new_with_config(channel.into_stream(), config)
                .await
                .map_err(|e| {
                    Error::new(format!(
                        "SFTP: the server didn't start an SFTP session ({e}). Is SFTP enabled \
                         on it (Subsystem sftp in sshd_config)?"
                    ))
                })
        })?;
        Ok(Sftp::new(self.clone(), session))
    }

    /// Ends the connection, telling the server.
    pub fn disconnect(&self) {
        self.block_on(async {
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                self.inner
                    .ssh
                    .disconnect(Disconnect::ByApplication, "", "en"),
            )
            .await;
            if let Some(jump) = &self.inner.jump {
                let _ = tokio::time::timeout(
                    Duration::from_secs(2),
                    jump.disconnect(Disconnect::ByApplication, "", "en"),
                )
                .await;
            }
        });
    }

    pub(crate) fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.inner
            .runtime
            .as_ref()
            .expect("runtime lives as long as the connection")
            .block_on(future)
    }

    fn lost(&self, e: russh::Error) -> Error {
        Error::with_kind(
            format!("the connection to {} is lost: {e}", self.inner.server),
            ErrorKind::Disconnected,
        )
    }
}

impl crate::remote::Server for Connection {
    fn name(&self) -> &str {
        self.server()
    }

    fn security(&self) -> crate::remote::Security {
        crate::remote::Security::Ssh
    }

    fn open(&self) -> Result<Box<dyn crate::remote::Session>, Error> {
        Ok(Box::new(self.sftp()?))
    }

    fn is_closed(&self) -> bool {
        Connection::is_closed(self)
    }

    fn disconnect(&self) {
        Connection::disconnect(self)
    }
}

/// The SSH server's address.
pub(crate) struct Server {
    pub host: String,
    pub port: u16,
    /// The jump host to the server, not the server: said in messages.
    pub jump: bool,
}

impl Server {
    fn new(host: &str, port: u16) -> Result<Self, Error> {
        let host = host.trim();
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        if host.is_empty() {
            return Err(Error::new("enter the server to connect to"));
        }
        Ok(Self {
            host: host.to_owned(),
            port: if port == 0 { DEFAULT_PORT } else { port },
            jump: false,
        })
    }
}

impl fmt::Display for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.jump {
            f.write_str("the jump host ")?;
        }
        if self.port == DEFAULT_PORT {
            f.write_str(&self.host)
        } else if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// The login's deadline, put off while the user answers prompts.
pub(crate) struct Deadline(Mutex<tokio::time::Instant>);

impl Deadline {
    pub(crate) fn new(timeout: Duration) -> Self {
        Self(Mutex::new(tokio::time::Instant::now() + timeout))
    }

    fn at(&self) -> tokio::time::Instant {
        *self.0.lock().expect("deadline mutex")
    }

    /// From now on, `timeout` is left.
    fn put_off(&self, timeout: Duration) {
        *self.0.lock().expect("deadline mutex") = tokio::time::Instant::now() + timeout;
    }

    /// Runs `future` until the deadline; `None` if it passed first.
    pub(crate) async fn run<F: Future>(&self, future: F) -> Option<F::Output> {
        let mut future = std::pin::pin!(future);
        loop {
            let at = self.at();
            match tokio::time::timeout_at(at, future.as_mut()).await {
                Ok(output) => return Some(output),
                // Put off in the meantime.
                Err(_) if self.at() > at => {}
                Err(_) => return None,
            }
        }
    }
}

/// A logged-in connection, and the jump host's it runs through.
pub(crate) struct LoggedIn {
    pub ssh: Handle<Client>,
    pub jump: Option<Handle<Client>>,
}

pub(crate) async fn login(
    server: &Server,
    params: &SshParams,
    deadline: &Deadline,
) -> Result<LoggedIn, Error> {
    let user = params.username.trim();
    if user.is_empty() {
        return Err(Error::new("enter the user to log in as"));
    }
    let Some(jump) = &params.jump else {
        let socket = tcp_connect(server).await?;
        let mut ssh = handshake(server, socket, params).await?;
        authenticate(&mut ssh, server, user, params, deadline).await?;
        info!("logged in to {server} over SSH");
        return Ok(LoggedIn { ssh, jump: None });
    };
    let mut jump_server = Server::new(&jump.host, jump.port)?;
    jump_server.jump = true;
    let jump_user = Some(jump.username.trim())
        .filter(|u| !u.is_empty())
        .unwrap_or(user);
    let socket = tcp_connect(&jump_server).await?;
    let mut jump_ssh = handshake(&jump_server, socket, params).await?;
    authenticate(&mut jump_ssh, &jump_server, jump_user, params, deadline).await?;
    info!("logged in to {jump_server} over SSH");
    let channel = jump_ssh
        .channel_open_direct_tcpip(server.host.clone(), u32::from(server.port), "127.0.0.1", 0)
        .await
        .map_err(|e| Error::new(format!("{jump_server} can't connect to {server}: {e}")))?;
    let mut ssh = handshake(server, channel.into_stream(), params).await?;
    authenticate(&mut ssh, server, user, params, deadline).await?;
    info!("logged in to {server} over SSH through {jump_server}");
    Ok(LoggedIn {
        ssh,
        jump: Some(jump_ssh),
    })
}

async fn tcp_connect(server: &Server) -> Result<TcpStream, Error> {
    let socket = tokio::time::timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((server.host.as_str(), server.port)),
    )
    .await
    .map_err(|_| {
        Error::new(format!(
            "no answer from {server} within {} seconds",
            CONNECT_TIMEOUT.as_secs()
        ))
    })?
    .map_err(|e| Error::new(format!("can't connect to {server}: {e}")))?;
    let _ = socket.set_nodelay(true);
    Ok(socket)
}

/// The SSH handshake on `stream`, checking the host key.
async fn handshake<S>(
    server: &Server,
    stream: S,
    params: &SshParams,
) -> Result<Handle<Client>, Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let config = Arc::new(client::Config {
        // Keeps NAT and firewalls from dropping an idle connection, and
        // notices a dead one.
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
        // Bigger windows for faster transfers.
        window_size: 16 * 1024 * 1024,
        maximum_packet_size: 64 * 1024,
        ..Default::default()
    });
    let rejected = Arc::new(Mutex::new(None));
    let client = Client {
        host: server.host.clone(),
        port: server.port,
        jump: server.jump,
        known_hosts: params.known_hosts.clone(),
        rejected: rejected.clone(),
    };
    client::connect_stream(config, stream, client)
        .await
        .map_err(|e| match rejected.lock().expect("rejected mutex").take() {
            Some(error) => error,
            None => Error::new(format!("{server}: {e}")),
        })
}

async fn authenticate(
    ssh: &mut Handle<Client>,
    server: &Server,
    user: &str,
    params: &SshParams,
    deadline: &Deadline,
) -> Result<(), Error> {
    let failed = |e: russh::Error| Error::new(format!("logging in to {server}: {e}"));
    let (tried, result, password) = match &params.auth {
        Auth::KeyFile { path, passphrase } => {
            let key = load_key(path, passphrase)?;
            if let Some(mut signer) =
                SecurityKey::new(&key, params.pin.clone(), params.on_touch.clone())
            {
                let result = ssh
                    .authenticate_publickey_with(user, key.public_key().clone(), None, &mut signer)
                    .await
                    .map_err(|e| security_key_error(server, &e.0.to_string()))?;
                (
                    format!("the security key of {}", path.display()),
                    result,
                    None,
                )
            } else {
                let key = Arc::new(key);
                let result = match certificate_login(ssh, user, path, &key).await {
                    Some(result) => result,
                    None => {
                        let hash = ssh
                            .best_supported_rsa_hash()
                            .await
                            .map_err(failed)?
                            .flatten();
                        ssh.authenticate_publickey(user, PrivateKeyWithHashAlg::new(key, hash))
                            .await
                            .map_err(failed)?
                    }
                };
                ("the key file".to_owned(), result, None)
            }
        }
        Auth::Password(password) => {
            let result = ssh
                .authenticate_password(user, password)
                .await
                .map_err(failed)?;
            ("the password".to_owned(), result, Some(password.as_str()))
        }
        Auth::Agent => (
            "the SSH agent's keys".to_owned(),
            agent(ssh, user).await?,
            None,
        ),
    };
    // Keyboard-interactive: with the password if the server didn't take it
    // as such (or offers nothing else), or for a second factor, e.g. a
    // one-time code after the key.
    let (tried, result) = match result {
        AuthResult::Failure {
            remaining_methods,
            partial_success,
        } if remaining_methods.contains(&MethodKind::KeyboardInteractive)
            && (password.is_some() || partial_success) =>
        {
            let (result, asked) =
                keyboard_interactive(ssh, server, user, password, params, deadline).await?;
            let tried = if asked {
                format!("{tried} and the answers")
            } else {
                tried
            };
            (tried, result)
        }
        result => (tried, result),
    };
    match result {
        AuthResult::Success => Ok(()),
        AuthResult::Failure {
            remaining_methods, ..
        } => Err(Error::new(format!(
            "{server} didn't accept {tried} for {user}{}",
            accepted(&remaining_methods)
        ))),
    }
}

/// The OpenSSH certificate next to a key file, as `ssh` looks for it.
fn certificate_path(key_file: &Path) -> PathBuf {
    let mut path = key_file.as_os_str().to_owned();
    path.push("-cert.pub");
    PathBuf::from(path)
}

/// Logs in with the key file's certificate (`<key file>-cert.pub`), if there
/// is one. `None` if there is none or the server didn't take it: the key
/// alone is tried then.
async fn certificate_login(
    ssh: &mut Handle<Client>,
    user: &str,
    key_file: &Path,
    key: &Arc<russh::keys::PrivateKey>,
) -> Option<AuthResult> {
    let path = certificate_path(key_file);
    if !path.is_file() {
        return None;
    }
    let certificate = match russh::keys::load_openssh_certificate(&path) {
        Ok(certificate) => certificate,
        Err(e) => {
            warn!("reading the certificate {}: {e}", path.display());
            return None;
        }
    };
    match ssh
        .authenticate_openssh_cert(user, key.clone(), certificate)
        .await
    {
        Ok(AuthResult::Success) => {
            info!("logged in with the certificate {}", path.display());
            Some(AuthResult::Success)
        }
        // Accepted, another factor to follow.
        Ok(
            partial @ AuthResult::Failure {
                partial_success: true,
                ..
            },
        ) => Some(partial),
        Ok(AuthResult::Failure { .. }) => {
            info!(
                "the server didn't accept the certificate {}; trying the key alone",
                path.display()
            );
            None
        }
        Err(e) => {
            warn!("logging in with the certificate {}: {e}", path.display());
            None
        }
    }
}

/// Why the security key didn't sign; a PIN the app can ask for.
fn security_key_error(server: &Server, reason: &str) -> Error {
    let message = format!("logging in to {server}: {reason}");
    if reason.contains(crate::fido::PIN_NEEDED) || reason.contains(crate::fido::PIN_WRONG) {
        Error::with_kind(message, ErrorKind::Pin)
    } else {
        Error::new(message)
    }
}

/// What the server would accept instead, if it said.
fn accepted(methods: &MethodSet) -> String {
    let names: Vec<&str> = methods
        .iter()
        .filter(|m| **m != MethodKind::None)
        .map(<&str>::from)
        .collect();
    if names.is_empty() {
        String::new()
    } else {
        format!(" (it accepts: {})", names.join(", "))
    }
}

fn load_key(path: &Path, passphrase: &str) -> Result<russh::keys::PrivateKey, Error> {
    let passphrase = Some(passphrase).filter(|p| !p.is_empty());
    russh::keys::load_secret_key(path, passphrase).map_err(|e| match e {
        russh::keys::Error::KeyIsEncrypted => Error::with_kind(
            format!(
                "the key file {} is protected by a passphrase: enter it",
                path.display()
            ),
            ErrorKind::Passphrase,
        ),
        // A wrong passphrase fails in the cipher, as "cryptographic error"
        // or "Padding error": the key is encrypted, and it doesn't open it.
        _ if passphrase.is_some()
            && matches!(
                russh::keys::load_secret_key(path, None),
                Err(russh::keys::Error::KeyIsEncrypted)
            ) =>
        {
            Error::with_kind(
                format!(
                    "the passphrase doesn't open the key file {}",
                    path.display()
                ),
                ErrorKind::Passphrase,
            )
        }
        e => Error::new(format!("reading the key file {}: {e}", path.display())),
    })
}

/// Keyboard-interactive authentication: the password answers the first
/// hidden "Password:" prompt, the user the others (a one-time code, say).
/// Whether the user was asked comes with the result.
async fn keyboard_interactive(
    ssh: &mut Handle<Client>,
    server: &Server,
    user: &str,
    password: Option<&str>,
    params: &SshParams,
    deadline: &Deadline,
) -> Result<(AuthResult, bool), Error> {
    let failed = |e: russh::Error| Error::new(format!("logging in to {server}: {e}"));
    let mut password = password;
    let mut asked = false;
    let mut reply = ssh
        .authenticate_keyboard_interactive_start(user, None)
        .await
        .map_err(failed)?;
    // A server could keep asking; a login takes a few rounds at most.
    for _ in 0..8 {
        let (name, instructions, prompts) = match reply {
            KeyboardInteractiveAuthResponse::Success => return Ok((AuthResult::Success, asked)),
            KeyboardInteractiveAuthResponse::Failure {
                remaining_methods,
                partial_success,
            } => {
                return Ok((
                    AuthResult::Failure {
                        remaining_methods,
                        partial_success,
                    },
                    asked,
                ));
            }
            KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => (name, instructions, prompts),
        };
        let answers = match (password, prompts.as_slice()) {
            // Servers send rounds without prompts too.
            (_, []) => Vec::new(),
            (Some(known), [prompt]) if !prompt.echo && is_password_prompt(&prompt.prompt) => {
                // Only once: asked again, the password was wrong.
                password = None;
                vec![known.to_owned()]
            }
            _ => {
                asked = true;
                let prompts = Prompts {
                    server: server.to_string(),
                    name,
                    instructions,
                    prompts: prompts
                        .into_iter()
                        .map(|p| Prompt {
                            text: p.prompt,
                            echo: p.echo,
                        })
                        .collect(),
                };
                ask(prompts, params, deadline).await?
            }
        };
        reply = ssh
            .authenticate_keyboard_interactive_respond(answers)
            .await
            .map_err(failed)?;
    }
    Err(Error::new(format!(
        "{server} kept asking questions to log in; gave up"
    )))
}

fn is_password_prompt(prompt: &str) -> bool {
    prompt.to_lowercase().contains("password")
}

/// The user's answers, waited for off the runtime's threads, without the
/// login's timeout running.
async fn ask(
    prompts: Prompts,
    params: &SshParams,
    deadline: &Deadline,
) -> Result<Vec<String>, Error> {
    let count = prompts.prompts.len();
    let Some(on_prompt) = params.on_prompt.clone() else {
        let asked: Vec<&str> = prompts.prompts.iter().map(|p| p.text.trim()).collect();
        return Err(Error::new(format!(
            "{} asks for {} to log in, and there is no one to answer",
            prompts.server,
            asked.join(", ")
        )));
    };
    let server = prompts.server.clone();
    deadline.put_off(PROMPT_TIMEOUT);
    let answers = tokio::task::spawn_blocking(move || on_prompt(prompts))
        .await
        .ok()
        .flatten();
    deadline.put_off(LOGIN_TIMEOUT);
    let Some(mut answers) = answers else {
        return Err(Error::with_kind(
            format!("logging in to {server}: cancelled"),
            ErrorKind::Cancelled,
        ));
    };
    answers.resize(count, String::new());
    Ok(answers)
}

/// Logs in with the keys and certificates of the SSH agent (Pageant or
/// OpenSSH's on Windows). Security keys in the agent sign there, the agent
/// waiting for the touch.
async fn agent(ssh: &mut Handle<Client>, user: &str) -> Result<AuthResult, Error> {
    let (mut agent, identities) = agent_keys()
        .await
        .map_err(|e| Error::new(format!("there is no SSH agent to log in with: {e}")))?;
    let hash = ssh
        .best_supported_rsa_hash()
        .await
        .map_err(|e| Error::new(format!("SSH: {e}")))?
        .flatten();
    let mut result = AuthResult::Failure {
        remaining_methods: MethodSet::empty(),
        partial_success: false,
    };
    for identity in identities {
        let (signed, comment) = match identity {
            AgentIdentity::PublicKey { key, comment } => (
                ssh.authenticate_publickey_with(user, key, hash, &mut agent)
                    .await,
                comment,
            ),
            AgentIdentity::Certificate {
                certificate,
                comment,
            } => (
                ssh.authenticate_certificate_with(user, certificate, hash, &mut agent)
                    .await,
                comment,
            ),
        };
        match signed {
            Ok(AuthResult::Success) => return Ok(AuthResult::Success),
            // Another factor wanted, e.g. a one-time code.
            Ok(
                failure @ AuthResult::Failure {
                    partial_success: true,
                    ..
                },
            ) => return Ok(failure),
            Ok(failure) => result = failure,
            Err(e) => warn!("SSH agent couldn't sign with {comment}: {e}"),
        }
    }
    Ok(result)
}

type Agent = AgentClient<Box<dyn AgentStream + Send + Unpin>>;

/// The SSH agent and its keys.
async fn agent_keys() -> Result<(Agent, Vec<AgentIdentity>), russh::keys::Error> {
    #[cfg(windows)]
    {
        // Pageant (PuTTY) first, then the agent of Windows' OpenSSH.
        if let Ok(pageant) = AgentClient::connect_pageant().await {
            let mut pageant = pageant.dynamic();
            if let Ok(keys) = pageant.request_identities().await
                && !keys.is_empty()
            {
                return Ok((pageant, keys));
            }
        }
        let mut agent = AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent")
            .await?
            .dynamic();
        let keys = agent.request_identities().await?;
        Ok((agent, keys))
    }
    #[cfg(not(windows))]
    {
        let mut agent = AgentClient::connect_env().await?.dynamic();
        let keys = agent.request_identities().await?;
        Ok((agent, keys))
    }
}

/// Checks the server's host key.
pub(crate) struct Client {
    host: String,
    port: u16,
    /// A jump host's key: said in messages.
    jump: bool,
    known_hosts: PathBuf,
    /// Why the key was rejected, for the connect error.
    rejected: Arc<Mutex<Option<Error>>>,
}

impl Client {
    fn check(&self, key: &PublicKey) -> Result<(), Error> {
        let server = Server {
            host: self.host.clone(),
            port: self.port,
            jump: self.jump,
        };
        let user_file = std::env::home_dir().map(|home| home.join(".ssh").join("known_hosts"));
        for file in user_file.iter().chain([&self.known_hosts]) {
            match russh::keys::known_hosts::check_known_hosts_path(&self.host, self.port, key, file)
            {
                Ok(true) => return Ok(()),
                Ok(false) => {}
                Err(russh::keys::Error::KeyChanged { line }) => {
                    return Err(Error::new(format!(
                        "the host key of {server} isn't the one in {}, line {}. Someone could \
                         be intercepting the connection. If the server got a new key, remove \
                         that line.",
                        file.display(),
                        file_line(file, line)
                    )));
                }
                Err(e) => warn!("reading {}: {e}", file.display()),
            }
        }
        Err(Error::with_kind(
            format!("the host key of {server} is unknown"),
            ErrorKind::UnknownHostKey(Box::new(HostKey::new(
                &self.host,
                self.port,
                key,
                &self.known_hosts,
            ))),
        ))
    }
}

/// The line number in `file` of russh's `entry`, which doesn't count
/// comment lines.
fn file_line(file: &Path, entry: usize) -> usize {
    let text = fs::read_to_string(file).unwrap_or_default();
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.starts_with('#'))
        .nth(entry.saturating_sub(1))
        .map_or(entry, |(index, _)| index + 1)
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // A host certificate is checked like its key: the key is what the
        // user trusts.
        let key = match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
            PublicKeyOrCertificate::Certificate(cert) => PublicKey::from(cert.public_key().clone()),
        };
        match self.check(&key) {
            Ok(()) => Ok(true),
            Err(error) => {
                *self.rejected.lock().expect("rejected mutex") = Some(error);
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn servers() {
        let s = Server::new(" example.com ", 22).unwrap();
        assert_eq!(s.to_string(), "example.com");
        let s = Server::new("example.com", 2222).unwrap();
        assert_eq!(s.to_string(), "example.com:2222");
        let s = Server::new("[::1]", 2222).unwrap();
        assert_eq!(
            (s.host.as_str(), s.to_string()),
            ("::1", "[::1]:2222".into())
        );
        assert_eq!(Server::new("h", 0).unwrap().port, 22);
        assert!(Server::new("", 22).is_err());
    }
}
