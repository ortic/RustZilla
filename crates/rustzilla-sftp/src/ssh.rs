//! Logging in over SSH, as DbCraft's tunnels do: password (and
//! keyboard-interactive with it), a key file (OpenSSH, PEM or PuTTY), the
//! key file of a security key, or the SSH agent's keys.
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
        // A security key waits for its touch as well.
        let timeout = match &params.auth {
            Auth::KeyFile { path, .. } if is_security_key(path) => {
                LOGIN_TIMEOUT + crate::fido::TOUCH_TIMEOUT
            }
            Auth::Agent => LOGIN_TIMEOUT + crate::fido::TOUCH_TIMEOUT,
            _ => LOGIN_TIMEOUT,
        };
        let ssh = runtime
            .block_on(async { tokio::time::timeout(timeout, login(&server, params)).await })
            .map_err(|_| {
                Error::new(format!(
                    "{server} didn't complete the login within {} seconds",
                    timeout.as_secs()
                ))
            })??;
        Ok(Self {
            inner: Arc::new(Inner {
                runtime: Some(runtime),
                ssh,
                server: server.to_string(),
            }),
        })
    }

    /// The server, as `host` or `host:port`.
    pub fn server(&self) -> &str {
        &self.inner.server
    }

    pub fn is_closed(&self) -> bool {
        self.inner.ssh.is_closed()
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
        let _ = self.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(2),
                self.inner
                    .ssh
                    .disconnect(Disconnect::ByApplication, "", "en"),
            )
            .await
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

/// The SSH server's address.
pub(crate) struct Server {
    pub host: String,
    pub port: u16,
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
        })
    }
}

impl fmt::Display for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.port == DEFAULT_PORT {
            f.write_str(&self.host)
        } else if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

pub(crate) async fn login(server: &Server, params: &SshParams) -> Result<Handle<Client>, Error> {
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
        known_hosts: params.known_hosts.clone(),
        rejected: rejected.clone(),
    };
    let mut ssh = client::connect_stream(config, socket, client)
        .await
        .map_err(|e| match rejected.lock().expect("rejected mutex").take() {
            Some(error) => error,
            None => Error::new(format!("{server}: {e}")),
        })?;
    authenticate(&mut ssh, server, params).await?;
    info!("logged in to {server} over SSH");
    Ok(ssh)
}

async fn authenticate(
    ssh: &mut Handle<Client>,
    server: &Server,
    params: &SshParams,
) -> Result<(), Error> {
    let user = params.username.trim();
    if user.is_empty() {
        return Err(Error::new("enter the user to log in as"));
    }
    let failed = |e: russh::Error| Error::new(format!("logging in to {server}: {e}"));
    let (tried, result) = match &params.auth {
        Auth::KeyFile { path, passphrase } => {
            let key = load_key(path, passphrase)?;
            if let Some(mut signer) =
                SecurityKey::new(&key, params.pin.clone(), params.on_touch.clone())
            {
                let result = ssh
                    .authenticate_publickey_with(user, key.public_key().clone(), None, &mut signer)
                    .await
                    .map_err(|e| security_key_error(server, &e.0.to_string()))?;
                return match result {
                    AuthResult::Success => Ok(()),
                    AuthResult::Failure {
                        remaining_methods, ..
                    } => Err(Error::new(format!(
                        "{server} didn't accept the security key of {} for {user}{}",
                        path.display(),
                        accepted(&remaining_methods)
                    ))),
                };
            }
            let hash = ssh
                .best_supported_rsa_hash()
                .await
                .map_err(failed)?
                .flatten();
            let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash);
            let result = ssh
                .authenticate_publickey(user, key)
                .await
                .map_err(failed)?;
            ("the key file", result)
        }
        Auth::Password(password) => {
            let result = password_login(ssh, user, password).await.map_err(failed)?;
            ("the password", result)
        }
        Auth::Agent => ("the SSH agent's keys", agent(ssh, user).await?),
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

/// Password authentication, and keyboard-interactive with the password for
/// servers that only offer that.
async fn password_login(
    ssh: &mut Handle<Client>,
    user: &str,
    password: &str,
) -> Result<AuthResult, russh::Error> {
    let result = ssh.authenticate_password(user, password).await?;
    let AuthResult::Failure {
        remaining_methods, ..
    } = &result
    else {
        return Ok(result);
    };
    if !remaining_methods.contains(&MethodKind::KeyboardInteractive) {
        return Ok(result);
    }
    let mut reply = ssh
        .authenticate_keyboard_interactive_start(user, None)
        .await?;
    // A server could keep asking; a password login takes a round or two.
    for _ in 0..4 {
        match reply {
            KeyboardInteractiveAuthResponse::Success => return Ok(AuthResult::Success),
            KeyboardInteractiveAuthResponse::Failure {
                remaining_methods,
                partial_success,
            } => {
                return Ok(AuthResult::Failure {
                    remaining_methods,
                    partial_success,
                });
            }
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                // Hidden prompts ask for the password; there is nothing to
                // answer others (e.g. a one-time code) with.
                let answers = prompts
                    .iter()
                    .map(|p| {
                        if p.echo {
                            String::new()
                        } else {
                            password.to_owned()
                        }
                    })
                    .collect();
                reply = ssh
                    .authenticate_keyboard_interactive_respond(answers)
                    .await?;
            }
        }
    }
    Ok(result)
}

/// Logs in with the keys of the SSH agent (Pageant or OpenSSH's on Windows).
/// Security keys in the agent sign there, the agent waiting for the touch.
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
        let AgentIdentity::PublicKey { key, comment } = identity else {
            continue;
        };
        match ssh
            .authenticate_publickey_with(user, key, hash, &mut agent)
            .await
        {
            Ok(AuthResult::Success) => return Ok(AuthResult::Success),
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
    known_hosts: PathBuf,
    /// Why the key was rejected, for the connect error.
    rejected: Arc<Mutex<Option<Error>>>,
}

impl Client {
    fn check(&self, key: &PublicKey) -> Result<(), Error> {
        let server = Server {
            host: self.host.clone(),
            port: self.port,
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
