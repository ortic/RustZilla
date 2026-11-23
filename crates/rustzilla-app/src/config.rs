//! Where RustZilla keeps its files, and the sites of the Site Manager
//! (`sites.toml`; passwords and passphrases go to the OS keychain).

use std::fs;
use std::path::PathBuf;

use rustzilla_remote::{FtpEncryption, Protocol};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
}

impl Paths {
    pub fn detect() -> Option<Self> {
        let dirs = directories::ProjectDirs::from("com", "ortic", "RustZilla")?;
        Some(Self {
            config_dir: dirs.config_dir().to_owned(),
            data_dir: dirs.data_dir().to_owned(),
        })
    }

    /// Host keys trusted in RustZilla (`~/.ssh/known_hosts` is read too).
    pub fn known_hosts(&self) -> PathBuf {
        self.data_dir.join("known_hosts")
    }

    /// TLS certificates trusted in RustZilla (FTPS).
    pub fn trusted_certs(&self) -> PathBuf {
        self.data_dir.join("trusted_certificates")
    }

    pub fn log_dir(&self) -> PathBuf {
        self.data_dir.join("logs")
    }

    fn sites_file(&self) -> PathBuf {
        self.config_dir.join("sites.toml")
    }
}

/// How a site logs in, as FileZilla's logon types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Logon {
    /// With a password kept in the keychain.
    #[default]
    Normal,
    /// Asks for the password on each connect.
    AskPassword,
    /// A private key file, or a security key's key file (a YubiKey's
    /// `id_ecdsa_sk`, `id_ed25519_sk`).
    KeyFile,
    /// The keys of the SSH agent.
    Agent,
    /// Anonymous FTP.
    Anonymous,
}

impl Logon {
    /// The logon types of `protocol`.
    pub fn of(protocol: Protocol) -> &'static [Logon] {
        match protocol {
            Protocol::Sftp => &[
                Logon::Normal,
                Logon::AskPassword,
                Logon::KeyFile,
                Logon::Agent,
            ],
            Protocol::Ftp => &[Logon::Anonymous, Logon::Normal, Logon::AskPassword],
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Logon::Normal => "Normal",
            Logon::AskPassword => "Ask for password",
            Logon::KeyFile => "Key file / security key",
            Logon::Agent => "SSH agent",
            Logon::Anonymous => "Anonymous",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Site {
    /// Stable across renames: the keychain entry's name.
    pub id: String,
    pub name: String,
    pub protocol: Protocol,
    /// How FTP is encrypted (FTP only).
    pub encryption: FtpEncryption,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub logon: Logon,
    pub key_file: String,
    /// Opened after connecting; empty for the home directory.
    pub remote_dir: String,
    /// Opened on the local side after connecting, if set.
    pub local_dir: String,
}

impl Default for Site {
    fn default() -> Self {
        Self {
            id: new_id(),
            name: "New site".into(),
            protocol: Protocol::Sftp,
            encryption: FtpEncryption::ExplicitIfAvailable,
            host: String::new(),
            port: 22,
            user: String::new(),
            logon: Logon::Normal,
            key_file: String::new(),
            remote_dir: String::new(),
            local_dir: String::new(),
        }
    }
}

pub fn new_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("site-{nanos:x}")
}

#[derive(Default, Serialize, Deserialize)]
struct SitesFile {
    #[serde(default, rename = "site")]
    sites: Vec<Site>,
}

pub fn load_sites(paths: &Paths) -> Result<Vec<Site>, String> {
    let file = paths.sites_file();
    let text = match fs::read_to_string(&file) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("reading {}: {e}", file.display())),
    };
    toml::from_str::<SitesFile>(&text)
        .map(|f| f.sites)
        .map_err(|e| format!("reading {}: {e}", file.display()))
}

pub fn save_sites(paths: &Paths, sites: &[Site]) -> Result<(), String> {
    let file = paths.sites_file();
    let text = toml::to_string_pretty(&SitesFile {
        sites: sites.to_vec(),
    })
    .map_err(|e| e.to_string())?;
    fs::create_dir_all(&paths.config_dir)
        .and_then(|()| fs::write(&file, text))
        .map_err(|e| format!("saving {}: {e}", file.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sites_round_trip() {
        let dir = std::env::temp_dir().join(format!("rustzilla-cfg-{}", std::process::id()));
        let paths = Paths {
            config_dir: dir.clone(),
            data_dir: dir.clone(),
        };
        assert!(load_sites(&paths).unwrap().is_empty());
        let sites = vec![
            Site {
                name: "web".into(),
                host: "example.com".into(),
                user: "deploy".into(),
                logon: Logon::KeyFile,
                key_file: "~/.ssh/id_ecdsa_sk".into(),
                ..Site::default()
            },
            Site::default(),
        ];
        save_sites(&paths, &sites).unwrap();
        assert_eq!(load_sites(&paths).unwrap(), sites);
        let _ = fs::remove_dir_all(dir);
    }
}
