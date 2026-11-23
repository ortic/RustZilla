//! Sites from elsewhere: FileZilla's Site Manager (`sitemanager.xml`) and
//! OpenSSH's `~/.ssh/config`.

use std::path::{Path, PathBuf};

use rustzilla_remote::{FtpEncryption, Protocol};

use crate::config::{Logon, Site, new_id};

/// A site to add, with its password if the file had one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Imported {
    pub site: Site,
    pub password: Option<String>,
    /// OpenSSH's `ProxyJump`, as written.
    pub jump: Option<String>,
}

/// What an import found.
#[derive(Debug, Default)]
pub struct Found {
    pub sites: Vec<Imported>,
    /// Why entries weren't taken: one line each.
    pub skipped: Vec<String>,
}

/// Where FileZilla keeps its sites on this system.
pub fn filezilla_file() -> Option<PathBuf> {
    let candidates = [
        std::env::var_os("APPDATA").map(|d| PathBuf::from(d).join("FileZilla")),
        directories::BaseDirs::new().map(|d| d.config_dir().join("filezilla")),
        directories::BaseDirs::new().map(|d| d.home_dir().join(".config/filezilla")),
        directories::BaseDirs::new().map(|d| d.home_dir().join(".filezilla")),
    ];
    candidates
        .into_iter()
        .flatten()
        .map(|dir| dir.join("sitemanager.xml"))
        .find(|f| f.is_file())
}

pub fn ssh_config_file() -> Option<PathBuf> {
    directories::BaseDirs::new()
        .map(|d| d.home_dir().join(".ssh/config"))
        .filter(|f| f.is_file())
}

pub fn read_filezilla(file: &Path) -> Result<Found, String> {
    let text =
        std::fs::read_to_string(file).map_err(|e| format!("reading {}: {e}", file.display()))?;
    filezilla(&text).map_err(|e| format!("reading {}: {e}", file.display()))
}

/// The sites of a `sitemanager.xml`; those in folders are named
/// `Folder / Site`.
pub fn filezilla(xml: &str) -> Result<Found, String> {
    let doc = roxmltree::Document::parse(xml).map_err(|e| e.to_string())?;
    let servers = doc
        .descendants()
        .find(|n| n.has_tag_name("Servers"))
        .ok_or("there are no sites in it")?;
    let mut found = Found::default();
    walk(servers, "", &mut found);
    Ok(found)
}

fn walk(node: roxmltree::Node, prefix: &str, found: &mut Found) {
    for child in node.children().filter(|n| n.is_element()) {
        if child.has_tag_name("Folder") {
            // The folder's name is its own text, before the sites in it.
            let name = child
                .children()
                .filter(|n| n.is_text())
                .filter_map(|n| n.text())
                .map(str::trim)
                .find(|t| !t.is_empty())
                .unwrap_or("Folder");
            walk(child, &format!("{prefix}{name} / "), found);
        } else if child.has_tag_name("Server") {
            match server(child, prefix) {
                Ok(imported) => found.sites.push(imported),
                Err(why) => found.skipped.push(why),
            }
        }
    }
}

fn server(node: roxmltree::Node, prefix: &str) -> Result<Imported, String> {
    let field = |name: &str| {
        node.children()
            .find(|n| n.has_tag_name(name))
            .and_then(|n| n.text())
            .unwrap_or("")
            .trim()
            .to_owned()
    };
    let name = format!("{prefix}{}", field("Name"));
    let host = field("Host");
    if host.is_empty() {
        return Err(format!("{name}: no host"));
    }
    // FileZilla's protocol numbers.
    let (protocol, encryption) = match field("Protocol").as_str() {
        "" | "0" => (Protocol::Ftp, FtpEncryption::ExplicitIfAvailable),
        "1" => (Protocol::Sftp, FtpEncryption::ExplicitIfAvailable),
        "3" => (Protocol::Ftp, FtpEncryption::Implicit),
        "4" => (Protocol::Ftp, FtpEncryption::Explicit),
        "6" => (Protocol::Ftp, FtpEncryption::Plain),
        "7" => (Protocol::S3, FtpEncryption::Explicit),
        other => {
            return Err(format!(
                "{name}: FileZilla's protocol {other} isn't supported"
            ));
        }
    };
    let logon = match field("Logontype").as_str() {
        "0" => Logon::Anonymous,
        "2" | "3" => Logon::AskPassword,
        "5" if protocol == Protocol::Sftp => Logon::KeyFile,
        _ => Logon::Normal,
    };
    let pass = node.children().find(|n| n.has_tag_name("Pass"));
    let password = pass.and_then(|p| match p.attribute("encoding") {
        Some("base64") => {
            let bytes = base64_decode(p.text().unwrap_or("").trim())?;
            String::from_utf8(bytes).ok()
        }
        // Encrypted with FileZilla's master password: not readable here.
        Some(_) => None,
        None => p.text().map(str::to_owned),
    });
    let port = field("Port")
        .parse()
        .unwrap_or(protocol.default_port(encryption));
    Ok(Imported {
        site: Site {
            id: new_id(),
            name: if name.trim_end_matches(" / ").is_empty() {
                host.clone()
            } else {
                name
            },
            protocol,
            encryption,
            host,
            port,
            user: field("User"),
            logon,
            key_file: field("Keyfile"),
            remote_dir: remote_dir(&field("RemoteDir")),
            local_dir: field("LocalDir"),
            ..Site::default()
        },
        password: password.filter(|p| !p.is_empty() && logon == Logon::Normal),
        jump: None,
    })
}

/// FileZilla's remote paths: `1 0 4 home 4 remo` is `/home/remo` (the
/// server type, a prefix, then each segment after its length).
fn remote_dir(text: &str) -> String {
    let mut rest = text;
    let number = |rest: &mut &str| -> Option<usize> {
        let s = rest.trim_start_matches(' ');
        let end = s.find(' ').unwrap_or(s.len());
        let n = s[..end].parse().ok()?;
        *rest = &s[end..];
        Some(n)
    };
    let take = |rest: &mut &str, len: usize| -> Option<String> {
        let s = rest.strip_prefix(' ')?;
        let end = s.char_indices().nth(len).map_or(s.len(), |(i, _)| i);
        let segment = s[..end].to_owned();
        *rest = &s[end..];
        Some(segment)
    };
    let Some(_kind) = number(&mut rest) else {
        return String::new();
    };
    let Some(prefix_len) = number(&mut rest) else {
        return String::new();
    };
    let mut path = String::new();
    if prefix_len > 0 {
        match take(&mut rest, prefix_len) {
            Some(prefix) => path.push_str(&prefix),
            None => return String::new(),
        }
    }
    let mut segments = Vec::new();
    while !rest.trim().is_empty() {
        let Some(len) = number(&mut rest) else { break };
        let Some(segment) = take(&mut rest, len) else {
            break;
        };
        segments.push(segment);
    }
    if segments.is_empty() && path.is_empty() {
        return String::new();
    }
    format!("{path}/{}", segments.join("/"))
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let value = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let clean: Vec<u8> = text.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    let mut out = Vec::new();
    for chunk in clean.chunks(4) {
        let chunk: Vec<u8> = chunk.iter().copied().filter(|&c| c != b'=').collect();
        let mut n = 0u32;
        for &c in &chunk {
            n = n << 6 | value(c)?;
        }
        n <<= 6 * (4 - chunk.len() as u32);
        let bytes = n.to_be_bytes();
        out.extend_from_slice(&bytes[1..chunk.len().max(1)]);
    }
    Some(out)
}

pub fn read_ssh_config(file: &Path) -> Result<Found, String> {
    let text =
        std::fs::read_to_string(file).map_err(|e| format!("reading {}: {e}", file.display()))?;
    Ok(ssh_config(&text))
}

/// The hosts of an OpenSSH client configuration, as SFTP sites. Patterns
/// (`*`, `?`, `!`) and `Match` blocks aren't sites; `Host *` settings
/// aren't applied to the others.
pub fn ssh_config(text: &str) -> Found {
    #[derive(Default)]
    struct Block {
        aliases: Vec<String>,
        hostname: Option<String>,
        user: Option<String>,
        port: Option<u16>,
        identity: Option<String>,
        jump: Option<String>,
    }
    let mut blocks: Vec<Block> = Vec::new();
    let mut found = Found::default();
    let mut in_match = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = match line.find(|c: char| c == '=' || c.is_whitespace()) {
            Some(i) => (
                &line[..i],
                line[i..].trim_start_matches(|c: char| c == '=' || c.is_whitespace()),
            ),
            None => (line, ""),
        };
        let value = value.trim().trim_matches('"').to_owned();
        match key.to_ascii_lowercase().as_str() {
            "host" => {
                in_match = false;
                blocks.push(Block {
                    aliases: value.split_whitespace().map(str::to_owned).collect(),
                    ..Block::default()
                });
            }
            "match" => in_match = true,
            "include" => found
                .skipped
                .push(format!("Include {value}: included files aren't read")),
            _ if in_match => {}
            key => {
                let Some(block) = blocks.last_mut() else {
                    continue;
                };
                // The first value counts, as in OpenSSH.
                match key {
                    "hostname" => {
                        block.hostname.get_or_insert(value);
                    }
                    "user" => {
                        block.user.get_or_insert(value);
                    }
                    "port" => {
                        if block.port.is_none() {
                            block.port = value.parse().ok();
                        }
                    }
                    "identityfile" => {
                        block.identity.get_or_insert(value);
                    }
                    "proxyjump" => {
                        block.jump.get_or_insert(value);
                    }
                    _ => {}
                }
            }
        }
    }
    for block in blocks {
        for alias in &block.aliases {
            if alias.contains(['*', '?', '!']) {
                continue;
            }
            let host = block
                .hostname
                .clone()
                .map(|h| h.replace("%h", alias))
                .unwrap_or_else(|| alias.clone());
            let (logon, key_file) = match &block.identity {
                Some(file) => (Logon::KeyFile, file.clone()),
                None => (Logon::Agent, String::new()),
            };
            found.sites.push(Imported {
                site: Site {
                    id: new_id(),
                    name: alias.clone(),
                    protocol: Protocol::Sftp,
                    host,
                    port: block.port.unwrap_or(22),
                    user: block.user.clone().unwrap_or_default(),
                    logon,
                    key_file,
                    ..Site::default()
                },
                password: None,
                jump: block
                    .jump
                    .clone()
                    .filter(|j| !j.eq_ignore_ascii_case("none")),
            });
        }
    }
    found
}

/// Whether `site` is there already: the same server and user.
pub fn known(sites: &[Site], site: &Site) -> bool {
    sites.iter().any(|s| {
        s.protocol == site.protocol
            && s.host.eq_ignore_ascii_case(&site.host)
            && s.port == site.port
            && s.user == site.user
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filezilla_sites() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<FileZilla3 version="3.66.0" platform="*nix">
  <Servers>
    <Server>
      <Host>example.com</Host><Port>2222</Port><Protocol>1</Protocol>
      <Type>0</Type><User>deploy</User><Logontype>5</Logontype>
      <Keyfile>/home/me/.ssh/id_ed25519</Keyfile>
      <Name>Web</Name><RemoteDir>1 0 3 var 3 www</RemoteDir><LocalDir>/home/me/site</LocalDir>
    </Server>
    <Folder expanded="1">Clients
      <Server>
        <Host>ftp.example.org</Host><Port>21</Port><Protocol>4</Protocol>
        <User>bob</User><Pass encoding="base64">czNjcmV0IQ==</Pass><Logontype>1</Logontype>
        <Name>Bob's shop</Name>
      </Server>
      <Server>
        <Host>vault.example.org</Host><Protocol>0</Protocol><User>x</User>
        <Pass encoding="crypt">abc</Pass><Logontype>1</Logontype><Name>Locked</Name>
      </Server>
      <Server><Host>gdrive</Host><Protocol>14</Protocol><Name>Drive</Name></Server>
    </Folder>
  </Servers>
</FileZilla3>"#;
        let found = filezilla(xml).unwrap();
        assert_eq!(found.sites.len(), 3);
        let web = &found.sites[0].site;
        assert_eq!(
            (web.name.as_str(), web.host.as_str(), web.port, web.protocol),
            ("Web", "example.com", 2222, Protocol::Sftp)
        );
        assert_eq!(
            (web.logon, web.key_file.as_str()),
            (Logon::KeyFile, "/home/me/.ssh/id_ed25519")
        );
        assert_eq!(web.remote_dir, "/var/www");
        assert_eq!(web.local_dir, "/home/me/site");
        let bob = &found.sites[1];
        assert_eq!(bob.site.name, "Clients / Bob's shop");
        assert_eq!(
            (bob.site.protocol, bob.site.encryption),
            (Protocol::Ftp, FtpEncryption::Explicit)
        );
        assert_eq!(bob.password.as_deref(), Some("s3cret!"));
        // An encrypted password can't be read: the site comes without.
        assert_eq!(found.sites[2].password, None);
        assert_eq!(found.skipped.len(), 1);
        assert!(found.skipped[0].contains("Drive"));
    }

    #[test]
    fn filezilla_remote_dirs() {
        assert_eq!(remote_dir("1 0 4 home 4 remo"), "/home/remo");
        assert_eq!(remote_dir("1 0 7 my docs"), "/my docs");
        assert_eq!(remote_dir("1 0"), "");
        assert_eq!(remote_dir(""), "");
    }

    #[test]
    fn base64() {
        assert_eq!(base64_decode("czNjcmV0IQ==").unwrap(), b"s3cret!");
        assert_eq!(base64_decode("YQ==").unwrap(), b"a");
        assert_eq!(base64_decode("YWI=").unwrap(), b"ab");
        assert_eq!(base64_decode("YWJj").unwrap(), b"abc");
    }

    #[test]
    fn ssh_config_hosts() {
        let config = "
# comment
Host web prod-web
    HostName 203.0.113.7
    User deploy
    Port 2222
    IdentityFile ~/.ssh/id_ed25519_sk
    ProxyJump bastion.example.com

Host bastion.example.com
  User=jump

Host *.internal *
    User nobody

Match host foo
    User matched
Include ~/.ssh/config.d/*
";
        let found = ssh_config(config);
        let names: Vec<&str> = found.sites.iter().map(|s| s.site.name.as_str()).collect();
        assert_eq!(names, ["web", "prod-web", "bastion.example.com"]);
        let web = &found.sites[0];
        assert_eq!(
            (
                web.site.host.as_str(),
                web.site.port,
                web.site.user.as_str()
            ),
            ("203.0.113.7", 2222, "deploy")
        );
        assert_eq!(web.site.logon, Logon::KeyFile);
        assert_eq!(web.jump.as_deref(), Some("bastion.example.com"));
        let bastion = &found.sites[2];
        assert_eq!(
            (bastion.site.host.as_str(), bastion.site.user.as_str()),
            ("bastion.example.com", "jump")
        );
        assert_eq!(bastion.site.logon, Logon::Agent);
        assert_eq!(found.skipped.len(), 1);
        assert!(known(std::slice::from_ref(&web.site), &found.sites[1].site));
    }
}
