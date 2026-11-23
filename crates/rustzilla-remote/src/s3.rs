//! Amazon S3 and compatible object stores (MinIO, Cloudflare R2, Wasabi,
//! Backblaze B2, DigitalOcean Spaces…), signed with AWS Signature V4 on
//! ring. Paths are `/bucket/key`: the root lists the buckets, `/` in keys
//! makes the folders. Addressing is path-style (`host/bucket/key`), which
//! every endpoint takes.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use ring::digest::{SHA256, digest};
use ring::hmac;
use ureq::http::{Request, Response};
use ureq::{Agent, Body, SendBody};

use crate::error::Error;
use crate::http;
use crate::path;
use crate::remote::{Security, Server, Session};
use crate::sftp::{EntryKind, Progress, RemoteEntry};
use crate::util;
use crate::webdav::Counting;

const CHUNK: usize = 256 * 1024;
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Where the object store is and the keys to sign with.
#[derive(Clone)]
pub struct S3Params {
    /// The endpoint, e.g. `s3.amazonaws.com`, `s3.eu-central-1.wasabisys.com`.
    pub host: String,
    pub port: u16,
    pub tls: bool,
    /// e.g. `eu-central-1`; `us-east-1` if empty.
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
}

impl fmt::Debug for S3Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Params")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tls", &self.tls)
            .field("region", &self.region)
            .field("access_key", &self.access_key)
            .finish_non_exhaustive()
    }
}

struct S3 {
    agent: Agent,
    base: String,
    /// What the Host header says (signed).
    authority: String,
    name: String,
    tls: bool,
    region: String,
    access_key: String,
    secret_key: String,
    /// Buckets in other regions than `region`, as the store said.
    regions: Mutex<HashMap<String, String>>,
    closed: AtomicBool,
}

pub struct S3Server {
    s3: Arc<S3>,
}

impl S3Server {
    /// Lists the buckets, to check the keys.
    pub fn open(params: &S3Params) -> Result<Self, Error> {
        let host = params.host.trim();
        if host.is_empty() {
            return Err(Error::new("enter the S3 endpoint, e.g. s3.amazonaws.com"));
        }
        if params.access_key.trim().is_empty() {
            return Err(Error::new(
                "enter the access key ID as the user and the secret key as the password",
            ));
        }
        let default_port = if params.tls { 443 } else { 80 };
        let port = if params.port == 0 {
            default_port
        } else {
            params.port
        };
        let authority = if port == default_port {
            host.to_owned()
        } else {
            format!("{host}:{port}")
        };
        let s3 = S3 {
            agent: http::agent(),
            base: format!(
                "{}://{authority}",
                if params.tls { "https" } else { "http" }
            ),
            name: format!("s3://{authority}"),
            authority,
            tls: params.tls,
            region: match params.region.trim() {
                "" => "us-east-1".to_owned(),
                r => r.to_owned(),
            },
            access_key: params.access_key.trim().to_owned(),
            secret_key: params.secret_key.clone(),
            regions: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
        };
        let mut response = s3.request("GET", "/", &[], &[], EMPTY_SHA256, SendBody::none())?;
        match response.status().as_u16() {
            200..=299 => {}
            403 => {
                return Err(Error::new(format!(
                    "{} didn't accept the keys: {}",
                    s3.name,
                    http::error_text(&mut response)
                )));
            }
            _ => {
                return Err(Error::new(format!(
                    "{}: {}",
                    s3.name,
                    http::error_text(&mut response)
                )));
            }
        }
        Ok(Self { s3: Arc::new(s3) })
    }
}

impl Server for S3Server {
    fn name(&self) -> &str {
        &self.s3.name
    }

    fn security(&self) -> Security {
        if self.s3.tls {
            Security::Tls
        } else {
            Security::Plain
        }
    }

    fn open(&self) -> Result<Box<dyn Session>, Error> {
        Ok(Box::new(S3Session {
            s3: self.s3.clone(),
        }))
    }

    fn is_closed(&self) -> bool {
        self.s3.closed.load(Ordering::SeqCst)
    }

    fn disconnect(&self) {
        self.s3.closed.store(true, Ordering::SeqCst);
    }
}

fn sha256_hex(data: &[u8]) -> String {
    util::hex(digest(&SHA256, data).as_ref())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data)
        .as_ref()
        .to_vec()
}

/// `/bucket/key` as (bucket, key); the root has no bucket.
fn split(path: &str) -> (Option<&str>, &str) {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return (None, "");
    }
    match trimmed.split_once('/') {
        Some((bucket, key)) => (Some(bucket), key.trim_end_matches('/')),
        None => (Some(trimmed), ""),
    }
}

impl S3 {
    fn region_of(&self, bucket: Option<&str>) -> String {
        bucket
            .and_then(|b| self.regions.lock().expect("regions").get(b).cloned())
            .unwrap_or_else(|| self.region.clone())
    }

    /// Signs and sends a request; once more in the bucket's own region if
    /// the store says it is elsewhere, or if the connection dropped and
    /// there is no body.
    fn request(
        &self,
        method: &str,
        uri: &str,
        query: &[(&str, String)],
        headers: &[(&str, String)],
        payload_hash: &str,
        body: SendBody<'_>,
    ) -> Result<Response<Body>, Error> {
        let bucket = split(&util::decode(uri)).0.map(str::to_owned);
        let region = self.region_of(bucket.as_deref());
        // A body that is a reader can't be sent twice: only bodiless
        // requests are retried in another region.
        let response =
            match self.signed(method, uri, query, headers, payload_hash, body, &region)? {
                Ok(response) => response,
                // A request without a body can be signed and sent again.
                Err(e) if payload_hash == EMPTY_SHA256 && http::dropped(&e) => {
                    tracing::debug!("{}: {e}; sending the request again", self.name);
                    self.signed(
                        method,
                        uri,
                        query,
                        headers,
                        payload_hash,
                        SendBody::none(),
                        &region,
                    )?
                    .map_err(|e| http::network_error(&self.name, &e))?
                }
                Err(e) => return Err(http::network_error(&self.name, &e)),
            };
        let elsewhere = response
            .headers()
            .get("x-amz-bucket-region")
            .and_then(|v| v.to_str().ok())
            .filter(|r| *r != region)
            .map(str::to_owned);
        match (response.status().as_u16(), elsewhere, bucket) {
            (301 | 400, Some(other), Some(bucket)) if payload_hash == EMPTY_SHA256 => {
                self.regions
                    .lock()
                    .expect("regions")
                    .insert(bucket, other.clone());
                self.signed(
                    method,
                    uri,
                    query,
                    headers,
                    payload_hash,
                    SendBody::none(),
                    &other,
                )?
                .map_err(|e| http::network_error(&self.name, &e))
            }
            _ => Ok(response),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn signed(
        &self,
        method: &str,
        uri: &str,
        query: &[(&str, String)],
        headers: &[(&str, String)],
        payload_hash: &str,
        body: SendBody<'_>,
        region: &str,
    ) -> Result<Result<Response<Body>, ureq::Error>, Error> {
        let (amz_date, date) = util::amz_date(util::secs(SystemTime::now()));
        let mut query: Vec<(String, String)> = query
            .iter()
            .map(|(k, v)| (util::encode_component(k), util::encode_component(v)))
            .collect();
        query.sort();
        let query_text = query
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        let mut signed: Vec<(String, String)> = vec![
            ("host".into(), self.authority.clone()),
            ("x-amz-content-sha256".into(), payload_hash.to_owned()),
            ("x-amz-date".into(), amz_date.clone()),
        ];
        for (name, value) in headers {
            let name = name.to_ascii_lowercase();
            if name.starts_with("x-amz-") {
                signed.push((name, value.trim().to_owned()));
            }
        }
        signed.sort();
        let canonical_headers: String = signed.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
        let signed_headers = signed
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>()
            .join(";");
        let canonical = format!(
            "{method}\n{uri}\n{query_text}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        );
        let scope = format!("{date}/{region}/s3/aws4_request");
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            sha256_hex(canonical.as_bytes())
        );
        let mut key = hmac_sha256(
            format!("AWS4{}", self.secret_key).as_bytes(),
            date.as_bytes(),
        );
        for part in [region, "s3", "aws4_request"] {
            key = hmac_sha256(&key, part.as_bytes());
        }
        let signature = util::hex(&hmac_sha256(&key, to_sign.as_bytes()));
        let url = if query_text.is_empty() {
            format!("{}{uri}", self.base)
        } else {
            format!("{}{uri}?{query_text}", self.base)
        };
        let mut builder = Request::builder()
            .method(method)
            .uri(url)
            .header(
                "Authorization",
                format!(
                    "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, \
                     Signature={signature}",
                    self.access_key
                ),
            )
            .header("x-amz-date", amz_date)
            .header("x-amz-content-sha256", payload_hash);
        for (name, value) in headers {
            builder = builder.header(*name, value);
        }
        let request = builder
            .body(body)
            .map_err(|e| Error::new(format!("{}: {e}", self.name)))?;
        // The network's errors go to the caller, which may send again.
        Ok(self.agent.run(request))
    }

    /// `/bucket/key` as a signed URI path.
    fn uri(bucket: &str, key: &str) -> String {
        if key.is_empty() {
            format!("/{}", util::encode_path(bucket))
        } else {
            format!("/{}/{}", util::encode_path(bucket), util::encode_path(key))
        }
    }

    fn fail(what: &str, path: &str, response: &mut Response<Body>) -> Error {
        Error::new(format!("{what} {path}: {}", http::error_text(response)))
    }

    fn text(response: Response<Body>, what: &str) -> Result<String, Error> {
        response
            .into_body()
            .into_with_config()
            .limit(64 * 1024 * 1024)
            .read_to_string()
            .map_err(|e| Error::new(format!("{what}: {e}")))
    }
}

fn child<'a>(node: roxmltree::Node<'a, 'a>, name: &str) -> Option<&'a str> {
    node.children()
        .find(|n| n.tag_name().name() == name)
        .and_then(|n| n.text())
}

fn dir_entry(name: &str, modified: Option<SystemTime>) -> RemoteEntry {
    RemoteEntry {
        name: name.to_owned(),
        kind: EntryKind::Dir,
        symlink: false,
        size: 0,
        modified,
        permissions: None,
        owner: String::new(),
        group: String::new(),
    }
}

pub struct S3Session {
    s3: Arc<S3>,
}

impl S3Session {
    fn list_buckets(&mut self) -> Result<Vec<RemoteEntry>, Error> {
        let mut response = self
            .s3
            .request("GET", "/", &[], &[], EMPTY_SHA256, SendBody::none())?;
        if !response.status().is_success() {
            return Err(S3::fail("listing", "the buckets", &mut response));
        }
        let xml = S3::text(response, "listing the buckets")?;
        let doc = roxmltree::Document::parse(&xml)
            .map_err(|e| Error::new(format!("listing the buckets: {e}")))?;
        Ok(doc
            .descendants()
            .filter(|n| n.tag_name().name() == "Bucket")
            .filter_map(|b| {
                let name = child(b, "Name")?;
                Some(dir_entry(
                    name,
                    child(b, "CreationDate").and_then(util::parse_iso8601),
                ))
            })
            .collect())
    }

    /// The objects and folders under `prefix` (with its slash), at most
    /// `max` (0: all).
    fn list_prefix(
        &mut self,
        bucket: &str,
        prefix: &str,
        max: usize,
    ) -> Result<Vec<RemoteEntry>, Error> {
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        let uri = S3::uri(bucket, "");
        loop {
            let mut query = vec![
                ("list-type", "2".to_owned()),
                ("delimiter", "/".to_owned()),
                ("prefix", prefix.to_owned()),
            ];
            if max > 0 {
                query.push(("max-keys", max.to_string()));
            }
            if let Some(token) = &token {
                query.push(("continuation-token", token.clone()));
            }
            let mut response =
                self.s3
                    .request("GET", &uri, &query, &[], EMPTY_SHA256, SendBody::none())?;
            if !response.status().is_success() {
                return Err(S3::fail(
                    "listing",
                    &format!("/{bucket}/{prefix}"),
                    &mut response,
                ));
            }
            let xml = S3::text(response, "listing")?;
            let doc = roxmltree::Document::parse(&xml)
                .map_err(|e| Error::new(format!("listing {bucket}: {e}")))?;
            for node in doc.root_element().children() {
                match node.tag_name().name() {
                    "CommonPrefixes" => {
                        if let Some(p) = child(node, "Prefix") {
                            let name = p[prefix.len().min(p.len())..].trim_end_matches('/');
                            if !name.is_empty() {
                                out.push(dir_entry(name, None));
                            }
                        }
                    }
                    "Contents" => {
                        let Some(key) = child(node, "Key") else {
                            continue;
                        };
                        let name = &key[prefix.len().min(key.len())..];
                        // The folder's own marker object.
                        if name.is_empty() || name.ends_with('/') {
                            continue;
                        }
                        out.push(RemoteEntry {
                            name: name.to_owned(),
                            kind: EntryKind::File,
                            symlink: false,
                            size: child(node, "Size")
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(0),
                            modified: child(node, "LastModified").and_then(util::parse_iso8601),
                            permissions: None,
                            owner: String::new(),
                            group: String::new(),
                        });
                    }
                    _ => {}
                }
            }
            let truncated = doc
                .descendants()
                .find(|n| n.tag_name().name() == "IsTruncated")
                .and_then(|n| n.text())
                == Some("true");
            token = doc
                .descendants()
                .find(|n| n.tag_name().name() == "NextContinuationToken")
                .and_then(|n| n.text())
                .map(str::to_owned);
            if !truncated || token.is_none() || (max > 0 && out.len() >= max) {
                return Ok(out);
            }
        }
    }

    fn simple(&mut self, method: &str, uri: &str, what: &str, path: &str) -> Result<(), Error> {
        let mut response =
            self.s3
                .request(method, uri, &[], &[], EMPTY_SHA256, SendBody::none())?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(S3::fail(what, path, &mut response))
        }
    }
}

impl Session for S3Session {
    fn canonicalize(&mut self, path: &str) -> Result<String, Error> {
        let path = path.trim();
        if path.is_empty() || path == "." {
            return Ok("/".into());
        }
        let mut parts: Vec<&str> = Vec::new();
        for part in path.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                p => parts.push(p),
            }
        }
        Ok(format!("/{}", parts.join("/")))
    }

    fn list(&mut self, dir: &str) -> Result<Vec<RemoteEntry>, Error> {
        match split(dir) {
            (None, _) => self.list_buckets(),
            (Some(bucket), key) => {
                let prefix = if key.is_empty() {
                    String::new()
                } else {
                    format!("{key}/")
                };
                let entries = self.list_prefix(bucket, &prefix, 0)?;
                // Folders are prefixes: an empty one without its marker
                // object isn't there.
                if entries.is_empty() && !prefix.is_empty() {
                    let marker = self.s3.request(
                        "HEAD",
                        &S3::uri(bucket, &prefix),
                        &[],
                        &[],
                        EMPTY_SHA256,
                        SendBody::none(),
                    )?;
                    if !marker.status().is_success() {
                        return Err(Error::new(format!("listing {dir}: no such directory")));
                    }
                }
                Ok(entries)
            }
        }
    }

    fn stat(&mut self, path: &str) -> Result<Option<RemoteEntry>, Error> {
        let name = path::file_name(path).to_owned();
        match split(path) {
            (None, _) => Ok(Some(dir_entry("/", None))),
            (Some(bucket), "") => {
                let response = self.s3.request(
                    "HEAD",
                    &S3::uri(bucket, ""),
                    &[],
                    &[],
                    EMPTY_SHA256,
                    SendBody::none(),
                )?;
                Ok(response
                    .status()
                    .is_success()
                    .then(|| dir_entry(&name, None)))
            }
            (Some(bucket), key) => {
                let response = self.s3.request(
                    "HEAD",
                    &S3::uri(bucket, key),
                    &[],
                    &[],
                    EMPTY_SHA256,
                    SendBody::none(),
                )?;
                if response.status().is_success() {
                    let header = |h: &str| {
                        response
                            .headers()
                            .get(h)
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned)
                    };
                    return Ok(Some(RemoteEntry {
                        name,
                        kind: EntryKind::File,
                        symlink: false,
                        size: header("Content-Length")
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(0),
                        modified: header("Last-Modified").and_then(|t| util::parse_http_date(&t)),
                        permissions: None,
                        owner: String::new(),
                        group: String::new(),
                    }));
                }
                // A folder exists while something is in it.
                let inside = self.list_prefix(bucket, &format!("{key}/"), 1)?;
                let marker = self.s3.request(
                    "HEAD",
                    &S3::uri(bucket, &format!("{key}/")),
                    &[],
                    &[],
                    EMPTY_SHA256,
                    SendBody::none(),
                )?;
                Ok((!inside.is_empty() || marker.status().is_success())
                    .then(|| dir_entry(&name, None)))
            }
        }
    }

    fn mkdir(&mut self, path: &str) -> Result<(), Error> {
        match split(path) {
            (None, _) => Err(Error::new("the root holds the buckets")),
            (Some(bucket), "") => {
                let body = if self.s3.region == "us-east-1" {
                    String::new()
                } else {
                    format!(
                        "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                         <LocationConstraint>{}</LocationConstraint></CreateBucketConfiguration>",
                        self.s3.region
                    )
                };
                let mut response = self.s3.request(
                    "PUT",
                    &S3::uri(bucket, ""),
                    &[],
                    &[("Content-Length", body.len().to_string())],
                    &sha256_hex(body.as_bytes()),
                    SendBody::from_reader(&mut body.as_bytes()),
                )?;
                if response.status().is_success() {
                    Ok(())
                } else {
                    Err(S3::fail("creating the bucket", path, &mut response))
                }
            }
            (Some(bucket), key) => {
                // A folder is an empty object named with its slash.
                let mut response = self.s3.request(
                    "PUT",
                    &S3::uri(bucket, &format!("{key}/")),
                    &[],
                    &[("Content-Length", "0".to_owned())],
                    EMPTY_SHA256,
                    SendBody::none(),
                )?;
                if response.status().is_success() {
                    Ok(())
                } else {
                    Err(S3::fail("creating the directory", path, &mut response))
                }
            }
        }
    }

    fn remove_file(&mut self, path: &str) -> Result<(), Error> {
        let (Some(bucket), key) = split(path) else {
            return Err(Error::new("the root can't be deleted"));
        };
        self.simple("DELETE", &S3::uri(bucket, key), "deleting", path)
    }

    fn remove_dir(&mut self, path: &str) -> Result<(), Error> {
        match split(path) {
            (None, _) => Err(Error::new("the root can't be deleted")),
            (Some(bucket), "") => {
                self.simple("DELETE", &S3::uri(bucket, ""), "deleting the bucket", path)
            }
            // Deleting a missing marker succeeds: a folder without one is
            // gone with its last object.
            (Some(bucket), key) => self.simple(
                "DELETE",
                &S3::uri(bucket, &format!("{key}/")),
                "deleting the directory",
                path,
            ),
        }
    }

    fn rename(&mut self, from: &str, to: &str) -> Result<(), Error> {
        let (Some(bucket), key) = split(from) else {
            return Err(Error::new("the root can't be renamed"));
        };
        let (Some(to_bucket), to_key) = split(to) else {
            return Err(Error::new("objects go into buckets"));
        };
        if key.is_empty() || to_key.is_empty() {
            return Err(Error::new("S3 can't rename buckets"));
        }
        if self.stat(from)?.is_some_and(|e| e.is_dir()) {
            return Err(Error::new(format!(
                "renaming {from}: S3 can't rename folders, only objects"
            )));
        }
        // A copy, then the original deleted.
        let source = format!("/{bucket}/{}", util::encode_path(key));
        let mut response = self.s3.request(
            "PUT",
            &S3::uri(to_bucket, to_key),
            &[],
            &[("x-amz-copy-source", source)],
            EMPTY_SHA256,
            SendBody::none(),
        )?;
        if !response.status().is_success() {
            return Err(S3::fail("renaming", from, &mut response));
        }
        self.remove_file(from)
    }

    fn chmod(&mut self, path: &str, _mode: u32) -> Result<(), Error> {
        Err(Error::new(format!(
            "changing the permissions of {path}: S3 objects have no Unix permissions"
        )))
    }

    fn download(
        &mut self,
        remote: &str,
        local: &Path,
        offset: u64,
        progress: Progress,
    ) -> Result<u64, Error> {
        let (Some(bucket), key) = split(remote) else {
            return Err(Error::new("the root is no file"));
        };
        let local_error =
            |what: &str, e: io::Error| Error::new(format!("{what} {}: {e}", local.display()));
        let mut headers = Vec::new();
        if offset > 0 {
            headers.push(("Range", format!("bytes={offset}-")));
        }
        let mut response = self.s3.request(
            "GET",
            &S3::uri(bucket, key),
            &[],
            &headers,
            EMPTY_SHA256,
            SendBody::none(),
        )?;
        let status = response.status().as_u16();
        if status == 416 {
            return Ok(offset);
        }
        if !(200..300).contains(&status) {
            return Err(S3::fail("opening", remote, &mut response));
        }
        let offset = if status == 206 { offset } else { 0 };
        let modified = response
            .headers()
            .get("Last-Modified")
            .and_then(|v| v.to_str().ok())
            .and_then(util::parse_http_date);
        let mut out = if offset > 0 {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .open(local)
                .map_err(|e| local_error("opening", e))?;
            file.set_len(offset)
                .and_then(|()| file.seek(SeekFrom::Start(offset)))
                .map_err(|e| local_error("resuming", e))?;
            file
        } else {
            fs::File::create(local).map_err(|e| local_error("creating", e))?
        };
        let mut reader = response.into_body().into_reader();
        let mut buffer = vec![0; CHUNK];
        let mut done = offset;
        loop {
            let n = reader
                .read(&mut buffer)
                .map_err(|e| Error::new(format!("reading {remote}: {e}")))?;
            if n == 0 {
                break;
            }
            out.write_all(&buffer[..n])
                .map_err(|e| local_error("writing", e))?;
            done += n as u64;
            if !progress(done) {
                return Err(Error::cancelled());
            }
        }
        out.flush().map_err(|e| local_error("writing", e))?;
        if let Some(time) = modified {
            let _ = out.set_modified(time);
        }
        Ok(done)
    }

    /// Objects go up whole (a single PUT, up to 5 GiB), whatever `offset`.
    fn upload(
        &mut self,
        local: &Path,
        remote: &str,
        _offset: u64,
        progress: Progress,
    ) -> Result<u64, Error> {
        let (Some(bucket), key) = split(remote) else {
            return Err(Error::new("files go into buckets"));
        };
        if key.is_empty() {
            return Err(Error::new("files go into buckets, not beside them"));
        }
        let file = fs::File::open(local)
            .map_err(|e| Error::new(format!("opening {}: {e}", local.display())))?;
        let size = file
            .metadata()
            .map_err(|e| Error::new(format!("reading {}: {e}", local.display())))?
            .len();
        let mut reader = Counting::new(file, progress);
        let result = self.s3.request(
            "PUT",
            &S3::uri(bucket, key),
            &[],
            &[("Content-Length", size.to_string())],
            "UNSIGNED-PAYLOAD",
            SendBody::from_reader(&mut reader),
        );
        if reader.cancelled {
            return Err(Error::cancelled());
        }
        let mut response = result?;
        if response.status().is_success() {
            Ok(reader.done)
        } else {
            Err(S3::fail("writing", remote, &mut response))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(split("/"), (None, ""));
        assert_eq!(split("/b"), (Some("b"), ""));
        assert_eq!(split("/b/"), (Some("b"), ""));
        assert_eq!(split("/b/a/c.txt"), (Some("b"), "a/c.txt"));
        assert_eq!(S3::uri("b", "a b/c"), "/b/a%20b/c");
    }

    /// AWS's own example of a signing key (Signature V4 docs).
    #[test]
    fn signing_key() {
        let mut key = hmac_sha256(b"AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", b"20120215");
        for part in ["us-east-1", "iam", "aws4_request"] {
            key = hmac_sha256(&key, part.as_bytes());
        }
        assert_eq!(
            util::hex(&key),
            "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
        );
    }
}
