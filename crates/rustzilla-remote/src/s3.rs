//! Amazon S3 and compatible object stores (MinIO, Cloudflare R2, Wasabi,
//! Backblaze B2, DigitalOcean Spaces…), signed with AWS Signature V4 on
//! ring. Paths are `/bucket/key`: the root lists the buckets, `/` in keys
//! makes the folders.
//!
//! Addressing is virtual-hosted (`bucket.host/key`) on AWS
//! (`*.amazonaws.com`) for DNS-compatible bucket names, path-style
//! (`host/bucket/key`) everywhere else: other stores, IP addresses, and
//! dotted bucket names over TLS (AWS's wildcard certificate doesn't cover
//! them).
//!
//! Files up to 16 MiB go up in one PUT; bigger ones in a multipart upload
//! of 16 MiB parts (more when that would be over 10,000 parts), up to S3's
//! 5 TiB. A cancelled multipart upload, or one whose connection dropped,
//! stays on the server: [`Session::stat`] shows the key with the size of
//! its finished parts, and an upload with an offset (resume) carries on
//! with them. Other failures abort it; an upload from the start aborts the
//! key's unfinished ones.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use ring::digest::{SHA256, digest};
use ring::hmac;
use ureq::http::{Request, Response};
use ureq::{Agent, Body, SendBody};

use crate::aws;
use crate::error::{Error, ErrorKind};
use crate::http;
use crate::path;
use crate::remote::{Security, Server, Session};
use crate::sftp::{EntryKind, Progress, RemoteEntry};
use crate::util;
use crate::webdav::Counting;

const CHUNK: usize = 256 * 1024;
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const MIB: u64 = 1024 * 1024;
/// The parts of multipart uploads, at least; files up to this go up whole.
const PART_SIZE: u64 = 16 * MIB;
const MAX_PARTS: u64 = 10_000;
/// The biggest object S3 takes.
const MAX_OBJECT: u64 = 5 * 1024 * 1024 * MIB;

/// For the tests: the part size instead of 16 MiB (0: 16 MiB). S3 wants
/// at least 5 MiB but for the last part.
pub(crate) static TEST_PART_SIZE: AtomicU64 = AtomicU64::new(0);

fn base_part_size() -> u64 {
    match TEST_PART_SIZE.load(Ordering::Relaxed) {
        0 => PART_SIZE,
        n => n,
    }
}

/// The part size for an object of `size` bytes: `base`, or as many whole
/// MiB as keep it within 10,000 parts.
fn part_size(size: u64, base: u64) -> u64 {
    base.max(size.div_ceil(MAX_PARTS).div_ceil(MIB) * MIB)
}

/// Where the object store is and the keys to sign with.
#[derive(Clone, Default)]
pub struct S3Params {
    /// The endpoint, e.g. `s3.amazonaws.com`, `s3.eu-central-1.wasabisys.com`.
    pub host: String,
    pub port: u16,
    pub tls: bool,
    /// e.g. `eu-central-1`; the profile's, or `us-east-1`, if empty.
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    /// The token of temporary credentials (`X-Amz-Security-Token`).
    pub session_token: Option<String>,
    /// An AWS profile (`~/.aws/credentials`, `~/.aws/config`; `env` for
    /// the `AWS_*` environment variables) to take the keys, the token and
    /// the region from, instead of the fields above.
    pub profile: Option<String>,
}

impl fmt::Debug for S3Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Params")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tls", &self.tls)
            .field("region", &self.region)
            .field("access_key", &self.access_key)
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

/// What requests are signed with.
struct Keys {
    access_key: String,
    secret_key: String,
    session_token: Option<String>,
}

struct S3 {
    agent: Agent,
    /// `http` or `https`.
    scheme: &'static str,
    /// The endpoint's host name, without the port.
    host: String,
    /// `:port`, unless it is the default one.
    port: String,
    name: String,
    tls: bool,
    region: String,
    keys: Keys,
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
        let (keys, profile_region) = match &params.profile {
            Some(profile) => {
                let found = aws::load(profile)?;
                (
                    Keys {
                        access_key: found.access_key,
                        secret_key: found.secret_key,
                        session_token: found.session_token,
                    },
                    found.region,
                )
            }
            None => (
                Keys {
                    access_key: params.access_key.trim().to_owned(),
                    secret_key: params.secret_key.clone(),
                    session_token: params.session_token.clone(),
                },
                None,
            ),
        };
        let keys = Keys {
            session_token: keys
                .session_token
                .map(|t| t.trim().to_owned())
                .filter(|t| !t.is_empty()),
            ..keys
        };
        if keys.access_key.is_empty() {
            return Err(Error::new(
                "enter the access key ID as the user and the secret key as the password",
            ));
        }
        let default_port = if params.tls { 443 } else { 80 };
        let port = match params.port {
            0 => default_port,
            port => port,
        };
        let port = if port == default_port {
            String::new()
        } else {
            format!(":{port}")
        };
        let region = match params.region.trim() {
            "" => profile_region
                .map(|r| r.trim().to_owned())
                .filter(|r| !r.is_empty())
                .unwrap_or_else(|| "us-east-1".to_owned()),
            r => r.to_owned(),
        };
        let s3 = S3 {
            agent: http::agent(),
            scheme: if params.tls { "https" } else { "http" },
            name: format!("s3://{host}{port}"),
            host: host.to_owned(),
            port,
            tls: params.tls,
            region,
            keys,
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

/// Whether `bucket` is addressed as `bucket.host`: on AWS, if the name is
/// DNS-compatible (and has no dots over TLS, which AWS's wildcard
/// certificate doesn't cover).
fn virtual_host(host: &str, bucket: &str, tls: bool) -> bool {
    let host = host.to_ascii_lowercase();
    let aws = host.ends_with(".amazonaws.com") || host.ends_with(".amazonaws.com.cn");
    let bytes = bucket.as_bytes();
    let dns = (3..=63).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.'))
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && !bucket.contains("..")
        && !bucket.contains(".-")
        && !bucket.contains("-.")
        && bucket.parse::<std::net::Ipv4Addr>().is_err();
    aws && dns && !(tls && bucket.contains('.'))
}

/// The Host header and the path of a request for the path-style `uri`
/// (`/bucket/key`, encoded).
fn address(host: &str, port: &str, tls: bool, uri: &str) -> (String, String) {
    let bucket = uri
        .strip_prefix('/')
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("");
    if !bucket.is_empty() && virtual_host(host, bucket, tls) {
        let rest = &uri[1 + bucket.len()..];
        let path = if rest.is_empty() { "/" } else { rest };
        (format!("{bucket}.{host}{port}"), path.to_owned())
    } else {
        (format!("{host}{port}"), uri.to_owned())
    }
}

/// The canonical query string: encoded and sorted.
fn canonical_query(query: &[(&str, String)]) -> String {
    let mut query: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (util::encode_component(k), util::encode_component(v)))
        .collect();
    query.sort();
    query
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// The `Authorization` header of a request (Signature V4): `signed` are
/// the headers to sign (lower-case names: `host`, `x-amz-*`), `query` the
/// canonical query string, `amz_date` as `20130524T000000Z`.
#[allow(clippy::too_many_arguments)]
fn authorization(
    keys: &Keys,
    region: &str,
    method: &str,
    path: &str,
    query: &str,
    mut signed: Vec<(String, String)>,
    payload_hash: &str,
    amz_date: &str,
) -> String {
    let date = &amz_date[..8];
    signed.sort();
    let canonical_headers: String = signed.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers = signed
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical =
        format!("{method}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
    let scope = format!("{date}/{region}/s3/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical.as_bytes())
    );
    let mut key = hmac_sha256(
        format!("AWS4{}", keys.secret_key).as_bytes(),
        date.as_bytes(),
    );
    for part in [region, "s3", "aws4_request"] {
        key = hmac_sha256(&key, part.as_bytes());
    }
    let signature = util::hex(&hmac_sha256(&key, to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, \
         Signature={signature}",
        keys.access_key
    )
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
        let (amz_date, _) = util::amz_date(util::secs(SystemTime::now()));
        let query_text = canonical_query(query);
        let (authority, path) = address(&self.host, &self.port, self.tls, uri);
        let url = if query_text.is_empty() {
            format!("{}://{authority}{path}", self.scheme)
        } else {
            format!("{}://{authority}{path}?{query_text}", self.scheme)
        };
        let mut signed: Vec<(String, String)> = vec![
            ("host".into(), authority),
            ("x-amz-content-sha256".into(), payload_hash.to_owned()),
            ("x-amz-date".into(), amz_date.clone()),
        ];
        if let Some(token) = &self.keys.session_token {
            signed.push(("x-amz-security-token".into(), token.clone()));
        }
        for (name, value) in headers {
            let name = name.to_ascii_lowercase();
            if name.starts_with("x-amz-") {
                signed.push((name, value.trim().to_owned()));
            }
        }
        let authorization = authorization(
            &self.keys,
            region,
            method,
            &path,
            &query_text,
            signed,
            payload_hash,
            &amz_date,
        );
        let mut builder = Request::builder()
            .method(method)
            .uri(url)
            .header("Authorization", authorization)
            .header("x-amz-date", amz_date)
            .header("x-amz-content-sha256", payload_hash);
        if let Some(token) = &self.keys.session_token {
            builder = builder.header("x-amz-security-token", token);
        }
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

    /// The unfinished multipart uploads of `key`, oldest first; none if
    /// the store can't list them.
    fn uploads(&self, bucket: &str, key: &str) -> Vec<String> {
        let query = [("uploads", String::new()), ("prefix", key.to_owned())];
        let listed = self
            .s3
            .request(
                "GET",
                &S3::uri(bucket, ""),
                &query,
                &[],
                EMPTY_SHA256,
                SendBody::none(),
            )
            .and_then(|mut response| {
                if response.status().is_success() {
                    S3::text(response, "listing the uploads")
                } else {
                    Err(S3::fail("listing the uploads of", key, &mut response))
                }
            });
        let xml = match listed {
            Ok(xml) => xml,
            Err(e) => {
                tracing::debug!("{}: {e}", self.s3.name);
                return Vec::new();
            }
        };
        let Ok(doc) = roxmltree::Document::parse(&xml) else {
            return Vec::new();
        };
        let mut uploads: Vec<(&str, &str)> = doc
            .descendants()
            .filter(|n| n.tag_name().name() == "Upload")
            .filter(|n| child(*n, "Key") == Some(key))
            .filter_map(|n| Some((child(n, "Initiated").unwrap_or(""), child(n, "UploadId")?)))
            .collect();
        // ISO 8601 times sort as text.
        uploads.sort();
        uploads.into_iter().map(|(_, id)| id.to_owned()).collect()
    }

    /// The parts of an unfinished upload: (number, size, ETag), by number.
    fn parts(&self, bucket: &str, key: &str, id: &str) -> Result<Vec<(u64, u64, String)>, Error> {
        let mut parts = Vec::new();
        let mut marker: Option<String> = None;
        loop {
            let mut query = vec![("uploadId", id.to_owned())];
            if let Some(marker) = &marker {
                query.push(("part-number-marker", marker.clone()));
            }
            let mut response = self.s3.request(
                "GET",
                &S3::uri(bucket, key),
                &query,
                &[],
                EMPTY_SHA256,
                SendBody::none(),
            )?;
            if !response.status().is_success() {
                return Err(S3::fail("listing the parts of", key, &mut response));
            }
            let xml = S3::text(response, "listing the parts")?;
            let doc = roxmltree::Document::parse(&xml)
                .map_err(|e| Error::new(format!("listing the parts of {key}: {e}")))?;
            for part in doc.descendants().filter(|n| n.tag_name().name() == "Part") {
                let number = child(part, "PartNumber").and_then(|n| n.parse().ok());
                let size = child(part, "Size").and_then(|n| n.parse().ok());
                if let (Some(number), Some(size), Some(etag)) = (number, size, child(part, "ETag"))
                {
                    parts.push((number, size, etag.to_owned()));
                }
            }
            let truncated = doc
                .descendants()
                .find(|n| n.tag_name().name() == "IsTruncated")
                .and_then(|n| n.text())
                == Some("true");
            marker = doc
                .descendants()
                .find(|n| n.tag_name().name() == "NextPartNumberMarker")
                .and_then(|n| n.text())
                .map(str::to_owned);
            if !truncated || marker.is_none() {
                break;
            }
        }
        parts.sort_by_key(|p| p.0);
        Ok(parts)
    }

    /// How much of `key` its newest unfinished upload holds: its parts
    /// from the first on, as long as they are the first one's size (a
    /// shorter last part may be the end, or cut short).
    fn partial_size(&self, bucket: &str, key: &str) -> Option<u64> {
        let id = self.uploads(bucket, key).pop()?;
        let parts = self.parts(bucket, key, &id).ok()?;
        let first = parts.first().filter(|p| p.0 == 1)?.1;
        let size: u64 = parts
            .iter()
            .zip(1..)
            .take_while(|((number, size, _), n)| number == n && *size == first)
            .map(|((_, size, _), _)| size)
            .sum();
        (size > 0).then_some(size)
    }

    fn abort(&self, bucket: &str, key: &str, id: &str) {
        let result = self.s3.request(
            "DELETE",
            &S3::uri(bucket, key),
            &[("uploadId", id.to_owned())],
            &[],
            EMPTY_SHA256,
            SendBody::none(),
        );
        match result {
            Ok(response) if response.status().is_success() => {}
            Ok(mut response) => tracing::debug!(
                "{}: aborting the upload of {key}: {}",
                self.s3.name,
                http::error_text(&mut response)
            ),
            Err(e) => tracing::debug!("{}: aborting the upload of {key}: {e}", self.s3.name),
        }
    }

    /// A file of up to 5 GiB, in one PUT.
    fn put(
        &mut self,
        file: fs::File,
        size: u64,
        remote: &str,
        bucket: &str,
        key: &str,
        progress: Progress,
    ) -> Result<u64, Error> {
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

    /// A file in parts: the parts of an unfinished upload of `key` are
    /// taken up again if `resume`.
    #[allow(clippy::too_many_arguments)]
    fn put_parts(
        &mut self,
        mut file: fs::File,
        size: u64,
        remote: &str,
        bucket: &str,
        key: &str,
        resume: bool,
        progress: Progress,
    ) -> Result<u64, Error> {
        if size > MAX_OBJECT {
            return Err(Error::new(format!(
                "writing {remote}: S3 objects can't be bigger than 5 TiB"
            )));
        }
        let part = part_size(size, base_part_size());
        let count = size.div_ceil(part);
        let length = |number: u64| part.min(size - (number - 1) * part);
        let mut unfinished = self.uploads(bucket, key);
        let mut etags: Vec<String> = Vec::new();
        let resumed = if resume { unfinished.pop() } else { None };
        let id = match resumed {
            Some(id) => {
                // The parts from the first on that are as this file's.
                let parts = self.parts(bucket, key, &id)?;
                for ((number, part_size, etag), n) in parts.into_iter().zip(1..) {
                    if number != n || n > count || part_size != length(n) {
                        break;
                    }
                    etags.push(etag);
                }
                id
            }
            None => self.create_upload(bucket, key, remote)?,
        };
        // Older ones of the same key would never finish.
        for stale in unfinished {
            self.abort(bucket, key, &stale);
        }
        let result = self.send_parts(
            &mut file, size, part, &id, &mut etags, remote, bucket, key, progress,
        );
        match result {
            Ok(done) => Ok(done),
            // Kept to resume.
            Err(e) if matches!(e.kind, ErrorKind::Cancelled | ErrorKind::Disconnected) => Err(e),
            Err(e) => {
                self.abort(bucket, key, &id);
                Err(e)
            }
        }
    }

    fn create_upload(&self, bucket: &str, key: &str, remote: &str) -> Result<String, Error> {
        let mut response = self.s3.request(
            "POST",
            &S3::uri(bucket, key),
            &[("uploads", String::new())],
            &[("Content-Length", "0".to_owned())],
            EMPTY_SHA256,
            SendBody::none(),
        )?;
        if !response.status().is_success() {
            return Err(S3::fail("writing", remote, &mut response));
        }
        let xml = S3::text(response, "starting the upload")?;
        roxmltree::Document::parse(&xml)
            .ok()
            .and_then(|doc| {
                doc.descendants()
                    .find(|n| n.tag_name().name() == "UploadId")
                    .and_then(|n| n.text())
                    .map(str::to_owned)
            })
            .ok_or_else(|| Error::new(format!("writing {remote}: the store gave no upload ID")))
    }

    /// The parts after those in `etags`, then the upload completed.
    #[allow(clippy::too_many_arguments)]
    fn send_parts(
        &self,
        file: &mut fs::File,
        size: u64,
        part: u64,
        id: &str,
        etags: &mut Vec<String>,
        remote: &str,
        bucket: &str,
        key: &str,
        progress: Progress,
    ) -> Result<u64, Error> {
        let uri = S3::uri(bucket, key);
        let local_error = |e: io::Error| Error::new(format!("reading the file for {remote}: {e}"));
        let mut done = etags.len() as u64 * part;
        if !progress(done) {
            return Err(Error::cancelled());
        }
        while done < size {
            let number = etags.len() as u64 + 1;
            let length = part.min(size - done);
            // Once more if the connection dropped: the part can be read
            // again.
            let mut attempt = 0;
            let mut response = loop {
                attempt += 1;
                file.seek(SeekFrom::Start(done)).map_err(local_error)?;
                let mut part_progress = |n: u64| progress(done + n);
                let mut reader = Counting::new((&mut *file).take(length), &mut part_progress);
                let result = self.s3.request(
                    "PUT",
                    &uri,
                    &[
                        ("partNumber", number.to_string()),
                        ("uploadId", id.to_owned()),
                    ],
                    &[("Content-Length", length.to_string())],
                    "UNSIGNED-PAYLOAD",
                    SendBody::from_reader(&mut reader),
                );
                if reader.cancelled {
                    return Err(Error::cancelled());
                }
                match result {
                    Err(e) if e.kind == ErrorKind::Disconnected && attempt < 2 => {
                        tracing::debug!("{}: {e}; sending part {number} again", self.s3.name);
                    }
                    result => break result?,
                }
            };
            if !response.status().is_success() {
                return Err(S3::fail("writing", remote, &mut response));
            }
            let etag = response
                .headers()
                .get("ETag")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
                .ok_or_else(|| {
                    Error::new(format!(
                        "writing {remote}: the store gave no ETag for part {number}"
                    ))
                })?;
            etags.push(etag);
            done += length;
        }
        let escape = |text: &str| {
            text.replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
        };
        let parts: String = etags
            .iter()
            .zip(1..)
            .map(|(etag, n)| {
                format!(
                    "<Part><PartNumber>{n}</PartNumber><ETag>{}</ETag></Part>",
                    escape(etag)
                )
            })
            .collect();
        let body = format!(
            "<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             {parts}</CompleteMultipartUpload>"
        );
        let mut response = self.s3.request(
            "POST",
            &uri,
            &[("uploadId", id.to_owned())],
            &[("Content-Length", body.len().to_string())],
            &sha256_hex(body.as_bytes()),
            SendBody::from_reader(&mut body.as_bytes()),
        )?;
        if !response.status().is_success() {
            return Err(S3::fail("writing", remote, &mut response));
        }
        // A 200 can still carry an error.
        let xml = S3::text(response, "completing the upload")?;
        if let Ok(doc) = roxmltree::Document::parse(&xml)
            && doc.root_element().tag_name().name() == "Error"
        {
            let message = child(doc.root_element(), "Message").unwrap_or("the upload failed");
            return Err(Error::new(format!("writing {remote}: {message}")));
        }
        Ok(done)
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
                if !inside.is_empty() || marker.status().is_success() {
                    return Ok(Some(dir_entry(&name, None)));
                }
                // An unfinished multipart upload: a file as big as its
                // parts, to resume. No time: it isn't newer than anything.
                Ok(self.partial_size(bucket, key).map(|size| RemoteEntry {
                    name,
                    kind: EntryKind::File,
                    symlink: false,
                    size,
                    modified: None,
                    permissions: None,
                    owner: String::new(),
                    group: String::new(),
                }))
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

    /// Files up to the part size go up whole, whatever `offset`; bigger
    /// ones in parts, after those of the unfinished upload if `offset` (a
    /// resume).
    fn upload(
        &mut self,
        local: &Path,
        remote: &str,
        offset: u64,
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
        if size <= base_part_size() {
            self.put(file, size, remote, bucket, key, progress)
        } else {
            self.put_parts(file, size, remote, bucket, key, offset > 0, progress)
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

    #[test]
    fn addressing() {
        let aws = "s3.amazonaws.com";
        assert!(virtual_host(aws, "my-bucket", true));
        assert!(virtual_host("s3.eu-central-1.amazonaws.com", "abc", false));
        assert!(virtual_host("S3.AMAZONAWS.COM", "logs.example", false));
        // Dots over TLS, names DNS can't have, other stores, addresses.
        assert!(!virtual_host(aws, "logs.example", true));
        assert!(!virtual_host(aws, "My_Bucket", false));
        assert!(!virtual_host(aws, "ab", false));
        assert!(!virtual_host(aws, "-bucket", false));
        assert!(!virtual_host(aws, "a..b", false));
        assert!(!virtual_host(aws, "192.168.1.1", false));
        assert!(!virtual_host("play.min.io", "bucket", true));
        assert!(!virtual_host("127.0.0.1", "bucket", false));

        assert_eq!(
            address(aws, "", true, "/my-bucket/a%20b/c.txt"),
            ("my-bucket.s3.amazonaws.com".into(), "/a%20b/c.txt".into())
        );
        assert_eq!(
            address(aws, "", true, "/my-bucket"),
            ("my-bucket.s3.amazonaws.com".into(), "/".into())
        );
        assert_eq!(
            address(aws, "", true, "/my-bucket/folder/"),
            ("my-bucket.s3.amazonaws.com".into(), "/folder/".into())
        );
        assert_eq!(address(aws, "", true, "/"), (aws.into(), "/".into()));
        assert_eq!(
            address(aws, "", true, "/dotted.name/k"),
            (aws.into(), "/dotted.name/k".into())
        );
        assert_eq!(
            address("127.0.0.1", ":9000", false, "/bucket/k"),
            ("127.0.0.1:9000".into(), "/bucket/k".into())
        );
    }

    fn example_keys(session_token: Option<&str>) -> Keys {
        Keys {
            access_key: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: session_token.map(str::to_owned),
        }
    }

    /// AWS's example "GET Bucket (List Objects)" of the S3 Signature V4
    /// docs, which is virtual-hosted.
    #[test]
    fn signature() {
        let (host, path) = address("s3.amazonaws.com", "", true, "/examplebucket");
        let query = canonical_query(&[("max-keys", "2".into()), ("prefix", "J".into())]);
        assert_eq!(query, "max-keys=2&prefix=J");
        let headers = |extra: Option<&str>| {
            let mut headers = vec![
                ("host".to_owned(), host.clone()),
                ("x-amz-content-sha256".to_owned(), EMPTY_SHA256.to_owned()),
                ("x-amz-date".to_owned(), "20130524T000000Z".to_owned()),
            ];
            if let Some(token) = extra {
                headers.push(("x-amz-security-token".into(), token.into()));
            }
            headers
        };
        let auth = authorization(
            &example_keys(None),
            "us-east-1",
            "GET",
            &path,
            &query,
            headers(None),
            EMPTY_SHA256,
            "20130524T000000Z",
        );
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
             Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
        );
        // A session token is signed too.
        let auth = authorization(
            &example_keys(Some("TOKEN")),
            "us-east-1",
            "GET",
            &path,
            &query,
            headers(Some("TOKEN")),
            EMPTY_SHA256,
            "20130524T000000Z",
        );
        assert!(
            auth.contains(
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token,"
            ),
            "{auth}"
        );
        assert!(
            !auth.ends_with("34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7")
        );
    }

    #[test]
    fn part_sizes() {
        assert_eq!(part_size(100 * MIB, PART_SIZE), PART_SIZE);
        assert_eq!(part_size(MAX_PARTS * PART_SIZE, PART_SIZE), PART_SIZE);
        // Over 10,000 parts of 16 MiB: bigger ones, in whole MiB.
        let size = MAX_PARTS * PART_SIZE + 1;
        assert_eq!(part_size(size, PART_SIZE), 17 * MIB);
        let biggest = part_size(MAX_OBJECT, PART_SIZE);
        assert_eq!(biggest % MIB, 0);
        assert!(MAX_OBJECT.div_ceil(biggest) <= MAX_PARTS);
        assert!(biggest <= 5 * 1024 * MIB);
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
