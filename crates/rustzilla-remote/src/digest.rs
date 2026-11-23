//! HTTP Digest authentication (RFC 7616): MD5 and SHA-256, their `-sess`
//! variants, `qop=auth` (or none, as RFC 2069 servers do). WebDAV servers
//! that refuse Basic over plain HTTP ask for it.

use ring::rand::{SecureRandom, SystemRandom};

use crate::util;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Algorithm {
    Md5,
    Md5Sess,
    Sha256,
    Sha256Sess,
}

impl Algorithm {
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name.to_ascii_uppercase().as_str() {
            "MD5" => Self::Md5,
            "MD5-SESS" => Self::Md5Sess,
            "SHA-256" => Self::Sha256,
            "SHA-256-SESS" => Self::Sha256Sess,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Md5Sess => "MD5-sess",
            Self::Sha256 => "SHA-256",
            Self::Sha256Sess => "SHA-256-sess",
        }
    }

    fn sess(self) -> bool {
        matches!(self, Self::Md5Sess | Self::Sha256Sess)
    }

    /// The hash of `data`, in lowercase hex.
    fn hash(self, data: &str) -> String {
        match self {
            Self::Md5 | Self::Md5Sess => {
                use md5::Digest;
                util::hex(&md5::Md5::digest(data.as_bytes()))
            }
            Self::Sha256 | Self::Sha256Sess => {
                util::hex(ring::digest::digest(&ring::digest::SHA256, data.as_bytes()).as_ref())
            }
        }
    }

    /// The stronger, the better.
    fn rank(self) -> u8 {
        match self {
            Self::Sha256 | Self::Sha256Sess => 2,
            Self::Md5 | Self::Md5Sess => 1,
        }
    }
}

/// A `Digest` challenge of a `WWW-Authenticate` header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Challenge {
    pub realm: String,
    pub nonce: String,
    pub opaque: Option<String>,
    pub algorithm: Algorithm,
    /// `qop=auth` offered; RFC 2069 style otherwise.
    pub qop: bool,
    /// The nonce ran out, the password was fine.
    pub stale: bool,
    /// The user name goes hashed.
    pub userhash: bool,
}

impl Challenge {
    /// The challenge of the parameters of a `Digest` scheme, if this can
    /// answer it.
    fn from_params(params: &[(String, String)]) -> Option<Self> {
        let get = |name: &str| {
            params
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        };
        let algorithm = match get("algorithm") {
            None => Algorithm::Md5,
            Some(name) => Algorithm::parse(name)?,
        };
        let qop = match get("qop") {
            None => false,
            Some(qops) => {
                if !qops
                    .split(',')
                    .any(|q| q.trim().eq_ignore_ascii_case("auth"))
                {
                    // auth-int only: not for streamed bodies.
                    return None;
                }
                true
            }
        };
        let yes = |name: &str| get(name).is_some_and(|v| v.eq_ignore_ascii_case("true"));
        Some(Self {
            realm: get("realm").unwrap_or_default().to_owned(),
            nonce: get("nonce")?.to_owned(),
            opaque: get("opaque").map(str::to_owned),
            algorithm,
            qop,
            stale: yes("stale"),
            userhash: yes("userhash"),
        })
    }

    /// The `response` to a request with nonce count `nc`.
    pub fn response(
        &self,
        username: &str,
        password: &str,
        method: &str,
        uri: &str,
        nc: u32,
        cnonce: &str,
    ) -> String {
        let h = |data: String| self.algorithm.hash(&data);
        let mut ha1 = h(format!("{username}:{}:{password}", self.realm));
        if self.algorithm.sess() {
            ha1 = h(format!("{ha1}:{}:{cnonce}", self.nonce));
        }
        let ha2 = h(format!("{method}:{uri}"));
        if self.qop {
            h(format!("{ha1}:{}:{nc:08x}:{cnonce}:auth:{ha2}", self.nonce))
        } else {
            h(format!("{ha1}:{}:{ha2}", self.nonce))
        }
    }

    /// The user name as it is sent.
    pub fn username(&self, username: &str) -> String {
        if self.userhash {
            self.algorithm.hash(&format!("{username}:{}", self.realm))
        } else {
            username.to_owned()
        }
    }

    /// The `Authorization` header of a request.
    pub fn authorization(
        &self,
        username: &str,
        password: &str,
        method: &str,
        uri: &str,
        nc: u32,
        cnonce: &str,
    ) -> String {
        let response = self.response(username, password, method, uri, nc, cnonce);
        let mut out = format!(
            "Digest username={}, realm={}, uri={}, algorithm={}, nonce={}",
            quote(&self.username(username)),
            quote(&self.realm),
            quote(uri),
            self.algorithm.name(),
            quote(&self.nonce),
        );
        if self.qop {
            out.push_str(&format!(
                ", nc={nc:08x}, cnonce={}, qop=auth",
                quote(cnonce)
            ));
        }
        out.push_str(&format!(", response={}", quote(&response)));
        if let Some(opaque) = &self.opaque {
            out.push_str(&format!(", opaque={}", quote(opaque)));
        }
        if self.userhash {
            out.push_str(", userhash=true");
        }
        out
    }
}

/// What the `WWW-Authenticate` headers offer.
#[derive(Debug, Default)]
pub(crate) struct Offer {
    /// The strongest Digest challenge this can answer.
    pub digest: Option<Challenge>,
    pub basic: bool,
}

pub(crate) fn offer<'a>(headers: impl IntoIterator<Item = &'a str>) -> Offer {
    let mut out = Offer::default();
    for (scheme, params) in headers.into_iter().flat_map(parse) {
        if scheme.eq_ignore_ascii_case("basic") {
            out.basic = true;
        } else if scheme.eq_ignore_ascii_case("digest")
            && let Some(challenge) = Challenge::from_params(&params)
            && out
                .digest
                .as_ref()
                .is_none_or(|d| d.algorithm.rank() < challenge.algorithm.rank())
        {
            out.digest = Some(challenge);
        }
    }
    out
}

/// The schemes of a `WWW-Authenticate` (or `Authorization`) header with
/// their parameters: `Digest realm="x", nonce="y", Basic realm="z"`.
pub(crate) fn parse(header: &str) -> Vec<(String, Vec<(String, String)>)> {
    let bytes = header.as_bytes();
    let mut out: Vec<(String, Vec<(String, String)>)> = Vec::new();
    let mut i = 0;
    let skip_space = |i: &mut usize| {
        while *i < bytes.len() && bytes[*i].is_ascii_whitespace() {
            *i += 1;
        }
    };
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b',') {
            i += 1;
        }
        let start = i;
        while i < bytes.len() && !matches!(bytes[i], b' ' | b'\t' | b',' | b'=') {
            i += 1;
        }
        let token = &header[start..i];
        skip_space(&mut i);
        if token.is_empty() {
            // A stray `=`.
            i += 1;
            continue;
        }
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            skip_space(&mut i);
            let value = if i < bytes.len() && bytes[i] == b'"' {
                i += 1;
                let mut value = Vec::new();
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        i += 1;
                    }
                    value.push(bytes[i]);
                    i += 1;
                }
                i += 1;
                String::from_utf8_lossy(&value).into_owned()
            } else {
                let start = i;
                while i < bytes.len() && !matches!(bytes[i], b' ' | b'\t' | b',') {
                    i += 1;
                }
                header[start..i].to_owned()
            };
            if let Some((_, params)) = out.last_mut() {
                params.push((token.to_owned(), value));
            }
        } else {
            out.push((token.to_owned(), Vec::new()));
        }
    }
    out
}

fn quote(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

/// A fresh client (or server) nonce.
pub(crate) fn nonce() -> String {
    let mut bytes = [0; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .expect("the system's random numbers");
    util::hex(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7616, 3.9.1.
    const CHALLENGES: [&str; 2] = [
        r#"Digest realm="http-auth@example.org", qop="auth, auth-int", algorithm=SHA-256, nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS""#,
        r#"Digest realm="http-auth@example.org", qop="auth, auth-int", algorithm=MD5, nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS""#,
    ];
    const CNONCE: &str = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ";

    #[test]
    fn md5_of_rfc_1321() {
        assert_eq!(Algorithm::Md5.hash(""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(
            Algorithm::Md5.hash("abc"),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            Algorithm::Md5.hash(
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            ),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }

    #[test]
    fn rfc_7616_example() {
        let offered = offer(CHALLENGES);
        assert!(!offered.basic);
        let sha = offered.digest.unwrap();
        assert_eq!(sha.algorithm, Algorithm::Sha256);
        assert!(sha.qop && !sha.stale);
        assert_eq!(sha.realm, "http-auth@example.org");
        assert_eq!(
            sha.opaque.as_deref(),
            Some("FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS")
        );
        let response = |c: &Challenge| {
            c.response(
                "Mufasa",
                "Circle of Life",
                "GET",
                "/dir/index.html",
                1,
                CNONCE,
            )
        };
        assert_eq!(
            response(&sha),
            "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1"
        );
        let md5 = offer([CHALLENGES[1]]).digest.unwrap();
        assert_eq!(response(&md5), "8ca523f5e9506fed4657c9700eebdbec");
        assert_eq!(
            md5.authorization(
                "Mufasa",
                "Circle of Life",
                "GET",
                "/dir/index.html",
                1,
                CNONCE
            ),
            "Digest username=\"Mufasa\", realm=\"http-auth@example.org\", \
             uri=\"/dir/index.html\", algorithm=MD5, \
             nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", nc=00000001, \
             cnonce=\"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ\", qop=auth, \
             response=\"8ca523f5e9506fed4657c9700eebdbec\", \
             opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\""
        );
    }

    /// RFC 2617, 3.5.
    #[test]
    fn rfc_2617_example() {
        let challenge = offer([
            r#"Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41""#,
        ])
        .digest
        .unwrap();
        assert_eq!(challenge.algorithm, Algorithm::Md5);
        assert_eq!(
            challenge.response(
                "Mufasa",
                "Circle Of Life",
                "GET",
                "/dir/index.html",
                1,
                "0a4f113b"
            ),
            "6629fae49393a05397450978507c4ef1"
        );
    }

    #[test]
    fn headers() {
        let offered = offer([
            r#"Basic realm="x", Digest realm="a\"b", nonce=abc, stale=TRUE, algorithm=MD5-sess"#,
            r#"Digest realm="y", nonce="n", qop="auth-int""#,
            r#"Negotiate, Digest realm="z", nonce="n", algorithm=SHA-512-256"#,
        ]);
        assert!(offered.basic);
        let digest = offered.digest.unwrap();
        assert_eq!(
            (digest.realm.as_str(), digest.nonce.as_str()),
            ("a\"b", "abc")
        );
        assert_eq!(digest.algorithm, Algorithm::Md5Sess);
        assert!(digest.stale && !digest.qop);
        assert_eq!(
            parse(r#"Digest username="u", nc=00000002"#),
            [(
                "Digest".to_owned(),
                vec![
                    ("username".to_owned(), "u".to_owned()),
                    ("nc".to_owned(), "00000002".to_owned())
                ]
            )]
        );
        assert!(offer(["Basic realm=\"x\""]).digest.is_none());
    }
}
