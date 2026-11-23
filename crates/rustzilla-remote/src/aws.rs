//! S3 keys from AWS's shared files, as the AWS CLI and SDKs keep them:
//! `~/.aws/credentials` (`[name]` sections) and `~/.aws/config`
//! (`[profile name]`, and `[default]`), or the files that
//! `AWS_SHARED_CREDENTIALS_FILE` and `AWS_CONFIG_FILE` name. A profile
//! gives `aws_access_key_id`, `aws_secret_access_key`, optionally
//! `aws_session_token` and `region`; keys in the credentials file come
//! before those in the config file.
//!
//! The profile [`ENV_PROFILE`] (`env`) is the environment instead:
//! `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` and
//! `AWS_REGION` (or `AWS_DEFAULT_REGION`). An empty profile name is
//! `AWS_PROFILE`, or `default`.
//!
//! Profiles that get their keys elsewhere (`role_arn`, SSO,
//! `credential_process`) aren't supported.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use crate::error::Error;

/// The profile that means the `AWS_*` environment variables.
pub const ENV_PROFILE: &str = "env";

/// What a profile says.
#[derive(Clone, PartialEq, Eq)]
pub struct AwsCredentials {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
    pub region: Option<String>,
}

impl std::fmt::Debug for AwsCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsCredentials")
            .field("access_key", &self.access_key)
            .field("region", &self.region)
            .finish_non_exhaustive()
    }
}

/// The sections of an INI file and their settings. Sections that come
/// twice are merged; `#` and `;` start comment lines; the indented lines
/// under a setting without a value (`s3 =` and its sub-settings) are
/// skipped.
pub(crate) fn parse_ini(text: &str) -> HashMap<String, HashMap<String, String>> {
    let mut sections: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut current: Option<String> = None;
    let mut nested = false;
    for line in text.lines() {
        let indented = line.starts_with([' ', '\t']);
        let line = line.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if indented && nested {
            continue;
        }
        nested = false;
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            let name = name.split_whitespace().collect::<Vec<_>>().join(" ");
            sections.entry(name.clone()).or_default();
            current = Some(name);
            continue;
        }
        let (Some(section), Some((key, value))) = (&current, line.split_once('=')) else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        if value.is_empty() {
            nested = true;
            continue;
        }
        sections
            .entry(section.clone())
            .or_default()
            .insert(key.to_owned(), value.to_owned());
    }
    sections
}

/// The keys of `profile`, from the files or the environment.
pub fn load(profile: &str) -> Result<AwsCredentials, Error> {
    let env = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
    let file = |variable: &str, default: &str| -> Option<PathBuf> {
        match env(variable) {
            Some(path) => Some(expand_home(path.trim())),
            None => std::env::home_dir().map(|home| home.join(".aws").join(default)),
        }
    };
    let read = |path: Option<PathBuf>| path.and_then(|p| fs::read_to_string(p).ok());
    let credentials = read(file("AWS_SHARED_CREDENTIALS_FILE", "credentials"));
    let config = read(file("AWS_CONFIG_FILE", "config"));
    resolve(profile, &env, credentials.as_deref(), config.as_deref())
}

fn expand_home(path: &str) -> PathBuf {
    match (path.strip_prefix("~/"), std::env::home_dir()) {
        (Some(rest), Some(home)) => home.join(rest),
        _ => PathBuf::from(path),
    }
}

/// The keys of `profile`: from `env` for [`ENV_PROFILE`], else from the
/// credentials and config files' texts.
pub(crate) fn resolve(
    profile: &str,
    env: &dyn Fn(&str) -> Option<String>,
    credentials: Option<&str>,
    config: Option<&str>,
) -> Result<AwsCredentials, Error> {
    let profile = match profile.trim() {
        "" => env("AWS_PROFILE").unwrap_or_else(|| "default".into()),
        name => name.to_owned(),
    };
    if profile == ENV_PROFILE {
        let (Some(access_key), Some(secret_key)) =
            (env("AWS_ACCESS_KEY_ID"), env("AWS_SECRET_ACCESS_KEY"))
        else {
            return Err(Error::new(
                "the profile `env` takes the keys from AWS_ACCESS_KEY_ID and \
                 AWS_SECRET_ACCESS_KEY, which aren't set",
            ));
        };
        return Ok(AwsCredentials {
            access_key: access_key.trim().to_owned(),
            secret_key: secret_key.trim().to_owned(),
            session_token: env("AWS_SESSION_TOKEN").map(|t| t.trim().to_owned()),
            region: env("AWS_REGION")
                .or_else(|| env("AWS_DEFAULT_REGION"))
                .map(|r| r.trim().to_owned()),
        });
    }
    let credentials = credentials.map(parse_ini).unwrap_or_default();
    let config = config.map(parse_ini).unwrap_or_default();
    let in_credentials = credentials.get(&profile);
    let in_config = config.get(&format!("profile {profile}")).or_else(|| {
        (profile == "default")
            .then(|| config.get("default"))
            .flatten()
    });
    if in_credentials.is_none() && in_config.is_none() {
        return Err(Error::new(format!(
            "there is no AWS profile `{profile}` in ~/.aws/credentials or ~/.aws/config"
        )));
    }
    let get = |key: &str| {
        in_credentials
            .and_then(|s| s.get(key))
            .or_else(|| in_config.and_then(|s| s.get(key)))
            .cloned()
    };
    let (Some(access_key), Some(secret_key)) =
        (get("aws_access_key_id"), get("aws_secret_access_key"))
    else {
        let elsewhere = [
            "role_arn",
            "sso_session",
            "sso_start_url",
            "credential_process",
        ]
        .into_iter()
        .find(|key| get(key).is_some());
        return Err(Error::new(match elsewhere {
            Some(key) => format!(
                "the AWS profile `{profile}` gets its keys by {key}, which RustZilla doesn't \
                 support: give it aws_access_key_id and aws_secret_access_key, or start \
                 RustZilla with AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY set and use the \
                 profile `env`"
            ),
            None => format!(
                "the AWS profile `{profile}` has no aws_access_key_id and aws_secret_access_key"
            ),
        }));
    };
    Ok(AwsCredentials {
        access_key,
        secret_key,
        session_token: get("aws_session_token").or_else(|| get("aws_security_token")),
        region: in_config
            .and_then(|s| s.get("region"))
            .or_else(|| in_credentials.and_then(|s| s.get("region")))
            .cloned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CREDENTIALS: &str = "\
# The keys.
[default]
aws_access_key_id = AKDEFAULT
aws_secret_access_key = secret/default+key

[dev]
aws_access_key_id=AKDEV
aws_secret_access_key=devsecret
aws_session_token = token=with=equals
";

    const CONFIG: &str = "\
[default]
region = eu-central-1
s3 =
  max_concurrent_requests = 20
  region = not-this-one
output = json

; Only in the config file.
[profile ops]
aws_access_key_id = AKOPS
aws_secret_access_key = opssecret
region = us-west-2

[profile dev]
region = eu-west-1

[profile assumed]
role_arn = arn:aws:iam::123456789012:role/admin
source_profile = default

[dev]
region = wrong-section
";

    fn none(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn ini() {
        let sections = parse_ini(CONFIG);
        assert_eq!(sections["default"]["region"], "eu-central-1");
        assert_eq!(sections["default"]["output"], "json");
        assert!(!sections["default"].contains_key("max_concurrent_requests"));
        assert_eq!(sections["profile ops"]["region"], "us-west-2");
        assert_eq!(parse_ini("[ profile  x ]\na=1")["profile x"]["a"], "1");
        assert_eq!(parse_ini("a = outside\n[s]\nb = c = d")["s"]["b"], "c = d");
        assert!(parse_ini("a = outside").is_empty());
    }

    #[test]
    fn profiles() {
        let load = |name: &str| resolve(name, &none, Some(CREDENTIALS), Some(CONFIG));
        assert_eq!(
            load("default").unwrap(),
            AwsCredentials {
                access_key: "AKDEFAULT".into(),
                secret_key: "secret/default+key".into(),
                session_token: None,
                region: Some("eu-central-1".into()),
            }
        );
        // Empty: `default`.
        assert_eq!(load("").unwrap().access_key, "AKDEFAULT");
        let dev = load("dev").unwrap();
        assert_eq!(dev.session_token.as_deref(), Some("token=with=equals"));
        assert_eq!(dev.region.as_deref(), Some("eu-west-1"));
        let ops = load(" ops ").unwrap();
        assert_eq!(
            (ops.access_key.as_str(), ops.region.as_deref()),
            ("AKOPS", Some("us-west-2"))
        );
        let error = load("assumed").unwrap_err();
        assert!(error.message.contains("role_arn"), "{error}");
        let error = load("nope").unwrap_err();
        assert!(error.message.contains("no AWS profile `nope`"), "{error}");
        // Without files.
        assert!(resolve("default", &none, None, None).is_err());
    }

    #[test]
    fn environment() {
        let env = |name: &str| match name {
            "AWS_ACCESS_KEY_ID" => Some("AKENV".to_owned()),
            "AWS_SECRET_ACCESS_KEY" => Some("envsecret".to_owned()),
            "AWS_SESSION_TOKEN" => Some("envtoken".to_owned()),
            "AWS_DEFAULT_REGION" => Some("ap-south-1".to_owned()),
            "AWS_PROFILE" => Some("dev".to_owned()),
            _ => None,
        };
        assert_eq!(
            resolve("env", &env, None, None).unwrap(),
            AwsCredentials {
                access_key: "AKENV".into(),
                secret_key: "envsecret".into(),
                session_token: Some("envtoken".into()),
                region: Some("ap-south-1".into()),
            }
        );
        // AWS_PROFILE names the profile when none is given.
        assert_eq!(
            resolve("", &env, Some(CREDENTIALS), None)
                .unwrap()
                .access_key,
            "AKDEV"
        );
        let error = resolve("env", &none, None, None).unwrap_err();
        assert!(error.message.contains("AWS_ACCESS_KEY_ID"), "{error}");
    }
}
