//! Site passwords and key passphrases in the OS keychain, never in files.

use tracing::warn;

const SERVICE: &str = "rustzilla";

fn entry(site: &str) -> Option<keyring::Entry> {
    keyring::Entry::new(SERVICE, site)
        .inspect_err(|e| warn!("keychain unavailable: {e}"))
        .ok()
}

pub fn load(site: &str) -> Option<String> {
    entry(site)?.get_password().ok()
}

/// Stores the secret, or forgets it when it is empty. The error says why
/// the keychain doesn't keep it.
pub fn store(site: &str, secret: &str) -> Result<(), String> {
    if secret.is_empty() {
        forget(site);
        return Ok(());
    }
    keyring::Entry::new(SERVICE, site)
        .and_then(|entry| entry.set_password(secret))
        .map_err(|e| format!("the keychain didn't keep the password: {e}"))
}

pub fn forget(site: &str) {
    if let Some(entry) = entry(site) {
        let _ = entry.delete_credential();
    }
}
