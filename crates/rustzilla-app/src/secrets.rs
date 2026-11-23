//! Site passwords and key passphrases in the OS keychain, never in files.
//! Tests keep them in memory: a keychain can block (or prompt) on a
//! headless machine, and tests mustn't touch the user's.

use tracing::warn;

#[cfg(test)]
static TEST_STORE: std::sync::Mutex<Vec<(String, String)>> = std::sync::Mutex::new(Vec::new());

const SERVICE: &str = "rustzilla";

fn entry(site: &str) -> Option<keyring::Entry> {
    keyring::Entry::new(SERVICE, site)
        .inspect_err(|e| warn!("keychain unavailable: {e}"))
        .ok()
}

pub fn load(site: &str) -> Option<String> {
    #[cfg(test)]
    {
        TEST_STORE
            .lock()
            .ok()?
            .iter()
            .find(|(s, _)| s == site)
            .map(|(_, p)| p.clone())
    }
    #[cfg(not(test))]
    {
        entry(site)?.get_password().ok()
    }
}

/// Stores the secret, or forgets it when it is empty. The error says why
/// the keychain doesn't keep it.
pub fn store(site: &str, secret: &str) -> Result<(), String> {
    if secret.is_empty() {
        forget(site);
        return Ok(());
    }
    #[cfg(test)]
    {
        let mut store = TEST_STORE.lock().map_err(|e| e.to_string())?;
        store.retain(|(s, _)| s != site);
        store.push((site.to_owned(), secret.to_owned()));
        Ok(())
    }
    #[cfg(not(test))]
    keyring::Entry::new(SERVICE, site)
        .and_then(|entry| entry.set_password(secret))
        .map_err(|e| format!("the keychain didn't keep the password: {e}"))
}

pub fn forget(site: &str) {
    #[cfg(test)]
    if let Ok(mut store) = TEST_STORE.lock() {
        store.retain(|(s, _)| s != site);
        return;
    }
    if let Some(entry) = entry(site) {
        let _ = entry.delete_credential();
    }
}
