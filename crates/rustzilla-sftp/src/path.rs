//! Remote paths: always `/`-separated, whatever the local system uses.

/// `name` in the directory `dir`.
pub fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_owned()
    } else if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// The directory that holds `path`; `/` is its own parent.
pub fn parent(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(0) | None if path.starts_with('/') => "/".to_owned(),
        Some(i) => trimmed[..i].to_owned(),
        None => ".".to_owned(),
    }
}

/// The last component of `path`.
pub fn file_name(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    trimmed.rsplit('/').next().unwrap_or(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(join("/home/u", "a.txt"), "/home/u/a.txt");
        assert_eq!(join("/", "etc"), "/etc");
        assert_eq!(join("", "x"), "x");
        assert_eq!(parent("/home/u/a.txt"), "/home/u");
        assert_eq!(parent("/home/"), "/");
        assert_eq!(parent("/home"), "/");
        assert_eq!(parent("/"), "/");
        assert_eq!(parent("a/b"), "a");
        assert_eq!(parent("a"), ".");
        assert_eq!(file_name("/home/u/a.txt"), "a.txt");
        assert_eq!(file_name("/home/u/"), "u");
    }
}
