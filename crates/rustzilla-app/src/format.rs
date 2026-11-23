//! Sizes, times and permissions as the panes show them.

use std::time::{Duration, SystemTime};

use crate::pane::Row;

/// `1.5 MiB`.
pub fn size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["bytes", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return format!("{bytes} bytes");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// `1,234,567`: exact, as the file lists show sizes.
pub fn size_exact(bytes: u64) -> String {
    let digits = bytes.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

pub fn counts(files: usize, dirs: usize) -> String {
    let plural =
        |n: usize, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
    match (files, dirs) {
        (0, 0) => "Empty directory".into(),
        (f, 0) => plural(f, "file", "files"),
        (0, d) => plural(d, "directory", "directories"),
        (f, d) => format!(
            "{} and {}",
            plural(f, "file", "files"),
            plural(d, "directory", "directories")
        ),
    }
}

/// In local time, `2026-11-23 14:05`.
pub fn time(time: Option<SystemTime>) -> String {
    time.map(|t| {
        chrono::DateTime::<chrono::Local>::from(t)
            .format("%Y-%m-%d %H:%M")
            .to_string()
    })
    .unwrap_or_default()
}

/// `drwxr-xr-x`, or empty if unknown.
pub fn permissions(row: &Row) -> String {
    let Some(mode) = row.permissions else {
        return String::new();
    };
    let kind = if row.symlink {
        'l'
    } else if row.is_dir {
        'd'
    } else {
        '-'
    };
    format!("{kind}{}", mode_string(mode))
}

/// `rwxr-xr-x` for `0o755`, with the setuid, setgid and sticky bits.
pub fn mode_string(mode: u32) -> String {
    let mut out = String::with_capacity(9);
    for (shift, special, set, unset) in [
        (6, 0o4000, 's', 'S'),
        (3, 0o2000, 's', 'S'),
        (0, 0o1000, 't', 'T'),
    ] {
        let bits = (mode >> shift) & 7;
        out.push(if bits & 4 != 0 { 'r' } else { '-' });
        out.push(if bits & 2 != 0 { 'w' } else { '-' });
        out.push(match (bits & 1 != 0, mode & special != 0) {
            (true, true) => set,
            (false, true) => unset,
            (true, false) => 'x',
            (false, false) => '-',
        });
    }
    out
}

/// `1:05:03` or `5:03`.
pub fn duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 3600 {
        format!("{}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60)
    } else {
        format!("{}:{:02}", secs / 60, secs % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(size(512), "512 bytes");
        assert_eq!(size(1536), "1.5 KiB");
        assert_eq!(size(5 * 1024 * 1024 * 1024), "5.0 GiB");
        assert_eq!(size_exact(1234567), "1,234,567");
        assert_eq!(size_exact(999), "999");
        assert_eq!(counts(0, 0), "Empty directory");
        assert_eq!(counts(1, 2), "1 file and 2 directories");
        assert_eq!(mode_string(0o755), "rwxr-xr-x");
        assert_eq!(mode_string(0o4755), "rwsr-xr-x");
        assert_eq!(mode_string(0o1777), "rwxrwxrwt");
        assert_eq!(mode_string(0o2644), "rw-r-Sr--");
        assert_eq!(duration(Duration::from_secs(303)), "5:03");
        assert_eq!(duration(Duration::from_secs(3903)), "1:05:03");
    }
}
