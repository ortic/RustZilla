//! Small helpers of the protocols: dates as the servers write them,
//! percent-encoding, Base64 and hex.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Days since 1970-01-01 of a date (Howard Hinnant's algorithm).
pub fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date of days since 1970-01-01: (year, month, day).
pub fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

/// UTC fields of `secs` since the epoch: (y, m, d, h, min, s).
pub fn utc(secs: u64) -> (i64, i64, i64, u64, u64, u64) {
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let rest = secs % 86_400;
    (y, m, d, rest / 3600, rest / 60 % 60, rest % 60)
}

pub fn time(secs: i64) -> Option<SystemTime> {
    UNIX_EPOCH.checked_add(Duration::from_secs(u64::try_from(secs).ok()?))
}

pub fn secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// `YYYYMMDDHHMMSS`, as FTP's MDTM and MFMT write times.
pub fn mdtm(secs: u64) -> String {
    let (y, m, d, h, min, s) = utc(secs);
    format!("{y:04}{m:02}{d:02}{h:02}{min:02}{s:02}")
}

/// `20130524T000000Z` and `20130524`, as AWS signatures date requests.
pub fn amz_date(secs: u64) -> (String, String) {
    let (y, m, d, h, min, s) = utc(secs);
    (
        format!("{y:04}{m:02}{d:02}T{h:02}{min:02}{s:02}Z"),
        format!("{y:04}{m:02}{d:02}"),
    )
}

fn seconds_of(y: i64, m: i64, d: i64, h: i64, min: i64, s: i64) -> i64 {
    days_from_civil(y, m, d) * 86_400 + h * 3600 + min * 60 + s
}

/// An HTTP date: `Sun, 06 Nov 1994 08:49:37 GMT`.
pub fn parse_http_date(text: &str) -> Option<SystemTime> {
    let mut parts = text.split_whitespace().skip(1);
    let day: i64 = parts.next()?.parse().ok()?;
    let month = match parts.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: i64 = parts.next()?.parse().ok()?;
    let mut clock = parts.next()?.split(':').map(|p| p.parse::<i64>());
    let (h, min, s) = (
        clock.next()?.ok()?,
        clock.next()?.ok()?,
        clock.next()?.ok()?,
    );
    time(seconds_of(year, month, day, h, min, s))
}

/// An ISO 8601 time in UTC: `2009-10-12T17:50:30.000Z`.
pub fn parse_iso8601(text: &str) -> Option<SystemTime> {
    let text = text.trim();
    let num = |range: std::ops::Range<usize>| text.get(range)?.parse::<i64>().ok();
    time(seconds_of(
        num(0..4)?,
        num(5..7)?,
        num(8..10)?,
        num(11..13)?,
        num(14..16)?,
        num(17..19)?,
    ))
}

/// Percent-encodes a path for a URL, `/` kept; unreserved characters
/// (RFC 3986) stay as they are, as AWS signatures need.
pub fn encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for byte in path.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                out.push(byte as char)
            }
            b => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Percent-encodes a query value (`/` too).
pub fn encode_component(text: &str) -> String {
    encode_path(text).replace('/', "%2F")
}

/// Decodes `%XX` (and nothing else).
pub fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3])
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn base64(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(TABLE[(n >> shift & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(mdtm(0), "19700101000000");
        assert_eq!(mdtm(1_795_000_000), "20261118110640");
        assert_eq!(
            amz_date(1_369_353_600),
            ("20130524T000000Z".into(), "20130524".into())
        );
        assert_eq!(
            parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"),
            time(784_111_777)
        );
        assert_eq!(
            parse_iso8601("2009-10-12T17:50:30.000Z"),
            time(1_255_369_830)
        );
        for days in [-1000, 0, 19_000, 20_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }

    #[test]
    fn encodings() {
        assert_eq!(encode_path("/a b/ä+c"), "/a%20b/%C3%A4%2Bc");
        assert_eq!(encode_component("a/b c"), "a%2Fb%20c");
        assert_eq!(decode("/a%20b/%C3%A4"), "/a b/ä");
        assert_eq!(decode("100%"), "100%");
        assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
        assert_eq!(base64(b"a"), "YQ==");
        assert_eq!(base64(b"ab"), "YWI=");
        assert_eq!(hex(&[0, 255]), "00ff");
    }
}
