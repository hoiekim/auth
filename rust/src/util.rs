//! What the TypeScript server gets from its runtime, written out: JavaScript's
//! rules for strings (lengths in UTF-16 code units, what `trim` removes),
//! `Date`, the encodings, and the URL helpers. A limit counted differently
//! here would accept or refuse an input the other server doesn't.

use base64::Engine;
use chrono::{DateTime, Datelike, Timelike, Utc};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};

/// `Date.now()`.
pub fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

/// `Math.floor(Date.now() / 1000)`.
pub fn now_secs() -> i64 {
    now_ms().div_euclid(1000)
}

/// `new Date()`: the clock at millisecond precision.
pub fn js_now() -> DateTime<Utc> {
    DateTime::from_timestamp_millis(now_ms()).expect("the clock is within chrono's range")
}

/// `Date.prototype.toISOString()` for a timestamp Postgres gave: the
/// microseconds are cut, not rounded, and a year past 9999 takes a sign and
/// six digits.
pub fn iso(t: &DateTime<Utc>) -> String {
    let y = t.year();
    let year = if (0..=9999).contains(&y) {
        format!("{y:04}")
    } else if y < 0 {
        format!("-{:06}", -y)
    } else {
        format!("+{y:06}")
    };
    format!("{year}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z", t.month(), t.day(), t.hour(), t.minute(), t.second(), t.timestamp_subsec_millis())
}

pub fn iso_opt(t: &Option<DateTime<Utc>>) -> serde_json::Value {
    match t {
        Some(t) => serde_json::Value::String(iso(t)),
        None => serde_json::Value::Null,
    }
}

/// `string.length`.
pub fn utf16_len(s: &str) -> usize {
    s.chars().map(char::len_utf16).sum()
}

/// `string.slice(0, n)`, ending on a character: a pair `slice` would cut in
/// half is left out whole.
pub fn utf16_prefix(s: &str, n: usize) -> &str {
    let mut units = 0;
    for (i, c) in s.char_indices() {
        units += c.len_utf16();
        if units > n {
            return &s[..i];
        }
    }
    s
}

/// `[...string].length`.
pub fn char_count(s: &str) -> usize {
    s.chars().count()
}

/// What `\s` and `trim` call white space: ECMAScript's WhiteSpace and
/// LineTerminator, which differ from Unicode's White_Space by U+FEFF and U+0085.
pub fn is_js_space(c: char) -> bool {
    matches!(
        c,
        '\u{9}'..='\u{d}' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
    )
}

/// `string.trim()`.
pub fn js_trim(s: &str) -> &str {
    s.trim_matches(is_js_space)
}

/// `/[\u0000-\u001f\u007f]/.test(string)`.
pub fn has_control(s: &str) -> bool {
    s.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}')
}

pub fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// The first run of digits in a text, as a number; 0 when there is none.
pub fn first_number(s: &str) -> u64 {
    let digits: String = s.chars().skip_while(|c| !c.is_ascii_digit()).take_while(char::is_ascii_digit).collect();
    digits.parse().unwrap_or(0)
}

// ------------------------------------------------------------------ encodings

pub fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn b64_nopad(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes)
}

pub fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// `Buffer.from(text, "base64")` and `"base64url"`: either alphabet, anything
/// else skipped, the first `=` ends the text, and a last group of one
/// character is dropped.
pub fn from_b64(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => continue,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}

pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some((0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect())
}

const RFC4648: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// RFC 4648 base32, lowercase, no padding.
pub fn base32(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut bits = 0;
    let mut value: u32 = 0;
    for byte in bytes {
        value = (value << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            out.push(RFC4648[((value >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
        value &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(RFC4648[((value << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn from_base32(text: &str) -> Option<Vec<u8>> {
    let lower = text.to_lowercase();
    let clean = lower.trim_end_matches('=');
    let mut out = Vec::new();
    let mut bits = 0;
    let mut value: u32 = 0;
    for ch in clean.chars() {
        let i = RFC4648.iter().position(|c| *c as char == ch)? as u32;
        value = (value << 5) | i;
        bits += 5;
        if bits >= 8 {
            out.push(((value >> (bits - 8)) & 255) as u8);
            bits -= 8;
        }
        value &= (1 << bits) - 1;
    }
    Some(out)
}

// `encodeURIComponent` leaves A-Z a-z 0-9 - _ . ! ~ * ' ( ) as they are.
const COMPONENT: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'!').remove(b'~').remove(b'*').remove(b'\'').remove(b'(').remove(b')');

pub fn encode_uri_component(s: &str) -> String {
    utf8_percent_encode(s, COMPONENT).to_string()
}

/// `decodeURIComponent`, or `None` where it throws: a malformed escape, or
/// escapes that are not UTF-8.
pub fn decode_uri_component(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok().filter(|_| hex.bytes().all(|b| b.is_ascii_hexdigit()))?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// `Number(text)`: JavaScript's reading of a string as a number, NaN where
/// it reads none. Whitespace around it is ignored, an empty string is 0, and
/// `0x`, `0o` and `0b` prefixes, exponents and `Infinity` are numbers.
pub fn js_number(text: &str) -> f64 {
    let s = js_trim(text);
    if s.is_empty() {
        return 0.0;
    }
    match s {
        "Infinity" | "+Infinity" => return f64::INFINITY,
        "-Infinity" => return f64::NEG_INFINITY,
        _ => {}
    }
    let radix = match s.get(..2) {
        Some("0x" | "0X") => 16,
        Some("0o" | "0O") => 8,
        Some("0b" | "0B") => 2,
        _ => 10,
    };
    if radix != 10 {
        let digits = &s[2..];
        if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
            return f64::NAN;
        }
        return digits.chars().fold(0.0, |n, c| n * f64::from(radix) + f64::from(c.to_digit(radix).unwrap_or(0)));
    }
    let b = s.as_bytes();
    let digits_from = |mut i: usize| {
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        i
    };
    let start = usize::from(matches!(b[0], b'+' | b'-'));
    let mut i = digits_from(start);
    let mut digits = i - start;
    if b.get(i) == Some(&b'.') {
        let end = digits_from(i + 1);
        digits += end - i - 1;
        i = end;
    }
    if digits == 0 {
        return f64::NAN;
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        let sign = usize::from(matches!(b.get(i + 1), Some(b'+' | b'-')));
        let end = digits_from(i + 1 + sign);
        if end == i + 1 + sign {
            return f64::NAN;
        }
        i = end;
    }
    if i != b.len() {
        return f64::NAN;
    }
    s.parse().unwrap_or(f64::NAN)
}

/// `new URLSearchParams(pairs).toString()`.
pub fn form_encode(pairs: &[(&str, &str)]) -> String {
    let mut s = form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        s.append_pair(k, v);
    }
    s.finish()
}

/// `new URLSearchParams(text)`: the pairs in order.
pub fn form_decode(text: &str) -> Vec<(String, String)> {
    let text = text.strip_prefix('?').unwrap_or(text);
    form_urlencoded::parse(text.as_bytes()).into_owned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_count_utf16_units() {
        assert_eq!(utf16_len("a\u{1f600}"), 3);
        assert_eq!(utf16_prefix("a\u{1f600}b", 2), "a");
        assert_eq!(utf16_prefix("a\u{1f600}b", 3), "a\u{1f600}");
        assert_eq!(char_count("a\u{1f600}"), 2);
    }

    #[test]
    fn numbers_read_as_javascript_reads_them() {
        for (text, n) in [
            ("5433", 5433.0),
            (" 5433\n", 5433.0),
            ("", 0.0),
            ("  ", 0.0),
            ("0x1F", 31.0),
            ("0o17", 15.0),
            ("0b101", 5.0),
            ("5e3", 5000.0),
            ("1.5", 1.5),
            (".5", 0.5),
            ("5.", 5.0),
            ("+5", 5.0),
            ("-5", -5.0),
            ("007", 7.0),
            ("1E+2", 100.0),
        ] {
            assert_eq!(js_number(text), n, "{text:?}");
        }
        assert_eq!(js_number("Infinity"), f64::INFINITY);
        assert_eq!(js_number("-Infinity"), f64::NEG_INFINITY);
        for text in ["abc", "5a", "0x", "0xg", "-0x5", "1_000", "inf", "nan", "NaN", ".", "+", "1e", "1e+", "e5", "5 5", "infinity"] {
            assert!(js_number(text).is_nan(), "{text:?}");
        }
    }

    #[test]
    fn trim_is_javascripts() {
        assert_eq!(js_trim("  \u{85}x\u{feff}\u{a0}"), "\u{85}x");
    }

    #[test]
    fn base64_reads_as_buffer_from_does() {
        assert_eq!(from_b64("YWJj$ZGVm"), b"abcdef");
        assert_eq!(from_b64("YWJj=ZGVm"), b"abc");
        assert_eq!(from_b64("YW Jj\nZGVm"), b"abcdef");
        assert_eq!(hex(&from_b64("YWJjZGV")), "6162636465");
        assert_eq!(hex(&from_b64("YWJjZ")), "616263");
        assert_eq!(hex(&from_b64("a-_b+/c")), "6befdbfbf7");
        assert_eq!(from_b64("=YWJj"), b"");
        assert_eq!(hex(&from_b64("YQ==YWJj")), "61");
    }

    #[test]
    fn base32_round_trips() {
        for len in 0..40 {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(from_base32(&base32(&bytes)).unwrap(), bytes);
        }
        assert_eq!(base32(b"foobar"), "mzxw6ytboi");
        assert_eq!(from_base32("MZXW6YTBOI======").unwrap(), b"foobar");
        assert!(from_base32("a1").is_none());
    }

    #[test]
    fn iso_cuts_to_milliseconds_and_widens_the_year() {
        let t = DateTime::parse_from_rfc3339("2026-11-12T16:02:11.999600Z").unwrap().with_timezone(&Utc);
        assert_eq!(iso(&t), "2026-11-12T16:02:11.999Z");
        let before = DateTime::parse_from_rfc3339("1969-12-31T23:59:59.999600Z").unwrap().with_timezone(&Utc);
        assert_eq!(iso(&before), "1969-12-31T23:59:59.999Z");
    }

    #[test]
    fn uri_components() {
        assert_eq!(encode_uri_component("a b&c/d!~*'()é"), "a%20b%26c%2Fd!~*'()%C3%A9");
        assert_eq!(decode_uri_component("a%20b%C3%A9").unwrap(), "a b\u{e9}");
        assert!(decode_uri_component("%zz").is_none());
        assert!(decode_uri_component("%ff").is_none());
        assert_eq!(form_encode(&[("return_to", "/a b?x=1&y=é")]), "return_to=%2Fa+b%3Fx%3D1%26y%3D%C3%A9");
    }
}
