//! Just enough of an X.509 certificate's DER for the two checks the TLS
//! verifier adds to rustls's (rust/src/tls.rs): whether a server sent a
//! trusted self-signed root as its own certificate, and the names in its
//! subject.

use chrono::NaiveDate;

pub struct Cert<'a> {
    /// The issuer and subject Names and the SubjectPublicKeyInfo, each
    /// without its SEQUENCE header, as a trust anchor holds them.
    pub issuer: &'a [u8],
    pub subject: &'a [u8],
    pub spki: &'a [u8],
    /// The validity period, in seconds since 1970.
    pub not_before: i64,
    pub not_after: i64,
    /// The subject's common names.
    pub common_names: Vec<String>,
    /// Whether subjectAltName holds a DNS name.
    pub has_dns_names: bool,
}

/// One element: its tag, its contents, and what follows it.
fn element(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        (rest[..n].iter().fold(0usize, |len, b| (len << 8) | usize::from(*b)), &rest[n..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

fn expect(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (t, contents, rest) = element(input)?;
    (t == tag).then_some((contents, rest))
}

const SEQUENCE: u8 = 0x30;
const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];

pub fn parse(der: &[u8]) -> Option<Cert<'_>> {
    let (cert, _) = expect(der, SEQUENCE)?;
    let (tbs, _) = expect(cert, SEQUENCE)?;
    let mut rest = tbs;
    if rest.first() == Some(&0xa0) {
        rest = element(rest)?.2;
    }
    let (_, rest) = expect(rest, 0x02)?;
    let (_, rest) = expect(rest, SEQUENCE)?;
    let (issuer, rest) = expect(rest, SEQUENCE)?;
    let (validity, rest) = expect(rest, SEQUENCE)?;
    let (subject, rest) = expect(rest, SEQUENCE)?;
    let (spki, mut rest) = expect(rest, SEQUENCE)?;
    let (not_before, after) = time(validity)?;
    let (not_after, _) = time(after)?;

    let mut has_dns_names = false;
    while let Some((tag, contents, next)) = element(rest) {
        rest = next;
        if tag != 0xa3 {
            continue;
        }
        let (mut extensions, _) = expect(contents, SEQUENCE)?;
        while let Some((extension, next)) = expect(extensions, SEQUENCE) {
            extensions = next;
            let (oid, mut fields) = expect(extension, 0x06)?;
            if fields.first() == Some(&0x01) {
                fields = element(fields)?.2;
            }
            let (value, _) = expect(fields, 0x04)?;
            if oid == SUBJECT_ALT_NAME {
                let (mut names, _) = expect(value, SEQUENCE)?;
                while let Some((tag, _, next)) = element(names) {
                    has_dns_names |= tag == 0x82;
                    names = next;
                }
            }
        }
    }

    let mut common_names = Vec::new();
    let mut names = subject;
    while let Some((set, next)) = expect(names, 0x31) {
        names = next;
        let mut attributes = set;
        while let Some((attribute, next)) = expect(attributes, SEQUENCE) {
            attributes = next;
            let (oid, value) = expect(attribute, 0x06)?;
            if oid == COMMON_NAME {
                common_names.extend(string(value));
            }
        }
    }
    Some(Cert { issuer, subject, spki, not_before, not_after, common_names, has_dns_names })
}

/// A UTCTime or GeneralizedTime, `Z` only, as seconds since 1970.
fn time(input: &[u8]) -> Option<(i64, &[u8])> {
    let (tag, contents, rest) = element(input)?;
    let text = std::str::from_utf8(contents).ok()?.strip_suffix('Z')?;
    let digits = match tag {
        0x17 => {
            let year: i32 = text.get(..2)?.parse().ok()?;
            format!("{}{text}", if year >= 50 { "19" } else { "20" })
        }
        0x18 => text.to_string(),
        _ => return None,
    };
    if digits.len() != 14 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n = |range: std::ops::Range<usize>| digits[range].parse::<u32>().ok();
    let at = NaiveDate::from_ymd_opt(i32::try_from(n(0..4)?).ok()?, n(4..6)?, n(6..8)?)?.and_hms_opt(n(8..10)?, n(10..12)?, n(12..14)?)?;
    Some((at.and_utc().timestamp(), rest))
}

fn string(input: &[u8]) -> Option<String> {
    let (tag, contents, _) = element(input)?;
    match tag {
        // UTF8String, PrintableString, IA5String
        0x0c | 0x13 | 0x16 => String::from_utf8(contents.to_vec()).ok(),
        // TeletexString, read as Latin-1
        0x14 => Some(contents.iter().map(|b| char::from(*b)).collect()),
        // BMPString
        0x1e if contents.len() % 2 == 0 => String::from_utf16(&contents.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect::<Vec<_>>()).ok(),
        _ => None,
    }
}

/// Whether a certificate name stands for `host`, as OpenSSL matches one:
/// without regard to ASCII case, and with `*` as a whole leftmost label
/// standing for one label, two or more labels before the end.
pub fn name_matches(pattern: &str, host: &str) -> bool {
    let (pattern, host) = (pattern.to_ascii_lowercase(), host.trim_end_matches('.').to_ascii_lowercase());
    if pattern == host {
        return true;
    }
    match (pattern.strip_prefix("*."), host.split_once('.')) {
        (Some(suffix), Some((label, rest))) => suffix.contains('.') && !suffix.contains('*') && !label.is_empty() && rest == suffix,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn der(pem: &str) -> Vec<u8> {
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        base64::engine::general_purpose::STANDARD.decode(body).expect("base64")
    }

    // openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=localhost
    // (no subjectAltName; basicConstraints CA:TRUE, as req -x509 makes it)
    const CN_ONLY: &str = "-----BEGIN CERTIFICATE-----
MIIBfDCCASOgAwIBAgIUZPS1s4kFjbQzczOmFupVzAm/MZkwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MTEyMjA5MDExOVoXDTI2MTEyNDA5
MDExOVowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEpxq4L+3mmOEtJmmXrPSd9WFqnqYxqJMpeO64DCHaFabIGQ19FD/fkMjC
HVCEjc0GYExAot9fanrhSA+XFS82SKNTMFEwHQYDVR0OBBYEFAB6A1DYKDiM2Bpe
ffxkZKxDxq44MB8GA1UdIwQYMBaAFAB6A1DYKDiM2BpeffxkZKxDxq44MA8GA1Ud
EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgMNoyjsjX4rwZdk1T3jAmF9gn
OJ3+OeInpfRHNenDBL0CIDCh9Wgb54iWu1z5RyT9FEmspU17jL9bL1wKhp+Z9EXn
-----END CERTIFICATE-----";

    #[test]
    fn reads_a_self_signed_certificate() {
        let der = der(CN_ONLY);
        let cert = parse(&der).expect("a certificate");
        assert_eq!(cert.issuer, cert.subject);
        assert_eq!(cert.common_names, ["localhost"]);
        assert!(!cert.has_dns_names);
        assert_eq!(cert.not_after - cert.not_before, 2 * 86400);
        assert_eq!(cert.not_before, NaiveDate::from_ymd_opt(2026, 11, 22).unwrap().and_hms_opt(9, 1, 19).unwrap().and_utc().timestamp());
        assert_eq!(cert.spki.len(), 89);
        assert!(parse(&der[..der.len() - 1]).is_none());
        assert!(parse(b"\x30\x00").is_none());
    }

    #[test]
    fn names_match_as_openssl_matches_them() {
        for (pattern, host) in [("localhost", "localhost"), ("LocalHost", "localhost"), ("db.internal", "DB.internal."), ("*.example.com", "db.example.com")] {
            assert!(name_matches(pattern, host), "{pattern} {host}");
        }
        for (pattern, host) in [
            ("other", "localhost"),
            ("*.example.com", "example.com"),
            ("*.example.com", "a.b.example.com"),
            ("*.com", "example.com"),
            ("*.localhost", "a.localhost"),
            ("f*.example.com", "foo.example.com"),
            ("*.*.example.com", "a.b.example.com"),
        ] {
            assert!(!name_matches(pattern, host), "{pattern} {host}");
        }
    }
}
