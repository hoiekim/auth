//! Client addresses (docs/DESIGN.md §9.4): `X-Real-IP` counts only when the
//! connecting peer is a trusted proxy, which sets it from its own connecting
//! address. Anything else would let a client pick its own rate-limit key.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::util::js_trim;

#[derive(Debug, Clone, PartialEq)]
pub struct Cidr {
    pub bytes: Vec<u8>,
    pub prefix: u32,
}

// `^::ffff:(\d+\.\d+\.\d+\.\d+)$`, ignoring case: the dotted tail.
fn mapped_tail(s: &str) -> Option<&str> {
    let head = s.get(..7)?;
    let tail = &s[7..];
    let dotted = tail.split('.').count() == 4 && tail.split('.').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    (head.eq_ignore_ascii_case("::ffff:") && dotted).then_some(tail)
}

/// An address as 4 or 16 bytes. An IPv4-mapped address written with a dotted
/// tail is the IPv4 address, so one rule matches both.
pub fn parse_ip(text: &str) -> Option<Vec<u8>> {
    let mut s = js_trim(text);
    if s.starts_with('[') && s.ends_with(']') && s.len() >= 2 {
        s = &s[1..s.len() - 1];
    }
    if let Some(zone) = s.find('%') {
        s = &s[..zone];
    }
    if let Ok(v4) = s.parse::<Ipv4Addr>() {
        return Some(v4.octets().to_vec());
    }
    let v6 = s.parse::<Ipv6Addr>().ok()?;
    if let Some(tail) = mapped_tail(s) {
        return parse_ip(tail);
    }
    Some(v6.octets().to_vec())
}

pub fn is_ip(text: &str) -> u8 {
    if text.parse::<Ipv4Addr>().is_ok() {
        4
    } else if text.parse::<Ipv6Addr>().is_ok() {
        6
    } else {
        0
    }
}

pub fn parse_cidr(text: &str) -> Option<Cidr> {
    let mut parts = js_trim(text).split('/');
    let addr = parts.next().filter(|a| !a.is_empty())?;
    let len = parts.next();
    if parts.next().is_some() {
        return None;
    }
    let bytes = parse_ip(addr)?;
    let max = bytes.len() as u32 * 8;
    let prefix = match len {
        None => max,
        Some(l) if (1..=3).contains(&l.len()) && l.bytes().all(|b| b.is_ascii_digit()) => l.parse().ok()?,
        Some(_) => return None,
    };
    (prefix <= max).then_some(Cidr { bytes, prefix })
}

pub fn in_cidr(ip: &[u8], cidr: &Cidr) -> bool {
    if ip.len() != cidr.bytes.len() {
        return false;
    }
    let mut bits = cidr.prefix as i64;
    for i in 0..ip.len() {
        if bits <= 0 {
            break;
        }
        let mask: u8 = if bits >= 8 { 0xff } else { 0xffu8 << (8 - bits) };
        if ip[i] & mask != cidr.bytes[i] & mask {
            return false;
        }
        bits -= 8;
    }
    true
}

pub fn format_ip(bytes: &[u8]) -> String {
    if bytes.len() == 4 {
        return bytes.iter().map(u8::to_string).collect::<Vec<_>>().join(".");
    }
    let groups: Vec<u16> = (0..16).step_by(2).map(|i| (u16::from(bytes[i]) << 8) | u16::from(bytes[i + 1])).collect();
    // RFC 5952: the longest run of two or more zero groups becomes "::".
    let mut best: Option<usize> = None;
    let mut best_len = 1;
    let mut i = 0;
    while i < 8 {
        let mut j = i;
        while j < 8 && groups[j] == 0 {
            j += 1;
        }
        if j - i > best_len {
            best = Some(i);
            best_len = j - i;
        }
        i = if j == i { i + 1 } else { j };
    }
    let hex: Vec<String> = groups.iter().map(|g| format!("{g:x}")).collect();
    match best {
        None => hex.join(":"),
        Some(at) => format!("{}::{}", hex[..at].join(":"), hex[at + best_len..].join(":")),
    }
}

/// The client's address: the proxy's `X-Real-IP` when the peer is a trusted
/// proxy, else the peer itself. Returned normalized, or None when unknown.
pub fn client_ip(peer: Option<&str>, real_ip: Option<&str>, trusted: &[Cidr]) -> Option<String> {
    let peer_bytes = parse_ip(peer?)?;
    if let Some(real) = real_ip.filter(|r| !r.is_empty()) {
        if trusted.iter().any(|c| in_cidr(&peer_bytes, c)) {
            if let Some(real) = parse_ip(real) {
                return Some(format_ip(&real));
            }
        }
    }
    Some(format_ip(&peer_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_normalized() {
        assert_eq!(format_ip(&parse_ip("::ffff:192.0.2.1").unwrap()), "192.0.2.1");
        assert_eq!(format_ip(&parse_ip("[2001:DB8:0:0:0:0:0:1]").unwrap()), "2001:db8::1");
        assert_eq!(format_ip(&parse_ip("fe80::1%eth0").unwrap()), "fe80::1");
        assert_eq!(format_ip(&parse_ip("2001:db8:0:1:0:0:0:1").unwrap()), "2001:db8:0:1::1");
        assert_eq!(format_ip(&parse_ip("1:0:1:0:1:0:1:0").unwrap()), "1:0:1:0:1:0:1:0");
        assert_eq!(format_ip(&parse_ip("::").unwrap()), "::");
        assert_eq!(format_ip(&parse_ip("::1.2.3.4").unwrap()), "::102:304");
        assert!(parse_ip("01.2.3.4").is_none());
        assert!(parse_ip("proxy.internal").is_none());
    }

    #[test]
    fn only_a_trusted_peer_names_the_client() {
        let trusted = vec![parse_cidr("10.0.0.0/8").unwrap(), parse_cidr("::1").unwrap()];
        assert_eq!(client_ip(Some("10.1.2.3"), Some("203.0.113.9"), &trusted).unwrap(), "203.0.113.9");
        assert_eq!(client_ip(Some("192.0.2.7"), Some("203.0.113.9"), &trusted).unwrap(), "192.0.2.7");
        assert_eq!(client_ip(Some("::1"), Some("not an address"), &trusted).unwrap(), "::1");
        assert_eq!(client_ip(None, Some("203.0.113.9"), &trusted), None);
        assert!(parse_cidr("10.0.0.0/33").is_none());
        assert!(parse_cidr("10.0.0.0/8/1").is_none());
        assert!(parse_cidr("10.0.0.0/").is_none());
    }
}
