//! RFC 6238 with SHA-1, 6 digits and a 30-second step, accepting one step
//! either side (docs/DESIGN.md §9.1). Replay is refused by the caller, which
//! records the last step used.

use ring::hmac;

use crate::crypto::{random, safe_equal};
use crate::util::{base32, encode_uri_component, form_encode};

pub const STEP_SECONDS: i64 = 30;

pub fn new_totp_secret() -> Vec<u8> {
    random(20)
}

pub fn otpauth_uri(secret: &[u8], issuer_host: &str, username: &str) -> String {
    let label = format!("{}:{}", encode_uri_component(issuer_host), encode_uri_component(username));
    let params = form_encode(&[("secret", &base32(secret).to_uppercase()), ("issuer", issuer_host), ("algorithm", "SHA1"), ("digits", "6"), ("period", &STEP_SECONDS.to_string())]);
    format!("otpauth://totp/{label}?{params}")
}

pub fn hotp(secret: &[u8], counter: i64) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let mac = hmac::sign(&key, &(counter as u64).to_be_bytes());
    let mac = mac.as_ref();
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let bin = (u32::from(mac[offset] & 0x7f) << 24) | (u32::from(mac[offset + 1]) << 16) | (u32::from(mac[offset + 2]) << 8) | u32::from(mac[offset + 3]);
    format!("{:06}", bin % 1_000_000)
}

/// The step a code matches, newest first, among those after `last_step`; None
/// when none does.
pub fn matching_step(secret: &[u8], code: &str, unix_seconds: i64, last_step: i64) -> Option<i64> {
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let now = unix_seconds.div_euclid(STEP_SECONDS);
    let mut found = None;
    for step in [now + 1, now, now - 1] {
        // Every candidate is compared, so the time taken doesn't depend on which matched.
        let matches = safe_equal(&hotp(secret, step), code);
        if matches && step > last_step && found.is_none() {
            found = Some(step);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_6238_vectors() {
        let secret = b"12345678901234567890";
        assert_eq!(hotp(secret, 59 / 30), "287082");
        assert_eq!(hotp(secret, 1111111109 / 30), "081804");
        assert_eq!(hotp(secret, 20000000000 / 30), "353130");
    }

    #[test]
    fn a_code_matches_its_step_and_its_neighbours_once() {
        let secret = b"12345678901234567890";
        let now = 1_700_000_000;
        let step = now / 30;
        assert_eq!(matching_step(secret, &hotp(secret, step), now, 0), Some(step));
        assert_eq!(matching_step(secret, &hotp(secret, step - 1), now, 0), Some(step - 1));
        assert_eq!(matching_step(secret, &hotp(secret, step + 1), now, 0), Some(step + 1));
        assert_eq!(matching_step(secret, &hotp(secret, step - 2), now, 0), None);
        assert_eq!(matching_step(secret, &hotp(secret, step), now, step), None);
        assert_eq!(matching_step(secret, "12345", now, 0), None);
    }

    #[test]
    fn the_uri_an_authenticator_scans() {
        assert_eq!(
            otpauth_uri(b"12345678901234567890", "auth.example.com", "alice"),
            "otpauth://totp/auth.example.com:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=auth.example.com&algorithm=SHA1&digits=6&period=30"
        );
    }
}
