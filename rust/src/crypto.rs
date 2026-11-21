//! Hashes, ids and encryption at rest (docs/DESIGN.md §7.3, §9.3). Every
//! format here is the other server's too: two copies run side by side during
//! a deploy, and each reads what the other wrote.

use std::collections::HashMap;
use std::sync::Mutex;

use ring::rand::{SecureRandom, SystemRandom};
use ring::{aead, digest, hkdf, hmac};
use serde_json::{json, Value};

use crate::util::{b64url, from_b64, now_ms, utf16_len};

pub fn sha256(data: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA256, data).as_ref().to_vec()
}

pub fn sha1_hex_upper(data: &[u8]) -> String {
    crate::util::hex(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data).as_ref()).to_uppercase()
}

pub fn random(bytes: usize) -> Vec<u8> {
    let mut out = vec![0u8; bytes];
    SystemRandom::new().fill(&mut out).expect("the system's random source");
    out
}

/// 32 random bytes, base64url: codes, cookies, one-time and refresh tokens.
pub fn random_token() -> String {
    b64url(&random(32))
}

/// Compares equal-length digests in constant time, so neither the length nor
/// the content of either side leaks through the comparison's timing.
pub fn safe_equal(a: &str, b: &str) -> bool {
    let (x, y) = (sha256(a.as_bytes()), sha256(b.as_bytes()));
    x.iter().zip(y.iter()).fold(0u8, |acc, (p, q)| acc | (p ^ q)) == 0
}

pub fn bytes_equal(a: &[u8], b: &[u8]) -> bool {
    safe_equal(&crate::util::hex(a), &crate::util::hex(b))
}

// Crockford's alphabet, lowercase: ids read aloud or typed never mix up 0/o
// or 1/l/i.
const CROCKFORD: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

static LAST_ID: Mutex<(u64, u16)> = Mutex::new((0, 0));

// A UUIDv7: 48 bits of milliseconds, the version, a 12-bit counter that keeps
// ids made in one millisecond in order, the variant, and 62 random bits.
fn uuid_v7() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    SystemRandom::new().fill(&mut bytes).expect("the system's random source");
    let (ms, seq) = {
        let mut last = LAST_ID.lock().unwrap();
        let now = now_ms() as u64;
        if now > last.0 {
            *last = (now, u16::from_be_bytes([bytes[6], bytes[7]]) & 0x07ff);
        } else if last.1 < 0x0fff {
            last.1 += 1;
        } else {
            *last = (last.0 + 1, 0);
        }
        *last
    };
    bytes[..6].copy_from_slice(&ms.to_be_bytes()[2..]);
    bytes[6] = 0x70 | ((seq >> 8) as u8 & 0x0f);
    bytes[7] = seq as u8;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}

/// `<prefix>_` and 26 characters encoding a UUIDv7, so ids sort by creation.
pub fn new_id(prefix: &str) -> String {
    let mut n = u128::from_be_bytes(uuid_v7());
    let mut out = [0u8; 26];
    for slot in out.iter_mut().rev() {
        *slot = CROCKFORD[(n & 31) as usize];
        n >>= 5;
    }
    format!("{prefix}_{}", std::str::from_utf8(&out).unwrap())
}

/// `^[a-z]{2,3}_[0-9a-hjkmnp-tv-z]{26}$`
pub fn is_id(s: &str) -> bool {
    let Some((prefix, rest)) = s.split_once('_') else { return false };
    (2..=3).contains(&prefix.len()) && prefix.bytes().all(|b| b.is_ascii_lowercase()) && rest.len() == 26 && rest.bytes().all(|b| CROCKFORD.contains(&b))
}

/// `^[A-Za-z0-9_-]{43}$`: 32 random bytes as base64url.
pub fn is_token(s: &str) -> bool {
    s.len() == 43 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

// AES-256-GCM with the key's version as a prefix and the row id as
// additional data, so a ciphertext moved to another row fails to decrypt,
// and the key can be rotated (docs/DESIGN.md §9.3): new data is written
// under the current key, and every configured key still reads what it wrote.

#[derive(Clone)]
pub struct EncryptionKey {
    pub version: u32,
    pub key: Vec<u8>,
}

pub struct CryptError;

pub struct Encrypter {
    current: EncryptionKey,
    keys: Vec<EncryptionKey>,
    subkeys: Mutex<HashMap<String, Vec<u8>>>,
}

// `^v(\d{1,4}):` over the first six bytes: the version and the prefix's length.
fn version_prefix(sealed: &[u8]) -> Option<(u32, usize)> {
    if sealed.first() != Some(&b'v') {
        return None;
    }
    let digits = sealed[1..sealed.len().min(5)].iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 || sealed.get(1 + digits) != Some(&b':') {
        return None;
    }
    let version = std::str::from_utf8(&sealed[1..1 + digits]).ok()?.parse().ok()?;
    Some((version, digits + 2))
}

impl Encrypter {
    /// `current` encrypts; `others` only decrypt.
    pub fn new(current: EncryptionKey, others: Vec<EncryptionKey>) -> Encrypter {
        let mut keys = vec![current.clone()];
        keys.extend(others);
        Encrypter { current, keys, subkeys: Mutex::new(HashMap::new()) }
    }

    pub fn version(&self) -> u32 {
        self.current.version
    }

    pub fn versions(&self) -> Vec<u32> {
        self.keys.iter().map(|k| k.version).collect()
    }

    /// The key version a ciphertext was written under, or None when it has none.
    pub fn version_of(sealed: &[u8]) -> Option<u32> {
        version_prefix(sealed).map(|(v, _)| v)
    }

    fn key(&self, version: u32) -> Option<&[u8]> {
        self.keys.iter().find(|k| k.version == version).map(|k| k.key.as_slice())
    }

    pub fn encrypt(&self, plaintext: &[u8], aad: &str) -> Vec<u8> {
        seal(&self.current.key, self.current.version, plaintext, aad)
    }

    pub fn decrypt(&self, sealed: &[u8], aad: &str) -> Result<Vec<u8>, CryptError> {
        let version = Encrypter::version_of(sealed).ok_or(CryptError)?;
        open(self.key(version).ok_or(CryptError)?, sealed, aad)
    }

    // A key for one purpose, derived so that no two purposes share key material
    // with each other or with encryption at rest.
    fn subkey(&self, version: u32, purpose: &str) -> Option<Vec<u8>> {
        let id = format!("{version}:{purpose}");
        if let Some(k) = self.subkeys.lock().unwrap().get(&id) {
            return Some(k.clone());
        }
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(self.key(version)?);
        let info = format!("auth:{purpose}");
        let info_parts = [info.as_bytes()];
        let okm = prk.expand(&info_parts, hkdf::HKDF_SHA256).ok()?;
        let mut out = vec![0u8; 32];
        okm.fill(&mut out).ok()?;
        self.subkeys.lock().unwrap().insert(id, out.clone());
        Some(out)
    }

    fn hmac_under(&self, version: u32, purpose: &str, data: &str) -> String {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.subkey(version, purpose).expect("a configured key"));
        b64url(hmac::sign(&key, data.as_bytes()).as_ref())
    }

    pub fn hmac(&self, purpose: &str, data: &str) -> String {
        self.hmac_under(self.current.version, purpose, data)
    }

    /// Whether `candidate` is the HMAC of `data` under any configured key, so a
    /// value issued before a rotation still holds after it.
    pub fn hmac_matches(&self, purpose: &str, data: &str, candidate: &str) -> bool {
        let mut ok = false;
        for version in self.versions() {
            if safe_equal(candidate, &self.hmac_under(version, purpose, data)) {
                ok = true;
            }
        }
        ok
    }

    /// A short-lived, tamper-proof, confidential value handed to the browser or
    /// a client and read back later: a pending second factor, a TOTP enrolment,
    /// a WebAuthn challenge.
    pub fn seal_value(&self, purpose: &str, value: &Value, ttl_seconds: i64) -> String {
        let body = json!({ "v": value, "exp": now_ms() + ttl_seconds * 1000 }).to_string();
        let version = self.current.version;
        let key = self.subkey(version, &format!("sealed:{purpose}")).expect("the current key");
        b64url(&seal(&key, version, body.as_bytes(), purpose))
    }

    pub fn open_value(&self, purpose: &str, token: Option<&str>) -> Option<Value> {
        let token = token.filter(|t| !t.is_empty() && utf16_len(t) <= 8192)?;
        let sealed = from_b64(token);
        let version = Encrypter::version_of(&sealed)?;
        let key = self.subkey(version, &format!("sealed:{purpose}"))?;
        let body: Value = serde_json::from_slice(&open(&key, &sealed, purpose).ok()?).ok()?;
        let exp = body.as_object()?.get("exp")?.as_f64()?;
        if exp < now_ms() as f64 {
            return None;
        }
        Some(body.get("v").cloned().unwrap_or(Value::Null))
    }
}

fn seal(key: &[u8], version: u32, plaintext: &[u8], aad: &str) -> Vec<u8> {
    let iv = random(12);
    let sealing = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, key).expect("a 32-byte key"));
    let mut body = plaintext.to_vec();
    sealing.seal_in_place_append_tag(aead::Nonce::try_assume_unique_for_key(&iv).unwrap(), aead::Aad::from(aad.as_bytes()), &mut body).expect("AES-GCM seals");
    let mut out = format!("v{version}:").into_bytes();
    out.extend_from_slice(&iv);
    out.extend_from_slice(&body);
    out
}

// The caller chose `key` by the version in this same prefix.
fn open(key: &[u8], sealed: &[u8], aad: &str) -> Result<Vec<u8>, CryptError> {
    let (_, prefix) = version_prefix(sealed).ok_or(CryptError)?;
    if sealed.len() < prefix + 12 + 16 {
        return Err(CryptError);
    }
    let opening = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| CryptError)?);
    let nonce = aead::Nonce::try_assume_unique_for_key(&sealed[prefix..prefix + 12]).map_err(|_| CryptError)?;
    let mut body = sealed[prefix + 12..].to_vec();
    let plain = opening.open_in_place(nonce, aead::Aad::from(aad.as_bytes()), &mut body).map_err(|_| CryptError)?;
    Ok(plain.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crypt() -> Encrypter {
        Encrypter::new(EncryptionKey { version: 2, key: vec![7; 32] }, vec![EncryptionKey { version: 1, key: vec![9; 32] }])
    }

    #[test]
    fn ids_sort_by_creation_and_match_the_pattern() {
        let ids: Vec<String> = (0..2000).map(|_| new_id("usr")).collect();
        assert!(ids.iter().all(|i| is_id(i)));
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(sorted, ids);
        assert!(!is_id("usr_0123456789abcdefghjkmnpqri"));
        assert!(!is_id("user_0123456789abcdefghjkmnpqrs"));
    }

    #[test]
    fn a_ciphertext_is_bound_to_its_row_and_key_version() {
        let c = crypt();
        let sealed = c.encrypt(b"secret", "row-1");
        assert!(sealed.starts_with(b"v2:"));
        assert_eq!(c.decrypt(&sealed, "row-1").ok().unwrap(), b"secret");
        assert!(c.decrypt(&sealed, "row-2").is_err());
        let old = Encrypter::new(EncryptionKey { version: 1, key: vec![9; 32] }, vec![]);
        let written_before = old.encrypt(b"older", "row-1");
        assert_eq!(c.decrypt(&written_before, "row-1").ok().unwrap(), b"older");
        assert!(old.decrypt(&sealed, "row-1").is_err());
        assert_eq!(Encrypter::version_of(b"v12345:x"), None);
        assert_eq!(Encrypter::version_of(b"v9999:x"), Some(9999));
        assert_eq!(Encrypter::version_of(b"x1:"), None);
    }

    #[test]
    fn sealed_values_expire_and_keep_to_their_purpose() {
        let c = crypt();
        let token = c.seal_value("pending", &json!({ "u": "usr_1" }), 60);
        assert_eq!(c.open_value("pending", Some(&token)).unwrap(), json!({ "u": "usr_1" }));
        assert!(c.open_value("totp-enrol", Some(&token)).is_none());
        assert!(c.open_value("pending", Some(&c.seal_value("pending", &json!(1), -1))).is_none());
        assert!(c.open_value("pending", None).is_none());
        assert!(c.open_value("pending", Some("")).is_none());
    }

    #[test]
    fn an_hmac_holds_under_any_configured_key() {
        let c = crypt();
        let old = Encrypter::new(EncryptionKey { version: 1, key: vec![9; 32] }, vec![]);
        assert!(c.hmac_matches("csrf", "token", &c.hmac("csrf", "token")));
        assert!(c.hmac_matches("csrf", "token", &old.hmac("csrf", "token")));
        assert!(!c.hmac_matches("csrf", "token", &c.hmac("other", "token")));
        assert!(!c.hmac_matches("csrf", "token", ""));
    }
}
