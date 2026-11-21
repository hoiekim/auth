//! Account passwords (docs/DESIGN.md §9.1).

use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordVerifier, Version};
use tokio::sync::{OnceCell, Semaphore};

use crate::crypto::random;
use crate::util::{b64_nopad, char_count};

// OWASP's minimum for argon2id: m = 19 MiB, t = 2, p = 1.
const MEMORY_KIB: u32 = 19456;
const TIME: u32 = 2;
const CURRENT_PREFIX: &str = "$argon2id$v=19$m=19456,t=2,p=1$";

fn argon2id(password: &[u8]) -> String {
    let salt = random(32);
    let mut out = [0u8; 32];
    let params = Params::new(MEMORY_KIB, TIME, 1, Some(32)).expect("argon2 parameters");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(password, &salt, &mut out).expect("argon2id hashes");
    format!("{CURRENT_PREFIX}{}${}", b64_nopad(&salt), b64_nopad(&out))
}

// A bcrypt hash can only have been imported (§13), and standard bcrypt reads
// the first 72 bytes of a password.
fn verify_blocking(password: &str, target: &str) -> bool {
    if target.starts_with("$2") {
        let bytes = password.as_bytes();
        return bcrypt::verify(&bytes[..bytes.len().min(72)], target).unwrap_or(false);
    }
    if !target.starts_with("$argon2") {
        return false;
    }
    match PasswordHash::new(target) {
        Ok(parsed) => Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}

pub struct Verdict {
    pub ok: bool,
    pub rehash: bool,
}

pub struct Hasher {
    // One hash at a time caps hashing memory at 19 MiB. On half a CPU a second
    // slot adds no throughput, since both hashes would share the same half core.
    slots: Semaphore,
    dummy: OnceCell<String>,
}

impl Hasher {
    pub fn new() -> Hasher {
        Hasher { slots: Semaphore::new(1), dummy: OnceCell::new() }
    }

    pub async fn hash(&self, password: &str) -> String {
        let _slot = self.slots.acquire().await.expect("the hashing slot");
        let password = password.to_string();
        tokio::task::spawn_blocking(move || argon2id(password.as_bytes())).await.expect("hashing")
    }

    /// `stored` None (an unknown user, or one without a password) verifies
    /// against a dummy hash, so the answer takes as long as a real one.
    pub async fn verify(&self, password: &str, stored: Option<&str>) -> Verdict {
        let target = match stored {
            Some(s) => s.to_string(),
            None => self.dummy.get_or_init(|| self.hash("not a password anyone has: the dummy hash for unknown users")).await.clone(),
        };
        let matched = {
            let _slot = self.slots.acquire().await.expect("the hashing slot");
            let (password, target) = (password.to_string(), target);
            tokio::task::spawn_blocking(move || verify_blocking(&password, &target)).await.unwrap_or(false)
        };
        let ok = matched && stored.is_some();
        Verdict { ok, rehash: ok && !stored.is_some_and(|s| s.starts_with(CURRENT_PREFIX)) }
    }
}

pub const MIN_PASSWORD: usize = 12;
pub const MAX_PASSWORD: usize = 256;

/// NIST SP 800-63B: length only, no composition rules; not the username or
/// the email. The breached-password check is separate (it's a network call).
pub fn password_problem(password: &str, username: Option<&str>, email: Option<&str>) -> Option<String> {
    let length = char_count(password);
    if length < MIN_PASSWORD {
        return Some(format!("Use at least {MIN_PASSWORD} characters."));
    }
    if length > MAX_PASSWORD {
        return Some(format!("Use at most {MAX_PASSWORD} characters."));
    }
    let lower = password.to_lowercase();
    if username.is_some_and(|u| !u.is_empty() && lower == u.to_lowercase()) {
        return Some("Don't use your username as your password.".into());
    }
    if email.is_some_and(|e| !e.is_empty() && lower == e.to_lowercase()) {
        return Some("Don't use your email address as your password.".into());
    }
    None
}

pub const BREACHED_MESSAGE: &str = "This password appears in known data breaches. Choose another.";

/// Have I Been Pwned's k-anonymity range API, or the deployment's mirror of it.
pub const BREACHED_PASSWORDS_URL: &str = "https://api.pwnedpasswords.com/range";

/// Only the first five hex characters of the SHA-1 leave the host, and padding
/// hides how many suffixes came back. A timeout or an error allows the password.
pub async fn is_breached(client: &reqwest::Client, range_url: &str, password: &str) -> bool {
    let sha1 = crate::crypto::sha1_hex_upper(password.as_bytes());
    let (prefix, suffix) = sha1.split_at(5);
    let request = client.get(format!("{range_url}/{prefix}")).header("Add-Padding", "true").timeout(std::time::Duration::from_millis(2000));
    let Ok(res) = request.send().await else { return false };
    if !res.status().is_success() {
        return false;
    }
    let Ok(body) = res.text().await else { return false };
    body.split('\n').any(|line| {
        let mut parts = crate::util::js_trim(line).split(':');
        parts.next() == Some(suffix) && parts.next().and_then(|count| crate::util::js_trim(count).parse::<f64>().ok()).is_some_and(|n| n > 0.0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_have_todays_parameters_and_verify() {
        let hash = argon2id(b"correct horse battery");
        assert!(hash.starts_with(CURRENT_PREFIX));
        assert!(verify_blocking("correct horse battery", &hash));
        assert!(!verify_blocking("correct horse batterz", &hash));
    }

    #[test]
    fn a_hash_the_other_server_made_verifies() {
        // Bun.password.hash("x", { algorithm: "argon2id", memoryCost: 19456, timeCost: 2 })
        let theirs = "$argon2id$v=19$m=19456,t=2,p=1$vNg9W7OgVF8aCCsLfUZxdUk2h7ICcETNml3jH3OShzg$CTn+rQG9jfILMgxKJ0uJzGsVs158tuy5JW7RdZo65os";
        assert!(verify_blocking("x", theirs));
        assert!(!verify_blocking("y", theirs));
        assert!(!verify_blocking("x", "not a hash"));
        assert!(!verify_blocking("x", "$argon2id$garbage"));
    }

    #[test]
    fn the_policy_counts_characters() {
        assert_eq!(password_problem("short", None, None).unwrap(), "Use at least 12 characters.");
        assert!(password_problem(&"\u{1f600}".repeat(12), None, None).is_none());
        assert_eq!(password_problem(&"a".repeat(257), None, None).unwrap(), "Use at most 256 characters.");
        assert_eq!(password_problem("Alice-Alice-1", Some("alice-alice-1"), None).unwrap(), "Don't use your username as your password.");
        assert_eq!(password_problem("ALICE@example.com", None, Some("alice@example.com")).unwrap(), "Don't use your email address as your password.");
    }
}
