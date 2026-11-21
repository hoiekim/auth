//! JWTs signed with Ed25519 (docs/DESIGN.md §7.3). `alg` is EdDSA by
//! construction: a verifier never reads it from the token to decide anything,
//! and refuses a token whose header names another.

use std::sync::Arc;

use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};
use serde_json::{json, Map, Value};

use crate::util::{b64url, from_b64, utf16_len};

#[derive(Clone)]
pub struct Signer {
    pub kid: String,
    pub key: Arc<Ed25519KeyPair>,
}

/// `typ` is "at+jwt", "JWT" or "secevent+jwt".
pub fn sign_jwt(typ: &str, payload: &Value, key: &Signer) -> String {
    let header = b64url(json!({ "alg": "EdDSA", "typ": typ, "kid": key.kid }).to_string().as_bytes());
    let body = b64url(payload.to_string().as_bytes());
    let signature = key.key.sign(format!("{header}.{body}").as_bytes());
    format!("{header}.{body}.{}", b64url(signature.as_ref()))
}

pub struct VerifyOptions<'a> {
    pub typ: &'a str,
    pub issuer: &'a str,
    /// Accepted audiences; None accepts any (the caller then checks it).
    pub audience: Option<Vec<String>>,
    pub now_seconds: i64,
    pub leeway_seconds: i64,
}

fn record(part: &str) -> Option<Map<String, Value>> {
    match serde_json::from_str(&String::from_utf8_lossy(&from_b64(part))).ok()? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

/// The payload when every check passes, else None. `key_for` returns only keys
/// auth itself published, so `kid` merely selects among them.
pub fn verify_jwt(token: &str, key_for: impl Fn(&str) -> Option<Vec<u8>>, opts: &VerifyOptions) -> Option<Map<String, Value>> {
    if utf16_len(token) > 8192 {
        return None;
    }
    let parts: Vec<&str> = token.split('.').collect();
    let [h, p, s] = parts.as_slice() else { return None };
    let header = record(h)?;
    let payload = record(p)?;
    if header.get("alg").and_then(Value::as_str) != Some("EdDSA") || header.get("typ").and_then(Value::as_str) != Some(opts.typ) || header.contains_key("crit") {
        return None;
    }
    let key = key_for(header.get("kid")?.as_str()?)?;
    UnparsedPublicKey::new(&ED25519, key).verify(format!("{h}.{p}").as_bytes(), &from_b64(s)).ok()?;
    if payload.get("iss").and_then(Value::as_str) != Some(opts.issuer) {
        return None;
    }
    if let Some(audience) = &opts.audience {
        let aud = payload.get("aud").and_then(Value::as_str)?;
        if !audience.iter().any(|a| a == aud) {
            return None;
        }
    }
    let leeway = opts.leeway_seconds as f64;
    let now = opts.now_seconds as f64;
    let exp = payload.get("exp").filter(|v| v.is_number())?.as_f64()?;
    if exp + leeway < now {
        return None;
    }
    let iat = payload.get("iat").filter(|v| v.is_number())?.as_f64()?;
    if iat - leeway > now {
        return None;
    }
    Some(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::KeyPair;

    fn signer() -> Signer {
        Signer { kid: "k1".into(), key: Arc::new(Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).unwrap()) }
    }

    fn opts(typ: &str) -> VerifyOptions<'_> {
        VerifyOptions { typ, issuer: "https://auth.example.com", audience: Some(vec!["wiki".into()]), now_seconds: 1000, leeway_seconds: 30 }
    }

    #[test]
    fn a_token_verifies_only_as_what_it_is() {
        let key = signer();
        let public = key.key.public_key().as_ref().to_vec();
        let key_for = |kid: &str| (kid == "k1").then(|| public.clone());
        let claims = json!({ "iss": "https://auth.example.com", "aud": "wiki", "iat": 1000, "exp": 1600 });
        let token = sign_jwt("at+jwt", &claims, &key);
        assert!(verify_jwt(&token, key_for, &opts("at+jwt")).is_some());
        assert!(verify_jwt(&token, key_for, &opts("JWT")).is_none());
        assert!(verify_jwt(&token, |_| None, &opts("at+jwt")).is_none());
        let mut late = opts("at+jwt");
        late.now_seconds = 1631;
        assert!(verify_jwt(&token, key_for, &late).is_none());
        late.now_seconds = 1630;
        assert!(verify_jwt(&token, key_for, &late).is_some());
        let mut other = opts("at+jwt");
        other.audience = Some(vec!["tasks".into()]);
        assert!(verify_jwt(&token, key_for, &other).is_none());
        let tampered = format!("{}x", token);
        assert!(verify_jwt(&tampered, key_for, &opts("at+jwt")).is_none());
        let none = format!("{}.{}.", b64url(br#"{"alg":"none","typ":"at+jwt","kid":"k1"}"#), token.split('.').nth(1).unwrap());
        assert!(verify_jwt(&none, key_for, &opts("at+jwt")).is_none());
    }
}
