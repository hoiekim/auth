//! WebAuthn's relying-party checks (docs/DESIGN.md §9.1; W3C Web Authentication
//! Level 3, §7.1 and §7.2), for the one way auth uses it: discoverable
//! credentials, user verification required, attestation "none".
//!
//! Attestation is "none", so nothing here trusts what made a key, and the
//! attestation statement is never read: not its signature and not its
//! certificates. The browser vouches for the origin, the authenticator data
//! for the RP ID and the flags, and at sign-in the signature for both.

use p256::ecdsa::signature::Verifier;
use ring::signature;
use serde_json::{json, Value};

use crate::cbor::{decode_cbor, decode_cbor_prefix, Cbor};
use crate::crypto::{bytes_equal, random, sha256};
use crate::util::{b64url, from_b64};

// COSE algorithm ids, in the order an authenticator should prefer them.
const EDDSA: i64 = -8;
const ES256: i64 = -7;
const RS256: i64 = -257;
const ALGORITHMS: [i64; 3] = [EDDSA, ES256, RS256];

const TIMEOUT_MS: i64 = 60_000;
const MAX_CREDENTIAL_ID: usize = 1023;

const UP: u8 = 0x01; // user present
const UV: u8 = 0x04; // user verified
const BE: u8 = 0x08; // backup eligible
const BS: u8 = 0x10; // backed up
const AT: u8 = 0x40; // attested credential data follows
const ED: u8 = 0x80; // extension data follows

pub struct RelyingParty {
    /// The RP ID: the issuer's host.
    pub id: String,
    /// The issuer's origin.
    pub origin: String,
}

pub fn new_challenge() -> String {
    b64url(&random(32))
}

/// Where the browser should make the passkey: "platform" is the device's own
/// authenticator, "cross-platform" a security key or another device. Only a
/// preference for which prompt the browser shows: attestation being "none",
/// nothing in the response proves which kind made the key.
pub fn is_attachment(v: &Value) -> bool {
    matches!(v.as_str(), Some("platform" | "cross-platform"))
}

pub fn creation_options(rp: &RelyingParty, challenge: &str, user_handle: &[u8], name: &str, display_name: &str, exclude: &[Vec<u8>], attachment: Option<&str>) -> Value {
    let mut selection = serde_json::Map::new();
    if let Some(a) = attachment {
        selection.insert("authenticatorAttachment".into(), json!(a));
    }
    selection.insert("residentKey".into(), json!("required"));
    selection.insert("requireResidentKey".into(), json!(true));
    selection.insert("userVerification".into(), json!("required"));
    json!({
        "challenge": challenge,
        "rp": { "name": rp.id, "id": rp.id },
        "user": { "id": b64url(user_handle), "name": name, "displayName": display_name },
        "pubKeyCredParams": ALGORITHMS.iter().map(|alg| json!({ "type": "public-key", "alg": alg })).collect::<Vec<_>>(),
        "timeout": TIMEOUT_MS,
        "attestation": "none",
        "excludeCredentials": exclude.iter().map(|id| json!({ "type": "public-key", "id": b64url(id) })).collect::<Vec<_>>(),
        "authenticatorSelection": selection,
    })
}

/// No allowCredentials: a discoverable credential names its own user, so the
/// options reveal nothing about who has passkeys.
pub fn request_options(rp: &RelyingParty, challenge: &str) -> Value {
    json!({ "rpId": rp.id, "challenge": challenge, "timeout": TIMEOUT_MS, "userVerification": "required" })
}

pub struct NewCredential {
    pub id: Vec<u8>,
    /// COSE_Key, as the authenticator encoded it.
    pub public_key: Vec<u8>,
    pub sign_count: i64,
}

/// §7.1: a registration response as PublicKeyCredential.toJSON() gives it.
/// The credential, or None when any check fails.
pub fn verify_registration(rp: &RelyingParty, challenge: &str, response: &Value) -> Option<NewCredential> {
    let response = response.as_object()?;
    if response.get("type").and_then(Value::as_str) != Some("public-key") {
        return None;
    }
    let response_id = response.get("id")?.as_str()?;
    let r = response.get("response")?.as_object()?;
    let client_data = r.get("clientDataJSON")?.as_str()?;
    let attestation_object = r.get("attestationObject")?.as_str()?;
    if !client_data_matches(client_data, "webauthn.create", rp, challenge) {
        return None;
    }

    let attestation = decode_cbor(&from_b64(attestation_object)).ok()?;
    attestation.as_map()?;
    let auth_data = attestation.get_text("authData")?.as_bytes()?;
    if !matches!(attestation.get_text("fmt"), Some(Cbor::Text(_))) || !matches!(attestation.get_text("attStmt"), Some(Cbor::Map(_))) {
        return None;
    }

    let (flags, sign_count) = auth_data_head(rp, auth_data)?;
    if flags & AT == 0 {
        return None;
    }
    // aaguid (16 bytes), then the credential id's length and the id.
    let mut at = 37 + 16;
    if auth_data.len() < at + 2 {
        return None;
    }
    let id_length = (usize::from(auth_data[at]) << 8) | usize::from(auth_data[at + 1]);
    at += 2;
    if id_length == 0 || id_length > MAX_CREDENTIAL_ID || auth_data.len() < at + id_length {
        return None;
    }
    let id = auth_data[at..at + id_length].to_vec();
    at += id_length;
    if response_id != b64url(&id) {
        return None;
    }

    let (key, end) = decode_cbor_prefix(&auth_data[at..]).ok()?;
    let public_key = auth_data[at..at + end].to_vec();
    at += end;
    if flags & ED != 0 {
        if !matches!(decode_cbor(&auth_data[at..]).ok()?, Cbor::Map(_)) {
            return None;
        }
    } else if at != auth_data.len() {
        return None;
    }
    cose_key(&key)?;
    Some(NewCredential { id, public_key, sign_count })
}

/// §7.2: an assertion as PublicKeyCredential.toJSON() gives it, checked
/// against the stored key. The authenticator's new signature counter, or None
/// when any check fails, the counter going backwards included.
pub fn verify_assertion(rp: &RelyingParty, challenge: &str, stored_key: &[u8], stored_count: i64, response: &Value) -> Option<i64> {
    let response = response.as_object()?;
    if response.get("type").and_then(Value::as_str) != Some("public-key") {
        return None;
    }
    let r = response.get("response")?.as_object()?;
    let client_data = r.get("clientDataJSON")?.as_str()?;
    let authenticator_data = r.get("authenticatorData")?.as_str()?;
    let signature = r.get("signature")?.as_str()?;
    if !client_data_matches(client_data, "webauthn.get", rp, challenge) {
        return None;
    }

    let auth_data = from_b64(authenticator_data);
    let (_, sign_count) = auth_data_head(rp, &auth_data)?;

    let key = cose_key(&decode_cbor(stored_key).ok()?)?;
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&sha256(&from_b64(client_data)));
    if !key.verify(&signed, &from_b64(signature)) {
        return None;
    }

    // A counter that doesn't move past the stored one means a cloned
    // authenticator. Synced passkeys report 0 every time, which is allowed.
    if (sign_count > 0 || stored_count > 0) && sign_count <= stored_count {
        return None;
    }
    Some(sign_count)
}

fn client_data_matches(encoded: &str, kind: &str, rp: &RelyingParty, challenge: &str) -> bool {
    let Ok(Value::Object(c)) = serde_json::from_str::<Value>(&String::from_utf8_lossy(&from_b64(encoded))) else { return false };
    // Auth's pages can't be framed (§9.2), so a cross-origin ceremony is never ours.
    c.get("type").and_then(Value::as_str) == Some(kind)
        && c.get("challenge").and_then(Value::as_str) == Some(challenge)
        && c.get("origin").and_then(Value::as_str) == Some(rp.origin.as_str())
        && c.get("crossOrigin") != Some(&Value::Bool(true))
}

// The fixed 37 bytes every authenticator data starts with: the RP ID's hash,
// the flags and the signature counter.
fn auth_data_head(rp: &RelyingParty, auth_data: &[u8]) -> Option<(u8, i64)> {
    if auth_data.len() < 37 || !bytes_equal(&sha256(rp.id.as_bytes()), &auth_data[..32]) {
        return None;
    }
    let flags = auth_data[32];
    if flags & UP == 0 || flags & UV == 0 {
        return None;
    }
    if flags & BS != 0 && flags & BE == 0 {
        return None;
    }
    let sign_count = u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    Some((flags, i64::from(sign_count)))
}

enum PublicKey {
    Ed25519(Vec<u8>),
    P256(p256::ecdsa::VerifyingKey),
    Rsa { n: Vec<u8>, e: Vec<u8> },
}

impl PublicKey {
    fn verify(&self, signed: &[u8], sig: &[u8]) -> bool {
        match self {
            PublicKey::Ed25519(x) => signature::UnparsedPublicKey::new(&signature::ED25519, x).verify(signed, sig).is_ok(),
            // ES256 signatures are DER.
            PublicKey::P256(key) => p256::ecdsa::Signature::from_der(sig).is_ok_and(|s| key.verify(signed, &s).is_ok()),
            PublicKey::Rsa { n, e } => signature::RsaPublicKeyComponents { n, e }.verify(&signature::RSA_PKCS1_2048_8192_SHA256, signed, sig).is_ok(),
        }
    }
}

fn unsigned(bytes: &[u8]) -> &[u8] {
    &bytes[bytes.iter().take_while(|b| **b == 0).count()..]
}

// A COSE_Key (RFC 9053) for one of ALGORITHMS, with the key type and curve
// that algorithm needs, checked as far as a key can be without a signature
// (a P-256 point must be on the curve). None for anything else.
fn cose_key(cose: &Cbor) -> Option<PublicKey> {
    cose.as_map()?;
    let kty = cose.get_int(1).and_then(Cbor::as_int);
    let alg = cose.get_int(3).and_then(Cbor::as_int);
    let crv = cose.get_int(-1).and_then(Cbor::as_int);
    let bytes = |label: i64, length: Option<usize>| cose.get_int(label).and_then(Cbor::as_bytes).filter(|v| length.is_none_or(|l| v.len() == l));
    if alg == Some(EDDSA) && kty == Some(1) && crv == Some(6) {
        return Some(PublicKey::Ed25519(bytes(-2, Some(32))?.to_vec()));
    }
    if alg == Some(ES256) && kty == Some(2) && crv == Some(1) {
        let mut point = vec![0x04];
        point.extend_from_slice(bytes(-2, Some(32))?);
        point.extend_from_slice(bytes(-3, Some(32))?);
        return p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).ok().map(PublicKey::P256);
    }
    if alg == Some(RS256) && kty == Some(3) {
        let (n, e) = (unsigned(bytes(-1, None)?), unsigned(bytes(-2, None)?));
        // Any exponent verifies, and with e = 1 anyone can sign.
        let modulus_bits = n.len() * 8 - n.first().map_or(8, |b| b.leading_zeros() as usize);
        if n.is_empty() || !(2048..=4096).contains(&modulus_bits) || e != [0x01, 0x00, 0x01] || n[n.len() - 1] & 1 == 0 {
            return None;
        }
        return Some(PublicKey::Rsa { n: n.to_vec(), e: e.to_vec() });
    }
    None
}
