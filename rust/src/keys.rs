//! Token signing keys (docs/DESIGN.md §9.3). A new Ed25519 key is made every
//! 90 days, published in JWKS a day before it signs, and kept there for a day
//! after it stops. Postgres holds them, private halves encrypted; every copy
//! reads the same rows, and rotation runs in whichever copy takes the lock.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};

use crate::crypto::{random, sha256, Encrypter};
use crate::db::{Tx, Q};
use crate::error::{Error, Result};
use crate::jwt::Signer;
use crate::util::{b64url, from_b64};

/// An Ed25519 public key as this service writes one: an object, OKP,
/// Ed25519, and 32 bytes of x in base64url.
fn public_key_of(jwk: &Value) -> Option<Vec<u8>> {
    let (Some("OKP"), Some("Ed25519"), Some(x)) = (jwk.get("kty").and_then(Value::as_str), jwk.get("crv").and_then(Value::as_str), jwk.get("x").and_then(Value::as_str)) else { return None };
    let encoded = x.len() == 43 && x.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    Some(from_b64(x)).filter(|key| encoded && key.len() == 32)
}

struct LoadedKey {
    kid: String,
    jwk: Value,
    public: Vec<u8>,
    sealed: Vec<u8>,
    private: Option<Arc<Ed25519KeyPair>>,
}

#[derive(Default)]
struct State {
    published: Vec<LoadedKey>,
    signer_kid: Option<String>,
    loaded_at: Option<Instant>,
}

const CACHE: Duration = Duration::from_secs(60);

// A PKCS#8 PrivateKeyInfo (version 0) for Ed25519 is this, then the 32-byte
// seed: the form the other server writes and reads.
const PKCS8_ED25519: [u8; 16] = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];

fn key_pair(der: &[u8]) -> Option<Ed25519KeyPair> {
    if der.len() == 48 && der[..16] == PKCS8_ED25519 {
        return Ed25519KeyPair::from_seed_unchecked(&der[16..]).ok();
    }
    Ed25519KeyPair::from_pkcs8_maybe_unchecked(der).ok()
}

pub struct KeyStore {
    state: Mutex<State>,
    loading: tokio::sync::Mutex<()>,
}

impl KeyStore {
    pub fn new() -> KeyStore {
        KeyStore { state: Mutex::new(State::default()), loading: tokio::sync::Mutex::new(()) }
    }

    fn fresh(&self) -> bool {
        self.state.lock().unwrap().loaded_at.is_some_and(|at| at.elapsed() < CACHE)
    }

    /// Re-read after a minute, so a rotation another copy made shows up here
    /// well inside the day a new key is published early. Inside a
    /// transaction, `q` is that transaction: waiting for another pool
    /// connection while holding one could wedge the pool.
    pub async fn refresh(&self, force: bool, q: Q<'_>) -> Result<()> {
        if !force && self.fresh() {
            return Ok(());
        }
        let _loading = self.loading.lock().await;
        if !force && self.fresh() {
            return Ok(());
        }
        let rows = q
            .query(
                "SELECT kid, public_jwk, private_key_enc,
                        sign_from = (SELECT max(sign_from) FROM signing_keys WHERE sign_from <= now()) AS signs
                 FROM signing_keys
                 WHERE publish_at <= now() AND (retire_at IS NULL OR retire_at > now())
                 ORDER BY sign_from",
                &[],
            )
            .await?;
        let mut state = self.state.lock().unwrap();
        // Checked before anything changes: a key already loaded isn't read again.
        for r in &rows {
            let kid: String = r.try_get("kid")?;
            if !state.published.iter().any(|k| k.kid == kid) && public_key_of(&r.try_get("public_jwk")?).is_none() {
                return Err(Error::UnreadableKey(kid));
            }
        }
        let mut previous = std::mem::take(&mut state.published);
        let mut signer_kid = None;
        for r in &rows {
            let kid: String = r.try_get("kid")?;
            if r.try_get::<_, Option<bool>>("signs")?.unwrap_or(false) && signer_kid.is_none() {
                signer_kid = Some(kid.clone());
            }
            let known = previous.iter().position(|k| k.kid == kid).map(|i| previous.swap_remove(i));
            let key = match known {
                Some(k) => k,
                None => {
                    let jwk: Value = r.try_get("public_jwk")?;
                    let public = public_key_of(&jwk).ok_or_else(|| Error::UnreadableKey(kid.clone()))?;
                    LoadedKey { kid, jwk, public, sealed: r.try_get("private_key_enc")?, private: None }
                }
            };
            state.published.push(key);
        }
        state.signer_kid = signer_kid;
        state.loaded_at = Some(Instant::now());
        Ok(())
    }

    pub async fn signer(&self, crypt: &Encrypter, q: Q<'_>) -> Result<Signer> {
        self.refresh(false, q).await?;
        let mut state = self.state.lock().unwrap();
        let kid = state.signer_kid.clone().ok_or(Error::Other("NoSigningKeyError"))?;
        let key = state.published.iter_mut().find(|k| k.kid == kid).ok_or(Error::Other("NoSigningKeyError"))?;
        if key.private.is_none() {
            let der = crypt.decrypt(&key.sealed, &key.kid).map_err(|_| Error::Other("DecryptError"))?;
            key.private = Some(Arc::new(key_pair(&der).ok_or(Error::Other("KeyError"))?));
        }
        Ok(Signer { kid, key: key.private.clone().unwrap() })
    }

    /// Synchronous lookup over the cached set; call refresh() first.
    pub fn public_key(&self, kid: &str) -> Option<Vec<u8>> {
        self.state.lock().unwrap().published.iter().find(|k| k.kid == kid).map(|k| k.public.clone())
    }

    pub async fn jwks(&self, q: Q<'_>) -> Result<Value> {
        self.refresh(false, q).await?;
        let keys: Vec<Value> = self.state.lock().unwrap().published.iter().map(|k| k.jwk.clone()).collect();
        Ok(json!({ "keys": keys }))
    }
}

// RFC 7638 thumbprint, so a kid names its key and nothing else.
fn thumbprint(x: &str) -> String {
    b64url(&sha256(json!({ "crv": "Ed25519", "kty": "OKP", "x": x }).to_string().as_bytes()))
}

pub struct NewKey {
    pub kid: String,
    pub jwk: Value,
    pub sealed: Vec<u8>,
}

pub fn generate_signing_key(crypt: &Encrypter) -> NewKey {
    let seed = random(32);
    let pair = Ed25519KeyPair::from_seed_unchecked(&seed).expect("an Ed25519 seed");
    let x = b64url(pair.public_key().as_ref());
    let kid = thumbprint(&x);
    let mut der = PKCS8_ED25519.to_vec();
    der.extend_from_slice(&seed);
    NewKey { jwk: json!({ "kty": "OKP", "crv": "Ed25519", "x": x, "kid": kid, "alg": "EdDSA", "use": "sig" }), sealed: crypt.encrypt(&der, &kid), kid }
}

/// Brings the keys up to date: a first key that signs at once; a successor
/// published a day before the current key turns 90 days old; a retirement
/// date a day after each key is superseded; and old keys removed.
pub async fn rotate_keys(pool: &deadpool_postgres::Pool, crypt: &Encrypter) -> Result<()> {
    let tx = Tx::begin(pool).await?;
    let work = async {
        let q = tx.q();
        q.query("SELECT pg_advisory_xact_lock(hashtext('auth.keys'))", &[]).await?;
        let state = q
            .one(
                "SELECT
                   (SELECT max(sign_from) FROM signing_keys WHERE sign_from <= now()) AS current_from,
                   (SELECT count(*)::int FROM signing_keys WHERE sign_from > now()) AS pending,
                   (SELECT max(sign_from) <= now() - interval '89 days' FROM signing_keys WHERE sign_from <= now()) AS due",
                &[],
            )
            .await?;
        let current_from: Option<DateTime<Utc>> = state.try_get("current_from")?;
        let pending: i32 = state.try_get("pending")?;
        let due: bool = state.try_get::<_, Option<bool>>("due")?.unwrap_or(false);
        let delay_days: Option<i32> = if current_from.is_none() && pending == 0 {
            Some(0)
        } else if due && pending == 0 {
            Some(1)
        } else {
            None
        };
        if let Some(days) = delay_days {
            let key = generate_signing_key(crypt);
            q.execute(
                "INSERT INTO signing_keys (kid, public_jwk, private_key_enc, publish_at, sign_from)
                 VALUES ($1, $2::text::jsonb, $3, now(), now() + make_interval(days => $4))",
                &[&key.kid, &key.jwk.to_string(), &key.sealed, &days],
            )
            .await?;
        }
        q.execute(
            "UPDATE signing_keys k
             SET retire_at = (SELECT min(n.sign_from) FROM signing_keys n WHERE n.sign_from > k.sign_from) + interval '1 day'
             WHERE k.retire_at IS NULL
               AND EXISTS (SELECT 1 FROM signing_keys n WHERE n.sign_from > k.sign_from AND n.sign_from <= now())",
            &[],
        )
        .await?;
        q.execute("DELETE FROM signing_keys WHERE retire_at < now() - interval '1 day'", &[]).await?;
        Ok(())
    }
    .await;
    tx.finish(work).await
}
