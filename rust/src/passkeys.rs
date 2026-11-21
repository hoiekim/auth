//! Passkeys (docs/DESIGN.md §9.1). The RP ID is the issuer's host, not its
//! parent domain, so a sibling subdomain can never ask for an assertion.
//! User verification is required, so a passkey is two factors by itself.
//! Attestation is "none". The challenge travels sealed and is accepted once.

use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use crate::app::App;
use crate::crypto::new_id;
use crate::db::Q;
use crate::error::Result;
use crate::throttle::once;
use crate::util::{from_b64, iso, iso_opt};
use crate::webauthn::{creation_options, new_challenge, request_options, verify_assertion, verify_registration, RelyingParty};

const CHALLENGE_SECONDS: i64 = 5 * 60;

fn rp(app: &App) -> RelyingParty {
    let host = url::Url::parse(&app.config.issuer).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default();
    RelyingParty { id: host, origin: app.config.issuer.clone() }
}

pub fn passkey_json(id: &str, name: &str, created_at: &DateTime<Utc>, last_used_at: &Option<DateTime<Utc>>) -> Value {
    json!({ "id": id, "name": name, "created_at": iso(created_at), "last_used_at": iso_opt(last_used_at) })
}

pub async fn list_passkeys(q: Q<'_>, user_id: &str) -> Result<Vec<Value>> {
    let rows = q.query("SELECT id, name, created_at, last_used_at FROM passkeys WHERE user_id = $1 ORDER BY created_at", &[&user_id]).await?;
    let mut out = Vec::new();
    for r in &rows {
        out.push(passkey_json(&r.try_get::<_, String>("id")?, &r.try_get::<_, String>("name")?, &r.try_get("created_at")?, &r.try_get("last_used_at")?));
    }
    Ok(out)
}

pub async fn registration_options(app: &App, user_id: &str, username: &str, name: &str, attachment: Option<&str>) -> Result<Value> {
    let rows = app.db().query("SELECT credential_id FROM passkeys WHERE user_id = $1", &[&user_id]).await?;
    let mut existing: Vec<Vec<u8>> = Vec::new();
    for r in &rows {
        existing.push(r.try_get("credential_id")?);
    }
    let challenge = new_challenge();
    let options = creation_options(&rp(app), &challenge, user_id.as_bytes(), username, if name.is_empty() { username } else { name }, &existing, attachment);
    let registration = app.crypt.seal_value("passkey-reg", &json!({ "u": user_id, "c": challenge }), CHALLENGE_SECONDS);
    Ok(json!({ "options": options, "registration": registration }))
}

/// The new passkey's id, or None when the response doesn't verify.
pub async fn finish_registration(q: Q<'_>, app: &App, user_id: &str, registration: Option<&Value>, response: Option<&Value>, name: &str) -> Result<Option<String>> {
    let Some(sealed) = app.crypt.open_value("passkey-reg", registration.and_then(Value::as_str)) else { return Ok(None) };
    let (Some(challenge), Some(response)) = (sealed.get("c").and_then(Value::as_str), response.filter(|r| r.is_object())) else { return Ok(None) };
    if sealed.get("u").and_then(Value::as_str) != Some(user_id) {
        return Ok(None);
    }
    if !once(q, &format!("once:webauthn:{challenge}")).await? {
        return Ok(None);
    }
    let Some(cred) = verify_registration(&rp(app), challenge, response) else { return Ok(None) };
    let id = new_id("pk");
    let rows = q
        .query(
            "INSERT INTO passkeys (id, user_id, credential_id, public_key, sign_count, name) VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (credential_id) DO NOTHING RETURNING id",
            &[&id, &user_id, &cred.id, &cred.public_key, &cred.sign_count, &name],
        )
        .await?;
    Ok((rows.len() == 1).then_some(id))
}

/// Options for a discoverable-credential sign-in: no username, so nothing
/// about who has passkeys is revealed. The sealed challenge goes in a cookie.
pub fn authentication_options(app: &App) -> (Value, String) {
    let challenge = new_challenge();
    (request_options(&rp(app), &challenge), app.crypt.seal_value("passkey-auth", &json!({ "c": challenge }), CHALLENGE_SECONDS))
}

/// The user a passkey assertion proves, or None. Updates the signature
/// counter, which verify_assertion refuses to see go backwards.
pub async fn finish_authentication(app: &App, state: Option<&str>, response: Option<&Value>) -> Result<Option<String>> {
    let Some(sealed) = app.crypt.open_value("passkey-auth", state) else { return Ok(None) };
    let Some(challenge) = sealed.get("c").and_then(Value::as_str) else { return Ok(None) };
    let Some(response) = response.filter(|r| r.is_object()) else { return Ok(None) };
    let Some(credential_id) = response.get("id").and_then(Value::as_str) else { return Ok(None) };
    let q = app.db();
    let row = q
        .first(
            "SELECT p.id, p.user_id, p.credential_id, p.public_key, p.sign_count
             FROM passkeys p JOIN users u ON u.id = p.user_id
             WHERE p.credential_id = $1 AND u.disabled_at IS NULL AND u.kind = 'person'",
            &[&from_b64(credential_id)],
        )
        .await?;
    let Some(row) = row else { return Ok(None) };
    if !once(q, &format!("once:webauthn:{challenge}")).await? {
        return Ok(None);
    }
    let Some(sign_count) = verify_assertion(&rp(app), challenge, &row.try_get::<_, Vec<u8>>("public_key")?, row.try_get("sign_count")?, response) else { return Ok(None) };
    q.execute("UPDATE passkeys SET sign_count = $2, last_used_at = now() WHERE id = $1", &[&row.try_get::<_, String>("id")?, &sign_count]).await?;
    Ok(Some(row.try_get("user_id")?))
}
