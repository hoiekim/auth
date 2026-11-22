//! Second factors (docs/DESIGN.md §9.1): TOTP and recovery codes. Passkeys are
//! in passkeys.rs.

use serde_json::{json, Value};

use crate::app::App;
use crate::crypto::{random, sha256};
use crate::db::Q;
use crate::error::Result;
use crate::totp::{matching_step, new_totp_secret, otpauth_uri};
use crate::util::{base32, from_base32, is_js_space, js_trim, now_ms};

pub struct Factors {
    pub totp: bool,
    pub passkeys: i32,
    pub recovery_codes: i32,
}

impl Factors {
    pub fn json(&self) -> Value {
        json!({ "totp": self.totp, "passkeys": self.passkeys, "recovery_codes": self.recovery_codes })
    }
}

pub async fn factors_of(q: Q<'_>, user_id: &str) -> Result<Factors> {
    let row = q
        .one(
            "SELECT EXISTS (SELECT 1 FROM totp WHERE user_id = $1) AS totp,
                    (SELECT count(*)::int FROM passkeys WHERE user_id = $1) AS passkeys,
                    (SELECT count(*)::int FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL) AS recovery_codes",
            &[&user_id],
        )
        .await?;
    Ok(Factors { totp: row.try_get("totp")?, passkeys: row.try_get("passkeys")?, recovery_codes: row.try_get("recovery_codes")? })
}

// Enrolment is two steps with nothing stored between them: the secret
// travels sealed, bound to the user, and is saved only once a code from it
// is confirmed.
const ENROLL_SECONDS: i64 = 15 * 60;

pub fn start_totp_enrolment(app: &App, user_id: &str, username: &str) -> Value {
    let secret = new_totp_secret();
    let host = url::Url::parse(&app.config.issuer).ok().map(|u| match (u.host_str(), u.port()) {
        (Some(h), Some(p)) => format!("{h}:{p}"),
        (Some(h), None) => h.to_string(),
        _ => String::new(),
    });
    json!({
        "otpauth_uri": otpauth_uri(&secret, &host.unwrap_or_default(), username),
        "secret": base32(&secret).to_uppercase(),
        "enrollment": app.crypt.seal_value("totp-enrol", &json!({ "u": user_id, "s": base32(&secret) }), ENROLL_SECONDS),
    })
}

/// Saves the secret if `code` matches it; the step used becomes last_step, so
/// the confirming code can't be replayed at sign-in.
pub async fn confirm_totp_enrolment(q: Q<'_>, app: &App, user_id: &str, enrollment: Option<&Value>, code: Option<&Value>) -> Result<bool> {
    let Some(sealed) = app.crypt.open_value("totp-enrol", enrollment.and_then(Value::as_str)) else { return Ok(false) };
    let (Some(code), true) = (code.and_then(Value::as_str), sealed.get("u").and_then(Value::as_str) == Some(user_id)) else { return Ok(false) };
    let Some(secret) = sealed.get("s").and_then(Value::as_str).and_then(from_base32) else { return Ok(false) };
    let Some(step) = matching_step(&secret, js_trim(code), now_ms().div_euclid(1000), 0) else { return Ok(false) };
    q.execute(
        "INSERT INTO totp (user_id, secret_enc, last_step) VALUES ($1, $2, $3)
         ON CONFLICT (user_id) DO UPDATE SET secret_enc = EXCLUDED.secret_enc, last_step = EXCLUDED.last_step, created_at = now()",
        &[&user_id, &app.crypt.encrypt(&secret, user_id), &step],
    )
    .await?;
    Ok(true)
}

/// A code is accepted once: the update only succeeds while last_step is
/// below the code's step, so two requests racing with one code can't both pass.
pub async fn check_totp(q: Q<'_>, app: &App, user_id: &str, code: &str) -> Result<bool> {
    let Some(row) = q.first("SELECT secret_enc, last_step FROM totp WHERE user_id = $1", &[&user_id]).await? else { return Ok(false) };
    let Ok(secret) = app.crypt.decrypt(&row.try_get::<_, Vec<u8>>("secret_enc")?, user_id) else { return Ok(false) };
    let Some(step) = matching_step(&secret, js_trim(code), now_ms().div_euclid(1000), row.try_get("last_step")?) else { return Ok(false) };
    let updated = q.query("UPDATE totp SET last_step = $2 WHERE user_id = $1 AND last_step < $2 RETURNING 1", &[&user_id, &step]).await?;
    Ok(updated.len() == 1)
}

pub async fn remove_totp(q: Q<'_>, user_id: &str) -> Result<bool> {
    Ok(q.query("DELETE FROM totp WHERE user_id = $1 RETURNING 1", &[&user_id]).await?.len() == 1)
}

/// 10 codes of 24 base32 characters (120 bits), shown as six groups of four.
/// At this length a code is stored and found by its SHA-256, like an app
/// password (§9.1).
pub async fn new_recovery_codes(q: Q<'_>, user_id: &str) -> Result<Vec<String>> {
    let codes: Vec<String> = (0..10).map(|_| base32(&random(15))).collect();
    q.execute("DELETE FROM recovery_codes WHERE user_id = $1", &[&user_id]).await?;
    for code in &codes {
        q.execute("INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)", &[&user_id, &sha256(code.as_bytes())]).await?;
    }
    Ok(codes.iter().map(|c| c.as_bytes().chunks(4).map(|g| std::str::from_utf8(g).unwrap_or("")).collect::<Vec<_>>().join("-")).collect())
}

pub fn canonical_recovery_code(input: &str) -> Option<String> {
    let clean: String = input.to_lowercase().chars().filter(|c| !is_js_space(*c) && *c != '-').collect();
    (clean.len() == 24 && clean.bytes().all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))).then_some(clean)
}

/// One indexed lookup scoped to the account, the same cost whether or not the
/// account exists or has codes left. Marks the code used; true if it was
/// unused.
pub async fn use_recovery_code(q: Q<'_>, user_id: Option<&str>, input: &str) -> Result<bool> {
    let code = canonical_recovery_code(input);
    let rows = q
        .query(
            "UPDATE recovery_codes SET used_at = now() WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL RETURNING 1",
            &[&user_id.unwrap_or(""), &sha256(code.as_deref().unwrap_or(input).as_bytes())],
        )
        .await?;
    Ok(code.is_some() && rows.len() == 1)
}

/// Whether an unused code matches, without using it: so a step that can
/// still fail after the code is checked doesn't spend it.
pub async fn recovery_code_valid(q: Q<'_>, user_id: Option<&str>, input: &str) -> Result<bool> {
    let code = canonical_recovery_code(input);
    let rows =
        q.query("SELECT 1 FROM recovery_codes WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL", &[&user_id.unwrap_or(""), &sha256(code.as_deref().unwrap_or(input).as_bytes())]).await?;
    Ok(code.is_some() && rows.len() == 1)
}

/// A sign-in's second factor: a TOTP code or, failing that, a recovery code.
/// Answers "otp" or "recovery".
pub async fn check_second_factor(q: Q<'_>, app: &App, user_id: &str, input: &str) -> Result<Option<&'static str>> {
    let value = js_trim(input);
    if value.len() == 6 && value.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(check_totp(q, app, user_id, value).await?.then_some("otp"));
    }
    Ok(use_recovery_code(q, Some(user_id), value).await?.then_some("recovery"))
}
