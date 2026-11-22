//! App passwords and API keys (docs/DESIGN.md §7.3, §9.1, §12.4, §12.5). Each
//! has at least 80 bits, so SHA-256 is enough, and the secret alone finds its
//! row. Nothing of the secret is kept or shown after it is created.

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use tokio_postgres::Row;

use crate::app::App;
use crate::audit::{audit, Audit};
use crate::crypto::{new_id, random, sha256};
use crate::db::Q;
use crate::error::{bail, Result};
use crate::events::emit;
use crate::registry::lock_service;
use crate::services::Service;
use crate::util::{b64url, base32, char_count, has_control, iso, iso_opt, js_trim, utf16_len};

#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    AppPassword,
    ApiKey,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::AppPassword => "app_password",
            Kind::ApiKey => "api_key",
        }
    }
}

pub struct CredentialRow {
    pub id: String,
    pub kind: String,
    pub service: String,
    pub scopes: Vec<String>,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

const COLUMNS: &str = "id, kind, service, scopes, name, created_at, last_used_at, expires_at";

impl CredentialRow {
    fn from_row(r: &Row) -> Result<CredentialRow> {
        Ok(CredentialRow {
            id: r.try_get("id")?,
            kind: r.try_get("kind")?,
            service: r.try_get("service")?,
            scopes: r.try_get("scopes")?,
            name: r.try_get("name")?,
            created_at: r.try_get("created_at")?,
            last_used_at: r.try_get("last_used_at")?,
            expires_at: r.try_get("expires_at")?,
        })
    }
}

pub fn credential_json(c: &CredentialRow) -> Value {
    let mut out = json!({
        "id": c.id,
        "name": c.name,
        "service": c.service,
        "scopes": c.scopes,
        "created_at": iso(&c.created_at),
        "last_used_at": iso_opt(&c.last_used_at),
    });
    if c.kind == "api_key" {
        out["expires_at"] = iso_opt(&c.expires_at);
    }
    out
}

const MAX_PER_USER: i32 = 100;

fn is_base32_char(b: u8) -> bool {
    b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)
}

// `^[a-z2-7]{4}-?[a-z2-7]{4}-?[a-z2-7]{4}-?[a-z2-7]{4}$`
fn is_app_password(s: &str) -> bool {
    let b = s.as_bytes();
    let mut at = 0;
    for group in 0..4 {
        if group > 0 && b.get(at) == Some(&b'-') {
            at += 1;
        }
        if b.len() < at + 4 || !b[at..at + 4].iter().all(|c| is_base32_char(*c)) {
            return false;
        }
        at += 4;
    }
    at == b.len()
}

fn groups_of_four(chars: &str) -> String {
    chars.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap_or("")).collect::<Vec<_>>().join("-")
}

// `xxxx-xxxx-xxxx-xxxx`: 16 base32 characters, 80 bits, easy to type into a
// phone. Hashed in this canonical form.
fn new_app_password() -> String {
    groups_of_four(&base32(&random(10)))
}

/// The hashes a presented secret could be stored under: as given (API keys,
/// and keys imported from an app's own table, §12.5), and an app password
/// typed without dashes or in capitals.
pub fn candidate_hashes(secret: &str) -> Vec<Vec<u8>> {
    let mut hashes = vec![sha256(secret.as_bytes())];
    let lower = js_trim(secret).to_lowercase();
    if is_app_password(&lower) {
        let canonical = groups_of_four(&lower.replace('-', ""));
        if canonical != secret {
            hashes.push(sha256(canonical.as_bytes()));
        }
    }
    hashes
}

pub fn scopes_of(service: &Service, kind: Kind) -> &[String] {
    match kind {
        Kind::AppPassword => &service.app_password_scopes,
        Kind::ApiKey => &service.api_key_scopes,
    }
}

pub struct NewCredential<'a> {
    pub user_id: &'a str,
    pub kind: Kind,
    pub service: &'a Service,
    pub scopes: Option<&'a Value>,
    pub name: Option<&'a Value>,
    pub expires_at: Option<&'a Value>,
    pub actor: &'a str,
    pub ip: Option<&'a str>,
}

// What `Date.parse` takes of a text that starts `YYYY-MM-DDT`: a time with
// minutes, optional seconds and fraction, and no zone, `Z`, or `±HH:MM` /
// `±HHMM`. Days run to 31 in any month, and 24:00:00 is midnight.
fn parses_as_date(s: &str) -> bool {
    let b = s.as_bytes();
    let two = |at: usize| -> Option<u32> {
        let d = b.get(at..at + 2)?;
        d.iter().all(u8::is_ascii_digit).then(|| u32::from(d[0] - b'0') * 10 + u32::from(d[1] - b'0'))
    };
    let shaped = b.len() >= 16 && b[..4].iter().all(u8::is_ascii_digit) && b[4] == b'-' && b[7] == b'-' && b[10] == b'T' && b[13] == b':';
    if !shaped {
        return false;
    }
    let (Some(month), Some(day), Some(hour), Some(minute)) = (two(5), two(8), two(11), two(14)) else { return false };
    let mut at = 16;
    let mut second = 0;
    let mut fraction = false;
    if b.get(at) == Some(&b':') {
        let Some(sec) = two(at + 1) else { return false };
        second = sec;
        at += 3;
        if b.get(at) == Some(&b'.') {
            let digits = b[at + 1..].iter().take_while(|c| c.is_ascii_digit()).count();
            if digits == 0 {
                return false;
            }
            fraction = b[at + 1..at + 1 + digits].iter().any(|c| *c != b'0');
            at += 1 + digits;
        }
    }
    let zone = &b[at..];
    let zone_ok = match zone {
        [] | [b'Z'] | [b'z'] => true,
        [b'+' | b'-', rest @ ..] => {
            let digits: Vec<u8> = match rest {
                [h1, h2, b':', m1, m2] | [h1, h2, m1, m2] => vec![*h1, *h2, *m1, *m2],
                _ => return false,
            };
            digits.iter().all(u8::is_ascii_digit) && (digits[0] - b'0') * 10 + (digits[1] - b'0') <= 23 && (digits[2] - b'0') * 10 + (digits[3] - b'0') <= 59
        }
        _ => false,
    };
    zone_ok && (1..=12).contains(&month) && (1..=31).contains(&day) && minute <= 59 && second <= 59 && (hour <= 23 || (hour == 24 && minute == 0 && second == 0 && !fraction))
}

/// Creates a credential, and answers with its row and its secret, shown once.
pub async fn create_credential(q: Q<'_>, app: &App, c: &NewCredential<'_>) -> Result<(CredentialRow, String)> {
    let locked = lock_service(q, c.service).await?;
    let declared = scopes_of(&locked, c.kind);
    let label = if c.kind == Kind::AppPassword { "app passwords" } else { "API keys" };
    let service = &c.service.name;
    if declared.is_empty() {
        bail!(400, "invalid_request", "{service} takes no {label}.");
    }
    let listed = c.scopes.and_then(Value::as_array).filter(|l| !l.is_empty() && l.iter().all(|s| s.as_str().is_some_and(|s| declared.iter().any(|d| d == s))));
    let Some(listed) = listed else { bail!(400, "invalid_request", "scopes must be a non-empty list from: {}.", declared.join(", ")) };
    let mut scopes: Vec<String> = Vec::new();
    for s in listed.iter().filter_map(Value::as_str) {
        if !scopes.iter().any(|x| x == s) {
            scopes.push(s.to_string());
        }
    }
    let name = match c.name.and_then(Value::as_str).filter(|n| !js_trim(n).is_empty() && char_count(n) <= 100 && !has_control(n)) {
        Some(n) => js_trim(n).to_string(),
        None => bail!(400, "invalid_request", "name is 1 to 100 characters, with no control characters."),
    };
    let mut expires_at: Option<String> = None;
    if c.kind == Kind::ApiKey {
        if let Some(given) = c.expires_at.filter(|v| !v.is_null()) {
            let Some(text) = given.as_str().filter(|t| parses_as_date(t)) else { bail!(400, "invalid_request", "expires_at must be an RFC 3339 timestamp.") };
            // A date the calendar doesn't have (30 February) reads as a later
            // one above; Postgres knows better.
            if !q.one("SELECT pg_input_is_valid($1, 'timestamptz') AS ok", &[&text]).await?.try_get::<_, bool>("ok")? {
                bail!(400, "invalid_request", "expires_at must be an RFC 3339 timestamp.");
            }
            if !q.one("SELECT $1::text::timestamptz > now() AS ok", &[&text]).await?.try_get::<_, bool>("ok")? {
                bail!(400, "invalid_request", "expires_at must be in the future.");
            }
            expires_at = Some(text.to_string());
        }
    }
    if q.first("SELECT 1 FROM access WHERE user_id = $1 AND service = $2", &[&c.user_id, service]).await?.is_none() {
        bail!(403, "forbidden", "You need a role on {service} to create {label} for it.");
    }
    let count: i32 = q.one("SELECT count(*)::int AS n FROM credentials WHERE user_id = $1 AND kind = $2 AND revoked_at IS NULL", &[&c.user_id, &c.kind.as_str()]).await?.try_get("n")?;
    if count >= MAX_PER_USER {
        bail!(409, "conflict", "You have {MAX_PER_USER} {label}; revoke one first.");
    }

    let id = new_id(if c.kind == Kind::AppPassword { "apw" } else { "key" });
    let secret = match c.kind {
        Kind::AppPassword => new_app_password(),
        Kind::ApiKey => match &app.config.api_key_prefix {
            Some(prefix) => format!("{prefix}_{id}_{}", b64url(&random(32))),
            None => bail!(500, "server_error", "API_KEY_PREFIX is not configured."),
        },
    };
    let row = q
        .one(
            &format!(
                "INSERT INTO credentials (id, user_id, kind, service, scopes, name, secret_hash, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::text::timestamptz)
                 RETURNING {COLUMNS}"
            ),
            &[&id, &c.user_id, &c.kind.as_str(), service, &scopes, &name, &sha256(secret.as_bytes()), &expires_at],
        )
        .await?;
    audit(q, Audit::new(Some(c.actor), &format!("{}.create", c.kind.as_str())).user(Some(c.user_id)).ip(c.ip).detail(json!({ "id": id, "service": service, "scopes": scopes }))).await?;
    Ok((CredentialRow::from_row(&row)?, secret))
}

pub async fn list_credentials(q: Q<'_>, user_id: &str, kind: Kind) -> Result<Vec<CredentialRow>> {
    let rows = q.query(&format!("SELECT {COLUMNS} FROM credentials WHERE user_id = $1 AND kind = $2 AND revoked_at IS NULL ORDER BY id"), &[&user_id, &kind.as_str()]).await?;
    rows.iter().map(CredentialRow::from_row).collect()
}

pub async fn revoke_credential(q: Q<'_>, app: &App, user_id: &str, kind: Kind, id: &str, actor: &str, ip: Option<&str>) -> Result<bool> {
    let rows = q.query("UPDATE credentials SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND kind = $3 AND revoked_at IS NULL RETURNING service", &[&id, &user_id, &kind.as_str()]).await?;
    let Some(row) = rows.first() else { return Ok(false) };
    let service: String = row.try_get("service")?;
    audit(q, Audit::new(Some(actor), &format!("{}.revoke", kind.as_str())).user(Some(user_id)).ip(ip).detail(json!({ "id": id, "service": service }))).await?;
    emit(q, app, &service, "credential.revoked", json!({ "sub": user_id, "id": id })).await?;
    Ok(true)
}

pub struct Introspected {
    pub id: String,
    pub user_id: String,
    pub username: String,
    pub scopes: Vec<String>,
    pub role: String,
}

/// An active credential of the calling service only: unexpired, unrevoked, its
/// owner enabled and holding a role there (§7.2). The service filter is in
/// the query, so no other service's credential is ever read.
pub async fn introspect_secret(q: Q<'_>, service: &str, secret: &str) -> Result<Option<Introspected>> {
    if secret.is_empty() || utf16_len(secret) > 512 {
        return Ok(None);
    }
    let hashes = candidate_hashes(secret);
    let row = q
        .first(
            "SELECT c.id, c.user_id, c.scopes, u.username, a.role,
                    c.last_used_at IS NULL OR c.last_used_at < now() - interval '1 minute' AS stale
             FROM credentials c
             JOIN users u ON u.id = c.user_id
             JOIN access a ON a.user_id = c.user_id AND a.service = c.service
             WHERE c.secret_hash IN ($1, $2)
               AND c.service = $3
               AND c.revoked_at IS NULL
               AND (c.expires_at IS NULL OR c.expires_at > now())
               AND u.disabled_at IS NULL",
            &[&hashes[0], hashes.get(1).unwrap_or(&hashes[0]), &service],
        )
        .await?;
    let Some(row) = row else { return Ok(None) };
    let id: String = row.try_get("id")?;
    if row.try_get::<_, bool>("stale")? {
        q.execute("UPDATE credentials SET last_used_at = now() WHERE id = $1", &[&id]).await?;
    }
    Ok(Some(Introspected { id, user_id: row.try_get("user_id")?, username: row.try_get("username")?, scopes: row.try_get("scopes")?, role: row.try_get("role")? }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_app_password_is_found_however_it_was_typed() {
        assert_eq!(candidate_hashes("abcd-efgh-ijkl-mnop").len(), 1);
        assert_eq!(candidate_hashes("ABCDEFGHIJKLMNOP")[1], sha256(b"abcd-efgh-ijkl-mnop"));
        assert_eq!(candidate_hashes(" abcd-efgh-ijkl-mnop ")[1], sha256(b"abcd-efgh-ijkl-mnop"));
        assert_eq!(candidate_hashes("abcd-efgh-ijkl-mno1").len(), 1);
        assert_eq!(candidate_hashes("testkey_key_x").len(), 1);
    }

    #[test]
    fn expiry_texts_read_as_date_parse_reads_them() {
        for ok in [
            "2026-11-12T10:00",
            "2026-11-12T10:00:00",
            "2026-11-12T10:00:00.1",
            "2026-11-12T10:00:00.1234567890123Z",
            "2026-11-12T24:00",
            "2026-11-12T24:00:00.000",
            "2026-11-12T10:00:00z",
            "2026-11-12T10:00:00+01:00",
            "2026-11-12T10:00:00-0100",
            "2026-11-12T10:00+23:59",
            "2026-02-30T00:00:00Z",
            "0000-01-01T00:00:00Z",
        ] {
            assert!(parses_as_date(ok), "{ok}");
        }
        for bad in [
            "2026-11-12T",
            "2026-11-12T10",
            "2026-11-12T25:00:00Z",
            "2026-11-12T24:00:01",
            "2026-11-12T24:00:00.001",
            "2026-11-12T23:60",
            "2026-11-12T23:59:60",
            "2026-13-12T10:00:00Z",
            "2026-00-12T10:00:00Z",
            "2026-11-32T10:00:00Z",
            "2026-11-00T10:00:00Z",
            "2026-11-12T10:00:00.Z",
            "2026-11-12T10:00:00+01",
            "2026-11-12T10:00:00+24:00",
            "2026-11-12T10:00:00+12:60",
            "2026-11-12T10:00:00 Z",
            "2026-11-12T10:00:00Z ",
            "2026-11-12t10:00:00Z",
            "2026-11-12T1:00:00Z",
            "2026-11-12T10:00:00,5Z",
            "2026-11-12T10:00:00+1:00",
            "2026-11-12T10:00:00 GMT",
            "2026-11-12 10:00:00Z",
        ] {
            assert!(!parses_as_date(bad), "{bad}");
        }
    }
}
