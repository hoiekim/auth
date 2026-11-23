//! Moving an app's users and API keys into auth (docs/DESIGN.md §12.5, §13).
//! One JSON object per line. Every line is checked before anything is
//! written, every problem is listed by line number, and no value that can be
//! a secret or an address is echoed. Then all rows are written in one
//! transaction, or none.

use std::sync::Arc;

use serde_json::{json, Map, Value};

use crate::access::{put_access, Grant};
use crate::app::App;
use crate::audit::{audit, Audit};
use crate::crypto::{is_id, new_id};
use crate::error::Result;
use crate::json::{discard, Held};
use crate::mail::is_email_address;
use crate::registry::lock_service;
use crate::services::Service;
use crate::tokens::{issue_token, Purpose};
use crate::users::{insert_user, is_username, NewUser, MAX_NAME};
use crate::util::{char_count, first_number, from_b64, from_hex, has_control, hex, js_trim, utf16_len, utf16_prefix};

const ACTOR: &str = "host-cli";

// Enough for a deployment's users in one go, and few enough that each check
// stays one query and the whole run stays small beside the server in its
// container (§10). Larger imports are split into several files.
pub const MAX_LINES: usize = 10_000;

// Blank lines are skipped; a line that isn't a JSON object is a problem. A
// line can nest as deep as the input is long, so each is held in `Held`.
fn parse_lines(text: &str, problems: &mut Vec<String>) -> Vec<(usize, Held<Map<String, Value>>)> {
    let raws: Vec<&str> = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l)).collect();
    if raws.iter().filter(|r| !js_trim(r).is_empty()).count() > MAX_LINES {
        problems.push(format!("the input has more than {MAX_LINES} lines; split it"));
        return Vec::new();
    }
    let mut out = Vec::new();
    for (i, raw) in raws.iter().enumerate() {
        if js_trim(raw).is_empty() {
            continue;
        }
        match crate::json::parse(raw) {
            None => problems.push(format!("line {}: not valid JSON", i + 1)),
            Some(Value::Object(value)) => out.push((i + 1, Held(value))),
            Some(other) => {
                discard(other);
                problems.push(format!("line {}: not a JSON object", i + 1));
            }
        }
    }
    if out.is_empty() && problems.is_empty() {
        problems.push("the input has no lines".into());
    }
    out
}

fn unknown_fields(value: &Map<String, Value>, allowed: &[&str], problems: &mut Vec<String>, n: usize) {
    for key in value.keys() {
        if !allowed.contains(&key.as_str()) {
            problems.push(format!("line {n}: unknown field \"{}\"", utf16_prefix(key, 40)));
        }
    }
}

fn digits(s: &str) -> Option<u32> {
    (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse().ok()).flatten()
}

// RFC 3339 with a zone, as the API takes, and a real calendar date.
// `^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d)(?::(\d\d)(?:\.\d{1,6})?)?(?:Z|[+-](\d\d):(\d\d))$`
fn is_timestamp(value: &str) -> bool {
    let b = value.as_bytes();
    let shaped = b.len() >= 17 && value.is_ascii() && b[4] == b'-' && b[7] == b'-' && b[10] == b'T' && b[13] == b':';
    if !shaped {
        return false;
    }
    let (Some(y), Some(mo), Some(d), Some(h), Some(mi)) = (digits(&value[..4]), digits(&value[5..7]), digits(&value[8..10]), digits(&value[11..13]), digits(&value[14..16])) else {
        return false;
    };
    let mut rest = &value[16..];
    let mut s = 0;
    if let Some(after) = rest.strip_prefix(':') {
        let Some(sec) = after.get(..2).and_then(digits) else { return false };
        s = sec;
        rest = &after[2..];
        if let Some(fraction) = rest.strip_prefix('.') {
            let n = fraction.bytes().take_while(u8::is_ascii_digit).count();
            if !(1..=6).contains(&n) {
                return false;
            }
            rest = &fraction[n..];
        }
    }
    let (oh, om) = match rest.as_bytes() {
        [b'Z'] => (0, 0),
        [b'+' | b'-', _, _, b':', _, _] => match (digits(&rest[1..3]), digits(&rest[4..6])) {
            (Some(oh), Some(om)) => (oh, om),
            _ => return false,
        },
        _ => return false,
    };
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days = match mo {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    y >= 1 && (1..=12).contains(&mo) && (1..=days).contains(&d) && h <= 23 && mi <= 59 && s <= 59 && oh <= 15 && om <= 59
}

// Some(None) for an absent or null field, Some(Some(text)) for a timestamp,
// None for anything else.
fn timestamp(value: Option<&Value>) -> Option<Option<String>> {
    match value {
        None | Some(Value::Null) => Some(None),
        Some(Value::String(s)) if is_timestamp(s) => Some(Some(s.clone())),
        Some(_) => None,
    }
}

// An imported hash is verified at its own cost until the first sign-in
// rehashes it, behind the same hashing slot. More memory than §9.1's
// 19 MiB would break the 19 MiB budget that slot keeps (§10), so such a
// hash is refused and its user takes an activation link instead; time is
// bounded so one attempt can't hold the slot for long.
const MAX_ARGON2_MEMORY_KIB: u64 = 19456;
const MAX_ARGON2_TIME: u64 = 3;
const MAX_ARGON2_PARALLELISM: u64 = 4;
const MAX_BCRYPT_COST: u64 = 12;

fn is_b64(s: &str, extra: &[u8]) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
}

// `^\$argon2(?:id|i|d)\$v=\d+\$m=(\d+),t=(\d+),p=(\d+)\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$`
fn argon2_costs(hash: &str) -> Option<(u64, u64, u64)> {
    let parts: Vec<&str> = hash.split('$').collect();
    let [empty, algorithm, version, params, salt, digest] = parts.as_slice() else { return None };
    let version_ok = version.strip_prefix("v=").is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()));
    if !empty.is_empty() || !matches!(*algorithm, "argon2id" | "argon2i" | "argon2d") || !version_ok || !is_b64(salt, b"+/") || !is_b64(digest, b"+/") {
        return None;
    }
    let fields: Vec<&str> = params.split(',').collect();
    let [m, t, p] = fields.as_slice() else { return None };
    let number = |field: &str, prefix: &str| field.strip_prefix(prefix).filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())).map(|v| v.parse::<u64>().unwrap_or(u64::MAX));
    Some((number(m, "m=")?, number(t, "t=")?, number(p, "p=")?))
}

// `^\$2[aby]\$(\d{2})\$[./A-Za-z0-9]{53}$`
fn bcrypt_cost(hash: &str) -> Option<u64> {
    let parts: Vec<&str> = hash.split('$').collect();
    let [empty, version, cost, rest] = parts.as_slice() else { return None };
    let ok = empty.is_empty() && matches!(*version, "2a" | "2b" | "2y") && cost.len() == 2 && rest.len() == 53 && is_b64(rest, b"./");
    ok.then(|| digits(cost)).flatten().map(u64::from)
}

// The PHC strings a sign-in can verify: argon2 and bcrypt (§13).
fn hash_problem(hash: &str) -> Option<String> {
    if let Some((m, t, p)) = argon2_costs(hash) {
        return (m > MAX_ARGON2_MEMORY_KIB || t > MAX_ARGON2_TIME || p > MAX_ARGON2_PARALLELISM).then(|| {
            format!(
                "password_hash costs more than this service verifies (argon2 at most m={MAX_ARGON2_MEMORY_KIB}, t={MAX_ARGON2_TIME}, p={MAX_ARGON2_PARALLELISM}); leave it out and the user gets an activation link"
            )
        });
    }
    if let Some(cost) = bcrypt_cost(hash) {
        return (cost > MAX_BCRYPT_COST)
            .then(|| format!("password_hash costs more than this service verifies (bcrypt cost at most {MAX_BCRYPT_COST}); leave it out and the user gets an activation link"));
    }
    Some("password_hash is not an argon2 or bcrypt PHC string".into())
}

pub struct ImportedUser {
    pub username: String,
    pub email: String,
    /// An activation link's token, for users imported without a password.
    pub activation: Option<String>,
}

struct CheckedUser {
    username: String,
    email: String,
    name: String,
    verified: bool,
    hash: Option<String>,
    grants: Vec<(Arc<Service>, String)>,
}

fn sort_by_line(problems: &mut [String]) {
    problems.sort_by_key(|p| first_number(p));
}

// The write is one transaction, so a failure part-way leaves nothing behind.
// It is reported by the error's name only: a database message can quote a
// value from the input.
fn write_failed(e: &crate::error::Error) -> Vec<String> {
    vec![format!("writing failed ({}); nothing was written", e.name())]
}

/// The problems found, and the users written (none when there is a problem,
/// or on a dry run).
pub async fn import_users(app: &App, text: &str, dry_run: bool) -> Result<(Vec<String>, Vec<ImportedUser>)> {
    let mut problems: Vec<String> = Vec::new();
    let lines = parse_lines(text, &mut problems);
    let mut usernames: Vec<(String, usize)> = Vec::new();
    let mut emails: Vec<(String, usize)> = Vec::new();
    let mut checked: Vec<CheckedUser> = Vec::new();

    for (n, v) in &lines {
        let n = *n;
        let mut unknown = Vec::new();
        unknown_fields(v, &["username", "email", "name", "email_verified", "password_hash", "access"], &mut unknown, n);
        problems.extend(unknown);
        let mut p = |msg: String| problems.push(format!("line {n}: {msg}"));
        let username = v.get("username").and_then(Value::as_str).unwrap_or("").to_string();
        if !is_username(&username) {
            p("username must be 3 to 32 characters: a–z, 0–9 and '-', starting with a letter and not ending with '-'".into());
        } else if let Some((_, first)) = usernames.iter().find(|(u, _)| *u == username) {
            p(format!("username is also on line {first}"));
        } else {
            usernames.push((username.clone(), n));
        }
        let email = v.get("email").and_then(Value::as_str).map(js_trim).unwrap_or("").to_string();
        let lower = email.to_lowercase();
        if !is_email_address(&email) {
            p("email is not an email address".into());
        } else if let Some((_, first)) = emails.iter().find(|(e, _)| *e == lower) {
            p(format!("email is also on line {first}"));
        } else {
            emails.push((lower, n));
        }
        let name = match v.get("name") {
            None => Some(""),
            Some(Value::String(s)) if char_count(s) <= MAX_NAME && !has_control(s) => Some(s.as_str()),
            Some(_) => None,
        };
        if name.is_none() {
            p(format!("name must be text of at most {MAX_NAME} characters"));
        }
        if v.get("email_verified").is_some_and(|e| !e.is_boolean()) {
            p("email_verified must be true or false".into());
        }
        let mut hash = None;
        if let Some(given) = v.get("password_hash").filter(|h| !h.is_null()) {
            let problem = match given.as_str().filter(|s| utf16_len(s) <= 512) {
                None => Some("password_hash is not an argon2 or bcrypt PHC string".to_string()),
                Some(s) => hash_problem(s),
            };
            match problem {
                Some(problem) => p(problem),
                None => hash = given.as_str().map(str::to_string),
            }
        }
        let mut grants = Vec::new();
        match v.get("access") {
            None => {}
            Some(Value::Object(access)) => {
                for (service_name, role) in access {
                    match (app.services.get(service_name), role.as_str()) {
                        (None, _) => p("access names a service auth doesn't have".into()),
                        (Some(service), Some(role)) if service.has_role(role) => grants.push((service.clone(), role.to_string())),
                        (Some(service), _) => p(format!("access gives {} a role it doesn't declare", service.name)),
                    }
                }
            }
            Some(_) => p("access must be an object of service: role".into()),
        }
        checked.push(CheckedUser { username, email, name: js_trim(name.unwrap_or("")).to_string(), verified: v.get("email_verified") == Some(&Value::Bool(true)), hash, grants });
    }

    // Against what auth already has, in two queries rather than one per line.
    if !usernames.is_empty() {
        let names: Vec<&str> = usernames.iter().map(|(u, _)| u.as_str()).collect();
        for r in &app.db().query("SELECT username FROM users WHERE username = ANY($1)", &[&names]).await? {
            let taken: String = r.try_get("username")?;
            if let Some((_, n)) = usernames.iter().find(|(u, _)| *u == taken) {
                problems.push(format!("line {n}: username is taken"));
            }
        }
    }
    if !emails.is_empty() {
        let addresses: Vec<&str> = emails.iter().map(|(e, _)| e.as_str()).collect();
        for r in &app.db().query("SELECT lower(email) AS email FROM users WHERE lower(email) = ANY($1)", &[&addresses]).await? {
            let taken: String = r.try_get("email")?;
            if let Some((_, n)) = emails.iter().find(|(e, _)| *e == taken) {
                problems.push(format!("line {n}: email is used by another account"));
            }
        }
    }
    sort_by_line(&mut problems);
    if !problems.is_empty() || dry_run {
        return Ok((problems, Vec::new()));
    }

    let tx = app.begin().await?;
    let work = async {
        let mut done = Vec::new();
        for u in &checked {
            let new = NewUser { username: &u.username, name: &u.name, email: Some(&u.email), email_verified: u.verified, kind: "person", owner_id: None, password_hash: u.hash.as_deref() };
            let id = insert_user(tx.q(), &new).await?;
            audit(tx.q(), Audit::new(Some(ACTOR), "user.create").user(Some(&id)).detail(json!({ "username": u.username, "kind": "person", "imported": true }))).await?;
            for (service, role) in &u.grants {
                put_access(&tx, app, &Grant { user_id: &id, service, role, actor: ACTOR, ip: None, reason: Some("import"), never_lower: false }).await?;
            }
            let activation = match u.hash {
                Some(_) => None,
                None => Some(issue_token(tx.q(), Purpose::Activate, &id, Some(&u.email)).await?),
            };
            done.push(ImportedUser { username: u.username.clone(), email: u.email.clone(), activation });
        }
        Ok(done)
    }
    .await;
    match tx.finish(work).await {
        Ok(rows) => Ok((Vec::new(), rows)),
        Err(e) => Ok((write_failed(&e), Vec::new())),
    }
}

// What an owner may hold at once (credentials.rs), so their list stays one page.
const MAX_KEYS_PER_OWNER: i64 = 100;

// A key's SHA-256: 64 hex characters, or 32 bytes in base64 or base64url.
fn digest(value: Option<&Value>) -> Option<Vec<u8>> {
    let value = value?.as_str()?;
    if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return from_hex(value);
    }
    // `^[A-Za-z0-9+/_-]{43}=?$`
    let body = value.strip_suffix('=').unwrap_or(value);
    if body.len() == 43 && body.bytes().all(|b| b.is_ascii_alphanumeric() || b"+/_-".contains(&b)) {
        return Some(from_b64(body)).filter(|b| b.len() == 32);
    }
    None
}

struct CheckedKey {
    n: usize,
    owner: String,
    hash: Vec<u8>,
    scopes: Vec<String>,
    name: String,
    times: [Option<String>; 4],
}

const TIME_FIELDS: [&str; 4] = ["expires_at", "revoked_at", "created_at", "last_used_at"];

/// The problems found, and how many keys were written.
pub async fn import_api_keys(app: &App, service: &Service, text: &str, dry_run: bool) -> Result<(Vec<String>, usize)> {
    if service.api_key_scopes.is_empty() {
        return Ok((vec![format!("{} declares no api_key_scopes, so it takes no API keys", service.name)], 0));
    }
    let mut problems: Vec<String> = Vec::new();
    let lines = parse_lines(text, &mut problems);
    let mut hashes: Vec<(String, usize)> = Vec::new();
    let mut checked: Vec<CheckedKey> = Vec::new();

    for (n, v) in &lines {
        let n = *n;
        let mut unknown = Vec::new();
        unknown_fields(v, &["owner", "sha256", "scopes", "name", "expires_at", "revoked_at", "created_at", "last_used_at"], &mut unknown, n);
        problems.extend(unknown);
        let mut p = |msg: String| problems.push(format!("line {n}: {msg}"));
        let owner = v.get("owner").and_then(Value::as_str).filter(|o| is_id(o) || is_username(o));
        if owner.is_none() {
            p("owner must be a user's sub (usr_…) or username".into());
        }
        let hash = digest(v.get("sha256"));
        match &hash {
            None => p("sha256 must be 64 hex characters, or 32 bytes in base64".into()),
            Some(h) => {
                let key = hex(h);
                match hashes.iter().find(|(known, _)| *known == key) {
                    Some((_, first)) => p(format!("sha256 is also on line {first}")),
                    None => hashes.push((key, n)),
                }
            }
        }
        let scopes = v.get("scopes").and_then(Value::as_array).filter(|l| !l.is_empty() && l.iter().all(|s| s.as_str().is_some_and(|s| service.api_key_scopes.iter().any(|d| d == s))));
        if scopes.is_none() {
            p(format!("scopes must be a non-empty list from: {}", service.api_key_scopes.join(", ")));
        }
        let name = match v.get("name") {
            None => Some("imported"),
            Some(Value::String(s)) if !js_trim(s).is_empty() && char_count(s) <= 100 && !has_control(s) => Some(s.as_str()),
            Some(_) => None,
        };
        if name.is_none() {
            p("name is 1 to 100 characters".into());
        }
        let mut times: [Option<String>; 4] = Default::default();
        for (i, field) in TIME_FIELDS.iter().enumerate() {
            match timestamp(v.get(*field)) {
                Some(t) => times[i] = t,
                None => p(format!("{field} must be an RFC 3339 timestamp")),
            }
        }
        if let (Some(owner), Some(hash)) = (owner, hash) {
            let mut unique: Vec<String> = Vec::new();
            for s in v.get("scopes").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                if !unique.iter().any(|u| u == s) {
                    unique.push(s.to_string());
                }
            }
            checked.push(CheckedKey { n, owner: owner.to_string(), hash, scopes: unique, name: js_trim(name.unwrap_or("")).to_string(), times });
        }
    }

    // Each owner exists and holds a role on the service: introspection
    // answers only for those (§7.2), so a key without one would never work.
    let mut owners: Vec<(String, String)> = Vec::new();
    for k in &checked {
        if owners.iter().any(|(o, _)| *o == k.owner) {
            continue;
        }
        let by = if is_id(&k.owner) { "u.id" } else { "u.username" };
        let row = app.db().first(&format!("SELECT u.id, a.role FROM users u LEFT JOIN access a ON a.user_id = u.id AND a.service = $1 WHERE {by} = $2"), &[&service.name, &k.owner]).await?;
        match row {
            None => problems.push(format!("line {}: owner is not a user", k.n)),
            Some(r) if r.try_get::<_, Option<String>>("role")?.is_none() => problems.push(format!("line {}: owner has no role on {}", k.n, service.name)),
            Some(r) => owners.push((k.owner.clone(), r.try_get("id")?)),
        }
    }
    let user_of = |owner: &str| owners.iter().find(|(o, _)| o == owner).map(|(_, id)| id.as_str());
    // Live keys only, as the owner's own limit counts them.
    let mut adding: Vec<(String, i64)> = Vec::new();
    for k in checked.iter().filter(|k| k.times[1].is_none()) {
        if let Some(user_id) = user_of(&k.owner) {
            match adding.iter_mut().find(|(u, _)| u == user_id) {
                Some((_, count)) => *count += 1,
                None => adding.push((user_id.to_string(), 1)),
            }
        }
    }
    for (user_id, n) in &adding {
        let held = i64::from(app.db().one("SELECT count(*)::int AS n FROM credentials WHERE user_id = $1 AND kind = 'api_key' AND revoked_at IS NULL", &[user_id]).await?.try_get::<_, i32>("n")?);
        if held + n > MAX_KEYS_PER_OWNER {
            if let Some(first) = checked.iter().find(|k| user_of(&k.owner) == Some(user_id.as_str())) {
                problems.push(format!("line {}: owner would hold {} live API keys, more than {MAX_KEYS_PER_OWNER}", first.n, held + n));
            }
        }
    }
    if !hashes.is_empty() {
        let keys: Vec<&str> = hashes.iter().map(|(h, _)| h.as_str()).collect();
        for r in &app.db().query("SELECT encode(secret_hash, 'hex') AS h FROM credentials WHERE encode(secret_hash, 'hex') = ANY($1)", &[&keys]).await? {
            let existing: String = r.try_get("h")?;
            if let Some((_, n)) = hashes.iter().find(|(h, _)| *h == existing) {
                problems.push(format!("line {n}: sha256 is already a credential"));
            }
        }
    }
    sort_by_line(&mut problems);
    if !problems.is_empty() || dry_run {
        return Ok((problems, 0));
    }

    let tx = app.begin().await?;
    let work = async {
        // A registered service deleted since the checks takes nothing.
        lock_service(tx.q(), service).await?;
        for k in &checked {
            let id = new_id("key");
            let user_id = user_of(&k.owner).unwrap_or("");
            tx.q()
                .execute(
                    "INSERT INTO credentials (id, user_id, kind, service, scopes, name, secret_hash, created_at, last_used_at, expires_at, revoked_at)
                     VALUES ($1, $2, 'api_key', $3, $4, $5, $6,
                             COALESCE($7::text::timestamptz, now()), $8::text::timestamptz,
                             $9::text::timestamptz, $10::text::timestamptz)",
                    &[&id, &user_id, &service.name, &k.scopes, &k.name, &k.hash, &k.times[2], &k.times[3], &k.times[0], &k.times[1]],
                )
                .await?;
            audit(tx.q(), Audit::new(Some(ACTOR), "api_key.create").user(Some(user_id)).detail(json!({ "id": id, "service": service.name, "scopes": k.scopes, "imported": true }))).await?;
        }
        Ok(checked.len())
    }
    .await;
    match tx.finish(work).await {
        Ok(count) => Ok((Vec::new(), count)),
        Err(e) => Ok((write_failed(&e), 0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_are_rfc_3339_with_a_zone_and_a_real_date() {
        for ok in ["2026-11-12T10:00Z", "2026-11-12T10:00:00Z", "2026-11-12T10:00:00.123456+15:59", "2024-02-29T23:59:59-00:00"] {
            assert!(is_timestamp(ok), "{ok}");
        }
        for bad in [
            "2026-11-12T10:00:00",
            "2026-02-30T10:00:00Z",
            "2026-02-29T10:00:00Z",
            "2026-11-12T24:00:00Z",
            "2026-11-12T10:00:00.1234567Z",
            "2026-11-12T10:00:00+16:00",
            "2026-11-12T10:00:00+0100",
            "2026-11-12 10:00:00Z",
            "0000-01-01T00:00:00Z",
            "2026-11-12T10:00:00.Z",
            "2026-11-12T10:00:00z",
        ] {
            assert!(!is_timestamp(bad), "{bad}");
        }
    }

    #[test]
    fn hashes_within_the_budget() {
        assert!(hash_problem("$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g").is_none());
        assert!(hash_problem("$argon2id$v=19$m=65536,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g").unwrap().contains("argon2 at most m=19456"));
        assert!(hash_problem(&format!("$2b$12${}", "a".repeat(53))).is_none());
        assert!(hash_problem(&format!("$2b$13${}", "a".repeat(53))).unwrap().contains("bcrypt cost at most 12"));
        assert_eq!(hash_problem("plaintext").unwrap(), "password_hash is not an argon2 or bcrypt PHC string");
    }

    #[test]
    fn digests() {
        assert_eq!(digest(Some(&json!("ab".repeat(32)))).unwrap(), vec![0xab; 32]);
        assert_eq!(digest(Some(&json!(crate::util::b64(&[7u8; 32])))).unwrap(), vec![7u8; 32]);
        assert_eq!(digest(Some(&json!(crate::util::b64url(&[0xfbu8; 32])))).unwrap(), vec![0xfbu8; 32]);
        assert!(digest(Some(&json!("abc"))).is_none());
        assert!(digest(Some(&json!(5))).is_none());
    }
}
