//! Users (docs/DESIGN.md §6): a person or a bot, with an immutable username
//! that a service may use as a DNS label or an address.

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use tokio_postgres::Row;

use crate::app::App;
use crate::audit::{audit, Audit};
use crate::crypto::new_id;
use crate::db::Q;
use crate::error::{bail, http, Result};
use crate::events::emit_all;
use crate::mail::is_email_address;
use crate::sessions::end_user_sessions;
use crate::util::{char_count, has_control, iso, js_now, js_trim, utf16_len};

pub const MAX_NAME: usize = 200;

/// `^[a-z][a-z0-9-]{1,30}[a-z0-9]$`
pub fn is_username(s: &str) -> bool {
    let b = s.as_bytes();
    (3..=32).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && (b[b.len() - 1].is_ascii_lowercase() || b[b.len() - 1].is_ascii_digit())
        && b[1..b.len() - 1].iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

#[derive(Debug, Clone)]
pub struct UserRow {
    pub id: String,
    pub username: String,
    pub name: String,
    pub email: Option<String>,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub kind: String,
    pub owner_id: Option<String>,
    pub password_hash: Option<String>,
    pub disabled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// The columns a `UserRow` reads, for a SELECT: named one by one, so a column
/// a later migration adds changes no prepared statement's result.
pub const USER_COLUMNS: &str = "id, username, name, email, email_verified_at, kind, owner_id, password_hash, disabled_at, created_at";

impl UserRow {
    pub fn from_row(r: &Row) -> Result<UserRow> {
        Ok(UserRow {
            id: r.try_get("id")?,
            username: r.try_get("username")?,
            name: r.try_get("name")?,
            email: r.try_get("email")?,
            email_verified_at: r.try_get("email_verified_at")?,
            kind: r.try_get("kind")?,
            owner_id: r.try_get("owner_id")?,
            password_hash: r.try_get("password_hash")?,
            disabled_at: r.try_get("disabled_at")?,
            created_at: r.try_get("created_at")?,
        })
    }

    pub fn is_person(&self) -> bool {
        self.kind == "person"
    }
}

pub fn user_json(u: &UserRow) -> Value {
    json!({
        "id": u.id,
        "username": u.username,
        "name": u.name,
        "email": u.email,
        "email_verified": u.email_verified_at.is_some(),
        "kind": u.kind,
        "owner_id": u.owner_id,
        "disabled": u.disabled_at.is_some(),
        "created_at": iso(&u.created_at),
    })
}

pub fn check_username(value: Option<&Value>) -> Result<String> {
    match value.and_then(Value::as_str).filter(|s| is_username(s)) {
        Some(s) => Ok(s.to_string()),
        None => Err(http(400, "invalid_request", "A username is 3 to 32 characters: a–z, 0–9 and '-', starting with a letter and not ending with '-'.")),
    }
}

pub fn check_name(value: Option<&Value>) -> Result<String> {
    match value {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(s)) if char_count(s) <= MAX_NAME && !has_control(s) => Ok(js_trim(s).to_string()),
        Some(_) => Err(http(400, "invalid_request", format!("A name is at most {MAX_NAME} characters, with no control characters."))),
    }
}

pub fn check_email(value: Option<&Value>) -> Result<String> {
    match value.and_then(Value::as_str).map(js_trim).filter(|s| is_email_address(s)) {
        Some(s) => Ok(s.to_string()),
        None => Err(http(400, "invalid_request", "That is not an email address.")),
    }
}

pub async fn find_user(q: Q<'_>, id: &str) -> Result<Option<UserRow>> {
    match q.first(&format!("SELECT {USER_COLUMNS} FROM users WHERE id = $1"), &[&id]).await? {
        Some(r) => Ok(Some(UserRow::from_row(&r)?)),
        None => Ok(None),
    }
}

/// By username, or by email ignoring case, as typed into a sign-in form.
pub async fn find_user_by_login(q: Q<'_>, login: &str) -> Result<Option<UserRow>> {
    let value = js_trim(login);
    // No username or address holds a NUL, and Postgres's text can't.
    if value.is_empty() || utf16_len(value) > 254 || value.contains('\0') {
        return Ok(None);
    }
    let row = if value.contains('@') {
        q.first(&format!("SELECT {USER_COLUMNS} FROM users WHERE lower(email) = lower($1)"), &[&value]).await?
    } else {
        q.first(&format!("SELECT {USER_COLUMNS} FROM users WHERE username = $1"), &[&value.to_lowercase()]).await?
    };
    match row {
        Some(r) => Ok(Some(UserRow::from_row(&r)?)),
        None => Ok(None),
    }
}

pub struct NewUser<'a> {
    pub username: &'a str,
    pub name: &'a str,
    pub email: Option<&'a str>,
    pub email_verified: bool,
    pub kind: &'a str,
    pub owner_id: Option<&'a str>,
    pub password_hash: Option<&'a str>,
}

/// A conflict aborts the caller's transaction, which then rolls back whole.
pub async fn insert_user(q: Q<'_>, u: &NewUser<'_>) -> Result<String> {
    let id = new_id("usr");
    let verified_at = u.email_verified.then(js_now);
    let inserted = q
        .execute(
            "INSERT INTO users (id, username, name, email, email_verified_at, kind, owner_id, password_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &[&id, &u.username, &u.name, &u.email, &verified_at, &u.kind, &u.owner_id, &u.password_hash],
        )
        .await;
    match inserted {
        Ok(_) => Ok(id),
        Err(e) if e.is_unique_violation(Some("users_username_key")) => Err(http(409, "conflict", "That username is taken.")),
        Err(e) if e.is_unique_violation(Some("users_email")) => Err(http(409, "conflict", "Another account uses that email address.")),
        Err(e) => Err(e),
    }
}

/// Disabling overrides every access row without deleting it (§6 rule 5):
/// sessions end, and refreshes, app passwords and keys stop because each
/// check reads disabled_at. Re-enabling restores the access they had.
pub async fn set_disabled(q: Q<'_>, app: &App, user: &UserRow, disabled: bool, actor: Option<&str>, ip: Option<&str>) -> Result<()> {
    if disabled == user.disabled_at.is_some() {
        return Ok(());
    }
    let at = disabled.then(js_now);
    q.execute("UPDATE users SET disabled_at = $2, updated_at = now() WHERE id = $1", &[&user.id, &at]).await?;
    if disabled {
        end_user_sessions(q, app, &user.id, None).await?;
        emit_all(q, app, "user.disabled", json!({ "sub": user.id })).await?;
    }
    audit(q, Audit::new(actor, if disabled { "user.disable" } else { "user.enable" }).user(Some(&user.id)).ip(ip)).await
}

/// Erases a user (A4, U14). Every app is told, so it can delete or anonymise
/// its own data. A person who owns bots keeps them from being orphaned: they
/// are deleted or reassigned first.
pub async fn delete_user(q: Q<'_>, app: &App, user: &UserRow, actor: Option<&str>, ip: Option<&str>) -> Result<()> {
    let bots: i32 = q.one("SELECT count(*)::int AS n FROM users WHERE owner_id = $1", &[&user.id]).await?.try_get("n")?;
    if bots > 0 {
        bail!(409, "conflict", "This user owns bot users; delete them or give them another owner first.");
    }
    end_user_sessions(q, app, &user.id, None).await?;
    emit_all(q, app, "user.deleted", json!({ "sub": user.id })).await?;
    q.execute("DELETE FROM users WHERE id = $1", &[&user.id]).await?;
    audit(q, Audit::new(actor, "user.delete").user(Some(&user.id)).ip(ip).detail(json!({ "username": user.username }))).await
}
