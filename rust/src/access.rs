//! Access (docs/DESIGN.md §6): (user, service) → one role from the service's
//! declared list. No row is no access; there is nothing else to evaluate.

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use tokio_postgres::Row;

use crate::app::App;
use crate::audit::{audit, Audit};
use crate::db::Tx;
use crate::db::Q;
use crate::error::{bail, Result};
use crate::events::emit;
use crate::registry::lock_service;
use crate::services::{Service, Signup, AUTH_SERVICE};
use crate::util::iso;

pub struct AccessRow {
    pub service: String,
    pub role: String,
    pub granted_by: String,
    pub granted_at: DateTime<Utc>,
}

impl AccessRow {
    pub fn from_row(r: &Row) -> Result<AccessRow> {
        Ok(AccessRow { service: r.try_get("service")?, role: r.try_get("role")?, granted_by: r.try_get("granted_by")?, granted_at: r.try_get("granted_at")? })
    }
}

pub fn access_json(a: &AccessRow) -> Value {
    json!({ "service": a.service, "role": a.role, "granted_by": a.granted_by, "granted_at": iso(&a.granted_at) })
}

/// The role an enabled user holds on a service, from its row only.
pub async fn role_of(q: Q<'_>, user_id: &str, service: &str) -> Result<Option<String>> {
    let row = q
        .first("SELECT a.role FROM access a JOIN users u ON u.id = a.user_id WHERE a.user_id = $1 AND a.service = $2 AND u.disabled_at IS NULL", &[&user_id, &service])
        .await?;
    match row {
        Some(r) => Ok(Some(r.try_get("role")?)),
        None => Ok(None),
    }
}

/// The role a sign-in to a service gets: the user's row, or on a service with
/// `signup: "open"`, its default_role, which is then written down (§6 rule 1).
pub async fn role_at_sign_in(tx: &Tx, app: &App, user_id: &str, service: &Service, ip: Option<&str>) -> Result<Option<String>> {
    let role = role_of(tx.q(), user_id, &service.name).await?;
    let default_role = match (&role, service.signup, &service.default_role) {
        (None, Signup::Open, Some(default_role)) => default_role.clone(),
        _ => return Ok(role),
    };
    put_access(tx, app, &Grant { user_id, service, role: &default_role, actor: user_id, ip, reason: Some("open_signup"), never_lower: false }).await?;
    Ok(Some(default_role))
}

pub struct Grant<'a> {
    pub user_id: &'a str,
    pub service: &'a Service,
    pub role: &'a str,
    pub actor: &'a str,
    pub ip: Option<&'a str>,
    pub reason: Option<&'a str>,
    /// An invitation never lowers a role the user already holds (§7.5).
    pub never_lower: bool,
}

/// Creates or changes a row, and tells the service in the same transaction.
pub async fn put_access(tx: &Tx, app: &App, g: &Grant<'_>) -> Result<AccessRow> {
    let q = tx.q();
    // Checked against the service as it is at commit, not as the request found it.
    let service = lock_service(q, g.service).await?;
    if !service.has_role(g.role) {
        bail!(400, "invalid_request", "\"{}\" is not a role of {}: use {}.", g.role, service.name, service.roles.join(", "));
    }
    let name = &g.service.name;
    let current: Option<String> = match q.first("SELECT role FROM access WHERE user_id = $1 AND service = $2 FOR UPDATE", &[&g.user_id, name]).await? {
        Some(r) => Some(r.try_get("role")?),
        None => None,
    };
    if let Some(held) = &current {
        if held == g.role || (g.never_lower && service.rank(held) > service.rank(g.role)) {
            let row = q.one("SELECT service, role, granted_by, granted_at FROM access WHERE user_id = $1 AND service = $2", &[&g.user_id, name]).await?;
            return AccessRow::from_row(&row);
        }
    }
    let row = q
        .one(
            "INSERT INTO access (user_id, service, role, granted_by) VALUES ($1, $2, $3, $4)
             ON CONFLICT (user_id, service) DO UPDATE SET role = EXCLUDED.role, granted_by = EXCLUDED.granted_by, granted_at = now()
             RETURNING service, role, granted_by, granted_at",
            &[&g.user_id, name, &g.role, &g.actor],
        )
        .await?;
    let mut detail = json!({ "service": name, "role": g.role, "previous": current });
    if let Some(reason) = g.reason {
        detail["reason"] = json!(reason);
    }
    audit(q, Audit::new(Some(g.actor), "access.put").user(Some(g.user_id)).ip(g.ip).detail(detail)).await?;
    emit(q, app, name, "access.changed", json!({ "sub": g.user_id, "role": g.role })).await?;
    if name == AUTH_SERVICE {
        alert_auth_access(tx, app, g.user_id, Some(g.role), g.actor);
    }
    AccessRow::from_row(&row)
}

/// Removes a row. On an open service the next sign-in would grant
/// default_role again, so removal is refused; disabling is how to keep
/// someone out (§6).
pub async fn delete_access(tx: &Tx, app: &App, user_id: &str, service: &Service, actor: &str, ip: Option<&str>) -> Result<bool> {
    let q = tx.q();
    if service.signup == Signup::Open {
        bail!(409, "conflict", "{} is open to sign-up, so a role can be changed but not removed; disable the user to keep them out.", service.name);
    }
    let rows = q.query("DELETE FROM access WHERE user_id = $1 AND service = $2 RETURNING role", &[&user_id, &service.name]).await?;
    let Some(removed) = rows.first() else { return Ok(false) };
    let previous: String = removed.try_get("role")?;
    audit(q, Audit::new(Some(actor), "access.delete").user(Some(user_id)).ip(ip).detail(json!({ "service": service.name, "previous": previous }))).await?;
    emit(q, app, &service.name, "access.changed", json!({ "sub": user_id, "role": null })).await?;
    if service.name == AUTH_SERVICE {
        alert_auth_access(tx, app, user_id, None, actor);
    }
    Ok(true)
}

// Every change to who administers auth is alerted (§9.5).
fn alert_auth_access(tx: &Tx, app: &App, user_id: &str, role: Option<&str>, actor: &str) {
    let what = match role {
        Some(role) => format!("{user_id} was given auth:{role}"),
        None => format!("{user_id} lost auth access"),
    };
    let (app, text) = (app.clone(), format!("auth: {what} by {actor}"));
    tx.after(move || app.alert(text));
}
