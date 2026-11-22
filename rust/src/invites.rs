//! Invitations (docs/DESIGN.md §7.5, §12.6): an email that lets its holder
//! create an account, or use the one they have, and get a role on a service.

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use tokio_postgres::Row;

use crate::access::{put_access, Grant};
use crate::app::App;
use crate::audit::{audit, Audit};
use crate::crypto::{new_id, random_token, sha256};
use crate::db::{Tx, Q};
use crate::emails::invite_email;
use crate::error::{bail, http, Result};
use crate::events::emit;
use crate::registry::lock_service;
use crate::services::{Service, Signup};
use crate::tokens::token_hash;
use crate::util::{iso, iso_opt};

const INVITE_SECONDS: f64 = 14.0 * 24.0 * 60.0 * 60.0;

pub struct InviteRow {
    pub id: String,
    pub email: String,
    pub service: String,
    pub role: String,
    pub invited_by: String,
    pub expires_at: DateTime<Utc>,
    pub accepted_by: Option<String>,
    pub accepted_at: Option<DateTime<Utc>>,
}

pub const INVITE_COLUMNS: &str = "id, email, service, role, invited_by, expires_at, accepted_by, accepted_at";

impl InviteRow {
    pub fn from_row(r: &Row) -> Result<InviteRow> {
        Ok(InviteRow {
            id: r.try_get("id")?,
            email: r.try_get("email")?,
            service: r.try_get("service")?,
            role: r.try_get("role")?,
            invited_by: r.try_get("invited_by")?,
            expires_at: r.try_get("expires_at")?,
            accepted_by: r.try_get("accepted_by")?,
            accepted_at: r.try_get("accepted_at")?,
        })
    }
}

pub fn invite_json(i: &InviteRow) -> Value {
    json!({
        "id": i.id,
        "email": i.email,
        "service": i.service,
        "role": i.role,
        "invited_by": i.invited_by,
        "expires_at": iso(&i.expires_at),
        "accepted_by": i.accepted_by,
        "accepted_at": iso_opt(&i.accepted_at),
    })
}

pub async fn create_invite(tx: &Tx, app: &App, email: &str, service: &Service, role: &str, actor: &str, ip: Option<&str>) -> Result<InviteRow> {
    let q = tx.q();
    let locked = lock_service(q, service).await?;
    if locked.signup == Signup::Closed {
        bail!(409, "conflict", "{} is closed to sign-up, so it takes no invitations; an admin grants access to existing accounts.", locked.name);
    }
    if !locked.has_role(role) {
        bail!(400, "invalid_request", "\"{role}\" is not a role of {}: use {}.", locked.name, locked.roles.join(", "));
    }
    let token = random_token();
    let row = q
        .one(
            &format!(
                "INSERT INTO invites (id, email, service, role, token_hash, invited_by, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(secs => $7))
                 RETURNING {INVITE_COLUMNS}"
            ),
            &[&new_id("inv"), &email, &service.name, &role, &sha256(token.as_bytes()), &actor, &INVITE_SECONDS],
        )
        .await?;
    let invite = InviteRow::from_row(&row)?;
    audit(q, Audit::new(Some(actor), "invite.create").ip(ip).detail(json!({ "id": invite.id, "service": service.name, "role": role }))).await?;
    let (app, message) = (app.clone(), invite_email(&app.config.issuer, email, &service.name, &token));
    tx.after(move || app.mail(message));
    Ok(invite)
}

pub async fn find_live_invite(q: Q<'_>, token: Option<&str>) -> Result<Option<InviteRow>> {
    let row = q.first(&format!("SELECT {INVITE_COLUMNS} FROM invites WHERE token_hash = $1 AND accepted_at IS NULL AND expires_at > now()"), &[&token_hash(token)]).await?;
    match row {
        Some(r) => Ok(Some(InviteRow::from_row(&r)?)),
        None => Ok(None),
    }
}

/// Marks the invitation accepted by `user_id`, once, and gives the invited
/// role without lowering one the user already holds. The service learns who
/// accepted, so it can give them what it tied to the invitation.
pub async fn accept_invite(tx: &Tx, app: &App, token: Option<&str>, user_id: &str, ip: Option<&str>) -> Result<InviteRow> {
    let q = tx.q();
    let hash = token_hash(token);
    // The service's row is locked before the invitation's, the order in which
    // a service's deletion takes them, so the two can't deadlock.
    let pending: Option<String> = match q.first("SELECT service FROM invites WHERE token_hash = $1 AND accepted_at IS NULL AND expires_at > now()", &[&hash]).await? {
        Some(r) => Some(r.try_get("service")?),
        None => None,
    };
    let known = pending.as_deref().and_then(|name| app.services.get(name));
    let service = match known {
        Some(known) => match lock_service(q, known).await {
            Ok(s) => Some(s),
            Err(e) if e.http_status() == Some(404) => return Err(http(409, "conflict", "This invitation is no longer valid.")),
            Err(e) => return Err(e),
        },
        None => None,
    };
    let row = q
        .first(
            &format!(
                "UPDATE invites SET accepted_by = $2, accepted_at = now()
                 WHERE token_hash = $1 AND accepted_at IS NULL AND expires_at > now()
                 RETURNING {INVITE_COLUMNS}"
            ),
            &[&hash, &user_id],
        )
        .await?;
    let Some(row) = row else { bail!(409, "conflict", "This invitation has expired or was already used.") };
    let invite = InviteRow::from_row(&row)?;
    let Some(service) = service.filter(|s| s.name == invite.service && s.signup != Signup::Closed && s.has_role(&invite.role)) else { bail!(409, "conflict", "This invitation is no longer valid.") };
    put_access(tx, app, &Grant { user_id, service: &service, role: &invite.role, actor: user_id, ip, reason: Some("invite"), never_lower: true }).await?;
    audit(q, Audit::new(Some(user_id), "invite.accept").user(Some(user_id)).ip(ip).detail(json!({ "id": invite.id, "service": service.name }))).await?;
    emit(q, app, &service.name, "invite.accepted", json!({ "invite": invite.id, "sub": user_id })).await?;
    Ok(invite)
}
