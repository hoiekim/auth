//! The management API (docs/DESIGN.md §7.5), JSON under /v1. Callers are a
//! signed-in user (the __Host-auth cookie, plus X-CSRF-Token on changes) or a
//! service's own client (HTTP Basic), which reaches only the ★ endpoints and
//! only its own service.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use crate::access::{access_json, delete_access, put_access, role_of, AccessRow, Grant};
use crate::app::App;
use crate::audit::{audit, client_actor, Audit};
use crate::clients::{authenticate_client, retire_old_client_secrets, rotate_client_secret};
use crate::credentials::{create_credential, credential_json, list_credentials, revoke_credential, Kind, NewCredential};
use crate::crypto::is_id;
use crate::db::Tx;
use crate::emails::{activation_email, address_in_use_email, reset_email, security_notice, verify_email};
use crate::error::{bail, http, Error, HttpError, Result};
use crate::factors::{confirm_totp_enrolment, factors_of, new_recovery_codes, remove_totp, start_totp_enrolment};
use crate::http::{json as json_response, json_with, no_content, read_json, retry_after, Extras, Request, Response};
use crate::invites::{create_invite, invite_json, InviteRow, INVITE_COLUMNS};
use crate::pages::signin::account_key;
use crate::passkeys::{finish_registration, list_passkeys, passkey_json, registration_options};
use crate::passwords::{password_problem, BREACHED_MESSAGE};
use crate::registry::{delete_service as remove_service, insert_service, lock_client, replace_service};
use crate::server::Ctx;
use crate::services::{parse_service, service_json, Client, Service, Source, AUTH_SERVICE};
use crate::sessions::{clear_session_cookie, end_family, end_session, end_user_sessions, load_session, require_csrf, session_cookie, step_up, Session, REAUTH_SECONDS};
use crate::throttle::{failure_wait, hit, record_failure};
use crate::tokens::{email_allowed, issue_token, Purpose};
use crate::users::{check_email, check_name, check_username, delete_user, find_user, insert_user, set_disabled, user_json, NewUser, UserRow, USER_COLUMNS};
use crate::util::{iso, js_trim, utf16_len, utf16_prefix};
use crate::webauthn::is_attachment;

enum Caller {
    User { session: Session, admin: bool },
    Client { client: Client, service: Arc<Service> },
}

async fn caller(app: &App, req: &Request, allow_client: bool) -> Result<Caller> {
    if req.header("Authorization").is_some_and(|h| !h.is_empty()) {
        let client = authenticate_client(app, req, None, false).await?;
        let service = app.services.get(&client.service).ok_or(Error::Other("ServiceError"))?.clone();
        if !allow_client || !service.manages_own_members {
            bail!(403, "forbidden", "This endpoint is not open to a service's client.");
        }
        return Ok(Caller::Client { client, service });
    }
    let Some(session) = load_session(app, req).await? else { bail!(401, "unauthorized", "Sign in first.") };
    if req.method != "GET" {
        require_csrf(app, req, &session)?;
    }
    let admin = role_of(app.db(), &session.user_id, AUTH_SERVICE).await?.as_deref() == Some("admin");
    Ok(Caller::User { session, admin })
}

async fn signed_in(app: &App, req: &Request) -> Result<Session> {
    match caller(app, req, false).await? {
        Caller::User { session, .. } => Ok(session),
        Caller::Client { .. } => Err(http(403, "forbidden", "Sign in first.")),
    }
}

// auth:admin always requires MFA (§6), so an admin's session must have used it.
fn require_admin(c: &Caller) -> Result<&Session> {
    match c {
        Caller::User { session, admin: true } if session.has_mfa() => Ok(session),
        Caller::User { admin: true, .. } => Err(http(403, "forbidden", "Admin actions need a sign-in with a second factor.")),
        _ => Err(http(403, "forbidden", "This needs the auth admin role.")),
    }
}

// The service a ★ call may act on: any for an admin, its own for a client.
fn service_for(app: &App, c: &Caller, name: &str) -> Result<Arc<Service>> {
    if let Caller::Client { service, .. } = c {
        if name != service.name {
            bail!(403, "forbidden", "A client reaches only its own service.");
        }
        return Ok(service.clone());
    }
    require_admin(c)?;
    app.services.get(name).cloned().ok_or_else(|| http(404, "not_found", format!("There is no service \"{name}\".")))
}

fn actor_of(c: &Caller) -> String {
    match c {
        Caller::Client { service, .. } => client_actor(&service.name),
        Caller::User { session, .. } => session.user_id.clone(),
    }
}

// Changing a credential, or deleting the account, needs a full sign-in in
// the last 15 minutes (§7.5). When the account has a second factor, that
// sign-in must have used it: otherwise the password alone could enroll a
// factor of its own, mint protocol credentials, or remove the factor.
async fn require_recent(app: &App, session: &Session) -> Result<()> {
    if session.auth_age > REAUTH_SECONDS {
        bail!(403, "reauth_required", "Sign in again to make this change.");
    }
    if !session.has_mfa() {
        let factors = factors_of(app.db(), &session.user_id).await?;
        if factors.totp || factors.passkeys > 0 {
            bail!(403, "reauth_required", "Sign in again with your second factor to make this change.");
        }
    }
    Ok(())
}

fn page_params(req: &Request) -> Result<(String, i64)> {
    let q = req.query();
    let limit: i64 = match q.get("limit") {
        None => 50,
        Some(raw) if (1..=3).contains(&raw.len()) && raw.bytes().all(|b| b.is_ascii_digit()) => raw.parse().unwrap_or(-1),
        Some(_) => -1,
    };
    if !(1..=100).contains(&limit) {
        bail!(400, "invalid_request", "limit is 1 to 100.");
    }
    let after = q.get("after").unwrap_or("").to_string();
    if utf16_len(&after) > 64 {
        bail!(400, "invalid_request", "after is not a cursor.");
    }
    Ok((after, limit))
}

// A page of a list: `rows` holds one more than the page when there is more.
fn list_of(mut rows: Vec<(String, Value)>, limit: i64) -> Value {
    let more = rows.len() as i64 > limit;
    rows.truncate(limit as usize);
    let next = if more { rows.last().map(|(cursor, _)| json!(cursor)) } else { None };
    json!({ "items": rows.into_iter().map(|(_, item)| item).collect::<Vec<_>>(), "next": next })
}

fn like_prefix(q: &str) -> String {
    let mut out = String::with_capacity(q.len() + 1);
    for c in q.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    out
}

async fn user_or_404(app: &App, id: &str) -> Result<UserRow> {
    let user = if is_id(id) { find_user(app.db(), id).await? } else { None };
    user.ok_or_else(|| http(404, "not_found", "No such user."))
}

// Every admin action is alerted (§9.5), once it has committed.
fn admin_alert(app: &App, tx: &Tx, c: &Caller, text: String) {
    if let Caller::User { session, .. } = c {
        let (app, text) = (app.clone(), format!("auth: {} {text}", session.username));
        tx.after(move || app.alert(text));
    }
}

fn notify(app: &App, tx: &Tx, email: Option<&str>, username: &str, change: &str, detail: Option<&str>) {
    if let Some(email) = email.filter(|e| !e.is_empty()) {
        let (app, message) = (app.clone(), security_notice(email, username, change, detail));
        tx.after(move || app.mail(message));
    }
}

fn merged(base: Value, more: Value) -> Value {
    let (Value::Object(mut out), Value::Object(extra)) = (base, more) else { return Value::Null };
    out.extend(extra);
    Value::Object(out)
}

fn items(list: Vec<Value>) -> Value {
    json!({ "items": list, "next": null })
}

// ------------------------------------------------------------- /v1/me

async fn me_json(app: &App, session: &Session) -> Result<Value> {
    let Some(user) = find_user(app.db(), &session.user_id).await? else { bail!(401, "unauthorized", "Sign in first.") };
    let factors = factors_of(app.db(), &user.id).await?;
    let pending = app
        .db()
        .first(
            "SELECT email FROM one_time_tokens WHERE user_id = $1 AND purpose = 'verify_email' AND used_at IS NULL AND expires_at > now()
             ORDER BY expires_at DESC LIMIT 1",
            &[&user.id],
        )
        .await?;
    let email_pending: Option<String> = match pending {
        Some(r) => r.try_get("email")?,
        None => None,
    };
    Ok(merged(
        user_json(&user),
        json!({
            "email_pending": email_pending,
            "mfa": factors.json(),
            "admin": role_of(app.db(), &user.id, AUTH_SERVICE).await?.as_deref() == Some("admin"),
            "account_deletion": app.config.allow_account_deletion,
        }),
    ))
}

pub async fn get_me(ctx: Ctx) -> Result<Response> {
    let session = signed_in(&ctx.app, &ctx.req).await?;
    Ok(json_response(200, &me_json(&ctx.app, &session).await?))
}

pub async fn patch_me(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let session = signed_in(app, &ctx.req).await?;
    let body = read_json(&ctx.req)?;
    let name = match body.get("name") {
        Some(v) => Some(check_name(Some(v))?),
        None => None,
    };
    let email = match body.get("email") {
        Some(v) => Some(check_email(Some(v))?),
        None => None,
    };
    if let Some(email) = &email {
        require_recent(app, &session).await?;
        let limit = email_allowed(app.db(), email, &format!("user:{}", session.user_id)).await?;
        if !limit.allowed {
            return Err(Error::Http(HttpError::with(429, "rate_limited", "Too many emails to that address.", retry_after(limit.retry_after))));
        }
    }
    let tx = app.begin().await?;
    let work = async {
        let q = tx.q();
        if let Some(name) = &name {
            q.execute("UPDATE users SET name = $2, updated_at = now() WHERE id = $1", &[&session.user_id, name]).await?;
            audit(q, Audit::new(Some(&session.user_id), "user.update").user(Some(&session.user_id)).ip(ctx.ip()).detail(json!({ "fields": ["name"] }))).await?;
        }
        if let Some(email) = email.as_deref().filter(|e| e.to_lowercase() != session.email.as_deref().unwrap_or("").to_lowercase()) {
            // The address changes only once the new one is confirmed; the old one
            // is told now (§9.1). Only the newest pending address can be
            // confirmed. A token is made either way, so the answer is the same
            // whether or not another account uses the address; that account's
            // owner gets a notice instead of the link.
            q.execute("DELETE FROM one_time_tokens WHERE user_id = $1 AND purpose = 'verify_email'", &[&session.user_id]).await?;
            let token = issue_token(q, Purpose::VerifyEmail, &session.user_id, Some(email)).await?;
            let taken = q.first("SELECT 1 FROM users WHERE lower(email) = lower($1)", &[&email]).await?.is_some();
            let message = if taken { address_in_use_email(email) } else { verify_email(&app.config.issuer, email, &token) };
            let mailing = app.clone();
            tx.after(move || mailing.mail(message));
            notify(app, &tx, session.email.as_deref(), &session.username, "your email address is changing", Some("A confirmation link went to the new address."));
            audit(q, Audit::new(Some(&session.user_id), "email.change").user(Some(&session.user_id)).ip(ctx.ip())).await?;
        }
        Ok(())
    }
    .await;
    tx.finish(work).await?;
    Ok(json_response(200, &me_json(app, &session).await?))
}

pub async fn delete_me(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let session = signed_in(app, &ctx.req).await?;
    if !app.config.allow_account_deletion {
        bail!(403, "forbidden", "This deployment doesn't let people delete their own accounts.");
    }
    require_recent(app, &session).await?;
    let user = user_or_404(app, &session.user_id).await?;
    let tx = app.begin().await?;
    let work = delete_user(tx.q(), app, &user, Some(&session.user_id), ctx.ip()).await;
    tx.finish(work).await?;
    Ok(no_content(Extras::cookies(vec![clear_session_cookie()])))
}

pub async fn change_password(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let session = signed_in(app, &ctx.req).await?;
    require_recent(app, &session).await?;
    let body = read_json(&ctx.req)?;
    let user = user_or_404(app, &session.user_id).await?;
    let Some(new) = body.get("new").and_then(Value::as_str) else { bail!(400, "invalid_request", "new is required.") };
    // Guessing the current password is held to the sign-in limits (§9.4).
    let per_ip = hit(app.db(), &format!("ip:{}:login", ctx.ip().unwrap_or("unknown")), 30, 15 * 60).await?;
    if !per_ip.allowed {
        return Err(Error::Http(HttpError::with(429, "rate_limited", "Too many attempts from your network.", retry_after(per_ip.retry_after))));
    }
    let wait = failure_wait(app.db(), &account_key(&user.id)).await?;
    if !wait.allowed {
        return Err(Error::Http(HttpError::with(429, "rate_limited", "Too many failed attempts.", retry_after(wait.retry_after))));
    }
    if let Some(stored) = &user.password_hash {
        let current = body.get("current").and_then(Value::as_str).map(|c| utf16_prefix(c, 1024)).unwrap_or("");
        if !app.hasher.verify(current, Some(stored)).await.ok {
            record_failure(app.db(), &account_key(&user.id)).await?;
            bail!(403, "forbidden", "The current password is wrong.");
        }
    }
    let mut problem = password_problem(new, Some(&user.username), user.email.as_deref());
    if problem.is_none() && app.breached(new).await {
        problem = Some(BREACHED_MESSAGE.to_string());
    }
    if let Some(problem) = problem {
        bail!(400, "invalid_request", "{problem}");
    }
    let hash = app.hasher.hash(new).await;
    let tx = app.begin().await?;
    let work = async {
        let q = tx.q();
        q.execute("UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1", &[&user.id, &hash]).await?;
        end_user_sessions(q, app, &user.id, Some(&session.id)).await?;
        audit(q, Audit::new(Some(&user.id), "password.change").user(Some(&user.id)).ip(ctx.ip())).await?;
        notify(app, &tx, user.email.as_deref(), &user.username, "password changed", None);
        Ok(())
    }
    .await;
    tx.finish(work).await?;
    Ok(no_content(Extras::default()))
}

pub async fn post_totp(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let session = signed_in(app, &ctx.req).await?;
    require_recent(app, &session).await?;
    let body = read_json(&ctx.req)?;
    if !body.contains_key("enrollment") {
        return Ok(json_response(200, &start_totp_enrolment(app, &session.user_id, &session.username)));
    }
    let tx = app.begin().await?;
    let work = async {
        let q = tx.q();
        if !confirm_totp_enrolment(q, app, &session.user_id, body.get("enrollment"), body.get("code")).await? {
            return Ok(None);
        }
        let left: i32 = q.one("SELECT count(*)::int AS n FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL", &[&session.user_id]).await?.try_get("n")?;
        let codes = if left == 0 { Some(new_recovery_codes(q, &session.user_id).await?) } else { None };
        // The code just confirmed is a second factor: the session steps up.
        let mut amr = session.amr.clone();
        for method in ["otp", "mfa"] {
            if !amr.iter().any(|m| m == method) {
                amr.push(method.to_string());
            }
        }
        let token = step_up(q, &session.id, &amr).await?;
        audit(q, Audit::new(Some(&session.user_id), "totp.enroll").user(Some(&session.user_id)).ip(ctx.ip())).await?;
        notify(app, &tx, session.email.as_deref(), &session.username, "two-factor authentication added", None);
        Ok(Some((codes, token)))
    }
    .await;
    let Some((codes, token)) = tx.finish(work).await? else { bail!(400, "invalid_request", "That code doesn't match; the enrolment may have expired.") };
    Ok(json_with(200, &json!({ "recovery_codes": codes }), &[], vec![session_cookie(&token)]))
}

pub async fn delete_totp(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let session = signed_in(app, &ctx.req).await?;
    require_recent(app, &session).await?;
    let tx = app.begin().await?;
    let work = async {
        if !remove_totp(tx.q(), &session.user_id).await? {
            bail!(404, "not_found", "No authenticator app is set up.");
        }
        audit(tx.q(), Audit::new(Some(&session.user_id), "totp.remove").user(Some(&session.user_id)).ip(ctx.ip())).await?;
        notify(app, &tx, session.email.as_deref(), &session.username, "two-factor authentication removed", None);
        Ok(())
    }
    .await;
    tx.finish(work).await?;
    Ok(no_content(Extras::default()))
}

pub async fn post_recovery_codes(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let session = signed_in(app, &ctx.req).await?;
    require_recent(app, &session).await?;
    let tx = app.begin().await?;
    let work = async {
        let codes = new_recovery_codes(tx.q(), &session.user_id).await?;
        audit(tx.q(), Audit::new(Some(&session.user_id), "recovery.regenerate").user(Some(&session.user_id)).ip(ctx.ip())).await?;
        notify(app, &tx, session.email.as_deref(), &session.username, "recovery codes regenerated", None);
        Ok(codes)
    }
    .await;
    Ok(json_response(200, &json!({ "codes": tx.finish(work).await? })))
}

pub async fn get_passkeys(ctx: Ctx) -> Result<Response> {
    let session = signed_in(&ctx.app, &ctx.req).await?;
    Ok(json_response(200, &items(list_passkeys(ctx.app.db(), &session.user_id).await?)))
}

pub async fn post_passkey(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let session = signed_in(app, &ctx.req).await?;
    require_recent(app, &session).await?;
    let body = read_json(&ctx.req)?;
    if !body.contains_key("registration") {
        // Which authenticator the browser should offer; absent leaves it the choice.
        let attachment = body.get("attachment").filter(|a| !a.is_null());
        if attachment.is_some_and(|a| !is_attachment(a)) {
            bail!(400, "invalid_request", "attachment is \"platform\" or \"cross-platform\".");
        }
        let options = registration_options(app, &session.user_id, &session.username, &session.name, attachment.and_then(Value::as_str)).await?;
        return Ok(json_response(200, &options));
    }
    let name = match body.get("name").and_then(Value::as_str).filter(|n| !js_trim(n).is_empty()) {
        Some(_) => utf16_prefix(&check_name(body.get("name"))?, 100).to_string(),
        None => "Passkey".to_string(),
    };
    let tx = app.begin().await?;
    let work = async {
        let Some(pk) = finish_registration(tx.q(), app, &session.user_id, body.get("registration"), body.get("response"), &name).await? else { return Ok(None) };
        audit(tx.q(), Audit::new(Some(&session.user_id), "passkey.add").user(Some(&session.user_id)).ip(ctx.ip()).detail(json!({ "id": pk }))).await?;
        notify(app, &tx, session.email.as_deref(), &session.username, "a passkey was added", Some(&format!("Name: {name}")));
        Ok(Some(pk))
    }
    .await;
    let Some(id) = tx.finish(work).await? else { bail!(400, "invalid_request", "The passkey couldn't be verified.") };
    let row = app.db().one("SELECT id, name, created_at, last_used_at FROM passkeys WHERE id = $1", &[&id]).await?;
    Ok(json_response(201, &passkey_json(&row.try_get::<_, String>("id")?, &row.try_get::<_, String>("name")?, &row.try_get("created_at")?, &row.try_get("last_used_at")?)))
}

pub async fn delete_passkey(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let session = signed_in(app, &ctx.req).await?;
    require_recent(app, &session).await?;
    let id = ctx.param("id");
    let tx = app.begin().await?;
    let work = async {
        let rows = tx.q().query("DELETE FROM passkeys WHERE id = $1 AND user_id = $2 RETURNING name", &[&id, &session.user_id]).await?;
        let Some(row) = rows.first() else { bail!(404, "not_found", "No such passkey.") };
        let name: String = row.try_get("name")?;
        audit(tx.q(), Audit::new(Some(&session.user_id), "passkey.remove").user(Some(&session.user_id)).ip(ctx.ip()).detail(json!({ "id": id }))).await?;
        notify(app, &tx, session.email.as_deref(), &session.username, "a passkey was removed", Some(&format!("Name: {name}")));
        Ok(())
    }
    .await;
    tx.finish(work).await?;
    Ok(no_content(Extras::default()))
}

async fn sessions_of(app: &App, user_id: &str, current: &str) -> Result<Vec<Value>> {
    let sso = app
        .db()
        .query(
            "SELECT id, created_at, last_seen_at, host(ip) AS ip, user_agent, amr FROM sessions
             WHERE user_id = $1 AND expires_at > now() AND ends_at > now() ORDER BY last_seen_at DESC",
            &[&user_id],
        )
        .await?;
    let native = app
        .db()
        .query(
            "SELECT family_id AS id, client_id, min(created_at) AS created_at, max(created_at) AS last_seen_at FROM refresh_tokens
             WHERE user_id = $1 AND session_id IS NULL AND revoked_at IS NULL AND expires_at > now()
             GROUP BY family_id, client_id ORDER BY max(created_at) DESC",
            &[&user_id],
        )
        .await?;
    let mut out = Vec::new();
    for s in &sso {
        let id: String = s.try_get("id")?;
        out.push(json!({
            "id": id,
            "current": id == current,
            "created_at": iso(&s.try_get::<_, DateTime<Utc>>("created_at")?),
            "last_seen_at": iso(&s.try_get::<_, DateTime<Utc>>("last_seen_at")?),
            "ip": s.try_get::<_, Option<String>>("ip")?,
            "user_agent": s.try_get::<_, Option<String>>("user_agent")?,
            "amr": s.try_get::<_, Vec<String>>("amr")?,
            "client": null,
        }));
    }
    for f in &native {
        out.push(json!({
            "id": f.try_get::<_, String>("id")?,
            "current": false,
            "created_at": iso(&f.try_get::<_, DateTime<Utc>>("created_at")?),
            "last_seen_at": iso(&f.try_get::<_, DateTime<Utc>>("last_seen_at")?),
            "ip": null,
            "user_agent": null,
            "amr": null,
            "client": f.try_get::<_, String>("client_id")?,
        }));
    }
    Ok(out)
}

pub async fn get_sessions(ctx: Ctx) -> Result<Response> {
    let session = signed_in(&ctx.app, &ctx.req).await?;
    Ok(json_response(200, &items(sessions_of(&ctx.app, &session.user_id, &session.id).await?)))
}

/// Signs out every device, this one included (U4).
pub async fn delete_sessions(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let session = signed_in(app, &ctx.req).await?;
    let tx = app.begin().await?;
    let work = async {
        end_user_sessions(tx.q(), app, &session.user_id, None).await?;
        audit(tx.q(), Audit::new(Some(&session.user_id), "session.end_all").user(Some(&session.user_id)).ip(ctx.ip())).await
    }
    .await;
    tx.finish(work).await?;
    Ok(no_content(Extras::cookies(vec![clear_session_cookie()])))
}

pub async fn delete_one_session(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let session = signed_in(app, &ctx.req).await?;
    let id = ctx.param("id");
    let tx = app.begin().await?;
    let work = async {
        let q = tx.q();
        let own = q.first("SELECT 1 FROM sessions WHERE id = $1 AND user_id = $2", &[&id, &session.user_id]).await?.is_some();
        let done = if own {
            end_session(q, app, id).await?;
            true
        } else {
            end_family(q, app, id, &session.user_id).await?
        };
        if done {
            audit(q, Audit::new(Some(&session.user_id), "session.end").user(Some(&session.user_id)).ip(ctx.ip()).detail(json!({ "sid": id }))).await?;
        }
        Ok(done)
    }
    .await;
    if !tx.finish(work).await? {
        bail!(404, "not_found", "No such session.");
    }
    Ok(no_content(if id == session.id { Extras::cookies(vec![clear_session_cookie()]) } else { Extras::default() }))
}

// App passwords and API keys, for the signed-in user or, by an admin, for a
// bot user (A9), which can't sign in to manage its own.

struct Owner {
    user_id: String,
    actor: String,
    notify_email: Option<String>,
    notify_username: String,
    /// The calling admin and the bot's username, on the bot endpoints.
    admin: Option<(Caller, String)>,
}

fn label(kind: Kind) -> &'static str {
    match kind {
        Kind::AppPassword => "app password",
        Kind::ApiKey => "API key",
    }
}

async fn owner(ctx: &Ctx, kind: Kind, change: bool) -> Result<Owner> {
    let app = &ctx.app;
    let Some(bot_id) = ctx.params.get("user") else {
        let session = signed_in(app, &ctx.req).await?;
        if change {
            require_recent(app, &session).await?;
        }
        return Ok(Owner { user_id: session.user_id.clone(), actor: session.user_id, notify_email: session.email, notify_username: session.username, admin: None });
    };
    let c = caller(app, &ctx.req, false).await?;
    let session = require_admin(&c)?.clone();
    if change {
        require_recent(app, &session).await?;
    }
    let bot = user_or_404(app, bot_id).await?;
    if bot.kind != "bot" {
        bail!(409, "conflict", "People manage their own {}s; this endpoint is for bot users.", label(kind));
    }
    let owner_row = match &bot.owner_id {
        Some(owner_id) => find_user(app.db(), owner_id).await?,
        None => None,
    };
    let (notify_email, notify_username) = match owner_row {
        Some(o) => (o.email, o.username),
        None => (None, bot.username.clone()),
    };
    Ok(Owner { user_id: bot.id, actor: session.user_id, notify_email, notify_username, admin: Some((c, bot.username)) })
}

async fn list_credentials_route(ctx: Ctx, kind: Kind) -> Result<Response> {
    let o = owner(&ctx, kind, false).await?;
    let rows = list_credentials(ctx.app.db(), &o.user_id, kind).await?;
    Ok(json_response(200, &items(rows.iter().map(credential_json).collect())))
}

async fn create_credential_route(ctx: Ctx, kind: Kind) -> Result<Response> {
    let app = &ctx.app;
    let o = owner(&ctx, kind, true).await?;
    let body = read_json(&ctx.req)?;
    let Some(service) = body.get("service").and_then(Value::as_str).and_then(|name| app.services.get(name)).cloned() else { bail!(400, "invalid_request", "service must name a service.") };
    let tx = app.begin().await?;
    let work = async {
        let new = NewCredential { user_id: &o.user_id, kind, service: &service, scopes: body.get("scopes"), name: body.get("name"), expires_at: body.get("expires_at"), actor: &o.actor, ip: ctx.ip() };
        let (row, secret) = create_credential(tx.q(), app, &new).await?;
        let change = if kind == Kind::AppPassword { "an app password was created" } else { "an API key was created" };
        notify(app, &tx, o.notify_email.as_deref(), &o.notify_username, change, Some(&format!("For {}: {}", service.name, row.name)));
        if let Some((admin, bot)) = &o.admin {
            admin_alert(app, &tx, admin, format!("made an {} for the bot {bot} on {}", label(kind), service.name));
        }
        Ok((row, secret))
    }
    .await;
    let (row, secret) = tx.finish(work).await?;
    let mut out = credential_json(&row);
    out[if kind == Kind::AppPassword { "password" } else { "key" }] = json!(secret);
    Ok(json_response(201, &out))
}

async fn revoke_credential_route(ctx: Ctx, kind: Kind) -> Result<Response> {
    let app = &ctx.app;
    let o = owner(&ctx, kind, true).await?;
    let tx = app.begin().await?;
    let work = async {
        let done = revoke_credential(tx.q(), app, &o.user_id, kind, ctx.param("id"), &o.actor, ctx.ip()).await?;
        if let (true, Some((admin, bot))) = (done, &o.admin) {
            admin_alert(app, &tx, admin, format!("revoked an {} of the bot {bot}", label(kind)));
        }
        Ok(done)
    }
    .await;
    if !tx.finish(work).await? {
        bail!(404, "not_found", "No such {}.", label(kind));
    }
    Ok(no_content(Extras::default()))
}

pub async fn list_app_passwords(ctx: Ctx) -> Result<Response> {
    list_credentials_route(ctx, Kind::AppPassword).await
}

pub async fn create_app_password(ctx: Ctx) -> Result<Response> {
    create_credential_route(ctx, Kind::AppPassword).await
}

pub async fn revoke_app_password(ctx: Ctx) -> Result<Response> {
    revoke_credential_route(ctx, Kind::AppPassword).await
}

pub async fn list_api_keys(ctx: Ctx) -> Result<Response> {
    list_credentials_route(ctx, Kind::ApiKey).await
}

pub async fn create_api_key(ctx: Ctx) -> Result<Response> {
    create_credential_route(ctx, Kind::ApiKey).await
}

pub async fn revoke_api_key(ctx: Ctx) -> Result<Response> {
    revoke_credential_route(ctx, Kind::ApiKey).await
}

pub async fn get_my_access(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let session = signed_in(app, &ctx.req).await?;
    let rows = app.db().query("SELECT service, role, granted_by, granted_at FROM access WHERE user_id = $1 ORDER BY service", &[&session.user_id]).await?;
    let mut list = Vec::new();
    for r in &rows {
        let row = AccessRow::from_row(r)?;
        let service = app.services.get(&row.service);
        list.push(merged(
            access_json(&row),
            json!({
                "app_password_scopes": service.map(|s| s.app_password_scopes.clone()).unwrap_or_default(),
                "api_key_scopes": service.map(|s| s.api_key_scopes.clone()).unwrap_or_default(),
            }),
        ));
    }
    Ok(json_response(200, &items(list)))
}

// ------------------------------------------------------------ administration

pub async fn list_users(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let c = caller(app, &ctx.req, true).await?;
    let (after, limit) = page_params(&ctx.req)?;
    let query = ctx.req.query();
    let q = utf16_prefix(js_trim(query.get("q").unwrap_or("")), 254).to_string();
    let prefix = like_prefix(&q.to_lowercase());
    let fetch = limit + 1;
    if let Caller::Client { service, .. } = &c {
        // A service's client sees only the enabled users with a role on its
        // service, and can't list addresses: an email matches only whole (§7.5).
        let rows = app
            .db()
            .query(
                "SELECT u.id, u.username, u.name, a.role FROM users u
                 JOIN access a ON a.user_id = u.id AND a.service = $1
                 WHERE u.disabled_at IS NULL AND u.id > $2
                   AND ($3 = '' OR u.username LIKE $4 OR lower(u.name) LIKE $4 OR lower(u.email) = lower($3))
                 ORDER BY u.id LIMIT $5",
                &[&service.name, &after, &q, &prefix, &fetch],
            )
            .await?;
        let mut list = Vec::new();
        for r in &rows {
            let id: String = r.try_get("id")?;
            list.push((id.clone(), json!({ "id": id, "username": r.try_get::<_, String>("username")?, "name": r.try_get::<_, String>("name")?, "role": r.try_get::<_, String>("role")? })));
        }
        return Ok(json_response(200, &list_of(list, limit)));
    }
    require_admin(&c)?;
    let rows = app
        .db()
        .query(
            &format!(
                "SELECT {USER_COLUMNS} FROM users
                 WHERE id > $1
                   AND ($2 = '' OR username LIKE $3 OR lower(name) LIKE $3 OR lower(email) LIKE $3)
                 ORDER BY id LIMIT $4"
            ),
            &[&after, &q, &prefix, &fetch],
        )
        .await?;
    let mut list = Vec::new();
    for r in &rows {
        let user = UserRow::from_row(r)?;
        list.push((user.id.clone(), user_json(&user)));
    }
    Ok(json_response(200, &list_of(list, limit)))
}

// An id from a body: one that isn't a string can only miss.
fn id_of(v: &Value) -> String {
    v.as_str().unwrap_or_default().to_string()
}

pub async fn create_user(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let c = caller(app, &ctx.req, false).await?;
    let session = require_admin(&c)?;
    let body = read_json(&ctx.req)?;
    let username = check_username(body.get("username"))?;
    let name = check_name(body.get("name"))?;
    let kind = match body.get("kind") {
        None => "person",
        Some(Value::String(k)) if k == "person" || k == "bot" => k.as_str(),
        Some(_) => bail!(400, "invalid_request", "kind is \"person\" or \"bot\"."),
    };
    let mut owner_id: Option<String> = None;
    let mut email: Option<String> = None;
    if kind == "bot" {
        if body.get("email").is_some_and(|e| !e.is_null()) {
            bail!(400, "invalid_request", "A bot user has no email.");
        }
        let id = body.get("owner_id").map(id_of).unwrap_or_else(|| session.user_id.clone());
        let owner = user_or_404(app, &id).await?;
        if !owner.is_person() {
            bail!(400, "invalid_request", "A bot's owner is a person.");
        }
        owner_id = Some(id);
    } else {
        email = Some(check_email(body.get("email"))?);
    }
    let tx = app.begin().await?;
    let work = async {
        let q = tx.q();
        let new = NewUser { username: &username, name: &name, email: email.as_deref(), email_verified: false, kind, owner_id: owner_id.as_deref(), password_hash: None };
        let id = insert_user(q, &new).await?;
        audit(q, Audit::new(Some(&session.user_id), "user.create").user(Some(&id)).ip(ctx.ip()).detail(json!({ "username": username, "kind": kind }))).await?;
        admin_alert(app, &tx, &c, format!("created the {kind} {username}"));
        if let Some(email) = &email {
            let token = issue_token(q, Purpose::Activate, &id, Some(email)).await?;
            let (mailing, message) = (app.clone(), activation_email(&app.config.issuer, email, &username, &token));
            tx.after(move || mailing.mail(message));
        }
        find_user(q, &id).await?.ok_or(Error::Other("NoRowError"))
    }
    .await;
    Ok(json_response(201, &user_json(&tx.finish(work).await?)))
}

async fn access_of(app: &App, user_id: &str) -> Result<Vec<Value>> {
    let rows = app.db().query("SELECT service, role, granted_by, granted_at FROM access WHERE user_id = $1 ORDER BY service", &[&user_id]).await?;
    rows.iter().map(|r| Ok(access_json(&AccessRow::from_row(r)?))).collect()
}

pub async fn get_user(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let c = caller(app, &ctx.req, false).await?;
    require_admin(&c)?;
    let user = user_or_404(app, ctx.param("id")).await?;
    let factors = factors_of(app.db(), &user.id).await?;
    Ok(json_response(200, &merged(user_json(&user), json!({ "mfa": factors.json(), "access": access_of(app, &user.id).await? }))))
}

pub async fn patch_user(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let c = caller(app, &ctx.req, false).await?;
    let session = require_admin(&c)?;
    let user = user_or_404(app, ctx.param("id")).await?;
    let body = read_json(&ctx.req)?;
    let name = match body.get("name") {
        Some(v) => Some(check_name(Some(v))?),
        None => None,
    };
    let email = match body.get("email") {
        Some(v) if user.is_person() => Some(check_email(Some(v))?),
        _ => None,
    };
    let disabled = match body.get("disabled") {
        None => None,
        Some(Value::Bool(b)) => Some(*b),
        Some(_) => bail!(400, "invalid_request", "disabled is true or false."),
    };
    let mut owner_id: Option<String> = None;
    if let Some(given) = body.get("owner_id") {
        if user.kind != "bot" {
            bail!(400, "invalid_request", "Only a bot user has an owner.");
        }
        let owner = user_or_404(app, &id_of(given)).await?;
        if !owner.is_person() {
            bail!(400, "invalid_request", "A bot's owner is a person.");
        }
        owner_id = Some(owner.id);
    }
    let tx = app.begin().await?;
    let work = async {
        let q = tx.q();
        let mut fields: Vec<&str> = Vec::new();
        if let Some(name) = &name {
            q.execute("UPDATE users SET name = $2, updated_at = now() WHERE id = $1", &[&user.id, name]).await?;
            fields.push("name");
        }
        if let Some(email) = email.as_deref().filter(|e| e.to_lowercase() != user.email.as_deref().unwrap_or("").to_lowercase()) {
            match q.execute("UPDATE users SET email = $2, email_verified_at = NULL, updated_at = now() WHERE id = $1", &[&user.id, &email]).await {
                Ok(_) => {}
                Err(e) if e.is_unique_violation(None) => bail!(409, "conflict", "Another account uses that email address."),
                Err(e) => return Err(e),
            }
            // Links sent to the old address stop working; an account not yet
            // activated gets a new activation link at the new one.
            q.execute("DELETE FROM one_time_tokens WHERE user_id = $1", &[&user.id]).await?;
            if user.password_hash.is_none() {
                let token = issue_token(q, Purpose::Activate, &user.id, Some(email)).await?;
                let (mailing, message) = (app.clone(), activation_email(&app.config.issuer, email, &user.username, &token));
                tx.after(move || mailing.mail(message));
            }
            notify(app, &tx, user.email.as_deref(), &user.username, "your email address is changing", Some("An administrator changed it."));
            fields.push("email");
        }
        if let Some(owner_id) = &owner_id {
            q.execute("UPDATE users SET owner_id = $2, updated_at = now() WHERE id = $1", &[&user.id, owner_id]).await?;
            fields.push("owner_id");
        }
        if !fields.is_empty() {
            audit(q, Audit::new(Some(&session.user_id), "user.update").user(Some(&user.id)).ip(ctx.ip()).detail(json!({ "fields": fields }))).await?;
            admin_alert(app, &tx, &c, format!("changed the {} of {}", fields.join(", "), user.username));
        }
        if let Some(disabled) = disabled {
            set_disabled(q, app, &user, disabled, Some(&session.user_id), ctx.ip()).await?;
            admin_alert(app, &tx, &c, format!("{} {}", if disabled { "disabled" } else { "enabled" }, user.username));
        }
        Ok(())
    }
    .await;
    tx.finish(work).await?;
    Ok(json_response(200, &user_json(&user_or_404(app, &user.id).await?)))
}

pub async fn delete_user_route(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let c = caller(app, &ctx.req, false).await?;
    let session = require_admin(&c)?;
    let user = user_or_404(app, ctx.param("id")).await?;
    let tx = app.begin().await?;
    let work = async {
        delete_user(tx.q(), app, &user, Some(&session.user_id), ctx.ip()).await?;
        admin_alert(app, &tx, &c, format!("deleted {}", user.username));
        Ok(())
    }
    .await;
    tx.finish(work).await?;
    Ok(no_content(Extras::default()))
}

pub async fn put_user_access(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let c = caller(app, &ctx.req, true).await?;
    let service = service_for(app, &c, ctx.param("service"))?;
    let body = read_json(&ctx.req)?;
    let Some(role) = body.get("role").and_then(Value::as_str) else { bail!(400, "invalid_request", "role is required.") };
    let user = user_or_404(app, ctx.param("id")).await?;
    let actor = actor_of(&c);
    let tx = app.begin().await?;
    let work = async {
        let row = put_access(&tx, app, &Grant { user_id: &user.id, service: &service, role, actor: &actor, ip: ctx.ip(), reason: None, never_lower: false }).await?;
        if service.name != AUTH_SERVICE {
            admin_alert(app, &tx, &c, format!("set {}'s role on {} to {}", user.username, service.name, row.role));
        }
        Ok(row)
    }
    .await;
    Ok(json_response(200, &access_json(&tx.finish(work).await?)))
}

pub async fn delete_user_access(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let c = caller(app, &ctx.req, true).await?;
    let service = service_for(app, &c, ctx.param("service"))?;
    let user = user_or_404(app, ctx.param("id")).await?;
    let actor = actor_of(&c);
    let tx = app.begin().await?;
    let work = async {
        let done = delete_access(&tx, app, &user.id, &service, &actor, ctx.ip()).await?;
        if done && service.name != AUTH_SERVICE {
            admin_alert(app, &tx, &c, format!("removed {}'s role on {}", user.username, service.name));
        }
        Ok(done)
    }
    .await;
    if !tx.finish(work).await? {
        bail!(404, "not_found", "The user has no role on this service.");
    }
    Ok(no_content(Extras::default()))
}

pub async fn get_user_access(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let c = caller(app, &ctx.req, true).await?;
    let user = user_or_404(app, ctx.param("id")).await?;
    let list = match &c {
        Caller::Client { service, .. } => {
            let rows = app
                .db()
                .query(
                    "SELECT a.service, a.role, a.granted_by, a.granted_at FROM access a JOIN users u ON u.id = a.user_id
                     WHERE a.user_id = $1 AND a.service = $2 AND u.disabled_at IS NULL",
                    &[&user.id, &service.name],
                )
                .await?;
            rows.iter().map(|r| Ok(access_json(&AccessRow::from_row(r)?))).collect::<Result<Vec<_>>>()?
        }
        Caller::User { .. } => {
            require_admin(&c)?;
            access_of(app, &user.id).await?
        }
    };
    Ok(json_response(200, &items(list)))
}

pub async fn delete_user_sessions(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let c = caller(app, &ctx.req, false).await?;
    let session = require_admin(&c)?;
    let user = user_or_404(app, ctx.param("id")).await?;
    let tx = app.begin().await?;
    let work = async {
        end_user_sessions(tx.q(), app, &user.id, None).await?;
        audit(tx.q(), Audit::new(Some(&session.user_id), "session.end_all").user(Some(&user.id)).ip(ctx.ip())).await?;
        admin_alert(app, &tx, &c, format!("signed {} out everywhere", user.username));
        Ok(())
    }
    .await;
    tx.finish(work).await?;
    Ok(no_content(Extras::default()))
}

/// A5: after verifying someone out of band. Audited and alerted.
pub async fn reset_user(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let c = caller(app, &ctx.req, false).await?;
    let session = require_admin(&c)?;
    let user = user_or_404(app, ctx.param("id")).await?;
    let body = read_json(&ctx.req)?;
    let send_link = body.get("send_link") == Some(&Value::Bool(true));
    let clear_mfa = body.get("clear_mfa") == Some(&Value::Bool(true));
    if !send_link && !clear_mfa {
        bail!(400, "invalid_request", "Set send_link, clear_mfa or both.");
    }
    if !user.is_person() {
        bail!(409, "conflict", "A bot user has no password or second factor.");
    }
    let email = user.email.clone().filter(|e| !e.is_empty());
    if send_link && email.is_none() {
        bail!(409, "conflict", "The user has no email address to send a link to.");
    }
    let tx = app.begin().await?;
    let work = async {
        let q = tx.q();
        if clear_mfa {
            q.execute("DELETE FROM totp WHERE user_id = $1", &[&user.id]).await?;
            q.execute("DELETE FROM passkeys WHERE user_id = $1", &[&user.id]).await?;
            q.execute("DELETE FROM recovery_codes WHERE user_id = $1", &[&user.id]).await?;
            end_user_sessions(q, app, &user.id, None).await?;
            audit(q, Audit::new(Some(&session.user_id), "mfa.cleared").user(Some(&user.id)).ip(ctx.ip())).await?;
            notify(app, &tx, user.email.as_deref(), &user.username, "two-factor authentication was cleared by an administrator", None);
        }
        if let (true, Some(email)) = (send_link, &email) {
            let token = issue_token(q, Purpose::Reset, &user.id, Some(email)).await?;
            audit(q, Audit::new(Some(&session.user_id), "reset.sent").user(Some(&user.id)).ip(ctx.ip())).await?;
            let (mailing, message) = (app.clone(), reset_email(&app.config.issuer, email, &token));
            tx.after(move || mailing.mail(message));
        }
        let did: Vec<String> = [clear_mfa.then_some("cleared the MFA of"), send_link.then_some("sent a reset link to")].into_iter().flatten().map(|a| format!("{a} {}", user.username)).collect();
        admin_alert(app, &tx, &c, did.join(" and "));
        Ok(())
    }
    .await;
    tx.finish(work).await?;
    Ok(no_content(Extras::default()))
}

// ----------------------------------------------------------------- invites

pub async fn post_invite(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let c = caller(app, &ctx.req, true).await?;
    let body = read_json(&ctx.req)?;
    let Some(service_name) = body.get("service").and_then(Value::as_str) else { bail!(400, "invalid_request", "service is required.") };
    let service = service_for(app, &c, service_name)?;
    let email = check_email(body.get("email"))?;
    let Some(role) = body.get("role").and_then(Value::as_str) else { bail!(400, "invalid_request", "role is required.") };
    let sender = match &c {
        Caller::Client { client, .. } => format!("client:{}", client.id),
        Caller::User { session, .. } => format!("user:{}", session.user_id),
    };
    let limit = email_allowed(app.db(), &email, &sender).await?;
    if !limit.allowed {
        return Err(Error::Http(HttpError::with(429, "rate_limited", "Too many invitations; try again later.", retry_after(limit.retry_after))));
    }
    let actor = actor_of(&c);
    let tx = app.begin().await?;
    let work = async {
        let invite = create_invite(&tx, app, &email, &service, role, &actor, ctx.ip()).await?;
        admin_alert(app, &tx, &c, format!("invited someone to {} as {}", service.name, invite.role));
        Ok(invite)
    }
    .await;
    Ok(json_response(201, &invite_json(&tx.finish(work).await?)))
}

// The one service a caller's invitation calls are limited to: its own for a
// client, none ("") for an admin.
fn invites_of(c: &Caller) -> Result<String> {
    match c {
        Caller::Client { service, .. } => Ok(service.name.clone()),
        Caller::User { .. } => {
            require_admin(c)?;
            Ok(String::new())
        }
    }
}

pub async fn list_invites(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let c = caller(app, &ctx.req, true).await?;
    let (after, limit) = page_params(&ctx.req)?;
    let own = invites_of(&c)?;
    let query = ctx.req.query();
    let service = if matches!(c, Caller::Client { .. }) { own } else { query.get("service").unwrap_or("").to_string() };
    let rows = app.db().query(&format!("SELECT {INVITE_COLUMNS} FROM invites WHERE ($1 = '' OR service = $1) AND id > $2 ORDER BY id LIMIT $3"), &[&service, &after, &(limit + 1)]).await?;
    let mut list = Vec::new();
    for r in &rows {
        let invite = InviteRow::from_row(r)?;
        list.push((invite.id.clone(), invite_json(&invite)));
    }
    Ok(json_response(200, &list_of(list, limit)))
}

pub async fn get_invite(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let c = caller(app, &ctx.req, true).await?;
    let service = invites_of(&c)?;
    let row = app.db().first(&format!("SELECT {INVITE_COLUMNS} FROM invites WHERE id = $1 AND ($2 = '' OR service = $2)"), &[&ctx.param("id"), &service]).await?;
    let Some(row) = row else { bail!(404, "not_found", "No such invitation.") };
    Ok(json_response(200, &invite_json(&InviteRow::from_row(&row)?)))
}

pub async fn delete_invite(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let c = caller(app, &ctx.req, true).await?;
    let service = invites_of(&c)?;
    let (id, actor) = (ctx.param("id"), actor_of(&c));
    let tx = app.begin().await?;
    let work = async {
        let rows = tx.q().query("DELETE FROM invites WHERE id = $1 AND ($2 = '' OR service = $2) RETURNING service", &[&id, &service]).await?;
        let Some(row) = rows.first() else { return Ok(false) };
        let of: String = row.try_get("service")?;
        audit(tx.q(), Audit::new(Some(&actor), "invite.delete").ip(ctx.ip()).detail(json!({ "id": id, "service": of }))).await?;
        admin_alert(app, &tx, &c, format!("withdrew an invitation to {of}"));
        Ok(true)
    }
    .await;
    if !tx.finish(work).await? {
        bail!(404, "not_found", "No such invitation.");
    }
    Ok(no_content(Extras::default()))
}

// ------------------------------------------------------- services and audit

// The live secrets of every confidential client, newest first, by client id.
async fn live_secrets(app: &App) -> Result<HashMap<String, Vec<DateTime<Utc>>>> {
    let rows = app.db().query("SELECT client_id, created_at FROM client_secrets WHERE revoked_at IS NULL ORDER BY created_at DESC", &[]).await?;
    let mut out: HashMap<String, Vec<DateTime<Utc>>> = HashMap::new();
    for r in &rows {
        out.entry(r.try_get("client_id")?).or_default().push(r.try_get("created_at")?);
    }
    Ok(out)
}

pub async fn list_services(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let c = caller(app, &ctx.req, false).await?;
    require_admin(&c)?;
    let secrets = live_secrets(app).await?;
    Ok(json_response(
        200,
        &json!({
            "items": app.services.all().iter().map(|s| service_json(s, &secrets)).collect::<Vec<_>>(),
            "held": app.services.held.iter().map(|s| service_json(s, &secrets)).collect::<Vec<_>>(),
            "next": null,
        }),
    ))
}

// A change to a service can add a redirect URI and make a secret, which is
// enough to sign in to its app as anyone: it needs what a credential change
// needs (§6.2).
async fn service_admin(app: &App, req: &Request) -> Result<Caller> {
    let c = caller(app, req, false).await?;
    let session = require_admin(&c)?;
    require_recent(app, session).await?;
    Ok(c)
}

// A registration's body: one service in the shape of §6, every problem listed.
fn registration(app: &App, req: &Request) -> Result<Service> {
    let (service, mut problems) = parse_service(&Value::Object(read_json(req)?), Source::Database);
    if !service.api_key_scopes.is_empty() && app.config.api_key_prefix.is_none() {
        problems.push("api_key_scopes needs API_KEY_PREFIX, which this deployment hasn't set".into());
    }
    if !problems.is_empty() {
        bail!(400, "invalid_request", "{}", problems.join("; "));
    }
    Ok(service)
}

fn uri_list(uris: &[String]) -> String {
    if uris.is_empty() {
        "none".to_string()
    } else {
        uris.join(", ")
    }
}

fn registered_json(service: &Service, held: bool) -> Value {
    merged(service_json(service, &HashMap::new()), json!({ "held": held }))
}

pub async fn post_service(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let c = service_admin(app, &ctx.req).await?;
    let actor = actor_of(&c);
    let service = registration(app, &ctx.req)?;
    let tx = app.begin().await?;
    let work = async {
        let held = insert_service(tx.q(), &app.services, &service, &actor).await?;
        let clients: Vec<&str> = service.clients.iter().map(|cl| cl.id.as_str()).collect();
        audit(tx.q(), Audit::new(Some(&actor), "service.create").ip(ctx.ip()).detail(json!({ "service": service.name, "clients": clients, "held": held }))).await?;
        let uris: Vec<String> = service.clients.iter().flat_map(|cl| cl.redirect_uris.iter().chain(cl.post_logout_redirect_uris.iter())).cloned().collect();
        let as_held = if held { " as a held copy of the services file's" } else { "" };
        admin_alert(app, &tx, &c, format!("registered the service {}{as_held}, with the redirect URIs {}", service.name, uri_list(&uris)));
        Ok(held)
    }
    .await;
    let held = tx.finish(work).await?;
    Ok(json_response(201, &registered_json(&service, held)))
}

// The service a change may touch: one registered on the admin page and in
// effect. The file's change with the file, and a held copy is deleted, not
// changed (§6.2).
fn registered_service(app: &App, name: &str, delete: bool) -> Result<()> {
    let source = app.services.get(name).map(|s| s.source);
    if source == Some(Source::Builtin) {
        bail!(409, "conflict", "auth's own service can't be {}.", if delete { "deleted" } else { "changed" });
    }
    let held_copy = app.services.held.iter().any(|h| h.name == name);
    if delete && held_copy {
        return Ok(());
    }
    if source == Some(Source::File) {
        bail!(409, "conflict", "{name} is declared in the services file; {} it there.", if delete { "delete" } else { "change" });
    }
    if held_copy {
        bail!(409, "conflict", "{name} is a held copy; delete it and copy the service again.");
    }
    if source.is_none() {
        bail!(404, "not_found", "There is no service \"{name}\".");
    }
    Ok(())
}

pub async fn put_service(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let c = service_admin(app, &ctx.req).await?;
    let actor = actor_of(&c);
    let name = ctx.param("name");
    registered_service(app, name, false)?;
    let service = registration(app, &ctx.req)?;
    if service.name != name {
        bail!(400, "invalid_request", "A service's name can't change.");
    }
    let tx = app.begin().await?;
    let work = async {
        let change = replace_service(tx.q(), &app.services, &service).await?;
        if change.fields.is_empty() {
            return Ok(());
        }
        let detail = json!({ "service": name, "fields": change.fields, "added_clients": change.added_clients, "removed_clients": change.removed_clients });
        audit(tx.q(), Audit::new(Some(&actor), "service.update").ip(ctx.ip()).detail(detail)).await?;
        let added = if change.added_uris.is_empty() { String::new() } else { format!("; added the redirect URIs {}", uri_list(&change.added_uris)) };
        admin_alert(app, &tx, &c, format!("changed the {} of the service {name}{added}", change.fields.join(", ")));
        Ok(())
    }
    .await;
    tx.finish(work).await?;
    Ok(json_response(200, &registered_json(&service, false)))
}

pub async fn delete_service(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let c = service_admin(app, &ctx.req).await?;
    let actor = actor_of(&c);
    let name = ctx.param("name");
    registered_service(app, name, true)?;
    let tx = app.begin().await?;
    let work = async {
        let held = remove_service(tx.q(), &app.services, name).await?;
        audit(tx.q(), Audit::new(Some(&actor), "service.delete").ip(ctx.ip()).detail(json!({ "service": name, "held": held }))).await?;
        let what = if held { format!("deleted the held copy of the service {name}") } else { format!("deleted the service {name}, with every role, invitation and credential on it") };
        admin_alert(app, &tx, &c, what);
        Ok(())
    }
    .await;
    tx.finish(work).await?;
    Ok(no_content(Extras::default()))
}

// A registered service's confidential client. The services file's are out
// of an admin's reach: their secrets come from the CLI (§6.2).
fn confidential_client(app: &App, id: &str) -> Result<(Client, Arc<Service>)> {
    let Some(client) = app.services.client(id) else { bail!(404, "not_found", "No such client.") };
    if client.public {
        bail!(409, "conflict", "A public client has no secret.");
    }
    let service = app.services.get(&client.service).ok_or(Error::Other("ServiceError"))?;
    if service.source != Source::Database {
        bail!(409, "conflict", "{id} is a client of the services file: make its secret with the CLI ({} client secret {id}).", crate::cli::NAME);
    }
    Ok((client.clone(), service.clone()))
}

/// A new secret, shown once. The newest earlier one keeps working until the
/// old ones are retired, so the app can be moved to this one (§9.3).
pub async fn post_client_secret(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let c = service_admin(app, &ctx.req).await?;
    let actor = actor_of(&c);
    let (client, service) = confidential_client(app, ctx.param("id"))?;
    let tx = app.begin().await?;
    let work = async {
        lock_client(tx.q(), &service, &client).await?;
        let secret = rotate_client_secret(tx.q(), &client.id).await?;
        audit(tx.q(), Audit::new(Some(&actor), "client.secret").ip(ctx.ip()).detail(json!({ "client": client.id }))).await?;
        admin_alert(app, &tx, &c, format!("made a new secret for the client {}", client.id));
        Ok(secret)
    }
    .await;
    let secret = tx.finish(work).await?;
    Ok(json_response(201, &json!({ "client_id": client.id, "service": service.name, "secret": secret })))
}

pub async fn retire_old_secrets(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let c = service_admin(app, &ctx.req).await?;
    let actor = actor_of(&c);
    let (client, service) = confidential_client(app, ctx.param("id"))?;
    let tx = app.begin().await?;
    let work = async {
        lock_client(tx.q(), &service, &client).await?;
        let retired = retire_old_client_secrets(tx.q(), &client.id).await?;
        audit(tx.q(), Audit::new(Some(&actor), "client.secret_retire").ip(ctx.ip()).detail(json!({ "client": client.id, "retired": retired }))).await?;
        if retired > 0 {
            admin_alert(app, &tx, &c, format!("retired the old secrets of the client {}", client.id));
        }
        Ok(retired)
    }
    .await;
    let retired = tx.finish(work).await?;
    Ok(json_response(200, &json!({ "client_id": client.id, "retired": retired })))
}

pub async fn list_audit(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let c = caller(app, &ctx.req, false).await?;
    require_admin(&c)?;
    let (after, limit) = page_params(&ctx.req)?;
    // Newest first; the cursor is the last id seen.
    let before: Option<i64> = match after.as_str() {
        "" => None,
        digits if digits.bytes().all(|b| b.is_ascii_digit()) => Some(digits.parse().map_err(|_| http(400, "invalid_request", "after is not a cursor."))?),
        _ => bail!(400, "invalid_request", "after is not a cursor."),
    };
    let query = ctx.req.query();
    let user = query.get("user").unwrap_or("");
    let rows = app
        .db()
        .query(
            "SELECT id, at, actor, action, user_id, host(ip) AS ip, detail FROM audit
             WHERE ($1 = '' OR user_id = $1) AND ($2::bigint IS NULL OR id < $2)
             ORDER BY id DESC LIMIT $3",
            &[&user, &before, &(limit + 1)],
        )
        .await?;
    let mut list = Vec::new();
    for r in &rows {
        let id = r.try_get::<_, i64>("id")?.to_string();
        list.push((
            id.clone(),
            json!({
                "id": id,
                "at": iso(&r.try_get::<_, DateTime<Utc>>("at")?),
                "actor": r.try_get::<_, Option<String>>("actor")?,
                "action": r.try_get::<_, String>("action")?,
                "user_id": r.try_get::<_, Option<String>>("user_id")?,
                "ip": r.try_get::<_, Option<String>>("ip")?,
                "detail": r.try_get::<_, Value>("detail")?,
            }),
        ));
    }
    Ok(json_response(200, &list_of(list, limit)))
}
