//! SSO sessions at the issuer (docs/DESIGN.md §9.2). The cookie holds 32
//! random bytes and only their SHA-256 is stored. A session lasts 7 days idle
//! and 30 days absolute; its token is replaced at every sign-in and step-up.

use serde_json::json;

use crate::app::App;
use crate::crypto::{is_token, new_id, random_token, sha256};
use crate::db::Q;
use crate::error::{http, Result};
use crate::events::{emit, emit_session_ended, services_of_clients};
use crate::http::{clear_cookie, from_issuer, host_cookie, set_cookie, Request};
use crate::util::utf16_prefix;

pub const COOKIE: &str = "auth";
const IDLE_DAYS: i32 = 7;
const ABSOLUTE_DAYS: i32 = 30;
/// Changing a credential needs a full sign-in this recent (§7.5).
pub const REAUTH_SECONDS: i64 = 15 * 60;

#[derive(Clone)]
pub struct Session {
    pub id: String,
    pub token: String,
    pub user_id: String,
    pub username: String,
    pub name: String,
    pub email: Option<String>,
    pub amr: Vec<String>,
    /// Seconds since the last full sign-in, by the database's clock.
    pub auth_age: i64,
}

impl Session {
    pub fn has_mfa(&self) -> bool {
        has_mfa(&self.amr)
    }
}

pub fn has_mfa(amr: &[String]) -> bool {
    amr.iter().any(|m| m == "mfa")
}

pub async fn load_session(app: &App, req: &Request) -> Result<Option<Session>> {
    let Some(token) = host_cookie(req, COOKIE).filter(|t| is_token(t)) else { return Ok(None) };
    let row = app
        .db()
        .first(
            "SELECT s.id, s.user_id, s.amr,
                    extract(epoch FROM now() - s.auth_time)::int AS auth_age,
                    s.last_seen_at < now() - interval '1 minute' AS stale,
                    u.username, u.name, u.email
             FROM sessions s JOIN users u ON u.id = s.user_id
             WHERE s.token_hash = $1 AND s.expires_at > now() AND s.ends_at > now()
               AND u.disabled_at IS NULL AND u.kind = 'person'",
            &[&sha256(token.as_bytes())],
        )
        .await?;
    let Some(row) = row else { return Ok(None) };
    let id: String = row.try_get("id")?;
    if row.try_get::<_, bool>("stale")? {
        touch(app.db(), &id).await?;
    }
    Ok(Some(Session {
        id,
        token,
        user_id: row.try_get("user_id")?,
        username: row.try_get("username")?,
        name: row.try_get("name")?,
        email: row.try_get("email")?,
        amr: row.try_get("amr")?,
        auth_age: i64::from(row.try_get::<_, i32>("auth_age")?),
    }))
}

/// Use at auth or by an app's refresh keeps the session alive, up to its
/// absolute end.
pub async fn touch(q: Q<'_>, session_id: &str) -> Result<()> {
    q.execute("UPDATE sessions SET last_seen_at = now(), expires_at = LEAST(now() + make_interval(days => $2), ends_at) WHERE id = $1", &[&session_id, &IDLE_DAYS]).await?;
    Ok(())
}

pub fn session_cookie(token: &str) -> String {
    set_cookie(COOKIE, token, Some(i64::from(ABSOLUTE_DAYS) * 24 * 60 * 60), "Lax")
}

pub fn clear_session_cookie() -> String {
    clear_cookie(COOKIE)
}

/// A full sign-in. The same user signing in again keeps the session's id, the
/// `sid` apps hold, with a new token, sign-in time and lifetime; anyone else
/// gets a new session, and the previous one ends. Answers the session's id
/// and its new token.
pub async fn sign_in_session(q: Q<'_>, app: &App, user_id: &str, amr: &[String], previous: Option<(&str, &str)>, ip: Option<&str>, user_agent: Option<&str>) -> Result<(String, String)> {
    let token = random_token();
    let hash = sha256(token.as_bytes());
    let ua = user_agent.map(|u| utf16_prefix(u, 512));
    let amr = amr.to_vec();
    match previous {
        Some((previous_id, previous_user)) if previous_user == user_id => {
            let rows = q
                .query(
                    "UPDATE sessions SET token_hash = $2, auth_time = now(), amr = $3,
                       ip = $4::text::inet, user_agent = $5, last_seen_at = now(),
                       expires_at = now() + make_interval(days => $6), ends_at = now() + make_interval(days => $7)
                     WHERE id = $1 RETURNING id",
                    &[&previous_id, &hash, &amr, &ip, &ua, &IDLE_DAYS, &ABSOLUTE_DAYS],
                )
                .await?;
            if rows.len() == 1 {
                return Ok((previous_id.to_string(), token));
            }
        }
        Some((previous_id, _)) => end_session(q, app, previous_id).await?,
        None => {}
    }
    let id = new_id("ses");
    q.execute(
        "INSERT INTO sessions (id, user_id, token_hash, auth_time, amr, ip, user_agent, expires_at, ends_at)
         VALUES ($1, $2, $3, now(), $4, $5::text::inet, $6, now() + make_interval(days => $7), now() + make_interval(days => $8))",
        &[&id, &user_id, &hash, &amr, &ip, &ua, &IDLE_DAYS, &ABSOLUTE_DAYS],
    )
    .await?;
    Ok((id, token))
}

/// A second factor added to a signed-in session: new methods, new token,
/// same sign-in time.
pub async fn step_up(q: Q<'_>, session_id: &str, amr: &[String]) -> Result<String> {
    let token = random_token();
    q.execute("UPDATE sessions SET token_hash = $2, amr = $3 WHERE id = $1", &[&session_id, &sha256(token.as_bytes()), &amr.to_vec()]).await?;
    Ok(token)
}

/// Ends one SSO session, and with it the refresh tokens of the confidential
/// clients that used it; each app that holds tokens under it is told.
pub async fn end_session(q: Q<'_>, app: &App, session_id: &str) -> Result<()> {
    emit_session_ended(q, app, session_id).await?;
    q.execute("DELETE FROM sessions WHERE id = $1", &[&session_id]).await?;
    Ok(())
}

/// Serializes everything that ends or extends a refresh-token family, taken
/// before any of its rows is locked: otherwise a rotation in flight could
/// insert a token an ending UPDATE never sees.
pub async fn lock_family(q: Q<'_>, family_id: &str) -> Result<()> {
    q.query("SELECT pg_advisory_xact_lock(hashtext($1))", &[&format!("family:{family_id}")]).await?;
    Ok(())
}

/// Ends a public client's refresh-token family, which outlives the SSO session
/// it started from; its id is the `sid` of the tokens it issued.
pub async fn end_family(q: Q<'_>, app: &App, family_id: &str, user_id: &str) -> Result<bool> {
    lock_family(q, family_id).await?;
    let rows = q
        .query(
            "UPDATE refresh_tokens SET revoked_at = now()
             WHERE family_id = $1 AND user_id = $2 AND session_id IS NULL AND revoked_at IS NULL
             RETURNING client_id",
            &[&family_id, &user_id],
        )
        .await?;
    let mut ids = Vec::new();
    for r in &rows {
        ids.push(r.try_get::<_, String>("client_id")?);
    }
    for service in services_of_clients(app, ids.into_iter()) {
        emit(q, app, &service, "session.ended", json!({ "sid": family_id })).await?;
    }
    Ok(!rows.is_empty())
}

/// Signs a user out everywhere: every SSO session and every public client's
/// family, except the one session named.
pub async fn end_user_sessions(q: Q<'_>, app: &App, user_id: &str, except: Option<&str>) -> Result<()> {
    for s in &q.query("SELECT id FROM sessions WHERE user_id = $1", &[&user_id]).await? {
        let id: String = s.try_get("id")?;
        if Some(id.as_str()) != except {
            end_session(q, app, &id).await?;
        }
    }
    let families = q.query("SELECT DISTINCT family_id FROM refresh_tokens WHERE user_id = $1 AND session_id IS NULL AND revoked_at IS NULL", &[&user_id]).await?;
    for f in &families {
        end_family(q, app, &f.try_get::<_, String>("family_id")?, user_id).await?;
    }
    Ok(())
}

/// The synchronizer token of §9.2, derived from the session's own token, so
/// it changes whenever the session's token does and needs no storage.
pub fn csrf_token(app: &App, session: &Session) -> String {
    app.crypt.hmac("csrf", &session.token)
}

/// A signed-in browser's state-changing request: Origin must be the issuer's,
/// and the synchronizer token must match.
pub fn require_csrf(app: &App, req: &Request, session: &Session) -> Result<()> {
    require_origin(app, req)?;
    let sent = req.header("X-CSRF-Token").unwrap_or_default();
    if !app.crypt.hmac_matches("csrf", &session.token, &sent) {
        return Err(http(403, "forbidden", "The CSRF token is missing or wrong."));
    }
    Ok(())
}

pub fn require_origin(app: &App, req: &Request) -> Result<()> {
    if !from_issuer(&app.config.issuer, req) {
        return Err(http(403, "forbidden", "The request's Origin is not this issuer."));
    }
    Ok(())
}
