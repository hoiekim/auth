//! Events to apps (docs/DESIGN.md §7.4): Security Event Tokens signed when the
//! change commits, written to the outbox in the same transaction, and POSTed
//! to each service's events_url until it answers 2xx.

use std::time::Duration;

use serde_json::{json, Value};

use crate::app::App;
use crate::crypto::new_id;
use crate::db::Q;
use crate::error::Result;
use crate::jwt::sign_jwt;
use crate::util::{from_b64, now_ms, now_secs};

/// Queues one event for one service, inside the caller's transaction. A
/// service without an events_url relies on the pull (§7.1), so it gets none.
pub async fn emit(q: Q<'_>, app: &App, service: &str, event: &str, payload: Value) -> Result<()> {
    if app.services.get(service).and_then(|s| s.events_url.as_ref()).is_none() {
        return Ok(());
    }
    let signer = app.keys.signer(&app.crypt, q).await?;
    let mut events = serde_json::Map::new();
    events.insert(event.to_string(), payload);
    let claims = json!({ "iss": app.config.issuer, "aud": service, "iat": now_secs(), "jti": new_id("evt"), "events": events });
    let token = sign_jwt("secevent+jwt", &claims, &signer);
    q.execute("INSERT INTO outbox (service, token) VALUES ($1, $2)", &[&service, &token]).await?;
    Ok(())
}

/// To every service that takes events: disabling or deleting a user reaches
/// every app, whichever ones they used.
pub async fn emit_all(q: Q<'_>, app: &App, event: &str, payload: Value) -> Result<()> {
    for s in app.services.all() {
        emit(q, app, &s.name, event, payload.clone()).await?;
    }
    Ok(())
}

/// The services, each once, that the clients named in `rows` belong to.
pub fn services_of_clients(app: &App, client_ids: impl Iterator<Item = String>) -> Vec<String> {
    let mut services: Vec<String> = Vec::new();
    for id in client_ids {
        if let Some(c) = app.services.client(&id) {
            if !services.contains(&c.service) {
                services.push(c.service.clone());
            }
        }
    }
    services
}

/// Every service whose clients hold refresh tokens under a session, so its
/// end reaches each app that signed in with it.
pub async fn emit_session_ended(q: Q<'_>, app: &App, sid: &str) -> Result<()> {
    let rows = q.query("SELECT DISTINCT client_id FROM refresh_tokens WHERE session_id = $1 OR family_id = $1", &[&sid]).await?;
    let mut ids = Vec::new();
    for r in &rows {
        ids.push(r.try_get::<_, String>("client_id")?);
    }
    for service in services_of_clients(app, ids.into_iter()) {
        emit(q, app, &service, "session.ended", json!({ "sid": sid })).await?;
    }
    Ok(())
}

const LEASE_SECONDS: f64 = 60.0;
const GIVE_UP_SECONDS: f64 = 24.0 * 60.0 * 60.0;
const MAX_BACKOFF_SECONDS: f64 = 60.0 * 60.0;

struct Due {
    id: i64,
    service: String,
    token: String,
    attempts: i32,
}

/// One pass over the due events. Rows are leased with SKIP LOCKED, so copies
/// running this at once never deliver the same row in the same pass, and a
/// copy that dies mid-delivery leaves its rows to be retried after the lease.
pub async fn deliver_due(app: &App, limit: i64) -> Result<usize> {
    let rows = app
        .db()
        .query(
            "UPDATE outbox SET attempts = attempts + 1, next_attempt_at = now() + make_interval(secs => $1)
             WHERE id IN (
               SELECT id FROM outbox
               WHERE delivered_at IS NULL AND failed_at IS NULL AND next_attempt_at <= now()
               ORDER BY id LIMIT $2
               FOR UPDATE SKIP LOCKED)
             RETURNING id, service, token, attempts",
            &[&LEASE_SECONDS, &limit],
        )
        .await?;
    if rows.is_empty() {
        return Ok(0);
    }
    // Each to its service's events_url as it is now.
    let current = app.prepare().await?;
    let mut deliveries = tokio::task::JoinSet::new();
    let count = rows.len();
    for r in &rows {
        let due = Due { id: r.try_get("id")?, service: r.try_get("service")?, token: r.try_get("token")?, attempts: r.try_get("attempts")? };
        let app = current.clone();
        deliveries.spawn(async move { deliver_one(&app, due).await });
    }
    let mut failure = None;
    while let Some(done) = deliveries.join_next().await {
        if let Ok(Err(e)) = done {
            failure = Some(e);
        }
    }
    match failure {
        Some(e) => Err(e),
        None => Ok(count),
    }
}

async fn deliver_one(app: &App, row: Due) -> Result<()> {
    let url = app.services.get(&row.service).and_then(|s| s.events_url.clone());
    let mut delivered = false;
    if let Some(url) = &url {
        let request = app.http.post(url).header("Content-Type", "application/secevent+jwt").header("Accept", "application/json").body(row.token.clone()).timeout(Duration::from_millis(5000));
        if let Ok(res) = request.send().await {
            delivered = res.status().is_success();
        }
    }
    if delivered {
        app.db().execute("UPDATE outbox SET delivered_at = now() WHERE id = $1", &[&row.id]).await?;
        return Ok(());
    }
    // iat was set from this process's clock at signing, so age is measured on
    // the same clock.
    let age = now_ms() as f64 / 1000.0 - issued_at(&row.token);
    let give_up = url.is_none() || age >= GIVE_UP_SECONDS;
    let backoff = (5.0 * 2f64.powi((row.attempts - 1).max(0))).min(MAX_BACKOFF_SECONDS);
    if give_up {
        app.db().execute("UPDATE outbox SET failed_at = now() WHERE id = $1", &[&row.id]).await?;
        app.log(&format!("event {} for {} given up after {} attempts", row.id, row.service, row.attempts));
        app.alert(format!("auth: gave up delivering an event to {} after {} attempts", row.service, row.attempts));
    } else {
        app.db().execute("UPDATE outbox SET next_attempt_at = now() + make_interval(secs => $2) WHERE id = $1", &[&row.id, &backoff]).await?;
    }
    Ok(())
}

fn issued_at(token: &str) -> f64 {
    let payload = token.split('.').nth(1).unwrap_or("");
    crate::json::parse(&String::from_utf8_lossy(&from_b64(payload))).and_then(|p| p.get("iat").filter(|v| v.is_number()).and_then(Value::as_f64)).unwrap_or(0.0)
}
