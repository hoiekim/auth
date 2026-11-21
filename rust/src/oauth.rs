//! The OAuth 2.0 and OpenID Connect endpoints (docs/DESIGN.md §7.1–§7.3): the
//! authorization code flow with PKCE and nothing more.

use serde_json::{json, Value};
use url::Url;

use crate::access::{role_at_sign_in, role_of};
use crate::app::App;
use crate::audit::{audit, client_actor, Audit};
use crate::clients::authenticate_client;
use crate::credentials::introspect_secret;
use crate::crypto::{new_id, random_token, safe_equal, sha256};
use crate::db::Q;
use crate::error::{http, Error, HttpError, Result};
use crate::events::emit_session_ended;
use crate::factors::factors_of;
use crate::http::{error_response, json as json_response, json_with, read_form, redirect, retry_after, Extras, Params, Response};
use crate::jwt::{sign_jwt, verify_jwt, VerifyOptions};
use crate::net::{format_ip, parse_ip};
use crate::pages::layout::message_page;
use crate::registry::lock_client;
use crate::server::Ctx;
use crate::services::{Client, Service};
use crate::sessions::{clear_session_cookie, end_family, end_session, has_mfa, load_session, lock_family, touch};
use crate::throttle::{hit, peek};
use crate::util::{b64url, form_encode, js_trim, now_secs, utf16_len};

const ACCESS_TOKEN_SECONDS: i64 = 600;
const CODE_SECONDS: f64 = 60.0;
const PUBLIC_REFRESH_DAYS: i32 = 30;
const REUSE_GRACE_SECONDS: f64 = 30.0;

fn cached_for_an_hour() -> Vec<(String, String)> {
    vec![("Cache-Control".to_string(), "public, max-age=3600".to_string())]
}

pub async fn discovery(ctx: Ctx) -> Result<Response> {
    let iss = &ctx.app.config.issuer;
    let body = json!({
        "issuer": iss,
        "authorization_endpoint": format!("{iss}/oauth/authorize"),
        "token_endpoint": format!("{iss}/oauth/token"),
        "userinfo_endpoint": format!("{iss}/oauth/userinfo"),
        "jwks_uri": format!("{iss}/.well-known/jwks.json"),
        "end_session_endpoint": format!("{iss}/logout"),
        "revocation_endpoint": format!("{iss}/oauth/revoke"),
        "introspection_endpoint": format!("{iss}/oauth/introspect"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "none"],
        "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "none"],
        "introspection_endpoint_auth_methods_supported": ["client_secret_basic"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["openid", "profile", "email"],
        "prompt_values_supported": ["none", "login"],
        "claims_supported": ["iss", "sub", "aud", "iat", "exp", "sid", "username", "name", "role", "nonce", "auth_time", "amr", "email", "email_verified"],
    });
    Ok(json_with(200, &body, &cached_for_an_hour(), Vec::new()))
}

pub async fn jwks(ctx: Ctx) -> Result<Response> {
    Ok(json_with(200, &ctx.app.keys.jwks(ctx.app.db()).await?, &cached_for_an_hour(), Vec::new()))
}

// RFC 7636 §4.1: 43 to 128 unreserved characters. `^[A-Za-z0-9._~-]{43,128}$`
fn is_verifier(s: &str) -> bool {
    (43..=128).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._~-".contains(&b))
}

// ---------------------------------------------------------------- authorize

// Errors that can't be sent back to the client (an unknown client or an
// unregistered redirect URI) are shown here, never redirected (RFC 6749
// §4.1.2.1).
fn authorize_error_page(app: &App, message: &str) -> Response {
    message_page(app, 400, "This sign-in link is not valid", message, None, Extras::default())
}

/// A registered address with parameters added to its query, as
/// `url.searchParams.append` writes them.
fn with_params(uri: &str, params: &[(&str, &str)]) -> String {
    let Ok(mut url) = Url::parse(uri) else { return uri.to_string() };
    let mut pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
    pairs.extend(params.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    url.query_pairs_mut().clear().extend_pairs(pairs);
    url.to_string()
}

fn back_to_client(redirect_uri: &str, params: &[(&str, &str)]) -> Response {
    redirect(&with_params(redirect_uri, params), Extras::default(), 302)
}

enum Outcome {
    NoAccess,
    NeedsMfa,
    Code(String),
}

pub async fn authorize(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let q = ctx.req.query();
    let (Ok(client_id), Ok(redirect_uri)) = (q.single("client_id"), q.single("redirect_uri")) else {
        return Ok(authorize_error_page(app, "A parameter is repeated."));
    };
    let Some(client) = client_id.filter(|c| !c.is_empty()).and_then(|c| app.services.client(c)) else {
        return Ok(authorize_error_page(app, "The app that sent you here is not registered."));
    };
    let Some(redirect_uri) = redirect_uri.filter(|r| !r.is_empty() && client.redirect_uris.iter().any(|u| u == r)) else {
        return Ok(authorize_error_page(app, "The app sent you here with a return address it hasn't registered."));
    };
    let service = app.services.get(&client.service).ok_or(Error::Other("ServiceError"))?.clone();

    let fail = |state: Option<&str>, error: &str, description: &str| {
        let mut params = vec![("error", error), ("error_description", description)];
        if let Some(state) = state {
            params.push(("state", state));
        }
        Ok(back_to_client(redirect_uri, &params))
    };
    const NAMES: [&str; 9] = ["response_type", "state", "code_challenge", "code_challenge_method", "scope", "nonce", "prompt", "max_age", "login_hint"];
    let mut given: Vec<Option<&str>> = Vec::new();
    for name in NAMES {
        match q.single(name) {
            Ok(v) => given.push(v),
            Err(_) => return fail(None, "invalid_request", "A parameter is repeated."),
        }
    }
    let [response_type, state, code_challenge, code_challenge_method, scope, nonce, prompt, max_age, login_hint] = given[..] else { unreachable!() };
    if response_type != Some("code") {
        return fail(state, "unsupported_response_type", "Only response_type=code is supported.");
    }
    let Some(valid_state) = state.filter(|s| !s.is_empty() && utf16_len(s) <= 1024) else {
        return fail(state, "invalid_request", "state is required.");
    };
    let challenge = code_challenge.filter(|c| c.len() == 43 && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'));
    let (Some(challenge), Some("S256")) = (challenge, code_challenge_method) else {
        return fail(state, "invalid_request", "PKCE is required: code_challenge with code_challenge_method=S256.");
    };
    let openid = scope.unwrap_or("").split(' ').any(|s| s == "openid");
    let nonce = nonce.filter(|n| !n.is_empty());
    if openid && nonce.is_none() {
        return fail(state, "invalid_request", "nonce is required with the openid scope.");
    }
    if nonce.is_some_and(|n| utf16_len(n) > 1024) {
        return fail(state, "invalid_request", "nonce is too long.");
    }
    if !matches!(prompt, None | Some("none") | Some("login")) {
        return fail(state, "invalid_request", "prompt may be none or login.");
    }
    let max_age: Option<i64> = match max_age {
        None => None,
        Some(m) if (1..=9).contains(&m.len()) && m.bytes().all(|b| b.is_ascii_digit()) => m.parse().ok(),
        Some(_) => return fail(state, "invalid_request", "max_age must be a whole number of seconds."),
    };

    let session = load_session(app, &ctx.req).await?;
    let session = match session {
        Some(s) if prompt != Some("login") && max_age.is_none_or(|m| s.auth_age <= m) => s,
        _ => {
            if prompt == Some("none") {
                return fail(state, "login_required", "The user is not signed in.");
            }
            // Back here after the sign-in, which is then fresh: prompt and max_age
            // have done their job and are left out, or they would ask again.
            let kept: Vec<(&str, &str)> = q.0.iter().filter(|(k, _)| k != "prompt" && k != "max_age").map(|(k, v)| (k.as_str(), v.as_str())).collect();
            let back = if kept.is_empty() { ctx.req.path().to_string() } else { format!("{}?{}", ctx.req.path(), form_encode(&kept)) };
            let mut login = vec![("return_to", back.as_str())];
            if let Some(hint) = login_hint.filter(|h| !h.is_empty() && utf16_len(h) <= 254) {
                login.push(("login_hint", hint));
            }
            return Ok(redirect(&format!("/login?{}", form_encode(&login)), Extras::default(), 302));
        }
    };

    let tx = app.begin().await?;
    let work = async {
        let Some(role) = role_at_sign_in(&tx, app, &session.user_id, &service, ctx.ip()).await? else { return Ok(Outcome::NoAccess) };
        if service.requires_mfa(&role) && !session.has_mfa() {
            return Ok(Outcome::NeedsMfa);
        }
        let code = random_token();
        tx.q()
            .execute(
                "INSERT INTO auth_codes (code_hash, client_id, session_id, redirect_uri, code_challenge, nonce, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(secs => $7))",
                &[&sha256(code.as_bytes()), &client.id, &session.id, &redirect_uri, &challenge, &nonce, &CODE_SECONDS],
            )
            .await?;
        Ok(Outcome::Code(code))
    }
    .await;
    match tx.finish(work).await? {
        Outcome::NoAccess => {
            if prompt == Some("none") {
                return fail(state, "access_denied", "The user has no access to this service.");
            }
            let message = format!("You don't have access to {}. Ask an administrator for access.", service.name);
            Ok(message_page(app, 403, "No access", &message, Some(("/account", "Your account")), Extras::default()))
        }
        Outcome::NeedsMfa => {
            if prompt == Some("none") {
                return fail(state, "interaction_required", "This role needs a sign-in with a second factor.");
            }
            let factors = factors_of(app.db(), &session.user_id).await?;
            let back = ctx.req.path_and_search();
            let location = if factors.totp || factors.passkeys > 0 {
                format!("/login?{}", form_encode(&[("return_to", &back), ("second_factor", &service.name)]))
            } else {
                format!("/mfa-required?{}", form_encode(&[("service", &service.name), ("return_to", &back)]))
            };
            Ok(redirect(&location, Extras::default(), 302))
        }
        Outcome::Code(code) => Ok(back_to_client(redirect_uri, &[("code", &code), ("state", valid_state)])),
    }
}

// -------------------------------------------------------------------- token

struct Holder {
    user_id: String,
    username: String,
    name: String,
    email: Option<String>,
    email_verified: bool,
}

async fn holder(q: Q<'_>, user_id: &str) -> Result<Option<Holder>> {
    let row = q.first("SELECT id, username, name, email, email_verified_at IS NOT NULL AS email_verified FROM users WHERE id = $1 AND disabled_at IS NULL", &[&user_id]).await?;
    match row {
        Some(u) => Ok(Some(Holder { user_id: u.try_get("id")?, username: u.try_get("username")?, name: u.try_get("name")?, email: u.try_get("email")?, email_verified: u.try_get("email_verified")? })),
        None => Ok(None),
    }
}

// Claims are the ones §7.3 lists, and no others.
async fn access_token(app: &App, user: &Holder, service: &str, sid: &str, role: &str, now: i64) -> Result<String> {
    let claims = json!({
        "iss": app.config.issuer,
        "sub": user.user_id,
        "aud": service,
        "iat": now,
        "exp": now + ACCESS_TOKEN_SECONDS,
        "sid": sid,
        "username": user.username,
        "name": user.name,
        "role": role,
    });
    Ok(sign_jwt("at+jwt", &claims, &app.keys.signer(&app.crypt, app.db()).await?))
}

// A role that needs MFA, held by a sign-in that didn't use it, gets no token
// (§9.1), so a promotion takes effect at the next refresh.
fn mfa_missing(service: &Service, role: &str, amr: &[String]) -> bool {
    service.requires_mfa(role) && !has_mfa(amr)
}

pub async fn token(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let form = read_form(&ctx.req)?;
    let client = authenticate_client(app, &ctx.req, Some(&form), true).await?;
    let limit = hit(app.db(), &format!("client:{}:token", client.id), 60, 60).await?;
    if !limit.allowed {
        return Err(Error::Http(HttpError::with(429, "rate_limited", "Too many token requests.", retry_after(limit.retry_after))));
    }
    let grant = form.single("grant_type")?;
    let service = app.services.get(&client.service).ok_or(Error::Other("ServiceError"))?.clone();
    let mut res = match grant {
        Some("authorization_code") => code_grant(app, &client, &service, &form).await?,
        Some("refresh_token") => refresh_grant(app, &client, &service, &form).await?,
        _ => return Err(http(400, "unsupported_grant_type", "Use authorization_code or refresh_token.")),
    };
    res.set_header("Pragma", "no-cache");
    Ok(res)
}

struct CodeResult {
    user: Holder,
    role: String,
    sid: String,
    refresh: String,
    amr: Vec<String>,
    auth_time: i64,
    nonce: Option<String>,
}

async fn code_grant(app: &App, client: &Client, service: &Service, form: &Params) -> Result<Response> {
    let code = form.single("code")?.filter(|v| !v.is_empty());
    let redirect_uri = form.single("redirect_uri")?.filter(|v| !v.is_empty());
    let verifier = form.single("code_verifier")?.filter(|v| !v.is_empty());
    let (Some(code), Some(redirect_uri), Some(verifier)) = (code, redirect_uri, verifier) else {
        return Err(http(400, "invalid_request", "code, redirect_uri and code_verifier are required."));
    };
    if !is_verifier(verifier) {
        return Err(http(400, "invalid_request", "code_verifier is malformed."));
    }

    let tx = app.begin().await?;
    let work = async {
        let q = tx.q();
        lock_client(q, service, client).await?;
        // Marked used before anything else is checked, in one statement, so a
        // code is redeemed at most once however many requests race.
        let presented = if utf16_len(code) <= 256 { code } else { "" };
        let row = q
            .first(
                "UPDATE auth_codes SET used_at = now()
                 WHERE code_hash = $1 AND used_at IS NULL
                 RETURNING client_id, session_id, redirect_uri, code_challenge, nonce, expires_at > now() AS live",
                &[&sha256(presented.as_bytes())],
            )
            .await?;
        let Some(row) = row.filter(|r| r.try_get::<_, bool>("live").unwrap_or(false)) else { return Ok(None) };
        let issued_uri: String = row.try_get("redirect_uri")?;
        if row.try_get::<_, String>("client_id")? != client.id || issued_uri != redirect_uri {
            return Ok(None);
        }
        // A URI removed since the code was issued redeems nothing (§6.2).
        if !client.redirect_uris.contains(&issued_uri) {
            return Ok(None);
        }
        if !safe_equal(&b64url(&sha256(verifier.as_bytes())), &row.try_get::<_, String>("code_challenge")?) {
            return Ok(None);
        }
        let session = q
            .first(
                "SELECT s.id, s.user_id, s.amr, extract(epoch FROM s.auth_time)::bigint AS auth_time
                 FROM sessions s JOIN users u ON u.id = s.user_id
                 WHERE s.id = $1 AND s.expires_at > now() AND s.ends_at > now() AND u.disabled_at IS NULL",
                &[&row.try_get::<_, String>("session_id")?],
            )
            .await?;
        let Some(s) = session else { return Ok(None) };
        let (session_id, user_id, amr): (String, String, Vec<String>) = (s.try_get("id")?, s.try_get("user_id")?, s.try_get("amr")?);
        let Some(role) = role_of(q, &user_id, &service.name).await?.filter(|role| !mfa_missing(service, role, &amr)) else { return Ok(None) };
        let Some(user) = holder(q, &user_id).await? else { return Ok(None) };
        let refresh = format!("rt_{}", random_token());
        // A confidential client's token lives and dies with the SSO session; a
        // public client's family outlives it, and its id is the tokens' sid.
        let sid = if client.public { new_id("ses") } else { session_id.clone() };
        if client.public {
            q.execute(
                "INSERT INTO refresh_tokens (token_hash, family_id, session_id, user_id, client_id, expires_at, amr)
                 VALUES ($1, $2, NULL, $3, $4, now() + make_interval(days => $5), $6)",
                &[&sha256(refresh.as_bytes()), &sid, &user_id, &client.id, &PUBLIC_REFRESH_DAYS, &amr],
            )
            .await?;
        } else {
            q.execute(
                "INSERT INTO refresh_tokens (token_hash, family_id, session_id, user_id, client_id, expires_at, amr)
                 SELECT $1, id, id, user_id, $2, ends_at, amr FROM sessions WHERE id = $3",
                &[&sha256(refresh.as_bytes()), &client.id, &session_id],
            )
            .await?;
        }
        touch(q, &session_id).await?;
        Ok(Some(CodeResult { user, role, sid, refresh, amr, auth_time: s.try_get("auth_time")?, nonce: row.try_get("nonce")? }))
    }
    .await;
    let Some(result) = tx.finish(work).await? else {
        return Err(http(400, "invalid_grant", "The authorization code is invalid, expired or used."));
    };

    let now = now_secs();
    let signer = app.keys.signer(&app.crypt, app.db()).await?;
    let mut claims = json!({
        "iss": app.config.issuer,
        "sub": result.user.user_id,
        "aud": client.id,
        "iat": now,
        "exp": now + ACCESS_TOKEN_SECONDS,
        "sid": result.sid,
        "username": result.user.username,
        "name": result.user.name,
        "role": result.role,
    });
    if let Some(nonce) = result.nonce.as_deref().filter(|n| !n.is_empty()) {
        claims["nonce"] = json!(nonce);
    }
    claims["auth_time"] = json!(result.auth_time);
    claims["amr"] = json!(result.amr);
    claims["email"] = json!(result.user.email);
    claims["email_verified"] = json!(result.user.email_verified);
    let id_token = sign_jwt("JWT", &claims, &signer);
    Ok(json_response(
        200,
        &json!({
            "access_token": access_token(app, &result.user, &service.name, &result.sid, &result.role, now).await?,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_SECONDS,
            "refresh_token": result.refresh,
            "id_token": id_token,
        }),
    ))
}

enum Refreshed {
    Reused,
    Tokens { user: Holder, role: String, sid: String, next: Option<String> },
}

async fn refresh_grant(app: &App, client: &Client, service: &Service, form: &Params) -> Result<Response> {
    let Some(presented) = form.single("refresh_token")?.filter(|v| !v.is_empty()) else {
        return Err(http(400, "invalid_request", "refresh_token is required."));
    };
    let hash = sha256(if utf16_len(presented) <= 256 { presented.as_bytes() } else { b"" });

    let tx = app.begin().await?;
    let work = async {
        let q = tx.q();
        lock_client(q, service, client).await?;
        let Some(found) = q.first("SELECT family_id FROM refresh_tokens WHERE token_hash = $1", &[&hash]).await? else { return Ok(None) };
        lock_family(q, &found.try_get::<_, String>("family_id")?).await?;
        let rt = q
            .first(
                "SELECT r.family_id, r.session_id, r.user_id, r.client_id, r.revoked_at IS NOT NULL AS revoked,
                        r.expires_at > now() AS live, r.rotated_at IS NOT NULL AS rotated,
                        r.rotated_at > now() - make_interval(secs => $2) AS in_grace,
                        r.amr, s.amr AS session_amr, (s.expires_at > now() AND s.ends_at > now()) AS session_live
                 FROM refresh_tokens r LEFT JOIN sessions s ON s.id = r.session_id
                 WHERE r.token_hash = $1
                 FOR UPDATE OF r",
                &[&hash, &REUSE_GRACE_SECONDS],
            )
            .await?;
        let Some(rt) = rt else { return Ok(None) };
        if rt.try_get::<_, String>("client_id")? != client.id || rt.try_get::<_, bool>("revoked")? || !rt.try_get::<_, bool>("live")? {
            return Ok(None);
        }
        let (family_id, user_id): (String, String) = (rt.try_get("family_id")?, rt.try_get("user_id")?);
        let session_id: Option<String> = rt.try_get("session_id")?;
        let amr: Vec<String> = if !client.public {
            if session_id.is_none() || !rt.try_get::<_, Option<bool>>("session_live")?.unwrap_or(false) {
                return Ok(None);
            }
            rt.try_get::<_, Option<Vec<String>>>("session_amr")?.unwrap_or_default()
        } else {
            // A token issued to a confidential client under this id is useless
            // without that client's secret, whatever the id's type is now (§6.2).
            if session_id.is_some() {
                return Ok(None);
            }
            // Rotation (OAuth 2.1 §4.3.1): a token used again past the grace
            // period means two parties hold it, so the whole family ends.
            if rt.try_get::<_, bool>("rotated")? && !rt.try_get::<_, Option<bool>>("in_grace")?.unwrap_or(false) {
                q.execute("UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL", &[&family_id]).await?;
                emit_session_ended(q, app, &family_id).await?;
                audit(q, Audit::new(None, "refresh.reuse").user(Some(&user_id)).detail(json!({ "client": client.id }))).await?;
                let (alerting, text) = (app.clone(), format!("auth: a reused refresh token ended a session family of {user_id} ({})", client.id));
                tx.after(move || alerting.alert(text));
                return Ok(Some(Refreshed::Reused));
            }
            rt.try_get("amr")?
        };
        let Some(role) = role_of(q, &user_id, &service.name).await?.filter(|role| !mfa_missing(service, role, &amr)) else { return Ok(None) };
        let Some(user) = holder(q, &user_id).await? else { return Ok(None) };
        let mut next = None;
        if client.public {
            let token = format!("rt_{}", random_token());
            q.execute("UPDATE refresh_tokens SET rotated_at = COALESCE(rotated_at, now()) WHERE token_hash = $1", &[&hash]).await?;
            q.execute(
                "INSERT INTO refresh_tokens (token_hash, family_id, session_id, user_id, client_id, expires_at, amr)
                 VALUES ($1, $2, NULL, $3, $4, now() + make_interval(days => $5), $6)",
                &[&sha256(token.as_bytes()), &family_id, &user_id, &client.id, &PUBLIC_REFRESH_DAYS, &amr],
            )
            .await?;
            next = Some(token);
        } else if let Some(session_id) = &session_id {
            touch(q, session_id).await?;
        }
        Ok(Some(Refreshed::Tokens { user, role, sid: family_id, next }))
    }
    .await;
    let Some(Refreshed::Tokens { user, role, sid, next }) = tx.finish(work).await? else {
        return Err(http(400, "invalid_grant", "The refresh token is invalid, expired or revoked."));
    };
    let now = now_secs();
    let mut body = json!({
        "access_token": access_token(app, &user, &service.name, &sid, &role, now).await?,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_SECONDS,
    });
    if let Some(next) = next {
        body["refresh_token"] = json!(next);
    }
    Ok(json_response(200, &body))
}

// ------------------------------------------------------------------- revoke

/// RFC 7009: refresh tokens only, and only the caller's own. The answer is 200
/// whether or not the token was known. A public client's revocation ends its
/// whole family, since it is signing out.
pub async fn revoke(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let form = read_form(&ctx.req)?;
    let client = authenticate_client(app, &ctx.req, Some(&form), true).await?;
    let Some(presented) = form.single("token")?.filter(|v| !v.is_empty()) else {
        return Err(http(400, "invalid_request", "token is required."));
    };
    let hash = sha256(if utf16_len(presented) <= 256 { presented.as_bytes() } else { b"" });
    let tx = app.begin().await?;
    let work = async {
        let q = tx.q();
        let Some(found) = q.first("SELECT family_id, user_id FROM refresh_tokens WHERE token_hash = $1 AND client_id = $2 AND revoked_at IS NULL", &[&hash, &client.id]).await? else {
            return Ok(());
        };
        let (family_id, user_id): (String, String) = (found.try_get("family_id")?, found.try_get("user_id")?);
        if client.public {
            // The app is signing a device out: its service hears of it like any
            // other ended session.
            end_family(q, app, &family_id, &user_id).await?;
        } else {
            lock_family(q, &family_id).await?;
            q.execute("UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL", &[&hash]).await?;
        }
        audit(q, Audit::new(Some(&client_actor(&client.service)), "token.revoke").user(Some(&user_id)).detail(json!({ "client": client.id }))).await
    }
    .await;
    tx.finish(work).await?;
    Ok(json_response(200, &json!({})))
}

// --------------------------------------------------------------- introspect

// Failures counted per client, and per end-user address the client names,
// so a protocol server's brute-force limits hold (§9.4).
const INTROSPECT_PER_MINUTE: i32 = 600;
const FAILURES_PER_ADDRESS: i32 = 10;
const FAILURES_PER_ADDRESS_WINDOW: i64 = 15 * 60;
const FAILURES_PER_CLIENT: i32 = 1000;
const FAILURES_PER_CLIENT_WINDOW: i64 = 60 * 60;

pub async fn introspect(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let form = read_form(&ctx.req)?;
    let client = authenticate_client(app, &ctx.req, Some(&form), false).await?;
    let limit = hit(app.db(), &format!("client:{}:introspect", client.id), INTROSPECT_PER_MINUTE, 60).await?;
    if !limit.allowed {
        return Err(Error::Http(HttpError::with(429, "rate_limited", "Too many introspection requests.", retry_after(limit.retry_after))));
    }
    let Some(secret) = form.single("token")?.filter(|v| !v.is_empty()) else {
        return Err(http(400, "invalid_request", "token is required."));
    };

    // Only for this counter: the client vouches for its own end user's address.
    // Through the proxy, the proxy has replaced it with the client's own
    // address (it is then the request's address too), and keying on it would
    // put all the client's users in one bucket; the per-client counter still
    // applies.
    let address = ctx.req.header("X-Real-IP").and_then(|named| parse_ip(&named)).map(|bytes| format_ip(&bytes));
    let address_key = address.filter(|a| Some(a.as_str()) != ctx.ip()).map(|a| format!("client:{}:introspect-fail:{a}", client.id));
    let client_key = format!("client:{}:introspect-fail", client.id);
    let mut limits = vec![(client_key.as_str(), FAILURES_PER_CLIENT, FAILURES_PER_CLIENT_WINDOW)];
    if let Some(key) = &address_key {
        limits.push((key.as_str(), FAILURES_PER_ADDRESS, FAILURES_PER_ADDRESS_WINDOW));
    }
    for (key, max, window) in &limits {
        let v = peek(app.db(), key, *max, *window).await?;
        if !v.allowed {
            return Err(Error::Http(HttpError::with(429, "rate_limited", "Too many failed checks.", retry_after(v.retry_after))));
        }
    }

    let Some(found) = introspect_secret(app.db(), &client.service, secret).await? else {
        for (key, max, window) in &limits {
            hit(app.db(), key, *max, *window).await?;
        }
        return Ok(json_response(200, &json!({ "active": false })));
    };
    Ok(json_response(200, &json!({ "active": true, "sub": found.user_id, "username": found.username, "scope": found.scopes.join(" "), "role": found.role, "jti": found.id })))
}

// ----------------------------------------------------------------- userinfo

pub async fn userinfo(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let unauthorized =
        || Ok(error_response(401, "invalid_token", "The access token is missing, invalid or expired.", &[("WWW-Authenticate".to_string(), "Bearer error=\"invalid_token\"".to_string())]));
    let header = ctx.req.header("Authorization").unwrap_or_default();
    // `^Bearer ([A-Za-z0-9._-]+)$`
    let Some(token) = js_trim(&header).strip_prefix("Bearer ").filter(|t| !t.is_empty() && t.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))) else {
        return unauthorized();
    };
    app.keys.refresh(false, app.db()).await?;
    let opts = VerifyOptions { typ: "at+jwt", issuer: &app.config.issuer, audience: Some(app.services.all().iter().map(|s| s.name.clone()).collect()), now_seconds: now_secs(), leeway_seconds: 30 };
    let Some(claims) = verify_jwt(token, |kid| app.keys.public_key(kid), &opts) else { return unauthorized() };
    let Some(sub) = claims.get("sub").and_then(Value::as_str) else { return unauthorized() };
    let Some(user) = holder(app.db(), sub).await? else { return unauthorized() };
    Ok(json_response(
        200,
        &json!({
            "sub": user.user_id,
            "username": user.username,
            "preferred_username": user.username,
            "name": user.name,
            "email": user.email,
            "email_verified": user.email_verified,
        }),
    ))
}

// ------------------------------------------------------------------- logout

/// RP-initiated logout (§7.1): ends the SSO session, tells every app that
/// holds tokens under it, and returns to a registered address.
pub async fn logout(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let q = ctx.req.query();
    let (Ok(client_id), Ok(target), Ok(state)) = (q.single("client_id"), q.single("post_logout_redirect_uri"), q.single("state")) else {
        return Ok(message_page(app, 400, "Sign-out failed", "A parameter is repeated.", None, Extras::default()));
    };
    if let Some(target) = target {
        let registered = client_id.filter(|c| !c.is_empty()).and_then(|c| app.services.client(c)).is_some_and(|c| c.post_logout_redirect_uris.iter().any(|u| u == target));
        if !registered {
            return Ok(message_page(app, 400, "Sign-out failed", "The app sent you here with a return address it hasn't registered.", None, Extras::default()));
        }
    }
    if let Some(session) = load_session(app, &ctx.req).await? {
        let tx = app.begin().await?;
        let work = async {
            end_session(tx.q(), app, &session.id).await?;
            audit(tx.q(), Audit::new(Some(&session.user_id), "logout").user(Some(&session.user_id)).ip(ctx.ip()).detail(json!({ "client": client_id }))).await
        }
        .await;
        tx.finish(work).await?;
    }
    let extras = Extras::cookies(vec![clear_session_cookie()]);
    if let Some(target) = target {
        let location = match state.filter(|s| utf16_len(s) <= 1024) {
            Some(state) => with_params(target, &[("state", state)]),
            None => Url::parse(target).map(|u| u.to_string()).unwrap_or_else(|_| target.to_string()),
        };
        return Ok(redirect(&location, extras, 302));
    }
    Ok(message_page(app, 200, "Signed out", "You are signed out.", Some(("/login", "Sign in again")), extras))
}
