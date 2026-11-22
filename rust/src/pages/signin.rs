//! Signing in (docs/DESIGN.md §7.1, §9.1, §9.4): a password, then TOTP or a
//! recovery code when the account has TOTP; or a passkey, which is two
//! factors by itself.

use serde_json::{json, Value};

use crate::app::App;
use crate::audit::{audit, Audit};
use crate::crypto::{is_token, random_token, sha256};
use crate::emails::security_notice;
use crate::error::{Error, HttpError, Result};
use crate::factors::{check_second_factor, factors_of};
use crate::http::{clear_cookie, host_cookie, json_with, read_form, read_json, retry_after, see_other, set_cookie, Extras, Request, Response};
use crate::pages::layout::{check_form, extras_with, flash, form_token, h, hidden_csrf, icon, local_path, message_page, page, PageOptions};
use crate::passkeys::{authentication_options, finish_authentication};
use crate::server::Ctx;
use crate::sessions::{load_session, require_origin, session_cookie, sign_in_session};
use crate::throttle::{clear, failure_wait, hit, record_failure};
use crate::users::{find_user, find_user_by_login};
use crate::util::{b64url, form_encode, js_trim, utf16_prefix};

const PENDING: &str = "pending";
const PENDING_SECONDS: i64 = 5 * 60;
pub const WEBAUTHN: &str = "webauthn";
const DEVICE: &str = "device";

const IP_LIMIT: i32 = 30;
const IP_WINDOW: i64 = 15 * 60;
const SECOND_FACTOR_ATTEMPTS: i32 = 5;

pub fn account_key(user_id: &str) -> String {
    format!("login:user:{user_id}")
}

pub fn ip_key(ip: Option<&str>) -> String {
    format!("ip:{}:login", ip.unwrap_or("unknown"))
}

fn minutes(seconds: i64) -> String {
    let m = (seconds + 59) / 60;
    if m <= 1 {
        "a minute".to_string()
    } else {
        format!("{m} minutes")
    }
}

// The sign-in form again, still leading where the sign-in was going.
fn login_again(return_to: &str) -> String {
    format!("/login?{}", form_encode(&[("return_to", return_to)]))
}

struct LoginForm<'a> {
    return_to: &'a str,
    login: &'a str,
    error: Option<&'a str>,
    notice: Option<&'a str>,
    status: u16,
}

fn login_form(app: &App, req: &Request, f: LoginForm) -> Response {
    let (token, cookie) = form_token(req);
    let signup =
        if app.services.any_open() { format!(r#"<p class="callout">New here? <a href="/signup?{}">Create an account</a></p>"#, form_encode(&[("return_to", f.return_to)])) } else { String::new() };
    let body = format!(
        r#"
<h1>Sign in</h1>
{notice}
{error}
<form method="post" action="/login" class="card">
  {csrf}
  <input type="hidden" name="return_to" value="{return_to}">
  <label>Username or email <input name="login" autocomplete="username webauthn" required maxlength="254" value="{login}"></label>
  <div class="field">
    <div class="field-head"><label for="login-password">Password</label><a href="/reset">Forgot password?</a></div>
    <input id="login-password" name="password" type="password" autocomplete="current-password" required maxlength="1024">
  </div>
  <button type="submit" class="block">Sign in</button>
</form>
<div class="passkey" hidden>
  <p class="divider">or</p>
  <button type="button" class="secondary block" id="passkey-signin" data-return-to="{return_to}">{passkey}Sign in with a passkey</button>
  <p class="error" id="passkey-error" role="alert" hidden></p>
</div>
{signup}"#,
        notice = f.notice.map(|n| flash("notice", n)).unwrap_or_default(),
        error = f.error.map(|e| flash("error", e)).unwrap_or_default(),
        csrf = hidden_csrf(&token),
        return_to = h(f.return_to),
        login = h(f.login),
        passkey = icon("passkey", 16),
    );
    page(app, "Sign in", &body, PageOptions { status: Some(f.status), scripts: vec!["signin.js"], extras: extras_with(cookie, Vec::new()), ..Default::default() })
}

pub async fn get_login(ctx: Ctx) -> Result<Response> {
    let q = ctx.req.query();
    let return_to = local_path(q.get("return_to"));
    let notice = match (q.get("second_factor").filter(|s| !s.is_empty()), q.get("reauth").filter(|s| !s.is_empty()), q.get("notice")) {
        (Some(service), _, _) => Some(format!("Your role on {} needs a second factor: sign in with your password and authenticator code, or with a passkey.", utf16_prefix(service, 64))),
        (None, Some(_), _) => Some("Sign in again to continue.".to_string()),
        (None, None, Some("activated")) => Some("Your password is set. Sign in.".to_string()),
        (None, None, Some("reset")) => Some("Your password is changed. Sign in.".to_string()),
        _ => None,
    };
    let login = q.get("login_hint").map(|l| utf16_prefix(l, 254)).unwrap_or("");
    Ok(login_form(&ctx.app, &ctx.req, LoginForm { return_to: &return_to, login, error: None, notice: notice.as_deref(), status: 200 }))
}

pub async fn post_login(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let form = read_form(&ctx.req)?;
    check_form(app, &ctx.req, &form)?;
    let return_to = local_path(form.get("return_to"));
    let login = utf16_prefix(js_trim(form.get("login").unwrap_or("")), 254).to_string();
    let password = form.get("password").unwrap_or("");
    let again = |error: &str, status: u16, headers: Vec<(String, String)>| {
        let mut res = login_form(app, &ctx.req, LoginForm { return_to: &return_to, login: &login, error: Some(error), notice: None, status });
        for (k, v) in headers {
            res.set_header(&k, &v);
        }
        res
    };

    let per_ip = hit(app.db(), &ip_key(ctx.ip()), IP_LIMIT, IP_WINDOW).await?;
    if !per_ip.allowed {
        return Ok(again(&format!("Too many sign-in attempts from your network. Try again in {}.", minutes(per_ip.retry_after)), 429, retry_after(per_ip.retry_after)));
    }

    // Unknown accounts are counted and delayed like known ones, so the
    // answers can't tell them apart.
    let user = find_user_by_login(app.db(), &login).await?;
    let key = match &user {
        Some(u) => account_key(&u.id),
        None => format!("login:name:{}", login.to_lowercase()),
    };
    let wait = failure_wait(app.db(), &key).await?;
    if !wait.allowed {
        return Ok(again(&format!("Too many failed attempts. Try again in {}.", minutes(wait.retry_after)), 429, retry_after(wait.retry_after)));
    }

    let usable = user.as_ref().filter(|u| u.is_person()).and_then(|u| u.password_hash.as_deref());
    let check = app.hasher.verify(utf16_prefix(password, 1024), usable).await;
    let failed = user.as_ref().map(|u| u.id.clone());
    let Some(user) = user.filter(|_| check.ok) else {
        record_failure(app.db(), &key).await?;
        audit(app.db(), Audit::new(None, "login.fail").user(failed.as_deref()).ip(ctx.ip()).detail(json!({ "method": "password" }))).await?;
        return Ok(again("Wrong username or password.", 401, Vec::new()));
    };
    if user.disabled_at.is_some() {
        audit(app.db(), Audit::new(None, "login.fail").user(Some(&user.id)).ip(ctx.ip()).detail(json!({ "method": "password", "reason": "disabled" }))).await?;
        return Ok(again("This account is disabled.", 403, Vec::new()));
    }
    // An imported hash (bcrypt, older argon2 parameters) becomes today's at the
    // first sign-in that proves the password (§13).
    if check.rehash {
        let fresh = app.hasher.hash(password).await;
        app.db().execute("UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1", &[&user.id, &fresh]).await?;
    }

    let factors = factors_of(app.db(), &user.id).await?;
    if factors.totp {
        let pending = json!({ "u": user.id, "id": random_token(), "r": return_to });
        // return_to rides along in the URL and the form too, so that starting
        // over, or a pending sign-in that expired, still leads back to it. A
        // finished sign-in follows only the sealed one.
        let cookie = set_cookie(PENDING, &app.crypt.seal_value(PENDING, &pending, PENDING_SECONDS), Some(PENDING_SECONDS), "Lax");
        return Ok(see_other(&format!("/login/second-factor?{}", form_encode(&[("return_to", &return_to)])), Extras::cookies(vec![cookie])));
    }
    complete_sign_in(app, &ctx.req, ctx.ip(), &user.id, &["pwd"], &return_to, "password").await
}

fn second_factor_form(app: &App, req: &Request, return_to: &str, error: Option<&str>, status: u16) -> Response {
    let (token, cookie) = form_token(req);
    let body = format!(
        r#"
<h1>Second factor</h1>
{error}
<form method="post" action="/login/second-factor" class="card">
  {csrf}
  <input type="hidden" name="return_to" value="{return_to}">
  <label>Authentication code
    <input name="code" autocomplete="one-time-code" inputmode="text" required maxlength="40" autofocus></label>
  <p class="hint">The 6-digit code from your authenticator app, or a recovery code.</p>
  <button type="submit" class="block">Continue</button>
</form>
<p class="links"><a href="{again}">Start over</a></p>"#,
        error = error.map(|e| flash("error", e)).unwrap_or_default(),
        csrf = hidden_csrf(&token),
        return_to = h(return_to),
        again = h(&login_again(return_to)),
    );
    page(app, "Second factor", &body, PageOptions { status: Some(status), extras: extras_with(cookie, Vec::new()), ..Default::default() })
}

// A pending second factor: the user, this sign-in's id, and where it leads.
fn pending_of(app: &App, req: &Request) -> Option<(String, String, String)> {
    let sealed = app.crypt.open_value(PENDING, host_cookie(req, PENDING).as_deref())?;
    let text = |key: &str| sealed.get(key).and_then(Value::as_str).map(str::to_string);
    Some((text("u")?, text("id")?, text("r")?))
}

pub async fn get_second_factor(ctx: Ctx) -> Result<Response> {
    let Some((_, _, return_to)) = pending_of(&ctx.app, &ctx.req) else {
        return Ok(see_other(&login_again(&local_path(ctx.req.query().get("return_to"))), Extras::default()));
    };
    Ok(second_factor_form(&ctx.app, &ctx.req, &return_to, None, 200))
}

pub async fn post_second_factor(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let form = read_form(&ctx.req)?;
    check_form(app, &ctx.req, &form)?;
    let Some((user_id, id, return_to)) = pending_of(app, &ctx.req) else {
        return Ok(see_other(&login_again(&local_path(form.get("return_to"))), Extras::default()));
    };
    // Five attempts per password sign-in, then it starts over (§9.4). Each
    // failure also counts against the account, so starting over again and
    // again doesn't buy more guesses.
    let attempts = hit(app.db(), &format!("mfa:{id}"), SECOND_FACTOR_ATTEMPTS, PENDING_SECONDS).await?;
    let wait = failure_wait(app.db(), &account_key(&user_id)).await?;
    if !attempts.allowed || !wait.allowed {
        let mut res = message_page(app, 429, "Too many attempts", "Too many wrong codes. Sign in again later.", Some((&login_again(&return_to), "Sign in")), Extras::default());
        res.append_header("Set-Cookie", &clear_cookie(PENDING));
        return Ok(res);
    }
    let code = utf16_prefix(form.get("code").unwrap_or(""), 40);
    let Some(kind) = check_second_factor(app.db(), app, &user_id, code).await? else {
        record_failure(app.db(), &account_key(&user_id)).await?;
        audit(app.db(), Audit::new(None, "login.mfa_fail").user(Some(&user_id)).ip(ctx.ip())).await?;
        return Ok(second_factor_form(app, &ctx.req, &return_to, Some("That code didn't work."), 401));
    };
    let method = if kind == "recovery" { "recovery_code" } else { "totp" };
    complete_sign_in(app, &ctx.req, ctx.ip(), &user_id, &["pwd", "otp", "mfa"], &return_to, method).await
}

pub async fn passkey_options(ctx: Ctx) -> Result<Response> {
    require_origin(&ctx.app, &ctx.req)?;
    let (options, state) = authentication_options(&ctx.app);
    Ok(json_with(200, &json!({ "options": options }), &[], vec![set_cookie(WEBAUTHN, &state, Some(300), "Lax")]))
}

pub async fn passkey_sign_in(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    require_origin(app, &ctx.req)?;
    let body = read_json(&ctx.req)?;
    let per_ip = hit(app.db(), &ip_key(ctx.ip()), IP_LIMIT, IP_WINDOW).await?;
    if !per_ip.allowed {
        return Err(Error::Http(HttpError::with(429, "rate_limited", "Too many sign-in attempts from your network.", retry_after(per_ip.retry_after))));
    }
    let Some(user_id) = finish_authentication(app, host_cookie(&ctx.req, WEBAUTHN).as_deref(), body.get("response")).await? else {
        audit(app.db(), Audit::new(None, "login.fail").ip(ctx.ip()).detail(json!({ "method": "passkey" }))).await?;
        return Err(Error::Http(HttpError::new(401, "unauthorized", "That passkey sign-in didn't work.")));
    };
    let return_to = local_path(body.get("return_to").and_then(Value::as_str));
    let res = complete_sign_in(app, &ctx.req, ctx.ip(), &user_id, &["swk", "user", "mfa"], &return_to, "passkey").await?;
    // The page's script follows the redirect itself.
    let location = res.header("Location").unwrap_or("/account").to_string();
    let mut cookies = res.set_cookies();
    cookies.push(clear_cookie(WEBAUTHN));
    Ok(json_with(200, &json!({ "redirect": location }), &[], cookies))
}

/// The end of every sign-in: the session, the audit row, a notice when the
/// device is new, and the failure counter cleared.
pub async fn complete_sign_in(app: &App, req: &Request, ip: Option<&str>, user_id: &str, amr: &[&str], return_to: &str, method: &str) -> Result<Response> {
    let Some(user) = find_user(app.db(), user_id).await?.filter(|u| u.disabled_at.is_none() && u.is_person()) else {
        return Ok(message_page(app, 403, "Can't sign in", "This account is disabled.", Some(("/login", "Back")), Extras::default()));
    };
    let previous = load_session(app, req).await?;
    let device = host_cookie(req, DEVICE).filter(|d| is_token(d)).unwrap_or_else(random_token);
    let device_id: String = b64url(&sha256(device.as_bytes())).chars().take(22).collect();
    let user_agent = req.header("User-Agent");
    let amr: Vec<String> = amr.iter().map(|m| m.to_string()).collect();
    let tx = app.begin().await?;
    let work = async {
        let q = tx.q();
        let history = q
            .one(
                "SELECT count(*)::int AS logins,
                        (count(*) FILTER (WHERE detail->>'device' = $2))::int AS on_device
                 FROM audit WHERE user_id = $1 AND action = 'login.ok'",
                &[&user_id, &device_id],
            )
            .await?;
        let previous = previous.as_ref().map(|p| (p.id.as_str(), p.user_id.as_str()));
        let (_, token) = sign_in_session(q, app, user_id, &amr, previous, ip, user_agent.as_deref()).await?;
        audit(q, Audit::new(Some(user_id), "login.ok").user(Some(user_id)).ip(ip).detail(json!({ "method": method, "amr": amr, "device": device_id }))).await?;
        let email = user.email.as_deref().filter(|e| !e.is_empty());
        if method == "recovery_code" {
            audit(q, Audit::new(Some(user_id), "recovery.used").user(Some(user_id)).ip(ip)).await?;
            if let Some(email) = email {
                let (mailing, message) = (app.clone(), security_notice(email, &user.username, "a recovery code was used", None));
                tx.after(move || mailing.mail(message));
            }
        }
        if history.try_get::<_, i32>("logins")? > 0 && history.try_get::<_, i32>("on_device")? == 0 {
            if let Some(email) = email {
                let browser = utf16_prefix(user_agent.as_deref().unwrap_or("unknown"), 200);
                let detail = match ip {
                    Some(ip) => format!("Browser: {browser}\nAddress: {ip}"),
                    None => format!("Browser: {browser}"),
                };
                let (mailing, message) = (app.clone(), security_notice(email, &user.username, "a sign-in from a new device", Some(&detail)));
                tx.after(move || mailing.mail(message));
            }
        }
        Ok(token)
    }
    .await;
    let token = tx.finish(work).await?;
    clear(app.db(), &account_key(user_id)).await?;
    let cookies = vec![session_cookie(&token), clear_cookie(PENDING), set_cookie(DEVICE, &device, Some(400 * 24 * 60 * 60), "Lax")];
    Ok(see_other(return_to, Extras::cookies(cookies)))
}

/// A page handler's refusal is a page: the status, what went wrong, and a way
/// back to the sign-in.
pub async fn page_errors(app: App, outcome: Result<Response>) -> Result<Response> {
    match outcome {
        Err(Error::Http(e)) => {
            let mut res = message_page(&app, e.status, "Something went wrong", &e.description, Some(("/login", "Sign in")), Extras::default());
            for (k, v) in &e.headers {
                res.set_header(k, v);
            }
            Ok(res)
        }
        other => other,
    }
}
