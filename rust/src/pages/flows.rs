//! The pages around an account's life: sign-up, invitations, activation,
//! password reset and email verification (docs/DESIGN.md U5–U7, A1).

use serde_json::{json, Value};

use crate::app::App;
use crate::audit::{audit, Audit};
use crate::emails::{address_in_use_email, reset_email, security_notice, verify_email};
use crate::error::{Error, Result};
use crate::factors::{check_second_factor, factors_of, recovery_code_valid, use_recovery_code};
use crate::http::{host_cookie, read_form, retry_after, see_other, Extras, Params, Request, Response};
use crate::invites::{accept_invite, find_live_invite};
use crate::mail::is_email_address;
use crate::pages::layout::{check_form, extras_with, flash, form_token, h, hidden_csrf, local_path, message_page, page, PageOptions};
use crate::pages::signin::{account_key, complete_sign_in, ip_key, WEBAUTHN};
use crate::passkeys::finish_authentication;
use crate::passwords::{password_problem, BREACHED_MESSAGE};
use crate::server::Ctx;
use crate::sessions::{end_user_sessions, load_session};
use crate::throttle::{clear, failure_wait, hit, record_failure};
use crate::tokens::{consume_token, email_allowed, issue_token, peek_token, Purpose};
use crate::users::{find_user, find_user_by_login, insert_user, is_username, NewUser, UserRow};
use crate::util::{char_count, form_encode, has_control, js_trim, utf16_prefix};

const SIGNUPS_PER_IP: i32 = 10;

async fn new_password_problem(app: &App, password: &str, username: Option<&str>, email: Option<&str>) -> Option<String> {
    if let Some(problem) = password_problem(password, username, email) {
        return Some(problem);
    }
    app.breached(password).await.then(|| BREACHED_MESSAGE.to_string())
}

fn field(label: &str, name: &str, attrs: &str, value: &str) -> String {
    format!(r#"<label>{} <input name="{}" {attrs} value="{}"></label>"#, h(label), h(name), h(value))
}

const PASSWORD_ATTRS: &str = r#"type="password" autocomplete="new-password" required minlength="12" maxlength="256""#;
const USERNAME_ATTRS: &str = r#"required pattern="[a-z][a-z0-9\-]{1,30}[a-z0-9]" autocomplete="username" maxlength="32""#;
const USERNAME_HINT: &str = "3–32 characters: a–z, 0–9 and '-'. It can never change.";
const PASSWORD_HINT: &str = "At least 12 characters.";

fn signup_key(ip: Option<&str>) -> String {
    format!("signup:ip:{}", ip.unwrap_or("unknown"))
}

fn token_link(path: &str, token: Option<&str>) -> String {
    format!("{path}?{}", form_encode(&[("token", token.unwrap_or(""))]))
}

// ------------------------------------------------------------------- sign-up

struct Signup<'a> {
    return_to: &'a str,
    username: &'a str,
    name: &'a str,
    email: &'a str,
}

fn signup_form(app: &App, req: &Request, v: &Signup, error: Option<&str>, status: u16) -> Response {
    let (token, cookie) = form_token(req);
    let body = format!(
        r#"
<h1>Create an account</h1>
{error}
<form method="post" action="/signup" class="card">
  {csrf}
  <input type="hidden" name="return_to" value="{return_to}">
  {username}
  <p class="hint">{username_hint}</p>
  {name}
  {email}
  {password}
  <p class="hint">{password_hint}</p>
  <button type="submit" class="block">Create account</button>
</form>
<p class="callout">Already have an account? <a href="/login?{login}">Sign in</a></p>"#,
        error = error.map(|e| flash("error", e)).unwrap_or_default(),
        csrf = hidden_csrf(&token),
        return_to = h(v.return_to),
        username = field("Username", "username", USERNAME_ATTRS, v.username),
        username_hint = h(USERNAME_HINT),
        name = field("Name", "name", r#"autocomplete="name" maxlength="200""#, v.name),
        email = field("Email", "email", r#"type="email" required autocomplete="email" maxlength="254""#, v.email),
        password = field("Password", "password", PASSWORD_ATTRS, ""),
        password_hint = h(PASSWORD_HINT),
        login = form_encode(&[("return_to", v.return_to)]),
    );
    page(app, "Create an account", &body, PageOptions { status: Some(status), extras: extras_with(cookie, Vec::new()), ..Default::default() })
}

fn not_available(app: &App) -> Response {
    message_page(app, 404, "Not available", "Accounts here are created by invitation.", None, Extras::default())
}

pub async fn get_signup(ctx: Ctx) -> Result<Response> {
    if !ctx.app.services.any_open() {
        return Ok(not_available(&ctx.app));
    }
    let return_to = local_path(ctx.req.query().get("return_to"));
    Ok(signup_form(&ctx.app, &ctx.req, &Signup { return_to: &return_to, username: "", name: "", email: "" }, None, 200))
}

pub async fn post_signup(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    if !app.services.any_open() {
        return Ok(not_available(app));
    }
    let form = read_form(&ctx.req)?;
    check_form(app, &ctx.req, &form)?;
    let return_to = local_path(form.get("return_to"));
    let username = js_trim(form.get("username").unwrap_or("")).to_lowercase();
    let name = js_trim(form.get("name").unwrap_or("")).to_string();
    let email = js_trim(form.get("email").unwrap_or("")).to_string();
    let v = Signup { return_to: &return_to, username: &username, name: &name, email: &email };
    let password = form.get("password").unwrap_or("");
    let again = |error: &str, status: u16| Ok(signup_form(app, &ctx.req, &v, Some(error), status));
    if !is_username(&username) {
        return again(&format!("That username can't be used. {USERNAME_HINT}"), 400);
    }
    if char_count(&name) > 200 || has_control(&name) {
        return again("That name is too long.", 400);
    }
    if !is_email_address(&email) {
        return again("That is not an email address.", 400);
    }
    if let Some(problem) = new_password_problem(app, password, Some(&username), Some(&email)).await {
        return again(&problem, 400);
    }

    if !hit(app.db(), &signup_key(ctx.ip()), SIGNUPS_PER_IP, 3600).await?.allowed {
        return again("Too many accounts were created from your network. Try again later.", 429);
    }
    if !email_allowed(app.db(), &email, &format!("ip:{}", ctx.ip().unwrap_or("unknown"))).await?.allowed {
        return again("Too many emails were sent to that address. Try again later.", 429);
    }

    let hash = app.hasher.hash(password).await;
    let tx = app.begin().await?;
    let work = async {
        let q = tx.q();
        // The address is set only once verified, so a sign-up can't take or
        // reveal an address another account uses (§9.4).
        // A token is made either way, so nothing the new account can read
        // differs; the address's owner gets a notice instead of the link.
        let new = NewUser { username: &username, name: &name, email: None, email_verified: false, kind: "person", owner_id: None, password_hash: Some(&hash) };
        let id = insert_user(q, &new).await?;
        let token = issue_token(q, Purpose::VerifyEmail, &id, Some(&email)).await?;
        let taken = q.first("SELECT 1 FROM users WHERE lower(email) = lower($1)", &[&email]).await?.is_some();
        let message = if taken { address_in_use_email(&email) } else { verify_email(&app.config.issuer, &email, &token) };
        let mailing = app.clone();
        tx.after(move || mailing.mail(message));
        audit(q, Audit::new(Some(&id), "user.signup").user(Some(&id)).ip(ctx.ip())).await?;
        Ok(id)
    }
    .await;
    let user_id = match tx.finish(work).await {
        Ok(id) => id,
        Err(Error::Http(e)) if e.status == 409 => return again(&e.description, 409),
        Err(e) => return Err(e),
    };
    complete_sign_in(app, &ctx.req, ctx.ip(), &user_id, &["pwd"], &return_to, "signup").await
}

// ---------------------------------------------------------------- invitation

fn invitation_not_valid(app: &App) -> Response {
    message_page(app, 404, "Invitation not valid", "This invitation has expired or was already used.", None, Extras::default())
}

pub async fn get_invite(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let query = ctx.req.query();
    let token = query.get("token");
    let Some(invite) = find_live_invite(app.db(), token).await? else { return Ok(invitation_not_valid(app)) };
    let session = load_session(app, &ctx.req).await?;
    let (csrf, cookie) = form_token(&ctx.req);
    let here = token_link("/invite", token);
    let login = form_encode(&[("return_to", &here)]);
    let accept = match &session {
        Some(session) => format!(
            r#"<form method="post" action="/invite" class="card">
  {csrf}
  <input type="hidden" name="token" value="{token}">
  <input type="hidden" name="action" value="accept">
  <p>You're signed in as <strong>{username}</strong>.</p>
  <button type="submit" class="block">Accept as {username}</button>
</form>
<p class="links"><a href="/login?{login}">Sign in as someone else</a></p>"#,
            csrf = hidden_csrf(&csrf),
            token = h(token.unwrap_or("")),
            username = h(&session.username),
        ),
        None => format!(
            r#"<div class="card">
  <p>Already have an account?</p>
  <a class="button block" href="/login?{login}">Sign in to accept</a>
</div>
<h2 class="divider">Or create an account</h2>
<form method="post" action="/invite" class="card">
  {csrf}
  <input type="hidden" name="token" value="{token}">
  <input type="hidden" name="action" value="create">
  <p class="field-static"><span>Email</span> <span>{email}</span></p>
  {username}
  <p class="hint">{username_hint}</p>
  {name}
  {password}
  <p class="hint">{password_hint}</p>
  <button type="submit" class="block">Create account and accept</button>
</form>"#,
            csrf = hidden_csrf(&csrf),
            token = h(token.unwrap_or("")),
            email = h(&invite.email),
            username = field("Username", "username", USERNAME_ATTRS, ""),
            username_hint = h(USERNAME_HINT),
            name = field("Name", "name", r#"autocomplete="name" maxlength="200""#, ""),
            password = field("Password", "password", PASSWORD_ATTRS, ""),
            password_hint = h(PASSWORD_HINT),
        ),
    };
    let body = format!("<h1>You're invited to {}</h1>\n{accept}", h(&invite.service));
    Ok(page(app, "Invitation", &body, PageOptions { extras: extras_with(cookie, Vec::new()), ..Default::default() }))
}

pub async fn post_invite(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let form = read_form(&ctx.req)?;
    check_form(app, &ctx.req, &form)?;
    let token = form.get("token");
    let Some(invite) = find_live_invite(app.db(), token).await? else { return Ok(invitation_not_valid(app)) };
    let here = token_link("/invite", token);

    if form.get("action") == Some("accept") {
        let Some(session) = load_session(app, &ctx.req).await? else {
            return Ok(see_other(&format!("/login?{}", form_encode(&[("return_to", &here)])), Extras::default()));
        };
        let tx = app.begin().await?;
        let work = accept_invite(&tx, app, token, &session.user_id, ctx.ip()).await;
        tx.finish(work).await?;
        let message = format!("You can now use {}.", invite.service);
        return Ok(message_page(app, 200, "Invitation accepted", &message, Some(("/account", "Your account")), Extras::default()));
    }

    let username = js_trim(form.get("username").unwrap_or("")).to_lowercase();
    let name = js_trim(form.get("name").unwrap_or("")).to_string();
    let password = form.get("password").unwrap_or("");
    let fail = |message: &str, status: u16| Ok(message_page(app, status, "Couldn't create the account", message, Some((&here, "Back")), Extras::default()));
    if !is_username(&username) {
        return fail(&format!("That username can't be used. {USERNAME_HINT}"), 400);
    }
    if char_count(&name) > 200 || has_control(&name) {
        return fail("That name is too long.", 400);
    }
    if let Some(problem) = new_password_problem(app, password, Some(&username), Some(&invite.email)).await {
        return fail(&problem, 400);
    }
    if !hit(app.db(), &signup_key(ctx.ip()), SIGNUPS_PER_IP, 3600).await?.allowed {
        return fail("Too many accounts were created from your network. Try again later.", 429);
    }

    let hash = app.hasher.hash(password).await;
    let tx = app.begin().await?;
    let work = async {
        // Holding the emailed link verifies the address.
        let new = NewUser { username: &username, name: &name, email: Some(&invite.email), email_verified: true, kind: "person", owner_id: None, password_hash: Some(&hash) };
        let id = insert_user(tx.q(), &new).await?;
        audit(tx.q(), Audit::new(Some(&id), "user.signup").user(Some(&id)).ip(ctx.ip()).detail(json!({ "invite": invite.id }))).await?;
        accept_invite(&tx, app, token, &id, ctx.ip()).await?;
        Ok(id)
    }
    .await;
    let user_id = match tx.finish(work).await {
        Ok(id) => id,
        Err(Error::Http(e)) if e.status == 409 => {
            let message = if e.description.contains("email") { "An account already uses this address: sign in to it, then open the invitation again." } else { e.description.as_str() };
            return fail(message, 409);
        }
        Err(e) => return Err(e),
    };
    complete_sign_in(app, &ctx.req, ctx.ip(), &user_id, &["pwd"], "/account", "signup").await
}

// ---------------------------------------------------------------- activation

async fn token_user(app: &App, purpose: Purpose, token: Option<&str>) -> Result<Option<UserRow>> {
    match peek_token(app.db(), purpose, token).await? {
        Some(row) => find_user(app.db(), &row.user_id).await,
        None => Ok(None),
    }
}

pub async fn get_activate(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let query = ctx.req.query();
    let token = query.get("token");
    let Some(user) = token_user(app, Purpose::Activate, token).await? else {
        let message = "This activation link has expired or was already used. Ask an administrator for a new one.";
        return Ok(message_page(app, 404, "Link not valid", message, None, Extras::default()));
    };
    let (csrf, cookie) = form_token(&ctx.req);
    let body = format!(
        r#"
<h1>Activate your account</h1>
<form method="post" action="/activate" class="card">
  {csrf}
  <input type="hidden" name="token" value="{token}">
  <input type="hidden" name="username" value="{username}" autocomplete="username">
  <p class="field-static"><span>Username</span> <span>{username}</span></p>
  {password}
  <p class="hint">{password_hint}</p>
  <button type="submit" class="block">Set password</button>
</form>"#,
        csrf = hidden_csrf(&csrf),
        token = h(token.unwrap_or("")),
        username = h(&user.username),
        password = field("Choose a password", "password", PASSWORD_ATTRS, ""),
        password_hint = h(PASSWORD_HINT),
    );
    Ok(page(app, "Activate your account", &body, PageOptions { extras: extras_with(cookie, Vec::new()), ..Default::default() }))
}

pub async fn post_activate(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let form = read_form(&ctx.req)?;
    check_form(app, &ctx.req, &form)?;
    let token = form.get("token");
    let not_valid = || message_page(app, 404, "Link not valid", "This activation link has expired or was already used.", None, Extras::default());
    let Some(user) = token_user(app, Purpose::Activate, token).await? else { return Ok(not_valid()) };
    let password = form.get("password").unwrap_or("");
    if let Some(problem) = new_password_problem(app, password, Some(&user.username), user.email.as_deref()).await {
        return Ok(message_page(app, 400, "Choose another password", &problem, Some((&token_link("/activate", token), "Back")), Extras::default()));
    }
    let hash = app.hasher.hash(password).await;
    let tx = app.begin().await?;
    let work = async {
        let q = tx.q();
        let Some(used) = consume_token(q, Purpose::Activate, token).await? else { return Ok(false) };
        // Only for the address it was sent to, and only before the account has a
        // password: after that, a reset (with its second factor) is the way in.
        let set = q
            .query(
                "UPDATE users SET password_hash = $2, email_verified_at = now(), updated_at = now()
                 WHERE id = $1 AND password_hash IS NULL AND email IS NOT NULL AND lower(email) = lower($3)
                 RETURNING 1",
                &[&used.user_id, &hash, &used.email.as_deref().unwrap_or("")],
            )
            .await?;
        if set.is_empty() {
            return Ok(false);
        }
        audit(q, Audit::new(Some(&used.user_id), "user.activate").user(Some(&used.user_id)).ip(ctx.ip())).await?;
        Ok(true)
    }
    .await;
    if !tx.finish(work).await? {
        return Ok(not_valid());
    }
    Ok(see_other(&format!("/login?{}", form_encode(&[("login_hint", &user.username), ("notice", "activated")])), Extras::default()))
}

// --------------------------------------------------------------------- reset

fn reset_request_page(app: &App, req: &Request, message: Option<&str>, status: u16) -> Response {
    let (token, cookie) = form_token(req);
    let body = format!(
        r#"
<h1>Reset your password</h1>
{message}
<form method="post" action="/reset" class="card">
  {csrf}
  <input type="hidden" name="action" value="email">
  {login}
  <p class="hint">We'll email a link to the account's address.</p>
  <button type="submit" class="block">Email me a link</button>
</form>
<h2 class="divider">Can't reach your email?</h2>
<form method="post" action="/reset" class="card">
  {csrf}
  <input type="hidden" name="action" value="recovery">
  <p class="hint">Use one of your recovery codes instead.</p>
  {username}
  {code}
  {password}
  <p class="hint">{password_hint}</p>
  <button type="submit" class="secondary block">Reset with a recovery code</button>
</form>"#,
        message = message.map(|m| flash("notice", m)).unwrap_or_default(),
        csrf = hidden_csrf(&token),
        login = field("Username or email", "login", r#"required autocomplete="username" maxlength="254""#, ""),
        username = field("Username", "login", r#"required autocomplete="username" maxlength="254""#, ""),
        code = field("Recovery code", "code", r#"required autocomplete="off" maxlength="40""#, ""),
        password = field("New password", "password", PASSWORD_ATTRS, ""),
        password_hint = h(PASSWORD_HINT),
    );
    page(app, "Reset your password", &body, PageOptions { status: Some(status), extras: extras_with(cookie, Vec::new()), ..Default::default() })
}

pub async fn get_reset(ctx: Ctx) -> Result<Response> {
    Ok(reset_request_page(&ctx.app, &ctx.req, None, 200))
}

/// The same answer, in the same time, whether or not the account exists: the
/// lookup, the token and the email all happen after the response.
pub async fn post_reset(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let form = read_form(&ctx.req)?;
    check_form(app, &ctx.req, &form)?;
    let login = utf16_prefix(js_trim(form.get("login").unwrap_or("")), 254).to_string();
    if form.get("action") == Some("recovery") {
        return reset_with_recovery_code(&ctx, &login, &form).await;
    }

    let sent = "If an account uses that name or address, we've sent it a link. It expires in 30 minutes.";
    if login.is_empty() {
        return Ok(reset_request_page(app, &ctx.req, Some(sent), 200));
    }
    let limit = email_allowed(app.db(), &login, &format!("ip:{}", ctx.ip().unwrap_or("unknown"))).await?;
    if !limit.allowed {
        let mut res = reset_request_page(app, &ctx.req, Some("Too many reset emails were asked for. Try again later."), 429);
        res.set_header("Retry-After", &limit.retry_after.to_string());
        return Ok(res);
    }
    let (sending, ip) = (app.clone(), ctx.ip.clone());
    tokio::spawn(async move {
        if let Err(e) = send_reset_link(&sending, &login, ip.as_deref()).await {
            sending.log(&format!("reset link failed: {}", e.name()));
        }
    });
    Ok(reset_request_page(app, &ctx.req, Some(sent), 200))
}

/// The address mail goes to gets at most three an hour, however it was typed
/// (a username, or the address itself). Past that the mail is quietly not
/// sent: a counter of its own, so no answer depends on whether, or to which
/// address, an account exists.
pub async fn send_reset_link(app: &App, login: &str, ip: Option<&str>) -> Result<()> {
    let Some(user) = find_user_by_login(app.db(), login).await?.filter(|u| u.is_person() && u.disabled_at.is_none()) else { return Ok(()) };
    let Some(email) = user.email.clone().filter(|e| !e.is_empty()) else { return Ok(()) };
    if !hit(app.db(), &format!("mail:sent:{}", email.to_lowercase()), 3, 3600).await?.allowed {
        return Ok(());
    }
    let tx = app.begin().await?;
    let work = async {
        let token = issue_token(tx.q(), Purpose::Reset, &user.id, Some(&email)).await?;
        audit(tx.q(), Audit::new(None, "reset.requested").user(Some(&user.id)).ip(ip)).await?;
        let (mailing, message) = (app.clone(), reset_email(&app.config.issuer, &email, &token));
        tx.after(move || mailing.mail(message));
        Ok(())
    }
    .await;
    tx.finish(work).await
}

fn reset_done(username: &str) -> Response {
    see_other(&format!("/login?{}", form_encode(&[("login_hint", username), ("notice", "reset")])), Extras::default())
}

// U6 without email: a recovery code stands in for the link. It is held to
// the sign-in limits (§9.4), and the next sign-in still needs the second
// factor.
async fn reset_with_recovery_code(ctx: &Ctx, login: &str, form: &Params) -> Result<Response> {
    let app = &ctx.app;
    let fail = |message: &str, status: u16, headers: Vec<(String, String)>| {
        let mut res = reset_request_page(app, &ctx.req, Some(message), status);
        for (k, v) in headers {
            res.set_header(&k, &v);
        }
        Ok(res)
    };
    let per_ip = hit(app.db(), &ip_key(ctx.ip()), 30, 15 * 60).await?;
    if !per_ip.allowed {
        return fail("Too many attempts from your network. Try again later.", 429, retry_after(per_ip.retry_after));
    }
    let user = find_user_by_login(app.db(), login).await?;
    let key = match &user {
        Some(u) => account_key(&u.id),
        None => format!("login:name:{}", login.to_lowercase()),
    };
    let wait = failure_wait(app.db(), &key).await?;
    if !wait.allowed {
        return fail("Too many failed attempts. Try again later.", 429, retry_after(wait.retry_after));
    }
    let password = form.get("password").unwrap_or("");
    let code = utf16_prefix(form.get("code").unwrap_or(""), 40);
    let found = user.as_ref().map(|u| u.id.clone());
    let live = user.filter(|u| u.is_person() && u.disabled_at.is_none());
    // The code is proved before anything about the account is told (the
    // password rules read its email), and spent only once everything passes.
    let proved = recovery_code_valid(app.db(), live.as_ref().map(|u| u.id.as_str()), code).await?;
    let Some(live) = live.filter(|_| proved) else {
        record_failure(app.db(), &key).await?;
        audit(app.db(), Audit::new(None, "reset.fail").user(found.as_deref()).ip(ctx.ip()).detail(json!({ "method": "recovery_code" }))).await?;
        return fail("That username and recovery code don't match.", 401, Vec::new());
    };
    if let Some(problem) = new_password_problem(app, password, Some(&live.username), live.email.as_deref()).await {
        return fail(&problem, 400, Vec::new());
    }
    if !use_recovery_code(app.db(), Some(&live.id), code).await? {
        return fail("That username and recovery code don't match.", 401, Vec::new());
    }
    let hash = app.hasher.hash(password).await;
    finish_reset(app, &live, &hash, ctx.ip(), "recovery_code").await?;
    Ok(reset_done(&live.username))
}

async fn finish_reset(app: &App, user: &UserRow, hash: &str, ip: Option<&str>, method: &str) -> Result<()> {
    let tx = app.begin().await?;
    let work = async {
        let q = tx.q();
        q.execute("UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1", &[&user.id, &hash]).await?;
        // A reset ends every session and refresh token (§9.1).
        end_user_sessions(q, app, &user.id, None).await?;
        audit(q, Audit::new(Some(&user.id), "password.reset").user(Some(&user.id)).ip(ip).detail(json!({ "method": method }))).await?;
        if method == "recovery_code" {
            audit(q, Audit::new(Some(&user.id), "recovery.used").user(Some(&user.id)).ip(ip)).await?;
        }
        if let Some(email) = user.email.as_deref().filter(|e| !e.is_empty()) {
            let mut notices = vec![security_notice(email, &user.username, "password reset", None)];
            if method == "recovery_code" {
                notices.push(security_notice(email, &user.username, "a recovery code was used", None));
            }
            let mailing = app.clone();
            tx.after(move || notices.into_iter().for_each(|n| mailing.mail(n)));
        }
        Ok(())
    }
    .await;
    tx.finish(work).await?;
    clear(app.db(), &account_key(&user.id)).await
}

pub async fn get_reset_confirm(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let query = ctx.req.query();
    let token = query.get("token");
    let Some(user) = token_user(app, Purpose::Reset, token).await? else {
        return Ok(message_page(app, 404, "Link not valid", "This reset link has expired or was already used.", Some(("/reset", "Ask for a new one")), Extras::default()));
    };
    let factors = factors_of(app.db(), &user.id).await?;
    let (csrf, cookie) = form_token(&ctx.req);
    let second = if factors.totp {
        format!(
            "{}\n  <p class=\"hint\">The 6-digit code from your authenticator app, or a recovery code.</p>",
            field("Authentication code", "code", r#"required autocomplete="one-time-code" maxlength="40""#, "")
        )
    } else if factors.passkeys > 0 {
        format!(
            r#"<input type="hidden" name="passkey" id="passkey-response">
  <p class="hint">Confirm with your passkey, or enter a recovery code.</p>
  <button type="button" class="secondary block" id="passkey-confirm">Use my passkey</button>
  <p class="error" id="passkey-error" role="alert" hidden></p>
  {}"#,
            field("Recovery code", "code", r#"autocomplete="off" maxlength="40""#, "")
        )
    } else {
        String::new()
    };
    let body = format!(
        r#"
<h1>Choose a new password</h1>
<form method="post" action="/reset/confirm" id="reset-form" class="card">
  {csrf}
  <input type="hidden" name="token" value="{token}">
  <input type="hidden" name="username" value="{username}" autocomplete="username">
  {password}
  <p class="hint">{password_hint}</p>
  {second}
  <button type="submit" class="block">Change password</button>
</form>"#,
        csrf = hidden_csrf(&csrf),
        token = h(token.unwrap_or("")),
        username = h(&user.username),
        password = field("New password", "password", PASSWORD_ATTRS, ""),
        password_hint = h(PASSWORD_HINT),
    );
    let scripts = if factors.passkeys > 0 && !factors.totp { vec!["signin.js"] } else { Vec::new() };
    Ok(page(app, "Choose a new password", &body, PageOptions { scripts, extras: extras_with(cookie, Vec::new()), ..Default::default() }))
}

/// A reset link also needs the second factor when one is enrolled (§9.1).
pub async fn post_reset_confirm(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let form = read_form(&ctx.req)?;
    check_form(app, &ctx.req, &form)?;
    let token = form.get("token");
    let here = token_link("/reset/confirm", token);
    let back = Some((here.as_str(), "Back"));
    let not_valid = || message_page(app, 404, "Link not valid", "This reset link has expired or was already used.", None, Extras::default());
    let Some(user) = token_user(app, Purpose::Reset, token).await?.filter(|u| u.disabled_at.is_none()) else { return Ok(not_valid()) };

    // Checked before the second factor, so a refused password doesn't spend a
    // code.
    let password = form.get("password").unwrap_or("");
    if let Some(problem) = new_password_problem(app, password, Some(&user.username), user.email.as_deref()).await {
        return Ok(message_page(app, 400, "Choose another password", &problem, back, Extras::default()));
    }
    let factors = factors_of(app.db(), &user.id).await?;
    let mut method = "email";
    if factors.totp || factors.passkeys > 0 {
        // Like every second-factor failure, these count against the account's
        // sign-in limit too (§9.4).
        let attempts = hit(app.db(), &format!("reset:{}:second-factor", user.id), 5, 30 * 60).await?;
        let wait = failure_wait(app.db(), &account_key(&user.id)).await?;
        if !attempts.allowed || !wait.allowed {
            return Ok(message_page(app, 429, "Too many attempts", "Too many wrong codes. Try again later.", back, Extras::default()));
        }
        let code = utf16_prefix(js_trim(form.get("code").unwrap_or("")), 40);
        let ok = if factors.totp {
            let kind = if code.is_empty() { None } else { check_second_factor(app.db(), app, &user.id, code).await? };
            if kind == Some("recovery") {
                method = "recovery_code";
            }
            kind.is_some()
        } else if !code.is_empty() {
            let used = use_recovery_code(app.db(), Some(&user.id), code).await?;
            if used {
                method = "recovery_code";
            }
            used
        } else {
            let response: Value = serde_json::from_str(form.get("passkey").unwrap_or("null")).unwrap_or(Value::Null);
            finish_authentication(app, host_cookie(&ctx.req, WEBAUTHN).as_deref(), Some(&response)).await?.as_deref() == Some(user.id.as_str())
        };
        if !ok {
            record_failure(app.db(), &account_key(&user.id)).await?;
            audit(app.db(), Audit::new(None, "reset.fail").user(Some(&user.id)).ip(ctx.ip()).detail(json!({ "method": "second_factor" }))).await?;
            return Ok(message_page(app, 401, "Second factor didn't work", "That code or passkey didn't work.", back, Extras::default()));
        }
    }
    let hash = app.hasher.hash(password).await;
    let tx = app.begin().await?;
    let used = consume_token(tx.q(), Purpose::Reset, token).await;
    if !tx.finish(used).await?.is_some_and(|u| u.user_id == user.id) {
        return Ok(not_valid());
    }
    finish_reset(app, &user, &hash, ctx.ip(), method).await?;
    Ok(reset_done(&user.username))
}

// -------------------------------------------------------- email verification

pub async fn get_verify_email(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let query = ctx.req.query();
    let token = query.get("token");
    let Some(row) = peek_token(app.db(), Purpose::VerifyEmail, token).await? else {
        return Ok(message_page(app, 404, "Link not valid", "This link has expired or was already used.", None, Extras::default()));
    };
    let (csrf, cookie) = form_token(&ctx.req);
    // A button, not the link itself, confirms: mail scanners open links.
    let body = format!(
        r#"
<h1>Confirm your email address</h1>
<form method="post" action="/verify-email" class="card">
  {csrf}
  <input type="hidden" name="token" value="{token}">
  <p class="value">{email}</p>
  <button type="submit" class="block">Confirm</button>
</form>"#,
        csrf = hidden_csrf(&csrf),
        token = h(token.unwrap_or("")),
        email = h(row.email.as_deref().unwrap_or("")),
    );
    Ok(page(app, "Confirm your email address", &body, PageOptions { extras: extras_with(cookie, Vec::new()), ..Default::default() }))
}

pub async fn post_verify_email(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let form = read_form(&ctx.req)?;
    check_form(app, &ctx.req, &form)?;
    let token = form.get("token");
    let tx = app.begin().await?;
    let work = async {
        let q = tx.q();
        let Some(used) = consume_token(q, Purpose::VerifyEmail, token).await? else { return Ok(false) };
        let Some(email) = used.email.filter(|e| !e.is_empty()) else { return Ok(false) };
        q.execute("UPDATE users SET email = $2, email_verified_at = now(), updated_at = now() WHERE id = $1", &[&used.user_id, &email]).await?;
        // Links sent to any other address stop working.
        q.execute("DELETE FROM one_time_tokens WHERE user_id = $1 AND purpose IN ('verify_email', 'reset') AND used_at IS NULL", &[&used.user_id]).await?;
        audit(q, Audit::new(Some(&used.user_id), "email.verify").user(Some(&used.user_id)).ip(ctx.ip())).await?;
        Ok(true)
    }
    .await;
    match tx.finish(work).await {
        Ok(true) => Ok(message_page(app, 200, "Address confirmed", "Your email address is confirmed.", Some(("/account", "Your account")), Extras::default())),
        Ok(false) => Ok(message_page(app, 404, "Link not valid", "This link has expired or was already used.", None, Extras::default())),
        Err(e) if e.is_unique_violation(Some("users_email")) => {
            Ok(message_page(app, 409, "Address in use", "Another account already uses this address, so it can't be added to this one.", None, Extras::default()))
        }
        Err(e) => Err(e),
    }
}

// ------------------------------------------------------------- MFA required

pub async fn get_mfa_required(ctx: Ctx) -> Result<Response> {
    let query = ctx.req.query();
    let service = utf16_prefix(query.get("service").unwrap_or(""), 64);
    let return_to = local_path(query.get("return_to"));
    let body = format!(
        r#"
<h1>Two-factor authentication needed</h1>
<div class="card">
  <p>Your role on {service} needs a second factor. Add an authenticator app or a passkey to your account, then continue.</p>
  <a class="button block" href="/account#security">Set up a second factor</a>
</div>
<p class="links"><a href="{return_to}">Continue to {service}</a></p>"#,
        service = h(service),
        return_to = h(&return_to),
    );
    Ok(page(&ctx.app, "Two-factor authentication needed", &body, PageOptions::default()))
}
