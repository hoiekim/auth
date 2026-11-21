//! The account and admin pages: a shell whose script calls the /v1 API, the
//! same handlers apps use (docs/DESIGN.md §7.5). And the static files, which
//! are ../src/assets: the one copy both servers serve.

use crate::access::role_of;
use crate::app::App;
use crate::error::Result;
use crate::http::{asset, error_response, redirect, Extras, Response};
use crate::pages::layout::{h, logo, message_page, page, PageOptions};
use crate::server::Ctx;
use crate::services::AUTH_SERVICE;
use crate::sessions::{csrf_token, load_session};
use crate::util::form_encode;

// Built in: a fixed set, so no request path ever reaches the file system.
const ASSETS: [(&str, &str, &[u8]); 7] = [
    ("style.css", "text/css; charset=utf-8", include_bytes!("../../../src/assets/style.css")),
    ("signin.js", "text/javascript; charset=utf-8", include_bytes!("../../../src/assets/signin.js")),
    ("account.js", "text/javascript; charset=utf-8", include_bytes!("../../../src/assets/account.js")),
    ("admin.js", "text/javascript; charset=utf-8", include_bytes!("../../../src/assets/admin.js")),
    ("icon.svg", "image/svg+xml", include_bytes!("../../../src/assets/icon.svg")),
    ("apple-touch-icon.png", "image/png", include_bytes!("../../../src/assets/apple-touch-icon.png")),
    ("favicon.ico", "image/x-icon", include_bytes!("../../../src/assets/favicon.ico")),
];

fn named(name: &str) -> Option<Response> {
    ASSETS.iter().find(|(n, _, _)| *n == name).map(|(_, kind, body)| asset(body, kind))
}

pub async fn asset_route(ctx: Ctx) -> Result<Response> {
    Ok(named(ctx.param("file")).unwrap_or_else(|| error_response(404, "not_found", "No such asset.", &[])))
}

/// Browsers ask for /favicon.ico on their own, for pages and JSON alike.
pub async fn favicon(_ctx: Ctx) -> Result<Response> {
    Ok(named("favicon.ico").expect("the favicon is built in"))
}

pub async fn home(_ctx: Ctx) -> Result<Response> {
    Ok(redirect("/account", Extras::default(), 302))
}

// The bar above the account and admin pages. The account page shows its
// Admin link once its script knows the user is an admin.
fn header(app: &App, current: &str) -> String {
    let here = |name: &str| if name == current { r#" aria-current="page""# } else { "" };
    let issuer = &app.config.issuer;
    let host = issuer.strip_prefix("https://").or_else(|| issuer.strip_prefix("http://")).unwrap_or(issuer);
    format!(
        r#"<header class="app-header">
<a class="app-brand" href="/account">{}<span>{}</span></a>
<nav class="app-nav" aria-label="Main">
<a href="/account"{}>Account</a>
<a href="/admin" id="admin-link"{}{}>Admin</a>
<a href="/logout">Sign out</a>
</nav>
</header>"#,
        logo(28),
        h(host),
        here("account"),
        here("admin"),
        if current == "admin" { "" } else { " hidden" },
    )
}

fn shell(what: &str) -> String {
    format!("\n<div id=\"app\"><p class=\"loading\">Loading…</p></div>\n<noscript><p class=\"notice\">The {what} page needs JavaScript.</p></noscript>")
}

pub async fn account_page(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let Some(session) = load_session(app, &ctx.req).await? else {
        return Ok(redirect(&format!("/login?{}", form_encode(&[("return_to", "/account")])), Extras::default(), 302));
    };
    let opts = PageOptions { header: Some(header(app, "account")), scripts: vec!["account.js"], meta: vec![("csrf-token".to_string(), csrf_token(app, &session))], ..Default::default() };
    Ok(page(app, "Your account", &shell("account"), opts))
}

pub async fn admin_page(ctx: Ctx) -> Result<Response> {
    let app = &ctx.app;
    let Some(session) = load_session(app, &ctx.req).await? else {
        return Ok(redirect(&format!("/login?{}", form_encode(&[("return_to", "/admin")])), Extras::default(), 302));
    };
    if role_of(app.db(), &session.user_id, AUTH_SERVICE).await?.as_deref() != Some("admin") {
        return Ok(message_page(app, 403, "No access", "This page is for auth's administrators.", Some(("/account", "Your account")), Extras::default()));
    }
    if !session.has_mfa() {
        return Ok(redirect(&format!("/login?{}", form_encode(&[("return_to", "/admin"), ("second_factor", AUTH_SERVICE)])), Extras::default(), 302));
    }
    let opts = PageOptions { header: Some(header(app, "admin")), scripts: vec!["admin.js"], meta: vec![("csrf-token".to_string(), csrf_token(app, &session))], ..Default::default() };
    Ok(page(app, "Admin", &shell("admin"), opts))
}
