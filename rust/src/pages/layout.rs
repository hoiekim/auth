//! The page shell and the helpers every page uses. Every value is escaped;
//! scripts and styles come only from /assets, as the CSP requires.

use crate::app::App;
use crate::crypto::{is_token, random_token, safe_equal};
use crate::error::{http, Result};
use crate::http::{from_issuer, host_cookie, html, page_csp, set_cookie, Extras, Params, Request, Response};
use crate::util::utf16_len;

pub fn h(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

// Icons are inline SVG: the CSP loads no images. 16×16, drawn with the text
// color.
fn icon_path(name: &str) -> &'static str {
    match name {
        "info" => r#"<circle cx="8" cy="8" r="6.25"/><path d="M8 7.25v3.5M8 5v.25"/>"#,
        "alert" => r#"<path d="M8 2.25 1.75 13.25h12.5L8 2.25ZM8 6.5v3M8 11.25v.25"/>"#,
        "check" => r#"<circle cx="8" cy="8" r="6.25"/><path d="m5.5 8.25 1.75 1.75 3.25-3.5"/>"#,
        "passkey" => r#"<circle cx="6" cy="5" r="2.5"/><path d="M1.75 13.25c.4-2.4 2.1-3.75 4.25-3.75.8 0 1.5.2 2.1.5"/><circle cx="12" cy="8.25" r="1.75"/><path d="M12 10v3.75M12 12.25h1.25"/>"#,
        _ => "",
    }
}

pub fn icon(name: &str, size: u32) -> String {
    format!(
        r#"<svg class="icon" width="{size}" height="{size}" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">{}</svg>"#,
        icon_path(name)
    )
}

/// A keyhole: the mark above the sign-in pages and in the account header.
pub fn logo(size: u32) -> String {
    format!(
        r##"<svg class="logo" width="{size}" height="{size}" viewBox="0 0 32 32" aria-hidden="true" focusable="false"><rect class="logo-bg" width="32" height="32" rx="8" fill="#0969da"/><circle class="logo-fg" cx="16" cy="13" r="4.5" fill="#fff"/><path class="logo-fg" d="M13.6 15.5h4.8l1.35 8.5h-7.5z" fill="#fff"/></svg>"##
    )
}

/// A message box: "notice", "success" or "error". An error is announced as an
/// alert, the others as a status.
pub fn flash(kind: &str, message: &str) -> String {
    let role = if kind == "error" { r#" role="alert""# } else { r#" role="status""# };
    let glyph = match kind {
        "success" => "check",
        "notice" => "info",
        _ => "alert",
    };
    format!(r#"<p class="{kind}"{role}>{}<span>{}</span></p>"#, icon(glyph, 16), h(message))
}

#[derive(Default)]
pub struct PageOptions {
    pub status: Option<u16>,
    pub scripts: Vec<&'static str>,
    pub meta: Vec<(String, String)>,
    pub extras: Extras,
    /// The account and admin pages: a header bar and a wide frame. Every other
    /// page is a narrow card under the logo.
    pub header: Option<String>,
}

pub fn page(app: &App, title: &str, body: &str, opts: PageOptions) -> Response {
    let meta: Vec<String> = opts.meta.iter().map(|(k, v)| format!(r#"<meta name="{}" content="{}">"#, h(k), h(v))).collect();
    let scripts: Vec<String> = opts.scripts.iter().map(|s| format!(r#"<script src="/assets/{}" defer></script>"#, h(s))).collect();
    let frame = match &opts.header {
        Some(header) => format!("<body class=\"app-frame\">\n{header}\n<main class=\"app-main\">\n{body}\n</main>\n</body>"),
        None => format!("<body class=\"card-frame\">\n<main class=\"card-main\">\n<div class=\"brand-mark\">{}</div>\n{body}\n</main>\n</body>", logo(48)),
    };
    let doc = format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
{}
<title>{}</title>
<link rel="icon" href="/favicon.ico" sizes="32x32">
<link rel="icon" href="/assets/icon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/assets/apple-touch-icon.png">
<link rel="stylesheet" href="/assets/style.css">
{}
</head>
{frame}
</html>"#,
        meta.join("\n"),
        h(title),
        scripts.join("\n"),
    );
    html(opts.status.unwrap_or(200), doc, &page_csp(&app.services.form_action_sources()), opts.extras)
}

/// A page that says one thing, with at most one link (its href and text).
pub fn message_page(app: &App, status: u16, title: &str, message: &str, link: Option<(&str, &str)>, extras: Extras) -> Response {
    let ok = status < 400;
    let a = match link {
        Some((href, text)) => format!(r#"<a class="button block{}" href="{}">{}</a>"#, if ok { "" } else { " secondary" }, h(href), h(text)),
        None => String::new(),
    };
    let body = format!(
        "<h1>{}</h1>\n<div class=\"card\">\n<div class=\"status-icon{}\">{}</div>\n<p>{}</p>\n{a}\n</div>",
        h(title),
        if ok { "" } else { " warn" },
        icon(if ok { "check" } else { "alert" }, 24),
        h(message),
    );
    page(app, title, &body, PageOptions { status: Some(status), extras, ..Default::default() })
}

// Forms posted before or without a session carry a double-submit token: a
// random __Host- cookie echoed in a hidden field. With the Origin check it
// blocks login CSRF (§9.2).
pub const FORM_COOKIE: &str = "csrf";

/// The form's token, and the cookie to set when the browser has none.
pub fn form_token(req: &Request) -> (String, Option<String>) {
    if let Some(existing) = host_cookie(req, FORM_COOKIE).filter(|t| is_token(t)) {
        return (existing, None);
    }
    let token = random_token();
    let cookie = set_cookie(FORM_COOKIE, &token, None, "Strict");
    (token, Some(cookie))
}

pub fn hidden_csrf(token: &str) -> String {
    format!(r#"<input type="hidden" name="csrf" value="{}">"#, h(token))
}

pub fn check_form(app: &App, req: &Request, form: &Params) -> Result<()> {
    if !from_issuer(&app.config.issuer, req) {
        return Err(http(403, "forbidden", "This form was not sent from this site."));
    }
    let cookie = host_cookie(req, FORM_COOKIE).unwrap_or_default();
    let sent = form.get("csrf").unwrap_or("");
    if cookie.is_empty() || !safe_equal(&cookie, sent) {
        return Err(http(403, "forbidden", "This form has expired. Go back, reload the page and try again."));
    }
    Ok(())
}

/// A path on this site to go to after a step, never another origin.
pub fn local_path(value: Option<&str>) -> String {
    local_path_or(value, "/account")
}

/// Printable ASCII only, as a path the server writes is: anything else would
/// go into a Location header raw.
pub fn local_path_or(value: Option<&str>, fallback: &str) -> String {
    match value {
        Some(v) if !v.is_empty() && utf16_len(v) <= 4096 && v.starts_with('/') && !v.starts_with("//") && !v.starts_with("/\\") && !v.chars().any(|c| !(' '..='~').contains(&c) || c == '\\') => {
            v.to_string()
        }
        _ => fallback.to_string(),
    }
}

pub fn extras_with(cookie: Option<String>, more: Vec<String>) -> Extras {
    Extras::cookies(cookie.into_iter().chain(more).collect())
}
