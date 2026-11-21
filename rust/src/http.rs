//! Requests and responses. Every response carries the security headers, and
//! every error has the one shape docs/DESIGN.md §7.7 defines:
//! {"error": "<code>", "error_description": "<text>"}.

use serde_json::{json, Map, Value};
use url::Url;

use crate::error::{Error, HttpError, Result};
use crate::util::{form_decode, js_trim};

pub const MAX_BODY_BYTES: usize = 64 * 1024;

const SECURITY_HEADERS: [(&str, &str); 5] = [
    ("Cache-Control", "no-store"),
    ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
    ("Referrer-Policy", "no-referrer"),
    ("Strict-Transport-Security", "max-age=63072000"),
    ("X-Content-Type-Options", "nosniff"),
];

/// A request as a handler sees it: the body is already read, and capped.
pub struct Request {
    pub method: String,
    pub url: Url,
    /// Lower-case names, in the order received.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// A header's value. One sent several times reads as the values joined,
    /// as the Fetch API joins them: cookies with "; ", the others with ", ".
    pub fn header(&self, name: &str) -> Option<String> {
        let lower = name.to_ascii_lowercase();
        let values: Vec<&str> = self.headers.iter().filter(|(n, _)| *n == lower).map(|(_, v)| v.as_str()).collect();
        if values.is_empty() {
            return None;
        }
        Some(values.join(if lower == "cookie" { "; " } else { ", " }))
    }

    pub fn path(&self) -> &str {
        self.url.path()
    }

    /// The query string's pairs, in order.
    pub fn query(&self) -> Params {
        Params(form_decode(self.url.query().unwrap_or("")))
    }

    /// `pathname + search`.
    pub fn path_and_search(&self) -> String {
        match self.url.query() {
            Some(q) if !q.is_empty() => format!("{}?{}", self.url.path(), q),
            _ => self.url.path().to_string(),
        }
    }

    /// The body as text.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// `URLSearchParams`: a query string's or a form's pairs.
#[derive(Debug, Clone, Default)]
pub struct Params(pub Vec<(String, String)>);

impl Params {
    /// The first value of a name.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    pub fn has(&self, name: &str) -> bool {
        self.0.iter().any(|(k, _)| k == name)
    }

    /// One value of a parameter; a repeated parameter is refused, as OAuth
    /// requires (RFC 6749 §3.1).
    pub fn single(&self, name: &str) -> Result<Option<&str>> {
        let mut all = self.0.iter().filter(|(k, _)| k == name);
        let first = all.next();
        if all.next().is_some() {
            return Err(Error::Http(HttpError::new(400, "invalid_request", format!("The parameter \"{name}\" is repeated."))));
        }
        Ok(first.map(|(_, v)| v.as_str()))
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// `headers.set`: replaces every header of that name.
    pub fn set_header(&mut self, name: &str, value: &str) {
        self.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        self.headers.push((name.to_string(), value.to_string()));
    }

    pub fn append_header(&mut self, name: &str, value: &str) {
        self.headers.push((name.to_string(), value.to_string()));
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    pub fn set_cookies(&self) -> Vec<String> {
        self.headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case("Set-Cookie")).map(|(_, v)| v.clone()).collect()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Extras {
    pub headers: Vec<(String, String)>,
    pub cookies: Vec<String>,
}

impl Extras {
    pub fn cookies(cookies: Vec<String>) -> Extras {
        Extras { headers: Vec::new(), cookies }
    }
}

fn respond(status: u16, body: Vec<u8>, content_type: Option<&str>, extras: &Extras) -> Response {
    let mut res = Response { status, headers: SECURITY_HEADERS.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect(), body };
    if let Some(t) = content_type {
        res.set_header("Content-Type", t);
    }
    for (k, v) in &extras.headers {
        res.set_header(k, v);
    }
    for c in &extras.cookies {
        res.append_header("Set-Cookie", c);
    }
    res
}

pub fn json(status: u16, body: &Value) -> Response {
    json_with(status, body, &[], Vec::new())
}

pub fn json_with(status: u16, body: &Value, headers: &[(String, String)], cookies: Vec<String>) -> Response {
    respond(status, body.to_string().into_bytes(), Some("application/json"), &Extras { headers: headers.to_vec(), cookies })
}

pub fn error_response(status: u16, error: &str, description: &str, headers: &[(String, String)]) -> Response {
    json_with(status, &json!({ "error": error, "error_description": description }), headers, Vec::new())
}

pub fn no_content(extras: Extras) -> Response {
    respond(204, Vec::new(), None, &extras)
}

/// Pages: scripts and styles come only from auth itself, and a form may post
/// only to auth or lead, through redirects, to a registered redirect origin
/// (§9.2).
pub fn page_csp(form_action_sources: &[String]) -> String {
    let form_action = format!("form-action 'self' {}", form_action_sources.join(" "));
    ["default-src 'self'", "frame-ancestors 'none'", js_trim(&form_action), "base-uri 'none'"].join("; ")
}

pub fn html(status: u16, body: String, csp: &str, extras: Extras) -> Response {
    let mut headers = vec![("Content-Security-Policy".to_string(), csp.to_string())];
    headers.extend(extras.headers);
    respond(status, body.into_bytes(), Some("text/html; charset=utf-8"), &Extras { headers, cookies: extras.cookies })
}

pub fn redirect(location: &str, extras: Extras, status: u16) -> Response {
    let mut headers = extras.headers;
    headers.push(("Location".to_string(), location.to_string()));
    respond(status, Vec::new(), None, &Extras { headers, cookies: extras.cookies })
}

/// A redirect after a form post.
pub fn see_other(location: &str, extras: Extras) -> Response {
    redirect(location, extras, 303)
}

pub fn asset(body: &[u8], content_type: &str) -> Response {
    respond(200, body.to_vec(), Some(content_type), &Extras { headers: vec![("Cache-Control".to_string(), "public, max-age=300".to_string())], cookies: Vec::new() })
}

// `^<type>\b`, ignoring case.
fn content_type_is(req: &Request, wanted: &str) -> bool {
    let value = req.header("Content-Type").unwrap_or_default();
    let bytes = value.as_bytes();
    bytes.len() >= wanted.len() && bytes[..wanted.len()].eq_ignore_ascii_case(wanted.as_bytes()) && bytes.get(wanted.len()).is_none_or(|c| !(c.is_ascii_alphanumeric() || *c == b'_'))
}

pub fn read_json(req: &Request) -> Result<Map<String, Value>> {
    if !content_type_is(req, "application/json") {
        return Err(Error::Http(HttpError::new(415, "invalid_request", "Send application/json.")));
    }
    let text = req.text();
    if text.is_empty() {
        return Ok(Map::new());
    }
    match serde_json::from_str::<Value>(&text) {
        Err(_) => Err(Error::Http(HttpError::new(400, "invalid_request", "The body is not valid JSON."))),
        Ok(Value::Object(map)) => Ok(map),
        Ok(_) => Err(Error::Http(HttpError::new(400, "invalid_request", "The body must be a JSON object."))),
    }
}

pub fn read_form(req: &Request) -> Result<Params> {
    if !content_type_is(req, "application/x-www-form-urlencoded") {
        return Err(Error::Http(HttpError::new(415, "invalid_request", "Send application/x-www-form-urlencoded.")));
    }
    Ok(Params(form_decode(&req.text())))
}

/// The request's cookies; of two with one name, the first.
pub fn cookies(req: &Request) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for part in req.header("Cookie").unwrap_or_default().split(';') {
        let Some(eq) = part.find('=') else { continue };
        let name = js_trim(&part[..eq]);
        if !name.is_empty() && !out.iter().any(|(n, _)| n == name) {
            out.push((name.to_string(), js_trim(&part[eq + 1..]).to_string()));
        }
    }
    out
}

pub fn host_cookie(req: &Request, name: &str) -> Option<String> {
    let wanted = format!("__Host-{name}");
    cookies(req).into_iter().find(|(n, _)| *n == wanted).map(|(_, v)| v)
}

/// __Host- cookies only (§9.2): Secure, Path=/, no Domain, so a sibling
/// subdomain can't set or overwrite them.
pub fn set_cookie(name: &str, value: &str, max_age_seconds: Option<i64>, same_site: &str) -> String {
    let mut out = format!("__Host-{name}={value}; Path=/; Secure; HttpOnly; SameSite={same_site}");
    if let Some(age) = max_age_seconds {
        out.push_str(&format!("; Max-Age={age}"));
    }
    out
}

pub fn clear_cookie(name: &str) -> String {
    format!("__Host-{name}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
}

/// The request came from one of the issuer's own pages (§9.2): Origin is the
/// issuer's. Under the pages' Referrer-Policy: no-referrer a browser sends
/// `Origin: null` on a same-origin form post and says so in Sec-Fetch-Site,
/// which page scripts can't set. A missing Origin is refused.
pub fn from_issuer(issuer: &str, req: &Request) -> bool {
    match req.header("Origin") {
        Some(origin) if origin == issuer => true,
        Some(origin) => origin == "null" && req.header("Sec-Fetch-Site").as_deref() == Some("same-origin"),
        None => false,
    }
}

/// `Retry-After` for a 429.
pub fn retry_after(seconds: i64) -> Vec<(String, String)> {
    vec![("Retry-After".to_string(), seconds.to_string())]
}
