//! Services (docs/DESIGN.md §6, §6.2): which services exist, their roles,
//! sign-up policy, scopes, clients and event URL. They come from the services
//! file, read once at start, where a rule broken stops the start with every
//! problem listed, and from the database, where the same rules refuse a
//! registration (registry.rs).

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};
use url::Url;

use crate::util::{iso, utf16_len};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Signup {
    Closed,
    Invite,
    Open,
}

impl Signup {
    pub fn as_str(self) -> &'static str {
        match self {
            Signup::Closed => "closed",
            Signup::Invite => "invite",
            Signup::Open => "open",
        }
    }

    pub fn parse(s: &str) -> Signup {
        match s {
            "open" => Signup::Open,
            "invite" => Signup::Invite,
            _ => Signup::Closed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Source {
    Builtin,
    File,
    Database,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Builtin => "builtin",
            Source::File => "file",
            Source::Database => "database",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Client {
    pub id: String,
    pub public: bool,
    pub service: String,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
}

impl Client {
    pub fn kind(&self) -> &'static str {
        if self.public {
            "public"
        } else {
            "confidential"
        }
    }
}

#[derive(Debug, Clone)]
pub struct Service {
    pub name: String,
    pub roles: Vec<String>,
    pub mfa_roles: Vec<String>,
    pub signup: Signup,
    pub default_role: Option<String>,
    pub manages_own_members: bool,
    pub api_key_scopes: Vec<String>,
    pub app_password_scopes: Vec<String>,
    pub clients: Vec<Client>,
    pub events_url: Option<String>,
    pub source: Source,
}

impl Service {
    /// A role's place in the service's order, lowest first, as declared.
    pub fn rank(&self, role: &str) -> Option<usize> {
        self.roles.iter().position(|r| r == role)
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    pub fn requires_mfa(&self, role: &str) -> bool {
        self.mfa_roles.iter().any(|r| r == role)
    }
}

/// auth's own service: its one role manages every service and reads the audit
/// log, and always requires MFA (§6).
pub const AUTH_SERVICE: &str = "auth";

fn auth_service() -> Service {
    Service {
        name: AUTH_SERVICE.to_string(),
        roles: vec!["admin".into()],
        mfa_roles: vec!["admin".into()],
        signup: Signup::Closed,
        default_role: None,
        manages_own_members: false,
        api_key_scopes: Vec::new(),
        app_password_scopes: Vec::new(),
        clients: Vec::new(),
        events_url: None,
        source: Source::Builtin,
    }
}

/// One set of services, as a request sees it from start to end. `held` are
/// the database's services that the file overrides (§6.2): listed, not used.
pub struct Services {
    in_effect: Vec<Arc<Service>>,
    by_name: HashMap<String, usize>,
    clients: Vec<Client>,
    client_index: HashMap<String, usize>,
    pub held: Vec<Arc<Service>>,
}

impl Services {
    pub fn new(services: Vec<Service>, held: Vec<Service>) -> Services {
        let mut in_effect: Vec<Arc<Service>> = Vec::new();
        let mut by_name = HashMap::new();
        // Of two with one name, the later one is what the name gives.
        for s in std::iter::once(auth_service()).chain(services.iter().cloned()) {
            match by_name.get(&s.name) {
                Some(i) => in_effect[*i] = Arc::new(s),
                None => {
                    by_name.insert(s.name.clone(), in_effect.len());
                    in_effect.push(Arc::new(s));
                }
            }
        }
        let mut clients: Vec<Client> = Vec::new();
        let mut client_index = HashMap::new();
        for c in services.iter().flat_map(|s| s.clients.iter()) {
            match client_index.get(&c.id) {
                Some(i) => clients[*i] = c.clone(),
                None => {
                    client_index.insert(c.id.clone(), clients.len());
                    clients.push(c.clone());
                }
            }
        }
        Services { in_effect, by_name, clients, client_index, held: held.into_iter().map(Arc::new).collect() }
    }

    pub fn get(&self, name: &str) -> Option<&Arc<Service>> {
        self.by_name.get(name).map(|i| &self.in_effect[*i])
    }

    pub fn client(&self, id: &str) -> Option<&Client> {
        self.client_index.get(id).map(|i| &self.clients[*i])
    }

    pub fn all(&self) -> &[Arc<Service>] {
        &self.in_effect
    }

    pub fn any_open(&self) -> bool {
        self.in_effect.iter().any(|s| s.signup == Signup::Open)
    }

    /// Where a sign-in form's redirects may lead: CSP form-action covers the
    /// redirects that follow a form post (§9.2).
    pub fn form_action_sources(&self) -> Vec<String> {
        let mut sources: Vec<String> = Vec::new();
        for client in &self.clients {
            for uri in &client.redirect_uris {
                let Ok(url) = Url::parse(uri) else { continue };
                let source = if url.scheme() == "https" || url.scheme() == "http" { url.origin().ascii_serialization() } else { format!("{}:", url.scheme()) };
                if !sources.contains(&source) {
                    sources.push(source);
                }
            }
        }
        sources.sort();
        sources
    }
}

const SERVICE_FIELDS: [&str; 10] = ["name", "roles", "mfa_roles", "signup", "default_role", "manages_own_members", "api_key_scopes", "app_password_scopes", "clients", "events_url"];
const CLIENT_FIELDS: [&str; 4] = ["id", "type", "redirect_uris", "post_logout_redirect_uris"];

fn lower_or_digit(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit()
}

// `^[a-z][a-z0-9-]{0,62}$`
fn is_service_name(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=63).contains(&b.len()) && b[0].is_ascii_lowercase() && b[1..].iter().all(|c| lower_or_digit(*c) || *c == b'-')
}

// `^[a-z][a-z0-9_-]{0,31}$`
fn is_role(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=32).contains(&b.len()) && b[0].is_ascii_lowercase() && b[1..].iter().all(|c| lower_or_digit(*c) || *c == b'_' || *c == b'-')
}

// `^[a-z][a-z0-9:._-]{0,63}$`
fn is_scope(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=64).contains(&b.len()) && b[0].is_ascii_lowercase() && b[1..].iter().all(|c| lower_or_digit(*c) || b":._-".contains(c))
}

// `^[a-z0-9][a-z0-9._-]{0,63}$`
fn is_client_id(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=64).contains(&b.len()) && lower_or_digit(b[0]) && b[1..].iter().all(|c| lower_or_digit(*c) || b"._-".contains(c))
}

// RFC 8252 §7.1: a reverse domain name with at least one dot,
// `^[a-z][a-z0-9+.-]*\.[a-z0-9+.-]+:$` over the scheme and its colon.
fn is_private_scheme(scheme: &str) -> bool {
    let b = scheme.as_bytes();
    !b.is_empty() && b[0].is_ascii_lowercase() && b.iter().all(|c| lower_or_digit(*c) || b"+.-".contains(c)) && (1..b.len().saturating_sub(1)).any(|i| b[i] == b'.')
}

pub fn is_loopback_host(hostname: &str) -> bool {
    hostname == "localhost" || hostname == "127.0.0.1" || hostname == "[::1]"
}

pub fn parse_services(text: &str) -> (Services, Vec<String>) {
    let empty = || Services::new(Vec::new(), Vec::new());
    let Ok(doc) = serde_json::from_str::<Value>(text) else {
        return (empty(), vec!["the services file is not valid JSON".into()]);
    };
    let Some(list) = doc.as_object().and_then(|d| d.get("services")).and_then(Value::as_array) else {
        return (empty(), vec!["the services file must be an object with a \"services\" array".into()]);
    };
    let mut problems: Vec<String> = Vec::new();
    for key in doc.as_object().unwrap().keys() {
        if key != "services" {
            problems.push(format!("the services file has an unknown field \"{key}\""));
        }
    }

    let mut services: Vec<Service> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    let mut client_ids: Vec<String> = Vec::new();
    for (i, raw) in list.iter().enumerate() {
        let at = match raw.as_object().and_then(|r| r.get("name")).and_then(Value::as_str) {
            Some(name) => format!("service \"{name}\""),
            None => format!("services[{i}]"),
        };
        let (s, found) = parse_service(raw, Source::File);
        for msg in found {
            problems.push(format!("{at}: {msg}"));
        }
        if names.contains(&s.name) {
            problems.push(format!("{at}: name is used by another service"));
        }
        names.push(s.name.clone());
        for (j, c) in s.clients.iter().enumerate() {
            if client_ids.contains(&c.id) {
                problems.push(format!("{at}: clients[{j}]: id \"{}\" is used by another client", c.id));
            }
            client_ids.push(c.id.clone());
        }
        services.push(s);
    }
    (Services::new(services, Vec::new()), problems)
}

/// A registration's limits (§6), so every copy can hold every service.
const LIMIT_NAMES: usize = 32;
const LIMIT_CLIENTS: usize = 5;
const LIMIT_URIS: usize = 10;
const LIMIT_URI_LENGTH: usize = 1024;

/// One service in the shape of §6, from the file or a registration's body.
/// Every problem is listed; rules across services (unique names and client
/// ids) are the caller's. A registration may write [] or null for a field the
/// file leaves out, as GET /v1/services answers, and is capped.
pub fn parse_service(raw: &Value, source: Source) -> (Service, Vec<String>) {
    let mut problems: Vec<String> = Vec::new();
    let registered = source == Source::Database;
    let absent = |v: Option<&Value>| v.is_none() || (registered && v == Some(&Value::Null));
    let no_fields = Map::new();
    let r = match raw.as_object() {
        Some(r) => r,
        None => {
            problems.push("must be an object".into());
            &no_fields
        }
    };
    for key in r.keys() {
        if !SERVICE_FIELDS.contains(&key.as_str()) {
            problems.push(format!("unknown field \"{key}\""));
        }
    }

    let name = r.get("name").and_then(Value::as_str).unwrap_or("").to_string();
    if !is_service_name(&name) {
        problems.push("name must match [a-z][a-z0-9-]{0,62}".into());
    } else if name == AUTH_SERVICE {
        problems.push(format!("the name \"{AUTH_SERVICE}\" is reserved"));
    }

    let roles = string_list(r.get("roles"), is_role, "roles", &mut problems, true, true);
    let mfa_roles = string_list(r.get("mfa_roles"), is_role, "mfa_roles", &mut problems, true, false);
    for role in &mfa_roles {
        if !roles.contains(role) {
            problems.push(format!("mfa_roles has \"{role}\", which is not one of roles"));
        }
    }

    let signup = r.get("signup").and_then(Value::as_str).filter(|s| matches!(*s, "closed" | "invite" | "open"));
    if signup.is_none() {
        problems.push("signup must be \"closed\", \"invite\" or \"open\"".into());
    }
    let mut default_role = None;
    if signup == Some("open") {
        match r.get("default_role").and_then(Value::as_str).filter(|d| roles.iter().any(|x| x == d)) {
            Some(d) => default_role = Some(d.to_string()),
            None => problems.push("default_role must be one of roles when signup is open".into()),
        }
    } else if !absent(r.get("default_role")) {
        problems.push("default_role is only for signup \"open\"".into());
    }

    if r.get("manages_own_members").is_some_and(|v| !v.is_boolean()) {
        problems.push("manages_own_members must be true or false".into());
    }
    let api_key_scopes = string_list(r.get("api_key_scopes"), is_scope, "api_key_scopes", &mut problems, false, !registered);
    let app_password_scopes = string_list(r.get("app_password_scopes"), is_scope, "app_password_scopes", &mut problems, false, !registered);
    let clients_raw = r.get("clients").and_then(Value::as_array);
    if registered {
        for (field, list) in [("roles", &roles), ("api_key_scopes", &api_key_scopes), ("app_password_scopes", &app_password_scopes)] {
            if list.len() > LIMIT_NAMES {
                problems.push(format!("{field} has more than {LIMIT_NAMES} names"));
            }
        }
        if clients_raw.is_some_and(|c| c.len() > LIMIT_CLIENTS) {
            problems.push(format!("clients has more than {LIMIT_CLIENTS}"));
        }
    }

    let mut clients: Vec<Client> = Vec::new();
    let mut ids: Vec<String> = Vec::new();
    match clients_raw.filter(|c| !c.is_empty()) {
        None => problems.push("clients must be a non-empty array".into()),
        Some(list) => {
            for (j, c) in list.iter().enumerate() {
                let mut found: Vec<String> = Vec::new();
                let Some(c) = c.as_object() else {
                    problems.push(format!("clients[{j}]: must be an object"));
                    continue;
                };
                for key in c.keys() {
                    if !CLIENT_FIELDS.contains(&key.as_str()) {
                        found.push(format!("unknown field \"{key}\""));
                    }
                }
                let id = c.get("id").and_then(Value::as_str).unwrap_or("").to_string();
                if !is_client_id(&id) {
                    found.push("id must match [a-z0-9][a-z0-9._-]{0,63}".into());
                } else if ids.contains(&id) {
                    found.push(format!("id \"{id}\" is used by another client"));
                }
                ids.push(id.clone());
                let kind = c.get("type").and_then(Value::as_str);
                if kind != Some("confidential") && kind != Some("public") {
                    found.push("type must be \"confidential\" or \"public\"".into());
                }
                let public = kind == Some("public");
                let redirect_uris = uri_list(c.get("redirect_uris"), public, "redirect_uris", &mut found, true);
                let post_logout = uri_list(c.get("post_logout_redirect_uris"), public, "post_logout_redirect_uris", &mut found, false);
                if registered {
                    for (field, list) in [("redirect_uris", &redirect_uris), ("post_logout_redirect_uris", &post_logout)] {
                        if list.len() > LIMIT_URIS {
                            found.push(format!("{field} has more than {LIMIT_URIS} URIs"));
                        }
                        if list.iter().any(|u| utf16_len(u) > LIMIT_URI_LENGTH) {
                            found.push(format!("{field} has a URI longer than {LIMIT_URI_LENGTH} characters"));
                        }
                    }
                }
                problems.extend(found.into_iter().map(|msg| format!("clients[{j}]: {msg}")));
                clients.push(Client { id, public, service: name.clone(), redirect_uris, post_logout_redirect_uris: post_logout });
            }
        }
    }

    let mut events_url = None;
    if !absent(r.get("events_url")) {
        let text = r.get("events_url").and_then(Value::as_str);
        let ok = text
            .and_then(|t| Url::parse(t).ok())
            .is_some_and(|url| (url.scheme() == "https" || url.scheme() == "http") && url.username().is_empty() && url.password().unwrap_or("").is_empty() && url.fragment().unwrap_or("").is_empty());
        if !ok {
            problems.push("events_url must be an http(s) URL without credentials or a fragment".into());
        } else if registered && utf16_len(text.unwrap()) > LIMIT_URI_LENGTH {
            problems.push(format!("events_url is longer than {LIMIT_URI_LENGTH} characters"));
        } else {
            events_url = text.map(str::to_string);
        }
    }

    let service = Service {
        name,
        roles,
        mfa_roles,
        signup: Signup::parse(signup.unwrap_or("closed")),
        default_role,
        manages_own_members: r.get("manages_own_members") == Some(&Value::Bool(true)),
        api_key_scopes,
        app_password_scopes,
        clients,
        events_url,
        source,
    };
    (service, problems)
}

/// The shape of §6, as the management API answers with it. `secrets` gives
/// each confidential client's live secrets' creation times, newest first.
pub fn service_json(s: &Service, secrets: &HashMap<String, Vec<DateTime<Utc>>>) -> Value {
    let clients: Vec<Value> = s
        .clients
        .iter()
        .map(|c| {
            let mut out = json!({
                "id": c.id,
                "type": c.kind(),
                "redirect_uris": c.redirect_uris,
                "post_logout_redirect_uris": c.post_logout_redirect_uris,
            });
            if !c.public {
                let live: Vec<Value> = secrets.get(&c.id).map(|v| v.iter().map(|at| json!({ "created_at": iso(at) })).collect()).unwrap_or_default();
                out["secrets"] = Value::Array(live);
            }
            out
        })
        .collect();
    json!({
        "name": s.name,
        "roles": s.roles,
        "mfa_roles": s.mfa_roles,
        "signup": s.signup.as_str(),
        "default_role": s.default_role,
        "manages_own_members": s.manages_own_members,
        "api_key_scopes": s.api_key_scopes,
        "app_password_scopes": s.app_password_scopes,
        "clients": clients,
        "events_url": s.events_url,
        "source": s.source.as_str(),
    })
}

fn string_list(value: Option<&Value>, pattern: fn(&str) -> bool, field: &str, problems: &mut Vec<String>, required: bool, non_empty: bool) -> Vec<String> {
    if value.is_none() && !required {
        return Vec::new();
    }
    let Some(list) = value.and_then(Value::as_array).filter(|l| !(non_empty && l.is_empty())) else {
        problems.push(format!("{field} must be {} array of names", if non_empty { "a non-empty" } else { "an" }));
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for v in list {
        match v.as_str().filter(|s| pattern(s)) {
            None => problems.push(format!("{field} has an invalid name {v}")),
            Some(s) if out.iter().any(|o| o == s) => problems.push(format!("{field} lists \"{s}\" twice")),
            Some(s) => out.push(s.to_string()),
        }
    }
    out
}

// Absolute redirect URIs: https, http only for a loopback host, or a
// private-use scheme for a public client (RFC 8252). Compared later by exact
// string, so they're kept as written.
fn uri_list(value: Option<&Value>, public: bool, field: &str, problems: &mut Vec<String>, required: bool) -> Vec<String> {
    if value.is_none() && !required {
        return Vec::new();
    }
    let Some(list) = value.and_then(Value::as_array).filter(|l| !(required && l.is_empty())) else {
        problems.push(format!("{field} must be a{} array of URIs", if required { " non-empty" } else { "n" }));
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for v in list {
        let url = v.as_str().and_then(|s| Url::parse(s).ok());
        let credentials = url.as_ref().is_some_and(|u| !u.username().is_empty() || !u.password().unwrap_or("").is_empty());
        let ok = url.as_ref().is_some_and(|u| {
            u.fragment().unwrap_or("").is_empty()
                && !credentials
                && (u.scheme() == "https" || (u.scheme() == "http" && is_loopback_host(u.host_str().unwrap_or(""))) || (public && is_private_scheme(u.scheme())))
        });
        if ok {
            out.push(v.as_str().unwrap().to_string());
        } else {
            // A URI with credentials in it is named without them.
            let shown = if credentials { "a URI with credentials".to_string() } else { v.to_string() };
            problems.push(format!("{field} has {shown}, which is not an https URI, an http URI on a loopback host, or (for a public client) a private-use scheme"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schemes_and_names() {
        assert!(is_private_scheme("com.example.tasks"));
        assert!(!is_private_scheme("myapp"));
        assert!(!is_private_scheme(".example"));
        assert!(!is_private_scheme("example."));
        assert!(is_service_name("wiki") && !is_service_name("Wiki") && !is_service_name(""));
        assert!(is_client_id("0wiki.app") && !is_client_id("-wiki"));
    }

    #[test]
    fn every_problem_of_a_service_is_listed() {
        let (_, problems) = parse_service(&json!({ "name": "auth", "roles": [], "signup": "maybe", "extra": 1, "clients": [] }), Source::File);
        assert_eq!(
            problems,
            vec![
                "unknown field \"extra\"",
                "the name \"auth\" is reserved",
                "roles must be a non-empty array of names",
                "mfa_roles must be an array of names",
                "signup must be \"closed\", \"invite\" or \"open\"",
                "clients must be a non-empty array",
            ]
        );
    }
}
