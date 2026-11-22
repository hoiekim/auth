//! DATABASE_URL, read the way the Bun server's SQL client reads it (Bun
//! 1.4.4's `internal/sql/options.ts`, for the postgres adapter given a URL and
//! `{ max: 5 }`), so that one connection string means the same to both
//! servers: which query keys are the client's, which go to Postgres as
//! startup settings, how `sslmode` reads, and the `PG*` variables it falls
//! back on. `rust/tests/database_urls.json` records what Bun makes of each
//! case, and the tests below hold this reading to it.

use std::time::Duration;

use url::Url;

use crate::util::{decode_uri_component, js_number};

/// How much TLS: none; when the server offers it; always; always, with the
/// certificate's chain checked; and with its name checked too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SslMode {
    Disable = 0,
    Prefer = 1,
    Require = 2,
    VerifyCa = 3,
    VerifyFull = 4,
}

/// The files `sslrootcert`, `sslcert`, `sslkey` and `sslpassword` name.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TlsFiles {
    /// Trusted alone, in place of the usual roots.
    pub ca_file: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub passphrase: Option<String>,
    /// `sslrootcert=system`: the usual roots, checked.
    pub system: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub database: String,
    /// A Unix socket to connect to in place of `hostname`.
    pub path: Option<String>,
    pub ssl_mode: SslMode,
    pub tls: TlsFiles,
    /// Sent to Postgres in the startup message, in this order.
    pub startup: Vec<(String, String)>,
    /// `disable`, `prefer` or `require`.
    pub channel_binding: String,
    pub prepare: bool,
    pub connect_timeout: Option<Duration>,
    pub idle_timeout: Option<Duration>,
    pub max_lifetime: Option<Duration>,
}

/// Why a connection string can't be used. Never shown with the string.
pub type Refusal = &'static str;

/// Reads `target`, with `env` giving the process's environment.
pub fn parse(target: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<Settings, Refusal> {
    let var = |name: &str| env(name).filter(|v| !v.is_empty());
    let env_of = |name: &str| var(&format!("PG_{name}")).or_else(|| var(&format!("PG{name}")));

    let mut startup = Vec::new();
    if let Some(name) = var("PGAPPNAME") {
        set(&mut startup, "application_name", name);
    }
    if let Some(options) = var("PGOPTIONS") {
        set(&mut startup, "options", options);
    }
    let (url, url_hostname) = server_url(target)?;
    let query = read_query(&url, &mut startup)?;

    let mut hostname = query.hostname.clone().or(Some(url_hostname).filter(|h| !h.is_empty())).or_else(|| env_of("HOST")).unwrap_or_else(|| "localhost".into());
    let port = match (&query.port, url.port(), env_of("PORT")) {
        (Some(port), _, _) => js_number(port),
        (None, Some(port), _) => f64::from(port),
        (None, None, Some(port)) => js_number(&port),
        (None, None, None) => 5432.0,
    };
    if !(1.0..=65535.0).contains(&port) || port.fract() != 0.0 {
        return Err("port");
    }
    let port = port as u16;
    let username = match &query.username {
        Some(username) => username.clone(),
        None => match decode_if_valid(url.username())? {
            Some(username) => username,
            None => var("PGUSERNAME").or_else(|| env_of("USER")).or_else(|| var("USER")).or_else(|| var("USERNAME")).unwrap_or_else(|| "postgres".into()),
        },
    };
    let password = match &query.password {
        Some(password) => password.clone(),
        None => match decode_if_valid(url.password().unwrap_or(""))? {
            Some(password) => password,
            None => env_of("PASSWORD").unwrap_or_default(),
        },
    };
    let database = match env_of("DATABASE").or_else(|| query.database.clone()) {
        Some(database) => database,
        None => decode_if_valid(url.path().get(1..).unwrap_or(""))?.unwrap_or_else(|| username.clone()),
    };
    let mut path = query.path.clone().unwrap_or_default();
    let host_is_path = path.is_empty() && hostname.starts_with('/');
    if host_is_path {
        path = std::mem::replace(&mut hostname, "localhost".into());
    }
    if !path.is_empty() && !path.contains("/.s.PGSQL.") && (host_is_path || std::fs::metadata(&path).is_ok_and(|m| m.is_dir())) {
        path = format!("{path}/.s.PGSQL.{port}");
    }

    let idle_timeout = seconds(query.idle_timeout.as_deref())?;
    let connect_timeout = seconds(query.connect_timeout.clone().or_else(|| var("PGCONNECT_TIMEOUT")).as_deref())?;
    let max_lifetime = seconds(query.max_lifetime.as_deref())?;
    let prepare = !matches!(query.prepare.as_deref(), Some("false" | "0"));
    let channel_binding = query.channel_binding.clone().or_else(|| var("PGCHANNELBINDING")).unwrap_or_else(|| "disable".into());
    if !matches!(channel_binding.as_str(), "disable" | "prefer" | "require") {
        return Err("channel_binding");
    }

    let mut ssl_mode = ssl_mode(env_of("SSLMODE").as_deref().unwrap_or(""))?;
    if let Some(mode) = query.ssl_mode {
        ssl_mode = mode;
    }
    if query.tls && ssl_mode <= SslMode::Prefer {
        ssl_mode = SslMode::Require;
    }
    if ssl_mode != SslMode::Disable && ssl_mode < SslMode::VerifyCa && (query.files.system || query.files.ca_file.is_some()) {
        ssl_mode = SslMode::VerifyFull;
    }
    let mut tls = query.files;
    if !path.is_empty() {
        ssl_mode = SslMode::Disable;
        tls = TlsFiles::default();
    }

    Ok(Settings {
        hostname,
        port,
        username,
        password,
        database,
        path: Some(path).filter(|p| !p.is_empty()),
        ssl_mode,
        tls,
        startup,
        channel_binding,
        prepare,
        connect_timeout,
        idle_timeout,
        max_lifetime,
    })
}

/// `new URL(value)`, with Bun's second try for a URL whose host is missing
/// (`postgres://user@/db`, `postgres://:5432/db`): `localhost` put in its
/// place, and the host then left to the query, `PGHOST` or the default.
fn server_url(target: &str) -> Result<(Url, String), Refusal> {
    let value = if target.contains("://") { target.to_string() } else { format!("postgres://{target}") };
    let url = match Url::parse(&value) {
        Ok(url) => url,
        Err(_) => {
            let start = value.find("://").map_or(0, |i| i + 3);
            let end = value[start..].find(['/', '?', '#']).map_or(value.len(), |i| start + i);
            let host = value[..end].rfind('@').map_or(0, |i| i + 1).max(start);
            if end > start && (host == end || value.as_bytes()[host] == b':') {
                if let Ok(url) = Url::parse(&format!("{}localhost{}", &value[..host], &value[host..])) {
                    return Ok((url, String::new()));
                }
            }
            return Err("url");
        }
    };
    let hostname = url.host_str().unwrap_or("");
    let hostname = if hostname.starts_with("%2F") || hostname.starts_with("%2f") { decode_uri_component(hostname).ok_or("host escape")? } else { hostname.to_string() };
    Ok((url, hostname))
}

#[derive(Default)]
struct Query {
    ssl_mode: Option<SslMode>,
    tls: bool,
    files: TlsFiles,
    path: Option<String>,
    connect_timeout: Option<String>,
    idle_timeout: Option<String>,
    max_lifetime: Option<String>,
    max: Option<String>,
    prepare: Option<String>,
    found_rows: Option<String>,
    channel_binding: Option<String>,
    hostname: Option<String>,
    port: Option<String>,
    username: Option<String>,
    password: Option<String>,
    database: Option<String>,
}

impl Query {
    /// The client's own options a query key sets, the first non-empty value
    /// winning.
    fn option(&mut self, key: &str) -> Option<&mut Option<String>> {
        Some(match key {
            "path" | "socket" => &mut self.path,
            "connect_timeout" => &mut self.connect_timeout,
            "idle_timeout" => &mut self.idle_timeout,
            "max_lifetime" => &mut self.max_lifetime,
            "max" => &mut self.max,
            "prepare" => &mut self.prepare,
            "foundrows" => &mut self.found_rows,
            "channel_binding" => &mut self.channel_binding,
            "host" => &mut self.hostname,
            "port" => &mut self.port,
            "user" => &mut self.username,
            "password" => &mut self.password,
            "dbname" => &mut self.database,
            _ => return None,
        })
    }
}

/// libpq's keywords for its own connection that Bun reads past.
fn ignored(key: &str, value: &str) -> bool {
    match key {
        "keepalives"
        | "keepalives_idle"
        | "keepalives_interval"
        | "keepalives_count"
        | "tcp_user_timeout"
        | "target_session_attrs"
        | "load_balance_hosts"
        | "fallback_application_name"
        | "sslnegotiation"
        | "sslcompression" => true,
        "gssencmode" => value != "require",
        _ => false,
    }
}

fn read_query(url: &Url, startup: &mut Vec<(String, String)>) -> Result<Query, Refusal> {
    // URLSearchParams.toJSON(): a repeated key's values, joined by commas.
    let mut pairs: Vec<(String, Vec<String>)> = Vec::new();
    for (key, value) in url.query_pairs() {
        match pairs.iter_mut().find(|(k, _)| *k == key) {
            Some((_, values)) => values.push(value.into_owned()),
            None => pairs.push((key.into_owned(), vec![value.into_owned()])),
        }
    }
    let mut query = Query::default();
    for (key, values) in pairs {
        let value = values.join(",");
        let lower = key.to_lowercase();
        match lower.as_str() {
            "sslmode" | "ssl-mode" | "ssl_mode" => query.ssl_mode = Some(ssl_mode(&value)?),
            "ssl" | "tls" => match value.to_lowercase().as_str() {
                "true" | "1" => query.tls = true,
                "false" | "0" => query.ssl_mode = Some(SslMode::Disable),
                "" => {}
                other => query.ssl_mode = Some(ssl_mode(other)?),
            },
            "sslrootcert" | "sslcert" | "sslkey" | "sslpassword" => {
                if value.is_empty() {
                    continue;
                }
                query.tls = true;
                let files = &mut query.files;
                match lower.as_str() {
                    "sslrootcert" if value == "system" => files.system = true,
                    "sslrootcert" => files.ca_file = Some(value),
                    "sslcert" => files.cert_file = Some(value),
                    "sslkey" => files.key_file = Some(value),
                    _ => files.passphrase = Some(value),
                }
            }
            _ => {
                if let Some(slot) = query.option(&lower) {
                    if slot.is_none() && !value.is_empty() {
                        *slot = Some(value);
                    }
                } else if !ignored(&lower, &value) {
                    if key.contains('\0') || value.contains('\0') {
                        return Err("null byte");
                    }
                    set(startup, &key, value);
                }
            }
        }
    }
    Ok(query)
}

/// Sets a startup parameter; one set again keeps its place.
fn set(startup: &mut Vec<(String, String)>, key: &str, value: String) {
    match startup.iter_mut().find(|(k, _)| k == key) {
        Some((_, v)) => *v = value,
        None => startup.push((key.to_string(), value)),
    }
}

fn ssl_mode(value: &str) -> Result<SslMode, Refusal> {
    Ok(match value.to_lowercase().as_str() {
        "" | "disable" | "disabled" => SslMode::Disable,
        "allow" | "prefer" | "preferred" => SslMode::Prefer,
        "require" | "required" => SslMode::Require,
        "verify-ca" | "verify_ca" => SslMode::VerifyCa,
        "verify-full" | "verify_full" | "verify-identity" | "verify_identity" => SslMode::VerifyFull,
        _ => return Err("sslmode"),
    })
}

/// `decodeURIComponent` of a part of the URL, which Bun lets throw.
fn decode_if_valid(value: &str) -> Result<Option<String>, Refusal> {
    if value.is_empty() {
        return Ok(None);
    }
    decode_uri_component(value).map(Some).ok_or("escape")
}

/// A count of seconds, which may be fractional, below 2^31.
fn seconds(value: Option<&str>) -> Result<Option<Duration>, Refusal> {
    let Some(value) = value else { return Ok(None) };
    let seconds = js_number(value);
    if seconds.is_nan() || !(0.0..=2_147_483_648.0).contains(&seconds) {
        return Err("seconds");
    }
    Ok(Some(Duration::from_secs_f64(seconds)))
}

/// Postgres's `options`, carrying the startup parameters a client library
/// can't send under their own names: each as `-c name=value`, after the
/// `options` given, which they override as they would in the startup
/// message. A backslash escapes whitespace and itself.
pub fn options_with(options: &str, parameters: &[(&str, &str)]) -> String {
    let escape = |s: &str| {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            if matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r' | '\\') {
                out.push('\\');
            }
            out.push(c);
        }
        out
    };
    let mut out = options.to_string();
    for (name, value) in parameters {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&format!("-c {}={}", escape(name), escape(value)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    /// Milliseconds as JSON writes them: whole ones without a fraction.
    fn ms(d: Duration) -> Value {
        let ms = d.as_nanos() as f64 / 1e6;
        if ms.fract() == 0.0 {
            json!(ms as u64)
        } else {
            json!(ms)
        }
    }

    /// Bun's answer for each case: what `new SQL(url, { max: 5 }).options`
    /// holds with that environment, or that it threw.
    #[test]
    fn reads_each_recorded_case_as_bun_does() {
        let cases: Value = serde_json::from_str(include_str!("../tests/database_urls.json")).expect("the cases");
        let cases = cases.as_array().expect("a list");
        assert!(cases.len() > 50);
        for case in cases {
            let url = case["url"].as_str().expect("url");
            let env: Vec<(String, String)> = case["env"].as_object().map(|o| o.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string())).collect()).unwrap_or_default();
            let lookup = |name: &str| env.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
            let got = match parse(url, &lookup) {
                Err(_) => json!({ "refused": true }),
                Ok(s) => {
                    let mut tls = serde_json::Map::new();
                    if s.ssl_mode != SslMode::Disable {
                        for (key, value) in [("caFile", &s.tls.ca_file), ("certFile", &s.tls.cert_file), ("keyFile", &s.tls.key_file), ("passphrase", &s.tls.passphrase)] {
                            if let Some(value) = value {
                                tls.insert(key.into(), json!(value));
                            }
                        }
                        if s.tls.system {
                            tls.insert("rejectUnauthorized".into(), json!(true));
                        }
                        tls.insert("serverName".into(), json!(s.hostname));
                    }
                    json!({
                        "hostname": s.hostname,
                        "port": s.port,
                        "username": s.username,
                        "password": s.password,
                        "database": s.database,
                        "path": s.path,
                        "sslMode": s.ssl_mode as u8,
                        "tls": if s.ssl_mode == SslMode::Disable { Value::Null } else { Value::Object(tls) },
                        "startup": s.startup.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
                        "channelBinding": s.channel_binding,
                        "prepare": s.prepare,
                        "connectionTimeout": s.connect_timeout.map(ms),
                        "idleTimeout": s.idle_timeout.map(ms),
                        "maxLifetime": s.max_lifetime.map(ms),
                    })
                }
            };
            assert_eq!(got, case["bun"], "{url} with {env:?}");
        }
    }

    #[test]
    fn startup_parameters_ride_in_options() {
        assert_eq!(options_with("", &[]), "");
        assert_eq!(options_with("-c search_path=s", &[("statement_timeout", "5")]), "-c search_path=s -c statement_timeout=5");
        assert_eq!(options_with("", &[("search_path", "a b"), ("x", "back\\slash\ttab")]), "-c search_path=a\\ b -c x=back\\\\slash\\\ttab");
    }
}
