//! The service's configuration, read from the environment once at start
//! (docs/DESIGN.md §11). Every problem is collected, so a misconfigured
//! deployment learns all of them in one restart. A message never echoes a
//! value that can carry a secret.

use url::Url;

use crate::crypto::EncryptionKey;
use crate::mail::{parse_from, parse_smtp_url, SmtpSecurity, SmtpSettings};
use crate::net::{parse_cidr, Cidr};
use crate::passwords::BREACHED_PASSWORDS_URL;
use crate::services::{is_loopback_host, parse_services, Services};
use crate::util::{from_b64, is_digits, js_trim};

pub struct Config {
    pub port: u16,
    pub database_url: String,
    /// The issuer's origin, e.g. https://auth.example.com: no path, no trailing slash.
    pub issuer: String,
    /// The services file's, when the deployment has one (docs/DESIGN.md §6.2).
    pub services: std::sync::Arc<Services>,
    /// Encrypts everything new; the others only decrypt (§9.3).
    pub encryption_key: EncryptionKey,
    pub decryption_keys: Vec<EncryptionKey>,
    pub api_key_prefix: Option<String>,
    pub trusted_proxies: Vec<Cidr>,
    pub smtp: SmtpSettings,
    pub email_from: String,
    pub audit_retention_days: i32,
    pub allow_account_deletion: bool,
    pub alert_webhook_url: Option<String>,
    /// The range API the breached-password check asks (§9.1), without a trailing slash.
    pub breached_passwords_url: String,
}

#[derive(Debug)]
pub struct ConfigError {
    pub problems: Vec<String>,
}

impl ConfigError {
    pub fn message(&self) -> String {
        format!("invalid configuration:\n{}", self.problems.iter().map(|p| format!("  - {p}")).collect::<Vec<_>>().join("\n"))
    }
}

const DEFAULT_PORT: u16 = 3000;
const DEFAULT_AUDIT_RETENTION_DAYS: i32 = 365;

// `^[a-z][a-z0-9]{1,15}$`
fn is_api_key_prefix(s: &str) -> bool {
    let b = s.as_bytes();
    (2..=16).contains(&b.len()) && b[0].is_ascii_lowercase() && b[1..].iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

pub fn load_config(env: &dyn Fn(&str) -> Option<String>, read_file: &dyn Fn(&str) -> std::io::Result<String>) -> Result<Config, ConfigError> {
    let mut problems: Vec<String> = Vec::new();
    let value = |name: &str| env(name).map(|v| js_trim(&v).to_string()).unwrap_or_default();

    let mut port = DEFAULT_PORT;
    let raw_port = value("PORT");
    if !raw_port.is_empty() {
        match is_digits(&raw_port).then(|| raw_port.parse::<u64>().ok()).flatten().filter(|p| (1..=65535).contains(p)) {
            Some(p) => port = p as u16,
            None => problems.push(format!("PORT must be a whole number from 1 to 65535, not \"{raw_port}\"")),
        }
    }

    let database_url = value("DATABASE_URL");
    if database_url.is_empty() {
        problems.push("DATABASE_URL is required".into());
    } else if !(database_url.starts_with("postgres://") || database_url.starts_with("postgresql://")) {
        problems.push("DATABASE_URL must be a postgres:// or postgresql:// URL".into());
    } else if crate::pgurl::parse(&database_url, env).is_err() {
        // Read as the pool will read it, environment included, so what it
        // can't use is reported with the other problems instead of failing
        // the start after them. Not echoed: it can hold a password.
        problems.push("DATABASE_URL is not a well-formed URL".into());
    }

    let issuer = parse_issuer(&value("ISSUER_URL"), &mut problems);

    let mut services = Services::new(Vec::new(), Vec::new());
    let services_file = value("SERVICES_FILE");
    if !services_file.is_empty() {
        match read_file(&services_file) {
            Err(_) => problems.push(format!("SERVICES_FILE \"{services_file}\" can't be read")),
            Ok(text) => {
                let parsed = parse_services(&text);
                for p in parsed.1 {
                    problems.push(format!("SERVICES_FILE: {p}"));
                }
                services = parsed.0;
            }
        }
    }

    // Neither key is ever echoed: a message names the variable and the entry.
    let mut encryption_key = EncryptionKey { version: 1, key: Vec::new() };
    let raw_key = value("AUTH_ENCRYPTION_KEY");
    if raw_key.is_empty() {
        problems.push("AUTH_ENCRYPTION_KEY is required".into());
    } else {
        match parse_key(&raw_key, false) {
            Some(k) => encryption_key = k,
            None => problems.push("AUTH_ENCRYPTION_KEY must be 32 bytes, base64-encoded (openssl rand -base64 32), optionally as v<N>:<base64>".into()),
        }
    }
    let mut decryption_keys: Vec<EncryptionKey> = Vec::new();
    let raw_others = value("AUTH_DECRYPTION_KEYS");
    for (i, entry) in raw_others.split(',').map(js_trim).filter(|s| !s.is_empty()).enumerate() {
        match parse_key(entry, true) {
            None => problems.push(format!("AUTH_DECRYPTION_KEYS entry {} must be v<N>:<32 bytes, base64>", i + 1)),
            Some(k) if k.version == encryption_key.version || decryption_keys.iter().any(|d| d.version == k.version) => {
                problems.push(format!("AUTH_DECRYPTION_KEYS entry {} has version {}, which another key already has", i + 1, k.version));
            }
            Some(k) => decryption_keys.push(k),
        }
    }

    let api_key_prefix = Some(value("API_KEY_PREFIX")).filter(|p| !p.is_empty());
    if api_key_prefix.as_deref().is_some_and(|p| !is_api_key_prefix(p)) {
        problems.push("API_KEY_PREFIX must match [a-z][a-z0-9]{1,15}".into());
    }
    if api_key_prefix.is_none() && services.all().iter().any(|s| !s.api_key_scopes.is_empty()) {
        problems.push("API_KEY_PREFIX is required when a service declares api_key_scopes".into());
    }

    let mut trusted_proxies: Vec<Cidr> = Vec::new();
    let raw_proxies = value("TRUSTED_PROXIES");
    for entry in raw_proxies.split(',').map(js_trim).filter(|s| !s.is_empty()) {
        match parse_cidr(entry) {
            Some(cidr) => trusted_proxies.push(cidr),
            None => problems.push(format!("TRUSTED_PROXIES has \"{entry}\", which is not an IP address or CIDR range")),
        }
    }

    let mut smtp = SmtpSettings { host: String::new(), port: 0, secure: SmtpSecurity::None, username: None, password: None };
    let smtp_url = value("SMTP_URL");
    if smtp_url.is_empty() {
        problems.push("SMTP_URL is required".into());
    } else {
        match parse_smtp_url(&smtp_url) {
            Ok(s) => smtp = s,
            Err(_) => problems.push("SMTP_URL must be smtps://[user:password@]host[:port], or smtp:// (STARTTLS, or plain only to a loopback host)".into()),
        }
    }

    let email_from = value("EMAIL_FROM");
    if email_from.is_empty() {
        problems.push("EMAIL_FROM is required".into());
    } else if parse_from(&email_from).is_err() {
        problems.push("EMAIL_FROM must be an address, or \"Name <address>\"".into());
    }

    let mut audit_retention_days = DEFAULT_AUDIT_RETENTION_DAYS;
    let raw_retention = value("AUDIT_RETENTION_DAYS");
    if !raw_retention.is_empty() {
        match is_digits(&raw_retention).then(|| raw_retention.parse::<u64>().ok()).flatten().filter(|d| (1..=36500).contains(d)) {
            Some(d) => audit_retention_days = d as i32,
            None => problems.push(format!("AUDIT_RETENTION_DAYS must be a whole number of days from 1 to 36500, not \"{raw_retention}\"")),
        }
    }

    let mut allow_account_deletion = false;
    let raw_deletion = value("ALLOW_ACCOUNT_DELETION");
    if raw_deletion == "true" {
        allow_account_deletion = true;
    } else if !raw_deletion.is_empty() && raw_deletion != "false" {
        problems.push("ALLOW_ACCOUNT_DELETION must be \"true\" or \"false\"".into());
    }

    // The URL can carry a token in its path (chat webhooks do), so it's never echoed.
    let mut alert_webhook_url = None;
    let raw_alert = value("ALERT_WEBHOOK_URL");
    if !raw_alert.is_empty() {
        match Url::parse(&raw_alert) {
            Ok(url) if url.scheme() == "https" || url.scheme() == "http" => alert_webhook_url = Some(raw_alert),
            _ => problems.push("ALERT_WEBHOOK_URL must be an http(s) URL".into()),
        }
    }

    let mut breached_passwords_url = BREACHED_PASSWORDS_URL.to_string();
    let raw_breached = value("BREACHED_PASSWORDS_URL");
    if !raw_breached.is_empty() {
        let ok = Url::parse(&raw_breached).is_ok_and(|url| (url.scheme() == "https" || url.scheme() == "http") && url.username().is_empty() && url.password().unwrap_or("").is_empty())
            && !raw_breached.contains(['?', '#']);
        if ok {
            breached_passwords_url = raw_breached.trim_end_matches('/').to_string();
        } else {
            problems.push("BREACHED_PASSWORDS_URL must be an http(s) URL without credentials, a query or a fragment".into());
        }
    }

    if !problems.is_empty() {
        return Err(ConfigError { problems });
    }
    Ok(Config {
        port,
        database_url,
        issuer,
        services: std::sync::Arc::new(services),
        encryption_key,
        decryption_keys,
        api_key_prefix,
        trusted_proxies,
        smtp,
        email_from,
        audit_retention_days,
        allow_account_deletion,
        alert_webhook_url,
        breached_passwords_url,
    })
}

// `v<N>:<base64>`, or a bare base64 key as version 1 where that's allowed:
// `^(?:v(\d{1,4}):)?([A-Za-z0-9+/_-]+={0,2})$`
fn parse_key(raw: &str, version_required: bool) -> Option<EncryptionKey> {
    let (version, encoded) = match raw.strip_prefix('v').and_then(|rest| rest.split_once(':')) {
        Some((digits, encoded)) if (1..=4).contains(&digits.len()) && is_digits(digits) => (Some(digits.parse::<u32>().ok()?), encoded),
        _ => (None, raw),
    };
    if version_required && version.is_none() {
        return None;
    }
    let body = encoded.trim_end_matches('=');
    let padding = encoded.len() - body.len();
    if body.is_empty() || padding > 2 || !body.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'_' | b'-')) {
        return None;
    }
    let key = from_b64(encoded);
    let version = version.unwrap_or(1);
    (version >= 1 && key.len() == 32).then_some(EncryptionKey { version, key })
}

fn parse_issuer(raw: &str, problems: &mut Vec<String>) -> String {
    if raw.is_empty() {
        problems.push("ISSUER_URL is required".into());
        return String::new();
    }
    let ok = Url::parse(raw).ok().filter(|url| {
        (url.scheme() == "https" || (url.scheme() == "http" && is_loopback_host(url.host_str().unwrap_or(""))))
            && url.username().is_empty()
            && url.password().unwrap_or("").is_empty()
            && (url.path() == "/" || url.path().is_empty())
            && url.query().unwrap_or("").is_empty()
            && url.fragment().unwrap_or("").is_empty()
            // An empty query or fragment reads as none above.
            && !raw.contains(['?', '#'])
            && !raw.ends_with('/')
    });
    match ok {
        Some(url) => url.origin().ascii_serialization(),
        None => {
            // Not echoed: a mistake here can be another variable's value, credentials included.
            problems.push("ISSUER_URL must be an https origin with no path or trailing slash (http only for a loopback host)".into());
            String::new()
        }
    }
}
