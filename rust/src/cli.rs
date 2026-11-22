//! The break-glass CLI (docs/DESIGN.md §9.6), run inside a running auth
//! container by whoever can reach it, so it works whichever copy is up. It
//! needs no sign-in. Every action is audited as `host-cli` and posted to the
//! alert webhook.

use std::collections::HashMap;

use serde_json::{json, Value};
use tokio::io::AsyncReadExt;

use crate::access::{put_access, Grant};
use crate::app::{post_alert, App};
use crate::audit::{audit, Audit};
use crate::clients::{retire_old_client_secrets, rotate_client_secret};
use crate::emails::{activation_email, reset_email, security_notice};
use crate::error::Error;
use crate::imports::{import_api_keys, import_users};
use crate::keys::rotate_keys;
use crate::mail::{MailMessage, Mailer};
use crate::migrate::migrate;
use crate::registry::lock_client;
use crate::rekey::{encryption_status, reencrypt};
use crate::sessions::end_user_sessions;
use crate::tokens::{issue_token, Purpose};
use crate::users::{check_email, check_name, check_username, find_user_by_login, insert_user, set_disabled, NewUser, UserRow};

const ACTOR: &str = "host-cli";

/// How the CLI is called, as its own messages name it.
pub const NAME: &str = "auth cli";

fn help() -> String {
    format!(
        "usage: {NAME} <command>

  user create --username <name> --email <address> [--name <name>] [--access <service>:<role>]... [--print-link]
  user create --username <name> --bot --owner <username> [--name <name>] [--access <service>:<role>]...
      Creates a user. A person gets an activation link by email, or printed
      here with --print-link.
  user clear-mfa <username>      Removes TOTP, passkeys and recovery codes, and signs the user out.
  user disable <username>        Disables the user everywhere.
  user enable <username>         Re-enables a disabled user.
  user reset-link <username> [--print-link]
      Sends a password reset link, or prints it.
  client secret <client id>      Prints a new secret for a confidential client, once. The
                                 previous secret keeps working until retire-old-secrets.
  client retire-old-secrets <client id>
  encryption status              Counts TOTP secrets and signing keys per encryption key version.
  encryption reencrypt           Rewrites them all under AUTH_ENCRYPTION_KEY (a key rotation's
                                 third step, docs/DESIGN.md §9.3).
  import users <file | -> [--dry-run] [--print-links]
      Creates users from JSON Lines: {{\"username\", \"email\", \"name\"?, \"email_verified\"?,
      \"password_hash\"? (argon2 or bcrypt), \"access\"? {{\"<service>\": \"<role>\"}}}}. Users without
      a password hash get an activation link by email, or printed with --print-links.
  import api-keys --service <name> <file | -> [--dry-run]
      Adds an app's existing API keys from JSON Lines: {{\"owner\" (sub or username), \"sha256\",
      \"scopes\", \"name\"?, \"expires_at\"?, \"revoked_at\"?, \"created_at\"?, \"last_used_at\"?}}.
      Both imports check every line first and write all or nothing; - reads standard input.
  migrate                        Applies pending migrations (the server does this at start).
"
    )
}

/// A mistake in how the command was given: reported as `error: …`, exit 2.
struct Usage(String);

enum Failure {
    Usage(Usage),
    Other(Error),
}

impl From<Usage> for Failure {
    fn from(u: Usage) -> Failure {
        Failure::Usage(u)
    }
}

impl From<Error> for Failure {
    fn from(e: Error) -> Failure {
        Failure::Other(e)
    }
}

fn usage<T>(message: impl Into<String>) -> std::result::Result<T, Failure> {
    Err(Failure::Usage(Usage(message.into())))
}

// Refused as it is read, before more is buffered: the CLI shares the
// server's container (§10). Ten thousand lines fit well inside it.
const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;

async fn read_input(path: &str) -> std::result::Result<String, Failure> {
    let cant_read = || Failure::Usage(Usage(format!("can't read {path}")));
    let mut bytes = Vec::new();
    let capped = (MAX_INPUT_BYTES + 1) as u64;
    if path == "-" {
        tokio::io::stdin().take(capped).read_to_end(&mut bytes).await.map_err(|_| cant_read())?;
    } else {
        let file = tokio::fs::File::open(path).await.map_err(|_| cant_read())?;
        if !file.metadata().await.map_err(|_| cant_read())?.is_file() {
            return Err(cant_read());
        }
        file.take(capped).read_to_end(&mut bytes).await.map_err(|_| cant_read())?;
    }
    if bytes.len() > MAX_INPUT_BYTES {
        return usage("the input is larger than 8 MB; split it");
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

struct Args {
    positional: Vec<String>,
    flags: HashMap<String, Vec<String>>,
}

const BOOLEAN_FLAGS: [&str; 4] = ["bot", "print-link", "print-links", "dry-run"];

fn parse(argv: &[String]) -> std::result::Result<Args, Usage> {
    let mut args = Args { positional: Vec::new(), flags: HashMap::new() };
    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        i += 1;
        let Some(name) = arg.strip_prefix("--") else {
            args.positional.push(arg.clone());
            continue;
        };
        let value = if BOOLEAN_FLAGS.contains(&name) {
            "true".to_string()
        } else {
            let value = argv.get(i).cloned().ok_or_else(|| Usage(format!("--{name} needs a value")))?;
            i += 1;
            value
        };
        args.flags.entry(name.to_string()).or_default().push(value);
    }
    Ok(args)
}

impl Args {
    fn has(&self, name: &str) -> bool {
        self.flags.contains_key(name)
    }

    fn one(&self, name: &str) -> std::result::Result<Option<&str>, Failure> {
        match self.flags.get(name).map(Vec::as_slice) {
            Some([_, _, ..]) => usage(format!("--{name} is given twice")),
            Some([value]) => Ok(Some(value)),
            _ => Ok(None),
        }
    }
}

struct Cli {
    app: App,
    mailer: Mailer,
}

impl Cli {
    fn out(&self, line: &str) {
        println!("{line}");
    }

    async fn user_named(&self, username: Option<&str>) -> std::result::Result<UserRow, Failure> {
        let Some(username) = username.filter(|u| !u.is_empty()) else { return usage("name the user") };
        match find_user_by_login(self.app.db(), username).await? {
            Some(user) => Ok(user),
            None => usage(format!("no user \"{username}\"")),
        }
    }

    async fn send(&self, msg: MailMessage, username: &str) {
        match self.mailer.send(&msg).await {
            Ok(()) => self.out(&format!("emailed {}", msg.to)),
            Err(e) => self.out(&format!("the email to {} failed ({}); print a link instead with: {NAME} user reset-link {username} --print-link", msg.to, e.0)),
        }
    }

    async fn alert(&self, text: &str) {
        if let Some(url) = &self.app.config.alert_webhook_url {
            post_alert(&self.app.http, url, &format!("auth (break-glass CLI): {text}"), |line| self.out(line)).await;
        }
    }

    async fn run(&self, args: &Args) -> std::result::Result<u8, Failure> {
        let group = args.positional.first().map(String::as_str);
        let command = args.positional.get(1).map(String::as_str);
        let target = args.positional.get(2).map(String::as_str);
        // The services as they are now, the registered ones included.
        let app = if matches!(group, Some("user" | "client" | "import")) { self.app.prepare().await? } else { self.app.clone() };
        let app = &app;
        let issuer = &app.config.issuer;

        match (group, command) {
            (Some("user"), Some("create")) => {
                let flag = |name: &str| -> std::result::Result<Option<Value>, Failure> { Ok(args.one(name)?.map(|v| json!(v))) };
                let username = check_username(flag("username")?.as_ref())?;
                let name = check_name(flag("name")?.as_ref())?;
                let bot = args.has("bot");
                let email = if bot { None } else { Some(check_email(flag("email")?.as_ref())?) };
                let owner = if bot { Some(self.user_named(args.one("owner")?).await?) } else { None };
                if owner.as_ref().is_some_and(|o| !o.is_person()) {
                    return usage("a bot's owner is a person");
                }
                let mut grants = Vec::new();
                for g in args.flags.get("access").map(Vec::as_slice).unwrap_or(&[]) {
                    let mut parts = g.split(':');
                    let service = parts.next().filter(|s| !s.is_empty()).and_then(|s| app.services.get(s));
                    let role = parts.next().filter(|r| !r.is_empty());
                    match (service, role, parts.next()) {
                        (Some(service), Some(role), None) if service.has_role(role) => grants.push((service.clone(), role.to_string())),
                        _ => return usage(format!("--access {g}: use <service>:<role> with a role the service declares")),
                    }
                }
                let kind = if bot { "bot" } else { "person" };
                let tx = app.begin().await?;
                let work = async {
                    let new = NewUser { username: &username, name: &name, email: email.as_deref(), email_verified: false, kind, owner_id: owner.as_ref().map(|o| o.id.as_str()), password_hash: None };
                    let id = insert_user(tx.q(), &new).await?;
                    audit(tx.q(), Audit::new(Some(ACTOR), "user.create").user(Some(&id)).detail(json!({ "username": username, "kind": kind }))).await?;
                    for (service, role) in &grants {
                        put_access(&tx, app, &Grant { user_id: &id, service, role, actor: ACTOR, ip: None, reason: None, never_lower: false }).await?;
                    }
                    let token = match &email {
                        Some(email) => Some(issue_token(tx.q(), Purpose::Activate, &id, Some(email)).await?),
                        None => None,
                    };
                    Ok((id, token))
                }
                .await;
                let (id, token) = tx.finish(work).await?;
                self.out(&format!("created {username} ({id})"));
                if let (Some(email), Some(token)) = (&email, &token) {
                    if args.has("print-link") {
                        self.out(&format!("activation link (works once, 14 days): {issuer}/activate?token={token}"));
                    } else {
                        self.send(activation_email(issuer, email, &username, token), &username).await;
                    }
                }
                let with = if grants.is_empty() { String::new() } else { format!(" with {}", grants.iter().map(|(s, r)| format!("{}:{r}", s.name)).collect::<Vec<_>>().join(", ")) };
                self.alert(&format!("created {username}{with}")).await;
                Ok(0)
            }

            (Some("user"), Some("clear-mfa")) => {
                let user = self.user_named(target).await?;
                let tx = app.begin().await?;
                let work = async {
                    let q = tx.q();
                    q.execute("DELETE FROM totp WHERE user_id = $1", &[&user.id]).await?;
                    q.execute("DELETE FROM passkeys WHERE user_id = $1", &[&user.id]).await?;
                    q.execute("DELETE FROM recovery_codes WHERE user_id = $1", &[&user.id]).await?;
                    end_user_sessions(q, app, &user.id, None).await?;
                    audit(q, Audit::new(Some(ACTOR), "mfa.cleared").user(Some(&user.id))).await
                }
                .await;
                tx.finish(work).await?;
                self.out(&format!("cleared the second factors of {} and signed them out", user.username));
                if let Some(email) = user.email.as_deref().filter(|e| !e.is_empty()) {
                    self.send(security_notice(email, &user.username, "two-factor authentication was cleared by an administrator", None), &user.username).await;
                }
                self.alert(&format!("cleared the MFA of {}", user.username)).await;
                Ok(0)
            }

            (Some("user"), Some(verb @ ("disable" | "enable"))) => {
                let user = self.user_named(target).await?;
                let tx = app.begin().await?;
                let work = set_disabled(tx.q(), app, &user, verb == "disable", Some(ACTOR), None).await;
                tx.finish(work).await?;
                self.out(&format!("{verb}d {}", user.username));
                self.alert(&format!("{verb}d {}", user.username)).await;
                Ok(0)
            }

            (Some("user"), Some("reset-link")) => {
                let user = self.user_named(target).await?;
                if !user.is_person() {
                    return usage("a bot user has no password");
                }
                let email = user.email.clone().filter(|e| !e.is_empty());
                if email.is_none() && !args.has("print-link") {
                    return usage("the user has no email address; use --print-link");
                }
                let tx = app.begin().await?;
                let work = async {
                    let token = issue_token(tx.q(), Purpose::Reset, &user.id, email.as_deref()).await?;
                    audit(tx.q(), Audit::new(Some(ACTOR), "reset.sent").user(Some(&user.id))).await?;
                    Ok(token)
                }
                .await;
                let token = tx.finish(work).await?;
                match email {
                    Some(email) if !args.has("print-link") => self.send(reset_email(issuer, &email, &token), &user.username).await,
                    _ => self.out(&format!("reset link (works once, 30 minutes): {issuer}/reset/confirm?token={token}")),
                }
                self.alert(&format!("made a reset link for {}", user.username)).await;
                Ok(0)
            }

            (Some("client"), Some(verb @ ("secret" | "retire-old-secrets"))) => {
                let Some(client) = target.and_then(|t| app.services.client(t)).filter(|c| !c.public).cloned() else { return usage("name a confidential client") };
                let service = app.services.get(&client.service).ok_or(Error::Other("ServiceError"))?.clone();
                let tx = app.begin().await?;
                if verb == "secret" {
                    let work = async {
                        // A registered client removed since the services were read gets
                        // no secret that a client registered later under its id would
                        // inherit (§6.2): client_secrets has no foreign key to clients.
                        lock_client(tx.q(), &service, &client).await?;
                        let secret = rotate_client_secret(tx.q(), &client.id).await?;
                        audit(tx.q(), Audit::new(Some(ACTOR), "client.secret").detail(json!({ "client": client.id }))).await?;
                        Ok(secret)
                    }
                    .await;
                    let secret = tx.finish(work).await?;
                    self.out(&secret);
                    self.alert(&format!("made a new secret for the client {}", client.id)).await;
                } else {
                    let work = async {
                        lock_client(tx.q(), &service, &client).await?;
                        let retired = retire_old_client_secrets(tx.q(), &client.id).await?;
                        audit(tx.q(), Audit::new(Some(ACTOR), "client.secret_retire").detail(json!({ "client": client.id, "retired": retired }))).await?;
                        Ok(retired)
                    }
                    .await;
                    let retired = tx.finish(work).await?;
                    self.out(&format!("retired {retired} old secret(s) of {}", client.id));
                    self.alert(&format!("retired the old secrets of the client {}", client.id)).await;
                }
                Ok(0)
            }

            (Some("encryption"), Some("status")) => {
                for c in encryption_status(&app.pool, &app.crypt).await? {
                    let mut counts: Vec<String> = c.by_version.iter().map(|(v, n)| format!("v{v}: {n}")).collect();
                    // A value with no version prefix names no key at all.
                    if c.unversioned > 0 {
                        counts.push(format!("no version: {}", c.unversioned));
                    }
                    let counts = if counts.is_empty() { "none".to_string() } else { counts.join(", ") };
                    let unreadable = if c.unreadable > 0 { format!(" ({} no configured key can read)", c.unreadable) } else { String::new() };
                    self.out(&format!("{}: {counts}{unreadable}", c.label));
                }
                self.out(&format!("AUTH_ENCRYPTION_KEY is v{}", app.crypt.version()));
                Ok(0)
            }

            (Some("encryption"), Some("reencrypt")) => {
                let version = app.crypt.version();
                let results = reencrypt(&app.pool, &app.crypt).await?;
                let failed: Vec<String> = results.iter().flat_map(|r| r.failed.iter().map(|id| format!("{}: {id}", r.label))).collect();
                for r in &results {
                    self.out(&format!("{}: {} rewritten under v{version}, {} already were", r.label, r.rewritten, r.current));
                }
                for f in &failed {
                    self.out(&format!("no configured key reads {f}; left as it was"));
                }
                let rewritten: usize = results.iter().map(|r| r.rewritten).sum();
                audit(app.db(), Audit::new(Some(ACTOR), "encryption.reencrypt").detail(json!({ "version": version, "rewritten": rewritten, "failed": failed.len() }))).await?;
                let unreadable = if failed.is_empty() { String::new() } else { format!("; {} unreadable", failed.len()) };
                self.alert(&format!("re-encrypted {rewritten} values under key v{version}{unreadable}")).await;
                Ok(if failed.is_empty() { 0 } else { 1 })
            }

            (Some("import"), Some(what @ ("users" | "api-keys"))) => {
                let Some(target) = target else { return usage("name the input file, or - for standard input") };
                let text = read_input(target).await?;
                let dry_run = args.has("dry-run");
                let (problems, count) = if what == "users" {
                    let (problems, rows) = import_users(app, &text, dry_run).await?;
                    for u in &rows {
                        let Some(activation) = &u.activation else { continue };
                        if args.has("print-links") {
                            self.out(&format!("{}: {issuer}/activate?token={activation}", u.username));
                        } else {
                            self.send(activation_email(issuer, &u.email, &u.username, activation), &u.username).await;
                        }
                    }
                    (problems, rows.len())
                } else {
                    let Some(service) = args.one("service")?.and_then(|name| app.services.get(name)).cloned() else { return usage("--service must name a service") };
                    import_api_keys(app, &service, &text, dry_run).await?
                };
                for problem in &problems {
                    self.out(problem);
                }
                if !problems.is_empty() {
                    self.out(&format!("nothing imported: {} problem(s)", problems.len()));
                    return Ok(1);
                }
                if dry_run {
                    self.out("every line passed; nothing written (--dry-run)");
                    return Ok(0);
                }
                let what = if what == "users" { "users" } else { "API keys" };
                self.out(&format!("imported {count} {what}"));
                self.alert(&format!("imported {count} {what}")).await;
                Ok(0)
            }

            (Some("migrate"), _) => {
                migrate(&app.pool, |line| self.out(line)).await?;
                self.out("migrations are up to date");
                Ok(0)
            }

            _ => {
                println!("{}", help());
                Ok(if matches!(group, Some("help") | None) { 0 } else { 2 })
            }
        }
    }
}

pub async fn main(argv: &[String]) -> u8 {
    let config = match crate::config_from_environment() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("{}", e.message());
            return 1;
        }
    };
    let (pool, mailer) = match (crate::db::connect(&config.database_url), Mailer::new(config.smtp.clone(), &config.email_from)) {
        (Ok(pool), Ok(mailer)) => (pool, mailer),
        _ => {
            eprintln!("invalid configuration");
            return 1;
        }
    };
    let app = App::new(config, pool, mailer.clone(), true);
    let cli = Cli { app: app.clone(), mailer };
    let outcome: std::result::Result<u8, Failure> = async {
        // Before any command but help and migrate: the schema, and a signing
        // key that is due, as the server sees to at start.
        if !matches!(argv.first().map(String::as_str), Some("migrate" | "help") | None) {
            migrate(&app.pool, |_| {}).await?;
            rotate_keys(&app.pool, &app.crypt).await?;
        }
        let args = match parse(argv) {
            Ok(args) => args,
            Err(u) => {
                print!("{}\n\n{}\n", u.0, help());
                return Ok(2);
            }
        };
        cli.run(&args).await
    }
    .await;
    let code = match outcome {
        Ok(code) => code,
        Err(Failure::Usage(u)) => {
            println!("error: {}", u.0);
            2
        }
        Err(Failure::Other(Error::Http(e))) => {
            println!("error: {}", e.description);
            1
        }
        Err(Failure::Other(e)) => {
            eprintln!("error: {}", e.name());
            1
        }
    };
    // Alerts a command's changes raised go out before the process ends; each
    // gives up after five seconds.
    app.drain_alerts().await;
    app.pool.close();
    code
}
