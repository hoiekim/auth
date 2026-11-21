//! The services in effect (docs/DESIGN.md §6.2): the services file's, read at
//! start, and those registered on the admin page, stored here. A copy keeps
//! them in memory under the revision it loaded them at, and each request reads
//! the revision first, so no copy serves a service another has changed.

use std::sync::{Arc, Mutex};

use deadpool_postgres::Pool;
use serde_json::{json, Value};

use crate::app::{log_line, App};
use crate::audit::{audit, Audit};
use crate::db::Q;
use crate::error::{bail, http, Result};
use crate::services::{Client, Service, Services, Signup, Source};

pub struct ServiceRegistry {
    file: Vec<Service>,
    log_to_stderr: bool,
    loaded: Mutex<Option<(i64, Arc<Services>)>>,
    loading: tokio::sync::Mutex<()>,
}

impl ServiceRegistry {
    pub fn new(file: Vec<Service>, log_to_stderr: bool) -> ServiceRegistry {
        ServiceRegistry { file, log_to_stderr, loaded: Mutex::new(None), loading: tokio::sync::Mutex::new(()) }
    }

    fn loaded_at(&self, revision: i64) -> Option<Arc<Services>> {
        self.loaded.lock().unwrap().as_ref().filter(|(r, _)| *r >= revision).map(|(_, s)| s.clone())
    }

    /// The services as of now: one single-row read, and one more query when
    /// another request, on any copy, has changed them since.
    pub async fn current(&self, pool: &Pool) -> Result<Arc<Services>> {
        let q = Q::Pool(pool);
        let row = q.one("SELECT revision FROM services_revision", &[]).await?;
        let revision: i64 = row.try_get("revision")?;
        loop {
            if let Some(services) = self.loaded_at(revision) {
                return Ok(services);
            }
            // Requests that arrive while a load runs wait for it, and take
            // what it loaded unless it started before the change they saw.
            let _loading = self.loading.lock().await;
            if let Some(services) = self.loaded_at(revision) {
                return Ok(services);
            }
            let (fresh_revision, services) = self.load(q).await?;
            let services = Arc::new(services);
            let mut loaded = self.loaded.lock().unwrap();
            if loaded.as_ref().map_or(true, |(r, _)| *r < fresh_revision) {
                *loaded = Some((fresh_revision, services.clone()));
            }
            if fresh_revision >= revision {
                return Ok(services);
            }
        }
    }

    // The revision and every registered service in one statement, so they
    // come from one snapshot.
    async fn load(&self, q: Q<'_>) -> Result<(i64, Services)> {
        let rows = q
            .query(
                "SELECT r.revision, s.name, s.roles, s.mfa_roles, s.signup, s.default_role, s.manages_own_members,
                        s.api_key_scopes, s.app_password_scopes, s.events_url,
                        c.id AS client_id, c.type AS client_type, c.redirect_uris, c.post_logout_redirect_uris
                 FROM services_revision r
                 LEFT JOIN services s ON true
                 LEFT JOIN clients c ON c.service = s.name
                 ORDER BY s.created_at, s.name, c.created_at, c.id",
                &[],
            )
            .await?;
        let mut registered: Vec<Service> = Vec::new();
        for r in &rows {
            let Some(name) = r.try_get::<_, Option<String>>("name")? else { continue };
            if !registered.iter().any(|s| s.name == name) {
                registered.push(Service {
                    name: name.clone(),
                    roles: r.try_get("roles")?,
                    mfa_roles: r.try_get("mfa_roles")?,
                    signup: Signup::parse(&r.try_get::<_, String>("signup")?),
                    default_role: r.try_get("default_role")?,
                    manages_own_members: r.try_get("manages_own_members")?,
                    api_key_scopes: r.try_get("api_key_scopes")?,
                    app_password_scopes: r.try_get("app_password_scopes")?,
                    clients: Vec::new(),
                    events_url: r.try_get("events_url")?,
                    source: Source::Database,
                });
            }
            if let Some(id) = r.try_get::<_, Option<String>>("client_id")? {
                let service = registered.iter_mut().find(|s| s.name == name).unwrap();
                service.clients.push(Client {
                    id,
                    public: r.try_get::<_, String>("client_type")? == "public",
                    service: name,
                    redirect_uris: r.try_get("redirect_uris")?,
                    post_logout_redirect_uris: r.try_get("post_logout_redirect_uris")?,
                });
            }
        }
        let (services, held) = merge(&self.file, registered);
        for s in &held {
            if !self.file.iter().any(|f| f.name == s.name) {
                log_line(self.log_to_stderr, &format!("service {} is held: the services file gives one of its client ids to another service", s.name));
            }
        }
        let revision = match rows.first() {
            Some(r) => r.try_get("revision")?,
            None => 0,
        };
        Ok((revision, Services::new(services, held)))
    }
}

/// The file's services win: a registered service is held when the file
/// declares its name, or gives one of its client ids to another service.
pub fn merge(file: &[Service], registered: Vec<Service>) -> (Vec<Service>, Vec<Service>) {
    let owner = |client_id: &str| file.iter().find(|s| s.clients.iter().any(|c| c.id == client_id)).map(|s| s.name.as_str());
    let mut in_effect: Vec<Service> = file.to_vec();
    let mut held = Vec::new();
    for s in registered {
        let clash = file.iter().any(|f| f.name == s.name) || s.clients.iter().any(|c| owner(&c.id).unwrap_or(&s.name) != s.name);
        if clash {
            held.push(s);
        } else {
            in_effect.push(s);
        }
    }
    (in_effect, held)
}

// ------------------------------------------------------------------ writes
//
// Each runs in the caller's transaction, with the change's audit row, and
// starts by bumping the revision: that serializes every change to the
// services, and makes every copy reload them at its next request.

// So every copy can hold every service (§6).
const MAX_REGISTERED: i32 = 100;

async fn bump(q: Q<'_>) -> Result<()> {
    q.execute("UPDATE services_revision SET revision = revision + 1", &[]).await?;
    Ok(())
}

// A client id is free for `service` unless another service uses it: a
// registered one, held or not, or one in the file. A held copy of a file
// service keeps each of its clients' types.
async fn require_free_client_id(q: Q<'_>, current: &Services, service: &str, c: &Client) -> Result<()> {
    let row = q.first("SELECT service FROM clients WHERE id = $1", &[&c.id]).await?;
    let file_client = current.client(&c.id).filter(|in_effect| current.get(&in_effect.service).is_some_and(|s| s.source == Source::File));
    let owner: Option<String> = match row {
        Some(r) => Some(r.try_get("service")?),
        None => file_client.map(|f| f.service.clone()),
    };
    if let Some(owner) = owner.filter(|o| o != service) {
        bail!(409, "conflict", "The client id \"{}\" is used by {owner}.", c.id);
    }
    if let Some(f) = file_client.filter(|f| f.public != c.public) {
        bail!(400, "invalid_request", "The services file's client {} is {}, and a client's type can't change.", c.id, f.kind());
    }
    Ok(())
}

async fn insert_client(q: Q<'_>, service: &str, c: &Client) -> Result<()> {
    q.execute(
        "INSERT INTO clients (id, service, type, redirect_uris, post_logout_redirect_uris) VALUES ($1, $2, $3, $4, $5)",
        &[&c.id, &service, &c.kind(), &c.redirect_uris, &c.post_logout_redirect_uris],
    )
    .await?;
    Ok(())
}

/// Registers a service; held when the file declares its name (§6.2).
pub async fn insert_service(q: Q<'_>, current: &Services, s: &Service, actor: &str) -> Result<bool> {
    bump(q).await?;
    if q.first("SELECT 1 FROM services WHERE name = $1", &[&s.name]).await?.is_some() {
        bail!(409, "conflict", "A service named {} is registered already.", s.name);
    }
    let count: i32 = q.one("SELECT count(*)::int AS n FROM services", &[]).await?.try_get("n")?;
    if count >= MAX_REGISTERED {
        bail!(409, "conflict", "{MAX_REGISTERED} services are registered, the most there can be; delete one first.");
    }
    for c in &s.clients {
        require_free_client_id(q, current, &s.name, c).await?;
    }
    let held = current.get(&s.name).is_some_and(|f| f.source == Source::File);
    q.execute(
        "INSERT INTO services (name, roles, mfa_roles, signup, default_role, manages_own_members, api_key_scopes, app_password_scopes, events_url, held, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        &[&s.name, &s.roles, &s.mfa_roles, &s.signup.as_str(), &s.default_role, &s.manages_own_members, &s.api_key_scopes, &s.app_password_scopes, &s.events_url, &held, &actor],
    )
    .await?;
    for c in &s.clients {
        insert_client(q, &s.name, c).await?;
    }
    Ok(held)
}

pub struct ServiceChange {
    /// The fields of §6 that differ, by their JSON names.
    pub fields: Vec<String>,
    pub added_clients: Vec<String>,
    pub removed_clients: Vec<String>,
    /// Redirect and sign-out URIs that no client of the service had before.
    pub added_uris: Vec<String>,
}

/// Replaces a registered service's definition. Its name and its clients' ids
/// and types are fixed (§6.2).
pub async fn replace_service(q: Q<'_>, current: &Services, s: &Service) -> Result<ServiceChange> {
    bump(q).await?;
    let row = q
        .first(
            "SELECT name, roles, mfa_roles, signup, default_role, manages_own_members, api_key_scopes, app_password_scopes, events_url
             FROM services WHERE name = $1 FOR UPDATE",
            &[&s.name],
        )
        .await?
        .ok_or_else(|| http(404, "not_found", format!("There is no registered service \"{}\".", s.name)))?;
    // Locked, so no token request for one of them is half done (lock_client).
    let old_rows = q
        .query("SELECT id, type, redirect_uris, post_logout_redirect_uris FROM clients WHERE service = $1 ORDER BY created_at, id FOR UPDATE", &[&s.name])
        .await?;
    let mut old_clients: Vec<Client> = Vec::new();
    for r in &old_rows {
        old_clients.push(Client {
            id: r.try_get("id")?,
            public: r.try_get::<_, String>("type")? == "public",
            service: s.name.clone(),
            redirect_uris: r.try_get("redirect_uris")?,
            post_logout_redirect_uris: r.try_get("post_logout_redirect_uris")?,
        });
    }

    for c in &s.clients {
        match old_clients.iter().find(|o| o.id == c.id) {
            None => require_free_client_id(q, current, &s.name, c).await?,
            Some(old) if old.public != c.public => {
                bail!(400, "invalid_request", "A client's type can't change: add a {} client with a new id, and remove {}.", c.kind(), c.id)
            }
            Some(_) => {}
        }
    }

    let old_roles: Vec<String> = row.try_get("roles")?;
    let removed_roles: Vec<String> = old_roles.iter().filter(|r| !s.roles.contains(r)).cloned().collect();
    if !removed_roles.is_empty() {
        require_unused(q, &s.name, &removed_roles).await?;
    }

    q.execute(
        "UPDATE services SET roles = $2, mfa_roles = $3, signup = $4, default_role = $5, manages_own_members = $6, api_key_scopes = $7,
           app_password_scopes = $8, events_url = $9, updated_at = now()
         WHERE name = $1",
        &[&s.name, &s.roles, &s.mfa_roles, &s.signup.as_str(), &s.default_role, &s.manages_own_members, &s.api_key_scopes, &s.app_password_scopes, &s.events_url],
    )
    .await?;
    let removed_clients: Vec<String> = old_clients.iter().filter(|o| !s.clients.iter().any(|c| c.id == o.id)).map(|o| o.id.clone()).collect();
    for id in &removed_clients {
        retire_client(q, id).await?;
        q.execute("DELETE FROM clients WHERE id = $1", &[id]).await?;
    }
    let mut added_clients = Vec::new();
    for c in &s.clients {
        match old_clients.iter().find(|o| o.id == c.id) {
            Some(old) => {
                q.execute("UPDATE clients SET redirect_uris = $2, post_logout_redirect_uris = $3 WHERE id = $1", &[&c.id, &c.redirect_uris, &c.post_logout_redirect_uris]).await?;
                // A code issued for a URI that's gone goes with it.
                let dropped: Vec<String> = old.redirect_uris.iter().filter(|u| !c.redirect_uris.contains(u)).cloned().collect();
                if !dropped.is_empty() {
                    q.execute("DELETE FROM auth_codes WHERE client_id = $1 AND redirect_uri = ANY($2)", &[&c.id, &dropped]).await?;
                }
            }
            None => {
                insert_client(q, &s.name, c).await?;
                added_clients.push(c.id.clone());
            }
        }
    }

    let known: Vec<&String> = old_clients.iter().flat_map(|c| c.redirect_uris.iter().chain(c.post_logout_redirect_uris.iter())).collect();
    let mut added_uris: Vec<String> = Vec::new();
    for u in s.clients.iter().flat_map(|c| c.redirect_uris.iter().chain(c.post_logout_redirect_uris.iter())) {
        if !known.contains(&u) && !added_uris.contains(u) {
            added_uris.push(u.clone());
        }
    }
    let clients_json = |clients: &[Client]| -> Value { clients.iter().map(|c| json!([c.id, c.kind(), c.redirect_uris, c.post_logout_redirect_uris])).collect() };
    let was = [
        ("roles", json!(old_roles)),
        ("mfa_roles", json!(row.try_get::<_, Vec<String>>("mfa_roles")?)),
        ("signup", json!(row.try_get::<_, String>("signup")?)),
        ("default_role", json!(row.try_get::<_, Option<String>>("default_role")?)),
        ("manages_own_members", json!(row.try_get::<_, bool>("manages_own_members")?)),
        ("api_key_scopes", json!(row.try_get::<_, Vec<String>>("api_key_scopes")?)),
        ("app_password_scopes", json!(row.try_get::<_, Vec<String>>("app_password_scopes")?)),
        ("events_url", json!(row.try_get::<_, Option<String>>("events_url")?)),
        ("clients", clients_json(&old_clients)),
    ];
    let is = [
        json!(s.roles),
        json!(s.mfa_roles),
        json!(s.signup.as_str()),
        json!(s.default_role),
        json!(s.manages_own_members),
        json!(s.api_key_scopes),
        json!(s.app_password_scopes),
        json!(s.events_url),
        clients_json(&s.clients),
    ];
    let fields = was.iter().zip(is.iter()).filter(|((_, before), after)| before != *after).map(|((name, _), _)| name.to_string()).collect();
    Ok(ServiceChange { fields, added_clients, removed_clients, added_uris })
}

// A role leaves a service only when no one holds it and no pending
// invitation offers it: a row with an undeclared role escapes mfa_roles.
async fn require_unused(q: Q<'_>, service: &str, roles: &[String]) -> Result<()> {
    let holders = q.query("SELECT role, count(*)::int AS n FROM access WHERE service = $1 AND role = ANY($2) GROUP BY role ORDER BY role", &[&service, &roles]).await?;
    let invited = q
        .query(
            "SELECT role, count(*)::int AS n FROM invites
             WHERE service = $1 AND role = ANY($2) AND accepted_at IS NULL AND expires_at > now()
             GROUP BY role ORDER BY role",
            &[&service, &roles],
        )
        .await?;
    let mut uses: Vec<String> = Vec::new();
    for h in &holders {
        let (role, n): (String, i32) = (h.try_get("role")?, h.try_get("n")?);
        uses.push(format!("{n} {} \"{role}\"", if n == 1 { "user holds" } else { "users hold" }));
    }
    for i in &invited {
        let (role, n): (String, i32) = (i.try_get("role")?, i.try_get("n")?);
        uses.push(format!("{n} pending {} \"{role}\"", if n == 1 { "invitation offers" } else { "invitations offer" }));
    }
    if !uses.is_empty() {
        bail!(409, "conflict", "A role still in use can't be removed: {}. Change their roles or delete the invitations first.", uses.join(", "));
    }
    Ok(())
}

/// Deletes a registered service (§6.2). What is keyed by its name or its
/// client ids goes with it, unless the file uses that name or id: then the
/// row was a held copy, and those belong to the file's service. Answers
/// whether it was a held copy.
pub async fn delete_service(q: Q<'_>, current: &Services, name: &str) -> Result<bool> {
    bump(q).await?;
    if q.first("SELECT name FROM services WHERE name = $1 FOR UPDATE", &[&name]).await?.is_none() {
        bail!(404, "not_found", "There is no registered service \"{name}\".");
    }
    let clients = q.query("SELECT id FROM clients WHERE service = $1 ORDER BY id FOR UPDATE", &[&name]).await?;
    let file_owns = |id: &str| current.client(id).and_then(|c| current.get(&c.service)).is_some_and(|s| s.source == Source::File);
    let source = current.get(name).map(|s| s.source);
    if source != Some(Source::File) {
        q.execute("DELETE FROM access WHERE service = $1", &[&name]).await?;
        q.execute("DELETE FROM invites WHERE service = $1", &[&name]).await?;
        q.execute("UPDATE credentials SET revoked_at = now() WHERE service = $1 AND revoked_at IS NULL", &[&name]).await?;
        q.execute("DELETE FROM outbox WHERE service = $1 AND delivered_at IS NULL AND failed_at IS NULL", &[&name]).await?;
    }
    for c in &clients {
        let id: String = c.try_get("id")?;
        if !file_owns(&id) {
            retire_client(q, &id).await?;
        }
    }
    q.execute("DELETE FROM services WHERE name = $1", &[&name]).await?;
    Ok(source != Some(Source::Database))
}

// A client that goes leaves nothing a later client of the same id could use.
async fn retire_client(q: Q<'_>, id: &str) -> Result<()> {
    q.execute("UPDATE client_secrets SET revoked_at = now() WHERE client_id = $1 AND revoked_at IS NULL", &[&id]).await?;
    q.execute("UPDATE refresh_tokens SET revoked_at = now() WHERE client_id = $1 AND revoked_at IS NULL", &[&id]).await?;
    q.execute("DELETE FROM auth_codes WHERE client_id = $1", &[&id]).await?;
    Ok(())
}

/// What a copy can't serve under its configuration, checked at start: a
/// registered service with API key scopes needs API_KEY_PREFIX (§6.2).
pub async fn registered_problems(q: Q<'_>, api_key_prefix: Option<&str>) -> Result<Vec<String>> {
    if api_key_prefix.is_some() {
        return Ok(Vec::new());
    }
    let rows = q.query("SELECT name FROM services WHERE api_key_scopes <> '{}' ORDER BY name", &[]).await?;
    let mut out = Vec::new();
    for r in &rows {
        out.push(format!("API_KEY_PREFIX is required: the registered service {} declares api_key_scopes", r.try_get::<_, String>("name")?));
    }
    Ok(out)
}

/// At start: remembers which registered services this copy holds, and audits
/// and alerts each held copy it finds in effect, naming its redirect URIs
/// (§6.2). Copies starting at once each update different rows, so each
/// take-over is reported once.
pub async fn note_held(app: &App) -> Result<Vec<String>> {
    let current = app.prepare().await?;
    let held: Vec<String> = current.services.held.iter().map(|s| s.name.clone()).collect();
    let in_effect: Vec<Arc<Service>> = current.services.all().iter().filter(|s| s.source == Source::Database).cloned().collect();
    let tx = app.begin().await?;
    let work = async {
        let q = tx.q();
        if !held.is_empty() {
            q.execute("UPDATE services SET held = true WHERE name = ANY($1) AND NOT held", &[&held]).await?;
        }
        if in_effect.is_empty() {
            return Ok(Vec::new());
        }
        let names: Vec<String> = in_effect.iter().map(|s| s.name.clone()).collect();
        let rows = q.query("UPDATE services SET held = false WHERE name = ANY($1) AND held RETURNING name", &[&names]).await?;
        let mut took_effect: Vec<String> = Vec::new();
        for r in &rows {
            took_effect.push(r.try_get("name")?);
        }
        let mut reported = Vec::new();
        for s in in_effect.iter().filter(|s| took_effect.contains(&s.name)) {
            let uris = redirect_uris_of(s);
            audit(q, Audit::new(None, "service.held_copy_in_effect").detail(json!({ "service": s.name, "redirect_uris": uris }))).await?;
            let (app, name) = (app.clone(), s.name.clone());
            tx.after(move || {
                let listed = if uris.is_empty() { "none".to_string() } else { uris.join(", ") };
                app.alert(format!("auth: the held copy of the service {name} took effect, the services file no longer declaring it; redirect URIs: {listed}"));
            });
            reported.push(s.name.clone());
        }
        Ok(reported)
    }
    .await;
    tx.finish(work).await
}

pub fn redirect_uris_of(s: &Service) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for u in s.clients.iter().flat_map(|c| c.redirect_uris.iter().chain(c.post_logout_redirect_uris.iter())) {
        if !out.contains(u) {
            out.push(u.clone());
        }
    }
    out
}

// ------------------------------------------------------------------- locks
//
// A request loaded its services when it started; a registered one may have
// changed or gone since. Its row, read again and locked until commit, is what
// a grant, an invitation or a credential is checked against, and a change
// waits for those to commit, or they for it. The file's services can't change
// while the process runs.

pub async fn lock_service(q: Q<'_>, service: &Service) -> Result<Service> {
    if service.source != Source::Database {
        return Ok(service.clone());
    }
    let row = q
        .first("SELECT roles, mfa_roles, signup, default_role, api_key_scopes, app_password_scopes FROM services WHERE name = $1 FOR SHARE", &[&service.name])
        .await?
        .ok_or_else(|| http(404, "not_found", format!("There is no service \"{}\".", service.name)))?;
    Ok(Service {
        roles: row.try_get("roles")?,
        mfa_roles: row.try_get("mfa_roles")?,
        signup: Signup::parse(&row.try_get::<_, String>("signup")?),
        default_role: row.try_get("default_role")?,
        api_key_scopes: row.try_get("api_key_scopes")?,
        app_password_scopes: row.try_get("app_password_scopes")?,
        ..service.clone()
    })
}

/// Taken first in a token grant's transaction, before any refresh-token lock,
/// so a client's removal can't deadlock with a grant: either the grant
/// commits first and the removal revokes what it issued, or the grant finds
/// the client gone.
pub async fn lock_client(q: Q<'_>, service: &Service, client: &Client) -> Result<()> {
    if service.source != Source::Database {
        return Ok(());
    }
    if q.first("SELECT 1 FROM clients WHERE id = $1 AND service = $2 FOR SHARE", &[&client.id, &service.name]).await?.is_none() {
        bail!(401, "invalid_client", "Client authentication failed.");
    }
    Ok(())
}
