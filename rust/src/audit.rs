//! The audit log (docs/DESIGN.md §8): identity events, never a secret, a token
//! or a password in `detail`. Written in the same transaction as the change it
//! records.

use serde_json::{json, Value};

use crate::db::Q;
use crate::error::Result;

pub struct Audit<'a> {
    /// usr_…, cli_<service>, 'host-cli', or None for anonymous.
    pub actor: Option<&'a str>,
    pub action: &'a str,
    pub user_id: Option<&'a str>,
    pub ip: Option<&'a str>,
    pub detail: Value,
}

impl<'a> Audit<'a> {
    pub fn new(actor: Option<&'a str>, action: &'a str) -> Audit<'a> {
        Audit { actor, action, user_id: None, ip: None, detail: json!({}) }
    }

    pub fn user(mut self, user_id: Option<&'a str>) -> Audit<'a> {
        self.user_id = user_id;
        self
    }

    pub fn ip(mut self, ip: Option<&'a str>) -> Audit<'a> {
        self.ip = ip;
        self
    }

    pub fn detail(mut self, detail: Value) -> Audit<'a> {
        self.detail = detail;
        self
    }
}

pub async fn audit(q: Q<'_>, e: Audit<'_>) -> Result<()> {
    q.execute("INSERT INTO audit (actor, action, user_id, ip, detail) VALUES ($1, $2, $3, $4::text::inet, $5::text::jsonb)", &[&e.actor, &e.action, &e.user_id, &e.ip, &e.detail.to_string()]).await?;
    Ok(())
}

/// The actor recorded for a service's own client (§7.5 ★ endpoints).
pub fn client_actor(service: &str) -> String {
    format!("cli_{service}")
}
