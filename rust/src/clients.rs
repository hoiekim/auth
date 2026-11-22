//! Client authentication (docs/DESIGN.md §5.1, §7.2): a confidential client
//! sends its id and secret with HTTP Basic (client_secret_basic); a public
//! client names itself in the form and proves nothing but PKCE.

use crate::app::App;
use crate::crypto::{random_token, sha256};
use crate::db::Q;
use crate::error::{Error, HttpError, Result};
use crate::http::{Params, Request};
use crate::services::Client;
use crate::util::{decode_uri_component, from_b64, js_trim, utf16_len};

fn invalid_client(basic: bool) -> Error {
    let headers = if basic { vec![("WWW-Authenticate".to_string(), "Basic realm=\"auth\"".to_string())] } else { Vec::new() };
    Error::Http(HttpError::with(401, "invalid_client", "Client authentication failed.", headers))
}

// RFC 6749 §2.3.1: the id and secret are form-encoded before Base64.
// `^Basic ([A-Za-z0-9+/=]{1,1024})$`
fn parse_basic(header: &str) -> Option<(String, String)> {
    let encoded = js_trim(header).strip_prefix("Basic ")?;
    if encoded.is_empty() || encoded.len() > 1024 || !encoded.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')) {
        return None;
    }
    let decoded = String::from_utf8_lossy(&from_b64(encoded)).into_owned();
    let (id, secret) = decoded.split_once(':')?;
    let form_decode = |s: &str| decode_uri_component(&s.replace('+', " "));
    Some((form_decode(id)?, form_decode(secret)?))
}

pub async fn check_client_secret(q: Q<'_>, client_id: &str, secret: &str) -> Result<bool> {
    if secret.is_empty() || utf16_len(secret) > 512 {
        return Ok(false);
    }
    let rows = q.query("SELECT 1 FROM client_secrets WHERE client_id = $1 AND secret_hash = $2 AND revoked_at IS NULL", &[&client_id, &sha256(secret.as_bytes())]).await?;
    Ok(rows.len() == 1)
}

/// The calling client. A confidential client must use Basic; a client secret
/// in the form body (client_secret_post) is not offered and is refused.
pub async fn authenticate_client(app: &App, req: &Request, form: Option<&Params>, allow_public: bool) -> Result<Client> {
    if let Some(header) = req.header("Authorization").filter(|h| !h.is_empty()) {
        let (id, secret) = parse_basic(&header).ok_or_else(|| invalid_client(true))?;
        let client = app.services.client(&id).filter(|c| !c.public).ok_or_else(|| invalid_client(true))?;
        if !check_client_secret(app.db(), &client.id, &secret).await? {
            return Err(invalid_client(true));
        }
        let named = match form {
            Some(f) => f.single("client_id")?,
            None => None,
        };
        if named.is_some_and(|n| n != client.id) {
            return Err(invalid_client(true));
        }
        return Ok(client.clone());
    }
    let form = form.filter(|f| allow_public && !f.has("client_secret")).ok_or_else(|| invalid_client(false))?;
    let id = form.single("client_id")?.filter(|i| !i.is_empty());
    id.and_then(|i| app.services.client(i)).filter(|c| c.public).cloned().ok_or_else(|| invalid_client(false))
}

/// A new secret for a client, shown once (§9.3). Two stay live so the app can
/// be moved to the new one: this one and the newest before it. Runs in the
/// caller's transaction, with the change's audit row.
pub async fn rotate_client_secret(q: Q<'_>, client_id: &str) -> Result<String> {
    let secret = random_token();
    q.execute(
        "UPDATE client_secrets SET revoked_at = now()
         WHERE client_id = $1 AND revoked_at IS NULL
           AND secret_hash <> ALL (SELECT secret_hash FROM client_secrets
                                   WHERE client_id = $1 AND revoked_at IS NULL
                                   ORDER BY created_at DESC LIMIT 1)",
        &[&client_id],
    )
    .await?;
    q.execute("INSERT INTO client_secrets (client_id, secret_hash) VALUES ($1, $2)", &[&client_id, &sha256(secret.as_bytes())]).await?;
    Ok(secret)
}

/// Ends a rotation: every secret but the newest stops working. Runs in the
/// caller's transaction.
pub async fn retire_old_client_secrets(q: Q<'_>, client_id: &str) -> Result<i64> {
    let rows = q
        .query(
            "UPDATE client_secrets SET revoked_at = now()
             WHERE client_id = $1 AND revoked_at IS NULL
               AND secret_hash <> ALL (SELECT secret_hash FROM client_secrets
                                       WHERE client_id = $1 AND revoked_at IS NULL
                                       ORDER BY created_at DESC LIMIT 1)
             RETURNING 1",
            &[&client_id],
        )
        .await?;
    Ok(rows.len() as i64)
}
