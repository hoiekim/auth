import type { SQL } from "bun";
import type { App } from "./app";
import { randomToken, sha256 } from "./crypto";
import { HttpError, single } from "./http";
import type { Client } from "./services";

// Client authentication (docs/DESIGN.md §5.1, §7.2): a confidential client
// sends its id and secret with HTTP Basic (client_secret_basic); a public
// client names itself in the form and proves nothing but PKCE.

function invalidClient(basic: boolean): HttpError {
  return new HttpError(401, "invalid_client", "Client authentication failed.", basic ? { "WWW-Authenticate": 'Basic realm="auth"' } : {});
}

// RFC 6749 §2.3.1: the id and secret are form-encoded before Base64.
function parseBasic(header: string): { id: string; secret: string } | null {
  const m = /^Basic ([A-Za-z0-9+/=]{1,1024})$/.exec(header.trim());
  if (!m?.[1]) return null;
  const decoded = Buffer.from(m[1], "base64").toString("utf8");
  const colon = decoded.indexOf(":");
  if (colon < 0) return null;
  try {
    const formDecode = (s: string) => decodeURIComponent(s.replace(/\+/g, " "));
    return { id: formDecode(decoded.slice(0, colon)), secret: formDecode(decoded.slice(colon + 1)) };
  } catch {
    return null;
  }
}

export async function checkClientSecret(sql: SQL, clientId: string, secret: string): Promise<boolean> {
  if (secret.length === 0 || secret.length > 512) return false;
  const rows = await sql`
    SELECT 1 FROM client_secrets WHERE client_id = ${clientId} AND secret_hash = ${sha256(secret)} AND revoked_at IS NULL`;
  return rows.length === 1;
}

// The calling client. A confidential client must use Basic; a client secret
// in the form body (client_secret_post) is not offered and is refused.
export async function authenticateClient(app: App, req: Request, form: URLSearchParams | null, allowPublic: boolean): Promise<Client> {
  const header = req.headers.get("Authorization");
  if (header) {
    const creds = parseBasic(header);
    if (!creds) throw invalidClient(true);
    const client = app.services.client(creds.id);
    if (!client || client.type !== "confidential" || !(await checkClientSecret(app.sql, client.id, creds.secret))) {
      throw invalidClient(true);
    }
    const named = form ? single(form, "client_id") : null;
    if (named !== null && named !== client.id) throw invalidClient(true);
    return client;
  }
  if (!form || !allowPublic || form.has("client_secret")) throw invalidClient(false);
  const id = single(form, "client_id");
  const client = id ? app.services.client(id) : undefined;
  if (!client || client.type !== "public") throw invalidClient(false);
  return client;
}

// A new secret for a client, printed once by the CLI (§9.3). Two stay live
// so the app can be moved to the new one: this one and the newest before it.
// Runs in the caller's transaction, with the change's audit row.
export async function rotateClientSecret(tx: SQL, clientId: string): Promise<string> {
  const secret = randomToken();
  await tx`
    UPDATE client_secrets SET revoked_at = now()
    WHERE client_id = ${clientId} AND revoked_at IS NULL
      AND secret_hash <> ALL (SELECT secret_hash FROM client_secrets
                              WHERE client_id = ${clientId} AND revoked_at IS NULL
                              ORDER BY created_at DESC LIMIT 1)`;
  await tx`INSERT INTO client_secrets (client_id, secret_hash) VALUES (${clientId}, ${sha256(secret)})`;
  return secret;
}

// Ends a rotation: every secret but the newest stops working. Runs in the
// caller's transaction.
export async function retireOldClientSecrets(tx: SQL, clientId: string): Promise<number> {
  const rows = await tx`
    UPDATE client_secrets SET revoked_at = now()
    WHERE client_id = ${clientId} AND revoked_at IS NULL
      AND secret_hash <> ALL (SELECT secret_hash FROM client_secrets
                              WHERE client_id = ${clientId} AND revoked_at IS NULL
                              ORDER BY created_at DESC LIMIT 1)
    RETURNING 1`;
  return rows.length;
}
