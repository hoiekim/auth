import type { SQL } from "bun";
import type { App } from "./app";
import { audit } from "./audit";
import { base32, base64url, newId, random, sha256 } from "./crypto";
import { emit } from "./events";
import { HttpError } from "./http";
import type { Service } from "./services";

// App passwords and API keys (docs/DESIGN.md §7.3, §9.1, §12.4, §12.5). Each
// has at least 80 bits, so SHA-256 is enough, and the secret alone finds its
// row. Nothing of the secret is kept or shown after it is created.

export type CredentialKind = "app_password" | "api_key";

export interface CredentialRow {
  id: string;
  kind: CredentialKind;
  service: string;
  scopes: string[];
  name: string;
  created_at: Date;
  last_used_at: Date | null;
  expires_at: Date | null;
}

export function credentialJson(c: CredentialRow) {
  return {
    id: c.id,
    name: c.name,
    service: c.service,
    scopes: c.scopes,
    created_at: c.created_at.toISOString(),
    last_used_at: c.last_used_at?.toISOString() ?? null,
    ...(c.kind === "api_key" ? { expires_at: c.expires_at?.toISOString() ?? null } : {}),
  };
}

const MAX_PER_USER = 100;
const APP_PASSWORD = /^[a-z2-7]{4}-?[a-z2-7]{4}-?[a-z2-7]{4}-?[a-z2-7]{4}$/;

// `xxxx-xxxx-xxxx-xxxx`: 16 base32 characters, 80 bits, easy to type into a
// phone. Hashed in this canonical form.
function newAppPassword(): string {
  const chars = base32(random(10));
  return chars.match(/.{4}/g)!.join("-");
}

// The hashes a presented secret could be stored under: as given (API keys,
// and keys imported from an app's own table, §12.5), and an app password
// typed without dashes or in capitals.
export function candidateHashes(secret: string): Buffer[] {
  const hashes = [sha256(secret)];
  const lower = secret.trim().toLowerCase();
  if (APP_PASSWORD.test(lower)) {
    const canonical = lower.replace(/-/g, "").match(/.{4}/g)!.join("-");
    if (canonical !== secret) hashes.push(sha256(canonical));
  }
  return hashes;
}

export function scopesOf(service: Service, kind: CredentialKind): string[] {
  return kind === "app_password" ? service.appPasswordScopes : service.apiKeyScopes;
}

export interface NewCredential {
  userId: string;
  kind: CredentialKind;
  service: Service;
  scopes: unknown;
  name: unknown;
  expiresAt?: unknown;
  actor: string;
  ip: string | null;
}

export async function createCredential(tx: SQL, app: App, c: NewCredential): Promise<{ row: CredentialRow; secret: string }> {
  const declared = scopesOf(c.service, c.kind);
  const label = c.kind === "app_password" ? "app passwords" : "API keys";
  if (declared.length === 0) throw new HttpError(400, "invalid_request", `${c.service.name} takes no ${label}.`);
  if (!Array.isArray(c.scopes) || c.scopes.length === 0 || c.scopes.some((s) => typeof s !== "string" || !declared.includes(s))) {
    throw new HttpError(400, "invalid_request", `scopes must be a non-empty list from: ${declared.join(", ")}.`);
  }
  const scopes = [...new Set(c.scopes as string[])];
  if (typeof c.name !== "string" || c.name.trim().length === 0 || [...c.name].length > 100 || /[\u0000-\u001f\u007f]/.test(c.name)) {
    throw new HttpError(400, "invalid_request", "name is 1 to 100 characters, with no control characters.");
  }
  let expiresAt: string | null = null;
  if (c.kind === "api_key" && c.expiresAt !== undefined && c.expiresAt !== null) {
    if (typeof c.expiresAt !== "string" || Number.isNaN(Date.parse(c.expiresAt)) || !/^\d{4}-\d\d-\d\dT/.test(c.expiresAt)) {
      throw new HttpError(400, "invalid_request", "expires_at must be an RFC 3339 timestamp.");
    }
    const [future] = await tx`SELECT ${c.expiresAt}::timestamptz > now() AS ok`;
    if (!future.ok) throw new HttpError(400, "invalid_request", "expires_at must be in the future.");
    expiresAt = c.expiresAt;
  }
  const [role] = await tx`SELECT 1 FROM access WHERE user_id = ${c.userId} AND service = ${c.service.name}`;
  if (!role) throw new HttpError(403, "forbidden", `You need a role on ${c.service.name} to create ${label} for it.`);
  const [count] = await tx`SELECT count(*)::int AS n FROM credentials WHERE user_id = ${c.userId} AND kind = ${c.kind} AND revoked_at IS NULL`;
  if (count.n >= MAX_PER_USER) throw new HttpError(409, "conflict", `You have ${MAX_PER_USER} ${label}; revoke one first.`);

  const id = newId(c.kind === "app_password" ? "apw" : "key");
  let secret: string;
  if (c.kind === "app_password") secret = newAppPassword();
  else {
    if (!app.config.apiKeyPrefix) throw new HttpError(500, "server_error", "API_KEY_PREFIX is not configured.");
    secret = `${app.config.apiKeyPrefix}_${id}_${base64url(random(32))}`;
  }
  const [row] = await tx`
    INSERT INTO credentials (id, user_id, kind, service, scopes, name, secret_hash, expires_at)
    VALUES (${id}, ${c.userId}, ${c.kind}, ${c.service.name}, ${tx.array(scopes, "TEXT")}, ${c.name.trim()}, ${sha256(secret)}, ${expiresAt}::timestamptz)
    RETURNING id, kind, service, scopes, name, created_at, last_used_at, expires_at`;
  await audit(tx, {
    actor: c.actor,
    action: `${c.kind}.create`,
    userId: c.userId,
    ip: c.ip,
    detail: { id, service: c.service.name, scopes },
  });
  return { row: row as CredentialRow, secret };
}

export async function listCredentials(sql: SQL, userId: string, kind: CredentialKind): Promise<CredentialRow[]> {
  return (await sql`
    SELECT id, kind, service, scopes, name, created_at, last_used_at, expires_at FROM credentials
    WHERE user_id = ${userId} AND kind = ${kind} AND revoked_at IS NULL
    ORDER BY id`) as CredentialRow[];
}

export async function revokeCredential(
  tx: SQL,
  app: App,
  userId: string,
  kind: CredentialKind,
  id: string,
  actor: string,
  ip: string | null,
): Promise<boolean> {
  const rows = await tx`
    UPDATE credentials SET revoked_at = now()
    WHERE id = ${id} AND user_id = ${userId} AND kind = ${kind} AND revoked_at IS NULL
    RETURNING service`;
  if (rows.length === 0) return false;
  await audit(tx, { actor, action: `${kind}.revoke`, userId, ip, detail: { id, service: rows[0].service } });
  await emit(tx, app, rows[0].service, "credential.revoked", { sub: userId, id });
  return true;
}

export interface Introspected {
  id: string;
  userId: string;
  username: string;
  scopes: string[];
  role: string;
}

// An active credential of the calling service only: unexpired, unrevoked, its
// owner enabled and holding a role there (§7.2). The service filter is in
// the query, so no other service's credential is ever read.
export async function introspectSecret(sql: SQL, service: string, secret: string): Promise<Introspected | null> {
  if (secret.length === 0 || secret.length > 512) return null;
  const hashes = candidateHashes(secret);
  const [row] = await sql`
    SELECT c.id, c.user_id, c.scopes, u.username, a.role,
           c.last_used_at IS NULL OR c.last_used_at < now() - interval '1 minute' AS stale
    FROM credentials c
    JOIN users u ON u.id = c.user_id
    JOIN access a ON a.user_id = c.user_id AND a.service = c.service
    WHERE c.secret_hash IN (${hashes[0]!}, ${hashes[1] ?? hashes[0]!})
      AND c.service = ${service}
      AND c.revoked_at IS NULL
      AND (c.expires_at IS NULL OR c.expires_at > now())
      AND u.disabled_at IS NULL`;
  if (!row) return null;
  if (row.stale) await sql`UPDATE credentials SET last_used_at = now() WHERE id = ${row.id}`;
  return { id: row.id, userId: row.user_id, username: row.username, scopes: row.scopes, role: row.role };
}
