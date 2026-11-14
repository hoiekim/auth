import type { SQL } from "bun";
import type { App } from "./app";
import { newId, randomToken, sha256 } from "./crypto";
import { emit, emitSessionEnded } from "./events";
import { clearCookie, fromIssuer, hostCookie, HttpError, setCookie } from "./http";

// SSO sessions at the issuer (docs/DESIGN.md §9.2). The cookie holds 32
// random bytes and only their SHA-256 is stored. A session lasts 7 days idle
// and 30 days absolute; its token is replaced at every sign-in and step-up.

export const COOKIE = "auth";
const IDLE_DAYS = 7;
const ABSOLUTE_DAYS = 30;
// Changing a credential needs a full sign-in this recent (§7.5).
export const REAUTH_SECONDS = 15 * 60;

export interface Session {
  id: string;
  token: string;
  userId: string;
  username: string;
  name: string;
  email: string | null;
  emailVerified: boolean;
  amr: string[];
  // Seconds since the last full sign-in, by the database's clock.
  authAge: number;
  authTime: number;
}

export function hasMfa(session: { amr: string[] }): boolean {
  return session.amr.includes("mfa");
}

export async function loadSession(app: App, req: Request): Promise<Session | null> {
  const token = hostCookie(req, COOKIE);
  if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
  const [row] = await app.sql`
    SELECT s.id, s.user_id, s.amr,
           extract(epoch FROM now() - s.auth_time)::int AS auth_age,
           extract(epoch FROM s.auth_time)::bigint AS auth_time,
           s.last_seen_at < now() - interval '1 minute' AS stale,
           u.username, u.name, u.email, u.email_verified_at IS NOT NULL AS email_verified
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ${sha256(token)} AND s.expires_at > now() AND s.ends_at > now()
      AND u.disabled_at IS NULL AND u.kind = 'person'`;
  if (!row) return null;
  if (row.stale) await touch(app.sql, row.id);
  return {
    id: row.id,
    token,
    userId: row.user_id,
    username: row.username,
    name: row.name,
    email: row.email,
    emailVerified: row.email_verified,
    amr: row.amr,
    authAge: row.auth_age,
    authTime: Number(row.auth_time),
  };
}

// Use at auth or by an app's refresh keeps the session alive, up to its
// absolute end.
export async function touch(sql: SQL, sessionId: string): Promise<void> {
  await sql`
    UPDATE sessions SET last_seen_at = now(), expires_at = LEAST(now() + make_interval(days => ${IDLE_DAYS}), ends_at)
    WHERE id = ${sessionId}`;
}

export function sessionCookie(token: string): string {
  return setCookie(COOKIE, token, ABSOLUTE_DAYS * 24 * 60 * 60);
}

export function clearSessionCookie(): string {
  return clearCookie(COOKIE);
}

// A full sign-in. The same user signing in again keeps the session's id, the
// `sid` apps hold, with a new token, sign-in time and lifetime; anyone else
// gets a new session, and the previous one ends.
export async function signInSession(
  tx: SQL,
  app: App,
  userId: string,
  amr: string[],
  previous: { id: string; userId: string } | null,
  client: { ip: string | null; userAgent: string | null },
): Promise<{ id: string; token: string }> {
  const token = randomToken();
  const ua = client.userAgent?.slice(0, 512) ?? null;
  if (previous && previous.userId === userId) {
    const rows = await tx`
      UPDATE sessions SET token_hash = ${sha256(token)}, auth_time = now(), amr = ${tx.array(amr, "TEXT")},
        ip = ${client.ip}::inet, user_agent = ${ua}, last_seen_at = now(),
        expires_at = now() + make_interval(days => ${IDLE_DAYS}), ends_at = now() + make_interval(days => ${ABSOLUTE_DAYS})
      WHERE id = ${previous.id} RETURNING id`;
    if (rows.length === 1) return { id: previous.id, token };
  } else if (previous) {
    await endSession(tx, app, previous.id);
  }
  const id = newId("ses");
  await tx`
    INSERT INTO sessions (id, user_id, token_hash, auth_time, amr, ip, user_agent, expires_at, ends_at)
    VALUES (${id}, ${userId}, ${sha256(token)}, now(), ${tx.array(amr, "TEXT")}, ${client.ip}::inet, ${ua},
            now() + make_interval(days => ${IDLE_DAYS}), now() + make_interval(days => ${ABSOLUTE_DAYS}))`;
  return { id, token };
}

// A second factor added to a signed-in session: new methods, new token,
// same sign-in time.
export async function stepUp(tx: SQL, sessionId: string, amr: string[]): Promise<string> {
  const token = randomToken();
  await tx`UPDATE sessions SET token_hash = ${sha256(token)}, amr = ${tx.array(amr, "TEXT")} WHERE id = ${sessionId}`;
  return token;
}

// Ends one SSO session, and with it the refresh tokens of the confidential
// clients that used it; each app that holds tokens under it is told.
export async function endSession(tx: SQL, app: App, sessionId: string): Promise<void> {
  await emitSessionEnded(tx, app, sessionId);
  await tx`DELETE FROM sessions WHERE id = ${sessionId}`;
}

// Serializes everything that ends or extends a refresh-token family, taken
// before any of its rows is locked: otherwise a rotation in flight could
// insert a token an ending UPDATE never sees.
export async function lockFamily(tx: SQL, familyId: string): Promise<void> {
  await tx`SELECT pg_advisory_xact_lock(hashtext(${`family:${familyId}`}))`;
}

// Ends a public client's refresh-token family, which outlives the SSO session
// it started from; its id is the `sid` of the tokens it issued.
export async function endFamily(tx: SQL, app: App, familyId: string, userId: string): Promise<boolean> {
  await lockFamily(tx, familyId);
  const rows: { client_id: string }[] = await tx`
    UPDATE refresh_tokens SET revoked_at = now()
    WHERE family_id = ${familyId} AND user_id = ${userId} AND session_id IS NULL AND revoked_at IS NULL
    RETURNING client_id`;
  const services = new Set(rows.map((r) => app.services.client(r.client_id)?.service).filter((s) => s !== undefined));
  for (const service of services) await emit(tx, app, service, "session.ended", { sid: familyId });
  return rows.length > 0;
}

// Signs a user out everywhere: every SSO session and every public client's
// family, except the one session named.
export async function endUserSessions(tx: SQL, app: App, userId: string, except: string | null = null): Promise<void> {
  const sessions: { id: string }[] = await tx`SELECT id FROM sessions WHERE user_id = ${userId}`;
  for (const s of sessions) if (s.id !== except) await endSession(tx, app, s.id);
  const families: { family_id: string }[] = await tx`
    SELECT DISTINCT family_id FROM refresh_tokens WHERE user_id = ${userId} AND session_id IS NULL AND revoked_at IS NULL`;
  for (const f of families) await endFamily(tx, app, f.family_id, userId);
}

// The synchronizer token of §9.2, derived from the session's own token, so
// it changes whenever the session's token does and needs no storage.
export function csrfToken(app: App, session: Session): string {
  return app.crypt.hmac("csrf", session.token);
}

// A signed-in browser's state-changing request: Origin must be the issuer's,
// and the synchronizer token must match.
export function requireCsrf(app: App, req: Request, session: Session): void {
  requireOrigin(app, req);
  const sent = req.headers.get("X-CSRF-Token") ?? "";
  if (!app.crypt.hmacMatches("csrf", session.token, sent)) {
    throw new HttpError(403, "forbidden", "The CSRF token is missing or wrong.");
  }
}

export function requireOrigin(app: App, req: Request): void {
  if (!fromIssuer(app.config.issuer, req)) {
    throw new HttpError(403, "forbidden", "The request's Origin is not this issuer.");
  }
}
