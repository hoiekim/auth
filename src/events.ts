import type { SQL } from "bun";
import type { App } from "./app";
import { fromBase64url, newId } from "./crypto";
import { signJwt } from "./jwt";

// Events to apps (docs/DESIGN.md §7.4): Security Event Tokens signed when the
// change commits, written to the outbox in the same transaction, and POSTed
// to each service's events_url until it answers 2xx.

export type EventType =
  | "session.ended"
  | "access.changed"
  | "user.disabled"
  | "invite.accepted"
  | "user.deleted"
  | "credential.revoked";

type EventDeps = Pick<App, "config" | "services" | "keys">;

// Queues one event for one service, inside the caller's transaction. A
// service without an events_url relies on the pull (§7.1), so it gets none.
export async function emit(tx: SQL, app: EventDeps, service: string, type: EventType, payload: Record<string, unknown>): Promise<void> {
  if (!app.services.get(service)?.eventsUrl) return;
  const signer = await app.keys.signer(tx);
  const token = signJwt(
    "secevent+jwt",
    {
      iss: app.config.issuer,
      aud: service,
      iat: Math.floor(Date.now() / 1000),
      jti: newId("evt"),
      events: { [type]: payload },
    },
    signer,
  );
  await tx`INSERT INTO outbox (service, token) VALUES (${service}, ${token})`;
}

// To every service that takes events: disabling or deleting a user reaches
// every app, whichever ones they used.
export async function emitAll(tx: SQL, app: EventDeps, type: EventType, payload: Record<string, unknown>): Promise<void> {
  for (const s of app.services.all()) await emit(tx, app, s.name, type, payload);
}

// Every service whose clients hold refresh tokens under a session, so its
// end reaches each app that signed in with it.
export async function emitSessionEnded(tx: SQL, app: EventDeps, sid: string): Promise<void> {
  const rows: { client_id: string }[] = await tx`
    SELECT DISTINCT client_id FROM refresh_tokens WHERE session_id = ${sid} OR family_id = ${sid}`;
  const services = new Set(rows.map((r) => app.services.client(r.client_id)?.service).filter((s) => s !== undefined));
  for (const service of services) await emit(tx, app, service, "session.ended", { sid });
}

const LEASE_SECONDS = 60;
const GIVE_UP_SECONDS = 24 * 60 * 60;
const MAX_BACKOFF_SECONDS = 60 * 60;

// One pass over the due events. Rows are leased with SKIP LOCKED, so copies
// running this at once never deliver the same row in the same pass, and a
// copy that dies mid-delivery leaves its rows to be retried after the lease.
export async function deliverDue(app: App, fetchFn: typeof fetch = fetch, limit = 20): Promise<number> {
  const rows: { id: string; service: string; token: string; attempts: number }[] = await app.sql`
    UPDATE outbox SET attempts = attempts + 1, next_attempt_at = now() + make_interval(secs => ${LEASE_SECONDS})
    WHERE id IN (
      SELECT id FROM outbox
      WHERE delivered_at IS NULL AND failed_at IS NULL AND next_attempt_at <= now()
      ORDER BY id LIMIT ${limit}
      FOR UPDATE SKIP LOCKED)
    RETURNING id, service, token, attempts`;
  await Promise.all(rows.map((row) => deliverOne(app, fetchFn, row)));
  return rows.length;
}

async function deliverOne(app: App, fetchFn: typeof fetch, row: { id: string; service: string; token: string; attempts: number }) {
  const url = app.services.get(row.service)?.eventsUrl ?? null;
  let delivered = false;
  if (url) {
    try {
      const res = await fetchFn(url, {
        method: "POST",
        headers: { "Content-Type": "application/secevent+jwt", Accept: "application/json" },
        body: row.token,
        redirect: "manual",
        signal: AbortSignal.timeout(5000),
      });
      await res.body?.cancel();
      delivered = res.status >= 200 && res.status < 300;
    } catch {
      delivered = false;
    }
  }
  if (delivered) {
    await app.sql`UPDATE outbox SET delivered_at = now() WHERE id = ${row.id}`;
    return;
  }
  // iat was set from this process's clock at signing, so age is measured on
  // the same clock.
  const age = Date.now() / 1000 - issuedAt(row.token);
  const giveUp = url === null || age >= GIVE_UP_SECONDS;
  const backoff = Math.min(5 * 2 ** Math.max(row.attempts - 1, 0), MAX_BACKOFF_SECONDS);
  if (giveUp) {
    await app.sql`UPDATE outbox SET failed_at = now() WHERE id = ${row.id}`;
    app.log(`event ${row.id} for ${row.service} given up after ${row.attempts} attempts`);
    app.alert(`auth: gave up delivering an event to ${row.service} after ${row.attempts} attempts`);
  } else {
    await app.sql`UPDATE outbox SET next_attempt_at = now() + make_interval(secs => ${backoff}) WHERE id = ${row.id}`;
  }
}

function issuedAt(token: string): number {
  try {
    const payload = JSON.parse(fromBase64url(token.split(".")[1] ?? "").toString("utf8"));
    return typeof payload.iat === "number" ? payload.iat : 0;
  } catch {
    return 0;
  }
}
