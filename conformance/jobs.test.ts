import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, verify as verifySignature } from "node:crypto";
import {
  b64u,
  Browser,
  decodeJwt,
  defaultServices,
  enabled,
  freePort,
  linkIn,
  newId,
  sha256,
  signInTo,
  Stack,
  waitFor,
  type ServerProcess,
  type TestUser,
} from "./harness";

// Background work (docs/DESIGN.md §7.4, §8 Housekeeping, §9.3): events
// delivered from the outbox, retried and given up; housekeeping at start;
// signing keys made, published, rotated and retired.

setDefaultTimeout(30_000);

const unique = (prefix: string) => `${prefix}-${randomBytes(3).toString("hex")}`;
const EVT = /^evt_[0-9a-hjkmnp-tv-z]{26}$/;

// A Browser that talks to another copy of the server on the same database.
function browserOn(stack: Stack, copy: ServerProcess, from?: Browser): Browser {
  const view = Object.create(stack) as Stack;
  Object.defineProperty(view, "url", { value: copy.url });
  const browser = new Browser(view);
  for (const [k, v] of from?.cookies ?? []) browser.cookies.set(k, v);
  return browser;
}

// A token in the shape of a SET, signed by nothing: for outbox rows a test
// writes itself.
function unsignedSet(claims: Record<string, unknown>): string {
  return `${b64u(JSON.stringify({ alg: "EdDSA", typ: "secevent+jwt", kid: "none" }))}.${b64u(JSON.stringify(claims))}.${b64u(randomBytes(64))}`;
}

function thumbprint(x: string): string {
  return b64u(sha256(JSON.stringify({ crv: "Ed25519", kty: "OKP", x })));
}

describe.skipIf(!enabled)("events (§7.4)", () => {
  let stack: Stack;
  let admin: { user: TestUser; browser: Browser };
  // Events about these subs are answered 500; about these jtis, with the Response.
  const failing = new Set<string>();
  const answers = new Map<string, Response | (() => Response)>();
  beforeAll(async () => {
    stack = await Stack.start();
    admin = await stack.admin();
    stack.http.onEvent = (e) => {
      const answer = answers.get(e.token);
      if (answer) return typeof answer === "function" ? answer() : answer;
      if (failing.has(e.payload.sub) || failing.has(e.token)) return 500;
      return 204;
    };
  });
  afterAll(async () => {
    await stack.stop();
  });
  beforeEach(async () => {
    await stack.resetLimits();
  });

  const outboxRow = async (id: string) => {
    const [row] = await stack.db`
      SELECT id::text AS id, service, token, attempts, delivered_at, failed_at,
             extract(epoch FROM next_attempt_at - now())::float8 AS wait
      FROM outbox WHERE id = ${id}`;
    return row as { id: string; service: string; token: string; attempts: number; delivered_at: Date | null; failed_at: Date | null; wait: number };
  };
  const rowsAbout = async (sub: string) => (await stack.outbox()).filter((e) => e.payload.sub === sub);

  // The whole of one delivered event: its request, its token, its claims.
  const expectDelivered = async (service: string, type: string, payload: Record<string, unknown>) => {
    const e = await stack.http.waitForEvent(service, type, (x) => Bun.deepEquals(x.payload, payload));
    expect(e.contentType).toBe("application/secevent+jwt");
    expect(e.accept).toBe("application/json");
    expect(Object.keys(e.header).sort()).toEqual(["alg", "kid", "typ"]);
    expect(e.header).toMatchObject({ alg: "EdDSA", typ: "secevent+jwt" });
    expect(typeof e.header.kid).toBe("string");
    const claims = await stack.verified(e.token, "secevent+jwt");
    expect(Object.keys(claims).sort()).toEqual(["aud", "events", "iat", "iss", "jti"]);
    expect(claims.iss).toBe(stack.issuer);
    expect(claims.aud).toBe(service);
    expect(Number.isInteger(claims.iat)).toBe(true);
    expect(Math.abs(claims.iat - Date.now() / 1000)).toBeLessThan(120);
    expect(claims.jti).toMatch(EVT);
    expect(claims.events).toEqual({ [type]: payload });
    // The outbox row is marked delivered.
    await waitFor(async () => {
      const [row] = await stack.db`SELECT delivered_at, failed_at FROM outbox WHERE token = ${e.token}`;
      return row?.delivered_at !== null && row?.delivered_at !== undefined && row.failed_at === null;
    }, "the row to be marked delivered");
    return e;
  };

  describe("each type reaches its service as a signed SET", () => {
    test("access.changed, from a grant", async () => {
      const user = await stack.user({ username: unique("acc") });
      const res = await admin.browser.api("PUT", `/v1/users/${user.id}/access/wiki`, { role: "member" });
      expect(res.status).toBe(200);
      await expectDelivered("wiki", "access.changed", { sub: user.id, role: "member" });
    });

    test("access.changed with role null, from a removal", async () => {
      const user = await stack.user({ username: unique("rem"), access: { wiki: "member" } });
      const res = await admin.browser.api("DELETE", `/v1/users/${user.id}/access/wiki`);
      expect(res.status).toBe(204);
      await expectDelivered("wiki", "access.changed", { sub: user.id, role: null });
    });

    test("user.disabled, to every service with an events_url", async () => {
      const user = await stack.user({ username: unique("dis") });
      const res = await admin.browser.api("PATCH", `/v1/users/${user.id}`, { disabled: true });
      expect(res.status).toBe(200);
      for (const service of ["wiki", "tasks", "mailbox"]) await expectDelivered(service, "user.disabled", { sub: user.id });
      expect((await rowsAbout(user.id)).map((r) => r.service).sort()).toEqual(["mailbox", "tasks", "wiki"]);
    });

    test("user.deleted, to every service with an events_url", async () => {
      const user = await stack.user({ username: unique("del") });
      const res = await admin.browser.api("DELETE", `/v1/users/${user.id}`);
      expect(res.status).toBe(204);
      for (const service of ["wiki", "tasks", "mailbox"]) await expectDelivered(service, "user.deleted", { sub: user.id });
    });

    test("invite.accepted, with the access it gives", async () => {
      const user = await stack.user({ username: unique("inv") });
      const res = await admin.browser.api("POST", "/v1/invites", { email: user.email, service: "wiki", role: "member" });
      expect(res.status).toBe(201);
      const invite = (await res.json()) as { id: string };
      const mail = await stack.smtp.waitFor(user.email!, (m) => m.subject === "You're invited to wiki");
      const token = linkIn(mail).searchParams.get("token")!;
      const browser = await stack.session(user);
      const accepted = await browser.form("/invite", { token, action: "accept" });
      expect(accepted.status).toBe(200);
      await expectDelivered("wiki", "invite.accepted", { invite: invite.id, sub: user.id });
      await expectDelivered("wiki", "access.changed", { sub: user.id, role: "member" });
    });

    test("session.ended, to the services whose clients hold tokens under the session", async () => {
      const user = await stack.user({ username: unique("ses"), access: { wiki: "member" } });
      const browser = await stack.session(user);
      const { response } = await signInTo(stack, browser, "wiki");
      expect(response.status).toBe(200);
      const sid = browser.sessionId!;
      const res = await browser.api("DELETE", `/v1/me/sessions/${sid}`);
      expect(res.status).toBe(204);
      await expectDelivered("wiki", "session.ended", { sid });
      expect((await stack.outbox()).filter((e) => e.payload.sid === sid).map((e) => e.service)).toEqual(["wiki"]);
    });

    test("credential.revoked, from revoking an API key", async () => {
      const user = await stack.user({ username: unique("key"), access: { tasks: "user" } });
      const browser = await stack.session(user);
      const created = await browser.api("POST", "/v1/me/api-keys", { service: "tasks", scopes: ["tasks:read"], name: "ci" });
      expect(created.status).toBe(201);
      const { id } = (await created.json()) as { id: string };
      const res = await browser.api("DELETE", `/v1/me/api-keys/${id}`);
      expect(res.status).toBe(204);
      await expectDelivered("tasks", "credential.revoked", { sub: user.id, id });
    });

    test("a service without an events_url gets no outbox row", async () => {
      const user = await stack.user({ username: unique("notes") });
      const res = await admin.browser.api("PUT", `/v1/users/${user.id}/access/notes`, { role: "reader" });
      expect(res.status).toBe(200);
      expect((await stack.audit("access.put")).filter((a) => a.user_id === user.id)).toHaveLength(1);
      // Disabling reaches the others, never notes.
      await admin.browser.api("PATCH", `/v1/users/${user.id}`, { disabled: true });
      expect((await rowsAbout(user.id)).map((r) => r.service).sort()).toEqual(["mailbox", "tasks", "wiki"]);
    });
  });

  describe("retries", () => {
    // Queues an access.changed for wiki about a fresh user whose events fail.
    const failingRow = async () => {
      const user = await stack.user({ username: unique("retry") });
      failing.add(user.id);
      const res = await admin.browser.api("PUT", `/v1/users/${user.id}/access/wiki`, { role: "member" });
      expect(res.status).toBe(200);
      const [row] = await rowsAbout(user.id);
      return { user, id: row!.id };
    };
    // Waits for an attempt to finish: past its lease (60 s) and onto its backoff.
    const attempted = (id: string, attempts: number) =>
      waitFor(async () => {
        const row = await outboxRow(id);
        return row.attempts === attempts && row.wait < 59 ? row : null;
      }, `attempt ${attempts}`, 8000);
    const due = (id: string) => stack.db`UPDATE outbox SET next_attempt_at = now() WHERE id = ${id}`;

    test("a non-2xx leaves the row, backing off 5 s, doubling, to at most an hour; once due again it is redelivered with the same jti", async () => {
      const { user, id } = await failingRow();
      for (const [attempt, backoff] of [
        [1, 5],
        [2, 10],
        [3, 20],
      ] as const) {
        if (attempt > 1) await due(id);
        const row = await attempted(id, attempt);
        expect(row.delivered_at).toBeNull();
        expect(row.failed_at).toBeNull();
        expect(row.wait).toBeGreaterThan(backoff - 3);
        expect(row.wait).toBeLessThanOrEqual(backoff + 0.5);
      }
      for (const [from, backoff] of [
        [7, 5 * 2 ** 7],
        [10, 3600],
        [40, 3600],
      ] as const) {
        await stack.db`UPDATE outbox SET attempts = ${from}, next_attempt_at = now() WHERE id = ${id}`;
        const row = await waitFor(async () => {
          const r = await outboxRow(id);
          return r.attempts === from + 1 && Math.abs(r.wait - 60) > 1 ? r : null;
        }, `attempt ${from + 1}`, 8000);
        expect(row.wait).toBeGreaterThan(backoff - 3);
        expect(row.wait).toBeLessThanOrEqual(backoff + 0.5);
      }
      // The receiver recovers.
      failing.delete(user.id);
      await due(id);
      await waitFor(async () => (await outboxRow(id)).delivered_at !== null, "the redelivery");
      const received = stack.http.eventsFor("wiki", "access.changed").filter((e) => e.payload.sub === user.id);
      expect(received.length).toBeGreaterThanOrEqual(7);
      expect(new Set(received.map((e) => e.token)).size).toBe(1);
      expect(new Set(received.map((e) => e.claims.jti)).size).toBe(1);
      expect((await outboxRow(id)).attempts).toBe(42);
    });

    test("a redirect is not followed and counts as a failure", async () => {
      const { id } = await failingRow();
      const row = await attempted(id, 1);
      answers.set(row.token, () => new Response(null, { status: 307, headers: { Location: stack.http.eventsUrl("redirected") } }));
      const seen = stack.http.eventsFor("wiki").filter((e) => e.token === row.token).length;
      await due(id);
      const after = await attempted(id, 2);
      expect(stack.http.eventsFor("wiki").filter((e) => e.token === row.token).length).toBe(seen + 1);
      expect(after.delivered_at).toBeNull();
      expect(after.failed_at).toBeNull();
      expect(after.wait).toBeGreaterThan(7);
      expect(after.wait).toBeLessThanOrEqual(10.5);
      expect(stack.http.eventsFor("redirected")).toEqual([]);
      answers.delete(row.token);
    });

    test("an event over 24 hours old is given up after a failed attempt, logged and alerted", async () => {
      const iat = Math.floor(Date.now() / 1000) - 24 * 3600 - 60;
      const token = unsignedSet({ iss: stack.issuer, aud: "wiki", iat, jti: newId("usr").replace("usr", "evt"), events: { "user.disabled": { sub: newId("usr") } } });
      failing.add(token);
      const alerts = stack.alerts.filter((a) => a === "auth: gave up delivering an event to wiki after 1 attempts").length;
      const [row] = await stack.db`INSERT INTO outbox (service, token) VALUES ('wiki', ${token}) RETURNING id::text AS id`;
      const done = await waitFor(async () => {
        const r = await outboxRow(row.id);
        return r.failed_at !== null ? r : null;
      }, "the row to be given up", 8000);
      expect(done.attempts).toBe(1);
      expect(done.delivered_at).toBeNull();
      expect(stack.http.eventsFor("wiki").filter((e) => e.token === token)).toHaveLength(1);
      await waitFor(() => stack.logs.includes(`event ${row.id} for wiki given up after 1 attempts`), "the log line");
      await waitFor(() => stack.alerts.filter((a) => a === "auth: gave up delivering an event to wiki after 1 attempts").length > alerts, "the alert");
    });

    test("an event just under 24 hours old is retried", async () => {
      const iat = Math.floor(Date.now() / 1000) - 23 * 3600;
      const token = unsignedSet({ iss: stack.issuer, aud: "wiki", iat, jti: "evt_x", events: { "user.disabled": { sub: newId("usr") } } });
      failing.add(token);
      const [row] = await stack.db`INSERT INTO outbox (service, token) VALUES ('wiki', ${token}) RETURNING id::text AS id`;
      const r = await attempted(row.id, 1);
      expect(r.failed_at).toBeNull();
      expect(r.wait).toBeGreaterThan(2);
    });

    test.each([
      ["not a JWT", () => `garbage-${randomBytes(4).toString("hex")}`],
      ["a payload that isn't JSON", () => `${b64u("{}")}.${b64u(`not json ${randomBytes(4).toString("hex")}`)}.sig`],
      ["an iat that isn't a number", () => unsignedSet({ iat: String(Math.floor(Date.now() / 1000)), aud: "wiki", jti: randomBytes(4).toString("hex") })],
    ])("a token that is %s counts as old: given up after one failed attempt", async (_, make) => {
      const value = make();
      failing.add(value);
      const [row] = await stack.db`INSERT INTO outbox (service, token) VALUES ('wiki', ${value}) RETURNING id::text AS id`;
      const done = await waitFor(async () => {
        const r = await outboxRow(row.id);
        return r.failed_at !== null ? r : null;
      }, "the row to be given up", 8000);
      expect(done.attempts).toBe(1);
      await waitFor(() => stack.logs.includes(`event ${row.id} for wiki given up after 1 attempts`), "the log line");
      // stack.outbox() reads every row as a SET.
      await stack.db`DELETE FROM outbox WHERE id = ${row.id}`;
    });
  });
});

describe.skipIf(!enabled)("events to a registered service", () => {
  test("an unreachable URL is retried; once the service has no events_url the row is given up at its next attempt", async () => {
    const services = { services: defaultServices(() => "").services.filter((s) => s.name !== "notes").map((s) => ({ ...s, events_url: undefined })) };
    const stack = await Stack.start({ services });
    try {
      const admin = await stack.admin();
      const closed = await freePort();
      const notes = {
        name: "notes",
        roles: ["reader", "writer"],
        mfa_roles: [],
        signup: "closed",
        clients: [{ id: "notes", type: "confidential", redirect_uris: ["https://notes.example.com/auth/callback"] }],
        events_url: `http://127.0.0.1:${closed}/events`,
      };
      expect((await admin.browser.api("POST", "/v1/services", notes)).status).toBe(201);
      const user = await stack.user({ username: "alice" });
      expect((await admin.browser.api("PUT", `/v1/users/${user.id}/access/notes`, { role: "reader" })).status).toBe(200);
      const [queued] = await stack.outbox("notes");
      expect(queued!.type).toBe("access.changed");
      const row = async () => {
        const [r] = await stack.db`SELECT attempts, failed_at, delivered_at, extract(epoch FROM next_attempt_at - now())::float8 AS wait FROM outbox WHERE id = ${queued!.id}`;
        return r as { attempts: number; failed_at: Date | null; delivered_at: Date | null; wait: number };
      };
      const first = await waitFor(async () => {
        const r = await row();
        return r.attempts === 1 && r.wait < 59 ? r : null;
      }, "the first attempt", 10_000);
      expect(first.failed_at).toBeNull();
      expect(first.wait).toBeGreaterThan(1);
      expect(first.wait).toBeLessThanOrEqual(5.5);

      const { events_url: _, ...without } = notes;
      expect((await admin.browser.api("PUT", "/v1/services/notes", without)).status).toBe(200);
      await stack.db`UPDATE outbox SET next_attempt_at = now() WHERE id = ${queued!.id}`;
      const given = await waitFor(async () => {
        const r = await row();
        return r.failed_at !== null ? r : null;
      }, "the row to be given up", 10_000);
      expect(given.attempts).toBe(2);
      expect(given.delivered_at).toBeNull();
      await waitFor(() => stack.logs.includes(`event ${queued!.id} for notes given up after 2 attempts`), "the log line");
      await stack.http.waitForAlert("auth: gave up delivering an event to notes after 2 attempts");
      // Nothing more is queued for it.
      expect((await admin.browser.api("PUT", `/v1/users/${user.id}/access/notes`, { role: "writer" })).status).toBe(200);
      expect(await stack.outbox("notes")).toHaveLength(1);
    } finally {
      await stack.stop();
    }
  });
});

describe.skipIf(!enabled)("housekeeping at start (§8)", () => {
  let stack: Stack;
  let user: TestUser;
  let live: string;
  const token = (claims: Record<string, unknown> = {}) => unsignedSet({ iss: "x", aud: "wiki", iat: 0, jti: "evt_x", events: { "user.disabled": { sub: "usr_x" } }, ...claims });

  beforeAll(async () => {
    stack = await Stack.start();
    user = await stack.user({ username: "alice" });
    const sql = stack.db;
    const session = (id: string, expires: string, ends: string) => sql`
      INSERT INTO sessions (id, user_id, token_hash, auth_time, amr, expires_at, ends_at)
      VALUES (${id}, ${user.id}, ${sha256(id)}, now(), '{pwd}', now() + ${expires}::interval, now() + ${ends}::interval)`;
    live = newId("ses");
    await session(live, "1 day", "10 days");
    await session("ses_idle_gone", "-1 minute", "10 days");
    await session("ses_idle_kept", "5 minutes", "10 days");
    await session("ses_end_gone", "1 day", "-1 minute");
    await session("ses_end_kept", "1 day", "5 minutes");

    const code = (name: string, expires: string) => sql`
      INSERT INTO auth_codes (code_hash, client_id, session_id, redirect_uri, code_challenge, expires_at)
      VALUES (${sha256(name)}, 'wiki', ${live}, 'https://wiki.example.com/auth/callback', 'x', now() + ${expires}::interval)`;
    await code("code_gone", "-61 minutes");
    await code("code_kept", "-55 minutes");

    const ott = (name: string, expires: string) => sql`
      INSERT INTO one_time_tokens (token_hash, purpose, user_id, email, expires_at)
      VALUES (${sha256(name)}, 'reset', ${user.id}, ${user.email}, now() + ${expires}::interval)`;
    await ott("ott_gone", "-1 day -1 minute");
    await ott("ott_kept", "-23 hours");

    const refresh = (name: string, expires: string, revoked: string | null) => sql`
      INSERT INTO refresh_tokens (token_hash, family_id, user_id, client_id, expires_at, revoked_at)
      VALUES (${sha256(name)}, ${name}, ${user.id}, 'tasks-ios', now() + ${expires}::interval, now() + ${revoked}::interval)`;
    await refresh("rt_expired_gone", "-1 minute", null);
    await refresh("rt_expiring_kept", "5 minutes", null);
    await refresh("rt_revoked_gone", "10 days", "-1 day -1 minute");
    await refresh("rt_revoked_kept", "10 days", "-23 hours");

    const invite = (id: string, expires: string, accepted: boolean) => sql`
      INSERT INTO invites (id, email, service, role, token_hash, invited_by, expires_at, accepted_by, accepted_at)
      VALUES (${id}, 'someone@example.com', 'wiki', 'member', ${sha256(id)}, 'host-cli', now() + ${expires}::interval,
              ${accepted ? user.id : null}, now() + ${accepted ? "-40 days" : null}::interval)`;
    await invite("inv_gone", "-30 days -1 minute", false);
    await invite("inv_kept", "-29 days", false);
    await invite("inv_accepted_kept", "-60 days", true);

    await sql`INSERT INTO throttle (key, window_start, hits) VALUES
      ('hk:gone', now() - interval '1 day 1 minute', 1), ('hk:kept', now() - interval '23 hours', 1)`;

    const outbox = (name: string, delivered: string | null, failed: string | null) => sql`
      INSERT INTO outbox (service, token, attempts, delivered_at, failed_at)
      VALUES ('wiki', ${token({ jti: name })}, 1, now() + ${delivered}::interval, now() + ${failed}::interval)`;
    await outbox("ob_delivered_gone", "-7 days -1 minute", null);
    await outbox("ob_delivered_kept", "-6 days", null);
    await outbox("ob_failed_gone", null, "-7 days -1 minute");
    await outbox("ob_failed_kept", null, "-6 days");

    await sql`INSERT INTO audit (action, at) VALUES ('hk.gone', now() - interval '30 days 1 minute'), ('hk.kept', now() - interval '29 days')`;

    const copy = await stack.spawn({ env: { AUDIT_RETENTION_DAYS: "30" } });
    await copy.ready();
    await waitFor(async () => (await sql`SELECT 1 FROM audit WHERE action = 'hk.gone'`).length === 0, "housekeeping to run", 10_000);
  });
  afterAll(async () => {
    await stack.stop();
  });

  const present = async (query: Promise<unknown[]>) => (await query).length > 0;

  test.each([
    ["auth_codes, an hour past expiry", "code_gone", false],
    ["auth_codes, inside the hour", "code_kept", true],
  ])("%s", async (_, name, kept) => {
    expect(await present(stack.db`SELECT 1 FROM auth_codes WHERE code_hash = ${sha256(name)}`)).toBe(kept);
  });

  test.each([
    ["one_time_tokens, a day past expiry", "ott_gone", false],
    ["one_time_tokens, inside the day", "ott_kept", true],
  ])("%s", async (_, name, kept) => {
    expect(await present(stack.db`SELECT 1 FROM one_time_tokens WHERE token_hash = ${sha256(name)}`)).toBe(kept);
  });

  test.each([
    ["sessions, idle past expiry", "ses_idle_gone", false],
    ["sessions, idle not yet expired", "ses_idle_kept", true],
    ["sessions, past the absolute end", "ses_end_gone", false],
    ["sessions, before the absolute end", "ses_end_kept", true],
  ])("%s", async (_, id, kept) => {
    expect(await present(stack.db`SELECT 1 FROM sessions WHERE id = ${id}`)).toBe(kept);
  });

  test.each([
    ["refresh_tokens, expired", "rt_expired_gone", false],
    ["refresh_tokens, not yet expired", "rt_expiring_kept", true],
    ["refresh_tokens, revoked over a day ago", "rt_revoked_gone", false],
    ["refresh_tokens, revoked inside the day", "rt_revoked_kept", true],
  ])("%s", async (_, name, kept) => {
    expect(await present(stack.db`SELECT 1 FROM refresh_tokens WHERE token_hash = ${sha256(name)}`)).toBe(kept);
  });

  test.each([
    ["invites, unaccepted 30 days past expiry", "inv_gone", false],
    ["invites, unaccepted inside the 30 days", "inv_kept", true],
    ["invites, accepted, however old", "inv_accepted_kept", true],
  ])("%s", async (_, id, kept) => {
    expect(await present(stack.db`SELECT 1 FROM invites WHERE id = ${id}`)).toBe(kept);
  });

  test.each([
    ["throttle, a window over a day old", "hk:gone", false],
    ["throttle, a window inside the day", "hk:kept", true],
  ])("%s", async (_, key, kept) => {
    expect(await present(stack.db`SELECT 1 FROM throttle WHERE key = ${key}`)).toBe(kept);
  });

  test.each([
    ["outbox, delivered over 7 days ago", "ob_delivered_gone", false],
    ["outbox, delivered inside the 7 days", "ob_delivered_kept", true],
    ["outbox, given up over 7 days ago", "ob_failed_gone", false],
    ["outbox, given up inside the 7 days", "ob_failed_kept", true],
  ])("%s", async (_, jti, kept) => {
    const rows = await stack.outbox("wiki");
    expect(rows.some((r) => r.claims.jti === jti)).toBe(kept);
  });

  test.each([
    ["audit, past AUDIT_RETENTION_DAYS", "hk.gone", false],
    ["audit, inside AUDIT_RETENTION_DAYS", "hk.kept", true],
  ])("%s", async (_, action, kept) => {
    expect(await present(stack.db`SELECT 1 FROM audit WHERE action = ${action}`)).toBe(kept);
  });

  test("the live session and what hangs off it stay", async () => {
    expect(await present(stack.db`SELECT 1 FROM sessions WHERE id = ${live}`)).toBe(true);
  });
});

describe.skipIf(!enabled)("signing keys (§9.3)", () => {
  let stack: Stack;
  let admin: { user: TestUser; browser: Browser };
  let target: TestUser;
  beforeAll(async () => {
    stack = await Stack.start();
    admin = await stack.admin();
    target = await stack.user({ username: "alice" });
  });
  afterAll(async () => {
    await stack.stop();
  });

  type KeyRow = { kid: string; public_jwk: Record<string, string>; private_key_enc: Uint8Array; publish_at: Date; sign_from: Date; retire_at: Date | null; pending: boolean };
  const keys = async (): Promise<KeyRow[]> =>
    (await stack.db`SELECT kid, public_jwk, private_key_enc, publish_at, sign_from, retire_at, sign_from > now() AS pending FROM signing_keys ORDER BY sign_from`) as KeyRow[];

  // A newly started copy: the kids it publishes, and the kid it signs with
  // (read from an event it signs for a grant made through it).
  let role = "member";
  const fresh = async () => {
    const copy = await stack.spawn();
    await copy.ready();
    const published = ((await (await fetch(`${copy.url}/.well-known/jwks.json`)).json()) as { keys: Record<string, string>[] }).keys;
    role = role === "member" ? "admin" : "member";
    const browser = browserOn(stack, copy, admin.browser);
    const res = await browser.api("PUT", `/v1/users/${target.id}/access/wiki`, { role });
    expect(res.status).toBe(200);
    const [row] = await stack.db`SELECT token FROM outbox ORDER BY id DESC LIMIT 1`;
    const jwt = decodeJwt(row.token);
    expect(jwt.claims.events).toEqual({ "access.changed": { sub: target.id, role } });
    const jwk = published.find((k) => k.kid === jwt.header.kid);
    expect(jwk).toBeDefined();
    expect(verifySignature(null, Buffer.from(jwt.signed), createPublicKey({ key: jwk as any, format: "jwk" }), jwt.signature)).toBe(true);
    await copy.stop();
    return { published: published.map((k) => k.kid), signer: jwt.header.kid as string, jwks: published };
  };

  test("a fresh database gets one key that signs at once, stored as the design says", async () => {
    const [key, ...rest] = await keys();
    expect(rest).toEqual([]);
    expect(key!.pending).toBe(false);
    expect(key!.retire_at).toBeNull();
    expect(key!.publish_at.getTime()).toBeLessThanOrEqual(Date.now() + 1000);
    expect(key!.sign_from.getTime()).toBe(key!.publish_at.getTime());
    const jwk = key!.public_jwk;
    expect(Object.keys(jwk).sort()).toEqual(["alg", "crv", "kid", "kty", "use", "x"]);
    expect(jwk).toMatchObject({ kty: "OKP", crv: "Ed25519", alg: "EdDSA", use: "sig", kid: key!.kid });
    expect(key!.kid).toBe(thumbprint(jwk.x!));
    expect(Buffer.from(key!.private_key_enc).subarray(0, 3).toString()).toBe("v1:");
    const der = stack.crypt.decrypt(key!.private_key_enc, key!.kid);
    const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    expect(privateKey.asymmetricKeyType).toBe("ed25519");
    expect((createPublicKey(privateKey).export({ format: "jwk" }) as { x: string }).x).toBe(jwk.x!);
    expect(() => stack.crypt.decrypt(key!.private_key_enc, "another-kid")).toThrow();
    expect((await stack.jwks()).keys).toEqual([jwk]);
    const { signer } = await fresh();
    expect(signer).toBe(key!.kid);
  });

  test("rotation: a successor published a day early, signing from its sign_from; the old key retired a day later, then deleted", async () => {
    const [first] = await keys();
    // 89 days on, the next start publishes a successor that doesn't sign yet.
    await stack.db`UPDATE signing_keys SET publish_at = now() - interval '89 days 1 hour', sign_from = now() - interval '89 days 1 hour'`;
    const a = await fresh();
    const [old, successor, ...more] = await keys();
    expect(more).toEqual([]);
    expect(old!.kid).toBe(first!.kid);
    expect(successor!.pending).toBe(true);
    expect(successor!.sign_from.getTime() - successor!.publish_at.getTime()).toBe(24 * 3600 * 1000);
    expect(Math.abs(successor!.publish_at.getTime() - Date.now())).toBeLessThan(60_000);
    expect(successor!.kid).toBe(thumbprint(successor!.public_jwk.x!));
    expect(old!.retire_at).toBeNull();
    expect(a.published).toEqual([first!.kid, successor!.kid]);
    expect(a.signer).toBe(first!.kid);
    // Another start changes nothing: a successor is pending.
    const again = await fresh();
    expect((await keys()).map((k) => k.kid)).toEqual([first!.kid, successor!.kid]);
    expect(again.signer).toBe(first!.kid);

    // Once the successor's sign_from has passed, it signs, and the old key gets retire_at a day after.
    await stack.db`UPDATE signing_keys SET publish_at = now() - interval '1 day 1 minute', sign_from = now() - interval '1 minute' WHERE kid = ${successor!.kid}`;
    const b = await fresh();
    expect(b.signer).toBe(successor!.kid);
    expect(b.published).toEqual([first!.kid, successor!.kid]);
    const [retiring, current] = await keys();
    expect(retiring!.retire_at!.getTime()).toBe(current!.sign_from.getTime() + 24 * 3600 * 1000);
    expect(current!.retire_at).toBeNull();

    // Past its retire_at it leaves the JWKS; a day after that, the table.
    await stack.db`UPDATE signing_keys SET retire_at = now() - interval '1 hour' WHERE kid = ${first!.kid}`;
    const c = await fresh();
    expect(c.published).toEqual([successor!.kid]);
    expect((await keys()).map((k) => k.kid)).toEqual([first!.kid, successor!.kid]);
    await stack.db`UPDATE signing_keys SET retire_at = now() - interval '1 day 1 minute' WHERE kid = ${first!.kid}`;
    const d = await fresh();
    expect(d.published).toEqual([successor!.kid]);
    expect((await keys()).map((k) => k.kid)).toEqual([successor!.kid]);
  });

  test("a key written in the stored format, newest sign_from, is what a new copy signs with", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const x = (publicKey.export({ format: "jwk" }) as { x: string }).x;
    const kid = thumbprint(x);
    const der = privateKey.export({ format: "der", type: "pkcs8" });
    const jwk = { kty: "OKP", crv: "Ed25519", x, kid, alg: "EdDSA", use: "sig" };
    await stack.db`
      INSERT INTO signing_keys (kid, public_jwk, private_key_enc, publish_at, sign_from)
      VALUES (${kid}, ${JSON.stringify(jwk)}::text::jsonb, ${stack.crypt.encrypt(der, kid)}, now() - interval '2 minutes', now() - interval '30 seconds')`;
    const before = (await keys()).filter((k) => k.kid !== kid);
    const result = await fresh();
    expect(result.signer).toBe(kid);
    expect(result.jwks.find((k) => k.kid === kid)).toEqual(jwk);
    // The previous signer now retires a day after the new key's sign_from.
    const [row] = await stack.db`SELECT retire_at, (SELECT sign_from FROM signing_keys WHERE kid = ${kid}) AS from FROM signing_keys WHERE kid = ${before.at(-1)!.kid}`;
    expect(row.retire_at.getTime()).toBe(row.from.getTime() + 24 * 3600 * 1000);
  });
});

