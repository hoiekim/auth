import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { checkClientSecret } from "./clients";
import { runCli } from "./cli";
import { emit } from "./events";
import { deliverDue } from "./events";
import { housekeep } from "./jobs";
import { KeyStore, rotateKeys } from "./keys";
import { SQL } from "bun";
import type { MailMessage } from "./mail";
import { migrate } from "./migrate";
import { Browser, makeUser, TEST_DATABASE_URL, testApp, testDb, type TestApp, type TestDb } from "./testing/harness";
import { random } from "./crypto";

// Background work, keys, migrations and the break-glass CLI
// (docs/DESIGN.md §7.4, §8, §9.3, §9.6).
describe.skipIf(!TEST_DATABASE_URL)("operations", () => {
  let db: TestDb;
  let t: TestApp;
  beforeAll(async () => {
    db = await testDb();
    t = await testApp(db.sql);
  });
  afterAll(() => db.drop());

  describe("the outbox (§7.4)", () => {
    const fakeFetch = (status: number, seen: { url: string; body: string; type: string | null }[] = []) =>
      (async (url: string, init: RequestInit) => {
        seen.push({ url, body: String(init.body), type: new Headers(init.headers).get("Content-Type") });
        return new Response(null, { status });
      }) as unknown as typeof fetch;

    test("a delivered event is POSTed as a SET to the service's events_url, once", async () => {
      await t.app.sql`DELETE FROM outbox`;
      await t.app.sql.begin((tx) => emit(tx, t.app, "wiki", "session.ended", { sid: "ses_x" }));
      const seen: { url: string; body: string; type: string | null }[] = [];
      expect(await deliverDue(t.app, fakeFetch(202, seen))).toBe(1);
      expect(seen).toHaveLength(1);
      expect(seen[0]!.url).toBe("http://wiki.internal:3000/auth/events");
      expect(seen[0]!.type).toBe("application/secevent+jwt");
      const header = JSON.parse(Buffer.from(seen[0]!.body.split(".")[0]!, "base64url").toString());
      expect(header).toMatchObject({ alg: "EdDSA", typ: "secevent+jwt" });
      const claims = JSON.parse(Buffer.from(seen[0]!.body.split(".")[1]!, "base64url").toString());
      expect(claims).toMatchObject({ iss: "https://auth.example.com", aud: "wiki", events: { "session.ended": { sid: "ses_x" } } });
      expect(claims.jti).toMatch(/^evt_/);
      expect(await deliverDue(t.app, fakeFetch(202, seen))).toBe(0);
      expect(seen).toHaveLength(1);
    });

    test("a service without events_url gets no events", async () => {
      await t.app.sql`DELETE FROM outbox`;
      await t.app.sql.begin((tx) => emit(tx, t.app, "notes", "user.disabled", { sub: "usr_x" }));
      expect(await t.app.sql`SELECT 1 FROM outbox`).toHaveLength(0);
    });

    test("a failure backs off from 5 s, doubling to an hour", async () => {
      await t.app.sql`DELETE FROM outbox`;
      await t.app.sql.begin((tx) => emit(tx, t.app, "wiki", "user.disabled", { sub: "usr_x" }));
      const waits: number[] = [];
      for (let i = 0; i < 12; i++) {
        await t.app.sql`UPDATE outbox SET next_attempt_at = now()`;
        await deliverDue(t.app, fakeFetch(500));
        const [r] = await t.app.sql`SELECT round(extract(epoch FROM next_attempt_at - now()))::int AS wait FROM outbox`;
        waits.push(r.wait);
      }
      expect(waits.slice(0, 4)).toEqual([5, 10, 20, 40]);
      expect(waits.at(-1)).toBe(3600);
    });

    test("after 24 hours it gives up and alerts", async () => {
      await t.app.sql`DELETE FROM outbox`;
      const realNow = Date.now;
      Date.now = () => realNow() - 25 * 60 * 60 * 1000;
      try {
        await t.app.sql.begin((tx) => emit(tx, t.app, "wiki", "user.deleted", { sub: "usr_old" }));
      } finally {
        Date.now = realNow;
      }
      t.alerts.length = 0;
      await deliverDue(t.app, fakeFetch(503));
      const [row] = await t.app.sql`SELECT failed_at IS NOT NULL AS failed FROM outbox`;
      expect(row.failed).toBe(true);
      expect(t.alerts).toEqual(["auth: gave up delivering an event to wiki after 1 attempts"]);
    });

    test("five transactions emitting at once, with the key cache cold, don't wedge the 5-connection pool", async () => {
      await t.app.sql`DELETE FROM outbox`;
      const realKeys = t.app.keys;
      t.app.keys = new KeyStore(t.app.sql, t.app.crypt);
      try {
        const all = Promise.all(
          Array.from({ length: 5 }, (_, i) =>
            t.app.sql.begin(async (tx) => {
              await tx`SELECT 1`;
              await Bun.sleep(20);
              await emit(tx, t.app, "wiki", "session.ended", { sid: `ses_${i}` });
            }),
          ),
        );
        expect(await Promise.race([all.then(() => "done"), Bun.sleep(5000).then(() => "stuck")])).toBe("done");
        expect(await t.app.sql`SELECT 1 FROM outbox`).toHaveLength(5);
      } finally {
        t.app.keys = realKeys;
      }
    });

    test("two copies delivering at once never send the same event twice", async () => {
      await t.app.sql`DELETE FROM outbox`;
      for (let i = 0; i < 30; i++) await t.app.sql.begin((tx) => emit(tx, t.app, "wiki", "session.ended", { sid: `ses_${i}` }));
      const seen: { url: string; body: string; type: string | null }[] = [];
      const slow = (async (url: string, init: RequestInit) => {
        seen.push({ url, body: String(init.body), type: null });
        await Bun.sleep(5);
        return new Response(null, { status: 200 });
      }) as unknown as typeof fetch;
      await Promise.all([deliverDue(t.app, slow, 20), deliverDue(t.app, slow, 20), deliverDue(t.app, slow, 20)]);
      expect(seen).toHaveLength(30);
      expect(new Set(seen.map((s) => s.body)).size).toBe(30);
    });
  });

  describe("signing keys (§9.3)", () => {
    test("a new key is published a day before it signs, and the old one leaves a day after", async () => {
      await t.app.sql`DELETE FROM signing_keys`;
      await rotateKeys(t.app.sql, t.app.crypt);
      const [first] = await t.app.sql`SELECT kid FROM signing_keys`;
      // 89 days on, a successor is published, signing from tomorrow.
      await t.app.sql`UPDATE signing_keys SET publish_at = now() - interval '89 days 1 hour', sign_from = now() - interval '89 days 1 hour'`;
      await rotateKeys(t.app.sql, t.app.crypt);
      const keys = await t.app.sql`SELECT kid, sign_from > now() AS pending, retire_at FROM signing_keys ORDER BY sign_from`;
      expect(keys).toHaveLength(2);
      expect(keys[1].pending).toBe(true);
      await t.app.keys.refresh(true);
      expect((await t.app.keys.jwks()).keys.map((k) => k.kid)).toEqual([first.kid, keys[1].kid]);
      expect((await t.app.keys.signer()).kid).toBe(first.kid);
      // A day later the new one signs; the old one is still published, for a day.
      await t.app.sql`UPDATE signing_keys SET sign_from = sign_from - interval '1 day 1 minute', publish_at = publish_at - interval '1 day 1 minute'`;
      await rotateKeys(t.app.sql, t.app.crypt);
      await t.app.keys.refresh(true);
      expect((await t.app.keys.signer()).kid).toBe(keys[1].kid);
      const [old] = await t.app.sql`SELECT retire_at > now() AS published FROM signing_keys WHERE kid = ${first.kid}`;
      expect(old.published).toBe(true);
      // Two days later it's gone from JWKS, then from the table.
      await t.app.sql`UPDATE signing_keys SET retire_at = now() - interval '2 days' WHERE kid = ${first.kid}`;
      await rotateKeys(t.app.sql, t.app.crypt);
      await t.app.keys.refresh(true);
      expect((await t.app.keys.jwks()).keys.map((k) => k.kid)).toEqual([keys[1].kid]);
      expect(await t.app.sql`SELECT 1 FROM signing_keys WHERE kid = ${first.kid}`).toHaveLength(0);
    });

    test("private keys are stored encrypted, bound to their kid", async () => {
      const [row] = await t.app.sql`SELECT kid, private_key_enc FROM signing_keys LIMIT 1`;
      expect(Buffer.from(row.private_key_enc).subarray(0, 3).toString()).toBe("v1:");
      expect(() => t.app.crypt.decrypt(row.private_key_enc, "another-kid")).toThrow();
      expect(t.app.crypt.decrypt(row.private_key_enc, row.kid).length).toBeGreaterThan(0);
    });

    test("JWKS lists public halves only, cacheable for an hour", async () => {
      const res = await new Browser(t).request("/.well-known/jwks.json");
      expect(res.headers.get("Cache-Control")).toBe("public, max-age=3600");
      const { keys } = await res.json() as any;
      for (const k of keys) expect(Object.keys(k).sort()).toEqual(["alg", "crv", "kid", "kty", "use", "x"]);
    });
  });

  test("discovery lists only what is implemented", async () => {
    const d = await (await new Browser(t).request("/.well-known/openid-configuration")).json() as any;
    expect(d.issuer).toBe("https://auth.example.com");
    expect(d.response_types_supported).toEqual(["code"]);
    expect(d.grant_types_supported).toEqual(["authorization_code", "refresh_token"]);
    expect(d.code_challenge_methods_supported).toEqual(["S256"]);
    expect(d.id_token_signing_alg_values_supported).toEqual(["EdDSA"]);
    expect(d.token_endpoint_auth_methods_supported).toEqual(["client_secret_basic", "none"]);
  });

  test("housekeeping drops what has expired, in one copy at a time", async () => {
    const id = await makeUser(t, { username: "keeper" });
    await t.app.sql`INSERT INTO throttle (key, window_start, hits) VALUES ('old', now() - interval '2 days', 1), ('new', now(), 1)`;
    await t.app.sql`INSERT INTO audit (action, at) VALUES ('ancient', now() - interval '400 days'), ('recent', now())`;
    await t.app.sql`
      INSERT INTO sessions (id, user_id, token_hash, auth_time, amr, expires_at, ends_at)
      VALUES ('ses_dead', ${id}, '\\x01', now(), '{pwd}', now() - interval '1 second', now() + interval '1 day'),
             ('ses_live', ${id}, '\\x02', now(), '{pwd}', now() + interval '1 day', now() + interval '1 day')`;
    expect(await housekeep(t.app.sql, 365)).toBe(true);
    expect((await t.app.sql`SELECT key FROM throttle WHERE key IN ('old', 'new')`).map((r: { key: string }) => r.key)).toEqual(["new"]);
    expect((await t.app.sql`SELECT action FROM audit WHERE action IN ('ancient', 'recent')`).map((r: { action: string }) => r.action)).toEqual(["recent"]);
    expect((await t.app.sql`SELECT id FROM sessions WHERE id IN ('ses_dead', 'ses_live')`).map((r: { id: string }) => r.id)).toEqual(["ses_live"]);
  });

  test("housekeeping skips its run while another copy holds the lock", async () => {
    const other = await t.app.sql.reserve();
    try {
      await other`SELECT pg_advisory_lock(hashtext('auth.housekeeping'))`;
      expect(await housekeep(t.app.sql, 365)).toBe(false);
      await other`SELECT pg_advisory_unlock(hashtext('auth.housekeeping'))`;
    } finally {
      other.release();
    }
    expect(await housekeep(t.app.sql, 365)).toBe(true);
  });

  test("migrations apply once when three copies start together on an empty database", async () => {
    const schema = `t_${random(6).toString("hex")}`;
    const admin = new SQL(TEST_DATABASE_URL!, { max: 1 });
    await admin.unsafe(`CREATE SCHEMA ${schema}`);
    const copies = Array.from({ length: 3 }, () => new SQL(TEST_DATABASE_URL!, { max: 2, connection: { search_path: schema } }));
    try {
      const applied: string[] = [];
      await Promise.all(copies.map((c) => migrate(c, (line) => applied.push(line))));
      expect(applied).toEqual(["migration 0001_initial applied"]);
      const rows = await copies[0]!`SELECT version FROM schema_migrations`;
      expect(rows.map((r: { version: string }) => r.version)).toEqual(["0001_initial"]);
    } finally {
      await Promise.all(copies.map((c) => c.close()));
      await admin.unsafe(`DROP SCHEMA ${schema} CASCADE`);
      await admin.close();
    }
  });

  describe("the break-glass CLI (§9.6)", () => {
    const run = async (...argv: string[]) => {
      const out: string[] = [];
      const sent: MailMessage[] = [];
      const code = await runCli(argv, { app: t.app, mailer: { send: async (m) => void sent.push(m) }, out: (l) => out.push(l) });
      return { code, out, sent };
    };

    test("creates the first admin, with an activation link, audited as host-cli", async () => {
      const { code, out } = await run("user", "create", "--username", "first-admin", "--email", "first@example.com", "--access", "auth:admin", "--print-link");
      expect(code).toBe(0);
      expect(out.join("\n")).toMatch(/activation link .*: https:\/\/auth\.example\.com\/activate\?token=[\w-]{43}/);
      const [row] = await t.app.sql`SELECT a.role, a.granted_by FROM access a JOIN users u ON u.id = a.user_id WHERE u.username = 'first-admin'`;
      expect(row).toEqual({ role: "admin", granted_by: "host-cli" });
      const actions = await t.app.sql`SELECT actor, action FROM audit WHERE user_id = (SELECT id FROM users WHERE username = 'first-admin') ORDER BY id`;
      expect(actions).toEqual([
        { actor: "host-cli", action: "user.create" },
        { actor: "host-cli", action: "access.put" },
      ]);
    });

    test("emails the link without --print-link", async () => {
      const { code, sent } = await run("user", "create", "--username", "second", "--email", "second@example.com");
      expect(code).toBe(0);
      expect(sent.map((m) => m.to)).toEqual(["second@example.com"]);
    });

    test("refuses a role a service doesn't declare, and an unknown command", async () => {
      expect((await run("user", "create", "--username", "third", "--email", "t@example.com", "--access", "wiki:root")).code).toBe(2);
      expect(await t.app.sql`SELECT 1 FROM users WHERE username = 'third'`).toHaveLength(0);
      expect((await run("user", "explode")).code).toBe(2);
    });

    test("a client secret is printed once; two stay live during a rotation", async () => {
      const a = (await run("client", "secret", "wiki")).out[0]!;
      const b = (await run("client", "secret", "wiki")).out[0]!;
      expect(await checkClientSecret(t.app.sql, "wiki", a)).toBe(true);
      expect(await checkClientSecret(t.app.sql, "wiki", b)).toBe(true);
      const c = (await run("client", "secret", "wiki")).out[0]!;
      expect(await checkClientSecret(t.app.sql, "wiki", a)).toBe(false);
      expect(await checkClientSecret(t.app.sql, "wiki", b)).toBe(true);
      await run("client", "retire-old-secrets", "wiki");
      expect(await checkClientSecret(t.app.sql, "wiki", b)).toBe(false);
      expect(await checkClientSecret(t.app.sql, "wiki", c)).toBe(true);
      expect((await run("client", "secret", "tasks-ios")).code).toBe(2);
      // Stored as hashes.
      const stored = await t.app.sql`SELECT secret_hash FROM client_secrets WHERE client_id = 'wiki'`;
      expect(stored.every((r: { secret_hash: Buffer }) => r.secret_hash.length === 32)).toBe(true);
    });

    test("clear-mfa and disable act at once", async () => {
      const id = await makeUser(t, { username: "victim", password: "correct horse battery" });
      await t.app.sql`INSERT INTO totp (user_id, secret_enc) VALUES (${id}, '\\x00')`;
      expect((await run("user", "clear-mfa", "victim")).code).toBe(0);
      expect(await t.app.sql`SELECT 1 FROM totp WHERE user_id = ${id}`).toHaveLength(0);
      expect((await run("user", "disable", "victim")).code).toBe(0);
      const [u] = await t.app.sql`SELECT disabled_at IS NOT NULL AS d FROM users WHERE id = ${id}`;
      expect(u.d).toBe(true);
      expect((await run("user", "disable", "nobody")).code).toBe(2);
    });
  });
});
