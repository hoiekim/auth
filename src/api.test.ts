import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { fromBase32, sha256 } from "./crypto";
import { hotp, stepAt } from "./totp";
import { basic, Browser, flush, makeUser, outboxEvents, TEST_DATABASE_URL, testApp, testDb, type TestApp, type TestDb } from "./testing/harness";

// The management API (docs/DESIGN.md §7.5) and introspection (§7.2): who may
// call what, and what each change leaves behind.
describe.skipIf(!TEST_DATABASE_URL)("management API", () => {
  let db: TestDb;
  let t: TestApp;
  const PW = "correct horse battery";
  let root: Browser;
  let rootId: string;

  // A signed-in admin whose session used a second factor.
  async function adminBrowser(username: string): Promise<{ b: Browser; id: string }> {
    const id = await makeUser(t, { username, password: PW, access: { auth: "admin" } });
    const b = new Browser(t);
    await b.signIn(username, PW);
    const start = await (await b.api("POST", "/v1/me/totp", {})).json() as any;
    await b.api("POST", "/v1/me/totp", { enrollment: start.enrollment, code: hotp(fromBase32(start.secret)!, stepAt(Date.now() / 1000)) });
    return { b, id };
  }

  const client = (id: string) => ({ Authorization: basic(id, t.secrets[id]!) });
  const asClient = (id: string, method: string, path: string, body?: unknown) =>
    new Browser(t).request(path, {
      method,
      origin: null,
      headers: { ...client(id), ...(body !== undefined ? { "Content-Type": "application/json" } : {}) },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });

  beforeAll(async () => {
    db = await testDb();
    t = await testApp(db.sql);
    ({ b: root, id: rootId } = await adminBrowser("root"));
  });
  afterAll(() => db.drop());

  describe("browser callers", () => {
    test("a change needs the CSRF token and this issuer's Origin", async () => {
      const csrf = await root.csrf();
      const send = (headers: Record<string, string>, origin?: string | null) =>
        root.request("/v1/me", { method: "PATCH", headers: { "Content-Type": "application/json", ...headers }, body: '{"name":"Root"}', origin });
      expect((await send({})).status).toBe(403);
      expect((await send({ "X-CSRF-Token": "wrong" })).status).toBe(403);
      expect((await send({ "X-CSRF-Token": csrf }, "https://evil.example.com")).status).toBe(403);
      expect((await send({ "X-CSRF-Token": csrf }, null)).status).toBe(403);
      expect((await send({ "X-CSRF-Token": csrf })).status).toBe(200);
    });

    test("no session is 401", async () => {
      expect((await new Browser(t).api("GET", "/v1/me")).status).toBe(401);
    });

    test("credential changes need a sign-in in the last 15 minutes", async () => {
      await makeUser(t, { username: "stale", password: PW, access: { mailbox: "user" } });
      const b = new Browser(t);
      await b.signIn("stale", PW);
      await t.app.sql`UPDATE sessions SET auth_time = now() - interval '16 minutes' WHERE user_id = (SELECT id FROM users WHERE username = 'stale')`;
      for (const [method, path, body] of [
        ["POST", "/v1/me/password", { current: PW, new: "another long password" }],
        ["POST", "/v1/me/totp", {}],
        ["POST", "/v1/me/recovery-codes", {}],
        ["POST", "/v1/me/passkeys", {}],
        ["POST", "/v1/me/app-passwords", { name: "x", service: "mailbox", scopes: ["imap"] }],
        ["POST", "/v1/me/api-keys", { name: "x", service: "tasks", scopes: ["tasks:read"] }],
        ["PATCH", "/v1/me", { email: "new@example.com" }],
      ] as const) {
        const res = await b.api(method, path, body);
        expect(res.status).toBe(403);
        expect((await res.json() as any).error).toBe("reauth_required");
      }
      // A name isn't a credential.
      expect((await b.api("PATCH", "/v1/me", { name: "Stale" })).status).toBe(200);
    });

    test("with a second factor on the account, a password-only session changes no credential", async () => {
      // A passkey and no TOTP: the password alone signs in, without mfa.
      const id = await makeUser(t, { username: "pkonly", password: PW, access: { auth: "admin", mailbox: "user", tasks: "user" } });
      await t.app.sql`INSERT INTO passkeys (id, user_id, credential_id, public_key, name) VALUES ('pk_x', ${id}, '\\x0102', '\\x03', 'laptop')`;
      const b = new Browser(t);
      await b.signIn("pkonly", PW);
      for (const [method, path, body] of [
        ["POST", "/v1/me/totp", {}],
        ["POST", "/v1/me/passkeys", {}],
        ["DELETE", "/v1/me/passkeys/pk_x", undefined],
        ["POST", "/v1/me/recovery-codes", {}],
        ["POST", "/v1/me/app-passwords", { name: "x", service: "mailbox", scopes: ["imap"] }],
        ["POST", "/v1/me/api-keys", { name: "x", service: "tasks", scopes: ["tasks:read"] }],
        ["POST", "/v1/me/password", { current: PW, new: "another long password" }],
        ["PATCH", "/v1/me", { email: "pk@example.org" }],
      ] as const) {
        const res = await b.api(method, path, body);
        expect([path, res.status]).toEqual([path, 403]);
        expect((await res.json() as any).error).toBe("reauth_required");
      }
      expect((await b.api("GET", "/v1/users")).status).toBe(403);
      const [s] = await t.app.sql`SELECT amr FROM sessions WHERE user_id = ${id}`;
      expect(s.amr).toEqual(["pwd"]);
    });

    test("every credential change, removals included, needs a recent sign-in", async () => {
      const id = await makeUser(t, { username: "stale2", password: PW, access: { mailbox: "user" } });
      const b = new Browser(t);
      await b.signIn("stale2", PW);
      const pw = await (await b.api("POST", "/v1/me/app-passwords", { name: "x", service: "mailbox", scopes: ["imap"] })).json() as any;
      await t.app.sql`INSERT INTO passkeys (id, user_id, credential_id, public_key, name) VALUES ('pk_y', ${id}, '\\x0405', '\\x06', 'phone')`;
      await t.app.sql`UPDATE sessions SET auth_time = now() - interval '16 minutes', amr = '{swk,user,mfa}' WHERE user_id = ${id}`;
      for (const [method, path] of [
        ["DELETE", "/v1/me/totp"],
        ["DELETE", "/v1/me/passkeys/pk_y"],
        ["DELETE", `/v1/me/app-passwords/${pw.id}`],
        ["DELETE", "/v1/me"],
      ] as const) {
        expect([path, (await b.api(method, path)).status]).toEqual([path, 403]);
      }
      // An admin's changes to a bot's credentials too.
      const bot = await makeUser(t, { username: "stale-bot", kind: "bot", ownerId: rootId, access: { mailbox: "user" } });
      await t.app.sql`UPDATE sessions SET auth_time = now() - interval '16 minutes' WHERE user_id = ${rootId}`;
      const res = await root.api("POST", `/v1/users/${bot}/app-passwords`, { name: "x", service: "mailbox", scopes: ["smtp"] });
      expect((await res.json() as any).error).toBe("reauth_required");
      await t.app.sql`UPDATE sessions SET auth_time = now() WHERE user_id = ${rootId}`;
    });

    test("guessing the current password is held to the sign-in limits", async () => {
      await makeUser(t, { username: "guessed", password: PW });
      const b = new Browser(t, "192.0.2.77");
      await b.signIn("guessed", PW);
      for (let i = 0; i < 5; i++) expect((await b.api("POST", "/v1/me/password", { current: `wrong ${i}`, new: "a brand new password" })).status).toBe(403);
      const res = await b.api("POST", "/v1/me/password", { current: PW, new: "a brand new password" });
      expect(res.status).toBe(429);
    });

    test("an admin needs a session that used MFA; anyone else is refused", async () => {
      await makeUser(t, { username: "halfadmin", password: PW, access: { auth: "admin" } });
      const half = new Browser(t);
      await half.signIn("halfadmin", PW);
      const res = await half.api("GET", "/v1/users");
      expect(res.status).toBe(403);
      expect((await res.json() as any).error_description).toContain("second factor");
      await makeUser(t, { username: "plain", password: PW });
      const plain = new Browser(t);
      await plain.signIn("plain", PW);
      expect((await plain.api("GET", "/v1/users")).status).toBe(403);
      expect((await root.api("GET", "/v1/users")).status).toBe(200);
    });

    test("changing the password ends the other sessions, not this one", async () => {
      await makeUser(t, { username: "pwchange", password: PW });
      const here = new Browser(t);
      const there = new Browser(t);
      await here.signIn("pwchange", PW);
      await there.signIn("pwchange", PW);
      expect((await here.api("POST", "/v1/me/password", { current: "wrong", new: "a brand new password" })).status).toBe(403);
      expect((await here.api("POST", "/v1/me/password", { current: PW, new: "password1234" })).status).toBe(400);
      expect((await here.api("POST", "/v1/me/password", { current: PW, new: "a brand new password" })).status).toBe(204);
      expect((await here.api("GET", "/v1/me")).status).toBe(200);
      expect((await there.api("GET", "/v1/me")).status).toBe(401);
    });

    test("an email change waits for the new address, and tells the old one", async () => {
      await makeUser(t, { username: "mover", password: PW });
      const b = new Browser(t);
      await b.signIn("mover", PW);
      t.mails.length = 0;
      const me = await (await b.api("PATCH", "/v1/me", { email: "moved@example.com" })).json() as any;
      expect(me.email).toBe("mover@example.com");
      expect(me.email_pending).toBe("moved@example.com");
      await flush();
      expect(t.mails.map((m) => m.to).sort()).toEqual(["moved@example.com", "mover@example.com"]);
      const link = t.mails.find((m) => m.to === "moved@example.com")!.text.match(/token=([\w-]+)/)![1]!;
      const confirm = new Browser(t);
      expect((await confirm.form("/verify-email", { token: link })).status).toBe(200);
      expect((await (await b.api("GET", "/v1/me")).json() as any).email).toBe("moved@example.com");
    });

    test("an address another account uses is never revealed or taken", async () => {
      await makeUser(t, { username: "taker", password: PW });
      const b = new Browser(t);
      await b.signIn("taker", PW);
      t.mails.length = 0;
      const res = await b.api("PATCH", "/v1/me", { email: "ROOT@example.com" });
      expect(res.status).toBe(200);
      // What the account reads back is the same as for a free address.
      expect((await res.json() as any).email_pending).toBe("ROOT@example.com");
      const free = await (await b.api("PATCH", "/v1/me", { email: "nobody-yet@example.com" })).json() as any;
      expect(free.email_pending).toBe("nobody-yet@example.com");
      await flush();
      expect(t.mails.map((m) => m.subject)).toContain("Your address was used for another account");
      expect(t.mails.some((m) => m.to === "ROOT@example.com" && m.text.includes("verify-email"))).toBe(false);
    });
  });

  describe("★ endpoints for a service's own client", () => {
    let alice: string;
    beforeAll(async () => {
      alice = await makeUser(t, { username: "alice", password: PW, email: "alice@example.com", access: { wiki: "member", tasks: "user" } });
      await makeUser(t, { username: "alicia", password: PW, access: { tasks: "user" } });
    });

    test("search shows only the enabled users with a role on the service, without emails", async () => {
      const res = await asClient("wiki", "GET", "/v1/users?q=ali");
      const body = await res.json() as any;
      expect(body.items).toEqual([{ id: alice, username: "alice", name: "Alice", role: "member" }]);
      expect(JSON.stringify(body)).not.toContain("@");
    });

    test("an email matches only whole, ignoring case, so addresses can't be listed", async () => {
      expect((await (await asClient("wiki", "GET", "/v1/users?q=alice%40")).json() as any).items).toHaveLength(0);
      expect((await (await asClient("wiki", "GET", "/v1/users?q=ALICE%40example.com")).json() as any).items).toHaveLength(1);
    });

    test("LIKE wildcards in q are literal", async () => {
      expect((await (await asClient("wiki", "GET", "/v1/users?q=%25")).json() as any).items).toHaveLength(0);
      expect((await (await asClient("wiki", "GET", "/v1/users?q=_")).json() as any).items).toHaveLength(0);
    });

    test("a disabled user drops out of search", async () => {
      const gone = await makeUser(t, { username: "alfred", password: PW, access: { wiki: "member" } });
      await t.app.sql`UPDATE users SET disabled_at = now() WHERE id = ${gone}`;
      expect((await (await asClient("wiki", "GET", "/v1/users?q=alf")).json() as any).items).toHaveLength(0);
    });

    test("a client changes roles on its own service only", async () => {
      const put = await asClient("wiki", "PUT", `/v1/users/${alice}/access/wiki`, { role: "admin" });
      expect(put.status).toBe(200);
      expect(await put.json() as any).toMatchObject({ service: "wiki", role: "admin", granted_by: "cli_wiki" });
      expect((await asClient("wiki", "PUT", `/v1/users/${alice}/access/tasks`, { role: "user" })).status).toBe(403);
      expect((await asClient("wiki", "PUT", `/v1/users/${alice}/access/auth`, { role: "admin" })).status).toBe(403);
      expect((await asClient("wiki", "PUT", `/v1/users/${alice}/access/wiki`, { role: "superuser" })).status).toBe(400);
      const ev = (await outboxEvents(t.app.sql, "wiki")).filter((e) => e.type === "access.changed" && e.payload.sub === alice);
      expect(ev.at(-1)?.payload).toEqual({ sub: alice, role: "admin" });
      const [a] = await t.app.sql`SELECT actor, detail FROM audit WHERE action = 'access.put' AND user_id = ${alice} ORDER BY id DESC LIMIT 1`;
      expect(a).toMatchObject({ actor: "cli_wiki", detail: { service: "wiki", role: "admin", previous: "member" } });
    });

    test("a client sees only its own access row", async () => {
      const rows = (await (await asClient("wiki", "GET", `/v1/users/${alice}/access`)).json() as any).items;
      expect(rows.map((r: { service: string }) => r.service)).toEqual(["wiki"]);
    });

    test("a service without manages_own_members gets no ★ endpoint", async () => {
      expect((await asClient("tasks", "GET", "/v1/users")).status).toBe(403);
      expect((await asClient("tasks", "PUT", `/v1/users/${alice}/access/tasks`, { role: "user" })).status).toBe(403);
    });

    test("a client can't reach the endpoints without ★", async () => {
      expect((await asClient("wiki", "POST", "/v1/users", { username: "x-user", email: "x@example.com" })).status).toBe(403);
      expect((await asClient("wiki", "GET", `/v1/users/${alice}`)).status).toBe(403);
      expect((await asClient("wiki", "GET", "/v1/audit")).status).toBe(403);
      expect((await asClient("wiki", "GET", "/v1/me")).status).toBe(403);
    });

    test("a wrong secret is invalid_client", async () => {
      const res = await new Browser(t).request("/v1/users", { headers: { Authorization: basic("wiki", "not-the-secret") } });
      expect(res.status).toBe(401);
      expect((await res.json() as any).error).toBe("invalid_client");
    });

    test("removing a role on an open service is a 409; on others it works and tells the app", async () => {
      const { b } = { b: root };
      const open = await b.api("DELETE", `/v1/users/${alice}/access/tasks`);
      expect(open.status).toBe(409);
      expect((await open.json() as any).error).toBe("conflict");
      expect((await asClient("wiki", "DELETE", `/v1/users/${alice}/access/wiki`)).status).toBe(204);
      expect((await asClient("wiki", "DELETE", `/v1/users/${alice}/access/wiki`)).status).toBe(404);
      const ev = (await outboxEvents(t.app.sql, "wiki")).filter((e) => e.payload.sub === alice).at(-1);
      expect(ev).toMatchObject({ type: "access.changed", payload: { sub: alice, role: null } });
    });

    test("invitations: refused on a closed service, accepted without lowering a role, and announced", async () => {
      expect((await root.api("POST", "/v1/invites", { email: "x@example.com", service: "notes", role: "reader" })).status).toBe(409);
      expect((await asClient("wiki", "POST", "/v1/invites", { email: "x@example.com", service: "mailbox", role: "user" })).status).toBe(403);
      const owner = await makeUser(t, { username: "owner1", password: PW, access: { wiki: "owner" } });
      t.mails.length = 0;
      const inv = await asClient("wiki", "POST", "/v1/invites", { email: "owner1@example.com", service: "wiki", role: "member" });
      expect(inv.status).toBe(201);
      const invite = await inv.json() as any;
      expect(invite).toMatchObject({ service: "wiki", role: "member", invited_by: "cli_wiki", accepted_by: null });
      await flush();
      const token = t.mails[0]!.text.match(/token=([\w-]+)/)![1]!;
      // The token is stored as its hash only.
      expect(await t.app.sql`SELECT 1 FROM invites WHERE token_hash = ${sha256(token)}`).toHaveLength(1);

      const b = new Browser(t);
      await b.signIn("owner1", PW);
      const accepted = await b.form("/invite", { token, action: "accept" });
      expect(accepted.status).toBe(200);
      const [row] = await t.app.sql`SELECT role FROM access WHERE user_id = ${owner} AND service = 'wiki'`;
      expect(row.role).toBe("owner");
      const seen = await (await asClient("wiki", "GET", `/v1/invites/${invite.id}`)).json() as any;
      expect(seen.accepted_by).toBe(owner);
      expect((await outboxEvents(t.app.sql, "wiki")).some((e) => e.type === "invite.accepted" && e.payload.invite === invite.id && e.payload.sub === owner)).toBe(true);
      // Used once.
      expect((await b.form("/invite", { token, action: "accept" })).status).toBe(404);
    });

    test("an invitation creates an account with the invited address, verified", async () => {
      t.mails.length = 0;
      await root.api("POST", "/v1/invites", { email: "newbie@example.com", service: "mailbox", role: "user" });
      await flush();
      const token = t.mails[0]!.text.match(/token=([\w-]+)/)![1]!;
      const b = new Browser(t);
      const res = await b.form("/invite", { token, action: "create", username: "newbie", name: "New", password: PW });
      expect(res.status).toBe(303);
      const [u] = await t.app.sql`SELECT email, email_verified_at IS NOT NULL AS v FROM users WHERE username = 'newbie'`;
      expect(u).toEqual({ email: "newbie@example.com", v: true });
      expect((await (await b.api("GET", "/v1/me/access")).json() as any).items.map((i: { service: string }) => i.service)).toEqual(["mailbox"]);
    });

    test("a client reads and deletes only its own service's invitations", async () => {
      const mine = await (await root.api("POST", "/v1/invites", { email: "z@example.com", service: "mailbox", role: "user" })).json() as any;
      expect((await asClient("wiki", "GET", `/v1/invites/${mine.id}`)).status).toBe(404);
      expect((await asClient("wiki", "DELETE", `/v1/invites/${mine.id}`)).status).toBe(404);
      const listed = (await (await asClient("wiki", "GET", "/v1/invites")).json() as any).items;
      expect(listed.every((i: { service: string }) => i.service === "wiki")).toBe(true);
    });
  });

  describe("app passwords, API keys and introspection", () => {
    let carol: string;
    let b: Browser;
    beforeAll(async () => {
      carol = await makeUser(t, { username: "carol", password: PW, access: { mailbox: "user", tasks: "user" } });
      b = new Browser(t);
      await b.signIn("carol", PW);
    });
    const introspect = (clientId: string, secret: string, ip?: string) =>
      new Browser(t).request("/oauth/introspect", {
        method: "POST",
        origin: null,
        headers: { ...client(clientId), "Content-Type": "application/x-www-form-urlencoded", ...(ip ? { "X-Real-IP": ip } : {}) },
        body: new URLSearchParams({ token: secret }).toString(),
      });

    test("an app password is shown once, listed by name, and checked by its own service", async () => {
      const res = await b.api("POST", "/v1/me/app-passwords", { name: "phone", service: "mailbox", scopes: ["imap", "smtp"] });
      expect(res.status).toBe(201);
      const created = await res.json() as any;
      expect(created.password).toMatch(/^[a-z2-7]{4}(-[a-z2-7]{4}){3}$/);
      const listed = await (await b.api("GET", "/v1/me/app-passwords")).json() as any;
      expect(JSON.stringify(listed)).not.toContain(created.password);
      expect(listed.items[0]).toMatchObject({ id: created.id, name: "phone", service: "mailbox", scopes: ["imap", "smtp"] });
      // Nothing of the secret is in the audit log or the request log.
      const audit = await t.app.sql`SELECT detail::text AS d FROM audit`;
      expect(audit.map((r: { d: string }) => r.d).join("\n")).not.toContain(created.password);
      expect(t.logs.join("\n")).not.toContain(created.password);

      const ok = await (await introspect("mailbox", created.password)).json() as any;
      expect(ok).toEqual({ active: true, sub: carol, username: "carol", scope: "imap smtp", role: "user", jti: created.id });
      expect(await (await introspect("wiki", created.password)).json() as any).toEqual({ active: false });
    });

    test("scopes and services are checked when one is made", async () => {
      expect((await b.api("POST", "/v1/me/app-passwords", { name: "x", service: "mailbox", scopes: ["pop3"] })).status).toBe(400);
      expect((await b.api("POST", "/v1/me/app-passwords", { name: "x", service: "mailbox", scopes: [] })).status).toBe(400);
      expect((await b.api("POST", "/v1/me/app-passwords", { name: "x", service: "tasks", scopes: ["tasks:read"] })).status).toBe(400);
      expect((await b.api("POST", "/v1/me/app-passwords", { name: "x", service: "wiki", scopes: ["imap"] })).status).toBe(400);
      expect((await b.api("POST", "/v1/me/api-keys", { name: "x", service: "tasks", scopes: ["tasks:read"], expires_at: "2001-01-01T00:00:00Z" })).status).toBe(400);
    });

    test("an API key carries the deployment's prefix and its id, and expires", async () => {
      const created = await (await b.api("POST", "/v1/me/api-keys", { name: "ci", service: "tasks", scopes: ["tasks:read"] })).json() as any;
      expect(created.key).toStartWith(`testkey_${created.id}_`);
      expect(created.id).toMatch(/^key_/);
      const tasksIntrospect = await (await introspect("tasks", created.key)).json() as any;
      expect(tasksIntrospect).toMatchObject({ active: true, sub: carol, scope: "tasks:read", role: "user", jti: created.id });
      await t.app.sql`UPDATE credentials SET expires_at = now() - interval '1 second' WHERE id = ${created.id}`;
      expect((await (await introspect("tasks", created.key)).json() as any).active).toBe(false);
    });

    test("revoking stops it at once and tells the service", async () => {
      const created = await (await b.api("POST", "/v1/me/app-passwords", { name: "laptop", service: "mailbox", scopes: ["imap"] })).json() as any;
      expect((await b.api("DELETE", `/v1/me/app-passwords/${created.id}`)).status).toBe(204);
      expect((await (await introspect("mailbox", created.password)).json() as any).active).toBe(false);
      const ev = (await outboxEvents(t.app.sql, "mailbox")).find((e) => e.type === "credential.revoked" && e.payload.id === created.id);
      expect(ev?.payload).toEqual({ sub: carol, id: created.id });
      expect((await b.api("DELETE", `/v1/me/app-passwords/${created.id}`)).status).toBe(404);
    });

    test("losing the service role or being disabled stops every credential for it", async () => {
      const created = await (await b.api("POST", "/v1/me/app-passwords", { name: "tablet", service: "mailbox", scopes: ["imap"] })).json() as any;
      await t.app.sql`UPDATE users SET disabled_at = now() WHERE id = ${carol}`;
      expect((await (await introspect("mailbox", created.password)).json() as any).active).toBe(false);
      await t.app.sql`UPDATE users SET disabled_at = NULL WHERE id = ${carol}`;
      expect((await (await introspect("mailbox", created.password)).json() as any).active).toBe(true);
      await t.app.sql`DELETE FROM access WHERE user_id = ${carol} AND service = 'mailbox'`;
      expect((await (await introspect("mailbox", created.password)).json() as any).active).toBe(false);
      await t.app.sql`INSERT INTO access (user_id, service, role, granted_by) VALUES (${carol}, 'mailbox', 'user', 'host-cli')`;
    });

    test("failures are limited per end-user address the client names", async () => {
      for (let i = 0; i < 10; i++) expect((await (await introspect("mailbox", `wrong-${i}`, "203.0.113.50")).json() as any).active).toBe(false);
      const limited = await introspect("mailbox", "wrong-again", "203.0.113.50");
      expect(limited.status).toBe(429);
      expect(Number(limited.headers.get("Retry-After"))).toBeGreaterThan(0);
      // Another address is unaffected.
      expect((await introspect("mailbox", "wrong", "203.0.113.51")).status).toBe(200);
    });

    test("a public client can't introspect", async () => {
      const res = await new Browser(t).request("/oauth/introspect", {
        method: "POST",
        origin: null,
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "client_id=tasks-ios&token=x",
      });
      expect(res.status).toBe(401);
    });
  });

  describe("administration", () => {
    test("creating a person emails an activation link; the link sets the password", async () => {
      t.mails.length = 0;
      const res = await root.api("POST", "/v1/users", { username: "hannah", name: "Hannah", email: "hannah@example.com" });
      expect(res.status).toBe(201);
      const user = await res.json() as any;
      expect(user).toMatchObject({ username: "hannah", kind: "person", email_verified: false, disabled: false });
      await flush();
      const token = t.mails[0]!.text.match(/activate\?token=([\w-]+)/)![1]!;
      const b = new Browser(t);
      expect((await b.form("/activate", { token, password: "password1234" })).status).toBe(400);
      expect((await b.form("/activate", { token, password: PW })).headers.get("Location")).toStartWith("/login?");
      expect((await b.form("/activate", { token, password: PW })).status).toBe(404);
      expect((await new Browser(t).signIn("hannah", PW)).status).toBe(303);
      expect((await root.api("POST", "/v1/users", { username: "hannah", email: "h2@example.com" })).status).toBe(409);
    });

    test("disabling ends sessions, stops refreshes and tells every app", async () => {
      const ivan = await makeUser(t, { username: "ivan", password: PW, access: { wiki: "member" } });
      const b = new Browser(t);
      await b.signIn("ivan", PW);
      const res = await root.api("PATCH", `/v1/users/${ivan}`, { disabled: true });
      expect(res.status).toBe(200);
      expect((await res.json() as any).disabled).toBe(true);
      expect((await b.api("GET", "/v1/me")).status).toBe(401);
      const services = (await outboxEvents(t.app.sql)).filter((e) => e.type === "user.disabled" && e.payload.sub === ivan).map((e) => e.service);
      expect(services.sort()).toEqual(["mailbox", "tasks", "wiki"]);
      expect(t.alerts).toContain("auth: root disabled ivan");
      // The access row stays, and comes back with the user.
      expect(await t.app.sql`SELECT role FROM access WHERE user_id = ${ivan}`).toEqual([{ role: "member" }]);
      expect(await t.app.sql`SELECT 1 FROM sessions WHERE user_id = ${ivan}`).toHaveLength(0);
      await root.api("PATCH", `/v1/users/${ivan}`, { disabled: false });
      // The old session ended rather than being hidden: it stays signed out.
      expect((await b.api("GET", "/v1/me")).status).toBe(401);
      expect((await new Browser(t).signIn("ivan", PW)).status).toBe(303);
    });

    test("bot users hold credentials an admin makes for them; a person's are their own", async () => {
      const bot = await (await root.api("POST", "/v1/users", { username: "build-bot", kind: "bot" })).json() as any;
      expect(bot).toMatchObject({ kind: "bot", owner_id: rootId, email: null });
      await root.api("PUT", `/v1/users/${bot.id}/access/mailbox`, { role: "user" });
      const pw = await root.api("POST", `/v1/users/${bot.id}/app-passwords`, { name: "smtp relay", service: "mailbox", scopes: ["smtp"] });
      expect(pw.status).toBe(201);
      const { password } = await pw.json() as any;
      const check = await new Browser(t).request("/oauth/introspect", {
        method: "POST",
        origin: null,
        headers: { ...client("mailbox"), "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ token: password }).toString(),
      });
      expect(await check.json() as any).toMatchObject({ active: true, username: "build-bot", scope: "smtp" });
      const person = (await (await root.api("GET", "/v1/users?q=carol")).json() as any).items[0];
      expect((await root.api("POST", `/v1/users/${person.id}/app-passwords`, { name: "x", service: "mailbox", scopes: ["imap"] })).status).toBe(409);
      // A bot can't sign in.
      expect((await new Browser(t).form("/login", { login: "build-bot", password: "" })).status).toBe(401);
      // Its owner can't be deleted while it exists.
      expect((await root.api("DELETE", `/v1/users/${rootId}`)).status).toBe(409);
    });

    test("deleting a user erases them and tells every app", async () => {
      const gone = await makeUser(t, { username: "gone", password: PW, access: { wiki: "member" } });
      expect((await root.api("DELETE", `/v1/users/${gone}`)).status).toBe(204);
      expect(await t.app.sql`SELECT 1 FROM users WHERE id = ${gone}`).toHaveLength(0);
      const services = (await outboxEvents(t.app.sql)).filter((e) => e.type === "user.deleted" && e.payload.sub === gone).map((e) => e.service);
      expect(services.sort()).toEqual(["mailbox", "tasks", "wiki"]);
      // The audit log outlives them.
      expect((await t.app.sql`SELECT 1 FROM audit WHERE user_id = ${gone} AND action = 'user.delete'`).length).toBe(1);
    });

    test("clearing MFA is audited, alerted and emailed, and signs the user out", async () => {
      const { b, id } = await adminBrowser("lostphone");
      t.alerts.length = 0;
      t.mails.length = 0;
      expect((await root.api("POST", `/v1/users/${id}/reset`, { clear_mfa: true, send_link: true })).status).toBe(204);
      expect(await t.app.sql`SELECT 1 FROM totp WHERE user_id = ${id}`).toHaveLength(0);
      expect((await b.api("GET", "/v1/me")).status).toBe(401);
      expect(t.alerts.join("\n")).toContain("cleared the MFA of lostphone");
      await flush();
      expect(t.mails.map((m) => m.subject).sort()).toEqual(["Reset your password", "Security notice: two-factor authentication was cleared by an administrator"]);
      const actions = (await t.app.sql`SELECT action FROM audit WHERE user_id = ${id} ORDER BY id DESC LIMIT 2`).map((r: { action: string }) => r.action);
      expect(actions.sort()).toEqual(["mfa.cleared", "reset.sent"]);
    });

    test("granting auth:admin is alerted", async () => {
      const x = await makeUser(t, { username: "promoted", password: PW });
      t.alerts.length = 0;
      await root.api("PUT", `/v1/users/${x}/access/auth`, { role: "admin" });
      expect(t.alerts).toEqual([`auth: ${x} was given auth:admin by ${rootId}`]);
    });

    test("the audit log reads newest first, a page at a time", async () => {
      const first = await (await root.api("GET", "/v1/audit?limit=2")).json() as any;
      expect(first.items).toHaveLength(2);
      expect(Number(first.items[0].id)).toBeGreaterThan(Number(first.items[1].id));
      const next = await (await root.api("GET", `/v1/audit?limit=2&after=${first.next}`)).json() as any;
      expect(Number(next.items[0].id)).toBeLessThan(Number(first.items[1].id));
      expect((await root.api("GET", "/v1/audit?limit=101")).status).toBe(400);
    });

    test("self-service deletion is off unless the deployment allows it", async () => {
      await makeUser(t, { username: "leaver", password: PW });
      const b = new Browser(t);
      await b.signIn("leaver", PW);
      expect((await b.api("DELETE", "/v1/me")).status).toBe(403);
    });
  });
});

describe.skipIf(!TEST_DATABASE_URL)("self-service deletion, where allowed (U14)", () => {
  let db: TestDb;
  let t: TestApp;
  beforeAll(async () => {
    db = await testDb();
    t = await testApp(db.sql, { ALLOW_ACCOUNT_DELETION: "true" });
  });
  afterAll(() => db.drop());

  test("needs a recent sign-in, erases the account and tells every app", async () => {
    const id = await makeUser(t, { username: "leaver", password: "correct horse battery" });
    const b = new Browser(t);
    await b.signIn("leaver", "correct horse battery");
    await t.app.sql`UPDATE sessions SET auth_time = now() - interval '16 minutes'`;
    expect((await b.api("DELETE", "/v1/me")).status).toBe(403);
    await t.app.sql`UPDATE sessions SET auth_time = now()`;
    expect((await b.api("DELETE", "/v1/me")).status).toBe(204);
    expect(await t.app.sql`SELECT 1 FROM users WHERE id = ${id}`).toHaveLength(0);
    expect((await outboxEvents(t.app.sql)).filter((e) => e.type === "user.deleted").length).toBe(3);
  });
});
