import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { randomBytes } from "node:crypto";
import { basic, type Browser, enabled, ID, linkIn, newId, pkce, authorizeParams, REDIRECTS, backChannel, sha256, Stack, type TestUser } from "./harness";

// The administration half of the management API (docs/DESIGN.md §6, §7.5,
// §7.7): users, their access, sessions and resets, a bot's credentials,
// invitations and the audit log, for each kind of caller an endpoint takes
// and refuses.

setDefaultTimeout(30_000);

// ------------------------------------------------------------------ helpers

const ISO = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;

// A unique username (and so a unique name and email prefix) for one test.
function uname(prefix = "u"): string {
  return `${prefix}${randomBytes(4).toString("hex")}`;
}

async function expectError(res: Response, status: number, error: string, description: string): Promise<void> {
  expect({ status: res.status, body: await res.json() }).toEqual({ status, body: { error, error_description: description } });
}

async function bodyOf(res: Response, status: number): Promise<any> {
  const text = await res.text();
  if (res.status !== status) throw new Error(`expected ${status}, got ${res.status}: ${text}`);
  return text ? JSON.parse(text) : null;
}

describe.skipIf(!enabled)("administration API", () => {
  let stack: Stack;
  let admin: { user: TestUser; browser: Browser };
  let root: Browser;
  let rootName: string;

  // A call by a service's own client, with HTTP Basic.
  function asClient(clientId: string, method: string, path: string, body?: unknown, secret?: string): Promise<Response> {
    const headers: Record<string, string> = { Authorization: basic(clientId, secret ?? stack.secrets[clientId]!) };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    return fetch(`${stack.url}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: "manual" });
  }

  const alert = async (text: string) => {
    expect(await stack.http.waitForAlert(text)).toBe(text);
  };
  const adminAlert = (text: string) => alert(`auth: ${rootName} ${text}`);

  // Audit rows of one action for one subject, oldest first.
  const auditOf = async (action: string, userId?: string) => (await stack.audit(action)).filter((r) => userId === undefined || r.user_id === userId);

  beforeAll(async () => {
    stack = await Stack.start();
    admin = await stack.admin();
    root = admin.browser;
    rootName = admin.user.username;
  });
  afterAll(async () => {
    await stack.stop();
  });
  beforeEach(async () => {
    await stack.resetLimits();
  });

  // ---------------------------------------------------------------- callers

  describe("callers", () => {
    let target: TestUser;
    let bot: TestUser;
    let plain: Browser;
    let half: Browser;

    beforeAll(async () => {
      target = await stack.user({ username: uname("target"), access: { wiki: "member" } });
      bot = await stack.user({ username: uname("bot"), kind: "bot", ownerId: admin.user.id, access: { mailbox: "user", tasks: "user" } });
      // A person with a second factor, but no auth:admin.
      const person = await stack.user({ username: uname("plain"), totp: true, access: { wiki: "owner" } });
      plain = await stack.session(person, { amr: ["pwd", "otp", "mfa"] });
      // An auth:admin whose session used the password alone.
      const halfAdmin = await stack.user({ username: uname("half"), access: { auth: "admin" }, totp: true });
      half = await stack.session(halfAdmin, { amr: ["pwd"] });
    });

    type Endpoint = { method: string; path: () => string; body?: unknown; star: boolean; label?: string };
    const endpoints = (): Endpoint[] => [
      { method: "GET", path: () => "/v1/users", star: true },
      { method: "POST", path: () => "/v1/users", body: { username: "matrix-user", name: "M", email: "matrix-user@example.com" }, star: false },
      { method: "GET", path: () => `/v1/users/${target.id}`, star: false },
      { method: "PATCH", path: () => `/v1/users/${target.id}`, body: { name: "Changed" }, star: false },
      { method: "DELETE", path: () => `/v1/users/${target.id}`, star: false },
      { method: "GET", path: () => `/v1/users/${target.id}/access`, star: true },
      { method: "PUT", path: () => `/v1/users/${target.id}/access/wiki`, body: { role: "owner" }, star: true },
      { method: "DELETE", path: () => `/v1/users/${target.id}/access/wiki`, star: true },
      { method: "DELETE", path: () => `/v1/users/${target.id}/sessions`, star: false },
      { method: "POST", path: () => `/v1/users/${target.id}/reset`, body: { send_link: true, clear_mfa: true }, star: false },
      { method: "GET", path: () => `/v1/users/${bot.id}/app-passwords`, star: false },
      { method: "POST", path: () => `/v1/users/${bot.id}/app-passwords`, body: { name: "x", service: "mailbox", scopes: ["imap"] }, star: false },
      { method: "DELETE", path: () => `/v1/users/${bot.id}/app-passwords/${newId("apw")}`, star: false },
      { method: "GET", path: () => `/v1/users/${bot.id}/api-keys`, star: false },
      { method: "POST", path: () => `/v1/users/${bot.id}/api-keys`, body: { name: "x", service: "tasks", scopes: ["tasks:read"] }, star: false },
      { method: "DELETE", path: () => `/v1/users/${bot.id}/api-keys/${newId("key")}`, star: false },
      { method: "GET", path: () => "/v1/invites", star: true },
      { method: "POST", path: () => "/v1/invites", body: { email: "matrix@example.com", service: "wiki", role: "member" }, star: true },
      { method: "GET", path: () => `/v1/invites/${newId("inv")}`, star: true },
      { method: "DELETE", path: () => `/v1/invites/${newId("inv")}`, star: true },
      { method: "GET", path: () => "/v1/audit", star: false },
    ];
    // Labels are made before the fixtures exist.
    const label = (e: Endpoint) => {
      target ??= { id: "usr_…" } as TestUser;
      bot ??= { id: "usr_…" } as TestUser;
      return `${e.method} ${e.path().replace(/(usr|apw|key|inv)_[\w…]+/g, "$1_…")}`;
    };
    const send = (b: Browser, e: Endpoint) => b.api(e.method, e.path(), e.body);

    test.each(endpoints().map((e) => [label(e), e] as const))("nobody: %s answers 401", async (_, e) => {
      const res = await fetch(`${stack.url}${e.path()}`, {
        method: e.method,
        headers: e.body === undefined ? {} : { "Content-Type": "application/json", Origin: stack.issuer },
        body: e.body === undefined ? undefined : JSON.stringify(e.body),
      });
      await expectError(res, 401, "unauthorized", "Sign in first.");
    });

    test.each(endpoints().map((e) => [label(e), e] as const))("a signed-in user without auth:admin: %s answers 403", async (_, e) => {
      await expectError(await send(plain, e), 403, "forbidden", "This needs the auth admin role.");
    });

    test.each(endpoints().map((e) => [label(e), e] as const))("an admin whose session used no second factor: %s answers 403", async (_, e) => {
      await expectError(await send(half, e), 403, "forbidden", "Admin actions need a sign-in with a second factor.");
    });

    test.each(endpoints().map((e) => [label(e), e] as const))("a client with a wrong secret: %s answers 401 invalid_client", async (_, e) => {
      const res = await asClient("wiki", e.method, e.path(), e.body, "not-the-secret");
      expect(res.headers.get("WWW-Authenticate")).toBe('Basic realm="auth"');
      await expectError(res, 401, "invalid_client", "Client authentication failed.");
    });

    test.each(endpoints().map((e) => [label(e), e] as const))("the client of a service without manages_own_members: %s answers 403", async (_, e) => {
      await expectError(await asClient("tasks", e.method, e.path(), e.body), 403, "forbidden", "This endpoint is not open to a service's client.");
    });

    test.each(endpoints().filter((e) => !e.star).map((e) => [label(e), e] as const))("a managing client on an endpoint without ★: %s answers 403", async (_, e) => {
      await expectError(await asClient("wiki", e.method, e.path(), e.body), 403, "forbidden", "This endpoint is not open to a service's client.");
    });

    test("none of the refused calls changed anything", async () => {
      const [row] = await stack.db`SELECT name, disabled_at FROM users WHERE id = ${target.id}`;
      expect(row).toEqual({ name: target.name, disabled_at: null });
      expect(await stack.db`SELECT role FROM access WHERE user_id = ${target.id}`).toEqual([{ role: "member" }]);
      expect(await stack.db`SELECT 1 FROM users WHERE username = 'matrix-user'`).toHaveLength(0);
      expect(await stack.db`SELECT 1 FROM invites WHERE email = 'matrix@example.com'`).toHaveLength(0);
      expect(await stack.db`SELECT 1 FROM credentials WHERE user_id = ${bot.id}`).toHaveLength(0);
    });

    test.each([
      ["a Bearer token", "Bearer abc123"],
      ["Basic without a colon", `Basic ${Buffer.from("wiki").toString("base64")}`],
      ["Basic that is not base64", "Basic ***"],
      ["a public client's id", basic("tasks-ios", "anything")],
      ["an unknown client", basic("nobody", "anything")],
      ["an empty secret", basic("wiki", "")],
    ])("an Authorization header with %s is invalid_client, even on a ★ endpoint", async (_, header) => {
      const res = await fetch(`${stack.url}/v1/users`, { headers: { Authorization: header } });
      expect(res.headers.get("WWW-Authenticate")).toBe('Basic realm="auth"');
      await expectError(res, 401, "invalid_client", "Client authentication failed.");
    });

    test("Authorization wins over a session cookie", async () => {
      const res = await root.request("/v1/audit", { headers: { Authorization: stack.basic("wiki") } });
      await expectError(res, 403, "forbidden", "This endpoint is not open to a service's client.");
    });

    test("a change needs the CSRF token and this issuer's Origin; a read doesn't", async () => {
      const path = `/v1/users/${target.id}`;
      await expectError(await root.api("PATCH", path, { name: "Changed" }, { "X-CSRF-Token": "" }), 403, "forbidden", "The CSRF token is missing or wrong.");
      await expectError(await root.api("PATCH", path, { name: "Changed" }, { "X-CSRF-Token": "abc123" }), 403, "forbidden", "The CSRF token is missing or wrong.");
      await expectError(await root.api("PATCH", path, { name: "Changed" }, {}, { origin: "https://evil.example.com" }), 403, "forbidden", "The request's Origin is not this issuer.");
      await expectError(await root.api("PATCH", path, { name: "Changed" }, {}, { origin: null }), 403, "forbidden", "The request's Origin is not this issuer.");
      expect((await root.api("GET", path)).status).toBe(200);
      expect((await stack.db`SELECT name FROM users WHERE id = ${target.id}`)[0].name).toBe(target.name);
    });

    test("a session that is not an admin's any more, or of a disabled admin, is refused", async () => {
      const gone = await stack.admin(uname("demoted"));
      await stack.db`DELETE FROM access WHERE user_id = ${gone.user.id}`;
      await expectError(await gone.browser.api("GET", "/v1/audit"), 403, "forbidden", "This needs the auth admin role.");
      const off = await stack.admin(uname("off"));
      await stack.db`UPDATE users SET disabled_at = now() WHERE id = ${off.user.id}`;
      await expectError(await off.browser.api("GET", "/v1/audit"), 401, "unauthorized", "Sign in first.");
    });

    test("an expired session is nobody", async () => {
      const u = await stack.user({ username: uname("exp"), access: { auth: "admin" }, totp: true });
      const b = await stack.session(u, { amr: ["pwd", "otp", "mfa"], expiresIn: "-1 second" });
      await expectError(await b.api("GET", "/v1/audit"), 401, "unauthorized", "Sign in first.");
    });
  });

  // ------------------------------------------------------------------ lists

  describe("GET /v1/users", () => {
    test("an admin sees each user whole, in id order", async () => {
      const tag = uname("ls");
      const a = await stack.user({ username: `${tag}-a`, name: "Ann", access: { wiki: "member" } });
      const b = await stack.user({ username: `${tag}-b`, kind: "bot", ownerId: a.id, disabled: true });
      const body = await bodyOf(await root.api("GET", `/v1/users?q=${tag}`), 200);
      expect(body.next).toBeNull();
      expect(body.items).toHaveLength(2);
      expect(body.items[0]).toEqual({
        id: a.id,
        username: a.username,
        name: "Ann",
        email: `${a.username}@example.com`,
        email_verified: true,
        kind: "person",
        owner_id: null,
        disabled: false,
        created_at: expect.stringMatching(ISO),
      });
      expect(body.items[1]).toEqual({
        id: b.id,
        username: b.username,
        name: b.name,
        email: null,
        email_verified: false,
        kind: "bot",
        owner_id: a.id,
        disabled: true,
        created_at: expect.stringMatching(ISO),
      });
    });

    describe("pages", () => {
      let tag: string;
      let ids: string[];
      beforeAll(async () => {
        tag = uname("pg");
        ids = [];
        for (let i = 0; i < 51; i++) ids.push((await stack.user({ username: `${tag}-${String(i).padStart(2, "0")}`, password: null })).id);
        ids.sort();
      });

      test("50 by default, with the last id as the cursor", async () => {
        const first = await bodyOf(await root.api("GET", `/v1/users?q=${tag}`), 200);
        expect(first.items.map((u: any) => u.id)).toEqual(ids.slice(0, 50));
        expect(first.next).toBe(ids[49]);
        const second = await bodyOf(await root.api("GET", `/v1/users?q=${tag}&after=${first.next}`), 200);
        expect(second).toEqual({ items: [expect.objectContaining({ id: ids[50] })], next: null });
      });

      test.each([
        ["1", 1, true],
        ["050", 50, true],
        ["51", 51, false],
        ["100", 51, false],
      ])("limit=%s", async (limit, count, more) => {
        const body = await bodyOf(await root.api("GET", `/v1/users?q=${tag}&limit=${limit}`), 200);
        expect(body.items).toHaveLength(count);
        expect(body.next).toBe(more ? ids[count - 1]! : null);
      });

      test("a repeated limit takes the first", async () => {
        const body = await bodyOf(await root.api("GET", `/v1/users?q=${tag}&limit=2&limit=500`), 200);
        expect(body.items).toHaveLength(2);
      });

      test.each(["0", "101", "-1", "abc", "1.5", "", "0050", "1e2", "%205", "999"])("limit=%s is refused", async (limit) => {
        await expectError(await root.api("GET", `/v1/users?q=${tag}&limit=${limit}`), 400, "invalid_request", "limit is 1 to 100.");
      });

      test("a cursor of 64 characters is read; one of 65 is refused", async () => {
        const ok = await bodyOf(await root.api("GET", `/v1/users?q=${tag}&after=${"z".repeat(64)}`), 200);
        expect(ok).toEqual({ items: [], next: null });
        await expectError(await root.api("GET", `/v1/users?q=${tag}&after=${"z".repeat(65)}`), 400, "invalid_request", "after is not a cursor.");
      });

      test("a cursor that is not an id lists what sorts after it", async () => {
        const body = await bodyOf(await root.api("GET", `/v1/users?q=${tag}&after=a&limit=1`), 200);
        expect(body.items[0].id).toBe(ids[0]);
      });

      test("a client's list pages the same way", async () => {
        const ctag = uname("cp");
        const made: string[] = [];
        for (let i = 0; i < 3; i++) made.push((await stack.user({ username: `${ctag}-${i}`, password: null, access: { wiki: "member" } })).id);
        made.sort();
        const first = await bodyOf(await asClient("wiki", "GET", `/v1/users?q=${ctag}&limit=2`), 200);
        expect(first.items.map((u: any) => u.id)).toEqual(made.slice(0, 2));
        expect(first.next).toBe(made[1]);
        const second = await bodyOf(await asClient("wiki", "GET", `/v1/users?q=${ctag}&limit=2&after=${first.next}`), 200);
        expect(second.items.map((u: any) => u.id)).toEqual(made.slice(2));
        expect(second.next).toBeNull();
        await expectError(await asClient("wiki", "GET", "/v1/users?limit=0"), 400, "invalid_request", "limit is 1 to 100.");
        await expectError(await asClient("wiki", "GET", `/v1/users?after=${"z".repeat(65)}`), 400, "invalid_request", "after is not a cursor.");
      });
    });

    describe("search", () => {
      let tag: string;
      let byName: Record<string, TestUser>;
      beforeAll(async () => {
        tag = uname("sq");
        byName = {
          percent: await stack.user({ username: `${tag}-p`, name: "Hundred% Sure", email: `hp-${tag}@example.com`, access: { wiki: "member" } }),
          underscore: await stack.user({ username: `${tag}-u`, name: "Snake_Case", email: `hu-${tag}@example.com`, access: { wiki: "admin" } }),
          backslash: await stack.user({ username: `${tag}-b`, name: "Back\\Slash", email: `hb-${tag}@example.com`, access: { tasks: "user" } }),
          plain: await stack.user({ username: `${tag}-x`, name: "Hundreds", email: `Mixed.${tag}@Example.com`, access: { wiki: "member" } }),
          disabled: await stack.user({ username: `${tag}-d`, name: "Gone", email: `hd-${tag}@example.com`, access: { wiki: "member" }, disabled: true }),
        };
      });
      const usernames = (body: any) => body.items.map((u: any) => u.username).sort();
      const admin = async (q: string) => usernames(await bodyOf(await root.api("GET", `/v1/users?q=${encodeURIComponent(q)}`), 200));
      const client = async (q: string) => bodyOf(await asClient("wiki", "GET", `/v1/users?q=${encodeURIComponent(q)}`), 200);

      test("an admin's q matches the start of a username, ignoring case and the spaces around it", async () => {
        const all = [`${tag}-b`, `${tag}-d`, `${tag}-p`, `${tag}-u`, `${tag}-x`];
        expect(await admin(tag)).toEqual(all);
        expect(await admin(tag.toUpperCase())).toEqual(all);
        expect(await admin(`  ${tag}  `)).toEqual(all);
        expect(await admin(`${tag}-p`)).toEqual([`${tag}-p`]);
        // Not the middle of one.
        expect(await admin(tag.slice(1))).toEqual([]);
      });

      test("an admin's q matches the start of a name or an email, ignoring case", async () => {
        expect(await admin(`hp-${tag}@exa`)).toEqual([`${tag}-p`]);
        expect(await admin(`MIXED.${tag}@example.COM`)).toEqual([`${tag}-x`]);
        expect(await admin(`mixed.${tag}`)).toEqual([`${tag}-x`]);
      });

      test("LIKE's metacharacters in an admin's q are matched literally", async () => {
        const users = await bodyOf(await root.api("GET", `/v1/users?q=${encodeURIComponent("hundred%")}`), 200);
        expect(users.items.map((u: any) => u.username)).toContain(`${tag}-p`);
        expect(users.items.map((u: any) => u.username)).not.toContain(`${tag}-x`);
        const under = await bodyOf(await root.api("GET", `/v1/users?q=${encodeURIComponent("snake_")}`), 200);
        expect(under.items.map((u: any) => u.username)).toContain(`${tag}-u`);
        const notWild = await bodyOf(await root.api("GET", `/v1/users?q=${encodeURIComponent("snak_")}`), 200);
        expect(notWild.items.map((u: any) => u.username)).not.toContain(`${tag}-u`);
        const back = await bodyOf(await root.api("GET", `/v1/users?q=${encodeURIComponent("back\\")}`), 200);
        expect(back.items.map((u: any) => u.username)).toContain(`${tag}-b`);
        const backNot = await bodyOf(await root.api("GET", `/v1/users?q=${encodeURIComponent("back\\s")}`), 200);
        expect(backNot.items.map((u: any) => u.username)).toContain(`${tag}-b`);
        const pct = await bodyOf(await root.api("GET", `/v1/users?q=${encodeURIComponent("%")}`), 200);
        expect(pct.items.map((u: any) => u.username)).not.toContain(`${tag}-p`);
      });

      test("a client sees only the enabled users with a role on its service, as {id, username, name, role}", async () => {
        const body = await client(tag);
        expect(body.next).toBeNull();
        expect(body.items).toEqual([
          { id: byName.percent!.id, username: `${tag}-p`, name: "Hundred% Sure", role: "member" },
          { id: byName.underscore!.id, username: `${tag}-u`, name: "Snake_Case", role: "admin" },
          { id: byName.plain!.id, username: `${tag}-x`, name: "Hundreds", role: "member" },
        ].sort((a, b) => (a.id < b.id ? -1 : 1)));
        expect(JSON.stringify(body)).not.toContain("@");
      });

      test("a client's q matches the start of a username or name, or a whole email ignoring case", async () => {
        expect(usernames(await client(`${tag}-u`))).toEqual([`${tag}-u`]);
        expect(usernames(await client(tag.toUpperCase()))).toHaveLength(3);
        expect(usernames(await client("snake_c"))).toEqual(expect.arrayContaining([`${tag}-u`]));
        // An email only whole.
        expect(usernames(await client(`mixed.${tag}@example`))).toEqual([]);
        expect(usernames(await client(`mixed.${tag}`))).toEqual([]);
        expect(usernames(await client(`MIXED.${tag}@EXAMPLE.COM`))).toEqual([`${tag}-x`]);
        expect(usernames(await client(`  mixed.${tag}@example.com `))).toEqual([`${tag}-x`]);
        // Not another service's user, nor a disabled one, by any field.
        expect(usernames(await client(`hb-${tag}@example.com`))).toEqual([]);
        expect(usernames(await client(`hd-${tag}@example.com`))).toEqual([]);
        expect(usernames(await client(`${tag}-d`))).toEqual([]);
      });

      test("LIKE's metacharacters in a client's q are matched literally", async () => {
        expect(usernames(await client("hundred%"))).toEqual([`${tag}-p`]);
        expect(usernames(await client("snak_"))).toEqual([]);
        expect((await client("%")).items).toEqual([]);
        expect((await client("_")).items).toEqual([]);
        expect((await client("\\")).items).toEqual([]);
      });

      test("a client of another service sees its own users only", async () => {
        const body = await bodyOf(await asClient("mailbox", "GET", `/v1/users?q=${tag}`), 200);
        expect(body).toEqual({ items: [], next: null });
      });
    });
  });

  // ------------------------------------------------------------------ users

  describe("POST /v1/users", () => {
    test("a person: 201 with the new user, an activation email, an audit row and an alert", async () => {
      const username = uname("new");
      const res = await root.api("POST", "/v1/users", { username, name: "  New Person  ", email: ` ${username}@Example.com ` });
      const user = await bodyOf(res, 201);
      expect(user).toEqual({
        id: expect.stringMatching(ID),
        username,
        name: "New Person",
        email: `${username}@Example.com`,
        email_verified: false,
        kind: "person",
        owner_id: null,
        disabled: false,
        created_at: expect.stringMatching(ISO),
      });
      expect(user.id).toStartWith("usr_");
      const [row] = await stack.db`SELECT password_hash, email_verified_at FROM users WHERE id = ${user.id}`;
      expect(row).toEqual({ password_hash: null, email_verified_at: null });

      const mail = await stack.smtp.waitFor(`${username}@Example.com`, (m) => m.subject === "Activate your account");
      expect(mail.text).toContain(`An account with the username "${username}" was created for you.`);
      const link = linkIn(mail);
      expect(`${link.origin}${link.pathname}`).toBe(`${stack.issuer}/activate`);
      expect((await fetch(link)).status).toBe(200);
      const tokens = await stack.db`SELECT purpose, email FROM one_time_tokens WHERE user_id = ${user.id}`;
      expect(tokens).toEqual([{ purpose: "activate", email: `${username}@Example.com` }]);

      const [a] = await auditOf("user.create", user.id);
      expect(a).toMatchObject({ actor: admin.user.id, ip: root.ip, detail: { username, kind: "person" } });
      await adminAlert(`created the person ${username}`);
    });

    test("a bot: no email, owned by the calling admin unless named, no activation email", async () => {
      const username = uname("bot");
      const bot = await bodyOf(await root.api("POST", "/v1/users", { username, kind: "bot" }), 201);
      expect(bot).toMatchObject({ username, name: "", email: null, email_verified: false, kind: "bot", owner_id: admin.user.id });
      await adminAlert(`created the bot ${username}`);
      const [a] = await auditOf("user.create", bot.id);
      expect(a!.detail).toEqual({ username, kind: "bot" });
      expect(await stack.db`SELECT 1 FROM one_time_tokens WHERE user_id = ${bot.id}`).toHaveLength(0);

      const owner = await stack.user({ username: uname("own") });
      const owned = await bodyOf(await root.api("POST", "/v1/users", { username: uname("bot"), kind: "bot", email: null, owner_id: owner.id }), 201);
      expect(owned.owner_id).toBe(owner.id);
    });

    test("a person's owner_id is ignored", async () => {
      const username = uname("np");
      const user = await bodyOf(await root.api("POST", "/v1/users", { username, email: `${username}@example.com`, owner_id: admin.user.id }), 201);
      expect(user.owner_id).toBeNull();
    });

    const USERNAME_RULE = "A username is 3 to 32 characters: a–z, 0–9 and '-', starting with a letter and not ending with '-'.";
    test.each([
      ["missing", undefined],
      ["null", null],
      ["a number", 123],
      ["an array", ["abc"]],
      ["2 characters", "ab"],
      ["33 characters", `a${"b".repeat(32)}`],
      ["a capital", "Alice"],
      ["a leading digit", "1abc"],
      ["a trailing dash", "abc-"],
      ["an underscore", "ab_c"],
      ["a non-ASCII letter", "abç"],
      ["a space", "ab c"],
    ])("a username that is %s is refused", async (_, username) => {
      await expectError(await root.api("POST", "/v1/users", { username, email: "x@example.com" }), 400, "invalid_request", USERNAME_RULE);
    });

    test("usernames of 3 and of 32 characters are taken", async () => {
      const short = `${String.fromCharCode(97 + Math.floor(Math.random() * 26))}${randomBytes(1).toString("hex")}`;
      const res = await root.api("POST", "/v1/users", { username: short, kind: "bot" });
      // A 3-character name may already exist from another run in this schema: either way, not a 400.
      expect([201, 409]).toContain(res.status);
      const long = `l${randomBytes(15).toString("hex")}a`;
      expect(long).toHaveLength(32);
      expect((await root.api("POST", "/v1/users", { username: long, kind: "bot" })).status).toBe(201);
    });

    const NAME_RULE = "A name is at most 200 characters, with no control characters.";
    test.each([
      ["a number", 5],
      ["an object", {}],
      ["201 characters", "n".repeat(201)],
      ["201 emoji", "😀".repeat(201)],
      ["a newline", "a\nb"],
      ["a tab", "a\tb"],
      ["a DEL", "a\u007fb"],
      ["a NUL", "a\u0000b"],
    ])("a name that is %s is refused", async (_, name) => {
      await expectError(await root.api("POST", "/v1/users", { username: uname("n"), name, kind: "bot" }), 400, "invalid_request", NAME_RULE);
    });

    test.each([
      ["missing", undefined, ""],
      ["null", null, ""],
      ["200 characters", "n".repeat(200), "n".repeat(200)],
      ["200 emoji", "😀".repeat(200), "😀".repeat(200)],
      ["padded", "  Ada  ", "Ada"],
    ])("a name that is %s is taken", async (_, name, stored) => {
      const user = await bodyOf(await root.api("POST", "/v1/users", { username: uname("n"), name, kind: "bot" }), 201);
      expect(user.name).toBe(stored);
    });

    test.each([
      ["robot", "robot"],
      ["null", null],
      ["a number", 1],
      ["capitalised", "Bot"],
    ])("a kind that is %s is refused", async (_, kind) => {
      await expectError(await root.api("POST", "/v1/users", { username: uname("k"), email: "k@example.com", kind }), 400, "invalid_request", 'kind is "person" or "bot".');
    });

    test.each([
      ["missing", undefined],
      ["null", null],
      ["a number", 5],
      ["empty", ""],
      ["without an @", "nobody.example.com"],
      ["with two @", "a@b@example.com"],
      ["a bare host", "a@localhost"],
      ["255 characters", `${"a".repeat(64)}@${"b".repeat(186)}.com`],
    ])("a person's email that is %s is refused", async (_, email) => {
      await expectError(await root.api("POST", "/v1/users", { username: uname("e"), email }), 400, "invalid_request", "That is not an email address.");
    });

    test.each([
      ["an address", "bot@example.com"],
      ["an empty string", ""],
    ])("a bot with an email (%s) is refused", async (_, email) => {
      await expectError(await root.api("POST", "/v1/users", { username: uname("b"), kind: "bot", email }), 400, "invalid_request", "A bot user has no email.");
    });

    test("a bot's owner must be a person who exists", async () => {
      await expectError(await root.api("POST", "/v1/users", { username: uname("b"), kind: "bot", owner_id: newId("usr") }), 404, "not_found", "No such user.");
      await expectError(await root.api("POST", "/v1/users", { username: uname("b"), kind: "bot", owner_id: "nope" }), 404, "not_found", "No such user.");
      await expectError(await root.api("POST", "/v1/users", { username: uname("b"), kind: "bot", owner_id: 42 }), 404, "not_found", "No such user.");
      const other = await stack.user({ username: uname("ob"), kind: "bot", ownerId: admin.user.id });
      await expectError(await root.api("POST", "/v1/users", { username: uname("b"), kind: "bot", owner_id: other.id }), 400, "invalid_request", "A bot's owner is a person.");
    });

    test("the fields are checked in order: username, name, kind, then the email or owner", async () => {
      await expectError(await root.api("POST", "/v1/users", { username: "X", name: 5, kind: "x", email: "x" }), 400, "invalid_request", USERNAME_RULE);
      await expectError(await root.api("POST", "/v1/users", { username: uname("o"), name: 5, kind: "x", email: "x" }), 400, "invalid_request", NAME_RULE);
      await expectError(await root.api("POST", "/v1/users", { username: uname("o"), kind: "x", email: "x" }), 400, "invalid_request", 'kind is "person" or "bot".');
    });

    test("a taken username or email is a conflict, the email ignoring case, and nothing is written", async () => {
      const existing = await stack.user({ username: uname("taken") });
      const before = (await stack.audit("user.create")).length;
      await expectError(
        await root.api("POST", "/v1/users", { username: existing.username, email: `${uname("fresh")}@example.com` }),
        409,
        "conflict",
        "That username is taken.",
      );
      await expectError(
        await root.api("POST", "/v1/users", { username: uname("fresh"), email: existing.email!.toUpperCase() }),
        409,
        "conflict",
        "Another account uses that email address.",
      );
      expect((await stack.audit("user.create")).length).toBe(before);
    });

    test("the body must be a JSON object sent as application/json", async () => {
      await expectError(await root.api("POST", "/v1/users", "{", {}), 400, "invalid_request", "The body is not valid JSON.");
      await expectError(await root.api("POST", "/v1/users", "[]", {}), 400, "invalid_request", "The body must be a JSON object.");
      await expectError(await root.api("POST", "/v1/users", "null", {}), 400, "invalid_request", "The body must be a JSON object.");
      await expectError(await root.api("POST", "/v1/users", '"x"', {}), 400, "invalid_request", "The body must be a JSON object.");
      await expectError(await root.api("POST", "/v1/users", "username=x", { "Content-Type": "application/x-www-form-urlencoded" }), 415, "invalid_request", "Send application/json.");
      // An empty JSON body is an empty object.
      await expectError(await root.api("POST", "/v1/users", "", {}), 400, "invalid_request", USERNAME_RULE);
    });
  });

  describe("GET /v1/users/:id", () => {
    test("adds the second factors and the access, by service", async () => {
      const user = await stack.user({ username: uname("get"), totp: true, recoveryCodes: 3, access: { wiki: "admin", mailbox: "user" } });
      const body = await bodyOf(await root.api("GET", `/v1/users/${user.id}`), 200);
      expect(body).toEqual({
        id: user.id,
        username: user.username,
        name: user.name,
        email: user.email,
        email_verified: true,
        kind: "person",
        owner_id: null,
        disabled: false,
        created_at: expect.stringMatching(ISO),
        mfa: { totp: true, passkeys: 0, recovery_codes: 3 },
        access: [
          { service: "mailbox", role: "user", granted_by: "host-cli", granted_at: expect.stringMatching(ISO) },
          { service: "wiki", role: "admin", granted_by: "host-cli", granted_at: expect.stringMatching(ISO) },
        ],
      });
      const bare = await stack.user({ username: uname("get"), email: null, password: null });
      const b = await bodyOf(await root.api("GET", `/v1/users/${bare.id}`), 200);
      expect(b).toMatchObject({ email: null, email_verified: false, mfa: { totp: false, passkeys: 0, recovery_codes: 0 }, access: [] });
    });

    test.each([["an unknown id", () => newId("usr")], ["a malformed id", () => "nope"], ["an id of another kind", () => newId("inv")]])(
      "%s is 404",
      async (_, id) => {
        for (const method of ["GET", "PATCH", "DELETE"]) {
          await expectError(await root.api(method, `/v1/users/${id()}`, method === "PATCH" ? { name: "x" } : undefined), 404, "not_found", "No such user.");
        }
      },
    );
  });

  describe("PATCH /v1/users/:id", () => {
    test("name: audited, alerted, answered", async () => {
      const user = await stack.user({ username: uname("pn") });
      const body = await bodyOf(await root.api("PATCH", `/v1/users/${user.id}`, { name: "  Renamed " }), 200);
      expect(body).toMatchObject({ id: user.id, name: "Renamed", email_verified: true });
      const [a] = await auditOf("user.update", user.id);
      expect(a).toMatchObject({ actor: admin.user.id, ip: root.ip, detail: { fields: ["name"] } });
      await adminAlert(`changed the name of ${user.username}`);
    });

    test("an empty body changes nothing and writes no audit row", async () => {
      const user = await stack.user({ username: uname("pe") });
      const body = await bodyOf(await root.api("PATCH", `/v1/users/${user.id}`, {}), 200);
      expect(body).toMatchObject({ id: user.id, name: user.name, email: user.email });
      expect(await auditOf("user.update", user.id)).toEqual([]);
    });

    test("a name that breaks the rules is refused", async () => {
      const user = await stack.user({ username: uname("pn") });
      await expectError(await root.api("PATCH", `/v1/users/${user.id}`, { name: "a\u0001" }), 400, "invalid_request", "A name is at most 200 characters, with no control characters.");
      await expectError(await root.api("PATCH", `/v1/users/${user.id}`, { name: 7 }), 400, "invalid_request", "A name is at most 200 characters, with no control characters.");
    });

    test("email, for an activated person: unverified, earlier links voided, the old address told, no activation", async () => {
      const user = await stack.user({ username: uname("pm") });
      // A reset link sent to the old address.
      await bodyOf(await root.api("POST", `/v1/users/${user.id}/reset`, { send_link: true }), 204);
      const resetMail = await stack.smtp.waitFor(user.email!, (m) => m.subject === "Reset your password");
      const fresh = `${uname("nm")}@example.com`;
      const body = await bodyOf(await root.api("PATCH", `/v1/users/${user.id}`, { email: fresh }), 200);
      expect(body).toMatchObject({ email: fresh, email_verified: false });
      expect(await stack.db`SELECT 1 FROM one_time_tokens WHERE user_id = ${user.id}`).toHaveLength(0);
      expect((await fetch(linkIn(resetMail))).status).toBe(404);

      const notice = await stack.smtp.waitFor(user.email!, (m) => m.subject === "Security notice: your email address is changing");
      expect(notice.text).toBe(
        `On the account "${user.username}": your email address is changing.\n\nAn administrator changed it.\n\nIf this wasn't you, reset your password and contact an administrator.`,
      );
      const [a] = await auditOf("user.update", user.id);
      expect(a!.detail).toEqual({ fields: ["email"] });
      await adminAlert(`changed the email of ${user.username}`);
      // A later email to the new address arrives; no activation link went before it.
      await bodyOf(await root.api("POST", `/v1/users/${user.id}/reset`, { send_link: true }), 204);
      await stack.smtp.waitFor(fresh, (m) => m.subject === "Reset your password");
      expect(stack.smtp.to(fresh).map((m) => m.subject)).toEqual(["Reset your password"]);
    });

    test("email, for an account not yet activated: the activation link goes to the new address, the old one stops working", async () => {
      const username = uname("pa");
      const created = await bodyOf(await root.api("POST", "/v1/users", { username, email: `${username}@example.com` }), 201);
      const first = await stack.smtp.waitFor(`${username}@example.com`, (m) => m.subject === "Activate your account");
      const fresh = `${username}-new@example.com`;
      await bodyOf(await root.api("PATCH", `/v1/users/${created.id}`, { email: fresh }), 200);
      const second = await stack.smtp.waitFor(fresh, (m) => m.subject === "Activate your account");
      expect((await fetch(linkIn(first))).status).toBe(404);
      expect((await fetch(linkIn(second))).status).toBe(200);
      expect(await stack.db`SELECT purpose, email FROM one_time_tokens WHERE user_id = ${created.id}`).toEqual([{ purpose: "activate", email: fresh }]);
      await stack.smtp.waitFor(`${username}@example.com`, (m) => m.subject === "Security notice: your email address is changing");
    });

    test("email: the same address in another case is no change; an invalid one is refused; another account's is a conflict", async () => {
      const user = await stack.user({ username: uname("pc") });
      const other = await stack.user({ username: uname("po") });
      await bodyOf(await root.api("PATCH", `/v1/users/${user.id}`, { email: user.email!.toUpperCase() }), 200);
      expect(await auditOf("user.update", user.id)).toEqual([]);
      expect((await stack.db`SELECT email, email_verified_at IS NOT NULL AS v FROM users WHERE id = ${user.id}`)[0]).toEqual({ email: user.email, v: true });
      await expectError(await root.api("PATCH", `/v1/users/${user.id}`, { email: "nope" }), 400, "invalid_request", "That is not an email address.");
      await expectError(await root.api("PATCH", `/v1/users/${user.id}`, { email: null }), 400, "invalid_request", "That is not an email address.");
      await expectError(
        await root.api("PATCH", `/v1/users/${user.id}`, { name: "Not Kept", email: other.email!.toUpperCase() }),
        409,
        "conflict",
        "Another account uses that email address.",
      );
      expect((await stack.db`SELECT name, email FROM users WHERE id = ${user.id}`)[0]).toEqual({ name: user.name, email: user.email });
    });

    test("name and email together are one audit row and one alert", async () => {
      const user = await stack.user({ username: uname("pb") });
      await bodyOf(await root.api("PATCH", `/v1/users/${user.id}`, { name: "Both", email: `${uname("b")}@example.com` }), 200);
      const rows = await auditOf("user.update", user.id);
      expect(rows.map((r) => r.detail)).toEqual([{ fields: ["name", "email"] }]);
      await adminAlert(`changed the name, email of ${user.username}`);
    });

    test("a bot's email is ignored", async () => {
      const bot = await stack.user({ username: uname("pbe"), kind: "bot", ownerId: admin.user.id });
      const body = await bodyOf(await root.api("PATCH", `/v1/users/${bot.id}`, { email: "not an address" }), 200);
      expect(body.email).toBeNull();
      expect(await auditOf("user.update", bot.id)).toEqual([]);
    });

    test("disabled: true ends the sessions, tells every service with an events_url, and keeps the access rows", async () => {
      const user = await stack.user({ username: uname("pd"), access: { wiki: "member" } });
      const b = await stack.session(user);
      expect((await b.api("GET", "/v1/me")).status).toBe(200);
      const body = await bodyOf(await root.api("PATCH", `/v1/users/${user.id}`, { disabled: true }), 200);
      expect(body.disabled).toBe(true);
      expect((await b.api("GET", "/v1/me")).status).toBe(401);
      expect(await stack.db`SELECT 1 FROM sessions WHERE user_id = ${user.id}`).toHaveLength(0);
      expect(await stack.db`SELECT role FROM access WHERE user_id = ${user.id}`).toEqual([{ role: "member" }]);
      const events = (await stack.outbox()).filter((e) => e.type === "user.disabled" && e.payload.sub === user.id);
      expect(events.map((e) => e.service).sort()).toEqual(["mailbox", "tasks", "wiki"]);
      for (const e of events) expect(e.payload).toEqual({ sub: user.id });
      await stack.http.waitForEvent("wiki", "user.disabled", (e) => e.payload.sub === user.id);
      const [a] = await auditOf("user.disable", user.id);
      expect(a).toMatchObject({ actor: admin.user.id, ip: root.ip, detail: {} });
      await adminAlert(`disabled ${user.username}`);

      // Again: nothing more happens.
      await bodyOf(await root.api("PATCH", `/v1/users/${user.id}`, { disabled: true }), 200);
      expect(await auditOf("user.disable", user.id)).toHaveLength(1);
      expect((await stack.outbox()).filter((e) => e.type === "user.disabled" && e.payload.sub === user.id)).toHaveLength(3);

      // false enables again, with the old session still over.
      const enabled = await bodyOf(await root.api("PATCH", `/v1/users/${user.id}`, { disabled: false }), 200);
      expect(enabled.disabled).toBe(false);
      expect(await auditOf("user.enable", user.id)).toHaveLength(1);
      await adminAlert(`enabled ${user.username}`);
      expect((await b.api("GET", "/v1/me")).status).toBe(401);
      expect((await (await stack.session(user)).api("GET", "/v1/me")).status).toBe(200);
      // Enabling an enabled user writes nothing.
      await bodyOf(await root.api("PATCH", `/v1/users/${user.id}`, { disabled: false }), 200);
      expect(await auditOf("user.enable", user.id)).toHaveLength(1);
    });

    test.each([["a string", "true"], ["null", null], ["a number", 1], ["an object", {}]])("disabled as %s is refused", async (_, disabled) => {
      const user = await stack.user({ username: uname("pdx") });
      await expectError(await root.api("PATCH", `/v1/users/${user.id}`, { name: "Kept?", disabled }), 400, "invalid_request", "disabled is true or false.");
      expect((await stack.db`SELECT name, disabled_at FROM users WHERE id = ${user.id}`)[0]).toEqual({ name: user.name, disabled_at: null });
    });

    test("owner_id: a bot's changes to another person; not to a bot, an unknown user, or for a person", async () => {
      const bot = await stack.user({ username: uname("pob"), kind: "bot", ownerId: admin.user.id });
      const next = await stack.user({ username: uname("pon") });
      const body = await bodyOf(await root.api("PATCH", `/v1/users/${bot.id}`, { owner_id: next.id }), 200);
      expect(body.owner_id).toBe(next.id);
      expect((await auditOf("user.update", bot.id)).map((r) => r.detail)).toEqual([{ fields: ["owner_id"] }]);
      await adminAlert(`changed the owner_id of ${bot.username}`);

      const otherBot = await stack.user({ username: uname("pox"), kind: "bot", ownerId: admin.user.id });
      await expectError(await root.api("PATCH", `/v1/users/${bot.id}`, { owner_id: otherBot.id }), 400, "invalid_request", "A bot's owner is a person.");
      await expectError(await root.api("PATCH", `/v1/users/${bot.id}`, { owner_id: newId("usr") }), 404, "not_found", "No such user.");
      await expectError(await root.api("PATCH", `/v1/users/${next.id}`, { owner_id: admin.user.id }), 400, "invalid_request", "Only a bot user has an owner.");
      expect((await stack.db`SELECT owner_id FROM users WHERE id = ${bot.id}`)[0].owner_id).toBe(next.id);
    });

    test("the body is read after the user is found", async () => {
      await expectError(await root.api("PATCH", `/v1/users/${newId("usr")}`, "{", {}), 404, "not_found", "No such user.");
      const user = await stack.user({ username: uname("pj") });
      await expectError(await root.api("PATCH", `/v1/users/${user.id}`, "{", {}), 400, "invalid_request", "The body is not valid JSON.");
    });
  });

  describe("DELETE /v1/users/:id", () => {
    test("erases the user and their rows, tells every service, and keeps the audit trail", async () => {
      const user = await stack.user({ username: uname("del"), access: { wiki: "member" }, totp: true });
      await stack.session(user);
      const res = await root.api("DELETE", `/v1/users/${user.id}`);
      expect(res.status).toBe(204);
      expect(await res.text()).toBe("");
      for (const table of ["users", "access", "sessions", "totp"]) {
        const col = table === "users" ? "id" : "user_id";
        expect(await stack.db.unsafe(`SELECT 1 FROM ${table} WHERE ${col} = $1`, [user.id])).toHaveLength(0);
      }
      const events = (await stack.outbox()).filter((e) => e.type === "user.deleted" && e.payload.sub === user.id);
      expect(events.map((e) => e.service).sort()).toEqual(["mailbox", "tasks", "wiki"]);
      for (const e of events) expect(e.payload).toEqual({ sub: user.id });
      const [a] = await auditOf("user.delete", user.id);
      expect(a).toMatchObject({ actor: admin.user.id, ip: root.ip, detail: { username: user.username } });
      await adminAlert(`deleted ${user.username}`);
      await expectError(await root.api("GET", `/v1/users/${user.id}`), 404, "not_found", "No such user.");
    });

    test("a person who owns bots is a conflict until they go or move", async () => {
      const owner = await stack.user({ username: uname("dow") });
      const bot = await stack.user({ username: uname("dbt"), kind: "bot", ownerId: owner.id });
      await expectError(await root.api("DELETE", `/v1/users/${owner.id}`), 409, "conflict", "This user owns bot users; delete them or give them another owner first.");
      expect(await stack.db`SELECT 1 FROM users WHERE id = ${owner.id}`).toHaveLength(1);
      expect((await root.api("DELETE", `/v1/users/${bot.id}`)).status).toBe(204);
      expect((await root.api("DELETE", `/v1/users/${owner.id}`)).status).toBe(204);
    });
  });

  // ----------------------------------------------------------------- access

  describe("PUT /v1/users/:id/access/:service", () => {
    test("an admin creates a row, then changes it: audited, announced, alerted", async () => {
      const user = await stack.user({ username: uname("ap") });
      const created = await bodyOf(await root.api("PUT", `/v1/users/${user.id}/access/wiki`, { role: "member" }), 200);
      expect(created).toEqual({ service: "wiki", role: "member", granted_by: admin.user.id, granted_at: expect.stringMatching(ISO) });
      await adminAlert(`set ${user.username}'s role on wiki to member`);
      const changed = await bodyOf(await root.api("PUT", `/v1/users/${user.id}/access/wiki`, { role: "owner" }), 200);
      expect(changed).toMatchObject({ service: "wiki", role: "owner", granted_by: admin.user.id });
      await adminAlert(`set ${user.username}'s role on wiki to owner`);

      const rows = await auditOf("access.put", user.id);
      expect(rows.map((r) => [r.actor, r.ip, r.detail])).toEqual([
        [admin.user.id, root.ip, { service: "wiki", role: "member", previous: null }],
        [admin.user.id, root.ip, { service: "wiki", role: "owner", previous: "member" }],
      ]);
      const events = (await stack.outbox("wiki")).filter((e) => e.type === "access.changed" && e.payload.sub === user.id);
      expect(events.map((e) => e.payload)).toEqual([
        { sub: user.id, role: "member" },
        { sub: user.id, role: "owner" },
      ]);
    });

    test("an identical put changes nothing: the same row, no audit row, no event", async () => {
      const user = await stack.user({ username: uname("ai") });
      await stack.grant(user.id, "wiki", "admin", "host-cli");
      const [before] = await stack.db`SELECT granted_at FROM access WHERE user_id = ${user.id}`;
      const body = await bodyOf(await root.api("PUT", `/v1/users/${user.id}/access/wiki`, { role: "admin" }), 200);
      expect(body).toEqual({ service: "wiki", role: "admin", granted_by: "host-cli", granted_at: before.granted_at.toISOString() });
      expect(await auditOf("access.put", user.id)).toEqual([]);
      expect((await stack.outbox("wiki")).filter((e) => e.payload.sub === user.id)).toEqual([]);
    });

    test("a role the service doesn't declare is refused, naming the roles", async () => {
      const user = await stack.user({ username: uname("ar") });
      await expectError(await root.api("PUT", `/v1/users/${user.id}/access/wiki`, { role: "superuser" }), 400, "invalid_request", '"superuser" is not a role of wiki: use member, admin, owner.');
      await expectError(await root.api("PUT", `/v1/users/${user.id}/access/wiki`, { role: "" }), 400, "invalid_request", '"" is not a role of wiki: use member, admin, owner.');
      await expectError(await root.api("PUT", `/v1/users/${user.id}/access/wiki`, { role: "Member" }), 400, "invalid_request", '"Member" is not a role of wiki: use member, admin, owner.');
      expect(await stack.db`SELECT 1 FROM access WHERE user_id = ${user.id}`).toHaveLength(0);
    });

    test.each([["missing", undefined], ["null", null], ["a number", 1], ["an array", ["member"]], ["an object", { name: "member" }]])(
      "a role that is %s is refused",
      async (_, role) => {
        const user = await stack.user({ username: uname("aq") });
        await expectError(await root.api("PUT", `/v1/users/${user.id}/access/wiki`, { role }), 400, "invalid_request", "role is required.");
      },
    );

    test("the order of checks: the service, the body, the role, then the user", async () => {
      await expectError(await root.api("PUT", `/v1/users/${newId("usr")}/access/nowhere`, "{", {}), 404, "not_found", 'There is no service "nowhere".');
      await expectError(await root.api("PUT", `/v1/users/${newId("usr")}/access/wiki`, "{", {}), 400, "invalid_request", "The body is not valid JSON.");
      await expectError(await root.api("PUT", `/v1/users/${newId("usr")}/access/wiki`, {}), 400, "invalid_request", "role is required.");
      await expectError(await root.api("PUT", `/v1/users/${newId("usr")}/access/wiki`, { role: "member" }), 404, "not_found", "No such user.");
      await expectError(await root.api("PUT", "/v1/users/nope/access/wiki", { role: "member" }), 404, "not_found", "No such user.");
    });

    test("granting auth:admin is alerted with ids, not as an admin action", async () => {
      const user = await stack.user({ username: uname("aa") });
      const body = await bodyOf(await root.api("PUT", `/v1/users/${user.id}/access/auth`, { role: "admin" }), 200);
      expect(body).toMatchObject({ service: "auth", role: "admin", granted_by: admin.user.id });
      await alert(`auth: ${user.id} was given auth:admin by ${admin.user.id}`);
      await expectError(await root.api("PUT", `/v1/users/${user.id}/access/auth`, { role: "owner" }), 400, "invalid_request", '"owner" is not a role of auth: use admin.');
      // auth has no events_url: nothing is queued for it.
      expect((await stack.outbox()).filter((e) => e.service === "auth")).toEqual([]);
      // Removing it is alerted the same way.
      expect((await root.api("DELETE", `/v1/users/${user.id}/access/auth`)).status).toBe(204);
      await alert(`auth: ${user.id} lost auth access by ${admin.user.id}`);
      expect(stack.alerts).not.toContain(`auth: ${rootName} set ${user.username}'s role on auth to admin`);
    });

    test("a service without an events_url gets no event", async () => {
      const user = await stack.user({ username: uname("an") });
      await bodyOf(await root.api("PUT", `/v1/users/${user.id}/access/notes`, { role: "writer" }), 200);
      expect((await auditOf("access.put", user.id)).map((r) => r.detail)).toEqual([{ service: "notes", role: "writer", previous: null }]);
      expect((await stack.outbox()).filter((e) => e.payload.sub === user.id)).toEqual([]);
    });

    test("a managing client: its own service only, recorded as cli_<service>, not alerted", async () => {
      const user = await stack.user({ username: uname("ac"), access: { wiki: "member" } });
      const body = await bodyOf(await asClient("wiki", "PUT", `/v1/users/${user.id}/access/wiki`, { role: "admin" }), 200);
      expect(body).toEqual({ service: "wiki", role: "admin", granted_by: "cli_wiki", granted_at: expect.stringMatching(ISO) });
      const [a] = await auditOf("access.put", user.id);
      expect(a).toMatchObject({ actor: "cli_wiki", detail: { service: "wiki", role: "admin", previous: "member" } });
      expect((await stack.outbox("wiki")).filter((e) => e.payload.sub === user.id).map((e) => e.payload)).toEqual([{ sub: user.id, role: "admin" }]);
      for (const service of ["mailbox", "tasks", "auth", "nowhere"]) {
        await expectError(await asClient("wiki", "PUT", `/v1/users/${user.id}/access/${service}`, { role: "user" }), 403, "forbidden", "A client reaches only its own service.");
      }
      await expectError(await asClient("wiki", "PUT", `/v1/users/${user.id}/access/wiki`, { role: "superuser" }), 400, "invalid_request", '"superuser" is not a role of wiki: use member, admin, owner.');
      await expectError(await asClient("wiki", "PUT", `/v1/users/${newId("usr")}/access/wiki`, { role: "member" }), 404, "not_found", "No such user.");
      // A later admin action's alert arrives; none came for the client's.
      await bodyOf(await root.api("PATCH", `/v1/users/${user.id}`, { name: "Marker" }), 200);
      await adminAlert(`changed the name of ${user.username}`);
      expect(stack.alerts.filter((a) => a.includes(`${user.username}'s role`))).toEqual([]);
    });
  });

  describe("DELETE /v1/users/:id/access/:service", () => {
    test("an admin removes a row: 204, audited, announced with role null, alerted", async () => {
      const user = await stack.user({ username: uname("dr"), access: { wiki: "admin" } });
      const res = await root.api("DELETE", `/v1/users/${user.id}/access/wiki`);
      expect(res.status).toBe(204);
      expect(await stack.db`SELECT 1 FROM access WHERE user_id = ${user.id}`).toHaveLength(0);
      const [a] = await auditOf("access.delete", user.id);
      expect(a).toMatchObject({ actor: admin.user.id, ip: root.ip, detail: { service: "wiki", previous: "admin" } });
      expect((await stack.outbox("wiki")).filter((e) => e.payload.sub === user.id).map((e) => [e.type, e.payload])).toEqual([
        ["access.changed", { sub: user.id, role: null }],
      ]);
      await adminAlert(`removed ${user.username}'s role on wiki`);
      await expectError(await root.api("DELETE", `/v1/users/${user.id}/access/wiki`), 404, "not_found", "The user has no role on this service.");
    });

    test("an open service refuses a removal, row or no row", async () => {
      const user = await stack.user({ username: uname("do"), access: { tasks: "user" } });
      const text = "tasks is open to sign-up, so a role can be changed but not removed; disable the user to keep them out.";
      await expectError(await root.api("DELETE", `/v1/users/${user.id}/access/tasks`), 409, "conflict", text);
      const none = await stack.user({ username: uname("dn") });
      await expectError(await root.api("DELETE", `/v1/users/${none.id}/access/tasks`), 409, "conflict", text);
      expect(await stack.db`SELECT role FROM access WHERE user_id = ${user.id}`).toEqual([{ role: "user" }]);
    });

    test("unknown service and user", async () => {
      const user = await stack.user({ username: uname("du") });
      await expectError(await root.api("DELETE", `/v1/users/${user.id}/access/nowhere`), 404, "not_found", 'There is no service "nowhere".');
      await expectError(await root.api("DELETE", `/v1/users/${newId("usr")}/access/wiki`), 404, "not_found", "No such user.");
    });

    test("a managing client removes on its own service only, as cli_<service>", async () => {
      const user = await stack.user({ username: uname("dc"), access: { wiki: "member", mailbox: "user" } });
      await expectError(await asClient("wiki", "DELETE", `/v1/users/${user.id}/access/mailbox`), 403, "forbidden", "A client reaches only its own service.");
      expect((await asClient("wiki", "DELETE", `/v1/users/${user.id}/access/wiki`)).status).toBe(204);
      const [a] = await auditOf("access.delete", user.id);
      expect(a).toMatchObject({ actor: "cli_wiki", detail: { service: "wiki", previous: "member" } });
      await expectError(await asClient("wiki", "DELETE", `/v1/users/${user.id}/access/wiki`), 404, "not_found", "The user has no role on this service.");
      expect(await stack.db`SELECT service FROM access WHERE user_id = ${user.id}`).toEqual([{ service: "mailbox" }]);
    });
  });

  describe("GET /v1/users/:id/access", () => {
    test("an admin sees every row, by service; a client only its own, and none for a disabled user", async () => {
      const user = await stack.user({ username: uname("la"), access: { wiki: "member", tasks: "user", mailbox: "admin" } });
      const all = await bodyOf(await root.api("GET", `/v1/users/${user.id}/access`), 200);
      expect(all).toEqual({
        items: ["mailbox", "tasks", "wiki"].map((service) => ({
          service,
          role: { mailbox: "admin", tasks: "user", wiki: "member" }[service],
          granted_by: "host-cli",
          granted_at: expect.stringMatching(ISO),
        })),
        next: null,
      });
      const own = await bodyOf(await asClient("wiki", "GET", `/v1/users/${user.id}/access`), 200);
      expect(own).toEqual({ items: [{ service: "wiki", role: "member", granted_by: "host-cli", granted_at: expect.stringMatching(ISO) }], next: null });
      const none = await stack.user({ username: uname("lb"), access: { tasks: "user" } });
      expect(await bodyOf(await asClient("wiki", "GET", `/v1/users/${none.id}/access`), 200)).toEqual({ items: [], next: null });
      await stack.db`UPDATE users SET disabled_at = now() WHERE id = ${user.id}`;
      expect(await bodyOf(await asClient("wiki", "GET", `/v1/users/${user.id}/access`), 200)).toEqual({ items: [], next: null });
      expect((await bodyOf(await root.api("GET", `/v1/users/${user.id}/access`), 200)).items).toHaveLength(3);
      await expectError(await root.api("GET", `/v1/users/${newId("usr")}/access`), 404, "not_found", "No such user.");
      await expectError(await asClient("wiki", "GET", `/v1/users/${newId("usr")}/access`), 404, "not_found", "No such user.");
    });
  });

  // --------------------------------------------------------------- sessions

  describe("DELETE /v1/users/:id/sessions", () => {
    test("signs the user out everywhere, telling each service holding tokens under a session", async () => {
      const user = await stack.user({ username: uname("ss"), access: { wiki: "member" } });
      const a = await stack.session(user);
      const b = await stack.session(user);
      // wiki holds a refresh token under session a.
      const { verifier, challenge } = pkce();
      const back = await a.authorize(authorizeParams("wiki", REDIRECTS.wiki!, challenge));
      const tokens = await bodyOf(
        await backChannel(stack, "/oauth/token", { grant_type: "authorization_code", code: back.searchParams.get("code")!, redirect_uri: REDIRECTS.wiki!, code_verifier: verifier }, stack.basic("wiki")),
        200,
      );
      expect(tokens.refresh_token).toBeString();

      const res = await root.api("DELETE", `/v1/users/${user.id}/sessions`);
      expect(res.status).toBe(204);
      expect((await a.api("GET", "/v1/me")).status).toBe(401);
      expect((await b.api("GET", "/v1/me")).status).toBe(401);
      expect(await stack.db`SELECT 1 FROM sessions WHERE user_id = ${user.id}`).toHaveLength(0);
      const ended = (await stack.outbox("wiki")).filter((e) => e.type === "session.ended" && e.payload.sid === a.sessionId);
      expect(ended.map((e) => e.payload)).toEqual([{ sid: a.sessionId }]);
      const refreshed = await backChannel(stack, "/oauth/token", { grant_type: "refresh_token", refresh_token: tokens.refresh_token }, stack.basic("wiki"));
      expect(((await refreshed.json()) as any).error).toBe("invalid_grant");
      const [row] = await auditOf("session.end_all", user.id);
      expect(row).toMatchObject({ actor: admin.user.id, ip: root.ip, detail: {} });
      await adminAlert(`signed ${user.username} out everywhere`);
      // A user without sessions: still 204, still audited.
      expect((await root.api("DELETE", `/v1/users/${user.id}/sessions`)).status).toBe(204);
      expect(await auditOf("session.end_all", user.id)).toHaveLength(2);
      await expectError(await root.api("DELETE", `/v1/users/${newId("usr")}/sessions`), 404, "not_found", "No such user.");
    });
  });

  // ------------------------------------------------------------------ reset

  describe("POST /v1/users/:id/reset", () => {
    test("send_link emails a reset link, audited and alerted", async () => {
      const user = await stack.user({ username: uname("rl"), totp: true });
      const s = await stack.session(user);
      expect((await root.api("POST", `/v1/users/${user.id}/reset`, { send_link: true })).status).toBe(204);
      const mail = await stack.smtp.waitFor(user.email!, (m) => m.subject === "Reset your password");
      const link = linkIn(mail);
      expect(`${link.origin}${link.pathname}`).toBe(`${stack.issuer}/reset/confirm`);
      expect(await stack.db`SELECT purpose, email FROM one_time_tokens WHERE user_id = ${user.id}`).toEqual([{ purpose: "reset", email: user.email }]);
      expect(await auditOf("reset.sent", user.id)).toEqual([expect.objectContaining({ actor: admin.user.id, ip: root.ip, detail: {} })]);
      await adminAlert(`sent a reset link to ${user.username}`);
      // The factors and sessions stay.
      expect(await stack.db`SELECT 1 FROM totp WHERE user_id = ${user.id}`).toHaveLength(1);
      expect((await s.api("GET", "/v1/me")).status).toBe(200);
      expect(await auditOf("mfa.cleared", user.id)).toEqual([]);
    });

    test("clear_mfa removes every factor, signs the user out, and tells them", async () => {
      const user = await stack.user({ username: uname("rc"), totp: true, recoveryCodes: 4 });
      await stack.db`INSERT INTO passkeys (id, user_id, credential_id, public_key, name) VALUES (${newId("pk")}, ${user.id}, ${randomBytes(16)}, ${randomBytes(32)}, 'Key')`;
      const s = await stack.session(user, { amr: ["pwd", "otp", "mfa"] });
      expect((await root.api("POST", `/v1/users/${user.id}/reset`, { clear_mfa: true })).status).toBe(204);
      for (const table of ["totp", "passkeys", "recovery_codes", "sessions"]) {
        expect(await stack.db.unsafe(`SELECT 1 FROM ${table} WHERE user_id = $1`, [user.id])).toHaveLength(0);
      }
      expect((await s.api("GET", "/v1/me")).status).toBe(401);
      const notice = await stack.smtp.waitFor(user.email!, (m) => m.subject === "Security notice: two-factor authentication was cleared by an administrator");
      expect(notice.text).toBe(
        `On the account "${user.username}": two-factor authentication was cleared by an administrator.\n\nIf this wasn't you, reset your password and contact an administrator.`,
      );
      expect(await auditOf("mfa.cleared", user.id)).toEqual([expect.objectContaining({ actor: admin.user.id, ip: root.ip, detail: {} })]);
      expect(await auditOf("reset.sent", user.id)).toEqual([]);
      await adminAlert(`cleared the MFA of ${user.username}`);
      expect(await stack.db`SELECT 1 FROM one_time_tokens WHERE user_id = ${user.id}`).toHaveLength(0);
    });

    test("both: one alert naming both, both mails, both audit rows", async () => {
      const user = await stack.user({ username: uname("rb"), totp: true });
      expect((await root.api("POST", `/v1/users/${user.id}/reset`, { send_link: true, clear_mfa: true })).status).toBe(204);
      await stack.smtp.waitFor(user.email!, (m) => m.subject === "Reset your password");
      await stack.smtp.waitFor(user.email!, (m) => m.subject.startsWith("Security notice: two-factor"));
      const actions = (await stack.audit()).filter((r) => r.user_id === user.id).map((r) => r.action);
      expect(actions).toEqual(["mfa.cleared", "reset.sent"]);
      await adminAlert(`cleared the MFA of ${user.username} and sent a reset link to ${user.username}`);
    });

    test("clear_mfa on an account without an email works, and mails no one", async () => {
      const user = await stack.user({ username: uname("rn"), email: null, totp: true });
      expect((await root.api("POST", `/v1/users/${user.id}/reset`, { clear_mfa: true })).status).toBe(204);
      expect(await stack.db`SELECT 1 FROM totp WHERE user_id = ${user.id}`).toHaveLength(0);
      await adminAlert(`cleared the MFA of ${user.username}`);
    });

    test.each([
      ["nothing", {}],
      ["both false", { send_link: false, clear_mfa: false }],
      ["strings", { send_link: "true", clear_mfa: "true" }],
      ["numbers", { send_link: 1, clear_mfa: 1 }],
      ["null", { send_link: null }],
    ])("%s is refused", async (_, body) => {
      const user = await stack.user({ username: uname("rx") });
      await expectError(await root.api("POST", `/v1/users/${user.id}/reset`, body), 400, "invalid_request", "Set send_link, clear_mfa or both.");
    });

    test("a bot is a conflict; send_link to an account without an email is a conflict", async () => {
      const bot = await stack.user({ username: uname("rbt"), kind: "bot", ownerId: admin.user.id });
      for (const body of [{ send_link: true }, { clear_mfa: true }]) {
        await expectError(await root.api("POST", `/v1/users/${bot.id}/reset`, body), 409, "conflict", "A bot user has no password or second factor.");
      }
      const user = await stack.user({ username: uname("rne"), email: null, totp: true });
      await expectError(
        await root.api("POST", `/v1/users/${user.id}/reset`, { send_link: true, clear_mfa: true }),
        409,
        "conflict",
        "The user has no email address to send a link to.",
      );
      // Refused whole: the factor stays.
      expect(await stack.db`SELECT 1 FROM totp WHERE user_id = ${user.id}`).toHaveLength(1);
    });

    test("the order of checks: the user, the body, then what it asks", async () => {
      await expectError(await root.api("POST", `/v1/users/${newId("usr")}/reset`, {}), 404, "not_found", "No such user.");
      const bot = await stack.user({ username: uname("rbo"), kind: "bot", ownerId: admin.user.id });
      await expectError(await root.api("POST", `/v1/users/${bot.id}/reset`, {}), 400, "invalid_request", "Set send_link, clear_mfa or both.");
      await expectError(await root.api("POST", `/v1/users/${bot.id}/reset`, "[1]", {}), 400, "invalid_request", "The body must be a JSON object.");
    });
  });

  // -------------------------------------------------------- bot credentials

  describe("a bot's app passwords and API keys", () => {
    const introspect = (clientId: string, token: string) => backChannel(stack, "/oauth/introspect", { token }, stack.basic(clientId));

    test.each([
      ["app-passwords", "app password", "password", "mailbox", ["imap", "smtp"], "an app password was created"],
      ["api-keys", "API key", "key", "tasks", ["tasks:read"], "an API key was created"],
    ] as const)("%s: made for the bot, shown once, emailed to the owner, alerted, working, listed, revoked", async (path, label, field, service, scopes, change) => {
      const owner = await stack.user({ username: uname("own") });
      const bot = await stack.user({ username: uname("cb"), kind: "bot", ownerId: owner.id, access: { [service]: "user" } });
      const res = await root.api("POST", `/v1/users/${bot.id}/${path}`, { name: " relay ", service, scopes: [...scopes, scopes[0]] });
      const made = await bodyOf(res, 201);
      const secret = made[field] as string;
      expect(made).toEqual({
        id: expect.stringMatching(path === "app-passwords" ? /^apw_/ : /^key_/),
        name: "relay",
        service,
        scopes: [...scopes],
        created_at: expect.stringMatching(ISO),
        last_used_at: null,
        ...(path === "api-keys" ? { expires_at: null } : {}),
        [field]: expect.any(String),
      });
      if (path === "app-passwords") expect(secret).toMatch(/^[a-z2-7]{4}(-[a-z2-7]{4}){3}$/);
      else expect(secret).toStartWith(`testkey_${made.id}_`);

      const ok = await bodyOf(await introspect(service, secret), 200);
      expect(ok).toEqual({ active: true, sub: bot.id, username: bot.username, scope: scopes.join(" "), role: "user", jti: made.id });

      const mail = await stack.smtp.waitFor(owner.email!, (m) => m.subject === `Security notice: ${change}`);
      expect(mail.text).toBe(`On the account "${owner.username}": ${change}.\n\nFor ${service}: relay\n\nIf this wasn't you, reset your password and contact an administrator.`);
      await adminAlert(`made an ${label} for the bot ${bot.username} on ${service}`);
      const [a] = await auditOf(`${path === "app-passwords" ? "app_password" : "api_key"}.create`, bot.id);
      expect(a).toMatchObject({ actor: admin.user.id, ip: root.ip, detail: { id: made.id, service, scopes: [...scopes] } });

      const listed = await bodyOf(await root.api("GET", `/v1/users/${bot.id}/${path}`), 200);
      const { [field]: _, ...shown } = made;
      expect(listed.next).toBeNull();
      expect(listed.items).toHaveLength(1);
      expect(listed.items[0]).toMatchObject({ ...shown, last_used_at: expect.stringMatching(ISO) });
      expect(JSON.stringify(listed)).not.toContain(secret);

      expect((await root.api("DELETE", `/v1/users/${bot.id}/${path}/${made.id}`)).status).toBe(204);
      expect(await bodyOf(await introspect(service, secret), 200)).toEqual({ active: false });
      await adminAlert(`revoked an ${label} of the bot ${bot.username}`);
      const [r] = await auditOf(`${path === "app-passwords" ? "app_password" : "api_key"}.revoke`, bot.id);
      expect(r).toMatchObject({ actor: admin.user.id, detail: { id: made.id, service } });
      expect((await stack.outbox(service)).filter((e) => e.type === "credential.revoked" && e.payload.id === made.id).map((e) => e.payload)).toEqual([
        { sub: bot.id, id: made.id },
      ]);
      await expectError(await root.api("DELETE", `/v1/users/${bot.id}/${path}/${made.id}`), 404, "not_found", `No such ${label}.`);
      expect((await bodyOf(await root.api("GET", `/v1/users/${bot.id}/${path}`), 200)).items).toEqual([]);
    });

    test.each([
      ["app-passwords", "app password"],
      ["api-keys", "API key"],
    ])("%s: a person is a conflict; an unknown user is 404", async (path, label) => {
      const person = await stack.user({ username: uname("cp"), access: { mailbox: "user", tasks: "user" } });
      const text = `People manage their own ${label}s; this endpoint is for bot users.`;
      await expectError(await root.api("GET", `/v1/users/${person.id}/${path}`), 409, "conflict", text);
      await expectError(await root.api("POST", `/v1/users/${person.id}/${path}`, { name: "x", service: "mailbox", scopes: ["imap"] }), 409, "conflict", text);
      await expectError(await root.api("DELETE", `/v1/users/${person.id}/${path}/${newId("apw")}`), 409, "conflict", text);
      await expectError(await root.api("GET", `/v1/users/${newId("usr")}/${path}`), 404, "not_found", "No such user.");
      await expectError(await root.api("GET", `/v1/users/nope/${path}`), 404, "not_found", "No such user.");
    });

    test("making or revoking needs a sign-in in the last 15 minutes; listing doesn't", async () => {
      const bot = await stack.user({ username: uname("cr"), kind: "bot", ownerId: admin.user.id, access: { mailbox: "user" } });
      const stale = await stack.session(admin.user, { amr: ["pwd", "otp", "mfa"], authAge: 16 * 60 });
      for (const [method, path, body] of [
        ["POST", `/v1/users/${bot.id}/app-passwords`, { name: "x", service: "mailbox", scopes: ["imap"] }],
        ["DELETE", `/v1/users/${bot.id}/app-passwords/${newId("apw")}`, undefined],
        ["POST", `/v1/users/${bot.id}/api-keys`, { name: "x", service: "tasks", scopes: ["tasks:read"] }],
        ["DELETE", `/v1/users/${bot.id}/api-keys/${newId("key")}`, undefined],
      ] as const) {
        await expectError(await stale.api(method, path, body), 403, "reauth_required", "Sign in again to make this change.");
      }
      // Checked before the user is looked up.
      await expectError(await stale.api("POST", `/v1/users/${newId("usr")}/app-passwords`, {}), 403, "reauth_required", "Sign in again to make this change.");
      expect((await stale.api("GET", `/v1/users/${bot.id}/app-passwords`)).status).toBe(200);
      const almost = await stack.session(admin.user, { amr: ["pwd", "otp", "mfa"], authAge: 14 * 60 });
      expect((await almost.api("POST", `/v1/users/${bot.id}/app-passwords`, { name: "x", service: "mailbox", scopes: ["imap"] })).status).toBe(201);
    });

    test("what is made is checked as a user's own would be", async () => {
      const bot = await stack.user({ username: uname("cv"), kind: "bot", ownerId: admin.user.id, access: { mailbox: "user" } });
      const post = (body: unknown) => root.api("POST", `/v1/users/${bot.id}/app-passwords`, body);
      await expectError(await post({ name: "x", scopes: ["imap"] }), 400, "invalid_request", "service must name a service.");
      await expectError(await post({ name: "x", service: "nowhere", scopes: ["imap"] }), 400, "invalid_request", "service must name a service.");
      await expectError(await post({ name: "x", service: 5, scopes: ["imap"] }), 400, "invalid_request", "service must name a service.");
      await expectError(await post({ name: "x", service: "wiki", scopes: ["imap"] }), 400, "invalid_request", "wiki takes no app passwords.");
      await expectError(await post({ name: "x", service: "mailbox", scopes: ["pop3"] }), 400, "invalid_request", "scopes must be a non-empty list from: imap, smtp.");
      await expectError(await post({ name: "", service: "mailbox", scopes: ["imap"] }), 400, "invalid_request", "name is 1 to 100 characters, with no control characters.");
      const noRole = await stack.user({ username: uname("cw"), kind: "bot", ownerId: admin.user.id });
      await expectError(
        await root.api("POST", `/v1/users/${noRole.id}/app-passwords`, { name: "x", service: "mailbox", scopes: ["imap"] }),
        403,
        "forbidden",
        "You need a role on mailbox to create app passwords for it.",
      );
      expect(await stack.db`SELECT 1 FROM credentials WHERE user_id IN (${bot.id}, ${noRole.id})`).toHaveLength(0);
    });

    test("a bot's credential is not reachable through another bot", async () => {
      const a = await stack.user({ username: uname("ca"), kind: "bot", ownerId: admin.user.id, access: { mailbox: "user" } });
      const b = await stack.user({ username: uname("cb"), kind: "bot", ownerId: admin.user.id, access: { mailbox: "user" } });
      const made = await bodyOf(await root.api("POST", `/v1/users/${a.id}/app-passwords`, { name: "x", service: "mailbox", scopes: ["imap"] }), 201);
      await expectError(await root.api("DELETE", `/v1/users/${b.id}/app-passwords/${made.id}`), 404, "not_found", "No such app password.");
      await expectError(await root.api("DELETE", `/v1/users/${a.id}/api-keys/${made.id}`), 404, "not_found", "No such API key.");
      expect((await bodyOf(await root.api("GET", `/v1/users/${b.id}/app-passwords`), 200)).items).toEqual([]);
    });
  });

  // ---------------------------------------------------------------- invites

  describe("invitations", () => {
    test("an admin invites: 201, an email with the link, an audit row, an alert", async () => {
      const email = `${uname("inv")}@Example.com`;
      const res = await root.api("POST", "/v1/invites", { email: ` ${email} `, service: "wiki", role: "admin" });
      const invite = await bodyOf(res, 201);
      expect(invite).toEqual({
        id: expect.stringMatching(ID),
        email,
        service: "wiki",
        role: "admin",
        invited_by: admin.user.id,
        expires_at: expect.stringMatching(ISO),
        accepted_by: null,
        accepted_at: null,
      });
      expect(invite.id).toStartWith("inv_");
      const days = (Date.parse(invite.expires_at) - Date.now()) / 86_400_000;
      expect(days).toBeGreaterThan(13.9);
      expect(days).toBeLessThan(14.1);
      const mail = await stack.smtp.waitFor(email, (m) => m.subject === "You're invited to wiki");
      const link = linkIn(mail);
      expect(`${link.origin}${link.pathname}`).toBe(`${stack.issuer}/invite`);
      expect(await stack.db`SELECT 1 FROM invites WHERE id = ${invite.id} AND token_hash = ${sha256(link.searchParams.get("token")!)}`).toHaveLength(1);
      const [a] = (await stack.audit("invite.create")).filter((r) => r.detail.id === invite.id);
      expect(a).toMatchObject({ actor: admin.user.id, user_id: null, ip: root.ip, detail: { id: invite.id, service: "wiki", role: "admin" } });
      await adminAlert("invited someone to wiki as admin");
      expect(await bodyOf(await root.api("GET", `/v1/invites/${invite.id}`), 200)).toEqual(invite);
    });

    test("a managing client invites to its own service, as cli_<service>, not alerted", async () => {
      const email = `${uname("ci")}@example.com`;
      const invite = await bodyOf(await asClient("wiki", "POST", "/v1/invites", { email, service: "wiki", role: "member" }), 201);
      expect(invite).toMatchObject({ email, service: "wiki", role: "member", invited_by: "cli_wiki" });
      const [a] = (await stack.audit("invite.create")).filter((r) => r.detail.id === invite.id);
      expect(a!.actor).toBe("cli_wiki");
      await stack.smtp.waitFor(email, (m) => m.subject === "You're invited to wiki");
      for (const service of ["mailbox", "notes", "nowhere", "auth"]) {
        await expectError(await asClient("wiki", "POST", "/v1/invites", { email, service, role: "user" }), 403, "forbidden", "A client reaches only its own service.");
      }
    });

    test("the service: required, a string, known, and not closed to sign-up", async () => {
      const email = `${uname("is")}@example.com`;
      await expectError(await root.api("POST", "/v1/invites", { email, role: "member" }), 400, "invalid_request", "service is required.");
      await expectError(await root.api("POST", "/v1/invites", { email, service: 5, role: "member" }), 400, "invalid_request", "service is required.");
      await expectError(await root.api("POST", "/v1/invites", { email, service: null, role: "member" }), 400, "invalid_request", "service is required.");
      await expectError(await root.api("POST", "/v1/invites", { email, service: "nowhere", role: "member" }), 404, "not_found", 'There is no service "nowhere".');
      await expectError(
        await root.api("POST", "/v1/invites", { email, service: "notes", role: "reader" }),
        409,
        "conflict",
        "notes is closed to sign-up, so it takes no invitations; an admin grants access to existing accounts.",
      );
      await expectError(
        await root.api("POST", "/v1/invites", { email, service: "auth", role: "admin" }),
        409,
        "conflict",
        "auth is closed to sign-up, so it takes no invitations; an admin grants access to existing accounts.",
      );
      // An open service takes them.
      expect((await root.api("POST", "/v1/invites", { email, service: "tasks", role: "user" })).status).toBe(201);
    });

    test("the email and the role", async () => {
      for (const email of [undefined, null, 5, "", "nope", "a@b"]) {
        await expectError(await root.api("POST", "/v1/invites", { email, service: "wiki", role: "member" }), 400, "invalid_request", "That is not an email address.");
      }
      const email = `${uname("ir")}@example.com`;
      for (const role of [undefined, null, 1, ["member"]]) {
        await expectError(await root.api("POST", "/v1/invites", { email, service: "wiki", role }), 400, "invalid_request", "role is required.");
      }
      await expectError(await root.api("POST", "/v1/invites", { email, service: "wiki", role: "boss" }), 400, "invalid_request", '"boss" is not a role of wiki: use member, admin, owner.');
      // The closed service is refused before its role is read.
      await expectError(
        await root.api("POST", "/v1/invites", { email, service: "notes", role: "boss" }),
        409,
        "conflict",
        "notes is closed to sign-up, so it takes no invitations; an admin grants access to existing accounts.",
      );
      expect(await stack.db`SELECT 1 FROM invites WHERE email = ${email}`).toHaveLength(0);
    });

    test("3 an hour to one address, from anyone; then 429 with Retry-After", async () => {
      const email = `${uname("il")}@example.com`;
      for (let i = 0; i < 2; i++) expect((await root.api("POST", "/v1/invites", { email, service: "wiki", role: "member" })).status).toBe(201);
      expect((await asClient("wiki", "POST", "/v1/invites", { email: email.toUpperCase(), service: "wiki", role: "member" })).status).toBe(201);
      for (const res of [
        await root.api("POST", "/v1/invites", { email, service: "wiki", role: "member" }),
        await asClient("mailbox", "POST", "/v1/invites", { email, service: "mailbox", role: "user" }),
      ]) {
        const retry = Number(res.headers.get("Retry-After"));
        expect(retry).toBeGreaterThan(0);
        expect(retry).toBeLessThanOrEqual(3600);
        await expectError(res, 429, "rate_limited", "Too many invitations; try again later.");
      }
      expect(await stack.db`SELECT 1 FROM invites WHERE lower(email) = lower(${email})`).toHaveLength(3);
    });

    test("10 an hour from one admin, and 10 from one client, each counted on its own", async () => {
      const other = await stack.admin(uname("inviter"));
      const send = (b: Browser | "wiki", i: number) => {
        const body = { email: `${uname(`i${i}`)}@example.com`, service: "wiki", role: "member" };
        return b === "wiki" ? asClient("wiki", "POST", "/v1/invites", body) : b.api("POST", "/v1/invites", body);
      };
      for (let i = 0; i < 10; i++) expect((await send(other.browser, i)).status).toBe(201);
      const over = await send(other.browser, 10);
      expect(Number(over.headers.get("Retry-After"))).toBeGreaterThan(0);
      await expectError(over, 429, "rate_limited", "Too many invitations; try again later.");
      // Another admin, and a client, each have their own count.
      expect((await send(root, 0)).status).toBe(201);
      for (let i = 0; i < 10; i++) expect((await send("wiki", i)).status).toBe(201);
      await expectError(await send("wiki", 10), 429, "rate_limited", "Too many invitations; try again later.");
      // A refused invitation counts too.
      const third = await stack.admin(uname("inviter"));
      for (let i = 0; i < 10; i++) {
        await third.browser.api("POST", "/v1/invites", { email: `${uname("r")}@example.com`, service: "notes", role: "reader" });
      }
      await expectError(await send(third.browser, 0), 429, "rate_limited", "Too many invitations; try again later.");
    });

    test("GET lists every invitation, filtered by service; a client sees its own service's only", async () => {
      const tag = uname("il");
      const made: any[] = [];
      for (const [service, role] of [
        ["wiki", "member"],
        ["mailbox", "user"],
        ["wiki", "owner"],
      ]) {
        made.push(await bodyOf(await root.api("POST", "/v1/invites", { email: `${tag}-${made.length}@example.com`, service, role }), 201));
      }
      const mine = (body: any) => body.items.filter((i: any) => i.email.startsWith(tag));
      const all = await bodyOf(await root.api("GET", `/v1/invites?limit=100&after=${made[0].id.slice(0, -1)}`), 200);
      expect(mine(all)).toEqual(made);
      const wiki = await bodyOf(await root.api("GET", "/v1/invites?service=wiki&limit=100"), 200);
      expect(wiki.items.every((i: any) => i.service === "wiki")).toBe(true);
      expect(mine(wiki)).toEqual([made[0], made[2]]);
      expect(await bodyOf(await root.api("GET", "/v1/invites?service=nowhere"), 200)).toEqual({ items: [], next: null });
      const client = await bodyOf(await asClient("wiki", "GET", "/v1/invites?service=mailbox&limit=100"), 200);
      expect(client.items.every((i: any) => i.service === "wiki")).toBe(true);
      expect(mine(client)).toEqual([made[0], made[2]]);
      expect(await bodyOf(await asClient("mailbox", "GET", `/v1/invites?after=${made[1].id}&limit=100`), 200)).toEqual({ items: [], next: null });
    });

    test("GET pages with limit and after", async () => {
      const tag = uname("ip");
      const made: string[] = [];
      for (let i = 0; i < 3; i++) made.push((await bodyOf(await root.api("POST", "/v1/invites", { email: `${tag}-${i}@example.com`, service: "mailbox", role: "user" }), 201)).id);
      const start = made[0]!.slice(0, -1);
      const first = await bodyOf(await root.api("GET", `/v1/invites?service=mailbox&after=${start}&limit=2`), 200);
      expect(first.items.map((i: any) => i.id)).toEqual(made.slice(0, 2));
      expect(first.next).toBe(made[1]);
      const second = await bodyOf(await root.api("GET", `/v1/invites?service=mailbox&after=${first.next}&limit=2`), 200);
      expect(second.items.map((i: any) => i.id)).toEqual(made.slice(2));
      expect(second.next).toBeNull();
      await expectError(await root.api("GET", "/v1/invites?limit=101"), 400, "invalid_request", "limit is 1 to 100.");
      await expectError(await root.api("GET", `/v1/invites?after=${"a".repeat(65)}`), 400, "invalid_request", "after is not a cursor.");
      await expectError(await asClient("wiki", "GET", "/v1/invites?limit=x"), 400, "invalid_request", "limit is 1 to 100.");
    });

    test("GET and DELETE one: across services for an admin, the client's own service only", async () => {
      const mailbox = await bodyOf(await root.api("POST", "/v1/invites", { email: `${uname("ig")}@example.com`, service: "mailbox", role: "user" }), 201);
      const wiki = await bodyOf(await root.api("POST", "/v1/invites", { email: `${uname("ig")}@example.com`, service: "wiki", role: "member" }), 201);
      await expectError(await asClient("wiki", "GET", `/v1/invites/${mailbox.id}`), 404, "not_found", "No such invitation.");
      await expectError(await asClient("wiki", "DELETE", `/v1/invites/${mailbox.id}`), 404, "not_found", "No such invitation.");
      expect(await bodyOf(await asClient("wiki", "GET", `/v1/invites/${wiki.id}`), 200)).toEqual(wiki);
      expect(await bodyOf(await asClient("mailbox", "GET", `/v1/invites/${mailbox.id}`), 200)).toEqual(mailbox);

      const res = await root.api("DELETE", `/v1/invites/${mailbox.id}`);
      expect(res.status).toBe(204);
      const [a] = (await stack.audit("invite.delete")).filter((r) => r.detail.id === mailbox.id);
      expect(a).toMatchObject({ actor: admin.user.id, user_id: null, ip: root.ip, detail: { id: mailbox.id, service: "mailbox" } });
      await adminAlert("withdrew an invitation to mailbox");
      await expectError(await root.api("GET", `/v1/invites/${mailbox.id}`), 404, "not_found", "No such invitation.");
      await expectError(await root.api("DELETE", `/v1/invites/${mailbox.id}`), 404, "not_found", "No such invitation.");

      expect((await asClient("wiki", "DELETE", `/v1/invites/${wiki.id}`)).status).toBe(204);
      const [b] = (await stack.audit("invite.delete")).filter((r) => r.detail.id === wiki.id);
      expect(b).toMatchObject({ actor: "cli_wiki", detail: { id: wiki.id, service: "wiki" } });
      await expectError(await root.api("GET", `/v1/invites/${newId("inv")}`), 404, "not_found", "No such invitation.");
      await expectError(await root.api("GET", "/v1/invites/nope"), 404, "not_found", "No such invitation.");
    });

    test("once accepted on the invitation page, GET shows accepted_by and accepted_at, and the service is told", async () => {
      const user = await stack.user({ username: uname("ia"), access: { wiki: "admin" } });
      const invite = await bodyOf(await asClient("wiki", "POST", "/v1/invites", { email: user.email, service: "wiki", role: "member" }), 201);
      const mail = await stack.smtp.waitFor(user.email!, (m) => m.subject === "You're invited to wiki");
      const token = linkIn(mail).searchParams.get("token")!;
      const b = await stack.session(user);
      const accepted = await b.form("/invite", { token, action: "accept" });
      expect(accepted.status).toBe(200);
      expect(await accepted.text()).toContain("Invitation accepted");
      const seen = await bodyOf(await asClient("wiki", "GET", `/v1/invites/${invite.id}`), 200);
      expect(seen).toEqual({ ...invite, accepted_by: user.id, accepted_at: expect.stringMatching(ISO) });
      expect(Math.abs(Date.parse(seen.accepted_at) - Date.now())).toBeLessThan(60_000);
      // Never lowering the role held.
      expect(await stack.db`SELECT role FROM access WHERE user_id = ${user.id} AND service = 'wiki'`).toEqual([{ role: "admin" }]);
      expect((await stack.outbox("wiki")).filter((e) => e.type === "invite.accepted").map((e) => e.payload)).toContainEqual({ invite: invite.id, sub: user.id });
      const listed = await bodyOf(await root.api("GET", `/v1/invites?service=wiki&after=${invite.id.slice(0, -1)}&limit=100`), 200);
      expect(listed.items.find((i: any) => i.id === invite.id)).toEqual(seen);
    });
  });

  // ------------------------------------------------------------------ audit

  describe("GET /v1/audit", () => {
    test("newest first; each row as {id, at, actor, action, user_id, ip, detail}", async () => {
      const user = await stack.user({ username: uname("au") });
      await bodyOf(await root.api("PATCH", `/v1/users/${user.id}`, { name: "One" }), 200);
      await bodyOf(await root.api("PATCH", `/v1/users/${user.id}`, { disabled: true }), 200);
      const body = await bodyOf(await root.api("GET", `/v1/audit?user=${user.id}`), 200);
      expect(body).toEqual({
        items: [
          { id: expect.stringMatching(/^\d+$/), at: expect.stringMatching(ISO), actor: admin.user.id, action: "user.disable", user_id: user.id, ip: root.ip, detail: {} },
          { id: expect.stringMatching(/^\d+$/), at: expect.stringMatching(ISO), actor: admin.user.id, action: "user.update", user_id: user.id, ip: root.ip, detail: { fields: ["name"] } },
        ],
        next: null,
      });
      expect(Number(body.items[0].id)).toBeGreaterThan(Number(body.items[1].id));
      const all = await bodyOf(await root.api("GET", "/v1/audit?limit=100"), 200);
      const ids = all.items.map((r: any) => Number(r.id));
      expect([...ids].sort((a, b) => b - a)).toEqual(ids);
    });

    test("pages by the last id seen", async () => {
      const user = await stack.user({ username: uname("ap") });
      for (let i = 0; i < 3; i++) await bodyOf(await root.api("PATCH", `/v1/users/${user.id}`, { name: `N${i}` }), 200);
      const all = (await bodyOf(await root.api("GET", `/v1/audit?user=${user.id}`), 200)).items.map((r: any) => r.id);
      expect(all).toHaveLength(3);
      const first = await bodyOf(await root.api("GET", `/v1/audit?user=${user.id}&limit=2`), 200);
      expect(first.items.map((r: any) => r.id)).toEqual(all.slice(0, 2));
      expect(first.next).toBe(all[1]);
      const second = await bodyOf(await root.api("GET", `/v1/audit?user=${user.id}&limit=2&after=${first.next}`), 200);
      expect(second).toEqual({ items: [expect.objectContaining({ id: all[2] })], next: null });
      const exact = await bodyOf(await root.api("GET", `/v1/audit?user=${user.id}&limit=3`), 200);
      expect(exact.next).toBeNull();
      expect(await bodyOf(await root.api("GET", `/v1/audit?user=${user.id}&after=1`), 200)).toEqual({ items: [], next: null });
      expect(await bodyOf(await root.api("GET", `/v1/audit?user=${newId("usr")}`), 200)).toEqual({ items: [], next: null });
    });

    test("ids of every length come newest first, by number, and page so", async () => {
      const user = await stack.user({ username: uname("al") });
      // Far past the sequence; as text they'd sort 900000000, 80000000, 7000000, 3000000000, 2000000000.
      const ids = [3_000_000_000, 2_000_000_000, 900_000_000, 80_000_000, 7_000_000];
      for (const id of [...ids].reverse()) await stack.db`INSERT INTO audit (id, action, user_id) VALUES (${id}, 'user.update', ${user.id})`;
      const all = await bodyOf(await root.api("GET", `/v1/audit?user=${user.id}`), 200);
      expect(all.items.map((r: any) => r.id)).toEqual(ids.map(String));
      let next: string | null = null;
      const paged: string[] = [];
      do {
        const page: any = await bodyOf(await root.api("GET", `/v1/audit?user=${user.id}&limit=2${next ? `&after=${next}` : ""}`), 200);
        paged.push(...page.items.map((r: any) => r.id));
        next = page.next;
      } while (next);
      expect(paged).toEqual(ids.map(String));
      expect((await bodyOf(await root.api("GET", `/v1/audit?user=${user.id}&after=${ids[2]}`), 200)).items.map((r: any) => r.id)).toEqual(ids.slice(3).map(String));
      await stack.db`DELETE FROM audit WHERE user_id = ${user.id}`;
    });

    test.each([
      ["/v1/users?q=a%00b"],
      ["/v1/users?after=a%00b"],
      ["/v1/users?a%00b=1"],
      ["/v1/audit?user=a%00b"],
      ["/v1/invites?service=a%00b"],
      ["/v1/invites?after=a%00b"],
    ])("%s: a NUL in a query parameter is refused", async (path) => {
      await expectError(await root.api("GET", path), 400, "invalid_request", "No query parameter may hold a NUL character.");
    });

    test("a NUL is refused for a client too, and an escaped %00 is only text", async () => {
      await expectError(await asClient("wiki", "GET", "/v1/users?q=a%00b"), 400, "invalid_request", "No query parameter may hold a NUL character.");
      expect(await bodyOf(await root.api("GET", "/v1/users?q=a%2500b"), 200)).toEqual({ items: [], next: null });
    });

    test("the largest bigint is a cursor; anything past it is not", async () => {
      expect((await root.api("GET", "/v1/audit?limit=1&after=9223372036854775807")).status).toBe(200);
      for (const after of ["9223372036854775808", "99999999999999999999", "0".repeat(10) + "9".repeat(20)]) {
        await expectError(await root.api("GET", `/v1/audit?after=${after}`), 400, "invalid_request", "after is not a cursor.");
      }
    });

    test.each(["abc", "-1", "1.5", "1e3", " 1", "0x10"])("after=%s is not a cursor", async (after) => {
      await expectError(await root.api("GET", `/v1/audit?after=${encodeURIComponent(after)}`), 400, "invalid_request", "after is not a cursor.");
    });

    test("limits and an over-long cursor", async () => {
      await expectError(await root.api("GET", "/v1/audit?limit=101"), 400, "invalid_request", "limit is 1 to 100.");
      await expectError(await root.api("GET", "/v1/audit?limit=0"), 400, "invalid_request", "limit is 1 to 100.");
      await expectError(await root.api("GET", `/v1/audit?after=${"1".repeat(65)}`), 400, "invalid_request", "after is not a cursor.");
      const one = await bodyOf(await root.api("GET", "/v1/audit?limit=1"), 200);
      expect(one.items).toHaveLength(1);
      expect(one.next).toBe(one.items[0].id);
      // 51 rows for one user: 50 by default.
      const user = await stack.user({ username: uname("a5") });
      for (let i = 0; i < 51; i++) await bodyOf(await root.api("PATCH", `/v1/users/${user.id}`, { name: `N${i}` }), 200);
      const fifty = await bodyOf(await root.api("GET", `/v1/audit?user=${user.id}`), 200);
      expect(fifty.items).toHaveLength(50);
      expect(fifty.next).toBe(fifty.items[49].id);
      const rest = await bodyOf(await root.api("GET", `/v1/audit?user=${user.id}&after=${fifty.next}`), 200);
      expect(rest.items).toHaveLength(1);
      expect(rest.next).toBeNull();
      expect((await bodyOf(await root.api("GET", `/v1/audit?user=${user.id}&limit=100`), 200)).items).toHaveLength(51);
    });
  });
});
