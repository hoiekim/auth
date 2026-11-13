import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { base64url, fromBase32, random, sha256 } from "./crypto";
import { hotp, stepAt } from "./totp";
import { Browser, flush, makeUser, TEST_DATABASE_URL, testApp, testDb, type TestApp, type TestDb } from "./testing/harness";

// Signing in at auth's pages, and /oauth/authorize's decisions
// (docs/DESIGN.md §7.1, §9.1, §9.2, §9.4).
describe.skipIf(!TEST_DATABASE_URL)("sign-in", () => {
  let db: TestDb;
  let t: TestApp;
  const PW = "correct horse battery";

  beforeAll(async () => {
    db = await testDb();
    t = await testApp(db.sql);
  });
  afterAll(() => db.drop());

  async function enrolTotp(b: Browser): Promise<Buffer> {
    const start = await (await b.api("POST", "/v1/me/totp", {})).json() as any;
    const secret = fromBase32(start.secret)!;
    const res = await b.api("POST", "/v1/me/totp", { enrollment: start.enrollment, code: hotp(secret, stepAt(Date.now() / 1000)) });
    expect(res.status).toBe(200);
    return secret;
  }

  test("a password signs in, sets a __Host- session cookie, and lands on return_to", async () => {
    await makeUser(t, { username: "alice", password: PW });
    const b = new Browser(t);
    const res = await b.form("/login", { login: "alice", password: PW, return_to: "/account" });
    expect(res.status).toBe(303);
    expect(res.headers.get("Location")).toBe("/account");
    const cookie = res.headers.getSetCookie().find((c) => c.startsWith("__Host-auth="))!;
    expect(cookie).toMatch(/^__Host-auth=[A-Za-z0-9_-]{43}; Path=\/; Secure; HttpOnly; SameSite=Lax; Max-Age=\d+$/);
    // Only the hash is stored.
    const token = cookie.split(";")[0]!.split("=")[1]!;
    const [row] = await t.app.sql`SELECT token_hash, amr FROM sessions WHERE token_hash = ${sha256(token)}`;
    expect(row.amr).toEqual(["pwd"]);
    expect((await b.api("GET", "/v1/me")).status).toBe(200);
  });

  test("by email too, ignoring case", async () => {
    const b = new Browser(t);
    expect((await b.form("/login", { login: "ALICE@example.com", password: PW })).status).toBe(303);
  });

  test.each([
    ["a missing Origin", { origin: null }],
    ["another Origin", { origin: "https://evil.example.com" }],
    ["no CSRF field", { csrf: null }],
    ["a wrong CSRF field", { csrf: "x".repeat(43) }],
  ])("a sign-in form with %s is refused", async (_, opts) => {
    const b = new Browser(t);
    await b.formCsrf();
    const res = await b.form("/login", { login: "alice", password: PW }, opts as { origin?: string | null; csrf?: string | null });
    expect(res.status).toBe(403);
    expect(b.cookies.has("__Host-auth")).toBe(false);
  });

  test("an unknown user and a wrong password get the same answer", async () => {
    const b = new Browser(t, "192.0.2.50");
    const wrong = await b.form("/login", { login: "alice", password: "not the password" });
    const unknown = await b.form("/login", { login: "nobody-here", password: "not the password" });
    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    const strip = (s: string) => s.replace(/name="(login|csrf)"[^>]*>/g, "");
    expect(strip(await unknown.text())).toBe(strip(await wrong.text()));
  });

  test("five failures, then one attempt a minute; the right password waits too; success clears it", async () => {
    const bob = await makeUser(t, { username: "bob", password: PW });
    const b = new Browser(t, "192.0.2.51");
    for (let i = 0; i < 5; i++) expect((await b.form("/login", { login: "bob", password: "wrong password!" })).status).toBe(401);
    const blocked = await b.form("/login", { login: "bob", password: PW });
    expect(blocked.status).toBe(429);
    expect(Number(blocked.headers.get("Retry-After"))).toBeGreaterThan(50);
    expect(Number(blocked.headers.get("Retry-After"))).toBeLessThanOrEqual(60);
    // A minute later one attempt goes through.
    await t.app.sql`UPDATE throttle SET window_start = window_start - interval '61 seconds' WHERE key = ${`login:user:${bob}`}`;
    expect((await b.form("/login", { login: "bob", password: PW })).status).toBe(303);
    const [left] = await t.app.sql`SELECT count(*)::int AS n FROM throttle WHERE key = ${`login:user:${bob}`}`;
    expect(left.n).toBe(0);
  });

  test("the wait doubles, up to fifteen minutes", async () => {
    await makeUser(t, { username: "bob2", password: PW });
    const [u] = await t.app.sql`SELECT id FROM users WHERE username = 'bob2'`;
    await t.app.sql`INSERT INTO throttle (key, window_start, hits) VALUES (${`login:user:${u.id}`}, now(), 7)`;
    const res = await new Browser(t, "192.0.2.52").form("/login", { login: "bob2", password: PW });
    expect(Number(res.headers.get("Retry-After"))).toBe(240);
    await t.app.sql`UPDATE throttle SET hits = 30 WHERE key = ${`login:user:${u.id}`}`;
    const capped = await new Browser(t, "192.0.2.52").form("/login", { login: "bob2", password: PW });
    expect(Number(capped.headers.get("Retry-After"))).toBe(900);
  });

  test("thirty sign-ins per address per fifteen minutes", async () => {
    const b = new Browser(t, "198.51.100.99");
    for (let i = 0; i < 30; i++) await b.form("/login", { login: `nobody-${i}`, password: "wrong password!" });
    const res = await b.form("/login", { login: "alice", password: PW });
    expect(res.status).toBe(429);
    expect(await res.text()).toContain("from your network");
  });

  test("TOTP: the second step, a code used once, and five tries per sign-in", async () => {
    await makeUser(t, { username: "carol", password: PW });
    const b = new Browser(t, "192.0.2.60");
    await b.signIn("carol", PW);
    const secret = await enrolTotp(b);

    const c = new Browser(t, "192.0.2.61");
    const first = await c.form("/login", { login: "carol", password: PW });
    expect(first.headers.get("Location")).toBe("/login/second-factor");
    expect(c.cookies.has("__Host-auth")).toBe(false);
    // The enrolment used the current step; the next one is fresh.
    const step = stepAt(Date.now() / 1000) + 1;
    const ok = await c.form("/login/second-factor", { code: hotp(secret, step) });
    expect(ok.status).toBe(303);
    const [s] = await t.app.sql`SELECT amr FROM sessions WHERE token_hash = ${sha256(c.cookies.get("__Host-auth")!)}`;
    expect(s.amr).toEqual(["pwd", "otp", "mfa"]);

    // The same code again is refused.
    const d = new Browser(t, "192.0.2.62");
    await d.form("/login", { login: "carol", password: PW });
    expect((await d.form("/login/second-factor", { code: hotp(secret, step) })).status).toBe(401);
    for (let i = 0; i < 4; i++) await d.form("/login/second-factor", { code: "000000" });
    const out = await d.form("/login/second-factor", { code: hotp(secret, step + 1) });
    expect(out.status).toBe(429);
    expect(d.cookies.has("__Host-pending")).toBe(false);
  });

  test("a recovery code stands in for TOTP once, and is audited and emailed", async () => {
    await makeUser(t, { username: "dan", password: PW });
    const b = new Browser(t, "192.0.2.70");
    await b.signIn("dan", PW);
    await enrolTotp(b);
    const codes: string[] = (await (await b.api("POST", "/v1/me/recovery-codes")).json() as any).codes;
    expect(codes).toHaveLength(10);
    expect(codes[0]).toMatch(/^([a-z2-7]{4}-){5}[a-z2-7]{4}$/);
    const [stored] = await t.app.sql`SELECT count(*)::int AS n FROM recovery_codes WHERE code_hash = ${sha256(codes[0]!.replace(/-/g, ""))}`;
    expect(stored.n).toBe(1);

    t.mails.length = 0;
    const c = new Browser(t, "192.0.2.71");
    await c.form("/login", { login: "dan", password: PW });
    expect((await c.form("/login/second-factor", { code: codes[0]!.toUpperCase() })).status).toBe(303);
    await flush();
    expect(t.mails.some((m) => m.to === "dan@example.com" && m.subject.includes("recovery code"))).toBe(true);
    const d = new Browser(t, "192.0.2.72");
    await d.form("/login", { login: "dan", password: PW });
    expect((await d.form("/login/second-factor", { code: codes[0]! })).status).toBe(401);
  });

  test("a sign-in from a new device is emailed; the same device again is not", async () => {
    await makeUser(t, { username: "erin", password: PW });
    const b = new Browser(t, "192.0.2.80");
    await b.signIn("erin", PW);
    t.mails.length = 0;
    await b.signIn("erin", PW);
    await flush();
    expect(t.mails).toHaveLength(0);
    await new Browser(t, "192.0.2.81").signIn("erin", PW);
    await flush();
    expect(t.mails.map((m) => m.subject)).toEqual(["Security notice: a sign-in from a new device"]);
  });

  test("signing in again as the same user keeps the sid and replaces the cookie", async () => {
    const b = new Browser(t, "192.0.2.90");
    await b.signIn("erin", PW);
    const before = b.cookies.get("__Host-auth")!;
    const [s1] = await t.app.sql`SELECT id FROM sessions WHERE token_hash = ${sha256(before)}`;
    await b.signIn("erin", PW);
    const after = b.cookies.get("__Host-auth")!;
    expect(after).not.toBe(before);
    const [s2] = await t.app.sql`SELECT id FROM sessions WHERE token_hash = ${sha256(after)}`;
    expect(s2.id).toBe(s1.id);
    expect(await t.app.sql`SELECT 1 FROM sessions WHERE token_hash = ${sha256(before)}`).toHaveLength(0);
  });

  test("a disabled user is refused even with the right password", async () => {
    await makeUser(t, { username: "frank", password: PW });
    await t.app.sql`UPDATE users SET disabled_at = now() WHERE username = 'frank'`;
    const res = await new Browser(t, "192.0.2.91").form("/login", { login: "frank", password: PW });
    expect(res.status).toBe(403);
  });

  test("return_to only ever leads to this site", async () => {
    for (const evil of ["https://evil.example.com/", "//evil.example.com/", "/\\evil.example.com"]) {
      const res = await new Browser(t, "192.0.2.92").form("/login", { login: "alice", password: PW, return_to: evil });
      expect(res.headers.get("Location")).toBe("/account");
    }
  });
});

describe.skipIf(!TEST_DATABASE_URL)("/oauth/authorize", () => {
  let db: TestDb;
  let t: TestApp;
  const PW = "correct horse battery";
  const challenge = base64url(sha256(base64url(random(32))));
  const params = (over: Record<string, string | null> = {}) => {
    const p: Record<string, string | null> = {
      client_id: "wiki",
      redirect_uri: "https://wiki.example.com/auth/callback",
      response_type: "code",
      state: "st-1",
      scope: "openid",
      nonce: "n-1",
      code_challenge: challenge,
      code_challenge_method: "S256",
      ...over,
    };
    return `/oauth/authorize?${new URLSearchParams(Object.entries(p).filter((e): e is [string, string] => e[1] !== null))}`;
  };

  beforeAll(async () => {
    db = await testDb();
    t = await testApp(db.sql);
  });
  afterAll(() => db.drop());

  test("an unregistered redirect URI or client is shown, never redirected to", async () => {
    for (const over of [{ redirect_uri: "https://evil.example.com/cb" }, { redirect_uri: "https://wiki.example.com/auth/callback/x" }, { client_id: "nope" }] as Record<string, string>[]) {
      const res = await new Browser(t).request(params(over));
      expect(res.status).toBe(400);
      expect(res.headers.get("Location")).toBeNull();
      expect(res.headers.get("Content-Type")).toStartWith("text/html");
    }
  });

  test.each([
    ["no PKCE", { code_challenge: null }, "invalid_request"],
    ["the plain method", { code_challenge_method: "plain" }, "invalid_request"],
    ["no nonce with openid", { nonce: null }, "invalid_request"],
    ["another response_type", { response_type: "token" }, "unsupported_response_type"],
    ["an unknown prompt", { prompt: "consent" }, "invalid_request"],
  ])("%s is sent back to the client as an error, with state", async (_, over, error) => {
    const res = await new Browser(t).request(params(over));
    expect(res.status).toBe(302);
    const back = new URL(res.headers.get("Location")!);
    expect(back.origin + back.pathname).toBe("https://wiki.example.com/auth/callback");
    expect(back.searchParams.get("error")).toBe(error);
    expect(back.searchParams.get("state")).toBe("st-1");
    expect(back.searchParams.get("code")).toBeNull();
  });

  test("no state is refused", async () => {
    const back = new URL((await new Browser(t).request(params({ state: null }))).headers.get("Location")!);
    expect(back.searchParams.get("error")).toBe("invalid_request");
  });

  test("prompt=none without a session answers login_required", async () => {
    const back = new URL((await new Browser(t).request(params({ prompt: "none" }))).headers.get("Location")!);
    expect(back.searchParams.get("error")).toBe("login_required");
  });

  test("no access row: a page saying so, or access_denied with prompt=none", async () => {
    await makeUser(t, { username: "nora", password: PW });
    const b = new Browser(t);
    await b.signIn("nora", PW);
    const page = await b.request(params());
    expect(page.status).toBe(403);
    expect(await page.text()).toContain("You don&#39;t have access to wiki");
    const back = new URL((await b.request(params({ prompt: "none" }))).headers.get("Location")!);
    expect(back.searchParams.get("error")).toBe("access_denied");
  });

  test("an open service gives a signed-in user its default role, and tells the app", async () => {
    const b = new Browser(t);
    await b.signIn("nora", PW);
    const res = await b.request(params({ client_id: "tasks", redirect_uri: "https://tasks.example.com/auth/callback" }));
    expect(new URL(res.headers.get("Location")!).searchParams.get("code")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const [row] = await t.app.sql`SELECT a.role FROM access a JOIN users u ON u.id = a.user_id WHERE u.username = 'nora' AND a.service = 'tasks'`;
    expect(row.role).toBe("user");
  });

  test("a role in mfa_roles without MFA: enrolment first, or a sign-in with the second factor", async () => {
    await makeUser(t, { username: "olga", password: PW, access: { wiki: "admin" } });
    const b = new Browser(t);
    await b.signIn("olga", PW);
    const res = await b.request(params());
    expect(res.headers.get("Location")).toStartWith("/mfa-required?");
    expect(new URL((await b.request(params({ prompt: "none" }))).headers.get("Location")!).searchParams.get("error")).toBe("interaction_required");
    const start = await (await b.api("POST", "/v1/me/totp", {})).json() as any;
    await b.api("POST", "/v1/me/totp", { enrollment: start.enrollment, code: hotp(fromBase32(start.secret)!, stepAt(Date.now() / 1000)) });
    // Enrolling stepped this session up, so the code is issued now.
    const now = await b.request(params());
    expect(new URL(now.headers.get("Location")!).searchParams.get("code")).not.toBeNull();
    // A fresh password-only session is sent to sign in with the second factor.
    await t.app.sql`UPDATE sessions SET amr = '{pwd}' WHERE user_id = (SELECT id FROM users WHERE username = 'olga')`;
    expect((await b.request(params())).headers.get("Location")).toStartWith("/login?return_to=");
  });

  test("prompt=login and max_age ask for a fresh sign-in, then don't ask again", async () => {
    await makeUser(t, { username: "pete", password: PW, access: { wiki: "member" } });
    const b = new Browser(t);
    await b.signIn("pete", PW);
    const login = await b.request(params({ prompt: "login" }));
    expect(login.headers.get("Location")).toStartWith("/login?");
    const returnTo = new URL(login.headers.get("Location")!, "https://x.test").searchParams.get("return_to")!;
    expect(returnTo).not.toContain("prompt");
    await t.app.sql`UPDATE sessions SET auth_time = now() - interval '2 hours' WHERE user_id = (SELECT id FROM users WHERE username = 'pete')`;
    expect((await b.request(params({ max_age: "3600" }))).headers.get("Location")).toStartWith("/login?");
    expect((await b.request(params({ max_age: "86400" }))).headers.get("Location")).toStartWith("https://wiki.example.com/");
  });

  test("logout refuses an unregistered return address and keeps the session", async () => {
    const b = new Browser(t);
    await b.signIn("pete", PW);
    const res = await b.request(`/logout?${new URLSearchParams({ client_id: "wiki", post_logout_redirect_uri: "https://evil.example.com/" })}`);
    expect(res.status).toBe(400);
    expect((await b.api("GET", "/v1/me")).status).toBe(200);
    const ok = await b.request("/logout");
    expect(ok.status).toBe(200);
    expect((await b.api("GET", "/v1/me")).status).toBe(401);
  });
});
