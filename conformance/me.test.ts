import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { randomBytes } from "node:crypto";
import {
  backChannel,
  base32,
  basic,
  type Browser,
  decodeJwt,
  defaultServices,
  enabled,
  errorOf,
  fromBase32,
  ID,
  linkIn,
  newId,
  sha1Hex,
  sha256,
  signInTo,
  Stack,
  type TestUser,
  totp,
} from "./harness";

// The self-service half of the management API (docs/DESIGN.md §7.5), as a
// signed-in browser reaches it: who may call it (§9.2), the profile, the
// password, TOTP and recovery codes (§9.1), devices, app passwords and API
// keys (§7.3), and the services a user may use.

setDefaultTimeout(30_000);

const PASSWORD = "correct horse battery";
const SESSION_COOKIE = /^__Host-auth=([A-Za-z0-9_-]{43}); Path=\/; Secure; HttpOnly; SameSite=Lax; Max-Age=2592000$/;
const CLEARED_COOKIE = "__Host-auth=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0";
const ISO = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const RECOVERY_CODE = /^[a-z2-7]{4}(-[a-z2-7]{4}){5}$/;
const APP_PASSWORD = /^[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}$/;

let counter = 0;
// A username of its own for every test: [a-z][a-z0-9-]{1,30}[a-z0-9].
function uname(prefix: string): string {
  return `${prefix}-${randomBytes(3).toString("hex")}${(++counter).toString(36)}`;
}

// The text of a security notice (§9.1), as every change sends it.
function noticeText(username: string, change: string, detail?: string): string {
  return [`On the account "${username}": ${change}.`, ...(detail ? ["", detail] : []), "", "If this wasn't you, reset your password and contact an administrator."].join("\n");
}

async function expectError(res: Response, status: number, error: string, description: string): Promise<void> {
  expect(await errorOf(res)).toEqual({ status, error, description });
}

describe.skipIf(!enabled)("the self-service API", () => {
  let stack: Stack;

  beforeAll(async () => {
    stack = await Stack.start();
  });
  afterAll(async () => {
    await stack.stop();
  });
  beforeEach(async () => {
    await stack.resetLimits();
  });

  async function person(prefix: string, more: Partial<Parameters<Stack["user"]>[0]> = {}): Promise<TestUser> {
    return stack.user({ username: uname(prefix), ...more });
  }

  // A user and a browser signed in a moment ago.
  async function signedIn(prefix: string, more: Partial<Parameters<Stack["user"]>[0]> = {}, s: Parameters<Stack["session"]>[1] = {}) {
    const user = await person(prefix, more);
    const browser = await stack.session(user, s);
    return { user, browser };
  }

  async function auditOf(userId: string, action?: string) {
    return (await stack.audit(action)).filter((r) => r.user_id === userId);
  }

  async function me(browser: Browser): Promise<Record<string, any>> {
    const res = await browser.api("GET", "/v1/me");
    expect(res.status).toBe(200);
    return (await res.json()) as Record<string, any>;
  }

  // ------------------------------------------------------------- callers

  const SELF_SERVICE: [string, string][] = [
    ["GET", "/v1/me"],
    ["PATCH", "/v1/me"],
    ["DELETE", "/v1/me"],
    ["POST", "/v1/me/password"],
    ["POST", "/v1/me/totp"],
    ["DELETE", "/v1/me/totp"],
    ["POST", "/v1/me/recovery-codes"],
    ["GET", "/v1/me/passkeys"],
    ["POST", "/v1/me/passkeys"],
    ["DELETE", "/v1/me/passkeys/pk_x"],
    ["GET", "/v1/me/sessions"],
    ["DELETE", "/v1/me/sessions"],
    ["DELETE", "/v1/me/sessions/ses_x"],
    ["GET", "/v1/me/app-passwords"],
    ["POST", "/v1/me/app-passwords"],
    ["DELETE", "/v1/me/app-passwords/apw_x"],
    ["GET", "/v1/me/api-keys"],
    ["POST", "/v1/me/api-keys"],
    ["DELETE", "/v1/me/api-keys/key_x"],
    ["GET", "/v1/me/access"],
  ];

  describe("callers", () => {
    test.each(SELF_SERVICE)("%s %s without a session is 401 unauthorized", async (method, path) => {
      const res = await stack.browser().api(method, path, method === "GET" ? undefined : {}, method === "GET" ? {} : { "X-CSRF-Token": "x" });
      await expectError(res, 401, "unauthorized", "Sign in first.");
    });

    test.each([
      ["a cookie that isn't 43 base64url characters", "abc"],
      ["a cookie of the right shape that no session has", "a".repeat(43)],
      ["a cookie with a character outside base64url", `${"a".repeat(42)}.`],
    ])("%s is 401", async (_, value) => {
      const browser = stack.browser();
      browser.cookies.set("__Host-auth", value);
      await expectError(await browser.api("GET", "/v1/me"), 401, "unauthorized", "Sign in first.");
    });

    test("the cookie must carry the __Host- prefix", async () => {
      const { browser } = await signedIn("prefix");
      const token = browser.cookies.get("__Host-auth")!;
      browser.cookies.delete("__Host-auth");
      browser.cookies.set("auth", token);
      await expectError(await browser.api("GET", "/v1/me"), 401, "unauthorized", "Sign in first.");
    });

    test.each([
      ["idle-expired", { expiresIn: "-1 second" }],
      ["past its absolute end", { endsIn: "-1 second" }],
    ])("a session %s is 401", async (_, s) => {
      const { browser } = await signedIn("expired", {}, s);
      await expectError(await browser.api("GET", "/v1/me"), 401, "unauthorized", "Sign in first.");
    });

    test("an ended session is 401", async () => {
      const { browser } = await signedIn("ended");
      expect((await browser.api("GET", "/v1/me")).status).toBe(200);
      await stack.db`DELETE FROM sessions WHERE id = ${browser.sessionId}`;
      await expectError(await browser.api("GET", "/v1/me"), 401, "unauthorized", "Sign in first.");
    });

    test("a disabled user's session is 401", async () => {
      const { browser } = await signedIn("disabled", { disabled: true });
      await expectError(await browser.api("GET", "/v1/me"), 401, "unauthorized", "Sign in first.");
    });

    test("a bot user's session is 401", async () => {
      const owner = await person("owner");
      const bot = await stack.user({ username: uname("bot"), kind: "bot", ownerId: owner.id });
      const browser = await stack.session(bot);
      await expectError(await browser.api("GET", "/v1/me"), 401, "unauthorized", "Sign in first.");
    });

    describe("a change needs this issuer's Origin and the session's CSRF token", () => {
      test("with both, it is made", async () => {
        const { browser } = await signedIn("csrf");
        const res = await browser.api("PATCH", "/v1/me", { name: "Changed" });
        expect(res.status).toBe(200);
        expect(((await res.json()) as any).name).toBe("Changed");
      });

      test.each([
        ["missing", ""],
        ["wrong", "not-the-token"],
        ["another session's", null],
      ])("an X-CSRF-Token %s is 403", async (_, token) => {
        const { user, browser } = await signedIn("csrf");
        let value = token;
        if (value === null) value = await (await stack.session(user)).csrf();
        const res = await browser.api("PATCH", "/v1/me", { name: "Changed" }, { "X-CSRF-Token": value });
        await expectError(res, 403, "forbidden", "The CSRF token is missing or wrong.");
        expect((await me(browser)).name).not.toBe("Changed");
      });

      test("the token of the session's earlier cookie is wrong after a step-up replaced it", async () => {
        const { browser } = await signedIn("csrf-step");
        const before = await browser.csrf();
        const start = (await (await browser.api("POST", "/v1/me/totp", {})).json()) as any;
        const res = await browser.api("POST", "/v1/me/totp", { enrollment: start.enrollment, code: totp(fromBase32(start.secret)) });
        expect(res.status).toBe(200);
        await expectError(await browser.api("PATCH", "/v1/me", { name: "x" }, { "X-CSRF-Token": before }), 403, "forbidden", "The CSRF token is missing or wrong.");
        expect((await browser.api("PATCH", "/v1/me", { name: "x" })).status).toBe(200);
      });

      test.each([
        ["missing", null, {}],
        ["another site's", "https://evil.example.com", {}],
        ["the issuer's with a trailing slash", "ISSUER/", {}],
        ["the issuer under another host name", "http://localhost:PORT", {}],
        ["null, without Sec-Fetch-Site", "null", {}],
        ["null, with Sec-Fetch-Site: cross-site", "null", { "Sec-Fetch-Site": "cross-site" }],
        ["null, with Sec-Fetch-Site: same-site", "null", { "Sec-Fetch-Site": "same-site" }],
      ] as const)("an Origin %s is 403", async (_, origin, headers) => {
        const { browser } = await signedIn("origin");
        const value = origin === null ? null : origin.replace("ISSUER", stack.issuer).replace("PORT", String(stack.port));
        const res = await browser.api("PATCH", "/v1/me", { name: "Changed" }, { ...headers }, { origin: value });
        await expectError(res, 403, "forbidden", "The request's Origin is not this issuer.");
      });

      test("Origin: null with Sec-Fetch-Site: same-origin counts as the issuer's", async () => {
        const { browser } = await signedIn("origin-null");
        const res = await browser.api("PATCH", "/v1/me", { name: "Same" }, { "Sec-Fetch-Site": "same-origin" }, { origin: "null" });
        expect(res.status).toBe(200);
      });

      test("the Origin is checked before the CSRF token", async () => {
        const { browser } = await signedIn("origin-first");
        const res = await browser.api("PATCH", "/v1/me", { name: "x" }, { "X-CSRF-Token": "" }, { origin: "https://evil.example.com" });
        await expectError(res, 403, "forbidden", "The request's Origin is not this issuer.");
      });

      test("a GET needs neither", async () => {
        const { browser } = await signedIn("get");
        const res = await browser.request("/v1/me", { headers: { Origin: "https://evil.example.com" } });
        expect(res.status).toBe(200);
        expect((await browser.request("/v1/me")).status).toBe(200);
      });

      test("an unknown session is 401 before the Origin or token is looked at", async () => {
        const res = await stack.browser().api("PATCH", "/v1/me", { name: "x" }, { "X-CSRF-Token": "" }, { origin: null });
        await expectError(res, 401, "unauthorized", "Sign in first.");
      });
    });

    describe("a service's client", () => {
      test.each(SELF_SERVICE)("%s %s with a managing client's Basic credentials is 403", async (method, path) => {
        const res = await stack.browser().request(path, {
          method,
          origin: null,
          headers: { Authorization: stack.basic("wiki"), ...(method === "GET" ? {} : { "Content-Type": "application/json" }) },
          body: method === "GET" ? undefined : "{}",
        });
        await expectError(res, 403, "forbidden", "This endpoint is not open to a service's client.");
      });

      test("a client without manages_own_members is 403 too", async () => {
        const res = await stack.browser().request("/v1/me", { headers: { Authorization: stack.basic("tasks") } });
        await expectError(res, 403, "forbidden", "This endpoint is not open to a service's client.");
      });

      test("Basic credentials win over a session cookie", async () => {
        const { browser } = await signedIn("both");
        const res = await browser.request("/v1/me", { headers: { Authorization: stack.basic("wiki") } });
        await expectError(res, 403, "forbidden", "This endpoint is not open to a service's client.");
      });

      test.each([
        ["a wrong secret", () => basic("wiki", "s3cret-pw")],
        ["an unknown client", () => basic("nobody", "s3cret-pw")],
        ["a public client", () => basic("tasks-ios", "s3cret-pw")],
        ["a scheme other than Basic", () => "Bearer abc123"],
        ["Basic without a colon", () => `Basic ${Buffer.from("wiki").toString("base64")}`],
      ])("%s is 401 invalid_client, even beside a session", async (_, header) => {
        const { browser } = await signedIn("badclient");
        const res = await browser.request("/v1/me", { headers: { Authorization: header() } });
        expect(res.headers.get("WWW-Authenticate")).toBe('Basic realm="auth"');
        await expectError(res, 401, "invalid_client", "Client authentication failed.");
      });
    });

    describe("a recent sign-in", () => {
      const CHANGES: [string, string, unknown][] = [
        ["PATCH", "/v1/me", { email: "new@example.com" }],
        ["POST", "/v1/me/password", { current: PASSWORD, new: "a brand new passphrase" }],
        ["POST", "/v1/me/totp", {}],
        ["DELETE", "/v1/me/totp", undefined],
        ["POST", "/v1/me/recovery-codes", undefined],
        ["POST", "/v1/me/passkeys", {}],
        ["DELETE", "/v1/me/passkeys/pk_x", undefined],
        ["POST", "/v1/me/app-passwords", { service: "mailbox", scopes: ["imap"], name: "Phone" }],
        ["DELETE", "/v1/me/app-passwords/apw_x", undefined],
        ["POST", "/v1/me/api-keys", { service: "tasks", scopes: ["tasks:read"], name: "CI" }],
        ["DELETE", "/v1/me/api-keys/key_x", undefined],
      ];

      test.each(CHANGES)("%s %s is refused with reauth_required just past 15 minutes", async (method, path, body) => {
        const { browser } = await signedIn("stale", { access: { mailbox: "user", tasks: "user" } }, { authAge: 15 * 60 + 5 });
        await expectError(await browser.api(method, path, body), 403, "reauth_required", "Sign in again to make this change.");
      });

      test.each(CHANGES)("%s %s with a second factor the session didn't use is refused", async (method, path, body) => {
        const { browser } = await signedIn("onefactor", { access: { mailbox: "user", tasks: "user" }, totp: true }, { amr: ["pwd"] });
        await expectError(await browser.api(method, path, body), 403, "reauth_required", "Sign in again with your second factor to make this change.");
      });

      test("a passkey counts as a second factor the session must have used", async () => {
        const { user, browser } = await signedIn("pkonly");
        await stack.db`INSERT INTO passkeys (id, user_id, credential_id, public_key, name) VALUES (${newId("pk")}, ${user.id}, ${randomBytes(16)}, ${Buffer.from([0xa0])}, 'Key')`;
        await expectError(await browser.api("POST", "/v1/me/recovery-codes"), 403, "reauth_required", "Sign in again with your second factor to make this change.");
      });

      test("the age is checked first, whatever the factors", async () => {
        const { browser } = await signedIn("both-stale", { totp: true }, { amr: ["pwd", "otp", "mfa"], authAge: 3600 });
        await expectError(await browser.api("POST", "/v1/me/recovery-codes"), 403, "reauth_required", "Sign in again to make this change.");
      });

      test("just inside 15 minutes is recent enough", async () => {
        const { browser } = await signedIn("fresh", {}, { authAge: 15 * 60 - 20 });
        expect((await browser.api("POST", "/v1/me/recovery-codes")).status).toBe(200);
      });

      test("a session that used the second factor makes the change", async () => {
        const { browser } = await signedIn("twofactor", { totp: true }, { amr: ["pwd", "otp", "mfa"] });
        expect((await browser.api("POST", "/v1/me/recovery-codes")).status).toBe(200);
      });

      test("reading, renaming and signing out need no recent sign-in", async () => {
        const { browser } = await signedIn("old", { totp: true }, { authAge: 30 * 24 * 3600 - 60, amr: ["pwd"] });
        for (const path of ["/v1/me", "/v1/me/passkeys", "/v1/me/sessions", "/v1/me/app-passwords", "/v1/me/api-keys", "/v1/me/access"]) {
          expect((await browser.api("GET", path)).status).toBe(200);
        }
        expect((await browser.api("PATCH", "/v1/me", { name: "Still Me" })).status).toBe(200);
        expect((await browser.api("DELETE", `/v1/me/sessions/${newId("ses")}`)).status).toBe(404);
      });

      test("the credential change isn't half made: a refused email change keeps the name", async () => {
        const { browser } = await signedIn("half", { name: "Before" }, { authAge: 3600 });
        const res = await browser.api("PATCH", "/v1/me", { name: "After", email: "half-new@example.com" });
        expect(res.status).toBe(403);
        expect((await me(browser)).name).toBe("Before");
      });
    });

    describe("the body", () => {
      const raw = async (browser: Browser, body: string | Uint8Array, contentType: string | null) => {
        const headers: Record<string, string> = { "X-CSRF-Token": await browser.csrf() };
        if (contentType !== null) headers["Content-Type"] = contentType;
        return browser.request("/v1/me", { method: "PATCH", headers, body });
      };

      test.each(["text/plain", "application/x-www-form-urlencoded", "application/jsonx", "json"])("Content-Type %s is 415", async (type) => {
        const { browser } = await signedIn("ctype");
        await expectError(await raw(browser, '{"name":"x"}', type), 415, "invalid_request", "Send application/json.");
      });

      test("no Content-Type is 415", async () => {
        const { browser } = await signedIn("noctype");
        await expectError(await raw(browser, new TextEncoder().encode('{"name":"x"}'), null), 415, "invalid_request", "Send application/json.");
      });

      test.each(["application/json; charset=utf-8", "Application/JSON"])("Content-Type %s is read", async (type) => {
        const { browser } = await signedIn("ctype-ok");
        const res = await raw(browser, '{"name":"Typed"}', type);
        expect(res.status).toBe(200);
        expect(((await res.json()) as any).name).toBe("Typed");
      });

      test.each(["{", "{'name':'x'}", '{"name":"x"', "nam", '{"name":"x"} x'])("%s is 400, not JSON", async (body) => {
        const { browser } = await signedIn("badjson");
        await expectError(await raw(browser, body, "application/json"), 400, "invalid_request", "The body is not valid JSON.");
      });

      test.each(["[]", '[{"name":"x"}]', "1", '"name"', "null", "true"])("%s is 400, not an object", async (body) => {
        const { browser } = await signedIn("notobject");
        await expectError(await raw(browser, body, "application/json"), 400, "invalid_request", "The body must be a JSON object.");
      });

      // Read as JSON.parse reads it, in both servers, to 64 levels (DESIGN §9.4).
      test("nesting to 64 levels is read, and what isn't asked for is ignored; deeper is not JSON", async () => {
        const { browser } = await signedIn("deep");
        // The body is a level, and each array another.
        const body = (levels: number) => `{"name":"Deep","extra":${"[".repeat(levels - 1)}${"]".repeat(levels - 1)}}`;
        const res = await raw(browser, body(64), "application/json");
        expect(res.status).toBe(200);
        expect(((await res.json()) as any).name).toBe("Deep");
        for (const levels of [65, 5000]) {
          await expectError(await raw(browser, body(levels), "application/json"), 400, "invalid_request", "The body is not valid JSON.");
        }
      });

      test("an escaped lone surrogate is read, and stored as U+FFFD", async () => {
        const { user, browser } = await signedIn("lone");
        expect((await raw(browser, '{"name":"Lone \\ud800 one"}', "application/json")).status).toBe(200);
        const [row] = await stack.db`SELECT name FROM users WHERE id = ${user.id}`;
        expect(row.name).toBe("Lone \uFFFD one");
      });

      test("a number past a double's range is a number, not invalid JSON", async () => {
        const { browser } = await signedIn("huge");
        await expectError(await raw(browser, '{"name":1e400}', "application/json"), 400, "invalid_request", "A name is at most 200 characters, with no control characters.");
      });

      test("a key given twice takes its last value", async () => {
        const { browser } = await signedIn("twice");
        const res = await raw(browser, '{"name":"First","name":"Last"}', "application/json");
        expect(res.status).toBe(200);
        expect(((await res.json()) as any).name).toBe("Last");
      });

      test("an empty body is an empty object", async () => {
        const { user, browser } = await signedIn("empty");
        const res = await raw(browser, "", "application/json");
        expect(res.status).toBe(200);
        expect(((await res.json()) as any).name).toBe(user.name);
      });

      test("the body is read after the caller is checked", async () => {
        const { browser } = await signedIn("order", {}, { authAge: 3600 });
        const res = await browser.api("POST", "/v1/me/password", "{", {});
        await expectError(res, 403, "reauth_required", "Sign in again to make this change.");
      });
    });
  });

  // -------------------------------------------------------------- /v1/me

  describe("GET /v1/me", () => {
    test("shows the profile, the pending address, the factors, the admin flag and whether deletion is allowed", async () => {
      const { user, browser } = await signedIn("profile", { name: "Alice Example" });
      const body = await me(browser);
      const [row] = await stack.db`SELECT created_at FROM users WHERE id = ${user.id}`;
      expect(body).toEqual({
        id: user.id,
        username: user.username,
        name: "Alice Example",
        email: `${user.username}@example.com`,
        email_verified: true,
        kind: "person",
        owner_id: null,
        disabled: false,
        created_at: (row.created_at as Date).toISOString(),
        email_pending: null,
        mfa: { totp: false, passkeys: 0, recovery_codes: 0 },
        admin: false,
        account_deletion: false,
      });
      expect(body.created_at).toMatch(ISO);
      expect(browser.cookies.get("__Host-auth")).toBeDefined();
    });

    test("counts the factors: TOTP, passkeys, and unused recovery codes only", async () => {
      const { user, browser } = await signedIn("factors", { totp: true, recoveryCodes: 4 }, { amr: ["pwd", "otp", "mfa"] });
      for (let i = 0; i < 2; i++) {
        await stack.db`INSERT INTO passkeys (id, user_id, credential_id, public_key, name) VALUES (${newId("pk")}, ${user.id}, ${randomBytes(16)}, ${Buffer.from([0xa0])}, 'Key')`;
      }
      await stack.db`UPDATE recovery_codes SET used_at = now() WHERE code_hash = ${sha256(user.recoveryCodes[0]!.replace(/-/g, ""))}`;
      expect((await me(browser)).mfa).toEqual({ totp: true, passkeys: 2, recovery_codes: 3 });
    });

    test("an auth:admin is admin; a role on another service is not", async () => {
      const { browser } = await signedIn("adminflag", { access: { auth: "admin" } });
      expect((await me(browser)).admin).toBe(true);
      const other = await signedIn("notadmin", { access: { wiki: "admin" } });
      expect((await me(other.browser)).admin).toBe(false);
    });

    test("an unverified address, and an account without one", async () => {
      const a = await signedIn("unverified", { emailVerified: false });
      const body = await me(a.browser);
      expect(body.email).toBe(`${a.user.username}@example.com`);
      expect(body.email_verified).toBe(false);
      const b = await signedIn("noemail", { email: null });
      const nobody = await me(b.browser);
      expect(nobody.email).toBeNull();
      expect(nobody.email_verified).toBe(false);
    });

    test("email_pending is the newest live link's address; a used or expired one is not shown", async () => {
      const { user, browser } = await signedIn("pending");
      expect((await browser.api("PATCH", "/v1/me", { email: `${user.username}-new@example.com` })).status).toBe(200);
      expect((await me(browser)).email_pending).toBe(`${user.username}-new@example.com`);
      await stack.db`UPDATE one_time_tokens SET expires_at = now() - interval '1 second' WHERE user_id = ${user.id}`;
      expect((await me(browser)).email_pending).toBeNull();
      await stack.db`UPDATE one_time_tokens SET expires_at = now() + interval '1 hour', used_at = now() WHERE user_id = ${user.id}`;
      expect((await me(browser)).email_pending).toBeNull();
    });
  });

  describe("PATCH /v1/me", () => {
    describe("name", () => {
      test("is trimmed, saved and audited", async () => {
        const { user, browser } = await signedIn("rename");
        const res = await browser.api("PATCH", "/v1/me", { name: "  Zoë 李 Example  " });
        expect(res.status).toBe(200);
        const body = (await res.json()) as any;
        expect(body.name).toBe("Zoë 李 Example");
        expect(body.email_pending).toBeNull();
        expect(body.mfa).toEqual({ totp: false, passkeys: 0, recovery_codes: 0 });
        const [row] = await stack.db`SELECT name FROM users WHERE id = ${user.id}`;
        expect(row.name).toBe("Zoë 李 Example");
        const audit = await auditOf(user.id, "user.update");
        expect(audit).toHaveLength(1);
        expect(audit[0]).toMatchObject({ actor: user.id, user_id: user.id, ip: browser.ip, detail: { fields: ["name"] } });
      });

      test.each([
        ["200 code points", "😀".repeat(200), "😀".repeat(200)],
        ["an empty string", "", ""],
        ["spaces only", "   ", ""],
        ["null, which clears it", null, ""],
        ["a space inside", "A B", "A B"],
      ])("takes %s", async (_, value, saved) => {
        const { browser } = await signedIn("name-ok");
        const res = await browser.api("PATCH", "/v1/me", { name: value });
        expect(res.status).toBe(200);
        expect(((await res.json()) as any).name).toBe(saved);
      });

      test.each([
        ["201 code points", "😀".repeat(201)],
        ["a NUL", "a\u0000b"],
        ["a newline", "a\nb"],
        ["a tab", "a\tb"],
        ["a unit separator", "a\u001fb"],
        ["DEL", "a\u007fb"],
        ["a number", 5],
        ["true", true],
        ["an array", ["Alice"]],
        ["an object", { first: "Alice" }],
      ])("refuses %s", async (_, value) => {
        const { user, browser } = await signedIn("name-bad");
        await expectError(await browser.api("PATCH", "/v1/me", { name: value }), 400, "invalid_request", "A name is at most 200 characters, with no control characters.");
        const [row] = await stack.db`SELECT name FROM users WHERE id = ${user.id}`;
        expect(row.name).toBe(user.name);
        expect(await auditOf(user.id)).toEqual([]);
      });

      test("201 code points of which trailing spaces would be trimmed are still too many", async () => {
        const { browser } = await signedIn("name-len");
        await expectError(await browser.api("PATCH", "/v1/me", { name: `${"a".repeat(199)}  ` }), 400, "invalid_request", "A name is at most 200 characters, with no control characters.");
      });

      test("an empty body changes nothing and is not audited", async () => {
        const { user, browser } = await signedIn("noop");
        const res = await browser.api("PATCH", "/v1/me", {});
        expect(res.status).toBe(200);
        expect(((await res.json()) as any).name).toBe(user.name);
        expect(await auditOf(user.id)).toEqual([]);
      });

      test("the name is checked before the email", async () => {
        const { browser } = await signedIn("order2");
        await expectError(await browser.api("PATCH", "/v1/me", { name: 1, email: "nope" }), 400, "invalid_request", "A name is at most 200 characters, with no control characters.");
      });
    });

    describe("email", () => {
      test.each([
        ["no @", "nope"],
        ["no dot in the domain", "a@b"],
        ["two @", "a@b@example.com"],
        ["an empty string", ""],
        ["a space inside", "a b@example.com"],
        ["a number", 5],
        ["null", null],
        ["an array", ["a@example.com"]],
        ["a domain whose last label has no letter", "a@example.123"],
        ["a local part over 64 characters", `${"a".repeat(65)}@example.com`],
      ])("refuses %s", async (_, value) => {
        const { user, browser } = await signedIn("email-bad");
        await expectError(await browser.api("PATCH", "/v1/me", { email: value }), 400, "invalid_request", "That is not an email address.");
        expect(await auditOf(user.id)).toEqual([]);
      });

      test("a change sends a confirmation link to the new address and a notice to the old one, and waits", async () => {
        const { user, browser } = await signedIn("change");
        const next = `${user.username}-next@example.com`;
        const res = await browser.api("PATCH", "/v1/me", { email: `  ${next}  ` });
        expect(res.status).toBe(200);
        const body = (await res.json()) as any;
        expect(body.email).toBe(user.email);
        expect(body.email_verified).toBe(true);
        expect(body.email_pending).toBe(next);

        const link = await stack.smtp.waitFor(next, (m) => m.subject === "Confirm your email address");
        const url = linkIn(link);
        expect(url.origin + url.pathname).toBe(`${stack.issuer}/verify-email`);
        const token = url.searchParams.get("token")!;
        expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
        expect(link.text.trimEnd()).toBe(
          [
            "Confirm that this address is yours with this link. It works once and expires in 24 hours:",
            `${stack.issuer}/verify-email?token=${token}`,
            "",
            "If you didn't ask for this, ignore this message.",
          ].join("\n"),
        );
        const notice = await stack.smtp.waitFor(user.email!, (m) => m.subject === "Security notice: your email address is changing");
        expect(notice.text.trimEnd()).toBe(noticeText(user.username, "your email address is changing", "A confirmation link went to the new address."));

        const [row] = await stack.db`SELECT email FROM users WHERE id = ${user.id}`;
        expect(row.email).toBe(user.email);
        const tokens = await stack.db`SELECT email, purpose, expires_at > now() + interval '23 hours' AS long FROM one_time_tokens WHERE user_id = ${user.id}`;
        expect(tokens).toEqual([{ email: next, purpose: "verify_email", long: true }]);
        const audit = await auditOf(user.id, "email.change");
        expect(audit).toHaveLength(1);
        expect(audit[0]).toMatchObject({ actor: user.id, user_id: user.id, ip: browser.ip, detail: {} });
      });

      test("a name and an address change together are two audit rows", async () => {
        const { user, browser } = await signedIn("both");
        const res = await browser.api("PATCH", "/v1/me", { name: "New Name", email: `${user.username}-b@example.com` });
        expect(res.status).toBe(200);
        expect(((await res.json()) as any).name).toBe("New Name");
        expect((await auditOf(user.id)).map((r) => r.action)).toEqual(["user.update", "email.change"]);
      });

      test("only the newest pending link stays", async () => {
        const { user, browser } = await signedIn("newest");
        const first = `${user.username}-1@example.com`;
        const second = `${user.username}-2@example.com`;
        await browser.api("PATCH", "/v1/me", { email: first });
        const firstMail = await stack.smtp.waitFor(first, (m) => m.subject === "Confirm your email address");
        await browser.api("PATCH", "/v1/me", { email: second });
        const secondMail = await stack.smtp.waitFor(second, (m) => m.subject === "Confirm your email address");
        expect((await me(browser)).email_pending).toBe(second);
        const tokens: { token_hash: Buffer; email: string }[] = await stack.db`SELECT token_hash, email FROM one_time_tokens WHERE user_id = ${user.id}`;
        expect(tokens.map((t) => t.email)).toEqual([second]);
        expect(Buffer.from(tokens[0]!.token_hash).equals(sha256(linkIn(secondMail).searchParams.get("token")!))).toBe(true);
        expect(Buffer.from(tokens[0]!.token_hash).equals(sha256(linkIn(firstMail).searchParams.get("token")!))).toBe(false);
      });

      test("an address another account uses gets a notice instead of the link, and the answer is the same", async () => {
        const other = await person("holder");
        const { user, browser } = await signedIn("taker");
        const taken = other.email!.toUpperCase();
        const res = await browser.api("PATCH", "/v1/me", { email: taken });
        expect(res.status).toBe(200);
        const body = (await res.json()) as any;
        expect(body.email).toBe(user.email);
        expect(body.email_pending).toBe(taken);
        const inUse = await stack.smtp.waitFor(taken, (m) => m.subject === "Your address was used for another account");
        expect(inUse.text.trimEnd()).toBe(
          ["Someone tried to use this address for an account, but it already belongs to yours.", "Nothing changed. If it was you, sign in to the account you have."].join("\n"),
        );
        await stack.smtp.waitFor(user.email!, (m) => m.subject === "Security notice: your email address is changing");
        expect(stack.smtp.to(taken).filter((m) => m.subject === "Confirm your email address")).toEqual([]);
        expect(stack.smtp.to(other.email!)).toEqual([]);
        const [row] = await stack.db`SELECT email FROM users WHERE id = ${other.id}`;
        expect(row.email).toBe(other.email);
        expect(await auditOf(user.id, "email.change")).toHaveLength(1);
      });

      test("the same address in another case changes nothing", async () => {
        const { user, browser } = await signedIn("samecase");
        const res = await browser.api("PATCH", "/v1/me", { email: user.email!.toUpperCase() });
        expect(res.status).toBe(200);
        expect(((await res.json()) as any).email_pending).toBeNull();
        expect(await stack.db`SELECT 1 FROM one_time_tokens WHERE user_id = ${user.id}`).toHaveLength(0);
        expect(await auditOf(user.id)).toEqual([]);
        // A real change afterwards: its notice is the only one.
        await browser.api("PATCH", "/v1/me", { email: `${user.username}-x@example.com` });
        await stack.smtp.waitFor(`${user.username}-x@example.com`);
        await stack.smtp.waitFor(user.email!, (m) => m.subject.startsWith("Security notice"));
        expect(stack.smtp.to(user.email!)).toHaveLength(1);
        expect(stack.smtp.to(user.email!.toUpperCase())).toEqual([]);
      });

      test("an account without an address gets the link and no notice", async () => {
        const { user, browser } = await signedIn("noaddr", { email: null });
        const next = `${user.username}@example.com`;
        expect((await browser.api("PATCH", "/v1/me", { email: next })).status).toBe(200);
        await stack.smtp.waitFor(next, (m) => m.subject === "Confirm your email address");
        expect(stack.smtp.to(next)).toHaveLength(1);
        expect(await auditOf(user.id, "email.change")).toHaveLength(1);
      });

      test("past three emails an hour to one address it is 429 with Retry-After", async () => {
        const { user, browser } = await signedIn("limit-to");
        const target = `${user.username}-t@example.com`;
        for (let i = 0; i < 3; i++) expect((await browser.api("PATCH", "/v1/me", { email: i % 2 === 0 ? target : target.toUpperCase() })).status).toBe(200);
        const res = await browser.api("PATCH", "/v1/me", { email: target });
        expect(Number(res.headers.get("Retry-After"))).toBeGreaterThan(3500);
        expect(Number(res.headers.get("Retry-After"))).toBeLessThanOrEqual(3600);
        await expectError(res, 429, "rate_limited", "Too many emails to that address.");
        expect(await auditOf(user.id, "email.change")).toHaveLength(3);
      });

      test("past ten emails an hour from one user it is 429", async () => {
        const { user, browser } = await signedIn("limit-from");
        for (let i = 0; i < 10; i++) expect((await browser.api("PATCH", "/v1/me", { email: `${user.username}-${i}@example.com` })).status).toBe(200);
        const res = await browser.api("PATCH", "/v1/me", { email: `${user.username}-10@example.com` });
        expect(res.headers.get("Retry-After")).toMatch(/^\d+$/);
        await expectError(res, 429, "rate_limited", "Too many emails to that address.");
        expect((await me(browser)).email_pending).toBe(`${user.username}-9@example.com`);
      });

      test("a change to the account's own address counts against the limits too", async () => {
        const { user, browser } = await signedIn("limit-self");
        for (let i = 0; i < 3; i++) expect((await browser.api("PATCH", "/v1/me", { email: user.email })).status).toBe(200);
        await expectError(await browser.api("PATCH", "/v1/me", { email: user.email }), 429, "rate_limited", "Too many emails to that address.");
      });
    });
  });

  describe("DELETE /v1/me", () => {
    test("is 403 when the deployment doesn't allow it, before the sign-in's age is looked at", async () => {
      for (const authAge of [0, 3600]) {
        const { user, browser } = await signedIn("nodelete", {}, { authAge });
        await expectError(await browser.api("DELETE", "/v1/me"), 403, "forbidden", "This deployment doesn't let people delete their own accounts.");
        expect(await stack.db`SELECT 1 FROM users WHERE id = ${user.id}`).toHaveLength(1);
      }
    });

    describe("with ALLOW_ACCOUNT_DELETION=true", () => {
      let del: Stack;
      beforeAll(async () => {
        del = await Stack.start({ env: { ALLOW_ACCOUNT_DELETION: "true" } });
      });
      afterAll(async () => {
        await del.stop();
      });

      test("GET /v1/me says so", async () => {
        const u = await del.user({ username: uname("flag") });
        expect(((await (await (await del.session(u)).api("GET", "/v1/me")).json()) as any).account_deletion).toBe(true);
      });

      test("needs a recent sign-in", async () => {
        const u = await del.user({ username: uname("stale") });
        const b = await del.session(u, { authAge: 16 * 60 });
        await expectError(await b.api("DELETE", "/v1/me"), 403, "reauth_required", "Sign in again to make this change.");
      });

      test("needs the second factor when the account has one", async () => {
        const u = await del.user({ username: uname("tfa"), totp: true });
        const b = await del.session(u);
        await expectError(await b.api("DELETE", "/v1/me"), 403, "reauth_required", "Sign in again with your second factor to make this change.");
      });

      test("is 409 while the user owns bots", async () => {
        const u = await del.user({ username: uname("owner") });
        await del.user({ username: uname("bot"), kind: "bot", ownerId: u.id });
        const b = await del.session(u);
        await expectError(await b.api("DELETE", "/v1/me"), 409, "conflict", "This user owns bot users; delete them or give them another owner first.");
        expect(await del.db`SELECT 1 FROM users WHERE id = ${u.id}`).toHaveLength(1);
      });

      test("erases the account, clears the cookie, tells every service with an events_url, and is audited", async () => {
        const u = await del.user({ username: uname("gone"), access: { wiki: "member" }, totp: true, recoveryCodes: 2 });
        const b = await del.session(u, { amr: ["pwd", "otp", "mfa"] });
        const other = await del.session(u);
        const res = await b.api("DELETE", "/v1/me");
        expect(res.status).toBe(204);
        expect(await res.text()).toBe("");
        expect(res.headers.getSetCookie()).toContain(CLEARED_COOKIE);
        expect(await del.db`SELECT 1 FROM users WHERE id = ${u.id}`).toHaveLength(0);
        expect(await del.db`SELECT 1 FROM sessions WHERE user_id = ${u.id}`).toHaveLength(0);
        await expectError(await other.api("GET", "/v1/me"), 401, "unauthorized", "Sign in first.");
        for (const service of ["wiki", "tasks", "mailbox"]) {
          const e = await del.http.waitForEvent(service, "user.deleted", (x) => x.payload.sub === u.id);
          expect(e.payload).toEqual({ sub: u.id });
        }
        expect((await del.outbox("notes")).length).toBe(0);
        const audit = (await del.audit("user.delete")).filter((r) => r.user_id === u.id);
        expect(audit).toHaveLength(1);
        expect(audit[0]).toMatchObject({ actor: u.id, ip: b.ip, detail: { username: u.username } });
      });
    });
  });

  // ------------------------------------------------------------ password

  describe("POST /v1/me/password", () => {
    test.each([
      ["missing", {}],
      ["null", { new: null }],
      ["a number", { new: 123456789012 }],
      ["an array", { new: ["a long enough password"] }],
      ["an object", { new: {} }],
    ])("new %s is 400", async (_, body) => {
      const { browser } = await signedIn("pw-new");
      await expectError(await browser.api("POST", "/v1/me/password", { current: PASSWORD, ...body }), 400, "invalid_request", "new is required.");
    });

    test.each([
      ["wrong", { current: "s3cret-pw wrong" }],
      ["missing", {}],
      ["a number", { current: 1234 }],
      ["an empty string", { current: "" }],
    ])("current %s is 403 and counts as a failure", async (_, body) => {
      const { user, browser } = await signedIn("pw-cur");
      await expectError(await browser.api("POST", "/v1/me/password", { new: "a brand new passphrase", ...body }), 403, "forbidden", "The current password is wrong.");
      const [row] = await stack.db`SELECT password_hash FROM users WHERE id = ${user.id}`;
      expect(await Bun.password.verify(PASSWORD, row.password_hash)).toBe(true);
      expect(await auditOf(user.id, "password.change")).toEqual([]);
    });

    test("five wrong current passwords, then 429 with Retry-After, even for the right one", async () => {
      const { browser } = await signedIn("pw-guess");
      for (let i = 0; i < 5; i++) {
        await expectError(await browser.api("POST", "/v1/me/password", { current: `wrong-${i}`, new: "a brand new passphrase" }), 403, "forbidden", "The current password is wrong.");
      }
      const res = await browser.api("POST", "/v1/me/password", { current: PASSWORD, new: "a brand new passphrase" });
      const retry = Number(res.headers.get("Retry-After"));
      expect(retry).toBeGreaterThanOrEqual(1);
      expect(retry).toBeLessThanOrEqual(60);
      await expectError(res, 429, "rate_limited", "Too many failed attempts.");
    });

    test("the wrong-password count is the account's sign-in count", async () => {
      const { user, browser } = await signedIn("pw-shared");
      for (let i = 0; i < 5; i++) await browser.api("POST", "/v1/me/password", { current: `wrong-${i}`, new: "a brand new passphrase" });
      const page = await stack.browser().form("/login", { login: user.username, password: PASSWORD, return_to: "/account" });
      expect(page.status).toBe(429);
      await page.body?.cancel();
    });

    test("thirty attempts from one address in 15 minutes, then 429 with Retry-After", async () => {
      const { user, browser } = await signedIn("pw-ip", { password: null });
      for (let i = 0; i < 30; i++) {
        await expectError(await browser.api("POST", "/v1/me/password", { new: "short" }), 400, "invalid_request", "Use at least 12 characters.");
      }
      const res = await browser.api("POST", "/v1/me/password", { new: "a brand new passphrase" });
      const retry = Number(res.headers.get("Retry-After"));
      expect(retry).toBeGreaterThan(800);
      expect(retry).toBeLessThanOrEqual(900);
      await expectError(res, 429, "rate_limited", "Too many attempts from your network.");
      // Another address isn't held back.
      const elsewhere = await stack.session(user);
      await expectError(await elsewhere.api("POST", "/v1/me/password", { new: "short" }), 400, "invalid_request", "Use at least 12 characters.");
    });

    test("the per-address limit is not reached by a request that lacks new", async () => {
      const { browser } = await signedIn("pw-ip2", { password: null });
      for (let i = 0; i < 31; i++) expect((await browser.api("POST", "/v1/me/password", {})).status).toBe(400);
      await expectError(await browser.api("POST", "/v1/me/password", { new: "short" }), 400, "invalid_request", "Use at least 12 characters.");
    });

    test.each([
      ["11 characters", "a".repeat(11), "Use at least 12 characters."],
      ["11 code points in 22 UTF-16 units", "😀".repeat(11), "Use at least 12 characters."],
      ["257 characters", "a".repeat(257), "Use at most 256 characters."],
      ["a breached password", "password1234", "This password appears in known data breaches. Choose another."],
    ])("refuses %s", async (_, value, message) => {
      const { user, browser } = await signedIn("pw-policy", { password: null });
      await expectError(await browser.api("POST", "/v1/me/password", { new: value }), 400, "invalid_request", message);
      const [row] = await stack.db`SELECT password_hash FROM users WHERE id = ${user.id}`;
      expect(row.password_hash).toBeNull();
    });

    test("refuses the username and the email address, in any case", async () => {
      const { user, browser } = await signedIn("pw-username-x", { password: null });
      await expectError(await browser.api("POST", "/v1/me/password", { new: user.username.toUpperCase() }), 400, "invalid_request", "Don't use your username as your password.");
      await expectError(await browser.api("POST", "/v1/me/password", { new: user.email!.toUpperCase() }), 400, "invalid_request", "Don't use your email address as your password.");
    });

    test("the breached-password check asks the range API for a padded prefix of the SHA-1", async () => {
      const { browser } = await signedIn("pw-range", { password: null });
      const before = stack.http.rangeRequests.length;
      await browser.api("POST", "/v1/me/password", { new: "password1234" });
      const asked = stack.http.rangeRequests.slice(before);
      expect(asked).toEqual([{ path: `/range/${sha1Hex("password1234").slice(0, 5)}`, padding: "true" }]);
    });

    test.each([
      ["12 characters", "abcdefghijkl"],
      ["12 code points of emoji", "😀".repeat(12)],
      ["256 characters", "b".repeat(256)],
    ])("takes %s", async (_, value) => {
      const { user, browser } = await signedIn("pw-ok", { password: null });
      expect((await browser.api("POST", "/v1/me/password", { new: value })).status).toBe(204);
      const [row] = await stack.db`SELECT password_hash FROM users WHERE id = ${user.id}`;
      expect(await Bun.password.verify(value, row.password_hash)).toBe(true);
    });

    test("a change ends the other sessions, keeps this one, sends a notice and is audited", async () => {
      const { user, browser } = await signedIn("pw-change");
      const other = await stack.session(user);
      const res = await browser.api("POST", "/v1/me/password", { current: PASSWORD, new: "a brand new passphrase" });
      expect(res.status).toBe(204);
      expect(await res.text()).toBe("");
      expect(res.headers.getSetCookie()).toEqual([]);
      expect((await browser.api("GET", "/v1/me")).status).toBe(200);
      await expectError(await other.api("GET", "/v1/me"), 401, "unauthorized", "Sign in first.");
      const [row] = await stack.db`SELECT password_hash FROM users WHERE id = ${user.id}`;
      expect(row.password_hash).toStartWith("$argon2id$v=19$m=19456,t=2,p=1$");
      expect(await Bun.password.verify("a brand new passphrase", row.password_hash)).toBe(true);
      const mail = await stack.smtp.waitFor(user.email!, (m) => m.subject === "Security notice: password changed");
      expect(mail.text.trimEnd()).toBe(noticeText(user.username, "password changed"));
      const audit = await auditOf(user.id, "password.change");
      expect(audit).toHaveLength(1);
      expect(audit[0]).toMatchObject({ actor: user.id, ip: browser.ip, detail: {} });
    });

    test("ends a public client's refresh-token family too", async () => {
      const { user, browser } = await signedIn("pw-family", { access: { tasks: "user" } });
      const { tokens } = await signInTo(stack, browser, "tasks-ios");
      expect((await browser.api("POST", "/v1/me/password", { current: PASSWORD, new: "a brand new passphrase" })).status).toBe(204);
      const res = await backChannel(stack, "/oauth/token", { grant_type: "refresh_token", refresh_token: tokens.refresh_token!, client_id: "tasks-ios" });
      await expectError(res, 400, "invalid_grant", "The refresh token is invalid, expired or revoked.");
      expect((await browser.api("GET", "/v1/me")).status).toBe(200);
      expect(user.id).toMatch(ID);
    });

    test("an account without a password sets one, whatever current says", async () => {
      const { user, browser } = await signedIn("pw-none", { password: null });
      expect((await browser.api("POST", "/v1/me/password", { current: "s3cret-pw", new: "a first passphrase" })).status).toBe(204);
      const [row] = await stack.db`SELECT password_hash FROM users WHERE id = ${user.id}`;
      expect(await Bun.password.verify("a first passphrase", row.password_hash)).toBe(true);
    });
  });

  // ---------------------------------------------------------------- TOTP

  describe("POST /v1/me/totp", () => {
    async function start(browser: Browser): Promise<{ otpauth_uri: string; secret: string; enrollment: string }> {
      const res = await browser.api("POST", "/v1/me/totp", {});
      expect(res.status).toBe(200);
      return (await res.json()) as any;
    }

    test("starting answers a URI, the secret and a sealed enrolment, and stores nothing", async () => {
      const { user, browser } = await signedIn("totp-start");
      const s = await start(browser);
      expect(Object.keys(s).sort()).toEqual(["enrollment", "otpauth_uri", "secret"]);
      expect(s.secret).toMatch(/^[A-Z2-7]{32}$/);
      const host = `127.0.0.1%3A${stack.port}`;
      expect(s.otpauth_uri).toBe(`otpauth://totp/${host}:${user.username}?secret=${s.secret}&issuer=${host}&algorithm=SHA1&digits=6&period=30`);
      const opened = stack.crypt.open<{ u: string; s: string }>("totp-enrol", s.enrollment);
      expect(opened.v).toEqual({ u: user.id, s: s.secret.toLowerCase() });
      expect(opened.exp).toBeGreaterThan(Date.now() + 14 * 60 * 1000);
      expect(opened.exp).toBeLessThanOrEqual(Date.now() + 15 * 60 * 1000);
      expect(await stack.db`SELECT 1 FROM totp WHERE user_id = ${user.id}`).toHaveLength(0);
      expect((await start(browser)).secret).not.toBe(s.secret);
    });

    test("a right code saves the secret, steps the session up, gives ten codes, and is audited and announced", async () => {
      const { user, browser } = await signedIn("totp-ok");
      const oldToken = browser.cookies.get("__Host-auth")!;
      const s = await start(browser);
      const res = await browser.api("POST", "/v1/me/totp", { enrollment: s.enrollment, code: totp(fromBase32(s.secret)) });
      expect(res.status).toBe(200);
      const cookies = res.headers.getSetCookie();
      expect(cookies).toHaveLength(1);
      const m = SESSION_COOKIE.exec(cookies[0]!);
      expect(m).not.toBeNull();
      expect(m![1]).not.toBe(oldToken);
      const body = (await res.json()) as { recovery_codes: string[] };
      expect(Object.keys(body)).toEqual(["recovery_codes"]);
      expect(body.recovery_codes).toHaveLength(10);
      for (const c of body.recovery_codes) expect(c).toMatch(RECOVERY_CODE);
      expect(new Set(body.recovery_codes).size).toBe(10);

      const [session] = await stack.db`SELECT id, amr, token_hash FROM sessions WHERE user_id = ${user.id}`;
      expect(session.id).toBe(browser.sessionId);
      expect(session.amr).toEqual(["pwd", "otp", "mfa"]);
      expect(Buffer.from(session.token_hash).equals(sha256(m![1]!))).toBe(true);
      const [row] = await stack.db`SELECT secret_enc, last_step FROM totp WHERE user_id = ${user.id}`;
      expect(stack.crypt.decrypt(row.secret_enc, user.id).equals(fromBase32(s.secret))).toBe(true);
      expect(Number(row.last_step)).toBeGreaterThanOrEqual(Math.floor(Date.now() / 30000) - 1);
      const codes: { code_hash: Buffer }[] = await stack.db`SELECT code_hash FROM recovery_codes WHERE user_id = ${user.id} AND used_at IS NULL`;
      expect(codes.map((c) => Buffer.from(c.code_hash).toString("hex")).sort()).toEqual(body.recovery_codes.map((c) => sha256(c.replace(/-/g, "")).toString("hex")).sort());

      // The old cookie is gone; the new one carries the second factor.
      const stale = stack.browser();
      stale.cookies.set("__Host-auth", oldToken);
      await expectError(await stale.api("GET", "/v1/me"), 401, "unauthorized", "Sign in first.");
      expect((await me(browser)).mfa).toEqual({ totp: true, passkeys: 0, recovery_codes: 10 });
      expect((await browser.api("POST", "/v1/me/recovery-codes")).status).toBe(200);

      const audit = await auditOf(user.id, "totp.enroll");
      expect(audit).toHaveLength(1);
      expect(audit[0]).toMatchObject({ actor: user.id, ip: browser.ip, detail: {} });
      const mail = await stack.smtp.waitFor(user.email!, (x) => x.subject === "Security notice: two-factor authentication added");
      expect(mail.text.trimEnd()).toBe(noticeText(user.username, "two-factor authentication added"));
    });

    test("with recovery codes left, the codes are kept and none are given", async () => {
      const { user, browser } = await signedIn("totp-codes", { recoveryCodes: 3 });
      const s = await start(browser);
      const res = await browser.api("POST", "/v1/me/totp", { enrollment: s.enrollment, code: totp(fromBase32(s.secret)) });
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ recovery_codes: null });
      expect(await stack.db`SELECT 1 FROM recovery_codes WHERE user_id = ${user.id}`).toHaveLength(3);
    });

    test("with every recovery code used, ten new ones replace them", async () => {
      const { user, browser } = await signedIn("totp-used", { recoveryCodes: 2 });
      await stack.db`UPDATE recovery_codes SET used_at = now() WHERE user_id = ${user.id}`;
      const s = await start(browser);
      const body = (await (await browser.api("POST", "/v1/me/totp", { enrollment: s.enrollment, code: totp(fromBase32(s.secret)) })).json()) as any;
      expect(body.recovery_codes).toHaveLength(10);
      expect(await stack.db`SELECT 1 FROM recovery_codes WHERE user_id = ${user.id}`).toHaveLength(10);
    });

    test("an amr that already had the factors keeps each once", async () => {
      const { user, browser } = await signedIn("totp-again", { totp: true }, { amr: ["pwd", "otp", "mfa"] });
      const s = await start(browser);
      expect((await browser.api("POST", "/v1/me/totp", { enrollment: s.enrollment, code: ` ${totp(fromBase32(s.secret))} ` })).status).toBe(200);
      const [session] = await stack.db`SELECT amr FROM sessions WHERE id = ${browser.sessionId}`;
      expect(session.amr).toEqual(["pwd", "otp", "mfa"]);
      // Enrolling again replaces the secret.
      const [row] = await stack.db`SELECT secret_enc FROM totp WHERE user_id = ${user.id}`;
      expect(stack.crypt.decrypt(row.secret_enc, user.id).equals(fromBase32(s.secret))).toBe(true);
    });

    test("the next step's code is accepted", async () => {
      const { browser } = await signedIn("totp-next");
      const s = await start(browser);
      expect((await browser.api("POST", "/v1/me/totp", { enrollment: s.enrollment, code: totp(fromBase32(s.secret), Date.now(), 1) })).status).toBe(200);
    });

    test("the confirming code can't then be used to sign in", async () => {
      const { user, browser } = await signedIn("totp-replay");
      const s = await start(browser);
      const code = totp(fromBase32(s.secret), Date.now(), 1);
      expect((await browser.api("POST", "/v1/me/totp", { enrollment: s.enrollment, code })).status).toBe(200);
      const other = stack.browser();
      const res = await other.signIn(user.username, PASSWORD, code);
      expect(res.status).toBe(401);
      expect(await res.text()).toContain("That code didn&#39;t work.");
    });

    test("confirming the same enrolment again saves the same secret again", async () => {
      const { user, browser } = await signedIn("totp-twice");
      const s = await start(browser);
      const code = totp(fromBase32(s.secret));
      expect((await browser.api("POST", "/v1/me/totp", { enrollment: s.enrollment, code })).status).toBe(200);
      const again = await browser.api("POST", "/v1/me/totp", { enrollment: s.enrollment, code });
      expect(again.status).toBe(200);
      expect(await again.json()).toEqual({ recovery_codes: null });
      expect(await auditOf(user.id, "totp.enroll")).toHaveLength(2);
    });

    const REFUSED = "That code doesn't match; the enrolment may have expired.";

    test.each([
      ["a wrong code", (s: any) => ({ enrollment: s.enrollment, code: totp(fromBase32(s.secret)) === "000000" ? "111111" : "000000" })],
      ["a code two steps old", (s: any) => ({ enrollment: s.enrollment, code: totp(fromBase32(s.secret), Date.now(), -2) })],
      ["a code of five digits", (s: any) => ({ enrollment: s.enrollment, code: totp(fromBase32(s.secret)).slice(1) })],
      ["a code with letters", (s: any) => ({ enrollment: s.enrollment, code: "12a456" })],
      ["a code as a number", (s: any) => ({ enrollment: s.enrollment, code: Number(`1${totp(fromBase32(s.secret))}`) - 1000000 })],
      ["no code", (s: any) => ({ enrollment: s.enrollment })],
      ["a null code", (s: any) => ({ enrollment: s.enrollment, code: null })],
      ["an array code", (s: any) => ({ enrollment: s.enrollment, code: [totp(fromBase32(s.secret))] })],
      ["a null enrolment", (s: any) => ({ enrollment: null, code: totp(fromBase32(s.secret)) })],
      ["an enrolment that is a number", (s: any) => ({ enrollment: 5, code: totp(fromBase32(s.secret)) })],
      ["an enrolment that is an object", (s: any) => ({ enrollment: { u: "x" }, code: totp(fromBase32(s.secret)) })],
      ["an enrolment that isn't sealed", (s: any) => ({ enrollment: "abc123", code: totp(fromBase32(s.secret)) })],
      ["an empty enrolment", (s: any) => ({ enrollment: "", code: totp(fromBase32(s.secret)) })],
      ["an enrolment changed by one character", (s: any) => ({ enrollment: s.enrollment.slice(0, -2) + (s.enrollment.endsWith("AA") ? "BB" : "AA"), code: totp(fromBase32(s.secret)) })],
    ])("%s is 400 and saves nothing", async (_, body) => {
      const { user, browser } = await signedIn("totp-bad");
      const s = await start(browser);
      const token = browser.cookies.get("__Host-auth");
      const res = await browser.api("POST", "/v1/me/totp", body(s));
      expect(res.headers.getSetCookie()).toEqual([]);
      await expectError(res, 400, "invalid_request", REFUSED);
      expect(browser.cookies.get("__Host-auth")).toBe(token);
      expect(await stack.db`SELECT 1 FROM totp WHERE user_id = ${user.id}`).toHaveLength(0);
      expect(await auditOf(user.id, "totp.enroll")).toEqual([]);
    });

    test("an expired enrolment is refused", async () => {
      const { user, browser } = await signedIn("totp-exp");
      const secret = randomBytes(20);
      const enrollment = stack.crypt.seal("totp-enrol", { u: user.id, s: base32(secret) }, -1);
      await expectError(await browser.api("POST", "/v1/me/totp", { enrollment, code: totp(secret) }), 400, "invalid_request", REFUSED);
      // The same, still live, is accepted.
      const live = stack.crypt.seal("totp-enrol", { u: user.id, s: base32(secret) }, 60);
      expect((await browser.api("POST", "/v1/me/totp", { enrollment: live, code: totp(secret) })).status).toBe(200);
    });

    test("an enrolment sealed for another user is refused", async () => {
      const { browser } = await signedIn("totp-mine");
      const other = await person("totp-theirs");
      const secret = randomBytes(20);
      const enrollment = stack.crypt.seal("totp-enrol", { u: other.id, s: base32(secret) }, 60);
      await expectError(await browser.api("POST", "/v1/me/totp", { enrollment, code: totp(secret) }), 400, "invalid_request", REFUSED);
      expect(await stack.db`SELECT 1 FROM totp WHERE user_id = ${other.id}`).toHaveLength(0);
    });

    test("another user's real enrolment is refused", async () => {
      const a = await signedIn("totp-a");
      const b = await signedIn("totp-b");
      const s = await start(a.browser);
      await expectError(await b.browser.api("POST", "/v1/me/totp", { enrollment: s.enrollment, code: totp(fromBase32(s.secret)) }), 400, "invalid_request", REFUSED);
    });

    test("an enrolment sealed for another purpose is refused", async () => {
      const { user, browser } = await signedIn("totp-purpose");
      const secret = randomBytes(20);
      const enrollment = stack.crypt.seal("passkey-reg", { u: user.id, s: base32(secret) }, 60);
      await expectError(await browser.api("POST", "/v1/me/totp", { enrollment, code: totp(secret) }), 400, "invalid_request", REFUSED);
    });

    test("without enrollment a code alone starts again", async () => {
      const { user, browser } = await signedIn("totp-codeonly");
      const res = await browser.api("POST", "/v1/me/totp", { code: "123456" });
      expect(res.status).toBe(200);
      expect(Object.keys((await res.json()) as object).sort()).toEqual(["enrollment", "otpauth_uri", "secret"]);
      expect(await stack.db`SELECT 1 FROM totp WHERE user_id = ${user.id}`).toHaveLength(0);
    });
  });

  describe("DELETE /v1/me/totp", () => {
    test("removes the authenticator, keeps the recovery codes, and is audited and announced", async () => {
      const { user, browser } = await signedIn("untotp", { totp: true, recoveryCodes: 2 }, { amr: ["pwd", "otp", "mfa"] });
      const res = await browser.api("DELETE", "/v1/me/totp");
      expect(res.status).toBe(204);
      expect(await res.text()).toBe("");
      expect(await stack.db`SELECT 1 FROM totp WHERE user_id = ${user.id}`).toHaveLength(0);
      expect(await stack.db`SELECT 1 FROM recovery_codes WHERE user_id = ${user.id}`).toHaveLength(2);
      const audit = await auditOf(user.id, "totp.remove");
      expect(audit).toHaveLength(1);
      expect(audit[0]).toMatchObject({ actor: user.id, ip: browser.ip, detail: {} });
      const mail = await stack.smtp.waitFor(user.email!, (m) => m.subject === "Security notice: two-factor authentication removed");
      expect(mail.text.trimEnd()).toBe(noticeText(user.username, "two-factor authentication removed"));
    });

    test("without an authenticator it is 404", async () => {
      const { user, browser } = await signedIn("nototp");
      await expectError(await browser.api("DELETE", "/v1/me/totp"), 404, "not_found", "No authenticator app is set up.");
      expect(await auditOf(user.id)).toEqual([]);
    });
  });

  describe("POST /v1/me/recovery-codes", () => {
    test("makes ten codes in six groups of four, replacing every old one, audited and announced", async () => {
      const { user, browser } = await signedIn("codes", { totp: true, recoveryCodes: 5 }, { amr: ["pwd", "otp", "mfa"] });
      const res = await browser.api("POST", "/v1/me/recovery-codes");
      expect(res.status).toBe(200);
      const body = (await res.json()) as { codes: string[] };
      expect(Object.keys(body)).toEqual(["codes"]);
      expect(body.codes).toHaveLength(10);
      for (const c of body.codes) expect(c).toMatch(RECOVERY_CODE);
      expect(new Set(body.codes).size).toBe(10);
      const rows: { code_hash: Buffer; used_at: Date | null }[] = await stack.db`SELECT code_hash, used_at FROM recovery_codes WHERE user_id = ${user.id}`;
      expect(rows.map((r) => Buffer.from(r.code_hash).toString("hex")).sort()).toEqual(body.codes.map((c) => sha256(c.replace(/-/g, "")).toString("hex")).sort());
      expect(rows.every((r) => r.used_at === null)).toBe(true);
      for (const old of user.recoveryCodes) expect(rows.some((r) => Buffer.from(r.code_hash).equals(sha256(old.replace(/-/g, ""))))).toBe(false);
      expect((await me(browser)).mfa.recovery_codes).toBe(10);
      const audit = await auditOf(user.id, "recovery.regenerate");
      expect(audit).toHaveLength(1);
      expect(audit[0]).toMatchObject({ actor: user.id, ip: browser.ip, detail: {} });
      const mail = await stack.smtp.waitFor(user.email!, (m) => m.subject === "Security notice: recovery codes regenerated");
      expect(mail.text.trimEnd()).toBe(noticeText(user.username, "recovery codes regenerated"));
    });

    test("an account without an address gets its codes and no mail", async () => {
      const { user, browser } = await signedIn("codes-nomail", { email: null });
      expect((await browser.api("POST", "/v1/me/recovery-codes")).status).toBe(200);
      expect(await auditOf(user.id, "recovery.regenerate")).toHaveLength(1);
    });
  });

  // ------------------------------------------------------------ sessions

  describe("sessions", () => {
    test("GET lists the SSO sessions, the current one marked, then each public client's family", async () => {
      const user = await person("devices", { access: { tasks: "user" } });
      const b1 = await stack.session(user, { ip: "192.0.2.10", userAgent: "Agent One" });
      const b2 = await stack.session(user, { ip: "2001:db8::1", userAgent: null, amr: ["pwd", "otp", "mfa"] });
      await stack.session(user, { expiresIn: "-1 second" });
      await stack.session(user, { endsIn: "-1 second" });
      await stack.session(await person("stranger"));
      const { tokens } = await signInTo(stack, b1, "tasks-ios");
      const family = decodeJwt(tokens.access_token).claims.sid as string;
      // A confidential client's tokens ride on the SSO session: not listed apart.
      await signInTo(stack, b1, "tasks");
      // A revoked family isn't listed.
      const revoked = await signInTo(stack, b2, "tasks-ios");
      await stack.db`UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = ${decodeJwt(revoked.tokens.access_token).claims.sid}`;
      await stack.db`UPDATE sessions SET last_seen_at = now() - interval '30 seconds' WHERE id = ${b2.sessionId}`;

      const res = await b1.api("GET", "/v1/me/sessions");
      expect(res.status).toBe(200);
      const body = (await res.json()) as { items: any[]; next: null };
      const [s1] = await stack.db`SELECT created_at, last_seen_at FROM sessions WHERE id = ${b1.sessionId}`;
      const [s2] = await stack.db`SELECT created_at, last_seen_at FROM sessions WHERE id = ${b2.sessionId}`;
      const [f] = await stack.db`SELECT min(created_at) AS created_at, max(created_at) AS last_seen_at FROM refresh_tokens WHERE family_id = ${family}`;
      expect(body).toEqual({
        items: [
          { id: b1.sessionId, current: true, created_at: s1.created_at.toISOString(), last_seen_at: s1.last_seen_at.toISOString(), ip: "192.0.2.10", user_agent: "Agent One", amr: ["pwd"], client: null },
          { id: b2.sessionId, current: false, created_at: s2.created_at.toISOString(), last_seen_at: s2.last_seen_at.toISOString(), ip: "2001:db8::1", user_agent: null, amr: ["pwd", "otp", "mfa"], client: null },
          { id: family, current: false, created_at: f.created_at.toISOString(), last_seen_at: f.last_seen_at.toISOString(), ip: null, user_agent: null, amr: null, client: "tasks-ios" },
        ],
        next: null,
      });
      expect(family).toMatch(/^ses_/);
      // From the other device, that one is current.
      const fromB2 = (await (await b2.api("GET", "/v1/me/sessions")).json()) as { items: any[] };
      expect(fromB2.items.map((i) => [i.id, i.current])).toEqual([
        [b1.sessionId, false],
        [b2.sessionId, true],
        [family, false],
      ]);
    });

    test("DELETE one ends another device's session, tells the apps that hold tokens under it, and is audited", async () => {
      const user = await person("endone", { access: { tasks: "user" } });
      const b1 = await stack.session(user);
      const b2 = await stack.session(user);
      await signInTo(stack, b2, "tasks");
      const res = await b1.api("DELETE", `/v1/me/sessions/${b2.sessionId}`);
      expect(res.status).toBe(204);
      expect(res.headers.getSetCookie()).toEqual([]);
      await expectError(await b2.api("GET", "/v1/me"), 401, "unauthorized", "Sign in first.");
      expect((await b1.api("GET", "/v1/me")).status).toBe(200);
      expect((await stack.outbox("tasks")).filter((e) => e.type === "session.ended" && e.payload.sid === b2.sessionId).map((e) => e.payload)).toEqual([{ sid: b2.sessionId }]);
      const audit = await auditOf(user.id, "session.end");
      expect(audit).toHaveLength(1);
      expect(audit[0]).toMatchObject({ actor: user.id, ip: b1.ip, detail: { sid: b2.sessionId } });
    });

    test("DELETE the current session clears the cookie", async () => {
      const { user, browser } = await signedIn("endself");
      const id = browser.sessionId!;
      const res = await browser.api("DELETE", `/v1/me/sessions/${id}`);
      expect(res.status).toBe(204);
      expect(res.headers.getSetCookie()).toEqual([CLEARED_COOKIE]);
      expect(await stack.db`SELECT 1 FROM sessions WHERE id = ${id}`).toHaveLength(0);
      expect(await auditOf(user.id, "session.end")).toHaveLength(1);
    });

    test("DELETE a public client's family stops its refresh token and tells its service", async () => {
      const { user, browser } = await signedIn("endfamily", { access: { tasks: "user" } });
      const { tokens } = await signInTo(stack, browser, "tasks-ios");
      const family = decodeJwt(tokens.access_token).claims.sid as string;
      const res = await browser.api("DELETE", `/v1/me/sessions/${family}`);
      expect(res.status).toBe(204);
      expect(res.headers.getSetCookie()).toEqual([]);
      const refresh = await backChannel(stack, "/oauth/token", { grant_type: "refresh_token", refresh_token: tokens.refresh_token!, client_id: "tasks-ios" });
      await expectError(refresh, 400, "invalid_grant", "The refresh token is invalid, expired or revoked.");
      const e = await stack.http.waitForEvent("tasks", "session.ended", (x) => x.payload.sid === family);
      expect(e.payload).toEqual({ sid: family });
      expect((await browser.api("GET", "/v1/me")).status).toBe(200);
      const audit = await auditOf(user.id, "session.end");
      expect(audit.map((a) => a.detail)).toEqual([{ sid: family }]);
      // It's gone from the list, and ending it again is 404.
      const list = (await (await browser.api("GET", "/v1/me/sessions")).json()) as { items: any[] };
      expect(list.items.map((i) => i.id)).toEqual([browser.sessionId]);
      await expectError(await browser.api("DELETE", `/v1/me/sessions/${family}`), 404, "not_found", "No such session.");
    });

    test("an unknown id, or another user's session or family, is 404 and ends nothing", async () => {
      const { user, browser } = await signedIn("endother", { access: { tasks: "user" } });
      const theirs = await stack.session(await person("victim", { access: { tasks: "user" } }));
      const { tokens } = await signInTo(stack, theirs, "tasks-ios");
      const family = decodeJwt(tokens.access_token).claims.sid as string;
      for (const id of [newId("ses"), "nope", theirs.sessionId!, family]) {
        await expectError(await browser.api("DELETE", `/v1/me/sessions/${id}`), 404, "not_found", "No such session.");
      }
      expect((await theirs.api("GET", "/v1/me")).status).toBe(200);
      const refresh = await backChannel(stack, "/oauth/token", { grant_type: "refresh_token", refresh_token: tokens.refresh_token!, client_id: "tasks-ios" });
      expect(refresh.status).toBe(200);
      expect(await auditOf(user.id)).toEqual([]);
    });

    test("DELETE all signs out every device and family, this one included, and is audited", async () => {
      const { user, browser } = await signedIn("endall", { access: { tasks: "user" } });
      const other = await stack.session(user);
      const { tokens } = await signInTo(stack, other, "tasks-ios");
      const bystander = await stack.session(await person("bystander"));
      const res = await browser.api("DELETE", "/v1/me/sessions");
      expect(res.status).toBe(204);
      expect(res.headers.getSetCookie()).toEqual([CLEARED_COOKIE]);
      expect(await stack.db`SELECT 1 FROM sessions WHERE user_id = ${user.id}`).toHaveLength(0);
      await expectError(await other.api("GET", "/v1/me"), 401, "unauthorized", "Sign in first.");
      const refresh = await backChannel(stack, "/oauth/token", { grant_type: "refresh_token", refresh_token: tokens.refresh_token!, client_id: "tasks-ios" });
      expect(refresh.status).toBe(400);
      expect((await bystander.api("GET", "/v1/me")).status).toBe(200);
      const audit = await auditOf(user.id, "session.end_all");
      expect(audit).toHaveLength(1);
      expect(audit[0]).toMatchObject({ actor: user.id, ip: browser.ip, detail: {} });
    });
  });

  // ---------------------------------------- app passwords and API keys

  const KINDS = [
    {
      kind: "app_password",
      path: "/v1/me/app-passwords",
      service: "mailbox",
      scopes: ["imap", "smtp"],
      field: "password",
      plural: "app passwords",
      singular: "app password",
      prefix: "apw",
      other: "tasks",
    },
    {
      kind: "api_key",
      path: "/v1/me/api-keys",
      service: "tasks",
      scopes: ["tasks:read", "tasks:write"],
      field: "key",
      plural: "API keys",
      singular: "API key",
      prefix: "key",
      other: "mailbox",
    },
  ] as const;

  describe.each(KINDS)("$path", (k) => {
    const access = { mailbox: "user", tasks: "user", notes: "reader", wiki: "member" };
    const good = (more: Record<string, unknown> = {}) => ({ service: k.service, scopes: [k.scopes[0]], name: "My device", ...more });
    const scopesError = `scopes must be a non-empty list from: ${k.scopes.join(", ")}.`;
    const nameError = "name is 1 to 100 characters, with no control characters.";

    test("a new one is shown once with its secret, listed without it, announced and audited", async () => {
      const { user, browser } = await signedIn("cred", { access });
      const res = await browser.api("POST", k.path, { service: k.service, scopes: [...k.scopes], name: "  Phone  " });
      expect(res.status).toBe(201);
      const body = (await res.json()) as Record<string, any>;
      const secret = body[k.field] as string;
      const [row] = await stack.db`SELECT id, created_at, secret_hash, expires_at FROM credentials WHERE user_id = ${user.id}`;
      expect(body).toEqual({
        id: row.id,
        name: "Phone",
        service: k.service,
        scopes: [...k.scopes],
        created_at: row.created_at.toISOString(),
        last_used_at: null,
        ...(k.kind === "api_key" ? { expires_at: null } : {}),
        [k.field]: secret,
      });
      expect(body.id).toMatch(ID);
      expect(body.id).toStartWith(`${k.prefix}_`);
      if (k.kind === "app_password") expect(secret).toMatch(APP_PASSWORD);
      else expect(secret).toMatch(new RegExp(`^testkey_${body.id}_[A-Za-z0-9_-]{43}$`));
      expect(Buffer.from(row.secret_hash).equals(sha256(secret))).toBe(true);

      const list = await browser.api("GET", k.path);
      expect(list.status).toBe(200);
      const text = await list.text();
      expect(text).not.toContain(secret);
      const { [k.field]: _, ...shown } = body;
      expect(JSON.parse(text)).toEqual({ items: [shown], next: null });

      const mail = await stack.smtp.waitFor(user.email!, (m) => m.subject === `Security notice: an ${k.singular} was created`);
      expect(mail.text.trimEnd()).toBe(noticeText(user.username, `an ${k.singular} was created`, `For ${k.service}: Phone`));
      expect(mail.text).not.toContain(secret);
      const audit = await auditOf(user.id, `${k.kind}.create`);
      expect(audit).toHaveLength(1);
      expect(audit[0]).toMatchObject({ actor: user.id, ip: browser.ip, detail: { id: body.id, service: k.service, scopes: [...k.scopes] } });
      expect(JSON.stringify(await stack.audit())).not.toContain(secret);
      expect((await stack.outbox(k.service)).filter((e) => e.payload.sub === user.id)).toEqual([]);
    });

    test("it answers introspection by its service's client, only there, and stops once revoked", async () => {
      const { user, browser } = await signedIn("intro", { access });
      const body = (await (await browser.api("POST", k.path, { service: k.service, scopes: [...k.scopes].reverse(), name: "Laptop" })).json()) as Record<string, any>;
      const secret = body[k.field] as string;
      const check = async (client: string, token: string) => (await (await backChannel(stack, "/oauth/introspect", { token }, stack.basic(client))).json()) as Record<string, any>;
      expect(await check(k.service, secret)).toEqual({ active: true, sub: user.id, username: user.username, scope: [...k.scopes].reverse().join(" "), role: "user", jti: body.id });
      if (k.kind === "app_password") expect((await check(k.service, secret.replace(/-/g, "").toUpperCase())).active).toBe(true);
      expect(await check(k.other, secret)).toEqual({ active: false });

      const res = await browser.api("DELETE", `${k.path}/${body.id}`);
      expect(res.status).toBe(204);
      expect(await res.text()).toBe("");
      expect(await check(k.service, secret)).toEqual({ active: false });
      expect(((await (await browser.api("GET", k.path)).json()) as any).items).toEqual([]);

      const e = await stack.http.waitForEvent(k.service, "credential.revoked", (x) => x.payload.id === body.id);
      expect(e.payload).toEqual({ sub: user.id, id: body.id });
      const audit = await auditOf(user.id, `${k.kind}.revoke`);
      expect(audit).toHaveLength(1);
      expect(audit[0]).toMatchObject({ actor: user.id, ip: browser.ip, detail: { id: body.id, service: k.service } });
      await expectError(await browser.api("DELETE", `${k.path}/${body.id}`), 404, "not_found", `No such ${k.singular}.`);
      expect(await auditOf(user.id, `${k.kind}.revoke`)).toHaveLength(1);
    });

    test("another user's, an unknown one, or one of the other kind is 404 and stays", async () => {
      const owner = await signedIn("credowner", { access });
      const mine = (await (await owner.browser.api("POST", k.path, good())).json()) as Record<string, any>;
      const otherPath = k.kind === "app_password" ? "/v1/me/api-keys" : "/v1/me/app-passwords";
      const otherKind = KINDS.find((x) => x.kind !== k.kind)!;
      const theirs = (await (await owner.browser.api("POST", otherPath, { service: otherKind.service, scopes: [otherKind.scopes[0]], name: "x" })).json()) as Record<string, any>;
      const { user, browser } = await signedIn("credthief", { access });
      for (const id of [mine.id, newId(k.prefix), "nope"]) {
        await expectError(await browser.api("DELETE", `${k.path}/${id}`), 404, "not_found", `No such ${k.singular}.`);
      }
      await expectError(await owner.browser.api("DELETE", `${k.path}/${theirs.id}`), 404, "not_found", `No such ${k.singular}.`);
      expect(await stack.db`SELECT 1 FROM credentials WHERE user_id = ${owner.user.id} AND revoked_at IS NULL`).toHaveLength(2);
      expect(await auditOf(user.id)).toEqual([]);
    });

    test.each([
      ["missing", {}],
      ["a number", { service: 1 }],
      ["null", { service: null }],
      ["unknown", { service: "nope" }],
      ["in another case", { service: k.service.toUpperCase() }],
    ])("service %s is 400", async (_, more) => {
      const { browser } = await signedIn("svc", { access });
      const { service: __, ...rest } = good();
      await expectError(await browser.api("POST", k.path, { ...rest, ...more }), 400, "invalid_request", "service must name a service.");
    });

    test.each([k.other, "notes", "wiki", "auth"])("a service that declares no %s scopes is 400", async (service) => {
      const { browser } = await signedIn("svckind", { access });
      await expectError(await browser.api("POST", k.path, good({ service })), 400, "invalid_request", `${service} takes no ${k.plural}.`);
    });

    test.each([
      ["missing", undefined],
      ["null", null],
      ["a string", k.scopes[0]],
      ["empty", []],
      ["an undeclared scope", [k.scopes[0], "admin"]],
      ["a number", [1]],
      ["null inside", [null]],
      ["a scope in another case", [k.scopes[0].toUpperCase()]],
      ["an object", { 0: k.scopes[0] }],
    ])("scopes %s is 400", async (_, scopes) => {
      const { user, browser } = await signedIn("scopes", { access });
      await expectError(await browser.api("POST", k.path, good({ scopes })), 400, "invalid_request", scopesError);
      expect(await stack.db`SELECT 1 FROM credentials WHERE user_id = ${user.id}`).toHaveLength(0);
    });

    test("duplicate scopes collapse, in their first order", async () => {
      const { browser } = await signedIn("dupes", { access });
      const res = await browser.api("POST", k.path, good({ scopes: [k.scopes[1], k.scopes[0], k.scopes[1]] }));
      expect(res.status).toBe(201);
      expect(((await res.json()) as any).scopes).toEqual([k.scopes[1], k.scopes[0]]);
    });

    test.each([
      ["missing", undefined],
      ["null", null],
      ["empty", ""],
      ["spaces only", "   "],
      ["101 code points", "😀".repeat(101)],
      ["100 characters with spaces around", `  ${"a".repeat(98)}  `],
      ["a newline", "a\nb"],
      ["a tab", "a\tb"],
      ["DEL", "a\u007f"],
      ["a number", 5],
      ["an array", ["Phone"]],
    ])("name %s is 400", async (_, name) => {
      const { browser } = await signedIn("credname", { access });
      await expectError(await browser.api("POST", k.path, good({ name })), 400, "invalid_request", nameError);
    });

    test.each([
      ["100 code points", "😀".repeat(100), "😀".repeat(100)],
      ["unicode", "Zoë's 李 phone", "Zoë's 李 phone"],
    ])("name %s is taken", async (_, name, saved) => {
      const { browser } = await signedIn("credname-ok", { access });
      const res = await browser.api("POST", k.path, good({ name }));
      expect(res.status).toBe(201);
      expect(((await res.json()) as any).name).toBe(saved);
    });

    test("the checks run in order: service, scopes, name, then the role", async () => {
      const { browser } = await signedIn("credorder");
      await expectError(await browser.api("POST", k.path, { service: k.service, scopes: [], name: "" }), 400, "invalid_request", scopesError);
      await expectError(await browser.api("POST", k.path, { service: k.service, scopes: [k.scopes[0]], name: "" }), 400, "invalid_request", nameError);
      await expectError(await browser.api("POST", k.path, good()), 403, "forbidden", `You need a role on ${k.service} to create ${k.plural} for it.`);
    });

    test("without a role on the service it is 403", async () => {
      const { user, browser } = await signedIn("norole", { access: { wiki: "member" } });
      await expectError(await browser.api("POST", k.path, good()), 403, "forbidden", `You need a role on ${k.service} to create ${k.plural} for it.`);
      expect(await auditOf(user.id)).toEqual([]);
    });

    test("100 live is the most: the next is 409; a revoked one doesn't count", async () => {
      const { user, browser } = await signedIn("full", { access });
      await stack.db`
        INSERT INTO credentials (id, user_id, kind, service, scopes, name, secret_hash, revoked_at)
        SELECT ${k.prefix} || '_' || substr(md5(random()::text || i::text), 1, 26), ${user.id}, ${k.kind}, ${k.service}, ARRAY[${k.scopes[0]}]::text[], 'seed ' || i,
               sha256((${user.id} || ':' || i)::bytea), CASE WHEN i = 100 THEN now() ELSE NULL END
        FROM generate_series(1, 100) AS i`;
      const ok = await browser.api("POST", k.path, good());
      expect(ok.status).toBe(201);
      await expectError(await browser.api("POST", k.path, good()), 409, "conflict", `You have 100 ${k.plural}; revoke one first.`);
      expect(((await (await browser.api("GET", k.path)).json()) as any).items).toHaveLength(100);
    });

    test("the list is in id order, with each one's last use", async () => {
      const { user, browser } = await signedIn("listing", { access });
      const a = (await (await browser.api("POST", k.path, good({ name: "A" }))).json()) as any;
      const b = (await (await browser.api("POST", k.path, good({ name: "B" }))).json()) as any;
      await backChannel(stack, "/oauth/introspect", { token: b[k.field] }, stack.basic(k.service));
      const [used] = await stack.db`SELECT last_used_at FROM credentials WHERE id = ${b.id}`;
      expect(used.last_used_at).not.toBeNull();
      const list = (await (await browser.api("GET", k.path)).json()) as { items: any[] };
      expect(list.items.map((i) => [i.id, i.name, i.last_used_at])).toEqual([
        [a.id, "A", null],
        [b.id, "B", used.last_used_at.toISOString()],
      ]);
      expect(user.id).toMatch(ID);
    });

    if (k.kind === "api_key") {
      test.each([
        ["UTC", "2030-01-01T00:00:00Z", "2030-01-01T00:00:00.000Z"],
        ["an offset", "2030-01-01T02:00:00+02:00", "2030-01-01T00:00:00.000Z"],
        ["fractional seconds", "2030-06-15T12:30:45.123Z", "2030-06-15T12:30:45.123Z"],
        ["a lowercase z", "2031-03-04T05:06:07z", "2031-03-04T05:06:07.000Z"],
      ])("expires_at with %s is taken", async (_, value, saved) => {
        const { user, browser } = await signedIn("expiry", { access });
        const res = await browser.api("POST", k.path, good({ expires_at: value }));
        expect(res.status).toBe(201);
        expect(((await res.json()) as any).expires_at).toBe(saved);
        const [row] = await stack.db`SELECT expires_at FROM credentials WHERE user_id = ${user.id}`;
        expect(row.expires_at.toISOString()).toBe(saved);
      });

      test("expires_at null is no expiry", async () => {
        const { browser } = await signedIn("noexpiry", { access });
        const res = await browser.api("POST", k.path, good({ expires_at: null }));
        expect(res.status).toBe(201);
        expect(((await res.json()) as any).expires_at).toBeNull();
      });

      test.each([
        ["a number", 1893456000],
        ["true", true],
        ["an object", {}],
        ["a date alone", "2030-01-01"],
        ["words", "tomorrow"],
        ["an empty string", ""],
        ["month 13", "2030-13-01T00:00:00Z"],
        ["a time without a T", "2030-01-01 00:00:00Z"],
        ["30 February", "2030-02-30T00:00:00Z"],
        ["29 February in a common year", "2030-02-29T00:00:00Z"],
        ["31 April", "2030-04-31T00:00:00Z"],
      ])("expires_at as %s is 400", async (_, value) => {
        const { browser } = await signedIn("badexpiry", { access });
        await expectError(await browser.api("POST", k.path, good({ expires_at: value })), 400, "invalid_request", "expires_at must be an RFC 3339 timestamp.");
      });

      test("expires_at in the past is 400", async () => {
        const { browser } = await signedIn("pastexpiry", { access });
        await expectError(await browser.api("POST", k.path, good({ expires_at: "2020-01-01T00:00:00Z" })), 400, "invalid_request", "expires_at must be in the future.");
        await expectError(await browser.api("POST", k.path, good({ expires_at: new Date(Date.now() - 5000).toISOString() })), 400, "invalid_request", "expires_at must be in the future.");
      });

      test("expires_at is checked before the role", async () => {
        const { browser } = await signedIn("expiryorder");
        await expectError(await browser.api("POST", k.path, good({ expires_at: "soon" })), 400, "invalid_request", "expires_at must be an RFC 3339 timestamp.");
      });

      test("an expired key no longer answers introspection, and is still listed", async () => {
        const { browser } = await signedIn("expired", { access });
        const body = (await (await browser.api("POST", k.path, good({ expires_at: "2030-01-01T00:00:00Z" }))).json()) as any;
        await stack.db`UPDATE credentials SET expires_at = now() - interval '1 second' WHERE id = ${body.id}`;
        expect(await (await backChannel(stack, "/oauth/introspect", { token: body.key }, stack.basic("tasks"))).json()).toEqual({ active: false });
        expect(((await (await browser.api("GET", k.path)).json()) as any).items.map((i: any) => i.id)).toEqual([body.id]);
      });
    } else {
      test.each([["garbage", "not a time"], ["a number", 5], ["a past time", "2020-01-01T00:00:00Z"]])("expires_at as %s is ignored", async (_, value) => {
        const { user, browser } = await signedIn("ignored", { access });
        const res = await browser.api("POST", k.path, good({ expires_at: value }));
        expect(res.status).toBe(201);
        expect("expires_at" in ((await res.json()) as object)).toBe(false);
        const [row] = await stack.db`SELECT expires_at FROM credentials WHERE user_id = ${user.id}`;
        expect(row.expires_at).toBeNull();
      });
    }
  });

  // A deployment without API_KEY_PREFIX can't declare api_key_scopes, so no
  // service takes API keys there and a key can never be made without a prefix.
  describe("without API_KEY_PREFIX", () => {
    test("a services file with api_key_scopes is refused at start", async () => {
      const exit = await stack.exitOf({ API_KEY_PREFIX: undefined });
      expect(exit.code).toBe(1);
      expect(exit.stderr).toContain("API_KEY_PREFIX is required when a service declares api_key_scopes");
    });

    test("without api_key_scopes anywhere, no service takes API keys; app passwords still work", async () => {
      const bare = await Stack.start({
        env: { API_KEY_PREFIX: undefined },
        services: (events: (s: string) => string) => {
          const file = defaultServices(events);
          for (const s of file.services) delete s.api_key_scopes;
          return file;
        },
      });
      try {
        const user = await bare.user({ username: uname("bare"), access: { tasks: "user", mailbox: "user" } });
        const browser = await bare.session(user);
        await expectError(await browser.api("POST", "/v1/me/api-keys", { service: "tasks", scopes: ["tasks:read"], name: "CI" }), 400, "invalid_request", "tasks takes no API keys.");
        expect((await browser.api("POST", "/v1/me/app-passwords", { service: "mailbox", scopes: ["imap"], name: "Phone" })).status).toBe(201);
        const access = (await (await browser.api("GET", "/v1/me/access")).json()) as { items: any[] };
        expect(access.items.map((i) => [i.service, i.api_key_scopes])).toEqual([
          ["mailbox", []],
          ["tasks", []],
        ]);
      } finally {
        await bare.stop();
      }
    });
  });

  // -------------------------------------------------------------- access

  describe("GET /v1/me/access", () => {
    test("lists each role with its service's credential scopes, by service", async () => {
      const { user, browser } = await signedIn("access", { access: { wiki: "member", tasks: "user", mailbox: "admin" } });
      await stack.db`INSERT INTO access (user_id, service, role, granted_by) VALUES (${user.id}, 'gone', 'member', ${user.id})`;
      const res = await browser.api("GET", "/v1/me/access");
      expect(res.status).toBe(200);
      const rows = await stack.db`SELECT service, granted_at FROM access WHERE user_id = ${user.id} ORDER BY service`;
      const at = Object.fromEntries((rows as any[]).map((r) => [r.service, r.granted_at.toISOString()]));
      expect(await res.json()).toEqual({
        items: [
          { service: "gone", role: "member", granted_by: user.id, granted_at: at.gone, app_password_scopes: [], api_key_scopes: [] },
          { service: "mailbox", role: "admin", granted_by: "host-cli", granted_at: at.mailbox, app_password_scopes: ["imap", "smtp"], api_key_scopes: [] },
          { service: "tasks", role: "user", granted_by: "host-cli", granted_at: at.tasks, app_password_scopes: [], api_key_scopes: ["tasks:read", "tasks:write"] },
          { service: "wiki", role: "member", granted_by: "host-cli", granted_at: at.wiki, app_password_scopes: [], api_key_scopes: [] },
        ],
        next: null,
      });
    });

    test("no roles is an empty list", async () => {
      const { browser } = await signedIn("noaccess");
      expect(await (await browser.api("GET", "/v1/me/access")).json()).toEqual({ items: [], next: null });
    });
  });
});
