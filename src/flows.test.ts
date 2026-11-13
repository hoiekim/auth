import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { fromBase32 } from "./crypto";
import { hotp, stepAt } from "./totp";
import { Browser, flush, makeUser, TEST_DATABASE_URL, testApp, testDb, waitFor, type TestApp, type TestDb } from "./testing/harness";

// Sign-up, password reset and recovery (docs/DESIGN.md U5–U7, §9.1, §9.4).
describe.skipIf(!TEST_DATABASE_URL)("account flows", () => {
  let db: TestDb;
  let t: TestApp;
  const PW = "correct horse battery";
  beforeAll(async () => {
    db = await testDb();
    t = await testApp(db.sql);
  });
  afterAll(() => db.drop());

  const link = (path: string) => {
    const mail = t.mails.findLast((m) => m.text.includes(path));
    return mail?.text.match(/token=([\w-]+)/)?.[1] ?? null;
  };

  describe("sign-up on an open service", () => {
    test("creates the account, signs in, and verifies the address by email", async () => {
      t.mails.length = 0;
      const b = new Browser(t, "192.0.2.1");
      const res = await b.form("/signup", { username: "sam", name: "Sam", email: "sam@example.com", password: PW, return_to: "/account" });
      expect(res.status).toBe(303);
      const me = await (await b.api("GET", "/v1/me")).json() as any;
      // The address is set only once confirmed.
      expect(me).toMatchObject({ username: "sam", email: null, email_pending: "sam@example.com" });
      await flush();
      expect((await new Browser(t).form("/verify-email", { token: link("verify-email")! })).status).toBe(200);
      expect((await (await b.api("GET", "/v1/me")).json() as any).email).toBe("sam@example.com");
    });

    test("an address another account uses gets the same answer, and its owner a notice", async () => {
      t.mails.length = 0;
      const b = new Browser(t, "192.0.2.2");
      const res = await b.form("/signup", { username: "sam2", email: "SAM@example.com", password: PW, return_to: "/account" });
      expect(res.status).toBe(303);
      await flush();
      expect(t.mails.map((m) => [m.to, m.subject])).toEqual([["SAM@example.com", "Your address was used for another account"]]);
      expect((await (await b.api("GET", "/v1/me")).json() as any).email).toBeNull();
    });

    test("a taken username, a weak or breached password, are refused", async () => {
      const b = new Browser(t, "192.0.2.3");
      expect((await b.form("/signup", { username: "sam", email: "x@example.com", password: PW })).status).toBe(409);
      expect((await b.form("/signup", { username: "newname", email: "x@example.com", password: "short" })).status).toBe(400);
      const breached = await b.form("/signup", { username: "newname", email: "x@example.com", password: "password1234" });
      expect(breached.status).toBe(400);
      expect(await breached.text()).toContain("known data breaches");
      expect((await b.form("/signup", { username: "Bad_Name", email: "x@example.com", password: PW })).status).toBe(400);
    });

    test("ten accounts an hour per address", async () => {
      const b = new Browser(t, "192.0.2.4");
      for (let i = 0; i < 10; i++) expect((await b.form("/signup", { username: `bulk-${i}`, email: `bulk${i}@example.com`, password: PW })).status).toBe(303);
      expect((await b.form("/signup", { username: "bulk-10", email: "bulk10@example.com", password: PW })).status).toBe(429);
    });
  });

  describe("password reset", () => {
    test("the answer is the same for an unknown account, and only a real one gets mail", async () => {
      await makeUser(t, { username: "rita", password: PW });
      t.mails.length = 0;
      const known = await new Browser(t, "192.0.2.10").form("/reset", { action: "email", login: "rita" });
      const unknown = await new Browser(t, "192.0.2.11").form("/reset", { action: "email", login: "nobody-at-all" });
      expect(known.status).toBe(unknown.status);
      const strip = (s: string) => s.replace(/value="[\w-]{43}"/g, "");
      expect(strip(await known.text())).toBe(strip(await unknown.text()));
      await waitFor(() => t.mails.length > 0);
      await flush();
      expect(t.mails.map((m) => m.to)).toEqual(["rita@example.com"]);
    });

    test("three emails an hour per address", async () => {
      const b = new Browser(t, "192.0.2.12");
      for (let i = 0; i < 2; i++) expect((await b.form("/reset", { action: "email", login: "rita" })).status).toBe(200);
      expect((await b.form("/reset", { action: "email", login: "rita" })).status).toBe(429);
    });

    test("a link resets the password, ends every session, and works once", async () => {
      const rita = new Browser(t, "192.0.2.13");
      await rita.signIn("rita", PW);
      await t.app.sql`DELETE FROM throttle WHERE key LIKE 'mail:%'`;
      t.mails.length = 0;
      await new Browser(t, "192.0.2.14").form("/reset", { action: "email", login: "rita@example.com" });
      await waitFor(() => link("reset/confirm") !== null);
      const token = link("reset/confirm")!;
      const b = new Browser(t, "192.0.2.14");
      expect((await b.request(`/reset/confirm?token=${token}`)).status).toBe(200);
      const done = await b.form("/reset/confirm", { token, password: "a whole new password" });
      expect(done.headers.get("Location")).toStartWith("/login?");
      expect((await rita.api("GET", "/v1/me")).status).toBe(401);
      expect((await new Browser(t).signIn("rita", "a whole new password")).status).toBe(303);
      expect((await b.form("/reset/confirm", { token, password: "yet another password" })).status).toBe(404);
    });

    test("an expired link is refused", async () => {
      t.mails.length = 0;
      await t.app.sql`DELETE FROM throttle WHERE key LIKE 'mail:%'`;
      await new Browser(t, "192.0.2.15").form("/reset", { action: "email", login: "rita" });
      await waitFor(() => link("reset/confirm") !== null);
      const token = link("reset/confirm")!;
      await t.app.sql`UPDATE one_time_tokens SET expires_at = now() - interval '1 second' WHERE purpose = 'reset'`;
      expect((await new Browser(t).form("/reset/confirm", { token, password: "a whole new password" })).status).toBe(404);
    });

    test("with TOTP enrolled, the link alone isn't enough", async () => {
      await makeUser(t, { username: "tom", password: PW });
      const b = new Browser(t, "192.0.2.20");
      await b.signIn("tom", PW);
      const start = await (await b.api("POST", "/v1/me/totp", {})).json() as any;
      const secret = fromBase32(start.secret)!;
      await b.api("POST", "/v1/me/totp", { enrollment: start.enrollment, code: hotp(secret, stepAt(Date.now() / 1000)) });
      await t.app.sql`DELETE FROM throttle WHERE key LIKE 'mail:%'`;
      t.mails.length = 0;
      await new Browser(t, "192.0.2.21").form("/reset", { action: "email", login: "tom" });
      await waitFor(() => link("reset/confirm") !== null);
      const token = link("reset/confirm")!;
      const c = new Browser(t, "192.0.2.21");
      expect((await c.form("/reset/confirm", { token, password: "a whole new password" })).status).toBe(401);
      expect((await c.form("/reset/confirm", { token, password: "a whole new password", code: "123456" })).status).toBe(401);
      const ok = await c.form("/reset/confirm", { token, password: "a whole new password", code: hotp(secret, stepAt(Date.now() / 1000) + 1) });
      expect(ok.headers.get("Location")).toStartWith("/login?");
    });

    test("the per-address limit counts the address mail goes to, however it was typed", async () => {
      await makeUser(t, { username: "vera", password: PW });
      t.mails.length = 0;
      const b = new Browser(t, "192.0.2.40");
      for (let i = 0; i < 3; i++) await b.form("/reset", { action: "email", login: "vera" });
      for (let i = 0; i < 3; i++) expect((await b.form("/reset", { action: "email", login: "VERA@example.com" })).status).toBe(200);
      await Bun.sleep(100);
      expect(t.mails.filter((m) => m.to === "vera@example.com")).toHaveLength(3);
    });

    test("second-factor failures at a reset link count against the account", async () => {
      const id = await makeUser(t, { username: "wanda", password: PW });
      const b = new Browser(t, "192.0.2.41");
      await b.signIn("wanda", PW);
      const start = await (await b.api("POST", "/v1/me/totp", {})).json() as any;
      await b.api("POST", "/v1/me/totp", { enrollment: start.enrollment, code: hotp(fromBase32(start.secret)!, stepAt(Date.now() / 1000)) });
      await t.app.sql`DELETE FROM throttle WHERE key LIKE 'mail:%'`;
      t.mails.length = 0;
      await new Browser(t, "192.0.2.42").form("/reset", { action: "email", login: "wanda" });
      await waitFor(() => link("reset/confirm") !== null);
      const token = link("reset/confirm")!;
      for (let i = 0; i < 2; i++) await new Browser(t, "192.0.2.42").form("/reset/confirm", { token, password: "a whole new password", code: "000000" });
      const [row] = await t.app.sql`SELECT hits FROM throttle WHERE key = ${`login:user:${id}`}`;
      expect(row.hits).toBe(2);
    });

    test("a recovery-code reset proves the code before telling anything about the account", async () => {
      await makeUser(t, { username: "quinn", password: PW, email: "quinn.long@example.com" });
      const c = new Browser(t, "192.0.2.43");
      // A password equal to the account's email would be refused, but only
      // after the code is proved: a wrong code says nothing about the email.
      const res = await c.form("/reset", { action: "recovery", login: "quinn", code: "aaaa-aaaa-aaaa-aaaa-aaaa-aaaa", password: "quinn.long@example.com" });
      expect(res.status).toBe(401);
      expect(await res.text()).toContain("don&#39;t match");
    });

    test("a recovery code resets without email, once, under the sign-in limits", async () => {
      await makeUser(t, { username: "uma", password: PW });
      const b = new Browser(t, "192.0.2.30");
      await b.signIn("uma", PW);
      const codes: string[] = (await (await b.api("POST", "/v1/me/recovery-codes")).json() as any).codes;
      const c = new Browser(t, "192.0.2.31");
      // A refused password doesn't spend the code.
      expect((await c.form("/reset", { action: "recovery", login: "uma", code: codes[0]!, password: "short" })).status).toBe(400);
      const ok = await c.form("/reset", { action: "recovery", login: "uma", code: codes[0]!, password: "a whole new password" });
      expect(ok.headers.get("Location")).toStartWith("/login?");
      expect((await b.api("GET", "/v1/me")).status).toBe(401);
      expect((await c.form("/reset", { action: "recovery", login: "uma", code: codes[0]!, password: "another new password" })).status).toBe(401);
      // An unknown user gets the same answer as a wrong code.
      const unknown = await c.form("/reset", { action: "recovery", login: "nobody-at-all", code: codes[1]!, password: "another new password" });
      expect(unknown.status).toBe(401);
      // Wrong codes count against the account.
      for (let i = 0; i < 4; i++) await c.form("/reset", { action: "recovery", login: "uma", code: "aaaa-aaaa-aaaa-aaaa-aaaa-aaaa", password: "another new password" });
      expect((await c.form("/reset", { action: "recovery", login: "uma", code: codes[1]!, password: "another new password" })).status).toBe(429);
    });
  });

  describe("links bound to an address", () => {
    let bossSecret: string | null = null;
    test("an admin's email change voids the old activation link and sends a new one", async () => {
      const admin = await makeUser(t, { username: "boss", password: PW, access: { auth: "admin" } });
      const b = new Browser(t, "192.0.2.50");
      await b.signIn("boss", PW);
      const start = await (await b.api("POST", "/v1/me/totp", {})).json() as any;
      bossSecret = start.secret;
      await b.api("POST", "/v1/me/totp", { enrollment: start.enrollment, code: hotp(fromBase32(start.secret)!, stepAt(Date.now() / 1000)) });
      t.mails.length = 0;
      const user = await (await b.api("POST", "/v1/users", { username: "typo", email: "typo@exmaple.test" })).json() as any;
      await flush();
      const oldLink = link("activate")!;
      t.mails.length = 0;
      expect((await b.api("PATCH", `/v1/users/${user.id}`, { email: "typo@example.com" })).status).toBe(200);
      await flush();
      const newLink = link("activate")!;
      expect(t.mails.find((m) => m.text.includes("activate"))?.to).toBe("typo@example.com");
      expect((await new Browser(t).form("/activate", { token: oldLink, password: PW })).status).toBe(404);
      expect((await new Browser(t).form("/activate", { token: newLink, password: PW })).status).toBe(303);
      void admin;
    });

    test("an admin's email change voids a reset link sent to the old address", async () => {
      const id = await makeUser(t, { username: "moved-by-admin", password: PW });
      const token = await t.app.sql.begin(async (tx) => (await import("./tokens")).issueToken(tx, "reset", id, "moved-by-admin@example.com"));
      const admin = new Browser(t, "192.0.2.52");
      await admin.signIn("boss", PW, hotp(fromBase32(bossSecret!)!, stepAt(Date.now() / 1000) + 1));
      expect((await admin.api("PATCH", `/v1/users/${id}`, { email: "moved@example.org" })).status).toBe(200);
      expect((await new Browser(t).form("/reset/confirm", { token, password: "a whole new password" })).status).toBe(404);
    });

    test("an activation link can't set the password of an account that has one", async () => {
      const id = await makeUser(t, { username: "settled", password: PW });
      const token = await t.app.sql.begin(async (tx) => (await import("./tokens")).issueToken(tx, "activate", id, "settled@example.com"));
      expect((await new Browser(t).form("/activate", { token, password: "a whole new password" })).status).toBe(404);
      expect((await new Browser(t).signIn("settled", PW)).status).toBe(303);
    });

    test("only the newest pending address can be confirmed", async () => {
      await makeUser(t, { username: "yan", password: PW });
      const b = new Browser(t, "192.0.2.51");
      await b.signIn("yan", PW);
      t.mails.length = 0;
      await b.api("PATCH", "/v1/me", { email: "yan@exmaple.test" });
      await flush();
      const mistyped = link("verify-email")!;
      await b.api("PATCH", "/v1/me", { email: "yan@example.org" });
      await flush();
      expect((await new Browser(t).form("/verify-email", { token: mistyped })).status).toBe(404);
      expect((await (await b.api("GET", "/v1/me")).json() as any).email).toBe("yan@example.com");
    });
  });
});
