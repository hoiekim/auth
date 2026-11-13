import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { fromBase32 } from "./crypto";
import { hotp, stepAt } from "./totp";
import { Browser, flush, makeUser, TEST_DATABASE_URL, testApp, testDb, type TestApp, type TestDb } from "./testing/harness";

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
      await flush();
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
      await flush();
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
      await flush();
      const token = link("reset/confirm")!;
      const c = new Browser(t, "192.0.2.21");
      expect((await c.form("/reset/confirm", { token, password: "a whole new password" })).status).toBe(401);
      expect((await c.form("/reset/confirm", { token, password: "a whole new password", code: "123456" })).status).toBe(401);
      const ok = await c.form("/reset/confirm", { token, password: "a whole new password", code: hotp(secret, stepAt(Date.now() / 1000) + 1) });
      expect(ok.headers.get("Location")).toStartWith("/login?");
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
});
