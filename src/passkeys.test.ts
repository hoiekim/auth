import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { sha256 } from "./crypto";
import { SoftAuthenticator } from "./testing/authenticator";
import { Browser, makeUser, TEST_DATABASE_URL, testApp, testDb, type TestApp, type TestDb } from "./testing/harness";

// Adding a passkey at /v1/me/passkeys and signing in with it at
// /login/passkey (docs/DESIGN.md §7.5, §9.1), with a software authenticator.
describe.skipIf(!TEST_DATABASE_URL)("passkeys", () => {
  let db: TestDb;
  let t: TestApp;
  const PW = "correct horse battery";
  const ORIGIN = "https://auth.example.com";

  beforeAll(async () => {
    db = await testDb();
    t = await testApp(db.sql);
  });
  afterAll(() => db.drop());

  async function signedIn(username: string): Promise<{ b: Browser; id: string }> {
    const id = await makeUser(t, { username, password: PW });
    const b = new Browser(t);
    await b.signIn(username, PW);
    return { b, id };
  }

  async function begin(b: Browser): Promise<{ options: any; registration: string }> {
    const res = await b.api("POST", "/v1/me/passkeys", {});
    expect(res.status).toBe(200);
    return (await res.json()) as any;
  }

  async function add(b: Browser, a: SoftAuthenticator, name = "Laptop"): Promise<Response> {
    const { options, registration } = await begin(b);
    return b.api("POST", "/v1/me/passkeys", { registration, response: a.create(options, ORIGIN), name });
  }

  async function passkeySignIn(b: Browser, a: SoftAuthenticator, edit: Parameters<SoftAuthenticator["get"]>[2] = {}) {
    const opts = (await (await b.request("/login/passkey/options", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" })).json()) as any;
    const response = a.get(opts.options, ORIGIN, edit);
    const res = await b.request("/login/passkey", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ response, return_to: "/account" }),
    });
    return { res, response };
  }

  test("a passkey is added, stored as its COSE key, and listed", async () => {
    const { b, id } = await signedIn("alice");
    const { options } = await begin(b);
    expect(options.rp).toEqual({ name: "auth.example.com", id: "auth.example.com" });
    expect(options.user).toEqual({ id: Buffer.from(id).toString("base64url"), name: "alice", displayName: "Alice" });
    expect(options.attestation).toBe("none");
    expect(options.authenticatorSelection).toEqual({ residentKey: "required", requireResidentKey: true, userVerification: "required" });
    expect(options.excludeCredentials).toEqual([]);

    const a = new SoftAuthenticator();
    const res = await add(b, a);
    expect(res.status).toBe(201);
    const body = (await res.json()) as any;
    expect(body).toMatchObject({ name: "Laptop", last_used_at: null });
    const [row] = await t.app.sql`SELECT user_id, credential_id, public_key, sign_count FROM passkeys WHERE id = ${body.id}`;
    expect(row.user_id).toBe(id);
    expect(Buffer.from(row.credential_id).equals(a.credentialId)).toBe(true);
    expect(Buffer.from(row.public_key).equals(Buffer.from(a.cose))).toBe(true);
    expect(Number(row.sign_count)).toBe(0);

    // The next registration excludes it, so the same authenticator isn't
    // added twice. Adding another now needs a sign-in that used it (§7.5).
    const c = new Browser(t);
    expect((await passkeySignIn(c, a)).res.status).toBe(200);
    expect((await begin(c)).options.excludeCredentials).toEqual([{ type: "public-key", id: a.id }]);
  });

  test("a registration token is used once, and only by the user it was made for", async () => {
    const { b, id } = await signedIn("bruno");
    const { b: other } = await signedIn("carla");
    const { options, registration } = await begin(b);
    const a = new SoftAuthenticator();
    const response = a.create(options, ORIGIN);
    expect((await other.api("POST", "/v1/me/passkeys", { registration, response })).status).toBe(400);
    // A failed attempt spends the token, so a good response can't follow it.
    expect((await b.api("POST", "/v1/me/passkeys", { registration, response: a.create(options, "https://evil.example.com") })).status).toBe(400);
    expect((await b.api("POST", "/v1/me/passkeys", { registration, response })).status).toBe(400);
    expect(await t.app.sql`SELECT 1 FROM passkeys WHERE user_id = ${id}`).toHaveLength(0);
    expect((await add(b, a)).status).toBe(201);
  });

  test("a response that fails a check adds nothing", async () => {
    const { b, id } = await signedIn("dmitri");
    const { options, registration } = await begin(b);
    const res = await b.api("POST", "/v1/me/passkeys", { registration, response: new SoftAuthenticator().create(options, "https://evil.example.com") });
    expect(res.status).toBe(400);
    expect(await t.app.sql`SELECT 1 FROM passkeys WHERE user_id = ${id}`).toHaveLength(0);
  });

  test("a passkey signs in with two factors and records its use", async () => {
    const { b, id } = await signedIn("erin");
    const a = new SoftAuthenticator(-8, { counts: true });
    expect((await add(b, a)).status).toBe(201);

    const fresh = new Browser(t);
    const { res } = await passkeySignIn(fresh, a);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ redirect: "/account" });
    const [s] = await t.app.sql`SELECT user_id, amr FROM sessions WHERE token_hash = ${sha256(fresh.cookies.get("__Host-auth")!)}`;
    expect(s.user_id).toBe(id);
    expect(s.amr).toEqual(["swk", "user", "mfa"]);
    const [row] = await t.app.sql`SELECT sign_count, last_used_at FROM passkeys WHERE user_id = ${id}`;
    expect(Number(row.sign_count)).toBe(2);
    expect(row.last_used_at).not.toBeNull();
  });

  test("a sign-in challenge is accepted once", async () => {
    const { b } = await signedIn("farah");
    const a = new SoftAuthenticator();
    expect((await add(b, a)).status).toBe(201);
    const c = new Browser(t);
    const opts = (await (await c.request("/login/passkey/options", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" })).json()) as any;
    // A sign-in clears the challenge cookie, so keep it to send again.
    const challengeCookie = [...c.cookies].find(([k]) => k.endsWith("webauthn"))!;
    const body = JSON.stringify({ response: a.get(opts.options, ORIGIN) });
    const post = (b: Browser) => b.request("/login/passkey", { method: "POST", headers: { "Content-Type": "application/json" }, body });
    expect((await post(c)).status).toBe(200);
    const replay = new Browser(t);
    replay.cookies.set(...challengeCookie);
    expect((await post(replay)).status).toBe(401);
  });

  test("a counter that doesn't move forward is refused, and the stored one is kept", async () => {
    const { b, id } = await signedIn("gwen");
    const a = new SoftAuthenticator(-7, { counts: true });
    expect((await add(b, a)).status).toBe(201);
    expect((await passkeySignIn(new Browser(t), a)).res.status).toBe(200);
    const { res } = await passkeySignIn(new Browser(t), a, { counter: 2 });
    expect(res.status).toBe(401);
    const [row] = await t.app.sql`SELECT sign_count FROM passkeys WHERE user_id = ${id}`;
    expect(Number(row.sign_count)).toBe(2);
  });

  test("an assertion signed by another key is refused", async () => {
    const { b } = await signedIn("hana");
    const a = new SoftAuthenticator();
    expect((await add(b, a)).status).toBe(201);
    const { res } = await passkeySignIn(new Browser(t), a, { signWith: new SoftAuthenticator().privateKey });
    expect(res.status).toBe(401);
  });

  test("registration asks for the device's own authenticator, or a security key or another device, when told which", async () => {
    const { b, id } = await signedIn("ines");
    const selection = { residentKey: "required", requireResidentKey: true, userVerification: "required" };
    for (const attachment of ["platform", "cross-platform"]) {
      const res = await b.api("POST", "/v1/me/passkeys", { attachment });
      expect(res.status).toBe(200);
      expect(((await res.json()) as any).options.authenticatorSelection).toEqual({ authenticatorAttachment: attachment, ...selection });
    }
    // null is the same as leaving it out: the browser offers every kind.
    const open = (await (await b.api("POST", "/v1/me/passkeys", { attachment: null })).json()) as any;
    expect(open.options.authenticatorSelection).toEqual(selection);
    expect("authenticatorAttachment" in open.options.authenticatorSelection).toBe(false);

    for (const attachment of ["Platform", "internal", "", 1, true, ["platform"]]) {
      const res = await b.api("POST", "/v1/me/passkeys", { attachment });
      expect(res.status).toBe(400);
      expect(((await res.json()) as any).error).toBe("invalid_request");
    }

    // The choice only steers the browser's prompt: the key is checked and
    // stored as any other.
    const a = new SoftAuthenticator();
    const { options, registration } = (await (await b.api("POST", "/v1/me/passkeys", { attachment: "platform" })).json()) as any;
    expect((await b.api("POST", "/v1/me/passkeys", { registration, response: a.create(options, ORIGIN), name: "Phone" })).status).toBe(201);
    const [row] = await t.app.sql`SELECT credential_id FROM passkeys WHERE user_id = ${id}`;
    expect(Buffer.from(row.credential_id).equals(a.credentialId)).toBe(true);
  });
});
