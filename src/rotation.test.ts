import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { runCli } from "./cli";
import { Encrypter, fromBase32 } from "./crypto";
import { checkTotp } from "./factors";
import { encryptionStatus, reencrypt } from "./rekey";
import { hotp, stepAt } from "./totp";
import { Browser, makeUser, TEST_DATABASE_URL, testApp, testDb, type TestApp, type TestDb } from "./testing/harness";

// Rotating AUTH_ENCRYPTION_KEY (docs/DESIGN.md §9.3).

const OLD = Buffer.alloc(32, 7).toString("base64");
const NEW = Buffer.alloc(32, 9).toString("base64");

describe("the encryption keyring", () => {
  const v1 = { version: 1, key: Buffer.alloc(32, 1) };
  const v2 = { version: 2, key: Buffer.alloc(32, 2) };

  test("writes under the current key's version and reads every configured version", () => {
    const before = new Encrypter(v1);
    const during = new Encrypter(v2, [v1]);
    const old = before.encrypt(Buffer.from("s3cret-totp"), "usr_a");
    const fresh = during.encrypt(Buffer.from("s3cret-totp"), "usr_a");
    expect(old.subarray(0, 3).toString()).toBe("v1:");
    expect(fresh.subarray(0, 3).toString()).toBe("v2:");
    expect(during.decrypt(old, "usr_a").toString()).toBe("s3cret-totp");
    expect(during.decrypt(fresh, "usr_a").toString()).toBe("s3cret-totp");
    expect(() => before.decrypt(fresh, "usr_a")).toThrow();
    expect(Encrypter.versionOf(fresh)).toBe(2);
  });

  test("a version with the wrong key, a forged prefix or no prefix is refused", () => {
    const forged = new Encrypter({ version: 2, key: Buffer.alloc(32, 3) }).encrypt(Buffer.from("x"), "usr_a");
    expect(() => new Encrypter(v2, [v1]).decrypt(forged, "usr_a")).toThrow();
    const relabelled = Buffer.concat([Buffer.from("v1:"), new Encrypter(v2).encrypt(Buffer.from("x"), "usr_a").subarray(3)]);
    expect(() => new Encrypter(v2, [v1]).decrypt(relabelled, "usr_a")).toThrow();
    expect(() => new Encrypter(v1).decrypt(Buffer.from("no prefix at all, just bytes"), "usr_a")).toThrow();
  });

  test("refuses two keys with one version", () => {
    expect(() => new Encrypter(v1, [{ version: 1, key: Buffer.alloc(32, 5) }])).toThrow();
  });

  test("CSRF tokens and sealed values made before a rotation still hold after it, and not with an unrelated key", () => {
    const before = new Encrypter(v1);
    const after = new Encrypter(v2, [v1]);
    const token = before.hmac("csrf", "session-token");
    expect(after.hmacMatches("csrf", "session-token", token)).toBe(true);
    expect(after.hmacMatches("csrf", "session-token", after.hmac("csrf", "session-token"))).toBe(true);
    expect(after.hmacMatches("csrf", "another-session", token)).toBe(false);
    expect(new Encrypter(v2).hmacMatches("csrf", "session-token", token)).toBe(false);
    const sealed = before.sealValue("pending", { u: "usr_a" }, 60);
    expect(after.openValue("pending", sealed)).toEqual({ u: "usr_a" });
    expect(new Encrypter(v2).openValue("pending", sealed)).toBeNull();
  });
});

describe.skipIf(!TEST_DATABASE_URL)("a rotation, deploy by deploy", () => {
  let db: TestDb;
  let original: TestApp;
  const PW = "correct horse battery";
  const now = () => stepAt(Date.now() / 1000);

  beforeAll(async () => {
    db = await testDb();
    original = await testApp(db.sql, { AUTH_ENCRYPTION_KEY: OLD });
  });
  afterAll(() => db.drop());

  // One copy of auth, configured as a deploy would be.
  const copy = (env: Record<string, string>) => testApp(db.sql, env);
  // Whether a copy can verify the user's current code, which needs it to
  // decrypt the stored secret. The replay guard isn't what's tested here.
  const verifies = async (t: TestApp, userId: string, secret: Buffer) => {
    await db.sql`UPDATE totp SET last_step = 0 WHERE user_id = ${userId}`;
    return checkTotp(db.sql, t.app, userId, hotp(secret, now()));
  };

  test("every step keeps sign-in, TOTP and signing working, and ends with nothing under the old key", async () => {
    const alice = await makeUser(original, { username: "alice", password: PW });
    const b = new Browser(original);
    await b.signIn("alice", PW);
    const start = (await (await b.api("POST", "/v1/me/totp", {})).json()) as any;
    const secret = fromBase32(start.secret)!;
    expect((await b.api("POST", "/v1/me/totp", { enrollment: start.enrollment, code: hotp(secret, now()) })).status).toBe(200);

    // 1. The new key is added to AUTH_DECRYPTION_KEYS. Writes stay v1.
    const one = await copy({ AUTH_ENCRYPTION_KEY: OLD, AUTH_DECRYPTION_KEYS: `v2:${NEW}` });
    expect(await verifies(one, alice, secret)).toBe(true);

    // 2. The new key encrypts; the old one only decrypts. A copy still on
    //    step 1 reads what this one writes, and the other way round.
    const two = await copy({ AUTH_ENCRYPTION_KEY: `v2:${NEW}`, AUTH_DECRYPTION_KEYS: `v1:${OLD}` });
    const bob = await makeUser(two, { username: "bob", password: PW });
    const b2 = new Browser(two);
    await b2.signIn("bob", PW);
    const start2 = (await (await b2.api("POST", "/v1/me/totp", {})).json()) as any;
    const secret2 = fromBase32(start2.secret)!;
    expect((await b2.api("POST", "/v1/me/totp", { enrollment: start2.enrollment, code: hotp(secret2, now()) })).status).toBe(200);
    const [row] = await db.sql`SELECT secret_enc FROM totp WHERE user_id = ${bob}`;
    expect(Encrypter.versionOf(row.secret_enc)).toBe(2);
    expect(await verifies(one, bob, secret2)).toBe(true);
    expect(await verifies(two, alice, secret)).toBe(true);
    // A session signed in before the rotation keeps working, CSRF token and all.
    const csrfBefore = await b.csrf();
    const res = await new Browser(two).request("/v1/me", {
      method: "PATCH",
      headers: { Cookie: `__Host-auth=${b.cookies.get("__Host-auth")}`, "X-CSRF-Token": csrfBefore, "Content-Type": "application/json" },
      body: JSON.stringify({ name: "Alice" }),
    });
    expect(res.status).toBe(200);

    // 3. Re-encryption moves everything to v2.
    const before = await encryptionStatus(db.sql, two.app.crypt);
    expect(before.find((c) => c.label === "TOTP secrets")?.byVersion).toEqual({ "1": 1, "2": 1 });
    const out: string[] = [];
    const code = await runCli(["encryption", "reencrypt"], { app: two.app, mailer: { send: async () => {} }, out: (l) => out.push(l) });
    expect(code).toBe(0);
    expect(out[0]).toBe("TOTP secrets: 1 rewritten under v2, 1 already were");
    const after = await encryptionStatus(db.sql, two.app.crypt);
    for (const c of after) expect(Object.keys(c.byVersion)).toEqual(["2"]);
    expect(await db.sql`SELECT 1 FROM audit WHERE action = 'encryption.reencrypt' AND actor = 'host-cli'`).toHaveLength(1);

    // 4. The old key is gone, and nothing needed it.
    const four = await copy({ AUTH_ENCRYPTION_KEY: `v2:${NEW}` });
    expect(await verifies(four, alice, secret)).toBe(true);
    expect(await verifies(four, bob, secret2)).toBe(true);
    // And a copy that never had the new key can't read the rewritten values.
    expect(await verifies(await copy({ AUTH_ENCRYPTION_KEY: OLD }), alice, secret)).toBe(false);
    await four.app.keys.refresh(true);
    expect((await four.app.keys.signer()).kid).toBeTruthy();
  });

  test("a value no configured key reads is reported and left as it was", async () => {
    const carol = await makeUser(original, { username: "carol", password: PW });
    const stranger = new Encrypter({ version: 7, key: Buffer.alloc(32, 4) }).encrypt(Buffer.from("x"), carol);
    await db.sql`INSERT INTO totp (user_id, secret_enc) VALUES (${carol}, ${stranger})`;
    const app = (await copy({ AUTH_ENCRYPTION_KEY: `v2:${NEW}` })).app;
    const status = await encryptionStatus(db.sql, app.crypt);
    expect(status.find((c) => c.label === "TOTP secrets")?.unreadable).toBe(1);
    const results = await reencrypt(db.sql, app.crypt);
    expect(results.find((r) => r.label === "TOTP secrets")?.failed).toEqual([carol]);
    const [row] = await db.sql`SELECT secret_enc FROM totp WHERE user_id = ${carol}`;
    expect(Buffer.from(row.secret_enc).equals(stranger)).toBe(true);
    const out: string[] = [];
    expect(await runCli(["encryption", "reencrypt"], { app, mailer: { send: async () => {} }, out: (l) => out.push(l) })).toBe(1);
    expect(out.some((l) => l.includes(carol))).toBe(true);
    await db.sql`DELETE FROM totp WHERE user_id = ${carol}`;
  });
});
