import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { AT, BE, BS, type CborValue, ED, type Edits, encodeCbor, SoftAuthenticator, UP, UV } from "../src/testing/authenticator";
import { b64u, type Browser, enabled, errorOf, ID, newId, Stack } from "./harness";

// Passkeys over HTTP (docs/DESIGN.md §7.5, §9.1): registration through
// POST /v1/me/passkeys (options, then the authenticator's response), the
// relying-party checks and the CBOR they read, listing and removal, and the
// sign-in each stored key then makes through /login/passkey.

setDefaultTimeout(30_000);

const REFUSED = "The passkey couldn't be verified.";
const SESSION_COOKIE = /^__Host-auth=[A-Za-z0-9_-]{43}; Path=\/; Secure; HttpOnly; SameSite=Lax; Max-Age=2592000$/;
const ISO = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const TWO_FACTORS = ["pwd", "otp", "mfa"];

let counter = 0;
function uname(prefix: string): string {
  return `${prefix}-${randomBytes(3).toString("hex")}${(++counter).toString(36)}`;
}

function noticeText(username: string, change: string, detail?: string): string {
  return [`On the account "${username}": ${change}.`, ...(detail ? ["", detail] : []), "", "If this wasn't you, reset your password and contact an administrator."].join("\n");
}

async function expectError(res: Response, status: number, error: string, description: string): Promise<void> {
  expect(await errorOf(res)).toEqual({ status, error, description });
}

// ------------------------------------------------------------- raw CBOR
// What encodeCbor won't write: the decoder must refuse each.

const cat = (...parts: (Uint8Array | number[])[]): Buffer => Buffer.concat(parts.map((p) => Buffer.from(p)));
const text = (s: string): Uint8Array => encodeCbor(s);
// A definite map of fewer than 24 pairs, each already encoded.
const rawMap = (pairs: [Uint8Array | number[], Uint8Array | number[]][]): Buffer => cat([0xa0 | pairs.length], ...pairs.flat());
const nested = (depth: number, inner: number[] = [0x01]): number[] => [...Array(depth).fill(0x81), ...inner];

// The attestation object with its three fields as given, plus `more`.
function attestation(fields: Map<string, CborValue>, more: [Uint8Array | number[], Uint8Array | number[]][] = []): Buffer {
  return rawMap([[text("fmt"), encodeCbor(fields.get("fmt")!)], [text("attStmt"), encodeCbor(fields.get("attStmt")!)], [text("authData"), encodeCbor(fields.get("authData")!)], ...more]);
}

describe.skipIf(!enabled)("passkeys", () => {
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

  async function signedIn(prefix: string, more: Partial<Parameters<Stack["user"]>[0]> = {}, s: Parameters<Stack["session"]>[1] = {}) {
    const user = await stack.user({ username: uname(prefix), ...more });
    const browser = await stack.session(user, s);
    return { user, browser };
  }

  async function auditOf(userId: string, action?: string) {
    return (await stack.audit(action)).filter((r) => r.user_id === userId);
  }

  async function start(browser: Browser, body: Record<string, unknown> = {}): Promise<{ options: any; registration: string }> {
    const res = await browser.api("POST", "/v1/me/passkeys", body);
    expect(res.status).toBe(200);
    return (await res.json()) as { options: any; registration: string };
  }

  // Both calls of a registration; `edit` changes what the authenticator answers.
  async function register(browser: Browser, auth: SoftAuthenticator, edit: Edits = {}, more: Record<string, unknown> = {}): Promise<Response> {
    const { options, registration } = await start(browser);
    return browser.api("POST", "/v1/me/passkeys", { registration, response: auth.create(options, stack.issuer, edit), ...more });
  }

  async function passkeysOf(userId: string) {
    return (await stack.db`SELECT id, credential_id, public_key, sign_count, name, last_used_at FROM passkeys WHERE user_id = ${userId} ORDER BY created_at`) as any[];
  }

  // A sign-in through /login/passkey, from a browser of its own.
  async function passkeySignIn(auth: SoftAuthenticator, edit: Edits = {}, body: Record<string, unknown> = {}) {
    const browser = stack.browser();
    const o = await browser.request("/login/passkey/options", { method: "POST" });
    expect(o.status).toBe(200);
    const { options } = (await o.json()) as { options: any };
    const response = auth.get(options, stack.issuer, edit);
    const res = await browser.request("/login/passkey", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ response, ...body }) });
    return { browser, res, options, response };
  }

  // ------------------------------------------------------------ options

  describe("registration options", () => {
    test("name the RP, the user, the algorithms in order, no attestation, and a discoverable, verified credential", async () => {
      const { user, browser } = await signedIn("opts", { name: "Alice Example" });
      const { options, registration } = await start(browser);
      expect(options.challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(options).toEqual({
        challenge: options.challenge,
        rp: { name: "127.0.0.1", id: "127.0.0.1" },
        user: { id: b64u(user.id), name: user.username, displayName: "Alice Example" },
        pubKeyCredParams: [
          { type: "public-key", alg: -8 },
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 },
        ],
        timeout: 60000,
        attestation: "none",
        excludeCredentials: [],
        authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
      });
      const sealed = stack.crypt.open<{ u: string; c: string }>("passkey-reg", registration);
      expect(sealed.v).toEqual({ u: user.id, c: options.challenge });
      expect(sealed.exp).toBeGreaterThan(Date.now() + 4 * 60 * 1000);
      expect(sealed.exp).toBeLessThanOrEqual(Date.now() + 5 * 60 * 1000);
      expect((await start(browser)).options.challenge).not.toBe(options.challenge);
      expect(await passkeysOf(user.id)).toEqual([]);
    });

    test("the display name falls back to the username", async () => {
      const { user, browser } = await signedIn("noname", { name: "" });
      expect((await start(browser)).options.user).toEqual({ id: b64u(user.id), name: user.username, displayName: user.username });
    });

    test.each(["platform", "cross-platform"])("attachment %s becomes authenticatorAttachment", async (attachment) => {
      const { browser } = await signedIn("attach");
      expect((await start(browser, { attachment })).options.authenticatorSelection).toEqual({
        authenticatorAttachment: attachment,
        residentKey: "required",
        requireResidentKey: true,
        userVerification: "required",
      });
    });

    test.each([
      ["absent", {}],
      ["null", { attachment: null }],
    ])("attachment %s leaves the browser the choice", async (_, body) => {
      const { browser } = await signedIn("attach-none");
      expect((await start(browser, body)).options.authenticatorSelection).toEqual({ residentKey: "required", requireResidentKey: true, userVerification: "required" });
    });

    test.each([["Platform"], ["internal"], [""], [1], [true], [["platform"]], [{ platform: true }]])("attachment %p is 400", async (attachment) => {
      const { browser } = await signedIn("attach-bad");
      await expectError(await browser.api("POST", "/v1/me/passkeys", { attachment }), 400, "invalid_request", 'attachment is "platform" or "cross-platform".');
    });

    test("once a passkey exists, it is excluded", async () => {
      const { browser } = await signedIn("exclude", {}, { amr: TWO_FACTORS });
      const a = new SoftAuthenticator(-7);
      const b = new SoftAuthenticator(-8);
      expect((await register(browser, a)).status).toBe(201);
      expect((await register(browser, b)).status).toBe(201);
      expect((await start(browser)).options.excludeCredentials).toEqual([
        { type: "public-key", id: a.id },
        { type: "public-key", id: b.id },
      ]);
    });

    test("another user's passkeys are not excluded", async () => {
      const other = await signedIn("exclude-other");
      expect((await register(other.browser, new SoftAuthenticator())).status).toBe(201);
      const { browser } = await signedIn("exclude-mine");
      expect((await start(browser)).options.excludeCredentials).toEqual([]);
    });
  });

  // ---------------------------------------------------------- finishing

  describe("finishing a registration", () => {
    test.each([
      ["EdDSA", -8],
      ["ES256", -7],
      ["RS256", -257],
    ] as const)("an %s key is stored, answered with 201, audited and announced", async (_, alg) => {
      const { user, browser } = await signedIn("reg", {}, {});
      const auth = new SoftAuthenticator(alg);
      const res = await register(browser, auth);
      expect(res.status).toBe(201);
      const body = (await res.json()) as Record<string, any>;
      const [row] = await passkeysOf(user.id);
      const [created] = await stack.db`SELECT created_at FROM passkeys WHERE id = ${body.id}`;
      expect(body).toEqual({ id: row.id, name: "Passkey", created_at: created.created_at.toISOString(), last_used_at: null });
      expect(body.id).toMatch(ID);
      expect(body.id).toStartWith("pk_");
      expect(body.created_at).toMatch(ISO);
      expect(Buffer.from(row.credential_id).equals(auth.credentialId)).toBe(true);
      expect(Buffer.from(row.public_key).equals(Buffer.from(auth.cose))).toBe(true);
      expect(Number(row.sign_count)).toBe(0);
      const audit = await auditOf(user.id, "passkey.add");
      expect(audit).toHaveLength(1);
      expect(audit[0]).toMatchObject({ actor: user.id, ip: browser.ip, detail: { id: body.id } });
      const mail = await stack.smtp.waitFor(user.email!, (m) => m.subject === "Security notice: a passkey was added");
      expect(mail.text.trimEnd()).toBe(noticeText(user.username, "a passkey was added", "Name: Passkey"));
      const res2 = await browser.api("GET", "/v1/me");
      expect(((await res2.json()) as any).mfa).toEqual({ totp: false, passkeys: 1, recovery_codes: 0 });
    });

    test("a counting authenticator's counter is kept", async () => {
      const { user, browser } = await signedIn("reg-count");
      expect((await register(browser, new SoftAuthenticator(-7, { counts: true }))).status).toBe(201);
      expect(Number((await passkeysOf(user.id))[0].sign_count)).toBe(1);
    });

    test.each([
      ["trimmed", "  Laptop  ", "Laptop"],
      ["cut to 100 characters", "a".repeat(150), "a".repeat(100)],
      ["200 characters, cut to 100", "b".repeat(200), "b".repeat(100)],
      ["unicode", "Zoë's 李 key", "Zoë's 李 key"],
      ["cut between characters, never inside one", "a" + "😀".repeat(60), "a" + "😀".repeat(49)],
      ["of emoji only, cut to 50 of them", "😀".repeat(60), "😀".repeat(50)],
      ["spaces only, so the default", "   ", "Passkey"],
      ["empty, so the default", "", "Passkey"],
      ["null, so the default", null, "Passkey"],
      ["a number, so the default", 5, "Passkey"],
      ["an array, so the default", ["Laptop"], "Passkey"],
    ])("a name %s", async (_, name, saved) => {
      const { user, browser } = await signedIn("pkname");
      const res = await register(browser, new SoftAuthenticator(), {}, { name });
      expect(res.status).toBe(201);
      expect(((await res.json()) as any).name).toBe(saved);
      expect((await passkeysOf(user.id))[0].name).toBe(saved);
      const mail = await stack.smtp.waitFor(user.email!, (m) => m.subject === "Security notice: a passkey was added");
      expect(mail.text).toContain(`Name: ${saved}`);
    });

    test.each([
      ["a newline", "a\nb"],
      ["a NUL", "a\u0000"],
      ["DEL", "key\u007f"],
      ["201 code points", "😀".repeat(201)],
    ])("a name with %s is 400, before the response is read", async (_, name) => {
      const { user, browser } = await signedIn("pkname-bad");
      const auth = new SoftAuthenticator();
      const { options, registration } = await start(browser);
      const response = auth.create(options, stack.issuer);
      await expectError(await browser.api("POST", "/v1/me/passkeys", { registration, response, name }), 400, "invalid_request", "A name is at most 200 characters, with no control characters.");
      expect(await passkeysOf(user.id)).toEqual([]);
      // The challenge wasn't spent.
      expect((await browser.api("POST", "/v1/me/passkeys", { registration, response })).status).toBe(201);
    });

    test("the response a browser sends, extra fields included, is accepted", async () => {
      const { browser } = await signedIn("extra");
      const auth = new SoftAuthenticator();
      const { options, registration } = await start(browser);
      const response = { ...auth.create(options, stack.issuer, { crossOrigin: false }), authenticatorAttachment: "platform" };
      expect((await browser.api("POST", "/v1/me/passkeys", { registration, response })).status).toBe(201);
    });

    const p256 = generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({ format: "jwk" }) as { x: string; y: string };
    const x = Buffer.from(p256.x, "base64url");
    const y = Buffer.from(p256.y, "base64url");
    const ed = Buffer.from((generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" }) as { x: string }).x, "base64url");
    const rsaN = Buffer.from((generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ format: "jwk" }) as { n: string }).n, "base64url");
    const key = (entries: [number, CborValue][]) => encodeCbor(new Map<number, CborValue>(entries));

    test.each([
      ["a sign-in's client data type", { type: "webauthn.get" }],
      ["another challenge", { challenge: b64u(Buffer.alloc(32, 1)) }],
      ["another origin", { origin: "https://evil.example.com" }],
      ["the issuer under another host name", { origin: "http://localhost:PORT" }],
      ["the origin with a trailing slash", { origin: "ISSUER/" }],
      ["a cross-origin ceremony", { crossOrigin: true }],
      ["another RP ID", { rpId: "example.com" }],
      ["the RP ID with the port", { rpId: "127.0.0.1:PORT" }],
      ["no user presence", { flags: UV | AT }],
      ["no user verification", { flags: UP | AT }],
      ["backed up but not backup eligible", { flags: UP | UV | AT | BS }],
      ["no attested credential data", { flags: UP | UV }],
      ["an id that isn't the credential's", { id: b64u(Buffer.alloc(16, 9)) }],
      ["a zero-length credential id", { credentialId: new Uint8Array(0), id: "" }],
      ["a credential id of 1024 bytes", { credentialId: new Uint8Array(1024).fill(7), id: b64u(new Uint8Array(1024).fill(7)) }],
      ["bytes after the key without the ED flag", { afterKey: Uint8Array.from([0xa0]) }],
      ["the ED flag with extensions that aren't a map", { flags: UP | UV | AT | ED, afterKey: encodeCbor([1]) }],
      ["the ED flag with nothing after the key", { flags: UP | UV | AT | ED }],
      ["the ED flag with two maps after the key", { flags: UP | UV | AT | ED, afterKey: Uint8Array.from([0xa0, 0xa0]) }],
      ["an unsupported algorithm (ES384)", { publicKey: key([[1, 2], [3, -35], [-1, 2], [-2, x], [-3, y]]) }],
      ["an algorithm the key type doesn't match: ES256 on OKP", { publicKey: key([[1, 1], [3, -7], [-1, 1], [-2, x], [-3, y]]) }],
      ["ES256 on another curve", { publicKey: key([[1, 2], [3, -7], [-1, 2], [-2, x], [-3, y]]) }],
      ["a short P-256 x", { publicKey: key([[1, 2], [3, -7], [-1, 1], [-2, x.subarray(1)], [-3, y]]) }],
      ["a long P-256 y", { publicKey: key([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, Buffer.concat([y, Buffer.from([0])])]]) }],
      ["a P-256 coordinate that is text", { publicKey: key([[1, 2], [3, -7], [-1, 1], [-2, "x"], [-3, y]]) }],
      ["a P-256 point off the curve", { publicKey: key([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, Buffer.alloc(32, 1)]]) }],
      ["EdDSA on EC2", { publicKey: key([[1, 2], [3, -8], [-1, 6], [-2, ed]]) }],
      ["EdDSA on another curve", { publicKey: key([[1, 1], [3, -8], [-1, 7], [-2, ed]]) }],
      ["a short Ed25519 key", { publicKey: key([[1, 1], [3, -8], [-1, 6], [-2, ed.subarray(1)]]) }],
      ["RS256 on EC2", { publicKey: key([[1, 2], [3, -257], [-1, rsaN], [-2, Uint8Array.from([1, 0, 1])]]) }],
      ["an RSA exponent of 3", { publicKey: key([[1, 3], [3, -257], [-1, rsaN], [-2, Uint8Array.from([3])]]) }],
      ["an RSA exponent of 1", { publicKey: key([[1, 3], [3, -257], [-1, rsaN], [-2, Uint8Array.from([1])]]) }],
      ["an RSA exponent of 65539", { publicKey: key([[1, 3], [3, -257], [-1, rsaN], [-2, Uint8Array.from([1, 0, 3])]]) }],
      ["an RSA key without its exponent", { publicKey: key([[1, 3], [3, -257], [-1, rsaN]]) }],
      ["a key without an algorithm", { publicKey: key([[1, 2], [-1, 1], [-2, x], [-3, y]]) }],
      ["a key that isn't a map", { publicKey: encodeCbor([1, 2]) }],
      ["a key with a text algorithm", { publicKey: encodeCbor(new Map<number, CborValue>([[1, 2], [3, "ES256"], [-1, 1], [-2, x], [-3, y]])) }],
      ["a missing key", { publicKey: new Uint8Array(0) }],
      ["an attestation object that isn't a map", { attestationObject: () => encodeCbor(["none", new Map(), new Uint8Array(37)]) }],
      ["an attestation object without fmt", { attestationObject: (f: Map<string, CborValue>) => (f.delete("fmt"), encodeCbor(f)) }],
      ["an attestation object without attStmt", { attestationObject: (f: Map<string, CborValue>) => (f.delete("attStmt"), encodeCbor(f)) }],
      ["an attestation object without authData", { attestationObject: (f: Map<string, CborValue>) => (f.delete("authData"), encodeCbor(f)) }],
      ["fmt that is a number", { attestationObject: (f: Map<string, CborValue>) => encodeCbor(f.set("fmt", 1)) }],
      ["fmt that is bytes", { attestationObject: (f: Map<string, CborValue>) => encodeCbor(f.set("fmt", new Uint8Array([0x6e]))) }],
      ["attStmt that is text", { attestationObject: (f: Map<string, CborValue>) => encodeCbor(f.set("attStmt", "none")) }],
      ["attStmt that is an array", { attestationObject: (f: Map<string, CborValue>) => encodeCbor(f.set("attStmt", [])) }],
      ["attStmt that is null", { attestationObject: (f: Map<string, CborValue>) => encodeCbor(f.set("attStmt", null)) }],
      ["authData that is text", { attestationObject: (f: Map<string, CborValue>) => encodeCbor(f.set("authData", "data")) }],
      ["authData that is an array", { attestationObject: (f: Map<string, CborValue>) => encodeCbor(f.set("authData", [1, 2])) }],
      ["authData shorter than 37 bytes", { attestationObject: (f: Map<string, CborValue>) => encodeCbor(f.set("authData", (f.get("authData") as Uint8Array).subarray(0, 36))) }],
      ["authData cut inside the credential id's length", { attestationObject: (f: Map<string, CborValue>) => encodeCbor(f.set("authData", (f.get("authData") as Uint8Array).subarray(0, 54))) }],
      ["authData cut inside the credential id", { attestationObject: (f: Map<string, CborValue>) => encodeCbor(f.set("authData", (f.get("authData") as Uint8Array).subarray(0, 60))) }],
      ["authData cut inside the key", { attestationObject: (f: Map<string, CborValue>) => encodeCbor(f.set("authData", (f.get("authData") as Uint8Array).subarray(0, 80))) }],
      ["text map keys in the attestation as numbers", { attestationObject: (f: Map<string, CborValue>) => encodeCbor(new Map<number, CborValue>([[1, f.get("fmt")!], [2, f.get("attStmt")!], [3, f.get("authData")!]])) }],
    ] as const)("refuses %s", async (_, edit) => {
      const { user, browser } = await signedIn("refuse");
      const fixed: Edits = { ...(edit as Edits) };
      if (fixed.origin) fixed.origin = fixed.origin.replace("ISSUER", stack.issuer).replace("PORT", String(stack.port));
      if (fixed.rpId) fixed.rpId = fixed.rpId.replace("PORT", String(stack.port));
      await expectError(await register(browser, new SoftAuthenticator(), fixed), 400, "invalid_request", REFUSED);
      expect(await passkeysOf(user.id)).toEqual([]);
      expect(await auditOf(user.id)).toEqual([]);
    });

    test("an RSA key of 1024 bits is refused", async () => {
      const { browser } = await signedIn("rsa1024");
      await expectError(await register(browser, new SoftAuthenticator(-257, { rsaBits: 1024 })), 400, "invalid_request", REFUSED);
    });

    test.each([
      ["backed up and backup eligible", { flags: UP | UV | AT | BE | BS }],
      ["backup eligible, not backed up", { flags: UP | UV | AT | BE }],
      ["a credential id of 1023 bytes", { credentialId: new Uint8Array(1023).fill(3), id: b64u(new Uint8Array(1023).fill(3)) }],
      ["a credential id of 1 byte", { credentialId: Uint8Array.from([9]), id: b64u(Uint8Array.from([9])) }],
      ["extensions after the key with the ED flag", { flags: UP | UV | AT | ED, afterKey: encodeCbor(new Map<string, CborValue>([["credProtect", 2]])) }],
      ["an empty extensions map with the ED flag", { flags: UP | UV | AT | ED, afterKey: encodeCbor(new Map()) }],
      ["crossOrigin false", { crossOrigin: false }],
      ["a packed attestation, which isn't read", { fmt: "packed", attStmt: new Map<string, CborValue>([["alg", -7], ["sig", Uint8Array.from([1])], ["x5c", [Uint8Array.from([0x30, 0x03, 0x02, 0x01, 0x01])]]]) }],
      ["a format nobody knows", { fmt: "something-new" }],
      ["the fields in another order", { attestationObject: (f: Map<string, CborValue>) => encodeCbor(new Map<string, CborValue>([["authData", f.get("authData")!], ["fmt", f.get("fmt")!], ["attStmt", f.get("attStmt")!]])) }],
      ["an extra member in the attestation object", { attestationObject: (f: Map<string, CborValue>) => encodeCbor(f.set("extra", 1)) }],
      ["an RSA exponent written with a leading zero", { publicKey: encodeCbor(new Map<number, CborValue>([[1, 3], [3, -257], [-1, rsaN], [-2, Uint8Array.from([0, 1, 0, 1])]])) }],
    ] as const)("accepts %s", async (_, edit) => {
      const { user, browser } = await signedIn("accept");
      const res = await register(browser, new SoftAuthenticator(), edit as Edits);
      expect(res.status).toBe(201);
      expect(await passkeysOf(user.id)).toHaveLength(1);
    });

    describe("CBOR the decoder refuses", () => {
      test.each([
        ["an indefinite-length attestation map", (f: Map<string, CborValue>) => cat([0xbf], text("fmt"), encodeCbor(f.get("fmt")!), text("attStmt"), encodeCbor(f.get("attStmt")!), text("authData"), encodeCbor(f.get("authData")!), [0xff])],
        ["an indefinite-length attStmt", (f: Map<string, CborValue>) => rawMap([[text("fmt"), text("none")], [text("attStmt"), [0xbf, 0xff]], [text("authData"), encodeCbor(f.get("authData")!)]])],
        ["an indefinite-length byte string as authData", (f: Map<string, CborValue>) => rawMap([[text("fmt"), text("none")], [text("attStmt"), [0xa0]], [text("authData"), cat([0x5f], encodeCbor(f.get("authData")!), [0xff])]])],
        ["a reserved length (info 28)", (f: Map<string, CborValue>) => attestation(f, [[text("x"), [0x1c]]])],
        ["a tag around the attestation object", (f: Map<string, CborValue>) => cat([0xd8, 0x18], encodeCbor(f))],
        ["a tag inside attStmt", (f: Map<string, CborValue>) => attestation(f, [[text("x"), [0xc1, 0x00]]])],
        ["a half-precision float", (f: Map<string, CborValue>) => attestation(f, [[text("x"), [0xf9, 0x3c, 0x00]]])],
        ["a double", (f: Map<string, CborValue>) => attestation(f, [[text("x"), [0xfb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0]]])],
        ["the simple value undefined", (f: Map<string, CborValue>) => attestation(f, [[text("x"), [0xf7]]])],
        ["a duplicate map key", (f: Map<string, CborValue>) => attestation(f, [[text("fmt"), text("none")]])],
        ["a byte-string map key", (f: Map<string, CborValue>) => attestation(f, [[[0x41, 0x78], [0x01]]])],
        ["an array map key", (f: Map<string, CborValue>) => attestation(f, [[[0x80], [0x01]]])],
        ["nesting past the limit", (f: Map<string, CborValue>) => rawMap([[text("fmt"), text("none")], [text("attStmt"), rawMap([[text("x"), nested(7)]])], [text("authData"), encodeCbor(f.get("authData")!)]])],
        ["trailing bytes", (f: Map<string, CborValue>) => cat(encodeCbor(f), [0x00])],
        ["a second item after the map", (f: Map<string, CborValue>) => cat(encodeCbor(f), [0xa0])],
        ["truncation", (f: Map<string, CborValue>) => Buffer.from(encodeCbor(f)).subarray(0, encodeCbor(f).length - 1)],
        ["a length past the end", (f: Map<string, CborValue>) => attestation(f, [[text("x"), [0x5a, 0x00, 0x01, 0x00, 0x00, 0x01]]])],
        ["a map count past the end", (f: Map<string, CborValue>) => cat([0xa4], text("fmt"), text("none"), text("attStmt"), [0xa0], text("authData"), encodeCbor(f.get("authData")!))],
        ["invalid UTF-8 in fmt", (f: Map<string, CborValue>) => rawMap([[text("fmt"), [0x62, 0xc3, 0x28]], [text("attStmt"), [0xa0]], [text("authData"), encodeCbor(f.get("authData")!)]])],
        ["invalid UTF-8 in a key", (f: Map<string, CborValue>) => attestation(f, [[[0x62, 0xff, 0xfe], [0x01]]])],
        ["an integer of 2^53", (f: Map<string, CborValue>) => attestation(f, [[text("x"), [0x1b, 0x00, 0x20, 0, 0, 0, 0, 0, 0]]])],
        ["a negative integer of -1 - 2^53", (f: Map<string, CborValue>) => attestation(f, [[text("x"), [0x3b, 0x00, 0x20, 0, 0, 0, 0, 0, 0]]])],
        ["an integer of 2^64 - 1", (f: Map<string, CborValue>) => attestation(f, [[text("x"), [0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]]])],
        ["empty input", () => new Uint8Array(0)],
      ] as const)("refuses %s in the attestation object", async (_, build) => {
        const { user, browser } = await signedIn("cbor");
        await expectError(await register(browser, new SoftAuthenticator(), { attestationObject: build as (f: Map<string, CborValue>) => Uint8Array }), 400, "invalid_request", REFUSED);
        expect(await passkeysOf(user.id)).toEqual([]);
      });

      test.each([
        ["nesting at the limit", (f: Map<string, CborValue>) => rawMap([[text("fmt"), text("none")], [text("attStmt"), rawMap([[text("x"), nested(6)]])], [text("authData"), encodeCbor(f.get("authData")!)]])],
        ["an integer of 2^53 - 1", (f: Map<string, CborValue>) => attestation(f, [[text("x"), [0x1b, 0x00, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]]])],
        ["true, false and null", (f: Map<string, CborValue>) => attestation(f, [[text("x"), [0x83, 0xf5, 0xf4, 0xf6]]])],
        ["an integer map key", (f: Map<string, CborValue>) => attestation(f, [[[0x20], [0x01]]])],
        ["a long-form length for a short string", (f: Map<string, CborValue>) => rawMap([[text("fmt"), [0x78, 0x04, ...Buffer.from("none")]], [text("attStmt"), [0xa0]], [text("authData"), encodeCbor(f.get("authData")!)]])],
      ] as const)("accepts %s", async (_, build) => {
        const { browser } = await signedIn("cbor-ok");
        expect((await register(browser, new SoftAuthenticator(), { attestationObject: build as (f: Map<string, CborValue>) => Uint8Array })).status).toBe(201);
      });

      test.each([
        ["a tag", (cose: Uint8Array) => cat([0xc1], cose)],
        ["a float inside", () => rawMap([[[0x01], [0x02]], [[0x03], [0x26]], [[0x20], [0x01]], [[0x21], [0xf9, 0x3c, 0x00]], [[0x22], [0x01]]])],
        ["an indefinite-length map", (cose: Uint8Array) => cat([0xbf], Buffer.from(cose).subarray(1), [0xff])],
        ["a duplicate label", () => rawMap([[[0x01], [0x02]], [[0x01], [0x02]], [[0x03], [0x26]]])],
        ["an integer past 2^53", () => rawMap([[[0x01], [0x1b, 0x00, 0x20, 0, 0, 0, 0, 0, 0]], [[0x03], [0x26]]])],
        ["truncation", (cose: Uint8Array) => Buffer.from(cose).subarray(0, cose.length - 1)],
      ] as const)("refuses %s in the credential's key", async (_, build) => {
        const { browser } = await signedIn("cbor-key");
        const auth = new SoftAuthenticator(-7);
        await expectError(await register(browser, auth, { publicKey: build(auth.cose) }), 400, "invalid_request", REFUSED);
      });

      test("refuses a tag in the extensions", async () => {
        const { browser } = await signedIn("cbor-ext");
        await expectError(await register(browser, new SoftAuthenticator(), { flags: UP | UV | AT | ED, afterKey: Uint8Array.from([0xc1, 0xa0]) }), 400, "invalid_request", REFUSED);
      });
    });

    test.each([
      ["a type other than public-key", (r: any) => ({ ...r, type: "password" })],
      ["no type", (r: any) => ({ ...r, type: undefined })],
      ["an id that is a number", (r: any) => ({ ...r, id: 5 })],
      ["no id", (r: any) => ({ ...r, id: undefined })],
      ["no inner response", (r: any) => ({ ...r, response: undefined })],
      ["an inner response that is an array", (r: any) => ({ ...r, response: [r.response] })],
      ["clientDataJSON that is a number", (r: any) => ({ ...r, response: { ...r.response, clientDataJSON: 1 } })],
      ["no attestationObject", (r: any) => ({ ...r, response: { ...r.response, attestationObject: undefined } })],
      ["clientDataJSON that isn't JSON", (r: any) => ({ ...r, response: { ...r.response, clientDataJSON: b64u("{") } })],
      ["clientDataJSON that is a JSON array", (r: any) => ({ ...r, response: { ...r.response, clientDataJSON: b64u("[]") } })],
    ])("refuses a response with %s", async (_, change) => {
      const { user, browser } = await signedIn("shape");
      const { options, registration } = await start(browser);
      const response = change(new SoftAuthenticator().create(options, stack.issuer));
      await expectError(await browser.api("POST", "/v1/me/passkeys", { registration, response }), 400, "invalid_request", REFUSED);
      expect(await passkeysOf(user.id)).toEqual([]);
    });

    test.each([
      ["a string", "abc"],
      ["an array", []],
      ["null", null],
      ["a number", 1],
      ["missing", undefined],
    ])("a response that is %s is refused without spending the challenge", async (_, response) => {
      const { browser } = await signedIn("notobj");
      const auth = new SoftAuthenticator();
      const { options, registration } = await start(browser);
      await expectError(await browser.api("POST", "/v1/me/passkeys", { registration, response }), 400, "invalid_request", REFUSED);
      expect((await browser.api("POST", "/v1/me/passkeys", { registration, response: auth.create(options, stack.issuer) })).status).toBe(201);
    });

    test.each([
      ["null", null],
      ["a number", 5],
      ["an object", { u: "x", c: "y" }],
      ["an empty string", ""],
      ["a string that isn't sealed", "abc123"],
      ["true", true],
    ])("a registration that is %s is refused", async (_, registration) => {
      const { user, browser } = await signedIn("regtype");
      const { options } = await start(browser);
      await expectError(await browser.api("POST", "/v1/me/passkeys", { registration, response: new SoftAuthenticator().create(options, stack.issuer) }), 400, "invalid_request", REFUSED);
      expect(await passkeysOf(user.id)).toEqual([]);
    });

    test("a challenge is used once, even by a failed attempt", async () => {
      const { user, browser } = await signedIn("once", {}, { amr: TWO_FACTORS });
      const { options, registration } = await start(browser);
      const a = new SoftAuthenticator();
      expect((await browser.api("POST", "/v1/me/passkeys", { registration, response: a.create(options, stack.issuer) })).status).toBe(201);
      await expectError(await browser.api("POST", "/v1/me/passkeys", { registration, response: new SoftAuthenticator().create(options, stack.issuer) }), 400, "invalid_request", REFUSED);
      const second = await start(browser);
      await expectError(await browser.api("POST", "/v1/me/passkeys", { registration: second.registration, response: new SoftAuthenticator().create(second.options, stack.issuer, { rpId: "example.com" }) }), 400, "invalid_request", REFUSED);
      await expectError(await browser.api("POST", "/v1/me/passkeys", { registration: second.registration, response: new SoftAuthenticator().create(second.options, stack.issuer) }), 400, "invalid_request", REFUSED);
      expect(await passkeysOf(user.id)).toHaveLength(1);
    });

    test("an expired registration is refused; the same, live, is accepted", async () => {
      const { user, browser } = await signedIn("expired");
      const { options } = await start(browser);
      const auth = new SoftAuthenticator();
      const expired = stack.crypt.seal("passkey-reg", { u: user.id, c: options.challenge }, -1);
      await expectError(await browser.api("POST", "/v1/me/passkeys", { registration: expired, response: auth.create(options, stack.issuer) }), 400, "invalid_request", REFUSED);
      const live = stack.crypt.seal("passkey-reg", { u: user.id, c: options.challenge }, 60);
      expect((await browser.api("POST", "/v1/me/passkeys", { registration: live, response: auth.create(options, stack.issuer) })).status).toBe(201);
    });

    test("a registration sealed for another user is refused", async () => {
      const { user, browser } = await signedIn("mine");
      const other = await stack.user({ username: uname("theirs") });
      const challenge = b64u(randomBytes(32));
      const options = { challenge, rp: { id: "127.0.0.1" }, pubKeyCredParams: [{ alg: -7 }] };
      const registration = stack.crypt.seal("passkey-reg", { u: other.id, c: challenge }, 60);
      await expectError(await browser.api("POST", "/v1/me/passkeys", { registration, response: new SoftAuthenticator().create(options, stack.issuer) }), 400, "invalid_request", REFUSED);
      expect(await passkeysOf(user.id)).toEqual([]);
      expect(await passkeysOf(other.id)).toEqual([]);
    });

    test("another user's real registration is refused", async () => {
      const a = await signedIn("reg-a");
      const b = await signedIn("reg-b");
      const { options, registration } = await start(a.browser);
      await expectError(await b.browser.api("POST", "/v1/me/passkeys", { registration, response: new SoftAuthenticator().create(options, stack.issuer) }), 400, "invalid_request", REFUSED);
    });

    test("a registration sealed for another purpose is refused", async () => {
      const { user, browser } = await signedIn("purpose");
      const challenge = b64u(randomBytes(32));
      const registration = stack.crypt.seal("totp-enrol", { u: user.id, c: challenge }, 60);
      const options = { challenge, rp: { id: "127.0.0.1" }, pubKeyCredParams: [{ alg: -7 }] };
      await expectError(await browser.api("POST", "/v1/me/passkeys", { registration, response: new SoftAuthenticator().create(options, stack.issuer) }), 400, "invalid_request", REFUSED);
    });

    test("the same credential can't be registered twice, by anyone", async () => {
      const { user, browser } = await signedIn("twice", {}, { amr: TWO_FACTORS });
      const auth = new SoftAuthenticator();
      expect((await register(browser, auth)).status).toBe(201);
      await expectError(await register(browser, auth), 400, "invalid_request", REFUSED);
      const other = await signedIn("twice-other");
      await expectError(await register(other.browser, auth), 400, "invalid_request", REFUSED);
      expect(await passkeysOf(user.id)).toHaveLength(1);
      expect(await passkeysOf(other.user.id)).toEqual([]);
      expect(await auditOf(user.id, "passkey.add")).toHaveLength(1);
    });
  });

  // -------------------------------------------------- recent sign-in

  describe("a recent sign-in", () => {
    test.each([
      ["starting", (b: Browser) => b.api("POST", "/v1/me/passkeys", {})],
      ["finishing", (b: Browser) => b.api("POST", "/v1/me/passkeys", { registration: "x", response: {} })],
      ["removing", (b: Browser) => b.api("DELETE", `/v1/me/passkeys/${newId("pk")}`)],
    ])("%s needs a sign-in in the last 15 minutes", async (_, call) => {
      const { browser } = await signedIn("stale", {}, { authAge: 16 * 60 });
      await expectError(await call(browser), 403, "reauth_required", "Sign in again to make this change.");
    });

    test("after the first passkey, a password-only session adds or removes none", async () => {
      const { browser } = await signedIn("second");
      const res = await register(browser, new SoftAuthenticator());
      expect(res.status).toBe(201);
      const { id } = (await res.json()) as { id: string };
      await expectError(await browser.api("POST", "/v1/me/passkeys", {}), 403, "reauth_required", "Sign in again with your second factor to make this change.");
      await expectError(await browser.api("DELETE", `/v1/me/passkeys/${id}`), 403, "reauth_required", "Sign in again with your second factor to make this change.");
    });

    test("a session from a passkey sign-in has the second factor", async () => {
      const { browser } = await signedIn("swk", {}, { amr: ["swk", "user", "mfa"] });
      await stack.db`INSERT INTO passkeys (id, user_id, credential_id, public_key, name) VALUES (${newId("pk")}, (SELECT user_id FROM sessions WHERE id = ${browser.sessionId}), ${randomBytes(16)}, ${Buffer.from([0xa0])}, 'Old')`;
      expect((await register(browser, new SoftAuthenticator())).status).toBe(201);
    });

    test("the list needs no recent sign-in", async () => {
      const { browser } = await signedIn("oldlist", {}, { authAge: 24 * 3600 });
      expect(await (await browser.api("GET", "/v1/me/passkeys")).json()).toEqual({ items: [], next: null });
    });
  });

  // ------------------------------------------------- list and delete

  describe("listing and removing", () => {
    test("the list shows the user's own passkeys, oldest first, without keys", async () => {
      const { user, browser } = await signedIn("list", {}, { amr: TWO_FACTORS });
      const a = (await (await register(browser, new SoftAuthenticator(-7), {}, { name: "First" })).json()) as any;
      const b = (await (await register(browser, new SoftAuthenticator(-8), {}, { name: "Second" })).json()) as any;
      await stack.db`UPDATE passkeys SET created_at = now() - interval '1 minute' WHERE id = ${a.id}`;
      const other = await signedIn("list-other");
      await register(other.browser, new SoftAuthenticator());
      const res = await browser.api("GET", "/v1/me/passkeys");
      expect(res.status).toBe(200);
      const rows = await stack.db`SELECT id, created_at FROM passkeys WHERE user_id = ${user.id} ORDER BY created_at`;
      expect(await res.json()).toEqual({
        items: [
          { id: a.id, name: "First", created_at: (rows as any[])[0].created_at.toISOString(), last_used_at: null },
          { id: b.id, name: "Second", created_at: (rows as any[])[1].created_at.toISOString(), last_used_at: null },
        ],
        next: null,
      });
    });

    test("removing one is 204, audited and announced; it then no longer signs in", async () => {
      const { user, browser } = await signedIn("remove", {}, { amr: TWO_FACTORS });
      const auth = new SoftAuthenticator();
      const { id } = (await (await register(browser, auth, {}, { name: "Old phone" })).json()) as { id: string };
      const res = await browser.api("DELETE", `/v1/me/passkeys/${id}`);
      expect(res.status).toBe(204);
      expect(await res.text()).toBe("");
      expect(await passkeysOf(user.id)).toEqual([]);
      const audit = await auditOf(user.id, "passkey.remove");
      expect(audit).toHaveLength(1);
      expect(audit[0]).toMatchObject({ actor: user.id, ip: browser.ip, detail: { id } });
      const mail = await stack.smtp.waitFor(user.email!, (m) => m.subject === "Security notice: a passkey was removed");
      expect(mail.text.trimEnd()).toBe(noticeText(user.username, "a passkey was removed", "Name: Old phone"));
      await expectError((await passkeySignIn(auth)).res, 401, "unauthorized", "That passkey sign-in didn't work.");
      await expectError(await browser.api("DELETE", `/v1/me/passkeys/${id}`), 404, "not_found", "No such passkey.");
      expect(await auditOf(user.id, "passkey.remove")).toHaveLength(1);
    });

    test("an unknown id or another user's passkey is 404 and stays", async () => {
      const owner = await signedIn("pkowner");
      const { id } = (await (await register(owner.browser, new SoftAuthenticator())).json()) as { id: string };
      const { user, browser } = await signedIn("pkthief");
      for (const target of [id, newId("pk"), "nope"]) {
        await expectError(await browser.api("DELETE", `/v1/me/passkeys/${target}`), 404, "not_found", "No such passkey.");
      }
      expect(await passkeysOf(owner.user.id)).toHaveLength(1);
      expect(await auditOf(user.id)).toEqual([]);
    });
  });

  // ------------------------------------------------------------ sign-in

  describe("signing in with a stored key", () => {
    test("the options name the RP ID and a challenge, and set a sealed cookie", async () => {
      const browser = stack.browser();
      const res = await browser.request("/login/passkey/options", { method: "POST" });
      expect(res.status).toBe(200);
      const { options } = (await res.json()) as { options: any };
      expect(options).toEqual({ rpId: "127.0.0.1", challenge: options.challenge, timeout: 60000, userVerification: "required" });
      expect(options.challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
      const cookie = res.headers.getSetCookie();
      expect(cookie).toHaveLength(1);
      const m = /^__Host-webauthn=([A-Za-z0-9_-]+); Path=\/; Secure; HttpOnly; SameSite=Lax; Max-Age=300$/.exec(cookie[0]!);
      expect(m).not.toBeNull();
      expect(stack.crypt.open("passkey-auth", m![1]!).v).toEqual({ c: options.challenge });
    });

    test.each([
      ["EdDSA", -8],
      ["ES256", -7],
      ["RS256", -257],
    ] as const)("an %s passkey signs in with two factors and records its use", async (_, alg) => {
      const { user, browser: owner } = await signedIn("signin");
      const auth = new SoftAuthenticator(alg);
      const { id } = (await (await register(owner, auth)).json()) as { id: string };
      const { browser, res } = await passkeySignIn(auth, {}, { return_to: "/account?tab=keys" });
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ redirect: "/account?tab=keys" });
      const cookies = res.headers.getSetCookie();
      expect(cookies.some((c) => SESSION_COOKIE.test(c))).toBe(true);
      expect(cookies).toContain("__Host-webauthn=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0");
      const meRes = await browser.api("GET", "/v1/me");
      expect(((await meRes.json()) as any).id).toBe(user.id);
      const [session] = await stack.db`SELECT amr FROM sessions WHERE user_id = ${user.id} AND id <> ${owner.sessionId}`;
      expect(session.amr).toEqual(["swk", "user", "mfa"]);
      const [row] = await passkeysOf(user.id);
      expect(row.id).toBe(id);
      expect(Number(row.sign_count)).toBe(0);
      expect(row.last_used_at).not.toBeNull();
      const list = (await (await owner.api("GET", "/v1/me/passkeys")).json()) as { items: any[] };
      expect(list.items[0].last_used_at).toBe(row.last_used_at.toISOString());
      const audit = await auditOf(user.id, "login.ok");
      expect(audit).toHaveLength(1);
      expect(audit[0]!.detail).toMatchObject({ method: "passkey", amr: ["swk", "user", "mfa"] });
    });

    test("without return_to, or with one off this site, it leads to /account", async () => {
      const { browser: owner } = await signedIn("signin-rt");
      const auth = new SoftAuthenticator();
      await register(owner, auth);
      for (const return_to of [undefined, "https://evil.example.com/", "//evil.example.com", 5]) {
        const { res } = await passkeySignIn(auth, {}, { return_to });
        expect(await res.json()).toEqual({ redirect: "/account" });
      }
    });

    test("a synced passkey reports 0 every time, and is accepted every time", async () => {
      const { user, browser } = await signedIn("synced");
      const auth = new SoftAuthenticator(-7);
      await register(browser, auth);
      for (let i = 0; i < 3; i++) expect((await passkeySignIn(auth)).res.status).toBe(200);
      expect(Number((await passkeysOf(user.id))[0].sign_count)).toBe(0);
    });

    test("a counting authenticator must move forward: equal or lower is refused, and the stored count kept", async () => {
      const { user, browser } = await signedIn("counting");
      const auth = new SoftAuthenticator(-7, { counts: true });
      await register(browser, auth);
      const count = async () => Number((await passkeysOf(user.id))[0].sign_count);
      expect(await count()).toBe(1);
      expect((await passkeySignIn(auth, { counter: 2 })).res.status).toBe(200);
      expect(await count()).toBe(2);
      for (const counter of [2, 1, 0]) {
        await expectError((await passkeySignIn(auth, { counter })).res, 401, "unauthorized", "That passkey sign-in didn't work.");
        expect(await count()).toBe(2);
      }
      expect((await passkeySignIn(auth, { counter: 7 })).res.status).toBe(200);
      expect(await count()).toBe(7);
      const fails = (await stack.audit("login.fail")).filter((r) => r.detail.method === "passkey" && r.user_id === null);
      expect(fails.length).toBeGreaterThanOrEqual(3);
    });

    test("a key that started at 0 and then counts is accepted", async () => {
      const { user, browser } = await signedIn("startzero");
      const auth = new SoftAuthenticator(-8);
      await register(browser, auth);
      expect((await passkeySignIn(auth, { counter: 1 })).res.status).toBe(200);
      expect(Number((await passkeysOf(user.id))[0].sign_count)).toBe(1);
      await expectError((await passkeySignIn(auth, { counter: 0 })).res, 401, "unauthorized", "That passkey sign-in didn't work.");
    });

    test.each([
      ["a signature by another key", () => ({ signWith: new SoftAuthenticator(-7).privateKey })],
      ["another origin", () => ({ origin: "https://evil.example.com" })],
      ["a registration's client data type", () => ({ type: "webauthn.create" })],
      ["another RP ID", () => ({ rpId: "example.com" })],
      ["no user verification", () => ({ flags: UP })],
      ["an unknown credential", () => ({ id: b64u(randomBytes(16)) })],
    ])("refuses %s, with an audit row", async (_, edit) => {
      const { browser } = await signedIn("badsign");
      const auth = new SoftAuthenticator(-7);
      await register(browser, auth);
      const before = (await stack.audit("login.fail")).length;
      const { res, browser: b } = await passkeySignIn(auth, edit());
      expect(res.headers.getSetCookie().some((c) => c.startsWith("__Host-auth="))).toBe(false);
      await expectError(res, 401, "unauthorized", "That passkey sign-in didn't work.");
      expect((await b.api("GET", "/v1/me")).status).toBe(401);
      const fails = (await stack.audit("login.fail")).slice(before);
      expect(fails.map((f) => [f.actor, f.user_id, f.ip, f.detail])).toEqual([[null, null, b.ip, { method: "passkey" }]]);
    });

    test("a disabled user's passkey doesn't sign in", async () => {
      const { user, browser } = await signedIn("disabledpk");
      const auth = new SoftAuthenticator();
      await register(browser, auth);
      await stack.db`UPDATE users SET disabled_at = now() WHERE id = ${user.id}`;
      await expectError((await passkeySignIn(auth)).res, 401, "unauthorized", "That passkey sign-in didn't work.");
    });

    test("a sign-in challenge is accepted once", async () => {
      const { browser: owner } = await signedIn("replay");
      const auth = new SoftAuthenticator();
      await register(owner, auth);
      const browser = stack.browser();
      const o = await browser.request("/login/passkey/options", { method: "POST" });
      const { options } = (await o.json()) as { options: any };
      const cookie = browser.cookies.get("__Host-webauthn")!;
      const send = (b: Browser) => b.request("/login/passkey", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ response: auth.get(options, stack.issuer) }) });
      expect((await send(browser)).status).toBe(200);
      const again = stack.browser();
      again.cookies.set("__Host-webauthn", cookie);
      await expectError(await send(again), 401, "unauthorized", "That passkey sign-in didn't work.");
    });

    test("without the options' cookie it doesn't sign in", async () => {
      const { browser: owner } = await signedIn("nocookie");
      const auth = new SoftAuthenticator();
      await register(owner, auth);
      const browser = stack.browser();
      const o = await browser.request("/login/passkey/options", { method: "POST" });
      const { options } = (await o.json()) as { options: any };
      browser.cookies.delete("__Host-webauthn");
      const res = await browser.request("/login/passkey", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ response: auth.get(options, stack.issuer) }) });
      await expectError(res, 401, "unauthorized", "That passkey sign-in didn't work.");
    });
  });
});

