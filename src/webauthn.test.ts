import { describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import { CborError, decodeCbor, decodeCborPrefix } from "./cbor";
import { base64url } from "./crypto";
import { AT, BS, ED, encodeCbor, SoftAuthenticator, UP, UV, type Algorithm, type CborValue } from "./testing/authenticator";
import { creationOptions, isAttachment, newChallenge, requestOptions, verifyAssertion, verifyRegistration, type RelyingParty } from "./webauthn";

// WebAuthn's relying-party checks (docs/DESIGN.md §9.1) against a software
// authenticator, and the CBOR they read.

const RP: RelyingParty = { id: "auth.example.com", origin: "https://auth.example.com" };
const USER = { handle: new TextEncoder().encode("usr_0"), name: "alice", displayName: "Alice" };

function register(a: SoftAuthenticator, edit: Parameters<SoftAuthenticator["create"]>[2] = {}) {
  const challenge = newChallenge();
  const options = creationOptions(RP, challenge, USER, []);
  return verifyRegistration(RP, challenge, a.create(options, RP.origin, edit));
}

function signIn(a: SoftAuthenticator, stored: { publicKey: Uint8Array; signCount: number }, edit: Parameters<SoftAuthenticator["get"]>[2] = {}) {
  const challenge = newChallenge();
  return verifyAssertion(RP, challenge, stored, a.get(requestOptions(RP, challenge), RP.origin, edit));
}

describe("CBOR", () => {
  test("decodes the types WebAuthn uses", () => {
    const value = new Map<number | string, CborValue>([
      [1, 2],
      [-1, -300],
      ["fmt", "none"],
      ["b", Uint8Array.from([1, 2, 3])],
      ["list", [true, false, null, 2 ** 40]],
    ]);
    expect(decodeCbor(encodeCbor(value))).toEqual(value);
  });

  test("a prefix decode stops after one item and says where", () => {
    const bytes = Uint8Array.from([...encodeCbor(new Map([[1, 2]])), 0xa0]);
    expect(decodeCborPrefix(bytes).end).toBe(3);
    expect(() => decodeCbor(bytes)).toThrow(CborError);
  });

  test.each([
    ["empty input", [], "truncated"],
    ["a truncated byte string", [0x45, 1, 2], "truncated"],
    ["an indefinite-length byte string", [0x5f, 0x41, 1, 0xff], "indefinite"],
    ["an indefinite-length map", [0xbf, 0xff], "indefinite"],
    ["a tag", [0xc0, 0x61, 0x61], "tags"],
    ["a half-precision float", [0xf9, 0x3c, 0x00], "float"],
    ["an undefined simple value", [0xf7], "simple value"],
    ["an integer above 2^53", [0x1b, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], "too large"],
    ["a length claim beyond the input", [0x5b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00], "truncated"],
    ["an array count beyond the input", [0x9a, 0xff, 0xff, 0xff, 0xff, 0x01], "truncated"],
    ["a duplicate map key", [0xa2, 0x01, 0x01, 0x01, 0x02], "duplicate"],
    ["a byte-string map key", [0xa1, 0x41, 0x00, 0x01], "map key"],
    ["invalid UTF-8", [0x62, 0xc3, 0x28], "UTF-8"],
    ["nesting deeper than 8", [...Array(10).fill(0x81), 0x01], "nested"],
  ])("refuses %s", (_, bytes, why) => {
    expect(() => decodeCbor(Uint8Array.from(bytes as number[]))).toThrow(new RegExp(why as string));
  });
});

describe("options", () => {
  test("registration asks for a discoverable, user-verified credential with no attestation", () => {
    const o = creationOptions(RP, "abc", USER, [Uint8Array.from([1, 2, 3])]);
    expect(o).toEqual({
      challenge: "abc",
      rp: { name: "auth.example.com", id: "auth.example.com" },
      user: { id: base64url(USER.handle), name: "alice", displayName: "Alice" },
      pubKeyCredParams: [
        { type: "public-key", alg: -8 },
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      timeout: 60000,
      attestation: "none",
      excludeCredentials: [{ type: "public-key", id: "AQID" }],
      authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
    });
  });

  test.each(["platform", "cross-platform"] as const)("registration can ask for a %s authenticator, and still for the same credential", (attachment) => {
    expect(creationOptions(RP, "abc", USER, [], attachment).authenticatorSelection).toEqual({
      authenticatorAttachment: attachment,
      residentKey: "required",
      requireResidentKey: true,
      userVerification: "required",
    });
  });

  test("registration names no attachment unless asked", () => {
    expect("authenticatorAttachment" in creationOptions(RP, "abc", USER, []).authenticatorSelection).toBe(false);
  });

  test("an attachment is platform or cross-platform, spelled as WebAuthn spells it", () => {
    expect(["platform", "cross-platform", "Platform", "internal", "", null, undefined, 1].map(isAttachment)).toEqual([true, true, false, false, false, false, false, false]);
  });

  test("sign-in names no credentials, and requires user verification", () => {
    expect(requestOptions(RP, "abc")).toEqual({ rpId: "auth.example.com", challenge: "abc", timeout: 60000, userVerification: "required" });
  });

  test("challenges are 32 random bytes", () => {
    const c = newChallenge();
    expect(Buffer.from(c, "base64url")).toHaveLength(32);
    expect(newChallenge()).not.toBe(c);
  });
});

describe("registration (§7.1)", () => {
  test.each([
    ["ES256", -7],
    ["EdDSA", -8],
    ["RS256", -257],
  ] as const)("registers a %s key, which then verifies a sign-in", (_, alg) => {
    const a = new SoftAuthenticator(alg as Algorithm);
    const cred = register(a)!;
    expect(cred.id.equals(a.credentialId)).toBe(true);
    expect(cred.publicKey.equals(Buffer.from(a.cose))).toBe(true);
    expect(cred.signCount).toBe(0);
    expect(signIn(a, { publicKey: cred.publicKey, signCount: 0 })).toEqual({ signCount: 0 });
  });

  test("keeps a counting authenticator's counter", () => {
    const a = new SoftAuthenticator(-7, { counts: true });
    expect(register(a)!.signCount).toBe(1);
  });

  test("extension data after the key is allowed when the ED flag says so", () => {
    const a = new SoftAuthenticator();
    const cred = register(a, { flags: UP | UV | AT | ED, afterKey: encodeCbor(new Map([["credProtect", 2]])) })!;
    expect(cred.publicKey.equals(Buffer.from(a.cose))).toBe(true);
  });

  test("the attestation statement is not read: any format and statement register the same key", () => {
    const a = new SoftAuthenticator();
    const certs = [Uint8Array.from([0x30, 0x03, 0x02, 0x01, 0x01])];
    for (const edit of [
      { fmt: "packed", attStmt: new Map<string, CborValue>([["alg", -7], ["sig", Uint8Array.from([1])], ["x5c", certs]]) },
      { fmt: "android-key", attStmt: new Map<string, CborValue>([["alg", -7], ["sig", Uint8Array.from([1])], ["x5c", certs]]) },
      { fmt: "something-new" },
    ]) {
      expect(register(a, edit)?.publicKey.equals(Buffer.from(a.cose))).toBe(true);
    }
  });

  test("accepts the response a browser sends, extra fields included", () => {
    const a = new SoftAuthenticator();
    const challenge = newChallenge();
    const res = { ...a.create(creationOptions(RP, challenge, USER, []), RP.origin), authenticatorAttachment: "platform" };
    expect(verifyRegistration(RP, challenge, res)).not.toBeNull();
  });

  const otherKey = (cose: Map<number, CborValue>) => encodeCbor(cose);
  const p256 = generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const x = Buffer.from(p256.x, "base64url");
  const y = Buffer.from(p256.y, "base64url");

  test.each([
    ["a sign-in's client data type", { type: "webauthn.get" }],
    ["another challenge", { challenge: base64url(Buffer.alloc(32, 1)) }],
    ["another origin", { origin: "https://evil.example.com" }],
    ["a sibling subdomain's origin", { origin: "https://app.auth.example.com" }],
    ["the origin over http", { origin: "http://auth.example.com" }],
    ["a cross-origin ceremony", { crossOrigin: true }],
    ["another RP ID", { rpId: "example.com" }],
    ["no user presence", { flags: UV | AT }],
    ["no user verification", { flags: UP | AT }],
    ["no attested credential data", { flags: UP | UV }],
    ["backed up but not backup eligible", { flags: UP | UV | AT | BS }],
    ["an id that isn't the credential's", { id: base64url(Buffer.alloc(16, 9)) }],
    ["an empty credential id", { credentialId: new Uint8Array(0), id: "" }],
    ["a credential id over 1023 bytes", { credentialId: new Uint8Array(1024), id: base64url(new Uint8Array(1024)) }],
    ["bytes after the key without the ED flag", { afterKey: Uint8Array.from([0xa0]) }],
    ["the ED flag with nothing after the key", { flags: UP | UV | AT | ED }],
    ["an algorithm that wasn't offered (ES384)", { publicKey: otherKey(new Map<number, CborValue>([[1, 2], [3, -35], [-1, 2], [-2, x], [-3, y]])) }],
    ["ES256 on a key that isn't EC2", { publicKey: otherKey(new Map<number, CborValue>([[1, 1], [3, -7], [-1, 1], [-2, x], [-3, y]])) }],
    ["ES256 on another curve", { publicKey: otherKey(new Map<number, CborValue>([[1, 2], [3, -7], [-1, 2], [-2, x], [-3, y]])) }],
    ["a P-256 point off the curve", { publicKey: otherKey(new Map<number, CborValue>([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, Buffer.alloc(32, 1)]])) }],
    ["a short P-256 coordinate", { publicKey: otherKey(new Map<number, CborValue>([[1, 2], [3, -7], [-1, 1], [-2, x.subarray(1)], [-3, y]])) }],
    ["a key with no algorithm", { publicKey: otherKey(new Map<number, CborValue>([[1, 2], [-1, 1], [-2, x], [-3, y]])) }],
    ["a key that isn't a map", { publicKey: encodeCbor([1, 2]) }],
    ["an attestation object with trailing bytes", { attestationObject: (f: Map<string, CborValue>) => Uint8Array.from([...encodeCbor(f), 0]) }],
    ["an attestation object without a format", { attestationObject: (f: Map<string, CborValue>) => (f.delete("fmt"), encodeCbor(f)) }],
    ["an attestation object that isn't a map", { attestationObject: () => encodeCbor(["none"]) }],
  ] as const)("refuses %s", (_, edit) => {
    expect(register(new SoftAuthenticator(), edit as never)).toBeNull();
  });

  test("refuses an RSA key under 2048 bits", () => {
    expect(register(new SoftAuthenticator(-257, { rsaBits: 1024 }))).toBeNull();
  });

  test("refuses an RSA key whose exponent isn't 65537", () => {
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ format: "jwk" }) as { n: string };
    const n = Buffer.from(rsa.n, "base64url");
    for (const e of [[1], [3], [1, 0, 0, 1]]) {
      expect(register(new SoftAuthenticator(), { publicKey: encodeCbor(new Map<number, CborValue>([[1, 3], [3, -257], [-1, n], [-2, Uint8Array.from(e)]])) })).toBeNull();
    }
    expect(register(new SoftAuthenticator(), { publicKey: encodeCbor(new Map<number, CborValue>([[1, 3], [3, -257], [-1, n], [-2, Uint8Array.from([1, 0, 1])]])) })).not.toBeNull();
  });

  test.each([
    ["nothing", null],
    ["an array", []],
    ["another credential type", { type: "password", id: "x", response: {} }],
    ["no response", { type: "public-key", id: "x" }],
    ["fields that aren't strings", { type: "public-key", id: "x", response: { clientDataJSON: 1, attestationObject: 2 } }],
    ["client data that isn't JSON", { type: "public-key", id: "x", response: { clientDataJSON: base64url(Buffer.from("{")), attestationObject: "" } }],
  ])("refuses %s as a response", (_, response) => {
    expect(verifyRegistration(RP, newChallenge(), response)).toBeNull();
  });
});

describe("sign-in (§7.2)", () => {
  function enrolled(alg: Algorithm = -7, opts: { counts?: boolean } = {}) {
    const a = new SoftAuthenticator(alg, opts);
    const cred = register(a)!;
    return { a, stored: { publicKey: cred.publicKey, signCount: cred.signCount } };
  }

  test.each([
    ["ES256", -7],
    ["EdDSA", -8],
    ["RS256", -257],
  ] as const)("refuses a %s signature by another key", (_, alg) => {
    const { a, stored } = enrolled(alg as Algorithm);
    const other = new SoftAuthenticator(alg as Algorithm);
    expect(signIn(a, stored, { signWith: other.privateKey })).toBeNull();
  });

  test("a counting authenticator's counter moves forward, and a repeat or a step back is refused", () => {
    const { a, stored } = enrolled(-7, { counts: true });
    expect(stored.signCount).toBe(1);
    expect(signIn(a, stored)).toEqual({ signCount: 2 });
    expect(signIn(a, { ...stored, signCount: 2 }, { counter: 2 })).toBeNull();
    expect(signIn(a, { ...stored, signCount: 2 }, { counter: 1 })).toBeNull();
    expect(signIn(a, { ...stored, signCount: 2 }, { counter: 0 })).toBeNull();
    expect(signIn(a, { ...stored, signCount: 2 }, { counter: 3 })).toEqual({ signCount: 3 });
  });

  test("a synced passkey's counter stays 0", () => {
    const { a, stored } = enrolled();
    expect(signIn(a, stored)).toEqual({ signCount: 0 });
    expect(signIn(a, stored)).toEqual({ signCount: 0 });
  });

  test.each([
    ["a registration's client data type", { type: "webauthn.create" }],
    ["another challenge", { challenge: base64url(Buffer.alloc(32, 1)) }],
    ["another origin", { origin: "https://evil.example.com" }],
    ["a cross-origin ceremony", { crossOrigin: true }],
    ["another RP ID", { rpId: "example.com" }],
    ["no user presence", { flags: UV }],
    ["no user verification", { flags: UP }],
    ["backed up but not backup eligible", { flags: UP | UV | BS }],
    ["flags changed after signing", { flags: UP | UV, authenticatorData: (d: Buffer) => Buffer.concat([d.subarray(0, 32), Buffer.from([UP | UV | 0x08]), d.subarray(33)]) }],
    ["a counter changed after signing", { authenticatorData: (d: Buffer) => Buffer.concat([d.subarray(0, 33), Buffer.from([0, 0, 0, 9])]) }],
    ["truncated authenticator data", { authenticatorData: (d: Buffer) => d.subarray(0, 36) }],
  ] as const)("refuses %s", (_, edit) => {
    const { a, stored } = enrolled();
    expect(signIn(a, stored, edit as never)).toBeNull();
  });

  test("refuses a stored key that doesn't parse", () => {
    const { a } = enrolled();
    expect(signIn(a, { publicKey: Uint8Array.from([0xa0]), signCount: 0 })).toBeNull();
  });

  test.each([
    ["nothing", null],
    ["another credential type", { type: "password", response: {} }],
    ["no signature", { type: "public-key", response: { clientDataJSON: "", authenticatorData: "" } }],
  ])("refuses %s as a response", (_, response) => {
    const { stored } = enrolled();
    expect(verifyAssertion(RP, newChallenge(), stored, response)).toBeNull();
  });
});
