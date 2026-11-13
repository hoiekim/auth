import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, createHmac } from "node:crypto";
import { base32, base64url, Encrypter, fromBase32, ID_PATTERN, newId, random } from "./crypto";
import { signJwt, verifyJwt } from "./jwt";
import { clientIp, formatIp, inCidr, parseCidr, parseIp } from "./net";
import { Hasher, isBreached, passwordProblem, Semaphore } from "./passwords";
import { hotp, matchingStep, otpauthUri } from "./totp";

describe("ids and encodings", () => {
  test("ids are prefixed, 26 Crockford characters, and sort by creation", async () => {
    const a = newId("usr");
    await Bun.sleep(2);
    const b = newId("usr");
    expect(a).toMatch(/^usr_[0-9a-hjkmnp-tv-z]{26}$/);
    expect(ID_PATTERN.test(a)).toBe(true);
    expect(a < b).toBe(true);
  });

  test("base32 round-trips, and 15 bytes are 24 characters (recovery codes)", () => {
    const bytes = random(15);
    expect(base32(bytes)).toHaveLength(24);
    expect(fromBase32(base32(bytes))!.equals(bytes)).toBe(true);
    expect(base32(Buffer.from("foobar"))).toBe("mzxw6ytboi");
    expect(fromBase32("not base32!")).toBeNull();
  });
});

describe("encryption at rest (§9.3)", () => {
  const crypt = new Encrypter(Buffer.alloc(32, 1));

  test("starts with the key version and round-trips under the same row id", () => {
    const sealed = crypt.encrypt(Buffer.from("s3cret-totp"), "usr_a");
    expect(sealed.subarray(0, 3).toString()).toBe("v1:");
    expect(crypt.decrypt(sealed, "usr_a").toString()).toBe("s3cret-totp");
  });

  test("a ciphertext moved to another row doesn't decrypt", () => {
    const sealed = crypt.encrypt(Buffer.from("s3cret-totp"), "usr_a");
    expect(() => crypt.decrypt(sealed, "usr_b")).toThrow();
  });

  test("another key doesn't decrypt, and a tampered byte is refused", () => {
    const sealed = crypt.encrypt(Buffer.from("s3cret-totp"), "usr_a");
    expect(() => new Encrypter(Buffer.alloc(32, 2)).decrypt(sealed, "usr_a")).toThrow();
    sealed[sealed.length - 20]! ^= 1;
    expect(() => crypt.decrypt(sealed, "usr_a")).toThrow();
  });

  test("sealed values are bound to their purpose and expire", async () => {
    const token = crypt.sealValue("pending", { u: "usr_a" }, 60);
    expect(crypt.openValue("pending", token)).toEqual({ u: "usr_a" });
    expect(crypt.openValue("totp-enrol", token)).toBeNull();
    const short = crypt.sealValue("pending", { u: "usr_a" }, 0.001);
    await Bun.sleep(5);
    expect(crypt.openValue("pending", short)).toBeNull();
    expect(crypt.openValue("pending", "garbage")).toBeNull();
  });
});

describe("JWT verification pins everything (§7.3)", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const signer = { kid: "k1", privateKey };
  const keyFor = (kid: string) => (kid === "k1" ? publicKey : undefined);
  const now = 1_763_000_000;
  const claims = { iss: "https://auth.example.com", aud: "wiki", sub: "usr_x", iat: now, exp: now + 600 };
  const opts = { typ: "at+jwt" as const, issuer: "https://auth.example.com", audience: ["wiki"], nowSeconds: now };
  const forge = (header: object, payload: object, sig = "") =>
    `${base64url(Buffer.from(JSON.stringify(header)))}.${base64url(Buffer.from(JSON.stringify(payload)))}.${sig}`;

  test("accepts a token it signed", () => {
    expect(verifyJwt(signJwt("at+jwt", claims, signer), keyFor, opts)).toMatchObject({ sub: "usr_x" });
  });

  test("refuses alg none, HS256 keyed with the public key, and an unknown kid", () => {
    expect(verifyJwt(forge({ alg: "none", typ: "at+jwt", kid: "k1" }, claims), keyFor, opts)).toBeNull();
    const pub = publicKey.export({ format: "jwk" }) as { x: string };
    const header = base64url(Buffer.from(JSON.stringify({ alg: "HS256", typ: "at+jwt", kid: "k1" })));
    const body = base64url(Buffer.from(JSON.stringify(claims)));
    const hs = createHmac("sha256", pub.x).update(`${header}.${body}`).digest("base64url");
    expect(verifyJwt(`${header}.${body}.${hs}`, keyFor, opts)).toBeNull();
    expect(verifyJwt(signJwt("at+jwt", claims, { kid: "k2", privateKey }), keyFor, opts)).toBeNull();
  });

  test("refuses an EdDSA signature under a header naming another alg", () => {
    const token = signJwt("at+jwt", claims, signer);
    const [, p, s] = token.split(".");
    const header = base64url(Buffer.from(JSON.stringify({ alg: "ES256", typ: "at+jwt", kid: "k1" })));
    expect(verifyJwt(`${header}.${p}.${s}`, keyFor, opts)).toBeNull();
  });

  test.each([
    ["the wrong issuer", { iss: "https://evil.example.com" }],
    ["the wrong audience", { aud: "tasks" }],
    ["an expiry past the leeway", { exp: now - 31 }],
    ["an iat in the future", { iat: now + 31 }],
    ["no exp", { exp: undefined }],
  ])("refuses %s", (_, over) => {
    expect(verifyJwt(signJwt("at+jwt", { ...claims, ...over }, signer), keyFor, opts)).toBeNull();
  });

  test("accepts an expiry within the 30 s leeway", () => {
    expect(verifyJwt(signJwt("at+jwt", { ...claims, exp: now - 29 }, signer), keyFor, opts)).not.toBeNull();
  });

  test("refuses another token type: an event or ID token isn't an access token", () => {
    expect(verifyJwt(signJwt("secevent+jwt", claims, signer), keyFor, opts)).toBeNull();
    expect(verifyJwt(signJwt("JWT", claims, signer), keyFor, opts)).toBeNull();
  });

  test("refuses a changed payload", () => {
    const [h, , s] = signJwt("at+jwt", claims, signer).split(".");
    const p = base64url(Buffer.from(JSON.stringify({ ...claims, sub: "usr_admin" })));
    expect(verifyJwt(`${h}.${p}.${s}`, keyFor, opts)).toBeNull();
  });
});

describe("TOTP (RFC 6238)", () => {
  // RFC 6238 Appendix B, SHA-1, truncated to 6 digits.
  const secret = Buffer.from("12345678901234567890");
  test.each([
    [59, "287082"],
    [1111111109, "081804"],
    [1111111111, "050471"],
    [1234567890, "005924"],
    [2000000000, "279037"],
  ])("at %p the code is %p", (t, code) => {
    expect(hotp(secret, Math.floor(t / 30))).toBe(code);
  });

  test("accepts one step either side, and not two", () => {
    const now = 1_111_111_111;
    const step = Math.floor(now / 30);
    expect(matchingStep(secret, hotp(secret, step - 1), now, 0)).toBe(step - 1);
    expect(matchingStep(secret, hotp(secret, step + 1), now, 0)).toBe(step + 1);
    expect(matchingStep(secret, hotp(secret, step - 2), now, 0)).toBeNull();
  });

  test("refuses a code at or before the last step used", () => {
    const now = 1_111_111_111;
    const step = Math.floor(now / 30);
    expect(matchingStep(secret, hotp(secret, step), now, step)).toBeNull();
    expect(matchingStep(secret, hotp(secret, step), now, step - 1)).toBe(step);
  });

  test("refuses anything but six digits", () => {
    expect(matchingStep(secret, "28708", 59, 0)).toBeNull();
    expect(matchingStep(secret, "2870822", 59, 0)).toBeNull();
  });

  test("the otpauth URI names the issuer's host and the username", () => {
    const uri = otpauthUri(secret, "auth.example.com", "alice");
    expect(uri).toStartWith("otpauth://totp/auth.example.com:alice?");
    expect(new URL(uri).searchParams.get("secret")).toBe(base32(secret).toUpperCase());
  });
});

describe("client addresses (§9.4)", () => {
  const trusted = [parseCidr("10.0.0.0/8")!, parseCidr("fd00::/8")!];

  test("X-Real-IP counts only from a trusted proxy", () => {
    expect(clientIp("10.1.2.3", "203.0.113.9", trusted)).toBe("203.0.113.9");
    expect(clientIp("::ffff:10.1.2.3", "203.0.113.9", trusted)).toBe("203.0.113.9");
    expect(clientIp("fd12::1", "2001:db8::9", trusted)).toBe("2001:db8::9");
    expect(clientIp("192.0.2.1", "203.0.113.9", trusted)).toBe("192.0.2.1");
    expect(clientIp("10.1.2.3", "not an ip", trusted)).toBe("10.1.2.3");
    expect(clientIp(null, "203.0.113.9", trusted)).toBeNull();
  });

  test.each([
    ["1.2.3.4", "1.2.3.4"],
    ["::1", "::1"],
    ["2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"],
    ["[::1]", "::1"],
    ["::ffff:127.0.0.1", "127.0.0.1"],
  ])("normalizes %p to %p", (input, out) => {
    expect(formatIp(parseIp(input)!)).toBe(out);
  });

  test.each(["1.2.3", "1::2::3", "2001:db8::g", "10.0.0.0/33", "x"])("refuses %p", (s) => {
    expect(s.includes("/") ? parseCidr(s) : parseIp(s)).toBeNull();
  });

  test("prefix boundaries", () => {
    const c = parseCidr("192.0.2.128/25")!;
    expect(inCidr(parseIp("192.0.2.128")!, c)).toBe(true);
    expect(inCidr(parseIp("192.0.2.127")!, c)).toBe(false);
    expect(inCidr(parseIp("::1")!, c)).toBe(false);
  });
});

describe("passwords (§9.1)", () => {
  test("length rules count characters, and refuse the username and email", () => {
    expect(passwordProblem("a".repeat(11), {})).toContain("at least 12");
    expect(passwordProblem("é".repeat(12), {})).toBeNull();
    expect(passwordProblem("a".repeat(257), {})).toContain("at most 256");
    expect(passwordProblem("Alice-Example", { username: "alice-example" })).toContain("username");
    expect(passwordProblem("alice@example.com", { email: "Alice@Example.com" })).toContain("email");
  });

  test("hashes with argon2id at m=19 MiB, t=2, p=1", async () => {
    const hash = await new Hasher().hash("correct horse battery");
    expect(hash).toStartWith("$argon2id$v=19$m=19456,t=2,p=1$");
  });

  test("an unknown user verifies against a dummy hash and fails", async () => {
    const h = new Hasher();
    expect(await h.verify("anything at all", null)).toEqual({ ok: false, rehash: false });
  });

  test("an imported bcrypt hash verifies and asks to be rehashed", async () => {
    const bcrypt = await Bun.password.hash("correct horse battery", { algorithm: "bcrypt", cost: 4 });
    expect(await new Hasher().verify("correct horse battery", bcrypt)).toEqual({ ok: true, rehash: true });
  });

  test("the semaphore runs at most two at once", async () => {
    const sem = new Semaphore(2);
    let running = 0;
    let peak = 0;
    await Promise.all(
      Array.from({ length: 8 }, () =>
        sem.run(async () => {
          running++;
          peak = Math.max(peak, running);
          await Bun.sleep(2);
          running--;
        }),
      ),
    );
    expect(peak).toBe(2);
  });

  test("the breach check sends five hex characters and matches a suffix", async () => {
    const sha1 = new Bun.CryptoHasher("sha1").update("password1234").digest("hex").toUpperCase();
    let asked = "";
    const fakeFetch = (async (url: string) => {
      asked = url;
      return new Response(`${sha1.slice(5)}:12\r\n0000000000000000000000000000000000A:0\r\n`);
    }) as unknown as typeof fetch;
    expect(await isBreached("password1234", fakeFetch)).toBe(true);
    expect(asked).toBe(`https://api.pwnedpasswords.com/range/${sha1.slice(0, 5)}`);
    expect(asked).not.toContain(sha1.slice(5));
    expect(await isBreached("another password", fakeFetch)).toBe(false);
  });

  test("a padding entry (count 0) is not a match, and a timeout allows the password", async () => {
    const sha1 = new Bun.CryptoHasher("sha1").update("password1234").digest("hex").toUpperCase();
    const padded = (async () => new Response(`${sha1.slice(5)}:0\r\n`)) as unknown as typeof fetch;
    expect(await isBreached("password1234", padded)).toBe(false);
    const hang = ((_: string, init: RequestInit) =>
      new Promise((_r, reject) => init.signal!.addEventListener("abort", () => reject(new Error("aborted"))))) as unknown as typeof fetch;
    expect(await isBreached("password1234", hang, 20)).toBe(false);
  });
});
