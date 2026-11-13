import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";

// Encodings, hashes, ids and encryption at rest (docs/DESIGN.md §7.3, §9.3).

export function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export function fromBase64url(text: string): Buffer {
  return Buffer.from(text, "base64url");
}

export function sha256(data: string | Uint8Array): Buffer {
  return createHash("sha256").update(data).digest();
}

export function random(bytes: number): Buffer {
  return randomBytes(bytes);
}

// 32 random bytes, base64url: codes, cookies, one-time and refresh tokens.
export function randomToken(): string {
  return base64url(random(32));
}

// Equal-length digests, so neither the length nor the content of either side
// leaks through the comparison's timing.
export function safeEqual(a: string, b: string): boolean {
  return timingSafeEqual(sha256(a), sha256(b));
}

const RFC4648 = "abcdefghijklmnopqrstuvwxyz234567";

// RFC 4648 base32, lowercase, no padding.
export function base32(bytes: Uint8Array): string {
  let out = "";
  let bits = 0;
  let value = 0;
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += RFC4648[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += RFC4648[(value << (5 - bits)) & 31];
  return out;
}

export function fromBase32(text: string): Buffer | null {
  const clean = text.toLowerCase().replace(/=+$/, "");
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const ch of clean) {
    const i = RFC4648.indexOf(ch);
    if (i < 0) return null;
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

// Crockford's alphabet, lowercase: ids read aloud or typed never mix up 0/o
// or 1/l/i.
const CROCKFORD = "0123456789abcdefghjkmnpqrstvwxyz";

export type IdPrefix = "usr" | "ses" | "apw" | "key" | "inv" | "evt" | "pk";

// `<prefix>_` and 26 characters encoding a UUIDv7, so ids sort by creation.
export function newId(prefix: IdPrefix): string {
  const bytes = Bun.randomUUIDv7("buffer");
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = "";
  for (let i = 0; i < 26; i++) {
    out = CROCKFORD[Number(n & 31n)] + out;
    n >>= 5n;
  }
  return `${prefix}_${out}`;
}

export const ID_PATTERN = /^[a-z]{2,3}_[0-9a-hjkmnp-tv-z]{26}$/;

// AES-256-GCM with a key version prefix and the row id as additional data, so
// a ciphertext moved to another row fails to decrypt.
const VERSION = Buffer.from("v1:");

export class Encrypter {
  readonly #key: Buffer;
  readonly #subkeys = new Map<string, Buffer>();

  constructor(key: Buffer) {
    if (key.length !== 32) throw new Error("the encryption key must be 32 bytes");
    this.#key = key;
  }

  encrypt(plaintext: Uint8Array, aad: string): Buffer {
    return seal(this.#key, plaintext, aad);
  }

  decrypt(sealed: Uint8Array, aad: string): Buffer {
    return open(this.#key, sealed, aad);
  }

  // A key for one purpose, derived so that no two purposes share key material
  // with each other or with encryption at rest.
  subkey(purpose: string): Buffer {
    let k = this.#subkeys.get(purpose);
    if (!k) {
      k = Buffer.from(hkdfSync("sha256", this.#key, Buffer.alloc(0), `auth:${purpose}`, 32));
      this.#subkeys.set(purpose, k);
    }
    return k;
  }

  hmac(purpose: string, data: string): string {
    return createHmac("sha256", this.subkey(purpose)).update(data).digest("base64url");
  }

  // A short-lived, tamper-proof, confidential value handed to the browser or
  // a client and read back later: a pending second factor, a TOTP enrolment,
  // a WebAuthn challenge. `expiresAt` is in milliseconds.
  sealValue(purpose: string, value: unknown, ttlSeconds: number): string {
    const body = JSON.stringify({ v: value, exp: Date.now() + ttlSeconds * 1000 });
    return base64url(seal(this.subkey(`sealed:${purpose}`), Buffer.from(body), purpose));
  }

  openValue<T>(purpose: string, token: string | null | undefined): T | null {
    if (!token || token.length > 8192) return null;
    try {
      const body = JSON.parse(open(this.subkey(`sealed:${purpose}`), fromBase64url(token), purpose).toString("utf8"));
      if (typeof body !== "object" || body === null || typeof body.exp !== "number" || body.exp < Date.now()) return null;
      return body.v as T;
    } catch {
      return null;
    }
  }
}

function seal(key: Buffer, plaintext: Uint8Array, aad: string): Buffer {
  const iv = random(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(aad));
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([VERSION, iv, body, cipher.getAuthTag()]);
}

function open(key: Buffer, sealed: Uint8Array, aad: string): Buffer {
  const buf = Buffer.from(sealed);
  if (buf.length < VERSION.length + 12 + 16 || !buf.subarray(0, VERSION.length).equals(VERSION)) {
    throw new Error("unknown ciphertext version");
  }
  const iv = buf.subarray(VERSION.length, VERSION.length + 12);
  const tag = buf.subarray(buf.length - 16);
  const body = buf.subarray(VERSION.length + 12, buf.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]);
}
