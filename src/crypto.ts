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

// AES-256-GCM with the key's version as a prefix and the row id as
// additional data, so a ciphertext moved to another row fails to decrypt,
// and the key can be rotated (docs/DESIGN.md §9.3): new data is written
// under the current key, and every configured key still reads what it wrote.

export interface EncryptionKey {
  version: number;
  key: Buffer;
}

const VERSION_PREFIX = /^v(\d{1,4}):/;

export class Encrypter {
  readonly #current: EncryptionKey;
  readonly #keys: Map<number, Buffer>;
  readonly #subkeys = new Map<string, Buffer>();

  // `current` encrypts; `others` only decrypt. A bare key is version 1.
  constructor(current: EncryptionKey | Buffer, others: EncryptionKey[] = []) {
    this.#current = Buffer.isBuffer(current) ? { version: 1, key: current } : current;
    this.#keys = new Map();
    for (const k of [this.#current, ...others]) {
      if (k.key.length !== 32) throw new Error("an encryption key must be 32 bytes");
      if (!Number.isInteger(k.version) || k.version < 1 || k.version > 9999) throw new Error("a key version is 1 to 9999");
      if (this.#keys.has(k.version)) throw new Error(`two encryption keys have version ${k.version}`);
      this.#keys.set(k.version, k.key);
    }
  }

  get version(): number {
    return this.#current.version;
  }

  get versions(): number[] {
    return [...this.#keys.keys()];
  }

  // The key version a ciphertext was written under, or null when it has none.
  static versionOf(sealed: Uint8Array): number | null {
    const m = VERSION_PREFIX.exec(Buffer.from(sealed.subarray(0, 6)).toString("latin1"));
    return m?.[1] ? Number(m[1]) : null;
  }

  encrypt(plaintext: Uint8Array, aad: string): Buffer {
    return seal(this.#current.key, this.#current.version, plaintext, aad);
  }

  decrypt(sealed: Uint8Array, aad: string): Buffer {
    const version = Encrypter.versionOf(sealed);
    const key = version === null ? undefined : this.#keys.get(version);
    if (!key || version === null) throw new Error("no configured key for this ciphertext's version");
    return open(key, sealed, aad);
  }

  // A key for one purpose, derived so that no two purposes share key material
  // with each other or with encryption at rest.
  #subkey(version: number, purpose: string): Buffer {
    const id = `${version}:${purpose}`;
    let k = this.#subkeys.get(id);
    if (!k) {
      k = Buffer.from(hkdfSync("sha256", this.#keys.get(version)!, Buffer.alloc(0), `auth:${purpose}`, 32));
      this.#subkeys.set(id, k);
    }
    return k;
  }

  hmac(purpose: string, data: string): string {
    return createHmac("sha256", this.#subkey(this.#current.version, purpose)).update(data).digest("base64url");
  }

  // Whether `candidate` is the HMAC of `data` under any configured key, so a
  // value issued before a rotation still holds after it.
  hmacMatches(purpose: string, data: string, candidate: string): boolean {
    let ok = false;
    for (const version of this.#keys.keys()) {
      const expected = createHmac("sha256", this.#subkey(version, purpose)).update(data).digest("base64url");
      if (safeEqual(candidate, expected)) ok = true;
    }
    return ok;
  }

  // A short-lived, tamper-proof, confidential value handed to the browser or
  // a client and read back later: a pending second factor, a TOTP enrolment,
  // a WebAuthn challenge.
  sealValue(purpose: string, value: unknown, ttlSeconds: number): string {
    const body = JSON.stringify({ v: value, exp: Date.now() + ttlSeconds * 1000 });
    const version = this.#current.version;
    return base64url(seal(this.#subkey(version, `sealed:${purpose}`), version, Buffer.from(body), purpose));
  }

  openValue<T>(purpose: string, token: string | null | undefined): T | null {
    if (!token || token.length > 8192) return null;
    try {
      const sealed = fromBase64url(token);
      const version = Encrypter.versionOf(sealed);
      if (version === null || !this.#keys.has(version)) return null;
      const body = JSON.parse(open(this.#subkey(version, `sealed:${purpose}`), sealed, purpose).toString("utf8"));
      if (typeof body !== "object" || body === null || typeof body.exp !== "number" || body.exp < Date.now()) return null;
      return body.v as T;
    } catch {
      return null;
    }
  }
}

function seal(key: Buffer, version: number, plaintext: Uint8Array, aad: string): Buffer {
  const iv = random(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(aad));
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([Buffer.from(`v${version}:`), iv, body, cipher.getAuthTag()]);
}

// The caller chose `key` by the version in this same prefix.
function open(key: Buffer, sealed: Uint8Array, aad: string): Buffer {
  const buf = Buffer.from(sealed);
  const prefix = VERSION_PREFIX.exec(buf.subarray(0, 6).toString("latin1"))?.[0].length ?? 0;
  if (prefix === 0 || buf.length < prefix + 12 + 16) throw new Error("unknown ciphertext version");
  const iv = buf.subarray(prefix, prefix + 12);
  const tag = buf.subarray(buf.length - 16);
  const body = buf.subarray(prefix + 12, buf.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]);
}
