import type { SQL } from "bun";
import { createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from "node:crypto";
import { base64url, sha256, type Encrypter } from "./crypto";
import type { Signer } from "./jwt";

// Token signing keys (docs/DESIGN.md §9.3). A new Ed25519 key is made every
// 90 days, published in JWKS a day before it signs, and kept there for a day
// after it stops. Postgres holds them, private halves encrypted; every copy
// reads the same rows, and rotation runs in whichever copy takes the lock.

export interface PublicJwk {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
  kid: string;
  alg: "EdDSA";
  use: "sig";
}

interface LoadedKey {
  kid: string;
  jwk: PublicJwk;
  publicKey: KeyObject;
  sealed: Buffer;
  privateKey: KeyObject | null;
}

const CACHE_MS = 60_000;

export class KeyStore {
  #published: LoadedKey[] = [];
  #signerKid: string | null = null;
  #loadedAt = 0;
  #loading: Promise<void> | null = null;

  constructor(
    private readonly sql: SQL,
    private readonly crypt: Encrypter,
  ) {}

  // Re-read after CACHE_MS, so a rotation another copy made shows up here
  // within a minute, well inside the day a new key is published early.
  async refresh(force = false): Promise<void> {
    if (!force && Date.now() - this.#loadedAt < CACHE_MS) return;
    this.#loading ??= this.#load().finally(() => {
      this.#loading = null;
    });
    await this.#loading;
  }

  async #load(): Promise<void> {
    const rows: { kid: string; public_jwk: PublicJwk; private_key_enc: Buffer; signs: boolean }[] = await this.sql`
      SELECT kid, public_jwk, private_key_enc,
             sign_from = (SELECT max(sign_from) FROM signing_keys WHERE sign_from <= now()) AS signs
      FROM signing_keys
      WHERE publish_at <= now() AND (retire_at IS NULL OR retire_at > now())
      ORDER BY sign_from`;
    const previous = new Map(this.#published.map((k) => [k.kid, k]));
    this.#published = rows.map((r) => {
      const known = previous.get(r.kid);
      if (known) return known;
      return {
        kid: r.kid,
        jwk: r.public_jwk,
        publicKey: createPublicKey({ key: r.public_jwk, format: "jwk" }),
        sealed: Buffer.from(r.private_key_enc),
        privateKey: null,
      };
    });
    this.#signerKid = rows.find((r) => r.signs)?.kid ?? null;
    this.#loadedAt = Date.now();
  }

  async signer(): Promise<Signer> {
    await this.refresh();
    const key = this.#published.find((k) => k.kid === this.#signerKid);
    if (!key) throw new Error("no signing key");
    key.privateKey ??= createPrivateKey({ key: this.crypt.decrypt(key.sealed, key.kid), format: "der", type: "pkcs8" });
    return { kid: key.kid, privateKey: key.privateKey };
  }

  // Synchronous lookup over the cached set; call refresh() first.
  publicKey(kid: string): KeyObject | undefined {
    return this.#published.find((k) => k.kid === kid)?.publicKey;
  }

  async jwks(): Promise<{ keys: PublicJwk[] }> {
    await this.refresh();
    return { keys: this.#published.map((k) => k.jwk) };
  }
}

// RFC 7638 thumbprint, so a kid names its key and nothing else.
function thumbprint(x: string): string {
  return base64url(sha256(JSON.stringify({ crv: "Ed25519", kty: "OKP", x })));
}

export function generateSigningKey(crypt: Encrypter): { kid: string; jwk: PublicJwk; sealed: Buffer } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const x = (publicKey.export({ format: "jwk" }) as { x: string }).x;
  const kid = thumbprint(x);
  const der = privateKey.export({ format: "der", type: "pkcs8" });
  return {
    kid,
    jwk: { kty: "OKP", crv: "Ed25519", x, kid, alg: "EdDSA", use: "sig" },
    sealed: crypt.encrypt(der, kid),
  };
}

// Brings the keys up to date: a first key that signs at once; a successor
// published a day before the current key turns 90 days old; a retirement
// date a day after each key is superseded; and old keys removed.
export async function rotateKeys(sql: SQL, crypt: Encrypter): Promise<void> {
  await sql.begin(async (tx) => {
    await tx`SELECT pg_advisory_xact_lock(hashtext('auth.keys'))`;
    const [state] = await tx`
      SELECT
        (SELECT max(sign_from) FROM signing_keys WHERE sign_from <= now()) AS current_from,
        (SELECT count(*)::int FROM signing_keys WHERE sign_from > now()) AS pending,
        (SELECT max(sign_from) <= now() - interval '89 days' FROM signing_keys WHERE sign_from <= now()) AS due`;
    const insert = async (delayDays: number) => {
      const key = generateSigningKey(crypt);
      await tx`
        INSERT INTO signing_keys (kid, public_jwk, private_key_enc, publish_at, sign_from)
        VALUES (${key.kid}, ${JSON.stringify(key.jwk)}::text::jsonb, ${key.sealed}, now(),
                now() + make_interval(days => ${delayDays}))`;
    };
    if (state.current_from === null && state.pending === 0) await insert(0);
    else if (state.due && state.pending === 0) await insert(1);
    await tx`
      UPDATE signing_keys k
      SET retire_at = (SELECT min(n.sign_from) FROM signing_keys n WHERE n.sign_from > k.sign_from) + interval '1 day'
      WHERE k.retire_at IS NULL
        AND EXISTS (SELECT 1 FROM signing_keys n WHERE n.sign_from > k.sign_from AND n.sign_from <= now())`;
    await tx`DELETE FROM signing_keys WHERE retire_at < now() - interval '1 day'`;
  });
}
