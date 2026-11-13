import { sign, verify, type KeyObject } from "node:crypto";
import { base64url, fromBase64url } from "./crypto";

// JWTs signed with Ed25519 (docs/DESIGN.md §7.3). `alg` is EdDSA by
// construction: a verifier never reads it from the token to decide anything,
// and refuses a token whose header names another.

export type JwtType = "at+jwt" | "JWT" | "secevent+jwt";

export interface Signer {
  kid: string;
  privateKey: KeyObject;
}

export function signJwt(typ: JwtType, payload: Record<string, unknown>, key: Signer): string {
  const header = base64url(Buffer.from(JSON.stringify({ alg: "EdDSA", typ, kid: key.kid })));
  const body = base64url(Buffer.from(JSON.stringify(payload)));
  const signature = sign(null, Buffer.from(`${header}.${body}`), key.privateKey);
  return `${header}.${body}.${base64url(signature)}`;
}

export interface VerifyOptions {
  typ: JwtType;
  issuer: string;
  // Accepted audiences; omit to accept any (the caller then checks it).
  audience?: string[];
  nowSeconds: number;
  leewaySeconds?: number;
}

// The payload when every check passes, else null. `keyFor` returns only keys
// auth itself published, so `kid` merely selects among them.
export function verifyJwt(
  token: string,
  keyFor: (kid: string) => KeyObject | undefined,
  opts: VerifyOptions,
): Record<string, unknown> | null {
  if (token.length > 8192) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts as [string, string, string];
  let header: unknown;
  let payload: unknown;
  try {
    header = JSON.parse(fromBase64url(h).toString("utf8"));
    payload = JSON.parse(fromBase64url(p).toString("utf8"));
  } catch {
    return null;
  }
  if (!isRecord(header) || !isRecord(payload)) return null;
  if (header.alg !== "EdDSA" || header.typ !== opts.typ || typeof header.kid !== "string" || "crit" in header) return null;
  const key = keyFor(header.kid);
  if (!key) return null;
  if (!verify(null, Buffer.from(`${h}.${p}`), key, fromBase64url(s))) return null;
  const leeway = opts.leewaySeconds ?? 30;
  if (payload.iss !== opts.issuer) return null;
  if (opts.audience && !(typeof payload.aud === "string" && opts.audience.includes(payload.aud))) return null;
  if (typeof payload.exp !== "number" || payload.exp + leeway < opts.nowSeconds) return null;
  if (typeof payload.iat !== "number" || payload.iat - leeway > opts.nowSeconds) return null;
  return payload;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
