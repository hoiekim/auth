import { createPublicKey, verify, type JsonWebKeyInput, type KeyObject } from "node:crypto";
import { decodeCbor, decodeCborPrefix, type Cbor } from "./cbor";
import { base64url, fromBase64url, random, sha256 } from "./crypto";

// WebAuthn's relying-party checks (docs/DESIGN.md §9.1; W3C Web Authentication
// Level 3, §7.1 and §7.2), for the one way auth uses it: discoverable
// credentials, user verification required, attestation "none".
//
// Attestation is "none", so nothing here trusts what made a key, and the
// attestation statement is never read: not its signature and not its
// certificates. The browser vouches for the origin, the authenticator data
// for the RP ID and the flags, and at sign-in the signature for both.

// COSE algorithm ids, in the order an authenticator should prefer them.
const EDDSA = -8;
const ES256 = -7;
const RS256 = -257;
const ALGORITHMS = [EDDSA, ES256, RS256] as const;
type Algorithm = (typeof ALGORITHMS)[number];

const TIMEOUT_MS = 60_000;
const MAX_CREDENTIAL_ID = 1023;

const UP = 0x01; // user present
const UV = 0x04; // user verified
const BE = 0x08; // backup eligible
const BS = 0x10; // backed up
const AT = 0x40; // attested credential data follows
const ED = 0x80; // extension data follows

export interface RelyingParty {
  id: string; // the RP ID: the issuer's host
  origin: string; // the issuer's origin
}

export function newChallenge(): string {
  return base64url(random(32));
}

// Where the browser should make the passkey: "platform" is the device's own
// authenticator (Face ID or Touch ID, an Android phone's fingerprint or
// screen lock, Windows Hello), "cross-platform" a security key or another
// device. Only a preference for which prompt the browser shows: attestation
// being "none", nothing in the response proves which kind made the key.
export type Attachment = "platform" | "cross-platform";

export function isAttachment(v: unknown): v is Attachment {
  return v === "platform" || v === "cross-platform";
}

export function creationOptions(
  rp: RelyingParty,
  challenge: string,
  user: { handle: Uint8Array; name: string; displayName: string },
  exclude: Uint8Array[],
  attachment?: Attachment,
) {
  return {
    challenge,
    rp: { name: rp.id, id: rp.id },
    user: { id: base64url(user.handle), name: user.name, displayName: user.displayName },
    pubKeyCredParams: ALGORITHMS.map((alg) => ({ type: "public-key" as const, alg })),
    timeout: TIMEOUT_MS,
    attestation: "none" as const,
    excludeCredentials: exclude.map((id) => ({ type: "public-key" as const, id: base64url(id) })),
    authenticatorSelection: {
      ...(attachment ? { authenticatorAttachment: attachment } : {}),
      residentKey: "required" as const,
      requireResidentKey: true,
      userVerification: "required" as const,
    },
  };
}

// No allowCredentials: a discoverable credential names its own user, so the
// options reveal nothing about who has passkeys.
export function requestOptions(rp: RelyingParty, challenge: string) {
  return { rpId: rp.id, challenge, timeout: TIMEOUT_MS, userVerification: "required" as const };
}

export interface NewCredential {
  id: Buffer;
  publicKey: Buffer; // COSE_Key, as the authenticator encoded it
  signCount: number;
}

// §7.1: a registration response as PublicKeyCredential.toJSON() gives it.
// The credential, or null when any check fails.
export function verifyRegistration(rp: RelyingParty, challenge: string, response: unknown): NewCredential | null {
  try {
    if (!isObject(response) || response.type !== "public-key" || typeof response.id !== "string") return null;
    const r = response.response;
    if (!isObject(r) || typeof r.clientDataJSON !== "string" || typeof r.attestationObject !== "string") return null;
    if (!clientDataMatches(r.clientDataJSON, "webauthn.create", rp, challenge)) return null;

    const attestation = decodeCbor(fromBase64url(r.attestationObject));
    if (!(attestation instanceof Map)) return null;
    const authData = attestation.get("authData");
    if (!(authData instanceof Uint8Array) || typeof attestation.get("fmt") !== "string" || !(attestation.get("attStmt") instanceof Map)) return null;

    const head = authDataHead(rp, authData);
    if (!head || !(head.flags & AT)) return null;
    // aaguid (16 bytes), then the credential id's length and the id.
    let at = 37 + 16;
    if (authData.length < at + 2) return null;
    const idLength = (authData[at]! << 8) | authData[at + 1]!;
    at += 2;
    if (idLength === 0 || idLength > MAX_CREDENTIAL_ID || authData.length < at + idLength) return null;
    const id = Buffer.from(authData.subarray(at, at + idLength));
    at += idLength;
    if (response.id !== base64url(id)) return null;

    const key = decodeCborPrefix(authData.subarray(at));
    const publicKey = Buffer.from(authData.subarray(at, at + key.end));
    at += key.end;
    if (head.flags & ED) {
      if (!(decodeCbor(authData.subarray(at)) instanceof Map)) return null;
    } else if (at !== authData.length) {
      return null;
    }
    if (!coseKey(key.value)) return null;
    return { id, publicKey, signCount: head.signCount };
  } catch {
    return null;
  }
}

// §7.2: an assertion as PublicKeyCredential.toJSON() gives it, checked
// against the stored key. The authenticator's new signature counter, or null
// when any check fails, the counter going backwards included.
export function verifyAssertion(
  rp: RelyingParty,
  challenge: string,
  stored: { publicKey: Uint8Array; signCount: number },
  response: unknown,
): { signCount: number } | null {
  try {
    if (!isObject(response) || response.type !== "public-key") return null;
    const r = response.response;
    if (!isObject(r) || typeof r.clientDataJSON !== "string" || typeof r.authenticatorData !== "string" || typeof r.signature !== "string") return null;
    if (!clientDataMatches(r.clientDataJSON, "webauthn.get", rp, challenge)) return null;

    const authData = fromBase64url(r.authenticatorData);
    const head = authDataHead(rp, authData);
    if (!head) return null;

    const key = coseKey(decodeCbor(stored.publicKey));
    if (!key) return null;
    const signed = Buffer.concat([authData, sha256(fromBase64url(r.clientDataJSON))]);
    const signature = fromBase64url(r.signature);
    // ES256 signatures are DER, node:crypto's default for ECDSA.
    const ok = key.alg === EDDSA ? verify(null, signed, key.key, signature) : verify("sha256", signed, key.key, signature);
    if (!ok) return null;

    // A counter that doesn't move past the stored one means a cloned
    // authenticator. Synced passkeys report 0 every time, which is allowed.
    if ((head.signCount > 0 || stored.signCount > 0) && head.signCount <= stored.signCount) return null;
    return { signCount: head.signCount };
  } catch {
    return null;
  }
}

function clientDataMatches(encoded: string, type: string, rp: RelyingParty, challenge: string): boolean {
  const c: unknown = JSON.parse(fromBase64url(encoded).toString("utf8"));
  if (!isObject(c)) return false;
  // Auth's pages can't be framed (§9.2), so a cross-origin ceremony is never ours.
  return c.type === type && c.challenge === challenge && c.origin === rp.origin && c.crossOrigin !== true;
}

// The fixed 37 bytes every authenticator data starts with: the RP ID's hash,
// the flags and the signature counter.
function authDataHead(rp: RelyingParty, authData: Uint8Array): { flags: number; signCount: number } | null {
  if (authData.length < 37) return null;
  if (!sha256(rp.id).equals(authData.subarray(0, 32))) return null;
  const flags = authData[32]!;
  if (!(flags & UP) || !(flags & UV)) return null;
  if (flags & BS && !(flags & BE)) return null;
  const signCount = new DataView(authData.buffer, authData.byteOffset, authData.byteLength).getUint32(33);
  return { flags, signCount };
}

// A COSE_Key (RFC 9053) for one of ALGORITHMS, with the key type and curve
// that algorithm needs, as a key node:crypto has checked (a P-256 point must
// be on the curve) and can verify with. Null for anything else.
function coseKey(cose: Cbor): { alg: Algorithm; key: KeyObject } | null {
  if (!(cose instanceof Map)) return null;
  const kty = cose.get(1);
  const alg = cose.get(3);
  const crv = cose.get(-1);
  const bytes = (label: number, length?: number) => {
    const v = cose.get(label);
    return v instanceof Uint8Array && (length === undefined || v.length === length) ? base64url(v) : null;
  };
  let found: { alg: Algorithm; jwk: JsonWebKeyInput["key"] } | null = null;
  if (alg === EDDSA && kty === 1 && crv === 6) {
    const x = bytes(-2, 32);
    if (x) found = { alg: EDDSA, jwk: { kty: "OKP", crv: "Ed25519", x } };
  } else if (alg === ES256 && kty === 2 && crv === 1) {
    const x = bytes(-2, 32);
    const y = bytes(-3, 32);
    if (x && y) found = { alg: ES256, jwk: { kty: "EC", crv: "P-256", x, y } };
  } else if (alg === RS256 && kty === 3) {
    const n = bytes(-1);
    const e = bytes(-2);
    if (n && e) found = { alg: RS256, jwk: { kty: "RSA", n, e } };
  }
  if (!found) return null;
  const key = createPublicKey({ key: found.jwk, format: "jwk" });
  // node:crypto takes any RSA exponent, and with e = 1 anyone can sign.
  if (found.alg === RS256) {
    const { modulusLength = 0, publicExponent } = key.asymmetricKeyDetails ?? {};
    if (modulusLength < 2048 || modulusLength > 4096 || publicExponent !== 65537n) return null;
  }
  return { alg: found.alg, key };
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
