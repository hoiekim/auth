import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import type { SQL } from "bun";
import type { App } from "./app";
import { base64url, fromBase64url, newId } from "./crypto";
import { once } from "./throttle";

// Passkeys (docs/DESIGN.md §9.1). The RP ID is the issuer's host, not its
// parent domain, so a sibling subdomain can never ask for an assertion.
// User verification is required, so a passkey is two factors by itself.
// Attestation is "none". The challenge travels sealed and is accepted once.

const CHALLENGE_SECONDS = 5 * 60;

function rp(app: App) {
  return { id: new URL(app.config.issuer).hostname, origin: app.config.issuer };
}

export interface PasskeyRow {
  id: string;
  name: string;
  created_at: Date;
  last_used_at: Date | null;
}

export function passkeyJson(p: PasskeyRow) {
  return { id: p.id, name: p.name, created_at: p.created_at.toISOString(), last_used_at: p.last_used_at?.toISOString() ?? null };
}

export async function listPasskeys(sql: SQL, userId: string): Promise<PasskeyRow[]> {
  return (await sql`SELECT id, name, created_at, last_used_at FROM passkeys WHERE user_id = ${userId} ORDER BY created_at`) as PasskeyRow[];
}

export async function registrationOptions(app: App, user: { id: string; username: string; name: string }) {
  const existing: { credential_id: Buffer }[] = await app.sql`SELECT credential_id FROM passkeys WHERE user_id = ${user.id}`;
  const options = await generateRegistrationOptions({
    rpName: rp(app).id,
    rpID: rp(app).id,
    userName: user.username,
    userDisplayName: user.name || user.username,
    userID: new TextEncoder().encode(user.id),
    attestationType: "none",
    excludeCredentials: existing.map((e) => ({ id: base64url(e.credential_id) })),
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
  });
  const registration = app.crypt.sealValue("passkey-reg", { u: user.id, c: options.challenge }, CHALLENGE_SECONDS);
  return { options, registration };
}

export async function finishRegistration(
  tx: SQL,
  app: App,
  userId: string,
  registration: unknown,
  response: unknown,
  name: string,
): Promise<string | null> {
  const sealed = app.crypt.openValue<{ u: string; c: string }>("passkey-reg", typeof registration === "string" ? registration : null);
  if (!sealed || sealed.u !== userId || !isObject(response)) return null;
  if (!(await once(tx, `once:webauthn:${sealed.c}`))) return null;
  let verified;
  try {
    verified = await verifyRegistrationResponse({
      response: response as unknown as RegistrationResponseJSON,
      expectedChallenge: sealed.c,
      expectedOrigin: rp(app).origin,
      expectedRPID: rp(app).id,
      requireUserVerification: true,
    });
  } catch {
    return null;
  }
  if (!verified.verified) return null;
  const cred = verified.registrationInfo.credential;
  const id = newId("pk");
  const rows = await tx`
    INSERT INTO passkeys (id, user_id, credential_id, public_key, sign_count, name)
    VALUES (${id}, ${userId}, ${fromBase64url(cred.id)}, ${Buffer.from(cred.publicKey)}, ${cred.counter}, ${name})
    ON CONFLICT (credential_id) DO NOTHING RETURNING id`;
  return rows.length === 1 ? id : null;
}

// Options for a discoverable-credential sign-in: no username, so nothing
// about who has passkeys is revealed. The sealed challenge goes in a cookie.
export async function authenticationOptions(app: App) {
  const options = await generateAuthenticationOptions({ rpID: rp(app).id, userVerification: "required" });
  return { options, state: app.crypt.sealValue("passkey-auth", { c: options.challenge }, CHALLENGE_SECONDS) };
}

// The user a passkey assertion proves, or null. Updates the signature
// counter, which the library refuses to see go backwards.
export async function finishAuthentication(app: App, state: string | null, response: unknown): Promise<string | null> {
  const sealed = app.crypt.openValue<{ c: string }>("passkey-auth", state);
  if (!sealed || !isObject(response) || typeof response.id !== "string") return null;
  const [row] = await app.sql`
    SELECT p.id, p.user_id, p.credential_id, p.public_key, p.sign_count
    FROM passkeys p JOIN users u ON u.id = p.user_id
    WHERE p.credential_id = ${fromBase64url(response.id)} AND u.disabled_at IS NULL AND u.kind = 'person'`;
  if (!row) return null;
  if (!(await once(app.sql, `once:webauthn:${sealed.c}`))) return null;
  let verified;
  try {
    verified = await verifyAuthenticationResponse({
      response: response as unknown as AuthenticationResponseJSON,
      expectedChallenge: sealed.c,
      expectedOrigin: rp(app).origin,
      expectedRPID: rp(app).id,
      credential: { id: base64url(row.credential_id), publicKey: new Uint8Array(row.public_key), counter: Number(row.sign_count) },
      requireUserVerification: true,
    });
  } catch {
    return null;
  }
  if (!verified.verified) return null;
  await app.sql`
    UPDATE passkeys SET sign_count = ${verified.authenticationInfo.newCounter}, last_used_at = now() WHERE id = ${row.id}`;
  return row.user_id;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
