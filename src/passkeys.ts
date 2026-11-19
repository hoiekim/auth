import type { SQL } from "bun";
import type { App } from "./app";
import { fromBase64url, newId } from "./crypto";
import { once } from "./throttle";
import { creationOptions, newChallenge, requestOptions, verifyAssertion, verifyRegistration, type Attachment, type RelyingParty } from "./webauthn";

// Passkeys (docs/DESIGN.md §9.1). The RP ID is the issuer's host, not its
// parent domain, so a sibling subdomain can never ask for an assertion.
// User verification is required, so a passkey is two factors by itself.
// Attestation is "none". The challenge travels sealed and is accepted once.

const CHALLENGE_SECONDS = 5 * 60;

function rp(app: App): RelyingParty {
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

export async function registrationOptions(app: App, user: { id: string; username: string; name: string }, attachment?: Attachment) {
  const existing: { credential_id: Buffer }[] = await app.sql`SELECT credential_id FROM passkeys WHERE user_id = ${user.id}`;
  const challenge = newChallenge();
  const options = creationOptions(
    rp(app),
    challenge,
    { handle: new TextEncoder().encode(user.id), name: user.username, displayName: user.name || user.username },
    existing.map((e) => e.credential_id),
    attachment,
  );
  const registration = app.crypt.sealValue("passkey-reg", { u: user.id, c: challenge }, CHALLENGE_SECONDS);
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
  const cred = verifyRegistration(rp(app), sealed.c, response);
  if (!cred) return null;
  const id = newId("pk");
  const rows = await tx`
    INSERT INTO passkeys (id, user_id, credential_id, public_key, sign_count, name)
    VALUES (${id}, ${userId}, ${cred.id}, ${cred.publicKey}, ${cred.signCount}, ${name})
    ON CONFLICT (credential_id) DO NOTHING RETURNING id`;
  return rows.length === 1 ? id : null;
}

// Options for a discoverable-credential sign-in: no username, so nothing
// about who has passkeys is revealed. The sealed challenge goes in a cookie.
export function authenticationOptions(app: App) {
  const challenge = newChallenge();
  return { options: requestOptions(rp(app), challenge), state: app.crypt.sealValue("passkey-auth", { c: challenge }, CHALLENGE_SECONDS) };
}

// The user a passkey assertion proves, or null. Updates the signature
// counter, which verifyAssertion refuses to see go backwards.
export async function finishAuthentication(app: App, state: string | null, response: unknown): Promise<string | null> {
  const sealed = app.crypt.openValue<{ c: string }>("passkey-auth", state);
  if (!sealed || !isObject(response) || typeof response.id !== "string") return null;
  const [row] = await app.sql`
    SELECT p.id, p.user_id, p.credential_id, p.public_key, p.sign_count
    FROM passkeys p JOIN users u ON u.id = p.user_id
    WHERE p.credential_id = ${fromBase64url(response.id)} AND u.disabled_at IS NULL AND u.kind = 'person'`;
  if (!row) return null;
  if (!(await once(app.sql, `once:webauthn:${sealed.c}`))) return null;
  const verified = verifyAssertion(rp(app), sealed.c, { publicKey: row.public_key, signCount: Number(row.sign_count) }, response);
  if (!verified) return null;
  await app.sql`
    UPDATE passkeys SET sign_count = ${verified.signCount}, last_used_at = now() WHERE id = ${row.id}`;
  return row.user_id;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
