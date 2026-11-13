import type { SQL } from "bun";
import type { App } from "./app";
import { base32, fromBase32, random, sha256 } from "./crypto";
import { matchingStep, newTotpSecret, otpauthUri } from "./totp";

// Second factors (docs/DESIGN.md §9.1): TOTP and recovery codes. Passkeys are
// in passkeys.ts.

export interface Factors {
  totp: boolean;
  passkeys: number;
  recoveryCodes: number;
}

export async function factorsOf(sql: SQL, userId: string): Promise<Factors> {
  const [row] = await sql`
    SELECT EXISTS (SELECT 1 FROM totp WHERE user_id = ${userId}) AS totp,
           (SELECT count(*)::int FROM passkeys WHERE user_id = ${userId}) AS passkeys,
           (SELECT count(*)::int FROM recovery_codes WHERE user_id = ${userId} AND used_at IS NULL) AS recovery_codes`;
  return { totp: row.totp, passkeys: row.passkeys, recoveryCodes: row.recovery_codes };
}

// Enrolment is two steps with nothing stored between them: the secret
// travels sealed, bound to the user, and is saved only once a code from it
// is confirmed.
const ENROLL_SECONDS = 15 * 60;

export function startTotpEnrolment(app: App, userId: string, username: string) {
  const secret = newTotpSecret();
  return {
    otpauth_uri: otpauthUri(secret, new URL(app.config.issuer).host, username),
    secret: base32(secret).toUpperCase(),
    enrollment: app.crypt.sealValue("totp-enrol", { u: userId, s: base32(secret) }, ENROLL_SECONDS),
  };
}

// Saves the secret if `code` matches it; the step used becomes last_step, so
// the confirming code can't be replayed at sign-in.
export async function confirmTotpEnrolment(tx: SQL, app: App, userId: string, enrollment: unknown, code: unknown): Promise<boolean> {
  const sealed = app.crypt.openValue<{ u: string; s: string }>("totp-enrol", typeof enrollment === "string" ? enrollment : null);
  if (!sealed || sealed.u !== userId || typeof code !== "string") return false;
  const secret = fromBase32(sealed.s);
  if (!secret) return false;
  const step = matchingStep(secret, code.trim(), Date.now() / 1000, 0);
  if (step === null) return false;
  await tx`
    INSERT INTO totp (user_id, secret_enc, last_step) VALUES (${userId}, ${app.crypt.encrypt(secret, userId)}, ${step})
    ON CONFLICT (user_id) DO UPDATE SET secret_enc = EXCLUDED.secret_enc, last_step = EXCLUDED.last_step, created_at = now()`;
  return true;
}

// A code is accepted once: the update only succeeds while last_step is
// below the code's step, so two requests racing with one code can't both pass.
export async function checkTotp(sql: SQL, app: App, userId: string, code: string): Promise<boolean> {
  const [row] = await sql`SELECT secret_enc, last_step FROM totp WHERE user_id = ${userId}`;
  if (!row) return false;
  let secret: Buffer;
  try {
    secret = app.crypt.decrypt(row.secret_enc, userId);
  } catch {
    return false;
  }
  const step = matchingStep(secret, code.trim(), Date.now() / 1000, Number(row.last_step));
  if (step === null) return false;
  const updated = await sql`UPDATE totp SET last_step = ${step} WHERE user_id = ${userId} AND last_step < ${step} RETURNING 1`;
  return updated.length === 1;
}

export async function removeTotp(sql: SQL, userId: string): Promise<boolean> {
  return (await sql`DELETE FROM totp WHERE user_id = ${userId} RETURNING 1`).length === 1;
}

// 10 codes of 24 base32 characters (120 bits), shown as six groups of four.
// At this length a code is stored and found by its SHA-256, like an app
// password (§9.1).
export async function newRecoveryCodes(sql: SQL, userId: string): Promise<string[]> {
  const codes = Array.from({ length: 10 }, () => base32(random(15)));
  await sql`DELETE FROM recovery_codes WHERE user_id = ${userId}`;
  for (const code of codes) await sql`INSERT INTO recovery_codes (user_id, code_hash) VALUES (${userId}, ${sha256(code)})`;
  return codes.map((c) => c.match(/.{4}/g)!.join("-"));
}

export function canonicalRecoveryCode(input: string): string | null {
  const clean = input.toLowerCase().replace(/[\s-]/g, "");
  return /^[a-z2-7]{24}$/.test(clean) ? clean : null;
}

// One indexed lookup scoped to the account, the same cost whether or not the
// account exists or has codes left. Marks the code used; true if it was
// unused.
export async function useRecoveryCode(sql: SQL, userId: string | null, input: string): Promise<boolean> {
  const code = canonicalRecoveryCode(input);
  const rows = await sql`
    UPDATE recovery_codes SET used_at = now()
    WHERE user_id = ${userId ?? ""} AND code_hash = ${sha256(code ?? input)} AND used_at IS NULL
    RETURNING 1`;
  return code !== null && rows.length === 1;
}

// A sign-in's second factor: a TOTP code or, failing that, a recovery code.
export async function checkSecondFactor(sql: SQL, app: App, userId: string, input: string): Promise<"otp" | "recovery" | null> {
  const value = input.trim();
  if (/^\d{6}$/.test(value)) return (await checkTotp(sql, app, userId, value)) ? "otp" : null;
  return (await useRecoveryCode(sql, userId, value)) ? "recovery" : null;
}
