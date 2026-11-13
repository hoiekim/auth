import type { SQL } from "bun";
import { randomToken, sha256 } from "./crypto";
import { hit, type Verdict } from "./throttle";

// One-time tokens (docs/DESIGN.md §7.3): reset 30 minutes, email
// verification 24 hours, activation 14 days like an invitation. Single use,
// stored as SHA-256.

export type Purpose = "reset" | "verify_email" | "activate";

export const LIFETIME_SECONDS: Record<Purpose, number> = {
  reset: 30 * 60,
  verify_email: 24 * 60 * 60,
  activate: 14 * 24 * 60 * 60,
};

export async function issueToken(tx: SQL, purpose: Purpose, userId: string, email: string | null): Promise<string> {
  const token = randomToken();
  await tx`
    INSERT INTO one_time_tokens (token_hash, purpose, user_id, email, expires_at)
    VALUES (${sha256(token)}, ${purpose}, ${userId}, ${email}, now() + make_interval(secs => ${LIFETIME_SECONDS[purpose]}))`;
  return token;
}

export interface TokenRow {
  user_id: string;
  email: string | null;
}

function hashOf(token: string | null): Buffer {
  return sha256(token && token.length <= 128 ? token : "");
}

// A live token without using it up: to show the form it leads to.
export async function peekToken(sql: SQL, purpose: Purpose, token: string | null): Promise<TokenRow | null> {
  const [row] = await sql`
    SELECT user_id, email FROM one_time_tokens
    WHERE token_hash = ${hashOf(token)} AND purpose = ${purpose} AND used_at IS NULL AND expires_at > now()`;
  return (row as TokenRow) ?? null;
}

// Uses a token up, once, however many requests race for it.
export async function consumeToken(tx: SQL, purpose: Purpose, token: string | null): Promise<TokenRow | null> {
  const [row] = await tx`
    UPDATE one_time_tokens SET used_at = now()
    WHERE token_hash = ${hashOf(token)} AND purpose = ${purpose} AND used_at IS NULL AND expires_at > now()
    RETURNING user_id, email`;
  return (row as TokenRow) ?? null;
}

// Reset, invite and sign-up emails: 3 an hour per address, 10 an hour per
// sender (§9.4), counted whether or not the address has an account.
export async function emailAllowed(sql: SQL, address: string, sender: string): Promise<Verdict> {
  const perAddress = await hit(sql, `mail:to:${address.toLowerCase()}`, 3, 3600);
  const perSender = await hit(sql, `mail:from:${sender}`, 10, 3600);
  if (!perAddress.allowed) return perAddress;
  return perSender;
}
