import type { SQL } from "bun";
import type { App } from "./app";
import { audit } from "./audit";
import { newId } from "./crypto";
import { emitAll } from "./events";
import { HttpError } from "./http";
import { isEmailAddress } from "./mail";
import { endUserSessions } from "./sessions";

// Users (docs/DESIGN.md §6): a person or a bot, with an immutable username
// that a service may use as a DNS label or an address.

export const USERNAME = /^[a-z][a-z0-9-]{1,30}[a-z0-9]$/;
export const MAX_NAME = 200;

export interface UserRow {
  id: string;
  username: string;
  name: string;
  email: string | null;
  email_verified_at: Date | null;
  kind: "person" | "bot";
  owner_id: string | null;
  password_hash: string | null;
  disabled_at: Date | null;
  created_at: Date;
}

export function userJson(u: UserRow) {
  return {
    id: u.id,
    username: u.username,
    name: u.name,
    email: u.email,
    email_verified: u.email_verified_at !== null,
    kind: u.kind,
    owner_id: u.owner_id,
    disabled: u.disabled_at !== null,
    created_at: u.created_at.toISOString(),
  };
}

export function checkUsername(value: unknown): string {
  if (typeof value !== "string" || !USERNAME.test(value)) {
    throw new HttpError(400, "invalid_request", "A username is 3 to 32 characters: a–z, 0–9 and '-', starting with a letter and not ending with '-'.");
  }
  return value;
}

export function checkName(value: unknown): string {
  if (value === undefined || value === null) return "";
  if (typeof value !== "string" || [...value].length > MAX_NAME || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new HttpError(400, "invalid_request", `A name is at most ${MAX_NAME} characters, with no control characters.`);
  }
  return value.trim();
}

export function checkEmail(value: unknown): string {
  if (typeof value !== "string" || !isEmailAddress(value.trim())) throw new HttpError(400, "invalid_request", "That is not an email address.");
  return value.trim();
}

export function isUniqueViolation(e: unknown, constraint?: string): boolean {
  const err = e as { errno?: string; constraint?: string };
  return err?.errno === "23505" && (constraint === undefined || err.constraint === constraint);
}

export async function findUser(sql: SQL, id: string): Promise<UserRow | null> {
  const [row] = await sql`SELECT * FROM users WHERE id = ${id}`;
  return (row as UserRow) ?? null;
}

// By username, or by email ignoring case, as typed into a sign-in form.
export async function findUserByLogin(sql: SQL, login: string): Promise<UserRow | null> {
  const value = login.trim();
  if (value.length === 0 || value.length > 254) return null;
  const [row] = value.includes("@")
    ? await sql`SELECT * FROM users WHERE lower(email) = lower(${value})`
    : await sql`SELECT * FROM users WHERE username = ${value.toLowerCase()}`;
  return (row as UserRow) ?? null;
}

export interface NewUser {
  username: string;
  name: string;
  email: string | null;
  emailVerified: boolean;
  kind: "person" | "bot";
  ownerId: string | null;
  passwordHash: string | null;
}

// A conflict aborts the caller's transaction, which then rolls back whole.
export async function insertUser(tx: SQL, u: NewUser): Promise<string> {
  const id = newId("usr");
  try {
    await tx`
      INSERT INTO users (id, username, name, email, email_verified_at, kind, owner_id, password_hash)
      VALUES (${id}, ${u.username}, ${u.name}, ${u.email}, ${u.emailVerified ? new Date() : null}, ${u.kind}, ${u.ownerId}, ${u.passwordHash})`;
  } catch (e) {
    if (isUniqueViolation(e, "users_username_key")) throw new HttpError(409, "conflict", "That username is taken.");
    if (isUniqueViolation(e, "users_email")) throw new HttpError(409, "conflict", "Another account uses that email address.");
    throw e;
  }
  return id;
}

// Disabling overrides every access row without deleting it (§6 rule 5):
// sessions end, and refreshes, app passwords and keys stop because each
// check reads disabled_at. Re-enabling restores the access they had.
export async function setDisabled(tx: SQL, app: App, user: UserRow, disabled: boolean, actor: string | null, ip: string | null): Promise<void> {
  if (disabled === (user.disabled_at !== null)) return;
  await tx`UPDATE users SET disabled_at = ${disabled ? new Date() : null}, updated_at = now() WHERE id = ${user.id}`;
  if (disabled) {
    await endUserSessions(tx, app, user.id);
    await emitAll(tx, app, "user.disabled", { sub: user.id });
  }
  await audit(tx, { actor, action: disabled ? "user.disable" : "user.enable", userId: user.id, ip });
}

// Erases a user (A4, U14). Every app is told, so it can delete or anonymise
// its own data. A person who owns bots keeps them from being orphaned: they
// are deleted or reassigned first.
export async function deleteUser(tx: SQL, app: App, user: UserRow, actor: string | null, ip: string | null): Promise<void> {
  const [bots] = await tx`SELECT count(*)::int AS n FROM users WHERE owner_id = ${user.id}`;
  if (bots.n > 0) throw new HttpError(409, "conflict", "This user owns bot users; delete them or give them another owner first.");
  await endUserSessions(tx, app, user.id);
  await emitAll(tx, app, "user.deleted", { sub: user.id });
  await tx`DELETE FROM users WHERE id = ${user.id}`;
  await audit(tx, { actor, action: "user.delete", userId: user.id, ip, detail: { username: user.username } });
}
