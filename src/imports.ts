import { putAccess } from "./access";
import type { App } from "./app";
import { audit } from "./audit";
import { fromBase64url, ID_PATTERN, newId } from "./crypto";
import { isEmailAddress } from "./mail";
import type { Service } from "./services";
import { issueToken } from "./tokens";
import { transaction } from "./tx";
import { insertUser, MAX_NAME, USERNAME } from "./users";

// Moving an app's users and API keys into auth (docs/DESIGN.md §12.5, §13).
// One JSON object per line. Every line is checked before anything is
// written, every problem is listed by line number, and no value that can be
// a secret or an address is echoed. Then all rows are written in one
// transaction, or none.

const ACTOR = "host-cli";

type Json = Record<string, unknown>;

interface Line {
  n: number;
  value: Json;
}

// Enough for a deployment's users in one go, and few enough that each check
// stays one query and the whole run stays small beside the server in its
// container (§10). Larger imports are split into several files.
export const MAX_LINES = 10_000;

// Blank lines are skipped; a line that isn't a JSON object is a problem.
function parseLines(text: string, problems: string[]): Line[] {
  const out: Line[] = [];
  const raws = text.split(/\r?\n/);
  if (raws.filter((r) => r.trim() !== "").length > MAX_LINES) {
    problems.push(`the input has more than ${MAX_LINES} lines; split it`);
    return out;
  }
  raws.forEach((raw, i) => {
    if (raw.trim() === "") return;
    let value: unknown;
    try {
      value = JSON.parse(raw);
    } catch {
      problems.push(`line ${i + 1}: not valid JSON`);
      return;
    }
    if (typeof value !== "object" || value === null || Array.isArray(value)) problems.push(`line ${i + 1}: not a JSON object`);
    else out.push({ n: i + 1, value: value as Json });
  });
  if (out.length === 0 && problems.length === 0) problems.push("the input has no lines");
  return out;
}

function unknownFields(line: Line, allowed: string[], p: (msg: string) => void): void {
  for (const key of Object.keys(line.value)) if (!allowed.includes(key)) p(`unknown field "${key.slice(0, 40)}"`);
}

// RFC 3339 with a zone, as the API takes, and a real calendar date: JS's
// Date.parse rolls 30 February over into March, where Postgres refuses it.
function timestamp(value: unknown): string | null | undefined {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") return undefined;
  const m = /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d)(?::(\d\d)(?:\.\d{1,6})?)?(?:Z|[+-](\d\d):(\d\d))$/.exec(value);
  if (!m) return undefined;
  const [y, mo, d, h, mi, s, oh, om] = m.slice(1).map((x) => (x === undefined ? 0 : Number(x))) as number[];
  const days = new Date(Date.UTC(y!, mo!, 0)).getUTCDate();
  const ok = y! >= 1 && mo! >= 1 && mo! <= 12 && d! >= 1 && d! <= days && h! <= 23 && mi! <= 59 && s! <= 59 && oh! <= 15 && om! <= 59;
  return ok ? value : undefined;
}

// The PHC strings Bun.password.verify reads: argon2 and bcrypt (§13).
const ARGON2 = /^\$argon2(?:id|i|d)\$v=\d+\$m=(\d+),t=(\d+),p=(\d+)\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/;
const BCRYPT = /^\$2[aby]\$(\d{2})\$[./A-Za-z0-9]{53}$/;

// An imported hash is verified at its own cost until the first sign-in
// rehashes it, behind the same two hashing slots. More memory than §9.1's
// 19 MiB would break the 38 MiB budget those slots keep (§10), so such a
// hash is refused and its user takes an activation link instead; time is
// bounded so two attempts can't hold both slots for long.
export const MAX_ARGON2 = { memoryKiB: 19456, time: 3, parallelism: 4 };
export const MAX_BCRYPT_COST = 12;

function hashProblem(hash: string): string | null {
  const a = ARGON2.exec(hash);
  if (a) {
    const [m, t, p] = [Number(a[1]), Number(a[2]), Number(a[3])];
    if (m > MAX_ARGON2.memoryKiB || t > MAX_ARGON2.time || p > MAX_ARGON2.parallelism) {
      return `password_hash costs more than this service verifies (argon2 at most m=${MAX_ARGON2.memoryKiB}, t=${MAX_ARGON2.time}, p=${MAX_ARGON2.parallelism}); leave it out and the user gets an activation link`;
    }
    return null;
  }
  const b = BCRYPT.exec(hash);
  if (b) {
    return Number(b[1]) > MAX_BCRYPT_COST
      ? `password_hash costs more than this service verifies (bcrypt cost at most ${MAX_BCRYPT_COST}); leave it out and the user gets an activation link`
      : null;
  }
  return "password_hash is not an argon2 or bcrypt PHC string";
}

export interface ImportedUser {
  id: string;
  username: string;
  email: string;
  // An activation link's token, for users imported without a password.
  activation: string | null;
}

export interface ImportResult<T> {
  problems: string[];
  rows: T[];
}

export async function importUsers(app: App, text: string, opts: { dryRun: boolean }): Promise<ImportResult<ImportedUser>> {
  const problems: string[] = [];
  const lines = parseLines(text, problems);
  const usernames = new Map<string, number>();
  const emails = new Map<string, number>();
  const checked: { username: string; email: string; name: string; verified: boolean; hash: string | null; grants: { service: Service; role: string }[] }[] = [];

  for (const line of lines) {
    const p = (msg: string) => problems.push(`line ${line.n}: ${msg}`);
    const v = line.value;
    unknownFields(line, ["username", "email", "name", "email_verified", "password_hash", "access"], p);
    const username = typeof v.username === "string" ? v.username : "";
    if (!USERNAME.test(username)) p("username must be 3 to 32 characters: a–z, 0–9 and '-', starting with a letter and not ending with '-'");
    else if (usernames.has(username)) p(`username is also on line ${usernames.get(username)}`);
    else usernames.set(username, line.n);
    const email = typeof v.email === "string" ? v.email.trim() : "";
    if (!isEmailAddress(email)) p("email is not an email address");
    else if (emails.has(email.toLowerCase())) p(`email is also on line ${emails.get(email.toLowerCase())}`);
    else emails.set(email.toLowerCase(), line.n);
    const name = v.name === undefined ? "" : v.name;
    if (typeof name !== "string" || [...name].length > MAX_NAME || /[\u0000-\u001f\u007f]/.test(name)) p(`name must be text of at most ${MAX_NAME} characters`);
    if (v.email_verified !== undefined && typeof v.email_verified !== "boolean") p("email_verified must be true or false");
    let hash: string | null = null;
    if (v.password_hash !== undefined && v.password_hash !== null) {
      const problem = typeof v.password_hash !== "string" || v.password_hash.length > 512 ? "password_hash is not an argon2 or bcrypt PHC string" : hashProblem(v.password_hash);
      if (problem) p(problem);
      else hash = v.password_hash as string;
    }
    const grants: { service: Service; role: string }[] = [];
    if (v.access !== undefined) {
      if (typeof v.access !== "object" || v.access === null || Array.isArray(v.access)) p("access must be an object of service: role");
      else {
        for (const [serviceName, role] of Object.entries(v.access as Json)) {
          const service = app.services.get(serviceName);
          if (!service) p(`access names a service the services file doesn't have`);
          else if (typeof role !== "string" || !service.roles.includes(role)) p(`access gives ${service.name} a role it doesn't declare`);
          else grants.push({ service, role });
        }
      }
    }
    checked.push({ username, email, name: typeof name === "string" ? name.trim() : "", verified: v.email_verified === true, hash, grants });
  }

  // Against what auth already has, in two queries rather than one per line.
  if (usernames.size > 0) {
    const taken = await app.sql`SELECT username FROM users WHERE username IN ${app.sql([...usernames.keys()])}`;
    for (const r of taken as { username: string }[]) problems.push(`line ${usernames.get(r.username)}: username is taken`);
  }
  if (emails.size > 0) {
    const taken = await app.sql`SELECT lower(email) AS email FROM users WHERE lower(email) IN ${app.sql([...emails.keys()])}`;
    for (const r of taken as { email: string }[]) problems.push(`line ${emails.get(r.email)}: email is used by another account`);
  }
  problems.sort((a, b) => Number(/\d+/.exec(a)?.[0] ?? 0) - Number(/\d+/.exec(b)?.[0] ?? 0));
  if (problems.length > 0 || opts.dryRun) return { problems, rows: [] };

  const rows = await writeAll(() => transaction(app.sql, async (tx, after) => {
    const done: ImportedUser[] = [];
    for (const u of checked) {
      const id = await insertUser(tx, { username: u.username, name: u.name, email: u.email, emailVerified: u.verified, kind: "person", ownerId: null, passwordHash: u.hash });
      await audit(tx, { actor: ACTOR, action: "user.create", userId: id, detail: { username: u.username, kind: "person", imported: true } });
      for (const g of u.grants) await putAccess(tx, app, { userId: id, service: g.service, role: g.role, actor: ACTOR, ip: null, reason: "import" }, after);
      done.push({ id, username: u.username, email: u.email, activation: u.hash ? null : await issueToken(tx, "activate", id, u.email) });
    }
    return done;
  }));
  return rows instanceof Array ? { problems: [], rows } : rows;
}

// The write is one transaction, so a failure part-way leaves nothing behind.
// It is reported by the error's name only: a database message can quote a
// value from the input.
async function writeAll<T>(write: () => Promise<T[]>): Promise<T[] | ImportResult<T>> {
  try {
    return await write();
  } catch (e) {
    return { problems: [`writing failed (${e instanceof Error ? e.name : typeof e}); nothing was written`], rows: [] };
  }
}

// What an owner may hold at once (credentials.ts), so their list stays one page.
const MAX_KEYS_PER_OWNER = 100;

export interface ImportedKey {
  id: string;
  owner: string;
}

// A key's SHA-256: 64 hex characters, or 32 bytes in base64 or base64url.
function digest(value: unknown): Buffer | null {
  if (typeof value !== "string") return null;
  if (/^[0-9a-fA-F]{64}$/.test(value)) return Buffer.from(value, "hex");
  if (/^[A-Za-z0-9+/_-]{43}=?$/.test(value)) {
    const b = fromBase64url(value.replace(/\+/g, "-").replace(/\//g, "_").replace(/=$/, ""));
    return b.length === 32 ? b : null;
  }
  return null;
}

export async function importApiKeys(app: App, service: Service, text: string, opts: { dryRun: boolean }): Promise<ImportResult<ImportedKey>> {
  const problems: string[] = [];
  if (service.apiKeyScopes.length === 0) return { problems: [`${service.name} declares no api_key_scopes, so it takes no API keys`], rows: [] };
  const lines = parseLines(text, problems);
  const hashes = new Map<string, number>();
  const checked: { n: number; owner: string; hash: Buffer; scopes: string[]; name: string; times: Record<string, string | null> }[] = [];

  for (const line of lines) {
    const p = (msg: string) => problems.push(`line ${line.n}: ${msg}`);
    const v = line.value;
    unknownFields(line, ["owner", "sha256", "scopes", "name", "expires_at", "revoked_at", "created_at", "last_used_at"], p);
    const owner = typeof v.owner === "string" && (ID_PATTERN.test(v.owner) || USERNAME.test(v.owner)) ? v.owner : null;
    if (!owner) p("owner must be a user's sub (usr_…) or username");
    const hash = digest(v.sha256);
    if (!hash) p("sha256 must be 64 hex characters, or 32 bytes in base64");
    else if (hashes.has(hash.toString("hex"))) p(`sha256 is also on line ${hashes.get(hash.toString("hex"))}`);
    else hashes.set(hash.toString("hex"), line.n);
    const scopes = v.scopes;
    if (!Array.isArray(scopes) || scopes.length === 0 || scopes.some((s) => typeof s !== "string" || !service.apiKeyScopes.includes(s))) {
      p(`scopes must be a non-empty list from: ${service.apiKeyScopes.join(", ")}`);
    }
    const name = v.name === undefined ? "imported" : v.name;
    if (typeof name !== "string" || name.trim() === "" || [...name].length > 100 || /[\u0000-\u001f\u007f]/.test(name)) p("name is 1 to 100 characters");
    const times: Record<string, string | null> = {};
    for (const field of ["expires_at", "revoked_at", "created_at", "last_used_at"]) {
      const t = timestamp(v[field]);
      if (t === undefined) p(`${field} must be an RFC 3339 timestamp`);
      else times[field] = t;
    }
    if (owner && hash) {
      checked.push({ n: line.n, owner, hash, scopes: [...new Set(scopes as string[])], name: typeof name === "string" ? name.trim() : "", times });
    }
  }

  // Each owner exists and holds a role on the service: introspection
  // answers only for those (§7.2), so a key without one would never work.
  const owners = new Map<string, string>();
  for (const k of checked) {
    if (owners.has(k.owner)) continue;
    const [row] = ID_PATTERN.test(k.owner)
      ? await app.sql`SELECT u.id, a.role FROM users u LEFT JOIN access a ON a.user_id = u.id AND a.service = ${service.name} WHERE u.id = ${k.owner}`
      : await app.sql`SELECT u.id, a.role FROM users u LEFT JOIN access a ON a.user_id = u.id AND a.service = ${service.name} WHERE u.username = ${k.owner}`;
    if (!row) problems.push(`line ${k.n}: owner is not a user`);
    else if (!row.role) problems.push(`line ${k.n}: owner has no role on ${service.name}`);
    else owners.set(k.owner, row.id);
  }
  // Live keys only, as the owner's own limit counts them.
  const adding = new Map<string, number>();
  for (const k of checked) if (!k.times.revoked_at && owners.has(k.owner)) adding.set(owners.get(k.owner)!, (adding.get(owners.get(k.owner)!) ?? 0) + 1);
  for (const [userId, n] of adding) {
    const [held] = await app.sql`SELECT count(*)::int AS n FROM credentials WHERE user_id = ${userId} AND kind = 'api_key' AND revoked_at IS NULL`;
    if (held.n + n > MAX_KEYS_PER_OWNER) {
      const first = checked.find((k) => owners.get(k.owner) === userId)!;
      problems.push(`line ${first.n}: owner would hold ${held.n + n} live API keys, more than ${MAX_KEYS_PER_OWNER}`);
    }
  }
  if (hashes.size > 0) {
    const existing = await app.sql`SELECT encode(secret_hash, 'hex') AS h FROM credentials WHERE encode(secret_hash, 'hex') IN ${app.sql([...hashes.keys()])}`;
    for (const r of existing as { h: string }[]) problems.push(`line ${hashes.get(r.h)}: sha256 is already a credential`);
  }
  problems.sort((a, b) => Number(/\d+/.exec(a)?.[0] ?? 0) - Number(/\d+/.exec(b)?.[0] ?? 0));
  if (problems.length > 0 || opts.dryRun) return { problems, rows: [] };

  const rows = await writeAll(() => app.sql.begin(async (tx) => {
    const done: ImportedKey[] = [];
    for (const k of checked) {
      const id = newId("key");
      const userId = owners.get(k.owner)!;
      await tx`
        INSERT INTO credentials (id, user_id, kind, service, scopes, name, secret_hash, created_at, last_used_at, expires_at, revoked_at)
        VALUES (${id}, ${userId}, 'api_key', ${service.name}, ${tx.array(k.scopes, "TEXT")}, ${k.name}, ${k.hash},
                COALESCE(${k.times.created_at}::timestamptz, now()), ${k.times.last_used_at}::timestamptz,
                ${k.times.expires_at}::timestamptz, ${k.times.revoked_at}::timestamptz)`;
      await audit(tx, { actor: ACTOR, action: "api_key.create", userId, detail: { id, service: service.name, scopes: k.scopes, imported: true } });
      done.push({ id, owner: userId });
    }
    return done;
  }));
  return rows instanceof Array ? { problems: [], rows } : rows;
}
