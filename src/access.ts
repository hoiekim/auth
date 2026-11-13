import type { SQL } from "bun";
import type { App } from "./app";
import { audit } from "./audit";
import { emit } from "./events";
import { HttpError } from "./http";
import { AUTH_SERVICE, type Service } from "./services";
import type { After } from "./tx";

// Access (docs/DESIGN.md §6): (user, service) → one role from the service's
// declared list. No row is no access; there is nothing else to evaluate.

export interface AccessRow {
  service: string;
  role: string;
  granted_by: string;
  granted_at: Date;
}

export function accessJson(a: AccessRow) {
  return { service: a.service, role: a.role, granted_by: a.granted_by, granted_at: a.granted_at.toISOString() };
}

// The role an enabled user holds on a service, from its row only.
export async function roleOf(sql: SQL, userId: string, service: string): Promise<string | null> {
  const [row] = await sql`
    SELECT a.role FROM access a JOIN users u ON u.id = a.user_id
    WHERE a.user_id = ${userId} AND a.service = ${service} AND u.disabled_at IS NULL`;
  return row?.role ?? null;
}

// The role a sign-in to a service gets: the user's row, or on a service with
// `signup: "open"`, its default_role, which is then written down (§6 rule 1).
export async function roleAtSignIn(tx: SQL, app: App, userId: string, service: Service, ip: string | null, after: After): Promise<string | null> {
  const role = await roleOf(tx, userId, service.name);
  if (role || service.signup !== "open" || !service.defaultRole) return role;
  await putAccess(tx, app, { userId, service, role: service.defaultRole, actor: userId, ip, reason: "open_signup" }, after);
  return service.defaultRole;
}

export interface Grant {
  userId: string;
  service: Service;
  role: string;
  actor: string;
  ip: string | null;
  reason?: string;
  // An invitation never lowers a role the user already holds (§7.5).
  neverLower?: boolean;
}

// Creates or changes a row, and tells the service in the same transaction.
export async function putAccess(tx: SQL, app: App, g: Grant, after: After): Promise<AccessRow> {
  if (!g.service.roles.includes(g.role)) {
    throw new HttpError(400, "invalid_request", `"${g.role}" is not a role of ${g.service.name}: use ${g.service.roles.join(", ")}.`);
  }
  const [current] = await tx`SELECT role FROM access WHERE user_id = ${g.userId} AND service = ${g.service.name} FOR UPDATE`;
  if (current && (current.role === g.role || (g.neverLower && g.service.roles.indexOf(current.role) > g.service.roles.indexOf(g.role)))) {
    const [row] = await tx`SELECT service, role, granted_by, granted_at FROM access WHERE user_id = ${g.userId} AND service = ${g.service.name}`;
    return row as AccessRow;
  }
  const [row] = await tx`
    INSERT INTO access (user_id, service, role, granted_by) VALUES (${g.userId}, ${g.service.name}, ${g.role}, ${g.actor})
    ON CONFLICT (user_id, service) DO UPDATE SET role = EXCLUDED.role, granted_by = EXCLUDED.granted_by, granted_at = now()
    RETURNING service, role, granted_by, granted_at`;
  await audit(tx, {
    actor: g.actor,
    action: "access.put",
    userId: g.userId,
    ip: g.ip,
    detail: { service: g.service.name, role: g.role, previous: current?.role ?? null, ...(g.reason ? { reason: g.reason } : {}) },
  });
  await emit(tx, app, g.service.name, "access.changed", { sub: g.userId, role: g.role });
  if (g.service.name === AUTH_SERVICE) after(() => alertAuthAccess(app, g.userId, g.role, g.actor));
  return row as AccessRow;
}

// Removes a row. On an open service the next sign-in would grant
// default_role again, so removal is refused; disabling is how to keep
// someone out (§6).
export async function deleteAccess(
  tx: SQL,
  app: App,
  userId: string,
  service: Service,
  actor: string,
  ip: string | null,
  after: After,
): Promise<boolean> {
  if (service.signup === "open") {
    throw new HttpError(409, "conflict", `${service.name} is open to sign-up, so a role can be changed but not removed; disable the user to keep them out.`);
  }
  const rows = await tx`DELETE FROM access WHERE user_id = ${userId} AND service = ${service.name} RETURNING role`;
  if (rows.length === 0) return false;
  await audit(tx, { actor, action: "access.delete", userId, ip, detail: { service: service.name, previous: rows[0].role } });
  await emit(tx, app, service.name, "access.changed", { sub: userId, role: null });
  if (service.name === AUTH_SERVICE) after(() => alertAuthAccess(app, userId, null, actor));
  return true;
}

// Every change to who administers auth is alerted (§9.5).
function alertAuthAccess(app: App, userId: string, role: string | null, actor: string): void {
  app.alert(`auth: ${role ? `${userId} was given auth:${role}` : `${userId} lost auth access`} by ${actor}`);
}
