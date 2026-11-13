import type { SQL } from "bun";
import { putAccess } from "./access";
import type { App } from "./app";
import { audit } from "./audit";
import { newId, randomToken, sha256 } from "./crypto";
import { inviteEmail } from "./emails";
import { emit } from "./events";
import { HttpError } from "./http";
import type { Service } from "./services";
import type { After } from "./tx";

// Invitations (docs/DESIGN.md §7.5, §12.6): an email that lets its holder
// create an account, or use the one they have, and get a role on a service.

const INVITE_SECONDS = 14 * 24 * 60 * 60;

export interface InviteRow {
  id: string;
  email: string;
  service: string;
  role: string;
  invited_by: string;
  expires_at: Date;
  accepted_by: string | null;
  accepted_at: Date | null;
}

export function inviteJson(i: InviteRow) {
  return {
    id: i.id,
    email: i.email,
    service: i.service,
    role: i.role,
    invited_by: i.invited_by,
    expires_at: i.expires_at.toISOString(),
    accepted_by: i.accepted_by,
    accepted_at: i.accepted_at?.toISOString() ?? null,
  };
}

export async function createInvite(
  tx: SQL,
  app: App,
  i: { email: string; service: Service; role: string; actor: string; ip: string | null },
  after: After,
): Promise<InviteRow> {
  if (i.service.signup === "closed") {
    throw new HttpError(409, "conflict", `${i.service.name} is closed to sign-up, so it takes no invitations; an admin grants access to existing accounts.`);
  }
  if (!i.service.roles.includes(i.role)) {
    throw new HttpError(400, "invalid_request", `"${i.role}" is not a role of ${i.service.name}: use ${i.service.roles.join(", ")}.`);
  }
  const token = randomToken();
  const [row] = await tx`
    INSERT INTO invites (id, email, service, role, token_hash, invited_by, expires_at)
    VALUES (${newId("inv")}, ${i.email}, ${i.service.name}, ${i.role}, ${sha256(token)}, ${i.actor},
            now() + make_interval(secs => ${INVITE_SECONDS}))
    RETURNING id, email, service, role, invited_by, expires_at, accepted_by, accepted_at`;
  await audit(tx, { actor: i.actor, action: "invite.create", ip: i.ip, detail: { id: row.id, service: i.service.name, role: i.role } });
  after(() => app.mail(inviteEmail(app.config.issuer, i.email, i.service.name, token)));
  return row as InviteRow;
}

export async function findLiveInvite(sql: SQL, token: string | null): Promise<InviteRow | null> {
  const [row] = await sql`
    SELECT id, email, service, role, invited_by, expires_at, accepted_by, accepted_at FROM invites
    WHERE token_hash = ${sha256(token && token.length <= 128 ? token : "")} AND accepted_at IS NULL AND expires_at > now()`;
  return (row as InviteRow) ?? null;
}

// Marks the invitation accepted by `userId`, once, and gives the invited
// role without lowering one the user already holds. The service learns who
// accepted, so it can give them what it tied to the invitation.
export async function acceptInvite(tx: SQL, app: App, token: string | null, userId: string, ip: string | null, after: After): Promise<InviteRow> {
  const [row] = await tx`
    UPDATE invites SET accepted_by = ${userId}, accepted_at = now()
    WHERE token_hash = ${sha256(token && token.length <= 128 ? token : "")} AND accepted_at IS NULL AND expires_at > now()
    RETURNING id, email, service, role, invited_by, expires_at, accepted_by, accepted_at`;
  if (!row) throw new HttpError(409, "conflict", "This invitation has expired or was already used.");
  const service = app.services.get(row.service);
  if (!service || service.signup === "closed" || !service.roles.includes(row.role)) {
    throw new HttpError(409, "conflict", "This invitation is no longer valid.");
  }
  await putAccess(tx, app, { userId, service, role: row.role, actor: userId, ip, reason: "invite", neverLower: true }, after);
  await audit(tx, { actor: userId, action: "invite.accept", userId, ip, detail: { id: row.id, service: service.name } });
  await emit(tx, app, service.name, "invite.accepted", { invite: row.id, sub: userId });
  return row as InviteRow;
}
