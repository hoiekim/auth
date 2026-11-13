import { accessJson, deleteAccess, putAccess, roleOf, type AccessRow } from "./access";
import type { App } from "./app";
import { audit, clientActor } from "./audit";
import { authenticateClient } from "./clients";
import { createCredential, credentialJson, listCredentials, revokeCredential, type CredentialKind } from "./credentials";
import { ID_PATTERN } from "./crypto";
import { activationEmail, addressInUseEmail, resetEmail, securityNotice, verifyEmail, type SecurityChange } from "./emails";
import { confirmTotpEnrolment, factorsOf, newRecoveryCodes, removeTotp, startTotpEnrolment } from "./factors";
import { HttpError, json, noContent, readJson } from "./http";
import { createInvite, inviteJson, type InviteRow } from "./invites";
import { finishRegistration, listPasskeys, passkeyJson, registrationOptions } from "./passkeys";
import { BREACHED_MESSAGE, passwordProblem } from "./passwords";
import type { Ctx } from "./server";
import { AUTH_SERVICE, type Client, type Service } from "./services";
import {
  clearSessionCookie,
  endFamily,
  endSession,
  endUserSessions,
  hasMfa,
  loadSession,
  REAUTH_SECONDS,
  requireCsrf,
  sessionCookie,
  stepUp,
  type Session,
} from "./sessions";
import { emailAllowed, issueToken } from "./tokens";
import { recordFailure } from "./throttle";
import { transaction, type After } from "./tx";
import { accountKey } from "./pages/signin";
import { checkEmail, checkName, checkUsername, deleteUser, findUser, insertUser, setDisabled, userJson, type UserRow } from "./users";

// The management API (docs/DESIGN.md §7.5), JSON under /v1. Callers are a
// signed-in user (the __Host-auth cookie, plus X-CSRF-Token on changes) or a
// service's own client (HTTP Basic), which reaches only the ★ endpoints and
// only its own service.

type Caller = { kind: "user"; session: Session; admin: boolean } | { kind: "client"; client: Client; service: Service };

async function caller(app: App, req: Request, allowClient: boolean): Promise<Caller> {
  if (req.headers.get("Authorization")) {
    const client = await authenticateClient(app, req, null, false);
    const service = app.services.get(client.service)!;
    if (!allowClient || !service.managesOwnMembers) {
      throw new HttpError(403, "forbidden", "This endpoint is not open to a service's client.");
    }
    return { kind: "client", client, service };
  }
  const session = await loadSession(app, req);
  if (!session) throw new HttpError(401, "unauthorized", "Sign in first.");
  if (req.method !== "GET") requireCsrf(app, req, session);
  const admin = (await roleOf(app.sql, session.userId, AUTH_SERVICE)) === "admin";
  return { kind: "user", session, admin };
}

async function signedIn(app: App, req: Request): Promise<Session> {
  const c = await caller(app, req, false);
  if (c.kind !== "user") throw new HttpError(403, "forbidden", "Sign in first.");
  return c.session;
}

// auth:admin always requires MFA (§6), so an admin's session must have used it.
function requireAdmin(c: Caller): asserts c is Extract<Caller, { kind: "user" }> {
  if (c.kind !== "user" || !c.admin) throw new HttpError(403, "forbidden", "This needs the auth admin role.");
  if (!hasMfa(c.session)) throw new HttpError(403, "forbidden", "Admin actions need a sign-in with a second factor.");
}

// The service a ★ call may act on: any for an admin, its own for a client.
function serviceFor(app: App, c: Caller, name: string): Service {
  const service = app.services.get(name);
  if (c.kind === "client") {
    if (name !== c.service.name) throw new HttpError(403, "forbidden", "A client reaches only its own service.");
    return c.service;
  }
  requireAdmin(c);
  if (!service) throw new HttpError(404, "not_found", `There is no service "${name}".`);
  return service;
}

function actorOf(c: Caller): string {
  return c.kind === "client" ? clientActor(c.service.name) : c.session.userId;
}

// Changing a credential, or deleting the account, needs a full sign-in in
// the last 15 minutes (§7.5).
function requireRecent(session: Session): void {
  if (session.authAge > REAUTH_SECONDS) throw new HttpError(403, "reauth_required", "Sign in again to make this change.");
}

function pageParams(url: URL): { after: string; limit: number } {
  const raw = url.searchParams.get("limit");
  const limit = raw === null ? 50 : /^\d{1,3}$/.test(raw) ? Number(raw) : -1;
  if (limit < 1 || limit > 100) throw new HttpError(400, "invalid_request", "limit is 1 to 100.");
  const after = url.searchParams.get("after") ?? "";
  if (after.length > 64) throw new HttpError(400, "invalid_request", "after is not a cursor.");
  return { after, limit };
}

function listOf<T>(rows: T[], limit: number, cursor: (row: T) => string, render: (row: T) => unknown) {
  const more = rows.length > limit;
  const items = rows.slice(0, limit);
  return { items: items.map(render), next: more && items.length > 0 ? cursor(items[items.length - 1]!) : null };
}

function likePrefix(q: string): string {
  return `${q.replace(/[\\%_]/g, (m) => `\\${m}`)}%`;
}

async function userOr404(app: App, id: string): Promise<UserRow> {
  const user = ID_PATTERN.test(id) ? await findUser(app.sql, id) : null;
  if (!user) throw new HttpError(404, "not_found", "No such user.");
  return user;
}

// Every admin action is alerted (§9.5), once it has committed.
function adminAlert(app: App, after: After, c: Caller, text: string): void {
  if (c.kind === "user") after(() => app.alert(`auth: ${c.session.username} ${text}`));
}

function notify(app: App, after: After, user: { email: string | null; username: string }, change: SecurityChange, detail?: string) {
  if (user.email) after(() => app.mail(securityNotice(user.email!, user.username, change, detail)));
}

// ------------------------------------------------------------- /v1/me

async function meJson(app: App, session: Session) {
  const user = await findUser(app.sql, session.userId);
  if (!user) throw new HttpError(401, "unauthorized", "Sign in first.");
  const factors = await factorsOf(app.sql, user.id);
  const [pending] = await app.sql`
    SELECT email FROM one_time_tokens WHERE user_id = ${user.id} AND purpose = 'verify_email' AND used_at IS NULL AND expires_at > now()
    ORDER BY expires_at DESC LIMIT 1`;
  return {
    ...userJson(user),
    email_pending: pending?.email ?? null,
    mfa: { totp: factors.totp, passkeys: factors.passkeys, recovery_codes: factors.recoveryCodes },
    admin: (await roleOf(app.sql, user.id, AUTH_SERVICE)) === "admin",
    account_deletion: app.config.allowAccountDeletion,
  };
}

export async function getMe({ req, deps: app }: Ctx<App>): Promise<Response> {
  return json(200, await meJson(app, await signedIn(app, req)));
}

export async function patchMe({ req, ip, deps: app }: Ctx<App>): Promise<Response> {
  const session = await signedIn(app, req);
  const body = await readJson(req);
  const name = body.name !== undefined ? checkName(body.name) : null;
  const email = body.email !== undefined ? checkEmail(body.email) : null;
  if (email !== null) {
    requireRecent(session);
    const limit = await emailAllowed(app.sql, email, `user:${session.userId}`);
    if (!limit.allowed) throw new HttpError(429, "rate_limited", "Too many emails to that address.", { "Retry-After": String(limit.retryAfter) });
  }
  await transaction(app.sql, async (tx, after) => {
    if (name !== null) {
      await tx`UPDATE users SET name = ${name}, updated_at = now() WHERE id = ${session.userId}`;
      await audit(tx, { actor: session.userId, action: "user.update", userId: session.userId, ip, detail: { fields: ["name"] } });
    }
    if (email !== null && email.toLowerCase() !== (session.email ?? "").toLowerCase()) {
      // The address changes only once the new one is confirmed; the old one
      // is told now (§9.1).
      const [taken] = await tx`SELECT 1 FROM users WHERE lower(email) = lower(${email})`;
      if (taken) after(() => app.mail(addressInUseEmail(email)));
      else {
        const token = await issueToken(tx, "verify_email", session.userId, email);
        after(() => app.mail(verifyEmail(app.config.issuer, email, token)));
      }
      notify(app, after, session, "your email address is changing", `A confirmation link went to the new address.`);
      await audit(tx, { actor: session.userId, action: "email.change", userId: session.userId, ip });
    }
  });
  return json(200, await meJson(app, session));
}

export async function deleteMe({ req, ip, deps: app }: Ctx<App>): Promise<Response> {
  const session = await signedIn(app, req);
  if (!app.config.allowAccountDeletion) throw new HttpError(403, "forbidden", "This deployment doesn't let people delete their own accounts.");
  requireRecent(session);
  const user = await userOr404(app, session.userId);
  await transaction(app.sql, (tx) => deleteUser(tx, app, user, session.userId, ip));
  return noContent({ cookies: [clearSessionCookie()] });
}

export async function changePassword({ req, ip, deps: app }: Ctx<App>): Promise<Response> {
  const session = await signedIn(app, req);
  requireRecent(session);
  const body = await readJson(req);
  const user = await userOr404(app, session.userId);
  if (typeof body.new !== "string") throw new HttpError(400, "invalid_request", "new is required.");
  if (user.password_hash !== null) {
    const check = await app.hasher.verify(typeof body.current === "string" ? body.current.slice(0, 1024) : "", user.password_hash);
    if (!check.ok) {
      await recordFailure(app.sql, accountKey(user.id));
      throw new HttpError(403, "forbidden", "The current password is wrong.");
    }
  }
  const problem = passwordProblem(body.new, user) ?? ((await app.breached(body.new)) ? BREACHED_MESSAGE : null);
  if (problem) throw new HttpError(400, "invalid_request", problem);
  const hash = await app.hasher.hash(body.new);
  await transaction(app.sql, async (tx, after) => {
    await tx`UPDATE users SET password_hash = ${hash}, updated_at = now() WHERE id = ${user.id}`;
    await endUserSessions(tx, app, user.id, session.id);
    await audit(tx, { actor: user.id, action: "password.change", userId: user.id, ip });
    notify(app, after, user, "password changed");
  });
  return noContent();
}

export async function postTotp({ req, ip, deps: app }: Ctx<App>): Promise<Response> {
  const session = await signedIn(app, req);
  requireRecent(session);
  const body = await readJson(req);
  if (body.enrollment === undefined) return json(200, startTotpEnrolment(app, session.userId, session.username));
  const result = await transaction(app.sql, async (tx, after) => {
    if (!(await confirmTotpEnrolment(tx, app, session.userId, body.enrollment, body.code))) return null;
    const [left] = await tx`SELECT count(*)::int AS n FROM recovery_codes WHERE user_id = ${session.userId} AND used_at IS NULL`;
    const codes = left.n === 0 ? await newRecoveryCodes(tx, session.userId) : null;
    // The code just confirmed is a second factor: the session steps up.
    const amr = [...new Set([...session.amr, "otp", "mfa"])];
    const token = await stepUp(tx, session.id, amr);
    await audit(tx, { actor: session.userId, action: "totp.enroll", userId: session.userId, ip });
    notify(app, after, session, "two-factor authentication added");
    return { codes, token };
  });
  if (!result) throw new HttpError(400, "invalid_request", "That code doesn't match; the enrolment may have expired.");
  return json(200, { recovery_codes: result.codes }, {}, [sessionCookie(result.token)]);
}

export async function deleteTotp({ req, ip, deps: app }: Ctx<App>): Promise<Response> {
  const session = await signedIn(app, req);
  requireRecent(session);
  await transaction(app.sql, async (tx, after) => {
    if (!(await removeTotp(tx, session.userId))) throw new HttpError(404, "not_found", "No authenticator app is set up.");
    await audit(tx, { actor: session.userId, action: "totp.remove", userId: session.userId, ip });
    notify(app, after, session, "two-factor authentication removed");
  });
  return noContent();
}

export async function postRecoveryCodes({ req, ip, deps: app }: Ctx<App>): Promise<Response> {
  const session = await signedIn(app, req);
  requireRecent(session);
  const codes = await transaction(app.sql, async (tx, after) => {
    const c = await newRecoveryCodes(tx, session.userId);
    await audit(tx, { actor: session.userId, action: "recovery.regenerate", userId: session.userId, ip });
    notify(app, after, session, "recovery codes regenerated");
    return c;
  });
  return json(200, { codes });
}

export async function getPasskeys({ req, deps: app }: Ctx<App>): Promise<Response> {
  const session = await signedIn(app, req);
  return json(200, { items: (await listPasskeys(app.sql, session.userId)).map(passkeyJson), next: null });
}

export async function postPasskey({ req, ip, deps: app }: Ctx<App>): Promise<Response> {
  const session = await signedIn(app, req);
  requireRecent(session);
  const body = await readJson(req);
  if (body.registration === undefined) {
    return json(200, await registrationOptions(app, { id: session.userId, username: session.username, name: session.name }));
  }
  const name = typeof body.name === "string" && body.name.trim() ? checkName(body.name).slice(0, 100) : "Passkey";
  const id = await transaction(app.sql, async (tx, after) => {
    const pk = await finishRegistration(tx, app, session.userId, body.registration, body.response, name);
    if (!pk) return null;
    await audit(tx, { actor: session.userId, action: "passkey.add", userId: session.userId, ip, detail: { id: pk } });
    notify(app, after, session, "a passkey was added", `Name: ${name}`);
    return pk;
  });
  if (!id) throw new HttpError(400, "invalid_request", "The passkey couldn't be verified.");
  const [row] = await app.sql`SELECT id, name, created_at, last_used_at FROM passkeys WHERE id = ${id}`;
  return json(201, passkeyJson(row));
}

export async function deletePasskey({ req, params, ip, deps: app }: Ctx<App>): Promise<Response> {
  const session = await signedIn(app, req);
  requireRecent(session);
  await transaction(app.sql, async (tx, after) => {
    const rows = await tx`DELETE FROM passkeys WHERE id = ${params.id!} AND user_id = ${session.userId} RETURNING name`;
    if (rows.length === 0) throw new HttpError(404, "not_found", "No such passkey.");
    await audit(tx, { actor: session.userId, action: "passkey.remove", userId: session.userId, ip, detail: { id: params.id! } });
    notify(app, after, session, "a passkey was removed", `Name: ${rows[0].name}`);
  });
  return noContent();
}

async function sessionsOf(app: App, userId: string, current: string | null) {
  const sso = await app.sql`
    SELECT id, created_at, last_seen_at, host(ip) AS ip, user_agent, amr FROM sessions
    WHERE user_id = ${userId} AND expires_at > now() AND ends_at > now() ORDER BY last_seen_at DESC`;
  const native = await app.sql`
    SELECT family_id AS id, client_id, min(created_at) AS created_at, max(created_at) AS last_seen_at FROM refresh_tokens
    WHERE user_id = ${userId} AND session_id IS NULL AND revoked_at IS NULL AND expires_at > now()
    GROUP BY family_id, client_id ORDER BY max(created_at) DESC`;
  return [
    ...sso.map((s: any) => ({
      id: s.id,
      current: s.id === current,
      created_at: s.created_at.toISOString(),
      last_seen_at: s.last_seen_at.toISOString(),
      ip: s.ip,
      user_agent: s.user_agent,
      amr: s.amr,
      client: null,
    })),
    ...native.map((f: any) => ({
      id: f.id,
      current: false,
      created_at: f.created_at.toISOString(),
      last_seen_at: f.last_seen_at.toISOString(),
      ip: null,
      user_agent: null,
      amr: null,
      client: f.client_id,
    })),
  ];
}

export async function getSessions({ req, deps: app }: Ctx<App>): Promise<Response> {
  const session = await signedIn(app, req);
  return json(200, { items: await sessionsOf(app, session.userId, session.id), next: null });
}

// Signs out every device, this one included (U4).
export async function deleteSessions({ req, ip, deps: app }: Ctx<App>): Promise<Response> {
  const session = await signedIn(app, req);
  await transaction(app.sql, async (tx) => {
    await endUserSessions(tx, app, session.userId);
    await audit(tx, { actor: session.userId, action: "session.end_all", userId: session.userId, ip });
  });
  return noContent({ cookies: [clearSessionCookie()] });
}

export async function deleteOneSession({ req, params, ip, deps: app }: Ctx<App>): Promise<Response> {
  const session = await signedIn(app, req);
  const id = params.id!;
  const ended = await transaction(app.sql, async (tx) => {
    const [own] = await tx`SELECT 1 FROM sessions WHERE id = ${id} AND user_id = ${session.userId}`;
    let done = false;
    if (own) {
      await endSession(tx, app, id);
      done = true;
    } else done = await endFamily(tx, app, id, session.userId);
    if (done) await audit(tx, { actor: session.userId, action: "session.end", userId: session.userId, ip, detail: { sid: id } });
    return done;
  });
  if (!ended) throw new HttpError(404, "not_found", "No such session.");
  return noContent(id === session.id ? { cookies: [clearSessionCookie()] } : {});
}

// App passwords and API keys, for the signed-in user or, by an admin, for a
// bot user (A9), which can't sign in to manage its own.
function credentialRoutes(kind: CredentialKind) {
  const label = kind === "app_password" ? "app password" : "API key";
  const secretField = kind === "app_password" ? "password" : "key";

  async function owner(app: App, req: Request, params: Record<string, string>, change: boolean) {
    if (params.user === undefined) {
      const session = await signedIn(app, req);
      if (change) requireRecent(session);
      return { userId: session.userId, actor: session.userId, notifyTo: session as { email: string | null; username: string }, admin: null, bot: null };
    }
    const c = await caller(app, req, false);
    requireAdmin(c);
    if (change) requireRecent(c.session);
    const bot = await userOr404(app, params.user);
    if (bot.kind !== "bot") throw new HttpError(409, "conflict", `People manage their own ${label}s; this endpoint is for bot users.`);
    const ownerRow = bot.owner_id ? await findUser(app.sql, bot.owner_id) : null;
    return { userId: bot.id, actor: c.session.userId, notifyTo: ownerRow ?? { email: null, username: bot.username }, admin: c, bot: bot.username };
  }

  return {
    async list({ req, params, deps: app }: Ctx<App>): Promise<Response> {
      const o = await owner(app, req, params, false);
      return json(200, { items: (await listCredentials(app.sql, o.userId, kind)).map(credentialJson), next: null });
    },
    async create({ req, params, ip, deps: app }: Ctx<App>): Promise<Response> {
      const o = await owner(app, req, params, true);
      const body = await readJson(req);
      const service = typeof body.service === "string" ? app.services.get(body.service) : undefined;
      if (!service) throw new HttpError(400, "invalid_request", "service must name a service.");
      const created = await transaction(app.sql, async (tx, after) => {
        const c = await createCredential(tx, app, {
          userId: o.userId,
          kind,
          service,
          scopes: body.scopes,
          name: body.name,
          expiresAt: body.expires_at,
          actor: o.actor,
          ip,
        });
        notify(app, after, o.notifyTo, kind === "app_password" ? "an app password was created" : "an API key was created", `For ${service.name}: ${c.row.name}`);
        if (o.admin) adminAlert(app, after, o.admin, `made an ${label} for the bot ${o.bot} on ${service.name}`);
        return c;
      });
      return json(201, { ...credentialJson(created.row), [secretField]: created.secret });
    },
    async revoke({ req, params, ip, deps: app }: Ctx<App>): Promise<Response> {
      const o = await owner(app, req, params, true);
      const ok = await transaction(app.sql, async (tx, after) => {
        const done = await revokeCredential(tx, app, o.userId, kind, params.id!, o.actor, ip);
        if (done && o.admin) adminAlert(app, after, o.admin, `revoked a ${label} of the bot ${o.bot}`);
        return done;
      });
      if (!ok) throw new HttpError(404, "not_found", `No such ${label}.`);
      return noContent();
    },
  };
}

export const appPasswords = credentialRoutes("app_password");
export const apiKeys = credentialRoutes("api_key");

export async function getMyAccess({ req, deps: app }: Ctx<App>): Promise<Response> {
  const session = await signedIn(app, req);
  const rows = (await app.sql`
    SELECT service, role, granted_by, granted_at FROM access WHERE user_id = ${session.userId} ORDER BY service`) as AccessRow[];
  return json(200, {
    items: rows.map((r) => {
      const s = app.services.get(r.service);
      return { ...accessJson(r), app_password_scopes: s?.appPasswordScopes ?? [], api_key_scopes: s?.apiKeyScopes ?? [] };
    }),
    next: null,
  });
}

// ------------------------------------------------------------ administration

export async function listUsers({ req, url, deps: app }: Ctx<App>): Promise<Response> {
  const c = await caller(app, req, true);
  const { after, limit } = pageParams(url);
  const q = (url.searchParams.get("q") ?? "").trim().slice(0, 254);
  if (c.kind === "client") {
    // A service's client sees only the enabled users with a role on its
    // service, and can't list addresses: an email matches only whole (§7.5).
    const rows = await app.sql`
      SELECT u.id, u.username, u.name, a.role FROM users u
      JOIN access a ON a.user_id = u.id AND a.service = ${c.service.name}
      WHERE u.disabled_at IS NULL AND u.id > ${after}
        AND (${q} = '' OR u.username LIKE ${likePrefix(q.toLowerCase())} OR lower(u.name) LIKE ${likePrefix(q.toLowerCase())}
             OR lower(u.email) = lower(${q}))
      ORDER BY u.id LIMIT ${limit + 1}`;
    return json(200, listOf(rows as any[], limit, (r) => r.id, (r) => ({ id: r.id, username: r.username, name: r.name, role: r.role })));
  }
  requireAdmin(c);
  const rows = await app.sql`
    SELECT * FROM users
    WHERE id > ${after}
      AND (${q} = '' OR username LIKE ${likePrefix(q.toLowerCase())} OR lower(name) LIKE ${likePrefix(q.toLowerCase())}
           OR lower(email) LIKE ${likePrefix(q.toLowerCase())})
    ORDER BY id LIMIT ${limit + 1}`;
  return json(200, listOf(rows as UserRow[], limit, (r) => r.id, userJson));
}

export async function createUser({ req, ip, deps: app }: Ctx<App>): Promise<Response> {
  const c = await caller(app, req, false);
  requireAdmin(c);
  const body = await readJson(req);
  const username = checkUsername(body.username);
  const name = checkName(body.name);
  const kind = body.kind === undefined ? "person" : body.kind;
  if (kind !== "person" && kind !== "bot") throw new HttpError(400, "invalid_request", 'kind is "person" or "bot".');
  let ownerId: string | null = null;
  let email: string | null = null;
  if (kind === "bot") {
    if (body.email !== undefined && body.email !== null) throw new HttpError(400, "invalid_request", "A bot user has no email.");
    ownerId = body.owner_id === undefined ? c.session.userId : String(body.owner_id);
    const owner = await userOr404(app, ownerId);
    if (owner.kind !== "person") throw new HttpError(400, "invalid_request", "A bot's owner is a person.");
  } else {
    email = checkEmail(body.email);
  }
  const user = await transaction(app.sql, async (tx, after) => {
    const id = await insertUser(tx, { username, name, email, emailVerified: false, kind, ownerId, passwordHash: null });
    await audit(tx, { actor: c.session.userId, action: "user.create", userId: id, ip, detail: { username, kind } });
    adminAlert(app, after, c, `created the ${kind} ${username}`);
    if (email) {
      const token = await issueToken(tx, "activate", id, email);
      after(() => app.mail(activationEmail(app.config.issuer, email!, username, token)));
    }
    const [row] = await tx`SELECT * FROM users WHERE id = ${id}`;
    return row as UserRow;
  });
  return json(201, userJson(user));
}

export async function getUser({ req, params, deps: app }: Ctx<App>): Promise<Response> {
  const c = await caller(app, req, false);
  requireAdmin(c);
  const user = await userOr404(app, params.id!);
  const factors = await factorsOf(app.sql, user.id);
  const access = (await app.sql`SELECT service, role, granted_by, granted_at FROM access WHERE user_id = ${user.id} ORDER BY service`) as AccessRow[];
  return json(200, {
    ...userJson(user),
    mfa: { totp: factors.totp, passkeys: factors.passkeys, recovery_codes: factors.recoveryCodes },
    access: access.map(accessJson),
  });
}

export async function patchUser({ req, params, ip, deps: app }: Ctx<App>): Promise<Response> {
  const c = await caller(app, req, false);
  requireAdmin(c);
  const user = await userOr404(app, params.id!);
  const body = await readJson(req);
  const name = body.name !== undefined ? checkName(body.name) : null;
  const email = body.email !== undefined && user.kind === "person" ? checkEmail(body.email) : null;
  if (body.disabled !== undefined && typeof body.disabled !== "boolean") throw new HttpError(400, "invalid_request", "disabled is true or false.");
  let ownerId: string | null = null;
  if (body.owner_id !== undefined) {
    if (user.kind !== "bot") throw new HttpError(400, "invalid_request", "Only a bot user has an owner.");
    const owner = await userOr404(app, String(body.owner_id));
    if (owner.kind !== "person") throw new HttpError(400, "invalid_request", "A bot's owner is a person.");
    ownerId = owner.id;
  }
  await transaction(app.sql, async (tx, after) => {
    const fields: string[] = [];
    if (name !== null) {
      await tx`UPDATE users SET name = ${name}, updated_at = now() WHERE id = ${user.id}`;
      fields.push("name");
    }
    if (email !== null && email.toLowerCase() !== (user.email ?? "").toLowerCase()) {
      try {
        await tx`UPDATE users SET email = ${email}, email_verified_at = NULL, updated_at = now() WHERE id = ${user.id}`;
      } catch (e) {
        if ((e as { errno?: string }).errno === "23505") throw new HttpError(409, "conflict", "Another account uses that email address.");
        throw e;
      }
      notify(app, after, user, "your email address is changing", "An administrator changed it.");
      fields.push("email");
    }
    if (ownerId !== null) {
      await tx`UPDATE users SET owner_id = ${ownerId}, updated_at = now() WHERE id = ${user.id}`;
      fields.push("owner_id");
    }
    if (fields.length > 0) {
      await audit(tx, { actor: c.session.userId, action: "user.update", userId: user.id, ip, detail: { fields } });
      adminAlert(app, after, c, `changed the ${fields.join(", ")} of ${user.username}`);
    }
    if (typeof body.disabled === "boolean") {
      await setDisabled(tx, app, user, body.disabled, c.session.userId, ip);
      adminAlert(app, after, c, `${body.disabled ? "disabled" : "enabled"} ${user.username}`);
    }
  });
  const fresh = await userOr404(app, user.id);
  return json(200, userJson(fresh));
}

export async function deleteUserRoute({ req, params, ip, deps: app }: Ctx<App>): Promise<Response> {
  const c = await caller(app, req, false);
  requireAdmin(c);
  const user = await userOr404(app, params.id!);
  await transaction(app.sql, async (tx, after) => {
    await deleteUser(tx, app, user, c.session.userId, ip);
    adminAlert(app, after, c, `deleted ${user.username}`);
  });
  return noContent();
}

export async function putUserAccess({ req, params, ip, deps: app }: Ctx<App>): Promise<Response> {
  const c = await caller(app, req, true);
  const service = serviceFor(app, c, params.service!);
  const body = await readJson(req);
  if (typeof body.role !== "string") throw new HttpError(400, "invalid_request", "role is required.");
  const user = await userOr404(app, params.id!);
  const row = await transaction(app.sql, async (tx, after) => {
    const r = await putAccess(tx, app, { userId: user.id, service, role: body.role as string, actor: actorOf(c), ip }, after);
    if (service.name !== AUTH_SERVICE) adminAlert(app, after, c, `set ${user.username}'s role on ${service.name} to ${r.role}`);
    return r;
  });
  return json(200, accessJson(row));
}

export async function deleteUserAccess({ req, params, ip, deps: app }: Ctx<App>): Promise<Response> {
  const c = await caller(app, req, true);
  const service = serviceFor(app, c, params.service!);
  const user = await userOr404(app, params.id!);
  const removed = await transaction(app.sql, async (tx, after) => {
    const done = await deleteAccess(tx, app, user.id, service, actorOf(c), ip, after);
    if (done && service.name !== AUTH_SERVICE) adminAlert(app, after, c, `removed ${user.username}'s role on ${service.name}`);
    return done;
  });
  if (!removed) throw new HttpError(404, "not_found", "The user has no role on this service.");
  return noContent();
}

export async function getUserAccess({ req, params, deps: app }: Ctx<App>): Promise<Response> {
  const c = await caller(app, req, true);
  const user = await userOr404(app, params.id!);
  let rows: AccessRow[];
  if (c.kind === "client") {
    rows = (await app.sql`
      SELECT a.service, a.role, a.granted_by, a.granted_at FROM access a JOIN users u ON u.id = a.user_id
      WHERE a.user_id = ${user.id} AND a.service = ${c.service.name} AND u.disabled_at IS NULL`) as AccessRow[];
  } else {
    requireAdmin(c);
    rows = (await app.sql`SELECT service, role, granted_by, granted_at FROM access WHERE user_id = ${user.id} ORDER BY service`) as AccessRow[];
  }
  return json(200, { items: rows.map(accessJson), next: null });
}

export async function deleteUserSessions({ req, params, ip, deps: app }: Ctx<App>): Promise<Response> {
  const c = await caller(app, req, false);
  requireAdmin(c);
  const user = await userOr404(app, params.id!);
  await transaction(app.sql, async (tx, after) => {
    await endUserSessions(tx, app, user.id);
    await audit(tx, { actor: c.session.userId, action: "session.end_all", userId: user.id, ip });
    adminAlert(app, after, c, `signed ${user.username} out everywhere`);
  });
  return noContent();
}

// A5: after verifying someone out of band. Audited and alerted.
export async function resetUser({ req, params, ip, deps: app }: Ctx<App>): Promise<Response> {
  const c = await caller(app, req, false);
  requireAdmin(c);
  const user = await userOr404(app, params.id!);
  const body = await readJson(req);
  const sendLink = body.send_link === true;
  const clearMfa = body.clear_mfa === true;
  if (!sendLink && !clearMfa) throw new HttpError(400, "invalid_request", "Set send_link, clear_mfa or both.");
  if (user.kind !== "person") throw new HttpError(409, "conflict", "A bot user has no password or second factor.");
  if (sendLink && !user.email) throw new HttpError(409, "conflict", "The user has no email address to send a link to.");
  await transaction(app.sql, async (tx, after) => {
    if (clearMfa) {
      await tx`DELETE FROM totp WHERE user_id = ${user.id}`;
      await tx`DELETE FROM passkeys WHERE user_id = ${user.id}`;
      await tx`DELETE FROM recovery_codes WHERE user_id = ${user.id}`;
      await endUserSessions(tx, app, user.id);
      await audit(tx, { actor: c.session.userId, action: "mfa.cleared", userId: user.id, ip });
      notify(app, after, user, "two-factor authentication was cleared by an administrator");
    }
    if (sendLink) {
      const token = await issueToken(tx, "reset", user.id, user.email);
      await audit(tx, { actor: c.session.userId, action: "reset.sent", userId: user.id, ip });
      after(() => app.mail(resetEmail(app.config.issuer, user.email!, token)));
    }
    const did = [clearMfa ? "cleared the MFA of" : null, sendLink ? "sent a reset link to" : null]
      .filter((a) => a !== null)
      .map((a) => `${a} ${user.username}`)
      .join(" and ");
    adminAlert(app, after, c, did);
  });
  return noContent();
}

// ----------------------------------------------------------------- invites

export async function postInvite({ req, ip, deps: app }: Ctx<App>): Promise<Response> {
  const c = await caller(app, req, true);
  const body = await readJson(req);
  if (typeof body.service !== "string") throw new HttpError(400, "invalid_request", "service is required.");
  const service = serviceFor(app, c, body.service);
  const email = checkEmail(body.email);
  if (typeof body.role !== "string") throw new HttpError(400, "invalid_request", "role is required.");
  const limit = await emailAllowed(app.sql, email, c.kind === "client" ? `client:${c.client.id}` : `user:${c.session.userId}`);
  if (!limit.allowed) throw new HttpError(429, "rate_limited", "Too many invitations; try again later.", { "Retry-After": String(limit.retryAfter) });
  const row = await transaction(app.sql, async (tx, after) => {
    const invite = await createInvite(tx, app, { email, service, role: body.role as string, actor: actorOf(c), ip }, after);
    adminAlert(app, after, c, `invited someone to ${service.name} as ${invite.role}`);
    return invite;
  });
  return json(201, inviteJson(row));
}

export async function listInvites({ req, url, deps: app }: Ctx<App>): Promise<Response> {
  const c = await caller(app, req, true);
  const { after, limit } = pageParams(url);
  let service = url.searchParams.get("service") ?? "";
  if (c.kind === "client") service = c.service.name;
  else requireAdmin(c);
  const rows = await app.sql`
    SELECT id, email, service, role, invited_by, expires_at, accepted_by, accepted_at FROM invites
    WHERE (${service} = '' OR service = ${service}) AND id > ${after}
    ORDER BY id LIMIT ${limit + 1}`;
  return json(200, listOf(rows as InviteRow[], limit, (r) => r.id, inviteJson));
}

export async function getInvite({ req, params, deps: app }: Ctx<App>): Promise<Response> {
  const c = await caller(app, req, true);
  if (c.kind === "user") requireAdmin(c);
  const service = c.kind === "client" ? c.service.name : "";
  const [row] = await app.sql`
    SELECT id, email, service, role, invited_by, expires_at, accepted_by, accepted_at FROM invites WHERE id = ${params.id!} AND (${service} = '' OR service = ${service})`;
  if (!row) throw new HttpError(404, "not_found", "No such invitation.");
  return json(200, inviteJson(row as InviteRow));
}

export async function deleteInvite({ req, params, ip, deps: app }: Ctx<App>): Promise<Response> {
  const c = await caller(app, req, true);
  if (c.kind === "user") requireAdmin(c);
  const service = c.kind === "client" ? c.service.name : "";
  const removed = await transaction(app.sql, async (tx, after) => {
    const rows = await tx`DELETE FROM invites WHERE id = ${params.id!} AND (${service} = '' OR service = ${service}) RETURNING service`;
    if (rows.length === 0) return false;
    await audit(tx, { actor: actorOf(c), action: "invite.delete", ip, detail: { id: params.id!, service: rows[0].service } });
    adminAlert(app, after, c, `withdrew an invitation to ${rows[0].service}`);
    return true;
  });
  if (!removed) throw new HttpError(404, "not_found", "No such invitation.");
  return noContent();
}

// ------------------------------------------------------- services and audit

export async function listServices({ req, deps: app }: Ctx<App>): Promise<Response> {
  const c = await caller(app, req, false);
  requireAdmin(c);
  return json(200, {
    items: app.services.all().map((s) => ({
      name: s.name,
      roles: s.roles,
      mfa_roles: s.mfaRoles,
      signup: s.signup,
      default_role: s.defaultRole,
      manages_own_members: s.managesOwnMembers,
      api_key_scopes: s.apiKeyScopes,
      app_password_scopes: s.appPasswordScopes,
      clients: s.clients.map((cl) => ({ id: cl.id, type: cl.type, redirect_uris: cl.redirectUris, post_logout_redirect_uris: cl.postLogoutRedirectUris })),
      events_url: s.eventsUrl,
    })),
    next: null,
  });
}

export async function listAudit({ req, url, deps: app }: Ctx<App>): Promise<Response> {
  const c = await caller(app, req, false);
  requireAdmin(c);
  const { after, limit } = pageParams(url);
  if (after && !/^\d+$/.test(after)) throw new HttpError(400, "invalid_request", "after is not a cursor.");
  const user = url.searchParams.get("user") ?? "";
  // Newest first; the cursor is the last id seen.
  const rows = await app.sql`
    SELECT id::text AS id, at, actor, action, user_id, host(ip) AS ip, detail FROM audit
    WHERE (${user} = '' OR user_id = ${user}) AND (${after} = '' OR id < ${after || "0"}::bigint)
    ORDER BY id DESC LIMIT ${limit + 1}`;
  return json(
    200,
    listOf(rows as any[], limit, (r) => r.id, (r) => ({
      id: r.id,
      at: r.at.toISOString(),
      actor: r.actor,
      action: r.action,
      user_id: r.user_id,
      ip: r.ip,
      detail: r.detail,
    })),
  );
}
