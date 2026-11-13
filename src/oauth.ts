import type { SQL } from "bun";
import { roleAtSignIn, roleOf } from "./access";
import type { App } from "./app";
import { audit } from "./audit";
import { authenticateClient } from "./clients";
import { base64url, newId, randomToken, safeEqual, sha256 } from "./crypto";
import { factorsOf } from "./factors";
import { introspectSecret } from "./credentials";
import { emitSessionEnded } from "./events";
import { errorResponse, HttpError, json, readForm, redirect, single } from "./http";
import { signJwt, verifyJwt } from "./jwt";
import { parseIp, formatIp } from "./net";
import { h, messagePage, page } from "./pages/layout";
import type { Ctx } from "./server";
import type { Client, Service } from "./services";
import { clearSessionCookie, endSession, hasMfa, loadSession, touch } from "./sessions";
import { hit, peek, tooMany } from "./throttle";
import { transaction } from "./tx";

// The OAuth 2.0 and OpenID Connect endpoints (docs/DESIGN.md §7.1–§7.3): the
// authorization code flow with PKCE and nothing more.

const ACCESS_TOKEN_SECONDS = 600;
const CODE_SECONDS = 60;
const PUBLIC_REFRESH_DAYS = 30;
const REUSE_GRACE_SECONDS = 30;

export async function discovery({ deps: app }: Ctx<App>): Promise<Response> {
  const iss = app.config.issuer;
  return json(
    200,
    {
      issuer: iss,
      authorization_endpoint: `${iss}/oauth/authorize`,
      token_endpoint: `${iss}/oauth/token`,
      userinfo_endpoint: `${iss}/oauth/userinfo`,
      jwks_uri: `${iss}/.well-known/jwks.json`,
      end_session_endpoint: `${iss}/logout`,
      revocation_endpoint: `${iss}/oauth/revoke`,
      introspection_endpoint: `${iss}/oauth/introspect`,
      response_types_supported: ["code"],
      response_modes_supported: ["query"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["EdDSA"],
      token_endpoint_auth_methods_supported: ["client_secret_basic", "none"],
      revocation_endpoint_auth_methods_supported: ["client_secret_basic", "none"],
      introspection_endpoint_auth_methods_supported: ["client_secret_basic"],
      code_challenge_methods_supported: ["S256"],
      scopes_supported: ["openid", "profile", "email"],
      prompt_values_supported: ["none", "login"],
      claims_supported: ["iss", "sub", "aud", "iat", "exp", "sid", "username", "name", "role", "nonce", "auth_time", "amr", "email", "email_verified"],
    },
    { "Cache-Control": "public, max-age=3600" },
  );
}

export async function jwks({ deps: app }: Ctx<App>): Promise<Response> {
  return json(200, await app.keys.jwks(), { "Cache-Control": "public, max-age=3600" });
}

// RFC 7636 §4.1: 43 to 128 unreserved characters.
const VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;
const CHALLENGE = /^[A-Za-z0-9_-]{43}$/;

// ---------------------------------------------------------------- authorize

// Errors that can't be sent back to the client (an unknown client or an
// unregistered redirect URI) are shown here, never redirected (RFC 6749
// §4.1.2.1).
function authorizeErrorPage(app: App, message: string): Response {
  return messagePage(app, 400, "This sign-in link is not valid", message);
}

function backToClient(redirectUri: string, params: Record<string, string>): Response {
  const url = new URL(redirectUri);
  for (const [k, v] of Object.entries(params)) url.searchParams.append(k, v);
  return redirect(url.toString(), {}, 302);
}

export async function authorize({ req, url, ip, deps: app }: Ctx<App>): Promise<Response> {
  const q = url.searchParams;
  let clientId: string | null;
  let redirectUri: string | null;
  try {
    clientId = single(q, "client_id");
    redirectUri = single(q, "redirect_uri");
  } catch {
    return authorizeErrorPage(app, "A parameter is repeated.");
  }
  const client = clientId ? app.services.client(clientId) : undefined;
  if (!client) return authorizeErrorPage(app, "The app that sent you here is not registered.");
  if (!redirectUri || !client.redirectUris.includes(redirectUri)) {
    return authorizeErrorPage(app, "The app sent you here with a return address it hasn't registered.");
  }
  const service = app.services.get(client.service)!;

  let state: string | null = null;
  const fail = (error: string, description: string) =>
    backToClient(redirectUri, { error, error_description: description, ...(state !== null ? { state } : {}) });
  const names = ["response_type", "state", "code_challenge", "code_challenge_method", "scope", "nonce", "prompt", "max_age", "login_hint"] as const;
  let params: Record<(typeof names)[number], string | null>;
  try {
    params = Object.fromEntries(names.map((n) => [n, single(q, n)])) as typeof params;
  } catch {
    return fail("invalid_request", "A parameter is repeated.");
  }
  state = params.state ?? null;
  if (params.response_type !== "code") return fail("unsupported_response_type", "Only response_type=code is supported.");
  if (!state || state.length > 1024) return fail("invalid_request", "state is required.");
  if (!params.code_challenge || !CHALLENGE.test(params.code_challenge) || params.code_challenge_method !== "S256") {
    return fail("invalid_request", "PKCE is required: code_challenge with code_challenge_method=S256.");
  }
  const scopes = (params.scope ?? "").split(" ").filter(Boolean);
  const nonce = params.nonce;
  if (scopes.includes("openid") && !nonce) return fail("invalid_request", "nonce is required with the openid scope.");
  if (nonce && nonce.length > 1024) return fail("invalid_request", "nonce is too long.");
  const prompt = params.prompt;
  if (prompt !== null && prompt !== "none" && prompt !== "login") return fail("invalid_request", "prompt may be none or login.");
  let maxAge: number | null = null;
  if (params.max_age !== null) {
    if (!/^\d{1,9}$/.test(params.max_age)) return fail("invalid_request", "max_age must be a whole number of seconds.");
    maxAge = Number(params.max_age);
  }

  const session = await loadSession(app, req);
  const needSignIn = !session || prompt === "login" || (maxAge !== null && session.authAge > maxAge);
  if (needSignIn) {
    if (prompt === "none") return fail("login_required", "The user is not signed in.");
    // Back here after the sign-in, which is then fresh: prompt and max_age
    // have done their job and are left out, or they would ask again.
    const back = new URL(url);
    back.searchParams.delete("prompt");
    back.searchParams.delete("max_age");
    const login = new URLSearchParams({ return_to: `${back.pathname}${back.search}` });
    if (params.login_hint && params.login_hint.length <= 254) login.set("login_hint", params.login_hint);
    return redirect(`/login?${login}`, {}, 302);
  }

  const outcome = await transaction(app.sql, async (tx, after) => {
    const role = await roleAtSignIn(tx, app, session.userId, service, ip, after);
    if (!role) return { kind: "no_access" as const };
    if (service.mfaRoles.includes(role) && !hasMfa(session)) return { kind: "needs_mfa" as const };
    const code = randomToken();
    await tx`
      INSERT INTO auth_codes (code_hash, client_id, session_id, redirect_uri, code_challenge, nonce, expires_at)
      VALUES (${sha256(code)}, ${client.id}, ${session.id}, ${redirectUri}, ${params.code_challenge}, ${nonce},
              now() + make_interval(secs => ${CODE_SECONDS}))`;
    return { kind: "code" as const, code };
  });

  if (outcome.kind === "no_access") {
    if (prompt === "none") return fail("access_denied", "The user has no access to this service.");
    return messagePage(app, 403, "No access", `You don't have access to ${service.name}. Ask an administrator for access.`, {
      href: "/account",
      text: "Your account",
    });
  }
  if (outcome.kind === "needs_mfa") {
    if (prompt === "none") return fail("interaction_required", "This role needs a sign-in with a second factor.");
    const factors = await factorsOf(app.sql, session.userId);
    const back = `${url.pathname}${url.search}`;
    if (factors.totp || factors.passkeys > 0) {
      return redirect(`/login?${new URLSearchParams({ return_to: back, second_factor: service.name })}`, {}, 302);
    }
    return redirect(`/mfa-required?${new URLSearchParams({ service: service.name, return_to: back })}`, {}, 302);
  }
  return backToClient(redirectUri, { code: outcome.code, state });
}

// -------------------------------------------------------------------- token

interface Holder {
  userId: string;
  username: string;
  name: string;
  email: string | null;
  emailVerified: boolean;
}

async function holder(sql: SQL, userId: string): Promise<Holder | null> {
  const [u] = await sql`
    SELECT id, username, name, email, email_verified_at IS NOT NULL AS email_verified FROM users
    WHERE id = ${userId} AND disabled_at IS NULL`;
  return u ? { userId: u.id, username: u.username, name: u.name, email: u.email, emailVerified: u.email_verified } : null;
}

// Claims are the ones §7.3 lists, and no others.
async function accessToken(app: App, user: Holder, service: string, sid: string, role: string, now: number): Promise<string> {
  return signJwt(
    "at+jwt",
    { iss: app.config.issuer, sub: user.userId, aud: service, iat: now, exp: now + ACCESS_TOKEN_SECONDS, sid, username: user.username, name: user.name, role },
    await app.keys.signer(),
  );
}

function tokenError(status: number, error: "invalid_request" | "invalid_grant" | "unsupported_grant_type", description: string): never {
  throw new HttpError(status, error, description);
}

// A role that needs MFA, held by a sign-in that didn't use it, gets no token
// (§9.1), so a promotion takes effect at the next refresh.
function mfaMissing(service: Service, role: string, amr: string[]): boolean {
  return service.mfaRoles.includes(role) && !amr.includes("mfa");
}

export async function token({ req, deps: app }: Ctx<App>): Promise<Response> {
  const form = await readForm(req);
  const client = await authenticateClient(app, req, form, true);
  const limit = await hit(app.sql, `client:${client.id}:token`, 60, 60);
  if (!limit.allowed) throw new HttpError(429, "rate_limited", "Too many token requests.", tooMany(limit));
  const grant = single(form, "grant_type");
  const service = app.services.get(client.service)!;
  const res =
    grant === "authorization_code"
      ? await codeGrant(app, client, service, form)
      : grant === "refresh_token"
        ? await refreshGrant(app, client, service, form)
        : tokenError(400, "unsupported_grant_type", "Use authorization_code or refresh_token.");
  res.headers.set("Pragma", "no-cache");
  return res;
}

async function codeGrant(app: App, client: Client, service: Service, form: URLSearchParams): Promise<Response> {
  const code = single(form, "code");
  const redirectUri = single(form, "redirect_uri");
  const verifier = single(form, "code_verifier");
  if (!code || !redirectUri || !verifier) tokenError(400, "invalid_request", "code, redirect_uri and code_verifier are required.");
  if (!VERIFIER.test(verifier)) tokenError(400, "invalid_request", "code_verifier is malformed.");

  const result = await app.sql.begin(async (tx) => {
    // Marked used before anything else is checked, in one statement, so a
    // code is redeemed at most once however many requests race.
    const [row] = await tx`
      UPDATE auth_codes SET used_at = now()
      WHERE code_hash = ${sha256(code.length <= 256 ? code : "")} AND used_at IS NULL
      RETURNING client_id, session_id, redirect_uri, code_challenge, nonce, expires_at > now() AS live`;
    if (!row || !row.live) return null;
    if (row.client_id !== client.id || row.redirect_uri !== redirectUri) return null;
    if (!safeEqual(base64url(sha256(verifier)), row.code_challenge)) return null;
    const [s] = await tx`
      SELECT s.id, s.user_id, s.amr, extract(epoch FROM s.auth_time)::bigint AS auth_time
      FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.id = ${row.session_id} AND s.expires_at > now() AND s.ends_at > now() AND u.disabled_at IS NULL`;
    if (!s) return null;
    const role = await roleOf(tx, s.user_id, service.name);
    if (!role || mfaMissing(service, role, s.amr)) return null;
    const user = await holder(tx, s.user_id);
    if (!user) return null;
    const refresh = `rt_${randomToken()}`;
    // A confidential client's token lives and dies with the SSO session; a
    // public client's family outlives it, and its id is the tokens' sid.
    const sid = client.type === "public" ? newId("ses") : s.id;
    if (client.type === "public") {
      await tx`
        INSERT INTO refresh_tokens (token_hash, family_id, session_id, user_id, client_id, expires_at, amr)
        VALUES (${sha256(refresh)}, ${sid}, NULL, ${s.user_id}, ${client.id}, now() + make_interval(days => ${PUBLIC_REFRESH_DAYS}), ${tx.array(s.amr, "TEXT")})`;
    } else {
      await tx`
        INSERT INTO refresh_tokens (token_hash, family_id, session_id, user_id, client_id, expires_at, amr)
        SELECT ${sha256(refresh)}, id, id, user_id, ${client.id}, ends_at, amr FROM sessions WHERE id = ${s.id}`;
    }
    await touch(tx, s.id);
    return { user, role, sid, refresh, amr: s.amr as string[], authTime: Number(s.auth_time), nonce: row.nonce as string | null };
  });
  if (!result) tokenError(400, "invalid_grant", "The authorization code is invalid, expired or used.");

  const now = Math.floor(Date.now() / 1000);
  const signer = await app.keys.signer();
  const idToken = signJwt(
    "JWT",
    {
      iss: app.config.issuer,
      sub: result.user.userId,
      aud: client.id,
      iat: now,
      exp: now + ACCESS_TOKEN_SECONDS,
      sid: result.sid,
      username: result.user.username,
      name: result.user.name,
      role: result.role,
      ...(result.nonce ? { nonce: result.nonce } : {}),
      auth_time: result.authTime,
      amr: result.amr,
      email: result.user.email,
      email_verified: result.user.emailVerified,
    },
    signer,
  );
  return json(200, {
    access_token: await accessToken(app, result.user, service.name, result.sid, result.role, now),
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_SECONDS,
    refresh_token: result.refresh,
    id_token: idToken,
  });
}

async function refreshGrant(app: App, client: Client, service: Service, form: URLSearchParams): Promise<Response> {
  const presented = single(form, "refresh_token");
  if (!presented) tokenError(400, "invalid_request", "refresh_token is required.");
  const hash = sha256(presented.length <= 256 ? presented : "");

  const result = await transaction(app.sql, async (tx, after) => {
    const [rt] = await tx`
      SELECT r.family_id, r.session_id, r.user_id, r.client_id, r.revoked_at IS NOT NULL AS revoked,
             r.expires_at > now() AS live, r.rotated_at IS NOT NULL AS rotated,
             r.rotated_at > now() - make_interval(secs => ${REUSE_GRACE_SECONDS}) AS in_grace,
             r.amr, s.amr AS session_amr, (s.expires_at > now() AND s.ends_at > now()) AS session_live
      FROM refresh_tokens r LEFT JOIN sessions s ON s.id = r.session_id
      WHERE r.token_hash = ${hash}
      FOR UPDATE OF r`;
    if (!rt || rt.client_id !== client.id || rt.revoked || !rt.live) return null;
    let amr: string[];
    if (client.type === "confidential") {
      if (!rt.session_id || !rt.session_live) return null;
      amr = rt.session_amr;
    } else {
      // Rotation (OAuth 2.1 §4.3.1): a token used again past the grace
      // period means two parties hold it, so the whole family ends.
      if (rt.rotated && !rt.in_grace) {
        await tx`UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = ${rt.family_id} AND revoked_at IS NULL`;
        await emitSessionEnded(tx, app, rt.family_id);
        await audit(tx, { actor: null, action: "refresh.reuse", userId: rt.user_id, detail: { client: client.id } });
        after(() => app.alert(`auth: a reused refresh token ended a session family of ${rt.user_id} (${client.id})`));
        return { reused: true as const };
      }
      amr = rt.amr;
    }
    const role = await roleOf(tx, rt.user_id, service.name);
    if (!role || mfaMissing(service, role, amr)) return null;
    const user = await holder(tx, rt.user_id);
    if (!user) return null;
    let next: string | undefined;
    if (client.type === "public") {
      next = `rt_${randomToken()}`;
      await tx`UPDATE refresh_tokens SET rotated_at = COALESCE(rotated_at, now()) WHERE token_hash = ${hash}`;
      await tx`
        INSERT INTO refresh_tokens (token_hash, family_id, session_id, user_id, client_id, expires_at, amr)
        VALUES (${sha256(next)}, ${rt.family_id}, NULL, ${rt.user_id}, ${client.id}, now() + make_interval(days => ${PUBLIC_REFRESH_DAYS}), ${tx.array(amr, "TEXT")})`;
    } else {
      await touch(tx, rt.session_id);
    }
    return { reused: false as const, user, role, sid: rt.family_id as string, next };
  });
  if (!result || result.reused) tokenError(400, "invalid_grant", "The refresh token is invalid, expired or revoked.");
  const now = Math.floor(Date.now() / 1000);
  return json(200, {
    access_token: await accessToken(app, result.user, service.name, result.sid, result.role, now),
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_SECONDS,
    ...(result.next ? { refresh_token: result.next } : {}),
  });
}

// ------------------------------------------------------------------- revoke

// RFC 7009: refresh tokens only, and only the caller's own. The answer is 200
// whether or not the token was known. A public client's revocation ends its
// whole family, since it is signing out.
export async function revoke({ req, deps: app }: Ctx<App>): Promise<Response> {
  const form = await readForm(req);
  const client = await authenticateClient(app, req, form, true);
  const presented = single(form, "token");
  if (!presented) throw new HttpError(400, "invalid_request", "token is required.");
  const hash = sha256(presented.length <= 256 ? presented : "");
  await app.sql.begin(async (tx) => {
    const [rt] = await tx`
      UPDATE refresh_tokens SET revoked_at = now()
      WHERE token_hash = ${hash} AND client_id = ${client.id} AND revoked_at IS NULL
      RETURNING family_id, user_id`;
    if (rt && client.type === "public") {
      await tx`UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = ${rt.family_id} AND revoked_at IS NULL`;
    }
  });
  return json(200, {});
}

// --------------------------------------------------------------- introspect

// Failures counted per client, and per end-user address the client names,
// so a protocol server's brute-force limits hold (§9.4).
const INTROSPECT_PER_MINUTE = 600;
const FAILURES_PER_ADDRESS = 10;
const FAILURES_PER_ADDRESS_WINDOW = 15 * 60;
const FAILURES_PER_CLIENT = 1000;
const FAILURES_PER_CLIENT_WINDOW = 60 * 60;

export async function introspect({ req, deps: app }: Ctx<App>): Promise<Response> {
  const form = await readForm(req);
  const client = await authenticateClient(app, req, form, false);
  const limit = await hit(app.sql, `client:${client.id}:introspect`, INTROSPECT_PER_MINUTE, 60);
  if (!limit.allowed) throw new HttpError(429, "rate_limited", "Too many introspection requests.", tooMany(limit));
  const secret = single(form, "token");
  if (!secret) throw new HttpError(400, "invalid_request", "token is required.");

  // Only for this counter: the client vouches for its own end user's address.
  const named = req.headers.get("X-Real-IP");
  const parsed = named ? parseIp(named) : null;
  const addressKey = parsed ? `client:${client.id}:introspect-fail:${formatIp(parsed)}` : null;
  const clientKey = `client:${client.id}:introspect-fail`;
  for (const [key, max, window] of [
    [clientKey, FAILURES_PER_CLIENT, FAILURES_PER_CLIENT_WINDOW],
    ...(addressKey ? [[addressKey, FAILURES_PER_ADDRESS, FAILURES_PER_ADDRESS_WINDOW] as const] : []),
  ] as const) {
    const v = await peek(app.sql, key, max, window);
    if (!v.allowed) throw new HttpError(429, "rate_limited", "Too many failed checks.", tooMany(v));
  }

  const found = await introspectSecret(app.sql, client.service, secret);
  if (!found) {
    await hit(app.sql, clientKey, FAILURES_PER_CLIENT, FAILURES_PER_CLIENT_WINDOW);
    if (addressKey) await hit(app.sql, addressKey, FAILURES_PER_ADDRESS, FAILURES_PER_ADDRESS_WINDOW);
    return json(200, { active: false });
  }
  return json(200, {
    active: true,
    sub: found.userId,
    username: found.username,
    scope: found.scopes.join(" "),
    role: found.role,
    jti: found.id,
  });
}

// ----------------------------------------------------------------- userinfo

export async function userinfo({ req, deps: app }: Ctx<App>): Promise<Response> {
  const header = req.headers.get("Authorization") ?? "";
  const m = /^Bearer ([A-Za-z0-9._-]+)$/.exec(header.trim());
  const unauthorized = () =>
    errorResponse(401, "invalid_token", "The access token is missing, invalid or expired.", {
      "WWW-Authenticate": 'Bearer error="invalid_token"',
    });
  if (!m?.[1]) return unauthorized();
  await app.keys.refresh();
  const claims = verifyJwt(m[1], (kid) => app.keys.publicKey(kid), {
    typ: "at+jwt",
    issuer: app.config.issuer,
    audience: app.services.all().map((s) => s.name),
    nowSeconds: Math.floor(Date.now() / 1000),
  });
  if (!claims || typeof claims.sub !== "string") return unauthorized();
  const user = await holder(app.sql, claims.sub);
  if (!user) return unauthorized();
  return json(200, {
    sub: user.userId,
    username: user.username,
    preferred_username: user.username,
    name: user.name,
    email: user.email,
    email_verified: user.emailVerified,
  });
}

// ------------------------------------------------------------------- logout

// RP-initiated logout (§7.1): ends the SSO session, tells every app that
// holds tokens under it, and returns to a registered address.
export async function logout({ req, url, ip, deps: app }: Ctx<App>): Promise<Response> {
  const q = url.searchParams;
  let clientId: string | null;
  let target: string | null;
  let state: string | null;
  try {
    clientId = single(q, "client_id");
    target = single(q, "post_logout_redirect_uri");
    state = single(q, "state");
  } catch {
    return messagePage(app, 400, "Sign-out failed", "A parameter is repeated.");
  }
  if (target !== null) {
    const client = clientId ? app.services.client(clientId) : undefined;
    if (!client || !client.postLogoutRedirectUris.includes(target)) {
      return messagePage(app, 400, "Sign-out failed", "The app sent you here with a return address it hasn't registered.");
    }
  }
  const session = await loadSession(app, req);
  if (session) {
    await app.sql.begin(async (tx) => {
      await endSession(tx, app, session.id);
      await audit(tx, { actor: session.userId, action: "logout", userId: session.userId, ip, detail: { client: clientId } });
    });
  }
  const extras = { cookies: [clearSessionCookie()] };
  if (target !== null) {
    const back = new URL(target);
    if (state !== null && state.length <= 1024) back.searchParams.append("state", state);
    return redirect(back.toString(), extras, 302);
  }
  return page(app, "Signed out", `<h1>Signed out</h1>\n<p>You are signed out.</p>\n<p><a href="/login">${h("Sign in again")}</a></p>`, { extras });
}
