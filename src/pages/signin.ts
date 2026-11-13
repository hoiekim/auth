import type { App } from "../app";
import { audit } from "../audit";
import { base64url, randomToken, sha256 } from "../crypto";
import { securityNotice } from "../emails";
import { factorsOf, checkSecondFactor } from "../factors";
import { clearCookie, hostCookie, HttpError, json, readForm, readJson, redirect, setCookie } from "../http";
import { authenticationOptions, finishAuthentication } from "../passkeys";
import type { Ctx } from "../server";
import { loadSession, requireOrigin, sessionCookie, signInSession } from "../sessions";
import { clear, failureWait, hit, recordFailure, tooMany } from "../throttle";
import { transaction } from "../tx";
import { findUser, findUserByLogin } from "../users";
import { checkForm, extrasWith, formToken, h, hiddenCsrf, localPath, messagePage, page } from "./layout";

// Signing in (docs/DESIGN.md §7.1, §9.1, §9.4): a password, then TOTP or a
// recovery code when the account has TOTP; or a passkey, which is two
// factors by itself.

const PENDING = "pending";
const PENDING_SECONDS = 5 * 60;
const WEBAUTHN = "webauthn";
const DEVICE = "device";

const IP_LIMIT = 30;
const IP_WINDOW = 15 * 60;
const SECOND_FACTOR_ATTEMPTS = 5;

export function accountKey(userId: string): string {
  return `login:user:${userId}`;
}

interface Pending {
  u: string;
  id: string;
  r: string;
}

function minutes(seconds: number): string {
  const m = Math.ceil(seconds / 60);
  return m <= 1 ? "a minute" : `${m} minutes`;
}

function loginForm(app: App, req: Request, opts: { returnTo: string; login?: string; error?: string; notice?: string; status?: number }): Response {
  const { token, cookie } = formToken(req);
  const body = `
<h1>Sign in</h1>
${opts.notice ? `<p class="notice">${h(opts.notice)}</p>` : ""}
${opts.error ? `<p class="error" role="alert">${h(opts.error)}</p>` : ""}
<form method="post" action="/login">
  ${hiddenCsrf(token)}
  <input type="hidden" name="return_to" value="${h(opts.returnTo)}">
  <label>Username or email <input name="login" autocomplete="username webauthn" required maxlength="254" value="${h(opts.login ?? "")}"></label>
  <label>Password <input name="password" type="password" autocomplete="current-password" required maxlength="1024"></label>
  <button type="submit">Sign in</button>
</form>
<div class="passkey" hidden>
  <p>or</p>
  <button type="button" id="passkey-signin" data-return-to="${h(opts.returnTo)}">Sign in with a passkey</button>
  <p class="error" id="passkey-error" role="alert" hidden></p>
</div>
<p class="links"><a href="/reset">Forgot your password?</a>${app.services.anyOpen() ? ` · <a href="/signup?${new URLSearchParams({ return_to: opts.returnTo })}">Create an account</a>` : ""}</p>`;
  return page(app, "Sign in", body, { status: opts.status, scripts: ["signin.js"], extras: extrasWith(cookie) });
}

export async function getLogin({ req, url, deps: app }: Ctx<App>): Promise<Response> {
  const q = url.searchParams;
  const returnTo = localPath(q.get("return_to"));
  const service = q.get("second_factor");
  const notice = service
    ? `Your role on ${service.slice(0, 64)} needs a second factor: sign in with your password and authenticator code, or with a passkey.`
    : q.get("reauth")
      ? "Sign in again to continue."
      : q.get("notice") === "activated"
        ? "Your password is set. Sign in."
        : q.get("notice") === "reset"
          ? "Your password is changed. Sign in."
          : undefined;
  return loginForm(app, req, { returnTo, login: q.get("login_hint")?.slice(0, 254), notice });
}

export async function postLogin({ req, ip, deps: app }: Ctx<App>): Promise<Response> {
  const form = await readForm(req);
  checkForm(app, req, form);
  const returnTo = localPath(form.get("return_to"));
  const login = (form.get("login") ?? "").trim().slice(0, 254);
  const password = form.get("password") ?? "";
  const again = (error: string, status = 400, headers?: Record<string, string>) => {
    const res = loginForm(app, req, { returnTo, login, error, status });
    for (const [k, v] of Object.entries(headers ?? {})) res.headers.set(k, v);
    return res;
  };

  const perIp = await hit(app.sql, `ip:${ip ?? "unknown"}:login`, IP_LIMIT, IP_WINDOW);
  if (!perIp.allowed) return again(`Too many sign-in attempts from your network. Try again in ${minutes(perIp.retryAfter)}.`, 429, tooMany(perIp));

  // Unknown accounts are counted and delayed like known ones, so the
  // answers can't tell them apart.
  const user = await findUserByLogin(app.sql, login);
  const key = user ? accountKey(user.id) : `login:name:${login.toLowerCase()}`;
  const wait = await failureWait(app.sql, key);
  if (!wait.allowed) return again(`Too many failed attempts. Try again in ${minutes(wait.retryAfter)}.`, 429, tooMany(wait));

  const usable = user && user.kind === "person" ? user.password_hash : null;
  const check = await app.hasher.verify(password.slice(0, 1024), usable);
  if (!check.ok || !user) {
    await recordFailure(app.sql, key);
    await audit(app.sql, { actor: null, action: "login.fail", userId: user?.id ?? null, ip, detail: { method: "password" } });
    return again("Wrong username or password.", 401);
  }
  if (user.disabled_at) {
    await audit(app.sql, { actor: null, action: "login.fail", userId: user.id, ip, detail: { method: "password", reason: "disabled" } });
    return again("This account is disabled.", 403);
  }
  // An imported hash (bcrypt, older argon2 parameters) becomes today's at the
  // first sign-in that proves the password (§13).
  if (check.rehash) {
    const fresh = await app.hasher.hash(password);
    await app.sql`UPDATE users SET password_hash = ${fresh}, updated_at = now() WHERE id = ${user.id}`;
  }

  const factors = await factorsOf(app.sql, user.id);
  if (factors.totp) {
    const pending: Pending = { u: user.id, id: randomToken(), r: returnTo };
    return redirect("/login/second-factor", {
      cookies: [setCookie(PENDING, app.crypt.sealValue(PENDING, pending, PENDING_SECONDS), PENDING_SECONDS)],
    });
  }
  return completeSignIn(app, req, ip, user.id, ["pwd"], returnTo, "password");
}

function secondFactorForm(app: App, req: Request, error?: string, status = 200): Response {
  const { token, cookie } = formToken(req);
  const body = `
<h1>Second factor</h1>
${error ? `<p class="error" role="alert">${h(error)}</p>` : ""}
<form method="post" action="/login/second-factor">
  ${hiddenCsrf(token)}
  <label>The 6-digit code from your authenticator app, or a recovery code
    <input name="code" autocomplete="one-time-code" inputmode="text" required maxlength="40" autofocus></label>
  <button type="submit">Continue</button>
</form>
<p class="links"><a href="/login">Start over</a></p>`;
  return page(app, "Second factor", body, { status, extras: extrasWith(cookie) });
}

export async function getSecondFactor({ req, deps: app }: Ctx<App>): Promise<Response> {
  if (!app.crypt.openValue<Pending>(PENDING, hostCookie(req, PENDING))) return redirect("/login");
  return secondFactorForm(app, req);
}

export async function postSecondFactor({ req, ip, deps: app }: Ctx<App>): Promise<Response> {
  const form = await readForm(req);
  checkForm(app, req, form);
  const pending = app.crypt.openValue<Pending>(PENDING, hostCookie(req, PENDING));
  if (!pending) return redirect("/login");
  // Five attempts per password sign-in, then it starts over (§9.4). Each
  // failure also counts against the account, so starting over again and
  // again doesn't buy more guesses.
  const attempts = await hit(app.sql, `mfa:${pending.id}`, SECOND_FACTOR_ATTEMPTS, PENDING_SECONDS);
  const wait = await failureWait(app.sql, accountKey(pending.u));
  if (!attempts.allowed || !wait.allowed) {
    const res = messagePage(app, 429, "Too many attempts", "Too many wrong codes. Sign in again later.", { href: "/login", text: "Sign in" });
    res.headers.append("Set-Cookie", clearCookie(PENDING));
    return res;
  }
  const kind = await checkSecondFactor(app.sql, app, pending.u, (form.get("code") ?? "").slice(0, 40));
  if (!kind) {
    await recordFailure(app.sql, accountKey(pending.u));
    await audit(app.sql, { actor: null, action: "login.mfa_fail", userId: pending.u, ip });
    return secondFactorForm(app, req, "That code didn't work.", 401);
  }
  return completeSignIn(app, req, ip, pending.u, ["pwd", "otp", "mfa"], pending.r, kind === "recovery" ? "recovery_code" : "totp");
}

export async function passkeyOptions({ req, deps: app }: Ctx<App>): Promise<Response> {
  requireOrigin(app, req);
  const { options, state } = await authenticationOptions(app);
  return json(200, { options }, {}, [setCookie(WEBAUTHN, state, 300)]);
}

export async function passkeySignIn({ req, ip, deps: app }: Ctx<App>): Promise<Response> {
  requireOrigin(app, req);
  const body = await readJson(req);
  const perIp = await hit(app.sql, `ip:${ip ?? "unknown"}:login`, IP_LIMIT, IP_WINDOW);
  if (!perIp.allowed) throw new HttpError(429, "rate_limited", "Too many sign-in attempts from your network.", tooMany(perIp));
  const userId = await finishAuthentication(app, hostCookie(req, WEBAUTHN), body.response);
  if (!userId) {
    await audit(app.sql, { actor: null, action: "login.fail", ip, detail: { method: "passkey" } });
    throw new HttpError(401, "unauthorized", "That passkey sign-in didn't work.");
  }
  const res = await completeSignIn(app, req, ip, userId, ["swk", "user", "mfa"], localPath(typeof body.return_to === "string" ? body.return_to : null), "passkey");
  // The page's script follows the redirect itself.
  const location = res.headers.get("Location") ?? "/account";
  const out = json(200, { redirect: location });
  for (const c of res.headers.getSetCookie()) out.headers.append("Set-Cookie", c);
  out.headers.append("Set-Cookie", clearCookie(WEBAUTHN));
  return out;
}

// The end of every sign-in: the session, the audit row, a notice when the
// device is new, and the failure counter cleared.
export async function completeSignIn(
  app: App,
  req: Request,
  ip: string | null,
  userId: string,
  amr: string[],
  returnTo: string,
  method: string,
): Promise<Response> {
  const user = await findUser(app.sql, userId);
  if (!user || user.disabled_at || user.kind !== "person") {
    return messagePage(app, 403, "Can't sign in", "This account is disabled.", { href: "/login", text: "Back" });
  }
  const previous = await loadSession(app, req);
  const existingDevice = hostCookie(req, DEVICE);
  const device = existingDevice && /^[A-Za-z0-9_-]{43}$/.test(existingDevice) ? existingDevice : randomToken();
  const deviceId = base64url(sha256(device)).slice(0, 22);
  const userAgent = req.headers.get("User-Agent");
  const session = await transaction(app.sql, async (tx, after) => {
    const [history] = await tx`
      SELECT count(*)::int AS logins,
             count(*) FILTER (WHERE detail->>'device' = ${deviceId})::int AS on_device
      FROM audit WHERE user_id = ${userId} AND action = 'login.ok'`;
    const s = await signInSession(tx, app, userId, amr, previous, { ip, userAgent });
    await audit(tx, { actor: userId, action: "login.ok", userId, ip, detail: { method, amr, device: deviceId } });
    if (method === "recovery_code") {
      await audit(tx, { actor: userId, action: "recovery.used", userId, ip });
      if (user.email) after(() => app.mail(securityNotice(user.email!, user.username, "a recovery code was used")));
    }
    if (history.logins > 0 && history.on_device === 0 && user.email) {
      const detail = `Browser: ${(userAgent ?? "unknown").slice(0, 200)}${ip ? `\nAddress: ${ip}` : ""}`;
      after(() => app.mail(securityNotice(user.email!, user.username, "a sign-in from a new device", detail)));
    }
    return s;
  });
  await clear(app.sql, accountKey(userId));
  return redirect(returnTo, {
    cookies: [sessionCookie(session.token), clearCookie(PENDING), setCookie(DEVICE, device, 400 * 24 * 60 * 60)],
  });
}

export function pageErrors(handler: (ctx: Ctx<App>) => Promise<Response>) {
  return async (ctx: Ctx<App>): Promise<Response> => {
    try {
      return await handler(ctx);
    } catch (e) {
      if (!(e instanceof HttpError)) throw e;
      const res = messagePage(ctx.deps, e.status, "Something went wrong", e.description, { href: "/login", text: "Sign in" });
      for (const [k, v] of Object.entries(e.headers)) res.headers.set(k, v);
      return res;
    }
  };
}
