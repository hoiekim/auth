import type { App } from "../app";
import { audit } from "../audit";
import { addressInUseEmail, resetEmail, securityNotice, verifyEmail } from "../emails";
import { factorsOf, checkSecondFactor, useRecoveryCode } from "../factors";
import { hostCookie, HttpError, readForm, redirect } from "../http";
import { acceptInvite, findLiveInvite } from "../invites";
import { isEmailAddress } from "../mail";
import { finishAuthentication } from "../passkeys";
import { BREACHED_MESSAGE, passwordProblem } from "../passwords";
import type { Ctx } from "../server";
import { endUserSessions, loadSession } from "../sessions";
import { clear, failureWait, hit, recordFailure, tooMany } from "../throttle";
import { consumeToken, emailAllowed, issueToken, peekToken } from "../tokens";
import { transaction } from "../tx";
import { findUser, findUserByLogin, insertUser, isUniqueViolation, USERNAME } from "../users";
import { checkForm, extrasWith, formToken, h, hiddenCsrf, localPath, messagePage, page } from "./layout";
import { accountKey, completeSignIn } from "./signin";

// The pages around an account's life: sign-up, invitations, activation,
// password reset and email verification (docs/DESIGN.md U5–U7, A1).

const SIGNUPS_PER_IP = 10;

async function newPasswordProblem(app: App, password: string, avoid: { username?: string | null; email?: string | null }) {
  return passwordProblem(password, avoid) ?? ((await app.breached(password)) ? BREACHED_MESSAGE : null);
}

function field(label: string, name: string, attrs: string, value = ""): string {
  return `<label>${h(label)} <input name="${h(name)}" ${attrs} value="${h(value)}"></label>`;
}

const PASSWORD_ATTRS = 'type="password" autocomplete="new-password" required minlength="12" maxlength="256"';
const USERNAME_HINT = "3–32 characters: a–z, 0–9 and '-'. It can never change.";

// ------------------------------------------------------------------- sign-up

function signupForm(app: App, req: Request, v: { returnTo: string; username?: string; name?: string; email?: string; error?: string }, status = 200) {
  const { token, cookie } = formToken(req);
  const body = `
<h1>Create an account</h1>
${v.error ? `<p class="error" role="alert">${h(v.error)}</p>` : ""}
<form method="post" action="/signup">
  ${hiddenCsrf(token)}
  <input type="hidden" name="return_to" value="${h(v.returnTo)}">
  ${field("Username", "username", 'required pattern="[a-z][a-z0-9-]{1,30}[a-z0-9]" autocomplete="username" maxlength="32"', v.username)}
  <p class="hint">${h(USERNAME_HINT)}</p>
  ${field("Name", "name", 'autocomplete="name" maxlength="200"', v.name)}
  ${field("Email", "email", 'type="email" required autocomplete="email" maxlength="254"', v.email)}
  ${field("Password", "password", PASSWORD_ATTRS)}
  <button type="submit">Create account</button>
</form>
<p class="links"><a href="/login?${new URLSearchParams({ return_to: v.returnTo })}">I have an account</a></p>`;
  return page(app, "Create an account", body, { status, extras: extrasWith(cookie) });
}

export async function getSignup({ req, url, deps: app }: Ctx<App>): Promise<Response> {
  if (!app.services.anyOpen()) return messagePage(app, 404, "Not available", "Accounts here are created by invitation.");
  return signupForm(app, req, { returnTo: localPath(url.searchParams.get("return_to")) });
}

export async function postSignup({ req, ip, deps: app }: Ctx<App>): Promise<Response> {
  if (!app.services.anyOpen()) return messagePage(app, 404, "Not available", "Accounts here are created by invitation.");
  const form = await readForm(req);
  checkForm(app, req, form);
  const v = {
    returnTo: localPath(form.get("return_to")),
    username: (form.get("username") ?? "").trim().toLowerCase(),
    name: (form.get("name") ?? "").trim(),
    email: (form.get("email") ?? "").trim(),
  };
  const password = form.get("password") ?? "";
  const again = (error: string, status = 400) => signupForm(app, req, { ...v, error }, status);
  if (!USERNAME.test(v.username)) return again(`That username can't be used. ${USERNAME_HINT}`);
  if ([...v.name].length > 200 || /[\u0000-\u001f\u007f]/.test(v.name)) return again("That name is too long.");
  if (!isEmailAddress(v.email)) return again("That is not an email address.");
  const problem = await newPasswordProblem(app, password, v);
  if (problem) return again(problem);

  const perIp = await hit(app.sql, `signup:ip:${ip ?? "unknown"}`, SIGNUPS_PER_IP, 3600);
  if (!perIp.allowed) return again("Too many accounts were created from your network. Try again later.", 429);
  const mail = await emailAllowed(app.sql, v.email, `ip:${ip ?? "unknown"}`);
  if (!mail.allowed) return again("Too many emails were sent to that address. Try again later.", 429);

  const hash = await app.hasher.hash(password);
  let userId: string;
  try {
    userId = await transaction(app.sql, async (tx, after) => {
      // The address is set only once verified, so a sign-up can't take or
      // reveal an address another account uses (§9.4).
      const id = await insertUser(tx, { username: v.username, name: v.name, email: null, emailVerified: false, kind: "person", ownerId: null, passwordHash: hash });
      const [taken] = await tx`SELECT 1 FROM users WHERE lower(email) = lower(${v.email})`;
      if (taken) after(() => app.mail(addressInUseEmail(v.email)));
      else {
        const token = await issueToken(tx, "verify_email", id, v.email);
        after(() => app.mail(verifyEmail(app.config.issuer, v.email, token)));
      }
      await audit(tx, { actor: id, action: "user.signup", userId: id, ip });
      return id;
    });
  } catch (e) {
    if (e instanceof HttpError && e.status === 409) return again(e.description, 409);
    throw e;
  }
  return completeSignIn(app, req, ip, userId, ["pwd"], v.returnTo, "signup");
}

// ---------------------------------------------------------------- invitation

export async function getInvite({ req, url, deps: app }: Ctx<App>): Promise<Response> {
  const token = url.searchParams.get("token");
  const invite = await findLiveInvite(app.sql, token);
  if (!invite) return messagePage(app, 404, "Invitation not valid", "This invitation has expired or was already used.");
  const session = await loadSession(app, req);
  const { token: csrf, cookie } = formToken(req);
  const here = `/invite?${new URLSearchParams({ token: token ?? "" })}`;
  const accept = session
    ? `<form method="post" action="/invite">
  ${hiddenCsrf(csrf)}
  <input type="hidden" name="token" value="${h(token)}">
  <input type="hidden" name="action" value="accept">
  <button type="submit">Accept as ${h(session.username)}</button>
</form>
<p class="links"><a href="/login?${new URLSearchParams({ return_to: here })}">Sign in as someone else</a></p>`
    : `<p><a class="button" href="/login?${new URLSearchParams({ return_to: here })}">Sign in to accept</a></p>
<h2>Or create an account</h2>
<form method="post" action="/invite">
  ${hiddenCsrf(csrf)}
  <input type="hidden" name="token" value="${h(token)}">
  <input type="hidden" name="action" value="create">
  <p>Email: ${h(invite.email)}</p>
  ${field("Username", "username", 'required pattern="[a-z][a-z0-9-]{1,30}[a-z0-9]" autocomplete="username" maxlength="32"')}
  <p class="hint">${h(USERNAME_HINT)}</p>
  ${field("Name", "name", 'autocomplete="name" maxlength="200"')}
  ${field("Password", "password", PASSWORD_ATTRS)}
  <button type="submit">Create account and accept</button>
</form>`;
  const body = `<h1>You're invited to ${h(invite.service)}</h1>\n${accept}`;
  return page(app, "Invitation", body, { extras: extrasWith(cookie) });
}

export async function postInvite({ req, ip, deps: app }: Ctx<App>): Promise<Response> {
  const form = await readForm(req);
  checkForm(app, req, form);
  const token = form.get("token");
  const invite = await findLiveInvite(app.sql, token);
  if (!invite) return messagePage(app, 404, "Invitation not valid", "This invitation has expired or was already used.");
  const done = (service: string) =>
    messagePage(app, 200, "Invitation accepted", `You can now use ${service}.`, { href: "/account", text: "Your account" });

  if (form.get("action") === "accept") {
    const session = await loadSession(app, req);
    if (!session) return redirect(`/login?${new URLSearchParams({ return_to: `/invite?${new URLSearchParams({ token: token ?? "" })}` })}`);
    await transaction(app.sql, (tx, after) => acceptInvite(tx, app, token, session.userId, ip, after));
    return done(invite.service);
  }

  const username = (form.get("username") ?? "").trim().toLowerCase();
  const name = (form.get("name") ?? "").trim();
  const password = form.get("password") ?? "";
  const fail = (message: string, status = 400) =>
    messagePage(app, status, "Couldn't create the account", message, { href: `/invite?${new URLSearchParams({ token: token ?? "" })}`, text: "Back" });
  if (!USERNAME.test(username)) return fail(`That username can't be used. ${USERNAME_HINT}`);
  if ([...name].length > 200 || /[\u0000-\u001f\u007f]/.test(name)) return fail("That name is too long.");
  const problem = await newPasswordProblem(app, password, { username, email: invite.email });
  if (problem) return fail(problem);
  const perIp = await hit(app.sql, `signup:ip:${ip ?? "unknown"}`, SIGNUPS_PER_IP, 3600);
  if (!perIp.allowed) return fail("Too many accounts were created from your network. Try again later.", 429);

  const hash = await app.hasher.hash(password);
  let userId: string;
  try {
    userId = await transaction(app.sql, async (tx, after) => {
      // Holding the emailed link verifies the address.
      const id = await insertUser(tx, { username, name, email: invite.email, emailVerified: true, kind: "person", ownerId: null, passwordHash: hash });
      await audit(tx, { actor: id, action: "user.signup", userId: id, ip, detail: { invite: invite.id } });
      await acceptInvite(tx, app, token, id, ip, after);
      return id;
    });
  } catch (e) {
    if (e instanceof HttpError && e.status === 409) {
      return fail(
        e.description.includes("email") ? "An account already uses this address: sign in to it, then open the invitation again." : e.description,
        409,
      );
    }
    throw e;
  }
  return completeSignIn(app, req, ip, userId, ["pwd"], "/account", "signup");
}

// ---------------------------------------------------------------- activation

export async function getActivate({ req, url, deps: app }: Ctx<App>): Promise<Response> {
  const token = url.searchParams.get("token");
  const row = await peekToken(app.sql, "activate", token);
  const user = row ? await findUser(app.sql, row.user_id) : null;
  if (!row || !user) return messagePage(app, 404, "Link not valid", "This activation link has expired or was already used. Ask an administrator for a new one.");
  const { token: csrf, cookie } = formToken(req);
  const body = `
<h1>Activate your account</h1>
<p>Username: <strong>${h(user.username)}</strong></p>
<form method="post" action="/activate">
  ${hiddenCsrf(csrf)}
  <input type="hidden" name="token" value="${h(token)}">
  <input type="hidden" name="username" value="${h(user.username)}" autocomplete="username">
  ${field("Choose a password", "password", PASSWORD_ATTRS)}
  <button type="submit">Set password</button>
</form>`;
  return page(app, "Activate your account", body, { extras: extrasWith(cookie) });
}

export async function postActivate({ req, ip, deps: app }: Ctx<App>): Promise<Response> {
  const form = await readForm(req);
  checkForm(app, req, form);
  const token = form.get("token");
  const row = await peekToken(app.sql, "activate", token);
  const user = row ? await findUser(app.sql, row.user_id) : null;
  if (!row || !user) return messagePage(app, 404, "Link not valid", "This activation link has expired or was already used.");
  const password = form.get("password") ?? "";
  const problem = await newPasswordProblem(app, password, { username: user.username, email: user.email });
  if (problem) return messagePage(app, 400, "Choose another password", problem, { href: `/activate?${new URLSearchParams({ token: token ?? "" })}`, text: "Back" });
  const hash = await app.hasher.hash(password);
  const ok = await app.sql.begin(async (tx) => {
    const used = await consumeToken(tx, "activate", token);
    if (!used) return false;
    await tx`
      UPDATE users SET password_hash = ${hash}, updated_at = now(),
        email_verified_at = CASE WHEN email IS NOT NULL AND lower(email) = lower(${used.email ?? ""}) THEN now() ELSE email_verified_at END
      WHERE id = ${used.user_id}`;
    await audit(tx, { actor: used.user_id, action: "user.activate", userId: used.user_id, ip });
    return true;
  });
  if (!ok) return messagePage(app, 404, "Link not valid", "This activation link has expired or was already used.");
  return redirect(`/login?${new URLSearchParams({ login_hint: user.username, notice: "activated" })}`);
}

// --------------------------------------------------------------------- reset

function resetRequestPage(app: App, req: Request, message?: string, status = 200): Response {
  const { token, cookie } = formToken(req);
  const body = `
<h1>Reset your password</h1>
${message ? `<p class="notice" role="status">${h(message)}</p>` : ""}
<form method="post" action="/reset">
  ${hiddenCsrf(token)}
  <input type="hidden" name="action" value="email">
  ${field("Username or email", "login", 'required autocomplete="username" maxlength="254"')}
  <button type="submit">Email me a link</button>
</form>
<h2>Can't reach your email?</h2>
<p>Use one of your recovery codes instead.</p>
<form method="post" action="/reset">
  ${hiddenCsrf(token)}
  <input type="hidden" name="action" value="recovery">
  ${field("Username", "login", 'required autocomplete="username" maxlength="254"')}
  ${field("Recovery code", "code", 'required autocomplete="off" maxlength="40"')}
  ${field("New password", "password", PASSWORD_ATTRS)}
  <button type="submit">Reset with a recovery code</button>
</form>`;
  return page(app, "Reset your password", body, { status, extras: extrasWith(cookie) });
}

export async function getReset({ req, deps: app }: Ctx<App>): Promise<Response> {
  return resetRequestPage(app, req);
}

// The same answer, in the same time, whether or not the account exists: the
// email goes out after the response, if at all.
export async function postReset({ req, ip, deps: app }: Ctx<App>): Promise<Response> {
  const form = await readForm(req);
  checkForm(app, req, form);
  const login = (form.get("login") ?? "").trim().slice(0, 254);
  if (form.get("action") === "recovery") return resetWithRecoveryCode(app, req, ip, login, form);

  const sent = "If an account uses that name or address, we've sent it a link. It expires in 30 minutes.";
  if (!login) return resetRequestPage(app, req, sent);
  const limit = await emailAllowed(app.sql, login, `ip:${ip ?? "unknown"}`);
  if (!limit.allowed) {
    const res = resetRequestPage(app, req, "Too many reset emails were asked for. Try again later.", 429);
    res.headers.set("Retry-After", String(limit.retryAfter));
    return res;
  }
  const user = await findUserByLogin(app.sql, login);
  if (user && user.kind === "person" && !user.disabled_at && user.email) {
    await transaction(app.sql, async (tx, after) => {
      const token = await issueToken(tx, "reset", user.id, user.email);
      await audit(tx, { actor: null, action: "reset.requested", userId: user.id, ip });
      after(() => app.mail(resetEmail(app.config.issuer, user.email!, token)));
    });
  }
  return resetRequestPage(app, req, sent);
}

// U6 without email: a recovery code stands in for the link. It is held to
// the sign-in limits (§9.4), and the next sign-in still needs the second
// factor.
async function resetWithRecoveryCode(app: App, req: Request, ip: string | null, login: string, form: URLSearchParams): Promise<Response> {
  const fail = (message: string, status = 400, headers: Record<string, string> = {}) => {
    const res = resetRequestPage(app, req, message, status);
    for (const [k, v] of Object.entries(headers)) res.headers.set(k, v);
    return res;
  };
  const perIp = await hit(app.sql, `ip:${ip ?? "unknown"}:login`, 30, 15 * 60);
  if (!perIp.allowed) return fail("Too many attempts from your network. Try again later.", 429, tooMany(perIp));
  const user = await findUserByLogin(app.sql, login);
  const key = user ? accountKey(user.id) : `login:name:${login.toLowerCase()}`;
  const wait = await failureWait(app.sql, key);
  if (!wait.allowed) return fail("Too many failed attempts. Try again later.", 429, tooMany(wait));
  const password = form.get("password") ?? "";
  // Checked before the code is spent, so a refused password doesn't cost one.
  const problem = await newPasswordProblem(app, password, { username: login, email: user?.email });
  if (problem) return fail(problem);
  const live = user && user.kind === "person" && !user.disabled_at ? user : null;
  const used = await useRecoveryCode(app.sql, live?.id ?? null, (form.get("code") ?? "").slice(0, 40));
  if (!used || !live) {
    await recordFailure(app.sql, key);
    await audit(app.sql, { actor: null, action: "reset.fail", userId: user?.id ?? null, ip, detail: { method: "recovery_code" } });
    return fail("That username and recovery code don't match.", 401);
  }
  await finishReset(app, live.id, live.username, live.email, await app.hasher.hash(password), ip, "recovery_code");
  return redirect(`/login?${new URLSearchParams({ login_hint: live.username, notice: "reset" })}`);
}

async function finishReset(app: App, userId: string, username: string, email: string | null, hash: string, ip: string | null, method: string) {
  await transaction(app.sql, async (tx, after) => {
    await tx`UPDATE users SET password_hash = ${hash}, updated_at = now() WHERE id = ${userId}`;
    // A reset ends every session and refresh token (§9.1).
    await endUserSessions(tx, app, userId);
    await audit(tx, { actor: userId, action: "password.reset", userId, ip, detail: { method } });
    if (method === "recovery_code") await audit(tx, { actor: userId, action: "recovery.used", userId, ip });
    if (email) {
      after(() => app.mail(securityNotice(email, username, "password reset")));
      if (method === "recovery_code") after(() => app.mail(securityNotice(email, username, "a recovery code was used")));
    }
  });
  await clear(app.sql, accountKey(userId));
}

export async function getResetConfirm({ req, url, deps: app }: Ctx<App>): Promise<Response> {
  const token = url.searchParams.get("token");
  const row = await peekToken(app.sql, "reset", token);
  const user = row ? await findUser(app.sql, row.user_id) : null;
  if (!row || !user) return messagePage(app, 404, "Link not valid", "This reset link has expired or was already used.", { href: "/reset", text: "Ask for a new one" });
  const factors = await factorsOf(app.sql, user.id);
  const { token: csrf, cookie } = formToken(req);
  const second = factors.totp
    ? field("The 6-digit code from your authenticator app, or a recovery code", "code", 'required autocomplete="one-time-code" maxlength="40"')
    : factors.passkeys > 0
      ? `<input type="hidden" name="passkey" id="passkey-response">
  <p>Confirm with your passkey, or enter a recovery code.</p>
  <button type="button" id="passkey-confirm">Use my passkey</button>
  <p class="error" id="passkey-error" role="alert" hidden></p>
  ${field("Recovery code", "code", 'autocomplete="off" maxlength="40"')}`
      : "";
  const body = `
<h1>Choose a new password</h1>
<form method="post" action="/reset/confirm" id="reset-form">
  ${hiddenCsrf(csrf)}
  <input type="hidden" name="token" value="${h(token)}">
  <input type="hidden" name="username" value="${h(user.username)}" autocomplete="username">
  ${field("New password", "password", PASSWORD_ATTRS)}
  ${second}
  <button type="submit">Change password</button>
</form>`;
  return page(app, "Choose a new password", body, { scripts: factors.passkeys > 0 && !factors.totp ? ["signin.js"] : [], extras: extrasWith(cookie) });
}

// A reset link also needs the second factor when one is enrolled (§9.1).
export async function postResetConfirm({ req, ip, deps: app }: Ctx<App>): Promise<Response> {
  const form = await readForm(req);
  checkForm(app, req, form);
  const token = form.get("token");
  const back = { href: `/reset/confirm?${new URLSearchParams({ token: token ?? "" })}`, text: "Back" };
  const row = await peekToken(app.sql, "reset", token);
  const user = row ? await findUser(app.sql, row.user_id) : null;
  if (!row || !user || user.disabled_at) return messagePage(app, 404, "Link not valid", "This reset link has expired or was already used.");

  // Checked before the second factor, so a refused password doesn't spend a
  // code.
  const password = form.get("password") ?? "";
  const problem = await newPasswordProblem(app, password, { username: user.username, email: user.email });
  if (problem) return messagePage(app, 400, "Choose another password", problem, back);
  const factors = await factorsOf(app.sql, user.id);
  let method = "email";
  if (factors.totp || factors.passkeys > 0) {
    const attempts = await hit(app.sql, `reset:${user.id}:second-factor`, 5, 30 * 60);
    if (!attempts.allowed) return messagePage(app, 429, "Too many attempts", "Too many wrong codes. Try again later.", back);
    const code = (form.get("code") ?? "").trim().slice(0, 40);
    let ok = false;
    if (factors.totp) {
      const kind = code ? await checkSecondFactor(app.sql, app, user.id, code) : null;
      ok = kind !== null;
      if (kind === "recovery") method = "email+recovery_code";
    } else if (code) {
      ok = await useRecoveryCode(app.sql, user.id, code);
      if (ok) method = "email+recovery_code";
    } else {
      let response: unknown = null;
      try {
        response = JSON.parse(form.get("passkey") ?? "null");
      } catch {
        response = null;
      }
      ok = (await finishAuthentication(app, hostCookie(req, "webauthn"), response)) === user.id;
    }
    if (!ok) {
      await audit(app.sql, { actor: null, action: "reset.fail", userId: user.id, ip, detail: { method: "second_factor" } });
      return messagePage(app, 401, "Second factor didn't work", "That code or passkey didn't work.", back);
    }
  }
  const hash = await app.hasher.hash(password);
  const used = await app.sql.begin((tx) => consumeToken(tx, "reset", token));
  if (!used || used.user_id !== user.id) return messagePage(app, 404, "Link not valid", "This reset link has expired or was already used.");
  await finishReset(app, user.id, user.username, user.email, hash, ip, method === "email+recovery_code" ? "recovery_code" : method);
  return redirect(`/login?${new URLSearchParams({ login_hint: user.username, notice: "reset" })}`);
}

// -------------------------------------------------------- email verification

export async function getVerifyEmail({ req, url, deps: app }: Ctx<App>): Promise<Response> {
  const token = url.searchParams.get("token");
  const row = await peekToken(app.sql, "verify_email", token);
  if (!row) return messagePage(app, 404, "Link not valid", "This link has expired or was already used.");
  const { token: csrf, cookie } = formToken(req);
  // A button, not the link itself, confirms: mail scanners open links.
  const body = `
<h1>Confirm your email address</h1>
<p>${h(row.email)}</p>
<form method="post" action="/verify-email">
  ${hiddenCsrf(csrf)}
  <input type="hidden" name="token" value="${h(token)}">
  <button type="submit">Confirm</button>
</form>`;
  return page(app, "Confirm your email address", body, { extras: extrasWith(cookie) });
}

export async function postVerifyEmail({ req, ip, deps: app }: Ctx<App>): Promise<Response> {
  const form = await readForm(req);
  checkForm(app, req, form);
  const token = form.get("token");
  try {
    const ok = await app.sql.begin(async (tx) => {
      const used = await consumeToken(tx, "verify_email", token);
      if (!used || !used.email) return false;
      await tx`UPDATE users SET email = ${used.email}, email_verified_at = now(), updated_at = now() WHERE id = ${used.user_id}`;
      await audit(tx, { actor: used.user_id, action: "email.verify", userId: used.user_id, ip });
      return true;
    });
    if (!ok) return messagePage(app, 404, "Link not valid", "This link has expired or was already used.");
  } catch (e) {
    if (isUniqueViolation(e, "users_email")) {
      return messagePage(app, 409, "Address in use", "Another account already uses this address, so it can't be added to this one.");
    }
    throw e;
  }
  return messagePage(app, 200, "Address confirmed", "Your email address is confirmed.", { href: "/account", text: "Your account" });
}

// ------------------------------------------------------------- MFA required

export async function getMfaRequired({ url, deps: app }: Ctx<App>): Promise<Response> {
  const service = (url.searchParams.get("service") ?? "").slice(0, 64);
  const returnTo = localPath(url.searchParams.get("return_to"));
  const body = `
<h1>Two-factor authentication needed</h1>
<p>Your role on ${h(service)} needs a second factor. Add an authenticator app or a passkey to your account, then continue.</p>
<p><a class="button" href="/account#security">Set up a second factor</a></p>
<p class="links"><a href="${h(returnTo)}">Continue to ${h(service)}</a></p>`;
  return page(app, "Two-factor authentication needed", body);
}
