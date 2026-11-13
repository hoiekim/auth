import * as api from "./api";
import type { App } from "./app";
import { authorize, discovery, introspect, jwks, logout, revoke, token, userinfo } from "./oauth";
import { accountPage, adminPage, assetRoute, home } from "./pages/app";
import * as flows from "./pages/flows";
import { getLogin, getSecondFactor, pageErrors, passkeyOptions, passkeySignIn, postLogin, postSecondFactor } from "./pages/signin";
import { healthRoutes, Router } from "./server";

// Every endpoint. Route names are what the request log prints in place of
// the path (docs/DESIGN.md §9.3).
export function buildRouter(): Router<App> {
  const r = healthRoutes(new Router<App>());
  const pages = pageErrors;

  // OAuth and OIDC (§7.2)
  r.add("/.well-known/openid-configuration", "discovery", { GET: discovery })
    .add("/.well-known/jwks.json", "jwks", { GET: jwks })
    .add("/oauth/authorize", "authorize", { GET: authorize })
    .add("/oauth/token", "token", { POST: token })
    .add("/oauth/revoke", "revoke", { POST: revoke })
    .add("/oauth/introspect", "introspect", { POST: introspect })
    .add("/oauth/userinfo", "userinfo", { GET: userinfo, POST: userinfo })
    .add("/logout", "logout", { GET: logout });

  // Pages (§5.1 front channel)
  r.add("/", "home", { GET: home })
    .add("/login", "login", { GET: pages(getLogin), POST: pages(postLogin) })
    .add("/login/second-factor", "login.second_factor", { GET: pages(getSecondFactor), POST: pages(postSecondFactor) })
    .add("/login/passkey/options", "login.passkey_options", { POST: passkeyOptions })
    .add("/login/passkey", "login.passkey", { POST: passkeySignIn })
    .add("/signup", "signup", { GET: pages(flows.getSignup), POST: pages(flows.postSignup) })
    .add("/invite", "invite", { GET: pages(flows.getInvite), POST: pages(flows.postInvite) })
    .add("/activate", "activate", { GET: pages(flows.getActivate), POST: pages(flows.postActivate) })
    .add("/reset", "reset", { GET: pages(flows.getReset), POST: pages(flows.postReset) })
    .add("/reset/confirm", "reset.confirm", { GET: pages(flows.getResetConfirm), POST: pages(flows.postResetConfirm) })
    .add("/verify-email", "verify_email", { GET: pages(flows.getVerifyEmail), POST: pages(flows.postVerifyEmail) })
    .add("/mfa-required", "mfa_required", { GET: pages(flows.getMfaRequired) })
    .add("/account", "account", { GET: accountPage })
    .add("/admin", "admin", { GET: adminPage })
    .add("/assets/:file", "asset", { GET: assetRoute });

  // Management API, self-service (§7.5)
  r.add("/v1/me", "v1.me", { GET: api.getMe, PATCH: api.patchMe, DELETE: api.deleteMe })
    .add("/v1/me/password", "v1.me.password", { POST: api.changePassword })
    .add("/v1/me/totp", "v1.me.totp", { POST: api.postTotp, DELETE: api.deleteTotp })
    .add("/v1/me/recovery-codes", "v1.me.recovery_codes", { POST: api.postRecoveryCodes })
    .add("/v1/me/passkeys", "v1.me.passkeys", { GET: api.getPasskeys, POST: api.postPasskey })
    .add("/v1/me/passkeys/:id", "v1.me.passkey", { DELETE: api.deletePasskey })
    .add("/v1/me/sessions", "v1.me.sessions", { GET: api.getSessions, DELETE: api.deleteSessions })
    .add("/v1/me/sessions/:id", "v1.me.session", { DELETE: api.deleteOneSession })
    .add("/v1/me/app-passwords", "v1.me.app_passwords", { GET: api.appPasswords.list, POST: api.appPasswords.create })
    .add("/v1/me/app-passwords/:id", "v1.me.app_password", { DELETE: api.appPasswords.revoke })
    .add("/v1/me/api-keys", "v1.me.api_keys", { GET: api.apiKeys.list, POST: api.apiKeys.create })
    .add("/v1/me/api-keys/:id", "v1.me.api_key", { DELETE: api.apiKeys.revoke })
    .add("/v1/me/access", "v1.me.access", { GET: api.getMyAccess });

  // Management API, administration and the ★ endpoints (§7.5)
  r.add("/v1/users", "v1.users", { GET: api.listUsers, POST: api.createUser })
    .add("/v1/users/:id", "v1.user", { GET: api.getUser, PATCH: api.patchUser, DELETE: api.deleteUserRoute })
    .add("/v1/users/:id/access", "v1.user.access_list", { GET: api.getUserAccess })
    .add("/v1/users/:id/access/:service", "v1.user.access", { PUT: api.putUserAccess, DELETE: api.deleteUserAccess })
    .add("/v1/users/:id/sessions", "v1.user.sessions", { DELETE: api.deleteUserSessions })
    .add("/v1/users/:id/reset", "v1.user.reset", { POST: api.resetUser })
    .add("/v1/users/:user/app-passwords", "v1.user.app_passwords", { GET: api.appPasswords.list, POST: api.appPasswords.create })
    .add("/v1/users/:user/app-passwords/:id", "v1.user.app_password", { DELETE: api.appPasswords.revoke })
    .add("/v1/users/:user/api-keys", "v1.user.api_keys", { GET: api.apiKeys.list, POST: api.apiKeys.create })
    .add("/v1/users/:user/api-keys/:id", "v1.user.api_key", { DELETE: api.apiKeys.revoke })
    .add("/v1/invites", "v1.invites", { GET: api.listInvites, POST: api.postInvite })
    .add("/v1/invites/:id", "v1.invite", { GET: api.getInvite, DELETE: api.deleteInvite })
    .add("/v1/services", "v1.services", { GET: api.listServices })
    .add("/v1/audit", "v1.audit", { GET: api.listAudit });
  return r;
}
