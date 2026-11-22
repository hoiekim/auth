//! Every endpoint. Route names are what the request log prints in place of
//! the path (docs/DESIGN.md §9.3).

use crate::pages::{app as shell, flows, signin};
use crate::server::{h, healthz, Router};
use crate::{api, oauth};

/// A page's handler: what it refuses is rendered as a page (signin.rs
/// page_errors).
macro_rules! p {
    ($f:path) => {{
        fn handler(ctx: $crate::server::Ctx) -> $crate::server::BoxFuture<$crate::error::Result<$crate::http::Response>> {
            Box::pin(async move {
                let app = ctx.app.clone();
                $crate::pages::signin::page_errors(app, $f(ctx).await).await
            })
        }
        handler as $crate::server::Handler
    }};
}

pub fn build_router() -> Router {
    let mut r = Router::default();
    r.add("/healthz", "healthz", vec![("GET", h!(healthz))], true);

    // OAuth and OIDC (§7.2)
    r.add("/.well-known/openid-configuration", "discovery", vec![("GET", h!(oauth::discovery))], false)
        .add("/.well-known/jwks.json", "jwks", vec![("GET", h!(oauth::jwks))], false)
        .add("/oauth/authorize", "authorize", vec![("GET", h!(oauth::authorize))], false)
        .add("/oauth/token", "token", vec![("POST", h!(oauth::token))], false)
        .add("/oauth/revoke", "revoke", vec![("POST", h!(oauth::revoke))], false)
        .add("/oauth/introspect", "introspect", vec![("POST", h!(oauth::introspect))], false)
        .add("/oauth/userinfo", "userinfo", vec![("GET", h!(oauth::userinfo)), ("POST", h!(oauth::userinfo))], false)
        .add("/logout", "logout", vec![("GET", h!(oauth::logout))], false);

    // Pages (§5.1 front channel)
    r.add("/", "home", vec![("GET", h!(shell::home))], true)
        .add("/login", "login", vec![("GET", p!(signin::get_login)), ("POST", p!(signin::post_login))], false)
        .add("/login/second-factor", "login.second_factor", vec![("GET", p!(signin::get_second_factor)), ("POST", p!(signin::post_second_factor))], false)
        .add("/login/passkey/options", "login.passkey_options", vec![("POST", h!(signin::passkey_options))], false)
        .add("/login/passkey", "login.passkey", vec![("POST", h!(signin::passkey_sign_in))], false)
        .add("/signup", "signup", vec![("GET", p!(flows::get_signup)), ("POST", p!(flows::post_signup))], false)
        .add("/invite", "invite", vec![("GET", p!(flows::get_invite)), ("POST", p!(flows::post_invite))], false)
        .add("/activate", "activate", vec![("GET", p!(flows::get_activate)), ("POST", p!(flows::post_activate))], false)
        .add("/reset", "reset", vec![("GET", p!(flows::get_reset)), ("POST", p!(flows::post_reset))], false)
        .add("/reset/confirm", "reset.confirm", vec![("GET", p!(flows::get_reset_confirm)), ("POST", p!(flows::post_reset_confirm))], false)
        .add("/verify-email", "verify_email", vec![("GET", p!(flows::get_verify_email)), ("POST", p!(flows::post_verify_email))], false)
        .add("/mfa-required", "mfa_required", vec![("GET", p!(flows::get_mfa_required))], false)
        .add("/account", "account", vec![("GET", h!(shell::account_page))], false)
        .add("/admin", "admin", vec![("GET", h!(shell::admin_page))], false)
        .add("/assets/:file", "asset", vec![("GET", h!(shell::asset_route))], true)
        .add("/favicon.ico", "favicon", vec![("GET", h!(shell::favicon))], true);

    // Management API, self-service (§7.5)
    r.add("/v1/me", "v1.me", vec![("GET", h!(api::get_me)), ("PATCH", h!(api::patch_me)), ("DELETE", h!(api::delete_me))], false)
        .add("/v1/me/password", "v1.me.password", vec![("POST", h!(api::change_password))], false)
        .add("/v1/me/totp", "v1.me.totp", vec![("POST", h!(api::post_totp)), ("DELETE", h!(api::delete_totp))], false)
        .add("/v1/me/recovery-codes", "v1.me.recovery_codes", vec![("POST", h!(api::post_recovery_codes))], false)
        .add("/v1/me/passkeys", "v1.me.passkeys", vec![("GET", h!(api::get_passkeys)), ("POST", h!(api::post_passkey))], false)
        .add("/v1/me/passkeys/:id", "v1.me.passkey", vec![("DELETE", h!(api::delete_passkey))], false)
        .add("/v1/me/sessions", "v1.me.sessions", vec![("GET", h!(api::get_sessions)), ("DELETE", h!(api::delete_sessions))], false)
        .add("/v1/me/sessions/:id", "v1.me.session", vec![("DELETE", h!(api::delete_one_session))], false)
        .add("/v1/me/app-passwords", "v1.me.app_passwords", vec![("GET", h!(api::list_app_passwords)), ("POST", h!(api::create_app_password))], false)
        .add("/v1/me/app-passwords/:id", "v1.me.app_password", vec![("DELETE", h!(api::revoke_app_password))], false)
        .add("/v1/me/api-keys", "v1.me.api_keys", vec![("GET", h!(api::list_api_keys)), ("POST", h!(api::create_api_key))], false)
        .add("/v1/me/api-keys/:id", "v1.me.api_key", vec![("DELETE", h!(api::revoke_api_key))], false)
        .add("/v1/me/access", "v1.me.access", vec![("GET", h!(api::get_my_access))], false);

    // Management API, administration and the ★ endpoints (§7.5)
    r.add("/v1/users", "v1.users", vec![("GET", h!(api::list_users)), ("POST", h!(api::create_user))], false)
        .add("/v1/users/:id", "v1.user", vec![("GET", h!(api::get_user)), ("PATCH", h!(api::patch_user)), ("DELETE", h!(api::delete_user_route))], false)
        .add("/v1/users/:id/access", "v1.user.access_list", vec![("GET", h!(api::get_user_access))], false)
        .add("/v1/users/:id/access/:service", "v1.user.access", vec![("PUT", h!(api::put_user_access)), ("DELETE", h!(api::delete_user_access))], false)
        .add("/v1/users/:id/sessions", "v1.user.sessions", vec![("DELETE", h!(api::delete_user_sessions))], false)
        .add("/v1/users/:id/reset", "v1.user.reset", vec![("POST", h!(api::reset_user))], false)
        .add("/v1/users/:user/app-passwords", "v1.user.app_passwords", vec![("GET", h!(api::list_app_passwords)), ("POST", h!(api::create_app_password))], false)
        .add("/v1/users/:user/app-passwords/:id", "v1.user.app_password", vec![("DELETE", h!(api::revoke_app_password))], false)
        .add("/v1/users/:user/api-keys", "v1.user.api_keys", vec![("GET", h!(api::list_api_keys)), ("POST", h!(api::create_api_key))], false)
        .add("/v1/users/:user/api-keys/:id", "v1.user.api_key", vec![("DELETE", h!(api::revoke_api_key))], false)
        .add("/v1/invites", "v1.invites", vec![("GET", h!(api::list_invites)), ("POST", h!(api::post_invite))], false)
        .add("/v1/invites/:id", "v1.invite", vec![("GET", h!(api::get_invite)), ("DELETE", h!(api::delete_invite))], false)
        .add("/v1/services", "v1.services", vec![("GET", h!(api::list_services)), ("POST", h!(api::post_service))], false)
        .add("/v1/services/:name", "v1.service", vec![("PUT", h!(api::put_service)), ("DELETE", h!(api::delete_service))], false)
        .add("/v1/clients/:id/secrets", "v1.client.secrets", vec![("POST", h!(api::post_client_secret))], false)
        .add("/v1/clients/:id/old-secrets", "v1.client.old_secrets", vec![("DELETE", h!(api::retire_old_secrets))], false)
        .add("/v1/audit", "v1.audit", vec![("GET", h!(api::list_audit))], false);
    r
}
