import { readFileSync } from "node:fs";
import { join } from "node:path";
import { roleOf } from "../access";
import type { App } from "../app";
import { asset, errorResponse, redirect } from "../http";
import type { Ctx } from "../server";
import { AUTH_SERVICE } from "../services";
import { csrfToken, hasMfa, loadSession } from "../sessions";
import { messagePage, page } from "./layout";

// The account and admin pages: a shell whose script calls the /v1 API, the
// same handlers apps use (docs/DESIGN.md §7.5).

const ASSET_DIR = join(import.meta.dir, "..", "assets");
const TYPES: Record<string, string> = { css: "text/css; charset=utf-8", js: "text/javascript; charset=utf-8" };
// Read once at start: a fixed set, so no request path ever reaches the file system.
const ASSETS = new Map(
  ["style.css", "signin.js", "account.js", "admin.js"].map((name) => [
    name,
    { body: readFileSync(join(ASSET_DIR, name), "utf8"), type: TYPES[name.split(".").pop()!]! },
  ]),
);

export async function assetRoute({ params }: Ctx<App>): Promise<Response> {
  const found = ASSETS.get(params.file!);
  if (!found) return errorResponse(404, "not_found", "No such asset.");
  return asset(found.body, found.type);
}

export async function home(): Promise<Response> {
  return redirect("/account", {}, 302);
}

export async function accountPage({ req, deps: app }: Ctx<App>): Promise<Response> {
  const session = await loadSession(app, req);
  if (!session) return redirect(`/login?${new URLSearchParams({ return_to: "/account" })}`, {}, 302);
  const body = `
<header class="bar"><strong>${app.config.issuer.replace(/^https?:\/\//, "")}</strong>
<nav><a href="/account">Account</a> <a href="/admin" id="admin-link" hidden>Admin</a> <a href="/logout">Sign out</a></nav></header>
<div id="app"><p>Loading…</p></div>
<noscript><p>The account page needs JavaScript.</p></noscript>`;
  return page(app, "Your account", body, { scripts: ["account.js"], meta: { "csrf-token": csrfToken(app, session) } });
}

export async function adminPage({ req, deps: app }: Ctx<App>): Promise<Response> {
  const session = await loadSession(app, req);
  if (!session) return redirect(`/login?${new URLSearchParams({ return_to: "/admin" })}`, {}, 302);
  if ((await roleOf(app.sql, session.userId, AUTH_SERVICE)) !== "admin") {
    return messagePage(app, 403, "No access", "This page is for auth's administrators.", { href: "/account", text: "Your account" });
  }
  if (!hasMfa(session)) {
    return redirect(`/login?${new URLSearchParams({ return_to: "/admin", second_factor: AUTH_SERVICE })}`, {}, 302);
  }
  const body = `
<header class="bar"><strong>${app.config.issuer.replace(/^https?:\/\//, "")} admin</strong>
<nav><a href="/account">Account</a> <a href="/admin">Admin</a> <a href="/logout">Sign out</a></nav></header>
<div id="app"><p>Loading…</p></div>
<noscript><p>The admin page needs JavaScript.</p></noscript>`;
  return page(app, "Admin", body, { scripts: ["admin.js"], meta: { "csrf-token": csrfToken(app, session) } });
}
