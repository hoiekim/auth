import { readFileSync } from "node:fs";
import { join } from "node:path";
import { roleOf } from "../access";
import type { App } from "../app";
import { CLI } from "../cli-name";
import { asset, errorResponse, redirect } from "../http";
import type { Ctx } from "../server";
import { AUTH_SERVICE } from "../services";
import { csrfToken, hasMfa, loadSession } from "../sessions";
import { h, logo, messagePage, page } from "./layout";

// The account and admin pages: a shell whose script calls the /v1 API, the
// same handlers apps use (docs/DESIGN.md §7.5).

const ASSET_DIR = join(import.meta.dir, "..", "assets");
const TYPES: Record<string, string> = {
  css: "text/css; charset=utf-8",
  js: "text/javascript; charset=utf-8",
  svg: "image/svg+xml",
  png: "image/png",
  ico: "image/x-icon",
};
// Read once at start, as bytes: a fixed set, so no request path ever reaches
// the file system.
const ASSETS = new Map(
  ["style.css", "signin.js", "account.js", "admin.js", "icon.svg", "apple-touch-icon.png", "favicon.ico"].map((name) => [
    name,
    { body: new Uint8Array(readFileSync(join(ASSET_DIR, name))), type: TYPES[name.split(".").pop()!]! },
  ]),
);

export async function assetRoute({ params }: Ctx<App>): Promise<Response> {
  const found = ASSETS.get(params.file!);
  if (!found) return errorResponse(404, "not_found", "No such asset.");
  return asset(found.body, found.type);
}

// Browsers ask for /favicon.ico on their own, for pages and JSON alike.
export async function favicon(): Promise<Response> {
  const found = ASSETS.get("favicon.ico")!;
  return asset(found.body, found.type);
}

export async function home(): Promise<Response> {
  return redirect("/account", {}, 302);
}

// The bar above the account and admin pages. The account page shows its
// Admin link once its script knows the user is an admin.
function header(app: App, current: "account" | "admin"): string {
  const here = (name: string) => (name === current ? ' aria-current="page"' : "");
  return `<header class="app-header">
<a class="app-brand" href="/account">${logo(28)}<span>${h(app.config.issuer.replace(/^https?:\/\//, ""))}</span></a>
<nav class="app-nav" aria-label="Main">
<a href="/account"${here("account")}>Account</a>
<a href="/admin" id="admin-link"${here("admin")}${current === "admin" ? "" : " hidden"}>Admin</a>
<a href="/logout">Sign out</a>
</nav>
</header>`;
}

export async function accountPage({ req, deps: app }: Ctx<App>): Promise<Response> {
  const session = await loadSession(app, req);
  if (!session) return redirect(`/login?${new URLSearchParams({ return_to: "/account" })}`, {}, 302);
  const body = `
<div id="app"><p class="loading">Loading…</p></div>
<noscript><p class="notice">The account page needs JavaScript.</p></noscript>`;
  return page(app, "Your account", body, {
    header: header(app, "account"),
    scripts: ["account.js"],
    meta: { "csrf-token": csrfToken(app, session) },
  });
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
<div id="app"><p class="loading">Loading…</p></div>
<noscript><p class="notice">The admin page needs JavaScript.</p></noscript>`;
  return page(app, "Admin", body, {
    header: header(app, "admin"),
    scripts: ["admin.js"],
    meta: { "csrf-token": csrfToken(app, session), cli: CLI },
  });
}
