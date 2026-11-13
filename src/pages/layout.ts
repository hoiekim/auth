import type { App } from "../app";
import { randomToken, safeEqual } from "../crypto";
import { fromIssuer, hostCookie, html, HttpError, pageCsp, setCookie, type ResponseExtras } from "../http";

// Server-rendered pages (docs/DESIGN.md §5.1 front channel). Every value is
// escaped; scripts and styles come only from /assets, as the CSP requires.

export function h(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export interface PageOptions {
  status?: number;
  scripts?: string[];
  meta?: Record<string, string>;
  extras?: ResponseExtras;
}

export function page(app: App, title: string, body: string, opts: PageOptions = {}): Response {
  const meta = Object.entries(opts.meta ?? {})
    .map(([k, v]) => `<meta name="${h(k)}" content="${h(v)}">`)
    .join("\n");
  const scripts = (opts.scripts ?? []).map((s) => `<script src="/assets/${h(s)}" defer></script>`).join("\n");
  const doc = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
${meta}
<title>${h(title)}</title>
<link rel="stylesheet" href="/assets/style.css">
${scripts}
</head>
<body>
<main>
${body}
</main>
</body>
</html>`;
  return html(opts.status ?? 200, doc, pageCsp(app.services.formActionSources()), opts.extras);
}

export function messagePage(app: App, status: number, title: string, message: string, link?: { href: string; text: string }): Response {
  const a = link ? `<p><a href="${h(link.href)}">${h(link.text)}</a></p>` : "";
  return page(app, title, `<h1>${h(title)}</h1>\n<p>${h(message)}</p>\n${a}`, { status });
}

// Forms posted before or without a session carry a double-submit token: a
// random __Host- cookie echoed in a hidden field. With the Origin check it
// blocks login CSRF (§9.2).
export const FORM_COOKIE = "csrf";

export function formToken(req: Request): { token: string; cookie: string | null } {
  const existing = hostCookie(req, FORM_COOKIE);
  if (existing && /^[A-Za-z0-9_-]{43}$/.test(existing)) return { token: existing, cookie: null };
  const token = randomToken();
  return { token, cookie: setCookie(FORM_COOKIE, token, null, "Strict") };
}

export function hiddenCsrf(token: string): string {
  return `<input type="hidden" name="csrf" value="${h(token)}">`;
}

export function checkForm(app: App, req: Request, form: URLSearchParams): void {
  if (!fromIssuer(app.config.issuer, req)) throw new HttpError(403, "forbidden", "This form was not sent from this site.");
  const cookie = hostCookie(req, FORM_COOKIE) ?? "";
  const sent = form.get("csrf") ?? "";
  if (!cookie || !safeEqual(cookie, sent)) throw new HttpError(403, "forbidden", "This form has expired. Go back, reload the page and try again.");
}

// A path on this site to go to after a step, never another origin.
export function localPath(value: string | null | undefined, fallback = "/account"): string {
  if (!value || value.length > 4096 || !value.startsWith("/") || value.startsWith("//") || value.startsWith("/\\")) return fallback;
  if (/[\u0000-\u001f\\]/.test(value)) return fallback;
  return value;
}

export function extrasWith(cookie: string | null, more: string[] = []): ResponseExtras {
  return { cookies: [...(cookie ? [cookie] : []), ...more] };
}
