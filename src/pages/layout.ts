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

// Icons are inline SVG: the CSP loads no images. 16×16, drawn with the text
// color.
const ICONS: Record<string, string> = {
  info: '<circle cx="8" cy="8" r="6.25"/><path d="M8 7.25v3.5M8 5v.25"/>',
  alert: '<path d="M8 2.25 1.75 13.25h12.5L8 2.25ZM8 6.5v3M8 11.25v.25"/>',
  check: '<circle cx="8" cy="8" r="6.25"/><path d="m5.5 8.25 1.75 1.75 3.25-3.5"/>',
  passkey: '<circle cx="6" cy="5" r="2.5"/><path d="M1.75 13.25c.4-2.4 2.1-3.75 4.25-3.75.8 0 1.5.2 2.1.5"/><circle cx="12" cy="8.25" r="1.75"/><path d="M12 10v3.75M12 12.25h1.25"/>',
};

export function icon(name: string, size = 16): string {
  return `<svg class="icon" width="${size}" height="${size}" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${ICONS[name] ?? ""}</svg>`;
}

// A keyhole: the mark above the sign-in pages and in the account header.
export function logo(size: number): string {
  return `<svg class="logo" width="${size}" height="${size}" viewBox="0 0 32 32" aria-hidden="true" focusable="false"><rect class="logo-bg" width="32" height="32" rx="8" fill="#0969da"/><circle class="logo-fg" cx="16" cy="13" r="4.5" fill="#fff"/><path class="logo-fg" d="M13.6 15.5h4.8l1.35 8.5h-7.5z" fill="#fff"/></svg>`;
}

// A message box. An error is announced as an alert, the others as a status.
export function flash(kind: "notice" | "success" | "error", message: string): string {
  const role = kind === "error" ? ' role="alert"' : ' role="status"';
  const glyph = kind === "success" ? "check" : kind === "notice" ? "info" : "alert";
  return `<p class="${kind}"${role}>${icon(glyph)}<span>${h(message)}</span></p>`;
}

export interface PageOptions {
  status?: number;
  scripts?: string[];
  meta?: Record<string, string>;
  extras?: ResponseExtras;
  // The account and admin pages: a header bar and a wide frame. Every other
  // page is a narrow card under the logo.
  header?: string;
}

export function page(app: App, title: string, body: string, opts: PageOptions = {}): Response {
  const meta = Object.entries(opts.meta ?? {})
    .map(([k, v]) => `<meta name="${h(k)}" content="${h(v)}">`)
    .join("\n");
  const scripts = (opts.scripts ?? []).map((s) => `<script src="/assets/${h(s)}" defer></script>`).join("\n");
  const frame =
    opts.header !== undefined
      ? `<body class="app-frame">
${opts.header}
<main class="app-main">
${body}
</main>
</body>`
      : `<body class="card-frame">
<main class="card-main">
<div class="brand-mark">${logo(48)}</div>
${body}
</main>
</body>`;
  const doc = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
${meta}
<title>${h(title)}</title>
<link rel="icon" href="/favicon.ico" sizes="32x32">
<link rel="icon" href="/assets/icon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/assets/apple-touch-icon.png">
<link rel="stylesheet" href="/assets/style.css">
${scripts}
</head>
${frame}
</html>`;
  return html(opts.status ?? 200, doc, pageCsp(app.services.formActionSources()), opts.extras);
}

export function messagePage(
  app: App,
  status: number,
  title: string,
  message: string,
  link?: { href: string; text: string },
  extras?: ResponseExtras,
): Response {
  const ok = status < 400;
  const a = link ? `<a class="button block${ok ? "" : " secondary"}" href="${h(link.href)}">${h(link.text)}</a>` : "";
  const body = `<h1>${h(title)}</h1>
<div class="card">
<div class="status-icon${ok ? "" : " warn"}">${icon(ok ? "check" : "alert", 24)}</div>
<p>${h(message)}</p>
${a}
</div>`;
  return page(app, title, body, { status, extras });
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
  // Printable ASCII only, as a path the server writes is: anything else would
  // go into a Location header raw.
  if (/[^\u0020-\u007e]|\\/.test(value)) return fallback;
  return value;
}

export function extrasWith(cookie: string | null, more: string[] = []): ResponseExtras {
  return { cookies: [...(cookie ? [cookie] : []), ...more] };
}
