// Response helpers. Every response carries the security headers, and every
// error has the one shape docs/DESIGN.md §7.7 defines:
// {"error": "<code>", "error_description": "<text>"}.

export type ErrorCode =
  | "invalid_request"
  | "unauthorized"
  | "forbidden"
  | "reauth_required"
  | "not_found"
  | "method_not_allowed"
  | "conflict"
  | "rate_limited"
  | "invalid_grant"
  | "invalid_client"
  | "unsupported_grant_type"
  | "invalid_token"
  | "server_error"
  | "temporarily_unavailable";

const SECURITY_HEADERS: Record<string, string> = {
  "Cache-Control": "no-store",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  "Referrer-Policy": "no-referrer",
  "Strict-Transport-Security": "max-age=63072000",
  "X-Content-Type-Options": "nosniff",
};

export interface ResponseExtras {
  headers?: Record<string, string>;
  cookies?: string[];
}

function respond(status: number, body: string | null, contentType: string | null, extras: ResponseExtras = {}): Response {
  const headers = new Headers(SECURITY_HEADERS);
  if (contentType) headers.set("Content-Type", contentType);
  for (const [k, v] of Object.entries(extras.headers ?? {})) headers.set(k, v);
  for (const c of extras.cookies ?? []) headers.append("Set-Cookie", c);
  return new Response(body, { status, headers });
}

export function json(status: number, body: unknown, headers: Record<string, string> = {}, cookies: string[] = []): Response {
  return respond(status, JSON.stringify(body), "application/json", { headers, cookies });
}

export function errorResponse(
  status: number,
  error: ErrorCode,
  description: string,
  headers: Record<string, string> = {},
): Response {
  return json(status, { error, error_description: description }, headers);
}

export function noContent(extras: ResponseExtras = {}): Response {
  return respond(204, null, null, extras);
}

// Pages: scripts and styles come only from auth itself, and a form may post
// only to auth or lead, through redirects, to a registered redirect origin
// (§9.2).
export function pageCsp(formActionSources: string[]): string {
  return ["default-src 'self'", "frame-ancestors 'none'", `form-action 'self' ${formActionSources.join(" ")}`.trim(), "base-uri 'none'"].join("; ");
}

export function html(status: number, body: string, csp: string, extras: ResponseExtras = {}): Response {
  return respond(status, body, "text/html; charset=utf-8", {
    ...extras,
    headers: { "Content-Security-Policy": csp, ...extras.headers },
  });
}

export function redirect(location: string, extras: ResponseExtras = {}, status = 303): Response {
  return respond(status, null, null, { ...extras, headers: { ...extras.headers, Location: location } });
}

export function asset(body: string, contentType: string): Response {
  return respond(200, body, contentType, { headers: { "Cache-Control": "public, max-age=300" } });
}

// A refusal a handler throws; the router turns it into the error response.
export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: ErrorCode,
    readonly description: string,
    readonly headers: Record<string, string> = {},
  ) {
    super(code);
    this.name = "HttpError";
  }

  response(): Response {
    return errorResponse(this.status, this.code, this.description, this.headers);
  }
}

export const MAX_BODY_BYTES = 64 * 1024;

// The body as text, refused past `max` bytes before more is buffered.
export async function readText(req: Request, max = MAX_BODY_BYTES): Promise<string> {
  const declared = Number(req.headers.get("Content-Length") ?? "0");
  if (declared > max) throw new HttpError(413, "invalid_request", "The request body is too large.");
  if (!req.body) return "";
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      await reader.cancel();
      throw new HttpError(413, "invalid_request", "The request body is too large.");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export async function readJson(req: Request): Promise<Record<string, unknown>> {
  const type = req.headers.get("Content-Type") ?? "";
  if (!/^application\/json\b/i.test(type)) throw new HttpError(415, "invalid_request", "Send application/json.");
  const text = await readText(req);
  let body: unknown;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    throw new HttpError(400, "invalid_request", "The body is not valid JSON.");
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw new HttpError(400, "invalid_request", "The body must be a JSON object.");
  }
  return body as Record<string, unknown>;
}

export async function readForm(req: Request): Promise<URLSearchParams> {
  const type = req.headers.get("Content-Type") ?? "";
  if (!/^application\/x-www-form-urlencoded\b/i.test(type)) {
    throw new HttpError(415, "invalid_request", "Send application/x-www-form-urlencoded.");
  }
  return new URLSearchParams(await readText(req));
}

// One value of a form or query parameter; a repeated parameter is refused, as
// OAuth requires (RFC 6749 §3.1).
export function single(params: URLSearchParams, name: string): string | null {
  const all = params.getAll(name);
  if (all.length > 1) throw new HttpError(400, "invalid_request", `The parameter "${name}" is repeated.`);
  return all[0] ?? null;
}

export function cookies(req: Request): Map<string, string> {
  const out = new Map<string, string>();
  for (const part of (req.headers.get("Cookie") ?? "").split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const name = part.slice(0, eq).trim();
    if (name && !out.has(name)) out.set(name, part.slice(eq + 1).trim());
  }
  return out;
}

// __Host- cookies only (§9.2): Secure, Path=/, no Domain, so a sibling
// subdomain can't set or overwrite them.
export function setCookie(name: string, value: string, maxAgeSeconds: number | null, sameSite: "Lax" | "Strict" = "Lax"): string {
  const parts = [`__Host-${name}=${value}`, "Path=/", "Secure", "HttpOnly", `SameSite=${sameSite}`];
  if (maxAgeSeconds !== null) parts.push(`Max-Age=${maxAgeSeconds}`);
  return parts.join("; ");
}

export function clearCookie(name: string): string {
  return `__Host-${name}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`;
}

// The request came from one of the issuer's own pages (§9.2): Origin is the
// issuer's. Under the pages' Referrer-Policy: no-referrer a browser sends
// `Origin: null` on a same-origin form post and says so in Sec-Fetch-Site,
// which page scripts can't set. A missing Origin is refused.
export function fromIssuer(issuer: string, req: Request): boolean {
  const origin = req.headers.get("Origin");
  return origin === issuer || (origin === "null" && req.headers.get("Sec-Fetch-Site") === "same-origin");
}

export function hostCookie(req: Request, name: string): string | null {
  return cookies(req).get(`__Host-${name}`) ?? null;
}
