// Response helpers. Every response carries the security headers, and every
// error has the one shape docs/DESIGN.md §7.7 defines:
// {"error": "<code>", "error_description": "<text>"}.

export type ErrorCode =
  | "invalid_request"
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "method_not_allowed"
  | "server_error"
  | "temporarily_unavailable";

const SECURITY_HEADERS: Record<string, string> = {
  "Cache-Control": "no-store",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  "Referrer-Policy": "no-referrer",
  "Strict-Transport-Security": "max-age=63072000",
  "X-Content-Type-Options": "nosniff",
};

export function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...SECURITY_HEADERS, "Content-Type": "application/json", ...headers },
  });
}

export function errorResponse(
  status: number,
  error: ErrorCode,
  description: string,
  headers: Record<string, string> = {},
): Response {
  return json(status, { error, error_description: description }, headers);
}
