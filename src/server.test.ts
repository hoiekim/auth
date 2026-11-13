import { describe, expect, test } from "bun:test";
import { handle, healthRoutes, Router, type ServerDeps } from "./server";

function deps(overrides: Partial<ServerDeps> = {}) {
  const lines: string[] = [];
  const d: ServerDeps = {
    pingDatabase: async () => {},
    log: (line) => lines.push(line),
    ...overrides,
  };
  return { deps: d, lines };
}

const get = (path: string, method = "GET") => new Request(`http://auth.test${path}`, { method });

describe("GET /healthz", () => {
  test("answers 200 when the database answers", async () => {
    const { deps: d, lines } = deps();
    const res = await handle(get("/healthz"), d);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "ok" });
    expect(lines).toEqual([]);
  });

  test("answers 503 when the ping fails, without the failure's message", async () => {
    const { deps: d, lines } = deps({
      pingDatabase: async () => {
        throw new Error("connect ECONNREFUSED postgres://auth:s3cret-pw@db:5432/auth");
      },
    });
    const res = await handle(get("/healthz"), d);
    expect(res.status).toBe(503);
    const body = await res.text();
    expect(JSON.parse(body)).toEqual({
      error: "temporarily_unavailable",
      error_description: "The database is unreachable.",
    });
    expect(body + lines.join("\n")).not.toContain("s3cret-pw");
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/^GET healthz 503 \d+ms$/);
  });

  test("answers 405 with Allow to another method", async () => {
    const { deps: d } = deps();
    const res = await handle(get("/healthz", "POST"), d);
    expect(res.status).toBe(405);
    expect(res.headers.get("Allow")).toBe("GET");
    expect(await res.json()).toMatchObject({ error: "method_not_allowed" });
  });
});

describe("every response", () => {
  test("an unknown path is a JSON 404 in the shared error shape", async () => {
    const { deps: d } = deps();
    const res = await handle(get("/oauth/authorize"), d);
    expect(res.status).toBe(404);
    expect(res.headers.get("Content-Type")).toBe("application/json");
    expect(await res.json()).toEqual({ error: "not_found", error_description: "No such endpoint." });
  });

  test.each([
    ["/healthz", "GET"],
    ["/nope", "GET"],
    ["/healthz", "DELETE"],
  ])("%s %s carries the security headers", async (path, method) => {
    const { deps: d } = deps();
    const res = await handle(get(path, method), d);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("Content-Security-Policy")).toBe("default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
    expect(res.headers.get("Referrer-Policy")).toBe("no-referrer");
    expect(res.headers.get("Strict-Transport-Security")).toBe("max-age=63072000");
    expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
  });

  test("the log names the route, never the path or query", async () => {
    const { deps: d, lines } = deps();
    await handle(get("/callback?code=abc123&state=xyz"), d);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/^GET unmatched 404 \d+ms$/);
  });

  test("a handler that throws is a 500, logged by its error's name only", async () => {
    const { deps: d, lines } = deps();
    const router = new Router<ServerDeps>().add("/boom", "boom", {
      GET: async () => {
        throw new TypeError("token=abc123");
      },
    });
    const res = await handle(get("/boom?code=abc123"), d, router);
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "server_error", error_description: "Internal error." });
    expect(lines).toHaveLength(2);
    expect(lines[0]).toBe("GET boom threw TypeError");
    expect(lines[1]).toMatch(/^GET boom 500 \d+ms$/);
  });
});

describe("Router", () => {
  const ok = (body: string) => async () => new Response(body);
  const router = new Router<ServerDeps>()
    .add("/v1/users", "users", { GET: ok("list") })
    .add("/v1/users/:id", "user", { GET: ok("one"), DELETE: ok("gone") })
    .add("/v1/users/:id/access/:service", "access", { PUT: ok("put") });

  test("matches exact paths before patterns, and fills parameters", () => {
    expect(router.match("/v1/users")?.route.name).toBe("users");
    expect(router.match("/v1/users/usr_1")).toMatchObject({ route: { name: "user" }, params: { id: "usr_1" } });
    expect(router.match("/v1/users/usr_1/access/wiki")).toMatchObject({ route: { name: "access" }, params: { id: "usr_1", service: "wiki" } });
  });

  test.each(["/v1/users/", "/v1/users/a/b", "/v1/users/%2e%2e", "/v1/users/a%2Fb/access/wiki", "/v1/users/a b"])("refuses %p", (path) => {
    expect(router.match(path)).toBeNull();
  });

  test("a known path with another method is a 405 listing the methods", async () => {
    const { deps: d } = deps();
    const res = await handle(get("/v1/users/usr_1", "PATCH"), d, router);
    expect(res.status).toBe(405);
    expect(res.headers.get("Allow")).toBe("GET, DELETE");
  });

  test("the health route can be mounted on any router", async () => {
    const { deps: d } = deps();
    const res = await handle(get("/healthz"), d, healthRoutes(new Router<ServerDeps>()));
    expect(res.status).toBe(200);
  });
});
