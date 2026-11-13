import { errorResponse, HttpError, json } from "./http";

export interface ServerDeps {
  // Settles within a bounded time (databasePing in db.ts).
  pingDatabase: () => Promise<void>;
  log: (line: string) => void;
}

export interface Ctx<D> {
  req: Request;
  url: URL;
  params: Record<string, string>;
  // The client's address (net.ts clientIp), or null when unknown.
  ip: string | null;
  deps: D;
}

export type Handler<D> = (ctx: Ctx<D>) => Promise<Response>;

export interface Route<D> {
  // Logged in place of the request path, whose query string can carry a
  // code or a token (docs/DESIGN.md §9.3).
  name: string;
  methods: Partial<Record<string, Handler<D>>>;
}

const PARAM = /^[A-Za-z0-9._~-]{1,128}$/;

// Exact paths and `:param` segments. A parameter is one path segment of
// unreserved characters, so nothing in it needs decoding.
export class Router<D> {
  readonly #exact = new Map<string, Route<D>>();
  readonly #patterns: { segments: string[]; route: Route<D> }[] = [];

  add(pattern: string, name: string, methods: Route<D>["methods"]): this {
    const route = { name, methods };
    if (pattern.includes("/:")) this.#patterns.push({ segments: pattern.split("/"), route });
    else this.#exact.set(pattern, route);
    return this;
  }

  match(pathname: string): { route: Route<D>; params: Record<string, string> } | null {
    const exact = this.#exact.get(pathname);
    if (exact) return { route: exact, params: {} };
    const parts = pathname.split("/");
    for (const { segments, route } of this.#patterns) {
      if (segments.length !== parts.length) continue;
      const params: Record<string, string> = {};
      let ok = true;
      for (let i = 0; i < segments.length && ok; i++) {
        const seg = segments[i]!;
        const part = parts[i]!;
        if (seg.startsWith(":")) {
          if (PARAM.test(part)) params[seg.slice(1)] = part;
          else ok = false;
        } else ok = seg === part;
      }
      if (ok) return { route, params };
    }
    return null;
  }
}

export function healthRoutes<D extends ServerDeps>(router: Router<D> = new Router<D>()): Router<D> {
  return router.add("/healthz", "healthz", { GET: healthz });
}

export async function handle<D extends ServerDeps>(
  req: Request,
  deps: D,
  router: Router<D> = healthRoutes<D>(),
  ip: string | null = null,
): Promise<Response> {
  const started = performance.now();
  const url = new URL(req.url);
  const found = router.match(url.pathname);
  const name = found?.route.name ?? "unmatched";
  let res: Response;
  try {
    if (!found) {
      res = errorResponse(404, "not_found", "No such endpoint.");
    } else {
      const handler = found.route.methods[req.method];
      if (!handler) {
        const allowed = Object.keys(found.route.methods);
        res = errorResponse(405, "method_not_allowed", `Use ${allowed.join(" or ")}.`, { Allow: allowed.join(", ") });
      } else {
        res = await handler({ req, url, params: found.params, ip, deps });
      }
    }
  } catch (e) {
    if (e instanceof HttpError) res = e.response();
    else {
      // The error's name only: a message can quote a query, a token or a
      // connection string.
      deps.log(`${req.method} ${name} threw ${e instanceof Error ? e.name : typeof e}`);
      res = errorResponse(500, "server_error", "Internal error.");
    }
  }
  // A probe every few seconds would bury everything else.
  if (!(name === "healthz" && res.status === 200)) {
    deps.log(`${req.method} ${name} ${res.status} ${Math.round(performance.now() - started)}ms`);
  }
  return res;
}

async function healthz({ deps }: Ctx<ServerDeps>): Promise<Response> {
  try {
    await deps.pingDatabase();
    return json(200, { status: "ok" });
  } catch {
    return errorResponse(503, "temporarily_unavailable", "The database is unreachable.");
  }
}
