import { errorResponse, json } from "./http";

export interface ServerDeps {
  // Settles within a bounded time (databasePing in db.ts).
  pingDatabase: () => Promise<void>;
  log: (line: string) => void;
}

export interface Route {
  // Logged in place of the request path, whose query string can carry a
  // code or a token (docs/DESIGN.md §9.3).
  name: string;
  methods: string[];
  handle: (req: Request, deps: ServerDeps) => Promise<Response>;
}

const routes: ReadonlyMap<string, Route> = new Map([["/healthz", { name: "healthz", methods: ["GET"], handle: healthz }]]);

export async function handle(req: Request, deps: ServerDeps, table = routes): Promise<Response> {
  const started = performance.now();
  const route = table.get(new URL(req.url).pathname);
  let res: Response;
  try {
    if (!route) {
      res = errorResponse(404, "not_found", "No such endpoint.");
    } else if (!route.methods.includes(req.method)) {
      res = errorResponse(405, "method_not_allowed", `Use ${route.methods.join(" or ")}.`, {
        Allow: route.methods.join(", "),
      });
    } else {
      res = await route.handle(req, deps);
    }
  } catch (e) {
    // The error's name only: a message can quote a query, a token or a
    // connection string.
    deps.log(`${req.method} ${route?.name ?? "unmatched"} threw ${e instanceof Error ? e.name : typeof e}`);
    res = errorResponse(500, "server_error", "Internal error.");
  }
  // A probe every few seconds would bury everything else.
  if (!(route?.name === "healthz" && res.status === 200)) {
    deps.log(`${req.method} ${route?.name ?? "unmatched"} ${res.status} ${Math.round(performance.now() - started)}ms`);
  }
  return res;
}

async function healthz(_req: Request, deps: ServerDeps): Promise<Response> {
  try {
    await deps.pingDatabase();
    return json(200, { status: "ok" });
  } catch {
    return errorResponse(503, "temporarily_unavailable", "The database is unreachable.");
  }
}
