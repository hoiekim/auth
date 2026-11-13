import { createApp } from "./app";
import { ConfigError, loadConfig, type Config } from "./config";
import { connect } from "./db";
import { errorResponse, MAX_BODY_BYTES } from "./http";
import { startJobs } from "./jobs";
import { rotateKeys } from "./keys";
import { smtpMailer } from "./mail";
import { migrate } from "./migrate";
import { clientIp } from "./net";
import { buildRouter } from "./routes";
import { handle } from "./server";

let config: Config;
try {
  config = loadConfig(process.env);
} catch (e) {
  if (!(e instanceof ConfigError)) throw e;
  console.error(e.message);
  process.exit(1);
}

const sql = connect(config.databaseUrl);
const app = createApp(config, sql, smtpMailer(config.smtp, config.emailFrom));
const ping = app.pingDatabase;
let ready = false;
// Not healthy until the schema and a signing key are in place.
app.pingDatabase = async () => {
  if (!ready) throw new Error("starting");
  await ping();
};
const router = buildRouter();

const server = Bun.serve({
  port: config.port,
  // Bun derives this from NODE_ENV when it is left out, and in development
  // mode an uncaught error is answered with its stack.
  development: false,
  // Every body is capped before it is parsed (§10).
  maxRequestBodySize: MAX_BODY_BYTES,
  fetch(req, srv) {
    const ip = clientIp(srv.requestIP(req)?.address ?? null, req.headers.get("X-Real-IP"), config.trustedProxies);
    if (!ready && new URL(req.url).pathname !== "/healthz") {
      return errorResponse(503, "temporarily_unavailable", "Starting up.", { "Retry-After": "5" });
    }
    return handle(req, app, router, ip);
  },
});
console.log(`listening on :${server.port}`);

let jobs: { stop: () => Promise<void> } | null = null;
let stopping = false;

// Migrations need the database, which may still be starting; until they
// have run, every request but /healthz answers 503.
async function start() {
  for (let attempt = 1; !stopping; attempt++) {
    try {
      await migrate(sql, (line) => console.log(line));
      await rotateKeys(sql, app.crypt);
      await app.keys.refresh(true);
      break;
    } catch (e) {
      console.log(`start: database not ready (${e instanceof Error ? e.name : typeof e}), retrying`);
      await Bun.sleep(Math.min(1000 * attempt, 10_000));
    }
  }
  if (stopping) return;
  ready = true;
  jobs = startJobs(app);
}
void start();

// A deploy stops the old copy with SIGTERM while the new one serves.
// Requests in flight finish; new ones go to the other copy.
async function stop(signal: string) {
  if (stopping) return;
  stopping = true;
  console.log(`${signal}: finishing requests in flight`);
  await server.stop();
  await jobs?.stop();
  await sql.close({ timeout: 5 });
  process.exit(0);
}
process.on("SIGTERM", () => void stop("SIGTERM"));
process.on("SIGINT", () => void stop("SIGINT"));
