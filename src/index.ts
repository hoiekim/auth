import { ConfigError, loadConfig, type Config } from "./config";
import { connect, databasePing } from "./db";
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
const deps = {
  pingDatabase: databasePing(sql, 2000),
  log: (line: string) => console.log(line),
};

const server = Bun.serve({
  port: config.port,
  // Bun derives this from NODE_ENV when it is left out, and in development
  // mode an uncaught error is answered with its stack.
  development: false,
  fetch: (req) => handle(req, deps),
});
console.log(`listening on :${server.port}`);

// A deploy stops the old copy with SIGTERM while the new one serves.
// Requests in flight finish; new ones go to the other copy.
let stopping = false;
async function stop(signal: string) {
  if (stopping) return;
  stopping = true;
  console.log(`${signal}: finishing requests in flight`);
  await server.stop();
  await sql.close({ timeout: 5 });
  process.exit(0);
}
process.on("SIGTERM", () => void stop("SIGTERM"));
process.on("SIGINT", () => void stop("SIGINT"));
