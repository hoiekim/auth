import { connect } from "./db";

// The service's configuration, read from the environment once at start.
// Every problem is collected, so a misconfigured deployment learns all of
// them in one restart. A message never echoes a value that can carry a
// secret.

export interface Config {
  port: number;
  databaseUrl: string;
}

export class ConfigError extends Error {
  constructor(readonly problems: string[]) {
    super(`invalid configuration:\n${problems.map((p) => `  - ${p}`).join("\n")}`);
    this.name = "ConfigError";
  }
}

const DEFAULT_PORT = 3000;

export function loadConfig(env: Record<string, string | undefined>): Config {
  const problems: string[] = [];

  let port = DEFAULT_PORT;
  const rawPort = env.PORT?.trim();
  if (rawPort) {
    port = /^\d+$/.test(rawPort) ? Number(rawPort) : 0;
    if (port < 1 || port > 65535) problems.push(`PORT must be a whole number from 1 to 65535, not "${rawPort}"`);
  }

  const databaseUrl = env.DATABASE_URL?.trim() ?? "";
  if (!databaseUrl) problems.push("DATABASE_URL is required");
  else if (!/^postgres(ql)?:\/\//.test(databaseUrl)) problems.push("DATABASE_URL must be a postgres:// or postgresql:// URL");
  else if (!parsesAsDatabaseUrl(databaseUrl)) problems.push("DATABASE_URL is not a well-formed URL");

  if (problems.length > 0) throw new ConfigError(problems);
  return { port, databaseUrl };
}

// Bun's SQL client reads the URL when the pool is created, and throws on
// anything it can't use: the port, a percent-escape, sslmode, a timeout.
// Creating the pool here, with the same call the server makes, reports that
// with the other problems instead of crashing the start after them. It
// opens no connection.
function parsesAsDatabaseUrl(value: string): boolean {
  try {
    void connect(value).close();
    return true;
  } catch {
    return false;
  }
}
