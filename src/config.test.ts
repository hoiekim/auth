import { describe, expect, test } from "bun:test";
import { ConfigError, loadConfig } from "./config";

const DATABASE_URL = "postgres://auth:s3cret-pw@db.internal:5432/auth";

function problems(env: Record<string, string | undefined>): string[] {
  try {
    loadConfig(env);
  } catch (e) {
    if (e instanceof ConfigError) return e.problems;
    throw e;
  }
  throw new Error("loadConfig accepted the environment");
}

describe("loadConfig", () => {
  test("reads a complete environment", () => {
    expect(loadConfig({ PORT: "8080", DATABASE_URL })).toEqual({ port: 8080, databaseUrl: DATABASE_URL });
  });

  test("defaults PORT to 3000 when it is unset or blank", () => {
    expect(loadConfig({ DATABASE_URL }).port).toBe(3000);
    expect(loadConfig({ PORT: "  ", DATABASE_URL }).port).toBe(3000);
  });

  test("accepts postgresql:// as well as postgres://", () => {
    const url = "postgresql://auth@localhost/auth";
    expect(loadConfig({ DATABASE_URL: url }).databaseUrl).toBe(url);
  });

  test("lists every problem at once", () => {
    expect(problems({ PORT: "http" })).toEqual([
      'PORT must be a whole number from 1 to 65535, not "http"',
      "DATABASE_URL is required",
    ]);
  });

  test.each(["0", "65536", "-1", "3e3", "80.5", "0x50"])("refuses PORT=%p", (port) => {
    expect(problems({ PORT: port, DATABASE_URL })).toHaveLength(1);
  });

  test.each(["1", "65535"])("accepts PORT=%p at the edge of the range", (port) => {
    expect(loadConfig({ PORT: port, DATABASE_URL }).port).toBe(Number(port));
  });

  test("refuses a DATABASE_URL that isn't a Postgres URL, without echoing it", () => {
    const url = "mysql://auth:s3cret-pw@db.internal/auth";
    const found = problems({ DATABASE_URL: url });
    expect(found).toEqual(["DATABASE_URL must be a postgres:// or postgresql:// URL"]);
    expect(found.join("\n")).not.toContain("s3cret-pw");
  });

  test.each([
    ["a port that isn't a number", "postgres://auth:s3cret-pw@db.internal:notaport/auth"],
    ["a port out of range", "postgres://auth:s3cret-pw@db.internal:99999/auth"],
    ["a broken percent-escape in the password", "postgres://auth:s3cret-pw%zz@db.internal/auth"],
    ["a broken percent-escape in the user", "postgres://a%zz:s3cret-pw@db.internal/auth"],
    ["port 0", "postgres://auth:s3cret-pw@db.internal:0/auth"],
    ["an unknown sslmode", "postgres://auth:s3cret-pw@db.internal/auth?sslmode=bogus"],
    ["a connect_timeout that isn't a number", "postgres://auth:s3cret-pw@db.internal/auth?connect_timeout=abc"],
  ])("refuses a postgres:// URL with %s, without echoing it", (_, url) => {
    const found = problems({ DATABASE_URL: url });
    expect(found).toEqual(["DATABASE_URL is not a well-formed URL"]);
    expect(found.join("\n")).not.toContain("s3cret-pw");
  });

  test("a malformed DATABASE_URL is reported alongside the other problems", () => {
    expect(problems({ PORT: "x", DATABASE_URL: "postgres://auth:pw@db:notaport/auth" })).toEqual([
      'PORT must be a whole number from 1 to 65535, not "x"',
      "DATABASE_URL is not a well-formed URL",
    ]);
  });

  test("the error message lists each problem on its own line", () => {
    expect(() => loadConfig({})).toThrow("invalid configuration:\n  - DATABASE_URL is required");
  });
});
