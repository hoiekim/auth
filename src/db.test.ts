import { afterAll, describe, expect, test } from "bun:test";
import type { SQL } from "bun";
import { connect, databasePing } from "./db";
import { handle } from "./server";

const silent = { log: () => {} };

// Stands in for Bun's SQL tag: counts queries and answers each with `answer()`.
function fakeSql(answer: () => Promise<unknown>) {
  const counter = { queries: 0 };
  const sql = (() => {
    counter.queries++;
    return answer();
  }) as unknown as SQL;
  return { sql, counter };
}

const never = () => new Promise<unknown>(() => {});

// How `promise` settled, or "still pending" after `ms`, so a missing timeout
// fails the test instead of hanging the run.
function within<T>(promise: Promise<T>, ms = 1000): Promise<T | "still pending"> {
  return Promise.race([promise, Bun.sleep(ms).then(() => "still pending" as const)]);
}
const outcome = (promise: Promise<unknown>) =>
  within(promise.then(() => "resolved", (e: unknown) => `rejected: ${e instanceof Error ? e.message : String(e)}`));

describe("databasePing", () => {
  test("callers that overlap share one query", async () => {
    const { sql, counter } = fakeSql(never);
    const ping = databasePing(sql, 1000);
    for (let i = 0; i < 50; i++) ping().catch(() => {});
    expect(counter.queries).toBe(1);
  });

  test("a query that never answers is reported as a failure within the timeout", async () => {
    const { sql } = fakeSql(never);
    expect(await outcome(databasePing(sql, 20)())).toBe("rejected: timed out");
  });

  test("one stuck query doesn't hold health down: after its timeout a fresh query answers", async () => {
    const { sql, counter } = fakeSql(() => (counter.queries === 1 ? never() : Promise.resolve([])));
    const ping = databasePing(sql, 20);
    expect(await outcome(ping())).toBe("rejected: timed out");
    expect(await outcome(ping())).toBe("resolved");
    expect(counter.queries).toBe(2);
  });

  test("once two queries are stuck, later callers fail at once without sending another", async () => {
    const { sql, counter } = fakeSql(never);
    const ping = databasePing(sql, 50);
    expect(await outcome(ping())).toBe("rejected: timed out");
    expect(await outcome(ping())).toBe("rejected: timed out");
    const started = performance.now();
    expect(await outcome(ping())).toBe("rejected: timed out");
    expect(performance.now() - started).toBeLessThan(30);
    expect(counter.queries).toBe(2);
  });

  test("a stuck query that finally answers frees its place for a fresh one", async () => {
    const releases: (() => void)[] = [];
    const { sql, counter } = fakeSql(() =>
      counter.queries <= 2 ? new Promise((resolve) => releases.push(() => resolve([]))) : Promise.resolve([]),
    );
    const ping = databasePing(sql, 20);
    expect(await outcome(ping())).toBe("rejected: timed out");
    expect(await outcome(ping())).toBe("rejected: timed out");
    expect(await outcome(ping())).toBe("rejected: timed out");
    expect(counter.queries).toBe(2);
    releases[0]?.();
    await Bun.sleep(0);
    expect(await outcome(ping())).toBe("resolved");
    expect(counter.queries).toBe(3);
  });

  test("health probes during a database stall send at most two queries, and all answer 503", async () => {
    const { sql, counter } = fakeSql(never);
    const deps = { ...silent, pingDatabase: databasePing(sql, 20) };
    const probe = () => handle(new Request("http://auth.test/healthz"), deps);
    const statuses = async () => {
      const answers = await within(Promise.all(Array.from({ length: 20 }, probe)));
      return answers === "still pending" ? answers : answers.map((r) => r.status);
    };
    for (let round = 0; round < 3; round++) expect(await statuses()).toEqual(Array(20).fill(503));
    expect(counter.queries).toBe(2);
  });

  // A probe that waited on a stuck query would keep a reaction on it, about
  // 70 bytes each, for as long as the query stays stuck.
  test("probes during a stall don't accumulate memory", async () => {
    const { sql } = fakeSql(never);
    const deps = { ...silent, pingDatabase: databasePing(sql, 5) };
    const probe = () => handle(new Request("http://auth.test/healthz"), deps);
    const batch = () => Promise.all(Array.from({ length: 1000 }, probe));
    await batch();
    await Bun.sleep(10);
    await batch();
    await Bun.sleep(10);
    Bun.gc(true);
    const before = process.memoryUsage().heapUsed;
    for (let i = 0; i < 150; i++) await batch();
    Bun.gc(true);
    expect(process.memoryUsage().heapUsed - before).toBeLessThan(4_000_000);
  }, 30_000);

  test("once a ping settles, the next call queries again", async () => {
    const { sql, counter } = fakeSql(() => Promise.resolve([]));
    const ping = databasePing(sql, 1000);
    await ping();
    await ping();
    expect(counter.queries).toBe(2);
  });

  test("a failed ping fails every caller that shared it, then clears", async () => {
    let fail = true;
    const { sql, counter } = fakeSql(() => (fail ? Promise.reject(new Error("down")) : Promise.resolve([])));
    const ping = databasePing(sql, 1000);
    const shared = await Promise.allSettled([ping(), ping(), ping()]);
    expect(shared.map((r) => r.status)).toEqual(["rejected", "rejected", "rejected"]);
    expect(counter.queries).toBe(1);
    fail = false;
    await ping();
    expect(counter.queries).toBe(2);
  });
});

test("healthz answers 503, not a hang, when nothing listens at the database's address", async () => {
  const sql = connect("postgres://auth:s3cret-pw@127.0.0.1:1/auth");
  try {
    const res = await handle(new Request("http://auth.test/healthz"), { ...silent, pingDatabase: databasePing(sql, 2000) });
    expect(res.status).toBe(503);
    expect(await res.text()).not.toContain("s3cret-pw");
  } finally {
    await sql.close();
  }
});

// Needs a reachable Postgres: CI provides one; locally, set TEST_DATABASE_URL.
const url = process.env.TEST_DATABASE_URL;
describe.skipIf(!url)("against Postgres", () => {
  const sql = connect(url ?? "");
  afterAll(() => sql.close());

  test("healthz answers 200", async () => {
    const res = await handle(new Request("http://auth.test/healthz"), { ...silent, pingDatabase: databasePing(sql, 2000) });
    expect(res.status).toBe(200);
  });
});
