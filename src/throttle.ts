import type { SQL } from "bun";

// Rate limits (docs/DESIGN.md §9.4), counted in the shared `throttle` table so
// every copy sees the same numbers and a restart doesn't reset them.

export interface Verdict {
  allowed: boolean;
  retryAfter: number;
}

// A fixed window: `limit` hits per `windowSeconds`, counted per key.
export async function hit(sql: SQL, key: string, limit: number, windowSeconds: number): Promise<Verdict> {
  const [row] = await sql`
    INSERT INTO throttle AS t (key, window_start, hits) VALUES (${key}, now(), 1)
    ON CONFLICT (key) DO UPDATE SET
      window_start = CASE WHEN t.window_start <= now() - make_interval(secs => ${windowSeconds}) THEN now() ELSE t.window_start END,
      hits = CASE WHEN t.window_start <= now() - make_interval(secs => ${windowSeconds}) THEN 1 ELSE t.hits + 1 END
    RETURNING hits,
      GREATEST(1, ceil(extract(epoch FROM window_start + make_interval(secs => ${windowSeconds}) - now())))::int AS retry_after`;
  return { allowed: row.hits <= limit, retryAfter: row.retry_after };
}

// Sign-in failures per account: five, then one attempt a minute, doubling up
// to fifteen minutes. There is no lockout, so nobody can lock another person
// out; a success or a reset clears it.
export async function failureWait(sql: SQL, key: string): Promise<Verdict> {
  const [row] = await sql`
    SELECT GREATEST(0, ceil(extract(epoch FROM
             window_start + make_interval(secs => LEAST(60 * power(2, hits - 5), 900)) - now())))::int AS wait
    FROM throttle WHERE key = ${key} AND hits >= 5`;
  const wait = row?.wait ?? 0;
  return { allowed: wait === 0, retryAfter: wait };
}

export async function recordFailure(sql: SQL, key: string): Promise<void> {
  await sql`
    INSERT INTO throttle AS t (key, window_start, hits) VALUES (${key}, now(), 1)
    ON CONFLICT (key) DO UPDATE SET window_start = now(), hits = t.hits + 1`;
}

export async function clear(sql: SQL, ...keys: string[]): Promise<void> {
  for (const key of keys) await sql`DELETE FROM throttle WHERE key = ${key}`;
}

// True the first time a key is seen: a WebAuthn challenge used once.
// Housekeeping drops the row after a day, longer than anything it guards lives.
export async function once(sql: SQL, key: string): Promise<boolean> {
  const rows = await sql`
    INSERT INTO throttle (key, window_start, hits) VALUES (${key}, now(), 1)
    ON CONFLICT (key) DO NOTHING RETURNING key`;
  return rows.length === 1;
}

export function tooMany(verdict: Verdict): Record<string, string> {
  return { "Retry-After": String(verdict.retryAfter) };
}

// The hits counted under a key in its current window, without adding one:
// for limits that count failures only.
export async function peek(sql: SQL, key: string, limit: number, windowSeconds: number): Promise<Verdict> {
  const [row] = await sql`
    SELECT hits, GREATEST(1, ceil(extract(epoch FROM window_start + make_interval(secs => ${windowSeconds}) - now())))::int AS retry_after
    FROM throttle WHERE key = ${key} AND window_start > now() - make_interval(secs => ${windowSeconds})`;
  return { allowed: !row || row.hits < limit, retryAfter: row?.retry_after ?? 0 };
}
