import { SQL } from "bun";

// docs/DESIGN.md §10 sizes the pool.
export function connect(url: string): SQL {
  return new SQL(url, { max: 5 });
}

// Below the pool's 5, so stalled pings never take every connection.
const MAX_PINGS = 2;

// Answers within `timeoutMs`, with at most MAX_PINGS queries in the pool.
//
// A caller that stops waiting can't cancel its query, which keeps its place
// in the pool until the database answers. So callers that arrive while a
// query runs share it, and share one answer that settles when the query does
// or when the timeout passes, whichever comes first. A promise that never
// settles keeps everything waiting on it alive, so no caller waits on a query
// past its timeout. After a timeout the next caller sends a fresh query, which
// another connection can answer when only one is stuck; once MAX_PINGS are
// stuck, callers get the last timed-out answer at once.
export function databasePing(sql: SQL, timeoutMs: number): () => Promise<void> {
  const queries = new Set<Promise<void>>();
  let answer: Promise<void> = Promise.resolve();
  let answering = false;
  return () => {
    if (answering || queries.size >= MAX_PINGS) return answer;
    const query = (async () => {
      await sql`SELECT 1`;
    })();
    queries.add(query);
    const done = () => {
      queries.delete(query);
    };
    query.then(done, done);
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timedOut = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error("timed out")), timeoutMs);
    });
    const current: Promise<void> = Promise.race([query, timedOut]).finally(() => {
      clearTimeout(timer);
      if (answer === current) answering = false;
    });
    answer = current;
    answering = true;
    return current;
  };
}
