import type { SQL } from "bun";

// A transaction whose side effects outside Postgres (emails, alerts) run
// only once it has committed, so nothing announces a change that rolled back.
export type After = (effect: () => void) => void;

export async function transaction<T>(sql: SQL, work: (tx: SQL, after: After) => Promise<T>): Promise<T> {
  const effects: (() => void)[] = [];
  const result = await sql.begin((tx) => work(tx, (effect) => effects.push(effect)));
  for (const effect of effects) effect();
  return result;
}
