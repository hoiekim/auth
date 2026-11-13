import type { SQL } from "bun";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

// Plain SQL migrations, applied at start under an advisory lock so two copies
// starting together apply each one once (docs/DESIGN.md §8). Each is
// expand-only: the copy still running the previous image keeps working.

const DIR = join(import.meta.dir, "migrations");

export async function migrate(sql: SQL, log: (line: string) => void = () => {}): Promise<void> {
  const files = readdirSync(DIR)
    .filter((f) => /^\d{4}_[a-z0-9_]+\.sql$/.test(f))
    .sort();
  const conn = await sql.reserve();
  try {
    await conn`SELECT pg_advisory_lock(hashtext('auth.migrate'))`;
    try {
      await conn`CREATE TABLE IF NOT EXISTS schema_migrations (
        version    text PRIMARY KEY,
        applied_at timestamptz NOT NULL DEFAULT now()
      )`;
      const applied = new Set((await conn`SELECT version FROM schema_migrations`).map((r: { version: string }) => r.version));
      for (const file of files) {
        const version = file.slice(0, -".sql".length);
        if (applied.has(version)) continue;
        const text = readFileSync(join(DIR, file), "utf8");
        await conn.begin(async (tx) => {
          await tx.unsafe(text);
          await tx`INSERT INTO schema_migrations (version) VALUES (${version})`;
        });
        log(`migration ${version} applied`);
      }
    } finally {
      await conn`SELECT pg_advisory_unlock(hashtext('auth.migrate'))`;
    }
  } finally {
    conn.release();
  }
}
