import type { SQL } from "bun";
import type { App } from "./app";
import { deliverDue } from "./events";
import { rotateKeys } from "./keys";

// Background work. Every copy runs it; Postgres decides who does what, so
// nothing depends on which copy is up (docs/DESIGN.md §8).

// Drops what has expired (§8 Housekeeping), in one copy at a time.
export async function housekeep(sql: SQL, auditRetentionDays: number): Promise<boolean> {
  return sql.begin(async (tx) => {
    const [lock] = await tx`SELECT pg_try_advisory_xact_lock(hashtext('auth.housekeeping')) AS got`;
    if (!lock.got) return false;
    await tx`DELETE FROM auth_codes WHERE expires_at < now() - interval '1 hour'`;
    await tx`DELETE FROM one_time_tokens WHERE expires_at < now() - interval '1 day'`;
    await tx`DELETE FROM sessions WHERE expires_at < now() OR ends_at < now()`;
    await tx`DELETE FROM refresh_tokens WHERE expires_at < now() OR revoked_at < now() - interval '1 day'`;
    await tx`DELETE FROM invites WHERE accepted_at IS NULL AND expires_at < now() - interval '30 days'`;
    await tx`DELETE FROM throttle WHERE window_start < now() - interval '1 day'`;
    await tx`DELETE FROM outbox WHERE delivered_at < now() - interval '7 days' OR failed_at < now() - interval '7 days'`;
    await tx`DELETE FROM audit WHERE at < now() - make_interval(days => ${auditRetentionDays})`;
    return true;
  });
}

const OUTBOX_EVERY_MS = 1000;
const HOURLY_MS = 60 * 60 * 1000;

export function startJobs(app: App): { stop: () => Promise<void> } {
  let delivering: Promise<unknown> | null = null;
  let hourly: Promise<unknown> | null = null;
  const outbox = setInterval(() => {
    delivering ??= deliverDue(app)
      .catch((e: unknown) => app.log(`outbox delivery failed: ${e instanceof Error ? e.name : typeof e}`))
      .finally(() => {
        delivering = null;
      });
  }, OUTBOX_EVERY_MS);
  const runHourly = () => {
    hourly ??= (async () => {
      await rotateKeys(app.sql, app.crypt);
      await housekeep(app.sql, app.config.auditRetentionDays);
    })()
      .catch((e: unknown) => app.log(`housekeeping failed: ${e instanceof Error ? e.name : typeof e}`))
      .finally(() => {
        hourly = null;
      });
  };
  const clock = setInterval(runHourly, HOURLY_MS);
  runHourly();
  return {
    async stop() {
      clearInterval(outbox);
      clearInterval(clock);
      await Promise.allSettled([delivering, hourly]);
    },
  };
}
