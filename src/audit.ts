import type { SQL } from "bun";

// The audit log (docs/DESIGN.md §8): identity events, never a secret, a token
// or a password in `detail`. Written in the same transaction as the change it
// records.

export interface AuditEntry {
  // usr_…, cli_<service>, 'host-cli', or null for anonymous
  actor: string | null;
  action: string;
  userId?: string | null;
  ip?: string | null;
  detail?: Record<string, string | number | boolean | null | string[]>;
}

export async function audit(sql: SQL, e: AuditEntry): Promise<void> {
  await sql`
    INSERT INTO audit (actor, action, user_id, ip, detail)
    VALUES (${e.actor}, ${e.action}, ${e.userId ?? null}, ${e.ip ?? null}::inet, ${JSON.stringify(e.detail ?? {})}::text::jsonb)`;
}

// The actor recorded for a service's own client (§7.5 ★ endpoints).
export function clientActor(service: string): string {
  return `cli_${service}`;
}
