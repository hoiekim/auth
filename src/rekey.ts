import type { SQL } from "bun";
import { Encrypter } from "./crypto";

// Re-encryption after the encryption key changes (docs/DESIGN.md §9.3): every
// TOTP secret and private signing key, each under its row id as additional
// data, moves to the current key. Each row is rewritten in a transaction of
// its own under a row lock, so the server can keep running alongside.

interface Column {
  label: string;
  ids: (sql: SQL) => Promise<string[]>;
  read: (tx: SQL, id: string) => Promise<Buffer | null>;
  write: (tx: SQL, id: string, sealed: Buffer) => Promise<unknown>;
}

const COLUMNS: Column[] = [
  {
    label: "TOTP secrets",
    ids: async (sql) => (await sql`SELECT user_id FROM totp ORDER BY user_id`).map((r: { user_id: string }) => r.user_id),
    read: async (tx, id) => (await tx`SELECT secret_enc FROM totp WHERE user_id = ${id} FOR UPDATE`)[0]?.secret_enc ?? null,
    write: (tx, id, sealed) => tx`UPDATE totp SET secret_enc = ${sealed} WHERE user_id = ${id}`,
  },
  {
    label: "signing keys",
    ids: async (sql) => (await sql`SELECT kid FROM signing_keys ORDER BY kid`).map((r: { kid: string }) => r.kid),
    read: async (tx, id) => (await tx`SELECT private_key_enc FROM signing_keys WHERE kid = ${id} FOR UPDATE`)[0]?.private_key_enc ?? null,
    write: (tx, id, sealed) => tx`UPDATE signing_keys SET private_key_enc = ${sealed} WHERE kid = ${id}`,
  },
];

export interface ColumnStatus {
  label: string;
  // Rows per key version, e.g. { "1": 4, "2": 10 }.
  byVersion: Record<string, number>;
  // Rows whose version has no configured key.
  unreadable: number;
}

export async function encryptionStatus(sql: SQL, crypt: Encrypter): Promise<ColumnStatus[]> {
  const out: ColumnStatus[] = [];
  for (const column of COLUMNS) {
    const status: ColumnStatus = { label: column.label, byVersion: {}, unreadable: 0 };
    for (const id of await column.ids(sql)) {
      const sealed = await column.read(sql, id);
      if (!sealed) continue;
      const version = Encrypter.versionOf(sealed);
      const name = version === null ? "none" : String(version);
      status.byVersion[name] = (status.byVersion[name] ?? 0) + 1;
      if (version === null || !crypt.versions.includes(version)) status.unreadable++;
    }
    out.push(status);
  }
  return out;
}

export interface ColumnResult {
  label: string;
  rewritten: number;
  current: number;
  // Rows no configured key could read, left as they were.
  failed: string[];
}

export async function reencrypt(sql: SQL, crypt: Encrypter): Promise<ColumnResult[]> {
  const out: ColumnResult[] = [];
  for (const column of COLUMNS) {
    const result: ColumnResult = { label: column.label, rewritten: 0, current: 0, failed: [] };
    for (const id of await column.ids(sql)) {
      const outcome = await sql.begin(async (tx) => {
        const sealed = await column.read(tx, id);
        if (!sealed) return "gone";
        if (Encrypter.versionOf(sealed) === crypt.version) return "current";
        let plaintext: Buffer;
        try {
          plaintext = crypt.decrypt(sealed, id);
        } catch {
          return "failed";
        }
        await column.write(tx, id, crypt.encrypt(plaintext, id));
        return "rewritten";
      });
      if (outcome === "rewritten") result.rewritten++;
      else if (outcome === "current") result.current++;
      else if (outcome === "failed") result.failed.push(id);
    }
    out.push(result);
  }
  return out;
}
