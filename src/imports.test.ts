import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { runCli } from "./cli";
import type { MailMessage } from "./mail";
import { basic, Browser, makeUser, outboxEvents, TEST_DATABASE_URL, testApp, testDb, type TestApp, type TestDb } from "./testing/harness";

// Moving an app's users and API keys into auth (docs/DESIGN.md §12.5, §13).
describe.skipIf(!TEST_DATABASE_URL)("imports", () => {
  let db: TestDb;
  let t: TestApp;
  beforeAll(async () => {
    db = await testDb();
    t = await testApp(db.sql);
  });
  afterAll(() => db.drop());

  async function run(argv: string[], input: string) {
    const out: string[] = [];
    const sent: MailMessage[] = [];
    let readFrom = "";
    const code = await runCli(argv, {
      app: t.app,
      mailer: { send: async (m) => void sent.push(m) },
      out: (l) => out.push(l),
      readInput: async (path) => {
        readFrom = path;
        return input;
      },
    });
    return { code, out, sent, readFrom };
  }
  const jsonl = (...rows: object[]) => rows.map((r) => JSON.stringify(r)).join("\n");
  const userCount = async () => (await db.sql`SELECT count(*)::int AS n FROM users`)[0].n as number;

  describe("users", () => {
    test("bcrypt and argon2 hashes sign in with the old passwords, and are rehashed at the first sign-in", async () => {
      const bcrypt = await Bun.password.hash("old bcrypt password", { algorithm: "bcrypt", cost: 4 });
      const argon = await Bun.password.hash("old argon password", { algorithm: "argon2id", memoryCost: 65536, timeCost: 3 });
      const { code, out } = await run(
        ["import", "users", "-"],
        jsonl(
          { username: "ida", email: "ida@example.com", name: "Ida", email_verified: true, password_hash: bcrypt, access: { wiki: "member", tasks: "user" } },
          { username: "jon", email: "jon@example.com", password_hash: argon },
        ),
      );
      expect(code).toBe(0);
      expect(out.at(-1)).toBe("imported 2 users");
      expect((await new Browser(t).signIn("ida", "old bcrypt password")).status).toBe(303);
      expect((await new Browser(t).signIn("jon", "old argon password")).status).toBe(303);
      const rows = await db.sql`SELECT username, password_hash, email_verified_at IS NOT NULL AS verified FROM users WHERE username IN ('ida', 'jon') ORDER BY username`;
      for (const r of rows) expect(r.password_hash).toStartWith("$argon2id$v=19$m=19456,t=2,p=1$");
      expect(rows.map((r: { verified: boolean }) => r.verified)).toEqual([true, false]);
      const access = await db.sql`SELECT a.service, a.role, a.granted_by FROM access a JOIN users u ON u.id = a.user_id WHERE u.username = 'ida' ORDER BY service`;
      expect(access).toEqual([
        { service: "tasks", role: "user", granted_by: "host-cli" },
        { service: "wiki", role: "member", granted_by: "host-cli" },
      ]);
      expect((await outboxEvents(db.sql, "wiki")).some((e) => e.type === "access.changed" && e.payload.role === "member")).toBe(true);
      const [a] = await db.sql`SELECT actor, detail FROM audit WHERE action = 'user.create' AND detail->>'username' = 'ida'`;
      expect(a).toMatchObject({ actor: "host-cli", detail: { imported: true } });
    });

    test("a user without a password hash gets an activation link, emailed or printed", async () => {
      const emailed = await run(["import", "users", "users.jsonl"], jsonl({ username: "kim", email: "kim@example.com" }));
      expect(emailed.readFrom).toBe("users.jsonl");
      expect(emailed.sent.map((m) => [m.to, m.subject])).toEqual([["kim@example.com", "Activate your account"]]);
      const printed = await run(["import", "users", "-", "--print-links"], jsonl({ username: "lea", email: "lea@example.com" }));
      expect(printed.sent).toHaveLength(0);
      const link = printed.out.find((l) => l.startsWith("lea: "))!;
      const token = new URL(link.slice(5)).searchParams.get("token")!;
      expect((await new Browser(t).form("/activate", { token, password: "correct horse battery" })).status).toBe(303);
    });

    test("one bad line writes nothing, and every problem is listed by line without echoing a value", async () => {
      const before = await userCount();
      const hash = "$2b$04$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0s3cret";
      const { code, out } = await run(
        ["import", "users", "-"],
        [
          JSON.stringify({ username: "fine-one", email: "fine@example.com" }),
          JSON.stringify({ username: "ida", email: "taken-name@example.com" }),
          JSON.stringify({ username: "moe", email: "IDA@example.com" }),
          JSON.stringify({ username: "fine-one", email: "dup@example.com" }),
          JSON.stringify({ username: "nina", email: "nina@example.com", password_hash: "md5:5f4dcc3b5aa765d61d8327deb882cf99" }),
          JSON.stringify({ username: "olaf", email: "not-an-address", passwrod_hash: hash }),
          JSON.stringify({ username: "pia", email: "pia@example.com", access: { wiki: "superuser", nowhere: "x" } }),
          "{ not json",
          "",
          "[1, 2]",
        ].join("\n"),
      );
      expect(code).toBe(1);
      expect(await userCount()).toBe(before);
      expect(out).toEqual([
        "line 2: username is taken",
        "line 3: email is used by another account",
        "line 4: username is also on line 1",
        "line 5: password_hash is not an argon2 or bcrypt PHC string",
        'line 6: unknown field "passwrod_hash"',
        "line 6: email is not an email address",
        "line 7: access gives wiki a role it doesn't declare",
        "line 7: access names a service the services file doesn't have",
        "line 8: not valid JSON",
        "line 10: not a JSON object",
        "nothing imported: 10 problem(s)",
      ]);
      expect(out.join("\n")).not.toContain("s3cret");
      expect(out.join("\n")).not.toContain("5f4dcc3b");
    });

    test("--dry-run checks and writes nothing", async () => {
      const before = await userCount();
      const { code, out } = await run(["import", "users", "-", "--dry-run"], jsonl({ username: "quinn", email: "quinn@example.com" }));
      expect(code).toBe(0);
      expect(out).toEqual(["every line passed; nothing written (--dry-run)"]);
      expect(await userCount()).toBe(before);
    });

    test("an empty input is a problem", async () => {
      expect((await run(["import", "users", "-"], "\n\n")).out[0]).toBe("the input has no lines");
    });
  });

  describe("API keys", () => {
    let rae: string;
    const key = (n: number) => `legacy_${n}_${"k".repeat(30)}`;
    const sha = (k: string) => createHash("sha256").update(k).digest();
    const introspect = async (secret: string) =>
      (await (
        await new Browser(t).request("/oauth/introspect", {
          method: "POST",
          origin: null,
          headers: { Authorization: basic("tasks", t.secrets.tasks!), "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ token: secret }).toString(),
        })
      ).json()) as any;

    beforeAll(async () => {
      rae = await makeUser(t, { username: "rae", password: "correct horse battery", access: { tasks: "user" } });
      await makeUser(t, { username: "sid", password: "correct horse battery" });
    });

    test("existing keys keep working without reissue, found by their SHA-256", async () => {
      const { code, out } = await run(
        ["import", "api-keys", "--service", "tasks", "-"],
        jsonl(
          { owner: "rae", sha256: sha(key(1)).toString("hex"), scopes: ["tasks:read"], name: "ci", created_at: "2025-01-02T03:04:05Z" },
          { owner: rae, sha256: sha(key(2)).toString("base64"), scopes: ["tasks:read", "tasks:write"] },
          { owner: "rae", sha256: sha(key(3)).toString("base64url"), scopes: ["tasks:read"], revoked_at: "2026-01-01T00:00:00Z" },
          { owner: "rae", sha256: sha(key(4)).toString("hex"), scopes: ["tasks:read"], expires_at: "2020-01-01T00:00:00+00:00" },
        ),
      );
      expect(out.at(-1)).toBe("imported 4 API keys");
      expect(code).toBe(0);
      expect(await introspect(key(1))).toMatchObject({ active: true, sub: rae, username: "rae", scope: "tasks:read", role: "user" });
      expect(await introspect(key(2))).toMatchObject({ active: true, scope: "tasks:read tasks:write" });
      expect((await introspect(key(3))).active).toBe(false);
      expect((await introspect(key(4))).active).toBe(false);
      const [row] = await db.sql`SELECT name, created_at FROM credentials WHERE secret_hash = ${sha(key(1))}`;
      expect(row.name).toBe("ci");
      expect(row.created_at.toISOString()).toBe("2025-01-02T03:04:05.000Z");
      // The owner sees them listed, by id and name only.
      const b = new Browser(t);
      await b.signIn("rae", "correct horse battery");
      const listed = (await (await b.api("GET", "/v1/me/api-keys")).json()) as any;
      expect(listed.items.map((k: { name: string }) => k.name)).toContain("ci");
    });

    test("every refusal is listed, and nothing is written", async () => {
      const before = (await db.sql`SELECT count(*)::int AS n FROM credentials`)[0].n;
      const { code, out } = await run(
        ["import", "api-keys", "--service", "tasks", "-"],
        jsonl(
          { owner: "sid", sha256: sha(key(10)).toString("hex"), scopes: ["tasks:read"] },
          { owner: "nobody-here", sha256: sha(key(11)).toString("hex"), scopes: ["tasks:read"] },
          { owner: "rae", sha256: sha(key(1)).toString("hex"), scopes: ["tasks:read"] },
          { owner: "rae", sha256: sha(key(12)).toString("hex"), scopes: ["tasks:admin"] },
          { owner: "rae", sha256: "not-a-hash", scopes: ["tasks:read"] },
          { owner: "rae", sha256: sha(key(13)).toString("hex"), scopes: ["tasks:read"], expires_at: "tomorrow" },
          { owner: "rae", sha256: sha(key(13)).toString("hex"), scopes: ["tasks:read"] },
          { owner: "rae", sha256: sha(key(14)).toString("hex"), scopes: ["tasks:read"] },
        ),
      );
      expect(code).toBe(1);
      expect(out).toEqual([
        "line 1: owner has no role on tasks",
        "line 2: owner is not a user",
        "line 3: sha256 is already a credential",
        "line 4: scopes must be a non-empty list from: tasks:read, tasks:write",
        "line 5: sha256 must be 64 hex characters, or 32 bytes in base64",
        "line 6: expires_at must be an RFC 3339 timestamp",
        "line 7: sha256 is also on line 6",
        "nothing imported: 7 problem(s)",
      ]);
      expect((await db.sql`SELECT count(*)::int AS n FROM credentials`)[0].n).toBe(before);
    });

    test("--dry-run checks the keys and writes none", async () => {
      const before = (await db.sql`SELECT count(*)::int AS n FROM credentials`)[0].n;
      const { code, out } = await run(
        ["import", "api-keys", "--service", "tasks", "-", "--dry-run"],
        jsonl({ owner: "rae", sha256: sha(key(20)).toString("hex"), scopes: ["tasks:read"] }),
      );
      expect(code).toBe(0);
      expect(out).toEqual(["every line passed; nothing written (--dry-run)"]);
      expect((await db.sql`SELECT count(*)::int AS n FROM credentials`)[0].n).toBe(before);
      expect((await introspect(key(20))).active).toBe(false);
    });

    test("a service without API key scopes, or an unknown one, takes none", async () => {
      expect((await run(["import", "api-keys", "--service", "wiki", "-"], jsonl({ owner: "rae" }))).out[0]).toBe(
        "wiki declares no api_key_scopes, so it takes no API keys",
      );
      expect((await run(["import", "api-keys", "--service", "nope", "-"], "{}")).code).toBe(2);
    });
  });
});
