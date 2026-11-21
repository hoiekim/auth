import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { randomBytes } from "node:crypto";
import { backChannel, basic, CLI, Crypt, enabled, hashPassword, ID, newId, sha256, Stack, type Exit } from "./harness";

// The break-glass CLI (docs/DESIGN.md §9.3, §9.6, §13; docs/DEPLOYMENT.md
// §3): every command, every refusal and its words, what each writes, audits,
// mails and alerts, and the imports' per-line checks.

setDefaultTimeout(60_000);

const HELP = `usage: ${CLI} <command>

  user create --username <name> --email <address> [--name <name>] [--access <service>:<role>]... [--print-link]
  user create --username <name> --bot --owner <username> [--name <name>] [--access <service>:<role>]...
      Creates a user. A person gets an activation link by email, or printed
      here with --print-link.
  user clear-mfa <username>      Removes TOTP, passkeys and recovery codes, and signs the user out.
  user disable <username>        Disables the user everywhere.
  user enable <username>         Re-enables a disabled user.
  user reset-link <username> [--print-link]
      Sends a password reset link, or prints it.
  client secret <client id>      Prints a new secret for a confidential client, once. The
                                 previous secret keeps working until retire-old-secrets.
  client retire-old-secrets <client id>
  encryption status              Counts TOTP secrets and signing keys per encryption key version.
  encryption reencrypt           Rewrites them all under AUTH_ENCRYPTION_KEY (a key rotation's
                                 third step, docs/DESIGN.md §9.3).
  import users <file | -> [--dry-run] [--print-links]
      Creates users from JSON Lines: {"username", "email", "name"?, "email_verified"?,
      "password_hash"? (argon2 or bcrypt), "access"? {"<service>": "<role>"}}. Users without
      a password hash get an activation link by email, or printed with --print-links.
  import api-keys --service <name> <file | -> [--dry-run]
      Adds an app's existing API keys from JSON Lines: {"owner" (sub or username), "sha256",
      "scopes", "name"?, "expires_at"?, "revoked_at"?, "created_at"?, "last_used_at"?}.
      Both imports check every line first and write all or nothing; - reads standard input.
  migrate                        Applies pending migrations (the server does this at start).
`;

const PASSWORD = "correct horse battery";
const TOKEN = "[A-Za-z0-9_-]{43}";
const unique = (prefix: string) => `${prefix}-${randomBytes(3).toString("hex")}`;
const lines = (...values: unknown[]) => values.map((v) => (typeof v === "string" ? v : JSON.stringify(v))).join("\n") + "\n";
const key = (fill: number) => Buffer.alloc(32, fill).toString("base64");
const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

function expectExit(exit: Exit, code: number, out: string[]): void {
  expect({ code: exit.code, out: exit.out }).toEqual({ code, out });
}

describe.skipIf(!enabled)("the break-glass CLI", () => {
  let stack: Stack;
  beforeAll(async () => {
    stack = await Stack.start();
  });
  afterAll(async () => {
    await stack.stop();
  });
  beforeEach(async () => {
    await stack.resetLimits();
    stack.smtp.replies = {};
    stack.http.onAlert = () => 200;
  });

  const cli = (args: string[], opts: { stdin?: string; env?: Record<string, string | undefined> } = {}) => stack.cli(args, opts);
  const userRow = async (username: string) => {
    const [row] = await stack.db`SELECT * FROM users WHERE username = ${username}`;
    return row as { id: string; username: string; name: string; email: string | null; kind: string; owner_id: string | null; password_hash: string | null; disabled_at: Date | null; email_verified_at: Date | null } | undefined;
  };
  const auditOf = async (userId: string) => (await stack.audit()).filter((a) => a.user_id === userId).map((a) => ({ actor: a.actor, action: a.action, detail: a.detail }));
  // Whether a client secret authenticates at the token introspection endpoint.
  const authenticates = async (clientId: string, secret: string) => {
    const res = await backChannel(stack, "/oauth/introspect", { token: "x" }, basic(clientId, secret));
    await res.body?.cancel();
    return res.status === 200;
  };

  describe("usage", () => {
    test.each([
      ["help", ["help"], 0],
      ["no arguments", [], 0],
      ["an unknown command", ["user", "explode"], 2],
      ["an unknown group", ["frobnicate"], 2],
      ["a group alone", ["user"], 2],
    ])("%s prints the help", async (_, args, code) => {
      const exit = await cli(args);
      expect(exit.stdout).toBe(`${HELP}\n`);
      expect(exit.code).toBe(code);
    });

    test("a flag without a value is refused with the help", async () => {
      const exit = await cli(["user", "create", "--username"]);
      expect(exit.stdout).toBe(`--username needs a value\n\n${HELP}\n`);
      expect(exit.code).toBe(2);
    });

    test.each([
      ["--username", ["user", "create", "--username", "alice-a", "--username", "alice-b", "--email", "a@example.com"]],
      ["--email", ["user", "create", "--username", "alice-c", "--email", "a@example.com", "--email", "b@example.com"]],
      ["--name", ["user", "create", "--username", "alice-d", "--email", "a@example.com", "--name", "A", "--name", "B"]],
      ["--owner", ["user", "create", "--username", "bot-e", "--bot", "--owner", "x", "--owner", "y"]],
      ["--service", ["import", "api-keys", "--service", "tasks", "--service", "tasks", "-"]],
    ])("%s given twice is refused", async (flag, args) => {
      expectExit(await cli(args, { stdin: "" }), 2, [`error: ${flag} is given twice`]);
    });

    test("a configuration problem stops the CLI before anything, even help", async () => {
      const exit = await cli(["help"], { env: { DATABASE_URL: undefined, SMTP_URL: "smtp://user:s3cret-pw@mail.example.com/x" } });
      expect(exit.stderr).toBe(
        "invalid configuration:\n  - DATABASE_URL is required\n  - SMTP_URL must be smtps://[user:password@]host[:port], or smtp:// (STARTTLS, or plain only to a loopback host)\n",
      );
      expect(exit.stdout).toBe("");
      expect(exit.code).toBe(1);
    });
  });

  describe("user create", () => {
    test("a person, with an activation link printed, audited as host-cli and alerted", async () => {
      const username = unique("alice");
      const exit = await cli(["user", "create", "--username", username, "--email", `${username}@example.com`, "--name", "  Alice Example ", "--print-link"]);
      expect(exit.code).toBe(0);
      const row = (await userRow(username))!;
      expect(exit.out).toHaveLength(2);
      expect(exit.out[0]).toBe(`created ${username} (${row.id})`);
      expect(exit.out[1]).toMatch(new RegExp(`^activation link \\(works once, 14 days\\): ${escape(stack.issuer)}/activate\\?token=${TOKEN}$`));
      expect(row.id).toMatch(ID);
      expect(row).toMatchObject({ name: "Alice Example", email: `${username}@example.com`, kind: "person", owner_id: null, password_hash: null, disabled_at: null, email_verified_at: null });
      expect(await auditOf(row.id)).toEqual([{ actor: "host-cli", action: "user.create", detail: { username, kind: "person" } }]);
      await stack.http.waitForAlert(`auth (break-glass CLI): created ${username}`);
      expect(stack.alerts).toContain(`auth (break-glass CLI): created ${username}`);
      expect(stack.smtp.to(`${username}@example.com`)).toEqual([]);
      // The link opens the activation page.
      const link = new URL(exit.out[1]!.slice(exit.out[1]!.indexOf("http")));
      const page = await stack.browser().get(link.pathname + link.search);
      expect(page.status).toBe(200);
      const html = await page.text();
      expect(html).toContain("<title>Activate your account");
      expect(html).toContain(`name="username" value="${username}"`);
    });

    test("without --print-link the activation link is emailed", async () => {
      const username = unique("bob");
      const email = `${username}@example.com`;
      const exit = await cli(["user", "create", "--username", username, "--email", ` ${email} `]);
      const row = (await userRow(username))!;
      expectExit(exit, 0, [`created ${username} (${row.id})`, `emailed ${email}`]);
      const mail = await stack.smtp.waitFor(email);
      expect(mail.subject).toBe("Activate your account");
      expect(mail.text).toMatch(new RegExp(`${escape(stack.issuer)}/activate\\?token=${TOKEN}\\n`));
      expect(row.email).toBe(email);
    });

    test("a mail that fails says how to print a link instead", async () => {
      const username = unique("carol");
      stack.smtp.replies = { RCPT: "550 no such user" };
      const exit = await cli(["user", "create", "--username", username, "--email", `${username}@example.com`]);
      const row = (await userRow(username))!;
      expectExit(exit, 0, [
        `created ${username} (${row.id})`,
        `the email to ${username}@example.com failed (smtp: server answered 550 to RCPT); print a link instead with: ${CLI} user reset-link ${username} --print-link`,
      ]);
    });

    test("--access once grants the role, audited, with an event to the service", async () => {
      const username = unique("dave");
      const exit = await cli(["user", "create", "--username", username, "--email", `${username}@example.com`, "--access", "wiki:member", "--print-link"]);
      expect(exit.code).toBe(0);
      const row = (await userRow(username))!;
      const access = await stack.db`SELECT service, role, granted_by FROM access WHERE user_id = ${row.id}`;
      expect(access).toEqual([{ service: "wiki", role: "member", granted_by: "host-cli" }]);
      expect(await auditOf(row.id)).toEqual([
        { actor: "host-cli", action: "user.create", detail: { username, kind: "person" } },
        { actor: "host-cli", action: "access.put", detail: { service: "wiki", role: "member", previous: null } },
      ]);
      const events = (await stack.outbox("wiki")).filter((e) => e.payload.sub === row.id);
      expect(events.map((e) => [e.type, e.payload])).toEqual([["access.changed", { sub: row.id, role: "member" }]]);
      await stack.http.waitForAlert(`auth (break-glass CLI): created ${username} with wiki:member`);
    });

    test("--access several times grants each, and the alert names them", async () => {
      const username = unique("erin");
      const exit = await cli(["user", "create", "--username", username, "--email", `${username}@example.com`, "--access", "wiki:admin", "--access", "tasks:user", "--access", "notes:reader", "--print-link"]);
      expect(exit.code).toBe(0);
      const row = (await userRow(username))!;
      const access = await stack.db`SELECT service, role FROM access WHERE user_id = ${row.id} ORDER BY service`;
      expect(access).toEqual([
        { service: "notes", role: "reader" },
        { service: "tasks", role: "user" },
        { service: "wiki", role: "admin" },
      ]);
      // notes has no events_url.
      expect((await stack.outbox()).filter((e) => e.payload.sub === row.id).map((e) => e.service).sort()).toEqual(["tasks", "wiki"]);
      await stack.http.waitForAlert(`auth (break-glass CLI): created ${username} with wiki:admin, tasks:user, notes:reader`);
    });

    test("--access auth:admin makes an administrator", async () => {
      const username = unique("root");
      expect((await cli(["user", "create", "--username", username, "--email", `${username}@example.com`, "--access", "auth:admin", "--print-link"])).code).toBe(0);
      const row = (await userRow(username))!;
      expect(await stack.db`SELECT service, role, granted_by FROM access WHERE user_id = ${row.id}`).toEqual([{ service: "auth", role: "admin", granted_by: "host-cli" }]);
      await stack.http.waitForAlert(`auth (break-glass CLI): created ${username} with auth:admin`);
    });

    test.each([
      ["an unknown role", "wiki:root"],
      ["an unknown service", "nowhere:member"],
      ["no role", "wiki"],
      ["an empty role", "wiki:"],
      ["no service", ":member"],
      ["a role of another service", "wiki:user"],
    ])("--access with %s is refused, and nothing is written", async (_, grant) => {
      const username = unique("frank");
      expectExit(await cli(["user", "create", "--username", username, "--email", `${username}@example.com`, "--access", "wiki:member", "--access", grant]), 2, [
        `error: --access ${grant}: use <service>:<role> with a role the service declares`,
      ]);
      expect(await userRow(username)).toBeUndefined();
    });

    test.each([
      ["missing", []],
      ["too short", ["--username", "ab"]],
      ["upper case", ["--username", "Alice"]],
      ["ending in -", ["--username", "alice-"]],
      ["33 characters", ["--username", `a${"b".repeat(32)}`]],
    ])("a username %s is refused", async (_, args) => {
      expectExit(await cli(["user", "create", ...args, "--email", "someone@example.com"]), 1, [
        "error: A username is 3 to 32 characters: a–z, 0–9 and '-', starting with a letter and not ending with '-'.",
      ]);
    });

    test.each([
      ["missing", []],
      ["not an address", ["--email", "alice"]],
      ["without a dot in the domain", ["--email", "alice@localhost"]],
    ])("an email %s is refused", async (_, args) => {
      const username = unique("gina");
      expectExit(await cli(["user", "create", "--username", username, ...args]), 1, ["error: That is not an email address."]);
      expect(await userRow(username)).toBeUndefined();
    });

    test.each([
      ["201 characters", "n".repeat(201)],
      ["a control character", "Al\u0007ice"],
    ])("a name of %s is refused", async (_, name) => {
      const username = unique("hank");
      expectExit(await cli(["user", "create", "--username", username, "--email", `${username}@example.com`, "--name", name]), 1, [
        "error: A name is at most 200 characters, with no control characters.",
      ]);
    });

    test("a name of 200 characters, some outside ASCII, is kept", async () => {
      const username = unique("ines");
      const name = "é".repeat(200);
      expect((await cli(["user", "create", "--username", username, "--email", `${username}@example.com`, "--name", name, "--print-link"])).code).toBe(0);
      expect((await userRow(username))!.name).toBe(name);
    });

    test("a username or address that is taken is a conflict, exit 1", async () => {
      const taken = await stack.user({ username: unique("jack") });
      expectExit(await cli(["user", "create", "--username", taken.username, "--email", "other@example.com"]), 1, ["error: That username is taken."]);
      const username = unique("jill");
      expectExit(await cli(["user", "create", "--username", username, "--email", taken.email!.toUpperCase()]), 1, ["error: Another account uses that email address."]);
      expect(await userRow(username)).toBeUndefined();
    });

    test("a bot, owned by a person, has no email and no link", async () => {
      const owner = await stack.user({ username: unique("kate") });
      const username = unique("mailer");
      const exit = await cli(["user", "create", "--username", username, "--bot", "--owner", owner.username, "--access", "mailbox:user", "--email", "ignored@example.com"]);
      const row = (await userRow(username))!;
      expectExit(exit, 0, [`created ${username} (${row.id})`]);
      expect(row).toMatchObject({ kind: "bot", owner_id: owner.id, email: null, password_hash: null });
      expect(await auditOf(row.id)).toEqual([
        { actor: "host-cli", action: "user.create", detail: { username, kind: "bot" } },
        { actor: "host-cli", action: "access.put", detail: { service: "mailbox", role: "user", previous: null } },
      ]);
      await stack.http.waitForAlert(`auth (break-glass CLI): created ${username} with mailbox:user`);
    });

    test("a bot's owner is named by email too", async () => {
      const owner = await stack.user({ username: unique("liam") });
      const username = unique("robot");
      expect((await cli(["user", "create", "--username", username, "--bot", "--owner", owner.email!])).code).toBe(0);
      expect((await userRow(username))!.owner_id).toBe(owner.id);
    });

    test.each([
      ["no owner", () => [], "error: name the user"],
      ["an unknown owner", () => ["--owner", "nobody-here"], 'error: no user "nobody-here"'],
    ])("a bot with %s is refused", async (_, more, message) => {
      const username = unique("drone");
      expectExit(await cli(["user", "create", "--username", username, "--bot", ...more()]), 2, [message]);
      expect(await userRow(username)).toBeUndefined();
    });

    test("a bot's owner must be a person", async () => {
      const owner = await stack.user({ username: unique("mia") });
      const bot = await stack.user({ username: unique("bot"), kind: "bot", ownerId: owner.id });
      const username = unique("drone");
      expectExit(await cli(["user", "create", "--username", username, "--bot", "--owner", bot.username]), 2, ["error: a bot's owner is a person"]);
      expect(await userRow(username)).toBeUndefined();
    });
  });

  describe("user clear-mfa", () => {
    test("removes every second factor, ends every session, mails a notice, audits and alerts", async () => {
      const user = await stack.user({ username: unique("nina"), totp: true, recoveryCodes: 3 });
      await stack.db`
        INSERT INTO passkeys (id, user_id, credential_id, public_key, name)
        VALUES (${newId("pk")}, ${user.id}, ${randomBytes(16)}, ${randomBytes(32)}, 'Laptop')`;
      const a = await stack.session(user, { amr: ["pwd", "otp", "mfa"] });
      await stack.session(user);
      expect((await a.get("/v1/me")).status).toBe(200);
      const exit = await cli(["user", "clear-mfa", user.username]);
      expectExit(exit, 0, [`cleared the second factors of ${user.username} and signed them out`, `emailed ${user.email}`]);
      for (const table of ["totp", "passkeys", "recovery_codes", "sessions"]) {
        expect(await stack.db.unsafe(`SELECT 1 FROM ${table} WHERE user_id = $1`, [user.id])).toHaveLength(0);
      }
      expect((await a.get("/v1/me")).status).toBe(401);
      expect(await auditOf(user.id)).toEqual([{ actor: "host-cli", action: "mfa.cleared", detail: {} }]);
      const mail = await stack.smtp.waitFor(user.email!);
      expect(mail.subject).toBe("Security notice: two-factor authentication was cleared by an administrator");
      await stack.http.waitForAlert(`auth (break-glass CLI): cleared the MFA of ${user.username}`);
    });

    test("a user without an email address gets no notice", async () => {
      const user = await stack.user({ username: unique("omar"), email: null, totp: true });
      expectExit(await cli(["user", "clear-mfa", user.username]), 0, [`cleared the second factors of ${user.username} and signed them out`]);
    });

    test.each([
      ["an unknown user", ["nobody-here"], 'error: no user "nobody-here"'],
      ["no user", [], "error: name the user"],
    ])("%s is refused", async (_, args, message) => {
      expectExit(await cli(["user", "clear-mfa", ...args]), 2, [message]);
    });
  });

  describe("user disable and enable", () => {
    test("disable ends sessions, tells every service with an events_url, audits and alerts; enable restores", async () => {
      const user = await stack.user({ username: unique("paul"), access: { wiki: "member" } });
      const browser = await stack.session(user);
      expectExit(await cli(["user", "disable", user.username]), 0, [`disabled ${user.username}`]);
      const [row] = await stack.db`SELECT disabled_at FROM users WHERE id = ${user.id}`;
      expect(row.disabled_at).not.toBeNull();
      expect(await stack.db`SELECT 1 FROM sessions WHERE user_id = ${user.id}`).toHaveLength(0);
      expect((await browser.get("/v1/me")).status).toBe(401);
      const events = (await stack.outbox()).filter((e) => e.payload.sub === user.id);
      expect(events.map((e) => [e.service, e.type, e.payload]).sort()).toEqual([
        ["mailbox", "user.disabled", { sub: user.id }],
        ["tasks", "user.disabled", { sub: user.id }],
        ["wiki", "user.disabled", { sub: user.id }],
      ]);
      await stack.http.waitForAlert(`auth (break-glass CLI): disabled ${user.username}`);

      // Again: nothing more happens, and it still succeeds.
      expectExit(await cli(["user", "disable", user.username]), 0, [`disabled ${user.username}`]);
      expect(await auditOf(user.id)).toEqual([{ actor: "host-cli", action: "user.disable", detail: {} }]);
      expect((await stack.outbox()).filter((e) => e.payload.sub === user.id)).toHaveLength(3);

      expectExit(await cli(["user", "enable", user.username]), 0, [`enabled ${user.username}`]);
      const [after] = await stack.db`SELECT disabled_at FROM users WHERE id = ${user.id}`;
      expect(after.disabled_at).toBeNull();
      await stack.http.waitForAlert(`auth (break-glass CLI): enabled ${user.username}`);
      expectExit(await cli(["user", "enable", user.username]), 0, [`enabled ${user.username}`]);
      expect(await auditOf(user.id)).toEqual([
        { actor: "host-cli", action: "user.disable", detail: {} },
        { actor: "host-cli", action: "user.enable", detail: {} },
      ]);
      expect((await stack.outbox()).filter((e) => e.payload.sub === user.id)).toHaveLength(3);
      expect(await stack.db`SELECT role FROM access WHERE user_id = ${user.id}`).toEqual([{ role: "member" }]);
    });

    test.each(["disable", "enable"])("%s refuses an unknown user", async (command) => {
      expectExit(await cli(["user", command, "nobody-here"]), 2, ['error: no user "nobody-here"']);
      expectExit(await cli(["user", command]), 2, ["error: name the user"]);
    });
  });

  describe("user reset-link", () => {
    test("mails a reset link, audited and alerted", async () => {
      const user = await stack.user({ username: unique("quinn") });
      expectExit(await cli(["user", "reset-link", user.username]), 0, [`emailed ${user.email}`]);
      const mail = await stack.smtp.waitFor(user.email!);
      expect(mail.subject).toBe("Reset your password");
      expect(mail.text).toMatch(new RegExp(`${escape(stack.issuer)}/reset/confirm\\?token=${TOKEN}\\n`));
      expect(await auditOf(user.id)).toEqual([{ actor: "host-cli", action: "reset.sent", detail: {} }]);
      await stack.http.waitForAlert(`auth (break-glass CLI): made a reset link for ${user.username}`);
    });

    test("--print-link prints a link that opens the reset page", async () => {
      const user = await stack.user({ username: unique("rosa") });
      const exit = await cli(["user", "reset-link", user.username, "--print-link"]);
      expect(exit.code).toBe(0);
      expect(exit.out).toHaveLength(1);
      expect(exit.out[0]).toMatch(new RegExp(`^reset link \\(works once, 30 minutes\\): ${escape(stack.issuer)}/reset/confirm\\?token=${TOKEN}$`));
      const link = new URL(exit.out[0]!.slice(exit.out[0]!.indexOf("http")));
      const page = await stack.browser().get(link.pathname + link.search);
      expect(page.status).toBe(200);
      const html = await page.text();
      expect(html).toContain("<h1>Choose a new password</h1>");
      expect(html).toContain(`name="username" value="${user.username}"`);
      expect(stack.smtp.to(user.email!)).toEqual([]);
    });

    test("a user without an email address needs --print-link", async () => {
      const user = await stack.user({ username: unique("sam"), email: null });
      expectExit(await cli(["user", "reset-link", user.username]), 2, ["error: the user has no email address; use --print-link"]);
      expect(await auditOf(user.id)).toEqual([]);
      const exit = await cli(["user", "reset-link", user.username, "--print-link"]);
      expect(exit.code).toBe(0);
      expect(exit.out[0]).toStartWith("reset link (works once, 30 minutes): ");
    });

    test("a bot has no password to reset", async () => {
      const owner = await stack.user({ username: unique("tess") });
      const bot = await stack.user({ username: unique("bot"), kind: "bot", ownerId: owner.id });
      expectExit(await cli(["user", "reset-link", bot.username, "--print-link"]), 2, ["error: a bot user has no password"]);
    });

    test("an unknown user is refused", async () => {
      expectExit(await cli(["user", "reset-link", "nobody-here"]), 2, ['error: no user "nobody-here"']);
    });
  });

  describe("client secrets", () => {
    test("secret prints only a new secret, which authenticates; the previous one works until the next", async () => {
      const first = await stack.clientSecret("mailbox");
      const a = await cli(["client", "secret", "mailbox"]);
      expect(a.code).toBe(0);
      expect(a.out).toHaveLength(1);
      expect(a.stdout).toMatch(new RegExp(`^${TOKEN}\\n$`));
      const second = a.out[0]!;
      expect(await authenticates("mailbox", second)).toBe(true);
      expect(await authenticates("mailbox", first)).toBe(true);
      const [stored] = await stack.db`SELECT secret_hash FROM client_secrets WHERE client_id = 'mailbox' AND secret_hash = ${sha256(second)}`;
      expect(stored).toBeDefined();
      await stack.http.waitForAlert("auth (break-glass CLI): made a new secret for the client mailbox");
      const audit = (await stack.audit("client.secret")).at(-1)!;
      expect(audit).toMatchObject({ actor: "host-cli", user_id: null, detail: { client: "mailbox" } });

      const third = (await cli(["client", "secret", "mailbox"])).out[0]!;
      expect(await authenticates("mailbox", third)).toBe(true);
      expect(await authenticates("mailbox", second)).toBe(true);
      expect(await authenticates("mailbox", first)).toBe(false);

      expectExit(await cli(["client", "retire-old-secrets", "mailbox"]), 0, ["retired 1 old secret(s) of mailbox"]);
      expect(await authenticates("mailbox", second)).toBe(false);
      expect(await authenticates("mailbox", third)).toBe(true);
      expect((await stack.audit("client.secret_retire")).at(-1)).toMatchObject({ actor: "host-cli", detail: { client: "mailbox", retired: 1 } });
      await stack.http.waitForAlert("auth (break-glass CLI): retired the old secrets of the client mailbox");
      expectExit(await cli(["client", "retire-old-secrets", "mailbox"]), 0, ["retired 0 old secret(s) of mailbox"]);
    });

    test("retire-old-secrets counts every older live secret", async () => {
      await stack.clientSecret("notes");
      await stack.clientSecret("notes");
      await stack.clientSecret("notes");
      const [live] = await stack.db`SELECT count(*)::int AS n FROM client_secrets WHERE client_id = 'notes' AND revoked_at IS NULL`;
      expect(live.n).toBeGreaterThanOrEqual(3);
      expectExit(await cli(["client", "retire-old-secrets", "notes"]), 0, [`retired ${live.n - 1} old secret(s) of notes`]);
      expect((await stack.db`SELECT count(*)::int AS n FROM client_secrets WHERE client_id = 'notes' AND revoked_at IS NULL`)[0].n).toBe(1);
    });

    test.each([
      ["secret", "a public client", ["tasks-ios"]],
      ["secret", "an unknown client", ["nobody"]],
      ["secret", "no client", []],
      ["retire-old-secrets", "a public client", ["tasks-ios"]],
      ["retire-old-secrets", "an unknown client", ["nobody"]],
    ])("%s refuses %s", async (command, _, args) => {
      expectExit(await cli(["client", command, ...args]), 2, ["error: name a confidential client"]);
    });

    test("a registered service's client gets a secret too", async () => {
      const other = await Stack.start({ services: null });
      try {
        await other.db`INSERT INTO services (name, roles, mfa_roles, signup, created_by) VALUES ('notes', '{reader}', '{}', 'closed', 'host-cli')`;
        await other.db`INSERT INTO clients (id, service, type, redirect_uris) VALUES ('notes', 'notes', 'confidential', '{https://notes.example.com/auth/callback}'),
                                                                                   ('notes-ios', 'notes', 'public', '{com.example.notes:/auth/callback}')`;
        await other.db`UPDATE services_revision SET revision = revision + 1`;
        const exit = await other.cli(["client", "secret", "notes"]);
        expect(exit.code).toBe(0);
        const res = await backChannel(other, "/oauth/introspect", { token: "x" }, basic("notes", exit.out[0]!));
        expect(res.status).toBe(200);
        expect(await res.json()).toEqual({ active: false });
        expectExit(await other.cli(["client", "secret", "notes-ios"]), 2, ["error: name a confidential client"]);
      } finally {
        await other.stop();
      }
    });
  });

  describe("encryption status and reencrypt", () => {
    test("counts per version, rewrites under the current key, reports what no key reads", async () => {
      const e = await Stack.start();
      try {
        expectExit(await e.cli(["encryption", "status"]), 0, ["TOTP secrets: none", "signing keys: v1: 1", "AUTH_ENCRYPTION_KEY is v1"]);
        const a = await e.user({ username: "alice", totp: true });
        const b = await e.user({ username: "bob", totp: true });
        const v2 = { AUTH_ENCRYPTION_KEY: `v2:${key(9)}`, AUTH_DECRYPTION_KEYS: `v1:${e.env.AUTH_ENCRYPTION_KEY}` };
        expectExit(await e.cli(["encryption", "status"], { env: v2 }), 0, ["TOTP secrets: v1: 2", "signing keys: v1: 1", "AUTH_ENCRYPTION_KEY is v2"]);

        // A row under a key this deployment doesn't have.
        const c = await e.user({ username: "carol" });
        const v3 = new Crypt(Buffer.alloc(32, 3), 3);
        await e.db`INSERT INTO totp (user_id, secret_enc) VALUES (${c.id}, ${v3.encrypt(randomBytes(20), c.id)})`;
        expectExit(await e.cli(["encryption", "status"], { env: v2 }), 0, [
          "TOTP secrets: v1: 2, v3: 1 (1 under a key that isn't configured)",
          "signing keys: v1: 1",
          "AUTH_ENCRYPTION_KEY is v2",
        ]);

        const before = e.alerts.length;
        expectExit(await e.cli(["encryption", "reencrypt"], { env: v2 }), 1, [
          "TOTP secrets: 2 rewritten under v2, 0 already were",
          "signing keys: 1 rewritten under v2, 0 already were",
          `no configured key reads TOTP secrets: ${c.id}; left as it was`,
        ]);
        const [audit] = await e.audit("encryption.reencrypt");
        expect(audit).toMatchObject({ actor: "host-cli", user_id: null, detail: { version: 2, rewritten: 3, failed: 1 } });
        await e.http.waitForAlert("auth (break-glass CLI): re-encrypted 3 values under key v2; 1 unreadable");
        expect(e.alerts.length).toBe(before + 1);

        // Rewritten under v2 with the row id as additional data.
        const crypt2 = new Crypt(Buffer.alloc(32, 9), 2);
        for (const u of [a, b]) {
          const [row] = await e.db`SELECT secret_enc FROM totp WHERE user_id = ${u.id}`;
          expect(Buffer.from(row.secret_enc).subarray(0, 3).toString()).toBe("v2:");
          expect(crypt2.decrypt(row.secret_enc, u.id).equals(u.totpSecret!)).toBe(true);
        }
        const [signing] = await e.db`SELECT kid, private_key_enc FROM signing_keys`;
        expect(crypt2.decrypt(signing.private_key_enc, signing.kid).length).toBeGreaterThan(0);
        expectExit(await e.cli(["encryption", "status"], { env: v2 }), 0, [
          "TOTP secrets: v2: 2, v3: 1 (1 under a key that isn't configured)",
          "signing keys: v2: 1",
          "AUTH_ENCRYPTION_KEY is v2",
        ]);

        // Once it's gone, a second run has nothing left to do.
        await e.db`DELETE FROM totp WHERE user_id = ${c.id}`;
        expectExit(await e.cli(["encryption", "reencrypt"], { env: v2 }), 0, ["TOTP secrets: 0 rewritten under v2, 2 already were", "signing keys: 0 rewritten under v2, 1 already were"]);
        await e.http.waitForAlert(/^auth \(break-glass CLI\): re-encrypted 0 values under key v2$/);
        expect((await e.audit("encryption.reencrypt")).at(-1)).toMatchObject({ detail: { version: 2, rewritten: 0, failed: 0 } });
        // A copy under the new key alone signs in with a rewritten secret.
        const copy = await e.spawn({ env: { AUTH_ENCRYPTION_KEY: `v2:${key(9)}` } });
        await copy.ready();
        const view = Object.create(e) as Stack;
        Object.defineProperty(view, "url", { value: copy.url });
        const browser = view.browser();
        const res = await browser.signIn("alice", PASSWORD, await e.code(a));
        expect(res.status).toBe(303);
        expect(res.headers.get("Location")).toBe("/account");
      } finally {
        await e.stop();
      }
    });
  });

  describe("import users", () => {
    const run = (input: string, ...flags: string[]) => cli(["import", "users", "-", ...flags], { stdin: input });

    test("every per-line problem, sorted by line, with nothing written", async () => {
      const taken = await stack.user({ username: unique("taken") });
      const ok = unique("okay");
      const input = [
        JSON.stringify({ username: ok, email: `${ok}@example.com` }),
        "",
        "{not json",
        "[1, 2]",
        '"a string"',
        "null",
        "42",
        JSON.stringify({ username: "Bad Name", email: "nope" }),
        JSON.stringify({ username: ok, email: `${ok.toUpperCase()}@EXAMPLE.COM` }),
        JSON.stringify({ username: taken.username, email: taken.email!.toUpperCase() }),
        JSON.stringify({ username: unique("a"), email: "x1@example.com", name: "n".repeat(201) }),
        JSON.stringify({ username: unique("b"), email: "x2@example.com", name: 7 }),
        JSON.stringify({ username: unique("c"), email: "x3@example.com", name: "tab\there" }),
        JSON.stringify({ username: unique("d"), email: "x4@example.com", email_verified: "yes" }),
        JSON.stringify({ username: unique("e"), email: "x5@example.com", password_hash: "plaintext" }),
        JSON.stringify({ username: unique("f"), email: "x6@example.com", password_hash: 12 }),
        JSON.stringify({ username: unique("g"), email: "x7@example.com", access: ["wiki"] }),
        JSON.stringify({ username: unique("h"), email: "x8@example.com", access: { nowhere: "member", wiki: "root", tasks: 1 } }),
        JSON.stringify({ username: unique("i"), email: "x9@example.com", role: "admin", [`x${"y".repeat(60)}`]: 1 }),
        JSON.stringify({ username: 5, email: null }),
        JSON.stringify({ email: "x10@example.com", access: null }),
      ].join("\n");
      const exit = await run(input);
      expect(exit.code).toBe(1);
      expect(exit.out).toEqual([
        "line 3: not valid JSON",
        "line 4: not a JSON object",
        "line 5: not a JSON object",
        "line 6: not a JSON object",
        "line 7: not a JSON object",
        "line 8: username must be 3 to 32 characters: a–z, 0–9 and '-', starting with a letter and not ending with '-'",
        "line 8: email is not an email address",
        "line 9: username is also on line 1",
        "line 9: email is also on line 1",
        "line 10: username is taken",
        "line 10: email is used by another account",
        "line 11: name must be text of at most 200 characters",
        "line 12: name must be text of at most 200 characters",
        "line 13: name must be text of at most 200 characters",
        "line 14: email_verified must be true or false",
        "line 15: password_hash is not an argon2 or bcrypt PHC string",
        "line 16: password_hash is not an argon2 or bcrypt PHC string",
        "line 17: access must be an object of service: role",
        "line 18: access names a service auth doesn't have",
        "line 18: access gives wiki a role it doesn't declare",
        "line 18: access gives tasks a role it doesn't declare",
        `line 19: unknown field "role"`,
        `line 19: unknown field "x${"y".repeat(39)}"`,
        "line 20: username must be 3 to 32 characters: a–z, 0–9 and '-', starting with a letter and not ending with '-'",
        "line 20: email is not an email address",
        "line 21: username must be 3 to 32 characters: a–z, 0–9 and '-', starting with a letter and not ending with '-'",
        "line 21: access must be an object of service: role",
        "nothing imported: 27 problem(s)",
      ]);
      expect(await userRow(ok)).toBeUndefined();
      expect(exit.stdout).not.toContain(taken.email!.toUpperCase());
      expect(exit.stdout).not.toContain("plaintext");
    });

    test.each([
      ["an empty input", ""],
      ["only blank lines", "\n  \n\t\n"],
    ])("%s has no lines", async (_, input) => {
      expectExit(await run(input), 1, ["the input has no lines", "nothing imported: 1 problem(s)"]);
    });

    test("more than 10,000 lines is refused before any line is checked", async () => {
      expectExit(await run("{}\n".repeat(10_001)), 1, ["the input has more than 10000 lines; split it", "nothing imported: 1 problem(s)"]);
    });

    test("10,000 lines, blank lines aside, pass", async () => {
      const tag = randomBytes(2).toString("hex");
      const input = Array.from({ length: 10_000 }, (_, i) => JSON.stringify({ username: `bulk${tag}-${i}`, email: `bulk${tag}-${i}@example.com` })).join("\n\n");
      expectExit(await run(input, "--dry-run"), 0, ["every line passed; nothing written (--dry-run)"]);
    });

    test("--dry-run checks against the database and writes nothing", async () => {
      const username = unique("dry");
      expectExit(await run(lines({ username, email: `${username}@example.com` }), "--dry-run"), 0, ["every line passed; nothing written (--dry-run)"]);
      expect(await userRow(username)).toBeUndefined();
      const taken = await stack.user({ username: unique("wet") });
      expectExit(await run(lines({ username: taken.username, email: "fresh@example.com" }), "--dry-run"), 1, ["line 1: username is taken", "nothing imported: 1 problem(s)"]);
    });

    test("imports users: activation links printed, access granted, audited and alerted", async () => {
      const [u1, u2] = [unique("imp"), unique("imp")];
      const exit = await run(
        lines(
          { username: u1, email: ` ${u1}@example.com `, name: "  Imported One ", email_verified: true, access: { wiki: "member", tasks: "user" } },
          { username: u2, email: `${u2}@example.com` },
        ).replace(/\n/g, "\r\n"),
        "--print-links",
      );
      expect(exit.code).toBe(0);
      expect(exit.out).toHaveLength(3);
      expect(exit.out[0]).toMatch(new RegExp(`^${u1}: ${escape(stack.issuer)}/activate\\?token=${TOKEN}$`));
      expect(exit.out[1]).toMatch(new RegExp(`^${u2}: ${escape(stack.issuer)}/activate\\?token=${TOKEN}$`));
      expect(exit.out[2]).toBe("imported 2 users");
      const one = (await userRow(u1))!;
      expect(one).toMatchObject({ name: "Imported One", email: `${u1}@example.com`, kind: "person", password_hash: null });
      expect(one.email_verified_at).not.toBeNull();
      expect((await userRow(u2))!.email_verified_at).toBeNull();
      expect(await stack.db`SELECT service, role, granted_by FROM access WHERE user_id = ${one.id} ORDER BY service`).toEqual([
        { service: "tasks", role: "user", granted_by: "host-cli" },
        { service: "wiki", role: "member", granted_by: "host-cli" },
      ]);
      expect(await auditOf(one.id)).toEqual([
        { actor: "host-cli", action: "user.create", detail: { username: u1, kind: "person", imported: true } },
        { actor: "host-cli", action: "access.put", detail: { service: "wiki", role: "member", previous: null, reason: "import" } },
        { actor: "host-cli", action: "access.put", detail: { service: "tasks", role: "user", previous: null, reason: "import" } },
      ]);
      expect((await stack.outbox()).filter((e) => e.payload.sub === one.id).map((e) => [e.service, e.type]).sort()).toEqual([
        ["tasks", "access.changed"],
        ["wiki", "access.changed"],
      ]);
      await stack.http.waitForAlert(/^auth \(break-glass CLI\): imported 2 users$/);
      expect(stack.smtp.to(`${u1}@example.com`)).toEqual([]);
    });

    test("without --print-links the activation links are mailed; a user with a hash gets none", async () => {
      const [u1, u2] = [unique("mail"), unique("hash")];
      const file = stack.file(`${u1}.jsonl`, lines({ username: u1, email: `${u1}@example.com` }, { username: u2, email: `${u2}@example.com`, password_hash: await hashPassword("imported horse battery") }));
      expectExit(await cli(["import", "users", file]), 0, [`emailed ${u1}@example.com`, "imported 2 users"]);
      const mail = await stack.smtp.waitFor(`${u1}@example.com`);
      expect(mail.subject).toBe("Activate your account");
      expect(mail.text).toContain(`An account with the username "${u1}" was created for you.`);
    });

    test.each([
      ["argon2id within the bounds", async () => hashPassword("imported horse battery")],
      ["bcrypt within the bounds", async () => Bun.password.hash("imported horse battery", { algorithm: "bcrypt", cost: 4 })],
    ])("a user imported with %s signs in with the password, which is then rehashed", async (_, make) => {
      const username = unique("signin");
      const hash = await make();
      expectExit(await run(lines({ username, email: `${username}@example.com`, password_hash: hash })), 0, ["imported 1 users"]);
      expect((await userRow(username))!.password_hash).toBe(hash);
      const res = await stack.browser().signIn(username, "imported horse battery");
      expect(res.status).toBe(303);
      expect(res.headers.get("Location")).toBe("/account");
      const stored = (await userRow(username))!.password_hash!;
      expect(stored).toStartWith("$argon2id$v=19$m=19456,t=2,p=1$");
    });

    const SALT = "c29tZXNhbHRzb21lc2FsdA";
    const HASH = "aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g";
    const bcrypt = (cost: string) => `$2b$${cost}$${"a".repeat(53)}`;
    test.each([
      [`$argon2id$v=19$m=19456,t=3,p=4$${SALT}$${HASH}`, null],
      [`$argon2i$v=19$m=4096,t=1,p=1$${SALT}$${HASH}`, null],
      [`$argon2d$v=19$m=19456,t=1,p=1$${SALT}$${HASH}`, null],
      [bcrypt("12"), null],
      [bcrypt("04").replace("$2b$", "$2a$"), null],
      [bcrypt("10").replace("$2b$", "$2y$"), null],
      [`$argon2id$v=19$m=19457,t=2,p=1$${SALT}$${HASH}`, "argon2"],
      [`$argon2id$v=19$m=19456,t=4,p=1$${SALT}$${HASH}`, "argon2"],
      [`$argon2id$v=19$m=19456,t=2,p=5$${SALT}$${HASH}`, "argon2"],
      [`$argon2id$v=19$m=65536,t=3,p=4$${SALT}$${HASH}`, "argon2"],
      [bcrypt("13"), "bcrypt"],
      [bcrypt("31"), "bcrypt"],
      [`$2x$10$${"a".repeat(53)}`, "format"],
      [`$2b$10$${"a".repeat(52)}`, "format"],
      [`$scrypt$ln=16,r=8,p=1$${SALT}$${HASH}`, "format"],
      [`$argon2id$v=19$m=19456,t=2$${SALT}$${HASH}`, "format"],
      [`$argon2id$v=19$m=19456,t=2,p=1$${"A".repeat(520)}$${HASH}`, "format"],
      ["", "format"],
    ])("password_hash %p", async (hash, problem) => {
      const username = unique("hashes");
      const exit = await run(lines({ username, email: `${username}@example.com`, password_hash: hash }), "--dry-run");
      if (problem === null) {
        expectExit(exit, 0, ["every line passed; nothing written (--dry-run)"]);
        return;
      }
      const message = {
        argon2: "password_hash costs more than this service verifies (argon2 at most m=19456, t=3, p=4); leave it out and the user gets an activation link",
        bcrypt: "password_hash costs more than this service verifies (bcrypt cost at most 12); leave it out and the user gets an activation link",
        format: "password_hash is not an argon2 or bcrypt PHC string",
      }[problem];
      expectExit(exit, 1, [`line 1: ${message}`, "nothing imported: 1 problem(s)"]);
      if (hash) expect(exit.stdout).not.toContain(hash);
    });

    test("a null password_hash is left out", async () => {
      const username = unique("nullhash");
      expectExit(await run(lines({ username, email: `${username}@example.com`, password_hash: null }), "--print-links"), 0, [
        expect.stringMatching(new RegExp(`^${username}: `)) as unknown as string,
        "imported 1 users",
      ]);
    });

    test("addresses are compared trimmed and ignoring case", async () => {
      const username = unique("same");
      const other = unique("same");
      const exit = await run(lines({ username, email: `${username}@example.com` }, { username: other, email: ` ${username.toUpperCase()}@Example.com ` }));
      expectExit(exit, 1, ["line 2: email is also on line 1", "nothing imported: 1 problem(s)"]);
      expect(await userRow(username)).toBeUndefined();
    });

    test.each([
      ["no input named", [], "error: name the input file, or - for standard input"],
      ["a file that doesn't exist", ["/nonexistent/users.jsonl"], "error: can't read /nonexistent/users.jsonl"],
    ])("%s is refused", async (_, args, message) => {
      expectExit(await cli(["import", "users", ...args]), 2, [message]);
    });

    test("an input over 8 MB is refused", async () => {
      expectExit(await run(" ".repeat(8 * 1024 * 1024 + 1)), 2, ["error: the input is larger than 8 MB; split it"]);
    });
  });

  describe("import api-keys", () => {
    const run = (input: string, ...flags: string[]) => cli(["import", "api-keys", "--service", "tasks", "-", ...flags], { stdin: input });
    const hex = (secret: string) => sha256(secret).toString("hex");

    test("--service must name a service that takes API keys", async () => {
      expectExit(await cli(["import", "api-keys", "-"], { stdin: "" }), 2, ["error: --service must name a service"]);
      expectExit(await cli(["import", "api-keys", "--service", "nowhere", "-"], { stdin: "" }), 2, ["error: --service must name a service"]);
      expectExit(await cli(["import", "api-keys", "--service", "wiki", "-"], { stdin: "{}\n" }), 1, ["wiki declares no api_key_scopes, so it takes no API keys", "nothing imported: 1 problem(s)"]);
      expectExit(await cli(["import", "api-keys", "--service", "tasks"]), 2, ["error: name the input file, or - for standard input"]);
    });

    test("every per-line problem, sorted by line", async () => {
      const owner = await stack.user({ username: unique("owner"), access: { tasks: "user" } });
      const roleless = await stack.user({ username: unique("roleless") });
      const existing = `legacy-${randomBytes(8).toString("hex")}`;
      const seed = await run(lines({ owner: owner.username, sha256: hex(existing), scopes: ["tasks:read"] }));
      expect(seed.code).toBe(0);
      const dup = hex(`dup-${randomBytes(4).toString("hex")}`);
      const input = lines(
        { owner: "Not A User!", sha256: "abc", scopes: [] },
        { owner: owner.id, sha256: dup, scopes: ["tasks:read"] },
        { owner: owner.username, sha256: dup.toUpperCase(), scopes: ["tasks:admin"] },
        { owner: owner.username, sha256: hex(`x-${randomBytes(4).toString("hex")}`), scopes: "tasks:read" },
        { owner: owner.username, sha256: hex(`y-${randomBytes(4).toString("hex")}`), scopes: ["tasks:read", 3] },
        { owner: owner.username, sha256: hex(`z-${randomBytes(4).toString("hex")}`), scopes: ["tasks:read"], name: "   " },
        { owner: owner.username, sha256: hex(`w-${randomBytes(4).toString("hex")}`), scopes: ["tasks:read"], name: "n".repeat(101) },
        { owner: owner.username, sha256: hex(`v-${randomBytes(4).toString("hex")}`), scopes: ["tasks:read"], name: "a\u0000b" },
        { owner: owner.username, sha256: hex(`u-${randomBytes(4).toString("hex")}`), scopes: ["tasks:read"], name: 5 },
        { owner: "nobody-at-all", sha256: hex(`t-${randomBytes(4).toString("hex")}`), scopes: ["tasks:read"] },
        { owner: newId("usr"), sha256: hex(`s-${randomBytes(4).toString("hex")}`), scopes: ["tasks:read"] },
        { owner: roleless.username, sha256: hex(`r-${randomBytes(4).toString("hex")}`), scopes: ["tasks:read"] },
        { owner: owner.username, sha256: hex(existing), scopes: ["tasks:read"] },
        { owner: owner.username, sha256: hex(`q-${randomBytes(4).toString("hex")}`), scopes: ["tasks:read"], expires_at: "2026-02-30T00:00:00Z", revoked_at: 1700000000, created_at: "2026-01-02 03:04:05Z", last_used_at: "2026-01-02T03:04:05" },
        { owner: owner.username, sha256: hex(`p-${randomBytes(4).toString("hex")}`), scopes: ["tasks:read"], secret: "abc123" },
        { sha256: 5 },
      );
      const exit = await run(input);
      expect(exit.code).toBe(1);
      expect(exit.out).toEqual([
        "line 1: owner must be a user's sub (usr_…) or username",
        "line 1: sha256 must be 64 hex characters, or 32 bytes in base64",
        "line 1: scopes must be a non-empty list from: tasks:read, tasks:write",
        "line 3: sha256 is also on line 2",
        "line 3: scopes must be a non-empty list from: tasks:read, tasks:write",
        "line 4: scopes must be a non-empty list from: tasks:read, tasks:write",
        "line 5: scopes must be a non-empty list from: tasks:read, tasks:write",
        "line 6: name is 1 to 100 characters",
        "line 7: name is 1 to 100 characters",
        "line 8: name is 1 to 100 characters",
        "line 9: name is 1 to 100 characters",
        "line 10: owner is not a user",
        "line 11: owner is not a user",
        "line 12: owner has no role on tasks",
        "line 13: sha256 is already a credential",
        "line 14: expires_at must be an RFC 3339 timestamp",
        "line 14: revoked_at must be an RFC 3339 timestamp",
        "line 14: created_at must be an RFC 3339 timestamp",
        "line 14: last_used_at must be an RFC 3339 timestamp",
        'line 15: unknown field "secret"',
        "line 16: owner must be a user's sub (usr_…) or username",
        "line 16: sha256 must be 64 hex characters, or 32 bytes in base64",
        "line 16: scopes must be a non-empty list from: tasks:read, tasks:write",
        "nothing imported: 23 problem(s)",
      ]);
      expect(exit.stdout).not.toContain(dup);
      expect(exit.stdout).not.toContain("abc123");
      expect(await stack.db`SELECT 1 FROM credentials WHERE secret_hash = ${Buffer.from(dup, "hex")}`).toHaveLength(0);
    });

    test.each([
      ["2026-01-02T03:04:05Z", true],
      ["2026-01-02T03:04Z", true],
      ["2026-01-02T03:04:05.123456+02:00", true],
      ["2024-02-29T23:59:59-15:59", true],
      ["2026-01-02T03:04:05.1234567Z", false],
      ["2025-02-29T00:00:00Z", false],
      ["2026-04-31T00:00:00Z", false],
      ["2026-13-01T00:00:00Z", false],
      ["2026-00-01T00:00:00Z", false],
      ["2026-01-02T24:00:00Z", false],
      ["2026-01-02T23:60:00Z", false],
      ["2026-01-02T23:59:60Z", false],
      ["2026-01-02T03:04:05+16:00", false],
      ["2026-01-02T03:04:05+02:60", false],
      ["2026-01-02t03:04:05z", false],
      ["2026-01-02", false],
      ["0000-01-01T00:00:00Z", false],
      [true, false],
    ])("the timestamp %p is %s", async (value, ok) => {
      const owner = await stack.user({ username: unique("times"), access: { tasks: "user" } });
      const exit = await run(lines({ owner: owner.username, sha256: hex(randomBytes(8).toString("hex")), scopes: ["tasks:read"], created_at: value }), "--dry-run");
      if (ok) expectExit(exit, 0, ["every line passed; nothing written (--dry-run)"]);
      else expectExit(exit, 1, ["line 1: created_at must be an RFC 3339 timestamp", "nothing imported: 1 problem(s)"]);
    });

    test("imports keys, by sub or username, in hex, base64 and base64url; each answers introspection", async () => {
      const owner = await stack.user({ username: unique("keys"), access: { tasks: "user" } });
      const other = await stack.user({ username: unique("keys"), access: { tasks: "user" } });
      const secrets = Array.from({ length: 6 }, (_, i) => `legacy-${i}-${randomBytes(8).toString("hex")}`);
      const input = lines(
        { owner: owner.username, sha256: hex(secrets[0]!), scopes: ["tasks:read", "tasks:read"], name: "  CI key ", created_at: "2024-05-06T07:08:09Z", last_used_at: "2025-01-01T00:00:00Z" },
        { owner: other.id, sha256: sha256(secrets[1]!).toString("base64"), scopes: ["tasks:write", "tasks:read"] },
        { owner: owner.username, sha256: sha256(secrets[2]!).toString("base64url"), scopes: ["tasks:read"] },
        { owner: owner.username, sha256: sha256(secrets[3]!).toString("base64").replace(/=$/, ""), scopes: ["tasks:read"], expires_at: "2020-01-01T00:00:00Z" },
        { owner: owner.username, sha256: hex(secrets[4]!).toUpperCase(), scopes: ["tasks:read"], revoked_at: "2025-01-01T00:00:00+01:00" },
        { owner: owner.username, sha256: hex(secrets[5]!), scopes: ["tasks:read"], expires_at: null },
      );
      expectExit(await run(input), 0, ["imported 6 API keys"]);
      await stack.http.waitForAlert(/^auth \(break-glass CLI\): imported 6 API keys$/);

      const rows = await stack.db`
        SELECT id, user_id, kind, service, scopes, name, created_at, last_used_at, expires_at, revoked_at FROM credentials
        WHERE user_id = ${owner.id} OR user_id = ${other.id} ORDER BY id`;
      expect(rows).toHaveLength(6);
      const first = rows[0];
      expect(first.id).toMatch(/^key_/);
      expect(first).toMatchObject({ user_id: owner.id, kind: "api_key", service: "tasks", scopes: ["tasks:read"], name: "CI key" });
      expect(first.created_at.toISOString()).toBe("2024-05-06T07:08:09.000Z");
      expect(rows[1]).toMatchObject({ user_id: other.id, scopes: ["tasks:write", "tasks:read"], name: "imported" });
      expect(rows[4].revoked_at.toISOString()).toBe("2024-12-31T23:00:00.000Z");
      const audits = (await stack.audit("api_key.create")).filter((a) => a.user_id === owner.id);
      expect(audits[0]).toMatchObject({ actor: "host-cli", detail: { id: first.id, service: "tasks", scopes: ["tasks:read"], imported: true } });

      const introspect = async (secret: string) => (await backChannel(stack, "/oauth/introspect", { token: secret }, stack.basic("tasks"))).json();
      expect(await introspect(secrets[0]!)).toEqual({ active: true, sub: owner.id, username: owner.username, scope: "tasks:read", role: "user", jti: first.id });
      expect(await introspect(secrets[1]!)).toMatchObject({ active: true, sub: other.id, scope: "tasks:write tasks:read" });
      expect(await introspect(secrets[2]!)).toMatchObject({ active: true });
      expect(await introspect(secrets[3]!)).toEqual({ active: false });
      expect(await introspect(secrets[4]!)).toEqual({ active: false });
      expect(await introspect(secrets[5]!)).toMatchObject({ active: true });
      // Imported once; again it is a duplicate.
      expectExit(await run(lines({ owner: owner.username, sha256: hex(secrets[0]!), scopes: ["tasks:read"] })), 1, ["line 1: sha256 is already a credential", "nothing imported: 1 problem(s)"]);
    });

    test("an owner holds at most 100 live keys, imported and existing together; revoked ones don't count", async () => {
      const owner = await stack.user({ username: unique("many"), access: { tasks: "user" } });
      for (let i = 0; i < 98; i++) {
        await stack.db`INSERT INTO credentials (id, user_id, kind, service, scopes, name, secret_hash)
                       VALUES (${newId("key")}, ${owner.id}, 'api_key', 'tasks', '{tasks:read}', 'k', ${randomBytes(32)})`;
      }
      await stack.db`INSERT INTO credentials (id, user_id, kind, service, scopes, name, secret_hash, revoked_at)
                     VALUES (${newId("key")}, ${owner.id}, 'api_key', 'tasks', '{tasks:read}', 'k', ${randomBytes(32)}, now())`;
      const line = (more: Record<string, unknown> = {}) => ({ owner: owner.username, sha256: hex(randomBytes(8).toString("hex")), scopes: ["tasks:read"], ...more });
      const other = await stack.user({ username: unique("few"), access: { tasks: "user" } });
      expectExit(await run(lines({ owner: other.username, sha256: hex(randomBytes(8).toString("hex")), scopes: ["tasks:read"] }, line(), line(), line()), "--dry-run"), 1, [
        "line 2: owner would hold 101 live API keys, more than 100",
        "nothing imported: 1 problem(s)",
      ]);
      expectExit(await run(lines(line(), line(), line({ revoked_at: "2025-01-01T00:00:00Z" })), "--dry-run"), 0, ["every line passed; nothing written (--dry-run)"]);
    });

    test("--dry-run writes nothing", async () => {
      const owner = await stack.user({ username: unique("dry"), access: { tasks: "user" } });
      const secret = randomBytes(8).toString("hex");
      expectExit(await run(lines({ owner: owner.username, sha256: hex(secret), scopes: ["tasks:read"] }), "--dry-run"), 0, ["every line passed; nothing written (--dry-run)"]);
      expect(await stack.db`SELECT 1 FROM credentials WHERE user_id = ${owner.id}`).toHaveLength(0);
    });

    test("a file is read as well as standard input", async () => {
      const owner = await stack.user({ username: unique("file"), access: { tasks: "user" } });
      const file = stack.file(`${owner.username}.jsonl`, lines({ owner: owner.username, sha256: hex(randomBytes(8).toString("hex")), scopes: ["tasks:write"] }));
      expectExit(await cli(["import", "api-keys", "--service", "tasks", file]), 0, ["imported 1 API keys"]);
    });
  });

  describe("migrate", () => {
    test("applies every migration to an empty schema, then has nothing to do; it makes no signing key", async () => {
      const empty = await Stack.start({ start: false });
      try {
        expectExit(await empty.cli(["migrate"]), 0, ["migration 0001_initial applied", "migration 0002_services applied", "migrations are up to date"]);
        expect((await empty.db`SELECT version FROM schema_migrations ORDER BY version`).map((r: { version: string }) => r.version)).toEqual(["0001_initial", "0002_services"]);
        expect(await empty.db`SELECT 1 FROM signing_keys`).toHaveLength(0);
        expectExit(await empty.cli(["migrate"]), 0, ["migrations are up to date"]);
        expect(await empty.db`SELECT 1 FROM audit`).toHaveLength(0);
      } finally {
        await empty.stop();
      }
    });

    test("any other command migrates first, silently, and makes a signing key", async () => {
      const empty = await Stack.start({ start: false });
      try {
        expectExit(await empty.cli(["encryption", "status"]), 0, ["TOTP secrets: none", "signing keys: v1: 1", "AUTH_ENCRYPTION_KEY is v1"]);
        expect(await empty.db`SELECT version FROM schema_migrations`).toHaveLength(2);
        expect(await empty.db`SELECT 1 FROM audit`).toHaveLength(0);
      } finally {
        await empty.stop();
      }
    });
  });

  describe("alerts", () => {
    test("an alert the webhook refuses is reported on the CLI's output, and the command still succeeds", async () => {
      stack.http.onAlert = () => 500;
      const user = await stack.user({ username: unique("alerted") });
      expectExit(await cli(["user", "disable", user.username]), 0, [`disabled ${user.username}`, "alert webhook answered 500"]);
    });

    test("without ALERT_WEBHOOK_URL nothing is posted", async () => {
      const user = await stack.user({ username: unique("quiet") });
      const before = stack.alerts.length;
      expectExit(await cli(["user", "disable", user.username], { env: { ALERT_WEBHOOK_URL: undefined } }), 0, [`disabled ${user.username}`]);
      const marker = await stack.user({ username: unique("marker") });
      expect((await cli(["user", "disable", marker.username])).code).toBe(0);
      await stack.http.waitForAlert(`disabled ${marker.username}`);
      expect(stack.alerts.slice(before)).toEqual([`auth (break-glass CLI): disabled ${marker.username}`]);
    });
  });
});
