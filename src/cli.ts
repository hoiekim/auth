import { putAccess } from "./access";
import { createApp, postAlert, type App } from "./app";
import { audit } from "./audit";
import { retireOldClientSecrets, rotateClientSecret } from "./clients";
import { ConfigError, loadConfig } from "./config";
import { connect } from "./db";
import { activationEmail, resetEmail, securityNotice } from "./emails";
import { HttpError } from "./http";
import { rotateKeys } from "./keys";
import { smtpMailer, type MailMessage, type Mailer } from "./mail";
import { importApiKeys, importUsers } from "./imports";
import { migrate } from "./migrate";
import { encryptionStatus, reencrypt } from "./rekey";
import { endUserSessions } from "./sessions";
import { issueToken } from "./tokens";
import { transaction } from "./tx";
import { checkEmail, checkName, checkUsername, findUserByLogin, insertUser, setDisabled, type UserRow } from "./users";

// The break-glass CLI (docs/DESIGN.md §9.6), run inside a running auth
// container by whoever can reach it, so it works whichever copy is up. It
// needs no sign-in. Every action is audited as `host-cli` and posted to the
// alert webhook.

const ACTOR = "host-cli";

const HELP = `usage: bun cli.ts <command>

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

export interface CliContext {
  app: App;
  mailer: Mailer;
  out: (line: string) => void;
  // A file's text, or standard input's for "-".
  readInput?: (path: string) => Promise<string>;
}

const MAX_INPUT_BYTES = 64 * 1024 * 1024;

async function readInput(path: string): Promise<string> {
  let text: string;
  try {
    text = path === "-" ? await Bun.stdin.text() : await Bun.file(path).text();
  } catch {
    throw new UsageError(`can't read ${path}`);
  }
  if (text.length > MAX_INPUT_BYTES) throw new UsageError("the input is larger than 64 MB; split it");
  return text;
}

interface Args {
  positional: string[];
  flags: Map<string, string[]>;
}

const BOOLEAN_FLAGS = new Set(["bot", "print-link", "print-links", "dry-run"]);

function parse(argv: string[]): Args {
  const positional: string[] = [];
  const flags = new Map<string, string[]>();
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (!arg.startsWith("--")) {
      positional.push(arg);
      continue;
    }
    const name = arg.slice(2);
    const value = BOOLEAN_FLAGS.has(name) ? "true" : argv[++i];
    if (value === undefined) throw new UsageError(`--${name} needs a value`);
    flags.set(name, [...(flags.get(name) ?? []), value]);
  }
  return { positional, flags };
}

class UsageError extends Error {}

function one(args: Args, name: string): string | undefined {
  const values = args.flags.get(name);
  if (values && values.length > 1) throw new UsageError(`--${name} is given twice`);
  return values?.[0];
}

async function userNamed(ctx: CliContext, username: string | undefined): Promise<UserRow> {
  if (!username) throw new UsageError("name the user");
  const user = await findUserByLogin(ctx.app.sql, username);
  if (!user) throw new UsageError(`no user "${username}"`);
  return user;
}

async function send(ctx: CliContext, msg: MailMessage, username: string): Promise<void> {
  try {
    await ctx.mailer.send(msg);
    ctx.out(`emailed ${msg.to}`);
  } catch (e) {
    const why = e instanceof Error && e.name === "SmtpError" ? e.message : "error";
    ctx.out(`the email to ${msg.to} failed (${why}); print a link instead with: bun cli.ts user reset-link ${username} --print-link`);
  }
}

async function alert(ctx: CliContext, text: string): Promise<void> {
  if (ctx.app.config.alertWebhookUrl) await postAlert(ctx.app.config.alertWebhookUrl, fetch, ctx.out, `auth (break-glass CLI): ${text}`);
}

export async function runCli(argv: string[], ctx: CliContext): Promise<number> {
  let args: Args;
  try {
    args = parse(argv);
  } catch (e) {
    ctx.out(`${(e as Error).message}\n\n${HELP}`);
    return 2;
  }
  const [group, command, target] = args.positional;
  const { app } = ctx;
  try {
    if (group === "user" && command === "create") {
      const username = checkUsername(one(args, "username"));
      const name = checkName(one(args, "name"));
      const bot = args.flags.has("bot");
      const email = bot ? null : checkEmail(one(args, "email"));
      const owner = bot ? await userNamed(ctx, one(args, "owner")) : null;
      if (owner && owner.kind !== "person") throw new UsageError("a bot's owner is a person");
      const grants = (args.flags.get("access") ?? []).map((g) => {
        const [service, role] = g.split(":");
        const s = service ? app.services.get(service) : undefined;
        if (!s || !role || !s.roles.includes(role)) throw new UsageError(`--access ${g}: use <service>:<role> with a role the service declares`);
        return { service: s, role };
      });
      const { id, token } = await transaction(app.sql, async (tx, after) => {
        const id = await insertUser(tx, { username, name, email, emailVerified: false, kind: bot ? "bot" : "person", ownerId: owner?.id ?? null, passwordHash: null });
        await audit(tx, { actor: ACTOR, action: "user.create", userId: id, detail: { username, kind: bot ? "bot" : "person" } });
        for (const g of grants) await putAccess(tx, app, { userId: id, service: g.service, role: g.role, actor: ACTOR, ip: null }, after);
        return { id, token: email ? await issueToken(tx, "activate", id, email) : null };
      });
      ctx.out(`created ${username} (${id})`);
      if (email && token) {
        if (args.flags.has("print-link")) ctx.out(`activation link (works once, 14 days): ${app.config.issuer}/activate?token=${token}`);
        else await send(ctx, activationEmail(app.config.issuer, email, username, token), username);
      }
      await alert(ctx, `created ${username}${grants.length ? ` with ${grants.map((g) => `${g.service.name}:${g.role}`).join(", ")}` : ""}`);
      return 0;
    }

    if (group === "user" && command === "clear-mfa") {
      const user = await userNamed(ctx, target);
      await transaction(app.sql, async (tx) => {
        await tx`DELETE FROM totp WHERE user_id = ${user.id}`;
        await tx`DELETE FROM passkeys WHERE user_id = ${user.id}`;
        await tx`DELETE FROM recovery_codes WHERE user_id = ${user.id}`;
        await endUserSessions(tx, app, user.id);
        await audit(tx, { actor: ACTOR, action: "mfa.cleared", userId: user.id });
      });
      ctx.out(`cleared the second factors of ${user.username} and signed them out`);
      if (user.email) await send(ctx, securityNotice(user.email, user.username, "two-factor authentication was cleared by an administrator"), user.username);
      await alert(ctx, `cleared the MFA of ${user.username}`);
      return 0;
    }

    if (group === "user" && (command === "disable" || command === "enable")) {
      const user = await userNamed(ctx, target);
      await transaction(app.sql, (tx) => setDisabled(tx, app, user, command === "disable", ACTOR, null));
      ctx.out(`${command}d ${user.username}`);
      await alert(ctx, `${command}d ${user.username}`);
      return 0;
    }

    if (group === "user" && command === "reset-link") {
      const user = await userNamed(ctx, target);
      if (user.kind !== "person") throw new UsageError("a bot user has no password");
      if (!user.email && !args.flags.has("print-link")) throw new UsageError("the user has no email address; use --print-link");
      const token = await transaction(app.sql, async (tx) => {
        const t = await issueToken(tx, "reset", user.id, user.email);
        await audit(tx, { actor: ACTOR, action: "reset.sent", userId: user.id });
        return t;
      });
      if (args.flags.has("print-link")) ctx.out(`reset link (works once, 30 minutes): ${app.config.issuer}/reset/confirm?token=${token}`);
      else await send(ctx, resetEmail(app.config.issuer, user.email!, token), user.username);
      await alert(ctx, `made a reset link for ${user.username}`);
      return 0;
    }

    if (group === "client" && (command === "secret" || command === "retire-old-secrets")) {
      const client = target ? app.services.client(target) : undefined;
      if (!client || client.type !== "confidential") throw new UsageError("name a confidential client from the services file");
      if (command === "secret") {
        const secret = await transaction(app.sql, async (tx) => {
          const s = await rotateClientSecret(tx, client.id);
          await audit(tx, { actor: ACTOR, action: "client.secret", detail: { client: client.id } });
          return s;
        });
        ctx.out(secret);
        await alert(ctx, `made a new secret for the client ${client.id}`);
      } else {
        const n = await transaction(app.sql, async (tx) => {
          const retired = await retireOldClientSecrets(tx, client.id);
          await audit(tx, { actor: ACTOR, action: "client.secret_retire", detail: { client: client.id, retired } });
          return retired;
        });
        ctx.out(`retired ${n} old secret(s) of ${client.id}`);
        await alert(ctx, `retired the old secrets of the client ${client.id}`);
      }
      return 0;
    }

    if (group === "encryption" && (command === "status" || command === "reencrypt")) {
      if (command === "status") {
        for (const c of await encryptionStatus(app.sql, app.crypt)) {
          const counts = Object.entries(c.byVersion).map(([v, n]) => `v${v}: ${n}`).join(", ") || "none";
          ctx.out(`${c.label}: ${counts}${c.unreadable ? ` (${c.unreadable} under a key that isn't configured)` : ""}`);
        }
        ctx.out(`AUTH_ENCRYPTION_KEY is v${app.crypt.version}`);
        return 0;
      }
      const results = await reencrypt(app.sql, app.crypt);
      const failed = results.flatMap((r) => r.failed.map((id) => `${r.label}: ${id}`));
      for (const r of results) ctx.out(`${r.label}: ${r.rewritten} rewritten under v${app.crypt.version}, ${r.current} already were`);
      for (const f of failed) ctx.out(`no configured key reads ${f}; left as it was`);
      const rewritten = results.reduce((n, r) => n + r.rewritten, 0);
      await audit(app.sql, { actor: ACTOR, action: "encryption.reencrypt", detail: { version: app.crypt.version, rewritten, failed: failed.length } });
      await alert(ctx, `re-encrypted ${rewritten} values under key v${app.crypt.version}${failed.length ? `; ${failed.length} unreadable` : ""}`);
      return failed.length > 0 ? 1 : 0;
    }

    if (group === "import" && (command === "users" || command === "api-keys")) {
      if (!target) throw new UsageError("name the input file, or - for standard input");
      const text = await (ctx.readInput ?? readInput)(target);
      const dryRun = args.flags.has("dry-run");
      let problems: string[];
      let count: number;
      if (command === "users") {
        const result = await importUsers(app, text, { dryRun });
        problems = result.problems;
        count = result.rows.length;
        for (const u of result.rows) {
          if (!u.activation) continue;
          if (args.flags.has("print-links")) ctx.out(`${u.username}: ${app.config.issuer}/activate?token=${u.activation}`);
          else await send(ctx, activationEmail(app.config.issuer, u.email, u.username, u.activation), u.username);
        }
      } else {
        const name = one(args, "service");
        const service = name ? app.services.get(name) : undefined;
        if (!service) throw new UsageError("--service must name a service from the services file");
        const result = await importApiKeys(app, service, text, { dryRun });
        problems = result.problems;
        count = result.rows.length;
      }
      for (const problem of problems) ctx.out(problem);
      if (problems.length > 0) {
        ctx.out(`nothing imported: ${problems.length} problem(s)`);
        return 1;
      }
      if (dryRun) {
        ctx.out("every line passed; nothing written (--dry-run)");
        return 0;
      }
      const what = command === "users" ? "users" : "API keys";
      ctx.out(`imported ${count} ${what}`);
      await alert(ctx, `imported ${count} ${what}`);
      return 0;
    }

    if (group === "migrate") {
      await migrate(app.sql, ctx.out);
      ctx.out("migrations are up to date");
      return 0;
    }

    ctx.out(HELP);
    return group === "help" || group === undefined ? 0 : 2;
  } catch (e) {
    if (e instanceof UsageError) {
      ctx.out(`error: ${e.message}`);
      return 2;
    }
    if (e instanceof HttpError) {
      ctx.out(`error: ${e.description}`);
      return 1;
    }
    throw e;
  }
}

export async function main(argv: string[]): Promise<number> {
  let config;
  try {
    config = loadConfig(process.env);
  } catch (e) {
    if (!(e instanceof ConfigError)) throw e;
    console.error(e.message);
    return 1;
  }
  const sql = connect(config.databaseUrl);
  try {
    const mailer = smtpMailer(config.smtp, config.emailFrom);
    const app = createApp(config, sql, mailer, { log: (line) => console.error(line) });
    if (argv[0] !== "migrate" && argv[0] !== "help" && argv.length > 0) {
      await migrate(sql);
      await rotateKeys(sql, app.crypt);
    }
    return await runCli(argv, { app, mailer, out: (line) => console.log(line) });
  } finally {
    await sql.close({ timeout: 5 });
  }
}
