import { SQL } from "bun";
import { createApp, type App } from "../app";
import { rotateClientSecret } from "../clients";
import { loadConfig } from "../config";
import { random } from "../crypto";
import { putAccess } from "../access";
import type { MailMessage } from "../mail";
import { migrate } from "../migrate";
import { buildRouter } from "../routes";
import { handle, type Router } from "../server";
import { transaction } from "../tx";
import { insertUser } from "../users";
import { ARGON2 } from "../passwords";
import { rotateKeys } from "../keys";

// Test support: a throwaway schema per test file, an app wired to fakes, and
// a cookie-keeping browser that drives the real router. Not shipped: the
// image build removes src/testing.

export const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;
export const ISSUER = "https://auth.example.com";

export const SERVICES = {
  services: [
    {
      name: "wiki",
      roles: ["member", "admin", "owner"],
      mfa_roles: ["admin", "owner"],
      signup: "invite",
      manages_own_members: true,
      clients: [
        {
          id: "wiki",
          type: "confidential",
          redirect_uris: ["https://wiki.example.com/auth/callback"],
          post_logout_redirect_uris: ["https://wiki.example.com/"],
        },
      ],
      events_url: "http://wiki.internal:3000/auth/events",
    },
    {
      name: "tasks",
      roles: ["user"],
      mfa_roles: [],
      signup: "open",
      default_role: "user",
      api_key_scopes: ["tasks:read", "tasks:write"],
      clients: [
        { id: "tasks", type: "confidential", redirect_uris: ["https://tasks.example.com/auth/callback"] },
        { id: "tasks-ios", type: "public", redirect_uris: ["com.example.tasks:/auth/callback"] },
      ],
      events_url: "http://tasks.internal:3000/auth/events",
    },
    {
      name: "mailbox",
      roles: ["user", "admin"],
      mfa_roles: ["admin"],
      signup: "invite",
      manages_own_members: true,
      app_password_scopes: ["imap", "smtp"],
      clients: [{ id: "mailbox", type: "confidential", redirect_uris: ["https://mail.example.com/auth/callback"] }],
      events_url: "http://mailbox.internal:3000/auth/events",
    },
    {
      name: "notes",
      roles: ["reader", "writer"],
      mfa_roles: [],
      signup: "closed",
      clients: [{ id: "notes", type: "confidential", redirect_uris: ["https://notes.example.com/auth/callback"] }],
    },
  ],
};

export const TEST_ENV: Record<string, string> = {
  DATABASE_URL: "postgres://auth:s3cret-pw@db.internal:5432/auth",
  ISSUER_URL: ISSUER,
  SERVICES_FILE: "/services.json",
  AUTH_ENCRYPTION_KEY: Buffer.alloc(32, 7).toString("base64"),
  API_KEY_PREFIX: "testkey",
  SMTP_URL: "smtp://localhost:2525",
  EMAIL_FROM: "auth@example.com",
};

export function testConfig(env: Record<string, string> = {}, services: unknown = SERVICES) {
  return loadConfig({ ...TEST_ENV, ...env }, () => JSON.stringify(services));
}

export interface TestDb {
  sql: SQL;
  drop(): Promise<void>;
}

// A schema of its own, migrated, dropped afterwards. Nothing else in the
// database is touched.
export async function testDb(): Promise<TestDb> {
  const url = TEST_DATABASE_URL!;
  const schema = `t_${random(6).toString("hex")}`;
  const admin = new SQL(url, { max: 1 });
  await admin.unsafe(`CREATE SCHEMA ${schema}`);
  const sql = new SQL(url, { max: 5, connection: { search_path: schema } });
  await migrate(sql);
  return {
    sql,
    async drop() {
      await sql.close();
      await admin.unsafe(`DROP SCHEMA ${schema} CASCADE`);
      await admin.close();
    },
  };
}

export interface TestApp {
  app: App;
  router: Router<App>;
  mails: MailMessage[];
  alerts: string[];
  logs: string[];
  secrets: Record<string, string>;
}

// Emails, alerts and the breached-password check are fakes; everything else
// is the real thing against Postgres.
export async function testApp(sql: SQL, env: Record<string, string> = {}, services: unknown = SERVICES): Promise<TestApp> {
  const mails: MailMessage[] = [];
  const alerts: string[] = [];
  const logs: string[] = [];
  const app = createApp(testConfig(env, services), sql, { send: async () => {} }, { log: (l) => logs.push(l), breached: async (pw) => pw === "password1234" });
  app.mail = (m) => mails.push(m);
  app.alert = (t) => alerts.push(t);
  await rotateKeys(sql, app.crypt);
  const secrets: Record<string, string> = {};
  for (const s of app.services.all()) {
    for (const c of s.clients) if (c.type === "confidential") secrets[c.id] = await sql.begin((tx) => rotateClientSecret(tx, c.id));
  }
  return { app, router: buildRouter(), mails, alerts, logs, secrets };
}

// §9.1's parameters, hashed directly: fixtures don't need the semaphore.
export async function fixtureHash(password: string): Promise<string> {
  return Bun.password.hash(password, ARGON2);
}

export async function makeUser(
  t: TestApp,
  u: { username: string; password?: string; email?: string; kind?: "person" | "bot"; access?: Record<string, string>; ownerId?: string },
): Promise<string> {
  const hash = u.password ? await fixtureHash(u.password) : null;
  return transaction(t.app.sql, async (tx, after) => {
    const id = await insertUser(tx, {
      username: u.username,
      name: u.username.charAt(0).toUpperCase() + u.username.slice(1),
      email: u.email ?? (u.kind === "bot" ? null : `${u.username}@example.com`),
      emailVerified: true,
      kind: u.kind ?? "person",
      ownerId: u.ownerId ?? null,
      passwordHash: hash,
    });
    for (const [service, role] of Object.entries(u.access ?? {})) {
      await putAccess(tx, t.app, { userId: id, service: t.app.services.get(service)!, role, actor: "host-cli", ip: null }, after);
    }
    return id;
  });
}

export function basic(id: string, secret: string): string {
  return `Basic ${Buffer.from(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`).toString("base64")}`;
}

// Keeps cookies like a browser, sends Origin on non-GET requests, and calls
// the router directly.
export class Browser {
  readonly cookies = new Map<string, string>();
  constructor(
    readonly t: TestApp,
    readonly ip = "192.0.2.10",
  ) {}

  async request(path: string, init: RequestInit & { origin?: string | null } = {}): Promise<Response> {
    const headers = new Headers(init.headers);
    if (this.cookies.size > 0) headers.set("Cookie", [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; "));
    const method = init.method ?? "GET";
    const issuer = this.t.app.config.issuer;
    if (method !== "GET" && init.origin !== null) headers.set("Origin", init.origin ?? issuer);
    const url = path.startsWith("http") ? path : `${issuer}${path}`;
    const res = await handle(new Request(url, { ...init, headers }), this.t.app, this.t.router, this.ip);
    for (const c of res.headers.getSetCookie()) {
      const [pair] = c.split(";");
      const eq = pair!.indexOf("=");
      const name = pair!.slice(0, eq);
      const value = pair!.slice(eq + 1);
      if (/Max-Age=0/.test(c)) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
    return res;
  }

  async form(path: string, fields: Record<string, string>, opts: { origin?: string | null; csrf?: string | null } = {}): Promise<Response> {
    const body = new URLSearchParams(fields);
    if (opts.csrf !== null) body.set("csrf", opts.csrf ?? (await this.formCsrf()));
    return this.request(path, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
      origin: opts.origin,
    });
  }

  async formCsrf(): Promise<string> {
    if (!this.cookies.has("__Host-csrf")) await this.request("/login");
    return this.cookies.get("__Host-csrf")!;
  }

  async signIn(login: string, password: string, code?: string): Promise<Response> {
    const res = await this.form("/login", { login, password, return_to: "/account" });
    if (res.headers.get("Location") === "/login/second-factor" && code !== undefined) {
      return this.form("/login/second-factor", { code });
    }
    return res;
  }

  // The synchronizer token the account page would read from its meta tag.
  async csrf(): Promise<string> {
    const res = await this.request("/account");
    const m = /name="csrf-token" content="([^"]+)"/.exec(await res.text());
    return m?.[1] ?? "";
  }

  async api(method: string, path: string, body?: unknown, extra: Record<string, string> = {}): Promise<Response> {
    const headers: Record<string, string> = { ...extra };
    if (method !== "GET") {
      headers["X-CSRF-Token"] ??= await this.csrf();
      headers["Content-Type"] ??= "application/json";
    }
    return this.request(path, { method, headers, body: body === undefined ? (method === "GET" ? undefined : "{}") : JSON.stringify(body) });
  }
}

// What the outbox holds for a service, decoded.
export async function outboxEvents(sql: SQL, service?: string): Promise<{ service: string; type: string; payload: Record<string, unknown> }[]> {
  const rows: { service: string; token: string }[] = await sql`SELECT service, token FROM outbox ORDER BY id`;
  return rows
    .filter((r) => !service || r.service === service)
    .map((r) => {
      const claims = JSON.parse(Buffer.from(r.token.split(".")[1]!, "base64url").toString());
      const [type, payload] = Object.entries(claims.events)[0] as [string, Record<string, unknown>];
      return { service: r.service, type, payload };
    });
}

export async function flush(): Promise<void> {
  await Bun.sleep(5);
}

// Waits for work that runs after a response (a reset link is made then).
export async function waitFor(check: () => boolean, ms = 2000): Promise<void> {
  const until = Date.now() + ms;
  while (!check()) {
    if (Date.now() > until) throw new Error("timed out waiting");
    await Bun.sleep(5);
  }
}
