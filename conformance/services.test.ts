import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import {
  authorizeParams,
  backChannel,
  basic,
  type Browser,
  CLI,
  decodeJwt,
  defaultServices,
  enabled,
  nest,
  newId,
  pkce,
  sha256,
  Stack,
  type TestUser,
  waitFor,
} from "./harness";

// Services registered through the management API (docs/DESIGN.md §6, §6.2,
// §7.5): the listing, registration with every rule of §6, changes and
// deletions and what they do to what exists, client secrets, and the
// services file checked at start.

setDefaultTimeout(30_000);

const ISO = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;

async function expectError(res: Response, status: number, error: string, description: string): Promise<void> {
  expect({ status: res.status, body: await res.json() }).toEqual({ status, body: { error, error_description: description } });
}

async function bodyOf(res: Response, status: number): Promise<any> {
  const text = await res.text();
  if (res.status !== status) throw new Error(`expected ${status}, got ${res.status}: ${text}`);
  return text ? JSON.parse(text) : null;
}

// A fresh service name, one of the reserved fixture names with a suffix.
function sname(base: "wiki" | "tasks" | "mailbox" | "notes" = "wiki"): string {
  return `${base}-${randomBytes(4).toString("hex")}`;
}

// One registrable definition in the shape of §6.
function def(name: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    name,
    roles: ["member", "editor"],
    mfa_roles: ["editor"],
    signup: "invite",
    clients: [{ id: name, type: "confidential", redirect_uris: [`https://${name}.example.com/auth/callback`] }],
    ...extra,
  };
}

const callback = (name: string) => `https://${name}.example.com/auth/callback`;
const URI_RULE = "which is not an https URI, an http URI on a loopback host, or (for a public client) a private-use scheme";

describe.skipIf(!enabled)("registered services", () => {
  let stack: Stack;
  let admin: { user: TestUser; browser: Browser };
  let root: Browser;
  let rootName: string;

  const register = (body: unknown, b: Browser = root) => b.api("POST", "/v1/services", body);
  const list = async (b: Browser = root) => bodyOf(await b.api("GET", "/v1/services"), 200);
  async function newSecret(clientId: string): Promise<string> {
    return (await bodyOf(await root.api("POST", `/v1/clients/${clientId}/secrets`, {}), 201)).secret;
  }
  // 200 for a client that authenticates, 401 for one that doesn't.
  const authStatus = async (clientId: string, secret: string, base?: string) => {
    const res = await fetch(`${base ?? stack.url}/oauth/introspect`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: basic(clientId, secret) },
      body: "token=nothing",
    });
    await res.body?.cancel();
    return res.status;
  };
  const alert = async (text: string) => {
    expect(await stack.http.waitForAlert(text)).toBe(text);
  };
  const adminAlert = (text: string) => alert(`auth: ${rootName} ${text}`);
  const auditFor = async (action: string, service: string) => (await stack.audit(action)).filter((r) => r.detail.service === service);

  // An authorization code for a client, through a signed-in browser, at a
  // copy's URL.
  async function codeFor(b: Browser, clientId: string, redirectUri: string, base?: string): Promise<{ code: string; verifier: string }> {
    const { verifier, challenge } = pkce();
    const res = await b.request(`${base ?? stack.url}/oauth/authorize?${new URLSearchParams(authorizeParams(clientId, redirectUri, challenge))}`);
    const location = res.headers.get("Location");
    await res.body?.cancel();
    const code = location ? new URL(location, stack.url).searchParams.get("code") : null;
    if (!code) throw new Error(`no code: ${res.status} ${location}`);
    return { code, verifier };
  }
  const exchange = (clientId: string, secret: string, code: string, verifier: string, redirectUri: string, base?: string) =>
    fetch(`${base ?? stack.url}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: basic(clientId, secret) },
      body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: redirectUri, code_verifier: verifier }).toString(),
    });

  beforeAll(async () => {
    stack = await Stack.start();
    admin = await stack.admin();
    root = admin.browser;
    rootName = admin.user.username;
  });
  afterAll(async () => {
    await stack.stop();
  });
  beforeEach(async () => {
    await stack.resetLimits();
  });

  // ---------------------------------------------------------------- callers

  describe("callers", () => {
    const changes = (name: string) =>
      [
        ["POST", "/v1/services", def(sname())],
        ["PUT", `/v1/services/${name}`, def(name)],
        ["DELETE", `/v1/services/${name}`, undefined],
        ["POST", `/v1/clients/${name}/secrets`, {}],
        ["DELETE", `/v1/clients/${name}/old-secrets`, undefined],
      ] as const;

    test("every change needs a sign-in with a second factor in the last 15 minutes; GET needs only the admin", async () => {
      const name = sname();
      await bodyOf(await register(def(name)), 201);
      const stale = await stack.session(admin.user, { amr: ["pwd", "otp", "mfa"], authAge: 16 * 60 });
      for (const [method, path, body] of [...changes(name), ["PUT", "/v1/services/nowhere", def("nowhere")] as const]) {
        await expectError(await stale.api(method, path, body), 403, "reauth_required", "Sign in again to make this change.");
      }
      expect(await stack.db`SELECT 1 FROM client_secrets WHERE client_id = ${name}`).toHaveLength(0);
      expect((await stale.api("GET", "/v1/services")).status).toBe(200);
      const recent = await stack.session(admin.user, { amr: ["pwd", "otp", "mfa"], authAge: 14 * 60 });
      expect((await recent.api("POST", `/v1/clients/${name}/secrets`, {})).status).toBe(201);
    });

    test("an admin without a second factor, a user without auth:admin, a client, and nobody are refused", async () => {
      const name = sname();
      await bodyOf(await register(def(name)), 201);
      const half = await stack.session((await stack.user({ username: `half-${randomBytes(3).toString("hex")}`, access: { auth: "admin" }, totp: true })).id, { amr: ["pwd"] });
      const plain = await stack.session((await stack.user({ username: `plain-${randomBytes(3).toString("hex")}`, access: { wiki: "owner" } })).id, { amr: ["pwd", "otp", "mfa"] });
      const all = [["GET", "/v1/services", undefined] as const, ...changes(name)];
      for (const [method, path, body] of all) {
        await expectError(await half.api(method, path, body), 403, "forbidden", "Admin actions need a sign-in with a second factor.");
        await expectError(await plain.api(method, path, body), 403, "forbidden", "This needs the auth admin role.");
        const headers: Record<string, string> = { Authorization: stack.basic("wiki") };
        if (body !== undefined) headers["Content-Type"] = "application/json";
        const asClient = await fetch(`${stack.url}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
        await expectError(asClient, 403, "forbidden", "This endpoint is not open to a service's client.");
        const wrong = await fetch(`${stack.url}${path}`, { method, headers: { ...headers, Authorization: basic("wiki", "abc123") }, body: body === undefined ? undefined : JSON.stringify(body) });
        expect(wrong.headers.get("WWW-Authenticate")).toBe('Basic realm="auth"');
        await expectError(wrong, 401, "invalid_client", "Client authentication failed.");
        const nobody = await fetch(`${stack.url}${path}`, { method, headers: body === undefined ? {} : { "Content-Type": "application/json", Origin: stack.issuer }, body: body === undefined ? undefined : JSON.stringify(body) });
        await expectError(nobody, 401, "unauthorized", "Sign in first.");
      }
      expect(await stack.db`SELECT 1 FROM client_secrets WHERE client_id = ${name}`).toHaveLength(0);
      expect(await stack.db`SELECT 1 FROM services WHERE name = ${name}`).toHaveLength(1);
    });

    test("a change needs the CSRF token", async () => {
      await expectError(await root.api("POST", "/v1/services", def(sname()), { "X-CSRF-Token": "" }), 403, "forbidden", "The CSRF token is missing or wrong.");
    });
  });

  // -------------------------------------------------------------------- GET

  describe("GET /v1/services", () => {
    test("auth, then the file's services, each whole, with its source and its confidential clients' live secrets", async () => {
      const body = await list();
      expect(body.next).toBeNull();
      expect(body.held).toBeArray();
      expect(body.items.slice(0, 5).map((s: any) => s.name)).toEqual(["auth", "wiki", "tasks", "mailbox", "notes"]);
      const secret = [{ created_at: expect.stringMatching(ISO) }];
      expect(body.items.slice(0, 5)).toEqual([
        {
          name: "auth",
          roles: ["admin"],
          mfa_roles: ["admin"],
          signup: "closed",
          default_role: null,
          manages_own_members: false,
          api_key_scopes: [],
          app_password_scopes: [],
          clients: [],
          events_url: null,
          source: "builtin",
        },
        {
          name: "wiki",
          roles: ["member", "admin", "owner"],
          mfa_roles: ["admin", "owner"],
          signup: "invite",
          default_role: null,
          manages_own_members: true,
          api_key_scopes: [],
          app_password_scopes: [],
          clients: [
            {
              id: "wiki",
              type: "confidential",
              redirect_uris: ["https://wiki.example.com/auth/callback"],
              post_logout_redirect_uris: ["https://wiki.example.com/"],
              secrets: secret,
            },
          ],
          events_url: stack.http.eventsUrl("wiki"),
          source: "file",
        },
        {
          name: "tasks",
          roles: ["user"],
          mfa_roles: [],
          signup: "open",
          default_role: "user",
          manages_own_members: false,
          api_key_scopes: ["tasks:read", "tasks:write"],
          app_password_scopes: [],
          clients: [
            { id: "tasks", type: "confidential", redirect_uris: ["https://tasks.example.com/auth/callback"], post_logout_redirect_uris: [], secrets: secret },
            { id: "tasks-ios", type: "public", redirect_uris: ["com.example.tasks:/auth/callback"], post_logout_redirect_uris: [] },
          ],
          events_url: stack.http.eventsUrl("tasks"),
          source: "file",
        },
        {
          name: "mailbox",
          roles: ["user", "admin"],
          mfa_roles: ["admin"],
          signup: "invite",
          default_role: null,
          manages_own_members: true,
          api_key_scopes: [],
          app_password_scopes: ["imap", "smtp"],
          clients: [{ id: "mailbox", type: "confidential", redirect_uris: ["https://mail.example.com/auth/callback"], post_logout_redirect_uris: [], secrets: secret }],
          events_url: stack.http.eventsUrl("mailbox"),
          source: "file",
        },
        {
          name: "notes",
          roles: ["reader", "writer"],
          mfa_roles: [],
          signup: "closed",
          default_role: null,
          manages_own_members: false,
          api_key_scopes: [],
          app_password_scopes: [],
          clients: [{ id: "notes", type: "confidential", redirect_uris: ["https://notes.example.com/auth/callback"], post_logout_redirect_uris: [], secrets: secret }],
          events_url: null,
          source: "file",
        },
      ]);
    });

    test("a registered service is listed after them, as database, with each live secret newest first", async () => {
      const name = sname();
      const pub = `${name}-ios`;
      await bodyOf(
        await register(def(name, { clients: [...(def(name).clients as unknown[]), { id: pub, type: "public", redirect_uris: ["com.example.app:/cb"] }] })),
        201,
      );
      const before = (await list()).items.find((s: any) => s.name === name);
      expect(before.source).toBe("database");
      expect(before.clients).toEqual([
        { id: name, type: "confidential", redirect_uris: [callback(name)], post_logout_redirect_uris: [], secrets: [] },
        { id: pub, type: "public", redirect_uris: ["com.example.app:/cb"], post_logout_redirect_uris: [] },
      ]);
      await newSecret(name);
      await stack.db`UPDATE client_secrets SET created_at = now() - interval '1 hour' WHERE client_id = ${name}`;
      await newSecret(name);
      const after = (await list()).items.find((s: any) => s.name === name);
      const secrets = after.clients[0].secrets.map((s: any) => Date.parse(s.created_at));
      expect(secrets).toHaveLength(2);
      expect(secrets[0]).toBeGreaterThan(secrets[1]);
      expect(after.clients[1].secrets).toBeUndefined();
    });
  });

  // ----------------------------------------------------------- registration

  describe("POST /v1/services", () => {
    test("registers: 201 with the definition as stored, audited and alerted", async () => {
      const name = sname();
      const body = def(name, {
        signup: "open",
        default_role: "member",
        manages_own_members: true,
        api_key_scopes: [`${name}:read`],
        app_password_scopes: [],
        events_url: `http://${name}.internal:3000/auth/events`,
        clients: [
          {
            id: name,
            type: "confidential",
            redirect_uris: [callback(name), "http://localhost:8080/cb"],
            post_logout_redirect_uris: [`https://${name}.example.com/`],
          },
          { id: `${name}.ios`, type: "public", redirect_uris: ["com.example.app:/cb", "http://127.0.0.1/cb", "http://[::1]:9000/cb"] },
        ],
      });
      const res = await register(body);
      expect(await bodyOf(res, 201)).toEqual({
        name,
        roles: ["member", "editor"],
        mfa_roles: ["editor"],
        signup: "open",
        default_role: "member",
        manages_own_members: true,
        api_key_scopes: [`${name}:read`],
        app_password_scopes: [],
        clients: [
          { id: name, type: "confidential", redirect_uris: [callback(name), "http://localhost:8080/cb"], post_logout_redirect_uris: [`https://${name}.example.com/`], secrets: [] },
          { id: `${name}.ios`, type: "public", redirect_uris: ["com.example.app:/cb", "http://127.0.0.1/cb", "http://[::1]:9000/cb"], post_logout_redirect_uris: [] },
        ],
        events_url: `http://${name}.internal:3000/auth/events`,
        source: "database",
        held: false,
      });
      const [a] = await auditFor("service.create", name);
      expect(a).toMatchObject({ actor: admin.user.id, user_id: null, ip: root.ip, detail: { service: name, clients: [name, `${name}.ios`], held: false } });
      await adminAlert(
        `registered the service ${name}, with the redirect URIs ${callback(name)}, http://localhost:8080/cb, https://${name}.example.com/, com.example.app:/cb, http://127.0.0.1/cb, http://[::1]:9000/cb`,
      );
      const listed = (await list()).items.find((s: any) => s.name === name);
      expect(listed).toMatchObject({ name, source: "database", default_role: "member" });
      expect("held" in listed).toBe(false);
    });

    test("null and [] where the file would leave a field out", async () => {
      const name = sname();
      const body = await bodyOf(
        await register(def(name, { default_role: null, events_url: null, api_key_scopes: [], app_password_scopes: [], mfa_roles: [], signup: "closed" })),
        201,
      );
      expect(body).toMatchObject({ default_role: null, events_url: null, api_key_scopes: [], app_password_scopes: [], mfa_roles: [], signup: "closed", manages_own_members: false });
    });

    test("a registered service works at once: its client authenticates and a user signs in to it, on another copy too", async () => {
      const copy = await stack.spawn();
      await copy.ready();
      // The copy has loaded the services before this one exists.
      expect((await fetch(`${copy.url}/login`)).status).toBe(200);
      const name = sname();
      await bodyOf(await register(def(name)), 201);
      const secret = await newSecret(name);
      expect(await authStatus(name, secret, copy.url)).toBe(200);
      const user = await stack.user({ username: `sw-${randomBytes(3).toString("hex")}`, access: { [name]: "member" } });
      const b = await stack.session(user);
      const { code, verifier } = await codeFor(b, name, callback(name), copy.url);
      const tokens = await bodyOf(await exchange(name, secret, code, verifier, callback(name), copy.url), 200);
      expect(decodeJwt(tokens.access_token).claims).toMatchObject({ aud: name, role: "member", sub: user.id, username: user.username });
      await copy.stop();
    });

    describe("every rule of §6, each problem on its own", () => {
      const many = (n: number, f: (i: number) => unknown) => Array.from({ length: n }, (_, i) => f(i));
      const client = (over: Record<string, unknown>) => ({ clients: [{ id: "c1", type: "confidential", redirect_uris: ["https://c.example.com/cb"], ...over }] });
      const cases: [string, Record<string, unknown>, string][] = [
        ["no name", { name: undefined }, "name must match [a-z][a-z0-9-]{0,62}"],
        ["a numeric name", { name: 7 }, "name must match [a-z][a-z0-9-]{0,62}"],
        ["a capitalised name", { name: "Wiki" }, "name must match [a-z][a-z0-9-]{0,62}"],
        ["a name starting with a dash", { name: "-wiki" }, "name must match [a-z][a-z0-9-]{0,62}"],
        ["a name with an underscore", { name: "wi_ki" }, "name must match [a-z][a-z0-9-]{0,62}"],
        ["a name of 64 characters", { name: `w${"x".repeat(63)}` }, "name must match [a-z][a-z0-9-]{0,62}"],
        ["the name auth", { name: "auth" }, 'the name "auth" is reserved'],
        ["no roles", { roles: undefined, mfa_roles: [] }, "roles must be a non-empty array of names"],
        ["null roles", { roles: null, mfa_roles: [] }, "roles must be a non-empty array of names"],
        ["empty roles", { roles: [], mfa_roles: [] }, "roles must be a non-empty array of names"],
        ["roles as a string", { roles: "member", mfa_roles: [] }, "roles must be a non-empty array of names"],
        ["a capitalised role", { roles: ["Member"], mfa_roles: [] }, 'roles has an invalid name "Member"'],
        ["a numeric role", { roles: [1], mfa_roles: [] }, "roles has an invalid name 1"],
        ["a null role", { roles: [null], mfa_roles: [] }, "roles has an invalid name null"],
        ["a role of 33 characters", { roles: [`r${"x".repeat(32)}`], mfa_roles: [] }, `roles has an invalid name "r${"x".repeat(32)}"`],
        ["a repeated role", { roles: ["member", "member"], mfa_roles: [] }, 'roles lists "member" twice'],
        ["33 roles", { roles: many(33, (i) => `r${i}`), mfa_roles: [] }, "roles has more than 32 names"],
        ["no mfa_roles", { mfa_roles: undefined }, "mfa_roles must be an array of names"],
        ["null mfa_roles", { mfa_roles: null }, "mfa_roles must be an array of names"],
        ["an mfa role that isn't a role", { mfa_roles: ["owner"] }, 'mfa_roles has "owner", which is not one of roles'],
        ["an invalid mfa role", { mfa_roles: ["Owner"] }, 'mfa_roles has an invalid name "Owner"'],
        ["a repeated mfa role", { mfa_roles: ["editor", "editor"] }, 'mfa_roles lists "editor" twice'],
        ["no signup", { signup: undefined }, 'signup must be "closed", "invite" or "open"'],
        ["an unknown signup", { signup: "public" }, 'signup must be "closed", "invite" or "open"'],
        ["a numeric signup", { signup: 1 }, 'signup must be "closed", "invite" or "open"'],
        ["open without default_role", { signup: "open" }, "default_role must be one of roles when signup is open"],
        ["open with a null default_role", { signup: "open", default_role: null }, "default_role must be one of roles when signup is open"],
        ["open with an undeclared default_role", { signup: "open", default_role: "boss" }, "default_role must be one of roles when signup is open"],
        ["a default_role on an invite service", { default_role: "member" }, 'default_role is only for signup "open"'],
        ["an empty default_role on a closed service", { signup: "closed", default_role: "" }, 'default_role is only for signup "open"'],
        ["manages_own_members as a string", { manages_own_members: "yes" }, "manages_own_members must be true or false"],
        ["manages_own_members as null", { manages_own_members: null }, "manages_own_members must be true or false"],
        ["manages_own_members as a number", { manages_own_members: 1 }, "manages_own_members must be true or false"],
        ["null api_key_scopes", { api_key_scopes: null }, "api_key_scopes must be an array of names"],
        ["api_key_scopes as a string", { api_key_scopes: "x:read" }, "api_key_scopes must be an array of names"],
        ["an invalid API key scope", { api_key_scopes: ["X:read"] }, 'api_key_scopes has an invalid name "X:read"'],
        ["an API key scope of 65 characters", { api_key_scopes: [`s${"x".repeat(64)}`] }, `api_key_scopes has an invalid name "s${"x".repeat(64)}"`],
        ["a repeated API key scope", { api_key_scopes: ["x:read", "x:read"] }, 'api_key_scopes lists "x:read" twice'],
        ["33 API key scopes", { api_key_scopes: many(33, (i) => `s${i}`) }, "api_key_scopes has more than 32 names"],
        ["null app_password_scopes", { app_password_scopes: null }, "app_password_scopes must be an array of names"],
        ["an invalid app password scope", { app_password_scopes: ["imap/"] }, 'app_password_scopes has an invalid name "imap/"'],
        ["a repeated app password scope", { app_password_scopes: ["imap", "imap"] }, 'app_password_scopes lists "imap" twice'],
        ["33 app password scopes", { app_password_scopes: many(33, (i) => `s${i}`) }, "app_password_scopes has more than 32 names"],
        ["no clients", { clients: undefined }, "clients must be a non-empty array"],
        ["null clients", { clients: null }, "clients must be a non-empty array"],
        ["empty clients", { clients: [] }, "clients must be a non-empty array"],
        ["clients as an object", { clients: { id: "c1" } }, "clients must be a non-empty array"],
        ["6 clients", { clients: many(6, (i) => ({ id: `c${i}`, type: "public", redirect_uris: ["https://c.example.com/cb"] })) }, "clients has more than 5"],
        ["a client that is a string", { clients: ["c1"] }, "clients[0]: must be an object"],
        ["a client that is null", { clients: [null] }, "clients[0]: must be an object"],
        ["a client that is an array", { clients: [[]] }, "clients[0]: must be an object"],
        ["a client with secrets", client({ secrets: [] }), 'clients[0]: unknown field "secrets"'],
        ["a client with a secret", client({ secret: "abc123" }), 'clients[0]: unknown field "secret"'],
        ["a client without an id", client({ id: undefined }), "clients[0]: id must match [a-z0-9][a-z0-9._-]{0,63}"],
        ["a client with a capitalised id", client({ id: "C1" }), "clients[0]: id must match [a-z0-9][a-z0-9._-]{0,63}"],
        ["a client id starting with a dot", client({ id: ".c1" }), "clients[0]: id must match [a-z0-9][a-z0-9._-]{0,63}"],
        ["a client id of 65 characters", client({ id: `c${"x".repeat(64)}` }), "clients[0]: id must match [a-z0-9][a-z0-9._-]{0,63}"],
        ["a numeric client id", client({ id: 5 }), "clients[0]: id must match [a-z0-9][a-z0-9._-]{0,63}"],
        [
          "two clients with one id",
          { clients: [{ id: "c1", type: "confidential", redirect_uris: ["https://c.example.com/cb"] }, { id: "c1", type: "public", redirect_uris: ["https://c.example.com/cb"] }] },
          'clients[1]: id "c1" is used by another client',
        ],
        ["a client without a type", client({ type: undefined }), 'clients[0]: type must be "confidential" or "public"'],
        ["a client of an unknown type", client({ type: "spa" }), 'clients[0]: type must be "confidential" or "public"'],
        ["no redirect_uris", client({ redirect_uris: undefined }), "clients[0]: redirect_uris must be a non-empty array of URIs"],
        ["null redirect_uris", client({ redirect_uris: null }), "clients[0]: redirect_uris must be a non-empty array of URIs"],
        ["empty redirect_uris", client({ redirect_uris: [] }), "clients[0]: redirect_uris must be a non-empty array of URIs"],
        ["redirect_uris as a string", client({ redirect_uris: "https://c.example.com/cb" }), "clients[0]: redirect_uris must be a non-empty array of URIs"],
        ["an http redirect off loopback", client({ redirect_uris: ["http://c.example.com/cb"] }), `clients[0]: redirect_uris has "http://c.example.com/cb", ${URI_RULE}`],
        ["an http redirect on a loopback-looking host", client({ redirect_uris: ["http://localhost.example.com/cb"] }), `clients[0]: redirect_uris has "http://localhost.example.com/cb", ${URI_RULE}`],
        ["a redirect with a fragment", client({ redirect_uris: ["https://c.example.com/cb#x"] }), `clients[0]: redirect_uris has "https://c.example.com/cb#x", ${URI_RULE}`],
        ["a relative redirect", client({ redirect_uris: ["/cb"] }), `clients[0]: redirect_uris has "/cb", ${URI_RULE}`],
        ["an ftp redirect", client({ redirect_uris: ["ftp://c.example.com/cb"] }), `clients[0]: redirect_uris has "ftp://c.example.com/cb", ${URI_RULE}`],
        ["a private-use scheme on a confidential client", client({ redirect_uris: ["com.example.app:/cb"] }), `clients[0]: redirect_uris has "com.example.app:/cb", ${URI_RULE}`],
        ["a scheme without a dot on a public client", client({ type: "public", redirect_uris: ["app:/cb"] }), `clients[0]: redirect_uris has "app:/cb", ${URI_RULE}`],
        ["a numeric redirect", client({ redirect_uris: [5] }), `clients[0]: redirect_uris has 5, ${URI_RULE}`],
        ["a redirect with credentials", client({ redirect_uris: ["https://u:s3cret-pw@c.example.com/cb"] }), `clients[0]: redirect_uris has a URI with credentials, ${URI_RULE}`],
        ["a redirect with a user", client({ redirect_uris: ["https://abc123@c.example.com/cb"] }), `clients[0]: redirect_uris has a URI with credentials, ${URI_RULE}`],
        ["11 redirect URIs", client({ redirect_uris: many(11, (i) => `https://c.example.com/${i}`) }), "clients[0]: redirect_uris has more than 10 URIs"],
        ["a redirect of 1025 characters", client({ redirect_uris: [`https://c.example.com/${"x".repeat(1025 - 22)}`] }), "clients[0]: redirect_uris has a URI longer than 1024 characters"],
        ["null post_logout_redirect_uris", client({ post_logout_redirect_uris: null }), "clients[0]: post_logout_redirect_uris must be an array of URIs"],
        ["post_logout_redirect_uris as a string", client({ post_logout_redirect_uris: "https://c.example.com/" }), "clients[0]: post_logout_redirect_uris must be an array of URIs"],
        ["an http sign-out URI off loopback", client({ post_logout_redirect_uris: ["http://c.example.com/"] }), `clients[0]: post_logout_redirect_uris has "http://c.example.com/", ${URI_RULE}`],
        ["a sign-out URI with credentials", client({ post_logout_redirect_uris: ["https://u:s3cret-pw@c.example.com/"] }), `clients[0]: post_logout_redirect_uris has a URI with credentials, ${URI_RULE}`],
        ["11 sign-out URIs", client({ post_logout_redirect_uris: many(11, (i) => `https://c.example.com/${i}`) }), "clients[0]: post_logout_redirect_uris has more than 10 URIs"],
        ["a sign-out URI of 1025 characters", client({ post_logout_redirect_uris: [`https://c.example.com/${"x".repeat(1025 - 22)}`] }), "clients[0]: post_logout_redirect_uris has a URI longer than 1024 characters"],
        ["an ftp events_url", { events_url: "ftp://events.internal/e" }, "events_url must be an http(s) URL without credentials or a fragment"],
        ["an events_url with credentials", { events_url: "https://u:s3cret-pw@events.internal/e" }, "events_url must be an http(s) URL without credentials or a fragment"],
        ["an events_url with a fragment", { events_url: "https://events.internal/e#x" }, "events_url must be an http(s) URL without credentials or a fragment"],
        ["a relative events_url", { events_url: "/events" }, "events_url must be an http(s) URL without credentials or a fragment"],
        ["a numeric events_url", { events_url: 5 }, "events_url must be an http(s) URL without credentials or a fragment"],
        ["an events_url of 1025 characters", { events_url: `https://events.internal/${"x".repeat(1025 - 24)}` }, "events_url is longer than 1024 characters"],
        ["an unknown field", { extra: 1 }, 'unknown field "extra"'],
        ["a source", { source: "database" }, 'unknown field "source"'],
        ["secrets", { secrets: [] }, 'unknown field "secrets"'],
        ["held", { held: false }, 'unknown field "held"'],
      ];

      test.each(cases)("%s", async (_, over, problem) => {
        const name = sname();
        const body = def(name, over);
        const res = await register(body);
        await expectError(res, 400, "invalid_request", problem);
        expect(await stack.db`SELECT 1 FROM services WHERE name = ${name}`).toHaveLength(0);
      });

      test("a URI with credentials is never echoed", async () => {
        const res = await register(def(sname(), client({ redirect_uris: ["https://u:s3cret-pw@c.example.com/cb"] })));
        expect(await res.text()).not.toContain("s3cret-pw");
      });

      test.each([
        ["10 redirect URIs", client({ redirect_uris: many(10, (i) => `https://c.example.com/${i}`) })],
        ["a redirect of 1024 characters", client({ redirect_uris: [`https://c.example.com/${"x".repeat(1024 - 22)}`] })],
        ["10 sign-out URIs", client({ post_logout_redirect_uris: many(10, (i) => `https://c.example.com/${i}`) })],
        ["32 roles", { roles: many(32, (i) => `r${i}`), mfa_roles: [] }],
        ["32 API key scopes", { api_key_scopes: many(32, (i) => `s${i}`) }],
        ["5 clients", { clients: many(5, (i) => ({ id: `c${i}`, type: "public", redirect_uris: ["https://c.example.com/cb"] })) }],
        ["an events_url of 1024 characters", { events_url: `https://events.internal/${"x".repeat(1024 - 24)}` }],
        ["a role of 32 characters", { roles: [`r${"x".repeat(31)}`], mfa_roles: [] }],
        ["a scope of 64 characters", { app_password_scopes: [`s${"x".repeat(63)}`] }],
      ] as [string, Record<string, unknown>][])("at the limit: %s", async (_, over) => {
        // Client ids are unique across services: each case gets its own.
        const suffix = randomBytes(3).toString("hex");
        const clients = (over.clients as any[] | undefined)?.map((c) => ({ ...c, id: `${c.id}-${suffix}` }));
        expect((await register(def(sname(), { ...over, ...(clients ? { clients } : {}) }))).status).toBe(201);
      });

      test("a one-letter name", async () => {
        const letter = String.fromCharCode(97 + Math.floor(Math.random() * 26));
        await root.api("DELETE", `/v1/services/${letter}`);
        const res = await register(def(letter, { clients: [{ id: `one-${randomBytes(3).toString("hex")}`, type: "public", redirect_uris: ["https://c.example.com/cb"] }] }));
        expect(res.status).toBe(201);
        expect((await root.api("DELETE", `/v1/services/${letter}`)).status).toBe(204);
      });

      test("several problems at once are joined with '; ', in the order of the rules", async () => {
        const res = await register({
          extra: 1,
          name: "Bad Name",
          roles: ["member", "member"],
          mfa_roles: ["admin"],
          signup: "open",
          manages_own_members: "no",
          api_key_scopes: ["Bad"],
          clients: [{ id: "Bad", type: "spa", redirect_uris: ["com.example.app:/cb"], extra: true }],
          events_url: "ftp://x",
        });
        await expectError(
          res,
          400,
          "invalid_request",
          [
            'unknown field "extra"',
            "name must match [a-z][a-z0-9-]{0,62}",
            'roles lists "member" twice',
            'mfa_roles has "admin", which is not one of roles',
            "default_role must be one of roles when signup is open",
            "manages_own_members must be true or false",
            'api_key_scopes has an invalid name "Bad"',
            'clients[0]: unknown field "extra"',
            "clients[0]: id must match [a-z0-9][a-z0-9._-]{0,63}",
            'clients[0]: type must be "confidential" or "public"',
            `clients[0]: redirect_uris has "com.example.app:/cb", ${URI_RULE}`,
            "events_url must be an http(s) URL without credentials or a fragment",
          ].join("; "),
        );
      });

      test("a body nested 64 levels deep is read and its problems shown; deeper, as deep as the body holds included, is not JSON", async () => {
        const nested = (levels: number) => "[".repeat(levels) + "]".repeat(levels);
        const name = sname();
        // The definition and its roles are two levels.
        const definition = (roles: string) => JSON.stringify(def(name, { roles: ["member", "<roles>"], mfa_roles: [] })).replace('"<roles>"', roles);
        await expectError(await register(definition(nested(62))), 400, "invalid_request", `roles has an invalid name ${nested(62)}`);
        await expectError(await register(definition(nested(63))), 400, "invalid_request", "The body is not valid JSON.");
        await expectError(await register(nest(definition("<nest>"))), 400, "invalid_request", "The body is not valid JSON.");
      });

      test("the body must be a JSON object sent as application/json", async () => {
        await expectError(await root.api("POST", "/v1/services", "{", {}), 400, "invalid_request", "The body is not valid JSON.");
        await expectError(await root.api("POST", "/v1/services", "[]", {}), 400, "invalid_request", "The body must be a JSON object.");
        await expectError(await root.api("POST", "/v1/services", "x", { "Content-Type": "text/plain" }), 415, "invalid_request", "Send application/json.");
        await expectError(
          await root.api("POST", "/v1/services", "", {}),
          400,
          "invalid_request",
          'name must match [a-z][a-z0-9-]{0,62}; roles must be a non-empty array of names; mfa_roles must be an array of names; signup must be "closed", "invite" or "open"; clients must be a non-empty array',
        );
      });
    });

    test("a name registered already, or a client id another service uses, is a conflict", async () => {
      const name = sname();
      await bodyOf(await register(def(name)), 201);
      await expectError(await register(def(name)), 409, "conflict", `A service named ${name} is registered already.`);
      // A client id of a registered service, or of the file's.
      await expectError(await register(def(sname(), { clients: [{ id: name, type: "confidential", redirect_uris: ["https://c.example.com/cb"] }] })), 409, "conflict", `The client id "${name}" is used by ${name}.`);
      await expectError(await register(def(sname(), { clients: [{ id: "tasks-ios", type: "public", redirect_uris: ["com.example.app:/cb"] }] })), 409, "conflict", 'The client id "tasks-ios" is used by tasks.');
      await expectError(await register(def(sname(), { clients: [{ id: "wiki", type: "confidential", redirect_uris: ["https://c.example.com/cb"] }] })), 409, "conflict", 'The client id "wiki" is used by wiki.');
      // Even for a copy of a file service, another file service's client.
      await expectError(await register(def("notes", { clients: [{ id: "mailbox", type: "confidential", redirect_uris: ["https://c.example.com/cb"] }] })), 409, "conflict", 'The client id "mailbox" is used by mailbox.');
      expect(await stack.db`SELECT 1 FROM services WHERE name = 'notes'`).toHaveLength(0);
    });

    test("at most 100 registered services", async () => {
      const [{ n }] = await stack.db`SELECT count(*)::int AS n FROM services`;
      const prefix = `fill-${randomBytes(3).toString("hex")}`;
      await stack.db`
        INSERT INTO services (name, roles, mfa_roles, signup, created_by)
        SELECT ${prefix} || '-' || g, '{member}', '{}', 'closed', 'test' FROM generate_series(1, ${100 - n}) g`;
      try {
        const name = sname();
        await expectError(await register(def(name)), 409, "conflict", "100 services are registered, the most there can be; delete one first.");
        expect(await stack.db`SELECT 1 FROM services WHERE name = ${name}`).toHaveLength(0);
        await stack.db`DELETE FROM services WHERE name = ${`${prefix}-1`}`;
        expect((await register(def(name))).status).toBe(201);
        await expectError(await register(def(sname())), 409, "conflict", "100 services are registered, the most there can be; delete one first.");
        expect((await root.api("DELETE", `/v1/services/${name}`)).status).toBe(204);
      } finally {
        await stack.db`DELETE FROM services WHERE name LIKE ${`${prefix}-%`}`;
      }
    });

    test("a name the file declares makes a held copy: listed under held, not in effect", async () => {
      const notes = defaultServices(() => "").services.find((s) => s.name === "notes")!;
      const copy = { ...notes, clients: [{ ...notes.clients[0]!, redirect_uris: ["https://notes.example.com/elsewhere"] }] };
      const res = await register(copy);
      expect(await bodyOf(res, 201)).toMatchObject({ name: "notes", source: "database", held: true });
      try {
        const [a] = await auditFor("service.create", "notes");
        expect(a!.detail).toEqual({ service: "notes", clients: ["notes"], held: true });
        await adminAlert("registered the service notes as a held copy of the services file's, with the redirect URIs https://notes.example.com/elsewhere");
        const listed = await list();
        expect(listed.items.find((s: any) => s.name === "notes")).toMatchObject({ source: "file", clients: [{ redirect_uris: ["https://notes.example.com/auth/callback"] }] });
        expect(listed.held.filter((s: any) => s.name === "notes")).toEqual([
          {
            ...copy,
            default_role: null,
            manages_own_members: false,
            api_key_scopes: [],
            app_password_scopes: [],
            events_url: null,
            clients: [{ ...copy.clients[0], post_logout_redirect_uris: [], secrets: [expect.objectContaining({ created_at: expect.stringMatching(ISO) })] }],
            source: "database",
          },
        ]);
        // The file's client is the one in effect.
        const user = await stack.user({ username: `hc-${randomBytes(3).toString("hex")}`, access: { notes: "reader" } });
        const b = await stack.session(user);
        const { code, verifier } = await codeFor(b, "notes", "https://notes.example.com/auth/callback");
        expect((await exchange("notes", stack.secrets.notes!, code, verifier, "https://notes.example.com/auth/callback")).status).toBe(200);
        const held = await b.request(`/oauth/authorize?${new URLSearchParams(authorizeParams("notes", "https://notes.example.com/elsewhere", pkce().challenge))}`);
        expect(held.status).toBe(400);
        expect(held.headers.get("Location")).toBeNull();
        // A held copy is deleted, not changed.
        await expectError(await root.api("PUT", "/v1/services/notes", copy), 409, "conflict", "notes is declared in the services file; change it there.");
        await expectError(await register(copy), 409, "conflict", "A service named notes is registered already.");
      } finally {
        expect((await root.api("DELETE", "/v1/services/notes")).status).toBe(204);
      }
    });

    test("a held copy must keep the file client's type", async () => {
      const notes = defaultServices(() => "").services.find((s) => s.name === "notes")!;
      await expectError(
        await register({ ...notes, clients: [{ id: "notes", type: "public", redirect_uris: ["com.example.notes:/cb"] }] }),
        400,
        "invalid_request",
        "The services file's client notes is confidential, and a client's type can't change.",
      );
      expect(await stack.db`SELECT 1 FROM services WHERE name = 'notes'`).toHaveLength(0);
    });
  });

  describe("api_key_scopes on a deployment without API_KEY_PREFIX", () => {
    let bare: Stack;
    beforeAll(async () => {
      bare = await Stack.start({
        env: { API_KEY_PREFIX: undefined },
        services: (events: (s: string) => string) => ({ services: defaultServices(events).services.filter((s) => s.name !== "tasks") }),
      });
    });
    afterAll(async () => {
      await bare.stop();
    });

    test("are refused, with the other problems", async () => {
      const { browser } = await bare.admin();
      const name = sname();
      await expectError(await browser.api("POST", "/v1/services", def(name, { api_key_scopes: ["x:read"] })), 400, "invalid_request", "api_key_scopes needs API_KEY_PREFIX, which this deployment hasn't set");
      await expectError(
        await browser.api("POST", "/v1/services", def(name, { api_key_scopes: ["x:read"], signup: "nope" })),
        400,
        "invalid_request",
        'signup must be "closed", "invite" or "open"; api_key_scopes needs API_KEY_PREFIX, which this deployment hasn\'t set',
      );
      expect((await browser.api("POST", "/v1/services", def(name, { api_key_scopes: [] }))).status).toBe(201);
    });
  });

  // -------------------------------------------------------------------- PUT

  describe("PUT /v1/services/:name", () => {
    test("what can't be changed: auth, a file service, an unknown name, a name, a client's type", async () => {
      const name = sname();
      await bodyOf(await register(def(name)), 201);
      const wiki = defaultServices((s) => stack.http.eventsUrl(s)).services[0];
      await expectError(await root.api("PUT", "/v1/services/auth", def("auth")), 409, "conflict", "auth's own service can't be changed.");
      await expectError(await root.api("PUT", "/v1/services/wiki", wiki), 409, "conflict", "wiki is declared in the services file; change it there.");
      await expectError(await root.api("PUT", "/v1/services/nowhere", def("nowhere")), 404, "not_found", 'There is no service "nowhere".');
      await expectError(await root.api("PUT", `/v1/services/${name}`, def(sname())), 400, "invalid_request", "A service's name can't change.");
      await expectError(
        await root.api("PUT", `/v1/services/${name}`, def(name, { clients: [{ id: name, type: "public", redirect_uris: ["com.example.app:/cb"] }] })),
        400,
        "invalid_request",
        `A client's type can't change: add a public client with a new id, and remove ${name}.`,
      );
      // The service is checked before the body, and the body's rules before its name.
      await expectError(await root.api("PUT", "/v1/services/auth", "{", {}), 409, "conflict", "auth's own service can't be changed.");
      const bad = await root.api("PUT", `/v1/services/${name}`, def(name, { name: "Other" }));
      expect(bad.status).toBe(400);
      expect(((await bad.json()) as any).error_description).toBe("name must match [a-z][a-z0-9-]{0,62}");
      // A client id another service uses.
      await expectError(
        await root.api("PUT", `/v1/services/${name}`, def(name, { clients: [...(def(name).clients as unknown[]), { id: "wiki", type: "confidential", redirect_uris: ["https://c.example.com/cb"] }] })),
        409,
        "conflict",
        'The client id "wiki" is used by wiki.',
      );
      expect((await list()).items.find((s: any) => s.name === name).clients.map((c: any) => c.id)).toEqual([name]);
    });

    test("an unchanged definition answers the service and writes no audit row and no alert", async () => {
      const name = sname();
      await bodyOf(await register(def(name)), 201);
      const res = await root.api("PUT", `/v1/services/${name}`, def(name));
      expect(await bodyOf(res, 200)).toEqual({
        name,
        roles: ["member", "editor"],
        mfa_roles: ["editor"],
        signup: "invite",
        default_role: null,
        manages_own_members: false,
        api_key_scopes: [],
        app_password_scopes: [],
        clients: [{ id: name, type: "confidential", redirect_uris: [callback(name)], post_logout_redirect_uris: [], secrets: [] }],
        events_url: null,
        source: "database",
        held: false,
      });
      expect(await auditFor("service.update", name)).toEqual([]);
      // A later change's alert arrives; none came for the unchanged one.
      await bodyOf(await root.api("PUT", `/v1/services/${name}`, def(name, { roles: ["member", "editor", "owner"] })), 200);
      await adminAlert(`changed the roles of the service ${name}`);
      expect(stack.alerts.filter((a) => a.includes(`service ${name}`) && a.includes("changed"))).toHaveLength(1);
    });

    test("the fields that changed are audited and alerted, by their JSON names", async () => {
      const name = sname();
      await bodyOf(await register(def(name)), 201);
      const changed = def(name, {
        roles: ["member", "editor", "owner"],
        mfa_roles: ["editor", "owner"],
        signup: "open",
        default_role: "member",
        manages_own_members: true,
        api_key_scopes: ["x:read"],
        app_password_scopes: ["imap"],
        events_url: `http://${name}.internal/e`,
      });
      const body = await bodyOf(await root.api("PUT", `/v1/services/${name}`, changed), 200);
      expect(body).toMatchObject({ signup: "open", default_role: "member", manages_own_members: true, events_url: `http://${name}.internal/e`, held: false });
      const fields = ["roles", "mfa_roles", "signup", "default_role", "manages_own_members", "api_key_scopes", "app_password_scopes", "events_url"];
      const [a] = await auditFor("service.update", name);
      expect(a).toMatchObject({ actor: admin.user.id, user_id: null, ip: root.ip, detail: { service: name, fields, added_clients: [], removed_clients: [] } });
      await adminAlert(`changed the ${fields.join(", ")} of the service ${name}`);
      expect((await list()).items.find((s: any) => s.name === name)).toMatchObject({ roles: ["member", "editor", "owner"], signup: "open" });
    });

    test("clients added and removed: a removed client's secrets and refresh tokens revoked, its unused codes dropped", async () => {
      const name = sname();
      const tv = `${name}-tv`;
      const tvClient = { id: tv, type: "confidential", redirect_uris: ["https://tv.example.com/cb"] };
      await bodyOf(await register(def(name, { clients: [...(def(name).clients as unknown[]), tvClient] })), 201);
      const secret = await newSecret(tv);
      const user = await stack.user({ username: `cr-${randomBytes(3).toString("hex")}`, access: { [name]: "member" } });
      const b = await stack.session(user);
      const first = await codeFor(b, tv, "https://tv.example.com/cb");
      const tokens = await bodyOf(await exchange(tv, secret, first.code, first.verifier, "https://tv.example.com/cb"), 200);
      const unused = await codeFor(b, tv, "https://tv.example.com/cb");

      const added = { id: `${name}-ios`, type: "public", redirect_uris: ["com.example.app:/cb"], post_logout_redirect_uris: ["https://out.example.com/"] };
      const res = await root.api("PUT", `/v1/services/${name}`, def(name, { clients: [...(def(name).clients as unknown[]), added] }));
      expect((await bodyOf(res, 200)).clients.map((c: any) => c.id)).toEqual([name, `${name}-ios`]);
      expect(await authStatus(tv, secret)).toBe(401);
      expect(await stack.db`SELECT 1 FROM client_secrets WHERE client_id = ${tv} AND revoked_at IS NULL`).toHaveLength(0);
      const [rt] = await stack.db`SELECT revoked_at FROM refresh_tokens WHERE token_hash = ${sha256(tokens.refresh_token)}`;
      expect(rt.revoked_at).not.toBeNull();
      expect(await stack.db`SELECT 1 FROM auth_codes WHERE code_hash = ${sha256(unused.code)}`).toHaveLength(0);
      expect(await stack.db`SELECT 1 FROM clients WHERE id = ${tv}`).toHaveLength(0);
      // The user's session is untouched.
      expect(await stack.db`SELECT 1 FROM sessions WHERE user_id = ${user.id}`).toHaveLength(1);
      const [a] = await auditFor("service.update", name);
      expect(a!.detail).toEqual({ service: name, fields: ["clients"], added_clients: [`${name}-ios`], removed_clients: [tv] });
      await adminAlert(`changed the clients of the service ${name}; added the redirect URIs com.example.app:/cb, https://out.example.com/`);
    });

    test("a removed redirect URI drops the unused codes issued for it; the others stay redeemable", async () => {
      const name = sname();
      const two = { id: name, type: "confidential", redirect_uris: [`https://${name}.example.com/a`, `https://${name}.example.com/b`] };
      await bodyOf(await register(def(name, { clients: [two] })), 201);
      const secret = await newSecret(name);
      const user = await stack.user({ username: `ru-${randomBytes(3).toString("hex")}`, access: { [name]: "member" } });
      const b = await stack.session(user);
      const kept = await codeFor(b, name, two.redirect_uris[0]!);
      const gone = await codeFor(b, name, two.redirect_uris[1]!);
      const moved = { ...two, redirect_uris: [two.redirect_uris[0]!, `https://${name}.example.com/c`] };
      await bodyOf(await root.api("PUT", `/v1/services/${name}`, def(name, { clients: [moved] })), 200);
      expect(await stack.db`SELECT 1 FROM auth_codes WHERE code_hash = ${sha256(gone.code)}`).toHaveLength(0);
      expect(((await (await exchange(name, secret, gone.code, gone.verifier, two.redirect_uris[1]!)).json()) as any).error).toBe("invalid_grant");
      expect((await exchange(name, secret, kept.code, kept.verifier, two.redirect_uris[0]!)).status).toBe(200);
      const [a] = await auditFor("service.update", name);
      expect(a!.detail).toEqual({ service: name, fields: ["clients"], added_clients: [], removed_clients: [] });
      await adminAlert(`changed the clients of the service ${name}; added the redirect URIs https://${name}.example.com/c`);
    });

    test("a role still held, or offered by a pending invitation, can't be removed; the counts are in the text", async () => {
      const name = sname();
      const roles = ["guest", "member", "editor", "owner"];
      await bodyOf(await register(def(name, { roles, mfa_roles: ["owner"] })), 201);
      for (const role of ["editor", "editor", "guest"]) await stack.user({ username: `rh-${randomBytes(3).toString("hex")}`, access: { [name]: role } });
      const invites: string[] = [];
      for (const role of ["owner", "owner", "owner", "member"]) {
        invites.push((await bodyOf(await root.api("POST", "/v1/invites", { email: `rh-${randomBytes(3).toString("hex")}@example.com`, service: name, role }), 201)).id);
      }
      // Neither an expired nor an accepted invitation counts.
      await stack.db`UPDATE invites SET expires_at = now() - interval '1 second' WHERE id = ${invites[2]!}`;
      await stack.db`UPDATE invites SET accepted_at = now() WHERE id = ${invites[3]!}`;

      const without = (...gone: string[]) => def(name, { roles: roles.filter((r) => !gone.includes(r)), mfa_roles: gone.includes("owner") ? [] : ["owner"] });
      await expectError(
        await root.api("PUT", `/v1/services/${name}`, without("editor", "guest", "owner")),
        409,
        "conflict",
        'A role still in use can\'t be removed: 2 users hold "editor", 1 user holds "guest", 2 pending invitations offer "owner". Change their roles or delete the invitations first.',
      );
      await stack.db`DELETE FROM invites WHERE id = ${invites[0]!}`;
      await expectError(
        await root.api("PUT", `/v1/services/${name}`, without("owner")),
        409,
        "conflict",
        'A role still in use can\'t be removed: 1 pending invitation offers "owner". Change their roles or delete the invitations first.',
      );
      expect((await list()).items.find((s: any) => s.name === name).roles).toEqual(roles);
      // The accepted invitation's role, which no one holds, goes.
      await bodyOf(await root.api("PUT", `/v1/services/${name}`, without("member")), 200);
      expect((await list()).items.find((s: any) => s.name === name).roles).toEqual(["guest", "editor", "owner"]);
    });
  });

  // ----------------------------------------------------------------- DELETE

  describe("DELETE /v1/services/:name", () => {
    test("deletes the service and everything keyed by it; one registered again starts empty", async () => {
      const name = sname();
      const body = def(name, { api_key_scopes: [`${name}:read`], events_url: `${stack.http.url}/nowhere/${name}` });
      await bodyOf(await register(body), 201);
      const secret = await newSecret(name);
      const user = await stack.user({ username: `sd-${randomBytes(3).toString("hex")}` });
      // Through the API, so the grant queues an event the sink won't take.
      await bodyOf(await root.api("PUT", `/v1/users/${user.id}/access/${name}`, { role: "member" }), 200);
      const b = await stack.session(user);
      await bodyOf(await b.api("POST", "/v1/me/api-keys", { name: "script", service: name, scopes: [`${name}:read`] }), 201);
      const signIn = await codeFor(b, name, callback(name));
      const tokens = await bodyOf(await exchange(name, secret, signIn.code, signIn.verifier, callback(name)), 200);
      const unused = await codeFor(b, name, callback(name));
      await bodyOf(await root.api("POST", "/v1/invites", { email: `sd-${randomBytes(3).toString("hex")}@example.com`, service: name, role: "member" }), 201);
      await waitFor(async () => (await stack.outbox(name)).some((e) => e.attempts > 0 && !e.delivered), "a failed delivery");
      const queued = (await stack.outbox(name)).length;
      expect(queued).toBeGreaterThan(0);

      const res = await root.api("DELETE", `/v1/services/${name}`);
      expect(res.status).toBe(204);
      expect(await stack.db`SELECT 1 FROM services WHERE name = ${name}`).toHaveLength(0);
      expect(await stack.db`SELECT 1 FROM clients WHERE service = ${name}`).toHaveLength(0);
      expect(await stack.db`SELECT 1 FROM access WHERE service = ${name}`).toHaveLength(0);
      expect(await stack.db`SELECT 1 FROM invites WHERE service = ${name}`).toHaveLength(0);
      expect(await stack.db`SELECT 1 FROM credentials WHERE service = ${name} AND revoked_at IS NULL`).toHaveLength(0);
      expect(await stack.db`SELECT 1 FROM credentials WHERE service = ${name}`).toHaveLength(1);
      expect(await stack.db`SELECT 1 FROM outbox WHERE service = ${name} AND delivered_at IS NULL AND failed_at IS NULL`).toHaveLength(0);
      expect(await stack.db`SELECT 1 FROM client_secrets WHERE client_id = ${name} AND revoked_at IS NULL`).toHaveLength(0);
      const [rt] = await stack.db`SELECT revoked_at FROM refresh_tokens WHERE token_hash = ${sha256(tokens.refresh_token)}`;
      expect(rt.revoked_at).not.toBeNull();
      expect(await stack.db`SELECT 1 FROM auth_codes WHERE code_hash = ${sha256(unused.code)}`).toHaveLength(0);
      // No event for the app that is gone.
      expect(await stack.outbox(name)).toEqual([]);
      const [a] = await auditFor("service.delete", name);
      expect(a).toMatchObject({ actor: admin.user.id, user_id: null, ip: root.ip, detail: { service: name, held: false } });
      await adminAlert(`deleted the service ${name}, with every role, invitation and credential on it`);
      expect((await list()).items.find((s: any) => s.name === name)).toBeUndefined();
      expect(await authStatus(name, secret)).toBe(401);

      await bodyOf(await register(body), 201);
      expect(await authStatus(name, secret)).toBe(401);
      expect((await bodyOf(await root.api("GET", `/v1/users/${user.id}/access`), 200)).items).toEqual([]);
      expect((await list()).items.find((s: any) => s.name === name).clients[0].secrets).toEqual([]);
    });

    test("auth, a file service and an unknown name", async () => {
      await expectError(await root.api("DELETE", "/v1/services/auth"), 409, "conflict", "auth's own service can't be deleted.");
      await expectError(await root.api("DELETE", "/v1/services/wiki"), 409, "conflict", "wiki is declared in the services file; delete it there.");
      await expectError(await root.api("DELETE", "/v1/services/nowhere"), 404, "not_found", 'There is no service "nowhere".');
      expect(await authStatus("wiki", stack.secrets.wiki!)).toBe(200);
    });

    test("a held copy of a file service goes without touching what the file's service uses", async () => {
      const notes = defaultServices(() => "").services.find((s) => s.name === "notes")!;
      const user = await stack.user({ username: `hd-${randomBytes(3).toString("hex")}`, access: { notes: "reader" } });
      await bodyOf(await register(notes), 201);
      const res = await root.api("DELETE", "/v1/services/notes");
      expect(res.status).toBe(204);
      expect(await stack.db`SELECT role FROM access WHERE service = 'notes' AND user_id = ${user.id}`).toEqual([{ role: "reader" }]);
      expect(await authStatus("notes", stack.secrets.notes!)).toBe(200);
      expect(await stack.db`SELECT 1 FROM services WHERE name = 'notes'`).toHaveLength(0);
      const rows = await auditFor("service.delete", "notes");
      expect(rows.at(-1)).toMatchObject({ actor: admin.user.id, detail: { service: "notes", held: true } });
      await adminAlert("deleted the held copy of the service notes");
      expect((await list()).held.filter((s: any) => s.name === "notes")).toEqual([]);
    });

    test("a copy held because the file gives one of its client ids to another service: listed, logged, not changed, deleted", async () => {
      const name = sname("mailbox");
      const user = await stack.user({ username: `hx-${randomBytes(3).toString("hex")}` });
      await stack.db.begin(async (tx) => {
        await tx`INSERT INTO services (name, roles, mfa_roles, signup, created_by) VALUES (${name}, '{member}', '{}', 'invite', 'test')`;
        await tx`INSERT INTO clients (id, service, type, redirect_uris) VALUES ('mailbox', ${name}, 'confidential', '{https://elsewhere.example.com/cb}')`;
        await tx`INSERT INTO access (user_id, service, role, granted_by) VALUES (${user.id}, ${name}, 'member', 'host-cli')`;
        await tx`UPDATE services_revision SET revision = revision + 1`;
      });
      const listed = await list();
      expect(listed.items.find((s: any) => s.name === name)).toBeUndefined();
      expect(listed.held.filter((s: any) => s.name === name)).toEqual([
        expect.objectContaining({ name, source: "database", clients: [expect.objectContaining({ id: "mailbox", redirect_uris: ["https://elsewhere.example.com/cb"] })] }),
      ]);
      expect(listed.items.find((s: any) => s.name === "mailbox").clients[0].redirect_uris).toEqual(["https://mail.example.com/auth/callback"]);
      await waitFor(() => stack.logs.includes(`service ${name} is held: the services file gives one of its client ids to another service`), "the held log line");
      await expectError(
        await root.api("PUT", `/v1/services/${name}`, def(name, { roles: ["member"], mfa_roles: [], clients: [{ id: "mailbox", type: "confidential", redirect_uris: ["https://elsewhere.example.com/cb"] }] })),
        409,
        "conflict",
        `${name} is a held copy; delete it and copy the service again.`,
      );
      expect((await root.api("DELETE", `/v1/services/${name}`)).status).toBe(204);
      await adminAlert(`deleted the held copy of the service ${name}`);
      // The file's client keeps its secret; the copy's own name loses its access.
      expect(await authStatus("mailbox", stack.secrets.mailbox!)).toBe(200);
      expect(await stack.db`SELECT 1 FROM access WHERE service = ${name}`).toHaveLength(0);
      expect((await auditFor("service.delete", name))[0]!.detail).toEqual({ service: name, held: true });
    });
  });

  // ---------------------------------------------------------- client secrets

  describe("client secrets", () => {
    test("POST answers a new secret once; two stay live; a third retires the oldest", async () => {
      const name = sname();
      await bodyOf(await register(def(name)), 201);
      const res = await root.api("POST", `/v1/clients/${name}/secrets`, {});
      const first = await bodyOf(res, 201);
      expect(first).toEqual({ client_id: name, service: name, secret: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/) });
      expect(await authStatus(name, first.secret)).toBe(200);
      const [a] = (await stack.audit("client.secret")).filter((r) => r.detail.client === name);
      expect(a).toMatchObject({ actor: admin.user.id, user_id: null, ip: root.ip, detail: { client: name } });
      await adminAlert(`made a new secret for the client ${name}`);

      const second = await newSecret(name);
      expect(await authStatus(name, first.secret)).toBe(200);
      expect(await authStatus(name, second)).toBe(200);
      const third = await newSecret(name);
      expect(await authStatus(name, first.secret)).toBe(401);
      expect(await authStatus(name, second)).toBe(200);
      expect(await authStatus(name, third)).toBe(200);
      expect((await list()).items.find((s: any) => s.name === name).clients[0].secrets).toHaveLength(2);

      // No secret reaches the audit log, an alert or the server's log.
      const text = [...(await stack.audit()).map((r) => JSON.stringify(r.detail)), ...stack.alerts, ...stack.logs].join("\n");
      for (const s of [first.secret, second, third]) expect(text).not.toContain(s);
    });

    test("DELETE …/old-secrets retires every secret but the newest and reports how many", async () => {
      const name = sname();
      await bodyOf(await register(def(name)), 201);
      const s1 = await newSecret(name);
      const s2 = await newSecret(name);
      const res = await root.api("DELETE", `/v1/clients/${name}/old-secrets`);
      expect(await bodyOf(res, 200)).toEqual({ client_id: name, retired: 1 });
      expect(await authStatus(name, s1)).toBe(401);
      expect(await authStatus(name, s2)).toBe(200);
      const rows = (await stack.audit("client.secret_retire")).filter((r) => r.detail.client === name);
      expect(rows.map((r) => [r.actor, r.ip, r.detail])).toEqual([[admin.user.id, root.ip, { client: name, retired: 1 }]]);
      await adminAlert(`retired the old secrets of the client ${name}`);
      // Nothing left to retire: audited, not alerted.
      expect(await bodyOf(await root.api("DELETE", `/v1/clients/${name}/old-secrets`), 200)).toEqual({ client_id: name, retired: 0 });
      expect((await stack.audit("client.secret_retire")).filter((r) => r.detail.client === name).map((r) => r.detail)).toEqual([
        { client: name, retired: 1 },
        { client: name, retired: 0 },
      ]);
      await newSecret(name);
      await adminAlert(`made a new secret for the client ${name}`);
      expect(stack.alerts.filter((a) => a === `auth: ${rootName} retired the old secrets of the client ${name}`)).toHaveLength(1);
      expect(await authStatus(name, s2)).toBe(200);
      // With no secret at all.
      const bare = sname();
      await bodyOf(await register(def(bare)), 201);
      expect(await bodyOf(await root.api("DELETE", `/v1/clients/${bare}/old-secrets`), 200)).toEqual({ client_id: bare, retired: 0 });
    });

    test("a public client, a file client and an unknown client are refused", async () => {
      const name = sname();
      await bodyOf(await register(def(name, { clients: [{ id: name, type: "public", redirect_uris: ["com.example.app:/cb"] }] })), 201);
      for (const [method, path] of [
        ["POST", "secrets"],
        ["DELETE", "old-secrets"],
      ] as const) {
        const body = method === "POST" ? {} : undefined;
        await expectError(await root.api(method, `/v1/clients/${name}/${path}`, body), 409, "conflict", "A public client has no secret.");
        await expectError(await root.api(method, `/v1/clients/tasks-ios/${path}`, body), 409, "conflict", "A public client has no secret.");
        for (const id of ["notes", "wiki"]) {
          await expectError(await root.api(method, `/v1/clients/${id}/${path}`, body), 409, "conflict", `${id} is a client of the services file: make its secret with the CLI (${CLI} client secret ${id}).`);
        }
        await expectError(await root.api(method, `/v1/clients/nobody/${path}`, body), 404, "not_found", "No such client.");
      }
      expect(await authStatus("notes", stack.secrets.notes!)).toBe(200);
      expect(await stack.db`SELECT 1 FROM client_secrets WHERE client_id = 'notes' AND revoked_at IS NULL`).toHaveLength(1);
    });
  });

  // -------------------------------------------------------------- at start

  describe("the services file, checked at start", () => {
    const svc = (over: Record<string, unknown> = {}) => ({
      name: "wiki",
      roles: ["member", "admin"],
      mfa_roles: ["admin"],
      signup: "invite",
      clients: [{ id: "wiki", type: "confidential", redirect_uris: ["https://wiki.example.com/cb"] }],
      ...over,
    });
    const linesOf = (stderr: string) => stderr.trimEnd().split("\n");
    async function refused(services: unknown, env: Record<string, string | undefined> = {}): Promise<string[]> {
      const exit = await stack.exitOf(env, services === undefined ? {} : { services });
      expect(exit.code).toBe(1);
      const lines = linesOf(exit.stderr);
      expect(lines[0]).toBe("invalid configuration:");
      return lines.slice(1);
    }

    test("a file nested 64 levels deep is read; deeper, or millions deep, is not JSON", async () => {
      const nested = (levels: number) => "[".repeat(levels) + "]".repeat(levels);
      // The file, its services, the service and its roles are four levels.
      const file = (entry: string) => JSON.stringify({ services: [svc({ roles: ["member", "<entry>"], mfa_roles: [] })] }).replace('"<entry>"', entry);
      expect(await refused(file(nested(60)))).toEqual([`  - SERVICES_FILE: service "wiki": roles has an invalid name ${nested(60)}`]);
      expect(await refused(file(nested(61)))).toEqual(["  - SERVICES_FILE: the services file is not valid JSON"]);
      expect(await refused(nest(file("<nest>"), 2_000_000))).toEqual(["  - SERVICES_FILE: the services file is not valid JSON"]);
    });

    test.each([
      ["not JSON", "{", ["the services file is not valid JSON"]],
      ["empty", "", ["the services file is not valid JSON"]],
      ["an array", [], ['the services file must be an object with a "services" array']],
      ["null", "null", ['the services file must be an object with a "services" array']],
      ["without services", { service: [] }, ['the services file must be an object with a "services" array']],
      ["with services as an object", { services: {} }, ['the services file must be an object with a "services" array']],
      ["with an unknown top-level field", { services: [svc()], extra: 1 }, ['the services file has an unknown field "extra"']],
    ])("a file that is %s", async (_, file, problems) => {
      expect(await refused(file)).toEqual(problems.map((p) => `  - SERVICES_FILE: ${p}`));
    });

    test.each([
      ["the reserved name", { name: "auth" }, 'service "auth": the name "auth" is reserved'],
      ["a bad name", { name: "Wiki" }, 'service "Wiki": name must match [a-z][a-z0-9-]{0,62}'],
      ["no name", { name: undefined }, "services[0]: name must match [a-z][a-z0-9-]{0,62}"],
      ["a numeric name", { name: 5 }, "services[0]: name must match [a-z][a-z0-9-]{0,62}"],
      ["no mfa_roles", { mfa_roles: undefined }, 'service "wiki": mfa_roles must be an array of names'],
      ["empty api_key_scopes", { api_key_scopes: [] }, 'service "wiki": api_key_scopes must be a non-empty array of names'],
      ["empty app_password_scopes", { app_password_scopes: [] }, 'service "wiki": app_password_scopes must be a non-empty array of names'],
      ["a null default_role", { default_role: null }, 'service "wiki": default_role is only for signup "open"'],
      ["a null events_url", { events_url: null }, 'service "wiki": events_url must be an http(s) URL without credentials or a fragment'],
      ["a source field", { source: "file" }, 'service "wiki": unknown field "source"'],
      ["no clients", { clients: [] }, 'service "wiki": clients must be a non-empty array'],
      ["a client of an unknown type", { clients: [{ id: "wiki", type: "spa", redirect_uris: ["https://wiki.example.com/cb"] }] }, 'service "wiki": clients[0]: type must be "confidential" or "public"'],
      [
        "a redirect URI with credentials",
        { clients: [{ id: "wiki", type: "confidential", redirect_uris: ["https://u:s3cret-pw@wiki.example.com/cb"] }] },
        `service "wiki": clients[0]: redirect_uris has a URI with credentials, ${URI_RULE}`,
      ],
    ])("a service with %s", async (_, over, problem) => {
      expect(await refused({ services: [svc(over)] })).toEqual([`  - SERVICES_FILE: ${problem}`]);
    });

    test("a file's lists have no registration caps", async () => {
      const many = (n: number, f: (i: number) => unknown) => Array.from({ length: n }, (_, i) => f(i));
      const file = {
        services: [
          svc({
            roles: many(40, (i) => `r${i}`),
            mfa_roles: [],
            app_password_scopes: many(40, (i) => `s${i}`),
            clients: [
              { id: "wiki", type: "confidential", redirect_uris: many(12, (i) => `https://wiki.example.com/${i}`) },
              ...many(6, (i) => ({ id: `w${i}`, type: "public", redirect_uris: [`https://wiki.example.com/${"x".repeat(1100)}`] })),
            ],
          }),
        ],
      };
      // A database nothing listens on: the configuration passes, and the copy waits for the database.
      const exit = await stack.exitOf({ DATABASE_URL: "postgres://auth:auth@127.0.0.1:9/auth" }, { services: file, waitMs: 1500 });
      expect(exit.code).toBeNull();
      expect(exit.stderr).not.toContain("invalid configuration");
    });

    test("duplicate names and client ids across services", async () => {
      expect(await refused({ services: [svc(), svc({ clients: [{ id: "other", type: "public", redirect_uris: ["https://o.example.com/cb"] }] })] })).toEqual([
        '  - SERVICES_FILE: service "wiki": name is used by another service',
      ]);
      expect(await refused({ services: [svc(), svc({ name: "tasks" })] })).toEqual(['  - SERVICES_FILE: service "tasks": clients[0]: id "wiki" is used by another client']);
    });

    test("an entry that is not an object, and every problem at once", async () => {
      expect(await refused({ services: [svc(), "x"] })).toEqual(
        [
          "must be an object",
          "name must match [a-z][a-z0-9-]{0,62}",
          "roles must be a non-empty array of names",
          "mfa_roles must be an array of names",
          'signup must be "closed", "invite" or "open"',
          "clients must be a non-empty array",
        ].map((p) => `  - SERVICES_FILE: services[1]: ${p}`),
      );
      const lines = await refused(
        { services: [svc({ name: "auth", signup: "x", api_key_scopes: ["a:read"] }), svc({ name: "notes", clients: [{ id: "wiki", type: "public", redirect_uris: ["https://n.example.com/cb"] }] })], extra: 1 },
        { API_KEY_PREFIX: undefined },
      );
      expect(lines).toEqual([
        '  - SERVICES_FILE: the services file has an unknown field "extra"',
        '  - SERVICES_FILE: service "auth": the name "auth" is reserved',
        '  - SERVICES_FILE: service "auth": signup must be "closed", "invite" or "open"',
        '  - SERVICES_FILE: service "notes": clients[0]: id "wiki" is used by another client',
        "  - API_KEY_PREFIX is required when a service declares api_key_scopes",
      ]);
    });

    test("an unreadable SERVICES_FILE is named", async () => {
      const missing = join(stack.dir, "missing-services.json");
      expect(await refused(undefined, { SERVICES_FILE: missing })).toEqual([`  - SERVICES_FILE "${missing}" can't be read`]);
      expect(await refused(undefined, { SERVICES_FILE: stack.dir })).toEqual([`  - SERVICES_FILE "${stack.dir}" can't be read`]);
    });

    test("API_KEY_PREFIX is required when the file declares api_key_scopes", async () => {
      expect(await refused(undefined, { API_KEY_PREFIX: undefined })).toEqual(["  - API_KEY_PREFIX is required when a service declares api_key_scopes"]);
    });

    test("API_KEY_PREFIX is required when a registered service declares api_key_scopes", async () => {
      const name = sname();
      await bodyOf(await register(def(name, { api_key_scopes: ["x:read"] })), 201);
      try {
        const file = { services: defaultServices((s) => stack.http.eventsUrl(s)).services.filter((s) => s.name !== "tasks") };
        const exit = await stack.exitOf({ API_KEY_PREFIX: undefined }, { services: file, waitMs: 15_000 });
        expect(exit.code).toBe(1);
        const lines = linesOf(exit.stderr);
        expect(lines[0]).toBe("invalid configuration:");
        expect(lines).toContain(`  - API_KEY_PREFIX is required: the registered service ${name} declares api_key_scopes`);
      } finally {
        expect((await root.api("DELETE", `/v1/services/${name}`)).status).toBe(204);
      }
    });

    test("a held copy is in effect on a copy whose file no longer declares it: audited once, with its redirect URIs, and alerted", async () => {
      const notes = defaultServices(() => "").services.find((s) => s.name === "notes")!;
      const held = { ...notes, clients: [{ ...notes.clients[0]!, redirect_uris: ["https://notes.example.com/auth/callback", "https://notes.example.com/new"], post_logout_redirect_uris: ["https://notes.example.com/"] }] };
      await bodyOf(await register(held), 201);
      const file = { services: defaultServices((s) => stack.http.eventsUrl(s)).services.filter((s) => s.name !== "notes") };
      const before = (await stack.audit("service.held_copy_in_effect")).length;
      try {
        const copy = await stack.spawn({ services: file });
        await copy.ready();
        const rows = (await stack.audit("service.held_copy_in_effect")).slice(before);
        expect(rows).toEqual([
          {
            id: expect.any(String),
            actor: null,
            action: "service.held_copy_in_effect",
            user_id: null,
            ip: null,
            detail: { service: "notes", redirect_uris: ["https://notes.example.com/auth/callback", "https://notes.example.com/new", "https://notes.example.com/"] },
          },
        ]);
        await alert(
          "auth: the held copy of the service notes took effect, the services file no longer declaring it; redirect URIs: https://notes.example.com/auth/callback, https://notes.example.com/new, https://notes.example.com/",
        );
        // There, it is the service in effect.
        const there = await bodyOf(await root.request(`${copy.url}/v1/services`), 200);
        expect(there.items.find((s: any) => s.name === "notes")).toMatchObject({ source: "database", clients: [{ redirect_uris: held.clients[0]!.redirect_uris }] });
        expect(there.held.filter((s: any) => s.name === "notes")).toEqual([]);
        // A second copy started the same way reports nothing more.
        const again = await stack.spawn({ services: file });
        await again.ready();
        expect((await stack.audit("service.held_copy_in_effect")).length).toBe(before + 1);
        await copy.stop();
        await again.stop();
      } finally {
        expect((await root.api("DELETE", "/v1/services/notes")).status).toBe(204);
      }
    });
  });
});
