import { describe, expect, test } from "bun:test";
import { ConfigError, loadConfig } from "./config";
import { SERVICES, TEST_ENV } from "./testing/harness";

const DATABASE_URL = "postgres://auth:s3cret-pw@db.internal:5432/auth";
const ENV = { ...TEST_ENV, DATABASE_URL };
const read = (services: unknown) => () => (typeof services === "string" ? services : JSON.stringify(services));

function problems(env: Record<string, string | undefined>, services: unknown = SERVICES): string[] {
  try {
    loadConfig(env, read(services));
  } catch (e) {
    if (e instanceof ConfigError) return e.problems;
    throw e;
  }
  throw new Error("loadConfig accepted the environment");
}

const load = (env: Record<string, string | undefined> = {}, services: unknown = SERVICES) => loadConfig({ ...ENV, ...env }, read(services));

describe("loadConfig", () => {
  test("reads a complete environment", () => {
    const c = load({ PORT: "8080", TRUSTED_PROXIES: "10.0.0.0/8, ::1", AUDIT_RETENTION_DAYS: "90", ALLOW_ACCOUNT_DELETION: "true" });
    expect(c.port).toBe(8080);
    expect(c.databaseUrl).toBe(DATABASE_URL);
    expect(c.issuer).toBe("https://auth.example.com");
    expect(c.encryptionKey).toHaveLength(32);
    expect(c.apiKeyPrefix).toBe("testkey");
    expect(c.trustedProxies).toHaveLength(2);
    expect(c.smtp).toMatchObject({ host: "localhost", secure: "none" });
    expect(c.emailFrom).toBe("auth@example.com");
    expect(c.auditRetentionDays).toBe(90);
    expect(c.allowAccountDeletion).toBe(true);
    expect(c.alertWebhookUrl).toBeNull();
    expect(c.services.all().map((s) => s.name)).toEqual(["auth", "wiki", "tasks", "mailbox", "notes"]);
  });

  test("defaults: port 3000, a year of audit, no self-deletion, no trusted proxy", () => {
    const c = load({ PORT: "  " });
    expect(c.port).toBe(3000);
    expect(c.auditRetentionDays).toBe(365);
    expect(c.allowAccountDeletion).toBe(false);
    expect(c.trustedProxies).toEqual([]);
  });

  test("accepts postgresql:// as well as postgres://", () => {
    const url = "postgresql://auth@localhost/auth";
    expect(load({ DATABASE_URL: url }).databaseUrl).toBe(url);
  });

  test("lists every problem at once", () => {
    expect(problems({ PORT: "http" })).toEqual([
      'PORT must be a whole number from 1 to 65535, not "http"',
      "DATABASE_URL is required",
      "ISSUER_URL is required",
      "SERVICES_FILE is required",
      "AUTH_ENCRYPTION_KEY is required",
      "SMTP_URL is required",
      "EMAIL_FROM is required",
    ]);
  });

  test.each(["0", "65536", "-1", "3e3", "80.5", "0x50"])("refuses PORT=%p", (port) => {
    expect(problems({ ...ENV, PORT: port })).toHaveLength(1);
  });

  test.each(["1", "65535"])("accepts PORT=%p at the edge of the range", (port) => {
    expect(load({ PORT: port }).port).toBe(Number(port));
  });

  test("refuses a DATABASE_URL that isn't a Postgres URL, without echoing it", () => {
    const found = problems({ ...ENV, DATABASE_URL: "mysql://auth:s3cret-pw@db.internal/auth" });
    expect(found).toEqual(["DATABASE_URL must be a postgres:// or postgresql:// URL"]);
    expect(found.join("\n")).not.toContain("s3cret-pw");
  });

  test.each([
    ["a port that isn't a number", "postgres://auth:s3cret-pw@db.internal:notaport/auth"],
    ["a port out of range", "postgres://auth:s3cret-pw@db.internal:99999/auth"],
    ["a broken percent-escape in the password", "postgres://auth:s3cret-pw%zz@db.internal/auth"],
    ["a broken percent-escape in the user", "postgres://a%zz:s3cret-pw@db.internal/auth"],
    ["port 0", "postgres://auth:s3cret-pw@db.internal:0/auth"],
    ["an unknown sslmode", "postgres://auth:s3cret-pw@db.internal/auth?sslmode=bogus"],
    ["a connect_timeout that isn't a number", "postgres://auth:s3cret-pw@db.internal/auth?connect_timeout=abc"],
  ])("refuses a postgres:// URL with %s, without echoing it", (_, url) => {
    const found = problems({ ...ENV, DATABASE_URL: url });
    expect(found).toEqual(["DATABASE_URL is not a well-formed URL"]);
    expect(found.join("\n")).not.toContain("s3cret-pw");
  });

  test.each(["http://auth.example.com", "https://auth.example.com/", "https://auth.example.com/auth", "https://auth.example.com?x=1", "auth.example.com", "https://u:p@auth.example.com"])(
    "refuses ISSUER_URL=%p",
    (issuer) => {
      expect(problems({ ...ENV, ISSUER_URL: issuer })).toHaveLength(1);
    },
  );

  test("a refused ISSUER_URL is never echoed: it can be another variable's value", () => {
    for (const value of ["postgres://auth:s3cret-pw@db.internal:5432/auth", "https://admin:s3cret-pw@auth.example.com"]) {
      const found = problems({ ...ENV, ISSUER_URL: value });
      expect(found).toEqual(["ISSUER_URL must be an https origin with no path or trailing slash (http only for a loopback host)"]);
    }
  });

  test("allows an http issuer on a loopback host only", () => {
    expect(load({ ISSUER_URL: "http://localhost:3000" }).issuer).toBe("http://localhost:3000");
  });

  test.each(["", "c2hvcnQ=", Buffer.alloc(31).toString("base64"), Buffer.alloc(33).toString("base64"), "not base64!"])("refuses AUTH_ENCRYPTION_KEY=%p", (key) => {
    const found = problems({ ...ENV, AUTH_ENCRYPTION_KEY: key });
    expect(found).toHaveLength(1);
    expect(found[0]).toStartWith("AUTH_ENCRYPTION_KEY");
  });

  test("needs API_KEY_PREFIX only when a service declares API key scopes", () => {
    expect(problems({ ...ENV, API_KEY_PREFIX: "" })).toEqual(["API_KEY_PREFIX is required when a service declares api_key_scopes"]);
    const noKeys = { services: SERVICES.services.filter((s) => !("api_key_scopes" in s)) };
    expect(load({ API_KEY_PREFIX: "" }, noKeys).apiKeyPrefix).toBeNull();
    expect(problems({ ...ENV, API_KEY_PREFIX: "Has_Underscore" })).toEqual(["API_KEY_PREFIX must match [a-z][a-z0-9]{1,15}"]);
  });

  test("refuses an SMTP_URL it can't use, without echoing the password", () => {
    for (const url of ["http://mail.example.com", "smtp://user:s3cret-pw@mail.example.com/path", "smtp://user:s3cret-pw@mail.example.com?x=1"]) {
      const found = problems({ ...ENV, SMTP_URL: url });
      expect(found).toHaveLength(1);
      expect(found.join("\n")).not.toContain("s3cret-pw");
    }
  });

  test("refuses a TRUSTED_PROXIES entry that isn't an address or range", () => {
    expect(problems({ ...ENV, TRUSTED_PROXIES: "10.0.0.0/8, proxy.internal" })).toEqual([
      'TRUSTED_PROXIES has "proxy.internal", which is not an IP address or CIDR range',
    ]);
  });

  test("refuses other values for the switches and numbers", () => {
    expect(problems({ ...ENV, ALLOW_ACCOUNT_DELETION: "yes" })).toEqual(['ALLOW_ACCOUNT_DELETION must be "true" or "false"']);
    expect(problems({ ...ENV, AUDIT_RETENTION_DAYS: "0" })).toHaveLength(1);
    expect(problems({ ...ENV, ALERT_WEBHOOK_URL: "ftp://alerts.example.com" })).toEqual(["ALERT_WEBHOOK_URL must be an http(s) URL"]);
  });

  test("an alert webhook problem never echoes the URL, which can carry a token", () => {
    const found = problems({ ...ENV, ALERT_WEBHOOK_URL: "ftp://alerts.example.com/hooks/abc123" });
    expect(found.join("\n")).not.toContain("abc123");
  });

  test("the error message lists each problem on its own line", () => {
    expect(() => loadConfig({}, read(SERVICES))).toThrow("invalid configuration:\n  - DATABASE_URL is required");
  });

  test("a services file that can't be read is a problem, not a crash", () => {
    const found = (() => {
      try {
        loadConfig(ENV, () => {
          throw new Error("ENOENT");
        });
      } catch (e) {
        return (e as ConfigError).problems;
      }
      return [];
    })();
    expect(found).toEqual(['SERVICES_FILE "/services.json" can\'t be read']);
  });
});

describe("the services file (§6)", () => {
  const svc = (over: Record<string, unknown> = {}) => ({
    name: "wiki",
    roles: ["member", "admin"],
    mfa_roles: ["admin"],
    signup: "invite",
    clients: [{ id: "wiki", type: "confidential", redirect_uris: ["https://wiki.example.com/cb"] }],
    ...over,
  });
  const check = (...services: unknown[]) => problems(ENV, { services }).map((p) => p.replace(/^SERVICES_FILE: /, ""));

  test("accepts the design's example", () => {
    expect(load().services.get("wiki")?.mfaRoles).toEqual(["admin", "owner"]);
  });

  test("adds auth's own service, whose admin always needs MFA", () => {
    const auth = load().services.get("auth")!;
    expect(auth).toMatchObject({ roles: ["admin"], mfaRoles: ["admin"], signup: "closed", clients: [] });
  });

  test.each([
    ["not JSON", "{", ["the services file is not valid JSON"]],
    ["no services array", { service: [] }, ['the services file must be an object with a "services" array']],
  ])("refuses a file that is %s", (_, doc, expected) => {
    expect(problems(ENV, doc).map((p) => p.replace(/^SERVICES_FILE: /, ""))).toEqual(expected);
  });

  test.each([
    ["the reserved name", { name: "auth" }, 'service "auth": the name "auth" is reserved'],
    ["a bad name", { name: "Wiki" }, 'service "Wiki": name must match [a-z][a-z0-9-]{0,62}'],
    ["no mfa_roles", { mfa_roles: undefined }, 'service "wiki": mfa_roles must be an array of names'],
    ["an mfa role that isn't a role", { mfa_roles: ["root"] }, 'service "wiki": mfa_roles has "root", which is not one of roles'],
    ["empty roles", { roles: [], mfa_roles: [] }, 'service "wiki": roles must be a non-empty array of names'],
    ["a repeated role", { roles: ["member", "member"], mfa_roles: [] }, 'service "wiki": roles lists "member" twice'],
    ["an unknown signup", { signup: "public" }, 'service "wiki": signup must be "closed", "invite" or "open"'],
    ["open without default_role", { signup: "open" }, 'service "wiki": default_role must be one of roles when signup is open'],
    ["default_role when not open", { default_role: "member" }, 'service "wiki": default_role is only for signup "open"'],
    ["an unknown field", { mfa_role: [] }, 'service "wiki": unknown field "mfa_role"'],
    ["no clients", { clients: [] }, 'service "wiki": clients must be a non-empty array'],
    ["empty api_key_scopes", { api_key_scopes: [] }, 'service "wiki": api_key_scopes must be a non-empty array of names'],
    ["an events_url with credentials", { events_url: "https://u:p@wiki.internal/e" }, 'service "wiki": events_url must be an http(s) URL without credentials or a fragment'],
  ])("refuses a service with %s", (_, over, expected) => {
    expect(check(svc(over))).toEqual([expected]);
  });

  test.each([
    ["an http redirect off loopback", { redirect_uris: ["http://wiki.example.com/cb"] }],
    ["a fragment", { redirect_uris: ["https://wiki.example.com/cb#x"] }],
    ["a relative URI", { redirect_uris: ["/cb"] }],
    ["a private-use scheme on a confidential client", { redirect_uris: ["com.example.wiki:/cb"] }],
    ["a scheme without a dot", { type: "public", redirect_uris: ["wiki:/cb"] }],
    ["an unknown type", { type: "spa" }],
  ])("refuses a client with %s", (_, over) => {
    expect(check(svc({ clients: [{ id: "wiki", type: "confidential", redirect_uris: ["https://wiki.example.com/cb"], ...over }] }))).toHaveLength(1);
  });

  test("a refused redirect URI with credentials in it is named without them", () => {
    const found = check(svc({ clients: [{ id: "wiki", type: "confidential", redirect_uris: ["https://u:s3cret-pw@wiki.example.com/cb"] }] }));
    expect(found).toHaveLength(1);
    expect(found[0]).toContain("a URI with credentials");
    expect(found[0]).not.toContain("s3cret-pw");
  });

  test("accepts loopback http and a public client's private-use scheme", () => {
    const services = { services: [svc({ clients: [{ id: "w", type: "public", redirect_uris: ["http://127.0.0.1:8080/cb", "com.example.wiki:/cb"] }] })] };
    expect(load({}, services).services.client("w")?.redirectUris).toEqual(["http://127.0.0.1:8080/cb", "com.example.wiki:/cb"]);
  });

  test("client ids are unique across every service, and so are names", () => {
    expect(check(svc(), svc({ name: "other" }))).toEqual(['service "other": clients[0]: id "wiki" is used by another client']);
    expect(check(svc(), svc({ clients: [{ id: "x", type: "public", redirect_uris: ["https://x.example.com/"] }] }))).toEqual([
      'service "wiki": name is used by another service',
    ]);
  });

  test("form-action covers every redirect origin", () => {
    expect(load().services.formActionSources()).toEqual([
      "com.example.tasks:",
      "https://mail.example.com",
      "https://notes.example.com",
      "https://tasks.example.com",
      "https://wiki.example.com",
    ]);
  });
});
