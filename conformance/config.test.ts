import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { randomBytes } from "node:crypto";
import { Browser, enabled, freePort, Stack, type Exit, type ServerProcess, type TestUser } from "./harness";

// The configuration (docs/DESIGN.md §11, docs/DEPLOYMENT.md §3): every
// variable the server reads at start, what it refuses and with what words,
// and what an accepted value does, observed from outside. Also the client
// address of §9.4 (X-Real-IP from a trusted proxy), which TRUSTED_PROXIES
// configures.

setDefaultTimeout(30_000);

const SECRET = "s3cret-pw";
const key = (fill: number) => Buffer.alloc(32, fill).toString("base64");

// A Browser that talks to another copy of the server on the same database:
// the same issuer (so Origin and CSRF hold), another address.
function browserOn(stack: Stack, copy: ServerProcess, ip?: string | null): Browser {
  const view = Object.create(stack) as Stack;
  Object.defineProperty(view, "url", { value: copy.url });
  return new Browser(view, ip);
}

function expectRefused(exit: Exit, problems: string[]): void {
  expect(exit.stderr).toBe(`invalid configuration:\n${problems.map((p) => `  - ${p}`).join("\n")}\n`);
  expect(exit.code).toBe(1);
}

describe.skipIf(!enabled)("configuration", () => {
  let stack: Stack;
  beforeAll(async () => {
    stack = await Stack.start();
  });
  afterAll(async () => {
    await stack.stop();
  });
  beforeEach(async () => {
    await stack.resetLimits();
  });

  const refused = async (env: Record<string, string | undefined>, problems: string[], opts: { services?: unknown } = {}) => {
    const exit = await stack.exitOf(env, { ...opts, waitMs: 20_000 });
    expectRefused(exit, problems);
    expect(exit.stdout + exit.stderr).not.toContain(SECRET);
    return exit;
  };

  // Starts a copy with a changed environment and waits until it is healthy.
  const started = async (env: Record<string, string | undefined>, services?: unknown): Promise<ServerProcess> => {
    const copy = await stack.spawn({ env, services });
    await copy.ready();
    return copy;
  };

  describe("refusals", () => {
    test("every problem is listed at once, in the order of the variables, and the start exits 1", async () => {
      await refused(
        {
          PORT: "http",
          DATABASE_URL: undefined,
          ISSUER_URL: undefined,
          AUTH_ENCRYPTION_KEY: undefined,
          SMTP_URL: undefined,
          EMAIL_FROM: undefined,
        },
        [
          'PORT must be a whole number from 1 to 65535, not "http"',
          "DATABASE_URL is required",
          "ISSUER_URL is required",
          "AUTH_ENCRYPTION_KEY is required",
          "SMTP_URL is required",
          "EMAIL_FROM is required",
        ],
      );
    });

    test("one problem of each variable, all at once", async () => {
      await refused(
        {
          PORT: "0",
          DATABASE_URL: `mysql://auth:${SECRET}@db.internal/auth`,
          ISSUER_URL: `https://admin:${SECRET}@auth.example.com`,
          SERVICES_FILE: "/nonexistent/services.json",
          AUTH_ENCRYPTION_KEY: SECRET,
          AUTH_DECRYPTION_KEYS: SECRET,
          API_KEY_PREFIX: "Bad_Prefix",
          TRUSTED_PROXIES: "proxy.internal",
          SMTP_URL: `http://user:${SECRET}@mail.example.com`,
          EMAIL_FROM: "nobody",
          AUDIT_RETENTION_DAYS: "0",
          ALLOW_ACCOUNT_DELETION: "yes",
          ALERT_WEBHOOK_URL: `ftp://alerts.example.com/${SECRET}`,
          BREACHED_PASSWORDS_URL: `https://user:${SECRET}@pwned.example.com/range`,
        },
        [
          'PORT must be a whole number from 1 to 65535, not "0"',
          "DATABASE_URL must be a postgres:// or postgresql:// URL",
          "ISSUER_URL must be an https origin with no path or trailing slash (http only for a loopback host)",
          'SERVICES_FILE "/nonexistent/services.json" can\'t be read',
          "AUTH_ENCRYPTION_KEY must be 32 bytes, base64-encoded (openssl rand -base64 32), optionally as v<N>:<base64>",
          "AUTH_DECRYPTION_KEYS entry 1 must be v<N>:<32 bytes, base64>",
          "API_KEY_PREFIX must match [a-z][a-z0-9]{1,15}",
          'TRUSTED_PROXIES has "proxy.internal", which is not an IP address or CIDR range',
          "SMTP_URL must be smtps://[user:password@]host[:port], or smtp:// (STARTTLS, or plain only to a loopback host)",
          'EMAIL_FROM must be an address, or "Name <address>"',
          'AUDIT_RETENTION_DAYS must be a whole number of days from 1 to 36500, not "0"',
          'ALLOW_ACCOUNT_DELETION must be "true" or "false"',
          "ALERT_WEBHOOK_URL must be an http(s) URL",
          "BREACHED_PASSWORDS_URL must be an http(s) URL without credentials, a query or a fragment",
        ],
      );
    });

    test.each(["0", "65536", "99999", "-1", "3e3", "80.5", "0x50", "http", "+80"])("PORT=%p is refused, echoed", async (port) => {
      await refused({ PORT: port }, [`PORT must be a whole number from 1 to 65535, not "${port}"`]);
    });

    test("PORT is echoed as trimmed", async () => {
      await refused({ PORT: "  70000 " }, ['PORT must be a whole number from 1 to 65535, not "70000"']);
    });

    describe("DATABASE_URL", () => {
      test.each([
        ["unset", undefined],
        ["empty", ""],
        ["whitespace only", "  \t "],
      ])("%s is required", async (_, value) => {
        await refused({ DATABASE_URL: value }, ["DATABASE_URL is required"]);
      });

      test.each([`mysql://auth:${SECRET}@db.internal/auth`, `http://auth:${SECRET}@db.internal/auth`, `db.internal/auth?password=${SECRET}`, `postgres:/auth:${SECRET}@db.internal`])(
        "%p has the wrong scheme, not echoed",
        async (url) => {
          await refused({ DATABASE_URL: url }, ["DATABASE_URL must be a postgres:// or postgresql:// URL"]);
        },
      );

      test.each([`postgres://auth:${SECRET}@db.internal:notaport/auth`, `postgresql://auth:${SECRET}@db.internal:99999/auth`])("%p is malformed, not echoed", async (url) => {
        await refused({ DATABASE_URL: url }, ["DATABASE_URL is not a well-formed URL"]);
      });
    });

    describe("ISSUER_URL", () => {
      const MESSAGE = "ISSUER_URL must be an https origin with no path or trailing slash (http only for a loopback host)";

      test.each([
        ["unset", undefined],
        ["empty", ""],
        ["whitespace only", "   "],
      ])("%s is required", async (_, value) => {
        await refused({ ISSUER_URL: value }, ["ISSUER_URL is required"]);
      });

      test.each([
        ["http on a non-loopback host", "http://auth.example.com"],
        ["http on another loopback-looking host", "http://127.0.0.2:3000"],
        ["a path", "https://auth.example.com/auth"],
        ["a trailing slash", "https://auth.example.com/"],
        ["a trailing slash on loopback", "http://127.0.0.1:3000/"],
        ["a query", "https://auth.example.com?x=1"],
        ["a fragment", "https://auth.example.com#top"],
        ["credentials", `https://admin:${SECRET}@auth.example.com`],
        ["a user only", `https://${SECRET}@auth.example.com`],
        ["no scheme", "auth.example.com"],
        ["another scheme", "ftp://auth.example.com"],
        ["another variable's value", `postgres://auth:${SECRET}@db.internal:5432/auth`],
      ])("%s is refused, not echoed", async (_, value) => {
        await refused({ ISSUER_URL: value }, [MESSAGE]);
      });
    });

    test("an unreadable SERVICES_FILE is named", async () => {
      await refused({ SERVICES_FILE: "/nonexistent/services.json" }, ['SERVICES_FILE "/nonexistent/services.json" can\'t be read']);
      await refused({ SERVICES_FILE: stack.dir }, [`SERVICES_FILE "${stack.dir}" can't be read`]);
    });

    test("a services file that isn't JSON is a problem of SERVICES_FILE", async () => {
      await refused({}, ["SERVICES_FILE: the services file is not valid JSON"], { services: "{" });
    });

    describe("AUTH_ENCRYPTION_KEY", () => {
      const MESSAGE = "AUTH_ENCRYPTION_KEY must be 32 bytes, base64-encoded (openssl rand -base64 32), optionally as v<N>:<base64>";

      test.each([
        ["unset", undefined],
        ["empty", ""],
        ["whitespace only", " "],
      ])("%s is required", async (_, value) => {
        await refused({ AUTH_ENCRYPTION_KEY: value }, ["AUTH_ENCRYPTION_KEY is required"]);
      });

      test.each([
        ["a short value", SECRET],
        ["a versioned short value", `v1:${SECRET}`],
        ["31 bytes", Buffer.alloc(31, 1).toString("base64")],
        ["33 bytes", Buffer.alloc(33, 1).toString("base64")],
        ["characters outside base64", `${key(1).slice(0, -2)}!=`],
        ["a space inside", `${key(1).slice(0, 10)} ${key(1).slice(10)}`],
        ["version 0", `v0:${key(1)}`],
        ["a five-digit version", `v10000:${key(1)}`],
        ["a version without its number", `v:${key(1)}`],
        ["another prefix", `k1:${key(1)}`],
        ["three padding characters", `${key(1)}==`],
      ])("%s is refused, not echoed", async (_, value) => {
        const exit = await refused({ AUTH_ENCRYPTION_KEY: value }, [MESSAGE]);
        expect(exit.stderr).not.toContain(value);
      });
    });

    describe("AUTH_DECRYPTION_KEYS", () => {
      test.each([
        ["an entry without a version", key(2), "AUTH_DECRYPTION_KEYS entry 1 must be v<N>:<32 bytes, base64>"],
        ["a short key", `v2:${SECRET}`, "AUTH_DECRYPTION_KEYS entry 1 must be v<N>:<32 bytes, base64>"],
        ["version 0", `v0:${key(2)}`, "AUTH_DECRYPTION_KEYS entry 1 must be v<N>:<32 bytes, base64>"],
        ["the current key's version", `v1:${key(2)}`, "AUTH_DECRYPTION_KEYS entry 1 has version 1, which another key already has"],
      ])("%s is refused, not echoed", async (_, value, message) => {
        const exit = await refused({ AUTH_DECRYPTION_KEYS: value }, [message]);
        expect(exit.stderr).not.toContain(value);
      });

      test("duplicate versions name the later entry", async () => {
        await refused({ AUTH_DECRYPTION_KEYS: `v2:${key(2)},v2:${key(3)}` }, ["AUTH_DECRYPTION_KEYS entry 2 has version 2, which another key already has"]);
      });

      test("the current key's version, when it is versioned", async () => {
        await refused({ AUTH_ENCRYPTION_KEY: `v3:${key(1)}`, AUTH_DECRYPTION_KEYS: `v1:${key(2)},v3:${key(4)}` }, [
          "AUTH_DECRYPTION_KEYS entry 2 has version 3, which another key already has",
        ]);
      });

      test("blank entries are skipped when entries are numbered, and every bad entry is listed", async () => {
        await refused({ AUTH_DECRYPTION_KEYS: ` , v2:${key(2)} , , nope, v2:${key(5)}, ${SECRET}` }, [
          "AUTH_DECRYPTION_KEYS entry 2 must be v<N>:<32 bytes, base64>",
          "AUTH_DECRYPTION_KEYS entry 3 has version 2, which another key already has",
          "AUTH_DECRYPTION_KEYS entry 4 must be v<N>:<32 bytes, base64>",
        ]);
      });
    });

    describe("API_KEY_PREFIX", () => {
      test.each(["Bad_Prefix", "a", "1abc", "ab-c", "abcdefghijklmnopq", "ABC"])("%p doesn't match the pattern", async (prefix) => {
        await refused({ API_KEY_PREFIX: prefix }, ["API_KEY_PREFIX must match [a-z][a-z0-9]{1,15}"]);
      });

      test.each([
        ["unset", undefined],
        ["empty", ""],
        ["whitespace only", "  "],
      ])("%s is refused when the services file declares api_key_scopes", async (_, value) => {
        await refused({ API_KEY_PREFIX: value }, ["API_KEY_PREFIX is required when a service declares api_key_scopes"]);
      });
    });

    test.each([
      ["proxy.internal", ["proxy.internal"]],
      ["10.0.0.0/33", ["10.0.0.0/33"]],
      ["::1/129", ["::1/129"]],
      ["10.0.0.0/8/1", ["10.0.0.0/8/1"]],
      ["10.0.0.0/", ["10.0.0.0/"]],
      ["/8", ["/8"]],
      ["10.0.0.0/x", ["10.0.0.0/x"]],
      ["10.0.0.0/-1", ["10.0.0.0/-1"]],
      ["256.0.0.1", ["256.0.0.1"]],
      ["1:2:3:4:5:6:7:8:9", ["1:2:3:4:5:6:7:8:9"]],
      ["10.0.0.0/8, proxy.internal , ::1, nope", ["proxy.internal", "nope"]],
    ])("TRUSTED_PROXIES=%p names each bad entry", async (value, bad) => {
      await refused(
        { TRUSTED_PROXIES: value },
        bad.map((b) => `TRUSTED_PROXIES has "${b}", which is not an IP address or CIDR range`),
      );
    });

    describe("SMTP_URL", () => {
      const MESSAGE = "SMTP_URL must be smtps://[user:password@]host[:port], or smtp:// (STARTTLS, or plain only to a loopback host)";

      test.each([
        ["unset", undefined],
        ["whitespace only", "  "],
      ])("%s is required", async (_, value) => {
        await refused({ SMTP_URL: value }, ["SMTP_URL is required"]);
      });

      test.each([
        ["not a URL", `${SECRET} mail.example.com`],
        ["another scheme", `http://user:${SECRET}@mail.example.com`],
        ["a path", `smtp://user:${SECRET}@mail.example.com/path`],
        ["a query", `smtp://user:${SECRET}@mail.example.com?x=1`],
        ["a fragment", `smtp://user:${SECRET}@mail.example.com#x`],
        ["no host", `smtp://user:${SECRET}@`],
        ["a host that isn't a host name", `smtp://user:${SECRET}@mail_server.example.com`],
        ["port 0", `smtps://user:${SECRET}@mail.example.com:0`],
        ["a port out of range", `smtps://user:${SECRET}@mail.example.com:70000`],
        ["a user without a password", "smtps://user@mail.example.com"],
        ["a password without a user", `smtps://:${SECRET}@mail.example.com`],
        ["a malformed percent-escape", `smtps://user:${SECRET}%zz@mail.example.com`],
        ["a NUL in the password", `smtps://user:${SECRET}%00@mail.example.com`],
        ["a NUL in the user", `smtps://us%00er:${SECRET}@mail.example.com`],
      ])("%s is refused, not echoed", async (_, value) => {
        await refused({ SMTP_URL: value }, [MESSAGE]);
      });
    });

    describe("EMAIL_FROM", () => {
      const MESSAGE = 'EMAIL_FROM must be an address, or "Name <address>"';

      test.each([
        ["unset", undefined],
        ["whitespace only", "   "],
      ])("%s is required", async (_, value) => {
        await refused({ EMAIL_FROM: value }, ["EMAIL_FROM is required"]);
      });

      test.each([
        ["not an address", "auth"],
        ["a name and no address", "Auth <>"],
        ["a domain without a dot", "Auth <auth@localhost>"],
        ["two @", "auth@@example.com"],
        ["a quoted local part", '"a b"@example.com'],
        ["an address literal", "auth@[127.0.0.1]"],
        ["a control character in the name", "Au\u0001th <auth@example.com>"],
        ["a tab in the name", "Au\tth <auth@example.com>"],
        ["a name without brackets", "Auth auth@example.com"],
      ])("%s is refused", async (_, value) => {
        await refused({ EMAIL_FROM: value }, [MESSAGE]);
      });
    });

    test.each(["0", "36501", "-1", "1.5", "a year", "1e2"])("AUDIT_RETENTION_DAYS=%p is refused, echoed", async (value) => {
      await refused({ AUDIT_RETENTION_DAYS: value }, [`AUDIT_RETENTION_DAYS must be a whole number of days from 1 to 36500, not "${value}"`]);
    });

    test.each(["yes", "TRUE", "1", "False", "on"])("ALLOW_ACCOUNT_DELETION=%p is refused", async (value) => {
      await refused({ ALLOW_ACCOUNT_DELETION: value }, ['ALLOW_ACCOUNT_DELETION must be "true" or "false"']);
    });

    test.each([`ftp://alerts.example.com/hooks/${SECRET}`, `alerts.example.com/hooks/${SECRET}`, `not a url ${SECRET}`, `mailto:${SECRET}@example.com`])(
      "ALERT_WEBHOOK_URL=%p is refused, not echoed",
      async (value) => {
        await refused({ ALERT_WEBHOOK_URL: value }, ["ALERT_WEBHOOK_URL must be an http(s) URL"]);
      },
    );

    test.each([
      "ftp://pwned.example.com/range",
      "pwned.example.com/range",
      `https://user:${SECRET}@pwned.example.com/range`,
      `https://${SECRET}@pwned.example.com/range`,
      `https://pwned.example.com/range?key=${SECRET}`,
      "https://pwned.example.com/range?",
      `https://pwned.example.com/range#${SECRET}`,
    ])("BREACHED_PASSWORDS_URL=%p is refused, not echoed", async (value) => {
      await refused({ BREACHED_PASSWORDS_URL: value }, ["BREACHED_PASSWORDS_URL must be an http(s) URL without credentials, a query or a fragment"]);
    });
  });

  describe("accepted configurations", () => {
    test("PORT, trimmed, is where the server listens", async () => {
      const port = await freePort();
      const copy = await started({ PORT: ` ${port} ` });
      expect(copy.logs).toContain(`listening on :${port}`);
      expect((await fetch(`http://127.0.0.1:${port}/healthz`)).status).toBe(200);
      await copy.stop();
    });

    test.each([
      ["a loopback name", "http://localhost:3000", "http://localhost:3000"],
      ["a loopback IPv4 address", "http://127.0.0.1:4000", "http://127.0.0.1:4000"],
      ["the IPv6 loopback address", "http://[::1]:3000", "http://[::1]:3000"],
      ["an https origin", "https://auth.example.com", "https://auth.example.com"],
      ["an https origin with a port", "https://auth.example.com:8443", "https://auth.example.com:8443"],
      ["surrounding whitespace", "  https://auth.example.com  ", "https://auth.example.com"],
    ])("ISSUER_URL as %s is the issuer", async (_, value, issuer) => {
      const copy = await started({ ISSUER_URL: value });
      const discovery = (await (await fetch(`${copy.url}/.well-known/openid-configuration`)).json()) as { issuer: string };
      expect(discovery.issuer).toBe(issuer);
      await copy.stop();
    });

    test.each([
      ["true", true],
      ["false", false],
      [" true ", true],
      ["  ", false],
      [undefined, false],
    ])("ALLOW_ACCOUNT_DELETION=%p is GET /v1/me's account_deletion", async (value, expected) => {
      const copy = await started({ ALLOW_ACCOUNT_DELETION: value });
      const user = await stack.user({ username: `del-${randomBytes(3).toString("hex")}` });
      const session = await stack.session(user);
      const res = await session.get(`${copy.url}/v1/me`);
      expect(res.status).toBe(200);
      expect(((await res.json()) as { account_deletion: boolean }).account_deletion).toBe(expected);
      await copy.stop();
    });

    test("API_KEY_PREFIX may be unset when no service declares api_key_scopes", async () => {
      const services = { services: (stack.servicesFile as { services: any[] }).services.filter((s) => s.api_key_scopes === undefined) };
      const copy = await started({ API_KEY_PREFIX: undefined }, services);
      expect((await fetch(`${copy.url}/healthz`)).status).toBe(200);
      await copy.stop();
    });

    test.each([
      ["a plain address", "auth@example.com", "auth@example.com"],
      ["a name and an address", "Example Auth <auth@example.com>", "Example Auth <auth@example.com>"],
      ["a quoted name", '"Auth, Example" <auth@example.com>', '"Auth, Example" <auth@example.com>'],
      ["a quoted name that needs no quotes", '"Auth" <auth@example.com>', "Auth <auth@example.com>"],
      ["a name with an escaped quote", '"Auth \\"Main\\"" <auth@example.com>', '"Auth \\"Main\\"" <auth@example.com>'],
      ["a name with a period", "Example Inc. <auth@example.com>", '"Example Inc." <auth@example.com>'],
      ["a non-ASCII name", "Authentifizierungsdienst Müller <auth@example.com>", null],
    ])("EMAIL_FROM as %s is the From header", async (_, value, header) => {
      const copy = await started({ EMAIL_FROM: value });
      const user = await stack.user({ username: `from-${randomBytes(3).toString("hex")}` });
      const session = await stack.session(user);
      const to = `${user.username}-new@example.com`;
      const res = await session.api("PATCH", `${copy.url}/v1/me`, { email: to });
      expect(res.status).toBe(200);
      const mail = await stack.smtp.waitFor(to);
      expect(mail.from).toBe("auth@example.com");
      expect(mail.helo).toBe("example.com");
      if (header !== null) expect(mail.headers.from).toBe(header);
      else {
        // RFC 2047: encoded words, then the address.
        expect(mail.raw).toMatch(/^From: =\?UTF-8\?B\?[A-Za-z0-9+/=]+\?=(?:\r\n =\?UTF-8\?B\?[A-Za-z0-9+/=]+\?=)* <auth@example\.com>\r\n/m);
        const words = [...mail.headers.from!.matchAll(/=\?UTF-8\?B\?([^?]*)\?=/g)].map((m) => Buffer.from(m[1]!, "base64"));
        expect(Buffer.concat(words).toString("utf8")).toBe("Authentifizierungsdienst Müller");
      }
      await copy.stop();
    });

    test("a versioned AUTH_ENCRYPTION_KEY with the old key in AUTH_DECRYPTION_KEYS reads what version 1 wrote", async () => {
      // The stack's key is bare, so a TOTP secret it writes is under v1.
      const user = await stack.user({ username: `rot-${randomBytes(3).toString("hex")}`, totp: true });
      const [row] = await stack.db`SELECT secret_enc FROM totp WHERE user_id = ${user.id}`;
      expect(Buffer.from(row.secret_enc).subarray(0, 3).toString()).toBe("v1:");
      const copy = await started({ AUTH_ENCRYPTION_KEY: `v2:${key(9)}`, AUTH_DECRYPTION_KEYS: `v1:${stack.env.AUTH_ENCRYPTION_KEY}` });
      const browser = browserOn(stack, copy);
      const res = await browser.signIn(user.username, user.password!, await stack.code(user));
      expect(res.status).toBe(303);
      expect(res.headers.get("Location")).toBe("/account");
      const ok = (await stack.audit("login.ok")).filter((a) => a.user_id === user.id);
      expect(ok).toHaveLength(1);
      expect(ok[0]!.detail.amr).toEqual(["pwd", "otp", "mfa"]);
      await copy.stop();
    });

    test("BREACHED_PASSWORDS_URL with a trailing slash is asked without a doubled slash", async () => {
      const copy = await started({ BREACHED_PASSWORDS_URL: `${stack.http.url}/range//` });
      const user = await stack.user({ username: `pw-${randomBytes(3).toString("hex")}` });
      const session = await stack.session(user);
      const before = stack.http.rangeRequests.length;
      const res = await session.api("POST", `${copy.url}/v1/me/password`, { current: user.password, new: "password1234" });
      expect(res.status).toBe(400);
      const requests = stack.http.rangeRequests.slice(before);
      expect(requests).toHaveLength(1);
      expect(requests[0]!.path).toMatch(/^\/range\/[0-9A-F]{5}$/);
      await copy.stop();
    });

    test("a registered service that declares api_key_scopes needs API_KEY_PREFIX, named in the refusal", async () => {
      const other = await Stack.start({ services: null });
      try {
        await other.db`
          INSERT INTO services (name, roles, mfa_roles, signup, api_key_scopes, created_by)
          VALUES ('notes', '{reader}', '{}', 'closed', '{notes:read}', 'host-cli'),
                 ('tasks', '{user}', '{}', 'closed', '{tasks:read}', 'host-cli'),
                 ('wiki', '{member}', '{}', 'closed', '{}', 'host-cli')`;
        const exit = await other.exitOf({ API_KEY_PREFIX: undefined }, { waitMs: 20_000 });
        expectRefused(exit, [
          "API_KEY_PREFIX is required: the registered service notes declares api_key_scopes",
          "API_KEY_PREFIX is required: the registered service tasks declares api_key_scopes",
        ]);
        // With the prefix, the same database starts.
        const copy = await other.spawn();
        await copy.ready();
        await copy.stop();
      } finally {
        await other.stop();
      }
    });
  });

  describe("the client address (§9.4)", () => {
    // A failed sign-in to a fresh account through `copy`, and the address its audit row records.
    const recorded = async (copy: ServerProcess | null, realIp: string | null): Promise<string | null> => {
      const user: TestUser = await stack.user({ username: `ip-${randomBytes(4).toString("hex")}` });
      const browser = copy ? browserOn(stack, copy, null) : stack.browser(null);
      const headers: Record<string, string> = realIp === null ? {} : { "X-Real-IP": realIp };
      const res = await browser.form("/login", { login: user.username, password: "wrong password" }, { headers });
      expect(res.status).toBe(401);
      await res.body?.cancel();
      const rows = (await stack.audit("login.fail")).filter((a) => a.user_id === user.id);
      expect(rows).toHaveLength(1);
      return rows[0]!.ip;
    };

    test.each([
      ["an IPv4 address", "203.0.113.7", "203.0.113.7"],
      ["an IPv6 address", "2001:db8::7", "2001:db8::7"],
      ["a long IPv6 form", "2001:0db8:0000:0000:0000:0000:0000:0007", "2001:db8::7"],
      ["upper-case IPv6", "2001:DB8::A", "2001:db8::a"],
      ["a bracketed IPv6 address", "[2001:db8::8]", "2001:db8::8"],
      ["an IPv6 address with a zone", "fe80::1%eth0", "fe80::1"],
      ["an IPv4-mapped address", "::ffff:198.51.100.4", "198.51.100.4"],
      ["an upper-case IPv4-mapped address", "::FFFF:198.51.100.5", "198.51.100.5"],
      ["an unparseable value", "not-an-address", "127.0.0.1"],
      ["a list", "203.0.113.1, 203.0.113.2", "127.0.0.1"],
      ["an IPv4 address out of range", "203.0.113.256", "127.0.0.1"],
    ])("from a trusted proxy, X-Real-IP as %s is the client", async (_, realIp, ip) => {
      expect(await recorded(null, realIp)).toBe(ip);
    });

    test("without X-Real-IP, the peer is the client", async () => {
      expect(await recorded(null, null)).toBe("127.0.0.1");
    });

    test.each([
      ["unset", undefined, "127.0.0.1"],
      ["another range", "10.0.0.0/8, 192.0.2.1", "127.0.0.1"],
      ["another IPv6 range", "2001:db8::/32", "127.0.0.1"],
      ["a CIDR range holding the peer", "127.0.0.0/8", "203.0.113.9"],
      ["a /32 among others", "10.0.0.0/8, 127.0.0.1/32", "203.0.113.9"],
      ["a range on an odd bit boundary", "127.0.0.0/9", "203.0.113.9"],
      ["the IPv4-mapped form of the peer", "::ffff:127.0.0.1", "203.0.113.9"],
      ["every address", "0.0.0.0/0", "203.0.113.9"],
    ])("TRUSTED_PROXIES %s: X-Real-IP from 127.0.0.1 gives %p", async (_, proxies, ip) => {
      const copy = await started({ TRUSTED_PROXIES: proxies });
      expect(await recorded(copy, "203.0.113.9")).toBe(ip);
      await copy.stop();
    });
  });
});
