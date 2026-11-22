import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { Certificates, enabled, PostgresFront, Stack, TEST_DATABASE_URL, waitFor, type Certificate, type ServerProcess } from "./harness";

// DATABASE_URL (docs/DEPLOYMENT.md §3): how a connection string is read, and
// TLS to Postgres. Both servers read it as the Bun server's SQL client does:
// which query keys are the client's, which go to Postgres as settings, how
// sslmode reads, the PG* variables it falls back on, and which certificates
// it accepts. A PostgresFront stands in for a Postgres that speaks TLS, in
// front of the test database, and records what each connection did.

setDefaultTimeout(30_000);

const SECRET = "s3cret-pw";
const NOT_READY = /^start: database not ready \(.+\), retrying$/;

describe.skipIf(!enabled)("DATABASE_URL", () => {
  let stack: Stack;
  let keys: unknown;
  let certs: Certificates;
  const db = new URL(TEST_DATABASE_URL ?? "postgres://localhost/");
  const local = db.hostname === "localhost" || db.hostname === "127.0.0.1";

  beforeAll(async () => {
    stack = await Stack.start();
    keys = await (await fetch(`${stack.url}/.well-known/jwks.json`)).json();
    certs = new Certificates(join(stack.dir, "certs"));
  });
  afterAll(async () => {
    await stack.stop();
  });

  // The test database's own address and the stack's schema, `query` after it.
  const direct = (query = "") => `postgres://${db.username}:${db.password}@${db.host}${db.pathname}?options=-c%20search_path%3D${stack.schema}${query ? `&${query}` : ""}`;

  // Starts a copy on `url` and waits until it serves the stack's own keys:
  // its start ran to the end, on the stack's schema. `meanwhile` runs while
  // it serves; the copy is stopped after.
  async function serves(url: string, env: Record<string, string | undefined> = {}, meanwhile?: (copy: ServerProcess) => Promise<void>): Promise<void> {
    const copy = await stack.spawn({ env: { DATABASE_URL: url, ...env } });
    try {
      const body = await waitFor(
        async () => {
          if (!copy.running) throw new Error(`the copy exited:\n${copy.logText()}`);
          if (copy.logs.some((l) => NOT_READY.test(l))) throw new Error(`the copy can't reach the database:\n${copy.logText()}`);
          const res = await fetch(`${copy.url}/.well-known/jwks.json`).catch(() => null);
          return res?.status === 200 && (await res.json());
        },
        "the copy to serve",
        20_000,
      );
      expect(body).toEqual(keys);
      await meanwhile?.(copy);
    } finally {
      await copy.stop();
    }
  }

  // Starts a copy on `url` and waits until it says it can't reach the
  // database: it keeps trying, and answers 503 meanwhile.
  async function cannotReach(url: string, env: Record<string, string | undefined> = {}): Promise<void> {
    const copy = await stack.spawn({ env: { DATABASE_URL: url, ...env } });
    try {
      await waitFor(
        () => {
          if (!copy.running) throw new Error(`the copy exited:\n${copy.logText()}`);
          return copy.logs.some((l) => NOT_READY.test(l));
        },
        "the copy to retry",
        20_000,
      );
      const health = await fetch(`${copy.url}/healthz`);
      expect(health.status).toBe(503);
      expect(await health.json()).toEqual({ error: "temporarily_unavailable", error_description: "The database is unreachable." });
      const page = await fetch(`${copy.url}/.well-known/openid-configuration`);
      expect(page.status).toBe(503);
      expect(await page.json()).toEqual({ error: "temporarily_unavailable", error_description: "Starting up." });
    } finally {
      await copy.stop();
    }
  }

  // A start refused for the URL alone, without echoing it.
  async function refused(url: string, env: Record<string, string | undefined> = {}): Promise<void> {
    const exit = await stack.exitOf({ DATABASE_URL: url, ...env }, { waitMs: 20_000 });
    expect(exit.stderr).toBe("invalid configuration:\n  - DATABASE_URL is not a well-formed URL\n");
    expect(exit.code).toBe(1);
    expect(exit.stdout + exit.stderr).not.toContain(SECRET);
  }

  const appNames = async (prefix: string) => (await stack.db`SELECT DISTINCT application_name AS name FROM pg_stat_activity WHERE application_name LIKE ${`${prefix}%`}`).map((r: { name: string }) => r.name);

  describe("what the URL says", () => {
    test.each([
      ["sslmode=disable"],
      ["sslmode="],
      ["sslmode"],
      ["sslmode=DISABLED"],
      ["ssl=false"],
      ["tls=0"],
      ["ssl="],
      ["sslrootcert="],
      // libpq's keywords for its own connection, read past
      ["keepalives=1&keepalives_idle=5&keepalives_interval=1&keepalives_count=3&tcp_user_timeout=9000&target_session_attrs=read-write&load_balance_hosts=random&fallback_application_name=x&sslnegotiation=direct&sslcompression=0&gssencmode=disable"],
      // the client's own options
      ["connect_timeout=10&idle_timeout=30&max_lifetime=60&max=abc&foundrows=1&prepare=false&channel_binding=disable"],
      ["connect_timeout=0x10&idle_timeout=-0&max_lifetime=2147483648"],
      ["channel_binding=prefer"],
      ["port=&host=&user=&password=&dbname="],
      ["#fragment"],
    ])("?%s reaches the database", async (query) => {
      await serves(query.startsWith("#") ? `${direct()}${query}` : direct(query));
    });

    test("the host, port, user, password and database can be query parameters, over the URL's own, in any case", async () => {
      const q = new URLSearchParams({ host: db.hostname, port: db.port || "5432", user: decodeURIComponent(db.username), password: decodeURIComponent(db.password), dbname: db.pathname.slice(1) });
      await serves(`postgres://nobody:${SECRET}@unreachable.invalid:1/nonexistent?options=-c%20search_path%3D${stack.schema}&${q}`);
      const upper = new URLSearchParams({ HOST: db.hostname, Port: db.port || "5432", USER: decodeURIComponent(db.username), Password: decodeURIComponent(db.password), DBNAME: db.pathname.slice(1) });
      await serves(`postgres://nobody:${SECRET}@unreachable.invalid:1/nonexistent?options=-c%20search_path%3D${stack.schema}&${upper}`);
    });

    test("a port is read as JavaScript reads a number", async () => {
      const port = Number(db.port || 5432);
      await serves(direct(`port=0x${port.toString(16)}`).replace(`:${port}/`, ":1/"));
      await serves(direct(`port=%20${port}.0%20`).replace(`:${port}/`, ":1/"));
    });

    test("every part of the URL may be percent-encoded", async () => {
      const every = (s: string) => [...Buffer.from(decodeURIComponent(s))].map((b) => `%${b.toString(16).padStart(2, "0")}`).join("");
      await serves(`postgres://${every(db.username)}:${every(db.password)}@${db.host}/${every(db.pathname.slice(1))}?options=-c%20search_path%3D${stack.schema}`);
    });

    test.skipIf(!local)("a URL with no host reaches localhost", async () => {
      await serves(`postgres://${db.username}:${db.password}@:${db.port || 5432}${db.pathname}?options=-c%20search_path%3D${stack.schema}`);
      await serves(`postgres://${db.username}:${db.password}@/${db.pathname.slice(1)}?options=-c%20search_path%3D${stack.schema}&port=${db.port || 5432}`);
    });

    test("PGHOST, PGPORT, PGUSER and PGPASSWORD stand in for what the URL leaves out", async () => {
      await serves(`postgres:///${db.pathname.slice(1)}?options=-c%20search_path%3D${stack.schema}`, {
        PGHOST: db.hostname,
        PGPORT: db.port || "5432",
        PGUSER: decodeURIComponent(db.username),
        PGPASSWORD: decodeURIComponent(db.password),
      });
      await serves(`postgres:///${db.pathname.slice(1)}?options=-c%20search_path%3D${stack.schema}`, {
        PG_HOST: db.hostname,
        PGHOST: "unreachable.invalid",
        PGPORT: db.port || "5432",
        PGUSERNAME: decodeURIComponent(db.username),
        PGUSER: "nobody",
        PG_PASSWORD: decodeURIComponent(db.password),
      });
    });

    test("PGDATABASE, and a database query parameter, win over the URL's path", async () => {
      await serves(direct().replace(`${db.host}${db.pathname}?`, `${db.host}/nonexistent?`), { PGDATABASE: db.pathname.slice(1) });
      await serves(direct(`dbname=nonexistent`), { PGDATABASE: db.pathname.slice(1) });
      // `database` isn't the client's: it goes to Postgres as a startup
      // parameter, after the client's own, and wins.
      await serves(direct(`database=${db.pathname.slice(1)}`).replace(`${db.host}${db.pathname}?`, `${db.host}/nonexistent?`));
    });

    test("a variable the URL also sets gives way to it", async () => {
      await serves(direct(), { PGHOST: "unreachable.invalid", PGPORT: "1", PGUSER: "nobody", PGPASSWORD: SECRET, PGCONNECT_TIMEOUT: "5", PGSSLMODE: "disable" });
    });

    test("application_name names the server's connections: repeated values joined by commas, + a space, a stray % kept", async () => {
      const name = `conf-${randomBytes(4).toString("hex")}`;
      await serves(direct(`application_name=${name}&application_name=b+c%zz`), {}, async () => {
        expect(await appNames(name)).toEqual([`${name},b c%zz`]);
      });
    });

    test("PGAPPNAME names them when the URL doesn't, and gives way when it does", async () => {
      const name = `conf-${randomBytes(4).toString("hex")}`;
      await serves(direct(), { PGAPPNAME: `${name}-env` }, async () => {
        expect(await appNames(name)).toEqual([`${name}-env`]);
      });
      await serves(direct(`application_name=${name}-url`), { PGAPPNAME: `${name}-env` }, async () => {
        expect(await appNames(name)).toEqual([`${name}-url`]);
      });
    });

    test("any other key is a setting for Postgres, over the same one in options, in any case", async () => {
      // Were the order or the name lost, the copy would look in a schema
      // that doesn't exist, and never start.
      const missing = `options=-c%20search_path%3Dnonexistent_${randomBytes(4).toString("hex")}`;
      const base = `postgres://${db.username}:${db.password}@${db.host}${db.pathname}`;
      await serves(`${base}?${missing}&search_path=${stack.schema}`);
      await serves(`${base}?search_path=${stack.schema}&${missing}`);
      await serves(`${base}?${missing}&Search_Path=${stack.schema}`);
    });

    test.each([["foo=bar"], ["gssencmode=require"], ["statement_timeout=nonsense"], ["channel_binding=require"]])("?%s starts, and can't reach the database", async (query) => {
      await cannotReach(direct(query));
    });

    test.each([
      ["an unknown sslmode", `sslmode=bogus`],
      ["sslmode=no-verify", `sslmode=no-verify`],
      ["a repeated sslmode", `sslmode=disable&sslmode=require`],
      ["an unknown ssl", `ssl=maybe`],
      ["an unknown tls", `tls=sometimes`],
      ["an unknown channel_binding", `channel_binding=sometimes`],
      ["channel_binding in capitals", `channel_binding=REQUIRE`],
      ["a negative connect_timeout", `connect_timeout=-1`],
      ["a connect_timeout that isn't a number", `connect_timeout=abc`],
      ["a connect_timeout past 2^31 seconds", `connect_timeout=2147483649`],
      ["a negative idle_timeout", `idle_timeout=-1`],
      ["an endless max_lifetime", `max_lifetime=Infinity`],
      ["a port of 0", `port=0`],
      ["a fractional port", `port=1.5`],
      ["a port past 65535", `port=70000`],
      ["a NUL in a setting", `application_name=a%00b`],
      ["a NUL in a setting's name", `a%00b=1`],
    ])("%s is refused, not echoed", async (_, query) => {
      await refused(`postgres://auth:${SECRET}@db.internal/auth?${query}`);
    });

    test.each([
      ["a bad escape in the password", `postgres://auth:${SECRET}%zz@db.internal/auth`],
      ["an escape that isn't UTF-8 in the password", `postgres://auth:${SECRET}%ff@db.internal/auth`],
      ["a bad escape in the user", `postgres://a%zz:${SECRET}@db.internal/auth`],
      ["a bad escape in the database", `postgres://auth:${SECRET}@db.internal/a%zz`],
      ["a bad escape in a socket's host", `postgres://auth:${SECRET}@%2F%zz/auth`],
      ["an IPv6 zone", `postgres://auth:${SECRET}@[fe80::1%25eth0]/auth`],
      ["two hosts", `postgres://auth:${SECRET}@a.internal:1,b.internal:2/auth`],
    ])("%s is refused, not echoed", async (_, url) => {
      await refused(url);
    });

    test("a bad escape the query's user stands in for is never read", async () => {
      const q = new URLSearchParams({ user: decodeURIComponent(db.username) });
      await serves(`postgres://a%zz:${db.password}@${db.host}${db.pathname}?options=-c%20search_path%3D${stack.schema}&${q}`);
    });

    test.each([
      ["PGSSLMODE", { PGSSLMODE: "bogus" }, ""],
      ["PGSSLMODE, though the URL sets sslmode", { PGSSLMODE: "bogus" }, "?sslmode=require"],
      ["PGCHANNELBINDING", { PGCHANNELBINDING: "always" }, ""],
      ["PGCONNECT_TIMEOUT", { PGCONNECT_TIMEOUT: "never" }, ""],
      ["PGPORT", { PGPORT: "abc" }, ""],
    ] as [string, Record<string, string>, string][])("an unusable %s refuses the start", async (_, env, query) => {
      await refused(`postgres://auth:${SECRET}@db.internal/auth${query}`, env);
    });
  });

  describe("TLS", () => {
    // Postgres's own documentation's certificate: self-signed, marked as a
    // CA, for localhost.
    let server: Certificate;
    let front: PostgresFront;
    let plain: PostgresFront;
    beforeAll(async () => {
      server = certs.selfSigned("/CN=localhost", { san: "DNS:localhost" });
      front = await PostgresFront.start(server);
      plain = await PostgresFront.start(null);
    });
    afterAll(async () => {
      await front.stop();
      await plain.stop();
    });

    // What the connections a copy made through `on` did.
    async function through(on: PostgresFront, run: () => Promise<void>): Promise<{ asked: boolean; tls: boolean; clientCert: string | null }[]> {
      const from = on.sessions.length;
      await run();
      return on.sessions.slice(from);
    }
    const none = (sessions: { tls: boolean; asked: boolean }[]) => sessions.length > 0 && sessions.every((s) => !s.asked && !s.tls);
    const encrypted = (sessions: { tls: boolean }[]) => sessions.length > 0 && sessions.every((s) => s.tls);

    test.each([[""], ["sslmode=disable"], ["ssl=0"]])("?%s never asks for TLS", async (query) => {
      expect(none(await through(front, () => serves(front.url(stack, query))))).toBe(true);
    });

    test.each([["sslmode=prefer"], ["sslmode=allow"], ["sslmode=preferred"]])("?%s takes TLS when offered, without checking the certificate, and goes on without", async (query) => {
      expect(encrypted(await through(front, () => serves(front.url(stack, query))))).toBe(true);
      const sessions = await through(plain, () => serves(plain.url(stack, query)));
      expect(sessions.length).toBeGreaterThan(0);
      expect(sessions.every((s) => s.asked && !s.tls)).toBe(true);
    });

    test.each([["sslmode=require"], ["sslmode=Required"], ["ssl=true"], ["tls=1"], ["ssl=require"], ["sslmode=prefer&ssl=true"]])("?%s insists on TLS without checking the certificate", async (query) => {
      expect(encrypted(await through(front, () => serves(front.url(stack, query))))).toBe(true);
      await cannotReach(plain.url(stack, query));
    });

    test("PGSSLMODE asks for TLS when the URL doesn't say, and gives way when it does", async () => {
      expect(encrypted(await through(front, () => serves(front.url(stack), { PGSSLMODE: "require" })))).toBe(true);
      expect(none(await through(front, () => serves(front.url(stack, "sslmode=disable"), { PGSSLMODE: "verify-full" })))).toBe(true);
    });

    test("verify-ca checks the certificate's chain, not its name", async () => {
      await cannotReach(front.url(stack, "sslmode=verify-ca", "localhost"));
      await serves(front.url(stack, `sslmode=verify-ca&sslrootcert=${server.cert}`));
      await serves(front.url(stack, `sslmode=verify_ca&sslrootcert=${server.cert}`, "localhost"));
    });

    test("verify-full checks its name too", async () => {
      await cannotReach(front.url(stack, `sslmode=verify-full&sslrootcert=${server.cert}`));
      expect(encrypted(await through(front, () => serves(front.url(stack, `sslmode=verify-full&sslrootcert=${server.cert}`, "localhost"))))).toBe(true);
      await serves(front.url(stack, `ssl_mode=verify_identity&sslrootcert=${server.cert}`, "localhost"));
      await serves(front.url(stack, `tls=verify-full&sslrootcert=${server.cert}`, "localhost"));
    });

    test("sslrootcert alone, or beside a weaker sslmode, means verify-full", async () => {
      for (const query of [`sslrootcert=${server.cert}`, `sslmode=require&sslrootcert=${server.cert}`, `sslmode=prefer&sslrootcert=${server.cert}`, `sslmode=disable&sslrootcert=${server.cert}`]) {
        await cannotReach(front.url(stack, query));
        expect(encrypted(await through(front, () => serves(front.url(stack, query, "localhost"))))).toBe(true);
      }
    });

    test("the usual roots include SSL_CERT_FILE and NODE_EXTRA_CA_CERTS", async () => {
      await serves(front.url(stack, "sslmode=verify-full", "localhost"), { SSL_CERT_FILE: server.cert });
      await serves(front.url(stack, "sslmode=verify-full", "localhost"), { NODE_EXTRA_CA_CERTS: server.cert });
      await cannotReach(front.url(stack, "sslmode=verify-full", "localhost"));
    });

    test("sslrootcert=system checks against the usual roots", async () => {
      await cannotReach(front.url(stack, "sslmode=require&sslrootcert=system", "localhost"));
      await serves(front.url(stack, "sslmode=require&sslrootcert=system", "localhost"), { SSL_CERT_FILE: server.cert });
    });

    test("an sslrootcert file is the only root trusted", async () => {
      const other = certs.selfSigned("/CN=localhost", { san: "DNS:localhost" });
      await cannotReach(front.url(stack, `sslmode=verify-full&sslrootcert=${other.cert}`, "localhost"), { SSL_CERT_FILE: server.cert, NODE_EXTRA_CA_CERTS: server.cert });
    });

    test("an sslrootcert that can't be read fails the connection, not the start", async () => {
      await cannotReach(front.url(stack, `sslmode=require&sslrootcert=${join(stack.dir, "missing.pem")}`, "localhost"));
    });

    describe("certificates", () => {
      // [what, how it's made, the host, the root, verify-full, verify-ca]
      const cases: [string, () => [Certificate, string], string, boolean, boolean][] = [
        ["self-signed, marked as a CA, its name a DNS name", () => [certs.selfSigned("/CN=other.internal", { san: "DNS:localhost" }), "self"], "localhost", true, true],
        ["self-signed, not marked as a CA", () => [certs.selfSigned("/CN=localhost", { san: "DNS:localhost", ca: false }), "self"], "localhost", true, true],
        ["self-signed, its name only its common name", () => [certs.selfSigned("/CN=localhost"), "self"], "localhost", true, true],
        ["self-signed, another common name", () => [certs.selfSigned("/CN=other.internal"), "self"], "localhost", false, true],
        ["self-signed, the address as a name", () => [certs.selfSigned("/CN=x", { san: "IP:127.0.0.1" }), "self"], "127.0.0.1", true, true],
        ["self-signed, the address as its common name", () => [certs.selfSigned("/CN=127.0.0.1"), "self"], "127.0.0.1", false, true],
        ["self-signed, a wildcard one label too short", () => [certs.selfSigned("/CN=x", { san: "DNS:*.localhost" }), "self"], "localhost", false, true],
        ["self-signed, a DNS name beside a matching common name", () => [certs.selfSigned("/CN=localhost", { san: "DNS:other.internal" }), "self"], "localhost", false, true],
        ["issued by the root", () => [certs.issued("/CN=other.internal", { san: "DNS:localhost" }), "ca"], "localhost", true, true],
        ["issued, its name only its common name", () => [certs.issued("/CN=localhost"), "ca"], "localhost", true, true],
        ["issued, expired", () => [certs.issued("/CN=localhost", { san: "DNS:localhost", expired: true }), "ca"], "localhost", false, false],
        ["issued, but only itself trusted", () => [certs.issued("/CN=localhost", { san: "DNS:localhost" }), "self"], "localhost", false, false],
      ];
      test.each(cases)("%s", async (_, make, host, full, ca) => {
        const [cert, root] = make();
        const rootFile = root === "self" ? cert.cert : certs.ca.cert;
        const on = await PostgresFront.start(cert);
        try {
          for (const [mode, expected] of [
            ["verify-full", full],
            ["verify-ca", ca],
          ] as const) {
            const url = on.url(stack, `sslmode=${mode}&sslrootcert=${rootFile}`, host);
            if (expected) await serves(url);
            else await cannotReach(url);
          }
        } finally {
          await on.stop();
        }
      });
    });

    test("a client certificate is shown when both it and its key are named", async () => {
      const client = certs.selfSigned("/CN=auth-client");
      const shown = await through(front, () => serves(front.url(stack, `sslmode=require&sslcert=${client.cert}&sslkey=${client.key}`)));
      expect(shown.length).toBeGreaterThan(0);
      expect(shown.every((s) => s.tls && s.clientCert === "auth-client")).toBe(true);
      const certOnly = await through(front, () => serves(front.url(stack, `sslmode=require&sslcert=${client.cert}`)));
      expect(encrypted(certOnly) && certOnly.every((s) => s.clientCert === null)).toBe(true);
      // Naming them asks for TLS.
      const noSslmode = await through(front, () => serves(front.url(stack, `sslcert=${client.cert}&sslkey=${client.key}`)));
      expect(noSslmode.length > 0 && noSslmode.every((s) => s.tls && s.clientCert === "auth-client")).toBe(true);
    });
  });
});
