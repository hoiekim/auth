import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import net from "node:net";
import { API_CSP, enabled, rawRequest, rawStatus, SECURITY_HEADERS, Stack, waitFor } from "./harness";

// The server as a process (docs/DESIGN.md §9.2, §9.3, §11): its health check,
// the headers and error shape of every response, what it logs, and how it
// starts and stops.

// Starting a server takes longer than a test's default five seconds on a busy machine.
setDefaultTimeout(30_000);

const raw = rawRequest;
const statusOf = rawStatus;

describe.skipIf(!enabled)("the server process", () => {
  let stack: Stack;
  beforeAll(async () => {
    stack = await Stack.start();
  });
  afterAll(async () => {
    await stack.stop();
  });

  describe("GET /healthz", () => {
    test("answers 200 once the schema and a signing key are in place", async () => {
      const res = await fetch(`${stack.url}/healthz`);
      expect(res.status).toBe(200);
      expect(res.headers.get("Content-Type")).toBe("application/json");
      expect(await res.json()).toEqual({ status: "ok" });
    });

    test("is not logged when it answers 200", async () => {
      const before = stack.logs.length;
      await fetch(`${stack.url}/healthz`);
      await fetch(`${stack.url}/nope`);
      await Bun.sleep(50);
      expect(stack.logs.slice(before).filter((l) => l.includes("healthz"))).toEqual([]);
    });

    test.each(["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "PURGE"])("answers 405 with Allow to %s", async (method) => {
      const res = await fetch(`${stack.url}/healthz`, { method });
      expect(res.status).toBe(405);
      expect(res.headers.get("Allow")).toBe("GET");
      expect(await res.json()).toEqual({ error: "method_not_allowed", error_description: "Use GET." });
    });

    test("answers HEAD with 405 and no body", async () => {
      const res = await fetch(`${stack.url}/healthz`, { method: "HEAD" });
      expect(res.status).toBe(405);
      expect(res.headers.get("Allow")).toBe("GET");
      expect(await res.text()).toBe("");
    });
  });

  describe("every response", () => {
    test.each([
      ["GET", "/healthz", 200],
      ["GET", "/nope", 404],
      ["DELETE", "/healthz", 405],
      ["GET", "/.well-known/openid-configuration", 200],
      ["POST", "/oauth/token", 415],
      ["GET", "/v1/me", 401],
      ["GET", "/", 302],
    ])("%s %s carries the security headers", async (method, path, status) => {
      const res = await fetch(`${stack.url}${path}`, { method, redirect: "manual" });
      expect(res.status).toBe(status);
      for (const [name, value] of Object.entries(SECURITY_HEADERS)) expect(res.headers.get(name)).toBe(value);
      expect(res.headers.get("Content-Security-Policy")).toBe(API_CSP);
      if (path !== "/.well-known/openid-configuration") expect(res.headers.get("Cache-Control")).toBe("no-store");
    });

    test("an unknown path is a JSON 404 in the shared error shape", async () => {
      const res = await fetch(`${stack.url}/no/such/endpoint`);
      expect(res.status).toBe(404);
      expect(res.headers.get("Content-Type")).toBe("application/json");
      expect(await res.json()).toEqual({ error: "not_found", error_description: "No such endpoint." });
    });

    test.each(["/healthz/", "//healthz", "/%68ealthz", "/HEALTHZ", "/healthz/x"])("%s is not /healthz", async (path) => {
      expect(statusOf(await raw(stack.port, `GET ${path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n`))).toBe(404);
    });

    test("dot segments and a query string are resolved before a route is matched", async () => {
      expect(statusOf(await raw(stack.port, "GET /v1/../healthz?x=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))).toBe(200);
      expect(statusOf(await raw(stack.port, "GET /a/./b/../../healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))).toBe(200);
    });

    test("a known path with another method is a 405 listing its methods", async () => {
      const res = await fetch(`${stack.url}/v1/me`, { method: "PUT" });
      expect(res.status).toBe(405);
      expect(res.headers.get("Allow")).toBe("GET, PATCH, DELETE");
      expect(await res.json()).toEqual({ error: "method_not_allowed", error_description: "Use GET or PATCH or DELETE." });
    });

    test.each([
      "/v1/users/a%2Fb",
      "/v1/users/a b",
      `/v1/users/${"a".repeat(129)}`,
      "/v1/users/usr_1/access/wi*ki",
      "/v1/me/passkeys/",
      "/assets/../assets/style.css/x",
    ])("a parameter that is not one unreserved segment matches nothing: %s", async (path) => {
      expect(statusOf(await raw(stack.port, `GET ${path.replace(/ /g, "%20")} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n`))).toBe(404);
    });
  });

  describe("request bodies", () => {
    const post = (length: number, type = "application/x-www-form-urlencoded") =>
      raw(stack.port, `POST /oauth/token HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: ${type}\r\nContent-Length: ${length}\r\n\r\n${"a".repeat(length)}`);

    test("a body of 64 KiB is read", async () => {
      // Read and refused for what it lacks: a client.
      const res = await post(64 * 1024);
      expect(statusOf(res)).toBe(401);
      expect(res).toContain('"error":"invalid_client"');
    });

    test("a body past 64 KiB is refused with 413 before it is read, and the connection closed", async () => {
      const res = await post(64 * 1024 + 1);
      expect(statusOf(res)).toBe(413);
      expect(res.toLowerCase()).toContain("connection: close");
    });

    test.each(["PUT", "PATCH", "DELETE"])("the cap holds for %s too", async (method) => {
      const res = await raw(stack.port, `${method} /v1/me HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 70000\r\n\r\n${"a".repeat(70000)}`);
      expect(statusOf(res)).toBe(413);
    });

    test("a chunked body past the cap is refused with 413", async () => {
      const chunk = `${(40000).toString(16)}\r\n${"a".repeat(40000)}\r\n`;
      const res = await raw(
        stack.port,
        `POST /oauth/token HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\n\r\n${chunk}${chunk}0\r\n\r\n`,
      );
      expect(statusOf(res)).toBe(413);
    });

    test("a chunked body within the cap is read", async () => {
      const res = await raw(
        stack.port,
        "POST /oauth/token HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\n\r\n3\r\na=b\r\n0\r\n\r\n",
      );
      expect(statusOf(res)).toBe(401);
    });
  });

    test.each([
      ["a JSON string", `"not a key"`],
      ["an empty object", `{}`],
      ["an array", `[1]`],
      ["another curve", `{"kty":"OKP","crv":"Ed448","x":"${"A".repeat(43)}"}`],
      ["an x one character short", `{"kty":"OKP","crv":"Ed25519","x":"${"A".repeat(42)}"}`],
      ["an x outside base64url", `{"kty":"OKP","crv":"Ed25519","x":"${"A".repeat(42)}+"}`],
    ])("a signing key whose public half is %s holds the start, named, until it is fixed", async (_, broken) => {
      const [key] = await stack.db`SELECT kid, public_jwk::text AS jwk FROM signing_keys ORDER BY sign_from LIMIT 1`;
      await stack.db`UPDATE signing_keys SET public_jwk = ${broken}::text::jsonb WHERE kid = ${key.kid}`;
      const copy = await stack.spawn();
      try {
        const line = `start: signing key ${key.kid} has an unreadable public key, retrying`;
        await waitFor(() => copy.logs.includes(line), "the copy to name the key", 15_000);
        expect(copy.logs.some((l) => l.startsWith("start: database not ready"))).toBe(false);
        expect((await fetch(`${copy.url}/.well-known/jwks.json`)).status).toBe(503);
      } finally {
        await stack.db`UPDATE signing_keys SET public_jwk = ${key.jwk}::text::jsonb WHERE kid = ${key.kid}`;
      }
      // Fixed, a later attempt starts it.
      await waitFor(async () => (await fetch(`${copy.url}/.well-known/jwks.json`)).status === 200, "the copy to start", 20_000);
      expect(await copy.stop()).toBe(0);
    });

  describe("the HTTP layer", () => {
    // Writes each step (a pause first, if it has one) and collects what comes
    // back until the server closes or `waitMs` passes.
    type Step = string | Buffer | { pauseMs: number; send: string };
    function exchange(steps: Step[], waitMs = 1500): Promise<{ data: string; closedAfterMs: number | null }> {
      return new Promise((done) => {
        const started = Date.now();
        const socket = net.connect(stack.port, "127.0.0.1");
        let data = "";
        const timer = setTimeout(() => {
          socket.destroy();
          done({ data, closedAfterMs: null });
        }, waitMs);
        socket.on("data", (d) => (data += d.toString("latin1")));
        socket.on("error", () => {});
        socket.on("close", () => {
          clearTimeout(timer);
          done({ data, closedAfterMs: Date.now() - started });
        });
        socket.on("connect", async () => {
          for (const step of steps) {
            if (typeof step === "object" && "pauseMs" in step) {
              await Bun.sleep(step.pauseMs);
              if (!socket.destroyed) socket.write(step.send);
            } else if (!socket.destroyed) socket.write(step);
          }
        });
      });
    }
    const statuses = (data: string) => [...data.matchAll(/HTTP\/1\.[01] (\d{3})/g)].map((m) => Number(m[1]));
    const bodyOf = (data: string) => data.split("\r\n\r\n")[1] ?? "";
    const H = "Host: 127.0.0.1\r\n";
    // A GET /healthz head of exactly `size` bytes, the excess in one header or in the query.
    const head = (size: number, where: "header" | "query" = "header") => {
      const base = where === "header" ? `GET /healthz HTTP/1.1\r\n${H}Connection: close\r\nX-Pad: \r\n\r\n` : `GET /healthz? HTTP/1.1\r\n${H}Connection: close\r\n\r\n`;
      const pad = "a".repeat(size - base.length);
      return where === "header" ? base.replace("X-Pad: ", `X-Pad: ${pad}`) : base.replace("/healthz? ", `/healthz?${pad} `);
    };
    const post = (headers: string, body: string) => `POST /oauth/token HTTP/1.1\r\n${H}Content-Type: application/x-www-form-urlencoded\r\n${headers}Connection: close\r\n\r\n${body}`;
    const refusedBare = (data: string, status: number) => {
      expect(statuses(data)).toEqual([status]);
      expect(bodyOf(data)).toBe("");
    };

    test.each([["header"], ["query"]] as const)("a request head of 16 KiB is read; one byte more is 431, the connection closed (the excess in the %s)", async (where) => {
      expect(head(16_384, where)).toHaveLength(16_384);
      const ok = await exchange([head(16_384, where)]);
      expect(statuses(ok.data)).toEqual([200]);
      const over = await exchange([head(16_385, where)]);
      refusedBare(over.data, 431);
      expect(over.closedAfterMs).not.toBeNull();
    });

    test("198 headers are read; 199 are 431", async () => {
      const withHeaders = (n: number) => `GET /healthz HTTP/1.1\r\n${H}Connection: close\r\n${Array.from({ length: n - 2 }, (_, i) => `X-H${i}: v\r\n`).join("")}\r\n`;
      expect(statuses((await exchange([withHeaders(198)])).data)).toEqual([200]);
      refusedBare((await exchange([withHeaders(199)])).data, 431);
    });

    const KNOWN = ["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH", "PURGE", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "SEARCH", "REPORT", "MKACTIVITY", "CHECKOUT", "MERGE", "M-SEARCH", "NOTIFY", "SUBSCRIBE", "UNSUBSCRIBE", "ACL", "BIND", "UNBIND", "REBIND", "LINK", "UNLINK", "SOURCE", "QUERY", "MKCALENDAR"];
    test("every method the server knows reaches the router", async () => {
      for (const method of KNOWN) {
        const { data } = await exchange([`${method} /healthz HTTP/1.1\r\n${H}Content-Length: 0\r\nConnection: close\r\n\r\n`]);
        expect([method, statuses(data)]).toEqual([method, [method === "GET" ? 200 : 405]]);
      }
    });

    test.each(["FOO", "FOO-BAR", "get", "Get", "G-ET", "DESCRIBE", "PRI", "A"])("%s, an unknown method of letters, closes the connection unanswered", async (method) => {
      const { data, closedAfterMs } = await exchange([`${method} /healthz HTTP/1.1\r\n${H}Connection: close\r\n\r\n`]);
      expect(data).toBe("");
      expect(closedAfterMs).not.toBeNull();
    });

    test.each(["G_ET", "G1", "GET1", "1GET", "G.ET", "G~ET", "G!ET", "_", "1"])("%s, a method with other characters, is a bad request", async (method) => {
      refusedBare((await exchange([`${method} /healthz HTTP/1.1\r\n${H}Connection: close\r\n\r\n`])).data, 400);
    });

    test.each([
      ["two lengths", post("Content-Length: 3\r\nContent-Length: 4\r\n", "a=bc")],
      ["a list of lengths", post("Content-Length: 3, 3\r\n", "a=b")],
      ["a length that isn't a number", post("Content-Length: abc\r\n", "a=b")],
      ["a negative length", post("Content-Length: -1\r\n", "a=b")],
      ["a signed length", post("Content-Length: +3\r\n", "a=b")],
      ["chunked after another coding", post("Transfer-Encoding: gzip, chunked\r\n", "3\r\na=b\r\n0\r\n\r\n")],
      ["chunked twice in one header", post("Transfer-Encoding: chunked, chunked\r\n", "3\r\na=b\r\n0\r\n\r\n")],
      ["Transfer-Encoding twice", post("Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n", "3\r\na=b\r\n0\r\n\r\n")],
      ["a coding other than chunked", post("Transfer-Encoding: identity\r\n", "a=b")],
      ["a chunk size that isn't hex", post("Transfer-Encoding: chunked\r\n", "zz\r\na=b\r\n0\r\n\r\n")],
      ["a chunk size past any length", post("Transfer-Encoding: chunked\r\n", "ffffffffffffffffff\r\na=b\r\n0\r\n\r\n")],
      ["a chunk without its line end", post("Transfer-Encoding: chunked\r\n", "3\r\na=bXX0\r\n\r\n")],
      ["trailers after the last chunk", post("Transfer-Encoding: chunked\r\n", "3\r\na=b\r\n0\r\nX-T: 1\r\n\r\n")],
      ["a folded header line", `GET /healthz HTTP/1.1\r\n${H}X-A: a\r\n b\r\nConnection: close\r\n\r\n`],
      ["a space before a header's colon", `GET /healthz HTTP/1.1\r\nHost : 127.0.0.1\r\nConnection: close\r\n\r\n`],
      ["a header line without a colon", `GET /healthz HTTP/1.1\r\n${H}Garbage\r\nConnection: close\r\n\r\n`],
      ["a header without a name", `GET /healthz HTTP/1.1\r\n${H}: v\r\nConnection: close\r\n\r\n`],
      ["a header name with a parenthesis", `GET /healthz HTTP/1.1\r\n${H}X(A): b\r\nConnection: close\r\n\r\n`],
      ["a NUL in a header value", `GET /healthz HTTP/1.1\r\n${H}X-A: a\u0000b\r\nConnection: close\r\n\r\n`],
      ["a method with a space", `GE T /healthz HTTP/1.1\r\n${H}Connection: close\r\n\r\n`],
      ["* as the target", `OPTIONS * HTTP/1.1\r\n${H}Connection: close\r\n\r\n`],
      ["a target without its leading slash", `GET healthz HTTP/1.1\r\n${H}Connection: close\r\n\r\n`],
    ])("%s is refused bare with 400", async (_, request) => {
      const { data, closedAfterMs } = await exchange([request]);
      refusedBare(data, 400);
      expect(closedAfterMs).not.toBeNull();
    });

    test.each([
      ["Transfer-Encoding in another case", post("Transfer-Encoding: Chunked\r\n", "3\r\na=b\r\n0\r\n\r\n")],
      ["a chunk extension", post("Transfer-Encoding: chunked\r\n", "3;ext=1\r\na=b\r\n0\r\n\r\n")],
      ["a length given twice alike", post("Content-Length: 3\r\nContent-Length: 3\r\n", "a=b")],
      ["spaces around a length", post("Content-Length:  3 \r\n", "a=b")],
      ["an Expect the server doesn't know", post("Expect: something\r\nContent-Length: 3\r\n", "a=b")],
    ])("%s is read", async (_, request) => {
      // Read, and refused for what it lacks: a client.
      expect(statuses((await exchange([request])).data)).toEqual([401]);
    });

    test("Expect: 100-continue is answered 100 before the body is sent", async () => {
      const { data } = await exchange([`POST /oauth/token HTTP/1.1\r\n${H}Content-Type: application/x-www-form-urlencoded\r\nExpect: 100-continue\r\nContent-Length: 3\r\nConnection: close\r\n\r\n`, { pauseMs: 500, send: "a=b" }]);
      expect(statuses(data)).toEqual([100, 401]);
    });

    test.each([[`http://127.0.0.1/healthz`], ["http://elsewhere.example.com/healthz"]])("an absolute URL, %s, as the target is served", async (target) => {
      expect(statuses((await exchange([`GET ${target} HTTP/1.1\r\n${H}Connection: close\r\n\r\n`])).data)).toEqual([200]);
    });

    test.each([["asked to keep it", "Connection: keep-alive\r\n"], ["not asked", ""]])("HTTP/1.0 gets one answer, then the connection is closed, %s", async (_, extra) => {
      const { data, closedAfterMs } = await exchange([`GET /healthz HTTP/1.0\r\n${H}${extra}\r\n`]);
      expect(statuses(data)).toEqual([200]);
      expect(closedAfterMs).not.toBeNull();
    });

    test("HTTP/1.1 keeps the connection for the next request", async () => {
      const socket = net.connect(stack.port, "127.0.0.1");
      let data = "";
      socket.on("data", (d) => {
        data += d.toString("latin1");
        if (statuses(data).length === 1) socket.write(`GET /nope HTTP/1.1\r\n${H}\r\n`);
      });
      socket.on("connect", () => socket.write(`GET /healthz HTTP/1.1\r\n${H}\r\n`));
      await waitFor(() => statuses(data).length === 2, "two answers on one connection");
      socket.destroy();
      expect(statuses(data)).toEqual([200, 404]);
    });

    // Bun closes on a timer that ticks every few seconds, so after 8 to 13
    // seconds; the Rust server after 10.
    test("a connection that doesn't finish its request is closed unanswered after about ten seconds", async () => {
      const stalled: [string, Step[]][] = [
        ["idle after an answer", [`GET /healthz HTTP/1.1\r\n${H}\r\n`]],
        ["silent", []],
        ["half a request line", ["GET /heal"]],
        ["headers unfinished", [`GET /healthz HTTP/1.1\r\n${H}X-A: b\r\n`]],
        ["a header trickled a byte a second", ["GET /healthz HTTP/1.1\r\nX-Slow: ", ...Array.from({ length: 25 }, () => ({ pauseMs: 1000, send: "a" }))]],
        ["a body unfinished", [post("Content-Length: 100\r\n", "a=b").replace("Connection: close\r\n", "")]],
        ["a body trickled a byte a second", [post("Content-Length: 30\r\n", "").replace("Connection: close\r\n", ""), ...Array.from({ length: 29 }, () => ({ pauseMs: 1000, send: "a" }))]],
      ];
      const outcomes = await Promise.all(stalled.map(async ([what, steps]) => [what, await exchange(steps, 20_000)] as const));
      for (const [what, { data, closedAfterMs }] of outcomes) {
        expect([what, statuses(data)]).toEqual([what, what === "idle after an answer" ? [200] : []]);
        expect([what, closedAfterMs !== null && closedAfterMs >= 7_000 && closedAfterMs <= 16_000]).toEqual([what, true]);
      }
    }, 40_000);
  });

  describe("the Host header", () => {
    const get = (host: string | null, version: string) =>
      raw(stack.port, `GET /healthz?code=abc123 HTTP/${version}\r\n${host === null ? "" : `Host: ${host}\r\n`}Connection: close\r\n\r\n`);

    // A Host that doesn't make a URL with the target: the server can't tell
    // what was asked for.
    test.each([
      ["missing, in HTTP/1.0", null, "1.0"],
      ["missing, in HTTP/1.1", null, "1.1"],
      ["empty", "", "1.1"],
      ["a space", " ", "1.1"],
      ["a path", "a/b", "1.1"],
      ["a query", "a?b", "1.1"],
      ["a fragment", "a#b", "1.1"],
      ["a user", "a@b", "1.1"],
      ["a backslash", "a\\b", "1.1"],
      ["a space inside", "a b", "1.1"],
      ["a character outside ASCII", "\u00e9.example.com", "1.1"],
      ["an escaped slash", "a%2Fb", "1.1"],
      ["a port past 65535", "x:99999", "1.1"],
      ["a port that isn't a number", "x:abc", "1.1"],
      ["five numbers", "1.2.3.4.5", "1.1"],
      ["a number past 255", "256.1.1.1", "1.1"],
      ["brackets around no address", "[zz]", "1.1"],
    ] as [string, string | null, string][])("%s is refused bare with 400, the connection closed, and nothing logged", async (_, host, version) => {
      const before = stack.logs.length;
      const res = await get(host, version);
      expect(statusOf(res)).toBe(400);
      expect(res.split("\r\n\r\n")[1]).toBe("");
      expect(res.toLowerCase()).toContain("connection: close");
      // A request after it, whose line marks where the log has got to.
      await (await fetch(`${stack.url}/nope`)).body?.cancel();
      await waitFor(() => stack.logs.slice(before).some((l) => l.startsWith("GET unmatched 404")), "the next request's log line");
      expect(stack.logs.slice(before)).toEqual([expect.stringMatching(/^GET unmatched 404 \d+ms$/)]);
    });

    test.each([["[::1]"], ["[::1]:80"], ["x:"], ["x:0"], ["%41"], ["UPPER.example.com"], ["_x"], ["x.y."], ["127.0.0.1:1"]])("%s is a host, and the request is served", async (host) => {
      const res = await get(host, "1.1");
      expect(statusOf(res)).toBe(200);
      expect(res.split("\r\n\r\n")[1]).toBe('{"status":"ok"}');
    });
  });

  describe("the request log", () => {
    test("names the method, the route, the status and the time, never the path or query", async () => {
      const before = stack.logs.length;
      await fetch(`${stack.url}/oauth/authorize?code=abc123&state=s3cret-pw&client_id=nobody`);
      await fetch(`${stack.url}/callback?code=abc123`);
      await fetch(`${stack.url}/v1/users/usr_abc123`, { headers: { Authorization: "Basic czNjcmV0LXB3OnMzY3JldC1wdw==", Cookie: "__Host-auth=s3cret-pw" } });
      await Bun.sleep(50);
      const lines = stack.logs.slice(before);
      expect(lines).toHaveLength(3);
      expect(lines[0]).toMatch(/^GET authorize 400 \d+ms$/);
      expect(lines[1]).toMatch(/^GET unmatched 404 \d+ms$/);
      expect(lines[2]).toMatch(/^GET v1\.user 401 \d+ms$/);
      expect(lines.join("\n")).not.toContain("abc123");
      expect(lines.join("\n")).not.toContain("s3cret-pw");
      expect(lines.join("\n")).not.toContain("czNjcmV0");
    });

    test("the start is logged", () => {
      expect(stack.logs).toContain(`listening on :${stack.port}`);
      expect(stack.logs).toContain("migration 0001_initial applied");
      expect(stack.logs).toContain("migration 0002_services applied");
    });
  });

  describe("an unexpected failure", () => {
    test("is a 500 in the shared shape, logged by a name only", async () => {
      const copy = await Stack.start();
      try {
        // The table a sign-in page's session lookup reads is gone.
        const browser = copy.browser();
        browser.cookies.set("__Host-auth", "a".repeat(43));
        await copy.db.unsafe("ALTER TABLE sessions RENAME TO sessions_s3cret_pw");
        const res = await browser.request("/v1/me");
        expect(res.status).toBe(500);
        expect(res.headers.get("Content-Type")).toBe("application/json");
        expect(await res.json()).toEqual({ error: "server_error", error_description: "Internal error." });
        await Bun.sleep(50);
        const lines = copy.logs.filter((l) => l.includes("v1.me"));
        expect(lines).toHaveLength(2);
        expect(lines[0]).toMatch(/^GET v1\.me threw \w+$/);
        expect(lines[1]).toMatch(/^GET v1\.me 500 \d+ms$/);
        expect(copy.server.logText()).not.toContain("s3cret_pw");
        await copy.db.unsafe("ALTER TABLE sessions_s3cret_pw RENAME TO sessions");
      } finally {
        await copy.stop();
      }
    });
  });
});

describe.skipIf(!enabled)("starting and stopping", () => {
  test("SIGTERM finishes and exits 0; so does SIGINT", async () => {
    const stack = await Stack.start();
    try {
      const second = await stack.spawn();
      await second.ready();
      expect(await second.stop("SIGINT")).toBe(0);
      expect(second.logs).toContain("SIGINT: finishing requests in flight");
      expect(await stack.server.stop("SIGTERM")).toBe(0);
      expect(stack.logs).toContain("SIGTERM: finishing requests in flight");
    } finally {
      await stack.stop();
    }
  });

  test("a second copy starts on a migrated database without applying anything again", async () => {
    const stack = await Stack.start();
    try {
      const second = await stack.spawn();
      await second.ready();
      expect(second.logs.filter((l) => l.startsWith("migration "))).toEqual([]);
      const versions: { version: string }[] = await stack.db`SELECT version FROM schema_migrations ORDER BY version`;
      expect(versions.map((v) => v.version)).toEqual(["0001_initial", "0002_services"]);
      // Both serve the same keys.
      const a = await (await fetch(`${stack.url}/.well-known/jwks.json`)).json();
      const b = await (await fetch(`${second.url}/.well-known/jwks.json`)).json();
      expect(b).toEqual(a);
    } finally {
      await stack.stop();
    }
  });

  // A database that takes the connection and never says a word.
  async function tarpit(): Promise<{ port: number; close: () => void }> {
    const sockets = new Set<import("node:net").Socket>();
    const server = (await import("node:net")).createServer((socket) => {
      sockets.add(socket);
      socket.on("error", () => {});
    });
    await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
    return {
      port: (server.address() as import("node:net").AddressInfo).port,
      close: () => {
        for (const socket of sockets) socket.destroy();
        server.close();
      },
    };
  }

  test("a stop while the database never answers exits 0 within a deploy's grace period", async () => {
    const stack = await Stack.start({ start: false });
    const db = await tarpit();
    try {
      const copy = await stack.spawn({ env: { DATABASE_URL: `postgres://auth:s3cret-pw@127.0.0.1:${db.port}/auth` } });
      await waitFor(() => copy.logs.some((l) => l.startsWith("listening on :")), "the copy to listen", 20_000);
      const asked = Date.now();
      expect(await copy.stop()).toBe(0);
      expect(Date.now() - asked).toBeLessThan(10_000);
    } finally {
      db.close();
      await stack.stop();
    }
  });

  test("a connection the database never answers is given up after connect_timeout, and tried again", async () => {
    const stack = await Stack.start({ start: false });
    const db = await tarpit();
    try {
      const copy = await stack.spawn({ env: { DATABASE_URL: `postgres://auth:s3cret-pw@127.0.0.1:${db.port}/auth?connect_timeout=1` } });
      await waitFor(() => copy.logs.filter((l) => /^start: database not ready \(\w+\), retrying$/.test(l)).length >= 2, "two attempts given up", 20_000);
      expect(copy.logText()).not.toContain("s3cret-pw");
      expect(await copy.stop()).toBe(0);
    } finally {
      db.close();
      await stack.stop();
    }
  });

  test("until the database answers, /healthz and everything else answer 503, and the copy keeps trying", async () => {
    const stack = await Stack.start({ start: false });
    try {
      // A database nothing listens on: the port is free.
      const copy = await stack.spawn({ env: { DATABASE_URL: "postgres://auth:s3cret-pw@127.0.0.1:9/auth" } });
      const res = await (async () => {
        for (let i = 0; i < 200; i++) {
          try {
            return await fetch(`${copy.url}/.well-known/openid-configuration`);
          } catch {
            await Bun.sleep(25);
          }
        }
        throw new Error("the copy never listened");
      })();
      expect(res.status).toBe(503);
      expect(res.headers.get("Retry-After")).toBe("5");
      expect(await res.json()).toEqual({ error: "temporarily_unavailable", error_description: "Starting up." });
      const health = await fetch(`${copy.url}/healthz`);
      expect(health.status).toBe(503);
      expect(await health.json()).toEqual({ error: "temporarily_unavailable", error_description: "The database is unreachable." });
      await Bun.sleep(1200);
      expect(copy.logs.some((l) => /^start: database not ready \(\w+\), retrying$/.test(l))).toBe(true);
      expect(copy.logText()).not.toContain("s3cret-pw");
      expect(copy.running).toBe(true);
      expect(await copy.stop()).toBe(0);
    } finally {
      await stack.stop();
    }
  });
});
