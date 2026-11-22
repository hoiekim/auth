import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { createHash, createPrivateKey, randomBytes, sign, type KeyObject } from "node:crypto";
import {
  API_CSP,
  authorizeParams,
  b64u,
  backChannel,
  base32,
  basic,
  type Browser,
  decodeJwt,
  defaultServices,
  enabled,
  errorOf,
  newId,
  pkce,
  randomToken,
  REDIRECTS,
  SECURITY_HEADERS,
  type ServerProcess,
  sha256,
  Stack,
  type TestUser,
  type TokenSet,
} from "./harness";

// The OAuth 2.0 and OpenID Connect endpoints (docs/DESIGN.md §7.1–§7.3, §9.4):
// discovery and keys, client authentication, the authorization request, the
// code and refresh grants for confidential and public clients, revocation,
// introspection, userinfo and RP-initiated logout.

setDefaultTimeout(30_000);

// ------------------------------------------------------------------ helpers

let seq = 0;
// A username of its own for each test.
function uname(prefix: string): string {
  return `${prefix}-${(++seq).toString(36)}${randomBytes(2).toString("hex")}`;
}

function post(base: string, path: string, fields: Record<string, string> | string, headers: Record<string, string> = {}): Promise<Response> {
  return fetch(`${base}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
    body: typeof fields === "string" ? fields : new URLSearchParams(fields).toString(),
    redirect: "manual",
  });
}

function decodeEntities(s: string): string {
  return s
    .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCodePoint(parseInt(n, 16)))
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
    .replace(/&quot;/g, '"')
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

// What a message page says: its title, heading, message and link.
async function pageOf(res: Response): Promise<{ status: number; title: string; h1: string; message: string; links: { href: string; text: string }[] }> {
  expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
  const text = await res.text();
  const title = decodeEntities(/<title>([\s\S]*?)<\/title>/.exec(text)?.[1]?.trim() ?? "");
  const h1 = decodeEntities(/<h1>([\s\S]*?)<\/h1>/.exec(text)?.[1]?.trim() ?? "");
  const message = decodeEntities(/<div class="card">[\s\S]*?<p>([\s\S]*?)<\/p>/.exec(text)?.[1]?.trim() ?? "");
  const links = [...text.matchAll(/<a\b[^>]*href="([^"]*)"[^>]*>([\s\S]*?)<\/a>/g)].map((m) => ({ href: decodeEntities(m[1]!), text: decodeEntities(m[2]!.trim()) }));
  return { status: res.status, title, h1, message, links };
}

function cookieAttrs(setCookie: string): { name: string; value: string; attrs: Set<string> } {
  const [pair, ...rest] = setCookie.split(";").map((s) => s.trim());
  const eq = pair!.indexOf("=");
  return { name: pair!.slice(0, eq), value: pair!.slice(eq + 1), attrs: new Set(rest.map((a) => a.toLowerCase())) };
}

function expectSessionCookieCleared(res: Response): void {
  const cleared = res.headers.getSetCookie().map(cookieAttrs).find((c) => c.name === "__Host-auth");
  expect(cleared).toBeDefined();
  expect(cleared!.value).toBe("");
  for (const a of ["path=/", "secure", "httponly", "samesite=lax", "max-age=0"]) expect(cleared!.attrs.has(a)).toBe(true);
}

function expectJson(res: Response): void {
  expect(res.headers.get("Content-Type")).toBe("application/json");
  expect(res.headers.get("Cache-Control")).toBe("no-store");
}

// The expected Location of a redirect back to a client: the URI with each
// parameter appended, as a URL's searchParams writes it.
function back(redirectUri: string, params: Record<string, string>): string {
  const url = new URL(redirectUri);
  for (const [k, v] of Object.entries(params)) url.searchParams.append(k, v);
  return url.toString();
}

const CODE = /^[A-Za-z0-9_-]{43}$/;
const REFRESH = /^rt_[A-Za-z0-9_-]{43}$/;
const SID = /^ses_[0-9a-hjkmnp-tv-z]{26}$/;
const ACCESS_CLAIMS = ["aud", "exp", "iat", "iss", "name", "role", "sid", "sub", "username"];
const ID_CLAIMS = [...ACCESS_CLAIMS, "amr", "auth_time", "email", "email_verified", "nonce"].sort();

const INVALID_CLIENT = { status: 401, error: "invalid_client", description: "Client authentication failed." };
const INVALID_CODE = { status: 400, error: "invalid_grant", description: "The authorization code is invalid, expired or used." };
const INVALID_REFRESH = { status: 400, error: "invalid_grant", description: "The refresh token is invalid, expired or revoked." };

describe.skipIf(!enabled)("OAuth and OIDC", () => {
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

  const form = (path: string, fields: Record<string, string> | string, authorization?: string | null, headers: Record<string, string> = {}) =>
    post(stack.url, path, fields, authorization ? { Authorization: authorization, ...headers } : headers);

  // A user with a fresh SSO session.
  async function signedIn(access: Record<string, string>, opts: { amr?: string[]; authAge?: number; totp?: boolean; email?: string | null; prefix?: string } = {}): Promise<{ user: TestUser; browser: Browser }> {
    const user = await stack.user({ username: uname(opts.prefix ?? "u"), access, totp: opts.totp, email: opts.email });
    const browser = await stack.session(user, { amr: opts.amr, authAge: opts.authAge });
    return { user, browser };
  }

  // An authorization request through the browser's session, answered with a code.
  // A parameter given as null is left out.
  async function codeFor(browser: Browser, clientId: string, more: Record<string, string | null> = {}, redirectUri = REDIRECTS[clientId]!) {
    const { verifier, challenge } = pkce();
    const params = authorizeParams(clientId, redirectUri, challenge, Object.fromEntries(Object.entries(more).filter(([, v]) => v !== null)) as Record<string, string>);
    for (const [k, v] of Object.entries(more)) if (v === null) delete params[k];
    const res = await browser.request(`/oauth/authorize?${new URLSearchParams(params)}`);
    const location = res.headers.get("Location");
    if (res.status !== 302 || !location) throw new Error(`no redirect: ${res.status} ${(await res.text()).slice(0, 300)}`);
    const code = new URL(location).searchParams.get("code");
    if (!code) throw new Error(`no code: ${location}`);
    return { code, verifier, params, location };
  }

  const isPublic = (clientId: string) => stack.secrets[clientId] === undefined;

  function exchange(clientId: string, code: string, verifier: string, redirectUri = REDIRECTS[clientId]!, extra: Record<string, string> = {}) {
    const pub = isPublic(clientId);
    return form(
      "/oauth/token",
      { grant_type: "authorization_code", code, redirect_uri: redirectUri, code_verifier: verifier, ...(pub ? { client_id: clientId } : {}), ...extra },
      pub ? null : stack.basic(clientId),
    );
  }

  function refresh(clientId: string, token: string) {
    const pub = isPublic(clientId);
    return form("/oauth/token", { grant_type: "refresh_token", refresh_token: token, ...(pub ? { client_id: clientId } : {}) }, pub ? null : stack.basic(clientId));
  }

  async function tokensFor(browser: Browser, clientId: string, more: Record<string, string> = {}): Promise<TokenSet & { nonce: string }> {
    const { code, verifier, params } = await codeFor(browser, clientId, more);
    const res = await exchange(clientId, code, verifier);
    if (res.status !== 200) throw new Error(`exchange failed: ${res.status} ${await res.text()}`);
    return { ...((await res.json()) as TokenSet), nonce: params.nonce! };
  }

  // A token signed with the server's own current key, for claims the server
  // would never issue (expired, wrong audience, …).
  let signingKey: { kid: string; key: KeyObject } | null = null;
  async function forge(claims: Record<string, unknown>, header: Record<string, unknown> = {}): Promise<string> {
    if (!signingKey) {
      const [row] = await stack.db`SELECT kid, private_key_enc FROM signing_keys WHERE sign_from <= now() ORDER BY sign_from DESC LIMIT 1`;
      signingKey = { kid: row.kid, key: createPrivateKey({ key: stack.crypt.decrypt(row.private_key_enc, row.kid), format: "der", type: "pkcs8" }) };
    }
    const h = b64u(JSON.stringify({ alg: "EdDSA", typ: "at+jwt", kid: signingKey.kid, ...header }));
    const p = b64u(JSON.stringify(claims));
    return `${h}.${p}.${b64u(sign(null, Buffer.from(`${h}.${p}`), signingKey.key))}`;
  }

  // ------------------------------------------------------------ discovery

  describe("discovery and keys", () => {
    test("the discovery document lists exactly what is implemented", async () => {
      const res = await fetch(`${stack.url}/.well-known/openid-configuration`);
      expect(res.status).toBe(200);
      expect(res.headers.get("Content-Type")).toBe("application/json");
      expect(res.headers.get("Cache-Control")).toBe("public, max-age=3600");
      for (const [name, value] of Object.entries(SECURITY_HEADERS)) expect(res.headers.get(name)).toBe(value);
      expect(res.headers.get("Content-Security-Policy")).toBe(API_CSP);
      const iss = stack.issuer;
      expect(await res.json()).toEqual({
        issuer: iss,
        authorization_endpoint: `${iss}/oauth/authorize`,
        token_endpoint: `${iss}/oauth/token`,
        userinfo_endpoint: `${iss}/oauth/userinfo`,
        jwks_uri: `${iss}/.well-known/jwks.json`,
        end_session_endpoint: `${iss}/logout`,
        revocation_endpoint: `${iss}/oauth/revoke`,
        introspection_endpoint: `${iss}/oauth/introspect`,
        response_types_supported: ["code"],
        response_modes_supported: ["query"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["EdDSA"],
        token_endpoint_auth_methods_supported: ["client_secret_basic", "none"],
        revocation_endpoint_auth_methods_supported: ["client_secret_basic", "none"],
        introspection_endpoint_auth_methods_supported: ["client_secret_basic"],
        code_challenge_methods_supported: ["S256"],
        scopes_supported: ["openid", "profile", "email"],
        prompt_values_supported: ["none", "login"],
        claims_supported: ["iss", "sub", "aud", "iat", "exp", "sid", "username", "name", "role", "nonce", "auth_time", "amr", "email", "email_verified"],
      });
    });

    test("the JWKS publishes Ed25519 keys named by their RFC 7638 thumbprint", async () => {
      const res = await fetch(`${stack.url}/.well-known/jwks.json`);
      expect(res.status).toBe(200);
      expect(res.headers.get("Content-Type")).toBe("application/json");
      expect(res.headers.get("Cache-Control")).toBe("public, max-age=3600");
      const body = (await res.json()) as { keys: Record<string, unknown>[] };
      expect(Object.keys(body)).toEqual(["keys"]);
      expect(body.keys).toHaveLength(1);
      const key = body.keys[0]!;
      expect(Object.keys(key).sort()).toEqual(["alg", "crv", "kid", "kty", "use", "x"]);
      expect(key).toMatchObject({ kty: "OKP", crv: "Ed25519", alg: "EdDSA", use: "sig" });
      expect(key.x).toMatch(/^[A-Za-z0-9_-]{43}$/);
      const thumb = b64u(createHash("sha256").update(JSON.stringify({ crv: "Ed25519", kty: "OKP", x: key.x })).digest());
      expect(key.kid).toBe(thumb);
      const [row] = await stack.db`SELECT kid FROM signing_keys`;
      expect(row.kid).toBe(thumb);
    });

    test.each([
      ["/.well-known/openid-configuration", "POST", "GET"],
      ["/.well-known/jwks.json", "POST", "GET"],
      ["/oauth/authorize", "POST", "GET"],
      ["/oauth/token", "GET", "POST"],
      ["/oauth/revoke", "GET", "POST"],
      ["/oauth/introspect", "GET", "POST"],
      ["/oauth/userinfo", "PUT", "GET, POST"],
      ["/logout", "POST", "GET"],
    ])("%s refuses %s with 405 and Allow: %s", async (path, method, allow) => {
      const res = await fetch(`${stack.url}${path}`, { method, redirect: "manual" });
      expect(res.status).toBe(405);
      expect(res.headers.get("Allow")).toBe(allow);
      await res.body?.cancel();
    });
  });

  // ---------------------------------------------------- client authentication

  describe("client authentication", () => {
    // A refresh with an unknown token: past client authentication, it is invalid_grant.
    const probe = (authorization: string | null, fields: Record<string, string> = {}, path = "/oauth/token") =>
      form(path, path === "/oauth/token" ? { grant_type: "refresh_token", refresh_token: "rt_unknown", ...fields } : { token: "unknown", ...fields }, authorization);

    test("a confidential client's Basic credentials are accepted", async () => {
      expect(await errorOf(await probe(stack.basic("wiki")))).toEqual(INVALID_REFRESH);
    });

    test("the id and secret are form-decoded after Base64 (RFC 6749 §2.3.1)", async () => {
      const raw = (s: string) => `Basic ${Buffer.from(s).toString("base64")}`;
      // Not encoded at all, and every character percent-encoded.
      expect(await errorOf(await probe(raw(`wiki:${stack.secrets.wiki}`)))).toEqual(INVALID_REFRESH);
      const pct = (s: string) => [...Buffer.from(s)].map((b) => `%${b.toString(16).padStart(2, "0")}`).join("");
      expect(await errorOf(await probe(raw(`${pct("wiki")}:${pct(stack.secrets.wiki!)}`)))).toEqual(INVALID_REFRESH);
      // Surrounding whitespace in the header is ignored.
      expect(await errorOf(await probe(`  ${stack.basic("wiki")}  `))).toEqual(INVALID_REFRESH);
    });

    test("a secret with a space is sent as + and decoded", async () => {
      const secret = "s3cret pw with spaces and + plus";
      await stack.db`INSERT INTO client_secrets (client_id, secret_hash) VALUES ('mailbox', ${sha256(secret)})`;
      const header = `Basic ${Buffer.from(`mailbox:${secret.replace(/\+/g, "%2B").replace(/ /g, "+")}`).toString("base64")}`;
      expect(await errorOf(await probe(header))).toEqual(INVALID_REFRESH);
      await stack.db`UPDATE client_secrets SET revoked_at = now() WHERE secret_hash = ${sha256(secret)}`;
    });

    test.each([
      ["a header that is not Basic", "Bearer abc123"],
      ["a lower-case scheme", "basic d2lraTp4"],
      ["no credentials", "Basic "],
      ["characters outside Base64", "Basic d2lraTp4!"],
      ["Base64 with no colon", `Basic ${Buffer.from("wiki").toString("base64")}`],
      ["a malformed percent-encoding", `Basic ${Buffer.from("wiki:%zz").toString("base64")}`],
      ["over 1024 Base64 characters", `Basic ${"A".repeat(1025)}`],
      ["an empty secret", `Basic ${Buffer.from("wiki:").toString("base64")}`],
      ["a wrong secret", basic("wiki", "s3cret-pw")],
      ["a secret over 512 characters", basic("wiki", "a".repeat(513))],
      ["another client's secret", "TASKS"],
      ["an unknown client", basic("nobody", "s3cret-pw")],
      ["a public client using Basic", basic("tasks-ios", "s3cret-pw")],
    ])("%s is invalid_client with WWW-Authenticate: Basic", async (_, header) => {
      const authorization = header === "TASKS" ? basic("wiki", stack.secrets.tasks!) : header;
      const res = await probe(authorization);
      expect(res.headers.get("WWW-Authenticate")).toBe('Basic realm="auth"');
      expectJson(res);
      expect(await errorOf(res)).toEqual(INVALID_CLIENT);
    });

    test("an over-long Base64 credential is refused even when it decodes to a real one", async () => {
      const padded = `Basic ${Buffer.from(`wiki:${stack.secrets.wiki}`).toString("base64")}${"=".repeat(1024)}`;
      expect(await errorOf(await probe(padded))).toEqual(INVALID_CLIENT);
    });

    test("a revoked secret is refused; two live secrets both work", async () => {
      const second = await stack.clientSecret("wiki");
      expect(await errorOf(await probe(basic("wiki", second)))).toEqual(INVALID_REFRESH);
      expect(await errorOf(await probe(stack.basic("wiki")))).toEqual(INVALID_REFRESH);
      await stack.db`UPDATE client_secrets SET revoked_at = now() WHERE secret_hash = ${sha256(second)}`;
      const res = await probe(basic("wiki", second));
      expect(res.headers.get("WWW-Authenticate")).toBe('Basic realm="auth"');
      expect(await errorOf(res)).toEqual(INVALID_CLIENT);
      expect(await errorOf(await probe(stack.basic("wiki")))).toEqual(INVALID_REFRESH);
    });

    test("a client_id in the form must name the Basic client", async () => {
      expect(await errorOf(await probe(stack.basic("wiki"), { client_id: "wiki" }))).toEqual(INVALID_REFRESH);
      const res = await probe(stack.basic("wiki"), { client_id: "tasks" });
      expect(res.headers.get("WWW-Authenticate")).toBe('Basic realm="auth"');
      expect(await errorOf(res)).toEqual(INVALID_CLIENT);
      expect(await errorOf(await probe(stack.basic("wiki"), { client_id: "" }))).toEqual(INVALID_CLIENT);
    });

    test("a repeated client_id with Basic is refused as a repeated parameter", async () => {
      const res = await form("/oauth/token", "grant_type=refresh_token&refresh_token=rt_x&client_id=wiki&client_id=wiki", stack.basic("wiki"));
      expect(await errorOf(res)).toEqual({ status: 400, error: "invalid_request", description: 'The parameter "client_id" is repeated.' });
    });

    test.each([
      ["a confidential client without Basic", { client_id: "wiki" }],
      ["no client at all", {}],
      ["an empty client_id", { client_id: "" }],
      ["an unknown client_id", { client_id: "nobody" }],
      ["client_secret in the form (client_secret_post)", { client_id: "wiki", client_secret: "SECRET" }],
      ["client_secret in the form, even for a public client", { client_id: "tasks-ios", client_secret: "" }],
    ])("%s is invalid_client without WWW-Authenticate", async (_, fields: Record<string, string>) => {
      const f = { ...fields };
      if (f.client_secret === "SECRET") f.client_secret = stack.secrets.wiki!;
      const res = await probe(null, f);
      expect(res.headers.get("WWW-Authenticate")).toBeNull();
      expect(await errorOf(res)).toEqual(INVALID_CLIENT);
    });

    test("a public client names itself by client_id at the token and revocation endpoints", async () => {
      expect(await errorOf(await probe(null, { client_id: "tasks-ios" }))).toEqual(INVALID_REFRESH);
      const res = await probe(null, { client_id: "tasks-ios" }, "/oauth/revoke");
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({});
    });

    test("introspection takes no public client", async () => {
      const res = await probe(null, { client_id: "tasks-ios" }, "/oauth/introspect");
      expect(res.headers.get("WWW-Authenticate")).toBeNull();
      expect(await errorOf(res)).toEqual(INVALID_CLIENT);
      const basicRes = await probe(basic("tasks-ios", "x"), {}, "/oauth/introspect");
      expect(basicRes.headers.get("WWW-Authenticate")).toBe('Basic realm="auth"');
      expect(await errorOf(basicRes)).toEqual(INVALID_CLIENT);
    });

    test.each(["/oauth/token", "/oauth/revoke", "/oauth/introspect"])("%s wants a form body: 415 before the client is checked", async (path) => {
      for (const type of [null, "application/json", "text/plain", "multipart/form-data; boundary=x"]) {
        const headers: Record<string, string> = { Authorization: "Basic !!" };
        if (type) headers["Content-Type"] = type;
        const res = await fetch(`${stack.url}${path}`, { method: "POST", headers, body: type === "application/json" ? "{}" : "grant_type=refresh_token" });
        expect(await errorOf(res)).toEqual({ status: 415, error: "invalid_request", description: "Send application/x-www-form-urlencoded." });
      }
      // The type's parameters and case don't matter.
      const ok = await fetch(`${stack.url}${path}`, {
        method: "POST",
        headers: { "Content-Type": "Application/X-WWW-Form-Urlencoded; charset=utf-8", Authorization: stack.basic("wiki") },
        body: "grant_type=refresh_token&refresh_token=rt_x&token=x",
      });
      expect(ok.status).not.toBe(415);
      await ok.body?.cancel();
    });
  });

  // ------------------------------------------------------------- authorize

  describe("GET /oauth/authorize", () => {
    let browser: Browser;
    let user: TestUser;
    beforeAll(async () => {
      ({ user, browser } = await signedIn({ wiki: "member" }, { prefix: "az" }));
    });

    const go = (b: Browser, params: Record<string, string> | string) =>
      b.request(`/oauth/authorize?${typeof params === "string" ? params : new URLSearchParams(params)}`);
    const valid = (more: Record<string, string> = {}) => authorizeParams("wiki", REDIRECTS.wiki!, pkce().challenge, more);
    const without = (p: Record<string, string>, ...names: string[]) => Object.fromEntries(Object.entries(p).filter(([k]) => !names.includes(k)));

    async function expectInvalidLinkPage(res: Response, message: string) {
      expect(res.status).toBe(400);
      expect(res.headers.get("Location")).toBeNull();
      expect(await pageOf(res)).toEqual({ status: 400, title: "This sign-in link is not valid", h1: "This sign-in link is not valid", message, links: [] });
    }

    describe("errors shown on auth's own page", () => {
      test.each([
        ["no client_id", (p: Record<string, string>) => without(p, "client_id"), "The app that sent you here is not registered."],
        ["an empty client_id", (p: Record<string, string>) => ({ ...p, client_id: "" }), "The app that sent you here is not registered."],
        ["an unknown client", (p: Record<string, string>) => ({ ...p, client_id: "nobody" }), "The app that sent you here is not registered."],
        ["a client id in another case", (p: Record<string, string>) => ({ ...p, client_id: "WIKI" }), "The app that sent you here is not registered."],
        ["no redirect_uri", (p: Record<string, string>) => without(p, "redirect_uri"), "The app sent you here with a return address it hasn't registered."],
        ["an empty redirect_uri", (p: Record<string, string>) => ({ ...p, redirect_uri: "" }), "The app sent you here with a return address it hasn't registered."],
        ["an unregistered redirect_uri", (p: Record<string, string>) => ({ ...p, redirect_uri: "https://evil.example.com/cb" }), "The app sent you here with a return address it hasn't registered."],
        ["a redirect_uri that only starts like a registered one", (p: Record<string, string>) => ({ ...p, redirect_uri: `${REDIRECTS.wiki}/x` }), "The app sent you here with a return address it hasn't registered."],
        ["a redirect_uri with a trailing slash", (p: Record<string, string>) => ({ ...p, redirect_uri: `${REDIRECTS.wiki}/` }), "The app sent you here with a return address it hasn't registered."],
        ["another client's redirect_uri", (p: Record<string, string>) => ({ ...p, redirect_uri: REDIRECTS.tasks! }), "The app sent you here with a return address it hasn't registered."],
      ])("%s", async (_, change, message) => {
        await expectInvalidLinkPage(await go(browser, change(valid())), message);
      });

      test.each(["client_id", "redirect_uri"])("a repeated %s, even with an unknown client", async (name) => {
        const p = valid();
        await expectInvalidLinkPage(await go(browser, `${new URLSearchParams(p)}&${name}=${encodeURIComponent(p[name]!)}`), "A parameter is repeated.");
        await expectInvalidLinkPage(await go(browser, `client_id=nobody&client_id=nobody&redirect_uri=x`), "A parameter is repeated.");
      });

      test("an unknown client is reported before the other parameters are read", async () => {
        await expectInvalidLinkPage(await go(browser, "client_id=nobody&response_type=token"), "The app that sent you here is not registered.");
      });
    });

    describe("errors sent back to the client", () => {
      async function expectBack(res: Response, error: string, description: string, state: string | null) {
        expect(res.status).toBe(302);
        expect(res.headers.get("Location")).toBe(back(REDIRECTS.wiki!, { error, error_description: description, ...(state !== null ? { state } : {}) }));
        await res.body?.cancel();
      }

      test.each(["response_type", "code_challenge", "code_challenge_method", "scope", "nonce", "prompt", "max_age", "login_hint"])(
        "a repeated %s is invalid_request, with the state sent",
        async (name) => {
          const p = valid({ prompt: "login", max_age: "60", login_hint: "alice" });
          await expectBack(await go(browser, `${new URLSearchParams(p)}&${name}=${encodeURIComponent(p[name]!)}`), "invalid_request", "A parameter is repeated.", p.state!);
        },
      );

      test("a repeated state is invalid_request, with no state to send back", async () => {
        const p = valid();
        await expectBack(await go(browser, `${new URLSearchParams(p)}&state=other`), "invalid_request", "A parameter is repeated.", null);
        await expectBack(await go(browser, `${new URLSearchParams(p)}&state=${encodeURIComponent(p.state!)}`), "invalid_request", "A parameter is repeated.", null);
      });

      test("a repeated parameter auth doesn't read is ignored", async () => {
        const res = await go(browser, `${new URLSearchParams(valid())}&foo=1&foo=2`);
        expect(new URL(res.headers.get("Location")!).searchParams.get("code")).toMatch(CODE);
      });

      test.each([
        ["missing", null],
        ["empty", ""],
        ["token", "token"],
        ["code id_token", "code id_token"],
        ["CODE", "CODE"],
      ])("response_type %s is unsupported_response_type", async (_, value) => {
        const p = value === null ? without(valid(), "response_type") : valid({ response_type: value });
        await expectBack(await go(browser, p), "unsupported_response_type", "Only response_type=code is supported.", p.state!);
      });

      test("response_type is checked before state", async () => {
        await expectBack(await go(browser, without(valid({ response_type: "token" }), "state")), "unsupported_response_type", "Only response_type=code is supported.", null);
      });

      test("a missing or empty state is invalid_request", async () => {
        await expectBack(await go(browser, without(valid(), "state")), "invalid_request", "state is required.", null);
        // An empty one goes back as sent.
        const res = await go(browser, valid({ state: "" }));
        expect(res.headers.get("Location")).toBe(back(REDIRECTS.wiki!, { error: "invalid_request", error_description: "state is required.", state: "" }));
      });

      test("a state of 1024 characters is accepted; 1025 is refused, and echoed", async () => {
        const ok = await go(browser, valid({ state: "s".repeat(1024) }));
        const loc = new URL(ok.headers.get("Location")!);
        expect(loc.searchParams.get("state")).toBe("s".repeat(1024));
        expect(loc.searchParams.get("code")).toMatch(CODE);
        const long = "s".repeat(1025);
        await expectBack(await go(browser, valid({ state: long })), "invalid_request", "state is at most 1024 characters.", long);
        // Counted in UTF-16 units, as both servers count every length.
        await expectBack(await go(browser, valid({ state: "\u{1f600}".repeat(513) })), "invalid_request", "state is at most 1024 characters.", "\u{1f600}".repeat(513));
        expect(new URL((await go(browser, valid({ state: "\u{1f600}".repeat(512) }))).headers.get("Location")!).searchParams.get("code")).toMatch(CODE);
      });

      test("a state with unicode, spaces and reserved characters comes back intact", async () => {
        const state = "été & a=b/c?d#e +100% ☃";
        const res = await go(browser, valid({ state }));
        const loc = res.headers.get("Location")!;
        const code = new URL(loc).searchParams.get("code")!;
        expect(code).toMatch(CODE);
        expect(loc).toBe(back(REDIRECTS.wiki!, { code, state }));
      });

      test.each([
        ["no code_challenge", (p: Record<string, string>) => without(p, "code_challenge")],
        ["an empty code_challenge", (p: Record<string, string>) => ({ ...p, code_challenge: "" })],
        ["a code_challenge of 42 characters", (p: Record<string, string>) => ({ ...p, code_challenge: "a".repeat(42) })],
        ["a code_challenge of 44 characters", (p: Record<string, string>) => ({ ...p, code_challenge: "a".repeat(44) })],
        ["a code_challenge in standard Base64", (p: Record<string, string>) => ({ ...p, code_challenge: `${"a".repeat(42)}+` })],
        ["a code_challenge with padding", (p: Record<string, string>) => ({ ...p, code_challenge: `${"a".repeat(42)}=` })],
        ["no code_challenge_method", (p: Record<string, string>) => without(p, "code_challenge_method")],
        ["code_challenge_method plain", (p: Record<string, string>) => ({ ...p, code_challenge_method: "plain" })],
        ["code_challenge_method s256", (p: Record<string, string>) => ({ ...p, code_challenge_method: "s256" })],
      ])("%s is invalid_request", async (_, change) => {
        const p: Record<string, string> = change(valid());
        await expectBack(await go(browser, p), "invalid_request", "PKCE is required: code_challenge with code_challenge_method=S256.", p.state!);
      });

      test.each([
        ["openid without a nonce", { scope: "openid profile" }, ["nonce"], "nonce is required with the openid scope."],
        ["openid with an empty nonce", { scope: "openid", nonce: "" }, [], "nonce is required with the openid scope."],
        ["a nonce of 1025 characters", { nonce: "n".repeat(1025) }, [], "nonce is too long."],
        ["a nonce of 1025 characters without openid", { scope: "", nonce: "n".repeat(1025) }, [], "nonce is too long."],
        ["prompt=consent", { prompt: "consent" }, [], "prompt may be none or login."],
        ["an empty prompt", { prompt: "" }, [], "prompt may be none or login."],
        ["prompt=none login", { prompt: "none login" }, [], "prompt may be none or login."],
        ["prompt=NONE", { prompt: "NONE" }, [], "prompt may be none or login."],
        ["an empty max_age", { max_age: "" }, [], "max_age must be a whole number of seconds."],
        ["a negative max_age", { max_age: "-1" }, [], "max_age must be a whole number of seconds."],
        ["a fractional max_age", { max_age: "1.5" }, [], "max_age must be a whole number of seconds."],
        ["a max_age of 10 digits", { max_age: "1234567890" }, [], "max_age must be a whole number of seconds."],
        ["a max_age with a sign", { max_age: "+5" }, [], "max_age must be a whole number of seconds."],
        ["a max_age that is a word", { max_age: "day" }, [], "max_age must be a whole number of seconds."],
      ])("%s is invalid_request", async (_, more: Record<string, string>, drop: string[], description) => {
        const p = without(valid(more), ...drop);
        await expectBack(await go(browser, p), "invalid_request", description, p.state!);
      });

      test("the checks run in order: PKCE before nonce before prompt before max_age", async () => {
        const p = valid({ code_challenge: "x", nonce: "", prompt: "x", max_age: "x" });
        await expectBack(await go(browser, p), "invalid_request", "PKCE is required: code_challenge with code_challenge_method=S256.", p.state!);
        const q = valid({ nonce: "", prompt: "x", max_age: "x" });
        await expectBack(await go(browser, q), "invalid_request", "nonce is required with the openid scope.", q.state!);
        const r = valid({ prompt: "x", max_age: "x" });
        await expectBack(await go(browser, r), "invalid_request", "prompt may be none or login.", r.state!);
      });

      test("errors are checked before the session: none needed for them", async () => {
        const p = valid({ prompt: "bogus" });
        await expectBack(await go(stack.browser(), p), "invalid_request", "prompt may be none or login.", p.state!);
      });
    });

    describe("what is accepted", () => {
      test.each([
        ["a nonce of 1024 characters", { nonce: "n".repeat(1024) }, []],
        ["no openid scope and no nonce", { scope: "profile email" }, ["nonce"]],
        ["no scope at all and no nonce", {}, ["scope", "nonce"]],
        ["a scope with extra spaces", { scope: "  openid  profile " }, []],
        ["prompt=none with a session", { prompt: "none" }, []],
        ["max_age=0 with a session just made", { max_age: "0" }, []],
        ["max_age of 9 digits", { max_age: "999999999" }, []],
        ["a login_hint", { login_hint: "alice" }, []],
      ])("%s", async (_, more: Record<string, string>, drop: string[]) => {
        const fresh = await stack.session(user);
        const p = without(valid(more), ...drop);
        const res = await go(fresh, p);
        expect(res.status).toBe(302);
        const code = new URL(res.headers.get("Location")!).searchParams.get("code")!;
        expect(code).toMatch(CODE);
        expect(res.headers.get("Location")).toBe(back(REDIRECTS.wiki!, { code, state: p.state! }));
      });

      test("the code comes back to an https redirect URI with code and state, and nothing else", async () => {
        const p = valid();
        const res = await go(browser, p);
        expect(res.status).toBe(302);
        const loc = res.headers.get("Location")!;
        const url = new URL(loc);
        expect([...url.searchParams.keys()]).toEqual(["code", "state"]);
        expect(loc).toBe(`${REDIRECTS.wiki}?code=${url.searchParams.get("code")}&state=${p.state}`);
        expect(res.headers.getSetCookie()).toEqual([]);
        await res.body?.cancel();
        // Stored hashed, bound to the client, session, redirect URI, challenge and nonce, for 60 seconds.
        const [row] = await stack.db`
          SELECT client_id, session_id, redirect_uri, code_challenge, nonce, used_at,
                 extract(epoch FROM expires_at - now())::int AS ttl
          FROM auth_codes WHERE code_hash = ${sha256(url.searchParams.get("code")!)}`;
        expect(row).toMatchObject({ client_id: "wiki", session_id: browser.sessionId, redirect_uri: REDIRECTS.wiki, code_challenge: p.code_challenge, nonce: p.nonce, used_at: null });
        expect(row.ttl).toBeGreaterThan(55);
        expect(row.ttl).toBeLessThanOrEqual(60);
      });

      test("the code comes back to a private-use-scheme redirect URI", async () => {
        const { browser: b } = await signedIn({ tasks: "user" });
        const { code, params, location } = await codeFor(b, "tasks-ios");
        expect(location).toBe(`com.example.tasks:/auth/callback?code=${code}&state=${params.state}`);
      });

      test("a nonce is stored as null when none is sent", async () => {
        const fresh = await stack.session(user);
        const { code } = await codeFor(fresh, "wiki", { scope: "profile", nonce: null });
        const [row] = await stack.db`SELECT nonce FROM auth_codes WHERE code_hash = ${sha256(code)}`;
        expect(row.nonce).toBeNull();
      });
    });

    describe("asking for a sign-in", () => {
      const loginLocation = (p: Record<string, string>, hint?: string) => {
        const q = new URLSearchParams(p);
        q.delete("prompt");
        q.delete("max_age");
        const login = new URLSearchParams({ return_to: `/oauth/authorize?${q}` });
        if (hint !== undefined) login.set("login_hint", hint);
        return `/login?${login}`;
      };

      async function expectLogin(res: Response, location: string) {
        expect(res.status).toBe(302);
        expect(res.headers.get("Location")).toBe(location);
        await res.body?.cancel();
      }

      test("without a session: to /login, back to the same request", async () => {
        const p = valid();
        await expectLogin(await go(stack.browser(), p), loginLocation(p));
      });

      test("a cookie that is not a live session is no session", async () => {
        const p = valid();
        const b = stack.browser();
        b.cookies.set("__Host-auth", "not-a-token");
        await expectLogin(await go(b, p), loginLocation(p));
        b.cookies.set("__Host-auth", randomToken());
        await expectLogin(await go(b, p), loginLocation(p));
        const expired = await stack.session(user, { expiresIn: "-1 second" });
        await expectLogin(await go(expired, p), loginLocation(p));
        const ended = await stack.session(user, { endsIn: "-1 second" });
        await expectLogin(await go(ended, p), loginLocation(p));
      });

      test("a disabled user's session is no session", async () => {
        const { user: u, browser: b } = await signedIn({ wiki: "member" });
        await stack.db`UPDATE users SET disabled_at = now() WHERE id = ${u.id}`;
        const p = valid();
        await expectLogin(await go(b, p), loginLocation(p));
      });

      test("prompt=login asks again; prompt and max_age are left out of return_to", async () => {
        const p = valid({ prompt: "login", max_age: "100", login_hint: "alice@example.com" });
        await expectLogin(await go(browser, p), loginLocation(p, "alice@example.com"));
      });

      test("max_age shorter than the sign-in's age asks again; as long or longer doesn't", async () => {
        const { browser: old } = await signedIn({ wiki: "member" }, { authAge: 120 });
        const p = valid({ max_age: "60" });
        await expectLogin(await go(old, p), loginLocation(p));
        const res = await go(old, valid({ max_age: "600" }));
        expect(new URL(res.headers.get("Location")!).searchParams.get("code")).toMatch(CODE);
      });

      test("login_hint is passed on up to 254 characters, and dropped past that", async () => {
        const hint254 = `${"a".repeat(242)}@example.com`;
        expect(hint254).toHaveLength(254);
        const p = valid({ login_hint: hint254 });
        await expectLogin(await go(stack.browser(), p), loginLocation(p, hint254));
        const hint255 = `a${hint254}`;
        const q = valid({ login_hint: hint255 });
        await expectLogin(await go(stack.browser(), q), loginLocation(q));
        // An empty hint is no hint.
        const r = valid({ login_hint: "" });
        await expectLogin(await go(stack.browser(), r), loginLocation(r));
        const u = valid({ login_hint: "élodie" });
        await expectLogin(await go(stack.browser(), u), loginLocation(u, "élodie"));
      });

      test("prompt=none without a session is login_required at the redirect URI", async () => {
        const p = valid({ prompt: "none" });
        const res = await go(stack.browser(), p);
        expect(res.status).toBe(302);
        expect(res.headers.get("Location")).toBe(back(REDIRECTS.wiki!, { error: "login_required", error_description: "The user is not signed in.", state: p.state! }));
      });

      test("prompt=none with a sign-in older than max_age is login_required", async () => {
        const { browser: old } = await signedIn({ wiki: "member" }, { authAge: 120 });
        const p = valid({ prompt: "none", max_age: "60" });
        const res = await go(old, p);
        expect(res.headers.get("Location")).toBe(back(REDIRECTS.wiki!, { error: "login_required", error_description: "The user is not signed in.", state: p.state! }));
      });
    });

    describe("access", () => {
      test("a user without a role gets the 403 page, and no code is made", async () => {
        const { user: u, browser: b } = await signedIn({ wiki: "member" });
        const p = authorizeParams("notes", REDIRECTS.notes!, pkce().challenge);
        const res = await go(b, p);
        expect(res.status).toBe(403);
        expect(await pageOf(res)).toEqual({
          status: 403,
          title: "No access",
          h1: "No access",
          message: "You don't have access to notes. Ask an administrator for access.",
          links: [{ href: "/account", text: "Your account" }],
        });
        expect(await stack.db`SELECT 1 FROM auth_codes a JOIN sessions s ON s.id = a.session_id WHERE s.user_id = ${u.id}`).toHaveLength(0);
        expect(await stack.db`SELECT 1 FROM access WHERE user_id = ${u.id} AND service = 'notes'`).toHaveLength(0);
      });

      test("an invite-only service grants nothing at sign-in", async () => {
        const { user: u, browser: b } = await signedIn({});
        const res = await go(b, authorizeParams("wiki", REDIRECTS.wiki!, pkce().challenge));
        expect(res.status).toBe(403);
        expect((await pageOf(res)).message).toBe("You don't have access to wiki. Ask an administrator for access.");
        expect(await stack.db`SELECT 1 FROM access WHERE user_id = ${u.id}`).toHaveLength(0);
      });

      test("prompt=none without a role is access_denied", async () => {
        const { browser: b } = await signedIn({});
        const p = authorizeParams("notes", REDIRECTS.notes!, pkce().challenge, { prompt: "none" });
        const res = await go(b, p);
        expect(res.headers.get("Location")).toBe(back(REDIRECTS.notes!, { error: "access_denied", error_description: "The user has no access to this service.", state: p.state! }));
      });

      test("an open service gives its default role at the first sign-in, audited and announced", async () => {
        const { user: u, browser: b } = await signedIn({});
        const { code } = await codeFor(b, "tasks");
        expect(code).toMatch(CODE);
        const [row] = await stack.db`SELECT role, granted_by FROM access WHERE user_id = ${u.id} AND service = 'tasks'`;
        expect(row).toEqual({ role: "user", granted_by: u.id });
        const audits = (await stack.audit("access.put")).filter((a) => a.user_id === u.id);
        expect(audits).toHaveLength(1);
        expect(audits[0]).toMatchObject({ actor: u.id, ip: b.ip, detail: { service: "tasks", role: "user", previous: null, reason: "open_signup" } });
        const events = (await stack.outbox("tasks")).filter((e) => e.type === "access.changed" && e.payload.sub === u.id);
        expect(events.map((e) => e.payload)).toEqual([{ sub: u.id, role: "user" }]);
        await stack.http.waitForEvent("tasks", "access.changed", (e) => e.payload.sub === u.id);
        // The second sign-in finds the row: nothing more is written.
        await codeFor(b, "tasks-ios");
        expect((await stack.audit("access.put")).filter((a) => a.user_id === u.id)).toHaveLength(1);
        expect((await stack.outbox("tasks")).filter((e) => e.type === "access.changed" && e.payload.sub === u.id)).toHaveLength(1);
      });

      test("prompt=none on an open service also grants the default role", async () => {
        const { user: u, browser: b } = await signedIn({});
        await codeFor(b, "tasks", { prompt: "none" });
        expect(await stack.db`SELECT role FROM access WHERE user_id = ${u.id} AND service = 'tasks'`).toEqual([{ role: "user" }]);
      });

      test("an MFA role without a second factor in the session: to the second-factor sign-in when the user has one", async () => {
        const { browser: b } = await signedIn({ wiki: "admin" }, { totp: true });
        const qs = new URLSearchParams(valid()).toString();
        const res = await go(b, qs);
        expect(res.status).toBe(302);
        expect(res.headers.get("Location")).toBe(`/login?${new URLSearchParams({ return_to: `/oauth/authorize?${qs}`, second_factor: "wiki" })}`);
      });

      test("an MFA role and no factor enrolled: to /mfa-required", async () => {
        const { browser: b } = await signedIn({ wiki: "owner" });
        const qs = new URLSearchParams(valid()).toString();
        const res = await go(b, qs);
        expect(res.status).toBe(302);
        expect(res.headers.get("Location")).toBe(`/mfa-required?${new URLSearchParams({ service: "wiki", return_to: `/oauth/authorize?${qs}` })}`);
      });

      test("an MFA role with prompt=none is interaction_required", async () => {
        const { browser: b } = await signedIn({ wiki: "admin" }, { totp: true });
        const p = valid({ prompt: "none" });
        const res = await go(b, p);
        expect(res.headers.get("Location")).toBe(
          back(REDIRECTS.wiki!, { error: "interaction_required", error_description: "This role needs a sign-in with a second factor.", state: p.state! }),
        );
      });

      test("an MFA role with a two-factor session gets a code", async () => {
        const { browser: b } = await signedIn({ wiki: "admin" }, { totp: true, amr: ["pwd", "otp", "mfa"] });
        const { code } = await codeFor(b, "wiki");
        expect(code).toMatch(CODE);
      });

      test("otp without mfa in the session's methods is not a second factor", async () => {
        const { browser: b } = await signedIn({ wiki: "admin" }, { totp: true, amr: ["pwd", "otp"] });
        const res = await go(b, valid());
        expect(res.headers.get("Location")).toStartWith("/login?");
      });
    });

    test("a registered redirect URI with a query string keeps it, and the parameters are added", async () => {
      const services = (events: (s: string) => string) => {
        const doc = defaultServices(events);
        doc.services.find((s: any) => s.name === "wiki").clients[0].redirect_uris.push("https://wiki.example.com/cb?tenant=a&x=%20y");
        return doc;
      };
      const other = await Stack.start({ services });
      try {
        const u = await other.user({ username: uname("qs"), access: { wiki: "member" } });
        const b = await other.session(u);
        const uri = "https://wiki.example.com/cb?tenant=a&x=%20y";
        const { verifier, challenge } = pkce();
        const p = authorizeParams("wiki", uri, challenge);
        const res = await b.request(`/oauth/authorize?${new URLSearchParams(p)}`);
        const loc = res.headers.get("Location")!;
        const code = new URL(loc).searchParams.get("code")!;
        expect(loc).toBe(back(uri, { code, state: p.state! }));
        expect(loc).toStartWith("https://wiki.example.com/cb?tenant=a&x=");
        const err = await b.request(`/oauth/authorize?${new URLSearchParams({ ...p, response_type: "token" })}`);
        expect(err.headers.get("Location")).toBe(back(uri, { error: "unsupported_response_type", error_description: "Only response_type=code is supported.", state: p.state! }));
        const tokens = await backChannel(other, "/oauth/token", { grant_type: "authorization_code", code, redirect_uri: uri, code_verifier: verifier }, other.basic("wiki"));
        expect(tokens.status).toBe(200);
        await tokens.body?.cancel();
      } finally {
        await other.stop();
      }
    });
  });

  // ------------------------------------------------------------ code grant

  describe("POST /oauth/token: authorization_code", () => {
    test("a confidential client gets an access token, a refresh token and an ID token", async () => {
      const { user, browser } = await signedIn({ wiki: "member" }, { authAge: 30 });
      const { code, verifier, params } = await codeFor(browser, "wiki");
      const res = await exchange("wiki", code, verifier);
      expect(res.status).toBe(200);
      expectJson(res);
      expect(res.headers.get("Pragma")).toBe("no-cache");
      const body = (await res.json()) as Record<string, any>;
      expect(Object.keys(body).sort()).toEqual(["access_token", "expires_in", "id_token", "refresh_token", "token_type"]);
      expect(body.token_type).toBe("Bearer");
      expect(body.expires_in).toBe(600);
      expect(body.refresh_token).toMatch(REFRESH);

      const at = decodeJwt(body.access_token);
      expect(at.header).toEqual({ alg: "EdDSA", typ: "at+jwt", kid: (await stack.jwks()).keys[0]!.kid });
      const claims = await stack.verified(body.access_token, "at+jwt");
      expect(Object.keys(claims).sort()).toEqual(ACCESS_CLAIMS);
      expect(claims).toMatchObject({ iss: stack.issuer, sub: user.id, aud: "wiki", sid: browser.sessionId, username: user.username, name: user.name, role: "member" });
      expect(claims.exp - claims.iat).toBe(600);
      expect(Math.abs(claims.iat - Date.now() / 1000)).toBeLessThan(10);

      const it = decodeJwt(body.id_token);
      expect(it.header).toEqual({ alg: "EdDSA", typ: "JWT", kid: at.header.kid });
      const id = await stack.verified(body.id_token, "JWT");
      expect(Object.keys(id).sort()).toEqual(ID_CLAIMS);
      const [s] = await stack.db`SELECT extract(epoch FROM auth_time)::bigint AS t FROM sessions WHERE id = ${browser.sessionId}`;
      expect(id).toMatchObject({
        iss: stack.issuer,
        sub: user.id,
        aud: "wiki",
        sid: browser.sessionId,
        username: user.username,
        name: user.name,
        role: "member",
        nonce: params.nonce,
        auth_time: Number(s.t),
        amr: ["pwd"],
        email: user.email,
        email_verified: true,
      });
      expect(id.exp - id.iat).toBe(600);
      expect(Math.abs(id.auth_time - (Date.now() / 1000 - 30))).toBeLessThan(10);

      // Stored hashed, bound to the SSO session and ending with it.
      const [rt] = await stack.db`
        SELECT r.family_id, r.session_id, r.user_id, r.client_id, r.expires_at = s.ends_at AS with_session, r.rotated_at, r.revoked_at
        FROM refresh_tokens r JOIN sessions s ON s.id = r.session_id WHERE r.token_hash = ${sha256(body.refresh_token)}`;
      expect(rt).toEqual({ family_id: browser.sessionId, session_id: browser.sessionId, user_id: user.id, client_id: "wiki", with_session: true, rotated_at: null, revoked_at: null });
      const [used] = await stack.db`SELECT used_at IS NOT NULL AS used FROM auth_codes WHERE code_hash = ${sha256(code)}`;
      expect(used.used).toBe(true);
    });

    test("the ID token has no nonce when none was sent; a user without email has null and false", async () => {
      const { user, browser } = await signedIn({ wiki: "admin" }, { email: null, totp: true, amr: ["pwd", "otp", "mfa"] });
      const { code, verifier } = await codeFor(browser, "wiki", { scope: "profile", nonce: null });
      const body = (await (await exchange("wiki", code, verifier)).json()) as TokenSet;
      const id = await stack.verified(body.id_token!, "JWT");
      expect("nonce" in id).toBe(false);
      expect(Object.keys(id).sort()).toEqual(ID_CLAIMS.filter((c) => c !== "nonce"));
      expect(id).toMatchObject({ sub: user.id, role: "admin", amr: ["pwd", "otp", "mfa"], email: null, email_verified: false });
    });

    test("an unverified email is reported as such", async () => {
      const user = await stack.user({ username: uname("unv"), access: { wiki: "member" }, emailVerified: false });
      const browser = await stack.session(user);
      const body = await tokensFor(browser, "wiki");
      expect(await stack.verified(body.id_token!, "JWT")).toMatchObject({ email: user.email, email_verified: false });
    });

    test("a public client gets a rotating family of its own, whose id is the sid", async () => {
      const { user, browser } = await signedIn({ tasks: "user" });
      const { code, verifier } = await codeFor(browser, "tasks-ios");
      const res = await exchange("tasks-ios", code, verifier);
      expect(res.status).toBe(200);
      expect(res.headers.get("Pragma")).toBe("no-cache");
      const body = (await res.json()) as Record<string, any>;
      expect(Object.keys(body).sort()).toEqual(["access_token", "expires_in", "id_token", "refresh_token", "token_type"]);
      const at = await stack.verified(body.access_token, "at+jwt");
      expect(at.aud).toBe("tasks");
      expect(at.sid).toMatch(SID);
      expect(at.sid).not.toBe(browser.sessionId);
      const id = await stack.verified(body.id_token, "JWT");
      expect(id.aud).toBe("tasks-ios");
      expect(id.sid).toBe(at.sid);
      const [rt] = await stack.db`
        SELECT family_id, session_id, user_id, client_id, amr, extract(epoch FROM expires_at - now())::int AS ttl
        FROM refresh_tokens WHERE token_hash = ${sha256(body.refresh_token)}`;
      expect(rt).toMatchObject({ family_id: at.sid, session_id: null, user_id: user.id, client_id: "tasks-ios", amr: ["pwd"] });
      expect(Math.abs(rt.ttl - 30 * 86400)).toBeLessThan(60);
    });

    test("the exchange keeps the SSO session alive", async () => {
      const { browser } = await signedIn({ wiki: "member" });
      const { code, verifier } = await codeFor(browser, "wiki");
      await stack.db`UPDATE sessions SET last_seen_at = now() - interval '1 hour', expires_at = now() + interval '1 hour' WHERE id = ${browser.sessionId}`;
      expect((await exchange("wiki", code, verifier)).status).toBe(200);
      const [s] = await stack.db`
        SELECT last_seen_at > now() - interval '1 minute' AS seen, extract(epoch FROM expires_at - now())::int AS idle FROM sessions WHERE id = ${browser.sessionId}`;
      expect(s.seen).toBe(true);
      expect(Math.abs(s.idle - 7 * 86400)).toBeLessThan(60);
    });

    test.each([
      ["no code", ["code"]],
      ["no redirect_uri", ["redirect_uri"]],
      ["no code_verifier", ["code_verifier"]],
      ["nothing", ["code", "redirect_uri", "code_verifier"]],
    ])("%s is invalid_request", async (_, drop) => {
      const fields: Record<string, string> = { grant_type: "authorization_code", code: "abc123", redirect_uri: REDIRECTS.wiki!, code_verifier: "v".repeat(43) };
      for (const d of drop) delete fields[d];
      const res = await form("/oauth/token", fields, stack.basic("wiki"));
      expect(res.headers.get("Pragma")).toBeNull();
      expect(await errorOf(res)).toEqual({ status: 400, error: "invalid_request", description: "code, redirect_uri and code_verifier are required." });
      const empty = await form("/oauth/token", { ...fields, ...Object.fromEntries(drop.map((d) => [d, ""])) }, stack.basic("wiki"));
      expect(await errorOf(empty)).toEqual({ status: 400, error: "invalid_request", description: "code, redirect_uri and code_verifier are required." });
    });

    test.each(["code", "redirect_uri", "code_verifier", "grant_type"])("a repeated %s is refused", async (name) => {
      const fields = new URLSearchParams({ grant_type: "authorization_code", code: "abc123", redirect_uri: REDIRECTS.wiki!, code_verifier: "v".repeat(43) });
      fields.append(name, fields.get(name)!);
      expect(await errorOf(await form("/oauth/token", fields.toString(), stack.basic("wiki")))).toEqual({
        status: 400,
        error: "invalid_request",
        description: `The parameter "${name}" is repeated.`,
      });
    });

    test.each([
      ["42 characters", "a".repeat(42)],
      ["129 characters", "a".repeat(129)],
      ["a character outside the unreserved set", `${"a".repeat(42)}+`],
      ["a space", `${"a".repeat(42)} `],
      ["unicode", `${"a".repeat(42)}é`],
    ])("a code_verifier of %s is malformed, and the code is not spent", async (_, bad) => {
      const { browser } = await signedIn({ wiki: "member" });
      const { code, verifier } = await codeFor(browser, "wiki");
      expect(await errorOf(await exchange("wiki", code, bad))).toEqual({ status: 400, error: "invalid_request", description: "code_verifier is malformed." });
      expect((await exchange("wiki", code, verifier)).status).toBe(200);
    });

    test("a verifier of 43 and of 128 unreserved characters is well formed", async () => {
      for (const verifier of [`${"a".repeat(39)}-._~`, "Z9".repeat(64)]) {
        const { browser } = await signedIn({ wiki: "member" });
        const challenge = b64u(sha256(verifier));
        const p = authorizeParams("wiki", REDIRECTS.wiki!, challenge);
        const res = await browser.request(`/oauth/authorize?${new URLSearchParams(p)}`);
        const code = new URL(res.headers.get("Location")!).searchParams.get("code")!;
        expect((await exchange("wiki", code, verifier)).status).toBe(200);
      }
    });

    test("a code is single use", async () => {
      const { browser } = await signedIn({ wiki: "member" });
      const { code, verifier } = await codeFor(browser, "wiki");
      expect((await exchange("wiki", code, verifier)).status).toBe(200);
      expect(await errorOf(await exchange("wiki", code, verifier))).toEqual(INVALID_CODE);
    });

    test("racing requests redeem a code once", async () => {
      const { browser } = await signedIn({ wiki: "member" });
      const { code, verifier } = await codeFor(browser, "wiki");
      const all = await Promise.all(Array.from({ length: 5 }, () => exchange("wiki", code, verifier)));
      expect(all.map((r) => r.status).sort()).toEqual([200, 400, 400, 400, 400]);
    });

    test.each([
      ["a wrong verifier", (c: { verifier: string }) => ({ clientId: "wiki", verifier: pkce().verifier, redirect: REDIRECTS.wiki! })],
      ["another redirect URI", (c: { verifier: string }) => ({ clientId: "wiki", verifier: c.verifier, redirect: "https://wiki.example.com/other" })],
      ["another client", (c: { verifier: string }) => ({ clientId: "mailbox", verifier: c.verifier, redirect: REDIRECTS.wiki! })],
      ["a public client of another service", (c: { verifier: string }) => ({ clientId: "tasks-ios", verifier: c.verifier, redirect: REDIRECTS.wiki! })],
    ])("%s is invalid_grant, and spends the code", async (_, wrong) => {
      const { browser } = await signedIn({ wiki: "member", mailbox: "user" });
      const c = await codeFor(browser, "wiki");
      const w = wrong(c);
      expect(await errorOf(await exchange(w.clientId, c.code, w.verifier, w.redirect))).toEqual(INVALID_CODE);
      expect(await errorOf(await exchange("wiki", c.code, c.verifier))).toEqual(INVALID_CODE);
    });

    test.each([
      ["an unknown code", "abc123"],
      ["a code of 257 characters", "a".repeat(257)],
    ])("%s is invalid_grant", async (_, code) => {
      expect(await errorOf(await exchange("wiki", code, pkce().verifier))).toEqual(INVALID_CODE);
    });

    test("an expired code is invalid_grant", async () => {
      const { browser } = await signedIn({ wiki: "member" });
      const { code, verifier } = await codeFor(browser, "wiki");
      await stack.db`UPDATE auth_codes SET expires_at = now() - interval '1 second' WHERE code_hash = ${sha256(code)}`;
      expect(await errorOf(await exchange("wiki", code, verifier))).toEqual(INVALID_CODE);
    });

    test.each([
      ["the session was ended", (u: TestUser, sid: string) => stack.db`DELETE FROM sessions WHERE id = ${sid}`],
      ["the session expired", (u: TestUser, sid: string) => stack.db`UPDATE sessions SET expires_at = now() - interval '1 second' WHERE id = ${sid}`],
      ["the session reached its absolute end", (u: TestUser, sid: string) => stack.db`UPDATE sessions SET ends_at = now() - interval '1 second' WHERE id = ${sid}`],
      ["the user was disabled", (u: TestUser) => stack.db`UPDATE users SET disabled_at = now() WHERE id = ${u.id}`],
      ["the user's access was removed", (u: TestUser) => stack.db`DELETE FROM access WHERE user_id = ${u.id}`],
      ["the role now needs MFA", (u: TestUser) => stack.db`UPDATE access SET role = 'admin' WHERE user_id = ${u.id}`],
    ])("between authorization and exchange %s: invalid_grant", async (_, change) => {
      const { user, browser } = await signedIn({ wiki: "member" });
      const { code, verifier } = await codeFor(browser, "wiki");
      await change(user, browser.sessionId!);
      expect(await errorOf(await exchange("wiki", code, verifier))).toEqual(INVALID_CODE);
    });

    test("a role changed between authorization and exchange is the one in the tokens", async () => {
      const { user, browser } = await signedIn({ wiki: "admin" }, { amr: ["pwd", "otp", "mfa"] });
      const { code, verifier } = await codeFor(browser, "wiki");
      await stack.db`UPDATE access SET role = 'owner' WHERE user_id = ${user.id}`;
      const body = (await (await exchange("wiki", code, verifier)).json()) as TokenSet;
      expect((await stack.verified(body.access_token)).role).toBe("owner");
    });

    test.each([
      ["missing", null],
      ["empty", ""],
      ["password", "password"],
      ["client_credentials", "client_credentials"],
      ["implicit", "implicit"],
      ["Authorization_Code", "Authorization_Code"],
    ])("grant_type %s is unsupported_grant_type", async (_, grant) => {
      const fields: Record<string, string> = { username: "alice", password: "s3cret-pw" };
      if (grant !== null) fields.grant_type = grant;
      const res = await form("/oauth/token", fields, stack.basic("wiki"));
      expect(await errorOf(res)).toEqual({ status: 400, error: "unsupported_grant_type", description: "Use authorization_code or refresh_token." });
    });

    test("sixty token requests a minute per client, then 429 with Retry-After", async () => {
      await stack.db`INSERT INTO throttle (key, window_start, hits) VALUES ('client:wiki:token', now(), 59)`;
      expect(await errorOf(await refresh("wiki", "rt_unknown"))).toEqual(INVALID_REFRESH);
      const res = await refresh("wiki", "rt_unknown");
      const retry = Number(res.headers.get("Retry-After"));
      expect(retry).toBeGreaterThan(0);
      expect(retry).toBeLessThanOrEqual(60);
      expect(await errorOf(res)).toEqual({ status: 429, error: "rate_limited", description: "Too many token requests." });
      // Counted per client, and after authentication: other clients aren't touched.
      expect(await errorOf(await refresh("tasks", "rt_unknown"))).toEqual(INVALID_REFRESH);
      const [row] = await stack.db`SELECT hits FROM throttle WHERE key = 'client:wiki:token'`;
      expect(row.hits).toBe(61);
    });

    test("an unauthenticated request doesn't count against the client", async () => {
      await form("/oauth/token", { grant_type: "refresh_token", refresh_token: "x" }, basic("wiki", "wrong"));
      expect(await stack.db`SELECT 1 FROM throttle WHERE key = 'client:wiki:token'`).toHaveLength(0);
    });

    test("a public client's limit is its own, and checked before the grant", async () => {
      await stack.db`INSERT INTO throttle (key, window_start, hits) VALUES ('client:tasks-ios:token', now(), 60)`;
      const res = await form("/oauth/token", { grant_type: "nonsense", client_id: "tasks-ios" });
      expect(res.headers.get("Retry-After")).not.toBeNull();
      expect(await errorOf(res)).toEqual({ status: 429, error: "rate_limited", description: "Too many token requests." });
    });

    test("a window that has passed starts again", async () => {
      await stack.db`INSERT INTO throttle (key, window_start, hits) VALUES ('client:wiki:token', now() - interval '61 seconds', 500)`;
      expect(await errorOf(await refresh("wiki", "rt_unknown"))).toEqual(INVALID_REFRESH);
    });
  });

  // ---------------------------------------------------------- refresh grant

  describe("POST /oauth/token: refresh_token", () => {
    test("a confidential client's token is not rotated and keeps the session's sid", async () => {
      const { user, browser } = await signedIn({ wiki: "member" });
      const tokens = await tokensFor(browser, "wiki");
      for (let i = 0; i < 2; i++) {
        const res = await refresh("wiki", tokens.refresh_token!);
        expect(res.status).toBe(200);
        expectJson(res);
        expect(res.headers.get("Pragma")).toBe("no-cache");
        const body = (await res.json()) as Record<string, any>;
        expect(Object.keys(body).sort()).toEqual(["access_token", "expires_in", "token_type"]);
        expect(body).toMatchObject({ token_type: "Bearer", expires_in: 600 });
        const claims = await stack.verified(body.access_token, "at+jwt");
        expect(Object.keys(claims).sort()).toEqual(ACCESS_CLAIMS);
        expect(claims).toMatchObject({ iss: stack.issuer, sub: user.id, aud: "wiki", sid: browser.sessionId, role: "member", username: user.username, name: user.name });
        expect(claims.exp - claims.iat).toBe(600);
      }
    });

    test("a new role is picked up at the next refresh", async () => {
      const { user, browser } = await signedIn({ tasks: "user", wiki: "member" }, { amr: ["pwd", "otp", "mfa"] });
      const tokens = await tokensFor(browser, "wiki");
      await stack.db`UPDATE access SET role = 'owner' WHERE user_id = ${user.id} AND service = 'wiki'`;
      const body = (await (await refresh("wiki", tokens.refresh_token!)).json()) as TokenSet;
      expect((await stack.verified(body.access_token)).role).toBe("owner");
    });

    test("a new name is picked up at the next refresh", async () => {
      const { user, browser } = await signedIn({ wiki: "member" });
      const tokens = await tokensFor(browser, "wiki");
      await stack.db`UPDATE users SET name = 'Alice Example', username = ${`${user.username}-x`} WHERE id = ${user.id}`;
      const body = (await (await refresh("wiki", tokens.refresh_token!)).json()) as TokenSet;
      expect(await stack.verified(body.access_token)).toMatchObject({ name: "Alice Example", username: `${user.username}-x` });
    });

    test("a refresh keeps the SSO session alive, up to its absolute end", async () => {
      const { browser } = await signedIn({ wiki: "member" });
      const tokens = await tokensFor(browser, "wiki");
      await stack.db`UPDATE sessions SET last_seen_at = now() - interval '2 hours', expires_at = now() + interval '1 hour' WHERE id = ${browser.sessionId}`;
      expect((await refresh("wiki", tokens.refresh_token!)).status).toBe(200);
      const [s] = await stack.db`
        SELECT last_seen_at > now() - interval '1 minute' AS seen, extract(epoch FROM expires_at - now())::int AS idle FROM sessions WHERE id = ${browser.sessionId}`;
      expect(s.seen).toBe(true);
      expect(Math.abs(s.idle - 7 * 86400)).toBeLessThan(60);
      await stack.db`UPDATE sessions SET ends_at = now() + interval '2 days', expires_at = now() + interval '1 hour' WHERE id = ${browser.sessionId}`;
      expect((await refresh("wiki", tokens.refresh_token!)).status).toBe(200);
      const [t] = await stack.db`SELECT expires_at = ends_at AS capped FROM sessions WHERE id = ${browser.sessionId}`;
      expect(t.capped).toBe(true);
    });

    test("missing or empty refresh_token is invalid_request", async () => {
      for (const fields of [{ grant_type: "refresh_token" }, { grant_type: "refresh_token", refresh_token: "" }] as Record<string, string>[]) {
        expect(await errorOf(await form("/oauth/token", fields, stack.basic("wiki")))).toEqual({
          status: 400,
          error: "invalid_request",
          description: "refresh_token is required.",
        });
      }
    });

    test.each([
      ["an unknown token", "rt_abc123"],
      ["a token of 257 characters", `rt_${"a".repeat(254)}`],
    ])("%s is invalid_grant", async (_, token) => {
      expect(await errorOf(await refresh("wiki", token))).toEqual(INVALID_REFRESH);
    });

    test("an access token is not a refresh token", async () => {
      const { browser } = await signedIn({ wiki: "member" });
      const tokens = await tokensFor(browser, "wiki");
      expect(await errorOf(await refresh("wiki", tokens.access_token))).toEqual(INVALID_REFRESH);
    });

    test.each([
      ["the SSO session ended", (u: TestUser, sid: string) => stack.db`DELETE FROM sessions WHERE id = ${sid}`],
      ["the SSO session expired", (u: TestUser, sid: string) => stack.db`UPDATE sessions SET expires_at = now() - interval '1 second' WHERE id = ${sid}`],
      ["the SSO session reached its end", (u: TestUser, sid: string) => stack.db`UPDATE sessions SET ends_at = now() - interval '1 second' WHERE id = ${sid}`],
      ["the token expired", (u: TestUser) => stack.db`UPDATE refresh_tokens SET expires_at = now() - interval '1 second' WHERE user_id = ${u.id}`],
      ["the token was revoked", (u: TestUser) => stack.db`UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = ${u.id}`],
      ["the user was disabled", (u: TestUser) => stack.db`UPDATE users SET disabled_at = now() WHERE id = ${u.id}`],
      ["the access was removed", (u: TestUser) => stack.db`DELETE FROM access WHERE user_id = ${u.id} AND service = 'wiki'`],
      ["the role now needs MFA", (u: TestUser) => stack.db`UPDATE access SET role = 'admin' WHERE user_id = ${u.id} AND service = 'wiki'`],
    ])("confidential, %s: invalid_grant", async (_, change) => {
      const { user, browser } = await signedIn({ wiki: "member" });
      const tokens = await tokensFor(browser, "wiki");
      await change(user, browser.sessionId!);
      expect(await errorOf(await refresh("wiki", tokens.refresh_token!))).toEqual(INVALID_REFRESH);
    });

    test("the SSO session's methods decide MFA: a step-up after sign-in lets an MFA role refresh", async () => {
      const { user, browser } = await signedIn({ wiki: "member" });
      const tokens = await tokensFor(browser, "wiki");
      await stack.db`UPDATE access SET role = 'admin' WHERE user_id = ${user.id}`;
      expect(await errorOf(await refresh("wiki", tokens.refresh_token!))).toEqual(INVALID_REFRESH);
      await stack.db`UPDATE sessions SET amr = '{pwd,otp,mfa}' WHERE id = ${browser.sessionId}`;
      expect((await refresh("wiki", tokens.refresh_token!)).status).toBe(200);
    });

    test("another client's token is invalid_grant, and stays good for its own client", async () => {
      const { browser } = await signedIn({ wiki: "member", mailbox: "user" });
      const tokens = await tokensFor(browser, "wiki");
      expect(await errorOf(await refresh("mailbox", tokens.refresh_token!))).toEqual(INVALID_REFRESH);
      expect(await errorOf(await refresh("tasks-ios", tokens.refresh_token!))).toEqual(INVALID_REFRESH);
      expect((await refresh("wiki", tokens.refresh_token!)).status).toBe(200);
    });

    describe("public clients", () => {
      async function publicTokens() {
        const { user, browser } = await signedIn({ tasks: "user" });
        const tokens = await tokensFor(browser, "tasks-ios");
        const sid = (await stack.verified(tokens.access_token)).sid as string;
        return { user, browser, tokens, sid };
      }

      test("each refresh rotates the token; the new one works, in the same family", async () => {
        const { user, tokens, sid } = await publicTokens();
        const res = await refresh("tasks-ios", tokens.refresh_token!);
        expect(res.status).toBe(200);
        expect(res.headers.get("Pragma")).toBe("no-cache");
        const body = (await res.json()) as Record<string, any>;
        expect(Object.keys(body).sort()).toEqual(["access_token", "expires_in", "refresh_token", "token_type"]);
        expect(body.refresh_token).toMatch(REFRESH);
        expect(body.refresh_token).not.toBe(tokens.refresh_token);
        expect(await stack.verified(body.access_token, "at+jwt")).toMatchObject({ sub: user.id, aud: "tasks", sid, role: "user" });
        const rows = await stack.db`
          SELECT token_hash = ${sha256(tokens.refresh_token!)} AS old, rotated_at IS NOT NULL AS rotated, family_id, amr,
                 extract(epoch FROM expires_at - now())::int AS ttl
          FROM refresh_tokens WHERE user_id = ${user.id} ORDER BY created_at`;
        expect(rows.map((r: any) => [r.old, r.rotated, r.family_id])).toEqual([
          [true, true, sid],
          [false, false, sid],
        ]);
        expect(rows[1].amr).toEqual(["pwd"]);
        expect(Math.abs(rows[1].ttl - 30 * 86400)).toBeLessThan(60);
        const next = await refresh("tasks-ios", body.refresh_token);
        expect(next.status).toBe(200);
        await next.body?.cancel();
      });

      test("the family outlives the SSO session it started from", async () => {
        const { browser, tokens } = await publicTokens();
        await stack.db`DELETE FROM sessions WHERE id = ${browser.sessionId}`;
        expect((await refresh("tasks-ios", tokens.refresh_token!)).status).toBe(200);
      });

      test("the old token still works for 30 seconds after rotation", async () => {
        const { user, tokens } = await publicTokens();
        const first = (await (await refresh("tasks-ios", tokens.refresh_token!)).json()) as TokenSet;
        await stack.db`UPDATE refresh_tokens SET rotated_at = now() - interval '25 seconds' WHERE token_hash = ${sha256(tokens.refresh_token!)}`;
        const again = await refresh("tasks-ios", tokens.refresh_token!);
        expect(again.status).toBe(200);
        const second = (await again.json()) as TokenSet;
        expect(second.refresh_token).toMatch(REFRESH);
        expect(second.refresh_token).not.toBe(first.refresh_token);
        // Both successors live; the grace runs from the first rotation.
        expect((await refresh("tasks-ios", first.refresh_token!)).status).toBe(200);
        expect((await refresh("tasks-ios", second.refresh_token!)).status).toBe(200);
        const [r] = await stack.db`SELECT extract(epoch FROM now() - rotated_at)::int AS age FROM refresh_tokens WHERE token_hash = ${sha256(tokens.refresh_token!)}`;
        expect(r.age).toBeGreaterThanOrEqual(24);
        expect(await stack.db`SELECT 1 FROM refresh_tokens WHERE user_id = ${user.id} AND revoked_at IS NOT NULL`).toHaveLength(0);
      });

      test("reuse past the grace period ends the whole family, audited, alerted and announced", async () => {
        const { user, tokens, sid } = await publicTokens();
        const next = (await (await refresh("tasks-ios", tokens.refresh_token!)).json()) as TokenSet;
        await stack.db`UPDATE refresh_tokens SET rotated_at = now() - interval '31 seconds' WHERE token_hash = ${sha256(tokens.refresh_token!)}`;
        expect(await errorOf(await refresh("tasks-ios", tokens.refresh_token!))).toEqual(INVALID_REFRESH);
        expect(await stack.db`SELECT 1 FROM refresh_tokens WHERE family_id = ${sid} AND revoked_at IS NULL`).toHaveLength(0);
        expect(await errorOf(await refresh("tasks-ios", next.refresh_token!))).toEqual(INVALID_REFRESH);
        const audits = (await stack.audit("refresh.reuse")).filter((a) => a.user_id === user.id);
        expect(audits).toHaveLength(1);
        expect(audits[0]).toMatchObject({ actor: null, ip: null, detail: { client: "tasks-ios" } });
        expect((await stack.outbox("tasks")).filter((e) => e.type === "session.ended" && e.payload.sid === sid).map((e) => e.payload)).toEqual([{ sid }]);
        await stack.http.waitForEvent("tasks", "session.ended", (e) => e.payload.sid === sid);
        expect(await stack.http.waitForAlert(`auth: a reused refresh token ended a session family of ${user.id} (tasks-ios)`)).toBe(
          `auth: a reused refresh token ended a session family of ${user.id} (tasks-ios)`,
        );
        // A revoked token presented again is merely refused: nothing more is written.
        expect(await errorOf(await refresh("tasks-ios", tokens.refresh_token!))).toEqual(INVALID_REFRESH);
        expect((await stack.audit("refresh.reuse")).filter((a) => a.user_id === user.id)).toHaveLength(1);
      });

      test.each([
        ["the token expired (30 days idle)", (u: TestUser) => stack.db`UPDATE refresh_tokens SET expires_at = now() - interval '1 second' WHERE user_id = ${u.id}`],
        ["the token was revoked", (u: TestUser) => stack.db`UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = ${u.id}`],
        ["the user was disabled", (u: TestUser) => stack.db`UPDATE users SET disabled_at = now() WHERE id = ${u.id}`],
        ["the role is gone", (u: TestUser) => stack.db`DELETE FROM access WHERE user_id = ${u.id}`],
      ])("public, %s: invalid_grant", async (_, change) => {
        const { user, tokens } = await publicTokens();
        await change(user);
        expect(await errorOf(await refresh("tasks-ios", tokens.refresh_token!))).toEqual(INVALID_REFRESH);
      });

      test("a public family keeps the sign-in's methods: a role needing MFA is refused without them", async () => {
        // A service where the public client's role needs MFA.
        const services = (events: (s: string) => string) => ({
          services: [
            {
              name: "tasks",
              roles: ["user", "admin"],
              mfa_roles: ["admin"],
              signup: "invite",
              clients: [{ id: "tasks-ios", type: "public", redirect_uris: ["com.example.tasks:/auth/callback"] }],
              events_url: events("tasks"),
            },
          ],
        });
        const other = await Stack.start({ services });
        try {
          const run = async (amr: string[]) => {
            const u = await other.user({ username: uname("pm"), access: { tasks: "user" } });
            const b = await other.session(u, { amr });
            const { verifier, challenge } = pkce();
            const p = authorizeParams("tasks-ios", REDIRECTS["tasks-ios"]!, challenge);
            const res = await b.request(`/oauth/authorize?${new URLSearchParams(p)}`);
            const code = new URL(res.headers.get("Location")!).searchParams.get("code")!;
            const t = (await (
              await backChannel(other, "/oauth/token", { grant_type: "authorization_code", code, redirect_uri: REDIRECTS["tasks-ios"]!, code_verifier: verifier, client_id: "tasks-ios" })
            ).json()) as TokenSet;
            await other.db`UPDATE access SET role = 'admin' WHERE user_id = ${u.id}`;
            // The SSO session's methods no longer matter: the family's do.
            await other.db`UPDATE sessions SET amr = '{pwd,otp,mfa}' WHERE user_id = ${u.id}`;
            return backChannel(other, "/oauth/token", { grant_type: "refresh_token", refresh_token: t.refresh_token!, client_id: "tasks-ios" });
          };
          expect(await errorOf(await run(["pwd"]))).toEqual(INVALID_REFRESH);
          const ok = await run(["pwd", "otp", "mfa"]);
          expect(ok.status).toBe(200);
          const body = (await ok.json()) as TokenSet;
          expect((await other.verified(body.access_token)).role).toBe("admin");
        } finally {
          await other.stop();
        }
      });

      test("a token issued to a confidential client is refused for a public client of the same id, and the reverse", async () => {
        const { user, browser } = await signedIn({ tasks: "user" });
        const insert = async (clientId: string, sessionId: string | null) => {
          const token = `rt_${randomToken()}`;
          const family = sessionId ?? newId("ses");
          await stack.db`
            INSERT INTO refresh_tokens (token_hash, family_id, session_id, user_id, client_id, expires_at, amr)
            VALUES (${sha256(token)}, ${family}, ${sessionId}, ${user.id}, ${clientId}, now() + interval '1 day', '{pwd}')`;
          return token;
        };
        // Rows of each shape work for the type they were issued to …
        expect((await refresh("tasks-ios", await insert("tasks-ios", null))).status).toBe(200);
        expect((await refresh("tasks", await insert("tasks", browser.sessionId))).status).toBe(200);
        // … and not for the other type under the same id.
        expect(await errorOf(await refresh("tasks-ios", await insert("tasks-ios", browser.sessionId)))).toEqual(INVALID_REFRESH);
        expect(await errorOf(await refresh("tasks", await insert("tasks", null)))).toEqual(INVALID_REFRESH);
      });
    });
  });

  // ---------------------------------------------------------------- revoke

  describe("POST /oauth/revoke", () => {
    test("a confidential client revokes that token only, audited", async () => {
      const { user, browser } = await signedIn({ wiki: "member" });
      const a = await tokensFor(browser, "wiki");
      const b = await tokensFor(browser, "wiki");
      const res = await form("/oauth/revoke", { token: a.refresh_token! }, stack.basic("wiki"));
      expect(res.status).toBe(200);
      expectJson(res);
      expect(await res.json()).toEqual({});
      expect(await errorOf(await refresh("wiki", a.refresh_token!))).toEqual(INVALID_REFRESH);
      expect((await refresh("wiki", b.refresh_token!)).status).toBe(200);
      const audits = (await stack.audit("token.revoke")).filter((x) => x.user_id === user.id);
      expect(audits).toHaveLength(1);
      expect(audits[0]).toMatchObject({ actor: "cli_wiki", ip: null, detail: { client: "wiki" } });
      // The SSO session is untouched, and nothing is announced.
      expect(await stack.db`SELECT 1 FROM sessions WHERE id = ${browser.sessionId}`).toHaveLength(1);
      expect((await stack.outbox("wiki")).filter((e) => e.payload.sid === browser.sessionId)).toHaveLength(0);
      // Revoking it again is a quiet 200.
      expect((await form("/oauth/revoke", { token: a.refresh_token! }, stack.basic("wiki"))).status).toBe(200);
      expect((await stack.audit("token.revoke")).filter((x) => x.user_id === user.id)).toHaveLength(1);
    });

    test("an unknown token, an over-long one and another client's are 200 and change nothing", async () => {
      const { user, browser } = await signedIn({ wiki: "member", mailbox: "user" });
      const tokens = await tokensFor(browser, "wiki");
      for (const [token, auth] of [
        ["rt_unknown", stack.basic("wiki")],
        ["a".repeat(300), stack.basic("wiki")],
        [tokens.refresh_token!, stack.basic("mailbox")],
      ] as const) {
        const res = await form("/oauth/revoke", { token }, auth);
        expect(res.status).toBe(200);
        expect(await res.json()).toEqual({});
      }
      const pub = await form("/oauth/revoke", { token: tokens.refresh_token!, client_id: "tasks-ios" });
      expect(pub.status).toBe(200);
      await pub.body?.cancel();
      expect((await refresh("wiki", tokens.refresh_token!)).status).toBe(200);
      expect((await stack.audit("token.revoke")).filter((x) => x.user_id === user.id)).toHaveLength(0);
    });

    test("an access token is not revoked: there is nothing to revoke", async () => {
      const { user, browser } = await signedIn({ wiki: "member" });
      const tokens = await tokensFor(browser, "wiki");
      expect((await form("/oauth/revoke", { token: tokens.access_token }, stack.basic("wiki"))).status).toBe(200);
      expect((await stack.audit("token.revoke")).filter((x) => x.user_id === user.id)).toHaveLength(0);
    });

    test("a public client's revocation ends the whole family and tells its service", async () => {
      const { user, browser } = await signedIn({ tasks: "user" });
      const tokens = await tokensFor(browser, "tasks-ios");
      const sid = (await stack.verified(tokens.access_token)).sid as string;
      const rotated = (await (await refresh("tasks-ios", tokens.refresh_token!)).json()) as TokenSet;
      const res = await form("/oauth/revoke", { token: tokens.refresh_token!, client_id: "tasks-ios" });
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({});
      expect(await stack.db`SELECT 1 FROM refresh_tokens WHERE family_id = ${sid} AND revoked_at IS NULL`).toHaveLength(0);
      expect(await errorOf(await refresh("tasks-ios", rotated.refresh_token!))).toEqual(INVALID_REFRESH);
      expect((await stack.outbox("tasks")).filter((e) => e.type === "session.ended" && e.payload.sid === sid).map((e) => e.payload)).toEqual([{ sid }]);
      await stack.http.waitForEvent("tasks", "session.ended", (e) => e.payload.sid === sid);
      const audits = (await stack.audit("token.revoke")).filter((x) => x.user_id === user.id);
      expect(audits).toHaveLength(1);
      expect(audits[0]).toMatchObject({ actor: "cli_tasks", detail: { client: "tasks-ios" } });
      // The SSO session is not the family: it lives on.
      expect(await stack.db`SELECT 1 FROM sessions WHERE id = ${browser.sessionId}`).toHaveLength(1);
    });

    test("missing, empty or repeated token is invalid_request", async () => {
      for (const fields of [{}, { token: "" }] as Record<string, string>[]) {
        expect(await errorOf(await form("/oauth/revoke", fields, stack.basic("wiki")))).toEqual({ status: 400, error: "invalid_request", description: "token is required." });
      }
      expect(await errorOf(await form("/oauth/revoke", { client_id: "tasks-ios" }))).toEqual({ status: 400, error: "invalid_request", description: "token is required." });
      expect(await errorOf(await form("/oauth/revoke", "token=a&token=b", stack.basic("wiki")))).toEqual({
        status: 400,
        error: "invalid_request",
        description: 'The parameter "token" is repeated.',
      });
    });

    test("token_type_hint is ignored", async () => {
      const { browser } = await signedIn({ wiki: "member" });
      const tokens = await tokensFor(browser, "wiki");
      expect((await form("/oauth/revoke", { token: tokens.refresh_token!, token_type_hint: "access_token" }, stack.basic("wiki"))).status).toBe(200);
      expect(await errorOf(await refresh("wiki", tokens.refresh_token!))).toEqual(INVALID_REFRESH);
    });
  });

  // ------------------------------------------------------------ introspect

  describe("POST /oauth/introspect", () => {
    async function credential(
      user: TestUser,
      kind: "app_password" | "api_key",
      service: string,
      scopes: string[],
      opts: { expiresAt?: string; revoked?: boolean; lastUsed?: string } = {},
    ): Promise<{ id: string; secret: string }> {
      const id = newId(kind === "app_password" ? "apw" : "key");
      const secret = kind === "app_password" ? base32(randomBytes(10)).match(/.{4}/g)!.join("-") : `testkey_${id}_${randomToken()}`;
      await stack.db`
        INSERT INTO credentials (id, user_id, kind, service, scopes, name, secret_hash, expires_at, revoked_at, last_used_at)
        VALUES (${id}, ${user.id}, ${kind}, ${service}, ${stack.db.array(scopes, "TEXT")}, 'test', ${sha256(secret)},
                now() + ${opts.expiresAt ?? "1 day"}::interval, ${opts.revoked ? new Date() : null},
                ${opts.lastUsed === undefined ? null : stack.db`now() - ${opts.lastUsed}::interval`})`;
      return { id, secret };
    }

    const introspect = (clientId: string, token: string, headers: Record<string, string> = {}) => form("/oauth/introspect", { token }, stack.basic(clientId), headers);

    test("an app password of the caller's service is active, with its owner, scopes, role and id", async () => {
      const user = await stack.user({ username: uname("ip"), access: { mailbox: "admin" } });
      const { id, secret } = await credential(user, "app_password", "mailbox", ["imap", "smtp"]);
      const res = await introspect("mailbox", secret);
      expect(res.status).toBe(200);
      expectJson(res);
      expect(await res.json()).toEqual({ active: true, sub: user.id, username: user.username, scope: "imap smtp", role: "admin", jti: id });
    });

    test("an app password typed without dashes, in capitals or with spaces around it", async () => {
      const user = await stack.user({ username: uname("ip"), access: { mailbox: "user" } });
      const { id, secret } = await credential(user, "app_password", "mailbox", ["imap"]);
      for (const typed of [secret.replace(/-/g, ""), secret.toUpperCase(), secret.replace(/-/g, "").toUpperCase(), ` ${secret} `, `${secret.slice(0, 9)}${secret.slice(10)}`]) {
        expect(await (await introspect("mailbox", typed)).json()).toEqual({ active: true, sub: user.id, username: user.username, scope: "imap", role: "user", jti: id });
      }
    });

    test("an API key is active for its service, found as given only", async () => {
      const user = await stack.user({ username: uname("ik"), access: { tasks: "user" } });
      const { id, secret } = await credential(user, "api_key", "tasks", ["tasks:read"]);
      expect(await (await introspect("tasks", secret)).json()).toEqual({ active: true, sub: user.id, username: user.username, scope: "tasks:read", role: "user", jti: id });
      expect(await (await introspect("tasks", secret.toUpperCase())).json()).toEqual({ active: false });
    });

    test("an API key without an expiry is active", async () => {
      const user = await stack.user({ username: uname("ik"), access: { tasks: "user" } });
      const { id, secret } = await credential(user, "api_key", "tasks", ["tasks:read", "tasks:write"]);
      await stack.db`UPDATE credentials SET expires_at = NULL WHERE id = ${id}`;
      expect(await (await introspect("tasks", secret)).json()).toMatchObject({ active: true, scope: "tasks:read tasks:write" });
    });

    test.each([
      ["an unknown secret", async () => "abcd-efgh-ijkl-mnop", "mailbox"],
      ["another service's credential", async (u: TestUser) => (await credential(u, "app_password", "mailbox", ["imap"])).secret, "wiki"],
      ["a revoked credential", async (u: TestUser) => (await credential(u, "app_password", "mailbox", ["imap"], { revoked: true })).secret, "mailbox"],
      ["an expired credential", async (u: TestUser) => (await credential(u, "api_key", "tasks", ["tasks:read"], { expiresAt: "-1 second" })).secret, "tasks"],
      [
        "a credential of a disabled owner",
        async (u: TestUser) => {
          const c = await credential(u, "app_password", "mailbox", ["imap"]);
          await stack.db`UPDATE users SET disabled_at = now() WHERE id = ${u.id}`;
          return c.secret;
        },
        "mailbox",
      ],
      [
        "a credential whose owner has no role on the service",
        async (u: TestUser) => {
          const c = await credential(u, "app_password", "mailbox", ["imap"]);
          await stack.db`DELETE FROM access WHERE user_id = ${u.id} AND service = 'mailbox'`;
          return c.secret;
        },
        "mailbox",
      ],
      ["a secret over 512 characters", async () => "a".repeat(513), "mailbox"],
    ])("%s is inactive", async (_, make, clientId) => {
      const user = await stack.user({ username: uname("in"), access: { mailbox: "user", tasks: "user", wiki: "member" } });
      const secret = await make(user);
      const res = await introspect(clientId, secret);
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ active: false });
    });

    test("a JWT is never introspected", async () => {
      const { browser } = await signedIn({ wiki: "member" });
      const tokens = await tokensFor(browser, "wiki");
      for (const t of [tokens.access_token, tokens.id_token!, tokens.refresh_token!]) expect(await (await introspect("wiki", t)).json()).toEqual({ active: false });
    });

    test("a use is recorded, at most once a minute", async () => {
      const user = await stack.user({ username: uname("lu"), access: { mailbox: "user" } });
      const { id, secret } = await credential(user, "app_password", "mailbox", ["imap"]);
      await introspect("mailbox", secret);
      const [a] = await stack.db`SELECT last_used_at > now() - interval '1 minute' AS recent FROM credentials WHERE id = ${id}`;
      expect(a.recent).toBe(true);
      await stack.db`UPDATE credentials SET last_used_at = now() - interval '30 seconds' WHERE id = ${id}`;
      await introspect("mailbox", secret);
      const [b] = await stack.db`SELECT extract(epoch FROM now() - last_used_at)::int AS age FROM credentials WHERE id = ${id}`;
      expect(b.age).toBeGreaterThanOrEqual(29);
      await stack.db`UPDATE credentials SET last_used_at = now() - interval '2 minutes' WHERE id = ${id}`;
      await introspect("mailbox", secret);
      const [c] = await stack.db`SELECT extract(epoch FROM now() - last_used_at)::int AS age FROM credentials WHERE id = ${id}`;
      expect(c.age).toBeLessThan(10);
    });

    test("missing, empty or repeated token is invalid_request", async () => {
      for (const body of ["", "token="]) {
        expect(await errorOf(await form("/oauth/introspect", body, stack.basic("mailbox")))).toEqual({ status: 400, error: "invalid_request", description: "token is required." });
      }
      expect(await errorOf(await form("/oauth/introspect", "token=a&token=b", stack.basic("mailbox")))).toEqual({
        status: 400,
        error: "invalid_request",
        description: 'The parameter "token" is repeated.',
      });
    });

    test("600 a minute per client, then 429", async () => {
      await stack.db`INSERT INTO throttle (key, window_start, hits) VALUES ('client:mailbox:introspect', now(), 599)`;
      expect((await introspect("mailbox", "x")).status).toBe(200);
      const res = await introspect("mailbox", "x");
      expect(Number(res.headers.get("Retry-After"))).toBeGreaterThan(0);
      expect(Number(res.headers.get("Retry-After"))).toBeLessThanOrEqual(60);
      expect(await errorOf(res)).toEqual({ status: 429, error: "rate_limited", description: "Too many introspection requests." });
      expect((await introspect("tasks", "x")).status).toBe(200);
    });

    test("a failure counts against the client; a success doesn't", async () => {
      const user = await stack.user({ username: uname("fc"), access: { mailbox: "user" } });
      const { secret } = await credential(user, "app_password", "mailbox", ["imap"]);
      await introspect("mailbox", secret);
      expect(await stack.db`SELECT key FROM throttle WHERE key LIKE 'client:mailbox:introspect-fail%'`).toHaveLength(0);
      await introspect("mailbox", "wrong");
      await introspect("mailbox", "wrong");
      expect(await stack.db`SELECT key, hits FROM throttle WHERE key LIKE 'client:mailbox:introspect-fail%'`).toEqual([{ key: "client:mailbox:introspect-fail", hits: 2 }]);
    });

    test("1000 failures an hour per client, then 429 for every check, good or bad", async () => {
      const user = await stack.user({ username: uname("fl"), access: { mailbox: "user" } });
      const { secret } = await credential(user, "app_password", "mailbox", ["imap"]);
      await stack.db`INSERT INTO throttle (key, window_start, hits) VALUES ('client:mailbox:introspect-fail', now() - interval '30 minutes', 999)`;
      expect(await (await introspect("mailbox", "wrong")).json()).toEqual({ active: false });
      for (const token of ["wrong", secret]) {
        const res = await introspect("mailbox", token);
        const retry = Number(res.headers.get("Retry-After"));
        expect(retry).toBeGreaterThan(1700);
        expect(retry).toBeLessThanOrEqual(1800);
        expect(await errorOf(res)).toEqual({ status: 429, error: "rate_limited", description: "Too many failed checks." });
      }
      // A window that has passed counts no more.
      await stack.db`UPDATE throttle SET window_start = now() - interval '61 minutes' WHERE key = 'client:mailbox:introspect-fail'`;
      expect((await introspect("mailbox", secret)).status).toBe(200);
    });

    test("the address in X-Real-IP keys nothing when it is the request's own", async () => {
      // Through the trusted proxy, X-Real-IP is the request's address.
      for (const ip of ["203.0.113.9", "not-an-address"]) await introspect("mailbox", "wrong", { "X-Real-IP": ip });
      expect((await stack.db`SELECT key FROM throttle WHERE key LIKE 'client:mailbox:introspect-fail%'`).map((r: any) => r.key)).toEqual(["client:mailbox:introspect-fail"]);
    });

    describe("per end-user address (a client not behind the proxy)", () => {
      let copy: ServerProcess;
      beforeAll(async () => {
        // The tests' own address is not a trusted proxy here, so X-Real-IP is
        // an address the client names.
        copy = await stack.spawn({ env: { TRUSTED_PROXIES: "192.0.2.1" } });
        await copy.ready();
      });
      const ask = (token: string, ip?: string) =>
        post(copy.url, "/oauth/introspect", { token }, { Authorization: stack.basic("mailbox"), ...(ip !== undefined ? { "X-Real-IP": ip } : {}) });

      test("a failure counts against the client and the address it names, normalized", async () => {
        await ask("wrong", "2001:0DB8:0:0:0:0:0:1");
        await ask("wrong", "198.51.100.4");
        await ask("wrong", "198.51.100.4");
        // Its own address, or none that parses, keys nothing.
        await ask("wrong", "127.0.0.1");
        await ask("wrong", "garbage");
        await ask("wrong");
        const rows = await stack.db`SELECT key, hits FROM throttle WHERE key LIKE 'client:mailbox:introspect-fail%' ORDER BY key`;
        expect(rows).toEqual([
          { key: "client:mailbox:introspect-fail", hits: 6 },
          { key: "client:mailbox:introspect-fail:198.51.100.4", hits: 2 },
          { key: "client:mailbox:introspect-fail:2001:db8::1", hits: 1 },
        ]);
      });

      test("10 failures per address in 15 minutes, then 429 for that address only", async () => {
        const user = await stack.user({ username: uname("fa"), access: { mailbox: "user" } });
        const { secret } = await credential(user, "app_password", "mailbox", ["imap"]);
        await stack.db`INSERT INTO throttle (key, window_start, hits) VALUES ('client:mailbox:introspect-fail:198.51.100.7', now() - interval '5 minutes', 9)`;
        expect(await (await ask("wrong", "198.51.100.7")).json()).toEqual({ active: false });
        for (const token of ["wrong", secret]) {
          const res = await ask(token, "198.51.100.7");
          const retry = Number(res.headers.get("Retry-After"));
          expect(retry).toBeGreaterThan(500);
          expect(retry).toBeLessThanOrEqual(600);
          expect(await errorOf(res)).toEqual({ status: 429, error: "rate_limited", description: "Too many failed checks." });
        }
        expect(await (await ask(secret, "198.51.100.8")).json()).toMatchObject({ active: true });
        expect(await (await ask(secret)).json()).toMatchObject({ active: true });
        // Another client's counter for the address is its own.
        const other = await post(copy.url, "/oauth/introspect", { token: "wrong" }, { Authorization: stack.basic("tasks"), "X-Real-IP": "198.51.100.7" });
        expect(other.status).toBe(200);
        await other.body?.cancel();
      });
    });
  });

  // -------------------------------------------------------------- userinfo

  describe("/oauth/userinfo", () => {
    const ask = (authorization: string | null, method: "GET" | "POST" = "GET") =>
      fetch(`${stack.url}/oauth/userinfo`, { method, headers: authorization === null ? {} : { Authorization: authorization } });

    async function expectRefused(res: Response) {
      expect(res.headers.get("WWW-Authenticate")).toBe('Bearer error="invalid_token"');
      expectJson(res);
      expect(await errorOf(res)).toEqual({ status: 401, error: "invalid_token", description: "The access token is missing, invalid or expired." });
    }

    test.each(["GET", "POST"] as const)("%s answers for a valid access token", async (method) => {
      const { user, browser } = await signedIn({ wiki: "member" });
      const tokens = await tokensFor(browser, "wiki");
      const res = await ask(`Bearer ${tokens.access_token}`, method);
      expect(res.status).toBe(200);
      expectJson(res);
      expect(await res.json()).toEqual({
        sub: user.id,
        username: user.username,
        preferred_username: user.username,
        name: user.name,
        email: user.email,
        email_verified: true,
      });
    });

    test("an access token of any service; the user as they are now", async () => {
      const { user, browser } = await signedIn({ tasks: "user" }, { email: null });
      const tokens = await tokensFor(browser, "tasks-ios");
      await stack.db`UPDATE users SET name = 'Bob Example' WHERE id = ${user.id}`;
      expect(await (await ask(`Bearer ${tokens.access_token}`)).json()).toEqual({
        sub: user.id,
        username: user.username,
        preferred_username: user.username,
        name: "Bob Example",
        email: null,
        email_verified: false,
      });
    });

    test("surrounding whitespace in the header is ignored", async () => {
      const { browser } = await signedIn({ wiki: "member" });
      const tokens = await tokensFor(browser, "wiki");
      expect((await ask(`  Bearer ${tokens.access_token}  `)).status).toBe(200);
    });

    test("an access token within the 30-second leeway past its expiry still answers", async () => {
      const user = await stack.user({ username: uname("lw"), access: { wiki: "member" } });
      const now = Math.floor(Date.now() / 1000);
      const token = await forge({ iss: stack.issuer, sub: user.id, aud: "wiki", iat: now - 610, exp: now - 10 });
      expect((await ask(`Bearer ${token}`)).status).toBe(200);
    });

    describe("refusals", () => {
      let user: TestUser;
      let tokens: TokenSet;
      beforeAll(async () => {
        const s = await signedIn({ wiki: "member" });
        user = s.user;
        tokens = await tokensFor(s.browser, "wiki");
      });
      const now = () => Math.floor(Date.now() / 1000);
      const claims = (more: Record<string, unknown> = {}) => ({ iss: stack.issuer, sub: user.id, aud: "wiki", iat: now(), exp: now() + 600, ...more });

      test.each<[string, () => Promise<string | null>]>([
        ["no Authorization header", async () => null],
        ["an empty header", async () => ""],
        ["Bearer with no token", async () => "Bearer "],
        ["a lower-case scheme", async () => `bearer ${tokens.access_token}`],
        ["Basic credentials", async () => stack.basic("wiki")],
        ["two spaces after Bearer", async () => `Bearer  ${tokens.access_token}`],
        ["characters outside a JWT's", async () => `Bearer ${tokens.access_token}+`],
        ["a garbage token", async () => "Bearer abc123"],
        ["a token of two parts", async () => `Bearer ${tokens.access_token.split(".").slice(0, 2).join(".")}`],
        ["a refresh token", async () => `Bearer ${tokens.refresh_token}`],
        ["an ID token (typ JWT)", async () => `Bearer ${tokens.id_token}`],
        ["a tampered signature", async () => `Bearer ${tokens.access_token.slice(0, -4)}${tokens.access_token.endsWith("AAAA") ? "BBBB" : "AAAA"}`],
        [
          "tampered claims",
          async () => {
            const [h, , s] = tokens.access_token.split(".");
            return `Bearer ${h}.${b64u(JSON.stringify({ ...decodeJwt(tokens.access_token).claims, role: "owner" }))}.${s}`;
          },
        ],
        ["an expired token", async () => `Bearer ${await forge(claims({ iat: now() - 700, exp: now() - 31 }))}`],
        ["a token issued in the future", async () => `Bearer ${await forge(claims({ iat: now() + 60 }))}`],
        ["a token without exp", async () => `Bearer ${await forge(claims({ exp: undefined }))}`],
        ["another issuer", async () => `Bearer ${await forge(claims({ iss: "https://auth.example.com" }))}`],
        ["an audience that is no service", async () => `Bearer ${await forge(claims({ aud: "elsewhere" }))}`],
        ["an audience list", async () => `Bearer ${await forge(claims({ aud: ["wiki"] }))}`],
        ["auth's own service as the audience, which no client has", async () => `Bearer ${await forge(claims({ aud: "auth" }))}`],
        ["no sub", async () => `Bearer ${await forge(claims({ sub: undefined }))}`],
        ["an unknown sub", async () => `Bearer ${await forge(claims({ sub: newId("usr") }))}`],
        ["a security event token's typ", async () => `Bearer ${await forge(claims(), { typ: "secevent+jwt" })}`],
        ["alg none", async () => `Bearer ${await forge(claims(), { alg: "none" })}`],
        ["an unknown kid", async () => `Bearer ${await forge(claims(), { kid: "nope" })}`],
        ["a crit header", async () => `Bearer ${await forge(claims(), { crit: ["exp"] })}`],
        ["a token over 8192 characters", async () => `Bearer ${await forge(claims({ name: "x".repeat(8200) }))}`],
      ])("%s", async (_, header) => {
        await expectRefused(await ask(await header()));
      });

      test("POST refuses the same way", async () => {
        await expectRefused(await ask(null, "POST"));
        await expectRefused(await ask(`Bearer ${tokens.id_token}`, "POST"));
      });

      test("a disabled user, then a deleted one", async () => {
        const s = await signedIn({ wiki: "member" });
        const t = await tokensFor(s.browser, "wiki");
        expect((await ask(`Bearer ${t.access_token}`)).status).toBe(200);
        await stack.db`UPDATE users SET disabled_at = now() WHERE id = ${s.user.id}`;
        await expectRefused(await ask(`Bearer ${t.access_token}`));
        await stack.db`DELETE FROM users WHERE id = ${s.user.id}`;
        await expectRefused(await ask(`Bearer ${t.access_token}`));
      });
    });
  });

  // ---------------------------------------------------------------- logout

  describe("GET /logout", () => {
    const WIKI_HOME = "https://wiki.example.com/";

    test("ends the session, tells every service holding tokens under it, audits, and returns to the app with state", async () => {
      const { user, browser } = await signedIn({ wiki: "member", tasks: "user" });
      const wiki = await tokensFor(browser, "wiki");
      await tokensFor(browser, "tasks");
      const ios = await tokensFor(browser, "tasks-ios");
      const iosSid = (await stack.verified(ios.access_token)).sid;
      const sid = browser.sessionId!;
      const res = await browser.request(`/logout?${new URLSearchParams({ client_id: "wiki", post_logout_redirect_uri: WIKI_HOME, state: "st-é 1" })}`);
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe(back(WIKI_HOME, { state: "st-é 1" }));
      expectSessionCookieCleared(res);
      expect(await stack.db`SELECT 1 FROM sessions WHERE id = ${sid}`).toHaveLength(0);
      expect(await stack.db`SELECT 1 FROM refresh_tokens WHERE session_id = ${sid}`).toHaveLength(0);
      for (const service of ["wiki", "tasks"]) {
        expect((await stack.outbox(service)).filter((e) => e.type === "session.ended" && e.payload.sid === sid).map((e) => e.payload)).toEqual([{ sid }]);
      }
      expect((await stack.outbox("mailbox")).filter((e) => e.payload.sid === sid)).toHaveLength(0);
      await stack.http.waitForEvent("wiki", "session.ended", (e) => e.payload.sid === sid);
      const audits = (await stack.audit("logout")).filter((a) => a.user_id === user.id);
      expect(audits).toHaveLength(1);
      expect(audits[0]).toMatchObject({ actor: user.id, ip: browser.ip, detail: { client: "wiki" } });
      expect(await errorOf(await refresh("wiki", wiki.refresh_token!))).toEqual(INVALID_REFRESH);
      // A public client's family is the device's own sign-in, ended separately.
      expect((await stack.outbox("tasks")).filter((e) => e.payload.sid === iosSid)).toHaveLength(0);
      expect((await refresh("tasks-ios", ios.refresh_token!)).status).toBe(200);
    });

    test("without a return address: the signed-out page", async () => {
      const { user, browser } = await signedIn({ wiki: "member" });
      const res = await browser.request("/logout");
      expect(res.status).toBe(200);
      expectSessionCookieCleared(res);
      expect(await pageOf(res)).toEqual({ status: 200, title: "Signed out", h1: "Signed out", message: "You are signed out.", links: [{ href: "/login", text: "Sign in again" }] });
      expect(await stack.db`SELECT 1 FROM sessions WHERE id = ${browser.sessionId}`).toHaveLength(0);
      const audits = (await stack.audit("logout")).filter((a) => a.user_id === user.id);
      expect(audits.map((a) => a.detail)).toEqual([{ client: null }]);
    });

    test("a client_id without a return address is recorded, and the page shown", async () => {
      const { user, browser } = await signedIn({ wiki: "member" });
      const res = await browser.request("/logout?client_id=nobody&state=x");
      expect(res.status).toBe(200);
      expect((await pageOf(res)).title).toBe("Signed out");
      expect((await stack.audit("logout")).filter((a) => a.user_id === user.id).map((a) => a.detail)).toEqual([{ client: "nobody" }]);
    });

    test("without a session: nothing to end, the cookie is still cleared", async () => {
      const before = (await stack.audit("logout")).length;
      const b = stack.browser();
      b.cookies.set("__Host-auth", randomToken());
      const page = await b.request("/logout");
      expect(page.status).toBe(200);
      expectSessionCookieCleared(page);
      expect((await pageOf(page)).title).toBe("Signed out");
      const res = await stack.browser().request(`/logout?${new URLSearchParams({ client_id: "wiki", post_logout_redirect_uri: WIKI_HOME })}`);
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe(WIKI_HOME);
      expectSessionCookieCleared(res);
      expect((await stack.audit("logout")).length).toBe(before);
    });

    test("state is passed back up to 1024 characters, and dropped past that", async () => {
      const ok = await stack.browser().request(`/logout?${new URLSearchParams({ client_id: "wiki", post_logout_redirect_uri: WIKI_HOME, state: "s".repeat(1024) })}`);
      expect(ok.headers.get("Location")).toBe(back(WIKI_HOME, { state: "s".repeat(1024) }));
      const long = await stack.browser().request(`/logout?${new URLSearchParams({ client_id: "wiki", post_logout_redirect_uri: WIKI_HOME, state: "s".repeat(1025) })}`);
      expect(long.status).toBe(302);
      expect(long.headers.get("Location")).toBe(WIKI_HOME);
      const empty = await stack.browser().request(`/logout?${new URLSearchParams({ client_id: "wiki", post_logout_redirect_uri: WIKI_HOME, state: "" })}`);
      expect(empty.headers.get("Location")).toBe(`${WIKI_HOME}?state=`);
    });

    test.each([
      ["no client_id", { post_logout_redirect_uri: WIKI_HOME }],
      ["an unknown client", { client_id: "nobody", post_logout_redirect_uri: WIKI_HOME }],
      ["another client", { client_id: "tasks", post_logout_redirect_uri: WIKI_HOME }],
      ["an unregistered address", { client_id: "wiki", post_logout_redirect_uri: "https://evil.example.com/" }],
      ["a longer address", { client_id: "wiki", post_logout_redirect_uri: `${WIKI_HOME}x` }],
      ["an empty address", { client_id: "wiki", post_logout_redirect_uri: "" }],
      ["a sign-in redirect URI", { client_id: "wiki", post_logout_redirect_uri: REDIRECTS.wiki! }],
    ])("%s: an error page, and the session lives on", async (_, params: Record<string, string>) => {
      const { browser } = await signedIn({ wiki: "member" });
      const res = await browser.request(`/logout?${new URLSearchParams(params)}`);
      expect(res.headers.getSetCookie()).toEqual([]);
      expect(await pageOf(res)).toEqual({
        status: 400,
        title: "Sign-out failed",
        h1: "Sign-out failed",
        message: "The app sent you here with a return address it hasn't registered.",
        links: [],
      });
      expect(await stack.db`SELECT 1 FROM sessions WHERE id = ${browser.sessionId}`).toHaveLength(1);
    });

    test.each(["client_id", "post_logout_redirect_uri", "state"])("a repeated %s: an error page, and the session lives on", async (name) => {
      const { browser } = await signedIn({ wiki: "member" });
      const q = new URLSearchParams({ client_id: "wiki", post_logout_redirect_uri: WIKI_HOME, state: "x" });
      q.append(name, q.get(name)!);
      const res = await browser.request(`/logout?${q}`);
      expect(await pageOf(res)).toEqual({ status: 400, title: "Sign-out failed", h1: "Sign-out failed", message: "A parameter is repeated.", links: [] });
      expect(await stack.db`SELECT 1 FROM sessions WHERE id = ${browser.sessionId}`).toHaveLength(1);
    });
  });
});

// ------------------------------------------------- registered (database) clients

describe.skipIf(!enabled)("a service registered on the admin page", () => {
  let stack: Stack;
  let admin: Browser;
  let secret: string;
  const A = "https://notes.example.com/auth/callback";
  const B = "https://notes.example.com/cb?tenant=a";
  const body = (uris: string[]) => ({
    name: "notes",
    roles: ["reader", "writer"],
    mfa_roles: [],
    signup: "open",
    default_role: "reader",
    clients: [{ id: "notes", type: "confidential", redirect_uris: uris }],
  });

  beforeAll(async () => {
    stack = await Stack.start({ services: null });
    ({ browser: admin } = await stack.admin());
    const created = await admin.api("POST", "/v1/services", body([A, B]));
    if (created.status !== 201) throw new Error(`registration failed: ${created.status} ${await created.text()}`);
    const s = await admin.api("POST", "/v1/clients/notes/secrets");
    if (s.status !== 201) throw new Error(`no secret: ${s.status} ${await s.text()}`);
    secret = ((await s.json()) as { secret: string }).secret;
  });
  afterAll(async () => {
    await stack.stop();
  });

  async function codeFor(redirectUri: string) {
    const user = await stack.user({ username: uname("rg") });
    const browser = await stack.session(user);
    const { verifier, challenge } = pkce();
    const p = authorizeParams("notes", redirectUri, challenge);
    const res = await browser.request(`/oauth/authorize?${new URLSearchParams(p)}`);
    const location = res.headers.get("Location")!;
    const code = new URL(location).searchParams.get("code");
    if (!code) throw new Error(`no code: ${res.status} ${location}`);
    return { user, code, verifier, state: p.state!, location };
  }
  const exchange = (code: string, verifier: string, redirectUri: string) =>
    backChannel(stack, "/oauth/token", { grant_type: "authorization_code", code, redirect_uri: redirectUri, code_verifier: verifier }, basic("notes", secret));

  // In order: the service changes under them.
  test("its client signs a user in, at a redirect URI with a query string too", async () => {
    const a = await codeFor(A);
    const res = await exchange(a.code, a.verifier, A);
    expect(res.status).toBe(200);
    const tokens = (await res.json()) as TokenSet;
    expect(await stack.verified(tokens.access_token, "at+jwt")).toMatchObject({ sub: a.user.id, aud: "notes", role: "reader" });
    expect((await stack.verified(tokens.id_token!, "JWT")).aud).toBe("notes");
    const b = await codeFor(B);
    expect(b.location).toBe(back(B, { code: b.code, state: b.state }));
    expect((await exchange(b.code, b.verifier, B)).status).toBe(200);
    const r = await backChannel(stack, "/oauth/token", { grant_type: "refresh_token", refresh_token: tokens.refresh_token! }, basic("notes", secret));
    expect(r.status).toBe(200);
    await r.body?.cancel();
  });

  test("a code is not redeemed once its redirect URI was removed", async () => {
    const a = await codeFor(A);
    const b = await codeFor(B);
    const put = await admin.api("PUT", "/v1/services/notes", body([A]));
    expect(put.status).toBe(200);
    await put.body?.cancel();
    expect(await errorOf(await exchange(b.code, b.verifier, B))).toEqual(INVALID_CODE);
    expect((await exchange(a.code, a.verifier, A)).status).toBe(200);
    // The removed address is no longer accepted at the authorization endpoint either.
    const browser = await stack.session(a.user);
    const res = await browser.request(`/oauth/authorize?${new URLSearchParams(authorizeParams("notes", B, pkce().challenge))}`);
    expect(res.status).toBe(400);
    await res.body?.cancel();
  });

  test("once the service is deleted, its codes and tokens redeem nothing and its client is unknown", async () => {
    const a = await codeFor(A);
    const live = await codeFor(A);
    const tokens = (await (await exchange(live.code, live.verifier, A)).json()) as TokenSet;
    const del = await admin.api("DELETE", "/v1/services/notes");
    expect(del.status).toBe(204);
    for (const res of [
      await exchange(a.code, a.verifier, A),
      await backChannel(stack, "/oauth/token", { grant_type: "refresh_token", refresh_token: tokens.refresh_token! }, basic("notes", secret)),
      await backChannel(stack, "/oauth/revoke", { token: tokens.refresh_token! }, basic("notes", secret)),
    ]) {
      expect(res.headers.get("WWW-Authenticate")).toBe('Basic realm="auth"');
      expect(await errorOf(res)).toEqual(INVALID_CLIENT);
    }
    const res = await stack.browser().request(`/oauth/authorize?${new URLSearchParams(authorizeParams("notes", A, pkce().challenge))}`);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("The app that sent you here is not registered.");
  });
});
