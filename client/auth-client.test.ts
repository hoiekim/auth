import { afterAll, beforeEach, describe, expect, test } from "bun:test";
import { createHash, createHmac, generateKeyPairSync, sign as edSign, type KeyObject } from "node:crypto";
import {
  createAuthClient,
  InvalidGrant,
  InvalidToken,
  LoginError,
  Unavailable,
  type AuthClientOptions,
} from "./auth-client";

const ISSUER = "https://auth.example.test";
const REDIRECT = "https://wiki.example.test/auth/callback";
const T0 = 1_763_000_000_000;

function keyPair(kid: string) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { kid, privateKey, jwk: { ...publicKey.export({ format: "jwk" }), kid, alg: "EdDSA", use: "sig" } };
}

const k1 = keyPair("k1");
const k2 = keyPair("k2");
const stranger = keyPair("k1");

interface Seen {
  path: string;
  headers: Headers;
  form: URLSearchParams;
}

type Handler = (form: URLSearchParams, req: Request) => Response;

const fake = {
  issuer: ISSUER,
  keys: [k1],
  seen: [] as Seen[],
  token: (() => json(500, {})) as Handler,
  introspect: (() => json(200, { active: false })) as Handler,
  revoke: (() => new Response(null, { status: 200 })) as Handler,
};

let clock = T0;
let down = false;
const nowS = () => Math.floor(clock / 1000);

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const server = Bun.serve({
  port: 0,
  async fetch(req) {
    const path = new URL(req.url).pathname;
    const form = new URLSearchParams(req.method === "POST" ? await req.text() : "");
    fake.seen.push({ path, headers: req.headers, form });
    const at = (p: string) => `${fake.issuer}${p}`;
    switch (path) {
      case "/.well-known/openid-configuration":
        return json(200, {
          issuer: fake.issuer,
          authorization_endpoint: at("/oauth/authorize"),
          token_endpoint: at("/oauth/token"),
          revocation_endpoint: at("/oauth/revoke"),
          introspection_endpoint: at("/oauth/introspect"),
          userinfo_endpoint: at("/oauth/userinfo"),
          jwks_uri: at("/.well-known/jwks.json"),
          end_session_endpoint: at("/logout"),
        });
      case "/.well-known/jwks.json":
        return json(200, { keys: fake.keys.map((k) => k.jwk) });
      case "/oauth/token":
        return fake.token(form, req);
      case "/oauth/introspect":
        return fake.introspect(form, req);
      case "/oauth/revoke":
        return fake.revoke(form, req);
    }
    return json(404, { error: "not_found" });
  },
});
afterAll(() => server.stop(true));
const BACK = `http://localhost:${server.port}`;

const fetchVia = (async (input: string | URL | Request, init?: RequestInit) => {
  if (down) throw new TypeError("fetch failed");
  return fetch(input, init);
}) as typeof fetch;

function client(over: Partial<AuthClientOptions> = {}) {
  return createAuthClient({
    issuer: ISSUER,
    backChannelUrl: BACK,
    clientId: "wiki",
    clientSecret: "s3cret-pw",
    redirectUri: REDIRECT,
    fetch: fetchVia,
    now: () => clock,
    ...over,
  });
}

function jwt(header: object, payload: object, key: KeyObject = k1.privateKey): string {
  const h = Buffer.from(JSON.stringify(header)).toString("base64url");
  const p = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${h}.${p}.${edSign(null, Buffer.from(`${h}.${p}`), key).toString("base64url")}`;
}

function accessToken(claims: object = {}, header: object = {}, key?: KeyObject): string {
  return jwt(
    { alg: "EdDSA", typ: "at+jwt", kid: "k1", ...header },
    {
      iss: fake.issuer,
      sub: "usr_alice",
      aud: "wiki",
      iat: nowS(),
      exp: nowS() + 600,
      sid: "ses_1",
      username: "alice",
      name: "Alice",
      role: "member",
      ...claims,
    },
    key,
  );
}

function idToken(claims: object = {}, header: object = {}): string {
  return jwt(
    { alg: "EdDSA", typ: "JWT", kid: "k1", ...header },
    {
      iss: fake.issuer,
      sub: "usr_alice",
      aud: "wiki",
      iat: nowS(),
      exp: nowS() + 600,
      nonce: "n",
      auth_time: nowS(),
      amr: ["pwd", "otp", "mfa"],
      email: "alice@example.com",
      email_verified: true,
      ...claims,
    },
  );
}

function setToken(events: object, claims: object = {}, header: object = {}, key?: KeyObject): string {
  return jwt(
    { alg: "EdDSA", typ: "secevent+jwt", kid: "k1", ...header },
    { iss: fake.issuer, aud: "wiki", iat: nowS(), jti: "evt_1", events, ...claims },
    key,
  );
}

const seen = (path: string) => fake.seen.filter((s) => s.path === path);

beforeEach(() => {
  clock = T0;
  down = false;
  fake.issuer = ISSUER;
  fake.keys = [k1];
  fake.seen = [];
  fake.token = () => json(200, { access_token: accessToken(), token_type: "Bearer", expires_in: 600 });
  fake.introspect = () => json(200, { active: false });
  fake.revoke = () => new Response(null, { status: 200 });
});

async function failure(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (e) {
    return e;
  }
  throw new Error("expected a rejection");
}

describe("createAuthClient", () => {
  test.each([
    ["an http issuer that isn't localhost", { issuer: "http://auth.example.test" }],
    ["an issuer with a query", { issuer: "https://auth.example.test/?x=1" }],
    ["a missing issuer", { issuer: "" }],
    ["a missing clientId", { clientId: "" }],
    ["a redirectUri that isn't a URL", { redirectUri: "/auth/callback" }],
    ["an empty clientSecret", { clientSecret: "" }],
    ["a backChannelUrl that isn't http", { backChannelUrl: "ftp://auth.internal" }],
  ])("refuses %s", (_, over) => {
    expect(() => client(over)).toThrow();
  });

  test.each(["http://localhost:3000", "http://127.0.0.1:3000", "http://[::1]:3000", "https://auth.example.test"])(
    "accepts issuer %s",
    (issuer) => {
      expect(() => client({ issuer })).not.toThrow();
    },
  );
});

async function startLogin(c = client(), opts?: Parameters<ReturnType<typeof client>["startLogin"]>[1]) {
  const { redirectUrl, loginCookie } = await c.startLogin(new Request("https://wiki.example.test/pages"), opts);
  const url = new URL(redirectUrl);
  return { url, loginCookie, cookie: loginCookie.split(";")[0] ?? "", q: (name: string) => url.searchParams.get(name) ?? "" };
}

function callback(query: string, cookie?: string): Request {
  return new Request(`${REDIRECT}?${query}`, cookie === undefined ? {} : { headers: { cookie } });
}

// Answers the code exchange as auth would: checks PKCE, then issues tokens
// carrying the nonce the authorize request sent.
function issueFor(login: Awaited<ReturnType<typeof startLogin>>, ids: object = {}, at: object = {}): Handler {
  return (form) => {
    const challenge = createHash("sha256").update(form.get("code_verifier") ?? "").digest("base64url");
    if (form.get("code") !== "c0de" || challenge !== login.q("code_challenge") || form.get("redirect_uri") !== REDIRECT) {
      return json(400, { error: "invalid_grant", error_description: "bad code" });
    }
    return json(200, {
      access_token: accessToken(at),
      id_token: idToken({ nonce: login.q("nonce"), ...ids }),
      refresh_token: "rt_abc123",
      token_type: "Bearer",
      expires_in: 600,
    });
  };
}

describe("startLogin", () => {
  test("redirects to the issuer's authorize endpoint with PKCE S256, state and nonce", async () => {
    const login = await startLogin(client(), { maxAge: 86400, prompt: "login", loginHint: "alice" });
    expect(login.url.origin + login.url.pathname).toBe(`${ISSUER}/oauth/authorize`);
    expect(login.q("response_type")).toBe("code");
    expect(login.q("client_id")).toBe("wiki");
    expect(login.q("redirect_uri")).toBe(REDIRECT);
    expect(login.q("scope")).toBe("openid profile email");
    expect(login.q("code_challenge_method")).toBe("S256");
    expect(login.q("max_age")).toBe("86400");
    expect(login.q("prompt")).toBe("login");
    expect(login.q("login_hint")).toBe("alice");
    expect(login.q("state")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(login.q("nonce")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const saved = JSON.parse(Buffer.from(login.cookie.split("=")[1] ?? "", "base64url").toString());
    expect(saved.state).toBe(login.q("state"));
    expect(saved.nonce).toBe(login.q("nonce"));
    expect(createHash("sha256").update(saved.verifier).digest("base64url")).toBe(login.q("code_challenge"));
  });

  test("the login cookie is __Host-, Secure, HttpOnly, SameSite=Lax and lasts 5 minutes", async () => {
    const { loginCookie } = await startLogin();
    expect(loginCookie).toMatch(/^__Host-login=[A-Za-z0-9_-]+; Path=\/; Secure; HttpOnly; SameSite=Lax; Max-Age=300$/);
  });

  test.each(["//evil.example/x", "/\\evil.example", "https://evil.example/", "pages", "/\t/evil.example/x", "/\n/evil.example", "/x\\..\\..\\evil"])(
    "replaces returnTo %p, which isn't a local path, with /",
    async (returnTo) => {
      const login = await startLogin(client(), { returnTo });
      fake.token = issueFor(login);
      const done = await client().finishLogin(callback(`code=c0de&state=${login.q("state")}`, login.cookie));
      expect(done.returnTo).toBe("/");
    },
  );

  test("refuses a prompt other than none or login, and a negative maxAge", async () => {
    expect(await failure(startLogin(client(), { prompt: "consent" as "login" }))).toBeInstanceOf(Error);
    expect(await failure(startLogin(client(), { maxAge: -1 }))).toBeInstanceOf(Error);
  });
});

describe("finishLogin", () => {
  test("exchanges the code over the back channel and returns verified claims", async () => {
    const login = await startLogin(client(), { returnTo: "/pages/7" });
    fake.token = issueFor(login);
    const done = await client().finishLogin(callback(`code=c0de&state=${login.q("state")}`, login.cookie));
    expect(done.claims).toMatchObject({ sub: "usr_alice", role: "member", username: "alice", sid: "ses_1" });
    expect(done.idClaims).toMatchObject({ sub: "usr_alice", email: "alice@example.com", amr: ["pwd", "otp", "mfa"] });
    expect(done.refreshToken).toBe("rt_abc123");
    expect(done.returnTo).toBe("/pages/7");
    expect(done.clearCookie).toBe("__Host-login=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0");
    const [exchange] = seen("/oauth/token");
    expect(exchange?.form.get("grant_type")).toBe("authorization_code");
  });

  test("refuses a callback without the login cookie", async () => {
    const login = await startLogin();
    const e = await failure(client().finishLogin(callback(`code=c0de&state=${login.q("state")}`)));
    expect(e).toBeInstanceOf(LoginError);
    expect((e as LoginError).code).toBe("no_login_cookie");
  });

  test("refuses a login cookie older than 5 minutes", async () => {
    const login = await startLogin();
    fake.token = issueFor(login);
    clock += 301_000;
    const e = await failure(client().finishLogin(callback(`code=c0de&state=${login.q("state")}`, login.cookie)));
    expect((e as LoginError).code).toBe("login_expired");
    expect(seen("/oauth/token")).toHaveLength(0);
  });

  test("refuses a state that differs from the cookie's", async () => {
    const login = await startLogin();
    fake.token = issueFor(login);
    const e = await failure(client().finishLogin(callback(`code=c0de&state=${login.q("state")}x`, login.cookie)));
    expect((e as LoginError).code).toBe("state_mismatch");
    expect(seen("/oauth/token")).toHaveLength(0);
  });

  test("refuses a missing state", async () => {
    const login = await startLogin();
    const e = await failure(client().finishLogin(callback("code=c0de", login.cookie)));
    expect((e as LoginError).code).toBe("state_mismatch");
  });

  test("reports an error the provider redirected with", async () => {
    const login = await startLogin();
    const e = await failure(client().finishLogin(callback(`error=access_denied&state=${login.q("state")}`, login.cookie)));
    expect(e).toMatchObject({ code: "authorization_error", error: "access_denied" });
  });

  test("refuses an ID token whose nonce isn't the one sent", async () => {
    const login = await startLogin();
    fake.token = issueFor(login, { nonce: "another-nonce" });
    const e = await failure(client().finishLogin(callback(`code=c0de&state=${login.q("state")}`, login.cookie)));
    expect(e).toBeInstanceOf(InvalidToken);
  });

  test("refuses an ID token for another client", async () => {
    const login = await startLogin();
    fake.token = issueFor(login, { aud: "tasks" });
    const e = await failure(client().finishLogin(callback(`code=c0de&state=${login.q("state")}`, login.cookie)));
    expect(e).toBeInstanceOf(InvalidToken);
  });

  test("refuses an ID token naming another subject than the access token", async () => {
    const login = await startLogin();
    fake.token = issueFor(login, { sub: "usr_bob" });
    const e = await failure(client().finishLogin(callback(`code=c0de&state=${login.q("state")}`, login.cookie)));
    expect(e).toBeInstanceOf(InvalidToken);
  });

  test("refuses an access token in place of the ID token", async () => {
    const login = await startLogin();
    fake.token = () => json(200, { access_token: accessToken(), id_token: accessToken({ nonce: login.q("nonce") }), token_type: "Bearer" });
    const e = await failure(client().finishLogin(callback(`code=c0de&state=${login.q("state")}`, login.cookie)));
    expect(e).toBeInstanceOf(InvalidToken);
  });

  test("with maxAge, a sign-in older than asked is refused, even if the request lost max_age", async () => {
    const login = await startLogin(client(), { maxAge: 3600 });
    fake.token = issueFor(login, { auth_time: nowS() - 2 * 86400 });
    const e = await failure(client().finishLogin(callback(`code=c0de&state=${login.q("state")}`, login.cookie)));
    expect(e).toBeInstanceOf(InvalidToken);
    const fresh = await startLogin(client(), { maxAge: 3600 });
    fake.token = issueFor(fresh, { auth_time: nowS() - 600 });
    expect((await client().finishLogin(callback(`code=c0de&state=${fresh.q("state")}`, fresh.cookie))).idClaims.sub).toBe("usr_alice");
  });

  test("with prompt=login, a sign-in from before the request is refused", async () => {
    const login = await startLogin(client(), { prompt: "login" });
    fake.token = issueFor(login, { auth_time: nowS() - 120 });
    expect(await failure(client().finishLogin(callback(`code=c0de&state=${login.q("state")}`, login.cookie)))).toBeInstanceOf(InvalidToken);
    const noTime = await startLogin(client(), { prompt: "login" });
    fake.token = issueFor(noTime, { auth_time: undefined });
    expect(await failure(client().finishLogin(callback(`code=c0de&state=${noTime.q("state")}`, noTime.cookie)))).toBeInstanceOf(InvalidToken);
  });

  test("a code the provider refuses is InvalidGrant", async () => {
    const login = await startLogin();
    fake.token = issueFor(login);
    const e = await failure(client().finishLogin(callback(`code=wrong&state=${login.q("state")}`, login.cookie)));
    expect(e).toBeInstanceOf(InvalidGrant);
  });
});

describe("client authentication", () => {
  test("a confidential client sends client_secret_basic with each part form-encoded", async () => {
    const secret = "s3cret:pw%2F& +";
    await client({ clientSecret: secret }).refresh("rt_abc123");
    const [call] = seen("/oauth/token");
    const auth = call?.headers.get("authorization") ?? "";
    expect(auth.startsWith("Basic ")).toBe(true);
    const decoded = Buffer.from(auth.slice(6), "base64").toString();
    const colon = decoded.indexOf(":");
    const unform = (s: string) => decodeURIComponent(s.replace(/\+/g, " "));
    expect(unform(decoded.slice(0, colon))).toBe("wiki");
    expect(unform(decoded.slice(colon + 1))).toBe(secret);
    expect(call?.form.get("client_id")).toBeNull();
  });

  test("a public client sends client_id in the body and no Authorization", async () => {
    await client({ clientId: "tasks-ios", clientSecret: undefined, audience: "tasks" }).refresh("rt_abc123").catch(() => {});
    const [call] = seen("/oauth/token");
    expect(call?.headers.get("authorization")).toBeNull();
    expect(call?.form.get("client_id")).toBe("tasks-ios");
  });
});

describe("refresh", () => {
  test("returns the new access token's claims; a confidential client gets no new refresh token", async () => {
    const r = await client().refresh("rt_abc123");
    expect(r.claims.role).toBe("member");
    expect(r.refreshToken).toBeUndefined();
    const [call] = seen("/oauth/token");
    expect(call?.form.get("grant_type")).toBe("refresh_token");
    expect(call?.form.get("refresh_token")).toBe("rt_abc123");
  });

  test("returns the rotated refresh token of a public client", async () => {
    fake.token = () => json(200, { access_token: accessToken({ aud: "tasks" }), refresh_token: "rt_next", token_type: "Bearer" });
    const r = await client({ clientId: "tasks-ios", clientSecret: undefined, audience: "tasks" }).refresh("rt_abc123");
    expect(r.refreshToken).toBe("rt_next");
  });

  test("invalid_grant throws InvalidGrant", async () => {
    fake.token = () => json(400, { error: "invalid_grant", error_description: "revoked" });
    expect(await failure(client().refresh("rt_abc123"))).toBeInstanceOf(InvalidGrant);
  });

  test("invalid_client is a configuration error, neither InvalidGrant nor Unavailable", async () => {
    fake.token = () => json(401, { error: "invalid_client" });
    const e = await failure(client().refresh("rt_abc123"));
    expect(e).not.toBeInstanceOf(InvalidGrant);
    expect(e).not.toBeInstanceOf(Unavailable);
    expect((e as Error).message).toContain("invalid_client");
  });

  test("a 5xx is Unavailable", async () => {
    fake.token = () => json(503, { error: "temporarily_unavailable" });
    expect(await failure(client().refresh("rt_abc123"))).toBeInstanceOf(Unavailable);
  });

  test("a network failure is Unavailable", async () => {
    const c = client();
    await c.verifyAccessToken(accessToken());
    down = true;
    expect(await failure(c.refresh("rt_abc123"))).toBeInstanceOf(Unavailable);
  });

  test("nothing listening at the back channel is Unavailable", async () => {
    const c = client({ backChannelUrl: "http://localhost:1", fetch: undefined });
    expect(await failure(c.refresh("rt_abc123"))).toBeInstanceOf(Unavailable);
  });

  test("a refreshed token that fails verification is InvalidToken", async () => {
    fake.token = () => json(200, { access_token: accessToken({ aud: "tasks" }), token_type: "Bearer" });
    expect(await failure(client().refresh("rt_abc123"))).toBeInstanceOf(InvalidToken);
  });
});

describe("verifyAccessToken", () => {
  test("accepts a token auth signed for this audience", async () => {
    expect(await client().verifyAccessToken(accessToken())).toMatchObject({ sub: "usr_alice", aud: "wiki", role: "member" });
  });

  const refusals: [string, () => string][] = [
    [
      "alg none",
      () => {
        const h = Buffer.from(JSON.stringify({ alg: "none", typ: "at+jwt", kid: "k1" })).toString("base64url");
        const p = Buffer.from(JSON.stringify({ iss: ISSUER, sub: "usr_alice", aud: "wiki", iat: nowS(), exp: nowS() + 600 })).toString("base64url");
        return `${h}.${p}.`;
      },
    ],
    [
      "HS256 keyed with the public key",
      () => {
        const h = Buffer.from(JSON.stringify({ alg: "HS256", typ: "at+jwt", kid: "k1" })).toString("base64url");
        const p = Buffer.from(JSON.stringify({ iss: ISSUER, sub: "usr_alice", aud: "wiki", iat: nowS(), exp: nowS() + 600, sid: "s", username: "alice", name: "", role: "admin" })).toString("base64url");
        const mac = createHmac("sha256", Buffer.from(String(k1.jwk.x), "base64url")).update(`${h}.${p}`).digest("base64url");
        return `${h}.${p}.${mac}`;
      },
    ],
    ["a valid Ed25519 signature under a header naming another alg", () => accessToken({}, { alg: "ES256" })],
    ["a signature by another key under a known kid", () => accessToken({}, {}, stranger.privateKey)],
    ["another issuer", () => accessToken({ iss: "https://evil.example" })],
    ["another audience", () => accessToken({ aud: "tasks" })],
    ["an expiry more than 30 s past", () => accessToken({ exp: nowS() - 31 })],
    ["no expiry", () => accessToken({ exp: undefined })],
    ["an iat more than 30 s ahead", () => accessToken({ iat: nowS() + 31 })],
    ["an ID token (typ JWT)", () => idToken()],
    ["no typ", () => accessToken({}, { typ: undefined })],
    ["an event token", () => setToken({ "user.disabled": { sub: "usr_alice" } })],
    ["a token without role", () => accessToken({ role: undefined })],
    ["a crit header", () => accessToken({}, { crit: ["exp"] })],
    ["a malformed token", () => "not.a.jwt!"],
  ];
  test.each(refusals)("refuses %s", async (_, token) => {
    expect(await failure(client().verifyAccessToken(token()))).toBeInstanceOf(InvalidToken);
  });

  test("allows 30 s of clock skew on exp and iat", async () => {
    const c = client();
    await c.verifyAccessToken(accessToken({ exp: nowS() - 30 }));
    await c.verifyAccessToken(accessToken({ iat: nowS() + 30 }));
  });

  test("caches the key set for an hour, then fetches it again", async () => {
    const c = client();
    await c.verifyAccessToken(accessToken());
    await c.verifyAccessToken(accessToken());
    expect(seen("/.well-known/jwks.json")).toHaveLength(1);
    clock += 3_600_000;
    await c.verifyAccessToken(accessToken());
    expect(seen("/.well-known/jwks.json")).toHaveLength(2);
  });

  test("keeps verifying with the cached keys while auth is unreachable", async () => {
    const c = client();
    await c.verifyAccessToken(accessToken());
    clock += 2 * 3_600_000;
    down = true;
    expect(await c.verifyAccessToken(accessToken())).toMatchObject({ sub: "usr_alice" });
  });

  test("with no keys yet and auth unreachable, the answer is Unavailable", async () => {
    down = true;
    expect(await failure(client().verifyAccessToken(accessToken()))).toBeInstanceOf(Unavailable);
  });

  test("an unknown kid fetches the key set again, at most once per 30 s", async () => {
    const c = client();
    await c.verifyAccessToken(accessToken());
    expect(seen("/.well-known/jwks.json")).toHaveLength(1);
    const unknown = () => accessToken({}, { kid: "k9" }, k2.privateKey);
    expect(await failure(c.verifyAccessToken(unknown()))).toBeInstanceOf(InvalidToken);
    clock += 31_000;
    expect(await failure(c.verifyAccessToken(unknown()))).toBeInstanceOf(InvalidToken);
    expect(seen("/.well-known/jwks.json")).toHaveLength(2);
    expect(await failure(c.verifyAccessToken(unknown()))).toBeInstanceOf(InvalidToken);
    clock += 29_000;
    expect(await failure(c.verifyAccessToken(unknown()))).toBeInstanceOf(InvalidToken);
    expect(seen("/.well-known/jwks.json")).toHaveLength(2);
    clock += 1_000;
    expect(await failure(c.verifyAccessToken(unknown()))).toBeInstanceOf(InvalidToken);
    expect(seen("/.well-known/jwks.json")).toHaveLength(3);
  });

  test("picks up a key published after the last fetch", async () => {
    const c = client();
    await c.verifyAccessToken(accessToken());
    fake.keys = [k1, k2];
    clock += 31_000;
    expect(await c.verifyAccessToken(accessToken({}, { kid: "k2" }, k2.privateKey))).toMatchObject({ sub: "usr_alice" });
  });

  test("ignores keys that aren't Ed25519 signing keys", async () => {
    fake.keys = [{ ...k1, jwk: { ...k1.jwk, use: "enc" } }];
    expect(await failure(client().verifyAccessToken(accessToken()))).toBeInstanceOf(InvalidToken);
  });

  test("checks against the configured audience when it differs from the client id", async () => {
    const c = client({ clientId: "tasks-web", audience: "tasks" });
    expect(await c.verifyAccessToken(accessToken({ aud: "tasks" }))).toMatchObject({ aud: "tasks" });
    expect(await failure(c.verifyAccessToken(accessToken({ aud: "tasks-web" })))).toBeInstanceOf(InvalidToken);
  });
});

describe("discovery", () => {
  test("goes over the back channel, while browser redirects use the issuer", async () => {
    const c = client();
    const login = await startLogin(c);
    expect(login.url.origin).toBe(ISSUER);
    expect(await c.logoutUrl("https://wiki.example.test/")).toBe(
      `${ISSUER}/logout?client_id=wiki&post_logout_redirect_uri=${encodeURIComponent("https://wiki.example.test/")}`,
    );
    expect(seen("/.well-known/openid-configuration")).toHaveLength(1);
  });

  test("works without a back channel against an issuer on localhost", async () => {
    fake.issuer = BACK;
    const c = client({ issuer: BACK, backChannelUrl: undefined });
    expect(await c.verifyAccessToken(accessToken())).toMatchObject({ iss: BACK });
  });

  test("refuses a document that names another issuer", async () => {
    fake.issuer = "https://other.example.test";
    const e = await failure(client().verifyAccessToken(accessToken()));
    expect((e as Error).message).toContain("issuer");
  });
});

describe("introspect", () => {
  const active = { active: true, sub: "usr_alice", username: "alice", scope: "imap smtp", role: "user", jti: "apw_1" };
  const answer = { sub: "usr_alice", username: "alice", role: "user", scopes: ["imap", "smtp"], id: "apw_1" };

  test("answers an active credential, forwarding the end user's address", async () => {
    fake.introspect = () => json(200, active);
    expect(await client().introspect("abcd-efgh-ijkl-mnop", { ip: "192.0.2.7" })).toEqual(answer);
    const [call] = seen("/oauth/introspect");
    expect(call?.form.get("token")).toBe("abcd-efgh-ijkl-mnop");
    expect(call?.headers.get("x-real-ip")).toBe("192.0.2.7");
    expect(call?.headers.get("authorization")).toStartWith("Basic ");
  });

  test("sends no X-Real-IP unless given one, and refuses one that isn't an address", async () => {
    fake.introspect = () => json(200, active);
    await client().introspect("abcd-efgh-ijkl-mnop");
    expect(seen("/oauth/introspect")[0]?.headers.get("x-real-ip")).toBeNull();
    const e = await failure(client().introspect("abcd-efgh-ijkl-mnop", { ip: "192.0.2.7\r\nX-Evil: 1" }));
    expect(e).not.toBeInstanceOf(Unavailable);
  });

  test("an inactive credential is null, and negatives aren't cached", async () => {
    const c = client();
    expect(await c.introspect("abcd-efgh-ijkl-mnop")).toBeNull();
    expect(await c.introspect("abcd-efgh-ijkl-mnop")).toBeNull();
    expect(seen("/oauth/introspect")).toHaveLength(2);
  });

  test("a positive answer is served from the cache for 60 s, then checked again", async () => {
    fake.introspect = () => json(200, active);
    const c = client();
    await c.introspect("abcd-efgh-ijkl-mnop");
    clock += 59_000;
    expect(await c.introspect("abcd-efgh-ijkl-mnop")).toEqual(answer);
    expect(seen("/oauth/introspect")).toHaveLength(1);
    clock += 1_000;
    await c.introspect("abcd-efgh-ijkl-mnop");
    expect(seen("/oauth/introspect")).toHaveLength(2);
  });

  test("the cache is per secret", async () => {
    fake.introspect = () => json(200, active);
    const c = client();
    await c.introspect("abcd-efgh-ijkl-mnop");
    await c.introspect("abcd-efgh-ijkl-mnoq");
    expect(seen("/oauth/introspect")).toHaveLength(2);
  });

  test("a stale answer is served only while auth is unreachable, and for at most 10 minutes", async () => {
    fake.introspect = () => json(200, active);
    const c = client();
    await c.introspect("abcd-efgh-ijkl-mnop");
    clock += 5 * 60_000;
    down = true;
    expect(await c.introspect("abcd-efgh-ijkl-mnop")).toEqual(answer);
    clock += 5 * 60_000;
    expect(await failure(c.introspect("abcd-efgh-ijkl-mnop"))).toBeInstanceOf(Unavailable);
  });

  test("a 5xx counts as unreachable", async () => {
    fake.introspect = () => json(200, active);
    const c = client();
    await c.introspect("abcd-efgh-ijkl-mnop");
    clock += 61_000;
    fake.introspect = () => json(503, { error: "temporarily_unavailable" });
    expect(await c.introspect("abcd-efgh-ijkl-mnop")).toEqual(answer);
  });

  test("with nothing cached, an unreachable auth is Unavailable", async () => {
    const c = client();
    await c.verifyAccessToken(accessToken());
    down = true;
    expect(await failure(c.introspect("abcd-efgh-ijkl-mnop"))).toBeInstanceOf(Unavailable);
  });

  test("an inactive answer drops the cached one, so it isn't served stale later", async () => {
    fake.introspect = () => json(200, active);
    const c = client();
    await c.introspect("abcd-efgh-ijkl-mnop");
    clock += 61_000;
    fake.introspect = () => json(200, { active: false });
    expect(await c.introspect("abcd-efgh-ijkl-mnop")).toBeNull();
    down = true;
    expect(await failure(c.introspect("abcd-efgh-ijkl-mnop"))).toBeInstanceOf(Unavailable);
  });

  test("a rate-limited check fails closed and isn't cached", async () => {
    fake.introspect = () => json(429, { error: "rate_limited" });
    const c = client();
    expect(await c.introspect("abcd-efgh-ijkl-mnop")).toBeNull();
    fake.introspect = () => json(200, active);
    expect(await c.introspect("abcd-efgh-ijkl-mnop")).toEqual(answer);
  });

  test("forget drops a user's answers, or one credential's", async () => {
    fake.introspect = () => json(200, active);
    const c = client();
    await c.introspect("abcd-efgh-ijkl-mnop");
    c.forget({ sub: "usr_bob" });
    await c.introspect("abcd-efgh-ijkl-mnop");
    expect(seen("/oauth/introspect")).toHaveLength(1);
    c.forget({ sub: "usr_alice" });
    await c.introspect("abcd-efgh-ijkl-mnop");
    expect(seen("/oauth/introspect")).toHaveLength(2);
    c.forget({ id: "apw_1" });
    await c.introspect("abcd-efgh-ijkl-mnop");
    expect(seen("/oauth/introspect")).toHaveLength(3);
  });

  test("a public client can't introspect", async () => {
    const e = await failure(client({ clientSecret: undefined }).introspect("abcd-efgh-ijkl-mnop"));
    expect((e as Error).message).toContain("confidential");
    expect(seen("/oauth/introspect")).toHaveLength(0);
  });

  test("the caller can't change what the cache holds", async () => {
    fake.introspect = () => json(200, active);
    const c = client();
    const first = await c.introspect("abcd-efgh-ijkl-mnop");
    first?.scopes.push("admin");
    expect((await c.introspect("abcd-efgh-ijkl-mnop"))?.scopes).toEqual(["imap", "smtp"]);
  });
});

describe("revoke", () => {
  test("posts the refresh token with its hint", async () => {
    await client().revoke("rt_abc123");
    const [call] = seen("/oauth/revoke");
    expect(call?.form.get("token")).toBe("rt_abc123");
    expect(call?.form.get("token_type_hint")).toBe("refresh_token");
    expect(call?.headers.get("authorization")).toStartWith("Basic ");
  });

  test("is Unavailable when auth is unreachable", async () => {
    const c = client();
    await c.verifyAccessToken(accessToken());
    down = true;
    expect(await failure(c.revoke("rt_abc123"))).toBeInstanceOf(Unavailable);
  });
});

describe("readEvent", () => {
  test.each([
    ["session.ended", { sid: "ses_1" }, { sid: "ses_1" }],
    ["access.changed", { sub: "usr_alice", role: "admin" }, { sub: "usr_alice", role: "admin" }],
    ["access.changed", { sub: "usr_alice", role: null }, { sub: "usr_alice", role: null }],
    ["user.disabled", { sub: "usr_alice" }, { sub: "usr_alice" }],
    ["invite.accepted", { invite: "inv_1", sub: "usr_alice" }, { invite: "inv_1", sub: "usr_alice" }],
    ["user.deleted", { sub: "usr_alice" }, { sub: "usr_alice" }],
    ["credential.revoked", { sub: "usr_alice", id: "apw_1" }, { sub: "usr_alice", id: "apw_1" }],
  ])("reads %s %p", async (type, payload, fields) => {
    expect(await client().readEvent(setToken({ [type]: payload }))).toEqual({ type, jti: "evt_1", ...fields });
  });

  test("returns an event type it doesn't know with its type and jti only, so it can be acknowledged", async () => {
    expect(await client().readEvent(setToken({ "user.renamed": { sub: "usr_alice" } }))).toEqual({ type: "user.renamed", jti: "evt_1" });
  });

  test("events have no expiry: one delivered a day late still verifies", async () => {
    const body = setToken({ "user.disabled": { sub: "usr_alice" } });
    clock += 23 * 3_600_000;
    expect((await client().readEvent(body)).type).toBe("user.disabled");
  });

  const refusals: [string, () => string][] = [
    ["an access token", () => accessToken()],
    ["a SET typed at+jwt", () => setToken({ "user.disabled": { sub: "usr_alice" } }, {}, { typ: "at+jwt" })],
    ["another audience", () => setToken({ "user.disabled": { sub: "usr_alice" } }, { aud: "tasks" })],
    ["another issuer", () => setToken({ "user.disabled": { sub: "usr_alice" } }, { iss: "https://evil.example" })],
    ["an iat more than 30 s ahead", () => setToken({ "user.disabled": { sub: "usr_alice" } }, { iat: nowS() + 31 })],
    ["two events", () => setToken({ "user.disabled": { sub: "usr_alice" }, "user.deleted": { sub: "usr_alice" } })],
    ["no events", () => setToken({})],
    ["no jti", () => setToken({ "user.disabled": { sub: "usr_alice" } }, { jti: undefined })],
    ["user.disabled without sub", () => setToken({ "user.disabled": {} })],
    ["credential.revoked without id", () => setToken({ "credential.revoked": { sub: "usr_alice" } })],
    ["access.changed without role", () => setToken({ "access.changed": { sub: "usr_alice" } })],
    ["a signature by another key", () => setToken({ "user.disabled": { sub: "usr_alice" } }, {}, {}, stranger.privateKey)],
  ];
  test.each(refusals)("refuses %s", async (_, body) => {
    expect(await failure(client().readEvent(body()))).toBeInstanceOf(InvalidToken);
  });

  test("drops the user's cached introspection answers on user.disabled, access.changed and user.deleted", async () => {
    fake.introspect = () => json(200, { active: true, sub: "usr_alice", username: "alice", scope: "imap", role: "user", jti: "apw_1" });
    const c = client();
    let calls = 0;
    for (const event of [
      { "user.disabled": { sub: "usr_alice" } },
      { "access.changed": { sub: "usr_alice", role: null } },
      { "user.deleted": { sub: "usr_alice" } },
    ]) {
      await c.introspect("abcd-efgh-ijkl-mnop");
      calls++;
      await c.introspect("abcd-efgh-ijkl-mnop");
      expect(seen("/oauth/introspect")).toHaveLength(calls);
      await c.readEvent(setToken(event));
    }
    await c.introspect("abcd-efgh-ijkl-mnop");
    expect(seen("/oauth/introspect")).toHaveLength(calls + 1);
  });

  test("credential.revoked drops that credential's answer only", async () => {
    let n = 0;
    fake.introspect = () => json(200, { active: true, sub: "usr_alice", username: "alice", scope: "imap", role: "user", jti: `apw_${++n}` });
    const c = client();
    await c.introspect("aaaa-aaaa-aaaa-aaaa");
    await c.introspect("bbbb-bbbb-bbbb-bbbb");
    await c.readEvent(setToken({ "credential.revoked": { sub: "usr_alice", id: "apw_1" } }));
    await c.introspect("aaaa-aaaa-aaaa-aaaa");
    await c.introspect("bbbb-bbbb-bbbb-bbbb");
    expect(seen("/oauth/introspect")).toHaveLength(3);
  });
});
