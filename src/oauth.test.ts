import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { base64url, random, sha256 } from "./crypto";
import { signJwt } from "./jwt";
import { basic, Browser, makeUser, outboxEvents, TEST_DATABASE_URL, testApp, testDb, type TestApp, type TestDb } from "./testing/harness";

// The token, revocation, introspection, userinfo and logout endpoints' refusals
// (docs/DESIGN.md §7.2, §7.3, §9.4), each sent the input it refuses.
describe.skipIf(!TEST_DATABASE_URL)("OAuth endpoints", () => {
  let db: TestDb;
  let t: TestApp;
  const PW = "correct horse battery";
  beforeAll(async () => {
    db = await testDb();
    t = await testApp(db.sql);
  });
  afterAll(() => db.drop());

  const verifier = base64url(random(32));
  const authorizeUrl = (clientId: string, redirectUri: string) =>
    `/oauth/authorize?${new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: "code",
      state: "st",
      scope: "openid",
      nonce: "nn",
      code_challenge: base64url(sha256(verifier)),
      code_challenge_method: "S256",
    })}`;

  async function codeFor(b: Browser, clientId = "wiki", redirectUri = "https://wiki.example.com/auth/callback"): Promise<string> {
    const res = await b.request(authorizeUrl(clientId, redirectUri));
    const code = new URL(res.headers.get("Location")!).searchParams.get("code");
    if (!code) throw new Error(`no code: ${res.status} ${res.headers.get("Location")}`);
    return code;
  }

  const form = (path: string, fields: Record<string, string>, auth?: string, headers: Record<string, string> = {}) =>
    new Browser(t).request(path, {
      method: "POST",
      origin: null,
      headers: { "Content-Type": "application/x-www-form-urlencoded", ...(auth ? { Authorization: auth } : {}), ...headers },
      body: new URLSearchParams(fields).toString(),
    });
  const wikiAuth = () => basic("wiki", t.secrets.wiki!);
  const exchange = (code: string, auth = wikiAuth(), redirectUri = "https://wiki.example.com/auth/callback") =>
    form("/oauth/token", { grant_type: "authorization_code", code, redirect_uri: redirectUri, code_verifier: verifier }, auth);

  async function signedIn(username: string, access: Record<string, string>): Promise<{ b: Browser; id: string }> {
    const id = await makeUser(t, { username, password: PW, access });
    const b = new Browser(t);
    await b.signIn(username, PW);
    return { b, id };
  }

  describe("token", () => {
    test("a session that ended between authorize and exchange gets no tokens", async () => {
      const { b, id } = await signedIn("expiring", { wiki: "member" });
      const code = await codeFor(b);
      await t.app.sql`UPDATE sessions SET expires_at = now() - interval '1 second' WHERE user_id = ${id}`;
      expect((await (await exchange(code)).json() as any).error).toBe("invalid_grant");
    });

    test("a role that needs MFA by exchange time gets no tokens from a password-only session", async () => {
      const { b, id } = await signedIn("promoted-late", { wiki: "member" });
      const code = await codeFor(b);
      await t.app.sql`UPDATE access SET role = 'admin' WHERE user_id = ${id} AND service = 'wiki'`;
      expect((await (await exchange(code)).json() as any).error).toBe("invalid_grant");
    });

    test("a client id in the form must match the Basic one", async () => {
      const { b } = await signedIn("mismatch", { wiki: "member" });
      const code = await codeFor(b);
      const res = await form(
        "/oauth/token",
        { grant_type: "authorization_code", code, redirect_uri: "https://wiki.example.com/auth/callback", code_verifier: verifier, client_id: "tasks" },
        wikiAuth(),
      );
      expect(res.status).toBe(401);
      expect((await res.json() as any).error).toBe("invalid_client");
    });

    test("another grant type is unsupported_grant_type", async () => {
      expect((await (await form("/oauth/token", { grant_type: "password", username: "x", password: "y" }, wikiAuth())).json() as any).error).toBe(
        "unsupported_grant_type",
      );
    });

    test("refresh: another client, an expired token or an ended SSO session gets invalid_grant", async () => {
      const { b, id } = await signedIn("refresher", { wiki: "member", tasks: "user" });
      const tokens = (await (await exchange(await codeFor(b))).json()) as any;
      const refresh = (auth: string) => form("/oauth/token", { grant_type: "refresh_token", refresh_token: tokens.refresh_token }, auth);
      expect((await refresh(wikiAuth())).status).toBe(200);
      expect((await (await refresh(basic("tasks", t.secrets.tasks!))).json() as any).error).toBe("invalid_grant");
      await t.app.sql`UPDATE refresh_tokens SET expires_at = now() - interval '1 second' WHERE token_hash = ${sha256(tokens.refresh_token)}`;
      expect((await (await refresh(wikiAuth())).json() as any).error).toBe("invalid_grant");
      await t.app.sql`UPDATE refresh_tokens SET expires_at = now() + interval '1 day' WHERE token_hash = ${sha256(tokens.refresh_token)}`;
      await t.app.sql`UPDATE sessions SET ends_at = now() - interval '1 second' WHERE user_id = ${id}`;
      expect((await (await refresh(wikiAuth())).json() as any).error).toBe("invalid_grant");
    });

    test("sixty token requests a minute per client", async () => {
      await t.app.sql`INSERT INTO throttle (key, window_start, hits) VALUES ('client:mailbox:token', now(), 60)`;
      const res = await form("/oauth/token", { grant_type: "refresh_token", refresh_token: "rt_x" }, basic("mailbox", t.secrets.mailbox!));
      expect(res.status).toBe(429);
      expect(Number(res.headers.get("Retry-After"))).toBeGreaterThan(0);
    });
  });

  describe("revoke (RFC 7009)", () => {
    test("revokes the caller's own refresh token, and nobody else's", async () => {
      const { b } = await signedIn("revoker", { wiki: "member" });
      const tokens = (await (await exchange(await codeFor(b))).json()) as any;
      expect((await form("/oauth/revoke", { token: tokens.refresh_token }, basic("tasks", t.secrets.tasks!))).status).toBe(200);
      const still = await form("/oauth/token", { grant_type: "refresh_token", refresh_token: tokens.refresh_token }, wikiAuth());
      expect(still.status).toBe(200);
      expect((await form("/oauth/revoke", { token: tokens.refresh_token }, wikiAuth())).status).toBe(200);
      const gone = await form("/oauth/token", { grant_type: "refresh_token", refresh_token: tokens.refresh_token }, wikiAuth());
      expect((await gone.json() as any).error).toBe("invalid_grant");
      // An unknown token gets the same answer.
      expect((await form("/oauth/revoke", { token: "rt_unknown" }, wikiAuth())).status).toBe(200);
    });

    test("a public client's revocation ends its family, tells the service and is audited", async () => {
      const { b, id } = await signedIn("native", { tasks: "user" });
      const code = await codeFor(b, "tasks-ios", "com.example.tasks:/auth/callback");
      const res = await form("/oauth/token", {
        grant_type: "authorization_code",
        code,
        redirect_uri: "com.example.tasks:/auth/callback",
        code_verifier: verifier,
        client_id: "tasks-ios",
      });
      const tokens = (await res.json()) as any;
      const rotated = (await (await form("/oauth/token", { grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: "tasks-ios" })).json()) as any;
      expect((await form("/oauth/revoke", { token: rotated.refresh_token, client_id: "tasks-ios" })).status).toBe(200);
      const [{ live }] = await t.app.sql`SELECT count(*)::int AS live FROM refresh_tokens WHERE user_id = ${id} AND revoked_at IS NULL`;
      expect(live).toBe(0);
      const sid = JSON.parse(Buffer.from(tokens.access_token.split(".")[1], "base64url").toString()).sid;
      expect((await outboxEvents(t.app.sql, "tasks")).some((e) => e.type === "session.ended" && e.payload.sid === sid)).toBe(true);
      expect(await t.app.sql`SELECT 1 FROM audit WHERE user_id = ${id} AND action = 'token.revoke'`).toHaveLength(1);
    });

    test("ending a family while it rotates leaves no live token", async () => {
      for (let round = 0; round < 8; round++) {
        const { b, id } = await signedIn(`racer-${round}`, { tasks: "user" });
        const code = await codeFor(b, "tasks-ios", "com.example.tasks:/auth/callback");
        const tokens = (await (
          await form("/oauth/token", { grant_type: "authorization_code", code, redirect_uri: "com.example.tasks:/auth/callback", code_verifier: verifier, client_id: "tasks-ios" })
        ).json()) as any;
        const sid = JSON.parse(Buffer.from(tokens.access_token.split(".")[1], "base64url").toString()).sid;
        await Promise.all([
          form("/oauth/token", { grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: "tasks-ios" }),
          b.api("DELETE", `/v1/me/sessions/${sid}`),
        ]);
        const [{ live }] = await t.app.sql`SELECT count(*)::int AS live FROM refresh_tokens WHERE user_id = ${id} AND revoked_at IS NULL`;
        expect(live).toBe(0);
      }
    });
  });

  describe("introspect", () => {
    test("600 a minute per client, and 1000 failures an hour per client", async () => {
      await t.app.sql`INSERT INTO throttle (key, window_start, hits) VALUES ('client:wiki:introspect', now(), 600)`;
      expect((await form("/oauth/introspect", { token: "x" }, wikiAuth())).status).toBe(429);
      await t.app.sql`DELETE FROM throttle WHERE key = 'client:wiki:introspect'`;
      await t.app.sql`INSERT INTO throttle (key, window_start, hits) VALUES ('client:wiki:introspect-fail', now(), 1000)`;
      expect((await form("/oauth/introspect", { token: "x" }, wikiAuth())).status).toBe(429);
      await t.app.sql`DELETE FROM throttle WHERE key = 'client:wiki:introspect-fail'`;
    });

    test("an address the proxy set, the request's own, doesn't key the per-address counter", async () => {
      // The harness's request address is 192.0.2.10, as a proxy would set it.
      for (let i = 0; i < 12; i++) {
        expect((await form("/oauth/introspect", { token: `wrong-${i}` }, basic("mailbox", t.secrets.mailbox!), { "X-Real-IP": "192.0.2.10" })).status).toBe(200);
      }
      await t.app.sql`DELETE FROM throttle WHERE key LIKE 'client:mailbox:introspect%'`;
    });
  });

  describe("userinfo", () => {
    test("answers for a valid access token of any service", async () => {
      const { b, id } = await signedIn("info", { wiki: "member" });
      const tokens = (await (await exchange(await codeFor(b))).json()) as any;
      const res = await new Browser(t).request("/oauth/userinfo", { headers: { Authorization: `Bearer ${tokens.access_token}` } });
      expect(await res.json()).toMatchObject({ sub: id, username: "info", preferred_username: "info", email: "info@example.com", email_verified: true });
    });

    test("refuses no token, an ID token, a token for no service, and a disabled user", async () => {
      const { b, id } = await signedIn("info2", { wiki: "member" });
      const tokens = (await (await exchange(await codeFor(b))).json()) as any;
      const ask = (token?: string) => new Browser(t).request("/oauth/userinfo", { headers: token ? { Authorization: `Bearer ${token}` } : {} });
      const none = await ask();
      expect(none.status).toBe(401);
      expect(none.headers.get("WWW-Authenticate")).toBe('Bearer error="invalid_token"');
      expect((await ask(tokens.id_token)).status).toBe(401);
      const now = Math.floor(Date.now() / 1000);
      const stray = signJwt("at+jwt", { iss: t.app.config.issuer, sub: id, aud: "elsewhere", iat: now, exp: now + 600 }, await t.app.keys.signer());
      expect((await ask(stray)).status).toBe(401);
      await t.app.sql`UPDATE users SET disabled_at = now() WHERE id = ${id}`;
      expect((await ask(tokens.access_token)).status).toBe(401);
    });
  });

  describe("logout", () => {
    test("the return address matches a registered one exactly, not by prefix", async () => {
      const { b } = await signedIn("leaving", { wiki: "member" });
      const res = await b.request(`/logout?${new URLSearchParams({ client_id: "wiki", post_logout_redirect_uri: "https://wiki.example.com/x" })}`);
      expect(res.status).toBe(400);
      expect((await b.api("GET", "/v1/me")).status).toBe(200);
    });

    test("signing out is audited", async () => {
      const { b, id } = await signedIn("audited", { wiki: "member" });
      await b.request("/logout?client_id=wiki&post_logout_redirect_uri=https%3A%2F%2Fwiki.example.com%2F");
      expect(await t.app.sql`SELECT 1 FROM audit WHERE user_id = ${id} AND action = 'logout'`).toHaveLength(1);
    });
  });
});
