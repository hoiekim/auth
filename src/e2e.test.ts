import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import type { Server } from "bun";
import { createAuthClient, InvalidGrant } from "../client/auth-client";
import { createCredential } from "./credentials";
import { base64url, random, sha256 } from "./crypto";
import { handle } from "./server";
import { Browser, makeUser, outboxEvents, TEST_DATABASE_URL, testApp, testDb, type TestApp, type TestDb } from "./testing/harness";
import { transaction } from "./tx";

// The whole sign-in, refresh, revocation and logout path, driven by the
// published client library (client/auth-client.ts) against the real server
// over HTTP, as an app would (docs/DESIGN.md §7.1–§7.6).
describe.skipIf(!TEST_DATABASE_URL)("an app using the client library", () => {
  let db: TestDb;
  let t: TestApp;
  let server: Server<unknown>;
  let issuer: string;

  beforeAll(async () => {
    db = await testDb();
    let current: TestApp | null = null;
    server = Bun.serve({ port: 0, development: false, fetch: (req) => handle(req, current!.app, current!.router, "127.0.0.1") });
    issuer = `http://localhost:${server.port}`;
    t = await testApp(db.sql, { ISSUER_URL: issuer });
    current = t;
  });
  afterAll(async () => {
    await server.stop(true);
    await db.drop();
  });

  const wiki = () =>
    createAuthClient({ issuer, clientId: "wiki", clientSecret: t.secrets.wiki, redirectUri: "https://wiki.example.com/auth/callback" });

  // The browser's part: follow auth's redirects, signing in when asked, until
  // auth sends it back to the app.
  async function browse(browser: Browser, url: string, credentials: { login: string; password: string }): Promise<string> {
    let res = await browser.request(url);
    for (let hops = 0; hops < 5; hops++) {
      const location = res.headers.get("Location") ?? "";
      if (location.startsWith("https://wiki.example.com/") || location.startsWith("com.example.tasks:")) return location;
      if (location.startsWith("/login?")) {
        const returnTo = new URL(location, issuer).searchParams.get("return_to")!;
        res = await browser.form("/login", { ...credentials, return_to: returnTo });
        continue;
      }
      if (!location) throw new Error(`stopped at ${res.status}: ${(await res.text()).slice(0, 200)}`);
      res = await browser.request(location);
    }
    throw new Error("too many redirects");
  }

  function callback(location: string, loginCookie: string): Request {
    return new Request(location.replace("com.example.tasks:/", "https://tasks.example.com/"), {
      headers: { Cookie: loginCookie.split(";")[0]! },
    });
  }

  test("sign-in, refresh, verification, events and sign-out", async () => {
    const alice = await makeUser(t, { username: "alice", password: "correct horse battery", access: { wiki: "member" } });
    const auth = wiki();
    const browser = new Browser(t);

    const { redirectUrl, loginCookie } = await auth.startLogin(new Request("https://wiki.example.com/pages"), { returnTo: "/pages" });
    const back = await browse(browser, redirectUrl, { login: "alice", password: "correct horse battery" });
    const login = await auth.finishLogin(callback(back, loginCookie));

    expect(login.returnTo).toBe("/pages");
    expect(login.claims).toMatchObject({ iss: issuer, sub: alice, aud: "wiki", username: "alice", name: "Alice", role: "member" });
    expect(Object.keys(login.claims).sort()).toEqual(["aud", "exp", "iat", "iss", "name", "role", "sid", "sub", "username"]);
    expect(login.claims.exp - login.claims.iat).toBe(600);
    expect(login.idClaims).toMatchObject({ aud: "wiki", sub: alice, amr: ["pwd"], email: "alice@example.com", email_verified: true });
    expect(login.refreshToken).toMatch(/^rt_[A-Za-z0-9_-]{43}$/);

    // A confidential client's refresh token isn't rotated.
    const refreshed = await auth.refresh(login.refreshToken!);
    expect(refreshed.refreshToken).toBeUndefined();
    expect(refreshed.claims).toMatchObject({ sub: alice, role: "member", sid: login.claims.sid });
    expect(await auth.verifyAccessToken(refreshed.accessToken)).toMatchObject({ sub: alice });

    // A role change reaches the next refresh, and the app by event.
    const admin = await makeUser(t, { username: "root", password: "correct horse battery" });
    await transaction(t.app.sql, async (tx, after) => {
      const { putAccess } = await import("./access");
      await putAccess(tx, t.app, { userId: alice, service: t.app.services.get("wiki")!, role: "owner", actor: admin, ip: null }, after);
    });
    // owner needs MFA, and this sign-in used a password only.
    await expect(auth.refresh(login.refreshToken!)).rejects.toBeInstanceOf(InvalidGrant);
    const [changed] = (await outboxEvents(t.app.sql, "wiki")).filter((e) => e.type === "access.changed" && e.payload.role === "owner");
    expect(changed?.payload).toEqual({ sub: alice, role: "owner" });
    const tokens: { token: string }[] = await t.app.sql`SELECT token FROM outbox WHERE service = 'wiki' ORDER BY id DESC LIMIT 1`;
    expect(await auth.readEvent(tokens[0]!.token)).toMatchObject({ type: "access.changed", sub: alice, role: "owner" });

    // Back to member, then sign out: the SSO session ends, the app is told,
    // and its refresh token stops.
    await t.app.sql`UPDATE access SET role = 'member' WHERE user_id = ${alice} AND service = 'wiki'`;
    expect((await auth.refresh(login.refreshToken!)).claims.role).toBe("member");
    const out = await browser.request(await auth.logoutUrl("https://wiki.example.com/"));
    expect(out.status).toBe(302);
    expect(out.headers.get("Location")).toBe("https://wiki.example.com/");
    const ended = (await outboxEvents(t.app.sql, "wiki")).filter((e) => e.type === "session.ended");
    expect(ended.map((e) => e.payload)).toEqual([{ sid: login.claims.sid }]);
    await expect(auth.refresh(login.refreshToken!)).rejects.toBeInstanceOf(InvalidGrant);
  });

  test("SSO: a second sign-in reuses the session without a password", async () => {
    await makeUser(t, { username: "sso-user", password: "correct horse battery", access: { wiki: "member", tasks: "user" } });
    const browser = new Browser(t);
    const first = await wiki().startLogin(new Request("https://wiki.example.com/"));
    await browse(browser, first.redirectUrl, { login: "sso-user", password: "correct horse battery" });
    const tasks = createAuthClient({ issuer, clientId: "tasks", clientSecret: t.secrets.tasks, redirectUri: "https://tasks.example.com/auth/callback" });
    const second = await tasks.startLogin(new Request("https://tasks.example.com/"));
    const res = await browser.request(second.redirectUrl);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location.startsWith("https://tasks.example.com/auth/callback?code=")).toBe(true);
    const login = await tasks.finishLogin(callback(location, second.loginCookie));
    expect(login.claims).toMatchObject({ aud: "tasks", role: "user", username: "sso-user" });
  });

  test("a public client's refresh tokens rotate, and reuse past the grace period ends the family", async () => {
    await makeUser(t, { username: "mobile", password: "correct horse battery" });
    const app = createAuthClient({ issuer, clientId: "tasks-ios", redirectUri: "com.example.tasks:/auth/callback", audience: "tasks" });
    const browser = new Browser(t);
    const { redirectUrl, loginCookie } = await app.startLogin(new Request("https://tasks.example.com/"));
    const back = await browse(browser, redirectUrl, { login: "mobile", password: "correct horse battery" });
    const login = await app.finishLogin(callback(back, loginCookie));
    // An open service gives a first sign-in its default_role.
    expect(login.claims.role).toBe("user");

    const r1 = await app.refresh(login.refreshToken!);
    expect(r1.refreshToken).toMatch(/^rt_/);
    expect(r1.refreshToken).not.toBe(login.refreshToken);
    // Within 30 s the old token still works (two requests racing).
    const r1b = await app.refresh(login.refreshToken!);
    expect(r1b.claims.sid).toBe(login.claims.sid);

    await t.app.sql`UPDATE refresh_tokens SET rotated_at = now() - interval '31 seconds' WHERE token_hash = ${sha256(login.refreshToken!)}`;
    await expect(app.refresh(login.refreshToken!)).rejects.toBeInstanceOf(InvalidGrant);
    // The whole family is gone, the newest token included.
    await expect(app.refresh(r1.refreshToken!)).rejects.toBeInstanceOf(InvalidGrant);
    expect(t.alerts.some((a) => a.includes("reused refresh token"))).toBe(true);
    expect((await outboxEvents(t.app.sql, "tasks")).some((e) => e.type === "session.ended" && e.payload.sid === login.claims.sid)).toBe(true);
  });

  test("a password-only protocol server checks app passwords by introspection", async () => {
    const carol = await makeUser(t, { username: "carol", password: "correct horse battery", access: { mailbox: "user" } });
    const created = await transaction(t.app.sql, (tx) =>
      createCredential(tx, t.app, {
        userId: carol,
        kind: "app_password",
        service: t.app.services.get("mailbox")!,
        scopes: ["imap"],
        name: "phone",
        actor: carol,
        ip: null,
      }),
    );
    expect(created.secret).toMatch(/^[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}$/);
    const mailbox = createAuthClient({ issuer, clientId: "mailbox", clientSecret: t.secrets.mailbox, redirectUri: "https://mail.example.com/auth/callback" });
    expect(await mailbox.introspect(created.secret, { ip: "198.51.100.7" })).toEqual({
      sub: carol,
      username: "carol",
      role: "user",
      scopes: ["imap"],
      id: created.row.id,
    });
    // Typed without dashes, in capitals, on a phone keyboard.
    mailbox.forget({ id: created.row.id });
    expect((await mailbox.introspect(created.secret.replace(/-/g, "").toUpperCase()))?.id).toBe(created.row.id);
    // Another service's client never sees it.
    const wikiClient = wiki();
    expect(await wikiClient.introspect(created.secret)).toBeNull();
  });

  test("the authorization code is single use and bound to the client, redirect URI and verifier", async () => {
    // A role on both services, so only the code's binding to its client can refuse another client.
    await makeUser(t, { username: "dave", password: "correct horse battery", access: { wiki: "member", tasks: "user" } });
    const browser = new Browser(t);
    const verifier = base64url(random(32));
    const challenge = base64url(sha256(verifier));
    const authorize = `/oauth/authorize?${new URLSearchParams({
      client_id: "wiki",
      redirect_uri: "https://wiki.example.com/auth/callback",
      response_type: "code",
      state: "st",
      scope: "openid",
      nonce: "nn",
      code_challenge: challenge,
      code_challenge_method: "S256",
    })}`;
    const code = async () => new URL(await browse(browser, authorize, { login: "dave", password: "correct horse battery" })).searchParams.get("code")!;
    const exchange = (fields: Record<string, string>, auth = `Basic ${Buffer.from(`wiki:${t.secrets.wiki}`).toString("base64")}`) =>
      fetch(`${issuer}/oauth/token`, {
        method: "POST",
        headers: { Authorization: auth, "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(fields),
      });
    const good = { grant_type: "authorization_code", redirect_uri: "https://wiki.example.com/auth/callback", code_verifier: verifier };

    const c1 = await code();
    expect((await exchange({ ...good, code: c1 })).status).toBe(200);
    const reused = await exchange({ ...good, code: c1 });
    expect(reused.status).toBe(400);
    expect(await reused.json() as any).toMatchObject({ error: "invalid_grant" });

    const c2 = await code();
    expect((await (await exchange({ ...good, code: c2, code_verifier: base64url(random(32)) })).json() as any).error).toBe("invalid_grant");
    // The failed attempt used the code up.
    expect((await exchange({ ...good, code: c2 })).status).toBe(400);

    const c3 = await code();
    expect((await (await exchange({ ...good, code: c3, redirect_uri: "https://wiki.example.com/auth/callback/" })).json() as any).error).toBe("invalid_grant");

    const c4 = await code();
    const tasksAuth = `Basic ${Buffer.from(`tasks:${t.secrets.tasks}`).toString("base64")}`;
    expect((await (await exchange({ ...good, code: c4 }, tasksAuth)).json() as any).error).toBe("invalid_grant");

    const c5 = await code();
    await t.app.sql`UPDATE auth_codes SET expires_at = now() - interval '1 second' WHERE code_hash = ${sha256(c5)}`;
    expect((await (await exchange({ ...good, code: c5 })).json() as any).error).toBe("invalid_grant");

    const c6 = await code();
    const wrongSecret = await exchange({ ...good, code: c6 }, `Basic ${Buffer.from("wiki:not-the-secret").toString("base64")}`);
    expect(wrongSecret.status).toBe(401);
    expect(wrongSecret.headers.get("WWW-Authenticate")).toBe('Basic realm="auth"');
    expect(await wrongSecret.json() as any).toMatchObject({ error: "invalid_client" });
    // client_secret_post isn't offered.
    const post = await fetch(`${issuer}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ ...good, code: c6, client_id: "wiki", client_secret: t.secrets.wiki! }),
    });
    expect((await post.json() as any).error).toBe("invalid_client");
  });
});
