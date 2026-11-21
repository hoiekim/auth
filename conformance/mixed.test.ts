import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { SoftAuthenticator } from "../src/testing/authenticator";
import { authorizeParams, BACKEND, bothBackends, type Browser, decodeJwt, enabled, fromBase32, OTHER, pkce, REDIRECTS, type ServerProcess, Stack, totp, type TokenSet } from "./harness";

// The two servers side by side on one database, as during a deploy that
// moves a deployment from one to the other (docs/DESIGN.md §3: two copies at
// once, every piece of state in Postgres). Whatever one writes, the other
// reads: password hashes, sessions and their CSRF tokens, encrypted TOTP
// secrets and signing keys, sealed cookies, codes and refresh tokens,
// passkeys, API keys, registered services and rate-limit counters.
//
// It needs both servers, so it runs only where the Rust one is built.

setDefaultTimeout(60_000);

let seq = 0;
const uname = (prefix: string) => `${prefix}-${Date.now().toString(36).slice(-5)}${(seq++).toString(36)}`;

async function post(base: string, path: string, fields: Record<string, string>, authorization?: string): Promise<Response> {
  const headers: Record<string, string> = { "Content-Type": "application/x-www-form-urlencoded" };
  if (authorization) headers.Authorization = authorization;
  return fetch(`${base}${path}`, { method: "POST", headers, body: new URLSearchParams(fields).toString(), redirect: "manual" });
}

describe.skipIf(!enabled || !bothBackends)(`a ${BACKEND} copy and a ${OTHER} copy on one database`, () => {
  let stack: Stack;
  let other: ServerProcess;

  beforeAll(async () => {
    stack = await Stack.start();
    other = await stack.spawn({ backend: OTHER });
    await other.ready();
  });
  afterAll(async () => {
    await stack.stop();
  });
  beforeEach(async () => {
    await stack.resetLimits();
  });

  test(`the ${OTHER} copy starts on the schema the ${BACKEND} copy made, and serves the same keys`, async () => {
    expect(stack.logs.filter((l) => l.startsWith("migration "))).toEqual(["migration 0001_initial applied", "migration 0002_services applied"]);
    expect(other.logs.filter((l) => l.startsWith("migration "))).toEqual([]);
    const mine = (await (await fetch(`${stack.url}/.well-known/jwks.json`)).json()) as { keys: unknown[] };
    const theirs = (await (await fetch(`${other.url}/.well-known/jwks.json`)).json()) as { keys: unknown[] };
    expect(mine.keys).toHaveLength(1);
    expect(theirs).toEqual(mine);
    expect(await (await fetch(`${other.url}/.well-known/openid-configuration`)).json()).toEqual(await (await fetch(`${stack.url}/.well-known/openid-configuration`)).json());
  });

  // Each scenario runs both ways: written by one server and read by the other.
  describe.each([
    [BACKEND, OTHER],
    [OTHER, BACKEND],
  ] as const)("written by %s, read by %s", (writer, reader) => {
    const w = () => (writer === BACKEND ? stack.url : other.url);
    const r = () => (reader === BACKEND ? stack.url : other.url);
    const at = (base: string, from?: Browser): Browser => {
      const b = stack.browser();
      b.base = base;
      if (from) for (const [k, v] of from.cookies) b.cookies.set(k, v);
      return b;
    };

    test("a password set through one is verified by the other", async () => {
      const username = uname("pw");
      const made = await stack.cli(["user", "create", "--username", username, "--email", `${username}@example.com`, "--print-link"], { backend: writer });
      expect(made.code).toBe(0);
      const link = new URL(made.out.find((l) => l.startsWith("activation link"))!.split(": ")[1]!);
      const activating = at(w());
      await activating.request(link.pathname + link.search);
      const set = await activating.form("/activate", { token: link.searchParams.get("token")!, password: "a password one server hashed" });
      expect(set.status).toBe(303);
      const hash: { password_hash: string }[] = await stack.db`SELECT password_hash FROM users WHERE username = ${username}`;
      expect(hash[0]!.password_hash).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/);

      const wrong = await at(r()).signIn(username, "a password no server hashed");
      expect(wrong.status).toBe(401);
      const right = await at(r()).signIn(username, "a password one server hashed");
      expect(right.status).toBe(303);
      expect(right.headers.get("Location")).toBe("/account");
      // It was already in today's format: the other server leaves it as it is.
      expect(await stack.db`SELECT password_hash FROM users WHERE username = ${username}`).toEqual(hash);
    });

    test("a session one opened, and its CSRF token, hold at the other", async () => {
      const user = await stack.user({ username: uname("ses") });
      const first = at(w());
      expect((await first.signIn(user.username, user.password!)).status).toBe(303);
      const csrf = await first.csrf();
      expect(csrf).not.toBe("");

      const second = at(r(), first);
      const me = await second.request("/v1/me");
      expect(me.status).toBe(200);
      expect(((await me.json()) as { id: string }).id).toBe(user.id);
      expect(await second.csrf()).toBe(csrf);
      const renamed = await second.request("/v1/me", { method: "PATCH", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: JSON.stringify({ name: "Renamed" }) });
      expect(renamed.status).toBe(200);
      const refused = await second.request("/v1/me", { method: "PATCH", headers: { "Content-Type": "application/json", "X-CSRF-Token": `${csrf}x` }, body: JSON.stringify({ name: "No" }) });
      expect(refused.status).toBe(403);

      // Signed out at one, signed out at the other.
      expect((await second.request("/v1/me/sessions", { method: "DELETE", headers: { "X-CSRF-Token": csrf } })).status).toBe(204);
      expect((await first.request("/v1/me")).status).toBe(401);
    });

    test("a TOTP secret one encrypted, and the pending sign-in it sealed, are read by the other", async () => {
      const user = await stack.user({ username: uname("totp") });
      const enrolling = at(w());
      await enrolling.signIn(user.username, user.password!);
      const started = (await (await enrolling.api("POST", "/v1/me/totp", {})).json()) as { secret: string; enrollment: string };
      const secret = fromBase32(started.secret);
      const confirmed = await enrolling.api("POST", "/v1/me/totp", { enrollment: started.enrollment, code: totp(secret) });
      expect(confirmed.status).toBe(200);
      const { recovery_codes } = (await confirmed.json()) as { recovery_codes: string[] };
      expect(recovery_codes).toHaveLength(10);

      // Password and code both at the reader.
      await stack.db`UPDATE totp SET last_step = 0 WHERE user_id = ${user.id}`;
      const there = at(r());
      expect((await there.signIn(user.username, user.password!, totp(secret))).headers.get("Location")).toBe("/account");
      const amr: { amr: string[] }[] = await stack.db`SELECT amr FROM sessions WHERE user_id = ${user.id} ORDER BY created_at DESC LIMIT 1`;
      expect(amr[0]!.amr).toEqual(["pwd", "otp", "mfa"]);

      // The password at the writer, which seals the pending sign-in in a
      // cookie; the code at the reader, which opens it.
      await stack.db`UPDATE totp SET last_step = 0 WHERE user_id = ${user.id}`;
      const half = at(w());
      const password = await half.form("/login", { login: user.username, password: user.password!, return_to: "/account#here" });
      expect(password.headers.get("Location")).toStartWith("/login/second-factor?");
      const finishing = at(r(), half);
      const code = await finishing.form("/login/second-factor", { code: totp(secret) });
      expect(code.status).toBe(303);
      expect(code.headers.get("Location")).toBe("/account#here");

      // A recovery code one made is spent at the other.
      const recovering = at(r());
      const recovered = await recovering.signIn(user.username, user.password!, recovery_codes[0]!);
      expect(recovered.headers.get("Location")).toBe("/account");
      const left: { n: number }[] = await stack.db`SELECT count(*)::int AS n FROM recovery_codes WHERE user_id = ${user.id} AND used_at IS NULL`;
      expect(left[0]!.n).toBe(9);
    });

    test("a code one issued is redeemed by the other, whose tokens both verify; a refresh token crosses too", async () => {
      const user = await stack.user({ username: uname("oidc"), access: { wiki: "member" } });
      const browser = at(w());
      await browser.signIn(user.username, user.password!);
      const { verifier, challenge } = pkce();
      const back = await browser.authorize(authorizeParams("wiki", REDIRECTS.wiki!, challenge));
      const code = back.searchParams.get("code")!;
      expect(code).toMatch(/^[A-Za-z0-9_-]{43}$/);

      const exchanged = await post(r(), "/oauth/token", { grant_type: "authorization_code", code, redirect_uri: REDIRECTS.wiki!, code_verifier: verifier }, stack.basic("wiki"));
      expect(exchanged.status).toBe(200);
      const tokens = (await exchanged.json()) as TokenSet;
      // Signed by the reader with the key in the database; checked against
      // the keys either publishes.
      expect(await stack.verified(tokens.access_token, "at+jwt")).toMatchObject({ iss: stack.issuer, sub: user.id, aud: "wiki", role: "member", username: user.username });
      expect(await stack.verified(tokens.id_token!, "JWT")).toMatchObject({ aud: "wiki", sub: user.id, amr: ["pwd"], email: user.email });
      expect(Object.keys(decodeJwt(tokens.access_token).claims).sort()).toEqual(["aud", "exp", "iat", "iss", "name", "role", "sid", "sub", "username"]);

      for (const base of [w(), r()]) {
        const info = await fetch(`${base}/oauth/userinfo`, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
        expect(info.status).toBe(200);
        expect(((await info.json()) as { sub: string }).sub).toBe(user.id);
      }

      const refreshed = await post(w(), "/oauth/token", { grant_type: "refresh_token", refresh_token: tokens.refresh_token! }, stack.basic("wiki"));
      expect(refreshed.status).toBe(200);
      const again = (await refreshed.json()) as TokenSet;
      expect((await stack.verified(again.access_token, "at+jwt")).sid).toBe(decodeJwt(tokens.access_token).claims.sid);

      // Used once, at either.
      expect((await post(w(), "/oauth/token", { grant_type: "authorization_code", code, redirect_uri: REDIRECTS.wiki!, code_verifier: verifier }, stack.basic("wiki"))).status).toBe(400);
    });

    test("a public client's refresh token rotates across the two", async () => {
      const user = await stack.user({ username: uname("native") });
      const browser = at(w());
      await browser.signIn(user.username, user.password!);
      const { verifier, challenge } = pkce();
      const back = await browser.authorize(authorizeParams("tasks-ios", REDIRECTS["tasks-ios"]!, challenge));
      const first = (await (await post(w(), "/oauth/token", { grant_type: "authorization_code", code: back.searchParams.get("code")!, redirect_uri: REDIRECTS["tasks-ios"]!, code_verifier: verifier, client_id: "tasks-ios" })).json()) as TokenSet;
      const second = (await (await post(r(), "/oauth/token", { grant_type: "refresh_token", refresh_token: first.refresh_token!, client_id: "tasks-ios" })).json()) as TokenSet;
      expect(second.refresh_token).toMatch(/^rt_/);
      expect(second.refresh_token).not.toBe(first.refresh_token);
      const third = await post(w(), "/oauth/token", { grant_type: "refresh_token", refresh_token: second.refresh_token!, client_id: "tasks-ios" });
      expect(third.status).toBe(200);
      // Reuse past the grace period, seen by the other copy, ends the family for both.
      await stack.db`UPDATE refresh_tokens SET rotated_at = now() - interval '31 seconds' WHERE rotated_at IS NOT NULL AND user_id = ${user.id}`;
      expect((await post(r(), "/oauth/token", { grant_type: "refresh_token", refresh_token: first.refresh_token!, client_id: "tasks-ios" })).status).toBe(400);
      const newest = ((await third.json()) as TokenSet).refresh_token!;
      expect((await post(w(), "/oauth/token", { grant_type: "refresh_token", refresh_token: newest, client_id: "tasks-ios" })).status).toBe(400);
    });

    test("an API key and an app password one made answer the other's introspection, until revoked", async () => {
      const user = await stack.user({ username: uname("cred"), access: { tasks: "user", mailbox: "user" } });
      const browser = at(w());
      await browser.signIn(user.username, user.password!);
      const key = (await (await browser.api("POST", "/v1/me/api-keys", { name: "ci", service: "tasks", scopes: ["tasks:read"] })).json()) as { id: string; key: string };
      const app = (await (await browser.api("POST", "/v1/me/app-passwords", { name: "phone", service: "mailbox", scopes: ["imap"] })).json()) as { id: string; password: string };
      expect(key.key).toStartWith(`testkey_${key.id}_`);
      expect(app.password).toMatch(/^[a-z2-7]{4}(-[a-z2-7]{4}){3}$/);

      const introspect = async (base: string, client: string, token: string) => (await (await post(base, "/oauth/introspect", { token }, stack.basic(client))).json()) as Record<string, unknown>;
      expect(await introspect(r(), "tasks", key.key)).toEqual({ active: true, sub: user.id, username: user.username, scope: "tasks:read", role: "user", jti: key.id });
      expect(await introspect(r(), "mailbox", app.password.replace(/-/g, "").toUpperCase())).toMatchObject({ active: true, jti: app.id, scope: "imap" });

      const there = at(r(), browser);
      expect((await there.api("DELETE", `/v1/me/api-keys/${key.id}`)).status).toBe(204);
      expect(await introspect(w(), "tasks", key.key)).toEqual({ active: false });
      expect((await stack.outbox("tasks")).some((e) => e.type === "credential.revoked" && e.payload.id === key.id)).toBe(true);
    });

    test("a passkey registered at one signs in at the other, the challenge sealed by either", async () => {
      const user = await stack.user({ username: uname("pk") });
      const browser = at(w());
      await browser.signIn(user.username, user.password!);
      const authenticator = new SoftAuthenticator(-7);
      const begun = (await (await browser.api("POST", "/v1/me/passkeys", {})).json()) as { options: any; registration: string };
      const registered = await browser.api("POST", "/v1/me/passkeys", { registration: begun.registration, response: authenticator.create(begun.options, stack.issuer), name: "Key" });
      expect(registered.status).toBe(201);

      // The whole ceremony at the reader.
      const there = at(r());
      const options = (await (await there.request("/login/passkey/options", { method: "POST" })).json()) as { options: any };
      const signedIn = await there.request("/login/passkey", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ response: authenticator.get(options.options, stack.issuer) }) });
      expect(signedIn.status).toBe(200);
      expect(await signedIn.json()).toEqual({ redirect: "/account" });
      expect((await there.request("/v1/me")).status).toBe(200);

      // The challenge sealed by the writer, the assertion checked by the reader.
      const split = at(w());
      const sealed = (await (await split.request("/login/passkey/options", { method: "POST" })).json()) as { options: any };
      const finished = await at(r(), split).request("/login/passkey", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ response: authenticator.get(sealed.options, stack.issuer) }) });
      expect(finished.status).toBe(200);
      // And used once, whichever copy it is shown to next.
      const replayed = await at(w(), split).request("/login/passkey", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ response: authenticator.get(sealed.options, stack.issuer) }) });
      expect(replayed.status).toBe(401);
    });

    test("a service registered at one serves at the other at once, with the secret it made", async () => {
      const { browser } = await stack.admin();
      browser.base = w();
      const name = uname("svc");
      const definition = { name, roles: ["user"], mfa_roles: [], signup: "invite", clients: [{ id: name, type: "confidential", redirect_uris: [`https://${name}.example.com/cb`] }] };
      expect((await post(r(), "/oauth/introspect", { token: "x" }, `Basic ${Buffer.from(`${name}:nope`).toString("base64")}`)).status).toBe(401);
      expect((await browser.api("POST", "/v1/services", definition)).status).toBe(201);
      const { secret } = (await (await browser.api("POST", `/v1/clients/${name}/secrets`)).json()) as { secret: string };
      const authorization = `Basic ${Buffer.from(`${name}:${secret}`).toString("base64")}`;
      const known = await post(r(), "/oauth/introspect", { token: "x" }, authorization);
      expect(known.status).toBe(200);
      expect(await known.json()).toEqual({ active: false });
      // Deleted at the other, gone at the first.
      browser.base = r();
      expect((await browser.api("DELETE", `/v1/services/${name}`)).status).toBe(204);
      expect((await post(w(), "/oauth/introspect", { token: "x" }, authorization)).status).toBe(401);
    });

    test("failed sign-ins counted by one hold at the other", async () => {
      const user = await stack.user({ username: uname("limit") });
      const guessing = at(w());
      for (let i = 0; i < 5; i++) expect((await guessing.signIn(user.username, "not the password, attempt")).status).toBe(401);
      const refused = await at(r()).signIn(user.username, user.password!);
      expect(refused.status).toBe(429);
      expect(Number(refused.headers.get("Retry-After"))).toBeGreaterThan(0);
    });

    test("one's CLI works on what the other serves", async () => {
      const status = await stack.cli(["encryption", "status"], { backend: writer });
      expect(status.code).toBe(0);
      expect(status.out).toContain("signing keys: v1: 1");
      expect(status.out.at(-1)).toBe("AUTH_ENCRYPTION_KEY is v1");

      const made = await stack.cli(["client", "secret", "notes"], { backend: writer });
      expect(made.code).toBe(0);
      const secret = made.out[0]!;
      const answer = await post(r(), "/oauth/introspect", { token: "x" }, `Basic ${Buffer.from(`notes:${secret}`).toString("base64")}`);
      expect(answer.status).toBe(200);

      const user = await stack.user({ username: uname("cli"), totp: true });
      const session = await stack.session(user, { amr: ["pwd", "otp", "mfa"] });
      session.base = r();
      expect((await session.request("/v1/me")).status).toBe(200);
      expect((await stack.cli(["user", "clear-mfa", user.username], { backend: writer })).code).toBe(0);
      expect((await session.request("/v1/me")).status).toBe(401);
      expect(await stack.db`SELECT 1 FROM totp WHERE user_id = ${user.id}`).toHaveLength(0);
    });
  });
});

describe.skipIf(!enabled || !bothBackends)(`a ${BACKEND} copy on a database a ${OTHER} copy set up`, () => {
  let stack: Stack;
  let first: ServerProcess;

  beforeAll(async () => {
    stack = await Stack.start({ start: false });
    first = await stack.spawn({ backend: OTHER });
    await first.ready();
    await stack.boot();
  });
  afterAll(async () => {
    await stack.stop();
  });

  test("applies nothing again, and signs with the key the other made and encrypted", async () => {
    expect(first.logs.filter((l) => l.startsWith("migration "))).toEqual(["migration 0001_initial applied", "migration 0002_services applied"]);
    expect(stack.logs.filter((l) => l.startsWith("migration "))).toEqual([]);
    const keys: { kid: string; public_jwk: Record<string, string>; private_key_enc: Uint8Array }[] = await stack.db`SELECT kid, public_jwk, private_key_enc FROM signing_keys`;
    expect(keys).toHaveLength(1);
    // PKCS#8, version 0, Ed25519: 48 bytes, under the row's id.
    expect(stack.crypt.decrypt(keys[0]!.private_key_enc, keys[0]!.kid)).toHaveLength(48);

    const user = await stack.user({ username: "alice", access: { wiki: "member" } });
    const browser = stack.browser();
    await browser.signIn(user.username, user.password!);
    const { verifier, challenge } = pkce();
    const back = await browser.authorize(authorizeParams("wiki", REDIRECTS.wiki!, challenge));
    const exchanged = await post(stack.url, "/oauth/token", { grant_type: "authorization_code", code: back.searchParams.get("code")!, redirect_uri: REDIRECTS.wiki!, code_verifier: verifier }, stack.basic("wiki"));
    expect(exchanged.status).toBe(200);
    const tokens = (await exchanged.json()) as TokenSet;
    expect(decodeJwt(tokens.access_token).header.kid).toBe(keys[0]!.kid);
    expect(await stack.verified(tokens.access_token, "at+jwt")).toMatchObject({ sub: user.id, aud: "wiki" });

    // An event signed by this copy is one an app verifies against the same key.
    const { browser: root } = await stack.admin();
    expect((await root.api("PUT", `/v1/users/${user.id}/access/wiki`, { role: "owner" })).status).toBe(200);
    const event = await stack.http.waitForEvent("wiki", "access.changed", (e) => e.payload.role === "owner");
    expect(event.header.kid).toBe(keys[0]!.kid);
    expect(await stack.verified(event.token, "secevent+jwt")).toMatchObject({ aud: "wiki", events: { "access.changed": { sub: user.id, role: "owner" } } });

    const status = await stack.cli(["encryption", "status"]);
    expect(status.out).toContain("signing keys: v1: 1");
  });
});
