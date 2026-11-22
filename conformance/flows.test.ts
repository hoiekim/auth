import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { randomBytes } from "node:crypto";
import { SoftAuthenticator } from "../src/testing/authenticator";
import { backChannel, type Browser, defaultServices, enabled, linkIn, newId, REDIRECTS, sha1Hex, sha256, signInTo, Stack, type TestUser, totp, waitFor } from "./harness";

// The pages around an account's life (docs/DESIGN.md U5–U7, §7.5, §9.1,
// §9.4): sign-up, invitations, activation, password reset and email
// verification, reached as a browser reaches them.

setDefaultTimeout(30_000);

// ------------------------------------------------------------------ helpers

const PW = "correct horse battery";
const NEW_PW = "a whole new password";

function decode(s: string): string {
  return s
    .replace(/&#x([0-9a-f]+);/gi, (_, n: string) => String.fromCodePoint(parseInt(n, 16)))
    .replace(/&#(\d+);/g, (_, n: string) => String.fromCodePoint(Number(n)))
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

// The visible text of a page: tags removed, entities decoded, whitespace collapsed.
function textOf(html: string): string {
  const body = html.replace(/<head>[\s\S]*?<\/head>/i, "").replace(/<svg[\s\S]*?<\/svg>/gi, "");
  return decode(body.replace(/<[^>]*>/g, " "))
    .replace(/\s+/g, " ")
    .replace(/ ([.,:;!?])(?=\s|$)/g, "$1")
    .trim();
}

function attrsOf(tag: string): Record<string, string> {
  const out: Record<string, string> = {};
  const inner = tag.replace(/^<\w+/, "").replace(/\/?>$/, "");
  for (const m of inner.matchAll(/([a-zA-Z_:][-a-zA-Z0-9_:.]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g)) {
    out[m[1]!.toLowerCase()] = decode(m[2] ?? m[3] ?? m[4] ?? "");
  }
  return out;
}

interface Form {
  attrs: Record<string, string>;
  inputs: Record<string, string>[];
  html: string;
}

interface Page {
  status: number;
  html: string;
  text: string;
  title: string;
  h1: string;
  forms: Form[];
  inputs: Record<string, string>[];
  links: { href: string; text: string; attrs: Record<string, string> }[];
  scripts: string[];
  res: Response;
}

async function pageOf(res: Response): Promise<Page> {
  const html = await res.text();
  const inputsIn = (s: string) => [...s.matchAll(/<input\b[^>]*>/gi)].map((m) => attrsOf(m[0]));
  return {
    status: res.status,
    html,
    text: textOf(html),
    title: decode(/<title>([\s\S]*?)<\/title>/i.exec(html)?.[1] ?? "").trim(),
    h1: textOf(/<h1\b[^>]*>([\s\S]*?)<\/h1>/i.exec(html)?.[1] ?? ""),
    forms: [...html.matchAll(/(<form\b[^>]*>)([\s\S]*?)<\/form>/gi)].map((m) => ({ attrs: attrsOf(m[1]!), inputs: inputsIn(m[2]!), html: m[2]! })),
    inputs: inputsIn(html),
    links: [...html.matchAll(/(<a\b[^>]*>)([\s\S]*?)<\/a>/gi)].map((m) => ({ attrs: attrsOf(m[1]!), href: attrsOf(m[1]!).href ?? "", text: textOf(m[2]!) })),
    scripts: [...html.matchAll(/<script\b[^>]*>/gi)].map((m) => attrsOf(m[0]).src ?? ""),
    res,
  };
}

function input(where: { inputs: Record<string, string>[] }, name: string): Record<string, string> | undefined {
  return where.inputs.find((i) => i.name === name);
}

function linkTo(p: Page, text: string): { href: string; text: string } | undefined {
  return p.links.find((l) => l.text === text);
}

// A page of the message kind: its title, heading, text and the one link.
async function expectMessage(res: Response, status: number, title: string, message: string, link?: { href: string; text: string } | null): Promise<Page> {
  const p = await pageOf(res);
  expect(p.status).toBe(status);
  expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
  expect(p.title).toBe(title);
  expect(p.h1).toBe(title);
  expect(p.text).toContain(message);
  if (link) expect(p.links.map((l) => ({ href: l.href, text: l.text }))).toContainEqual(link);
  if (link === null) expect(p.links.filter((l) => l.attrs.class?.includes("button"))).toEqual([]);
  return p;
}

// What pageErrors renders for a refusal thrown inside a page handler.
function expectRefusal(res: Response, status: number, message: string): Promise<Page> {
  return expectMessage(res, status, "Something went wrong", message, { href: "/login", text: "Sign in" });
}

let seq = 0;
// A fresh username: `<prefix>-<n><hex>`, at most 32 characters.
function uname(prefix = "u"): string {
  seq++;
  return `${prefix.slice(0, 18)}-${seq}${randomBytes(3).toString("hex")}`;
}

function tokenIn(url: string): string {
  return new URL(url).searchParams.get("token")!;
}

const FORM_REFUSED = "This form has expired. Go back, reload the page and try again.";
const ORIGIN_REFUSED = "This form was not sent from this site.";
const BREACHED = "This password appears in known data breaches. Choose another.";
const USERNAME_BAD = "That username can't be used. 3–32 characters: a–z, 0–9 and '-'. It can never change.";
const RESET_SENT = "If an account uses that name or address, we've sent it a link. It expires in 30 minutes.";

describe.skipIf(!enabled)("account flows", () => {
  let stack: Stack;
  beforeAll(async () => {
    stack = await Stack.start();
  });
  afterAll(async () => {
    await stack.stop();
  });
  beforeEach(async () => {
    await stack.resetLimits();
    stack.http.onRange = null;
  });

  // A one-time token row, written as the server writes one.
  async function issue(purpose: "reset" | "verify_email" | "activate", userId: string, email: string | null, opts: { expired?: boolean; used?: boolean } = {}): Promise<string> {
    const token = randomBytes(32).toString("base64url");
    await stack.db`
      INSERT INTO one_time_tokens (token_hash, purpose, user_id, email, expires_at, used_at)
      VALUES (${sha256(token)}, ${purpose}, ${userId}, ${email},
              ${opts.expired ? new Date(Date.now() - 1000) : new Date(Date.now() + 30 * 60 * 1000)}, ${opts.used ? new Date() : null})`;
    return token;
  }

  async function invite(email: string, service = "wiki", role = "member", opts: { expired?: boolean } = {}): Promise<{ id: string; token: string }> {
    const token = randomBytes(32).toString("base64url");
    const id = newId("inv");
    await stack.db`
      INSERT INTO invites (id, email, service, role, token_hash, invited_by, expires_at)
      VALUES (${id}, ${email}, ${service}, ${role}, ${sha256(token)}, 'host-cli',
              ${opts.expired ? new Date(Date.now() - 1000) : new Date(Date.now() + 14 * 86400 * 1000)})`;
    return { id, token };
  }

  async function userRow(id: string): Promise<Record<string, any> | undefined> {
    const [row] = await stack.db`SELECT * FROM users WHERE id = ${id}`;
    return row;
  }

  async function userNamed(username: string): Promise<Record<string, any> | undefined> {
    const [row] = await stack.db`SELECT * FROM users WHERE username = ${username}`;
    return row;
  }

  async function auditFor(action: string, userId: string | null) {
    return (await stack.audit(action)).filter((r) => r.user_id === userId);
  }

  async function signedIn(b: Browser): Promise<Record<string, any> | null> {
    const res = await b.request("/v1/me");
    if (res.status !== 200) {
      await res.body?.cancel();
      return null;
    }
    return (await res.json()) as Record<string, any>;
  }

  // A mail, then a marker sent after it: once the marker is in, anything
  // the first request would have sent has had its time.
  async function marker(): Promise<void> {
    const u = await stack.user({ username: uname("marker") });
    const b = stack.browser();
    await (await b.form("/reset", { action: "email", login: u.username })).body?.cancel();
    await stack.smtp.waitFor(u.email!, (m) => m.subject === "Reset your password");
  }

  // ================================================================ sign-up

  describe("sign-up", () => {
    const signup = (b: Browser, fields: Record<string, string>) =>
      b.form("/signup", { username: uname("s"), name: "Sam", email: `${uname("e")}@example.com`, password: PW, return_to: "/account", ...fields });

    test("GET shows the form, with a fresh form token cookie and the return path", async () => {
      const b = stack.browser();
      const res = await b.get("/signup?return_to=%2Foauth%2Fauthorize%3Fclient_id%3Dtasks");
      const p = await pageOf(res);
      expect(p.status).toBe(200);
      expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
      expect(res.headers.get("Cache-Control")).toBe("no-store");
      expect(res.headers.get("Content-Security-Policy")).toStartWith("default-src 'self'");
      expect(p.title).toBe("Create an account");
      expect(p.h1).toBe("Create an account");
      const cookie = res.headers.getSetCookie().find((c) => c.startsWith("__Host-csrf="))!;
      expect(cookie).toMatch(/^__Host-csrf=[A-Za-z0-9_-]{43}; /);
      const parts = cookie.split("; ").slice(1).sort();
      expect(parts).toEqual(["HttpOnly", "Path=/", "SameSite=Strict", "Secure"]);
      expect(p.forms).toHaveLength(1);
      const f = p.forms[0]!;
      expect(f.attrs.method).toBe("post");
      expect(f.attrs.action).toBe("/signup");
      expect(input(f, "csrf")).toMatchObject({ type: "hidden", value: b.cookies.get("__Host-csrf")! });
      expect(input(f, "return_to")).toMatchObject({ type: "hidden", value: "/oauth/authorize?client_id=tasks" });
      expect(input(f, "username")).toMatchObject({ maxlength: "32", autocomplete: "username", value: "" });
      expect(input(f, "username")!.required).toBeDefined();
      expect(input(f, "name")).toMatchObject({ maxlength: "200", autocomplete: "name", value: "" });
      expect(input(f, "email")).toMatchObject({ type: "email", maxlength: "254", autocomplete: "email", value: "" });
      expect(input(f, "email")!.required).toBeDefined();
      expect(input(f, "password")).toMatchObject({ type: "password", autocomplete: "new-password", minlength: "12", maxlength: "256", value: "" });
      expect(p.text).toContain("3–32 characters: a–z, 0–9 and '-'. It can never change.");
      expect(p.text).toContain("At least 12 characters.");
      const signIn = linkTo(p, "Sign in")!;
      const u = new URL(signIn.href, stack.url);
      expect(u.pathname).toBe("/login");
      expect(u.searchParams.get("return_to")).toBe("/oauth/authorize?client_id=tasks");
    });

    test("GET keeps a valid form token cookie, and sets none", async () => {
      const b = stack.browser();
      const csrf = await b.formCsrf();
      const res = await b.get("/signup");
      expect(res.headers.getSetCookie().filter((c) => c.startsWith("__Host-csrf="))).toEqual([]);
      const p = await pageOf(res);
      expect(input(p, "csrf")!.value).toBe(csrf);
      expect(input(p, "return_to")!.value).toBe("/account");
    });

    test.each([
      ["missing", undefined],
      ["empty", ""],
      ["another origin", "https://evil.example.com/x"],
      ["protocol-relative", "//evil.example.com/x"],
      ["a backslash after the slash", "/\\evil.example.com"],
      ["a backslash inside", "/a\\b"],
      ["a control character", "/a\nb"],
      ["not a path", "account"],
      ["too long", `/${"a".repeat(4096)}`],
    ])("GET falls back to /account for a return_to that is %s", async (_, value) => {
      const q = value === undefined ? "" : `?${new URLSearchParams({ return_to: value })}`;
      const p = await pageOf(await stack.browser().get(`/signup${q}`));
      expect(input(p, "return_to")!.value).toBe("/account");
    });

    test("a return_to of 4096 characters is kept", async () => {
      const value = `/${"a".repeat(4095)}`;
      const p = await pageOf(await stack.browser().get(`/signup?${new URLSearchParams({ return_to: value })}`));
      expect(input(p, "return_to")!.value).toBe(value);
    });

    test("success: the account has no email until confirmed, a verification link is mailed, and the browser is signed in", async () => {
      const b = stack.browser();
      const username = uname("sam");
      const email = `${username}@example.com`;
      const res = await b.form("/signup", { username: `  ${username.toUpperCase()} `, name: "  Sam Sample ", email: `  ${email} `, password: PW, return_to: "/oauth/authorize?x=1" });
      expect(res.status).toBe(303);
      expect(res.headers.get("Location")).toBe("/oauth/authorize?x=1");
      const auth = res.headers.getSetCookie().find((c) => c.startsWith("__Host-auth="))!;
      expect(auth).toMatch(/^__Host-auth=[A-Za-z0-9_-]{43}; /);
      expect(auth.split("; ").slice(1).sort()).toEqual(["HttpOnly", "Max-Age=2592000", "Path=/", "SameSite=Lax", "Secure"]);

      const row = (await userNamed(username))!;
      expect(row).toMatchObject({ name: "Sam Sample", email: null, email_verified_at: null, kind: "person", owner_id: null, disabled_at: null });
      expect(row.password_hash).toStartWith("$argon2id$");
      expect(await Bun.password.verify(PW, row.password_hash)).toBe(true);

      const tokens = await stack.db`SELECT purpose, email, used_at, extract(epoch FROM expires_at - now())::int AS ttl FROM one_time_tokens WHERE user_id = ${row.id}`;
      expect(tokens).toHaveLength(1);
      expect(tokens[0]).toMatchObject({ purpose: "verify_email", email, used_at: null });
      expect(tokens[0].ttl).toBeGreaterThan(24 * 3600 - 120);
      expect(tokens[0].ttl).toBeLessThanOrEqual(24 * 3600);

      const mail = await stack.smtp.waitFor(email);
      expect(mail.subject).toBe("Confirm your email address");
      const link = linkIn(mail);
      expect(link.origin + link.pathname).toBe(`${stack.issuer}/verify-email`);
      expect(mail.text).toContain("expires in 24 hours");

      const [a] = await auditFor("user.signup", row.id);
      expect(a).toMatchObject({ actor: row.id, ip: b.ip, detail: {} });
      const [login] = await auditFor("login.ok", row.id);
      expect(login!.detail).toMatchObject({ method: "signup", amr: ["pwd"] });

      const me = (await signedIn(b))!;
      expect(me).toMatchObject({ username, email: null });

      // The link sets the address.
      const done = await stack.browser().form("/verify-email", { token: tokenIn(link.href) });
      await expectMessage(done, 200, "Address confirmed", "Your email address is confirmed.", { href: "/account", text: "Your account" });
      expect((await userRow(row.id))!.email).toBe(email);
    });

    test("an address another account uses gets the same answer; its owner gets a notice instead of the link", async () => {
      const owner = await stack.user({ username: uname("owner") });
      const b = stack.browser();
      const username = uname("taker");
      const typed = owner.email!.toUpperCase();
      const res = await b.form("/signup", { username, email: typed, password: PW, return_to: "/account" });
      expect(res.status).toBe(303);
      expect(res.headers.get("Location")).toBe("/account");
      expect(res.headers.getSetCookie().some((c) => c.startsWith("__Host-auth="))).toBe(true);
      const row = (await userNamed(username))!;
      expect(row.email).toBeNull();
      const [token] = await stack.db`SELECT purpose, email FROM one_time_tokens WHERE user_id = ${row.id}`;
      expect(token).toEqual({ purpose: "verify_email", email: typed });
      const mail = await stack.smtp.waitFor(typed);
      expect(mail.subject).toBe("Your address was used for another account");
      expect(mail.text).toContain("Someone tried to use this address for an account, but it already belongs to yours.");
      expect(mail.text).not.toContain("http");
      await marker();
      expect(stack.smtp.to(typed).map((m) => m.subject)).toEqual(["Your address was used for another account"]);
      expect(stack.smtp.to(owner.email!)).toEqual([]);
      expect(await signedIn(b)).toMatchObject({ username, email: null });
    });

    test("a taken username: 409 with the form and the values kept", async () => {
      const taken = await stack.user({ username: uname("taken") });
      const b = stack.browser();
      const email = `${uname("x")}@example.com`;
      const res = await b.form("/signup", { username: taken.username, name: "Other", email, password: PW, return_to: "/x" });
      const p = await pageOf(res);
      expect(p.status).toBe(409);
      expect(p.title).toBe("Create an account");
      expect(p.text).toContain("That username is taken.");
      expect(input(p, "username")!.value).toBe(taken.username);
      expect(input(p, "email")!.value).toBe(email);
      expect(input(p, "return_to")!.value).toBe("/x");
      expect(res.headers.getSetCookie().some((c) => c.startsWith("__Host-auth="))).toBe(false);
      // Nothing of the attempt stays.
      expect(await stack.db`SELECT 1 FROM one_time_tokens WHERE email = ${email}`).toHaveLength(0);
    });

    test("a refusal re-renders the form with every value kept and escaped, the password never", async () => {
      const b = stack.browser();
      const name = `<script>alert("x")</script> & co`;
      const res = await b.form("/signup", { username: "Bad_Name", name, email: `"<x>"@example.com`, password: "s3cret-pw-s3cret-pw", return_to: `/a?b="<c>"` });
      const p = await pageOf(res);
      expect(p.status).toBe(400);
      expect(p.html).not.toContain("<script>alert");
      expect(p.html).not.toContain("s3cret-pw");
      expect(p.html).not.toContain('"<x>"');
      expect(input(p, "username")!.value).toBe("bad_name");
      expect(input(p, "name")!.value).toBe(name);
      expect(input(p, "email")!.value).toBe(`"<x>"@example.com`);
      expect(input(p, "password")!.value).toBe("");
      expect(input(p, "return_to")!.value).toBe(`/a?b="<c>"`);
      expect(p.text).toContain(USERNAME_BAD);
      // The message is an alert.
      expect(p.html).toMatch(/role="alert"/);
    });

    test.each([
      ["upper case is lowered, so it can pass", "  OK-NAME  ", null],
      ["too short", "ab", USERNAME_BAD],
      ["too long (33)", `a${"b".repeat(32)}`, USERNAME_BAD],
      ["a digit first", "1abc", USERNAME_BAD],
      ["a dash last", "abc-", USERNAME_BAD],
      ["an underscore", "ab_c", USERNAME_BAD],
      ["a space inside", "ab c", USERNAME_BAD],
      ["unicode", "abcé", USERNAME_BAD],
      ["empty", "", USERNAME_BAD],
    ])("username %s", async (_, username, error) => {
      const b = stack.browser();
      // A bad email too: the username is checked first, and a good one goes on to the email.
      const p = await pageOf(await b.form("/signup", { username, email: "not-an-email", password: PW }));
      expect(p.status).toBe(400);
      expect(p.text).toContain(error ?? "That is not an email address.");
      expect(input(p, "username")!.value).toBe(username.trim().toLowerCase());
    });

    test("a missing username field is refused like an empty one", async () => {
      const p = await pageOf(await stack.browser().form("/signup", { email: "a@example.com", password: PW }));
      expect(p.status).toBe(400);
      expect(p.text).toContain(USERNAME_BAD);
    });

    test.each([
      ["201 code points", "a".repeat(201), "That name is too long."],
      ["201 astral code points", "😀".repeat(201), "That name is too long."],
      ["a control character inside", "Sam\u0007Sample", "That name is too long."],
      ["a tab inside", "Sam\tSample", "That name is too long."],
      ["DEL inside", "Sam\u007fSample", "That name is too long."],
      ["200 astral code points", "😀".repeat(200), null],
      ["200 code points after trimming", ` ${"a".repeat(200)}\n`, null],
      ["missing", undefined, null],
    ])("name: %s", async (_, name, error) => {
      const b = stack.browser();
      const fields: Record<string, string> = { username: uname("n"), email: "not-an-email", password: PW };
      if (name !== undefined) fields.name = name;
      const p = await pageOf(await b.form("/signup", fields));
      expect(p.status).toBe(400);
      expect(p.text).toContain(error ?? "That is not an email address.");
    });

    test.each([
      ["no @", "sam.example.com"],
      ["no dot in the domain", "sam@example"],
      ["a last label without a letter", "sam@example.123"],
      ["two @", "sam@x@example.com"],
      ["nothing before @", "@example.com"],
      ["a space", "sam smith@example.com"],
      ["a quoted local part", '"sam"@example.com'],
      ["an address literal", "sam@[127.0.0.1]"],
      ["a local part past 64", `${"a".repeat(65)}@example.com`],
      ["past 254 characters", `a@${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(63)}.${"e".repeat(63)}.com`],
      ["empty", ""],
    ])("email: %s is not an address", async (_, email) => {
      const p = await pageOf(await stack.browser().form("/signup", { username: uname("m"), email, password: "short" }));
      expect(p.status).toBe(400);
      expect(p.text).toContain("That is not an email address.");
    });

    const astral = (n: number) => "𝔸".repeat(n);
    test.each([
      ["11 characters", "abcdefghijk", "Use at least 12 characters."],
      ["11 astral characters (22 UTF-16 units)", astral(11), "Use at least 12 characters."],
      ["empty", "", "Use at least 12 characters."],
      ["257 characters", "a".repeat(257), "Use at most 256 characters."],
      ["257 astral characters", astral(257), "Use at most 256 characters."],
    ])("password: %s", async (_, password, error) => {
      const p = await pageOf(await stack.browser().form("/signup", { username: uname("p"), email: `${uname("e")}@example.com`, password }));
      expect(p.status).toBe(400);
      expect(p.text).toContain(error);
      expect(input(p, "password")!.value).toBe("");
    });

    test.each([
      ["12 astral characters", astral(12)],
      ["256 astral characters", astral(256)],
      ["256 characters", "z".repeat(256)],
    ])("password: %s is accepted", async (_, password) => {
      const res = await signup(stack.browser(), { password });
      expect(res.status).toBe(303);
    });

    test("password: the username, in any case, is refused", async () => {
      const username = `long-name-${seq++}${randomBytes(2).toString("hex")}`;
      const p = await pageOf(await stack.browser().form("/signup", { username, email: `${uname("e")}@example.com`, password: username.toUpperCase() }));
      expect(p.status).toBe(400);
      expect(p.text).toContain("Don't use your username as your password.");
    });

    test("password: the email, in any case, is refused", async () => {
      const email = `${uname("Mail")}@Example.com`;
      const p = await pageOf(await stack.browser().form("/signup", { username: uname("q"), email, password: email.toLowerCase() }));
      expect(p.status).toBe(400);
      expect(p.text).toContain("Don't use your email address as your password.");
    });

    test("password: a breached one is refused; only five hex characters of its SHA-1 reach the range API", async () => {
      const password = `breached-${randomBytes(6).toString("hex")}`;
      stack.http.breached.add(password);
      const before = stack.http.rangeRequests.length;
      const p = await pageOf(await stack.browser().form("/signup", { username: uname("br"), email: `${uname("e")}@example.com`, password }));
      expect(p.status).toBe(400);
      expect(p.text).toContain(BREACHED);
      const asked = stack.http.rangeRequests.slice(before);
      expect(asked).toEqual([{ path: `/range/${sha1Hex(password).slice(0, 5)}`, padding: "true" }]);
    });

    test("password: the default breached password is refused", async () => {
      const p = await pageOf(await stack.browser().form("/signup", { username: uname("br"), email: `${uname("e")}@example.com`, password: "password1234" }));
      expect(p.status).toBe(400);
      expect(p.text).toContain(BREACHED);
    });

    test("password: a range API that fails allows the password", async () => {
      stack.http.onRange = () => new Response("down", { status: 503 });
      const res = await signup(stack.browser(), { password: "password1234" });
      expect(res.status).toBe(303);
    });

    test("password: a range API that hangs allows the password", async () => {
      stack.http.onRange = () => new Promise((done) => setTimeout(() => done(new Response("")), 12_000));
      const res = await signup(stack.browser(), { password: "password1234" });
      expect(res.status).toBe(303);
    });

    test("ten sign-ups an hour per IP, then 429 with the form", async () => {
      const b = stack.browser();
      for (let i = 0; i < 10; i++) expect((await signup(b, {})).status).toBe(303);
      const p = await pageOf(await signup(b, { username: "eleventh-try" }));
      expect(p.status).toBe(429);
      expect(p.text).toContain("Too many accounts were created from your network. Try again later.");
      expect(input(p, "username")!.value).toBe("eleventh-try");
      expect(await userNamed("eleventh-try")).toBeUndefined();
      // A refused form doesn't count: another address is unaffected.
      expect((await signup(stack.browser(), {})).status).toBe(303);
    });

    test("three sign-up emails an hour per address, whatever its case, then 429", async () => {
      const email = `${uname("busy")}@example.com`;
      for (let i = 0; i < 3; i++) expect((await signup(stack.browser(), { email: i === 1 ? email.toUpperCase() : email })).status).toBe(303);
      const username = uname("fourth");
      const p = await pageOf(await signup(stack.browser(), { username, email }));
      expect(p.status).toBe(429);
      expect(p.text).toContain("Too many emails were sent to that address. Try again later.");
      expect(await userNamed(username)).toBeUndefined();
    });

    test("ten emails an hour per sender: reset requests and sign-ups share it", async () => {
      const b = stack.browser();
      for (let i = 0; i < 10; i++) expect((await b.form("/reset", { action: "email", login: `nobody-${i}-${seq}` })).status).toBe(200);
      const p = await pageOf(await signup(b, {}));
      expect(p.status).toBe(429);
      expect(p.text).toContain("Too many emails were sent to that address. Try again later.");
    });

    test("an invalid form is not counted against the per-IP limit", async () => {
      const b = stack.browser();
      for (let i = 0; i < 12; i++) expect((await signup(b, { password: "short" })).status).toBe(400);
      expect((await signup(b, {})).status).toBe(303);
    });

    test("signing up while signed in as someone else ends that session and starts the new one", async () => {
      const other = await stack.user({ username: uname("prev") });
      const b = await stack.session(other);
      const old = b.sessionId!;
      const username = uname("next");
      expect((await signup(b, { username })).status).toBe(303);
      expect(await signedIn(b)).toMatchObject({ username });
      expect(await stack.db`SELECT 1 FROM sessions WHERE id = ${old}`).toHaveLength(0);
    });
  });

  // ============================================================= invitation

  describe("invitations", () => {
    test("an invitation made through the API is mailed, and its link opens the page", async () => {
      const { browser: admin } = await stack.admin();
      const email = `${uname("inv")}@example.com`;
      const res = await admin.api("POST", "/v1/invites", { email, service: "wiki", role: "member" });
      expect(res.status).toBe(201);
      const mail = await stack.smtp.waitFor(email);
      expect(mail.subject).toBe("You're invited to wiki");
      const link = linkIn(mail);
      expect(link.origin + link.pathname).toBe(`${stack.issuer}/invite`);
      const p = await pageOf(await stack.browser().get(link.pathname + link.search));
      expect(p.status).toBe(200);
      expect(p.text).toContain(email);
    });

    test("GET, not signed in: the invited address, a sign-in link back here, and the create-account form", async () => {
      const email = `o'neil+${seq++}@example.com`;
      const { token } = await invite(email, "mailbox", "user");
      const b = stack.browser();
      const res = await b.get(`/invite?token=${token}`);
      const p = await pageOf(res);
      expect(p.status).toBe(200);
      expect(p.title).toBe("Invitation");
      expect(p.h1).toBe("You're invited to mailbox");
      expect(p.text).toContain("Already have an account?");
      expect(p.text).toContain(`Email ${email}`);
      expect(p.html).not.toContain("o'neil");
      const signIn = linkTo(p, "Sign in to accept")!;
      const u = new URL(signIn.href, stack.url);
      expect(u.pathname).toBe("/login");
      expect(u.searchParams.get("return_to")).toBe(`/invite?token=${token}`);
      expect(p.forms).toHaveLength(1);
      const f = p.forms[0]!;
      expect(f.attrs).toMatchObject({ method: "post", action: "/invite" });
      expect(input(f, "csrf")!.value).toBe(b.cookies.get("__Host-csrf")!);
      expect(input(f, "token")).toMatchObject({ type: "hidden", value: token });
      expect(input(f, "action")).toMatchObject({ type: "hidden", value: "create" });
      expect(input(f, "username")).toMatchObject({ maxlength: "32" });
      expect(input(f, "name")).toMatchObject({ maxlength: "200" });
      expect(input(f, "password")).toMatchObject({ type: "password", minlength: "12", maxlength: "256", autocomplete: "new-password" });
      expect(input(f, "email")).toBeUndefined();
      expect(p.text).toContain("Create account and accept");
    });

    test("GET, signed in: accept as the signed-in user, or sign in as someone else", async () => {
      const alice = await stack.user({ username: uname("alice") });
      const { token } = await invite(`${uname("x")}@example.com`);
      const b = await stack.session(alice);
      const p = await pageOf(await b.get(`/invite?token=${token}`));
      expect(p.status).toBe(200);
      expect(p.h1).toBe("You're invited to wiki");
      expect(p.text).toContain(`You're signed in as ${alice.username}.`);
      expect(p.text).toContain(`Accept as ${alice.username}`);
      expect(p.forms).toHaveLength(1);
      const f = p.forms[0]!;
      expect(input(f, "token")!.value).toBe(token);
      expect(input(f, "action")!.value).toBe("accept");
      expect(input(f, "password")).toBeUndefined();
      const other = new URL(linkTo(p, "Sign in as someone else")!.href, stack.url);
      expect(other.pathname).toBe("/login");
      expect(other.searchParams.get("return_to")).toBe(`/invite?token=${token}`);
    });

    test.each([
      ["unknown", async () => randomBytes(32).toString("base64url")],
      ["missing", async () => null],
      ["empty", async () => ""],
      ["too long", async () => "a".repeat(129)],
      ["expired", async (inv: typeof invite) => (await inv(`${uname("x")}@example.com`, "wiki", "member", { expired: true })).token],
    ])("GET and POST with a token that is %s: 404 Invitation not valid", async (_, make) => {
      const token = await make(invite);
      const q = token === null ? "" : `?${new URLSearchParams({ token })}`;
      await expectMessage(await stack.browser().get(`/invite${q}`), 404, "Invitation not valid", "This invitation has expired or was already used.");
      const fields: Record<string, string> = { action: "accept" };
      if (token !== null) fields.token = token;
      const b = await stack.session(await stack.user({ username: uname("v") }));
      await expectMessage(await b.form("/invite", fields), 404, "Invitation not valid", "This invitation has expired or was already used.");
    });

    test("POST accept, not signed in: 303 to the sign-in page, back to the invitation", async () => {
      const { token } = await invite(`${uname("x")}@example.com`);
      const res = await stack.browser().form("/invite", { token, action: "accept" });
      expect(res.status).toBe(303);
      expect(res.headers.get("Location")).toBe(`/login?${new URLSearchParams({ return_to: `/invite?token=${token}` })}`);
      expect((await stack.db`SELECT accepted_at FROM invites WHERE token_hash = ${sha256(token)}`)[0].accepted_at).toBeNull();
    });

    test("POST accept, signed in: the role, audit rows, events, the invitation marked; a second use is refused", async () => {
      const bob = await stack.user({ username: uname("bob") });
      const { id, token } = await invite(`${uname("x")}@example.com`, "wiki", "admin");
      const b = await stack.session(bob);
      const res = await b.form("/invite", { token, action: "accept" });
      await expectMessage(res, 200, "Invitation accepted", "You can now use wiki.", { href: "/account", text: "Your account" });
      const [access] = await stack.db`SELECT role, granted_by FROM access WHERE user_id = ${bob.id} AND service = 'wiki'`;
      expect(access).toEqual({ role: "admin", granted_by: bob.id });
      const [row] = await stack.db`SELECT accepted_by, accepted_at FROM invites WHERE id = ${id}`;
      expect(row.accepted_by).toBe(bob.id);
      expect(row.accepted_at).toBeInstanceOf(Date);
      const [acc] = await auditFor("invite.accept", bob.id);
      expect(acc).toMatchObject({ actor: bob.id, ip: b.ip, detail: { id, service: "wiki" } });
      const [put] = await auditFor("access.put", bob.id);
      expect(put).toMatchObject({ actor: bob.id, ip: b.ip, detail: { service: "wiki", role: "admin", previous: null, reason: "invite" } });
      const queued = (await stack.outbox("wiki")).filter((e) => e.payload.sub === bob.id);
      expect(queued.map((e) => [e.type, e.payload])).toEqual([
        ["access.changed", { sub: bob.id, role: "admin" }],
        ["invite.accepted", { invite: id, sub: bob.id }],
      ]);
      await stack.http.waitForEvent("wiki", "invite.accepted", (e) => e.payload.invite === id);
      await expectMessage(await b.form("/invite", { token, action: "accept" }), 404, "Invitation not valid", "This invitation has expired or was already used.");
      // Neither can it make an account now.
      await expectMessage(await stack.browser().form("/invite", { token, action: "create", username: uname("late"), password: PW }), 404, "Invitation not valid", "This invitation has expired or was already used.");
    });

    test("accepting raises a lower role", async () => {
      const carol = await stack.user({ username: uname("carol"), access: { wiki: "member" } });
      const { token } = await invite(`${uname("x")}@example.com`, "wiki", "owner");
      const b = await stack.session(carol);
      expect((await b.form("/invite", { token, action: "accept" })).status).toBe(200);
      expect((await stack.db`SELECT role FROM access WHERE user_id = ${carol.id} AND service = 'wiki'`)[0].role).toBe("owner");
      expect((await auditFor("access.put", carol.id))[0]!.detail).toMatchObject({ role: "owner", previous: "member", reason: "invite" });
    });

    test("accepting never lowers a higher role, and changes nothing but the invitation", async () => {
      const dave = await stack.user({ username: uname("dave"), access: { wiki: "owner" } });
      const { id, token } = await invite(`${uname("x")}@example.com`, "wiki", "member");
      const b = await stack.session(dave);
      expect((await b.form("/invite", { token, action: "accept" })).status).toBe(200);
      expect(await stack.db`SELECT role, granted_by FROM access WHERE user_id = ${dave.id} AND service = 'wiki'`).toEqual([{ role: "owner", granted_by: "host-cli" }]);
      expect(await auditFor("access.put", dave.id)).toEqual([]);
      expect((await auditFor("invite.accept", dave.id))).toHaveLength(1);
      const queued = (await stack.outbox("wiki")).filter((e) => e.payload.sub === dave.id);
      expect(queued.map((e) => [e.type, e.payload])).toEqual([["invite.accepted", { invite: id, sub: dave.id }]]);
    });

    test("accepting the same role again writes no access row change", async () => {
      const erin = await stack.user({ username: uname("erin"), access: { wiki: "member" } });
      const { token } = await invite(`${uname("x")}@example.com`, "wiki", "member");
      expect((await (await stack.session(erin)).form("/invite", { token, action: "accept" })).status).toBe(200);
      expect(await auditFor("access.put", erin.id)).toEqual([]);
    });

    test.each([
      ["a closed service", "notes", "reader"],
      ["a role the service no longer has", "wiki", "editor"],
      ["a service that no longer exists", "gallery", "member"],
    ])("accepting an invitation to %s: 409, no longer valid, and the invitation stays unused", async (_, service, role) => {
      const frank = await stack.user({ username: uname("frank") });
      const { id, token } = await invite(`${uname("x")}@example.com`, service, role);
      const b = await stack.session(frank);
      // The page still shows: the check is at acceptance.
      expect((await b.get(`/invite?token=${token}`)).status).toBe(200);
      await expectRefusal(await b.form("/invite", { token, action: "accept" }), 409, "This invitation is no longer valid.");
      expect((await stack.db`SELECT accepted_at FROM invites WHERE id = ${id}`)[0].accepted_at).toBeNull();
      expect(await stack.db`SELECT 1 FROM access WHERE user_id = ${frank.id}`).toHaveLength(0);
    });

    test.each([
      ["a closed service", "notes", "reader"],
      ["a role the service no longer has", "mailbox", "owner"],
    ])("creating an account from an invitation to %s: 409, no longer valid, and no account", async (_, service, role) => {
      const { token } = await invite(`${uname("x")}@example.com`, service, role);
      const username = uname("gone");
      await expectMessage(await stack.browser().form("/invite", { token, action: "create", username, password: PW }), 409, "Couldn't create the account", "This invitation is no longer valid.", {
        href: `/invite?${new URLSearchParams({ token })}`,
        text: "Back",
      });
      expect(await userNamed(username)).toBeUndefined();
    });

    test("POST create: the account with the invited address verified, the role, signed in, redirected to /account", async () => {
      const email = `${uname("new")}@Example.com`;
      const { id, token } = await invite(email, "mailbox", "user");
      const b = stack.browser();
      const username = uname("gina");
      const res = await b.form("/invite", { token, action: "create", username: ` ${username.toUpperCase()} `, name: " Gina ", password: PW });
      expect(res.status).toBe(303);
      expect(res.headers.get("Location")).toBe("/account");
      expect(res.headers.getSetCookie().some((c) => /^__Host-auth=[A-Za-z0-9_-]{43};/.test(c))).toBe(true);
      const row = (await userNamed(username))!;
      expect(row).toMatchObject({ name: "Gina", email, kind: "person" });
      expect(row.email_verified_at).toBeInstanceOf(Date);
      expect(await Bun.password.verify(PW, row.password_hash)).toBe(true);
      expect(await stack.db`SELECT role, granted_by FROM access WHERE user_id = ${row.id}`).toEqual([{ role: "user", granted_by: row.id }]);
      expect((await auditFor("user.signup", row.id))[0]).toMatchObject({ actor: row.id, ip: b.ip, detail: { invite: id } });
      expect((await auditFor("invite.accept", row.id))[0]).toMatchObject({ detail: { id, service: "mailbox" } });
      expect((await auditFor("access.put", row.id))[0]!.detail).toEqual({ service: "mailbox", role: "user", previous: null, reason: "invite" });
      expect((await auditFor("login.ok", row.id))[0]!.detail).toMatchObject({ method: "signup", amr: ["pwd"] });
      const [inv] = await stack.db`SELECT accepted_by FROM invites WHERE id = ${id}`;
      expect(inv.accepted_by).toBe(row.id);
      const types = (await stack.outbox("mailbox")).filter((e) => e.payload.sub === row.id).map((e) => e.type);
      expect(types).toEqual(["access.changed", "invite.accepted"]);
      expect(await signedIn(b)).toMatchObject({ username, email });
      // No verification mail: the link proved the address.
      await marker();
      expect(stack.smtp.to(email)).toEqual([]);
    });

    test("POST with no action is the create-account form", async () => {
      const { token } = await invite(`${uname("x")}@example.com`);
      const username = uname("noact");
      expect((await stack.browser().form("/invite", { token, username, password: PW })).status).toBe(303);
      expect(await userNamed(username)).toBeDefined();
    });

    const back = (token: string) => ({ href: `/invite?${new URLSearchParams({ token })}`, text: "Back" });
    test.each([
      ["a bad username", { username: "No_Good" }, USERNAME_BAD],
      ["an empty username", { username: "" }, USERNAME_BAD],
      ["a name too long", { name: "n".repeat(201) }, "That name is too long."],
      ["a name with a control character", { name: "a\u0000b" }, "That name is too long."],
      ["a short password", { password: "short" }, "Use at least 12 characters."],
      ["a long password", { password: "p".repeat(257) }, "Use at most 256 characters."],
      ["a breached password", { password: "password1234" }, BREACHED],
    ])("POST create with %s: 400 Couldn't create the account, with a Back link", async (_, fields, message) => {
      const { token } = await invite(`${uname("x")}@example.com`);
      const all = { token, action: "create", username: uname("h"), name: "H", password: PW, ...fields };
      await expectMessage(await stack.browser().form("/invite", all), 400, "Couldn't create the account", message, back(token));
      expect((await stack.db`SELECT accepted_at FROM invites WHERE token_hash = ${sha256(token)}`)[0].accepted_at).toBeNull();
    });

    test("POST create: the username, or the invited address, as the password is refused", async () => {
      const email = `${uname("pw")}@example.com`;
      const { token } = await invite(email);
      const username = `long-user-${seq++}${randomBytes(2).toString("hex")}`;
      await expectMessage(await stack.browser().form("/invite", { token, action: "create", username, password: username.toUpperCase() }), 400, "Couldn't create the account", "Don't use your username as your password.", back(token));
      await expectMessage(await stack.browser().form("/invite", { token, action: "create", username, password: email.toUpperCase() }), 400, "Couldn't create the account", "Don't use your email address as your password.", back(token));
    });

    test("POST create: a taken username is 409 with its message", async () => {
      const taken = await stack.user({ username: uname("tk") });
      const { token } = await invite(`${uname("x")}@example.com`);
      await expectMessage(await stack.browser().form("/invite", { token, action: "create", username: taken.username, password: PW }), 409, "Couldn't create the account", "That username is taken.", back(token));
    });

    test("POST create: an invited address an account already uses is 409 with its own message", async () => {
      const owner = await stack.user({ username: uname("has") });
      const { token } = await invite(owner.email!.toUpperCase());
      const username = uname("dup");
      await expectMessage(
        await stack.browser().form("/invite", { token, action: "create", username, password: PW }),
        409,
        "Couldn't create the account",
        "An account already uses this address: sign in to it, then open the invitation again.",
        back(token),
      );
      expect(await userNamed(username)).toBeUndefined();
      expect((await stack.db`SELECT accepted_at FROM invites WHERE token_hash = ${sha256(token)}`)[0].accepted_at).toBeNull();
    });

    test("POST create shares the per-IP account-creation limit with sign-up", async () => {
      const b = stack.browser();
      for (let i = 0; i < 10; i++) {
        const res = await b.form("/signup", { username: uname("bulk"), email: `${uname("e")}@example.com`, password: PW });
        expect(res.status).toBe(303);
      }
      const { token } = await invite(`${uname("x")}@example.com`);
      const username = uname("over");
      await expectMessage(await b.form("/invite", { token, action: "create", username, password: PW }), 429, "Couldn't create the account", "Too many accounts were created from your network. Try again later.", back(token));
      expect(await userNamed(username)).toBeUndefined();
    });
  });

  // ============================================================= activation

  describe("activation", () => {
    async function pending(): Promise<{ user: TestUser; token: string }> {
      const user = await stack.user({ username: uname("act"), password: null, emailVerified: false });
      return { user, token: await issue("activate", user.id, user.email) };
    }

    test("an account an admin creates gets a link by email that sets its password", async () => {
      const { browser: admin } = await stack.admin();
      const username = uname("made");
      const email = `${username}@example.com`;
      expect((await admin.api("POST", "/v1/users", { username, email })).status).toBe(201);
      const mail = await stack.smtp.waitFor(email);
      expect(mail.subject).toBe("Activate your account");
      const link = linkIn(mail);
      expect(link.origin + link.pathname).toBe(`${stack.issuer}/activate`);
      const b = stack.browser();
      expect((await b.get(link.pathname + link.search)).status).toBe(200);
      const res = await b.form("/activate", { token: tokenIn(link.href), password: NEW_PW });
      expect(res.status).toBe(303);
    });

    test("the CLI's printed link works too", async () => {
      const username = uname("cli");
      const out = await stack.cli(["user", "create", "--username", username, "--email", `${username}@example.com`, "--print-link"]);
      expect(out.code).toBe(0);
      const url = /https?:\/\/\S+\/activate\?token=\S+/.exec(out.stdout)![0];
      expect(new URL(url).origin).toBe(stack.issuer);
      const [ttl] = await stack.db`SELECT extract(epoch FROM t.expires_at - now())::int AS s FROM one_time_tokens t JOIN users u ON u.id = t.user_id WHERE u.username = ${username}`;
      expect(ttl.s).toBeGreaterThan(14 * 86400 - 120);
      expect(ttl.s).toBeLessThanOrEqual(14 * 86400);
      expect((await stack.browser().form("/activate", { token: tokenIn(url), password: NEW_PW })).status).toBe(303);
    });

    test("GET with a live token: the form, naming the account", async () => {
      const { user, token } = await pending();
      const b = stack.browser();
      const p = await pageOf(await b.get(`/activate?token=${token}`));
      expect(p.status).toBe(200);
      expect(p.title).toBe("Activate your account");
      expect(p.h1).toBe("Activate your account");
      expect(p.text).toContain(`Username ${user.username}`);
      const f = p.forms[0]!;
      expect(f.attrs).toMatchObject({ method: "post", action: "/activate" });
      expect(input(f, "csrf")!.value).toBe(b.cookies.get("__Host-csrf")!);
      expect(input(f, "token")).toMatchObject({ type: "hidden", value: token });
      expect(input(f, "username")).toMatchObject({ type: "hidden", value: user.username, autocomplete: "username" });
      expect(input(f, "password")).toMatchObject({ type: "password", minlength: "12", maxlength: "256", autocomplete: "new-password" });
      // Peeking spends nothing.
      expect((await b.get(`/activate?token=${token}`)).status).toBe(200);
    });

    test.each([
      ["unknown", async () => randomBytes(32).toString("base64url")],
      ["missing", async () => null],
      ["expired", async (u: TestUser) => issue("activate", u.id, u.email, { expired: true })],
      ["used", async (u: TestUser) => issue("activate", u.id, u.email, { used: true })],
      ["for another purpose", async (u: TestUser) => issue("reset", u.id, u.email)],
    ])("a token that is %s: 404 Link not valid on GET and POST", async (_, make) => {
      const user = await stack.user({ username: uname("na"), password: null });
      const token = await make(user);
      const q = token === null ? "" : `?${new URLSearchParams({ token })}`;
      await expectMessage(await stack.browser().get(`/activate${q}`), 404, "Link not valid", "This activation link has expired or was already used. Ask an administrator for a new one.");
      const fields: Record<string, string> = { password: NEW_PW };
      if (token !== null) fields.token = token;
      const p = await expectMessage(await stack.browser().form("/activate", fields), 404, "Link not valid", "This activation link has expired or was already used.");
      expect(p.text).not.toContain("Ask an administrator");
    });

    test.each([
      ["short", "short-pw", "Use at least 12 characters."],
      ["long", "x".repeat(257), "Use at most 256 characters."],
      ["breached", "password1234", BREACHED],
    ])("a %s password: 400 Choose another password, with a Back link, and the link still works", async (_, password, message) => {
      const { token } = await pending();
      await expectMessage(await stack.browser().form("/activate", { token, password }), 400, "Choose another password", message, {
        href: `/activate?${new URLSearchParams({ token })}`,
        text: "Back",
      });
      expect((await stack.browser().get(`/activate?token=${token}`)).status).toBe(200);
    });

    test("the username or the email as the password is refused", async () => {
      const user = await stack.user({ username: `activate-me-${seq++}${randomBytes(2).toString("hex")}`, password: null });
      const token = await issue("activate", user.id, user.email);
      await expectMessage(await stack.browser().form("/activate", { token, password: user.username.toUpperCase() }), 400, "Choose another password", "Don't use your username as your password.");
      await expectMessage(await stack.browser().form("/activate", { token, password: user.email!.toUpperCase() }), 400, "Choose another password", "Don't use your email address as your password.");
    });

    test("success: the password is set, the address verified, audited, and the link works once", async () => {
      const { user, token } = await pending();
      const b = stack.browser();
      const res = await b.form("/activate", { token, password: NEW_PW });
      expect(res.status).toBe(303);
      expect(res.headers.get("Location")).toBe(`/login?${new URLSearchParams({ login_hint: user.username, notice: "activated" })}`);
      // Not signed in by it.
      expect(res.headers.getSetCookie().some((c) => c.startsWith("__Host-auth="))).toBe(false);
      const row = (await userRow(user.id))!;
      expect(row.email_verified_at).toBeInstanceOf(Date);
      expect(await Bun.password.verify(NEW_PW, row.password_hash)).toBe(true);
      expect((await auditFor("user.activate", user.id))[0]).toMatchObject({ actor: user.id, ip: b.ip, detail: {} });
      await expectMessage(await stack.browser().form("/activate", { token, password: "another new password" }), 404, "Link not valid", "This activation link has expired or was already used.");
      await expectMessage(await stack.browser().get(`/activate?token=${token}`), 404, "Link not valid", "This activation link has expired or was already used.");
      expect(await Bun.password.verify(NEW_PW, (await userRow(user.id))!.password_hash)).toBe(true);
      // The login page it leads to.
      const login = await pageOf(await stack.browser().get(res.headers.get("Location")!));
      expect(login.text).toContain("Your password is set. Sign in.");
    });

    test("refused once the account has a password", async () => {
      const user = await stack.user({ username: uname("has-pw") });
      const token = await issue("activate", user.id, user.email);
      await expectMessage(await stack.browser().form("/activate", { token, password: NEW_PW }), 404, "Link not valid", "This activation link has expired or was already used.");
      expect(await Bun.password.verify(PW, (await userRow(user.id))!.password_hash)).toBe(true);
      expect(await auditFor("user.activate", user.id)).toEqual([]);
    });

    test.each([
      ["another address", "elsewhere@example.org"],
      ["no address", null],
    ])("refused once the account's email is %s, not the token's", async (_, email) => {
      const { user, token } = await pending();
      await stack.db`UPDATE users SET email = ${email} WHERE id = ${user.id}`;
      await expectMessage(await stack.browser().form("/activate", { token, password: NEW_PW }), 404, "Link not valid", "This activation link has expired or was already used.");
      expect((await userRow(user.id))!.password_hash).toBeNull();
    });

    test("the token's address matches the account's ignoring case", async () => {
      const { user, token } = await pending();
      await stack.db`UPDATE users SET email = upper(email) WHERE id = ${user.id}`;
      expect((await stack.browser().form("/activate", { token, password: NEW_PW })).status).toBe(303);
    });
  });

  // ========================================================== reset request

  describe("reset request", () => {
    test("GET: the email form and the recovery-code form", async () => {
      const b = stack.browser();
      const p = await pageOf(await b.get("/reset"));
      expect(p.status).toBe(200);
      expect(p.title).toBe("Reset your password");
      expect(p.h1).toBe("Reset your password");
      expect(p.forms).toHaveLength(2);
      const [email, recovery] = p.forms as [Form, Form];
      for (const f of [email, recovery]) {
        expect(f.attrs).toMatchObject({ method: "post", action: "/reset" });
        expect(input(f, "csrf")!.value).toBe(b.cookies.get("__Host-csrf")!);
      }
      expect(input(email, "action")).toMatchObject({ type: "hidden", value: "email" });
      expect(input(email, "login")).toMatchObject({ maxlength: "254", autocomplete: "username" });
      expect(input(recovery, "action")).toMatchObject({ type: "hidden", value: "recovery" });
      expect(input(recovery, "login")).toMatchObject({ maxlength: "254" });
      expect(input(recovery, "code")).toMatchObject({ maxlength: "40", autocomplete: "off" });
      expect(input(recovery, "password")).toMatchObject({ type: "password", minlength: "12", maxlength: "256", autocomplete: "new-password" });
      expect(p.text).toContain("Can't reach your email?");
      expect(p.text).not.toContain(RESET_SENT);
    });

    test("the same page whether the account exists, is unknown, disabled, a bot, or has no email; mail only to the real one", async () => {
      const real = await stack.user({ username: uname("real") });
      const disabled = await stack.user({ username: uname("off"), disabled: true });
      const owner = await stack.user({ username: uname("bot-owner") });
      const bot = await stack.user({ username: uname("bot"), kind: "bot", ownerId: owner.id, email: `${uname("botmail")}@example.com` });
      const noEmail = await stack.user({ username: uname("nomail"), email: null });
      const b = stack.browser();
      const answers: string[] = [];
      for (const login of [real.username, "nobody-here-at-all", disabled.username, disabled.email!, bot.username, bot.email!, noEmail.username]) {
        const res = await b.form("/reset", { action: "email", login });
        expect(res.status).toBe(200);
        expect(res.headers.getSetCookie()).toEqual([]);
        const p = await pageOf(res);
        expect(p.text).toContain(RESET_SENT);
        answers.push(p.html);
      }
      expect(new Set(answers).size).toBe(1);
      const mail = await stack.smtp.waitFor(real.email!);
      expect(mail.subject).toBe("Reset your password");
      expect(mail.text).toContain("expires in 30 minutes");
      const link = linkIn(mail);
      expect(link.origin + link.pathname).toBe(`${stack.issuer}/reset/confirm`);
      const [tok] = await stack.db`SELECT purpose, email, extract(epoch FROM expires_at - now())::int AS ttl FROM one_time_tokens WHERE user_id = ${real.id}`;
      expect(tok.purpose).toBe("reset");
      expect(tok.email).toBe(real.email);
      expect(tok.ttl).toBeGreaterThan(30 * 60 - 120);
      expect(tok.ttl).toBeLessThanOrEqual(30 * 60);
      await waitFor(async () => (await auditFor("reset.requested", real.id)).length === 1, "the audit row");
      expect((await auditFor("reset.requested", real.id))[0]).toMatchObject({ actor: null, ip: b.ip, detail: {} });
      await marker();
      for (const u of [disabled, bot]) expect(stack.smtp.to(u.email!)).toEqual([]);
      for (const u of [disabled, bot, noEmail]) {
        expect(await auditFor("reset.requested", u.id)).toEqual([]);
        expect(await stack.db`SELECT 1 FROM one_time_tokens WHERE user_id = ${u.id}`).toHaveLength(0);
      }
    });

    test("a login with a NUL gets the same page, counted with the NUL kept as U+FFFD", async () => {
      const name = uname("nul");
      const res = await stack.browser().form("/reset", { action: "email", login: `${name}\u0000x` });
      expect(res.status).toBe(200);
      expect((await pageOf(res)).text).toContain(RESET_SENT);
      const [row] = await stack.db`SELECT hits FROM throttle WHERE key = ${`mail:to:${name}\uFFFDx`}`;
      expect(Number(row?.hits)).toBe(1);
    });

    test("by email address, ignoring case and spaces around it, the link goes to the stored address", async () => {
      const u = await stack.user({ username: uname("byaddr"), email: `${uname("Mixed")}@Example.com` });
      expect((await stack.browser().form("/reset", { action: "email", login: `  ${u.email!.toLowerCase()} ` })).status).toBe(200);
      const mail = await stack.smtp.waitFor(u.email!);
      expect(mail.to).toEqual([u.email!]);
    });

    test("an empty or missing login answers the same page", async () => {
      for (const fields of [{ action: "email", login: "   " }, { action: "email" }, {}] as Record<string, string>[]) {
        const p = await pageOf(await stack.browser().form("/reset", fields));
        expect(p.status).toBe(200);
        expect(p.text).toContain(RESET_SENT);
      }
    });

    test("the fourth request an hour for the same login is 429 with Retry-After", async () => {
      const login = `nobody-${seq++}@example.com`;
      for (let i = 0; i < 3; i++) expect((await stack.browser().form("/reset", { action: "email", login: i === 2 ? login.toUpperCase() : login })).status).toBe(200);
      const res = await stack.browser().form("/reset", { action: "email", login });
      const p = await pageOf(res);
      expect(p.status).toBe(429);
      expect(p.text).toContain("Too many reset emails were asked for. Try again later.");
      expect(p.text).not.toContain(RESET_SENT);
      const retry = Number(res.headers.get("Retry-After"));
      expect(retry).toBeGreaterThan(3500);
      expect(retry).toBeLessThanOrEqual(3600);
      expect(p.forms).toHaveLength(2);
    });

    test("the eleventh request an hour from one sender is 429", async () => {
      const b = stack.browser();
      for (let i = 0; i < 10; i++) expect((await b.form("/reset", { action: "email", login: `nobody-${i}-${seq}` })).status).toBe(200);
      const res = await b.form("/reset", { action: "email", login: "someone-else" });
      expect(res.status).toBe(429);
      expect(Number(res.headers.get("Retry-After"))).toBeGreaterThan(0);
      expect((await pageOf(res)).text).toContain("Too many reset emails were asked for. Try again later.");
    });

    test("at most three link mails an hour reach an address, however it was typed; the rest are quietly not sent", async () => {
      const u = await stack.user({ username: uname("vera") });
      for (let i = 0; i < 3; i++) expect((await stack.browser().form("/reset", { action: "email", login: u.username })).status).toBe(200);
      await waitFor(() => stack.smtp.to(u.email!).length === 3, "three mails");
      const res = await stack.browser().form("/reset", { action: "email", login: u.email!.toUpperCase() });
      expect(res.status).toBe(200);
      expect((await pageOf(res)).text).toContain(RESET_SENT);
      await marker();
      expect(stack.smtp.to(u.email!)).toHaveLength(3);
      expect(await auditFor("reset.requested", u.id)).toHaveLength(3);
    });

    // ------------------------------------------------- with a recovery code

    const recovery = (b: Browser, login: string, code: string, password = NEW_PW) => b.form("/reset", { action: "recovery", login, code, password });

    test("success: the password changed, the code spent, every session and refresh token ended, audited, two notices", async () => {
      const u = await stack.user({ username: uname("uma"), recoveryCodes: 2, access: { tasks: "user" } });
      const session = await stack.session(u);
      const { tokens } = await signInTo(stack, session, "tasks-ios");
      expect(tokens.refresh_token).toBeDefined();
      const b = stack.browser();
      // Four failures first: the success clears them.
      for (let i = 0; i < 4; i++) expect((await recovery(b, u.username, "aaaa-aaaa-aaaa-aaaa-aaaa-aaaa")).status).toBe(401);
      const res = await recovery(b, `  ${u.username.toUpperCase()}  `, u.recoveryCodes[0]!.toLowerCase().replace(/-/g, " "));
      expect(res.status).toBe(303);
      expect(res.headers.get("Location")).toBe(`/login?${new URLSearchParams({ login_hint: u.username, notice: "reset" })}`);
      expect(await Bun.password.verify(NEW_PW, (await userRow(u.id))!.password_hash)).toBe(true);
      expect(await signedIn(session)).toBeNull();
      expect(await stack.db`SELECT 1 FROM sessions WHERE user_id = ${u.id}`).toHaveLength(0);
      const refresh = await backChannel(stack, "/oauth/token", { grant_type: "refresh_token", refresh_token: tokens.refresh_token!, client_id: "tasks-ios" });
      expect(refresh.status).toBe(400);
      expect(((await refresh.json()) as any).error).toBe("invalid_grant");
      expect((await auditFor("password.reset", u.id))[0]).toMatchObject({ actor: u.id, ip: b.ip, detail: { method: "recovery_code" } });
      expect((await auditFor("recovery.used", u.id))[0]).toMatchObject({ actor: u.id, ip: b.ip });
      await stack.smtp.waitFor(u.email!, (m) => m.subject === "Security notice: password reset");
      const used = await stack.smtp.waitFor(u.email!, (m) => m.subject === "Security notice: a recovery code was used");
      expect(used.text).toContain(`On the account "${u.username}": a recovery code was used.`);
      // The code is spent.
      expect((await recovery(b, u.username, u.recoveryCodes[0]!, "another new password")).status).toBe(401);
      // The counter was cleared: the four earlier failures plus this one would otherwise make the next attempt wait.
      expect((await recovery(b, u.username, u.recoveryCodes[0]!, "another new password")).status).toBe(401);
      // The other code still works.
      expect((await recovery(b, u.username, u.recoveryCodes[1]!, "another new password")).status).toBe(303);
      const login = await pageOf(await stack.browser().get(res.headers.get("Location")!));
      expect(login.text).toContain("Your password is changed. Sign in.");
    });

    test("a wrong code and an unknown user get the same 401, each counted and audited", async () => {
      const u = await stack.user({ username: uname("wrong"), recoveryCodes: 1 });
      const b = stack.browser();
      const wrong = await pageOf(await recovery(b, u.username, "aaaa-aaaa-aaaa-aaaa-aaaa-aaaa"));
      const unknown = await pageOf(await recovery(b, "nobody-known-here", u.recoveryCodes[0]!));
      for (const p of [wrong, unknown]) {
        expect(p.status).toBe(401);
        expect(p.title).toBe("Reset your password");
        expect(p.text).toContain("That username and recovery code don't match.");
      }
      expect(wrong.html).toBe(unknown.html);
      expect((await auditFor("reset.fail", u.id))[0]).toMatchObject({ actor: null, ip: b.ip, detail: { method: "recovery_code" } });
      const anon = (await stack.audit("reset.fail")).filter((r) => r.user_id === null && r.ip === b.ip);
      expect(anon).toHaveLength(1);
      expect(anon[0]!.detail).toEqual({ method: "recovery_code" });
    });

    test("a login with a NUL is an unknown user, counted with the NUL kept as U+FFFD", async () => {
      const name = uname("nul");
      const p = await pageOf(await recovery(stack.browser(), `${name}\u0000x`, "aaaa-aaaa-aaaa-aaaa-aaaa-aaaa"));
      expect(p.status).toBe(401);
      expect(p.text).toContain("That username and recovery code don't match.");
      const [row] = await stack.db`SELECT hits FROM throttle WHERE key = ${`login:name:${name}\uFFFDx`}`;
      expect(Number(row?.hits)).toBe(1);
    });

    test.each([
      ["a malformed code", "not-a-code"],
      ["an empty code", ""],
      ["a code of 41 characters, cut at 40", "a".repeat(41)],
    ])("%s is a wrong code", async (_, code) => {
      const u = await stack.user({ username: uname("mal"), recoveryCodes: 1 });
      expect((await recovery(stack.browser(), u.username, code)).status).toBe(401);
    });

    test("a valid code with a refused password doesn't spend the code; the password rules come after the code", async () => {
      const u = await stack.user({ username: uname("quinn"), recoveryCodes: 1, email: `${uname("quinn")}@example.com` });
      const b = stack.browser();
      // The email as the password: a wrong code says nothing about it.
      const wrong = await pageOf(await recovery(b, u.username, "aaaa-aaaa-aaaa-aaaa-aaaa-aaaa", u.email!));
      expect(wrong.status).toBe(401);
      for (const [password, message] of [
        [u.email!, "Don't use your email address as your password."],
        ["short", "Use at least 12 characters."],
        ["password1234", BREACHED],
      ] as const) {
        const p = await pageOf(await recovery(b, u.username, u.recoveryCodes[0]!, password));
        expect(p.status).toBe(400);
        expect(p.text).toContain(message);
      }
      expect((await recovery(b, u.username, u.recoveryCodes[0]!)).status).toBe(303);
    });

    test.each([
      ["disabled", { disabled: true }],
      ["a bot", { kind: "bot" as const, password: null }],
    ])("an account that is %s gets the wrong-code answer even with a valid code", async (_, extra) => {
      const u = await stack.user({ username: uname("nope"), recoveryCodes: 1, ...extra });
      const p = await pageOf(await recovery(stack.browser(), u.username, u.recoveryCodes[0]!));
      expect(p.status).toBe(401);
      expect(p.text).toContain("That username and recovery code don't match.");
      expect(await stack.db`SELECT 1 FROM recovery_codes WHERE user_id = ${u.id} AND used_at IS NULL`).toHaveLength(1);
    });

    test("five failures on an account, then 429 with Retry-After, even with a valid code", async () => {
      const u = await stack.user({ username: uname("wait"), recoveryCodes: 1 });
      for (let i = 0; i < 5; i++) expect((await recovery(stack.browser(), u.username, "aaaa-aaaa-aaaa-aaaa-aaaa-aaaa")).status).toBe(401);
      const res = await recovery(stack.browser(), u.username, u.recoveryCodes[0]!);
      const p = await pageOf(res);
      expect(p.status).toBe(429);
      expect(p.text).toContain("Too many failed attempts. Try again later.");
      const retry = Number(res.headers.get("Retry-After"));
      expect(retry).toBeGreaterThan(0);
      expect(retry).toBeLessThanOrEqual(60);
      expect(await stack.db`SELECT 1 FROM recovery_codes WHERE user_id = ${u.id} AND used_at IS NULL`).toHaveLength(1);
    });

    test("an unknown name waits after five failures just like an account", async () => {
      const name = uname("ghost");
      for (let i = 0; i < 5; i++) expect((await recovery(stack.browser(), name, "aaaa-aaaa-aaaa-aaaa-aaaa-aaaa")).status).toBe(401);
      const res = await recovery(stack.browser(), name.toUpperCase(), "aaaa-aaaa-aaaa-aaaa-aaaa-aaaa");
      expect(res.status).toBe(429);
      expect((await pageOf(res)).text).toContain("Too many failed attempts. Try again later.");
    });

    test("thirty attempts per IP in fifteen minutes, shared with the sign-in form, then 429", async () => {
      const b = stack.browser();
      await (await b.form("/login", { login: "nobody-signs-in", password: "wrong password" })).body?.cancel();
      for (let i = 0; i < 29; i++) expect((await recovery(b, `nobody-${i}-${seq}`, "aaaa-aaaa-aaaa-aaaa-aaaa-aaaa")).status).toBe(401);
      const res = await recovery(b, "anyone", "aaaa-aaaa-aaaa-aaaa-aaaa-aaaa");
      const p = await pageOf(res);
      expect(p.status).toBe(429);
      expect(p.text).toContain("Too many attempts from your network. Try again later.");
      expect(Number(res.headers.get("Retry-After"))).toBeGreaterThan(800);
    });
  });

  // ========================================================== reset confirm

  describe("reset confirm", () => {
    async function withPasskey(user: TestUser): Promise<SoftAuthenticator> {
      const authenticator = new SoftAuthenticator();
      await stack.db`
        INSERT INTO passkeys (id, user_id, credential_id, public_key, name)
        VALUES (${newId("pk")}, ${user.id}, ${authenticator.credentialId}, ${Buffer.from(authenticator.cose)}, 'Laptop')`;
      return authenticator;
    }

    // An assertion as the page's script makes it, with its challenge cookie in the browser.
    async function assertion(b: Browser, authenticator: SoftAuthenticator): Promise<string> {
      const res = await b.request("/login/passkey/options", { method: "POST" });
      expect(res.status).toBe(200);
      const { options } = (await res.json()) as { options: { challenge: string; rpId: string } };
      expect(b.cookies.has("__Host-webauthn")).toBe(true);
      return JSON.stringify(authenticator.get(options, stack.issuer));
    }

    const back = (token: string) => ({ href: `/reset/confirm?${new URLSearchParams({ token })}`, text: "Back" });
    const wrongCode = (code: string) => String((Number(code) + 500_000) % 1_000_000).padStart(6, "0");

    test("the CLI's printed link works", async () => {
      const u = await stack.user({ username: uname("clireset") });
      const out = await stack.cli(["user", "reset-link", u.username, "--print-link"]);
      expect(out.code).toBe(0);
      const url = /https?:\/\/\S+\/reset\/confirm\?token=\S+/.exec(out.stdout)![0];
      expect((await stack.browser().form("/reset/confirm", { token: tokenIn(url), password: NEW_PW })).status).toBe(303);
    });

    test("the link from the reset mail works", async () => {
      const u = await stack.user({ username: uname("mailreset") });
      await (await stack.browser().form("/reset", { action: "email", login: u.username })).body?.cancel();
      const link = linkIn(await stack.smtp.waitFor(u.email!));
      const b = stack.browser();
      expect((await b.get(link.pathname + link.search)).status).toBe(200);
      expect((await b.form("/reset/confirm", { token: tokenIn(link.href), password: NEW_PW })).status).toBe(303);
    });

    test("GET, no second factor: the password only, no script", async () => {
      const u = await stack.user({ username: uname("plain") });
      const token = await issue("reset", u.id, u.email);
      const b = stack.browser();
      const p = await pageOf(await b.get(`/reset/confirm?token=${token}`));
      expect(p.status).toBe(200);
      expect(p.title).toBe("Choose a new password");
      expect(p.h1).toBe("Choose a new password");
      const f = p.forms[0]!;
      expect(f.attrs).toMatchObject({ method: "post", action: "/reset/confirm", id: "reset-form" });
      expect(input(f, "csrf")!.value).toBe(b.cookies.get("__Host-csrf")!);
      expect(input(f, "token")).toMatchObject({ type: "hidden", value: token });
      expect(input(f, "username")).toMatchObject({ type: "hidden", value: u.username, autocomplete: "username" });
      expect(input(f, "password")).toMatchObject({ type: "password", minlength: "12", maxlength: "256", autocomplete: "new-password" });
      expect(f.inputs.map((i) => i.name).sort()).toEqual(["csrf", "password", "token", "username"]);
      expect(p.scripts).toEqual([]);
      expect((await b.get(`/reset/confirm?token=${token}`)).status).toBe(200);
    });

    test("GET, with TOTP: a required code field, no script; the same with a passkey as well", async () => {
      for (const passkey of [false, true]) {
        const u = await stack.user({ username: uname("totp"), totp: true });
        if (passkey) await withPasskey(u);
        const p = await pageOf(await stack.browser().get(`/reset/confirm?token=${await issue("reset", u.id, u.email)}`));
        const f = p.forms[0]!;
        expect(input(f, "code")).toMatchObject({ autocomplete: "one-time-code", maxlength: "40" });
        expect(input(f, "code")!.required).toBeDefined();
        expect(input(f, "passkey")).toBeUndefined();
        expect(p.text).toContain("The 6-digit code from your authenticator app, or a recovery code.");
        expect(p.scripts).toEqual([]);
      }
    });

    test("GET, with a passkey only: the passkey field and button, an optional recovery code, and the sign-in script", async () => {
      const u = await stack.user({ username: uname("pk") });
      await withPasskey(u);
      const p = await pageOf(await stack.browser().get(`/reset/confirm?token=${await issue("reset", u.id, u.email)}`));
      const f = p.forms[0]!;
      expect(input(f, "passkey")).toMatchObject({ type: "hidden", id: "passkey-response" });
      expect(input(f, "code")).toMatchObject({ autocomplete: "off", maxlength: "40" });
      expect(input(f, "code")!.required).toBeUndefined();
      expect(f.html).toMatch(/<button[^>]*id="passkey-confirm"/);
      expect(p.text).toContain("Confirm with your passkey, or enter a recovery code.");
      expect(p.scripts).toEqual(["/assets/signin.js"]);
    });

    test.each([
      ["unknown", async () => randomBytes(32).toString("base64url")],
      ["missing", async () => null],
      ["expired", async (u: TestUser) => issue("reset", u.id, u.email, { expired: true })],
      ["used", async (u: TestUser) => issue("reset", u.id, u.email, { used: true })],
      ["for activation", async (u: TestUser) => issue("activate", u.id, u.email)],
    ])("a token that is %s: 404 on GET (with a link to ask again) and on POST", async (_, make) => {
      const u = await stack.user({ username: uname("bad") });
      const token = await make(u);
      const q = token === null ? "" : `?${new URLSearchParams({ token })}`;
      await expectMessage(await stack.browser().get(`/reset/confirm${q}`), 404, "Link not valid", "This reset link has expired or was already used.", { href: "/reset", text: "Ask for a new one" });
      const fields: Record<string, string> = { password: NEW_PW };
      if (token !== null) fields.token = token;
      await expectMessage(await stack.browser().form("/reset/confirm", fields), 404, "Link not valid", "This reset link has expired or was already used.", null);
      expect(await Bun.password.verify(PW, (await userRow(u.id))!.password_hash)).toBe(true);
    });

    test("POST for a disabled user: 404", async () => {
      const u = await stack.user({ username: uname("dis"), disabled: true });
      const token = await issue("reset", u.id, u.email);
      await expectMessage(await stack.browser().form("/reset/confirm", { token, password: NEW_PW }), 404, "Link not valid", "This reset link has expired or was already used.");
    });

    test("no second factor: success ends every session, notifies, and the link works once", async () => {
      const u = await stack.user({ username: uname("ok") });
      const session = await stack.session(u);
      // Failures from earlier sign-ins are cleared by the reset.
      for (let i = 0; i < 5; i++) await (await stack.browser().form("/login", { login: u.username, password: "wrong password!" })).body?.cancel();
      const token = await issue("reset", u.id, u.email);
      const b = stack.browser();
      const res = await b.form("/reset/confirm", { token, password: NEW_PW });
      expect(res.status).toBe(303);
      expect(res.headers.get("Location")).toBe(`/login?${new URLSearchParams({ login_hint: u.username, notice: "reset" })}`);
      expect(await Bun.password.verify(NEW_PW, (await userRow(u.id))!.password_hash)).toBe(true);
      expect(await signedIn(session)).toBeNull();
      expect((await auditFor("password.reset", u.id))[0]).toMatchObject({ actor: u.id, ip: b.ip, detail: { method: "email" } });
      expect(await auditFor("recovery.used", u.id)).toEqual([]);
      const notice = await stack.smtp.waitFor(u.email!, (m) => m.subject === "Security notice: password reset");
      expect(notice.text).toContain(`On the account "${u.username}": password reset.`);
      const [row] = await stack.db`SELECT used_at FROM one_time_tokens WHERE token_hash = ${sha256(token)}`;
      expect(row.used_at).toBeInstanceOf(Date);
      await expectMessage(await stack.browser().form("/reset/confirm", { token, password: "another new password" }), 404, "Link not valid", "This reset link has expired or was already used.");
      // The failure counter is gone: the new password signs in at once.
      expect((await stack.browser().form("/login", { login: u.username, password: NEW_PW })).status).toBe(303);
      await marker();
      expect(stack.smtp.to(u.email!).map((m) => m.subject)).toEqual(["Security notice: password reset"]);
    });

    test.each([
      ["short", "short", "Use at least 12 characters."],
      ["long", "y".repeat(257), "Use at most 256 characters."],
      ["breached", "password1234", BREACHED],
    ])("a %s password: 400 with a Back link, before the second factor, so nothing is spent", async (_, password, message) => {
      const u = await stack.user({ username: uname("pp"), totp: true, recoveryCodes: 1 });
      const token = await issue("reset", u.id, u.email);
      await expectMessage(await stack.browser().form("/reset/confirm", { token, password, code: u.recoveryCodes[0]! }), 400, "Choose another password", message, back(token));
      expect(await stack.db`SELECT 1 FROM recovery_codes WHERE user_id = ${u.id} AND used_at IS NULL`).toHaveLength(1);
      expect(await auditFor("reset.fail", u.id)).toEqual([]);
      expect((await stack.browser().form("/reset/confirm", { token, password: NEW_PW, code: u.recoveryCodes[0]! })).status).toBe(303);
    });

    test("the username or the email as the password is refused", async () => {
      const u = await stack.user({ username: `reset-user-${seq++}${randomBytes(2).toString("hex")}` });
      const token = await issue("reset", u.id, u.email);
      await expectMessage(await stack.browser().form("/reset/confirm", { token, password: u.username.toUpperCase() }), 400, "Choose another password", "Don't use your username as your password.", back(token));
      await expectMessage(await stack.browser().form("/reset/confirm", { token, password: u.email!.toUpperCase() }), 400, "Choose another password", "Don't use your email address as your password.", back(token));
    });

    test("TOTP: the right code resets", async () => {
      const u = await stack.user({ username: uname("tc"), totp: true });
      const token = await issue("reset", u.id, u.email);
      const res = await stack.browser().form("/reset/confirm", { token, password: NEW_PW, code: ` ${await stack.code(u)} ` });
      expect(res.status).toBe(303);
      expect((await auditFor("password.reset", u.id))[0]!.detail).toEqual({ method: "email" });
    });

    test("TOTP: a wrong code or an empty one is 401, counted against the account and audited", async () => {
      const u = await stack.user({ username: uname("tw"), totp: true });
      const token = await issue("reset", u.id, u.email);
      const b = stack.browser();
      for (const code of [wrongCode(await stack.code(u)), "", undefined]) {
        const fields: Record<string, string> = { token, password: NEW_PW };
        if (code !== undefined) fields.code = code;
        await expectMessage(await b.form("/reset/confirm", fields), 401, "Second factor didn't work", "That code or passkey didn't work.", back(token));
      }
      const fails = await auditFor("reset.fail", u.id);
      expect(fails).toHaveLength(3);
      expect(fails[0]).toMatchObject({ actor: null, ip: b.ip, detail: { method: "second_factor" } });
      // Counted against the account's sign-in limit: two more and the password sign-in waits.
      for (let i = 0; i < 2; i++) await (await stack.browser().form("/login", { login: u.username, password: "wrong password!" })).body?.cancel();
      const login = await stack.browser().form("/login", { login: u.username, password: PW });
      expect(login.status).toBe(429);
      // The link is unspent.
      expect((await stack.db`SELECT used_at FROM one_time_tokens WHERE token_hash = ${sha256(token)}`)[0].used_at).toBeNull();
    });

    test("TOTP: a recovery code instead is spent, audited and notified", async () => {
      const u = await stack.user({ username: uname("trc"), totp: true, recoveryCodes: 2 });
      const token = await issue("reset", u.id, u.email);
      const b = stack.browser();
      expect((await b.form("/reset/confirm", { token, password: NEW_PW, code: u.recoveryCodes[1]! })).status).toBe(303);
      expect((await auditFor("password.reset", u.id))[0]!.detail).toEqual({ method: "recovery_code" });
      expect((await auditFor("recovery.used", u.id))[0]).toMatchObject({ actor: u.id, ip: b.ip });
      expect(await stack.db`SELECT 1 FROM recovery_codes WHERE user_id = ${u.id} AND used_at IS NULL`).toHaveLength(1);
      await stack.smtp.waitFor(u.email!, (m) => m.subject === "Security notice: password reset");
      await stack.smtp.waitFor(u.email!, (m) => m.subject === "Security notice: a recovery code was used");
    });

    test("TOTP: five attempts per account, then 429, even with the right code; a refused password is still told first", async () => {
      const u = await stack.user({ username: uname("t5"), totp: true });
      const token = await issue("reset", u.id, u.email);
      for (let i = 0; i < 5; i++) expect((await stack.browser().form("/reset/confirm", { token, password: NEW_PW, code: "111111x" })).status).toBe(401);
      await expectMessage(await stack.browser().form("/reset/confirm", { token, password: NEW_PW, code: await stack.code(u) }), 429, "Too many attempts", "Too many wrong codes. Try again later.", back(token));
      expect((await stack.browser().form("/reset/confirm", { token, password: "short" })).status).toBe(400);
      // Another link for the same account is held too.
      const other = await issue("reset", u.id, u.email);
      expect((await stack.browser().form("/reset/confirm", { token: other, password: NEW_PW, code: await stack.code(u) })).status).toBe(429);
    });

    test("passkey only: an assertion with its challenge cookie resets", async () => {
      const u = await stack.user({ username: uname("pa") });
      const authenticator = await withPasskey(u);
      const token = await issue("reset", u.id, u.email);
      const b = stack.browser();
      const passkey = await assertion(b, authenticator);
      const res = await b.form("/reset/confirm", { token, password: NEW_PW, passkey });
      expect(res.status).toBe(303);
      expect((await auditFor("password.reset", u.id))[0]!.detail).toEqual({ method: "email" });
      expect(await auditFor("recovery.used", u.id)).toEqual([]);
    });

    test("passkey only: a recovery code instead", async () => {
      const u = await stack.user({ username: uname("pr"), recoveryCodes: 1 });
      await withPasskey(u);
      const token = await issue("reset", u.id, u.email);
      expect((await stack.browser().form("/reset/confirm", { token, password: NEW_PW, code: u.recoveryCodes[0]! })).status).toBe(303);
      expect((await auditFor("password.reset", u.id))[0]!.detail).toEqual({ method: "recovery_code" });
      expect(await auditFor("recovery.used", u.id)).toHaveLength(1);
    });

    test("passkey only: neither, a malformed one, one without its cookie, one used twice, or another user's, is 401", async () => {
      const u = await stack.user({ username: uname("pn"), recoveryCodes: 1 });
      const authenticator = await withPasskey(u);
      const other = await stack.user({ username: uname("po") });
      const otherKey = await withPasskey(other);
      const token = await issue("reset", u.id, u.email);
      const tryWith = async (b: Browser, fields: Record<string, string>) =>
        expectMessage(await b.form("/reset/confirm", { token, password: NEW_PW, ...fields }), 401, "Second factor didn't work", "That code or passkey didn't work.", back(token));
      await tryWith(stack.browser(), {});
      await tryWith(stack.browser(), { passkey: "{not json" });
      const noCookie = stack.browser();
      const loose = await assertion(noCookie, authenticator);
      noCookie.cookies.delete("__Host-webauthn");
      await tryWith(noCookie, { passkey: loose });
      expect(await auditFor("reset.fail", u.id)).toHaveLength(3);
      // A wrong recovery code is a failure too (its own field wins over the passkey).
      const b = stack.browser();
      const ok = await assertion(b, authenticator);
      await tryWith(b, { passkey: ok, code: "aaaa-aaaa-aaaa-aaaa-aaaa-aaaa" });
      const c = stack.browser();
      await tryWith(c, { passkey: await assertion(c, otherKey) });
      // Five attempts: the sixth is held.
      const d = stack.browser();
      await expectMessage(await d.form("/reset/confirm", { token, password: NEW_PW, passkey: await assertion(d, authenticator) }), 429, "Too many attempts", "Too many wrong codes. Try again later.", back(token));
    });

    test("passkey only: an assertion's challenge works once", async () => {
      const u = await stack.user({ username: uname("p1") });
      const authenticator = await withPasskey(u);
      const b = stack.browser();
      const passkey = await assertion(b, authenticator);
      const first = await issue("reset", u.id, u.email);
      expect((await b.form("/reset/confirm", { token: first, password: NEW_PW, passkey })).status).toBe(303);
      const second = await issue("reset", u.id, u.email);
      expect((await b.form("/reset/confirm", { token: second, password: "another new password", passkey })).status).toBe(401);
    });

    test("TOTP: the same code can't be used twice", async () => {
      const u = await stack.user({ username: uname("tr"), totp: true });
      const code = await stack.code(u);
      expect((await stack.browser().form("/reset/confirm", { token: await issue("reset", u.id, u.email), password: NEW_PW, code })).status).toBe(303);
      expect((await stack.browser().form("/reset/confirm", { token: await issue("reset", u.id, u.email), password: "another new password", code })).status).toBe(401);
    });

    test("a TOTP code from the next step is accepted", async () => {
      const u = await stack.user({ username: uname("tn"), totp: true });
      await stack.code(u);
      const res = await stack.browser().form("/reset/confirm", { token: await issue("reset", u.id, u.email), password: NEW_PW, code: totp(u.totpSecret!, Date.now(), 1) });
      expect(res.status).toBe(303);
    });
  });

  // ===================================================== email verification

  describe("email verification", () => {
    test("GET: the address and a confirm button; peeking spends nothing", async () => {
      const u = await stack.user({ username: uname("ver") });
      const address = `${uname("new")}@example.org`;
      const token = await issue("verify_email", u.id, address);
      const b = stack.browser();
      const p = await pageOf(await b.get(`/verify-email?token=${token}`));
      expect(p.status).toBe(200);
      expect(p.title).toBe("Confirm your email address");
      expect(p.h1).toBe("Confirm your email address");
      expect(p.text).toContain(address);
      const f = p.forms[0]!;
      expect(f.attrs).toMatchObject({ method: "post", action: "/verify-email" });
      expect(input(f, "csrf")!.value).toBe(b.cookies.get("__Host-csrf")!);
      expect(input(f, "token")).toMatchObject({ type: "hidden", value: token });
      expect(f.html).toMatch(/<button[^>]*type="submit"[^>]*>Confirm<\/button>/);
      expect((await b.get(`/verify-email?token=${token}`)).status).toBe(200);
    });

    test.each([
      ["unknown", async () => randomBytes(32).toString("base64url")],
      ["missing", async () => null],
      ["expired", async (u: TestUser) => issue("verify_email", u.id, "x@example.org", { expired: true })],
      ["used", async (u: TestUser) => issue("verify_email", u.id, "x@example.org", { used: true })],
      ["for a reset", async (u: TestUser) => issue("reset", u.id, u.email)],
    ])("a token that is %s: 404 on GET and POST", async (_, make) => {
      const u = await stack.user({ username: uname("vb") });
      const token = await make(u);
      const q = token === null ? "" : `?${new URLSearchParams({ token })}`;
      await expectMessage(await stack.browser().get(`/verify-email${q}`), 404, "Link not valid", "This link has expired or was already used.", null);
      await expectMessage(await stack.browser().form("/verify-email", token === null ? {} : { token }), 404, "Link not valid", "This link has expired or was already used.", null);
      expect((await userRow(u.id))!.email).toBe(u.email);
    });

    test("POST: sets the address, voids the other pending address and reset links, audits; a second use is 404", async () => {
      const u = await stack.user({ username: uname("vp"), emailVerified: false });
      const address = `${uname("Conf")}@Example.org`;
      const token = await issue("verify_email", u.id, address);
      const otherVerify = await issue("verify_email", u.id, "typo@exmaple.test");
      const reset = await issue("reset", u.id, u.email);
      const activate = await issue("activate", u.id, u.email);
      const someoneElse = await stack.user({ username: uname("vo") });
      const theirs = await issue("reset", someoneElse.id, someoneElse.email);
      const b = stack.browser();
      await expectMessage(await b.form("/verify-email", { token }), 200, "Address confirmed", "Your email address is confirmed.", { href: "/account", text: "Your account" });
      const row = (await userRow(u.id))!;
      expect(row.email).toBe(address);
      expect(row.email_verified_at).toBeInstanceOf(Date);
      expect((await auditFor("email.verify", u.id))[0]).toMatchObject({ actor: u.id, ip: b.ip, detail: {} });
      expect((await stack.browser().get(`/verify-email?token=${otherVerify}`)).status).toBe(404);
      expect((await stack.browser().get(`/reset/confirm?token=${reset}`)).status).toBe(404);
      expect((await stack.browser().get(`/activate?token=${activate}`)).status).toBe(200);
      expect((await stack.browser().get(`/reset/confirm?token=${theirs}`)).status).toBe(200);
      await expectMessage(await stack.browser().form("/verify-email", { token }), 404, "Link not valid", "This link has expired or was already used.");
    });

    test("the address taken by another account meanwhile: 409 Address in use, and nothing changes", async () => {
      const u = await stack.user({ username: uname("vt") });
      const address = `${uname("contested")}@example.org`;
      const token = await issue("verify_email", u.id, address);
      const reset = await issue("reset", u.id, u.email);
      await stack.user({ username: uname("vq"), email: address.toUpperCase() });
      await expectMessage(await stack.browser().form("/verify-email", { token }), 409, "Address in use", "Another account already uses this address, so it can't be added to this one.", null);
      expect((await userRow(u.id))!.email).toBe(u.email);
      expect(await auditFor("email.verify", u.id)).toEqual([]);
      // Rolled back whole: the links are as they were.
      expect((await stack.browser().get(`/verify-email?token=${token}`)).status).toBe(200);
      expect((await stack.browser().get(`/reset/confirm?token=${reset}`)).status).toBe(200);
    });

    test("a token without an address is spent and refused", async () => {
      const u = await stack.user({ username: uname("vn") });
      const token = await issue("verify_email", u.id, null);
      await expectMessage(await stack.browser().form("/verify-email", { token }), 404, "Link not valid", "This link has expired or was already used.");
      expect((await userRow(u.id))!.email).toBe(u.email);
    });
  });

  // ================================================== form CSRF and Origin

  describe("every form post checks its token and Origin", () => {
    const endpoints = ["/signup", "/invite", "/activate", "/reset", "/reset/confirm", "/verify-email"];

    test.each(endpoints)("%s: no form token is 403", async (path) => {
      const b = stack.browser();
      await b.formCsrf();
      await expectRefusal(await b.form(path, { token: "x", action: "email", login: "x" }, { csrf: null }), 403, FORM_REFUSED);
    });

    test.each(endpoints)("%s: a token that doesn't match the cookie is 403", async (path) => {
      const b = stack.browser();
      await b.formCsrf();
      await expectRefusal(await b.form(path, { token: "x" }, { csrf: "A".repeat(43) }), 403, FORM_REFUSED);
    });

    test.each(endpoints)("%s: a token without its cookie is 403", async (path) => {
      const b = stack.browser();
      const csrf = await b.formCsrf();
      b.cookies.delete("__Host-csrf");
      await expectRefusal(await b.form(path, { token: "x" }, { csrf }), 403, FORM_REFUSED);
    });

    test.each(endpoints)("%s: another Origin is 403", async (path) => {
      await expectRefusal(await stack.browser().form(path, { token: "x" }, { origin: "https://evil.example.com" }), 403, ORIGIN_REFUSED);
    });

    test.each(endpoints)("%s: no Origin is 403", async (path) => {
      await expectRefusal(await stack.browser().form(path, { token: "x" }, { origin: null }), 403, ORIGIN_REFUSED);
    });

    test.each(endpoints)("%s: Origin null with Sec-Fetch-Site same-origin passes", async (path) => {
      const res = await stack.browser().form(path, { token: "x" }, { origin: "null", headers: { "Sec-Fetch-Site": "same-origin" } });
      expect(res.status).not.toBe(403);
      await res.body?.cancel();
    });

    test.each(endpoints)("%s: Origin null alone is 403", async (path) => {
      await expectRefusal(await stack.browser().form(path, { token: "x" }, { origin: "null" }), 403, ORIGIN_REFUSED);
    });

    test.each(endpoints)("%s: a body that isn't a form is 415", async (path) => {
      const b = stack.browser();
      const csrf = await b.formCsrf();
      const res = await b.request(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ csrf, token: "x" }) });
      await expectRefusal(res, 415, "Send application/x-www-form-urlencoded.");
    });

    test("a successful form post is also refused from another Origin: no account is made", async () => {
      const username = uname("csrf");
      const res = await stack.browser().form("/signup", { username, email: `${username}@example.com`, password: PW }, { origin: "https://evil.example.com" });
      expect(res.status).toBe(403);
      expect(await userNamed(username)).toBeUndefined();
    });
  });
});

// ==================================================== a deployment without open sign-up

describe.skipIf(!enabled)("a deployment whose services take no sign-ups", () => {
  let stack: Stack;
  let admin: Browser;
  const definition = (extra: Record<string, unknown> = {}) => ({
    name: "tasks",
    roles: ["member", "editor"],
    mfa_roles: [],
    signup: "invite",
    clients: [{ id: "tasks", type: "confidential", redirect_uris: [REDIRECTS.tasks] }],
    ...extra,
  });

  beforeAll(async () => {
    stack = await Stack.start({ services: (events: (s: string) => string) => ({ services: defaultServices(events).services.filter((s: any) => s.name !== "tasks") }) });
    admin = (await stack.admin()).browser;
    const res = await admin.api("POST", "/v1/services", definition());
    expect(res.status).toBe(201);
  });
  afterAll(async () => {
    await stack.stop();
  });
  beforeEach(async () => {
    await stack.resetLimits();
    const res = await admin.api("PUT", "/v1/services/tasks", definition());
    expect(res.status).toBe(200);
  });

  async function invited(role: string): Promise<string> {
    const email = `${uname("reg")}@example.com`;
    const res = await admin.api("POST", "/v1/invites", { email, service: "tasks", role });
    expect(res.status).toBe(201);
    return tokenIn(linkIn(await stack.smtp.waitFor(email)).href);
  }

  test("GET and POST /signup: 404 Not available, before any form check", async () => {
    await expectMessage(await stack.browser().get("/signup"), 404, "Not available", "Accounts here are created by invitation.", null);
    const username = uname("closed");
    const res = await stack.browser().form("/signup", { username, email: `${username}@example.com`, password: PW }, { csrf: null, origin: "https://evil.example.com" });
    await expectMessage(res, 404, "Not available", "Accounts here are created by invitation.", null);
    expect(await stack.db`SELECT 1 FROM users WHERE username = ${username}`).toHaveLength(0);
  });

  test("the sign-in page offers no sign-up", async () => {
    const p = await pageOf(await stack.browser().get("/login"));
    expect(p.links.some((l) => l.href.startsWith("/signup"))).toBe(false);
  });

  test("sign-up is offered once a registered service opens", async () => {
    expect((await admin.api("PUT", "/v1/services/tasks", definition({ signup: "open", default_role: "member" }))).status).toBe(200);
    const p = await pageOf(await stack.browser().get("/signup"));
    expect(p.status).toBe(200);
    expect(p.title).toBe("Create an account");
  });

  test("an invitation whose service has since closed: accepting is 409, no longer valid", async () => {
    const token = await invited("member");
    expect((await admin.api("PUT", "/v1/services/tasks", definition({ signup: "closed" }))).status).toBe(200);
    const user = await stack.user({ username: uname("late") });
    const b = await stack.session(user);
    expect((await b.get(`/invite?token=${token}`)).status).toBe(200);
    await expectRefusal(await b.form("/invite", { token, action: "accept" }), 409, "This invitation is no longer valid.");
    expect(await stack.db`SELECT 1 FROM access WHERE user_id = ${user.id}`).toHaveLength(0);
    expect((await stack.db`SELECT accepted_at FROM invites WHERE token_hash = ${sha256(token)}`)[0].accepted_at).toBeNull();
  });

  test("an invitation whose service has since closed: creating the account is 409, no longer valid, and makes no account", async () => {
    const token = await invited("editor");
    expect((await admin.api("PUT", "/v1/services/tasks", definition({ signup: "closed" }))).status).toBe(200);
    const username = uname("norole");
    await expectMessage(await stack.browser().form("/invite", { token, action: "create", username, password: PW }), 409, "Couldn't create the account", "This invitation is no longer valid.", {
      href: `/invite?${new URLSearchParams({ token })}`,
      text: "Back",
    });
    expect(await stack.db`SELECT 1 FROM users WHERE username = ${username}`).toHaveLength(0);
  });

  test("an invitation to a registered service, still valid, is accepted", async () => {
    const token = await invited("editor");
    const user = await stack.user({ username: uname("reg-ok") });
    expect((await (await stack.session(user)).form("/invite", { token, action: "accept" })).status).toBe(200);
    expect(await stack.db`SELECT role FROM access WHERE user_id = ${user.id} AND service = 'tasks'`).toEqual([{ role: "editor" }]);
  });
});
