import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { SoftAuthenticator, UP, type Edits } from "../src/testing/authenticator";
import { API_CSP, b64u, backChannel, CLI, enabled, nest, randomToken, SECURITY_HEADERS, sha256, signInTo, Stack, totp, type Browser, type TestUser } from "./harness";

// Signing in at auth's own pages (docs/DESIGN.md §7.1, §9.1, §9.2, §9.4): the
// page shell and its headers, the static assets, the forms' CSRF defences,
// password, TOTP, recovery-code and passkey sign-in, the throttles, and the
// account and admin shells.

setDefaultTimeout(30_000);

const PW = "correct horse battery";
const ASSET_DIR = join(import.meta.dir, "..", "src", "assets");

// ------------------------------------------------------------------ helpers

function uname(prefix: string): string {
  return `${prefix}-${randomBytes(4).toString("hex")}`;
}

function decode(s: string): string {
  return s
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#0*39;|&#x0*27;|&apos;/gi, "'")
    .replace(/&amp;/g, "&");
}

// Visible text of an HTML fragment: tags dropped, entities decoded, spaces collapsed.
function textOf(fragment: string): string {
  return decode(fragment.replace(/<[^>]*>/g, " "))
    .replace(/\s+/g, " ")
    .trim();
}

interface Tag {
  attrs: Record<string, string>;
  inner: string;
}

// Every <name …> element, attributes decoded; `inner` up to the closing tag
// for elements that have one.
function tagsOf(html: string, name: string): Tag[] {
  const out: Tag[] = [];
  const re = new RegExp(`<${name}\\b([^>]*)>`, "gi");
  for (let m = re.exec(html); m; m = re.exec(html)) {
    const attrs: Record<string, string> = {};
    for (const a of m[1]!.matchAll(/([\w:-]+)(?:\s*=\s*"([^"]*)")?/g)) attrs[a[1]!.toLowerCase()] = decode(a[2] ?? "");
    const rest = html.slice(m.index + m[0].length);
    const close = rest.search(new RegExp(`</${name}>`, "i"));
    out.push({ attrs, inner: close < 0 ? "" : rest.slice(0, close) });
  }
  return out;
}

function findTag(html: string, name: string, attrs: Record<string, string>): Tag | undefined {
  return tagsOf(html, name).find((t) => Object.entries(attrs).every(([k, v]) => t.attrs[k] === v));
}

function expectTag(html: string, name: string, attrs: Record<string, string>): Tag {
  const t = findTag(html, name, attrs);
  if (!t) throw new Error(`no <${name}> with ${JSON.stringify(attrs)} in:\n${html}`);
  return t;
}

// The text of each <p class="<kind>"> message box.
function flashes(html: string, kind: "notice" | "error" | "success"): string[] {
  return tagsOf(html, "p")
    .filter((t) => (t.attrs.class ?? "").split(/\s+/).includes(kind) && !("hidden" in t.attrs))
    .map((t) => textOf(t.inner));
}

function titleOf(html: string): string {
  return textOf(tagsOf(html, "title")[0]?.inner ?? "");
}

function scriptsOf(html: string): string[] {
  return tagsOf(html, "script").map((t) => t.attrs.src ?? "");
}

function setCookieOf(res: Response, name: string): string | undefined {
  return res.headers.getSetCookie().find((c) => c.startsWith(`__Host-${name}=`));
}

// A Set-Cookie line as its value and its attributes, names lowercased.
function parseCookie(line: string | undefined): { value: string; attrs: Record<string, string> } {
  if (line === undefined) throw new Error("no such cookie was set");
  const [pair, ...rest] = line.split(";").map((p) => p.trim());
  const attrs: Record<string, string> = {};
  for (const a of rest) {
    const eq = a.indexOf("=");
    if (eq < 0) attrs[a.toLowerCase()] = "";
    else attrs[a.slice(0, eq).toLowerCase()] = a.slice(eq + 1);
  }
  return { value: pair!.slice(pair!.indexOf("=") + 1), attrs };
}

function cookieAttrs(sameSite: "Lax" | "Strict", maxAge?: number): Record<string, string> {
  const a: Record<string, string> = { path: "/", secure: "", httponly: "", samesite: sameSite };
  if (maxAge !== undefined) a["max-age"] = String(maxAge);
  return a;
}

function expectCleared(res: Response, name: string): void {
  const c = parseCookie(setCookieOf(res, name));
  expect(c.value).toBe("");
  expect(c.attrs).toEqual(cookieAttrs("Lax", 0));
}

const DEFAULT_SOURCES = "com.example.tasks: https://mail.example.com https://notes.example.com https://tasks.example.com https://wiki.example.com";
const pageCsp = (sources: string) => `default-src 'self'; frame-ancestors 'none'; form-action 'self'${sources ? ` ${sources}` : ""}; base-uri 'none'`;

// An HTML page with its headers, as every page is served.
async function expectPage(res: Response, status: number, title: string, sources = DEFAULT_SOURCES): Promise<string> {
  const html = await res.text();
  if (res.status !== status) throw new Error(`expected ${status}, got ${res.status}:\n${html.slice(0, 2000)}`);
  expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
  expect(res.headers.get("Content-Security-Policy")).toBe(pageCsp(sources));
  expect(res.headers.get("Cache-Control")).toBe("no-store");
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) expect(res.headers.get(k)).toBe(v);
  expect(html.trimStart().toLowerCase().startsWith("<!doctype html>")).toBe(true);
  expect(titleOf(html)).toBe(title);
  return html;
}

// A message page: its title, the message, and its one link.
async function expectMessage(res: Response, status: number, title: string, message: string, link: { href: string; text: string }): Promise<string> {
  const html = await expectPage(res, status, title);
  expect(textOf(tagsOf(html, "h1")[0]?.inner ?? "")).toBe(title);
  expect(tagsOf(html, "p").map((p) => textOf(p.inner))).toContain(message);
  expect(textOf(expectTag(html, "a", { href: link.href }).inner)).toBe(link.text);
  return html;
}

// A refusal pageErrors renders.
function expectWentWrong(res: Response, status: number, message: string): Promise<string> {
  return expectMessage(res, status, "Something went wrong", message, { href: "/login", text: "Sign in" });
}

async function expectJsonError(res: Response, status: number, error: string, description: string): Promise<void> {
  expect(res.status).toBe(status);
  expect(res.headers.get("Content-Type")).toBe("application/json");
  expect(res.headers.get("Content-Security-Policy")).toBe(API_CSP);
  expect(await res.json()).toEqual({ error, error_description: description });
}

const FORM_EXPIRED = "This form has expired. Go back, reload the page and try again.";
const NOT_FROM_SITE = "This form was not sent from this site.";
const WRONG_LOGIN = "Wrong username or password.";

// return_to values localPath refuses, with what makes each one wrong.
const LONG_OK = `/${"a".repeat(4095)}`;
const REFUSED_RETURN_TO: [string, string | null][] = [
  ["missing", null],
  ["empty", ""],
  ["relative", "account"],
  ["absolute URL", "https://evil.example.com/"],
  ["protocol-relative", "//evil.example.com/x"],
  ["slash-backslash", "/\\evil.example.com"],
  ["a backslash inside", "/account\\x"],
  ["a NUL", "/account\u0000x"],
  ["a newline", "/account\nx"],
  ["a tab", "/account\tx"],
  ["a unit separator", "/account\u001fx"],
  ["a DEL", "/a\u007fb"],
  // Never in a path the server writes, which comes percent-encoded; raw, it
  // would go into the Location header raw.
  ["a character outside ASCII", "/wiki/\u00e9"],
  ["one outside Latin-1", "/wiki?q=\u65e5\u672c"],
  ["an emoji", "/\u{1f600}"],
  ["4097 characters", `/${"a".repeat(4096)}`],
];
const ACCEPTED_RETURN_TO: [string, string][] = [
  ["the root", "/"],
  ["a path with query and fragment", "/account?tab=security&x=1#keys"],
  ["the admin page", "/admin"],
  ["4096 characters", LONG_OK],
  ["a space", "/a b"],
  ["every printable ASCII character but a backslash", "/ !\"#$%&'()*+,-./0123456789:;<=>?@AZ[]^_`az{|}~"],
];

describe.skipIf(!enabled)("signing in", () => {
  let stack: Stack;
  beforeAll(async () => {
    stack = await Stack.start();
  });
  afterAll(async () => {
    await stack.stop();
  });

  const throttleHits = async (key: string): Promise<number | null> => {
    const [row] = await stack.db`SELECT hits FROM throttle WHERE key = ${key}`;
    return row ? Number(row.hits) : null;
  };
  const sessionByToken = async (token: string | undefined) => {
    const [row] = await stack.db`
      SELECT id, user_id, amr, host(ip) AS ip, user_agent, auth_time, expires_at, ends_at, last_seen_at
      FROM sessions WHERE token_hash = ${sha256(token ?? "")}`;
    return row as
      | { id: string; user_id: string; amr: string[]; ip: string | null; user_agent: string | null; auth_time: Date; expires_at: Date; ends_at: Date; last_seen_at: Date }
      | undefined;
  };
  const auditFor = async (action: string, userId: string | null, ip?: string | null) =>
    (await stack.audit(action)).filter((r) => (userId === null ? r.user_id === null : r.user_id === userId) && (ip === undefined || r.ip === ip));
  const hashOf = async (userId: string): Promise<string> => {
    const [row] = await stack.db`SELECT password_hash FROM users WHERE id = ${userId}`;
    return row.password_hash;
  };
  const deviceIdOf = (device: string) => b64u(sha256(device)).slice(0, 22);

  // ------------------------------------------------------------- page shell

  describe("the page shell", () => {
    test("GET /login: doctype, title, the stylesheet and icons, signin.js, and no csrf-token meta", async () => {
      const res = await stack.browser().get("/login");
      const html = await expectPage(res, 200, "Sign in");
      expectTag(html, "meta", { charset: "utf-8" });
      expectTag(html, "meta", { name: "referrer", content: "no-referrer" });
      expectTag(html, "link", { rel: "stylesheet", href: "/assets/style.css" });
      expectTag(html, "link", { rel: "icon", href: "/favicon.ico" });
      expectTag(html, "link", { rel: "icon", href: "/assets/icon.svg", type: "image/svg+xml" });
      expectTag(html, "link", { rel: "apple-touch-icon", href: "/assets/apple-touch-icon.png" });
      expect(scriptsOf(html)).toEqual(["/assets/signin.js"]);
      expect(findTag(html, "meta", { name: "csrf-token" })).toBeUndefined();
      expect(findTag(html, "header", {})).toBeUndefined();
      // The form.
      expectTag(html, "form", { method: "post", action: "/login" });
      expectTag(html, "input", { name: "login", autocomplete: "username webauthn", maxlength: "254", value: "" });
      expectTag(html, "input", { name: "password", type: "password", autocomplete: "current-password", maxlength: "1024" });
      expectTag(html, "input", { type: "hidden", name: "return_to", value: "/account" });
      expectTag(html, "a", { href: "/reset" });
      expectTag(html, "button", { id: "passkey-signin", "data-return-to": "/account" });
    });

    test("a message page's title is escaped", async () => {
      // "Can't sign in": a pending second factor whose user was disabled meanwhile.
      const user = await stack.user({ username: uname("esc"), totp: true });
      const b = stack.browser();
      await (await b.form("/login", { login: user.username, password: PW })).body?.cancel();
      await stack.db`UPDATE users SET disabled_at = now() WHERE id = ${user.id}`;
      const res = await b.form("/login/second-factor", { code: await stack.code(user) });
      const html = await expectMessage(res, 403, "Can't sign in", "This account is disabled.", { href: "/login", text: "Back" });
      expect(html).not.toContain("<title>Can't sign in</title>");
      expect(b.cookies.has("__Host-auth")).toBe(false);
    });

    test("/account: the header nav with Admin hidden, account.js, and the session's csrf-token", async () => {
      const user = await stack.user({ username: uname("shell") });
      const b = await stack.session(user);
      const html = await expectPage(await b.get("/account"), 200, "Your account");
      expect(scriptsOf(html)).toEqual(["/assets/account.js"]);
      expect(expectTag(html, "meta", { name: "csrf-token" }).attrs.content).toBe(stack.crypt.csrf(b.cookies.get("__Host-auth")!));
      const nav = expectTag(html, "nav", {});
      const links = tagsOf(nav.inner, "a");
      expect(links.map((a) => [a.attrs.href, textOf(a.inner)])).toEqual([
        ["/account", "Account"],
        ["/admin", "Admin"],
        ["/logout", "Sign out"],
      ]);
      expect(links[0]!.attrs["aria-current"]).toBe("page");
      expect(links[1]!.attrs.id).toBe("admin-link");
      expect("hidden" in links[1]!.attrs).toBe(true);
      expect("aria-current" in links[1]!.attrs).toBe(false);
      expect("aria-current" in links[2]!.attrs).toBe(false);
      // The brand names the issuer's host.
      const header = expectTag(html, "header", {});
      expect(textOf(expectTag(header.inner, "a", { href: "/account" }).inner)).toBe(`127.0.0.1:${stack.port}`);
      expect(html).toContain("The account page needs JavaScript.");
    });

    test("/admin: Admin is the current page and shown, admin.js, and the session's csrf-token", async () => {
      const { browser } = await stack.admin();
      const html = await expectPage(await browser.get("/admin"), 200, "Admin");
      expect(scriptsOf(html)).toEqual(["/assets/admin.js"]);
      expect(expectTag(html, "meta", { name: "csrf-token" }).attrs.content).toBe(stack.crypt.csrf(browser.cookies.get("__Host-auth")!));
      // The page's script names the CLI as this server calls it.
      expect(expectTag(html, "meta", { name: "cli" }).attrs.content).toBe(CLI);
      const links = tagsOf(expectTag(html, "nav", {}).inner, "a");
      expect(links.map((a) => a.attrs.href)).toEqual(["/account", "/admin", "/logout"]);
      expect("aria-current" in links[0]!.attrs).toBe(false);
      expect(links[1]!.attrs["aria-current"]).toBe("page");
      expect("hidden" in links[1]!.attrs).toBe(false);
      expect(html).toContain("The admin page needs JavaScript.");
    });

    test("the second-factor and message pages load no script", async () => {
      const user = await stack.user({ username: uname("noscr"), totp: true });
      const b = stack.browser();
      await (await b.form("/login", { login: user.username, password: PW })).body?.cancel();
      expect(scriptsOf(await expectPage(await b.get("/login/second-factor"), 200, "Second factor"))).toEqual([]);
      const plain = await stack.session(await stack.user({ username: uname("noscr") }));
      expect(scriptsOf(await expectPage(await plain.get("/admin"), 403, "No access"))).toEqual([]);
      expect(scriptsOf(await expectPage(await b.get("/mfa-required?service=wiki"), 200, "Two-factor authentication needed"))).toEqual([]);
    });

    test("GET / redirects to /account", async () => {
      const res = await fetch(`${stack.url}/`, { redirect: "manual" });
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/account");
      expect(res.headers.get("Content-Security-Policy")).toBe(API_CSP);
      for (const [k, v] of Object.entries(SECURITY_HEADERS)) expect(res.headers.get(k)).toBe(v);
    });

    test("the page CSP's form-action lists the redirect URIs' https origins and private-use schemes, sorted, once each", async () => {
      const res = await stack.browser().get("/login");
      await res.body?.cancel();
      expect(res.headers.get("Content-Security-Policy")).toBe(
        "default-src 'self'; frame-ancestors 'none'; form-action 'self' com.example.tasks: https://mail.example.com https://notes.example.com https://tasks.example.com https://wiki.example.com; base-uri 'none'",
      );
    });
  });

  // ---------------------------------------------------------------- assets

  describe("assets", () => {
    test.each([
      ["style.css", "text/css; charset=utf-8"],
      ["signin.js", "text/javascript; charset=utf-8"],
      ["account.js", "text/javascript; charset=utf-8"],
      ["admin.js", "text/javascript; charset=utf-8"],
      ["icon.svg", "image/svg+xml"],
      ["apple-touch-icon.png", "image/png"],
      ["favicon.ico", "image/x-icon"],
    ])("/assets/%s is served byte for byte as %s, cached five minutes", async (name, type) => {
      const res = await fetch(`${stack.url}/assets/${name}`);
      expect(res.status).toBe(200);
      expect(res.headers.get("Content-Type")).toBe(type);
      expect(res.headers.get("Cache-Control")).toBe("public, max-age=300");
      expect(res.headers.get("Content-Security-Policy")).toBe(API_CSP);
      for (const [k, v] of Object.entries(SECURITY_HEADERS)) expect(res.headers.get(k)).toBe(v);
      expect(Buffer.from(await res.arrayBuffer()).equals(readFileSync(join(ASSET_DIR, name)))).toBe(true);
    });

    test("/favicon.ico is the same icon", async () => {
      const res = await fetch(`${stack.url}/favicon.ico`);
      expect(res.status).toBe(200);
      expect(res.headers.get("Content-Type")).toBe("image/x-icon");
      expect(res.headers.get("Cache-Control")).toBe("public, max-age=300");
      expect(Buffer.from(await res.arrayBuffer()).equals(readFileSync(join(ASSET_DIR, "favicon.ico")))).toBe(true);
    });

    test.each(["nope.js", "STYLE.CSS", "style.css.map", "favicon.png", "index.html", "style"])("/assets/%s is a JSON 404", async (name) => {
      const res = await fetch(`${stack.url}/assets/${name}`);
      expect(res.headers.get("Cache-Control")).toBe("no-store");
      await expectJsonError(res, 404, "not_found", "No such asset.");
    });

    test("an asset answers only GET", async () => {
      const res = await fetch(`${stack.url}/assets/style.css`, { method: "POST" });
      expect(res.headers.get("Allow")).toBe("GET");
      await expectJsonError(res, 405, "method_not_allowed", "Use GET.");
    });
  });

  // ------------------------------------------------------------ form CSRF

  describe("form CSRF", () => {
    test("GET /login sets a session-length __Host-csrf cookie, Strict, and echoes it in the form", async () => {
      const b = stack.browser();
      const res = await b.get("/login");
      const c = parseCookie(setCookieOf(res, "csrf"));
      expect(c.value).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(c.attrs).toEqual(cookieAttrs("Strict"));
      const html = await res.text();
      expectTag(html, "input", { type: "hidden", name: "csrf", value: c.value });
    });

    test("a valid cookie already present is not set again, and is the form's token", async () => {
      const b = stack.browser();
      const token = await b.formCsrf();
      const res = await b.get("/login");
      expect(setCookieOf(res, "csrf")).toBeUndefined();
      expectTag(await res.text(), "input", { name: "csrf", value: token });
      // Nor on a refused sign-in's form.
      const again = await b.form("/login", { login: uname("nobody"), password: "wrong-pw-1" });
      expect(again.status).toBe(401);
      expect(setCookieOf(again, "csrf")).toBeUndefined();
      expectTag(await again.text(), "input", { name: "csrf", value: token });
    });

    test.each([["short"], ["a".repeat(44)], ["a".repeat(42) + "!"]])("a malformed cookie (%s) is replaced", async (bad) => {
      const b = stack.browser();
      b.cookies.set("__Host-csrf", bad);
      const res = await b.get("/login");
      const c = parseCookie(setCookieOf(res, "csrf"));
      expect(c.value).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(c.value).not.toBe(bad);
      expectTag(await res.text(), "input", { name: "csrf", value: c.value });
    });

    test.each([
      ["no cookie", { cookie: null, field: "x".repeat(43) }],
      ["no field", { cookie: "c".repeat(43), field: null }],
      ["neither", { cookie: null, field: null }],
      ["an empty field and cookie", { cookie: "", field: "" }],
      ["a mismatch", { cookie: "c".repeat(43), field: "d".repeat(43) }],
      ["a field one character short", { cookie: "c".repeat(43), field: "c".repeat(42) }],
    ])("a sign-in with %s is refused with a 403 page, before any counting", async (_, { cookie, field }) => {
      const user = await stack.user({ username: uname("csrf") });
      const b = stack.browser();
      if (cookie !== null) b.cookies.set("__Host-csrf", cookie);
      const fields: Record<string, string> = { login: user.username, password: PW };
      if (field !== null) fields.csrf = field;
      const res = await b.form("/login", fields, { csrf: null });
      await expectWentWrong(res, 403, FORM_EXPIRED);
      expect(b.cookies.has("__Host-auth")).toBe(false);
      expect(await throttleHits(`ip:${b.ip}:login`)).toBeNull();
    });

    test("the double submit compares the two values only", async () => {
      const user = await stack.user({ username: uname("csrfv") });
      const b = stack.browser();
      b.cookies.set("__Host-csrf", "abc");
      const res = await b.form("/login", { login: user.username, password: PW }, { csrf: "abc" });
      expect(res.status).toBe(303);
    });

    test.each([
      ["missing", null, {}],
      ["another site's", "https://evil.example.com", {}],
      ["the issuer's with a trailing slash", "TRAILING", {}],
      ["null alone", "null", {}],
      ["null, cross-site", "null", { "Sec-Fetch-Site": "cross-site" }],
      ["null, same-site", "null", { "Sec-Fetch-Site": "same-site" }],
      ["another origin, with Sec-Fetch-Site: same-origin", "https://evil.example.com", { "Sec-Fetch-Site": "same-origin" }],
    ])("Origin %s is refused with a 403 page", async (_, origin, headers) => {
      const user = await stack.user({ username: uname("orig") });
      const b = stack.browser();
      const res = await b.form("/login", { login: user.username, password: PW }, { origin: origin === "TRAILING" ? `${stack.issuer}/` : origin, headers });
      await expectWentWrong(res, 403, NOT_FROM_SITE);
      expect(b.cookies.has("__Host-auth")).toBe(false);
    });

    test("Origin: null with Sec-Fetch-Site: same-origin counts as the issuer's", async () => {
      const user = await stack.user({ username: uname("onull") });
      const b = stack.browser();
      const res = await b.form("/login", { login: user.username, password: PW }, { origin: "null", headers: { "Sec-Fetch-Site": "same-origin" } });
      expect(res.status).toBe(303);
      expect(b.cookies.has("__Host-auth")).toBe(true);
    });

    test("Origin is checked before the token", async () => {
      const b = stack.browser();
      await expectWentWrong(await b.form("/login", { login: "x", password: "y" }, { origin: null, csrf: null }), 403, NOT_FROM_SITE);
    });

    test.each([
      ["application/json", 415],
      ["text/plain", 415],
      ["multipart/form-data; boundary=x", 415],
      ["", 415],
      ["application/x-www-form-urlencoded; charset=utf-8", 303],
      ["Application/X-WWW-Form-Urlencoded", 303],
    ])("Content-Type %p", async (type, status) => {
      const user = await stack.user({ username: uname("ctype") });
      const b = stack.browser();
      const csrf = await b.formCsrf();
      const headers: Record<string, string> = {};
      if (type) headers["Content-Type"] = type;
      const res = await b.request("/login", { method: "POST", headers, body: new URLSearchParams({ login: user.username, password: PW, csrf }).toString() });
      if (status === 415) await expectWentWrong(res, 415, "Send application/x-www-form-urlencoded.");
      else expect(res.status).toBe(303);
    });

    test("the content type is checked before Origin", async () => {
      const b = stack.browser();
      const res = await b.request("/login", { method: "POST", origin: null, headers: { "Content-Type": "application/json" }, body: "{}" });
      await expectWentWrong(res, 415, "Send application/x-www-form-urlencoded.");
    });

    test("the second-factor form has the same checks", async () => {
      const b = stack.browser();
      await expectWentWrong(await b.form("/login/second-factor", { code: "123456" }, { origin: "https://evil.example.com" }), 403, NOT_FROM_SITE);
      await expectWentWrong(await b.form("/login/second-factor", { code: "123456" }, { csrf: "z".repeat(43) }), 403, FORM_EXPIRED);
      const res = await b.request("/login/second-factor", { method: "POST", headers: { "Content-Type": "text/plain" }, body: "code=1" });
      await expectWentWrong(res, 415, "Send application/x-www-form-urlencoded.");
    });
  });

  // ------------------------------------------------------------- GET /login

  describe("GET /login", () => {
    const notices = async (query: string) => {
      const html = await expectPage(await stack.browser().get(`/login${query}`), 200, "Sign in");
      return { html, notices: flashes(html, "notice"), errors: flashes(html, "error") };
    };

    test.each([
      ["", []],
      ["?second_factor=wiki", ["Your role on wiki needs a second factor: sign in with your password and authenticator code, or with a passkey."]],
      ["?reauth=1", ["Sign in again to continue."]],
      ["?reauth=", []],
      ["?notice=activated", ["Your password is set. Sign in."]],
      ["?notice=reset", ["Your password is changed. Sign in."]],
      ["?notice=other", []],
      ["?notice=", []],
      ["?second_factor=", []],
      ["?second_factor=tasks&reauth=1&notice=reset", ["Your role on tasks needs a second factor: sign in with your password and authenticator code, or with a passkey."]],
      ["?reauth=yes&notice=activated", ["Sign in again to continue."]],
    ])("notice for %p", async (query, expected) => {
      const { notices: n, errors } = await notices(query);
      expect(n).toEqual(expected);
      expect(errors).toEqual([]);
    });

    test("second_factor is escaped and cut to 64 characters", async () => {
      const service = `<b>"x'&${"s".repeat(80)}`;
      const { html, notices: n } = await notices(`?${new URLSearchParams({ second_factor: service })}`);
      expect(n).toEqual([`Your role on ${service.slice(0, 64)} needs a second factor: sign in with your password and authenticator code, or with a passkey.`]);
      expect(html).not.toContain("<b>");
    });

    test("login_hint is prefilled, escaped, and cut to 254 characters", async () => {
      const hint = `"><script>alert(1)</script>${"h".repeat(300)}`;
      const { html } = await notices(`?${new URLSearchParams({ login_hint: hint })}`);
      expectTag(html, "input", { name: "login", value: hint.slice(0, 254) });
      expect(html).not.toContain("<script>alert");
      const plain = await notices("?login_hint=alice%40example.com");
      expectTag(plain.html, "input", { name: "login", value: "alice@example.com" });
    });

    test("the sign-up callout appears when a service is open, carrying return_to", async () => {
      const { html } = await notices(`?${new URLSearchParams({ return_to: "/admin?x=1" })}`);
      const link = expectTag(html, "a", { href: `/signup?${new URLSearchParams({ return_to: "/admin?x=1" })}` });
      expect(textOf(link.inner)).toBe("Create an account");
      expect(tagsOf(html, "p").some((p) => p.attrs.class === "callout" && textOf(p.inner) === "New here? Create an account")).toBe(true);
    });

    test.each(REFUSED_RETURN_TO)("return_to %s falls back to /account", async (_, value) => {
      const q = value === null ? "" : `?${new URLSearchParams({ return_to: value })}`;
      const { html } = await notices(q);
      expectTag(html, "input", { name: "return_to", value: "/account" });
      expectTag(html, "button", { id: "passkey-signin", "data-return-to": "/account" });
    });

    test.each([...ACCEPTED_RETURN_TO, ["markup", `/x?a="<b>'`]] as [string, string][])("return_to %s is kept", async (_, value) => {
      const { html } = await notices(`?${new URLSearchParams({ return_to: value })}`);
      expectTag(html, "input", { name: "return_to", value });
      expectTag(html, "button", { id: "passkey-signin", "data-return-to": value });
      expect(html).not.toContain("<b>");
    });
  });

  // -------------------------------------------------------- password sign-in

  describe("password sign-in", () => {
    test("a header's bytes are read one character each, as the Fetch standard reads them", async () => {
      const user = await stack.user({ username: uname("ua") });
      const b = stack.browser();
      // "Zoë" sent as UTF-8: the bytes C3 AB are two characters.
      const ua = "Zo\u00c3\u00ab-Browser/1.0 \u00ff";
      const res = await b.request("/login", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": ua },
        body: new URLSearchParams({ login: user.username, password: PW, return_to: "/account", csrf: await b.formCsrf() }).toString(),
      });
      expect(res.status).toBe(303);
      expect((await sessionByToken(parseCookie(setCookieOf(res, "auth")).value))?.user_agent).toBe(ua);
    });

    test("by username: the session cookie, the row, the device cookie, the audit row, the redirect", async () => {
      const user = await stack.user({ username: uname("pw") });
      const b = stack.browser();
      const ua = `Example-Browser/1.0 ${"u".repeat(600)}`;
      const res = await b.request("/login", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": ua },
        body: new URLSearchParams({ login: user.username, password: PW, return_to: "/account", csrf: await b.formCsrf() }).toString(),
      });
      expect(res.status).toBe(303);
      expect(res.headers.get("Location")).toBe("/account");
      const auth = parseCookie(setCookieOf(res, "auth"));
      expect(auth.value).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(auth.attrs).toEqual(cookieAttrs("Lax", 30 * 24 * 60 * 60));
      expectCleared(res, "pending");
      const device = parseCookie(setCookieOf(res, "device"));
      expect(device.value).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(device.attrs).toEqual(cookieAttrs("Lax", 400 * 24 * 60 * 60));

      const s = await sessionByToken(auth.value);
      expect(s).toBeDefined();
      expect(s!.id).toMatch(/^ses_[0-9a-hjkmnp-tv-z]{26}$/);
      expect(s!.user_id).toBe(user.id);
      expect(s!.amr).toEqual(["pwd"]);
      expect(s!.ip).toBe(b.ip);
      expect(s!.user_agent).toBe(ua.slice(0, 512));
      const now = Date.now();
      expect(Math.abs(s!.auth_time.getTime() - now)).toBeLessThan(60_000);
      expect(Math.abs(s!.expires_at.getTime() - (now + 7 * 86400_000))).toBeLessThan(60_000);
      expect(Math.abs(s!.ends_at.getTime() - (now + 30 * 86400_000))).toBeLessThan(60_000);

      const ok = await auditFor("login.ok", user.id);
      expect(ok).toHaveLength(1);
      expect(ok[0]!.actor).toBe(user.id);
      expect(ok[0]!.ip).toBe(b.ip);
      expect(ok[0]!.detail).toEqual({ method: "password", amr: ["pwd"], device: deviceIdOf(device.value) });
      // The page works with it.
      expect((await b.get("/account")).status).toBe(200);
    });

    test.each([
      ["upper-case username", (u: TestUser) => u.username.toUpperCase()],
      ["padded username", (u: TestUser) => `  ${u.username}\t`],
      ["email", (u: TestUser) => u.email!],
      ["email in another case", (u: TestUser) => u.email!.toUpperCase()],
      ["padded email", (u: TestUser) => ` ${u.email} `],
    ])("by %s", async (_, login) => {
      const user = await stack.user({ username: uname("by"), email: `${uname("Mixed")}@Example.COM` });
      const b = stack.browser();
      const res = await b.form("/login", { login: login(user), password: PW });
      expect(res.status).toBe(303);
      expect((await sessionByToken(b.cookies.get("__Host-auth")))?.user_id).toBe(user.id);
    });

    test("the password is not trimmed", async () => {
      const user = await stack.user({ username: uname("trim") });
      const b = stack.browser();
      expect((await b.form("/login", { login: user.username, password: ` ${PW}` })).status).toBe(401);
    });

    test("a wrong password and an unknown user get the same 401 answer; each is audited and counted", async () => {
      const user = await stack.user({ username: uname("same") });
      const b = stack.browser();
      const wrong = await b.form("/login", { login: user.username, password: "s3cret-pw", return_to: "/admin" });
      const unknownName = uname("ghost");
      const unknown = await b.form("/login", { login: unknownName, password: "s3cret-pw", return_to: "/admin" });
      expect(wrong.status).toBe(401);
      expect(unknown.status).toBe(401);
      const wrongHtml = await expectPage(wrong, 401, "Sign in");
      const unknownHtml = await expectPage(unknown, 401, "Sign in");
      expect(flashes(wrongHtml, "error")).toEqual([WRONG_LOGIN]);
      expect(flashes(unknownHtml, "error")).toEqual([WRONG_LOGIN]);
      expect(wrongHtml.replaceAll(user.username, "LOGIN")).toBe(unknownHtml.replaceAll(unknownName, "LOGIN"));
      expectTag(wrongHtml, "input", { name: "login", value: user.username });
      expectTag(wrongHtml, "input", { name: "return_to", value: "/admin" });
      expect(wrongHtml).not.toContain("s3cret-pw");
      expect(b.cookies.has("__Host-auth")).toBe(false);
      expect(setCookieOf(wrong, "device")).toBeUndefined();

      const fails = await auditFor("login.fail", user.id, b.ip);
      expect(fails).toHaveLength(1);
      expect(fails[0]!.actor).toBeNull();
      expect(fails[0]!.detail).toEqual({ method: "password" });
      const anon = await auditFor("login.fail", null, b.ip);
      expect(anon).toHaveLength(1);
      expect(anon[0]!.detail).toEqual({ method: "password" });
      expect(await throttleHits(`login:user:${user.id}`)).toBe(1);
      expect(await throttleHits(`login:name:${unknownName}`)).toBe(1);
    });

    test("the typed login is re-shown trimmed and cut to 254 characters", async () => {
      const b = stack.browser();
      const typed = `  ${"l".repeat(300)}  `;
      const res = await b.form("/login", { login: typed, password: "wrong-pw-1" });
      const html = await expectPage(res, 401, "Sign in");
      expectTag(html, "input", { name: "login", value: "l".repeat(254) });
    });

    test("an unknown account is counted under its typed name, lower-cased", async () => {
      const b = stack.browser();
      const name = uname("ghost");
      await (await b.form("/login", { login: name.toUpperCase(), password: "wrong-pw-1" })).body?.cancel();
      await (await b.form("/login", { login: ` ${name} `, password: "wrong-pw-1" })).body?.cancel();
      expect(await throttleHits(`login:name:${name}`)).toBe(2);
      const email = `${uname("nobody")}@example.com`;
      await (await b.form("/login", { login: email.toUpperCase(), password: "wrong-pw-1" })).body?.cancel();
      expect(await throttleHits(`login:name:${email}`)).toBe(1);
    });

    test("a login with a NUL is an unknown account, counted with the NUL kept as U+FFFD", async () => {
      const b = stack.browser();
      const name = uname("nul");
      const html = await expectPage(await b.form("/login", { login: `${name}\u0000x`, password: "wrong-pw-1" }), 401, "Sign in");
      expect(html).toContain(WRONG_LOGIN);
      expect(await throttleHits(`login:name:${name}\uFFFDx`)).toBe(1);
      expect(await auditFor("login.fail", null, b.ip)).toHaveLength(1);
    });

    test("a missing login or password is a wrong one", async () => {
      const user = await stack.user({ username: uname("miss") });
      const b = stack.browser();
      expect(flashes(await expectPage(await b.form("/login", { login: user.username }), 401, "Sign in"), "error")).toEqual([WRONG_LOGIN]);
      expect(flashes(await expectPage(await b.form("/login", { password: PW }), 401, "Sign in"), "error")).toEqual([WRONG_LOGIN]);
      expect(flashes(await expectPage(await b.form("/login", { login: "", password: "" }), 401, "Sign in"), "error")).toEqual([WRONG_LOGIN]);
    });

    test("a disabled user with the right password: 403, audited with the reason, not counted", async () => {
      const user = await stack.user({ username: uname("dis"), disabled: true });
      const b = stack.browser();
      const res = await b.form("/login", { login: user.username, password: PW });
      const html = await expectPage(res, 403, "Sign in");
      expect(flashes(html, "error")).toEqual(["This account is disabled."]);
      expect(b.cookies.has("__Host-auth")).toBe(false);
      const fails = await auditFor("login.fail", user.id);
      expect(fails).toHaveLength(1);
      expect(fails[0]!.detail).toEqual({ method: "password", reason: "disabled" });
      expect(await throttleHits(`login:user:${user.id}`)).toBeNull();
      // With a wrong password it is a wrong password.
      const wrong = await b.form("/login", { login: user.username, password: "wrong-pw-1" });
      expect(flashes(await expectPage(wrong, 401, "Sign in"), "error")).toEqual([WRONG_LOGIN]);
    });

    test("a bot can't sign in at the pages, even with its password", async () => {
      const owner = await stack.user({ username: uname("owner") });
      const bot = await stack.user({ username: uname("bot"), kind: "bot", ownerId: owner.id, password: PW });
      const b = stack.browser();
      const res = await b.form("/login", { login: bot.username, password: PW });
      expect(flashes(await expectPage(res, 401, "Sign in"), "error")).toEqual([WRONG_LOGIN]);
      expect((await auditFor("login.fail", bot.id))[0]?.detail).toEqual({ method: "password" });
      expect(await throttleHits(`login:user:${bot.id}`)).toBe(1);
    });

    test("an account without a password can't sign in with one", async () => {
      const user = await stack.user({ username: uname("nopw"), password: null });
      const b = stack.browser();
      for (const password of ["", PW, "anything"]) {
        const res = await b.form("/login", { login: user.username, password });
        expect(flashes(await expectPage(res, 401, "Sign in"), "error")).toEqual([WRONG_LOGIN]);
      }
      expect(await throttleHits(`login:user:${user.id}`)).toBe(3);
    });

    test("a success clears the account's failure counter", async () => {
      const user = await stack.user({ username: uname("clr") });
      await stack.db`INSERT INTO throttle (key, window_start, hits) VALUES (${`login:user:${user.id}`}, now(), 4)`;
      const b = stack.browser();
      expect((await b.form("/login", { login: user.username, password: PW })).status).toBe(303);
      expect(await throttleHits(`login:user:${user.id}`)).toBeNull();
    });

    test("the same user signing in again keeps the session id, with a new token", async () => {
      const user = await stack.user({ username: uname("again") });
      const b = await stack.session(user, { amr: ["pwd"], authAge: 3600 });
      const first = b.sessionId!;
      const oldToken = b.cookies.get("__Host-auth")!;
      await signInTo(stack, b, "tasks");
      const res = await b.form("/login", { login: user.username, password: PW });
      expect(res.status).toBe(303);
      const token = b.cookies.get("__Host-auth")!;
      expect(token).not.toBe(oldToken);
      const s = await sessionByToken(token);
      expect(s?.id).toBe(first);
      expect(Math.abs(s!.auth_time.getTime() - Date.now())).toBeLessThan(60_000);
      expect(s!.ip).toBe(b.ip);
      expect(await sessionByToken(oldToken)).toBeUndefined();
      expect((await stack.outbox("tasks")).filter((e) => e.type === "session.ended" && e.payload.sid === first)).toEqual([]);
    });

    test("another user's sign-in in the same browser ends the previous session, and its apps are told", async () => {
      const alice = await stack.user({ username: uname("alice") });
      const bob = await stack.user({ username: uname("bob") });
      const b = await stack.session(alice);
      const aliceSid = b.sessionId!;
      const { tokens } = await signInTo(stack, b, "tasks");
      expect(typeof tokens.refresh_token).toBe("string");
      const res = await b.form("/login", { login: bob.username, password: PW });
      expect(res.status).toBe(303);
      const s = await sessionByToken(b.cookies.get("__Host-auth"));
      expect(s?.user_id).toBe(bob.id);
      expect(s?.id).not.toBe(aliceSid);
      expect(await stack.db`SELECT 1 FROM sessions WHERE id = ${aliceSid}`).toHaveLength(0);
      const queued = (await stack.outbox("tasks")).filter((e) => e.type === "session.ended" && e.payload.sid === aliceSid);
      expect(queued).toHaveLength(1);
      const event = await stack.http.waitForEvent("tasks", "session.ended", (e) => e.payload.sid === aliceSid);
      expect(event.payload).toEqual({ sid: aliceSid });
      // Alice's refresh token went with her session.
      const refresh = await backChannel(stack, "/oauth/token", { grant_type: "refresh_token", refresh_token: tokens.refresh_token! }, stack.basic("tasks"));
      expect(refresh.status).toBe(400);
      expect(((await refresh.json()) as { error: string }).error).toBe("invalid_grant");
    });

    test("a session cookie of a session that no longer counts starts a new session", async () => {
      const user = await stack.user({ username: uname("stale") });
      const b = await stack.session(user, { expiresIn: "-1 second" });
      const old = b.sessionId!;
      expect((await b.form("/login", { login: user.username, password: PW })).status).toBe(303);
      expect((await sessionByToken(b.cookies.get("__Host-auth")))?.id).not.toBe(old);
    });

    test("the device cookie: kept when valid, replaced when not; the audit row names the device", async () => {
      const user = await stack.user({ username: uname("dev") });
      const b = stack.browser();
      const device = randomToken();
      b.cookies.set("__Host-device", device);
      const res = await b.form("/login", { login: user.username, password: PW });
      expect(parseCookie(setCookieOf(res, "device")).value).toBe(device);
      expect((await auditFor("login.ok", user.id)).at(-1)!.detail.device).toBe(deviceIdOf(device));

      const c = stack.browser();
      c.cookies.set("__Host-device", "not-a-device");
      const res2 = await c.form("/login", { login: user.username, password: PW });
      const fresh = parseCookie(setCookieOf(res2, "device")).value;
      expect(fresh).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(fresh).not.toBe("not-a-device");
    });

    test("new-device notices: none at the first sign-in, none from a known device, one from a new device", async () => {
      const user = await stack.user({ username: uname("notice") });
      const a = stack.browser();
      expect((await a.form("/login", { login: user.username, password: PW })).status).toBe(303);
      expect((await a.form("/login", { login: user.username, password: PW })).status).toBe(303);
      const b = stack.browser();
      const ua = `Example-Browser/2.0 ${"b".repeat(300)}`;
      const res = await b.request("/login", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": ua },
        body: new URLSearchParams({ login: user.username, password: PW, csrf: await b.formCsrf() }).toString(),
      });
      expect(res.status).toBe(303);
      const mail = await stack.smtp.waitFor(user.email!, (m) => m.subject === "Security notice: a sign-in from a new device");
      expect(mail.text).toBe(
        [
          `On the account "${user.username}": a sign-in from a new device.`,
          "",
          `Browser: ${ua.slice(0, 200)}`,
          `Address: ${b.ip}`,
          "",
          "If this wasn't you, reset your password and contact an administrator.",
        ].join("\n"),
      );
      // The device from the first two sign-ins, signing in again, is known.
      expect((await a.form("/login", { login: user.username, password: PW })).status).toBe(303);
      const c = stack.browser();
      expect((await c.form("/login", { login: user.username, password: PW })).status).toBe(303);
      await stack.smtp.waitFor(user.email!, (m) => m.subject === "Security notice: a sign-in from a new device" && m.text.includes(`Address: ${c.ip}`));
      expect(stack.smtp.to(user.email!).map((m) => m.subject)).toEqual(["Security notice: a sign-in from a new device", "Security notice: a sign-in from a new device"]);
    });

    test("an account without an email gets no notice, and still signs in", async () => {
      const user = await stack.user({ username: uname("nomail"), email: null });
      expect((await stack.browser().form("/login", { login: user.username, password: PW })).status).toBe(303);
      expect((await stack.browser().form("/login", { login: user.username, password: PW })).status).toBe(303);
      expect(await auditFor("login.ok", user.id)).toHaveLength(2);
    });

    test.each(REFUSED_RETURN_TO)("return_to %s leads to /account", async (_, value) => {
      const user = await stack.user({ username: uname("rt") });
      const fields: Record<string, string> = { login: user.username, password: PW };
      if (value !== null) fields.return_to = value;
      const res = await stack.browser().form("/login", fields);
      expect(res.status).toBe(303);
      expect(res.headers.get("Location")).toBe("/account");
    });

    test.each(ACCEPTED_RETURN_TO)("return_to %s is followed", async (_, value) => {
      const user = await stack.user({ username: uname("rt") });
      const res = await stack.browser().form("/login", { login: user.username, password: PW, return_to: value });
      expect(res.status).toBe(303);
      expect(res.headers.get("Location")).toBe(value);
    });
  });

  // ------------------------------------------------------------ throttling

  describe("throttling", () => {
    test("per IP: 30 attempts per 15 minutes, successes included; then a 429 page with Retry-After", async () => {
      const user = await stack.user({ username: uname("ipl") });
      const b = stack.browser();
      const key = `ip:${b.ip}:login`;
      expect((await b.form("/login", { login: user.username, password: PW })).status).toBe(303);
      expect(await throttleHits(key)).toBe(1);
      await stack.db`UPDATE throttle SET hits = 29 WHERE key = ${key}`;
      expect((await b.form("/login", { login: user.username, password: "wrong-pw-1" })).status).toBe(401);
      const before = (await stack.audit("login.fail")).length;
      const res = await b.form("/login", { login: user.username, password: PW });
      const retry = Number(res.headers.get("Retry-After"));
      expect(retry).toBeGreaterThan(840);
      expect(retry).toBeLessThanOrEqual(900);
      const html = await expectPage(res, 429, "Sign in");
      expect(flashes(html, "error")).toEqual(["Too many sign-in attempts from your network. Try again in 15 minutes."]);
      expectTag(html, "input", { name: "login", value: user.username });
      expect(setCookieOf(res, "auth")).toBeUndefined();
      // Neither audited nor counted against the account.
      expect((await stack.audit("login.fail")).length).toBe(before);
      expect(await throttleHits(`login:user:${user.id}`)).toBe(1);
    });

    test("per IP: the minutes in the message round up", async () => {
      const b = stack.browser();
      const key = `ip:${b.ip}:login`;
      await stack.db`INSERT INTO throttle (key, window_start, hits) VALUES (${key}, now() - interval '14 minutes 50 seconds', 30)`;
      const res = await b.form("/login", { login: "x", password: "y" });
      const retry = Number(res.headers.get("Retry-After"));
      expect(retry).toBeGreaterThan(0);
      expect(retry).toBeLessThanOrEqual(10);
      expect(flashes(await expectPage(res, 429, "Sign in"), "error")).toEqual(["Too many sign-in attempts from your network. Try again in a minute."]);
      await stack.db`UPDATE throttle SET window_start = now() - interval '12 minutes' WHERE key = ${key}`;
      const res2 = await b.form("/login", { login: "x", password: "y" });
      expect(Number(res2.headers.get("Retry-After"))).toBeGreaterThan(170);
      expect(flashes(await expectPage(res2, 429, "Sign in"), "error")).toEqual(["Too many sign-in attempts from your network. Try again in 3 minutes."]);
    });

    test("per IP: a window that has passed starts again", async () => {
      const user = await stack.user({ username: uname("ipw") });
      const b = stack.browser();
      const key = `ip:${b.ip}:login`;
      await stack.db`INSERT INTO throttle (key, window_start, hits) VALUES (${key}, now() - interval '901 seconds', 30)`;
      expect((await b.form("/login", { login: user.username, password: PW })).status).toBe(303);
      expect(await throttleHits(key)).toBe(1);
    });

    test("per IP: each browser address is counted apart", async () => {
      const user = await stack.user({ username: uname("ipa") });
      const blocked = stack.browser();
      await stack.db`INSERT INTO throttle (key, window_start, hits) VALUES (${`ip:${blocked.ip}:login`}, now(), 30)`;
      expect((await blocked.form("/login", { login: user.username, password: PW })).status).toBe(429);
      expect((await stack.browser().form("/login", { login: user.username, password: PW })).status).toBe(303);
    });

    test("per account: five failures, then a wait; the right password waits too and nothing more is counted", async () => {
      const user = await stack.user({ username: uname("acct") });
      const b = stack.browser();
      for (let i = 0; i < 5; i++) expect((await b.form("/login", { login: user.username, password: `wrong-pw-${i}` })).status).toBe(401);
      expect(await throttleHits(`login:user:${user.id}`)).toBe(5);
      const before = (await auditFor("login.fail", user.id)).length;
      const res = await b.form("/login", { login: user.username, password: PW });
      const retry = Number(res.headers.get("Retry-After"));
      expect(retry).toBeGreaterThan(50);
      expect(retry).toBeLessThanOrEqual(60);
      const html = await expectPage(res, 429, "Sign in");
      expect(flashes(html, "error")).toEqual(["Too many failed attempts. Try again in a minute."]);
      expect(b.cookies.has("__Host-auth")).toBe(false);
      expect(await throttleHits(`login:user:${user.id}`)).toBe(5);
      expect((await auditFor("login.fail", user.id)).length).toBe(before);
      // Another address waits as well: the count is the account's.
      expect((await stack.browser().form("/login", { login: user.email!, password: PW })).status).toBe(429);
    });

    test.each([
      [5, 60, "a minute"],
      [6, 120, "2 minutes"],
      [7, 240, "4 minutes"],
      [8, 480, "8 minutes"],
      [9, 900, "15 minutes"],
      [30, 900, "15 minutes"],
    ])("per account: %i failures wait %i s", async (hits, wait, words) => {
      const user = await stack.user({ username: uname("wait") });
      await stack.db`INSERT INTO throttle (key, window_start, hits) VALUES (${`login:user:${user.id}`}, now(), ${hits})`;
      const res = await stack.browser().form("/login", { login: user.username, password: PW });
      const retry = Number(res.headers.get("Retry-After"));
      expect(retry).toBeGreaterThan(wait - 10);
      expect(retry).toBeLessThanOrEqual(wait);
      expect(flashes(await expectPage(res, 429, "Sign in"), "error")).toEqual([`Too many failed attempts. Try again in ${words}.`]);
    });

    test("per account: four failures don't wait", async () => {
      const user = await stack.user({ username: uname("four") });
      await stack.db`INSERT INTO throttle (key, window_start, hits) VALUES (${`login:user:${user.id}`}, now(), 4)`;
      expect((await stack.browser().form("/login", { login: user.username, password: PW })).status).toBe(303);
    });

    test("per account: once the wait has passed one attempt goes through; a failure then waits twice as long", async () => {
      const user = await stack.user({ username: uname("pass") });
      const key = `login:user:${user.id}`;
      await stack.db`INSERT INTO throttle (key, window_start, hits) VALUES (${key}, now() - interval '61 seconds', 5)`;
      const b = stack.browser();
      expect((await b.form("/login", { login: user.username, password: "wrong-pw-1" })).status).toBe(401);
      expect(await throttleHits(key)).toBe(6);
      const res = await b.form("/login", { login: user.username, password: PW });
      expect(res.status).toBe(429);
      expect(Number(res.headers.get("Retry-After"))).toBeGreaterThan(110);
      await stack.db`UPDATE throttle SET window_start = now() - interval '121 seconds' WHERE key = ${key}`;
      expect((await b.form("/login", { login: user.username, password: PW })).status).toBe(303);
      expect(await throttleHits(key)).toBeNull();
    });

    test("per account: an unknown account waits alike, under its typed name", async () => {
      const name = uname("ghost");
      await stack.db`INSERT INTO throttle (key, window_start, hits) VALUES (${`login:name:${name}`}, now(), 6)`;
      const res = await stack.browser().form("/login", { login: name.toUpperCase(), password: "wrong-pw-1" });
      expect(Number(res.headers.get("Retry-After"))).toBeGreaterThan(110);
      expect(flashes(await expectPage(res, 429, "Sign in"), "error")).toEqual(["Too many failed attempts. Try again in 2 minutes."]);
    });

    test("per account: a known account's count is keyed by its id, not the name typed", async () => {
      const user = await stack.user({ username: uname("keyed") });
      await stack.db`INSERT INTO throttle (key, window_start, hits) VALUES (${`login:name:${user.username}`}, now(), 9)`;
      expect((await stack.browser().form("/login", { login: user.username, password: PW })).status).toBe(303);
    });
  });

  // ------------------------------------------------------------------ TOTP

  describe("TOTP", () => {
    // Waits, if need be, for a step with at least five seconds left, so a code
    // made for a neighbouring step is still that step when it arrives.
    const steadyStep = () => waitForClock(() => (Date.now() / 1000) % 30 < 25);

    const toSecondFactor = async (user: TestUser, returnTo?: string): Promise<{ b: Browser; res: Response }> => {
      const b = stack.browser();
      const fields: Record<string, string> = { login: user.username, password: PW };
      if (returnTo !== undefined) fields.return_to = returnTo;
      const res = await b.form("/login", fields);
      await res.body?.cancel();
      return { b, res };
    };

    test("the password step redirects to the second factor with a sealed pending cookie, and no session", async () => {
      const user = await stack.user({ username: uname("totp"), totp: true });
      const { b, res } = await toSecondFactor(user, "/admin?x=1");
      expect(res.status).toBe(303);
      expect(res.headers.get("Location")).toBe(`/login/second-factor?${new URLSearchParams({ return_to: "/admin?x=1" })}`);
      expect(setCookieOf(res, "auth")).toBeUndefined();
      expect(setCookieOf(res, "device")).toBeUndefined();
      const pending = parseCookie(setCookieOf(res, "pending"));
      expect(pending.attrs).toEqual(cookieAttrs("Lax", 300));
      const opened = stack.crypt.open<{ u: string; id: string; r: string }>("pending", pending.value);
      expect(opened.v.u).toBe(user.id);
      expect(opened.v.r).toBe("/admin?x=1");
      expect(opened.v.id).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(Math.abs(opened.exp - (Date.now() + 300_000))).toBeLessThan(60_000);
      expect(b.cookies.has("__Host-auth")).toBe(false);
      expect(await auditFor("login.ok", user.id)).toHaveLength(0);
    });

    test("GET with a pending cookie shows the form, leading to the sealed return_to", async () => {
      const user = await stack.user({ username: uname("totpg"), totp: true });
      const { b } = await toSecondFactor(user, "/account?resume=1#keys");
      const res = await b.get(`/login/second-factor?${new URLSearchParams({ return_to: "/elsewhere" })}`);
      const html = await expectPage(res, 200, "Second factor");
      expectTag(html, "form", { method: "post", action: "/login/second-factor" });
      expectTag(html, "input", { type: "hidden", name: "return_to", value: "/account?resume=1#keys" });
      expectTag(html, "input", { type: "hidden", name: "csrf", value: b.cookies.get("__Host-csrf")! });
      expectTag(html, "input", { name: "code", autocomplete: "one-time-code", maxlength: "40" });
      expect(textOf(expectTag(html, "a", { href: `/login?${new URLSearchParams({ return_to: "/account?resume=1#keys" })}` }).inner)).toBe("Start over");
      expect(flashes(html, "error")).toEqual([]);
    });

    test.each([
      ["no", null],
      ["an expired", "EXPIRED"],
      ["a tampered", "TAMPERED"],
      ["a garbage", "not-sealed"],
      ["another purpose's", "PURPOSE"],
    ])("GET with %s pending cookie starts over, keeping return_to", async (_, kind) => {
      const user = await stack.user({ username: uname("pend") });
      const b = stack.browser();
      const value = { u: user.id, id: randomToken(), r: "/account" };
      if (kind === "EXPIRED") b.cookies.set("__Host-pending", stack.crypt.seal("pending", value, -1));
      else if (kind === "TAMPERED") {
        const good = stack.crypt.seal("pending", value, 300);
        const i = 20;
        b.cookies.set("__Host-pending", good.slice(0, i) + (good[i] === "A" ? "B" : "A") + good.slice(i + 1));
      } else if (kind === "PURPOSE") b.cookies.set("__Host-pending", stack.crypt.seal("passkey-auth", value, 300));
      else if (kind !== null) b.cookies.set("__Host-pending", kind);
      const res = await b.get(`/login/second-factor?${new URLSearchParams({ return_to: "/admin" })}`);
      expect(res.status).toBe(303);
      expect(res.headers.get("Location")).toBe("/login?return_to=%2Fadmin");
      // And a refused return_to is not carried.
      const evil = await b.get(`/login/second-factor?${new URLSearchParams({ return_to: "//evil.example.com/" })}`);
      expect(evil.headers.get("Location")).toBe("/login?return_to=%2Faccount");
      // A POST without a usable pending sign-in starts over too, with the form's return_to.
      const post = await b.form("/login/second-factor", { code: "123456", return_to: "/admin" });
      expect(post.status).toBe(303);
      expect(post.headers.get("Location")).toBe("/login?return_to=%2Fadmin");
    });

    test.each(REFUSED_RETURN_TO)("starting over with return_to %s leads to /account", async (_, value) => {
      const b = stack.browser();
      const q = value === null ? "" : `?${new URLSearchParams({ return_to: value })}`;
      expect((await b.get(`/login/second-factor${q}`)).headers.get("Location")).toBe("/login?return_to=%2Faccount");
      const fields: Record<string, string> = { code: "123456" };
      if (value !== null) fields.return_to = value;
      expect((await b.form("/login/second-factor", fields)).headers.get("Location")).toBe("/login?return_to=%2Faccount");
    });

    test("the current code signs in with amr pwd, otp, mfa, following the sealed return_to only", async () => {
      const user = await stack.user({ username: uname("tok"), totp: true });
      const { b, res: step } = await toSecondFactor(user, "/account?resume=1");
      expect(step.status).toBe(303);
      const res = await b.form("/login/second-factor", { code: await stack.code(user), return_to: "/admin" });
      expect(res.status).toBe(303);
      expect(res.headers.get("Location")).toBe("/account?resume=1");
      expectCleared(res, "pending");
      expect(parseCookie(setCookieOf(res, "auth")).attrs).toEqual(cookieAttrs("Lax", 2592000));
      expect(setCookieOf(res, "device")).toBeDefined();
      expect(b.cookies.has("__Host-pending")).toBe(false);
      const s = await sessionByToken(b.cookies.get("__Host-auth"));
      expect(s?.user_id).toBe(user.id);
      expect(s?.amr).toEqual(["pwd", "otp", "mfa"]);
      const ok = await auditFor("login.ok", user.id);
      expect(ok).toHaveLength(1);
      expect(ok[0]!.detail).toEqual({ method: "totp", amr: ["pwd", "otp", "mfa"], device: deviceIdOf(b.cookies.get("__Host-device")!) });
    });

    test.each([
      ["the previous step", -1, true],
      ["the next step", 1, true],
      ["two steps back", -2, false],
      ["two steps ahead", 2, false],
    ])("a code for %s: accepted %p", async (_, offset, accepted) => {
      const user = await stack.user({ username: uname("skew"), totp: true });
      const { b } = await toSecondFactor(user);
      await stack.db`UPDATE totp SET last_step = 0 WHERE user_id = ${user.id}`;
      await steadyStep();
      const res = await b.form("/login/second-factor", { code: totp(user.totpSecret!, Date.now(), offset) });
      expect(res.status).toBe(accepted ? 303 : 401);
    });

    test("a code with spaces around it is accepted", async () => {
      const user = await stack.user({ username: uname("space"), totp: true });
      const { b } = await toSecondFactor(user);
      expect((await b.form("/login/second-factor", { code: ` ${await stack.code(user)} ` })).status).toBe(303);
    });

    test("a code is used once: replayed, or an older step after a newer one, it is refused", async () => {
      const user = await stack.user({ username: uname("replay"), totp: true });
      await steadyStep();
      const code = await stack.code(user);
      const first = await toSecondFactor(user);
      expect((await first.b.form("/login/second-factor", { code })).status).toBe(303);
      const second = await toSecondFactor(user);
      const res = await second.b.form("/login/second-factor", { code });
      expect(res.status).toBe(401);
      expect((await second.b.form("/login/second-factor", { code: totp(user.totpSecret!, Date.now(), -1) })).status).toBe(401);
    });

    test("a wrong code: 401 with the form again, audited, counted against the account", async () => {
      const user = await stack.user({ username: uname("wrong"), totp: true });
      const { b } = await toSecondFactor(user, "/admin");
      const good = await stack.code(user);
      const bad = good === "000000" ? "111111" : "000000";
      const res = await b.form("/login/second-factor", { code: bad });
      const html = await expectPage(res, 401, "Second factor");
      expect(flashes(html, "error")).toEqual(["That code didn't work."]);
      expectTag(html, "input", { name: "return_to", value: "/admin" });
      expect(b.cookies.has("__Host-pending")).toBe(true);
      expect(b.cookies.has("__Host-auth")).toBe(false);
      const fails = await auditFor("login.mfa_fail", user.id);
      expect(fails).toHaveLength(1);
      expect(fails[0]!.actor).toBeNull();
      expect(fails[0]!.ip).toBe(b.ip);
      expect(fails[0]!.detail).toEqual({});
      expect(await throttleHits(`login:user:${user.id}`)).toBe(1);
      // The same pending sign-in still takes the right code, which clears the count.
      expect((await b.form("/login/second-factor", { code: good })).status).toBe(303);
      expect(await throttleHits(`login:user:${user.id}`)).toBeNull();
    });

    test.each([
      ["empty", ""],
      ["five digits", "12345"],
      ["seven digits", "1234567"],
      ["letters", "abcdef"],
      ["a long value", "9".repeat(100)],
    ])("a malformed code (%s) is a wrong code", async (_, code) => {
      const user = await stack.user({ username: uname("bad"), totp: true });
      const { b } = await toSecondFactor(user);
      const res = await b.form("/login/second-factor", { code });
      expect(flashes(await expectPage(res, 401, "Second factor"), "error")).toEqual(["That code didn't work."]);
    });

    test("five attempts per password sign-in, then Too many attempts, and the pending cookie is cleared", async () => {
      const user = await stack.user({ username: uname("five"), totp: true });
      const { b } = await toSecondFactor(user, "/admin");
      const good = await stack.code(user);
      const bad = good === "000000" ? "111111" : "000000";
      for (let i = 0; i < 5; i++) expect((await b.form("/login/second-factor", { code: bad })).status).toBe(401);
      const pending = b.cookies.get("__Host-pending")!;
      const res = await b.form("/login/second-factor", { code: good });
      expectCleared(res, "pending");
      await expectMessage(res, 429, "Too many attempts", "Too many wrong codes. Sign in again later.", { href: "/login?return_to=%2Fadmin", text: "Sign in" });
      expect(b.cookies.has("__Host-auth")).toBe(false);
      // The same pending cookie sent again stays refused.
      b.cookies.set("__Host-pending", pending);
      expect((await b.form("/login/second-factor", { code: good })).status).toBe(429);
      expect(await throttleHits(`mfa:${stack.crypt.open<{ id: string }>("pending", pending).v.id}`)).toBe(7);
    });

    test("five attempts per sign-in, even with the account's counter cleared", async () => {
      const user = await stack.user({ username: uname("fivec"), totp: true });
      const { b } = await toSecondFactor(user);
      const good = await stack.code(user);
      const bad = good === "000000" ? "111111" : "000000";
      for (let i = 0; i < 5; i++) {
        expect((await b.form("/login/second-factor", { code: bad })).status).toBe(401);
        await stack.db`DELETE FROM throttle WHERE key = ${`login:user:${user.id}`}`;
      }
      expect((await b.form("/login/second-factor", { code: good })).status).toBe(429);
    });

    test("an account already waiting refuses the second factor at once", async () => {
      const user = await stack.user({ username: uname("waits"), totp: true });
      const { b } = await toSecondFactor(user);
      await stack.db`INSERT INTO throttle (key, window_start, hits) VALUES (${`login:user:${user.id}`}, now(), 5)`;
      const res = await b.form("/login/second-factor", { code: await stack.code(user) });
      await expectMessage(res, 429, "Too many attempts", "Too many wrong codes. Sign in again later.", { href: "/login?return_to=%2Faccount", text: "Sign in" });
    });

    test("starting over doesn't buy more guesses: the failures count against the account's sign-in", async () => {
      const user = await stack.user({ username: uname("over"), totp: true });
      const good = await stack.code(user);
      const bad = good === "000000" ? "111111" : "000000";
      const first = await toSecondFactor(user);
      for (let i = 0; i < 4; i++) await (await first.b.form("/login/second-factor", { code: bad })).body?.cancel();
      const second = await toSecondFactor(user);
      expect(second.res.status).toBe(303);
      await (await second.b.form("/login/second-factor", { code: bad })).body?.cancel();
      const res = await stack.browser().form("/login", { login: user.username, password: PW });
      expect(res.status).toBe(429);
    });

    test.each([
      ["as shown", (c: string) => c],
      ["without dashes", (c: string) => c.replace(/-/g, "")],
      ["in capitals", (c: string) => c.toUpperCase()],
      ["with spaces for dashes", (c: string) => c.replace(/-/g, " ")],
    ])("a recovery code %s is accepted once, audited and emailed", async (_, shape) => {
      const user = await stack.user({ username: uname("rec"), totp: true, recoveryCodes: 2 });
      const code = user.recoveryCodes[0]!;
      const { b } = await toSecondFactor(user, "/account?r=1");
      const res = await b.form("/login/second-factor", { code: shape(code) });
      expect(res.status).toBe(303);
      expect(res.headers.get("Location")).toBe("/account?r=1");
      const s = await sessionByToken(b.cookies.get("__Host-auth"));
      expect(s?.amr).toEqual(["pwd", "otp", "mfa"]);
      expect((await auditFor("login.ok", user.id))[0]!.detail).toEqual({ method: "recovery_code", amr: ["pwd", "otp", "mfa"], device: deviceIdOf(b.cookies.get("__Host-device")!) });
      const used = await auditFor("recovery.used", user.id);
      expect(used).toHaveLength(1);
      expect(used[0]!.actor).toBe(user.id);
      expect(used[0]!.ip).toBe(b.ip);
      expect(used[0]!.detail).toEqual({});
      const rows: { code_hash: Buffer; used_at: Date | null }[] = await stack.db`SELECT code_hash, used_at FROM recovery_codes WHERE user_id = ${user.id}`;
      const canonical = code.replace(/-/g, "");
      expect(rows.find((r) => Buffer.from(r.code_hash).equals(sha256(canonical)))?.used_at).not.toBeNull();
      expect(rows.filter((r) => r.used_at === null)).toHaveLength(1);
      const mail = await stack.smtp.waitFor(user.email!, (m) => m.subject === "Security notice: a recovery code was used");
      expect(mail.text).toBe(`On the account "${user.username}": a recovery code was used.\n\nIf this wasn't you, reset your password and contact an administrator.`);
      // Used once.
      const again = await toSecondFactor(user);
      expect((await again.b.form("/login/second-factor", { code })).status).toBe(401);
    });

    test("a recovery code of another account, or a made-up one, is a wrong code", async () => {
      const user = await stack.user({ username: uname("recx"), totp: true, recoveryCodes: 1 });
      const other = await stack.user({ username: uname("recy"), totp: true, recoveryCodes: 1 });
      const { b } = await toSecondFactor(user);
      expect((await b.form("/login/second-factor", { code: other.recoveryCodes[0]! })).status).toBe(401);
      expect((await b.form("/login/second-factor", { code: "aaaa-bbbb-cccc-dddd-eeee-ffff" })).status).toBe(401);
      expect((await b.form("/login/second-factor", { code: "aaaa-bbbb-cccc-dddd-eeee-fff1" })).status).toBe(401);
      expect(await auditFor("login.mfa_fail", user.id)).toHaveLength(3);
      const [left] = await stack.db`SELECT count(*)::int AS n FROM recovery_codes WHERE user_id = ${other.id} AND used_at IS NULL`;
      expect(left.n).toBe(1);
    });

    test("a pending sign-in for a bot ends at Can't sign in", async () => {
      const owner = await stack.user({ username: uname("owner") });
      const bot = await stack.user({ username: uname("tbot"), kind: "bot", ownerId: owner.id, totp: true });
      const b = stack.browser();
      b.cookies.set("__Host-pending", stack.crypt.seal("pending", { u: bot.id, id: randomToken(), r: "/account" }, 300));
      const res = await b.form("/login/second-factor", { code: await stack.code(bot) });
      await expectMessage(res, 403, "Can't sign in", "This account is disabled.", { href: "/login", text: "Back" });
      expect(b.cookies.has("__Host-auth")).toBe(false);
    });
  });

  // ---------------------------------------------------------------- rehash

  describe("rehash at the first sign-in", () => {
    const CURRENT = /^\$argon2id\$v=19\$m=19456,t=2,p=1\$/;

    test("an imported bcrypt hash becomes argon2id; only the first 72 bytes of the password count", async () => {
      // 80 bytes: 40 two-byte characters. bcrypt sees the first 36.
      const password = "é".repeat(40);
      const first72 = Buffer.from(password, "utf8").subarray(0, 72);
      const imported = await Bun.password.hash(first72, { algorithm: "bcrypt", cost: 4 });
      const user = await stack.user({ username: uname("bcrypt"), passwordHash: imported });
      // A wrong password leaves the hash alone.
      expect((await stack.browser().form("/login", { login: user.username, password: "é".repeat(35) })).status).toBe(401);
      expect(await hashOf(user.id)).toBe(imported);
      // Anything after byte 72 is not read.
      const typed = `${"é".repeat(36)}tail`;
      expect((await stack.browser().form("/login", { login: user.username, password: typed })).status).toBe(303);
      const fresh = await hashOf(user.id);
      expect(fresh).toMatch(CURRENT);
      // The new hash is of the whole password as typed.
      expect(await Bun.password.verify(typed, fresh)).toBe(true);
      expect(await Bun.password.verify(password, fresh)).toBe(false);
      expect((await stack.browser().form("/login", { login: user.username, password: typed })).status).toBe(303);
      expect(await hashOf(user.id)).toBe(fresh);
    });

    test("a bcrypt hash of a short password", async () => {
      const imported = await Bun.password.hash(PW, { algorithm: "bcrypt", cost: 4 });
      const user = await stack.user({ username: uname("bcs"), passwordHash: imported });
      expect((await stack.browser().form("/login", { login: user.username, password: PW })).status).toBe(303);
      const fresh = await hashOf(user.id);
      expect(fresh).toMatch(CURRENT);
      expect(await Bun.password.verify(PW, fresh)).toBe(true);
    });

    test.each([
      ["argon2id with other parameters", () => Bun.password.hash(PW, { algorithm: "argon2id", memoryCost: 8192, timeCost: 1 })],
      ["argon2i", () => Bun.password.hash(PW, { algorithm: "argon2i", memoryCost: 19456, timeCost: 2 })],
    ])("%s becomes the current argon2id", async (_, make) => {
      const imported = await make();
      expect(imported).not.toMatch(CURRENT);
      const user = await stack.user({ username: uname("argon"), passwordHash: imported });
      expect((await stack.browser().form("/login", { login: user.username, password: PW })).status).toBe(303);
      const fresh = await hashOf(user.id);
      expect(fresh).toMatch(CURRENT);
      expect(await Bun.password.verify(PW, fresh)).toBe(true);
    });

    test("a current-format hash is left as it is", async () => {
      const user = await stack.user({ username: uname("cur") });
      const before = await hashOf(user.id);
      expect(before).toMatch(CURRENT);
      expect((await stack.browser().form("/login", { login: user.username, password: PW })).status).toBe(303);
      expect(await hashOf(user.id)).toBe(before);
    });

    test("the rehash happens at the password step, before the second factor", async () => {
      const imported = await Bun.password.hash(PW, { algorithm: "bcrypt", cost: 4 });
      const user = await stack.user({ username: uname("bct"), passwordHash: imported, totp: true });
      const res = await stack.browser().form("/login", { login: user.username, password: PW });
      expect(res.headers.get("Location")).toBe("/login/second-factor?return_to=%2Faccount");
      expect(await hashOf(user.id)).toMatch(CURRENT);
    });

    test("a disabled user's imported hash is not rehashed", async () => {
      const imported = await Bun.password.hash(PW, { algorithm: "bcrypt", cost: 4 });
      const user = await stack.user({ username: uname("bcd"), passwordHash: imported, disabled: true });
      expect((await stack.browser().form("/login", { login: user.username, password: PW })).status).toBe(403);
      expect(await hashOf(user.id)).toBe(imported);
    });
  });

  // -------------------------------------------------------------- passkeys

  describe("passkey sign-in", () => {
    const ORIGIN = () => stack.issuer;

    // A passkey added through the API, as the account page adds one.
    async function register(user: TestUser, a: SoftAuthenticator, name = "Laptop"): Promise<string> {
      const b = await stack.session(user, { amr: ["swk", "user", "mfa"] });
      const start = await b.api("POST", "/v1/me/passkeys", {});
      expect(start.status).toBe(200);
      const { options, registration } = (await start.json()) as { options: any; registration: string };
      const res = await b.api("POST", "/v1/me/passkeys", { registration, response: a.create(options, ORIGIN()), name });
      expect(res.status).toBe(201);
      return ((await res.json()) as { id: string }).id;
    }

    async function options(b: Browser, init: { origin?: string | null; headers?: Record<string, string> } = {}) {
      const res = await b.request("/login/passkey/options", { method: "POST", headers: { "Content-Type": "application/json", ...init.headers }, body: "{}", origin: init.origin });
      return res;
    }

    async function begin(b: Browser): Promise<{ challenge: string; rpId: string }> {
      const res = await options(b);
      expect(res.status).toBe(200);
      return ((await res.json()) as { options: { challenge: string; rpId: string } }).options;
    }

    function finish(b: Browser, body: unknown, init: { origin?: string | null; type?: string } = {}) {
      return b.request("/login/passkey", {
        method: "POST",
        headers: { "Content-Type": init.type ?? "application/json" },
        body: typeof body === "string" ? body : JSON.stringify(body),
        origin: init.origin,
      });
    }

    async function signInWith(a: SoftAuthenticator, edit: Edits = {}, extra: Record<string, unknown> = {}) {
      const b = stack.browser();
      const opts = await begin(b);
      const res = await finish(b, { response: a.get(opts, ORIGIN(), edit), ...extra });
      return { b, res };
    }

    const DIDNT_WORK = "That passkey sign-in didn't work.";

    async function expectRefused(b: Browser, res: Response): Promise<void> {
      await expectJsonError(res, 401, "unauthorized", DIDNT_WORK);
      expect(b.cookies.has("__Host-auth")).toBe(false);
      const fails = await auditFor("login.fail", null, b.ip);
      expect(fails).toHaveLength(1);
      expect(fails[0]!.actor).toBeNull();
      expect(fails[0]!.detail).toEqual({ method: "passkey" });
    }

    test("options: the request options, and the sealed challenge in a five-minute cookie", async () => {
      const b = stack.browser();
      const res = await options(b);
      expect(res.status).toBe(200);
      expect(res.headers.get("Content-Type")).toBe("application/json");
      expect(res.headers.get("Cache-Control")).toBe("no-store");
      const body = (await res.json()) as { options: Record<string, unknown> };
      expect(body).toEqual({ options: { rpId: "127.0.0.1", challenge: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/), timeout: 60000, userVerification: "required" } });
      const cookie = parseCookie(setCookieOf(res, "webauthn"));
      expect(cookie.attrs).toEqual(cookieAttrs("Lax", 300));
      const opened = stack.crypt.open<{ c: string }>("passkey-auth", cookie.value);
      expect(opened.v).toEqual({ c: body.options.challenge as string });
      expect(Math.abs(opened.exp - (Date.now() + 300_000))).toBeLessThan(60_000);
      // A fresh challenge each time.
      expect((await begin(b)).challenge).not.toBe(body.options.challenge);
    });

    test.each([
      ["missing", null, {}],
      ["another site's", "https://evil.example.com", {}],
      ["null alone", "null", {}],
      ["null, cross-site", "null", { "Sec-Fetch-Site": "cross-site" }],
    ])("options with Origin %s: 403", async (_, origin, headers) => {
      const b = stack.browser();
      const res = await options(b, { origin, headers });
      await expectJsonError(res, 403, "forbidden", "The request's Origin is not this issuer.");
      expect(setCookieOf(res, "webauthn")).toBeUndefined();
    });

    test("options with Origin: null and Sec-Fetch-Site: same-origin", async () => {
      const res = await options(stack.browser(), { origin: "null", headers: { "Sec-Fetch-Site": "same-origin" } });
      expect(res.status).toBe(200);
      await res.body?.cancel();
    });

    test("options answers POST only", async () => {
      const res = await fetch(`${stack.url}/login/passkey/options`);
      expect(res.headers.get("Allow")).toBe("POST");
      await expectJsonError(res, 405, "method_not_allowed", "Use POST.");
    });

    test.each([
      ["ES256", -7 as const],
      ["EdDSA", -8 as const],
      ["RS256", -257 as const],
    ])("a good %s assertion signs in with amr swk, user, mfa", async (_, alg) => {
      const user = await stack.user({ username: uname("pk") });
      const a = new SoftAuthenticator(alg, { counts: true });
      const pk = await register(user, a);
      const ua = "Example-Browser/3.0";
      const b = stack.browser();
      const opts = await begin(b);
      const res = await b.request("/login/passkey", {
        method: "POST",
        headers: { "Content-Type": "application/json", "User-Agent": ua },
        body: JSON.stringify({ response: a.get(opts, ORIGIN()), return_to: "/account?via=passkey" }),
      });
      expect(res.status).toBe(200);
      expect(res.headers.get("Content-Type")).toBe("application/json");
      expect(await res.json()).toEqual({ redirect: "/account?via=passkey" });
      const auth = parseCookie(setCookieOf(res, "auth"));
      expect(auth.attrs).toEqual(cookieAttrs("Lax", 2592000));
      expectCleared(res, "pending");
      expectCleared(res, "webauthn");
      const device = parseCookie(setCookieOf(res, "device"));
      expect(device.attrs).toEqual(cookieAttrs("Lax", 34560000));
      const s = await sessionByToken(auth.value);
      expect(s?.user_id).toBe(user.id);
      expect(s?.amr).toEqual(["swk", "user", "mfa"]);
      expect(s?.ip).toBe(b.ip);
      expect(s?.user_agent).toBe(ua);
      const [row] = await stack.db`SELECT sign_count, last_used_at FROM passkeys WHERE id = ${pk}`;
      expect(Number(row.sign_count)).toBe(2);
      expect(Math.abs(new Date(row.last_used_at).getTime() - Date.now())).toBeLessThan(60_000);
      const ok = await auditFor("login.ok", user.id);
      expect(ok).toHaveLength(1);
      expect(ok[0]!.detail).toEqual({ method: "passkey", amr: ["swk", "user", "mfa"], device: deviceIdOf(device.value) });
      // The session opens the admin-grade pages a second factor gates.
      expect((await b.get("/account")).status).toBe(200);
    });

    test("a synced passkey's counter stays 0 and is accepted every time", async () => {
      const user = await stack.user({ username: uname("sync") });
      const a = new SoftAuthenticator(-7);
      const pk = await register(user, a);
      expect((await signInWith(a)).res.status).toBe(200);
      expect((await signInWith(a)).res.status).toBe(200);
      const [row] = await stack.db`SELECT sign_count FROM passkeys WHERE id = ${pk}`;
      expect(Number(row.sign_count)).toBe(0);
    });

    test("a counter that doesn't move forward is refused, and the stored one kept", async () => {
      const user = await stack.user({ username: uname("ctr") });
      const a = new SoftAuthenticator(-7, { counts: true });
      const pk = await register(user, a);
      expect((await signInWith(a)).res.status).toBe(200);
      for (const counter of [2, 1, 0]) {
        const { b, res } = await signInWith(a, { counter });
        await expectRefused(b, res);
      }
      const [row] = await stack.db`SELECT sign_count FROM passkeys WHERE id = ${pk}`;
      expect(Number(row.sign_count)).toBe(2);
      expect((await signInWith(a, { counter: 3 })).res.status).toBe(200);
    });

    test.each(REFUSED_RETURN_TO.filter(([, v]) => v !== null))("return_to %s leads to /account", async (_, value) => {
      const user = await stack.user({ username: uname("pkrt") });
      const a = new SoftAuthenticator(-8);
      await register(user, a);
      const { res } = await signInWith(a, {}, { return_to: value });
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ redirect: "/account" });
    });

    test.each([
      ["missing", undefined],
      ["null", null],
      ["a number", 5],
      ["an array", ["/admin"]],
      ["an object", { path: "/admin" }],
      ["true", true],
    ])("return_to %s leads to /account", async (_, value) => {
      const user = await stack.user({ username: uname("pkrt") });
      const a = new SoftAuthenticator(-8);
      await register(user, a);
      const { res } = await signInWith(a, {}, value === undefined ? {} : { return_to: value });
      expect(await res.json()).toEqual({ redirect: "/account" });
    });

    test.each(ACCEPTED_RETURN_TO)("return_to %s is followed", async (_, value) => {
      const user = await stack.user({ username: uname("pkrt") });
      const a = new SoftAuthenticator(-8);
      await register(user, a);
      const { res } = await signInWith(a, {}, { return_to: value });
      expect(await res.json()).toEqual({ redirect: value });
    });

    test("no challenge cookie: 401", async () => {
      const user = await stack.user({ username: uname("nock") });
      const a = new SoftAuthenticator();
      await register(user, a);
      const b = stack.browser();
      const opts = await begin(b);
      b.cookies.delete("__Host-webauthn");
      await expectRefused(b, await finish(b, { response: a.get(opts, ORIGIN()) }));
    });

    test.each([
      ["expired", "EXPIRED"],
      ["tampered", "TAMPERED"],
      ["another purpose's", "PURPOSE"],
      ["garbage", "GARBAGE"],
    ])("a %s challenge cookie: 401", async (_, kind) => {
      const user = await stack.user({ username: uname("badck") });
      const a = new SoftAuthenticator();
      await register(user, a);
      const b = stack.browser();
      const challenge = b64u(randomBytes(32));
      const good = stack.crypt.seal("passkey-auth", { c: challenge }, 300);
      const value =
        kind === "EXPIRED"
          ? stack.crypt.seal("passkey-auth", { c: challenge }, -1)
          : kind === "TAMPERED"
            ? good.slice(0, 20) + (good[20] === "A" ? "B" : "A") + good.slice(21)
            : kind === "PURPOSE"
              ? stack.crypt.seal("passkey-reg", { c: challenge }, 300)
              : "garbage";
      b.cookies.set("__Host-webauthn", value);
      await expectRefused(b, await finish(b, { response: a.get({ challenge, rpId: "127.0.0.1" }, ORIGIN()) }));
    });

    test("a challenge crafted and sealed like the server's is accepted", async () => {
      const user = await stack.user({ username: uname("craft") });
      const a = new SoftAuthenticator();
      await register(user, a);
      const b = stack.browser();
      const challenge = b64u(randomBytes(32));
      b.cookies.set("__Host-webauthn", stack.crypt.seal("passkey-auth", { c: challenge }, 300));
      expect((await finish(b, { response: a.get({ challenge, rpId: "127.0.0.1" }, ORIGIN()) })).status).toBe(200);
    });

    test("a challenge is accepted once", async () => {
      const user = await stack.user({ username: uname("once") });
      const a = new SoftAuthenticator();
      await register(user, a);
      const b = stack.browser();
      const opts = await begin(b);
      const cookie = b.cookies.get("__Host-webauthn")!;
      expect((await finish(b, { response: a.get(opts, ORIGIN()) })).status).toBe(200);
      expect(b.cookies.has("__Host-webauthn")).toBe(false);
      const replay = stack.browser();
      replay.cookies.set("__Host-webauthn", cookie);
      await expectRefused(replay, await finish(replay, { response: a.get(opts, ORIGIN()) }));
    });

    test("an unknown credential is refused without spending the challenge", async () => {
      const user = await stack.user({ username: uname("unk") });
      const a = new SoftAuthenticator();
      await register(user, a);
      const b = stack.browser();
      const opts = await begin(b);
      await expectRefused(b, await finish(b, { response: new SoftAuthenticator().get(opts, ORIGIN()) }));
      expect((await finish(b, { response: a.get(opts, ORIGIN()) })).status).toBe(200);
    });

    test("a failed check spends the challenge", async () => {
      const user = await stack.user({ username: uname("spend") });
      const a = new SoftAuthenticator();
      await register(user, a);
      const b = stack.browser();
      const opts = await begin(b);
      await expectRefused(b, await finish(b, { response: a.get(opts, ORIGIN(), { signWith: new SoftAuthenticator().privateKey }) }));
      const res = await finish(b, { response: a.get(opts, ORIGIN()) });
      await expectJsonError(res, 401, "unauthorized", DIDNT_WORK);
    });

    test.each([
      ["another origin", { origin: "https://evil.example.com" }],
      ["the origin with a trailing slash", { origin: "TRAILING" }],
      ["another RP ID", { rpId: "example.com" }],
      ["a signature by another key", { signWith: "OTHER" }],
      ["the create type", { type: "webauthn.create" }],
      ["another challenge", { challenge: "CHALLENGE" }],
      ["a cross-origin ceremony", { crossOrigin: true }],
      ["no user verification", { flags: UP }],
      ["authenticator data changed after signing", { authenticatorData: "CHANGED" }],
    ])("%s: 401", async (_, raw) => {
      const user = await stack.user({ username: uname("chk") });
      const a = new SoftAuthenticator();
      await register(user, a);
      const edit: Edits = {};
      const r = raw as Record<string, unknown>;
      if (r.origin === "TRAILING") edit.origin = `${stack.issuer}/`;
      else if (typeof r.origin === "string") edit.origin = r.origin;
      if (typeof r.rpId === "string") edit.rpId = r.rpId;
      if (r.signWith === "OTHER") edit.signWith = new SoftAuthenticator().privateKey;
      if (typeof r.type === "string") edit.type = r.type;
      if (r.challenge === "CHALLENGE") edit.challenge = b64u(randomBytes(32));
      if (r.crossOrigin === true) edit.crossOrigin = true;
      if (typeof r.flags === "number") edit.flags = r.flags;
      if (r.authenticatorData === "CHANGED") edit.authenticatorData = (d) => Buffer.concat([d.subarray(0, 33), Buffer.from([0, 0, 0, 9])]);
      const { b, res } = await signInWith(a, edit);
      await expectRefused(b, res);
    });

    test("crossOrigin false is fine", async () => {
      const user = await stack.user({ username: uname("xo") });
      const a = new SoftAuthenticator();
      await register(user, a);
      expect((await signInWith(a, { crossOrigin: false })).res.status).toBe(200);
    });

    test("a disabled user's passkey is refused", async () => {
      const user = await stack.user({ username: uname("pkdis") });
      const a = new SoftAuthenticator();
      await register(user, a);
      await stack.db`UPDATE users SET disabled_at = now() WHERE id = ${user.id}`;
      const { b, res } = await signInWith(a);
      await expectRefused(b, res);
    });

    test.each([
      ["no response", {}],
      ["a null response", { response: null }],
      ["a string response", { response: "x" }],
      ["an array response", { response: [] }],
      ["a response without an id", { response: { type: "public-key" } }],
      ["a response whose id is a number", { response: { id: 5, type: "public-key" } }],
    ])("%s: 401", async (_, body) => {
      const b = stack.browser();
      await begin(b);
      await expectRefused(b, await finish(b, body));
    });

    test("a response with the right id and broken fields: 401", async () => {
      const user = await stack.user({ username: uname("brk") });
      const a = new SoftAuthenticator();
      await register(user, a);
      const b = stack.browser();
      const opts = await begin(b);
      const good = a.get(opts, ORIGIN());
      await expectRefused(b, await finish(b, { response: { ...good, type: "other" } }));
    });

    test("an empty body is an empty object", async () => {
      const b = stack.browser();
      await begin(b);
      await expectRefused(b, await finish(b, ""));
    });

    test.each([
      ["text/plain", "{}", 415, "Send application/json."],
      ["application/x-www-form-urlencoded", "response=x", 415, "Send application/json."],
      ["application/json", "{", 400, "The body is not valid JSON."],
      ["application/json", "[]", 400, "The body must be a JSON object."],
      ["application/json", "null", 400, "The body must be a JSON object."],
      ["application/json", '"x"', 400, "The body must be a JSON object."],
      ["application/json", "5", 400, "The body must be a JSON object."],
    ])("Content-Type %s with %s: %i", async (type, body, status, description) => {
      const b = stack.browser();
      await begin(b);
      const res = await finish(b, body, { type });
      await expectJsonError(res, status, "invalid_request", description);
      // Refused before the per-IP count.
      expect(await throttleHits(`ip:${b.ip}:login`)).toBeNull();
    });

    test("application/json with a charset is JSON", async () => {
      const b = stack.browser();
      await begin(b);
      await expectRefused(b, await finish(b, "{}", { type: "application/json; charset=utf-8" }));
    });

    test("sign-ins padded to 64 KiB, queued on the password hasher, hold up no other request with a body", async () => {
      // Each names no account, so each waits its turn on the one hash slot;
      // the Rust server lets go of the body first (DESIGN §10). The small
      // request goes once the first is answered, so the rest are queued
      // however fast this machine hashes.
      const browsers = Array.from({ length: 24 }, () => stack.browser());
      for (const b of browsers) await b.formCsrf();
      let answered = 0;
      let firstAnswered!: () => void;
      const first = new Promise<void>((resolve) => (firstAnswered = resolve));
      const signIns = browsers.map(async (b) => {
        const res = await b.form("/login", { login: `nobody-${randomBytes(4).toString("hex")}`, password: "x", padding: "a".repeat(64 * 1024 - 400) });
        await res.body?.cancel();
        if (++answered === 1) firstAnswered();
        return res.status;
      });
      await first;
      const before = answered;
      const small = await stack.browser().request("/login/passkey/options", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
      const meanwhile = answered - before;
      expect(small.status).toBe(200);
      await small.body?.cancel();
      expect(await Promise.all(signIns)).toEqual(browsers.map(() => 401));
      // Most were still queued when it was sent, and it didn't wait for them.
      expect(before).toBeLessThanOrEqual(browsers.length / 2);
      expect(meanwhile).toBeLessThanOrEqual(2);
    });

    test("a burst of the largest bodies is answered, each as it would be alone", async () => {
      // 64 KiB each, of small objects: the shape that costs a parser the
      // most, which the Rust server takes in turn (DESIGN §10).
      const body = `{"response":[${Array.from({ length: Math.floor((64 * 1024 - 16) / 8) }, () => '{"a":0}').join(",")}]}`;
      expect(body.length).toBeGreaterThan(63 * 1024);
      expect(body.length).toBeLessThanOrEqual(64 * 1024);
      const answers = await Promise.all(
        Array.from({ length: 24 }, async () => {
          const res = await finish(stack.browser(), body);
          return `${res.status} ${((await res.json()) as { error_description?: string }).error_description}`;
        }),
      );
      expect(new Set(answers)).toEqual(new Set([`401 ${DIDNT_WORK}`]));
      expect((await fetch(`${stack.url}/healthz`)).status).toBe(200);
    });

    test("a body nested 64 levels deep is read; deeper, as deep as 64 KiB holds included, is not JSON", async () => {
      const b = stack.browser();
      await begin(b);
      // The body is a level, and each array another.
      const levels = (n: number) => `{"response":${"[".repeat(n - 1)}${"]".repeat(n - 1)}}`;
      await expectRefused(b, await finish(b, levels(64)));
      for (const body of [levels(65), nest('{"response":<nest>}'), nest("<nest>")]) {
        await expectJsonError(await finish(b, body), 400, "invalid_request", "The body is not valid JSON.");
      }
      // Refused before the per-IP count.
      expect(await throttleHits(`ip:${b.ip}:login`)).toBe(1);
      expect((await fetch(`${stack.url}/healthz`)).status).toBe(200);
    });

    test.each([
      ["missing", null, {}],
      ["another site's", "https://evil.example.com", {}],
      ["null alone", "null", {}],
    ])("sign-in with Origin %s: 403, before the body is read", async (_, origin, headers) => {
      const b = stack.browser();
      await begin(b);
      const res = await b.request("/login/passkey", { method: "POST", headers: { "Content-Type": "text/plain", ...headers }, body: "{", origin });
      await expectJsonError(res, 403, "forbidden", "The request's Origin is not this issuer.");
    });

    test("sign-in with Origin: null and Sec-Fetch-Site: same-origin", async () => {
      const user = await stack.user({ username: uname("pknull") });
      const a = new SoftAuthenticator();
      await register(user, a);
      const b = stack.browser();
      const opts = await begin(b);
      const res = await b.request("/login/passkey", {
        method: "POST",
        origin: "null",
        headers: { "Content-Type": "application/json", "Sec-Fetch-Site": "same-origin" },
        body: JSON.stringify({ response: a.get(opts, ORIGIN()) }),
      });
      expect(res.status).toBe(200);
    });

    test("the per-IP limit is shared with the password form", async () => {
      const user = await stack.user({ username: uname("pkip") });
      const a = new SoftAuthenticator();
      await register(user, a);
      const b = stack.browser();
      const key = `ip:${b.ip}:login`;
      expect((await b.form("/login", { login: uname("ghost"), password: "wrong-pw-1" })).status).toBe(401);
      const opts = await begin(b);
      expect((await finish(b, { response: a.get(opts, ORIGIN()) })).status).toBe(200);
      expect(await throttleHits(key)).toBe(2);
      // Refused sign-ins count too.
      await (await finish(b, {})).body?.cancel();
      expect(await throttleHits(key)).toBe(3);
      await stack.db`UPDATE throttle SET hits = 30 WHERE key = ${key}`;
      const before = (await stack.audit("login.fail")).length;
      const opts2 = await begin(b);
      const session = b.cookies.get("__Host-auth");
      const res = await finish(b, { response: a.get(opts2, ORIGIN()) });
      const retry = Number(res.headers.get("Retry-After"));
      expect(retry).toBeGreaterThan(840);
      expect(retry).toBeLessThanOrEqual(900);
      await expectJsonError(res, 429, "rate_limited", "Too many sign-in attempts from your network.");
      expect(setCookieOf(res, "auth")).toBeUndefined();
      expect(b.cookies.get("__Host-auth")).toBe(session);
      expect((await stack.audit("login.fail")).length).toBe(before);
      // The challenge was not spent: once the window passes, it still works.
      await stack.db`UPDATE throttle SET window_start = now() - interval '901 seconds' WHERE key = ${key}`;
      expect((await finish(b, { response: a.get(opts2, ORIGIN()) })).status).toBe(200);
    });

    test("a passkey sign-in in a browser signed in as someone else ends that session", async () => {
      const alice = await stack.user({ username: uname("pka") });
      const bob = await stack.user({ username: uname("pkb") });
      const a = new SoftAuthenticator(-8);
      await register(bob, a);
      const b = await stack.session(alice);
      const old = b.sessionId!;
      const opts = await begin(b);
      expect((await finish(b, { response: a.get(opts, ORIGIN()) })).status).toBe(200);
      expect(await stack.db`SELECT 1 FROM sessions WHERE id = ${old}`).toHaveLength(0);
      expect((await sessionByToken(b.cookies.get("__Host-auth")))?.user_id).toBe(bob.id);
    });
  });

  // ------------------------------------------------------ /account, /admin

  describe("/account and /admin", () => {
    test.each([
      ["/account", "/login?return_to=%2Faccount"],
      ["/admin", "/login?return_to=%2Fadmin"],
    ])("%s signed out redirects to sign in", async (path, location) => {
      const res = await stack.browser().get(path);
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe(location);
    });

    test.each([
      ["expired", { expiresIn: "-1 second" }, {}],
      ["past its absolute end", { endsIn: "-1 second" }, {}],
      ["of a disabled user", {}, { disabled: true }],
    ])("a session %s counts as signed out", async (_, session, userOpts) => {
      const user = await stack.user({ username: uname("gone"), access: { auth: "admin" }, ...userOpts });
      const b = await stack.session(user, { amr: ["pwd", "otp", "mfa"], ...session });
      expect((await b.get("/account")).headers.get("Location")).toBe("/login?return_to=%2Faccount");
      expect((await b.get("/admin")).headers.get("Location")).toBe("/login?return_to=%2Fadmin");
    });

    test("an ended (deleted) session counts as signed out", async () => {
      const user = await stack.user({ username: uname("ended") });
      const b = await stack.session(user);
      await stack.db`DELETE FROM sessions WHERE id = ${b.sessionId}`;
      expect((await b.get("/account")).status).toBe(302);
    });

    test("a bot's session counts as signed out", async () => {
      const owner = await stack.user({ username: uname("owner") });
      const bot = await stack.user({ username: uname("sbot"), kind: "bot", ownerId: owner.id });
      const b = await stack.session(bot);
      expect((await b.get("/account")).status).toBe(302);
    });

    test.each([["short"], ["a".repeat(44)], ["a".repeat(42) + "*"]])("a malformed session cookie (%s) is signed out", async (value) => {
      const b = stack.browser();
      b.cookies.set("__Host-auth", value);
      expect((await b.get("/account")).status).toBe(302);
    });

    test("a non-admin on /admin gets a 403 page", async () => {
      const user = await stack.user({ username: uname("plain"), access: { wiki: "admin" } });
      const b = await stack.session(user, { amr: ["pwd", "otp", "mfa"] });
      await expectMessage(await b.get("/admin"), 403, "No access", "This page is for auth's administrators.", { href: "/account", text: "Your account" });
    });

    test("an admin whose session lacks a second factor is sent to sign in with one", async () => {
      const user = await stack.user({ username: uname("nomfa"), access: { auth: "admin" }, totp: true });
      const b = await stack.session(user, { amr: ["pwd"] });
      const res = await b.get("/admin");
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/login?return_to=%2Fadmin&second_factor=auth");
      // The account page is fine.
      expect((await b.get("/account")).status).toBe(200);
    });

    test("an admin signed in with a passkey sees the admin page", async () => {
      const user = await stack.user({ username: uname("pkadm"), access: { auth: "admin" } });
      const b = await stack.session(user, { amr: ["swk", "user", "mfa"] });
      await expectPage(await b.get("/admin"), 200, "Admin");
    });

    test("a stale session is kept alive by a page view, up to its absolute end", async () => {
      const user = await stack.user({ username: uname("touch") });
      const b = await stack.session(user, { expiresIn: "1 hour" });
      await stack.db`UPDATE sessions SET last_seen_at = now() - interval '2 minutes' WHERE id = ${b.sessionId}`;
      expect((await b.get("/account")).status).toBe(200);
      const [row] = await stack.db`SELECT expires_at, last_seen_at FROM sessions WHERE id = ${b.sessionId}`;
      expect(Math.abs(new Date(row.expires_at).getTime() - (Date.now() + 7 * 86400_000))).toBeLessThan(60_000);
      expect(Math.abs(new Date(row.last_seen_at).getTime() - Date.now())).toBeLessThan(60_000);

      const capped = await stack.session(user, { expiresIn: "1 hour", endsIn: "1 day" });
      await stack.db`UPDATE sessions SET last_seen_at = now() - interval '2 minutes' WHERE id = ${capped.sessionId}`;
      expect((await capped.get("/account")).status).toBe(200);
      const [c] = await stack.db`SELECT expires_at = ends_at AS same FROM sessions WHERE id = ${capped.sessionId}`;
      expect(c.same).toBe(true);
    });

    test("a session seen in the last minute is not extended", async () => {
      const user = await stack.user({ username: uname("fresh") });
      const b = await stack.session(user, { expiresIn: "1 hour" });
      expect((await b.get("/account")).status).toBe(200);
      const [row] = await stack.db`SELECT expires_at FROM sessions WHERE id = ${b.sessionId}`;
      expect(new Date(row.expires_at).getTime()).toBeLessThan(Date.now() + 2 * 3600_000);
    });
  });

  // --------------------------------------------------------- /mfa-required

  describe("/mfa-required", () => {
    test("names the service, links the security settings and a way on", async () => {
      const res = await stack.browser().get(`/mfa-required?${new URLSearchParams({ service: "wiki", return_to: "/oauth/authorize?client_id=wiki" })}`);
      const html = await expectPage(res, 200, "Two-factor authentication needed");
      expect(textOf(tagsOf(html, "h1")[0]!.inner)).toBe("Two-factor authentication needed");
      expect(textOf(html)).toContain("Your role on wiki needs a second factor. Add an authenticator app or a passkey to your account, then continue.");
      expect(textOf(expectTag(html, "a", { href: "/account#security" }).inner)).toBe("Set up a second factor");
      expect(textOf(expectTag(html, "a", { href: "/oauth/authorize?client_id=wiki" }).inner)).toBe("Continue to wiki");
    });

    test("the service is escaped and cut to 64 characters", async () => {
      const service = `<img src=x onerror="a">'&${"s".repeat(80)}`;
      const res = await stack.browser().get(`/mfa-required?${new URLSearchParams({ service, return_to: "/x" })}`);
      const html = await expectPage(res, 200, "Two-factor authentication needed");
      expect(html).not.toContain("<img");
      const cut = service.slice(0, 64);
      expect(textOf(html)).toContain(`Your role on ${cut} needs a second factor.`);
      expect(textOf(expectTag(html, "a", { href: "/x" }).inner)).toBe(`Continue to ${cut}`);
    });

    test("no service", async () => {
      const html = await expectPage(await stack.browser().get("/mfa-required"), 200, "Two-factor authentication needed");
      expect(textOf(expectTag(html, "a", { href: "/account" }).inner)).toBe("Continue to");
    });

    test.each(REFUSED_RETURN_TO)("return_to %s leads to /account", async (_, value) => {
      const q = new URLSearchParams({ service: "wiki" });
      if (value !== null) q.set("return_to", value);
      const html = await expectPage(await stack.browser().get(`/mfa-required?${q}`), 200, "Two-factor authentication needed");
      expect(textOf(expectTag(html, "a", { href: "/account" }).inner)).toBe("Continue to wiki");
    });

    test.each(ACCEPTED_RETURN_TO)("return_to %s is linked", async (_, value) => {
      const html = await expectPage(await stack.browser().get(`/mfa-required?${new URLSearchParams({ service: "wiki", return_to: value })}`), 200, "Two-factor authentication needed");
      expect(textOf(expectTag(html, "a", { href: value }).inner)).toBe("Continue to wiki");
    });
  });
});

// Waits on the clock, never more than one TOTP step.
async function waitForClock(ok: () => boolean): Promise<void> {
  const until = Date.now() + 31_000;
  while (!ok()) {
    if (Date.now() > until) throw new Error("the clock never got there");
    await Bun.sleep(100);
  }
}

describe.skipIf(!enabled)("a deployment without a services file", () => {
  let stack: Stack;
  beforeAll(async () => {
    stack = await Stack.start({ services: null });
  });
  afterAll(async () => {
    await stack.stop();
  });

  test("the page CSP's form-action is 'self' alone, and no sign-up callout is shown", async () => {
    const res = await stack.browser().get("/login");
    const html = await expectPage(res, 200, "Sign in", "");
    expect(res.headers.get("Content-Security-Policy")).toBe("default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'");
    expect(html).not.toContain("Create an account");
    expect(tagsOf(html, "a").some((a) => (a.attrs.href ?? "").startsWith("/signup"))).toBe(false);
  });

  test("a service registered on the admin page adds its redirect origins", async () => {
    const { browser } = await stack.admin();
    const res = await browser.api("POST", "/v1/services", {
      name: "notes",
      roles: ["reader"],
      mfa_roles: [],
      signup: "open",
      default_role: "reader",
      clients: [
        { id: "notes", type: "public", redirect_uris: ["https://notes.example.com/auth/callback", "https://notes.example.com/other", "com.example.notes:/cb"] },
        { id: "notes-web", type: "confidential", redirect_uris: ["https://app.notes.example.com/cb"] },
      ],
    });
    expect(res.status).toBe(201);
    const page = await stack.browser().get("/login");
    const html = await expectPage(page, 200, "Sign in", "com.example.notes: https://app.notes.example.com https://notes.example.com");
    // It is open, so the callout shows.
    expect(textOf(expectTag(html, "a", { href: "/signup?return_to=%2Faccount" }).inner)).toBe("Create an account");
  });
});
