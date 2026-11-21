import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { randomBytes } from "node:crypto";
import { SoftAuthenticator } from "../src/testing/authenticator";
import { Browser, enabled, fromBase32, linkIn, newId, Stack, totp, waitFor, type Mail, type ServerProcess, type TestUser } from "./harness";

// The emails auth sends and how it sends them (docs/DESIGN.md §9.1, §11;
// docs/DEPLOYMENT.md §3): every message in full, the SMTP conversation as a
// server sees it, what a failure does, and the alert webhook.

setDefaultTimeout(30_000);

const PASSWORD = "correct horse battery";
const TOKEN = "[A-Za-z0-9_-]{43}";
const unique = (prefix: string) => `${prefix}-${randomBytes(3).toString("hex")}`;
const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// The text of a message whose one link carries a token: `<LINK>` marks it.
function withLink(text: string, link: string): RegExp {
  return new RegExp(`^${escape(text).replace("<LINK>", `${escape(link)}\\?token=${TOKEN}`)}$`);
}

function notice(username: string, change: string, detail?: string): string {
  return [`On the account "${username}": ${change}.`, ...(detail ? ["", detail] : []), "", "If this wasn't you, reset your password and contact an administrator."].join("\n");
}

function expectMail(mail: Mail, to: string, subject: string, text: string | RegExp): void {
  expect(mail.to).toEqual([to]);
  expect(mail.from).toBe("auth@example.com");
  expect(mail.headers.to).toBe(to);
  expect(mail.headers.from).toBe("Auth <auth@example.com>");
  expect(mail.subject).toBe(subject);
  expect(mail.headers.subject).toBe(subject);
  if (typeof text === "string") expect(mail.text).toBe(text);
  else expect(mail.text).toMatch(text);
}

// A Browser that talks to another copy of the server on the same database.
function browserOn(stack: Stack, copy: ServerProcess, from?: Browser): Browser {
  const view = Object.create(stack) as Stack;
  Object.defineProperty(view, "url", { value: copy.url });
  const browser = new Browser(view);
  for (const [k, v] of from?.cookies ?? []) browser.cookies.set(k, v);
  return browser;
}

describe.skipIf(!enabled)("email", () => {
  let stack: Stack;
  let admin: { user: TestUser; browser: Browser };
  beforeAll(async () => {
    stack = await Stack.start();
    admin = await stack.admin();
  });
  afterAll(async () => {
    await stack.stop();
  });
  beforeEach(async () => {
    await stack.resetLimits();
    stack.smtp.replies = {};
    stack.smtp.advertiseAuth = false;
  });

  describe("every message, in full", () => {
    test("activation, from an administrator creating a person", async () => {
      const username = unique("act");
      const email = `${username}@example.com`;
      const res = await admin.browser.api("POST", "/v1/users", { username, email });
      expect(res.status).toBe(201);
      const mail = await stack.smtp.waitFor(email);
      expectMail(
        mail,
        email,
        "Activate your account",
        withLink(
          [
            `An account with the username "${username}" was created for you.`,
            "",
            "Set your password with this link. It works once and expires in 14 days:",
            "<LINK>",
            "",
            "If you didn't expect this, ignore this message.",
          ].join("\n"),
          `${stack.issuer}/activate`,
        ),
      );
      const page = await stack.browser().get(linkIn(mail).pathname + linkIn(mail).search);
      expect(page.status).toBe(200);
      await page.body?.cancel();
    });

    test("invitation", async () => {
      const email = `${unique("inv")}@example.com`;
      const res = await admin.browser.api("POST", "/v1/invites", { email, service: "wiki", role: "member" });
      expect(res.status).toBe(201);
      const mail = await stack.smtp.waitFor(email);
      expectMail(
        mail,
        email,
        "You're invited to wiki",
        withLink(
          [
            "You've been invited to use wiki.",
            "",
            "Accept with this link, creating an account or using the one you have. It works once and expires in 14 days:",
            "<LINK>",
            "",
            "If you didn't expect this, ignore this message.",
          ].join("\n"),
          `${stack.issuer}/invite`,
        ),
      );
    });

    const RESET = [
      "Someone asked to reset the password of the account that uses this address.",
      "",
      "Choose a new password with this link. It works once and expires in 30 minutes:",
      "<LINK>",
      "",
      "If it wasn't you, ignore this message: your password stays as it is.",
    ].join("\n");

    test("reset, then the notice of the reset", async () => {
      const user = await stack.user({ username: unique("reset") });
      const res = await stack.browser().form("/reset", { login: user.username });
      expect(res.status).toBe(200);
      const mail = await stack.smtp.waitFor(user.email!, (m) => m.subject === "Reset your password");
      expectMail(mail, user.email!, "Reset your password", withLink(RESET, `${stack.issuer}/reset/confirm`));
      const token = linkIn(mail).searchParams.get("token")!;
      const done = await stack.browser().form("/reset/confirm", { token, password: "a fresh horse battery" });
      expect(done.status).toBe(303);
      const n = await stack.smtp.waitFor(user.email!, (m) => m.subject === "Security notice: password reset");
      expectMail(n, user.email!, "Security notice: password reset", notice(user.username, "password reset"));
    });

    test("reset from an administrator", async () => {
      const user = await stack.user({ username: unique("reset") });
      expect((await admin.browser.api("POST", `/v1/users/${user.id}/reset`, { send_link: true })).status).toBe(204);
      const mail = await stack.smtp.waitFor(user.email!);
      expectMail(mail, user.email!, "Reset your password", withLink(RESET, `${stack.issuer}/reset/confirm`));
    });

    test("verify-email, with the notice to the old address", async () => {
      const user = await stack.user({ username: unique("move") });
      const to = `${user.username}-new@example.com`;
      const res = await (await stack.session(user)).api("PATCH", "/v1/me", { email: to });
      expect(res.status).toBe(200);
      const mail = await stack.smtp.waitFor(to);
      expectMail(
        mail,
        to,
        "Confirm your email address",
        withLink(
          ["Confirm that this address is yours with this link. It works once and expires in 24 hours:", "<LINK>", "", "If you didn't ask for this, ignore this message."].join("\n"),
          `${stack.issuer}/verify-email`,
        ),
      );
      const old = await stack.smtp.waitFor(user.email!);
      expectMail(
        old,
        user.email!,
        "Security notice: your email address is changing",
        notice(user.username, "your email address is changing", "A confirmation link went to the new address."),
      );
    });

    test("address-in-use, to the account that has the address", async () => {
      const user = await stack.user({ username: unique("want") });
      const owner = await stack.user({ username: unique("owns") });
      const res = await (await stack.session(user)).api("PATCH", "/v1/me", { email: owner.email!.toUpperCase() });
      expect(res.status).toBe(200);
      const mail = await stack.smtp.waitFor(owner.email!.toUpperCase());
      expectMail(
        mail,
        owner.email!.toUpperCase(),
        "Your address was used for another account",
        ["Someone tried to use this address for an account, but it already belongs to yours.", "Nothing changed. If it was you, sign in to the account you have."].join("\n"),
      );
      await stack.smtp.waitFor(user.email!, (m) => m.subject === "Security notice: your email address is changing");
    });

    test("an administrator changing an address tells the old one, and activates at the new one", async () => {
      const user = await stack.user({ username: unique("admmove"), password: null });
      const to = `${user.username}-new@example.com`;
      expect((await admin.browser.api("PATCH", `/v1/users/${user.id}`, { email: to })).status).toBe(200);
      const old = await stack.smtp.waitFor(user.email!);
      expectMail(old, user.email!, "Security notice: your email address is changing", notice(user.username, "your email address is changing", "An administrator changed it."));
      const fresh = await stack.smtp.waitFor(to);
      expect(fresh.subject).toBe("Activate your account");
    });

    describe("security notices", () => {
      const noticeTo = async (user: TestUser, change: string, detail?: string) => {
        const subject = `Security notice: ${change}`;
        const mail = await stack.smtp.waitFor(user.email!, (m) => m.subject === subject);
        expectMail(mail, user.email!, subject, notice(user.username, change, detail));
      };

      test("password changed", async () => {
        const user = await stack.user({ username: unique("pw") });
        const res = await (await stack.session(user)).api("POST", "/v1/me/password", { current: PASSWORD, new: "a brand new horse battery" });
        expect(res.status).toBe(204);
        await noticeTo(user, "password changed");
      });

      test("password reset with a recovery code, and the code's use", async () => {
        const user = await stack.user({ username: unique("rec"), totp: true, recoveryCodes: 2 });
        const res = await stack.browser().form("/reset", { action: "recovery", login: user.username, password: "a fresh horse battery", code: user.recoveryCodes[0]! });
        expect(res.status).toBe(303);
        await noticeTo(user, "password reset");
        await noticeTo(user, "a recovery code was used");
      });

      test("two-factor authentication added", async () => {
        const user = await stack.user({ username: unique("totp") });
        const browser = await stack.session(user);
        const start = (await (await browser.api("POST", "/v1/me/totp", {})).json()) as { secret: string; enrollment: string };
        const res = await browser.api("POST", "/v1/me/totp", { enrollment: start.enrollment, code: totp(fromBase32(start.secret)) });
        expect(res.status).toBe(200);
        await noticeTo(user, "two-factor authentication added");
      });

      test("two-factor authentication removed", async () => {
        const user = await stack.user({ username: unique("untotp"), totp: true });
        const res = await (await stack.session(user, { amr: ["pwd", "otp", "mfa"] })).api("DELETE", "/v1/me/totp");
        expect(res.status).toBe(204);
        await noticeTo(user, "two-factor authentication removed");
      });

      test("recovery codes regenerated", async () => {
        const user = await stack.user({ username: unique("codes"), totp: true });
        const res = await (await stack.session(user, { amr: ["pwd", "otp", "mfa"] })).api("POST", "/v1/me/recovery-codes");
        expect(res.status).toBe(200);
        await noticeTo(user, "recovery codes regenerated");
      });

      test("a recovery code was used, to sign in", async () => {
        const user = await stack.user({ username: unique("use"), totp: true, recoveryCodes: 1 });
        const res = await stack.browser().signIn(user.username, PASSWORD, user.recoveryCodes[0]!);
        expect(res.status).toBe(303);
        await noticeTo(user, "a recovery code was used");
      });

      test("a passkey was added, named", async () => {
        const user = await stack.user({ username: unique("pkadd") });
        const browser = await stack.session(user);
        const start = (await (await browser.api("POST", "/v1/me/passkeys", {})).json()) as { options: any; registration: string };
        const authenticator = new SoftAuthenticator();
        const response = authenticator.create(start.options, stack.issuer);
        const res = await browser.api("POST", "/v1/me/passkeys", { registration: start.registration, response, name: "Work laptop" });
        expect(res.status).toBe(201);
        await noticeTo(user, "a passkey was added", "Name: Work laptop");
      });

      test("a passkey was removed, named", async () => {
        const user = await stack.user({ username: unique("pkdel") });
        const id = newId("pk");
        await stack.db`INSERT INTO passkeys (id, user_id, credential_id, public_key, name) VALUES (${id}, ${user.id}, ${randomBytes(16)}, ${Buffer.from([0xa0])}, 'Old key')`;
        const res = await (await stack.session(user, { amr: ["pwd", "mfa"] })).api("DELETE", `/v1/me/passkeys/${id}`);
        expect(res.status).toBe(204);
        await noticeTo(user, "a passkey was removed", "Name: Old key");
      });

      test("an app password was created", async () => {
        const user = await stack.user({ username: unique("apw"), access: { mailbox: "user" } });
        const res = await (await stack.session(user)).api("POST", "/v1/me/app-passwords", { service: "mailbox", scopes: ["imap"], name: "Phone" });
        expect(res.status).toBe(201);
        await noticeTo(user, "an app password was created", "For mailbox: Phone");
      });

      test("an API key was created", async () => {
        const user = await stack.user({ username: unique("key"), access: { tasks: "user" } });
        const res = await (await stack.session(user)).api("POST", "/v1/me/api-keys", { service: "tasks", scopes: ["tasks:read"], name: "CI" });
        expect(res.status).toBe(201);
        await noticeTo(user, "an API key was created", "For tasks: CI");
      });

      test("a sign-in from a new device, naming the browser and the address", async () => {
        const user = await stack.user({ username: unique("device") });
        await stack.db`INSERT INTO audit (actor, action, user_id, detail) VALUES (${user.id}, 'login.ok', ${user.id}, '{"device": "elsewhere"}')`;
        const browser = stack.browser();
        const res = await browser.form("/login", { login: user.username, password: PASSWORD, return_to: "/account" }, { headers: { "User-Agent": "Example Browser/1.0" } });
        expect(res.status).toBe(303);
        await noticeTo(user, "a sign-in from a new device", `Browser: Example Browser/1.0\nAddress: ${browser.ip}`);
      });

      test("a first sign-in, or one from a known device, sends no notice", async () => {
        const user = await stack.user({ username: unique("first") });
        const browser = stack.browser();
        expect((await browser.signIn(user.username, PASSWORD)).status).toBe(303);
        expect((await browser.signIn(user.username, PASSWORD)).status).toBe(303);
        // A marker that would arrive after any notice.
        await (await stack.session(user)).api("POST", "/v1/me/password", { current: PASSWORD, new: "a brand new horse battery" });
        await stack.smtp.waitFor(user.email!, (m) => m.subject === "Security notice: password changed");
        expect(stack.smtp.to(user.email!).map((m) => m.subject)).toEqual(["Security notice: password changed"]);
      });

      test("two-factor authentication was cleared by an administrator", async () => {
        const user = await stack.user({ username: unique("clear"), totp: true });
        expect((await admin.browser.api("POST", `/v1/users/${user.id}/reset`, { clear_mfa: true })).status).toBe(204);
        await noticeTo(user, "two-factor authentication was cleared by an administrator");
      });
    });
  });

  describe("the SMTP conversation", () => {
    // One message, sent alone: what the sink saw on its connection.
    const sendOne = async () => {
      const user = await stack.user({ username: unique("smtp") });
      const before = stack.smtp.commands.length;
      expect((await stack.browser().form("/reset", { login: user.username })).status).toBe(200);
      const mail = await stack.smtp.waitFor(user.email!);
      await waitFor(() => stack.smtp.commands.slice(before).includes("QUIT"), "the QUIT");
      return { user, mail, commands: stack.smtp.commands.slice(before) };
    };

    test("EHLO with the sender's domain, the envelope, and QUIT", async () => {
      const { user, mail, commands } = await sendOne();
      expect(commands).toEqual(["EHLO example.com", "MAIL FROM:<auth@example.com>", `RCPT TO:<${user.email}>`, "DATA", "QUIT"]);
      expect(mail.helo).toBe("example.com");
      expect(mail.auth).toBeNull();
    });

    test("the headers and a base64 body in lines of at most 76", async () => {
      const { user, mail } = await sendOne();
      const split = mail.raw.indexOf("\r\n\r\n");
      const head = mail.raw.slice(0, split).split("\r\n");
      expect(head.map((l) => l.slice(0, l.indexOf(":")))).toEqual(["From", "To", "Subject", "Date", "Message-ID", "MIME-Version", "Content-Type", "Content-Transfer-Encoding"]);
      expect(mail.headers.from).toBe("Auth <auth@example.com>");
      expect(mail.headers.to).toBe(user.email!);
      expect(mail.headers.subject).toBe("Reset your password");
      expect(mail.headers.date).toMatch(/^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d\d (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d\d:\d\d:\d\d \+0000$/);
      expect(Math.abs(new Date(mail.headers.date!.replace("+0000", "GMT")).getTime() - Date.now())).toBeLessThan(60_000);
      expect(mail.headers["message-id"]).toMatch(/^<[0-9a-f]{32}@example\.com>$/);
      expect(mail.headers["mime-version"]).toBe("1.0");
      expect(mail.headers["content-type"]).toBe("text/plain; charset=utf-8");
      expect(mail.headers["content-transfer-encoding"]).toBe("base64");
      const body = mail.raw.slice(split + 4).split("\r\n");
      expect(body.length).toBeGreaterThan(1);
      for (const line of body) expect(line).toMatch(/^[A-Za-z0-9+/=]{1,76}$/);
      for (const line of body.slice(0, -1)) expect(line).toHaveLength(76);
      // The text's line ends are CRLF.
      const decoded = Buffer.from(body.join(""), "base64").toString("utf8");
      expect(decoded).toContain("\r\n\r\n");
      expect(decoded.replace(/\r\n/g, "")).not.toContain("\n");
      expect(decoded.replace(/\r\n/g, "\n")).toBe(mail.text);
    });

    test("each message has its own Message-ID", async () => {
      const a = (await sendOne()).mail;
      const b = (await sendOne()).mail;
      expect(a.headers["message-id"]).not.toBe(b.headers["message-id"]);
    });

    test("a long non-ASCII sender name is RFC 2047 encoded words, folded", async () => {
      const name = "Ünïcødé Authentication Service — Example Organisation";
      const copy = await stack.spawn({ env: { EMAIL_FROM: `${name} <auth@mail.example.com>` } });
      try {
        await copy.ready();
        const user = await stack.user({ username: unique("utf") });
        const before = stack.smtp.commands.length;
        const res = await browserOn(stack, copy).form("/reset", { login: user.username });
        expect(res.status).toBe(200);
        const mail = await stack.smtp.waitFor(user.email!);
        const fromLine = /^From: ((?:.|\r\n )*)\r\n/m.exec(mail.raw)![1]!;
        const words = fromLine.replace(/ <auth@mail\.example\.com>$/, "").split("\r\n ");
        expect(words.length).toBeGreaterThan(1);
        for (const word of words) {
          expect(word).toMatch(/^=\?UTF-8\?B\?[A-Za-z0-9+/=]+\?=$/);
          expect(word.length).toBeLessThanOrEqual(75);
        }
        const decoded = Buffer.concat(words.map((w) => Buffer.from(w.slice(10, -2), "base64")));
        expect(decoded.toString("utf8")).toBe(name);
        // Each word is whole characters.
        for (const w of words) expect(Buffer.from(w.slice(10, -2), "base64").toString("utf8")).not.toContain("\uFFFD");
        expect(mail.from).toBe("auth@mail.example.com");
        expect(stack.smtp.commands.slice(before)[0]).toBe("EHLO mail.example.com");
        expect(mail.headers["message-id"]).toMatch(/^<[0-9a-f]{32}@mail\.example\.com>$/);
      } finally {
        await copy.stop();
      }
    });

    describe("AUTH PLAIN", () => {
      const withCredentials = async () => {
        const copy = await stack.spawn({ env: { SMTP_URL: `smtp://mailer%40example.com:s3cret-pw@127.0.0.1:${stack.smtp.port}` } });
        await copy.ready();
        return copy;
      };

      test("when SMTP_URL carries credentials and the server offers it", async () => {
        stack.smtp.advertiseAuth = true;
        const copy = await withCredentials();
        try {
          const user = await stack.user({ username: unique("auth") });
          const before = stack.smtp.commands.length;
          expect((await browserOn(stack, copy).form("/reset", { login: user.username })).status).toBe(200);
          const mail = await stack.smtp.waitFor(user.email!);
          expect(mail.auth).toEqual({ username: "mailer@example.com", password: "s3cret-pw" });
          const commands = stack.smtp.commands.slice(before);
          expect(commands[0]).toBe("EHLO example.com");
          expect(commands[1]).toBe(`AUTH PLAIN ${Buffer.from("\0mailer@example.com\0s3cret-pw").toString("base64")}`);
          expect(commands[2]).toBe("MAIL FROM:<auth@example.com>");
          expect(copy.logText()).not.toContain("s3cret-pw");
        } finally {
          await copy.stop();
        }
      });

      test("refused, and logged, when the server doesn't offer it", async () => {
        const copy = await withCredentials();
        try {
          const user = await stack.user({ username: unique("noauth") });
          const before = stack.smtp.commands.length;
          expect((await browserOn(stack, copy).form("/reset", { login: user.username })).status).toBe(200);
          await waitFor(() => copy.logs.includes("email failed: smtp: the server does not offer AUTH PLAIN"), "the log line");
          expect(stack.smtp.commands.slice(before)).toEqual(["EHLO example.com"]);
          expect(stack.smtp.to(user.email!)).toEqual([]);
          expect(copy.logText()).not.toContain("s3cret-pw");
        } finally {
          await copy.stop();
        }
      });

      test("an AUTH the server refuses is logged by its code", async () => {
        stack.smtp.advertiseAuth = true;
        stack.smtp.replies = { AUTH: "535 5.7.8 bad credentials" };
        const copy = await withCredentials();
        try {
          const user = await stack.user({ username: unique("badauth") });
          expect((await browserOn(stack, copy).form("/reset", { login: user.username })).status).toBe(200);
          await waitFor(() => copy.logs.includes("email failed: smtp: server answered 535 to AUTH"), "the log line");
          expect(copy.logText()).not.toContain("s3cret-pw");
        } finally {
          await copy.stop();
        }
      });
    });
  });

  describe("failures", () => {
    test.each([
      ["greeting", "554 5.3.2 not now", "554 to the greeting"],
      ["greeting", "421 busy", "421 to the greeting"],
      ["EHLO", "502 5.5.1 no", "502 to EHLO"],
      ["MAIL", "550 5.7.1 sender refused", "550 to MAIL"],
      ["RCPT", "550 5.1.1 no such user", "550 to RCPT"],
      ["DATA", "554 5.5.1 no", "554 to DATA"],
      ["message", "552 5.3.4 too big", "552 to the message"],
    ] as const)("a %s answered %p is logged, the request still succeeds, and the next mail goes out", async (stage, reply, logged) => {
      stack.smtp.replies = { [stage]: reply };
      const user = await stack.user({ username: unique("fail") });
      const before = stack.logs.length;
      const res = await stack.browser().form("/reset", { login: user.username });
      expect(res.status).toBe(200);
      expect(await res.text()).toContain("If an account uses that name or address");
      const line = `email failed: smtp: server answered ${logged}`;
      await waitFor(() => stack.logs.slice(before).includes(line), "the log line");
      const lines = stack.logs.slice(before).join("\n");
      expect(lines).not.toContain("token=");
      expect(lines).not.toContain("/reset/confirm");
      expect(lines).not.toContain(user.email!);
      expect(lines).not.toContain("Someone asked");
      expect(stack.smtp.to(user.email!)).toEqual([]);

      // The next one goes out.
      stack.smtp.replies = {};
      const next = await stack.user({ username: unique("next") });
      await stack.browser().form("/reset", { login: next.username });
      await stack.smtp.waitFor(next.email!);
    });

    test("an API request that mails answers the same whether or not the mail went out", async () => {
      stack.smtp.replies = { RCPT: "550 no" };
      const user = await stack.user({ username: unique("api") });
      const before = stack.logs.length;
      const res = await (await stack.session(user)).api("PATCH", "/v1/me", { email: `${user.username}-new@example.com` });
      expect(res.status).toBe(200);
      await waitFor(() => stack.logs.slice(before).filter((l) => l === "email failed: smtp: server answered 550 to RCPT").length === 2, "both failures");
      expect(stack.logs.slice(before).join("\n")).not.toContain("verify-email");
    });
  });
});

describe.skipIf(!enabled)("alerts", () => {
  let stack: Stack;
  let admin: { user: TestUser; browser: Browser };
  // A webhook of the test's own, which keeps every request whole.
  const received: { method: string; path: string; contentType: string | null; body: string }[] = [];
  let answer: (path: string) => Response = () => new Response(null, { status: 200 });
  let hook: ReturnType<typeof Bun.serve>;
  beforeAll(async () => {
    hook = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch: async (req) => {
        const url = new URL(req.url);
        received.push({ method: req.method, path: url.pathname, contentType: req.headers.get("Content-Type"), body: await req.text() });
        return answer(url.pathname);
      },
    });
    stack = await Stack.start();
    admin = await stack.admin();
  });
  afterAll(async () => {
    await stack.stop();
    await hook.stop(true);
  });

  const hookUrl = () => `http://127.0.0.1:${hook.port}/hooks/abc123`;
  // A copy alerting to the test's webhook, and an admin action through it.
  const alertVia = async (copy: ServerProcess) => {
    const user = await stack.user({ username: unique("target") });
    const res = await browserOn(stack, copy, admin.browser).api("PATCH", `/v1/users/${user.id}`, { disabled: true });
    expect(res.status).toBe(200);
    return `auth: ${admin.user.username} disabled ${user.username}`;
  };

  test('posts {"text": …} as JSON, and never logs the URL', async () => {
    answer = () => new Response(null, { status: 204 });
    const copy = await stack.spawn({ env: { ALERT_WEBHOOK_URL: hookUrl() } });
    try {
      await copy.ready();
      const text = await alertVia(copy);
      const got = await waitFor(() => received.find((r) => r.body.includes(text)), "the alert");
      expect(got.method).toBe("POST");
      expect(got.path).toBe("/hooks/abc123");
      expect(got.contentType).toBe("application/json");
      expect(JSON.parse(got.body)).toEqual({ text });
      expect(copy.logText()).not.toContain("abc123");
    } finally {
      await copy.stop();
    }
  });

  test("a non-2xx answer is logged by its status, and the URL never", async () => {
    answer = () => new Response("nope", { status: 503 });
    const copy = await stack.spawn({ env: { ALERT_WEBHOOK_URL: hookUrl() } });
    try {
      await copy.ready();
      const text = await alertVia(copy);
      await waitFor(() => received.find((r) => r.body.includes(text)), "the alert");
      await waitFor(() => copy.logs.includes("alert webhook answered 503"), "the log line");
      expect(copy.logText()).not.toContain("abc123");
    } finally {
      await copy.stop();
    }
  });

  test("a redirect is not followed", async () => {
    answer = (path) => (path === "/hooks/abc123" ? new Response(null, { status: 302, headers: { Location: `http://127.0.0.1:${hook.port}/moved` } }) : new Response(null, { status: 200 }));
    const copy = await stack.spawn({ env: { ALERT_WEBHOOK_URL: hookUrl() } });
    try {
      await copy.ready();
      const text = await alertVia(copy);
      await waitFor(() => received.find((r) => r.body.includes(text)), "the alert");
      await waitFor(() => copy.logs.includes("alert webhook answered 302"), "the log line");
      expect(received.filter((r) => r.path === "/moved")).toEqual([]);
      expect(copy.logText()).not.toContain("abc123");
    } finally {
      await copy.stop();
    }
  });

  test("an unreachable webhook is logged without the URL", async () => {
    const closed = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => new Response() });
    const port = closed.port;
    await closed.stop(true);
    const copy = await stack.spawn({ env: { ALERT_WEBHOOK_URL: `http://127.0.0.1:${port}/hooks/abc123` } });
    try {
      await copy.ready();
      await alertVia(copy);
      await waitFor(() => copy.logs.some((l) => l.startsWith("alert webhook failed: ")), "the log line");
      expect(copy.logText()).not.toContain("abc123");
    } finally {
      await copy.stop();
    }
  });

  test("a deployment without ALERT_WEBHOOK_URL raises nothing", async () => {
    const copy = await stack.spawn({ env: { ALERT_WEBHOOK_URL: undefined } });
    try {
      await copy.ready();
      const silent = await alertVia(copy);
      // A marker through the stack's own webhook, which would arrive after.
      const user = await stack.user({ username: unique("marker") });
      expect((await admin.browser.api("PATCH", `/v1/users/${user.id}`, { disabled: true })).status).toBe(200);
      await stack.http.waitForAlert(`auth: ${admin.user.username} disabled ${user.username}`);
      expect(stack.alerts).not.toContain(silent);
      expect(received.filter((r) => r.body.includes(silent))).toEqual([]);
      expect(copy.logs.filter((l) => l.startsWith("alert webhook"))).toEqual([]);
    } finally {
      await copy.stop();
    }
  });
});
