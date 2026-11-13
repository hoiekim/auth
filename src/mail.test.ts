import { afterAll, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import tls from "node:tls";
import { isEmailAddress, parseFrom, parseSmtpUrl, smtpMailer, type SmtpSettings } from "./mail";

interface FakeOptions {
  greet?: boolean;
  extensions?: string[];
  // An answer for a command line, or undefined for the default one.
  answer?: (line: string) => string | undefined;
  tlsCert?: { key: string; cert: string };
}

interface Fake {
  port: number;
  connections: number;
  // Command lines in the order received; those sent over TLS start "tls ".
  commands: string[];
  messages: string[];
  closed: Promise<void>;
  stop(): void;
}

// A scripted SMTP server on 127.0.0.1 that records what the client sends.
async function fakeSmtp(opts: FakeOptions = {}): Promise<Fake> {
  let markClosed = () => {};
  const fake: Fake = {
    port: 0,
    connections: 0,
    commands: [],
    messages: [],
    closed: new Promise<void>((resolve) => (markClosed = resolve)),
    stop: () => server.close(),
  };
  const server = net.createServer((socket) => {
    fake.connections++;
    socket.on("close", () => markClosed());
    serve(socket, false);
    if (opts.greet !== false) socket.write("220 fake.test ESMTP\r\n");
  });

  function serve(stream: net.Socket, overTls: boolean) {
    let buffer = "";
    let inData = false;
    const send = (text: string) => stream.write(`${text}\r\n`);
    const onData = (chunk: Buffer) => {
      buffer += chunk.toString("latin1");
      for (;;) {
        if (inData) {
          const end = buffer.indexOf("\r\n.\r\n");
          if (end < 0) return;
          fake.messages.push(buffer.slice(0, end));
          buffer = buffer.slice(end + 5);
          inData = false;
          send(opts.answer?.("<message>") ?? "250 queued");
          continue;
        }
        const end = buffer.indexOf("\r\n");
        if (end < 0) return;
        const line = buffer.slice(0, end);
        buffer = buffer.slice(end + 2);
        fake.commands.push(overTls ? `tls ${line}` : line);
        const custom = opts.answer?.(line);
        if (custom !== undefined) {
          stream.write(`${custom}\r\n`);
          continue;
        }
        const verb = (line.split(" ")[0] ?? "").toUpperCase();
        if (verb === "EHLO") {
          const extensions = [...(opts.extensions ?? []), ...(opts.tlsCert && !overTls ? ["STARTTLS"] : [])];
          const all = ["fake.test", ...extensions];
          all.forEach((text, i) => send(`250${i === all.length - 1 ? " " : "-"}${text}`));
        } else if (verb === "STARTTLS" && opts.tlsCert && !overTls) {
          send("220 go ahead");
          stream.off("data", onData);
          const secure = new tls.TLSSocket(stream, { isServer: true, key: opts.tlsCert.key, cert: opts.tlsCert.cert });
          secure.on("error", () => {});
          serve(secure, true);
          return;
        } else if (verb === "AUTH") send("235 ok");
        else if (verb === "MAIL" || verb === "RCPT") send("250 ok");
        else if (verb === "DATA") {
          inData = true;
          send("354 go on");
        } else if (verb === "QUIT") {
          send("221 bye");
          stream.end();
        } else send("502 unknown");
      }
    };
    stream.on("data", onData);
    stream.on("error", () => {});
  }

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  fake.port = (server.address() as net.AddressInfo).port;
  return fake;
}

const plain = (port: number, extra: Partial<SmtpSettings> = {}): SmtpSettings => ({
  host: "127.0.0.1",
  port,
  secure: "none",
  ...extra,
});

const FROM = "Example Auth <auth@example.com>";
const LINK = "https://auth.example.com/reset?token=abc123";

async function rejection(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
  throw new Error("the send succeeded");
}

function headersAndBody(message: string): { headers: Map<string, string>; body: string[] } {
  const split = message.indexOf("\r\n\r\n");
  const headers = new Map<string, string>();
  for (const field of message.slice(0, split).split(/\r\n(?![ \t])/)) {
    const colon = field.indexOf(":");
    headers.set(field.slice(0, colon), field.slice(colon + 1).trim());
  }
  return { headers, body: message.slice(split + 4).split("\r\n") };
}

function decodeWords(value: string): string {
  const words = value.split(/\r\n /);
  return words
    .map((word) => {
      const match = /^=\?UTF-8\?B\?([A-Za-z0-9+/=]+)\?=$/.exec(word);
      if (!match) throw new Error(`not an encoded word: ${word}`);
      return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(match[1] ?? "", "base64"));
    })
    .join("");
}

const fakes: Fake[] = [];
async function started(opts?: FakeOptions): Promise<Fake> {
  const fake = await fakeSmtp(opts);
  fakes.push(fake);
  return fake;
}
afterAll(() => fakes.forEach((f) => f.stop()));

describe("smtpMailer over plain SMTP on loopback", () => {
  test("sends the envelope, the headers and a base64 body, with CRLF line endings", async () => {
    const fake = await started();
    const text = "Someone asked to reset your password.\n\nOpen this link:\n" + LINK + "\n";
    await smtpMailer(plain(fake.port), FROM).send({ to: "alice@example.com", subject: "Reset your password", text });
    await fake.closed;

    expect(fake.commands).toEqual(["EHLO example.com", "MAIL FROM:<auth@example.com>", "RCPT TO:<alice@example.com>", "DATA", "QUIT"]);
    expect(fake.messages).toHaveLength(1);
    const message = fake.messages[0] ?? "";
    expect(message.replace(/\r\n/g, "")).not.toMatch(/[\r\n]/);

    const { headers, body } = headersAndBody(message);
    expect(headers.get("From")).toBe("Example Auth <auth@example.com>");
    expect(headers.get("To")).toBe("alice@example.com");
    expect(headers.get("Subject")).toBe("Reset your password");
    expect(headers.get("Date")).toMatch(/^[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} \+0000$/);
    expect(headers.get("Message-ID")).toMatch(/^<[0-9a-f]{32}@example\.com>$/);
    expect(headers.get("MIME-Version")).toBe("1.0");
    expect(headers.get("Content-Type")).toBe("text/plain; charset=utf-8");
    expect(headers.get("Content-Transfer-Encoding")).toBe("base64");
    for (const line of body) expect(line.length).toBeLessThanOrEqual(76);
    expect(Buffer.from(body.join(""), "base64").toString("utf8")).toBe(text.replace(/\n/g, "\r\n"));
  });

  test("authenticates with AUTH PLAIN before MAIL when credentials are set", async () => {
    const fake = await started({ extensions: ["AUTH LOGIN PLAIN"] });
    await smtpMailer(plain(fake.port, { username: "alice", password: "s3cret-pw" }), FROM).send({
      to: "bob@example.com",
      subject: "Hi",
      text: "Hello",
    });
    const token = Buffer.from("\0alice\0s3cret-pw").toString("base64");
    expect(fake.commands.slice(0, 3)).toEqual(["EHLO example.com", `AUTH PLAIN ${token}`, "MAIL FROM:<auth@example.com>"]);
  });

  test("refuses to authenticate when the server doesn't offer AUTH PLAIN", async () => {
    const fake = await started({ extensions: ["AUTH LOGIN"] });
    const mailer = smtpMailer(plain(fake.port, { username: "alice", password: "s3cret-pw" }), FROM);
    const message = await rejection(mailer.send({ to: "bob@example.com", subject: "Hi", text: "Hello" }));
    expect(message).toBe("smtp: the server does not offer AUTH PLAIN");
    expect(fake.commands).toEqual(["EHLO example.com"]);
  });

  test("a refused recipient rejects with the code and command only, never the password, the body or the reply", async () => {
    const fake = await started({
      extensions: ["AUTH PLAIN"],
      answer: (line) => (line.startsWith("RCPT") ? "550 5.1.1 no such user s3cret-pw abc123" : undefined),
    });
    const mailer = smtpMailer(plain(fake.port, { username: "alice", password: "s3cret-pw" }), FROM);
    const message = await rejection(mailer.send({ to: "bob@example.com", subject: "Reset", text: `Open ${LINK}` }));
    expect(message).toBe("smtp: server answered 550 to RCPT");
    expect(fake.commands).not.toContain("DATA");
  });

  test("a refused AUTH names the code only", async () => {
    const fake = await started({
      extensions: ["AUTH PLAIN"],
      answer: (line) => (line.startsWith("AUTH") ? "535 5.7.8 bad credentials for s3cret-pw" : undefined),
    });
    const mailer = smtpMailer(plain(fake.port, { username: "alice", password: "s3cret-pw" }), FROM);
    expect(await rejection(mailer.send({ to: "bob@example.com", subject: "Hi", text: LINK }))).toBe(
      "smtp: server answered 535 to AUTH",
    );
    expect(fake.commands.some((c) => c.startsWith("MAIL"))).toBe(false);
  });

  test("a refused message after DATA rejects", async () => {
    const fake = await started({ answer: (line) => (line === "<message>" ? "554 rejected" : undefined) });
    const message = await rejection(smtpMailer(plain(fake.port), FROM).send({ to: "bob@example.com", subject: "Hi", text: LINK }));
    expect(message).toBe("smtp: server answered 554 to the message");
  });

  test("a server that never greets times out", async () => {
    const fake = await started({ greet: false });
    const started_ = performance.now();
    const message = await rejection(
      smtpMailer(plain(fake.port), FROM, { timeoutMs: 100 }).send({ to: "bob@example.com", subject: "Hi", text: "x" }),
    );
    expect(message).toBe("smtp: timed out");
    expect(performance.now() - started_).toBeLessThan(1000);
  });

  test("a refused connection rejects without the address", async () => {
    const fake = await started();
    fake.stop();
    const message = await rejection(smtpMailer(plain(fake.port), FROM).send({ to: "bob@example.com", subject: "Hi", text: "x" }));
    expect(message).toMatch(/^smtp: connection failed( \([A-Z0-9_]+\))?$/);
  });

  test("a line break in the subject is refused before connecting", async () => {
    const fake = await started();
    const mailer = smtpMailer(plain(fake.port), FROM);
    const message = await rejection(mailer.send({ to: "bob@example.com", subject: "Hi\r\nBcc: eve@example.com", text: "x" }));
    expect(message).toBe("smtp: the subject has a line break");
    expect(await rejection(mailer.send({ to: "bob@example.com", subject: "Hi\nthere", text: "x" }))).toBe(
      "smtp: the subject has a line break",
    );
    expect(fake.connections).toBe(0);
  });

  test("a recipient that isn't an address is refused before connecting", async () => {
    const fake = await started();
    const mailer = smtpMailer(plain(fake.port), FROM);
    const message = await rejection(mailer.send({ to: "bob@example.com>\r\nRCPT TO:<eve@example.com", subject: "Hi", text: "x" }));
    expect(message).toBe("smtp: the recipient is not an email address");
    expect(fake.connections).toBe(0);
  });

  test("a non-ASCII subject is sent as RFC 2047 encoded words, split between characters", async () => {
    const fake = await started();
    const subject = "Réinitialisez votre mot de passe — ✓ ".repeat(4).trim();
    await smtpMailer(plain(fake.port), FROM).send({ to: "alice@example.com", subject, text: "x" });
    const raw = /\r\nSubject: (.*?)\r\n(?![ \t])/s.exec(fake.messages[0] ?? "")?.[1] ?? "";
    const words = raw.split("\r\n ");
    expect(words.length).toBeGreaterThan(1);
    for (const word of words) expect(word.length).toBeLessThanOrEqual(75);
    expect(decodeWords(raw)).toBe(subject);
  });
});

describe("smtpMailer with STARTTLS", () => {
  test("refuses to send anything past EHLO when the server doesn't offer STARTTLS", async () => {
    const fake = await started({ extensions: ["AUTH PLAIN"] });
    const settings: SmtpSettings = { host: "127.0.0.1", port: fake.port, secure: "starttls", username: "alice", password: "s3cret-pw" };
    const message = await rejection(smtpMailer(settings, FROM).send({ to: "bob@example.com", subject: "Hi", text: LINK }));
    expect(message).toBe("smtp: the server does not offer STARTTLS");
    expect(fake.commands).toEqual(["EHLO example.com"]);
  });

  test("refuses bytes the server sent after its STARTTLS reply", async () => {
    const fake = await started({
      extensions: ["STARTTLS", "AUTH PLAIN"],
      answer: (line) => (line === "STARTTLS" ? "220 go ahead\r\n250 injected" : undefined),
    });
    const settings: SmtpSettings = { host: "127.0.0.1", port: fake.port, secure: "starttls", username: "alice", password: "s3cret-pw" };
    const mailer = smtpMailer(settings, FROM, { timeoutMs: 1000 });
    const message = await rejection(mailer.send({ to: "bob@example.com", subject: "Hi", text: "x" }));
    expect(message).toBe("smtp: the server sent data after STARTTLS");
    expect(fake.commands).toEqual(["EHLO example.com", "STARTTLS"]);
  });

  const openssl = Bun.which("openssl");
  // The certificate is generated here and lives only for this run.
  describe.skipIf(!openssl)("against a server with a certificate", () => {
    const dir = mkdtempSync(join(tmpdir(), "mail-test-"));
    afterAll(() => rmSync(dir, { recursive: true, force: true }));
    const certificate = () => {
      const made = Bun.spawnSync([
        openssl ?? "openssl",
        "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1",
        "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
        "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem"),
      ]);
      if (made.exitCode !== 0) throw new Error("openssl failed");
      return { key: readFileSync(join(dir, "key.pem"), "utf8"), cert: readFileSync(join(dir, "cert.pem"), "utf8") };
    };

    test("upgrades, says EHLO again, and authenticates only over TLS", async () => {
      const tlsCert = certificate();
      const fake = await started({ extensions: ["AUTH PLAIN"], tlsCert });
      const settings: SmtpSettings = { host: "127.0.0.1", port: fake.port, secure: "starttls", username: "alice", password: "s3cret-pw" };
      await smtpMailer(settings, FROM, { ca: tlsCert.cert }).send({ to: "bob@example.com", subject: "Hi", text: "Hello" });
      const token = Buffer.from("\0alice\0s3cret-pw").toString("base64");
      expect(fake.commands.slice(0, 7)).toEqual([
        "EHLO example.com",
        "STARTTLS",
        "tls EHLO example.com",
        `tls AUTH PLAIN ${token}`,
        "tls MAIL FROM:<auth@example.com>",
        "tls RCPT TO:<bob@example.com>",
        "tls DATA",
      ]);
    });

    test("refuses a certificate it doesn't trust, before sending credentials", async () => {
      const fake = await started({ extensions: ["AUTH PLAIN"], tlsCert: certificate() });
      const settings: SmtpSettings = { host: "127.0.0.1", port: fake.port, secure: "starttls", username: "alice", password: "s3cret-pw" };
      const message = await rejection(smtpMailer(settings, FROM).send({ to: "bob@example.com", subject: "Hi", text: "x" }));
      expect(message).toMatch(/^smtp: connection failed/);
      expect(message).not.toContain("s3cret-pw");
      expect(fake.commands.filter((c) => c.startsWith("tls "))).toEqual([]);
    });
  });
});

describe("smtpMailer settings", () => {
  test("plain SMTP to a host that isn't loopback is refused", () => {
    expect(() => smtpMailer({ host: "mail.example.com", port: 25, secure: "none" }, FROM)).toThrow(
      "smtp: plain SMTP is allowed only to a loopback host",
    );
  });

  test("a sender that isn't an address is refused", () => {
    expect(() => smtpMailer(plain(25), "Example Auth <not-an-address>")).toThrow(/^EMAIL_FROM/);
  });
});

describe("parseSmtpUrl", () => {
  test.each([
    ["smtps://mail.example.com", { host: "mail.example.com", port: 465, secure: "implicit" }],
    ["smtp://mail.example.com", { host: "mail.example.com", port: 587, secure: "starttls" }],
    ["smtp://mail.example.com/", { host: "mail.example.com", port: 587, secure: "starttls" }],
    ["smtps://MAIL.Example.COM:2465", { host: "mail.example.com", port: 2465, secure: "implicit" }],
    ["smtp://localhost:1025", { host: "localhost", port: 1025, secure: "none" }],
    ["smtp://127.0.0.1:2525", { host: "127.0.0.1", port: 2525, secure: "none" }],
    ["smtp://[::1]:25", { host: "::1", port: 25, secure: "none" }],
    ["smtps://localhost", { host: "localhost", port: 465, secure: "implicit" }],
    [
      "smtp://alice%40example.com:p%40ss%3Aword@mail.example.com:2587",
      { host: "mail.example.com", port: 2587, secure: "starttls", username: "alice@example.com", password: "p@ss:word" },
    ],
  ])("%s", (url, expected) => {
    expect(parseSmtpUrl(url)).toEqual(expected as SmtpSettings);
  });

  test.each([
    ["not a URL", "smtp:// s3cret-pw"],
    ["another scheme", "http://alice:s3cret-pw@mail.example.com"],
    ["a path", "smtp://alice:s3cret-pw@mail.example.com/x"],
    ["a query", "smtp://alice:s3cret-pw@mail.example.com?tls=off"],
    ["a fragment", "smtp://alice:s3cret-pw@mail.example.com#x"],
    ["a user without a password", "smtp://s3cret-pw@mail.example.com"],
    ["a password without a user", "smtp://:s3cret-pw@mail.example.com"],
    ["a broken percent-escape", "smtp://alice:s3cret-pw%zz@mail.example.com"],
    ["port 0", "smtp://alice:s3cret-pw@mail.example.com:0"],
    ["a NUL in the password", "smtp://alice:s3cret-pw%00@mail.example.com"],
    ["no host", "smtp://alice:s3cret-pw@:25"],
  ])("refuses %s without echoing it", (_, url) => {
    let message = "";
    try {
      parseSmtpUrl(url);
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toMatch(/^SMTP_URL /);
    expect(message).not.toContain("s3cret-pw");
  });
});

describe("isEmailAddress", () => {
  test.each(["alice@example.com", "a.b+c@sub.example.com", "o'brien@example.co.uk", "x_y-z@ex-ample.test"])("accepts %p", (a) => {
    expect(isEmailAddress(a)).toBe(true);
  });

  test.each([
    "alice@example.com\r\nBcc: x@example.com",
    "alice@example.com\n",
    "alice",
    "@example.com",
    "alice@",
    "al ice@example.com",
    "alice@example",
    "<alice@example.com>",
    "alice@@example.com",
    "a@b@example.com",
    ".alice@example.com",
    "alice.@example.com",
    "al..ice@example.com",
    "alice@-example.com",
    "alice@example..com",
    "alice@1.2.3.4",
    `${"a".repeat(65)}@example.com`,
    `alice@${"a".repeat(250)}.com`,
    '"alice"@example.com',
  ])("refuses %p", (a) => {
    expect(isEmailAddress(a)).toBe(false);
  });
});

describe("parseFrom", () => {
  test.each([
    ["auth@example.com", "auth@example.com", "auth@example.com"],
    ["  auth@example.com  ", "auth@example.com", "auth@example.com"],
    ["Example Auth <auth@example.com>", "auth@example.com", "Example Auth <auth@example.com>"],
    ['"Example, Inc." <auth@example.com>', "auth@example.com", '"Example, Inc." <auth@example.com>'],
    ["Example Inc. <auth@example.com>", "auth@example.com", '"Example Inc." <auth@example.com>'],
    ["<auth@example.com>", "auth@example.com", "auth@example.com"],
  ])("%p", (from, address, header) => {
    expect(parseFrom(from)).toEqual({ address, header });
  });

  test("a non-ASCII name is encoded", () => {
    const { header } = parseFrom("Exämple Äuth <auth@example.com>");
    const match = /^(=\?UTF-8\?B\?[A-Za-z0-9+/=]+\?=) <auth@example\.com>$/.exec(header);
    expect(decodeWords(match?.[1] ?? "")).toBe("Exämple Äuth");
  });

  test.each(["Example <not-an-address>", "", "auth@example.com\r\nBcc: eve@example.com", "Exa\r\nmple <auth@example.com>"])(
    "refuses %p",
    (from) => {
      expect(() => parseFrom(from)).toThrow(/^EMAIL_FROM/);
    },
  );
});
