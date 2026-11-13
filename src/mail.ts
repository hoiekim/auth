import { randomBytes } from "node:crypto";
import net from "node:net";
import tls from "node:tls";

// Sends auth's emails over SMTP with node:net and node:tls alone. A body
// carries one-time links and SMTP_URL can carry a password, so an error names
// the command and the server's reply code, never the conversation, the body
// or the URL.

export interface MailMessage {
  to: string;
  subject: string;
  text: string;
}

export interface Mailer {
  send(msg: MailMessage): Promise<void>;
}

export interface SmtpSettings {
  host: string;
  port: number;
  // implicit: TLS from the first byte. starttls: the server must offer
  // STARTTLS, and nothing else is sent before it. none: no TLS, allowed only
  // to a loopback host.
  secure: "implicit" | "starttls" | "none";
  username?: string;
  password?: string;
}

export interface SmtpOptions {
  timeoutMs?: number;
  heloName?: string;
  // Replaces the system's trusted CAs.
  ca?: string | string[];
}

export class SmtpError extends Error {
  override name = "SmtpError";
}

const DEFAULT_TIMEOUT_MS = 15_000;

export function parseSmtpUrl(value: string): SmtpSettings {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("SMTP_URL is not a well-formed URL");
  }
  if (url.protocol !== "smtp:" && url.protocol !== "smtps:") throw new Error("SMTP_URL must be an smtp:// or smtps:// URL");
  if ((url.pathname !== "" && url.pathname !== "/") || url.search !== "" || url.hash !== "") {
    throw new Error("SMTP_URL must not have a path, a query or a fragment");
  }
  const host = url.hostname.toLowerCase().replace(/^\[(.*)\]$/, "$1");
  if (!isHostName(host) && net.isIP(host) === 0) throw new Error("SMTP_URL has no valid host");
  const implicit = url.protocol === "smtps:";
  const port = url.port === "" ? (implicit ? 465 : 587) : Number(url.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("SMTP_URL has a port out of range");

  let username: string;
  let password: string;
  try {
    username = decodeURIComponent(url.username);
    password = decodeURIComponent(url.password);
  } catch {
    throw new Error("SMTP_URL has a malformed percent-escape");
  }
  if ((username === "") !== (password === "")) throw new Error("SMTP_URL must give both a user and a password, or neither");
  if (username.includes("\0") || password.includes("\0")) throw new Error("SMTP_URL has a NUL byte in its user or password");

  const settings: SmtpSettings = { host, port, secure: implicit ? "implicit" : isLoopback(host) ? "none" : "starttls" };
  if (username !== "") {
    settings.username = username;
    settings.password = password;
  }
  return settings;
}

export function smtpMailer(settings: SmtpSettings, from: string, opts: SmtpOptions = {}): Mailer {
  const sender = parseFrom(from);
  const helo = opts.heloName ?? sender.address.slice(sender.address.lastIndexOf("@") + 1);
  if (!/^(?:[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*|\[[0-9A-Fa-f:.]+\])$/.test(helo)) throw new Error("smtp: the EHLO name is not a host name");
  if (settings.secure === "none" && !isLoopback(settings.host)) {
    throw new Error("smtp: plain SMTP is allowed only to a loopback host");
  }
  if ((settings.username === undefined) !== (settings.password === undefined)) {
    throw new Error("smtp: give both a user and a password, or neither");
  }
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  return {
    async send(msg) {
      if (!isEmailAddress(msg.to)) throw new SmtpError("smtp: the recipient is not an email address");
      if (/[\r\n]/.test(msg.subject)) throw new SmtpError("smtp: the subject has a line break");
      const message = buildMessage(sender, msg);
      await deliver(settings, opts.ca, helo, sender.address, msg.to, message, timeoutMs);
    },
  };
}

const ATOM = "[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+";
const LOCAL_PART = new RegExp(`^${ATOM}(?:\\.${ATOM})*$`);
const DNS_LABEL = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

// Deliberately narrower than RFC 5321: no quoted local parts, no address
// literals, and a domain with at least one dot whose last label has a letter.
export function isEmailAddress(value: string): boolean {
  if (typeof value !== "string" || value.length > 254) return false;
  const at = value.indexOf("@");
  if (at < 1 || at !== value.lastIndexOf("@")) return false;
  const local = value.slice(0, at);
  const labels = value.slice(at + 1).split(".");
  return (
    local.length <= 64 &&
    LOCAL_PART.test(local) &&
    labels.length >= 2 &&
    labels.every((label) => DNS_LABEL.test(label)) &&
    /[A-Za-z]/.test(labels[labels.length - 1] ?? "")
  );
}

export function parseFrom(from: string): { address: string; header: string } {
  const value = from.trim();
  const named = /^(.*?)\s*<([^<>]*)>$/.exec(value);
  const address = named ? (named[2] ?? "") : value;
  let name = named ? (named[1] ?? "").trim() : "";
  if (!isEmailAddress(address)) {
    throw new Error("EMAIL_FROM must be an address, or a name followed by an address in angle brackets");
  }
  if (/^".*"$/.test(name)) name = name.slice(1, -1).replace(/\\(.)/g, "$1");
  if (/[\x00-\x1f\x7f]/.test(name)) throw new Error("EMAIL_FROM's name has a control character");
  if (name === "") return { address, header: address };
  return { address, header: `${displayName(name)} <${address}>` };
}

function displayName(name: string): string {
  if (!/^[\x20-\x7e]*$/.test(name)) return encodedWords(name);
  if (/^[A-Za-z0-9!#$%&'*+/=?^_`{|}~ -]+$/.test(name)) return name;
  return `"${name.replace(/["\\]/g, "\\$&")}"`;
}

function isHostName(host: string): boolean {
  return host.length <= 253 && host.split(".").every((label) => DNS_LABEL.test(label));
}

// An address literal in 127/8, not just text that looks like one: anything
// else would be resolved through DNS and could lead off the host.
function isLoopback(host: string): boolean {
  return host === "localhost" || host === "::1" || (net.isIP(host) === 4 && host.startsWith("127."));
}

function buildMessage(sender: { address: string; header: string }, msg: MailMessage): string {
  const domain = sender.address.slice(sender.address.lastIndexOf("@") + 1);
  const body = Buffer.from(msg.text.replace(/\r\n|\r|\n/g, "\r\n"), "utf8").toString("base64");
  return [
    `From: ${sender.header}`,
    `To: ${msg.to}`,
    `Subject: ${headerText(msg.subject)}`,
    `Date: ${new Date().toUTCString().replace(/GMT$/, "+0000")}`,
    `Message-ID: <${randomBytes(16).toString("hex")}@${domain}>`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "Content-Transfer-Encoding: base64",
    "",
    ...(body.match(/.{1,76}/g) ?? []),
  ].join("\r\n");
}

function headerText(text: string): string {
  return /^[\x20-\x7e]*$/.test(text) && text.length <= 900 ? text : encodedWords(text);
}

// RFC 2047 encoded words of at most 75 characters (45 bytes of UTF-8), split
// between characters, folded onto continuation lines.
function encodedWords(text: string): string {
  const words: string[] = [];
  let chunk: number[] = [];
  const flush = () => words.push(`=?UTF-8?B?${Buffer.from(chunk).toString("base64")}?=`);
  for (const ch of text) {
    const bytes = Buffer.from(ch, "utf8");
    if (chunk.length + bytes.length > 45) {
      flush();
      chunk = [];
    }
    chunk.push(...bytes);
  }
  if (chunk.length > 0) flush();
  return words.join("\r\n ");
}

interface Reply {
  code: number;
  lines: string[];
}

async function deliver(
  settings: SmtpSettings,
  ca: SmtpOptions["ca"],
  helo: string,
  from: string,
  to: string,
  message: string,
  timeoutMs: number,
): Promise<void> {
  let session: Session | undefined;
  const timer = setTimeout(() => session?.abort(new SmtpError("smtp: timed out")), timeoutMs);
  try {
    session = new Session(
      settings.secure === "implicit"
        ? tls.connect({ host: settings.host, port: settings.port, servername: serverName(settings.host), ca })
        : net.connect({ host: settings.host, port: settings.port }),
    );
    expectCode(await session.read(), [220], "the greeting");
    let extensions = await ehlo(session, helo);
    if (settings.secure === "starttls") {
      if (!extensions.has("STARTTLS")) throw new SmtpError("smtp: the server does not offer STARTTLS");
      await command(session, "STARTTLS", "STARTTLS", [220]);
      await session.startTls(settings.host, ca);
      extensions = await ehlo(session, helo);
    }
    if (settings.username !== undefined && settings.password !== undefined) {
      if (!extensions.get("AUTH")?.includes("PLAIN")) throw new SmtpError("smtp: the server does not offer AUTH PLAIN");
      const token = Buffer.from(`\0${settings.username}\0${settings.password}`, "utf8").toString("base64");
      await command(session, `AUTH PLAIN ${token}`, "AUTH", [235]);
    }
    await command(session, `MAIL FROM:<${from}>`, "MAIL", [250]);
    await command(session, `RCPT TO:<${to}>`, "RCPT", [250, 251]);
    await command(session, "DATA", "DATA", [354]);
    await command(session, `${message.replace(/^\./gm, "..")}\r\n.`, "the message", [250]);
    session.quit();
  } catch (e) {
    const error = e instanceof SmtpError ? e : connectionError(e);
    session?.abort(error);
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

async function command(session: Session, line: string, name: string, codes: number[]): Promise<Reply> {
  session.write(`${line}\r\n`);
  const reply = await session.read();
  expectCode(reply, codes, name);
  return reply;
}

function expectCode(reply: Reply, codes: number[], name: string): void {
  if (!codes.includes(reply.code)) throw new SmtpError(`smtp: server answered ${reply.code} to ${name}`);
}

// The extensions EHLO advertises, keyword → parameters, both upper-cased.
async function ehlo(session: Session, helo: string): Promise<Map<string, string[]>> {
  const reply = await command(session, `EHLO ${helo}`, "EHLO", [250]);
  const extensions = new Map<string, string[]>();
  for (const line of reply.lines.slice(1)) {
    const [keyword = "", ...params] = line.trim().toUpperCase().split(/\s+/);
    extensions.set(keyword, params);
  }
  return extensions;
}

function serverName(host: string): string | undefined {
  return net.isIP(host) === 0 ? host : undefined;
}

function connectionError(e: unknown): SmtpError {
  const code = typeof e === "object" && e !== null ? (e as { code?: unknown }).code : undefined;
  return new SmtpError(
    typeof code === "string" && /^[A-Z0-9_]+$/.test(code) ? `smtp: connection failed (${code})` : "smtp: connection failed",
  );
}

const ignore = () => {};
const MAX_REPLY_BYTES = 64 * 1024;
const MAX_QUEUED_REPLIES = 8;

// One SMTP connection, read one reply at a time. The first failure (a socket
// error, the server closing, the timeout) rejects whatever is waiting and
// every later read and write.
class Session {
  private socket: net.Socket;
  private pending = "";
  private lines: string[] = [];
  private linesBytes = 0;
  private replies: Reply[] = [];
  private resolveReply: ((reply: Reply) => void) | undefined;
  private rejectWaiter: ((e: Error) => void) | undefined;
  private failure: Error | undefined;

  constructor(socket: net.Socket) {
    this.socket = socket;
    this.listen();
  }

  read(): Promise<Reply> {
    if (this.failure) return Promise.reject(this.failure);
    const next = this.replies.shift();
    if (next) return Promise.resolve(next);
    return new Promise((resolve, reject) => {
      this.resolveReply = resolve;
      this.rejectWaiter = reject;
    });
  }

  write(data: string): void {
    if (this.failure) throw this.failure;
    this.socket.write(data);
  }

  // Bytes the server sent after its reply to STARTTLS would be read as if
  // they came over TLS, so any are refused.
  async startTls(host: string, ca: SmtpOptions["ca"]): Promise<void> {
    if (this.pending !== "" || this.lines.length > 0 || this.replies.length > 0) {
      throw new SmtpError("smtp: the server sent data after STARTTLS");
    }
    this.unlisten();
    const plain = this.socket;
    plain.on("error", ignore);
    const secure = tls.connect({ socket: plain, servername: serverName(host), ca });
    this.socket = secure;
    this.listen();
    await new Promise<void>((resolve, reject) => {
      if (this.failure) return reject(this.failure);
      this.rejectWaiter = reject;
      secure.once("secureConnect", () => {
        this.rejectWaiter = undefined;
        resolve();
      });
    });
  }

  quit(): void {
    this.unlisten();
    this.socket.on("error", ignore);
    this.socket.end("QUIT\r\n");
    setTimeout(() => this.socket.destroy(), 1000).unref();
  }

  abort(error: Error): void {
    this.fail(error);
    this.unlisten();
    this.socket.on("error", ignore);
    this.socket.destroy();
  }

  private fail(error: Error): void {
    if (this.failure) return;
    this.failure = error;
    const reject = this.rejectWaiter;
    this.resolveReply = undefined;
    this.rejectWaiter = undefined;
    reject?.(error);
  }

  private readonly onData = (chunk: Buffer | string) => {
    this.pending += typeof chunk === "string" ? chunk : chunk.toString("latin1");
    if (this.pending.length > MAX_REPLY_BYTES) return this.abort(new SmtpError("smtp: the server's reply is too long"));
    for (let end = this.pending.indexOf("\n"); end >= 0; end = this.pending.indexOf("\n")) {
      const line = this.pending.slice(0, end).replace(/\r$/, "");
      this.pending = this.pending.slice(end + 1);
      const match = /^(\d{3})(?:([ -])(.*))?$/.exec(line);
      if (!match) return this.abort(new SmtpError("smtp: the server's reply is malformed"));
      // The whole reply is capped, continuation lines included, and so are
      // replies nobody asked for: a server can't make the process buffer
      // without bound.
      this.linesBytes += line.length;
      if (this.linesBytes > MAX_REPLY_BYTES) return this.abort(new SmtpError("smtp: the server's reply is too long"));
      this.lines.push(match[3] ?? "");
      if (match[2] === "-") continue;
      const reply = { code: Number(match[1]), lines: this.lines };
      this.lines = [];
      this.linesBytes = 0;
      const resolve = this.resolveReply;
      if (resolve) {
        this.resolveReply = undefined;
        this.rejectWaiter = undefined;
        resolve(reply);
      } else {
        if (this.replies.length >= MAX_QUEUED_REPLIES) return this.abort(new SmtpError("smtp: the server sent replies nobody asked for"));
        this.replies.push(reply);
      }
    }
  };

  private readonly onError = (e: unknown) => this.fail(connectionError(e));
  private readonly onClose = () => this.fail(new SmtpError("smtp: the server closed the connection"));

  private listen(): void {
    this.socket.on("data", this.onData);
    this.socket.on("error", this.onError);
    this.socket.on("close", this.onClose);
  }

  private unlisten(): void {
    this.socket.off("data", this.onData);
    this.socket.off("error", this.onError);
    this.socket.off("close", this.onClose);
  }
}
