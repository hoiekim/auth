import { SQL, type Subprocess } from "bun";
import { createCipheriv, createDecipheriv, createHash, createHmac, createPublicKey, hkdfSync, randomBytes, verify as verifySignature } from "node:crypto";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

// The conformance suite's support: it starts a server as a deployment would,
// as a process configured through its environment, and reaches it only over
// HTTP, SMTP and Postgres. The same tests run against either backend:
// AUTH_BACKEND=bun (the default) starts src/index.ts, AUTH_BACKEND=rust the
// binary built from rust/. Nothing here imports the server's code.

const ROOT = resolve(import.meta.dir, "..");

export const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;
// The suite needs Postgres; without it every file skips, like the database tests.
export const enabled = Boolean(TEST_DATABASE_URL);

export type Backend = "bun" | "rust";
const requested = process.env.AUTH_BACKEND ?? "bun";
if (requested !== "bun" && requested !== "rust") throw new Error(`AUTH_BACKEND must be "bun" or "rust", not "${requested}"`);
export const BACKEND: Backend = requested;

const RUST_BIN = process.env.AUTH_RUST_BIN ?? join(ROOT, "rust", "target", "release", "auth");

// How each backend's break-glass CLI is called, as its own messages name it.
export const CLI = BACKEND === "bun" ? "bun cli.ts" : "auth cli";

// The backend that isn't under test, and whether it can be started too: for
// the tests that run a copy of each on one database, as a deployment moving
// from one to the other does.
export const OTHER: Backend = BACKEND === "bun" ? "rust" : "bun";
export const bothBackends = existsSync(RUST_BIN);

function serverCommand(backend: Backend = BACKEND): string[] {
  if (backend === "bun") return ["bun", "--no-install", join(ROOT, "src", "index.ts")];
  if (!existsSync(RUST_BIN)) throw new Error(`the Rust server isn't built: cargo build --release --manifest-path rust/Cargo.toml (looked for ${RUST_BIN})`);
  return [RUST_BIN];
}

function cliCommand(args: string[], backend: Backend = BACKEND): string[] {
  if (backend === "bun") return ["bun", "--no-install", join(ROOT, "cli.ts"), ...args];
  return [RUST_BIN, "cli", ...args];
}

// ------------------------------------------------------------------ encodings

export function b64u(bytes: Uint8Array | string): string {
  return Buffer.from(bytes).toString("base64url");
}

export function sha256(data: string | Uint8Array): Buffer {
  return createHash("sha256").update(data).digest();
}

export function sha1Hex(data: string): string {
  return createHash("sha1").update(data).digest("hex").toUpperCase();
}

export function randomToken(): string {
  return b64u(randomBytes(32));
}

const RFC4648 = "abcdefghijklmnopqrstuvwxyz234567";

export function base32(bytes: Uint8Array): string {
  let out = "";
  let bits = 0;
  let value = 0;
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += RFC4648[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += RFC4648[(value << (5 - bits)) & 31];
  return out;
}

export function fromBase32(text: string): Buffer {
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const ch of text.toLowerCase().replace(/=+$/, "")) {
    const i = RFC4648.indexOf(ch);
    if (i < 0) throw new Error("not base32");
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

const CROCKFORD = "0123456789abcdefghjkmnpqrstvwxyz";
export const ID = /^[a-z]{2,3}_[0-9a-hjkmnp-tv-z]{26}$/;

// An id in the shape the server makes (docs/DESIGN.md §7.7), for rows a test
// writes itself.
export function newId(prefix: "usr" | "ses" | "apw" | "key" | "inv" | "pk"): string {
  let n = 0n;
  for (const b of Bun.randomUUIDv7("buffer")) n = (n << 8n) | BigInt(b);
  let out = "";
  for (let i = 0; i < 26; i++) {
    out = CROCKFORD[Number(n & 31n)] + out;
    n >>= 5n;
  }
  return `${prefix}_${out}`;
}

// RFC 6238, as an authenticator app computes it.
export function totp(secret: Uint8Array, atMs = Date.now(), stepOffset = 0): string {
  const counter = Math.floor(atMs / 1000 / 30) + stepOffset;
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac("sha1", secret).update(msg).digest();
  const offset = mac[mac.length - 1]! & 0x0f;
  const bin = ((mac[offset]! & 0x7f) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!;
  return String(bin % 1_000_000).padStart(6, "0");
}

export function pkce(): { verifier: string; challenge: string } {
  const verifier = b64u(randomBytes(32));
  return { verifier, challenge: b64u(sha256(verifier)) };
}

export function basic(id: string, secret: string): string {
  return `Basic ${Buffer.from(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`).toString("base64")}`;
}

export interface DecodedJwt {
  header: Record<string, any>;
  claims: Record<string, any>;
  signed: string;
  signature: Buffer;
}

export function decodeJwt(token: string): DecodedJwt {
  const [h, p, s] = token.split(".");
  if (h === undefined || p === undefined || s === undefined) throw new Error("not a JWT");
  return {
    header: JSON.parse(Buffer.from(h, "base64url").toString("utf8")),
    claims: JSON.parse(Buffer.from(p, "base64url").toString("utf8")),
    signed: `${h}.${p}`,
    signature: Buffer.from(s, "base64url"),
  };
}

// ----------------------------------------------- the server's formats at rest
//
// A test arranges state by writing rows, so it writes them in the formats
// both backends read (docs/DESIGN.md §9.3): what one copy wrote, the other
// must read during a rolling deploy.

export class Crypt {
  constructor(
    readonly key: Buffer,
    readonly version = 1,
  ) {}

  static fromEnv(value: string): Crypt {
    const m = /^(?:v(\d+):)?(.+)$/.exec(value)!;
    return new Crypt(Buffer.from(m[2]!, "base64"), m[1] ? Number(m[1]) : 1);
  }

  #subkey(purpose: string): Buffer {
    return Buffer.from(hkdfSync("sha256", this.key, Buffer.alloc(0), `auth:${purpose}`, 32));
  }

  #seal(key: Buffer, plaintext: Uint8Array, aad: string): Buffer {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(Buffer.from(aad));
    const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return Buffer.concat([Buffer.from(`v${this.version}:`), iv, body, cipher.getAuthTag()]);
  }

  #open(key: Buffer, sealed: Uint8Array, aad: string): Buffer {
    const buf = Buffer.from(sealed);
    const prefix = /^v\d{1,4}:/.exec(buf.subarray(0, 6).toString("latin1"))![0].length;
    const decipher = createDecipheriv("aes-256-gcm", key, buf.subarray(prefix, prefix + 12));
    decipher.setAAD(Buffer.from(aad));
    decipher.setAuthTag(buf.subarray(buf.length - 16));
    return Buffer.concat([decipher.update(buf.subarray(prefix + 12, buf.length - 16)), decipher.final()]);
  }

  // A column encrypted at rest: a TOTP secret or a private signing key, with
  // its row id as additional data.
  encrypt(plaintext: Uint8Array, rowId: string): Buffer {
    return this.#seal(this.key, plaintext, rowId);
  }

  decrypt(sealed: Uint8Array, rowId: string): Buffer {
    return this.#open(this.key, sealed, rowId);
  }

  // A sealed value as the server hands one to a browser: a pending second
  // factor ("pending"), a TOTP enrolment ("totp-enrol"), a WebAuthn challenge
  // ("passkey-reg", "passkey-auth").
  seal(purpose: string, value: unknown, ttlSeconds: number): string {
    const body = JSON.stringify({ v: value, exp: Date.now() + ttlSeconds * 1000 });
    return b64u(this.#seal(this.#subkey(`sealed:${purpose}`), Buffer.from(body), purpose));
  }

  open<T = any>(purpose: string, token: string): { v: T; exp: number } {
    return JSON.parse(this.#open(this.#subkey(`sealed:${purpose}`), Buffer.from(token, "base64url"), purpose).toString("utf8"));
  }

  // The synchronizer token of a session (§9.2).
  csrf(sessionToken: string): string {
    return createHmac("sha256", this.#subkey("csrf")).update(sessionToken).digest("base64url");
  }
}

// ---------------------------------------------------------------- processes

export interface Exit {
  code: number | null;
  stdout: string;
  stderr: string;
  // stdout, line by line.
  out: string[];
}

async function collect(stream: ReadableStream<Uint8Array> | undefined, onLine?: (line: string) => void): Promise<string> {
  if (!stream) return "";
  const decoder = new TextDecoder();
  let all = "";
  let pending = "";
  for await (const chunk of stream) {
    const text = decoder.decode(chunk, { stream: true });
    all += text;
    pending += text;
    for (let nl = pending.indexOf("\n"); nl >= 0; nl = pending.indexOf("\n")) {
      onLine?.(pending.slice(0, nl));
      pending = pending.slice(nl + 1);
    }
  }
  if (pending) onLine?.(pending);
  return all;
}

// A minimal environment: nothing of the developer's shell (a proxy setting,
// a .env beside the code) reaches the server under test.
function processEnv(env: Record<string, string | undefined>): Record<string, string> {
  const out: Record<string, string> = { PATH: process.env.PATH ?? "", TZ: "UTC" };
  if (process.env.HOME) out.HOME = process.env.HOME;
  for (const [k, v] of Object.entries(env)) if (v !== undefined) out[k] = v;
  return out;
}

async function run(cmd: string[], env: Record<string, string | undefined>, cwd: string, stdin?: string, timeoutMs = 60_000): Promise<Exit> {
  const proc = Bun.spawn(cmd, { env: processEnv(env), cwd, stdin: stdin === undefined ? "ignore" : "pipe", stdout: "pipe", stderr: "pipe" });
  if (stdin !== undefined) {
    const sink = proc.stdin as unknown as { write(data: string): void; end(): void | Promise<unknown> };
    sink.write(stdin);
    await sink.end();
  }
  const timer = setTimeout(() => proc.kill("SIGKILL"), timeoutMs);
  const [stdout, stderr, code] = await Promise.all([collect(proc.stdout), collect(proc.stderr), proc.exited]);
  clearTimeout(timer);
  return { code, stdout, stderr, out: stdout.split("\n").filter((l) => l !== "") };
}

// One running copy of the server.
export class ServerProcess {
  // Every line the process wrote, stdout and stderr together, in order.
  readonly logs: string[] = [];
  readonly url: string;
  readonly exited: Promise<number>;
  #proc: Subprocess<"ignore", "pipe", "pipe">;
  #drained: Promise<unknown>;

  constructor(cmd: string[], env: Record<string, string | undefined>, cwd: string, readonly port: number) {
    this.url = `http://127.0.0.1:${port}`;
    this.#proc = Bun.spawn(cmd, { env: processEnv(env), cwd, stdin: "ignore", stdout: "pipe", stderr: "pipe" });
    this.#drained = Promise.all([collect(this.#proc.stdout, (l) => this.logs.push(l)), collect(this.#proc.stderr, (l) => this.logs.push(l))]);
    this.exited = this.#proc.exited;
  }

  get running(): boolean {
    return this.#proc.exitCode === null && this.#proc.signalCode === null;
  }

  // Healthy: the schema and a signing key are in place.
  async ready(timeoutMs = 30_000): Promise<void> {
    const until = Date.now() + timeoutMs;
    for (;;) {
      if (!this.running) throw new Error(`the server exited before it was ready:\n${this.logs.join("\n")}`);
      try {
        const res = await fetch(`${this.url}/healthz`);
        await res.body?.cancel();
        if (res.status === 200) return;
      } catch {
        // Not listening yet.
      }
      if (Date.now() > until) throw new Error(`the server was not ready in ${timeoutMs} ms:\n${this.logs.join("\n")}`);
      await Bun.sleep(25);
    }
  }

  signal(signal: "SIGTERM" | "SIGINT" | "SIGKILL"): void {
    this.#proc.kill(signal);
  }

  // Stops it as a deploy does, and answers with its exit code.
  async stop(signal: "SIGTERM" | "SIGINT" = "SIGTERM", timeoutMs = 15_000): Promise<number> {
    if (this.running) this.#proc.kill(signal);
    const timer = setTimeout(() => this.#proc.kill("SIGKILL"), timeoutMs);
    const code = await this.exited;
    clearTimeout(timer);
    await this.#drained;
    return code;
  }

  logText(): string {
    return this.logs.join("\n");
  }
}

// One request written byte for byte, for what fetch won't send. Answers with
// everything the server wrote back, once a whole response has arrived, the
// connection has closed, or `waitMs` has passed.
export function rawRequest(port: number, data: string | Uint8Array, waitMs = 2000): Promise<string> {
  return new Promise((resolveResponse) => {
    const socket = net.connect(port, "127.0.0.1");
    let out = "";
    let settled = false;
    const done = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolveResponse(out);
    };
    const timer = setTimeout(done, waitMs);
    socket.on("data", (d) => {
      out += d.toString("latin1");
      const head = out.indexOf("\r\n\r\n");
      if (head < 0) return;
      const length = /^content-length:\s*(\d+)/im.exec(out.slice(0, head));
      if (length && out.length >= head + 4 + Number(length[1])) done();
    });
    socket.on("connect", () => socket.write(data));
    socket.on("error", () => {});
    socket.on("close", done);
  });
}

export function rawStatus(response: string): number {
  return Number(/^HTTP\/1\.1 (\d{3})/.exec(response)?.[1] ?? 0);
}

export async function freePort(): Promise<number> {
  return new Promise((resolvePort, reject) => {
    const s = net.createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address() as net.AddressInfo;
      s.close(() => resolvePort(port));
    });
  });
}

export async function waitFor<T>(check: () => T | undefined | null | false | Promise<T | undefined | null | false>, what = "a condition", timeoutMs = 5000): Promise<T> {
  const until = Date.now() + timeoutMs;
  for (;;) {
    const found = await check();
    if (found !== undefined && found !== null && found !== false) return found;
    if (Date.now() > until) throw new Error(`timed out waiting for ${what}`);
    await Bun.sleep(15);
  }
}

// -------------------------------------------------------------------- sinks

export interface Mail {
  helo: string;
  // The envelope.
  from: string;
  to: string[];
  // AUTH PLAIN's user and password, when the server authenticated.
  auth: { username: string; password: string } | null;
  headers: Record<string, string>;
  subject: string;
  // The decoded body, with \n line ends.
  text: string;
  raw: string;
}

type SmtpStage = "greeting" | "EHLO" | "AUTH" | "MAIL" | "RCPT" | "DATA" | "message";

// An SMTP server on a loopback port that keeps what it is sent.
export class SmtpSink {
  readonly mails: Mail[] = [];
  // A reply to give in place of the usual one, e.g. { RCPT: "550 no such user" }.
  replies: Partial<Record<SmtpStage, string>> = {};
  advertiseAuth = false;
  // Every command line received, across connections (the message's own lines aside).
  readonly commands: string[] = [];
  #server: net.Server;
  port = 0;

  constructor() {
    this.#server = net.createServer((socket) => this.#serve(socket));
  }

  async listen(): Promise<void> {
    await new Promise<void>((done) => this.#server.listen(0, "127.0.0.1", done));
    this.port = (this.#server.address() as net.AddressInfo).port;
  }

  async close(): Promise<void> {
    await new Promise<void>((done) => this.#server.close(() => done()));
  }

  #serve(socket: net.Socket): void {
    socket.on("error", () => {});
    let pending = "";
    let inData = false;
    let helo = "";
    let from = "";
    let to: string[] = [];
    let auth: Mail["auth"] = null;
    const say = (line: string) => socket.write(`${line}\r\n`);
    say(this.replies.greeting ?? "220 sink.test ESMTP");
    socket.on("data", (chunk) => {
      pending += chunk.toString("latin1");
      for (;;) {
        if (inData) {
          const end = pending.indexOf("\r\n.\r\n");
          if (end < 0) return;
          const raw = pending.slice(0, end).replace(/^\.\./gm, ".");
          pending = pending.slice(end + 5);
          inData = false;
          if (this.replies.message) say(this.replies.message);
          else {
            this.mails.push(parseMail(raw, helo, from, to, auth));
            say("250 queued");
          }
          from = "";
          to = [];
          continue;
        }
        const nl = pending.indexOf("\r\n");
        if (nl < 0) return;
        const line = pending.slice(0, nl);
        pending = pending.slice(nl + 2);
        this.commands.push(line);
        const verb = line.split(/[ :]/)[0]!.toUpperCase();
        if (verb === "EHLO") {
          helo = line.slice(5);
          if (this.replies.EHLO) say(this.replies.EHLO);
          else {
            say("250-sink.test");
            if (this.advertiseAuth) say("250-AUTH PLAIN LOGIN");
            say("250 SIZE 10485760");
          }
        } else if (verb === "AUTH") {
          const decoded = Buffer.from(line.split(" ")[2] ?? "", "base64").toString("utf8").split("\0");
          auth = { username: decoded[1] ?? "", password: decoded[2] ?? "" };
          say(this.replies.AUTH ?? "235 ok");
        } else if (verb === "MAIL") {
          from = /<([^>]*)>/.exec(line)?.[1] ?? "";
          say(this.replies.MAIL ?? "250 ok");
        } else if (verb === "RCPT") {
          to.push(/<([^>]*)>/.exec(line)?.[1] ?? "");
          say(this.replies.RCPT ?? "250 ok");
        } else if (verb === "DATA") {
          if (this.replies.DATA) say(this.replies.DATA);
          else {
            inData = true;
            say("354 go ahead");
          }
        } else if (verb === "QUIT") {
          say("221 bye");
          socket.end();
          return;
        } else say("500 what");
      }
    });
  }

  // The newest message to an address, once it has arrived.
  async waitFor(to: string, match: (m: Mail) => boolean = () => true, timeoutMs = 5000): Promise<Mail> {
    return waitFor(() => this.mails.findLast((m) => m.to.includes(to) && match(m)), `an email to ${to}`, timeoutMs);
  }

  to(address: string): Mail[] {
    return this.mails.filter((m) => m.to.includes(address));
  }
}

// RFC 2047 encoded words; adjacent ones are one text, and the folding
// between them is not part of it.
function decodeWords(value: string): string {
  const joined = value.replace(/(\?=)\s+(?==\?UTF-8\?B\?)/gi, "$1");
  return joined.replace(/(?:=\?UTF-8\?B\?[^?]*\?=)+/gi, (words) =>
    Buffer.concat([...words.matchAll(/=\?UTF-8\?B\?([^?]*)\?=/gi)].map((m) => Buffer.from(m[1]!, "base64"))).toString("utf8"),
  );
}

function parseMail(raw: string, helo: string, from: string, to: string[], auth: Mail["auth"]): Mail {
  const split = raw.indexOf("\r\n\r\n");
  const head = split < 0 ? raw : raw.slice(0, split);
  const body = split < 0 ? "" : raw.slice(split + 4);
  const headers: Record<string, string> = {};
  for (const line of head.replace(/\r\n[ \t]+/g, " ").split("\r\n")) {
    const colon = line.indexOf(":");
    if (colon > 0) headers[line.slice(0, colon).toLowerCase()] = line.slice(colon + 1).trim();
  }
  const encoded = (headers["content-transfer-encoding"] ?? "").toLowerCase() === "base64";
  const text = (encoded ? Buffer.from(body.replace(/\r\n/g, ""), "base64").toString("utf8") : Buffer.from(body, "latin1").toString("utf8")).replace(/\r\n/g, "\n");
  return { helo, from, to, auth, headers, subject: decodeWords(headers.subject ?? ""), text, raw };
}

// The first link in a message.
export function linkIn(mail: Mail): URL {
  const m = /https?:\/\/\S+/.exec(mail.text);
  if (!m) throw new Error(`no link in the email "${mail.subject}"`);
  return new URL(m[0]);
}

export interface ReceivedEvent {
  service: string;
  token: string;
  contentType: string | null;
  accept: string | null;
  header: Record<string, any>;
  claims: Record<string, any>;
  type: string;
  payload: Record<string, any>;
}

// What the deployment's other HTTP endpoints receive: each service's
// events_url, the alert webhook, and the breached-password range API.
export class HttpSink {
  readonly events: ReceivedEvent[] = [];
  readonly alerts: string[] = [];
  // Passwords the range API reports as breached.
  readonly breached = new Set<string>(["password1234"]);
  // Every request to the range API: the path asked and its Add-Padding header.
  readonly rangeRequests: { path: string; padding: string | null }[] = [];
  // What a service's events_url answers: a status, or a Response. 204 by default.
  onEvent: (e: ReceivedEvent) => number | Response | Promise<number | Response> = () => 204;
  onAlert: (text: string) => number | Response | Promise<number | Response> = () => 200;
  // In place of the range API's usual answer.
  onRange: ((prefix: string) => Response | Promise<Response>) | null = null;
  #server: ReturnType<typeof Bun.serve>;

  constructor() {
    this.#server = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      development: false,
      fetch: async (req) => {
        const url = new URL(req.url);
        const answer = (a: number | Response) => (typeof a === "number" ? new Response(null, { status: a }) : a);
        if (req.method === "POST" && url.pathname.startsWith("/events/")) {
          const token = await req.text();
          let header: Record<string, any> = {};
          let claims: Record<string, any> = {};
          try {
            ({ header, claims } = decodeJwt(token));
          } catch {
            // Kept as received.
          }
          const [type = "", payload = {}] = Object.entries((claims.events as Record<string, any>) ?? {})[0] ?? [];
          const e: ReceivedEvent = {
            service: url.pathname.slice("/events/".length),
            token,
            contentType: req.headers.get("Content-Type"),
            accept: req.headers.get("Accept"),
            header,
            claims,
            type,
            payload,
          };
          this.events.push(e);
          return answer(await this.onEvent(e));
        }
        if (req.method === "POST" && url.pathname === "/alert") {
          const body = (await req.json()) as { text?: unknown };
          const text = typeof body.text === "string" ? body.text : JSON.stringify(body);
          this.alerts.push(text);
          return answer(await this.onAlert(text));
        }
        if (req.method === "GET" && url.pathname.startsWith("/range/")) {
          const prefix = url.pathname.slice("/range/".length);
          this.rangeRequests.push({ path: url.pathname + url.search, padding: req.headers.get("Add-Padding") });
          if (this.onRange) return this.onRange(prefix);
          const lines = [...this.breached].map(sha1Hex).filter((h) => h.startsWith(prefix)).map((h) => `${h.slice(5)}:7`);
          // As the real API pads its answers.
          lines.push("0000000000000000000000000000000000A:0");
          return new Response(lines.join("\r\n"));
        }
        return new Response("no such sink", { status: 404 });
      },
    });
  }

  get url(): string {
    return `http://127.0.0.1:${this.#server.port}`;
  }

  eventsUrl(service: string): string {
    return `${this.url}/events/${service}`;
  }

  async close(): Promise<void> {
    await this.#server.stop(true);
  }

  eventsFor(service: string, type?: string): ReceivedEvent[] {
    return this.events.filter((e) => e.service === service && (type === undefined || e.type === type));
  }

  async waitForEvent(service: string, type: string, match: (e: ReceivedEvent) => boolean = () => true, timeoutMs = 8000): Promise<ReceivedEvent> {
    return waitFor(() => this.events.findLast((e) => e.service === service && e.type === type && match(e)), `a ${type} event for ${service}`, timeoutMs);
  }

  async waitForAlert(match: string | RegExp, timeoutMs = 5000): Promise<string> {
    return waitFor(() => this.alerts.findLast((a) => (typeof match === "string" ? a.includes(match) : match.test(a))), `an alert matching ${match}`, timeoutMs);
  }
}

// ------------------------------------------------------------------ services

// The services file most tests run under: one of each kind of service the
// design serves (docs/DESIGN.md §6). `events` gives each event URL.
export function defaultServices(events: (service: string) => string): { services: any[] } {
  return {
    services: [
      {
        name: "wiki",
        roles: ["member", "admin", "owner"],
        mfa_roles: ["admin", "owner"],
        signup: "invite",
        manages_own_members: true,
        clients: [
          {
            id: "wiki",
            type: "confidential",
            redirect_uris: ["https://wiki.example.com/auth/callback"],
            post_logout_redirect_uris: ["https://wiki.example.com/"],
          },
        ],
        events_url: events("wiki"),
      },
      {
        name: "tasks",
        roles: ["user"],
        mfa_roles: [],
        signup: "open",
        default_role: "user",
        api_key_scopes: ["tasks:read", "tasks:write"],
        clients: [
          { id: "tasks", type: "confidential", redirect_uris: ["https://tasks.example.com/auth/callback"] },
          { id: "tasks-ios", type: "public", redirect_uris: ["com.example.tasks:/auth/callback"] },
        ],
        events_url: events("tasks"),
      },
      {
        name: "mailbox",
        roles: ["user", "admin"],
        mfa_roles: ["admin"],
        signup: "invite",
        manages_own_members: true,
        app_password_scopes: ["imap", "smtp"],
        clients: [{ id: "mailbox", type: "confidential", redirect_uris: ["https://mail.example.com/auth/callback"] }],
        events_url: events("mailbox"),
      },
      {
        name: "notes",
        roles: ["reader", "writer"],
        mfa_roles: [],
        signup: "closed",
        clients: [{ id: "notes", type: "confidential", redirect_uris: ["https://notes.example.com/auth/callback"] }],
      },
    ],
  };
}

// -------------------------------------------------------------------- stack

export interface StackOptions {
  // Added to, or with `undefined` removed from, the default environment.
  env?: Record<string, string | undefined>;
  // The services file: its contents, a function of the events sink's URLs,
  // or null for a deployment without one. Default: defaultServices.
  services?: unknown | ((events: (service: string) => string) => unknown) | null;
  // Start the server and wait until it is healthy. Default true.
  start?: boolean;
}

export interface TestUser {
  id: string;
  username: string;
  name: string;
  email: string | null;
  password: string | null;
  totpSecret: Buffer | null;
  // As the server shows them: six dash-separated groups of four.
  recoveryCodes: string[];
}

export interface NewUser {
  username: string;
  // Default "correct horse battery"; null for an account without one.
  password?: string | null;
  // In place of hashing `password`: a PHC string as an import would bring.
  passwordHash?: string | null;
  // Default <username>@example.com; null for none.
  email?: string | null;
  emailVerified?: boolean;
  name?: string;
  kind?: "person" | "bot";
  ownerId?: string;
  disabled?: boolean;
  access?: Record<string, string>;
  // Enrols TOTP (a secret is made unless one is given).
  totp?: boolean | Uint8Array;
  // How many unused recovery codes to give the account.
  recoveryCodes?: number;
}

export interface NewSession {
  amr?: string[];
  // Seconds since the full sign-in.
  authAge?: number;
  ip?: string | null;
  userAgent?: string | null;
  // Idle and absolute expiry, as SQL intervals from now.
  expiresIn?: string;
  endsIn?: string;
}

const PASSWORD = "correct horse battery";
const hashes = new Map<string, Promise<string>>();

// §9.1's parameters, as either backend hashes.
export function hashPassword(password: string): Promise<string> {
  let hash = hashes.get(password);
  if (!hash) {
    hash = Bun.password.hash(password, { algorithm: "argon2id", memoryCost: 19456, timeCost: 2 });
    hashes.set(password, hash);
  }
  return hash;
}

let browsers = 0;

// A deployment in miniature: Postgres (a schema of its own), the server under
// test, and the endpoints it talks to.
export class Stack {
  readonly http = new HttpSink();
  readonly smtp = new SmtpSink();
  readonly schema = `c_${randomBytes(6).toString("hex")}`;
  readonly dir = mkdtempSync(join(tmpdir(), "auth-conformance-"));
  // Secrets of the services file's confidential clients, by client id.
  readonly secrets: Record<string, string> = {};
  // The copies started with spawn(), stopped with the stack.
  readonly copies: ServerProcess[] = [];
  port = 0;
  env: Record<string, string | undefined> = {};
  servicesFile: unknown = null;
  #admin!: SQL;
  #db!: SQL;
  #server: ServerProcess | null = null;
  #crypt: Crypt | null = null;

  static async start(opts: StackOptions = {}): Promise<Stack> {
    const stack = new Stack();
    await stack.#prepare(opts);
    if (opts.start !== false) await stack.boot();
    return stack;
  }

  async #prepare(opts: StackOptions): Promise<void> {
    if (!TEST_DATABASE_URL) throw new Error("TEST_DATABASE_URL is not set");
    await this.smtp.listen();
    this.port = await freePort();
    this.#admin = new SQL(TEST_DATABASE_URL, { max: 1 });
    await this.#admin.unsafe(`CREATE SCHEMA ${this.schema}`);
    this.#db = new SQL(TEST_DATABASE_URL, { max: 3, connection: { search_path: this.schema } });
    const services = opts.services === undefined ? defaultServices : opts.services;
    this.servicesFile = typeof services === "function" ? (services as (e: (s: string) => string) => unknown)((s) => this.http.eventsUrl(s)) : services;
    const file = join(this.dir, "services.json");
    if (this.servicesFile !== null) writeFileSync(file, typeof this.servicesFile === "string" ? this.servicesFile : JSON.stringify(this.servicesFile));
    this.env = {
      PORT: String(this.port),
      DATABASE_URL: this.databaseUrl,
      ISSUER_URL: this.issuer,
      SERVICES_FILE: this.servicesFile === null ? undefined : file,
      AUTH_ENCRYPTION_KEY: Buffer.alloc(32, 7).toString("base64"),
      API_KEY_PREFIX: "testkey",
      // The tests are the proxy: each browser names its own address.
      TRUSTED_PROXIES: "127.0.0.1",
      SMTP_URL: `smtp://127.0.0.1:${this.smtp.port}`,
      EMAIL_FROM: "Auth <auth@example.com>",
      ALERT_WEBHOOK_URL: `${this.http.url}/alert`,
      BREACHED_PASSWORDS_URL: `${this.http.url}/range`,
      ...opts.env,
    };
  }

  // Starts the server, and gives each confidential client of the services
  // file a secret.
  async boot(): Promise<void> {
    this.#server = new ServerProcess(serverCommand(), this.env, this.dir, this.port);
    await this.#server.ready();
    const declared = (this.servicesFile as { services?: { clients?: { id?: unknown; type?: unknown }[] }[] } | null)?.services ?? [];
    for (const s of declared) {
      for (const c of s.clients ?? []) {
        if (c.type === "confidential" && typeof c.id === "string" && !this.secrets[c.id]) this.secrets[c.id] = await this.clientSecret(c.id);
      }
    }
  }

  // The schema's own connection string, as a deployment's DATABASE_URL.
  get databaseUrl(): string {
    return `${TEST_DATABASE_URL}${TEST_DATABASE_URL!.includes("?") ? "&" : "?"}options=-c%20search_path%3D${this.schema}`;
  }

  get issuer(): string {
    return `http://127.0.0.1:${this.port}`;
  }

  get url(): string {
    return this.issuer;
  }

  get server(): ServerProcess {
    if (!this.#server) throw new Error("the server was not started");
    return this.#server;
  }

  // The primary server's log lines.
  get logs(): string[] {
    return this.server.logs;
  }

  get db(): SQL {
    return this.#db;
  }

  get crypt(): Crypt {
    this.#crypt ??= Crypt.fromEnv(this.env.AUTH_ENCRYPTION_KEY!);
    return this.#crypt;
  }

  get mails(): Mail[] {
    return this.smtp.mails;
  }

  get alerts(): string[] {
    return this.http.alerts;
  }

  get events(): ReceivedEvent[] {
    return this.http.events;
  }

  async stop(): Promise<void> {
    for (const copy of this.copies) await copy.stop();
    if (this.#server) await this.#server.stop();
    await this.#db.close();
    await this.#admin.unsafe(`DROP SCHEMA ${this.schema} CASCADE`);
    await this.#admin.close();
    await this.http.close();
    await this.smtp.close();
    rmSync(this.dir, { recursive: true, force: true });
  }

  // Another copy of the server on the same database, as in a rolling deploy
  // or a restart, with its own environment and services file. Not awaited
  // healthy: call ready() on it, or read its exit. `backend` starts the other
  // server in place of the one under test.
  async spawn(opts: { env?: Record<string, string | undefined>; services?: unknown | null; backend?: Backend } = {}): Promise<ServerProcess> {
    const port = await freePort();
    const env: Record<string, string | undefined> = { ...this.env, PORT: String(port), ...opts.env };
    if (opts.services !== undefined) {
      if (opts.services === null) env.SERVICES_FILE = undefined;
      else {
        const file = join(this.dir, `services-${port}.json`);
        writeFileSync(file, typeof opts.services === "string" ? opts.services : JSON.stringify(opts.services));
        env.SERVICES_FILE = file;
      }
    }
    const copy = new ServerProcess(serverCommand(opts.backend), env, this.dir, Number(env.PORT));
    this.copies.push(copy);
    return copy;
  }

  // Runs the server with a changed environment until it exits by itself, as
  // it does on a configuration it refuses; killed, with code null, if it is
  // still running after `waitMs`.
  async exitOf(env: Record<string, string | undefined>, opts: { services?: unknown; waitMs?: number } = {}): Promise<Exit> {
    const port = await freePort();
    const full: Record<string, string | undefined> = { ...this.env, PORT: String(port), ...env };
    if (opts.services !== undefined) {
      const file = join(this.dir, `services-${port}.json`);
      writeFileSync(file, typeof opts.services === "string" ? opts.services : JSON.stringify(opts.services));
      full.SERVICES_FILE = file;
    }
    const proc = Bun.spawn(serverCommand(), { env: processEnv(full), cwd: this.dir, stdin: "ignore", stdout: "pipe", stderr: "pipe" });
    let killed = false;
    const timer = setTimeout(() => {
      killed = true;
      proc.kill("SIGKILL");
    }, opts.waitMs ?? 5000);
    const [stdout, stderr, code] = await Promise.all([collect(proc.stdout), collect(proc.stderr), proc.exited]);
    clearTimeout(timer);
    return { code: killed ? null : code, stdout, stderr, out: stdout.split("\n").filter((l) => l !== "") };
  }

  // The break-glass CLI, run with the server's environment.
  async cli(args: string[], opts: { stdin?: string; env?: Record<string, string | undefined>; backend?: Backend } = {}): Promise<Exit> {
    return run(cliCommand(args, opts.backend), { ...this.env, ...opts.env }, this.dir, opts.stdin);
  }

  // A file in the stack's own directory, for the CLI to read.
  file(name: string, contents: string): string {
    const path = join(this.dir, name);
    writeFileSync(path, contents);
    return path;
  }

  // ------------------------------------------------------- arranging state

  // A live secret for a client, written as the server stores one.
  async clientSecret(clientId: string): Promise<string> {
    const secret = randomToken();
    await this.#db`INSERT INTO client_secrets (client_id, secret_hash) VALUES (${clientId}, ${sha256(secret)})`;
    return secret;
  }

  basic(clientId: string, secret: string | undefined = this.secrets[clientId]): string {
    if (secret === undefined) throw new Error(`no secret for the client ${clientId}`);
    return basic(clientId, secret);
  }

  async user(u: NewUser): Promise<TestUser> {
    const kind = u.kind ?? "person";
    const password = u.password === undefined ? (kind === "bot" || u.passwordHash !== undefined ? null : PASSWORD) : u.password;
    const hash = u.passwordHash !== undefined ? u.passwordHash : password === null ? null : await hashPassword(password);
    const email = u.email === undefined ? (kind === "bot" ? null : `${u.username}@example.com`) : u.email;
    const name = u.name ?? u.username.charAt(0).toUpperCase() + u.username.slice(1);
    const id = newId("usr");
    await this.#db`
      INSERT INTO users (id, username, name, email, email_verified_at, kind, owner_id, password_hash, disabled_at)
      VALUES (${id}, ${u.username}, ${name}, ${email}, ${(u.emailVerified ?? email !== null) ? new Date() : null}, ${kind}, ${u.ownerId ?? null}, ${hash},
              ${u.disabled ? new Date() : null})`;
    for (const [service, role] of Object.entries(u.access ?? {})) await this.grant(id, service, role);
    let totpSecret: Buffer | null = null;
    if (u.totp) {
      totpSecret = u.totp === true ? randomBytes(20) : Buffer.from(u.totp);
      await this.#db`INSERT INTO totp (user_id, secret_enc) VALUES (${id}, ${this.crypt.encrypt(totpSecret, id)})`;
    }
    const recoveryCodes: string[] = [];
    for (let i = 0; i < (u.recoveryCodes ?? 0); i++) {
      const code = base32(randomBytes(15));
      await this.#db`INSERT INTO recovery_codes (user_id, code_hash) VALUES (${id}, ${sha256(code)})`;
      recoveryCodes.push(code.match(/.{4}/g)!.join("-"));
    }
    return { id, username: u.username, name, email, password, totpSecret, recoveryCodes };
  }

  // An access row, written directly: no audit row and no event.
  async grant(userId: string, service: string, role: string, grantedBy = "host-cli"): Promise<void> {
    await this.#db`
      INSERT INTO access (user_id, service, role, granted_by) VALUES (${userId}, ${service}, ${role}, ${grantedBy})
      ON CONFLICT (user_id, service) DO UPDATE SET role = EXCLUDED.role, granted_by = EXCLUDED.granted_by`;
  }

  // A TOTP code the user's authenticator would show now. The replay guard is
  // reset first, so a test can sign in again within the same 30 seconds.
  async code(user: TestUser): Promise<string> {
    if (!user.totpSecret) throw new Error(`${user.username} has no TOTP secret`);
    await this.#db`UPDATE totp SET last_step = 0 WHERE user_id = ${user.id}`;
    return totp(user.totpSecret);
  }

  // A browser holding an SSO session written directly, without the sign-in
  // pages: for tests of what a signed-in user may do.
  async session(user: TestUser | string, s: NewSession = {}): Promise<Browser> {
    const userId = typeof user === "string" ? user : user.id;
    const token = randomToken();
    const id = newId("ses");
    const amr = s.amr ?? ["pwd"];
    await this.#db`
      INSERT INTO sessions (id, user_id, token_hash, auth_time, amr, ip, user_agent, expires_at, ends_at)
      VALUES (${id}, ${userId}, ${sha256(token)}, now() - make_interval(secs => ${s.authAge ?? 0}), ${this.#db.array(amr, "TEXT")},
              ${s.ip ?? null}::inet, ${s.userAgent ?? null}, now() + ${s.expiresIn ?? "7 days"}::interval, now() + ${s.endsIn ?? "30 days"}::interval)`;
    const browser = this.browser();
    browser.cookies.set("__Host-auth", token);
    browser.sessionId = id;
    return browser;
  }

  // An auth:admin with TOTP, signed in with both factors a moment ago.
  async admin(username = `root-${randomBytes(3).toString("hex")}`): Promise<{ user: TestUser; browser: Browser }> {
    const user = await this.user({ username, access: { auth: "admin" }, totp: true });
    return { user, browser: await this.session(user, { amr: ["pwd", "otp", "mfa"] }) };
  }

  browser(ip?: string | null): Browser {
    return new Browser(this, ip);
  }

  // Rate-limit counters, single-use WebAuthn challenges and the rest of the
  // throttle table: emptied between tests that would otherwise share a limit.
  async resetLimits(): Promise<void> {
    await this.#db`DELETE FROM throttle`;
  }

  // ---------------------------------------------------------- reading state

  // The outbox, decoded: what was queued for each service, delivered or not.
  async outbox(service?: string): Promise<{ id: string; service: string; type: string; payload: Record<string, any>; claims: Record<string, any>; delivered: boolean; failed: boolean; attempts: number }[]> {
    const rows: { id: string; service: string; token: string; delivered_at: Date | null; failed_at: Date | null; attempts: number }[] = await this
      .#db`SELECT id::text AS id, service, token, delivered_at, failed_at, attempts FROM outbox ORDER BY id`;
    return rows
      .filter((r) => service === undefined || r.service === service)
      .map((r) => {
        const { claims } = decodeJwt(r.token);
        const [type, payload] = Object.entries(claims.events as Record<string, Record<string, any>>)[0]!;
        return { id: r.id, service: r.service, type, payload, claims, delivered: r.delivered_at !== null, failed: r.failed_at !== null, attempts: r.attempts };
      });
  }

  // Audit rows, oldest first, optionally of one action.
  async audit(action?: string): Promise<{ id: string; actor: string | null; action: string; user_id: string | null; ip: string | null; detail: Record<string, any> }[]> {
    const rows = await this.#db`SELECT id::text AS id, actor, action, user_id, host(ip) AS ip, detail FROM audit ORDER BY id`;
    return (rows as any[]).filter((r) => action === undefined || r.action === action);
  }

  // The published signing keys.
  async jwks(): Promise<{ keys: Record<string, any>[] }> {
    return (await (await fetch(`${this.url}/.well-known/jwks.json`)).json()) as { keys: Record<string, any>[] };
  }

  // A token's claims, once its signature has been checked against the
  // published keys as an app checks it (§7.3): EdDSA, by kid.
  async verified(token: string, typ?: string): Promise<Record<string, any>> {
    const jwt = decodeJwt(token);
    if (jwt.header.alg !== "EdDSA") throw new Error(`alg is ${jwt.header.alg}`);
    if (typ !== undefined && jwt.header.typ !== typ) throw new Error(`typ is ${jwt.header.typ}, not ${typ}`);
    const jwk = (await this.jwks()).keys.find((k) => k.kid === jwt.header.kid);
    if (!jwk) throw new Error("the token's kid is not in the JWKS");
    const key = createPublicKey({ key: jwk as any, format: "jwk" });
    if (!verifySignature(null, Buffer.from(jwt.signed), key, jwt.signature)) throw new Error("the token's signature does not verify");
    return jwt.claims;
  }
}

export interface RequestOptions extends RequestInit {
  // The Origin header: the issuer's by default on anything but GET; null sends none.
  origin?: string | null;
  // In place of the browser's own address; null sends no X-Real-IP.
  ip?: string | null;
}

// Keeps cookies like a browser and sends Origin on non-GET requests. It
// never follows a redirect by itself.
export class Browser {
  readonly cookies = new Map<string, string>();
  readonly ip: string | null;
  // The copy this browser reaches: the stack's own server unless a test
  // points it at another (a ServerProcess's url). The issuer stays the
  // stack's, as behind one proxy.
  base: string | null = null;
  // Set by Stack.session.
  sessionId: string | null = null;
  #csrf: { session: string; token: string } | null = null;

  constructor(
    readonly stack: Stack,
    ip?: string | null,
  ) {
    // An address of its own, so no two browsers share a per-IP limit.
    if (ip === undefined) {
      const n = ++browsers;
      this.ip = `10.${(n >> 16) & 255}.${(n >> 8) & 255}.${n & 255}`;
    } else this.ip = ip;
  }

  async request(path: string, init: RequestOptions = {}): Promise<Response> {
    const { origin, ip, ...rest } = init;
    const headers = new Headers(rest.headers);
    if (this.cookies.size > 0 && !headers.has("Cookie")) headers.set("Cookie", [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; "));
    const method = rest.method ?? "GET";
    if (method !== "GET" && origin !== null && !headers.has("Origin")) headers.set("Origin", origin ?? this.stack.issuer);
    const address = ip === undefined ? this.ip : ip;
    if (address !== null && !headers.has("X-Real-IP")) headers.set("X-Real-IP", address);
    const url = /^https?:/.test(path) ? path : `${this.base ?? this.stack.url}${path}`;
    const res = await fetch(url, { ...rest, headers, redirect: "manual" });
    for (const c of res.headers.getSetCookie()) {
      const pair = c.split(";")[0]!;
      const eq = pair.indexOf("=");
      const name = pair.slice(0, eq);
      if (/Max-Age=0\b/.test(c)) this.cookies.delete(name);
      else this.cookies.set(name, pair.slice(eq + 1));
    }
    return res;
  }

  get(path: string, init: RequestOptions = {}): Promise<Response> {
    return this.request(path, init);
  }

  // The double-submit token of the forms (§9.2), fetched like a browser
  // loading the sign-in page.
  async formCsrf(): Promise<string> {
    if (!this.cookies.has("__Host-csrf")) await (await this.request("/login")).body?.cancel();
    return this.cookies.get("__Host-csrf")!;
  }

  // Posts a form as a page would; `csrf: null` leaves the token out.
  async form(path: string, fields: Record<string, string>, opts: { origin?: string | null; csrf?: string | null; headers?: Record<string, string> } = {}): Promise<Response> {
    const body = new URLSearchParams(fields);
    if (opts.csrf !== null) body.set("csrf", opts.csrf ?? (await this.formCsrf()));
    return this.request(path, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", ...opts.headers },
      body: body.toString(),
      origin: opts.origin,
    });
  }

  // Signs in through the pages: the password, then a TOTP or recovery code
  // when the account asks for one and `code` is given.
  async signIn(login: string, password: string, code?: string, returnTo = "/account"): Promise<Response> {
    const res = await this.form("/login", { login, password, return_to: returnTo });
    if (res.headers.get("Location")?.startsWith("/login/second-factor") && code !== undefined) {
      await res.body?.cancel();
      return this.form("/login/second-factor", { code, return_to: returnTo });
    }
    return res;
  }

  // The synchronizer token the account page carries in its meta tag.
  async csrf(): Promise<string> {
    const session = this.cookies.get("__Host-auth") ?? "";
    if (this.#csrf?.session === session) return this.#csrf.token;
    const res = await this.request("/account");
    const m = /name="csrf-token" content="([^"]+)"/.exec(await res.text());
    const token = m?.[1] ?? "";
    this.#csrf = { session, token };
    return token;
  }

  // A management API call as the pages' scripts make it: JSON, with the
  // X-CSRF-Token header on anything but GET (pass one in `headers` to
  // override it, or "" to send none).
  async api(method: string, path: string, body?: unknown, headers: Record<string, string> = {}, opts: { origin?: string | null } = {}): Promise<Response> {
    const h: Record<string, string> = { ...headers };
    if (method !== "GET") {
      if (h["X-CSRF-Token"] === undefined) h["X-CSRF-Token"] = await this.csrf();
      else if (h["X-CSRF-Token"] === "") delete h["X-CSRF-Token"];
      h["Content-Type"] ??= "application/json";
    }
    const payload = body === undefined ? (method === "GET" ? undefined : "{}") : typeof body === "string" ? body : JSON.stringify(body);
    return this.request(path, { method, headers: h, body: payload, origin: opts.origin });
  }

  // Follows auth's own redirects from an authorization request, signing in
  // when asked, and answers with the first Location outside auth: the app's
  // callback, with its code or error.
  async authorize(params: Record<string, string>, credentials?: { login: string; password: string; code?: string }): Promise<URL> {
    let res = await this.request(`/oauth/authorize?${new URLSearchParams(params)}`);
    for (let hops = 0; hops < 6; hops++) {
      const location = res.headers.get("Location");
      if (!location) throw new Error(`the authorization stopped at ${res.status}: ${(await res.text()).slice(0, 300)}`);
      await res.body?.cancel();
      if (!location.startsWith("/")) return new URL(location);
      if (location.startsWith("/login?") && credentials) {
        const returnTo = new URL(location, this.stack.url).searchParams.get("return_to") ?? "/account";
        res = await this.signIn(credentials.login, credentials.password, credentials.code, returnTo);
        continue;
      }
      if (location.startsWith("/login?")) throw new Error("the authorization asked for a sign-in, and no credentials were given");
      res = await this.request(location);
    }
    throw new Error("too many redirects");
  }
}

// The standard parameters of an authorization request for a client.
export function authorizeParams(clientId: string, redirectUri: string, challenge: string, more: Record<string, string> = {}): Record<string, string> {
  return {
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    state: "st-" + randomBytes(4).toString("hex"),
    scope: "openid",
    nonce: "n-" + randomBytes(4).toString("hex"),
    code_challenge: challenge,
    code_challenge_method: "S256",
    ...more,
  };
}

export const REDIRECTS: Record<string, string> = {
  wiki: "https://wiki.example.com/auth/callback",
  tasks: "https://tasks.example.com/auth/callback",
  "tasks-ios": "com.example.tasks:/auth/callback",
  mailbox: "https://mail.example.com/auth/callback",
  notes: "https://notes.example.com/auth/callback",
};

// A back-channel call as an app's server makes it: form-encoded, with the
// client's Basic credentials when `authorization` is given.
export async function backChannel(stack: Stack, path: string, fields: Record<string, string>, authorization?: string | null, headers: Record<string, string> = {}): Promise<Response> {
  const h: Record<string, string> = { "Content-Type": "application/x-www-form-urlencoded", ...headers };
  if (authorization) h.Authorization = authorization;
  return fetch(`${stack.url}${path}`, { method: "POST", headers: h, body: new URLSearchParams(fields).toString(), redirect: "manual" });
}

export interface TokenSet {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
}

// The whole sign-in of a user to a client of the default services: the
// authorization request through an existing browser session, then the code
// exchange.
export async function signInTo(stack: Stack, browser: Browser, clientId: string, more: Record<string, string> = {}): Promise<{ tokens: TokenSet; code: string; state: string; verifier: string; response: Response }> {
  const { verifier, challenge } = pkce();
  const params = authorizeParams(clientId, REDIRECTS[clientId]!, challenge, more);
  const back = await browser.authorize(params);
  const code = back.searchParams.get("code");
  if (!code) throw new Error(`no code: ${back.search}`);
  const confidential = stack.secrets[clientId] !== undefined;
  const response = await backChannel(
    stack,
    "/oauth/token",
    { grant_type: "authorization_code", code, redirect_uri: REDIRECTS[clientId]!, code_verifier: verifier, ...(confidential ? {} : { client_id: clientId }) },
    confidential ? stack.basic(clientId) : null,
  );
  const tokens = (await response.clone().json()) as TokenSet;
  return { tokens, code, state: params.state!, verifier, response };
}

// The headers every response carries (§9.2); `page` for an HTML page, whose
// policy lets its own scripts and styles load.
export const SECURITY_HEADERS: Record<string, string> = {
  "Referrer-Policy": "no-referrer",
  "Strict-Transport-Security": "max-age=63072000",
  "X-Content-Type-Options": "nosniff",
};
export const API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'";

export async function errorOf(res: Response): Promise<{ status: number; error: string; description: string }> {
  const body = (await res.json()) as { error: string; error_description: string };
  return { status: res.status, error: body.error, description: body.error_description };
}
