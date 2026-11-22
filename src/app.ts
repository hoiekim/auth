import type { SQL } from "bun";
import type { Config } from "./config";
import { Encrypter } from "./crypto";
import { databasePing } from "./db";
import { KeyStore } from "./keys";
import type { MailMessage, Mailer } from "./mail";
import { Hasher, isBreached, Semaphore } from "./passwords";
import { ServiceRegistry } from "./registry";
import type { ServerDeps } from "./server";
import type { Services } from "./services";

// Everything a handler needs, built once at start and injected, so tests
// substitute fakes without patching modules.
export interface App extends ServerDeps {
  config: Config;
  // The services as this request, or this pass of a job, loaded them; at
  // start, the file's only. prepare() gives a copy of the app with them
  // current (registry.ts).
  services: Services;
  registry: ServiceRegistry;
  prepare(): Promise<App>;
  sql: SQL;
  crypt: Encrypter;
  keys: KeyStore;
  // Queues an email; sending happens after the caller's response, so an
  // answer never waits on, or reveals, whether a message went out.
  mail: (msg: MailMessage) => void;
  // Settles once every queued email has been sent or has failed.
  drainMail: () => Promise<void>;
  // Posts to the deployment's alert webhook, when it has one, after the
  // caller's response.
  alert: (text: string) => void;
  // Settles once every alert posted has been answered or has failed.
  drainAlerts: () => Promise<void>;
  hasher: Hasher;
  breached: (password: string) => Promise<boolean>;
}

export interface AppOverrides {
  mailer?: Mailer;
  fetch?: typeof fetch;
  log?: (line: string) => void;
  breached?: (password: string) => Promise<boolean>;
}

export function createApp(config: Config, sql: SQL, mailer: Mailer, overrides: AppOverrides = {}): App {
  const log = overrides.log ?? ((line: string) => console.log(line));
  const fetchFn = overrides.fetch ?? fetch;
  const crypt = new Encrypter(config.encryptionKey, config.decryptionKeys);
  const queue = mailQueue(mailer, log);
  const registry = new ServiceRegistry(sql, config.services, log);
  const alerts = webhookAlert(config.alertWebhookUrl, fetchFn, log);
  const app: App = {
    config,
    services: config.services,
    registry,
    async prepare() {
      return { ...app, services: await registry.current() };
    },
    sql,
    crypt,
    keys: new KeyStore(sql, crypt),
    mail: queue.send,
    drainMail: queue.drain,
    alert: alerts.send,
    drainAlerts: alerts.drain,
    hasher: new Hasher(),
    breached: overrides.breached ?? ((pw) => isBreached(pw, fetchFn, 2000, config.breachedPasswordsUrl)),
    pingDatabase: databasePing(sql, 2000),
    log,
  };
  return app;
}

const MAX_QUEUED_EMAILS = 200;

export function mailQueue(mailer: Mailer, log: (line: string) => void): { send: (msg: MailMessage) => void; drain: () => Promise<void> } {
  const slots = new Semaphore(2);
  const inFlight = new Set<Promise<void>>();
  return {
    send(msg) {
      if (inFlight.size >= MAX_QUEUED_EMAILS) {
        log("email dropped: the send queue is full");
        return;
      }
      const sending: Promise<void> = slots
        .run(() => mailer.send(msg))
        .catch((e: unknown) => log(`email failed: ${describeMailError(e)}`))
        .finally(() => inFlight.delete(sending));
      inFlight.add(sending);
    },
    async drain() {
      await Promise.allSettled([...inFlight]);
    },
  };
}

// The mail module's own errors name an SMTP code and command and nothing
// else; anything else is logged by its name only.
function describeMailError(e: unknown): string {
  if (e instanceof Error && e.name === "SmtpError") return e.message;
  return e instanceof Error ? e.name : typeof e;
}

// Posts `{"text": …}`, the shape chat webhooks take. The URL is never logged:
// it can carry a token.
export async function postAlert(url: string, fetchFn: typeof fetch, log: (line: string) => void, text: string): Promise<void> {
  try {
    const res = await fetchFn(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
      redirect: "manual",
      signal: AbortSignal.timeout(5000),
    });
    await res.body?.cancel();
    if (!res.ok) log(`alert webhook answered ${res.status}`);
  } catch (e) {
    log(`alert webhook failed: ${e instanceof Error ? e.name : typeof e}`);
  }
}

export function webhookAlert(url: string | null, fetchFn: typeof fetch, log: (line: string) => void): { send: (text: string) => void; drain: () => Promise<void> } {
  const inFlight = new Set<Promise<void>>();
  return {
    send(text) {
      if (!url) return;
      const posting: Promise<void> = postAlert(url, fetchFn, log, text).finally(() => inFlight.delete(posting));
      inFlight.add(posting);
    },
    async drain() {
      await Promise.allSettled([...inFlight]);
    },
  };
}
