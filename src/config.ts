import { readFileSync } from "node:fs";
import type { EncryptionKey } from "./crypto";
import { connect } from "./db";
import { parseFrom, parseSmtpUrl, type SmtpSettings } from "./mail";
import { parseCidr, type Cidr } from "./net";
import { isLoopbackHost, parseServices, type Services } from "./services";

// The service's configuration, read from the environment once at start
// (docs/DESIGN.md §11). Every problem is collected, so a misconfigured
// deployment learns all of them in one restart. A message never echoes a
// value that can carry a secret.

export interface Config {
  port: number;
  databaseUrl: string;
  // The issuer's origin, e.g. https://auth.example.com: no path, no trailing slash.
  issuer: string;
  services: Services;
  // Encrypts everything new; the others only decrypt (§9.3).
  encryptionKey: EncryptionKey;
  decryptionKeys: EncryptionKey[];
  apiKeyPrefix: string | null;
  trustedProxies: Cidr[];
  smtp: SmtpSettings;
  emailFrom: string;
  auditRetentionDays: number;
  allowAccountDeletion: boolean;
  alertWebhookUrl: string | null;
}

export class ConfigError extends Error {
  constructor(readonly problems: string[]) {
    super(`invalid configuration:\n${problems.map((p) => `  - ${p}`).join("\n")}`);
    this.name = "ConfigError";
  }
}

const DEFAULT_PORT = 3000;
const DEFAULT_AUDIT_RETENTION_DAYS = 365;
const API_KEY_PREFIX = /^[a-z][a-z0-9]{1,15}$/;

export type ReadFile = (path: string) => string;
const readUtf8: ReadFile = (path) => readFileSync(path, "utf8");

export function loadConfig(env: Record<string, string | undefined>, readFile: ReadFile = readUtf8): Config {
  const problems: string[] = [];
  const value = (name: string) => env[name]?.trim() ?? "";

  let port = DEFAULT_PORT;
  const rawPort = value("PORT");
  if (rawPort) {
    port = /^\d+$/.test(rawPort) ? Number(rawPort) : 0;
    if (port < 1 || port > 65535) problems.push(`PORT must be a whole number from 1 to 65535, not "${rawPort}"`);
  }

  const databaseUrl = value("DATABASE_URL");
  if (!databaseUrl) problems.push("DATABASE_URL is required");
  else if (!/^postgres(ql)?:\/\//.test(databaseUrl)) problems.push("DATABASE_URL must be a postgres:// or postgresql:// URL");
  else if (!parsesAsDatabaseUrl(databaseUrl)) problems.push("DATABASE_URL is not a well-formed URL");

  const issuer = parseIssuer(value("ISSUER_URL"), problems);

  let services: Services | null = null;
  const servicesFile = value("SERVICES_FILE");
  if (!servicesFile) problems.push("SERVICES_FILE is required");
  else {
    let text: string | null = null;
    try {
      text = readFile(servicesFile);
    } catch {
      problems.push(`SERVICES_FILE "${servicesFile}" can't be read`);
    }
    if (text !== null) {
      const parsed = parseServices(text);
      for (const p of parsed.problems) problems.push(`SERVICES_FILE: ${p}`);
      services = parsed.services;
    }
  }

  // Neither key is ever echoed: a message names the variable and the entry.
  let encryptionKey: EncryptionKey = { version: 1, key: Buffer.alloc(0) };
  const rawKey = value("AUTH_ENCRYPTION_KEY");
  if (!rawKey) problems.push("AUTH_ENCRYPTION_KEY is required");
  else {
    const parsed = parseKey(rawKey, false);
    if (parsed) encryptionKey = parsed;
    else problems.push("AUTH_ENCRYPTION_KEY must be 32 bytes, base64-encoded (openssl rand -base64 32), optionally as v<N>:<base64>");
  }
  const decryptionKeys: EncryptionKey[] = [];
  value("AUTH_DECRYPTION_KEYS")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .forEach((entry, i) => {
      const parsed = parseKey(entry, true);
      if (!parsed) problems.push(`AUTH_DECRYPTION_KEYS entry ${i + 1} must be v<N>:<32 bytes, base64>`);
      else if (parsed.version === encryptionKey.version || decryptionKeys.some((k) => k.version === parsed.version)) {
        problems.push(`AUTH_DECRYPTION_KEYS entry ${i + 1} has version ${parsed.version}, which another key already has`);
      } else decryptionKeys.push(parsed);
    });

  const apiKeyPrefix = value("API_KEY_PREFIX") || null;
  if (apiKeyPrefix !== null && !API_KEY_PREFIX.test(apiKeyPrefix)) problems.push("API_KEY_PREFIX must match [a-z][a-z0-9]{1,15}");
  if (apiKeyPrefix === null && services?.all().some((s) => s.apiKeyScopes.length > 0)) {
    problems.push("API_KEY_PREFIX is required when a service declares api_key_scopes");
  }

  const trustedProxies: Cidr[] = [];
  for (const entry of value("TRUSTED_PROXIES").split(",").map((s) => s.trim()).filter(Boolean)) {
    const cidr = parseCidr(entry);
    if (cidr) trustedProxies.push(cidr);
    else problems.push(`TRUSTED_PROXIES has "${entry}", which is not an IP address or CIDR range`);
  }

  let smtp: SmtpSettings = { host: "", port: 0, secure: "none" };
  const smtpUrl = value("SMTP_URL");
  if (!smtpUrl) problems.push("SMTP_URL is required");
  else {
    try {
      smtp = parseSmtpUrl(smtpUrl);
    } catch {
      problems.push("SMTP_URL must be smtps://[user:password@]host[:port], or smtp:// (STARTTLS, or plain only to a loopback host)");
    }
  }

  const emailFrom = value("EMAIL_FROM");
  if (!emailFrom) problems.push("EMAIL_FROM is required");
  else {
    try {
      parseFrom(emailFrom);
    } catch {
      problems.push('EMAIL_FROM must be an address, or "Name <address>"');
    }
  }

  let auditRetentionDays = DEFAULT_AUDIT_RETENTION_DAYS;
  const rawRetention = value("AUDIT_RETENTION_DAYS");
  if (rawRetention) {
    auditRetentionDays = /^\d+$/.test(rawRetention) ? Number(rawRetention) : 0;
    if (auditRetentionDays < 1 || auditRetentionDays > 36500) {
      problems.push(`AUDIT_RETENTION_DAYS must be a whole number of days from 1 to 36500, not "${rawRetention}"`);
    }
  }

  let allowAccountDeletion = false;
  const rawDeletion = value("ALLOW_ACCOUNT_DELETION");
  if (rawDeletion === "true") allowAccountDeletion = true;
  else if (rawDeletion !== "" && rawDeletion !== "false") problems.push('ALLOW_ACCOUNT_DELETION must be "true" or "false"');

  // The URL can carry a token in its path (chat webhooks do), so it's never echoed.
  let alertWebhookUrl: string | null = null;
  const rawAlert = value("ALERT_WEBHOOK_URL");
  if (rawAlert) {
    const url = URL.parse(rawAlert);
    if (!url || (url.protocol !== "https:" && url.protocol !== "http:")) problems.push("ALERT_WEBHOOK_URL must be an http(s) URL");
    else alertWebhookUrl = rawAlert;
  }

  if (problems.length > 0 || !services) throw new ConfigError(problems);
  return {
    port,
    databaseUrl,
    issuer,
    services,
    encryptionKey,
    decryptionKeys,
    apiKeyPrefix,
    trustedProxies,
    smtp,
    emailFrom,
    auditRetentionDays,
    allowAccountDeletion,
    alertWebhookUrl,
  };
}

// `v<N>:<base64>`, or a bare base64 key as version 1 where that's allowed.
function parseKey(raw: string, versionRequired: boolean): EncryptionKey | null {
  const m = /^(?:v(\d{1,4}):)?([A-Za-z0-9+/_-]+={0,2})$/.exec(raw);
  if (!m?.[2] || (versionRequired && !m[1])) return null;
  const version = m[1] ? Number(m[1]) : 1;
  const key = Buffer.from(m[2], "base64");
  return version >= 1 && key.length === 32 ? { version, key } : null;
}

function parseIssuer(raw: string, problems: string[]): string {
  if (!raw) {
    problems.push("ISSUER_URL is required");
    return "";
  }
  const url = URL.parse(raw);
  const ok =
    url !== null &&
    (url.protocol === "https:" || (url.protocol === "http:" && isLoopbackHost(url.hostname))) &&
    !url.username &&
    !url.password &&
    (url.pathname === "/" || url.pathname === "") &&
    !url.search &&
    !url.hash &&
    !raw.endsWith("/");
  if (!ok || !url) {
    // Not echoed: a mistake here can be another variable's value, credentials included.
    problems.push("ISSUER_URL must be an https origin with no path or trailing slash (http only for a loopback host)");
    return "";
  }
  return url.origin;
}

// Bun's SQL client reads the URL when the pool is created, and throws on
// anything it can't use: the port, a percent-escape, sslmode, a timeout.
// Creating the pool here, with the same call the server makes, reports that
// with the other problems instead of crashing the start after them. It
// opens no connection.
function parsesAsDatabaseUrl(value: string): boolean {
  try {
    void connect(value).close();
    return true;
  } catch {
    return false;
  }
}
