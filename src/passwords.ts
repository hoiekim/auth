import { createHash } from "node:crypto";

// Account passwords (docs/DESIGN.md §9.1).

// OWASP's minimum for argon2id: m = 19 MiB, t = 2, p = 1. Bun's default is
// 64 MiB, and two of those at once would put a 128 MB container at its limit.
export const ARGON2 = { algorithm: "argon2id", memoryCost: 19456, timeCost: 2 } as const;
const CURRENT_PREFIX = "$argon2id$v=19$m=19456,t=2,p=1$";

// At most `limit` tasks at once; the rest wait in arrival order.
export class Semaphore {
  #free: number;
  readonly #waiting: (() => void)[] = [];

  constructor(limit: number) {
    this.#free = limit;
  }

  async run<T>(task: () => Promise<T>): Promise<T> {
    if (this.#free > 0) this.#free--;
    else await new Promise<void>((resolve) => this.#waiting.push(resolve));
    try {
      return await task();
    } finally {
      const next = this.#waiting.shift();
      if (next) next();
      else this.#free++;
    }
  }
}

export class Hasher {
  // Two hashes at a time cap hashing memory at 38 MiB.
  readonly #slots = new Semaphore(2);
  #dummy: Promise<string> | null = null;

  hash(password: string): Promise<string> {
    return this.#slots.run(() => Bun.password.hash(password, ARGON2));
  }

  // `stored` null (an unknown user, or one without a password) verifies
  // against a dummy hash, so the answer takes as long as a real one.
  async verify(password: string, stored: string | null): Promise<{ ok: boolean; rehash: boolean }> {
    this.#dummy ??= this.hash("not a password anyone has: the dummy hash for unknown users");
    const target = stored ?? (await this.#dummy);
    // A bcrypt hash can only have been imported (§13), and standard bcrypt
    // reads the first 72 bytes of a password; Bun treats a longer one
    // differently, so it gets what the source app's bcrypt got.
    const input = target.startsWith("$2") ? Buffer.from(password, "utf8").subarray(0, 72) : password;
    let ok = false;
    try {
      ok = await this.#slots.run(() => Bun.password.verify(input, target));
    } catch {
      ok = false;
    }
    return { ok: ok && stored !== null, rehash: ok && stored !== null && !stored.startsWith(CURRENT_PREFIX) };
  }
}

export const MIN_PASSWORD = 12;
export const MAX_PASSWORD = 256;

// NIST SP 800-63B: length only, no composition rules; not the username or
// the email. The breached-password check is separate (it's a network call).
export function passwordProblem(password: string, avoid: { username?: string | null; email?: string | null }): string | null {
  const length = [...password].length;
  if (length < MIN_PASSWORD) return `Use at least ${MIN_PASSWORD} characters.`;
  if (length > MAX_PASSWORD) return `Use at most ${MAX_PASSWORD} characters.`;
  const lower = password.toLowerCase();
  if (avoid.username && lower === avoid.username.toLowerCase()) return "Don't use your username as your password.";
  if (avoid.email && lower === avoid.email.toLowerCase()) return "Don't use your email address as your password.";
  return null;
}

export const BREACHED_MESSAGE = "This password appears in known data breaches. Choose another.";

// Have I Been Pwned's k-anonymity range API: only the first five hex
// characters of the SHA-1 leave the host, and padding hides how many
// suffixes came back. A timeout or an error allows the password.
export async function isBreached(password: string, fetchFn: typeof fetch = fetch, timeoutMs = 2000): Promise<boolean> {
  const sha1 = createHash("sha1").update(password).digest("hex").toUpperCase();
  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);
  try {
    const res = await fetchFn(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { "Add-Padding": "true" },
      signal: AbortSignal.timeout(timeoutMs),
      redirect: "error",
    });
    if (!res.ok) return false;
    const body = await res.text();
    for (const line of body.split("\n")) {
      const [s, count] = line.trim().split(":");
      if (s === suffix && Number(count) > 0) return true;
    }
    return false;
  } catch {
    return false;
  }
}
