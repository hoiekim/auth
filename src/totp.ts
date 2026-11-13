import { createHmac, timingSafeEqual } from "node:crypto";
import { base32, random } from "./crypto";

// RFC 6238 with SHA-1, 6 digits and a 30-second step, accepting one step
// either side (docs/DESIGN.md §9.1). Replay is refused by the caller, which
// records the last step used.

export const STEP_SECONDS = 30;

export function newTotpSecret(): Buffer {
  return random(20);
}

export function otpauthUri(secret: Uint8Array, issuerHost: string, username: string): string {
  const label = `${encodeURIComponent(issuerHost)}:${encodeURIComponent(username)}`;
  const params = new URLSearchParams({
    secret: base32(secret).toUpperCase(),
    issuer: issuerHost,
    algorithm: "SHA1",
    digits: "6",
    period: String(STEP_SECONDS),
  });
  return `otpauth://totp/${label}?${params}`;
}

export function hotp(secret: Uint8Array, counter: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac("sha1", secret).update(msg).digest();
  const offset = mac[mac.length - 1]! & 0x0f;
  const bin = ((mac[offset]! & 0x7f) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!;
  return String(bin % 1_000_000).padStart(6, "0");
}

export function stepAt(unixSeconds: number): number {
  return Math.floor(unixSeconds / STEP_SECONDS);
}

// The step a code matches, newest first, among those after `lastStep`; null
// when none does.
export function matchingStep(secret: Uint8Array, code: string, unixSeconds: number, lastStep: number): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  const now = stepAt(unixSeconds);
  let found: number | null = null;
  for (const step of [now + 1, now, now - 1]) {
    // Every candidate is compared, so the time taken doesn't depend on which matched.
    const match = timingSafeEqual(Buffer.from(hotp(secret, step)), Buffer.from(code));
    if (match && step > lastStep && found === null) found = step;
  }
  return found;
}
