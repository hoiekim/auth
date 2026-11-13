import { isIP } from "node:net";

// Client addresses (docs/DESIGN.md §9.4): `X-Real-IP` counts only when the
// connecting peer is a trusted proxy, which sets it from its own connecting
// address. Anything else would let a client pick its own rate-limit key.

export interface Cidr {
  bytes: Uint8Array;
  prefix: number;
}

export function parseIp(text: string): Uint8Array | null {
  let s = text.trim();
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
  const zone = s.indexOf("%");
  if (zone >= 0) s = s.slice(0, zone);
  const kind = isIP(s);
  if (kind === 4) return Uint8Array.from(s.split(".").map(Number));
  if (kind !== 6) return null;
  // An IPv4-mapped address is the IPv4 address, so one rule matches both.
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(s);
  if (mapped?.[1]) return parseIp(mapped[1]);
  return ipv6Bytes(s);
}

function ipv6Bytes(text: string): Uint8Array | null {
  // An embedded IPv4 tail (::1.2.3.4) becomes its two hex groups.
  const v4 = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(text);
  if (v4?.[1] && v4[2]) {
    const b = parseIp(v4[2]);
    if (!b || b.length !== 4) return null;
    text = `${v4[1]}${((b[0]! << 8) | b[1]!).toString(16)}:${((b[2]! << 8) | b[3]!).toString(16)}`;
  }
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const groups = (part: string | undefined) => (part ? part.split(":") : []);
  const left = groups(halves[0]);
  const right = groups(halves[1]);
  const missing = 8 - left.length - right.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return null;
  const all = [...left, ...Array<string>(halves.length === 1 ? 0 : missing).fill("0"), ...right];
  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    const g = all[i]!;
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
    const n = parseInt(g, 16);
    out[i * 2] = n >> 8;
    out[i * 2 + 1] = n & 255;
  }
  return out;
}

export function parseCidr(text: string): Cidr | null {
  const [addr, len, extra] = text.trim().split("/");
  if (extra !== undefined || !addr) return null;
  const bytes = parseIp(addr);
  if (!bytes) return null;
  const max = bytes.length * 8;
  const prefix = len === undefined ? max : /^\d{1,3}$/.test(len) ? Number(len) : -1;
  if (prefix < 0 || prefix > max) return null;
  return { bytes, prefix };
}

export function inCidr(ip: Uint8Array, cidr: Cidr): boolean {
  if (ip.length !== cidr.bytes.length) return false;
  let bits = cidr.prefix;
  for (let i = 0; i < ip.length && bits > 0; i++, bits -= 8) {
    const mask = bits >= 8 ? 0xff : (0xff << (8 - bits)) & 0xff;
    if ((ip[i]! & mask) !== (cidr.bytes[i]! & mask)) return false;
  }
  return true;
}

export function formatIp(bytes: Uint8Array): string {
  if (bytes.length === 4) return bytes.join(".");
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) groups.push((bytes[i]! << 8) | bytes[i + 1]!);
  // RFC 5952: the longest run of two or more zero groups becomes "::".
  let best = -1;
  let bestLen = 1;
  for (let i = 0; i < 8; ) {
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen) {
      best = i;
      bestLen = j - i;
    }
    i = j === i ? i + 1 : j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (best < 0) return hex.join(":");
  return `${hex.slice(0, best).join(":")}::${hex.slice(best + bestLen).join(":")}`;
}

// The client's address: the proxy's `X-Real-IP` when the peer is a trusted
// proxy, else the peer itself. Returned normalized, or null when unknown.
export function clientIp(peer: string | null, realIp: string | null, trusted: Cidr[]): string | null {
  const peerBytes = peer ? parseIp(peer) : null;
  if (!peerBytes) return null;
  if (realIp && trusted.some((c) => inCidr(peerBytes, c))) {
    const real = parseIp(realIp);
    if (real) return formatIp(real);
  }
  return formatIp(peerBytes);
}
