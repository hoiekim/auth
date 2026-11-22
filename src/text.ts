// The longest start of `s` within `units` UTF-16 code units that doesn't end
// halfway through a character. `slice` alone can split a surrogate pair,
// which Postgres would store as U+FFFD; the Rust server cuts the same way.
export function cut(s: string, units: number): string {
  if (s.length <= units) return s;
  const last = s.charCodeAt(units - 1);
  return s.slice(0, last >= 0xd800 && last <= 0xdbff ? units - 1 : units);
}
