// JSON from a request, a file or a token is read with parseJson, never a bare
// JSON.parse. JSON.parse takes any depth, and a 64 KiB body nested 32,000
// levels deep holds megabytes while it is answered (DESIGN §16). Deeper
// than MAX_DEPTH, counting every array and object, empty or not, the text is
// refused as a syntax error is, before it is parsed. The Rust server's
// crate::json::parse draws the same line.
export const MAX_DEPTH = 64;

export function parseJson(text: string): unknown {
  let depth = 0;
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (inString) {
      if (c === 0x5c) i++; // a backslash: the next character is escaped
      else if (c === 0x22) inString = false;
    } else if (c === 0x22) inString = true;
    else if (c === 0x5b || c === 0x7b) {
      if (++depth > MAX_DEPTH) throw new SyntaxError(`JSON nested more than ${MAX_DEPTH} levels deep`);
    } else if (c === 0x5d || c === 0x7d) depth--;
  }
  return JSON.parse(text);
}
