//! JSON read as `JSON.parse` reads it, where the Bun server parses JSON: a
//! request body, the services file, a token's parts, WebAuthn's client data,
//! an import line. Stricter readers would refuse what the Bun server takes:
//!
//! - nesting is capped at `MAX_DEPTH` levels, as the Bun server's
//!   `parseJson` caps it: deeper, the text isn't read as JSON at all. A
//!   64 KiB body could otherwise nest 32,000 levels, and hold megabytes
//!   while it is answered;
//! - a number is a double: `1e400` is Infinity, held as the largest finite
//!   double of its sign, which compares as Infinity does with any time or
//!   count; a whole number is kept as an integer, as JavaScript prints it;
//! - an escaped lone surrogate, which a Rust string can't hold, is U+FFFD,
//!   as it is once the Bun server stores or prints it;
//! - a key given twice keeps its first place and its last value, and keys
//!   that are array indices come first, in numeric order, as in a
//!   JavaScript object.

use serde_json::{Map, Number, Value};

/// The deepest nesting read, counting every array and object, empty or not.
pub const MAX_DEPTH: usize = 64;

pub fn parse(text: &str) -> Option<Value> {
    let mut p = Parser { s: text.as_bytes(), text, i: 0 };
    // Containers being filled, innermost last; an object's entry waits for
    // its value under its key.
    enum Open {
        Array(Vec<Value>),
        Object(Map<String, Value>, Option<String>),
    }
    let mut stack: Vec<Open> = Vec::new();
    loop {
        p.space();
        // A value starts here: a scalar, or a container opened, one level
        // deeper than those still open.
        if matches!(p.peek(), Some(b'[' | b'{')) && stack.len() >= MAX_DEPTH {
            return None;
        }
        let mut value = match p.peek()? {
            b'[' => {
                p.i += 1;
                p.space();
                if p.eat(b']') {
                    Value::Array(Vec::new())
                } else {
                    stack.push(Open::Array(Vec::new()));
                    continue;
                }
            }
            b'{' => {
                p.i += 1;
                p.space();
                if p.eat(b'}') {
                    Value::Object(Map::new())
                } else {
                    let key = p.key()?;
                    stack.push(Open::Object(Map::new(), Some(key)));
                    continue;
                }
            }
            b'"' => Value::String(p.string()?),
            b't' => p.word("true", Value::Bool(true))?,
            b'f' => p.word("false", Value::Bool(false))?,
            b'n' => p.word("null", Value::Null)?,
            _ => p.number()?,
        };
        // The value goes into its container; a closed container is itself a
        // value for the one around it.
        loop {
            p.space();
            match stack.last_mut() {
                None => {
                    return (p.i == p.s.len()).then_some(value);
                }
                Some(Open::Array(items)) => {
                    items.push(value);
                    if p.eat(b',') {
                        break;
                    }
                    if !p.eat(b']') {
                        return None;
                    }
                    // Without its spare room: a value is 72 bytes, and an
                    // array grows room for four at its first.
                    let Some(Open::Array(mut items)) = stack.pop() else { return None };
                    items.shrink_to_fit();
                    value = Value::Array(items);
                }
                Some(Open::Object(map, key)) => {
                    map.insert(key.take()?, value);
                    if p.eat(b',') {
                        p.space();
                        *key = Some(p.key()?);
                        break;
                    }
                    if !p.eat(b'}') {
                        return None;
                    }
                    let Some(Open::Object(map, _)) = stack.pop() else { return None };
                    value = Value::Object(indices_first(map));
                }
            }
        }
    }
}

/// A JavaScript object's order: array-index keys ascending, then the rest as
/// they came.
fn indices_first(map: Map<String, Value>) -> Map<String, Value> {
    let index = |k: &str| -> Option<u32> { (k == "0" || (!k.starts_with('0') && k.bytes().all(|b| b.is_ascii_digit()))).then(|| k.parse::<u32>().ok()).flatten().filter(|n| *n != u32::MAX) };
    if !map.keys().any(|k| index(k).is_some()) {
        return map;
    }
    let mut entries: Vec<(String, Value)> = map.into_iter().collect();
    let (mut indices, rest): (Vec<_>, Vec<_>) = entries.drain(..).partition(|(k, _)| index(k).is_some());
    indices.sort_by_key(|(k, _)| index(k));
    indices.into_iter().chain(rest).collect()
}

struct Parser<'a> {
    s: &'a [u8],
    text: &'a str,
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn eat(&mut self, b: u8) -> bool {
        let found = self.peek() == Some(b);
        if found {
            self.i += 1;
        }
        found
    }

    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn key(&mut self) -> Option<String> {
        if self.peek() != Some(b'"') {
            return None;
        }
        let key = self.string()?;
        self.space();
        self.eat(b':').then_some(key)
    }

    fn word(&mut self, word: &str, value: Value) -> Option<Value> {
        self.s[self.i..].starts_with(word.as_bytes()).then(|| {
            self.i += word.len();
            value
        })
    }

    fn string(&mut self) -> Option<String> {
        self.i += 1;
        let mut out = String::new();
        // UTF-16 units from \u escapes, paired up once a run of them ends.
        let mut units: Vec<u16> = Vec::new();
        let flush = |units: &mut Vec<u16>, out: &mut String| {
            out.extend(char::decode_utf16(units.drain(..)).map(|c| c.unwrap_or('\u{fffd}')));
        };
        loop {
            let start = self.i;
            while let Some(b) = self.peek() {
                if b == b'"' || b == b'\\' || b < 0x20 {
                    break;
                }
                self.i += 1;
            }
            if self.i > start {
                flush(&mut units, &mut out);
                out.push_str(&self.text[start..self.i]);
            }
            match self.peek()? {
                b'"' => {
                    self.i += 1;
                    flush(&mut units, &mut out);
                    return Some(out);
                }
                b'\\' => {
                    self.i += 1;
                    let escaped = self.peek()?;
                    self.i += 1;
                    if escaped == b'u' {
                        let hex = self.text.get(self.i..self.i + 4)?;
                        if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                            return None;
                        }
                        units.push(u16::from_str_radix(hex, 16).ok()?);
                        self.i += 4;
                        continue;
                    }
                    flush(&mut units, &mut out);
                    out.push(match escaped {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        _ => return None,
                    });
                }
                // A raw control character.
                _ => return None,
            }
        }
    }

    fn number(&mut self) -> Option<Value> {
        let start = self.i;
        self.eat(b'-');
        let digits = |p: &mut Self| {
            let from = p.i;
            while matches!(p.peek(), Some(b'0'..=b'9')) {
                p.i += 1;
            }
            p.i - from
        };
        match self.peek()? {
            b'0' => self.i += 1,
            b'1'..=b'9' => {
                digits(self);
            }
            _ => return None,
        }
        if self.eat(b'.') && digits(self) == 0 {
            return None;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if !self.eat(b'+') {
                self.eat(b'-');
            }
            if digits(self) == 0 {
                return None;
            }
        }
        let n: f64 = self.text[start..self.i].parse().ok()?;
        Some(Value::Number(as_number(n)))
    }
}

fn as_number(n: f64) -> Number {
    if n.is_infinite() {
        return Number::from_f64(f64::MAX.copysign(n)).expect("finite");
    }
    if n.fract() == 0.0 && n.abs() < 9_007_199_254_740_992.0 {
        return Number::from(n as i64);
    }
    Number::from_f64(n).expect("finite")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_what_json_parse_reads() {
        assert_eq!(parse(" {\"a\":[1,2.5,-0,true,false,null,\"x\"]}\n"), Some(json!({ "a": [1, 2.5, 0, true, false, null, "x"] })));
        assert_eq!(parse("1e400").and_then(|v| v.as_f64()), Some(f64::MAX));
        assert_eq!(parse("-1e400").and_then(|v| v.as_f64()), Some(-f64::MAX));
        assert_eq!(parse("1e-400"), Some(json!(0)));
        assert_eq!(parse("12345678901234567890").and_then(|v| v.as_f64()), Some(12345678901234567000.0));
        assert_eq!(parse(r#""\ud800x""#), Some(json!("\u{fffd}x")));
        assert_eq!(parse(r#""\ud83d\ude00""#), Some(json!("\u{1f600}")));
        assert_eq!(parse(r#""\uD800\u0041""#), Some(json!("\u{fffd}A")));
        assert_eq!(parse(r#""\u00e9 \/ \n""#), Some(json!("é / \n")));
        assert_eq!(parse("\"\u{2028}\""), Some(json!("\u{2028}")));
        let order = parse(r#"{"b":1,"2":2,"a":3,"1":4,"01":5,"4294967294":6,"4294967295":7,"b":8}"#).expect("an object");
        assert_eq!(order.as_object().expect("a map").keys().collect::<Vec<_>>(), ["1", "2", "4294967294", "b", "a", "01", "4294967295"]);
        assert_eq!(order["b"], json!(8));
        assert_eq!(parse(r#"{"__proto__":1}"#), Some(json!({ "__proto__": 1 })));
    }

    #[test]
    fn reads_64_levels_and_no_more() {
        let nested = |levels: usize, inner: &str| format!("{}{inner}{}", "[".repeat(levels), "]".repeat(levels));
        assert!(parse(&nested(64, "")).is_some());
        assert!(parse(&nested(63, "1")).is_some());
        assert!(parse(&nested(65, "")).is_none(), "an empty array is a level too");
        assert!(parse(&nested(64, "{}")).is_none());
        assert!(parse(&nested(30_000, "")).is_none());
        // Objects count as arrays do, and brackets in strings not at all.
        let objects = format!("{}1{}", "{\"a\":".repeat(64), "}".repeat(64));
        assert!(parse(&objects).is_some());
        assert!(parse(&format!("[{objects}]")).is_none());
        assert_eq!(parse(&format!("[\"{}\"]", "[{".repeat(100))).map(|v| v[0].as_str().map(str::len)), Some(Some(200)));
    }

    #[test]
    fn an_array_keeps_no_spare_room() {
        let Some(Value::Array(outer)) = parse("[[1],[2,3],[]]") else { panic!("an array") };
        assert_eq!(outer.capacity(), 3);
        assert!(outer.iter().all(|v| v.as_array().is_some_and(|a| a.capacity() == a.len())));
    }

    #[test]
    fn refuses_what_json_parse_refuses() {
        for text in [
            "",
            " ",
            "\u{feff}{}",
            "{}\u{a0}",
            "{,}",
            "[1,]",
            "{\"a\":1,}",
            "'a'",
            "\"\\x41\"",
            "\"a\tb\"",
            "01",
            "1.",
            ".5",
            "+1",
            "-",
            "1e",
            "NaN",
            "tru",
            "nul",
            "[] x",
            "{\"a\"}",
            "{\"a\" 1}",
            "{1:2}",
            "[",
            "{\"a\":",
            "\"abc",
            "\"\\u12\"",
            "\"\\u12G4\"",
        ] {
            assert_eq!(parse(text), None, "{text:?}");
        }
    }
}
