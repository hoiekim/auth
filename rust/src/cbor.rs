//! The part of CBOR (RFC 8949) that WebAuthn uses (docs/DESIGN.md §9.1):
//! integers, byte and text strings, arrays and maps of definite length, and
//! false, true and null. Tags, floats, indefinite lengths, duplicate map keys
//! and integers beyond 2^53 are refused, so every value has one reading.

#[derive(Debug, Clone, PartialEq)]
pub enum Cbor {
    Int(i64),
    Text(String),
    Bool(bool),
    Null,
    Bytes(Vec<u8>),
    Array(Vec<Cbor>),
    Map(Vec<(Key, Cbor)>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Key {
    Int(i64),
    Text(String),
}

impl Cbor {
    pub fn as_map(&self) -> Option<&[(Key, Cbor)]> {
        match self {
            Cbor::Map(m) => Some(m),
            _ => None,
        }
    }

    pub fn get_int(&self, key: i64) -> Option<&Cbor> {
        self.as_map()?.iter().find(|(k, _)| *k == Key::Int(key)).map(|(_, v)| v)
    }

    pub fn get_text(&self, key: &str) -> Option<&Cbor> {
        self.as_map()?.iter().find(|(k, _)| matches!(k, Key::Text(t) if t == key)).map(|(_, v)| v)
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Cbor::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Cbor::Int(n) => Some(*n),
            _ => None,
        }
    }
}

pub struct CborError;

const MAX_DEPTH: usize = 8;
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// One item from the start of `bytes`, and the offset just past it. Whatever
/// follows is the caller's to read or refuse.
pub fn decode_cbor_prefix(bytes: &[u8]) -> Result<(Cbor, usize), CborError> {
    let mut r = Reader { bytes, at: 0 };
    let value = r.item(0)?;
    Ok((value, r.at))
}

/// Exactly one item, with nothing after it.
pub fn decode_cbor(bytes: &[u8]) -> Result<Cbor, CborError> {
    let (value, end) = decode_cbor_prefix(bytes)?;
    if end != bytes.len() {
        return Err(CborError);
    }
    Ok(value)
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: u64) -> Result<&'a [u8], CborError> {
        if n > (self.bytes.len() - self.at) as u64 {
            return Err(CborError);
        }
        let out = &self.bytes[self.at..self.at + n as usize];
        self.at += n as usize;
        Ok(out)
    }

    // The argument of a head: the value itself, or a length or count.
    fn argument(&mut self, info: u8) -> Result<u64, CborError> {
        if info < 24 {
            return Ok(u64::from(info));
        }
        if info > 27 {
            return Err(CborError);
        }
        let mut n: u64 = 0;
        for byte in self.take(1 << (info - 24))? {
            n = (n << 8) | u64::from(*byte);
        }
        if n > MAX_SAFE_INTEGER {
            return Err(CborError);
        }
        Ok(n)
    }

    fn item(&mut self, depth: usize) -> Result<Cbor, CborError> {
        if depth > MAX_DEPTH {
            return Err(CborError);
        }
        let head = self.take(1)?[0];
        let (major, info) = (head >> 5, head & 31);
        match major {
            0 => Ok(Cbor::Int(self.argument(info)? as i64)),
            1 => Ok(Cbor::Int(-1 - self.argument(info)? as i64)),
            2 => {
                let n = self.argument(info)?;
                Ok(Cbor::Bytes(self.take(n)?.to_vec()))
            }
            3 => {
                let n = self.argument(info)?;
                Ok(Cbor::Text(std::str::from_utf8(self.take(n)?).map_err(|_| CborError)?.to_string()))
            }
            // A count larger than what is left fails at the first missing item:
            // every item takes at least one byte.
            4 => {
                let n = self.argument(info)?;
                let mut out = Vec::new();
                for _ in 0..n {
                    out.push(self.item(depth + 1)?);
                }
                Ok(Cbor::Array(out))
            }
            5 => {
                let n = self.argument(info)?;
                let mut out: Vec<(Key, Cbor)> = Vec::new();
                for _ in 0..n {
                    let key = match self.item(depth + 1)? {
                        Cbor::Int(i) => Key::Int(i),
                        Cbor::Text(t) => Key::Text(t),
                        _ => return Err(CborError),
                    };
                    if out.iter().any(|(k, _)| *k == key) {
                        return Err(CborError);
                    }
                    let value = self.item(depth + 1)?;
                    out.push((key, value));
                }
                Ok(Cbor::Map(out))
            }
            7 => match info {
                20 => Ok(Cbor::Bool(false)),
                21 => Ok(Cbor::Bool(true)),
                22 => Ok(Cbor::Null),
                _ => Err(CborError),
            },
            _ => Err(CborError),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_subset_is_read() {
        assert_eq!(decode_cbor(&[0x18, 0x64]).ok().unwrap(), Cbor::Int(100));
        assert_eq!(decode_cbor(&[0x26]).ok().unwrap(), Cbor::Int(-7));
        assert_eq!(decode_cbor(&[0x39, 0x01, 0x00]).ok().unwrap(), Cbor::Int(-257));
        assert_eq!(decode_cbor(&[0x62, b'h', b'i']).ok().unwrap(), Cbor::Text("hi".into()));
        let map = decode_cbor(&[0xa2, 0x01, 0x02, 0x61, b'a', 0x41, 0xff]).ok().unwrap();
        assert_eq!(map.get_int(1), Some(&Cbor::Int(2)));
        assert_eq!(map.get_text("a").and_then(Cbor::as_bytes), Some(&[0xffu8][..]));
        assert_eq!(decode_cbor_prefix(&[0x01, 0x02]).ok().unwrap(), (Cbor::Int(1), 1));
    }

    #[test]
    fn everything_else_is_refused() {
        for bad in [
            &[0x01, 0x02][..],                                                   // trailing bytes
            &[0x5f, 0x41, 0x00, 0xff],                                           // indefinite length
            &[0xc0, 0x01],                                                       // a tag
            &[0xf9, 0x00, 0x00],                                                 // a float
            &[0xa2, 0x01, 0x02, 0x01, 0x03],                                     // a duplicate key
            &[0xa1, 0x41, 0x00, 0x01],                                           // a key that is bytes
            &[0x62, 0xff, 0xfe],                                                 // invalid UTF-8
            &[0x1b, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],             // 2^53
            &[0x42, 0x00],                                                       // truncated
            &[0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x00], // too deep
        ] {
            assert!(decode_cbor(bad).is_err(), "{bad:?}");
        }
        assert!(decode_cbor(&[0x1b, 0x00, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_ok());
        assert!(decode_cbor(&[0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x00]).is_ok());
    }
}
