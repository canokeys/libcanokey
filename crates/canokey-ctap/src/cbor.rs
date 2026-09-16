//! Strict canonical CBOR (RFC 8949) for CTAP2 messages.
//!
//! CTAP2 authenticators speak canonical CBOR; this module implements the
//! strict subset the CTAP2 client layer relies on, without external
//! dependencies. Decoding accepts only definite-length, shortest-form,
//! untagged items with at most [`MAX_DEPTH`] levels of nesting, rejects
//! duplicate map keys (recursively, compared by canonical encoding), rejects
//! invalid UTF-8 text, and rejects trailing bytes after a complete item.
//! Encoding always produces the canonical form: shortest-form integers and
//! lengths, and map keys sorted by canonical CBOR order (shorter encoded
//! keys first, then bytewise lexicographic).
//!
//! The exact output of [`encode`] is security-relevant: `pinUvAuthParam`
//! HMACs are computed over this canonical encoding, so any change here
//! changes the wire protocol.
//!
//! # Secrets
//!
//! CBOR values can carry key material (encrypted PINs, key-agreement
//! coordinates). [`Value`]'s `Debug` implementation redacts byte-string
//! contents, printing only their length. Values are ordinary heap buffers
//! and are **not** zeroized on drop; move secrets into
//! [`canokey_protocol::SecretBytes`] as soon as they leave a message.

use canokey_protocol::{Error, ErrorKind, Phase};
use std::collections::HashSet;
use std::fmt;

/// Maximum nesting depth accepted by the parser (the CTAP limit is 64).
pub const MAX_DEPTH: usize = 64;

fn invalid() -> Error {
    Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing)
}
fn limit() -> Error {
    Error::new(ErrorKind::LimitExceeded).at(Phase::Parsing)
}

/// A decoded CBOR data item.
///
/// `Negative(n)` represents the integer `-1 - n`, giving the full u64/i64
/// domain without negation overflow. Maps retain their wire order as a
/// vector of key/value pairs; duplicate keys are rejected by the parser, so
/// at most one entry matches any key lookup. See the module documentation
/// for the secrets handling contract.
#[derive(Clone, PartialEq, Eq)]
pub enum Value {
    /// An unsigned integer (major type 0).
    Unsigned(u64),
    /// A negative integer `n` stored as `-1 - n` (major type 1).
    Negative(u64),
    /// A byte string (major type 2).
    Bytes(Vec<u8>),
    /// A UTF-8 text string (major type 3).
    Text(String),
    /// An array (major type 4).
    Array(Vec<Value>),
    /// A map (major type 5) in wire order; keys are unique.
    Map(Vec<(Value, Value)>),
    /// A boolean (simple value 20/21).
    Bool(bool),
    /// Null (simple value 22).
    Null,
}
impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsigned(value) => f.debug_tuple("Unsigned").field(value).finish(),
            Self::Negative(value) => f.debug_tuple("Negative").field(value).finish(),
            // Byte strings may carry key material: print the length only.
            Self::Bytes(bytes) => write!(f, "Bytes(<{} bytes>)", bytes.len()),
            Self::Text(text) => f.debug_tuple("Text").field(text).finish(),
            Self::Array(items) => f.debug_tuple("Array").field(items).finish(),
            Self::Map(entries) => f.debug_tuple("Map").field(entries).finish(),
            Self::Bool(value) => f.debug_tuple("Bool").field(value).finish(),
            Self::Null => f.write_str("Null"),
        }
    }
}
impl Value {
    /// Build the integer value for `value`, choosing the major type.
    pub fn from_int(value: i64) -> Self {
        if value >= 0 {
            Self::Unsigned(value as u64)
        } else {
            Self::Negative((-(value + 1)) as u64)
        }
    }
    /// Borrow the entries when this value is a map.
    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Self::Map(entries) => Some(entries),
            _ => None,
        }
    }
    /// Borrow the items when this value is an array.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }
    /// Borrow the contents when this value is a byte string.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }
    /// Borrow the contents when this value is a text string.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            _ => None,
        }
    }
    /// Return the integer when this value is an unsigned integer.
    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Self::Unsigned(value) => Some(*value),
            _ => None,
        }
    }
    /// Return the integer when this value is any integer representable in
    /// `i64` (unsigned or negative).
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Unsigned(value) => i64::try_from(*value).ok(),
            Self::Negative(value) if *value <= i64::MAX as u64 => Some(-1 - (*value as i64)),
            _ => None,
        }
    }
    /// Return the boolean when this value is a boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }
    /// Return whether this value is null.
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
    /// Look up `key` in a map value, returning `None` for non-maps or
    /// absent keys.
    pub fn map_get(&self, key: &Value) -> Option<&Value> {
        self.as_map()?
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }
    /// Look up an integer key (including negative COSE labels) in a map
    /// value.
    pub fn map_get_int(&self, key: i64) -> Option<&Value> {
        self.map_get(&Self::from_int(key))
    }
    /// Look up a text key in a map value.
    pub fn map_get_text(&self, key: &str) -> Option<&Value> {
        self.map_get(&Self::Text(key.to_owned()))
    }
}

/// Read a multi-byte big-endian argument, rejecting truncation.
fn read_be(bytes: &[u8], pos: usize, count: usize) -> Result<(u64, usize), Error> {
    let end = pos.checked_add(count).ok_or_else(invalid)?;
    let slice = bytes.get(pos..end).ok_or_else(invalid)?;
    let mut value = 0u64;
    for &byte in slice {
        value = (value << 8) | u64::from(byte);
    }
    Ok((value, end))
}

fn parse_at(bytes: &[u8], pos: usize, depth: usize) -> Result<(Value, usize), Error> {
    if depth > MAX_DEPTH {
        return Err(limit());
    }
    let &initial = bytes.get(pos).ok_or_else(invalid)?;
    let major = initial >> 5;
    let info = initial & 0x1f;
    if major == 7 {
        // Floating-point, undefined, simple values and break are outside
        // the CTAP2 data model.
        let value = match info {
            20 => Value::Bool(false),
            21 => Value::Bool(true),
            22 => Value::Null,
            _ => return Err(invalid()),
        };
        return Ok((value, pos + 1));
    }
    if major == 6 {
        // Tags are rejected everywhere in CTAP2 messages.
        return Err(invalid());
    }
    let (argument, pos) = match info {
        0..=23 => (u64::from(info), pos + 1),
        width @ 24..=27 => {
            let count = 1usize << (width - 24);
            let (value, end) = read_be(bytes, pos + 1, count)?;
            // Canonical form requires the shortest possible argument width.
            let minimum = if count == 1 {
                24
            } else {
                1u64 << (8 * (count / 2))
            };
            if value < minimum {
                return Err(invalid());
            }
            (value, end)
        }
        // 28..=30 are reserved; 31 is indefinite-length or break.
        _ => return Err(invalid()),
    };
    let remaining = (bytes.len() - pos) as u64;
    let take = |length: u64| -> Result<(&[u8], usize), Error> {
        if length > remaining {
            return Err(invalid());
        }
        let end = pos + length as usize;
        Ok((&bytes[pos..end], end))
    };
    match major {
        0 => Ok((Value::Unsigned(argument), pos)),
        1 => Ok((Value::Negative(argument), pos)),
        2 => {
            let (raw, end) = take(argument)?;
            Ok((Value::Bytes(raw.to_vec()), end))
        }
        3 => {
            let (raw, end) = take(argument)?;
            let text = std::str::from_utf8(raw).map_err(|_| invalid())?;
            Ok((Value::Text(text.to_owned()), end))
        }
        4 => {
            if argument > remaining {
                // Every item needs at least one byte; reject before looping.
                return Err(invalid());
            }
            let mut items = Vec::with_capacity(argument.min(remaining) as usize);
            let mut cursor = pos;
            for _ in 0..argument {
                let (item, next) = parse_at(bytes, cursor, depth + 1)?;
                items.push(item);
                cursor = next;
            }
            Ok((Value::Array(items), cursor))
        }
        5 => {
            if argument > remaining / 2 {
                return Err(invalid());
            }
            let mut entries = Vec::with_capacity(argument.min(remaining) as usize);
            let mut seen = HashSet::new();
            let mut cursor = pos;
            for _ in 0..argument {
                let (key, next) = parse_at(bytes, cursor, depth + 1)?;
                // Duplicate keys are compared by canonical encoding.
                if !seen.insert(encode(&key)) {
                    return Err(invalid());
                }
                let (value, next) = parse_at(bytes, next, depth + 1)?;
                entries.push((key, value));
                cursor = next;
            }
            Ok((Value::Map(entries), cursor))
        }
        _ => unreachable!("major types 6 and 7 handled above"),
    }
}

/// Parse exactly one CBOR item and reject any trailing bytes.
///
/// This is the entry point for complete CTAP2 response payloads.
///
/// # Errors
/// Malformed, non-canonical, tagged, indefinite-length, duplicate-keyed or
/// trailing-byte input fails as [`ErrorKind::InvalidResponse`] in
/// [`Phase::Parsing`]; nesting beyond [`MAX_DEPTH`] fails as
/// [`ErrorKind::LimitExceeded`].
pub fn parse(bytes: &[u8]) -> Result<Value, Error> {
    let (value, consumed) = parse_item(bytes)?;
    if consumed != bytes.len() {
        return Err(invalid());
    }
    Ok(value)
}

/// Parse exactly one CBOR item from the start of `bytes`, returning the
/// item and the number of bytes consumed.
///
/// Callers parsing `authenticatorData` use this for the embedded COSE key
/// and extension items, whose lengths are not known in advance.
///
/// # Errors
/// See [`parse`]; trailing bytes after the first item are not an error here.
pub fn parse_item(bytes: &[u8]) -> Result<(Value, usize), Error> {
    parse_at(bytes, 0, 1)
}

/// Encode a value in canonical CBOR form: shortest-form integers and
/// lengths, and map keys sorted canonically (shorter encoded keys first,
/// then bytewise lexicographic). `pinUvAuthParam` HMACs depend on this
/// exact byte stream.
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

fn head(out: &mut Vec<u8>, major: u8, argument: u64) {
    let tag = major << 5;
    if argument < 24 {
        out.push(tag | argument as u8);
    } else if argument <= u64::from(u8::MAX) {
        out.push(tag | 24);
        out.push(argument as u8);
    } else if argument <= u64::from(u16::MAX) {
        out.push(tag | 25);
        out.extend_from_slice(&(argument as u16).to_be_bytes());
    } else if argument <= u64::from(u32::MAX) {
        out.push(tag | 26);
        out.extend_from_slice(&(argument as u32).to_be_bytes());
    } else {
        out.push(tag | 27);
        out.extend_from_slice(&argument.to_be_bytes());
    }
}

fn encode_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Unsigned(argument) => head(out, 0, *argument),
        Value::Negative(argument) => head(out, 1, *argument),
        Value::Bytes(bytes) => {
            head(out, 2, bytes.len() as u64);
            out.extend_from_slice(bytes);
        }
        Value::Text(text) => {
            head(out, 3, text.len() as u64);
            out.extend_from_slice(text.as_bytes());
        }
        Value::Array(items) => {
            head(out, 4, items.len() as u64);
            for item in items {
                encode_into(item, out);
            }
        }
        Value::Map(entries) => {
            let mut encoded: Vec<(Vec<u8>, &Value)> = entries
                .iter()
                .map(|(key, value)| (encode(key), value))
                .collect();
            // Canonical CBOR map order: shorter encoded keys first, then
            // bytewise lexicographic (RFC 8949 section 4.2.1).
            encoded.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
            head(out, 5, encoded.len() as u64);
            for (key, value) in encoded {
                out.extend_from_slice(&key);
                encode_into(value, out);
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
    }
}
