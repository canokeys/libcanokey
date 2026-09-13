//! Bounded, definite-length BER TLV; no map conversion discards duplicate tags.
use crate::{Error, ErrorKind, Phase, SecretBytes};
fn malformed() -> Error {
    Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tag {
    value: u32,
    len: u8,
}
impl Tag {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let (tag, len) = parse_tag(bytes)?;
        if len != bytes.len() {
            return Err(malformed());
        }
        Ok(tag)
    }
    pub fn value(self) -> u32 {
        self.value
    }
    pub fn to_bytes(self) -> Vec<u8> {
        self.value.to_be_bytes()[4 - self.len as usize..].to_vec()
    }
}
fn parse_tag(bytes: &[u8]) -> Result<(Tag, usize), Error> {
    let first = *bytes.first().ok_or_else(malformed)?;
    if first == 0 || first == 0xff {
        return Err(malformed());
    }
    let mut n = 1;
    if first & 31 == 31 {
        if bytes.get(1).is_none_or(|v| v & 127 == 0) {
            return Err(malformed());
        }
        loop {
            let byte = *bytes.get(n).ok_or_else(malformed)?;
            n += 1;
            if n > 4 {
                return Err(malformed());
            }
            if byte & 128 == 0 {
                break;
            }
        }
    }
    let value = bytes[..n].iter().fold(0, |v, b| (v << 8) | u32::from(*b));
    Ok((
        Tag {
            value,
            len: n as u8,
        },
        n,
    ))
}
#[derive(Clone, Copy, Debug)]
pub struct TlvLimits {
    pub max_value_bytes: usize,
    pub max_depth: usize,
}
impl Default for TlvLimits {
    fn default() -> Self {
        Self {
            max_value_bytes: 1024 * 1024,
            max_depth: 16,
        }
    }
}
#[derive(Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: Tag,
    pub value: &'a [u8],
    depth: usize,
    limits: TlvLimits,
}
impl<'a> Tlv<'a> {
    pub fn children(self) -> Result<TlvReader<'a>, Error> {
        if self.depth >= self.limits.max_depth {
            return Err(Error::new(ErrorKind::LimitExceeded));
        }
        Ok(TlvReader {
            bytes: self.value,
            depth: self.depth + 1,
            limits: self.limits,
        })
    }
}
pub struct TlvReader<'a> {
    bytes: &'a [u8],
    depth: usize,
    limits: TlvLimits,
}
impl<'a> TlvReader<'a> {
    pub fn new(bytes: &'a [u8], limits: TlvLimits) -> Self {
        Self {
            bytes,
            depth: 1,
            limits,
        }
    }
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Tlv<'a>>, Error> {
        if self.bytes.is_empty() {
            return Ok(None);
        }
        if self.depth > self.limits.max_depth {
            return Err(Error::new(ErrorKind::LimitExceeded));
        }
        let (tag, mut offset) = parse_tag(self.bytes)?;
        let first = *self.bytes.get(offset).ok_or_else(malformed)?;
        offset += 1;
        let len = if first < 128 {
            first as usize
        } else {
            let n = (first & 127) as usize;
            if n == 0 || n > 4 {
                return Err(malformed());
            }
            let encoded = self.bytes.get(offset..offset + n).ok_or_else(malformed)?;
            if encoded[0] == 0 {
                return Err(malformed());
            }
            offset += n;
            let mut len = 0usize;
            for b in encoded {
                len = len
                    .checked_mul(256)
                    .and_then(|v| v.checked_add(*b as usize))
                    .ok_or_else(malformed)?;
            }
            if len < 128 {
                return Err(malformed());
            }
            len
        };
        if len > self.limits.max_value_bytes {
            return Err(Error::new(ErrorKind::LimitExceeded));
        }
        let end = offset.checked_add(len).ok_or_else(malformed)?;
        let value = self.bytes.get(offset..end).ok_or_else(malformed)?;
        self.bytes = &self.bytes[end..];
        Ok(Some(Tlv {
            tag,
            value,
            depth: self.depth,
            limits: self.limits,
        }))
    }
}
pub struct TlvWriter {
    bytes: SecretBytes,
    limit: usize,
}
impl TlvWriter {
    pub fn new(limit: usize) -> Self {
        Self {
            bytes: SecretBytes::default(),
            limit,
        }
    }
    pub fn push(&mut self, tag: Tag, value: &[u8]) -> Result<(), Error> {
        let mut prefix = tag.to_bytes();
        if value.len() < 128 {
            prefix.push(value.len() as u8);
        } else {
            let n = u32::try_from(value.len()).map_err(|_| Error::new(ErrorKind::LimitExceeded))?;
            let bytes = n.to_be_bytes();
            let start = bytes.iter().position(|b| *b != 0).unwrap_or(3);
            prefix.push(0x80 | (4 - start) as u8);
            prefix.extend_from_slice(&bytes[start..]);
        }
        if self
            .bytes
            .len()
            .checked_add(prefix.len())
            .and_then(|n| n.checked_add(value.len()))
            .is_none_or(|n| n > self.limit)
        {
            return Err(Error::new(ErrorKind::LimitExceeded));
        }
        self.bytes.extend(&prefix);
        self.bytes.extend(value);
        Ok(())
    }
    pub fn into_bytes(self) -> SecretBytes {
        self.bytes
    }
}

impl Default for TlvWriter {
    fn default() -> Self {
        Self::new(1024 * 1024)
    }
}
