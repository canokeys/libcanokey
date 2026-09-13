use crate::{keys, types::invalid, PasswordStatus, Slot};
use canokey_protocol::{
    tlv::{TlvLimits, TlvReader},
    Error, ErrorKind, SecretBytes,
};
/// One owned OpenPGP field, preserving wire order and unknown tags.
#[derive(Debug)]
pub struct Field {
    /// Complete BER tag packed big-endian.
    pub tag: u32,
    /// Original field value, excluding its tag/length wrapper.
    pub value: SecretBytes,
}
fn fields(bytes: &[u8], limit: usize) -> Result<Vec<Field>, Error> {
    if bytes.len() > limit {
        return Err(Error::new(ErrorKind::LimitExceeded));
    }
    let mut r = TlvReader::new(
        bytes,
        TlvLimits {
            max_value_bytes: limit,
            ..Default::default()
        },
    );
    let mut fields = Vec::new();
    while let Some(f) = r.next()? {
        fields.push(Field {
            tag: f.tag.value(),
            value: SecretBytes::new(f.value.to_vec()),
        });
    }
    Ok(fields)
}
fn unique(fields: &[Field], tag: u32) -> Result<Option<&[u8]>, Error> {
    let mut found = None;
    for f in fields {
        if f.tag == tag {
            if found.is_some() {
                return Err(invalid());
            }
            found = Some(f.value.as_bytes());
        }
    }
    Ok(found)
}
/// Parsed application-related DO 6E; no certificate, identity or trust validation.
/// Known getters check duplicates/field lengths; unknown fields remain observable.
#[derive(Debug)]
pub struct ApplicationData {
    /// Complete original wrapped 6E response.
    pub raw: SecretBytes,
    /// Outer fields, including AID, historical bytes and raw discretionary 73.
    pub fields: Vec<Field>,
    /// Fields nested under the unique discretionary 73 object.
    pub discretionary: Vec<Field>,
}
impl ApplicationData {
    /// Parse one complete wrapped 6E object within the caller's byte limit.
    /// Missing/duplicate 73 or malformed TLV fails. Optional fields are not invented.
    pub fn parse(bytes: &[u8], limit: usize) -> Result<Self, Error> {
        if bytes.len() > limit {
            return Err(Error::new(ErrorKind::LimitExceeded));
        }
        let outer = fields(keys::one(bytes, 0x6e)?, limit)?;
        let discretionary = fields(unique(&outer, 0x73)?.ok_or_else(invalid)?, limit)?;
        Ok(Self {
            raw: SecretBytes::new(bytes.to_vec()),
            fields: outer,
            discretionary,
        })
    }
    /// Optional 16-byte AID, without asserting a manufacturer, serial or identity.
    pub fn aid(&self) -> Result<Option<[u8; 16]>, Error> {
        unique(&self.fields, 0x4f)?
            .map(|b| b.try_into().map_err(|_| invalid()))
            .transpose()
    }
    /// Optional typed PW status; retry observations are not authorization state.
    pub fn password_status(&self) -> Result<Option<PasswordStatus>, Error> {
        unique(&self.discretionary, 0xc4)?
            .map(PasswordStatus::parse)
            .transpose()
    }
    /// Optional raw per-slot algorithm attributes, without guessed defaults.
    pub fn algorithm_attributes(&self, slot: Slot) -> Result<Option<&[u8]>, Error> {
        unique(&self.discretionary, slot.attributes().into())
    }
    /// Optional 20-byte fingerprint from the 60-byte aggregate C5 field.
    pub fn fingerprint(&self, slot: Slot) -> Result<Option<[u8; 20]>, Error> {
        unique(&self.discretionary, 0xc5)?
            .map(|b| {
                if b.len() != 60 {
                    return Err(invalid());
                }
                let at = slot.occurrence() as usize * 20;
                b[at..at + 20].try_into().map_err(|_| invalid())
            })
            .transpose()
    }
    /// Optional generation time from the 12-byte aggregate CD; zero remains zero.
    pub fn generation_time(&self, slot: Slot) -> Result<Option<u32>, Error> {
        unique(&self.discretionary, 0xcd)?
            .map(|b| {
                if b.len() != 12 {
                    return Err(invalid());
                }
                let at = slot.occurrence() as usize * 4;
                Ok(u32::from_be_bytes(
                    b[at..at + 4].try_into().map_err(|_| invalid())?,
                ))
            })
            .transpose()
    }
    /// Optional raw two-byte UIF, preserving unknown policy/feature values.
    pub fn touch_policy(&self, slot: Slot) -> Result<Option<[u8; 2]>, Error> {
        unique(&self.discretionary, u32::from(0xd6 + slot.occurrence()))?
            .map(|b| b.try_into().map_err(|_| invalid()))
            .transpose()
    }
}
/// Parsed wrapped cardholder DO 65; opaque text bytes remain unchanged.
#[derive(Debug)]
pub struct CardholderData {
    /// All original fields in order, including unknown values.
    pub fields: Vec<Field>,
}
impl CardholderData {
    /// Parse exactly one wrapped 65 object within a byte budget.
    pub fn parse(bytes: &[u8], limit: usize) -> Result<Self, Error> {
        if bytes.len() > limit {
            return Err(Error::new(ErrorKind::LimitExceeded));
        }
        Ok(Self {
            fields: fields(keys::one(bytes, 0x65)?, limit)?,
        })
    }
    /// Optional raw cardholder name; duplicate names fail.
    pub fn name(&self) -> Result<Option<&[u8]>, Error> {
        unique(&self.fields, 0x5b)
    }
    /// Optional raw language preferences; duplicate fields fail.
    pub fn language(&self) -> Result<Option<&[u8]>, Error> {
        unique(&self.fields, 0x5f2d)
    }
    /// Optional raw sex marker, without interpreting its meaning.
    pub fn sex(&self) -> Result<Option<&[u8]>, Error> {
        unique(&self.fields, 0x5f35)
    }
}
