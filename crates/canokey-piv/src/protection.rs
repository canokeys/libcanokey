//! Host-managed PIV ADMIN DATA and PIN-protected PRINTED representations.
use canokey_protocol::{
    tlv::{TlvLimits, TlvReader},
    Error, ErrorKind, Phase, SecretBytes,
};

fn invalid() -> Error {
    Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing)
}
fn single(data: &[u8], expected: u32) -> Result<&[u8], Error> {
    let mut reader = TlvReader::new_ber(
        data,
        TlvLimits {
            max_value_bytes: 128,
            max_depth: 4,
        },
    );
    let field = reader
        .next()
        .map_err(|e| e.at(Phase::Parsing))?
        .ok_or_else(invalid)?;
    if field.tag.value() != expected || reader.next().map_err(|e| e.at(Phase::Parsing))?.is_some() {
        return Err(invalid());
    }
    Ok(field.value)
}

/// Validated stored management-protection flags; these are claims, not proof of
/// live authentication or of the actual PUK retry counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagementProtection {
    flags: u8,
}
impl ManagementProtection {
    /// Parse complete ADMIN DATA: 53 { 80 { 81 flags, optional 82 salt/83 date } }.
    /// An empty 53 or 80 is valid unconfigured data. Preserve unknown flag bits;
    /// reject duplicate/unknown fields, wrong lengths and trailing bytes.
    /// Salt is empty or 16 bytes; date is at most 8 bytes for legacy compatibility.
    /// No input is retained and no credential is read or changed.
    ///
    /// # Errors
    /// More than 128 input bytes returns LimitExceeded; malformed BER/schema
    /// returns InvalidResponse. Both report Parsing, never unconfigured success.
    pub fn from_admin_object(data: &[u8]) -> Result<Self, Error> {
        if data.len() > 128 {
            return Err(Error::new(ErrorKind::LimitExceeded).at(Phase::Parsing));
        }
        let outer = single(data, 0x53)?;
        if outer.is_empty() {
            return Ok(Self { flags: 0 });
        }
        let admin = single(outer, 0x80)?;
        let mut reader = TlvReader::new_ber(
            admin,
            TlvLimits {
                max_value_bytes: 128,
                max_depth: 4,
            },
        );
        let (mut flags, mut salt, mut date) = (None, false, false);
        while let Some(field) = reader.next().map_err(|e| e.at(Phase::Parsing))? {
            match field.tag.value() {
                0x81 if flags.is_none() && field.value.len() == 1 => flags = Some(field.value[0]),
                0x82 if !salt && matches!(field.value.len(), 0 | 16) => salt = true,
                0x83 if !date && field.value.len() <= 8 => date = true,
                _ => return Err(invalid()),
            }
        }
        Ok(Self {
            flags: flags.unwrap_or(0),
        })
    }
    /// Return observed flags, using zero for an omitted bit field.
    pub fn flags(self) -> u8 {
        self.flags
    }
    /// Whether the stored data claims a blocked PUK. Verify live retries separately.
    pub fn claims_blocked_puk(self) -> bool {
        self.flags & 1 != 0
    }
    /// Whether the stored data enables PIN-protected management-key retrieval.
    pub fn protects_management_key(self) -> bool {
        self.flags & 2 != 0
    }
}

/// Decode complete PRINTED data: 53 { 88 { 89 <24-byte management key> } }.
/// The returned owned bytes are redacted and zeroized; this does not authenticate
/// the key, select its cipher, or prove that ADMIN DATA enables its use.
///
/// # Errors
/// More than 64 input bytes returns LimitExceeded. Missing/duplicate/trailing
/// fields, malformed BER and any key length other than 24 return InvalidResponse.
/// All failures report Parsing; output is created only after complete validation.
pub fn protected_management_key_from_object(data: &[u8]) -> Result<SecretBytes, Error> {
    if data.len() > 64 {
        return Err(Error::new(ErrorKind::LimitExceeded).at(Phase::Parsing));
    }
    let key = single(single(single(data, 0x53)?, 0x88)?, 0x89)?;
    if key.len() != 24 {
        return Err(invalid());
    }
    Ok(SecretBytes::new(key.to_vec()))
}
