use crate::{keys, types::invalid, PasswordStatus, Slot};
use canokey_compat::{Capability, DeviceProfile, Support};
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
    let mut r = TlvReader::new_ber(
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
/// Borrow a constructed GET DATA value using actual firmware framing evidence.
/// Supports 65, 6E, 7A and FA only. Unknown firmware is an error; a missing wrapper
/// on modern firmware is never guessed. Validates definite BER and a total input
/// budget without rewriting original bytes or interpreting unknown field values.
pub fn data_object_contents<'a>(
    profile: &DeviceProfile,
    tag: u16,
    bytes: &'a [u8],
    limit: usize,
) -> Result<&'a [u8], Error> {
    profile.capability(Capability::OpenPgp).require()?;
    if bytes.len() > limit {
        return Err(Error::new(ErrorKind::LimitExceeded));
    }
    let wrapped = match tag {
        0x65 | 0x6e | 0x7a => Capability::OpenPgpWrappedData,
        0xfa => {
            profile
                .capability(Capability::OpenPgpAlgorithmInformation)
                .require()?;
            Capability::OpenPgpWrappedAlgorithmInformation
        }
        _ => return Err(Error::new(ErrorKind::InvalidArgument)),
    };
    let value = if profile.capability(wrapped).support == Support::Supported {
        keys::one(bytes, tag.into())?
    } else {
        bytes
    };
    let mut r = TlvReader::new_ber(
        value,
        TlvLimits {
            max_value_bytes: limit,
            ..Default::default()
        },
    );
    while let Some(f) = r.next()? {
        if f.tag.value() == u32::from(tag) {
            return Err(invalid());
        }
    }
    Ok(value)
}
/// Observed algorithm-information alternatives in card order. Repeated C1/C2/C3
/// tags are alternatives, not duplicates to discard. Unknown fields stay raw.
#[derive(Debug)]
pub struct AlgorithmInformation {
    /// Complete original FA response, including its outer tag only if transmitted.
    pub raw: SecretBytes,
    /// Advertised attribute values; advertisements do not authorize generation.
    pub fields: Vec<Field>,
}
impl AlgorithmInformation {
    /// Parse FA using the firmware's bare/wrapped layout, enforcing the input budget.
    /// Pre-1.6.1 returns UnsupportedFeature; absent alternatives are not invented.
    pub fn parse_with_profile(
        profile: &DeviceProfile,
        bytes: &[u8],
        limit: usize,
    ) -> Result<Self, Error> {
        let contents = data_object_contents(profile, 0xfa, bytes, limit)?;
        Ok(Self {
            raw: SecretBytes::new(bytes.to_vec()),
            fields: fields(contents, limit)?,
        })
    }
}
/// Parsed application-related DO 6E; no certificate, identity or trust validation.
/// Known getters check duplicates/field lengths; unknown fields remain observable.
#[derive(Debug)]
pub struct ApplicationData {
    /// Complete original 6E response; historical input may omit the outer tag.
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
    /// Parse a raw GET DATA response using the profile's explicit framing rule.
    /// Preserves original bytes, including nonminimal BER lengths. Missing or
    /// duplicate 73 fails; unknown firmware does not enable legacy guessing.
    pub fn parse_with_profile(
        profile: &DeviceProfile,
        bytes: &[u8],
        limit: usize,
    ) -> Result<Self, Error> {
        let outer = fields(data_object_contents(profile, 0x6e, bytes, limit)?, limit)?;
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
    /// Parse historical or current GET DATA framing from actual firmware evidence.
    /// The byte budget covers the original response; missing fields stay absent.
    pub fn parse_with_profile(
        profile: &DeviceProfile,
        bytes: &[u8],
        limit: usize,
    ) -> Result<Self, Error> {
        Ok(Self {
            fields: fields(data_object_contents(profile, 0x65, bytes, limit)?, limit)?,
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
