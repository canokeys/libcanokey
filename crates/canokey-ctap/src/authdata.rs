//! `authenticatorData` parsing for CTAP2 attestation and assertion responses.
//!
//! Layout: `rpIdHash[32] | flags[1] | signCount[4, big-endian] |
//! attestedCredentialData? | extensions?`. The attested credential data is
//! present when the AT flag is set: `aaguid[16] | credentialIdLength[2,
//! big-endian] | credentialId | credentialPublicKey` (one CBOR item). The
//! extensions, present when the ED flag is set, are one CBOR map with text
//! keys, kept undecoded as a [`Value`].

use crate::cbor::{self, Value};
use crate::cose::CoseKey;
use canokey_protocol::{Error, ErrorKind, Phase};

/// Minimum byte length of a valid `authenticatorData` (no AT/ED sections).
pub const MIN_LEN: usize = 37;
/// Maximum byte length accepted for `authenticatorData`.
pub const MAX_LEN: usize = 65536;
/// Maximum accepted credential ID length inside attested credential data.
pub const MAX_CREDENTIAL_ID_LEN: usize = 1023;

fn invalid() -> Error {
    Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing)
}

/// The attested credential data section of `authenticatorData` (AT flag).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestedCredentialData {
    aaguid: [u8; 16],
    credential_id: Vec<u8>,
    credential_public_key: CoseKey,
}
impl AttestedCredentialData {
    /// Return the authenticator's AAGUID.
    pub fn aaguid(&self) -> &[u8; 16] {
        &self.aaguid
    }
    /// Return the credential ID (1..=1023 bytes by construction).
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }
    /// Return the credential public key as a parsed COSE key.
    pub fn credential_public_key(&self) -> &CoseKey {
        &self.credential_public_key
    }
}

/// A parsed `authenticatorData` structure, retaining the raw bytes.
///
/// The raw bytes are the exact input slice (bounded by [`MAX_LEN`]) because
/// they are what attestation signatures and `pinUvAuthParam` HMACs cover.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatorData {
    raw: Vec<u8>,
    rp_id_hash: [u8; 32],
    flags: u8,
    sign_count: u32,
    attested_credential_data: Option<AttestedCredentialData>,
    extensions: Option<Value>,
}
impl AuthenticatorData {
    /// Flags bit: user present (UP, 0x01).
    pub const FLAG_UP: u8 = 0x01;
    /// Flags bit: user verified (UV, 0x04).
    pub const FLAG_UV: u8 = 0x04;
    /// Flags bit: backup eligible (BE, 0x08).
    pub const FLAG_BE: u8 = 0x08;
    /// Flags bit: backed up (BS, 0x10); requires [`Self::FLAG_BE`].
    pub const FLAG_BS: u8 = 0x10;
    /// Flags bit: attested credential data included (AT, 0x40).
    pub const FLAG_AT: u8 = 0x40;
    /// Flags bit: extension data included (ED, 0x80).
    pub const FLAG_ED: u8 = 0x80;

    /// Parse a complete `authenticatorData` byte string.
    ///
    /// The total length must be within [`MIN_LEN`]..=[`MAX_LEN`], BS must
    /// not be set without BE, an AT section must contain a credential ID of
    /// 1..=[`MAX_CREDENTIAL_ID_LEN`] bytes followed by exactly one CBOR COSE
    /// key, an ED section must be exactly one CBOR map with text keys, and
    /// no trailing bytes are accepted.
    ///
    /// # Errors
    /// Every structural violation fails as [`ErrorKind::InvalidResponse`] in
    /// [`Phase::Parsing`]; CBOR nesting beyond the limit fails as
    /// [`ErrorKind::LimitExceeded`].
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < MIN_LEN || bytes.len() > MAX_LEN {
            return Err(invalid());
        }
        let rp_id_hash: [u8; 32] = bytes[..32].try_into().map_err(|_| invalid())?;
        let flags = bytes[32];
        let sign_count = u32::from_be_bytes(bytes[33..37].try_into().map_err(|_| invalid())?);
        if flags & Self::FLAG_BS != 0 && flags & Self::FLAG_BE == 0 {
            return Err(invalid());
        }
        let mut pos = 37;
        let attested_credential_data = if flags & Self::FLAG_AT != 0 {
            let header = bytes.get(pos..pos + 18).ok_or_else(invalid)?;
            let aaguid: [u8; 16] = header[..16].try_into().map_err(|_| invalid())?;
            let id_len = u16::from_be_bytes([header[16], header[17]]) as usize;
            if !(1..=MAX_CREDENTIAL_ID_LEN).contains(&id_len) {
                return Err(invalid());
            }
            pos += 18;
            let credential_id = bytes.get(pos..pos + id_len).ok_or_else(invalid)?.to_vec();
            pos += id_len;
            let (key_value, consumed) = cbor::parse_item(&bytes[pos..])?;
            pos += consumed;
            let credential_public_key = CoseKey::from_value(&key_value)?;
            Some(AttestedCredentialData {
                aaguid,
                credential_id,
                credential_public_key,
            })
        } else {
            None
        };
        let extensions = if flags & Self::FLAG_ED != 0 {
            let (value, consumed) = cbor::parse_item(&bytes[pos..])?;
            let entries = value.as_map().ok_or_else(invalid)?;
            if entries.iter().any(|(key, _)| key.as_text().is_none()) {
                return Err(invalid());
            }
            pos += consumed;
            Some(value)
        } else {
            None
        };
        if pos != bytes.len() {
            return Err(invalid());
        }
        Ok(Self {
            raw: bytes.to_vec(),
            rp_id_hash,
            flags,
            sign_count,
            attested_credential_data,
            extensions,
        })
    }
    /// Return the raw `authenticatorData` bytes as received.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
    /// Return the SHA-256 hash of the relying party ID.
    pub fn rp_id_hash(&self) -> &[u8; 32] {
        &self.rp_id_hash
    }
    /// Return the raw flags byte.
    pub fn flags(&self) -> u8 {
        self.flags
    }
    /// Return the signature counter.
    pub fn sign_count(&self) -> u32 {
        self.sign_count
    }
    /// Return whether the user-present flag (UP) is set.
    pub fn user_present(&self) -> bool {
        self.flags & Self::FLAG_UP != 0
    }
    /// Return whether the user-verified flag (UV) is set.
    pub fn user_verified(&self) -> bool {
        self.flags & Self::FLAG_UV != 0
    }
    /// Return whether the backup-eligible flag (BE) is set.
    pub fn backup_eligible(&self) -> bool {
        self.flags & Self::FLAG_BE != 0
    }
    /// Return whether the backed-up flag (BS) is set.
    pub fn backed_up(&self) -> bool {
        self.flags & Self::FLAG_BS != 0
    }
    /// Return the attested credential data when the AT flag was set.
    pub fn attested_credential_data(&self) -> Option<&AttestedCredentialData> {
        self.attested_credential_data.as_ref()
    }
    /// Return the extensions map (text keys) when the ED flag was set.
    pub fn extensions(&self) -> Option<&Value> {
        self.extensions.as_ref()
    }
}
