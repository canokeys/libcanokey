//! COSE key format parsing and encoding for CTAP2 (RFC 9052 labels).
//!
//! This module only parses and validates key *formats*: key type, curve,
//! algorithm labels and exact coordinate/key widths. Consistent with the
//! workspace certificate-inspection rule, it enforces no trust, validity or
//! attestation policy, and it never handles private key material — a COSE
//! map carrying a private-key label (-4 for EC2/OKP, -2 for AKP) is
//! rejected outright.
//!
//! Unknown algorithms are preserved losslessly as the original CBOR map so
//! callers can pass them through to their own policy.

use crate::cbor::Value;
use canokey_protocol::{Error, ErrorKind, Phase};

fn invalid() -> Error {
    Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing)
}

/// Public-key length in bytes for ML-DSA-44 (COSE algorithm -48).
pub const ML_DSA_44_PUBLIC_LEN: usize = 1312;
/// Public-key length in bytes for ML-DSA-65 (COSE algorithm -49).
pub const ML_DSA_65_PUBLIC_LEN: usize = 1952;
/// Public-key length in bytes for ML-DSA-87 (COSE algorithm -50).
pub const ML_DSA_87_PUBLIC_LEN: usize = 2592;

/// A COSE algorithm identifier relevant to CTAP2 authenticators.
///
/// Resolution accepts the aliases authenticators use in practice: ES256 is
/// reported as -7 or fully-specified -9, Ed25519 as -8 or fully-specified
/// -19. [`Self::id`] normalizes to the primary identifier (-7 / -8).
/// [`Self::EcdhEsHkdf256`] (-25) is key agreement only and never signs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoseAlgorithm {
    /// ECDSA with SHA-256 over NIST P-256 (COSE -7, also accepted as -9).
    Es256,
    /// Ed25519 (COSE -8, also accepted as fully-specified -19).
    Ed25519,
    /// ML-DSA-44 (COSE -48, RFC 9964).
    MlDsa44,
    /// ML-DSA-65 (COSE -49, RFC 9964).
    MlDsa65,
    /// ML-DSA-87 (COSE -50, RFC 9964).
    MlDsa87,
    /// ECDH-ES with HKDF-SHA-256 (COSE -25); key agreement only, never a
    /// signature algorithm.
    EcdhEsHkdf256,
    /// Any other algorithm identifier, preserved raw.
    Unknown(i64),
}
impl CoseAlgorithm {
    /// Resolve a COSE algorithm identifier to a typed algorithm.
    pub fn from_id(id: i64) -> Self {
        match id {
            -7 | -9 => Self::Es256,
            -8 | -19 => Self::Ed25519,
            -48 => Self::MlDsa44,
            -49 => Self::MlDsa65,
            -50 => Self::MlDsa87,
            -25 => Self::EcdhEsHkdf256,
            other => Self::Unknown(other),
        }
    }
    /// Return the canonical COSE identifier for this algorithm. Aliases
    /// normalize: -9 becomes -7 and -19 becomes -8.
    pub fn id(self) -> i64 {
        match self {
            Self::Es256 => -7,
            Self::Ed25519 => -8,
            Self::MlDsa44 => -48,
            Self::MlDsa65 => -49,
            Self::MlDsa87 => -50,
            Self::EcdhEsHkdf256 => -25,
            Self::Unknown(id) => id,
        }
    }
    /// Return whether this algorithm produces signatures. ECDH-ES+HKDF-256
    /// is key agreement only, and unknown algorithms make no claim.
    pub fn is_signature(self) -> bool {
        matches!(
            self,
            Self::Es256 | Self::Ed25519 | Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87
        )
    }
}

/// A parsed COSE public key.
///
/// Coordinates are validated for presence and exact width only; point-on-
/// curve checks and any trust decision belong to the caller's cryptographic
/// backend. `Debug` is derived: all fields are public key material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoseKey {
    /// A NIST P-256 public key (COSE kty 2, crv 1). `algorithm` is either
    /// [`CoseAlgorithm::Es256`] or [`CoseAlgorithm::EcdhEsHkdf256`].
    P256 {
        /// The resolved algorithm of the key.
        algorithm: CoseAlgorithm,
        /// The x coordinate, exactly 32 bytes.
        x: [u8; 32],
        /// The y coordinate, exactly 32 bytes.
        y: [u8; 32],
    },
    /// An Ed25519 public key (COSE kty 1, crv 6).
    Ed25519 {
        /// The public key, exactly 32 bytes.
        x: [u8; 32],
    },
    /// An ML-DSA public key (COSE kty 7, RFC 9964).
    MlDsa {
        /// The resolved algorithm; determines the exact key length
        /// (1312/1952/2592 bytes for 44/65/87).
        algorithm: CoseAlgorithm,
        /// The public key bytes.
        public: Vec<u8>,
    },
    /// A key whose algorithm is not resolved, kept as the original map.
    Unknown(Value),
}
impl CoseKey {
    /// Parse a COSE key from a decoded CBOR map.
    ///
    /// Labels 1 (kty) and 3 (alg) are required integers. For resolved
    /// algorithms the key-type-specific labels are checked: EC2 keys need
    /// crv (-1) = 1 and 32-byte x (-2)/y (-3); OKP keys need crv (-1) = 6
    /// and a 32-byte x (-2); AKP keys need the public key (-1) at the exact
    /// ML-DSA length. Presence of private-key labels (-4 for EC2/OKP, -2
    /// for AKP) is an error. Unresolved algorithms are returned as
    /// [`CoseKey::Unknown`] with the original map preserved.
    ///
    /// # Errors
    /// Structural, label or width violations fail as
    /// [`ErrorKind::InvalidResponse`] in [`Phase::Parsing`].
    pub fn from_value(value: &Value) -> Result<Self, Error> {
        if value.as_map().is_none() {
            return Err(invalid());
        }
        let kty = value
            .map_get_int(1)
            .and_then(Value::as_int)
            .ok_or_else(invalid)?;
        let algorithm = CoseAlgorithm::from_id(
            value
                .map_get_int(3)
                .and_then(Value::as_int)
                .ok_or_else(invalid)?,
        );
        match algorithm {
            CoseAlgorithm::Es256 | CoseAlgorithm::EcdhEsHkdf256 => {
                if kty != 2 || value.map_get_int(-4).is_some() {
                    return Err(invalid());
                }
                let crv = value
                    .map_get_int(-1)
                    .and_then(Value::as_int)
                    .ok_or_else(invalid)?;
                let x = fixed_bytes(value.map_get_int(-2))?;
                let y = fixed_bytes(value.map_get_int(-3))?;
                if crv != 1 {
                    return Err(invalid());
                }
                Ok(Self::P256 { algorithm, x, y })
            }
            CoseAlgorithm::Ed25519 => {
                if kty != 1 || value.map_get_int(-4).is_some() {
                    return Err(invalid());
                }
                let crv = value
                    .map_get_int(-1)
                    .and_then(Value::as_int)
                    .ok_or_else(invalid)?;
                let x = fixed_bytes(value.map_get_int(-2))?;
                if crv != 6 {
                    return Err(invalid());
                }
                Ok(Self::Ed25519 { x })
            }
            CoseAlgorithm::MlDsa44 | CoseAlgorithm::MlDsa65 | CoseAlgorithm::MlDsa87 => {
                if kty != 7 || value.map_get_int(-2).is_some() {
                    return Err(invalid());
                }
                let public = value
                    .map_get_int(-1)
                    .and_then(Value::as_bytes)
                    .ok_or_else(invalid)?
                    .to_vec();
                let expected = match algorithm {
                    CoseAlgorithm::MlDsa44 => ML_DSA_44_PUBLIC_LEN,
                    CoseAlgorithm::MlDsa65 => ML_DSA_65_PUBLIC_LEN,
                    _ => ML_DSA_87_PUBLIC_LEN,
                };
                if public.len() != expected {
                    return Err(invalid());
                }
                Ok(Self::MlDsa { algorithm, public })
            }
            CoseAlgorithm::Unknown(_) => Ok(Self::Unknown(value.clone())),
        }
    }
    /// Return the resolved algorithm, or `None` for an unknown key (whose
    /// raw algorithm label, if any, can be read from the preserved map).
    pub fn algorithm(&self) -> Option<CoseAlgorithm> {
        match self {
            Self::P256 { algorithm, .. } | Self::MlDsa { algorithm, .. } => Some(*algorithm),
            Self::Ed25519 { .. } => Some(CoseAlgorithm::Ed25519),
            Self::Unknown(_) => None,
        }
    }
    /// Encode back to a CBOR map value, for example as a `keyAgreement`
    /// parameter in an authenticatorClientPIN request. Unknown keys encode
    /// as their preserved original map.
    pub fn to_value(&self) -> Value {
        match self {
            Self::P256 { algorithm, x, y } => Value::Map(vec![
                (Value::from_int(1), Value::from_int(2)),
                (Value::from_int(3), Value::from_int(algorithm.id())),
                (Value::from_int(-1), Value::from_int(1)),
                (Value::from_int(-2), Value::Bytes(x.to_vec())),
                (Value::from_int(-3), Value::Bytes(y.to_vec())),
            ]),
            Self::Ed25519 { x } => Value::Map(vec![
                (Value::from_int(1), Value::from_int(1)),
                (
                    Value::from_int(3),
                    Value::from_int(CoseAlgorithm::Ed25519.id()),
                ),
                (Value::from_int(-1), Value::from_int(6)),
                (Value::from_int(-2), Value::Bytes(x.to_vec())),
            ]),
            Self::MlDsa { algorithm, public } => Value::Map(vec![
                (Value::from_int(1), Value::from_int(7)),
                (Value::from_int(3), Value::from_int(algorithm.id())),
                (Value::from_int(-1), Value::Bytes(public.clone())),
            ]),
            Self::Unknown(map) => map.clone(),
        }
    }
}

fn fixed_bytes(value: Option<&Value>) -> Result<[u8; 32], Error> {
    let bytes = value.and_then(Value::as_bytes).ok_or_else(invalid)?;
    bytes.try_into().map_err(|_| invalid())
}
