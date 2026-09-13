//! Owned public-key fields and pure SubjectPublicKeyInfo encoding.
use crate::*;
use der::{
    asn1::{Any, BitString, ObjectIdentifier, UintRef},
    Encode,
};

/// Owned public-key fields. Byte formats are algorithm-specific; this structure
/// does not attest provenance or validate RSA factorization/curve membership.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    /// Unsigned, big-endian RSA components; no DER INTEGER sign octet.
    Rsa {
        /// Algorithm carrying the expected modulus size.
        algorithm: Algorithm,
        /// Modulus n.
        modulus: Vec<u8>,
        /// Public exponent e.
        exponent: Vec<u8>,
    },
    /// Uncompressed SEC1 point for a named short-Weierstrass curve.
    Ec {
        /// Curve identifier.
        algorithm: Algorithm,
        /// 04 || X || Y with fixed-width unsigned coordinates.
        point: Vec<u8>,
    },
    /// Raw Edwards/Montgomery or post-quantum public bytes.
    Raw {
        /// Ed25519, X25519, ML-DSA-65 or ML-KEM-768.
        algorithm: Algorithm,
        /// Raw public encoding, without TLV/SPKI prefixes.
        bytes: Vec<u8>,
    },
}
pub(crate) fn rsa_len(algorithm: Algorithm) -> Option<usize> {
    match algorithm {
        Algorithm::Rsa1024 => Some(128),
        Algorithm::Rsa2048 => Some(256),
        Algorithm::Rsa3072 => Some(384),
        Algorithm::Rsa4096 => Some(512),
        _ => None,
    }
}
pub(crate) fn curve_len(algorithm: Algorithm) -> Option<usize> {
    match algorithm {
        Algorithm::EccP256 | Algorithm::Secp256k1 | Algorithm::Sm2 => Some(32),
        Algorithm::EccP384 => Some(48),
        Algorithm::EccP521 => Some(66),
        _ => None,
    }
}
fn raw_len(algorithm: Algorithm) -> Option<usize> {
    match algorithm {
        Algorithm::Ed25519 | Algorithm::X25519 => Some(32),
        Algorithm::MlDsa65 => Some(1952),
        Algorithm::MlKem768 => Some(1184),
        _ => None,
    }
}
fn invalid() -> Error {
    Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing)
}
fn unsigned(bytes: &[u8]) -> Result<&[u8], Error> {
    let start = bytes.iter().position(|b| *b != 0).ok_or_else(invalid)?;
    Ok(&bytes[start..])
}
impl PublicKey {
    /// Parse inner public-key TLV fields (81 modulus / 82 exponent, or 86 point).
    /// Excludes the generation 7F49 or metadata 04 wrapper. Copies every field;
    /// duplicate/unknown tags, zero RSA components and inconsistent sizes fail.
    /// This checks encoding only, not mathematical key validity or trust.
    pub fn from_tlv(algorithm: Algorithm, bytes: &[u8], max_bytes: usize) -> Result<Self, Error> {
        if bytes.len() > max_bytes {
            return Err(Error::new(ErrorKind::LimitExceeded));
        }
        let mut reader = TlvReader::new(
            bytes,
            TlvLimits {
                max_value_bytes: max_bytes,
                ..Default::default()
            },
        );
        let (mut modulus, mut exponent, mut point) = (None, None, None);
        while let Some(field) = reader.next()? {
            match field.tag.value() {
                0x81 if modulus.is_none() => modulus = Some(field.value),
                0x82 if exponent.is_none() => exponent = Some(field.value),
                0x86 if point.is_none() => point = Some(field.value),
                _ => return Err(invalid()),
            }
        }
        if let Some(len) = rsa_len(algorithm) {
            if point.is_some() {
                return Err(invalid());
            }
            let modulus = unsigned(modulus.ok_or_else(invalid)?)?;
            let exponent = unsigned(exponent.ok_or_else(invalid)?)?;
            if modulus.len() != len || exponent.len() > len {
                return Err(invalid());
            }
            Ok(Self::Rsa {
                algorithm,
                modulus: modulus.to_vec(),
                exponent: exponent.to_vec(),
            })
        } else {
            if modulus.is_some() || exponent.is_some() {
                return Err(invalid());
            }
            let point = point.ok_or_else(invalid)?;
            if let Some(len) = curve_len(algorithm) {
                if point.len() != 1 + len * 2 || point[0] != 4 {
                    return Err(invalid());
                }
                Ok(Self::Ec {
                    algorithm,
                    point: point.to_vec(),
                })
            } else if Some(point.len()) == raw_len(algorithm) {
                Ok(Self::Raw {
                    algorithm,
                    bytes: point.to_vec(),
                })
            } else {
                Err(invalid())
            }
        }
    }
    /// Return the semantic algorithm without claiming firmware support.
    pub fn algorithm(&self) -> Algorithm {
        match self {
            Self::Rsa { algorithm, .. }
            | Self::Ec { algorithm, .. }
            | Self::Raw { algorithm, .. } => *algorithm,
        }
    }
    /// Encode canonical DER SubjectPublicKeyInfo using RustCrypto ASN.1 types.
    /// RSA uses rsaEncryption with NULL parameters, named curves use id-ecPublicKey,
    /// and Ed/X/ML identifiers have absent parameters. No device access occurs.
    /// Invalid public enum combinations/lengths return InvalidArgument.
    pub fn to_spki_der(&self) -> Result<Vec<u8>, Error> {
        let bad = || Error::new(ErrorKind::InvalidArgument);
        let oid = |s: &str| ObjectIdentifier::new(s).map_err(|_| bad());
        let (algorithm, parameters, bytes) = match self {
            Self::Rsa {
                algorithm,
                modulus,
                exponent,
            } => {
                if rsa_len(*algorithm) != Some(modulus.len())
                    || exponent.is_empty()
                    || exponent.len() > modulus.len()
                    || modulus.first() == Some(&0)
                    || exponent.first() == Some(&0)
                {
                    return Err(bad());
                }
                let rsa = pkcs1::RsaPublicKey {
                    modulus: UintRef::new(modulus).map_err(|_| bad())?,
                    public_exponent: UintRef::new(exponent).map_err(|_| bad())?,
                };
                (
                    oid("1.2.840.113549.1.1.1")?,
                    Some(Any::null()),
                    rsa.to_der().map_err(|_| bad())?,
                )
            }
            Self::Ec { algorithm, point } => {
                if curve_len(*algorithm).is_none_or(|n| point.len() != 1 + 2 * n)
                    || point.first() != Some(&4)
                {
                    return Err(bad());
                }
                let curve = match algorithm {
                    Algorithm::EccP256 => "1.2.840.10045.3.1.7",
                    Algorithm::EccP384 => "1.3.132.0.34",
                    Algorithm::EccP521 => "1.3.132.0.35",
                    Algorithm::Secp256k1 => "1.3.132.0.10",
                    Algorithm::Sm2 => "1.2.156.10197.1.301",
                    _ => return Err(bad()),
                };
                (
                    oid("1.2.840.10045.2.1")?,
                    Some(Any::encode_from(&oid(curve)?).map_err(|_| bad())?),
                    point.clone(),
                )
            }
            Self::Raw { algorithm, bytes } => {
                if raw_len(*algorithm) != Some(bytes.len()) {
                    return Err(bad());
                }
                let id = match algorithm {
                    Algorithm::Ed25519 => "1.3.101.112",
                    Algorithm::X25519 => "1.3.101.110",
                    Algorithm::MlDsa65 => "2.16.840.1.101.3.4.3.18",
                    Algorithm::MlKem768 => "2.16.840.1.101.3.4.4.2",
                    _ => return Err(bad()),
                };
                (oid(id)?, None, bytes.clone())
            }
        };
        spki::SubjectPublicKeyInfoOwned {
            algorithm: spki::AlgorithmIdentifierOwned {
                oid: algorithm,
                parameters,
            },
            subject_public_key: BitString::from_bytes(&bytes).map_err(|_| bad())?,
        }
        .to_der()
        .map_err(|_| bad())
    }
}
