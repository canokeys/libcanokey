//! Immutable capability snapshots. Version rules live here, not in operations.
#![forbid(unsafe_code)]
use canokey_protocol::{Error, ErrorKind};
use std::collections::BTreeMap;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirmwareVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
    pub suffix: Option<String>,
}
impl FirmwareVersion {
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim().strip_prefix('v').unwrap_or(text.trim());
        let at = text.find(['-', '+']).unwrap_or(text.len());
        let (numbers, suffix) = text.split_at(at);
        if !suffix.is_empty()
            && (suffix.len() == 1
                || !suffix.as_bytes()[1].is_ascii_alphanumeric()
                || !suffix[1..]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b)))
        {
            return None;
        }
        let numbers: Vec<&str> = numbers.split('.').collect();
        if !(2..=3).contains(&numbers.len())
            || numbers
                .iter()
                .any(|n| n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()))
        {
            return None;
        }
        Some(Self {
            major: numbers[0].parse().ok()?,
            minor: numbers[1].parse().ok()?,
            patch: numbers.get(2).unwrap_or(&"0").parse().ok()?,
            suffix: (!suffix.is_empty()).then(|| suffix.to_owned()),
        })
    }
    fn tuple(&self) -> (u16, u16, u16) {
        (self.major, self.minor, self.patch)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PivApplicationVersion(pub [u8; 3]);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Support {
    Supported,
    Unsupported,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evidence {
    Observed,
    FirmwareMatrix,
    LatestKnownFallback,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityStatus {
    pub support: Support,
    pub evidence: Evidence,
}
impl CapabilityStatus {
    pub fn require(self) -> Result<(), Error> {
        match self.support {
            Support::Supported => Ok(()),
            Support::Unsupported => Err(Error::new(ErrorKind::UnsupportedFeature)),
            Support::Unknown => Err(Error::new(ErrorKind::CapabilityUnknown)),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    Piv,
    Metadata,
    EccP256,
    EccP384,
    AlgorithmExtensions,
    RetiredSlots,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Algorithm {
    Rsa1024,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EccP256,
    EccP384,
    EccP521,
    Secp256k1,
    Sm2,
    Ed25519,
    X25519,
    MlDsa65,
    MlKem768,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlgorithmConfig {
    enabled: bool,
    ids: BTreeMap<Algorithm, u8>,
    raw: Vec<u8>,
}
impl AlgorithmConfig {
    /// Parse observed configuration without inventing missing extension fields.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() < 7 || data[0] > 1 {
            return Err(Error::new(ErrorKind::InvalidResponse));
        }
        let mut algorithms = vec![
            Algorithm::Ed25519,
            Algorithm::Rsa3072,
            Algorithm::Rsa4096,
            Algorithm::X25519,
            Algorithm::Secp256k1,
        ];
        if data.len() >= 8 {
            algorithms.push(Algorithm::EccP521);
        }
        algorithms.push(Algorithm::Sm2);
        if data.len() >= 9 {
            algorithms.push(Algorithm::MlDsa65);
        }
        if data.len() >= 10 {
            algorithms.push(Algorithm::MlKem768);
        }
        let mut ids = BTreeMap::new();
        for (alg, id) in algorithms.into_iter().zip(data[1..].iter().copied()) {
            if id == 0
                || [0x06, 0x07, 0x11, 0x14].contains(&id)
                || ids.values().any(|old| *old == id)
            {
                return Err(Error::new(ErrorKind::InvalidResponse));
            }
            ids.insert(alg, id);
        }
        Ok(Self {
            enabled: data[0] == 1,
            ids,
            raw: data.to_vec(),
        })
    }
    pub fn enabled(&self) -> bool {
        self.enabled
    }
    pub fn wire_id(&self, algorithm: Algorithm) -> Option<u8> {
        self.ids.get(&algorithm).copied().filter(|_| self.enabled)
    }
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
}
#[derive(Clone, Debug)]
pub struct DeviceInfo {
    firmware_text: Vec<u8>,
    firmware: Option<FirmwareVersion>,
    model: Option<String>,
    serial: Option<Vec<u8>>,
    piv_version: Option<PivApplicationVersion>,
}
impl DeviceInfo {
    pub fn firmware_text(&self) -> &[u8] {
        &self.firmware_text
    }
    pub fn firmware(&self) -> Option<&FirmwareVersion> {
        self.firmware.as_ref()
    }
    pub fn model(&self) -> Option<&str> {
        self.model.as_deref()
    }
    pub fn serial(&self) -> Option<&[u8]> {
        self.serial.as_deref()
    }
    pub fn piv_version(&self) -> Option<PivApplicationVersion> {
        self.piv_version
    }
}
/// Observations supplied together by a probe of one device. No credentials or I/O handles.
#[derive(Clone, Debug)]
pub struct DeviceObservations {
    pub firmware_text: Vec<u8>,
    pub model: Option<String>,
    pub serial: Option<Vec<u8>>,
    pub piv_version: Option<PivApplicationVersion>,
    pub algorithm_config: Option<AlgorithmConfig>,
    pub warnings: Vec<CompatibilityWarning>,
}
impl DeviceObservations {
    pub fn new(firmware_text: Vec<u8>) -> Self {
        Self {
            firmware_text,
            model: None,
            serial: None,
            piv_version: None,
            algorithm_config: None,
            warnings: Vec::new(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompatibilityWarning {
    UnrecognizedFirmware,
    LatestKnownFallback,
    OptionalCommandUnsupported(&'static str),
    OptionalCommandNeedsAuthentication(&'static str),
}
#[derive(Clone, Debug)]
pub struct DeviceProfile {
    info: DeviceInfo,
    config: Option<AlgorithmConfig>,
    warnings: Vec<CompatibilityWarning>,
}
impl DeviceProfile {
    pub fn from_observations(mut observations: DeviceObservations) -> Result<Self, Error> {
        if observations.firmware_text.is_empty()
            || observations.firmware_text.len() > 256
            || observations.serial.as_ref().is_some_and(|s| s.len() != 4)
        {
            return Err(Error::new(ErrorKind::InvalidResponse));
        }
        let firmware = std::str::from_utf8(&observations.firmware_text)
            .ok()
            .and_then(FirmwareVersion::parse);
        if firmware.is_none() {
            observations
                .warnings
                .push(CompatibilityWarning::UnrecognizedFirmware);
        } else if firmware
            .as_ref()
            .is_some_and(|f| f.tuple() > (3, 1, 0) || f.suffix.is_some())
        {
            observations
                .warnings
                .push(CompatibilityWarning::LatestKnownFallback);
        }
        Ok(Self {
            info: DeviceInfo {
                firmware_text: observations.firmware_text,
                firmware,
                model: observations.model,
                serial: observations.serial,
                piv_version: observations.piv_version,
            },
            config: observations.algorithm_config,
            warnings: observations.warnings,
        })
    }
    pub fn info(&self) -> &DeviceInfo {
        &self.info
    }
    pub fn warnings(&self) -> &[CompatibilityWarning] {
        &self.warnings
    }
    pub fn algorithm_config(&self) -> Option<&AlgorithmConfig> {
        self.config.as_ref()
    }
    pub fn capability(&self, feature: Capability) -> CapabilityStatus {
        use {Evidence::*, Support::*};
        if feature == Capability::Piv {
            return CapabilityStatus {
                support: if self.info.piv_version.is_some() {
                    Supported
                } else {
                    Unknown
                },
                evidence: Observed,
            };
        }
        if feature == Capability::AlgorithmExtensions {
            if self
                .warnings
                .contains(&CompatibilityWarning::OptionalCommandUnsupported(
                    "algorithm_config",
                ))
            {
                return CapabilityStatus {
                    support: Unsupported,
                    evidence: Observed,
                };
            }
            if self
                .warnings
                .contains(&CompatibilityWarning::OptionalCommandNeedsAuthentication(
                    "algorithm_config",
                ))
            {
                return CapabilityStatus {
                    support: Unknown,
                    evidence: Observed,
                };
            }
            if let Some(config) = &self.config {
                return CapabilityStatus {
                    support: if config.enabled {
                        Supported
                    } else {
                        Unsupported
                    },
                    evidence: Observed,
                };
            }
        }
        let threshold = match feature {
            Capability::EccP256 | Capability::EccP384 => (1, 3, 0),
            _ => (2, 0, 0),
        };
        if let Some(version) = self.info.firmware.as_ref() {
            if version.suffix.is_none() && ((1, 3, 0)..=(3, 1, 0)).contains(&version.tuple()) {
                return CapabilityStatus {
                    support: if version.tuple() >= threshold {
                        Supported
                    } else {
                        Unsupported
                    },
                    evidence: FirmwareMatrix,
                };
            }
        }
        CapabilityStatus {
            support: if feature == Capability::EccP256 && self.info.piv_version.is_some() {
                Supported
            } else {
                Unknown
            },
            evidence: LatestKnownFallback,
        }
    }
    /// A wire identifier alone is not evidence that a key operation is supported.
    pub fn algorithm_wire_id(&self, algorithm: Algorithm) -> Option<u8> {
        match algorithm {
            Algorithm::Rsa1024 => Some(0x06),
            Algorithm::Rsa2048 => Some(0x07),
            Algorithm::EccP256 => Some(0x11),
            Algorithm::EccP384 => Some(0x14),
            _ => {
                if let Some(config) = &self.config {
                    return config.wire_id(algorithm);
                }
                let legacy = self
                    .info
                    .firmware
                    .as_ref()
                    .is_some_and(|f| f.tuple() >= (2, 0, 0) && f.tuple() < (3, 0, 0));
                match algorithm {
                    Algorithm::Ed25519 => Some(if legacy { 0x22 } else { 0xe0 }),
                    Algorithm::Rsa3072 => Some(if legacy { 0x50 } else { 0x05 }),
                    Algorithm::Rsa4096 => Some(if legacy { 0x51 } else { 0x16 }),
                    Algorithm::X25519 => Some(if legacy { 0x52 } else { 0xe1 }),
                    _ => None,
                }
            }
        }
    }
    pub fn legacy_unwrapped_objects(&self) -> bool {
        self.info
            .firmware
            .as_ref()
            .is_some_and(|f| ((1, 3, 0)..(1, 6, 1)).contains(&f.tuple()) && f.suffix.is_none())
    }
}
