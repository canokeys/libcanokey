//! Immutable capability snapshots. Version rules live here, not in operations.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
use canokey_protocol::{Error, ErrorKind};
use std::collections::BTreeMap;
/// Parsed actual CanoKey firmware version, separate from the PIV compatibility version.
/// This parser is deliberately not a full SemVer implementation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirmwareVersion {
    /// Major firmware component.
    pub major: u16,
    /// Minor firmware component.
    pub minor: u16,
    /// Patch component; zero when the source has only major/minor.
    pub patch: u16,
    /// Original development/build suffix including its leading `-` or `+`.
    pub suffix: Option<String>,
}
impl FirmwareVersion {
    /// Parse two or three numeric u16 components, optional lowercase `v`, whitespace
    /// and an ASCII development/build suffix. Return `None` for an unrecognized form.
    ///
    /// ```
    /// use canokey_compat::FirmwareVersion;
    /// let version = FirmwareVersion::parse("v3.1-dev").unwrap();
    /// assert_eq!(version.patch, 0);
    /// assert_eq!(version.suffix.as_deref(), Some("-dev"));
    /// ```
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
/// PIV application major/minor/patch bytes; not the actual firmware version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PivApplicationVersion(
    /// Raw major, minor and patch bytes in that order.
    pub [u8; 3],
);
/// Three-valued capability result; Unknown must not be treated as Unsupported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Support {
    /// Evidence permits the capability; individual operation constraints still apply.
    Supported,
    /// Evidence establishes that the capability is unavailable.
    Unsupported,
    /// Evidence is insufficient to authorize capability-dependent behavior.
    Unknown,
}
/// Source used to derive a capability decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evidence {
    /// A directly observed response or recorded discovery outcome.
    Observed,
    /// A rule for a recognized firmware range.
    FirmwareMatrix,
    /// Conservative stable behavior for firmware outside the recognized matrix.
    LatestKnownFallback,
}
/// A support decision paired with its provenance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityStatus {
    /// Availability of the queried feature.
    pub support: Support,
    /// Source supporting this decision, including Unknown decisions.
    pub evidence: Evidence,
}
impl CapabilityStatus {
    /// Require Supported before constructing a feature-dependent operation.
    ///
    /// # Errors
    /// Unsupported returns [`ErrorKind::UnsupportedFeature`]; Unknown returns
    /// [`ErrorKind::CapabilityUnknown`]. The two cases are intentionally distinct.
    pub fn require(self) -> Result<(), Error> {
        match self.support {
            Support::Supported => Ok(()),
            Support::Unsupported => Err(Error::new(ErrorKind::UnsupportedFeature)),
            Support::Unknown => Err(Error::new(ErrorKind::CapabilityUnknown)),
        }
    }
}
/// Semantic feature keys used by the current compatibility model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    /// OpenPGP command and algorithm layout in pinned firmware 3.1.0.
    OpenPgp,
    /// OATH commands and full/truncated calculation layout in firmware 3.1.0.
    Oath,
    /// Admin configuration layout and commands observed in firmware 3.1.0.
    Admin,
    /// Observed PIV applet availability.
    Piv,
    /// PIV metadata command availability.
    Metadata,
    /// NIST P-256 capability/algorithm (wire support remains context-dependent).
    EccP256,
    /// NIST P-384 capability/algorithm (wire support remains context-dependent).
    EccP384,
    /// Configurable PIV algorithm extensions.
    AlgorithmExtensions,
    /// Retired key-management slot range.
    RetiredSlots,
    /// Object PUT DATA, including certificate containers.
    ObjectWrites,
    /// Short command chaining for PUT DATA.
    ObjectWriteChaining,
    /// Compact PIV key/certificate directory.
    MetadataDirectory,
    /// Per-slot UTF-16LE container names.
    ContainerNames,
    /// Move/delete ordinary asymmetric keys without moving certificates.
    KeyMoveDelete,
    /// Retry configuration that resets both PIN and PUK to defaults.
    RetryReset,
    /// Replacement of the complete algorithm configuration.
    AlgorithmConfigWrite,
    /// SM2 key agreement with separate peer static and ephemeral points.
    Sm2Agreement,
    /// On-device PIV attestation certificate generation.
    Attestation,
    /// Explicit reset after both PIN and PUK are blocked.
    PivReset,
    /// Certificate removal using an empty 53 container.
    CertificateDeletion,
}
/// Management-key block algorithm, separate from asymmetric key algorithms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagementKeyAlgorithm {
    /// Three-key triple DES, 24-byte key and eight-byte authentication block.
    Tdes,
    /// AES-192, 24-byte key and sixteen-byte authentication block.
    Aes192,
}
impl ManagementKeyAlgorithm {
    /// PIV GENERAL AUTHENTICATE / SET MANAGEMENT KEY algorithm identifier.
    pub fn wire_id(self) -> u8 {
        match self {
            Self::Tdes => 0x03,
            Self::Aes192 => 0x0a,
        }
    }
    /// Required witness and challenge length in bytes.
    pub fn block_len(self) -> usize {
        match self {
            Self::Tdes => 8,
            Self::Aes192 => 16,
        }
    }
}
/// Semantic algorithm names, independent of configurable wire identifiers.
/// An enum variant does not promise a factory implementation or firmware support.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Algorithm {
    /// RSA with a 1024-bit modulus.
    Rsa1024,
    /// RSA with a 2048-bit modulus.
    Rsa2048,
    /// RSA with a 3072-bit modulus.
    Rsa3072,
    /// RSA with a 4096-bit modulus.
    Rsa4096,
    /// NIST P-256 capability/algorithm (wire support remains context-dependent).
    EccP256,
    /// NIST P-384 capability/algorithm (wire support remains context-dependent).
    EccP384,
    /// NIST P-521.
    EccP521,
    /// SEC secp256k1.
    Secp256k1,
    /// SM2 elliptic-curve algorithm.
    Sm2,
    /// Ed25519 signature algorithm.
    Ed25519,
    /// X25519 key agreement.
    X25519,
    /// ML-DSA-65 signature algorithm.
    MlDsa65,
    /// ML-KEM-768 key encapsulation.
    MlKem768,
}
/// Owned observed extension-ID mapping, preserving the original bytes.
/// Missing extension fields stay absent; a disabled mapping exposes no wire IDs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlgorithmConfig {
    enabled: bool,
    ids: BTreeMap<Algorithm, u8>,
    raw: Vec<u8>,
}
impl AlgorithmConfig {
    /// Parse observed configuration without inventing missing extension fields.
    ///
    /// Seven bytes use the legacy layout; later fields add P-521, ML-DSA and ML-KEM.
    /// Bytes beyond the understood fields are preserved by [`Self::raw`].
    ///
    /// # Errors
    /// Returns [`ErrorKind::InvalidResponse`] for fewer than seven bytes, an invalid
    /// enable flag, or zero/reserved/duplicate IDs among recognized fields.
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
    /// Return whether the observed configuration enables algorithm extensions.
    pub fn enabled(&self) -> bool {
        self.enabled
    }
    /// Return an observed ID only when extensions are enabled and the field exists.
    pub fn wire_id(&self, algorithm: Algorithm) -> Option<u8> {
        self.ids.get(&algorithm).copied().filter(|_| self.enabled)
    }
    /// Borrow the complete original configuration, including unrecognized trailing bytes.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
}
/// Immutable identity observations; contains neither credentials nor a connection.
#[derive(Clone, Debug)]
pub struct DeviceInfo {
    firmware_text: Vec<u8>,
    firmware: Option<FirmwareVersion>,
    model: Option<String>,
    serial: Option<Vec<u8>>,
    piv_version: Option<PivApplicationVersion>,
}
impl DeviceInfo {
    /// Borrow original actual-firmware bytes; they need not be valid UTF-8.
    pub fn firmware_text(&self) -> &[u8] {
        &self.firmware_text
    }
    /// Borrow a parsed firmware version, or None if the original form was unrecognized.
    pub fn firmware(&self) -> Option<&FirmwareVersion> {
        self.firmware.as_ref()
    }
    /// Borrow the optional model text from Admin discovery.
    pub fn model(&self) -> Option<&str> {
        self.model.as_deref()
    }
    /// Borrow the optional four serial bytes; not a connection-generation identifier.
    pub fn serial(&self) -> Option<&[u8]> {
        self.serial.as_deref()
    }
    /// Return the independently observed PIV application version.
    pub fn piv_version(&self) -> Option<PivApplicationVersion> {
        self.piv_version
    }
}
/// Observations supplied together by a probe of one device. No credentials or I/O handles.
#[derive(Clone, Debug)]
pub struct DeviceObservations {
    /// Required nonempty actual-firmware bytes (at most 256).
    pub firmware_text: Vec<u8>,
    /// Optional Admin model text.
    pub model: Option<String>,
    /// Optional four-byte Admin serial observation.
    pub serial: Option<Vec<u8>>,
    /// Optional PIV application version; its presence establishes PIV observation.
    pub piv_version: Option<PivApplicationVersion>,
    /// Optional validated algorithm extension configuration.
    pub algorithm_config: Option<AlgorithmConfig>,
    /// Discovery outcomes to retain when normalizing the snapshot.
    pub warnings: Vec<CompatibilityWarning>,
}
impl DeviceObservations {
    /// Own firmware bytes with other observations absent. Validation is deferred to
    /// [`DeviceProfile::from_observations`]; the caller must supply one device's data.
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
/// Nonfatal compatibility/discovery information retained in a profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompatibilityWarning {
    /// Firmware text could not be parsed; raw bytes remain available.
    UnrecognizedFirmware,
    /// Firmware is newer or has a development suffix; conservative fallback applies.
    LatestKnownFallback,
    /// The named optional probe command reported an unsupported status.
    OptionalCommandUnsupported(&'static str),
    /// The named optional probe command requires authentication; no default was tried.
    OptionalCommandNeedsAuthentication(&'static str),
}
/// Caller-owned immutable capability snapshot for one connection generation.
///
/// Contains no live connection, login state, or credentials. Applet constructors
/// copy the configuration they require, so this value may then be dropped.
/// Reprobe after connection replacement or protocol-affecting configuration changes.
#[derive(Clone, Debug)]
pub struct DeviceProfile {
    info: DeviceInfo,
    config: Option<AlgorithmConfig>,
    warnings: Vec<CompatibilityWarning>,
}
impl DeviceProfile {
    /// Normalize owned observations without contacting a device.
    ///
    /// Unknown firmware remains usable under conservative capability decisions;
    /// this does not attest that supplied observations came from the same device.
    ///
    /// # Errors
    /// Returns [`ErrorKind::InvalidResponse`] for empty/oversized firmware bytes or
    /// a present serial whose length is not four bytes.
    ///
    /// # Examples
    /// ```
    /// use canokey_compat::{Capability, DeviceObservations, DeviceProfile,
    ///     PivApplicationVersion, Support};
    /// let mut observed = DeviceObservations::new(b"9.0.0".to_vec());
    /// observed.piv_version = Some(PivApplicationVersion([5, 7, 0]));
    /// let profile = DeviceProfile::from_observations(observed)?;
    /// assert_eq!(profile.capability(Capability::Piv).support, Support::Supported);
    /// assert_eq!(profile.capability(Capability::Metadata).support, Support::Unknown);
    /// # Ok::<(), canokey_protocol::Error>(())
    /// ```
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
    /// Borrow immutable raw and normalized device information.
    pub fn info(&self) -> &DeviceInfo {
        &self.info
    }
    /// Borrow retained discovery outcomes and normalization warnings.
    pub fn warnings(&self) -> &[CompatibilityWarning] {
        &self.warnings
    }
    /// Borrow observed algorithm configuration, if discovery supplied it.
    pub fn algorithm_config(&self) -> Option<&AlgorithmConfig> {
        self.config.as_ref()
    }
    /// Resolve a feature using observations, recognized firmware, or conservative fallback.
    /// Never probes the card or changes this snapshot.
    pub fn capability(&self, feature: Capability) -> CapabilityStatus {
        use {Evidence::*, Support::*};
        match feature {
            Capability::ObjectWrites => return self.firmware_range((1, 5, 2), (3, 1, 0)),
            Capability::ObjectWriteChaining => return self.firmware_range((1, 5, 2), (3, 1, 0)),
            Capability::OpenPgp
            | Capability::Oath
            | Capability::Admin
            | Capability::CertificateDeletion
            | Capability::MetadataDirectory
            | Capability::ContainerNames
            | Capability::KeyMoveDelete
            | Capability::RetryReset
            | Capability::AlgorithmConfigWrite
            | Capability::Sm2Agreement
            | Capability::Attestation
            | Capability::PivReset => return self.firmware_range((3, 1, 0), (3, 1, 0)),
            _ => {}
        }
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
    /// Resolve management-key algorithm support for both External and Mutual modes.
    /// Firmware 1.5.2..=3.0.3 uses 3DES; 3.1.0 uses AES-192. Unrecognized,
    /// development and newer firmware remain Unknown; no algorithm is tried implicitly.
    pub fn management_key_support(&self, algorithm: ManagementKeyAlgorithm) -> CapabilityStatus {
        match algorithm {
            ManagementKeyAlgorithm::Tdes => self.firmware_range((1, 5, 2), (3, 0, 3)),
            ManagementKeyAlgorithm::Aes192 => self.firmware_range((3, 1, 0), (3, 1, 0)),
        }
    }
    fn firmware_range(&self, first: (u16, u16, u16), last: (u16, u16, u16)) -> CapabilityStatus {
        if let Some(version) = &self.info.firmware {
            let v = version.tuple();
            if version.suffix.is_none() && (((1, 5, 2)..=(3, 0, 3)).contains(&v) || v == (3, 1, 0))
            {
                return CapabilityStatus {
                    support: if (first..=last).contains(&v) {
                        Support::Supported
                    } else {
                        Support::Unsupported
                    },
                    evidence: Evidence::FirmwareMatrix,
                };
            }
        }
        CapabilityStatus {
            support: Support::Unknown,
            evidence: Evidence::LatestKnownFallback,
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
    /// Resolve an observed asymmetric algorithm byte without authorizing key use.
    /// Configurable IDs follow this profile; unknown IDs remain absent.
    pub fn algorithm_from_wire_id(&self, id: u8) -> Option<Algorithm> {
        [
            Algorithm::Rsa1024,
            Algorithm::Rsa2048,
            Algorithm::Rsa3072,
            Algorithm::Rsa4096,
            Algorithm::EccP256,
            Algorithm::EccP384,
            Algorithm::EccP521,
            Algorithm::Secp256k1,
            Algorithm::Sm2,
            Algorithm::Ed25519,
            Algorithm::X25519,
            Algorithm::MlDsa65,
            Algorithm::MlKem768,
        ]
        .into_iter()
        .find(|a| self.algorithm_wire_id(*a) == Some(id))
    }
    /// Whether a slot reference is implemented in the inspected firmware range.
    /// Primary slots are available from 1.5.2; 82/83 from 2.0; 84..95 from 3.1.
    /// Management/PIN references are not asymmetric slots.
    pub fn piv_slot_support(&self, reference: u8) -> CapabilityStatus {
        match reference {
            0x9a | 0x9c | 0x9d | 0x9e => self.firmware_range((1, 5, 2), (3, 1, 0)),
            0x82 | 0x83 => self.firmware_range((2, 0, 0), (3, 1, 0)),
            0x84..=0x95 => self.firmware_range((3, 1, 0), (3, 1, 0)),
            _ => CapabilityStatus {
                support: Support::Unsupported,
                evidence: Evidence::FirmwareMatrix,
            },
        }
    }
    /// Whether the configuration read is known, independently of extension enablement
    /// and authentication requirements. Disabled extensions do not disable this read.
    pub fn algorithm_config_read_support(&self) -> CapabilityStatus {
        if self
            .warnings
            .contains(&CompatibilityWarning::OptionalCommandUnsupported(
                "algorithm_config",
            ))
        {
            return CapabilityStatus {
                support: Support::Unsupported,
                evidence: Evidence::Observed,
            };
        }
        self.firmware_range((2, 0, 0), (3, 1, 0))
    }
    /// Whether an asymmetric algorithm is evidenced for key operations.
    /// Extended algorithms require observed, enabled IDs; guessed fallback IDs
    /// never authorize a key write. RSA-1024 is not implemented by inspected firmware.
    /// Ed/X operations require the encoding fixes from 3.0.1 onward.
    pub fn key_algorithm_support(&self, algorithm: Algorithm) -> CapabilityStatus {
        let baseline = self.firmware_range((1, 5, 2), (3, 1, 0));
        if baseline.support != Support::Supported {
            return baseline;
        }
        match algorithm {
            Algorithm::Rsa2048 | Algorithm::EccP256 | Algorithm::EccP384 => baseline,
            Algorithm::Rsa1024 => CapabilityStatus {
                support: Support::Unsupported,
                evidence: Evidence::FirmwareMatrix,
            },
            _ => {
                let range = self.firmware_range(
                    match algorithm {
                        Algorithm::Ed25519 | Algorithm::X25519 => (3, 0, 1),
                        Algorithm::EccP521 | Algorithm::MlDsa65 | Algorithm::MlKem768 => (3, 1, 0),
                        _ => (2, 0, 0),
                    },
                    (3, 1, 0),
                );
                if range.support != Support::Supported {
                    return range;
                }
                CapabilityStatus {
                    support: match &self.config {
                        Some(config) if config.wire_id(algorithm).is_some() => Support::Supported,
                        Some(config) if !config.enabled() => Support::Unsupported,
                        _ => Support::Unknown,
                    },
                    evidence: Evidence::Observed,
                }
            }
        }
    }
    /// Whether the firmware supports the explicit streaming signing protocol.
    /// Only ML-DSA-65 (empty context), randomized Ed25519 and SM2 are accepted.
    /// Requires 3.1.0 and observed enabled algorithm IDs; future versions remain Unknown.
    pub fn streaming_signing_support(&self, algorithm: Algorithm) -> CapabilityStatus {
        if !matches!(
            algorithm,
            Algorithm::MlDsa65 | Algorithm::Ed25519 | Algorithm::Sm2
        ) {
            return CapabilityStatus {
                support: Support::Unsupported,
                evidence: Evidence::FirmwareMatrix,
            };
        }
        let version = self.firmware_range((3, 1, 0), (3, 1, 0));
        if version.support != Support::Supported {
            return version;
        }
        self.key_algorithm_support(algorithm)
    }
    /// Whether GET METADATA on a known empty key slot may return legacy 6900.
    pub fn legacy_empty_key_metadata(&self) -> bool {
        self.info
            .firmware
            .as_ref()
            .is_some_and(|v| v.suffix.is_none() && ((2, 0, 0)..(3, 0, 0)).contains(&v.tuple()))
    }
    /// Whether the evidenced SM2 signature response is fixed-width r || s.
    /// Known 3.1.0 uses this encoding; earlier supported releases use DER.
    /// This encoding selector is not a support check: require key_algorithm_support
    /// first, since unknown/newer firmware must not inherit a guessed encoding.
    pub fn sm2_uses_p1363_signatures(&self) -> bool {
        self.info
            .firmware
            .as_ref()
            .is_some_and(|v| v.suffix.is_none() && v.tuple() == (3, 1, 0))
    }
    /// Whether proven legacy firmware returns unwrapped CCC/CHUID objects.
    /// Applet code applies this narrowly to those object types; callers should prefer
    /// the semantic read-object factory over implementing their own workaround.
    pub fn legacy_unwrapped_objects(&self) -> bool {
        self.info
            .firmware
            .as_ref()
            .is_some_and(|f| ((1, 3, 0)..(1, 6, 1)).contains(&f.tuple()) && f.suffix.is_none())
    }
}
