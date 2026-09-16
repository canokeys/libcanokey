//! Owned PIV metadata, preserving unknown values and extension fields.
use crate::*;
use canokey_compat::{AlgorithmConfig, Support};

/// A known semantic value or its unrecognized raw byte; unknown values cannot
/// be passed as command policies/algorithms by accident.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KnownOrUnknown<T> {
    /// Recognized value.
    Known(T),
    /// Unrecognized on-wire value, retained without inventing semantics.
    Unknown(u8),
}
/// PIN policy for key construction and metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PinPolicy {
    /// Omit an explicit policy and let firmware choose its slot default.
    #[default]
    Default,
    /// No PIN required by this key's policy.
    Never,
    /// One verification authorizes subsequent uses until cleared.
    Once,
    /// Verify immediately before each private operation.
    Always,
}
/// Touch policy for key construction and metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TouchPolicy {
    /// Omit an explicit policy and use the firmware default.
    #[default]
    Default,
    /// Do not require touch.
    Never,
    /// Require touch for every use.
    Always,
    /// Allow firmware's touch cache; its duration is not inferred here.
    Cached,
}
/// Origin asserted by the card; no attestation is implied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyOrigin {
    /// Metadata reports no key present.
    NotPresent,
    /// Generated on device.
    Generated,
    /// Imported by a host.
    Imported,
}
/// Metadata query reference, distinct from signing slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetadataReference {
    /// Asymmetric key slot.
    Key(Slot),
    /// User PIN, reference 80.
    Pin,
    /// Unblocking key, reference 81.
    Puk,
    /// Management key, reference 9B.
    Management,
}
impl MetadataReference {
    /// Return the GET METADATA P2 reference byte.
    pub fn reference(self) -> u8 {
        match self {
            Self::Key(slot) => slot.reference(),
            Self::Pin => 0x80,
            Self::Puk => 0x81,
            Self::Management => 0x9b,
        }
    }
}
/// Unrecognized metadata field, preserved in wire order, including duplicates.
#[derive(Clone, Debug)]
pub struct MetadataField {
    /// Complete BER tag.
    pub tag: Tag,
    /// Owned field value with redacted Debug.
    pub value: SecretBytes,
}
/// Common metadata observations. Absent fields stay None; no defaults are invented.
#[derive(Debug)]
pub struct MetadataFields {
    /// Complete source TLV bytes, independent of the operation/profile.
    pub raw: SecretBytes,
    /// Algorithm byte as asserted by the card, including FF for PIN/PUK.
    pub algorithm_id: Option<u8>,
    /// Key policy if supplied (including unknown policy bytes).
    pub pin_policy: Option<KnownOrUnknown<PinPolicy>>,
    /// Touch policy if supplied.
    pub touch_policy: Option<KnownOrUnknown<TouchPolicy>>,
    /// Asserted origin if supplied.
    pub origin: Option<KnownOrUnknown<KeyOrigin>>,
    /// Default credential indicator; values beyond 00/01 are preserved.
    pub is_default: Option<KnownOrUnknown<bool>>,
    /// (Configured total, remaining) retries as reported, without enforcing consistency.
    pub retries: Option<(u8, u8)>,
    /// Raw public-key TLV value, without the metadata 04 wrapper.
    pub public_key_tlv: Option<SecretBytes>,
    /// Decoded public key when an algorithm is known. Unknown algorithm encodings
    /// remain available in public_key_tlv and raw.
    pub public_key: Option<PublicKey>,
    /// Fields outside the understood metadata schema, in source order.
    pub unknown_fields: Vec<MetadataField>,
}
/// Typed query result. No variant changes profile state or represents a login.
#[derive(Debug)]
pub enum Metadata {
    /// Asymmetric key observations for the requested slot.
    Key {
        /// Queried slot.
        slot: Slot,
        /// Owned observations.
        fields: MetadataFields,
    },
    /// PIN metadata.
    Pin(MetadataFields),
    /// PUK metadata.
    Puk(MetadataFields),
    /// Management-key metadata.
    Management(MetadataFields),
}
impl Metadata {
    /// Borrow common owned fields without performing device access.
    pub fn fields(&self) -> &MetadataFields {
        match self {
            Self::Key { fields, .. }
            | Self::Pin(fields)
            | Self::Puk(fields)
            | Self::Management(fields) => fields,
        }
    }
}
impl PinPolicy {
    pub(crate) fn wire(self) -> u8 {
        match self {
            Self::Default => 0,
            Self::Never => 1,
            Self::Once => 2,
            Self::Always => 3,
        }
    }
}
impl TouchPolicy {
    pub(crate) fn wire(self) -> u8 {
        match self {
            Self::Default => 0,
            Self::Never => 1,
            Self::Always => 2,
            Self::Cached => 3,
        }
    }
}
fn pin(value: u8) -> KnownOrUnknown<PinPolicy> {
    match value {
        0 => KnownOrUnknown::Known(PinPolicy::Default),
        1 => KnownOrUnknown::Known(PinPolicy::Never),
        2 => KnownOrUnknown::Known(PinPolicy::Once),
        3 => KnownOrUnknown::Known(PinPolicy::Always),
        v => KnownOrUnknown::Unknown(v),
    }
}
fn touch(value: u8) -> KnownOrUnknown<TouchPolicy> {
    match value {
        0 => KnownOrUnknown::Known(TouchPolicy::Default),
        1 => KnownOrUnknown::Known(TouchPolicy::Never),
        2 => KnownOrUnknown::Known(TouchPolicy::Always),
        3 => KnownOrUnknown::Known(TouchPolicy::Cached),
        v => KnownOrUnknown::Unknown(v),
    }
}
pub(crate) fn decode(
    profile: &DeviceProfile,
    reference: MetadataReference,
    data: SecretBytes,
    limit: usize,
) -> Result<Metadata, Error> {
    let invalid = || Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing);
    let mut fields = MetadataFields {
        raw: SecretBytes::default(),
        algorithm_id: None,
        pin_policy: None,
        touch_policy: None,
        origin: None,
        is_default: None,
        retries: None,
        public_key_tlv: None,
        public_key: None,
        unknown_fields: vec![],
    };
    let mut seen = [false; 7];
    let mut reader = TlvReader::new(
        data.as_bytes(),
        TlvLimits {
            max_value_bytes: limit,
            ..Default::default()
        },
    );
    while let Some(field) = reader.next()? {
        let tag = field.tag.value();
        if (1..=6).contains(&tag) {
            if seen[tag as usize] {
                return Err(invalid());
            }
            seen[tag as usize] = true;
            let expected = match tag {
                2 | 6 => 2,
                4 => field.value.len(),
                _ => 1,
            };
            if field.value.len() != expected {
                return Err(invalid());
            }
        }
        match tag {
            1 => fields.algorithm_id = Some(field.value[0]),
            2 => {
                fields.pin_policy = Some(pin(field.value[0]));
                fields.touch_policy = Some(touch(field.value[1]));
            }
            3 => {
                fields.origin = Some(match field.value[0] {
                    0 => KnownOrUnknown::Known(KeyOrigin::NotPresent),
                    1 => KnownOrUnknown::Known(KeyOrigin::Generated),
                    2 => KnownOrUnknown::Known(KeyOrigin::Imported),
                    v => KnownOrUnknown::Unknown(v),
                })
            }
            4 => fields.public_key_tlv = Some(SecretBytes::new(field.value.to_vec())),
            5 => {
                fields.is_default = Some(match field.value[0] {
                    0 => KnownOrUnknown::Known(false),
                    1 => KnownOrUnknown::Known(true),
                    v => KnownOrUnknown::Unknown(v),
                })
            }
            6 => fields.retries = Some((field.value[0], field.value[1])),
            _ => fields.unknown_fields.push(MetadataField {
                tag: field.tag,
                value: SecretBytes::new(field.value.to_vec()),
            }),
        }
    }
    if data.is_empty() {
        return Err(invalid());
    }
    if matches!(reference, MetadataReference::Key(_)) {
        if let (Some(id), Some(bytes)) = (fields.algorithm_id, &fields.public_key_tlv) {
            if let Some(algorithm) = profile.algorithm_from_wire_id(id) {
                fields.public_key = Some(PublicKey::from_tlv(algorithm, bytes.as_bytes(), limit)?);
            }
        }
    }
    fields.raw = data;
    Ok(match reference {
        MetadataReference::Key(slot) => Metadata::Key { slot, fields },
        MetadataReference::Pin => Metadata::Pin(fields),
        MetadataReference::Puk => Metadata::Puk(fields),
        MetadataReference::Management => Metadata::Management(fields),
    })
}
/// Select, optionally authenticate, and read one key/PIN/PUK/management metadata
/// record. Returned values own their bytes; no discovered defaults are used as
/// credentials. Unknown enum bytes/fields are retained and never command inputs.
///
/// # Errors
/// Requires evidenced metadata and slot support. Duplicate known fields, wrong
/// lengths and malformed key encodings fail. Legacy 2.x empty-slot 6900 is mapped
/// narrowly to NotFound, retaining its original SW; other card errors propagate.
pub fn get_metadata(
    profile: &DeviceProfile,
    reference: MetadataReference,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<Metadata>, Error> {
    let target = prepare_get_metadata(profile, reference, options)?;
    access::with_access(profile, access, target, options)
}

pub(crate) fn prepare_get_metadata(
    profile: &DeviceProfile,
    reference: MetadataReference,
    options: OperationOptions,
) -> Result<Sequence<Metadata>, Error> {
    require(profile)?;
    profile.capability(Capability::Metadata).require()?;
    if let MetadataReference::Key(slot) = reference {
        profile.piv_slot_support(slot.reference()).require()?;
    }
    let snapshot = profile.clone();
    let legacy = profile.legacy_empty_key_metadata();
    access::prepare(command::metadata(reference), options, move |r| {
        if legacy && matches!(reference, MetadataReference::Key(_)) && r.status.raw() == 0x6900 {
            let mut error = Error::status(r.status, Phase::Command, None);
            error.kind = ErrorKind::NotFound;
            return Err(error);
        }
        r.ensure_success(Phase::Command)?;
        decode(
            &snapshot,
            reference,
            r.data,
            options.limits.max_total_response_bytes,
        )
    })
}
/// Read observed algorithm extension IDs under one SELECT, with optional explicit
/// management access for firmware that protects this read. The returned config
/// does not mutate the source profile; callers decide how to refresh observations.
/// Unknown/proven-unsupported probe capability fails before SELECT; malformed IDs
/// return InvalidResponse. No authentication is inferred or attempted implicitly.
///
/// On 3.0.x firmware ([`Capability::PivProtectedAlgorithmConfigRead`]) the INS EE
/// read itself sits behind management-key GENERAL AUTHENTICATE, so [`Access::None`]
/// and [`Access::Pin`] cannot authorize it and are rejected with
/// [`ErrorKind::SecurityStatusNotSatisfied`] at construction, before any I/O.
/// [`Access::Existing`], [`Access::Management`] and [`Access::PinAndManagement`]
/// remain allowed; `Existing` stays an unproven caller assertion. From 3.1.0 the
/// read is unauthenticated and no access mode is rejected. Unknown firmware is
/// not rejected by this gate (no gate is invented without evidence); it still
/// fails the probe-capability check above with CapabilityUnknown.
///
/// # Errors
/// Returns capability, access-gate and host-budget errors before execution.
pub fn read_algorithm_config(
    profile: &DeviceProfile,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<AlgorithmConfig>, Error> {
    let target = prepare_read_algorithm_config(profile, options)?;
    if profile
        .capability(Capability::PivProtectedAlgorithmConfigRead)
        .support
        == Support::Supported
        && matches!(access, Access::None | Access::Pin(_))
    {
        return Err(Error::new(ErrorKind::SecurityStatusNotSatisfied));
    }
    access::with_access(profile, access, target, options)
}

pub(crate) fn prepare_read_algorithm_config(
    profile: &DeviceProfile,
    options: OperationOptions,
) -> Result<Sequence<AlgorithmConfig>, Error> {
    profile.algorithm_config_read_support().require()?;
    access::prepare(command::algorithm_config(), options, |r| {
        r.ensure_success(Phase::Command)?;
        AlgorithmConfig::parse(r.data.as_bytes())
    })
}
