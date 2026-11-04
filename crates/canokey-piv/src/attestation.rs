//! Dedicated attestation signer observation and provisioning; no host trust policy.
use crate::*;
use canokey_protocol::{ApduHeader, ExpectedLength};

/// Read the F9 signer's metadata, including its public key, on firmware 3.1.x.
/// Selects PIV without authenticating; returned fields own all bytes. F9 is not
/// exposed as an ordinary signing or move/delete slot. Provisioning uses the
/// dedicated attestation-key operations.
///
/// # Errors
/// Unsupported/unknown attestation capability fails before I/O. Missing keys
/// retain NotFound; malformed/duplicate metadata and response limits fail as in
/// [`get_metadata`]. No key presence, identity or attestation trust is inferred.
pub fn read_attestation_metadata(
    profile: &DeviceProfile,
    options: OperationOptions,
) -> Result<Operation<MetadataFields>, Error> {
    require(profile)?;
    profile.capability(Capability::Attestation).require()?;
    let command = LogicalCommand::new(
        ApduHeader {
            cla: 0,
            ins: 0xf7,
            p1: 0,
            p2: 0xf9,
        },
        Vec::new(),
        ExpectedLength::Absent,
    );
    let snapshot = profile.clone();
    let target = access::prepare(command, options, move |r| {
        r.ensure_success(Phase::Command)?;
        metadata::decode_fields(
            &snapshot,
            r.data,
            options.limits.max_total_response_bytes,
            true,
        )
    })?;
    access::with_access(profile, Access::None, target, options)
}

/// Read and unwrap the F9 signer's certificate in object 5FFF01 on 3.1.x.
/// Selects PIV without authentication; owns the unwrapped DER independently.
/// This parses only the bounded certificate container (including gzip), with
/// no X.509 syntax, signature, key-match or trust validation.
///
/// # Errors
/// Unsupported/unknown attestation capability fails before I/O. Missing objects,
/// invalid containers, unsupported compression flags and limits propagate as in
/// [`read_certificate`]. A certificate need not have a corresponding F9 key.
pub fn read_attestation_certificate(
    profile: &DeviceProfile,
    options: OperationOptions,
) -> Result<Operation<Certificate>, Error> {
    require(profile)?;
    profile.capability(Capability::Attestation).require()?;
    let limit = options.limits.max_total_response_bytes;
    read_object_with(
        profile,
        ObjectId::from_bytes(&[0x5f, 0xff, 0x01])?,
        Access::None,
        options,
        move |data| Certificate::from_object(data.as_bytes(), limit),
    )
}

/// Owned policies for provisioning the F9 attestation signer. The algorithm is
/// fixed to P-256; ordinary `Slot` values remain unchanged. Firmware-default
/// policies are selected by default. No consent or certificate trust is inferred.
#[derive(Clone, Copy, Debug, Default)]
pub struct AttestationKeyParameters {
    /// Explicit PIN policy or the firmware default (normally Never for F9).
    pub pin_policy: PinPolicy,
    /// Explicit touch policy or the firmware default.
    pub touch_policy: TouchPolicy,
}

fn provisioning_id(profile: &DeviceProfile) -> Result<u8, Error> {
    require(profile)?;
    profile.capability(Capability::Attestation).require()?;
    profile
        .key_algorithm_support(Algorithm::EccP256)
        .require()?;
    profile
        .algorithm_wire_id(Algorithm::EccP256)
        .ok_or_else(|| Error::new(ErrorKind::CapabilityUnknown))
}

/// Select PIV, authenticate management access, and generate a P-256 key in F9.
/// The result owns the public key; the private key stays on the device. Existing
/// keys are replaced and existing certificates are retained. The caller must
/// obtain overwrite consent and invalidate any old certificate/trust binding.
/// A lost or malformed response can follow a successful write: never replay.
///
/// # Errors
/// Requires evidenced attestation and P-256 support, explicit management access,
/// supported policies and bounded input/output. All construction checks run
/// before I/O; transport, authentication and card errors propagate without retry.
pub fn generate_attestation_key(
    profile: &DeviceProfile,
    parameters: AttestationKeyParameters,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<PublicKey>, Error> {
    let id = provisioning_id(profile)?;
    write::require_management(&access)?;
    let target = keys::prepare_generate_key_at(
        profile,
        Algorithm::EccP256,
        (id, 0xf9),
        (parameters.pin_policy, parameters.touch_policy),
        options,
    )?;
    access::with_access(profile, access, target, options)
}

/// Select PIV, authenticate management access, and import a P-256 scalar into F9.
/// The operation owns and wipes the material and encoded APDUs. Existing keys
/// are replaced while certificates remain; callers must obtain overwrite consent
/// and update trust/certificate bindings. No rollback or retry is performed.
///
/// # Errors
/// Non-P-256 material, unsupported/unknown firmware, missing management access,
/// invalid policies and input budgets fail before I/O. Authentication, card,
/// continuation and transport failures retain their typed errors.
pub fn import_attestation_key(
    profile: &DeviceProfile,
    parameters: AttestationKeyParameters,
    material: PrivateKeyMaterial,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<MutationResult>, Error> {
    let id = provisioning_id(profile)?;
    write::require_management(&access)?;
    let target = keys::prepare_import_key_at(
        profile,
        Algorithm::EccP256,
        (id, 0xf9),
        (parameters.pin_policy, parameters.touch_policy),
        material,
        options,
    )?;
    access::with_access(profile, access, target, options)
}
