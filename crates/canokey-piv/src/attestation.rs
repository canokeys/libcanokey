//! Read-only attestation signer observations; no trust policy or private operations.
use crate::*;
use canokey_protocol::{ApduHeader, ExpectedLength};

/// Read the F9 signer's metadata, including its public key, on firmware 3.1.x.
/// Selects PIV without authenticating; returned fields own all bytes. F9 is not
/// exposed as an ordinary signing, generation, import or move/delete slot.
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
