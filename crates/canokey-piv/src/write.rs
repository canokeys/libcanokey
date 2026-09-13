//! Explicit object/certificate writes and management-key replacement.
use crate::*;
use canokey_compat::Support;
use canokey_protocol::{tlv::TlvWriter, ApduHeader, ExpectedLength};

/// Management-key touch requirement; 3DES firmware supports Never only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagementTouchPolicy {
    /// No touch required for management authentication.
    Never,
    /// Require touch for each management authentication (AES-192 firmware).
    Always,
}

fn mutation(response: ResponseData) -> Result<MutationResult, Error> {
    response.ensure_success(Phase::Command)?;
    if !response.data.is_empty() {
        return Err(Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing));
    }
    Ok(unchanged())
}
fn require_management(access: &Access) -> Result<(), Error> {
    if matches!(
        access,
        Access::Management(_) | Access::PinAndManagement { .. }
    ) {
        Ok(())
    } else {
        Err(Error::new(ErrorKind::InvalidArgument))
    }
}
fn put_command(
    profile: &DeviceProfile,
    id: ObjectId,
    data: &[u8],
    options: OperationOptions,
) -> Result<LogicalCommand, Error> {
    require(profile)?;
    profile.capability(Capability::ObjectWrites).require()?;
    options.validate()?;
    let mut writer = TlvWriter::new(options.limits.max_input_bytes);
    writer.push(Tag::from_bytes(&[0x5c])?, &id.as_bytes())?;
    writer.push(Tag::from_bytes(&[0x53])?, data)?;
    let mut command = LogicalCommand::new(
        ApduHeader::new(0, 0xdb, 0x3f, 0xff),
        vec![],
        ExpectedLength::Absent,
    );
    command.data = writer.into_bytes();
    command.allow_chaining =
        profile.capability(Capability::ObjectWriteChaining).support == Support::Supported;
    // Older firmware expects the complete object selector in the first fragment.
    // The common conversation reserves six header bytes for short segmentation.
    if command.allow_chaining
        && options.exchange.max_command_bytes.saturating_sub(6) < id.as_bytes().len() + 2
    {
        return Err(Error::new(ErrorKind::LimitExceeded));
    }
    Ok(command)
}

/// Select, explicitly authenticate management (then optional PIN), and PUT DATA.
/// `data` is the normalized object value, without the outer 53 container. This
/// factory adds 5C/53 framing and owns the input. Access must contain management
/// authentication; None/Pin returns InvalidArgument before SELECT.
///
/// # Errors
/// Unknown/unsupported write firmware, invalid budgets and oversized encoded
/// input fail at construction. Card failures stop immediately. Chained writes
/// can modify storage before failure or cancellation; there is no rollback/replay.
/// Success returns Unchanged; callers must invalidate their affected object caches.
pub fn write_object(
    profile: &DeviceProfile,
    id: ObjectId,
    data: ObjectData,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<MutationResult>, Error> {
    require_management(&access)?;
    let command = put_command(profile, id, data.as_bytes(), options)?;
    access::command_with_access(profile, access, command, options, mutation)
}

/// Store a nonempty, uncompressed certificate payload using 70/71=00/FE fields.
/// Owns the payload and performs no X.509 syntax/trust validation. Authentication,
/// limits and partial-write behavior are the same as [`write_object`].
/// For pre-compressed certificates, use write_object with an explicit container.
/// Empty payloads return InvalidArgument; use [`delete_certificate`] to remove one.
pub fn write_certificate(
    profile: &DeviceProfile,
    slot: Slot,
    der: SecretBytes,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<MutationResult>, Error> {
    if der.is_empty() {
        return Err(Error::new(ErrorKind::InvalidArgument));
    }
    if matches!(slot, Slot::Retired(_)) {
        profile.capability(Capability::RetiredSlots).require()?;
    }
    let mut writer = TlvWriter::new(options.limits.max_input_bytes);
    writer.push(Tag::from_bytes(&[0x70])?, der.as_bytes())?;
    writer.push(Tag::from_bytes(&[0x71])?, &[0])?;
    writer.push(Tag::from_bytes(&[0xfe])?, &[])?;
    write_object(
        profile,
        ObjectId::certificate(slot),
        writer.into_bytes(),
        access,
        options,
    )
}

/// Remove a certificate using the evidenced empty 53 container, retaining its key.
/// Requires 3.1.0 certificate-deletion support and explicit management access.
/// Legacy firmware is rejected before SELECT: storing an empty container there
/// does not establish certificate removal. No key-deletion command is emitted.
/// Card errors, partial writes and cache invalidation follow [`write_object`].
pub fn delete_certificate(
    profile: &DeviceProfile,
    slot: Slot,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<MutationResult>, Error> {
    profile
        .capability(Capability::CertificateDeletion)
        .require()?;
    write_object(
        profile,
        ObjectId::certificate(slot),
        SecretBytes::default(),
        access,
        options,
    )
}

/// Authenticate with the current key, then replace it without another SELECT.
/// The replacement must use the firmware's supported algorithm; this is not an
/// algorithm-migration command. Both keys are owned and wiped when no longer needed.
/// A successful Unchanged result still requires callers to discard cached key
/// metadata/credentials. An uncertain write must not be automatically retried.
///
/// # Errors
/// Access without management authentication, unsupported algorithm/touch policy,
/// malformed responses and channel limits fail with typed errors. Touch Always is
/// supported only for AES-192; 3DES rejects it before contacting the card.
pub fn set_management_key(
    profile: &DeviceProfile,
    key: ManagementKey,
    touch: ManagementTouchPolicy,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<MutationResult>, Error> {
    require_management(&access)?;
    require(profile)?;
    profile.management_key_support(key.algorithm()).require()?;
    if touch == ManagementTouchPolicy::Always && key.algorithm() != ManagementKeyAlgorithm::Aes192 {
        return Err(Error::new(ErrorKind::UnsupportedFeature));
    }
    let command = key.replacement_command(touch == ManagementTouchPolicy::Always);
    access::command_with_access(profile, access, command, options, mutation)
}
