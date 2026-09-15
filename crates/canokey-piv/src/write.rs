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

pub(crate) fn mutation(response: ResponseData) -> Result<MutationResult, Error> {
    response.ensure_success(Phase::Command)?;
    if !response.data.is_empty() {
        return Err(Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing));
    }
    Ok(unchanged())
}
pub(crate) fn require_management(access: &Access) -> Result<(), Error> {
    if matches!(
        access,
        Access::Existing | Access::Management(_) | Access::PinAndManagement { .. }
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
/// authentication or Existing; None/Pin returns InvalidArgument before SELECT.
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
    write::require_management(&access)?;
    let target = prepare_write_object(profile, id, data, options)?;
    access::with_access(profile, access, target, options)
}

pub(crate) fn prepare_write_object(
    profile: &DeviceProfile,
    id: ObjectId,
    data: ObjectData,
    options: OperationOptions,
) -> Result<Sequence<MutationResult>, Error> {
    let command = put_command(profile, id, data.as_bytes(), options)?;
    access::prepare(command, options, mutation)
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
    require_management(&access)?;
    let target = prepare_write_certificate(profile, slot, der, options)?;
    access::with_access(profile, access, target, options)
}

pub(crate) fn prepare_write_certificate(
    profile: &DeviceProfile,
    slot: Slot,
    der: SecretBytes,
    options: OperationOptions,
) -> Result<Sequence<MutationResult>, Error> {
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
    prepare_write_object(
        profile,
        ObjectId::certificate(slot),
        writer.into_bytes(),
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
    require_management(&access)?;
    let target = prepare_delete_certificate(profile, slot, options)?;
    access::with_access(profile, access, target, options)
}

pub(crate) fn prepare_delete_certificate(
    profile: &DeviceProfile,
    slot: Slot,
    options: OperationOptions,
) -> Result<Sequence<MutationResult>, Error> {
    profile
        .capability(Capability::CertificateDeletion)
        .require()?;
    prepare_write_object(
        profile,
        ObjectId::certificate(slot),
        SecretBytes::default(),
        options,
    )
}

/// Authenticate with the current key, then replace it without another SELECT.
/// The replacement must use the firmware's supported algorithm; this is not an
/// algorithm-migration command. Both keys are owned and wiped when no longer needed.
/// A successful Unchanged result still requires callers to discard cached key
/// metadata/credentials. An uncertain write must not be automatically retried.
/// With `update_protected`, inspect ADMIN DATA; protected mode also reads PRINTED
/// before mutation (requiring PIN access), replaces the key, authenticates the new
/// key, then updates PRINTED. Otherwise change only the management key. The two
/// writes are not atomic: failure after replacement requires recovery using the
/// supplied new key and repair of PRINTED. Drop never restores either value.
///
/// # Errors
/// Access without management authentication, unsupported algorithm/touch policy,
/// malformed responses and channel limits fail with typed errors. Touch Always is
/// supported only for AES-192; 3DES rejects it before contacting the card.
pub fn set_management_key(
    profile: &DeviceProfile,
    key: ManagementKey,
    touch: ManagementTouchPolicy,
    update_protected: bool,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<MutationResult>, Error> {
    require_management(&access)?;
    let replacement = prepare_set_management_key(profile, key.clone(), touch, options)?;
    if !update_protected {
        return access::with_access(profile, access, replacement, options);
    }
    let printed = ObjectId::from_bytes(&[0x5f, 0xc1, 9])?;
    let mut value = SecretBytes::new(vec![0x88, 26, 0x89, 24]);
    value.extend(key.as_bytes());
    let printed_write = prepare_write_object(profile, printed, value, options)?;
    let auth = ManagementAuthentication::external(key);
    auth.validate(profile, options)?;
    access::with_access(
        profile,
        access,
        RotateManagement {
            stage: 0,
            replacement,
            printed_write,
            authentication: management::ManagementMachine::new(auth),
            protected: false,
        },
        options,
    )
}

pub(crate) fn prepare_set_management_key(
    profile: &DeviceProfile,
    key: ManagementKey,
    touch: ManagementTouchPolicy,
    options: OperationOptions,
) -> Result<Sequence<MutationResult>, Error> {
    require(profile)?;
    profile.management_key_support(key.algorithm()).require()?;
    if touch == ManagementTouchPolicy::Always && key.algorithm() != ManagementKeyAlgorithm::Aes192 {
        return Err(Error::new(ErrorKind::UnsupportedFeature));
    }
    let command = key.replacement_command(touch == ManagementTouchPolicy::Always);
    access::prepare(command, options, mutation)
}

/// Write one complete 53 object container in a management-authorized transaction.
/// Owns and validates the container, then emits exactly one 53 wrapper on PUT DATA.
/// This compatibility form is for existing APIs passing framed PIV data, including
/// certificates. Value consumers should use [`write_object`].
///
/// # Errors
/// Existing delegates authorization to the card; other access must authenticate
/// management. Invalid
/// framing, a wrong outer tag, trailing fields, and input limits reject construction.
/// Profile/options/card errors and uncertain-write behavior match [`write_object`].
pub fn write_object_container(
    profile: &DeviceProfile,
    id: ObjectId,
    container: SecretBytes,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<super::MutationResult>, Error> {
    write::require_management(&access)?;
    if container.len() > options.limits.max_input_bytes {
        return Err(Error::new(ErrorKind::LimitExceeded));
    }
    let mut reader = canokey_protocol::tlv::TlvReader::new(
        container.as_bytes(),
        canokey_protocol::tlv::TlvLimits {
            max_value_bytes: options.limits.max_input_bytes,
            ..Default::default()
        },
    );
    let value = reader
        .next()?
        .ok_or_else(|| Error::new(ErrorKind::InvalidArgument))?;
    if value.tag.value() != 0x53 || reader.next()?.is_some() {
        return Err(Error::new(ErrorKind::InvalidArgument));
    }
    let sequence = super::write::prepare_write_object(
        profile,
        id,
        SecretBytes::new(value.value.to_vec()),
        options,
    )?;
    crate::access::with_access(profile, access, sequence, options)
}

struct RotateManagement {
    stage: u8,
    protected: bool,
    replacement: Sequence<MutationResult>,
    authentication: management::ManagementMachine,
    printed_write: Sequence<MutationResult>,
}
impl Machine<MutationResult> for RotateManagement {
    fn next(&mut self, response: Option<ResponseData>) -> Result<Action<MutationResult>, Error> {
        match self.stage {
            0 => {
                self.stage = 1;
                Ok(Action::Command(command::get_data(ObjectId::from_bytes(
                    &[0x5f, 0xff, 0],
                )?)))
            }
            1 => {
                let response = response.ok_or_else(|| Error::new(ErrorKind::ProtocolViolation))?;
                if !matches!(response.status.raw(), 0x6a82 | 0x6a88) {
                    response.ensure_success(Phase::Command)?;
                    self.protected =
                        ManagementProtection::from_admin_object(response.data.as_bytes())?
                            .protects_management_key();
                }
                if self.protected {
                    self.stage = 2;
                    Ok(Action::Command(command::get_data(ObjectId::from_bytes(
                        &[0x5f, 0xc1, 9],
                    )?)))
                } else {
                    self.stage = 3;
                    self.next(None)
                }
            }
            2 => {
                let response = response.ok_or_else(|| Error::new(ErrorKind::ProtocolViolation))?;
                response.ensure_success(Phase::Command)?;
                // Require a valid protected object before committing either write.
                protected_management_key_from_object(response.data.as_bytes())?;
                self.stage = 3;
                self.next(None)
            }
            3 => match self.replacement.next(response)? {
                Action::Command(c) => Ok(Action::Command(c)),
                Action::Done(result) if !self.protected => Ok(Action::Done(result)),
                Action::Done(_) => {
                    self.stage = 4;
                    self.next(None)
                }
            },
            4 => match self.authentication.next(response)? {
                Action::Command(c) => Ok(Action::Command(c)),
                Action::Done(()) => {
                    self.stage = 5;
                    self.next(None)
                }
            },
            5 => self.printed_write.next(response),
            _ => Err(Error::new(ErrorKind::OperationStateError)),
        }
    }
}
