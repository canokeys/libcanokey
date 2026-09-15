//! Explicit operations with no implicit retries, credential defaults or cache updates.
use crate::*;
use canokey_compat::AlgorithmConfig;
use canokey_protocol::{ApduHeader, ExpectedLength};

/// Physical reference accepted by the container-name command. Attestation naming
/// does not make F9 an ordinary key-generation, signing or enumeration slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContainerNameReference {
    /// An ordinary PIV key slot.
    Key(Slot),
    /// The attestation key, physical reference F9.
    Attestation,
}
impl From<Slot> for ContainerNameReference {
    fn from(slot: Slot) -> Self {
        Self::Key(slot)
    }
}
impl ContainerNameReference {
    /// Return the physical PIV reference for F5.
    pub fn reference(self) -> u8 {
        match self {
            Self::Key(slot) => slot.reference(),
            Self::Attestation => 0xf9,
        }
    }
    fn check(self, profile: &DeviceProfile) -> Result<(), Error> {
        checked(
            profile,
            Capability::ContainerNames,
            match self {
                Self::Key(slot) => Some(slot),
                Self::Attestation => None,
            },
        )
    }
}

/// Validated container name: at most 78 UTF-16LE bytes, no NUL/unpaired surrogate.
/// Empty names clear the per-slot attribute; absent keys remain status errors.
#[derive(Debug)]
pub struct ContainerName(SecretBytes);
impl ContainerName {
    /// Copy bounded raw UTF-16LE, rejecting odd lengths, NUL and unpaired surrogates.
    pub fn from_utf16le(data: &[u8]) -> Result<Self, Error> {
        if data.len() > 78 || data.len() % 2 != 0 {
            return Err(Error::new(ErrorKind::InvalidArgument));
        }
        let units = data
            .chunks_exact(2)
            .map(|v| u16::from_le_bytes([v[0], v[1]]));
        for ch in char::decode_utf16(units) {
            if ch.is_err() || ch == Ok('\0') {
                return Err(Error::new(ErrorKind::InvalidArgument));
            }
        }
        Ok(Self(SecretBytes::new(data.to_vec())))
    }
    /// Encode UTF-8 text to bounded UTF-16LE. Empty text clears the name.
    pub fn from_text(text: &str) -> Result<Self, Error> {
        if text.encode_utf16().count() > 39 {
            return Err(Error::new(ErrorKind::InvalidArgument));
        }
        Self::from_utf16le(
            &text
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
    }
    /// Borrow validated UTF-16LE bytes with no terminator.
    pub fn as_utf16le(&self) -> &[u8] {
        self.0.as_bytes()
    }
    /// Return an owned UTF-8 rendering of the validated name.
    pub fn text(&self) -> String {
        String::from_utf16_lossy(
            &self
                .0
                .as_bytes()
                .chunks_exact(2)
                .map(|v| u16::from_le_bytes([v[0], v[1]]))
                .collect::<Vec<_>>(),
        )
    }
}
fn checked(profile: &DeviceProfile, feature: Capability, slot: Option<Slot>) -> Result<(), Error> {
    require(profile)?;
    profile.capability(feature).require()?;
    if let Some(slot) = slot {
        profile.piv_slot_support(slot.reference()).require()?;
    }
    Ok(())
}
fn command(ins: u8, p1: u8, p2: u8, data: SecretBytes, read: bool) -> LogicalCommand {
    let mut c = LogicalCommand::new(
        ApduHeader::new(0, ins, p1, p2),
        vec![],
        if read {
            ExpectedLength::Exact(256)
        } else {
            ExpectedLength::Absent
        },
    );
    c.data = data;
    c.correct_le = read;
    c
}
/// Read an ordinary or attestation key's container name. A zero-byte reply means no name;
/// missing keys remain NotFound. Malformed UTF-16 or oversized responses fail.
pub fn read_container_name(
    profile: &DeviceProfile,
    slot: impl Into<ContainerNameReference>,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<ContainerName>, Error> {
    let target = prepare_read_name(profile, slot, options)?;
    access::with_access(profile, access, target, options)
}
pub(crate) fn prepare_read_name(
    profile: &DeviceProfile,
    slot: impl Into<ContainerNameReference>,
    options: OperationOptions,
) -> Result<Sequence<ContainerName>, Error> {
    let slot = slot.into();
    slot.check(profile)?;
    access::prepare(
        command(0xf5, 0, slot.reference(), SecretBytes::default(), true),
        options,
        |r| {
            r.ensure_success(Phase::Command)?;
            ContainerName::from_utf16le(r.data.as_bytes())
                .map_err(|_| Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing))
        },
    )
}
/// Set/clear a container name with explicit management access. Firmware enforces
/// cross-slot uniqueness and existing-key requirements; no local cache is changed.
pub fn set_container_name(
    profile: &DeviceProfile,
    slot: impl Into<ContainerNameReference>,
    name: ContainerName,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<MutationResult>, Error> {
    write::require_management(&access)?;
    let target = prepare_set_name(profile, slot, name, options)?;
    access::with_access(profile, access, target, options)
}
pub(crate) fn prepare_set_name(
    profile: &DeviceProfile,
    slot: impl Into<ContainerNameReference>,
    name: ContainerName,
    options: OperationOptions,
) -> Result<Sequence<MutationResult>, Error> {
    let slot = slot.into();
    slot.check(profile)?;
    let mut target = command(0xf5, 1, slot.reference(), name.0, false);
    if target.data.is_empty() {
        // Keep the five-byte F5 clear form. It is still a mutation: a 6C
        // response must not authorize Le correction or replay.
        target.le = ExpectedLength::Exact(256);
    }
    access::prepare(target, options, write::mutation)
}
/// Move an ordinary key (including its name) to an empty slot. Certificates stay
/// in place. Requires explicit management access; invalidate both key caches even
/// after uncertain I/O failure. No overwrite, rollback or automatic replay occurs.
pub fn move_key(
    profile: &DeviceProfile,
    source: Slot,
    target: Slot,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<MutationResult>, Error> {
    write::require_management(&access)?;
    let op = prepare_move_delete(profile, source, Some(target), options)?;
    access::with_access(profile, access, op, options)
}
/// Delete an ordinary key and its name without deleting its certificate. Requires
/// management access. Firmware treats an already absent key as success.
pub fn delete_key(
    profile: &DeviceProfile,
    slot: Slot,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<MutationResult>, Error> {
    write::require_management(&access)?;
    let target = prepare_move_delete(profile, slot, None, options)?;
    access::with_access(profile, access, target, options)
}
pub(crate) fn prepare_move_delete(
    profile: &DeviceProfile,
    source: Slot,
    target: Option<Slot>,
    options: OperationOptions,
) -> Result<Sequence<MutationResult>, Error> {
    checked(profile, Capability::KeyMoveDelete, Some(source))?;
    if let Some(target) = target {
        profile.piv_slot_support(target.reference()).require()?;
        if target == source {
            return Err(Error::new(ErrorKind::InvalidArgument));
        }
    }
    access::prepare(
        command(
            0xf6,
            target.map_or(0xff, Slot::reference),
            source.reference(),
            SecretBytes::default(),
            false,
        ),
        options,
        write::mutation,
    )
}
/// Set retry limits AND reset PIN/PUK to firmware defaults (123456 / 12345678).
/// This is a credential reset, not a counter-only change. Requires both management
/// and PIN access; each limit is 1..=15. Firmware clears authentication before
/// writing; failure can leave partially changed credentials. Clear caller caches
/// on any attempted reset. No default credential is ever submitted by this factory.
pub fn reset_pin_puk_retries(
    profile: &DeviceProfile,
    pin_retries: u8,
    puk_retries: u8,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<MutationResult>, Error> {
    if !matches!(access, Access::PinAndManagement { .. } | Access::Existing) {
        return Err(Error::new(ErrorKind::InvalidArgument));
    }
    let target = prepare_retry_reset(profile, pin_retries, puk_retries, options)?;
    access::with_access(profile, access, target, options)
}
pub(crate) fn prepare_retry_reset(
    profile: &DeviceProfile,
    pin: u8,
    puk: u8,
    options: OperationOptions,
) -> Result<Sequence<MutationResult>, Error> {
    checked(profile, Capability::RetryReset, None)?;
    if !(1..=15).contains(&pin) || !(1..=15).contains(&puk) {
        return Err(Error::new(ErrorKind::InvalidArgument));
    }
    access::prepare(
        command(0xfa, pin, puk, SecretBytes::default(), false),
        options,
        write::mutation,
    )
}
/// Replace the complete algorithm-ID configuration with explicit management access.
/// Exactly ten known-layout bytes are required on 3.1.0; unknown trailing fields
/// are not silently discarded. Success returns ReprobeRequired; uncertain writes
/// also invalidate the caller's profile. Never continue with cached wire IDs.
pub fn set_algorithm_config(
    profile: &DeviceProfile,
    config: AlgorithmConfig,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<MutationResult>, Error> {
    write::require_management(&access)?;
    let target = prepare_config(profile, config, options)?;
    access::with_access(profile, access, target, options)
}
pub(crate) fn prepare_config(
    profile: &DeviceProfile,
    config: AlgorithmConfig,
    options: OperationOptions,
) -> Result<Sequence<MutationResult>, Error> {
    checked(profile, Capability::AlgorithmConfigWrite, None)?;
    if config.raw().len() != 10
        || (config.enabled()
            && config.raw()[1..]
                .iter()
                .any(|b| [0, 0x0a, 0x07, 0x11, 0x14, 0xff].contains(b)))
    {
        return Err(Error::new(ErrorKind::InvalidArgument));
    }
    access::prepare(
        command(0xee, 2, 0, SecretBytes::new(config.raw().to_vec()), false),
        options,
        |r| {
            write::mutation(r)?;
            Ok(MutationResult {
                profile_effect: ProfileEffect::ReprobeRequired,
            })
        },
    )
}
/// Request a device-generated attestation certificate for an ordinary slot.
/// Returns opaque DER bytes without certificate/trust verification. Firmware
/// requires a generated key and an installed attestation signer; status errors
/// propagate. No PIN/management credential or attestation trust is inferred.
pub fn attest(
    profile: &DeviceProfile,
    slot: Slot,
    options: OperationOptions,
) -> Result<Operation<SecretBytes>, Error> {
    let target = prepare_attest(profile, slot, options)?;
    access::with_access(profile, Access::None, target, options)
}
pub(crate) fn prepare_attest(
    profile: &DeviceProfile,
    slot: Slot,
    options: OperationOptions,
) -> Result<Sequence<SecretBytes>, Error> {
    checked(profile, Capability::Attestation, Some(slot))?;
    let mut command = command(0xf9, slot.reference(), 0, SecretBytes::default(), true);
    command.correct_le = false;
    access::prepare(command, options, |r| {
        r.ensure_success(Phase::Command)?;
        if r.data.is_empty() {
            return Err(Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing));
        }
        Ok(r.data)
    })
}
/// Explicitly reset PIV after both PIN and PUK are already blocked. This factory
/// never exhausts retries or tries credentials. Ordinary keys, certificates and
/// names are removed; the attestation slot survives. Success requires reprobe;
/// clear credential/object caches even after uncertain I/O failure.
pub fn reset_piv(
    profile: &DeviceProfile,
    options: OperationOptions,
) -> Result<Operation<MutationResult>, Error> {
    checked(profile, Capability::PivReset, None)?;
    let target = access::prepare(
        command(0xfb, 0, 0, SecretBytes::default(), false),
        options,
        |r| {
            write::mutation(r)?;
            Ok(MutationResult {
                profile_effect: ProfileEffect::ReprobeRequired,
            })
        },
    )?;
    access::with_access(profile, Access::None, target, options)
}
