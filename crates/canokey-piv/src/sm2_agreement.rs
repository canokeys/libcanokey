//! SM2's protocol is distinct from ECDH and includes its specified KDF on device.
use crate::*;
use canokey_protocol::tlv::TlvWriter;
/// Role in the SM2 key exchange, determining identity/public-key ordering in the KDF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sm2Role {
    /// Two GENERAL AUTHENTICATE steps on the card. Peer inputs must already be
    /// available before construction; this API does not pause for a network peer.
    Initiator,
    /// One GENERAL AUTHENTICATE step with pre-exchanged peer inputs.
    Responder,
}
/// Owned peer inputs and explicit SM2 key-exchange parameters.
#[derive(Debug)]
pub struct Sm2AgreementInput {
    /// Protocol role.
    pub role: Sm2Role,
    /// Peer's static key: 65-byte uncompressed SEC1 on SM2.
    pub peer_static: Vec<u8>,
    /// Peer's ephemeral key in the same format, acquired before constructing this operation.
    pub peer_ephemeral: Vec<u8>,
    /// Own identity, 1..=32 bytes; None uses firmware's 1234567812345678 default.
    pub user_id: Option<Vec<u8>>,
    /// Peer identity, 1..=32 bytes; None uses the same firmware default.
    pub peer_id: Option<Vec<u8>>,
    /// Requested session-key length, 1..=128 bytes. Firmware performs the SM2 KDF.
    pub key_len: u16,
}
impl Sm2AgreementInput {
    pub(crate) fn input_len(&self) -> usize {
        self.peer_static
            .len()
            .saturating_add(self.peer_ephemeral.len())
            .saturating_add(self.user_id.as_ref().map_or(0, Vec::len))
            .saturating_add(self.peer_id.as_ref().map_or(0, Vec::len))
    }
}
/// Owned SM2 key and public ephemeral point. No peer key confirmation is performed.
#[derive(Debug)]
pub struct Sm2Agreement {
    /// Own 65-byte ephemeral SEC1 point to communicate to the peer.
    pub ephemeral_public: Vec<u8>,
    /// Derived session key, wiped on drop. Do not use before application-level
    /// peer authentication/key confirmation appropriate to the enclosing protocol.
    pub key: SecretBytes,
}
fn invalid() -> Error {
    Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing)
}
fn point(bytes: &[u8]) -> bool {
    bytes.len() == 65 && bytes[0] == 4 && sm2::PublicKey::from_sec1_bytes(bytes).is_ok()
}
fn identity(id: &Option<Vec<u8>>) -> Result<(), Error> {
    if id.as_ref().is_some_and(|v| v.is_empty() || v.len() > 32) {
        Err(Error::new(ErrorKind::InvalidArgument))
    } else {
        Ok(())
    }
}
fn push(writer: &mut TlvWriter, tag: u8, bytes: &[u8]) -> Result<(), Error> {
    writer.push(Tag::from_bytes(&[tag])?, bytes)
}
fn ga(
    id: u8,
    slot: Slot,
    inner: SecretBytes,
    options: OperationOptions,
) -> Result<LogicalCommand, Error> {
    let mut outer = TlvWriter::new(options.limits.max_input_bytes);
    push(&mut outer, 0x7c, inner.as_bytes())?;
    let mut command = keys::key_command(0x87, id, slot.reference(), outer.into_bytes());
    // A chained first SM2 command selects signing, not agreement.
    command.allow_chaining = false;
    command.allow_extended = false;
    canokey_protocol::operation::validate_command(&command, options)?;
    Ok(command)
}
fn fields(response: ResponseData, tags: &[u8], limit: usize) -> Result<Vec<SecretBytes>, Error> {
    response.ensure_success(Phase::Command)?;
    // Firmware emits definite BER lengths with two octets even below 256.
    let mut r = TlvReader::new_ber(
        response.data.as_bytes(),
        TlvLimits {
            max_value_bytes: limit,
            ..Default::default()
        },
    );
    let outer = r.next()?.ok_or_else(invalid)?;
    if outer.tag.value() != 0x7c || r.next()?.is_some() {
        return Err(invalid());
    }
    let mut r = outer.children()?;
    let mut values = Vec::with_capacity(tags.len());
    for tag in tags {
        let field = r.next()?.ok_or_else(invalid)?;
        if field.tag.value() != u32::from(*tag) {
            return Err(invalid());
        }
        values.push(SecretBytes::new(field.value.to_vec()));
    }
    if r.next()?.is_some() {
        return Err(invalid());
    }
    Ok(values)
}
/// Agree an SM2 session key using pre-exchanged peer static/ephemeral keys.
/// Selects/authenticates once. The initiator first reads key policy and permits
/// only PIN Never/Once: pinned firmware consumes PIN-always on its first GA, while
/// VERIFY before the second GA destroys agreement state. Such keys fail before
/// generating an ephemeral key. The responder supports ordinary explicit Access.
///
/// # Errors
/// Invalid peers/IDs/lengths, unsupported firmware and frames that would require
/// chaining fail explicitly. Wrong response points/lengths/statuses stop without
/// replay. Cancellation/drop only erase host state; drain/isolate I/O, then begin
/// the next use with a new SELECT. Callers own networking and key confirmation.
pub fn agree_sm2(
    profile: &DeviceProfile,
    slot: Slot,
    input: Sm2AgreementInput,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<Sm2Agreement>, Error> {
    let target = prepare_agreement(profile, slot, input, options)?;
    access::with_access(profile, access, target, options)
}
pub(crate) struct AgreementMachine {
    preflight: Option<Sequence<Metadata>>,
    begin: Option<LogicalCommand>,
    finish: Option<LogicalCommand>,
    ephemeral: Option<Vec<u8>>,
    role: Sm2Role,
    key_len: usize,
    limit: usize,
}
impl Machine<Sm2Agreement> for AgreementMachine {
    fn next(&mut self, response: Option<ResponseData>) -> Result<Action<Sm2Agreement>, Error> {
        if let Some(preflight) = self.preflight.as_mut() {
            match preflight.next(response)? {
                Action::Command(c) => return Ok(Action::Command(c)),
                Action::Done(metadata) => {
                    match metadata.fields().pin_policy {
                        Some(KnownOrUnknown::Known(PinPolicy::Never | PinPolicy::Once)) => {}
                        Some(KnownOrUnknown::Known(PinPolicy::Always)) => {
                            return Err(Error::new(ErrorKind::UnsupportedFeature))
                        }
                        _ => return Err(Error::new(ErrorKind::CapabilityUnknown)),
                    }
                    self.preflight = None;
                    return self.next(None);
                }
            }
        }
        if let Some(begin) = self.begin.take() {
            return Ok(Action::Command(begin));
        }
        let response = response.ok_or_else(|| Error::new(ErrorKind::ProtocolViolation))?;
        if self.role == Sm2Role::Initiator && self.ephemeral.is_none() {
            let mut values = fields(response, &[0x82], self.limit)?;
            let ephemeral = values.remove(0);
            if !point(ephemeral.as_bytes()) {
                return Err(invalid());
            }
            self.ephemeral = Some(ephemeral.as_bytes().to_vec());
            return Ok(Action::Command(self.finish.take().ok_or_else(invalid)?));
        }
        let (ephemeral, key) = if self.role == Sm2Role::Responder {
            let mut values = fields(response, &[0x82, 0x85], self.limit)?;
            let key = values.pop().ok_or_else(invalid)?;
            let ephemeral = values.pop().ok_or_else(invalid)?;
            (ephemeral.as_bytes().to_vec(), key)
        } else {
            let mut values = fields(response, &[0x82], self.limit)?;
            (self.ephemeral.take().ok_or_else(invalid)?, values.remove(0))
        };
        if !point(&ephemeral) || key.len() != self.key_len {
            return Err(invalid());
        }
        Ok(Action::Done(Sm2Agreement {
            ephemeral_public: ephemeral,
            key,
        }))
    }
}
pub(crate) fn prepare_agreement(
    profile: &DeviceProfile,
    slot: Slot,
    input: Sm2AgreementInput,
    options: OperationOptions,
) -> Result<AgreementMachine, Error> {
    options.validate()?;
    profile.capability(Capability::Sm2Agreement).require()?;
    let id = keys::key_id(profile, slot, Algorithm::Sm2)?;
    if !matches!(slot, Slot::KeyManagement | Slot::Retired(_))
        || !point(&input.peer_static)
        || !point(&input.peer_ephemeral)
        || !(1..=128).contains(&input.key_len)
    {
        return Err(Error::new(ErrorKind::InvalidArgument));
    }
    identity(&input.user_id)?;
    identity(&input.peer_id)?;
    if input.input_len() > options.limits.max_input_bytes {
        return Err(Error::new(ErrorKind::LimitExceeded));
    }
    let mut exp = TlvWriter::new(options.limits.max_input_bytes);
    push(&mut exp, 0x86, &input.peer_static)?;
    push(&mut exp, 0x87, &input.peer_ephemeral)?;
    if let Some(id) = &input.peer_id {
        push(&mut exp, 0x88, id)?;
    }
    push(&mut exp, 0x89, &input.key_len.to_be_bytes())?;
    let mut inner = TlvWriter::new(options.limits.max_input_bytes);
    if input.role == Sm2Role::Responder {
        if let Some(id) = &input.user_id {
            push(&mut inner, 0x80, id)?;
        }
    }
    push(&mut inner, 0x82, &[])?;
    push(&mut inner, 0x85, exp.into_bytes().as_bytes())?;
    let finish = ga(id, slot, inner.into_bytes(), options)?;
    let (preflight, begin, finish) = if input.role == Sm2Role::Initiator {
        let mut inner = TlvWriter::new(options.limits.max_input_bytes);
        if let Some(id) = &input.user_id {
            push(&mut inner, 0x80, id)?;
        }
        push(&mut inner, 0x82, &[])?;
        (
            Some(metadata::prepare_get_metadata(
                profile,
                MetadataReference::Key(slot),
                options,
            )?),
            ga(id, slot, inner.into_bytes(), options)?,
            Some(finish),
        )
    } else {
        (None, finish, None)
    };
    Ok(AgreementMachine {
        preflight,
        begin: Some(begin),
        finish,
        ephemeral: None,
        role: input.role,
        key_len: input.key_len as usize,
        limit: options.limits.max_total_response_bytes,
    })
}
