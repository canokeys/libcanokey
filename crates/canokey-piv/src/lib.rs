//! Initial PIV operations: selection, PIN/PUK and object reads.
#![forbid(unsafe_code)]
pub use canokey_compat::Algorithm;
use canokey_compat::{Capability, DeviceProfile};
use canokey_protocol::operation::{
    engine::{Action, Machine},
    LogicalCommand, ResponseData,
};
use canokey_protocol::tlv::{Tag, TlvLimits, TlvReader};
use canokey_protocol::{
    Error, ErrorKind, Operation, OperationOptions, Phase, SecretBytes, SecretReference, StatusWord,
};
use std::collections::VecDeque;

#[derive(Clone, Debug)]
pub struct Pin(SecretBytes);
#[derive(Clone, Debug)]
pub struct Puk(SecretBytes);
fn secret(bytes: &[u8]) -> Result<SecretBytes, Error> {
    if !(6..=8).contains(&bytes.len()) || bytes.contains(&0xff) {
        return Err(Error::new(ErrorKind::InvalidPin));
    }
    Ok(SecretBytes::new(bytes.to_vec()))
}
impl Pin {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(secret(bytes)?))
    }
}
impl Puk {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(secret(bytes)?))
    }
}
#[derive(Clone, Debug)]
pub enum Access {
    None,
    Pin(Pin),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    Authentication,
    Signature,
    KeyManagement,
    CardAuthentication,
    Retired(RetiredSlot),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetiredSlot(u8);
impl RetiredSlot {
    pub fn new(index: u8) -> Result<Self, Error> {
        if (1..=20).contains(&index) {
            Ok(Self(index))
        } else {
            Err(Error::new(ErrorKind::InvalidArgument))
        }
    }
}
impl Slot {
    pub fn reference(self) -> u8 {
        match self {
            Self::Authentication => 0x9a,
            Self::Signature => 0x9c,
            Self::KeyManagement => 0x9d,
            Self::CardAuthentication => 0x9e,
            Self::Retired(n) => 0x81 + n.0,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectId(Tag);
impl ObjectId {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(Tag::from_bytes(bytes)?))
    }
    pub fn certificate(slot: Slot) -> Self {
        let last = match slot {
            Slot::Authentication => 5,
            Slot::Signature => 10,
            Slot::KeyManagement => 11,
            Slot::CardAuthentication => 1,
            Slot::Retired(n) => 12 + n.0,
        };
        // All constructed tags are valid BER tags.
        Self(Tag::from_bytes(&[0x5f, 0xc1, last]).expect("fixed PIV tag"))
    }
    pub fn as_bytes(self) -> Vec<u8> {
        self.0.to_bytes()
    }
}
#[derive(Debug)]
pub struct SelectionInfo {
    pub data: SecretBytes,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinStatus {
    pub verified: Option<bool>,
    pub retries_remaining: Option<u8>,
    pub retries_total: Option<u8>,
    pub blocked: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileEffect {
    Unchanged,
    ReprobeRequired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MutationResult {
    pub profile_effect: ProfileEffect,
}
pub type ObjectData = SecretBytes;
fn unchanged() -> MutationResult {
    MutationResult {
        profile_effect: ProfileEffect::Unchanged,
    }
}
fn require(profile: &DeviceProfile) -> Result<(), Error> {
    profile.capability(Capability::Piv).require()
}
fn auth_error(sw: StatusWord, reference: SecretReference) -> Error {
    Error::status(sw, Phase::Authentication, Some(reference))
}
fn require_auth(response: &ResponseData, reference: SecretReference) -> Result<(), Error> {
    if response.status.is_success() {
        Ok(())
    } else {
        Err(auth_error(response.status, reference))
    }
}

pub mod command {
    use super::*;
    use canokey_protocol::{ApduHeader, ExpectedLength};
    fn cmd(ins: u8, p1: u8, p2: u8, data: Vec<u8>, le: ExpectedLength) -> LogicalCommand {
        LogicalCommand::new(ApduHeader::new(0, ins, p1, p2), data, le)
    }
    pub fn select() -> LogicalCommand {
        cmd(0xa4, 4, 0, vec![0xa0, 0, 0, 3, 8], ExpectedLength::Absent)
    }
    fn read(ins: u8, p1: u8, p2: u8, data: Vec<u8>) -> LogicalCommand {
        let mut c = cmd(ins, p1, p2, data, ExpectedLength::Exact(256));
        c.correct_le = true;
        c
    }
    pub fn version() -> LogicalCommand {
        read(0xfd, 0, 0, vec![])
    }
    pub fn algorithm_config() -> LogicalCommand {
        read(0xee, 1, 0, vec![])
    }
    pub fn pin_status() -> LogicalCommand {
        read(0x20, 0, 0x80, vec![])
    }
    fn padded(secret: &SecretBytes) -> Vec<u8> {
        let mut data = Vec::with_capacity(8);
        data.extend_from_slice(secret.as_bytes());
        data.resize(8, 0xff);
        data
    }
    pub fn verify_pin(pin: &Pin) -> LogicalCommand {
        cmd(0x20, 0, 0x80, padded(&pin.0), ExpectedLength::Absent)
    }
    pub fn logout() -> LogicalCommand {
        cmd(0x20, 0xff, 0x80, vec![], ExpectedLength::Exact(256))
    }
    pub(super) fn change(
        ins: u8,
        reference: u8,
        old: &SecretBytes,
        new: &SecretBytes,
    ) -> LogicalCommand {
        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(old.as_bytes());
        data.resize(8, 0xff);
        data.extend_from_slice(new.as_bytes());
        data.resize(16, 0xff);
        cmd(ins, 0, reference, data, ExpectedLength::Absent)
    }
    pub fn get_data(id: ObjectId) -> LogicalCommand {
        let tag = id.as_bytes();
        let mut data = vec![0x5c, tag.len() as u8];
        data.extend(tag);
        read(0xcb, 0x3f, 0xff, data)
    }
}
struct Request {
    command: LogicalCommand,
    phase: Phase,
    reference: Option<SecretReference>,
}
type Parser<T> = Box<dyn FnOnce(ResponseData) -> Result<T, Error> + Send>;
struct Sequence<T> {
    pending: VecDeque<Request>,
    current: Option<(Phase, Option<SecretReference>)>,
    parse: Option<Parser<T>>,
}
impl<T> Machine<T> for Sequence<T> {
    fn next(&mut self, response: Option<ResponseData>) -> Result<Action<T>, Error> {
        if let Some(response) = response {
            if self.pending.is_empty() {
                return Ok(Action::Done(self
                    .parse
                    .take()
                    .ok_or_else(|| Error::new(ErrorKind::OperationStateError))?(
                    response,
                )?));
            }
            let (phase, reference) = self
                .current
                .ok_or_else(|| Error::new(ErrorKind::ProtocolViolation))?;
            if !response.status.is_success() {
                return Err(Error::status(response.status, phase, reference));
            }
        }
        let req = self
            .pending
            .pop_front()
            .ok_or_else(|| Error::new(ErrorKind::ProtocolViolation))?;
        self.current = Some((req.phase, req.reference));
        Ok(Action::Command(req.command))
    }
}
fn make<T: 'static>(
    commands: Vec<Request>,
    options: OperationOptions,
    parse: impl FnOnce(ResponseData) -> Result<T, Error> + Send + 'static,
) -> Result<Operation<T>, Error> {
    options.validate()?;
    for request in &commands {
        canokey_protocol::operation::validate_command(&request.command, options)?;
    }
    Operation::from_machine(
        Sequence {
            pending: commands.into(),
            current: None,
            parse: Some(Box::new(parse)),
        },
        options,
    )
}
fn request(command: LogicalCommand, phase: Phase, reference: Option<SecretReference>) -> Request {
    Request {
        command,
        phase,
        reference,
    }
}
fn selected(command: LogicalCommand) -> Vec<Request> {
    vec![
        request(command::select(), Phase::Select, None),
        request(command, Phase::Command, None),
    ]
}
pub fn select(
    profile: &DeviceProfile,
    options: OperationOptions,
) -> Result<Operation<SelectionInfo>, Error> {
    require(profile)?;
    make(
        vec![request(command::select(), Phase::Select, None)],
        options,
        |r| {
            r.ensure_success(Phase::Select)?;
            Ok(SelectionInfo { data: r.data })
        },
    )
}
pub fn verify_pin(
    profile: &DeviceProfile,
    pin: Pin,
    options: OperationOptions,
) -> Result<Operation<()>, Error> {
    require(profile)?;
    make(selected(command::verify_pin(&pin)), options, |r| {
        require_auth(&r, SecretReference::Pin)
    })
}
pub fn get_pin_status(
    profile: &DeviceProfile,
    options: OperationOptions,
) -> Result<Operation<PinStatus>, Error> {
    require(profile)?;
    make(selected(command::pin_status()), options, |r| {
        if !r.data.is_empty() {
            return Err(Error::new(ErrorKind::InvalidResponse));
        }
        match r.status.raw() {
            0x9000 => Ok(PinStatus {
                verified: Some(true),
                retries_remaining: None,
                retries_total: None,
                blocked: false,
            }),
            0x6983 => Ok(PinStatus {
                verified: Some(false),
                retries_remaining: Some(0),
                retries_total: None,
                blocked: true,
            }),
            sw if sw & 0xfff0 == 0x63c0 => Ok(PinStatus {
                verified: Some(false),
                retries_remaining: Some((sw & 15) as u8),
                retries_total: None,
                blocked: false,
            }),
            _ => Err(auth_error(r.status, SecretReference::Pin)),
        }
    })
}
pub fn logout(profile: &DeviceProfile, options: OperationOptions) -> Result<Operation<()>, Error> {
    require(profile)?;
    make(selected(command::logout()), options, |r| {
        r.ensure_success(Phase::Authentication)
    })
}
pub fn change_pin(
    profile: &DeviceProfile,
    old: Pin,
    new: Pin,
    options: OperationOptions,
) -> Result<Operation<MutationResult>, Error> {
    change_secret(
        profile,
        0x24,
        0x80,
        &old.0,
        &new.0,
        SecretReference::Pin,
        options,
    )
}
pub fn change_puk(
    profile: &DeviceProfile,
    old: Puk,
    new: Puk,
    options: OperationOptions,
) -> Result<Operation<MutationResult>, Error> {
    change_secret(
        profile,
        0x24,
        0x81,
        &old.0,
        &new.0,
        SecretReference::Puk,
        options,
    )
}
pub fn unblock_pin(
    profile: &DeviceProfile,
    puk: Puk,
    new_pin: Pin,
    options: OperationOptions,
) -> Result<Operation<MutationResult>, Error> {
    change_secret(
        profile,
        0x2c,
        0x80,
        &puk.0,
        &new_pin.0,
        SecretReference::Puk,
        options,
    )
}
fn change_secret(
    profile: &DeviceProfile,
    ins: u8,
    p2: u8,
    old: &SecretBytes,
    new: &SecretBytes,
    reference: SecretReference,
    options: OperationOptions,
) -> Result<Operation<MutationResult>, Error> {
    require(profile)?;
    make(
        selected(command::change(ins, p2, old, new)),
        options,
        move |r| {
            require_auth(&r, reference)?;
            Ok(unchanged())
        },
    )
}
pub fn read_object(
    profile: &DeviceProfile,
    id: ObjectId,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<ObjectData>, Error> {
    require(profile)?;
    let legacy = profile.legacy_unwrapped_objects();
    let mut commands = vec![request(command::select(), Phase::Select, None)];
    if let Access::Pin(pin) = access {
        commands.push(request(
            command::verify_pin(&pin),
            Phase::Authentication,
            Some(SecretReference::Pin),
        ));
    }
    commands.push(request(command::get_data(id), Phase::Command, None));
    let limit = options.limits.max_total_response_bytes;
    make(commands, options, move |r| {
        r.ensure_success(Phase::Command)?;
        let data = r.data.as_bytes();
        if legacy
            && ((id.0.value() == 0x5fc102 && data.first() == Some(&0x30))
                || (id.0.value() == 0x5fc107 && data.first() == Some(&0xf0)))
        {
            return Ok(r.data);
        }
        let mut reader = TlvReader::new(
            data,
            TlvLimits {
                max_value_bytes: limit,
                ..Default::default()
            },
        );
        let tlv = reader
            .next()?
            .ok_or_else(|| Error::new(ErrorKind::InvalidResponse))?;
        if tlv.tag.value() != if id.0.value() == 0x7e { 0x7e } else { 0x53 }
            || reader.next()?.is_some()
        {
            return Err(Error::new(ErrorKind::InvalidResponse));
        }
        Ok(SecretBytes::new(tlv.value.to_vec()))
    })
}
