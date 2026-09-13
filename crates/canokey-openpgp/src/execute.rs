use crate::{keys, types::invalid, *};
use canokey_compat::{Capability, DeviceProfile};
use canokey_protocol::{
    operation::{
        engine::{Action, Machine},
        validate_command, Continuation, LogicalCommand, ResponseData,
    },
    ApduHeader, Error, ErrorKind, ExpectedLength, Operation, OperationOptions, Phase, SecretBytes,
    SecretReference,
};
use std::collections::VecDeque;
fn argument() -> Error {
    Error::new(ErrorKind::InvalidArgument)
}
fn check_password(p: &Password, admin: bool) -> Result<(), Error> {
    if admin && p.0.len() < 8 {
        Err(Error::new(ErrorKind::InvalidPin))
    } else {
        Ok(())
    }
}
fn command(ins: u8, p1: u8, p2: u8, data: SecretBytes, read: bool, chain: bool) -> LogicalCommand {
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
    c.allow_chaining = chain;
    c
}
fn empty(ins: u8, p1: u8, p2: u8) -> LogicalCommand {
    let mut c = command(ins, p1, p2, SecretBytes::default(), false, false);
    c.continuation = Continuation::None;
    c
}
fn read(tag: u16) -> LogicalCommand {
    command(
        0xca,
        (tag >> 8) as u8,
        tag as u8,
        SecretBytes::default(),
        true,
        false,
    )
}
fn select() -> LogicalCommand {
    command(
        0xa4,
        4,
        0,
        SecretBytes::new(vec![0xd2, 0x76, 0, 1, 0x24, 1]),
        false,
        false,
    )
}
fn select_certificate(slot: Slot) -> LogicalCommand {
    command(
        0xa5,
        slot.occurrence(),
        4,
        SecretBytes::new(vec![0x60, 4, 0x5c, 2, 0x7f, 0x21]),
        false,
        false,
    )
}
fn write_data(value: &DataWrite) -> Result<LogicalCommand, Error> {
    let (tag, bytes): (u16, SecretBytes) = match value {
        DataWrite::Name(v) => {
            if v.len() > 39 {
                return Err(argument());
            }
            (0x5b, SecretBytes::new(v.clone()))
        }
        DataWrite::Login(v) => {
            if v.len() > 63 {
                return Err(argument());
            }
            (0x5e, v.clone())
        }
        DataWrite::Language(v) => {
            if v.len() > 8 {
                return Err(argument());
            }
            (0x5f2d, SecretBytes::new(v.clone()))
        }
        DataWrite::Sex(v) => (0x5f35, SecretBytes::new(vec![*v])),
        DataWrite::Url(v) => {
            if v.len() > 255 {
                return Err(argument());
            }
            (0x5f50, SecretBytes::new(v.clone()))
        }
        DataWrite::ResetCode(p) => {
            if let Some(p) = p {
                check_password(p, true)?;
            }
            (
                0xd3,
                p.as_ref()
                    .map_or_else(SecretBytes::default, |p| p.0.clone()),
            )
        }
        DataWrite::ReuseSignaturePin(reuse) => (0xc4, SecretBytes::new(vec![u8::from(*reuse)])),
        DataWrite::TouchPolicy(slot, policy) => (
            u16::from(0xd6 + slot.occurrence()),
            SecretBytes::new(vec![
                match policy {
                    TouchPolicy::Off => 0,
                    TouchPolicy::On => 1,
                    TouchPolicy::Permanent => 2,
                },
                0x20,
            ]),
        ),
        DataWrite::TouchCacheTime(seconds) => (0x0102, SecretBytes::new(vec![*seconds])),
        DataWrite::Algorithm(slot, a) => (
            slot.attributes().into(),
            SecretBytes::new(keys::attributes(*slot, *a)?),
        ),
        DataWrite::Fingerprint(slot, bytes) => (
            u16::from(0xc7 + slot.occurrence()),
            SecretBytes::new(bytes.to_vec()),
        ),
        DataWrite::CaFingerprint(slot, bytes) => (
            u16::from(0xca + slot.occurrence()),
            SecretBytes::new(bytes.to_vec()),
        ),
        DataWrite::GenerationTime(slot, time) => (
            u16::from(0xce + slot.occurrence()),
            SecretBytes::new(time.to_be_bytes().to_vec()),
        ),
    };
    let mut c = command(0xda, (tag >> 8) as u8, tag as u8, bytes, false, false);
    c.continuation = Continuation::None;
    Ok(c)
}
fn key_request(request: &Request) -> Option<(Slot, Option<Algorithm>)> {
    match request {
        Request::ReadPublicKey(slot) | Request::GenerateKey(slot) => Some((*slot, None)),
        Request::ImportKey {
            slot, algorithm, ..
        } => Some((*slot, Some(*algorithm))),
        Request::Sign(a, _) => Some((Slot::Signature, Some(*a))),
        Request::Authenticate(a, _) => Some((Slot::Authentication, Some(*a))),
        Request::Decrypt(a, _) | Request::Derive(a, _) => Some((Slot::Decryption, Some(*a))),
        _ => None,
    }
}
fn target(request: &Request) -> Result<Option<LogicalCommand>, Error> {
    let c = match request {
        Request::ReadData(tag) => read(*tag),
        Request::ReadCertificate(_) => read(0x7f21),
        Request::WriteCertificate(_, bytes) => {
            if bytes.len() > 1152 {
                return Err(Error::new(ErrorKind::LimitExceeded));
            }
            command(0xda, 0x7f, 0x21, bytes.clone(), false, true)
        }
        Request::PinStatus(r) => empty(0x20, 0, r.wire()),
        Request::Logout(r) => empty(0x20, 0xff, r.wire()),
        Request::Verify => return Ok(None),
        Request::ChangePassword {
            reference,
            old,
            new,
        } => {
            if *reference == PasswordReference::Pw1Other {
                return Err(argument());
            }
            check_password(old, *reference == PasswordReference::Pw3)?;
            check_password(new, *reference == PasswordReference::Pw3)?;
            let mut bytes = old.0.clone();
            bytes.extend(new.0.as_bytes());
            command(0x24, 0, reference.wire(), bytes, false, false)
        }
        Request::UnblockWithAdmin(new) => command(0x2c, 2, 0x81, new.0.clone(), false, false),
        Request::UnblockWithCode { code, new } => {
            check_password(code, true)?;
            let mut bytes = code.0.clone();
            bytes.extend(new.0.as_bytes());
            command(0x2c, 0, 0x81, bytes, false, false)
        }
        Request::ResetRetries(retries) => {
            if retries.iter().any(|r| !(1..=15).contains(r)) {
                return Err(argument());
            }
            command(0xf2, 0, 0, SecretBytes::new(retries.to_vec()), false, false)
        }
        Request::WriteData(v) => write_data(v)?,
        Request::ReadPublicKey(slot) | Request::GenerateKey(slot) => command(
            0x47,
            if matches!(request, Request::GenerateKey(_)) {
                0x80
            } else {
                0x81
            },
            0,
            SecretBytes::new(vec![slot.wire(), 0]),
            false,
            false,
        ),
        Request::ImportKey {
            slot,
            algorithm,
            key,
        } => command(
            0xdb,
            0x3f,
            0xff,
            keys::import(*slot, *algorithm, key)?,
            false,
            true,
        ),
        Request::Sign(a, bytes) | Request::Authenticate(a, bytes) => {
            keys::sign_input(*a, bytes.as_bytes())?;
            if matches!(request, Request::Sign(..)) {
                command(0x2a, 0x9e, 0x9a, bytes.clone(), false, false)
            } else {
                command(0x88, 0, 0, bytes.clone(), false, false)
            }
        }
        Request::Decrypt(a, bytes) => {
            keys::attributes(Slot::Decryption, *a)?;
            if canokey_key::rsa_len(*a) != Some(bytes.len()) {
                return Err(argument());
            }
            let mut data = SecretBytes::new(vec![0]);
            data.extend(bytes.as_bytes());
            command(0x2a, 0x80, 0x86, data, false, true)
        }
        Request::Derive(a, peer) => {
            command(0x2a, 0x80, 0x86, keys::derive_input(*a, peer)?, false, true)
        }
        Request::Terminate => empty(0xe6, 0, 0),
        Request::Activate => empty(0x44, 0, 0),
    };
    Ok(Some(c))
}
#[derive(Clone, Copy)]
enum Stage {
    Select,
    Metadata,
    Authenticate(PasswordReference),
    Acknowledge,
    Target,
}
/// Construct an OpenPGP operation for pinned firmware 3.1.0, owning every input.
///
/// SELECT happens once. Key operations read 6E/73 algorithm attributes before
/// explicit password verification and the target, so stale caller algorithms fail
/// without attempting a password or mutation. Certificate SELECT DATA happens after
/// authentication, immediately before GET/PUT. No constructor hashes a message,
/// generates timestamps, changes algorithm attributes implicitly, or replays mutations.
///
/// # Errors
/// Invalid credentials/inputs, missing or wrong Access, unsupported algorithms,
/// capability uncertainty and known encoding limits fail before execution. Runtime
/// failures retain raw status and credential reference. OpenPGP VERIFY 6982 means
/// authentication failure without a reported retry count. Cancel/drop perform no I/O.
pub fn operation(
    profile: &DeviceProfile,
    request: Request,
    access: Option<Access>,
    options: OperationOptions,
) -> Result<Operation<Outcome>, Error> {
    profile.capability(Capability::OpenPgp).require()?;
    use PasswordReference::*;
    let required = match request {
        Request::WriteCertificate(..)
        | Request::UnblockWithAdmin(_)
        | Request::ResetRetries(_)
        | Request::WriteData(_)
        | Request::GenerateKey(_)
        | Request::ImportKey { .. } => Some(Pw3),
        Request::Sign(..) => Some(Pw1Sign),
        Request::Authenticate(..) | Request::Decrypt(..) | Request::Derive(..) => Some(Pw1Other),
        _ => None,
    };
    if required.is_some() && access.as_ref().map(|a| a.reference) != required {
        return Err(Error::new(ErrorKind::SecurityStatusNotSatisfied));
    }
    if matches!(request, Request::Verify) && access.is_none() {
        return Err(argument());
    }
    if matches!(
        request,
        Request::PinStatus(_)
            | Request::Logout(_)
            | Request::ChangePassword { .. }
            | Request::UnblockWithCode { .. }
            | Request::Activate
    ) && access.is_some()
    {
        return Err(argument());
    }
    if matches!(request, Request::Terminate) && access.as_ref().is_some_and(|a| a.reference != Pw3)
    {
        return Err(argument());
    }
    let target = target(&request)?;
    let mut queue = VecDeque::new();
    queue.push_back((select(), Stage::Select));
    if key_request(&request).is_some() {
        queue.push_back((read(0x6e), Stage::Metadata));
    }
    if let Some(access) = access {
        check_password(&access.password, access.reference == Pw3)?;
        queue.push_back((
            command(
                0x20,
                0,
                access.reference.wire(),
                access.password.0,
                false,
                false,
            ),
            Stage::Authenticate(access.reference),
        ));
    }
    if let Request::ReadCertificate(slot) | Request::WriteCertificate(slot, _) = request {
        queue.push_back((select_certificate(slot), Stage::Acknowledge));
    }
    if let Some(target) = target {
        queue.push_back((target, Stage::Target));
    }
    for (c, _) in &queue {
        validate_command(c, options)?;
    }
    // Streaming import's first fragment must contain the complete 4D + CRT prefix.
    if matches!(request, Request::ImportKey { .. }) && options.exchange.max_command_bytes < 14 {
        return Err(Error::new(ErrorKind::LimitExceeded));
    }
    Operation::from_machine(
        OpenPgp {
            queue,
            pending: None,
            request,
            algorithm: None,
            limit: options.limits.max_total_response_bytes,
        },
        options,
    )
}
struct OpenPgp {
    queue: VecDeque<(LogicalCommand, Stage)>,
    pending: Option<Stage>,
    request: Request,
    algorithm: Option<Algorithm>,
    limit: usize,
}
impl OpenPgp {
    fn reference(&self, stage: Stage) -> Option<SecretReference> {
        match stage {
            Stage::Authenticate(r) => Some(r.secret()),
            Stage::Target => match self.request {
                Request::ChangePassword { reference, .. } | Request::PinStatus(reference) => {
                    Some(reference.secret())
                }
                Request::UnblockWithCode { .. } => Some(SecretReference::ResetCode),
                _ => None,
            },
            _ => None,
        }
    }
    fn result(&self, response: ResponseData) -> Result<Outcome, Error> {
        let bytes = response.data;
        Ok(match &self.request {
            Request::ReadData(_) | Request::ReadCertificate(_) => Outcome::Bytes(bytes),
            Request::ReadPublicKey(_) | Request::GenerateKey(_) => {
                Outcome::PublicKey(PublicKey::from_tlv(
                    self.algorithm.ok_or_else(invalid)?,
                    keys::one(bytes.as_bytes(), 0x7f49)?,
                    self.limit,
                )?)
            }
            Request::Sign(a, _) | Request::Authenticate(a, _) => {
                if bytes.len() != keys::signature_len(*a) {
                    return Err(invalid());
                }
                Outcome::Signature {
                    algorithm: *a,
                    bytes,
                }
            }
            Request::Decrypt(a, _) => {
                if bytes.len()
                    > canokey_key::rsa_len(*a)
                        .ok_or_else(invalid)?
                        .saturating_sub(11)
                {
                    return Err(invalid());
                }
                Outcome::Bytes(bytes)
            }
            Request::Derive(a, _) => {
                if bytes.len() != canokey_key::curve_len(*a).unwrap_or(32)
                    || *a == Algorithm::X25519 && bytes.as_bytes().iter().all(|b| *b == 0)
                {
                    return Err(invalid());
                }
                Outcome::Bytes(bytes)
            }
            _ => {
                if !bytes.is_empty() {
                    return Err(invalid());
                }
                Outcome::Unit
            }
        })
    }
}
impl Machine<Outcome> for OpenPgp {
    fn next(&mut self, response: Option<ResponseData>) -> Result<Action<Outcome>, Error> {
        if let Some(response) = response {
            let stage = self.pending.take().ok_or_else(invalid)?;
            if matches!(stage, Stage::Target) && matches!(self.request, Request::PinStatus(_)) {
                if !response.data.is_empty() {
                    return Err(invalid());
                }
                let sw = response.status.raw();
                let status = match sw {
                    0x9000 => Some(PinStatus {
                        verified: true,
                        retries_remaining: None,
                        blocked: false,
                    }),
                    0x6983 => Some(PinStatus {
                        verified: false,
                        retries_remaining: None,
                        blocked: true,
                    }),
                    n if n & 0xfff0 == 0x63c0 => Some(PinStatus {
                        verified: false,
                        retries_remaining: Some((n & 15) as u8),
                        blocked: n == 0x63c0,
                    }),
                    _ => None,
                };
                if let Some(status) = status {
                    return Ok(Action::Done(Outcome::PinStatus(status)));
                }
            }
            if !response.status.is_success() {
                let reference = self.reference(stage);
                let phase = match stage {
                    Stage::Select => Phase::Select,
                    Stage::Authenticate(_) => Phase::Authentication,
                    _ if reference.is_some() => Phase::Authentication,
                    _ => Phase::Command,
                };
                let mut e = Error::status(response.status, phase, reference);
                if reference.is_some() && response.status.raw() == 0x6982 {
                    e.kind = ErrorKind::AuthenticationFailed;
                }
                return Err(e);
            }
            match stage {
                Stage::Metadata => {
                    let (slot, expected) = key_request(&self.request).ok_or_else(invalid)?;
                    let observed = keys::observed(response.data.as_bytes(), slot)?;
                    if expected.is_some_and(|a| a != observed) {
                        return Err(Error::new(ErrorKind::UnsupportedAlgorithm));
                    }
                    self.algorithm = Some(observed);
                }
                Stage::Target => return Ok(Action::Done(self.result(response)?)),
                _ if !response.data.is_empty() => return Err(invalid()),
                _ => {}
            }
        }
        if let Some((c, stage)) = self.queue.pop_front() {
            self.pending = Some(stage);
            Ok(Action::Command(c))
        } else {
            Ok(Action::Done(Outcome::Unit))
        }
    }
}
