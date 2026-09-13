use crate::{types::invalid, *};
use canokey_compat::{Capability, DeviceProfile, Support};
use canokey_protocol::{
    operation::{
        engine::{Action, Machine},
        validate_command, Continuation, LogicalCommand, ResponseData,
    },
    ApduHeader, Error, ErrorKind, ExpectedLength, Operation, OperationOptions, Phase, SecretBytes,
    SecretReference,
};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use zeroize::Zeroize;
type HmacSha1 = Hmac<Sha1>;
fn argument() -> Error {
    Error::new(ErrorKind::InvalidArgument)
}
fn field(output: &mut SecretBytes, tag: u8, bytes: &[u8]) {
    output.extend(&[tag, bytes.len() as u8]);
    output.extend(bytes);
}
fn mac(key: &AccessKey, message: &[u8]) -> HmacSha1 {
    // HMAC permits every key length; AccessKey additionally fixes the protocol width.
    let mut mac = HmacSha1::new_from_slice(key.0.as_bytes()).expect("HMAC accepts any key length");
    mac.update(message);
    mac
}
fn proof(key: &AccessKey, message: &[u8]) -> SecretBytes {
    let mut digest = mac(key, message).finalize().into_bytes();
    let output = SecretBytes::new(digest.to_vec());
    digest.as_mut_slice().zeroize();
    output
}

fn command(ins: u8, p1: u8, p2: u8, data: SecretBytes, le: ExpectedLength) -> LogicalCommand {
    let mut c = LogicalCommand::new(ApduHeader::new(0, ins, p1, p2), vec![], le);
    c.data = data;
    c.continuation = Continuation::None;
    c
}
fn select() -> LogicalCommand {
    command(
        0xa4,
        4,
        0,
        SecretBytes::new(vec![0xa0, 0, 0, 5, 0x27, 0x21, 1]),
        ExpectedLength::Absent,
    )
}
fn target(request: &Request, legacy: bool) -> Result<Option<LogicalCommand>, Error> {
    let mut data = SecretBytes::default();
    let mut paged = false;
    let (ins, p2, le) = match request {
        Request::Select | Request::Validate => return Ok(None),
        Request::List => {
            paged = true;
            (if legacy { 3 } else { 0xa1 }, 0, ExpectedLength::Exact(255))
        }
        Request::Put(c) => {
            if !(4..=8).contains(&c.digits)
                || !(1..=64).contains(&c.secret.len())
                || c.kind == Kind::Totp && c.initial_counter != 0
                || c.kind == Kind::Hotp && c.increasing
            {
                return Err(argument());
            }
            field(&mut data, 0x71, c.name.as_bytes());
            data.extend(&[
                0x73,
                (c.secret.len() + 2) as u8,
                c.kind.wire() | c.algorithm.wire(),
                c.digits,
            ]);
            data.extend(c.secret.as_bytes());
            let properties = u8::from(c.increasing) | (u8::from(c.require_touch) << 1);
            if properties != 0 {
                if legacy {
                    field(&mut data, 0x78, &[properties]);
                } else {
                    data.extend(&[0x78, properties]);
                }
            } // Property is tag/value, not TLV.
            if c.kind == Kind::Hotp {
                field(&mut data, 0x7a, &c.initial_counter.to_be_bytes());
            }
            (1, 0, ExpectedLength::Absent)
        }
        Request::Delete(name) => {
            field(&mut data, 0x71, name.as_bytes());
            (2, 0, ExpectedLength::Absent)
        }
        Request::Rename { old, new } => {
            field(&mut data, 0x71, old.as_bytes());
            field(&mut data, 0x71, new.as_bytes());
            (5, 0, ExpectedLength::Absent)
        }
        Request::Calculate {
            name,
            kind,
            challenge,
            format,
            ..
        } => {
            if (*kind == Kind::Totp) != challenge.is_some() {
                return Err(argument());
            }
            field(&mut data, 0x71, name.as_bytes());
            if let Some(challenge) = challenge {
                field(&mut data, 0x74, challenge);
            }
            (
                if legacy { 4 } else { 0xa2 },
                u8::from(!legacy && *format == Format::Truncated),
                ExpectedLength::Absent,
            )
        }
        Request::CalculateAll { challenge, format } => {
            field(&mut data, 0x74, challenge);
            paged = true;
            (
                if legacy { 5 } else { 0xa4 },
                u8::from(!legacy && *format == Format::Truncated),
                ExpectedLength::Exact(255),
            )
        }
        Request::SetCode { key, challenge } => {
            data.extend(&[0x73, 17, 1]);
            data.extend(key.0.as_bytes());
            field(&mut data, 0x74, challenge);
            field(&mut data, 0x75, proof(key, challenge).as_bytes());
            (3, 0, ExpectedLength::Absent)
        }
        Request::ClearCode => {
            field(&mut data, 0x73, &[]);
            (3, 0, ExpectedLength::Absent)
        }
    };
    let mut c = command(ins, 0, p2, data, le);
    if paged {
        c.continuation = Continuation::Oath {
            instruction: if legacy { 6 } else { 0xa5 },
            probe_after_success: true,
        };
    }
    Ok(Some(c))
}
// OATH uses one-byte tag/length fields, not BER's long-form length encoding.
fn fields(mut bytes: &[u8]) -> Result<Vec<(u8, &[u8])>, Error> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 2 || bytes.len() - 2 < bytes[1] as usize {
            return Err(invalid());
        }
        let end = 2 + bytes[1] as usize;
        result.push((bytes[0], &bytes[2..end]));
        bytes = &bytes[end..];
    }
    Ok(result)
}
fn selection(data: SecretBytes) -> Result<Selection, Error> {
    let mut version = None;
    let mut handle = None;
    let mut challenge = None;
    let mut algorithm = None;
    for (tag, bytes) in fields(data.as_bytes())? {
        match tag {
            0x79 if version.is_none() => version = Some(bytes.try_into().map_err(|_| invalid())?),
            0x71 if handle.is_none() => handle = Some(bytes.try_into().map_err(|_| invalid())?),
            0x74 if challenge.is_none() => {
                challenge = Some(bytes.try_into().map_err(|_| invalid())?)
            }
            0x7b if algorithm.is_none() && bytes.len() == 1 => algorithm = Some(bytes[0]),
            0x79 | 0x71 | 0x74 | 0x7b => return Err(invalid()),
            _ => {}
        }
    }
    if challenge.is_some() != algorithm.is_some() {
        return Err(invalid());
    }
    Ok(Selection {
        version: version.ok_or_else(invalid)?,
        handle: handle.ok_or_else(invalid)?,
        challenge,
        algorithm,
        raw: data,
    })
}
fn calculation(
    tag: u8,
    raw: &[u8],
    format: Format,
    algorithm: Option<Algorithm>,
    markers: bool,
) -> Result<Calculation, Error> {
    let digits = *raw.first().ok_or_else(invalid)?;
    if !(4..=8).contains(&digits) {
        return Err(invalid());
    }
    let bytes = &raw[1..];
    let code = match tag {
        0x76 if format == Format::Truncated && bytes.len() == 4 && bytes[0] & 0x80 == 0 => {
            Code::Truncated(SecretBytes::new(bytes.to_vec()))
        }
        0x75 if format == Format::Full
            && algorithm.map_or([20, 32, 64].contains(&bytes.len()), |a| {
                a.len() == bytes.len()
            }) =>
        {
            Code::Full(SecretBytes::new(bytes.to_vec()))
        }
        0x77 if markers && bytes.is_empty() => Code::Hotp,
        0x7c if markers && bytes.is_empty() => Code::TouchRequired,
        _ => return Err(invalid()),
    };
    Ok(Calculation {
        name: None,
        digits,
        code,
    })
}
fn result(request: &Request, data: SecretBytes, legacy: bool) -> Result<Outcome, Error> {
    match request {
        Request::List if legacy => {
            let f = fields(data.as_bytes())?;
            if f.len() % 2 != 0 {
                return Err(invalid());
            }
            let mut entries = Vec::new();
            for pair in f.chunks_exact(2) {
                if pair[0].0 != 0x71 || pair[1].0 != 0x75 || pair[1].1.len() != 2 {
                    return Err(invalid());
                }
                entries.push(Entry {
                    name: Name::from_bytes(pair[0].1).map_err(|_| invalid())?,
                    algorithm_type: pair[1].1[0],
                    digits: Some(pair[1].1[1]),
                });
            }
            Ok(Outcome::Entries(entries))
        }
        Request::List => Ok(Outcome::Entries(
            fields(data.as_bytes())?
                .into_iter()
                .map(|(tag, bytes)| {
                    if tag != 0x72 || bytes.len() < 2 {
                        return Err(invalid());
                    }
                    Ok(Entry {
                        name: Name::from_bytes(&bytes[1..]).map_err(|_| invalid())?,
                        algorithm_type: bytes[0],
                        digits: None,
                    })
                })
                .collect::<Result<_, _>>()?,
        )),
        Request::Calculate {
            format, algorithm, ..
        } => {
            let fields = fields(data.as_bytes())?;
            if fields.len() != 1 {
                return Err(invalid());
            }
            Ok(Outcome::Calculations(vec![calculation(
                fields[0].0,
                fields[0].1,
                *format,
                Some(*algorithm),
                false,
            )?]))
        }
        Request::CalculateAll { format, .. } => {
            let fields = fields(data.as_bytes())?;
            if fields.len() % 2 != 0 {
                return Err(invalid());
            }
            let mut output = Vec::new();
            for pair in fields.chunks_exact(2) {
                if pair[0].0 != 0x71 {
                    return Err(invalid());
                }
                let mut c = calculation(pair[1].0, pair[1].1, *format, None, true)?;
                c.name = Some(Name::from_bytes(pair[0].1).map_err(|_| invalid())?);
                output.push(c);
            }
            Ok(Outcome::Calculations(output))
        }
        _ if data.is_empty() => Ok(Outcome::Unit),
        _ => Err(invalid()),
    }
}
/// Construct an owned OATH operation using the actual firmware's command dialect.
/// Legacy 1.3 has no access code, rename, SHA-512 or full response. Full response
/// requests require 2.0; they are never silently downgraded. Before 2.0, rename does
/// not detect duplicate destinations. Before 3.0.1, firmware may omit records at
/// page boundaries; the host cannot establish completeness or safely replay codes.
///
/// `None` access is allowed only when SELECT reports no access challenge (except
/// Select itself). A supplied key requires a challenge, preventing silent fallback
/// to an unprotected applet. A new operation always selects and validates again.
/// SELECT rejects an access input rather than silently ignoring it. Calculations
/// never retry 6C; paged results use A5 even after nonempty 9000 and only accept
/// terminal empty 6985 after that speculative poll. A later-page failure discards
/// codes but cannot roll back counter/time-state changes.
///
/// # Errors
/// Capability, input and known command-budget errors fail before execution.
/// Authentication, malformed fields, unexpected status and cumulative budget
/// failures stop execution without replay; all credential buffers are owned.
pub fn operation(
    profile: &DeviceProfile,
    request: Request,
    access: Option<Access>,
    options: OperationOptions,
) -> Result<Operation<Outcome>, Error> {
    profile.capability(Capability::Oath).require()?;
    if matches!(request, Request::Select) && access.is_some()
        || matches!(request, Request::Validate) && access.is_none()
    {
        return Err(argument());
    }
    let legacy = profile.capability(Capability::OathLegacy).support == Support::Supported;
    if access.is_some()
        || matches!(
            request,
            Request::Validate
                | Request::SetCode { .. }
                | Request::ClearCode
                | Request::Rename { .. }
        )
        || matches!(&request, Request::Put(c) if c.algorithm == Algorithm::Sha512)
        || matches!(
            request,
            Request::Calculate {
                algorithm: Algorithm::Sha512,
                ..
            }
        )
    {
        profile.capability(Capability::OathModern).require()?;
    }
    if matches!(
        request,
        Request::Calculate {
            format: Format::Full,
            ..
        } | Request::CalculateAll {
            format: Format::Full,
            ..
        }
    ) {
        profile.capability(Capability::OathFullResponse).require()?;
    }
    let explicit_le = profile.legacy_explicit_le();
    let mut target = target(&request, legacy)?;
    if explicit_le {
        if let Some(c) = &mut target {
            c.le = ExpectedLength::Exact(256);
        }
    }
    let mut selection = select();
    if explicit_le {
        selection.le = ExpectedLength::Exact(256);
    }
    // The current firmware reserves up to 133 bytes for one full CalculateAll entry.
    if matches!(request, Request::List | Request::CalculateAll { .. }) {
        let minimum = if matches!(request, Request::List) {
            if legacy {
                70
            } else {
                67
            }
        } else {
            133
        };
        if options.exchange.max_response_bytes < minimum + 2 {
            return Err(Error::new(ErrorKind::LimitExceeded));
        }
        if let Some(c) = &mut target {
            c.le = ExpectedLength::Exact(255.min(options.exchange.max_response_bytes - 2) as u32);
        }
    }
    validate_command(&selection, options)?;
    if let Some(c) = &target {
        validate_command(c, options)?;
    }
    if access.is_some() {
        validate_command(
            &command(
                0xa3,
                0,
                0,
                SecretBytes::new(vec![0; 32]),
                ExpectedLength::Absent,
            ),
            options,
        )?;
    }
    Operation::from_machine(
        Oath {
            request,
            access,
            target,
            phase: 0,
            legacy,
            explicit_le,
            serial: profile.info().serial().and_then(|s| s.try_into().ok()),
        },
        options,
    )
}
struct Oath {
    request: Request,
    access: Option<Access>,
    target: Option<LogicalCommand>,
    phase: u8,
    legacy: bool,
    explicit_le: bool,
    serial: Option<[u8; 4]>,
}
impl Oath {
    fn target(&mut self) -> Result<Action<Outcome>, Error> {
        self.phase = 3;
        Ok(match self.target.take() {
            Some(c) => Action::Command(c),
            None => Action::Done(Outcome::Unit),
        })
    }
}
impl Machine<Outcome> for Oath {
    fn next(&mut self, response: Option<ResponseData>) -> Result<Action<Outcome>, Error> {
        if self.phase == 0 {
            self.phase = 1;
            let mut c = select();
            if self.explicit_le {
                c.le = ExpectedLength::Exact(256);
            }
            return Ok(Action::Command(c));
        }
        let response = response.ok_or_else(invalid)?;
        let phase = match self.phase {
            1 => Phase::Select,
            2 => Phase::Authentication,
            _ => Phase::Command,
        };
        if !response.status.is_success() {
            let mut e = Error::status(
                response.status,
                phase,
                (self.phase == 2).then_some(SecretReference::OathAccess),
            );
            if self.phase == 2 && response.status.raw() == 0x6a80 {
                e.kind = ErrorKind::AuthenticationFailed;
            }
            if self.phase == 3
                && response.status.raw() == 0x6984
                && matches!(
                    self.request,
                    Request::Delete(_) | Request::Rename { .. } | Request::Calculate { .. }
                )
            {
                e.kind = ErrorKind::NotFound;
            }
            return Err(e);
        }
        match self.phase {
            1 => {
                if self.legacy {
                    if !response.data.is_empty() {
                        return Err(invalid());
                    }
                    return if matches!(self.request, Request::Select) {
                        Ok(Action::Done(Outcome::LegacySelection {
                            serial: self.serial,
                        }))
                    } else {
                        self.target()
                    };
                }
                let selection = selection(response.data)?;
                if matches!(self.request, Request::Select) {
                    return Ok(Action::Done(Outcome::Selection(selection)));
                }
                match (&self.access, selection.challenge) {
                    (None, None) => self.target(),
                    (None, Some(_)) => {
                        Err(Error::new(ErrorKind::SecurityStatusNotSatisfied)
                            .at(Phase::Authentication))
                    }
                    (Some(_), None) => {
                        Err(Error::new(ErrorKind::ConditionsNotSatisfied).at(Phase::Authentication))
                    }
                    (Some(access), Some(challenge)) => {
                        if selection.algorithm != Some(1) {
                            return Err(Error::new(ErrorKind::UnsupportedAlgorithm));
                        }
                        let mut data = SecretBytes::default();
                        field(&mut data, 0x75, proof(&access.key, &challenge).as_bytes());
                        field(&mut data, 0x74, &access.challenge);
                        self.phase = 2;
                        Ok(Action::Command(command(
                            0xa3,
                            0,
                            0,
                            data,
                            if self.explicit_le {
                                ExpectedLength::Exact(256)
                            } else {
                                ExpectedLength::Absent
                            },
                        )))
                    }
                }
            }
            2 => {
                let fields = fields(response.data.as_bytes())?;
                if fields.len() != 1 || fields[0].0 != 0x75 || fields[0].1.len() != 20 {
                    return Err(invalid());
                }
                let access = self.access.take().ok_or_else(invalid)?;
                mac(&access.key, &access.challenge)
                    .verify_slice(fields[0].1)
                    .map_err(|_| {
                        Error::new(ErrorKind::DeviceAuthenticationFailed).at(Phase::Authentication)
                    })?;
                self.target()
            }
            3 => Ok(Action::Done(result(
                &self.request,
                response.data,
                self.legacy,
            )?)),
            _ => Err(invalid()),
        }
    }
}
