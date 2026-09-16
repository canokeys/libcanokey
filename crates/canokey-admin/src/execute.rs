use crate::{command, types::invalid, *};
use canokey_compat::{AdminConfigurationLayout, Capability, DeviceProfile, Support};
use canokey_protocol::{
    operation::{
        engine::{Action, Machine},
        validate_command, Continuation, LogicalCommand, ResponseData,
    },
    ApduHeader, Error, ErrorKind, ExpectedLength, Operation, OperationOptions, Phase,
    SecretReference,
};
use std::collections::VecDeque;

fn cmd(ins: u8, p1: u8, p2: u8, data: Vec<u8>, read: bool) -> LogicalCommand {
    let mut c = LogicalCommand::new(
        ApduHeader::new(0, ins, p1, p2),
        data,
        if read {
            ExpectedLength::Exact(256)
        } else {
            ExpectedLength::Absent
        },
    );
    c.correct_le = read;
    if !read {
        c.continuation = Continuation::None;
    }
    c
}
fn read(ins: u8, p1: u8) -> LogicalCommand {
    cmd(ins, p1, 0, vec![], true)
}
fn write(ins: u8, p1: u8, p2: u8, data: Vec<u8>) -> LogicalCommand {
    cmd(ins, p1, p2, data, false)
}
fn argument() -> Error {
    Error::new(ErrorKind::InvalidArgument)
}
fn sm2_valid(s: Sm2Configuration) -> Result<(), Error> {
    if s.curve_id == 0
        || (1..=8).contains(&s.curve_id)
        || (256..=259).contains(&s.curve_id)
        || [-7, -8, -49].contains(&s.algorithm_id)
    {
        return Err(argument());
    }
    Ok(())
}

/// Build an Admin operation, copying only required profile evidence and owning inputs.
///
/// Baseline commands cover audited 1.3–3.1.0; individual requests and layouts
/// have independent capability gates. Old configuration/flash reads require PIN;
/// NFC reads require PIN on 3.0.0. Legacy SM2 identifier bytes stay uninterpreted.
/// SELECT
/// occurs once; `Some(pin)` causes explicit VERIFY before the request. Protected
/// requests require it. PinStatus and FactoryReset reject a PIN to prevent hidden
/// credential attempts. Patches are sequential, not atomic; confirmed writes remain
/// in `Operation::progress` after failure. Cancel/drop never roll back or send I/O.
/// Invalidate application credential/data caches whenever their mutation is exposed.
///
/// This is [`operation_with_access`] with `Some(pin)` mapped to [`Access::Pin`]
/// and `None` to [`Access::None`].
///
/// # Errors
/// Returns capability, invalid-input, missing-authentication or host-budget errors
/// before execution where inputs are known. Unknown feature bits forbid a feature
/// mask overwrite after the read; all patch values are checked before any write.
pub fn operation(
    profile: &DeviceProfile,
    request: Request,
    pin: Option<Pin>,
    options: OperationOptions,
) -> Result<Operation<Outcome>, Error> {
    operation_with_access(
        profile,
        request,
        pin.map(Access::Pin).unwrap_or(Access::None),
        options,
    )
}

/// Build an Admin operation with an explicit selection and authentication policy.
///
/// Validation, capability gates, patch semantics and progress reporting match
/// [`operation`]. [`Access::None`] and [`Access::Pin`] SELECT the Admin applet
/// once; `Pin` also sends explicit VERIFY before the request. [`Access::Existing`]
/// sends no SELECT and no implicit VERIFY: the caller asserts an already selected
/// Admin applet and any required prior verification. That assertion is an
/// execution policy, not proof of live authentication; firmware authorizes the
/// actual command and a protected request without prior verification fails with
/// 6982. Under `Existing`, PinStatus and ChangePin send only their own VERIFY
/// or CHANGE PIN command; `Request::VerifyPin` has no PIN of its own and is
/// rejected with `InvalidArgument`. PinStatus and FactoryReset reject
/// [`Access::Pin`] to prevent hidden credential attempts.
///
/// # Errors
/// Returns capability, invalid-input, missing-authentication or host-budget errors
/// before execution where inputs are known. Unknown feature bits forbid a feature
/// mask overwrite after the read; all patch values are checked before any write.
pub fn operation_with_access(
    profile: &DeviceProfile,
    request: Request,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<Outcome>, Error> {
    profile.capability(Capability::Admin).require()?;
    match &request {
        Request::CoreCommit | Request::AppletUsage | Request::ConfigureSm2(_) => profile
            .capability(Capability::AdminExtendedConfiguration)
            .require()?,
        Request::SetKeyboardInterface(_) => {
            profile.capability(Capability::AdminKeyboard).require()?
        }
        Request::SetKeyboardReturn(_) => profile
            .capability(Capability::AdminKeyboardReturn)
            .require()?,
        Request::SetLegacyPivExtensions(_) => profile
            .capability(Capability::AdminLegacyPivExtensions)
            .require()?,
        Request::SetLegacyOpenPgpTouch(_) => profile
            .capability(Capability::AdminLegacyOpenPgpTouch)
            .require()?,
        Request::WriteLegacySm2(_) => profile.capability(Capability::AdminLegacySm2).require()?,
        Request::ResetApplet(Applet::Ctap | Applet::Pass) => profile
            .capability(Capability::AdminCtapPassReset)
            .require()?,
        Request::NfcStatus | Request::SetNfc(_) => {
            profile.capability(Capability::AdminNfc).require()?
        }
        Request::Sm2Configuration => profile.capability(Capability::AdminSm2).require()?,
        Request::Configure(p) => {
            if p.ndef_enabled.is_some() || p.webusb_landing.is_some() {
                profile.capability(Capability::AdminNdefWebUsb).require()?;
            }
            if p.feature_mask != 0 {
                profile
                    .capability(Capability::AdminExtendedConfiguration)
                    .require()?;
            }
        }
        _ => {}
    }
    let protected_read = matches!(request, Request::Configuration | Request::FlashUsage)
        && profile
            .capability(Capability::AdminPublicConfiguration)
            .support
            == Support::Unsupported
        || matches!(request, Request::NfcStatus)
            && profile.capability(Capability::AdminPublicNfcStatus).support == Support::Unsupported;
    let protected = protected_read
        || matches!(
            request,
            Request::VerifyPin
                | Request::ChangePin(_)
                | Request::Configure(_)
                | Request::SetNfc(_)
                | Request::Sm2Configuration
                | Request::ConfigureSm2(_)
                | Request::ResetApplet(_)
                | Request::SetKeyboardInterface(_)
                | Request::SetKeyboardReturn(_)
                | Request::SetLegacyPivExtensions(_)
                | Request::SetLegacyOpenPgpTouch(_)
                | Request::WriteLegacySm2(_)
                | Request::SetKeyboardKeymap { .. }
                | Request::ClearKeyboardKeymap
                | Request::SetPassConfiguration(_)
                | Request::SetPassSlot { .. }
        );
    if protected && matches!(access, Access::None) {
        return Err(Error::new(ErrorKind::SecurityStatusNotSatisfied));
    }
    if matches!(access, Access::Existing) && matches!(request, Request::VerifyPin) {
        return Err(argument());
    }
    if matches!(access, Access::Pin(_))
        && matches!(request, Request::PinStatus | Request::FactoryReset)
    {
        return Err(argument());
    }
    if let Request::Configure(p) = &request {
        if p.feature_mask & !0x3f != 0 || p.feature_values & !p.feature_mask != 0 {
            return Err(argument());
        }
    }
    if let Request::ConfigureSm2(p) = &request {
        sm2_valid(Sm2Configuration {
            curve_id: p.curve_id.unwrap_or(9),
            algorithm_id: p.algorithm_id.unwrap_or(-54),
        })?;
    }
    let mut queue = VecDeque::new();
    if !matches!(access, Access::Existing) {
        queue.push_back((command::select(), Stage::Select));
    }
    if let Access::Pin(pin) = access {
        queue.push_back((
            write(0x20, 0, 0, pin.0.as_bytes().to_vec()),
            Stage::Authenticate,
        ));
    }
    let (target, stage) = match &request {
        Request::Firmware => (Some(command::firmware()), Stage::Read),
        Request::Model => (Some(command::model()), Stage::Read),
        Request::Serial => (Some(command::serial()), Stage::Read),
        Request::ChipId => (Some(read(0x32, 1)), Stage::Read),
        Request::CoreCommit => (Some(read(0x31, 2)), Stage::Read),
        Request::Configuration | Request::Configure(_) => (Some(read(0x42, 0)), Stage::Read),
        Request::FlashUsage => (Some(read(0x41, 0)), Stage::Read),
        Request::AppletUsage => (Some(read(0x41, 1)), Stage::Read),
        Request::KeyboardLayout => (Some(command::read_keyboard_layout()), Stage::Read),
        Request::KeyboardKeymap => (Some(command::read_keyboard_keymap()), Stage::Read),
        Request::SetKeyboardKeymap { layout_id, keymap } => (
            Some(command::write_keyboard_keymap(
                *layout_id,
                keymap.as_bytes(),
            )),
            Stage::Write(true),
        ),
        Request::ClearKeyboardKeymap => {
            (Some(command::clear_keyboard_keymap()), Stage::Write(true))
        }
        Request::PassConfiguration => (Some(command::pass_configuration()), Stage::Read),
        Request::SetPassConfiguration(data) => (
            Some(command::write_pass_configuration(data)),
            Stage::Write(true),
        ),
        Request::PassSlots => (Some(command::pass_configuration()), Stage::Read),
        Request::SetPassSlot { slot, config } => (
            Some(write(0x44, slot.wire(), 0, config.encode()?)),
            Stage::Write(true),
        ),
        Request::PinStatus => (Some(write(0x20, 0, 0, vec![])), Stage::Read),
        Request::VerifyPin => (None, Stage::Read),
        Request::ChangePin(p) => (
            Some(write(0x21, 0, 0, p.0.as_bytes().to_vec())),
            Stage::Write(false),
        ),
        Request::NfcStatus => (Some(read(0x14, 0)), Stage::Read),
        Request::SetNfc(on) => (
            Some(write(0x14, 1, u8::from(*on), vec![])),
            Stage::Write(true),
        ),
        Request::Sm2Configuration | Request::ConfigureSm2(_) => (Some(read(0x11, 0)), Stage::Read),
        Request::ResetApplet(a) => (
            Some(write(
                match a {
                    Applet::OpenPgp => 3,
                    Applet::Piv => 4,
                    Applet::Oath => 5,
                    Applet::Ndef => 7,
                    Applet::Ctap => 9,
                    Applet::Pass => 0x13,
                },
                0,
                0,
                vec![],
            )),
            Stage::Write(true),
        ),
        Request::SetKeyboardInterface(on) => (
            Some(write(0x40, 3, u8::from(*on), vec![])),
            Stage::Write(true),
        ),
        Request::SetKeyboardReturn(on) => (
            Some(write(0x40, 6, u8::from(*on), vec![])),
            Stage::Write(true),
        ),
        Request::SetLegacyPivExtensions(on) => (
            Some(write(0x40, 7, u8::from(*on), vec![])),
            Stage::Write(true),
        ),
        Request::SetLegacyOpenPgpTouch(t) => {
            let (index, value) = match t {
                LegacyOpenPgpTouch::Signature(on) => (0, u8::from(*on)),
                LegacyOpenPgpTouch::Decryption(on) => (1, u8::from(*on)),
                LegacyOpenPgpTouch::Authentication(on) => (2, u8::from(*on)),
                LegacyOpenPgpTouch::CacheSeconds(seconds) => (3, *seconds),
            };
            (Some(write(9, index, value, vec![])), Stage::Write(true))
        }
        Request::WriteLegacySm2(config) => (
            Some(write(0x12, 0, 0, config.raw().to_vec())),
            Stage::Write(true),
        ),
        Request::FactoryReset => (
            Some(write(0x50, 0, 0, b"RESET".to_vec())),
            Stage::Write(true),
        ),
    };
    if let Some(c) = target {
        queue.push_back((c, stage));
    }
    for (c, _) in &mut queue {
        if profile.legacy_explicit_le() && c.le == ExpectedLength::Absent {
            c.le = ExpectedLength::Exact(256);
        }
        validate_command(c, options)?;
    }
    // Dynamic patch commands have the same short, data-free shape (SM2: eight bytes).
    if matches!(request, Request::Configure(_) | Request::ConfigureSm2(_)) {
        validate_command(
            &write(
                0x12,
                0,
                0,
                if matches!(request, Request::ConfigureSm2(_)) {
                    vec![0; 8]
                } else {
                    vec![]
                },
            ),
            options,
        )?;
    }
    Operation::from_machine(
        Admin {
            queue,
            pending: None,
            request,
            options,
            profile: profile.clone(),
            outcome: Some(Outcome {
                value: Value::None,
                confirmed_writes: 0,
                reprobe_required: false,
            }),
        },
        options,
    )
}
#[derive(Clone, Copy)]
enum Stage {
    Select,
    Authenticate,
    Read,
    Write(bool),
}
struct Admin {
    queue: VecDeque<(LogicalCommand, Stage)>,
    pending: Option<Stage>,
    request: Request,
    options: OperationOptions,
    profile: DeviceProfile,
    outcome: Option<Outcome>,
}
impl Admin {
    fn outcome(&mut self) -> Result<&mut Outcome, Error> {
        self.outcome.as_mut().ok_or_else(invalid)
    }
    fn patch(&mut self, raw: &[u8], p: ConfigurationPatch) -> Result<(), Error> {
        if self.profile.admin_configuration_layout()? != AdminConfigurationLayout::Features {
            let config = LegacyConfiguration::parse(&self.profile, raw)?;
            let mut writes = Vec::new();
            for (value, old, ins, p1) in [
                (p.led_on, Some(config.led_on()), 0x40, 1),
                (p.ndef_read_only, Some(config.ndef_read_only()), 8, 0),
                (p.ndef_enabled, config.ndef_enabled(), 0x40, 4),
                (p.webusb_landing, config.webusb_landing(), 0x40, 5),
            ] {
                if let Some(value) = value {
                    let old = old.ok_or_else(|| Error::new(ErrorKind::UnsupportedFeature))?;
                    if value != old {
                        let mut c = if ins == 8 {
                            write(ins, u8::from(value), 0, vec![])
                        } else {
                            write(ins, p1, u8::from(value), vec![])
                        };
                        c.le = ExpectedLength::Exact(256);
                        validate_command(&c, self.options)?;
                        writes.push((c, Stage::Write(true)));
                    }
                }
            }
            self.queue.extend(writes);
            return Ok(());
        }
        let config = Configuration::parse(raw)?;
        let mut writes = Vec::new();
        for (value, old, ins, p1) in [
            (p.led_on, config.led_on(), 0x40, 1),
            (p.ndef_read_only, config.ndef_read_only(), 0x08, 0),
            (p.ndef_enabled, config.ndef_enabled(), 0x40, 4),
            (p.webusb_landing, config.webusb_landing(), 0x40, 5),
        ] {
            if let Some(value) = value.filter(|v| *v != old) {
                writes.push(if ins == 8 {
                    write(ins, u8::from(value), 0, vec![])
                } else {
                    write(ins, p1, u8::from(value), vec![])
                });
            }
        }
        let features = (config.features() & !p.feature_mask) | p.feature_values;
        if features != config.features() {
            if features & !0x3f != 0 {
                return Err(Error::new(ErrorKind::UnsupportedProtocolVersion));
            }
            writes.push(write(0x40, 6, features, vec![]));
        }
        for c in &writes {
            validate_command(c, self.options)?;
        }
        self.queue
            .extend(writes.into_iter().map(|c| (c, Stage::Write(true))));
        Ok(())
    }
    fn parse(&mut self, response: ResponseData) -> Result<(), Error> {
        let raw = response.data.as_bytes();
        if matches!(self.request, Request::PinStatus) {
            if !raw.is_empty() {
                return Err(invalid());
            }
            let status = response.status.raw();
            self.outcome()?.value = Value::PinStatus(match status {
                0x9000 => PinStatus {
                    verified: true,
                    retries_remaining: None,
                    blocked: false,
                },
                n if n & 0xfff0 == 0x63c0 => PinStatus {
                    verified: false,
                    retries_remaining: Some((n & 15) as u8),
                    blocked: n == 0x63c0,
                },
                0x6983 => PinStatus {
                    verified: false,
                    retries_remaining: None,
                    blocked: true,
                },
                _ => {
                    return Err(Error::status(
                        response.status,
                        Phase::Authentication,
                        Some(SecretReference::AdminPin),
                    ))
                }
            });
            return Ok(());
        }
        response.ensure_success(Phase::Command)?;
        let value = match &self.request {
            Request::Firmware
            | Request::Model
            | Request::Serial
            | Request::ChipId
            | Request::CoreCommit => {
                if matches!(self.request, Request::Serial) && raw.len() != 4 {
                    return Err(invalid());
                }
                Value::Bytes(raw.to_vec())
            }
            Request::Configuration => {
                if self.profile.admin_configuration_layout()? == AdminConfigurationLayout::Features
                {
                    Value::Configuration(Configuration::parse(raw)?)
                } else {
                    Value::LegacyConfiguration(LegacyConfiguration::parse(&self.profile, raw)?)
                }
            }
            Request::Configure(p) => {
                self.patch(raw, *p)?;
                Value::None
            }
            Request::Sm2Configuration => {
                if self.profile.capability(Capability::AdminLegacySm2).support == Support::Supported
                {
                    Value::LegacySm2Configuration(LegacySm2Configuration::from_bytes(raw)?)
                } else {
                    Value::Sm2Configuration(Sm2Configuration::parse(raw)?)
                }
            }
            Request::ConfigureSm2(p) => {
                let old = Sm2Configuration::parse(raw)?;
                let new = Sm2Configuration {
                    curve_id: p.curve_id.unwrap_or(old.curve_id),
                    algorithm_id: p.algorithm_id.unwrap_or(old.algorithm_id),
                };
                if new != old {
                    sm2_valid(new)?;
                    self.queue.push_back((
                        write(0x12, 0, 0, new.to_bytes().to_vec()),
                        Stage::Write(true),
                    ));
                }
                Value::None
            }
            Request::FlashUsage => {
                if raw.len() != 2 {
                    return Err(invalid());
                }
                Value::FlashUsage(FlashUsage {
                    used_kib: raw[0],
                    total_kib: raw[1],
                })
            }
            Request::AppletUsage => {
                if raw.len() != 48 {
                    return Err(invalid());
                }
                Value::AppletUsage(
                    raw.chunks_exact(6)
                        .map(|r| AppletUsage {
                            applet_id: r[0],
                            flags: r[1],
                            logical_bytes: u32::from_be_bytes([r[2], r[3], r[4], r[5]]),
                        })
                        .collect(),
                )
            }
            Request::KeyboardLayout => {
                if raw.len() != 1 {
                    return Err(invalid());
                }
                Value::KeyboardLayout(raw[0])
            }
            Request::KeyboardKeymap => Value::KeyboardKeymap(KeyboardKeymap::from_bytes(raw)?),
            Request::SetKeyboardKeymap { .. } | Request::ClearKeyboardKeymap => Value::None,
            Request::PassConfiguration => Value::Bytes(raw.to_vec()),
            Request::SetPassConfiguration(_) => Value::None,
            Request::PassSlots => Value::PassSlots(PassSlots::parse(raw)?),
            Request::SetPassSlot { .. } => Value::None,
            Request::NfcStatus => {
                if raw.len() != 1 || raw[0] > 1 {
                    return Err(invalid());
                }
                Value::NfcStatus(raw[0] != 0)
            }
            _ => return Err(invalid()),
        };
        self.outcome()?.value = value;
        Ok(())
    }
}
impl Machine<Outcome> for Admin {
    fn next(&mut self, response: Option<ResponseData>) -> Result<Action<Outcome>, Error> {
        if let Some(response) = response {
            match self.pending.take().ok_or_else(invalid)? {
                Stage::Read => self.parse(response)?,
                stage => {
                    let phase = match stage {
                        Stage::Select => Phase::Select,
                        Stage::Authenticate => Phase::Authentication,
                        _ => Phase::Command,
                    };
                    if !response.status.is_success() {
                        return Err(Error::status(
                            response.status,
                            phase,
                            matches!(stage, Stage::Authenticate)
                                .then_some(SecretReference::AdminPin),
                        ));
                    }
                    if !response.data.is_empty() {
                        return Err(invalid());
                    }
                    if matches!(stage, Stage::Write(_)) {
                        self.outcome()?.confirmed_writes += 1;
                    }
                }
            }
        }
        if let Some((c, stage)) = self.queue.pop_front() {
            if matches!(stage, Stage::Write(true)) {
                self.outcome()?.reprobe_required = true;
            }
            self.pending = Some(stage);
            Ok(Action::Command(c))
        } else {
            Ok(Action::Done(self.outcome.take().ok_or_else(invalid)?))
        }
    }
    fn progress(&self) -> Option<&Outcome> {
        self.outcome.as_ref()
    }
    fn take_progress(&mut self) -> Option<Outcome> {
        self.outcome.take()
    }
}
