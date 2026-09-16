//! Caller-owned CTAP/FIDO2 ISO7816 transport envelope.
//!
//! This crate implements only the ISO 7816 envelope of the CTAP transport:
//! SELECT of the FIDO2 application by DF name, CTAP command wrapping with
//! `CLA 80 / INS 10`, 61xx response continuation via GET RESPONSE with class
//! byte 80, and status-word classification. CBOR encoding, CTAP2 subcommand
//! semantics and ClientPin remain on the host side: the caller supplies the
//! complete CTAP message (first byte the CTAP command, for example 0x01 for
//! authenticatorMakeCredential) and interprets the returned payload.
//!
//! # Wire format
//!
//! SELECT is always explicit: `00 A4 04 00 08 <FIDO2 AID>`, where the AID is
//! [`FIDO2_AID`] (`A0 00 00 06 47 2F 00 01`). A CTAP message is wrapped as
//! `80 10 00 00 <Lc> <message>` with no Le byte. Messages up to 255 bytes use
//! short Lc; longer messages use the extended three-byte Lc (`00 hi lo`) when
//! the caller's exchange options permit extended encoding, otherwise command
//! chaining with CLA bit 0x10. Responses arriving with a 61xx status are
//! followed by `80 C0 00 00 <SW2>` until a terminal status word.
//!
//! The response data of a successful exchange is one CTAP status byte (0x00
//! for CTAP1_ERR_SUCCESS) followed by the payload, concatenated across any
//! continuation fragments. See [`CtapResponse`].
//!
//! # Lifecycle
//!
//! Factories copy their inputs and own no connection or card state. Cancel or
//! drop never sends APDUs, rolls back card state, or reconnects; hold one
//! exclusive application connection from `start` until completion or failure.
//! Nothing is retried automatically.
//!
//! # Example: offline authenticatorGetInfo transcript
//!
//! ```
//! use canokey_ctap::transceive;
//! use canokey_protocol::{OperationOptions, Step};
//! let mut op = transceive(&[0x04], OperationOptions::default())?;
//! assert_eq!(op.start()?, Step::Exchange);
//! assert_eq!(op.command()?.as_bytes(),
//!     &[0x00, 0xa4, 0x04, 0x00, 0x08, 0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01]);
//! assert_eq!(op.advance(&[0x90, 0x00])?, Step::Exchange);
//! assert_eq!(op.command()?.as_bytes(), &[0x80, 0x10, 0x00, 0x00, 0x01, 0x04]);
//! assert_eq!(op.advance(&[0x00, 0x61, 0x02])?, Step::Exchange);
//! assert_eq!(op.command()?.as_bytes(), &[0x80, 0xc0, 0x00, 0x00, 0x02]);
//! assert_eq!(op.advance(&[0xa1, 0x01, 0x90, 0x00])?, Step::Done);
//! let response = op.take_result()?;
//! assert!(response.status().is_success());
//! assert_eq!(response.payload(), &[0xa1, 0x01]);
//! # Ok::<(), canokey_protocol::Error>(())
//! ```
//!
//! # Errors
//!
//! Invalid arguments (including empty messages), option budgets and input
//! limits fail before any I/O. During execution a 6A82 to SELECT maps to
//! [`ErrorKind::UnsupportedDevice`],
//! 6985 to ConditionsNotSatisfied, and 6D00 to UnsupportedFeature; other
//! status words are retained raw as UnexpectedStatusWord. Malformed responses
//! fail as InvalidResponse in the Parsing phase.
#![deny(missing_docs)]
#![forbid(unsafe_code)]

use canokey_protocol::operation::engine::{Action, Machine};
use canokey_protocol::operation::{Continuation, LogicalCommand, ResponseData};
use canokey_protocol::{
    ApduHeader, Error, ErrorKind, ExpectedLength, Operation, OperationOptions, Phase, SecretBytes,
};
use std::collections::VecDeque;
use std::fmt;

/// The FIDO2 application identifier (DF name): `A0 00 00 06 47 2F 00 01`.
pub const FIDO2_AID: [u8; 8] = [0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01];

/// One-byte CTAP status from the start of a successful CTAP response.
///
/// Other CTAP1_ERR/CTAP2_ERR codes are surfaced raw through [`Self::raw`];
/// interpreting them and any CBOR payload remains the host's responsibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtapStatus(u8);
impl CtapStatus {
    /// CTAP1_ERR_SUCCESS (0x00).
    pub const SUCCESS: Self = Self(0x00);
    /// Return whether this status is CTAP1_ERR_SUCCESS.
    pub fn is_success(self) -> bool {
        self == Self::SUCCESS
    }
    /// Return the raw status byte as sent by the authenticator.
    pub fn raw(self) -> u8 {
        self.0
    }
}

/// Owned CTAP response: the status byte and the payload that follows it.
///
/// The payload is retained in a protected, zeroizing buffer because it can
/// carry credential material. Debug is redacted; only [`Self::payload`]
/// exposes the bytes.
pub struct CtapResponse {
    status: CtapStatus,
    payload: SecretBytes,
}
impl CtapResponse {
    /// Return the CTAP status byte; a raw non-success code is not an error here.
    pub fn status(&self) -> CtapStatus {
        self.status
    }
    /// Borrow the payload after the status byte (CBOR for CTAP2 responses).
    /// Interpreting these bytes remains the caller's responsibility.
    pub fn payload(&self) -> &[u8] {
        self.payload.as_bytes()
    }
}
impl fmt::Debug for CtapResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CtapResponse")
            .field("status", &self.status)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

/// Raw CTAP logical-command builders.
///
/// Except for [`select`](command::select), these require the FIDO2 applet to
/// be selected already. They perform no status mapping or CBOR handling.
/// Prefer the crate-level factories for complete standalone operations.
pub mod command {
    use super::*;
    /// Build SELECT FIDO2 by DF name, without Le.
    ///
    /// The firmware also switches to FIDO implicitly on bare 80/10 APDUs, but
    /// this library always selects explicitly; the core owns SELECT.
    pub fn select() -> LogicalCommand {
        LogicalCommand::new(
            ApduHeader::new(0x00, 0xa4, 0x04, 0x00),
            FIDO2_AID.to_vec(),
            ExpectedLength::Absent,
        )
    }
    /// Wrap a complete CTAP message as CTAP_INS_MSG: `80 10 00 00 <Lc> <msg>`.
    ///
    /// The first message byte is the CTAP command. Chaining and extended Lc
    /// are permitted, continuation uses GET RESPONSE with class byte 80, and
    /// no Le is sent; the firmware has no wrong-Le (6Cxx) correction path.
    pub fn msg(message: &[u8]) -> LogicalCommand {
        let mut command = LogicalCommand::new(
            ApduHeader::new(0x80, 0x10, 0x00, 0x00),
            message.to_vec(),
            ExpectedLength::Absent,
        );
        command.allow_chaining = true;
        command.allow_extended = true;
        command.continuation = Continuation::Iso7816 { cla: 0x80 };
        command
    }
}

struct Request {
    command: LogicalCommand,
    phase: Phase,
}
type Parser<T> = Box<dyn FnOnce(ResponseData) -> Result<T, Error> + Send>;
struct Sequence<T> {
    pending: VecDeque<Request>,
    current: Option<Phase>,
    parse: Option<Parser<T>>,
}
impl<T> Machine<T> for Sequence<T> {
    fn next(&mut self, response: Option<ResponseData>) -> Result<Action<T>, Error> {
        if let Some(response) = response {
            if self.pending.is_empty() {
                let parse = self
                    .parse
                    .take()
                    .ok_or_else(|| Error::new(ErrorKind::OperationStateError))?;
                return Ok(Action::Done(parse(response)?));
            }
            let phase = self
                .current
                .ok_or_else(|| Error::new(ErrorKind::ProtocolViolation))?;
            if !response.status.is_success() {
                return Err(Error::status(response.status, phase, None));
            }
        }
        let request = self
            .pending
            .pop_front()
            .ok_or_else(|| Error::new(ErrorKind::ProtocolViolation))?;
        self.current = Some(request.phase);
        Ok(Action::Command(request.command))
    }
}

fn single<T: 'static>(
    command: LogicalCommand,
    phase: Phase,
    options: OperationOptions,
    parse: impl FnOnce(ResponseData) -> Result<T, Error> + Send + 'static,
) -> Result<Operation<T>, Error> {
    let options = options.validate()?;
    canokey_protocol::operation::validate_command(&command, options)?;
    Operation::from_machine(
        Sequence {
            pending: vec![Request { command, phase }].into(),
            current: None,
            parse: Some(Box::new(parse)),
        },
        options,
    )
}

fn checked_message(message: &[u8], options: OperationOptions) -> Result<(), Error> {
    if message.is_empty() {
        return Err(Error::new(ErrorKind::InvalidArgument));
    }
    if message.len() > options.limits.max_input_bytes {
        return Err(Error::new(ErrorKind::LimitExceeded));
    }
    Ok(())
}

fn parse_response(response: ResponseData) -> Result<CtapResponse, Error> {
    response.ensure_success(Phase::Command)?;
    let (&status, payload) = response
        .data
        .as_bytes()
        .split_first()
        .ok_or_else(|| Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing))?;
    Ok(CtapResponse {
        status: CtapStatus(status),
        payload: SecretBytes::new(payload.to_vec()),
    })
}

/// Select the FIDO2 applet, returning no result beyond successful selection.
///
/// This profile-free form emits only `00 A4 04 00 08 <FIDO2 AID>`; the caller
/// owns the selected context. Successful selection does not authenticate
/// anything and may invalidate other applet state on the card.
///
/// # Errors
/// Invalid options fail before I/O. A 6A82 response during selection maps to
/// [`ErrorKind::UnsupportedDevice`]; other status, transport and budget
/// failures are terminal and retained in the operation.
pub fn select_application(options: OperationOptions) -> Result<Operation<()>, Error> {
    single(command::select(), Phase::Select, options, |response| {
        response.ensure_success(Phase::Select)
    })
}

/// Send one CTAP message to an already selected FIDO2 applet.
///
/// This profile-free form emits a single `80 10 00 00` command without any
/// SELECT; the caller owns the selected context, as with PIV `*_selected`
/// factories. The message is the complete raw CTAP message whose first byte
/// is the CTAP command. Large responses are reassembled through 61xx/GET
/// RESPONSE with class byte 80. Cancel/drop sends nothing further.
///
/// # Errors
/// An empty message fails as [`ErrorKind::InvalidArgument`] before any I/O,
/// and a message longer than `options.limits.max_input_bytes` fails as
/// [`ErrorKind::LimitExceeded`]. During execution, 6985 maps to
/// ConditionsNotSatisfied, 6D00 to UnsupportedFeature, and other non-success
/// status words to their classified errors. A successful status word with an
/// empty response (no CTAP status byte) is InvalidResponse in the Parsing
/// phase. CBOR interpretation and non-success CTAP codes remain the caller's.
pub fn transceive_selected(
    message: &[u8],
    options: OperationOptions,
) -> Result<Operation<CtapResponse>, Error> {
    checked_message(message, options)?;
    single(
        command::msg(message),
        Phase::Command,
        options,
        parse_response,
    )
}

/// Select the FIDO2 applet and send one CTAP message within that selection.
///
/// The operation sends SELECT (Phase::Select, so 6A82 maps to
/// [`ErrorKind::UnsupportedDevice`]) followed by the wrapped CTAP command
/// (Phase::Command). Everything else matches [`transceive_selected`].
///
/// # Errors
/// See [`transceive_selected`] and [`select_application`].
pub fn transceive(
    message: &[u8],
    options: OperationOptions,
) -> Result<Operation<CtapResponse>, Error> {
    let options = options.validate()?;
    checked_message(message, options)?;
    let requests = vec![
        Request {
            command: command::select(),
            phase: Phase::Select,
        },
        Request {
            command: command::msg(message),
            phase: Phase::Command,
        },
    ];
    for request in &requests {
        canokey_protocol::operation::validate_command(&request.command, options)?;
    }
    Operation::from_machine(
        Sequence {
            pending: requests.into(),
            current: None,
            parse: Some(Box::new(parse_response)),
        },
        options,
    )
}
