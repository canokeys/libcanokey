//! Read and replace the NDEF message stored on a CanoKey.
//!
//! The NDEF applet (AID `D2 76 00 00 85 01 01`) stores one NDEF message in a
//! Type 4 Tag style data file: bytes `[0..2)` hold the big-endian message
//! length (NLEN), followed by NLEN message bytes. Factories in this crate
//! select the applet, read the 15-byte capability container (CC, file ID
//! `0xE103`) and read or replace the message in the NDEF data file selected
//! by the ID the CC advertises (Type 4 Tag: the CC declares the file), using
//! explicit offset chunks of at most 240 bytes, so no APDU chaining or
//! extended length support is required. The crate performs no I/O itself.
//!
//! Most applications should depend on the `canokey` facade crate, which
//! re-exports this API as `canokey::ndef` alongside device probing and the
//! other applets. Depend on `canokey-ndef` directly only when you need NDEF
//! access without the rest of the facade.
//!
//! These factories are profile-free: no NDEF behaviour is known to vary across
//! firmware versions, so no `DeviceProfile` or compat capability is consulted.
//! A failed applet SELECT reports 0x6A82 as [`ErrorKind::UnsupportedDevice`],
//! which covers devices where the NDEF applet is disabled or absent.
//!
//! # Quick start: read an NDEF message
//!
//! The example below drives a read against an offline transcript; on real
//! hardware, send each command APDU over your own transport and advance with
//! the complete response including the status word.
//!
//! ```
//! use canokey_ndef::read_message;
//! use canokey_protocol::Step;
//! let mut op = read_message(Default::default())?;
//! assert_eq!(op.start()?, Step::Exchange);
//! assert_eq!(
//!     op.command()?.as_bytes(),
//!     &[0x00, 0xa4, 0x04, 0x00, 0x07, 0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01]
//! );
//! // SELECT applet and SELECT CC succeed; the CC advertises NDEF file 0x0001
//! // with a writable 1024-byte file.
//! op.advance(&[0x90, 0x00])?;
//! op.advance(&[0x90, 0x00])?;
//! op.advance(&[
//!     0x00, 0x0f, 0x20, 0x00, 0xff, 0x00, 0xff, 0x04, 0x06, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00,
//!     0x90, 0x00,
//! ])?;
//! // SELECT NDEF data file succeeds; NLEN is zero, so no message bytes follow.
//! op.advance(&[0x90, 0x00])?;
//! assert_eq!(op.advance(&[0x00, 0x00, 0x90, 0x00])?, Step::Done);
//! assert!(op.take_result()?.is_empty());
//! # Ok::<(), canokey_protocol::Error>(())
//! ```
//!
//! # Status word mapping
//!
//! 0x6A82 maps to [`ErrorKind::UnsupportedDevice`] only for the initial applet
//! SELECT ([`Phase::Select`]) and to [`ErrorKind::NotFound`] for the CC/NDEF
//! file selects; 0x6982 maps to [`ErrorKind::SecurityStatusNotSatisfied`]
//! (the read-only write check, also applied client-side from the CC) and
//! 0x6985 to [`ErrorKind::ConditionsNotSatisfied`]
//! (for example UPDATE BINARY without a selected data file). Unmapped status
//! words remain [`ErrorKind::UnexpectedStatusWord`] with the raw status.
//!
//! # Semantics you must know
//!
//! - Writes are crash-consistent: [`write_message`] reads the CC first and
//!   fails before any UPDATE when the CC marks the file read-only or
//!   advertises a maximum below the message length. It then writes a zero
//!   NLEN, the message chunks, and the real NLEN. A crash or connection loss
//!   mid-write therefore leaves the file with NLEN zero (no message) instead
//!   of a stale length pointing at a partially updated message.
//! - The caller drives every returned [`Operation`] and owns all transport
//!   I/O: start the operation, send each command APDU, and advance with the
//!   complete response. Command/result getters never send commands, and
//!   cancellation or drop never sends further commands.
//!
//! See `docs/design/api-design.md` in the repository for the full ownership
//! and execution contracts.
#![deny(missing_docs)]
#![forbid(unsafe_code)]

use canokey_protocol::operation::engine::{Action, Machine};
use canokey_protocol::operation::{validate_command, LogicalCommand, ResponseData};
use canokey_protocol::{
    ApduHeader, Error, ErrorKind, ExpectedLength, Operation, OperationOptions, Phase, SecretBytes,
};
use std::fmt;

/// NDEF applet application identifier, selected by DF name.
const NDEF_AID: [u8; 7] = [0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01];
/// Capability container file identifier inside the NDEF applet.
const CC_FILE_ID: u16 = 0xe103;
/// Capability container length in bytes; firmware bounds CC reads to this.
const CC_LEN: usize = 15;
/// Largest READ/UPDATE BINARY chunk, keeping every APDU within short encoding.
const CHUNK: usize = 240;
/// Hard firmware maximum for one NDEF message, excluding the two NLEN bytes.
pub const MAX_MESSAGE_LENGTH: usize = 1022;

/// Parsed NDEF capability container (CC) limits.
///
/// The CC is 15 bytes: CCLEN, mapping version, MLe/MLc, then the NDEF file
/// control TLV whose value carries the NDEF file ID, the maximum file size
/// and the read/write access bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NdefCapability {
    /// NDEF data file identifier advertised by the CC file control TLV, used
    /// for the NDEF file SELECT (Type 4 Tag: the CC declares the file).
    pub file_id: u16,
    /// Largest storable message in bytes, excluding the two NLEN bytes: the
    /// CC maximum file size minus two, clamped to [`MAX_MESSAGE_LENGTH`].
    pub max_message_length: usize,
    /// Whether the CC write-access byte is nonzero, meaning the device
    /// rejects UPDATE BINARY on the NDEF data file with 0x6982.
    pub read_only: bool,
}

/// An owned NDEF message read from the device.
///
/// The bytes are the raw message without the two NLEN length bytes. They are
/// held in a zeroizing buffer and redacted from `Debug` output.
#[derive(Clone)]
pub struct NdefMessage(SecretBytes);
impl NdefMessage {
    /// Borrow the raw NDEF message bytes, excluding the two NLEN bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
    /// Return the message length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Return whether the message is empty (the device reported NLEN zero).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
impl fmt::Debug for NdefMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NdefMessage([REDACTED])")
    }
}

/// Build SELECT by DF name for the NDEF applet.
fn select_applet() -> LogicalCommand {
    LogicalCommand::new(
        ApduHeader::new(0x00, 0xa4, 0x04, 0x00),
        NDEF_AID.to_vec(),
        ExpectedLength::Absent,
    )
}
/// Build SELECT by two-byte big-endian file ID inside the NDEF applet.
fn select_file(file_id: u16) -> LogicalCommand {
    LogicalCommand::new(
        ApduHeader::new(0x00, 0xa4, 0x00, 0x0c),
        file_id.to_be_bytes().to_vec(),
        ExpectedLength::Absent,
    )
}
/// Build READ BINARY at a big-endian P1/P2 offset with a short Le.
fn read_binary(offset: u16, length: usize) -> LogicalCommand {
    LogicalCommand::new(
        ApduHeader::new(0x00, 0xb0, (offset >> 8) as u8, offset as u8),
        vec![],
        ExpectedLength::Exact(length as u32),
    )
}
/// Build UPDATE BINARY at a big-endian P1/P2 offset with owned chunk data.
fn update_binary(offset: u16, data: &[u8]) -> LogicalCommand {
    LogicalCommand::new(
        ApduHeader::new(0x00, 0xd6, (offset >> 8) as u8, offset as u8),
        data.to_vec(),
        ExpectedLength::Absent,
    )
}

/// Parse the 15-byte capability container into validated limits.
///
/// # Errors
/// Returns [`ErrorKind::InvalidResponse`] at [`Phase::Parsing`] unless the
/// data is exactly 15 bytes, contains the 04/06 NDEF file control TLV
/// marker at bytes 7..9, and declares a maximum file size of at least two.
fn parse_cc(data: &[u8]) -> Result<NdefCapability, Error> {
    let invalid = || Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing);
    if data.len() != CC_LEN || data[7] != 0x04 || data[8] != 0x06 {
        return Err(invalid());
    }
    let max_file_size = u16::from_be_bytes([data[11], data[12]]) as usize;
    if max_file_size < 2 {
        return Err(invalid());
    }
    Ok(NdefCapability {
        file_id: u16::from_be_bytes([data[9], data[10]]),
        max_message_length: (max_file_size - 2).min(MAX_MESSAGE_LENGTH),
        read_only: data[14] != 0,
    })
}

/// Largest read chunk fitting the exchange response budget (at least one).
fn read_chunk(options: &OperationOptions) -> usize {
    CHUNK.min(options.exchange.max_response_bytes - 2)
}
/// Largest write chunk fitting the exchange command budget.
fn write_chunk(options: &OperationOptions) -> Result<usize, Error> {
    let chunk = CHUNK.min(options.exchange.max_command_bytes.saturating_sub(6));
    if chunk == 0 {
        return Err(Error::new(ErrorKind::LimitExceeded));
    }
    Ok(chunk)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadStep {
    SelectApplet,
    SelectCc,
    ReadCc,
    SelectNdef,
    ReadNlen,
    Message,
}

struct CapabilityMachine {
    step: ReadStep,
}
impl CapabilityMachine {
    fn command(&self) -> Result<LogicalCommand, Error> {
        match self.step {
            ReadStep::SelectApplet => Ok(select_applet()),
            ReadStep::SelectCc => Ok(select_file(CC_FILE_ID)),
            ReadStep::ReadCc => Ok(read_binary(0, CC_LEN)),
            _ => Err(Error::new(ErrorKind::ProtocolViolation)),
        }
    }
}
impl Machine<NdefCapability> for CapabilityMachine {
    fn next(&mut self, response: Option<ResponseData>) -> Result<Action<NdefCapability>, Error> {
        if let Some(response) = response {
            match self.step {
                ReadStep::SelectApplet => {
                    response.ensure_success(Phase::Select)?;
                    self.step = ReadStep::SelectCc;
                }
                ReadStep::SelectCc => {
                    response.ensure_success(Phase::Command)?;
                    self.step = ReadStep::ReadCc;
                }
                ReadStep::ReadCc => {
                    response.ensure_success(Phase::Command)?;
                    return Ok(Action::Done(parse_cc(response.data.as_bytes())?));
                }
                _ => return Err(Error::new(ErrorKind::ProtocolViolation)),
            }
        }
        Ok(Action::Command(self.command()?))
    }
}

struct ReadMachine {
    step: ReadStep,
    chunk: usize,
    file_id: u16,
    max_message: usize,
    offset: usize,
    remaining: usize,
    bytes: SecretBytes,
}
impl ReadMachine {
    fn command(&self) -> Result<LogicalCommand, Error> {
        match self.step {
            ReadStep::SelectApplet => Ok(select_applet()),
            ReadStep::SelectCc => Ok(select_file(CC_FILE_ID)),
            ReadStep::ReadCc => Ok(read_binary(0, CC_LEN)),
            ReadStep::SelectNdef => Ok(select_file(self.file_id)),
            ReadStep::ReadNlen => Ok(read_binary(0, 2)),
            ReadStep::Message => Ok(read_binary(
                self.offset as u16,
                self.remaining.min(self.chunk),
            )),
        }
    }
}
impl Machine<NdefMessage> for ReadMachine {
    fn next(&mut self, response: Option<ResponseData>) -> Result<Action<NdefMessage>, Error> {
        if let Some(response) = response {
            match self.step {
                ReadStep::SelectApplet => {
                    response.ensure_success(Phase::Select)?;
                    self.step = ReadStep::SelectCc;
                }
                ReadStep::SelectCc => {
                    response.ensure_success(Phase::Command)?;
                    self.step = ReadStep::ReadCc;
                }
                ReadStep::ReadCc => {
                    response.ensure_success(Phase::Command)?;
                    let capability = parse_cc(response.data.as_bytes())?;
                    self.file_id = capability.file_id;
                    self.max_message = capability.max_message_length;
                    self.step = ReadStep::SelectNdef;
                }
                ReadStep::SelectNdef => {
                    response.ensure_success(Phase::Command)?;
                    self.step = ReadStep::ReadNlen;
                }
                ReadStep::ReadNlen => {
                    response.ensure_success(Phase::Command)?;
                    let nlen: [u8; 2] =
                        response.data.as_bytes().try_into().map_err(|_| {
                            Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing)
                        })?;
                    let nlen = u16::from_be_bytes(nlen) as usize;
                    if nlen > self.max_message {
                        // The card claims a message beyond its own CC limit;
                        // do not allocate or read further.
                        return Err(Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing));
                    }
                    self.remaining = nlen;
                    self.offset = 2;
                    self.step = ReadStep::Message;
                    if nlen == 0 {
                        return Ok(Action::Done(NdefMessage(SecretBytes::default())));
                    }
                }
                ReadStep::Message => {
                    response.ensure_success(Phase::Command)?;
                    let want = self.remaining.min(self.chunk);
                    if response.data.len() != want {
                        return Err(Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing));
                    }
                    self.bytes.extend(response.data.as_bytes());
                    self.remaining -= want;
                    self.offset += want;
                    if self.remaining == 0 {
                        return Ok(Action::Done(NdefMessage(std::mem::take(&mut self.bytes))));
                    }
                }
            }
        }
        Ok(Action::Command(self.command()?))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WriteStep {
    SelectApplet,
    SelectCc,
    ReadCc,
    SelectNdef,
    ZeroLength,
    Message,
    FinalLength,
}

struct WriteMachine {
    step: WriteStep,
    /// Owned caller message copy; zeroized on drop like the read-side result.
    message: SecretBytes,
    chunk: usize,
    file_id: u16,
    offset: usize,
}
impl WriteMachine {
    fn command(&self) -> LogicalCommand {
        match self.step {
            WriteStep::SelectApplet => select_applet(),
            WriteStep::SelectCc => select_file(CC_FILE_ID),
            WriteStep::ReadCc => read_binary(0, CC_LEN),
            WriteStep::SelectNdef => select_file(self.file_id),
            WriteStep::ZeroLength => update_binary(0, &[0, 0]),
            WriteStep::Message => {
                let take = (self.message.len() - self.offset).min(self.chunk);
                update_binary(
                    2 + self.offset as u16,
                    &self.message.as_bytes()[self.offset..self.offset + take],
                )
            }
            WriteStep::FinalLength => update_binary(0, &(self.message.len() as u16).to_be_bytes()),
        }
    }
}
impl Machine<()> for WriteMachine {
    fn next(&mut self, response: Option<ResponseData>) -> Result<Action<()>, Error> {
        if let Some(response) = response {
            match self.step {
                WriteStep::SelectApplet => {
                    response.ensure_success(Phase::Select)?;
                    self.step = WriteStep::SelectCc;
                }
                WriteStep::SelectCc => {
                    response.ensure_success(Phase::Command)?;
                    self.step = WriteStep::ReadCc;
                }
                WriteStep::ReadCc => {
                    response.ensure_success(Phase::Command)?;
                    let capability = parse_cc(response.data.as_bytes())?;
                    // Fail before any UPDATE: the firmware would answer the
                    // first UPDATE BINARY with 0x6982 on a read-only file.
                    if capability.read_only {
                        return Err(
                            Error::new(ErrorKind::SecurityStatusNotSatisfied).at(Phase::Command)
                        );
                    }
                    if self.message.len() > capability.max_message_length {
                        return Err(Error::new(ErrorKind::LimitExceeded).at(Phase::Command));
                    }
                    self.file_id = capability.file_id;
                    self.step = WriteStep::SelectNdef;
                }
                WriteStep::SelectNdef => {
                    response.ensure_success(Phase::Command)?;
                    self.step = WriteStep::ZeroLength;
                }
                WriteStep::ZeroLength => {
                    response.ensure_success(Phase::Command)?;
                    self.step = if self.message.is_empty() {
                        WriteStep::FinalLength
                    } else {
                        WriteStep::Message
                    };
                }
                WriteStep::Message => {
                    response.ensure_success(Phase::Command)?;
                    self.offset += (self.message.len() - self.offset).min(self.chunk);
                    if self.offset == self.message.len() {
                        self.step = WriteStep::FinalLength;
                    }
                }
                WriteStep::FinalLength => {
                    response.ensure_success(Phase::Command)?;
                    return Ok(Action::Done(()));
                }
            }
        }
        Ok(Action::Command(self.command()))
    }
}

/// Read the NDEF capability container: maximum message length and write access.
///
/// The operation selects the NDEF applet, selects the CC file and reads its
/// 15 bytes; no NDEF data file is touched. No device profile is required: no
/// NDEF variance is known across firmware versions, and a 0x6A82 applet
/// SELECT failure maps to [`ErrorKind::UnsupportedDevice`].
///
/// # Errors
/// Invalid options fail at construction; a CC read must fit the response and
/// exchange budgets before any I/O, otherwise [`ErrorKind::LimitExceeded`].
/// During execution, card status failures retain their phase and a malformed
/// CC returns [`ErrorKind::InvalidResponse`] at [`Phase::Parsing`].
pub fn read_capability(options: OperationOptions) -> Result<Operation<NdefCapability>, Error> {
    let options = options.validate()?;
    if options.limits.max_total_response_bytes < CC_LEN || options.limits.max_exchanges < 3 {
        return Err(Error::new(ErrorKind::LimitExceeded));
    }
    validate_command(&read_binary(0, CC_LEN), options)?;
    Operation::from_machine(
        CapabilityMachine {
            step: ReadStep::SelectApplet,
        },
        options,
    )
}

/// Read the complete NDEF message, chunking READ BINARY at 240 bytes or less.
///
/// The operation selects the NDEF applet, reads and validates the CC, reads
/// the two-byte NLEN, then reads the message from offset two in explicit
/// offset chunks. An NLEN of zero completes without further reads; an NLEN
/// above the CC maximum message length fails before any allocation or
/// message read. The result owns its bytes and is redacted from `Debug`.
///
/// # Errors
/// Invalid options fail at construction. A worst-case read (CC + NLEN +
/// [`MAX_MESSAGE_LENGTH`] bytes, with its chunk exchanges) must fit the
/// operation budgets before any I/O, otherwise [`ErrorKind::LimitExceeded`].
/// During execution, card status failures retain their phase; a malformed
/// CC, short NLEN, oversized NLEN or short message chunk returns
/// [`ErrorKind::InvalidResponse`] at [`Phase::Parsing`].
pub fn read_message(options: OperationOptions) -> Result<Operation<NdefMessage>, Error> {
    let options = options.validate()?;
    if options.limits.max_total_response_bytes < CC_LEN + 2 + MAX_MESSAGE_LENGTH {
        return Err(Error::new(ErrorKind::LimitExceeded));
    }
    let chunk = read_chunk(&options);
    let exchanges = 5 + MAX_MESSAGE_LENGTH.div_ceil(chunk);
    if options.limits.max_exchanges < exchanges {
        return Err(Error::new(ErrorKind::LimitExceeded));
    }
    validate_command(&read_binary(0, CC_LEN), options)?;
    Operation::from_machine(
        ReadMachine {
            step: ReadStep::SelectApplet,
            chunk,
            file_id: 0,
            max_message: MAX_MESSAGE_LENGTH,
            offset: 0,
            remaining: 0,
            bytes: SecretBytes::default(),
        },
        options,
    )
}

/// Replace the complete NDEF message, chunking UPDATE BINARY at 240 bytes or less.
///
/// The message is copied at construction (into a zeroizing buffer) and must
/// not exceed [`MAX_MESSAGE_LENGTH`] (the firmware hard maximum). The
/// operation selects the NDEF applet, reads and validates the CC, and fails
/// before any UPDATE when the CC marks the file read-only
/// ([`ErrorKind::SecurityStatusNotSatisfied`]) or advertises a maximum
/// message length below the message ([`ErrorKind::LimitExceeded`]). It then
/// selects the NDEF data file advertised by the CC, writes a zero NLEN first
/// so an interrupted write leaves no stale message, writes the message from
/// offset two in explicit offset chunks, and finally writes the real NLEN.
///
/// This mutates device state; an I/O failure mid-write may leave the message
/// cleared (NLEN zero) and must not be replayed automatically.
///
/// # Errors
/// A message longer than [`MAX_MESSAGE_LENGTH`] fails at construction with
/// [`ErrorKind::InvalidArgument`] before any I/O, as do invalid options and
/// exchange budgets too small for the known command sequence
/// ([`ErrorKind::LimitExceeded`]). Card status failures during execution
/// retain the Command phase.
pub fn write_message(message: &[u8], options: OperationOptions) -> Result<Operation<()>, Error> {
    let options = options.validate()?;
    if message.len() > MAX_MESSAGE_LENGTH {
        return Err(Error::new(ErrorKind::InvalidArgument));
    }
    let chunk = write_chunk(&options)?;
    // SELECT applet/CC/NDEF file, CC read, zero NLEN, message chunks, real NLEN.
    let exchanges = 6 + message.len().div_ceil(chunk);
    if options.limits.max_exchanges < exchanges || options.limits.max_total_response_bytes < CC_LEN
    {
        return Err(Error::new(ErrorKind::LimitExceeded));
    }
    validate_command(&read_binary(0, CC_LEN), options)?;
    validate_command(&update_binary(0, &[0, 0]), options)?;
    if !message.is_empty() {
        validate_command(
            &update_binary(2, &message[..message.len().min(chunk)]),
            options,
        )?;
    }
    Operation::from_machine(
        WriteMachine {
            step: WriteStep::SelectApplet,
            message: SecretBytes::new(message.to_vec()),
            chunk,
            file_id: 0,
            offset: 0,
        },
        options,
    )
}
