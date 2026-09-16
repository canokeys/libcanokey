//! authenticatorLargeBlobs (0x0C): the serialized large-blob array.
//!
//! The large-blob array is one byte string of at most
//! [`MAX_LARGE_BLOB_ARRAY_BYTES`] bytes on CanoKey (the getInfo
//! `maxSerializedLargeBlobArray` value), stored on the device across power
//! cycles. Reads need no authentication; writes are authenticated with a
//! pinUvAuthToken carrying the largeBlobWrite permission
//! ([`crate::pin::Permissions::LARGE_BLOB_WRITE`], 0x10) when the device has
//! a PIN set. Obtain tokens with
//! [`crate::pin::get_pin_token_with_permissions`].
//!
//! # Fragmentation
//!
//! The array is exchanged in fragments because a whole array does not fit in
//! one message. The high-level [`read_array`] and [`write_array`] factories
//! own the fragmentation: the caller drives one [`Operation`] and receives
//! the whole array (or completes the whole write). [`read_chunk`] is the
//! single-shot read for callers implementing their own resume logic.
//!
//! The host-side fragment size is the conservative
//! [`DEFAULT_MAX_FRAGMENT_LENGTH`], clamped by the channel: reads never ask
//! for more than fits one physical response under
//! `options.exchange.max_response_bytes`, and writes never exceed
//! `options.limits.max_input_bytes` per message. The firmware's own
//! `MAX_FRAGMENT_LENGTH` (`MAX_CTAP_BUFSIZE - 64`) is platform-dependent but
//! always covers 1024 on CanoKey; a `get` above it fails with
//! CTAP1_ERR_INVALID_LENGTH (0x03).
//!
//! # Firmware semantics (verified against `ctap_large_blobs` and
//! `parse_large_blobs`)
//!
//! - Reads: `offset` greater than the stored size is CTAP1_ERR_INVALID_
//!   PARAMETER (0x02); reads clamp to the available bytes, and `offset` equal
//!   to the size yields an empty substring. Sending pinUvAuthParam or
//!   pinUvAuthProtocol with `get` is a parse error (0x02), so reads never
//!   carry them.
//! - Writes: fragments arrive at increasing offsets. The first fragment
//!   (offset 0) must carry `length`, the total expected size; it is rejected
//!   without it (0x02), below 17 (0x02), or above 4096 (0x18
//!   LARGE_BLOB_STORAGE_FULL). A later fragment carrying `length`, or any
//!   fragment at an offset other than the firmware-tracked next offset,
//!   fails (0x02 and CTAP1_ERR_INVALID_SEQ 0x04 respectively). Each fragment
//!   is committed to a temporary file; when the accumulated size reaches
//!   `length` the firmware verifies the 16-byte truncated SHA-256 integrity
//!   trailer (mismatch: 0x3D INTEGRITY_FAILURE) and atomically renames the
//!   temporary file over the array.
//! - Write authentication: `pinUvAuthParam = authenticate(protocol, M)` with
//!   `M = 0xFF * 32 || h'0C00' || uint32LittleEndian(offset) ||
//!   SHA-256(fragment)` — exactly 70 bytes, matching the firmware's `buf`
//!   construction in `ctap_large_blobs`. Each fragment's MAC covers its own
//!   offset and its own fragment hash. When the device has a PIN, a write
//!   without pinUvAuthParam fails with 0x36 PUAT_REQUIRED; without a PIN no
//!   authentication is required (pass `None`) and any keys 5/6 present are
//!   ignored.
//!
//! The serialized large-blob array the caller passes to [`write_array`] is
//! `contents || LEFT(SHA-256(contents), 16)`: the final 16 bytes are the
//! integrity trailer the firmware verifies at commit. This module transports
//! the array verbatim; constructing or parsing its contents is the caller's.
//!
//! This module is available with the default `clientpin` feature, which
//! provides [`PinToken`].

use crate::cbor::{self, Value};
use crate::pin::PinToken;
use crate::status::CtapStatus;
use crate::{command, invalid, select_then, typed, PinUvAuthProtocol};
use canokey_protocol::operation::engine::{Action, Machine};
use canokey_protocol::operation::{validate_command, ResponseData};
use canokey_protocol::{Error, ErrorKind, Operation, OperationOptions, Phase};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;

const COMMAND_LARGE_BLOBS: u8 = 0x0c;

/// Request key: get (uint, number of bytes to read).
const REQ_GET: u64 = 0x01;
/// Request key: set (bytes, the fragment to append).
const REQ_SET: u64 = 0x02;
/// Request key: offset (uint, required).
const REQ_OFFSET: u64 = 0x03;
/// Request key: length (uint, total array size; first fragment only).
const REQ_LENGTH: u64 = 0x04;
/// Request key: pinUvAuthParam (bytes).
const REQ_PIN_UV_AUTH_PARAM: u64 = 0x05;
/// Request key: pinUvAuthProtocol (uint).
const REQ_PIN_UV_AUTH_PROTOCOL: u64 = 0x06;
/// Response key: config (bytes, the substring read).
const RESP_CONFIG: i64 = 0x01;

/// Maximum serialized large-blob array size on CanoKey: the getInfo
/// `maxSerializedLargeBlobArray` value and the firmware's
/// `LARGE_BLOB_SIZE_LIMIT`. Host-side bound for the whole array.
pub const MAX_LARGE_BLOB_ARRAY_BYTES: usize = 4096;

/// Minimum serialized large-blob array size: one content byte plus the
/// 16-byte integrity trailer. The firmware rejects a smaller `length` with
/// CTAP1_ERR_INVALID_PARAMETER (0x02); the factory rejects it before any I/O.
pub const MIN_LARGE_BLOB_ARRAY_BYTES: usize = 17;

/// Conservative host-side cap on one large-blob fragment. The firmware's
/// `MAX_FRAGMENT_LENGTH` is `MAX_CTAP_BUFSIZE - 64` (platform-dependent);
/// 1024 stays below it on CanoKey. Read fragments are further clamped to fit
/// one physical response and write fragments to fit
/// `options.limits.max_input_bytes`.
pub const DEFAULT_MAX_FRAGMENT_LENGTH: usize = 1024;

/// Generous response-side margin for a read fragment: SW (2), the CTAP
/// status byte (1), the one-entry map head (2) and the byte-string head
/// (up to 3), plus slack.
const READ_RESPONSE_OVERHEAD: usize = 16;
/// Generous message-side margin for a write fragment: the command byte, map
/// head, key and byte-string head for `set`, the `offset`/`length` entries
/// and the pinUvAuthParam/pinUvAuthProtocol entries.
const WRITE_MESSAGE_OVERHEAD: usize = 64;

fn invalid_argument() -> Error {
    Error::new(ErrorKind::InvalidArgument)
}
fn uint(value: u64) -> Value {
    Value::Unsigned(value)
}

/// Split the reassembled CTAP response into its status byte and payload.
fn split_status(response: &ResponseData) -> Result<(CtapStatus, &[u8]), Error> {
    response.ensure_success(Phase::Command)?;
    let (&status, payload) = response
        .data
        .as_bytes()
        .split_first()
        .ok_or_else(|| Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing))?;
    Ok((CtapStatus::from_raw(status), payload))
}

/// Build a `get` message: `0x0C` followed by `{1: length, 3: offset}`.
fn get_message(offset: u64, length: u64) -> Result<Vec<u8>, Error> {
    let mut message = vec![COMMAND_LARGE_BLOBS];
    message.extend_from_slice(&cbor::encode(&Value::Map(vec![
        (uint(REQ_GET), uint(length)),
        (uint(REQ_OFFSET), uint(offset)),
    ]))?);
    Ok(message)
}

/// Build a `set` message: `0x0C` followed by `{2: fragment, 3: offset,
/// 4?: length, 5?: pinUvAuthParam, 6?: pinUvAuthProtocol}`.
///
/// `total` is the array's total size and is only sent on the first fragment
/// (offset 0). The MAC input is `0xFF * 32 || h'0C00' ||
/// uint32LittleEndian(offset) || SHA-256(fragment)` — the exact 70-byte
/// layout the firmware verifies in `ctap_large_blobs`.
fn set_message(
    fragment: &[u8],
    offset: u64,
    total: Option<u64>,
    token: Option<(&PinToken, PinUvAuthProtocol)>,
) -> Result<Vec<u8>, Error> {
    let mut entries = vec![
        (uint(REQ_SET), Value::Bytes(fragment.to_vec())),
        (uint(REQ_OFFSET), uint(offset)),
    ];
    if let Some(total) = total {
        entries.push((uint(REQ_LENGTH), uint(total)));
    }
    if let Some((token, protocol)) = token {
        let mut mac_input = vec![0xffu8; 32];
        mac_input.push(COMMAND_LARGE_BLOBS);
        mac_input.push(0x00);
        mac_input.extend_from_slice(
            &u32::try_from(offset)
                .map_err(|_| invalid_argument())?
                .to_le_bytes(),
        );
        mac_input.extend_from_slice(&Sha256::digest(fragment));
        let auth = token.authenticate(protocol, &mac_input);
        entries.push((
            uint(REQ_PIN_UV_AUTH_PARAM),
            Value::Bytes(auth.as_bytes().to_vec()),
        ));
        entries.push((
            uint(REQ_PIN_UV_AUTH_PROTOCOL),
            uint(u64::from(protocol.to_u8())),
        ));
    }
    let mut message = vec![COMMAND_LARGE_BLOBS];
    message.extend_from_slice(&cbor::encode(&Value::Map(entries))?);
    Ok(message)
}

/// Parse a `get` response payload: the map's config (key 1) byte string.
fn parse_config(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let value = cbor::parse(bytes)?;
    Ok(value
        .map_get_int(RESP_CONFIG)
        .ok_or_else(invalid)?
        .as_bytes()
        .ok_or_else(invalid)?
        .to_vec())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Select,
    Exchange,
}

/// The state machine behind [`read_array`]: SELECT, then `get` fragments of
/// `chunk` bytes at increasing offsets until a short or empty fragment.
struct ReadArray {
    stage: Stage,
    chunk: u64,
    offset: u64,
    /// Remaining read commands within the operation's exchange budget.
    remaining_reads: usize,
    buffer: Vec<u8>,
}
impl ReadArray {
    fn read_command(&self) -> Result<Action<Vec<u8>>, Error> {
        Ok(Action::Command(command::msg(&get_message(
            self.offset,
            self.chunk,
        )?)))
    }
}
impl Machine<Vec<u8>> for ReadArray {
    fn next(&mut self, response: Option<ResponseData>) -> Result<Action<Vec<u8>>, Error> {
        match self.stage {
            Stage::Select => match response {
                None => Ok(Action::Command(command::select())),
                Some(response) => {
                    response.ensure_success(Phase::Select)?;
                    self.stage = Stage::Exchange;
                    self.read_command()
                }
            },
            Stage::Exchange => {
                let response = response.ok_or_else(|| Error::new(ErrorKind::ProtocolViolation))?;
                let (status, payload) = split_status(&response)?;
                if let Some(error) = status.into_error(Phase::Command) {
                    return Err(error);
                }
                let bytes = parse_config(payload)?;
                if bytes.len() as u64 > self.chunk {
                    // The authenticator must never return more than requested.
                    return Err(invalid());
                }
                if self.buffer.len() + bytes.len() > MAX_LARGE_BLOB_ARRAY_BYTES {
                    return Err(Error::new(ErrorKind::LimitExceeded).at(Phase::Parsing));
                }
                self.buffer.extend_from_slice(&bytes);
                if (bytes.len() as u64) < self.chunk {
                    // A short or empty substring ends the array.
                    return Ok(Action::Done(std::mem::take(&mut self.buffer)));
                }
                if self.remaining_reads == 0 {
                    return Err(Error::new(ErrorKind::LimitExceeded).at(Phase::Parsing));
                }
                self.remaining_reads -= 1;
                self.offset += self.chunk;
                self.read_command()
            }
        }
    }
}

/// The state machine behind [`write_array`]: SELECT, then every prebuilt
/// `set` fragment message in order; each response must be empty.
struct WriteArray {
    stage: Stage,
    messages: VecDeque<Vec<u8>>,
}
impl WriteArray {
    fn next_fragment(&mut self) -> Result<Action<()>, Error> {
        match self.messages.pop_front() {
            Some(message) => Ok(Action::Command(command::msg(&message))),
            None => Ok(Action::Done(())),
        }
    }
}
impl Machine<()> for WriteArray {
    fn next(&mut self, response: Option<ResponseData>) -> Result<Action<()>, Error> {
        match self.stage {
            Stage::Select => match response {
                None => Ok(Action::Command(command::select())),
                Some(response) => {
                    response.ensure_success(Phase::Select)?;
                    self.stage = Stage::Exchange;
                    self.next_fragment()
                }
            },
            Stage::Exchange => {
                let response = response.ok_or_else(|| Error::new(ErrorKind::ProtocolViolation))?;
                let (status, payload) = split_status(&response)?;
                if let Some(error) = status.into_error(Phase::Command) {
                    return Err(error);
                }
                // A successful set returns an empty payload.
                if !payload.is_empty() {
                    return Err(invalid());
                }
                self.next_fragment()
            }
        }
    }
}

/// Read the entire serialized large-blob array: repeated `get` fragments.
///
/// Wire format per fragment: `0x0C` followed by `{1: chunk, 3: offset}`;
/// each response is `{1: config}` with the substring at `offset`. The
/// fragment size is [`DEFAULT_MAX_FRAGMENT_LENGTH`] clamped so one fragment
/// fits a single physical response under `options.exchange.max_response_bytes`.
/// The loop ends at the first short or empty fragment (the firmware clamps
/// reads at the end of the stored array, and `offset` equal to the stored
/// size yields an empty substring). Reads need no authentication and have no
/// card-side effects.
///
/// The accumulated array is bounded by [`MAX_LARGE_BLOB_ARRAY_BYTES`] and the
/// read count by the operation's exchange budget; an authenticator that
/// keeps returning full fragments fails as [`ErrorKind::LimitExceeded`]
/// instead of looping unbounded.
///
/// # Errors
/// Invalid options fail before any I/O. A non-success CTAP status is
/// classified in the Command phase with the raw byte retained (for example
/// 0x02 INVALID_PARAMETER when `offset` exceeds the stored size maps to
/// [`ErrorKind::UnexpectedStatusWord`]). A response that is not a map with a
/// byte string at key 1, or that returns more bytes than requested, fails as
/// [`ErrorKind::InvalidResponse`] in [`Phase::Parsing`].
///
/// # Example
///
/// ```
/// use canokey_ctap::largeblob::read_array;
/// use canokey_protocol::{OperationOptions, Step};
/// let mut op = read_array(OperationOptions::default())?;
/// assert_eq!(op.start()?, Step::Exchange);
/// assert_eq!(op.command()?.as_bytes(),
///     &[0x00, 0xa4, 0x04, 0x00, 0x08, 0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01]);
/// assert_eq!(op.advance(&[0x90, 0x00])?, Step::Exchange);
/// // First fragment request: get 242 bytes at offset 0 (default options).
/// assert_eq!(op.command()?.as_bytes(),
///     &[0x80, 0x10, 0x00, 0x00, 0x07, 0x0c, 0xa2, 0x01, 0x18, 0xf2, 0x03, 0x00]);
/// // The authenticator answers with an empty substring: nothing is stored.
/// assert_eq!(op.advance(&[0x00, 0xa1, 0x01, 0x40, 0x90, 0x00])?, Step::Done);
/// assert!(op.take_result()?.is_empty());
/// # Ok::<(), canokey_protocol::Error>(())
/// ```
pub fn read_array(options: OperationOptions) -> Result<Operation<Vec<u8>>, Error> {
    let options = options.validate()?;
    let chunk = DEFAULT_MAX_FRAGMENT_LENGTH.min(
        options
            .exchange
            .max_response_bytes
            .saturating_sub(READ_RESPONSE_OVERHEAD),
    );
    if chunk == 0 {
        return Err(Error::new(ErrorKind::LimitExceeded));
    }
    let message = get_message(0, chunk as u64)?;
    if message.len() > options.limits.max_input_bytes {
        return Err(Error::new(ErrorKind::LimitExceeded));
    }
    // Later reads only grow the offset's encoding; validate the worst case.
    let last = get_message(
        MAX_LARGE_BLOB_ARRAY_BYTES as u64 + chunk as u64,
        chunk as u64,
    )?;
    for message in [&message, &last] {
        validate_command(&command::msg(message), options)?;
    }
    validate_command(&command::select(), options)?;
    Operation::from_machine(
        ReadArray {
            stage: Stage::Select,
            chunk: chunk as u64,
            offset: 0,
            // SELECT consumes one exchange of the budget.
            remaining_reads: options.limits.max_exchanges.saturating_sub(1),
            buffer: Vec::new(),
        },
        options,
    )
}

/// Read one fragment of the serialized large-blob array: a single `get`.
///
/// Wire format: `0x0C` followed by `{1: length, 3: offset}`; the response is
/// `{1: config}` with the substring at `offset`. The firmware clamps the
/// substring to the available bytes, so a short result marks the end of the
/// array; an `offset` equal to the stored size yields an empty substring,
/// and a greater one fails with 0x02 INVALID_PARAMETER
/// ([`ErrorKind::UnexpectedStatusWord`]). This is the building block for
/// callers implementing their own resume logic; [`read_array`] reads the
/// whole array in one operation.
///
/// # Errors
/// A zero `length` or a `length` above [`DEFAULT_MAX_FRAGMENT_LENGTH`] fails
/// as [`ErrorKind::InvalidArgument`] before any I/O (a larger request risks
/// the firmware's platform-dependent `MAX_FRAGMENT_LENGTH`, which rejects it
/// with 0x03 INVALID_LENGTH). Response failures follow [`read_array`].
pub fn read_chunk(
    offset: u64,
    length: usize,
    options: OperationOptions,
) -> Result<Operation<Vec<u8>>, Error> {
    if length == 0 || length > DEFAULT_MAX_FRAGMENT_LENGTH {
        return Err(invalid_argument());
    }
    let message = get_message(offset, length as u64)?;
    select_then(&message, options, |response| typed(response, parse_config))
}

/// Replace the serialized large-blob array: `set` fragments at increasing
/// offsets, committed when the accumulated size reaches the announced total.
///
/// `data` is the complete serialized large-blob array, `contents ||
/// LEFT(SHA-256(contents), 16)`; it must be
/// [`MIN_LARGE_BLOB_ARRAY_BYTES`]..=[`MAX_LARGE_BLOB_ARRAY_BYTES`] bytes. The
/// library splits it into fragments of at most [`DEFAULT_MAX_FRAGMENT_LENGTH`]
/// (clamped to fit `options.limits.max_input_bytes`), sends the first
/// fragment (offset 0) with `length` = `data.len()`, and appends the rest in
/// order inside a single operation. Each fragment's pinUvAuthParam covers its
/// own offset and fragment hash: `authenticate(0xFF * 32 || h'0C00' ||
/// uint32LittleEndian(offset) || SHA-256(fragment))`, matching the firmware's
/// verification in `ctap_large_blobs`.
///
/// `token` must carry the largeBlobWrite permission
/// ([`crate::pin::Permissions::LARGE_BLOB_WRITE`]); obtain it with
/// [`crate::pin::get_pin_token_with_permissions`]. A device without a PIN
/// requires no authentication: pass `None` and keys 5/6 are omitted (the
/// firmware ignores them when no PIN is set). On a device with a PIN, an
/// unauthenticated write fails with 0x36 PUAT_REQUIRED
/// ([`ErrorKind::SecurityStatusNotSatisfied`]).
///
/// **This replaces the stored large-blob array.** Until the accumulated size
/// reaches `length` the firmware holds fragments in a temporary file; only
/// the final fragment commits, after verifying the 16-byte integrity trailer
/// (mismatch: 0x3D INTEGRITY_FAILURE). A wrong offset sequence fails with
/// CTAP1_ERR_INVALID_SEQ (0x04). Cancel/drop mid-write leaves the previous
/// array untouched and the temporary file pending.
///
/// # Errors
/// A `data` length outside
/// [`MIN_LARGE_BLOB_ARRAY_BYTES`]..=[`MAX_LARGE_BLOB_ARRAY_BYTES`] fails as
/// [`ErrorKind::InvalidArgument`] before any I/O; a fragment that cannot fit
/// `options.limits.max_input_bytes` or a fragment count beyond the exchange
/// budget fails as [`ErrorKind::LimitExceeded`]. A non-success CTAP status is
/// classified in the Command phase with the raw byte retained (0x33
/// PIN_AUTH_INVALID maps to [`ErrorKind::AuthenticationFailed`], 0x18
/// LARGE_BLOB_STORAGE_FULL to [`ErrorKind::LimitExceeded`]). A non-empty
/// successful payload is [`ErrorKind::InvalidResponse`] in [`Phase::Parsing`].
pub fn write_array(
    data: &[u8],
    token: Option<(&PinToken, PinUvAuthProtocol)>,
    options: OperationOptions,
) -> Result<Operation<()>, Error> {
    if !(MIN_LARGE_BLOB_ARRAY_BYTES..=MAX_LARGE_BLOB_ARRAY_BYTES).contains(&data.len()) {
        return Err(invalid_argument());
    }
    let options = options.validate()?;
    let fragment = DEFAULT_MAX_FRAGMENT_LENGTH.min(
        options
            .limits
            .max_input_bytes
            .saturating_sub(WRITE_MESSAGE_OVERHEAD),
    );
    if fragment == 0 {
        return Err(Error::new(ErrorKind::LimitExceeded));
    }
    let total = data.len() as u64;
    let mut messages = VecDeque::new();
    let mut offset = 0u64;
    for chunk in data.chunks(fragment) {
        // Only the first fragment (offset 0) carries the total length.
        let first = if offset == 0 { Some(total) } else { None };
        let message = set_message(chunk, offset, first, token)?;
        if message.len() > options.limits.max_input_bytes {
            return Err(Error::new(ErrorKind::LimitExceeded));
        }
        validate_command(&command::msg(&message), options)?;
        messages.push_back(message);
        offset += chunk.len() as u64;
    }
    // SELECT consumes one exchange of the budget.
    if messages.len() > options.limits.max_exchanges.saturating_sub(1) {
        return Err(Error::new(ErrorKind::LimitExceeded));
    }
    validate_command(&command::select(), options)?;
    Operation::from_machine(
        WriteArray {
            stage: Stage::Select,
            messages,
        },
        options,
    )
}
