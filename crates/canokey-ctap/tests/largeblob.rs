//! Golden transcript and failure-path tests for authenticatorLargeBlobs
//! (0x0C): fragmented reads, authenticated fragmented writes, and the
//! firmware's status-code paths.
//!
//! Writes are authenticated with a fixed pinUvAuthToken (plaintext
//! 0x10..=0x2F, minted through the clientPIN fixtures shared with
//! `client_pin.rs`), so every pinUvAuthParam is deterministic. The expected
//! HMAC-SHA-256 values (protocol V1, truncated to 16 bytes) were computed
//! with an independent implementation (Python stdlib `hmac`) on 2026-09-16,
//! over `0xFF * 32 || h'0C00' || uint32LittleEndian(offset) ||
//! SHA-256(fragment)` — the 70-byte layout the CanoKey firmware verifies in
//! `ctap_large_blobs`.
#![cfg(feature = "clientpin")]

use canokey_ctap::largeblob::{
    read_array, read_chunk, write_array, DEFAULT_MAX_FRAGMENT_LENGTH, MAX_LARGE_BLOB_ARRAY_BYTES,
};
use canokey_ctap::{get_key_agreement, get_pin_token, PinToken, PinUvAuthProtocol};
use canokey_protocol::{
    Error, ErrorKind, Operation, OperationLimits, OperationOptions, Phase, Step,
};

const SELECT: [u8; 13] = [
    0x00, 0xa4, 0x04, 0x00, 0x08, 0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01,
];

/// ClientPIN fixtures shared with `client_pin.rs` (ephemeral scalar
/// 0x01..=0x20, peer scalar 0xA0..=0xBF, PIN "1234").
const EPHEMERAL_SCALAR: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];
const PEER_KEY_AGREEMENT_PAYLOAD: &str = "a101a5010203381820012158200d0918a04198474605615b6df90fdcb34791fb3ecb822f4b26eb6e4fc4511b9d22582019b90c1b83c0c35cfbbb31ead32bb52ae33622f57e3cc1638097ce97f430baba";
const TOKEN_CT_V1: &str = "b98cc635132fa3ea8c191b7a4aa3e093ce926c35488221b4684fce766f3b14b0";
/// The decrypted token plaintext, 0x10..=0x2F; the HMAC key of every
/// pinUvAuthParam below.
const TOKEN_PLAINTEXT: [u8; 32] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];

/// The write payload: bytes 0x00..=0x63 (100 bytes), written as two 64/36
/// fragments when `max_input_bytes` clamps the fragment size to 64.
const WRITE_DATA: [u8; 100] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 0x61, 0x62, 0x63,
];
/// pinUvAuthParam (V1) of the first fragment: offset 0, length present.
const MAC_FRAGMENT_0: &str = "783e708130a5de3ec473749ae5ec0819";
/// pinUvAuthParam (V1) of the second fragment: offset 64, no length.
const MAC_FRAGMENT_1: &str = "39d71c8110da008e9d304e9065157675";

/// Decode a hex string, ignoring whitespace.
fn hex(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
        .collect()
}

/// Drive the mandatory SELECT and advance to the first CTAP command.
fn begin<T>(op: &mut Operation<T>) {
    assert_eq!(op.start().unwrap(), Step::Exchange);
    assert_eq!(op.command().unwrap().as_bytes(), &SELECT);
    assert_eq!(op.advance(&[0x90, 0x00]).unwrap(), Step::Exchange);
}

/// Assert the wrapped command bytes: `80 10 00 00 <Lc> <message>`.
fn assert_command(op: &Operation<impl Sized>, message: &[u8]) {
    let mut expected = vec![0x80, 0x10, 0x00, 0x00, message.len() as u8];
    expected.extend_from_slice(message);
    assert!(message.len() <= 255, "fixture must use short Lc");
    assert_eq!(op.command().unwrap().as_bytes(), &expected);
}

/// Advance with a successful CTAP response carrying `payload`.
fn advance_ok<T>(op: &mut Operation<T>, payload: &[u8]) -> Step {
    let mut reply = vec![0x00];
    reply.extend_from_slice(payload);
    reply.extend_from_slice(&[0x90, 0x00]);
    op.advance(&reply).unwrap()
}

/// Advance with a successful CTAP response that must fail parsing.
fn advance_bad<T>(op: &mut Operation<T>, payload: &[u8]) -> Error {
    let mut reply = vec![0x00];
    reply.extend_from_slice(payload);
    reply.extend_from_slice(&[0x90, 0x00]);
    op.advance(&reply).unwrap_err()
}

/// Mint the fixed V1 token (plaintext 0x10..=0x2F) through the clientPIN
/// fixture transcript.
fn token_v1() -> PinToken {
    let mut op = get_key_agreement(
        PinUvAuthProtocol::V1,
        &EPHEMERAL_SCALAR,
        OperationOptions::default(),
    )
    .unwrap();
    begin(&mut op);
    assert_eq!(
        advance_ok(&mut op, &hex(PEER_KEY_AGREEMENT_PAYLOAD)),
        Step::Done
    );
    let session = op.take_result().unwrap();
    let mut op = get_pin_token(&session, b"1234", None, OperationOptions::default()).unwrap();
    begin(&mut op);
    let ct = hex(TOKEN_CT_V1);
    // A 32-byte byte string needs the one-byte-length head (0x58 0x20).
    let mut payload = vec![0xa1, 0x02, 0x58, 0x20];
    payload.extend_from_slice(&ct);
    assert_eq!(advance_ok(&mut op, &payload), Step::Done);
    let token = op.take_result().unwrap();
    assert_eq!(token.token().as_bytes(), &TOKEN_PLAINTEXT);
    token
}

/// The read fragment size under default options: 258 - 16 overhead = 242.
const DEFAULT_READ_CHUNK: usize = 242;

/// Build a `get` response payload `{1: <bytes>}`.
fn config_payload(bytes: &[u8]) -> Vec<u8> {
    let mut payload = vec![0xa1, 0x01];
    match bytes.len() {
        0..=23 => payload.push(0x40 + bytes.len() as u8),
        24..=255 => payload.extend_from_slice(&[0x58, bytes.len() as u8]),
        _ => {
            payload.extend_from_slice(&[0x59, (bytes.len() >> 8) as u8, (bytes.len() & 0xff) as u8])
        }
    }
    payload.extend_from_slice(bytes);
    payload
}

/// Options that clamp write fragments to 64 bytes (`128 - 64` overhead).
fn clamped_options() -> OperationOptions {
    OperationOptions {
        limits: OperationLimits {
            max_input_bytes: 128,
            ..Default::default()
        },
        ..Default::default()
    }
}

// ---------------------------------------------------------------- read_chunk

#[test]
fn read_chunk_golden() {
    let mut op = read_chunk(0, 16, OperationOptions::default()).unwrap();
    begin(&mut op);
    assert_command(&op, &hex("0c a2 01 10 03 00"));
    let data: Vec<u8> = (0x20..0x30).collect();
    assert_eq!(advance_ok(&mut op, &config_payload(&data)), Step::Done);
    assert_eq!(op.take_result().unwrap(), data);
}

#[test]
fn read_chunk_at_offset_golden() {
    let mut op = read_chunk(300, 24, OperationOptions::default()).unwrap();
    begin(&mut op);
    // 300 = 0x19 0x012c; 24 = 0x18 0x18.
    assert_command(&op, &hex("0c a2 01 18 18 03 19 01 2c"));
    // offset equal to the stored size yields an empty substring.
    assert_eq!(advance_ok(&mut op, &config_payload(&[])), Step::Done);
    assert!(op.take_result().unwrap().is_empty());
}

#[test]
fn read_chunk_rejects_bad_length_before_io() {
    let error = read_chunk(0, 0, OperationOptions::default()).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidArgument);
    let error = read_chunk(
        0,
        DEFAULT_MAX_FRAGMENT_LENGTH + 1,
        OperationOptions::default(),
    )
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidArgument);
}

#[test]
fn read_chunk_invalid_parameter_keeps_raw_byte() {
    let mut op = read_chunk(9999, 16, OperationOptions::default()).unwrap();
    begin(&mut op);
    // Firmware: offset beyond the stored size -> CTAP1_ERR_INVALID_PARAMETER.
    // 0x02 is a CTAP1 code outside the CTAP2 classification table, so it is
    // retained raw as UnexpectedStatusWord.
    let error = op.advance(&[0x02, 0x90, 0x00]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::UnexpectedStatusWord);
    assert_eq!(error.phase, Phase::Command);
    assert_eq!(error.status_word.map(|sw| sw.raw()), Some(0x02));
}

#[test]
fn read_chunk_invalid_length_keeps_raw_byte() {
    let mut op = read_chunk(0, 1024, OperationOptions::default()).unwrap();
    begin(&mut op);
    // Firmware: get above maxFragmentLength -> CTAP1_ERR_INVALID_LENGTH (0x03).
    let error = op.advance(&[0x03, 0x90, 0x00]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::UnexpectedStatusWord);
    assert_eq!(error.phase, Phase::Command);
    assert_eq!(error.status_word.map(|sw| sw.raw()), Some(0x03));
}

#[test]
fn read_chunk_malformed_responses_are_invalid_response() {
    // Missing the config key (1).
    let mut op = read_chunk(0, 16, OperationOptions::default()).unwrap();
    begin(&mut op);
    let error = advance_bad(&mut op, &hex("a1 02 00"));
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert_eq!(error.phase, Phase::Parsing);
    // The config value is not a byte string.
    let mut op = read_chunk(0, 16, OperationOptions::default()).unwrap();
    begin(&mut op);
    let error = advance_bad(&mut op, &hex("a1 01 00"));
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    // The payload is not a map at all.
    let mut op = read_chunk(0, 16, OperationOptions::default()).unwrap();
    begin(&mut op);
    let error = advance_bad(&mut op, &hex("41 00"));
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
}

// ---------------------------------------------------------------- read_array

#[test]
fn read_array_multi_fragment_golden() {
    let mut op = read_array(OperationOptions::default()).unwrap();
    begin(&mut op);
    // Fragment size 242 (default clamp): get at offsets 0, 242, 484.
    assert_command(&op, &hex("0c a2 01 18 f2 03 00"));
    let data: Vec<u8> = (0..504u32).map(|i| (i % 251) as u8).collect();
    assert_eq!(
        advance_ok(&mut op, &config_payload(&data[..242])),
        Step::Exchange
    );
    assert_command(&op, &hex("0c a2 01 18 f2 03 18 f2"));
    assert_eq!(
        advance_ok(&mut op, &config_payload(&data[242..484])),
        Step::Exchange
    );
    assert_command(&op, &hex("0c a2 01 18 f2 03 19 01 e4"));
    // A short fragment ends the array.
    assert_eq!(
        advance_ok(&mut op, &config_payload(&data[484..])),
        Step::Done
    );
    assert_eq!(op.take_result().unwrap(), data);
}

#[test]
fn read_array_empty_first_fragment_is_empty_array() {
    let mut op = read_array(OperationOptions::default()).unwrap();
    begin(&mut op);
    assert_command(&op, &hex("0c a2 01 18 f2 03 00"));
    assert_eq!(advance_ok(&mut op, &config_payload(&[])), Step::Done);
    assert!(op.take_result().unwrap().is_empty());
}

#[test]
fn read_array_full_chunk_then_empty_terminates() {
    // The stored size is an exact multiple of the fragment size: the last
    // read lands on offset == size and returns an empty substring.
    let mut op = read_array(OperationOptions::default()).unwrap();
    begin(&mut op);
    let chunk = vec![0x5au8; DEFAULT_READ_CHUNK];
    assert_eq!(advance_ok(&mut op, &config_payload(&chunk)), Step::Exchange);
    assert_command(&op, &hex("0c a2 01 18 f2 03 18 f2"));
    assert_eq!(advance_ok(&mut op, &config_payload(&[])), Step::Done);
    assert_eq!(op.take_result().unwrap(), chunk);
}

#[test]
fn read_array_overlong_fragment_is_invalid_response() {
    let mut op = read_array(OperationOptions::default()).unwrap();
    begin(&mut op);
    // The authenticator returns one byte more than requested.
    let error = advance_bad(&mut op, &config_payload(&[0u8; DEFAULT_READ_CHUNK + 1]));
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert_eq!(error.phase, Phase::Parsing);
}

#[test]
fn read_array_runaway_hits_array_bound() {
    let mut op = read_array(OperationOptions::default()).unwrap();
    begin(&mut op);
    let chunk = vec![0x11u8; DEFAULT_READ_CHUNK];
    // Full fragments forever: 16 chunks accumulate 3872 bytes, the 17th
    // pushes the total past 4096.
    for _ in 0..16 {
        assert_eq!(advance_ok(&mut op, &config_payload(&chunk)), Step::Exchange);
    }
    let error = advance_bad(&mut op, &config_payload(&chunk));
    assert_eq!(error.kind, ErrorKind::LimitExceeded);
    assert_eq!(error.phase, Phase::Parsing);
    assert!(error.status_word.is_none());
}

#[test]
fn read_array_budget_exhausted_is_limit_exceeded() {
    let options = OperationOptions {
        limits: OperationLimits {
            // SELECT plus exactly three reads.
            max_exchanges: 4,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut op = read_array(options).unwrap();
    begin(&mut op);
    let chunk = vec![0x22u8; DEFAULT_READ_CHUNK];
    assert_eq!(advance_ok(&mut op, &config_payload(&chunk)), Step::Exchange);
    assert_eq!(advance_ok(&mut op, &config_payload(&chunk)), Step::Exchange);
    let error = advance_bad(&mut op, &config_payload(&chunk));
    assert_eq!(error.kind, ErrorKind::LimitExceeded);
}

// --------------------------------------------------------------- write_array

/// Build the expected `set` message bytes for a fragment of `WRITE_DATA`.
fn expected_set_message(offset: usize, total: Option<usize>, mac: Option<&str>) -> Vec<u8> {
    let end = (offset + 64).min(WRITE_DATA.len());
    let fragment = &WRITE_DATA[offset..end];
    let mut entries = vec![0xa2 + u8::from(total.is_some()) + u8::from(mac.is_some()) * 2];
    entries.push(0x02);
    entries.push(0x40 + 24); // 0x58: one-byte length head
    entries.push(fragment.len() as u8);
    entries.extend_from_slice(fragment);
    entries.push(0x03);
    match offset {
        0..=23 => entries.push(offset as u8),
        _ => entries.extend_from_slice(&[0x18, offset as u8]),
    }
    if let Some(total) = total {
        entries.push(0x04);
        entries.extend_from_slice(&[0x18, total as u8]);
    }
    if let Some(mac) = mac {
        entries.push(0x05);
        entries.push(0x50);
        entries.extend_from_slice(&hex(mac));
        entries.push(0x06);
        entries.push(0x01);
    }
    let mut message = vec![0x0c];
    message.extend_from_slice(&entries);
    message
}

#[test]
fn write_array_two_fragments_golden() {
    let token = token_v1();
    let mut op = write_array(
        &WRITE_DATA,
        Some((&token, PinUvAuthProtocol::V1)),
        clamped_options(),
    )
    .unwrap();
    begin(&mut op);
    // First fragment: 64 bytes at offset 0, carrying length = 100.
    assert_command(
        &op,
        &expected_set_message(0, Some(100), Some(MAC_FRAGMENT_0)),
    );
    assert_eq!(advance_ok(&mut op, &[]), Step::Exchange);
    // Second fragment: 36 bytes at offset 64, no length, its own MAC.
    assert_command(&op, &expected_set_message(64, None, Some(MAC_FRAGMENT_1)));
    assert_eq!(advance_ok(&mut op, &[]), Step::Done);
    op.take_result().unwrap();
}

#[test]
fn write_array_without_token_omits_auth_keys() {
    let data = [0xaau8; 17];
    let mut op = write_array(&data, None, OperationOptions::default()).unwrap();
    begin(&mut op);
    // One fragment: {2: h'AA..', 3: 0, 4: 17}; no keys 5/6.
    let mut message = vec![0x0c, 0xa3, 0x02, 0x51];
    message.extend_from_slice(&data);
    message.extend_from_slice(&[0x03, 0x00, 0x04, 0x11]);
    assert_command(&op, &message);
    assert_eq!(advance_ok(&mut op, &[]), Step::Done);
    op.take_result().unwrap();
}

#[test]
fn write_array_rejects_invalid_sizes_before_io() {
    let token = token_v1();
    let options = OperationOptions::default();
    // Below the firmware's minimum: 1 content byte + 16-byte trailer.
    let error =
        write_array(&[0u8; 16], Some((&token, PinUvAuthProtocol::V1)), options).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidArgument);
    // Above the advertised maxSerializedLargeBlobArray.
    let error = write_array(
        &[0u8; MAX_LARGE_BLOB_ARRAY_BYTES + 1],
        Some((&token, PinUvAuthProtocol::V1)),
        options,
    )
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidArgument);
    // The channel cannot fit even the message overhead: no fragment size.
    let tight = OperationOptions {
        limits: OperationLimits {
            max_input_bytes: 64,
            ..Default::default()
        },
        ..Default::default()
    };
    let error = write_array(&[0u8; 17], Some((&token, PinUvAuthProtocol::V1)), tight).unwrap_err();
    assert_eq!(error.kind, ErrorKind::LimitExceeded);
}

#[test]
fn write_array_pin_auth_invalid_keeps_raw_byte() {
    let token = token_v1();
    let mut op = write_array(
        &WRITE_DATA,
        Some((&token, PinUvAuthProtocol::V1)),
        clamped_options(),
    )
    .unwrap();
    begin(&mut op);
    let error = op.advance(&[0x33, 0x90, 0x00]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::AuthenticationFailed);
    assert_eq!(error.phase, Phase::Command);
    assert_eq!(error.status_word.map(|sw| sw.raw()), Some(0x33));
}

#[test]
fn write_array_storage_full_is_limit_exceeded() {
    let mut op = write_array(&WRITE_DATA, None, clamped_options()).unwrap();
    begin(&mut op);
    // CTAP2_ERR_LARGE_BLOB_STORAGE_FULL (0x18).
    let error = op.advance(&[0x18, 0x90, 0x00]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::LimitExceeded);
    assert_eq!(error.phase, Phase::Command);
    assert_eq!(error.status_word.map(|sw| sw.raw()), Some(0x18));
}

#[test]
fn write_array_non_empty_payload_is_invalid_response() {
    let token = token_v1();
    let mut op = write_array(
        &WRITE_DATA,
        Some((&token, PinUvAuthProtocol::V1)),
        clamped_options(),
    )
    .unwrap();
    begin(&mut op);
    // A successful set must return an empty payload.
    let error = advance_bad(&mut op, &hex("a0"));
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert_eq!(error.phase, Phase::Parsing);
}
