//! Golden transcript and failure-path tests for authenticatorConfig (0x0D).
//!
//! All requests are authenticated with a fixed pinUvAuthToken (plaintext
//! 0x10..=0x2F, minted through the clientPIN fixtures shared with
//! `client_pin.rs`), so every pinUvAuthParam is deterministic. Per the CTAP
//! 2.1 spec and the firmware's `cfg_pin_msg` construction, the MAC input is
//! `0xFF * 32 || 0x0D || subCommand || cbor(subCommandParams)` — note the
//! 0xFF header and command byte that credentialManagement does not have.
//! The expected HMAC-SHA-256 values (protocol V1, truncated to 16 bytes)
//! were computed with an independent implementation (Python stdlib `hmac`)
//! on 2026-09-16.
#![cfg(feature = "clientpin")]

use canokey_ctap::config::{enable_long_touch_for_reset, set_min_pin_length, toggle_always_uv};
use canokey_ctap::{get_key_agreement, get_pin_token, PinToken, PinUvAuthProtocol};
use canokey_protocol::{ErrorKind, Operation, OperationOptions, Phase, Step};

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

/// Complete config messages (0x0D + canonical CBOR), protocol V1. The MAC
/// inputs are:
/// - toggle:   `FF*32 || 0d || 02`
/// - setMin:   `FF*32 || 0d || 03 || a3010802816b6578616d706c652e636f6d03f5`
/// - longTouch: `FF*32 || 0d || 04`
const MSG_TOGGLE_ALWAYS_UV: &str = "0da30102030104504c5f2977f89922eb13b28960c0c7b4da";
const MSG_SET_MIN_PIN_LENGTH: &str =
    "0da4010302a3010802816b6578616d706c652e636f6d03f503010450477dff2bb8a3fba3b96035e32ecce793";
const MSG_ENABLE_LONG_TOUCH: &str = "0da3010403010450967369eaf14c745bb57c5340d0cc9416";

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
    let mut reply = vec![0x00];
    reply.extend_from_slice(&hex(PEER_KEY_AGREEMENT_PAYLOAD));
    reply.extend_from_slice(&[0x90, 0x00]);
    assert_eq!(op.advance(&reply).unwrap(), Step::Done);
    let session = op.take_result().unwrap();
    let mut op = get_pin_token(&session, b"1234", None, OperationOptions::default()).unwrap();
    begin(&mut op);
    let ct = hex(TOKEN_CT_V1);
    // A 32-byte byte string needs the one-byte-length head (0x58 0x20).
    let mut reply = vec![0x00, 0xa1, 0x02, 0x58, 0x20];
    reply.extend_from_slice(&ct);
    reply.extend_from_slice(&[0x90, 0x00]);
    assert_eq!(op.advance(&reply).unwrap(), Step::Done);
    let token = op.take_result().unwrap();
    assert_eq!(token.token().as_bytes(), &TOKEN_PLAINTEXT);
    token
}

/// Advance with a successful CTAP response carrying `payload`.
fn advance_payload<T>(
    op: &mut Operation<T>,
    payload: &[u8],
) -> Result<Step, canokey_protocol::Error> {
    let mut reply = vec![0x00];
    reply.extend_from_slice(payload);
    reply.extend_from_slice(&[0x90, 0x00]);
    op.advance(&reply)
}

// ---------------------------------------------------------- toggle_always_uv

#[test]
fn toggle_always_uv_golden() {
    let token = token_v1();
    let mut op =
        toggle_always_uv(&token, PinUvAuthProtocol::V1, OperationOptions::default()).unwrap();
    begin(&mut op);
    assert_command(&op, &hex(MSG_TOGGLE_ALWAYS_UV));
    assert_eq!(advance_payload(&mut op, &[]).unwrap(), Step::Done);
    op.take_result().unwrap();
}

#[test]
fn toggle_always_uv_pin_auth_invalid_keeps_raw_byte() {
    let token = token_v1();
    let mut op =
        toggle_always_uv(&token, PinUvAuthProtocol::V1, OperationOptions::default()).unwrap();
    begin(&mut op);
    let error = op.advance(&[0x33, 0x90, 0x00]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::AuthenticationFailed);
    assert_eq!(error.phase, Phase::Command);
    assert_eq!(error.status_word.map(|sw| sw.raw()), Some(0x33));
}

#[test]
fn toggle_always_uv_non_empty_response_is_invalid_response() {
    let token = token_v1();
    let mut op =
        toggle_always_uv(&token, PinUvAuthProtocol::V1, OperationOptions::default()).unwrap();
    begin(&mut op);
    let error = advance_payload(&mut op, &[0x00]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert_eq!(error.phase, Phase::Parsing);
}

// --------------------------------------------------------- set_min_pin_length

#[test]
fn set_min_pin_length_golden() {
    let token = token_v1();
    let mut op = set_min_pin_length(
        &token,
        PinUvAuthProtocol::V1,
        8,
        Some(true),
        vec!["example.com".to_owned()],
        OperationOptions::default(),
    )
    .unwrap();
    begin(&mut op);
    assert_command(&op, &hex(MSG_SET_MIN_PIN_LENGTH));
    assert_eq!(advance_payload(&mut op, &[]).unwrap(), Step::Done);
    op.take_result().unwrap();
}

#[test]
fn set_min_pin_length_below_floor_fails_before_io() {
    let token = token_v1();
    let error = set_min_pin_length(
        &token,
        PinUvAuthProtocol::V1,
        3,
        None,
        Vec::new(),
        OperationOptions::default(),
    )
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidArgument);
}

#[test]
fn set_min_pin_length_empty_rp_id_fails_before_io() {
    let token = token_v1();
    let error = set_min_pin_length(
        &token,
        PinUvAuthProtocol::V1,
        8,
        None,
        vec![String::new()],
        OperationOptions::default(),
    )
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidArgument);
}

#[test]
fn set_min_pin_length_too_many_rp_ids_fails_before_io() {
    let token = token_v1();
    let rp_ids: Vec<String> = (0..5).map(|i| format!("rp{i}.example.com")).collect();
    let error = set_min_pin_length(
        &token,
        PinUvAuthProtocol::V1,
        8,
        None,
        rp_ids,
        OperationOptions::default(),
    )
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidArgument);
}

#[test]
fn set_min_pin_length_pin_policy_violation_keeps_raw_byte() {
    let token = token_v1();
    let mut op = set_min_pin_length(
        &token,
        PinUvAuthProtocol::V1,
        8,
        None,
        Vec::new(),
        OperationOptions::default(),
    )
    .unwrap();
    begin(&mut op);
    let error = op.advance(&[0x37, 0x90, 0x00]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidPin);
    assert_eq!(error.phase, Phase::Command);
    assert_eq!(error.status_word.map(|sw| sw.raw()), Some(0x37));
}

// -------------------------------------------------- enable_long_touch_for_reset

#[test]
fn enable_long_touch_for_reset_golden() {
    let token = token_v1();
    let mut op =
        enable_long_touch_for_reset(&token, PinUvAuthProtocol::V1, OperationOptions::default())
            .unwrap();
    begin(&mut op);
    assert_command(&op, &hex(MSG_ENABLE_LONG_TOUCH));
    assert_eq!(advance_payload(&mut op, &[]).unwrap(), Step::Done);
    op.take_result().unwrap();
}

#[test]
fn enable_long_touch_for_reset_non_empty_response_is_invalid_response() {
    let token = token_v1();
    let mut op =
        enable_long_touch_for_reset(&token, PinUvAuthProtocol::V1, OperationOptions::default())
            .unwrap();
    begin(&mut op);
    let error = advance_payload(&mut op, &[0xa0]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert_eq!(error.phase, Phase::Parsing);
}
