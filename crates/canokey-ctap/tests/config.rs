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

mod support;

use canokey_ctap::config::{enable_long_touch_for_reset, set_min_pin_length, toggle_always_uv};
use canokey_ctap::PinUvAuthProtocol;
use canokey_protocol::{ErrorKind, OperationOptions, Step};
use support::{advance_ok, assert_command, begin, hex, token_v1};

/// Complete config messages (0x0D + canonical CBOR), protocol V1. The MAC
/// inputs are:
/// - toggle:   `FF*32 || 0d || 02`
/// - setMin:   `FF*32 || 0d || 03 || a3010802816b6578616d706c652e636f6d03f5`
/// - longTouch: `FF*32 || 0d || 04`
const MSG_TOGGLE_ALWAYS_UV: &str = "0da30102030104504c5f2977f89922eb13b28960c0c7b4da";
const MSG_SET_MIN_PIN_LENGTH: &str =
    "0da4010302a3010802816b6578616d706c652e636f6d03f503010450477dff2bb8a3fba3b96035e32ecce793";
const MSG_ENABLE_LONG_TOUCH: &str = "0da3010403010450967369eaf14c745bb57c5340d0cc9416";

// ---------------------------------------------------------- toggle_always_uv

#[test]
fn toggle_always_uv_golden() {
    let token = token_v1();
    let mut op =
        toggle_always_uv(&token, PinUvAuthProtocol::V1, OperationOptions::default()).unwrap();
    begin(&mut op);
    assert_command(&op, &hex(MSG_TOGGLE_ALWAYS_UV));
    assert_eq!(advance_ok(&mut op, &[]), Step::Done);
    op.take_result().unwrap();
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
    assert_eq!(advance_ok(&mut op, &[]), Step::Done);
    op.take_result().unwrap();
}

// --------------------------------------------------------- set_min_pin_length

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

// -------------------------------------------------- enable_long_touch_for_reset

#[test]
fn enable_long_touch_for_reset_golden() {
    let token = token_v1();
    let mut op =
        enable_long_touch_for_reset(&token, PinUvAuthProtocol::V1, OperationOptions::default())
            .unwrap();
    begin(&mut op);
    assert_command(&op, &hex(MSG_ENABLE_LONG_TOUCH));
    assert_eq!(advance_ok(&mut op, &[]), Step::Done);
    op.take_result().unwrap();
}
