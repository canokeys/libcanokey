//! Golden transcript and failure-path tests for the legacy CTAP1/U2F raw
//! commands (CLA-00 INS 0x01/0x02/0x03 on the selected FIDO2 applet).
//!
//! U2F responses carry no CTAP status byte: the response is raw U2F data
//! plus an ISO 7816 status word. All transcripts are synthetic; the key
//! handle, certificate and signature fixtures are not real credential
//! material (and are not secret).

use canokey_ctap::u2f::{
    authenticate, check_only, register, version, U2fAuthenticateRequest, U2fRegisterRequest,
    MAX_KEY_HANDLE_LEN, U2F_VERSION_V2,
};
use canokey_protocol::{ErrorKind, Operation, OperationOptions, Phase, Step};

const SELECT: [u8; 13] = [
    0x00, 0xa4, 0x04, 0x00, 0x08, 0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01,
];

const CHALLENGE: [u8; 32] = [0x11; 32];
const APPLICATION: [u8; 32] = [0x22; 32];
const KEY_HANDLE: [u8; 4] = [0xaa, 0xbb, 0xcc, 0xdd];

/// SEC1 uncompressed public key fixture: 0x04 || X(0x33*32) || Y(0x44*32).
fn public_key() -> [u8; 65] {
    let mut key = [0u8; 65];
    key[0] = 0x04;
    key[1..33].fill(0x33);
    key[33..].fill(0x44);
    key
}

/// Minimal fake DER slices; only the outer length frame is parsed.
const FAKE_CERT: [u8; 5] = [0x30, 0x03, 0x02, 0x01, 0x01];
const FAKE_SIG: [u8; 8] = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];

/// The complete synthetic REGISTER response data:
/// `05 || pubkey[65] || khLen || keyHandle || cert(DER) || sig(DER)`.
fn register_response() -> Vec<u8> {
    let mut data = vec![0x05];
    data.extend_from_slice(&public_key());
    data.push(KEY_HANDLE.len() as u8);
    data.extend_from_slice(&KEY_HANDLE);
    data.extend_from_slice(&FAKE_CERT);
    data.extend_from_slice(&FAKE_SIG);
    data
}

/// Drive the mandatory SELECT and advance to the U2F command.
fn begin<T>(op: &mut Operation<T>) {
    assert_eq!(op.start().unwrap(), Step::Exchange);
    assert_eq!(op.command().unwrap().as_bytes(), &SELECT);
    assert_eq!(op.advance(&[0x90, 0x00]).unwrap(), Step::Exchange);
}

fn register_request() -> U2fRegisterRequest {
    U2fRegisterRequest {
        challenge: CHALLENGE,
        application: APPLICATION,
    }
}

fn authenticate_request() -> U2fAuthenticateRequest {
    U2fAuthenticateRequest {
        challenge: CHALLENGE,
        application: APPLICATION,
        key_handle: KEY_HANDLE.to_vec(),
    }
}

/// The expected register command bytes: `00 01 00 00 40` plus the 64-byte
/// challenge || application body.
fn expected_register_command() -> Vec<u8> {
    let mut command = vec![0x00, 0x01, 0x00, 0x00, 0x40];
    command.extend_from_slice(&CHALLENGE);
    command.extend_from_slice(&APPLICATION);
    command
}

/// The expected authenticate command bytes for P1 and the 4-byte handle:
/// `00 02 <p1> 00 45` plus challenge || application || khLen || keyHandle.
fn expected_authenticate_command(p1: u8) -> Vec<u8> {
    let mut command = vec![0x00, 0x02, p1, 0x00, 0x45];
    command.extend_from_slice(&CHALLENGE);
    command.extend_from_slice(&APPLICATION);
    command.push(KEY_HANDLE.len() as u8);
    command.extend_from_slice(&KEY_HANDLE);
    command
}

// ---------------------------------------------------------------- register

#[test]
fn register_golden_and_parse() {
    let mut op = register(register_request(), OperationOptions::default()).unwrap();
    begin(&mut op);
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &expected_register_command()
    );
    let mut reply = register_response();
    reply.extend_from_slice(&[0x90, 0x00]);
    assert_eq!(op.advance(&reply).unwrap(), Step::Done);
    let registration = op.take_result().unwrap();
    assert_eq!(registration.user_public_key, public_key());
    assert_eq!(registration.key_handle, KEY_HANDLE);
    assert_eq!(registration.certificate, FAKE_CERT);
    assert_eq!(registration.signature, FAKE_SIG);
    assert_eq!(registration.raw, register_response());
}

#[test]
fn register_continues_61xx_with_get_response_cla_0() {
    let mut op = register(register_request(), OperationOptions::default()).unwrap();
    begin(&mut op);
    let data = register_response();
    let split = 60;
    let mut first = data[..split].to_vec();
    first.extend_from_slice(&[0x61, (data.len() - split) as u8]);
    assert_eq!(op.advance(&first).unwrap(), Step::Exchange);
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0x00, 0xc0, 0x00, 0x00, (data.len() - split) as u8]
    );
    let mut second = data[split..].to_vec();
    second.extend_from_slice(&[0x90, 0x00]);
    assert_eq!(op.advance(&second).unwrap(), Step::Done);
    let registration = op.take_result().unwrap();
    assert_eq!(registration.raw, data);
}

#[test]
fn register_conditions_not_satisfied_on_touch_timeout() {
    let mut op = register(register_request(), OperationOptions::default()).unwrap();
    begin(&mut op);
    let error = op.advance(&[0x69, 0x85]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::ConditionsNotSatisfied);
    assert_eq!(error.phase, Phase::Command);
    assert_eq!(error.status_word.map(|sw| sw.raw()), Some(0x6985));
}

#[test]
fn register_unsupported_feature_when_always_uv_enabled() {
    let mut op = register(register_request(), OperationOptions::default()).unwrap();
    begin(&mut op);
    let error = op.advance(&[0x6d, 0x00]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::UnsupportedFeature);
    assert_eq!(error.phase, Phase::Command);
    assert_eq!(error.status_word.map(|sw| sw.raw()), Some(0x6d00));
}

#[test]
fn register_truncated_response_is_invalid_response() {
    let mut op = register(register_request(), OperationOptions::default()).unwrap();
    begin(&mut op);
    // Only the reserved byte and the public key: khLen is missing.
    let mut reply = vec![0x05];
    reply.extend_from_slice(&public_key());
    reply.extend_from_slice(&[0x90, 0x00]);
    let error = op.advance(&reply).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert_eq!(error.phase, Phase::Parsing);
}

#[test]
fn register_certificate_overrunning_response_is_invalid_response() {
    let mut op = register(register_request(), OperationOptions::default()).unwrap();
    begin(&mut op);
    // A DER length frame claiming more bytes than remain.
    let mut reply = vec![0x05];
    reply.extend_from_slice(&public_key());
    reply.push(KEY_HANDLE.len() as u8);
    reply.extend_from_slice(&KEY_HANDLE);
    reply.extend_from_slice(&[0x30, 0x20, 0x02, 0x01, 0x01]);
    reply.extend_from_slice(&[0x90, 0x00]);
    let error = op.advance(&reply).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert_eq!(error.phase, Phase::Parsing);
}

// ------------------------------------------------------------ authenticate

#[test]
fn authenticate_golden_and_parse() {
    let mut op = authenticate(authenticate_request(), OperationOptions::default()).unwrap();
    begin(&mut op);
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &expected_authenticate_command(0x03)
    );
    // userPresence 0x01, counter 42 (big-endian), then the fake DER signature.
    let mut reply = vec![0x01, 0x00, 0x00, 0x00, 0x2a];
    reply.extend_from_slice(&FAKE_SIG);
    reply.extend_from_slice(&[0x90, 0x00]);
    assert_eq!(op.advance(&reply).unwrap(), Step::Done);
    let authentication = op.take_result().unwrap();
    assert_eq!(authentication.user_presence, 0x01);
    assert_eq!(authentication.counter, 42);
    assert_eq!(authentication.signature, FAKE_SIG);
}

#[test]
fn authenticate_invalid_key_handle_keeps_raw_status() {
    let mut op = authenticate(authenticate_request(), OperationOptions::default()).unwrap();
    begin(&mut op);
    // 6A80 SW_WRONG_DATA: unknown key handle or app ID mismatch.
    let error = op.advance(&[0x6a, 0x80]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::UnexpectedStatusWord);
    assert_eq!(error.phase, Phase::Command);
    assert_eq!(error.status_word.map(|sw| sw.raw()), Some(0x6a80));
}

#[test]
fn authenticate_empty_key_handle_fails_before_io() {
    let mut request = authenticate_request();
    request.key_handle = Vec::new();
    let error = authenticate(request, OperationOptions::default()).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidArgument);
}

#[test]
fn authenticate_oversized_key_handle_fails_before_io() {
    let mut request = authenticate_request();
    request.key_handle = vec![0xaa; MAX_KEY_HANDLE_LEN + 1];
    let error = authenticate(request, OperationOptions::default()).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidArgument);
    let mut request = authenticate_request();
    request.key_handle = vec![0xaa; MAX_KEY_HANDLE_LEN];
    authenticate(request, OperationOptions::default()).unwrap();
}

// -------------------------------------------------------------- check_only

#[test]
fn check_only_valid_handle_is_ok_true() {
    let mut op = check_only(authenticate_request(), OperationOptions::default()).unwrap();
    begin(&mut op);
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &expected_authenticate_command(0x07)
    );
    // By design, a valid check-only handle is answered with 6985.
    assert_eq!(op.advance(&[0x69, 0x85]).unwrap(), Step::Done);
    assert!(op.take_result().unwrap());
}

#[test]
fn check_only_invalid_handle_is_error_not_false() {
    let mut op = check_only(authenticate_request(), OperationOptions::default()).unwrap();
    begin(&mut op);
    let error = op.advance(&[0x6a, 0x80]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::UnexpectedStatusWord);
    assert_eq!(error.phase, Phase::Command);
    assert_eq!(error.status_word.map(|sw| sw.raw()), Some(0x6a80));
}

#[test]
fn check_only_success_status_is_invalid_response() {
    let mut op = check_only(authenticate_request(), OperationOptions::default()).unwrap();
    begin(&mut op);
    // The firmware never answers check-only with 9000; a success here is a
    // protocol violation by the authenticator.
    let error = op.advance(&[0x90, 0x00]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert_eq!(error.phase, Phase::Parsing);
}

// ----------------------------------------------------------------- version

#[test]
fn version_golden() {
    let mut op = version(OperationOptions::default()).unwrap();
    begin(&mut op);
    assert_eq!(op.command().unwrap().as_bytes(), &[0x00, 0x03, 0x00, 0x00]);
    let mut reply = U2F_VERSION_V2.to_vec();
    reply.extend_from_slice(&[0x90, 0x00]);
    assert_eq!(op.advance(&reply).unwrap(), Step::Done);
    assert_eq!(op.take_result().unwrap(), U2F_VERSION_V2);
}

#[test]
fn version_unexpected_string_is_invalid_response() {
    let mut op = version(OperationOptions::default()).unwrap();
    begin(&mut op);
    let mut reply = b"U2F_V1".to_vec();
    reply.extend_from_slice(&[0x90, 0x00]);
    let error = op.advance(&reply).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert_eq!(error.phase, Phase::Parsing);
}
