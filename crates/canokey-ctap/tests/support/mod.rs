//! Shared fixtures for the canokey-ctap test suite: the FIDO2 SELECT
//! transcript helpers and the deterministic ClientPIN fixture.
//!
//! The ClientPIN vectors are self-generated on 2026-09-16 from the fixed
//! fixtures below (platform ephemeral scalar 0x01..=0x20, peer scalar
//! 0xA0..=0xBF, PIN "1234", V2 IV 0x0F..=0x00) and cross-checked against an
//! independent implementation (Python `cryptography`: P-256 ECDH,
//! HKDF-SHA-256, AES-256-CBC; stdlib HMAC-SHA-256) on the same date.
#[cfg(feature = "clientpin")]
use canokey_ctap::{get_key_agreement, get_pin_token, PinSession, PinToken, PinUvAuthProtocol};
#[cfg(feature = "clientpin")]
use canokey_protocol::OperationOptions;
use canokey_protocol::{Error, Operation, Step};

/// The FIDO2 application SELECT command: `00 A4 04 00 08 <FIDO2 AID>`.
pub const SELECT: [u8; 13] = [
    0x00, 0xa4, 0x04, 0x00, 0x08, 0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01,
];

/// Platform ephemeral scalar fixture (0x01..=0x20).
#[cfg(feature = "clientpin")]
#[allow(dead_code)]
pub const EPHEMERAL_SCALAR: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];
/// Caller-supplied IV fixture for protocol V2.
#[cfg(feature = "clientpin")]
#[allow(dead_code)]
pub const IV_V2: [u8; 16] = [
    0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
];
/// Peer (authenticator) keyAgreement response payload: `{1: {1: 2, 3: -25,
/// -1: 1, -2: x, -3: y}}` for the peer scalar 0xA0..=0xBF.
#[cfg(feature = "clientpin")]
pub const PEER_KEY_AGREEMENT_PAYLOAD: &str = "a101a5010203381820012158200d0918a04198474605615b6df90fdcb34791fb3ecb822f4b26eb6e4fc4511b9d22582019b90c1b83c0c35cfbbb31ead32bb52ae33622f57e3cc1638097ce97f430baba";
/// Encrypted V1 token fixture for the token plaintext 0x10..=0x2F.
#[cfg(feature = "clientpin")]
pub const TOKEN_CT_V1: &str = "b98cc635132fa3ea8c191b7a4aa3e093ce926c35488221b4684fce766f3b14b0";
/// The decrypted token plaintext, 0x10..=0x2F; the HMAC key of every
/// pinUvAuthParam in the credmgmt/config/largeblob fixtures.
#[cfg(feature = "clientpin")]
pub const TOKEN_PLAINTEXT: [u8; 32] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];

/// Decode a hex string, ignoring whitespace.
#[allow(dead_code)]
pub fn hex(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
        .collect()
}

/// Drive the mandatory SELECT and advance to the CTAP command.
#[allow(dead_code)]
pub fn begin<T>(op: &mut Operation<T>) {
    assert_eq!(op.start().unwrap(), Step::Exchange);
    assert_eq!(op.command().unwrap().as_bytes(), &SELECT);
    assert_eq!(op.advance(&[0x90, 0x00]).unwrap(), Step::Exchange);
}

/// Assert the wrapped command bytes: `80 10 00 00 <Lc> <message>`.
#[allow(dead_code)]
pub fn assert_command(op: &Operation<impl Sized>, message: &[u8]) {
    let mut expected = vec![0x80, 0x10, 0x00, 0x00, message.len() as u8];
    expected.extend_from_slice(message);
    assert!(message.len() <= 255, "fixture must use short Lc");
    assert_eq!(op.command().unwrap().as_bytes(), &expected);
}

/// Advance with a successful CTAP response carrying `payload`.
#[allow(dead_code)]
pub fn advance_ok<T>(op: &mut Operation<T>, payload: &[u8]) -> Step {
    let mut reply = vec![0x00];
    reply.extend_from_slice(payload);
    reply.extend_from_slice(&[0x90, 0x00]);
    op.advance(&reply).unwrap()
}

/// Finish the operation with a successful CTAP response carrying `payload`.
#[allow(dead_code)]
pub fn finish<T>(op: &mut Operation<T>, payload: &[u8]) -> T {
    assert_eq!(advance_ok(op, payload), Step::Done);
    op.take_result().unwrap()
}

/// Feed a successful CTAP response carrying `payload`, expecting a
/// classified failure in the Parsing phase.
#[allow(dead_code)]
pub fn finish_err<T>(op: &mut Operation<T>, payload: &[u8]) -> Error {
    let mut reply = vec![0x00];
    reply.extend_from_slice(payload);
    reply.extend_from_slice(&[0x90, 0x00]);
    op.advance(&reply).unwrap_err()
}

/// Establish a pin/UV session for `protocol` against the fixture peer key.
#[cfg(feature = "clientpin")]
#[allow(dead_code)]
pub fn session(protocol: PinUvAuthProtocol) -> PinSession {
    let mut op =
        get_key_agreement(protocol, &EPHEMERAL_SCALAR, OperationOptions::default()).unwrap();
    begin(&mut op);
    finish(&mut op, &hex(PEER_KEY_AGREEMENT_PAYLOAD))
}

/// Mint the fixed V1 token (plaintext 0x10..=0x2F) through the clientPIN
/// fixture transcript.
#[cfg(feature = "clientpin")]
#[allow(dead_code)]
pub fn token_v1() -> PinToken {
    let session = session(PinUvAuthProtocol::V1);
    let mut op = get_pin_token(&session, b"1234", None, OperationOptions::default()).unwrap();
    begin(&mut op);
    // A 32-byte byte string needs the one-byte-length head (0x58 0x20).
    let mut payload = vec![0xa1, 0x02, 0x58, 0x20];
    payload.extend_from_slice(&hex(TOKEN_CT_V1));
    assert_eq!(advance_ok(&mut op, &payload), Step::Done);
    let token = op.take_result().unwrap();
    assert_eq!(token.token().as_bytes(), &TOKEN_PLAINTEXT);
    token
}
