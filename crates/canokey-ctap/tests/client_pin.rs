//! Golden transcript and failure-path tests for the ClientPIN protocol
//! (authenticatorClientPIN, 0x06) for pin/UV auth protocols 1 and 2.
//!
//! All crypto vectors are self-generated on 2026-09-16 from the fixed
//! fixtures below (ephemeral scalar 0x01..=0x20, peer scalar 0xA0..=0xBF,
//! PINs "1234"/"654321", V2 IV 0F..00) and cross-checked against an
//! independent implementation (Python `cryptography`: P-256 ECDH,
//! HKDF-SHA-256, AES-256-CBC; stdlib HMAC-SHA-256) on the same date.
#![cfg(feature = "clientpin")]

mod support;

use canokey_ctap::cose::CoseKey;
use canokey_ctap::{
    change_pin, get_key_agreement, get_pin_retries, get_pin_token, get_pin_token_with_permissions,
    set_pin, Permissions, PinToken, PinUvAuthProtocol,
};
use canokey_protocol::{ErrorKind, OperationOptions, Phase};
use support::{
    assert_command, begin, finish, hex, session, EPHEMERAL_SCALAR, IV_V2,
    PEER_KEY_AGREEMENT_PAYLOAD, TOKEN_CT_V1, TOKEN_PLAINTEXT,
};

/// Expected platform key-agreement coordinates for EPHEMERAL_SCALAR.
const PLATFORM_X: &str = "515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f";
const PLATFORM_Y: &str = "4536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f9354";
/// Shared secrets for EPHEMERAL_SCALAR x peer key.
const SHARED_SECRET_V1: &str = "14c399f80a6278f4a5bf4e6b8dc32755dbccaa652bc977c86ced182693499f38";
const SHARED_SECRET_V2: &str = "8aa632342bd4be82c98f90f9fbb695771a2b8ec84bc84dd263cba60ccdd1ebf38476874e7d76587817f1b181292759ca9fc6df4aeabe1256f9a343efe56b8fbb";

/// Complete clientPIN messages (0x06 command byte + canonical CBOR map).
const SET_PIN_MSG_V1: &str = "06a50101020303a501020338182001215820515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f2258204536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f93540450d4421839fa7606bcd586eddc6494d9620558406ce3b2501aea6143416b8de3b22671a0a351bc7cd39c13236e20a0c9e999c7da30a83a78c0ebe15c1948375d871d23c2fc6b34915a52f806f4be73f9c604f056";
const SET_PIN_MSG_V2: &str = "06a50102020303a501020338182001215820515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f2258204536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f9354045820431e258245363cec539cc0cf5ba429e4d122155741c81b7c55473fbe19c9b2650558500f0e0d0c0b0a09080706050403020100eb721e5129c4f3b3d780de13bdc001328e7c9eead4e15735a93382ae65f2b23ed020dbaea27fea48b44cad1597d65906de97d6f4444c221e1da73c2edcf7d511";
const CHANGE_PIN_MSG_V1: &str = "06a60101020403a501020338182001215820515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f2258204536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f93540450b40d138697eed83b85ec0633d11dff99055840ae2410a23e5d3edb4a340928107afa20e4c0c6430c43bc39b5a4613ab664c032073abf9d18dcefbaa8c3d69a1e8fef3cc4bab7ff0051a3b92951c70355c9c2fe0650540fcbd893ef5cb18b8e741b313ff977";
const CHANGE_PIN_MSG_V2: &str = "06a60102020403a501020338182001215820515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f2258204536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f93540458206c2bb83d6ccfae4ce1221fa074d85cd5fae42f9ab7f65dd8c09ac8616429245b0558500f0e0d0c0b0a09080706050403020100a8395df2289b10495a9c1c13919cfdda5971cd6436294c7bafd204cd4eb1c737bbb21695023d71532c8cd847780477e0bf741b09ac0d72fdbc21ac401fe3ff1b0658200f0e0d0c0b0a0908070605040302010017d937071b239273a39da474e04c6376";
const GET_PIN_TOKEN_MSG_V1: &str = "06a40101020503a501020338182001215820515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f2258204536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f93540650540fcbd893ef5cb18b8e741b313ff977";
const GET_PIN_TOKEN_MSG_V2: &str = "06a40102020503a501020338182001215820515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f2258204536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f93540658200f0e0d0c0b0a0908070605040302010017d937071b239273a39da474e04c6376";
/// permissions = MAKE_CREDENTIAL|GET_ASSERTION (0x03), rpId "example.com".
const GET_PIN_TOKEN_PERMS_MSG_V2: &str = "06a60102020903a501020338182001215820515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f2258204536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f93540658200f0e0d0c0b0a0908070605040302010017d937071b239273a39da474e04c637609030a6b6578616d706c652e636f6d";

/// Encrypted V2 token fixture for the shared token plaintext 0x10..=0x2F.
const TOKEN_CT_V2: &str =
    "0f0e0d0c0b0a09080706050403020100a1f914f091032bf439a162dbf45e137290ccdf4a4476a5f39b912b7dbbbb6f64";
/// pinUvAuthParam = token.authenticate(protocol, [0x5A; 32]) fixtures.
const TOKEN_AUTH_V1: &str = "8b533e4b9f8398fa58019dc2a92c69c0";
const TOKEN_AUTH_V2: &str = "8b533e4b9f8398fa58019dc2a92c69c0c7aeae1196032378bf112ffb21e48dd1";

/// The `{2: <encrypted token>}` response payload for getPinToken.
fn token_payload(token_ct: &str) -> Vec<u8> {
    let ct = hex(token_ct);
    // Byte strings of 32/48 bytes need the one-byte-length head (0x58).
    let mut payload = vec![0xa1, 0x02, 0x58, ct.len() as u8];
    payload.extend_from_slice(&ct);
    payload
}

// ------------------------------------------------------- get_key_agreement

#[test]
fn get_key_agreement_golden_v1() {
    let mut op = get_key_agreement(
        PinUvAuthProtocol::V1,
        &EPHEMERAL_SCALAR,
        OperationOptions::default(),
    )
    .unwrap();
    begin(&mut op);
    assert_command(&op, &hex("06 a2 01 01 02 02"));
    let session = finish(&mut op, &hex(PEER_KEY_AGREEMENT_PAYLOAD));
    assert_eq!(session.protocol(), PinUvAuthProtocol::V1);
    match session.key_agreement() {
        CoseKey::P256 { algorithm, x, y } => {
            assert_eq!(algorithm.id(), -25);
            assert_eq!(x, &hex(PLATFORM_X)[..]);
            assert_eq!(y, &hex(PLATFORM_Y)[..]);
        }
        other => panic!("unexpected key agreement key: {other:?}"),
    }
    assert_eq!(session.shared_secret().as_bytes(), &hex(SHARED_SECRET_V1));
}

#[test]
fn get_key_agreement_golden_v2() {
    let mut op = get_key_agreement(
        PinUvAuthProtocol::V2,
        &EPHEMERAL_SCALAR,
        OperationOptions::default(),
    )
    .unwrap();
    begin(&mut op);
    assert_command(&op, &hex("06 a2 01 02 02 02"));
    let session = finish(&mut op, &hex(PEER_KEY_AGREEMENT_PAYLOAD));
    assert_eq!(session.protocol(), PinUvAuthProtocol::V2);
    assert_eq!(session.shared_secret().as_bytes(), &hex(SHARED_SECRET_V2));
}

#[test]
fn get_key_agreement_rejects_invalid_scalar_before_io() {
    for scalar in [[0x00; 32], [0xff; 32]] {
        let error = get_key_agreement(PinUvAuthProtocol::V1, &scalar, OperationOptions::default())
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidArgument);
    }
}

#[test]
fn get_key_agreement_rejects_malformed_peer_key() {
    // One representative per pin-layer parse branch: a missing keyAgreement
    // member (required field), and a syntactically valid COSE key whose
    // point fails the ECDH public-key validation. COSE-level shape
    // rejections (wrong alg/kty, truncated coordinates) are covered by the
    // cose tests in ctap2_foundations.rs.
    let cases: &[(&str, &str)] = &[
        ("missing keyAgreement", "a0"),
        // x = y = 1 is not a P-256 point
        (
            "point not on curve",
            "a101a50102033818200121582000000000000000000000000000000000000000000000000000000000000000012258200000000000000000000000000000000000000000000000000000000000000001",
        ),
    ];
    for (name, payload) in cases {
        let mut op = get_key_agreement(
            PinUvAuthProtocol::V1,
            &EPHEMERAL_SCALAR,
            OperationOptions::default(),
        )
        .unwrap();
        begin(&mut op);
        let mut reply = vec![0x00];
        reply.extend_from_slice(&hex(payload));
        reply.extend_from_slice(&[0x90, 0x00]);
        let error = op.advance(&reply).unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidResponse, "{name}");
        assert_eq!(error.phase, Phase::Parsing, "{name}");
    }
}

// ----------------------------------------------------------- get_pin_retries

#[test]
fn get_pin_retries_golden_and_parse() {
    let mut op = get_pin_retries(PinUvAuthProtocol::V1, OperationOptions::default()).unwrap();
    begin(&mut op);
    assert_command(&op, &hex("06 a2 01 01 02 01"));
    let retries = finish(&mut op, &hex("a2 03 08 04 f5"));
    assert_eq!(retries.pin_retries, 8);
    assert_eq!(retries.power_cycle_state, Some(true));
}

#[test]
fn get_pin_retries_optional_power_cycle_state() {
    let mut op = get_pin_retries(PinUvAuthProtocol::V2, OperationOptions::default()).unwrap();
    begin(&mut op);
    assert_command(&op, &hex("06 a2 01 02 02 01"));
    let retries = finish(&mut op, &hex("a1 03 03"));
    assert_eq!(retries.pin_retries, 3);
    assert_eq!(retries.power_cycle_state, None);
}

#[test]
fn get_pin_retries_missing_counter_is_invalid_response() {
    let mut op = get_pin_retries(PinUvAuthProtocol::V1, OperationOptions::default()).unwrap();
    begin(&mut op);
    let error = {
        let reply = hex("00 a1 04 f5 90 00");
        op.advance(&reply).unwrap_err()
    };
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert_eq!(error.phase, Phase::Parsing);
}

// ------------------------------------------------------------------ set_pin

#[test]
fn set_pin_golden_v1() {
    let session = session(PinUvAuthProtocol::V1);
    let mut op = set_pin(&session, b"1234", None, OperationOptions::default()).unwrap();
    begin(&mut op);
    assert_command(&op, &hex(SET_PIN_MSG_V1));
    finish(&mut op, &[]);
}

#[test]
fn set_pin_golden_v2() {
    let session = session(PinUvAuthProtocol::V2);
    let mut op = set_pin(&session, b"1234", Some(&IV_V2), OperationOptions::default()).unwrap();
    begin(&mut op);
    assert_command(&op, &hex(SET_PIN_MSG_V2));
    finish(&mut op, &[]);
}

// --------------------------------------------------------------- change_pin

#[test]
fn change_pin_golden_v1() {
    let session = session(PinUvAuthProtocol::V1);
    let mut op = change_pin(
        &session,
        b"1234",
        b"654321",
        None,
        OperationOptions::default(),
    )
    .unwrap();
    begin(&mut op);
    assert_command(&op, &hex(CHANGE_PIN_MSG_V1));
    finish(&mut op, &[]);
}

#[test]
fn change_pin_golden_v2() {
    let session = session(PinUvAuthProtocol::V2);
    let mut op = change_pin(
        &session,
        b"1234",
        b"654321",
        Some(&IV_V2),
        OperationOptions::default(),
    )
    .unwrap();
    begin(&mut op);
    assert_command(&op, &hex(CHANGE_PIN_MSG_V2));
    finish(&mut op, &[]);
}

// ------------------------------------------------------------- get_pin_token

#[test]
fn get_pin_token_golden_v1() {
    let session = session(PinUvAuthProtocol::V1);
    let mut op = get_pin_token(&session, b"1234", None, OperationOptions::default()).unwrap();
    begin(&mut op);
    assert_command(&op, &hex(GET_PIN_TOKEN_MSG_V1));
    let token = finish(&mut op, &token_payload(TOKEN_CT_V1));
    assert_eq!(token.token().as_bytes(), &TOKEN_PLAINTEXT);
}

#[test]
fn get_pin_token_golden_v2() {
    let session = session(PinUvAuthProtocol::V2);
    let mut op =
        get_pin_token(&session, b"1234", Some(&IV_V2), OperationOptions::default()).unwrap();
    begin(&mut op);
    assert_command(&op, &hex(GET_PIN_TOKEN_MSG_V2));
    let token = finish(&mut op, &token_payload(TOKEN_CT_V2));
    assert_eq!(token.token().as_bytes(), &TOKEN_PLAINTEXT);
}

#[test]
fn get_pin_token_with_permissions_golden_v2() {
    let session = session(PinUvAuthProtocol::V2);
    let mut op = get_pin_token_with_permissions(
        &session,
        b"1234",
        Permissions::MAKE_CREDENTIAL | Permissions::GET_ASSERTION,
        Some("example.com"),
        Some(&IV_V2),
        OperationOptions::default(),
    )
    .unwrap();
    begin(&mut op);
    assert_command(&op, &hex(GET_PIN_TOKEN_PERMS_MSG_V2));
    let token = finish(&mut op, &token_payload(TOKEN_CT_V2));
    assert_eq!(token.token().as_bytes(), &TOKEN_PLAINTEXT);
}

#[test]
fn get_pin_token_with_permissions_omits_rp_id() {
    let session = session(PinUvAuthProtocol::V2);
    let mut op = get_pin_token_with_permissions(
        &session,
        b"1234",
        Permissions::GET_ASSERTION,
        None,
        Some(&IV_V2),
        OperationOptions::default(),
    )
    .unwrap();
    begin(&mut op);
    // Same map as the golden minus the trailing `0a 6b "example.com"` entry,
    // with permissions 0x02 and a 5-entry map header.
    let with_rp = hex(GET_PIN_TOKEN_PERMS_MSG_V2);
    let mut expected = with_rp[..with_rp.len() - 13].to_vec();
    expected[1] = 0xa5; // map(5)
    let last = expected.len() - 1;
    expected[last] = 0x02; // permissions = getAssertion only
    assert_command(&op, &expected);
}

#[test]
fn get_pin_token_undecryptable_token_is_invalid_response() {
    // V1: 15 bytes is not a whole number of AES blocks.
    let session_v1 = session(PinUvAuthProtocol::V1);
    let mut op = get_pin_token(&session_v1, b"1234", None, OperationOptions::default()).unwrap();
    begin(&mut op);
    let mut payload = vec![0xa1, 0x02, 0x4f];
    payload.extend_from_slice(&[0x00; 15]);
    let mut reply = vec![0x00];
    reply.extend_from_slice(&payload);
    reply.extend_from_slice(&[0x90, 0x00]);
    let error = op.advance(&reply).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert_eq!(error.phase, Phase::Parsing);

    // V2: IV + 15 bytes is misaligned.
    let session_v2 = session(PinUvAuthProtocol::V2);
    let mut op = get_pin_token(
        &session_v2,
        b"1234",
        Some(&IV_V2),
        OperationOptions::default(),
    )
    .unwrap();
    begin(&mut op);
    let mut payload = vec![0xa1, 0x02, 0x58, 0x1f]; // 31 bytes: IV + 15
    payload.extend_from_slice(&[0x00; 31]);
    let mut reply = vec![0x00];
    reply.extend_from_slice(&payload);
    reply.extend_from_slice(&[0x90, 0x00]);
    let error = op.advance(&reply).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
}

// --------------------------------------------------------------- validation

#[test]
fn pin_validation_fails_before_io() {
    let session = session(PinUvAuthProtocol::V1);
    // Fewer than 4 code points, including multi-byte characters.
    for pin in [&b"ab"[..], "你好好".as_bytes(), b""] {
        let error = set_pin(&session, pin, None, OperationOptions::default()).unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidPin, "pin {pin:?}");
    }
    // More than 63 UTF-8 bytes.
    let error = set_pin(&session, &[b'a'; 64], None, OperationOptions::default()).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidPin);
    // Invalid UTF-8.
    let error = set_pin(
        &session,
        &[0xff, 0xfe, 0x41, 0x42],
        None,
        OperationOptions::default(),
    )
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidPin);
    // Boundary: 63 one-byte code points is accepted.
    assert!(set_pin(&session, &[b'a'; 63], None, OperationOptions::default()).is_ok());
}

#[test]
fn iv_rules_by_protocol() {
    // The IV rule lives in the shared `check_iv` helper used by every
    // pin-token factory; one command per direction is representative.
    for (protocol, iv) in [
        (PinUvAuthProtocol::V1, Some(&IV_V2)),
        (PinUvAuthProtocol::V2, None),
    ] {
        let session = session(protocol);
        let error = set_pin(&session, b"1234", iv, OperationOptions::default()).unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidArgument);
    }
}

#[test]
fn permissions_argument_validation() {
    let session = session(PinUvAuthProtocol::V2);
    let error = get_pin_token_with_permissions(
        &session,
        b"1234",
        Permissions::from_bits(0),
        None,
        Some(&IV_V2),
        OperationOptions::default(),
    )
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidArgument);
    let error = get_pin_token_with_permissions(
        &session,
        b"1234",
        Permissions::GET_ASSERTION,
        Some(""),
        Some(&IV_V2),
        OperationOptions::default(),
    )
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidArgument);
}

#[test]
fn permissions_bitfield_round_trip() {
    let all = Permissions::MAKE_CREDENTIAL
        | Permissions::GET_ASSERTION
        | Permissions::CREDENTIAL_MANAGEMENT
        | Permissions::BIO_ENROLLMENT
        | Permissions::LARGE_BLOB_WRITE
        | Permissions::AUTHENTICATOR_CONFIG;
    assert_eq!(all.bits(), 0x3f);
    assert_eq!(Permissions::from_bits(0xa5).bits(), 0xa5);
    assert_eq!(
        (Permissions::MAKE_CREDENTIAL | Permissions::GET_ASSERTION).bits(),
        0x03
    );
}

// ------------------------------------------------------------ status errors

#[test]
fn ctap_status_errors_are_classified_with_raw_byte() {
    // One representative status: the full byte -> ErrorKind table is
    // unit-tested in src/status.rs; here we pin the typed() plumbing and the
    // raw-byte retention on the command path.
    let mut op = get_pin_retries(PinUvAuthProtocol::V1, OperationOptions::default()).unwrap();
    begin(&mut op);
    let error = op.advance(&[0x33, 0x90, 0x00]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::AuthenticationFailed);
    assert_eq!(error.phase, Phase::Command);
    assert_eq!(error.application_status, Some(0x33));
}

// --------------------------------------------------------- token auth widths

#[test]
fn pin_token_authenticate_widths_and_values() {
    let session = session(PinUvAuthProtocol::V1);
    let mut op = get_pin_token(&session, b"1234", None, OperationOptions::default()).unwrap();
    begin(&mut op);
    let token = finish(&mut op, &token_payload(TOKEN_CT_V1));
    let message = [0x5au8; 32];
    let v1 = token.authenticate(PinUvAuthProtocol::V1, &message);
    assert_eq!(v1.len(), 16);
    assert_eq!(v1.as_bytes(), &hex(TOKEN_AUTH_V1));
    let v2 = token.authenticate(PinUvAuthProtocol::V2, &message);
    assert_eq!(v2.len(), 32);
    assert_eq!(v2.as_bytes(), &hex(TOKEN_AUTH_V2));
}

// ----------------------------------------------------------------- redaction

#[test]
fn debug_redacts_all_key_material() {
    let session = session(PinUvAuthProtocol::V2);
    let debug = format!("{session:?}");
    assert!(debug.contains("[REDACTED]"));
    for secret in [
        &SHARED_SECRET_V1[..32],
        &SHARED_SECRET_V2[..32],
        &SHARED_SECRET_V2[64..96],
        "31323334", // "1234"
    ] {
        assert!(!debug.contains(secret), "session debug leaks {secret}");
    }

    let mut op =
        get_pin_token(&session, b"1234", Some(&IV_V2), OperationOptions::default()).unwrap();
    begin(&mut op);
    let token: PinToken = finish(&mut op, &token_payload(TOKEN_CT_V2));
    let debug = format!("{token:?}");
    assert!(debug.contains("[REDACTED]"));
    // The token plaintext never appears in Debug output.
    assert!(!debug.contains("10111213"));
    let auth = token.authenticate(PinUvAuthProtocol::V2, &[0x5a; 32]);
    assert!(!format!("{auth:?}").contains(&TOKEN_AUTH_V2[..16]));
}
