//! Golden transcript and failure-path tests for authenticatorCredentialManagement
//! (0x0A), including the CanoKey metadata-only extension (key 0x80).
//!
//! All requests are authenticated with a fixed pinUvAuthToken (plaintext
//! 0x10..=0x2F, minted through the clientPIN fixtures shared with
//! `client_pin.rs`), so every pinUvAuthParam is deterministic. The expected
//! HMAC-SHA-256 values (protocol V1, truncated to 16 bytes) were computed
//! with an independent implementation (Python stdlib `hmac`) on 2026-09-16.
#![cfg(feature = "clientpin")]

use canokey_ctap::credmgmt::{
    delete_credential, enumerate_credentials, enumerate_rps, get_creds_metadata,
    update_user_information, CredentialEntry,
};
use canokey_ctap::{
    get_key_agreement, get_pin_token, PinToken, PinUvAuthProtocol, PublicKeyCredentialDescriptor,
    UserEntity,
};
use canokey_protocol::{
    ErrorKind, Operation, OperationLimits, OperationOptions, Phase, SecretBytes, Step,
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

const RP_ID_HASH: [u8; 32] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
];
const RP2_ID_HASH: [u8; 32] = [
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
];

/// Complete credentialManagement messages (0x0A + canonical CBOR), V1.
const MSG_METADATA: &str = "0aa3010103010450eb4968086c8226dd16fb635457f38b49";
const MSG_RPS_BEGIN: &str = "0aa3010203010450d5dc1a03a1a284cf096b59a579eaf833";
const MSG_RPS_NEXT: &str = "0aa201030301";
const MSG_CREDS_BEGIN: &str =
    "0aa4010402a1015820a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf030104504773676a0cc6ba08a3bc8ab68a19868e";
const MSG_CREDS_META: &str =
    "0aa4010402a2015820a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf1880f5030104503ffd7ae91f8e3630cd70f9f245edec40";
const MSG_CREDS_NEXT: &str = "0aa201050301";
const MSG_DELETE: &str =
    "0aa4010602a102a2626964440102030464747970656a7075626c69632d6b657903010450038bc0ba9fef742b26ce891514a2142c";
const MSG_UPDATE: &str =
    "0aa4010702a202a2626964440102030464747970656a7075626c69632d6b657903a36269644405060708646e616d6565616c6963656b646973706c61794e616d6565416c696365030104503f101861670b03d4287bc78e520e9a21";
/// MAC input for the metadata-only Begin: `[0x04] || cbor(params)`; note
/// the canonical order puts key 0x01 before key 0x80.
const CREDS_META_MAC_INPUT: &str =
    "04a2015820a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf1880f5";
const MAC_CREDS_META_V1: &str = "3ffd7ae91f8e3630cd70f9f245edec40";

/// Response payloads (after the 0x00 CTAP status byte).
const RESP_METADATA: &str = "a20103021819";
const RESP_RP_BEGIN: &str =
    "a303a26269646b6578616d706c652e636f6d646e616d65674578616d706c65045820a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf0502";
const RESP_RP_BEGIN_HUGE_TOTAL: &str =
    "a303a26269646b6578616d706c652e636f6d646e616d65674578616d706c65045820a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf051864";
/// Same Begin payload with totalRPs = 0 alongside the entry: spec-violating.
const RESP_RP_BEGIN_ZERO_TOTAL: &str =
    "a303a26269646b6578616d706c652e636f6d646e616d65674578616d706c65045820a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf0500";
const RESP_RP_NEXT: &str =
    "a203a1626964696f746865722e6f7267045820c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf";
const RESP_CRED_BEGIN: &str =
    "a606a36269644405060708646e616d6565616c6963656b646973706c61794e616d6565416c69636507a2626964440102030464747970656a7075626c69632d6b657908a50102032620012158201111111111111111111111111111111111111111111111111111111111111111225820222222222222222222222222222222222222222222222222222222222222222209020a020b58203333333333333333333333333333333333333333333333333333333333333333";
const RESP_CRED_NEXT: &str =
    "a207a2626964440908070664747970656a7075626c69632d6b657908a501020326200121582044444444444444444444444444444444444444444444444444444444444444442258205555555555555555555555555555555555555555555555555555555555555555";
/// Metadata-only response: no key 8, key 0x80 carries COSE alg -49.
const RESP_CRED_META: &str =
    "a406a26269644405060708646e616d6565616c69636507a2626964440102030464747970656a7075626c69632d6b6579090118803830";
/// Both key 8 and key 0x80 present: a consistency violation.
const RESP_CRED_BOTH: &str =
    "a407a2626964440102030464747970656a7075626c69632d6b657908a5010203262001215820111111111111111111111111111111111111111111111111111111111111111122582022222222222222222222222222222222222222222222222222222222222222220901188026";
/// Neither key 8 nor key 0x80: a consistency violation.
const RESP_CRED_NEITHER: &str = "a207a2626964440102030464747970656a7075626c69632d6b65790901";

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

fn descriptor_01020304() -> PublicKeyCredentialDescriptor {
    PublicKeyCredentialDescriptor::new("public-key", vec![0x01, 0x02, 0x03, 0x04])
}

// ------------------------------------------------------- get_creds_metadata

#[test]
fn get_creds_metadata_golden_and_parse() {
    let token = token_v1();
    let mut op =
        get_creds_metadata(&token, PinUvAuthProtocol::V1, OperationOptions::default()).unwrap();
    begin(&mut op);
    assert_command(&op, &hex(MSG_METADATA));
    assert_eq!(advance_ok(&mut op, &hex(RESP_METADATA)), Step::Done);
    let metadata = op.take_result().unwrap();
    assert_eq!(metadata.existing_resident_credentials_count, 3);
    assert_eq!(
        metadata.max_possible_remaining_resident_credentials_count,
        25
    );
}

#[test]
fn get_creds_metadata_pin_auth_invalid_keeps_raw_byte() {
    let token = token_v1();
    let mut op =
        get_creds_metadata(&token, PinUvAuthProtocol::V1, OperationOptions::default()).unwrap();
    begin(&mut op);
    let error = op.advance(&[0x33, 0x90, 0x00]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::AuthenticationFailed);
    assert_eq!(error.phase, Phase::Command);
    assert_eq!(error.application_status, Some(0x33));
}

#[test]
fn get_creds_metadata_missing_counter_is_invalid_response() {
    let token = token_v1();
    let mut op =
        get_creds_metadata(&token, PinUvAuthProtocol::V1, OperationOptions::default()).unwrap();
    begin(&mut op);
    let error = advance_missing(&mut op, &hex("a1 01 03"));
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert_eq!(error.phase, Phase::Parsing);
}

/// Advance with a successful CTAP response that must fail parsing.
fn advance_missing<T>(op: &mut Operation<T>, payload: &[u8]) -> canokey_protocol::Error {
    let mut reply = vec![0x00];
    reply.extend_from_slice(payload);
    reply.extend_from_slice(&[0x90, 0x00]);
    op.advance(&reply).unwrap_err()
}

// -------------------------------------------------------------- enumerate_rps

#[test]
fn enumerate_rps_two_rps_begin_and_get_next() {
    let token = token_v1();
    let mut op = enumerate_rps(&token, PinUvAuthProtocol::V1, OperationOptions::default()).unwrap();
    begin(&mut op);
    assert_command(&op, &hex(MSG_RPS_BEGIN));
    assert_eq!(advance_ok(&mut op, &hex(RESP_RP_BEGIN)), Step::Exchange);
    assert_command(&op, &hex(MSG_RPS_NEXT));
    assert_eq!(advance_ok(&mut op, &hex(RESP_RP_NEXT)), Step::Done);
    let entries = op.take_result().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].rp.id, "example.com");
    assert_eq!(entries[0].rp.name.as_deref(), Some("Example"));
    assert_eq!(entries[0].rp_id_hash, RP_ID_HASH);
    assert_eq!(entries[1].rp.id, "other.org");
    assert_eq!(entries[1].rp.name, None);
    assert_eq!(entries[1].rp_id_hash, RP2_ID_HASH);
}

#[test]
fn enumerate_rps_no_credentials_is_empty_not_error() {
    let token = token_v1();
    let mut op = enumerate_rps(&token, PinUvAuthProtocol::V1, OperationOptions::default()).unwrap();
    begin(&mut op);
    // CTAP2_ERR_NO_CREDENTIALS on Begin: an empty enumeration, not an error.
    assert_eq!(op.advance(&[0x2e, 0x90, 0x00]).unwrap(), Step::Done);
    assert!(op.take_result().unwrap().is_empty());
}

#[test]
fn enumerate_rps_absurd_total_hits_limit_exceeded() {
    let token = token_v1();
    // Budget for SELECT + Begin + one GetNext only.
    let options = OperationOptions {
        limits: OperationLimits {
            max_exchanges: 3,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut op = enumerate_rps(&token, PinUvAuthProtocol::V1, options).unwrap();
    begin(&mut op);
    assert_command(&op, &hex(MSG_RPS_BEGIN));
    let error = advance_missing(&mut op, &hex(RESP_RP_BEGIN_HUGE_TOTAL));
    assert_eq!(error.kind, ErrorKind::LimitExceeded);
    assert_eq!(error.phase, Phase::Parsing);
}

#[test]
fn enumerate_rps_zero_total_with_entry_is_invalid_response() {
    let token = token_v1();
    let mut op = enumerate_rps(&token, PinUvAuthProtocol::V1, OperationOptions::default()).unwrap();
    begin(&mut op);
    assert_command(&op, &hex(MSG_RPS_BEGIN));
    // A successful Begin reporting totalRPs = 0 alongside a parseable entry
    // violates the CTAP2 contract and must not silently return the entry.
    let error = advance_missing(&mut op, &hex(RESP_RP_BEGIN_ZERO_TOTAL));
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert_eq!(error.phase, Phase::Parsing);
}

// ----------------------------------------------------- enumerate_credentials

#[test]
fn enumerate_credentials_standard_mode_begin_and_get_next() {
    let token = token_v1();
    let mut op = enumerate_credentials(
        &token,
        PinUvAuthProtocol::V1,
        RP_ID_HASH,
        false,
        OperationOptions::default(),
    )
    .unwrap();
    begin(&mut op);
    assert_command(&op, &hex(MSG_CREDS_BEGIN));
    assert_eq!(advance_ok(&mut op, &hex(RESP_CRED_BEGIN)), Step::Exchange);
    assert_command(&op, &hex(MSG_CREDS_NEXT));
    assert_eq!(advance_ok(&mut op, &hex(RESP_CRED_NEXT)), Step::Done);
    let entries = op.take_result().unwrap();
    assert_eq!(entries.len(), 2);

    let first = &entries[0];
    let user = first.user.as_ref().expect("user entity");
    assert_eq!(user.id, [0x05, 0x06, 0x07, 0x08]);
    assert_eq!(user.name.as_deref(), Some("alice"));
    assert_eq!(user.display_name.as_deref(), Some("Alice"));
    assert_eq!(first.credential_id.id, [0x01, 0x02, 0x03, 0x04]);
    assert_eq!(first.credential_id.type_, "public-key");
    let key = first.public_key.as_ref().expect("public key");
    assert_eq!(key.algorithm().map(|a| a.id()), Some(-7));
    assert_eq!(first.cred_protect, Some(2));
    assert_eq!(
        first.large_blob_key.as_ref().map(SecretBytes::as_bytes),
        Some(&[0x33; 32][..])
    );
    assert_eq!(first.cose_algorithm, None);

    let second = &entries[1];
    assert_eq!(second.user, None);
    assert_eq!(second.credential_id.id, [0x09, 0x08, 0x07, 0x06]);
    assert!(second.public_key.is_some());
    assert_eq!(second.cred_protect, None);
    assert!(second.large_blob_key.is_none());
    assert_eq!(second.cose_algorithm, None);
}

#[test]
fn enumerate_credentials_metadata_only_extension() {
    let token = token_v1();
    let mut op = enumerate_credentials(
        &token,
        PinUvAuthProtocol::V1,
        RP_ID_HASH,
        true,
        OperationOptions::default(),
    )
    .unwrap();
    begin(&mut op);
    // Exact request bytes: params `{0x01: rpIdHash, 0x80: true}` with key
    // 0x80 encoded `18 80` after key 0x01 (canonical order), and the MAC
    // covering the full parameter map including key 0x80.
    assert_command(&op, &hex(MSG_CREDS_META));
    assert_eq!(advance_ok(&mut op, &hex(RESP_CRED_META)), Step::Done);
    let entries = op.take_result().unwrap();
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    // Metadata-only: no publicKey (8), the raw COSE alg id under key 0x80.
    assert_eq!(entry.public_key, None);
    assert_eq!(entry.cose_algorithm, Some(-49));
    assert_eq!(entry.credential_id.id, [0x01, 0x02, 0x03, 0x04]);
    assert_eq!(
        entry.user.as_ref().and_then(|u| u.name.as_deref()),
        Some("alice")
    );
}

#[test]
fn pin_uv_auth_param_covers_subcommand_and_params_cbor() {
    let token = token_v1();
    let mac = token.authenticate(PinUvAuthProtocol::V1, &hex(CREDS_META_MAC_INPUT));
    // Protocol V1 truncates HMAC-SHA-256 to 16 bytes.
    assert_eq!(mac.len(), 16);
    assert_eq!(mac.as_bytes(), &hex(MAC_CREDS_META_V1));
}

#[test]
fn credential_entry_rejects_inconsistent_key_forms() {
    for (name, payload) in [
        ("both publicKey and coseAlgorithm", RESP_CRED_BOTH),
        ("neither publicKey nor coseAlgorithm", RESP_CRED_NEITHER),
    ] {
        let token = token_v1();
        let mut op = enumerate_credentials(
            &token,
            PinUvAuthProtocol::V1,
            RP_ID_HASH,
            false,
            OperationOptions::default(),
        )
        .unwrap();
        begin(&mut op);
        let error = advance_missing(&mut op, &hex(payload));
        assert_eq!(error.kind, ErrorKind::InvalidResponse, "{name}");
        assert_eq!(error.phase, Phase::Parsing, "{name}");
    }
}

// --------------------------------------------------------- delete_credential

#[test]
fn delete_credential_golden() {
    let token = token_v1();
    let mut op = delete_credential(
        &token,
        PinUvAuthProtocol::V1,
        &descriptor_01020304(),
        OperationOptions::default(),
    )
    .unwrap();
    begin(&mut op);
    assert_command(&op, &hex(MSG_DELETE));
    assert_eq!(advance_ok(&mut op, &[]), Step::Done);
    op.take_result().unwrap();
}

#[test]
fn delete_credential_rejects_empty_id_before_io() {
    let token = token_v1();
    let descriptor = PublicKeyCredentialDescriptor::new("public-key", Vec::new());
    let error = delete_credential(
        &token,
        PinUvAuthProtocol::V1,
        &descriptor,
        OperationOptions::default(),
    )
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidArgument);
}

// --------------------------------------------------- update_user_information

#[test]
fn update_user_information_golden() {
    let token = token_v1();
    let user = UserEntity {
        id: vec![0x05, 0x06, 0x07, 0x08],
        name: Some("alice".to_owned()),
        display_name: Some("Alice".to_owned()),
    };
    let mut op = update_user_information(
        &token,
        PinUvAuthProtocol::V1,
        &descriptor_01020304(),
        &user,
        OperationOptions::default(),
    )
    .unwrap();
    begin(&mut op);
    assert_command(&op, &hex(MSG_UPDATE));
    assert_eq!(advance_ok(&mut op, &[]), Step::Done);
    op.take_result().unwrap();
}

#[test]
fn update_user_information_rejects_invalid_user_id_before_io() {
    let token = token_v1();
    for id in [Vec::new(), vec![0x42; 65]] {
        let user = UserEntity {
            id,
            name: None,
            display_name: None,
        };
        let error = update_user_information(
            &token,
            PinUvAuthProtocol::V1,
            &descriptor_01020304(),
            &user,
            OperationOptions::default(),
        )
        .unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidArgument);
    }
}

// ------------------------------------------------------------------ redaction

#[test]
fn debug_redacts_large_blob_key() {
    let entry = CredentialEntry {
        user: None,
        credential_id: descriptor_01020304(),
        public_key: None,
        cred_protect: None,
        large_blob_key: Some(SecretBytes::new(vec![0xde, 0xad, 0xbe, 0xef])),
        cose_algorithm: Some(-7),
    };
    let debug = format!("{entry:?}");
    assert!(debug.contains("[REDACTED]"));
    for leaked in ["222", "173", "190", "239"] {
        assert!(!debug.contains(leaked), "debug leaks largeBlobKey: {debug}");
    }
}
