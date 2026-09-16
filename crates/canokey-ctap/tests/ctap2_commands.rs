//! Transcript tests for the CTAP2 command layer: exact command bytes
//! (including canonical CBOR payloads) and typed response parsing from
//! canned card responses.
use canokey_ctap::cbor::Value;
use canokey_ctap::cose::CoseAlgorithm;
use canokey_ctap::{
    get_assertion, get_info, get_next_assertion, make_credential, reset, selection,
    GetAssertionParams, MakeCredentialParams, PinUvAuth, PinUvAuthProtocol,
    PublicKeyCredentialDescriptor, RelyingParty, UserEntity,
};
use canokey_protocol::{ErrorKind, ExchangeOptions, Operation, OperationOptions, Phase, Step};

const SELECT: [u8; 13] = [
    0x00, 0xa4, 0x04, 0x00, 0x08, 0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01,
];
const AAGUID: &str = "244eb29ee0904e4981fe1f20f8d3b8f4";

/// Decode a hex string, ignoring whitespace.
fn hex(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
        .collect()
}

fn large_response_options() -> OperationOptions {
    OperationOptions {
        exchange: ExchangeOptions {
            max_response_bytes: 1024,
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Drive the mandatory SELECT and advance to the CTAP command.
fn begin<T>(op: &mut Operation<T>) {
    assert_eq!(op.start().unwrap(), Step::Exchange);
    assert_eq!(op.command().unwrap().as_bytes(), &SELECT);
    assert_eq!(op.advance(&[0x90, 0x00]).unwrap(), Step::Exchange);
}

fn assert_command(op: &Operation<impl Sized>, message: &[u8]) {
    let mut expected = vec![0x80, 0x10, 0x00, 0x00, message.len() as u8];
    expected.extend_from_slice(message);
    assert!(message.len() <= 255, "fixture must use short Lc");
    assert_eq!(op.command().unwrap().as_bytes(), &expected);
}

// ------------------------------------------------------------ get_info ----

/// A CanoKey 3.1.0-shaped authenticatorGetInfo response payload: versions
/// [U2F_V2, FIDO_2_0, FIDO_2_1, FIDO_2_3], seven extensions, nine options,
/// pinUvAuthProtocols [1, 2], transports [nfc, usb], and four algorithms
/// including ML-DSA-65 (-49) and the SM2 default (-54).
fn get_info_payload() -> Vec<u8> {
    hex("b1")
        .into_iter()
        .chain(hex(
            // 1: versions
            "01 84 665532465f5632 684649444f5f325f30 684649444f5f325f31 684649444f5f325f33",
        ))
        .chain(hex(
            // 2: extensions
            "02 87 6863726564426c6f62 6b6372656450726f74656374 6b686d61632d736563726574
         6e686d61632d7365637265742d6d63 6c6c61726765426c6f624b6579 6c6d696e50696e4c656e677468
         71746869726450617274795061796d656e74",
        ))
        .chain(hex(&format!("03 50 {AAGUID}")))
        .chain(hex(
            // 4: options (canonical key order)
            "04 a9 62726bf5 68616c776179735576f4 68637265644d676d74f5 69617574686e72436667f5
         69636c69656e7450696ef4 6a6c61726765426c6f6273f5 6e70696e557641757468546f6b656ef5
         6f7365744d696e50494e4c656e677468f5 706d616b654372656455764e6f74527164f5",
        ))
        .chain(hex("05 1904b0")) // 5: maxMsgSize 1200
        .chain(hex("06 82 01 02")) // 6: pinUvAuthProtocols [1, 2]
        .chain(hex("07 10")) // 7: maxCredentialCountInList 16
        .chain(hex("08 1880")) // 8: maxCredentialIdLength 128
        .chain(hex("09 82 636e6663 63757362")) // 9: transports [nfc, usb]
        .chain(hex(
            // 10: algorithms ES256, EdDSA, ML-DSA-65, SM2
            "0a 84
         a263616c672664747970656a7075626c69632d6b6579
         a263616c672764747970656a7075626c69632d6b6579
         a263616c67383064747970656a7075626c69632d6b6579
         a263616c67383564747970656a7075626c69632d6b6579",
        ))
        .chain(hex("0b 191000")) // 11: maxSerializedLargeBlobArray 4096
        .chain(hex("0d 04")) // 13: minPinLength 4
        .chain(hex("0e 1a00030100")) // 14: firmwareVersion 3.1.0
        .chain(hex("0f 1820")) // 15: maxCredBlobLength 32
        .chain(hex("10 04")) // 16: maxRPIDsForSetMinPINLength 4
        .chain(hex("14 1864")) // 20: remainingDiscoverableCredentials 100
        .chain(hex("15 81 1840")) // 21: vendorPrototypeConfigCommands [0x40]
        .collect()
}

#[test]
fn get_info_golden_command_and_full_typed_parse() {
    let mut op = get_info(large_response_options()).unwrap();
    begin(&mut op);
    assert_command(&op, &[0x04]);
    let mut reply = vec![0x00];
    reply.extend_from_slice(&get_info_payload());
    reply.extend_from_slice(&[0x90, 0x00]);
    assert_eq!(op.advance(&reply).unwrap(), Step::Done);
    let info = op.take_result().unwrap();

    assert_eq!(
        info.versions(),
        &["U2F_V2", "FIDO_2_0", "FIDO_2_1", "FIDO_2_3"]
    );
    assert_eq!(info.aaguid(), &hex(AAGUID)[..]);
    let extensions = info.extensions().unwrap();
    assert_eq!(extensions.len(), 7);
    assert!(extensions.contains(&"hmac-secret".to_owned()));
    assert!(extensions.contains(&"thirdPartyPayment".to_owned()));
    let options = info.options().unwrap();
    assert_eq!(options.len(), 9);
    assert_eq!(options[0], ("rk".to_owned(), true));
    assert!(options.contains(&("alwaysUv".to_owned(), false)));
    assert!(options.contains(&("clientPin".to_owned(), false)));
    assert!(options.contains(&("pinUvAuthToken".to_owned(), true)));
    assert_eq!(info.max_msg_size(), Some(1200));
    assert_eq!(info.pin_uv_auth_protocols(), Some(&[1, 2][..]));
    assert_eq!(PinUvAuthProtocol::from_u8(1), Some(PinUvAuthProtocol::V1));
    assert_eq!(PinUvAuthProtocol::from_u8(2), Some(PinUvAuthProtocol::V2));
    assert_eq!(PinUvAuthProtocol::from_u8(3), None);
    assert_eq!(PinUvAuthProtocol::V2.to_u8(), 2);
    assert_eq!(info.max_credential_count_in_list(), Some(16));
    assert_eq!(info.max_credential_id_length(), Some(128));
    assert_eq!(
        info.transports(),
        Some(&["nfc".to_owned(), "usb".to_owned()][..])
    );
    let algorithms = info.algorithms().unwrap();
    assert_eq!(algorithms.len(), 4);
    assert!(algorithms.iter().all(|p| p.type_ == "public-key"));
    assert_eq!(
        algorithms.iter().map(|p| p.alg).collect::<Vec<_>>(),
        [-7, -8, -49, -54]
    );
    assert_eq!(algorithms[0].algorithm(), CoseAlgorithm::Es256);
    assert_eq!(algorithms[2].algorithm(), CoseAlgorithm::MlDsa65);
    assert_eq!(algorithms[3].algorithm(), CoseAlgorithm::Unknown(-54));
    assert_eq!(info.max_serialized_large_blob_array(), Some(4096));
    assert_eq!(info.force_pin_change(), None);
    assert_eq!(info.min_pin_length(), Some(4));
    assert_eq!(info.firmware_version(), Some(0x0003_0100));
    assert_eq!(info.max_cred_blob_length(), Some(32));
    assert_eq!(info.max_rp_ids_for_set_min_pin_length(), Some(4));
    assert_eq!(info.remaining_discoverable_credentials(), Some(100));
    assert_eq!(info.vendor_prototype_config_commands(), Some(&[0x40][..]));
    // The raw map is retained with all 17 entries.
    assert_eq!(info.raw().as_map().unwrap().len(), 17);
}

#[test]
fn get_info_missing_versions_rejected() {
    let mut op = get_info(large_response_options()).unwrap();
    begin(&mut op);
    // Map with only aaguid (key 3); versions (key 1) is required.
    let mut reply = hex(&format!("00 a1 03 50 {AAGUID}"));
    reply.extend_from_slice(&[0x90, 0x00]);
    let error = op.advance(&reply).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert_eq!(error.phase, Phase::Parsing);
}

#[test]
fn get_info_trailing_bytes_rejected() {
    let mut op = get_info(large_response_options()).unwrap();
    begin(&mut op);
    // Valid minimal map {1: ["FIDO_2_0"], 3: aaguid} plus one trailing byte.
    let mut reply = hex(&format!("00 a2 01 81 684649444f5f325f30 03 50 {AAGUID} 00"));
    reply.extend_from_slice(&[0x90, 0x00]);
    let error = op.advance(&reply).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert_eq!(error.phase, Phase::Parsing);
}

// ----------------------------------------------------- make_credential ----

fn make_credential_params() -> MakeCredentialParams {
    let mut params = MakeCredentialParams::new(
        [0xaa; 32],
        RelyingParty {
            id: "example.com".to_owned(),
            name: Some("Example".to_owned()),
        },
        UserEntity {
            id: vec![0x01, 0x02, 0x03, 0x04],
            name: Some("user".to_owned()),
            display_name: Some("User".to_owned()),
        },
        vec![CoseAlgorithm::Es256, CoseAlgorithm::MlDsa65],
    );
    params.exclude_list = vec![PublicKeyCredentialDescriptor {
        type_: "public-key".to_owned(),
        id: vec![0xbb; 4],
        transports: vec!["nfc".to_owned()],
    }];
    params.extensions = vec![("hmac-secret".to_owned(), Value::Bool(true))];
    params.options = vec![("rk".to_owned(), true)];
    params.pin_uv_auth = Some(PinUvAuth::new(PinUvAuthProtocol::V1, &[0xcc; 16]).unwrap());
    params
}

/// Expected canonical CBOR of the makeCredential request map built by
/// [`make_credential_params`].
fn make_credential_message() -> Vec<u8> {
    let mut message = vec![0x01];
    message.extend_from_slice(&hex("a9
         01 5820 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
         02 a2 626964 6b6578616d706c652e636f6d 646e616d65 674578616d706c65
         03 a3 626964 4401020304 646e616d65 6475736572 6b646973706c61794e616d65 6455736572
         04 82 a263616c672664747970656a7075626c69632d6b6579
                a263616c67383064747970656a7075626c69632d6b6579
         05 81 a362696444bbbbbbbb64747970656a7075626c69632d6b65796a7472616e73706f72747381636e6663
         06 a1 6b686d61632d736563726574 f5
         07 a1 62726b f5
         08 50 cccccccccccccccccccccccccccccccc
         09 01"));
    message
}

/// authenticatorData with UP|AT|ED flags, a P-256 credential public key and
/// a credProtect extension.
fn attested_auth_data() -> Vec<u8> {
    hex(
        "1111111111111111111111111111111111111111111111111111111111111111
         c1 0000002a
         244eb29ee0904e4981fe1f20f8d3b8f4
         0004 01020304
         a5 0102 0326 2001 215820 0202020202020202020202020202020202020202020202020202020202020202
            225820 0303030303030303030303030303030303030303030303030303030303030303
         a1 6b6372656450726f74656374 02",
    )
}

#[test]
fn make_credential_golden_command_and_typed_response() {
    let mut op = make_credential(make_credential_params(), OperationOptions::default()).unwrap();
    begin(&mut op);
    assert_command(&op, &make_credential_message());

    // Response: {"fmt": "packed", authData, attStmt, epAtt: false,
    // largeBlobKey: 32 bytes}.
    let auth_data = attested_auth_data();
    assert_eq!(auth_data.len(), 0x96);
    let mut reply = hex("00 a5 01 667061636b6564 02 5896");
    reply.extend_from_slice(&auth_data);
    reply.extend_from_slice(&hex(
        "03 a3 63616c67 26 63736967 4401020304 63783563 8143aabbcc
         04 f4
         05 5820 7777777777777777777777777777777777777777777777777777777777777777",
    ));
    reply.extend_from_slice(&[0x90, 0x00]);
    assert_eq!(op.advance(&reply).unwrap(), Step::Done);
    let response = op.take_result().unwrap();

    assert_eq!(response.fmt(), "packed");
    let parsed = response.auth_data();
    assert!(parsed.user_present());
    assert!(parsed.flags() & 0x40 != 0, "AT flag");
    assert!(parsed.flags() & 0x80 != 0, "ED flag");
    assert_eq!(parsed.sign_count(), 42);
    assert_eq!(parsed.raw(), &auth_data[..]);
    let attested = parsed.attested_credential_data().unwrap();
    assert_eq!(attested.aaguid(), &hex(AAGUID)[..]);
    assert_eq!(attested.credential_id(), &[0x01, 0x02, 0x03, 0x04]);
    assert_eq!(
        attested.credential_public_key().algorithm(),
        Some(CoseAlgorithm::Es256)
    );
    let extensions = parsed.extensions().unwrap();
    assert_eq!(
        extensions.map_get_text("credProtect"),
        Some(&Value::Unsigned(2))
    );
    // attStmt is retained raw with text keys.
    let att_stmt = response.att_stmt();
    assert_eq!(att_stmt.map_get_text("alg"), Some(&Value::from_int(-7)));
    assert_eq!(
        att_stmt.map_get_text("sig"),
        Some(&Value::Bytes(vec![0x01, 0x02, 0x03, 0x04]))
    );
    assert_eq!(response.ep_att(), Some(false));
    assert_eq!(response.large_blob_key().unwrap().as_bytes(), &[0x77; 32]);
}

#[test]
fn make_credential_credential_excluded_status_is_classified() {
    let mut op = make_credential(make_credential_params(), OperationOptions::default()).unwrap();
    begin(&mut op);
    let error = op.advance(&[0x19, 0x90, 0x00]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::ConditionsNotSatisfied);
    assert_eq!(error.phase, Phase::Command);
    // CTAP-level failures carry the raw CTAP status byte, not an ISO word.
    assert_eq!(error.status_word.unwrap().raw(), 0x19);
}

#[test]
fn make_credential_invalid_arguments_fail_before_io() {
    let valid = make_credential_params;
    let cases: Vec<MakeCredentialParams> = vec![
        {
            let mut p = valid();
            p.rp.id = String::new();
            p
        },
        {
            let mut p = valid();
            p.user.id = Vec::new();
            p
        },
        {
            let mut p = valid();
            p.user.id = vec![0x00; 65];
            p
        },
        {
            let mut p = valid();
            p.pub_key_cred_params = Vec::new();
            p
        },
        {
            let mut p = valid();
            p.enterprise_attestation = Some(3);
            p
        },
    ];
    for params in cases {
        let error = make_credential(params, OperationOptions::default()).unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidArgument);
    }
    // pinUvAuthParam widths other than 16/32 are rejected at construction.
    for len in [0usize, 15, 17, 31, 33] {
        let error = PinUvAuth::new(PinUvAuthProtocol::V2, &vec![0x00; len]).unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidArgument, "len {len}");
    }
}

// ------------------------------------------------------- get_assertion ----

fn get_assertion_params() -> GetAssertionParams {
    let mut params = GetAssertionParams::new("example.com", [0xdd; 32]);
    params.allow_list = vec![PublicKeyCredentialDescriptor::new(
        "public-key",
        vec![0xee; 8],
    )];
    params.options = vec![("up".to_owned(), true)];
    params.pin_uv_auth = Some(PinUvAuth::new(PinUvAuthProtocol::V2, &[0x99; 32]).unwrap());
    params
}

fn get_assertion_message() -> Vec<u8> {
    let mut message = vec![0x02];
    message.extend_from_slice(&hex("a6
         01 6b6578616d706c652e636f6d
         02 5820 dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
         03 81 a262696448eeeeeeeeeeeeeeee64747970656a7075626c69632d6b6579
         05 a1 627570 f5
         06 5820 9999999999999999999999999999999999999999999999999999999999999999
         07 02"));
    message
}

/// Assertion authenticatorData without AT/ED sections (UP, signCount 1).
fn assertion_auth_data() -> Vec<u8> {
    hex("2222222222222222222222222222222222222222222222222222222222222222 01 00000001")
}

/// A getAssertion response payload with descriptor, user and
/// numberOfCredentials = 2.
fn get_assertion_payload() -> Vec<u8> {
    let mut payload =
        hex("a5 01 a262696448eeeeeeeeeeeeeeee64747970656a7075626c69632d6b6579 02 5825");
    payload.extend_from_slice(&assertion_auth_data());
    payload.extend_from_slice(&hex(
        "03 5840 5555555555555555555555555555555555555555555555555555555555555555
         5555555555555555555555555555555555555555555555555555555555555555
         04 a2 626964 420102 646e616d65 6475736572
         05 02",
    ));
    payload
}

#[test]
fn get_assertion_golden_command_and_typed_response() {
    let mut op = get_assertion(get_assertion_params(), OperationOptions::default()).unwrap();
    begin(&mut op);
    assert_command(&op, &get_assertion_message());

    let mut reply = vec![0x00];
    reply.extend_from_slice(&get_assertion_payload());
    reply.extend_from_slice(&[0x90, 0x00]);
    assert_eq!(op.advance(&reply).unwrap(), Step::Done);
    let response = op.take_result().unwrap();

    let credential = response.credential().unwrap();
    assert_eq!(credential.type_, "public-key");
    assert_eq!(credential.id, vec![0xee; 8]);
    assert!(credential.transports.is_empty());
    assert!(response.auth_data().user_present());
    assert!(!response.auth_data().user_verified());
    assert_eq!(response.auth_data().sign_count(), 1);
    assert_eq!(response.signature().as_bytes(), &[0x55; 64]);
    let user = response.user().unwrap();
    assert_eq!(user.id, vec![0x01, 0x02]);
    assert_eq!(user.name.as_deref(), Some("user"));
    assert_eq!(user.display_name, None);
    // Two credentials: the caller must drive get_next_assertion once more.
    assert_eq!(response.number_of_credentials(), Some(2));
    assert_eq!(response.user_selected(), None);
    assert!(response.large_blob_key().is_none());
}

#[test]
fn get_assertion_no_credentials_status_is_not_found() {
    let mut op = get_assertion(get_assertion_params(), OperationOptions::default()).unwrap();
    begin(&mut op);
    let error = op.advance(&[0x2e, 0x90, 0x00]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::NotFound);
    assert_eq!(error.phase, Phase::Command);
    assert_eq!(error.status_word.unwrap().raw(), 0x2e);
}

#[test]
fn get_assertion_empty_rp_id_rejected_before_io() {
    let params = GetAssertionParams::new("", [0xdd; 32]);
    let error = get_assertion(params, OperationOptions::default()).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidArgument);
}

#[test]
fn get_next_assertion_golden_command_and_minimal_response() {
    let mut op = get_next_assertion(OperationOptions::default()).unwrap();
    begin(&mut op);
    assert_command(&op, &[0x08]);

    // Minimal response: only the required authData and signature members.
    let mut reply = hex("00 a2 02 5825");
    reply.extend_from_slice(&assertion_auth_data());
    reply.extend_from_slice(&hex("03 5840"));
    reply.extend_from_slice(&[0xab; 64]);
    reply.extend_from_slice(&[0x90, 0x00]);
    assert_eq!(op.advance(&reply).unwrap(), Step::Done);
    let response = op.take_result().unwrap();
    assert!(response.credential().is_none());
    assert_eq!(response.number_of_credentials(), None);
    assert_eq!(response.signature().as_bytes(), &[0xab; 64]);
}

// ------------------------------------------------------ reset/selection ----

#[test]
fn reset_golden_command_and_empty_success() {
    let mut op = reset(OperationOptions::default()).unwrap();
    begin(&mut op);
    assert_command(&op, &[0x07]);
    assert_eq!(op.advance(&[0x00, 0x90, 0x00]).unwrap(), Step::Done);
    op.take_result().unwrap();
}

#[test]
fn reset_non_empty_response_is_invalid() {
    let mut op = reset(OperationOptions::default()).unwrap();
    begin(&mut op);
    let error = op.advance(&[0x00, 0xa0, 0x90, 0x00]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert_eq!(error.phase, Phase::Parsing);
}

#[test]
fn selection_golden_command_and_empty_success() {
    let mut op = selection(OperationOptions::default()).unwrap();
    begin(&mut op);
    assert_command(&op, &[0x0b]);
    assert_eq!(op.advance(&[0x00, 0x90, 0x00]).unwrap(), Step::Done);
    op.take_result().unwrap();
}

// ------------------------------------------------------------ redaction ----

#[test]
fn debug_redacts_pin_uv_auth_param_and_signature_material() {
    let params = make_credential_params();
    let debug = format!("{params:?}");
    assert!(debug.contains("REDACTED"));
    assert!(
        !debug.contains("204"),
        "pinUvAuthParam bytes (0xcc) leaked: {debug}"
    );

    let mut op = get_next_assertion(OperationOptions::default()).unwrap();
    begin(&mut op);
    // Response carrying signature 0xab*64 and largeBlobKey 0x55*32.
    let mut reply = hex("00 a3 02 5825");
    reply.extend_from_slice(&assertion_auth_data());
    reply.extend_from_slice(&hex("03 5840"));
    reply.extend_from_slice(&[0xab; 64]);
    reply.extend_from_slice(&hex("07 5820"));
    reply.extend_from_slice(&[0x55; 32]);
    reply.extend_from_slice(&[0x90, 0x00]);
    assert_eq!(op.advance(&reply).unwrap(), Step::Done);
    let response = op.take_result().unwrap();
    assert_eq!(response.large_blob_key().unwrap().as_bytes(), &[0x55; 32]);
    let debug = format!("{response:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("171"), "signature bytes (0xab) leaked");
    assert!(!debug.contains("85"), "largeBlobKey bytes (0x55) leaked");
}
