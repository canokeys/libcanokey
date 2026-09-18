//! Golden transcript and failure-path tests for the hmac-secret extension
//! (CTAP 2.x) and the CanoKey hmac-secret-mc makeCredential variant.
//!
//! All crypto vectors are self-generated on 2026-09-16 from the fixed
//! fixtures below (the same platform ephemeral scalar 0x01..=0x20 and peer
//! scalar 0xA0..=0xBF as tests/client_pin.rs, salts 0x30..=0x4F and
//! 0x50..=0x6F, V2 IV 0x0F..0x00, device V2 output IV 0x20..=0x2F) and
//! cross-checked against an independent implementation (Python
//! `cryptography`: P-256 ECDH, HKDF-SHA-256, AES-256-CBC; stdlib
//! HMAC-SHA-256) on the same date.

use canokey_ctap::cose::CoseAlgorithm;
#[cfg(feature = "clientpin")]
use canokey_ctap::PinUvAuthProtocol;
#[cfg(feature = "clientpin")]
use canokey_ctap::{get_assertion, GetAssertionParams};
use canokey_ctap::{make_credential, MakeCredentialParams, RelyingParty, UserEntity};
#[cfg(feature = "clientpin")]
use canokey_ctap::{HmacSecretInput, HmacSecretSalts};
#[cfg(feature = "clientpin")]
use canokey_protocol::Operation;
#[cfg(feature = "clientpin")]
use canokey_protocol::Phase;
use canokey_protocol::{ErrorKind, OperationOptions};

mod support;

use support::{assert_command, begin, finish, hex};
#[cfg(feature = "clientpin")]
use support::{finish_err, session, IV_V2};

/// Salt fixtures: salt1 = 0x30..=0x4F, salt2 = 0x50..=0x6F.
#[cfg(feature = "clientpin")]
const SALT1: [u8; 32] = [
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
];
#[cfg(feature = "clientpin")]
const SALT2: [u8; 32] = [
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
];
/// Authenticator output plaintext fixtures: one-salt 0x70..=0x8F, two-salt
/// 0x70..=0xAF.
#[cfg(feature = "clientpin")]
const OUTPUT_ONE: [u8; 32] = [
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
];
#[cfg(feature = "clientpin")]
const OUTPUT_TWO: [u8; 64] = [
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
];

/// Options permitting extended APDU encoding, for exchange inputs whose
/// messages exceed the 255-byte short-Lc limit.
#[cfg(feature = "clientpin")]
fn extended_options() -> OperationOptions {
    OperationOptions {
        exchange: canokey_protocol::ExchangeOptions {
            allow_extended: true,
            max_command_bytes: 1024,
            max_response_bytes: 1024,
        },
        ..Default::default()
    }
}

/// Assert the wrapped command bytes with extended Lc:
/// `80 10 00 00 00 <Lc hi> <Lc lo> <message>`.
#[cfg(feature = "clientpin")]
fn assert_command_extended(op: &Operation<impl Sized>, message: &[u8]) {
    let mut expected = vec![0x80, 0x10, 0x00, 0x00, 0x00];
    expected.extend_from_slice(&(message.len() as u16).to_be_bytes());
    expected.extend_from_slice(message);
    assert!(
        message.len() > 255 && message.len() <= 65535,
        "fixture must use extended Lc"
    );
    assert_eq!(op.command().unwrap().as_bytes(), &expected);
}

/// The minimal makeCredential parameter set used by the goldens:
/// clientDataHash 0xAA*32, rp "example.com", user id 01..04, ES256 only.
fn mc_params() -> MakeCredentialParams {
    MakeCredentialParams::new(
        [0xaa; 32],
        RelyingParty {
            id: "example.com".to_owned(),
            name: None,
        },
        UserEntity {
            id: vec![0x01, 0x02, 0x03, 0x04],
            name: None,
            display_name: None,
        },
        vec![CoseAlgorithm::Es256],
    )
}

/// The attested credential data section (AAGUID, credential id 01..04, P-256
/// credential key 0x02*/0x03*) shared by the authData fixtures.
const AT_SECTION: &str = "244eb29ee0904e4981fe1f20f8d3b8f4000401020304a501020326200121582002020202020202020202020202020202020202020202020202020202020202022258200303030303030303030303030303030303030303030303030303030303030303";

/// An authenticatorMakeCredential response payload `{1: "none",
/// 2: authData, 3: {}}` whose authData has UP|AT|ED flags, the AT section
/// above, and the given ED extensions CBOR map (empty slice: no ED flag).
fn mc_response(extensions: &str) -> Vec<u8> {
    let mut auth_data = hex("1111111111111111111111111111111111111111111111111111111111111111");
    if extensions.is_empty() {
        auth_data.push(0x41); // UP | AT
    } else {
        auth_data.push(0xc1); // UP | AT | ED
    }
    auth_data.extend_from_slice(&hex("0000002a"));
    auth_data.extend_from_slice(&hex(AT_SECTION));
    auth_data.extend_from_slice(&hex(extensions));
    let mut payload = hex("a3 01 646e6f6e65 02");
    payload.push(0x58);
    payload.push(auth_data.len() as u8);
    payload.extend_from_slice(&auth_data);
    payload.extend_from_slice(&hex("03 a0"));
    payload
}

// --------------------------------------------- makeCredential declaration

#[test]
fn mc_hmac_secret_declaration_golden() {
    let mut params = mc_params();
    params.hmac_secret = true;
    let mut op = make_credential(params, OperationOptions::default()).unwrap();
    begin(&mut op);
    assert_command(
        &op,
        &hex("01 a5
             01 5820 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
             02 a1 626964 6b6578616d706c652e636f6d
             03 a1 626964 4401020304
             04 81 a263616c672664747970656a7075626c69632d6b6579
             06 a1 6b686d61632d736563726574 f5"),
    );
    // authData ED extensions: {"hmac-secret": true}.
    let response = finish(&mut op, &mc_response("a1 6b686d61632d736563726574 f5"));
    assert!(response.hmac_secret_supported());
    assert_eq!(response.fmt(), "none");
    let extensions = response.auth_data().extensions().unwrap();
    assert_eq!(
        extensions.map_get_text("hmac-secret"),
        Some(&canokey_ctap::cbor::Value::Bool(true))
    );
}

#[test]
fn mc_hmac_secret_declaration_absent_is_not_supported() {
    let mut params = mc_params();
    params.hmac_secret = true;
    let mut op = make_credential(params, OperationOptions::default()).unwrap();
    begin(&mut op);
    // No ED flag and no extensions: the credential is not hmac-secret
    // capable.
    let response = finish(&mut op, &mc_response(""));
    assert!(!response.hmac_secret_supported());
}

#[test]
fn mc_hmac_secret_duplicate_raw_extension_rejected() {
    let mut params = mc_params();
    params.hmac_secret = true;
    params.extensions = vec![(
        "hmac-secret".to_owned(),
        canokey_ctap::cbor::Value::Bool(true),
    )];
    let error = make_credential(params, OperationOptions::default()).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidArgument);
}

// ------------------------------------------------------- salt validation

/// Salt buffers must be exactly 32 or 64 bytes; other lengths are rejected
/// before any I/O. (The per-protocol IV rule is the shared `check_iv`
/// helper, covered in client_pin.rs.)
#[cfg(feature = "clientpin")]
#[test]
fn salts_validation() {
    let error = HmacSecretSalts::new(&[0x42; 48]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidArgument);
    assert_eq!(HmacSecretSalts::one(SALT1).count(), 1);
    assert_eq!(HmacSecretSalts::two(SALT1, SALT2).count(), 2);
    assert_eq!(HmacSecretSalts::new(&[0x42; 32]).unwrap().count(), 1);
    assert_eq!(HmacSecretSalts::new(&[0x42; 64]).unwrap().count(), 2);
}

// ---------------------------------------------------- getAssertion exchange

/// GA request goldens: `{1: "example.com", 2: 0xDD*32, 4: {"hmac-secret":
/// {1: keyAgreement, 2: saltEnc, 3: saltAuth, 4: protocol}}}`.
#[cfg(feature = "clientpin")]
const GA_MSG_ONE_V1: &str = "02a3016b6578616d706c652e636f6d025820dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd04a16b686d61632d736563726574a401a501020338182001215820515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f2258204536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f935402582094eb73f07efce3095fb09feeb159b56fb43b5a5e25de8b495b353b01a2b6a2d7035004d6602ff53736ee80c042cfba93d0a60401";
#[cfg(feature = "clientpin")]
const GA_MSG_ONE_V2: &str = "02a3016b6578616d706c652e636f6d025820dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd04a16b686d61632d736563726574a401a501020338182001215820515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f2258204536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f93540258300f0e0d0c0b0a0908070605040302010038a5e4efa83a1b70f852afa222001e61e750a52490f2d02689d70d238031736f03582008294917edff707fac10f28dc42fc3acc5193582aa46e52fd9a5aea33b29645e0402";
#[cfg(feature = "clientpin")]
const GA_MSG_TWO_V1: &str = "02a3016b6578616d706c652e636f6d025820dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd04a16b686d61632d736563726574a401a501020338182001215820515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f2258204536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f935402584094eb73f07efce3095fb09feeb159b56fb43b5a5e25de8b495b353b01a2b6a2d71b624b12b9c10a46c2cf5cdb88d793879dea98fc53eb9e14aa4b9a24348752120350c3329b8aefc31d8f93caf0a3ce3a40570401";

/// GA response payloads `{2: authData, 3: 0x55*64}` with authData UP|ED and
/// extensions {"hmac-secret": <encrypted output>}.
#[cfg(feature = "clientpin")]
const GA_RESP_ONE_V1: &str = "a202585422222222222222222222222222222222222222222222222222222222222222228100000001a16b686d61632d7365637265745820aa22623dc263f9876a538f3c9e4b7f09218f9ee7dec8c47ea0fc6bd7e3ca3fe703584055555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555";
#[cfg(feature = "clientpin")]
const GA_RESP_ONE_V2: &str = "a202586422222222222222222222222222222222222222222222222222222222222222228100000001a16b686d61632d7365637265745830202122232425262728292a2b2c2d2e2f296fe5dfeabebc3fa0891701758030541269f02109435b6e32e5f34f383711e303584055555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555";
#[cfg(feature = "clientpin")]
const GA_RESP_TWO_V1: &str = "a202587422222222222222222222222222222222222222222222222222222222222222228100000001a16b686d61632d7365637265745840aa22623dc263f9876a538f3c9e4b7f09218f9ee7dec8c47ea0fc6bd7e3ca3fe7805a0082af60a45e8732db1729b509683e854572375274663fa6cd3840d88a2203584055555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555";

/// GA parameters with an hmac-secret exchange for `protocol` over `salts`.
#[cfg(feature = "clientpin")]
fn ga_params(protocol: PinUvAuthProtocol, salts: HmacSecretSalts) -> GetAssertionParams {
    let session = session(protocol);
    let iv = if protocol == PinUvAuthProtocol::V2 {
        Some(&IV_V2)
    } else {
        None
    };
    let input = HmacSecretInput::new(&session, salts, iv).unwrap();
    let mut params = GetAssertionParams::new("example.com", [0xdd; 32]);
    params.hmac_secret = Some(input);
    params
}

/// Run one GA exchange golden: request bytes must match `message`, and the
/// response `payload` must decrypt to `expected_output`. Messages over 255
/// bytes use extended-Lc encoding.
#[cfg(feature = "clientpin")]
fn ga_exchange_golden(
    protocol: PinUvAuthProtocol,
    salts: HmacSecretSalts,
    message: &str,
    payload: &str,
    expected_output: &[u8],
) {
    let message = hex(message);
    let options = if message.len() > 255 {
        extended_options()
    } else {
        OperationOptions::default()
    };
    let mut op = get_assertion(ga_params(protocol, salts), options).unwrap();
    begin(&mut op);
    if message.len() > 255 {
        assert_command_extended(&op, &message);
    } else {
        assert_command(&op, &message);
    }
    let response = finish(&mut op, &hex(payload));
    assert_eq!(response.hmac_secret().unwrap().as_bytes(), expected_output);
    assert_eq!(response.signature().as_bytes(), &[0x55; 64]);
}

#[cfg(feature = "clientpin")]
#[test]
fn ga_hmac_secret_golden_v1() {
    ga_exchange_golden(
        PinUvAuthProtocol::V1,
        HmacSecretSalts::one(SALT1),
        GA_MSG_ONE_V1,
        GA_RESP_ONE_V1,
        &OUTPUT_ONE,
    );
}

#[cfg(feature = "clientpin")]
#[test]
fn ga_hmac_secret_golden_v2() {
    ga_exchange_golden(
        PinUvAuthProtocol::V2,
        HmacSecretSalts::one(SALT1),
        GA_MSG_ONE_V2,
        GA_RESP_ONE_V2,
        &OUTPUT_ONE,
    );
}

#[cfg(feature = "clientpin")]
#[test]
fn ga_hmac_secret_golden_two_salts_v1() {
    ga_exchange_golden(
        PinUvAuthProtocol::V1,
        HmacSecretSalts::two(SALT1, SALT2),
        GA_MSG_TWO_V1,
        GA_RESP_TWO_V1,
        &OUTPUT_TWO,
    );
}

/// An exchange was requested but the response authData has no ED section:
/// the device silently dropping an accepted extension is a protocol
/// violation, surfaced as InvalidResponse.
#[cfg(feature = "clientpin")]
#[test]
fn ga_hmac_secret_missing_ed_is_invalid_response() {
    let mut op = get_assertion(
        ga_params(PinUvAuthProtocol::V1, HmacSecretSalts::one(SALT1)),
        OperationOptions::default(),
    )
    .unwrap();
    begin(&mut op);
    // authData without the ED flag: {2: authData, 3: sig}.
    let mut payload = hex("a2 02 5825");
    payload.extend_from_slice(&hex(
        "2222222222222222222222222222222222222222222222222222222222222222 01 00000001",
    ));
    payload.extend_from_slice(&hex("03 5840"));
    payload.extend_from_slice(&[0x55; 64]);
    let error = finish_err(&mut op, &payload);
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert_eq!(error.phase, Phase::Parsing);
}

/// The encrypted output must decrypt to exactly 32 or 64 bytes; any other
/// framing or length is InvalidResponse.
#[cfg(feature = "clientpin")]
#[test]
fn ga_hmac_secret_bad_ciphertext_is_invalid_response() {
    for ciphertext_len in [17usize, 48] {
        let mut op = get_assertion(
            ga_params(PinUvAuthProtocol::V1, HmacSecretSalts::one(SALT1)),
            OperationOptions::default(),
        )
        .unwrap();
        begin(&mut op);
        // authData UP|ED with {"hmac-secret": <ciphertext_len bytes>}.
        let mut auth_data =
            hex("2222222222222222222222222222222222222222222222222222222222222222 81 00000001");
        auth_data.extend_from_slice(&hex("a1 6b686d61632d736563726574"));
        auth_data.push(0x58);
        auth_data.push(ciphertext_len as u8);
        auth_data.extend_from_slice(&vec![0x42; ciphertext_len]);
        let mut payload = hex("a2 02 58");
        payload.push(auth_data.len() as u8);
        payload.extend_from_slice(&auth_data);
        payload.extend_from_slice(&hex("03 5840"));
        payload.extend_from_slice(&[0x55; 64]);
        let error = finish_err(&mut op, &payload);
        assert_eq!(
            error.kind,
            ErrorKind::InvalidResponse,
            "ciphertext len {ciphertext_len}"
        );
    }
}

/// Without a requested exchange, an (unexpected) hmac-secret output is left
/// undecoded in the authData extensions instead of failing or decrypting.
#[cfg(feature = "clientpin")]
#[test]
fn ga_hmac_secret_unrequested_output_is_passed_through() {
    let params = GetAssertionParams::new("example.com", [0xdd; 32]);
    let mut op = get_assertion(params, OperationOptions::default()).unwrap();
    begin(&mut op);
    let response = finish(&mut op, &hex(GA_RESP_ONE_V1));
    assert!(response.hmac_secret().is_none());
    let extensions = response.auth_data().extensions().unwrap();
    assert!(extensions.map_get_text("hmac-secret").is_some());
}

// ---------------------------------------------------------- hmac-secret-mc

/// MC request golden with both extension keys in canonical order:
/// "hmac-secret": true followed by "hmac-secret-mc": {1: keyAgreement,
/// 2: saltEnc, 3: saltAuth, 4: 1} (V1, two salts).
#[cfg(feature = "clientpin")]
const MC_MSG_MC_V1: &str = "01a5015820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa02a16269646b6578616d706c652e636f6d03a162696444010203040481a263616c672664747970656a7075626c69632d6b657906a26b686d61632d736563726574f56e686d61632d7365637265742d6d63a401a501020338182001215820515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f2258204536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f935402584094eb73f07efce3095fb09feeb159b56fb43b5a5e25de8b495b353b01a2b6a2d71b624b12b9c10a46c2cf5cdb88d793879dea98fc53eb9e14aa4b9a24348752120350c3329b8aefc31d8f93caf0a3ce3a40570401";

/// MC parameters with the declaration and the hmac-secret-mc exchange.
#[cfg(feature = "clientpin")]
fn mc_params_with_exchange() -> MakeCredentialParams {
    let session = session(PinUvAuthProtocol::V1);
    let input = HmacSecretInput::new(&session, HmacSecretSalts::two(SALT1, SALT2), None).unwrap();
    let mut params = mc_params();
    params.hmac_secret = true;
    params.hmac_secret_mc = Some(input);
    params
}

/// authData ED extensions of the hmac-secret-mc golden response:
/// {"hmac-secret": true, "hmac-secret-mc": <encrypted 64-byte output>}.
#[cfg(feature = "clientpin")]
const MC_EXT_MC_V1: &str = "a2 6b686d61632d736563726574 f5 6e686d61632d7365637265742d6d63 5840 aa22623dc263f9876a538f3c9e4b7f09218f9ee7dec8c47ea0fc6bd7e3ca3fe7805a0082af60a45e8732db1729b509683e854572375274663fa6cd3840d88a22";

#[cfg(feature = "clientpin")]
#[test]
fn mc_hmac_secret_mc_golden_v1() {
    let mut op = make_credential(mc_params_with_exchange(), extended_options()).unwrap();
    begin(&mut op);
    // 285 bytes: extended Lc.
    assert_command_extended(&op, &hex(MC_MSG_MC_V1));
    let response = finish(&mut op, &mc_response(MC_EXT_MC_V1));
    assert!(response.hmac_secret_supported());
    assert_eq!(response.hmac_secret_mc().unwrap().as_bytes(), &OUTPUT_TWO);
}

/// The firmware requires "hmac-secret": true alongside "hmac-secret-mc"
/// (CTAP2_ERR_MISSING_PARAMETER); the factory enforces this before any I/O.
#[cfg(feature = "clientpin")]
#[test]
fn mc_hmac_secret_mc_requires_declaration() {
    let session = session(PinUvAuthProtocol::V1);
    let input = HmacSecretInput::new(&session, HmacSecretSalts::one(SALT1), None).unwrap();
    let mut params = mc_params();
    params.hmac_secret_mc = Some(input);
    let error = make_credential(params, OperationOptions::default()).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidArgument);
}

// ------------------------------------------------------------- redaction

#[cfg(feature = "clientpin")]
#[test]
fn debug_redacts_salts_input_and_outputs() {
    let salts = HmacSecretSalts::two(SALT1, SALT2);
    let debug = format!("{salts:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("48"), "salt bytes (0x30) leaked: {debug}");

    let session = session(PinUvAuthProtocol::V1);
    let input = HmacSecretInput::new(&session, salts, None).unwrap();
    let debug = format!("{input:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("48"), "salt bytes (0x30) leaked: {debug}");

    // The decrypted exchange output in the parsed response is redacted too.
    let mut op = make_credential(mc_params_with_exchange(), extended_options()).unwrap();
    begin(&mut op);
    let response = finish(&mut op, &mc_response(MC_EXT_MC_V1));
    let debug = format!("{response:?}");
    assert!(debug.contains("REDACTED"));
    assert!(
        !debug.contains("112"),
        "output bytes (0x70) leaked: {debug}"
    );
}
