use canokey_compat::{DeviceObservations, DeviceProfile, PivApplicationVersion, Support};
use canokey_piv::*;
use canokey_protocol::{
    ErrorKind, Operation, OperationOptions, OperationState, Phase, SecretBytes, SecretReference,
    Step,
};

fn hex(s: &str) -> Vec<u8> {
    s.split_ascii_whitespace()
        .flat_map(|s| {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        })
        .collect()
}
fn profile(version: &str) -> DeviceProfile {
    let mut o = DeviceObservations::new(version.as_bytes().to_vec());
    o.piv_version = Some(PivApplicationVersion([5, 7, 0]));
    DeviceProfile::from_observations(o).unwrap()
}
struct Vector {
    algorithm: ManagementKeyAlgorithm,
    version: &'static str,
    key: &'static str,
    plain: &'static str,
    cipher: &'static str,
    encrypted_zero: &'static str,
}
// AES-192 FIPS 197 example and three-key TDEA known-answer inputs. Both directions
// and separate all-zero host challenges were cross-checked with OpenSSL 3 enc.
const VECTORS: [Vector; 3] = [
    Vector {
        algorithm: ManagementKeyAlgorithm::Tdes,
        version: "3.0.3",
        key: "0123456789abcdef23456789abcdef01456789abcdef0123",
        plain: "fedcba9876543210",
        cipher: "0737f6c53750d4a4",
        encrypted_zero: "4eba739c998bcb60",
    },
    Vector {
        algorithm: ManagementKeyAlgorithm::Aes192,
        version: "3.1.0",
        key: "000102030405060708090a0b0c0d0e0f1011121314151617",
        plain: "00112233445566778899aabbccddeeff",
        cipher: "dda97ca4864cdfe06eaf70a0ec0d7191",
        encrypted_zero: "916251821c73a522c396d62738019607",
    },
    Vector {
        algorithm: ManagementKeyAlgorithm::Tdes,
        version: "1.3",
        key: "0123456789abcdef23456789abcdef01456789abcdef0123",
        plain: "fedcba9876543210",
        cipher: "0737f6c53750d4a4",
        encrypted_zero: "4eba739c998bcb60",
    },
];
fn auth(v: &Vector, mutual: bool) -> ManagementAuthentication {
    let key = ManagementKey::from_bytes(v.algorithm, &hex(v.key)).unwrap();
    if mutual {
        ManagementAuthentication::mutual(key, &vec![0; v.algorithm.block_len()]).unwrap()
    } else {
        ManagementAuthentication::external(key)
    }
}
fn reply(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![0x7c, value.len() as u8 + 2, tag, value.len() as u8];
    out.extend(value);
    out.extend([0x90, 0]);
    out
}
fn selected<T>(op: &mut Operation<T>, v: &Vector) {
    assert_eq!(op.start().unwrap(), Step::Exchange);
    assert_eq!(
        op.command().unwrap().as_bytes(),
        hex(if v.algorithm == ManagementKeyAlgorithm::Tdes {
            "00a4040005a00000030800"
        } else {
            "00a4040005a000000308"
        })
    );
    op.advance(&[0x90, 0]).unwrap();
}
fn authenticate<T>(op: &mut Operation<T>, v: &Vector, mutual: bool) -> Step {
    let id = v.algorithm.wire_id();
    let mut expected = vec![
        0,
        0x87,
        id,
        0x9b,
        4,
        0x7c,
        2,
        if mutual { 0x80 } else { 0x81 },
        0,
    ];
    if v.algorithm == ManagementKeyAlgorithm::Tdes {
        expected.push(0);
    }
    assert_eq!(op.command().unwrap().as_bytes(), expected);
    op.advance(&reply(
        if mutual { 0x80 } else { 0x81 },
        &hex(if mutual { v.cipher } else { v.plain }),
    ))
    .unwrap();
    let mut fields = vec![
        if mutual { 0x80 } else { 0x82 },
        v.algorithm.block_len() as u8,
    ];
    fields.extend(hex(if mutual { v.plain } else { v.cipher }));
    if mutual {
        fields.extend([0x81, v.algorithm.block_len() as u8]);
        fields.extend(vec![0; v.algorithm.block_len()]);
    }
    let mut command = vec![
        0,
        0x87,
        id,
        0x9b,
        fields.len() as u8 + 2,
        0x7c,
        fields.len() as u8,
    ];
    command.extend(fields);
    if v.algorithm == ManagementKeyAlgorithm::Tdes {
        command.push(0);
    }
    assert_eq!(op.command().unwrap().as_bytes(), command);
    if mutual {
        op.advance(&reply(0x82, &hex(v.encrypted_zero))).unwrap()
    } else {
        op.advance(&[0x90, 0]).unwrap()
    }
}
#[test]
fn external_and_mutual_known_answers() {
    for v in &VECTORS {
        for mutual in [false, true] {
            let p = profile(v.version);
            let mut op =
                authenticate_management_key(&p, auth(v, mutual), true, Default::default()).unwrap();
            drop(p);
            assert!(!format!("{op:?}").contains(v.key));
            selected(&mut op, v);
            assert_eq!(authenticate(&mut op, v, mutual), Step::Done);
            op.result().unwrap();
            op.result().unwrap();
            op.take_result().unwrap();
            assert_eq!(op.state(), OperationState::ResultTaken);
            assert!(op.take_result().is_err());
        }
    }
}
#[test]
fn reject_wrong_card_and_malformed_authentication_fields() {
    let v = &VECTORS[1];
    for response in [
        reply(0x82, &[0; 16]),
        reply(0x82, &[0; 15]),
        hex("7c0080009000"),
        hex("9000"),
    ] {
        let mut op = authenticate_management_key(
            &profile(v.version),
            auth(v, true),
            true,
            Default::default(),
        )
        .unwrap();
        selected(&mut op, v);
        op.advance(&reply(0x80, &hex(v.cipher))).unwrap();
        let err = op.advance(&response).unwrap_err();
        if response == reply(0x82, &[0; 16]) {
            assert_eq!(err.kind, ErrorKind::DeviceAuthenticationFailed);
            assert_eq!(err.reference, Some(SecretReference::ManagementKey));
            assert_eq!(err.status_word, None);
        }
        assert_eq!(op.state(), OperationState::Failed);
        assert!(op.command().is_err());
        assert_eq!(op.error(), Some(&err));
    }
    for response in [
        hex("7c0080009000"),
        hex("7c04800080009000"),
        reply(0x81, &[0; 16]),
        reply(0x80, &[0; 15]),
        hex("7c128010019000"),
    ] {
        let mut op = authenticate_management_key(
            &profile(v.version),
            auth(v, true),
            true,
            Default::default(),
        )
        .unwrap();
        selected(&mut op, v);
        assert!(op.advance(&response).is_err());
        assert!(op.command().is_err());
    }
}
#[test]
fn management_failures_have_no_pin_retries_or_blocked_pin() {
    for sw in [
        hex("6982"),
        hex("63c2"),
        hex("6983"),
        hex("6f00"),
        hex("6c10"),
    ] {
        let v = &VECTORS[0];
        let mut op = authenticate_management_key(
            &profile(v.version),
            auth(v, false),
            true,
            Default::default(),
        )
        .unwrap();
        selected(&mut op, v);
        let err = op.advance(&sw).unwrap_err();
        assert_eq!(err.reference, Some(SecretReference::ManagementKey));
        assert_eq!(err.phase, Phase::Authentication);
        assert_eq!(err.retries_remaining, None);
        assert_ne!(err.kind, ErrorKind::PinBlocked);
        assert!(op.command().is_err());
    }
}
#[test]
fn capability_and_input_checks_precede_select() {
    let tdes = &VECTORS[0];
    let aes = &VECTORS[1];
    for (version, v, kind) in [
        ("3.1.0", tdes, ErrorKind::UnsupportedFeature),
        ("3.0.3", aes, ErrorKind::UnsupportedFeature),
        ("9.0.0", aes, ErrorKind::CapabilityUnknown),
        ("3.2.0-dev", aes, ErrorKind::CapabilityUnknown),
    ] {
        assert_eq!(
            authenticate_management_key(&profile(version), auth(v, true), true, Default::default())
                .unwrap_err()
                .kind,
            kind
        );
    }
    assert_eq!(
        profile("1.5.2")
            .management_key_support(ManagementKeyAlgorithm::Tdes)
            .support,
        Support::Supported
    );
    assert!(ManagementKey::from_bytes(ManagementKeyAlgorithm::Tdes, &[0; 23]).is_err());
    assert!(ManagementAuthentication::mutual(
        ManagementKey::from_bytes(ManagementKeyAlgorithm::Aes192, &[0; 24]).unwrap(),
        &[0; 8]
    )
    .is_err());
    let mut options = OperationOptions::default();
    options.exchange.max_command_bytes = 40;
    assert_eq!(
        authenticate_management_key(&profile(aes.version), auth(aes, true), true, options)
            .unwrap_err()
            .kind,
        ErrorKind::LimitExceeded
    );
}
#[test]
fn cancellation_and_select_failure_never_emit_authentication_or_target() {
    let v = &VECTORS[1];
    for stage in 0..3 {
        let mut op = write_certificate(
            &profile(v.version),
            Slot::Authentication,
            SecretBytes::new(vec![0x30, 0]),
            Access::Management(auth(v, true)),
            Default::default(),
        )
        .unwrap();
        if stage > 0 {
            selected(&mut op, v);
        }
        if stage > 1 {
            op.advance(&reply(0x80, &hex(v.cipher))).unwrap();
        }
        op.cancel();
        op.cancel();
        assert_eq!(op.state(), OperationState::Cancelled);
        assert!(op.command().is_err());
        assert!(op.advance(&[0x90, 0]).is_err());
    }
    let mut op =
        authenticate_management_key(&profile(v.version), auth(v, true), true, Default::default())
            .unwrap();
    op.start().unwrap();
    assert_eq!(op.advance(&[0x6a, 0x82]).unwrap_err().phase, Phase::Select);
    assert!(op.command().is_err());
}
#[test]
fn authenticated_certificate_write_keeps_pin_next_to_target() {
    let v = &VECTORS[1];
    let mut op = write_certificate(
        &profile(v.version),
        Slot::Authentication,
        SecretBytes::new(vec![0x30, 0]),
        Access::PinAndManagement {
            pin: Pin::from_bytes(b"123456").unwrap(),
            management: auth(v, true),
        },
        Default::default(),
    )
    .unwrap();
    selected(&mut op, v);
    assert_eq!(authenticate(&mut op, v, true), Step::Exchange);
    assert_eq!(
        op.command().unwrap().as_bytes(),
        hex("0020008008313233343536ffff")
    );
    op.advance(&[0x90, 0]).unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        hex("00db3fff105c035fc105530970023000710100fe00")
    );
    assert_eq!(op.advance(&[0x90, 0]).unwrap(), Step::Done);
    assert_eq!(
        op.result().unwrap().profile_effect,
        ProfileEffect::Unchanged
    );
}
#[test]
fn mutual_authentication_can_continue_but_never_correct_le() {
    let v = &VECTORS[0];
    let mut op =
        authenticate_management_key(&profile(v.version), auth(v, true), true, Default::default())
            .unwrap();
    selected(&mut op, v);
    let response = reply(0x80, &hex(v.cipher));
    let mut first = response[..6].to_vec();
    first.extend([0x61, 6]);
    op.advance(&first).unwrap();
    assert_eq!(op.command().unwrap().as_bytes(), hex("00c0000006"));
    op.advance(&response[6..]).unwrap();
    assert_eq!(op.command().unwrap().as_bytes()[1], 0x87);
    assert_eq!(
        op.advance(&[0x6c, 0x10])
            .unwrap_err()
            .status_word
            .unwrap()
            .raw(),
        0x6c10
    );
}
#[test]
fn chained_write_stops_without_replay_after_intermediate_error() {
    let v = &VECTORS[0];
    let id = ObjectId::certificate(Slot::Signature);
    let mut op = write_object(
        &profile(v.version),
        id,
        SecretBytes::new(vec![0x42; 600]),
        Access::Management(auth(v, false)),
        Default::default(),
    )
    .unwrap();
    selected(&mut op, v);
    authenticate(&mut op, v, false);
    let first = op.command().unwrap().as_bytes().to_vec();
    assert_eq!(&first[..5], &[0x10, 0xdb, 0x3f, 0xff, 255]);
    assert_eq!(&first[5..14], hex("5c035fc10a53820258"));
    op.advance(&[0x90, 0]).unwrap();
    assert_eq!(op.command().unwrap().as_bytes()[0], 0x10);
    assert_eq!(
        op.advance(&[0x6a, 0x84])
            .unwrap_err()
            .status_word
            .unwrap()
            .raw(),
        0x6a84
    );
    assert!(op.command().is_err());
    assert!(op.start().is_err());
    assert!(write_object(
        &profile("unknown"),
        id,
        SecretBytes::new(vec![0; 600]),
        Access::Management(auth(v, false)),
        Default::default()
    )
    .is_err());
}
#[test]
fn certificate_deletion_and_management_replacement_are_explicit() {
    let v = &VECTORS[1];
    let mut op = delete_certificate(
        &profile(v.version),
        Slot::Authentication,
        Access::Management(auth(v, false)),
        Default::default(),
    )
    .unwrap();
    selected(&mut op, v);
    authenticate(&mut op, v, false);
    assert_eq!(
        op.command().unwrap().as_bytes(),
        hex("00db3fff075c035fc1055300")
    );
    op.advance(&[0x90, 0]).unwrap();
    assert!(delete_certificate(
        &profile("3.0.3"),
        Slot::Authentication,
        Access::Management(auth(&VECTORS[0], false)),
        Default::default()
    )
    .is_err());
    let replacement = ManagementKey::from_bytes(v.algorithm, &[0x42; 24]).unwrap();
    let mut op = set_management_key(
        &profile(v.version),
        replacement,
        ManagementTouchPolicy::Always,
        false,
        Access::Management(auth(v, false)),
        Default::default(),
    )
    .unwrap();
    selected(&mut op, v);
    authenticate(&mut op, v, false);
    let command = op.command().unwrap().as_bytes();
    assert_eq!(&command[..8], hex("00fffffe1b0a9b18"));
    assert_eq!(&command[8..], &[0x42; 24]);
    assert_eq!(op.advance(&[0x90, 0]).unwrap(), Step::Done);
    assert!(write_object(
        &profile(v.version),
        ObjectId::certificate(Slot::Authentication),
        SecretBytes::default(),
        Access::None,
        Default::default()
    )
    .is_err());
}

#[test]
fn selected_context_management_preserves_firmware_encoding_without_reselect() {
    for v in &VECTORS {
        for mutual in [false, true] {
            let context = (profile(v.version)).clone();
            let mut op =
                authenticate_management_key(&context, auth(v, mutual), false, Default::default())
                    .unwrap();
            drop(context);
            assert_eq!(op.start().unwrap(), Step::Exchange);
            assert_eq!(authenticate(&mut op, v, mutual), Step::Done);
            op.take_result().unwrap();
            assert!(op.advance(&[0x90, 0]).is_err());
        }
    }
}

#[test]
fn rotation_preserves_protected_data_and_stops_at_each_irreversible_boundary() {
    let v = &VECTORS[1];
    for failure in [0u8, 1, 2, 3] {
        let key = ManagementKey::from_bytes(v.algorithm, &hex(v.key)).unwrap();
        let mut op = set_management_key(
            &profile(v.version),
            key,
            ManagementTouchPolicy::Never,
            true,
            Access::Existing,
            Default::default(),
        )
        .unwrap();
        op.start().unwrap();
        assert_eq!(op.command().unwrap().as_bytes()[1], 0xcb);
        op.advance(&hex("530580038101039000")).unwrap();
        let mut printed = hex("531c881a8918");
        printed.extend(hex(v.key));
        printed.extend([0x90, 0]);
        if failure == 1 {
            assert!(op.advance(&[0x69, 0x82]).is_err());
            assert!(op.command().is_err());
            continue; // No replacement without PIN-protected read authorization.
        }
        op.advance(&printed).unwrap();
        assert_eq!(op.command().unwrap().as_bytes()[1], 0xff);
        if failure == 2 {
            assert!(op.advance(&[0x6f, 0]).is_err());
            assert!(op.command().is_err());
            continue; // Uncertain replacement is never replayed.
        }
        op.advance(&[0x90, 0]).unwrap();
        authenticate(&mut op, v, false);
        let command = op.command().unwrap().as_bytes();
        assert_eq!(&command[..11], &hex("00db3fff235c035fc10953"));
        assert_eq!(&command[11..], &printed[..printed.len() - 2][1..]);
        if failure == 3 {
            assert!(op.advance(&[0x6f, 0]).is_err());
            assert!(op.command().is_err()); // Caller must repair PRINTED with the new key.
        } else {
            assert_eq!(op.advance(&[0x90, 0]).unwrap(), Step::Done);
        }
    }
}
