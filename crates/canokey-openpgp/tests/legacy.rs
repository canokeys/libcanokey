use canokey_compat::{Capability, DeviceObservations, DeviceProfile, Support};
use canokey_openpgp::*;
use canokey_protocol::{ErrorKind, SecretBytes, Step};
fn profile(v: &str) -> DeviceProfile {
    DeviceProfile::from_observations(DeviceObservations::new(v.as_bytes().to_vec())).unwrap()
}
fn access(r: PasswordReference) -> Access {
    Access {
        reference: r,
        password: Password::from_bytes(b"87654321").unwrap(),
    }
}
fn attrs(version: &str, tag: u8, bytes: &[u8]) -> Vec<u8> {
    // Firmware reserves two length bytes even for short constructed values.
    let mut v = vec![
        0x73,
        0x82,
        0,
        (bytes.len() + 2) as u8,
        tag,
        bytes.len() as u8,
    ];
    v.extend(bytes);
    if profile(version)
        .capability(Capability::OpenPgpWrappedData)
        .support
        == Support::Supported
    {
        let mut outer = vec![0x6e, 0x82, 0, v.len() as u8];
        outer.extend(v);
        v = outer;
    }
    v
}
#[test]
fn profile_aware_ber_preserves_original_and_does_not_guess_missing_wrappers() {
    for v in ["1.3", "1.5.2", "1.6.1", "1.6.2", "2.0.0", "3.0.1", "3.1.0"] {
        let bytes = attrs(v, 0xc1, &[1, 8, 0, 0, 32, 2]);
        let app = ApplicationData::parse_with_profile(&profile(v), &bytes, 128).unwrap();
        assert_eq!(app.raw.as_bytes(), bytes);
        assert_eq!(
            app.algorithm_attributes(Slot::Signature).unwrap(),
            Some(&[1, 8, 0, 0, 32, 2][..])
        );
        assert_eq!(
            ApplicationData::parse_with_profile(&profile(v), &bytes, bytes.len() - 1)
                .unwrap_err()
                .kind,
            ErrorKind::LimitExceeded
        );
    }
    assert!(ApplicationData::parse_with_profile(
        &profile("3.1.0"),
        &attrs("1.3", 0xc1, &[1, 8, 0, 0, 32, 2]),
        128
    )
    .is_err());
    assert_eq!(
        ApplicationData::parse_with_profile(&profile("4.0"), &[], 128)
            .unwrap_err()
            .kind,
        ErrorKind::CapabilityUnknown
    );
    let c = CardholderData::parse_with_profile(&profile("1.3"), &[0x5b, 1, b'A'], 32).unwrap();
    assert_eq!(c.name().unwrap(), Some(&b"A"[..]));
}
#[test]
fn algorithm_information_retains_alternatives_and_has_independent_boundary() {
    let bytes = [0xc1, 1, 1, 0xc1, 1, 19, 0xee, 1, 42];
    for v in ["1.6.1", "2.0.0", "3.0.1"] {
        let info = AlgorithmInformation::parse_with_profile(&profile(v), &bytes, 128).unwrap();
        assert_eq!(info.fields.len(), 3);
        assert_eq!(info.fields[2].tag, 0xee);
    }
    let mut wrapped = vec![0xfa, 0x82, 0, bytes.len() as u8];
    wrapped.extend(bytes);
    assert_eq!(
        AlgorithmInformation::parse_with_profile(&profile("3.1.0"), &wrapped, 128)
            .unwrap()
            .raw
            .as_bytes(),
        wrapped
    );
    for v in ["1.3", "1.5.2"] {
        assert_eq!(
            operation(
                &profile(v),
                Request::ReadData(0xfa),
                None,
                Default::default()
            )
            .unwrap_err()
            .kind,
            ErrorKind::UnsupportedFeature
        );
        // Lack of FA does not prevent reading the selected key attributes.
        assert!(operation(
            &profile(v),
            Request::ReadData(0x6e),
            None,
            Default::default()
        )
        .is_ok());
    }
}
#[test]
fn old_key_operations_preflight_before_password_without_selecting_again() {
    let mut op = operation(
        &profile("1.6.2"),
        Request::Sign(Algorithm::EccP256, SecretBytes::new(vec![42; 32])),
        Some(access(PasswordReference::Pw1Sign)),
        Default::default(),
    )
    .unwrap();
    op.start().unwrap();
    assert_eq!(op.command().unwrap().as_bytes().last(), Some(&0));
    op.advance(&[0x90, 0]).unwrap();
    let mut meta = attrs(
        "1.6.2",
        0xc1,
        &[0x13, 0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7],
    );
    meta.extend([0x90, 0]);
    op.advance(&meta).unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        b"\0\x20\0\x81\x0887654321\0"
    );
    op.advance(&[0x90, 0]).unwrap();
    assert_eq!(
        &op.command().unwrap().as_bytes()[..5],
        &[0, 0x2a, 0x9e, 0x9a, 32]
    );
    let mut signature = vec![42; 64];
    signature.extend([0x90, 0]);
    assert_eq!(op.advance(&signature).unwrap(), Step::Done);
    let mut op = operation(
        &profile("1.6.2"),
        Request::GenerateKey(Slot::Signature),
        Some(access(PasswordReference::Pw3)),
        Default::default(),
    )
    .unwrap();
    op.start().unwrap();
    op.advance(&[0x90, 0]).unwrap();
    let mut meta = attrs("1.6.2", 0xc1, &[1, 16, 0, 0, 32, 2]);
    meta.extend([0x90, 0]);
    assert_eq!(
        op.advance(&meta).unwrap_err().kind,
        ErrorKind::UnsupportedFeature
    );
    assert!(op.command().is_err());
}
#[test]
fn old_ed25519_read_back_discards_only_the_evidenced_extra_byte() {
    let mut op = operation(
        &profile("1.5.2"),
        Request::ReadPublicKey(Slot::Signature),
        None,
        Default::default(),
    )
    .unwrap();
    op.start().unwrap();
    op.advance(&[0x90, 0]).unwrap();
    let mut meta = attrs("1.5.2", 0xc1, &[0x16, 0x2b, 6, 1, 4, 1, 0xda, 0x47, 15, 1]);
    meta.extend([0x90, 0]);
    op.advance(&meta).unwrap();
    let mut key = vec![0x7f, 0x49, 34, 0x86, 32];
    key.extend([42; 32]);
    key.extend([0xde, 0x90, 0]);
    assert_eq!(op.advance(&key).unwrap(), Step::Done);
    assert!(matches!(op.take_result().unwrap(), Outcome::PublicKey(_)));
}
#[test]
fn old_derivation_extracts_x_coordinate_and_certificate_occurrence_is_stable() {
    let mut op = operation(
        &profile("1.3"),
        Request::Derive(Algorithm::EccP256, [vec![4], vec![42; 64]].concat()),
        Some(access(PasswordReference::Pw1Other)),
        Default::default(),
    )
    .unwrap();
    op.start().unwrap();
    op.advance(&[0x90, 0]).unwrap();
    let mut meta = attrs("1.3", 0xc2, &[0x12, 0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7]);
    meta.extend([0x90, 0]);
    op.advance(&meta).unwrap();
    op.advance(&[0x90, 0]).unwrap();
    let mut point = vec![4];
    point.extend([42; 32]);
    point.extend([43; 32]);
    point.extend([0x90, 0]);
    op.advance(&point).unwrap();
    let Outcome::Bytes(secret) = op.take_result().unwrap() else {
        panic!()
    };
    assert_eq!(secret.as_bytes(), &[42; 32]);
    for (slot, n) in [
        (Slot::Signature, 0),
        (Slot::Decryption, 1),
        (Slot::Authentication, 2),
    ] {
        let mut op = operation(
            &profile("1.3"),
            Request::ReadCertificate(slot),
            None,
            Default::default(),
        )
        .unwrap();
        op.start().unwrap();
        op.advance(&[0x90, 0]).unwrap();
        assert_eq!(
            op.command().unwrap().as_bytes(),
            &[0, 0xa5, n, 4, 6, 0x60, 4, 0x5c, 2, 0x7f, 0x21, 0]
        );
    }
}
#[test]
fn missing_features_and_terminated_state_are_not_conflated_with_baseline() {
    for v in ["1.3", "1.5.2", "1.6.2", "2.0.0", "3.0.1"] {
        assert_eq!(
            operation(
                &profile(v),
                Request::Sign(Algorithm::EccP384, SecretBytes::new(vec![42; 32])),
                Some(access(PasswordReference::Pw1Sign)),
                Default::default()
            )
            .unwrap_err()
            .kind,
            ErrorKind::UnsupportedFeature
        );
    }
    assert_eq!(
        operation(
            &profile("1.3"),
            Request::WriteData(DataWrite::TouchCacheTime(5)),
            Some(access(PasswordReference::Pw3)),
            Default::default()
        )
        .unwrap_err()
        .kind,
        ErrorKind::UnsupportedFeature
    );
    let mut op = operation(
        &profile("1.5.2"),
        Request::Activate,
        None,
        Default::default(),
    )
    .unwrap();
    op.start().unwrap();
    op.advance(&[0x62, 0x85]).unwrap();
    assert_eq!(op.command().unwrap().as_bytes(), &[0, 0x44, 0, 0, 0]);
    op.advance(&[0x90, 0]).unwrap();
    let mut op = operation(
        &profile("1.5.2"),
        Request::ReadData(0x6e),
        None,
        Default::default(),
    )
    .unwrap();
    op.start().unwrap();
    assert!(op.advance(&[0x62, 0x85]).is_err());
}
