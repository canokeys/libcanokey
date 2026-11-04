#[allow(dead_code)]
mod support;
use canokey_piv::*;
use canokey_protocol::{ErrorKind, Step};
use support::*;

#[test]
fn firmware_310_f9_metadata_and_certificate_are_read_only() {
    let mut op = read_attestation_metadata(&profile("3.1.0"), Default::default()).unwrap();
    selected(&mut op);
    assert_eq!(op.command().unwrap().as_bytes(), hex("00f700f9"));
    let mut data = hex("0101110202010103010204438641");
    data.extend(hex(P256_POINT));
    data.extend(hex("9000"));
    assert_eq!(op.advance(&data).unwrap(), Step::Done);
    let fields = op.take_result().unwrap();
    assert_eq!(fields.algorithm_id, Some(0x11));
    assert!(fields.public_key.is_some());
    assert_eq!(
        fields.origin,
        Some(KnownOrUnknown::Known(KeyOrigin::Imported))
    );

    let mut op = read_attestation_certificate(&profile("3.1.0"), Default::default()).unwrap();
    selected(&mut op);
    assert_eq!(
        op.command().unwrap().as_bytes(),
        hex("00cb3fff055c035fff0100")
    );
    // Container framing fixture; not a valid X.509 certificate.
    op.advance(&hex("530970023000710100fe009000")).unwrap();
    assert_eq!(op.take_result().unwrap().der(), hex("3000"));
}

#[test]
fn firmware_303_f9_is_rejected_before_io() {
    assert_eq!(
        read_attestation_metadata(&profile("3.0.3"), Default::default())
            .unwrap_err()
            .kind,
        ErrorKind::UnsupportedFeature
    );
    assert_eq!(
        read_attestation_certificate(&profile("3.0.3"), Default::default())
            .unwrap_err()
            .kind,
        ErrorKind::UnsupportedFeature
    );
}

#[test]
fn firmware_310_f9_missing_and_malformed_are_distinct() {
    let mut op = read_attestation_metadata(&profile("3.1.0"), Default::default()).unwrap();
    selected(&mut op);
    assert_eq!(
        op.advance(&hex("6a88")).unwrap_err().kind,
        ErrorKind::NotFound
    );
    let mut op = read_attestation_metadata(&profile("3.1.0"), Default::default()).unwrap();
    selected(&mut op);
    assert_eq!(
        op.advance(&hex("0101110101119000")).unwrap_err().kind,
        ErrorKind::InvalidResponse
    );
    let mut op = read_attestation_certificate(&profile("3.1.0"), Default::default()).unwrap();
    selected(&mut op);
    assert_eq!(
        op.advance(&hex("530270009000")).unwrap_err().kind,
        ErrorKind::InvalidResponse
    );
}

#[test]
fn firmware_310_f9_generate_authenticates_and_returns_p256_public_key() {
    let mut op = generate_attestation_key(
        &profile("3.1.0"),
        AttestationKeyParameters::default(),
        access(),
        Default::default(),
    )
    .unwrap();
    authenticate(&mut op);
    assert_eq!(
        op.command().unwrap().as_bytes(),
        hex("004700f905ac03800111")
    );
    let mut response = hex("7f49438641");
    response.extend(hex(P256_POINT));
    response.extend(hex("9000"));
    assert_eq!(op.advance(&response).unwrap(), Step::Done);
    let public = op.take_result().unwrap();
    assert_eq!(public.algorithm(), Algorithm::EccP256);
    assert!(!public.to_spki_der().unwrap().is_empty());
}

#[test]
fn firmware_310_f9_import_owns_scalar_and_does_not_retry_failures() {
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let material = PrivateKeyMaterial::ec_scalar(Algorithm::EccP256, &scalar).unwrap();
    let mut op = import_attestation_key(
        &profile("3.1.0"),
        AttestationKeyParameters {
            pin_policy: PinPolicy::Never,
            touch_policy: TouchPolicy::Never,
        },
        material,
        access(),
        Default::default(),
    )
    .unwrap();
    authenticate(&mut op);
    let mut expected = hex("00fe11f9280620");
    expected.extend(scalar);
    expected.extend(hex("aa0101ab0101"));
    assert_eq!(op.command().unwrap().as_bytes(), expected);
    assert_eq!(
        op.advance(&hex("6982")).unwrap_err().kind,
        ErrorKind::SecurityStatusNotSatisfied
    );
    assert!(op.command().is_err());
}

#[test]
fn f9_provisioning_rejects_legacy_missing_management_and_non_p256_before_io() {
    for version in ["3.0.3", "1.6.1"] {
        assert_eq!(
            generate_attestation_key(
                &profile(version),
                Default::default(),
                access(),
                Default::default()
            )
            .unwrap_err()
            .kind,
            ErrorKind::UnsupportedFeature
        );
        let material = PrivateKeyMaterial::ec_scalar(Algorithm::EccP256, &[1; 32]).unwrap();
        assert_eq!(
            import_attestation_key(
                &profile(version),
                Default::default(),
                material,
                access(),
                Default::default()
            )
            .unwrap_err()
            .kind,
            ErrorKind::UnsupportedFeature
        );
    }
    assert!(generate_attestation_key(
        &profile("3.1.0"),
        Default::default(),
        Access::None,
        Default::default()
    )
    .is_err());
    let material = PrivateKeyMaterial::ec_scalar(Algorithm::EccP384, &[1; 48]).unwrap();
    assert_eq!(
        import_attestation_key(
            &profile("3.1.0"),
            Default::default(),
            material,
            access(),
            Default::default()
        )
        .unwrap_err()
        .kind,
        ErrorKind::InvalidArgument
    );
}
