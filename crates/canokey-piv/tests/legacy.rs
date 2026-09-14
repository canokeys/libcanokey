use canokey_compat::{
    Capability, DeviceObservations, DeviceProfile, Evidence, PivApplicationVersion, Support,
};
use canokey_piv::*;
use canokey_protocol::{ErrorKind, SecretBytes};
fn profile(v: &str) -> DeviceProfile {
    let mut o = DeviceObservations::new(v.as_bytes().to_vec());
    o.piv_version = Some(PivApplicationVersion([5, 0, 0]));
    DeviceProfile::from_observations(o).unwrap()
}
fn access() -> Access {
    Access::Management(ManagementAuthentication::external(
        ManagementKey::from_bytes(ManagementKeyAlgorithm::Tdes, &[42; 24]).unwrap(),
    ))
}
#[test]
fn baseline_13_keys_and_pin_use_short_apdus_with_explicit_le() {
    let p = profile("1.3");
    for a in [Algorithm::Rsa2048, Algorithm::EccP256, Algorithm::EccP384] {
        let mut op = generate_key(
            &p,
            KeyParameters::new(Slot::Authentication, a),
            access(),
            Default::default(),
        )
        .unwrap();
        op.start().unwrap();
        assert_eq!(
            op.command().unwrap().as_bytes(),
            &[0, 0xa4, 4, 0, 5, 0xa0, 0, 0, 3, 8, 0]
        );
        op.advance(&[0x90, 0]).unwrap();
        assert_eq!(
            op.command().unwrap().as_bytes(),
            &[0, 0x87, 3, 0x9b, 4, 0x7c, 2, 0x81, 0, 0]
        );
        op.advance(&[0x7c, 10, 0x81, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0x90, 0])
            .unwrap();
        op.advance(&[0x90, 0]).unwrap();
        assert_eq!(
            op.command().unwrap().as_bytes(),
            &[
                0,
                0x47,
                0,
                0x9a,
                5,
                0xac,
                3,
                0x80,
                1,
                p.algorithm_wire_id(a).unwrap(),
                0
            ]
        );
        op.cancel();
        assert!(op.command().is_err());
    }
    let mut op = verify_pin(&p, Pin::from_bytes(b"123456").unwrap(), Default::default()).unwrap();
    op.start().unwrap();
    op.advance(&[0x90, 0]).unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        b"\0\x20\0\x80\x08123456\xff\xff\0"
    );
    let mut params = KeyParameters::new(Slot::Signature, Algorithm::EccP256);
    params.pin_policy = PinPolicy::Always;
    assert_eq!(
        generate_key(&p, params, access(), Default::default())
            .unwrap_err()
            .kind,
        ErrorKind::UnsupportedFeature
    );
    assert!(write_object(
        &p,
        ObjectId::certificate(Slot::Signature),
        SecretBytes::new(vec![0; 100]),
        access(),
        Default::default()
    )
    .is_ok());
}
#[test]
fn confirmed_2x_extension_flag_is_owned_and_never_faked_as_ee_bytes() {
    let original = profile("2.0.0");
    assert_eq!(
        original.algorithm_config_read_support().support,
        Support::Unsupported
    );
    assert_eq!(
        original.key_algorithm_support(Algorithm::Rsa4096).support,
        Support::Unknown
    );
    let enabled = original.with_legacy_piv_extensions(true).unwrap();
    let disabled = enabled.with_legacy_piv_extensions(false).unwrap();
    assert_eq!(original.legacy_piv_extensions(), None);
    assert_eq!(enabled.legacy_piv_extensions(), Some(true));
    assert!(enabled.algorithm_config().is_none());
    for (a, id) in [
        (Algorithm::Rsa3072, 0x50),
        (Algorithm::Rsa4096, 0x51),
        (Algorithm::Secp256k1, 0x53),
        (Algorithm::Sm2, 0x54),
    ] {
        assert_eq!(enabled.algorithm_wire_id(a), Some(id));
        assert_eq!(enabled.key_algorithm_support(a).support, Support::Supported);
        assert_eq!(
            enabled.key_algorithm_support(a).evidence,
            Evidence::Observed
        );
        assert!(generate_key(
            &enabled,
            KeyParameters::new(Slot::Signature, a),
            access(),
            Default::default()
        )
        .is_ok());
        assert_eq!(
            disabled.key_algorithm_support(a).support,
            Support::Unsupported
        );
    }
    assert_eq!(
        enabled.capability(Capability::AlgorithmExtensions).support,
        Support::Supported
    );
    assert_eq!(
        disabled.capability(Capability::AlgorithmExtensions).support,
        Support::Unsupported
    );
    for v in ["1.3", "1.6.2", "3.0.0", "3.1.0", "3.1.0-dev", "unknown"] {
        assert!(profile(v).with_legacy_piv_extensions(true).is_err());
    }
    assert_eq!(
        read_algorithm_config(&enabled, Access::None, Default::default())
            .unwrap_err()
            .kind,
        ErrorKind::UnsupportedFeature
    );
    // Existing Ed/X private-operation fix gates remain independent of enablement.
    assert_eq!(
        enabled.key_algorithm_support(Algorithm::X25519).support,
        Support::Unsupported
    );
}

#[test]
fn legacy_reset_never_exhausts_retries_or_assumes_select_logged_out() {
    let p = profile("1.3");
    assert_eq!(
        p.capability(Capability::PivSelectResetsAuthentication)
            .support,
        Support::Unsupported
    );
    let mut op = reset_piv(&p, Default::default()).unwrap();
    op.start().unwrap();
    op.advance(&[0x90, 0]).unwrap();
    assert_eq!(op.command().unwrap().as_bytes(), &[0, 0xfb, 0, 0, 0]);
    assert_eq!(
        op.advance(&[0x69, 0x82]).unwrap_err().kind,
        ErrorKind::SecurityStatusNotSatisfied
    );
    assert!(op.command().is_err());
}
