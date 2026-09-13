use canokey::*;
use compatibility::{
    Algorithm, AlgorithmConfig, Capability, DeviceObservations, Evidence, PivApplicationVersion,
    Support,
};
fn profile(version: &str) -> DeviceProfile {
    let mut observations = DeviceObservations::new(version.as_bytes().to_vec());
    observations.piv_version = Some(PivApplicationVersion([5, 7, 0]));
    DeviceProfile::from_observations(observations).unwrap()
}
fn exchange<T>(op: &mut Operation<T>, command: &[u8], response: &[u8]) -> Step {
    assert_eq!(op.command().unwrap().as_bytes(), command);
    op.advance(response).unwrap()
}
#[test]
fn minimal_probe_and_optional_statuses() {
    let mut op = probe_device(ProbeOptions {
        mode: ProbeMode::Minimal,
        ..Default::default()
    })
    .unwrap();
    op.start().unwrap();
    exchange(&mut op, &[0, 0xa4, 4, 0, 5, 0xf0, 0, 0, 0, 0], &[0x90, 0]);
    exchange(&mut op, &[0, 0x31, 0, 0, 0], b"3.1.0\x90\x00");
    exchange(&mut op, &[0, 0x31, 1, 0, 0], &[0x6d, 0]);
    assert_eq!(
        exchange(&mut op, &[0, 0x32, 0, 0, 0], &[1, 2, 3, 4, 0x90, 0]),
        Step::Done
    );
    let p = op.take_result().unwrap();
    assert_eq!(p.info().serial(), Some(&[1, 2, 3, 4][..]));
    assert_eq!(p.info().model(), None);
    assert_eq!(p.warnings().len(), 1);
}
#[test]
fn full_probe_keeps_firmware_and_piv_version_separate() {
    let mut op = probe_device(ProbeOptions::default()).unwrap();
    op.start().unwrap();
    op.advance(&[0x90, 0]).unwrap();
    op.advance(b"2.0.0\x90\x00").unwrap();
    op.advance(b"CanoKey\x90\x00").unwrap();
    op.advance(&[1, 2, 3, 4, 0x90, 0]).unwrap();
    exchange(&mut op, &[0, 0xa4, 4, 0, 5, 0xa0, 0, 0, 3, 8], &[0x90, 0]);
    exchange(&mut op, &[0, 0xfd, 0, 0, 0], &[5, 7, 0, 0x90, 0]);
    assert_eq!(
        exchange(
            &mut op,
            &[0, 0xee, 1, 0, 0],
            &[1, 0x22, 0x50, 0x51, 0x52, 0x53, 0x54, 0x90, 0]
        ),
        Step::Done
    );
    let p = op.result().unwrap();
    assert_eq!(p.info().firmware().unwrap().major, 2);
    assert_eq!(p.info().piv_version().unwrap().0, [5, 7, 0]);
    assert_eq!(p.algorithm_wire_id(Algorithm::Ed25519), Some(0x22));
    assert_eq!(p.algorithm_wire_id(Algorithm::MlDsa65), None);
}
#[test]
fn probe_does_not_hide_real_errors() {
    for response in [&[0x6f, 0][..], &[0x90][..], &[0xff, 0x90, 0][..]] {
        let mut op = probe_device(ProbeOptions::default()).unwrap();
        op.start().unwrap();
        op.advance(&[0x90, 0]).unwrap();
        op.advance(b"3.1.0\x90\x00").unwrap();
        assert!(op.advance(response).is_err());
        assert_eq!(op.state(), OperationState::Failed);
    }
}
#[test]
fn unknown_firmware_has_baseline_not_invented_capabilities() {
    let p = profile("9.0.0-dev");
    assert_eq!(
        p.capability(Capability::EccP256).support,
        Support::Supported
    );
    assert_eq!(p.capability(Capability::Metadata).support, Support::Unknown);
    assert_eq!(
        p.capability(Capability::Metadata).evidence,
        Evidence::LatestKnownFallback
    );
    let p = profile("unrecognized");
    assert!(p.info().firmware().is_none());
    assert!(!p.warnings().is_empty());
    assert_eq!(
        profile("1.5.2").capability(Capability::Metadata).support,
        Support::Unsupported
    );
    assert!(AlgorithmConfig::parse(&[1, 0xe0, 5, 0x16, 0xe1, 0x53, 0x54]).is_ok());
    assert!(AlgorithmConfig::parse(&[1, 0xe0, 0xe0, 0x16, 0xe1, 0x53, 0x54]).is_err());
}
#[test]
fn verify_owns_inputs_and_preserves_retry_error() {
    let p = profile("3.1.0");
    let pin = piv::Pin::from_bytes(b"123456").unwrap();
    let mut op = piv::verify_pin(&p, pin, OperationOptions::default()).unwrap();
    drop(p);
    op.start().unwrap();
    exchange(&mut op, &[0, 0xa4, 4, 0, 5, 0xa0, 0, 0, 3, 8], &[0x90, 0]);
    assert_eq!(
        op.command().unwrap().as_bytes(),
        [0, 0x20, 0, 0x80, 8, b'1', b'2', b'3', b'4', b'5', b'6', 0xff, 0xff]
    );
    let err = op.advance(&[0x63, 0xc2]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::AuthenticationFailed);
    assert_eq!(err.retries_remaining, Some(2));
    assert!(op.command().is_err());
    assert!(!format!("{op:?}").contains("123456"));
}
#[test]
fn query_pin_status_is_not_failed_authentication() {
    for (sw, retries, verified, blocked) in [
        ([0x63, 0xc2], Some(2), false, false),
        ([0x90, 0], None, true, false),
        ([0x69, 0x83], Some(0), false, true),
    ] {
        let mut op = piv::get_pin_status(&profile("3.1.0"), OperationOptions::default()).unwrap();
        op.start().unwrap();
        op.advance(&[0x90, 0]).unwrap();
        assert_eq!(op.advance(&sw).unwrap(), Step::Done);
        let s = op.result().unwrap();
        assert_eq!(s.retries_remaining, retries);
        assert_eq!(s.verified, Some(verified));
        assert_eq!(s.blocked, blocked);
    }
}
#[test]
fn protected_object_read_has_no_select_after_verify() {
    let p = profile("3.1.0");
    let id = piv::ObjectId::from_bytes(&[0x5f, 0xc1, 2]).unwrap();
    let mut op = piv::read_object(
        &p,
        id,
        piv::Access::Pin(piv::Pin::from_bytes(b"123456").unwrap()),
        OperationOptions::default(),
    )
    .unwrap();
    op.start().unwrap();
    op.advance(&[0x90, 0]).unwrap();
    op.advance(&[0x90, 0]).unwrap();
    exchange(
        &mut op,
        &[0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 2, 0],
        &[0x53, 3, 0xaa, 0x61, 2],
    );
    exchange(&mut op, &[0, 0xc0, 0, 0, 2], &[0xbb, 0xcc, 0x90, 0]);
    assert_eq!(op.result().unwrap().as_bytes(), [0xaa, 0xbb, 0xcc]);
}
#[test]
fn old_object_quirk_is_narrow() {
    let id = piv::ObjectId::from_bytes(&[0x5f, 0xc1, 2]).unwrap();
    for (version, ok) in [("1.5.2", true), ("3.1.0", false)] {
        let mut op = piv::read_object(
            &profile(version),
            id,
            piv::Access::None,
            OperationOptions::default(),
        )
        .unwrap();
        op.start().unwrap();
        op.advance(&[0x90, 0]).unwrap();
        assert_eq!(op.advance(&[0x30, 0, 0x90, 0]).is_ok(), ok);
    }
}

#[test]
fn pin_and_puk_mutations_preserve_secret_reference() {
    use canokey_protocol::SecretReference;
    let p = profile("3.1.0");
    let mut op = piv::unblock_pin(
        &p,
        piv::Puk::from_bytes(b"12345678").unwrap(),
        piv::Pin::from_bytes(b"654321").unwrap(),
        OperationOptions::default(),
    )
    .unwrap();
    op.start().unwrap();
    op.advance(&[0x90, 0]).unwrap();
    let cmd = op.command().unwrap().as_bytes();
    assert_eq!(&cmd[..5], &[0, 0x2c, 0, 0x80, 16]);
    assert_eq!(&cmd[5..13], b"12345678");
    let e = op.advance(&[0x63, 0xc1]).unwrap_err();
    assert_eq!(e.reference, Some(SecretReference::Puk));
    assert_eq!(e.retries_remaining, Some(1));
    let mut options = OperationOptions::default();
    options.exchange.max_command_bytes = 10;
    assert!(piv::verify_pin(&p, piv::Pin::from_bytes(b"123456").unwrap(), options).is_err());
}

#[test]
fn optional_discovery_failure_overrides_version_inference() {
    let mut observations = DeviceObservations::new(b"3.1.0".to_vec());
    observations
        .warnings
        .push(compatibility::CompatibilityWarning::OptionalCommandUnsupported("algorithm_config"));
    let p = DeviceProfile::from_observations(observations).unwrap();
    assert_eq!(
        p.capability(Capability::AlgorithmExtensions).support,
        Support::Unsupported
    );
    assert_eq!(
        p.capability(Capability::AlgorithmExtensions).evidence,
        Evidence::Observed
    );
}

#[test]
fn certificate_read_owns_profile_and_authenticates_without_reselect() {
    let p = profile("3.1.0");
    let mut op = piv::read_certificate(
        &p,
        piv::Slot::Authentication,
        piv::Access::Pin(piv::Pin::from_bytes(b"123456").unwrap()),
        Default::default(),
    )
    .unwrap();
    drop(p);
    op.start().unwrap();
    exchange(&mut op, &[0, 0xa4, 4, 0, 5, 0xa0, 0, 0, 3, 8], &[0x90, 0]);
    exchange(
        &mut op,
        &[
            0, 0x20, 0, 0x80, 8, b'1', b'2', b'3', b'4', b'5', b'6', 0xff, 0xff,
        ],
        &[0x90, 0],
    );
    assert_eq!(
        exchange(
            &mut op,
            &[0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 5, 0],
            &[0x53, 9, 0x70, 2, 0x30, 0, 0x71, 1, 0, 0xfe, 0, 0x90, 0]
        ),
        Step::Done
    );
    let cert = op.take_result().unwrap();
    drop(op);
    assert_eq!(cert.der(), &[0x30, 0]); // Container fixture, not a valid X.509 certificate.
}

#[test]
fn certificate_missing_and_auth_failure_remain_errors() {
    for (response, kind) in [
        ([0x6a, 0x82], ErrorKind::NotFound),
        ([0x69, 0x82], ErrorKind::SecurityStatusNotSatisfied),
    ] {
        let mut op = piv::read_certificate(
            &profile("3.1.0"),
            piv::Slot::Signature,
            piv::Access::None,
            Default::default(),
        )
        .unwrap();
        op.start().unwrap();
        op.advance(&[0x90, 0]).unwrap();
        assert_eq!(op.advance(&response).unwrap_err().kind, kind);
        assert_eq!(op.state(), OperationState::Failed);
        assert!(op.result().is_err());
    }
}

#[test]
fn reserved_extension_ids_cannot_change_private_operation_semantics() {
    for id in [0x0a, 0xff] {
        for (firmware, usable) in [("3.0.3", true), ("3.1.0", false)] {
            let raw = vec![1, id, 5, 0x16, 0xe1, 0x53, 0x54, 0x55, 0x56, 0x57];
            let mut observations = DeviceObservations::new(firmware.as_bytes().to_vec());
            observations.algorithm_config = Some(AlgorithmConfig::parse(&raw).unwrap());
            observations.piv_version = Some(PivApplicationVersion([5, 7, 0]));
            let profile = canokey::DeviceProfile::from_observations(observations).unwrap();
            assert_eq!(profile.algorithm_config().unwrap().raw(), raw);
            assert_eq!(
                profile.algorithm_wire_id(Algorithm::Ed25519),
                usable.then_some(id)
            );
            assert_eq!(
                profile.key_algorithm_support(Algorithm::Ed25519).support,
                if usable {
                    compatibility::Support::Supported
                } else {
                    compatibility::Support::Unsupported
                }
            );
            if !usable {
                assert!(canokey::piv::sign(
                    &profile,
                    canokey::piv::Slot::Signature,
                    Algorithm::Ed25519,
                    canokey::piv::SignInput::Message(canokey::SecretBytes::new(b"hello".to_vec())),
                    canokey::piv::Access::None,
                    Default::default()
                )
                .is_err());
            }
        }
    }
}
