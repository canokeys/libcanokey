use canokey_compat::{Capability, DeviceObservations, DeviceProfile, Support};
use canokey_oath::*;
use canokey_protocol::{ErrorKind, OperationOptions, SecretBytes, Step};

fn profile(version: &str) -> DeviceProfile {
    let mut o = DeviceObservations::new(version.as_bytes().to_vec());
    o.serial = Some(vec![1, 2, 3, 4]);
    DeviceProfile::from_observations(o).unwrap()
}
fn name() -> Name {
    Name::from_bytes(b"a").unwrap()
}
fn calculate(format: Format) -> Request {
    Request::Calculate {
        name: name(),
        kind: Kind::Hotp,
        algorithm: Algorithm::Sha1,
        challenge: None,
        format,
    }
}
#[test]
fn legacy_selection_does_not_invent_a_salt_or_version() {
    let mut op = operation(&profile("1.3"), Request::Select, None, Default::default()).unwrap();
    op.start().unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0, 0xa4, 4, 0, 7, 0xa0, 0, 0, 5, 0x27, 0x21, 1, 0]
    );
    op.advance(&[0x90, 0]).unwrap();
    assert!(matches!(
        op.take_result().unwrap(),
        Outcome::LegacySelection {
            serial: Some([1, 2, 3, 4])
        }
    ));
    let mut op = operation(&profile("1.3"), Request::Select, None, Default::default()).unwrap();
    op.start().unwrap();
    assert_eq!(
        op.advance(&[0x79, 3, 6, 0, 0, 0x90, 0]).unwrap_err().kind,
        ErrorKind::InvalidResponse
    );
}
#[test]
fn legacy_list_pages_preserve_metadata_and_use_only_send_remaining() {
    let mut op = operation(&profile("1.3"), Request::List, None, Default::default()).unwrap();
    op.start().unwrap();
    op.advance(&[0x90, 0]).unwrap();
    assert_eq!(op.command().unwrap().as_bytes(), &[0, 3, 0, 0, 255]);
    op.advance(&[0x71, 1, b'a', 0x75, 2, 0x21, 6, 0x61, 0xff])
        .unwrap();
    assert_eq!(op.command().unwrap().as_bytes(), &[0, 6, 0, 0, 255]);
    op.advance(&[0x71, 1, b'b', 0x75, 2, 0x12, 8, 0x90, 0])
        .unwrap();
    assert_eq!(op.command().unwrap().as_bytes(), &[0, 6, 0, 0, 255]);
    assert_eq!(op.advance(&[0x69, 0x85]).unwrap(), Step::Done);
    let Outcome::Entries(entries) = op.take_result().unwrap() else {
        panic!()
    };
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].digits, Some(8));
    assert_eq!(entries[1].algorithm_type, 0x12);
}
#[test]
fn legacy_touch_hotp_and_all_transcripts() {
    let request = Request::Put(Credential {
        name: name(),
        kind: Kind::Totp,
        algorithm: Algorithm::Sha1,
        digits: 6,
        secret: SecretBytes::new(vec![42]),
        require_touch: true,
        increasing: false,
        initial_counter: 0,
    });
    let mut op = operation(&profile("1.3"), request, None, Default::default()).unwrap();
    op.start().unwrap();
    op.advance(&[0x90, 0]).unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0, 1, 0, 0, 11, 0x71, 1, b'a', 0x73, 3, 0x21, 6, 42, 0x78, 1, 2, 0]
    );
    op.advance(&[0x90, 0]).unwrap();
    let mut op = operation(
        &profile("1.3"),
        calculate(Format::Truncated),
        None,
        Default::default(),
    )
    .unwrap();
    op.start().unwrap();
    op.advance(&[0x90, 0]).unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0, 4, 0, 0, 3, 0x71, 1, b'a', 0]
    );
    op.advance(&[0x76, 5, 6, 0, 0, 0, 42, 0x90, 0]).unwrap();
    let Outcome::Calculations(c) = op.take_result().unwrap() else {
        panic!()
    };
    assert_eq!(c[0].decimal().unwrap().as_bytes(), b"000042");
    let mut op = operation(
        &profile("1.3"),
        Request::CalculateAll {
            challenge: [0; 8],
            format: Format::Truncated,
        },
        None,
        Default::default(),
    )
    .unwrap();
    op.start().unwrap();
    op.advance(&[0x90, 0]).unwrap();
    assert_eq!(&op.command().unwrap().as_bytes()[..4], &[0, 5, 0, 0]);
    op.advance(&[0x71, 1, b'a', 0x7c, 1, 6, 0x90, 0]).unwrap();
    op.advance(&[0x69, 0x85]).unwrap();
    let Outcome::Calculations(c) = op.take_result().unwrap() else {
        panic!()
    };
    assert!(matches!(c[0].code, Code::TouchRequired));
}
#[test]
fn firmware_boundaries_fail_before_any_colliding_or_downgraded_command() {
    for version in ["1.3", "1.5.2", "1.6.1", "1.6.2"] {
        assert_eq!(
            operation(
                &profile(version),
                calculate(Format::Full),
                None,
                Default::default()
            )
            .unwrap_err()
            .kind,
            ErrorKind::UnsupportedFeature
        );
    }
    for request in [
        Request::ClearCode,
        Request::Rename {
            old: name(),
            new: name(),
        },
    ] {
        assert_eq!(
            operation(&profile("1.3"), request, None, Default::default())
                .unwrap_err()
                .kind,
            ErrorKind::UnsupportedFeature
        );
    }
    for version in ["1.4.0", "3.2.0", "3.2.0-dev", "nonsense"] {
        assert_eq!(
            operation(&profile(version), Request::List, None, Default::default())
                .unwrap_err()
                .kind,
            ErrorKind::CapabilityUnknown
        );
    }
    assert_eq!(
        profile("1.6.2")
            .capability(Capability::OathRenameCollisionCheck)
            .support,
        Support::Unsupported
    );
    assert_eq!(
        profile("3.0.0")
            .capability(Capability::OathReliablePagination)
            .support,
        Support::Unsupported
    );
    assert_eq!(
        profile("3.0.1")
            .capability(Capability::OathReliablePagination)
            .support,
        Support::Supported
    );
    let mut options = OperationOptions::default();
    options.exchange.max_response_bytes = 71;
    assert_eq!(
        operation(&profile("1.3"), Request::List, None, options)
            .unwrap_err()
            .kind,
        ErrorKind::LimitExceeded
    );
}
#[test]
fn legacy_set_default_single_slot_form_and_option_rejection() {
    let mut op = operation(
        &profile("2.0.0"),
        Request::SetDefault {
            slot: DefaultSlot::Short,
            append_enter: false,
            name: name(),
        },
        None,
        Default::default(),
    )
    .unwrap();
    op.start().unwrap();
    op.advance(&[0x79, 3, 5, 5, 5, 0x71, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0x90, 0])
        .unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0, 0x55, 0, 0, 3, 0x71, 1, b'a', 0]
    );
    assert_eq!(op.advance(&[0x90, 0]).unwrap(), Step::Done);
    assert!(matches!(op.take_result().unwrap(), Outcome::Unit));
    for version in ["1.3", "2.0.0"] {
        for request in [
            Request::SetDefault {
                slot: DefaultSlot::Long,
                append_enter: false,
                name: name(),
            },
            Request::SetDefault {
                slot: DefaultSlot::Short,
                append_enter: true,
                name: name(),
            },
        ] {
            let e = operation(&profile(version), request, None, Default::default()).unwrap_err();
            assert_eq!(e.kind, ErrorKind::InvalidArgument);
        }
    }
}
#[test]
fn old_modern_firmware_uses_modern_select_and_truncated_calculate() {
    for version in ["1.5.2", "1.6.1", "1.6.2", "2.0.0", "3.0.1"] {
        let mut op = operation(
            &profile(version),
            calculate(Format::Truncated),
            None,
            Default::default(),
        )
        .unwrap();
        op.start().unwrap();
        op.advance(&[0x79, 3, 5, 5, 5, 0x71, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0x90, 0])
            .unwrap();
        assert_eq!(
            op.command().unwrap().as_bytes(),
            &[0, 0xa2, 0, 1, 3, 0x71, 1, b'a', 0]
        );
        op.advance(&[0x76, 5, 6, 0, 0, 0, 1, 0x90, 0]).unwrap();
    }
}
#[test]
fn challenge_response_requires_pinned_3_1_evidence() {
    for version in ["1.3", "1.5.2", "2.0.1", "3.0.3"] {
        for request in [
            Request::GetSerial,
            Request::ChallengeResponseHmac {
                slot: HmacSlot::Short,
                challenge: vec![1],
            },
        ] {
            assert_eq!(
                operation(&profile(version), request, None, Default::default())
                    .unwrap_err()
                    .kind,
                ErrorKind::UnsupportedFeature
            );
        }
    }
    for version in ["3.2.0", "nonsense"] {
        assert_eq!(
            operation(
                &profile(version),
                Request::GetSerial,
                None,
                Default::default()
            )
            .unwrap_err()
            .kind,
            ErrorKind::CapabilityUnknown
        );
    }
    assert_eq!(
        profile("3.0.3")
            .capability(Capability::OathChallengeResponse)
            .support,
        Support::Unsupported
    );
    assert_eq!(
        profile("3.1.0")
            .capability(Capability::OathChallengeResponse)
            .support,
        Support::Supported
    );
}
