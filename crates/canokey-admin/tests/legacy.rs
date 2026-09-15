use canokey_admin::*;
use canokey_compat::{AdminConfigurationLayout, DeviceObservations, DeviceProfile};
use canokey_protocol::{ErrorKind, Step};
fn profile(v: &str) -> DeviceProfile {
    DeviceProfile::from_observations(DeviceObservations::new(v.as_bytes().to_vec())).unwrap()
}
fn pin() -> Option<Pin> {
    Some(Pin::from_bytes(b"654321").unwrap())
}
#[test]
fn layouts_keep_absent_flags_and_reserved_bytes_distinct() {
    for (v, raw, layout) in [
        (
            "1.3",
            vec![1, 0, 1, 2, 3, 4, 10],
            AdminConfigurationLayout::TouchPolicies,
        ),
        (
            "1.5.2",
            vec![1, 0, 1, 1, 0],
            AdminConfigurationLayout::Basic,
        ),
        (
            "1.6.1",
            vec![1, 0, 1, 1, 0],
            AdminConfigurationLayout::Basic,
        ),
        (
            "1.6.2",
            vec![1, 0, 1, 1, 0, 1],
            AdminConfigurationLayout::KeyboardReturn,
        ),
        (
            "2.0.0",
            vec![1, 0, 1, 1, 0, 1],
            AdminConfigurationLayout::KeyboardReturn,
        ),
        (
            "3.0.0",
            vec![1, 0x88, 1, 1, 0, 0xaa],
            AdminConfigurationLayout::Reserved,
        ),
    ] {
        assert_eq!(
            operation(
                &profile(v),
                Request::Configuration,
                None,
                Default::default()
            )
            .unwrap_err()
            .kind,
            ErrorKind::SecurityStatusNotSatisfied
        );
        let mut op = operation(
            &profile(v),
            Request::Configuration,
            pin(),
            Default::default(),
        )
        .unwrap();
        op.start().unwrap();
        op.advance(&[0x90, 0]).unwrap();
        assert_eq!(op.command().unwrap().as_bytes(), b"\0\x20\0\0\x06654321\0");
        op.advance(&[0x90, 0]).unwrap();
        let mut reply = raw.clone();
        reply.extend([0x90, 0]);
        op.advance(&reply).unwrap();
        let Value::LegacyConfiguration(c) = op.take_result().unwrap().value else {
            panic!()
        };
        assert_eq!(c.raw(), raw);
        assert_eq!(c.layout(), layout);
        if v == "1.3" {
            assert_eq!(c.ndef_enabled(), None);
            assert_eq!(c.openpgp_touch(), Some([2, 3, 4, 10]));
        }
        if v == "3.0.0" {
            assert_eq!(c.keyboard_interface(), None);
            assert_eq!(c.keyboard_return(), None);
        }
        assert!(LegacyConfiguration::parse(&profile(v), &raw[..raw.len() - 1]).is_err());
    }
    assert!(LegacyConfiguration::parse(&profile("1.5.2"), &[1, 0, 0, 1, 0, 0]).is_err());
}
#[test]
fn patches_do_not_treat_keyboard_or_reserved_octets_as_feature_masks() {
    for v in ["1.6.2", "2.0.1", "3.0.0"] {
        let p = ConfigurationPatch {
            led_on: Some(false),
            ..Default::default()
        };
        let mut op = operation(
            &profile(v),
            Request::Configure(p),
            pin(),
            Default::default(),
        )
        .unwrap();
        op.start().unwrap();
        op.advance(&[0x90, 0]).unwrap();
        op.advance(&[0x90, 0]).unwrap();
        op.advance(&[1, 0, 0, 1, 1, 1, 0x90, 0]).unwrap();
        assert_eq!(op.command().unwrap().as_bytes(), &[0, 0x40, 1, 0, 0]);
        assert_eq!(op.advance(&[0x90, 0]).unwrap(), Step::Done);
        assert_eq!(op.take_result().unwrap().confirmed_writes, 1);
        let p = ConfigurationPatch {
            feature_mask: 1,
            feature_values: 0,
            ..Default::default()
        };
        assert_eq!(
            operation(
                &profile(v),
                Request::Configure(p),
                pin(),
                Default::default()
            )
            .unwrap_err()
            .kind,
            ErrorKind::UnsupportedFeature
        );
    }
}
#[test]
fn legacy_switches_and_colliding_reset_are_explicitly_gated() {
    for (v, request, command) in [
        (
            "1.3",
            Request::SetKeyboardInterface(true),
            [0, 0x40, 3, 1, 0],
        ),
        (
            "1.6.2",
            Request::SetKeyboardReturn(true),
            [0, 0x40, 6, 1, 0],
        ),
        (
            "2.0.0",
            Request::SetLegacyPivExtensions(true),
            [0, 0x40, 7, 1, 0],
        ),
        (
            "1.3",
            Request::SetLegacyOpenPgpTouch(LegacyOpenPgpTouch::CacheSeconds(10)),
            [0, 9, 3, 10, 0],
        ),
        ("3.0.0", Request::ResetApplet(Applet::Ctap), [0, 9, 0, 0, 0]),
    ] {
        let mut op = operation(&profile(v), request, pin(), Default::default()).unwrap();
        op.start().unwrap();
        op.advance(&[0x90, 0]).unwrap();
        op.advance(&[0x90, 0]).unwrap();
        assert_eq!(op.command().unwrap().as_bytes(), command);
        op.advance(&[0x90, 0]).unwrap();
        assert!(op.take_result().unwrap().reprobe_required);
    }
    for (v, request) in [
        ("1.3", Request::ResetApplet(Applet::Ctap)),
        ("2.0.0", Request::ResetApplet(Applet::Pass)),
        (
            "3.0.0",
            Request::SetLegacyOpenPgpTouch(LegacyOpenPgpTouch::Signature(false)),
        ),
        ("3.0.0", Request::SetKeyboardReturn(false)),
        ("3.1.0", Request::SetLegacyPivExtensions(true)),
        ("1.5.2", Request::CoreCommit),
        ("3.0.1", Request::AppletUsage),
    ] {
        assert_eq!(
            operation(&profile(v), request, pin(), Default::default())
                .unwrap_err()
                .kind,
            ErrorKind::UnsupportedFeature
        );
    }
}
#[test]
fn nfc_read_authentication_and_sm2_layout_have_separate_boundaries() {
    assert_eq!(
        operation(
            &profile("3.0.0"),
            Request::NfcStatus,
            None,
            Default::default()
        )
        .unwrap_err()
        .kind,
        ErrorKind::SecurityStatusNotSatisfied
    );
    assert!(operation(
        &profile("3.0.1"),
        Request::NfcStatus,
        None,
        Default::default()
    )
    .is_ok());
    let raw = [1, 9, 0, 0, 0, 0xd0, 0xff, 0xff, 0xff];
    let mut op = operation(
        &profile("3.0.0"),
        Request::Sm2Configuration,
        pin(),
        Default::default(),
    )
    .unwrap();
    op.start().unwrap();
    op.advance(&[0x90, 0]).unwrap();
    op.advance(&[0x90, 0]).unwrap();
    let mut reply = raw.to_vec();
    reply.extend([0x90, 0]);
    op.advance(&reply).unwrap();
    let Value::LegacySm2Configuration(c) = op.take_result().unwrap().value else {
        panic!()
    };
    assert!(c.enabled());
    assert_eq!(c.raw(), &raw);
    let mut op = operation(
        &profile("3.0.0"),
        Request::WriteLegacySm2(c),
        pin(),
        Default::default(),
    )
    .unwrap();
    op.start().unwrap();
    op.advance(&[0x90, 0]).unwrap();
    op.advance(&[0x90, 0]).unwrap();
    let mut expected = vec![0, 0x12, 0, 0, 9];
    expected.extend(raw);
    expected.push(0);
    assert_eq!(op.command().unwrap().as_bytes(), expected);
    assert_eq!(
        operation(
            &profile("3.1.0"),
            Request::WriteLegacySm2(c),
            pin(),
            Default::default()
        )
        .unwrap_err()
        .kind,
        ErrorKind::UnsupportedFeature
    );
    assert_eq!(
        operation(
            &profile("3.0.0"),
            Request::ConfigureSm2(Sm2Patch::default()),
            pin(),
            Default::default()
        )
        .unwrap_err()
        .kind,
        ErrorKind::UnsupportedFeature
    );
}

#[test]
fn keyboard_keymap_requires_fixed_wire_length() {
    let map = [0u8; 256];
    assert_eq!(KeyboardKeymap::from_bytes(&map).unwrap().as_bytes(), &map);
    assert!(KeyboardKeymap::from_bytes(&map[..255]).is_err());
}
