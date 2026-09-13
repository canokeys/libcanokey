use canokey_admin::*;
use canokey_compat::{DeviceObservations, DeviceProfile};
use canokey_protocol::{ErrorKind, Operation, OperationOptions, SecretReference, Step};
fn profile() -> DeviceProfile {
    DeviceProfile::from_observations(DeviceObservations::new(b"3.1.0".to_vec())).unwrap()
}
fn pin() -> Pin {
    Pin::from_bytes(b"654321").unwrap()
}
fn begin(request: Request, authenticate: bool) -> Operation<Outcome> {
    let mut op = operation(
        &profile(),
        request,
        authenticate.then(pin),
        Default::default(),
    )
    .unwrap();
    assert_eq!(op.start().unwrap(), Step::Exchange);
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0, 0xa4, 4, 0, 5, 0xf0, 0, 0, 0, 0]
    );
    op.advance(&[0x90, 0]).unwrap();
    if authenticate {
        assert_eq!(op.command().unwrap().as_bytes(), b"\0\x20\0\0\x06654321");
        op.advance(&[0x90, 0]).unwrap();
    }
    op
}
#[test]
fn patch_preserves_unknowns_and_retains_partial_writes() {
    let mut op = begin(
        Request::Configure(ConfigurationPatch {
            led_on: Some(false),
            ndef_enabled: Some(false),
            ..Default::default()
        }),
        true,
    );
    assert_eq!(op.command().unwrap().as_bytes(), &[0, 0x42, 0, 0, 0]);
    op.advance(&[1, 0x88, 0, 1, 1, 0xbf, 0x90, 0]).unwrap();
    assert_eq!(op.command().unwrap().as_bytes(), &[0, 0x40, 1, 0]);
    assert!(op.progress().unwrap().reprobe_required);
    op.advance(&[0x90, 0]).unwrap();
    assert_eq!(op.command().unwrap().as_bytes(), &[0, 0x40, 4, 0]);
    assert_eq!(
        op.advance(&[0x69, 0x85]).unwrap_err().kind,
        ErrorKind::ConditionsNotSatisfied
    );
    assert_eq!(op.progress().unwrap().confirmed_writes, 1);
    assert!(op.command().is_err());
}
#[test]
fn unknown_feature_bits_block_all_patch_writes() {
    let mut op = begin(
        Request::Configure(ConfigurationPatch {
            led_on: Some(false),
            feature_mask: 1,
            feature_values: 0,
            ..Default::default()
        }),
        true,
    );
    assert_eq!(
        op.advance(&[1, 0, 0, 1, 1, 0xff, 0x90, 0])
            .unwrap_err()
            .kind,
        ErrorKind::UnsupportedProtocolVersion
    );
    assert_eq!(op.progress().unwrap().confirmed_writes, 0);
    assert!(!op.progress().unwrap().reprobe_required);
}
#[test]
fn no_op_patch_and_ndef_read_only_encoding() {
    let mut op = begin(Request::Configure(ConfigurationPatch::default()), true);
    assert_eq!(
        op.advance(&[1, 9, 0, 1, 1, 0xff, 0x90, 0]).unwrap(),
        Step::Done
    );
    assert!(!op.result().unwrap().reprobe_required);
    let mut op = begin(
        Request::Configure(ConfigurationPatch {
            ndef_read_only: Some(true),
            ..Default::default()
        }),
        true,
    );
    op.advance(&[1, 0, 0, 1, 1, 0x3f, 0x90, 0]).unwrap();
    assert_eq!(op.command().unwrap().as_bytes(), &[0, 8, 1, 0]);
    op.advance(&[0x90, 0]).unwrap();
    assert_eq!(op.take_result().unwrap().confirmed_writes, 1);
}
#[test]
fn pin_errors_are_contextual_and_never_retry() {
    let mut op = operation(
        &profile(),
        Request::VerifyPin,
        Some(pin()),
        Default::default(),
    )
    .unwrap();
    op.start().unwrap();
    op.advance(&[0x90, 0]).unwrap();
    let e = op.advance(&[0x63, 0xc2]).unwrap_err();
    assert_eq!(e.reference, Some(SecretReference::AdminPin));
    assert_eq!(e.retries_remaining, Some(2));
    assert!(op.command().is_err());
    let mut op = begin(Request::PinStatus, false);
    op.advance(&[0x63, 0xc0]).unwrap();
    assert!(matches!(
        op.result().unwrap().value,
        Value::PinStatus(PinStatus {
            blocked: true,
            retries_remaining: Some(0),
            ..
        })
    ));
    assert!(operation(
        &profile(),
        Request::FactoryReset,
        Some(pin()),
        Default::default()
    )
    .is_err());
    assert!(operation(&profile(), Request::VerifyPin, None, Default::default()).is_err());
}
#[test]
fn sm2_signed_patch_preserves_other_id() {
    let mut op = begin(
        Request::ConfigureSm2(Sm2Patch {
            curve_id: Some(-65537),
            algorithm_id: None,
        }),
        true,
    );
    assert_eq!(op.command().unwrap().as_bytes(), &[0, 0x11, 0, 0, 0]);
    op.advance(&[0, 0, 0, 9, 0xff, 0xff, 0xff, 0xca, 0x90, 0])
        .unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0, 0x12, 0, 0, 8, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xca]
    );
    assert_eq!(
        op.advance(&[0x6c, 8]).unwrap_err().kind,
        ErrorKind::UnexpectedStatusWord
    );
    assert!(op.progress().unwrap().reprobe_required);
    for id in [0, 1, 8, 256, 259] {
        assert!(operation(
            &profile(),
            Request::ConfigureSm2(Sm2Patch {
                curve_id: Some(id),
                algorithm_id: None
            }),
            Some(pin()),
            Default::default()
        )
        .is_err());
    }
}
#[test]
fn read_formats_and_malformed_data() {
    let mut op = begin(Request::FlashUsage, false);
    op.advance(&[250, 1, 0x90, 0]).unwrap();
    assert!(matches!(
        op.result().unwrap().value,
        Value::FlashUsage(FlashUsage {
            used_kib: 250,
            total_kib: 1
        })
    ));
    let mut op = begin(Request::AppletUsage, false);
    let mut response = [0; 50];
    response[..6].copy_from_slice(&[0xfe, 0x80, 0x12, 0x34, 0x56, 0x78]);
    response[48] = 0x90;
    op.advance(&response).unwrap();
    let Value::AppletUsage(entries) = &op.result().unwrap().value else {
        panic!()
    };
    assert_eq!(
        entries[0],
        AppletUsage {
            applet_id: 0xfe,
            flags: 0x80,
            logical_bytes: 0x12345678
        }
    );
    for request in [
        Request::Configuration,
        Request::Sm2Configuration,
        Request::AppletUsage,
        Request::Serial,
        Request::NfcStatus,
    ] {
        let protected = matches!(request, Request::Sm2Configuration);
        assert_eq!(
            begin(request, protected)
                .advance(&[2, 0x90, 0])
                .unwrap_err()
                .kind,
            ErrorKind::InvalidResponse
        );
    }
}
#[test]
fn explicit_reset_and_change_pin() {
    let mut op = begin(Request::FactoryReset, false);
    assert_eq!(op.command().unwrap().as_bytes(), b"\0\x50\0\0\x05RESET");
    op.advance(&[0x69, 0x85]).unwrap_err();
    assert!(op.progress().unwrap().reprobe_required);
    let mut op = begin(Request::ResetApplet(Applet::Piv), true);
    assert_eq!(op.command().unwrap().as_bytes(), &[0, 4, 0, 0]);
    op.cancel();
    assert!(op.progress().is_none());
    assert!(op.command().is_err());
    let mut op = begin(
        Request::ChangePin(Pin::from_bytes(b"newpin").unwrap()),
        true,
    );
    assert_eq!(op.command().unwrap().as_bytes(), b"\0\x21\0\0\x06newpin");
    op.advance(&[0x90, 0]).unwrap();
    assert_eq!(op.result().unwrap().confirmed_writes, 1);
}
#[test]
fn preflight_limits_and_unknown_firmware() {
    let mut options = OperationOptions::default();
    options.exchange.max_command_bytes = 10;
    assert_eq!(
        operation(&profile(), Request::ChangePin(pin()), Some(pin()), options)
            .unwrap_err()
            .kind,
        ErrorKind::LimitExceeded
    );
    let unknown =
        DeviceProfile::from_observations(DeviceObservations::new(b"9.0.0".to_vec())).unwrap();
    assert_eq!(
        operation(&unknown, Request::Configuration, None, Default::default())
            .unwrap_err()
            .kind,
        ErrorKind::CapabilityUnknown
    );
    assert!(Configuration::parse(&[1, 0, 0, 1, 1, 0xff]).is_ok());
    assert!(Configuration::parse(&[2, 0, 0, 1, 1, 0]).is_err());
    let p = Pin::from_bytes(b"super-secret").unwrap();
    assert!(!format!("{p:?}").contains("super-secret"));
}
