#[allow(dead_code)]
mod support;
use canokey_piv::*;
use canokey_protocol::{ErrorKind, SecretReference, Step};
use support::*;
#[test]
fn legacy_form_is_explicit_and_selected_commands_never_reselect() {
    assert!(Pin::from_bytes(b"1").is_err());
    assert!(Pin::from_legacy_bytes(b"").is_err());
    assert!(Puk::from_legacy_bytes(b"123456789").is_err());
    let profile = profile("3.1.0");
    let context = PivAccessContext::selected(&profile).unwrap();
    let mut verify = credential_in_context(
        &context,
        CredentialAction::VerifyPin(Pin::from_legacy_bytes(b"1").unwrap()),
        Default::default(),
    )
    .unwrap();
    let mut change = credential_in_context(
        &context,
        CredentialAction::ChangePin {
            old: Pin::from_legacy_bytes(b"1").unwrap(),
            new: Pin::from_legacy_bytes(&[0xff]).unwrap(),
        },
        Default::default(),
    )
    .unwrap();
    let mut logout =
        credential_in_context(&context, CredentialAction::Logout, Default::default()).unwrap();
    let mut unblock = credential_in_context(
        &context,
        CredentialAction::UnblockPin {
            puk: Puk::from_bytes(b"12345678").unwrap(),
            new_pin: Pin::from_bytes(b"123456").unwrap(),
        },
        Default::default(),
    )
    .unwrap();
    drop(context);
    drop(profile);
    verify.start().unwrap();
    assert_eq!(
        verify.command().unwrap().as_bytes(),
        hex("002000800831ffffffffffffff")
    );
    let error = verify.advance(&hex("63c2")).unwrap_err();
    assert_eq!(error.kind, ErrorKind::AuthenticationFailed);
    assert_eq!(error.reference, Some(SecretReference::Pin));
    assert_eq!(error.retries_remaining, Some(2));
    assert!(verify.command().is_err());
    change.start().unwrap();
    assert_eq!(
        change.command().unwrap().as_bytes(),
        hex("002400801031ffffffffffffffffffffffffffffff")
    );
    assert_eq!(change.advance(&hex("9000")).unwrap(), Step::Done);
    logout.start().unwrap();
    assert_eq!(logout.command().unwrap().as_bytes(), hex("0020ff8000"));
    assert_eq!(logout.advance(&hex("9000")).unwrap(), Step::Done);
    unblock.start().unwrap();
    assert_eq!(
        unblock.command().unwrap().as_bytes(),
        hex("002c0080103132333435363738313233343536ffff")
    );
    let error = unblock.advance(&hex("63c1")).unwrap_err();
    assert_eq!(error.reference, Some(SecretReference::Puk));
    assert_eq!(error.retries_remaining, Some(1));
    assert!(unblock.command().is_err());
}
#[test]
fn legacy_le_and_puk_reference_are_preserved() {
    let context = PivAccessContext::selected(&profile("1.3")).unwrap();
    let mut operation = credential_in_context(
        &context,
        CredentialAction::ChangePuk {
            old: Puk::from_legacy_bytes(b"1").unwrap(),
            new: Puk::from_legacy_bytes(b"2").unwrap(),
        },
        Default::default(),
    )
    .unwrap();
    operation.start().unwrap();
    assert_eq!(
        operation.command().unwrap().as_bytes(),
        hex("002400811031ffffffffffffff32ffffffffffffff00")
    );
    let error = operation.advance(&hex("6983")).unwrap_err();
    assert_eq!(error.kind, ErrorKind::PinBlocked);
    assert_eq!(error.reference, Some(SecretReference::Puk));
}

#[test]
fn credential_acknowledgements_are_empty_and_terminal() {
    let context = PivAccessContext::selected(&profile("3.1.0")).unwrap();
    let mut operation = credential_in_context(
        &context,
        CredentialAction::VerifyPin(Pin::from_bytes(b"123456").unwrap()),
        Default::default(),
    )
    .unwrap();
    operation.start().unwrap();
    let error = operation.advance(&hex("019000")).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert!(operation.result().is_err() && operation.command().is_err());
}
