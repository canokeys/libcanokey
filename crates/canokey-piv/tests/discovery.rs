use canokey_piv::*;
use canokey_protocol::{ErrorKind, SecretReference, Step};
#[test]
fn selected_version_and_configuration_validate_observations() {
    let mut version = read_version_selected(Default::default()).unwrap();
    version.start().unwrap();
    assert_eq!(version.command().unwrap().as_bytes(), &[0, 0xfd, 0, 0, 0]);
    assert_eq!(version.advance(&[6, 0, 0, 0x90, 0]).unwrap(), Step::Done);
    assert_eq!(version.result().unwrap().as_bytes(), &[6, 0, 0]);
    let mut malformed = read_version_selected(Default::default()).unwrap();
    malformed.start().unwrap();
    assert_eq!(
        malformed.advance(&[6, 0, 0x90, 0]).unwrap_err().kind,
        ErrorKind::InvalidResponse
    );
    let mut config = read_configuration_selected(Default::default()).unwrap();
    config.start().unwrap();
    assert_eq!(config.command().unwrap().as_bytes(), &[0, 0xee, 1, 0, 0]);
    config
        .advance(&[1, 0xe0, 5, 0x16, 0xe1, 0x53, 0x54, 0x90, 0])
        .unwrap();
    assert_eq!(config.result().unwrap().wire_id(Algorithm::Sm2), Some(0x54));
    assert_eq!(config.result().unwrap().wire_id(Algorithm::EccP521), None);
}
#[test]
fn random_is_version_gated_chunked_and_atomic() {
    let mut operation = random_selected(259, Default::default()).unwrap();
    operation.start().unwrap();
    assert_eq!(operation.command().unwrap().as_bytes(), &[0, 0xfd, 0, 0, 0]);
    operation.advance(&[6, 0, 0, 0x90, 0]).unwrap();
    assert_eq!(operation.command().unwrap().as_bytes(), &[0, 0x84, 0, 0, 0]);
    let mut response = vec![0x11; 256];
    response.extend([0x90, 0]);
    operation.advance(&response).unwrap();
    assert_eq!(operation.command().unwrap().as_bytes(), &[0, 0x84, 0, 0, 3]);
    operation.advance(&[1, 2, 3, 0x90, 0]).unwrap();
    let bytes = operation.take_result().unwrap();
    assert_eq!(&bytes.as_bytes()[256..], &[1, 2, 3]);
    for reply in [&[5, 7, 0, 0x90, 0][..], &[0x6d, 0]] {
        let mut old = random_selected(1, Default::default()).unwrap();
        old.start().unwrap();
        assert_eq!(
            old.advance(reply).unwrap_err().kind,
            ErrorKind::UnsupportedFeature
        );
        assert!(old.command().is_err() && old.result().is_err());
    }
    let mut malformed = random_selected(1, Default::default()).unwrap();
    malformed.start().unwrap();
    malformed.advance(&[6, 0, 0, 0x90, 0]).unwrap();
    assert_eq!(
        malformed.advance(&[0x90, 0]).unwrap_err().kind,
        ErrorKind::InvalidResponse
    );
    assert!(malformed.result().is_err());
    assert!(random_selected(usize::MAX, Default::default()).is_err());
    let mut empty = random_selected(0, Default::default()).unwrap();
    empty.start().unwrap();
    assert_eq!(empty.advance(&[6, 0, 0, 0x90, 0]).unwrap(), Step::Done);
    assert!(empty.result().unwrap().is_empty());
}
#[test]
fn selected_pin_status_maps_verify_status_words() {
    // Profile-free: a single empty VERIFY with no SELECT.
    let mut op = get_pin_status_selected(Default::default()).unwrap();
    assert_eq!(op.start().unwrap(), Step::Exchange);
    assert_eq!(op.command().unwrap().as_bytes(), &[0, 0x20, 0, 0x80, 0]);
    assert_eq!(op.advance(&[0x90, 0]).unwrap(), Step::Done);
    assert_eq!(
        op.result().unwrap(),
        &PinStatus {
            verified: Some(true),
            retries_remaining: None,
            retries_total: None,
            blocked: false,
        }
    );
    // 6983 reports a blocked PIN with zero remaining attempts.
    let mut op = get_pin_status_selected(Default::default()).unwrap();
    op.start().unwrap();
    op.advance(&[0x69, 0x83]).unwrap();
    assert_eq!(
        op.result().unwrap(),
        &PinStatus {
            verified: Some(false),
            retries_remaining: Some(0),
            retries_total: None,
            blocked: true,
        }
    );
    // 63Cx carries the remaining retry count as typed status data.
    let mut op = get_pin_status_selected(Default::default()).unwrap();
    op.start().unwrap();
    op.advance(&[0x63, 0xc2]).unwrap();
    assert_eq!(
        op.result().unwrap(),
        &PinStatus {
            verified: Some(false),
            retries_remaining: Some(2),
            retries_total: None,
            blocked: false,
        }
    );
}
#[test]
fn selected_pin_status_rejects_data_and_unmapped_statuses() {
    // Nonempty response data is malformed for an empty VERIFY query.
    let mut op = get_pin_status_selected(Default::default()).unwrap();
    op.start().unwrap();
    assert_eq!(
        op.advance(&[1, 0x90, 0]).unwrap_err().kind,
        ErrorKind::InvalidResponse
    );
    // Other statuses surface as authentication-context errors naming the PIN.
    let mut op = get_pin_status_selected(Default::default()).unwrap();
    op.start().unwrap();
    let error = op.advance(&[0x69, 0x82]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::SecurityStatusNotSatisfied);
    assert_eq!(error.reference, Some(SecretReference::Pin));
}
