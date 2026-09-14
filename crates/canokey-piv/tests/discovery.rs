use canokey_piv::*;
use canokey_protocol::{ErrorKind, Step};
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
