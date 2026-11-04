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
