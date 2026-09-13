use canokey_compat::{DeviceObservations, DeviceProfile};
use canokey_openpgp::*;
use canokey_protocol::{
    tlv::{Tag, TlvWriter},
    ErrorKind, Operation, SecretBytes, SecretReference,
};
fn profile() -> DeviceProfile {
    DeviceProfile::from_observations(DeviceObservations::new(b"3.1.0".to_vec())).unwrap()
}
fn secret(b: &[u8]) -> SecretBytes {
    SecretBytes::new(b.to_vec())
}
fn password() -> Password {
    Password::from_bytes(b"87654321").unwrap()
}
fn access(reference: PasswordReference) -> Access {
    Access {
        reference,
        password: password(),
    }
}
fn begin(request: Request, reference: Option<PasswordReference>) -> Operation<Outcome> {
    let mut op = operation(
        &profile(),
        request,
        reference.map(access),
        Default::default(),
    )
    .unwrap();
    op.start().unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0, 0xa4, 4, 0, 6, 0xd2, 0x76, 0, 1, 0x24, 1]
    );
    op.advance(&[0x90, 0]).unwrap();
    op
}
fn wrap(tag: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut w = TlvWriter::new(4096);
    w.push(Tag::from_bytes(tag).unwrap(), bytes).unwrap();
    w.into_bytes().as_bytes().to_vec()
}
fn attrs(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut b = wrap(&[0x6e], &wrap(&[0x73], &wrap(&[tag], bytes)));
    b.extend([0x90, 0]);
    b
}
#[test]
fn independent_password_modes_and_no_retry() {
    for (request, r, command) in [
        (
            Request::Sign(Algorithm::EccP256, secret(&[42])),
            PasswordReference::Pw1Sign,
            vec![0, 0x2a, 0x9e, 0x9a, 1, 42],
        ),
        (
            Request::Authenticate(Algorithm::EccP256, secret(&[42])),
            PasswordReference::Pw1Other,
            vec![0, 0x88, 0, 0, 1, 42],
        ),
    ] {
        let tag = if r == PasswordReference::Pw1Sign {
            0xc1
        } else {
            0xc3
        };
        let mut op = begin(request, Some(r));
        assert_eq!(op.command().unwrap().as_bytes(), &[0, 0xca, 0, 0x6e, 0]);
        op.advance(&attrs(tag, &[0x13, 0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7]))
            .unwrap();
        let mut verify = vec![0, 0x20, 0, if tag == 0xc1 { 0x81 } else { 0x82 }, 8];
        verify.extend(b"87654321");
        assert_eq!(op.command().unwrap().as_bytes(), verify);
        op.advance(&[0x90, 0]).unwrap();
        assert_eq!(op.command().unwrap().as_bytes(), command);
        assert_eq!(
            op.advance(&[0x6c, 64]).unwrap_err().kind,
            ErrorKind::UnexpectedStatusWord
        );
        assert!(op.command().is_err());
    }
    assert!(operation(
        &profile(),
        Request::Sign(Algorithm::Ed25519, secret(b"a")),
        Some(access(PasswordReference::Pw1Other)),
        Default::default()
    )
    .is_err());
    let mut op = begin(Request::Verify, Some(PasswordReference::Pw3));
    let e = op.advance(&[0x69, 0x82]).unwrap_err();
    assert_eq!(e.kind, ErrorKind::AuthenticationFailed);
    assert_eq!(e.reference, Some(SecretReference::Pw3));
    assert_eq!(e.retries_remaining, None);
}
#[test]
fn attribute_mismatch_fails_before_authentication() {
    let mut op = begin(
        Request::Sign(Algorithm::Ed25519, secret(b"hello")),
        Some(PasswordReference::Pw1Sign),
    );
    assert_eq!(
        op.advance(&attrs(0xc1, &[1, 8, 0, 0, 32, 2]))
            .unwrap_err()
            .kind,
        ErrorKind::UnsupportedAlgorithm
    );
    assert!(op.command().is_err());
    assert!(operation(
        &profile(),
        Request::Sign(Algorithm::Sm2, secret(&[1; 32])),
        Some(access(PasswordReference::Pw1Sign)),
        Default::default()
    )
    .is_err());
}
#[test]
fn certificate_selection_follows_admin_and_chaining_keeps_occurrence() {
    let mut op = begin(
        Request::WriteCertificate(Slot::Authentication, secret(&[42; 300])),
        Some(PasswordReference::Pw3),
    );
    op.advance(&[0x90, 0]).unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0, 0xa5, 2, 4, 6, 0x60, 4, 0x5c, 2, 0x7f, 0x21]
    );
    op.advance(&[0x90, 0]).unwrap();
    let c = op.command().unwrap().as_bytes();
    assert_eq!(&c[..5], &[0x10, 0xda, 0x7f, 0x21, 255]);
    assert_eq!(c.len(), 260);
    op.advance(&[0x90, 0]).unwrap();
    assert_eq!(
        &op.command().unwrap().as_bytes()[..5],
        &[0, 0xda, 0x7f, 0x21, 45]
    );
    op.advance(&[0x90, 0]).unwrap();
    assert!(matches!(op.result().unwrap(), Outcome::Unit));
}
#[test]
fn password_change_unblock_and_retry_reset_are_explicit() {
    let mut op = begin(
        Request::ChangePassword {
            reference: PasswordReference::Pw3,
            old: password(),
            new: Password::from_bytes(b"newadmin").unwrap(),
        },
        None,
    );
    assert_eq!(
        op.command().unwrap().as_bytes(),
        b"\0\x24\0\x83\x1087654321newadmin"
    );
    let e = op.advance(&[0x69, 0x83]).unwrap_err();
    assert_eq!(e.kind, ErrorKind::PinBlocked);
    let mut op = begin(
        Request::UnblockWithCode {
            code: password(),
            new: Password::from_bytes(b"newpin").unwrap(),
        },
        None,
    );
    assert_eq!(
        op.command().unwrap().as_bytes(),
        b"\0\x2c\0\x81\x0e87654321newpin"
    );
    let e = op.advance(&[0x69, 0x82]).unwrap_err();
    assert_eq!(e.reference, Some(SecretReference::ResetCode));
    let mut op = begin(
        Request::ResetRetries([3, 5, 7]),
        Some(PasswordReference::Pw3),
    );
    op.advance(&[0x90, 0]).unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0, 0xf2, 0, 0, 3, 3, 5, 7]
    );
    op.advance(&[0x90, 0]).unwrap();
    let mut op = begin(Request::PinStatus(PasswordReference::Pw1Other), None);
    op.advance(&[0x63, 0xc0]).unwrap();
    assert!(matches!(
        op.result().unwrap(),
        Outcome::PinStatus(PinStatus {
            blocked: true,
            retries_remaining: Some(0),
            ..
        })
    ));
}
#[test]
fn public_key_and_import_wire_formats() {
    let attr = [0x16, 0x2b, 6, 1, 4, 1, 0xda, 0x47, 15, 1];
    let mut op = begin(Request::ReadPublicKey(Slot::Signature), None);
    op.advance(&attrs(0xc1, &attr)).unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0, 0x47, 0x81, 0, 2, 0xb6, 0]
    );
    let mut response = wrap(&[0x7f, 0x49], &wrap(&[0x86], &[7; 32]));
    response.extend([0x90, 0]);
    op.advance(&response).unwrap();
    let Outcome::PublicKey(key) = op.take_result().unwrap() else {
        panic!()
    };
    assert_eq!(key.to_spki_der().unwrap().len(), 44);
    let mut op = begin(
        Request::ImportKey {
            slot: Slot::Signature,
            algorithm: Algorithm::Ed25519,
            key: PrivateKey::Ec(secret(&[42; 32])),
        },
        Some(PasswordReference::Pw3),
    );
    op.advance(&attrs(0xc1, &attr)).unwrap();
    op.advance(&[0x90, 0]).unwrap();
    let mut expected = vec![
        0, 0xdb, 0x3f, 0xff, 44, 0x4d, 42, 0xb6, 0, 0x7f, 0x48, 2, 0x92, 32, 0x5f, 0x48, 32,
    ];
    expected.extend([42; 32]);
    assert_eq!(op.command().unwrap().as_bytes(), expected);
    op.advance(&[0x90, 0]).unwrap();
}
#[test]
fn rsa_decipher_and_ecdh_are_distinct_from_piv() {
    let mut op = begin(
        Request::Decrypt(Algorithm::Rsa2048, secret(&[42; 256])),
        Some(PasswordReference::Pw1Other),
    );
    op.advance(&attrs(0xc2, &[1, 8, 0, 0, 32, 2])).unwrap();
    op.advance(&[0x90, 0]).unwrap();
    assert_eq!(
        &op.command().unwrap().as_bytes()[..6],
        &[0x10, 0x2a, 0x80, 0x86, 255, 0]
    );
    op.advance(&[0x90, 0]).unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0, 0x2a, 0x80, 0x86, 2, 42, 42]
    );
    op.advance(b"plaintext\x90\0").unwrap();
    let Outcome::Bytes(bytes) = op.result().unwrap() else {
        panic!()
    };
    assert_eq!(bytes.as_bytes(), b"plaintext");
    let mut op = begin(
        Request::Derive(Algorithm::X25519, vec![9; 32]),
        Some(PasswordReference::Pw1Other),
    );
    op.advance(&attrs(0xc2, &[0x12, 0x2b, 6, 1, 4, 1, 0x97, 0x55, 1, 5, 1]))
        .unwrap();
    op.advance(&[0x90, 0]).unwrap();
    assert_eq!(
        &op.command().unwrap().as_bytes()[..12],
        &[0, 0x2a, 0x80, 0x86, 39, 0xa6, 37, 0x7f, 0x49, 34, 0x86, 32]
    );
    let mut response = vec![0; 32];
    response.extend([0x90, 0]);
    assert_eq!(
        op.advance(&response).unwrap_err().kind,
        ErrorKind::InvalidResponse
    );
}
#[test]
fn parsed_objects_preserve_unknown_fields_and_check_known_lengths() {
    let mut fields = wrap(&[0xc4], &[0xfe, 64, 64, 64, 3, 4, 5]);
    fields.extend(wrap(&[0xd6], &[0xee, 0xaa]));
    fields.extend(wrap(&[0xef], &[1, 2, 3]));
    let mut outer = wrap(&[0x4f], &[42; 16]);
    outer.extend(wrap(&[0x73], &fields));
    let bytes = wrap(&[0x6e], &outer);
    let app = ApplicationData::parse(&bytes, 4096).unwrap();
    assert_eq!(app.aid().unwrap(), Some([42; 16]));
    assert_eq!(
        app.password_status().unwrap().unwrap().signature_policy,
        0xfe
    );
    assert_eq!(
        app.touch_policy(Slot::Signature).unwrap(),
        Some([0xee, 0xaa])
    );
    assert_eq!(app.discretionary[2].tag, 0xef);
    assert!(ApplicationData::parse(&bytes, 1).is_err());
    let b = wrap(&[0x65], &[0x5b, 1, 0xff, 0x5f, 0x2d, 2, b'e', b'n']);
    let holder = CardholderData::parse(&b, 64).unwrap();
    assert_eq!(holder.name().unwrap(), Some(&[0xff][..]));
}
#[test]
fn reset_policies_and_input_limits() {
    for (request, expected) in [
        (Request::Terminate, vec![0, 0xe6, 0, 0]),
        (Request::Activate, vec![0, 0x44, 0, 0]),
    ] {
        let mut op = begin(request, None);
        assert_eq!(op.command().unwrap().as_bytes(), expected);
        op.advance(&[0x69, 0x85]).unwrap_err();
    }
    let mut op = begin(
        Request::WriteData(DataWrite::TouchPolicy(
            Slot::Decryption,
            TouchPolicy::Permanent,
        )),
        Some(PasswordReference::Pw3),
    );
    op.advance(&[0x90, 0]).unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0, 0xda, 0, 0xd7, 2, 2, 0x20]
    );
    op.cancel();
    assert!(op.command().is_err());
    assert!(operation(
        &profile(),
        Request::Sign(Algorithm::Ed25519, secret(&[0; 256])),
        Some(access(PasswordReference::Pw1Sign)),
        Default::default()
    )
    .is_err());
}
