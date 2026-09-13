mod support;
use canokey_piv::*;
use canokey_protocol::{
    tlv::{Tag, TlvWriter},
    ErrorKind, OperationOptions, SecretBytes, Step,
};
use der::Decode;
use support::*;
fn tlv(tag: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut w = TlvWriter::default();
    w.push(Tag::from_bytes(tag).unwrap(), bytes).unwrap();
    w.into_bytes().as_bytes().to_vec()
}
fn response(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    out.extend([0x90, 0]);
    out
}
#[test]
fn owned_metadata_retains_unknown_values_and_retries() {
    let p = profile("3.1.0");
    let mut op =
        get_metadata(&p, MetadataReference::Pin, Access::None, Default::default()).unwrap();
    drop(p);
    selected(&mut op);
    assert_eq!(op.command().unwrap().as_bytes(), hex("00f7008000"));
    op.advance(&hex("0101ff050102060203098801aa8801bb9000"))
        .unwrap();
    let info = op.take_result().unwrap();
    drop(op);
    assert!(matches!(info, Metadata::Pin(_)));
    let f = info.fields();
    assert_eq!(f.is_default, Some(KnownOrUnknown::Unknown(2)));
    assert_eq!(f.retries, Some((3, 9)));
    assert_eq!(f.unknown_fields.len(), 2);
    assert_eq!(f.unknown_fields[1].value.as_bytes(), &[0xbb]);
    assert!(f.public_key.is_none());
    for value in ["0101070101149000", "0201009000", "05009000", "9000"] {
        let mut op = get_metadata(
            &profile("3.1.0"),
            MetadataReference::Key(Slot::Authentication),
            Access::None,
            Default::default(),
        )
        .unwrap();
        selected(&mut op);
        assert!(op.advance(&hex(value)).is_err());
    }
}
#[test]
fn metadata_keys_decode_spki_and_preserve_unknown_algorithms() {
    for (id, known) in [(0x11, true), (0xfa, false)] {
        let public = tlv(&[0x86], &hex(P256_POINT));
        let mut data = vec![1, 1, id, 2, 2, 0xfa, 2, 3, 1, 0xfb];
        data.extend(tlv(&[4], &public));
        let mut op = get_metadata(
            &profile("3.1.0"),
            MetadataReference::Key(Slot::Signature),
            Access::None,
            Default::default(),
        )
        .unwrap();
        selected(&mut op);
        op.advance(&response(&data)).unwrap();
        let f = op.result().unwrap().fields();
        assert_eq!(f.pin_policy, Some(KnownOrUnknown::Unknown(0xfa)));
        assert_eq!(f.origin, Some(KnownOrUnknown::Unknown(0xfb)));
        assert_eq!(f.public_key.is_some(), known);
        assert_eq!(f.public_key_tlv.as_ref().unwrap().as_bytes(), public);
        if let Some(key) = &f.public_key {
            let der = key.to_spki_der().unwrap();
            let spki = spki::SubjectPublicKeyInfoRef::from_der(&der).unwrap();
            assert_eq!(spki.subject_public_key.as_bytes().unwrap(), hex(P256_POINT));
            assert_eq!(spki.algorithm.oid.to_string(), "1.2.840.10045.2.1");
        }
    }
    let key = PublicKey::Raw {
        algorithm: Algorithm::Ed25519,
        bytes: vec![0x42; 32],
    };
    let mut expected = hex("302a300506032b6570032100");
    expected.extend([0x42; 32]);
    assert_eq!(key.to_spki_der().unwrap(), expected);
    let mut rsa = tlv(&[0x81], &[0x80; 256]);
    rsa.extend(tlv(&[0x82], &[1, 0, 1]));
    let key = PublicKey::from_tlv(Algorithm::Rsa2048, &rsa, 1024).unwrap();
    let der = key.to_spki_der().unwrap();
    let spki = spki::SubjectPublicKeyInfoRef::from_der(&der).unwrap();
    assert_eq!(spki.algorithm.oid.to_string(), "1.2.840.113549.1.1.1");
    let rsa = pkcs1::RsaPublicKey::from_der(spki.subject_public_key.as_bytes().unwrap()).unwrap();
    assert_eq!(rsa.public_exponent.as_bytes(), &[1, 0, 1]);
    assert_eq!(rsa.modulus.as_bytes(), &[0x80; 256]);
    for bad in [hex("8600"), tlv(&[0x86], &[0; 65]), hex("810101820100")] {
        assert!(PublicKey::from_tlv(Algorithm::EccP256, &bad, 1024).is_err());
    }
}
#[test]
fn metadata_legacy_status_and_slot_gates_are_narrow() {
    let reference = MetadataReference::Key(Slot::Authentication);
    for version in ["2.0.0", "3.0.3"] {
        let mut op = get_metadata(
            &profile(version),
            reference,
            Access::None,
            Default::default(),
        )
        .unwrap();
        selected(&mut op);
        let error = op.advance(&[0x69, 0]).unwrap_err();
        assert_eq!(
            error.kind,
            if version == "2.0.0" {
                ErrorKind::NotFound
            } else {
                ErrorKind::UnexpectedStatusWord
            }
        );
        assert_eq!(error.status_word.unwrap().raw(), 0x6900);
    }
    assert!(get_metadata(
        &profile("2.0.0"),
        MetadataReference::Key(Slot::Retired(RetiredSlot::new(3).unwrap())),
        Access::None,
        Default::default()
    )
    .is_err());
    let mut op =
        read_algorithm_config(&profile("3.0.3"), Access::None, Default::default()).unwrap();
    selected(&mut op);
    assert_eq!(op.command().unwrap().as_bytes(), hex("00ee010000"));
    op.advance(&[0, 0xe0, 5, 0x16, 0xe1, 0x53, 0x55, 0x90, 0])
        .unwrap();
    assert!(!op.result().unwrap().enabled());
}
#[test]
fn generation_and_import_are_authenticated_and_never_replayed() {
    let mut params = KeyParameters::new(Slot::Signature, Algorithm::EccP256);
    params.pin_policy = PinPolicy::Always;
    params.touch_policy = TouchPolicy::Always;
    let mut op = generate_key(&profile("3.1.0"), params, access(), Default::default()).unwrap();
    authenticate(&mut op);
    assert_eq!(
        op.command().unwrap().as_bytes(),
        hex("0047009c0bac09800111aa0103ab0102")
    );
    let public = tlv(&[0x7f, 0x49], &tlv(&[0x86], &hex(P256_POINT)));
    assert_eq!(op.advance(&response(&public)).unwrap(), Step::Done);
    assert_eq!(op.result().unwrap().algorithm(), Algorithm::EccP256);
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let material = PrivateKeyMaterial::ec_scalar(Algorithm::EccP256, &scalar).unwrap();
    let mut op = import_key(
        &profile("3.1.0"),
        params,
        material,
        access(),
        Default::default(),
    )
    .unwrap();
    scalar.fill(0);
    authenticate(&mut op);
    let command = op.command().unwrap().as_bytes();
    assert_eq!(&command[..7], hex("00fe119c280620"));
    assert_eq!(command[38], 1);
    assert_eq!(&command[39..], hex("aa0103ab0102"));
    assert!(op.advance(&[0x6c, 0x10]).is_err());
    assert!(op.command().is_err());
    assert!(PrivateKeyMaterial::ec_scalar(Algorithm::EccP256, &[0; 32]).is_err());
    assert!(PrivateKeyMaterial::ec_scalar(Algorithm::EccP256, &[0xff; 32]).is_err());
    assert!(generate_key(
        &profile("3.1.0"),
        KeyParameters::new(Slot::Authentication, Algorithm::Rsa1024),
        access(),
        Default::default()
    )
    .is_err());
}
#[test]
fn signing_owns_digest_applies_padding_and_converts_signatures() {
    for digest in [vec![0x42; 64], vec![0x42; 1]] {
        let mut op = sign(
            &profile("3.1.0"),
            Slot::Signature,
            Algorithm::EccP256,
            SignInput::Digest(SecretBytes::new(digest.clone())),
            Access::Pin(Pin::from_bytes(b"123456").unwrap()),
            Default::default(),
        )
        .unwrap();
        selected(&mut op);
        assert_eq!(
            op.command().unwrap().as_bytes(),
            hex("0020008008313233343536ffff")
        );
        op.advance(&[0x90, 0]).unwrap();
        let command = op.command().unwrap().as_bytes();
        assert_eq!(&command[..11], hex("0087119c267c2482008120"));
        assert_eq!(command.len(), 43);
        if digest.len() == 1 {
            assert_eq!(&command[11..42], &[0; 31]);
        } else {
            assert_eq!(&command[11..], &[0x42; 32]);
        }
        op.advance(&hex("7c0a820830060201010201029000")).unwrap();
        let signature = op.take_result().unwrap();
        let mut fixed = vec![0; 64];
        fixed[31] = 1;
        fixed[63] = 2;
        assert_eq!(signature.to_p1363().unwrap(), fixed);
        assert_eq!(
            Signature::from_p1363(Algorithm::EccP256, &fixed)
                .unwrap()
                .as_bytes(),
            signature.as_bytes()
        );
    }
    assert!(Signature::from_p1363(Algorithm::EccP256, &[0; 64]).is_err());
    let mut op = sign(
        &profile("3.1.0"),
        Slot::Signature,
        Algorithm::EccP256,
        SignInput::Digest(SecretBytes::new(vec![1; 32])),
        Access::None,
        Default::default(),
    )
    .unwrap();
    selected(&mut op);
    assert!(op.advance(&hex("7c0a820830060201000201029000")).is_err());
}
#[test]
fn rsa_chaining_and_derive_validate_lengths_without_kdf() {
    let mut op = decrypt(
        &profile("3.1.0"),
        Slot::KeyManagement,
        Algorithm::Rsa2048,
        SecretBytes::new(vec![0x42; 256]),
        Access::None,
        Default::default(),
    )
    .unwrap();
    selected(&mut op);
    assert_eq!(op.command().unwrap().as_bytes()[0], 0x10);
    op.advance(&[0x90, 0]).unwrap();
    assert_eq!(op.command().unwrap().as_bytes()[0], 0);
    // Multi-frame reply exercises GET RESPONSE and the normalized secret length.
    let reply = tlv(&[0x7c], &tlv(&[0x82], &[0x43; 256]));
    let mut first = reply[..200].to_vec();
    first.extend([0x61, 0]);
    op.advance(&first).unwrap();
    assert_eq!(op.command().unwrap().as_bytes(), hex("00c0000000"));
    op.advance(&response(&reply[200..])).unwrap();
    assert_eq!(op.result().unwrap().as_bytes(), &[0x43; 256]);
    let mut op = derive(
        &profile("3.1.0"),
        Slot::KeyManagement,
        Algorithm::EccP256,
        hex(P256_POINT),
        Access::None,
        Default::default(),
    )
    .unwrap();
    selected(&mut op);
    assert_eq!(
        &op.command().unwrap().as_bytes()[..11],
        hex("0087119d477c4582008541")
    );
    op.advance(&response(&tlv(&[0x7c], &tlv(&[0x82], &[0x42; 32]))))
        .unwrap();
    assert_eq!(op.result().unwrap().as_bytes(), &[0x42; 32]);
    for peer in [vec![0; 65], vec![4; 65], hex(P256_POINT)[..33].to_vec()] {
        assert!(derive(
            &profile("3.1.0"),
            Slot::KeyManagement,
            Algorithm::EccP256,
            peer,
            Access::None,
            Default::default()
        )
        .is_err());
    }
    let mut options = OperationOptions::default();
    options.limits.max_input_bytes = 31;
    assert!(sign(
        &profile("3.1.0"),
        Slot::Signature,
        Algorithm::EccP256,
        SignInput::Digest(SecretBytes::new(vec![0; 32])),
        Access::None,
        options
    )
    .is_err());
}

#[test]
fn extended_curve_import_checks_scalars_and_wire_ids() {
    for (algorithm, width, id) in [
        (Algorithm::EccP521, 66, 0x54),
        (Algorithm::Secp256k1, 32, 0x53),
        (Algorithm::Sm2, 32, 0x55),
    ] {
        let mut scalar = vec![0; width];
        scalar[width - 1] = 1;
        let material = PrivateKeyMaterial::ec_scalar(algorithm, &scalar).unwrap();
        let mut op = import_key(
            &profile("3.1.0"),
            KeyParameters::new(Slot::Signature, algorithm),
            material,
            access(),
            Default::default(),
        )
        .unwrap();
        scalar.fill(0);
        authenticate(&mut op);
        let mut expected = vec![0, 0xfe, id, 0x9c, (width + 2) as u8, 6, width as u8];
        expected.extend(vec![0; width - 1]);
        expected.push(1);
        assert_eq!(op.command().unwrap().as_bytes(), expected);
        op.advance(&[0x90, 0]).unwrap();
        assert!(PrivateKeyMaterial::ec_scalar(algorithm, &scalar).is_err());
        assert!(PrivateKeyMaterial::ec_scalar(algorithm, &vec![0xff; width]).is_err());
        assert!(PrivateKeyMaterial::ec_scalar(algorithm, &vec![1; width - 1]).is_err());
    }
}

#[test]
fn extended_ecdh_validates_points_and_retains_raw_secrets() {
    // Standard curve generators (SEC 2), independent of the validator under test.
    let p521 = hex(concat!("04",
        "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
        "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650"));
    let k256 = hex(concat!(
        "04",
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    ));
    for (algorithm, point, width, id) in [
        (Algorithm::EccP521, p521, 66, 0x54),
        (Algorithm::Secp256k1, k256, 32, 0x53),
    ] {
        let mut op = derive(
            &profile("3.1.0"),
            Slot::KeyManagement,
            algorithm,
            point.clone(),
            Access::None,
            Default::default(),
        )
        .unwrap();
        selected(&mut op);
        let cmd = op.command().unwrap().as_bytes();
        assert_eq!(&cmd[..4], &[0, 0x87, id, 0x9d]);
        assert_eq!(&cmd[cmd.len() - point.len()..], point);
        // Leading zeros are significant in fixed-width agreement results.
        let mut secret = vec![0; width];
        secret[width - 1] = 7;
        op.advance(&response(&tlv(&[0x7c], &tlv(&[0x82], &secret))))
            .unwrap();
        assert_eq!(op.take_result().unwrap().as_bytes(), secret);
        for peer in [
            vec![4; point.len()],
            point[..point.len() - 1].to_vec(),
            vec![0; point.len()],
        ] {
            assert!(derive(
                &profile("3.1.0"),
                Slot::KeyManagement,
                algorithm,
                peer,
                Access::None,
                Default::default()
            )
            .is_err());
        }
        let mut op = derive(
            &profile("3.1.0"),
            Slot::KeyManagement,
            algorithm,
            point,
            Access::None,
            Default::default(),
        )
        .unwrap();
        selected(&mut op);
        assert_eq!(
            op.advance(&response(&tlv(&[0x7c], &tlv(&[0x82], &secret[1..]))))
                .unwrap_err()
                .kind,
            ErrorKind::InvalidResponse
        );
    }
    assert!(derive(
        &profile("3.1.0"),
        Slot::KeyManagement,
        Algorithm::Sm2,
        hex(P256_POINT),
        Access::None,
        Default::default()
    )
    .is_err());
}

#[test]
fn sm2_signature_encoding_follows_firmware_and_preserves_original_bytes() {
    let mut fixed = vec![0; 64];
    fixed[31] = 1;
    fixed[63] = 2;
    let der = hex("3006020101020102");
    for (version, encoding, wire) in [
        ("3.0.3", SignatureEncoding::Der, &der),
        ("3.1.0", SignatureEncoding::P1363, &fixed),
    ] {
        let mut op = sign(
            &profile(version),
            Slot::Signature,
            Algorithm::Sm2,
            SignInput::Digest(SecretBytes::new(vec![1; 32])),
            Access::None,
            Default::default(),
        )
        .unwrap();
        selected(&mut op);
        op.advance(&response(&tlv(&[0x7c], &tlv(&[0x82], wire))))
            .unwrap();
        let signature = op.take_result().unwrap();
        assert_eq!(signature.encoding(), encoding);
        assert_eq!(signature.as_bytes(), wire);
        assert_eq!(signature.to_p1363().unwrap(), fixed);
        assert_eq!(signature.to_der().unwrap(), der);
        // Reject the wrong firmware encoding rather than guessing from bytes.
        let wrong = if version == "3.0.3" { &fixed } else { &der };
        let mut op = sign(
            &profile(version),
            Slot::Signature,
            Algorithm::Sm2,
            SignInput::Digest(SecretBytes::new(vec![1; 32])),
            Access::None,
            Default::default(),
        )
        .unwrap();
        selected(&mut op);
        assert_eq!(
            op.advance(&response(&tlv(&[0x7c], &tlv(&[0x82], wrong))))
                .unwrap_err()
                .kind,
            ErrorKind::InvalidResponse
        );
    }
    let mut op = sign(
        &profile("3.1.0"),
        Slot::Signature,
        Algorithm::Sm2,
        SignInput::Digest(SecretBytes::new(vec![1; 32])),
        Access::None,
        Default::default(),
    )
    .unwrap();
    selected(&mut op);
    assert!(op
        .advance(&response(&tlv(&[0x7c], &tlv(&[0x82], &[0; 64]))))
        .is_err());
    assert_eq!(
        Signature::from_p1363(Algorithm::Sm2, &fixed)
            .unwrap()
            .encoding(),
        SignatureEncoding::Der
    );
}
