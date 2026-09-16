//! Foundation tests for the CTAP2 layer: strict canonical CBOR, the CTAP
//! status table, COSE key parsing, and authenticatorData parsing.
use canokey_ctap::authdata::AuthenticatorData;
use canokey_ctap::cbor::{self, Value};
use canokey_ctap::cose::{CoseAlgorithm, CoseKey};
use canokey_ctap::status::{CtapErrorCode, CtapStatus};
use canokey_protocol::{ErrorKind, Phase};

// ---------------------------------------------------------------- cbor ----

fn assert_invalid(bytes: &[u8]) {
    let error = cbor::parse(bytes).expect_err("input must be rejected");
    assert_eq!(error.kind, ErrorKind::InvalidResponse, "bytes {bytes:02x?}");
}

#[test]
fn cbor_rfc8949_integer_round_trips() {
    let vectors: &[(u64, &[u8])] = &[
        (0, &[0x00]),
        (23, &[0x17]),
        (24, &[0x18, 0x18]),
        (255, &[0x18, 0xff]),
        (256, &[0x19, 0x01, 0x00]),
        (65535, &[0x19, 0xff, 0xff]),
        (65536, &[0x1a, 0x00, 0x01, 0x00, 0x00]),
        (u64::from(u32::MAX), &[0x1a, 0xff, 0xff, 0xff, 0xff]),
        (
            u64::MAX,
            &[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ),
    ];
    for &(value, bytes) in vectors {
        assert_eq!(cbor::parse(bytes).unwrap(), Value::Unsigned(value));
        assert_eq!(cbor::encode(&Value::Unsigned(value)).unwrap(), bytes);
    }
    // Negative integers: -1 and -256 from RFC 8949 appendix A.
    assert_eq!(cbor::parse(&[0x20]).unwrap(), Value::Negative(0));
    assert_eq!(cbor::encode(&Value::Negative(0)).unwrap(), [0x20]);
    assert_eq!(cbor::parse(&[0x38, 0xff]).unwrap(), Value::Negative(255));
    assert_eq!(cbor::encode(&Value::Negative(255)).unwrap(), [0x38, 0xff]);
    // Full i64 domain through from_int/as_int.
    assert_eq!(Value::from_int(-1).as_int(), Some(-1));
    assert_eq!(Value::from_int(i64::MIN).as_int(), Some(i64::MIN));
    assert_eq!(Value::from_int(i64::MAX).as_int(), Some(i64::MAX));
}

#[test]
fn cbor_rfc8949_compound_round_trips() {
    let vectors: &[(Value, &[u8])] = &[
        (Value::Bytes(vec![]), &[0x40]),
        (Value::Bytes(vec![0x01, 0x02]), &[0x42, 0x01, 0x02]),
        (Value::Text(String::new()), &[0x60]),
        (Value::Text("a".into()), &[0x61, 0x61]),
        (Value::Array(vec![]), &[0x80]),
        (
            Value::Array(vec![Value::Unsigned(1), Value::Unsigned(2)]),
            &[0x82, 0x01, 0x02],
        ),
        (Value::Map(vec![]), &[0xa0]),
        (
            Value::Map(vec![(Value::Unsigned(1), Value::Unsigned(2))]),
            &[0xa1, 0x01, 0x02],
        ),
        (Value::Bool(false), &[0xf4]),
        (Value::Bool(true), &[0xf5]),
        (Value::Null, &[0xf6]),
        // Nested: [1, [2, 3], {4: "x"}]
        (
            Value::Array(vec![
                Value::Unsigned(1),
                Value::Array(vec![Value::Unsigned(2), Value::Unsigned(3)]),
                Value::Map(vec![(Value::Unsigned(4), Value::Text("x".into()))]),
            ]),
            &[0x83, 0x01, 0x82, 0x02, 0x03, 0xa1, 0x04, 0x61, 0x78],
        ),
    ];
    for (value, bytes) in vectors {
        assert_eq!(&cbor::parse(bytes).unwrap(), value, "bytes {bytes:02x?}");
        assert_eq!(cbor::encode(value).unwrap(), *bytes, "value {value:?}");
    }
}

#[test]
fn cbor_rejects_indefinite_tagged_and_reserved_items() {
    assert_invalid(&[0x5f]); // indefinite-length byte string
    assert_invalid(&[0x7f]); // indefinite-length text string
    assert_invalid(&[0x9f, 0x01, 0xff]); // indefinite-length array
    assert_invalid(&[0xbf, 0x01, 0x01, 0xff]); // indefinite-length map
    assert_invalid(&[0xff]); // bare break
    assert_invalid(&[0xc0, 0x00]); // tag 0
    assert_invalid(&[0xd8, 0x20, 0x00]); // tag 32
    assert_invalid(&[0x1c]); // reserved additional information 28
    assert_invalid(&[0xf7]); // undefined
    assert_invalid(&[0xf8, 0x20]); // one-byte simple value
    assert_invalid(&[0xfa, 0x00, 0x00, 0x00, 0x00]); // half-precision float
    assert_invalid(&[]); // empty input
}

#[test]
fn cbor_rejects_non_shortest_form_arguments() {
    assert_invalid(&[0x18, 0x17]); // 23 encoded with a one-byte argument
    assert_invalid(&[0x19, 0x00, 0x18]); // 24 encoded with a two-byte argument
    assert_invalid(&[0x1a, 0x00, 0x00, 0x01, 0x00]); // 256 in four bytes
    assert_invalid(&[0x58, 0x01, 0x00]); // one-byte bstr with long length form
    assert_invalid(&[0x79, 0x00, 0x01, 0x61]); // "a" with a two-byte length
}

#[test]
fn cbor_rejects_truncation_trailing_bytes_and_invalid_utf8() {
    assert_invalid(&[0x18]); // truncated argument
    assert_invalid(&[0x42, 0x01]); // truncated byte string
    assert_invalid(&[0x82, 0x01]); // truncated array
    assert_invalid(&[0xa1, 0x01]); // truncated map
    assert_invalid(&[0x00, 0x00]); // trailing bytes
    assert_invalid(&[0x61, 0xff]); // invalid UTF-8
}

#[test]
fn cbor_rejects_duplicate_map_keys_recursively() {
    assert_invalid(&[0xa2, 0x01, 0x01, 0x01, 0x02]); // key 1 twice
                                                     // Duplicate key nested inside an array element.
    assert_invalid(&[0x81, 0xa2, 0x01, 0x01, 0x01, 0x02]);
    // Distinct keys (0 and -1) are fine.
    assert!(cbor::parse(&[0xa2, 0x00, 0x01, 0x20, 0x02]).is_ok());
}

#[test]
fn cbor_enforces_max_nesting_depth() {
    // 63 nested single-element arrays around a uint: accepted (depth 64).
    let mut ok = vec![0x81; 63];
    ok.push(0x00);
    assert!(cbor::parse(&ok).is_ok());
    // 64 nested arrays push the innermost item to depth 65: rejected.
    let mut deep = vec![0x81; 64];
    deep.push(0x00);
    let error = cbor::parse(&deep).expect_err("depth 65 must be rejected");
    assert_eq!(error.kind, ErrorKind::LimitExceeded);
}

#[test]
fn cbor_encode_enforces_max_nesting_depth() {
    // A caller-built value deeper than MAX_DEPTH must fail, not overflow the
    // stack; 63 nested arrays around a uint (depth 64) still encodes.
    let nest = |levels: usize| {
        let mut value = Value::Unsigned(0);
        for _ in 0..levels {
            value = Value::Array(vec![value]);
        }
        value
    };
    assert!(cbor::encode(&nest(63)).is_ok());
    let error = cbor::encode(&nest(64)).expect_err("depth 65 must be rejected");
    assert_eq!(error.kind, ErrorKind::LimitExceeded);
    assert_eq!(error.phase, Phase::Construction);
}

#[test]
fn cbor_encode_sorts_map_keys_canonically() {
    // Canonical order: shorter encoded keys first, then lexicographic.
    let map = Value::Map(vec![
        (Value::Text("a".into()), Value::Null),
        (Value::Unsigned(100), Value::Null),
        (Value::Negative(0), Value::Null),
        (Value::Unsigned(10), Value::Null),
        (Value::Unsigned(2), Value::Null),
    ]);
    let encoded = cbor::encode(&map).unwrap();
    // Keys: 2 (0x02), 10 (0x0a), -1 (0x20), then 100 (0x18 0x64) and "a".
    assert_eq!(
        encoded,
        [0xa5, 0x02, 0xf6, 0x0a, 0xf6, 0x20, 0xf6, 0x18, 0x64, 0xf6, 0x61, 0x61, 0xf6]
    );
    assert_eq!(cbor::parse(&encoded).unwrap().as_map().unwrap().len(), 5);
}

#[test]
fn cbor_parse_item_reports_consumed_bytes() {
    let (value, consumed) = cbor::parse_item(&[0x01, 0x02, 0x03]).unwrap();
    assert_eq!(value, Value::Unsigned(1));
    assert_eq!(consumed, 1);
}

#[test]
fn cbor_value_accessors() {
    let map = Value::Map(vec![
        (Value::from_int(-2), Value::Bytes(vec![0xaa; 32])),
        (Value::Unsigned(3), Value::from_int(-7)),
        (Value::Text("rk".into()), Value::Bool(true)),
    ]);
    assert_eq!(
        map.map_get_int(-2).and_then(Value::as_bytes),
        Some(&[0xaa; 32][..])
    );
    assert_eq!(map.map_get_int(3).and_then(Value::as_int), Some(-7));
    assert_eq!(map.map_get_text("rk").and_then(Value::as_bool), Some(true));
    assert!(map.map_get_int(99).is_none());
    assert!(map.map_get_text("missing").is_none());
    // Typed mismatches return None.
    assert!(map.map_get_int(3).and_then(Value::as_bytes).is_none());
    assert!(Value::Unsigned(1).as_map().is_none());
    assert!(Value::Null.is_null());
}

#[test]
fn cbor_debug_redacts_byte_strings() {
    let debug = format!("{:?}", Value::Bytes(vec![0xde, 0xad]));
    assert_eq!(debug, "Bytes(<2 bytes>)");
    assert!(!debug.contains("de"));
}

// -------------------------------------------------------------- status ----

#[test]
fn status_code_table_boundaries() {
    assert_eq!(
        CtapStatus::SUCCESS.code(),
        Some(CtapErrorCode::Ctap1ErrSuccess)
    );
    assert_eq!(
        CtapStatus::from_raw(0x40).code(),
        Some(CtapErrorCode::Ctap2ErrUnauthorizedPermission)
    );
    assert_eq!(
        CtapStatus::from_raw(0x7f).code(),
        Some(CtapErrorCode::Ctap1ErrOther)
    );
    // Boundary constants and gaps are not valid codes.
    assert_eq!(CtapStatus::from_raw(CtapErrorCode::SPEC_LAST).code(), None);
    assert_eq!(CtapStatus::from_raw(0x41).code(), None);
    assert_eq!(CtapStatus::from_raw(0x7e).code(), None);
    // Extension and vendor ranges keep their low nibble.
    assert_eq!(
        CtapStatus::from_raw(0xe0).code(),
        Some(CtapErrorCode::Extension(0))
    );
    assert_eq!(
        CtapStatus::from_raw(0xef).code(),
        Some(CtapErrorCode::Extension(15))
    );
    assert_eq!(
        CtapStatus::from_raw(0xf0).code(),
        Some(CtapErrorCode::Vendor(0))
    );
    assert_eq!(
        CtapStatus::from_raw(0xff).code(),
        Some(CtapErrorCode::Vendor(15))
    );
}

#[test]
fn status_code_round_trips_lossless() {
    for byte in 0u8..=0xff {
        match CtapErrorCode::from_byte(byte) {
            Some(code) => assert_eq!(code.byte(), byte),
            None => assert!(matches!(
                byte,
                0x07..=0x09 | 0x0c..=0x10 | 0x13 | 0x16 | 0x1a..=0x20 | 0x29..=0x2a
                    | 0x41..=0x7e | 0x80..=0xdf
            )),
        }
    }
}

// ---------------------------------------------------------------- cose ----

fn p256_map(algorithm: i64) -> Value {
    Value::Map(vec![
        (Value::from_int(1), Value::from_int(2)),
        (Value::from_int(3), Value::from_int(algorithm)),
        (Value::from_int(-1), Value::from_int(1)),
        (Value::from_int(-2), Value::Bytes(vec![0x11; 32])),
        (Value::from_int(-3), Value::Bytes(vec![0x22; 32])),
    ])
}

#[test]
fn cose_parses_es256_aliases() {
    for algorithm in [-7, -9] {
        let key = CoseKey::from_value(&p256_map(algorithm)).unwrap();
        match key {
            CoseKey::P256 {
                algorithm: resolved,
                x,
                y,
            } => {
                assert_eq!(resolved, CoseAlgorithm::Es256);
                assert_eq!(x, [0x11; 32]);
                assert_eq!(y, [0x22; 32]);
            }
            other => panic!("unexpected key: {other:?}"),
        }
    }
    assert!(CoseAlgorithm::Es256.is_signature());
}

#[test]
fn cose_parses_ed25519() {
    for algorithm in [-8, -19] {
        let map = Value::Map(vec![
            (Value::from_int(1), Value::from_int(1)),
            (Value::from_int(3), Value::from_int(algorithm)),
            (Value::from_int(-1), Value::from_int(6)),
            (Value::from_int(-2), Value::Bytes(vec![0x33; 32])),
        ]);
        let key = CoseKey::from_value(&map).unwrap();
        assert_eq!(key, CoseKey::Ed25519 { x: [0x33; 32] });
        assert_eq!(key.algorithm(), Some(CoseAlgorithm::Ed25519));
    }
}

#[test]
fn cose_parses_ml_dsa() {
    let cases = [
        (-48, CoseAlgorithm::MlDsa44, 1312),
        (-49, CoseAlgorithm::MlDsa65, 1952),
        (-50, CoseAlgorithm::MlDsa87, 2592),
    ];
    for (id, algorithm, length) in cases {
        let map = Value::Map(vec![
            (Value::from_int(1), Value::from_int(7)),
            (Value::from_int(3), Value::from_int(id)),
            (Value::from_int(-1), Value::Bytes(vec![0x44; length])),
        ]);
        let key = CoseKey::from_value(&map).unwrap();
        assert_eq!(key.algorithm(), Some(algorithm));
        assert!(algorithm.is_signature());
        // Wrong lengths are rejected.
        let short = Value::Map(vec![
            (Value::from_int(1), Value::from_int(7)),
            (Value::from_int(3), Value::from_int(id)),
            (Value::from_int(-1), Value::Bytes(vec![0x44; length - 1])),
        ]);
        let error = CoseKey::from_value(&short).expect_err("short key must fail");
        assert_eq!(error.kind, ErrorKind::InvalidResponse);
    }
}

#[test]
fn cose_ecdh_es_hkdf256_is_key_agreement_only() {
    let key = CoseKey::from_value(&p256_map(-25)).unwrap();
    assert_eq!(key.algorithm(), Some(CoseAlgorithm::EcdhEsHkdf256));
    assert!(!CoseAlgorithm::EcdhEsHkdf256.is_signature());
    // Round-trips to the platform key-agreement map shape.
    let encoded = cbor::encode(&key.to_value()).unwrap();
    assert_eq!(cbor::parse(&encoded).unwrap(), p256_map(-25));
}

#[test]
fn cose_rejects_private_key_labels_and_bad_shapes() {
    let mut with_private = p256_map(-7);
    if let Value::Map(entries) = &mut with_private {
        entries.push((Value::from_int(-4), Value::Bytes(vec![0x55; 32])));
    }
    assert!(CoseKey::from_value(&with_private).is_err());
    // OKP with a private key label -4.
    let okp_private = Value::Map(vec![
        (Value::from_int(1), Value::from_int(1)),
        (Value::from_int(3), Value::from_int(-8)),
        (Value::from_int(-1), Value::from_int(6)),
        (Value::from_int(-2), Value::Bytes(vec![0x33; 32])),
        (Value::from_int(-4), Value::Bytes(vec![0x55; 32])),
    ]);
    assert!(CoseKey::from_value(&okp_private).is_err());
    // AKP with private key label -2.
    let akp_private = Value::Map(vec![
        (Value::from_int(1), Value::from_int(7)),
        (Value::from_int(3), Value::from_int(-49)),
        (Value::from_int(-1), Value::Bytes(vec![0x44; 1952])),
        (Value::from_int(-2), Value::Bytes(vec![0x55; 32])),
    ]);
    assert!(CoseKey::from_value(&akp_private).is_err());
    // Wrong curve, wrong key type, wrong coordinate width, missing kty/alg.
    let wrong_crv = {
        let mut map = p256_map(-7);
        if let Value::Map(entries) = &mut map {
            entries[2].1 = Value::from_int(2);
        }
        map
    };
    assert!(CoseKey::from_value(&wrong_crv).is_err());
    let wrong_kty = {
        let mut map = p256_map(-7);
        if let Value::Map(entries) = &mut map {
            entries[0].1 = Value::from_int(1);
        }
        map
    };
    assert!(CoseKey::from_value(&wrong_kty).is_err());
    let short_x = {
        let mut map = p256_map(-7);
        if let Value::Map(entries) = &mut map {
            entries[3].1 = Value::Bytes(vec![0x11; 31]);
        }
        map
    };
    assert!(CoseKey::from_value(&short_x).is_err());
    let missing_alg = {
        let mut map = p256_map(-7);
        if let Value::Map(entries) = &mut map {
            entries.remove(1);
        }
        map
    };
    assert!(CoseKey::from_value(&missing_alg).is_err());
    // Not a map at all, and non-integer labels.
    assert!(CoseKey::from_value(&Value::Null).is_err());
    let text_kty = {
        let mut map = p256_map(-7);
        if let Value::Map(entries) = &mut map {
            entries[0].1 = Value::Text("EC2".into());
        }
        map
    };
    assert!(CoseKey::from_value(&text_kty).is_err());
}

#[test]
fn cose_unknown_algorithm_is_preserved_raw() {
    let map = Value::Map(vec![
        (Value::from_int(1), Value::from_int(2)),
        (Value::from_int(3), Value::from_int(-257)),
        (Value::from_int(-1), Value::from_int(1)),
        (Value::from_int(-2), Value::Bytes(vec![0x11; 32])),
        (Value::from_int(-3), Value::Bytes(vec![0x22; 32])),
    ]);
    let key = CoseKey::from_value(&map).unwrap();
    assert_eq!(key.algorithm(), None);
    assert_eq!(key, CoseKey::Unknown(map.clone()));
    assert_eq!(key.to_value(), map);
    assert_eq!(CoseAlgorithm::from_id(-257), CoseAlgorithm::Unknown(-257));
}

// ------------------------------------------------------------ authdata ----

fn es256_key_value() -> Value {
    p256_map(-7)
}

/// Build a golden authenticatorData with AT|ED set.
fn golden_authdata(flags: u8) -> Vec<u8> {
    let mut bytes = vec![0xaa; 32]; // rpIdHash
    bytes.push(flags);
    bytes.extend_from_slice(&0x0000_002au32.to_be_bytes()); // signCount
    if flags & AuthenticatorData::FLAG_AT != 0 {
        bytes.extend_from_slice(&[0xbb; 16]); // aaguid
        bytes.extend_from_slice(&4u16.to_be_bytes()); // credentialIdLength
        bytes.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // credentialId
        bytes.extend_from_slice(&cbor::encode(&es256_key_value()).unwrap());
    }
    if flags & AuthenticatorData::FLAG_ED != 0 {
        let extensions = Value::Map(vec![(Value::Text("hmac-secret".into()), Value::Bool(true))]);
        bytes.extend_from_slice(&cbor::encode(&extensions).unwrap());
    }
    bytes
}

#[test]
fn authdata_golden_parse_with_attestation_and_extensions() {
    let flags =
        AuthenticatorData::FLAG_UP | AuthenticatorData::FLAG_AT | AuthenticatorData::FLAG_ED;
    let bytes = golden_authdata(flags);
    let data = AuthenticatorData::parse(&bytes).unwrap();
    assert_eq!(data.raw(), bytes.as_slice());
    assert_eq!(data.rp_id_hash(), &[0xaa; 32]);
    assert_eq!(data.flags(), flags);
    assert_eq!(data.sign_count(), 42);
    assert!(data.user_present());
    assert!(!data.user_verified());
    let attested = data.attested_credential_data().expect("AT flag set");
    assert_eq!(attested.aaguid(), &[0xbb; 16]);
    assert_eq!(attested.credential_id(), &[0x01, 0x02, 0x03, 0x04]);
    assert_eq!(
        attested.credential_public_key().algorithm(),
        Some(CoseAlgorithm::Es256)
    );
    let extensions = data.extensions().expect("ED flag set");
    assert_eq!(
        extensions
            .map_get_text("hmac-secret")
            .and_then(Value::as_bool),
        Some(true)
    );
}

#[test]
fn authdata_minimal_parse_without_at_or_ed() {
    let bytes = golden_authdata(0x01);
    assert_eq!(bytes.len(), 37);
    let data = AuthenticatorData::parse(&bytes).unwrap();
    assert!(data.attested_credential_data().is_none());
    assert!(data.extensions().is_none());
}

#[test]
fn authdata_rejects_bs_without_be() {
    let error = AuthenticatorData::parse(&golden_authdata(0x10)).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    // BS together with BE is accepted.
    assert!(AuthenticatorData::parse(&golden_authdata(0x19)).is_ok());
}

#[test]
fn authdata_rejects_bad_lengths_and_trailing_bytes() {
    let error = AuthenticatorData::parse(&[0x00; 36]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    let mut overlong = golden_authdata(0x01);
    overlong.extend_from_slice(&[0x00]); // trailing byte
    assert!(AuthenticatorData::parse(&overlong).is_err());
    let too_long = vec![0x00; 65537];
    assert!(AuthenticatorData::parse(&too_long).is_err());
    // Truncated inside the AT section.
    let full = golden_authdata(AuthenticatorData::FLAG_UP | AuthenticatorData::FLAG_AT);
    for cut in [37 + 5, 37 + 18, 37 + 19] {
        assert!(AuthenticatorData::parse(&full[..cut]).is_err(), "cut {cut}");
    }
}

#[test]
fn authdata_rejects_bad_credential_id_lengths() {
    for id_len in [0u16, 1024] {
        let mut bytes = vec![0xaa; 32];
        bytes.push(AuthenticatorData::FLAG_UP | AuthenticatorData::FLAG_AT);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&[0xbb; 16]);
        bytes.extend_from_slice(&id_len.to_be_bytes());
        bytes.extend_from_slice(&cbor::encode(&es256_key_value()).unwrap());
        assert!(
            AuthenticatorData::parse(&bytes).is_err(),
            "id_len {id_len} must fail"
        );
    }
    // Boundary 1023 is accepted.
    let mut bytes = vec![0xaa; 32];
    bytes.push(AuthenticatorData::FLAG_UP | AuthenticatorData::FLAG_AT);
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&[0xbb; 16]);
    bytes.extend_from_slice(&1023u16.to_be_bytes());
    bytes.extend_from_slice(&[0xcc; 1023]);
    bytes.extend_from_slice(&cbor::encode(&es256_key_value()).unwrap());
    assert!(AuthenticatorData::parse(&bytes).is_ok());
}

#[test]
fn authdata_rejects_non_map_or_non_text_key_extensions() {
    for extensions in [
        Value::Array(vec![]),
        Value::Map(vec![(Value::Unsigned(1), Value::Bool(true))]),
    ] {
        let mut bytes = golden_authdata(0x01);
        bytes[32] = AuthenticatorData::FLAG_UP | AuthenticatorData::FLAG_ED;
        bytes.extend_from_slice(&cbor::encode(&extensions).unwrap());
        assert!(AuthenticatorData::parse(&bytes).is_err());
    }
}
