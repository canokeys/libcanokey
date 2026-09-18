use canokey_compat::{DeviceObservations, DeviceProfile};
use canokey_oath::*;
use canokey_protocol::{
    ErrorKind, Operation, OperationOptions, SecretBytes, SecretReference, Step,
};
fn profile() -> DeviceProfile {
    DeviceProfile::from_observations(DeviceObservations::new(b"3.1.0".to_vec())).unwrap()
}
fn name() -> Name {
    Name::from_bytes(b"test").unwrap()
}
fn selection(protected: bool) -> Vec<u8> {
    let mut data = vec![0x79, 3, 6, 0, 0, 0x71, 8];
    data.extend(b"12345678");
    if protected {
        data.extend([0x74, 8]);
        data.extend(b"CCCCCCCC");
        data.extend([0x7b, 1, 1]);
    }
    data.extend([0x90, 0]);
    data
}
fn begin(request: Request, access: Option<Access>) -> Operation<Outcome> {
    let mut op = operation(&profile(), request, access, Default::default()).unwrap();
    op.start().unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0, 0xa4, 4, 0, 7, 0xa0, 0, 0, 5, 0x27, 0x21, 1]
    );
    op
}
fn access() -> Access {
    Access {
        key: AccessKey::from_bytes(b"KKKKKKKKKKKKKKKK").unwrap(),
        challenge: *b"HHHHHHHH",
    }
}
fn hotp() -> Request {
    Request::Calculate {
        name: name(),
        kind: Kind::Hotp,
        algorithm: Algorithm::Sha1,
        challenge: None,
        format: Format::Truncated,
    }
}
#[test]
fn authenticated_hotp_transcript_and_decimal() {
    let mut op = begin(hotp(), Some(access()));
    op.advance(&selection(true)).unwrap();
    let mut expected = vec![0, 0xa3, 0, 0, 32, 0x75, 20];
    expected.extend([
        0x0d, 0xe0, 0xba, 0xe2, 0x81, 0xba, 0x21, 0x98, 0x0e, 0x76, 0x92, 0xc9, 0x34, 0x52, 0x9f,
        0x0f, 0x61, 0x11, 0x16, 0x51,
    ]);
    expected.extend([0x74, 8]);
    expected.extend(b"HHHHHHHH");
    assert_eq!(op.command().unwrap().as_bytes(), expected);
    let mut response = vec![0x75, 20];
    response.extend([
        0xca, 0xa1, 0x34, 0x6e, 0x39, 0x05, 0x8d, 0xd3, 0x6e, 0xd7, 0x6f, 0xb4, 0x90, 0x53, 0xe1,
        0x4f, 0x66, 0xce, 0x42, 0x8b,
    ]);
    response.extend([0x90, 0]);
    op.advance(&response).unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        b"\0\xa2\0\x01\x06\x71\x04test"
    );
    assert_eq!(
        op.advance(&[0x76, 5, 6, 0, 0, 0, 42, 0x90, 0]).unwrap(),
        Step::Done
    );
    let Outcome::Calculations(codes) = op.take_result().unwrap() else {
        panic!()
    };
    drop(op);
    assert_eq!(codes[0].decimal().unwrap().as_bytes(), b"000042");
    assert!(!format!("{:?}", codes[0]).contains("000042"));
}
#[test]
fn authentication_never_falls_back_or_retries() {
    let mut op = begin(Request::List, None);
    assert_eq!(
        op.advance(&selection(true)).unwrap_err().kind,
        ErrorKind::SecurityStatusNotSatisfied
    );
    let mut op = begin(Request::List, Some(access()));
    assert_eq!(
        op.advance(&selection(false)).unwrap_err().kind,
        ErrorKind::ConditionsNotSatisfied
    );
    let mut op = begin(Request::List, Some(access()));
    op.advance(&selection(true)).unwrap();
    let e = op.advance(&[0x6a, 0x80]).unwrap_err();
    assert_eq!(e.kind, ErrorKind::AuthenticationFailed);
    assert_eq!(e.reference, Some(SecretReference::OathAccess));
    assert_eq!(e.retries_remaining, None);
    let mut op = begin(hotp(), Some(access()));
    op.advance(&selection(true)).unwrap();
    let mut wrong = vec![0x75, 20];
    wrong.extend([0; 20]);
    wrong.extend([0x90, 0]);
    assert_eq!(
        op.advance(&wrong).unwrap_err().kind,
        ErrorKind::DeviceAuthenticationFailed
    );
    assert!(op.command().is_err());
    let mut op = begin(hotp(), None);
    op.advance(&selection(false)).unwrap();
    assert_eq!(
        op.advance(&[0x6c, 7]).unwrap_err().kind,
        ErrorKind::UnexpectedStatusWord
    );
    assert!(op.command().is_err());
}
#[test]
fn list_and_calculate_all_use_oath_pages() {
    let mut op = begin(Request::List, None);
    op.advance(&selection(false)).unwrap();
    assert_eq!(op.command().unwrap().as_bytes(), &[0, 0xa1, 0, 0, 255]);
    op.advance(&[0x72, 2, 0xfe, b'x', 0x90, 0]).unwrap();
    assert_eq!(op.command().unwrap().as_bytes(), &[0, 0xa5, 0, 0, 255]);
    op.advance(&[0x69, 0x85]).unwrap();
    let Outcome::Entries(entries) = op.result().unwrap() else {
        panic!()
    };
    assert_eq!(entries[0].algorithm_type, 0xfe);
    let mut op = begin(
        Request::CalculateAll {
            challenge: 1u64.to_be_bytes(),
            format: Format::Truncated,
        },
        None,
    );
    op.advance(&selection(false)).unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0, 0xa4, 0, 1, 10, 0x74, 8, 0, 0, 0, 0, 0, 0, 0, 1, 255]
    );
    op.advance(&[0x71, 1, b'a', 0x77, 1, 6, 0x61, 255]).unwrap();
    op.advance(&[0x71, 1, b'b', 0x7c, 1, 8, 0x90, 0]).unwrap();
    op.advance(&[0x90, 0]).unwrap();
    let Outcome::Calculations(codes) = op.result().unwrap() else {
        panic!()
    };
    assert_eq!(codes.len(), 2);
    assert!(matches!(codes[0].code, Code::Hotp));
    assert!(matches!(codes[1].code, Code::TouchRequired));
}
#[test]
fn put_property_is_not_ber_and_initial_counter_is_explicit() {
    let credential = Credential {
        name: name(),
        kind: Kind::Hotp,
        algorithm: Algorithm::Sha256,
        digits: 6,
        secret: SecretBytes::new(vec![1, 2, 3]),
        require_touch: true,
        increasing: false,
        initial_counter: 42,
    };
    let mut op = begin(Request::Put(credential), None);
    op.advance(&selection(false)).unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[
            0, 1, 0, 0, 21, 0x71, 4, b't', b'e', b's', b't', 0x73, 5, 0x12, 6, 1, 2, 3, 0x78, 2,
            0x7a, 4, 0, 0, 0, 42
        ]
    );
    op.advance(&[0x90, 0]).unwrap();
    let mut op = begin(
        Request::Rename {
            old: name(),
            new: Name::from_bytes(b"next").unwrap(),
        },
        None,
    );
    op.advance(&selection(false)).unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        b"\0\x05\0\0\x0c\x71\x04test\x71\x04next"
    );
    assert_eq!(
        op.advance(&[0x69, 0x84]).unwrap_err().kind,
        ErrorKind::NotFound
    );
}
#[test]
fn set_code_proof_and_password_derivation() {
    let key = AccessKey::from_password(SecretBytes::new(b"password".to_vec()), *b"12345678");
    let mut op = begin(
        Request::SetCode {
            key,
            challenge: *b"CCCCCCCC",
        },
        None,
    );
    op.advance(&selection(false)).unwrap();
    assert_eq!(
        &op.command().unwrap().as_bytes()[8..24],
        &[
            0xf5, 0x31, 0x15, 0x4d, 0x46, 0xd1, 0xbd, 0xbb, 0xcc, 0x1f, 0xcc, 0xe0, 0x2d, 0x6b,
            0x4c, 0x93
        ]
    );
    op.advance(&[0x90, 0]).unwrap();
    let mut op = begin(Request::ClearCode, None);
    op.advance(&selection(false)).unwrap();
    assert_eq!(op.command().unwrap().as_bytes(), &[0, 3, 0, 0, 2, 0x73, 0]);
}
#[test]
fn set_default_transcripts_and_status_mapping() {
    let set_default = |slot, append_enter| Request::SetDefault {
        slot,
        append_enter,
        name: name(),
    };
    let mut op = begin(set_default(DefaultSlot::Short, true), None);
    op.advance(&selection(false)).unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        b"\0\x55\x01\x01\x06\x71\x04test"
    );
    assert_eq!(op.advance(&[0x90, 0]).unwrap(), Step::Done);
    assert!(matches!(op.take_result().unwrap(), Outcome::Unit));
    let mut op = begin(set_default(DefaultSlot::Long, false), None);
    op.advance(&selection(false)).unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        b"\0\x55\x02\x00\x06\x71\x04test"
    );
    assert_eq!(
        op.advance(&[0x69, 0x84]).unwrap_err().kind,
        ErrorKind::NotFound
    );
}
#[test]
fn malformed_responses_budgets_and_cancellation() {
    let mut op = begin(Request::Select, None);
    assert_eq!(
        op.advance(&[0x90, 0]).unwrap_err().kind,
        ErrorKind::InvalidResponse
    );
    let mut op = begin(hotp(), None);
    op.advance(&selection(false)).unwrap();
    assert_eq!(
        op.advance(&[0x76, 5, 6, 0x80, 0, 0, 0, 0x90, 0])
            .unwrap_err()
            .kind,
        ErrorKind::InvalidResponse
    );
    let mut options = OperationOptions::default();
    options.limits.max_exchanges = 2;
    let mut op = operation(&profile(), Request::List, None, options).unwrap();
    op.start().unwrap();
    op.advance(&selection(false)).unwrap();
    assert_eq!(
        op.advance(&[0x72, 2, 0x21, b'a', 0x90, 0])
            .unwrap_err()
            .kind,
        ErrorKind::LimitExceeded
    );
    let mut op = begin(hotp(), None);
    op.advance(&selection(false)).unwrap();
    op.cancel();
    assert!(op.command().is_err());
    let mut op = begin(Request::List, None);
    op.advance(&selection(false)).unwrap();
    op.advance(&[0x72, 2, 0x21, b'a', 0x61, 255]).unwrap();
    assert_eq!(
        op.advance(&[0x69, 0x85]).unwrap_err().kind,
        ErrorKind::ConditionsNotSatisfied
    );
}
#[test]
fn get_serial_transcript_and_response_validation() {
    // A protected applet does not gate the vendor extension commands.
    let mut op = begin(Request::GetSerial, None);
    op.advance(&selection(true)).unwrap();
    assert_eq!(op.command().unwrap().as_bytes(), &[0, 1, 0x10, 0]);
    assert_eq!(
        op.advance(&[1, 2, 3, 0x90, 0]).unwrap_err().kind,
        ErrorKind::InvalidResponse
    );
    let mut op = begin(Request::GetSerial, None);
    op.advance(&selection(false)).unwrap();
    assert_eq!(op.advance(&[1, 2, 3, 4, 0x90, 0]).unwrap(), Step::Done);
    assert!(matches!(
        op.take_result().unwrap(),
        Outcome::Serial([1, 2, 3, 4])
    ));
    // An access input is rejected rather than silently ignored.
    assert_eq!(
        operation(
            &profile(),
            Request::GetSerial,
            Some(access()),
            Default::default()
        )
        .unwrap_err()
        .kind,
        ErrorKind::InvalidArgument
    );
}
#[test]
fn challenge_response_transcripts_status_and_redaction() {
    let hmac = [7u8; 20];
    let mut op = begin(
        Request::ChallengeResponseHmac {
            slot: HmacSlot::Short,
            challenge: b"challenge".to_vec(),
        },
        None,
    );
    op.advance(&selection(true)).unwrap();
    let mut expected = vec![0, 1, 0x30, 0, 9];
    expected.extend(b"challenge");
    assert_eq!(op.command().unwrap().as_bytes(), expected);
    let mut response = hmac.to_vec();
    response.extend([0x90, 0]);
    assert_eq!(op.advance(&response).unwrap(), Step::Done);
    let outcome = op.take_result().unwrap();
    assert!(!format!("{outcome:?}").contains("7, 7"));
    let Outcome::ChallengeResponse(bytes) = outcome else {
        panic!()
    };
    assert_eq!(bytes.as_bytes(), &hmac);
    let mut op = begin(
        Request::ChallengeResponseHmac {
            slot: HmacSlot::Short,
            challenge: vec![],
        },
        None,
    );
    op.advance(&selection(false)).unwrap();
    assert_eq!(op.command().unwrap().as_bytes(), &[0, 1, 0x30, 0]);
    let mut short = vec![7u8; 19];
    short.extend([0x90, 0]);
    assert_eq!(
        op.advance(&short).unwrap_err().kind,
        ErrorKind::InvalidResponse
    );
    let mut op = begin(
        Request::ChallengeResponseHmac {
            slot: HmacSlot::Long,
            challenge: vec![1],
        },
        None,
    );
    op.advance(&selection(false)).unwrap();
    assert_eq!(
        op.advance(&[0x6a, 0x82]).unwrap_err().kind,
        ErrorKind::NotFound
    );
    // Construction bounds the challenge without any I/O.
    let challenge_response = |challenge| Request::ChallengeResponseHmac {
        slot: HmacSlot::Short,
        challenge,
    };
    operation(
        &profile(),
        challenge_response(vec![0; 64]),
        None,
        Default::default(),
    )
    .unwrap();
    assert_eq!(
        operation(
            &profile(),
            challenge_response(vec![0; 65]),
            None,
            Default::default()
        )
        .unwrap_err()
        .kind,
        ErrorKind::InvalidArgument
    );
}
