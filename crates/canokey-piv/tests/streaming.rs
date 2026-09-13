#[allow(dead_code)]
mod support;
use canokey_piv::*;
use canokey_protocol::{ErrorKind, Operation, OperationState, SecretBytes, Step};
use support::*;
fn message(bytes: &[u8]) -> SecretBytes {
    SecretBytes::new(bytes.to_vec())
}
fn small_reply() -> Vec<u8> {
    let mut reply = vec![0x7c, 66, 0x82, 64];
    reply.extend([1; 64]);
    reply.extend([0x90, 0]);
    reply
}
fn operation(input: StreamingSignInput) -> Operation<Signature> {
    sign_streaming(
        &profile("3.1.0"),
        Slot::Signature,
        input,
        Access::None,
        Default::default(),
    )
    .unwrap()
}
#[test]
fn empty_messages_use_explicit_modes_and_sm2_always_starts_a_chain() {
    let mut ed = operation(StreamingSignInput::Ed25519Randomized(message(&[])));
    selected(&mut ed);
    assert_eq!(
        ed.command().unwrap().as_bytes(),
        hex("0087ff9c067c0482008100")
    );
    ed.advance(&small_reply()).unwrap();
    assert_eq!(ed.result().unwrap().algorithm(), Algorithm::Ed25519);
    assert_eq!(ed.result().unwrap().encoding(), SignatureEncoding::Raw);
    assert!(ed.result().unwrap().to_der().is_err());
    for id in [None, Some(b"Alice".to_vec())] {
        let mut sm2 = operation(StreamingSignInput::Sm2 {
            message: message(&[]),
            user_id: id.clone(),
        });
        selected(&mut sm2);
        assert_eq!(sm2.command().unwrap().as_bytes(), hex("1087559c017c"));
        sm2.advance(&[0x90, 0]).unwrap();
        let expected = if id.is_some() {
            hex("0087559c0c0b8005416c69636582008100")
        } else {
            hex("0087559c050482008100")
        };
        assert_eq!(sm2.command().unwrap().as_bytes(), expected);
        sm2.advance(&small_reply()).unwrap();
        assert_eq!(sm2.result().unwrap().encoding(), SignatureEncoding::P1363);
        assert_eq!(sm2.result().unwrap().to_p1363().unwrap(), [1; 64]);
    }
    // Classic Ed25519 remains explicit and never silently changes nonce semantics.
    assert!(sign(
        &profile("3.1.0"),
        Slot::Signature,
        Algorithm::Ed25519,
        SignInput::Message(message(&[])),
        Access::None,
        Default::default()
    )
    .is_err());
}
#[test]
fn mldsa_streaming_is_owned_and_reassembles_large_signature() {
    let p = profile("3.1.0");
    let mut op = sign_streaming(
        &p,
        Slot::Signature,
        StreamingSignInput::MlDsa65(message(&[0x42; 300])),
        Access::Pin(Pin::from_bytes(b"123456").unwrap()),
        Default::default(),
    )
    .unwrap();
    drop(p);
    selected(&mut op);
    assert_eq!(
        op.command().unwrap().as_bytes(),
        hex("0020008008313233343536ffff")
    );
    op.advance(&[0x90, 0]).unwrap();
    let mut template = hex("7c82013282008182012c");
    template.extend([0x42; 300]);
    for (index, bytes) in template.chunks(255).enumerate() {
        let mut expected = vec![
            if index == 0 { 0x10 } else { 0 },
            0x87,
            0x56,
            0x9c,
            bytes.len() as u8,
        ];
        expected.extend(bytes);
        assert_eq!(op.command().unwrap().as_bytes(), expected);
        if index == 0 {
            op.advance(&[0x90, 0]).unwrap();
        }
    }
    // Firmware's fixed prefix and 3309-byte signature, returned through ISO 61xx.
    let mut reply = hex("7c820cf182820ced");
    reply.extend([0x77; 3309]);
    let chunks = reply.chunks(200).collect::<Vec<_>>();
    for (index, chunk) in chunks.iter().enumerate() {
        let last = index + 1 == chunks.len();
        let mut response = chunk.to_vec();
        response.extend(if last { [0x90, 0] } else { [0x61, 0] });
        let step = op.advance(&response).unwrap();
        if !last {
            assert_eq!(step, Step::Exchange);
            assert_eq!(op.command().unwrap().as_bytes(), hex("00c0000000"));
        } else {
            assert_eq!(step, Step::Done);
        }
    }
    let signature = op.take_result().unwrap();
    drop(op);
    assert_eq!(signature.algorithm(), Algorithm::MlDsa65);
    assert_eq!(signature.as_bytes(), [0x77; 3309]);
}
#[test]
fn streaming_rejects_incorrect_prefix_ack_bounds_and_capabilities() {
    for response in [hex("6100"), hex("6c10"), hex("019000")] {
        let mut op = operation(StreamingSignInput::Sm2 {
            message: message(&[]),
            user_id: None,
        });
        selected(&mut op);
        assert!(op.advance(&response).is_err());
        assert!(op.command().is_err());
    }
    let mut op = operation(StreamingSignInput::Sm2 {
        message: message(&[]),
        user_id: None,
    });
    selected(&mut op);
    op.cancel();
    assert_eq!(op.state(), OperationState::Cancelled);
    assert!(op.advance(&[0x90, 0]).is_err());
    for id in [vec![], vec![1; 33]] {
        assert!(sign_streaming(
            &profile("3.1.0"),
            Slot::Signature,
            StreamingSignInput::Sm2 {
                message: message(&[]),
                user_id: Some(id)
            },
            Access::None,
            Default::default()
        )
        .is_err());
    }
    for version in ["3.0.3", "3.1.1", "3.1.0-dev"] {
        assert!(sign_streaming(
            &profile(version),
            Slot::Signature,
            StreamingSignInput::Ed25519Randomized(message(&[])),
            Access::None,
            Default::default()
        )
        .is_err());
    }
    assert_eq!(
        sign_streaming(
            &profile("3.1.0"),
            Slot::Signature,
            StreamingSignInput::MlDsa65(message(&vec![0; 65530])),
            Access::None,
            Default::default()
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::LimitExceeded
    );
    let mut op = operation(StreamingSignInput::MlDsa65(message(&[])));
    selected(&mut op);
    assert_eq!(
        op.command().unwrap().as_bytes(),
        hex("0087569c067c0482008100")
    );
    assert!(op.advance(&small_reply()).is_err());
}
#[test]
fn batch_streaming_keeps_signature_after_later_error() {
    let mut op = batch(
        &profile("3.1.0"),
        vec![
            BatchRequest::SignStreaming {
                slot: Slot::Signature,
                input: StreamingSignInput::Ed25519Randomized(message(&[])),
            },
            BatchRequest::ReadCertificate(Slot::Signature),
        ],
        Default::default(),
    )
    .unwrap();
    selected(&mut op);
    op.advance(&small_reply()).unwrap();
    assert!(op.advance(&[0x6a, 0x82]).is_err());
    let progress = batch_progress(&op).unwrap();
    assert_eq!(progress.failed_index(), Some(1));
    assert!(matches!(&progress.items()[0],BatchItem::Signature(s) if s.as_bytes()==[1;64]));
}
