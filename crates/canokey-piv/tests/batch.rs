mod support;
use canokey_piv::*;
use canokey_protocol::{ErrorKind, OperationOptions, OperationState, SecretBytes, Step};
use support::*;
fn sign_request() -> BatchRequest {
    BatchRequest::Sign {
        slot: Slot::Signature,
        algorithm: Algorithm::EccP256,
        input: SignInput::Digest(SecretBytes::new(vec![0x42; 32])),
    }
}
fn pin() -> BatchRequest {
    BatchRequest::VerifyPin(Pin::from_bytes(b"123456").unwrap())
}
#[test]
fn failure_keeps_completed_items_without_reselect_or_replay() {
    let mut op = batch(
        &profile("3.1.0"),
        vec![pin(), sign_request(), pin(), sign_request()],
        Default::default(),
    )
    .unwrap();
    assert!(batch_progress(&op).is_none());
    selected(&mut op);
    assert_eq!(batch_progress(&op).unwrap().items().len(), 0);
    assert_eq!(
        op.command().unwrap().as_bytes(),
        hex("0020008008313233343536ffff")
    );
    op.advance(&[0x90, 0]).unwrap();
    assert_eq!(batch_progress(&op).unwrap().items().len(), 1);
    assert_eq!(op.command().unwrap().as_bytes()[1], 0x87);
    op.advance(&hex("7c0a820830060201010201029000")).unwrap();
    assert_eq!(op.command().unwrap().as_bytes()[1], 0x20);
    assert_eq!(batch_progress(&op).unwrap().items().len(), 2);
    let error = op.advance(&[0x63, 0xc2]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::AuthenticationFailed);
    assert_eq!(error.retries_remaining, Some(2));
    let progress = batch_progress(&op).unwrap();
    assert_eq!(progress.failed_index(), Some(2));
    assert_eq!(progress.items().len(), 2);
    let BatchItem::Signature(sig) = &progress.items()[1] else {
        panic!("wrong item")
    };
    assert_eq!(sig.to_p1363().unwrap().len(), 64);
    assert_eq!(op.state(), OperationState::Failed);
    assert!(op.result().is_err());
    assert!(op.command().is_err());
    assert!(op.start().is_err());
    assert_eq!(op.error(), Some(&error));
    // Cancel after failure is the normal lifecycle no-op, retaining diagnostic data.
    op.cancel();
    assert_eq!(batch_progress(&op).unwrap().items().len(), 2);
}
#[test]
fn explicit_auth_generation_and_read_finish_with_owned_results() {
    let Access::Management(auth) = access() else {
        panic!()
    };
    let mut op = batch(
        &profile("3.1.0"),
        vec![
            BatchRequest::AuthenticateManagement(auth),
            BatchRequest::GenerateKey(KeyParameters::new(Slot::Authentication, Algorithm::EccP256)),
            BatchRequest::ReadCertificate(Slot::Authentication),
        ],
        Default::default(),
    )
    .unwrap();
    authenticate(&mut op);
    assert_eq!(batch_progress(&op).unwrap().items().len(), 1);
    assert_eq!(
        op.command().unwrap().as_bytes(),
        hex("0047009a05ac03800111")
    );
    let mut public = hex("7f49438641");
    public.extend(hex(P256_POINT));
    public.extend([0x90, 0]);
    op.advance(&public).unwrap();
    assert_eq!(op.command().unwrap().as_bytes()[1], 0xcb);
    assert_eq!(
        op.advance(&hex("530970023000710100fe009000")).unwrap(),
        Step::Done
    );
    assert_eq!(batch_progress(&op).unwrap().items().len(), 3);
    let results = op.take_result().unwrap();
    assert!(batch_progress(&op).is_none());
    drop(op);
    assert_eq!(results.failed_index(), None);
    let BatchItem::Certificate(c) = &results.items()[2] else {
        panic!()
    };
    assert_eq!(c.der(), &[0x30, 0]);
}
#[test]
fn conversation_failure_and_cancellation_have_precise_progress() {
    let mut options = OperationOptions::default();
    options.limits.max_exchanges = 3;
    let mut op = batch(
        &profile("3.1.0"),
        vec![pin(), sign_request(), pin()],
        options,
    )
    .unwrap();
    selected(&mut op);
    op.advance(&[0x90, 0]).unwrap();
    assert_eq!(
        op.advance(&hex("7c0a820830060201010201029000"))
            .unwrap_err()
            .kind,
        ErrorKind::LimitExceeded
    );
    let progress = batch_progress(&op).unwrap();
    assert_eq!(progress.items().len(), 2);
    assert_eq!(progress.failed_index(), Some(2));
    let mut op = batch(
        &profile("3.1.0"),
        vec![pin(), sign_request()],
        Default::default(),
    )
    .unwrap();
    selected(&mut op);
    op.advance(&[0x90, 0]).unwrap();
    op.cancel();
    assert_eq!(op.state(), OperationState::Cancelled);
    assert!(batch_progress(&op).is_none());
    assert!(op.command().is_err());
    let mut op = batch(&profile("3.1.0"), vec![pin()], Default::default()).unwrap();
    op.start().unwrap();
    op.advance(&[0x6a, 0x82]).unwrap_err();
    assert!(batch_progress(&op).is_none());
}
#[test]
fn malformed_later_reply_and_constructor_limits_do_not_hide_prior_success() {
    let mut op = batch(
        &profile("3.1.0"),
        vec![pin(), sign_request()],
        Default::default(),
    )
    .unwrap();
    selected(&mut op);
    op.advance(&[0x90, 0]).unwrap();
    assert!(op.advance(&[0x90]).is_err());
    assert_eq!(batch_progress(&op).unwrap().failed_index(), Some(1));
    assert!(batch(&profile("3.1.0"), vec![], Default::default()).is_err());
    assert!(batch(
        &profile("3.1.0"),
        (0..129).map(|_| pin()).collect(),
        Default::default()
    )
    .is_err());
    assert!(batch(
        &profile("3.1.0"),
        vec![BatchRequest::WriteObject {
            id: ObjectId::certificate(Slot::Signature),
            data: SecretBytes::default()
        }],
        Default::default()
    )
    .is_err());
    let mut options = OperationOptions::default();
    options.limits.max_input_bytes = 40;
    assert!(batch(
        &profile("3.1.0"),
        vec![sign_request(), sign_request()],
        options
    )
    .is_err());
    // Whole-batch validation catches a later unsupported algorithm before SELECT.
    assert!(batch(
        &profile("3.1.0"),
        vec![
            pin(),
            BatchRequest::Sign {
                slot: Slot::Signature,
                algorithm: Algorithm::Rsa1024,
                input: SignInput::RsaEncodedBlock(SecretBytes::new(vec![1; 128]))
            }
        ],
        Default::default()
    )
    .is_err());
}

#[test]
fn decoded_results_share_one_batch_budget() {
    use canokey_protocol::tlv::{Tag, TlvWriter};
    use std::io::Write;
    let mut compressor = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    compressor.write_all(&[0x42; 80]).unwrap();
    let compressed = compressor.finish().unwrap();
    let mut container = TlvWriter::default();
    container
        .push(Tag::from_bytes(&[0x70]).unwrap(), &compressed)
        .unwrap();
    container
        .push(Tag::from_bytes(&[0x71]).unwrap(), &[1])
        .unwrap();
    let mut outer = TlvWriter::default();
    outer
        .push(
            Tag::from_bytes(&[0x53]).unwrap(),
            container.into_bytes().as_bytes(),
        )
        .unwrap();
    let mut response = outer.into_bytes().as_bytes().to_vec();
    response.extend([0x90, 0]);
    assert!(response.len() * 2 < 120);
    let mut options = OperationOptions::default();
    options.limits.max_total_response_bytes = 120;
    let mut op = batch(
        &profile("3.1.0"),
        vec![
            BatchRequest::ReadCertificate(Slot::Authentication),
            BatchRequest::ReadCertificate(Slot::Signature),
        ],
        options,
    )
    .unwrap();
    selected(&mut op);
    op.advance(&response).unwrap();
    let err = op.advance(&response).unwrap_err();
    assert_eq!(err.kind, ErrorKind::LimitExceeded);
    let progress = batch_progress(&op).unwrap();
    assert_eq!(progress.items().len(), 1);
    assert_eq!(progress.failed_index(), Some(1));
}
