#[allow(dead_code)]
mod support;
use canokey_piv::*;
use canokey_protocol::{ErrorKind, Operation, OperationOptions, OperationState, SecretBytes, Step};
use support::*;

// Matches piv_test_mlkem_auth in the pinned firmware: 7C { 82 empty, 81 ciphertext }.
fn send_ciphertext<T>(op: &mut Operation<T>) {
    let mut payload = hex("7c820446820081820440");
    payload.extend([0x42; 1088]);
    let chunks = payload.chunks(255).collect::<Vec<_>>();
    for (i, chunk) in chunks.iter().enumerate() {
        let last = i == chunks.len() - 1;
        let mut command = vec![
            if last { 0 } else { 0x10 },
            0x87,
            0x57,
            0x9d,
            chunk.len() as u8,
        ];
        command.extend_from_slice(chunk);
        assert_eq!(op.command().unwrap().as_bytes(), command);
        assert_eq!(op.command().unwrap().as_bytes(), command);
        if !last {
            op.advance(&[0x90, 0]).unwrap();
        }
    }
}
fn secret_reply(len: usize) -> Vec<u8> {
    let mut data = vec![0x7c, (len + 2) as u8, 0x82, len as u8];
    data.extend(vec![0; len]);
    data.extend([0x90, 0]);
    data
}
fn operation() -> Operation<SecretBytes> {
    decapsulate(
        &profile("3.1.0"),
        Slot::KeyManagement,
        SecretBytes::new(vec![0x42; 1088]),
        Access::None,
        Default::default(),
    )
    .unwrap()
}
#[test]
fn decapsulation_owns_inputs_and_does_not_apply_x25519_zero_rejection() {
    let p = profile("3.1.0");
    let mut op = decapsulate(
        &p,
        Slot::KeyManagement,
        SecretBytes::new(vec![0x42; 1088]),
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
    send_ciphertext(&mut op);
    assert_eq!(op.advance(&secret_reply(32)).unwrap(), Step::Done);
    assert_eq!(op.result().unwrap().as_bytes(), &[0; 32]);
    let secret = op.take_result().unwrap();
    drop(op);
    assert_eq!(secret.len(), 32);
    assert!(!format!("{secret:?}").contains("[0, 0"));
}
#[test]
fn decapsulation_stops_on_chain_errors_cancel_and_malformed_results() {
    let mut op = operation();
    selected(&mut op);
    assert!(op.advance(&[0x6c, 0x20]).is_err());
    assert_eq!(op.state(), OperationState::Failed);
    assert!(op.command().is_err());
    let mut op = operation();
    selected(&mut op);
    op.advance(&[0x90, 0]).unwrap();
    op.cancel();
    assert_eq!(op.state(), OperationState::Cancelled);
    assert!(op.command().is_err());
    assert!(op.advance(&[0x90, 0]).is_err());
    for reply in [
        secret_reply(31),
        secret_reply(33),
        hex("7c0282009000"),
        hex("6982"),
    ] {
        let mut op = operation();
        selected(&mut op);
        send_ciphertext(&mut op);
        assert!(op.advance(&reply).is_err());
        assert!(op.result().is_err());
        assert!(op.command().is_err());
    }
}
#[test]
fn decapsulation_enforces_evidence_and_budgets_before_io() {
    for version in ["3.0.3", "3.1.1", "3.1.0-dev"] {
        assert!(decapsulate(
            &profile(version),
            Slot::KeyManagement,
            SecretBytes::new(vec![0; 1088]),
            Access::None,
            Default::default()
        )
        .is_err());
    }
    let mut observations = canokey_compat::DeviceObservations::new(b"3.1.0".to_vec());
    observations.piv_version = Some(canokey_compat::PivApplicationVersion([5, 7, 0]));
    let missing = canokey_compat::DeviceProfile::from_observations(observations).unwrap();
    assert_eq!(
        decapsulate(
            &missing,
            Slot::KeyManagement,
            SecretBytes::new(vec![0; 1088]),
            Access::None,
            Default::default()
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::CapabilityUnknown
    );
    for len in [0, 1087, 1089] {
        assert!(decapsulate(
            &profile("3.1.0"),
            Slot::KeyManagement,
            SecretBytes::new(vec![0; len]),
            Access::None,
            Default::default()
        )
        .is_err());
    }
    assert!(decapsulate(
        &profile("3.1.0"),
        Slot::Signature,
        SecretBytes::new(vec![0; 1088]),
        Access::None,
        Default::default()
    )
    .is_err());
    let mut options = OperationOptions::default();
    options.limits.max_input_bytes = 1097; // Ciphertext fits, complete template does not.
    assert_eq!(
        decapsulate(
            &profile("3.1.0"),
            Slot::KeyManagement,
            SecretBytes::new(vec![0; 1088]),
            Access::None,
            options
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::LimitExceeded
    );
    options = OperationOptions::default();
    options.limits.max_total_response_bytes = 33;
    let mut op = decapsulate(
        &profile("3.1.0"),
        Slot::KeyManagement,
        SecretBytes::new(vec![0x42; 1088]),
        Access::None,
        options,
    )
    .unwrap();
    selected(&mut op);
    send_ciphertext(&mut op);
    assert_eq!(
        op.advance(&secret_reply(32)).unwrap_err().kind,
        ErrorKind::LimitExceeded
    );
}
#[test]
fn batch_retains_decapsulated_secret_after_later_failure() {
    let mut op = batch(
        &profile("3.1.0"),
        vec![
            BatchRequest::Decapsulate {
                slot: Slot::KeyManagement,
                ciphertext: SecretBytes::new(vec![0x42; 1088]),
            },
            BatchRequest::ReadCertificate(Slot::Authentication),
        ],
        Default::default(),
    )
    .unwrap();
    selected(&mut op);
    send_ciphertext(&mut op);
    op.advance(&secret_reply(32)).unwrap();
    assert_eq!(
        op.advance(&[0x6a, 0x82]).unwrap_err().kind,
        ErrorKind::NotFound
    );
    let progress = batch_progress(&op).unwrap();
    assert_eq!(progress.failed_index(), Some(1));
    let BatchItem::Bytes(secret) = &progress.items()[0] else {
        panic!("expected shared secret")
    };
    assert_eq!(secret.as_bytes(), &[0; 32]);
}
