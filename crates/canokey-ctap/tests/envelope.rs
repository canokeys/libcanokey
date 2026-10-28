use canokey_ctap::{select_application, transceive, transceive_selected, CtapResponse};
use canokey_protocol::{
    ErrorKind, ExchangeOptions, Operation, OperationOptions, OperationState, Phase, Step,
};

mod support;

use support::SELECT;

fn begin_transceive(message: &[u8]) -> Operation<CtapResponse> {
    let mut op = transceive(message, OperationOptions::default()).unwrap();
    assert_eq!(op.start().unwrap(), Step::Exchange);
    assert_eq!(op.command().unwrap().as_bytes(), &SELECT);
    assert_eq!(op.advance(&[0x90, 0x00]).unwrap(), Step::Exchange);
    op
}

#[test]
fn select_application_golden_bytes_and_success() {
    let mut op = select_application(OperationOptions::default()).unwrap();
    assert_eq!(op.start().unwrap(), Step::Exchange);
    assert_eq!(op.command().unwrap().as_bytes(), &SELECT);
    assert_eq!(op.advance(&[0x90, 0x00]).unwrap(), Step::Done);
    assert_eq!(op.state(), OperationState::Completed);
    op.take_result().unwrap();
    assert_eq!(op.state(), OperationState::ResultTaken);
}

#[test]
fn select_application_missing_applet_is_unsupported_device() {
    let mut op = select_application(OperationOptions::default()).unwrap();
    op.start().unwrap();
    assert_eq!(op.advance(&[0x6a, 0x82]).unwrap(), Step::Exchange);
    let error = op.advance(&[0x6a, 0x82]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::UnsupportedDevice);
    assert_eq!(error.phase, Phase::Select);
    assert_eq!(op.state(), OperationState::Failed);
}

#[test]
fn transceive_golden_bytes_and_response_parse() {
    let mut op = begin_transceive(&[0x04]);
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0x80, 0x10, 0x00, 0x00, 0x01, 0x04]
    );
    assert_eq!(
        op.advance(&[0x00, 0xa1, 0x01, 0x83, 0x90, 0x00]).unwrap(),
        Step::Done
    );
    let response = op.take_result().unwrap();
    assert!(response.status().is_success());
    assert_eq!(response.status().raw(), 0x00);
    assert_eq!(response.payload(), &[0xa1, 0x01, 0x83]);
}

#[test]
fn transceive_selected_sends_no_select() {
    let mut op = transceive_selected(&[0x0a, 0x01], OperationOptions::default()).unwrap();
    assert_eq!(op.start().unwrap(), Step::Exchange);
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0x80, 0x10, 0x00, 0x00, 0x02, 0x0a, 0x01]
    );
    assert_eq!(op.advance(&[0x00, 0x90, 0x00]).unwrap(), Step::Done);
    let response = op.take_result().unwrap();
    assert!(response.status().is_success());
    assert!(response.payload().is_empty());
}

#[test]
fn transceive_selected_extended_length_command() {
    let message = vec![0x01; 300];
    let options = OperationOptions {
        exchange: ExchangeOptions {
            max_command_bytes: 1024,
            allow_extended: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut op = transceive_selected(&message, options).unwrap();
    assert_eq!(op.start().unwrap(), Step::Exchange);
    let mut expected = vec![0x80, 0x10, 0x00, 0x00, 0x00, 0x01, 0x2c];
    expected.extend_from_slice(&message);
    assert_eq!(op.command().unwrap().as_bytes(), &expected);
    assert_eq!(op.advance(&[0x00, 0x90, 0x00]).unwrap(), Step::Done);
    assert!(op.take_result().unwrap().status().is_success());
}

#[test]
fn continuation_loop_concatenates_payload() {
    let mut op = begin_transceive(&[0x04]);
    assert_eq!(
        op.advance(&[0x00, 0xaa, 0x61, 0x02]).unwrap(),
        Step::Exchange
    );
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0x80, 0xc0, 0x00, 0x00, 0x02]
    );
    assert_eq!(
        op.advance(&[0xbb, 0xcc, 0x61, 0x01]).unwrap(),
        Step::Exchange
    );
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0x80, 0xc0, 0x00, 0x00, 0x01]
    );
    assert_eq!(op.advance(&[0xdd, 0x90, 0x00]).unwrap(), Step::Done);
    let response = op.take_result().unwrap();
    assert!(response.status().is_success());
    assert_eq!(response.payload(), &[0xaa, 0xbb, 0xcc, 0xdd]);
}

#[test]
fn empty_success_response_is_invalid_response() {
    let mut op = begin_transceive(&[0x04]);
    let error = op.advance(&[0x90, 0x00]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert_eq!(error.phase, Phase::Parsing);
    assert_eq!(op.state(), OperationState::Failed);
    assert_eq!(op.error().unwrap().kind, ErrorKind::InvalidResponse);
}

#[test]
fn empty_message_rejected_before_io() {
    let error = transceive_selected(&[], OperationOptions::default()).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidArgument);
    let error = transceive(&[], OperationOptions::default()).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidArgument);
}

#[test]
fn message_over_input_limit_rejected_before_io() {
    let options = OperationOptions {
        limits: canokey_protocol::OperationLimits {
            max_input_bytes: 4,
            ..Default::default()
        },
        ..Default::default()
    };
    let error = transceive_selected(&[0x01, 0x02, 0x03, 0x04, 0x05], options).unwrap_err();
    assert_eq!(error.kind, ErrorKind::LimitExceeded);
    let error = transceive(&[0x01, 0x02, 0x03, 0x04, 0x05], options).unwrap_err();
    assert_eq!(error.kind, ErrorKind::LimitExceeded);
}

#[test]
fn conditions_not_satisfied_status_is_classified() {
    let mut op = begin_transceive(&[0x01]);
    let error = op.advance(&[0x69, 0x85]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::ConditionsNotSatisfied);
    assert_eq!(error.phase, Phase::Command);
    assert_eq!(error.status_word.unwrap().raw(), 0x6985);
}

#[test]
fn non_success_ctap_status_is_surfaced_raw() {
    let mut op = begin_transceive(&[0x01]);
    assert_eq!(op.advance(&[0x2e, 0xff, 0x90, 0x00]).unwrap(), Step::Done);
    let response = op.take_result().unwrap();
    assert!(!response.status().is_success());
    assert_eq!(response.status().raw(), 0x2e);
    assert_eq!(response.payload(), &[0xff]);
}

#[test]
fn cancel_mid_continuation_sends_nothing_further() {
    let mut op = begin_transceive(&[0x04]);
    assert_eq!(
        op.advance(&[0x00, 0xaa, 0x61, 0x02]).unwrap(),
        Step::Exchange
    );
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0x80, 0xc0, 0x00, 0x00, 0x02]
    );
    op.cancel();
    assert_eq!(op.state(), OperationState::Cancelled);
    let error = op.command().unwrap_err();
    assert_eq!(error.kind, ErrorKind::OperationStateError);
    let error = op.advance(&[0xbb, 0xcc, 0x90, 0x00]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::OperationStateError);
}

#[test]
fn debug_redacts_response_payload() {
    let mut op = begin_transceive(&[0x04]);
    let mut reply = vec![0x00];
    reply.extend_from_slice(b"credential-material-7f3a");
    reply.extend_from_slice(&[0x90, 0x00]);
    assert_eq!(op.advance(&reply).unwrap(), Step::Done);
    let response = op.take_result().unwrap();
    let debug = format!("{:?}", response);
    assert!(!debug.contains("credential-material-7f3a"));
    for byte in b"credential-material-7f3a" {
        assert!(!debug.contains(&byte.to_string()));
    }
    assert!(debug.contains("REDACTED"));
}

const STANDARD_SELECT: [u8; 13] = [
    0x00, 0xa4, 0x04, 0x00, 0x08, 0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01,
];

fn fallback<T>(op: &mut Operation<T>) {
    assert_eq!(op.start().unwrap(), Step::Exchange);
    assert_eq!(op.command().unwrap().as_bytes(), SELECT);
    assert_eq!(op.advance(&[0x6a, 0x82]).unwrap(), Step::Exchange);
    // Getters neither resend nor advance the selection negotiation.
    for _ in 0..2 {
        assert_eq!(op.command().unwrap().as_bytes(), STANDARD_SELECT);
    }
}

#[test]
fn legacy_and_nfc_selection_fallback_completes_once() {
    let mut op = select_application(OperationOptions::default()).unwrap();
    fallback(&mut op);
    assert_eq!(op.advance(b"U2F_V2\x90\x00").unwrap(), Step::Done);
    op.take_result().unwrap();
    assert!(op.take_result().is_err());

    let mut op = transceive(&[4], OperationOptions::default()).unwrap();
    fallback(&mut op);
    assert_eq!(op.advance(b"U2F_V2\x90\x00").unwrap(), Step::Exchange);
    assert_eq!(op.command().unwrap().as_bytes(), &[0x80, 0x10, 0, 0, 1, 4]);
    // A missing applet after selection must not restart or replay the command.
    let error = op.advance(&[0x6a, 0x82]).unwrap_err();
    assert_eq!(error.phase, Phase::Command);
    assert_eq!(op.state(), OperationState::Failed);
    assert!(op.command().is_err());
}

#[test]
fn selection_other_errors_never_fall_back() {
    for response in [&[0x69, 0x85][..], &[0x6d, 0x00], &[0x6a, 0x80], &[0x90]] {
        let mut op = select_application(OperationOptions::default()).unwrap();
        op.start().unwrap();
        assert!(op.advance(response).is_err());
        assert_eq!(op.state(), OperationState::Failed);
        assert!(op.command().is_err());
    }
}

#[test]
fn fallback_respects_cancel_and_exchange_budget() {
    let mut op = select_application(OperationOptions::default()).unwrap();
    fallback(&mut op);
    op.cancel();
    assert_eq!(op.state(), OperationState::Cancelled);
    assert!(op.command().is_err());
    assert!(op.advance(&[0x90, 0]).is_err());

    let mut options = OperationOptions::default();
    options.limits.max_exchanges = 1;
    let mut op = select_application(options).unwrap();
    op.start().unwrap();
    assert_eq!(
        op.advance(&[0x6a, 0x82]).unwrap_err().kind,
        ErrorKind::LimitExceeded
    );
    assert!(op.command().is_err());
}

#[test]
fn u2f_fallback_preserves_command_and_result() {
    let mut op = canokey_ctap::u2f::version(OperationOptions::default()).unwrap();
    fallback(&mut op);
    assert_eq!(op.advance(b"U2F_V2\x90\x00").unwrap(), Step::Exchange);
    assert_eq!(op.command().unwrap().as_bytes()[1], 0x03);
    assert_eq!(op.advance(b"U2F_V2\x90\x00").unwrap(), Step::Done);
    assert_eq!(op.take_result().unwrap(), b"U2F_V2");
}

#[cfg(feature = "clientpin")]
#[test]
fn management_machines_support_fallback() {
    let mut read = canokey_ctap::largeblob::read_array(OperationOptions::default()).unwrap();
    fallback(&mut read);
    assert_eq!(read.advance(&[0x90, 0]).unwrap(), Step::Exchange);
    assert_eq!(read.command().unwrap().as_bytes()[5], 0x0c);
    assert_eq!(
        read.advance(&[0, 0xa1, 1, 0x40, 0x90, 0]).unwrap(),
        Step::Done
    );
    assert!(read.take_result().unwrap().is_empty());

    let mut options = OperationOptions::default();
    options.limits.max_input_bytes = 128;
    let mut write = canokey_ctap::largeblob::write_array(&[0; 100], None, options).unwrap();
    fallback(&mut write);
    assert_eq!(write.advance(&[0x90, 0]).unwrap(), Step::Exchange);
    assert_eq!(write.command().unwrap().as_bytes()[5], 0x0c);
    // Fragment two follows directly, with no SELECT between mutations.
    assert_eq!(write.advance(&[0, 0x90, 0]).unwrap(), Step::Exchange);
    assert_eq!(write.command().unwrap().as_bytes()[5], 0x0c);
    assert_eq!(write.advance(&[0, 0x90, 0]).unwrap(), Step::Done);
    write.take_result().unwrap();

    let token = support::token_v1();
    let mut enumerate = canokey_ctap::credmgmt::enumerate_rps(
        &token,
        canokey_ctap::PinUvAuthProtocol::V1,
        OperationOptions::default(),
    )
    .unwrap();
    fallback(&mut enumerate);
    assert_eq!(enumerate.advance(&[0x90, 0]).unwrap(), Step::Exchange);
    assert_eq!(enumerate.command().unwrap().as_bytes()[5], 0x0a);
    assert_eq!(enumerate.advance(&[0x2e, 0x90, 0]).unwrap(), Step::Done);
    assert!(enumerate.take_result().unwrap().is_empty());
}
