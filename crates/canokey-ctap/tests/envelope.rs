use canokey_ctap::{select_application, transceive, transceive_selected, CtapResponse};
use canokey_protocol::{
    ErrorKind, ExchangeOptions, Operation, OperationOptions, OperationState, Phase, Step,
};

const SELECT: [u8; 13] = [
    0x00, 0xa4, 0x04, 0x00, 0x08, 0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01,
];

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
fn transceive_select_missing_applet_is_unsupported_device() {
    let mut op = transceive(&[0x04], OperationOptions::default()).unwrap();
    assert_eq!(op.start().unwrap(), Step::Exchange);
    assert_eq!(op.command().unwrap().as_bytes(), &SELECT);
    let error = op.advance(&[0x6a, 0x82]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::UnsupportedDevice);
    assert_eq!(error.phase, Phase::Select);
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
fn unsupported_ins_status_is_classified() {
    let mut op = begin_transceive(&[0x01]);
    let error = op.advance(&[0x6d, 0x00]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::UnsupportedFeature);
    assert_eq!(error.phase, Phase::Command);
}

#[test]
fn wrong_data_status_keeps_raw_word() {
    let mut op = begin_transceive(&[0x01]);
    let error = op.advance(&[0x6a, 0x80]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::UnexpectedStatusWord);
    assert_eq!(error.status_word.unwrap().raw(), 0x6a80);
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
