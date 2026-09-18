use canokey_ndef::{
    read_capability, read_message, write_message, NdefCapability, MAX_MESSAGE_LENGTH,
};
use canokey_protocol::{
    ErrorKind, ExchangeOptions, OperationLimits, OperationOptions, OperationState, Phase, Step,
};

const SELECT_APPLET: [u8; 12] = [
    0x00, 0xa4, 0x04, 0x00, 0x07, 0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01,
];
const SELECT_CC: [u8; 7] = [0x00, 0xa4, 0x00, 0x0c, 0x02, 0xe1, 0x03];
const SELECT_NDEF: [u8; 7] = [0x00, 0xa4, 0x00, 0x0c, 0x02, 0x00, 0x01];
const READ_CC: [u8; 5] = [0x00, 0xb0, 0x00, 0x00, 0x0f];
const READ_NLEN: [u8; 5] = [0x00, 0xb0, 0x00, 0x00, 0x02];
const OK: [u8; 2] = [0x90, 0x00];

/// A 15-byte capability container plus success status, advertising file 0x0001.
fn cc_response(max_file_size: u16, read_only: bool) -> Vec<u8> {
    cc_response_with_file(0x0001, max_file_size, read_only)
}

/// A 15-byte capability container advertising an arbitrary NDEF file ID.
fn cc_response_with_file(file_id: u16, max_file_size: u16, read_only: bool) -> Vec<u8> {
    let mut cc = vec![0x00, 0x0f, 0x20, 0x00, 0xff, 0x00, 0xff, 0x04, 0x06];
    cc.extend(file_id.to_be_bytes());
    cc.extend(max_file_size.to_be_bytes());
    cc.push(0x00);
    cc.push(if read_only { 0xff } else { 0x00 });
    cc.extend(OK);
    cc
}

/// Drive a read_message operation up to the pending NLEN read.
fn at_nlen_read() -> canokey_protocol::Operation<canokey_ndef::NdefMessage> {
    let mut op = read_message(Default::default()).unwrap();
    assert_eq!(op.start().unwrap(), Step::Exchange);
    assert_eq!(op.command().unwrap().as_bytes(), &SELECT_APPLET);
    op.advance(&OK).unwrap();
    assert_eq!(op.command().unwrap().as_bytes(), &SELECT_CC);
    op.advance(&OK).unwrap();
    assert_eq!(op.command().unwrap().as_bytes(), &READ_CC);
    op.advance(&cc_response(1024, false)).unwrap();
    assert_eq!(op.command().unwrap().as_bytes(), &SELECT_NDEF);
    op.advance(&OK).unwrap();
    assert_eq!(op.command().unwrap().as_bytes(), &READ_NLEN);
    op
}

#[test]
fn read_capability_transcript() {
    let mut op = read_capability(Default::default()).unwrap();
    assert_eq!(op.start().unwrap(), Step::Exchange);
    assert_eq!(op.command().unwrap().as_bytes(), &SELECT_APPLET);
    op.advance(&OK).unwrap();
    assert_eq!(op.command().unwrap().as_bytes(), &SELECT_CC);
    op.advance(&OK).unwrap();
    assert_eq!(op.command().unwrap().as_bytes(), &READ_CC);
    assert_eq!(op.advance(&cc_response(1024, false)).unwrap(), Step::Done);
    let capability = op.take_result().unwrap();
    assert_eq!(
        capability,
        NdefCapability {
            file_id: 0x0001,
            max_message_length: 1022,
            read_only: false,
        }
    );
}

#[test]
fn read_message_selects_cc_advertised_file_id() {
    // The CC declares the NDEF file; honor an ID other than the usual 0x0001.
    let mut op = read_message(Default::default()).unwrap();
    op.start().unwrap();
    op.advance(&OK).unwrap();
    op.advance(&OK).unwrap();
    op.advance(&cc_response_with_file(0xe104, 1024, false))
        .unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0x00, 0xa4, 0x00, 0x0c, 0x02, 0xe1, 0x04]
    );
}

#[test]
fn read_capability_rejects_invalid_cc() {
    // Bad NDEF file control TLV marker: the length/marker rejection branch.
    let mut bad_tag = cc_response(1024, false);
    bad_tag[7] = 0x05;
    // A maximum file size below the two NLEN bytes: the minimum-size branch.
    let tiny = cc_response(1, false);
    for cc in [bad_tag, tiny] {
        let mut op = read_capability(Default::default()).unwrap();
        op.start().unwrap();
        op.advance(&OK).unwrap();
        op.advance(&OK).unwrap();
        let error = op.advance(&cc).unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidResponse);
        assert_eq!(error.phase, Phase::Parsing);
        assert_eq!(op.state(), OperationState::Failed);
    }
}

#[test]
fn read_message_single_chunk() {
    let mut op = at_nlen_read();
    op.advance(&[0x00, 0x05, 0x90, 0x00]).unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0x00, 0xb0, 0x00, 0x02, 0x05]
    );
    assert_eq!(op.advance(b"hello\x90\x00").unwrap(), Step::Done);
    let message = op.take_result().unwrap();
    assert_eq!(message.as_bytes(), b"hello");
    assert_eq!(message.len(), 5);
    assert!(!message.is_empty());
    assert!(!format!("{message:?}").contains("hello"));
}

#[test]
fn read_message_multi_chunk() {
    let body: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
    let mut op = at_nlen_read();
    op.advance(&[0x01, 0x2c, 0x90, 0x00]).unwrap(); // NLEN = 300
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0x00, 0xb0, 0x00, 0x02, 0xf0]
    );
    let mut first: Vec<u8> = body[..240].to_vec();
    first.extend(OK);
    op.advance(&first).unwrap();
    // Second chunk starts at offset 242 with 60 bytes remaining.
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0x00, 0xb0, 0x00, 0xf2, 0x3c]
    );
    let mut second: Vec<u8> = body[240..].to_vec();
    second.extend(OK);
    assert_eq!(op.advance(&second).unwrap(), Step::Done);
    assert_eq!(op.result().unwrap().as_bytes(), body);
}

#[test]
fn read_message_rejects_nlen_beyond_cc_maximum() {
    let mut op = read_message(Default::default()).unwrap();
    op.start().unwrap();
    op.advance(&OK).unwrap();
    op.advance(&OK).unwrap();
    op.advance(&cc_response(10, false)).unwrap(); // max message = 8
    op.advance(&OK).unwrap();
    assert_eq!(op.command().unwrap().as_bytes(), &READ_NLEN);
    let error = op.advance(&[0x00, 0x09, 0x90, 0x00]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert_eq!(error.phase, Phase::Parsing);
    assert_eq!(op.state(), OperationState::Failed);
}

#[test]
fn read_message_rejects_short_nlen_and_short_chunk() {
    let mut op = at_nlen_read();
    let error = op.advance(&[0x00, 0x90, 0x00]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    let mut op = at_nlen_read();
    op.advance(&[0x00, 0x05, 0x90, 0x00]).unwrap();
    let error = op.advance(b"hell\x90\x00").unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidResponse);
    assert_eq!(error.phase, Phase::Parsing);
}

#[test]
fn select_failures_distinguish_applet_and_file() {
    let mut op = read_message(Default::default()).unwrap();
    op.start().unwrap();
    let error = op.advance(&[0x6a, 0x82]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::UnsupportedDevice);
    assert_eq!(error.phase, Phase::Select);

    let mut op = read_message(Default::default()).unwrap();
    op.start().unwrap();
    op.advance(&OK).unwrap();
    let error = op.advance(&[0x6a, 0x82]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::NotFound);
    assert_eq!(error.phase, Phase::Command);
}

#[test]
fn read_message_preflights_operation_limits() {
    let tight_response = OperationOptions {
        exchange: ExchangeOptions::default(),
        limits: OperationLimits {
            max_total_response_bytes: 15 + 2 + MAX_MESSAGE_LENGTH - 1,
            ..Default::default()
        },
    };
    assert_eq!(
        read_message(tight_response).unwrap_err().kind,
        ErrorKind::LimitExceeded
    );
    let tight_exchanges = OperationOptions {
        exchange: ExchangeOptions::default(),
        limits: OperationLimits {
            max_exchanges: 9,
            ..Default::default()
        },
    };
    assert_eq!(
        read_message(tight_exchanges).unwrap_err().kind,
        ErrorKind::LimitExceeded
    );
    // A channel too small for the 15-byte CC read fails at construction.
    let tight_channel = OperationOptions {
        exchange: ExchangeOptions {
            max_command_bytes: 261,
            max_response_bytes: 16,
            allow_extended: false,
        },
        limits: OperationLimits::default(),
    };
    assert_eq!(
        read_message(tight_channel).unwrap_err().kind,
        ErrorKind::LimitExceeded
    );
}

#[test]
fn write_message_single_chunk_transcript() {
    let mut op = write_message(b"hello", Default::default()).unwrap();
    assert_eq!(op.start().unwrap(), Step::Exchange);
    assert_eq!(op.command().unwrap().as_bytes(), &SELECT_APPLET);
    op.advance(&OK).unwrap();
    assert_eq!(op.command().unwrap().as_bytes(), &SELECT_CC);
    op.advance(&OK).unwrap();
    assert_eq!(op.command().unwrap().as_bytes(), &READ_CC);
    op.advance(&cc_response(1024, false)).unwrap();
    assert_eq!(op.command().unwrap().as_bytes(), &SELECT_NDEF);
    op.advance(&OK).unwrap();
    // Zero NLEN first: an interrupted write leaves no stale message.
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0x00, 0xd6, 0x00, 0x00, 0x02, 0x00, 0x00]
    );
    op.advance(&OK).unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0x00, 0xd6, 0x00, 0x02, 0x05, b'h', b'e', b'l', b'l', b'o']
    );
    op.advance(&OK).unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0x00, 0xd6, 0x00, 0x00, 0x02, 0x00, 0x05]
    );
    assert_eq!(op.advance(&OK).unwrap(), Step::Done);
    assert_eq!(op.state(), OperationState::Completed);
}

#[test]
fn write_message_multi_chunk() {
    let body: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
    let mut op = write_message(&body, Default::default()).unwrap();
    op.start().unwrap();
    op.advance(&OK).unwrap();
    op.advance(&OK).unwrap();
    op.advance(&cc_response(1024, false)).unwrap();
    op.advance(&OK).unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0x00, 0xd6, 0x00, 0x00, 0x02, 0x00, 0x00]
    );
    op.advance(&OK).unwrap();
    let mut expected = vec![0x00, 0xd6, 0x00, 0x02, 0xf0];
    expected.extend(&body[..240]);
    assert_eq!(op.command().unwrap().as_bytes(), expected);
    op.advance(&OK).unwrap();
    let mut expected = vec![0x00, 0xd6, 0x00, 0xf2, 0x3c];
    expected.extend(&body[240..]);
    assert_eq!(op.command().unwrap().as_bytes(), expected);
    op.advance(&OK).unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0x00, 0xd6, 0x00, 0x00, 0x02, 0x01, 0x2c]
    );
    assert_eq!(op.advance(&OK).unwrap(), Step::Done);
}

#[test]
fn write_message_empty_skips_chunks() {
    let mut op = write_message(b"", Default::default()).unwrap();
    op.start().unwrap();
    op.advance(&OK).unwrap();
    op.advance(&OK).unwrap();
    op.advance(&cc_response(1024, false)).unwrap();
    op.advance(&OK).unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0x00, 0xd6, 0x00, 0x00, 0x02, 0x00, 0x00]
    );
    op.advance(&OK).unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0x00, 0xd6, 0x00, 0x00, 0x02, 0x00, 0x00]
    );
    assert_eq!(op.advance(&OK).unwrap(), Step::Done);
}

#[test]
fn write_message_selects_cc_advertised_file_id() {
    let mut op = write_message(b"hi", Default::default()).unwrap();
    op.start().unwrap();
    op.advance(&OK).unwrap();
    op.advance(&OK).unwrap();
    op.advance(&cc_response_with_file(0xe104, 1024, false))
        .unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        &[0x00, 0xa4, 0x00, 0x0c, 0x02, 0xe1, 0x04]
    );
}

#[test]
fn write_message_read_only_cc_fails_before_any_update() {
    let mut op = write_message(b"hello", Default::default()).unwrap();
    op.start().unwrap();
    op.advance(&OK).unwrap();
    op.advance(&OK).unwrap();
    // The pending command is the CC read; a read-only CC fails the write
    // before any UPDATE BINARY is emitted.
    assert_eq!(op.command().unwrap().as_bytes(), &READ_CC);
    let error = op.advance(&cc_response(1024, true)).unwrap_err();
    assert_eq!(error.kind, ErrorKind::SecurityStatusNotSatisfied);
    assert_eq!(error.phase, Phase::Command);
    assert_eq!(op.state(), OperationState::Failed);
}

#[test]
fn write_message_beyond_cc_maximum_fails_before_any_update() {
    let mut op = write_message(b"hello", Default::default()).unwrap();
    op.start().unwrap();
    op.advance(&OK).unwrap();
    op.advance(&OK).unwrap();
    assert_eq!(op.command().unwrap().as_bytes(), &READ_CC);
    // CC maximum file size 6 allows only a four-byte message.
    let error = op.advance(&cc_response(6, false)).unwrap_err();
    assert_eq!(error.kind, ErrorKind::LimitExceeded);
    assert_eq!(error.phase, Phase::Command);
    assert_eq!(op.state(), OperationState::Failed);
}

#[test]
fn write_message_rejects_oversized_message_before_io() {
    let message = vec![0u8; MAX_MESSAGE_LENGTH + 1];
    let error = write_message(&message, Default::default()).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidArgument);
    // The firmware hard maximum itself is accepted at construction.
    let message = vec![0u8; MAX_MESSAGE_LENGTH];
    write_message(&message, Default::default()).unwrap();
}

#[test]
fn write_message_preflights_exchange_budget() {
    let tight = OperationOptions {
        exchange: ExchangeOptions::default(),
        limits: OperationLimits {
            max_exchanges: 4,
            ..Default::default()
        },
    };
    assert_eq!(
        write_message(b"hello", tight).unwrap_err().kind,
        ErrorKind::LimitExceeded
    );
}

#[test]
fn cancel_mid_operation_sends_nothing_further() {
    let mut op = at_nlen_read();
    op.cancel();
    assert_eq!(op.state(), OperationState::Cancelled);
    assert_eq!(
        op.command().unwrap_err().kind,
        ErrorKind::OperationStateError
    );
    assert_eq!(
        op.advance(&OK).unwrap_err().kind,
        ErrorKind::OperationStateError
    );
}
