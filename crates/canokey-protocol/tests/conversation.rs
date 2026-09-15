use canokey_protocol::operation::{conversation, LogicalCommand};
use canokey_protocol::tlv::*;
use canokey_protocol::*;
fn logical() -> LogicalCommand {
    LogicalCommand::new(
        ApduHeader::new(0, 0xcb, 0x3f, 0xff),
        vec![0x5c, 1, 0x7e],
        ExpectedLength::Exact(256),
    )
}
#[test]
fn apdu_cases_and_limits() {
    let h = ApduHeader::new(0, 0x20, 0, 0x80);
    assert_eq!(
        CommandApdu::encode(h, &[], ExpectedLength::Absent, ApduEncoding::Short)
            .unwrap()
            .as_bytes(),
        [0, 0x20, 0, 0x80]
    );
    assert_eq!(
        CommandApdu::encode(h, &[], ExpectedLength::Exact(256), ApduEncoding::Short)
            .unwrap()
            .as_bytes(),
        [0, 0x20, 0, 0x80, 0]
    );
    assert_eq!(
        CommandApdu::encode(h, &[], ExpectedLength::Exact(65536), ApduEncoding::Extended)
            .unwrap()
            .as_bytes(),
        [0, 0x20, 0, 0x80, 0, 0, 0]
    );
    assert_eq!(
        CommandApdu::encode(h, &[1, 2], ExpectedLength::Exact(256), ApduEncoding::Short)
            .unwrap()
            .as_bytes(),
        [0, 0x20, 0, 0x80, 2, 1, 2, 0]
    );
    assert!(
        CommandApdu::encode(h, &[0; 256], ExpectedLength::Absent, ApduEncoding::Short).is_err()
    );
    assert!(CommandApdu::encode(h, &[], ExpectedLength::Exact(0), ApduEncoding::Short).is_err());
}
#[test]
fn response_chaining_owned_result_and_terminal_states() {
    let mut op = conversation(logical(), OperationOptions::default()).unwrap();
    assert!(op.advance(&[0x90, 0]).is_err());
    assert_eq!(op.state(), OperationState::Created);
    assert_eq!(op.start().unwrap(), Step::Exchange);
    let initial = op.command().unwrap().as_bytes().to_vec();
    assert!(op.start().is_err());
    assert_eq!(op.command().unwrap().as_bytes(), initial);
    assert_eq!(op.advance(&[1, 2, 0x61, 2]).unwrap(), Step::Exchange);
    assert_eq!(op.command().unwrap().as_bytes(), [0, 0xc0, 0, 0, 2]);
    assert_eq!(op.advance(&[3, 4, 0x90, 0]).unwrap(), Step::Done);
    assert_eq!(op.result().unwrap().data.as_bytes(), [1, 2, 3, 4]);
    op.cancel(); // completed result remains available
    let result = op.take_result().unwrap();
    assert!(op.take_result().is_err());
    drop(op);
    assert_eq!(result.data.as_bytes(), [1, 2, 3, 4]);
}
#[test]
fn corrected_le_once_and_no_failed_data_accumulation() {
    let mut cmd = logical();
    cmd.correct_le = true;
    let mut op = conversation(cmd, OperationOptions::default()).unwrap();
    op.start().unwrap();
    op.advance(&[0xaa, 0x6c, 3]).unwrap();
    assert_eq!(op.command().unwrap().as_bytes().last(), Some(&3));
    op.advance(&[1, 2, 3, 0x90, 0]).unwrap();
    assert_eq!(op.result().unwrap().data.as_bytes(), [1, 2, 3]);
    let mut cmd = logical();
    cmd.correct_le = true;
    let mut op = conversation(cmd, OperationOptions::default()).unwrap();
    op.start().unwrap();
    op.advance(&[0x6c, 0]).unwrap();
    assert_eq!(op.command().unwrap().as_bytes().last(), Some(&0));
    assert_eq!(op.advance(&[0x6c, 0]).unwrap(), Step::Done);
    assert_eq!(op.result().unwrap().status.raw(), 0x6c00);
}
#[test]
fn command_chaining_and_intermediate_failure() {
    let mut c = LogicalCommand::new(
        ApduHeader::new(0, 0x87, 7, 0x9a),
        vec![0x55; 266],
        ExpectedLength::Exact(256),
    );
    c.allow_chaining = true;
    let mut op = conversation(c.clone(), OperationOptions::default()).unwrap();
    op.start().unwrap();
    assert_eq!(
        &op.command().unwrap().as_bytes()[..5],
        &[0x10, 0x87, 7, 0x9a, 255]
    );
    op.advance(&[0x90, 0]).unwrap();
    assert_eq!(
        &op.command().unwrap().as_bytes()[..5],
        &[0, 0x87, 7, 0x9a, 11]
    );
    op.advance(&[0x90, 0]).unwrap();
    let mut op = conversation(c, OperationOptions::default()).unwrap();
    op.start().unwrap();
    assert_eq!(
        op.advance(&[0x69, 0x82]).unwrap_err().kind,
        ErrorKind::SecurityStatusNotSatisfied
    );
    assert!(op.command().is_err());
    assert_eq!(op.state(), OperationState::Failed);
}
#[test]
fn resource_limits_and_cancel() {
    let mut options = OperationOptions::default();
    options.limits.max_exchanges = 2;
    let mut op = conversation(logical(), options).unwrap();
    op.start().unwrap();
    op.advance(&[1, 0x61, 0]).unwrap();
    assert_eq!(
        op.advance(&[2, 0x61, 0]).unwrap_err().kind,
        ErrorKind::LimitExceeded
    );
    let original = op.error().cloned();
    assert!(op.advance(&[0x90, 0]).is_err());
    assert_eq!(op.error(), original.as_ref());
    let mut op = conversation(logical(), OperationOptions::default()).unwrap();
    op.start().unwrap();
    op.cancel();
    op.cancel();
    assert_eq!(op.state(), OperationState::Cancelled);
    assert!(op.command().is_err());
    let mut op = conversation(logical(), OperationOptions::default()).unwrap();
    op.start().unwrap();
    assert_eq!(
        op.advance(&[0x90]).unwrap_err().kind,
        ErrorKind::InvalidResponse
    );
}
#[test]
fn tlv_duplicates_lengths_and_depth() {
    let mut reader = TlvReader::new(&[0x70, 1, 1, 0x70, 1, 2], TlvLimits::default());
    assert_eq!(reader.next().unwrap().unwrap().value, [1]);
    assert_eq!(reader.next().unwrap().unwrap().value, [2]);
    assert!(reader.next().unwrap().is_none());
    for input in [
        &[0x70, 0x80][..],
        &[0x70, 0x81, 1, 0][..],
        &[0x70, 2, 1][..],
        &[0x1f, 0x80][..],
    ] {
        assert!(TlvReader::new(input, TlvLimits::default()).next().is_err());
    }
    let item = TlvReader::new(
        &[0x7c, 2, 0x70, 0],
        TlvLimits {
            max_depth: 1,
            ..Default::default()
        },
    )
    .next()
    .unwrap()
    .unwrap();
    assert!(item.children().is_err());
    let mut writer = TlvWriter::new(1024);
    let bytes = vec![1; 256];
    writer
        .push(Tag::from_bytes(&[0x7f, 0x49]).unwrap(), &bytes)
        .unwrap();
    let data = writer.into_bytes();
    assert_eq!(&data.as_bytes()[..5], &[0x7f, 0x49, 0x82, 1, 0]);
    assert_eq!(
        TlvReader::new(data.as_bytes(), TlvLimits::default())
            .next()
            .unwrap()
            .unwrap()
            .value,
        bytes
    );
}
#[test]
fn parser_deterministic_fuzz_smoke() {
    let mut seed = 0x31415926u32;
    for n in 0..2048 {
        let mut data = vec![0; n % 257];
        for b in &mut data {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            *b = seed as u8;
        }
        let _ = ResponseApdu::parse(&data);
        let mut reader = TlvReader::new(&data, TlvLimits::default());
        while let Ok(Some(item)) = reader.next() {
            if let Ok(mut children) = item.children() {
                let _ = children.next();
            }
        }
    }
}

#[test]
fn working_state_is_dropped_on_every_terminal_path() {
    use canokey_protocol::operation::engine::{Action, Machine};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    struct OwnedWork(Arc<AtomicUsize>);
    impl Drop for OwnedWork {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    impl Machine<()> for OwnedWork {
        fn next(
            &mut self,
            response: Option<canokey_protocol::operation::ResponseData>,
        ) -> Result<Action<()>, Error> {
            if response.is_some() {
                Ok(Action::Done(()))
            } else {
                Ok(Action::Command(logical()))
            }
        }
    }
    for mode in 0..4 {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut op =
            Operation::from_machine(OwnedWork(drops.clone()), OperationOptions::default()).unwrap();
        op.start().unwrap();
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        match mode {
            0 => {
                op.advance(&[0x90, 0]).unwrap();
            }
            1 => op.cancel(),
            2 => {
                assert!(op.advance(&[]).is_err());
            }
            _ => {
                drop(op);
                assert_eq!(drops.load(Ordering::SeqCst), 1);
                continue;
            }
        }
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        drop(op);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn no_progress_response_budget_and_none_policy() {
    use canokey_protocol::operation::Continuation;
    let mut op = conversation(logical(), OperationOptions::default()).unwrap();
    op.start().unwrap();
    op.advance(&[0x61, 0]).unwrap();
    assert_eq!(
        op.advance(&[0x61, 0]).unwrap_err().kind,
        ErrorKind::ProtocolViolation
    );
    let mut limits = OperationOptions::default();
    limits.limits.max_total_response_bytes = 2;
    let mut op = conversation(logical(), limits).unwrap();
    op.start().unwrap();
    op.advance(&[1, 2, 0x61, 1]).unwrap();
    let error = op.advance(&[3, 0x90, 0]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::LimitExceeded);
    assert_eq!(error.phase, Phase::Conversation);
    assert_eq!(op.state(), OperationState::Failed);
    assert_eq!(op.error().unwrap().phase, Phase::Conversation);
    let mut cmd = logical();
    cmd.continuation = Continuation::None;
    let mut op = conversation(cmd, OperationOptions::default()).unwrap();
    op.start().unwrap();
    assert_eq!(op.advance(&[1, 0x61, 1]).unwrap(), Step::Done);
    assert_eq!(op.result().unwrap().status.raw(), 0x6101);
}

#[test]
fn smaller_channels_and_invalid_inputs_are_preflighted() {
    let mut opts = OperationOptions::default();
    opts.exchange.max_response_bytes = 18;
    let mut cmd = logical();
    cmd.correct_le = true;
    let mut op = conversation(cmd, opts).unwrap();
    op.start().unwrap();
    assert_eq!(op.command().unwrap().as_bytes().last(), Some(&16));
    let error = op.advance(&[0x6c, 0]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::LimitExceeded);
    assert_eq!(error.phase, Phase::Conversation);
    let mut oversized = conversation(logical(), OperationOptions::default()).unwrap();
    oversized.start().unwrap();
    let error = oversized.advance(&[0; 259]).unwrap_err();
    assert_eq!(error.kind, ErrorKind::LimitExceeded);
    assert_eq!(error.phase, Phase::Conversation);
    assert!(oversized.command().is_err() && oversized.result().is_err());
    let mut opts = OperationOptions::default();
    opts.exchange.max_command_bytes = 5;
    assert!(conversation(logical(), opts).is_err());
    let mut cmd = logical();
    cmd.data = SecretBytes::new(vec![0; 512]);
    assert!(conversation(cmd, OperationOptions::default()).is_err());
}
