use canokey_protocol::{
    operation::{conversation, Continuation, LogicalCommand},
    ApduHeader, ErrorKind, ExpectedLength, Step,
};
fn op(instruction: u8) -> canokey_protocol::Operation<canokey_protocol::operation::ResponseData> {
    let mut c = LogicalCommand::new(
        ApduHeader::new(0, 0xa4, 0, 1),
        vec![],
        ExpectedLength::Exact(255),
    );
    c.continuation = Continuation::Oath {
        instruction,
        probe_after_success: true,
    };
    let mut op = conversation(c, Default::default()).unwrap();
    op.start().unwrap();
    op
}
#[test]
fn modern_and_legacy_speculative_completion() {
    for ins in [6, 0xa5] {
        let mut op = op(ins);
        op.advance(&[1, 0x61, 0xff]).unwrap();
        assert_eq!(op.command().unwrap().as_bytes(), &[0, ins, 0, 0, 0xff]);
        op.advance(&[2, 0x90, 0]).unwrap();
        assert_eq!(op.command().unwrap().as_bytes(), &[0, ins, 0, 0, 0xff]);
        assert_eq!(op.advance(&[0x69, 0x85]).unwrap(), Step::Done);
        assert_eq!(op.result().unwrap().data.as_bytes(), &[1, 2]);
        assert!(op.result().unwrap().status.is_success());
    }
}
#[test]
fn promised_pages_cannot_end_with_conditions_failure() {
    let mut op = op(0xa5);
    op.advance(&[1, 0x61, 1]).unwrap();
    op.advance(&[0x69, 0x85]).unwrap();
    assert_eq!(op.result().unwrap().status.raw(), 0x6985);
    let mut op = op_for_empty();
    assert_eq!(
        op.advance(&[0x61, 0xff]).unwrap_err().kind,
        ErrorKind::ProtocolViolation
    );
}
fn op_for_empty() -> canokey_protocol::Operation<canokey_protocol::operation::ResponseData> {
    op(6)
}
#[test]
fn no_retry_or_nonempty_error_suppression() {
    let mut op = op(0xa5);
    op.advance(&[1, 0x90, 0]).unwrap();
    op.advance(&[0x6c, 10]).unwrap();
    assert_eq!(op.result().unwrap().status.raw(), 0x6c0a);
    let mut op = op_for_empty();
    op.advance(&[1, 0x90, 0]).unwrap();
    op.advance(&[8, 0x69, 0x85]).unwrap();
    assert_eq!(op.result().unwrap().status.raw(), 0x6985);
}
