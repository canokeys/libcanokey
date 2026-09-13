//! Stable, read-only CanoKey Admin bootstrap commands.
#![forbid(unsafe_code)]
use canokey_protocol::{operation::LogicalCommand, ApduHeader, ExpectedLength};
pub mod command {
    use super::*;
    pub fn select() -> LogicalCommand {
        LogicalCommand::new(
            ApduHeader::new(0, 0xa4, 4, 0),
            vec![0xf0, 0, 0, 0, 0],
            ExpectedLength::Absent,
        )
    }
    fn read(ins: u8, p1: u8) -> LogicalCommand {
        let mut command = LogicalCommand::new(
            ApduHeader::new(0, ins, p1, 0),
            vec![],
            ExpectedLength::Exact(256),
        );
        command.correct_le = true;
        command
    }
    pub fn firmware() -> LogicalCommand {
        read(0x31, 0)
    }
    pub fn model() -> LogicalCommand {
        read(0x31, 1)
    }
    pub fn serial() -> LogicalCommand {
        read(0x32, 0)
    }
}
