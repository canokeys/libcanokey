//! Stable, read-only CanoKey Admin bootstrap commands.
//!
//! These builders return raw logical commands; they do not select automatically,
//! interpret responses, or build device profiles. Applications normally use
//! `canokey::probe_device`, which orchestrates these reads with compatibility rules.
//! No full Admin configuration or authentication API is implemented yet.
//!
#![deny(missing_docs)]
#![forbid(unsafe_code)]
use canokey_protocol::{operation::LogicalCommand, ApduHeader, ExpectedLength};
/// Raw Admin bootstrap builders for use in a protocol conversation.
pub mod command {
    use super::*;
    /// Build SELECT for the Admin AID. Selecting may change card security state.
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
    /// Build the actual-firmware text read (INS 31, P1 00). Admin must be selected.
    /// This is not the PIV application compatibility version.
    pub fn firmware() -> LogicalCommand {
        read(0x31, 0)
    }
    /// Build the optional model read (INS 31, P1 01). Admin must be selected.
    pub fn model() -> LogicalCommand {
        read(0x31, 1)
    }
    /// Build the optional serial read (INS 32). Admin must be selected.
    /// The bootstrap protocol expects four response-data bytes.
    pub fn serial() -> LogicalCommand {
        read(0x32, 0)
    }
}
