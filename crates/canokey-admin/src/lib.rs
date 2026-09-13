//! Caller-owned CanoKey Admin operations and raw bootstrap builders.
//!
//! [`operation`] selects once, verifies only an explicitly supplied PIN, and
//! executes an owned [`Request`]. Configuration patches read before writing;
//! [`Outcome`] retains confirmed writes on failure through `Operation::progress`.
//! No operation stores a connection or changes the caller's immutable profile.
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

mod types;
pub use types::*;
mod execute;
pub use execute::operation;
