//! Caller-owned operations for the CanoKey Admin applet: identity and
//! configuration reads, Admin PIN management, NFC/NDEF switches, and explicit
//! device and applet resets.
//!
//! This crate builds command APDUs and parses complete responses; it never
//! touches a transport, keeps no connection, and holds no global device state.
//! Most applications should depend on the `canokey` facade crate instead,
//! which probes the device and drives these operations. Depend on
//! `canokey-admin` directly only when you orchestrate the Admin conversation
//! yourself.
//!
//! # Quick start: verify the Admin PIN (offline transcript)
//!
//! ```
//! use canokey_admin::{operation, Pin, Request};
//! use canokey_compat::{DeviceObservations, DeviceProfile};
//! use canokey_protocol::{ErrorKind, SecretReference, Step};
//! // Synthetic observations for an offline transcript, not a hardware attestation.
//! let profile = DeviceProfile::from_observations(DeviceObservations::new(b"3.1.0".to_vec()))?;
//! let pin = Pin::from_bytes(b"654321")?;
//! let mut op = operation(&profile, Request::VerifyPin, Some(pin), Default::default())?;
//! drop(profile);
//! assert_eq!(op.start()?, Step::Exchange);
//! // SELECT the Admin applet.
//! assert_eq!(op.command()?.as_bytes(), &[0, 0xa4, 4, 0, 5, 0xf0, 0, 0, 0, 0]);
//! op.advance(&[0x90, 0])?;
//! // VERIFY carries the explicitly supplied PIN; nothing is tried implicitly.
//! assert_eq!(op.command()?.as_bytes(), b"\0\x20\0\0\x06654321");
//! let error = op.advance(&[0x63, 0xc2]).unwrap_err();
//! assert_eq!(error.kind, ErrorKind::AuthenticationFailed);
//! assert_eq!(error.reference, Some(SecretReference::AdminPin));
//! assert_eq!(error.retries_remaining, Some(2));
//! // Report the failure; do not retry or try a default PIN.
//! # Ok::<(), canokey_protocol::Error>(())
//! ```
//!
//! # Semantics callers must know
//!
//! The Admin PIN is always supplied explicitly by the caller; this crate never
//! tries default credentials, and authentication failures are reported with
//! their credential reference and remaining retries. Destructive requests such
//! as [`Request::FactoryReset`] and [`Request::ResetApplet`] are sent only
//! because the caller asked for them — nothing is replayed or reset
//! implicitly. [`operation`] selects the Admin applet once per operation;
//! [`Access::Existing`] instead reuses the caller's already selected and
//! authorized transaction without resending SELECT or VERIFY. Configuration
//! patches read before writing, and [`Outcome`] retains confirmed writes on
//! failure through `Operation::progress`. See `docs/design/api-design.md` in
//! the repository for the full API contracts.
//!
//! The [`command`] module is lower-level: its raw bootstrap builders do not
//! SELECT or authenticate on behalf of the caller.
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
    /// Build WRITE KBD keymap (layout id in P2, exactly 256 mapping bytes).
    pub fn write_keyboard_keymap(layout: u8, keymap: &[u8; 256]) -> LogicalCommand {
        LogicalCommand::new(
            ApduHeader::new(0, 0x45, 0, layout),
            keymap.to_vec(),
            ExpectedLength::Absent,
        )
    }
    /// Build READ KBD keymap layout-id query.
    pub fn read_keyboard_layout() -> LogicalCommand {
        read(0x46, 0)
    }
    /// Build READ KBD keymap table query.
    pub fn read_keyboard_keymap() -> LogicalCommand {
        read(0x46, 1)
    }
    /// Build CLEAR KBD keymap.
    pub fn clear_keyboard_keymap() -> LogicalCommand {
        LogicalCommand::new(
            ApduHeader::new(0, 0x47, 0, 0),
            vec![],
            ExpectedLength::Absent,
        )
    }
    /// Build READ PASS configuration (INS 43).
    pub fn pass_configuration() -> LogicalCommand {
        read(0x43, 0)
    }
    /// Build WRITE PASS configuration (INS 44).
    pub fn write_pass_configuration(data: &[u8]) -> LogicalCommand {
        LogicalCommand::new(
            ApduHeader::new(0, 0x44, 0, 0),
            data.to_vec(),
            ExpectedLength::Absent,
        )
    }
}

mod types;
pub use types::*;
mod execute;
pub use execute::{operation, operation_with_access};
