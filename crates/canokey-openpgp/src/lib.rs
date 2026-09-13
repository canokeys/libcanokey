//! OpenPGP operations with caller-owned passwords, profiles and results.
//!
//! [`operation`] selects once, optionally verifies one explicit password reference,
//! and runs an owned request. PW1-sign and PW1-other are distinct authorization
//! modes. Key operations read algorithm attributes before interpreting key bytes;
//! they never silently change attributes, fingerprints or timestamps.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
pub use canokey_compat::Algorithm;
pub use canokey_key::PublicKey;
mod types;
pub use types::*;
mod execute;
pub use execute::operation;
mod data;
mod keys;
pub use data::*;
