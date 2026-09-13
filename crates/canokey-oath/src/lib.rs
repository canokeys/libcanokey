//! Caller-owned OATH credentials, access validation and calculations.
//!
//! The application supplies time challenges and fresh authentication randomness.
//! [`operation`] selects once, parses its challenge and validates an explicit access
//! key before its target. HOTP and increasing TOTP state can change on calculation;
//! failed or lost responses must never trigger automatic replay.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
mod types;
pub use types::*;
mod execute;
pub use execute::operation;
