//! Caller-owned OATH (TOTP/HOTP) operations for CanoKey devices.
//!
//! This crate builds the OATH applet APDUs — credential management, access-code
//! validation, and one-time-code calculation — and parses the responses; your
//! application owns the transport and supplies every time challenge and fresh
//! authentication randomness. Most applications should depend on the `canokey`
//! facade crate, which re-exports this crate as `canokey::oath` and adds device
//! probing. Depend on `canokey-oath` directly only when you already hold a
//! [`DeviceProfile`](canokey_compat::DeviceProfile) and want OATH without the
//! facade.
//!
//! # Quick start: a TOTP calculation
//!
//! Every operation is an owned, caller-driven state machine: `start`/`advance`
//! return `Step` and `command` yields the APDU bytes for the caller to send.
//! The example below uses a synthetic offline transcript — no hardware — with the
//! caller supplying the TOTP time step (here `1`) as the challenge.
//!
//! ```
//! use canokey_compat::{DeviceObservations, DeviceProfile};
//! use canokey_oath::{operation, Algorithm, Format, Kind, Name, Outcome, Request};
//! use canokey_protocol::Step;
//!
//! // Synthetic observations for an offline transcript, not a hardware probe.
//! let profile =
//!     DeviceProfile::from_observations(DeviceObservations::new(b"3.1.0".to_vec()))?;
//! let mut op = operation(
//!     &profile,
//!     Request::Calculate {
//!         name: Name::from_bytes(b"test")?,
//!         kind: Kind::Totp,
//!         algorithm: Algorithm::Sha1,
//!         // Caller-supplied time step: unix_time / 30 for a 30-second period.
//!         challenge: Some(1u64.to_be_bytes()),
//!         format: Format::Truncated,
//!     },
//!     None, // No access key: the applet is unprotected in this transcript.
//!     Default::default(),
//! )?;
//! drop(profile); // The operation owns its inputs.
//!
//! // SELECT the OATH applet.
//! assert_eq!(op.start()?, Step::Exchange);
//! assert_eq!(
//!     op.command()?.as_bytes(),
//!     &[0, 0xa4, 4, 0, 7, 0xa0, 0, 0, 5, 0x27, 0x21, 1]
//! );
//! op.advance(&[0x79, 3, 6, 0, 0, 0x71, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0x90, 0])?;
//!
//! // CALCULATE for credential "test" with the time-step challenge.
//! assert_eq!(
//!     op.command()?.as_bytes(),
//!     &[
//!         0, 0xa2, 0, 1, 16, 0x71, 4, b't', b'e', b's', b't', 0x74, 8, 0, 0, 0, 0, 0, 0,
//!         0, 1,
//!     ]
//! );
//! assert_eq!(op.advance(&[0x76, 5, 6, 0, 0, 0, 42, 0x90, 0])?, Step::Done);
//!
//! let Outcome::Calculations(codes) = op.take_result()? else {
//!     unreachable!()
//! };
//! let decimal = codes[0].decimal().expect("requested a truncated code");
//! assert_eq!(decimal.as_bytes(), b"000042");
//! # Ok::<(), canokey_protocol::Error>(())
//! ```
//!
//! # Contracts
//!
//! Factories return owned operations that copy their inputs; no transport,
//! credential cache, or device state is retained, and getters never send APDUs.
//! Card status and parsing failures are retained as typed errors in the
//! operation; failed or lost responses must never be replayed automatically.
//! HOTP and increasing-TOTP state can change on calculation, so treat a
//! calculation as a mutation. The full ownership, execution, and error contracts
//! live in `docs/design/api-design.md` in the repository.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
mod types;
pub use types::*;
mod execute;
pub use execute::operation;
