//! OpenPGP card applet operations: data objects, passwords, policies and keys.
//!
//! This crate builds complete OpenPGP command APDUs and parses complete
//! responses (data plus status words) for the CanoKey OpenPGP applet. It owns
//! no transport, connection, runtime or credential cache: the caller sends each
//! command, returns each response, and holds the connection exclusively until
//! the operation finishes. Depend on this crate directly when you compose your
//! own device probing or need the OpenPGP-specific types; most applications
//! should use the `canokey` facade crate, which probes the device, builds the
//! compatibility profile and re-exports this API.
//!
//! # Quick start: explicit PW1 verification
//!
//! [`operation`] returns an owned [`Operation`](canokey_protocol::Operation).
//! This example verifies PW1 in signature mode against a synthetic offline
//! transcript; on hardware, replace the canned responses with real transport
//! exchanges.
//!
//! ```
//! use canokey_compat::{DeviceObservations, DeviceProfile};
//! use canokey_openpgp::{operation, Access, Outcome, Password, PasswordReference, Request};
//! use canokey_protocol::Step;
//! // Synthetic observations for an offline transcript, not a hardware attestation.
//! let observed = DeviceObservations::new(b"3.1.0".to_vec());
//! let profile = DeviceProfile::from_observations(observed)?;
//! let mut op = operation(
//!     &profile,
//!     Request::Verify,
//!     Some(Access {
//!         reference: PasswordReference::Pw1Sign,
//!         password: Password::from_bytes(b"87654321")?,
//!     }),
//!     Default::default(),
//! )?;
//! drop(profile);
//! assert_eq!(op.start()?, Step::Exchange);
//! // SELECT the OpenPGP applet.
//! assert_eq!(
//!     op.command()?.as_bytes(),
//!     &[0, 0xa4, 4, 0, 6, 0xd2, 0x76, 0, 1, 0x24, 1]
//! );
//! assert_eq!(op.advance(&[0x90, 0])?, Step::Exchange);
//! // VERIFY with reference 81 (PW1 for signing).
//! assert_eq!(
//!     op.command()?.as_bytes(),
//!     &[0, 0x20, 0, 0x81, 8, b'8', b'7', b'6', b'5', b'4', b'3', b'2', b'1']
//! );
//! assert_eq!(op.advance(&[0x90, 0])?, Step::Done);
//! assert!(matches!(op.take_result()?, Outcome::Unit));
//! # Ok::<(), canokey_protocol::Error>(())
//! ```
//!
//! # Semantics callers must know
//!
//! - PW1 has two independent authorization modes: [`PasswordReference::Pw1Sign`]
//!   for COMPUTE DIGITAL SIGNATURE and [`PasswordReference::Pw1Other`] for
//!   decipher and INTERNAL AUTHENTICATE. Verifying one mode never authorizes
//!   the other.
//! - Password verification is always explicit through [`Access`]. Operations
//!   requiring authorization fail at construction when the required reference
//!   is missing, and no default password is ever tried.
//! - Failed or interrupted operations are never retried or replayed
//!   automatically; a reported retry count is data for the caller, not a cue
//!   to resubmit.
//!
//! The full ownership, execution and error contracts live in
//! `docs/design/api-design.md` in the repository.
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
