//! CanoKey's caller-owned, transport-free host protocol library.
//!
//! Most applications depend on this facade. [`piv`] provides semantic PIV factories,
//! [`compatibility`] owns firmware/capability rules, and [`apdu`]/[`tlv`] expose
//! low-level codecs. [`admin`] currently contains bootstrap command builders only.
//! C consumers use the separate `canokey-c` crate; a Rust/FRB wrapper uses this crate
//! directly. No layer here owns a transport, runtime, or mutable global state.
//! The optional `x509` feature adds owned DER/PEM certificate inspection; `serde`
//! additionally enables serialization of its results. Neither is enabled by default.
//!
//! # Quick start: offline probe
//!
//! The application owns the operation and drives every exchange. This deterministic
//! example checks the emitted commands; replace each fixture lookup with one raw
//! application transport call. Hold the device lock across the entire loop and keep
//! SW1/SW2 in the response. Do not let the transport also process continuation.
//!
//! ```
//! use canokey::{probe_device, ProbeMode, ProbeOptions, Step};
//! let transcript: &[(&[u8], &[u8])] = &[
//!     (&[0, 0xa4, 4, 0, 5, 0xf0, 0, 0, 0, 0], &[0x90, 0]),
//!     (&[0, 0x31, 0, 0, 0], b"3.1.0\x90\x00"),
//!     (&[0, 0x31, 1, 0, 0], b"CanoKey\x90\x00"),
//!     (&[0, 0x32, 0, 0, 0], &[1, 2, 3, 4, 0x90, 0]),
//! ];
//! let mut op = probe_device(ProbeOptions {
//!     mode: ProbeMode::Minimal, ..Default::default()
//! })?;
//! let mut step = op.start()?;
//! for &(command, response) in transcript {
//!     assert_eq!(step, Step::Exchange);
//!     assert_eq!(op.command()?.as_bytes(), command);
//!     step = op.advance(response)?;
//! }
//! assert_eq!(step, Step::Done);
//! let profile = op.take_result()?;
//! drop(op); // The profile is independent.
//! assert_eq!(profile.info().firmware_text(), b"3.1.0");
//! # Ok::<(), canokey::Error>(())
//! ```
//!
//! Use [`ProbeMode::Piv`] (the default) before constructing PIV operations. Minimal
//! probe does not observe the PIV applet and therefore leaves that capability unknown.
//! Transport failures are application errors: drop the operation and drain or isolate
//! pending I/O before releasing the connection. Drop/cancel do not send logout or
//! roll back card effects. See [`Operation`] for the complete lifecycle contract.
//!
#![deny(missing_docs)]
#![forbid(unsafe_code)]
pub use canokey_admin as admin;
pub use canokey_compat as compatibility;
pub use canokey_compat::DeviceProfile;
pub use canokey_piv as piv;
pub use canokey_protocol::{apdu, tlv};
pub use canokey_protocol::{
    Error, ErrorKind, ExchangeOptions, Operation, OperationLimits, OperationOptions,
    OperationState, SecretBytes, Step,
};
/// Optional, transport-free X.509 inspection (`x509` feature).
#[cfg(feature = "x509")]
pub use x509_info as x509;
mod probe;
pub use probe::{probe_device, ProbeMode, ProbeOptions};
