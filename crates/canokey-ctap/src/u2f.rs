//! Legacy CTAP1/U2F raw commands on the FIDO2 applet (no `clientpin` gate).
//!
//! The CanoKey firmware dispatches plain CLA-00 APDUs on the selected FIDO2
//! applet: INS 0x01 U2F REGISTER, INS 0x02 U2F AUTHENTICATE and INS 0x03 U2F
//! VERSION (INS 0xA4 is the applet SELECT, already covered by the envelope).
//! These are *not* `80 10`-wrapped CTAP messages and their responses carry no
//! CTAP status byte: the response is raw U2F data plus an ISO 7816 status
//! word, so status classification here uses the ISO layer, not
//! `CtapStatus::into_error`.
//!
//! Each factory returns an [`Operation`] that sends the explicit SELECT of
//! the FIDO2 application (re-SELECT is idempotent) followed by one CLA-00
//! command. Large REGISTER responses (the attestation certificate) are
//! reassembled through 61xx continuation with GET RESPONSE using class byte
//! 0; the firmware accepts both class bytes for GET RESPONSE. No Le byte is
//! sent: the firmware's APDU layer treats absent Le as 256 and streams the
//! remainder via 61xx, and U2F APDUs cannot be chained (the firmware only
//! chains CLA-80 CTAP messages), so command chaining and extended encoding
//! stay disabled.
//!
//! # CanoKey firmware notes
//!
//! - When alwaysUv is enabled (see the `config` module, feature
//!   `clientpin`), REGISTER and AUTHENTICATE are rejected with 6D00, which
//!   the generic ISO status mapping classifies as
//!   [`ErrorKind::UnsupportedFeature`]. VERSION still answers.
//! - Over USB both REGISTER and AUTHENTICATE (with
//!   [`CONTROL_ENFORCE_USER_PRESENCE_AND_SIGN`]) require a touch; a timeout
//!   or cancel surfaces as 6985 ([`ErrorKind::ConditionsNotSatisfied`]).
//!   Over NFC the firmware skips the touch requirement.
//! - CanoKey key handles are 70-byte `credential_id` structures bound to the
//!   application ID; a key handle from another authenticator (or an app ID
//!   mismatch) fails with 6A80, retained raw as
//!   [`ErrorKind::UnexpectedStatusWord`].
//!
//! U2F is the legacy protocol: no resident keys, no PIN, no CTAP2 CBOR.

use crate::command;
use canokey_protocol::operation::engine::{Action, Machine};
use canokey_protocol::operation::{validate_command, LogicalCommand, ResponseData};
use canokey_protocol::{
    ApduHeader, Error, ErrorKind, ExpectedLength, Operation, OperationOptions, Phase,
};

/// U2F REGISTER instruction byte (0x01).
const INS_REGISTER: u8 = 0x01;
/// U2F AUTHENTICATE instruction byte (0x02).
const INS_AUTHENTICATE: u8 = 0x02;
/// U2F VERSION instruction byte (0x03).
const INS_VERSION: u8 = 0x03;

/// U2F AUTHENTICATE control byte (P1): enforce user presence and sign (0x03).
pub const CONTROL_ENFORCE_USER_PRESENCE_AND_SIGN: u8 = 0x03;
/// U2F AUTHENTICATE control byte (P1): check-only (0x07). A valid key handle
/// is answered with 6985 *by design*; see [`check_only`].
pub const CONTROL_CHECK_ONLY: u8 = 0x07;
/// U2F AUTHENTICATE control byte (P1): sign without enforcing user presence
/// (0x08). Not used by this module's factories; the CanoKey firmware accepts
/// it over NFC where touch is skipped.
pub const CONTROL_DONT_ENFORCE_USER_PRESENCE: u8 = 0x08;

/// The version string returned by U2F VERSION: `U2F_V2`.
pub const U2F_VERSION_V2: &[u8; 6] = b"U2F_V2";

/// REGISTER response reserved byte (0x05), per the U2F raw message spec.
const REGISTER_RESERVED: u8 = 0x05;
/// SEC1 uncompressed-point tag expected at the start of the public key.
const SEC1_UNCOMPRESSED: u8 = 0x04;
/// Fixed request prefix: challenge (32) || application (32).
const FIXED_REQUEST_LEN: usize = 64;
/// Maximum key handle length accepted by [`authenticate`] and
/// [`check_only`]: the 65-byte authenticate request prefix plus the handle
/// must fit one short APDU (Lc at most 255, no chaining on CLA-00), and
/// CanoKey handles are 70 bytes.
pub const MAX_KEY_HANDLE_LEN: usize = 190;

fn invalid() -> Error {
    Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing)
}
fn invalid_argument() -> Error {
    Error::new(ErrorKind::InvalidArgument)
}

/// Build one plain CLA-00 U2F logical command with no Le.
///
/// Defaults apply: no chaining or extended encoding (the firmware cannot
/// chain CLA-00 APDUs), ISO 7816 continuation via GET RESPONSE with class
/// byte 0 for 61xx responses.
fn u2f_command(ins: u8, p1: u8, data: Vec<u8>) -> LogicalCommand {
    LogicalCommand::new(
        ApduHeader::new(0x00, ins, p1, 0x00),
        data,
        ExpectedLength::Absent,
    )
}

type Parser<T> = Box<dyn FnOnce(ResponseData) -> Result<T, Error> + Send>;

/// SELECT FIDO2 (phase Select), then one CLA-00 command (phase Command).
struct SelectThen<T> {
    command: Option<LogicalCommand>,
    parse: Option<Parser<T>>,
}
impl<T> Machine<T> for SelectThen<T> {
    fn next(&mut self, response: Option<ResponseData>) -> Result<Action<T>, Error> {
        match response {
            None => Ok(Action::Command(command::select())),
            Some(response) => match self.command.take() {
                Some(command) => {
                    response.ensure_success(Phase::Select)?;
                    Ok(Action::Command(command))
                }
                None => {
                    let parse = self
                        .parse
                        .take()
                        .ok_or_else(|| Error::new(ErrorKind::OperationStateError))?;
                    Ok(Action::Done(parse(response)?))
                }
            },
        }
    }
}

fn operation<T: 'static>(
    command: LogicalCommand,
    options: OperationOptions,
    parse: impl FnOnce(ResponseData) -> Result<T, Error> + Send + 'static,
) -> Result<Operation<T>, Error> {
    let options = options.validate()?;
    validate_command(&command::select(), options)?;
    validate_command(&command, options)?;
    Operation::from_machine(
        SelectThen {
            command: Some(command),
            parse: Some(Box::new(parse)),
        },
        options,
    )
}

/// Input to [`register`]: the challenge and application parameter, copied at
/// construction. Neither is secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct U2fRegisterRequest {
    /// The 32-byte challenge parameter (client data hash).
    pub challenge: [u8; 32],
    /// The 32-byte application parameter (SHA-256 of the app ID).
    pub application: [u8; 32],
}

/// Input to [`authenticate`] and [`check_only`], copied at construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct U2fAuthenticateRequest {
    /// The 32-byte challenge parameter (client data hash).
    pub challenge: [u8; 32],
    /// The 32-byte application parameter (SHA-256 of the app ID).
    pub application: [u8; 32],
    /// The key handle from a previous [`register`], 1..=[`MAX_KEY_HANDLE_LEN`]
    /// bytes. CanoKey handles are 70 bytes and bound to `application`.
    pub key_handle: Vec<u8>,
}

/// The parsed U2F REGISTER response.
///
/// `certificate` is the raw DER attestation certificate: it is length-framed
/// only, not validated — certificate validity, identity, trust and
/// attestation policy remain the caller's (see the workspace certificate
/// rule). `signature` is the DER ECDSA signature over
/// `0x00 || application || challenge || key_handle || user_public_key`.
/// `raw` preserves the complete response data. Key handles, certificates and
/// signatures are not secret; Debug is not redacted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct U2fRegistration {
    /// The user public key, SEC1 uncompressed SEC P-256 (0x04 || X || Y).
    pub user_public_key: [u8; 65],
    /// The generated key handle.
    pub key_handle: Vec<u8>,
    /// The raw DER attestation certificate, unvalidated.
    pub certificate: Vec<u8>,
    /// The raw DER attestation signature.
    pub signature: Vec<u8>,
    /// The complete raw response data (reserved byte through signature).
    pub raw: Vec<u8>,
}

/// The parsed U2F AUTHENTICATE (sign) response.
///
/// The signature is the DER ECDSA signature over
/// `application || user_presence || counter (BE) || challenge`; `counter` is
/// the big-endian 32-bit sign counter. None of these are secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct U2fAuthentication {
    /// The user-presence byte (bit 0 set when the user confirmed presence).
    pub user_presence: u8,
    /// The big-endian 32-bit signature counter.
    pub counter: u32,
    /// The raw DER signature.
    pub signature: Vec<u8>,
}

/// Total length of a DER SEQUENCE starting at `bytes[0]`, header included.
/// Only the outer length frame is read; the contents are not inspected.
fn der_sequence_len(bytes: &[u8]) -> Result<usize, Error> {
    if bytes.len() < 2 || bytes[0] != 0x30 {
        return Err(invalid());
    }
    let first = bytes[1];
    if first & 0x80 == 0 {
        return Ok(2 + usize::from(first));
    }
    let count = usize::from(first & 0x7f);
    // A certificate length never needs more than two length bytes.
    if count == 0 || count > 2 || bytes.len() < 2 + count {
        return Err(invalid());
    }
    let mut len = 0usize;
    for &byte in &bytes[2..2 + count] {
        len = (len << 8) | usize::from(byte);
    }
    Ok(2 + count + len)
}

/// Parse `0x05 || pubkey[65] || khLen[1] || keyHandle || cert(DER) || sig`.
/// The key-handle length byte bounds the variable split; the DER length
/// frame of the certificate separates it from the trailing signature.
fn parse_registration(bytes: &[u8]) -> Result<U2fRegistration, Error> {
    if bytes.len() < FIXED_REQUEST_LEN + 3
        || bytes[0] != REGISTER_RESERVED
        || bytes[1] != SEC1_UNCOMPRESSED
    {
        return Err(invalid());
    }
    let user_public_key: [u8; 65] = bytes[1..66].try_into().map_err(|_| invalid())?;
    let key_handle_len = usize::from(bytes[66]);
    let rest = &bytes[67..];
    if key_handle_len == 0 || rest.len() < key_handle_len {
        return Err(invalid());
    }
    let key_handle = rest[..key_handle_len].to_vec();
    let rest = &rest[key_handle_len..];
    let cert_len = der_sequence_len(rest)?;
    if cert_len > rest.len() {
        return Err(invalid());
    }
    let certificate = rest[..cert_len].to_vec();
    let signature = rest[cert_len..].to_vec();
    if signature.is_empty() {
        return Err(invalid());
    }
    Ok(U2fRegistration {
        user_public_key,
        key_handle,
        certificate,
        signature,
        raw: bytes.to_vec(),
    })
}

/// Parse `userPresence[1] || counter[4 BE] || signature`.
fn parse_authentication(bytes: &[u8]) -> Result<U2fAuthentication, Error> {
    if bytes.len() < 6 {
        return Err(invalid());
    }
    let counter = u32::from_be_bytes(bytes[1..5].try_into().map_err(|_| invalid())?);
    Ok(U2fAuthentication {
        user_presence: bytes[0],
        counter,
        signature: bytes[5..].to_vec(),
    })
}

fn authenticate_data(request: &U2fAuthenticateRequest) -> Result<Vec<u8>, Error> {
    if request.key_handle.is_empty() || request.key_handle.len() > MAX_KEY_HANDLE_LEN {
        return Err(invalid_argument());
    }
    let mut data = Vec::with_capacity(FIXED_REQUEST_LEN + 1 + request.key_handle.len());
    data.extend_from_slice(&request.challenge);
    data.extend_from_slice(&request.application);
    data.push(request.key_handle.len() as u8);
    data.extend_from_slice(&request.key_handle);
    Ok(data)
}

/// Register a new U2F credential: CLA-00 INS 0x01, P1 = P2 = 0.
///
/// Wire format: `00 01 00 00 40 challenge[32] || application[32]` (Lc exactly
/// 64, no Le). The response is `0x05 || pubkey[65] || khLen[1] || keyHandle
/// || attestation certificate (DER) || signature (DER)`, parsed into
/// [`U2fRegistration`]; responses larger than one frame are reassembled
/// through 61xx continuation.
///
/// Over USB this requires a touch; timeout or cancel surfaces as 6985
/// ([`ErrorKind::ConditionsNotSatisfied`]). NFC skips the touch. With
/// alwaysUv enabled the firmware rejects REGISTER with 6D00
/// ([`ErrorKind::UnsupportedFeature`]).
///
/// # Errors
/// Construction fails before I/O only on invalid options. Response failures:
/// 6985 → [`ErrorKind::ConditionsNotSatisfied`], 6D00 →
/// [`ErrorKind::UnsupportedFeature`], other statuses retained raw as
/// [`ErrorKind::UnexpectedStatusWord`]. A truncated response, a reserved byte
/// other than 0x05, a non-SEC1 public key, or a malformed certificate length
/// frame fails as [`ErrorKind::InvalidResponse`] in [`Phase::Parsing`].
pub fn register(
    request: U2fRegisterRequest,
    options: OperationOptions,
) -> Result<Operation<U2fRegistration>, Error> {
    let mut data = Vec::with_capacity(FIXED_REQUEST_LEN);
    data.extend_from_slice(&request.challenge);
    data.extend_from_slice(&request.application);
    operation(u2f_command(INS_REGISTER, 0x00, data), options, |response| {
        response.ensure_success(Phase::Command)?;
        parse_registration(response.data.as_bytes())
    })
}

/// Authenticate (sign) with a U2F credential: CLA-00 INS 0x02 with P1
/// [`CONTROL_ENFORCE_USER_PRESENCE_AND_SIGN`].
///
/// Wire format: `00 02 03 00 <Lc> challenge[32] || application[32] ||
/// khLen[1] || keyHandle` (no Le). The response is `userPresence[1] ||
/// counter[4 BE] || signature (DER)`, parsed into [`U2fAuthentication`]. The
/// signature covers `application || user_presence || counter || challenge`.
///
/// Over USB this requires a touch; timeout or cancel surfaces as 6985
/// ([`ErrorKind::ConditionsNotSatisfied`]). An unknown key handle or an app
/// ID mismatch fails with 6A80 (retained raw as
/// [`ErrorKind::UnexpectedStatusWord`]); a handle whose length byte does not
/// match the firmware's 70-byte `credential_id` fails with 6700 (also
/// [`ErrorKind::UnexpectedStatusWord`]). With alwaysUv enabled the firmware
/// rejects AUTHENTICATE with 6D00 ([`ErrorKind::UnsupportedFeature`]).
///
/// # Errors
/// An empty key handle or one longer than [`MAX_KEY_HANDLE_LEN`] fails as
/// [`ErrorKind::InvalidArgument`] before any I/O. Response failures follow
/// [`register`]; a response shorter than 6 bytes fails as
/// [`ErrorKind::InvalidResponse`] in [`Phase::Parsing`].
pub fn authenticate(
    request: U2fAuthenticateRequest,
    options: OperationOptions,
) -> Result<Operation<U2fAuthentication>, Error> {
    let data = authenticate_data(&request)?;
    operation(
        u2f_command(
            INS_AUTHENTICATE,
            CONTROL_ENFORCE_USER_PRESENCE_AND_SIGN,
            data,
        ),
        options,
        |response| {
            response.ensure_success(Phase::Command)?;
            parse_authentication(response.data.as_bytes())
        },
    )
}

/// Check whether a key handle is valid for an application without signing:
/// CLA-00 INS 0x02 with P1 [`CONTROL_CHECK_ONLY`].
///
/// Wire format matches [`authenticate`]. Per the U2F specification the
/// authenticator answers a *valid* handle with 6985 ("conditions not
/// satisfied" — valid but no signature by design), which this operation maps
/// to `Ok(true)`; this is the one case where 6985 is not an error. An
/// invalid handle or app ID mismatch fails with 6A80, retained raw as
/// [`ErrorKind::UnexpectedStatusWord`]: note it is an error here, not
/// `Ok(false)`. The firmware never answers check-only with success; a 9000
/// response fails as [`ErrorKind::InvalidResponse`].
///
/// # Errors
/// Input validation matches [`authenticate`]. Every status word except 6985
/// is classified normally by the ISO layer.
pub fn check_only(
    request: U2fAuthenticateRequest,
    options: OperationOptions,
) -> Result<Operation<bool>, Error> {
    let data = authenticate_data(&request)?;
    operation(
        u2f_command(INS_AUTHENTICATE, CONTROL_CHECK_ONLY, data),
        options,
        |response| {
            // 6985 is the U2F check-only "valid handle" answer by design.
            if response.status.raw() == 0x6985 {
                return Ok(true);
            }
            response.ensure_success(Phase::Command)?;
            Err(invalid())
        },
    )
}

/// Query the U2F version: CLA-00 INS 0x03 with no command data.
///
/// Wire format: `00 03 00 00` (no Lc, no Le). The firmware answers exactly
/// `U2F_V2` (even with alwaysUv enabled); the raw bytes are validated against
/// [`U2F_VERSION_V2`] and returned for the caller to compare or display.
///
/// # Errors
/// A response other than exactly `U2F_V2` fails as
/// [`ErrorKind::InvalidResponse`] in [`Phase::Parsing`]. Status-word failures
/// follow [`register`].
pub fn version(options: OperationOptions) -> Result<Operation<Vec<u8>>, Error> {
    operation(
        u2f_command(INS_VERSION, 0x00, Vec::new()),
        options,
        |response| {
            response.ensure_success(Phase::Command)?;
            let bytes = response.data.as_bytes();
            if bytes != U2F_VERSION_V2 {
                return Err(invalid());
            }
            Ok(bytes.to_vec())
        },
    )
}
