//! authenticatorConfig (0x0D): persistent authenticator configuration,
//! authenticated by a pinUvAuthToken.
//!
//! Each factory returns an [`Operation`] that sends the explicit SELECT of
//! the FIDO2 application followed by one wrapped `0x0D` message. A
//! non-success CTAP status byte is classified in the Command phase with the
//! raw byte retained in `Error::application_status`; a successful response must have
//! an empty payload (any payload is [`ErrorKind::InvalidResponse`]).
//!
//! # Authentication
//!
//! Every request carries pinUvAuthProtocol (key 3) and pinUvAuthParam
//! (key 4). Unlike credentialManagement, the MAC input for config commands is
//! `0xFF * 32 || 0x0D || subCommand || cbor(subCommandParams)`, as both the
//! CTAP 2.1 specification and the CanoKey firmware require (see
//! `ctap_config` in the firmware: the 32-byte 0xFF header, the command byte
//! and the subcommand byte precede the raw subCommandParams encoding). When
//! no parameters are sent the MAC input ends after the subcommand byte. The
//! token must carry the authenticatorConfig permission
//! ([`crate::pin::Permissions::AUTHENTICATOR_CONFIG`], 0x20); obtain it with
//! [`crate::pin::get_pin_token_with_permissions`].
//!
//! # CanoKey firmware notes
//!
//! The firmware at HEAD supports exactly the three subcommands implemented
//! here; enableEnterpriseAttestation (0x01) and vendor prototype (0xFF) are
//! rejected with CTAP1_ERR_INVALID_PARAMETER (0x02, retained as
//! [`ErrorKind::UnexpectedStatusWord`]). All three subcommands are persistent
//! configuration changes stored on the device; nothing is rolled back.
//! Firmware 2.0.x accepts command 0x0D but always fails it with
//! CTAP2_ERR_UNHANDLED_REQUEST (0xF1, vendor range, also
//! [`ErrorKind::UnexpectedStatusWord`]).
//!
//! This module is available with the default `clientpin` feature, which
//! provides [`PinToken`].

use crate::cbor::{self, Value};
use crate::pin::PinToken;
use crate::{empty_payload, select_then, typed, PinUvAuthProtocol};
use canokey_protocol::{Error, ErrorKind, Operation, OperationOptions};

const COMMAND_CONFIG: u8 = 0x0d;
const SUBCOMMAND_TOGGLE_ALWAYS_UV: u8 = 0x02;
const SUBCOMMAND_SET_MIN_PIN_LENGTH: u8 = 0x03;
const SUBCOMMAND_ENABLE_LONG_TOUCH_FOR_RESET: u8 = 0x04;

/// subCommandParams key: newMinPINLength (uint).
const PARAM_NEW_MIN_PIN_LENGTH: u64 = 0x01;
/// subCommandParams key: minPinLengthRPIDs (array of text). Note the CTAP
/// 2.1 numbering: RP IDs are key 2 and forcePinChange is key 3.
const PARAM_MIN_PIN_LENGTH_RP_IDS: u64 = 0x02;
/// subCommandParams key: forcePinChange (bool).
const PARAM_FORCE_PIN_CHANGE: u64 = 0x03;

/// Minimum value the firmware accepts for newMinPINLength
/// (`CTAP_DEFAULT_MIN_PIN_LENGTH`); the factory rejects smaller values.
pub const MIN_MIN_PIN_LENGTH: u8 = 4;
/// Maximum number of RP IDs the firmware stores for setMinPINLength
/// (`CTAP_MAX_RPIDS_FOR_SET_MIN_PIN_LENGTH`).
pub const MAX_MIN_PIN_LENGTH_RP_IDS: usize = 4;

fn invalid_argument() -> Error {
    Error::new(ErrorKind::InvalidArgument)
}
fn uint(value: u64) -> Value {
    Value::Unsigned(value)
}

/// Build the complete config message: the 0x0D command byte followed by the
/// canonical CBOR map `{1: subCommand, 2?: params, 3: pinUvAuthProtocol,
/// 4: pinUvAuthParam}`.
///
/// pinUvAuthParam is `token.authenticate(protocol, 0xFF * 32 || 0x0D ||
/// subCommand || cbor(params))`; the MAC input ends after the subcommand byte
/// when no parameters are sent. This 0xFF-prefixed layout (verified against
/// the firmware's `cfg_pin_msg` construction in `ctap_config`) differs from
/// credentialManagement, whose MAC input has no 0xFF header or command byte.
fn message(
    subcommand: u8,
    params: Option<Value>,
    protocol: PinUvAuthProtocol,
    token: &PinToken,
) -> Result<Vec<u8>, Error> {
    let mut entries = vec![(uint(1), uint(u64::from(subcommand)))];
    let mut mac_input = vec![0xffu8; 32];
    mac_input.push(COMMAND_CONFIG);
    mac_input.push(subcommand);
    if let Some(params) = params {
        mac_input.extend_from_slice(&cbor::encode(&params)?);
        entries.push((uint(2), params));
    }
    entries.push((uint(3), uint(u64::from(protocol.to_u8()))));
    let auth = token.authenticate(protocol, &mac_input);
    entries.push((uint(4), Value::Bytes(auth.as_bytes().to_vec())));
    let mut message = vec![COMMAND_CONFIG];
    message.extend_from_slice(&cbor::encode(&Value::Map(entries))?);
    Ok(message)
}

/// Toggle the alwaysUv option: authenticatorConfig subcommand 0x02.
///
/// Wire format: `0x0D` followed by `{1: 0x02, 3: pinUvAuthProtocol,
/// 4: pinUvAuthParam}` (no subCommandParams; the MAC input is
/// `0xFF * 32 || 0x0D || 0x02`). The token must carry
/// [`crate::pin::Permissions::AUTHENTICATOR_CONFIG`].
///
/// **This is a persistent configuration change.** Enabling alwaysUv requires
/// user verification on every CTAP2 operation, and on CanoKey firmware it
/// disables the legacy U2F/CTAP1 interface entirely: U2F REGISTER and
/// AUTHENTICATE then fail with 6D00 ([`ErrorKind::UnsupportedFeature`], see
/// the `u2f` module). The firmware permits disabling alwaysUv without a
/// PIN when none is set, but this library always authenticates the request.
///
/// # Errors
/// A non-success CTAP status byte is classified in the Command phase (0x33
/// PIN_AUTH_INVALID maps to [`ErrorKind::AuthenticationFailed`], 0x36
/// PUAT_REQUIRED to [`ErrorKind::SecurityStatusNotSatisfied`]). A non-empty
/// successful payload is [`ErrorKind::InvalidResponse`] in [`Phase::Parsing`](canokey_protocol::Phase::Parsing).
pub fn toggle_always_uv(
    token: &PinToken,
    protocol: PinUvAuthProtocol,
    options: OperationOptions,
) -> Result<Operation<()>, Error> {
    let message = message(SUBCOMMAND_TOGGLE_ALWAYS_UV, None, protocol, token)?;
    select_then(&message, options, |response| typed(response, empty_payload))
}

/// Set the minimum PIN length: authenticatorConfig subcommand 0x03.
///
/// Wire format: `0x0D` followed by `{1: 0x03, 2: {1: newMinPINLength,
/// 2?: minPinLengthRPIDs, 3?: forcePinChange}, 3: pinUvAuthProtocol,
/// 4: pinUvAuthParam}`; the MAC input is `0xFF * 32 || 0x0D || 0x03 ||
/// cbor(subCommandParams)`. `rp_ids` is omitted from the wire map when empty,
/// as is `force_pin_change` when `None`. The token must carry
/// [`crate::pin::Permissions::AUTHENTICATOR_CONFIG`].
///
/// **This is a persistent configuration change.** The firmware rejects a
/// `new_min_pin_length` below the currently stored minimum with 0x37
/// PIN_POLICY_VIOLATION ([`ErrorKind::InvalidPin`]), so the value can only
/// grow. Increasing it above the current PIN's length (or passing
/// `force_pin_change: Some(true)`) forces a PIN change and resets all
/// pinUvAuthTokens. The RP ID list bounds which relying parties may read the
/// minimum PIN length via the minPinLength extension.
///
/// # Errors
/// Construction fails before any I/O with [`ErrorKind::InvalidArgument`] when
/// `new_min_pin_length` is below [`MIN_MIN_PIN_LENGTH`], more than
/// [`MAX_MIN_PIN_LENGTH_RP_IDS`] RP IDs are given, or an RP ID is empty.
/// Response failures follow [`toggle_always_uv`].
pub fn set_min_pin_length(
    token: &PinToken,
    protocol: PinUvAuthProtocol,
    new_min_pin_length: u8,
    force_pin_change: Option<bool>,
    rp_ids: Vec<String>,
    options: OperationOptions,
) -> Result<Operation<()>, Error> {
    if new_min_pin_length < MIN_MIN_PIN_LENGTH
        || rp_ids.len() > MAX_MIN_PIN_LENGTH_RP_IDS
        || rp_ids.iter().any(|id| id.is_empty())
    {
        return Err(invalid_argument());
    }
    let mut params = vec![(
        uint(PARAM_NEW_MIN_PIN_LENGTH),
        uint(u64::from(new_min_pin_length)),
    )];
    if !rp_ids.is_empty() {
        params.push((
            uint(PARAM_MIN_PIN_LENGTH_RP_IDS),
            Value::Array(rp_ids.into_iter().map(Value::Text).collect()),
        ));
    }
    if let Some(force_pin_change) = force_pin_change {
        params.push((uint(PARAM_FORCE_PIN_CHANGE), Value::Bool(force_pin_change)));
    }
    let message = message(
        SUBCOMMAND_SET_MIN_PIN_LENGTH,
        Some(Value::Map(params)),
        protocol,
        token,
    )?;
    select_then(&message, options, |response| typed(response, empty_payload))
}

/// Require a 30-second long touch for authenticatorReset:
/// authenticatorConfig subcommand 0x04 (CanoKey firmware 3.x).
///
/// Wire format: `0x0D` followed by `{1: 0x04, 3: pinUvAuthProtocol,
/// 4: pinUvAuthParam}` (no subCommandParams; the MAC input is
/// `0xFF * 32 || 0x0D || 0x04`). The token must carry
/// [`crate::pin::Permissions::AUTHENTICATOR_CONFIG`].
///
/// **This is a persistent configuration change.** Once enabled, a reset
/// requires holding the touch for up to 30 seconds instead of a short touch;
/// the wait loop is not skipped over NFC, so an NFC reset then always times
/// out with 0x2F USER_ACTION_TIMEOUT. There is no config subcommand to
/// disable this again; only a full authenticatorReset clears it.
///
/// # Errors
/// See [`toggle_always_uv`].
pub fn enable_long_touch_for_reset(
    token: &PinToken,
    protocol: PinUvAuthProtocol,
    options: OperationOptions,
) -> Result<Operation<()>, Error> {
    let message = message(
        SUBCOMMAND_ENABLE_LONG_TOUCH_FOR_RESET,
        None,
        protocol,
        token,
    )?;
    select_then(&message, options, |response| typed(response, empty_payload))
}
