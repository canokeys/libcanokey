//! authenticatorCredentialManagement (0x0A): resident-credential inventory
//! and maintenance, authenticated by a pinUvAuthToken.
//!
//! Each factory returns an [`Operation`] that sends the explicit SELECT of
//! the FIDO2 application followed by one or more wrapped `0x0A` messages.
//! A non-success CTAP status byte is classified in the Command phase with
//! the raw byte retained in `Error::application_status`, with one exception: a
//! 0x2E NO_CREDENTIALS status on an enumeration Begin subcommand means "no
//! credentials/RPs at all" and yields an empty result vector rather than an
//! error.
//!
//! # Authentication
//!
//! Every request carries pinUvAuthProtocol (key 3). Every subcommand except
//! the GetNext variants (0x03, 0x05) also carries pinUvAuthParam (key 4),
//! computed as `token.authenticate(protocol, [subCommand] ||
//! cbor(subCommandParams))`; when no parameters are sent the MAC input is
//! just the one subcommand byte. The GetNext subcommands send neither
//! parameters nor pinUvAuthParam. The token must carry the
//! credentialManagement permission (0x04); obtain it with
//! [`crate::pin::get_pin_token_with_permissions`].
//!
//! # Enumeration
//!
//! [`enumerate_rps`] and [`enumerate_credentials`] run the whole
//! Begin/GetNext sequence inside a single operation: the caller drives one
//! [`Operation`] and receives the complete vector. The number of GetNext
//! calls is bounded by the authenticator-reported total *and* by the
//! operation's exchange budget (`limits.max_exchanges` minus the SELECT and
//! Begin exchanges); a device reporting an absurd total fails as
//! [`ErrorKind::LimitExceeded`] instead of looping unbounded.
//!
//! # CanoKey metadata-only extension
//!
//! [`enumerate_credentials`] supports the CanoKey vendor extension
//! `metadataOnly` (subCommandParams key 0x80): the authenticator then omits
//! publicKey (response key 8) and returns the raw COSE algorithm identifier
//! under response key 0x80 instead, which keeps responses small enough for
//! ML-DSA credentials. This is not part of the CTAP2 specification; the
//! caller is responsible for knowing the authenticator supports it. A
//! response must carry exactly one of the two forms — both or neither is
//! [`ErrorKind::InvalidResponse`].
//!
//! # CanoKey firmware notes
//!
//! The legacy preview command 0x41 maps onto the same handler; this module
//! only emits the standardized 0x0A. An unknown credentialManagement
//! subcommand is a firmware quirk that returns empty success, so response
//! parsers always require their mandatory fields.
//!
//! This module is available with the default `clientpin` feature, which
//! provides [`PinToken`].

use crate::cbor::{self, Value};
use crate::cose::CoseKey;
use crate::ctap2::{PublicKeyCredentialDescriptor, RelyingParty, UserEntity, MAX_USER_ID_LEN};
use crate::pin::PinToken;
use crate::status::CtapStatus;
use crate::{command, empty_payload, invalid, required, select_then, typed, PinUvAuthProtocol};
use canokey_protocol::operation::engine::{Action, Machine};
use canokey_protocol::operation::{validate_command, ResponseData};
use canokey_protocol::{Error, ErrorKind, Operation, OperationOptions, Phase, SecretBytes};
use std::fmt;

const COMMAND_CREDENTIAL_MANAGEMENT: u8 = 0x0a;
const SUBCOMMAND_GET_CREDS_METADATA: u8 = 0x01;
const SUBCOMMAND_ENUMERATE_RPS_BEGIN: u8 = 0x02;
const SUBCOMMAND_ENUMERATE_RPS_GET_NEXT: u8 = 0x03;
const SUBCOMMAND_ENUMERATE_CREDENTIALS_BEGIN: u8 = 0x04;
const SUBCOMMAND_ENUMERATE_CREDENTIALS_GET_NEXT: u8 = 0x05;
const SUBCOMMAND_DELETE_CREDENTIAL: u8 = 0x06;
const SUBCOMMAND_UPDATE_USER_INFORMATION: u8 = 0x07;

/// subCommandParams key: rpIdHash (32 bytes).
const PARAM_RP_ID_HASH: u64 = 0x01;
/// subCommandParams key: credentialID (PublicKeyCredentialDescriptor map).
const PARAM_CREDENTIAL_ID: u64 = 0x02;
/// subCommandParams key: user (PublicKeyCredentialUserEntity map).
const PARAM_USER: u64 = 0x03;
/// subCommandParams key: metadataOnly (bool) — CanoKey vendor extension.
const PARAM_METADATA_ONLY: u64 = 0x80;

/// Response key: existingResidentCredentialsCount.
const RESPONSE_EXISTING_COUNT: i64 = 0x01;
/// Response key: maxPossibleRemainingResidentCredentialsCount.
const RESPONSE_REMAINING_COUNT: i64 = 0x02;
/// Response key: rp (PublicKeyCredentialRpEntity map).
const RESPONSE_RP: i64 = 0x03;
/// Response key: rpIDHash (32 bytes).
const RESPONSE_RP_ID_HASH: i64 = 0x04;
/// Response key: totalRPs (Begin only).
const RESPONSE_TOTAL_RPS: i64 = 0x05;
/// Response key: user (PublicKeyCredentialUserEntity map).
const RESPONSE_USER: i64 = 0x06;
/// Response key: credentialID (PublicKeyCredentialDescriptor map).
const RESPONSE_CREDENTIAL_ID: i64 = 0x07;
/// Response key: publicKey (COSE_Key map); absent in metadata-only mode.
const RESPONSE_PUBLIC_KEY: i64 = 0x08;
/// Response key: totalCredentials (Begin only).
const RESPONSE_TOTAL_CREDENTIALS: i64 = 0x09;
/// Response key: credProtect (uint).
const RESPONSE_CRED_PROTECT: i64 = 0x0a;
/// Response key: largeBlobKey (bytes).
const RESPONSE_LARGE_BLOB_KEY: i64 = 0x0b;
/// Response key: coseAlgorithm (int) — CanoKey vendor extension.
const RESPONSE_COSE_ALGORITHM: i64 = 0x80;

/// CTAP2_ERR_NO_CREDENTIALS: an empty enumeration, not an error.
const STATUS_NO_CREDENTIALS: u8 = 0x2e;

fn invalid_argument() -> Error {
    Error::new(ErrorKind::InvalidArgument)
}
fn uint(value: u64) -> Value {
    Value::Unsigned(value)
}

fn opt<T>(
    map: &Value,
    key: i64,
    parse: impl FnOnce(&Value) -> Result<T, Error>,
) -> Result<Option<T>, Error> {
    map.map_get_int(key).map(parse).transpose()
}

/// Build the complete credentialManagement message: the 0x0A command byte
/// followed by the canonical CBOR map `{1: subCommand, 2?: params,
/// 3: pinUvAuthProtocol, 4?: pinUvAuthParam}`.
///
/// pinUvAuthProtocol (key 3) is always sent. When `token` is `Some`,
/// pinUvAuthParam (key 4) is `token.authenticate(protocol, [subCommand] ||
/// cbor(params))`; the MAC input is just the one subcommand byte when no
/// parameters are sent. The GetNext subcommands pass `None` for both
/// `params` and `token`.
fn message(
    subcommand: u8,
    params: Option<Value>,
    protocol: PinUvAuthProtocol,
    token: Option<&PinToken>,
) -> Result<Vec<u8>, Error> {
    let mut entries = vec![(uint(1), uint(u64::from(subcommand)))];
    let mut mac_input = vec![subcommand];
    if let Some(params) = params {
        mac_input.extend_from_slice(&cbor::encode(&params)?);
        entries.push((uint(2), params));
    }
    entries.push((uint(3), uint(u64::from(protocol.to_u8()))));
    if let Some(token) = token {
        let auth = token.authenticate(protocol, &mac_input);
        entries.push((uint(4), Value::Bytes(auth.as_bytes().to_vec())));
    }
    let mut message = vec![COMMAND_CREDENTIAL_MANAGEMENT];
    message.extend_from_slice(&cbor::encode(&Value::Map(entries))?);
    Ok(message)
}

fn descriptor_value(descriptor: &PublicKeyCredentialDescriptor) -> Value {
    let mut entries = vec![
        (
            Value::Text("type".to_owned()),
            Value::Text(descriptor.type_.clone()),
        ),
        (
            Value::Text("id".to_owned()),
            Value::Bytes(descriptor.id.clone()),
        ),
    ];
    if !descriptor.transports.is_empty() {
        entries.push((
            Value::Text("transports".to_owned()),
            Value::Array(
                descriptor
                    .transports
                    .iter()
                    .map(|t| Value::Text(t.clone()))
                    .collect(),
            ),
        ));
    }
    Value::Map(entries)
}

fn user_value(user: &UserEntity) -> Value {
    let mut entries = vec![(Value::Text("id".to_owned()), Value::Bytes(user.id.clone()))];
    if let Some(name) = &user.name {
        entries.push((Value::Text("name".to_owned()), Value::Text(name.clone())));
    }
    if let Some(display_name) = &user.display_name {
        entries.push((
            Value::Text("displayName".to_owned()),
            Value::Text(display_name.clone()),
        ));
    }
    Value::Map(entries)
}

fn parse_descriptor(value: &Value) -> Result<PublicKeyCredentialDescriptor, Error> {
    let type_ = required(value.map_get_text("type"))?
        .as_text()
        .ok_or_else(invalid)?
        .to_owned();
    let id = required(value.map_get_text("id"))?
        .as_bytes()
        .ok_or_else(invalid)?
        .to_vec();
    let transports = match value.map_get_text("transports") {
        None => Vec::new(),
        Some(list) => list
            .as_array()
            .ok_or_else(invalid)?
            .iter()
            .map(|item| item.as_text().map(str::to_owned).ok_or_else(invalid))
            .collect::<Result<_, _>>()?,
    };
    Ok(PublicKeyCredentialDescriptor {
        type_,
        id,
        transports,
    })
}

fn parse_user(value: &Value) -> Result<UserEntity, Error> {
    let id = required(value.map_get_text("id"))?
        .as_bytes()
        .ok_or_else(invalid)?
        .to_vec();
    let name = match value.map_get_text("name") {
        None => None,
        Some(v) => Some(v.as_text().ok_or_else(invalid)?.to_owned()),
    };
    let display_name = match value.map_get_text("displayName") {
        None => None,
        Some(v) => Some(v.as_text().ok_or_else(invalid)?.to_owned()),
    };
    Ok(UserEntity {
        id,
        name,
        display_name,
    })
}

/// The resident-credential counters reported by getCredsMetadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredsMetadata {
    /// Number of discoverable credentials currently stored (response key 1).
    pub existing_resident_credentials_count: u64,
    /// Maximum number of additional discoverable credentials the
    /// authenticator estimates it can store (response key 2).
    pub max_possible_remaining_resident_credentials_count: u64,
}

/// One relying party from [`enumerate_rps`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpEntry {
    /// The relying party entity (response key 3): `id` is required, `name`
    /// optional.
    pub rp: RelyingParty,
    /// The SHA-256 hash of the relying party ID (response key 4), usable as
    /// the `rp_id_hash` argument of [`enumerate_credentials`].
    pub rp_id_hash: [u8; 32],
}

/// One credential from [`enumerate_credentials`].
///
/// Exactly one of `public_key` (response key 8) and `cose_algorithm`
/// (response key 0x80, the CanoKey metadata-only extension) is present;
/// both or neither is a protocol violation. `large_blob_key` is
/// credential-adjacent key material: redacted in Debug and zeroized on drop.
#[derive(Clone)]
pub struct CredentialEntry {
    /// The user entity (response key 6) when the authenticator sent one.
    pub user: Option<UserEntity>,
    /// The credential descriptor (response key 7, required).
    pub credential_id: PublicKeyCredentialDescriptor,
    /// The credential public key (response key 8) in standard mode.
    pub public_key: Option<CoseKey>,
    /// The credential protection policy (response key 10) when reported.
    pub cred_protect: Option<u64>,
    /// The credential's largeBlobKey (response key 11) when present.
    /// Redacted in Debug and zeroized on drop.
    pub large_blob_key: Option<SecretBytes>,
    /// The raw COSE algorithm identifier (response key 0x80) in the CanoKey
    /// metadata-only mode, for example -7 for ES256 or -49 for ML-DSA-65.
    pub cose_algorithm: Option<i64>,
}
impl fmt::Debug for CredentialEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialEntry")
            .field("user", &self.user)
            .field("credential_id", &self.credential_id)
            .field("public_key", &self.public_key)
            .field("cred_protect", &self.cred_protect)
            .field(
                "large_blob_key",
                &self.large_blob_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("cose_algorithm", &self.cose_algorithm)
            .finish()
    }
}

fn parse_rp_entry(value: &Value) -> Result<RpEntry, Error> {
    if value.as_map().is_none() {
        return Err(invalid());
    }
    let rp_value = required(value.map_get_int(RESPONSE_RP))?;
    let id = required(rp_value.map_get_text("id"))?
        .as_text()
        .ok_or_else(invalid)?
        .to_owned();
    let name = match rp_value.map_get_text("name") {
        None => None,
        Some(v) => Some(v.as_text().ok_or_else(invalid)?.to_owned()),
    };
    let rp_id_hash = required(value.map_get_int(RESPONSE_RP_ID_HASH))?
        .as_bytes()
        .ok_or_else(invalid)?
        .try_into()
        .map_err(|_| invalid())?;
    Ok(RpEntry {
        rp: RelyingParty { id, name },
        rp_id_hash,
    })
}

fn parse_credential_entry(value: &Value) -> Result<CredentialEntry, Error> {
    if value.as_map().is_none() {
        return Err(invalid());
    }
    let user = opt(value, RESPONSE_USER, parse_user)?;
    let credential_id = parse_descriptor(required(value.map_get_int(RESPONSE_CREDENTIAL_ID))?)?;
    let public_key = opt(value, RESPONSE_PUBLIC_KEY, CoseKey::from_value)?;
    let cose_algorithm = opt(value, RESPONSE_COSE_ALGORITHM, |v| {
        v.as_int().ok_or_else(invalid)
    })?;
    // Standard responses carry publicKey (8), the CanoKey metadata-only
    // extension carries coseAlgorithm (0x80): exactly one of the two.
    if public_key.is_some() == cose_algorithm.is_some() {
        return Err(invalid());
    }
    Ok(CredentialEntry {
        user,
        credential_id,
        public_key,
        cred_protect: opt(value, RESPONSE_CRED_PROTECT, |v| {
            v.as_uint().ok_or_else(invalid)
        })?,
        large_blob_key: opt(value, RESPONSE_LARGE_BLOB_KEY, |v| {
            v.as_bytes()
                .map(|bytes| SecretBytes::new(bytes.to_vec()))
                .ok_or_else(invalid)
        })?,
        cose_algorithm,
    })
}

/// Split the reassembled CTAP response into its status byte and payload.
fn split_status(response: &ResponseData) -> Result<(CtapStatus, &[u8]), Error> {
    response.ensure_success(Phase::Command)?;
    let (&status, payload) = response
        .data
        .as_bytes()
        .split_first()
        .ok_or_else(|| Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing))?;
    Ok((CtapStatus::from_raw(status), payload))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Select,
    Begin,
    GetNext,
}

/// The state machine behind [`enumerate_rps`] and [`enumerate_credentials`]:
/// SELECT, one authenticated Begin, then up to `total - 1` GetNext commands.
struct Enumerate<T> {
    stage: Stage,
    begin_message: Vec<u8>,
    get_next_message: Vec<u8>,
    total_key: i64,
    parse_entry: fn(&Value) -> Result<T, Error>,
    /// Maximum acceptable number of GetNext calls, derived from the
    /// operation's exchange budget.
    max_get_next: u64,
    items: Vec<T>,
    remaining: u64,
}
impl<T: Send> Machine<Vec<T>> for Enumerate<T> {
    fn next(&mut self, response: Option<ResponseData>) -> Result<Action<Vec<T>>, Error> {
        match self.stage {
            Stage::Select => match response {
                None => Ok(Action::Command(command::select())),
                Some(response) => {
                    response.ensure_success(Phase::Select)?;
                    self.stage = Stage::Begin;
                    Ok(Action::Command(command::msg(&self.begin_message)))
                }
            },
            Stage::Begin => {
                let response = response.ok_or_else(|| Error::new(ErrorKind::ProtocolViolation))?;
                let (status, payload) = split_status(&response)?;
                if status.raw() == STATUS_NO_CREDENTIALS {
                    return Ok(Action::Done(Vec::new()));
                }
                if let Some(error) = status.into_error(Phase::Command) {
                    return Err(error);
                }
                let value = cbor::parse(payload)?;
                if value.as_map().is_none() {
                    return Err(invalid());
                }
                let total = required(value.map_get_int(self.total_key))?
                    .as_uint()
                    .ok_or_else(invalid)?;
                if total == 0 {
                    // A successful Begin carries one entry; reporting a zero
                    // total alongside it violates the CTAP2 contract.
                    return Err(invalid());
                }
                self.items.push((self.parse_entry)(&value)?);
                self.remaining = total - 1;
                if self.remaining > self.max_get_next {
                    // An absurd authenticator-reported total must not turn
                    // into an unbounded command loop.
                    return Err(Error::new(ErrorKind::LimitExceeded).at(Phase::Parsing));
                }
                if self.remaining == 0 {
                    return Ok(Action::Done(std::mem::take(&mut self.items)));
                }
                self.stage = Stage::GetNext;
                Ok(Action::Command(command::msg(&self.get_next_message)))
            }
            Stage::GetNext => {
                let response = response.ok_or_else(|| Error::new(ErrorKind::ProtocolViolation))?;
                let (status, payload) = split_status(&response)?;
                if let Some(error) = status.into_error(Phase::Command) {
                    return Err(error);
                }
                let value = cbor::parse(payload)?;
                self.items.push((self.parse_entry)(&value)?);
                self.remaining -= 1;
                if self.remaining == 0 {
                    Ok(Action::Done(std::mem::take(&mut self.items)))
                } else {
                    Ok(Action::Command(command::msg(&self.get_next_message)))
                }
            }
        }
    }
}

/// Shared construction of the enumeration operations: validates both
/// messages against the options, then builds the [`Enumerate`] machine.
fn enumerate<T: Send + 'static>(
    begin_message: Vec<u8>,
    get_next_message: Vec<u8>,
    total_key: i64,
    parse_entry: fn(&Value) -> Result<T, Error>,
    options: OperationOptions,
) -> Result<Operation<Vec<T>>, Error> {
    let options = options.validate()?;
    for message in [&begin_message, &get_next_message] {
        if message.len() > options.limits.max_input_bytes {
            return Err(Error::new(ErrorKind::LimitExceeded));
        }
        validate_command(&command::msg(message), options)?;
    }
    validate_command(&command::select(), options)?;
    // SELECT and the Begin command each consume at least one exchange; the
    // remaining budget bounds the GetNext loop. Physical exchanges beyond
    // this (chaining, continuation) are still caught by the operation's own
    // exchange budget.
    let max_get_next = options.limits.max_exchanges.saturating_sub(2) as u64;
    Operation::from_machine(
        Enumerate {
            stage: Stage::Select,
            begin_message,
            get_next_message,
            total_key,
            parse_entry,
            max_get_next,
            items: Vec::new(),
            remaining: 0,
        },
        options,
    )
}

/// Query resident-credential storage counters: getCredsMetadata (0x01).
///
/// Wire format: `0x0A` followed by `{1: 0x01, 3: pinUvAuthProtocol,
/// 4: pinUvAuthParam}` where the MAC input is the single byte `0x01`. The
/// response carries existingResidentCredentialsCount (key 1) and
/// maxPossibleRemainingResidentCredentialsCount (key 2); both are required.
/// This operation is read-only.
///
/// # Errors
/// A non-success CTAP status is classified in the Command phase with the raw
/// byte retained (for example 0x33 PIN_AUTH_INVALID maps to
/// [`ErrorKind::AuthenticationFailed`]). A response missing key 1 or 2, or
/// with mistyped members, fails as [`ErrorKind::InvalidResponse`] in
/// [`Phase::Parsing`].
pub fn get_creds_metadata(
    token: &PinToken,
    protocol: PinUvAuthProtocol,
    options: OperationOptions,
) -> Result<Operation<CredsMetadata>, Error> {
    let message = message(SUBCOMMAND_GET_CREDS_METADATA, None, protocol, Some(token))?;
    select_then(&message, options, |response| {
        typed(response, |bytes| {
            let value = cbor::parse(bytes)?;
            if value.as_map().is_none() {
                return Err(invalid());
            }
            let existing = required(value.map_get_int(RESPONSE_EXISTING_COUNT))?
                .as_uint()
                .ok_or_else(invalid)?;
            let remaining = required(value.map_get_int(RESPONSE_REMAINING_COUNT))?
                .as_uint()
                .ok_or_else(invalid)?;
            Ok(CredsMetadata {
                existing_resident_credentials_count: existing,
                max_possible_remaining_resident_credentials_count: remaining,
            })
        })
    })
}

/// Enumerate the relying parties with resident credentials:
/// enumerateRpsBegin (0x02) followed by enumerateRpsGetNextRP (0x03).
///
/// The whole sequence runs inside the returned operation: SELECT, one
/// authenticated Begin, then `totalRPs - 1` GetNext commands. The caller
/// drives one operation and receives the complete vector. A 0x2E
/// NO_CREDENTIALS status on Begin means no resident credentials exist and
/// yields an empty vector, **not** an error.
///
/// The GetNext count is bounded by the authenticator-reported `totalRPs`
/// and by the operation's exchange budget; a reported total that cannot fit
/// the budget fails as [`ErrorKind::LimitExceeded`] rather than looping
/// unbounded.
///
/// # Errors
/// Beyond the above, a non-success CTAP status is classified in the Command
/// phase; a Begin response missing the rp (3), rpIDHash (4) or totalRPs (5)
/// member, or a mistyped member anywhere, fails as
/// [`ErrorKind::InvalidResponse`] in [`Phase::Parsing`].
pub fn enumerate_rps(
    token: &PinToken,
    protocol: PinUvAuthProtocol,
    options: OperationOptions,
) -> Result<Operation<Vec<RpEntry>>, Error> {
    let begin = message(SUBCOMMAND_ENUMERATE_RPS_BEGIN, None, protocol, Some(token))?;
    let get_next = message(SUBCOMMAND_ENUMERATE_RPS_GET_NEXT, None, protocol, None)?;
    enumerate(begin, get_next, RESPONSE_TOTAL_RPS, parse_rp_entry, options)
}

/// Enumerate the resident credentials of one relying party:
/// enumerateCredentialsBegin (0x04) followed by
/// enumerateCredentialsGetNextCredential (0x05).
///
/// `rp_id_hash` is the SHA-256 hash of the relying party ID, typically from
/// [`RpEntry::rp_id_hash`]. The whole sequence runs inside the returned
/// operation; a 0x2E NO_CREDENTIALS status on Begin yields an empty vector,
/// **not** an error, and the loop is budget-bounded like [`enumerate_rps`].
///
/// # Metadata-only mode (CanoKey vendor extension)
///
/// With `metadata_only: true` the Begin parameters additionally carry
/// `{0x80: true}` and the MAC input covers the full parameter map including
/// key 0x80. The authenticator then omits publicKey (key 8) and reports the
/// raw COSE algorithm identifier under key 0x80 in
/// [`CredentialEntry::cose_algorithm`], which keeps responses small enough
/// for ML-DSA credentials. GetNext inherits the mode; key 0x80 is never
/// sent to GetNext. This extension is not part of CTAP2 — the caller is
/// responsible for knowing the authenticator supports it. Exactly one of
/// [`CredentialEntry::public_key`] and [`CredentialEntry::cose_algorithm`]
/// must be present in each response; both or neither fails as
/// [`ErrorKind::InvalidResponse`].
///
/// # Errors
/// A non-success CTAP status (other than Begin's 0x2E) is classified in the
/// Command phase. A response missing credentialID (key 7) or
/// totalCredentials (key 9 on Begin), with mistyped members, or violating
/// the publicKey/coseAlgorithm rule fails as [`ErrorKind::InvalidResponse`]
/// in [`Phase::Parsing`].
pub fn enumerate_credentials(
    token: &PinToken,
    protocol: PinUvAuthProtocol,
    rp_id_hash: [u8; 32],
    metadata_only: bool,
    options: OperationOptions,
) -> Result<Operation<Vec<CredentialEntry>>, Error> {
    let mut params = vec![(uint(PARAM_RP_ID_HASH), Value::Bytes(rp_id_hash.to_vec()))];
    if metadata_only {
        params.push((uint(PARAM_METADATA_ONLY), Value::Bool(true)));
    }
    let begin = message(
        SUBCOMMAND_ENUMERATE_CREDENTIALS_BEGIN,
        Some(Value::Map(params)),
        protocol,
        Some(token),
    )?;
    let get_next = message(
        SUBCOMMAND_ENUMERATE_CREDENTIALS_GET_NEXT,
        None,
        protocol,
        None,
    )?;
    enumerate(
        begin,
        get_next,
        RESPONSE_TOTAL_CREDENTIALS,
        parse_credential_entry,
        options,
    )
}

/// Delete one resident credential: deleteCredential (0x06).
///
/// Wire format: `0x0A` followed by `{1: 0x06, 2: {0x02: credentialId},
/// 3: pinUvAuthProtocol, 4: pinUvAuthParam}` where the MAC input is
/// `0x06 || cbor({0x02: credentialId})`. A successful response has an empty
/// payload.
///
/// **This permanently destroys the credential on the authenticator**, with
/// no confirmation step and no rollback; cancel/drop after the command was
/// sent does not undo it. An unknown credential ID surfaces as 0x2E
/// NO_CREDENTIALS or 0x22 INVALID_CREDENTIAL (both [`ErrorKind::NotFound`]).
///
/// # Errors
/// An empty `credential_id.id` fails as [`ErrorKind::InvalidArgument`]
/// before any I/O. A non-success CTAP status is classified in the Command
/// phase; a non-empty successful payload is [`ErrorKind::InvalidResponse`]
/// in [`Phase::Parsing`].
pub fn delete_credential(
    token: &PinToken,
    protocol: PinUvAuthProtocol,
    credential_id: &PublicKeyCredentialDescriptor,
    options: OperationOptions,
) -> Result<Operation<()>, Error> {
    if credential_id.id.is_empty() {
        return Err(invalid_argument());
    }
    let params = Value::Map(vec![(
        uint(PARAM_CREDENTIAL_ID),
        descriptor_value(credential_id),
    )]);
    let message = message(
        SUBCOMMAND_DELETE_CREDENTIAL,
        Some(params),
        protocol,
        Some(token),
    )?;
    select_then(&message, options, |response| typed(response, empty_payload))
}

/// Replace the user information of one resident credential:
/// updateUserInformation (0x07).
///
/// Wire format: `0x0A` followed by `{1: 0x07, 2: {0x02: credentialId,
/// 0x03: user}, 3: pinUvAuthProtocol, 4: pinUvAuthParam}` with the MAC over
/// `0x07 || cbor(params)`. A successful response has an empty payload. This
/// mutates card state: the credential's stored user entity is replaced by
/// `user`.
///
/// # Errors
/// An empty or overlong `user.id` (more than [`MAX_USER_ID_LEN`] bytes) or
/// an empty `credential_id.id` fails as [`ErrorKind::InvalidArgument`]
/// before any I/O. A non-success CTAP status is classified in the Command
/// phase; a non-empty successful payload is [`ErrorKind::InvalidResponse`]
/// in [`Phase::Parsing`].
pub fn update_user_information(
    token: &PinToken,
    protocol: PinUvAuthProtocol,
    credential_id: &PublicKeyCredentialDescriptor,
    user: &UserEntity,
    options: OperationOptions,
) -> Result<Operation<()>, Error> {
    if credential_id.id.is_empty() || user.id.is_empty() || user.id.len() > MAX_USER_ID_LEN {
        return Err(invalid_argument());
    }
    let params = Value::Map(vec![
        (uint(PARAM_CREDENTIAL_ID), descriptor_value(credential_id)),
        (uint(PARAM_USER), user_value(user)),
    ]);
    let message = message(
        SUBCOMMAND_UPDATE_USER_INFORMATION,
        Some(params),
        protocol,
        Some(token),
    )?;
    select_then(&message, options, |response| typed(response, empty_payload))
}
