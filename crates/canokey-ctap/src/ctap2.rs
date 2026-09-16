//! Command-level CTAP2 operations on top of the ISO 7816 envelope.
//!
//! Each factory returns an [`Operation`] that first sends SELECT of the FIDO2
//! application and then one wrapped CTAP message (`80 10 00 00`). The explicit
//! re-SELECT is idempotent for FIDO and does not invalidate pinUvAuthTokens.
//! A non-success CTAP status byte is classified through the status table in
//! the Command phase, with the raw byte retained in `Error::status_word`;
//! response CBOR is parsed strictly (canonical form, no tags, no duplicate
//! keys, no trailing bytes) and structural violations fail as
//! [`ErrorKind::InvalidResponse`] in [`Phase::Parsing`].
//!
//! All factories are profile-free: they enforce the CTAP2 specification, not
//! any authenticator's advertised capabilities. Card-controlled allocation is
//! bounded by the operation's response limits and the CBOR nesting limit.

use crate::authdata::AuthenticatorData;
use crate::cbor::{self, Value};
use crate::cose::CoseAlgorithm;
use crate::hmacsecret;
#[cfg(feature = "clientpin")]
use crate::hmacsecret::HmacSecretInput;
use crate::{select_then, CtapResponse};
use canokey_protocol::{Error, ErrorKind, Operation, OperationOptions, Phase, SecretBytes};

const COMMAND_MAKE_CREDENTIAL: u8 = 0x01;
const COMMAND_GET_ASSERTION: u8 = 0x02;
const COMMAND_GET_INFO: u8 = 0x04;
const COMMAND_RESET: u8 = 0x07;
const COMMAND_GET_NEXT_ASSERTION: u8 = 0x08;
const COMMAND_SELECTION: u8 = 0x0b;

/// Extension key of the hmac-secret declaration/exchange (CTAP 2.x).
pub(crate) const EXT_HMAC_SECRET: &str = "hmac-secret";
/// Extension key of the CanoKey hmac-secret-mc makeCredential variant.
#[cfg(feature = "clientpin")]
pub(crate) const EXT_HMAC_SECRET_MC: &str = "hmac-secret-mc";

/// Maximum byte length of a user ID in makeCredential/getAssertion (CTAP2).
pub const MAX_USER_ID_LEN: usize = 64;

fn invalid() -> Error {
    Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing)
}
fn invalid_argument() -> Error {
    Error::new(ErrorKind::InvalidArgument)
}
fn required(value: Option<&Value>) -> Result<&Value, Error> {
    value.ok_or_else(invalid)
}

/// A pin/UV auth protocol version as advertised by authenticatorGetInfo.
///
/// The wrapped byte is the CTAP2 protocol version number. Only the versions
/// this library can speak are constructible; unknown advertised versions are
/// preserved raw in [`AuthenticatorInfo::pin_uv_auth_protocols`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinUvAuthProtocol(u8);
impl PinUvAuthProtocol {
    /// Protocol version 1: SHA-256 shared secret, 16-byte pinUvAuthParam.
    pub const V1: Self = Self(1);
    /// Protocol version 2: HKDF-SHA-256 shared secret, 32-byte pinUvAuthParam.
    pub const V2: Self = Self(2);
    /// Resolve a raw protocol version byte, or `None` when unknown.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::V1),
            2 => Some(Self::V2),
            _ => None,
        }
    }
    /// Return the raw protocol version byte used on the wire.
    pub fn to_u8(self) -> u8 {
        self.0
    }
}

/// A pinUvAuthProtocol/pinUvAuthParam pair for makeCredential and
/// getAssertion requests. The parameter is redacted in Debug and zeroized.
///
/// Construction accepts a 16- or 32-byte parameter regardless of `protocol`
/// (the CTAP2 widths are 16 for V1 and 32 for V2). Matching the width to the
/// protocol is the caller's responsibility: a mismatch is only detected by
/// the authenticator, which rejects the request. `PinToken::authenticate`
/// (feature `clientpin`) already produces the width matching its protocol.
#[derive(Clone, Debug)]
pub struct PinUvAuth {
    /// The protocol version the parameter was computed with.
    pub protocol: PinUvAuthProtocol,
    param: SecretBytes,
}
impl PinUvAuth {
    /// Copy a pinUvAuthParam of exactly 16 or 32 bytes; the width is not
    /// checked against `protocol` (see the type documentation).
    ///
    /// # Errors
    /// Any other length fails as [`ErrorKind::InvalidArgument`] before I/O.
    pub fn new(protocol: PinUvAuthProtocol, param: &[u8]) -> Result<Self, Error> {
        if param.len() != 16 && param.len() != 32 {
            return Err(invalid_argument());
        }
        Ok(Self {
            protocol,
            param: SecretBytes::new(param.to_vec()),
        })
    }
    /// Borrow the pinUvAuthParam bytes. Avoid logging or unmanaged copies.
    pub fn param(&self) -> &SecretBytes {
        &self.param
    }
}

/// A PublicKeyCredentialDescriptor (`{"type", "id", "transports"?}`).
///
/// `transports` is omitted from the wire encoding when empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyCredentialDescriptor {
    /// The credential type, normally `"public-key"`.
    pub type_: String,
    /// The credential ID.
    pub id: Vec<u8>,
    /// Optional transport hints; omitted from the encoding when empty.
    pub transports: Vec<String>,
}
impl PublicKeyCredentialDescriptor {
    /// Build a descriptor without transport hints.
    pub fn new(type_: impl Into<String>, id: impl Into<Vec<u8>>) -> Self {
        Self {
            type_: type_.into(),
            id: id.into(),
            transports: Vec::new(),
        }
    }
    fn to_value(&self) -> Value {
        let mut entries = vec![
            (
                Value::Text("type".to_owned()),
                Value::Text(self.type_.clone()),
            ),
            (Value::Text("id".to_owned()), Value::Bytes(self.id.clone())),
        ];
        if !self.transports.is_empty() {
            entries.push((
                Value::Text("transports".to_owned()),
                Value::Array(
                    self.transports
                        .iter()
                        .map(|t| Value::Text(t.clone()))
                        .collect(),
                ),
            ));
        }
        Value::Map(entries)
    }
    fn from_value(value: &Value) -> Result<Self, Error> {
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
            Some(list) => text_array(list)?,
        };
        Ok(Self {
            type_,
            id,
            transports,
        })
    }
}

/// A relying party entity as sent in authenticatorMakeCredential (key 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelyingParty {
    /// The relying party ID, for example `"example.com"`; must not be empty.
    pub id: String,
    /// An optional human-readable relying party name.
    pub name: Option<String>,
}
impl RelyingParty {
    fn to_value(&self) -> Value {
        let mut entries = vec![(Value::Text("id".to_owned()), Value::Text(self.id.clone()))];
        if let Some(name) = &self.name {
            entries.push((Value::Text("name".to_owned()), Value::Text(name.clone())));
        }
        Value::Map(entries)
    }
}

/// A user entity as sent in makeCredential and returned by getAssertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserEntity {
    /// The user handle: 1..=[`MAX_USER_ID_LEN`] bytes in makeCredential.
    pub id: Vec<u8>,
    /// An optional username.
    pub name: Option<String>,
    /// An optional human-friendly display name.
    pub display_name: Option<String>,
}
impl UserEntity {
    fn to_value(&self) -> Value {
        let mut entries = vec![(Value::Text("id".to_owned()), Value::Bytes(self.id.clone()))];
        if let Some(name) = &self.name {
            entries.push((Value::Text("name".to_owned()), Value::Text(name.clone())));
        }
        if let Some(display_name) = &self.display_name {
            entries.push((
                Value::Text("displayName".to_owned()),
                Value::Text(display_name.clone()),
            ));
        }
        Value::Map(entries)
    }
    fn from_value(value: &Value) -> Result<Self, Error> {
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
        Ok(Self {
            id,
            name,
            display_name,
        })
    }
}

/// One entry of the getInfo `algorithms` list (`{"type", "alg"}`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyCredentialParameters {
    /// The credential type, normally `"public-key"`.
    pub type_: String,
    /// The raw COSE algorithm identifier (for example -7 for ES256).
    pub alg: i64,
}
impl PublicKeyCredentialParameters {
    /// Resolve the COSE algorithm identifier to a typed algorithm.
    pub fn algorithm(&self) -> CoseAlgorithm {
        CoseAlgorithm::from_id(self.alg)
    }
}

/// The parsed authenticatorGetInfo response.
///
/// Only `versions` and `aaguid` are required by the CTAP2 specification; a
/// response missing either fails as [`ErrorKind::InvalidResponse`] in
/// [`Phase::Parsing`]. Every other member is optional and typed. Unknown or
/// unlisted keys are preserved in [`Self::raw`]; optionality is the
/// authenticator's, so absent members are `None` rather than errors.
#[derive(Clone, Debug)]
pub struct AuthenticatorInfo {
    versions: Vec<String>,
    aaguid: [u8; 16],
    extensions: Option<Vec<String>>,
    options: Option<Vec<(String, bool)>>,
    max_msg_size: Option<u64>,
    pin_uv_auth_protocols: Option<Vec<u8>>,
    max_credential_count_in_list: Option<u64>,
    max_credential_id_length: Option<u64>,
    transports: Option<Vec<String>>,
    algorithms: Option<Vec<PublicKeyCredentialParameters>>,
    max_serialized_large_blob_array: Option<u64>,
    force_pin_change: Option<bool>,
    min_pin_length: Option<u64>,
    firmware_version: Option<u64>,
    max_cred_blob_length: Option<u64>,
    max_rp_ids_for_set_min_pin_length: Option<u64>,
    remaining_discoverable_credentials: Option<u64>,
    vendor_prototype_config_commands: Option<Vec<u64>>,
    raw: Value,
}
impl AuthenticatorInfo {
    /// Return the supported protocol versions (key 1, required), for example
    /// `["U2F_V2", "FIDO_2_0", "FIDO_2_1", "FIDO_2_3"]`.
    pub fn versions(&self) -> &[String] {
        &self.versions
    }
    /// Return the authenticator's AAGUID (key 3, required).
    pub fn aaguid(&self) -> &[u8; 16] {
        &self.aaguid
    }
    /// Return the supported extensions (key 2) when advertised.
    pub fn extensions(&self) -> Option<&[String]> {
        self.extensions.as_deref()
    }
    /// Return the options as ordered name/value pairs (key 4) when present.
    /// Ordering is the wire order; unknown option names are preserved.
    pub fn options(&self) -> Option<&[(String, bool)]> {
        self.options.as_deref()
    }
    /// Return the maximum CTAP message size the authenticator accepts (key 5).
    pub fn max_msg_size(&self) -> Option<u64> {
        self.max_msg_size
    }
    /// Return the advertised pin/UV auth protocol version bytes (key 6).
    /// Resolve each with [`PinUvAuthProtocol::from_u8`]; unknown versions are
    /// preserved raw.
    pub fn pin_uv_auth_protocols(&self) -> Option<&[u8]> {
        self.pin_uv_auth_protocols.as_deref()
    }
    /// Return the maximum number of credentials accepted in allow/exclude
    /// lists (key 7).
    pub fn max_credential_count_in_list(&self) -> Option<u64> {
        self.max_credential_count_in_list
    }
    /// Return the maximum credential ID length (key 8).
    pub fn max_credential_id_length(&self) -> Option<u64> {
        self.max_credential_id_length
    }
    /// Return the supported transports (key 9) when advertised.
    pub fn transports(&self) -> Option<&[String]> {
        self.transports.as_deref()
    }
    /// Return the supported signature algorithms in preference order
    /// (key 10) when advertised.
    pub fn algorithms(&self) -> Option<&[PublicKeyCredentialParameters]> {
        self.algorithms.as_deref()
    }
    /// Return the maximum serialized large-blob array size (key 11).
    pub fn max_serialized_large_blob_array(&self) -> Option<u64> {
        self.max_serialized_large_blob_array
    }
    /// Return whether the authenticator requires a PIN change (key 12).
    pub fn force_pin_change(&self) -> Option<bool> {
        self.force_pin_change
    }
    /// Return the current minimum PIN length (key 13).
    pub fn min_pin_length(&self) -> Option<u64> {
        self.min_pin_length
    }
    /// Return the authenticator firmware version (key 14); this is a CTAP
    /// version field, not the product firmware version.
    pub fn firmware_version(&self) -> Option<u64> {
        self.firmware_version
    }
    /// Return the maximum credBlob length (key 15).
    pub fn max_cred_blob_length(&self) -> Option<u64> {
        self.max_cred_blob_length
    }
    /// Return the maximum number of RP IDs for setMinPINLength (key 16).
    pub fn max_rp_ids_for_set_min_pin_length(&self) -> Option<u64> {
        self.max_rp_ids_for_set_min_pin_length
    }
    /// Return the estimated remaining discoverable-credential slots (key 20).
    pub fn remaining_discoverable_credentials(&self) -> Option<u64> {
        self.remaining_discoverable_credentials
    }
    /// Return the vendor prototype config commands (key 21) when advertised.
    pub fn vendor_prototype_config_commands(&self) -> Option<&[u64]> {
        self.vendor_prototype_config_commands.as_deref()
    }
    /// Return the raw decoded response map, including any keys this library
    /// does not type. Byte-string contents are redacted in its Debug output.
    pub fn raw(&self) -> &Value {
        &self.raw
    }
}

/// Parameters for [`make_credential`], copied at construction.
///
/// The required members are set with [`Self::new`]; the optional lists and
/// fields start empty/`None` and can be assigned directly. `exclude_list` and
/// `options` are omitted from the wire encoding when empty, as are the
/// extensions when neither `extensions` nor the typed extension fields
/// request any.
#[derive(Clone, Debug)]
pub struct MakeCredentialParams {
    /// The SHA-256 hash of the client data (key 1, required).
    pub client_data_hash: [u8; 32],
    /// The relying party (key 2, required); `rp.id` must not be empty.
    pub rp: RelyingParty,
    /// The user (key 3, required); `user.id` must be 1..=64 bytes.
    pub user: UserEntity,
    /// The acceptable COSE algorithms in preference order (key 4, required);
    /// must not be empty.
    pub pub_key_cred_params: Vec<CoseAlgorithm>,
    /// Credentials to exclude (key 5); omitted when empty.
    pub exclude_list: Vec<PublicKeyCredentialDescriptor>,
    /// Extension inputs as name/value pairs (key 6). Do not repeat the keys
    /// covered by the typed extension fields (`hmac_secret`,
    /// `hmac_secret_mc`): a duplicate is rejected at construction.
    pub extensions: Vec<(String, Value)>,
    /// Requested options as name/value pairs (key 7); omitted when empty.
    pub options: Vec<(String, bool)>,
    /// Optional pinUvAuthProtocol/pinUvAuthParam pair (keys 8/9).
    pub pin_uv_auth: Option<PinUvAuth>,
    /// Optional enterprise attestation request (key 10): 1 for
    /// vendor-facilitated or 2 for platform-managed.
    pub enterprise_attestation: Option<u32>,
    /// Request the hmac-secret declaration (extension `"hmac-secret": true`
    /// in key 6): asks the authenticator to mark the new credential as
    /// hmac-secret-capable. This is a plain declaration and works without
    /// any PIN or key agreement; the authenticator's confirmation is
    /// reported by [`MakeCredentialResponse::hmac_secret_supported`].
    pub hmac_secret: bool,
    /// Optional CanoKey-specific hmac-secret-mc exchange input (extension
    /// `"hmac-secret-mc"` in key 6): performs the encrypted hmac-secret salt
    /// exchange inside makeCredential. Requires `hmac_secret` to be `true`
    /// (the firmware fails the request with CTAP2_ERR_MISSING_PARAMETER
    /// otherwise); the decrypted salt outputs are reported by
    /// [`MakeCredentialResponse::hmac_secret_mc`]. Unlike the declaration,
    /// the exchange needs a pin/UV protocol key agreement (but no PIN) — see
    /// [`HmacSecretInput`].
    #[cfg(feature = "clientpin")]
    pub hmac_secret_mc: Option<HmacSecretInput>,
}
impl MakeCredentialParams {
    /// Build parameters with the required members; all optional members start
    /// empty, `false` or `None`.
    pub fn new(
        client_data_hash: [u8; 32],
        rp: RelyingParty,
        user: UserEntity,
        pub_key_cred_params: Vec<CoseAlgorithm>,
    ) -> Self {
        Self {
            client_data_hash,
            rp,
            user,
            pub_key_cred_params,
            exclude_list: Vec::new(),
            extensions: Vec::new(),
            options: Vec::new(),
            pin_uv_auth: None,
            enterprise_attestation: None,
            hmac_secret: false,
            #[cfg(feature = "clientpin")]
            hmac_secret_mc: None,
        }
    }
}

/// Parameters for [`get_assertion`], copied at construction.
///
/// `allow_list` and `options` are omitted from the wire encoding when empty;
/// an empty allow list requests a discoverable-credential (resident key)
/// assertion.
#[derive(Clone, Debug)]
pub struct GetAssertionParams {
    /// The relying party ID (key 1, required); must not be empty.
    pub rp_id: String,
    /// The SHA-256 hash of the client data (key 2, required).
    pub client_data_hash: [u8; 32],
    /// The acceptable credentials (key 3); omitted when empty.
    pub allow_list: Vec<PublicKeyCredentialDescriptor>,
    /// Extension inputs as name/value pairs (key 4). Do not repeat the key
    /// covered by the typed `hmac_secret` field: a duplicate is rejected at
    /// construction.
    pub extensions: Vec<(String, Value)>,
    /// Requested options as name/value pairs (key 5); omitted when empty.
    pub options: Vec<(String, bool)>,
    /// Optional pinUvAuthProtocol/pinUvAuthParam pair (keys 6/7).
    pub pin_uv_auth: Option<PinUvAuth>,
    /// Optional hmac-secret exchange input (extension `"hmac-secret"` in
    /// key 4): the encrypted salt exchange of CTAP 2.x. The decrypted salt
    /// outputs are reported by [`GetAssertionResponse::hmac_secret`]. The
    /// exchange needs a pin/UV protocol key agreement but no PIN — see
    /// [`HmacSecretInput`]. Note the CanoKey firmware rejects combining this
    /// extension with the `up: false` option (CTAP2_ERR_UNSUPPORTED_OPTION).
    #[cfg(feature = "clientpin")]
    pub hmac_secret: Option<HmacSecretInput>,
}
impl GetAssertionParams {
    /// Build parameters with the required members; all optional members start
    /// empty or `None`.
    pub fn new(rp_id: impl Into<String>, client_data_hash: [u8; 32]) -> Self {
        Self {
            rp_id: rp_id.into(),
            client_data_hash,
            allow_list: Vec::new(),
            extensions: Vec::new(),
            options: Vec::new(),
            pin_uv_auth: None,
            #[cfg(feature = "clientpin")]
            hmac_secret: None,
        }
    }
}

/// The parsed authenticatorMakeCredential response.
///
/// `fmt` and `auth_data` are required; `att_stmt` must be a CBOR map with
/// text keys and is retained undecoded because attestation statement formats
/// (and their trust evaluation) are the caller's. No certificate validity,
/// identity or attestation policy is enforced here.
#[derive(Clone, Debug)]
pub struct MakeCredentialResponse {
    fmt: String,
    auth_data: AuthenticatorData,
    att_stmt: Value,
    ep_att: Option<bool>,
    large_blob_key: Option<SecretBytes>,
    hmac_secret_supported: bool,
    #[cfg(feature = "clientpin")]
    hmac_secret_mc: Option<SecretBytes>,
}
impl MakeCredentialResponse {
    /// Return the attestation statement format identifier (key 1), for
    /// example `"packed"` or `"none"`.
    pub fn fmt(&self) -> &str {
        &self.fmt
    }
    /// Return the parsed authenticator data (key 2); the exact raw bytes the
    /// attestation signature covers are available through
    /// [`AuthenticatorData::raw`].
    pub fn auth_data(&self) -> &AuthenticatorData {
        &self.auth_data
    }
    /// Return the attestation statement (key 3) as the raw decoded CBOR map.
    /// All keys are text. Byte-string contents are redacted in Debug.
    pub fn att_stmt(&self) -> &Value {
        &self.att_stmt
    }
    /// Return whether the authenticator signals an enterprise attestation
    /// (key 4) when present.
    pub fn ep_att(&self) -> Option<bool> {
        self.ep_att
    }
    /// Return the credential's largeBlobKey (key 5) when present. The bytes
    /// are credential-adjacent key material: redacted and zeroized.
    pub fn large_blob_key(&self) -> Option<&SecretBytes> {
        self.large_blob_key.as_ref()
    }
    /// Return whether the authenticator confirmed the hmac-secret
    /// declaration (`"hmac-secret": true` in the authData extensions),
    /// marking the new credential as hmac-secret-capable. Absent means not
    /// supported; a present non-boolean value is a parse error.
    pub fn hmac_secret_supported(&self) -> bool {
        self.hmac_secret_supported
    }
    /// Return the decrypted hmac-secret-mc exchange output (32 bytes for one
    /// salt, 64 for two) when the exchange was requested through
    /// [`MakeCredentialParams::hmac_secret_mc`] and the authenticator
    /// answered it. The bytes are secret: redacted and zeroized.
    #[cfg(feature = "clientpin")]
    pub fn hmac_secret_mc(&self) -> Option<&SecretBytes> {
        self.hmac_secret_mc.as_ref()
    }
}

/// The parsed authenticatorGetAssertion / authenticatorGetNextAssertion
/// response.
///
/// `auth_data` and `signature` are required. `credential` may be omitted by
/// the authenticator (for example for a discoverable credential with a
/// single-credential allow list); callers that need it must correlate with
/// the request. `number_of_credentials` greater than one tells the caller to
/// collect the remaining assertions with [`get_next_assertion`].
#[derive(Clone, Debug)]
pub struct GetAssertionResponse {
    credential: Option<PublicKeyCredentialDescriptor>,
    auth_data: AuthenticatorData,
    signature: SecretBytes,
    user: Option<UserEntity>,
    number_of_credentials: Option<u64>,
    user_selected: Option<bool>,
    large_blob_key: Option<SecretBytes>,
    #[cfg(feature = "clientpin")]
    hmac_secret: Option<SecretBytes>,
}
impl GetAssertionResponse {
    /// Return the credential descriptor (key 1) when the authenticator sent
    /// one.
    pub fn credential(&self) -> Option<&PublicKeyCredentialDescriptor> {
        self.credential.as_ref()
    }
    /// Return the parsed authenticator data (key 2); the exact raw bytes the
    /// signature covers are available through [`AuthenticatorData::raw`].
    pub fn auth_data(&self) -> &AuthenticatorData {
        &self.auth_data
    }
    /// Return the assertion signature (key 3). It is credential-adjacent
    /// material: redacted in Debug and zeroized on drop.
    pub fn signature(&self) -> &SecretBytes {
        &self.signature
    }
    /// Return the user entity (key 4) when the authenticator sent one.
    pub fn user(&self) -> Option<&UserEntity> {
        self.user.as_ref()
    }
    /// Return the total number of credentials (key 5) when present. Values
    /// greater than one require [`get_next_assertion`] calls to collect the
    /// remaining assertions.
    pub fn number_of_credentials(&self) -> Option<u64> {
        self.number_of_credentials
    }
    /// Return whether the user was explicitly selected (key 6) when present.
    pub fn user_selected(&self) -> Option<bool> {
        self.user_selected
    }
    /// Return the credential's largeBlobKey (key 7) when present. The bytes
    /// are credential-adjacent key material: redacted and zeroized.
    pub fn large_blob_key(&self) -> Option<&SecretBytes> {
        self.large_blob_key.as_ref()
    }
    /// Return the decrypted hmac-secret exchange output (32 bytes for one
    /// salt, 64 for two) when the exchange was requested through
    /// [`GetAssertionParams::hmac_secret`] and the authenticator answered
    /// it. The bytes are secret: redacted and zeroized.
    #[cfg(feature = "clientpin")]
    pub fn hmac_secret(&self) -> Option<&SecretBytes> {
        self.hmac_secret.as_ref()
    }
}

/// Classify the CTAP status byte, then parse the response payload.
/// Transport and ISO 7816 status-word failures are surfaced unchanged by the
/// envelope below this layer.
fn typed<T>(
    response: CtapResponse,
    parse: impl FnOnce(&[u8]) -> Result<T, Error>,
) -> Result<T, Error> {
    if let Some(error) = response.status().into_error(Phase::Command) {
        return Err(error);
    }
    parse(response.payload())
}

fn text_array(value: &Value) -> Result<Vec<String>, Error> {
    value
        .as_array()
        .ok_or_else(invalid)?
        .iter()
        .map(|item| item.as_text().map(str::to_owned).ok_or_else(invalid))
        .collect()
}

fn uint_array(value: &Value) -> Result<Vec<u64>, Error> {
    value
        .as_array()
        .ok_or_else(invalid)?
        .iter()
        .map(|item| item.as_uint().ok_or_else(invalid))
        .collect()
}

fn opt<T>(
    map: &Value,
    key: i64,
    parse: impl FnOnce(&Value) -> Result<T, Error>,
) -> Result<Option<T>, Error> {
    map.map_get_int(key).map(parse).transpose()
}

fn opt_uint(map: &Value, key: i64) -> Result<Option<u64>, Error> {
    opt(map, key, |value| value.as_uint().ok_or_else(invalid))
}

fn opt_bool(map: &Value, key: i64) -> Result<Option<bool>, Error> {
    opt(map, key, |value| value.as_bool().ok_or_else(invalid))
}

fn opt_text_array(map: &Value, key: i64) -> Result<Option<Vec<String>>, Error> {
    opt(map, key, text_array)
}

fn opt_secret_bytes(map: &Value, key: i64) -> Result<Option<SecretBytes>, Error> {
    opt(map, key, |value| {
        value
            .as_bytes()
            .map(|bytes| SecretBytes::new(bytes.to_vec()))
            .ok_or_else(invalid)
    })
}

fn parse_options_map(value: &Value) -> Result<Vec<(String, bool)>, Error> {
    value
        .as_map()
        .ok_or_else(invalid)?
        .iter()
        .map(|(key, value)| {
            Ok((
                key.as_text().ok_or_else(invalid)?.to_owned(),
                value.as_bool().ok_or_else(invalid)?,
            ))
        })
        .collect()
}

fn parse_algorithms(value: &Value) -> Result<Vec<PublicKeyCredentialParameters>, Error> {
    value
        .as_array()
        .ok_or_else(invalid)?
        .iter()
        .map(|item| {
            let type_ = required(item.map_get_text("type"))?
                .as_text()
                .ok_or_else(invalid)?
                .to_owned();
            let alg = required(item.map_get_text("alg"))?
                .as_int()
                .ok_or_else(invalid)?;
            Ok(PublicKeyCredentialParameters { type_, alg })
        })
        .collect()
}

fn parse_get_info(bytes: &[u8]) -> Result<AuthenticatorInfo, Error> {
    let value = cbor::parse(bytes)?;
    if value.as_map().is_none() {
        return Err(invalid());
    }
    let versions = text_array(required(value.map_get_int(1))?)?;
    let aaguid = required(value.map_get_int(3))?
        .as_bytes()
        .ok_or_else(invalid)?
        .try_into()
        .map_err(|_| invalid())?;
    let pin_uv_auth_protocols = opt(&value, 6, |list| {
        uint_array(list)?
            .into_iter()
            .map(|n| u8::try_from(n).map_err(|_| invalid()))
            .collect()
    })?;
    Ok(AuthenticatorInfo {
        versions,
        aaguid,
        extensions: opt_text_array(&value, 2)?,
        options: opt(&value, 4, parse_options_map)?,
        max_msg_size: opt_uint(&value, 5)?,
        pin_uv_auth_protocols,
        max_credential_count_in_list: opt_uint(&value, 7)?,
        max_credential_id_length: opt_uint(&value, 8)?,
        transports: opt_text_array(&value, 9)?,
        algorithms: opt(&value, 10, parse_algorithms)?,
        max_serialized_large_blob_array: opt_uint(&value, 11)?,
        force_pin_change: opt_bool(&value, 12)?,
        min_pin_length: opt_uint(&value, 13)?,
        firmware_version: opt_uint(&value, 14)?,
        max_cred_blob_length: opt_uint(&value, 15)?,
        max_rp_ids_for_set_min_pin_length: opt_uint(&value, 16)?,
        remaining_discoverable_credentials: opt_uint(&value, 20)?,
        vendor_prototype_config_commands: opt(&value, 21, uint_array)?,
        raw: value,
    })
}

fn parse_make_credential(
    bytes: &[u8],
    #[cfg(feature = "clientpin")] hmac_secret_mc: Option<&HmacSecretInput>,
) -> Result<MakeCredentialResponse, Error> {
    let value = cbor::parse(bytes)?;
    if value.as_map().is_none() {
        return Err(invalid());
    }
    let fmt = required(value.map_get_int(1))?
        .as_text()
        .ok_or_else(invalid)?
        .to_owned();
    let auth_data = AuthenticatorData::parse(
        required(value.map_get_int(2))?
            .as_bytes()
            .ok_or_else(invalid)?,
    )?;
    let att_stmt = required(value.map_get_int(3))?.clone();
    let entries = att_stmt.as_map().ok_or_else(invalid)?;
    // attStmt is a CDDL map with text keys; non-text keys are malformed.
    if entries.iter().any(|(key, _)| key.as_text().is_none()) {
        return Err(invalid());
    }
    let hmac_secret_supported = hmacsecret::declaration_supported(&auth_data)?;
    #[cfg(feature = "clientpin")]
    let hmac_secret_mc =
        hmacsecret::exchange_output(&auth_data, EXT_HMAC_SECRET_MC, hmac_secret_mc)?;
    Ok(MakeCredentialResponse {
        fmt,
        auth_data,
        att_stmt,
        ep_att: opt_bool(&value, 4)?,
        large_blob_key: opt_secret_bytes(&value, 5)?,
        hmac_secret_supported,
        #[cfg(feature = "clientpin")]
        hmac_secret_mc,
    })
}

fn parse_get_assertion(
    bytes: &[u8],
    #[cfg(feature = "clientpin")] hmac_secret: Option<&HmacSecretInput>,
) -> Result<GetAssertionResponse, Error> {
    let value = cbor::parse(bytes)?;
    if value.as_map().is_none() {
        return Err(invalid());
    }
    // The credential descriptor may be omitted; the caller then correlates
    // the assertion with the requested credential.
    let credential = opt(&value, 1, PublicKeyCredentialDescriptor::from_value)?;
    let auth_data = AuthenticatorData::parse(
        required(value.map_get_int(2))?
            .as_bytes()
            .ok_or_else(invalid)?,
    )?;
    let signature = required(value.map_get_int(3))?
        .as_bytes()
        .ok_or_else(invalid)?;
    let user = opt(&value, 4, UserEntity::from_value)?;
    #[cfg(feature = "clientpin")]
    let hmac_secret = hmacsecret::exchange_output(&auth_data, EXT_HMAC_SECRET, hmac_secret)?;
    Ok(GetAssertionResponse {
        credential,
        auth_data,
        signature: SecretBytes::new(signature.to_vec()),
        user,
        number_of_credentials: opt_uint(&value, 5)?,
        user_selected: opt_bool(&value, 6)?,
        large_blob_key: opt_secret_bytes(&value, 7)?,
        #[cfg(feature = "clientpin")]
        hmac_secret,
    })
}

/// Require an empty response payload, as CTAP2 specifies for reset and
/// selection; a payload would be a protocol violation by the authenticator.
fn empty_payload(bytes: &[u8]) -> Result<(), Error> {
    if bytes.is_empty() {
        Ok(())
    } else {
        Err(invalid())
    }
}

fn extension_map(entries: &[(String, Value)]) -> Value {
    Value::Map(
        entries
            .iter()
            .map(|(key, value)| (Value::Text(key.clone()), value.clone()))
            .collect(),
    )
}

fn option_map(entries: &[(String, bool)]) -> Value {
    Value::Map(
        entries
            .iter()
            .map(|(key, value)| (Value::Text(key.clone()), Value::Bool(*value)))
            .collect(),
    )
}

/// Query authenticator capabilities: authenticatorGetInfo (0x04).
///
/// Wire format: the request is the single byte `0x04` (no CBOR body); the
/// response is one CBOR map with integer keys, parsed into
/// [`AuthenticatorInfo`]. SELECT is always sent first; re-SELECT is
/// idempotent for FIDO and does not invalidate pinUvAuthTokens. This
/// operation is read-only and has no card-side effects.
///
/// # Errors
/// A non-success CTAP status byte is classified in the Command phase with
/// the raw byte retained in `Error::status_word`. A response missing
/// `versions` or `aaguid`, mistyped members, or malformed CBOR fails as
/// [`ErrorKind::InvalidResponse`] in [`Phase::Parsing`].
pub fn get_info(options: OperationOptions) -> Result<Operation<AuthenticatorInfo>, Error> {
    select_then(&[COMMAND_GET_INFO], options, |response| {
        typed(response, parse_get_info)
    })
}

/// Create a credential: authenticatorMakeCredential (0x01).
///
/// Wire format: `0x01` followed by the canonical CBOR map with keys 1
/// (clientDataHash), 2 (rp), 3 (user), 4 (pubKeyCredParams), and optionally
/// 5 (excludeList, omitted when empty), 6 (extensions), 7 (options, omitted
/// when empty), 8/9 (pinUvAuthParam/pinUvAuthProtocol) and 10
/// (enterpriseAttestation). SELECT is always sent first; re-SELECT is
/// idempotent for FIDO and does not invalidate pinUvAuthTokens.
///
/// This operation can mutate card state: with a discoverable-credential
/// (`rk`) option it stores a resident credential, and it always requires user
/// presence. Relevant CTAP statuses include 0x19 CREDENTIAL_EXCLUDED (an
/// exclude-list credential already exists, mapped to
/// [`ErrorKind::ConditionsNotSatisfied`]), 0x27 OPERATION_DENIED (user touch
/// denied), 0x26 UNSUPPORTED_ALGORITHM, and 0x2E NO_CREDENTIALS when no PIN
/// is set but UV was requested.
///
/// # Errors
/// Construction fails before any I/O with [`ErrorKind::InvalidArgument`]
/// when `rp.id` is empty, `user.id` is empty or longer than
/// [`MAX_USER_ID_LEN`] bytes, `pub_key_cred_params` is empty,
/// `enterprise_attestation` is not 1 or 2, a raw `extensions` entry repeats
/// the key of a typed extension field that is also set (`"hmac-secret"` /
/// `"hmac-secret-mc"`), or `hmac_secret_mc` is set without `hmac_secret`.
/// Response failures follow [`get_info`]; a response missing `fmt`,
/// `authData` or a text-keyed `attStmt` is [`ErrorKind::InvalidResponse`] in
/// [`Phase::Parsing`]. When the hmac-secret-mc exchange was requested, a
/// response whose authData lacks the encrypted `"hmac-secret-mc"` output is
/// likewise [`ErrorKind::InvalidResponse`].
pub fn make_credential(
    params: MakeCredentialParams,
    options: OperationOptions,
) -> Result<Operation<MakeCredentialResponse>, Error> {
    let raw_extension = |name: &str| params.extensions.iter().any(|(key, _)| key == name);
    if params.rp.id.is_empty()
        || params.user.id.is_empty()
        || params.user.id.len() > MAX_USER_ID_LEN
        || params.pub_key_cred_params.is_empty()
        || matches!(params.enterprise_attestation, Some(n) if !(1..=2).contains(&n))
        || (params.hmac_secret && raw_extension(EXT_HMAC_SECRET))
    {
        return Err(invalid_argument());
    }
    #[cfg(feature = "clientpin")]
    if params.hmac_secret_mc.is_some() && (!params.hmac_secret || raw_extension(EXT_HMAC_SECRET_MC))
    {
        // The firmware requires "hmac-secret": true alongside
        // "hmac-secret-mc" (CTAP2_ERR_MISSING_PARAMETER otherwise); a raw
        // duplicate of either key would fail in our own strict parser.
        return Err(invalid_argument());
    }
    let mut entries = vec![
        (
            Value::Unsigned(1),
            Value::Bytes(params.client_data_hash.to_vec()),
        ),
        (Value::Unsigned(2), params.rp.to_value()),
        (Value::Unsigned(3), params.user.to_value()),
        (
            Value::Unsigned(4),
            Value::Array(
                params
                    .pub_key_cred_params
                    .iter()
                    .map(|algorithm| {
                        Value::Map(vec![
                            (
                                Value::Text("type".to_owned()),
                                Value::Text("public-key".to_owned()),
                            ),
                            (
                                Value::Text("alg".to_owned()),
                                Value::from_int(algorithm.id()),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
    ];
    if !params.exclude_list.is_empty() {
        entries.push((
            Value::Unsigned(5),
            Value::Array(params.exclude_list.iter().map(|d| d.to_value()).collect()),
        ));
    }
    let mut extensions = params.extensions.clone();
    if params.hmac_secret {
        extensions.push((EXT_HMAC_SECRET.to_owned(), Value::Bool(true)));
    }
    #[cfg(feature = "clientpin")]
    if let Some(input) = &params.hmac_secret_mc {
        // Canonical ordering places "hmac-secret" before "hmac-secret-mc".
        extensions.push((EXT_HMAC_SECRET_MC.to_owned(), input.to_value()));
    }
    if !extensions.is_empty() {
        entries.push((Value::Unsigned(6), extension_map(&extensions)));
    }
    if !params.options.is_empty() {
        entries.push((Value::Unsigned(7), option_map(&params.options)));
    }
    if let Some(pin_uv_auth) = &params.pin_uv_auth {
        entries.push((
            Value::Unsigned(8),
            Value::Bytes(pin_uv_auth.param.as_bytes().to_vec()),
        ));
        entries.push((
            Value::Unsigned(9),
            Value::Unsigned(u64::from(pin_uv_auth.protocol.to_u8())),
        ));
    }
    if let Some(enterprise_attestation) = params.enterprise_attestation {
        entries.push((
            Value::Unsigned(10),
            Value::Unsigned(u64::from(enterprise_attestation)),
        ));
    }
    let mut message = vec![COMMAND_MAKE_CREDENTIAL];
    message.extend_from_slice(&cbor::encode(&Value::Map(entries))?);
    // The parser needs the exchange's shared secret to decrypt the
    // authenticator's encrypted hmac-secret-mc output.
    #[cfg(feature = "clientpin")]
    let hmac_secret_mc = params.hmac_secret_mc;
    #[cfg(feature = "clientpin")]
    return select_then(&message, options, move |response| {
        typed(response, |bytes| {
            parse_make_credential(bytes, hmac_secret_mc.as_ref())
        })
    });
    #[cfg(not(feature = "clientpin"))]
    select_then(&message, options, |response| {
        typed(response, parse_make_credential)
    })
}

/// Sign an assertion: authenticatorGetAssertion (0x02).
///
/// Wire format: `0x02` followed by the canonical CBOR map with keys 1
/// (rpId), 2 (clientDataHash), and optionally 3 (allowList, omitted when
/// empty), 4 (extensions), 5 (options, omitted when empty) and 6/7
/// (pinUvAuthParam/pinUvAuthProtocol). SELECT is always sent first;
/// re-SELECT is idempotent for FIDO and does not invalidate pinUvAuthTokens.
///
/// An empty allow list exercises discoverable (resident) credentials. The
/// response's `number_of_credentials` tells the caller how many assertions
/// exist; collect the rest with [`get_next_assertion`]. Relevant CTAP
/// statuses include 0x2E NO_CREDENTIALS (no credential for this RP, mapped
/// to [`ErrorKind::NotFound`]), 0x22 INVALID_CREDENTIAL (allow-list entries
/// not recognized, also [`ErrorKind::NotFound`]), and 0x27 OPERATION_DENIED.
///
/// # Errors
/// Construction fails before any I/O with [`ErrorKind::InvalidArgument`]
/// when `rp_id` is empty or a raw `extensions` entry repeats
/// `"hmac-secret"` while the typed `hmac_secret` field is also set.
/// Response failures follow [`get_info`]; a response missing `authData` or
/// `signature` is [`ErrorKind::InvalidResponse`] in [`Phase::Parsing`]. When
/// the hmac-secret exchange was requested, a response whose authData lacks
/// the encrypted `"hmac-secret"` output is likewise
/// [`ErrorKind::InvalidResponse`].
pub fn get_assertion(
    params: GetAssertionParams,
    options: OperationOptions,
) -> Result<Operation<GetAssertionResponse>, Error> {
    if params.rp_id.is_empty() {
        return Err(invalid_argument());
    }
    #[cfg(feature = "clientpin")]
    if params.hmac_secret.is_some()
        && params
            .extensions
            .iter()
            .any(|(key, _)| key == EXT_HMAC_SECRET)
    {
        // A duplicate "hmac-secret" key would fail in our own strict parser.
        return Err(invalid_argument());
    }
    let mut entries = vec![
        (Value::Unsigned(1), Value::Text(params.rp_id.clone())),
        (
            Value::Unsigned(2),
            Value::Bytes(params.client_data_hash.to_vec()),
        ),
    ];
    if !params.allow_list.is_empty() {
        entries.push((
            Value::Unsigned(3),
            Value::Array(params.allow_list.iter().map(|d| d.to_value()).collect()),
        ));
    }
    #[cfg(feature = "clientpin")]
    let mut extensions = params.extensions.clone();
    #[cfg(not(feature = "clientpin"))]
    let extensions = params.extensions.clone();
    #[cfg(feature = "clientpin")]
    if let Some(input) = &params.hmac_secret {
        extensions.push((EXT_HMAC_SECRET.to_owned(), input.to_value()));
    }
    if !extensions.is_empty() {
        entries.push((Value::Unsigned(4), extension_map(&extensions)));
    }
    if !params.options.is_empty() {
        entries.push((Value::Unsigned(5), option_map(&params.options)));
    }
    if let Some(pin_uv_auth) = &params.pin_uv_auth {
        entries.push((
            Value::Unsigned(6),
            Value::Bytes(pin_uv_auth.param.as_bytes().to_vec()),
        ));
        entries.push((
            Value::Unsigned(7),
            Value::Unsigned(u64::from(pin_uv_auth.protocol.to_u8())),
        ));
    }
    let mut message = vec![COMMAND_GET_ASSERTION];
    message.extend_from_slice(&cbor::encode(&Value::Map(entries))?);
    // The parser needs the exchange's shared secret to decrypt the
    // authenticator's encrypted hmac-secret output.
    #[cfg(feature = "clientpin")]
    let hmac_secret = params.hmac_secret;
    #[cfg(feature = "clientpin")]
    return select_then(&message, options, move |response| {
        typed(response, |bytes| {
            parse_get_assertion(bytes, hmac_secret.as_ref())
        })
    });
    #[cfg(not(feature = "clientpin"))]
    select_then(&message, options, |response| {
        typed(response, parse_get_assertion)
    })
}

/// Collect the next assertion of a multi-credential getAssertion:
/// authenticatorGetNextAssertion (0x08).
///
/// Wire format: the single byte `0x08` (no CBOR body). Issue this only after
/// a getAssertion response whose `number_of_credentials` exceeds the number
/// of assertions already collected; the response has the same shape as
/// [`get_assertion`]. CTAP 0x2E NO_CREDENTIALS ([`ErrorKind::NotFound`])
/// means no further assertions exist.
///
/// Note: a getNextAssertion response can also carry an hmac-secret exchange
/// output for its credential, but this operation has no exchange context to
/// decrypt it with; the raw value remains available through
/// [`AuthenticatorData::extensions`].
///
/// # Errors
/// See [`get_assertion`].
pub fn get_next_assertion(
    options: OperationOptions,
) -> Result<Operation<GetAssertionResponse>, Error> {
    select_then(&[COMMAND_GET_NEXT_ASSERTION], options, |response| {
        typed(response, |bytes| {
            parse_get_assertion(
                bytes,
                #[cfg(feature = "clientpin")]
                None,
            )
        })
    })
}

/// Reset the whole FIDO authenticator state: authenticatorReset (0x07).
///
/// Wire format: the single byte `0x07` (no CBOR body); a successful response
/// has no payload (any payload is [`ErrorKind::InvalidResponse`]).
///
/// **This wipes all FIDO state on the device**: every credential, the PIN
/// and all pinUvAuthTokens. Authenticators typically require the command
/// within seconds of power-up plus a user-presence touch; failures surface
/// as 0x30 NOT_ALLOWED or 0x2F USER_ACTION_TIMEOUT (both
/// [`ErrorKind::ConditionsNotSatisfied`]). Nothing is retried automatically.
///
/// # Errors
/// See [`get_info`]; a non-empty successful payload is
/// [`ErrorKind::InvalidResponse`] in [`Phase::Parsing`].
pub fn reset(options: OperationOptions) -> Result<Operation<()>, Error> {
    select_then(&[COMMAND_RESET], options, |response| {
        typed(response, empty_payload)
    })
}

/// Ask the authenticator to identify itself to the user:
/// authenticatorSelection (0x0B).
///
/// Wire format: the single byte `0x0B` (no CBOR body); a successful response
/// has no payload (any payload is [`ErrorKind::InvalidResponse`]). The
/// authenticator typically blinks or beeps; there is no other effect.
///
/// # Errors
/// See [`reset`].
pub fn selection(options: OperationOptions) -> Result<Operation<()>, Error> {
    select_then(&[COMMAND_SELECTION], options, |response| {
        typed(response, empty_payload)
    })
}
