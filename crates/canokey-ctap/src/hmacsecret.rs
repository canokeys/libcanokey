//! The hmac-secret extension (CTAP 2.x) and the CanoKey hmac-secret-mc variant.
//!
//! The plain hmac-secret *declaration* in makeCredential (`"hmac-secret":
//! true`, a boolean both ways) is dependency-free and lives in [`ctap2`]; see
//! [`MakeCredentialParams::hmac_secret`] and
//! [`MakeCredentialResponse::hmac_secret_supported`]. This module implements
//! the encrypted salt *exchange* used by getAssertion (`"hmac-secret"`) and by
//! the CanoKey-specific makeCredential variant (`"hmac-secret-mc"`).
//!
//! # Wire format
//!
//! The exchange input is a CBOR map under the extension key with integer
//! keys: 1 = keyAgreement (the platform's COSE key), 2 = saltEnc, 3 =
//! saltAuth, 4 = pinUvAuthProtocol. The platform performs the same pin/UV
//! protocol encapsulation as authenticatorClientPIN against a session
//! established with `get_key_agreement` (module `pin`, feature
//! `clientpin`): `saltEnc = encrypt(shared, salt1 || salt2?)` (one 32-byte
//! salt or two concatenated salts) and `saltAuth = authenticate(shared,
//! saltEnc)` with the 16-byte (V1) or 32-byte (V2) width. This library
//! always sends key 4; the CanoKey firmware accepts it as optional
//! (defaulting to protocol 1).
//!
//! The output arrives in the authData ED extensions as a byte string under
//! the same key ("hmac-secret" for getAssertion, "hmac-secret-mc" for the
//! makeCredential variant), encrypted with the session's shared secret: 32
//! bytes (one salt) or 64 bytes (two salts) for protocol V1, prefixed with a
//! 16-byte IV (48/80 bytes total) for protocol V2. The response parsers
//! decrypt it during parsing when the exchange was requested.
//!
//! # Firmware notes (CanoKey)
//!
//! - The exchange requires a pin/UV protocol key agreement only; it does NOT
//!   require a PIN to be set on the device (key agreement is independent of
//!   the PIN state).
//! - hmac-secret-mc additionally requires `"hmac-secret": true` in the same
//!   makeCredential extensions map, otherwise the firmware fails with
//!   CTAP2_ERR_MISSING_PARAMETER; [`MakeCredentialParams`] enforces this
//!   before any I/O.
//! - getAssertion with the hmac-secret extension rejects the `up: false`
//!   option with CTAP2_ERR_UNSUPPORTED_OPTION.
//! - An authenticator that accepted the exchange but omits the extension
//!   output from authData violates the protocol; the parsers surface this as
//!   [`ErrorKind::InvalidResponse`] rather than a silent `None`.
//!
//! # Secrets
//!
//! Salts, the shared secret and the decrypted outputs are secret. They are
//! held in [`SecretBytes`]/zeroizing buffers and redacted in Debug.
//!
//! [`ctap2`]: crate::ctap2
//! [`MakeCredentialParams`]: crate::ctap2::MakeCredentialParams
//! [`MakeCredentialParams::hmac_secret`]: crate::ctap2::MakeCredentialParams::hmac_secret
//! [`MakeCredentialResponse::hmac_secret_supported`]: crate::ctap2::MakeCredentialResponse::hmac_secret_supported

use crate::authdata::AuthenticatorData;
#[cfg(feature = "clientpin")]
use crate::cbor::Value;
#[cfg(feature = "clientpin")]
use crate::cose::CoseKey;
use crate::ctap2;
#[cfg(feature = "clientpin")]
use crate::pin::{self, PinSession};
#[cfg(feature = "clientpin")]
use crate::PinUvAuthProtocol;
use canokey_protocol::{Error, ErrorKind, Phase, SecretBytes};
use std::fmt;

/// The length of one hmac-secret salt (CTAP2); one or two salts are sent.
pub const SALT_LEN: usize = 32;

fn invalid() -> Error {
    Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing)
}
fn invalid_argument() -> Error {
    Error::new(ErrorKind::InvalidArgument)
}

/// The salts for one hmac-secret exchange: one 32-byte salt or two
/// concatenated 32-byte salts. Redacted in Debug and zeroized on drop.
#[derive(Clone)]
pub struct HmacSecretSalts(SecretBytes);
impl HmacSecretSalts {
    /// Copy salts from a byte string of exactly 32 bytes (one salt) or 64
    /// bytes (two salts).
    ///
    /// # Errors
    /// Any other length fails as [`ErrorKind::InvalidArgument`] before any
    /// I/O.
    pub fn new(salts: &[u8]) -> Result<Self, Error> {
        if salts.len() != SALT_LEN && salts.len() != 2 * SALT_LEN {
            return Err(invalid_argument());
        }
        Ok(Self(SecretBytes::new(salts.to_vec())))
    }
    /// Build from a single 32-byte salt.
    pub fn one(salt: [u8; SALT_LEN]) -> Self {
        Self(SecretBytes::new(salt.to_vec()))
    }
    /// Build from two 32-byte salts, sent concatenated as `first || second`.
    pub fn two(first: [u8; SALT_LEN], second: [u8; SALT_LEN]) -> Self {
        let mut salts = Vec::with_capacity(2 * SALT_LEN);
        salts.extend_from_slice(&first);
        salts.extend_from_slice(&second);
        Self(SecretBytes::new(salts))
    }
    /// Return the number of salts (1 or 2).
    pub fn count(&self) -> usize {
        self.0.as_bytes().len() / SALT_LEN
    }
    /// Borrow the concatenated salt bytes (32 or 64 bytes).
    #[cfg(feature = "clientpin")]
    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}
impl fmt::Debug for HmacSecretSalts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("HmacSecretSalts")
            .field(&"[REDACTED]")
            .finish()
    }
}

/// The platform's prepared input for one hmac-secret salt exchange, in
/// getAssertion (`"hmac-secret"`) or the CanoKey makeCredential variant
/// (`"hmac-secret-mc"`).
///
/// The exchange reuses an established pin/UV protocol session: construction
/// copies the session's protocol, platform key-agreement key and shared
/// secret, then computes `saltEnc` and `saltAuth` exactly as the firmware
/// expects (see the module documentation). The same session can later
/// authenticate the surrounding command with a pinUvAuthToken; key agreement
/// itself does not require a PIN to be set on the device.
///
/// The prepared ciphertext and authenticator are retained so the response
/// parser can decrypt the authenticator's encrypted output with the same
/// shared secret. All secret material is redacted in Debug and zeroized on
/// drop.
#[cfg(feature = "clientpin")]
#[derive(Clone)]
pub struct HmacSecretInput {
    protocol: PinUvAuthProtocol,
    key_agreement: CoseKey,
    shared_secret: SecretBytes,
    salt_enc: Vec<u8>,
    salt_auth: SecretBytes,
}
#[cfg(feature = "clientpin")]
impl HmacSecretInput {
    /// Prepare the exchange against `session` for `salts`.
    ///
    /// # Randomness
    ///
    /// The ephemeral scalar was already supplied to
    /// [`get_key_agreement`](crate::pin::get_key_agreement) when `session`
    /// was established. Protocol V2 additionally requires `iv` to be a fresh
    /// 16-byte CSPRNG value used to encrypt the salts; protocol V1 requires
    /// `iv` to be `None` (V1 uses a zero IV by specification).
    ///
    /// # Errors
    /// A missing IV under V2 or a present IV under V1 fails as
    /// [`ErrorKind::InvalidArgument`] before any I/O.
    pub fn new(
        session: &PinSession,
        salts: HmacSecretSalts,
        iv: Option<&[u8; 16]>,
    ) -> Result<Self, Error> {
        pin::check_iv(session.protocol(), iv)?;
        let protocol = session.protocol();
        let shared_secret = session.shared_secret().clone();
        let salt_enc = pin::encrypt(protocol, shared_secret.as_bytes(), iv, salts.as_bytes())?;
        let salt_auth = pin::authenticate(protocol, shared_secret.as_bytes(), &salt_enc);
        Ok(Self {
            protocol,
            key_agreement: session.key_agreement().clone(),
            shared_secret,
            salt_enc,
            salt_auth,
        })
    }
    /// Return the pin/UV auth protocol this exchange was prepared with.
    pub fn protocol(&self) -> PinUvAuthProtocol {
        self.protocol
    }
    /// Encode the extension input map `{1: keyAgreement, 2: saltEnc,
    /// 3: saltAuth, 4: pinUvAuthProtocol}`.
    pub(crate) fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::Unsigned(1), self.key_agreement.to_value()),
            (Value::Unsigned(2), Value::Bytes(self.salt_enc.clone())),
            (
                Value::Unsigned(3),
                Value::Bytes(self.salt_auth.as_bytes().to_vec()),
            ),
            (
                Value::Unsigned(4),
                Value::Unsigned(u64::from(self.protocol.to_u8())),
            ),
        ])
    }
    /// Decrypt the authenticator's extension output with the session's
    /// shared secret. The plaintext must be exactly 32 bytes (one salt) or
    /// 64 bytes (two salts); any other framing or length is
    /// [`ErrorKind::InvalidResponse`].
    fn decrypt_output(&self, ciphertext: &[u8]) -> Result<SecretBytes, Error> {
        let plaintext = pin::decrypt(self.protocol, self.shared_secret.as_bytes(), ciphertext)?;
        let len = plaintext.as_bytes().len();
        if len != SALT_LEN && len != 2 * SALT_LEN {
            return Err(invalid());
        }
        Ok(plaintext)
    }
}
#[cfg(feature = "clientpin")]
impl fmt::Debug for HmacSecretInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HmacSecretInput")
            .field("protocol", &self.protocol)
            .field("key_agreement", &self.key_agreement)
            .field("shared_secret", &"[REDACTED]")
            .field("salt_enc", &"[REDACTED]")
            .field("salt_auth", &"[REDACTED]")
            .finish()
    }
}

/// Extract and decrypt an hmac-secret exchange output (`key` =
/// "hmac-secret" for getAssertion, "hmac-secret-mc" for the makeCredential
/// variant) from the authData ED extensions.
///
/// When the exchange was requested (`input` is `Some`), a missing ED
/// section, a missing key, a non-byte-string value, or a decryption/length
/// failure is [`ErrorKind::InvalidResponse`]: an authenticator that accepted
/// the extension must not silently drop the output. When no exchange was
/// requested the key is left untouched in
/// [`AuthenticatorData::extensions`].
#[cfg(feature = "clientpin")]
pub(crate) fn exchange_output(
    auth_data: &AuthenticatorData,
    key: &str,
    input: Option<&HmacSecretInput>,
) -> Result<Option<SecretBytes>, Error> {
    let value = auth_data
        .extensions()
        .and_then(|extensions| extensions.map_get_text(key));
    match (input, value) {
        (Some(input), Some(value)) => {
            let ciphertext = value.as_bytes().ok_or_else(invalid)?;
            Ok(Some(input.decrypt_output(ciphertext)?))
        }
        (Some(_), None) => Err(invalid()),
        (None, _) => Ok(None),
    }
}

/// Parse the makeCredential hmac-secret declaration output
/// (`"hmac-secret": true`) from the authData ED extensions. Absent means
/// not supported; a present non-boolean value is malformed.
pub(crate) fn declaration_supported(auth_data: &AuthenticatorData) -> Result<bool, Error> {
    match auth_data
        .extensions()
        .and_then(|extensions| extensions.map_get_text(ctap2::EXT_HMAC_SECRET))
    {
        None => Ok(false),
        Some(value) => value.as_bool().ok_or_else(invalid),
    }
}
