//! authenticatorClientPIN (0x06): PIN protocol v1 and v2 cryptography.
//!
//! This module implements the CTAP2 ClientPIN protocol on the host side:
//! key agreement over P-256 ECDH, shared-secret derivation (SHA-256 for
//! protocol V1, HKDF-SHA-256 with separate HMAC/AES halves for V2), AES-256
//! CBC PIN encryption, pinUvAuthParam HMACs, and PIN retry reporting. Every
//! operation sends the explicit SELECT of the FIDO2 application followed by
//! one wrapped `0x06` message; a non-success CTAP status byte is classified
//! in the Command phase with the raw byte retained in `Error::status_word`
//! (for example 0x31 PIN_INVALID maps to [`ErrorKind::InvalidPin`]).
//!
//! # Randomness
//!
//! This module never generates randomness. The caller supplies the ephemeral
//! P-256 scalar for [`get_key_agreement`] (32 CSPRNG bytes) and, for protocol
//! V2, a fresh 16-byte IV for every `set_pin`/`change_pin`/`get_pin_token*`
//! call. Reusing an IV under V2 breaks CBC security.
//!
//! # Secrets
//!
//! PINs are copied into zeroizing buffers immediately; the padded PIN, PIN
//! hash and shared-secret halves are zeroized intermediates. [`PinSession`]
//! and [`PinToken`] redact their key material in Debug and zeroize on drop.
//! The CanoKey firmware counts PIN length in Unicode code points; PIN
//! validation here rejects fewer than 4 code points, more than 63 UTF-8
//! bytes, and invalid UTF-8 before any I/O.
//!
//! # CanoKey firmware notes
//!
//! Both pin/UV auth protocols are supported. Legacy `getPinToken` (0x05)
//! rejects permissions/rpId parameters, so [`get_pin_token`] sends neither;
//! [`get_pin_token_with_permissions`] uses subcommand 0x09. An unknown
//! clientPIN subcommand is a firmware quirk that returns empty success, so
//! token responses always require the encrypted token field.

use crate::cbor::{self, Value};
use crate::cose::{CoseAlgorithm, CoseKey};
use crate::{select_then, CtapResponse, PinUvAuthProtocol};
use aes::Aes256;
use canokey_protocol::{Error, ErrorKind, Operation, OperationOptions, Phase, SecretBytes};
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};
use std::fmt;
use std::ops::BitOr;
use zeroize::Zeroizing;

const COMMAND_CLIENT_PIN: u8 = 0x06;
const SUBCOMMAND_GET_PIN_RETRIES: u8 = 0x01;
const SUBCOMMAND_GET_KEY_AGREEMENT: u8 = 0x02;
const SUBCOMMAND_SET_PIN: u8 = 0x03;
const SUBCOMMAND_CHANGE_PIN: u8 = 0x04;
const SUBCOMMAND_GET_PIN_TOKEN: u8 = 0x05;
const SUBCOMMAND_GET_PIN_TOKEN_WITH_PERMISSIONS: u8 = 0x09;
/// padPin output width: the UTF-8 PIN zero-padded to exactly 64 bytes.
const PADDED_PIN_LEN: usize = 64;
/// Maximum UTF-8 byte length of a PIN (CTAP2); also the firmware default.
const MAX_PIN_BYTES: usize = 63;
/// Minimum PIN length in Unicode code points (the firmware counts code
/// points, not bytes).
const MIN_PIN_CODE_POINTS: usize = 4;
/// HKDF-SHA-256 salt for protocol V2 shared-secret derivation.
const HKDF_SALT: [u8; 32] = [0u8; 32];
/// HKDF info string for the protocol V2 HMAC key half.
const HKDF_INFO_HMAC: &[u8] = b"CTAP2 HMAC key";
/// HKDF info string for the protocol V2 AES key half.
const HKDF_INFO_AES: &[u8] = b"CTAP2 AES key";

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

fn invalid() -> Error {
    Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing)
}
fn invalid_argument() -> Error {
    Error::new(ErrorKind::InvalidArgument)
}
fn invalid_pin() -> Error {
    Error::new(ErrorKind::InvalidPin)
}
fn required(value: Option<&Value>) -> Result<&Value, Error> {
    value.ok_or_else(invalid)
}

/// Classify the CTAP status byte, then parse the response payload.
fn typed<T>(
    response: CtapResponse,
    parse: impl FnOnce(&[u8]) -> Result<T, Error>,
) -> Result<T, Error> {
    if let Some(error) = response.status().into_error(Phase::Command) {
        return Err(error);
    }
    parse(response.payload())
}

/// Require an empty response payload, as CTAP2 specifies for setPIN and
/// changePIN.
fn empty_payload(bytes: &[u8]) -> Result<(), Error> {
    if bytes.is_empty() {
        Ok(())
    } else {
        Err(invalid())
    }
}

/// A pinUvAuthToken permission bitfield (CTAP2 `permissions` parameter).
///
/// Permission bits combine with `|` and round-trip through
/// [`Self::bits`]/[`Self::from_bits`]; unknown bits are preserved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permissions(u8);
impl Permissions {
    /// makeCredential permission (0x01).
    pub const MAKE_CREDENTIAL: Self = Self(0x01);
    /// getAssertion permission (0x02).
    pub const GET_ASSERTION: Self = Self(0x02);
    /// credentialManagement permission (0x04).
    pub const CREDENTIAL_MANAGEMENT: Self = Self(0x04);
    /// bioEnrollment permission (0x08).
    pub const BIO_ENROLLMENT: Self = Self(0x08);
    /// largeBlobWrite permission (0x10).
    pub const LARGE_BLOB_WRITE: Self = Self(0x10);
    /// authenticatorConfig permission (0x20).
    pub const AUTHENTICATOR_CONFIG: Self = Self(0x20);
    /// Wrap a raw permission bitfield, preserving unknown bits.
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }
    /// Return the raw permission bitfield.
    pub const fn bits(self) -> u8 {
        self.0
    }
}
impl BitOr for Permissions {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// The PIN retry counter reported by getPinRetries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinRetries {
    /// Remaining PIN retries (response key 3).
    pub pin_retries: u32,
    /// The authenticator's power-cycle state (response key 4) when present.
    pub power_cycle_state: Option<bool>,
}

/// Caller-owned key-agreement result: the protocol, the platform's own COSE
/// key to embed in subsequent clientPIN requests, and the shared secret.
///
/// The shared secret is redacted in Debug and zeroized on drop. A session
/// stays valid until the authenticator's key-agreement key rotates (the
/// firmware regenerates it on power-up); request new tokens from the same
/// session with [`get_pin_token`] or [`get_pin_token_with_permissions`].
pub struct PinSession {
    protocol: PinUvAuthProtocol,
    key_agreement: CoseKey,
    shared_secret: SecretBytes,
}
impl PinSession {
    /// Return the pin/UV auth protocol this session was established with.
    pub fn protocol(&self) -> PinUvAuthProtocol {
        self.protocol
    }
    /// Return the platform's own key-agreement COSE key, as embedded in
    /// every clientPIN request derived from this session. Public material.
    pub fn key_agreement(&self) -> &CoseKey {
        &self.key_agreement
    }
    /// Borrow the shared secret: 32 bytes for protocol V1, 64 bytes for
    /// protocol V2 (bytes 0..32 the HMAC key, bytes 32..64 the AES key).
    /// Avoid logging or unmanaged copies.
    pub fn shared_secret(&self) -> &SecretBytes {
        &self.shared_secret
    }
}
impl fmt::Debug for PinSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinSession")
            .field("protocol", &self.protocol)
            .field("key_agreement", &self.key_agreement)
            .field("shared_secret", &"[REDACTED]")
            .finish()
    }
}

/// A decrypted pinUvAuthToken. Redacted in Debug and zeroized on drop.
///
/// Tokens are ceremony-scoped: per CTAP 2.1 the authenticator clears all
/// permissions except largeBlobWrite after the token is used for a
/// makeCredential or getAssertion, so obtain a fresh token for each ceremony
/// instead of caching one. Tokens also expire on a firmware timer and on
/// power cycles.
pub struct PinToken(SecretBytes);
impl PinToken {
    /// Borrow the decrypted token bytes. Avoid logging or unmanaged copies.
    pub fn token(&self) -> &SecretBytes {
        &self.0
    }
    /// Compute a pinUvAuthParam over `message` with this token.
    ///
    /// Protocol V1 returns the first 16 bytes of HMAC-SHA-256 over the full
    /// token. Protocol V2 uses the token's first 32 bytes directly as the
    /// HMAC key and returns the full 32-byte HMAC-SHA-256 output.
    pub fn authenticate(&self, protocol: PinUvAuthProtocol, message: &[u8]) -> SecretBytes {
        authenticate(protocol, self.0.as_bytes(), message)
    }
}
impl fmt::Debug for PinToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PinToken").field(&"[REDACTED]").finish()
    }
}

/// Validate a PIN before any I/O: 4..=63 Unicode code points, at most 63
/// UTF-8 bytes, valid UTF-8. The firmware counts code points.
fn validate_pin(pin: &[u8]) -> Result<(), Error> {
    let text = std::str::from_utf8(pin).map_err(|_| invalid_pin())?;
    if pin.len() > MAX_PIN_BYTES || text.chars().count() < MIN_PIN_CODE_POINTS {
        return Err(invalid_pin());
    }
    Ok(())
}

/// Protocol V2 requires a caller-supplied IV; protocol V1 rejects one.
fn check_iv(protocol: PinUvAuthProtocol, iv: Option<&[u8; 16]>) -> Result<(), Error> {
    if (protocol == PinUvAuthProtocol::V2) != iv.is_some() {
        return Err(invalid_argument());
    }
    Ok(())
}

/// padPin: UTF-8 PIN bytes zero-padded to exactly 64 bytes.
fn pad_pin(pin: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut padded = Zeroizing::new(vec![0u8; PADDED_PIN_LEN]);
    padded[..pin.len()].copy_from_slice(pin);
    padded
}

/// LEFT(SHA-256(pin), 16), the plaintext wrapped as pinHashEnc.
fn pin_hash(pin: &[u8]) -> Zeroizing<Vec<u8>> {
    let digest = Sha256::digest(pin);
    Zeroizing::new(digest[..16].to_vec())
}

/// Derive the shared secret from the ECDH x-coordinate: V1 is SHA-256(x);
/// V2 is the HKDF-SHA-256 "CTAP2 HMAC key" and "CTAP2 AES key" halves.
fn derive_shared_secret(protocol: PinUvAuthProtocol, ecdh_x: &[u8; 32]) -> SecretBytes {
    if protocol == PinUvAuthProtocol::V1 {
        SecretBytes::new(Sha256::digest(ecdh_x).to_vec())
    } else {
        let hk = Hkdf::<Sha256>::new(Some(&HKDF_SALT), ecdh_x);
        let mut half = Zeroizing::new([0u8; 32]);
        let mut secret = Vec::with_capacity(64);
        hk.expand(HKDF_INFO_HMAC, half.as_mut())
            .expect("32 bytes are within the HKDF-SHA-256 output limit");
        secret.extend_from_slice(half.as_ref());
        hk.expand(HKDF_INFO_AES, half.as_mut())
            .expect("32 bytes are within the HKDF-SHA-256 output limit");
        secret.extend_from_slice(half.as_ref());
        SecretBytes::new(secret)
    }
}

/// HMAC-SHA-256 with the protocol's key selection and output width: V1 uses
/// the whole key and truncates to 16 bytes; V2 uses key[0..32] and returns
/// the full 32 bytes.
fn authenticate(protocol: PinUvAuthProtocol, key: &[u8], message: &[u8]) -> SecretBytes {
    let key = if protocol == PinUvAuthProtocol::V2 && key.len() > 32 {
        &key[..32]
    } else {
        key
    };
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC-SHA-256 accepts keys of any length");
    mac.update(message);
    let tag = mac.finalize().into_bytes();
    if protocol == PinUvAuthProtocol::V1 {
        SecretBytes::new(tag[..16].to_vec())
    } else {
        SecretBytes::new(tag.to_vec())
    }
}

/// AES-256-CBC with NoPadding; `plaintext` must be block-aligned (padPin
/// and the PIN hash are, by construction). V1 uses the shared secret as the
/// key and a zero IV; V2 uses bytes 32..64 as the key and the caller's IV,
/// with the wire value `IV || ciphertext`.
fn encrypt(
    protocol: PinUvAuthProtocol,
    shared_secret: &[u8],
    iv: Option<&[u8; 16]>,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let (key, iv) = if protocol == PinUvAuthProtocol::V1 {
        (
            shared_secret.get(..32).ok_or_else(invalid_argument)?,
            [0u8; 16],
        )
    } else {
        (
            shared_secret.get(32..64).ok_or_else(invalid_argument)?,
            *iv.ok_or_else(invalid_argument)?,
        )
    };
    let cipher = Aes256CbcEnc::new_from_slices(key, &iv).map_err(|_| invalid_argument())?;
    let mut out = vec![0u8; plaintext.len()];
    cipher
        .encrypt_padded_b2b_mut::<NoPadding>(plaintext, &mut out)
        .map_err(|_| invalid_argument())?;
    if protocol == PinUvAuthProtocol::V1 {
        Ok(out)
    } else {
        let mut wire = iv.to_vec();
        wire.extend_from_slice(&out);
        Ok(wire)
    }
}

/// The inverse of [`encrypt`] for the authenticator's encrypted
/// pinUvAuthToken. Any length, padding or framing violation is
/// [`ErrorKind::InvalidResponse`], never a panic.
fn decrypt_token(
    protocol: PinUvAuthProtocol,
    shared_secret: &[u8],
    ciphertext: &[u8],
) -> Result<SecretBytes, Error> {
    let (key, iv, blocks) = if protocol == PinUvAuthProtocol::V1 {
        if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
            return Err(invalid());
        }
        (
            shared_secret.get(..32).ok_or_else(invalid)?,
            [0u8; 16],
            ciphertext,
        )
    } else {
        if ciphertext.len() < 32 || (ciphertext.len() - 16) % 16 != 0 {
            return Err(invalid());
        }
        let (iv, blocks) = ciphertext.split_at(16);
        let iv: &[u8; 16] = iv.try_into().map_err(|_| invalid())?;
        (shared_secret.get(32..64).ok_or_else(invalid)?, *iv, blocks)
    };
    let cipher = Aes256CbcDec::new_from_slices(key, &iv).map_err(|_| invalid())?;
    let mut out = Zeroizing::new(vec![0u8; blocks.len()]);
    let len = cipher
        .decrypt_padded_b2b_mut::<NoPadding>(blocks, &mut out)
        .map_err(|_| invalid())?
        .len();
    out.truncate(len);
    Ok(SecretBytes::new(out.to_vec()))
}

/// Build the complete clientPIN message: command byte 0x06 followed by the
/// canonical CBOR map.
fn client_pin_message(entries: Vec<(Value, Value)>) -> Vec<u8> {
    let mut message = vec![COMMAND_CLIENT_PIN];
    message.extend_from_slice(&cbor::encode(&Value::Map(entries)));
    message
}

fn uint(value: u64) -> Value {
    Value::Unsigned(value)
}

fn protocol_entry(protocol: PinUvAuthProtocol) -> (Value, Value) {
    (uint(1), uint(u64::from(protocol.to_u8())))
}

/// Start key agreement: clientPIN subcommand 0x02 (getKeyAgreement).
///
/// Wire format: `0x06` followed by the CBOR map `{1: pinUvAuthProtocol,
/// 2: 0x02}`. The response's keyAgreement (key 1) must be an EC2 COSE key
/// with algorithm -25 (ECDH-ES+HKDF-256), curve P-256 and 32-byte x/y, and
/// the point must be a valid P-256 public key; the shared secret is then
/// derived per the protocol (see the module documentation).
///
/// # Randomness
///
/// `ephemeral_scalar` must be 32 bytes from a CSPRNG, used as the platform's
/// ephemeral P-256 secret scalar. It is the caller's responsibility to keep
/// it secret and never reuse it across sessions. A scalar that does not map
/// to a valid non-zero P-256 secret key is rejected before any I/O.
///
/// # Errors
/// An invalid scalar fails as [`ErrorKind::InvalidArgument`]. A response
/// missing key 1, with a non-EC2/ECDH/P-256 key, or with a point that is
/// not a valid P-256 public key fails as [`ErrorKind::InvalidResponse`] in
/// [`Phase::Parsing`]. A non-success CTAP status is classified in the
/// Command phase.
pub fn get_key_agreement(
    protocol: PinUvAuthProtocol,
    ephemeral_scalar: &[u8; 32],
    options: OperationOptions,
) -> Result<Operation<PinSession>, Error> {
    let secret_key =
        p256::SecretKey::from_slice(ephemeral_scalar).map_err(|_| invalid_argument())?;
    let platform_key = {
        let point = secret_key.public_key().to_encoded_point(false);
        let x: [u8; 32] = point
            .x()
            .and_then(|x| x.as_slice().try_into().ok())
            .ok_or_else(invalid_argument)?;
        let y: [u8; 32] = point
            .y()
            .and_then(|y| y.as_slice().try_into().ok())
            .ok_or_else(invalid_argument)?;
        CoseKey::P256 {
            algorithm: CoseAlgorithm::EcdhEsHkdf256,
            x,
            y,
        }
    };
    let message = client_pin_message(vec![
        protocol_entry(protocol),
        (uint(2), uint(u64::from(SUBCOMMAND_GET_KEY_AGREEMENT))),
    ]);
    select_then(&message, options, move |response| {
        typed(response, |bytes| {
            let value = cbor::parse(bytes)?;
            let peer = CoseKey::from_value(required(value.map_get_int(1))?)?;
            let (x, y) = match &peer {
                CoseKey::P256 {
                    algorithm: CoseAlgorithm::EcdhEsHkdf256,
                    x,
                    y,
                } => (*x, *y),
                _ => return Err(invalid()),
            };
            let mut sec1 = [0x04u8; 65];
            sec1[1..33].copy_from_slice(&x);
            sec1[33..].copy_from_slice(&y);
            let peer_public = p256::PublicKey::from_sec1_bytes(&sec1).map_err(|_| invalid())?;
            let shared =
                p256::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), peer_public.as_affine());
            let shared_secret = derive_shared_secret(protocol, shared.raw_secret_bytes().as_ref());
            Ok(PinSession {
                protocol,
                key_agreement: platform_key,
                shared_secret,
            })
        })
    })
}

/// Query the PIN retry counter: clientPIN subcommand 0x01 (getPinRetries).
///
/// Wire format: `0x06` followed by `{1: pinUvAuthProtocol, 2: 0x01}`. The
/// response carries pinRetries (key 3, required) and powerCycleState
/// (key 4, optional). This operation is read-only.
///
/// # Errors
/// A response missing key 3 or with mistyped members fails as
/// [`ErrorKind::InvalidResponse`] in [`Phase::Parsing`].
pub fn get_pin_retries(
    protocol: PinUvAuthProtocol,
    options: OperationOptions,
) -> Result<Operation<PinRetries>, Error> {
    let message = client_pin_message(vec![
        protocol_entry(protocol),
        (uint(2), uint(u64::from(SUBCOMMAND_GET_PIN_RETRIES))),
    ]);
    select_then(&message, options, |response| {
        typed(response, |bytes| {
            let value = cbor::parse(bytes)?;
            let pin_retries = u32::try_from(
                required(value.map_get_int(3))?
                    .as_uint()
                    .ok_or_else(invalid)?,
            )
            .map_err(|_| invalid())?;
            let power_cycle_state = value
                .map_get_int(4)
                .map(|v| v.as_bool().ok_or_else(invalid))
                .transpose()?;
            Ok(PinRetries {
                pin_retries,
                power_cycle_state,
            })
        })
    })
}

/// Set the initial PIN: clientPIN subcommand 0x03 (setPIN).
///
/// Wire format: `0x06` followed by `{1: pinUvAuthProtocol, 2: 0x03,
/// 3: keyAgreement, 4: pinUvAuthParam, 5: newPinEnc}`, where
/// `newPinEnc = encrypt(padPin(new_pin))` (the UTF-8 PIN zero-padded to
/// exactly 64 bytes) and `pinUvAuthParam = authenticate(newPinEnc)`.
/// A successful response has an empty payload. This mutates card state; the
/// card must not have a PIN set already.
///
/// # Randomness
///
/// Protocol V2 requires `iv` to be a fresh 16-byte CSPRNG value; protocol V1
/// requires `iv` to be `None` (V1 uses a zero IV by specification).
///
/// # Errors
/// An invalid PIN (fewer than 4 code points, more than 63 UTF-8 bytes, or
/// invalid UTF-8) fails as [`ErrorKind::InvalidPin`]; a missing IV under V2
/// or a present IV under V1 fails as [`ErrorKind::InvalidArgument`]; both
/// fail before any I/O. A PIN already set surfaces as a classified CTAP
/// status (0x30 NOT_ALLOWED) in the Command phase.
pub fn set_pin(
    session: &PinSession,
    new_pin: &[u8],
    iv: Option<&[u8; 16]>,
    options: OperationOptions,
) -> Result<Operation<()>, Error> {
    validate_pin(new_pin)?;
    check_iv(session.protocol, iv)?;
    let padded = pad_pin(new_pin);
    let new_pin_enc = encrypt(
        session.protocol,
        session.shared_secret.as_bytes(),
        iv,
        &padded,
    )?;
    drop(padded);
    let auth_param = authenticate(
        session.protocol,
        session.shared_secret.as_bytes(),
        &new_pin_enc,
    );
    let message = client_pin_message(vec![
        protocol_entry(session.protocol),
        (uint(2), uint(u64::from(SUBCOMMAND_SET_PIN))),
        (uint(3), session.key_agreement.to_value()),
        (uint(4), Value::Bytes(auth_param.as_bytes().to_vec())),
        (uint(5), Value::Bytes(new_pin_enc)),
    ]);
    select_then(&message, options, |response| typed(response, empty_payload))
}

/// Change the PIN: clientPIN subcommand 0x04 (changePIN).
///
/// Wire format: `0x06` followed by `{1: pinUvAuthProtocol, 2: 0x04,
/// 3: keyAgreement, 4: pinUvAuthParam, 5: newPinEnc, 6: pinHashEnc}`, where
/// `pinHashEnc = encrypt(LEFT(SHA-256(old_pin), 16))`, `newPinEnc =
/// encrypt(padPin(new_pin))` and `pinUvAuthParam = authenticate(newPinEnc ||
/// pinHashEnc)` — note the HMAC input order. A successful response has an
/// empty payload. This mutates card state.
///
/// # Randomness
///
/// Protocol V2 requires `iv` to be a fresh 16-byte CSPRNG value, used for
/// both encryptions of this request; protocol V1 requires `iv` to be `None`.
///
/// # Errors
/// PIN validation and IV rules match [`set_pin`]. A wrong current PIN
/// surfaces as 0x31 PIN_INVALID ([`ErrorKind::InvalidPin`]) from the card.
pub fn change_pin(
    session: &PinSession,
    old_pin: &[u8],
    new_pin: &[u8],
    iv: Option<&[u8; 16]>,
    options: OperationOptions,
) -> Result<Operation<()>, Error> {
    validate_pin(old_pin)?;
    validate_pin(new_pin)?;
    check_iv(session.protocol, iv)?;
    let hash = pin_hash(old_pin);
    let padded = pad_pin(new_pin);
    let pin_hash_enc = encrypt(
        session.protocol,
        session.shared_secret.as_bytes(),
        iv,
        &hash,
    )?;
    let new_pin_enc = encrypt(
        session.protocol,
        session.shared_secret.as_bytes(),
        iv,
        &padded,
    )?;
    drop(hash);
    drop(padded);
    let mut auth_input = new_pin_enc.clone();
    auth_input.extend_from_slice(&pin_hash_enc);
    let auth_param = authenticate(
        session.protocol,
        session.shared_secret.as_bytes(),
        &auth_input,
    );
    let message = client_pin_message(vec![
        protocol_entry(session.protocol),
        (uint(2), uint(u64::from(SUBCOMMAND_CHANGE_PIN))),
        (uint(3), session.key_agreement.to_value()),
        (uint(4), Value::Bytes(auth_param.as_bytes().to_vec())),
        (uint(5), Value::Bytes(new_pin_enc)),
        (uint(6), Value::Bytes(pin_hash_enc)),
    ]);
    select_then(&message, options, |response| typed(response, empty_payload))
}

fn pin_token_entries(
    session: &PinSession,
    subcommand: u8,
    pin_hash_enc: Vec<u8>,
    extra: Vec<(Value, Value)>,
) -> Vec<(Value, Value)> {
    let mut entries = vec![
        protocol_entry(session.protocol),
        (uint(2), uint(u64::from(subcommand))),
        (uint(3), session.key_agreement.to_value()),
        (uint(6), Value::Bytes(pin_hash_enc)),
    ];
    entries.extend(extra);
    entries
}

fn pin_token_operation(
    session: &PinSession,
    message: &[u8],
    options: OperationOptions,
) -> Result<Operation<PinToken>, Error> {
    let protocol = session.protocol;
    let shared_secret = session.shared_secret.clone();
    select_then(message, options, move |response| {
        typed(response, |bytes| {
            let value = cbor::parse(bytes)?;
            let encrypted = required(value.map_get_int(2))?
                .as_bytes()
                .ok_or_else(invalid)?;
            Ok(PinToken(decrypt_token(
                protocol,
                shared_secret.as_bytes(),
                encrypted,
            )?))
        })
    })
}

/// Obtain a pinUvAuthToken with the legacy getPinToken subcommand (0x05).
///
/// Wire format: `0x06` followed by `{1: pinUvAuthProtocol, 2: 0x05,
/// 3: keyAgreement, 6: pinHashEnc}` with `pinHashEnc =
/// encrypt(LEFT(SHA-256(pin), 16))`. No permissions or rpId parameters are
/// sent: the CanoKey firmware rejects them on this subcommand and grants
/// makeCredential+getAssertion permissions implicitly. The response's
/// encrypted token (key 2) is decrypted with the session's shared secret.
///
/// # Randomness
///
/// Protocol V2 requires `iv` to be a fresh 16-byte CSPRNG value; protocol V1
/// requires `iv` to be `None`.
///
/// # Errors
/// PIN validation and IV rules match [`set_pin`]. A wrong PIN surfaces as
/// 0x31 PIN_INVALID ([`ErrorKind::InvalidPin`]); a missing or undecryptable
/// token field fails as [`ErrorKind::InvalidResponse`] in [`Phase::Parsing`].
pub fn get_pin_token(
    session: &PinSession,
    pin: &[u8],
    iv: Option<&[u8; 16]>,
    options: OperationOptions,
) -> Result<Operation<PinToken>, Error> {
    validate_pin(pin)?;
    check_iv(session.protocol, iv)?;
    let hash = pin_hash(pin);
    let pin_hash_enc = encrypt(
        session.protocol,
        session.shared_secret.as_bytes(),
        iv,
        &hash,
    )?;
    drop(hash);
    let message = client_pin_message(pin_token_entries(
        session,
        SUBCOMMAND_GET_PIN_TOKEN,
        pin_hash_enc,
        Vec::new(),
    ));
    pin_token_operation(session, &message, options)
}

/// Obtain a pinUvAuthToken with explicit permissions:
/// getPinUvAuthTokenUsingPinWithPermissions (0x09).
///
/// Wire format: `0x06` followed by `{1: pinUvAuthProtocol, 2: 0x09,
/// 3: keyAgreement, 6: pinHashEnc, 9: permissions, 10?: rpId}`. `rp_id`, when
/// present, binds the token to that relying party (getAssertion only) and
/// must be non-empty. `permissions` must be non-zero.
///
/// # Randomness
///
/// Protocol V2 requires `iv` to be a fresh 16-byte CSPRNG value; protocol V1
/// requires `iv` to be `None`.
///
/// # Errors
/// PIN validation and IV rules match [`set_pin`]; zero permissions or an
/// empty rpId fail as [`ErrorKind::InvalidArgument`] before any I/O. Token
/// decryption failures follow [`get_pin_token`].
pub fn get_pin_token_with_permissions(
    session: &PinSession,
    pin: &[u8],
    permissions: Permissions,
    rp_id: Option<&str>,
    iv: Option<&[u8; 16]>,
    options: OperationOptions,
) -> Result<Operation<PinToken>, Error> {
    validate_pin(pin)?;
    check_iv(session.protocol, iv)?;
    if permissions.bits() == 0 || matches!(rp_id, Some("")) {
        return Err(invalid_argument());
    }
    let hash = pin_hash(pin);
    let pin_hash_enc = encrypt(
        session.protocol,
        session.shared_secret.as_bytes(),
        iv,
        &hash,
    )?;
    drop(hash);
    let mut extra = vec![(uint(9), uint(u64::from(permissions.bits())))];
    if let Some(rp_id) = rp_id {
        extra.push((uint(10), Value::Text(rp_id.to_owned())));
    }
    let message = client_pin_message(pin_token_entries(
        session,
        SUBCOMMAND_GET_PIN_TOKEN_WITH_PERMISSIONS,
        pin_hash_enc,
        extra,
    ));
    pin_token_operation(session, &message, options)
}
