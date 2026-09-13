use crate::{Algorithm, PublicKey};
use canokey_protocol::{Error, ErrorKind, Phase, SecretBytes, SecretReference};
/// Independent OpenPGP password authorization references.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordReference {
    /// PW1 for COMPUTE DIGITAL SIGNATURE (81).
    Pw1Sign,
    /// PW1 for decipher and INTERNAL AUTHENTICATE (82).
    Pw1Other,
    /// Administrative password PW3 (83).
    Pw3,
}
impl PasswordReference {
    pub(crate) fn wire(self) -> u8 {
        match self {
            Self::Pw1Sign => 0x81,
            Self::Pw1Other => 0x82,
            Self::Pw3 => 0x83,
        }
    }
    pub(crate) fn secret(self) -> SecretReference {
        match self {
            Self::Pw1Sign => SecretReference::Pw1Sign,
            Self::Pw1Other => SecretReference::Pw1Other,
            Self::Pw3 => SecretReference::Pw3,
        }
    }
}
/// Owned unpadded password; six through 64 bytes. PW3/reset code require at least
/// eight bytes at construction of their operation. Debug redacts the password.
#[derive(Debug)]
pub struct Password(pub(crate) SecretBytes);
impl Password {
    /// Copy bounded bytes; invalid lengths return InvalidPin. Encoding is caller-owned.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if !(6..=64).contains(&bytes.len()) {
            return Err(Error::new(ErrorKind::InvalidPin));
        }
        Ok(Self(SecretBytes::new(bytes.to_vec())))
    }
}
/// Explicit verification immediately before a target (after any metadata preflight).
#[derive(Debug)]
pub struct Access {
    /// PW1-sign, PW1-other or PW3. No inferred current login state is retained.
    pub reference: PasswordReference,
    /// Owned password bytes.
    pub password: Password,
}
/// OpenPGP asymmetric key references, independent of PIV slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// Signature B6 / algorithm attributes C1.
    Signature,
    /// Decipher B8 / algorithm attributes C2.
    Decryption,
    /// Authentication A4 / algorithm attributes C3.
    Authentication,
}
impl Slot {
    /// Certificate occurrence used in SELECT DATA, 0 signature, 1 decipher, 2 auth.
    pub fn occurrence(self) -> u8 {
        match self {
            Self::Signature => 0,
            Self::Decryption => 1,
            Self::Authentication => 2,
        }
    }
    pub(crate) fn wire(self) -> u8 {
        match self {
            Self::Signature => 0xb6,
            Self::Decryption => 0xb8,
            Self::Authentication => 0xa4,
        }
    }
    pub(crate) fn attributes(self) -> u8 {
        0xc1 + self.occurrence()
    }
}
/// Explicit touch policy; Permanent cannot be downgraded by ordinary writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TouchPolicy {
    /// Disable touch checks.
    Off,
    /// Enable touch with the configured cache time.
    On,
    /// Permanently enable the touch policy for the slot.
    Permanent,
}
/// Typed writable OpenPGP data objects. Fingerprints/timestamps are caller values;
/// these writes never compute a fingerprint or create an OpenPGP packet.
#[derive(Debug)]
pub enum DataWrite {
    /// Opaque cardholder name, at most 39 bytes.
    Name(Vec<u8>),
    /// Login data, at most 63 bytes.
    Login(SecretBytes),
    /// Opaque language bytes, at most eight.
    Language(Vec<u8>),
    /// Sex marker, encoded as one byte without interpreting its meaning.
    Sex(u8),
    /// URL bytes, at most 255; no URL or trust validation.
    Url(Vec<u8>),
    /// Set or clear reset code (None clears); a present code requires 8..64 bytes.
    ResetCode(Option<Password>),
    /// Whether one explicit PW1-sign verification may authorize multiple signatures.
    ReuseSignaturePin(bool),
    /// Slot touch policy; emits the standard two-byte UIF field.
    TouchPolicy(Slot, TouchPolicy),
    /// Touch cache duration in seconds.
    TouchCacheTime(u8),
    /// Explicit key algorithm replacement. Changing it discards the old key.
    Algorithm(Slot, Algorithm),
    /// Caller-computed 20-byte key fingerprint.
    Fingerprint(Slot, [u8; 20]),
    /// Caller-supplied 20-byte CA fingerprint.
    CaFingerprint(Slot, [u8; 20]),
    /// Caller-supplied four-byte generation timestamp, unsigned seconds big-endian.
    GenerationTime(Slot, u32),
}
/// Owned private-key import fields; the card derives public keys and checks inputs.
#[derive(Debug)]
pub enum PrivateKey {
    /// RSA CRT components, unsigned big-endian. Exponent is four bytes; p/q and
    /// CRT components must be half the modulus width. Host arithmetic validation
    /// remains the caller's responsibility; no exponent 65537 is substituted.
    Rsa {
        /// RSA public exponent, padded to four bytes.
        exponent: [u8; 4],
        /// Prime p.
        p: SecretBytes,
        /// Prime q.
        q: SecretBytes,
        /// q inverse modulo p.
        q_inverse: SecretBytes,
        /// d modulo p-1.
        d_p: SecretBytes,
        /// d modulo q-1.
        d_q: SecretBytes,
    },
    /// Fixed-width short-Weierstrass scalar, Ed25519 seed or X25519 private bytes.
    /// Firmware owns key derivation; do not reverse X25519 bytes implicitly.
    Ec(SecretBytes),
}
/// Owned operation request. Protected targets require matching explicit Access.
#[derive(Debug)]
pub enum Request {
    /// Read a data object by its complete two-byte tag; unknown tags reach the card
    /// and return their original status. Values preserve their original wrappers.
    ReadData(u16),
    /// Read the selected slot's opaque certificate bytes, without X.509 validation.
    ReadCertificate(Slot),
    /// Replace/clear certificate bytes (at most 1152); uses SELECT DATA after PW3.
    WriteCertificate(Slot, SecretBytes),
    /// Empty VERIFY observations. This may clear the selected PW1 mode on firmware;
    /// a verified status must never be reused as a PW1 authorization token.
    PinStatus(PasswordReference),
    /// Perform only the supplied explicit Access verification.
    Verify,
    /// Clear authorization for this reference; no implicit reconnect or PIN input.
    Logout(PasswordReference),
    /// Change PW1 (Pw1Sign reference) or PW3 using old||new, with no extra VERIFY.
    ChangePassword {
        /// Pw1Sign or Pw3; Pw1Other is invalid for CHANGE REFERENCE DATA.
        reference: PasswordReference,
        /// Existing password.
        old: Password,
        /// Replacement password.
        new: Password,
    },
    /// Reset PW1 using explicit PW3 access; does not change PW3.
    UnblockWithAdmin(Password),
    /// Reset PW1 using reset-code||new-PW1; no extra password verification.
    UnblockWithCode {
        /// Existing 8..64 byte reset code.
        code: Password,
        /// Replacement PW1.
        new: Password,
    },
    /// Set PW1/reset-code/PW3 retry limits 1..15. Resets PW1/PW3 to firmware
    /// defaults and clears authorization; interrupted writes may leave partial state.
    ResetRetries([u8; 3]),
    /// Write a typed field after explicit PW3 verification.
    WriteData(DataWrite),
    /// Read a public key using currently observed algorithm attributes.
    ReadPublicKey(Slot),
    /// Generate/replace a key using existing attributes, after PW3 verification.
    GenerateKey(Slot),
    /// Import into existing attributes. The algorithm must match the observed DO;
    /// use a separate explicit algorithm write to change it first.
    ImportKey {
        /// Destination slot.
        slot: Slot,
        /// Expected algorithm; mismatches fail before verification/import.
        algorithm: Algorithm,
        /// Owned private fields.
        key: PrivateKey,
    },
    /// Sign a caller-prepared digest/DigestInfo or Ed25519 message. RSA applies
    /// PKCS#1 v1.5 signature padding on card; EC returns fixed-width r||s.
    /// Pinned firmware does not chain sign inputs, so large messages fail preflight.
    Sign(Algorithm, SecretBytes),
    /// INTERNAL AUTHENTICATE with the auth slot and PW1-other; same input formats.
    Authenticate(Algorithm, SecretBytes),
    /// RSA PKCS#1 v1.5 ciphertext without the wire padding-indicator byte. Output
    /// is firmware-unpadded plaintext, unlike PIV's raw RSA private operation.
    Decrypt(Algorithm, SecretBytes),
    /// Short-Weierstrass SEC1 point or raw X25519 peer bytes. Output is the raw
    /// fixed-width shared secret; application owns peer validation and OpenPGP KDF.
    Derive(Algorithm, Vec<u8>),
    /// Terminate the applet with PW3, or with no access when PW3 is already blocked.
    Terminate,
    /// Activate/reset an already terminated applet. Does not terminate automatically.
    Activate,
}
/// Empty-VERIFY observations, never an authorization token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinStatus {
    /// Credential-level verification flag; selected PW1 usage mode may be cleared.
    pub verified: bool,
    /// Retry count only when explicitly returned.
    pub retries_remaining: Option<u8>,
    /// Whether the reference is blocked.
    pub blocked: bool,
}
/// Seven-byte PW status object, preserving the policy byte and three length limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PasswordStatus {
    /// Original policy byte (0 per signature, 1 reusable; other values preserved).
    pub signature_policy: u8,
    /// Maximum PW1/reset-code/PW3 lengths.
    pub maximum_lengths: [u8; 3],
    /// PW1/reset-code/PW3 remaining retries.
    pub retries: [u8; 3],
}
impl PasswordStatus {
    /// Parse exactly seven bytes without assuming retry counts or policy semantics.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 7 {
            return Err(invalid());
        }
        Ok(Self {
            signature_policy: bytes[0],
            maximum_lengths: [bytes[1], bytes[2], bytes[3]],
            retries: [bytes[4], bytes[5], bytes[6]],
        })
    }
}
/// Completed typed result. Mutations invalidate caller object/credential caches,
/// including uncertain attempts; no implicit refresh or rollback takes place.
#[derive(Debug)]
pub enum Outcome {
    /// Original DO/certificate bytes or owned secret plaintext/shared secret.
    Bytes(SecretBytes),
    /// Empty acknowledgment; includes mutation and verification success.
    Unit,
    /// Credential-level status observations.
    PinStatus(PinStatus),
    /// Owned public key with pure SPKI export.
    PublicKey(PublicKey),
    /// RSA signature, EC fixed-width r||s, or raw Ed25519 signature.
    Signature {
        /// Observed and expected algorithm.
        algorithm: Algorithm,
        /// Complete original signature bytes.
        bytes: SecretBytes,
    },
}
pub(crate) fn invalid() -> Error {
    Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing)
}
