//! Card-backed private operations; hashing, padding and KDF remain with callers.
use crate::*;
use canokey_protocol::tlv::TlvWriter;
use der::{asn1::Uint, Decode, Encode};
use public_key::{curve_len, rsa_len};

/// Explicit signing input. Constructors own bytes; no host hashing or padding is
/// performed implicitly. The selected key algorithm must match this variant.
#[derive(Debug)]
pub enum SignInput {
    /// Modulus-sized RSA encoded block; caller chooses PKCS#1/PSS/raw semantics.
    RsaEncodedBlock(SecretBytes),
    /// ECDSA digest or SM2 SM3(ZA || message) digest computed by the caller.
    /// ECDSA keeps the leftmost order bits and pads short values with zeros.
    Digest(SecretBytes),
    /// Nonempty Ed25519 message. Empty messages require a separately supported
    /// firmware streaming mode; this classic factory rejects them.
    Message(SecretBytes),
}
/// Owned algorithm-tagged signature. Debug is redacted; no verification is implied.
#[derive(Debug)]
pub struct Signature {
    algorithm: Algorithm,
    encoding: SignatureEncoding,
    bytes: SecretBytes,
}
/// Byte representation of an owned signature, independent of its algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureEncoding {
    /// Raw RSA, Ed25519 or ML-DSA signature bytes.
    Raw,
    /// DER SEQUENCE of unsigned r and s INTEGERs.
    Der,
    /// Fixed-width IEEE P1363 r || s (SM2 on newer firmware).
    P1363,
}
#[derive(der::Sequence)]
struct EcSignature {
    r: Uint,
    s: Uint,
}
impl Signature {
    /// Selected signing algorithm.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
    /// Encoding of as_bytes. Operation results retain the original card encoding;
    /// from_p1363 constructs a DER representation.
    pub fn encoding(&self) -> SignatureEncoding {
        self.encoding
    }
    /// Original card encoding: DER for ECDSA/legacy SM2, P1363 for SM2 on 3.1.0,
    /// raw modulus bytes for RSA, or the 64-byte Ed25519 signature.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_bytes()
    }
    /// Copy an ECDSA/SM2 signature as fixed-width IEEE P1363 r || s.
    /// Non-EC algorithms return UnsupportedAlgorithm; no device access occurs.
    pub fn to_p1363(&self) -> Result<Vec<u8>, Error> {
        let width =
            curve_len(self.algorithm).ok_or_else(|| Error::new(ErrorKind::UnsupportedAlgorithm))?;
        if self.encoding == SignatureEncoding::P1363 {
            return Ok(self.bytes.as_bytes().to_vec());
        }
        let parts = ec_signature(self.bytes.as_bytes(), width)?;
        let mut out = vec![0; 2 * width];
        for (target, value) in out
            .chunks_mut(width)
            .zip([parts.r.as_bytes(), parts.s.as_bytes()])
        {
            target[width - value.len()..].copy_from_slice(value);
        }
        Ok(out)
    }
    /// Copy an ECDSA/SM2 signature as DER without device access or verification.
    /// Non-EC algorithms return UnsupportedAlgorithm. The original bytes remain
    /// available through as_bytes, even when firmware returns P1363.
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        curve_len(self.algorithm).ok_or_else(|| Error::new(ErrorKind::UnsupportedAlgorithm))?;
        if self.encoding == SignatureEncoding::P1363 {
            Ok(Self::from_p1363(self.algorithm, self.bytes.as_bytes())?
                .bytes
                .as_bytes()
                .to_vec())
        } else {
            Ok(self.bytes.as_bytes().to_vec())
        }
    }
    /// Create an owned ECDSA/SM2 DER signature from fixed-width P1363 r || s.
    /// Requires nonzero components fitting the algorithm's scalar width. This is
    /// an encoding conversion only; no signature or curve-order verification occurs.
    pub fn from_p1363(algorithm: Algorithm, bytes: &[u8]) -> Result<Self, Error> {
        let width =
            curve_len(algorithm).ok_or_else(|| Error::new(ErrorKind::UnsupportedAlgorithm))?;
        if bytes.len() != 2 * width
            || bytes[..width].iter().all(|b| *b == 0)
            || bytes[width..].iter().all(|b| *b == 0)
        {
            return Err(Error::new(ErrorKind::InvalidArgument));
        }
        let invalid = || Error::new(ErrorKind::InvalidArgument);
        let encoded = EcSignature {
            r: Uint::new(&bytes[..width]).map_err(|_| invalid())?,
            s: Uint::new(&bytes[width..]).map_err(|_| invalid())?,
        }
        .to_der()
        .map_err(|_| invalid())?;
        Ok(Self {
            algorithm,
            encoding: SignatureEncoding::Der,
            bytes: SecretBytes::new(encoded),
        })
    }
}
fn invalid() -> Error {
    Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing)
}
fn ec_signature(data: &[u8], width: usize) -> Result<EcSignature, Error> {
    let value = EcSignature::from_der(data).map_err(|_| invalid())?;
    for n in [&value.r, &value.s] {
        if n.as_bytes().len() > width || n.as_bytes().iter().all(|b| *b == 0) {
            return Err(invalid());
        }
    }
    Ok(value)
}
fn digest(algorithm: Algorithm, data: &[u8]) -> Result<SecretBytes, Error> {
    let width = curve_len(algorithm).ok_or_else(|| Error::new(ErrorKind::UnsupportedAlgorithm))?;
    if data.is_empty() || (algorithm == Algorithm::Sm2 && data.len() != 32) {
        return Err(Error::new(ErrorKind::InvalidArgument));
    }
    let n = data.len().min(width);
    let mut out = zeroize::Zeroizing::new(vec![0; width]);
    out[width - n..].copy_from_slice(&data[..n]);
    if algorithm == Algorithm::EccP521 && data.len() >= width {
        let mut carry = 0;
        for byte in out.iter_mut() {
            let next = *byte << 1;
            *byte = (*byte >> 7) | carry;
            carry = next;
        }
    }
    Ok(SecretBytes::new(out.to_vec()))
}
fn command(
    profile: &DeviceProfile,
    slot: Slot,
    algorithm: Algorithm,
    tag: u8,
    input: &[u8],
    options: OperationOptions,
) -> Result<LogicalCommand, Error> {
    let id = keys::key_id(profile, slot, algorithm)?;
    let mut inner = TlvWriter::new(options.limits.max_input_bytes);
    inner.push(Tag::from_bytes(&[0x82])?, &[])?;
    inner.push(Tag::from_bytes(&[tag])?, input)?;
    let mut outer = TlvWriter::new(options.limits.max_input_bytes);
    outer.push(Tag::from_bytes(&[0x7c])?, inner.into_bytes().as_bytes())?;
    Ok(keys::key_command(
        0x87,
        id,
        slot.reference(),
        outer.into_bytes(),
    ))
}
fn reply(response: ResponseData, limit: usize) -> Result<SecretBytes, Error> {
    response.ensure_success(Phase::Command)?;
    // PIV GA uses definite BER; firmware may encode sub-256 lengths as 82 00 xx.
    // The EC signature inside this container is still validated as strict DER.
    let mut reader = TlvReader::new_ber(
        response.data.as_bytes(),
        TlvLimits {
            max_value_bytes: limit,
            ..Default::default()
        },
    );
    let outer = reader.next()?.ok_or_else(invalid)?;
    if outer.tag.value() != 0x7c || reader.next()?.is_some() {
        return Err(invalid());
    }
    let mut inner = outer.children()?;
    let value = inner.next()?.ok_or_else(invalid)?;
    if value.tag.value() != 0x82 || inner.next()?.is_some() {
        return Err(invalid());
    }
    Ok(SecretBytes::new(value.value.to_vec()))
}
/// Select, optionally authenticate, and sign one explicitly encoded input.
/// PIN access places VERIFY next to GENERAL AUTHENTICATE. RSA returns raw signature
/// bytes; ECDSA/SM2 encodings are structurally checked and can convert to DER or P1363. Ed25519
/// uses the message directly. No hashing/padding or automatic retry occurs.
///
/// # Errors
/// Input/algorithm mismatch, unsupported key evidence and limits fail before SELECT.
/// ML-DSA signing modes are not enabled by this classic signing factory. Malformed
/// signatures and card status failures propagate, without repeating PIN-always use.
pub fn sign(
    profile: &DeviceProfile,
    slot: Slot,
    algorithm: Algorithm,
    input: SignInput,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<Signature>, Error> {
    let target = prepare_sign(profile, slot, algorithm, input, options)?;
    access::with_access(profile, access, target, options)
}

pub(crate) fn prepare_sign(
    profile: &DeviceProfile,
    slot: Slot,
    algorithm: Algorithm,
    input: SignInput,
    options: OperationOptions,
) -> Result<Sequence<Signature>, Error> {
    let raw = match &input {
        SignInput::RsaEncodedBlock(b) | SignInput::Digest(b) | SignInput::Message(b) => b,
    };
    if raw.len() > options.limits.max_input_bytes {
        return Err(Error::new(ErrorKind::LimitExceeded));
    }
    let bytes = match input {
        SignInput::RsaEncodedBlock(bytes) if rsa_len(algorithm) == Some(bytes.len()) => bytes,
        SignInput::Digest(bytes) if curve_len(algorithm).is_some() => {
            digest(algorithm, bytes.as_bytes())?
        }
        SignInput::Message(bytes) if algorithm == Algorithm::Ed25519 && !bytes.is_empty() => {
            if bytes.len() > MAX_ED25519_MESSAGE {
                return Err(Error::new(ErrorKind::LimitExceeded));
            }
            bytes
        }
        _ => return Err(Error::new(ErrorKind::InvalidArgument)),
    };
    let command = command(profile, slot, algorithm, 0x81, bytes.as_bytes(), options)?;
    let encoding = if algorithm == Algorithm::Sm2 && profile.sm2_uses_p1363_signatures() {
        SignatureEncoding::P1363
    } else if curve_len(algorithm).is_some() {
        SignatureEncoding::Der
    } else {
        SignatureEncoding::Raw
    };
    access::prepare(command, options, move |r| {
        parse_signature(
            algorithm,
            encoding,
            r,
            options.limits.max_total_response_bytes,
        )
    })
}
pub(crate) fn parse_signature(
    algorithm: Algorithm,
    encoding: SignatureEncoding,
    response: ResponseData,
    limit: usize,
) -> Result<Signature, Error> {
    let bytes = reply(response, limit)?;
    if encoding == SignatureEncoding::P1363 {
        Signature::from_p1363(algorithm, bytes.as_bytes()).map_err(|_| invalid())?;
    } else if let Some(width) = curve_len(algorithm) {
        ec_signature(bytes.as_bytes(), width)?;
    } else {
        let width = if algorithm == Algorithm::MlDsa65 {
            3309
        } else {
            rsa_len(algorithm).unwrap_or(64)
        };
        if bytes.len() != width {
            return Err(invalid());
        }
    }
    Ok(Signature {
        algorithm,
        encoding,
        bytes,
    })
}
/// Perform an RSA private operation on a modulus-sized ciphertext block.
/// Return the raw modulus-sized plaintext block in zeroized storage. The caller
/// owns OAEP/PKCS#1 unpadding and must not log the result. No padding oracle policy
/// or retry is implemented by this library.
///
/// # Errors
/// Requires an RSA algorithm and an evidenced ordinary asymmetric slot. Wrong input/result
/// lengths, unavailable capabilities and card failures return typed errors.
pub fn decrypt(
    profile: &DeviceProfile,
    slot: Slot,
    algorithm: Algorithm,
    ciphertext: SecretBytes,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<SecretBytes>, Error> {
    let target = prepare_decrypt(profile, slot, algorithm, ciphertext, options)?;
    access::with_access(profile, access, target, options)
}

pub(crate) fn prepare_decrypt(
    profile: &DeviceProfile,
    slot: Slot,
    algorithm: Algorithm,
    ciphertext: SecretBytes,
    options: OperationOptions,
) -> Result<Sequence<SecretBytes>, Error> {
    let width = rsa_len(algorithm).ok_or_else(|| Error::new(ErrorKind::UnsupportedAlgorithm))?;
    if ciphertext.len() != width {
        return Err(Error::new(ErrorKind::InvalidArgument));
    }
    let command = command(
        profile,
        slot,
        algorithm,
        0x81,
        ciphertext.as_bytes(),
        options,
    )?;
    access::prepare(command, options, move |r| {
        let bytes = reply(r, options.limits.max_total_response_bytes)?;
        if bytes.len() != width {
            return Err(invalid());
        }
        Ok(bytes)
    })
}

/// Derive a raw ECDH/X25519 shared secret; no KDF is applied.
/// P-256/P-384/P-521/secp256k1 peers must be uncompressed SEC1 points on the named
/// curve, checked with RustCrypto. X25519 takes exactly 32 RFC 7748 bytes. The owned result is
/// wiped on drop; an all-zero X25519 shared secret is rejected.
///
/// # Errors
/// Requires an evidenced ordinary asymmetric slot, algorithm and a valid peer.
/// Wrong result lengths/encodings and card statuses fail without replay.
/// SM2 uses a separate agreement protocol and is not accepted by this factory.
pub fn derive(
    profile: &DeviceProfile,
    slot: Slot,
    algorithm: Algorithm,
    peer: Vec<u8>,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<SecretBytes>, Error> {
    let target = prepare_derive(profile, slot, algorithm, peer, options)?;
    access::with_access(profile, access, target, options)
}

pub(crate) fn prepare_derive(
    profile: &DeviceProfile,
    slot: Slot,
    algorithm: Algorithm,
    peer: Vec<u8>,
    options: OperationOptions,
) -> Result<Sequence<SecretBytes>, Error> {
    if peer.len() > options.limits.max_input_bytes {
        return Err(Error::new(ErrorKind::LimitExceeded));
    }
    let width = match algorithm {
        Algorithm::EccP256 => {
            if peer.len() != 65
                || peer.first() != Some(&4)
                || p256::PublicKey::from_sec1_bytes(&peer).is_err()
            {
                return Err(Error::new(ErrorKind::InvalidArgument));
            }
            32
        }
        Algorithm::EccP384 => {
            if peer.len() != 97
                || peer.first() != Some(&4)
                || p384::PublicKey::from_sec1_bytes(&peer).is_err()
            {
                return Err(Error::new(ErrorKind::InvalidArgument));
            }
            48
        }
        Algorithm::EccP521 => {
            if peer.len() != 133
                || peer.first() != Some(&4)
                || p521::PublicKey::from_sec1_bytes(&peer).is_err()
            {
                return Err(Error::new(ErrorKind::InvalidArgument));
            }
            66
        }
        Algorithm::Secp256k1 => {
            if peer.len() != 65
                || peer.first() != Some(&4)
                || k256::PublicKey::from_sec1_bytes(&peer).is_err()
            {
                return Err(Error::new(ErrorKind::InvalidArgument));
            }
            32
        }
        Algorithm::X25519 if peer.len() == 32 => 32,
        Algorithm::X25519 => return Err(Error::new(ErrorKind::InvalidArgument)),
        _ => return Err(Error::new(ErrorKind::UnsupportedAlgorithm)),
    };
    let command = command(profile, slot, algorithm, 0x85, &peer, options)?;
    access::prepare(command, options, move |r| {
        let bytes = reply(r, options.limits.max_total_response_bytes)?;
        if bytes.len() != width {
            return Err(invalid());
        }
        if algorithm == Algorithm::X25519 {
            use subtle::ConstantTimeEq;
            if bool::from(bytes.as_bytes().ct_eq(&[0; 32])) {
                return Err(invalid());
            }
        }
        Ok(bytes)
    })
}

/// Decapsulate an ML-KEM-768 ciphertext using a card-held private key.
/// The operation owns exactly 1088 ciphertext bytes and returns a 32-byte shared
/// secret in zeroized storage. Encapsulation, KDF and application key confirmation
/// remain with the caller. ML-KEM implicit rejection produces a secret even for
/// an invalid ciphertext; successful completion does not authenticate its sender.
///
/// # Errors
/// Requires an ordinary asymmetric slot and an observed, enabled ML-KEM-768 ID
/// on evidenced firmware. Wrong lengths, unavailable capabilities, input/response
/// budgets and card errors fail explicitly. Chaining never repeats authentication
/// or retries a failed private operation.
pub fn decapsulate(
    profile: &DeviceProfile,
    slot: Slot,
    ciphertext: SecretBytes,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<SecretBytes>, Error> {
    let target = prepare_decapsulate(profile, slot, ciphertext, options)?;
    access::with_access(profile, access, target, options)
}

pub(crate) fn prepare_decapsulate(
    profile: &DeviceProfile,
    slot: Slot,
    ciphertext: SecretBytes,
    options: OperationOptions,
) -> Result<Sequence<SecretBytes>, Error> {
    if ciphertext.len() != 1088 {
        return Err(Error::new(ErrorKind::InvalidArgument));
    }
    let command = command(
        profile,
        slot,
        Algorithm::MlKem768,
        0x81,
        ciphertext.as_bytes(),
        options,
    )?;
    access::prepare(command, options, move |r| {
        let bytes = reply(r, options.limits.max_total_response_bytes)?;
        if bytes.len() != 32 {
            return Err(invalid());
        }
        Ok(bytes)
    })
}
