//! Key generation and import. All authentication and secrets are operation-owned.
use crate::*;
use canokey_protocol::{tlv::TlvWriter, ApduHeader, ExpectedLength};
use public_key::{curve_len, rsa_len};

/// Parameters owned by one key generation/import operation. Policy defaults are
/// left to firmware; choosing a policy explicitly never changes user PIN data.
#[derive(Clone, Copy, Debug)]
pub struct KeyParameters {
    /// Target asymmetric slot; management reference 9B is not accepted.
    pub slot: Slot,
    /// Semantic algorithm; extended algorithms need observed enabled wire IDs.
    pub algorithm: Algorithm,
    /// Explicit policy or firmware default.
    pub pin_policy: PinPolicy,
    /// Explicit policy or firmware default.
    pub touch_policy: TouchPolicy,
}
impl KeyParameters {
    /// Select firmware-default policies for the given slot and algorithm.
    pub fn new(slot: Slot, algorithm: Algorithm) -> Self {
        Self {
            slot,
            algorithm,
            pin_policy: PinPolicy::Default,
            touch_policy: TouchPolicy::Default,
        }
    }
}

/// Typed, owned private-key import material, redacted and wiped on drop.
/// Constructors check wire representation; RSA component consistency/primality is
/// the caller's responsibility. No PEM/PKCS#8 parsing or random generation occurs.
#[derive(Debug)]
pub struct PrivateKeyMaterial {
    algorithm: Algorithm,
    fields: SecretBytes,
}
impl PrivateKeyMaterial {
    pub(crate) fn input_len(&self) -> usize {
        self.fields.len()
    }
    /// Copy RSA CRT p, q, dP, dQ, qInv in that order, as unsigned big-endian values.
    /// Each must be nonzero and fit half the modulus width; values are left padded
    /// to that width. The implicit public exponent is 65537; callers must supply
    /// a key with that exponent. Unsupported RSA size or malformed components fail
    /// before device access. This does not prove mathematical consistency.
    pub fn rsa_crt(algorithm: Algorithm, components: [&[u8]; 5]) -> Result<Self, Error> {
        let width =
            rsa_len(algorithm).ok_or_else(|| Error::new(ErrorKind::UnsupportedAlgorithm))? / 2;
        let mut writer = TlvWriter::new(1400);
        for (index, value) in components.into_iter().enumerate() {
            if value.is_empty() || value.len() > width || value.iter().all(|b| *b == 0) {
                return Err(Error::new(ErrorKind::InvalidArgument));
            }
            let mut padded = SecretBytes::new(vec![0; width - value.len()]);
            padded.extend(value);
            writer.push(Tag::from_bytes(&[index as u8 + 1])?, padded.as_bytes())?;
        }
        Ok(Self {
            algorithm,
            fields: writer.into_bytes(),
        })
    }
    /// Copy a P-256 or P-384 scalar in fixed-width, unsigned big-endian encoding.
    /// RustCrypto checks that it is nonzero and below the curve order. Invalid
    /// scalar/length returns InvalidArgument; other curves return UnsupportedAlgorithm.
    pub fn ec_scalar(algorithm: Algorithm, bytes: &[u8]) -> Result<Self, Error> {
        if curve_len(algorithm) != Some(bytes.len()) {
            return Err(Error::new(ErrorKind::InvalidArgument));
        }
        let valid = match algorithm {
            Algorithm::EccP256 => p256::SecretKey::from_slice(bytes).is_ok(),
            Algorithm::EccP384 => p384::SecretKey::from_slice(bytes).is_ok(),
            _ => return Err(Error::new(ErrorKind::UnsupportedAlgorithm)),
        };
        if !valid {
            return Err(Error::new(ErrorKind::InvalidArgument));
        }
        Self::field(algorithm, 0x06, bytes, bytes.len())
    }
    /// Copy a 32-byte Ed25519 seed (not an expanded 64-byte secret key).
    pub fn ed25519_seed(bytes: &[u8]) -> Result<Self, Error> {
        Self::field(Algorithm::Ed25519, 0x07, bytes, 32)
    }
    /// Copy a raw 32-byte RFC 7748 little-endian X25519 private input. Firmware
    /// performs scalar decoding/clamping; the library does not reverse its bytes.
    pub fn x25519_key(bytes: &[u8]) -> Result<Self, Error> {
        Self::field(Algorithm::X25519, 0x08, bytes, 32)
    }
    /// Copy a 32-byte ML-DSA-65 seed, not an expanded secret key.
    pub fn mldsa65_seed(bytes: &[u8]) -> Result<Self, Error> {
        Self::field(Algorithm::MlDsa65, 0x09, bytes, 32)
    }
    /// Copy a 64-byte ML-KEM-768 seed in d || z order.
    pub fn mlkem768_seed(bytes: &[u8]) -> Result<Self, Error> {
        Self::field(Algorithm::MlKem768, 0x0a, bytes, 64)
    }
    fn field(algorithm: Algorithm, tag: u8, bytes: &[u8], len: usize) -> Result<Self, Error> {
        if bytes.len() != len {
            return Err(Error::new(ErrorKind::InvalidArgument));
        }
        let mut writer = TlvWriter::new(len + 2);
        writer.push(Tag::from_bytes(&[tag])?, bytes)?;
        Ok(Self {
            algorithm,
            fields: writer.into_bytes(),
        })
    }
    /// Return the semantic algorithm without exposing secret bytes.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

pub(crate) fn key_id(
    profile: &DeviceProfile,
    slot: Slot,
    algorithm: Algorithm,
) -> Result<u8, Error> {
    require(profile)?;
    profile.piv_slot_support(slot.reference()).require()?;
    profile.key_algorithm_support(algorithm).require()?;
    profile
        .algorithm_wire_id(algorithm)
        .ok_or_else(|| Error::new(ErrorKind::CapabilityUnknown))
}
fn policies(
    profile: &DeviceProfile,
    parameters: KeyParameters,
    writer: &mut TlvWriter,
) -> Result<(), Error> {
    if parameters.pin_policy != PinPolicy::Default
        || parameters.touch_policy != TouchPolicy::Default
    {
        profile.capability(Capability::Metadata).require()?;
    }
    if parameters.pin_policy != PinPolicy::Default {
        writer.push(Tag::from_bytes(&[0xaa])?, &[parameters.pin_policy.wire()])?;
    }
    if parameters.touch_policy != TouchPolicy::Default {
        writer.push(Tag::from_bytes(&[0xab])?, &[parameters.touch_policy.wire()])?;
    }
    Ok(())
}
pub(crate) fn key_command(ins: u8, p1: u8, p2: u8, data: SecretBytes) -> LogicalCommand {
    let mut command = LogicalCommand::new(
        ApduHeader::new(0, ins, p1, p2),
        vec![],
        ExpectedLength::Absent,
    );
    command.data = data;
    command.allow_chaining = true;
    command.allow_extended = true;
    command
}
fn generated(
    algorithm: Algorithm,
    response: ResponseData,
    limit: usize,
) -> Result<PublicKey, Error> {
    response.ensure_success(Phase::Command)?;
    let mut reader = TlvReader::new(
        response.data.as_bytes(),
        TlvLimits {
            max_value_bytes: limit,
            ..Default::default()
        },
    );
    let field = reader
        .next()?
        .ok_or_else(|| Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing))?;
    if field.tag.value() != 0x7f49 || reader.next()?.is_some() {
        return Err(Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing));
    }
    PublicKey::from_tlv(algorithm, field.value, limit)
}
/// Select, authenticate management, and generate a key pair in the requested slot.
/// The private key remains on device; the result owns public fields and can encode
/// SPKI. Slot contents can change even if the response is lost or malformed, so
/// callers must invalidate key/certificate caches and never replay on I/O failure.
///
/// # Errors
/// Requires evidenced slot/algorithm/policies and management Access. Unknown
/// extension IDs, unsupported firmware, invalid replies and budgets fail explicitly.
/// Card generation is not assumed to update or remove any existing certificate.
pub fn generate_key(
    profile: &DeviceProfile,
    parameters: KeyParameters,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<PublicKey>, Error> {
    write::require_management(&access)?;
    let target = prepare_generate_key(profile, parameters, options)?;
    access::with_access(profile, access, target, options)
}

pub(crate) fn prepare_generate_key(
    profile: &DeviceProfile,
    parameters: KeyParameters,
    options: OperationOptions,
) -> Result<Sequence<PublicKey>, Error> {
    let id = key_id(profile, parameters.slot, parameters.algorithm)?;
    let mut fields = TlvWriter::new(options.limits.max_input_bytes);
    fields.push(Tag::from_bytes(&[0x80])?, &[id])?;
    policies(profile, parameters, &mut fields)?;
    let mut data = TlvWriter::new(options.limits.max_input_bytes);
    data.push(Tag::from_bytes(&[0xac])?, fields.into_bytes().as_bytes())?;
    let mut command = key_command(0x47, 0, parameters.slot.reference(), data.into_bytes());
    command.allow_chaining = false;
    access::prepare(command, options, move |r| {
        generated(
            parameters.algorithm,
            r,
            options.limits.max_total_response_bytes,
        )
    })
}
/// Select, authenticate management, and import caller-owned private material.
/// Material and KeyParameters algorithms must agree. The operation owns and wipes
/// all key bytes, including encoded/chained APDUs; caller copies remain the caller's
/// responsibility. Success returns Unchanged, but application key caches must change.
///
/// # Errors
/// Invalid material/parameters, unevidenced algorithms and budgets fail before
/// SELECT. Card/chaining errors stop immediately; partial writes are not rolled back.
pub fn import_key(
    profile: &DeviceProfile,
    parameters: KeyParameters,
    material: PrivateKeyMaterial,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<MutationResult>, Error> {
    write::require_management(&access)?;
    let target = prepare_import_key(profile, parameters, material, options)?;
    access::with_access(profile, access, target, options)
}

pub(crate) fn prepare_import_key(
    profile: &DeviceProfile,
    parameters: KeyParameters,
    material: PrivateKeyMaterial,
    options: OperationOptions,
) -> Result<Sequence<MutationResult>, Error> {
    if material.algorithm != parameters.algorithm {
        return Err(Error::new(ErrorKind::InvalidArgument));
    }
    let id = key_id(profile, parameters.slot, parameters.algorithm)?;
    let mut policy = TlvWriter::new(options.limits.max_input_bytes);
    policies(profile, parameters, &mut policy)?;
    let policy = policy.into_bytes();
    if material
        .fields
        .len()
        .checked_add(policy.len())
        .is_none_or(|n| n > options.limits.max_input_bytes)
    {
        return Err(Error::new(ErrorKind::LimitExceeded));
    }
    let mut fields = material.fields;
    fields.extend(policy.as_bytes());
    access::prepare(
        key_command(0xfe, id, parameters.slot.reference(), fields),
        options,
        write::mutation,
    )
}
