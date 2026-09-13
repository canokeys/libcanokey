//! Copied key/metadata descriptors and result projections.
use super::*;
use piv_mutation::{access, slot};

fn algorithm(value: u32) -> Result<piv::Algorithm, u32> {
    use piv::Algorithm::*;
    match value {
        1 => Ok(Rsa1024),
        2 => Ok(Rsa2048),
        3 => Ok(Rsa3072),
        4 => Ok(Rsa4096),
        5 => Ok(EccP256),
        6 => Ok(EccP384),
        7 => Ok(EccP521),
        8 => Ok(Secp256k1),
        9 => Ok(Sm2),
        10 => Ok(Ed25519),
        11 => Ok(X25519),
        12 => Ok(MlDsa65),
        13 => Ok(MlKem768),
        _ => Err(ARG),
    }
}
fn algorithm_code(value: piv::Algorithm) -> u32 {
    use piv::Algorithm::*;
    match value {
        Rsa1024 => 1,
        Rsa2048 => 2,
        Rsa3072 => 3,
        Rsa4096 => 4,
        EccP256 => 5,
        EccP384 => 6,
        EccP521 => 7,
        Secp256k1 => 8,
        Sm2 => 9,
        Ed25519 => 10,
        X25519 => 11,
        MlDsa65 => 12,
        MlKem768 => 13,
    }
}
/// Copied key-generation/import parameters; uses CNK_ALGORITHM_* constants.
#[repr(C)]
pub struct CnkKeyParameters {
    /// Supported prefix size in bytes.
    pub struct_size: u32,
    /// PIV slot reference (9A/9C/9D/9E or retired 82..95).
    pub slot: u32,
    /// Semantic algorithm code, never a configurable wire ID.
    pub algorithm: u32,
    /// CNK_KEY_PIN_* policy.
    pub pin_policy: u32,
    /// CNK_KEY_TOUCH_* policy.
    pub touch_policy: u32,
}
unsafe fn parameters(p: *const CnkKeyParameters) -> Result<piv::KeyParameters, u32> {
    let p = p.as_ref().ok_or(ARG)?;
    if p.struct_size < std::mem::size_of::<CnkKeyParameters>() as u32 {
        return Err(ARG);
    }
    Ok(piv::KeyParameters {
        slot: slot(p.slot)?,
        algorithm: algorithm(p.algorithm)?,
        pin_policy: match p.pin_policy {
            0 => piv::PinPolicy::Default,
            1 => piv::PinPolicy::Never,
            2 => piv::PinPolicy::Once,
            3 => piv::PinPolicy::Always,
            _ => return Err(ARG),
        },
        touch_policy: match p.touch_policy {
            0 => piv::TouchPolicy::Default,
            1 => piv::TouchPolicy::Never,
            2 => piv::TouchPolicy::Always,
            3 => piv::TouchPolicy::Cached,
            _ => return Err(ARG),
        },
    })
}
/// Readable input byte span, copied by its consuming constructor.
#[repr(C)]
pub struct CnkBytes {
    /// Readable bytes; NULL is permitted only for an empty range.
    pub data: *const u8,
    /// Byte length.
    pub len: usize,
}
unsafe fn material(
    algorithm: piv::Algorithm,
    components: *const CnkBytes,
    count: usize,
    error: *mut CnkError,
) -> Result<piv::PrivateKeyMaterial, u32> {
    use piv::Algorithm::*;
    let rsa = matches!(algorithm, Rsa1024 | Rsa2048 | Rsa3072 | Rsa4096);
    if components.is_null() || count != if rsa { 5 } else { 1 } {
        return Err(ARG);
    }
    let parts = slice::from_raw_parts(components, count);
    let mut values = Vec::with_capacity(count);
    for p in parts {
        if p.len > 256 {
            return Err(ARG);
        }
        values.push(bytes(p.data, p.len)?);
    }
    let result = if rsa {
        piv::PrivateKeyMaterial::rsa_crt(
            algorithm,
            [values[0], values[1], values[2], values[3], values[4]],
        )
    } else {
        match algorithm {
            EccP256 | EccP384 => piv::PrivateKeyMaterial::ec_scalar(algorithm, values[0]),
            Ed25519 => piv::PrivateKeyMaterial::ed25519_seed(values[0]),
            X25519 => piv::PrivateKeyMaterial::x25519_key(values[0]),
            MlDsa65 => piv::PrivateKeyMaterial::mldsa65_seed(values[0]),
            MlKem768 => piv::PrivateKeyMaterial::mlkem768_seed(values[0]),
            _ => return Err(failure(Error::new(ErrorKind::UnsupportedAlgorithm), error)),
        }
    };
    result.map_err(|e| failure(e, error))
}
/// Construct an authenticated key generation; use public-key copy getters after DONE.
/// # Safety
/// Follow the crate pointer/aliasing contract. profile, params, auth and nested
/// ranges must be readable/non-NULL; out writable/non-NULL. Optional opts/error
/// must be valid structs. All inputs are copied; free the resulting handle once.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_generate_key_new(
    profile: *const CnkProfile,
    params: *const CnkKeyParameters,
    auth: *const CnkPivAccess,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        piv::generate_key(
            &profile.as_ref().ok_or(ARG)?.0,
            parameters(params)?,
            access(auth, error)?,
            options(opts)?,
        )
        .map(Inner::PublicKey)
        .map_err(|e| failure(e, error))
    })
}
/// Import copied private components. RSA needs five spans p/q/dP/dQ/qInv with
/// implicit e=65537; other algorithms need one scalar/seed span. No PKCS#8 parsing.
/// # Safety
/// Follow the crate pointer/aliasing contract. profile/params/auth and nested
/// ranges must be readable/non-NULL; components must cover count valid spans.
/// out must be writable/non-NULL; optional opts/error must be valid structs.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_import_key_new(
    profile: *const CnkProfile,
    params: *const CnkKeyParameters,
    components: *const CnkBytes,
    count: usize,
    auth: *const CnkPivAccess,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        let params = parameters(params)?;
        piv::import_key(
            &profile.as_ref().ok_or(ARG)?.0,
            params,
            material(params.algorithm, components, count, error)?,
            access(auth, error)?,
            options(opts)?,
        )
        .map(Inner::Mutation)
        .map_err(|e| failure(e, error))
    })
}
/// Query one metadata record. reference accepts key slots, 80 PIN, 81 PUK or 9B.
/// Raw bytes and typed metadata/public-key getters are available after completion.
/// # Safety
/// Follow the crate pointer/aliasing contract. profile must be live/non-NULL;
/// optional auth/opts/error and nested ranges must be valid. out must be writable/
/// non-NULL. Inputs are copied; free the returned operation exactly once.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_get_metadata_new(
    profile: *const CnkProfile,
    reference: u32,
    auth: *const CnkPivAccess,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        let reference = match reference {
            0x80 => piv::MetadataReference::Pin,
            0x81 => piv::MetadataReference::Puk,
            0x9b => piv::MetadataReference::Management,
            n => piv::MetadataReference::Key(slot(n)?),
        };
        piv::get_metadata(
            &profile.as_ref().ok_or(ARG)?.0,
            reference,
            access(auth, error)?,
            options(opts)?,
        )
        .map(Inner::Metadata)
        .map_err(|e| failure(e, error))
    })
}
/// Read algorithm configuration with optional copied explicit authentication.
/// Result bytes retain the complete observed configuration, including its enable flag.
/// # Safety
/// Follow the crate pointer/aliasing contract. profile must be live/non-NULL;
/// optional auth/opts/error and nested ranges must be valid. out must be writable/
/// non-NULL. All inputs are copied; free the resulting handle once.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_read_algorithm_config_new(
    profile: *const CnkProfile,
    auth: *const CnkPivAccess,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        piv::read_algorithm_config(
            &profile.as_ref().ok_or(ARG)?.0,
            access(auth, error)?,
            options(opts)?,
        )
        .map(Inner::AlgorithmConfig)
        .map_err(|e| failure(e, error))
    })
}
unsafe fn input(
    data: *const u8,
    len: usize,
    options: OperationOptions,
    error: *mut CnkError,
) -> Result<SecretBytes, u32> {
    if len > options.limits.max_input_bytes {
        return Err(failure(Error::new(ErrorKind::LimitExceeded), error));
    }
    Ok(SecretBytes::new(bytes(data, len)?.to_vec()))
}
/// Sign an owned input: kind is CNK_SIGN_RSA_BLOCK, CNK_SIGN_DIGEST or CNK_SIGN_MESSAGE.
/// RSA padding, digest computation and transport are caller responsibilities.
/// # Safety
/// Follow the crate pointer/aliasing contract. profile must be live/non-NULL;
/// data must cover len bytes. Optional auth/opts/error and nested ranges must be
/// valid; out must be writable/non-NULL. All inputs are copied before return.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_sign_new(
    profile: *const CnkProfile,
    reference: u32,
    key_algorithm: u32,
    kind: u32,
    data: *const u8,
    len: usize,
    auth: *const CnkPivAccess,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        let options = options(opts)?;
        let data = input(data, len, options, error)?;
        let input = match kind {
            1 => piv::SignInput::RsaEncodedBlock(data),
            2 => piv::SignInput::Digest(data),
            3 => piv::SignInput::Message(data),
            _ => return Err(ARG),
        };
        piv::sign(
            &profile.as_ref().ok_or(ARG)?.0,
            slot(reference)?,
            algorithm(key_algorithm)?,
            input,
            access(auth, error)?,
            options,
        )
        .map(Inner::Signature)
        .map_err(|e| failure(e, error))
    })
}
/// Perform raw RSA decryption; result bytes are the modulus-sized block, without unpadding.
/// # Safety
/// Follow the crate pointer/aliasing contract. profile must be live/non-NULL;
/// data must cover len readable bytes; optional auth/opts/error and nested ranges
/// must be valid. out must be writable/non-NULL; all inputs are copied.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_decrypt_new(
    profile: *const CnkProfile,
    reference: u32,
    key_algorithm: u32,
    data: *const u8,
    len: usize,
    auth: *const CnkPivAccess,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        let options = options(opts)?;
        piv::decrypt(
            &profile.as_ref().ok_or(ARG)?.0,
            slot(reference)?,
            algorithm(key_algorithm)?,
            input(data, len, options, error)?,
            access(auth, error)?,
            options,
        )
        .map(Inner::Object)
        .map_err(|e| failure(e, error))
    })
}
/// Derive a raw ECDH/X25519 shared secret from copied peer bytes; no KDF is performed.
/// # Safety
/// Follow the crate pointer/aliasing contract. profile must be live/non-NULL;
/// peer must cover len readable bytes; optional auth/opts/error and nested ranges
/// must be valid. out must be writable/non-NULL. Free the returned handle once.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_derive_new(
    profile: *const CnkProfile,
    reference: u32,
    key_algorithm: u32,
    peer: *const u8,
    len: usize,
    auth: *const CnkPivAccess,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        let options = options(opts)?;
        if len > options.limits.max_input_bytes {
            return Err(failure(Error::new(ErrorKind::LimitExceeded), error));
        }
        piv::derive(
            &profile.as_ref().ok_or(ARG)?.0,
            slot(reference)?,
            algorithm(key_algorithm)?,
            bytes(peer, len)?.to_vec(),
            access(auth, error)?,
            options,
        )
        .map(Inner::Object)
        .map_err(|e| failure(e, error))
    })
}
/// Copied metadata scalar fields. Presence flags distinguish absent values; raw
/// policy/origin/default bytes are retained, including unknown values.
#[repr(C)]
pub struct CnkMetadata {
    /// Supported output prefix size in bytes, initialized by the caller.
    pub struct_size: u32,
    /// CNK_METADATA_HAS_* bitmask.
    pub presence_flags: u32,
    /// Original on-wire algorithm byte.
    pub algorithm_id: u8,
    /// Original PIN policy byte.
    pub pin_policy: u8,
    /// Original touch policy byte.
    pub touch_policy: u8,
    /// Original origin byte.
    pub origin: u8,
    /// Original default-credential indicator byte.
    pub is_default: u8,
    /// Reported total retries.
    pub retries_total: u8,
    /// Reported remaining retries.
    pub retries_remaining: u8,
    /// Written as zero.
    pub reserved: u8,
}
/// Copy metadata scalars; unknown fields remain in the raw-byte getter.
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live without concurrent
/// mutation/free; out must be writable/non-NULL with initialized struct_size.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_metadata(
    op: *const CnkOperation,
    out: *mut CnkMetadata,
) -> u32 {
    guard(|| {
        if out.is_null() || (*out).struct_size < std::mem::size_of::<CnkMetadata>() as u32 {
            return ARG;
        }
        let Some(op) = op.as_ref() else {
            return ARG;
        };
        if op.poisoned {
            return STATE;
        }
        let Inner::Metadata(inner) = &op.inner else {
            return TYPE;
        };
        let Ok(metadata) = inner.result() else {
            return STATE;
        };
        let mut result = CnkMetadata {
            struct_size: (*out).struct_size,
            presence_flags: 0,
            algorithm_id: 0,
            pin_policy: 0,
            touch_policy: 0,
            origin: 0,
            is_default: 0,
            retries_total: 0,
            retries_remaining: 0,
            reserved: 0,
        };
        use piv::KnownOrUnknown::{Known, Unknown};
        let fields = metadata.fields();
        if let Some(id) = fields.algorithm_id {
            result.presence_flags |= 1;
            result.algorithm_id = id;
        }
        if let (Some(pin), Some(touch)) = (fields.pin_policy, fields.touch_policy) {
            result.presence_flags |= 2;
            result.pin_policy = match pin {
                Unknown(raw) => raw,
                Known(piv::PinPolicy::Default) => 0,
                Known(piv::PinPolicy::Never) => 1,
                Known(piv::PinPolicy::Once) => 2,
                Known(piv::PinPolicy::Always) => 3,
            };
            result.touch_policy = match touch {
                Unknown(raw) => raw,
                Known(piv::TouchPolicy::Default) => 0,
                Known(piv::TouchPolicy::Never) => 1,
                Known(piv::TouchPolicy::Always) => 2,
                Known(piv::TouchPolicy::Cached) => 3,
            };
        }
        if let Some(origin) = fields.origin {
            result.presence_flags |= 4;
            result.origin = match origin {
                Unknown(raw) => raw,
                Known(piv::KeyOrigin::NotPresent) => 0,
                Known(piv::KeyOrigin::Generated) => 1,
                Known(piv::KeyOrigin::Imported) => 2,
            };
        }
        if let Some(default) = fields.is_default {
            result.presence_flags |= 8;
            result.is_default = match default {
                Unknown(raw) => raw,
                Known(v) => u8::from(v),
            };
        }
        if let Some((total, remaining)) = fields.retries {
            result.presence_flags |= 16;
            result.retries_total = total;
            result.retries_remaining = remaining;
        }
        ptr::write(out, result);
        OK
    })
}
unsafe fn public_key<'a>(op: *const CnkOperation) -> Result<&'a piv::PublicKey, u32> {
    let op = op.as_ref().ok_or(ARG)?;
    if op.poisoned {
        return Err(STATE);
    }
    match &op.inner {
        Inner::PublicKey(op) => op.result().map_err(|_| STATE),
        Inner::Metadata(op) => op
            .result()
            .map_err(|_| STATE)?
            .fields()
            .public_key
            .as_ref()
            .ok_or(TYPE),
        _ => Err(TYPE),
    }
}
/// Copy public-key components or DER SPKI. field uses CNK_PUBLIC_* constants;
/// NULL buffer queries size and short buffers never partially copy. Applicable
/// to generated public keys and metadata with a decoded public key.
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live without concurrent
/// mutation/free; len must be initialized/writable/non-NULL. A non-NULL buffer
/// must cover the incoming *len writable bytes and not overlap any input.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_public_key_copy(
    op: *const CnkOperation,
    field: u32,
    buffer: *mut u8,
    len: *mut usize,
) -> u32 {
    guard(|| {
        let key = match public_key(op) {
            Ok(key) => key,
            Err(code) => return code,
        };
        if field == 4 {
            return match key.to_spki_der() {
                Ok(der) => copy(&der, buffer, len),
                Err(_) => PROTOCOL,
            };
        }
        match (field, key) {
            (1, piv::PublicKey::Rsa { modulus, .. }) => copy(modulus, buffer, len),
            (2, piv::PublicKey::Rsa { exponent, .. }) => copy(exponent, buffer, len),
            (3, piv::PublicKey::Ec { point, .. }) => copy(point, buffer, len),
            (3, piv::PublicKey::Raw { bytes, .. }) => copy(bytes, buffer, len),
            (1..=3, _) => TYPE,
            _ => ARG,
        }
    })
}
/// Copy the semantic algorithm code for a public-key or signature result.
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live without concurrent
/// mutation/free; out must be writable/non-NULL and not alias the operation.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_key_algorithm(
    op: *const CnkOperation,
    out: *mut u32,
) -> u32 {
    guard(|| {
        if out.is_null() {
            return ARG;
        }
        let Some(value) = op.as_ref() else {
            return ARG;
        };
        if value.poisoned {
            return STATE;
        }
        if let Inner::Signature(inner) = &value.inner {
            match inner.result() {
                Ok(s) => {
                    *out = algorithm_code(s.algorithm());
                    return OK;
                }
                Err(_) => return STATE,
            }
        }
        match public_key(op) {
            Ok(key) => {
                *out = algorithm_code(key.algorithm());
                OK
            }
            Err(code) => code,
        }
    })
}
/// Copy a signature in fixed-width P1363 encoding; raw/DER is in the byte getter.
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live without concurrent
/// mutation/free; len must be writable/initialized/non-NULL; a non-NULL buffer
/// must cover the incoming *len bytes and not alias len or the operation.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_signature_p1363(
    op: *const CnkOperation,
    buffer: *mut u8,
    len: *mut usize,
) -> u32 {
    guard(|| {
        let Some(op) = op.as_ref() else {
            return ARG;
        };
        if op.poisoned {
            return STATE;
        }
        let Inner::Signature(inner) = &op.inner else {
            return TYPE;
        };
        let Ok(signature) = inner.result() else {
            return STATE;
        };
        match signature.to_p1363() {
            Ok(bytes) => copy(&bytes, buffer, len),
            Err(_) => TYPE,
        }
    })
}
