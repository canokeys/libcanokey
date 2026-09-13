//! C descriptors for explicit PIV authentication and mutation factories.
use super::*;

/// Copied management authentication descriptor, matching cnk_piv_management_v1.
/// Algorithm and mode use CNK_MANAGEMENT_* / CNK_AUTH_* semantic constants.
#[repr(C)]
pub struct CnkManagement {
    /// Supported descriptor size in bytes.
    pub struct_size: u32,
    /// CNK_MANAGEMENT_TDES or CNK_MANAGEMENT_AES192.
    pub algorithm: u32,
    /// CNK_AUTH_EXTERNAL or CNK_AUTH_MUTUAL; no implicit fallback.
    pub mode: u32,
    /// Exactly 24 readable key bytes, copied before return.
    pub key: *const u8,
    /// Key length in bytes.
    pub key_len: usize,
    /// Fresh caller-generated CSPRNG challenge for Mutual; NULL for External.
    pub challenge: *const u8,
    /// Mutual challenge length (8 or 16); must be zero for External.
    pub challenge_len: usize,
}
/// Copied PIV access descriptor. NULL means no authentication for read factories.
/// Mutations require a management descriptor; PIN, if present, follows management.
#[repr(C)]
pub struct CnkPivAccess {
    /// Supported descriptor size in bytes.
    pub struct_size: u32,
    /// Optional readable PIN; NULL with length zero means no PIN.
    pub pin: *const u8,
    /// PIN length in bytes; nonzero requires a valid PIN range.
    pub pin_len: usize,
    /// Optional management descriptor; must be present for mutation factories.
    pub management: *const CnkManagement,
}
unsafe fn algorithm(value: u32) -> Result<piv::ManagementKeyAlgorithm, u32> {
    match value {
        1 => Ok(piv::ManagementKeyAlgorithm::Tdes),
        2 => Ok(piv::ManagementKeyAlgorithm::Aes192),
        _ => Err(ARG),
    }
}
unsafe fn management(
    p: *const CnkManagement,
    error: *mut CnkError,
) -> Result<piv::ManagementAuthentication, u32> {
    let p = p.as_ref().ok_or(ARG)?;
    if p.struct_size < std::mem::size_of::<CnkManagement>() as u32 {
        return Err(ARG);
    }
    if p.key_len != 24 {
        return Err(ARG);
    }
    let key = piv::ManagementKey::from_bytes(algorithm(p.algorithm)?, bytes(p.key, p.key_len)?)
        .map_err(|e| failure(e, error))?;
    match p.mode {
        1 if p.challenge_len == 0 && p.challenge.is_null() => {
            Ok(piv::ManagementAuthentication::external(key))
        }
        2 => piv::ManagementAuthentication::mutual(key, bytes(p.challenge, p.challenge_len)?)
            .map_err(|e| failure(e, error)),
        _ => Err(ARG),
    }
}
pub(super) unsafe fn access(
    p: *const CnkPivAccess,
    error: *mut CnkError,
) -> Result<piv::Access, u32> {
    let Some(p) = p.as_ref() else {
        return Ok(piv::Access::None);
    };
    if p.struct_size < std::mem::size_of::<CnkPivAccess>() as u32 {
        return Err(ARG);
    }
    let pin = if p.pin.is_null() && p.pin_len == 0 {
        None
    } else {
        Some(piv::Pin::from_bytes(bytes(p.pin, p.pin_len)?).map_err(|e| failure(e, error))?)
    };
    let auth = if p.management.is_null() {
        None
    } else {
        Some(management(p.management, error)?)
    };
    Ok(match (pin, auth) {
        (None, None) => piv::Access::None,
        (Some(pin), None) => piv::Access::Pin(pin),
        (None, Some(auth)) => piv::Access::Management(auth),
        (Some(pin), Some(management)) => piv::Access::PinAndManagement { pin, management },
    })
}
pub(super) fn slot(value: u32) -> Result<piv::Slot, u32> {
    match value {
        0x9a => Ok(piv::Slot::Authentication),
        0x9c => Ok(piv::Slot::Signature),
        0x9d => Ok(piv::Slot::KeyManagement),
        0x9e => Ok(piv::Slot::CardAuthentication),
        0x82..=0x95 => Ok(piv::Slot::Retired(
            piv::RetiredSlot::new((value - 0x81) as u8).map_err(|_| ARG)?,
        )),
        _ => Err(ARG),
    }
}

/// Construct explicit External/Mutual authentication; copies key and challenge.
/// The source profile and descriptors may be released immediately after return.
/// # Safety
/// Follow the crate pointer/aliasing contract. profile/auth must be readable and
/// non-NULL, including all declared nested ranges; out must be writable/non-NULL.
/// Optional opts/error must be valid versioned structs. Free the output once.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_authenticate_management_key_new(
    profile: *const CnkProfile,
    auth: *const CnkManagement,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        piv::authenticate_management_key(
            &profile.as_ref().ok_or(ARG)?.0,
            management(auth, error)?,
            options(opts)?,
        )
        .map(Inner::Unit)
        .map_err(|e| failure(e, error))
    })
}
/// Construct SELECT/authentication/PUT DATA for a normalized value (without 53).
/// Copies descriptors and payload; management access is required. Partial card
/// writes can persist on failure; this operation never retries a mutation.
/// # Safety
/// Follow the crate pointer/aliasing contract. profile/access must be readable
/// and non-NULL, including nested ranges; tag/data must cover declared lengths.
/// out must be writable/non-NULL; optional opts/error must be valid structs.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_write_object_new(
    profile: *const CnkProfile,
    tag: *const u8,
    tag_len: usize,
    data: *const u8,
    data_len: usize,
    auth: *const CnkPivAccess,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        let options = options(opts)?;
        if data_len > options.limits.max_input_bytes {
            return Err(failure(Error::new(ErrorKind::LimitExceeded), error));
        }
        piv::write_object(
            &profile.as_ref().ok_or(ARG)?.0,
            piv::ObjectId::from_bytes(bytes(tag, tag_len)?).map_err(|e| failure(e, error))?,
            SecretBytes::new(bytes(data, data_len)?.to_vec()),
            access(auth, error)?,
            options,
        )
        .map(Inner::Mutation)
        .map_err(|e| failure(e, error))
    })
}
/// Construct an uncompressed certificate write for a semantic PIV slot reference.
/// Copies the payload, adds 70/71/FE framing, and performs explicit management
/// authentication. No certificate syntax/trust validation is performed.
/// # Safety
/// Follow the crate pointer/aliasing contract. profile/auth must be readable and
/// non-NULL, including nested ranges. data must cover data_len bytes; out must
/// be writable/non-NULL. Optional opts/error must be valid versioned structs.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_write_certificate_new(
    profile: *const CnkProfile,
    reference: u32,
    data: *const u8,
    data_len: usize,
    auth: *const CnkPivAccess,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        let options = options(opts)?;
        if data_len > options.limits.max_input_bytes {
            return Err(failure(Error::new(ErrorKind::LimitExceeded), error));
        }
        piv::write_certificate(
            &profile.as_ref().ok_or(ARG)?.0,
            slot(reference)?,
            SecretBytes::new(bytes(data, data_len)?.to_vec()),
            access(auth, error)?,
            options,
        )
        .map(Inner::Mutation)
        .map_err(|e| failure(e, error))
    })
}
/// Construct explicit certificate deletion, without deleting its private key.
/// Firmware without evidenced deletion support fails before an operation is exposed.
/// # Safety
/// Follow the crate pointer/aliasing contract. profile/auth must be readable and
/// non-NULL, including nested ranges. out must be writable/non-NULL; optional
/// opts/error must be valid versioned structs. Free the resulting handle once.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_delete_certificate_new(
    profile: *const CnkProfile,
    reference: u32,
    auth: *const CnkPivAccess,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        piv::delete_certificate(
            &profile.as_ref().ok_or(ARG)?.0,
            slot(reference)?,
            access(auth, error)?,
            options(opts)?,
        )
        .map(Inner::Mutation)
        .map_err(|e| failure(e, error))
    })
}
/// Construct management-key replacement with explicit current-key authentication.
/// Copies the new 24-byte key. Algorithm uses CNK_MANAGEMENT_* and touch uses
/// CNK_MANAGEMENT_TOUCH_*; invalid values fail before SELECT.
/// # Safety
/// Follow the crate pointer/aliasing contract. profile/auth and nested ranges
/// must be readable/non-NULL; key must cover key_len bytes. out must be writable/
/// non-NULL. Optional opts/error must be valid versioned structs.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_set_management_key_new(
    profile: *const CnkProfile,
    key_algorithm: u32,
    key: *const u8,
    key_len: usize,
    touch: u32,
    auth: *const CnkPivAccess,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        if key_len != 24 {
            return Err(ARG);
        }
        let key = piv::ManagementKey::from_bytes(algorithm(key_algorithm)?, bytes(key, key_len)?)
            .map_err(|e| failure(e, error))?;
        let touch = match touch {
            0 => piv::ManagementTouchPolicy::Never,
            1 => piv::ManagementTouchPolicy::Always,
            _ => return Err(ARG),
        };
        piv::set_management_key(
            &profile.as_ref().ok_or(ARG)?.0,
            key,
            touch,
            access(auth, error)?,
            options(opts)?,
        )
        .map(Inner::Mutation)
        .map_err(|e| failure(e, error))
    })
}
/// Completed mutation POD; no further operation/result handle is introduced.
#[repr(C)]
pub struct CnkMutationResult {
    /// Supported output prefix size in bytes, initialized by the caller.
    pub struct_size: u32,
    /// CNK_PROFILE_UNCHANGED or CNK_PROFILE_REPROBE_REQUIRED.
    pub profile_effect: u32,
}
/// Copy a completed mutation result without sending commands or advancing state.
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live without concurrent
/// mutation/free; out must be writable/non-NULL with initialized struct_size.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_mutation_result(
    op: *const CnkOperation,
    out: *mut CnkMutationResult,
) -> u32 {
    guard(|| {
        if out.is_null() || (*out).struct_size < std::mem::size_of::<CnkMutationResult>() as u32 {
            return ARG;
        }
        let Some(op) = op.as_ref() else {
            return ARG;
        };
        if op.poisoned {
            return STATE;
        }
        match &op.inner {
            Inner::Mutation(inner) => match inner.result() {
                Ok(result) => {
                    (*out).profile_effect = match result.profile_effect {
                        piv::ProfileEffect::Unchanged => 0,
                        piv::ProfileEffect::ReprobeRequired => 1,
                    };
                    OK
                }
                Err(_) => STATE,
            },
            _ => TYPE,
        }
    })
}
