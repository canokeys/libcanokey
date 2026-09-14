//! C factories for PIV configuration, names, directory and key lifecycle.
use super::*;
use piv_mutation::{access, slot};
pub(super) fn name_reference(value: u32) -> Result<piv::ContainerNameReference, u32> {
    if value == 0xf9 {
        Ok(piv::ContainerNameReference::Attestation)
    } else {
        slot(value).map(piv::ContainerNameReference::Key)
    }
}
/// Validate copied UTF-16LE name bytes without a profile, credential or card call.
/// Empty input clears a name; lengths over 78, odd lengths, NUL and unpaired
/// surrogates are rejected. No handle or input pointer survives the call.
/// # Safety
/// data must cover len readable bytes; NULL requires zero length. Optional error
/// must be aligned/writable with initialized struct_size and must not alias data.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_container_name_validate(
    data: *const u8,
    len: usize,
    error: *mut CnkError,
) -> u32 {
    guard(|| {
        if let Err(code) = clear_error(error) {
            return code;
        }
        if len > 78 {
            return ARG;
        }
        let input = match bytes(data, len) {
            Ok(input) => input,
            Err(code) => return code,
        };
        match piv::ContainerName::from_utf16le(input) {
            Ok(_) => OK,
            Err(e) => failure(e, error),
        }
    })
}
/// Read the compact directory; original bytes and typed indexed entries are available.
/// # Safety
/// Follow the crate pointer/aliasing contract. profile must be live/non-NULL;
/// all supplied input ranges/descriptors must be readable. out must be writable/
/// non-NULL; optional options/error must be valid. Inputs are copied before return.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_read_metadata_directory_new(
    profile: *const CnkProfile,
    auth: *const CnkPivAccess,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        piv::read_metadata_directory(
            &profile.as_ref().ok_or(ARG)?.0,
            access(auth, error)?,
            options(opts)?,
        )
        .map(Inner::Directory)
        .map_err(|e| failure(e, error))
    })
}
/// Read a container name. The byte getter returns UTF-16LE without a terminator.
/// # Safety
/// Follow the crate pointer/aliasing contract. profile must be live/non-NULL;
/// all supplied input ranges/descriptors must be readable. out must be writable/
/// non-NULL; optional options/error must be valid. Inputs are copied before return.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_read_container_name_new(
    profile: *const CnkProfile,
    reference: u32,
    auth: *const CnkPivAccess,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        piv::read_container_name(
            &profile.as_ref().ok_or(ARG)?.0,
            name_reference(reference)?,
            access(auth, error)?,
            options(opts)?,
        )
        .map(Inner::ContainerName)
        .map_err(|e| failure(e, error))
    })
}
/// Set a copied UTF-16LE name (at most 78 bytes); empty clears it. Requires management access.
/// # Safety
/// Follow the crate pointer/aliasing contract. profile must be live/non-NULL;
/// all supplied input ranges/descriptors must be readable. out must be writable/
/// non-NULL; optional options/error must be valid. Inputs are copied before return.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_set_container_name_new(
    profile: *const CnkProfile,
    reference: u32,
    data: *const u8,
    len: usize,
    auth: *const CnkPivAccess,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        if len > 78 {
            return Err(ARG);
        }
        piv::set_container_name(
            &profile.as_ref().ok_or(ARG)?.0,
            name_reference(reference)?,
            piv::ContainerName::from_utf16le(bytes(data, len)?).map_err(|e| failure(e, error))?,
            access(auth, error)?,
            options(opts)?,
        )
        .map(Inner::Mutation)
        .map_err(|e| failure(e, error))
    })
}
/// Move a key/name to an empty slot; certificates stay in place. Requires management access.
/// # Safety
/// Follow the crate pointer/aliasing contract. profile must be live/non-NULL;
/// all supplied input ranges/descriptors must be readable. out must be writable/
/// non-NULL; optional options/error must be valid. Inputs are copied before return.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_move_key_new(
    profile: *const CnkProfile,
    source: u32,
    target: u32,
    auth: *const CnkPivAccess,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        piv::move_key(
            &profile.as_ref().ok_or(ARG)?.0,
            slot(source)?,
            slot(target)?,
            access(auth, error)?,
            options(opts)?,
        )
        .map(Inner::Mutation)
        .map_err(|e| failure(e, error))
    })
}
/// Delete a key/name, retaining its certificate. Requires management access.
/// # Safety
/// Follow the crate pointer/aliasing contract. profile must be live/non-NULL;
/// all supplied input ranges/descriptors must be readable. out must be writable/
/// non-NULL; optional options/error must be valid. Inputs are copied before return.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_delete_key_new(
    profile: *const CnkProfile,
    reference: u32,
    auth: *const CnkPivAccess,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        piv::delete_key(
            &profile.as_ref().ok_or(ARG)?.0,
            slot(reference)?,
            access(auth, error)?,
            options(opts)?,
        )
        .map(Inner::Mutation)
        .map_err(|e| failure(e, error))
    })
}
/// Reset PIN/PUK to defaults with limits 1..15. Requires management AND PIN; clear cached credentials on attempted writes.
/// # Safety
/// Follow the crate pointer/aliasing contract. profile must be live/non-NULL;
/// all supplied input ranges/descriptors must be readable. out must be writable/
/// non-NULL; optional options/error must be valid. Inputs are copied before return.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_reset_pin_puk_retries_new(
    profile: *const CnkProfile,
    pin_retries: u32,
    puk_retries: u32,
    auth: *const CnkPivAccess,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        piv::reset_pin_puk_retries(
            &profile.as_ref().ok_or(ARG)?.0,
            u8::try_from(pin_retries).map_err(|_| ARG)?,
            u8::try_from(puk_retries).map_err(|_| ARG)?,
            access(auth, error)?,
            options(opts)?,
        )
        .map(Inner::Mutation)
        .map_err(|e| failure(e, error))
    })
}
/// Replace ten-byte algorithm configuration; requires management access. Reprobe after success or uncertain writes.
/// # Safety
/// Follow the crate pointer/aliasing contract. profile must be live/non-NULL;
/// all supplied input ranges/descriptors must be readable. out must be writable/
/// non-NULL; optional options/error must be valid. Inputs are copied before return.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_set_algorithm_config_new(
    profile: *const CnkProfile,
    data: *const u8,
    len: usize,
    auth: *const CnkPivAccess,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        if len != 10 {
            return Err(ARG);
        }
        piv::set_algorithm_config(
            &profile.as_ref().ok_or(ARG)?.0,
            canokey::compatibility::AlgorithmConfig::parse(bytes(data, len)?)
                .map_err(|e| failure(e, error))?,
            access(auth, error)?,
            options(opts)?,
        )
        .map(Inner::Mutation)
        .map_err(|e| failure(e, error))
    })
}
/// Read device-generated attestation DER without interpreting or trusting the certificate.
/// # Safety
/// Follow the crate pointer/aliasing contract. profile must be live/non-NULL;
/// all supplied input ranges/descriptors must be readable. out must be writable/
/// non-NULL; optional options/error must be valid. Inputs are copied before return.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_attest_new(
    profile: *const CnkProfile,
    reference: u32,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        piv::attest(
            &profile.as_ref().ok_or(ARG)?.0,
            slot(reference)?,
            options(opts)?,
        )
        .map(Inner::Object)
        .map_err(|e| failure(e, error))
    })
}
/// Reset PIV only when PIN and PUK are already blocked; never attempts credentials. Deletes ordinary keys/certificates; reprobe afterward.
/// # Safety
/// Follow the crate pointer/aliasing contract. profile must be live/non-NULL;
/// all supplied input ranges/descriptors must be readable. out must be writable/
/// non-NULL; optional options/error must be valid. Inputs are copied before return.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_reset_piv_new(
    profile: *const CnkProfile,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        piv::reset_piv(&profile.as_ref().ok_or(ARG)?.0, options(opts)?)
            .map(Inner::Mutation)
            .map_err(|e| failure(e, error))
    })
}

/// Directory header observation. Unknown versions have decoded=0 and count=0;
/// original bytes remain available through result-copy getters.
#[repr(C)]
pub struct CnkDirectoryInfo {
    /// Caller-initialized output prefix size.
    pub struct_size: u32,
    /// Raw version byte widened to u32.
    pub version: u32,
    /// One if the entry layout was decoded, otherwise zero.
    pub decoded: u32,
    /// Number of retained source-order entries.
    pub count: u32,
}
/// Fixed-width directory entry with raw fields and CNK_DIRECTORY_* diagnostics.
#[repr(C)]
pub struct CnkDirectoryEntry {
    /// Caller-initialized output prefix size.
    pub struct_size: u32,
    /// Raw slot reference, including unknown values.
    pub reference: u8,
    /// Raw flags; bit 0 key and bit 1 certificate.
    pub flags: u8,
    /// Raw algorithm byte; meaningful only if a key is present.
    pub algorithm_id: u8,
    /// Raw origin byte.
    pub origin: u8,
    /// Raw PIN policy byte.
    pub pin_policy: u8,
    /// Raw touch policy byte.
    pub touch_policy: u8,
    /// Written as zeros.
    pub reserved: [u8; 2],
    /// Bitmask of observed entry inconsistencies.
    pub issues: u32,
}
unsafe fn directory<'a>(
    op: *const CnkOperation,
    index: Option<usize>,
) -> Result<&'a piv::MetadataDirectory, u32> {
    let op = op.as_ref().ok_or(ARG)?;
    if op.poisoned {
        return Err(STATE);
    }
    match (&op.inner, index) {
        (Inner::Directory(d), None) => d.result().map_err(|_| STATE),
        (Inner::Batch(b), Some(index)) => {
            match piv::batch_progress(b).ok_or(STATE)?.items().get(index) {
                Some(piv::BatchItem::Directory(d)) => Ok(d),
                Some(_) => Err(TYPE),
                None => Err(ARG),
            }
        }
        _ => Err(TYPE),
    }
}
unsafe fn directory_info(d: &piv::MetadataDirectory, out: *mut CnkDirectoryInfo) -> u32 {
    if out.is_null() || (*out).struct_size < std::mem::size_of::<CnkDirectoryInfo>() as u32 {
        return ARG;
    }
    ptr::write(
        out,
        CnkDirectoryInfo {
            struct_size: (*out).struct_size,
            version: d.version() as u32,
            decoded: u32::from(d.entries().is_some()),
            count: d.entries().map_or(0, |e| e.len() as u32),
        },
    );
    OK
}
unsafe fn directory_entry(
    d: &piv::MetadataDirectory,
    index: usize,
    out: *mut CnkDirectoryEntry,
) -> u32 {
    if out.is_null() || (*out).struct_size < std::mem::size_of::<CnkDirectoryEntry>() as u32 {
        return ARG;
    }
    let Some(entries) = d.entries() else {
        return TYPE;
    };
    let Some(e) = entries.get(index) else {
        return ARG;
    };
    let mut issues = 0;
    for issue in &e.issues {
        issues |= match issue {
            piv::DirectoryIssue::UnknownSlot => 1,
            piv::DirectoryIssue::DuplicateSlot => 2,
            piv::DirectoryIssue::EmptyFlags => 4,
            piv::DirectoryIssue::UnknownFlags => 8,
            piv::DirectoryIssue::KeyFieldsWithoutKey => 16,
        };
    }
    ptr::write(
        out,
        CnkDirectoryEntry {
            struct_size: (*out).struct_size,
            reference: e.reference,
            flags: e.flags,
            algorithm_id: e.key_fields[0],
            origin: e.key_fields[1],
            pin_policy: e.key_fields[2],
            touch_policy: e.key_fields[3],
            reserved: [0; 2],
            issues,
        },
    );
    OK
}

/// Copy the directory version and decoded-entry count without executing the operation.
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live without concurrent
/// mutation/free; out must be writable/non-NULL with initialized struct_size.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_directory_info(
    op: *const CnkOperation,
    out: *mut CnkDirectoryInfo,
) -> u32 {
    guard(|| match directory(op, None) {
        Ok(d) => directory_info(d, out),
        Err(code) => code,
    })
}

/// Copy one source-order directory entry without executing the operation.
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live without concurrent
/// mutation/free; out must be writable/non-NULL with initialized struct_size.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_directory_entry(
    op: *const CnkOperation,
    entry_index: usize,
    out: *mut CnkDirectoryEntry,
) -> u32 {
    guard(|| match directory(op, None) {
        Ok(d) => directory_entry(d, entry_index, out),
        Err(code) => code,
    })
}

/// Copy the directory version and decoded-entry count without executing the operation.
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live without concurrent
/// mutation/free; out must be writable/non-NULL with initialized struct_size.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_batch_item_directory_info(
    op: *const CnkOperation,
    item_index: usize,
    out: *mut CnkDirectoryInfo,
) -> u32 {
    guard(|| match directory(op, Some(item_index)) {
        Ok(d) => directory_info(d, out),
        Err(code) => code,
    })
}

/// Copy one source-order directory entry without executing the operation.
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live without concurrent
/// mutation/free; out must be writable/non-NULL with initialized struct_size.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_batch_item_directory_entry(
    op: *const CnkOperation,
    item_index: usize,
    entry_index: usize,
    out: *mut CnkDirectoryEntry,
) -> u32 {
    guard(|| match directory(op, Some(item_index)) {
        Ok(d) => directory_entry(d, entry_index, out),
        Err(code) => code,
    })
}

/// Probe the selected PIV version, with no SELECT or retained caller pointer.
/// # Safety
/// out is non-NULL/writable; optional options/error have valid initialized
/// prefixes and do not alias output. Caller owns the selected transaction.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_read_version_selected_new(
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        piv::read_version_selected(options(opts)?)
            .map(Inner::Object)
            .map_err(|e| failure(e, error))
    })
}
/// Probe selected PIV algorithm configuration without selecting/authenticating.
/// Caller must establish that attempting this public probe is appropriate.
/// # Safety
/// out is non-NULL/writable; optional options/error have valid initialized
/// prefixes and do not alias output. Caller owns the selected transaction.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_read_configuration_selected_new(
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        piv::read_configuration_selected(options(opts)?)
            .map(Inner::AlgorithmConfig)
            .map_err(|e| failure(e, error))
    })
}
/// Read selected PIV RNG after an explicit live version gate, without SELECT.
/// Output and exchange budgets apply before allocation; output is owned/zeroized.
/// # Safety
/// out is non-NULL/writable; optional options/error have valid initialized
/// prefixes and do not alias output. Caller owns the selected transaction.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_random_selected_new(
    length: usize,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        piv::random_selected(length, options(opts)?)
            .map(Inner::Object)
            .map_err(|e| failure(e, error))
    })
}
/// Copy a ten-byte configuration projection: enabled, Ed25519, RSA3072,
/// RSA4096, X25519, secp256k1, P521, SM2, MLDSA65, MLKEM768. Zero means absent
/// or disabled; the raw byte getter retains the original observed format.
/// # Safety
/// op is live without concurrent mutation/free. len is initialized/writable;
/// a non-NULL buffer covers its capacity. Output ranges do not alias handles.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_piv_configuration_copy(
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
        let Inner::AlgorithmConfig(config) = &op.inner else {
            return TYPE;
        };
        let Ok(config) = config.result() else {
            return STATE;
        };
        let mut data = [0; 10];
        data[0] = u8::from(config.enabled());
        for (index, algorithm) in [
            piv::Algorithm::Ed25519,
            piv::Algorithm::Rsa3072,
            piv::Algorithm::Rsa4096,
            piv::Algorithm::X25519,
            piv::Algorithm::Secp256k1,
            piv::Algorithm::EccP521,
            piv::Algorithm::Sm2,
            piv::Algorithm::MlDsa65,
            piv::Algorithm::MlKem768,
        ]
        .into_iter()
        .enumerate()
        {
            data[index + 1] = config.wire_id(algorithm).unwrap_or(0);
        }
        copy(&data, buffer, len)
    })
}
