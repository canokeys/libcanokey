//! C ABI for caller-owned selected PIV transaction contexts.
use super::*;
use crate::piv_configuration::name_reference;
use crate::piv_keys::{algorithm, material, parameters, piv_input, streaming_input};
use crate::piv_mutation::{management, slot};

/// Opaque context copied from a caller-owned profile and authorization state.
///
/// # Operation-constructor safety
/// Context operation constructors require a live context with no concurrent
/// mutation/free. `out` is non-NULL, aligned and writable; optional options are
/// readable and optional error storage is writable with initialized `struct_size`.
/// Versioned structs cover their declared supported prefix. Outputs do not alias
/// inputs, handles or each other. Constructors copy inputs synchronously: release
/// each returned operation once, independently of the context and input buffers.
/// Additional byte-range or descriptor requirements are documented per entry.
pub struct CnkPivContext(pub piv::PivAccessContext);

/// Create a context without connecting, selecting, or authenticating.
/// State values are `CNK_PIV_CONTEXT_*` from the public header.
///
/// # Safety
/// `profile` must be a live handle from this library with no concurrent mutation
/// or free. `out` must be non-NULL, aligned and writable. Optional `error` must
/// be aligned and writable with initialized `struct_size`, covering its declared
/// supported prefix. Outputs must not alias each other or the profile. The
/// profile is copied during this call; free the returned context exactly once.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_context_new(
    profile: *const CnkProfile,
    state: u32,
    out: *mut *mut CnkPivContext,
    error: *mut CnkError,
) -> u32 {
    guard(|| {
        if out.is_null() || profile.is_null() {
            return ARG;
        }
        *out = ptr::null_mut();
        if let Err(code) = clear_error(error) {
            return code;
        }
        let state = match state {
            1 => piv::PivAccessState::Selected,
            2 => piv::PivAccessState::PinVerified,
            3 => piv::PivAccessState::ManagementAuthorized,
            4 => piv::PivAccessState::PinAndManagementAuthorized,
            _ => return ARG,
        };
        match piv::PivAccessContext::from_state(&profile.as_ref().unwrap().0, state) {
            Ok(context) => {
                *out = Box::into_raw(Box::new(CnkPivContext(context)));
                OK
            }
            Err(e) => failure(e, error),
        }
    })
}

/// Free a context created by `cnk_piv_context_new`.
///
/// # Safety
/// `context` must be NULL or a live handle returned by `cnk_piv_context_new`.
/// Free it exactly once, without concurrent access. This does not end the card
/// transaction and does not free operations already constructed from the context.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_context_free(context: *mut CnkPivContext) {
    if !context.is_null() {
        drop(Box::from_raw(context));
    }
}

unsafe fn create_in_context(
    context: *const CnkPivContext,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
    make: impl FnOnce(&piv::PivAccessContext, OperationOptions) -> Result<Inner, u32>,
) -> u32 {
    create(out, error, || {
        make(&context.as_ref().ok_or(ARG)?.0, options(opts)?)
    })
}

/// Construct metadata access without SELECT or authentication.
///
/// # Safety
/// Follow [CnkPivContext]'s operation-constructor safety contract.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_get_metadata_in_context_new(
    context: *const CnkPivContext,
    reference: u32,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create_in_context(context, opts, out, error, |context, options| {
        let reference = match reference {
            0x80 => piv::MetadataReference::Pin,
            0x81 => piv::MetadataReference::Puk,
            0x9b => piv::MetadataReference::Management,
            n => piv::MetadataReference::Key(slot(n)?),
        };
        piv::get_metadata_in_context(context, reference, options)
            .map(Inner::Metadata)
            .map_err(|e| failure(e, error))
    })
}

/// Construct certificate access without SELECT or authentication.
///
/// # Safety
/// Follow [CnkPivContext]'s operation-constructor safety contract.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_read_certificate_in_context_new(
    context: *const CnkPivContext,
    slot_reference: u32,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create_in_context(context, opts, out, error, |context, options| {
        piv::read_certificate_in_context(context, slot(slot_reference)?, options)
            .map(Inner::Certificate)
            .map_err(|e| failure(e, error))
    })
}

/// Construct signing access without SELECT, VERIFY, or management login.
///
/// # Safety
/// Follow [CnkPivContext]'s operation-constructor safety contract.
/// `data` must cover `len` readable bytes; NULL is allowed only for zero length.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_sign_in_context_new(
    context: *const CnkPivContext,
    slot_reference: u32,
    key_algorithm: u32,
    kind: u32,
    data: *const u8,
    len: usize,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create_in_context(context, opts, out, error, |context, options| {
        let data = piv_input(data, len, options, error)?;
        let input = match kind {
            1 => piv::SignInput::RsaEncodedBlock(data),
            2 => piv::SignInput::Digest(data),
            3 => piv::SignInput::Message(data),
            _ => return Err(ARG),
        };
        piv::sign_in_context(
            context,
            slot(slot_reference)?,
            algorithm(key_algorithm)?,
            input,
            options,
        )
        .map(Inner::Signature)
        .map_err(|e| failure(e, error))
    })
}

/// Construct an explicitly selected streaming sign operation without SELECT
/// or implicit authentication. Modes are CNK_STREAM_* constants.
///
/// # Safety
/// Follow [CnkPivContext]'s operation-constructor safety contract.
/// `message` and `user_id` must cover their declared readable byte ranges.
/// NULL is allowed only for zero length. A user ID is SM2-only: NULL/0 selects
/// the firmware default; an explicit ID has 1..=32 bytes.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_sign_streaming_in_context_new(
    context: *const CnkPivContext,
    slot_reference: u32,
    mode: u32,
    message: *const u8,
    message_len: usize,
    user_id: *const u8,
    user_id_len: usize,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create_in_context(context, opts, out, error, |context, options| {
        let input = streaming_input(
            mode,
            message,
            message_len,
            user_id,
            user_id_len,
            options,
            error,
        )?;
        piv::sign_streaming_in_context(context, slot(slot_reference)?, input, options)
            .map(Inner::Signature)
            .map_err(|e| failure(e, error))
    })
}

/// Construct a raw RSA private operation without SELECT or implicit authentication.
///
/// # Safety
/// Follow [CnkPivContext]'s operation-constructor safety contract.
/// `ciphertext` must cover `ciphertext_len` readable bytes; NULL requires zero length.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_decrypt_in_context_new(
    context: *const CnkPivContext,
    slot_reference: u32,
    key_algorithm: u32,
    ciphertext: *const u8,
    ciphertext_len: usize,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create_in_context(context, opts, out, error, |context, options| {
        piv::decrypt_in_context(
            context,
            slot(slot_reference)?,
            algorithm(key_algorithm)?,
            piv_input(ciphertext, ciphertext_len, options, error)?,
            options,
        )
        .map(Inner::Object)
        .map_err(|e| failure(e, error))
    })
}

/// Construct an ECDH/X25519 derivation without SELECT or implicit authentication.
///
/// # Safety
/// Follow [CnkPivContext]'s operation-constructor safety contract.
/// `peer` must cover `peer_len` readable bytes; NULL requires zero length.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_derive_in_context_new(
    context: *const CnkPivContext,
    slot_reference: u32,
    key_algorithm: u32,
    peer: *const u8,
    peer_len: usize,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create_in_context(context, opts, out, error, |context, options| {
        if peer_len > options.limits.max_input_bytes {
            return Err(failure(
                canokey::Error::new(canokey::ErrorKind::LimitExceeded),
                error,
            ));
        }
        piv::derive_in_context(
            context,
            slot(slot_reference)?,
            algorithm(key_algorithm)?,
            bytes(peer, peer_len)?.to_vec(),
            options,
        )
        .map(Inner::Object)
        .map_err(|e| failure(e, error))
    })
}

/// Construct an ML-KEM-768 decapsulation without SELECT or implicit authentication.
///
/// # Safety
/// Follow [CnkPivContext]'s operation-constructor safety contract.
/// `ciphertext` must cover `ciphertext_len` readable bytes; NULL requires zero length.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_decapsulate_in_context_new(
    context: *const CnkPivContext,
    slot_reference: u32,
    ciphertext: *const u8,
    ciphertext_len: usize,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create_in_context(context, opts, out, error, |context, options| {
        piv::decapsulate_in_context(
            context,
            slot(slot_reference)?,
            piv_input(ciphertext, ciphertext_len, options, error)?,
            options,
        )
        .map(Inner::Object)
        .map_err(|e| failure(e, error))
    })
}

/// Construct a PIV data-object read without SELECT or implicit authentication.
///
/// # Safety
/// Follow [CnkPivContext]'s operation-constructor safety contract.
/// `tag` must cover `tag_len` readable bytes; NULL requires zero length.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_read_object_in_context_new(
    context: *const CnkPivContext,
    tag: *const u8,
    tag_len: usize,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create_in_context(context, opts, out, error, |context, options| {
        let id = piv::ObjectId::from_bytes(bytes(tag, tag_len)?).map_err(|e| failure(e, error))?;
        piv::read_object_in_context(context, id, options)
            .map(Inner::Object)
            .map_err(|e| failure(e, error))
    })
}

/// Construct a metadata-directory read without SELECT or implicit authentication.
///
/// # Safety
/// Follow [CnkPivContext]'s operation-constructor safety contract.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_read_metadata_directory_in_context_new(
    context: *const CnkPivContext,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create_in_context(context, opts, out, error, |context, options| {
        piv::read_metadata_directory_in_context(context, options)
            .map(Inner::Directory)
            .map_err(|e| failure(e, error))
    })
}

/// Construct a persisted container-name read without SELECT or implicit authentication.
///
/// # Safety
/// Follow [CnkPivContext]'s operation-constructor safety contract.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_read_container_name_in_context_new(
    context: *const CnkPivContext,
    slot_reference: u32,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create_in_context(context, opts, out, error, |context, options| {
        piv::read_container_name_in_context(context, name_reference(slot_reference)?, options)
            .map(Inner::ContainerName)
            .map_err(|e| failure(e, error))
    })
}

/// Set or clear an ordinary/F9 container name without SELECT or authentication.
/// The context must assert management authorization in the caller's transaction.
/// Input is copied before return. Firmware enforces uniqueness and key existence;
/// no automatic retry or rollback occurs after a write is sent.
///
/// # Safety
/// context must be a live, unmodified handle from cnk_piv_context_new. out must
/// be non-NULL/aligned/writable. data must cover len readable bytes (NULL requires
/// zero length). Optional opts must be readable; optional error must be writable
/// with initialized struct_size. Versioned structs cover their declared prefix.
/// Output storage must not alias inputs or handles. Free the returned operation
/// once; the context and name may be released immediately after construction.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_set_container_name_in_context_new(
    context: *const CnkPivContext,
    slot_reference: u32,
    data: *const u8,
    len: usize,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create_in_context(context, opts, out, error, |context, options| {
        if len > 78 {
            return Err(ARG);
        }
        let name =
            piv::ContainerName::from_utf16le(bytes(data, len)?).map_err(|e| failure(e, error))?;
        piv::set_container_name_in_context(context, name_reference(slot_reference)?, name, options)
            .map(Inner::Mutation)
            .map_err(|e| failure(e, error))
    })
}

/// Construct a management-authorized PIV object write in the current transaction.
///
/// # Safety
/// Follow [CnkPivContext]'s operation-constructor safety contract.
/// `tag` and `data` must cover their declared readable byte ranges; each NULL
/// pointer requires zero length. The data is the object value without outer 53 framing.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_write_object_in_context_new(
    context: *const CnkPivContext,
    tag: *const u8,
    tag_len: usize,
    data: *const u8,
    data_len: usize,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create_in_context(context, opts, out, error, |context, options| {
        if data_len > options.limits.max_input_bytes {
            return Err(failure(Error::new(ErrorKind::LimitExceeded), error));
        }
        let id = piv::ObjectId::from_bytes(bytes(tag, tag_len)?).map_err(|e| failure(e, error))?;
        piv::write_object_in_context(context, id, bytes(data, data_len)?.to_vec(), options)
            .map(Inner::Mutation)
            .map_err(|e| failure(e, error))
    })
}

/// Construct a management-authorized certificate write in the current transaction.
///
/// # Safety
/// Follow [CnkPivContext]'s operation-constructor safety contract.
/// `der` must cover `der_len` readable bytes; NULL requires zero length.
/// The bytes are an uncompressed certificate payload, without PIV framing.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_write_certificate_in_context_new(
    context: *const CnkPivContext,
    slot_reference: u32,
    der: *const u8,
    der_len: usize,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create_in_context(context, opts, out, error, |context, options| {
        if der_len > options.limits.max_input_bytes {
            return Err(failure(Error::new(ErrorKind::LimitExceeded), error));
        }
        piv::write_certificate_in_context(
            context,
            slot(slot_reference)?,
            bytes(der, der_len)?.to_vec(),
            options,
        )
        .map(Inner::Mutation)
        .map_err(|e| failure(e, error))
    })
}

/// Construct a management-authorized certificate deletion in the current transaction.
///
/// # Safety
/// Follow [CnkPivContext]'s operation-constructor safety contract.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_delete_certificate_in_context_new(
    context: *const CnkPivContext,
    slot_reference: u32,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create_in_context(context, opts, out, error, |context, options| {
        piv::delete_certificate_in_context(context, slot(slot_reference)?, options)
            .map(Inner::Mutation)
            .map_err(|e| failure(e, error))
    })
}

/// Construct management-authorized key generation in the current transaction.
///
/// # Safety
/// Follow [CnkPivContext]'s operation-constructor safety contract.
/// `params` must be non-NULL and readable with an initialized `struct_size`.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_generate_key_in_context_new(
    context: *const CnkPivContext,
    params: *const CnkKeyParameters,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create_in_context(context, opts, out, error, |context, options| {
        piv::generate_key_in_context(context, parameters(params)?, options)
            .map(Inner::PublicKey)
            .map_err(|e| failure(e, error))
    })
}

/// Construct management-authorized key import in the current transaction.
///
/// # Safety
/// Follow [CnkPivContext]'s operation-constructor safety contract.
/// `params` must be non-NULL and readable with initialized `struct_size`.
/// `components` must cover `count` initialized, aligned `CnkBytes` descriptors;
/// each nested data pointer must cover its length (NULL only for zero length).
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_import_key_in_context_new(
    context: *const CnkPivContext,
    params: *const CnkKeyParameters,
    components: *const CnkBytes,
    count: usize,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create_in_context(context, opts, out, error, |context, options| {
        let params = parameters(params)?;
        piv::import_key_in_context(
            context,
            params,
            material(params.algorithm, components, count, error)?,
            options,
        )
        .map(Inner::Mutation)
        .map_err(|e| failure(e, error))
    })
}

/// Construct management-key authentication in an already selected transaction.
///
/// # Safety
/// Follow [CnkPivContext]'s operation-constructor safety contract.
/// `auth` must be non-NULL and readable with initialized `struct_size`.
/// Its key and challenge pointers must cover their declared readable byte ranges;
/// each NULL pointer requires zero length.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_authenticate_management_in_context_new(
    context: *const CnkPivContext,
    auth: *const CnkManagement,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create_in_context(context, opts, out, error, |context, options| {
        piv::authenticate_management_in_context(context, management(auth, error)?, options)
            .map(Inner::Unit)
            .map_err(|e| failure(e, error))
    })
}

/// Construct a raw PIV object read retaining the validated 53/7E wrapper.
/// No SELECT or implicit authentication is inserted.
///
/// # Safety
/// Follow [CnkPivContext]'s operation-constructor safety contract.
/// `tag` must cover `tag_len` readable bytes; NULL requires zero length.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_read_object_container_in_context_new(
    context: *const CnkPivContext,
    tag: *const u8,
    tag_len: usize,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create_in_context(context, opts, out, error, |context, options| {
        let id = piv::ObjectId::from_bytes(bytes(tag, tag_len)?).map_err(|e| failure(e, error))?;
        piv::read_object_container_in_context(context, id, options)
            .map(Inner::Object)
            .map_err(|e| failure(e, error))
    })
}

/// Construct a management-authorized write of an already framed 53 object.
///
/// # Safety
/// Follow [CnkPivContext]'s operation-constructor safety contract.
/// `tag` and `data` must cover their declared readable byte ranges; each NULL
/// pointer requires zero length. The data includes exactly one complete outer 53 container.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_write_object_container_in_context_new(
    context: *const CnkPivContext,
    tag: *const u8,
    tag_len: usize,
    data: *const u8,
    data_len: usize,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create_in_context(context, opts, out, error, |context, options| {
        if data_len > options.limits.max_input_bytes {
            return Err(failure(Error::new(ErrorKind::LimitExceeded), error));
        }
        let id = piv::ObjectId::from_bytes(bytes(tag, tag_len)?).map_err(|e| failure(e, error))?;
        piv::write_object_container_in_context(
            context,
            id,
            piv_input(data, data_len, options, error)?,
            options,
        )
        .map(Inner::Mutation)
        .map_err(|e| failure(e, error))
    })
}

/// Require a fresh explicit empty-slot response without parsing occupied key data.
/// No SELECT or mutation occurs; retain the transaction until the dependent write.
/// # Safety
/// context is live without concurrent mutation/free. out is non-NULL/writable;
/// optional options/error have valid initialized prefixes and do not alias output.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_require_empty_key_slot_in_context_new(
    context: *const CnkPivContext,
    reference: u32,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create_in_context(context, opts, out, error, |context, options| {
        piv::require_empty_key_slot_in_context(context, slot(reference)?, options)
            .map(Inner::Unit)
            .map_err(|e| failure(e, error))
    })
}
