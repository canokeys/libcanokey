//! C ABI for caller-owned selected PIV transaction contexts.
use super::*;
use crate::piv_keys::{algorithm, piv_input};
use crate::piv_mutation::slot;

/// Opaque context copied from a caller-owned profile and authorization state.
pub struct CnkPivContext(pub piv::PivAccessContext);

/// Create a context without connecting, selecting, or authenticating.
/// State values are `CNK_PIV_CONTEXT_*` from the public header.
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
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_context_free(context: *mut CnkPivContext) {
    if !context.is_null() {
        drop(Box::from_raw(context));
    }
}

unsafe fn context_ref<'a>(ptr: *const CnkPivContext) -> Result<&'a CnkPivContext, u32> {
    ptr.as_ref().ok_or(ARG)
}

/// Construct metadata access without SELECT or authentication.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_get_metadata_in_context_new(
    context: *const CnkPivContext,
    reference: u32,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        let context = context_ref(context)?;
        let reference = match reference {
            0x80 => piv::MetadataReference::Pin,
            0x81 => piv::MetadataReference::Puk,
            0x9b => piv::MetadataReference::Management,
            n => piv::MetadataReference::Key(slot(n)?),
        };
        let options = options(opts)?;
        piv::get_metadata_in_context(&context.0, reference, options)
            .map(Inner::Metadata)
            .map_err(|e| failure(e, error))
    })
}

/// Construct certificate access without SELECT or authentication.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_read_certificate_in_context_new(
    context: *const CnkPivContext,
    slot_reference: u32,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        let context = context_ref(context)?;
        let options = options(opts)?;
        piv::read_certificate_in_context(&context.0, slot(slot_reference)?, options)
            .map(Inner::Certificate)
            .map_err(|e| failure(e, error))
    })
}

/// Construct signing access without SELECT, VERIFY, or management login.
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
    create(out, error, || {
        let context = context_ref(context)?;
        let options = options(opts)?;
        let data = piv_input(data, len, options, error)?;
        let input = match kind {
            1 => piv::SignInput::RsaEncodedBlock(data),
            2 => piv::SignInput::Digest(data),
            3 => piv::SignInput::Message(data),
            _ => return Err(ARG),
        };
        piv::sign_in_context(
            &context.0,
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
    create(out, error, || {
        let context = context_ref(context)?;
        let options = options(opts)?;
        let message = piv_input(message, message_len, options, error)?;
        let input = match mode {
            1 => piv::StreamingSignInput::MlDsa65(message),
            2 => piv::StreamingSignInput::Ed25519Randomized(message),
            3 => piv::StreamingSignInput::Sm2 {
                message,
                user_id: if user_id_len == 0 {
                    None
                } else {
                    Some(bytes(user_id, user_id_len)?.to_vec())
                },
            },
            _ => return Err(ARG),
        };
        piv::sign_streaming_in_context(&context.0, slot(slot_reference)?, input, options)
            .map(Inner::Signature)
            .map_err(|e| failure(e, error))
    })
}

/// Construct a raw RSA private operation without SELECT or implicit authentication.
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
    create(out, error, || {
        let context = context_ref(context)?;
        let options = options(opts)?;
        piv::decrypt_in_context(
            &context.0,
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
    create(out, error, || {
        let context = context_ref(context)?;
        let options = options(opts)?;
        if peer_len > options.limits.max_input_bytes {
            return Err(failure(
                canokey::Error::new(canokey::ErrorKind::LimitExceeded),
                error,
            ));
        }
        piv::derive_in_context(
            &context.0,
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
    create(out, error, || {
        let context = context_ref(context)?;
        let options = options(opts)?;
        piv::decapsulate_in_context(
            &context.0,
            slot(slot_reference)?,
            piv_input(ciphertext, ciphertext_len, options, error)?,
            options,
        )
        .map(Inner::Object)
        .map_err(|e| failure(e, error))
    })
}
