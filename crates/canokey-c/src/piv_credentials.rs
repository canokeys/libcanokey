use super::*;
/// Construct explicit PIV logout. Drop/free alone never performs this operation.
///
/// # Safety
/// Follow the crate pointer contract. profile must be live/non-NULL, out writable/
/// non-NULL; optional options/error structures must have supported sizes.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_logout_new(
    profile: *const CnkProfile,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        piv::logout(&profile.as_ref().ok_or(ARG)?.0, options(opts)?)
            .map(Inner::Unit)
            .map_err(|e| failure(e, error))
    })
}
/// Construct PIV PIN replacement, copying old/new credential spans. No extra VERIFY
/// or automatic retry is performed; completion uses the mutation result getter.
///
/// # Safety
/// Follow the crate pointer contract. profile must be live/non-NULL, credential
/// spans readable, out writable/non-NULL and optional options/error versioned.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_change_pin_new(
    profile: *const CnkProfile,
    old: *const u8,
    old_len: usize,
    new: *const u8,
    new_len: usize,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        let old = piv::Pin::from_bytes(bytes(old, old_len)?).map_err(|e| failure(e, error))?;
        let new = piv::Pin::from_bytes(bytes(new, new_len)?).map_err(|e| failure(e, error))?;
        piv::change_pin(&profile.as_ref().ok_or(ARG)?.0, old, new, options(opts)?)
            .map(Inner::Mutation)
            .map_err(|e| failure(e, error))
    })
}
/// Construct PIV PUK replacement. Owns copied inputs; never retries uncertain writes.
///
/// # Safety
/// Follow the crate pointer contract. profile must be live/non-NULL, credential
/// spans readable, out writable/non-NULL and optional options/error versioned.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_change_puk_new(
    profile: *const CnkProfile,
    old: *const u8,
    old_len: usize,
    new: *const u8,
    new_len: usize,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        let old = piv::Puk::from_bytes(bytes(old, old_len)?).map_err(|e| failure(e, error))?;
        let new = piv::Puk::from_bytes(bytes(new, new_len)?).map_err(|e| failure(e, error))?;
        piv::change_puk(&profile.as_ref().ok_or(ARG)?.0, old, new, options(opts)?)
            .map(Inner::Mutation)
            .map_err(|e| failure(e, error))
    })
}
/// Construct PIV PIN unblock using an explicit PUK and replacement PIN. Owns copied
/// inputs and returns mutation completion; no hidden PIN attempts or rollback.
///
/// # Safety
/// Follow the crate pointer contract. profile must be live/non-NULL, credential
/// spans readable, out writable/non-NULL and optional options/error versioned.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_unblock_pin_new(
    profile: *const CnkProfile,
    puk: *const u8,
    puk_len: usize,
    new_pin: *const u8,
    new_pin_len: usize,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        let puk = piv::Puk::from_bytes(bytes(puk, puk_len)?).map_err(|e| failure(e, error))?;
        let new_pin =
            piv::Pin::from_bytes(bytes(new_pin, new_pin_len)?).map_err(|e| failure(e, error))?;
        piv::unblock_pin(
            &profile.as_ref().ok_or(ARG)?.0,
            puk,
            new_pin,
            options(opts)?,
        )
        .map(Inner::Mutation)
        .map_err(|e| failure(e, error))
    })
}

/// Run an explicit credential command; CNK_PIV_USE_EXISTING omits initial SELECT.
/// action uses CNK_PIV_CREDENTIAL_*: VERIFY uses old only, LOGOUT neither,
/// CHANGE_PIN/CHANGE_PUK both, UNBLOCK old PUK and new PIN. Credentials use the
/// legacy raw 1..=8-byte form, preserving FF bytes; factories copy them and
/// zeroize temporary storage. Unused spans must be empty. No implicit retry.
/// # Safety
/// profile must be live with no concurrent mutation/free. Nonempty credential
/// spans must be readable; NULL requires zero length. out is non-NULL/writable.
/// Optional opts is readable; optional error is writable with initialized
/// struct_size. All outputs are disjoint from inputs and each other. The caller
/// holds the selected transaction through completion and owns cache updates.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_credential_new(
    profile: *const CnkProfile,
    action: u32,
    old: *const u8,
    old_len: usize,
    new: *const u8,
    new_len: usize,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        let options = crate::piv_mutation::piv_options(opts)?;
        let profile = profile.as_ref().ok_or(ARG)?;
        if old_len > 8 || new_len > 8 {
            return Err(failure(Error::new(ErrorKind::InvalidPin), error));
        }
        let old = bytes(old, old_len)?;
        let new = bytes(new, new_len)?;
        let pin = |data: &[u8]| piv::Pin::from_legacy_bytes(data).map_err(|e| failure(e, error));
        let puk = |data: &[u8]| piv::Puk::from_legacy_bytes(data).map_err(|e| failure(e, error));
        let action = match action {
            1 if new.is_empty() => piv::CredentialAction::VerifyPin(pin(old)?),
            2 if old.is_empty() && new.is_empty() => piv::CredentialAction::Logout,
            3 => piv::CredentialAction::ChangePin {
                old: pin(old)?,
                new: pin(new)?,
            },
            4 => piv::CredentialAction::ChangePuk {
                old: puk(old)?,
                new: puk(new)?,
            },
            5 => piv::CredentialAction::UnblockPin {
                puk: puk(old)?,
                new_pin: pin(new)?,
            },
            _ => return Err(ARG),
        };
        piv::credential(
            &profile.0,
            action,
            crate::piv_mutation::select(opts),
            options,
        )
        .map(Inner::Mutation)
        .map_err(|e| failure(e, error))
    })
}

/// Select PIV before profile discovery, without assuming capabilities or credentials.
/// Returns raw selection bytes. The caller owns the transaction and must treat
/// selection as a possible authentication reset. No retry follows card failure.
/// # Safety
/// out must be non-NULL/aligned/writable. Optional opts is readable; optional
/// error is writable with initialized struct_size. Output storage is disjoint
/// from options/error. Free the returned operation once.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_select_application_new(
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        piv::select_application(options(opts)?)
            .map(Inner::Object)
            .map_err(|e| failure(e, error))
    })
}
