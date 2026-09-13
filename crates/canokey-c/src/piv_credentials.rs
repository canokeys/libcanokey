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
