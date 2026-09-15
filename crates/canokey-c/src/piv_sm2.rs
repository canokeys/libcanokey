//! Copied SM2 peer descriptors and result getters, without persistent sessions.
use super::*;
use piv_mutation::{piv_access, piv_options, slot};
/// Copied SM2 agreement parameters. All public points are uncompressed 65-byte
/// SEC1 on SM2; optional identities are NULL/0 or 1..=32 bytes.
#[repr(C)]
pub struct CnkSm2Input {
    /// Supported input prefix size.
    pub struct_size: u32,
    /// CNK_SM2_INITIATOR or CNK_SM2_RESPONDER.
    pub role: u32,
    /// Requested session-key bytes, 1..=128.
    pub key_len: u32,
    /// Peer static key, available before construction.
    pub peer_static: CnkBytes,
    /// Peer ephemeral key, available before construction.
    pub peer_ephemeral: CnkBytes,
    /// Own optional identity.
    pub user_id: CnkBytes,
    /// Peer optional identity.
    pub peer_id: CnkBytes,
}
pub(super) unsafe fn input(p: *const CnkSm2Input) -> Result<piv::Sm2AgreementInput, u32> {
    let p = p.as_ref().ok_or(ARG)?;
    if p.struct_size < std::mem::size_of::<CnkSm2Input>() as u32
        || p.peer_static.len != 65
        || p.peer_ephemeral.len != 65
        || p.user_id.len > 32
        || p.peer_id.len > 32
    {
        return Err(ARG);
    }
    let identity = |b: &CnkBytes| -> Result<Option<Vec<u8>>, u32> {
        if b.data.is_null() && b.len == 0 {
            Ok(None)
        } else {
            Ok(Some(bytes(b.data, b.len)?.to_vec()))
        }
    };
    Ok(piv::Sm2AgreementInput {
        role: match p.role {
            1 => piv::Sm2Role::Initiator,
            2 => piv::Sm2Role::Responder,
            _ => return Err(ARG),
        },
        key_len: u16::try_from(p.key_len).map_err(|_| ARG)?,
        peer_static: bytes(p.peer_static.data, p.peer_static.len)?.to_vec(),
        peer_ephemeral: bytes(p.peer_ephemeral.data, p.peer_ephemeral.len)?.to_vec(),
        user_id: identity(&p.user_id)?,
        peer_id: identity(&p.peer_id)?,
    })
}
/// Agree an SM2 key with pre-exchanged peer points. Initiator reads policy and
/// rejects PIN-always before starting agreement. The byte getter returns the
/// derived key; the ephemeral getter returns the public point. No key confirmation.
/// # Safety
/// Follow the crate pointer/aliasing contract. profile/input and all nested ranges
/// must be readable/non-NULL where required; out writable/non-NULL. Optional
/// auth/options/error must be valid. All inputs are copied before return.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_agree_sm2_new(
    profile: *const CnkProfile,
    reference: u32,
    parameters: *const CnkSm2Input,
    auth: *const CnkPivAccess,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        piv::agree_sm2(
            &profile.as_ref().ok_or(ARG)?.0,
            slot(reference)?,
            input(parameters)?,
            piv_access(auth, opts, error)?,
            piv_options(opts)?,
        )
        .map(Inner::Sm2Agreement)
        .map_err(|e| failure(e, error))
    })
}
unsafe fn agreement<'a>(
    op: *const CnkOperation,
    index: Option<usize>,
) -> Result<&'a piv::Sm2Agreement, u32> {
    let op = op.as_ref().ok_or(ARG)?;
    if op.poisoned {
        return Err(STATE);
    }
    match (&op.inner, index) {
        (Inner::Sm2Agreement(a), None) => a.result().map_err(|_| STATE),
        (Inner::Batch(b), Some(index)) => {
            match piv::batch_progress(b).ok_or(STATE)?.items().get(index) {
                Some(piv::BatchItem::Sm2Agreement(a)) => Ok(a),
                Some(_) => Err(TYPE),
                None => Err(ARG),
            }
        }
        _ => Err(TYPE),
    }
}
/// Copy the result's own 65-byte ephemeral point; NULL buffer queries length.
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live without concurrent
/// mutation/free; len must be initialized/writable/non-NULL; a non-NULL buffer
/// covers incoming *len bytes and does not overlap len or the operation.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_sm2_ephemeral_copy(
    op: *const CnkOperation,
    buffer: *mut u8,
    len: *mut usize,
) -> u32 {
    guard(|| match agreement(op, None) {
        Ok(a) => copy(&a.ephemeral_public, buffer, len),
        Err(c) => c,
    })
}
/// Copy a completed Batch agreement's own public ephemeral point, without I/O.
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live without concurrent
/// mutation/free; len must be initialized/writable/non-NULL; a non-NULL buffer
/// covers incoming *len bytes and does not overlap len or the operation.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_batch_item_sm2_ephemeral_copy(
    op: *const CnkOperation,
    index: usize,
    buffer: *mut u8,
    len: *mut usize,
) -> u32 {
    guard(|| match agreement(op, Some(index)) {
        Ok(a) => copy(&a.ephemeral_public, buffer, len),
        Err(c) => c,
    })
}
