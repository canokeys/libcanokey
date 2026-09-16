//! Experimental C ABI. No transport, global handles, or thread-local errors.
//!
//! # Safety
//! Every non-null pointer must be aligned, live, and valid for its declared length.
//! Output ranges must not alias inputs or handles. Handles are created by this
//! library, accessed without concurrent mutation, and freed exactly once.
//! A non-null versioned struct must contain at least its declared supported prefix.
#![deny(missing_docs)]
mod piv_protection;
pub use piv_protection::*;
mod piv_credentials;
pub use piv_credentials::*;
#[cfg(feature = "openpgp")]
mod openpgp;
#[cfg(feature = "openpgp")]
pub use openpgp::*;
#[cfg(feature = "oath")]
mod oath;
#[cfg(feature = "oath")]
pub use oath::*;
#[cfg(feature = "admin")]
mod admin;
#[cfg(feature = "admin")]
pub use admin::*;
mod piv_sm2;
pub use piv_sm2::*;
mod piv_configuration;
pub use piv_configuration::*;
mod piv_batch;
pub use piv_batch::*;
mod piv_keys;
pub use piv_keys::*;
mod piv_mutation;
use canokey::{
    compatibility::{Capability, DeviceProfile, Support},
    piv, Error, ErrorKind, Operation, OperationOptions, ProbeMode, ProbeOptions, SecretBytes, Step,
};
pub use piv_mutation::*;
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    ptr, slice,
};
/// Caller-owned error POD; mirrors `cnk_error_v1` in the C header.
/// Initialize struct_size before passing it. Presence flags govern optional fields.
/// No allocation, secret payload, or global last-error state is involved.
#[repr(C)]
pub struct CnkError {
    /// Caller-supplied size in bytes; must include the entire supported struct prefix.
    pub struct_size: u32,
    /// CNK_ERROR_* semantic error code, or zero when cleared.
    pub kind: u32,
    /// CNK_PHASE_* context code.
    pub phase: u32,
    /// CNK_REFERENCE_* credential reference; never credential bytes.
    pub reference: u32,
    /// CNK_ERROR_HAS_SW and CNK_ERROR_HAS_RETRIES bitmap for optional fields.
    pub presence_flags: u32,
    /// Original SW1/SW2 when CNK_ERROR_HAS_SW is set.
    pub status_word: u16,
    /// Authentication retries when CNK_ERROR_HAS_RETRIES is set.
    pub retries_remaining: u8,
    /// Reserved output byte, written as zero.
    pub reserved: u8,
}
/// Caller-owned `cnk_operation_options_v1`; constructors copy these limits.
/// NULL options selects Rust defaults. Zero explicit budgets are invalid.
/// The logical-command input limit currently remains the Rust default.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct CnkOptions {
    /// Caller-supplied size in bytes; must include the entire supported struct prefix.
    pub struct_size: u32,
    /// CNK_ALLOW_EXTENDED; PIV factories also accept CNK_PIV_USE_EXISTING.
    pub flags: u32,
    /// Maximum physical command bytes, including header and Lc/Le.
    pub max_command_bytes: u32,
    /// Maximum physical response bytes, including SW1/SW2.
    pub max_response_bytes: u32,
    /// Cumulative response-data budget, excluding SW; also bounds decoded certificates.
    pub max_total_response_bytes: u32,
    /// Maximum number of exposed physical commands, including continuations/retries.
    pub max_exchanges: u32,
}
/// Opaque caller-owned immutable device snapshot; release with [`cnk_profile_free`].
/// Never construct this type or inspect its Rust layout from C.
pub struct CnkProfile(DeviceProfile);
/// Opaque caller-owned operation; release with [`cnk_operation_free`].
/// Owns its command, result and error without a registry or connection handle.
/// Serialize access; never inspect its Rust layout from C.
pub struct CnkOperation {
    inner: Inner,
    poisoned: bool,
}
// Operation sizes differ by applet; the enum lives behind an opaque handle,
// so boxing selected variants would not change observable behavior.
#[allow(clippy::large_enum_variant)]
enum Inner {
    #[cfg(feature = "openpgp")]
    OpenPgp(Operation<canokey::openpgp::Outcome>),
    #[cfg(feature = "oath")]
    Oath(Operation<canokey::oath::Outcome>),
    #[cfg(feature = "admin")]
    Admin(Operation<canokey::admin::Outcome>),
    Sm2Agreement(Operation<piv::Sm2Agreement>),
    Directory(Operation<piv::MetadataDirectory>),
    ContainerName(Operation<piv::ContainerName>),
    Probe(Operation<DeviceProfile>),
    Unit(Operation<()>),
    PinStatus(Operation<piv::PinStatus>),
    Object(Operation<SecretBytes>),
    Certificate(Operation<piv::Certificate>),
    Mutation(Operation<piv::MutationResult>),
    Metadata(Operation<piv::Metadata>),
    Batch(Operation<piv::BatchResults>),
    PublicKey(Operation<piv::PublicKey>),
    Signature(Operation<piv::Signature>),
    AlgorithmConfig(Operation<canokey::compatibility::AlgorithmConfig>),
}
macro_rules! dispatch {
    ($value:expr, $op:ident => $body:expr) => {
        match $value {
            #[cfg(feature = "openpgp")]
            Inner::OpenPgp($op) => $body,
            #[cfg(feature = "oath")]
            Inner::Oath($op) => $body,
            #[cfg(feature = "admin")]
            Inner::Admin($op) => $body,
            Inner::Sm2Agreement($op) => $body,
            Inner::Directory($op) => $body,
            Inner::ContainerName($op) => $body,
            Inner::Probe($op) => $body,
            Inner::Unit($op) => $body,
            Inner::PinStatus($op) => $body,
            Inner::Object($op) => $body,
            Inner::Certificate($op) => $body,
            Inner::Mutation($op) => $body,
            Inner::Metadata($op) => $body,
            Inner::Batch($op) => $body,
            Inner::PublicKey($op) => $body,
            Inner::Signature($op) => $body,
            Inner::AlgorithmConfig($op) => $body,
        }
    };
}
const OK: u32 = 0;
const ARG: u32 = 1;
const STATE: u32 = 2;
const SMALL: u32 = 3;
const TYPE: u32 = 4;
const PROTOCOL: u32 = 5;
const PANIC: u32 = 6;
fn guard(f: impl FnOnce() -> u32) -> u32 {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(PANIC)
}
unsafe fn bytes<'a>(data: *const u8, len: usize) -> Result<&'a [u8], u32> {
    if len > isize::MAX as usize || (len != 0 && data.is_null()) {
        return Err(ARG);
    }
    if len == 0 {
        Ok(&[])
    } else {
        Ok(slice::from_raw_parts(data, len))
    }
}
unsafe fn options(p: *const CnkOptions) -> Result<OperationOptions, u32> {
    if p.is_null() {
        return Ok(OperationOptions::default());
    }
    if (*p).struct_size < std::mem::size_of::<CnkOptions>() as u32 || (*p).flags & !1 != 0 {
        return Err(ARG);
    }
    let mut out = OperationOptions::default();
    out.exchange.allow_extended = (*p).flags & 1 != 0;
    out.exchange.max_command_bytes = (*p).max_command_bytes as usize;
    out.exchange.max_response_bytes = (*p).max_response_bytes as usize;
    out.limits.max_total_response_bytes = (*p).max_total_response_bytes as usize;
    out.limits.max_exchanges = (*p).max_exchanges as usize;
    out.validate().map_err(|_| ARG)
}
unsafe fn clear_error(p: *mut CnkError) -> Result<(), u32> {
    if !p.is_null() {
        if (*p).struct_size < std::mem::size_of::<CnkError>() as u32 {
            return Err(ARG);
        }
        let size = (*p).struct_size;
        ptr::write(
            p,
            CnkError {
                struct_size: size,
                kind: 0,
                phase: 0,
                reference: 0,
                presence_flags: 0,
                status_word: 0,
                retries_remaining: 0,
                reserved: 0,
            },
        );
    }
    Ok(())
}
fn kind_code(kind: ErrorKind) -> u32 {
    match kind {
        ErrorKind::InvalidArgument => 1,
        ErrorKind::InvalidPin => 2,
        ErrorKind::InvalidResponse => 3,
        ErrorKind::ProtocolViolation => 4,
        ErrorKind::LimitExceeded => 5,
        ErrorKind::AuthenticationFailed => 6,
        ErrorKind::PinBlocked => 7,
        ErrorKind::SecurityStatusNotSatisfied => 8,
        ErrorKind::ConditionsNotSatisfied => 9,
        ErrorKind::NotFound => 10,
        ErrorKind::UnsupportedDevice => 11,
        ErrorKind::UnsupportedFeature => 12,
        ErrorKind::UnsupportedAlgorithm => 13,
        ErrorKind::CapabilityUnknown => 14,
        ErrorKind::UnsupportedProtocolVersion => 15,
        ErrorKind::UnexpectedStatusWord => 16,
        ErrorKind::OperationStateError => 17,
        ErrorKind::DeviceAuthenticationFailed => 18,
        _ => 255,
    }
}
unsafe fn failure(error: Error, out: *mut CnkError) -> u32 {
    if !out.is_null() {
        (*out).kind = kind_code(error.kind);
        (*out).phase = error.phase as u32;
        (*out).reference = error.reference.map_or(0, |r| {
            // Reference codes are independent of Rust enum order.
            match r {
                canokey::SecretReference::Pin => 1,
                canokey::SecretReference::Puk => 2,
                canokey::SecretReference::ManagementKey => 3,
                canokey::SecretReference::AdminPin => 4,
                canokey::SecretReference::OathAccess => 5,
                canokey::SecretReference::Pw1Sign => 6,
                canokey::SecretReference::Pw1Other => 7,
                canokey::SecretReference::Pw3 => 8,
                canokey::SecretReference::ResetCode => 9,
            }
        });
        if let Some(sw) = error.status_word {
            (*out).presence_flags |= 1;
            (*out).status_word = sw.raw();
        }
        if let Some(n) = error.retries_remaining {
            (*out).presence_flags |= 2;
            (*out).retries_remaining = n;
        }
    }
    match error.kind {
        ErrorKind::InvalidArgument | ErrorKind::InvalidPin => ARG,
        ErrorKind::OperationStateError => STATE,
        _ => PROTOCOL,
    }
}
unsafe fn create(
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
    f: impl FnOnce() -> Result<Inner, u32>,
) -> u32 {
    if out.is_null() {
        return ARG;
    }
    *out = ptr::null_mut();
    if let Err(code) = clear_error(error) {
        return code;
    }
    guard(|| match f() {
        Ok(inner) => {
            *out = Box::into_raw(Box::new(CnkOperation {
                inner,
                poisoned: false,
            }));
            OK
        }
        Err(code) => code,
    })
}
unsafe fn copy(data: &[u8], buffer: *mut u8, len: *mut usize) -> u32 {
    if len.is_null() {
        return ARG;
    }
    let capacity = *len;
    *len = data.len();
    if buffer.is_null() {
        return OK;
    }
    if capacity < data.len() {
        return SMALL;
    }
    ptr::copy_nonoverlapping(data.as_ptr(), buffer, data.len());
    OK
}
/// Return the ABI version as `(major << 16) | minor`: experimental 0.1.
/// This is independent of Rust crate and firmware versions.
#[no_mangle]
pub extern "C" fn cnk_abi_version() -> u32 {
    0x0000_0001
}
/// Release a profile; NULL is a no-op. Existing operations remain independent.
/// No logout or connection cleanup is performed.
///
/// # Safety
/// A non-NULL profile must be a live handle from this library, exclusively
/// owned for destruction, and freed exactly once. Do not access it afterward.
#[no_mangle]
pub unsafe extern "C" fn cnk_profile_free(profile: *mut CnkProfile) {
    if !profile.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(profile))));
    }
}
/// Release an operation and its remaining owned data; NULL is a no-op.
/// Does not stop application I/O, undo card effects, or send logout.
///
/// # Safety
/// A non-NULL op must be a live handle from this library, exclusively owned
/// for destruction and freed exactly once, with no concurrent method calls.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_free(op: *mut CnkOperation) {
    if !op.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(op))));
    }
}
/// Construct a probe for CNK_PROBE_MINIMAL or CNK_PROBE_PIV.
/// Copies options, initializes `*out` to NULL, and returns a new operation on OK.
/// No APDU is sent. Invalid mode/options returns INVALID_ARGUMENT.
///
/// # Safety
/// Follow the crate pointer/aliasing contract. `out` must be writable and
/// non-NULL; optional opts/error must have initialized struct_size. The caller
/// receives ownership of `*out` only on OK and must free it.
#[no_mangle]
pub unsafe extern "C" fn cnk_probe_device_new(
    mode: u32,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        let mode = match mode {
            0 => ProbeMode::Minimal,
            1 => ProbeMode::Piv,
            _ => return Err(ARG),
        };
        canokey::probe_device(ProbeOptions {
            mode,
            operation: options(opts)?,
        })
        .map(Inner::Probe)
        .map_err(|e| failure(e, error))
    })
}
/// Construct SELECT plus PIN verification, copying all credential bytes/options.
/// The source profile and input buffers may be released after return. Invalid
/// PIN returns INVALID_ARGUMENT with error details; capability errors propagate.
///
/// # Safety
/// Follow the crate pointer/aliasing contract. Supply a live non-NULL profile,
/// a readable pin range (NULL only for length zero), writable non-NULL out,
/// and valid optional versioned opts/error structs. Free the returned handle once.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_verify_pin_new(
    profile: *const CnkProfile,
    pin: *const u8,
    pin_len: usize,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        let profile = profile.as_ref().ok_or(ARG)?;
        let pin = piv::Pin::from_bytes(bytes(pin, pin_len)?).map_err(|e| failure(e, error))?;
        piv::verify_pin(&profile.0, pin, options(opts)?)
            .map(Inner::Unit)
            .map_err(|e| failure(e, error))
    })
}
/// Construct SELECT plus empty VERIFY. Retry/blocked statuses become typed data.
/// The operation owns its configuration; it does not retain profile or options.
///
/// # Safety
/// Follow the crate pointer/aliasing contract. Supply a live non-NULL profile,
/// writable non-NULL out and valid optional versioned opts/error structs.
/// The caller owns the returned operation.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_get_pin_status_new(
    profile: *const CnkProfile,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        piv::get_pin_status(&profile.as_ref().ok_or(ARG)?.0, options(opts)?)
            .map(Inner::PinStatus)
            .map_err(|e| failure(e, error))
    })
}

/// Construct empty VERIFY for an already selected PIV transaction, without a profile.
///
/// # Safety
/// `out` must be writable and `opts`/`error` follow the versioned pointer contract.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_get_pin_status_selected_new(
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        piv::get_pin_status_selected(options(opts)?)
            .map(Inner::PinStatus)
            .map_err(|e| failure(e, error))
    })
}
/// Construct an unprotected SELECT/GET DATA read for a complete BER object tag.
/// Copies tag/options and required profile configuration. Use the byte result
/// getter after DONE for the normalized object value, excluding its outer tag.
///
/// # Safety
/// Follow the crate pointer/aliasing contract. Supply a live non-NULL profile,
/// a readable tag range, writable non-NULL out, and valid optional versioned
/// opts/error structs. The caller owns the returned operation.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_read_object_new(
    profile: *const CnkProfile,
    tag: *const u8,
    tag_len: usize,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        let id = piv::ObjectId::from_bytes(bytes(tag, tag_len)?).map_err(|e| failure(e, error))?;
        piv::read_object(
            &profile.as_ref().ok_or(ARG)?.0,
            id,
            piv_mutation::piv_access(ptr::null(), opts, error)?,
            piv_mutation::piv_options(opts)?,
        )
        .map(Inner::Object)
        .map_err(|e| failure(e, error))
    })
}
/// Construct a public certificate read for slot 9A/9C/9D/9E or 82..95.
/// Other slot references return INVALID_ARGUMENT. The byte result getter returns
/// the unwrapped/bounded-decompressed payload; no X.509/trust validation occurs.
///
/// # Safety
/// Follow the crate pointer/aliasing contract. Supply a live non-NULL profile,
/// writable non-NULL out and valid optional versioned opts/error structs.
/// The operation owns copied configuration and must be freed by its caller.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_read_certificate_new(
    profile: *const CnkProfile,
    slot: u32,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        let slot = match slot {
            0x9a => piv::Slot::Authentication,
            0x9c => piv::Slot::Signature,
            0x9d => piv::Slot::KeyManagement,
            0x9e => piv::Slot::CardAuthentication,
            0x82..=0x95 => piv::Slot::Retired(
                piv::RetiredSlot::new((slot - 0x81) as u8).map_err(|e| failure(e, error))?,
            ),
            _ => return Err(ARG),
        };
        piv::read_certificate(
            &profile.as_ref().ok_or(ARG)?.0,
            slot,
            piv_mutation::piv_access(ptr::null(), opts, error)?,
            piv_mutation::piv_options(opts)?,
        )
        .map(Inner::Certificate)
        .map_err(|e| failure(e, error))
    })
}

unsafe fn drive(
    op: *mut CnkOperation,
    step: *mut u32,
    error: *mut CnkError,
    response: Option<&[u8]>,
) -> u32 {
    if step.is_null() {
        return ARG;
    }
    *step = 0;
    if let Err(code) = clear_error(error) {
        return code;
    }
    let Some(op) = op.as_mut() else {
        return ARG;
    };
    if op.poisoned {
        return STATE;
    }
    let result = catch_unwind(AssertUnwindSafe(
        || dispatch!(&mut op.inner,inner=>match response {None=>inner.start(),Some(r)=>inner.advance(r)}),
    ));
    match result {
        Ok(Ok(s)) => {
            *step = match s {
                Step::Exchange => 1,
                Step::Done => 2,
            };
            OK
        }
        Ok(Err(e)) => failure(e, error),
        Err(_) => {
            op.poisoned = true;
            dispatch!(&mut op.inner,inner=>inner.cancel());
            PANIC
        }
    }
}
/// Start a Created operation without performing I/O. On OK, write EXCHANGE or
/// DONE to step. On error, step is zero and protocol details are copied to error
/// when supplied. Wrong lifecycle/poisoned operation returns INVALID_STATE.
///
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live and exclusively
/// accessible; step must be non-NULL and writable. Optional error must be a
/// writable versioned struct. No call may race with free or another mutation.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_start(
    op: *mut CnkOperation,
    step: *mut u32,
    error: *mut CnkError,
) -> u32 {
    drive(op, step, error, None)
}
/// Consume one complete response data + SW1/SW2 to the pending command.
/// Copies/consumes input during this call only. On OK write EXCHANGE/DONE;
/// on failure write step zero. Protocol failures are retained on the operation.
/// Wrong lifecycle returns INVALID_STATE; invalid response pointer/length returns
/// INVALID_ARGUMENT. Transport failures must remain in the application.
///
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live and exclusively
/// accessible, response readable for len bytes (NULL only if len is zero),
/// step writable/non-NULL, and optional error a valid versioned struct.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_advance(
    op: *mut CnkOperation,
    response: *const u8,
    len: usize,
    step: *mut u32,
    error: *mut CnkError,
) -> u32 {
    match bytes(response, len) {
        Ok(r) => drive(op, step, error, Some(r)),
        Err(code) => {
            if !step.is_null() {
                *step = 0;
            }
            let _ = clear_error(error);
            code
        }
    }
}
/// Copy the pending complete APDU without advancing or sending it.
/// NULL buffer queries required length; too-small updates len and returns
/// BUFFER_TOO_SMALL without partial writes. Outside AwaitingResponse returns
/// INVALID_STATE. Copying an APDU may copy credentials: the caller must wipe it.
///
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live with no concurrent
/// mutation/free; len must be initialized, writable and non-NULL. A non-NULL
/// buffer must have at least the incoming *len writable bytes and not alias len.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_command(
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
        match dispatch!(&op.inner,inner=>inner.command()) {
            Ok(cmd) => copy(cmd.as_bytes(), buffer, len),
            Err(_) => STATE,
        }
    })
}
/// Transfer a completed probe result once; the profile survives operation free.
/// Initializes `*out` to NULL. Wrong result type returns RESULT_TYPE_MISMATCH;
/// wrong lifecycle or a second transfer returns INVALID_STATE.
///
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live and exclusively
/// accessible and out writable/non-NULL. On OK the caller owns *out and must
/// release it with cnk_profile_free, never the C allocator.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_take_profile(
    op: *mut CnkOperation,
    out: *mut *mut CnkProfile,
) -> u32 {
    guard(|| {
        if out.is_null() {
            return ARG;
        }
        *out = ptr::null_mut();
        let Some(op) = op.as_mut() else {
            return ARG;
        };
        if op.poisoned {
            return STATE;
        }
        match &mut op.inner {
            Inner::Probe(p) => match p.take_result() {
                Ok(p) => {
                    *out = Box::into_raw(Box::new(CnkProfile(p)));
                    OK
                }
                Err(_) => STATE,
            },
            _ => TYPE,
        }
    })
}
/// Copy completed object/secret bytes, an unwrapped certificate, a raw signature,
/// complete metadata TLV, or the original algorithm configuration.
/// NULL buffer queries length; too-small updates len without partial writes.
/// Getters never reread the card. Other result variants return RESULT_TYPE_MISMATCH;
/// a byte-result operation that is not Completed returns INVALID_STATE.
///
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live without concurrent
/// mutation/free; len must be initialized, writable and non-NULL. A non-NULL
/// buffer must cover the incoming *len writable bytes and not alias len.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_result_copy_bytes(
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
        match &op.inner {
            #[cfg(feature = "openpgp")]
            Inner::OpenPgp(p) => match p.result() {
                Ok(
                    canokey::openpgp::Outcome::Bytes(b)
                    | canokey::openpgp::Outcome::Signature { bytes: b, .. },
                ) => copy(b.as_bytes(), buffer, len),
                Ok(_) => TYPE,
                Err(_) => STATE,
            },
            #[cfg(feature = "admin")]
            Inner::Admin(p) => match p.result() {
                Ok(v) => match admin::result_bytes(&v.value) {
                    Some(b) => copy(&b, buffer, len),
                    None => TYPE,
                },
                Err(_) => STATE,
            },
            Inner::Metadata(p) => match p.result() {
                Ok(v) => copy(v.fields().raw.as_bytes(), buffer, len),
                Err(_) => STATE,
            },
            Inner::Signature(p) => match p.result() {
                Ok(v) => copy(v.as_bytes(), buffer, len),
                Err(_) => STATE,
            },
            Inner::Sm2Agreement(p) => match p.result() {
                Ok(a) => copy(a.key.as_bytes(), buffer, len),
                Err(_) => STATE,
            },
            Inner::Directory(p) => match p.result() {
                Ok(d) => copy(d.raw(), buffer, len),
                Err(_) => STATE,
            },
            Inner::ContainerName(p) => match p.result() {
                Ok(n) => copy(n.as_utf16le(), buffer, len),
                Err(_) => STATE,
            },
            Inner::AlgorithmConfig(p) => match p.result() {
                Ok(v) => copy(v.raw(), buffer, len),
                Err(_) => STATE,
            },
            Inner::Certificate(p) => match p.result() {
                Ok(v) => copy(v.der(), buffer, len),
                Err(_) => STATE,
            },
            Inner::Object(p) => match p.result() {
                Ok(v) => copy(v.as_bytes(), buffer, len),
                Err(_) => STATE,
            },
            _ => TYPE,
        }
    })
}
/// Caller-owned `cnk_pin_status_v1` result. Initialize struct_size before querying.
#[repr(C)]
pub struct CnkPinStatus {
    /// Caller-supplied size in bytes; must include the entire supported struct prefix.
    pub struct_size: u32,
    /// CNK_PIN_HAS_VERIFIED, CNK_PIN_HAS_REMAINING and CNK_PIN_HAS_TOTAL bitmap.
    pub presence_flags: u32,
    /// Zero/one verification observation, meaningful only with CNK_PIN_HAS_VERIFIED.
    pub verified: u8,
    /// Retry observation, meaningful only with CNK_PIN_HAS_REMAINING.
    pub remaining: u8,
    /// Total retry observation, meaningful only with CNK_PIN_HAS_TOTAL.
    pub total: u8,
    /// Zero/one blocked observation; always present on a successful query.
    pub blocked: u8,
}
/// Copy completed PIN status into caller POD without accessing the device.
/// Presence bits distinguish unknown verified/remaining/total values. Wrong type
/// returns RESULT_TYPE_MISMATCH; a pending PIN-status operation returns INVALID_STATE.
///
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live without concurrent
/// mutation/free. out must be writable/non-NULL with initialized struct_size
/// covering the supported CnkPinStatus prefix.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_pin_status(
    op: *const CnkOperation,
    out: *mut CnkPinStatus,
) -> u32 {
    guard(|| {
        if out.is_null() || (*out).struct_size < std::mem::size_of::<CnkPinStatus>() as u32 {
            return ARG;
        }
        let Some(op) = op.as_ref() else {
            return ARG;
        };
        if op.poisoned {
            return STATE;
        }
        match &op.inner {
            #[cfg(feature = "openpgp")]
            Inner::OpenPgp(p) => match p.result() {
                Ok(canokey::openpgp::Outcome::PinStatus(s)) => {
                    ptr::write(
                        out,
                        CnkPinStatus {
                            struct_size: (*out).struct_size,
                            presence_flags: 1 | (u32::from(s.retries_remaining.is_some()) << 1),
                            verified: u8::from(s.verified),
                            remaining: s.retries_remaining.unwrap_or(0),
                            total: 0,
                            blocked: u8::from(s.blocked),
                        },
                    );
                    OK
                }
                Ok(_) => TYPE,
                Err(_) => STATE,
            },
            Inner::PinStatus(p) => match p.result() {
                Ok(s) => {
                    let size = (*out).struct_size;
                    ptr::write(
                        out,
                        CnkPinStatus {
                            struct_size: size,
                            presence_flags: u32::from(s.verified.is_some())
                                | (u32::from(s.retries_remaining.is_some()) << 1)
                                | (u32::from(s.retries_total.is_some()) << 2),
                            verified: u8::from(s.verified.unwrap_or(false)),
                            remaining: s.retries_remaining.unwrap_or(0),
                            total: s.retries_total.unwrap_or(0),
                            blocked: u8::from(s.blocked),
                        },
                    );
                    OK
                }
                Err(_) => STATE,
            },
            _ => TYPE,
        }
    })
}
/// Copy raw actual-firmware bytes, without adding a NUL terminator.
/// NULL buffer queries length; BUFFER_TOO_SMALL updates len without partial copying.
/// The original text may not be valid UTF-8.
///
/// # Safety
/// Follow the crate pointer/aliasing contract. profile must be live with no
/// concurrent free; len must be initialized, writable and non-NULL. A non-NULL
/// buffer must cover the incoming *len writable bytes and not alias len.
#[no_mangle]
pub unsafe extern "C" fn cnk_profile_firmware_text(
    profile: *const CnkProfile,
    buffer: *mut u8,
    len: *mut usize,
) -> u32 {
    guard(|| match profile.as_ref() {
        Some(p) => copy(p.0.info().firmware_text(), buffer, len),
        None => ARG,
    })
}
/// Copy parsed firmware major/minor/patch into three u32 values. Unrecognized
/// firmware returns CNK_RESULT_TYPE_MISMATCH and leaves output untouched.
/// # Safety
/// profile is live without mutation/free; version covers three aligned writable
/// u32 values and does not alias the profile. No pointer is retained.
#[no_mangle]
pub unsafe extern "C" fn cnk_profile_firmware_version(
    profile: *const CnkProfile,
    version: *mut u32,
) -> u32 {
    guard(|| {
        if version.is_null() {
            return ARG;
        }
        let Some(profile) = profile.as_ref() else {
            return ARG;
        };
        let Some(firmware) = profile.0.info().firmware() else {
            return TYPE;
        };
        let (major, minor, patch) = (firmware.major, firmware.minor, firmware.patch);
        *version = major as u32;
        *version.add(1) = minor as u32;
        *version.add(2) = patch as u32;
        OK
    })
}
/// Copy model UTF-8 without a NUL terminator, with normal size-query semantics.
/// An absent model returns CNK_RESULT_TYPE_MISMATCH, distinct from empty text.
/// # Safety
/// profile is live without mutation/free; len is initialized/writable and a
/// non-NULL buffer covers its capacity. Outputs do not alias input or each other.
#[no_mangle]
pub unsafe extern "C" fn cnk_profile_model_copy(
    profile: *const CnkProfile,
    buffer: *mut u8,
    len: *mut usize,
) -> u32 {
    guard(|| {
        let Some(profile) = profile.as_ref() else {
            return ARG;
        };
        let Some(model) = profile.0.info().model() else {
            return TYPE;
        };
        copy(model.as_bytes(), buffer, len)
    })
}
/// Decode the observed four-byte big-endian serial into a u32. Missing serial
/// returns CNK_RESULT_TYPE_MISMATCH and never invents an identifier.
/// # Safety
/// profile is live without mutation/free; out is aligned/writable/non-NULL and
/// does not alias the profile. Output is unchanged on failure.
#[no_mangle]
pub unsafe extern "C" fn cnk_profile_serial_u32(profile: *const CnkProfile, out: *mut u32) -> u32 {
    guard(|| {
        if out.is_null() {
            return ARG;
        }
        let Some(profile) = profile.as_ref() else {
            return ARG;
        };
        let Some(serial) = profile.0.info().serial() else {
            return TYPE;
        };
        let Ok(bytes) = <[u8; 4]>::try_from(serial) else {
            return TYPE;
        };
        *out = u32::from_be_bytes(bytes);
        OK
    })
}

/// Write CNK_SUPPORT_UNKNOWN/SUPPORTED/UNSUPPORTED for observed PIV availability.
/// This is a local snapshot query, not a card probe.
///
/// # Safety
/// Follow the crate pointer/aliasing contract. profile must be live with no
/// concurrent free and out must be writable/non-NULL.
#[no_mangle]
pub unsafe extern "C" fn cnk_profile_piv_support(profile: *const CnkProfile, out: *mut u32) -> u32 {
    guard(|| {
        if out.is_null() {
            return ARG;
        }
        let Some(p) = profile.as_ref() else {
            return ARG;
        };
        *out = match p.0.capability(Capability::Piv).support {
            Support::Supported => 1,
            Support::Unsupported => 2,
            Support::Unknown => 0,
        };
        OK
    })
}
/// Resolve an observed PIV wire identifier to a CNK_ALGORITHM_* semantic code.
/// This consults the immutable profile's configuration and legacy IDs; it does
/// not authorize key use. Factories still enforce capability and input policy.
/// Unknown/out-of-range IDs return CNK_INVALID_ARGUMENT and leave out unchanged.
/// # Safety
/// profile must be live/readable with no concurrent mutation or free. out must
/// be non-NULL, aligned/writable and not alias the profile. No pointer is retained.
#[no_mangle]
pub unsafe extern "C" fn cnk_profile_piv_algorithm_from_wire(
    profile: *const CnkProfile,
    wire: u32,
    out: *mut u32,
) -> u32 {
    guard(|| {
        if out.is_null() || wire > u8::MAX as u32 {
            return ARG;
        }
        let Some(profile) = profile.as_ref() else {
            return ARG;
        };
        match profile.0.algorithm_from_wire_id(wire as u8) {
            Some(algorithm) => {
                *out = piv_keys::algorithm_code(algorithm);
                OK
            }
            None => ARG,
        }
    })
}

/// Require observed PIV and key-algorithm support without I/O or retained state.
/// `algorithm` is a CNK_ALGORITHM_* semantic code, never a configurable wire ID.
/// Unsupported and unknown capabilities return distinct typed protocol errors;
/// invalid codes/pointers return INVALID_ARGUMENT. This does not authenticate,
/// reserve a slot, or replace an operation factory's policy and input checks.
///
/// # Safety
/// profile must be live/readable without concurrent mutation or free. Optional
/// error must be writable with initialized struct_size and must not alias profile.
#[no_mangle]
pub unsafe extern "C" fn cnk_profile_piv_require_algorithm(
    profile: *const CnkProfile,
    algorithm: u32,
    error: *mut CnkError,
) -> u32 {
    guard(|| {
        if let Err(code) = clear_error(error) {
            return code;
        }
        let Some(profile) = profile.as_ref() else {
            return ARG;
        };
        let algorithm = match piv_keys::algorithm(algorithm) {
            Ok(algorithm) => algorithm,
            Err(code) => return code,
        };
        match profile
            .0
            .capability(Capability::Piv)
            .require()
            .and_then(|()| profile.0.key_algorithm_support(algorithm).require())
        {
            Ok(()) => OK,
            Err(e) => failure(e, error),
        }
    })
}

/// Discard active operation state locally; terminal states are unchanged.
/// No APDU or transport cancellation occurs. Drain or isolate in-flight I/O
/// before reusing the application connection. The handle still needs free.
///
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live and exclusively
/// accessible, with no concurrent calls or free.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_cancel(op: *mut CnkOperation) -> u32 {
    guard(|| {
        let Some(op) = op.as_mut() else {
            return ARG;
        };
        dispatch!(&mut op.inner,inner=>inner.cancel());
        OK
    })
}

/// Write the local CNK_STATE_* value without advancing.
/// A panic-poisoned operation returns INVALID_STATE instead of a normal state.
///
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live without concurrent
/// mutation/free and out must be writable/non-NULL.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_state(op: *const CnkOperation, out: *mut u32) -> u32 {
    guard(|| {
        if out.is_null() {
            return ARG;
        }
        let Some(op) = op.as_ref() else {
            return ARG;
        };
        if op.poisoned {
            return STATE;
        }
        *out = dispatch!(&op.inner, inner => inner.state()) as u32;
        OK
    })
}
/// Copy a stored protocol failure into caller POD, returning OK if one exists.
/// Returns INVALID_STATE when there is no stored failure or op is poisoned.
/// Clears the supported error fields before querying; this is not global last_error.
///
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live without concurrent
/// mutation/free. out must be writable/non-NULL with initialized struct_size.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_error(op: *const CnkOperation, out: *mut CnkError) -> u32 {
    guard(|| {
        if out.is_null() {
            return ARG;
        }
        if let Err(code) = clear_error(out) {
            return code;
        }
        let Some(op) = op.as_ref() else {
            return ARG;
        };
        if op.poisoned {
            return STATE;
        }
        match dispatch!(&op.inner, inner => inner.error()) {
            Some(error) => {
                failure(error.clone(), out);
                OK
            }
            None => STATE,
        }
    })
}
/// Write CNK_RESULT_* only for a Completed operation.
/// Returns INVALID_STATE before completion, after take/cancel/failure, or if poisoned.
///
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live without concurrent
/// mutation/free and out must be writable/non-NULL.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_result_kind(op: *const CnkOperation, out: *mut u32) -> u32 {
    guard(|| {
        if out.is_null() {
            return ARG;
        }
        let Some(op) = op.as_ref() else {
            return ARG;
        };
        if op.poisoned
            || dispatch!(&op.inner, inner => inner.state()) != canokey::OperationState::Completed
        {
            return STATE;
        }
        *out = match &op.inner {
            #[cfg(feature = "openpgp")]
            Inner::OpenPgp(_) => 17,
            #[cfg(feature = "oath")]
            Inner::Oath(_) => 16,
            #[cfg(feature = "admin")]
            Inner::Admin(_) => 15,
            Inner::Probe(_) => 1,
            Inner::Unit(_) => 2,
            Inner::PinStatus(_) => 3,
            Inner::Object(_) => 4,
            Inner::Certificate(_) => 5,
            Inner::Mutation(_) => 6,
            Inner::Metadata(_) => 7,
            Inner::PublicKey(_) => 8,
            Inner::Signature(_) => 9,
            Inner::AlgorithmConfig(_) => 10,
            Inner::Batch(_) => 11,
            Inner::Sm2Agreement(_) => 14,
            Inner::Directory(_) => 12,
            Inner::ContainerName(_) => 13,
        };
        OK
    })
}

/// Copy a 2.x profile with a caller-confirmed Admin 40/07 extension flag.
/// This performs no I/O and returns a separately owned immutable snapshot. The
/// caller must have an acknowledged write on the same connection generation;
/// unknown/lost outcomes must not be promoted to an observed flag.
///
/// # Safety
/// Follow the crate pointer contract. profile is live/non-NULL, enabled is 0/1,
/// out is writable/non-NULL and does not alias inputs; error is optional/versioned.
/// On success release the new *out with cnk_profile_free. Original stays owned.
#[no_mangle]
pub unsafe extern "C" fn cnk_profile_with_legacy_piv_extensions(
    profile: *const CnkProfile,
    enabled: u32,
    out: *mut *mut CnkProfile,
    error: *mut CnkError,
) -> u32 {
    guard(|| {
        if out.is_null() {
            return ARG;
        }
        ptr::write(out, ptr::null_mut());
        if let Err(code) = clear_error(error) {
            return code;
        }
        if enabled > 1 {
            return ARG;
        }
        let Some(profile) = profile.as_ref() else {
            return ARG;
        };
        match profile.0.with_legacy_piv_extensions(enabled != 0) {
            Ok(p) => {
                ptr::write(out, Box::into_raw(Box::new(CnkProfile(p))));
                OK
            }
            Err(e) => failure(e, error),
        }
    })
}
