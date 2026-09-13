//! Experimental C ABI. No transport, global handles, or thread-local errors.
//!
//! # Safety
//! Every non-null pointer must be aligned, live, and valid for its declared length.
//! Output ranges must not alias inputs or handles. Handles are created by this
//! library, accessed without concurrent mutation, and freed exactly once.
//! A non-null versioned struct must contain at least its declared supported prefix.
// These common C ABI contracts apply to every exported unsafe entry point.
#![allow(clippy::missing_safety_doc)]
use canokey::{
    compatibility::{Capability, DeviceProfile, Support},
    piv, Error, ErrorKind, Operation, OperationOptions, ProbeMode, ProbeOptions, SecretBytes, Step,
};
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    ptr, slice,
};
#[repr(C)]
pub struct CnkError {
    pub struct_size: u32,
    pub kind: u32,
    pub phase: u32,
    pub reference: u32,
    pub presence_flags: u32,
    pub status_word: u16,
    pub retries_remaining: u8,
    pub reserved: u8,
}
#[repr(C)]
pub struct CnkOptions {
    pub struct_size: u32,
    pub flags: u32,
    pub max_command_bytes: u32,
    pub max_response_bytes: u32,
    pub max_total_response_bytes: u32,
    pub max_exchanges: u32,
}
pub struct CnkProfile(DeviceProfile);
pub struct CnkOperation {
    inner: Inner,
    poisoned: bool,
}
enum Inner {
    Probe(Operation<DeviceProfile>),
    Unit(Operation<()>),
    PinStatus(Operation<piv::PinStatus>),
    Object(Operation<SecretBytes>),
    Certificate(Operation<piv::Certificate>),
}
macro_rules! dispatch {
    ($value:expr, $op:ident => $body:expr) => {
        match $value {
            Inner::Probe($op) => $body,
            Inner::Unit($op) => $body,
            Inner::PinStatus($op) => $body,
            Inner::Object($op) => $body,
            Inner::Certificate($op) => $body,
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
        _ => 255,
    }
}
unsafe fn failure(error: Error, out: *mut CnkError) -> u32 {
    if !out.is_null() {
        (*out).kind = kind_code(error.kind);
        (*out).phase = error.phase as u32;
        (*out).reference = error.reference.map_or(0, |r| r as u32 + 1);
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
#[no_mangle]
pub extern "C" fn cnk_abi_version() -> u32 {
    0x0000_0001
}
#[no_mangle]
pub unsafe extern "C" fn cnk_profile_free(profile: *mut CnkProfile) {
    if !profile.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(profile))));
    }
}
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_free(op: *mut CnkOperation) {
    if !op.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(op))));
    }
}
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
            piv::Access::None,
            options(opts)?,
        )
        .map(Inner::Object)
        .map_err(|e| failure(e, error))
    })
}
/// Read a public certificate. Slot is a PIV key reference, not an object tag.
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
            piv::Access::None,
            options(opts)?,
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
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_start(
    op: *mut CnkOperation,
    step: *mut u32,
    error: *mut CnkError,
) -> u32 {
    drive(op, step, error, None)
}
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
#[repr(C)]
pub struct CnkPinStatus {
    pub struct_size: u32,
    pub presence_flags: u32,
    pub verified: u8,
    pub remaining: u8,
    pub total: u8,
    pub blocked: u8,
}
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
            Inner::Probe(_) => 1,
            Inner::Unit(_) => 2,
            Inner::PinStatus(_) => 3,
            Inner::Object(_) => 4,
            Inner::Certificate(_) => 5,
        };
        OK
    })
}
