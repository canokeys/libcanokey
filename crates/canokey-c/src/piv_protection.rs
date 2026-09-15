//! Pure decoders for host-managed PIV protection objects.
use super::*;

/// Decode stored ADMIN DATA flags without I/O or retained input.
/// Empty 53/80 means unconfigured; malformed data is an error, not flags zero.
/// Flags describe stored claims and do not prove live PUK blocking/authentication.
/// # Safety
/// data covers len readable bytes; NULL requires zero length. flags must be
/// non-NULL/aligned/writable. Optional error is writable with initialized
/// struct_size. Outputs must not alias each other or input. Failure leaves flags
/// unchanged. The input bound is checked before parsing or allocation.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_admin_data_flags(
    data: *const u8,
    len: usize,
    flags: *mut u32,
    error: *mut CnkError,
) -> u32 {
    guard(|| {
        if let Err(code) = clear_error(error) {
            return code;
        }
        if flags.is_null() {
            return ARG;
        }
        if len > 128 {
            return failure(
                Error::new(ErrorKind::LimitExceeded).at(canokey::Phase::Parsing),
                error,
            );
        }
        let input = match bytes(data, len) {
            Ok(input) => input,
            Err(code) => return code,
        };
        match piv::ManagementProtection::from_admin_object(input) {
            Ok(policy) => {
                *flags = policy.flags() as u32;
                OK
            }
            Err(e) => failure(e, error),
        }
    })
}

/// Decode and copy the 24-byte management key from complete protected PRINTED.
/// NULL output queries size; short output reports 24 without partial copying.
/// Parsing alone never authenticates the key or authorizes its use.
/// # Safety
/// data covers len readable bytes; NULL requires zero length. out_len must be
/// non-NULL/aligned/readable/writable. Non-NULL out covers the incoming capacity.
/// Optional error has writable initialized struct_size. No output aliases input,
/// another output or error. Temporary secret storage is zeroized on every exit.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_printed_management_key_copy(
    data: *const u8,
    len: usize,
    out: *mut u8,
    out_len: *mut usize,
    error: *mut CnkError,
) -> u32 {
    guard(|| {
        if let Err(code) = clear_error(error) {
            return code;
        }
        if out_len.is_null() {
            return ARG;
        }
        if len > 64 {
            return failure(
                Error::new(ErrorKind::LimitExceeded).at(canokey::Phase::Parsing),
                error,
            );
        }
        let input = match bytes(data, len) {
            Ok(input) => input,
            Err(code) => return code,
        };
        match piv::protected_management_key_from_object(input) {
            Ok(key) => copy(key.as_bytes(), out, out_len),
            Err(e) => failure(e, error),
        }
    })
}
