//! Allocation and ownership regressions for the selected-context C ABI.
use canokey_c::*;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::ptr;

thread_local! {
    static ALLOCATIONS: Cell<(bool, usize)> = const { Cell::new((false, 0)) };
}
struct ObservedAllocator;
fn record(size: usize) {
    let _ = ALLOCATIONS.try_with(|state| {
        let (enabled, largest) = state.get();
        if enabled {
            state.set((true, largest.max(size)));
        }
    });
}
unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        System.alloc_zeroed(layout)
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        System.dealloc(pointer, layout);
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record(size);
        System.realloc(pointer, layout, size)
    }
}
#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

// These exported symbols intentionally use the same C ABI as canokey.h.
// Opaque pointee layouts never cross the ABI; only library-owned pointers do.
#[allow(improper_ctypes)]
extern "C" {
    fn cnk_piv_sign_streaming_new(
        context: *const CnkProfile,
        slot: u32,
        mode: u32,
        message: *const u8,
        message_len: usize,
        user_id: *const u8,
        user_id_len: usize,
        auth: *const std::ffi::c_void,
        options: *const CnkOptions,
        out: *mut *mut CnkOperation,
        error: *mut CnkError,
    ) -> u32;
    fn cnk_piv_write_object_new(
        context: *const CnkProfile,
        tag: *const u8,
        tag_len: usize,
        data: *const u8,
        data_len: usize,
        auth: *const std::ffi::c_void,
        options: *const CnkOptions,
        out: *mut *mut CnkOperation,
        error: *mut CnkError,
    ) -> u32;
    fn cnk_piv_write_certificate_new(
        context: *const CnkProfile,
        slot: u32,
        data: *const u8,
        data_len: usize,
        auth: *const std::ffi::c_void,
        options: *const CnkOptions,
        out: *mut *mut CnkOperation,
        error: *mut CnkError,
    ) -> u32;
}

struct Context(*mut CnkProfile);
impl Drop for Context {
    fn drop(&mut self) {
        unsafe { cnk_profile_free(self.0) }
    }
}
fn context() -> Context {
    unsafe {
        let mut probe = ptr::null_mut();
        let mut step = 0;
        assert_eq!(
            cnk_probe_device_new(1, ptr::null(), &mut probe, ptr::null_mut()),
            0
        );
        assert_eq!(cnk_operation_start(probe, &mut step, ptr::null_mut()), 0);
        for response in [
            &[0x90, 0][..],
            b"3.1.0\x90\x00",
            &[0x6d, 0],
            &[0x6d, 0],
            &[0x90, 0],
            &[5, 7, 0, 0x90, 0],
            &[
                1, 0xe0, 5, 0x16, 0xe1, 0x53, 0x54, 0x55, 0x56, 0x57, 0x90, 0,
            ],
        ] {
            assert_eq!(
                cnk_operation_advance(
                    probe,
                    response.as_ptr(),
                    response.len(),
                    &mut step,
                    ptr::null_mut()
                ),
                0
            );
        }
        let mut profile = ptr::null_mut();
        assert_eq!(cnk_operation_take_profile(probe, &mut profile), 0);
        cnk_operation_free(probe);
        Context(profile)
    }
}
const EXISTING: CnkOptions = CnkOptions {
    struct_size: size_of::<CnkOptions>() as u32,
    flags: 2,
    max_command_bytes: 261,
    max_response_bytes: 258,
    max_total_response_bytes: 1024 * 1024,
    max_exchanges: 4096,
};
fn error() -> CnkError {
    CnkError {
        struct_size: size_of::<CnkError>() as u32,
        kind: 0,
        phase: 0,
        reference: 0,
        presence_flags: 0,
        status_word: 0,
        retries_remaining: 0,
        reserved: 0,
    }
}
fn observed(f: impl FnOnce() -> u32) -> (u32, usize) {
    ALLOCATIONS.with(|state| state.set((true, 0)));
    let result = f();
    let peak = ALLOCATIONS.with(|state| state.replace((false, 0)).1);
    (result, peak)
}

#[test]
fn streaming_user_id_is_rejected_before_copy_and_matches_standalone_rules() {
    let context = context();
    let input = vec![0x41; 1024 * 1024 + 1];
    // Include the exact protocol boundary and the formerly accepted non-SM2 ID.
    for (mode, len, expected) in [
        (3, 32, 0),
        (3, 33, 1),
        (3, input.len(), 1),
        (2, 1, 1),
        (3, 0, 1),
    ] {
        let mut output = ptr::null_mut();
        let mut error = error();
        let (status, peak) = observed(|| unsafe {
            cnk_piv_sign_streaming_new(
                context.0,
                0x9c,
                mode,
                ptr::null(),
                0,
                input.as_ptr(),
                len,
                ptr::null(),
                &EXISTING,
                &mut output,
                &mut error,
            )
        });
        unsafe { cnk_operation_free(output) };
        assert_eq!(status, expected);
        if expected != 0 {
            assert!(output.is_null());
        }
        assert!(
            peak < 1024 * 1024,
            "copied a rejected user ID: {peak} bytes"
        );
    }
}

#[test]
fn mutation_payloads_are_rejected_before_allocation() {
    let context = context();
    let input = vec![0x41; 1024 * 1024 + 1];
    let tag = [0x5f, 0xc1, 5];
    for certificate in [false, true] {
        let mut output = ptr::null_mut();
        let mut error = error();
        let (status, peak) = observed(|| unsafe {
            if certificate {
                cnk_piv_write_certificate_new(
                    context.0,
                    0x9c,
                    input.as_ptr(),
                    input.len(),
                    ptr::null(),
                    &EXISTING,
                    &mut output,
                    &mut error,
                )
            } else {
                cnk_piv_write_object_new(
                    context.0,
                    tag.as_ptr(),
                    tag.len(),
                    input.as_ptr(),
                    input.len(),
                    ptr::null(),
                    &EXISTING,
                    &mut output,
                    &mut error,
                )
            }
        });
        unsafe { cnk_operation_free(output) };
        assert_eq!(status, 5);
        assert_eq!(error.kind, 5);
        assert!(output.is_null());
        assert!(
            peak < input.len(),
            "copied a rejected mutation payload: {peak} bytes"
        );
    }
}
