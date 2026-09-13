#ifndef CANOKEY_H
#define CANOKEY_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Experimental ABI 0.1. Valid, non-aliasing pointers are the caller's contract.
 * Constructors copy inputs. Never free Rust allocations with the C allocator.
 * No function performs I/O; serialize access to each operation.
 */
typedef struct CnkProfile cnk_profile_t;
typedef struct CnkOperation cnk_operation_t;
typedef uint32_t cnk_status_t;
typedef uint32_t cnk_step_kind_t;
enum { CNK_OK=0, CNK_INVALID_ARGUMENT=1, CNK_INVALID_STATE=2,
       CNK_BUFFER_TOO_SMALL=3, CNK_RESULT_TYPE_MISMATCH=4,
       CNK_PROTOCOL_ERROR=5, CNK_PANIC=6 };
enum { CNK_STEP_EXCHANGE=1, CNK_STEP_DONE=2 };
enum { CNK_PROBE_MINIMAL=0, CNK_PROBE_PIV=1 };
enum { CNK_SUPPORT_UNKNOWN=0, CNK_SUPPORT_SUPPORTED=1, CNK_SUPPORT_UNSUPPORTED=2 };
enum { CNK_ERROR_INVALID_ARGUMENT=1, CNK_ERROR_INVALID_PIN=2,
       CNK_ERROR_INVALID_RESPONSE=3, CNK_ERROR_PROTOCOL_VIOLATION=4,
       CNK_ERROR_LIMIT_EXCEEDED=5, CNK_ERROR_AUTHENTICATION_FAILED=6,
       CNK_ERROR_PIN_BLOCKED=7, CNK_ERROR_SECURITY_STATUS=8,
       CNK_ERROR_CONDITIONS=9, CNK_ERROR_NOT_FOUND=10,
       CNK_ERROR_UNSUPPORTED_DEVICE=11, CNK_ERROR_UNSUPPORTED_FEATURE=12,
       CNK_ERROR_UNSUPPORTED_ALGORITHM=13, CNK_ERROR_CAPABILITY_UNKNOWN=14,
       CNK_ERROR_UNSUPPORTED_PROTOCOL=15, CNK_ERROR_UNEXPECTED_STATUS=16,
       CNK_ERROR_OPERATION_STATE=17, CNK_ERROR_OTHER=255 };
enum { CNK_STATE_CREATED=0, CNK_STATE_AWAITING_RESPONSE=1,
       CNK_STATE_COMPLETED=2, CNK_STATE_FAILED=3, CNK_STATE_CANCELLED=4,
       CNK_STATE_RESULT_TAKEN=5 };
enum { CNK_PHASE_CONSTRUCTION=0, CNK_PHASE_SELECT=1, CNK_PHASE_COMMAND=2,
       CNK_PHASE_AUTHENTICATION=3, CNK_PHASE_PARSING=4, CNK_PHASE_CONVERSATION=5 };
enum { CNK_REFERENCE_NONE=0, CNK_REFERENCE_PIN=1, CNK_REFERENCE_PUK=2,
       CNK_REFERENCE_MANAGEMENT_KEY=3, CNK_REFERENCE_ADMIN_PIN=4 };
enum { CNK_ERROR_HAS_SW=1, CNK_ERROR_HAS_RETRIES=2 };
enum { CNK_RESULT_PROFILE=1, CNK_RESULT_UNIT=2, CNK_RESULT_PIN_STATUS=3,
       CNK_RESULT_OBJECT=4 };
enum { CNK_ALLOW_EXTENDED=1 };
enum { CNK_PIN_HAS_VERIFIED=1, CNK_PIN_HAS_REMAINING=2, CNK_PIN_HAS_TOTAL=4 };
typedef struct {
    uint32_t struct_size,kind,phase,reference,presence_flags;
    uint16_t status_word;
    uint8_t retries_remaining,reserved;
} cnk_error_v1;
typedef struct {
    uint32_t struct_size,flags,max_command_bytes,max_response_bytes,
             max_total_response_bytes,max_exchanges;
} cnk_operation_options_v1;
typedef struct {
    uint32_t struct_size,presence_flags;
    uint8_t verified,remaining,total,blocked;
} cnk_pin_status_v1;
uint32_t cnk_abi_version(void);
void cnk_profile_free(cnk_profile_t *);
void cnk_operation_free(cnk_operation_t *);
cnk_status_t cnk_probe_device_new(uint32_t mode,const cnk_operation_options_v1 *,cnk_operation_t **,cnk_error_v1 *);
cnk_status_t cnk_piv_verify_pin_new(const cnk_profile_t *,const uint8_t *,size_t,const cnk_operation_options_v1 *,cnk_operation_t **,cnk_error_v1 *);
cnk_status_t cnk_piv_get_pin_status_new(const cnk_profile_t *,const cnk_operation_options_v1 *,cnk_operation_t **,cnk_error_v1 *);
cnk_status_t cnk_piv_read_object_new(const cnk_profile_t *,const uint8_t *tag,size_t,const cnk_operation_options_v1 *,cnk_operation_t **,cnk_error_v1 *);
cnk_status_t cnk_operation_start(cnk_operation_t *,cnk_step_kind_t *,cnk_error_v1 *);
cnk_status_t cnk_operation_advance(cnk_operation_t *,const uint8_t *,size_t,cnk_step_kind_t *,cnk_error_v1 *);
/* NULL buffer queries size, success writes length, too-small never partially copies. */
cnk_status_t cnk_operation_command(const cnk_operation_t *,uint8_t *,size_t *);
cnk_status_t cnk_operation_take_profile(cnk_operation_t *,cnk_profile_t **);
cnk_status_t cnk_operation_result_copy_bytes(const cnk_operation_t *,uint8_t *,size_t *);
cnk_status_t cnk_operation_pin_status(const cnk_operation_t *,cnk_pin_status_v1 *);
cnk_status_t cnk_profile_firmware_text(const cnk_profile_t *,uint8_t *,size_t *);
cnk_status_t cnk_profile_piv_support(const cnk_profile_t *,uint32_t *);
cnk_status_t cnk_operation_cancel(cnk_operation_t *);
cnk_status_t cnk_operation_state(const cnk_operation_t *,uint32_t *);
cnk_status_t cnk_operation_error(const cnk_operation_t *,cnk_error_v1 *);
cnk_status_t cnk_operation_result_kind(const cnk_operation_t *,uint32_t *);
#ifdef __cplusplus
}
#endif
#endif
