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
       CNK_ERROR_OPERATION_STATE=17, CNK_ERROR_DEVICE_AUTHENTICATION_FAILED=18,
       CNK_ERROR_OTHER=255 };
enum { CNK_STATE_CREATED=0, CNK_STATE_AWAITING_RESPONSE=1,
       CNK_STATE_COMPLETED=2, CNK_STATE_FAILED=3, CNK_STATE_CANCELLED=4,
       CNK_STATE_RESULT_TAKEN=5 };
enum { CNK_PHASE_CONSTRUCTION=0, CNK_PHASE_SELECT=1, CNK_PHASE_COMMAND=2,
       CNK_PHASE_AUTHENTICATION=3, CNK_PHASE_PARSING=4, CNK_PHASE_CONVERSATION=5 };
enum { CNK_REFERENCE_NONE=0, CNK_REFERENCE_PIN=1, CNK_REFERENCE_PUK=2,
       CNK_REFERENCE_MANAGEMENT_KEY=3, CNK_REFERENCE_ADMIN_PIN=4 };
enum { CNK_ERROR_HAS_SW=1, CNK_ERROR_HAS_RETRIES=2 };
enum { CNK_RESULT_PROFILE=1, CNK_RESULT_UNIT=2, CNK_RESULT_PIN_STATUS=3,
       CNK_RESULT_OBJECT=4, CNK_RESULT_CERTIFICATE=5, CNK_RESULT_MUTATION=6,
       CNK_RESULT_METADATA=7, CNK_RESULT_PUBLIC_KEY=8, CNK_RESULT_SIGNATURE=9,
       CNK_RESULT_ALGORITHM_CONFIG=10, CNK_RESULT_BATCH=11, CNK_RESULT_DIRECTORY=12, CNK_RESULT_CONTAINER_NAME=13 };
enum { CNK_MANAGEMENT_TDES=1, CNK_MANAGEMENT_AES192=2 };
enum { CNK_AUTH_EXTERNAL=1, CNK_AUTH_MUTUAL=2 };
enum { CNK_MANAGEMENT_TOUCH_NEVER=0, CNK_MANAGEMENT_TOUCH_ALWAYS=1 };
enum { CNK_PROFILE_UNCHANGED=0, CNK_PROFILE_REPROBE_REQUIRED=1 };
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
/* All nested inputs are copied. Mutual requires fresh caller CSPRNG bytes;
 * External requires challenge=NULL and challenge_len=0. No default key/mode. */
typedef struct {
    uint32_t struct_size,algorithm,mode;
    const uint8_t *key;
    size_t key_len;
    const uint8_t *challenge;
    size_t challenge_len;
} cnk_piv_management_v1;
/* PIN is optional (NULL/0); management is mandatory for mutation factories.
 * Management runs before PIN, and no SELECT is inserted before the target. */
typedef struct {
    uint32_t struct_size;
    const uint8_t *pin;
    size_t pin_len;
    const cnk_piv_management_v1 *management;
} cnk_piv_access_v1;
typedef struct {
    uint32_t struct_size,profile_effect;
} cnk_mutation_result_v1;
/* Semantic algorithms are distinct from configurable on-wire IDs. */
enum { CNK_ALGORITHM_RSA1024=1, CNK_ALGORITHM_RSA2048=2,
       CNK_ALGORITHM_RSA3072=3, CNK_ALGORITHM_RSA4096=4,
       CNK_ALGORITHM_P256=5, CNK_ALGORITHM_P384=6, CNK_ALGORITHM_P521=7,
       CNK_ALGORITHM_SECP256K1=8, CNK_ALGORITHM_SM2=9,
       CNK_ALGORITHM_ED25519=10, CNK_ALGORITHM_X25519=11,
       CNK_ALGORITHM_MLDSA65=12, CNK_ALGORITHM_MLKEM768=13 };
enum { CNK_KEY_PIN_DEFAULT=0, CNK_KEY_PIN_NEVER=1, CNK_KEY_PIN_ONCE=2, CNK_KEY_PIN_ALWAYS=3 };
enum { CNK_KEY_TOUCH_DEFAULT=0, CNK_KEY_TOUCH_NEVER=1, CNK_KEY_TOUCH_ALWAYS=2, CNK_KEY_TOUCH_CACHED=3 };
enum { CNK_SIGN_RSA_BLOCK=1, CNK_SIGN_DIGEST=2, CNK_SIGN_MESSAGE=3 };
enum { CNK_STREAM_MLDSA65=1, CNK_STREAM_ED25519_RANDOMIZED=2, CNK_STREAM_SM2=3 };
enum { CNK_SIGNATURE_RAW=1, CNK_SIGNATURE_DER=2, CNK_SIGNATURE_P1363=3 };
enum { CNK_PUBLIC_MODULUS=1, CNK_PUBLIC_EXPONENT=2, CNK_PUBLIC_POINT_OR_RAW=3, CNK_PUBLIC_SPKI=4 };
enum { CNK_METADATA_HAS_ALGORITHM=1, CNK_METADATA_HAS_POLICY=2,
       CNK_METADATA_HAS_ORIGIN=4, CNK_METADATA_HAS_DEFAULT=8, CNK_METADATA_HAS_RETRIES=16 };
typedef struct {
    uint32_t struct_size,slot,algorithm,pin_policy,touch_policy;
} cnk_piv_key_parameters_v1;
typedef struct { const uint8_t *data; size_t len; } cnk_bytes_t;
typedef struct {
    uint32_t struct_size,presence_flags;
    uint8_t algorithm_id,pin_policy,touch_policy,origin,is_default,retries_total,retries_remaining,reserved;
} cnk_metadata_v1;
cnk_status_t cnk_piv_generate_key_new(const cnk_profile_t *,const cnk_piv_key_parameters_v1 *,const cnk_piv_access_v1 *,const cnk_operation_options_v1 *,cnk_operation_t **,cnk_error_v1 *);
/* RSA: five components p/q/dP/dQ/qInv, implicit e=65537. Others: one scalar/seed. */
cnk_status_t cnk_piv_import_key_new(const cnk_profile_t *,const cnk_piv_key_parameters_v1 *,const cnk_bytes_t *,size_t count,const cnk_piv_access_v1 *,const cnk_operation_options_v1 *,cnk_operation_t **,cnk_error_v1 *);
cnk_status_t cnk_piv_get_metadata_new(const cnk_profile_t *,uint32_t reference,const cnk_piv_access_v1 *,const cnk_operation_options_v1 *,cnk_operation_t **,cnk_error_v1 *);
cnk_status_t cnk_piv_read_algorithm_config_new(const cnk_profile_t *,const cnk_piv_access_v1 *,const cnk_operation_options_v1 *,cnk_operation_t **,cnk_error_v1 *);
cnk_status_t cnk_piv_sign_new(const cnk_profile_t *,uint32_t slot,uint32_t algorithm,uint32_t kind,const uint8_t *,size_t,const cnk_piv_access_v1 *,const cnk_operation_options_v1 *,cnk_operation_t **,cnk_error_v1 *);
/* Explicit full-message signing. ML-DSA has empty context; only SM2 accepts
 * user_id (NULL/0 for default or 1..32 bytes). No implicit mode selection. */
cnk_status_t cnk_piv_sign_streaming_new(const cnk_profile_t *,uint32_t slot,uint32_t mode,const uint8_t *message,size_t message_len,const uint8_t *user_id,size_t user_id_len,const cnk_piv_access_v1 *,const cnk_operation_options_v1 *,cnk_operation_t **,cnk_error_v1 *);
cnk_status_t cnk_piv_decrypt_new(const cnk_profile_t *,uint32_t slot,uint32_t algorithm,const uint8_t *,size_t,const cnk_piv_access_v1 *,const cnk_operation_options_v1 *,cnk_operation_t **,cnk_error_v1 *);
cnk_status_t cnk_piv_derive_new(const cnk_profile_t *,uint32_t slot,uint32_t algorithm,const uint8_t *,size_t,const cnk_piv_access_v1 *,const cnk_operation_options_v1 *,cnk_operation_t **,cnk_error_v1 *);
/* ML-KEM-768: exactly 1088 ciphertext bytes, 32 result bytes. No KDF or sender
 * authentication. Uses the observed enabled algorithm ID; inputs are copied. */
cnk_status_t cnk_piv_decapsulate_new(const cnk_profile_t *,uint32_t slot,const uint8_t *,size_t,const cnk_piv_access_v1 *,const cnk_operation_options_v1 *,cnk_operation_t **,cnk_error_v1 *);
cnk_status_t cnk_piv_read_metadata_directory_new(const cnk_profile_t * profile,const cnk_piv_access_v1 * auth,const cnk_operation_options_v1 * opts,cnk_operation_t ** out,cnk_error_v1 * error);
cnk_status_t cnk_piv_read_container_name_new(const cnk_profile_t * profile,uint32_t reference,const cnk_piv_access_v1 * auth,const cnk_operation_options_v1 * opts,cnk_operation_t ** out,cnk_error_v1 * error);
cnk_status_t cnk_piv_set_container_name_new(const cnk_profile_t * profile,uint32_t reference,const uint8_t * data,size_t len,const cnk_piv_access_v1 * auth,const cnk_operation_options_v1 * opts,cnk_operation_t ** out,cnk_error_v1 * error);
cnk_status_t cnk_piv_move_key_new(const cnk_profile_t * profile,uint32_t source,uint32_t target,const cnk_piv_access_v1 * auth,const cnk_operation_options_v1 * opts,cnk_operation_t ** out,cnk_error_v1 * error);
cnk_status_t cnk_piv_delete_key_new(const cnk_profile_t * profile,uint32_t reference,const cnk_piv_access_v1 * auth,const cnk_operation_options_v1 * opts,cnk_operation_t ** out,cnk_error_v1 * error);
cnk_status_t cnk_piv_reset_pin_puk_retries_new(const cnk_profile_t * profile,uint32_t pin_retries,uint32_t puk_retries,const cnk_piv_access_v1 * auth,const cnk_operation_options_v1 * opts,cnk_operation_t ** out,cnk_error_v1 * error);
cnk_status_t cnk_piv_set_algorithm_config_new(const cnk_profile_t * profile,const uint8_t * data,size_t len,const cnk_piv_access_v1 * auth,const cnk_operation_options_v1 * opts,cnk_operation_t ** out,cnk_error_v1 * error);
cnk_status_t cnk_piv_attest_new(const cnk_profile_t * profile,uint32_t reference,const cnk_operation_options_v1 * opts,cnk_operation_t ** out,cnk_error_v1 * error);
cnk_status_t cnk_piv_reset_piv_new(const cnk_profile_t * profile,const cnk_operation_options_v1 * opts,cnk_operation_t ** out,cnk_error_v1 * error);
/* Directory raw fields remain observable even when individual entries have issues.
 * Container-name result bytes are UTF-16LE without a terminator. Batch MOVE_KEY
 * uses reference=source, algorithm=target. RESET_PIN_PUK_RETRIES uses reference=PIN
 * retries, algorithm=PUK retries; it resets credentials to defaults. Configuration
 * writes use data/data_len and must terminate the batch. */
enum { CNK_DIRECTORY_UNKNOWN_SLOT=1, CNK_DIRECTORY_DUPLICATE_SLOT=2,
       CNK_DIRECTORY_EMPTY_FLAGS=4, CNK_DIRECTORY_UNKNOWN_FLAGS=8,
       CNK_DIRECTORY_KEY_FIELDS_WITHOUT_KEY=16 };
typedef struct { uint32_t struct_size,version,decoded,count; } cnk_directory_info_v1;
typedef struct {
    uint32_t struct_size;
    uint8_t reference,flags,algorithm_id,origin,pin_policy,touch_policy,reserved[2];
    uint32_t issues;
} cnk_directory_entry_v1;
cnk_status_t cnk_operation_directory_info(const cnk_operation_t *,cnk_directory_info_v1 *);
cnk_status_t cnk_operation_directory_entry(const cnk_operation_t *,size_t,cnk_directory_entry_v1 *);
cnk_status_t cnk_operation_batch_item_directory_info(const cnk_operation_t *,size_t,cnk_directory_info_v1 *);
cnk_status_t cnk_operation_batch_item_directory_entry(const cnk_operation_t *,size_t,size_t,cnk_directory_entry_v1 *);
cnk_status_t cnk_operation_metadata(const cnk_operation_t *,cnk_metadata_v1 *);
cnk_status_t cnk_operation_public_key_copy(const cnk_operation_t *,uint32_t field,uint8_t *,size_t *);
cnk_status_t cnk_operation_key_algorithm(const cnk_operation_t *,uint32_t *);
/* Result bytes preserve card encoding. EC conversions never execute the operation. */
cnk_status_t cnk_operation_signature_encoding(const cnk_operation_t *,uint32_t *);
cnk_status_t cnk_operation_signature_der(const cnk_operation_t *,uint8_t *,size_t *);
cnk_status_t cnk_operation_signature_p1363(const cnk_operation_t *,uint8_t *,size_t *);
enum { CNK_BATCH_VERIFY_PIN=1, CNK_BATCH_AUTHENTICATE_MANAGEMENT=2, CNK_BATCH_LOGOUT=3,
       CNK_BATCH_READ_OBJECT=4, CNK_BATCH_READ_CERTIFICATE=5, CNK_BATCH_WRITE_OBJECT=6,
       CNK_BATCH_WRITE_CERTIFICATE=7, CNK_BATCH_DELETE_CERTIFICATE=8, CNK_BATCH_GET_METADATA=9,
       CNK_BATCH_READ_ALGORITHM_CONFIG=10, CNK_BATCH_GENERATE_KEY=11, CNK_BATCH_IMPORT_KEY=12,
       CNK_BATCH_SIGN=13, CNK_BATCH_DECRYPT=14, CNK_BATCH_DERIVE=15, CNK_BATCH_SET_MANAGEMENT_KEY=16,
       CNK_BATCH_DECAPSULATE=17, CNK_BATCH_SIGN_STREAMING=18, CNK_BATCH_READ_DIRECTORY=19,
       CNK_BATCH_READ_CONTAINER_NAME=20, CNK_BATCH_SET_CONTAINER_NAME=21,
       CNK_BATCH_MOVE_KEY=22, CNK_BATCH_DELETE_KEY=23, CNK_BATCH_RESET_PIN_PUK_RETRIES=24,
       CNK_BATCH_SET_ALGORITHM_CONFIG=25, CNK_BATCH_ATTEST=26 };
/* Only fields relevant to kind are read. Unused pointers/lengths should be NULL/0.
 * All nested ranges are copied. No SELECT/probe/nested Batch requests exist. */
typedef struct {
    uint32_t struct_size,kind,reference,algorithm,input_kind;
    const uint8_t *data;
    size_t data_len;
    const uint8_t *tag;
    size_t tag_len;
    const cnk_piv_management_v1 *management;
    const cnk_piv_key_parameters_v1 *parameters;
    const cnk_bytes_t *components;
    size_t component_count;
    const uint8_t *user_id;
    size_t user_id_len;
} cnk_piv_batch_request_v1;
typedef struct {
    uint32_t struct_size,completed_count,has_failed_index,failed_index;
} cnk_batch_progress_v1;
cnk_status_t cnk_piv_batch_new(const cnk_profile_t *,const cnk_piv_batch_request_v1 *,size_t,const cnk_operation_options_v1 *,cnk_operation_t **,cnk_error_v1 *);
cnk_status_t cnk_operation_batch_progress(const cnk_operation_t *,cnk_batch_progress_v1 *);
cnk_status_t cnk_operation_batch_item_kind(const cnk_operation_t *,size_t,uint32_t *);
/* Public-key items return DER SPKI here; other byte results use their normal encoding. */
cnk_status_t cnk_operation_batch_item_copy_bytes(const cnk_operation_t *,size_t,uint8_t *,size_t *);
cnk_status_t cnk_operation_batch_item_mutation(const cnk_operation_t *,size_t,cnk_mutation_result_v1 *);
cnk_status_t cnk_operation_batch_item_metadata(const cnk_operation_t *,size_t,cnk_metadata_v1 *);
cnk_status_t cnk_operation_batch_item_public_key_copy(const cnk_operation_t *,size_t,uint32_t field,uint8_t *,size_t *);
cnk_status_t cnk_operation_batch_item_signature_encoding(const cnk_operation_t *,size_t,uint32_t *);
cnk_status_t cnk_operation_batch_item_signature_der(const cnk_operation_t *,size_t,uint8_t *,size_t *);
cnk_status_t cnk_operation_batch_item_signature_p1363(const cnk_operation_t *,size_t,uint8_t *,size_t *);
uint32_t cnk_abi_version(void);
void cnk_profile_free(cnk_profile_t *);
void cnk_operation_free(cnk_operation_t *);
cnk_status_t cnk_probe_device_new(uint32_t mode,const cnk_operation_options_v1 *,cnk_operation_t **,cnk_error_v1 *);
cnk_status_t cnk_piv_verify_pin_new(const cnk_profile_t *,const uint8_t *,size_t,const cnk_operation_options_v1 *,cnk_operation_t **,cnk_error_v1 *);
cnk_status_t cnk_piv_get_pin_status_new(const cnk_profile_t *,const cnk_operation_options_v1 *,cnk_operation_t **,cnk_error_v1 *);
cnk_status_t cnk_piv_read_object_new(const cnk_profile_t *,const uint8_t *tag,size_t,const cnk_operation_options_v1 *,cnk_operation_t **,cnk_error_v1 *);
/* Public certificate read; slot is 9A/9C/9D/9E or 82..95.
 * Byte result getter returns unwrapped, bounded-decompressed bytes.
 * No X.509 syntax or trust validation is performed. */
cnk_status_t cnk_piv_read_certificate_new(const cnk_profile_t *,uint32_t slot,const cnk_operation_options_v1 *,cnk_operation_t **,cnk_error_v1 *);
cnk_status_t cnk_piv_authenticate_management_key_new(const cnk_profile_t *,const cnk_piv_management_v1 *,const cnk_operation_options_v1 *,cnk_operation_t **,cnk_error_v1 *);
cnk_status_t cnk_piv_write_object_new(const cnk_profile_t *,const uint8_t *tag,size_t tag_len,const uint8_t *data,size_t data_len,const cnk_piv_access_v1 *,const cnk_operation_options_v1 *,cnk_operation_t **,cnk_error_v1 *);
cnk_status_t cnk_piv_write_certificate_new(const cnk_profile_t *,uint32_t slot,const uint8_t *data,size_t data_len,const cnk_piv_access_v1 *,const cnk_operation_options_v1 *,cnk_operation_t **,cnk_error_v1 *);
cnk_status_t cnk_piv_delete_certificate_new(const cnk_profile_t *,uint32_t slot,const cnk_piv_access_v1 *,const cnk_operation_options_v1 *,cnk_operation_t **,cnk_error_v1 *);
cnk_status_t cnk_piv_set_management_key_new(const cnk_profile_t *,uint32_t algorithm,const uint8_t *key,size_t key_len,uint32_t touch,const cnk_piv_access_v1 *,const cnk_operation_options_v1 *,cnk_operation_t **,cnk_error_v1 *);
cnk_status_t cnk_operation_mutation_result(const cnk_operation_t *,cnk_mutation_result_v1 *);
cnk_status_t cnk_operation_start(cnk_operation_t *,cnk_step_kind_t *,cnk_error_v1 *);
cnk_status_t cnk_operation_advance(cnk_operation_t *,const uint8_t *,size_t,cnk_step_kind_t *,cnk_error_v1 *);
/* NULL buffer queries size, success writes length, too-small never partially copies.
 * result_copy_bytes returns object/secret data, certificate payload, raw signature,
 * complete metadata TLV or raw algorithm configuration according to result kind. */
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
