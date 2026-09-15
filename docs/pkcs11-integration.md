# PKCS#11 integration boundary

This document is **application pseudocode**, not an implemented PKCS#11 integration. The [runnable C probe](../crates/canokey-c/examples/probe.c) uses today's ABI with complete cleanup. The [header](../crates/canokey-c/include/canokey.h) is authoritative for available functions. Shared contracts live in [design](api-design.md).

## Caller-owned state

```c
typedef struct {
    SCARDHANDLE card;
    uint64_t connection_generation;
    Mutex lock;
    cnk_profile_t *profile;
    LoginState login;
    SecretBuffer cached_user_pin, cached_management_key;
    ObjectCache objects;
} TokenContext;

typedef struct {
    TokenContext *token;
    CK_SESSION_HANDLE handle;
    SignState sign;
    DigestState digest;
    SecretBuffer context_pin;
} SessionContext;
```

All session tables, PKCS#11 objects, mechanism/hash state and login policies remain in C. Rust does not mirror them. Ordinary USER/SO login propagation across sessions, logout and lock ordering belong to the module; CKU_CONTEXT_SPECIFIC belongs to one session operation and must not silently use cached USER authorization.

If the module caches raw unpadded credentials for verification after SELECT, it owns erasure and cache policy. A profile belongs to the token context. An operation belongs to one C call and is freed after copying/taking its result. There is no Rust init/finalize or global handle registry.

## Executor and public certificate read

`CardLease` denotes the device lock plus PCSC transaction across the whole operation. The checked helpers below jump to cleanup on failure. `copy_command` uses query-size/reserve/copy; `pcsc_exchange_raw` makes one SCardTransmit call, retains SW1/SW2 and performs no continuation/replay. Buffers and error mapping are application-owned.

```c
/* Pseudocode helpers: CHECK_CNK maps protocol/binding errors by purpose;
 * CHECK_CK preserves application CK_RV. Both jump to cleanup. */
static CK_RV run_op(CardLease *lease, cnk_operation_t *op, ErrorPurpose purpose) {
    cnk_error_v1 error = {.struct_size = sizeof(error)};
    cnk_step_kind_t step = 0;
    ByteBuffer command = {0}, response = {0};
    CK_RV rv = CKR_OK;
    CHECK_CNK(cnk_operation_start(op, &step, &error), purpose);
    while (step == CNK_STEP_EXCHANGE) {
        CHECK_CK(copy_command(op, &command));
        CHECK_CK(pcsc_exchange_raw(lease, &command, &response));
        CHECK_CNK(cnk_operation_advance(op, response.data, response.length,
                                       &step, &error), purpose);
        buffer_wipe(&command);
        buffer_wipe(&response);
    }
    if (step != CNK_STEP_DONE) rv = CKR_DEVICE_ERROR;
cleanup:
    buffer_wipe_and_free(&command);
    buffer_wipe_and_free(&response);
    return rv; /* Borrows op; the caller frees it. */
}

/* Uses the current public-certificate ABI; no access descriptor is required. */
static CK_RV read_certificate(TokenContext *token, CardLease *lease,
                              uint32_t slot, ByteBuffer *out) {
    cnk_operation_t *op = NULL;
    cnk_error_v1 error = {.struct_size = sizeof(error)};
    CK_RV rv = CKR_OK;
    size_t n = 0;
    CHECK_CNK(cnk_piv_read_certificate_new(token->profile, slot, &lease->options,
                                          &op, &error), PURPOSE_READ_CERTIFICATE);
    CHECK_CK(run_op(lease, op, PURPOSE_READ_CERTIFICATE));
    CHECK_CNK(cnk_operation_result_copy_bytes(op, NULL, &n), PURPOSE_READ_CERTIFICATE);
    CHECK_CK(buffer_reserve(out, n));
    CHECK_CNK(cnk_operation_result_copy_bytes(op, out->data, &n), PURPOSE_READ_CERTIFICATE);
    out->length = n;
cleanup:
    cnk_operation_free(op);
    if (rv != CKR_OK) buffer_wipe_and_free(out);
    return rv;
}
```

Getter errors are binding status codes, so CHECK_CNK must only inspect error POD when a call actually populated it. The copied certificate payload survives operation destruction; the application parses X.509 and maps CKA_VALUE. Getter size queries do not reread the card. Only exact NotFound may mean an absent enumerated object; authentication, malformed containers and unsupported formats are distinct failures.

Probe uses the same executor: create `cnk_probe_device_new`, run, take_profile into the token context, free the operation. On reconnect invalidate the old profile **before** probing, so failure cannot leave a previous device's snapshot in use. Connection/frame budgets must match constructor options. I/O or allocation failures never cause a second SCardTransmit to retrieve a result.

## Login and signing

C_Login USER prepares a controlled PIN copy, runs the implemented verify-pin operation under the device lock, and commits token login state only on success; always free the operation. Map PIN AuthenticationFailed/PinBlocked to CKR_PIN_INCORRECT/CKR_PIN_LOCKED in this context. SO can run cnk_piv_authenticate_management_key_new with an explicit mode/key and a fresh C-supplied mutual challenge.

C_SignInit only records validated key/slot/mechanism/length/authorization requirements. It does not create a Rust operation spanning PKCS#11 calls. For P-256 CKM_ECDSA, a C_Sign adapter can use:

```c
/* Application pseudocode using the current C factory and result getter. */
const CK_ULONG required = 64; /* P1363 r || s, from validated key metadata. */
if (out == NULL) { *inout_len = required; return CKR_OK; }
if (*inout_len < required) {
    *inout_len = required;
    return CKR_BUFFER_TOO_SMALL;
}
/* Now obtain the card lease and validate USER/context-specific authorization. */
cnk_operation_t *op = NULL;
cnk_piv_access_v1 access = {.struct_size = sizeof(access)};
CHECK_CK(prepare_sign_access(session, &access));
CHECK_CNK(cnk_piv_sign_new(token->profile, slot, CNK_ALGORITHM_P256,
                           CNK_SIGN_DIGEST, digest.data, digest.length, &access,
                           &lease->options, &op, &error), PURPOSE_SIGN);
CHECK_CK(run_op(lease, op, PURPOSE_SIGN));
size_t n = required;
CHECK_CNK(cnk_operation_signature_p1363(op, out, &n), PURPOSE_SIGN);
*inout_len = (CK_ULONG)n;
cleanup:
cnk_operation_free(op);
finish_sign_attempt(session, rv);
```

Size-only and too-small paths send no APDU and consume neither signature nor context-specific authorization. After real execution, an unexpected result length is an internal/device error, not a reason to sign again. Production code must obey PKCS#11 state retention/termination rules for every return path.

CKM_ECDSA_SHA256 hashes in C; RSA PKCS1/PSS prepares the encoded block in C. C_SignUpdate stores C digest state; C_SignFinal creates a local operation only when producing output. PIV PinPolicy::Always and CKA_ALWAYS_AUTHENTICATE must agree: required VERIFY belongs in the same operation as the private-key command.

`cnk_piv_generate_key_new` returns public-key fields/SPKI for C object creation;
`cnk_piv_import_key_new` copies typed components before encoding. An explicit
AUTH/IMPORT/WRITE CERT sequence uses `cnk_piv_batch_new` with copied request
descriptors. On failure, inspect `cnk_operation_batch_progress` and indexed getters
before freeing the operation; update caches for successful preceding mutations.
No additional input/result handles or Rust session state are needed.

Raw RSA decryption, ECDH/X25519 derivation and ML-KEM decapsulation also return
owned bytes through the normal copy getter. The C module retains responsibility
for mechanism parameters, unpadding/KDF, secret erasure and supported-mechanism
advertising; the existence of a core factory alone does not implement a PKCS#11
mechanism.

## Cleanup events

| Event | Application action |
| --- | --- |
| C_Logout | Propagate token login changes and clear credentials; explicitly run logout or reset/disconnect as needed. Free alone does not revoke card authentication |
| Disconnect/reconnect | Drain or isolate in-flight I/O, advance generation, clear credentials/affected caches, release profile, probe the new connection |
| C_CloseSession | Clear session hash/context authorization; retain shared token profile as needed and follow standard login semantics |
| Token destruction/C_Finalize | Block new calls, wait for in-flight calls, release C state/profile/PCSC resources; no Rust finalize |

Use `CNK_PIV_USE_EXISTING` after the host has selected/authenticated under its
PC/SC transaction. Borrow the immutable profile under its token lock only for
factory construction, then release it before driving the operation. No separate
context handle or caller-declared PIN/admin state is needed. Reservations and
cached credentials remain host-owned; this flag never authorizes a PKCS11 call.
