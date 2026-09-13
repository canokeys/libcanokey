# API contracts

[README](../README.md) lists implemented features and examples;
[plan](../plan.md) tracks remaining work. Rustdoc and the
[experimental C header](../crates/canokey-c/include/canokey.h) define signatures.
[References](references.md) records firmware and consumer evidence.

## Ownership and execution

| Object | Contents | Application owner |
| --- | --- | --- |
| `DeviceProfile` | Immutable capability snapshot; no connection or authentication state | Device/token context |
| `Operation<T>` | Owned inputs, configuration, protocol machine, current APDU, result/error | One synchronous call or asynchronous use case |

Constructors own inputs and copy required profile data. Source profiles and FFI
buffers may be released immediately; changing application state cannot alter an
existing operation. The core has no transport, runtime, registry, mutable globals,
credential cache, or background tasks. Pure codecs return values without operations.

| Action | Contract |
| --- | --- |
| `start` | From Created, return Exchange/Done or failure; construction performs no I/O |
| `command` | Borrow the complete pending APDU in AwaitingResponse; repeatable |
| `advance` | Consume one response containing data and SW1/SW2 |
| `result` / `take_result` | Borrow a completed result repeatedly / transfer it once |
| `error` | Preserve the original typed protocol failure |
| `cancel` | Clear active working data from Created/AwaitingResponse; otherwise a no-op |
| drop/free/close | Release memory; no APDU, logout, reconnect, retry, or rollback |

Invalid-state calls do not replace the stored protocol error. Completion/failure
releases execution secrets; owned results survive until take/drop. Rust borrows
cannot span a mutable operation call. Bindings copy results and close deterministically.

The application holds exclusive access to the connection across the **entire
operation**. Transport failures remain application errors; drop the operation
instead of replaying its command. Cancellation does not stop pending I/O. Drain or
isolate old I/O before connection reuse, and never pass a late response to a new
operation. Connection generations and locks belong to the application.

## APDU/TLV conversations

- Exchange complete command/response APDUs. Disable transport continuation/retries.
- Le distinguishes absent, short 00=256, and extended 0000=65536. Frame budgets
  include headers/status words; extended encoding requires explicit permission.
- ISO 61xx produces GET RESPONSE; 6100 requests up to 256 bytes, within the channel
  limit. Only explicitly safe commands may repeat once after 6Cxx. Never accumulate
  rejected response data or restart authentication/private operations/mutations.
- Chaining checks intermediate acknowledgements and stops on failure. Decode TLV
  after reassembly. The internal machine interface composes operations, not I/O.
- Definite-length BER preserves order and duplicates. Semantic parsers check
  required/unique fields, lengths, bounds and trailing bytes without panicking.

`OperationOptions` bounds each frame, input bytes, cumulative response bytes and
exchange count. Defaults are 1 MiB cumulative response data, 4096 exchanges and TLV
depth 16. These are host budgets, not device capacity claims. Known unencodable
commands fail before transmission; no-progress continuation fails promptly.

## Profiles and probing

Actual firmware text/version, model, serial bytes and PIV application version are
separate observations. PIV compatibility version never substitutes for firmware.
`probe_device` reads Admin firmware/model/serial; default PIV mode then selects PIV,
reads its version and reads algorithm configuration only where probing is known safe.
Minimal mode stops after Admin. Probe performs no credential attempts or writes.

Capabilities distinguish Supported, Unsupported and Unknown; evidence distinguishes
Observed, FirmwareMatrix and LatestKnownFallback. Firmware rules live in compat.
Observed IDs override fallback names; guessed IDs never authorize extended private
operations or writes. Required failures and malformed responses propagate. Only
recognized optional unsupported statuses downgrade; authentication-required discovery
remains unknown with a warning. Unknown firmware text stays observable.

Probe changes applets and must not interrupt authentication. Reconnect requires a
new profile. Configuration changes or uncertain writes invalidate relevant profile
observations; ordinary key/certificate changes invalidate application caches.
`MutationResult::profile_effect` does not refresh either cache automatically.

## Authentication and PIV values

Standalone operations select once, then apply `Access::None`, `Pin`, `Management`
or `PinAndManagement` before their target. None does not assert an authenticated
session. Management precedes PIN so VERIFY stays next to PIN-always operations.
Verify success is not an authorization object surviving SELECT or reconnect.

Management authentication explicitly chooses External or Mutual. Mutual takes a
fresh caller-supplied CSPRNG challenge (3DES eight bytes, AES sixteen). The library
owns block cryptography and constant-time verification. It never tries default
credentials or silently downgrades algorithms/modes. Version evidence is in compat
and [references](references.md#canokey-core-firmware).

| Value | Boundary |
| --- | --- |
| `Slot` | Primary 9A/9C/9D/9E or checked retired index 1..20 (82..95); management 9B is not an asymmetric slot |
| `Pin` / `Puk` | Own 6..8 bytes excluding FF; pad to eight bytes on wire |
| `PinStatus` | Verification/retry fields may be unknown; query 63Cx is data, submitted-PIN 63Cx is failure |
| `ObjectData` | Normalized container value; proven legacy exceptions remain narrow |
| `Certificate` | Unwrapped payload and original compression flag; no X.509 syntax/trust validation |
| `Metadata` | Key/PIN/PUK/management observations; optional fields and Known/Unknown(raw) enums; unknown values cannot build commands |
| `PublicKey` | RSA unsigned big-endian n/e, uncompressed SEC1 points, raw Ed/X/ML bytes; pure SPKI conversion without mathematical key validation |
| `PrivateKeyMaterial` | Checked fixed-width scalars or typed seeds/CRT components; RSA consistency and implicit exponent 65537 remain caller responsibilities |
| `Signature` | Algorithm and explicit encoding; original card bytes, with pure EC DER/P1363 conversions |

Certificate containers require exactly one nonempty 70 field, optional 71=00/01
(absent means uncompressed), and optional empty FE. Duplicate/unknown/malformed
fields and trailing gzip members/data fail. Input and decompressed output are
bounded; gzip CRC/size must match. An empty/malformed container is not an empty slot.
Certificate deletion does not delete a key. Writes are not rolled back on failure.

Signing inputs distinguish RSA encoded blocks (caller hashing/padding), ECDSA
digests (order-bit truncation and short-value padding), nonempty Ed25519 messages,
and SM2 digests (caller computes SM3(ZA||M)). SM2 returns DER on legacy supported
firmware and P1363 on 3.1.0; `Signature::encoding()` reports this without guessing
from bytes. Conversion checks representation, not signature validity.

`sign_streaming` explicitly chooses pure ML-DSA-65 with empty context, randomized
Ed25519 or full-message SM2. All accept empty messages; none substitutes prehash
semantics. SM2 accepts an optional 1..32 byte identity and always starts a chain.
Firmware TLV lengths bound the body to 65535 bytes in addition to host budgets.

RSA decrypt returns a raw modulus-sized block without unpadding. ECDH checks
uncompressed peer points using RustCrypto; X25519 requires 32 RFC 7748 bytes and
rejects an all-zero result. ML-KEM-768 decapsulation requires 1088 ciphertext bytes
and returns 32 secret bytes; implicit rejection does not authenticate the sender.
No KDF is applied. SM2 agreement is a separate protocol, not generic ECDH. `agree_sm2` takes role,
peer static/ephemeral points, identities and key length up front; it returns an own
public ephemeral point and a key derived by the firmware's SM2 KDF. The initiator
reads policy first and rejects PIN-always because the two GA steps cannot preserve
that authorization. Peer networking and key confirmation remain caller-owned.

The compact directory uses a fixed five-byte header with a single-byte payload
length, including values above 127 (not BER long-form). Version 1 has at most 24
six-byte entries. Unknown versions retain their payload without guessed decoding;
unknown/duplicate slots, flags and inconsistent key fields remain diagnostic entries.
Names are at most 78 UTF-16LE bytes without NUL/unpaired surrogates; empty clears
an attribute. Moving/deleting keys leaves certificate objects in their original slots.

`reset_pin_puk_retries` requires management then PIN and restores both credentials
to firmware defaults; attempted writes invalidate credential caches, even on failure.
Batch requires an immediately preceding explicit VERIFY and discards assumed
management authorization afterward. Algorithm-configuration writes must end a Batch
and require reprobe. `reset_piv` never exhausts retries itself; firmware requires both
credentials already blocked. Attestation returns DER without trust verification.

File I/O, private-key PEM/PKCS#8 decoding, CSR policy, PKCS#11 hashing/padding/KDF,
object records and user prompts belong to applications. Optional `canokey::x509`
re-exports the external [x509-info](https://github.com/canokeys/x509-info) parser;
it uses no operation or connection. That project owns its model, CLI and schema
documentation. FRB may map owned fields directly; JSON is not a required bridge.

## Batch

`batch(profile, Vec<BatchRequest>, options)` executes explicit requests under one
SELECT. Requests omit Access and exclude SELECT, probe and nested Batch.
Authentication is an explicit request; mutations require preceding management
authentication. PIN-always requires a VERIFY before each private operation.

A batch accepts 1..=128 requests. Aggregate semantic input uses max_input_bytes;
cumulative responses and retained payloads use max_total_response_bytes, including
decompressed certificates. Stop at the first error without rollback or replay.

`batch_progress(&operation)` exposes successful items while running, after failure,
and after completion. Request/conversation failure retains its index in BatchResults
and the original Error in Operation. SELECT failure has no request index/progress.
Cancelling an active operation discards progress; cancel after failure is a no-op.
Taking the result transfers ownership. Ordinary operations expose no partial success.
Binding getters copy by index without introducing result handles.

## Errors, secrets and dependency reuse

Errors retain kind, phase, raw status when present, credential reference and reported
retries. Interpret status in command context: SELECT NotFound differs from a missing
object. Management failures never invent PIN retries. Mutual cryptogram mismatch
returns DeviceAuthenticationFailed without a fabricated status word. Keep protocol,
binding and transport failures distinct; localization belongs to applications.

Redact secrets/APDUs from Debug and logs. `SecretBytes` zeroizes working storage,
including old allocations replaced during growth. Applications own transport/FFI
copies; immutable UI strings cannot promise erasure. Secret results remain owned
until take/drop and must not be logged.

Reuse `thiserror`, `zeroize`, RustCrypto block/curve/DER/SPKI libraries and bounded
`flate2` decompression. Add dependencies with their first concrete use, minimal
features, compatible MSRV/licenses and checked advisories. No OS RNG or transport
features in core; randomness is caller-supplied. Native/wasm dependency checks enforce
these boundaries. Package reuse does not establish device support.

## Bindings

The C ABI has only `cnk_profile_t` and `cnk_operation_t` opaque handles. Inputs are
copied versioned descriptors; errors are caller-owned POD; results use query-size/copy.
There is no init/finalize, result/error/key handle, borrowed internal pointer or
thread-local last_error. Semantic integer enums are distinct from wire IDs.

- POD begins with struct_size; reject unknown input enums/flags. NULL options means
  defaults; explicit zero budgets are invalid. ABI stability is not frozen yet.
- Constructors initialize output handles to NULL and leave no partial handle on failure.
- NULL copy buffers query size. Short buffers update length without partial copying.
  Text has no NUL terminator. Getters never execute the operation.
- Probe profile transfer succeeds once and survives free(op). Other results are copied.
  free(NULL) is safe; non-NULL handles must be freed once with the matching function.
- Callers guarantee aligned live pointers, non-overlapping ranges, and no concurrent
  mutation/free. Catch unwindable panics; poisoned operations can only be freed.
  Dangling pointers and allocator/process aborts cannot be made recoverable.

A Console FRB adapter belongs in Console and calls the Rust facade directly. It may
hold a private enum of concrete Operation types and Option for idempotent close,
but must not duplicate protocol state. Dart owns async execution; Python bindings
would follow the same model with a caller-owned synchronous loop. Binding examples:
[Console](console-integration.md), [PKCS#11](pkcs11-integration.md).
