# API design

This document owns the common contracts and future API direction. [README](../README.md) is the authoritative implementation inventory; factories explicitly marked **planned** below are not callable yet. See [plan](../plan.md) for sequencing and [references](references.md) for evidence. Actual Rust signatures and the [experimental C header](../crates/canokey-c/include/canokey.h) take precedence over pseudocode.

## Ownership and execution

There are two lifecycle objects:

| Object | Contents | Application owner |
| --- | --- | --- |
| `DeviceProfile` | Immutable protocol capability snapshot | Device/token context |
| `Operation<T>` | Owned inputs/configuration, machine, current APDU, result/error | One local synchronous call or asynchronous use case |

There are no Rust device/operation registries, global locks, credential caches, thread-local errors, or background tasks. Immutable protocol constants may be static. Profile data contains no connection, current applet, login state, or PIN. Constructors copy required configuration and own inputs; source profiles and FFI input buffers can be released immediately. Changes to a profile do not alter existing operations.

```rust,ignore
pub enum Step { Exchange, Done }
pub enum OperationState {
    Created, AwaitingResponse, Completed, Failed, Cancelled, ResultTaken,
}
impl<T> Operation<T> {
    pub fn start(&mut self) -> Result<Step, Error>;
    pub fn advance(&mut self, response: &[u8]) -> Result<Step, Error>;
    pub fn command(&self) -> Result<&CommandApdu, Error>;
    pub fn result(&self) -> Result<&T, Error>;
    pub fn take_result(&mut self) -> Result<T, Error>;
    pub fn error(&self) -> Option<&Error>;
    pub fn state(&self) -> OperationState;
    pub fn cancel(&mut self);
}
```

| Action | Contract |
| --- | --- |
| start | From Created, return Exchange/Done or protocol failure; constructors perform no I/O |
| command | In AwaitingResponse, borrow the complete APDU; repeatable without advancing |
| advance | Consume one complete response data + SW1/SW2 for the pending command |
| result | In Completed, borrow the result repeatedly without device access |
| take_result | Transfer an independent result once, entering ResultTaken |
| error | Preserve the typed protocol error after failure |
| cancel | Clear active working data and enter Cancelled from Created/AwaitingResponse; otherwise a no-op |
| drop/close/free | Release memory only; no logout, disconnect, reconnect, rollback, or APDU |

Invalid-state calls return OperationStateError without replacing the stored protocol error. Completion/failure drops unnecessary working secrets; results survive until take/drop. Rust borrows cannot span the next mutable operation call. Bindings return copies; close is deterministic with a finalizer only as fallback. Pure codecs and conversions remain plain functions.

The application holds exclusive access to the physical connection for the **entire operation**. Transport errors stay application errors; close/drop the operation instead of feeding it a Timeout or replaying a command. Cancellation does not stop pending I/O. Drain/cancel the request successfully or isolate its old connection before reuse; never feed a late response to a new operation. Connection generations belong to the application, and serial numbers do not substitute for them.

## APDU/TLV conversations

`CommandApdu::encode`, `ResponseApdu::parse`, checked tags, TLV readers/writers, and applet command builders are pure computation. Current PIV command builders return `LogicalCommand`; the conversation layer performs physical encoding and segmentation. The doc-hidden machine extension point composes applet operations and never calls transport.

- Expected length distinguishes absent Le, short 00=256, and extended 0000=65536; short/extended encoding is explicit.
- Definite-length BER TLV preserves order and duplicates. Semantic parsers enforce required/unique fields, bounds, and trailing-byte rules. Malformed input must not panic.
- ISO 61xx produces GET RESPONSE; 6100 means up to 256 bytes, bounded by the channel. Applets select CLA/continuation policy.
- Only commands marked safe may retry one physical command after 6Cxx. Do not accumulate its rejected response data, restart authentication, or replay mutations.
- Chaining validates intermediate acknowledgements and stops on failure. Parse TLV only after reassembly.
- Planned OATH 06/A5 continuation and nonempty-9000 rules need an applet-specific conversation, not the ISO loop.

`OperationOptions` combines per-exchange byte limits/extended encoding permission and cumulative response/exchange budgets. Frame sizes include APDU headers or status words. Default cumulative response limit is 1 MiB and exchange limit 4096; TLV default depth is 16. These are host budgets, not card capacity claims. Unsafe/unencodable known commands fail before transmission; no-progress continuation fails promptly. Applications must disable their own continuation and preserve raw status words.

## Profiles and probing

`DeviceProfile::from_observations(DeviceObservations)` normalizes evidence from one device. Firmware text, optional parsed version and suffix, model, serial bytes, and PIV application version remain distinct. The current profile exposes info, capability, warning and algorithm-ID accessors; a richer per-applet profile is planned.

Capabilities distinguish Supported, Unsupported and Unknown; evidence distinguishes Observed, FirmwareMatrix and LatestKnownFallback. Capability (availability), variant (encoding), and quirk (historical behavior) are separate concepts. Firmware comparisons live only in compat. Observed IDs override matrix defaults; missing fields do not imply support. Unknown newer firmware gets conservative stable behavior, not wholesale rejection or speculative writes. PIV compatibility version never replaces real firmware.

`probe_device(ProbeOptions)` defaults to PIV mode. Minimal mode stops after Admin reads:

```text
00 A4 04 00 05 F0 00 00 00 00   SELECT Admin
00 31 00 00 00                  Required firmware text
00 31 01 00 00                  Optional model
00 32 00 00 00                  Optional serial
00 A4 04 00 05 A0 00 00 03 08   SELECT PIV
00 FD 00 00 00                  PIV application version
00 EE 01 00 00                  Algorithm config, only when known safe to probe
```

No default PIN attempts or write-based discovery. Probe changes applets and must not interrupt authentication. Required failures and malformed responses propagate. Only recognized optional unsupported statuses downgrade; authentication-required discovery remains Unknown with a warning. Unrecognized firmware text is retained. New/replaced connections require fresh probing. A future configuration mutation returning `ProfileEffect::ReprobeRequired`, or an uncertain configuration write, invalidates the snapshot; ordinary key changes invalidate relevant application object/metadata caches.

## PIV factories and values

Factories take `&DeviceProfile`, owned semantic inputs and `OperationOptions`, returning `Result<Operation<T>, Error>`. There is no persistent protocol session, public Sign class, or operation-specific handle.

| Factory | Result | Status |
| --- | --- | --- |
| select | SelectionInfo | Implemented |
| verify_pin / get_pin_status / logout | () / PinStatus / () | Implemented |
| change_pin / change_puk / unblock_pin | MutationResult | Implemented |
| read_object | ObjectData | Implemented; optional PIN |
| read_certificate | Certificate | Implemented; optional PIN |
| authenticate_management_key / set_management_key | () / MutationResult | Planned |
| get_metadata / read_algorithm_config | Metadata / AlgorithmConfig | Planned standalone factories |
| generate_key / import_key | PublicKey / MutationResult | Planned |
| sign / decrypt / derive | Signature / SecretBytes / SecretBytes | Planned |
| write_object / write_certificate / delete_certificate | MutationResult | Planned |

Slot references cover authentication 9A, signature 9C, key management 9D, card authentication 9E, and checked retired indices 1..20 (wire 82..95). Management reference 9B is not a signing slot. `ObjectId` accepts a complete checked BER tag; certificate mapping is library-owned.

`Pin/Puk::from_bytes` currently accepts 6..8 bytes excluding FF and pads to eight bytes on wire. Other applets use distinct secret types. Current Access is None or Pin. None makes no promise of existing authentication. Standalone operations select once, then authenticate immediately before their target. Verify success is not an authorization token surviving later SELECT or reconnect.

Planned Access adds Management and PinAndManagement. Management authentication explicitly selects External or Mutual; no silent downgrade. The application supplies a fresh CSPRNG challenge (3DES eight bytes, AES sixteen); the library owns witness/challenge cryptography and constant-time verification. Algorithm support must be proven for CanoKey. Dual authentication runs management before PIN so VERIFY stays next to the private operation. No implicit default credentials.

| Value | Contract |
| --- | --- |
| PinStatus | verified/remaining/total may be unknown; query 63Cx is data, submitted-PIN 63Cx is authentication failure; 9000 does not invent retry counts |
| ObjectData | Normalized container value, with discovery 7E and narrow proven legacy CCC/CHUID exceptions; secret-buffer handling |
| Certificate | Unwrapped payload and original compression flag; bounded gzip decoding; no X.509 syntax/trust validation |
| MutationResult | Unchanged or ReprobeRequired profile effect; no claim that application caches were refreshed |
| Metadata (planned) | Key/PIN/PUK/management variants, optional public key and policy, Known/Unknown(raw) fields; unknown values cannot construct commands |
| PublicKey (planned) | Unsigned big-endian RSA n/e, uncompressed SEC1 EC points, raw Ed/X/ML bytes; pure SPKI conversion |
| PrivateKeyMaterial (planned) | Typed, checked secret RSA CRT components, fixed EC scalar, Ed25519 seed, X25519 key, ML-DSA 32-byte / ML-KEM 64-byte seed |
| Signature (planned) | Algorithm-tagged result; RSA/Ed/ML raw bytes, ECDSA/SM2 DER or fixed-width P1363 conversion |

Certificate parsing requires exactly one nonempty 70 field, accepts absent 71 as uncompressed, accepts 71=00/01 only, and permits an optional empty FE. Duplicate, unknown, malformed fields and trailing gzip members/data fail. Input and decoded payload are independently bounded by max_total_response_bytes; gzip CRC and size must validate. Empty/malformed containers are not silently treated as empty slots. Object NotFound remains a status-derived error. Future certificate deletion must use the evidenced empty-container encoding without deleting a private key.

Planned SignInput distinguishes RSA encoded block (host owns hash/PKCS1/PSS), ECDSA digest (order-bit truncation and short-value padding), Ed25519 message, SM2 digest (host computes SM3(ZA||M)), and ML-DSA message/context. Unverified contexts are rejected before sending. RSA decrypt returns the modulus-sized raw block; unpadding stays in the application. ECDH/X25519 derive validates peer encoding and returns raw shared secret; no KDF. ML-KEM decapsulation is separate with checked ciphertext/secret lengths. Algorithm names are semantic identifiers, not reconfigurable wire IDs or support promises.

Files, PEM/PKCS#8, CSR/X.509 policy, PKCS#11 padding/KDF and object records stay outside the library. Enable directories, retry configuration, move/delete key, algorithm writes and new algorithms individually by evidence.

## Planned Batch

An owned builder creates one `Operation<BatchResults>` for explicit semantic requests under a single SELECT. Requests omit Access and exclude SELECT, probe and nested Batch; authentication is an explicit request. Bound request count and input bytes. Do not insert extra SELECT or Admin switches. PIN-always requires explicit VERIFY before each private operation.

Stop at the first error with failed index/completed count, without rollback or automatic continuation. A specialized completed-results getter exposes successful preceding items during execution/failure/completion, but not after take/cancel. Ordinary operations do not expose partial success. Binding getters copy by index without introducing result handles.

## Errors and secrets

Error contains kind, phase, optional raw status, secret reference and retries; Batch progress and device-authentication failures are planned extensions. Interpret statuses in command context: 6A82 on SELECT is different from GET DATA; a historical empty-slot 6700 requires a proven narrow quirk. Preserve unknown status values, and never invent user-PIN retries for management authentication.

Keep protocol, binding and transport failures separate. Redact PINs, keys, APDUs, temporary plaintext and sensitive results from Debug/error/log output. Zeroize working buffers, including allocations replaced during growth. Applications own transport/FFI copies; immutable Dart/Python strings cannot promise erasure. Success/failure releases execution secrets while results remain available until take/drop.

## C ABI

Only `cnk_profile_t` and `cnk_operation_t` are opaque. Other inputs are copied descriptors, errors are caller-owned pointer-free POD, results are getters on the operation. No init/finalize, result/error/key/access handles, borrowed internal pointers or global last_error. The experimental header lists implemented factories; the eventual design maps each Rust factory to a `_new` and adds typed metadata/public-key/mutation/Batch getters.

- Semantic enums/flags use fixed uint32_t mappings, distinct from wire algorithm IDs. Status codes: OK=0, INVALID_ARGUMENT=1, INVALID_STATE=2, BUFFER_TOO_SMALL=3, RESULT_TYPE_MISMATCH=4, PROTOCOL_ERROR=5, PANIC=6. Steps: EXCHANGE=1, DONE=2.
- Versioned POD begins with struct_size. Reject unknown input enums/flags. NULL options means defaults; explicit zero budgets are invalid. Final major-version trailing-field compatibility is not frozen yet.
- Constructors copy every input, initialize output handles to NULL, and leave no partial object on failure. Error POD can be NULL; otherwise initialize struct_size. Presence flags distinguish absent SW/retry data.
- NULL copy buffer queries required length; a short buffer updates length without partial copying; success reports actual length. Text has no appended NUL. Getters never advance or resend. Byte getters for certificates return the unwrapped payload.
- take_profile succeeds once on completed probe. The transferred profile survives free(op). Other results are copied before freeing op. free(NULL) is safe; non-NULL handles must be freed exactly once with the matching Rust allocator entry point.
- Callers guarantee aligned, live pointers, non-overlapping input/output/handle ranges, and no concurrent mutation or free. The ABI cannot detect dangling pointers. Catch unwindable panics; a poisoned operation cannot resume but can be freed. Allocator/process aborts are not recoverable errors.

## Dart and Python boundaries

The future Console FRB wrapper lives in Console and depends on the Rust facade, not C ABI. PyO3 belongs in a future canokey-python crate. Wrappers may dispatch private enums of `Operation<T>` and hold Option for idempotent close, but never duplicate command/result/error/protocol state. Expose concrete factories, start/advance, command copies, typed result DTOs, profile transfer, and close.

Dart owns async transport and execution; Python callers own their synchronous loop. Close in finally/context-manager after copying/taking results; finalizers are fallback only. Structured exceptions/DTOs preserve error kind, SW, reference, retries and future Batch progress. Localization and CLI formatting stay in applications. See [Console](console-integration.md) and [PKCS#11](pkcs11-integration.md) for examples.

## Dependency reuse

Use established libraries for standard cryptography and standard key formats. The core should implement CanoKey protocol orchestration and compatibility, not AES/DES rounds, curve arithmetic, constant-time equality, gzip, or general ASN.1 encoding. Keep protocol-facing public types owned and independent of dependency-specific layouts.

| Need | Dependency direction | Boundary and status |
| --- | --- | --- |
| Secret erasure | `zeroize` / `Zeroizing` | Already used by protocol. `SecretBytes` adds redacted Debug and wipes old allocations during growth; replacing that behavior requires equivalent guarantees |
| Certificate gzip | `flate2` with `rust_backend` and default features disabled | Already used by PIV. The applet layer still enforces input/output bounds, container rules, and trailing-data rejection |
| Management-key block cryptography | RustCrypto [`aes`](https://docs.rs/aes), [`des`](https://docs.rs/des), and their matching [`cipher`](https://docs.rs/cipher) traits | Planned for external/mutual authentication. Use exact single-block operations without padding. 3DES is for legacy protocol interoperability; do not implement primitives locally |
| Authentication response comparison | [`subtle`](https://docs.rs/subtle) | Planned constant-time comparison of fixed-size authentication values; reject incorrect public lengths first. Do not compare secrets with ordinary slice equality |
| Signature/public-key encoding | RustCrypto [`der`](https://docs.rs/der), [`spki`](https://docs.rs/spki), and curve-specific signature types where appropriate | Planned DER/P1363 and SPKI conversion. Reuse canonical integer/length handling; no handwritten generic ASN.1 codec |
| EC point validation | RustCrypto [`p256`](https://docs.rs/p256) and the matching curve crates | Planned only when key/peer validation requires it. Use checked point decoding, not just SEC1 prefix/length checks; private signing/key agreement still occurs on the card |

Random bytes remain explicit caller inputs. Do not enable a dependency's OS RNG, runtime, or transport features in the core. Host hashing/padding/KDF that belongs to PKCS#11 or application policy stays in that application; introduce hash/MAC/KDF dependencies only when an implemented protocol requires them.

Registry review on 2026-09-13 found concrete version/feature constraints: current `aes` 0.9.3 declares Rust 1.89, beyond this workspace's 1.85 MSRV. Current `p256` 0.14.0 enables `getrandom` through its `std` feature. Thus "latest" and default features are not automatically suitable. Select a compatible, maintained release and matching trait family, or explicitly revise the MSRV as part of implementation. Use minimal features, enable key-schedule zeroization where offered, and verify the complete resolved dependency closure on native and wasm. Registry metadata is a selection aid, not a completed integration test or an audit claim.

Add these dependencies together with their first real use, rather than populating Cargo.toml with unused future crates. Check license, MSRV, maintenance/security advisories, secret handling and transitive features; track the resulting Cargo.lock. Validate library composition with known-answer vectors and protocol transcripts, including malformed inputs and authentication failure. Package reuse does not establish CanoKey firmware support.

The existing BER TLV reader is a small applet framing codec with explicit bounds and duplicate preservation, distinct from X.509/DER schema handling. Reuse a BER dependency if it satisfies these semantics without losing evidence or adding platform I/O; do not replace it blindly with a DER-only parser. Certificate trust and X.509 policy remain outside the core.

## Later protocols and evidence gaps

Admin will add device/config/storage/chip/core-commit reads, updates, PIN, NFC/NDEF, SM2 configuration and explicit applet reset. Patches preserve unknown bits; multi-APDU writes are not atomic. OATH needs access validation, credentials and calculations with explicit challenge/time/randomness; never automatically retry HOTP increments. OpenPGP needs independent DO, PW1-sign/PW1-other/PW3, KDF, key/policy/operation semantics and caller-supplied fingerprints/timestamps. Keep FIDO's existing CTAP/HID/WebAuthn backends pending separate evaluation.

Before enablement, verify bootstrap firmware coverage, algorithm purpose/slot rules, management mutual authentication by firmware, ML signing modes, and directory/move/delete semantics using firmware sources or controlled transcripts. Generic YubiKey host APIs alone are insufficient evidence. User prompts, intentional PIN exhaustion, and certificate policy are never implicit library actions.
