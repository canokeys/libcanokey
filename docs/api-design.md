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
Observed IDs override fallback names; 3.1+ IDs colliding with AES management (0A)
or randomized Ed25519 (FF) remain raw observations and cannot authorize extension
operations. Guessed IDs never authorize extended private
operations or writes. Required failures and malformed responses propagate. Only
recognized optional unsupported statuses downgrade; authentication-required discovery
remains unknown with a warning. Unknown firmware text stays observable.

Probe changes applets and must not interrupt authentication. Reconnect requires a
new profile. Configuration changes or uncertain writes invalidate relevant profile
observations; ordinary key/certificate changes invalidate application caches.
`MutationResult::profile_effect` does not refresh either cache automatically.

The historical matrix follows ckman's pinned firmware changelog and executable
feature rules, cross-checked against core sources. It recognizes 1.3 and the existing
1.5.2–3.0.3/3.1.0 ranges; missing, unrecognized and newer base versions cannot authorize historical layouts.
Development/build suffixes are retained in identity observations and use their
declared numeric base version by default, with a DeclaredBaseVersion warning. Applet-reported version numbers never
select a dialect. See each applet's historical subsection for command boundaries.

PIV baseline slots, 3DES management, key/object operations and blocked-credential
reset extend to 1.3. Explicit generation policies require 2.0. PIV SELECT preserves
old authentication through 1.6.2; `PivSelectResetsAuthentication` records the 2.0
transition. Operations still authenticate explicitly and never assume SELECT logout.
Probe SELECT and historical final APDUs carry short explicit Le. Intermediate
command-chain fragments retain the protocol engine's ordinary chaining format.

PIV EE configuration reads start at 3.0; probes omit EE on 2.x. After an acknowledged
2.x Admin 40/07 write, callers may create a new immutable snapshot using
`with_legacy_piv_extensions(bool)` (C: `cnk_profile_with_legacy_piv_extensions`).
This records caller-confirmed enablement and uses firmware-fixed IDs; it never
fabricates an `AlgorithmConfig` response. Absent enablement remains Unknown and
explicit false is Unsupported. Lost responses and reconnections require renewed
evidence. Ed/X private-operation fix gates remain separate from the switch.

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

## Admin

`admin::operation` owns a Request and optional Admin PIN (6..64 unpadded bytes).
It selects once and authenticates explicitly before protected commands. Empty VERIFY
returns status data; submitted-PIN failures retain AdminPin and retries. Factory reset
rejects a supplied PIN and requires the card's existing blocked/physical-presence state.
Applet resets use Admin authorization and destroy the named applet's data/credentials.

Configuration patches read current state, preserve unspecified fields and only write
changes. Unknown feature bits remain observable and prevent unsafe feature overwrites.
All patch fields are checked before the first write. Writes persist separately:
`Outcome::confirmed_writes` is available through progress even after failure, and
`reprobe_required` is set before a profile-affecting write is exposed. An unacknowledged
write may still have changed the device. Invalidate credential/object caches on their
mutation attempts too. Neither progress nor completion is an automatic refresh.

The 3.1 CTAP SM2 configuration contains
two signed big-endian i32 identifiers, without an enable flag. NFC commands are vendor
hooks; a supported firmware layout does not establish vendor hardware support.

### Historical Admin layouts

Actual firmware chooses `AdminConfigurationLayout`: 1.3 has seven bytes ending
in OpenPGP touch flags/cache time; 1.5.2–1.6.1 has five configuration flags;
1.6.2–2.x adds keyboard return; 3.0 reserves bytes 1/5; 3.1 uses byte 5 for applet
feature bits. Reads return `Value::LegacyConfiguration` before 3.1. Optional
getters never invent NDEF/WebUSB or keyboard flags. Common configuration patches
preserve all unrelated fields; feature-mask writes require 3.1.

Explicit historical requests cover keyboard interface, keyboard return, the 2.x
PIV extension switch and 1.3 OpenPGP touch settings. Admin 09 is touch configuration
only on 1.3 and CTAP reset only from 3.0. Factory/app-specific resets never block
PINs or guess credentials. Old configuration/flash reads require supplied Admin
PIN; NFC status requires it on 3.0.0 but not from 3.0.1. Core-commit/app-usage reads
remain gated to pinned 3.1 evidence.

3.0.x CTAP SM2 reads return `LegacySm2Configuration`: one enable flag and eight
uninterpreted native-layout identifier bytes. `WriteLegacySm2` copies this explicit
nine-byte payload. Old core serializes a packed native struct, while Console's
current decoder assumes big-endian; the library does not guess across that conflict.
The 3.1 identifier patch API remains eight-byte big-endian and has no enable flag.
This is Admin/CTAP configuration, not OpenPGP SM2 support.

C request IDs 20–24 expose the historical writes without changing descriptor size.
Admin result kinds 8/9 distinguish legacy configuration/SM2; byte-copy getters return
the original payload. Applications select its interpretation from actual firmware.

## OATH

`oath::operation` selects once and performs explicit mutual HMAC-SHA1 validation
when the caller supplies an access key and fresh eight-byte challenge. SELECT-only
returns observations; it does not create a login handle. A protected applet without
a supplied key fails before the target. A supplied key on an unprotected applet also
fails instead of silently dropping validation. Password derivation is a pure PBKDF2
helper using the SELECT handle as salt; connection and password prompts stay outside.

Names are opaque 1..64 byte values. PUT owns 1..64 secret bytes, four through eight
digits, explicit properties and initial HOTP counter. The pinned firmware increments
HOTP before calculating (initial N produces N+1 on first use). Time steps and fresh
randomness always come from the caller. SHA-1/256/512 calculations expose either full
HMAC bytes or dynamic truncation; CalculateAll retains HOTP/touch markers. Optional
decimal conversion returns secret-owned ASCII bytes without logging codes.

The conversation engine supports OATH 06/A5, not ISO GET RESPONSE. After nonempty
9000 it may send a speculative SEND REMAINING; only an empty 6985 in that context
means completion. An error following 61xx remains an error, and empty 61xx fails for
lack of progress. No OATH calculation, mutation or continuation retries 6C. Lost
responses and later-page failures may leave HOTP/increasing-TOTP state changed;
no result getter, retry, cancel or drop can recover or roll back that state.

### Historical OATH commands

`Capability::Oath` covers baseline operations. `OathLegacy` selects the 1.3
instruction set; `OathModern` authorizes access codes, rename and SHA-512 from
1.5.2. `OathFullResponse` and `OathRenameCollisionCheck` start at 2.0. Legacy
SELECT returns `Outcome::LegacySelection`, with an optional independently observed
Admin serial and no synthetic version or password salt. Legacy LIST retains its
digit metadata. C result kind 5 represents legacy selection; copy field 5 returns
the observed serial when present, and info.flags bit 0 reports its presence.

Old final APDUs carry explicit Le. LIST and CalculateAll use 06 on 1.3 and A5
on modern firmware, including a bounded poll after a nonempty successful page.
Before 3.0.1, `OathReliablePagination` is Unsupported: firmware may omit records
at page boundaries. Success does not prove completeness, and calculations are
never replayed to compensate. Full-response requests fail before execution on
pre-2.0 firmware; ordinary rename remains available without a collision guarantee.

## OpenPGP

`openpgp::operation` owns a Request and optional explicit Access. PW1-sign (81),
PW1-other (82) and PW3 (83) remain distinct; private operations require the correct
reference. Empty VERIFY observes credential state and can clear a PW1 mode on the
pinned firmware. It never produces a reusable authorization object. Failed submitted
passwords can return 6982 without retries; errors retain their credential reference.
Change/unblock commands own old||new or reset-code||new and perform no extra VERIFY.

Key operations read wrapped 6E/73 algorithm attributes before authentication under
the same SELECT. Expected algorithms must match; generation/import do not silently
change attributes. Explicit attribute replacement discards the old key. RSA-2048/3072/
4096, P-256/384/521, secp256k1, Ed25519 and X25519 have independent OpenPGP evidence;
SM2 and post-quantum PIV support do not imply OpenPGP support. Public keys share the
`canokey-key` parser and SPKI representation, retaining the existing PIV public path.

RSA signing sends caller-prepared DigestInfo and applies PKCS#1 v1.5 on card; EC sends
short digests and returns fixed-width r||s; Ed25519 sends complete messages within
short-APDU limits. These commands cannot chain in the pinned firmware. RSA decipher
sends an explicit zero padding indicator and returns firmware-unpadded plaintext.
ECDH/X25519 returns raw shared bytes; peer validation and OpenPGP KDF remain caller
policy. Neither private operation is retried on 6C. Import uses typed RSA CRT or EC
scalar/seed fields, 4D/7F48/5F48 and bounded command chaining, without logging keys.

Certificates select their occurrence after PW3 verification and immediately before
GET/PUT. Partial certificate/import/password/reset writes are never rolled back;
callers invalidate affected caches even on uncertain completion. Retry reset restores
PW1/PW3 defaults; Terminate and Activate are separate explicit operations. Fingerprints
and timestamps are caller-supplied writes. DO parsers preserve unknown values without
identity/trust validation. Current firmware has no KDF DO/configuration implementation.

### Historical OpenPGP formats

Baseline commands cover audited 1.3–3.1.0 firmware. Actual firmware selects
65/6E/7A contents before 2.0 and wrapped objects from 2.0. Algorithm information
is absent before 1.6.1, bare until 3.1, then wrapped in FA. `ReadData` preserves
wire bytes; `parse_with_profile` and `data_object_contents` interpret these layouts
without guessing. OpenPGP uses explicit definite BER parsing, including firmware's
fixed-width lengths; other TLV readers keep their strict default.

Key operations read current attributes in 6E even when FA is unavailable.
Advertisements and configured attributes do not authorize every operation:
pre-2.0 RSA generation accepts only 2048 bits, P-521 requires 3.1, and digests
shorter than the curve width require 3.1. UIF starts at 1.5.2; retry reset at 3.1.
Old Ed/X public-key responses have one extraneous trailing byte until 1.6.1;
only that exact evidenced layout is normalized. On 1.3, short-Weierstrass ECDH
returns a point; Derive extracts its fixed-width X coordinate as the shared secret.
Neither normalization validates a peer or applies an OpenPGP KDF. X25519 import
bytes remain caller-supplied firmware bytes; the library never reverses them.

Final historical APDUs use explicit Le. Certificate occurrences remain sig=0,
dec=1, aut=2. Only explicit Activate accepts empty SELECT status 6285 and proceeds
to 44; unrelated requests preserve the failure.

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
Taking the result transfers ownership. Admin also exposes confirmed-write progress; other standalone operations expose no partial success.
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

`ManagementProtection` parses bounded ADMIN DATA and preserves stored flags.
Empty policy is distinct from malformed data; a blocked-PUK flag is a claim that
callers must verify against live retries. The PRINTED decoder requires exact
53/88/89 nesting and returns owned, zeroizing key bytes without authenticating
them. C callers use the same parsers with output atomicity and size-query rules.

Container names use `ContainerNameReference`: ordinary key slots or attestation
reference F9. This does not widen ordinary key-operation slots. Name reads and
writes have selected-context factories; writes require existing management
authorization and never SELECT or retry. Name clearing uses the five-byte F5
form without enabling 6C replay. The pure C name validator supports caller-side
preflight before card access; UTF-16 validation remains in the applet crate.

The C ABI exposes `cnk_profile_t`, `cnk_piv_context_t`, and `cnk_operation_t`
opaque handles. Inputs are copied versioned descriptors; errors are caller-owned
POD; results use query-size/copy. A selected PIV context copies its profile and
caller-declared authorization state without performing I/O. The caller keeps
the selected card transaction alive while driving dependent operations; freeing
a context neither releases that transaction nor invalidates existing operations.
There is no init/finalize, result/error/key handle, borrowed internal pointer or
thread-local last_error. Semantic integer enums are distinct from wire IDs. Use
`cnk_profile_piv_algorithm_from_wire` for profile-aware conversion; resolution
does not replace the operation factory's capability checks.

- POD begins with struct_size; reject unknown input enums/flags. NULL options means
  defaults; explicit zero budgets are invalid. ABI stability is not frozen yet.
- Constructors initialize output handles to NULL and leave no partial handle on failure.
- Context mutation factories check the input-byte budget before copying object or
  certificate payloads. Selected and standalone streaming signing share the same
  input validation: SM2 user IDs are absent (NULL/0) or 1..=32 bytes; other modes
  reject a supplied user ID. Invalid inputs expose no operation and perform no I/O.
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

CanoKey private RSA, ECDH/X25519 and ML-KEM operations may use every ordinary
asymmetric slot evidenced by the profile. PIV slot names do not impose host
key-usage policy; consumers such as PKCS#11/cardmod retain their own mapping and
operation admission rules. Algorithm/peer/ciphertext validation and card PIN
policy continue to apply, including on authentication and signature slots.

For raw PIV-object compatibility APIs, selected-context container factories
validate and preserve the complete 53/7E read response and accept one complete
53 container for writes. Normalized value factories remain unchanged. This
keeps ADMIN DATA/PRINTED and certificate write framing consistent without
reintroducing TLV parsing into consumers; malformed/trailing containers fail
before a write operation is exposed.

The C ABI builds all applet factories by default. Embedders that set
`default-features = false, features = ["piv"]` retain PIV and device probing,
but exclude Admin operation, OATH and OpenPGP C factories and their erased
operation variants. This is a link-time API subset: declarations in the common
header for an excluded applet have no corresponding symbols in that build.
PIV is the baseline C ABI; these flags do not disable its factories.
