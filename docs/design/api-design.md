# API contracts

[README](../../README.md) lists implemented features and examples;
[plan](../../plan.md) tracks remaining work. Rustdoc and the
[experimental C header](../../crates/canokey-c/include/canokey.h) define signatures.
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
declared numeric base version by default. Suffix-bearing parsed versions no newer
than the latest known base receive a DeclaredBaseVersion warning; recognition of
the base still determines feature support. Parsed newer bases,
including 3.2.0-dev, receive LatestKnownFallback instead; the newer-version branch
takes precedence and does not authorize historical layouts. Applet-reported
versions never select a dialect. See each applet's historical subsection for
command boundaries.

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

By default operations select once, then apply `Access::None`, `Pin`, `Management`
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
It selects once and authenticates explicitly before protected commands.
`admin::operation_with_access` takes an explicit `Access` policy instead:
`Access::Existing` sends no SELECT and no implicit VERIFY, reusing the caller's
selected Admin transaction and card authorization. As in PIV, this is an
execution policy, not proof of live authentication; firmware answers 6982 for a
protected request without prior verification. `Request::VerifyPin` carries no
PIN of its own and is rejected under `Existing`; PinStatus and ChangePin send
only their own VERIFY or CHANGE PIN command. PinStatus under `Existing` is the
no-SELECT Admin PIN status entry: a single empty VERIFY.
Empty VERIFY
returns status data; submitted-PIN failures retain AdminPin and retries. The
corresponding PIV profile-free no-SELECT entry remains `piv::get_pin_status_selected`.
Factory reset
rejects a supplied PIN and requires the card's existing blocked/physical-presence state.
Applet resets use Admin authorization and destroy the named applet's data/credentials.

Configuration patches read current state, preserve unspecified fields and only write
changes. Unknown feature bits remain observable and prevent unsafe feature overwrites.
All patch fields are checked before the first write. Writes persist separately:
`Outcome::confirmed_writes` is available through progress even after failure, and
`reprobe_required` is set before a profile-affecting write is exposed. An unacknowledged
write may still have changed the device. Invalidate credential/object caches on their
mutation attempts too. Neither progress nor completion is an automatic refresh.

Typed PASS slot operations layer on the raw PassConfiguration/SetPassConfiguration
commands (INS 43/44) under baseline Admin capability evidence; writes require
Admin PIN authentication like the raw write.
`Request::PassSlots` parses the two-slot dump into `PassSlots`: each
`PassSlotState` is Off, Static with only its append-enter flag, HmacSha1, Oath
with the verbatim credential name and append-enter flag, or Unknown(raw type
byte). Firmware never returns stored passwords or HMAC keys, so the typed read
preserves exactly what the raw read carries. `Request::SetPassSlot` targets
`PassSlotId::{Short, Long}` (wire P1 1/2) with a `PassSlotConfig` checked
before any I/O: Off, Static with an at-most-32-byte printable-ASCII password
(keyboard emulation cannot type other bytes), or HmacSha1 with an owned 20-byte
key; passwords and keys are redacted and zeroized. OATH slots are rejected by
firmware (6A80) and are configured through OATH set-default instead, so
`PassSlotConfig` has no OATH variant. The typed write marks the outcome
reprobe-required like the raw form. In C, the typed read is requested with
`CNK_ADMIN_PASS_SLOTS` (kind 31); `Value::PassSlots` then maps to Admin
outcome value_kind 10 and returns the raw two-slot dump bytes through
`cnk_operation_result_copy_bytes`.

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

`Request::SetDefault` marks an existing HOTP credential as the default emitted on
touch through keyboard emulation; it sends INS 55 with the name as
`71 <len> <name>` and mutates the on-card PASS configuration state, so deleting
the credential clears the slot firmware-side. Only HOTP credentials are eligible:
a TOTP name returns 6985 (ConditionsNotSatisfied), and a missing name returns
6984, mapped to NotFound in command context like Delete/Rename/Calculate. As a
mutation it is never replayed after a lost response.

The OATH applet also answers two vendor extension commands under INS 0x01,
dispatched by the firmware before its access-validation gate (the INS collides
with OATH PUT): `Request::GetSerial` (P1 0x10) returns the four-byte device
serial as `Outcome::Serial`, and `Request::ChallengeResponseHmac { slot:
HmacSlot, challenge }` (P1 0x30/0x38 for the short/long PASS HMAC slot) answers
an at-most-64-byte challenge with the 20-byte HMAC-SHA1 of the corresponding
PASS HMAC slot as `Outcome::ChallengeResponse`; an unconfigured slot returns
6A82, mapped to NotFound. This is the KeePassXC interop path; the HMAC key is
configured through the Admin typed PASS slot (HmacSha1). Because the dispatch
precedes the gate these commands work on an access-protected applet, and
supplying an access key with them is rejected with InvalidArgument before any
I/O. They are gated by `Capability::OathChallengeResponse` (3.1.0 only):
introduced by canokey-core commit b0416d7 (2026-05), absent from every release
tag up to 3.0.3 and present at the pinned 3.1.0 evidence HEAD.

### Historical OATH commands

`Capability::Oath` covers baseline operations. `OathLegacy` selects the 1.3
instruction set; `OathModern` authorizes access codes, rename and SHA-512 from
1.5.2. `OathFullResponse` and `OathRenameCollisionCheck` start at 2.0.
`OathSetDefaultSlots` selects the two-slot SET DEFAULT dialect from 3.0.0
(P1 = touch slot 1/2, P2 = append-enter); older recognized firmware uses the
legacy single-slot wire form with P1/P2 zero, and requesting a Long slot or
append-enter there fails construction with InvalidArgument before any I/O. Legacy
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

## NDEF

`ndef::read_capability`, `ndef::read_message` and `ndef::write_message` are
profile-free: no NDEF behavior is known to vary across firmware versions, so no
`DeviceProfile` or capability is consulted. The applet (AID D2 76 00 00 85 01
01) stores one message in a Type 4 Tag style data file: bytes [0..2) hold the
big-endian message length (NLEN), followed by NLEN message bytes. Operations
select the applet, then select files by ID: the 15-byte capability container
(CC, file 0xE103) and the NDEF data file (file 0x0001). Reads and writes use
explicit-offset READ/UPDATE BINARY in chunks of at most 240 bytes, negotiated
down to the caller's exchange budgets, so no APDU chaining or extended lengths
are required. `ndef::MAX_MESSAGE_LENGTH` is the firmware hard maximum of 1022
bytes; `read_message` rejects an NLEN above the CC-declared maximum before any
allocation or message read.

The CC parses into `NdefCapability`: the maximum storable message length (CC
file size minus two, clamped to 1022) and a read-only flag taken from the CC
write-access byte. `write_message` copies the message at construction, writes a
zero NLEN first, then the message chunks, then the real NLEN: an interrupted
write leaves the file with NLEN zero instead of a stale length pointing at a
partially updated message. The CC is not read on writes; a read-only file is
reported by the device as 6982, mapped to SecurityStatusNotSatisfied. This
mutates device state, and a mid-write I/O failure may leave the message
cleared; neither is replayed automatically.

6A82 maps to UnsupportedDevice only on applet SELECT (the NDEF applet disabled
in device configuration is indistinguishable from absent) and to NotFound on
the CC/NDEF file selects. 6985 maps to ConditionsNotSatisfied. Malformed CCs,
short or oversized NLEN values and short chunks fail as InvalidResponse in the
Parsing phase, never as panics. The owned message is zeroized and redacted from
Debug.

## CTAP

The CTAP crate implements the ISO 7816 transport envelope of CTAP/FIDO2 and,
on top of it, a typed CTAP2 client layer; WebAuthn ceremonies remain
host-side. At the envelope level the caller supplies the complete raw CTAP
message (first byte the CTAP command) and interprets the returned payload.
`ctap::transceive` selects the FIDO2 applet by DF name (`ctap::FIDO2_AID` A0
00 00 06 47 2F 00 01, `00 A4 04 00 08`) and then sends the message;
`ctap::transceive_selected` sends the wrapped command without SELECT for a
caller-owned selected context; `ctap::select_application` performs selection
only. `ctap::command::{select, msg}` are raw logical-command builders without
status mapping for composition in other conversations. All factories are
profile-free.

A CTAP message is wrapped as `80 10 00 00 <Lc> <message>` with no Le. Messages
up to 255 bytes use short Lc; longer messages use the extended three-byte Lc
when the caller's options permit extended encoding, otherwise command chaining
with CLA bit 0x10. Responses arriving with 61xx are reassembled through GET
RESPONSE `80 C0 00 00 <SW2>` (`Continuation::Iso7816 { cla: 0x80 }`) until a
terminal status word; the firmware has no 6C wrong-Le correction path. A
successful response is one CTAP status byte (0x00 CTAP1_ERR_SUCCESS) followed
by the payload, concatenated across continuation fragments.
`CtapResponse::status` exposes non-success CTAP codes raw rather than mapping
them to transport errors. The payload is zeroized and redacted from Debug.

6A82 on SELECT maps to UnsupportedDevice, 6985 to ConditionsNotSatisfied and
6D00 to UnsupportedFeature; other status words remain UnexpectedStatusWord with
the raw value. A successful status word with an empty response body (no CTAP
status byte) fails as InvalidResponse in the Parsing phase. An empty message
fails construction with InvalidArgument before any I/O.

The typed CTAP2 layer lives in `ctap::ctap2`, `ctap::status`, `ctap::cbor`,
`ctap::cose` and `ctap::authdata`, with ClientPin and credential management
behind the default `clientpin` feature. `ctap2` provides the command-level
operations `get_info`, `make_credential`, `get_assertion`,
`get_next_assertion`, `reset` and `selection`. Every command-level operation
sends the explicit SELECT of the FIDO2 application before its wrapped CTAP
message: re-SELECT is idempotent for FIDO and does not invalidate
pinUvAuthTokens, so the core owns SELECT and no CTAP2 operation needs a
caller-held selected context. All factories are profile-free: they enforce
the CTAP2 specification, not any authenticator's advertised capabilities.
`AuthenticatorInfo` retains the raw getInfo map alongside its typed
accessors, so fields the library does not interpret stay observable.

`cbor` implements the strict canonical CBOR CTAP2 authenticators speak:
definite-length items only, shortest-form integers and lengths, no tags, at
most 64 nesting levels, duplicate map keys rejected, no trailing bytes;
these rules mirror the strict decoder of the Dart fido2 consumer. The canonical
encoder is security-relevant because pinUvAuthParam HMACs cover its exact
output; byte-string contents are redacted from Debug. `cose` parses and
encodes COSE public keys (ES256 -7/-9, Ed25519 -8/-19, ML-DSA-44/65/87
-48/-49/-50 per RFC 9964, ECDH-ES+HKDF-256 -25 for key agreement), rejects
maps carrying private-key labels and preserves unknown algorithms as their
original CBOR map. `authdata` parses authenticatorData (flags UP/UV/BE/BS/
AT/ED, attested credential data, extensions kept as raw CBOR) under explicit
length bounds, with the BS flag implying BE.

A non-success CTAP status byte is classified into a typed error kind in the
Command phase: PIN_INVALID/PIN_POLICY_VIOLATION to InvalidPin,
PIN_BLOCKED/PIN_AUTH_BLOCKED to PinBlocked, PIN_AUTH_INVALID to
AuthenticationFailed, PIN_NOT_SET/PUAT_REQUIRED to
SecurityStatusNotSatisfied, NO_CREDENTIALS/INVALID_CREDENTIAL to NotFound,
UNSUPPORTED_ALGORITHM to UnsupportedAlgorithm, and further codes to
ConditionsNotSatisfied, UnsupportedFeature, LimitExceeded or
ProtocolViolation as their semantics dictate. Statuses without a specific
kind, including the extension (0xE0..0xEF) and vendor (0xF0..0xFF) ranges,
fall back to UnexpectedStatusWord. In every case the raw CTAP status byte is
preserved in `Error::status_word` widened to `u16`: for CTAP-level failures
that field carries the CTAP status byte, not an ISO 7816 status word. The
convention is stated in the crate documentation and in `ctap::status`, whose
`CtapErrorCode` types the full CTAP1/CTAP2 status table.

`make_credential` and `get_assertion` accept the caller's parameters as
owned values; the caller computes pinUvAuthParam with
`PinToken::authenticate` and passes it as `PinUvAuth` (the CTAP2 widths are
16 bytes under protocol v1 and 32 under v2; construction accepts either
width for any protocol and a mismatch is rejected card-side); the library
never authenticates implicitly.
Enterprise attestation is accepted as a parameter; the firmware may reject
it. Attestation statements are retained as the raw decoded CBOR map: no
certificate trust, identity or attestation policy is enforced, consistent
with the workspace certificate-inspection rule. What remains host-side is
WebAuthn ceremony logic: clientDataJSON construction, origin and rpId
policy, attestation trust decisions and assertion signature verification.

With the default `clientpin` feature, `ctap::pin` implements ClientPIN
protocols 1 and 2: `get_key_agreement` takes a caller-supplied 32-byte
ephemeral P-256 scalar and validates the authenticator's peer key as a P-256
ECDH-ES+HKDF-256 COSE key; `get_pin_retries`; `set_pin`/`change_pin` with
the 64-byte zero-padded PIN encoding (PINs are validated before any I/O:
fewer than 4 Unicode code points, more than 63 UTF-8 bytes and invalid UTF-8
are rejected); `get_pin_token` (legacy subcommand 0x05, which the CanoKey
firmware restricts to makeCredential/getAssertion permissions) and
`get_pin_token_with_permissions` (0x09 with a `Permissions` bitfield).
Protocol v1 derives the shared secret as SHA-256 of the ECDH X coordinate,
encrypts under a zero IV and truncates pinUvAuthParam HMACs to 16 bytes;
protocol v2 derives HKDF-SHA-256 HMAC/AES halves, encrypts under a fresh
caller-supplied 16-byte IV and uses full 32-byte HMACs. The module never
generates randomness: ephemeral scalars and v2 IVs are caller-supplied.
PINs, shared secrets and pinUvAuthTokens are redacted from Debug and
zeroized.

Also behind `clientpin`, `ctap::credmgmt` implements
authenticatorCredentialManagement: `get_creds_metadata`, `enumerate_rps` and
`enumerate_credentials` run their Begin/GetNext loops inside the operation,
bounded by the authenticator-reported total and by the operation's exchange
budget, with a 0x2E NO_CREDENTIALS status on Begin yielding an empty vector
rather than an error; `delete_credential` and `update_user_information`
complete the set. The CanoKey vendor metadata-only mode (subCommandParams
key 0x80, returning the raw COSE algorithm identifier under response key
0x80 instead of the public key) is caller opt-in; the legacy preview command
0x41 is never emitted.

Also behind `clientpin`, `ctap::config` implements authenticatorConfig (0x0D):
`toggle_always_uv`, `set_min_pin_length` (subCommandParams keys 1
newMinPINLength, 2 minPinLengthRPIDs, 3 forcePinChange, following the CTAP 2.1
numbering) and `enable_long_touch_for_reset`. Every request carries
pinUvAuthProtocol and pinUvAuthParam computed over
`0xFF * 32 || 0x0D || subCommand || cbor(subCommandParams)` — the MAC input
ends after the subcommand byte when no parameters are sent — with a
pinUvAuthToken holding `Permissions::AUTHENTICATOR_CONFIG`; a successful
response must have an empty payload. Construction enforces
`MIN_MIN_PIN_LENGTH` (4) and `MAX_MIN_PIN_LENGTH_RP_IDS` (4) before any I/O.
All three subcommands are persistent configuration changes. Enabling alwaysUv
requires user verification on every CTAP2 operation and on 3.1.0 firmware
disables the legacy U2F/CTAP1 interface entirely (see `ctap::u2f`). The
long-touch-for-reset option makes a reset require holding the touch for up to
30 seconds, and because the reset wait loop is not skipped over NFC, an NFC
reset then always times out; only a full authenticatorReset reverses it.

`ctap::largeblob` (also `clientpin`) implements authenticatorLargeBlobs
(0x0C). `read_array` owns the fragmentation of the serialized large-blob
array, requesting chunks of at most `DEFAULT_MAX_FRAGMENT_LENGTH` (1024)
clamped so one fragment fits a single physical response under
`max_response_bytes` (a 16-byte margin), accumulating at most
`MAX_LARGE_BLOB_ARRAY_BYTES` (4096) bytes within the exchange budget;
`read_chunk` is the single-shot read for callers implementing their own
resume logic. `write_array` takes the complete serialized array (17..=4096
bytes: the contents plus the caller-owned 16-byte truncated SHA-256 integrity
trailer, whose construction stays the caller's responsibility), fragments it
with `length` on the first fragment only and MACs each fragment over
`0xFF * 32 || 0x0C00 || uint32LittleEndian(offset) || SHA-256(fragment)` with
a token holding `Permissions::LARGE_BLOB_WRITE` (0x10); a device without a
PIN needs no token (pass `None`, and the firmware ignores any keys 5/6).
Firmware semantics: a fragment at a wrong offset fails with
CTAP1_ERR_INVALID_SEQ (0x04), and the integrity trailer is verified at commit
(mismatch 0x3D INTEGRITY_FAILURE), atomically replacing the previous array.
The library transports the array verbatim; parsing its contents is the
caller's.

`ctap::u2f` (no feature gate) sends the raw CTAP1/U2F commands the FIDO2
applet dispatches on plain CLA-00 APDUs: `register` (INS 0x01),
`authenticate` (INS 0x02 with `CONTROL_ENFORCE_USER_PRESENCE_AND_SIGN` 0x03;
`CONTROL_DONT_ENFORCE_USER_PRESENCE` 0x08 is exposed as a constant),
`check_only` (INS 0x02 with `CONTROL_CHECK_ONLY` 0x07) and `version` (INS
0x03, answering exactly `U2F_V2`). These are not `80 10`-wrapped CTAP
messages and their responses carry no CTAP status byte, so status
classification uses the ISO layer. `check_only` maps 6985 to `Ok(true)` by
design (the one case where 6985 is not an error), an invalid handle or app-ID
mismatch fails with 6A80 as an error rather than `Ok(false)`, and a success
status fails as InvalidResponse. With alwaysUv enabled the firmware answers
REGISTER and AUTHENTICATE with 6D00 (UnsupportedFeature); VERSION still
answers. The registration's raw DER attestation certificate is length-framed
only and preserved without validation, consistent with the workspace
certificate-inspection rule.

`ctap::hmacsecret` implements the hmac-secret extension. The makeCredential
declaration (`MakeCredentialParams::hmac_secret`, a boolean both ways,
reported by `MakeCredentialResponse::hmac_secret_supported`) is
dependency-free and lives in `ctap2`. The encrypted salt exchange is prepared
by `HmacSecretInput::new(&PinSession, HmacSecretSalts, iv)` behind
`clientpin`, reusing the pin/UV protocol encapsulation: `saltEnc` encrypts
one 32-byte salt or two concatenated salts (zero IV and same length under
protocol v1; a caller-supplied fresh 16-byte IV, prefixed to the ciphertext,
under v2) and `saltAuth` is the protocol HMAC over `saltEnc` (16 bytes under
v1, 32 under v2). Key agreement is PIN-independent: the exchange does not
require a PIN to be set on the device. GetAssertion
(`GetAssertionParams::hmac_secret`) and the CanoKey vendor hmac-secret-mc
makeCredential variant — which additionally requires the plain declaration in
the same map, enforced before any I/O — report their decrypted 32/64-byte
outputs as `GetAssertionResponse::hmac_secret` and
`MakeCredentialResponse::hmac_secret_mc`, read from the authData ED
extensions under the respective keys. A requested exchange whose output is
missing from the response fails as InvalidResponse rather than a silent
`None`. The firmware rejects combining the getAssertion exchange with
`up: false`.

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

Selected version/configuration probes do not invent a profile or authenticate.
RNG checks the live PIV version before bounded generation and owns zeroizing
output. Configuration projections use zero for disabled/unobserved IDs while raw
observations remain available. Firmware/model/serial accessors read immutable
probe results. Empty-slot checks accept only explicit absence and never decode
an occupied key into permission to replace it.

Bootstrap PIV selection is available before a profile exists; it uses a fixed
AID and explicit Le without fabricating capability evidence.
Selected credential actions verify, log out, replace PIN/PUK, or unblock PIN
without another SELECT. Their owned inputs and encoded copies are zeroized;
callers retain transaction, credential-cache and uncertain-mutation responsibility.
The explicit legacy-byte constructors preserve the C consumer's 1..=8-byte raw
form, including FF. Default Rust credential constructors retain stricter policy.

`ManagementProtection` parses bounded ADMIN DATA and preserves stored flags.
Empty policy is distinct from malformed data; a blocked-PUK flag is a claim that
callers must verify against live retries. The PRINTED decoder requires exact
53/88/89 nesting and returns owned, zeroizing key bytes without authenticating
them. C callers use the same parsers with output atomicity and size-query rules.

Container names use `ContainerNameReference`: ordinary key slots or attestation
reference F9. This does not widen ordinary key-operation slots. Name reads and
writes use the same factories for standalone and caller-selected transactions.
Name clearing uses the five-byte F5 form without enabling 6C replay. The pure
C name validator supports caller-side preflight; UTF-16 validation stays in PIV.

The C ABI exposes only `cnk_profile_t` and `cnk_operation_t` opaque handles.
Rust callers use `Access::Existing` to omit SELECT and reuse the caller's live
card authorization; PIV and Admin both offer this Rust policy.
C callers set `CNK_PIV_USE_EXISTING` in operation options;
access descriptors must then be empty. Explicit credential and management-auth
operations still send their requested authentication, but omit SELECT. Other
applets and standalone probe/bootstrap/selected-only factories reject the flag.
Default/null options retain previous behavior. Read APIs with no C access
argument also honor this flag for public object and certificate reads.

This policy is not proof of authentication: firmware authorizes the actual
command, and the host retains session policy and reservation checks. Hold one
PC/SC transaction from SELECT through authentication and dependent operations.
For concurrent profile refresh, hold the profile lock only during synchronous
factory construction; factories copy their inputs before releasing it. No
profile lock may survive into card I/O. Failed unlock discards the provisional
operation before execution. There is no separate selected-context allocation.
Inputs are copied versioned descriptors; errors are caller-owned POD; results
use query-size/copy. Freeing the source profile cannot invalidate an operation.
There is no init/finalize, result/error/key handle, borrowed internal pointer or
thread-local last_error. Semantic integer enums are distinct from wire IDs. Use
`cnk_profile_piv_algorithm_from_wire` for profile-aware conversion; resolution
does not replace the operation factory's capability checks.
`cnk_profile_piv_require_algorithm` checks observed PIV and semantic key support
locally, preserving Unsupported versus Unknown errors without authenticating or
retaining state. Factories still revalidate their complete operation policy.

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
[Console](../guides/console-integration.md), [PKCS#11](../guides/pkcs11-integration.md).

CanoKey private RSA, ECDH/X25519 and ML-KEM operations may use every ordinary
asymmetric slot evidenced by the profile. PIV slot names do not impose host
key-usage policy; consumers such as PKCS#11/cardmod retain their own mapping and
operation admission rules. Algorithm/peer/ciphertext validation and card PIN
policy continue to apply, including on authentication and signature slots.

For raw PIV-object compatibility APIs, raw-container factories
validate and preserve the complete 53/7E read response and accept one complete
53 container for writes. Normalized value factories remain unchanged. This
keeps ADMIN DATA/PRINTED and certificate write framing consistent without
reintroducing TLV parsing into consumers; malformed/trailing containers fail
before a write operation is exposed.

The C ABI builds the PIV, Admin, OATH and OpenPGP applet factories by
default; NDEF and CTAP have no C factories yet and remain Rust-only.
Embedders that set
`default-features = false, features = ["piv"]` retain PIV and device probing,
but exclude Admin operation, OATH and OpenPGP C factories and their erased
operation variants. This is a link-time API subset: declarations in the common
header for an excluded applet have no corresponding symbols in that build.
PIV is the baseline C ABI; these flags do not disable its factories.

## Consumer capability and protection boundaries

`cnk_profile_piv_capabilities` returns immutable algorithm/feature masks and message
limits from the same profile used by operation factories. Supported and unknown
masks are separate; a missing supported bit never licenses a caller to substitute
a raw configuration byte. Consumers may cache the profile with their own binding,
invalidation generation and TTL, but must resolve it before authentication.
Classic Ed25519 accepts at most 512 message bytes; streaming modes accept at most
65520 combined message/identity bytes. Host-only cryptography has its own limits.

`protection::pin_managed` / `cnk_piv_pin_managed_new` validates ADMIN DATA, checks
live PUK retries, reads PRINTED, resolves management metadata and authenticates
its recovered key in one transaction. Ordinary login requires zero PUK retries.
Supplying eight random entropy bytes explicitly requests finalization: authenticate
first, then exhaust PUK retries with at most 32 CHANGE commands and confirm zero.
A coincidentally successful guess switches to a provably wrong old PUK. The only
result is an owned, zeroized management key for the consumer's protected cache;
no USER/SO state is owned here. Failure does not undo card writes or retry loss.

`set_management_key` takes `update_protected` (`0/1` in C). Enabled mode checks
ADMIN DATA and requires readable, valid PRINTED before touching a protected key.
It replaces the key, authenticates the new key and updates PRINTED without SELECT.
These are separate durable writes. Failure after replacement requires the caller
to recover with its supplied new key and repair PRINTED; no rollback is claimed.
Batch's raw management-key replacement retains its explicit low-level semantics.

Attestation accepts the common selection policy (`select=false` in Rust,
`CNK_PIV_USE_EXISTING` in C); it does not authenticate or verify trust. SM2 agreement
responses accept definite BER length encodings, including the actual firmware's
non-minimal two-octet lengths for 128-byte secrets. Exact fields, point validity,
requested secret length and the common response/depth budgets remain enforced.
