# Design reference repositories

Cloned on 2026-09-13. The SHAs below pin the design evidence; source links do not follow moving branches. The three original clones are non-shallow, without fetched submodules, and used only as read-only reference material.

| Repository | Local directory | HEAD |
| --- | --- | --- |
| [canokey-console](https://github.com/canokeys/canokey-console) | `references/canokey-console` | `63863ef66ff0766754ee8f5bee28b9e977889f75` |
| [canokey-manager](https://github.com/canokeys/canokey-manager) | `references/canokey-manager` | `89a52a7ec237b93b01f1158f6ffc3d26a57e13f9` |
| [canokey-pkcs11](https://github.com/canokeys/canokey-pkcs11) | `references/canokey-pkcs11` | `086c4d135e59fc7b24c02e6efae2d3f0d982720a` |

## canokey-console

Relevant implementations, regression tests, and conventions:

- [lib/helper/utils/piv_card.dart](https://github.com/canokeys/canokey-console/blob/63863ef66ff0766754ee8f5bee28b9e977889f75/lib/helper/utils/piv_card.dart)
- [lib/helper/utils/piv_management_key.dart](https://github.com/canokeys/canokey-console/blob/63863ef66ff0766754ee8f5bee28b9e977889f75/lib/helper/utils/piv_management_key.dart)
- [lib/helper/utils/piv_post_quantum.dart](https://github.com/canokeys/canokey-console/blob/63863ef66ff0766754ee8f5bee28b9e977889f75/lib/helper/utils/piv_post_quantum.dart)
- [lib/helper/utils/piv_metadata_directory.dart](https://github.com/canokeys/canokey-console/blob/63863ef66ff0766754ee8f5bee28b9e977889f75/lib/helper/utils/piv_metadata_directory.dart)
- [lib/models/piv.dart](https://github.com/canokeys/canokey-console/blob/63863ef66ff0766754ee8f5bee28b9e977889f75/lib/models/piv.dart)
- [lib/controller/applets/piv/piv_controller.dart](https://github.com/canokeys/canokey-console/blob/63863ef66ff0766754ee8f5bee28b9e977889f75/lib/controller/applets/piv/piv_controller.dart)
- [lib/helper/utils/admin_card.dart](https://github.com/canokeys/canokey-console/blob/63863ef66ff0766754ee8f5bee28b9e977889f75/lib/helper/utils/admin_card.dart)
- [lib/helper/utils/oath_card.dart](https://github.com/canokeys/canokey-console/blob/63863ef66ff0766754ee8f5bee28b9e977889f75/lib/helper/utils/oath_card.dart)
- [lib/helper/utils/openpgp_card.dart](https://github.com/canokeys/canokey-console/blob/63863ef66ff0766754ee8f5bee28b9e977889f75/lib/helper/utils/openpgp_card.dart)
- [lib/helper/utils/apdu_transport.dart](https://github.com/canokeys/canokey-console/blob/63863ef66ff0766754ee8f5bee28b9e977889f75/lib/helper/utils/apdu_transport.dart)
- [test/helper/utils/piv_card_test.dart](https://github.com/canokeys/canokey-console/blob/63863ef66ff0766754ee8f5bee28b9e977889f75/test/helper/utils/piv_card_test.dart)
- [test/helper/utils/piv_management_key_test.dart](https://github.com/canokeys/canokey-console/blob/63863ef66ff0766754ee8f5bee28b9e977889f75/test/helper/utils/piv_management_key_test.dart)
- [test/helper/utils/oath_card_test.dart](https://github.com/canokeys/canokey-console/blob/63863ef66ff0766754ee8f5bee28b9e977889f75/test/helper/utils/oath_card_test.dart)
- [test/controller/applets/piv/piv_firmware_compatibility_test.dart](https://github.com/canokeys/canokey-console/blob/63863ef66ff0766754ee8f5bee28b9e977889f75/test/controller/applets/piv/piv_firmware_compatibility_test.dart)

Certificate inspection is maintained in the independent
[x509-info repository](https://github.com/canokeys/x509-info); it is a crates.io
dependency, not copied protocol code in this workspace.

## canokey-manager

Relevant implementations, regression tests, and conventions:

- [yubikit/canokey.py](https://github.com/canokeys/canokey-manager/blob/89a52a7ec237b93b01f1158f6ffc3d26a57e13f9/yubikit/canokey.py)
- [yubikit/piv.py](https://github.com/canokeys/canokey-manager/blob/89a52a7ec237b93b01f1158f6ffc3d26a57e13f9/yubikit/piv.py)
- [yubikit/core/smartcard/__init__.py](https://github.com/canokeys/canokey-manager/blob/89a52a7ec237b93b01f1158f6ffc3d26a57e13f9/yubikit/core/smartcard/__init__.py)
- [yubikit/management.py](https://github.com/canokeys/canokey-manager/blob/89a52a7ec237b93b01f1158f6ffc3d26a57e13f9/yubikit/management.py)
- [yubikit/oath.py](https://github.com/canokeys/canokey-manager/blob/89a52a7ec237b93b01f1158f6ffc3d26a57e13f9/yubikit/oath.py)
- [yubikit/openpgp.py](https://github.com/canokeys/canokey-manager/blob/89a52a7ec237b93b01f1158f6ffc3d26a57e13f9/yubikit/openpgp.py)
- [tests/integration/usbip/piv.sh](https://github.com/canokeys/canokey-manager/blob/89a52a7ec237b93b01f1158f6ffc3d26a57e13f9/tests/integration/usbip/piv.sh)

## canokey-pkcs11

Relevant implementations, regression tests, and conventions:

- [src/backend/pcsc.c](https://github.com/canokeys/canokey-pkcs11/blob/086c4d135e59fc7b24c02e6efae2d3f0d982720a/src/backend/pcsc.c)
- [include/private/backend/pcsc.h](https://github.com/canokeys/canokey-pkcs11/blob/086c4d135e59fc7b24c02e6efae2d3f0d982720a/include/private/backend/pcsc.h)
- [src/api/sign.c](https://github.com/canokeys/canokey-pkcs11/blob/086c4d135e59fc7b24c02e6efae2d3f0d982720a/src/api/sign.c)
- [src/api/encrypt.c](https://github.com/canokeys/canokey-pkcs11/blob/086c4d135e59fc7b24c02e6efae2d3f0d982720a/src/api/encrypt.c)
- [src/internal/rsa.c](https://github.com/canokeys/canokey-pkcs11/blob/086c4d135e59fc7b24c02e6efae2d3f0d982720a/src/internal/rsa.c)
- [include/pkcs11_canokey.h](https://github.com/canokeys/canokey-pkcs11/blob/086c4d135e59fc7b24c02e6efae2d3f0d982720a/include/pkcs11_canokey.h)
- [AGENTS.md](https://github.com/canokeys/canokey-pkcs11/blob/086c4d135e59fc7b24c02e6efae2d3f0d982720a/AGENTS.md)

## canokey-core firmware

Read-only protocol evidence at `references/canokey-core`, HEAD
[`9e77287b2a272f6123d516790af93933dec72b78`](https://github.com/canokeys/canokey-core/tree/9e77287b2a272f6123d516790af93933dec72b78).
No firmware is linked or built as a dependency.

- [`piv.c` at 1.5.2](https://github.com/canokeys/canokey-core/blob/b16e8c517ed72fe26e5101b450a99df2b3526aa1/applets/piv/piv.c),
  1.6.0, 1.6.2, 2.0.0, 2.0.1, 3.0.0, 3.0.2 and
  [`3.0.3`](https://github.com/canokeys/canokey-core/blob/7644370f0c16d5b5e0d2f503e6c47bd39aaa0e2f/applets/piv/piv.c)
  implement 3DES External and Mutual authentication (GENERAL AUTHENTICATE cases 2–5).
- [AES-192 transition](https://github.com/canokeys/canokey-core/commit/5e0b978)
  and the pinned HEAD implement AES-192 in both modes; manager's firmware matrix
  places this transition at 3.1.0. The host never tries both algorithms automatically.
- PUT DATA stores 5C's following container verbatim. On 1.5.2, the common
  `src/apdu.c` layer reassembles chained commands; from 1.6.0 the applet handles
  PUT DATA chaining itself. Other legacy commands use common reassembly. The pinned HEAD explicitly removes
  a certificate file for `53 00`; legacy releases merely store that container.
- SET MANAGEMENT KEY accepts exactly 24 bytes: old releases require 03/9B/18
  and P2=FF; AES-192 uses 0A/9B/18 and permits P2=FE for touch Always.

- GET METADATA uses tags 01..06 for algorithm, policies, origin, public key,
  default credential and retries. Unknown values/fields stay observable. Retired
  slots 82/83 occur in 2.x/3.0 sources; the full 82..95 range is in the pinned HEAD.
- Key generation wraps 80/AA/AB in AC and returns 7F49; import uses five RSA CRT
  fields (implicit e=65537), scalar 06, Ed/X 07/08 and ML seed 09/0A. Public-key
  TLV and seed formats are defined by `src/key.c`. RSA-1024 is not in the inspected
  firmware algorithm switch. Ed/X private operations require the 3.0.1 fixes.
- Classic signing requires a nonempty challenge (81) and empty response (82).
  ECDH/X25519 uses 85 instead of 81. Empty Ed25519 and ML signing need separate
  streaming-mode support and are not silently mapped to the classic command.
  `piv_ga_stream_begin` hardcodes the ML-DSA context header 00/00; nonempty
  contexts/prehash are not exposed. Randomized Ed25519 uses fixed P1=FF. SM2
  streaming begins with CLA=10 and optionally sends an 80 identity before 82/81.
  The incremental parser requires the final frame to finish the TLV; therefore
  SM2's forced prefix contains only the outer tag even for empty messages.
  ML-DSA returns a 3309-byte signature through the standard ISO response source.
- [SM2 protocol change](https://github.com/canokeys/canokey-core/commit/02026a9)
  makes both digest and message signatures raw r || s in the pinned 3.1.0 evidence;
  3.0.3 and earlier inspected SM2 implementations convert to DER. Compat selects
  the encoding; operations preserve original bytes and expose DER/P1363 conversions.

- ML-KEM dispatch and `test_piv_mlkem768_generate_metadata_decaps_and_lifecycle`
  in the pinned HEAD use `7C { 82 empty, 81 ciphertext }`: 1088 input bytes,
  32 result bytes, command chaining and implicit rejection. Wire IDs come from
  the observed algorithm configuration, not a fixed default.
- `src/key.c` imports short-Weierstrass scalars under tag 06. The classic GA
  agreement branch accepts uncompressed P-256/P-384/P-521/secp256k1 points and
  returns a fixed-width scalar-sized secret. SM2 has a separate agreement
  dispatcher; it must not use this generic ECDH operation.

- `include/piv.h` and the pinned `piv.c` document F5 container names, F6 key
  move/delete, FA retry reset, F7/01 directory, EE/02 algorithm replacement,
  F9 attestation and FB blocked-credential reset. Directory lengths are one-byte
  fixed fields, not BER; names are bounded UTF-16LE. FA clears authorization and
  rewrites default credentials. F6 moves names with keys but leaves certificates.
  These factories are enabled for the pinned 3.1.0 evidence only.

- `piv_general_authenticate_sm2_dispatch` uses an empty response request and
  85 containing peer static 86 / ephemeral 87, optional identity 88, and key-length
  89. Initiator starts with 82 plus optional own-ID 80, then completes without 80;
  responder returns both ephemeral 82 and derived key 85. Frames must not chain.
  `piv_security_status_check` consumes PIN-always at each GA, while any non-GA
  command clears pending agreement. Host initiators therefore preflight metadata
  and permit only explicit Never/Once policies; they do not re-VERIFY mid-agreement.

- `applets/admin/admin.c`, `include/admin.h` and `ctap.c` at the same pinned
  revision define the six-byte configuration, per-field writes, eight fixed logical
  storage records, raw Admin PIN, explicit applet/factory resets and eight-byte SM2
  configuration. SM2 rejects curve 0/1..8/256..259 and algorithm -7/-8/-49.
  Vendor NFC hooks are supplemented by Console's `admin_card.dart` command shapes.
  The older Console SM2 enable-flag format is not used for this firmware layout.

- `applets/oath/oath.c` and `include/oath.h` at pinned HEAD define A1/A2/A3/A4/A5,
  raw one-byte OATH lengths, the tag/value (not TLV) property field, SHA-1 mutual
  access validation, full/truncated output and HOTP pre-increment behavior. LIST
  and CalculateAll end in nonempty 9000 followed by empty 6985 on a final A5 poll.
  Older inspected tags and Console establish 06/A5 conversation shapes; semantic
  factories remain gated to current evidence rather than inferring old layouts.

These sources establish encoding and version rules, not hardware interoperability.
Newer, development and unrecognized versions remain Unknown for these mutations.

## Observations informing the design

| Source | Observation |
| --- | --- |
| manager canokey.py / piv.py | Actual CanoKey firmware differs from PIV compatibility version; SELECT security state, historical containers and empty-slot statuses vary |
| Console piv_management_key / manager piv.py | External and Mutual management authentication appear in different clients; Mutual requires host randomness |
| Console models/piv.dart / piv_post_quantum | Historical/configurable algorithm IDs and distinct ML-DSA/ML-KEM input/result formats |
| Console metadata_directory / piv_controller | Directory and individual metadata are distinct; entries may contain only certificates |
| Console piv_card / manager piv.py | Certificate payload tag 70, information tag 71 and optional empty FE; manager supports gzip decoding |
| Console oath_card | OATH uses 06/A5 continuation and may continue on nonempty 9000 |
| pkcs11 pcsc.c | PCSC and PIV encoding are mixed; RSA uses short command chaining; application owns authentication/mechanism state |
| Console smartcard.dart / FRB configuration | Dart owns transport; process includes identity APDUs, raw paths log complete APDUs, bridge calls default to synchronous Dart methods |

Host observations supplement the firmware evidence above; neither establishes hardware interoperability. Generic YubiKey APIs in manager are not proof of CanoKey support. No upstream application tests or hardware sessions were run. Any future code copying requires a per-file license and attribution review.
