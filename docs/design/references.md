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
- [lib/helper/utils/ndef_card.dart](https://github.com/canokeys/canokey-console/blob/63863ef66ff0766754ee8f5bee28b9e977889f75/lib/helper/utils/ndef_card.dart)
- [lib/helper/utils/pass_card.dart](https://github.com/canokeys/canokey-console/blob/63863ef66ff0766754ee8f5bee28b9e977889f75/lib/helper/utils/pass_card.dart)
- [lib/helper/utils/ctap_transmitter.dart](https://github.com/canokeys/canokey-console/blob/63863ef66ff0766754ee8f5bee28b9e977889f75/lib/helper/utils/ctap_transmitter.dart)
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
  ckman’s [firmware changelog](https://github.com/canokeys/canokey-manager/blob/89a52a7ec237b93b01f1158f6ffc3d26a57e13f9/doc/CanoKey-Firmware-Versions.md)
  and `yubikit/oath.py` establish legacy 1.3 dialect selection and the 2.0 full-HMAC
  boundary. Core `5f1e95f8341856d994abb4566995e2379cc0612d` confirms empty
  SELECT, LIST 71/75 pairs, truncated 76, touch TLV and continuation 06. The
  1.5.2/1.6.2/2.0/3.0 sources confirm modern command formats and old pagination
  limitations. Semantic factories select these layouts only from actual firmware.

- [`include/oath.h`](https://github.com/canokeys/canokey-core/blob/9e77287b2a272f6123d516790af93933dec72b78/include/oath.h)
  defines OATH_INS_SET_DEFAULT (0x55) with data `71 <len> <name>`. Core
  `5f1e95f`, 1.5.2 and 2.0.0 accept only the legacy single-slot form with
  P1=P2=0; 3.0.0, 3.0.3 and the pinned HEAD add the two-slot dialect with
  P1 in {1,2} (short/long touch) and P2 the append-enter flag. Firmware answers
  6984 for a missing record and 6985 when the named credential is TOTP.

- [`applets/oath/oath.c`](https://github.com/canokeys/canokey-core/blob/9e77287b2a272f6123d516790af93933dec72b78/applets/oath/oath.c#L682-L688)
  dispatches the vendor extension commands (upstream names YK_CMD_*) under
  INS 0x01 (which collides with
  OATH PUT) *before* the OATH access-validation gate, so KeePassXC-style
  clients work on an access-protected applet: P1 0x10 (GET SERIAL) returns the
  four-byte device serial, and P1 0x30/0x38 (`oath_yk_api_req`,
  [L646-L667](https://github.com/canokeys/canokey-core/blob/9e77287b2a272f6123d516790af93933dec72b78/applets/oath/oath.c#L646-L667))
  answer a challenge bounded by `PASS_HMAC_CHALLENGE_LENGTH` (64, per
  `include/pass.h`) with the 20-byte HMAC-SHA1 of the corresponding PASS
  HMAC slot, failing an unconfigured slot with 6A82. The dispatch was
  introduced by core commit
  [`b0416d7`](https://github.com/canokeys/canokey-core/commit/b0416d7)
  (2026-05, in no release tag up to 3.0.3), and commit
  [`e82e58b`](https://github.com/canokeys/canokey-core/commit/e82e58b)
  relaxed the challenge check to accept short challenges. The audited
  [1.5.2](https://github.com/canokeys/canokey-core/blob/b16e8c517ed72fe26e5101b450a99df2b3526aa1/applets/oath/oath.c)
  and
  [2.0.1](https://github.com/canokeys/canokey-core/blob/be6325b8c4e6d40e86b2943f65083ed6b71f8259/applets/oath/oath.c)
  sources route INS 0x01 only to PUT.

- [`include/ndef.h`](https://github.com/canokeys/canokey-core/blob/9e77287b2a272f6123d516790af93933dec72b78/include/ndef.h)
  defines the NDEF applet instructions A4/B0/D6, `NDEF_MSG_MAX_LENGTH` 1022 and
  the CC file E103 / NDEF data file 0001, with read-only encoded in CC byte 14.
  The AID table in
  [`src/apdu.c`](https://github.com/canokeys/canokey-core/blob/9e77287b2a272f6123d516790af93933dec72b78/src/apdu.c)
  maps NDEF_AID `D2760000850101` and FIDO_AID `A0000006472F0001`. NDEF UPDATE
  accepts CLA-0x10 command chaining, and large reads are served through the
  61xx response source.

- [`include/pass.h`](https://github.com/canokeys/canokey-core/blob/9e77287b2a272f6123d516790af93933dec72b78/include/pass.h)
  defines the PASS slot types OFF=0/OATH=1/STATIC=2/HMACSHA1=3,
  `PASS_MAX_PASSWORD_LENGTH` 32 and a 20-byte HMAC-SHA1 key. The read/write
  commands INS 43/44 are owned by the Admin applet behind its PIN gate per
  `applets/admin/admin.c` and `include/admin.h`.

- The pinned CTAP transport: CLA 80 INS 10 (CTAP_INS_MSG) carries the raw CTAP2
  message while CLA 00 carries U2F; the response is one CTAP status byte plus
  payload. GET RESPONSE (INS C0) accepts CLA 00 or 80, 61xx chains the
  response, there is no 6C wrong-Le handling, and 6986 reports nothing pending.

- `applets/openpgp/openpgp.c` and `src/key.c` at pinned HEAD establish independent
  PW1 usage modes, algorithm attributes nested in 6E/73, certificate occurrence state,
  F2 retry reset, separate E6/44 termination/activation and key import templates.
  OpenPGP's algorithm table excludes SM2 and PQ algorithms. RSA signatures pad on
  card and RSA decipher unpads PKCS#1 v1.5; EC signatures return r||s. Only certificate
  PUT, import and decipher accept command chaining. No F9 KDF DO/handler exists.

### CTAP2 command layer

- [`applets/ctap/ctap-internal.h`](https://github.com/canokeys/canokey-core/blob/9e77287b2a272f6123d516790af93933dec72b78/applets/ctap/ctap-internal.h)
  names the command bytes dispatched in
  [`applets/ctap/ctap.c`](https://github.com/canokeys/canokey-core/blob/9e77287b2a272f6123d516790af93933dec72b78/applets/ctap/ctap.c):
  makeCredential 0x01, getAssertion 0x02, getInfo 0x04, clientPIN 0x06,
  reset 0x07, getNextAssertion 0x08, credentialManagement 0x0A (the legacy
  preview 0x41 maps onto the same handler for old libfido2), selection 0x0B,
  largeBlobs 0x0C and config 0x0D with subcommands 2/3/4 (toggle always-UV,
  set min PIN length, enable long-touch-for-reset). Commands outside this
  set, including bioEnrollment and vendor commands, return the
  vendor-range status CTAP2_ERR_UNHANDLED_REQUEST 0xF1.
- ClientPIN subcommands are 01 getPINRetries, 02 getKeyAgreement, 03 setPIN,
  04 changePIN, 05 getPINToken and 09 getPinUvAuthTokenUsingPinWithPermissions,
  with getInfo advertising pinUvAuthProtocols [1, 2]. The legacy getPINToken
  forces MC|GA permissions (`cp_set_permission(CP_PERMISSION_MC | CP_PERMISSION_GA)`),
  and an unknown clientPIN or credentialManagement subcommand returns an empty
  success, so hosts must require the expected response fields.
- getInfo is emitted from a generated table
  ([`scripts/gen_ctap_get_info.py`](https://github.com/canokeys/canokey-core/blob/9e77287b2a272f6123d516790af93933dec72b78/scripts/gen_ctap_get_info.py),
  included as `ctap_get_info_cbor.inc`): versions U2F_V2/FIDO_2_0/FIDO_2_1/
  FIDO_2_3, extensions credBlob, credProtect, hmac-secret, hmac-secret-mc,
  largeBlobKey, minPinLength and thirdPartyPayment, algorithms ES256, EdDSA,
  ML-DSA-65 (-49) and an SM2 entry whose algorithm identifier is patched at
  runtime (default -54), and AAGUID 244eb29e-e090-4e49-81fe-1f20f8d3b8f4.
- authenticatorReset is honored only within ten seconds of power-up
  (`device_get_tick() > 10000` returns CTAP2_ERR_NOT_ALLOWED) and requires
  touch confirmation (a long touch when so configured), while the
  user-presence wait is skipped over NFC (`WAIT` breaks out when `is_nfc()`).
- Version differences: [2.0.1](https://github.com/canokeys/canokey-core/blob/be6325b8c4e6d40e86b2943f65083ed6b71f8259/applets/ctap/ctap.c)
  advertises FIDO_2_1 at most, pin/UV protocols 1 and 2, and
  credentialManagement without the metadata-only extension, with ES256 and
  EdDSA only. [1.5.2](https://github.com/canokeys/canokey-core/blob/b16e8c517ed72fe26e5101b450a99df2b3526aa1/applets/ctap/ctap.c)
  advertises FIDO_2_0 and U2F_V2, implements pin protocol v1 only (zero-IV
  AES-256-CBC with truncated 16-byte HMACs), and dispatches no
  credentialManagement.
- authenticatorConfig builds the pinUvAuthParam MAC input in
  [`ctap.c`](https://github.com/canokeys/canokey-core/blob/9e77287b2a272f6123d516790af93933dec72b78/applets/ctap/ctap.c#L3304-L3318)
  as 32 bytes of 0xFF, the command byte 0x0D, the subcommand byte and the raw
  subCommandParams encoding; only subcommands 0x02/0x03/0x04 are accepted
  ([L3237-L3238](https://github.com/canokeys/canokey-core/blob/9e77287b2a272f6123d516790af93933dec72b78/applets/ctap/ctap.c#L3237-L3238)),
  and the token must carry the authenticatorConfig permission
  (`CP_PERMISSION_ACFG`).
- authenticatorLargeBlobs (`ctap_large_blobs`,
  [`ctap.c` L3405](https://github.com/canokeys/canokey-core/blob/9e77287b2a272f6123d516790af93933dec72b78/applets/ctap/ctap.c#L3405))
  verifies each set fragment against the 70-byte MAC input
  `0xFF * 32 || h'0C00' || uint32LittleEndian(offset) || SHA-256(fragment)`
  ([L3528-L3538](https://github.com/canokeys/canokey-core/blob/9e77287b2a272f6123d516790af93933dec72b78/applets/ctap/ctap.c#L3528-L3538)),
  requires `length` on the first fragment only, answers a wrong offset with
  CTAP1_ERR_INVALID_SEQ (0x04,
  [L3505](https://github.com/canokeys/canokey-core/blob/9e77287b2a272f6123d516790af93933dec72b78/applets/ctap/ctap.c#L3505))
  and verifies the 16-byte truncated SHA-256 integrity trailer at commit
  ([L3560-L3578](https://github.com/canokeys/canokey-core/blob/9e77287b2a272f6123d516790af93933dec72b78/applets/ctap/ctap.c#L3560-L3578)).
  [`ctap-internal.h`](https://github.com/canokeys/canokey-core/blob/9e77287b2a272f6123d516790af93933dec72b78/applets/ctap/ctap-internal.h#L279-L283)
  fixes `LARGE_BLOB_SIZE_LIMIT` at 4096 and `MAX_FRAGMENT_LENGTH` as
  `MAX_CTAP_BUFSIZE - 64`, a platform-dependent value; the library therefore
  keeps a conservative host-side 1024-byte fragment cap.
- hmac-secret is parsed by `parse_hmac_secret_params` in
  [`ctap-parser.c`](https://github.com/canokeys/canokey-core/blob/9e77287b2a272f6123d516790af93933dec72b78/applets/ctap/ctap-parser.c#L658)
  with per-protocol saltEnc/saltAuth length checks
  ([L735-L744](https://github.com/canokeys/canokey-core/blob/9e77287b2a272f6123d516790af93933dec72b78/applets/ctap/ctap-parser.c#L735-L744));
  `ctap_build_hmac_secret_output`
  ([`ctap.c` L1559](https://github.com/canokeys/canokey-core/blob/9e77287b2a272f6123d516790af93933dec72b78/applets/ctap/ctap.c#L1559))
  produces the encrypted output placed in authData under "hmac-secret-mc" in
  makeCredential
  ([L1609-L1638](https://github.com/canokeys/canokey-core/blob/9e77287b2a272f6123d516790af93933dec72b78/applets/ctap/ctap.c#L1609-L1638))
  and under "hmac-secret" in getAssertion
  ([L2343-L2359](https://github.com/canokeys/canokey-core/blob/9e77287b2a272f6123d516790af93933dec72b78/applets/ctap/ctap.c#L2343-L2359)).
- The CLA-00 dispatch in
  [`ctap.c`](https://github.com/canokeys/canokey-core/blob/9e77287b2a272f6123d516790af93933dec72b78/applets/ctap/ctap.c#L3932-L3945)
  routes the raw U2F REGISTER/AUTHENTICATE/VERSION commands; with alwaysUv
  enabled REGISTER and AUTHENTICATE fail with SW_INS_NOT_SUPPORTED (6D00)
  while VERSION still answers. In
  [`u2f.c`](https://github.com/canokeys/canokey-core/blob/9e77287b2a272f6123d516790af93933dec72b78/applets/ctap/u2f.c)
  the check-only control byte is answered with 6985 by design
  ([L137](https://github.com/canokeys/canokey-core/blob/9e77287b2a272f6123d516790af93933dec72b78/applets/ctap/u2f.c#L137)),
  and an invalid key handle or application-ID mismatch fails with 6A80
  ([L131-L135](https://github.com/canokeys/canokey-core/blob/9e77287b2a272f6123d516790af93933dec72b78/applets/ctap/u2f.c#L131-L135)).

These sources establish encoding and version rules, not hardware interoperability.
Newer base versions and unrecognized versions remain Unknown for these mutations.
Development builds use the declared numeric base version while retaining their suffix.

## nfcim/fido2 (consumer-side)

The Dart [fido2](https://github.com/nfcim/fido2) package is the
consumer-side reference for the CTAP2 client layer, pinned at
`5f01f44a6286627d8ced7b05a8465c62140eb8b8`; it is not cloned locally and is
used as read-only reference material only.

- [`lib/src/strict_cbor.dart`](https://github.com/nfcim/fido2/blob/5f01f44a6286627d8ced7b05a8465c62140eb8b8/lib/src/strict_cbor.dart)
  enforces the strict decoding rules this library mirrors: nesting bounded at
  64 levels, duplicate map keys detected before the generic decoder collapses
  them, and rejection of truncated or oversized items.
- [`lib/src/ctap2/pin.dart`](https://github.com/nfcim/fido2/blob/5f01f44a6286627d8ced7b05a8465c62140eb8b8/lib/src/ctap2/pin.dart)
  is the reference for the ClientPIN wire cryptography: protocol v1 derives
  the shared secret as SHA-256 of the ECDH X coordinate, encrypts the PIN
  with zero-IV AES-256-CBC and truncates HMACs to 16 bytes; protocol v2
  derives HKDF-SHA-256 "CTAP2 HMAC key"/"CTAP2 AES key" halves, encrypts with
  a random-IV AES-256-CBC and uses full 32-byte HMACs.
- [`doc/metadata-only-extension.md`](https://github.com/nfcim/fido2/blob/5f01f44a6286627d8ced7b05a8465c62140eb8b8/doc/metadata-only-extension.md)
  documents the CanoKey credential-management metadata-only vendor extension:
  subCommandParams key 0x80 in enumerateCredentialsBegin requests metadata-only
  responses, which omit publicKey (key 8) and carry the raw COSE algorithm
  identifier under response key 0x80.

## Observations informing the design

| Source | Observation |
| --- | --- |
| manager canokey.py / piv.py | Actual CanoKey firmware differs from PIV compatibility version; SELECT security state, historical containers and empty-slot statuses vary |
| Console piv_management_key / manager piv.py | External and Mutual management authentication appear in different clients; Mutual requires host randomness |
| Console models/piv.dart / piv_post_quantum | Historical/configurable algorithm IDs and distinct ML-DSA/ML-KEM input/result formats |
| Console metadata_directory / piv_controller | Directory and individual metadata are distinct; entries may contain only certificates |
| Console piv_card / manager piv.py | Certificate payload tag 70, information tag 71 and optional empty FE; manager supports gzip decoding |
| Console oath_card | OATH uses 06/A5 continuation and may continue on nonempty 9000 |
| Console ndef_card / pass_card / ctap_transmitter | NDEF reads/writes use 240-byte chunks with zero-NLEN-first writes; PASS slots dump as typed records behind Admin; CTAP wraps messages as 80 10 with 80 C0 continuation |
| core ctap.c / gen_ctap_get_info.py | getInfo is a generated table with runtime-patched fields (SM2 algorithm id, maxMsgSize, PIN state); unhandled CTAP commands return vendor-range 0xF1; reset requires touch within ten seconds of power-up |
| fido2 strict_cbor.dart / ctap2/pin.dart | The Dart consumer enforces strict CBOR (bounded nesting, duplicate-key rejection) and the ClientPIN wire crypto this library mirrors: v1 SHA-256 of ECDH-x with zero IV and truncated-16 HMAC, v2 HKDF-derived HMAC/AES halves with random IV and full HMAC; metadata-only enumeration is a CanoKey vendor extension |
| pkcs11 pcsc.c | PCSC and PIV encoding are mixed; RSA uses short command chaining; application owns authentication/mechanism state |
| Console smartcard.dart / FRB configuration | Dart owns transport; process includes identity APDUs, raw paths log complete APDUs, bridge calls default to synchronous Dart methods |

Host observations supplement the firmware evidence above; neither establishes hardware interoperability. Generic YubiKey APIs in manager are not proof of CanoKey support. No upstream application tests or hardware sessions were run. Any future code copying requires a per-file license and attribution review.

Historical OpenPGP checks additionally use ckman's firmware changelog and
`yubikit/openpgp.py`, cross-checked against core 1.3 (`5f1e95f`), 1.5.2, 1.6.2,
2.0.0 and 3.0.0. They establish missing outer DO tags, fixed-width definite BER,
FA availability, the pre-2.0 RSA generation restriction and short-digest rejection.
Core 1.3 also returns the whole ECDH point, and pre-1.6.1 Ed/X key responses include
one extra trailing byte. These are narrow format normalizations, not generic
acceptance of malformed public keys.

Historical Admin checks use the same core versions. READ CONFIG changes from
seven touch-policy bytes (1.3) to five flags, then six with keyboard return;
3.0 reserves the removed keyboard fields. Core 1.3's `admin_set_touch_policy`
uses INS 09, which collides with the 3.0 CTAP reset. The 2.x extension switch is
40/07 and is not reported by READ CONFIG. `ctap-internal.h` and `ctap.c` at
3.0.0/3.0.3 serialize nine native-layout SM2 bytes, unlike Console's big-endian
decoder. Legacy SM2 reads/writes therefore preserve raw identifier bytes; the
current eight-byte format is explicitly big-endian at core `a0f0c09`.

PIV 1.3 core `5f1e95f` confirms 3DES authentication, the four primary slots,
RSA2048/P-256/P-384 generation, object writes and FB reset after both credentials
are blocked. ckman's matrix establishes SELECT authentication reset at 2.0.
The 2.x Admin 40/07 enable flag and fixed IDs are distinct from PIV EE (3.0+);
profiles record caller-confirmed enablement without fabricating response bytes.
Probe and historical applet commands use explicit short Le per ckman's transport
contract. No reference repository was modified or used as a build dependency.
