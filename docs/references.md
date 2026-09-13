# Design reference repositories

Cloned on 2026-09-13. The SHAs below pin the design evidence; source links do not follow moving branches. All three clones are non-shallow, without fetched submodules, and used only as read-only reference material.

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

These are host implementation observations, not complete firmware support guarantees. Generic YubiKey APIs in manager are not proof of CanoKey support. No upstream application tests or hardware sessions were run. Any future code copying requires a per-file license and attribution review.
