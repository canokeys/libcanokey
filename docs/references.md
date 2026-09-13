# 设计参考仓库

克隆日期：2026-09-13。以下 SHA 固定本次接口设计依据；在线链接指向固定 commit，不随默认分支移动。三个仓库均已完整克隆（未使用 shallow clone；未拉取子模块），仅作为只读设计资料。

| 仓库 | 本地目录 | HEAD |
| --- | --- | --- |
| [canokey-console](https://github.com/canokeys/canokey-console) | `references/canokey-console` | `63863ef66ff0766754ee8f5bee28b9e977889f75` |
| [canokey-manager](https://github.com/canokeys/canokey-manager) | `references/canokey-manager` | `89a52a7ec237b93b01f1158f6ffc3d26a57e13f9` |
| [canokey-pkcs11](https://github.com/canokeys/canokey-pkcs11) | `references/canokey-pkcs11` | `086c4d135e59fc7b24c02e6efae2d3f0d982720a` |

## canokey-console

关键实现、相关回归测试及约定：

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

关键实现、相关回归测试及约定：

- [yubikit/canokey.py](https://github.com/canokeys/canokey-manager/blob/89a52a7ec237b93b01f1158f6ffc3d26a57e13f9/yubikit/canokey.py)
- [yubikit/piv.py](https://github.com/canokeys/canokey-manager/blob/89a52a7ec237b93b01f1158f6ffc3d26a57e13f9/yubikit/piv.py)
- [yubikit/core/smartcard/__init__.py](https://github.com/canokeys/canokey-manager/blob/89a52a7ec237b93b01f1158f6ffc3d26a57e13f9/yubikit/core/smartcard/__init__.py)
- [yubikit/management.py](https://github.com/canokeys/canokey-manager/blob/89a52a7ec237b93b01f1158f6ffc3d26a57e13f9/yubikit/management.py)
- [yubikit/oath.py](https://github.com/canokeys/canokey-manager/blob/89a52a7ec237b93b01f1158f6ffc3d26a57e13f9/yubikit/oath.py)
- [yubikit/openpgp.py](https://github.com/canokeys/canokey-manager/blob/89a52a7ec237b93b01f1158f6ffc3d26a57e13f9/yubikit/openpgp.py)
- [tests/integration/usbip/piv.sh](https://github.com/canokeys/canokey-manager/blob/89a52a7ec237b93b01f1158f6ffc3d26a57e13f9/tests/integration/usbip/piv.sh)

## canokey-pkcs11

关键实现、相关回归测试及约定：

- [src/backend/pcsc.c](https://github.com/canokeys/canokey-pkcs11/blob/086c4d135e59fc7b24c02e6efae2d3f0d982720a/src/backend/pcsc.c)
- [include/private/backend/pcsc.h](https://github.com/canokeys/canokey-pkcs11/blob/086c4d135e59fc7b24c02e6efae2d3f0d982720a/include/private/backend/pcsc.h)
- [src/api/sign.c](https://github.com/canokeys/canokey-pkcs11/blob/086c4d135e59fc7b24c02e6efae2d3f0d982720a/src/api/sign.c)
- [src/api/encrypt.c](https://github.com/canokeys/canokey-pkcs11/blob/086c4d135e59fc7b24c02e6efae2d3f0d982720a/src/api/encrypt.c)
- [src/internal/rsa.c](https://github.com/canokeys/canokey-pkcs11/blob/086c4d135e59fc7b24c02e6efae2d3f0d982720a/src/internal/rsa.c)
- [include/pkcs11_canokey.h](https://github.com/canokeys/canokey-pkcs11/blob/086c4d135e59fc7b24c02e6efae2d3f0d982720a/include/pkcs11_canokey.h)
- [AGENTS.md](https://github.com/canokeys/canokey-pkcs11/blob/086c4d135e59fc7b24c02e6efae2d3f0d982720a/AGENTS.md)

## 影响设计的观测

| 来源 | 观测 |
| --- | --- |
| manager canokey.py / piv.py | CanoKey 真实版本与 PIV 兼容版本不同；SELECT 安全状态、旧对象容器、空槽 SW 随固件变化 |
| Console piv_management_key / manager piv.py | 现有客户端分别使用 External / Mutual 管理密钥认证；Mutual 有 host RNG 输入 |
| Console models/piv.dart / piv_post_quantum | 历史和可配置算法 ID；ML-DSA/ML-KEM 的独立输入与结果格式 |
| Console metadata_directory / piv_controller | 目录与单槽 metadata 分离，条目可能仅有证书 |
| Console oath_card | OATH 使用 06/A5 续传，部分非空 9000 仍继续读取 |
| pkcs11 pcsc.c | PCSC 与 PIV 编解码混合；RSA 使用 short command chaining；应用自己保存认证/机制状态 |
| Console smartcard.dart / FRB 配置 | Dart 管理通路；process 内含身份 APDU，raw 路径有完整 APDU 日志；Rust bridge 默认 Dart 同步调用 |

以上是 host 实现证据，不是完整固件支持保证；尤其 manager 的通用 YubiKey API 不能直接当 CanoKey 能力。当前未运行上游应用测试或连接真机。若以后复制代码，应按文件审查许可证及第三方归属。
