# libcanokey 实施计划

状态：已实现阶段 1a 基础版本及阶段 1b 的 PIN/PUK、对象读取切片；未发布、未经真机验证。本轮只实现本库，不执行其他仓库的接入。当前可用接口与验证命令见 [README](README.md)。

本文只定义目标、范围、实施顺序和验收。公开类型、生命周期及协议契约统一见 [design](docs/api-design.md)；应用用法见 [Console](docs/console-integration.md) 和 [PKCS#11](docs/pkcs11-integration.md)。

## 1. 目标与边界

建立独立的 CanoKey Host 协议库，让 Console、ckman 和 canokey-pkcs11 共用 APDU/TLV 编解码、协议状态机、错误解释与固件兼容逻辑，同时保留各自的设备连接和运行模型。

| libcanokey 负责 | 调用者负责 |
| --- | --- |
| PIV、Admin、OATH、OpenPGP 协议 | PCSC、USB/WebUSB、NFC、CCID/HID |
| SELECT、认证、续传、分包、响应解析 | 枚举、打开、权限、会话、断连重连 |
| 版本归一化、能力、协议变体、quirk | 同步/异步 executor、锁、超时和取消 I/O |
| 纯内存密码计算中属于协议的部分 | 系统随机数、时钟、文件、主机密码策略 |
| 类型化协议结果与错误 | Flutter UI、CLI、PKCS#11 对象/机制/登录状态 |

应用发送库生成的完整 command APDU，再把完整 `response data + SW1 + SW2` 交回库。核心不定义 transport trait、设备 manager、运行时或可变全局状态。

统一使用调用者持有的 `DeviceProfile` 和 `Operation<T>`；绑定不得建立独立的协议状态或结果缓存。细节只在 design 中维护。

## 2. 实施阶段

| 阶段 | 交付 | 验收重点 |
| --- | --- | --- |
| 1a：基础 | protocol、owned Operation、兼容模型、只读 probe、最小 Admin 读命令 | 无 I/O 驱动的 transcript 测试；未知固件不整体拒绝 |
| 1b：PIV | PIN/PUK、管理密钥、metadata、生成/导入、sign/decrypt/derive、对象/证书、Batch | 高层操作覆盖 SELECT+认证+目标命令；消费者不用拼 APDU/TLV |
| 1c：首个消费者 | C ABI、pkcs11 逐功能接入 | 两种 opaque handle；类型化结果；长度查询不触发签名 |
| 1d：复用验证 | Console FRB 接入、Python binding、ckman PIV 接入 | 同一核心支持 Dart async 与 C/Python sync；native/wasm 可构建 |
| 2：Admin | 完整设备信息、配置、NFC/NDEF、存储、显式 applet reset | 配置变更失效通知；多 APDU 写入部分完成语义 |
| 3：OATH | 凭据、访问密钥、计算、legacy/current conversation | 专用 continuation、触摸和 HOTP 副作用 |
| 4：OpenPGP | DO、PIN/KDF、密钥、证书、policy、私钥操作 | 独立引用/算法/认证语义及固件覆盖 |
| 后续评估 | 新 PIV 扩展和 FIDO 可共享部分 | 按证据开放；CTAP 不强套 APDU 模型 |

PIV 扩展算法、目录、移动/删除密钥、重试配置和 ML-KEM decapsulation 按能力逐项开放。枚举里存在某算法不等于一期承诺该固件支持；API 清单和待验证项见 design。

## 3. 工程组织

Rust workspace 按依赖边界组织，后续阶段的 crate 在需要时再创建：

```text
canokey-protocol          APDU / TLV / Operation / status
canokey-compat            DeviceInfo / DeviceProfile / matrix
canokey-piv               PIV 语义操作
canokey-admin             最小 bootstrap 命令，后扩展完整 Admin
canokey-oath/openpgp      后续协议
canokey                  facade + probe 编排
canokey-c                C ABI
canokey-python           PyO3 binding
```

protocol 不依赖 compat；compat 不依赖 applet crate；applet 依赖 protocol + compat。facade 组合 probe，避免 `compat -> admin -> compat` 环。FRB wrapper 留在 Console 仓库，C ABI 不依赖 PKCS#11 类型。

第一版不强制 no_std，优先零平台 I/O、零 runtime 依赖、wasm 可用。核心依赖不得出现 pcsc、rusb/libusb、hidapi、tokio、Flutter/FRB、PyO3；协议所需的纯内存密码库可以使用。PyO3 仅允许在 Python binding 中。

Rust API 使用 SemVer；C ABI 独立管理 major/minor；Python 对外版本跟随库 major。固件协议变体与包版本分离。完整 C header 与实现通过验证后再冻结 ABI，设计伪代码不视为已发布接口。

## 4. 迁移方式

按 `pkcs11 -> Console -> ckman` 验证 PIV，再扩展协议。允许旧实现与新路径通过构建开关共存，逐功能替换，覆盖完整后删除旧协议代码。

迁移边界包括两项必要改动：应用关闭自身的 APDU continuation，避免双重处理；所有旧/新 APDU 路径共享设备级互斥和连接生命周期。不得在库 operation 中间插入应用的身份查询或 SELECT。

参考仓库已克隆到 `references/`，固定 commit 和关键源码见 [参考依据](docs/references.md)。它们是 host 行为证据，不是所有固件能力的保证；通用 YubiKey 支持不能直接移植为 CanoKey 能力。

## 5. 验证与完成标准

| 层次 | 必需检查 |
| --- | --- |
| 编码/解析 | APDU golden vectors、TLV 边界、证书封装、密钥/签名格式 |
| 状态机 | SELECT/认证顺序、61xx/6Cxx、command chaining、失败/取消/限额、Batch 部分完成 |
| 兼容性 | 已知版本矩阵、历史 ID/容器/空槽状态、未知新固件、能力观测来源 |
| 绑定 | C ownership/缓冲查询/错误 POD、FRB native/wasm、Python typed result、所有失败清理路径 |
| 集成 | usbip/真机覆盖 stable、previous、next 固件；应用 transport 保持独立 |
| 工程 | fmt、clippy、相关测试、C/C++ 构建、Python 构建、wasm 构建、依赖边界和 parser fuzz smoke |

一期完成时，三个消费者应能复用同一套 PIV 协议实现，同时继续管理自己的连接、UI/CLI/PKCS#11 状态。新增已知固件差异集中修改兼容层或对应协议模块，不分别维护三个消费者的 workaround。

尚需核实的固件范围、算法用途、双向认证与扩展协议列在 design；取得源码或受控 transcript 证据后才把相关能力标记为 Supported。
