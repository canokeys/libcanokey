# libcanokey 接口设计

状态：最终目标设计，当前已实现基础子集，范围见 [README](../README.md)。本文统一维护接口方向与生命周期契约；代码块仍是目标声明/伪代码，实际可用 API 以 crate 源码为准。目标与实施顺序见 [plan](../plan.md)，接入示例见 [Console](console-integration.md) / [PKCS#11](pkcs11-integration.md)，源码证据见 [references](references.md)。

## 1. 对象与所有权

核心公开两个需要管理生命周期的对象：

| 对象 | 内容 | 调用者 owner |
| --- | --- | --- |
| `DeviceProfile` | 不可变协议能力快照 | device/token context |
| `Operation<T>` | 输入、有效配置、内部状态机、当前 APDU、结果和错误 | 一次同步调用或异步用例的局部变量 |

Rust 无设备表、operation ID 注册表、凭据缓存、全局锁、thread-local last_error 或后台任务；只读协议常量/兼容表可以 static。设备、登录策略、锁、transport、executor、超时、随机数和时钟由应用提供或管理。

构造 operation 时复制所需配置，取得 Rust 秘密输入 ownership，或复制 FFI 输入；不长期借用调用者 profile/buffer。构造返回后可释放输入来源。profile 不包含当前 applet、登录状态、PIN 或连接 handle；配置变化不会自动更新已构造的 operation。

结果复制/移出后独立存活。Rust 使用 Drop，C 使用配套 free，Dart/Python 使用确定性 close 加 GC 兜底。绑定只转换类型/分派具体 `Operation<T>`，不维护第二份协议、命令、结果或错误缓存。APDU/TLV 编码、格式转换等纯计算保留为普通函数，不包装成 operation。

## 2. Rust Operation API

```rust
pub struct Operation<T> { /* 私有 owned 状态，无调用者 lifetime */ }
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

pub fn probe_device(options: ProbeOptions)
    -> Result<Operation<DeviceProfile>, Error>;

// piv 命名空间示例；不再公开 Sign struct 或 Operation trait。
pub fn sign(profile: &DeviceProfile, slot: Slot, input: SignInput,
            access: Access, options: OperationOptions)
    -> Result<Operation<Signature>, Error>;
```

| 状态/动作 | 契约 |
| --- | --- |
| Created / start | 返回 Exchange、Done 或协议错误；constructor 不做 I/O |
| AwaitingResponse / command | 借用完整 command APDU；重复读取不推进、不发送 |
| AwaitingResponse / advance | 消费上一条命令的一条完整 `data + SW1 + SW2`，推进状态 |
| Completed / result | 重复借用结果，不访问设备 |
| Completed / take_result | 一次移出独立结果，进入 ResultTaken |
| Failed / error | 保留 typed error，无普通部分结果冒充成功 |
| cancel | Created/AwaitingResponse -> Cancelled 并擦除工作数据；其他状态幂等无操作 |
| drop / binding close | 释放剩余数据，不发送 logout、不关闭设备、不回滚 |

非法状态调用返回 OperationStateError，不改变状态或覆盖已保存的协议错误。Done/协议失败后及时释放不再需要的执行秘密；结果保留至 take/drop。Rust command/result 借用不能跨下一次可变调用；其他语言只取得副本。

应用必须独占整笔 operation 的卡连接，不能交错刷新/SELECT。transport 出错由应用保留原错误并 drop/close；库不接收 Timeout/Disconnected，不自动重放。取消本地对象不等于底层 I/O 已停止：应用须等请求完成/成功取消，或隔离旧连接后再复用通路；迟到响应不能交给新 operation。

原生 Rust executor 由应用自己编写：

```rust
async fn execute<T>(mut op: Operation<T>, card: &mut AppCard) -> AppResult<T> {
    let mut step = op.start()?;
    loop {
        match step {
            Step::Exchange => {
                let response = card.exchange(op.command()?.as_bytes()).await?;
                step = op.advance(&response)?;
            }
            Step::Done => return Ok(op.take_result()?),
        }
    }
}
```

## 3. APDU、TLV 与 conversation

低层提供 `CommandApdu::encode`、`ResponseApdu::parse`、`StatusWord`、checked `Tag`、`TlvReader/Writer`，以及 `piv::command::*` / `piv::response::*`。单 APDU builder 返回 CommandApdu；超长逻辑命令返回 LogicalCommand，由 `conversation(logical, policy, limits) -> Operation<ResponseData>` 拆分。

- `ExpectedLength::Absent | Exact(1..=65536)` 区分无 Le、短 Le=00（256）和扩展 Le=0000（65536）；encoding 显式为 Short/Extended。
- BER TLV 使用 definite length，保留顺序和重复 tag；业务 parser 检查唯一 tag、结构和尾随垃圾。畸形、溢出、越界返回错误；未知允许扩展字段可保留。
- ISO `61xx` 使用 GET RESPONSE；`6100` 按短 Le=256 处理，实际请求受通路限制。CLA/Le 和终止方式由 applet conversation 决定。
- `6Cxx` 仅对声明可安全修正 Le 的物理命令重试一次；不重启 SELECT/认证，不累加失败响应 data。未声明安全时报告 SW。
- command chaining 中间 ACK 按协议检查，失败立即停止；完整重组后才解析 TLV。OATH 专用 `06/A5` continuation 及非空 `9000` 继续规则不套 ISO 默认循环。
- 应用必须关闭重复的 `61xx/6Cxx` 处理，传递未被上层改写的 R-APDU；不把状态失败吞成空数据。

`OperationOptions` 含 `ExchangeOptions` 与 `OperationLimits`。前者给出单次完整 command/response 字节上限（含头/SW）及 allow_extended，有效能力取通路与 profile 交集；默认 short，按卡能力 chaining，无法编码时发送前报错。后者默认累计响应 1 MiB、exchange 4096 次、每命令一次 6C 修正、TLV 深度 16；可显式调整有界值，不代表卡存储容量。无进展续传、分配和解压均受预算限制。

## 4. Profile 与只读 probe

```rust
pub enum Support { Supported, Unsupported, Unknown }
pub enum Evidence { Observed, FirmwareMatrix, LatestKnownFallback }
DeviceProfile::from_observations(DeviceObservations) -> Result<DeviceProfile, Error>;
DeviceProfile::info(&self) -> &DeviceInfo;
DeviceProfile::capability(&self, feature: Capability) -> CapabilityStatus;
DeviceProfile::piv(&self) -> &PivProfile;
DeviceProfile::warnings(&self) -> &[CompatibilityWarning];
```

DeviceInfo 保存原始 firmware 文本及可选解析版本、PIV application version、model、serial bytes、chip ID；这些版本使用独立类型，开发后缀保留。profile 字段私有，不让应用手填 quirk。观测必须来自同一设备，序列号不能替代连接 generation。

`ProbeOptions` 包含通路/资源约束和 Minimal/Piv 模式，一期默认 Piv。实际 bootstrap 顺序如下，不虚构通用 GET CAPABILITIES：

```text
00 A4 04 00 05 F0 00 00 00 00   SELECT Admin
00 31 00 00 00                  真实 firmware 文本，必需读取
00 31 01 00 00                  model，可选
00 32 00 00 00                  serial，可选
00 A4 04 00 05 A0 00 00 03 08   SELECT PIV（Piv 模式）
00 FD 00 00 00                  PIV 兼容版本，不替代真实 firmware
00 EE 01 00 00                  算法配置，仅在已知可安全探测时
```

probe 不试默认 PIN、不用写命令探测；会切 applet，不得插入认证序列。Admin SELECT 明确不存在报 UnsupportedDevice。必需命令失败或畸形响应不能吞掉；可选命令只有已确认“不支持”的 SW 才降级，认证要求记 Unknown+warning，其他错误保留。格式未识别的 firmware 文本保留原文，只启用稳定协议或观测有依据的功能。

兼容规则集中在 compat：

- 区分 capability（能否使用）、variant（编码格式）、quirk（历史特殊行为）；operation 读取归一化配置，不自行比较固件号。
- 已知版本使用有来源的 matrix；合法实测能力/算法 ID 优先，配置缺失字段不自动表示新算法 Supported。
- 未知新版本使用 latest-known 稳定格式及 fallback 证据，保留 Unknown；不因版本较大拒绝整台设备。依赖未知写入格式/算法的操作返回 CapabilityUnknown，不试写猜测。
- PivProfile 包括 slot、按用途的算法、管理密钥算法、policy、metadata/目录、对象/编码限制；内部管理历史算法 ID、容器、空槽状态、默认 policy 和 SELECT 行为。
- 连接身份变化/重连后一期重新 probe。配置 mutation 返回 `ProfileEffect::ReprobeRequired` 时作废 profile；不确定是否生效的配置写失败也应重新探测。普通密钥 mutation 只使相关 metadata/object cache 失效。

## 5. PIV 类型与认证

```rust
pub enum Slot {
    Authentication, Signature, KeyManagement, CardAuthentication,
    Retired(RetiredSlot), // checked 1..=20；实际范围受 profile 限制
}
pub enum MetadataTarget { Key(Slot), Pin, Puk, ManagementKey }
pub enum Algorithm {
    Rsa1024, Rsa2048, Rsa3072, Rsa4096, EccP256, EccP384, EccP521,
    Secp256k1, Sm2, Ed25519, X25519, MlDsa65, MlKem768,
}
pub enum ManagementKeyAlgorithm { Tdes, Aes128, Aes192, Aes256 }
pub enum PinPolicy { Default, Never, Once, Always }
pub enum TouchPolicy { Default, Never, Always, Cached }
pub enum ManagementAuthentication {
    External { key: ManagementKey },
    Mutual { key: ManagementKey, host_challenge: SecretBytes },
}
pub enum Access {
    None, Pin(Pin), Management(ManagementAuthentication),
    PinAndManagement { pin: Pin, management: ManagementAuthentication },
}
```

算法名称是语义，不是可重配的 wire ID。`Pin/Puk::from_bytes` 采用一期 CanoKey 6..8-byte 规则，wire 填 FF 到 8 bytes；字符串便利接口只接受 ASCII，其他 applet 使用独立秘密类型。`ObjectId::from_bytes` 接受完整 checked BER tag，如 `5F C1 02`、`7E`；`ObjectId::certificate(slot)` 负责映射。9B 管理密钥不能成为签名槽。

独立高层操作执行 `SELECT -> 必需前置读取 -> 显式认证 -> 目标命令`。写对象/生成/导入/更换管理密钥须带 management；私钥操作可用 None（如 PIN-never）或 Pin；None 不承诺卡已认证。双认证顺序为 management 后 PIN，使 VERIFY 紧邻私钥命令。禁止在失败后尝试默认凭据。

VerifyPin/AuthenticateManagementKey 只验证本次凭据，成功不是跨 SELECT/连接的授权令牌。调用者若选择缓存凭据，自己管理其生命周期。Mutual 的新鲜 challenge 由应用 CSPRNG 提供，3DES 8 bytes、AES 16 bytes；库处理 witness/challenge 密码计算及常量时间验证，失败不自动降级 External。

## 6. PIV 工厂与数据契约

以下工厂均为 `piv::<name>(profile, 表中参数, options) -> Result<Operation<T>, Error>`。

| 一期工厂 | 中间参数 | T |
| --- | --- | --- |
| select | 无 | SelectionInfo |
| verify_pin / get_pin_status / logout | pin / 无 / 无 | () / PinStatus / () |
| change_pin / change_puk / unblock_pin | old+new / old+new / puk+new_pin | MutationResult |
| authenticate_management_key | auth | () |
| set_management_key | new_key, touch, access | MutationResult |
| get_metadata | MetadataTarget | Metadata |
| generate_key / import_key | slot, algorithm/key, KeyPolicies, access | PublicKey / MutationResult |
| sign / decrypt / derive | slot, SignInput/RsaCiphertext/PeerPublicKey, access | Signature / SecretBytes / SecretBytes |
| read_object / write_object | id, access / id, value, access | ObjectData / MutationResult |
| read_certificate / write_certificate / delete_certificate | slot, access / slot, CertificateInput, access / slot, access | Certificate / MutationResult / MutationResult |
| read_algorithm_config | 无 | AlgorithmConfig |

后续按能力增加 read_metadata_directory、set_pin_retries、move_key、delete_key、decapsulate、write_algorithm_config；不因通用 YubiKey API 存在就声称 CanoKey 支持。扩展算法同样按用途分别验证。

主要类型约定：

| 类型 | 语义 |
| --- | --- |
| PinStatus | verified、remaining、total 可未知，另有 blocked；空 VERIFY 的 9000 不伪造次数，63Cx 在查询中是数据，在提交 PIN 时才是认证错误 |
| Metadata | Key/Pin/Puk/ManagementKey 分型；algorithm、origin、policy、可选公钥与扩展；未识别返回值保留 Known/Unknown(raw)，Unknown 不能用于发命令 |
| PublicKey | RSA unsigned big-endian n/e、EC SEC1 uncompressed point、Ed/X 原始 32 bytes、ML 原始公钥；可纯转换 SPKI DER |
| PrivateKeyMaterial | 秘密 RSA CRT p/q/dp/dq/qinv、EC 定长标量、Ed25519 seed、X25519 私钥、ML-DSA 32-byte / ML-KEM 64-byte seed；检查组件/长度，库编码 TLV |
| Signature | 携带算法；RSA/Ed/ML 为标准原始 bytes，ECDSA/SM2 可转换 DER 或定宽 P1363 r||s |
| ObjectData | 规范化容器内 value，支持 discovery 7E 和有依据的旧容器 quirk，不任意宽松 unwrap；按敏感数据管理 |
| Certificate | 解封装/有界 gzip 解压后的 DER，保留压缩标记；写默认不压缩；不做信任验证 |
| MutationResult | profile_effect=Unchanged/ReprobeRequired；不表示应用对象缓存已刷新 |

SignInput 显式区分 RSA encoded block（模数长度，主机负责 PKCS1/PSS/hash）、ECDSA digest（统一按阶位数左截断/短值补齐）、Ed25519 message、SM2 digest（主机已算 SM3(ZA||M)）、ML-DSA message/context（未验证的非空 context 发送前拒绝）。Decrypt 仅 RSA private operation，返回原始模数长度块，unpadding 留应用；Derive 返回原始 ECDH/X25519 secret，不做 KDF；ML-KEM decapsulation 独立命名并校验密文/共享秘密长度。peer 曲线/编码不合法必须报错。

对象不存在报 NotFound，unsupported/畸形响应不能变为空槽。DeleteCertificate 使用已支持的空证书编码，不删除私钥。密钥文件/PEM/PKCS#8 读取、CSR/X.509 策略、PKCS#11 padding/KDF/对象模型在应用层。

## 7. Batch

一次 SELECT 下的显式语义序列使用 builder，不引入持久 protocol session：

```rust
let mut batch = piv::BatchBuilder::new(&profile, options)?;
batch.push(piv::Request::AuthenticateManagementKey(auth))?;
batch.push(piv::Request::ImportKey { slot, key, policies })?;
batch.push(piv::Request::WriteCertificate { slot, certificate })?;
let op: Operation<piv::BatchResults> = batch.build()?;
```

Request 对应一期语义工厂，但无 Access，不含 Select/Probe/嵌套 Batch；认证是显式 request。请求数/总输入有界，内部不额外 SELECT 或切 Admin。PIN-always 每次私钥操作前须显式 VerifyPin。

首错停止，Error 携带 failed index/completed count，不回滚、不自动续跑。`Operation<BatchResults>::completed_results() -> Result<&[BatchResult], Error>` 可读取执行中/失败/完成状态的已完成项；take/cancel 后不可读取已移出/清理的数据。其他普通 operation 不提供部分结果。绑定按索引复制，不增加结果 handle。

## 8. 错误与秘密

Error 含 kind、可选 SW、phase、secret reference、可选 retries 和 Batch progress。kind 覆盖 InvalidArgument/InvalidPin/InvalidKeyMaterial、InvalidResponse/ProtocolViolation/LimitExceeded、AuthenticationFailed/PinBlocked、SecurityStatusNotSatisfied/ConditionsNotSatisfied、NotFound、UnsupportedDevice/Feature/Algorithm/ProtocolVersion、CapabilityUnknown、UnexpectedStatusWord、OperationStateError、DeviceAuthenticationFailed。

SW 映射带命令上下文：6A82 在 SELECT/GET DATA 含义不同，6A88 可为空 metadata，旧 6700 只在确认的空槽 quirk 内解释；未知 SW 保留原值，管理密钥错误不伪造用户 PIN 次数。transport/binding 错误与设备协议错误分开。

PIN、管理密钥、私钥、command、临时明文及敏感结果使用 zeroize/secrecy 等方案；Debug/错误/默认日志不带 payload。应用负责 FFI/transport 副本，Python/Dart immutable 字符串不能承诺擦除。成功/失败释放执行秘密，尚需读取的敏感结果留到 take/drop。

## 9. C ABI

只公开 `cnk_profile_t`、`cnk_operation_t` 两种 opaque handle。其余输入是栈上 descriptor，错误是无指针 POD，结果从 operation getter 复制。无 init/finalize、result/error/access/key/request handle、借用内部指针或全局 last_error。

```c
typedef struct cnk_profile cnk_profile_t;
typedef struct cnk_operation cnk_operation_t;
typedef uint32_t cnk_status_t;
typedef uint32_t cnk_step_kind_t;

uint32_t cnk_abi_version(void);
void cnk_profile_free(cnk_profile_t *profile);
void cnk_operation_free(cnk_operation_t *op);
cnk_status_t cnk_operation_start(cnk_operation_t *op,
    cnk_step_kind_t *step, cnk_error_v1 *error);
cnk_status_t cnk_operation_advance(cnk_operation_t *op,
    const uint8_t *response, size_t response_len,
    cnk_step_kind_t *step, cnk_error_v1 *error);
cnk_status_t cnk_operation_command(const cnk_operation_t *op,
    uint8_t *buffer, size_t *inout_len);
cnk_status_t cnk_operation_take_profile(cnk_operation_t *op, cnk_profile_t **out);
cnk_status_t cnk_operation_signature_copy(const cnk_operation_t *op,
    uint32_t format, uint8_t *buffer, size_t *inout_len);
cnk_status_t cnk_operation_result_copy_bytes(const cnk_operation_t *op,
    uint8_t *buffer, size_t *inout_len);

cnk_status_t cnk_piv_sign_new(const cnk_profile_t *profile,
    uint32_t slot, const cnk_sign_input_v1 *input,
    const cnk_piv_access_v1 *access, const cnk_operation_options_v1 *options,
    cnk_operation_t **out, cnk_error_v1 *error);
```

每个 Rust 工厂对应 `_new`；另提供 operation state/cancel/error/result_kind、typed metadata/pin-status/mutation/public-key/selection/algorithm-config getter、profile info/capability getter。Batch wrapper 在 start 前保存核心 builder，通过 batch_push 复制 request，start 时 build；结果按索引读取，无额外 handle。

ABI 数据与调用规则：

- 使用 uint32_t 语义枚举和 flags，slot 为 PIV 引用值，algorithm 不等于 wire ID。status 常量为 OK=0、INVALID_ARGUMENT=1、INVALID_STATE=2、BUFFER_TOO_SMALL=3、RESULT_TYPE_MISMATCH=4、PROTOCOL_ERROR=5、PANIC=6；step EXCHANGE=1、DONE=2。
- 可扩展结构以 uint32_t struct_size 开头；未知输入枚举/flags 拒绝。options 含 flags 与单帧/累计/次数上限，NULL 表示默认，零上限无效。ABI major 独立版本化，同 major 的尾字段兼容规则在 header 实现时冻结。
- bytes descriptor 为 pointer+size_t；access 含 kind、pin、management algorithm/mode/key/challenge；sign input 含 kind/algorithm/data/context；private key input 使用 typed components。constructor/push 完整复制，失败不转移或留下半成品。
- error_v1 含 kind/phase/reference、presence flags、SW、retries、Batch index/count，无堆内存；可传 NULL 忽略详情，否则须初始化 struct_size。库初始化输出字段，不遗留旧错误。
- copy getter：buffer=NULL 查询 required 并返回 OK；容量不足更新 required、返回 BUFFER_TOO_SMALL、不部分写；成功写实际长度。文本不含/不追加 NUL。getter 不推进，不重发 APDU；普通结果在 DONE 可读，失败 Batch 仅有已完成项。
- take_profile 仅对完成的 probe 成功一次，移出后与 op 独立。其他结果复制后 free op 即可。free(NULL) 安全，非 NULL 仅释放一次；constructor out 先置 NULL。Rust 分配必须用对应 free。
- 调用者保证有效指针和串行可变访问；不承诺检测任意悬空指针。FFI 捕获可展开 panic，返回 PANIC，受影响 op 不可继续但可 free；不允许 unwind 跨 C，分配器 abort 等进程故障不伪称可恢复。

## 10. Dart / Python 绑定

| 核心动作 | Dart / FRB | Python |
| --- | --- | --- |
| 工厂 | newSign 等具体函数，opaque op | piv.sign 等工厂 |
| start/advance | Exchange / Done / Failed(error DTO) | Exchange / Done，失败抛 typed exception |
| command | commandBytes() 副本 | command_bytes() 副本 |
| result | signatureResult 等独立 DTO | result() 转成独立 Python 值 |
| probe result | takeProfile() | take_profile() |
| cleanup | finally close | with / finally close |

FRB 在 Console Rust crate，直接依赖 Rust facade，不经过 C ABI；PyO3 在 canokey-python。wrapper 可用私有 enum 分派不同 Operation<T>，不把核心泛型或协议状态展开到 UI。close 清空 Option 并幂等，finalizer 兜底，不能在 Done 读取结果前释放 op。profile wrapper 同样可 close，应用负责共享 wrapper 的同步与替换。

Python 不提供 transport/executor；ckman 自己实现 start/exchange/advance 循环。ProtocolError 暴露 typed kind、SW、reference、retries、Batch progress；构造输入错误为 ValueError，状态误用为 OperationStateError。Dart 显示错误文案、Python CLI 格式化都留调用者。

## 11. 后续协议与待验证项

| 模块 | 后续语义 API |
| --- | --- |
| Admin | read_device_info/config/storage/chip/core_commit、update_config、PIN、NFC/NDEF、SM2 config、显式 reset_applet |
| OATH | select/validate/access-key、list/put/delete/rename、calculate/all；challenge、时间和随机数显式输入 |
| OpenPGP | DO/card-info、PW1-sign/PW1-other/PW3 与 KDF、policy、key/certificate、sign/decrypt/authenticate、fingerprint/generation-time |
| FIDO | 先保留既有 CTAP/HID/WebAuthn backend；另评估 CBOR/credential model，不强套 APDU Operation |

Admin patch 保留未知配置位，read-modify-write 不承诺跨 APDU 原子性；OATH HOTP 增量不可自动重试；OpenPGP 引用/算法/policy 不复用 PIV 类型。耗尽 PIN/PUK、CLI 确认、CSR/X.509 策略不作为隐式操作。

实现前用固件源码或受控 transcript 核实：bootstrap 最低覆盖范围、各算法用途/slot、各版本管理密钥双向认证、ML signing 模式、目录/移动/删除语义。参考实现差异不能直接当支持保证。验收矩阵与构建要求统一见 plan，不在各接入文档重复维护。
