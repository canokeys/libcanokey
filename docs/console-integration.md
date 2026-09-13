# Console 接入示例

本文只演示 Console 的分层和调用；公共生命周期、错误与协议契约见 [design](api-design.md)。以下均为伪代码，尚未运行 FRB codegen。

## 1. 分层与迁移点

```text
Flutter 页面 / Controller
    ↓ 业务参数和结果
Dart service / executor
    ├── FRB → Console Rust wrapper → libcanokey Operation<T>
    └── await exchangeRaw → Dart CCID / WebUSB / NFC → CanoKey
```

页面处理输入/提示；Dart 持有连接、profile、锁和取消状态；Console Rust wrapper 只转换类型/分派核心对象。FRB 留在 Console 仓库，直接依赖 Rust facade，不经过 C ABI。

现有实现的必要调整（源码见 [references](references.md)）：

- `SmartCard.process()` 中 Admin SELECT/读序列号改由 probe 完成，提取只管理设备会话的 `withExclusiveSession()`，取消/错误必须向上层传播。
- `SmartCard.transceive()` 的完整 APDU 日志移除或脱敏；新增 `exchangeRaw()` 绑定本次实际连接，返回完整 R-APDU。插件仅支持 hex 时只在这里转换。
- 新路径不用 `transceiveChained()`、`assertOK()`、`dropSW()`；旧路径、后台刷新和新路径共用设备互斥，计数器不是锁。
- `rust/src/api/piv_crypto.rs` 保留文件解析、CSR/证书策略；私钥解析后直接构造核心 PrivateKeyMaterial，不把 IMPORT TLV 经 Dart 往返。

## 2. Rust wrapper

沿用当前 FRB 配置的同步短调用；只有 Dart transport 做异步 I/O。示意省略错误转换和重复 enum 分派，具体生成形式需验证 FRB 2.13 的 native/wasm 支持。

```rust
#[frb(opaque)]
pub struct ProtocolProfile { inner: Option<DeviceProfile> }
#[frb(opaque)]
pub struct ProtocolOp { inner: Option<AnyOperation> }

enum AnyOperation { // Console 私有类型，不实现协议
    Probe(Operation<DeviceProfile>),
    Sign(Operation<Signature>),
}
pub enum BridgeStep { Exchange, Done, Failed(ProtocolErrorDto) }
pub struct SignatureDto { pub der: Vec<u8>, pub p1363: Vec<u8> }

pub fn new_p256_sign(profile: &ProtocolProfile, slot: PivSlotDto,
                     digest: Vec<u8>, pin: Vec<u8>, options: OptionsDto)
    -> Result<ProtocolOp, BridgeError>
{
    let pin = Zeroizing::new(pin);
    validate_sha256_length(&digest)?;
    let op = canokey::piv::sign(
        profile.require_open()?, slot.try_into()?,
        SignInput::ecdsa_digest(Curve::P256, &digest)?,
        Access::Pin(Pin::from_bytes(&pin)?), options.try_into()?,
    )?;
    Ok(ProtocolOp { inner: Some(AnyOperation::Sign(op)) })
}

impl ProtocolOp {
    pub fn start(&mut self) -> BridgeStep { self.dispatch_start() }
    pub fn advance(&mut self, response: Vec<u8>) -> BridgeStep {
        let response = Zeroizing::new(response);
        self.dispatch_advance(&response)
    }
    pub fn command_bytes(&self) -> Result<Vec<u8>, BridgeError> {
        Ok(self.dispatch_command()?.as_bytes().to_vec())
    }
    pub fn signature_result(&self) -> Result<SignatureDto, BridgeError> {
        let signature = self.require_sign()?.result()?;
        Ok(SignatureDto {
            der: signature.to_der()?, p1363: signature.to_p1363()?,
        })
    }
    pub fn take_profile(&mut self) -> Result<ProtocolProfile, BridgeError> {
        Ok(ProtocolProfile { inner: Some(self.require_probe_mut()?.take_result()?) })
    }
    pub fn close(&mut self) { self.inner.take(); }
}
```

newProbe 包装 `probe_device()`；profile 有 info DTO getter 和 close。协议错误转换为结构化 kind/SW/retries/reference/phase，构造或 getter 错误也必须保留类型，不能仅靠异常字符串。wrapper 不重复保存 command/result/error/terminal；关闭状态仅由 Option 表达。

## 3. Dart executor

`CardLease` 已持有本次物理连接和设备锁；`readResult` 是 Dart 本地函数，不跨 FRB。

```dart
Future<T> execute<T>(ProtocolOp op, CardLease lease, CancellationToken cancel,
                     T Function(ProtocolOp) readResult) async {
  try {
    lease.assertCurrentGeneration();
    cancel.throwIfCancelled();
    var step = op.start();
    while (true) {
      switch (step) {
        case BridgeExchange():
          final command = op.commandBytes();
          Uint8List? response;
          try {
            lease.assertCurrentGeneration();
            cancel.throwIfCancelled();
            response = await lease.exchangeRaw(command);
            lease.assertCurrentGeneration();
            cancel.throwIfCancelled();
            step = op.advance(response);
          } finally {
            wipe(command);
            wipe(response);
          }
        case BridgeDone():
          return readResult(op); // 取得独立值后才 close
        case BridgeFailed(:final error):
          throw ProtocolFailure(error);
      }
    }
  } finally {
    op.close();
  }
}
```

同步 FRB 调用返回后输入必须已复制/消费，wipe 才安全。取消后 lease 按 design 的在途 I/O 规则清理/隔离连接，不能只 `Future.timeout()` 后立即解锁重用。

## 4. Service 与页面

先用每次用例 probe 的保守版本，特别适合 NFC。稳定 USB 连接可由 DeviceContext 按 generation 缓存 profile，替换/断连时 close；序列号不能替代 generation。

```dart
Future<SignatureDto> signP256Digest(slot, digest, pin, cancel) async {
  try { // service 取得 pin 可变副本的清理责任
    return await sessions.withExclusiveSession((lease) async {
      final profile = await execute(
        newProbe(lease.options), lease, cancel, (op) => op.takeProfile());
      try {
        return await execute(
          newP256Sign(profile, slot, digest, pin, lease.options),
          lease, cancel, (op) => op.signatureResult());
      } finally {
        profile.close(); // 缓存版本则由 DeviceContext 释放
      }
    });
  } finally {
    wipe(pin);
  }
}

// 页面：进入卡会话前收集输入；其余 UI 代码省略。
try {
  final signature = await service.signP256Digest(
    slot, consoleCrypto.sha256(document), pinBytes, pageCancellation);
  showSignature(signature.der);
} on ProtocolFailure catch (e) {
  showProtocolError(e.kind, retries: e.retriesRemaining);
} on TransportFailure catch (e) {
  showConnectionError(e);
}
```

Sign 自己完成 `SELECT -> VERIFY -> GENERAL AUTHENTICATE -> 续传`；Dart 只循环收发。63C2 已由 Rust 转成 AuthenticationFailed/retries=2，页面不认识其编码。

operation 跨多个 await 仍是一次用例的局部变量。页面关闭只请求取消，不与 executor 抢调用 close。UI String/插件 hex String 无法保证擦除，故不能宣称秘密未离开 Rust。

复杂用例仍由 service 编排：已知的 `AUTH -> IMPORT -> WRITE CERT` 用 Batch；依赖上一步公钥的 CSR 流程由 Console Rust 纯函数与多次 operation 组合。管理密钥 Mutual challenge 在 Console 应用层用 CSPRNG 生成，协议密码步骤仍在库内。
