# libcanokey

CanoKey Host 侧的 Rust 协议库。库生成 APDU、消费完整响应；连接、收发、并发和应用状态由调用者管理。当前为未发布的 0.1 开发版。

## 当前实现

- `canokey-protocol`：owned `Operation<T>`、APDU、BER TLV、ISO GET RESPONSE、受限 Le 修正、short command chaining、资源限额和敏感缓冲。
- `canokey-compat`：真实固件/PIV 兼容版本分离、能力证据、未知版本保守回退、历史/观测算法 ID、旧对象容器规则。
- `canokey-admin` / `canokey`：最小 Admin 命令与 Minimal/Piv 只读 probe。
- `canokey-piv`：SELECT、PIN 查询/验证/登出、修改 PIN/PUK、解锁 PIN、带可选 PIN 的对象读取。

尚未实现管理密钥认证、metadata、生成/导入/签名/解密/派生、证书 API、Batch、完整 Admin/OATH/OpenPGP 和 Python binding。没有修改或接入其他仓库；兼容性目前依据 host 实现和离线 transcript，未经真机/usbip 验证。

## 构建与使用

工具链固定为 Rust 1.85.1；安装 rustup 后在仓库运行：

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo build -p canokey --target wasm32-unknown-unknown
python3 scripts/check-dependencies.py
cargo run -p canokey --example probe
```

probe 示例仅执行固定响应 transcript，不连接设备。应用的实际执行循环如下：

```rust,ignore
let mut op = canokey::probe_device(Default::default())?;
let mut step = op.start()?;
while step == canokey::Step::Exchange {
    let response = app_transport.exchange(op.command()?.as_bytes())?;
    step = op.advance(&response)?;
}
let profile = op.take_result()?;
```

## 文档

| 文档 | 内容 |
| --- | --- |
| [plan](plan.md) | 阶段状态、后续范围和验收 |
| [design](docs/api-design.md) | 最终目标接口与生命周期契约；当前可用 API 以代码为准 |
| [Console 示例](docs/console-integration.md) / [PKCS#11 示例](docs/pkcs11-integration.md) | 后续接入伪代码，尚未执行接入 |
| [参考依据](docs/references.md) | 上游固定 commit 和源码 |
| [AGENTS.md](AGENTS.md) | 开发、验证与阶段提交约定 |

`references/` 和 `target/` 不提交；Cargo.lock 提交以固定依赖。核心依赖目前只有 zeroize，没有 transport/runtime 或可变全局状态。
