# libcanokey 工作约定

## 范围与文档

- 使用中文说明进展和结果，代码、API 文档和 commit message 使用清晰的英文。
- `plan.md` 管理阶段与验收，`docs/api-design.md` 管理最终接口契约；README 记录实际实现范围和验证命令。设计目标不等于已完成功能。
- 只在 libcanokey 中实现和测试。`references/` 是只读上游克隆，不修改、不提交、不作为编译依赖；未经用户另行指示，不接入其他仓库。
- 按阶段交付可构建、可验证的增量，不以空实现或恒定 Unsupported 代替尚未实现的协议。

## 架构与生命周期

- 核心无 I/O、transport trait、async runtime、设备枚举、线程或可变全局状态。禁止 handle 注册表、全局锁、凭据缓存、thread-local last_error；只读协议常量允许 static。
- 调用者持有 DeviceProfile 和 Operation<T>。constructor 拥有所需配置和输入，不能长期借用 FFI 内存；operation 不持有连接或应用 session。
- start/advance 只推进状态；command/result getter 不推进、不重新发送。take_result 一次转移结果；cancel/drop 不发送 APDU、不回滚或重连。
- 新增协议放对应 crate；版本规则集中在 compat，probe 编排在 facade。内部 machine 接口仅用于 applet 组合，不能变成 transport callback。
- 能力 Unknown 与 Unsupported 分开；不把 PIV 兼容版本当真实固件，不把参考项目的 YubiKey 功能当 CanoKey 支持证据。

## 协议与秘密

- transport 输入输出契约为完整 APDU / 完整 data + SW。SELECT、认证、61xx/6Cxx、chaining 和解析归核心。
- 任何卡响应都必须有界、可返回错误，不能因畸形输入 panic。SW 按命令上下文解释，不能把所有错误吞成空对象。
- 认证和目标命令之间不得隐式 SELECT；不自动尝试默认 PIN 或重放有副作用命令。
- PIN、管理密钥、私钥、APDU 和敏感结果默认 Debug/日志脱敏；秘密缓冲使用 zeroize。注意 Vec 扩容可能释放未擦除旧分配，不能只检查最终 Drop。
- C ABI 只用 profile/operation 两种 opaque handle；输入 descriptor 完整复制，错误为调用者 POD，getter 支持 query-size/copy。
- FFI 必须声明指针/别名/并发合同，捕获可展开 panic；用固定整数映射并同步 header，不暴露 Rust layout 或借用内部指针。

## 检查与提交

- 实现协议时增加有意义的 golden/transcript、错误路径及生命周期测试；无需为纯文案编辑增加测试。
- Rust 更改提交前运行 `cargo fmt --all --check`、相关测试和 `cargo clippy --workspace --all-targets -- -D warnings`。核心阶段完成时验证 wasm 构建和依赖边界。
- C ABI 更改须运行 Rust 检查与 `scripts/test-c-abi.sh`，验证 C/C++ header、链接、缓冲查询、所有权和错误。
- 构建/工具链问题应先自行排查，未执行的检查须如实说明。不能把 host transcript 测试写成真机验证。
- 初始化 Git 后按可评审的阶段及时提交。commit 使用 Conventional Commits，例如 `feat(protocol): ...`、`test(ffi): ...`、`docs: ...`；subject 用祈使语气，尽量不超过 72 字符。
- 提交前检查 staged diff、`git diff --check` 和状态；不提交上游克隆、target、缓存、环境秘密或生成的二进制。提交 Cargo.lock 以固定 workspace 验证依赖。
- 不修改全局 Git 配置，不强推、不撤销用户修改。提交身份优先遵循用户指定或仓库已有配置。
