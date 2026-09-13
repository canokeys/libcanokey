# PKCS#11 接入示例

本文只演示 C 调用方的组织方式；所有权与 C ABI 以 [design](api-design.md) 为准。伪代码中的 helper 属于 canokey-pkcs11，尚未实现或通过真机验证。

## 1. C 模块保存全部应用状态

```c
typedef struct {
    SCARDHANDLE card;
    uint64_t connection_generation;
    Mutex lock;
    cnk_profile_t *profile;
    LoginState login;
    SecretBuffer cached_user_pin, cached_management_key;
    ObjectCache objects;
} TokenContext;

typedef struct {
    TokenContext *token;
    CK_SESSION_HANDLE handle;
    SignState sign;
    DigestState digest;
    SecretBuffer context_pin;
} SessionContext;
```

PKCS#11 的入口 session 表留在 C 模块，Rust 不镜像。现有项目把凭据放在 CNK_PKCS11_SESSION，接库不必一次重写，但普通 USER/SO 登录的同 token 多 session 语义、登出传播和锁顺序必须由 C 保证。CKU_CONTEXT_SPECIFIC 绑定当前 session 的一次操作，不能自动用长期 USER PIN 代替。

C 可显式选择缓存原始未 padding PIN，以便新 SELECT 后重新验证；擦除、认证策略和对象/机制/hash 状态均由 C 管理。profile 放 token context，operation 只放一次调用栈，结果复制后立即释放。

## 2. 共用 executor 与 probe

`CardLease` 表示已持有设备锁和 PCSC transaction，覆盖整个 operation。下面 CHECK helper 的含义为“检查错误并跳 cleanup”；所有临时缓冲由 cleanup 擦除释放，不表示省略生产错误处理。

```c
static CK_RV run_op(CardLease *lease, cnk_operation_t *op, ErrorPurpose purpose) {
    cnk_error_v1 error = {.struct_size = sizeof(error)};
    cnk_step_kind_t step = 0;
    ByteBuffer command = {0}, response = {0};
    CK_RV rv = CKR_OK;

    CHECK_CNK(cnk_operation_start(op, &step, &error), purpose);
    while (step == CNK_STEP_EXCHANGE) {
        /* checked helper：query-size、reserve、copy；不推进 operation。 */
        CHECK_CK(copy_command(op, &command));
        /* 只封装 SCardTransmit，保留 data || SW，不重试、不处理 continuation。 */
        CHECK_CK(pcsc_exchange_raw(lease, &command, &response));
        CHECK_CNK(cnk_operation_advance(op, response.data, response.length,
                                        &step, &error), purpose);
        buffer_wipe(&command);
        buffer_wipe(&response);
    }
    if (step != CNK_STEP_DONE) rv = CKR_DEVICE_ERROR;
cleanup:
    buffer_wipe_and_free(&command);
    buffer_wipe_and_free(&response);
    return rv; // 借用 op，不负责 free
}

static CK_RV probe_token(TokenContext *token, CardLease *lease) {
    cnk_operation_t *op = NULL;
    cnk_profile_t *fresh = NULL;
    cnk_error_v1 error = {.struct_size = sizeof(error)};
    CK_RV rv = CKR_OK;
    CHECK_CNK(cnk_probe_device_new(&lease->probe_options, &op, &error), PURPOSE_PROBE);
    CHECK_CK(run_op(lease, op, PURPOSE_PROBE));
    CHECK_STATUS(cnk_operation_take_profile(op, &fresh));
    cnk_profile_free(token->profile);
    token->profile = fresh;
    fresh = NULL;
cleanup:
    cnk_profile_free(fresh);
    cnk_operation_free(op);
    return rv;
}
```

CHECK_CNK 使用传入的 error/purpose 映射 typed 协议错误；CHECK_STATUS 处理纯绑定错误，CHECK_CK 保留 CK_RV。用户 PIN 的 AuthenticationFailed/PinBlocked 可映射 CKR_PIN_INCORRECT/CKR_PIN_LOCKED；NotFound 根据枚举或指定对象访问分别处理。transport 错误由 PCSC helper 映射，不解析 SW。

重连前先作废旧 profile，不能让新设备 probe 失败后使用旧快照。通路上限与 constructor options 保持一致，通信/接收缓冲失败不通过再次 SCardTransmit“取结果”。

## 3. 登录与签名

C_Login 的 USER 分支：在 C 锁内先准备受控凭据副本，再运行 verify_pin operation；成功才提交 token 登录状态，最后无论结果都释放 op。C 保留的凭据由其自身登出/断连策略清理，Rust 不保存登录对象。SO 分支使用 authenticate_management_key；Mutual challenge 由 C CSPRNG 提供。

C_SignInit 只保存 key/slot/mechanism/长度/授权要求；不创建要跨调用保存的 Rust operation。以 P-256 CKM_ECDSA 为例：

```c
/* 已通过参数、session、机制、输入和授权前置校验，并持有相应锁。 */
static CK_RV sign_p256(SessionContext *s, CardLease *lease,
                       const uint8_t *digest, size_t digest_len,
                       uint8_t *out, CK_ULONG *inout_len) {
    const CK_ULONG required = 64; // PKCS#11 r || s，来自已验证 key 元数据
    if (out == NULL) { *inout_len = required; return CKR_OK; }
    if (*inout_len < required) {
        *inout_len = required;
        return CKR_BUFFER_TOO_SMALL;
    }

    cnk_operation_t *op = NULL;
    cnk_error_v1 error = {.struct_size = sizeof(error)};
    cnk_sign_input_v1 input = {
        .struct_size = sizeof(input), .kind = CNK_SIGN_ECDSA_DIGEST,
        .algorithm = CNK_ALGORITHM_P256, .data = {digest, digest_len},
    };
    cnk_piv_access_v1 access = {.struct_size = sizeof(access)};
    CK_RV rv = CKR_OK;
    CHECK_CK(prepare_sign_access(s, &access)); // C 的普通/context-specific 凭据或 NONE
    CHECK_CNK(cnk_piv_sign_new(s->token->profile, s->sign.piv_slot,
        &input, &access, &lease->options, &op, &error), PURPOSE_SIGN);
    CHECK_CK(run_op(lease, op, PURPOSE_SIGN));
    size_t n = required;
    CHECK_STATUS(cnk_operation_signature_copy(op, CNK_SIGNATURE_P1363, out, &n));
    *inout_len = (CK_ULONG)n;
cleanup:
    cnk_operation_free(op);
    finish_sign_attempt(s, rv);
    return rv;
}
```

size-only/too-small 不发 APDU、不消耗签名或 context-specific 授权，也可在获取 PCSC lease 前处理。真正执行后 getter 的异常长度不是让应用重签的 BUFFER_TOO_SMALL，应作为内部/设备错误终结。生产代码须完整遵守 PKCS#11 各错误的状态保留/终结规则。

CKM_ECDSA_SHA256 在 C 先 hash；RSA PKCS1/PSS 在 C 准备 encoded block。C_SignUpdate 保存 C digest 状态，C_SignFinal 真正输出时才创建局部 Rust operation。PIV PinPolicy::Always 与对外 CKA_ALWAYS_AUTHENTICATE 的映射须一致：每次卡私钥操作需要的 VERIFY 在这笔 operation 内完成。

## 4. 对象读写与清理

读取证书/metadata 采用同一局部生命周期：

```c
cnk_operation_t *op = NULL;
CHECK_CNK(cnk_piv_read_certificate_new(profile, slot, &access,
                                      &options, &op, &error), PURPOSE_READ_CERTIFICATE);
CHECK_CK(run_op(lease, op, PURPOSE_READ_CERTIFICATE));
CHECK_STATUS(cnk_operation_result_copy_bytes(op, NULL, &required));
CHECK_CK(reserve_output(&out, required));
CHECK_STATUS(cnk_operation_result_copy_bytes(op, out.data, &required));
/* out 是独立 DER bytes，由 C 对象层映射 CKA_VALUE。 */
cleanup:
cnk_operation_free(op);
```

上例沿用前述 checked helper，并由调用方在失败时释放输出缓冲。两个 getter 不重读卡；metadata 使用 typed getter，不再解析 TLV。枚举只跳过确切 NotFound，不吞认证或格式错误。

生成密钥返回公钥，C 创建 PKCS#11 object records；导入时 CKA_PRIME_1 等填入 typed private-key descriptor，库复制后编码。需要 `AUTH -> IMPORT -> WRITE CERT` 时用单个 Batch，仍只持有一个 op，无额外 input/result handle。

| 应用事件 | C 模块动作 |
| --- | --- |
| C_Logout | 更新同 token 相关 session、清凭据；按协议需要运行短期 Logout 或由连接层 reset/disconnect，free 本身不撤销卡上认证 |
| 断连/重连 | 等待/隔离在途 I/O，递增 generation、清凭据和受影响 cache、释放 profile，新连接 probe |
| C_CloseSession | 清本 session 的 hash/context auth；其他 session 使用 token 时保留 profile，最后 session 的登录语义按标准处理 |
| token 销毁/C_Finalize | 阻止新调用并等待在途调用，释放 C 状态、profile、PCSC 资源；无 Rust finalize |

参考实现与源码位置见 [references](references.md)，公共验证要求只在 [plan](../plan.md) 维护。
