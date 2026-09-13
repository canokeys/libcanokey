# libcanokey

CanoKey Host 侧统一协议库，目前处于设计阶段，尚未实现。

| 文档 | 内容 |
| --- | --- |
| [plan](plan.md) | 目标、边界、实施阶段和验收 |
| [design](docs/api-design.md) | 唯一的公开接口、所有权、协议与绑定契约 |
| [Console 示例](docs/console-integration.md) | Flutter / Rust 分层与异步调用 |
| [PKCS#11 示例](docs/pkcs11-integration.md) | C context、同步 executor 和签名/对象操作 |
| [参考依据](docs/references.md) | 固定 commit、源码与兼容证据 |

`references/` 是本地上游克隆，不作为库依赖或项目源码提交。
