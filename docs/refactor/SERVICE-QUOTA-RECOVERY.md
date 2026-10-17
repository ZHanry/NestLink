# 服务累计配额的离线恢复对账

Linux ARM64 release 服务端另经实际 QEMU 执行和独立 Python Ed25519 签名器完成 16 项 CLI 联调，覆盖四类快照缺失 UUID 债务导入、失败保持封锁、一次提交、重放和再次恢复后的旧证明拒绝。精确执行范围与原件见 [ARM64 开发记录](LINUX-ARM64-VERIFICATION.md)；该合成开发账本不代表生产外部账本已配置。

2026-10-15 开发验证：Windows/Linux 的 Node 持久计量四组各 29 项、Storage publication/恢复事务各 13 项、真实 HTTP→Node→QUIC→TCP 发布与启动取消各 2 项，以及实际离线 CLI 各 1 项通过。五 crate strict 和 server/daemon 夹具修复后的 strict 两端通过。原失败与修复后的输入单列，见 [集中检查](NATIVE-INTEGRATION-CHECKS-2026-10-15.md)。这不代表当前环境已经接入独立账本或完成正式运维恢复。

恢复旧快照会生成新的安全代次，并持久封锁新的服务额度签发。快照本身不能证明备份之后的用量；普通账号登录、修改限额、等待发布租约到期或者换资源 UUID 都不能代替对账。

当前实现提供两个离线命令，均持有控制进程的 singleton runtime lease 和既有部署 admission lease。控制进程仍在运行、维护未结束或部署不可信时拒绝操作。没有 HTTP 解封接口，也不会在恢复后自动签出证明。

```text
nestlink-server quota-recovery-request --config <恢复目录/server.toml> --output <新的私有请求文件>
nestlink-server quota-reconcile --config <恢复目录/server.toml> --trusted-ledger-key <独立配置的公钥文件> --proof <外部账本签名证明>
```

公钥文件须由运维从独立账本的可信渠道预先配置，内容为 32 字节原始 Ed25519 公钥，使用现有 OS 私有文件规则。文件不能来自恢复目录，也不能使用本部署 permit、node policy 或 service lease 的签名公钥。部署备份不会为操作者选择外部信任根。任意生成一把新钥匙、把旧快照数字签一遍，不能证明账本完整。

外部账本必须独立于被回滚的快照，覆盖整个部署的累计用量和所有未结额度，包含快照没有记录的账号、设备、节点及资源 UUID。对账前必须停止并隔离此前的所有额度签发者，等待完整服务租约及清理余量；不知道实际用量的 grant 按完整额度收费。没有可信外部材料时，正确结果是继续封锁发布。

共享契约位于 `crates/protocol/src/service_quota_recovery.rs`，签名适配位于 `crates/identity/src/service_quota_recovery.rs`。外部适配器使用独立的 `ExternalServiceQuotaSigner` 或同一签名域的实现。控制程序不会调用它为自己生成对账证明。

请求包含部署、新安全代次、policy/quota revision、已知 grant 摘要，以及四类 scope 的已知 spent/outstanding 下界。`service_quota_recovery_request_digest` 对共享结构的有界 JSON 编码计算 SHA-256；外部证明必须绑定这个精确摘要。请求只提供下界，外部账本还要补齐快照缺失的债务。

证明明确声明已覆盖全部历史 grant，并包含外部 ledger/checkpoint UUID、checkpoint 摘要、旧签发者停止时间和完整累计收费列表。四类 scope 的总和必须相等，条目按 `(scope.as_str(), UUID)` 排序且唯一。每个累计值及其聚合受 SQLite 有符号整数上限约束；最多 65,536 个 scope，claims 最多 16 MiB，有效期最多 15 分钟。外部签名域为：

```text
NestLink/v15/external-service-quota-reconciliation/v1\0
```

最后一字节为 NUL。签名对象的 `claims` 是原始共享 JSON 字节，`signature` 是 Ed25519 签名；外层 JSON 沿用项目的字节数组表示。验签后仍在同一 SQLite 事务重新比较当前请求，防止导出之后的限额或账本变化、旧代次证明和重复解封。

对账不能降低任何已知 `spent + outstanding`。旧 grant 的未知承诺继续保留，不制造 Node 停止封存，也不退额；新 spent 调整到外部累计收费减去这些已知承诺，避免重复收费。快照缺失的 UUID 也会保存债务，没有本地对象时默认可用限额为零。已有对象恢复其正常默认限额，已明确配置的限额保持原值。对账不会提高管理员设置的额度。

所有导入和 fence 清除在同一事务提交；最后一步失败会回滚先前导入。命令在提交前保全精确签名证明，在审计中记录其 claims 摘要。第一次成功后再次提交拒绝；再次恢复会产生新代次，使旧证明失效。设备授权、主机目标批准、节点租约、发布租约及入口物理清理仍按各自流程恢复，对账本身不创建转发权限。

当前环境尚未接入外部累计账本服务。开发回归使用独立签名夹具和实际 CLI/SQLite/OS 锁验证这些边界；它不能替代生产外部账本的完整性和运维停机证明。
