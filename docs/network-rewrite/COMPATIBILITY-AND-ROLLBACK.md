# 网络重构的兼容与回滚边界

产品版本、既有远控线协议、新网络签名对象和数据库 schema 分别版本化。`compatibility.json` 的协议 schema 不是 SQLite schema；当前 SQLite 版本以 `crates/storage/src/lib.rs` 的唯一 `SCHEMA_VERSION` 为准。`NestLink/v15` 配置命名空间与既有 `nestlink/1` ALPN 保持原语义，新网络授权对象有独立 schema、签名域、用途和空间，不能把它们解释为旧远控许可。

| 端点或制品组合 | 明确行为 | 当前证据边界 |
| --- | --- | --- |
| 双方都支持 `network-core-v1` | 双边校验后可选择新网络契约；迁移还要求双方都支持 `path-migration-v1` | 契约协商函数及反例已实现，生产统一能力握手尚待接线 |
| 新端与不支持新契约的端 | 只有双方无必需新能力时，契约允许选择原有 v15 业务；这不授权空间、TUN、转发、子网或任何新业务 | 生产入口当前使用明确的本地按空间/设备配置和签名授权，不应把纯契约测试称为完整混合节点验收 |
| 任一端要求对方不支持的新能力、未来能力或未知 schema | 拒绝，不能在握手失败后自动改用旧授权 | `network_contract` 与 Session 授权反例覆盖未知必需能力；实际旧新节点矩阵待验证 |
| 原始 0.7 RC 服务端与当前 SQLite schema | 旧可执行文件拒绝读取未知较新 schema | `network-upgrade.yml` 用公开保留的旧 DEB 实际执行，结果按对应 SHA 记录 |
| 当前服务端直接 `check` 旧 schema | 拒绝，要求先执行显式离线备份迁移 | 同上，另核对拒绝前后原数据库事实未变化 |
| 当前版本从旧 schema 向前迁移 | 创建并认证加密备份、保留旧目录、迁移新私有目录；保留部署钥匙、epoch、已撤销记录和累计债务 | 实际旧包 CLI 实验及现有加密迁移/存储回归，不能代替签名安装和现场升级资格 |
| 尚未准入业务的显式 deferred 迁移 | 用原 journal 与事务 UUID 完成或恢复原目录 | CLI 实验覆盖 `--defer-admission` 拒绝业务及准确回滚 |
| 已经完成准入的迁移 | 拒绝重放旧事务回滚；保留更晚的撤销和消耗 | CLI 实验写入更晚的 fixture 撤销/债务，再验证旧事务失败且事实不变 |
| 旧加密备份恢复到新目录 | 新随机安全 epoch、旧登录/凭据/会话失效；空间和累计配额保持恢复 fence，未经外部对账不能继续消费 | 原存储、操作库及 CLI 实验分别验证，不能将旧快照里的下界当作完整最新余额 |

`network-upgrade.yml` 固定使用已发布的 `v0.7.0-rc.1` 清单及 Linux x64/ARM64 DEB，核对既有清单 SHA256、每个 DEB 的 SHA256 和源 `82f1c8dfb31bdf0872ea7430b5608e205c1cbb08`。该旧源实际 SQLite schema 为 **25**；旧发行说明曾写 24，实验以受核验源码和真实 `init` 结果为准。当前服务端由本轮干净 SHA 和 Cargo.lock 在 GitHub 构建。新旧进程、SQL fixture 与执行日志都在托管 runner 上运行，工作区仅维护源码和阅读证据。

对线上部署先停止控制服务并确认其真实 lifetime owner 退出。通过当前已核验的服务端检查 `schema --config <私有部署>/server.toml`；不要用新二进制的业务入口隐式升级，也不要在仍运行的 WAL 数据库上复制主文件。保存密码托管和独立备份后，执行：

```text
nestlink-server migrate --config <绝对私有部署>/server.toml --from-schema <实际旧schema> --to-schema <此二进制schema> --backup <部署目录外的新私有归档> --password-file <私有密码文件>
```

受支持的正式 Linux 包 owner 使用 `--defer-admission`，待二进制、安装 generation 与 receipt 完成提交后才开放业务。尚未完成的事务必须保留 journal，按其中事务 UUID 显式 `recover-migration --complete` 或准入前 `--rollback`。旧目录、旧包或旧备份仍存在，并不意味着可以绕过事务准入边界。完整操作细节沿用 `docs/refactor/SCHEMA-UPGRADES.md`、`docs/refactor/BACKUP.md` 和各个 OS owner 的恢复流程。

按空间/设备的本地显式灰度不能扩大中心签发范围。回退时只切换到仍具备有效授权的旧路径；direct-only、撤销、终态和原预算优先。TUN、DNS、LAN、WireGuard 分别等待自身 owner 真实释放/恢复之后再回退或卸载。缺少新能力时，控制台应明确显示不可用。

W35 尚欠统一生产能力协商、Windows/Web/节点全组合和受核验签名包的目标升级回滚矩阵。纯函数协商、托管 Linux CLI 实验和既有历史迁移通过分别记录；没有对应执行证据的组合保持待验证。
