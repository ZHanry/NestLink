# 完整且有限的独立离线授权

状态：独立原语与私有服务的生产管理员启用、双端批准、原总额度持久预留、一次消费及 HTTP/SDK 恢复同步已通过同源 Actions；实际离线业务 carrier、常驻进程 CLI/UI 和远控共享额度仍在实施。

W27 复用现有 Ed25519 network authority、serde 的严格有界消息、安装公钥、系统安全存储和现有 TLS/QUIC 业务 owner。通用密码算法、TLS、数据库和传输不另写实现。新增代码只定义独立产品授权、明确本机同意、一次激活、固定时限、累计计量及终态。

比较过两种方案：延长旧 SessionPermit/ServiceLease 或独立 OfflineGrantBundle。选择后者。旧在线验证器仍不能解析、接受或转换离线签名；离线包不能假装有效的在线 membership、connection、path 或节点资源租约。

单个独立 domain 的签名覆盖全部必需部分：部署/空间/安全/策略/最高撤销 epoch、双方固定账号/安装/公钥/成员 epoch、双方在线批准时的内存进程 nonce、连接身份、直连 path/QUIC或TLS集合、具体远控操作或固定私有服务定义/目标摘要、独立持久资源预留身份与总字节/文件写入/重连次数、统一失效时间。任何部分缺失或额外 relay 字段均拒绝。最多 30 分钟；输入/剪贴板写入/文件写入逐项批准。没有 TURN、relay、子网、WireGuard 或公网发布类型。

激活必须在原进程存活且在线完成显式批准与中心持久消费后进行。独立签名不是消费或数据库预留证明；storage/SDK 接线原子预留并消费、固定摘要、目标账号同意、管理员启用及双端 process proof，不能让任意导入文件调用激活。整个预留 promise 从原总预算扣除，不根据不可信客户端声称的剩余额度退款。恢复同步必须先应用最新有效撤销和 epoch；旧备份与新进程的随机 nonce 不同，不可离线恢复。

私有服务复用原 account/device/node/resource 四个 service quota ledgers 与原 private exposure 子额度。第二个独立端点批准同一完整摘要时，在一笔 SQLite IMMEDIATE transaction 中检查所有在线 outstanding promises、已有离线承诺、原 ACL/成员/固定目标及恢复 fence，再永久记入全部四个原 spent 账本并签发。第一次批准不预支额度，第二次失败不能留下部分批准或部分扣款。每端消费原先独立生成的设备挑战，DeviceAction 签名同时固定 bundle/digest、端点及原内存 process nonce；重复消费不能恢复丢失的激活响应。原 ACL rule ID 与 exposure revision 持久保留，撤销后重授的新规则不能复活旧包，即使中间没有任何观察请求。

真实 HTTP 入口在 `/api/v3/network/spaces/{space}/offline` 下，分别提供管理员启用、private-drafts、bundles 读取/撤销、approval、consume-challenge 与 consume。SDK 先验证用户实际选定的完整摘要和原 process nonce，再执行认证在线消费，最后独立验签并激活。恢复读取失败、收到更高或回退的 epoch、原规则/目标不再有效均停止原 owner。源码 `94bbe13a10e1f79dd81dec967273cefe3a492570` 的 7 个身份原语、8 个 SQLite 案例、2 个实际 HTTP/SDK 案例、268 个原存储回归及严格 lint 已通过；具体范围和哈希见 `docs/network-rewrite/evidence/offline-management-94bbe13.json`。这些证据未涵盖实际断中心业务或 UI。

内存 owner 不可 Clone/Deserialize，重建直连复用相同累计 meter 和固定 monotonic deadline，不新建预算。消耗过的 bundle ID 在原进程保留。进程本机停止/Drop 通过共享终态关闭所有原 owner。收到撤销/epoch变化、时钟回拨、monotonic或wall期限、额度/次数耗尽均终态。业务 owner 后续必须最少每秒运行检查，失败后实际关闭通道；原语函数成功不代表生产清理已实现。

独立离线信任锚是在线预批准的空间 authority + 双方固定安装公钥。后续 TLS/QUIC 接线必须验证当前实际 peer 证书/endpoint proof 与该公钥及 bundle transcript 绑定，满足证书有效性；发现信息或名称不能替代它。不能通过忽略证书错误实现离线连接。

用户界面必须显示“离线仅直连”、具体操作、原到期时间、剩余额度、当前直连可用性，以及中心未送达撤销最多延迟至本包到期的限制。L1 原语 tests 不代表 AC45/AC46 整组通过；实际生产断中心业务、持久配额、恢复同步及到期物理清理仍必做。
