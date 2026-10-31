# 完整且有限的独立离线授权

状态：独立原语、私有服务的生产管理链、真实 QUIC/TCP 与本机受保护流、断中心业务、固定总预算、恢复同步和物理资源释放已通过同源 Actions。原 daemon 常驻 CLI 已接通并通过严格 lint；本机退出登录、登录替换、安装身份变化与维护对原授权的停止检查也已通过。远控原累计预算/Session 接线、私有服务 TLS 备用与 UDP、交互式多进程和完整真机验收仍在实施，不据此将 AC45/AC46 整组记为通过。

W27 复用现有 Ed25519 network authority、serde 的严格有界消息、安装公钥、系统安全存储和现有 TLS/QUIC 业务 owner。通用密码算法、TLS、数据库和传输不另写实现。新增代码只定义独立产品授权、明确本机同意、一次激活、固定时限、累计计量及终态。

比较过两种方案：延长旧 SessionPermit/ServiceLease 或独立 OfflineGrantBundle。选择后者。旧在线验证器仍不能解析、接受或转换离线签名；离线包不能假装有效的在线 membership、connection、path 或节点资源租约。

单个独立 domain 的签名覆盖全部必需部分：部署/空间/安全/策略/最高撤销 epoch、双方固定账号/安装/公钥/成员 epoch、双方在线批准时的内存进程 nonce、连接身份、直连 path/QUIC或TLS集合、具体远控操作或固定私有服务定义/目标摘要、独立持久资源预留身份与总字节/文件写入/重连次数、统一失效时间。任何部分缺失或额外 relay 字段均拒绝。最多 30 分钟；输入/剪贴板写入/文件写入逐项批准。没有 TURN、relay、子网、WireGuard 或公网发布类型。

激活必须在原进程存活且在线完成显式批准与中心持久消费后进行。独立签名不是消费或数据库预留证明；storage/SDK 接线原子预留并消费、固定摘要、目标账号同意、管理员启用及双端 process proof，不能让任意导入文件调用激活。整个预留 promise 从原总预算扣除，不根据不可信客户端声称的剩余额度退款。恢复同步必须先应用最新有效撤销和 epoch；旧备份与新进程的随机 nonce 不同，不可离线恢复。

私有服务复用原 account/device/node/resource 四个 service quota ledgers 与原 private exposure 子额度。第二个独立端点批准同一完整摘要时，在一笔 SQLite IMMEDIATE transaction 中检查所有在线 outstanding promises、已有离线承诺、原 ACL/成员/固定目标及恢复 fence，再永久记入全部四个原 spent 账本并签发。第一次批准不预支额度，第二次失败不能留下部分批准或部分扣款。每端消费原先独立生成的设备挑战，DeviceAction 签名同时固定 bundle/digest、端点及原内存 process nonce；重复消费不能恢复丢失的激活响应。原 ACL rule ID 与 exposure revision 持久保留，撤销后重授的新规则不能复活旧包，即使中间没有任何观察请求。

真实 HTTP 入口在 `/api/v3/network/spaces/{space}/offline` 下，分别提供管理员启用、private-drafts、bundles 读取/撤销、approval、consume-challenge 与 consume。SDK 先验证用户实际选定的完整摘要和原 process nonce，再执行认证在线消费，最后独立验签并激活。恢复读取失败、收到更高或回退的 epoch、原规则/目标不再有效均停止原 owner。源码 `94bbe13a10e1f79dd81dec967273cefe3a492570` 的 7 个身份原语、8 个 SQLite 案例、2 个实际 HTTP/SDK 案例、268 个原存储回归及严格 lint 已通过；具体范围和哈希见 `docs/network-rewrite/evidence/offline-management-94bbe13.json`。这些证据未涵盖实际断中心业务或 UI。

内存 owner 不可 Clone/Deserialize，重建直连复用相同累计 meter 和固定 monotonic deadline，不新建预算。消耗过的 bundle ID 在原进程保留。进程本机停止/Drop 通过共享终态关闭所有原 owner。收到撤销/epoch变化、时钟回拨、monotonic或wall期限、额度/次数耗尽均终态。私有服务实际 I/O 的两个方向使用同一累计 meter，每次 poll 只允许剩余的签名字节额度；在拨号或接受 TLS 前计入一次连接尝试，拨号、证明失败或取消均不退款。空闲检查每 250 ms 执行，停止后 join 原 worker、收集原 QUIC socket 物理释放回执并删除受保护的本机 endpoint。等待超时或取消保留原 join owner，不能误报已完成清理。

独立离线信任锚是在线预批准的空间 authority + 双方固定安装公钥。原 `PrivateListener` 的薄适配使用原 rustls 相互安装证书 pin，实际 QUIC channel 在任何目标连接或业务字节前验证新的完整 transcript。证明同时需要安装私钥与本次原进程的内存临时私钥；协议原 32 字节 process nonce 是该临时密钥的公钥，私钥由原 owner 的私有 Arc 保留且不可导出。因此保存完整 claims 和正确安装证书仍不能在新进程恢复旧包。发现信息或名称不能替代这些证明，也不通过忽略证书错误实现离线连接。

生产 carrier 只接受 SDK 在实际认证在线消费后返回的 opaque `ConsumedOfflineBundle`。固定本机 TCP/HTTP/HTTPS 目标复用 `LocalServiceTargetConsent`、原 `HttpsBackendTls` 和原受保护 Unix socket/Windows byte pipe，实际业务使用原 QUIC BiStream 与 Tokio 双向复制。管理链的独立签名、普通文件导入或安装身份均不能单独创建这个生产 owner。每两秒复用原 SDK 认证探测中心；认证成功后先同步进入恢复暂停闸，再读取最新原授权和 epoch，失败终态。恢复时用本机当前 wall clock 检查原单调与回拨约束，不能把较早服务器时间当作本机时间。

`nestlink-daemon private-service-proxy --state-dir <private state> offline --space <uuid> --role host|source` 提供实际常驻命令入口，复用原登录会话和 headless runtime lease；有界 JSON 行命令支持启用、固定目标完整审阅与摘要同意、原 ACL、创建草案、双方审阅批准、一次激活、状态、恢复、撤销和停止。原内存进程在目标和 ACL 准备后才创建；一次激活失败不创建替代 owner。EOF、Ctrl-C、本机退出登录/身份变化/维护都停止原授权并等待原清理。具体操作见 `docs/network-rewrite/offline-private-cli.md`。

真实 carrier 的证据以源码 `97541a240f75305f479ae98f81ddce3fecad0850` 的 run `41220272087` 为准：7 个原语、8 个 SQLite、269 个完整存储回归、7 个实际 HTTP/SDK/QUIC 案例及生产 daemon 严格 lint 全部通过；官方 ZIP 与各 receipt 文件 SHA-256 均已独立核验，见 `docs/network-rewrite/evidence/offline-carrier-97541a2.json`。后续源码 `091686cef34363eab216930e6fa75c8636559796` 的 run `41222241357` 全部通过，并新增执行原常驻 guard 的四种本机终态事件；这些事件测试不代替交互式双进程或保护登录恢复的现场验收。

常驻 CLI 已显示“离线仅直连”、完整授权/摘要、固定到期时间、剩余毫秒/字节、累计及当前连接数、恢复/清理状态，以及中心未送达撤销最多延迟至本包到期的限制。不能将 L1 原语、实际私有服务 TCP/QUIC 证据或 CLI 编译/guard 测试外推为远控、TLS 备用、UDP、交互 UI 或 AC45/AC46 整组通过。
