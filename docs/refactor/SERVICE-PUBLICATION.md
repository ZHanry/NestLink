# 服务发布实施状态

2026-10-15 当前生产树已接入服务配置 registry（schema 18）、独立本机目标批准挑战/签名、账号隔离、创建与批准登录的独立失效，以及 SDK/Core/桌面/Web/Android 的真实 CRUD。管理页只有服务器真实返回的配置状态；目前保存配置后的 `not_published` 不等于公网可用。管理权限、主机目标批准、节点 public ingress 许可和实际服务发布分别核验。

schema 20 的持久累计会计已合入：账号、设备、节点、资源四个 scope 同时计入 lifetime spent 和未结承诺；签名 grant 固定 UUID/代次/额度，Node 先持久准入再转发，累计 report 必须获得精确签名 ACK。停止须等待所有真实 flow/drain owner 关闭并封存最终报告；重试复用原字节，未知债务不退额。HTTP reporter 停机最多等待五秒，未确认对象继续留在 SQLite。测试目录只在 SQLite Connection 真实关闭后清理。整合及后续修复见 `artifacts/core-verification/service-accounting-quota-draft-20261015-integration.json` 与 `service-accounting-regression-followup-20261015-integration.json`；完整整合回归仍在执行。

恢复旧快照不能证明快照之后的用量。`invalidate_after_restore` 持久设置 quota restore fence，普通限额修改、短 publication fence 到期、新 UUID 或重启都不能解除；配额 API 的 `reconciliation_required` 明确返回这一状态。当前已实现离线请求导出及外部账本签名对账入口，绑定恢复代次和精确账本摘要，四 scope 的未知承诺继续收费；没有可信外部证明时保持拒绝。正式环境尚未接入外部累计账本，不能以旧快照自身证明对账完成。流程和契约见 [离线配额恢复](SERVICE-QUOTA-RECOVERY.md)。

第二层数据面已合入：服务专用派生签名密钥与 purpose、最长 10 秒租约/2 秒资源快照与开流挑战、固定 SocketAddr 的本机目标 owner、独立 NodeEdge/public ingress 准入、共享连接/速率/总字节预算、真实 OS TCP listener/半关闭/背压/撤销，以及 1200 字节整包上限的 UDP 目标侧 mapping/反重放窗口。单元测试中的 Tokio duplex 只验证流内核，不能替代生产加密 carrier；目标侧 UDP socket 也不能替代真正公网 UDP 入口。

独立审查发现资源对象重建会丢失同 runtime 的 sequence/tombstone。当前已合入 NodeControl 的粘性唯一 owner，阻止重建后重放；PreparedLocalTunnel 保存原 challenge 的单调期限，仅限制本机连接准入，已建立流沿用发布租约。原审查补丁位于 `artifacts/service-data-plane-audit-20261015/`，最终集成原件、结果与逐文件哈希另存于 `artifacts/service-publication-runtime-integration-20261015/`。

接入第三层前的开发检查：Windows 文件/remote、Core services 和 Android bridge 所选三组通过；Linux 六组的旧 daemon pending 文件夹具曾因权限 0644 被正确拒绝。该夹具现改为创建私有文件，新增真实 CLI 拒绝宽松权限的测试，后续 attempt02 的两端 daemon library、维护与子进程组均通过。旧失败仍保留。独立 SDK WASM library 的 UUID JS 随机源声明已修复，attempt02 通过。当前 Kotlin/JVM 67 项和 Web WASM 对应各自记录的源码快照，不构成新原生运行时代码通过。

第三层实际接线已合入：schema 19 的持久入口归属与容量承诺、server 签发 API、NodeControl 专用服务 poll、固定身份的 service ALPN QUIC、真正公网 TCP listener 到固定本机 backend，以及保留原清理 worker/endpoint 的 SDK host owner。节点签名与重放验证通过后、完整资源快照工作前扣除请求预算。TCP 单访客 ACL/两级容量拒绝改为关闭该访客并继续监听；普通线程析构仍使用捕获的原 Tokio Handle 驱动清理。新回归包括真实 TCP 拒绝后继续接纳、节点停止释放端口，以及跨线程析构期间保留原 UDP socket。

签发者续期增量也已合入：每份独立资源快照同时返回 policy-signed `ServiceResourceGrant`；edge 在 service control stream 发送 `ServiceLeaseRenewal`，主机在原部署、epoch、策略及服务密钥范围内验签并拒绝签发时间/期限回退。不会修改旧证明的期限。真实 QUIC worker 跨过初始短证明期限仍继续运行的回归已在 Windows/Linux SDK library 27/27 中通过。6 条 API 已接入唯一路由清单及共享模型注册，节点资源接口使用节点独立签名。OpenAPI 已由当前共享类型重新生成，生成 attempt02 的源码稳定/临时目录回收 receipt 已保留。

UDP 和后端 TLS 增量已合入：真实公网 UDP socket、独立 visitor mapping 与原生 QUIC DATAGRAM（1200 字节整包上限，无 stream fallback）；空包保留，过大包逐包丢弃。mapping 用单调 token 区分 owner，closed receiver 回收和独立表容量上限避免异常任务遗留或旧完成事件删除替代实例。HTTPS backend 使用本机显式提供的 SNI/CA，在固定 SocketAddr 上做真实 rustls 校验；不能静默降级为 HTTP。

HTTP/HTTPS 的 Caddy 运行时与本机 host 产品接线现已合入：私有回环/Unix Admin 管理独占动态 route 与证书 subject，保留流式 body 和 WebSocket；撤回须保留 owner 直到真实 route 404 和证书撤回。Core/IPC/桌面的本机批准、启动取消及停止持有真实 worker，单次 preview 绑定精确 runtime、snapshot、账号、服务代次和目标 TLS 摘要。本机 Stopped 仅证明本机资源已清理，远端撤回另有独立回执。两端真实 Caddy 2.11.7 合同与本轮 Rust Admin install/PATCH/GET/DELETE 进程回归通过，但未覆盖公网 DNS/ACME。部署范围见 [Web 服务部署](SERVICE-WEB-DEPLOYMENT.md)。

Windows/Linux all-target strict Clippy attempt04 均通过；加入 schema 迁移后的六个受影响 crate strict Clippy attempt03 也通过。运行 attempt02 的完整批次已结束：两端 SDK 27/27、transport-quic 9/9、配置/恢复 24/24、daemon、app-ipc 和桌面通过，Node/Storage 的 query 构造超过共享 1 秒上限与 Windows 单项 IPC 视频夹具失败均保留。query 现在使用 `min(SERVICE_RESOURCE_MS, NODE_RESOURCE_TTL_MS)`，共享 validator 保持原约束；attempt03 两端相关 library 29/29 与真实 HTTP→Node→QUIC→TCP 发布均通过。Windows IPC 视频夹具改为并发驱动实际 TLS 两端，单项复验通过。双平台每组的源码稳定、临时目录回收与时钟观察分别记录于 `artifacts/core-verification/services-publication-{windows,linux}-tests-20261015-attempt03.json`，原批次失败不能改写为整批成功。最新 service-web-host-schema 十组批次各九组通过；Core 新增测试漏配本机策略导致超时，补齐真实策略后两端 services 4/4 通过，默认拒绝策略未放宽。server/Core 两端 strict 与真实 Rust Caddy Admin 进程检查通过，详见 [集中记录](SERVICE-HOST-PRODUCER-CHECKS-2026-10-15.md)。持久累计计量现已合入，后续整合检查结果另行记录。安装维护及新安装代次代码已合入，签名安装/升级/回滚/卸载仍待验证；见 [安装状态](NATIVE-PACKAGING.md)。

正式验收仍需冻结同一提交及产物，运行已安装 Windows/Ubuntu 客户端、跨节点/真实跨网、资源与容量/长期稳定性、真实本机批准、授权撤销和升级卸载测试。签名证书与 ARM64 真机/公司及手机流量测试环境按用户确认尚未配置。GitHub 最终仓库切换与 Release 以全部实现、验收及旧历史保全完成为前提，当前尚未执行。
