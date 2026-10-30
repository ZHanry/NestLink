# 0.8.0RC 网络重构基线

记录日期：2026-10-30（Asia/Shanghai）。本文件是 W00 的源码与历史构建审阅记录。它不表示 AC01 已重放，也不表示本次网络重构或原报告的现场验收通过。

## 源码、分支和执行边界

- 仓库：`https://github.com/ZHanry/NestLink`，持久 repository node ID 为 `R_kgDOVNHMvg`。
- 首次取得的 `main` 和 `origin/main`：`82f1c8dfb31bdf0872ea7430b5608e205c1cbb08`，与需求研究基线一致，没有需要继承的基线后新增提交。提交标题为 `test(desktop): exercise GPU bitrate bounds with valid H264 level`，提交日期为 2026-10-26。
- 首次克隆没有已跟踪文件的本地修改；新增的 `docs/network-rewrite/` 是本次接入的需求和审阅文件。原始三文件保留在仓库父目录，没有覆盖历史验收材料。
- 本地只有 `main`，远程只有 `main`；GitHub API 在本次审阅时返回 `protected: false`。没有待删除的其它分支。没有修改仓库保护规则或权限。
- 检查仓库及 `C:\`、`C:\Users`、用户目录、桌面和任务父目录的 `AGENTS.md`，未发现适用文件。
- 当前公开产品版本为 `0.7.0-rc.1`。目标显示名为用户要求的 `0.8.0RC`；实现时需要统一公开版本、打包版本和发布脚本的契约。协议 `NestLink/v15`、ALPN `nestlink/1`、API `/api/v3` 和数据库 application ID 不能仅因公开版本升级而暗改。
- 依赖锁 `Cargo.lock` 的基线 SHA-256：`38e567a70770df13298c470747e0ae6fa06e7b7b7220eaa22b5b39785a88923a`。
- R01/R02 从本次开始适用：复用现有实现和成熟组件；本地只进行源码阅读、检索、编辑、Git 和文档维护。未运行项目依赖安装、编译、格式化、lint、测试、代码生成或打包。新的工具执行和实验必须在 GitHub 托管 Actions runner 上完成。

## 必须继承的真实调用链

以下是对上述固定 SHA 的人工源码审阅。代码存在说明可复用的实现边界，不等同于所有平台上的业务验收。

| 能力 | 已有生产实现与调用链 | 重构须保留的边界与剩余范围 |
| --- | --- | --- |
| 网卡和 STUN 发现 | `crates/sdk/src/discovery.rs::gather` 读取真实 `if_addrs`，调用 `DiscoverySocket::probe`；`crates/transport-quic/src/discovery.rs` 实现 Quinn `AsyncUdpSocket`，在实际接收路径内分流 STUN 与 QUIC，校验受信服务器、事务和 network generation | relay-only 不探测；同 socket、单一读取 owner 和取消后事务清理必须继承。当前 STUN binding 不能冒充新增的双端 ICE 检查成功 |
| 多承载原生拨号 | `crates/sdk/src/native.rs::NativeEndpoint::dial_native_with_relays` → `dial_native_with_local_paths` → `race` → `nestlink_connectivity::Scheduler`；按候选实际连接 QUIC、direct TCP/TLS、WSS 或获准 node relay | 地址、本地身份、许可路径和 relay 来源先过滤；保留 32 候选、4 并发、12 秒总预算对照及独立 WSS 机会。当前首成功即返回，不是已实现持续选路 |
| 端点和业务证明 | `NativeConnection::authorize` 接入 remote 授权；`crates/session/src/lib.rs` 的 session binding 绑定设备、许可、路径和 `connection_generation`；`crates/remote/src/quic.rs::authorize` 在 mutual proof 前拒绝业务流和数据报 | 旧路径语义不得被透明迁移替换；入网、连接和远控通道权利不能合并。新 Space/PathGrant 类型需另行显式协商 |
| 原生恢复 | `crates/app-core/src/runtime/native_recovery.rs::retain_source` 只接受 `TransportLost/NetworkChanged` 且清理成功的源；`Actor::start_native_recovery` 检查当前 core generation、管理端身份、截止时间、退出及清理任务后进入 `recover_native_session` | 撤销、退出、到期、身份错误为终态。恢复不能创建新的批准或延长授权；新能力需在 W14 验证，不能以现有恢复声称任意连接无感迁移 |
| QUIC 数据报中继 | `crates/transport-quic/src/virtual_udp.rs::RelaySocket` 在外层 QUIC DATAGRAM 上承载内层包，使用既有 `relay_datagram` 封装、有界重组、窗口、年龄和有界接收队列 | 可作为 W07 审查与适配起点；不能据此认定新的认证路由头、多跳、完整 1200 字节 Initial、IPv6 1280 字节或 PMTU 目标已验证 |
| 通道优先级和媒体边界 | `crates/remote/src/quic.rs` 按通道建立可靠流，音频使用有期限的 DATAGRAM 分片；`queues` 和 `LeaseControl` 控制队列与终止 | 不合并成无界单流，不重放输入/音频/剪贴板。媒体高阶格式和 GPU 实际资格仍需独立证据 |
| 四协议服务发布 | `crates/sdk/src/services/publication.rs::start_service_host_cancellable` 验证本机 `LocalServiceTargetConsent`，获取并验证 issuer delegation 与 `ServiceLease`，建立 `LocalTargetOwner`/`ServicePublication` 后调用 `transport-quic::service::connect`；业务直接使用 `quinn::Connection`/streams | 保留精确本地目标、HTTPS 后端信任、租约、配额和撤销；W16 需收敛具体承载依赖，不重新写授权内核 |
| 通用服务流 | `crates/node/src/service_plane/stream.rs::forward_streams<A,B>` 使用 `AsyncRead + AsyncWrite`，每次 I/O 前检查 `ServiceFlowPermit`、额度和期限，EOF 仅关闭对向 write half，撤销取消两个方向 | 优先复用到统一适配；不丢失半关闭、背压、计费或撤销 |
| 公网 HTTP/HTTPS | `docs/refactor/SERVICE-WEB-DEPLOYMENT.md`、`apps/server/src/service_edge*`、`crates/node` 维持独立 Caddy、签名 namespace、精确 DNS/TLS/readiness 和固定目标控制 | 私有可达不能抵扣公网治理；本机 `Stopped` 不代表 Caddy 删除 ACK；新多 edge 全入口撤销必须另测 |
| 浏览器远控 | `apps/web/src/browser_peer.rs` 使用已验证许可、浏览器临时身份、受信 ICE 配置与 SDK 签名信令；已有路径模式、selected pair 验证、TURN 生命周期与 online/offline 重启判断；host 复用 `crates/sdk/src/webrtc_host` | 保留 WebRTC/ICE/TURN。管理 WSS 不是 TURN；浏览器没有通用 TUN/任意 TCP/UDP，W17 三浏览器现场矩阵不能由类型或 SDP 代替 |
| 实际物理网络绑定 | `crates/platform-network/src/path.rs::NetworkPathManager` 枚举网络接口并按路由策略绑定 UDP；native endpoint 保留网络绑定和 generation | TUN 接入时须防物理端点再次走入自身 TUN；系统路由/DNS 归属和异常清理需新增受管资源生命周期 |

## 历史结果与必须保留的缺口

`config/product-scope.json` 将原外部 Edge↔HL 的直连和桌面画面键鼠定向回归标为 `passed_targeted_regression_4407106`，而四协议 tunnel 和完整报告发布验收仍为 `pending`。该定向记录对应 `440710625ef7707d579525edb9614e0631cac7b1`，不能自动计入当前基线或新内核。

`docs/refactor/REMEDIATION-ACCEPTANCE.md` 保留 2026-10-22 `2d250ea` 原网络连接和本机被控弹窗失败，2026-10-23 基本直连/画面/键鼠回归，以及 2026-10-24/25 媒体接线和待验证边界。这些历史失败不能删除或改成通过。该文档 2026-10-25 的“上一源 Windows 软件视频正向测试仍失败”是当时状态；本次观察到最新基线 Rust 工作流成功，但没有将它解释为原报告媒体性能或现场结果已通过。

GitHub 实际状态与仓库历史文字有一处明确差异：远端已经在 **2026-10-26 15:37:44（Asia/Shanghai）** 发布公开 prerelease [`v0.7.0-rc.1`](https://github.com/ZHanry/NestLink/releases/tag/v0.7.0-rc.1)，而仓库验收文档仍有“未创建 RC 标签或 Release”及 pending 文字。该 Release 有 15 个附件，正文明确说明按维护者当次要求先公开 RC1、调整此前验收后发布的时间安排，并保留 19 项现场/签名验收 pending；同时公开 GPU 编码颜色契约、高阶媒体、批量对照与长稳缺口。因此这是历史发布说明与较早仓库门禁文字的差异，不能臆断为未授权发布，也不能仅凭 Release 存在推导全部验收或正式签名通过。两者同时保留，当前 0.8 工作建立新的同源证据。

本次未在目标设备上重放旧版远控和 HTTP/HTTPS/TCP/UDP，未下载运行基线候选，未核验其产品字节；因此 AC01 保持 `not_run`，W00 不应宣称 `verified_target`。本基线审阅和接口范围已可供 W01 研究及 W02 契约设计使用，旧产品业务重放仍保留为必须完成的独立验证。

## 当前平台范围和 0.8 新增范围

保留 `config/product-scope.json` 中 Windows 10 22H2/Windows 11 x64、当前稳定 Chrome/Edge/Firefox、Ubuntu 24.04 x64/ARM64 后端及 Actions 分发。Android、Linux 图形远控和 macOS 图形远控没有因此恢复。

0.8 需求新增 Linux 无图形组网/子网网关角色、设备绑定空间成员/邀请和五组独立授权、持续选路与有界多跳、IPAM/名称/split DNS、private/public/both 共享预算、无 TUN 代理、可选 Windows/Linux TUN、子网/重叠映射、标准 WireGuard 手机 portal、隔离 origin 的私有 Web 网关、多 edge 固定入口 HA、有限离线、受控广播/真实 LAN 游戏，以及统一配置/诊断/安装生命周期。它们均是必交付开发范围；“可选”只表示用户是否启用。

范围变化应写入新的版本化范围文件并关联 F01–F26/W00–W40/AC01–AC70，保留既有产品范围及验收的历史意义。不能通过修改历史 pending 或退休平台记录来缩减本次要求。

## Actions 入口和已观察结果

本次通过 GitHub REST API 读取工作流、job 和制品元数据。可复核快照见 [`evidence/baseline-github-2026-10-30.json`](evidence/baseline-github-2026-10-30.json)。这是 `document_review` 执行来源；下表是旧 SHA 的 `build_provenance`，不是本地执行或本次新内核测试。

| 入口 | 触发与现有 runner | 固定基线观察结果 |
| --- | --- | --- |
| `rust-core.yml` | `main` push（paths）、PR（paths）、dispatch；Ubuntu 24.04 x64、Windows 2022 x64；另有 Ubuntu wasm、依赖审计、OpenAPI 和 Linux 平台实验 | [`40275811496`, attempt 1](https://github.com/ZHanry/NestLink/actions/runs/40275811496) success；Linux core job `121418201112`、Windows core job `121418201438` 均 success，API runner group 为 `GitHub Actions` |
| `web-build.yml` | paths push/PR/dispatch；Ubuntu 24.04；Rust 1.96.0、Trunk 0.21.14、wasm-bindgen 0.2.129、Binaryen 133 | [`40275892708`, attempt 1](https://github.com/ZHanry/NestLink/actions/runs/40275892708) success；另有标签 push run `40286955833` success |
| `codeql.yml` | main push、面向 main 的 PR、merge group、dispatch；Ubuntu latest，Python 和 JS/TS 无构建扫描 | [`40275811636`, attempt 1](https://github.com/ZHanry/NestLink/actions/runs/40275811636) success；这不是 Rust 安全分析或新协议审查的替代 |
| `secret-scan.yml` | main push、面向 main 的 PR、merge group、dispatch；Ubuntu latest | [`40275811526`, attempt 1](https://github.com/ZHanry/NestLink/actions/runs/40275811526) success |
| `regression-server.yml` | main/`release/**` paths push 或 dispatch；Ubuntu 24.04 ARM64 原生 runner | [`40275899404`, attempt 1](https://github.com/ZHanry/NestLink/actions/runs/40275899404) success；仅回归服务镜像，不能代替完整发行或网络现场结果 |
| `v15-candidate-build.yml` | 手动 dispatch，精确 40 位 source、序号和固定 Ubuntu OCI index；Windows 2022 x64、Ubuntu 24.04 x64/ARM64、Web/metadata/OCI/freeze | [`40280815318`, attempt 1](https://github.com/ZHanry/NestLink/actions/runs/40280815318) success；先要求同源 Rust/Web/secret/CodeQL 成功，生成候选，不自行发布 |
| `public-tunnel-acceptance.yml` | 手动 dispatch，Ubuntu 24.04，仅运行获准的外部 visitor；依赖现场 owned helper | 现有入口可复用到公网验收，但没有本次重放记录，不据此认定四协议或 HA 通过 |
| `dependency-lock-refresh.yml` | 手动 dispatch，固定 main source/dependency commit，Ubuntu 24.04；依赖推导 patch/receipt 制品 | 当前实现专用于既有 DTLS 修复并含“尚未补丁”断言，不能直接用于任意新增依赖；W02 需扩展或增加严格限定的依赖推导入口 |

基线候选合并制品 ID 为 `12632229166`，名称 `rc-development-candidate-1`，API 记录 zip 长度 `164277045`，digest 为 `sha256:2edd239022d9339f1cfc1c384c5813f3e6ebb7fcdfec342480725a8744041071`，观察时未过期。这里只核对 API 元数据，尚未下载字节或检验内部候选清单；产品文件摘要必须从核验后的清单取得，不能把 Actions zip digest 当作其中每个产品摘要。

现有 workflows 使用固定 Action 提交和 GitHub 托管 runner；没有使用用户电脑或部署服务器作为 self-hosted runner。能读取历史成功不保证本次额度、权限、特定网络命名空间或目标硬件可用，新 run 必须实际观察。

## W03 就绪建议与发布约束

1. 先复用既有 `rust-core`、Web、源码 readback、依赖审计及制品 receipt，补齐 `docs/network-rewrite/**`、新增网络配置、`tests/network/**`、`tests/security/**` 与网络脚本的触发路径。现有 `crates/**` 已涵盖新增 crate，不能重复造一套无人消费的验证体系。
2. 为迭代分支/最终 main 提供可触发的针对性网络工作流，在 GitHub 上输出格式补丁、L0/L1 和真实多进程 socket L2 记录；格式失败保留失败并提供 patch，不先在本地运行 formatter。
3. 原型优先证实 W07 包长与认证封装、W09 同 socket、W14 Quinn/虚拟 UDP 迁移或安全恢复；使用成熟 `ip netns`/`tc netem` 等隔离及损伤工具。不得用固定成功、UDP echo 或 loopback 结果关闭这些生产业务用例。
4. 每次结果绑定源码 SHA、workflow/job/run/attempt、runner、依赖锁、制品 SHA-256 和配置/拓扑。现场运行单列 `execution_provenance`；GitHub 构建的手机/GPU/公网工具不表示这些现场项目已经执行。
5. 按 `docs/refactor/REMEDIATION-ACCEPTANCE.md` 保留原 15 工作包和 10 体验门槛、原网络 100/99 次、UU 分层 200 次/2 个百分点、首帧 p95 3 秒、58fps/p95 25ms、输入对照、弱网/文件并发、恢复 p95 5 秒和多轮跨日单次 24 小时长稳。新增目标不能降低它们。
6. 复用现有候选/发布验证逻辑，包括精确源清单、全角色同源制品、许可证/SBOM、签名真实披露、候选不进入生产更新通道、上传前后摘要和远端 asset ID 回读。0.8 版本调整须更新脚本的版本契约，不能删除验收检查绕过门禁。
7. 用户已明确授权发布 0.8.0RC 和最后只留 main；实现仍须满足当前有效的事实与发布门禁。未完成必交付或未取得必需真实证据时，继续产出候选和缺口，不能填写 `released` 或宣布全量完成。

本记录的验证状态为人工源码/历史构建审阅完成、AC01 业务重放待执行。没有对 W00/AC01 或其它任务的 JSON 状态做成功变更。
