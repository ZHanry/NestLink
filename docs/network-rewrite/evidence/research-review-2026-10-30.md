# W01 独立文档审阅

日期：2026-10-30（Asia/Shanghai）。审阅者：Codex baseline_ci，独立于研究材料作者。

结论：本次审阅范围内，W01 的研究材料具备进入 W02 首个切片契约冻结所需的依据。W02 可按现有 `Cargo.lock` 复用方案推进，并须把未证明的承载、ICE 和迁移能力保留为明确门槛。本结论只评价研究文档的完整性、来源和决策边界，不代表实现、Actions、真机验收或发布门槛已经通过。

## 证据类型与范围

- `execution_provenance.environment`: `document_review`
- `build_provenance`: `null`
- `automated_project_validation_executed`: `false`
- `ci_run`: `null`；`device_execution`: `null`
- 方法：人工阅读四份材料，抽读现有锁文件及依赖补丁清单，阅读缓存的上游源码摘录，并通过官方 GitHub REST API 独立核对正式 tag 和三个文件的提交、路径、Git blob 对应关系。
- 未在本地安装项目依赖或执行项目脚本、格式、lint、编译、测试、原型及打包。本审阅没有 L1/L2/L3/L4、真实 NAT、GPU、移动设备、持续运行或 AC04 的执行结果。

审阅输入及当时文件字节的 SHA-256：

| 文件 | SHA-256 |
| --- | --- |
| `docs/network-rewrite/mechanisms/README.md` | `20a8104ef093079091ce52a16447b1a1c8ed4903e30ee48371fd7760d361c468` |
| `docs/network-rewrite/source-manifest.json` | `18a534fdc78170b4669ba03448bf92544259d384b85f4d944fb2149682b04192` |
| `docs/network-rewrite/components.json` | `e6018a96a14a8fe25ecc75353dce25c276ce02adb1283958a7571042a906848c` |
| `docs/adr/network/0001-component-boundaries.md` | `8aaadb4b52430275a2e37639ec17a0eb76bc6230ddfb23220620e5b0d016d39f` |

后续文档修订或换行转换可能改变这些字节摘要；本记录不自动覆盖后续版本。

## 九主题与七项内容

人工逐节核对：每个主题均包含用户问题、输入输出、状态与资源、成功过程、失败过程、取舍、NestLink 行为用例七项内容。每节的取舍均列出至少 A、B 两种方案及选择理由；行为用例同时包含成功和拒绝/清理情形。

| 主题 | 七项内容 | 取舍与关键边界 |
| --- | --- | --- |
| 发现与入网 | 完整 | 共享名称/秘密与设备绑定凭据比较；候选和目录不授予业务权限 |
| NAT 与 socket 生命周期 | 完整 | 自写打洞与成熟 ICE/STUN 薄适配比较；同 socket、唯一 reader、预算和取消明确 |
| 拓扑与路由 | 完整 | 静态 relay 与签名通告/成熟图算法比较；权限过滤、期限、防环与滞回明确 |
| 中继与空间隔离 | 完整 | 逐跳终止业务 TLS 与端到端 QUIC 比较；外层认证、资源上限及 direct_only 边界明确 |
| 身份、凭据与撤销 | 完整 | 单一入网标记与分层许可比较；网络、转发、业务及原始 IP 权利不能互换 |
| 用户态网关、子网与 WireGuard | 完整 | 自写通用协议/驱动与现有转发及成熟组件比较；独立客户端 key、源地址绑定、ACL 与恢复明确 |
| 管理、诊断与配置事务 | 完整 | 全局异步写入与 revision/事务/资源台账比较；保存意图与真实 readiness 分离 |
| 可移植内核与唯一资源 owner | 完整 | 第二调度器与扩展 connectivity 比较；真实 legacy 对照、任务回收和失败状态明确 |
| 浏览器边界 | 完整 | 开发版 EasyTier WASM 与现有 WebRTC/受限 HTTP 网关比较；普通浏览器权限边界明确 |

各主题还给出对应 W/AC，能够将设计用例交给后续实现和验收；这些映射不构成相应 AC 已通过的证据。

## 来源、版本与许可抽核

官方 API 返回 `refs/tags/v2.6.4` 直接指向提交 `8428a89d2dabc94c97d370ec607c6ca142473626`。研究材料把开发来源固定为 `c66076b8f3ec16e3fff20b0df920ebda1652e04c`，没有把开发版浏览器能力归入正式版。

下列提交/路径通过官方 contents API 核对；同时读取对应缓存内容或摘录，文件 SHA-256 与 source-manifest 相符：

| 来源与路径 | Git blob | 人工抽读结论 |
| --- | --- | --- |
| 正式提交的 `easytier/src/connector/udp_hole_punch/common.rs` | `e82b0663491ddac33b345361b253dba9364ff4fa` | 含 NAT/角色、socket 数组及监听资源；上游随机端口集合不成为 NestLink 未认证扫描策略 |
| 开发提交的 `easytier-core/src/connectivity/hole_punch/udp/binding.rs` | `e14713fad17dbe3ebd912e975ca93d9e31b1060e` | 已读开头的组合接口与 STUN/映射策略段；支持 socket、mapper、lease、sink 的边界观察，未审完整文件 |
| 开发提交的 `easytier-js/browser/README.md` | `f1264e657fa9c9fa576de77bca39ce37632e510f` | 全文明确 ws/wss、overlay IPv4 TCP、JSPI；无 native listener、TUN、STUN 或打洞 |

复核入口：官方仓库 `https://api.github.com/repos/EasyTier/EasyTier/git/ref/tags/v2.6.4`，以及以上路径的 `contents/<path>?ref=<commit>`。source-manifest 保存更完整的官方 URL、文件摘要和各文件实际审阅范围。

材料明确 EasyTier 为机制参考、LGPL-3.0，不选作运行依赖，也不声明复制、翻译或改名其实现；`strict_clean_room_claim=false` 与研究者/实现者共享上下文的事实一致。本次抽读支持这些设计边界，不构成全仓库代码相似性扫描、上游安全审计或法律结论。

手工核对 `Cargo.lock` 的实际版本为 Quinn 0.11.12、rustls 0.23.46、Tokio 1.53.3、ed25519-dalek 2.2.0、WebRTC 0.14.0、petgraph 0.8.3 和 ipnet 2.12.2。`webrtc-ice 0.14.0` 的实际来源与 `config/dependency-forks.json` 一致，固定在 NestLink-dependencies 提交 `c4cf95eda3c244eff429c73b0d933ff2f18745b4`；研究没有把候选 0.17.2 当成现有运行版本。

## W02 可推进范围与后续缺口

ADR 和组件登记符合 R01 的复用顺序：安装身份、分用途签名、现有 connectivity/SDK 生命周期、Quinn/rustls、通用服务流、SQLite、WebRTC、媒体及发行工具是起点。网络域 `NestLink/network/v1/<purpose>` 与 v15 兼容对象分开；新增网络许可不替代 SessionPermit/ServiceLease。独立网络策略扩展同一 owner，避免平行调度器。成熟协议实现只增加产品所需薄适配。

W02 可以冻结首个切片的身份/权限类型、HostAdapter、连接/流/数据报/事件/关闭/配置接口，以及 legacy 实际接入契约。下列内容仍须在对应实现前完成，不能由本审阅消除：

1. W07 必须在 Actions 证明真实承载上的外层认证、包长/MTU、有界分片及完整 QUIC Initial/IPv6；现有 virtual UDP 是复用起点。
2. W09 必须证明固定 ICE 版本与 Quinn 的同 socket 集成、唯一 reader、角色/consent/取消；现有同 socket STUN 不能代替完整双方 ICE。
3. W14 必须证明固定 Quinn 版本虚拟 UDP 上的连接保持、RTT/拥塞/PMTU 和迁移收敛；证明前只承诺已有应用恢复语义。
4. 新增的 etherparse、tun-rs、smoltcp、SOCKS、DNS、DNS-SD、WireGuard 等均为候选。各 W 在采用前须冻结实际版本/特性/平台/许可与分发资产，并在 Actions 留存 lock 和原型证据；petgraph/ipnet 已为传递依赖仍需直接接入审查。ICE mDNS 不等同完整 DNS-SD。
5. Wintun/驱动的分发、签名及许可，WireGuard 包和客户端资格，Caddy/LB 固定镜像/二进制，网络工具的实际 runner/权限/版本，均尚需各工作包补齐。它们不阻止当前仅复用锁定依赖的契约切片。
6. 真 NAT、多 relay 固定入口、手机、GPU/格式、安装恢复、长稳和继承的性能/24h/UU 门槛，仍要相应执行证据；版本号、文档审阅或旧版本 CI 不足以批准 0.8.0RC 发布。

综上，未发现阻止 W02 以所述受限首个切片推进的研究材料缺项。所有新增能力的实现与资格结论仍由后续证据决定。
