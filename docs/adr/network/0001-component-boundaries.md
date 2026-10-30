# ADR 0001：复用边界、独立网络行为与首个切片

状态：首个切片建议已形成；新增组件等待各自 Actions 原型，未将候选列为已验证运行依赖。
日期：2026-10-30（Asia/Shanghai）。关联：W01、W02；R01、R02；AC02、AC03。

## 背景

现有 NestLink 已有安装身份、分用途签名、SessionPermit/ServiceLease、同 socket STUN、Quinn/TLS/WSS、WebRTC/TURN、恢复、通用服务流及配额、媒体、安装发行工具。
EasyTier 的正式和开发版本仅用于机制研究。研究源、审阅范围、摘要与许可见 source-manifest；九主题独立行为和反例见 mechanisms/README.md。
不把运行依赖、复制上游代码或自写通用协议当作“自主网络内核”。

## 决策与替代方案

| 决策 | 方案 A | 方案 B 与选择理由 | 影响接口与失败条件 |
| --- | --- | --- | --- |
| 内核 owner | 新增第二套网络调度器 | 扩展 connectivity 并适配真实 SDK legacy；减少并行 owner 和相互重试 | HostAdapter 与连接生命周期；不能安全接管则先保留真实 legacy，不能启用双 owner |
| 安全承载 | 自写加密/可靠数据层或终止业务的 relay | 现有 Quinn/rustls、RelaySocket 与 transport-* 薄适配；保留端到端设备身份 | 外层头另行认证，包长/分片/资源约束须 W07 证明；TLS/身份错不降级 |
| 双向穿透 | 扩展自写 ICE 替代品 | 优先现有固定 webrtc-ice/STUN 能力并增加同 socket 适配；不重写角色/consent 协议 | W09 必须证明 Quinn 数据报 owner 唯一、实际端口不变；无法做到则评估成熟替代及接口，不虚报成功 |
| 路由算法 | 自写最短路径与通用图容器 | Cargo.lock 中已有 petgraph，显式添加所需直接依赖时由 Actions 更新锁并验证 | NestLink 自定签名通告与授权过滤，图算法不授予权限；防环/hop/期限有界 |
| 身份与许可 | 网络共享秘密即所有业务权限 | 现有 Ed25519/安装身份与五组独立权利取交集 | 网络域与 v15 对象分离，未知关键字段/错空间/旧 epoch 拒绝 |
| 无 TUN 服务 | 自写 SOCKS/TCP/IP 栈 | 通用服务转发 + 维护中的 SOCKS/网络栈组件，首选候选见 components | 回环本机边界、固定获准目标、空 UDP、半关闭与取消须实测；不能成为任意出口 |
| TUN、子网与包 ACL | 自写驱动、分片解析和 TCP/IP 栈 | 维护中的 tun provider、IP/包解析、smoltcp，NestLink 管 owner、授权与路由政策 | 驱动许可/分发和最小权限必须核验；源 IP/前缀绑定、分片和 IPv6 ACL 不能绕过 |
| WireGuard | 从 EasyTier 移植 portal 或自写协议 | Linux 标准 WireGuard 实现；必要的 userspace 候选独立审查；客户端公钥分别绑定授权 | 每客户端独立 key/ACL/地址/到期；仅源 IP 不足；真实 Android/iOS 证据不能省略 |
| 浏览器 | EasyTier browser WASM/JSPI | 保留普通浏览器 WebRTC 与服务隔离 origin 的 HTTP 网关 | 浏览器不具备通用 TUN/UDP；无后端能力不能显示可用按钮 |
| 管理与 HA | 新写通用 HTTP/LB 或把 Mesh 当固定公网入口 | 现有 Axum/Caddy 与成熟 LB；自主服务组/revision/租约/额度/撤销 | 需真实固定入口双 edge 四协议；无复制状态不承诺旧连接无损 |
| UI、存储与媒体 | 为统一风格另写全套基础设施 | 保留现有 egui/Leptos、SQLite、日志、系统媒体 API 及已锁定 codec | 新增产品入口与精确格式协商；GPU和高阶格式以真实输出资格为准 |

## 最小自研范围与缺口证据

新空间成员生命周期、五组许可交集、兼容 PathGrant 分组、授权拓扑和选路、设备/空间 IPAM 政策、资源 owner、离线完整授权链、服务入口组与共享额度属于 NestLink 产品差异。
仓库的现有 Scheduler 只在建连竞速中选首次成功路径；它不实现本规格空间/持续优化/有界多跳，故在同一 owner 扩展这些策略。现有 VerifiedPermit 提供业务许可，不能代替成员/转发/原始 IP 授权。
`node/service_plane/stream.rs` 已支持通用异步流、半关闭、撤销和计费，须复用；不能因为外层换传输而重写此内核或重置累计额度。
现有 `DiscoverySocket` 能同 socket STUN 分流，不等于完整双方 ICE；此实际缺口只需成熟 ICE 与资源/信令薄适配，尚无理由自写通用 ICE。
现有 `virtual_udp.rs` 已具备外层 QUIC 数据报的有界分片重组，是 W07 起点；不复制 EasyTier 包布局或实现。
这些是明确产品/接线缺口，不授权自研密码、驱动、TCP/IP、DNS、SOCKS、codec 或通用安装/日志框架。

## 迁移与失败处理

先由新接口运行 legacy 真实连接并记录行为，再按能力/空间灰度接入新网络契约。旧 v15 保持停止、重新证明和恢复语义；公开版本升级不隐含协议能力。
无法在既定 Quinn 版本安全保留连接时走已有应用快速恢复，不重放输入、剪贴板写入、过期音频或任意 TCP 请求。
数据库/系统配置迁移先保存可核验备份与归属；回滚遵守撤销/债务 fence，不能恢复权限或破坏其他 VPN。
组件不支持某环境时明确拒绝或选择仍获准路径；授权和 TLS 错误不是可绕过失败。

## 依赖冻结与验证

首个切片继承 Cargo.lock 中现有 Quinn 0.11.12、rustls 0.23.46、Tokio 1.53.3、Ed25519-dalek 2.2.0、WebRTC 0.14.0 等，保留已锁定安全补丁来源；不在工作区运行依赖解析。
组件登记中的新增版本只是截至研究日核对的非 yanked 候选，尚未批准为冻结依赖，也不代表符合全部功能或平台。新增依赖必须在 Actions 解析/构建/测试并保存 lock/provenance。
W07、W09、W14 的待测假设见 mechanisms；测试、格式、lint、原型和制品生成全部只在 GitHub 托管 runner 进行。
研究的文档手工审阅与后续 Actions/真机验收分别记录，不据此声称已实现、已验证或已发布 0.8.0RC。
