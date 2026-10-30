# 网络机制研究与独立行为规范

研究日期：2026-10-30（Asia/Shanghai）。NestLink 基线：`82f1c8dfb31bdf0872ea7430b5608e205c1cbb08`。
正式来源：EasyTier v2.6.4，`8428a89d2dabc94c97d370ec607c6ca142473626`；开发来源：`c66076b8f3ec16e3fff20b0df920ebda1652e04c`。
已通过 GitHub Git 对象 API 核对两个提交及正式 tag，实际审阅文件、范围、Git blob 和 SHA-256 见 `../source-manifest.json`。

本研究提取行为问题，随后独立定义 NestLink 的输入、权限、状态和反例；未移植、翻译或改名上游实现及测试。
研究者和开发者共享上下文，因此不作 clean-room 声明。EasyTier 根许可证是 LGPL-3.0，未成为运行依赖。
源码审阅不等于上游完整安全审计，也不证明候选组件能满足 NestLink 的约束。
下列用例是尚待实现并在 Actions/目标设备执行的验收设计，不是已经通过的结果。

## 1. 发现与入网（W04、W08、W18；AC05、AC12、AC29）

**用户问题。** 用户希望找到同一空间的 NAS 或电脑，使用多个 bootstrap 时不能重复加入或扩大权限；名称相同的设备不应互相冒充。

**输入输出。** 输入是本机安装公钥、空间成员凭据、明确配置的 bootstrap、系统接口事实及带来源/期限的目录项。
输出是经过权限过滤、绑定网络代次的候选集合和入网结果；候选不是连接授权。PeerId 来自设备公钥摘要，SpaceId 是隔离边界，显示名只用于展示。

**状态与资源。** 唯一 Peer owner 保存 `SpaceId/PeerId/identity_epoch`，候选 owner 保存接口、socket 标识、来源、观察时间、过期时间和 `network_generation`。
缓存按空间和身份分区且有容量、TTL；入网请求有 request ID、绝对截止时间及取消。邀请消费必须在存储事务中一次性完成。

**成功过程。** 管理员批准设备加入，端点独立核验签名成员关系；合并去重 bootstrap、接口、受信 STUN 与目录候选；先过滤再调度；成功后再次进行端点身份和具体业务许可校验。

**失败过程。** 撤销、过期、旧代次回复、重复邀请、私网范围未批准、危险地址和跨空间目录查询均拒绝；网络变化先失效旧候选再探测；bootstrap 离线显示有期限的缓存事实，不把缓存变成信任锚。

**取舍。** A：统一网络名称/共享密码入网，配置短但设备撤销和业务权限难以细分。B：设备绑定短期成员凭据与现有具体业务许可分离，控制面较复杂但可以按设备撤销。选择 B，复用现有安装身份、签名和 SQLite 事务。
正式版 `connector/mod.rs` 表明连接来源还需考虑接口族和受管地址回环；`common/config.rs` 有网络 identity/credential 模式，不能照搬为 NestLink 业务权限模型。

**NestLink 行为用例。** 两个 bootstrap 返回同一候选只拨号一次；成员甲复制成员乙的证书仍不能握手；同名新公钥不继承权限；旧代次 STUN 在新网络回复不入队；成员可以看见获准目录但不能由此打开未授权端口。

## 2. NAT 与 socket 生命周期（W07、W09、W10；AC11、AC13—AC16）

**用户问题。** 双方位于不同 NAT 时需要协作建立真实远控/服务连接；一次探测成功并不代表另一个端口能承载业务。

**输入输出。** 输入是双方认证身份、用途、PathGrant、候选代次、角色/事务、候选端口及总预算。
输出是经过认证检查的候选对、同一 socket/数据报接口的可用承载和失败阶段。NAT 分类仅为诊断事实。

**状态与资源。** 一个接收 owner 对 STUN/ICE 与 QUIC 分流；事务、候选检查、读任务、映射租约和 consent 都有界。网络变化使旧事务失效；取消等待实际任务/socket 退出。
复用现有 `DiscoverySocket` 的同 socket 观察和 GRO 分流，评估仓库固定的 webrtc-ice 能否交付 Quinn 所需的数据报接口；不能额外创建抢包读取者。

**成功过程。** 先获准候选过滤，双方通过成熟 ICE/STUN 引擎协同检查、处理角色冲突并选择候选；同一数据报 owner 继续承载实际 QUIC Initial、流及 DATAGRAM；保留独立 WSS 回退预算；显式启用的映射租约跟随 owner 清理。

**失败过程。** 假事务、未认证地址、黑洞、单向可达、过期 consent 和取消不能报告成功；先进 NAT 策略失败保留合法 relay；禁止对未认证公网地址随机扫描；socket A 成功后 socket B 通信不计验收。
内层合法 1200 字节 QUIC Initial、IPv6 完整 1280 字节都必须通过真实承载，必要时使用认证有界分片，不能拿小包 echo 抵扣。

**取舍。** A：扩展自写打洞协议，维护角色、重试、consent 与协议安全成本高。B：成熟 ICE/STUN + NestLink 授权/同 socket 薄适配，优先 B。
正式 `udp_hole_punch/common.rs` 能看到 socket 数组、监听器复用与清理；开发 `.../udp/binding.rs` 把 STUN mapper、socket factory、映射 lease 和 transport sink 分开。这里只提取资源边界，不采用上游实现，也不宣称当前 webrtc-ice 已支持所需 Quinn 集成。

**NestLink 行为用例。** 双方角色冲突可确定收敛；记录打洞与 QUIC 的相同本地端口及 socket owner；UDP 全黑洞仍能在总预算内启动获准 WSS；取消后无读任务；映射拒绝时显示原因且不删除他人映射；超预算停止探测。

## 3. 拓扑与路由（W11—W14；AC18—AC22）

**用户问题。** 直连暂不可用时希望经获准节点访问，活动 relay 故障后应能恢复，但不能抖动切路或接受伪造子网。

**输入输出。** 输入是签名空间通告、签发权限、`boot_incarnation/sequence/expiry`、有效 PathGrant、可导出前缀及本机测量。
输出是合法 `PeerRoute`、相邻 `CarrierPath`、下一跳/relay 列表、原因和测量新鲜度。未知 RTT 用缺失值，不能填零。

**状态与资源。** 每空间一个有界拓扑图与撤销水位；每活跃组一个主路径和至多一个热备；低频有界探测其他候选。
缓存通告必须受 TTL、大小和速率限制；拓扑重算不授予权限。会话代次、网络代次、path epoch 各自单调。

**成功过程。** 先验证成员和通告发布权，再更新图；用成熟图算法求满足 hop/费用/配额条件的路线；按用途选择，性能改善持续满足滞回后协商切换，故障切换可立即走健康合法备用。
新承载完成身份和迁移控制确认后才开放业务；正常旧路只在有限合法宽限内排空，撤销优先。

**失败过程。** 旧 incarnation/sequence、过期、未知前缀、默认路由、环路、过多跳数及泛洪拒绝；分区后不继续传播陈旧授权；无合法路线明确失败。Quinn 连接保持能力未经 W14 原型证实前只能承诺已有应用恢复语义。

**取舍。** A：静态 relay 列表易落地但不足以满足有界多跳与重算。B：签名增量通告 + petgraph + NestLink 策略，可审阅授权和拓扑收敛，选择 B；第一阶段先一跳主备，再增加多跳。
正式 `peer_ospf_route.rs` 使用 petgraph Dijkstra、版本、前缀和过期管理，证明可复用成熟图算法的方向，不复制其通告或选路实现；NestLink 自定签名格式和撤销语义。

**NestLink 行为用例。** 四节点授权链可运行真实业务；撤销中间节点后图与数据面同时拒绝；direct_only 远控与允许 relay 的文件分组，后一组切换不改变前者；突发延迟不反复切路；过期测量显示未知；丢失迁移确认重发幂等且超时清理。

## 4. 中继与空间隔离（W06、W07、W11；AC08—AC11、AC17）

**用户问题。** 自建中继应帮助连通，同时不获得屏幕、文件、输入等业务明文，也不能成为任意地址反射器。

**输入输出。** 输入是已认证邻接、精确 TransitGrant、SpaceId、目标 Peer、transport group、route ID、hop limit、期限与额度；输出是只能发往授权下一跳的不透明数据报及传输事实。

**状态与资源。** relay 按授权传输组维护有界队列、并发、字节/包计数及路由代次；端点持有端到端 Quinn/rustls 身份。
外层安全通道认证路由头与转发许可，内层 QUIC 身份认证具体端点。传输复用必须具有相同空间、peer pair 及兼容 PathGrant。

**成功过程。** 邻接认证后验证外层准入，relay 仅转发不透明内层包；最终端点重新核验业务许可；端点加密前执行媒体 QoS，relay 只按组调度。

**失败过程。** 头部改动、错误空间/组/目标、超 hop、旧代次、无许可下一跳、超额度和未注册 relay 拒绝；中继故障不会自动放宽 direct_only；fragment 数量、寿命、总内存有硬上限。

**取舍。** A：每一跳终止业务 TLS，易代理但扩大明文边界。B：现有虚拟 UDP 适配 + 端到端 QUIC，选择 B，并为 TLS/WSS 回退保留包界与背压。
正式 `foreign_network_manager.rs` 将外部网络转发、relay_data 配置及计数分开，`packet_def.rs` 有转发信息；这不等同于 NestLink 所需签名外层头，必须独立冻结认证绑定。

**NestLink 行为用例。** relay 捕获的载荷不能解析业务内容；修改外层 SpaceId/目标导致拒绝；允许 relay 文件与 direct_only 远控不复用不兼容连接；慢消费者触发界限并能取消；relay 不按内层视频帧选择性丢弃加密包。

## 5. 身份、凭据与撤销（W04、W18、W27；AC05、AC06、AC30、AC45、AC46）

**用户问题。** 加入空间、管理成员、使用远控、转发和访问原始 IP 是不同权利；重装、换钥、备份回滚不能恢复旧许可。

**输入输出。** 输入是固定部署信任锚、安装公钥、成员签名、策略 epoch、各级授权及时间；输出是不同不可混用的已验证成员、网络连接和业务连接类型。

**状态与资源。** 沿用现有安装身份与 Ed25519 域隔离签名；成员、连接/路径、SessionPermit/ServiceLease、Transit/RouteExport、NetworkAccess 五组权利独立。
单调撤销水位持久化；凭据绑定空间、双方设备、公钥摘要、purpose、期限和策略 epoch。离线必须另有完整 OfflineGrantBundle 和预留额度，不能延长在线 relay lease。

**成功过程。** 每层依次验证并取交集，业务流仍校验原许可；新钥由旧有效身份或有权管理员确认；退出/撤销先进入不可复活终态再完成清理。

**失败过程。** 复制证书到其他公钥、错空间、旧 epoch、未确认换钥、到期、旧备份和权限缺项拒绝；owner/admin 不隐含本机输入权限；中心离线期间如实说明撤销传播窗口。

**取舍。** A：单一“已入网”布尔值简单但容易扩大到业务和 OS 端口。B：类型区分和逐层许可，选择 B，复用现有 `VerifiedPermit`、purpose domain 和 Session 生命周期。
正式 `common/config.rs` 和 `peer_manager.rs` 表明上游区分 network identity、secure mode 与 credential；这里只借鉴分层问题，未完整审计其授权系统，不能把网络名称相同解释成 NestLink 的业务放行。

**NestLink 行为用例。** 入网成功但缺 SessionPermit 不能读屏；允许 Transit 不允许本机服务；NetworkAccess 不能代替 ServiceLease；已撤销 session 在网络恢复、旧确认或数据库备份恢复后仍拒绝；离线缺任一授权链环节失败。

## 6. 用户态网关、子网与 WireGuard（W19—W25；AC31—AC42）

**用户问题。** 普通用户无需管理员/TUN 即可访问获准 NAS/SSH；完整私网和手机接入可选启用；两处同网段不能误连到另一站点。

**输入输出。** 输入为获准设备/服务/精确前缀、协议端口、方向、期限、额度和独立 WG 公钥；输出为回环映射、受限 SOCKS、受管地址/名称/路由、或精确 portal 客户端配置。

**状态与资源。** 复用节点通用异步流转发及累计配额；IPAM/名称按空间隔离；映射、DNS、TUN、路由、WG peer、连接跟踪、分片重组都有 owner 与有界状态。
TUN 注入 OS/LAN 前把认证 Peer 绑定获准源 IP/前缀，再执行 L3/L4 ACL；WG 客户端身份绑定已验证公钥而非自报源 IP。

**成功过程。** 无 TUN 默认回环映射到本机批准的固定目标；透明模式经最小权限代理安装受管资源；子网先显式批准再发布；手机各有独立 key/地址/ACL/到期，流量经 portal。
浏览器私有 HTTP 网关按服务隔离 origin，使用固定目标及现有 TLS/HTTP/WebSocket 组件。

**失败过程。** 未授权端口、任意互联网出口、默认路由劫持、SSRF、跨空间 DNS、源伪造、分片绕过、重叠映射歧义、旧 WG key 拒绝；崩溃/卸载清理本产品资源且保留其他 VPN。
网关故障时依赖 NAT 状态的旧 TCP/UDP 连接可能断开，不重放数据库请求。

**取舍。** A：重新写代理、TCP/IP 栈和驱动，成本高且违背 R01。B：复用现有转发内核，成熟 SOCKS、smoltcp、tun provider、DNS、IP/包解析与标准 WireGuard 实现，选择 B。
正式 `gateway/mod.rs` 有 CIDR 映射，`gateway/socks5.rs` 使用用户态栈，`vpn_portal/wireguard.rs` 有 portal 到 overlay 接线。其配置派生 key、首次源 IP 注册等观察不能满足 NestLink 每客户端独立公钥授权，不能直接移植。
Linux 首选标准 WireGuard 内核接口/工具、Windows/Linux TUN provider 和 userspace WG 候选分别做许可与故障原型；未冻结前不宣称已具备产品能力。

**NestLink 行为用例。** 普通 Windows 账号经回环访问获准 SSH，访问其他端口失败；两个 192.168.1.0/24 站点使用不同映射可同时访问；IPv4 分片/IPv6 扩展头不能绕过端口 ACL；WG 客户端伪造他人源地址失败；关机/退出恢复 DNS；私有 HTML 无法进入管理 origin。

## 7. 管理、诊断与配置事务（W26、W29、W30、W35；AC43、AC44、AC49—AC52、AC61）

**用户问题。** 用户需要知道配置保存后是否真正可用、为什么经过 relay、恢复是否成功，失败后仍能取到诊断。

**输入输出。** 输入是期望 revision、验证后的配置意图及运行事件；输出是已提交 revision、明确回滚/部分失败，以及分开的 allowed_route_policy 和 observed_route。

**状态与资源。** 配置 CAS 事务、原资源快照、受管资源台账；request/session/network/path 的关联 ID；有界脱敏事件环和有限保留日志；诊断不依赖业务连接在线。
多 edge 公网发布有入口组、namespace revision、独立准入和共享累计预算，固定公网入口健康与内部路径健康分别观测。

**成功过程。** 先验证配置与权限、计算差异，提交资源后确认 readiness；失败按台账回滚或准确报告残留；展示真实 socket/候选/relay/首帧/清理事实；导出脱敏配置摘要和同源证据。

**失败过程。** 端口冲突、驱动缺失、TLS 错误、未获本机批准、离线 edge 不能被“配置已保存”掩盖；未知指标保持 unknown；令牌、私钥、屏幕和文件内容不进入导出。
数据库回滚有撤销/债务 fence，不允许以旧备份恢复权限或重置用量。

**取舍。** A：直接写全局配置并异步等待成功，容易部分生效。B：沿用现有存储事务和工作台，增加 revision、意图/事实、owner 台账及明确回滚，选择 B。
正式 `rpc_service/config.rs` 将 get/patch 转交实例配置服务，仅能据此确定管理入口，不据此宣称上游具有 NestLink 所需全部事务保证。

**NestLink 行为用例。** 旧 revision 更新冲突；配置成功但目标未批准显示不可用；断链后仍可导出最近失败；导出没有秘密；双 edge 撤销检查两端、旧 edge 恢复和 Caddy 删除确认；公网固定入口四协议新连接按实测结果报告。

## 8. 可移植内核与唯一资源 owner（W05—W07、W34；AC07—AC11、AC36）

**用户问题。** Windows 和 Linux 需要相同权限与连接行为，系统操作失败不能产生幽灵任务或破坏其他 VPN。

**输入输出。** 策略输入是身份、权限、候选、单调时钟事实和状态事件；输出是受限 host 命令和可审计事件。
HostAdapter 提供 socket、接口/网络事件、时钟、随机、持久化及受管系统操作，纯策略不直接创建 socket 或改系统配置。

**状态与资源。** 扩展现有 connectivity 为唯一 Peer/Path/Route owner；SDK/daemon/AppCore 复用它，transport-* 实现承载适配。
每资源只一个 owner，任务保留 join handle，取消/截止时间传播到有界队列及 I/O。`close_and_wait` 只有实际回收后才成功。

**成功过程。** 先通过新接口包装真实 legacy 连接作为行为对照，再接入自主路由；独立承载和系统适配注入相同策略；退出停止新流、释放输入、清敏感缓存、关闭 owner 并等待任务。

**失败过程。** 第二调度器、取消后抢读、关闭超时、未知能力静默开启拒绝；系统部分失败保留恢复台账，不能报告“已清理”。协议错误和认证失败不触发扩大权限的降级。

**取舍。** A：新增平行 network-core 并保留现调度器，各自重试和抢 owner，迁移风险高。B：扩展 connectivity 并逐步收敛现有 SDK，选择 B。
正式 `tunnel/mod.rs` 有通用包流抽象；开发 `.../udp/binding.rs` 显式使用 host/socket/STUN/sink 接口，说明可移植边界方向。NestLink 自定更严格的 owner、权限类型及关闭契约。

**NestLink 行为用例。** legacy 路径在新接口仍实际传输；同一个 socket 不存在两个 reader；关闭途中阻塞写仍可取消；超时状态明确且不得伪报清理完成；Windows/Linux 升级只移除本产品路由。

## 9. 浏览器边界（W17、W25；AC27、AC28、AC41、AC42）

**用户问题。** 用户希望普通浏览器访问远控和私有网页；界面不能提供浏览器做不到的任意 TCP/UDP/TUN 功能。

**输入输出。** 输入是验证后的业务许可、浏览器端身份、受信 STUN/TURN 配置和服务授权；输出是 WebRTC 选中的 candidate pair/恢复状态或固定服务 HTTP 网关入口。

**状态与资源。** 保留 BrowserPeer、WebRTC peer connection、ICE 代次、TURN 短凭据、媒体/数据通道及 origin 隔离。关闭、登出和撤销都终止相关媒体及网关流。

**成功过程。** 浏览器和原生宿主使用现有 WebRTC/ICE/TURN；网络变化按真实连接事实做 ICE restart，记录所选 pair；非 HTTP 服务明确交接本机映射或标准客户端。私有网页使用独立 HTTPS origin 和固定目标，不与管理页面共 origin。

**失败过程。** 管理 WSS 不能被标成 TURN；过期 TURN、无合法候选、ICE restart 失败准确停止或恢复；SSRF、重定向出界、跨服务 cookie、Host/Origin 欺骗和撤销后继续使用拒绝。

**取舍。** A：嵌入 EasyTier 开发浏览器 WASM，依赖 JSPI、仅 ws/wss + IPv4 TCP，也引入被禁止的 EasyTier 运行内核。B：现有标准 WebRTC 和受限 HTTP 网关，选择 B。
开发 README 明确无 native listeners、TUN、STUN、hole punching，不能把其示例 `connectTcp` 当作普通网页获得系统 TCP socket，更不能写成正式 v2.6.4 已提供。

**NestLink 行为用例。** 当前 Chrome/Edge/Firefox 直连和 TURN 各跑真实画面/键鼠；ICE restart 后旧代次消息不能恢复旧权限；STUN 项不被 TURN 更新误清空；SSH 入口显示本机客户端前置而不伪装网页直连。

## 首个切片冻结与尚待证明的假设

首个切片只复用仓库锁定依赖（实际 Cargo.lock 版本优先于 Cargo.toml 的范围），不引入 EasyTier 源码或运行库。网络签名对象另设 `NestLink/network/v1/<purpose>` 域，保持 v15 兼容对象原语义。
建议 W02 固定 `connect_peer/open_stream/send_datagram/subscribe_path_events/close_and_wait/apply_config`，网络认证类型与业务授权类型分离；transport group 至少绑定空间、规范化双方身份和兼容 PathGrant 摘要。
路径迁移固定 ProposalId、session generation、path epoch、挑战、截止时间、确定的同时提议规则、幂等确认及有限排空；旧路径全断时允许新承载上仅迁移控制的认证会话。

以下只能由指定原型后确认：W07 的 MTU/分片/外层认证实际承载；W09 成熟 ICE 接口与 Quinn 同 socket 的可行性和唯一 reader；W14 固定 Quinn 版本虚拟 UDP 的连接保持、RTT/拥塞/PMTU 收敛。
原型全部由 GitHub 托管 Actions 执行；真实 NAT、GPU、手机、跨日运行只使用核验后的 Actions 制品。研究文档的手工审阅不冒充这些实验。
