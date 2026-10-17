# 浏览器与原生主机互通检查（持续更新至 2026-10-16）

2026-10-16 输入续租最终增量已通过双平台定向验证：Windows/Linux 对同一组 1015 项输入分别执行 43 项 SDK 与 32 项 lifecycle 测试，各 75 项全部通过，两端 all-target strict Clippy 和 fmt 均通过。额外红测准确复现任务延迟唤醒后越过两秒等待上限；修复后，等待期限保留两秒与原授权期限的最早值，读取新许可前先检查，新增两项延迟唤醒回归通过。旧 Windows 严格检查的两处 parity lint 失败保留并已修正。Linux 经用户授权暂停校时/选择既有时钟源，采样无跳变，测试后已独立确认恢复 tsc + active。七文件原修复和后续三文件差异均分别保留；见[运行回执](../../artifacts/browser-input-renewal-20261016/RUNTIME_VERIFICATION.json)。固定 Build06 的 Chrome155、Edge155、Firefox158 真实 1080p30 + Opus / 输入 / 文件短测均通过，平均分别为 28.04、28.59、28.91 fps，各完成 5 次稳态续租；三端各 24 条实际发送的输入均在 lease 2，主机录制、文件精确字节和物理清理均通过，[浏览器复测回执](../../artifacts/browser-input-renewal-20261016/BROWSER_REPLAY_VERIFICATION.json)独立核验。此次为各 36 秒本机自有合成画面，不能扩展为 30 分钟 G1、真实采集或跨网通过；此前 Android 112 项结果仍绑定旧源码/APK，不覆盖本次共享 SDK/remote 修改。

2026-10-16 Build05 历史补测：Chrome、Edge、Firefox 的媒体、Opus、真实输入与文件短测已分别通过。Firefox 的首轮最终门槛捕获关闭后的 `InvalidStateError`；同版官方 Firefox 的独立复现确认关闭后的 SDP getter 会抛异常。探针现在在读取前停止关闭 peer 的定时观察，Firefox attempt02 的全部门槛及物理清理通过，首轮失败保留。

Chrome attempt07 的 1080p30 + Opus 平均 29.01 fps；attempt08 加入输入与文件后平均 28.95 fps，均达到每区间 27 fps 门槛。但 attempt08 的实际输入全部在首份许可内，不能据此认为续租期间输入已验证。增加“实际管理续租后立即输入”的检查后，attempt09 稳定复现真实缺陷：浏览器以 lease 2 发送合法坐标，主机尚未取得下一份签名许可，按旧快照拒绝输入并关闭连接，设备没有收到注入。反向的旧输入晚到也存在静态竞态，正在修复；本轮尚无三浏览器 1080p30、主动网络损伤或 30 分钟完整通过结论。

[诊断索引](../../artifacts/browser-native-throughput-20261016/INPUT_RENEWAL_DIAGNOSIS.json)重新核验八份历史运行的冻结探针、报告、进度、命令及严格解析的管理日志，保存上述失败与成功的准确范围。原生 Build05 和 Web 各有独立的编译源码归档；本轮仅使用自有合成画面、录制输入设备与临时文件，无已安装产品、真实平台采集或跨网验收结论。

2026-10-16 新增优化构建的 1080p30 + Opus 短测：Chrome 155.0.8059.40
实际连续解码 36.027 秒，平均 28.15 fps，三个约 12 秒区间分别为
28.71、28.45、27.28 fps，均达到原定 27 fps 门槛。Opus 实际解码约
48,000 samples/s、50 packets/s；5 次签名管理续租成功。自有画面和音频
经真实采集控制器、VP8/Opus、RTP 和正式 Web UI 到达浏览器。capture/audio
reset、浏览器/Caddy 退出、数据库、临时私钥和 profile 清理均通过。

本组固定的是 `optimized-build-attempt02` 的原生源码归档/二进制，以及新
Web 许可证替代后的独立构建站点。它不覆盖随后新增的 RTCP 码率适配代码。
采样与另一输入/文件夹具编译部分重叠，故保留为本机开发结果；尚非独占的
30 分钟性能验收、真实桌面采集、主动丢包/拥塞、TURN 或已安装产品验收。
浏览器主动断开后，主机保留的关闭原因是 `Some(Transport)`，未改写该原始事实。
原 debug attempt01 的帧率失败和 optimized attempt02 的登记失败继续保留。

逐区间原始计数、固定输入、清理和边界见
`artifacts/browser-native-throughput-20261016/SHORT_RUN_SUMMARY.json`，
SHA256 `252a50b1d29865e105ad1ba3f79d24d579ee39bbb2785c4c1b412ad0a0c6a8d3`。
以下保留 2026-10-15 的历史问题和对应批次，不据此扩展上述验证范围。

本轮修复两个真实管理服务集成问题：原生主机把审批请求的截止时间误当作
15 秒会话租约的截止时间，导致合法许可在启动或刷新时被拒绝；统一 offer
轮询没有调用已有的主机续租签名函数，空闲信令下的连接无法继续续租。

主机现在在同一轮询中维护授权、TURN 绑定和续租。每份租约只发送一次下个
序号的签名；控制端必须通过真实管理 API 提交双端签名，主机收到新签名
permit 后才延长本机授权。等待提交期间不重复签名，刷新中观察到新租约时
重新等待它自己的续租窗口。审批请求截止时间不参与活动租约的等值判断；
会话、端点、策略、权限、路径和签名 permit 仍逐项核验。

`webrtc_host::tests::data_loopback_tests::idle_offer_poll_renews_over_sctp_and_http_then_rejects_revocation`
使用真实管理路由、浏览器临时身份、SDP/ICE/SCTP 和双端会话证明。检查
证明前拒绝签名、信令为空时续租、两轮实际 HTTP 续租、重放拒绝、签名自身
不延长许可、跨过原租约截止时间后的媒体授权及撤销后拒绝继续。

- Windows 定向回归通过：`browser-host-renewal-windows-green-20261015-attempt02`。
- Linux SDK/Core library 共 55 项通过：`browser-host-renewal-linux-runtime-20261015-attempt01`。
- 两端 SDK/Core all-target strict Clippy 通过：Windows strict attempt01、Linux strict attempt01。
- Linux 临时时钟源的持有与恢复见 `browser-host-renewal-linux-clock-20261015-attempt01.log`，已读回 `tsc`。
- 原 Windows red attempt04 复现真实管理 permit 在主机启动时被拒绝；其他原失败、测试编译错误和重试也保留。

全部原始日志和逐文件源码、命令、退出状态及 scratch 清理回执均位于
`artifacts/core-verification/`。这些所选本机检查不等于正式浏览器到已安装
产品的跨网媒体验收。

新增的 [原生夹具](../../scripts/fixtures/browser-native-host/README.md) 和
`scripts/refactor-browser-native-check.cjs` 使用正式 Web 页面、真实原生
Core 与 VP8 编码器，生成自有测试像素并观察 36 秒解码、四轮管理续租和关闭。
它们不读取用户桌面，也不替代真实平台采集、音频/输入、TURN、签名或跨网
验收。Windows 本机的三款稳定浏览器检查现已通过，范围与原件见下文；每次结果必须同时具有
浏览器原始报告、原生 capture reset/清理结果、稳定源码/站点/二进制以及时钟恢复证据。

原生夹具 Linux build/strict attempt07 均通过，源码与 scratch 回执完整。
审批后夹具现在等待控制端通过真实 POST permit 签发非零 connection generation
和 lease sequence，之后才启动 `run_browser_host`，与正式 UI/Core 门槛一致。
它没有重试 403、放开生产授权或自行签发控制端许可。HTTPS 使用两小时临时
CA/leaf：Chrome/Edge 只信任新进程中的精确 leaf SPKI，Firefox 只在新 profile
导入临时 CA；系统信任与现有 profile 不变，`acceptInsecureCerts=false`。

Chrome 155.0.8059.40 的 attempt04/05 均在真实初始 permit、双端 SDP offer/answer
交换后连接超时，尚未开始采集。attempt05 保存关闭前的实际 peer/getStats
观察：浏览器 offer 为四个 mDNS host 候选，原生 answer 为八个 mDNS host
候选；整个连接预算内没有 remote-candidate 或 candidate-pair，ICE/DTLS
保持 new。无管理 API 失败或未处理页面异常。该证据把问题定位到候选解析/
可达性阶段，尚不能仅凭此断言 WSL 或生产 mDNS 的具体根因。下一步使用同一
正式路径的 Windows 本机原生夹具作对照，不放宽浏览器、许可或路径校验。
诊断只保存状态、候选类型/地址类别及计数，不保存候选地址、SDP、密钥或证明。

两次失败的 browser/lifecycle、management-stages、host-result 与日志全部保留。
各次均确认原生二进制/站点不变、浏览器和 Caddy 退出、自有数据库/临时私钥/
profile 回收、WSL clocksource 恢复。`capture_prepared=true`、`capture_starts=0`
是实际结果，不能将其记为媒体或解码通过。Windows 本机夹具不切换 WSL 时钟，
其运行记录会单独标明 host platform 与空临时父目录回收结果。

Windows 本机 fixture build/strict/usage attempt02 已通过。原生 ICE 改用库的
`QueryOnly`：继续解析浏览器 mDNS，原生端通过已授权的签名 SDP 发送实际 IP
候选，避免同一 mDNS 名称表达多网卡不同地址/端口的歧义。此改动有锁定依赖
源码依据，完整互通结果仍需验证。没有强制改变 DTLS 角色，也没有修改 Cargo
缓存中的依赖源码。

Chrome→Windows attempt01 在 ICE connected 后停于 DTLS connecting；attempt02
出现短暂 ICE disconnected 后恢复，浏览器实际观察到 peer/DTLS connected，
随后在证明阶段显示 `permit is invalid or expired`。主机采集启动和帧数仍为
零。源码核对确认 Web 在握手后构造 Session 时，把握手前的 request 时间与
当前剩余租约相加，重复扣除了握手耗时。已合入
`Session::activate_with_retained_deadline`：使用同一当前时钟样本激活，立即
收窄至已经保存的原许可/端点截止时间，返回前检查时钟；Web 在签发证明前
再次检查现存 authority。原三秒证明预算和到期/撤销检查继续保留。

该修复的 Windows Session 授权回归 17/17（含新增四项）和 all-target strict、
Web WASM all-target/all-feature strict、优化 production 构建均通过；各组
输入不变、日志哈希和 scratch 回收已核对，证据为
`web-proof-retained-deadline-*-20261015-attempt01`。Windows fixture build/strict/
usage attempt03 也通过。Chrome→Windows attempt03 不再出现上述许可错误，
但 DTLS connected 后仍在 WebRTC 操作预算内超时，未开始采集或管理续租。
首个 nominated pair 长期为 in-progress，五秒后靠新增 prflx pair 恢复连接；
原生 ICE 最终 failed。此后已修复锁定 ICE 库把 mDNS 候选的 `.local` 字符串与
解析后源 IP 比较而无法命中原候选的缺陷；这次历史失败本身不构成媒体通过。
DTLS 单侧状态不能作为媒体通过证据。

Windows 三次失败均保留 browser/lifecycle、management-stages、host-result 和
受限原生日志；自有数据库、私钥、profile、空临时父目录均已回收，浏览器和
Caddy 已关闭。Windows 不修改 WSL 内核时钟，Linux 的恢复记录继续独立保留。

锁定 `webrtc-ice 0.14.0` 已从原 `.crate` 导入
`crates/traversal/vendor/ice`，保留 MIT/Apache-2.0 来源与许可。生产修改仅将
候选匹配改为已解析 socket 的 IP/端口；没有修改 Cargo registry 缓存、解析器、
DTLS 角色或连接预算。隔离实际 AgentInternal 回归先复现 mDNS IPv4/IPv6 两项
失败，再验证四项通过。来源逐字节核对、根与独立夹具锁的唯一路径边变更，见
`ice-vendor-source-20261015-attempt01.json`、
`ice-vendor-lock-edge-20261015-attempt01.json` 与 vendor 的 `UPSTREAM.md`。
完整 all-feature 依赖图的 licenses/bans/sources 检查也已通过，证据为
`ice-vendor-graph-license-check-20261015-attempt02`；保留既有多版本依赖警告。
首轮离线检查缺少锁中既有的其他平台源码包，失败原件保留；通过 locked fetch
补齐后复验，根 manifest/lock 版本及内容未修改。

Windows fixture build/strict/usage attempt04 均通过。Chrome→Windows attempt04
实际完成双方证明、270 帧采集和四次签名管理续租；约 29 秒后 Network
Information change 触发真实 ICE 重协商，peer 仍为 connected 时，新候选对
还在 in-progress，Web 立即报 NoSelectedPath 并关闭。此失败原件保持失败。
已将调用方和状态监护共用的候选等待收敛到有界异步检查：暂未报告候选对时
继续等待，沿用原操作预算和原许可/端点/TURN 期限，每次异步等待检查撤销、
到期与时钟回退。实际选中违反许可的路径仍立即失败；只有验证成功才恢复
重协商前禁用的接收 track。没有延长许可或把 connected 本身当作路径证据。

修复后的 Web WASM all-target/all-feature strict 与 production 优化构建通过。
同一站点/Windows 主机二进制实际通过：

| 稳定浏览器 | 批次 | 连续解码 | 最后采样累计解码帧 | 实际签名续租 | 实际 offer 数 |
| --- | --- | --- | --- | --- | --- |
| Chrome 155.0.8059.40 | Windows attempt05 | 36.026 秒 | 255 | 5 | 3 |
| Edge 155.0.4283.45 | Windows attempt01 | 36.022 秒 | 237 | 5 | 2 |
| 官方 Firefox 158.0 | Windows attempt01 | 36.043 秒 | 242 | 5 | 2 |

每款浏览器都使用自有 BGRA 测试图、实际 VP8/RTP/浏览器解码，核对 320×180
尺寸和像素，并显式发送一次合成 online 事件，要求生产 UI 完成新的签名
offer/answer、实际 ICE 重协商及后续画面推进；该事件不证明真实 OS 换网。
Chrome 还实际观察到浏览器发出的 Network Information change。每次 native
capture 均启动一次、产生 335 帧并 reset；站点/二进制不变，浏览器、Caddy、
自有数据库、临时私钥/profile 与空临时父目录清理均核验通过，未修改内核时钟。
三引擎索引为 `browser-native-host-three-stable-engines-20261015-attempt01-summary.json`，
SHA256 `d89e97e92693968ef352f6fb03127eb67cae0de835da622f4b513cac4c0e37bf`。
修复和原始输入保存在 `artifacts/browser-ice-restart-wait-followup-20261015/`。
这组通过覆盖本机 Windows 原生 Core 与正式 Web UI 的 View 链路；真实平台
采集、音频/输入/文件/剪贴板、TURN 路线、已安装产品、真实换网与跨网仍需
各自的固定产物验收，不能由该组结果代替。

Windows workspace runtime attempt03 另在编译阶段暴露 session 两处测试仍
调用已移除的 `sign_endpoint_proof`；该批没有执行完整 workspace 测试，原
失败保留。其余包的 attempt04 显式排除 session 用于独立诊断，不作为完整
workspace 通过证据。修复和完整复验继续执行。
# 2026-10-16 补充：可选 TURN 与直连优先定向证据

已将此前固定输入的协议 5 项、SDK 52 项、Web 14 项测试，以及 Windows all-target Clippy/fmt、Linux WASM all-target/all-feature Clippy 汇总至 `artifacts/direct-preferred-turn-20261016/FROZEN_DIRECT_PREFERRED_TURN.json`。本次汇总只复核旧回执和日志摘要，没有重新执行测试。每份回执记录其实际源码、前后不变及自有临时目录清理；两份历史失败原件继续保留。

这些证据覆盖可选 TURN 不可用时的直连优先处理、必须中继时拒绝及本地 TURN 授权/续租和配置凭据清理。已 gather 的底层 allocation 可能保留至 peer 关闭或原期限，不宣称撤销即物理删除。本轮后续原生恢复、双栈、本机网络设置、权限代理、多显示器和双语修改不在这 71 项的冻结输入内，另行定向验证；正式 G0/G1、签名安装和真实跨网验收仍未完成。

