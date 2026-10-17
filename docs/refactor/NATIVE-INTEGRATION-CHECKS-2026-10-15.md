# 多屏、下载恢复、音画时序和服务计量开发检查

集中索引为 `artifacts/core-verification/native-av-accounting-recovery-status-20261015.json`，生成程序为同目录 `record-native-av-accounting-recovery-20261015.py`。它核对各次终态、实际日志 SHA256、运行期间源码不变和独有 scratch 回收，再记录当前源码逐文件指纹。不同时间运行的用例保留各自输入，`complete_receipt_scope_matches_recording_source` 明确标出整个输入范围是否仍与记录时相同；不会把早期通过结果改标成当前完整工作区通过。

Windows 的 22 组所选用例合计执行 280 项，Linux 的 23 组合计执行 290 项。这里选择每组最后一次实际执行，原失败批次、ignored 硬件和公网用例仍单列。它们是开发回归，不是一次完整 workspace 或固定安装产品验收。

| 所选范围 | Windows | Linux | 输入和结果记录 |
| --- | ---: | ---: | --- |
| 多屏/恢复协议 | 41 | 41 | `native-displays-file-recovery-*-protocol-displays-recovery-20261015-attempt01*` |
| 媒体时序/呈现 | 36 | 36 | 同前缀 `media-displays-recovery` |
| 远控输入/释放生命周期 | 30 | 30 | 同前缀 `remote-input-lifecycle` |
| 远控音频时钟事实 | 3 | 3 | 同前缀 `remote-audio-clock` |
| 平台音频边界 | 8 | 5 | 同前缀 `platform-audio-boundary`；设备 ignored 另计 |
| 平台下载跨进程恢复 | 15 | 16 | 同前缀 `platform-file-restart` |
| SDK 真实进程终止与新 TLS/QUIC 证明恢复 | 3 | 3 | 同前缀 `sdk-file-restart` |
| Core 原生会话 | 4 | 4 | 同前缀 `core-native-session` |
| IPC/桌面恢复状态 | 41 | 41 | 同前缀 `ipc-desktop-recovery` |
| daemon 根目录批准/撤销与 owner 回收 | 7 | 7 | 同前缀 `daemon-file-restart`，attempt03 |
| Node 持久计量、停止封存、快照和 HTTP 重报 | 29 | 29 | 同前缀四个 `node-*`，attempt02 |
| Storage 四 scope 累计额度和恢复事务 | 13 | 13 | 同前缀 `storage-service-budgets`，attempt02 |
| 真实 HTTP→Node→QUIC→TCP 发布及启动取消 | 2 | 2 | 同前缀 `sdk-real-service-publication`，attempt02；公网 Caddy/ACME ignored 单列 |
| 实际离线额度恢复 CLI 与互斥锁 | 1 | 1 | 同前缀 `server-quota-recovery`，attempt03 |

表格只列重点组，其余已执行组和完整计数见 JSON。早期整批均保留失败状态；attempt02 的会计修复通过和 attempt03 的两组夹具复验不能改写原整批结果。

## 本轮修复

Node 查询未停止 grant 的 nullable `stop_json` 时，原条件把整行排除了。修正后当前 grant 可以正常生成用量快照、上报及停止；公开 `ServiceResourceSet::accept` 与真实 Node 使用同一个持久 ledger。测试主动修改 lease 时显式重新签其嵌套 grant，外国签发者场景仍使用一致的外国签名验证 pinned 拒绝。

新 `quota-recovery-request` 和 `quota-reconcile` 已实现独立外部账本签名的保守恢复。完整请求、四 scope 累计量、旧 grant 未知债务、最后写失败回滚、旧 epoch/replay，以及重新批准后不重复发放已花额度均进入实际回归。CLI 测试使用操作系统真实私有目录，并验证运行中的控制实例拒绝离线操作。环境尚无独立账本材料，实际运维恢复仍保持封锁，见 [恢复契约](SERVICE-QUOTA-RECOVERY.md)。

daemon 测试把 23 字节样本错误地请求为 64 字节。复验改用合法范围，分别验证旧批准撤销后拒绝读取和新批准可以实际读到内容；生产有界读取规则不变。

双平台 protocol/identity/node/storage/server 五 crate strict Clippy、本轮 server/daemon all-target strict 以及所选前序检查均有成功 receipt，具体命令以 JSON 索引为准。Linux 音频 C ABI 的 ASan/UBSan 运行覆盖 100,000 个 PCM 边界输入，记录为 `native-av-pipewire-sanitizer-20261015-attempt01*`。硬件音画偏差仍须实测。

Windows 当前整合后的 16 crate all-target strict 另以 `native-integration-final-windows-clippy-20261015-attempt01.receipt.json` 通过，覆盖 protocol、identity、node、storage、server、platform-audio、remote、platform-files、platform-input、media-session、sdk、app-core、app-ipc、daemon、desktop、android-bridge；其完整输入和真实日志 SHA 保留在该 receipt，不将早期包含其他失败的 strict 命令改标成通过。

Linux 两次恢复回归在既有用户授权下临时使用 `hyperv_clocksource_tsc_page`。attempt02、attempt03 的 EXIT owner 日志均记录恢复，汇总程序还实际读回 `tsc`。原 attempt01 的墙钟回退记录保留，不能把所有历史运行写成零回退。

## 浏览器和 Android

WASM strict、两个优化 release 静态站点和 Chrome/Edge/Playwright patched Firefox 的所选本机检查已通过。Firefox 无激活剪贴板探针按原生产 30 秒期限等待 35 秒后验证拒绝且无 RPC；早期 20 秒探针的 incomplete 原件保留。随后官方稳定 Firefox 158.0 另经 WebDriver BiDi 通过相同的 14 个本机所选场景，独立记录为 `web-stock-firefox-bidi-20261015-attempt01.json`；工具链与正式验收边界见 [浏览器记录](WEB-BUSINESS.md)。

最新 Kotlin/JVM 75 项通过，包含应用/测试编译。JNI、APK、Android 11–16/API 30–36 当前源码矩阵另建新 receipt，不沿用旧 APK。ARM64 真机、正式证书、真实系统投影/SAF/无障碍、完整 GNOME/KDE/X11、稳定浏览器、公司/移动网络到家、容量和 72 小时固定产品运行仍须实际材料；本记录不宣称正式验收完成。
