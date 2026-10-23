# 首发需求与验收登记

> 当前范围（2026-10-23）：内网穿透 + 远程桌面，仅 Windows/Web 客户端，Linux 保留后端。本文保留前期实现和历史验收登记；Android 与 Linux 桌面要求已撤销，当前入口见 [平台范围](../../config/product-scope.json) 与 [RC 构建](CANDIDATE-BUILD.md)。全部发行构建在 GitHub，RC 须在实际验收完成后发布。

基线为方案 v3 第 3、9、12 节。当前正式 14.x 产物的已验证/未验证结果继续以其发行材料为准；下面登记 15.x 的要求，没有将旧代码入口、预览图或构建成功当成能力证据。

| 需求 | 旧入口/证据参考 | 15.x 实施与验收要求 |
| --- | --- | --- |
| 账号与授权 | Server `control-center` 账号/原生/浏览器授权测试 | 登录、所有权、本机批准、服务发布分别建模；TOTP/恢复码/刷新代次、逐项授权、暴力尝试防护；A08 |
| 设备与能力 | Server 设备能力 API；桌面/Android 正式目录 | 一个安装实例一个设备 ID，重装新身份，整机事务撤销；新数据不自动导入；A01/A06/A08 |
| 主控/被控 | Client 正式 Rust/Flutter CI；Android 固定 Client 锁 | Windows、Linux x64/ARM64、Android ARM64/x86_64 与 Web 主控；真实媒体/输入/附加通道；A03/A11/A17 |
| 连通性 | 2026-10-12 公司/手机到家的原失败证据 | QUIC/直接 TLS、策略允许的 QUIC/WSS 中继、浏览器 STUN/TURN；网卡候选代次、真实跨网；A04–A09 |
| 隧道 | Server `traffic-gateway` / compose；Client 正式打包配方 | 新 Rust edge/tunnel 的 HTTP/HTTPS/TCP/UDP，域名/ACL/配额、半关闭、背压和撤销；A10 |
| 系统授权 | Android Flutter 正式入口；Windows 系统集成 | MediaProjection/无障碍、前台 Service/本地停止；Linux portal/PipeWire；Windows 权限代理最小接口；A11/A14 |
| 附加通道 | 正式远控界面与安全测试 | 多屏、音频、文件、文本剪贴板逐项授权；文件路径/链接安全、续传/幂等；A11/A12 |
| 视觉 | Client `brand/`、正式 Flutter 布局；Server CSS | 紫色品牌、三导航、账户入口、明暗/中英文；1120×760、DPI/窄屏/无障碍/IME；自有来源逐项确认；A20/G3 |
| 生命周期 | 正式桌面与安装工作流 | 最小化任务栏、主窗口关闭到托盘、明确退出全部用户业务；Explorer 重启、无托盘可恢复；A20 |
| 运维与更新 | 旧 compose/发行签名/恢复材料 | 隔离新装、加密备份、恢复安全代次、故障回滚、固定全目标产物与平台签名；A13/A19/A21 |
| 来源与供应链 | 四仓各文件 LICENSE/NOTICE；源码/材料记录 | L-B、完整来源/非 Cargo 依赖/SBOM/NOTICE；禁用 codec；A14/A16/A18 |
| 容量与稳定性 | 历史报告只作为用例参考 | 固定设备、源码、包哈希、路径和环境的负载/时延及 72 小时实测；A15 |

## 既有安全工作流逐项登记

按方案 v3 第 3 节逐项登记以下工作流。该节明确要求登记旧安全工作流，也明确不能直接把全部旧菜单当作已承诺功能；首发必选范围以该节必选表及第 9、12 节的具体条目为准。下面如实保留历史附加选项与新实现的差异，没有把旧选项自动追加为首发必选，也没有将未实现选项写成已完成。旧入口均为 Client 正式 Rust/Flutter 工程中的需求参考，不表示迁用旧源码。最终全功能真实验收按用户最新安排，在处理 GitHub 后由用户执行；已有开发回归不等于最终设备验收，也不以缺少签名、真机或外网环境阻止继续实现。

| 工作流 | 当前实现事实与历史入口 | 首发边界与最终验证 |
| --- | --- | --- |
| 桌面安全锁与锁屏边界 | Windows 会话事实拒绝已锁定/断开的用户会话及非默认安全桌面；输入和采集持有原会话事实，变化后停止。Linux X11/Wayland 也核验当前用户、活动会话和锁屏事实。见 `crates/platform-session/src/windows.rs`、`crates/platform-session/src/linux.rs`、`crates/platform-input/src/windows.rs`、`crates/platform-input/src/portal.rs` 和 `crates/remote/src/lifecycle.rs`。旧 Client `client/flutter/lib/desktop/pages/desktop_setting_page.dart:916` 有 Unlock Security Settings，`client/src/server/connection.rs:4448` 有会话结束后锁屏选项。 | 第 9.2/9.3 节要求的输入释放、用户会话/UIPI/安全桌面边界已有实现；独立的安全设置解锁和会话结束主动锁屏属于已登记但未在新界面重造的历史附加选项。真实 Windows 锁屏/UIPI、安全桌面以及 GNOME/KDE portal 停止与恢复由用户最终验证。 |
| 权限预设与逐项批准 | 桌面默认仅请求 View；七项权限分别选择，主机对当前 nonce/策略/连接代次明确批准。Android 提供仅查看、查看+输入、查看+音频等快捷组合及独立文件/剪贴板方向。Web 默认附加方向关闭。受信设备和密码授权保留固定权限上限，不扩大当前请求。见 `apps/desktop/src/remote.rs`、`apps/android/app/src/main/java/com/zhanry/nestlink/MainActivity.kt`、`apps/web/src/remote_panel.rs` 与 `crates/app-core/src/sdk_call.rs`。旧 Client 设置页 `:1067` 的模式为 custom/full/view。 | 第 3 节明确的逐项权限、本机批准、一次性/受信设备/密码授权均保留。旧 full/view/custom 菜单没有直接作为新客户端的同名持久模式迁移；不将其扩展解释为任意命名预设编辑器。最终验证各入口默认值、部分批准和权限撤销是否一致。 |
| 空闲断开 | 当前远控许可有原始墙钟/单调时钟期限，后台 supervisor 即使无业务 I/O 也检查撤销、网络与平台变化；输入释放和退出不依赖下一条文件/媒体消息。服务发布另有可配置的 `idle_timeout_seconds`。见 `crates/session/src/lib.rs`、`crates/remote/src/lifecycle.rs`、`crates/node/src/service_plane/gate.rs` 与 `protocol-spec/management.rs`。旧 Client 设置页 `:1523` 及连接 `:1081/:5189/:5202` 实现 `allow-auto-disconnect` 和分钟超时，收到操作后更新时间。 | 远控按“多久没有用户输入”计时的可配置空闲断开是已登记、尚未重造的历史附加选项；第 3 节没有单独冻结其首发 UI/策略契约。服务空闲超时和会话短租约不能代替该选项。第 12 节已明确要求的租约、撤销、无 I/O 时仍停止与释放输入，继续按各自用例最终验证。 |
| 来源限制 | 服务发布配置具备逐服务 CIDR 来源 ACL，在 edge 准入中执行；原生网络设置仅放行本机明确批准的私网候选。远控绑定账号、设备密钥、明确登记的受信设备、逐项权限、路径策略和当前许可，知道设备 ID 不构成授权。见 `crates/protocol/src/services.rs`、`crates/node/src/service_plane/gate.rs`、`crates/app-core/src/native_network.rs`。旧 Client `docs/homedesk/CLIENT_NETWORK.md:15–16` 与 `client/src/server/connection.rs:1357` 另有家庭 CIDR/可选公网来源 IPv4 CIDR。 | 首发明确的远控身份/受信设备来源约束与 A10 服务 ACL 已有实现；旧的远控控制端源 IP/CIDR 选项尚无通用于直连/中继/WebRTC 的新管理界面，作为历史附加选项登记，不能据服务 ACL 声称它已实现，也不能因缺少该 UI 否定已有身份约束。真实来源限制、代理/TUN 与各允许路径的组合由用户最终验收。 |

## 当前未冻结的基线

- 用户已确认的开发目标为 Windows 10/11、Ubuntu 24.04 X11/GNOME/KDE、Android 11–16（API 30–36；arm64-v8a/x86_64）和当前稳定 Chrome/Edge/Firefox；Android 10/API 29 排除。最新 Android 全源码快照为 1070 个输入、SHA-256 `0e2b103b072c9de6ce07bc3b3ae2cd72d6af4ee1289106bb2509a6682055fa29`，127 项 JVM 与 119 项 API30–36 仿真器用例通过，双 ABI JNI/严格 Clippy、APK 组装和开发签名验证通过。模拟器实际页大小为 4 KiB；正式签名、ARM64 真机、真实系统授权和跨网验收尚未通过，详见 [ANDROID-VERIFICATION.md](ANDROID-VERIFICATION.md)。
- 正式已安装产品的截图与字体来源待采集；历史 Go/Compose 截图单列；第一批没有迁移来源未确认的视觉资产。
- Windows Authenticode 身份、新 Android applicationId/固定证书、Linux/OCI/更新签名身份和密钥系统存储入口待配置。原 Windows 未签名状态不作为新版本豁免。
- 2026-10-13 用户确认 Windows/Android 签名身份、ARM64 Android 真机及公司/手机流量到家里的环境尚未配置，要求继续实现与准备验收工具；这些正式验收项保留待执行状态。
- Mac/iOS、内核 VPN/TUN、任意出口 SOCKS、安全桌面绕过、计费与插件市场不在本方案首发范围。
- G0 通过前不声明上列平台能力已成立。后续每项用例记录源码 SHA、固定产物哈希、原件摘要及失败/重试证据，授权和来源失败不豁免。
