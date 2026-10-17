# 15.0 正式验收缺口（2026-10-17）

本登记按重构方案 v3 的 A01–A21 核对。**当前 21 项均未通过正式产品验收**：现有单元、集成、浏览器和模拟器结果只覆盖各自固定开发输入；最终源码提交、发行签名、安装产品、对应硬件/网络和逐项验收回执尚未形成同一固定批次。这不否定已通过的开发检查，也不把“未正式验收”误写成实现失败。

| 编号 | 已有开发证据 | 正式验收仍需补齐 |
| --- | --- | --- |
| A01 | 有安装实例、隔离目录和 Android 命名空间实现；最新 Android API30–36 开发仿真器回归通过。 | 各目标平台用固定签名包做干净安装、新账号/设备检查；证明新命名空间不读取旧配置，并确认 Android 新 applicationId 与旧包隔离。 |
| A02 | L-B 台账把 RustDesk 派生运行时代码列为排除项，历史来源保全与新产物来源分开记录。 | 对最终 Windows/Linux/Android/Web/OCI 字节执行旧 API、旧票据、旧服务入口和依赖扫描，并核对旧端点拒绝结果。 |
| A03 | Linux 先前完整 workspace 回归 1229 passed/0 failed/12 ignored、all-target strict Clippy 通过；10/17 attempt06 曾在 25 分钟上限中断，之后 10/17 attempt07 完整执行 `cargo test --workspace --locked --offline -- --test-threads=1`，141 个结果组为 1237 passed/0 failed/12 ignored，源文件清单未变，36 个 doctest target 均完成；详见 [attempt06](LINUX-WORKSPACE-ATTEMPT06-2026-10-17.md) 和 [attempt07](LINUX-WORKSPACE-ATTEMPT07-2026-10-17.md)。Windows 当前源码完整 workspace 141 suites 为 1187 passed/0 failed/10 ignored、all-target strict Clippy 通过；Android API30–36 119 项仿真器测试和 Chrome/Edge/Firefox 本机合成画面回放通过。 | 固定 OS/ABI 正式安装包的主控/被控组合仍需完成；验证真实系统画面、输入和已批准附加通道。 |
| A04 | 策略、转发、隧道与资源计数有单元及本机集成测试。 | 对固定产品分别跑 `deny`、`allow+direct_only`，同时保存节点计数、端点信息和抓包，证明禁止路径为零且允许隧道可用。 |
| A05 | 签名节点发现、relay-only 和自动中继路径有开发级真实调用回归。 | 固定安装包下验证 direct-preferred/relay-only 的实际路径、节点、流量和 UI 一致，并证明强制中继不拨直连。 |
| A06 | 许可续租、撤销、输入释放、队列/资源清理和超时路径有定向回归；本轮新增本机活动 TURN allocation 在在线 watch 撤销后两秒内关闭。 | 在真实在线/失联目标上测量禁用与撤销时限，在线两秒内停止，租约到期停止，并核实输入与 allocation 均已清理。 |
| A07 | QUIC、TLS/WSS、TURN 与中继各自有协议和权限边界测试。 | 用最终包交叉跑所有允许/拒绝组合，证明租约、配额、身份和撤销在各通道一致且无旁路。 |
| A08 | 账号、设备、MFA、重放、刷新、恢复和旧代次有大量开发安全测试；桌面与 Android 现已接入固定密码配置/撤销和绑定当前请求修订的一次性密码授权 UI。 | 从固定产品执行完整越权/错误凭据/批准/重放/账号切换/移除/过期矩阵，并保存逐项资源状态与拒绝回执。 |
| A09 | 网络恢复和损伤脚本已准备；本机浏览器重协商有短时开发证据。 | 公司网络与手机流量到家里的真实环境尚未配置；需跑 Clash/TUN、网卡切换、IPv4/IPv6、UDP 阻断、仅 443、丢包/乱序/MTU 矩阵。 |
| A10 | HTTP/HTTPS/TCP/UDP 服务与授权目标有协议、daemon 和本机运行测试。 | 用固定安装包完成全协议端到端验证，覆盖域名/ACL/配额、流式/WebSocket、半关闭、UDP 映射与撤销。 |
| A11 | 多屏、布局、音画时序、Android Host 和平台适配有开发回归。 | 真实显示器/DPI/IME/音频/旋转/休眠；Android 系统授权与停止、Linux GNOME/KDE portal、硬编失败后恢复均需在目标设备验证。 |
| A12 | 文件/剪贴板实现有路径、链接、续传、恢复、授权和清理测试；Android 119 项回归覆盖当前源码。 | 真实 SAF provider、跨平台大文件、校验/续传、剪贴板权限和撤销期间不阻塞输入需在已安装产品中复测。 |
| A13 | 加密备份/恢复、更新发布状态检查和安装失败回滚逻辑有开发级测试。 | 固定产品下实测进程崩溃、断网、磁盘满、证书续期、时钟回拨、备份恢复和旧租约失效。 |
| A14 | 当前 Cargo.lock（SHA-256 `9a34ff54642f69de251808368609ff4251dfb1b572d4cef617a8d87f572a4bb7`）覆盖 766 包，1365 份 NOTICE 与 2176 份归属文件完整收集，缺失项为 0；cargo-deny 对同一元数据的 advisories/bans/licenses/sources 检查通过（保留 58 条多版本警告）。`protoc` v36.2 八平台和 SQLite 3.50.2 bundled 源码已与上游字节核对，包含原文许可和摘要；细节见[当前收集回执](cargo-notice-current-2026-10-16.md)与[非 Cargo 来源核验](build-input-provenance-2026-10-16.md)。 | 完成组织级许可证兼容批准、完整非 Cargo/系统/二进制依赖 allowlist、模糊测试和预算证据，并把 SBOM/NOTICE 绑定最终构建材料。 |
| A15 | 有短时性能与资源测试；浏览器媒体回放约 36 秒。 | 固定机器、版本、链路、包和统计口径后运行容量/延迟/吞吐及连续 72 小时稳定性测试。 |
| A16 | libvpx/Opus 输入已锁定，禁用 codec 选项有构建配置检查。 | 从各最终包捕获实际 SDP/协商及依赖清单，证明第一方依赖和二进制不包含禁用 codec，并区分浏览器自带能力。 |
| A17 | Chrome、Edge、Firefox 有 36 秒 VP8/Opus 开发媒体运行；Android 有 ABI 构建与仿真器检查。 | 在固定浏览器/平台/ABI 上验证真实 codec、软硬编、格式、实时性、降级和失败提示，补足真实硬件能力数据。 |
| A18 | 新代码按 Apache-2.0/L-B 登记；当前锁定 Cargo 图 1365 份 NOTICE/2176 份归属文件无缺项，cargo-deny license/source/advisory/bans 检查通过；`protoc` 与 SQLite 精确来源、字节和许可证声明已核实，历史资料与新产品分离。 | 仍需组织级许可证兼容审批；闭合旧资产/测试向量逐文件纳入或排除决定、字体/图标来源、完整非 Cargo/系统依赖清单和最终 SBOM/发行材料绑定。 |
| A19 | Caddy、服务和 TURN 配置模板及本机部署检查已存在。 | 在公网/企业测试环境验证 ACME、HTTP/3/TCP 回落、Cookie/Admin 隔离、端口/防火墙及 TURN/TLS 443；当前真实网络条件未配置。 |
| A20 | 已检查 Android API35 初始身份页浅/深主题截图；中英文/主题有开发测试。 | 采集最终已安装产品的正式截图与字体基线，完成 DPI/窄屏/无障碍/IME、任务栏/托盘/退出及 Explorer 重启矩阵。 |
| A21 | 签名检查、发行 producer 和 handoff 工具已准备；不会用开发证书冒充发行签名。 | Windows Authenticode、固定 Android 证书、Linux/OCI/更新签名身份尚未配置；需签署固定字节并实测升级、旧签名拒绝和失败回滚。 |

用户已确认 Windows/Android 签名身份、ARM64 Android 真机和公司/手机到家的网络环境尚未配置，并要求继续实现和准备工具。相关工具和模板已保留于 [签名验收](SIGNATURE-ACCEPTANCE.md)、[发行交接](RELEASE-HANDOFF.md) 与 `config/`；缺少签名、硬件或外网条件的项保持未通过。
