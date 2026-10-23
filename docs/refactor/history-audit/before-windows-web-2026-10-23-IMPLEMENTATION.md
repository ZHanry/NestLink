# NestLink 实施记录

2026-10-17 Web 账户安全与授权的真实 UI 定向检查 9/9 通过：覆盖独立 HTTPS pin 登录、受信设备拒绝及重试、真实全屏进入/外部退出、密码 scope 变化、错误密码、后端已提交但响应截断后的撤销、重新认证、TOTP/恢复码及改密注销/新密码登录。1061 个输入和固定 Web/server 字节前后未变，自有进程和临时目录已回收；物理 Esc、媒体及本次最终 RC 安装验收仍待执行。证据见 [Web 安全检查](WEB-SECURITY-VERIFICATION.md) 和 [当前检查索引](current-verification-2026-10-17.json)。

2026-10-17 用户最新变更：暂停旧仓库整理，转为新建 `ZHanry/NestLink`、使用全新 Git 历史并发布 **0.1.0 RC1（0.1.0-rc.1）**。旧历史上传已停止，已传部分保留；后文旧仓合并、更名、删除及 15.0.0 交付顺序均作为变更前记录，不再执行。本次目标和证据范围见[新仓 RC 发布说明](NEW-REPOSITORY-RC.md)。

2026-10-17 最后接线的集中开发检查：服务发布 Storage 15 项、SDK 真实 HTTP→Node→QUIC→TCP/UDP 1 项、Server 1 项及契约无漂移检查通过；Storage/SDK/Server/Desktop 的 all-target strict Clippy 通过。SDK 原回执因并行变更 product-state.md 保留 unchanged=false，独立比对证明 936 个 Rust/Cargo/OpenAPI 输入未变。Web 账户安全、三种授权和全屏入口的 production/verification 优化构建及 WASM release strict Clippy 通过。Chrome、Edge 与官方稳定 Firefox 的持久身份、并发标签、账号隔离、不可导出密钥和篡改拒绝用例通过；首批未配置 Firefox 启动器的整体失败原件保留，官方稳定版单独复测通过。浏览器运行结果绑定固定站点字节，构建后的纯类型别名修正不冒充已重建。源码、日志、失败和清理回执均见[当前检查索引](current-verification-2026-10-17.json)。

2026-10-17 最新交付顺序以用户直接指示为准：补齐代码并集中做必要开发检查后，完成 GitHub 历史保全、主仓上传与更名、仅保留 main、上传 Release 及删除三个组件仓库；完整全功能真实验收由用户在仓库整理后执行。签名、真机、跨网和长期稳定性结果继续如实登记，不将 pending 改为 passed。

2026-10-17 TURN release 协议模糊测试按用户单次 90 分钟上限完整运行 5400 秒，UDP 483280 个数据报、TCP 21482 个连接/53952 帧、TLS 5390 个连接/13560 帧，发送/连接/握手错误均为 0，退出时活动 allocation 为 0。151 个选定源输入前后未变，自有 scratch 已删除；独立读取确认 WSL 为 `systemd-timesyncd=active`、时钟源 `tsc`。它是 loopback 开发检查，不代替真实公网或正式 G2。Android 服务发布三态 UI 修正后的 JVM 单测 133 项、22 个 XML 结果组全部通过；该次直接调用未抓前后源码清单，保留这一证据限制。日志和摘要见[当前检查索引](current-verification-2026-10-17.json)。

2026-10-17 TURN G2 开发补强：`TurnService::bind` 在绑定前拒绝已离线或监视发送端已关闭的节点，并在监听 socket 绑定后复核；TURN 鉴权和数据授权也直接读取在线监视器，节点掉线后立即拒绝新分配与转发。新增活动 allocation 两秒内撤销、端口耗尽释放容量后重试成功的服务回归。Linux TURN 套件 12/12、`node-turn` 配置/TLS 回归 4/4、workspace fmt 检查，以及 TURN crate 和 server 的 all-target strict Clippy 均通过。debug 与 release 各完成 10 秒 smoke；原 24 小时测试在用户规定 90 分钟上限后中止，后续完整 90 分钟结果见上文。回执见[当前检查索引](current-verification-2026-10-17.json)和[TURN 模糊测试说明](TURN-FUZZ-ACCEPTANCE.md)。G2 仍需目标负载/容量测量及真实公网 TLS/跨网验收。

2026-10-17 Linux workspace bounded attempt06 在 25 分钟上限后中断，结束前累计 1237 passed/0 failed/12 ignored；日志停在 `Doc-tests nestlink_sdk`，没有 workspace 完成回执。随后独立重跑 `cargo test --workspace --doc --locked --offline`，36 个 doctest target 均通过退出。独立时钟 watchdog 确认恢复 `tsc` 与 `systemd-timesyncd=active`，未观察到时钟跳变；该部分 runtime 输出不替代完整 workspace 结果。详见[中断批次记录](LINUX-WORKSPACE-ATTEMPT06-2026-10-17.md)及[当前检查索引](current-verification-2026-10-17.json)。

2026-10-17 Linux workspace attempt07 随后在用户批准的 30 分钟恢复窗口内完整通过：141 个结果组共 1237 passed/0 failed/12 ignored，1081 个源文件运行前后保持一致，自有临时文件清理完成。watchdog 采样 10783 次、未观察到墙钟跳变；运行后恢复 `tsc`、`systemd-timesyncd=active`，Ubuntu 与 Docker WSL 发行版回到 stopped。日志、回执及窗口摘要见 [attempt07 记录](LINUX-WORKSPACE-ATTEMPT07-2026-10-17.md)和[当前检查索引](current-verification-2026-10-17.json)。这是开发级回归，不替代固定签名安装产品验收。

2026-10-17 Android 固定密码 UI 增量的 Kotlin/JVM 全量单测 131/131 通过，0 错误、0 跳过，79 个选定输入在测试期间保持不变。首次尝试在测试启动前因临时盘符无法解析 Android SDK 失败；显式设置已安装 SDK 后完整重跑通过。该结果不覆盖 APK 重构建或模拟器仪器测试；日志和回执见[Android 验收记录](ANDROID-VERIFICATION.md)及[当前检查索引](current-verification-2026-10-17.json)。

桌面密码 UI 的 Windows x64 all-target strict Clippy 原先发现两处风格告警，已修复为等价条件和 Option 读取；修复后的 `nestlink-desktop` all-target `-D warnings` 与 workspace `cargo fmt --check` 均通过，969 个选定 Rust 输入保持不变。环境未设置 codec 前缀的 attempt02 与修复前告警 attempt03 均保留，最终有效回执为 attempt04，详见[当前检查索引](current-verification-2026-10-17.json)。

2026-10-17 最终化准备复核：旧 Release 附件本地归档 799/799 件、16,177,009,767 字节再次通过当前 GitHub 元数据与字节摘要核对；历史源码 bundle 在空 bare 仓库恢复 317 个引用并通过严格 fsck；14.1.0 Server/Client 脏工作树 ZIP 也已重新核对。三项缺失 hbb_common gitlink 仍未找到，持久远端归档、代码导入和正式验收未完成；本轮没有执行远端写操作。证据见[当前检查索引](current-verification-2026-10-17.json)。

2026-10-17 08:49–08:52 再做四仓只读远端复核：136 个可见 refs 在采集期间稳定；66 个 Release 的 799 个附件共 16,177,009,767 字节，与此前重新哈希过的本地 archive report 按 asset ID、名称、大小和 SHA-256 全部相符。没有重哈希 16 GB，也没有把本地备份上传到远端；三项历史 gitlink 与持久远端归档仍是 finalization 阻塞项，详见[远端复核记录](history-audit/REMOTE-INVENTORY-2026-10-17.md)。

2026-10-17 后续契约检查修复：cargo xtask check 暴露 Cargo metadata 将本地 TURN 上游 fork 也报告为 workspace member，导致 Apache-only first-party 检查误报。检查现按固定 vendor 根目录区分供应代码与第一方包，供应许可仍由 cargo-deny 检查；新增 2 项分类回归。当前 xtask 测试、all-target strict Clippy（-D warnings）、fmt、契约/workspace 检查和两种网络策略检查全部通过。回执和日志摘要见[当前检查索引](current-verification-2026-10-17.json)。这一轮只改动 xtask 校验器；上一段完整 workspace runtime/Clippy 结果保留其原始输入范围，产品运行时代码未变。

本轮最新结果与原件摘要见 [当前检查索引](current-verification-2026-10-17.json)；以下按时间保留实施记录，历史失败和旧包结果不改写。

2026-10-17 当前源码完整回归：Windows x64 workspace runtime 在 141 个测试套件中通过 1187 项、失败 0 项、环境专用忽略 10 项；同一 1249 项输入的 all-target strict Clippy `-D warnings` 通过。Clippy 暴露 `run_audio_source` 参数过多，已按现有视频 worker 模式收拢为 `AudioSourceContext`，未改动音频处理逻辑；修复后的 SDK 当前源码回归通过 194 项、失败 0 项、忽略 1 项。Linux 当前原生恢复定向回归 77/77 通过；Windows daemon maintenance/process 子进程回归 7/7 通过。所有命令均保留源码前后哈希一致的回执；完整 Windows runtime、strict Clippy、SDK 回归及 focused follow-up 的日志和摘要在[当前检查索引](current-verification-2026-10-17.json)。这些是开发级源码证据；签名、ARM64 真机、真实桌面与跨网安装产品验收仍未完成，A01–A21 仍保持未通过正式验收。

2026-10-16 最新 Android 全源码复核：1070 个输入文件，源码摘要 `0e2b103b072c9de6ce07bc3b3ae2cd72d6af4ee1289106bb2509a6682055fa29`；BuildAttempt01 / MatrixAttempt04 在 API30–36 各通过 17 项，共 119/119，Kotlin/JVM 127/127。双 ABI release JNI、严格 Clippy、APK 组装与开发签名验证通过；全部模拟器为 x86_64、实测页大小 4096 字节。与最新 Windows/Linux 检查有 996 个相同输入且逐文件一致。正式签名、ARM64 真机、16 KiB 设备运行、真实 Projection/SAF/无障碍和跨网仍待验收，详情见 [Android 验收记录](ANDROID-VERIFICATION.md)。

2026-10-16 当前 Linux workspace 回归与 strict Clippy：视频发送器之前把多路已授权 source 交给单路 `VideoController::poll()`，导致第二路首帧和忙源恢复测试超时；新增按已授权集合轮询，单 source 切换仍使用原单路接口。`media-session` 全部 39 项通过，workspace 全量 141 个测试套件通过 1229 项、失败 0 项、忽略 12 项；all-target strict Clippy `-D warnings` 通过。daemon 三条 unused 警告移除后，又对 daemon 最终源码通过 28 项定向回归。回归期间获准临时暂停 `systemd-timesyncd` 并切换已有 Hyper-V 时钟源，workspace 测试采样 12635 次无跳变；结束后 `tsc` 与服务 `active` 均恢复并读回。完整日志、输入摘要及回执见[当前检查索引](current-verification-2026-10-16.json)。此为开发级 Linux 结果，固定安装产品、真实桌面环境和逐项正式验收仍未完成。

2026-10-16 Windows 当前源码定向检查：原生恢复 1/1、原生全目标 strict Clippy `-D warnings`、Web strict Clippy、WebRTC host 54/54、Web 22/22，以及 privileged broker 18/18、IPC 2/2、daemon broker 2/2、desktop broker 3/3 均通过。各检查的源码输入前后摘要一致、自有测试 scratch 已清理；Windows 汇总和每份日志/回执摘要见[当前源码 Windows 检查](../../artifacts/native-network-integration-20261016/WINDOWS_CURRENT_SOURCE_SELECTED_VERIFICATION.json)。旧 attempt18 的 Web strict 失败原件保留；更新 worker 接口后当前源码 attempt21 strict 通过。此结果不代替已安装产品、桌面输入设备、签名或真实跨网正式验收。

2026-10-16 屏幕选择与 Android 一次性授权增量的初轮记录：Kotlin attempt03 通过 126 项 JVM 回归并编译 instrumentation 源，Windows 新屏幕协议 44 项和契约检查通过。后续 Android 完整源码构建与七版回归已完成，使用 1070 输入、127 项 JVM 和 119 项 instrumentation；其他当前状态以本文件顶部索引为准。

较早的 Android 输入续租源码 cohort（1044 项输入）已通过双 ABI JNI/严格检查和 112 项 API30–36 开发仿真器测试；该结果绑定其冻结源码，现由上方 1070 输入的完整复核取代。原始事件与旧包证据仍保留在 Android 验收记录中。

2026-10-16 双管理入口控制实例修复：真实 TURN 联调暴露了夹具分别创建 AppState、覆盖同一数据库运行代次的问题。新增显式配置的管理入口视图，共享数据库、事件、配额与运行所有者，各入口仍签名自己的固定 origin 并使用各自 Cookie 设置。原实现的实际 HTTP 409 已先复现；Windows/Linux 对相同 1016 项输入各通过三项运行回归及 strict/fmt。测试验证两个入口的真实签名资源快照、跨入口重放拒绝、身份签名、错误 Origin 拒绝和两条 Cookie 标志；本批未修改时钟或校时服务。Build07 保留 1136 项源码和独立二进制，浏览器 TURN 连接另行验证，详见[独立运行核验](../../artifacts/g1-managed-turn-20261016/shared-runtime-followup-attempt01/RUNTIME_VERIFICATION.json)。

2026-10-16 输入续租真实浏览器复测通过：固定 Build06、同一冻结 Web 和探针下，Chrome155 / Edge155 / Firefox158 的 1080p30 + Opus、真实输入和文件各 36 秒检查均通过，平均 28.04 / 28.59 / 28.91 fps。三端各在实际签名续租后以 lease 2 发送 24 条输入，主机实际录制、文件字节、释放和自有进程/文件清理通过；[独立复测索引](../../artifacts/browser-input-renewal-20261016/BROWSER_REPLAY_VERIFICATION.json)绑定全部固定输入。主动网络损伤、受管 TURN、30 分钟 G1 和正式平台验收分别记录，Android 旧包不覆盖本次共享代码增量。

2026-10-16 输入续租修复：保留真实已接受的当前/上一签名许可，输入队列不再绑定到达时快照；原许可的墙钟/单调期限在设备锁后再次检查。延迟唤醒越过等待预算的红测准确复现后，固定等待上限并增加两项回归。Windows/Linux 对同一组 1015 项输入各实际通过 75 项，strict/fmt 均通过，Linux 时钟源与校时服务已独立读回恢复。新原生 Build06 与浏览器续租后输入复测继续进行，Android 旧冻结包保持原覆盖边界，详见[运行索引](../../artifacts/browser-input-renewal-20261016/RUNTIME_VERIFICATION.json)。

2026-10-16 Android 当前源码增量：重新冻结 1042 项输入并构建双 ABI release JNI、执行双 ABI all-targets 严格检查和组装新 APK；API30–36 同一对包各通过 16 项，合计 112 项。父任务逐 hash 核对 122 份证据、36 份外部产物和当前源码，并从原始日志逐项确认实际启动/成功结果后更新索引。首次 API30 工具包缺失的 0 项失败原件保留，后续仅补跑 API30–34；七台自有模拟器及测试临时目录已清理。Android 10 排除，开发签名与 4 KiB x86_64 模拟器不代替正式签名、ARM64 真机或真实系统授权验收，详见 [Android 验收记录](ANDROID-VERIFICATION.md)。

2026-10-16 原生自动中继增量：调用方未传 route 时，SDK 通过正常签名节点发现选择双方共同节点，使用绑定当前会话/端点/代次的共享 allocation，再走既有端点证明与中继竞速；`relay_only` 不收集或尝试直连。Linux 实际 6 项运行回归和两项严格 Clippy 通过；Windows 的原 attempt04 有三条不完整 `--exact` 名称只运行到 0 项，父任务复核时拦截了该批索引。保留原件后，只补跑缺失的三个完整模块名用例，各实际通过 1 项，与原有效 3 项共同组成 6 项结果。逐例原始日志、两个平台各自的依赖图和更正记录已独立核对，见 [索引集成回执](../../artifacts/product-completion-audit-20261016/PARENT_INDEX_INTEGRATION.json)；本组不代替浏览器 TURN、跨网或正式产品验收。

2026-10-16 最新媒体增量：优化 Build02 的 Chrome 1080p30 + Opus 本机短测通过，连续解码 36.027 秒、平均 28.15 fps、5 次实际管理续租，采集/音频 reset 和自有环境清理通过；固定站点已使用通过审查的 Web 依赖替代。该运行与另一夹具编译部分重叠，原生二进制不包含随后新增的 RTCP 适配，故未记为正式 G1 或 30 分钟性能通过，见 [浏览器与原生检查](BROWSER-NATIVE-VERIFICATION.md)。新 RTCP/VP8 增量已接入当前视频 SSRC 的接收端估计与丢包报告、受配置上限约束的降码率/缓升码率，以及有频率上限的关键帧请求；Windows 编解码 17 项、WebRTC 18 项及 strict02 通过，Linux 编解码 19 项、WebRTC 18 项和两包 all-target 严格 Clippy 通过，第一方 VP8 桥 ASan/UBSan 通过。最终 Linux 编译输入另有完整归档，详见 [反馈实现与验证](WEBRTC-RATE-FEEDBACK.md)。真实浏览器输入/文件检查及包含这些原生改动的新 Android 包继续验证，旧 Android 112 项记录仅覆盖原冻结包。

2026-10-16 发布与安装恢复增量已通过双平台定向回归：发布输入固定为有界私有快照，上传与最终状态检查期间持续核对 tag 指向；失败/取消安装释放进程锁并保留恢复 journal/startup fence，精确同字节恢复仍须匹配原控制者与版本记录。详情见 [安装实例](INSTALL-INSTANCES.md) 和 [原生打包](NATIVE-PACKAGING.md)，签名安装验收仍独立进行。Web 两项及 Foundation 最后一项缺失 MIT 原文依赖已通过保留上游许可的最小消费者替代移除；针对当前锁定图 766 包重新收集 1365 份 notice、2176 份原始归属文件，缺项为 0；同一全特性元数据的 cargo-deny advisories/bans/licenses/sources 全部通过，保留 58 条多版本警告。`protoc` v36.2 的 8 个平台包和 SQLite 3.50.2 bundled 源码已与上游发布字节逐项核对，完整来源和摘要见[非 Cargo 构建输入核验](build-input-provenance-2026-10-16.md)；protobuf 发布 tag 未签名，组织级许可证批准、完整非 Cargo 运行时依赖清单及发行材料绑定仍未完成。父任务逐项复核了 Foundation 的 7273 份证据及 242 个集成输入，实际 collector/Foundation/metadata 19 项检查通过；见 [Web 供应审查](web-vendor-license-removal-2026-10-16.md)、[Foundation 供应审查](foundation-dispatch-removal-2026-10-16.md) 和 [当前 Cargo 回执](cargo-notice-current-2026-10-16.md)。完整原文收集与许可证兼容、正式产品/发布验收分别记录；后续旧缺口数量仅表示对应历史批次。

较早的 Android BuildAttempt15 / MatrixAttempt13 在七个 API 各通过 16 项，共 112 项；这是已被后续 BuildAttempt01 / MatrixAttempt04 完整源码复核取代的历史包。该时点 Cargo notice 库存为 1352 份 notice、2182 份归属文件并缺 3 份 MIT 原文；后续 Web/Foundation consumer 替代使当时锁定图的 765 包收集完整。当前 766 包锁定图已按新 Cargo.lock 重新收集，见本文最新回执。完整收集不等于组织级许可证兼容审批或 G0 通过。

2026-10-16 系统栏主题修复后，BuildAttempt13 的 API35 16 项实测及浅/深截图核对通过，Kotlin attempt04 119 项通过。随后完整依赖审计发现 rustls 0.23.45 四项安全公告，现已升级 0.23.46、用既有 PEM API 移除 rustls-pemfile、迁移 TURN 示例至已锁定 Clap 4 并移除 atty；bincode 停止维护公告按准确 DTLS 调用可达性单独登记。更新后的完整 cargo-deny 与 Windows PEM/真实 TLS 加密数据 4 项回归通过，当时 BuildAttempt14 双 ABI 尚待验证；后续 BuildAttempt15 和完整源码 BuildAttempt01 已分别完成，最新数据列于本文顶部。当前 Android 状态见 [ANDROID-VERIFICATION.md](ANDROID-VERIFICATION.md)，依赖处置见 [TLS 审查](tls-dependency-review-2026-10-16.md)。另已完成保留 157 引用、11,845 个组件提交的单一 main 图组装和空库恢复预演，见 [历史预演](history-audit/FILTERED-HISTORY-PREVIEW-2026-10-15.md)；尚未正式导入或执行远端变更。

2026-10-15 Android BrowserHost 的 AV/input、SAF/剪贴板和 Compose 接线已集中合入，补齐真实租约在 Android worker 执行前复查、取消同意请求的 RAII 清理、JNI 类引用与局部帧错误处理、失败帧清零、三主导航和有界 Wi-Fi 接收锁。随后按既有令牌修正深色提示/错误文字，并将桌面专用采样定义按目标编译；最新 40 路径清单保留原字节与增量差异。119 项 JVM 测试、Windows/Linux 各 26 项 bridge Rust 测试、两端严格 Clippy 以及实际 Android ARM64/x86_64 release/all-targets 严格 Clippy 全部通过。BuildAttempt11 旧包在 API35、36 各通过 16 项；源码修正后停止其旧矩阵下载并保留失败记录，当时 BuildAttempt12 准备重建 JNI/APK 并运行新矩阵；后续 BuildAttempt13–15 和最新完整源码矩阵已完成，见 [Android 验收记录](ANDROID-VERIFICATION.md)。本批不改变下文 Linux 完整回归的四项失败状态，也不替代真机、正式签名、系统权限、跨网或完整视觉验收。

三个组件的历史路径改写及独立空库恢复均已通过：157 个引用、11,845 个提交逐一核验原 tree 与新 `legacy/<component>` subtree 的 Git ID 一致，commit-map 和独立 bundle 已保留。首轮 Windows 非法历史文件名失败、第二轮挂载盘缓慢重打包的中止原件均保留；第三轮改用 ext4 和工具官方 `--no-gc`，严格 fsck 与选定产品源码输入稳定性通过。随后从三个独立 bundle 恢复全部引用，再次通过逐 tree、可达提交数和严格 fsck 检查。尚未导入产品历史或执行 GitHub 写操作，见 [历史路径预演](history-audit/FILTERED-HISTORY-PREVIEW-2026-10-15.md)。

2026-10-15 Linux workspace runtime attempt02 已完整执行：日志汇总 1084 passed、4 failed、12 ignored，失败为 SDK WebRTC 续租 1 项和 node_relay 关闭回执 3 项；原批次仍为失败。787 个输入前后不变、日志哈希与自有 scratch 回收已核对，clocksource 已恢复并实际读回 `tsc`。后段只读观测确认 `hyperv_clocksource_tsc_page` 下墙钟仍回退约 0.87 秒，不能把临时时钟源切换当作环境已稳定。相同源码的 Windows 定向续租 1/1、全部关闭组 6/6 通过；后续获准临时暂停 systemd-timesyncd 后，Linux 完整 workspace attempt03 通过 1100/0/12，采样 12,644 次无时钟跳变，且 tsc 与 active 校时服务均恢复并独立读回；不能用 Windows 结果替代该 Linux 证据。精确汇总为 `artifacts/core-verification/native-workspace-runtime-review-20261015-attempt01-summary.json`。Android 数据补丁在隔离树通过 Rust 26/26、Kotlin 86/86、strict 与 ARM64 编译，且 SAF 两项边界完成独立复核；AV/input/Compose 组合在该快照时尚未合入；后续已集中接入并由当前 Android 完整源码矩阵复验。

2026-10-16 当前源码下 Linux 原生恢复定向用例通过 1/1，完整源码/日志回执见 `artifacts/core-verification/native-recovery-linux-focused-20261016-attempt01.receipt.json`。其后多 source 调度修复通过完整 Linux workspace attempt05：1229 passed、0 failed、12 ignored，并通过 all-target strict Clippy；此前失败 attempt01/02/03 保留为历史证据。Windows attempt14 的诊断确认失败请求为 `POST /permit`，attempt15 随 SDK 变更通过，attempt18 再按当前源码通过 1/1；当前 SDK 在 controller 的后续 lease 上使用 `GET /permit`，而服务端 `POST /permit` 调用仅签发初始许可的 `initial_permit`，`GET /permit` 调用 `current_permit`。这定位了许可路由与 lease 阶段不匹配的修正路径，但 attempt14 日志没有记录请求对应的 lease claims，故不把单次失败归因于过期或宣称已证明唯一根因。attempt18 的 612 项源码输入前后未变、自有 scratch 已清理；Linux attempt03 与 Windows attempt18 的恢复代码、测试和诊断输入摘要一致。完整回执见 [当前检查索引](current-verification-2026-10-16.json) 与 `artifacts/native-network-integration-20261016/NATIVE_RECOVERY_CURRENT_SOURCE_VERIFICATION.json`，结果仍是开发级检查，不代表固定安装产品或正式发布验收。
2026-10-15 浏览器到 Windows Core 的真实 View 链路现已通过三款稳定引擎：Chrome 155.0.8059.40、Edge 155.0.4283.45、官方 Firefox 158.0。每款均以自有 BGRA 图经过实际 VP8/RTP 解码连续观察 36 秒，完成五次签名管理续租，并在合成 online 事件触发实际 ICE 重协商后继续接收画面；capture reset 和自有环境清理通过。已合入带来源记录的锁定 ICE 库候选匹配修复，以及 Web 在重协商候选暂未就绪时保留原预算等待的修复。WASM all-target/all-feature strict 和 production 优化构建通过，原 Chrome04 重协商失败保留。精确原件与边界见 [浏览器与原生检查](BROWSER-NATIVE-VERIFICATION.md)。本机合成采集与事件不代替真实平台采集、OS 换网、TURN、签名或跨网验收。当时 Android BrowserHost AV/input 与 SAF/剪贴板仍处于隔离联合接线；后续已合入，并由 1070 输入、127 项 JVM 和 119 项 API30–36 仪器回归复验。

2026-10-15 Android BuildAttempt09 的双 ABI JNI、应用/测试 APK 和静态 16 KiB 对齐已完成；同一组包在 API 30–36 七版模拟器均各通过 12 项 instrumentation 检查，共 84 项。七版索引已重新核对原始测试、APK/源码、实际设备及清理回执，原失败批次保留。此后已集中修改三份 Rust 回归测试、共享 BrowserHost 的精确 request ID 接口和原生 ICE 配置；该历史 APK 组不覆盖这些源码变化。当时 Android BrowserHost 被控接线仍在隔离实现；后续已合入并由最新完整源码 JNI/APK 与七版矩阵复验。ARM64 真机、真实系统授权、16 KiB 运行和正式签名验收仍待执行，见 [Android 验收记录](ANDROID-VERIFICATION.md)。

2026-10-15 完整 Linux workspace no-run compile attempt02 已在稳定源码上通过；Windows workspace runtime attempt06 已完整执行，源码稳定且自有 scratch 回收，原批次有音频夹具、私有 Win32 剪贴板和 SDK QUIC 续租三个失败 target。集中修正三份 Rust 测试后，Windows 定向 native_audio 3/3、真实 worker 迟到回收 1/1、续租 2/2 均通过；三次 724 个源码输入一致，各自日志哈希与 scratch 清理回执已核对，汇总为 `native-runtime-focused-windows-20261015-attempt01-summary.json`。私有 Win32 station 仍受本机 OS error 5 阻断，旧完整批次保持失败状态。完整 workspace/all-targets strict Clippy 已通过 Windows attempt01 和 Linux attempt03；各 724 个源码输入不变、日志哈希匹配、自有 scratch 已回收。该组覆盖 request ID 接口、QueryOnly 和两处 lint 修复，不覆盖之后的证明时限或 Android BrowserHost 修改。正式 Web 与原生主机夹具已补齐 HTTPS、真实初始租约门槛、协议阶段诊断和失败后的管理清理生命周期；Chrome→WSL attempt04/05 未形成 ICE 候选对，Windows 本机 attempt02 已观察到 DTLS connected，但在端点证明的许可时限检查处关闭，媒体仍未通过，详见 [浏览器与原生检查](BROWSER-NATIVE-VERIFICATION.md)。

2026-10-15 官方稳定 Firefox 158.0 已通过 14 项本机所选检查，覆盖真实 SCTP 剪贴板读写、全部受控 Promise 生命周期、无激活拒绝、peer 关闭及页面退出后的 OPFS 恢复。采用固定 WebDriver BiDi 工具链，官方发行字节通过 SHA512SUMS 和 Mozilla Authenticode 核验；25 个工具包的版本、integrity 和完整许可证来源已入账。这些是稳定浏览器的无头开发检查，已安装产品、真实跨网和正式发布验收仍需执行，见 [浏览器记录](WEB-BUSINESS.md)。

2026-10-15 Linux ARM64：当前服务端 release ELF 交叉构建成功，并以实际 AArch64 程序在 QEMU user mode 下通过 13 项初始化、加密备份/恢复、覆盖拒绝与恢复配额封锁检查。工具包逐项按可信 APT 元数据核验后私有解包，没有安装/升级宿主包。逐文件源码、字节和执行范围见 [ARM64 开发记录](LINUX-ARM64-VERIFICATION.md)；本结果不覆盖桌面/daemon、ARM64 真机或安装包验收。

2026-10-15 最新集中结果：原生多屏、下载跨进程恢复与旧读取 owner 撤销、Desktop 回执隔离、Android 原投屏授权内选屏、共享音画时钟及 schema 20 服务累计配额均已合入。按每组最后一次执行，所选回归合计 Windows 280 项、Linux 290 项通过；两处夹具复验各 8 项和 server/daemon strict 两端通过。原失败批次保留原状态。独立外部签名账本的恢复对账 CLI 已实现，环境无外部账本材料时仍封锁；普通限额修改、重启及短租约到期不解除阻断。锁文件仅新增指向既有锁定供应包的直接依赖边，未升级供应版本。浏览器优化构建与三引擎本机所选检查已通过，其中 Firefox 为 Playwright patched engine。精确输入与边界见 [集中检查](NATIVE-INTEGRATION-CHECKS-2026-10-15.md)。当前源码 Android 双 ABI JNI/APK 和 API 30–36 矩阵另行构建；签名、真机、跨网和固定产物完整验收仍未完成。

2026-10-15 前一批集中检查：Windows/Linux 的长路径 2/2、加密迁移 6/6、服务发布与启动取消、IPC/桌面和 daemon 维护均通过。原十组批次各为九组通过、一组 Core 新增夹具超时，原结果保留；夹具补齐真实策略配置后，两端 Core services 4/4 通过。真实 Rust Caddy Admin 进程回归在 Windows 回环与 Linux 回环/Unix 上通过；server/Core 两端 all-target strict Clippy 和整体 rustfmt 通过。各组源码稳定、独有临时目录已回收、墙钟回退为零；WSL 时钟源已恢复并实际读回 `tsc`。准确输入与边界见 [本轮集中记录](SERVICE-HOST-PRODUCER-CHECKS-2026-10-15.md)。这些既有结果不覆盖之后的多屏、文件跨进程恢复、音画时序和持久累计配额修改。

签名构建 producer 与安全 Release 上传入口已合入，真实隔离 Gradle 配置/任务图/开发版本拒绝三项检查通过，修正了 AGP 配置阶段尚无 `preReleaseBuild` 的任务接线。更新后的固定 codec lock 对应 Windows/Linux x64 与 Android 双 ABI 供应库已从官方源码重建；两端各 36 项 Python 纯工具回归通过。尚未运行正式签名工作流、GitHub 发布或新 JNI/APK/最终设备矩阵，不能视为固定产物验收。

2026-10-15 当前查询/迁移增量：共享节点 query 的构造期限已从错误的 2 秒收窄至共享上限 1 秒；Windows/Linux 定向服务 library 29/29 和真实 HTTP→Node poll→QUIC→TCP 发布回归均已通过，覆盖半关闭、持续续期与实际停机。跨 schema 加密迁移 14 路径已合入；SQLite 正常锁定的 Windows 长路径修正后，两端长路径 2/2 和迁移 6/6 均通过，原四项 Windows 失败保留。六个受影响 crate 的两端 all-target strict Clippy attempt03 通过。Windows IPC 大视频回归已改为并发发送/接收，定向复验通过，生产超时与容量未放宽。

UDP/TLS 与安装代次增量已合入：19 路径原生数据报/显式后端 SNI/CA、UDP owner 清理补丁和 16 路径安装实例身份接线均已进入生产树。此前双平台完整批次 SDK 27/27、transport-quic 9/9、服务配置/恢复 24/24、daemon lib/维护/子进程、app-ipc 和桌面检查通过；运行库中的 Node/Storage 查询失败已在上述定向组修复并复验。安装/迁移策略/发布交接的合并 Python 纯回归为 Windows 14 通过/16 跳过，Linux 29 通过/1 跳过；结果不能替代真实签名或安装。6 条服务 API 的 OpenAPI 已从共享类型重建，整体 rustfmt 和当前契约检查通过。Caddy HTTP/HTTPS、本机 host 产品接线及签名 build producer 已合入；公网 ACME、固定身份签名、安装和正式跨网验收仍待执行。

2026-10-15 服务发布运行时接入：已合入 schema 19、持久 namespace/入口归属与容量承诺、独立节点资源 poll、固定身份的 service QUIC、真实 TCP listener→本机 backend，以及签发者授权的持续签名续期。TCP 访客 ACL/容量拒绝保留监听，普通线程析构保留原 runtime 的清理监督。6 条 API 的共享契约清单/模型注册已接线，生成 OpenAPI 和集中 Windows/Linux strict Clippy、实际运行回归正在推进。安装维护第一批 26 路径也已合入，尚不能记为已安装产品通过。具体范围与限制见 [服务发布状态](SERVICE-PUBLICATION.md)、[安装状态](NATIVE-PACKAGING.md)。

本批接入前 Linux 六组已完成，五组通过；daemon 一项 CLI 测试因夹具 pending 文件为 0644 被私有权限检查拒绝，已修为 create-private 并补明确拒绝宽松权限的实际 CLI 回归，待复验。所有六组都有源码稳定/自有临时目录回收 receipt，墙钟回退观测为零，临时内核时钟源已恢复并实际确认 `tsc`。接入前独立 SDK WASM library attempt02 通过，各库直接声明所需 UUID JS 随机源 feature。历史通过记录不覆盖本批新运行时代码。

2026-10-15 服务管理与本机配额维护增量：服务 registry schema 18、独立本机目标批准签名、SDK、Core 和桌面/Web/Android 管理页已接线。配置保存仍明确显示未发布，当前不据此宣布公网隧道完成。服务数据面新增独立短租约/挑战/主机证明、固定目标 owner、真实 TCP 半关闭与撤销，以及有界 UDP 目标映射。Windows 所选原生/Android bridge all-target strict Clippy 与 Web WASM strict 检查通过；当时 Android Kotlin 源码编译及 67 项 JVM 测试通过；后续完整源码通过 127 项 JVM 与 119 项 API30–36 仪器回归。Windows/Linux 集中运行时回归仍在执行，原失败与每组源码 receipt 保留；审查另发现并在隔离增量修复资源对象重建丢失撤销历史及 prepared target 连接期限，尚待合入复验。服务签发、真实 carrier 和完整 HTTP/HTTPS/TCP/UDP 产品接线继续实施，详情见 [服务发布状态](SERVICE-PUBLICATION.md)。

本机文件写入配额已加入只读 inspect、原始元数据 export 和保守 recover 命令。维护须取得既有稳定锁；不明用量饱和计费，不扫描用户文件或恢复授权。本轮 Windows 回归发现测试夹具在活跃 OS 锁下直接读取 marker，需调整读取时序；生产拒绝活跃 owner 的约束保留。下载 watch 的自然线程结束通知和 IPC 关闭 fixture 已修，集中回归中继续核验。当前 JNI/APK、已安装产品与正式跨平台验收未完成。

2026-10-15 最新接线与检查：原生剪贴板后端关闭/析构后，还须原真实线程实际 join 才公开清理完成；阻塞启动和未知 Drop 保留同一 owner，32 个工作名额只在实际 join 后释放。Windows 当前 strict Clippy 通过；22 项 lib 用例中 20 通过、1 个隔离子用例由父测试调度、1 个私有 Win32 window-station 回归失败。定向诊断明确是 `CreateWindowStationW` 返回 OS error 5，原失败及源码/日志 receipt 保全；新增六项通用生命周期和三项 Android adapter 用例均通过，但不能把整批记为成功。

浏览器当前 WASM strict 检查和 verification/production 两个优化 release 静态构建通过。验证入口也启用真实优化器，修正 Binaryen 对 Rust 生成的 nontrapping float-to-int 指令的特性配置。Chrome/Edge 所选本机检查通过，Firefox 的同源存储/真实剪贴板 RPC/七项受控 Promise 生命周期检查通过；无用户激活读取未结算，该项未覆盖，三浏览器整批仍为 incomplete。证据和范围见 [浏览器文件与剪贴板](WEB-BUSINESS.md)。Core 跨会话下载预算、daemon 根目录真实 owner 预算及接收配额的持久记账正在集中实现/验证；当前 JNI/APK 和 API 30–36 仍需从冻结源码重建，不借用历史 APK 矩阵。GitHub 最终切换继续等待完整实现、固定产物验收和历史保全。

2026-10-15 当前增量：原生文件 route、Core 任务持有、daemon 本机动态根选择、严格本地 IPC 和桌面浏览/上传/下载操作已接线，正在集中编译与回归。文件 claim 只在会话建立时领取一次；任务回复丢失或窗口离开不会丢失实际 worker，运行错误和物理清理分开。Windows COM 与 Linux XDG 系统文件选择器已接入，选择不代替本机业务批准。剪贴板接线另覆盖逐端本机方向批准、一次性操作、IPC 只含状态而不含文本，以及原 Wayland portal session/grant 的完整 binding；未选择方向时的稳定服务即时拒绝、Controller 读请求的可撤销本机守卫和清理 owner 保留已修正，新增回归正在执行。本批并未完成正式产品验收，详情见 [文件状态](NATIVE-FILES.md)、[剪贴板集成](NATIVE-CLIPBOARD-INTEGRATION.md) 和 [桌面运行记录](DESKTOP-RUNTIME.md)。

Android 音频 owner 最新 Kotlin/JVM 回归为 35/35，测试临时目录已回收；这仅覆盖 Kotlin/JVM，不覆盖当前 JNI/APK 或正式设备矩阵。Android 10/API 29 已按用户要求排除，后续仍验证 Android 11–16/API 30–36。

2026-10-15 Android 原生库阶段历史状态：用户明确排除 Android 10/API 29，验收范围为 API 30–36。当时 ARM64 release JNI 构建 attempt05、x86_64 attempt01 的 Cargo 构建及 ARM64 ELF 静态对齐检查已完成，但 APK 和七版仪器矩阵尚未完成。后续全源码 BuildAttempt01 / MatrixAttempt04 已通过 API30–36 的 119 项测试；ARM64 真机和正式签名仍待验收，见 [Android 验收记录](ANDROID-VERIFICATION.md)。

2026-10-12 开始，依据 [v3 完整方案](../NestLink_重构最终方案_v3_2026-10-12.md)。本文件记录实际代码和验证范围，不能替代正式验收。

2026-10-14 Windows 桌面增量核验：`cargo test -p nestlink-desktop --locked` 通过 7 项 UI/远控选择测试；`cargo test -p nestlink-daemon --locked` 通过 1 项实际子进程 singleton/重启/显式退出测试。更新 [桌面运行状态](DESKTOP-RUNTIME.md) 和 Android README，移除过时的“API 32–34 检查中”记录；Android 11–16/API 30–36 当前版本仍是 21/21 仪器测试通过。此批未完成桌面媒体呈现、独立会话窗、服务发布、Android 主机采集、ARM64 真机或正式签名验收。

2026-10-14 浏览器控制端使用管理会话签发 enrollment challenge，再用临时安装密钥注册为仅 `controller`、无 `host` 的短租约设备。服务端固定 10 分钟截止时间；过期端点不再出现在设备查询、远控请求、session/lease 有效性和 permit 续期路径中，也不能注册持久 device credential。schema 16 增加 expiry 并支持 15→16 迁移和当前快照恢复。每账号同时最多 16 个有效浏览器端点，名额在 SQLite 注册事务中检查，到期当秒释放。Storage control 36/36、snapshot 14/14、HTTP server 1/1、SDK 1/1 及本轮并发上限测试 1/1 通过；日志见 [control](../../artifacts/core-verification/wsl-browser-endpoint-control-20261014.log)、[snapshots](../../artifacts/core-verification/wsl-browser-endpoint-snapshots-20261014.log)、[server](../../artifacts/core-verification/wsl-browser-endpoint-server-20261014.log)、[SDK](../../artifacts/core-verification/wsl-browser-endpoint-sdk-20261014.log) 和 [账号上限](../../artifacts/core-verification/browser-endpoint-account-cap-20261014.log)。WSL 测试退出钩子已将临时 clocksource 恢复并确认 `tsc`。浏览器 WebRTC host 媒体应答、真实 TURN allocation 和产品媒体界面仍未实现。

2026-10-14 修复 AppCore 原生会话停止时 endpoint 生命周期提前结束的问题：停止任务持有 `NativeEndpoint`，直到会话 `wait_stopped()` 完成；endpoint watcher 关闭仍按 fail-closed 处理。Linux 定向会话/所有权/撤销测试 1+1+1 项、取消筛选 3 项与慢写撤销 1 项通过，AppCore focused Clippy 通过；Windows 的 app-core/daemon/desktop 定向编译与撤销筛选 6 项通过。日志分别保存在 [Linux owner 回归](../../artifacts/core-verification/app-core-native-session-owner-20261014.log) 和 [Windows owner 回归目录](../../artifacts/core-verification/appcore-owner-windows-20261014)。这只证明会话所有权与应用编译检查，不代表媒体 UI 或全平台验收已完成。

2026-10-14 新增 Web 生产构建工作流，以 Trunk 0.21.14 和匹配 Cargo.lock 的 `wasm-bindgen-cli` 0.2.129 生成静态 `dist/` 并上传 CI 构建原件；actionlint 和两个工具版本的 crates.io 元数据核验通过。托管 runner 尚未执行该工作流，本机未声称已生成发布站点。部署路径与当前 WebRTC/文件工作流缺口记在 [Web README](../../apps/web/README.md) 和 [媒体就绪度审查](../../apps/web-local/REMOTE-MEDIA-READINESS-2026-10-14.md)。

2026-10-14 下载工作线程和 SDK 增量加入磁盘调用前后授权检查、真实 prefix/verifier 提交、共享取消视图、专属工作回执、原操作期限、显式暂停屏障与同签名资源/源路径接续。真实 provider 错误不能因同时取消等待而被误当作可暂停；回执迟到消费仍按原截止时间拒绝。原生 SDK 拥有完整源请求，不因 UI future 取消而丢失半个协议，先停止保存后处理慢源清理；终态精确回收客户端可同连接继续下一文件。显式退休永久封闭原文件 claim，迟到文件帧不阻塞其他通道且不终止当前观看。公共恢复预算也检查之后发生的休眠或观察器关闭，不能仅信首个 NetworkChanged 历史回执。本机目录元数据基础另加入独立同意、no-follow 查找、有界固定快照、逐页重验、本机不可伪造 cursor、固定截止时间和拥有式阻塞线程。初版源码、时钟观察、provider PermissionDenied 漏保留清理及清理观察超时的失败日志均保全；完整本批输入及开发检查见 [下载工作线程检查点](download-worker-checkpoint-2026-10-14.json)。网络目录协议、上传、聚合文件配额、实际 GUI/daemon/Web/Android 文件流程、持久恢复及正式全平台验收继续实施，详见 [文件实施状态](NATIVE-FILES.md)。

2026-10-14 管理 Web 新增 Leptos CSR 工作台：必须先用管理员提供的部署 ID/签发公钥核验服务器，再以内存会话登录并支持 TOTP/恢复码。页面按服务端角色展示设备、待处理请求、节点、账号和审计；管理员可查看版本化网络策略、撤销对象及创建普通账号，审计按 50 条继续翻页并显示保留清理边界。操作请求期间控件锁定，过期会话/列表响应丢弃；登录、切服和退出清除本地凭据。Leptos 锁定版本和新增间接许可/维护例外见 [Web 依赖审查](web-dependency-review-2026-10-14.md)。WASM target check、WASM all-target Clippy、workspace fmt 和 cargo-deny 通过。当前只确认浏览器 Rust/WASM 编译，不代表已接入 WebRTC 主控、浏览器文件流程、生产静态构建/部署、跨浏览器视觉和辅助技术矩阵或正式验收。

2026-10-14 下载存储增量加入本地新建私有目录、单文件名/大小批准、实际暂存字节的前缀与完整校验、客户端 owner/UUID 绑定及完整源 `End` 的独立事实。取消不能冒充完成。原子 hard link 发布不覆盖任何既有目标；Windows 暂存句柄拒绝写/删除/重命名，Unix 能力固定原目录且检查实际磁盘修改。OS 调用及撤销后清理保留真实发布、关闭和清理状态，永不删除最终文件。首次 Linux 开发回归复现 `O_PATH` 目录直接同步的 EBADF，已以原能力的可同步读句柄修复，原失败输入保全。真实 TLS/QUIC、空文件、多块/续传、来源替换、合法块摘要但错误完整内容、取消/业务及本机撤销、目标冲突/链接、句柄固定和目录替换场景进入开发回归。本批检查见 [下载存储检查点](download-storage-checkpoint-2026-10-14.json)；拥有式目的端线程、实际 UI/SDK 流程、上传及正式产品验收仍未完成。

2026-10-14 文件读取批次已以 `0338a1a` 提交。WSL 在用户明确授权下临时切到 `hyperv_clocksource_tsc_page`，完整回归仍在两项节点控制测试失败；45 秒预检观察两次倒退，整个测试期间共六次，结束后已恢复并核对 `tsc`。后续只读定向诊断在第三次运行捕获 `lease pump` 的 `LeaseExpired: node wall clock rolled back`，实际约 3.3 秒停止；该次原因已经确认，不据此推断所有历史超时。节点 fixture 现在保留激活失败的拥有式完成结果，并在停机断言中保留经过时间/确切原因；正常期满另核对原本机租约截止时间。授权、停止预算和失败断言不放宽。Windows 五项节点控制测试和所选 Clippy 通过，Ubuntu 原失败与定向结果单列在 [节点诊断记录](node-clock-diagnostic-2026-10-14.json)，正式 Linux/产品验收仍未完成。

2026-10-14 文件读取增量加入唯一 Protobuf 契约、逐块/完整 SHA256、精确偏移续传和本机目录同意。Windows/Linux 使用固定官方 cap-std/cap-fs-ext 4.0.3 的句柄相对逐组件 no-follow 查找，拒绝穿越、设备/ADS、特殊文件、不同文件系统和多链接文件；Unix 源内容在完成前重新计算，Windows 句柄阻止写入/替换。独立文件线程不持有授权锁，活动/墓碑/工作槽有界；空闲根撤销退役句柄，精确缓存重试也检查本地同意。实际直接 TLS/QUIC、真实临时目录/Windows junction、块校验/续传、错误前缀、恶意响应、容量和阻塞磁盘撤销已通过定向开发回归。初始测试误把 Windows 根句柄视为允许重命名，实际是 OS 共享拒绝；另复现 FileRead 服务错误先被接收器析构改记显式退出，已改为先记录实际终态再析构；原失败日志保留。当前源码的完整检查记录单列，见 [文件状态](NATIVE-FILES.md)。目的端原子落盘、上传/目录浏览、Android SAF、完整产品流程、其他网络路径和正式验收仍未完成。

此前关闭回执的冻结源码已以 `17f9a18` 提交：Windows 完整检查 352 项 Rust / 37 项工具测试，Ubuntu 所选核心检查 148 项 Rust / 37 项工具测试；两端 358 件源码内容一致。完整 Ubuntu 回归和正式验收仍未通过，证据见 [关闭回执检查点](relay-close-checkpoint-2026-10-14.json)。

2026-10-14 中继关闭增量加入 schema 15：分用途节点签名只陈述精确分配的实际最终关闭，控制端原子保存回执/原 ACK、关闭预留并记录 Node 操作者审计。关闭与续租任一提交顺序均按稳定绑定处理；精确重试与控制重启返回原结果，恢复新安全代次拒绝旧事实，撤销后的清理不增加业务权限。WSS 在承载 socket/队列结束后确认；复查 Quinn 0.11.12 发现 `close()` 仍可保留底层缓存 UDP 包，因此 QUIC 另等待共享 endpoint 的 `wait_idle()`，两秒等待超时或取消保留原容量承诺。节点活动/待排空/待 ACK 分配总计至多 256，失败按原签名字节轮转重试，授权停止后另有固定五秒收尾。开发失败首先发现快照恢复版本范围未加入 15，以及 fixture 的退出原因/JSON 缺字段 HTTP 状态预期错误；修正后继续完整检查，原日志保留。实际 WSS/QUIC 关闭释放、新 UUID 准入、丢失响应、损坏 ACK、业务停止收尾及另一 QUIC 分配继续存活时不提前退款已通过定向开发回归。当前双平台完整回归、已安装产品、TURN/edge/隧道、聚合配额、完整客户端、签名和正式验收仍未完成；完整边界见 [relay-close.md](../../protocol-spec/relay-close.md)，本批固定源码检查单独记录。

2026-10-14 原生恢复增量将空闲故障观察、旧资源清理、双方签名重连、当前节点发现、新分配、QUIC/WSS 竞速与原生证明串联到 `recover_native_relay`。旧队列不复用，新会话拥有原网络观察器；取旧会话最新续租许可并保留原单调期限，退出/撤销在 HTTP、DNS 和连接期间可取消。协议错误、平台/时钟变化、休眠、清理失败及到期不自动重连。双方以签名交换 nonce 派生相同新 UUID；节点满额时允许当前分配的另一端发现该节点，额外 UUID 仍拒绝。开发回归先复现默认 Windows 栈溢出、QUIC 外层掩盖内层故障，以及最后名额被先到端预留后导致另一端发现为空；修复均保留错误/容量检查，失败日志未删除。测试观察器在任一方失败后曾重复读取关闭通道并产生大日志，已改为只等待未完成端并保存有限状态变化。完整双平台检查以 [verification.json](verification.json) 为准；当前 SDK 入口恢复明确选定的单节点，已安装应用、多节点切换、TURN/edge/隧道和正式验收继续实施，见 [原生恢复协议](../../protocol-spec/native-recovery.md)。

该增量最终 Windows 完整检查通过 331 项 Rust 和 37 项 Python 工具测试，以及 fmt、Clippy、WASM、契约、两种策略和依赖审计；Ubuntu 完整检查仍未通过。Ubuntu 首次完整检查在原节点续租/计量测试超时，定向诊断获得后台任务 `LeaseExpired`；之后十次定向检查通过，但完整运行另在交叉到达顺序和授权期限测试失败。只读 WSL 时钟采样持续观察墙钟约每 34 秒倒退 0.4–0.8 秒，单调时钟正常推进；180 秒预检未取得连续 60 秒稳定期。这些是开发环境证据，尚不证明每次超时的精确触发条件。节点新增拥有式 `wait_finished`、阶段/HTTP 状态及具体时钟拒绝原因，未改变租约预算或倒退终止条件。诊断测试的 watch 借用跨越异步完成等待曾造成阻塞，已改为先复制本地事实、释放借用再等待；原失败/超时日志保留。348 个冻结源文件及各次检查、诊断日志的摘要保存在 [本批开发检查点](native-recovery-checkpoint-2026-10-14.json)，`verification.json` 继续代表之前的重连增量，不能据此宣称当前双平台完整通过。继续实现仓库代码，不修改未经明确授权的 WSL 系统设置；Linux、已安装产品和正式验收仍需完成。旧 Release 另以正式全清单重验完成 799 件/16,177,009,767 字节的本地保全，远端保全、历史导入及最终仓库操作继续等待，见 [完整本地归档证据](history-audit/release-preservation-local-verification-2026-10-14.json)。

2026-10-14 重连增量加入 schema 14：双方安装密钥对完整当前许可、严格下一连接代次/租约序号和随机 nonce 签名，控制方使用原申请登录。事务比较更新请求与 session，清除旧信令并保存幂等回执和操作者审计。新许可保持原权限、路径、密钥、能力和到期时间；旧节点分配失效且承诺容量不提前退款。签发方以独立用途签名绑定精确双方请求与新许可，响应丢失重试只返回原结果；之后续租、撤销、恢复或到期拒绝旧回执。SDK 加入双方证明协调、旧 NativeSession 停止清理、原请求时钟和新端点构建。开发回归范围为实际 HTTP/WSS/外层及内层 QUIC 双向合成业务帧、两秒内旧两端停止、原发送队列拒绝、提交后丢失 HTTP 响应的恢复、SQLite 竞争和审计失败回滚。双平台完整检查以 [verification.json](verification.json) 为准；应用级故障检测/候选调度、WebRTC/TURN、真实跨网、72 小时、容量及正式验收继续实施，见 [重连协议](../../protocol-spec/reconnection.md)。

## 位置与隔离

工作树：`D:\代码\远程控制\NestLink`；分支：`codex/nestlink-v15-core`；基于 Hub `da66975153385f9d92643daa4b7d9f1efbaa7a7d`。原四仓和 14.1.0 未提交修改保留。现有 `distribution.json`、14.x 下载和生产部署未变更。

新第一方代码为 Apache-2.0，独立依据方案实现。本批未迁入 RustDesk 派生 Rust/Dart/平台模块或旧业务源码。新构建只使用显式 workspace 成员，不连接 hbbs/FRP/Go/Node/Flutter 运行入口。旧 Release 工作流限于 14.x，15.x 不会被旧打包脚本误发布。

## 已实现

2026-10-14 签名节点发现增量加入 schema 13：管理员以版本比较更新 QUIC/WSS 地址，默认空表不新增节点权限。当前登录和端点持钥请求绑定完整许可摘要与随机 nonce；现有固定签发公钥以独立用途签名五秒、至多 16 节点的响应，绑定节点公钥、当前运行和配置代次。SDK 在 DNS 前验签并匹配当前分配，保留原请求单调期限和一次解析的固定地址，复用响应或 route 不延长期限。分配只包含配置允许的传输；地址更新撤销旧代次资源，旧 UUID 不采纳新配置且容量不提前退款。当前实际 HTTP→SDK→WSS/外层与内层 QUIC 回归已通过双向合成业务帧、两秒内撤回停止和旧代次/签发方/响应期限拒绝。最终双平台全量结果以 [verification.json](verification.json) 为准；真实多节点 DNS、已安装产品、跨网和正式验收继续实施，见 [node-discovery.md](../../protocol-spec/node-discovery.md)。

2026-10-14 双端中继配对增量将独立 WSS/QUIC 接入同一有界选择器。服务先验证原分配、端点与随机挑战，等待同一传输的双方到达后才提交资源；候选固定准备时的签发方和原票据单调期限，配对时重查当前授权，等待不占业务连接/字节额度。两个监听器共享套接字和 IP 速率预算，精确 token 清理及败选候选丢弃不关闭获选通道；已提交后的关闭仍退役分配 UUID。真实套接字验证单端 UDP 黑洞的两个方向、交叉到达顺序及任一传输胜出、同节点两个批准地址、重复候选、等待取消/超时/撤销，以及败选清理后的双向业务。原过期、续租、关闭 UUID 和配额测试保持。完整双平台结果以 [verification.json](verification.json) 为准；该增量不等于正式容量、跨网或已安装产品验收。签名发现和提交失败后的协调重试继续实施，详见 [relay-selection.md](../../protocol-spec/relay-selection.md)。

2026-10-14 独立 QUIC 数据报增量加入外层分配固定的节点 TLS 公钥、专用 ALPN 与随机端点挑战，双方端点通过 1200 字节虚拟 UDP 终止内层 QUIC，再完成原生证明和独立通道协商。分片、重组、过期、队列、速率和监听任务均有界；QUIC/WSS route 接入现有策略/网络代次约束的统一竞速，真实回环验证 UDP 不可达时 WSS 胜出。网络变化回归先发现内层停止后外层未及时关闭，已以显式 carrier owner 和内层关闭观察器修复，保留失败原件。WSS loopback 默认改为 28746，为 TURN/TLS 28745 留出监听空间。完整实现与开发/正式验收边界见 [independent-quic-relay.md](../../protocol-spec/independent-quic-relay.md)；签名地址发现、已准入后的跨传输重试、TURN/edge、真实网络负载及全量产品仍未完成。

2026-10-13 独立 WSS 转发增量加入 `nestlink-server relay`、节点 origin 的专用挑战/分配/端点签名接入、两角色有界密文队列及共享计量。服务不读取控制数据库，也不接收管理 bearer；SDK 按管理员明确批准的本地 origin 一次解析、固定实际地址并保留正常外层 TLS 校验，随后两端完成内层双向 TLS 与原生会话证明。写入前复查当前授权，guard 拥有最早节点/快照/分配期限的独立定时器，队列满时在锁外有界等待且重查授权，失败不计量；监听退出/取消停止全部空闲连接和控制，精确 token 清理不影响其他登记。八项真实 HTTP/SDK/WSS 联调通过双向业务帧、两秒内空闲撤销/查询失联/监听取消、配额变更与字节耗尽、错误 key/transport/challenge 重放、已关闭 UUID 和非法路由拒绝，以及原分配期限之后的同连接续签；增加无 watchdog 的期限测试和 hub 有界队列检查。当前业务帧为合成测试内容，正式 Caddy TLS、统一候选竞速接入、QUIC 虚拟 UDP、TURN/edge/隧道、UI 和完整产品验收仍待完成，详见 [independent-wss-relay.md](../../protocol-spec/independent-wss-relay.md)。最终双平台完整验证以 [verification.json](verification.json) 为准。

2026-10-13 独立节点资源快照增量加入注册节点签名的短期限查询、策略密钥签名且绑定原请求摘要的当前资源响应，以及原分配票据/端点公钥/传输/服务挑战共同验证的连接 guard。两端共用速率和累计字节额度，失败入队不计量，已关闭 UUID 不复活；相同 grant 不重算单调期限，只有仍存活且稳定绑定一致的更高序号才能续期。快照失效、业务撤销、配额/签发方变化或控制析构同步停止 guard，数据服务须在读写和空闲等待中观察停止。SQLite 查询只读当前业务事实，不续租或释放容量；原控制租约/报告通道与资源授权分别执行。定向签名、存储和 HTTP/SDK 联调已通过，实际空闲 loopback socket 在节点撤销后两秒内关闭；完整双平台检查以最新 [verification.json](verification.json) 为准。真实独立 WSS/QUIC 业务转发尚未接入，见 [node-resources.md](../../protocol-spec/node-resources.md)。

本批 Ubuntu 全量检查发现 `node-init` 会拒绝以 `-` 开头的合法 base64url 策略公钥；固定公开测试种子在 Windows 先确定性复现失败，修正 CLI 参数取值后继续双平台完整验证，并核对实际保存的公钥。原失败日志保留，未改成只规避该字符的测试数据。

2026-10-13 中继持久容量预留增量加入 schema 12：独立节点分配和组合 WSS 共用全局分配/双方账号名额，节点另预留两端连接。设备签名申请绑定完整当前许可，独立用途签名票据绑定节点运行、公钥、会话及策略/配额代次；期限不超过远控/节点已有期限及十秒，相同有效申请幂等，过期 UUID 不复活。撤销或运行接管保留旧签发期限内的容量；WSS 的 DB 结果边界拥有清理 guard，双方实际停止后按精确连接 token 释放，旧清理不删除替代连接。续租只有新许可代次才能延长持久承诺。AppState 冷重启/备份恢复先等十五秒加一秒单调屏障；未知快照后承诺和墙钟跳变不能绕过容量。新增管理员 HTTP/原生及 WASM SDK 查询、独立节点申请，以及存储/签名/真实 HTTP-WSS 取消、共享准入和既有 TLS 中继撤销回归；最终检查证据以 [verification.json](verification.json) 为准。独立资源快照、资源 guard、实际节点 QUIC/WSS 转发和正式产品验收仍未完成，票据不能替代业务授权，见 [relay-allocations.md](../../protocol-spec/relay-allocations.md)。

2026-10-13 独立节点运行代次与持久计量增量通过 Windows 220、Ubuntu 251 项 Rust 开发测试、两端各 15 项 Python 工具测试及 fmt/Clippy/WASM/契约/策略/当前依赖审计。schema 11 保存每次启动的 UUID、签入证明/租约的持久代次与有界重放墓碑；新运行使旧连接失效，退役/到期的 UUID 不能复活，恢复旋转安全代次并清空当前运行指针。节点提交分用途签名的累计连接/入队字节报告，最新相同字节重试返回原确认和接受时间；序号、时钟、计数回退、跳号、旧运行、错误签名、非当前策略/租约和不一致配额拒绝。管理员 HTTP/SDK 提供安全代次绑定分页。所有本地角色共享连接容量和允许一秒突发的令牌桶，RAII guard 在成功入队时计量、析构一次关闭；初次确认前不开容量，确认失败停止授权，每次入队仍需独立资源/会话许可。真实 HTTP/WSS 验证累计报告、并发新运行接管与两秒内旧授权/管理员撤销停止，确认重试不延长失联租约。复查首先复现任务首次 poll 前析构不立即通知的问题，修复为同步停止通知后，两端最终完整检查重新通过；原失败日志和两端首轮通过原件保留。精确毫秒状态、签名用途、存储/审计耗尽回滚和迁移边界也已验证。当前数字为节点自报的最后已确认入队累计，不证明送达或崩溃后的最终关闭数。独立 QUIC/WSS relay/edge 数据服务、控制侧资源预留、跨节点/账号/设备/资源总额度、TURN、隧道与产品验收继续实施，见 [node-usage.md](../../protocol-spec/node-usage.md)。

2026-10-13 组合 WSS 中继配额增量通过 Windows 207、Ubuntu 238 项 Rust 开发测试、两端各 15 项 Python 工具测试及 fmt/Clippy/WASM/契约/策略/当前依赖审计。schema 10 持久保存管理员版本化的分配数量、账号端点、每分配双向速率和累计字节限制，事务同时保存管理操作者审计；SQLite 重开和快照保持配置。改变配额版本会关闭既有分配，独立停止 watch 不受满数据队列影响，连接监督另重查持久版本；延迟登记/旧连接清理不会回退限额或删除替代连接。新增运行 ID/报告序号绑定的接纳字节、容量与关闭计数，重复读数和清理不重复扣量。真实 SDK→WSS 内层 TLS→已授权数据→零容量配额验证了两端关闭和新分配拒绝。首次编译的名称遮蔽及两个测试接收器过早析构的问题已修复后验证，原日志保留，没有作为已安装产品回归宣称。独立节点持久计量、账号/设备/资源聚合额度、QUIC/TURN/edge、配额 UI 与容量/固定产物验收继续实施，见 [relay-quotas.md](../../protocol-spec/relay-quotas.md)。

2026-10-13 审计操作者增量通过 Windows 200、Ubuntu 231 项 Rust 开发测试、两端各 15 项 Python 工具测试及 fmt/Clippy/WASM/契约/策略/当前依赖审计。schema 9 保留旧记录并标记未知操作者；新记录区分管理登录、已验签安装、用途绑定凭据、本地操作与未认证尝试，事务核对账号/登录/设备/安全代次关联。已实现业务事件加入操作者，补齐远控申请、首次许可、实际恢复码消费和计算前持久密码尝试；取消后 SQLite 重开仍保留证据，状态转换重试不重复记录。管理员变更另核对当前数据库角色与登录身份；HTTP 策略/设备撤销保留实际管理操作者。首次完整检查的测试模块位置 lint 已调整后重跑通过；失败日志保留，没有把静态问题称为产品回归。审计 UI、尚未实现的中继/edge/TURN/公开服务/配额事件、负载与固定产物验收继续实施，见 [audit.md](../../protocol-spec/audit.md)。

2026-10-13 审计管理增量通过 Windows 195、Ubuntu 226 项 Rust 开发测试、两端各 15 项 Python 工具测试及格式/Clippy/WASM/契约/策略/依赖审计。新增当前数据库管理员角色校验、绑定恢复安全代次的最多 100 条升序分页，以及默认 30 天、范围一小时至一年的版本化保留配置。业务事件事务分配持久序号，清空后不复用；计数器耗尽回滚业务操作。控制服务每分钟最多清理 500 条过期元数据，保存清理时钟/游标并向服务入口报告实际故障；不在线 VACUUM，不声称安全擦除数据库页或备份。迁移、恢复、权限降级、退出/过期、SQLite 关闭重开及真实 HTTP/SDK 场景通过。完整操作者归因、各业务事件覆盖、审计界面、配额/节点计量与固定产物验收继续实施，见 [audit.md](../../protocol-spec/audit.md)。额外原生平台 fixture 保留旧原件并明确标记复用。

| 模块 | 实际行为 |
| --- | --- |
| protocol | 唯一 Protobuf 源生成消息/权限/错误类型；独立 ALPN、API、schema；消息预算、非零 UUID、代次、权限、路径和能力校验 |
| identity | Ed25519 许可签名、可信签发公钥验证、分用途签名域、原始字节签名校验、端点持钥证明 |
| auth | Argon2id、随机令牌、账号绑定的 TOTP 加密、TOTP 防重放与一次性恢复码 |
| policy | 全局三项策略验证；全局/账号/设备/资源/会话/双方本地路径集合求交；公网隧道与远控路径分别判断 |
| session | 许可绑定部署、身份、公钥、资源、权限和代次；双方证明完成前拒绝业务；租约有界、旧响应拒绝、撤销/过期/休眠/换网/退出为终止状态 |
| storage | 新 SQLite、账号安全/管理会话、设备登记、审批/续租、显式受信设备授权、持久化范围策略；原子刷新、撤销与恢复安全代次失效 |
| server | Axum 管理 HTTP/WSS、bootstrap、账号、设备、审批/许可、策略与事件；有界工作/消息预算、Origin/CSRF/Cookie 隔离和速率限制 |
| platform-network | Windows IP Helper 地址/路由/接口通知、Linux kernel-only route-netlink；有界合并事件、休眠时钟差、关闭/失效终止；SDK 在建立 socket 前捕获代次，变化后清空 STUN 并中断各传输竞速 |
| platform-security | Windows 当前用户 DPAPI、Linux 服务用户私密文件；拒绝覆盖、链接和异常尺寸；最小 DPAPI unsafe 边界单独审查 |
| platform-input | Windows SendInput 物理键/指针/Unicode、共享观察器主动监护原 WTS 登录/连接，固定首次清理预算；X11 XKB/XTEST 与稳定 Unicode 映射、logind 会话检查和同服务清理；Wayland 新门户同意与撤销监护；真实 IME、Android 和产品接入继续实现 |
| platform-capture | View/连接代次约束的 VideoController；PipeWire 已授权 FD 与真实 source/link 绑定、Windows GDI、自有会话 X11 GetImage/光标；撤销与 worker 错误分别报告；Android、完整格式适配和产品媒体接入继续实现 |
| platform-session / platform-audio | 画面与音频共用只读 Windows 会话观察器，X11 输入和 Linux 音频共享原 logind 监护；独立 WASAPI/PipeWire worker、固定输出身份与真实 Link、系统 48 kHz PCM 转换、有界队列/flush、sticky 失效和清理错误；Linux 私有 44.1kHz 六声道转换与 signed lease 撤销验证通过，真实硬件/产品音画同步与 Android 后端继续实施 |
| transport-stream / transport-quic | 双向绑定安装 Ed25519 公钥的 TLS 1.3、TLS transcript 签名校验、直接 TCP 和 QUIC；消息/流内存预算、禁用 0-RTT 与 TLS 会话恢复 |
| remote | 两端连接挑战和持钥证明；逐通道权限/路径/租约检查，撤销中断等待中的 IO |
| media-codec / media-session | 固定官方 VP8/Opus 原生库及安装哈希校验；独立 codec 线程、授权视频交付与有界关键帧反馈/恢复，以及唯一音频消费者→Opus→PCM 入队、bounded PLC/reset 和共同撤销；音画同步、浏览器媒体和产品 UI 继续实现 |
| connectivity | IPv4/IPv6/LAN/反射/授权中继候选的有界调度、代次失效、路径限制；直连优先保留中继并发槽，强制中继不探测直连；SDK 已接入真实候选采集、QUIC/直接 TCP-TLS/WSS 联合竞速与 Windows/Linux 系统网络通知 |
| sdk | 共享 Rust 原生/WASM 管理客户端、部署与签发者信任锚、设备签名、双端许可与续租；原生 HTTP 和浏览器 Fetch 拒绝重定向，限制超时和流式响应大小 |
| apps/android | Android Compose 管理端、服务端身份核验/登录/设备登记与撤销；控制端可发出仅查看授权请求、读取请求状态并撤销；安装密钥以 AES-GCM 密文保存在 SharedPreferences，AES key 留在 Android Keystore；JNI 直接接入 SDK；API 36 编译/target，ARM64 与 x86_64 原生库 |
| signaling | 与当前许可绑定的设备签名候选及 SDP/DTLS 指纹，服务端和接收端均验签；有界 SQLite 最新信令、序列/网络代次防回退，限制危险地址和许可路径 |
| native WSS relay | 同机 control 内组合中继，端点挑战持钥认证和配对；内层固定双端公钥 TLS 1.3，服务端只转发密文；有界队列/背压、管理员持久配额、运行代次计量、独立停止 watch 和 250 ms 授权/配额版本检查；独立节点角色与持久计量仍待实现 |
| traversal / native discovery | 真实 STUN Binding/XOR IPv4/IPv6、指纹校验和有界服务端；QUIC 共用 UDP socket 探测、指定源/随机事务/网络代次绑定、GRO 保留与洪流让出；SDK 采集当前已启用 OS 地址并发探测配置的 STUN，relay_only 无探测 |
| operations / backup | SQLite 一致性在线快照、64 MiB/10秒预算、固定 Argon2id + XChaCha20-Poly1305 认证归档；只恢复到新私密目录、重建固定路径并重新保护密钥；新安全代次撤销旧登录/许可/恢复码和当前 TOTP 窗口，命令不启动监听 |
| node control | 管理员登记独立节点和配额；专用节点持钥挑战、独立派生的策略签名密钥、10秒租约/3秒续租；WSS 控制容量与消息预算、250 ms 撤销检查；节点在阻塞 IO 时也按单调期限终止，独立节点数据业务仍待接入 |
| xtask | 从 protocol-spec 共享模型和实际路由清单生成 OpenAPI 3.1，检查路由/规范漂移、版本与构建图 |
| CI | Windows/Linux fmt、clippy、安全测试与契约检查；protocol/policy 的 WASM 构建检查 |

2026-10-14 Android 增量将应用升级到 compile/target API 36，并加入身份核验、Keystore 密钥持久化和 JNI 远程查看请求烟测。最终 `com.zhanry.nestlink` Debug APK（minSdk 30、targetSdk 36）及所含 ARM64/x86_64 Rust ABI，在 API 30–36 x86_64 模拟器上各通过 3/3 项仪器测试，合计 21/21；最终 APK SHA-256 为 `637c5a10bf7b476616f3571f141127249375df558638eda0efb4956f80cf061a`，源码输入指纹为 `569be52a4dfba761e0c073f47d1b6655ab6e6579e04c897542b27732091d89cb`。逐版测试日志、包和 JNI 哈希、源码文件哈希及临时环境清理记录见 [Android 验收记录](ANDROID-VERIFICATION.md)；API 30–34 临时 AVD 与 system image 已删除，既有 API 35/36 AVD 在测试后关闭。API 29 按用户明确要求排除，签名脚本从 API 30 检查安装 SDK 范围兼容性。真实媒体会话/画面/输入、Android host、MediaProjection/编码/音频、SAF 文件及服务发布仍待完成；ARM64 真机运行尚未验证。Release 签名证书未配置，Debug 产物不构成发布验收。

2026-10-14 浏览器控制端新增底层 receive-only WebRTC peer：调用方必须传入与 `VerifiedPermit` 匹配的临时浏览器身份/租约，以及来自部署可信配置的 ICE servers。它发布签名 offer、读取 SDK 验证的签名 answer、按候选 pair stats 执行 permit 路径校验、向调用方交付真实 remote track，并在取消、授权到期、连接失败、路径不符、pagehide 或 document freeze 时关闭。调用方观察到网络变化后可发起带单调发送端网络代次的 ICE restart；answer 必须绑定精确 offer 序号，服务端事务核对最新 offer，浏览器忽略旧 offer 的迟到 answer 并拒绝指向未来 offer 的 answer；重启失败关闭旧连接。`direct_preferred` 在 permit 只允许 relay 时降级成 relay-only，强制 `iceTransportPolicy=relay`。协议、SDK、storage/Web 回归测试、WASM `cargo check`、契约检查、全仓 fmt、protocol/SDK/storage/Web 全目标严格 Clippy 和 `git diff --check` 通过。Windows GNU target 因缺少 MinGW 编译器未能检查。该 peer 尚未接入管理 UI；host SDP answerer、可信 TURN 配置服务、permit 续租、UI 网络观察器接线与真实跨浏览器媒体验收仍未完成。

开发测试随各增量持续运行，最新实际通过数量、源码文件哈希和检查日志摘要见 [verification.json](verification.json)，原始日志位于 `artifacts/core-verification/`。额外原生测试分别使用独立网络命名空间、自有 Xvfb、私有 D-Bus/PipeWire 服务与 Windows 自有窗口；需要特定环境的测试显式 ignored 并单独保留运行记录。本地套接字、合成像素和隔离显示服务不能替代跨网、真实媒体、平台安装和容量验收。

依赖审计使用 cargo-deny 0.20.2，本批 RustSec 公告库提交 `d8325cf4f578e2df4cc5b98a30e9f46b3b88e9f0`，已通过 GitHub API 与 fetch 后的本地提交一致性检查。旧版审计工具不支持 CVSS 4.0，已升级工具后重查；使用核验的当前公告库离线审计。没有忽略安全公告。保留上游不同版本线的依赖并存警告。新增 HTTPS/WSS 根证书数据使用 CDLA-Permissive-2.0，完整许可证已审查、摘要入账并放入 packaging/notices；cargo-deny 只为 webpki-roots 记录该许可的例外。

历史默认规则扫描：Hub 38、Server 5、Client 143、Android 0 条告警。Server 5 条已逐条核对为文件 SHA-256；Hub/Client 181 条已逐条分类，178 条误报，3 条公开上游 Firebase 客户端配置仅随原许可证历史保全、不进入新产品，见 [维护处置](history-audit/DISPOSITION.md)。没有复制秘密值或用批量忽略清除告警。[脱敏索引](history-audit-index.json) 记录路径、规则、提交、行号和原件摘要；历史尚未导入。

OpenAPI 已定义实际管理操作和共享 JSON 模型，运行方法见 [SERVER.md](SERVER.md)。原生通道已接入会话证明和撤销；真实平台输入已开始接入会话监护；完整输入、文件写入、TURN allocation、跨网和全平台 UI 继续实现与验收。完整产品尚未实现完毕。

后续增量加入 SDK、签名信令与原生 WSS 中继。实际 HTTP→账号→设备→审批→双端续租→QUIC，以及 HTTP→WSS→内层双向 TLS→双方会话证明→512 KiB 业务测试帧→服务端撤销，均有集成测试。测试帧不代表屏幕采集或编码。密码计算已移出服务端数据库锁；事务重新检查密码/管理会话代次/安全代次，阻止延迟计算复活旧身份。此增量的完整跨系统检查结果以最新 verification.json 为准。

候选采集增量使用与 QUIC 相同的 UDP socket 完成 STUN，已测试实际反射源端口与后续 QUIC 源端口一致、旧网络响应与伪源响应拒绝。OS 地址仅作为签名候选，不能代替 TLS 对端身份验证或实际可达性检查；独立节点数据服务与完整平台接入继续实施。密钥读取改为打开句柄后的元数据/属主/权限检查，Linux 最终路径禁止跟随链接，Windows 打开 reparse point 后拒绝；这不是文件传输的目录能力实现。

SDK 的 NativeEndpoint 绑定当前许可中的本地设备及双方公钥摘要，在同一 STUN/QUIC socket 上调用已有 Scheduler 执行真实 QUIC 候选竞速。私网/ULA 拨号需配置允许的 CIDR，硬性危险地址仍拒绝；本地网络代次与对端信令代次分开检查，候选任务在成功、取消、换网和许可过期时丢弃。真实错误 TLS 对端不会获选，随后正确候选能完成双方 native proof。测试使用仅 cfg(test) 存在的回环例外，正常构建没有该例外；不能替代真实跨网验收。联合竞速进一步接入直接 TCP/TLS 和已批准的管理入口 WSS，Windows/Linux 系统网卡/路由通知已接入监控构造器，UI 与 Android 生命周期仍待接入。

联合竞速使用同一个 12 秒总预算、6 秒单次预算、最多 4 个并发尝试。relay_only 不创建 UDP 端点，拒绝全部直连候选；RelayRoute 从已配置管理 origin 一次有界解析，并将实际 TCP socket 固定到解析结果，保留 HTTPS 域名/SNI/证书校验；对端声明不能替换中继 URL、端口或凭据目的地址。路由绑定完整许可摘要，换会话或换租约后重新生成。开发用明文 WS 即使通过 localhost 解析，也只允许实际回环地址。TCP/WSS 与 QUIC 共用取消、网络代次、单调许可期限和墙钟回拨检查。真实 UDP 黑洞→TCP/TLS→双方 proof→授权数据、等待中 TCP 握手关闭、强制中继的伪地址拒绝与无直连，以及服务端撤销的本地开发测试通过；正式 WSS HTTPS/跨网/企业链路仍待固定产物验收。

## 本地复现

2026-10-17 Web 管理员服务配额页已接入：管理员可按账号、设备、数据节点或服务资源查看已确认字节、未结清授权、活动授权数、最近节点运行代次和恢复对账状态，并基于当前配额修订保存新上限。过期修订由服务端拒绝；写入结果不确定时页面清除旧读数，要求管理员重新读取。WASM `cargo check`、严格 Clippy、release 编译、Trunk release 站点与资产检查，以及真实 HTTP/SDK 定向测试通过（1/1，含读取、更新和过期修订拒绝）。构建器会给 CSS 内容加哈希，已修正 CI 校验，改为检查 stylesheet 引用和非空 CSS/JS/WASM；这仍不等同浏览器安装产品或正式验收。

2026-10-17 固定密码 UI 接入桌面端与 Android：被控端可读取当前修订、配置/轮换/撤销；控制端可读取待处理请求对应的权限、路径、期限和修订，并只对该请求提交密码。桌面端以 `Zeroizing<String>` 管理输入；请求失效、offer 刷新或加载失败会清除输入并隐藏旧范围。Android 同样在刷新前移除缓存范围，输入不写入保存状态，并通过现有安装密钥和 app-core/bridge 动作签署配置与授权。Web 固定密码 UI 暂不提供：当前 Web 会话使用临时身份，没有协议要求的已登记持久控制端私钥；被控配置也要求已登记 host capability 和本机密钥。此限制记录于 [remote-password.md](../../protocol-spec/remote-password.md)。界面开发检查与正式签名、安装产品、daemon 本地同意、完整配额/审计和固定产物防爆破验收分开记录。

2026-10-13 固定密码授权协议与服务增量通过 Windows 187、Ubuntu 218 项 Rust 开发测试、两端各 15 项 Python 工具测试及 fmt/Clippy/WASM/契约/策略/最新依赖审计。被控端通过独立签名和一次性挑战配置权限、路径、版本与期限；主控端以安装私钥签署当前请求和密码尝试。Argon2 计算在数据库锁外进行，提交前重新核对登录代次、双方公钥、配置版本、策略和期限。每被控设备每分钟 5 次、每主控账号每分钟 30 次尝试在计算前持久化；并发/取消、SQLite 关闭重开、跨账号/设备、刷新登录、改密与时钟回退测试通过。固定密码撤销和替换分别通过真实 HTTP SDK→WSS 内层 TLS→双方证明/数据/续租验证实际关闭两端连接。schema 5/6 升级不继承密码权限，恢复清除校验值；固定产物防爆破验收、完整配额/审计仍待完成，见 [remote-password.md](../../protocol-spec/remote-password.md)。

2026-10-13 受信设备授权增量通过 Windows 177、Ubuntu 208 项 Rust 开发测试、两端各 15 项 Python 工具测试及 fmt/Clippy/WASM/契约/策略/依赖审计。当前许可之外的独立 host 签名登记双方固定公钥、批准权限、路径、版本与期限；旧版本签名和删除不能影响新授权。更新/撤销原子失效关联会话，分别通过实际 WSS 内层 TLS 连接验证关闭；续租不能越过授权期限。合法长度的未知 bearer 曾在认证前占用限流表，保留旧处理代码的失败复现与修复后测试；刷新令牌仍使用同一登录会话的限流预算。schema 5→6 不把既有审批转换成长期信任。受信 UI、daemon 本地同意、固定密码授权、防爆破及完整配额/审计仍待实现；协议见 [trusted-devices.md](../../protocol-spec/trusted-devices.md)。

2026-10-13 原生视频反馈增量通过 Windows 168、Ubuntu 199 项 Rust 开发测试、两端各 15 项 Python 工具测试及 fmt/Clippy/WASM/契约/策略/依赖审计。新增 View 授权的独立 VideoFeedback 通道、每 source 请求序号与幂等验证、250 ms 强制关键帧间隔、两秒恢复期限及 30 秒内三次恢复/熵失败上限。Video 独占消费者与独立恢复监护使文件事件 FIFO 满不再阻塞已收到的视频和恢复；静止来源从已授权缓存生成明确标记的恢复关键帧。持续更新来源饿死另一静止来源恢复的问题已先复现再修复。自动闭环通过应用层刻意省略一帧验证，不能当作 QUIC 丢包验收；静止请求/响应另在真实回环 QUIC 上通过。native C/FFI/供应未修改，平台额外 fixture 明确保留旧原件。浏览器 RTP/RTCP、外层中继、音画同步、完整 UI/Android 与固定产物验收继续实施，见 [NATIVE-MEDIA.md](NATIVE-MEDIA.md)。

2026-10-13 QUIC 通道增量已接入双方证明后的固定 profile、逐授权通道独立可靠流及有界 Audio 数据报，并通过 `NativeConnection::authorize` 接到 SDK。真实回环连接在文件发送背压时仍交付同向输入和音频；重复/越权/错误绑定通道拒绝，续租保持原传输绑定，撤销关闭全部流。合成 VP8 多来源画面与 Opus 单/双声道实际编解码已通过 QUIC 往返；HTTP 审批→QUIC 和 WSS 内层 TLS→统一 SDK→服务端撤销也通过。Windows 159、Ubuntu 190 项 Rust 开发测试、两端各 15 项 Python 工具测试及格式/Clippy/WASM/契约/策略/依赖审计通过。清理等待取消后继续持有任务；重复等待保留首次失败。协议见 [native-channels.md](../../protocol-spec/native-channels.md)，旧平台额外 fixture 明确保留为历史证据。原生视频反馈、外层 QUIC 中继、浏览器媒体、完整 UI 与固定产物正式验收继续实施。

使用固定 Rust 1.96.0，在本目录执行：

workspace 检查现在需要先按 [NATIVE-MEDIA.md](NATIVE-MEDIA.md) 构建当前目标的固定原生编解码库并设置 `NESTLINK_CODEC_PREFIX`。只构建不依赖媒体的 server/SDK 子集和 WASM 契约时不需要该前缀。

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo xtask check
cargo xtask policy config/network-policy.default.json
rustup target add wasm32-unknown-unknown
cargo check --locked --target wasm32-unknown-unknown -p nestlink-protocol -p nestlink-policy -p nestlink-connectivity -p nestlink-sdk
cargo install cargo-deny --version 0.20.2 --locked
cargo deny --all-features --locked check
```

当前机器已有工具链位于 `D:\home-tunnel-integration\toolchains\cargo` 与 `rustup`，需要设置 `CARGO_HOME`、`RUSTUP_HOME` 并将对应 bin 加入 PATH。Windows protoc 在 TEMP 中编译消息，再由 Rust 写回中文工作树；TEMP 也需 protoc 能识别的路径。

基线可重建：

```powershell
python scripts/refactor-baseline.py --integration-root D:\home-tunnel-integration --output docs/refactor/baseline.json
```

## 工作包与关口

| 工作包/关口 | 状态 | 下一完成条件 |
| --- | --- | --- |
| P0 | 进行中 | 四仓入口/契约基线已记录；历史引用、秘密告警与大文件完成审查后，在临时克隆导入历史并登记提交映射 |
| G0 | 未通过 | 目标平台家族已由用户确认；当前 Cargo.lock（SHA-256 `9a34ff54642f69de251808368609ff4251dfb1b572d4cef617a8d87f572a4bb7`）对应 766 包的 1365 份 NOTICE/2176 份归属文件已完整收集，cargo-deny v0.18.9 对同一全特性元数据的 advisories/bans/licenses/sources 检查通过，保留 58 条多版本警告；见[当前 Cargo 收集与策略检查回执](cargo-notice-current-2026-10-16.md)。`protoc` v36.2 八个平台发布包和 SQLite 3.50.2 bundled 源码已与上游逐字节核验，回执和哈希见[非 Cargo 构建输入来源核验](build-input-provenance-2026-10-16.md)；protobuf tag 未签名。仍需逐文件决定旧资产/测试向量的纳入或排除，完成完整非 Cargo 工具、系统和产品运行依赖清单，并把 SBOM/NOTICE 绑定最终发行材料；另需当前安装产品截图及字体渲染基线、具体桌面/设备/浏览器构建冻结，以及 Windows/Android/Linux/OCI/更新签名身份。自动 cargo-deny 检查不代替组织级许可证兼容审批；这些材料和固定签名身份未齐前 G0 保持未通过 |
| P1 | 进行中 | 账号/MFA、审批、受信设备/固定密码控制服务与 SDK、OS 密钥保存、签名租约、HTTP 认证和加密备份恢复已实现；固定密码 host 配置与单请求授权 UI 已接入桌面/Android，管理员服务配额 UI 已接入 Web；Web 持久身份前置条件、其余本地 daemon/信任流程、完整审计及正式产品验收仍待完成 |
| P2 | 进行中 | 控制 HTTP/WSS、QUIC/直接 TLS、原生会话证明、签名候选/SDP 交换和同机 WSS 密文中继已实现；真实候选采集、独立节点、QUIC 数据报中继与完整平台接入继续实施 |
| P3–P8 | 未完成 | TURN UDP/TCP/TLS 数据面、在线撤销、租约/对端过期和端口预算回收已有开发实现与回归；edge/公网隧道、平台媒体输入、全端 UI、完整安装/签名、全量验收和正式切换仍继续实施 |
| G1–G6 | 部分开发检查；正式关口未通过 | G2 已有 UDP/TCP/TLS、未配对 peer 拒绝、活动 allocation 两秒撤销、租约过期和端口池耗尽回归；仍需目标负载/容量数据、24 小时协议模糊测试与真实公网 TLS/跨网。G1 30 分钟媒体、G3/G4 平台 UI/采集和 G6 持续编码矩阵也仍待固定环境验证 |
| A01–A21 | 未通过正式验收 | 当前为开发安全/控制/本地通道测试；不使用历史证据或编译成功代替固定产物验收。逐项证据缺口见 [A01–A21 验收登记](ACCEPTANCE-GAPS-2026-10-17.md) |

继续按完整方案推进。历史导入在本地审查完成后执行。用户已明确要求全部完成后上传代码、主仓库更名为 ZHanry/NestLink、只保留 main 分支、上传正式 Release，并删除三个组件仓库；该请求取代方案中的旧仓归档建议。已核对仓库名称与 GitHub ID，最终操作和历史/旧发行保全条件见 [finalization.json](finalization.json)，尚未执行远程更名、删除、分支清理或发布。

原生媒体增量加入固定官方 libvpx 1.16.0 / Opus 1.6.1 供应、Cargo 安装文件校验和授权采集→VP8→可靠通道→逐 source 解码交付。额外 Portal 联合回归发现撤销先被像素回调观察时误报来源失效；统一四种回调的取消/错误结果，并保留已观察的超时、坏帧与原生来源删除错误后通过同一隔离联合场景。旧失败日志保留。原生媒体、供应及验证边界见 [NATIVE-MEDIA.md](NATIVE-MEDIA.md)，正式产品验收仍未完成。

本批 Windows 128、Linux 161 项 Rust 开发测试及两端各 15 项 Python 工具测试通过；WASM、契约、策略、Clippy、依赖审计与第一方 C 桥 ASan/UBSan 通过。固定供应的两端 receipt、构建日志和库摘要随验证证据保存。历史 gitlink 另恢复 2 个原始对象，本地缺口由 5 降至 3，见 [恢复补充](history-audit/GITLINK-RECOVERY-2026-10-13.md)；完整远端历史、旧发行保全和正式产品验收仍未完成。

后续音频会话增量通过 Windows 140、Ubuntu 173 项 Rust 测试及两端各 15 项 Python 工具测试；格式、Clippy、WASM、契约、策略与依赖审计通过，原 Windows 自有窗口、隔离 Xvfb、生产门户联合场景也在本批重新运行。已实现同 lease 的 PCM 采集/播放边界、唯一 Audio 消费者、独立 Opus 线程、最多 60 ms 的显式 PLC 和长缺口 reset；坏包不发布补偿音频，撤销清空待播数据并保留失败报告。实际验证为合成信号和记录播放适配器，系统音频/扬声器、真实音画同步、Android/WebRTC 和产品安装仍待实施，见 [NATIVE-AUDIO.md](NATIVE-AUDIO.md)。

后续 Windows 系统音频增量通过 Windows 148、Ubuntu 175 项 Rust 测试、两端各 15 项 Python 工具测试及 fmt/Clippy/WASM/协议/策略/依赖审计。两个本机 render endpoints 实际完成单/双声道 WASAPI 初始化与 reset，没有 Start、系统声音读取或扬声器写入；当前自有窗口采集回归重新通过，Linux 私有显示/门户额外 fixture 复用上一批原件并明确记录为复用。已实现固定本地 endpoint、48 kHz PCM 系统转换、loopback/播放 worker、播放队列与原生 stream buffer 预算、共用会话观察器、原生通知以及首次 HRESULT/清理超时保留。确定性阻塞 Start 替身复现并修复停止后一次取样的竞态，原失败日志保留。只读清单/初始化和需操作者明确启动的两秒音频检测入口已准备，真实声音链路、WASAPI sanitizer、产品接入和正式验收继续实施，见 [WINDOWS-AUDIO.md](WINDOWS-AUDIO.md)。

后续 Linux 系统音频增量通过 Windows 148、Ubuntu 181 项 Rust 基线测试与两端各 15 项 Python 工具测试，Clippy/WASM/契约/策略/最新依赖审计通过；最终 Linux 音频线程调整后重新运行五项音频测试、all-target Clippy 与真实私有服务 fixture。共享 logind 监护、固定 PipeWire 输出身份/实际 Link、授权 poll/enqueue、采集时钟/有界播放及终态清理已实现。X11/Wayland 单/双声道和实际 44.1kHz 六声道软件图转换、撤销/锁定、服务/socket/serial/Link 替换均通过；隔离 Xvfb/生产门户回归重新通过。第一方 PCM C 验证器的 100000 个对抗输入在 ASan/UBSan 下通过；系统 libpipewire 未插桩。WSL 重启后的原 codec 临时安装已按固定来源离线重建到持久目录，新 receipt/日志入账。Windows 自有窗口与未启动 WASAPI 的旧证据明确保留为复用；真实 GNOME/KDE/硬件、产品接入和正式验收继续实施，见 [LINUX-AUDIO.md](LINUX-AUDIO.md)。

后续 Windows 会话监护增量通过 150 项 Windows Rust 基线测试、15 项 Python 工具测试及 fmt/Clippy/WASM/契约/策略/依赖审计；最终清理时间边界调整后重新运行 16 项平台测试、all-target Clippy 与五项真实自有窗口/只读输入/未启动 WASAPI 检查。输入已共享主动观察器，固定 WTS 登录/连接身份、首次 reset 预算及失败，通知窗口关闭/WM_QUIT 不会无声失去监护。采集清理的晚线程退出改报成功问题先复现失败再修复，并用实际完成时间处理超时与等待锁的竞态；显式观察器 close 错误也进入结果。Linux 实现与供应未变更，181 项基线、最终音频 focused 和私有服务证据明确复用上一批。没有注入用户输入、触发 OS 锁屏或实际发声；RDP/IME/硬件/驱动阻塞及产品接入继续实施。

网络通知增量通过真实 Windows/Ubuntu 订阅、订阅关闭→TCP 竞速停止与 STUN 失效测试；Linux IPv4/IPv6 地址、路由和 link 事件已在独立网络命名空间通过实际 kernel 通知测试，测试先核对 namespace 与 PID 1 不同，不修改本机已有网络。物理网卡、代理网卡和实际休眠/恢复仍需安装产品验收。Windows IP Helper 取消返回异常时保留极小回调上下文，避免无法证明回调停止时释放内存；此情况不得用不安全释放掩盖。

2026-10-13 继续接入已建立会话的主动监护、独立收发任务和逐通道有界队列；SDK 成功结果保留原本地网络基线，空闲/部分帧/文件背压时仍可停止和续租。新增共用 protobuf 输入命令、三种 epoch/序列检查、中文提交幂等、局部布局改变先释放按钮、平台注入与释放失败报告。该批次未接入平台真实注入器或 QUIC 独立流/数据报；后续平台适配进展见下文，当前可靠流仍有同向队头阻塞，不能把开发记录适配器当作系统能力；见 [SESSION-RUNTIME.md](SESSION-RUNTIME.md)。

用户确认签名/真机/跨网环境尚未配置后，新增只读的 Windows/Android 固定产物签名检查工具与空身份模板。它记录源码与包摘要、系统信任、公开证书、时间戳或 APK 应用/版本/API/ABI；配置缺失明确 blocked。它不生成临时发行证书或上传产物，不替代平台验收；见 [SIGNATURE-ACCEPTANCE.md](SIGNATURE-ACCEPTANCE.md)。

2026-10-13 系统输入增量在 Windows/WSL Ubuntu 各通过 92 个 workspace 测试及 7 个 Python 验收工具测试。Linux 自有、随机认证的 Xvfb 在独立用户/挂载/网络命名空间实际验证了物理键、扩展键、指针、撤销/空闲布局变化释放，以及服务卡住时的失败报告与恢复后清理；另通过 1 个隔离内核事件测试。Windows 另通过只读实际交互桌面测试。完整行为和未完成项见 [PLATFORM-INPUT.md](PLATFORM-INPUT.md)。显示服务测试不使用当前用户 DISPLAY，也不修改 WSLg 挂载。原生 UI 与 SDK 的端到端产品接入、IME/Unicode、Wayland/Android 和正式输入验收仍未完成。

Wayland 门户客户端增量已实现新系统同意、logind/服务撤销监护、物理键/Unicode keysym/逻辑指针、原 owner 清理和 PipeWire FD 移交。6 项真实私有 D-Bus 开发测试通过；当前 WSLg 只读 probe 因没有 logind 桌面会话而受阻。PipeWire 图像读取已在后续增量接入，实际格式/DPI 观察、产品 GUI 以及 GNOME/KDE 输入法验收继续实施；见 [WAYLAND-PORTAL.md](WAYLAND-PORTAL.md)。

后续原始画面采集增量已加入 View/连接代次约束、布局坐标变换、过期帧丢弃与停止清理，并通过门户 FD 接入真实 PipeWire 原始图像读取。独立合成视频源、撤销与服务退出开发测试通过；像素格式/尺寸改变反向终止旧门户。真实 compositor、所有平台采集、VP8/Opus、线上媒体与产品界面仍未完成，见 [VIDEO-CAPTURE.md](VIDEO-CAPTURE.md)。

Windows 采集现已接入 GDI 显示设备与私有 DIB，约束原交互会话、桌面、显示器和 DPI 事实，失效与清理均为终态。X11 增加 logind 主动信号/空闲检查及会话稳定的 Unicode keycode 映射；真实私有总线与隔离 Xvfb 验证了快速锁/解锁、中文/emoji、容量预检和原键盘映射恢复。Windows 自有隐藏窗口验证合成像素和显示/会话变更通知。真实多屏/RDP/锁屏、XIM/长中文文本仍须固定产物验收；没有把开发测试改记为 A01–A21 通过。

此前未完成的 Hub 38 条与 Client 143 条历史告警现已逐条分类：178 条误报，3 条为公开上游 Firebase 客户端配置。三条配置仅随原许可历史保全，不进入新产品或复用上游云项目，未使用其 key 访问服务。脱敏分类、公开来源与维护处置见 [历史告警处置](history-audit/DISPOSITION.md)；历史许可证/引用/资产核验与导入仍待完成。

后续 Linux 采集增量实现 X11 GetImage 与 XFixes 光标、只观看 ScreenCast 授权、PipeWire 正负 stride/裁剪/八种方向变换，以及 64 位 serial 和实际 Link 两端绑定。工作线程和出队共同观察原系统会话失效事实；晚帧不能续期，清理保持最早截止时间。真实双源错接回归先复现旧实现问题，再验证终态和队列清空。生产门户 API→真实 FD→采集→业务视频/输入共同撤销的隔离联合测试覆盖六个场景；来源删除保留原 worker 错误，未改报成功。X11 HideCursor 无可见性字段已通过官方协议与自有 Xvfb 确认，隐藏指针匹配仍未完成，详见 [VIDEO-CAPTURE.md](VIDEO-CAPTURE.md)。

本增量 Windows 99、Linux 127 个 Rust 开发测试及两端各 10 个 Python 工具测试通过；自有 Windows 窗口、隔离 Xvfb、私有门户/PipeWire 联合场景另保留独立日志。WASM、契约、策略、Clippy 与依赖审计通过。结果和精确源码摘要见 [verification.json](verification.json)，不能代替正式安装或 A01–A21 验收。

历史保全新增 [本地保存清单](history-audit/LOCAL-PRESERVATION-INVENTORY.md) 与只读复现脚本：四仓已检查范围内无缺失可达 Git 对象，12 件指定旧候选发行附件的本地长度与 SHA256 匹配；118 个历史 gitlink 中仍有 5 个提交未在本地找到。远端全部 refs/Releases、缺失子模块闭包、完整许可来源及持久归档仍须补齐，未导入历史或执行远程切换。

2026-10-17 桌面端远控一次性密码已绑定当前待处理请求 ID 与有效 offer 修订号；请求、所选设备、请求状态或 offer 修订变化，以及 offer 刷新/失败时都会清空 Zeroizing 密码缓冲区，每帧上下文校验也会清理已失效输入。新增回归覆盖上下文绑定及请求/修订变化后的清零。Ubuntu 24.04 WSL 当前源码回归通过：桌面库测试 37/37、workspace 格式检查通过；58 个选定源文件运行前后保持一致。严格 Clippy 使用的 Windows x64 MSVC 当前源码结果见上一条桌面验收索引记录。首次 Linux 重跑因未设置已验证的 NESTLINK_CODEC_PREFIX 而在测试前失败，已保留失败日志和回执；补齐固定本地前缀后的通过日志、来源回执及格式记录见[当前检查索引](current-verification-2026-10-17.json)。该开发回归不替代固定签名安装产品验收。
