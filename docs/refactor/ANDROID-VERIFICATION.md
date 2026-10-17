# Android 验收记录（2026-10-16）

## 2026-10-17 固定密码 UI 全量 Kotlin/JVM 回归

桌面端与 Android 固定密码授权界面增量后，Android `testDebugUnitTest` 全量通过 **131 项，0 失败、0 错误、0 跳过**。本次使用 `-RerunTasks -NoIncremental`，79 个选定 Android/运行脚本输入在测试期间保持不变；日志与源码回执见[当前验证索引](current-verification-2026-10-17.json)。首次尝试因临时盘符下未解析到 Android SDK，在用例启动前失败；设置本机 SDK 的 `ANDROID_HOME` 和 `ANDROID_SDK_ROOT` 后 attempt02 完成全套测试。该回归只覆盖 Kotlin/JVM 单测，不重新构建 APK，也不替代下方固定 1070 输入的七版模拟器结果或正式签名验收。

## 2026-10-16 最新 Android 源码快照：BuildAttempt01 / MatrixAttempt04

本次从 1070 个 Android/Rust/protocol/native-build 输入文件重新构建，固定摘要为 `0e2b103b072c9de6ce07bc3b3ae2cd72d6af4ee1289106bb2509a6682055fa29`。相较前一 Android cohort，25 个 Android 应用或测试文件发生变化，因此没有沿用旧 JVM 结果：当前 Kotlin/JVM 全套 **127 项通过，0 失败**。两 ABI release JNI、Android bridge all-targets 严格 Clippy、应用与 instrumentation APK 组装均通过；包内 JNI 字节匹配本轮原生库，ELF 段和 APK JNI 数据偏移静态按 16 KiB 对齐，两包的 Android Debug 签名也经 `apksigner` 实际验证。

同一对 APK 在 API30–36（Android 11–16）x86_64 模拟器上各通过 17 项真实 instrumentation，共 **119/119**。 [七版索引](../../artifacts/android-input-renewal-full-source-20261016/android-browser-host-seven-api-20261016-attempt01.json)绑定当前源码摘要、APK 字节、实际测试名、设备指纹、页大小与清理记录；各版实测页大小都是 4096 字节。API30–34 使用留存官方系统镜像；本轮从已安装工具包复制并核对 Android Emulator 37.1.11 的 package.xml，矩阵结束后确认私有工具包、镜像、AVD 和模拟器进程均已回收。API35 当前身份页浅色/深色截图已检查；此项只覆盖初始身份页视觉。

更早的 MatrixAttempt01–03 失败状态均保留：旧测试计数先于启动器发现清单增加，API35 驱动曾只接受中文界面，随后 API30 因隔离 SDK 缺少已注册的 Emulator package 未能创建 AVD。修订后的 MatrixAttempt04 使用完整工具包核验流程，对七个 API 全部重新运行并通过。共同的 996 个 Rust/protocol 输入与最近一次 Windows/Linux 续租验证逐文件完全相同，因此那 184 项共享代码运行回归仍适用于这些共同输入；新增 Android 代码则由本轮 127 项 JVM 和 119 项仪器用例覆盖。

当前 Android [最终复核](../../artifacts/android-input-renewal-full-source-20261016/FINAL_REVIEW.json)、[冻结源码包](../../artifacts/android-input-renewal-full-source-20261016/source-inputs.tar.gz)、[双 ABI JNI 收据](../../artifacts/android-input-renewal-full-source-20261016/android-native-av-native-ready-20261016-attempt01.json)、[APK 收据](../../artifacts/android-input-renewal-full-source-20261016/android-native-av-apk-ready-20261016-attempt01.json)和[签名复核](../../artifacts/android-input-renewal-full-source-20261016/debug-apk-signatures-attempt01/checks.receipt.json)均已保存。Android 10/API29 按用户要求排除。

以下各节均为对应日期的历史快照；其中“当前”“正在”或“尚未”只描述该批次记录时的状态。最新状态以本页开头的完整源码复核和当前检查索引为准。

本次仍是开发签名和 x86_64 仿真器验收，不代表正式发行签名或完整产品验收。ARM64 Android 真机、实际 16 KiB 页大小运行、真实 Projection/SAF/无障碍授权和外网跨网络测试仍待可用硬件、证书与环境；本轮没有把这些记为通过。

## 历史快照：BuildAttempt02 / MatrixAttempt08（已由下文完整源码重验取代）

该历史 1070 项 Android 输入以基线 `1e43481ae4a872b946af9a0f11c9b15ac61a8721` 加工作树修改构建，源码摘要为 `3529ac75251c40cd26263e6e402669192c30b414cf811986a67ded14cb602d40`。ARM64 与 x86_64 release JNI、两 ABI all-targets 严格 Clippy、调试应用和 instrumentation APK 组装通过；静态 ELF/APK JNI 16 KiB 对齐及 APK zipalign 检查通过。应用 APK 为 70,777,300 字节，SHA-256 `80a5b0d9013b193f7b8308fbcc15c4c8accac30bca705e7810925abf10841cb8`；测试 APK 为 2,243,276 字节，SHA-256 `5ad345e6f8264d4d6f890b1a77f2348166209762444c3251341c4e82462420ca`。两包为开发签名。

该历史 APK 在 API30–36 的 x86_64 模拟器上各通过 17 项 instrumentation，共 **119/119**。[七版索引](../../artifacts/android-input-renewal-20261016/android-browser-host-seven-api-20261016-attempt02.json)重新核验了 119 次真实启动/成功、测试名、源码及 APK 哈希、设备身份和清理收据；各 API 使用的矩阵为 API30/attempt07、API31–34/attempt08、API35/attempt05、API36/attempt06。API35 的初始身份页浅/深主题截图已保留。所有实测页大小均为 4096 字节；此前 119 项 JVM 测试未在本轮重复。

矩阵 attempt02–05 的测试清单、语言检测、API30 私有 SDK 和 API36 输入焦点问题均保留为失败历史；修正后的 attempt05–08 单版记录构成上表索引。API30–34 使用已核验的本地官方镜像，并从本机复制 Android Emulator 37.1.11 到隔离 SDK，矩阵结束时确认专用包、AVD、私有镜像和模拟器进程均已清理。

本批只证明开发签名、x86_64 模拟器和上述 119 项检查。ARM64 真机、16 KiB 页大小 Android 设备运行、真实 Projection/SAF/无障碍授权、跨公网及正式签名仍未验收；Android 10/API29 按用户要求排除。

以下各节均为对应日期的历史快照；其中“当前”“正在”或“尚未”只描述该批次记录时的状态。最新状态以本页开头的完整源码复核和当前检查索引为准。构建和逐版原始记录见 [JNI 收据](../../artifacts/android-input-renewal-20261016/android-native-av-native-ready-20261016-attempt02.json)、[APK 收据](../../artifacts/android-input-renewal-20261016/android-native-av-apk-ready-20261016-attempt02.json)及七版索引。

## 历史快照：输入续租修复（1044 项源码；已由上文重验取代）

本轮共享 SDK/remote 输入续租修复后的 1044 项源码输入已冻结为 `065b58bf4447c477c1163edd862da3c99f273c5247ed4460aa48d911a6cbff77`。ARM64 与 x86_64 release JNI、两端 all-targets 严格 Clippy、新 APK 组装和两包开发签名检查通过；应用 APK SHA-256 为 `9f283a709adbbf5bea46a392777046c96b42ba2db72e553b47970b83ec8a5d1b`。包内 JNI 与本轮原生库字节一致，ELF 和 APK JNI 偏移的静态 16 KiB 对齐通过。

同一对 APK 在 Android 11–16 / API30–36 的 x86_64 模拟器上各实际通过 16 项，共 **112/112**；全部使用本轮 Matrix01。[七版索引](../../artifacts/android-input-renewal-20261016/android-browser-host-seven-api-20261016-attempt01.json)绑定实际测试名、原始日志、设备和 APK 身份。[最终复核](../../artifacts/android-input-renewal-20261016/FINAL_REVIEW.json)及[冻结清单](../../artifacts/android-input-renewal-20261016/FROZEN_ANDROID_INPUT_RENEWAL.json)保留本批固定证据。[文档集成回执](../../artifacts/android-input-renewal-integration-20261016/attempt01/INTEGRATION_RECEIPT.json)再次从原始仪器事件核对 112 次真实启动/成功并确认本批源码一致。

本轮开始前已逐文件验证完整 382 文件 emulator 工具包。七台自有模拟器、AVD 和五份自有 API30–34 镜像均已回收，既有 API35/36 SDK 镜像保留；构建和严格检查各自 scratch 的原命令清理回执通过。65 项 Android 应用输入与前批相同，因此沿用原 119 项 JVM 证据，没有重复运行。父任务已核对当前 API35 初始身份页浅/深两张截图，仅覆盖该页面。

实际运行页大小均为 4096 字节。本批仍是开发签名和 x86_64 模拟器验证，ARM64 真机、16 KiB 系统运行、真实 Projection/SAF/无障碍授权、跨公网及正式签名验收仍待外部条件。Android 10/API29 按用户要求排除。

以下各节均为对应日期的历史快照；其中“当前”“正在”或“尚未”只描述该批次记录时的状态。最新状态以本页开头的完整源码复核和当前检查索引为准。以下 1042 项输入及更早结果作为各自历史证据保留。

## 2026-10-16 前一批 1042 项源码：双 ABI 新包及七版回归

该批 1042 项输入已重新冻结为 `edd9cd42f16ff72ec58a0c053adb01db1f5a78ddc53f91c58cf68eaf97c55f51`，包含原生自动签名中继和 RTCP 适配等后续共享 Rust 增量。两 ABI 的 release JNI 构建与 all-targets 严格 Clippy 通过；本批应用 APK SHA-256 为 `f567a7ea188452407d0f58c4f608d264062d3585651a3d114c55a794e2645267`，测试 APK 为 `359475f000ee175338e803d2b588133c0546964ce21f788c01979a4f6f0a01d8`。包内 JNI 字节和 ELF/APK 静态 16 KiB 对齐已核对，两包的开发签名由 apksigner 实际验证。

同一对 APK 在 API30–36 各实际通过 16 项，共 **112/112**。API35/36 使用 Matrix01；API30 首次因自有 SDK 未含完整 emulator 工具包而在测试开始前失败，实际运行 0 项。保留该失败后，只补齐工具包并用 Matrix02 验证 API30–34，未重复已通过的两版。最终[七版索引](../../artifacts/android-current-increment-20261016/android-browser-host-seven-api-20261016-attempt02.json)明确保留每版 attempt、真实镜像路径、指纹、测试名及两轮历史；API35 外层 ImageVariant 标签与实际镜像来源的差异按实际路径与 source.properties 记录。

[父任务集成回执](../../artifacts/android-current-increment-20261016/PARENT_INDEX_INTEGRATION.json)重新核验了 122 份证据、36 份外部产物、源码归档与当前全部 1042 项输入，并从原始仪器日志逐项匹配 16 次启动和成功结果后更新共享索引。七台自有模拟器/AVD、六次自有镜像导入及 11 条实际命令的 scratch 清理通过；原 SDK 镜像保留。65 项 Android 应用输入未变，因此未重跑已有的 119 项 JVM 测试。

[独立只读复核](../../artifacts/android-current-readonly-review-20261016/REPORT.md)七组检查全部通过，另确认 APK 内包括 AndroidX 库在内的全部四份 `.so` 静态对齐、当前自有模拟器进程为零及精确 AVD 目录不存在。历史 scratch 原回执未保留独立路径，因此该部分核验的是清理完成后才写入的原始命令回执，不能解释为本次重新检查了历史目录。

本批仍是开发签名、x86_64 模拟器验证，实际页大小均为 4096 字节；不代表 ARM64 真机、16 KiB 运行、真实 Projection/SAF/无障碍授权、跨公网或正式签名验收。API29 按用户要求排除。以下 Build15 及更早结果保留为各自历史源码证据。

## 历史快照：BuildAttempt15 / MatrixAttempt13 七版源码回归

包含 rustls 0.23.46 与服务启动取消的实际 UDP 释放修复。同一应用/测试 APK 在 API30–36（Android 11、12、12L、13、14、15、16）x86_64 模拟器上各通过 16 项仪器测试，合计 **112/112**。逐项测试名、原始日志、设备指纹、源码/包哈希及清理回执已由[七版索引](../../artifacts/core-verification/android-browser-host-seven-api-20261015-attempt01.json)重新核对，索引 SHA-256 为 `22b50bd5caf5b053172cd45965955ec3462e9849fe6c9f3bce68c663f68e39c4`。每版均确认源码前后不变，实际测试页大小为 4096 字节，临时环境已回收。

共同源码指纹为 `0cbf05286b8f69d1d1c938760bec3bc8bfb159ed55492e2cdb87681602d6f656`；应用 APK 69,234,348 字节，SHA-256 `2d117ad5180e495a9ab5ab43f441ef338eba3c774f55ff91c062a25b232e2d69`；测试 APK 2,237,832 字节，SHA-256 `359475f000ee175338e803d2b588133c0546964ce21f788c01979a4f6f0a01d8`。包内 ARM64/x86_64 JNI 与本次原生构建逐字节一致，ELF 和 APK 的静态 16 KiB 对齐通过；[JNI 记录](../../artifacts/core-verification/android-native-av-native-ready-20261015-attempt15.json)和[APK 记录](../../artifacts/core-verification/android-native-av-apk-ready-20261015-attempt15.json)保留实际字节与输入。两 ABI 的 release/all-targets 严格 Clippy attempt02 通过，119 项 JVM 测试沿用未改变 Kotlin 输入的 attempt04 记录。

已实际打开并核对本批 API35 初始身份页的浅/深截图：系统栏、图标和文字主题符合对应令牌。范围仍限于初始页及上述仪器测试；ARM64 真机、真实 MediaProjection/SAF/无障碍授权、16 KiB 运行、正式签名和跨网验收尚待执行。API29 按用户要求排除。以下旧批次继续作为历史原件，不能替代本批输入。

## 2026-10-16 BuildAttempt13：系统栏主题修复及 API35 实测

按 API35 实际截图修正原生系统主题：新增 `values-night/styles.xml`，深色状态栏、导航栏及窗口背景采用既有 surface 令牌，图标使用浅色；浅色导航栏使用深色图标。移除编译器已证明冗余的 BrowserSession 非空条件。42 路径冻结源码、基线和差异见 [FINAL_CODE_AFTER_SYSTEM_BARS.json](../../artifacts/android-browser-host-integration-20261015/FINAL_CODE_AFTER_SYSTEM_BARS.json)，patch SHA-256 `5d656ef6adf508f15b1a261f76006c60aaa0c3691d37e5e32ef28b8a6365b571`。

119 项 JVM 测试和全部 16 项仪器测试源码编译通过，见 [Kotlin attempt04 原始 XML 索引](../../artifacts/android-browser-host-integration-20261015/kotlin-tests-attempt04/INDEX.json)。BuildAttempt13 双 ABI JNI/APK 构建、静态 16 KiB 对齐和包内 JNI 字节比对通过，共同源码指纹 `21e72f6fcfa0b6805bd82ce605299d7967dcc743f519c8231cdfd76e10fb4dcf`。应用 APK 为 69,204,684 字节，SHA-256 `d633a079a67e3b2b5440bcbc62c9ca4dacdad98c2209355fd552bf2e6b233279`；[APK 原件记录](../../artifacts/core-verification/android-native-av-apk-ready-20261015-attempt13.json) 保留各产物的实际字节。

同一 BuildAttempt13 在 API35/MatrixAttempt12 的 16 项仪器测试全部通过，源码前后稳定、日志及独有环境清理均通过，[verified receipt](../../artifacts/core-verification/android-browser-host-api35-emulator-20261015-attempt12.verified.json) 与原日志保留。已实际打开并核对该次初始身份页浅/深两张 PNG：系统栏随主题切换，深色文字对比度修复保持有效。范围仅为初始身份页和这些仪器测试，未覆盖登录后的全部页面、真机或真实系统授权。

之后完整依赖审计发现 rustls 0.23.45 命中四项安全公告，因此 BuildAttempt13 仅保留为上述主题修复的开发证据。已升级至 0.23.46，并移除 atty 与 rustls-pemfile；完整 cargo-deny 已重新通过，逐项处置见 [TLS 依赖审查](tls-dependency-review-2026-10-16.md)。BuildAttempt14 的双 ABI JNI 构建及静态对齐通过；随后 Linux 回归发现服务取消启动的 UDP socket 释放竞态，因此该版没有继续组装 APK/启动矩阵。包含[释放修复](SERVICE-HOST-SOCKET-RELEASE.md)的 BuildAttempt15 已完成上述 112 项七版回归；下文旧包结果不替代本批验收。

BuildAttempt12/MatrixAttempt11 的 API35、36 各 16 项通过；API30 原始 16 项执行完成，但因运行期间源码发生系统栏修正，最终源码 guard 拒绝并保留为失败，没有 verified receipt，也没有将其计入当前七版通过数。

## 2026-10-15 BuildAttempt12：深色文字及真实 Android 目标检查

按既有设计令牌修正提示和错误文字的深色颜色：surface 上的对比度分别由 2.81/2.01 提升至 6.86/7.65。移除三处用户文案中的内部 `host View` 术语；仅供测试/桌面使用的 Rust 定义按实际目标编译，不屏蔽警告。新 40 路径的原字节、冻结源码与差异见 [冻结清单](../../artifacts/android-browser-host-integration-20261015/FINAL_CODE_AFTER_DARK.json)，patch SHA-256 为 `5fe6fc3f95b271a981a6769660560c34439546f87da40bbf3fea1456764bdc72`；下文 BuildAttempt11 原件不变。

当时 119 项 JVM 测试（19 suites，0 failures/errors/skipped）和 16 项仪器测试源码编译通过，[原始 XML 与索引](../../artifacts/android-browser-host-integration-20261015/kotlin-tests-attempt03/INDEX.json) 已独立保留。Windows/Linux bridge 各 26 项及两端 all-targets 严格 Clippy 通过；另已通过实际 `aarch64-linux-android` 与 `x86_64-linux-android` 的 release/all-targets Clippy，全部使用 `-D warnings`。六份命令回执均核对源码前后不变、日志 hash 和独有 scratch 回收。Kotlin 编译仍有一处既有冗余非空条件警告，本记录不声称 Kotlin 无警告。

当时计划由 BuildAttempt12 的 JNI/APK 从这些字节重建，之后执行七版、每版 16 项的新矩阵。当时计划的新驱动逐版核对已保存的官方元数据、压缩包完整 SHA-1 与 SHA-256，在 D: 私有目录重新准备镜像，不重复网络下载；API35 将额外采集已安装初始身份页的浅/深主题截图，其范围不包括登录后的完整产品视觉验收。Android 10/API29 排除，真机、正式签名和跨网等正式验收条件不变。

## 2026-10-15 BuildAttempt11：浏览器共享接线已合入

Android 浏览器被控的屏幕、输入、播放音频、SAF 文件和文本剪贴板已合入正式工作树。系统同意结果绑定完整 BrowserHost 身份，与原生会话互斥；只有双方连接证明完成、实际 Video/所需 Audio/Input 租约仍有效时才激活平台资源，排队后的 Android worker 会再次检查。拒绝、撤销、过期和关闭会清理同一 owner，未知清理结果保留阻断状态。文件操作保留逐方向本地授权、一用 SAF grant 和迟到保存目标的清理记录。底部保留三个业务入口，文件/剪贴板/浏览器共享位于远控二级操作；隐藏面板仍保留 ActivityResult 和清理 owner。

Wi-Fi 接收锁由完整会话身份持有；未完成证明的等待窗口上限 60 秒，之后每秒核验真实 Rust 租约，撤销或本地停止释放，释放失败保留旧 owner 并支持后续清理。它只改变 Wi-Fi 多播接收，不提供媒体或输入授权。最终 39 个路径的字节、合入前备份与评审差异见 [冻结清单](../../artifacts/android-browser-host-integration-20261015/FINAL_CODE.json)。

同一版 Kotlin 主源码、测试源码及 16 项仪器测试源码均已编译通过；119 项 JVM 测试全部通过。Windows 和 Linux 的 bridge 各 26 项 Rust 测试及两端 all-targets strict Clippy 通过，各自源码稳定、日志与 scratch 回收回执位于 `artifacts/android-browser-host-integration-20261015/`。原 Rust/JNI 编译失败及首轮工具路径错误均保留，未改写为成功。

双 ABI 发布模式 JNI 和调试应用/仪器 APK 已完成构建；JNI 的 ELF、APK 数据均通过静态 16 KiB 对齐检查，包内两份 JNI 与原构建字节一致。共同 691 个源码输入的指纹为 `26c540aea0aa7c72c0496df1184cf449350ed1efc94a94be31f3a72ad4076468`，对应基线 HEAD 加当前工作树；[JNI 记录](../../artifacts/core-verification/android-native-av-native-ready-20261015-attempt11.json)、[APK 记录](../../artifacts/core-verification/android-native-av-apk-ready-20261015-attempt11.json) 固定实际字节。

| 产物 | 字节 | SHA-256 |
| --- | ---: | --- |
| ARM64 JNI | 18,690,320 | `2d745cef133e34c0ba085361eb4fde3915e9115e1550bd1b9d56dcb0ca18b38b` |
| x86_64 JNI | 20,902,456 | `4fb9e6911d883ab841f2397a4b484ebafdb29e342cf69f8d6b028d4e56ccad49` |
| 调试应用 APK | 69,204,428 | `325e5b1fc25f0d083e4bace72b676eb4f15b01c640598cb2b0ba9bbfe46d8e76` |
| 仪器测试 APK | 2,237,832 | `359475f000ee175338e803d2b588133c0546964ce21f788c01979a4f6f0a01d8` |

该组 APK 在 API35、36 各通过 16 项；API30 下载期间发生上述源码修正，因此核对精确下载进程身份后停止了已淘汰矩阵的 SDKmanager，自有 AVD/镜像和进程均清理，API30 为 0 项、失败状态保留，其余四版未运行。见 `android-browser-host-api-matrix-20261015-attempt10.json` 和 `android-browser-host-build11-download-stop-20261015.json`，不将此组记为七版通过。新增实际 APK 检查覆盖 BrowserHost JNI 入口、错误身份拒绝、选择文件 fd 关闭、失败导出截断/同步和 fd 关闭，以及两次失败连接的 JNI 应用类解析与真实 Core 清理。正式固定证书、ARM64 真机、真实 MediaProjection/SAF/无障碍完整流程、16 KiB 系统运行、跨网和已安装产品视觉验收仍待执行；Android 10/API 29 排除。

## 2026-10-15 BuildAttempt09：七版共 84 项通过

同一组双 ABI JNI、调试应用 APK 和仪器测试 APK 已在 Android 11–16 / API 30–36 的 x86_64 模拟器上各通过 12 项真实 instrumentation 检查，共 84 项。API 31 使用 MatrixAttempt08，其余六版使用 MatrixAttempt09。[七版索引](../../artifacts/core-verification/android-native-av-seven-api-20261015-attempt01.json) 重新解析原始测试名称和最终退出码，并核对 APK、源码、日志、设备事实及清理回执；索引 SHA-256 为 `21ca03ddd79c77bf80fc6cd9a5bc06f6d66920e9b626f97ebb0a7423f1d74239`。

共同源码指纹为 `2eef170e5a652053a0b975673c0b71fb7146dac53ff4c6e6355f1c726b0f3a21`，对应基线 HEAD `1e43481ae4a872b946af9a0f11c9b15ac61a8721` 加当时工作树。逐文件输入和供应见 `android-native-av-native-ready-20261015-attempt09.json` 与 `android-native-av-apk-ready-20261015-attempt09.json`。

| 产物 | 字节 | SHA-256 |
| --- | ---: | --- |
| ARM64 JNI | 18,443,992 | `e0d6531f2f460c7f8462f214f5ef17cdecc919a456f7ba635c225ac57fb342ab` |
| x86_64 JNI | 20,631,352 | `5035c739a3a1f3a68511bcbeb4e49dff060a76593e4127548f34a31b714b7bab` |
| 调试应用 APK | 68,392,612 | `76bb0c64f2848e688b8c51286aa585b64980a1564f20dabc5c416f99e9ca0a4a` |
| 仪器测试 APK | 2,223,000 | `e98d008b499f41b8ad0bcb76ebeec7e11cf0fb6d08732162b1da26d97ab5dea9` |

JNI 的 ELF 与 APK 数据均通过静态 16 KiB 对齐检查，APK 中 JNI 未压缩且与构建字节一致。七版实际页大小均为 4096，不能据此声明 16 KiB 系统运行通过。每版自有模拟器进程、AVD 和临时目录均已回收；API 30–34 的私有已解压系统镜像也已删除，既有 API 35/36 原镜像保留。失败下载残片的单独清理被自动审核以 `blocked by policy` 拒绝，未执行删除，见 `android-abandoned-download-cleanup-20261015-attempt01-rejected.json`。

API 31 原 MatrixAttempt07 的 11/12 失败保留。修正后的测试先等待 Activity 原有 Compose 页面可见，再在 `runOnIdle` 中替换内容；真实位图提交/回收和迟到回调断言保留。BuildAttempt07/08 的源码中途变化记录不混入有效索引。

索引生成后集中调整了三份 Rust 回归测试（Core 音频集成、media-session 测试模块、SDK 中继集成），随后又修改共享 BrowserHost request ID 接口、原生 ICE 配置和证明时限激活逻辑。索引固定保留实际已测源码和字节，不覆盖这些源码变化；当时 Android BrowserHost 投屏/输入/音频及 SAF/剪贴板接线仍在隔离实现；后续已合入，并由上方完整源码 BuildAttempt01/MatrixAttempt04 重建和复验。正式签名包、ARM64 真机、真实 MediaProjection/SAF/无障碍流程、16 KiB 运行和跨网完整验收仍未完成；Android 10/API 29 按用户要求排除。

## 历史 BuildAttempt05 双 ABI JNI 与 APK

当前构建使用 `android-native-av-*-20261015-attempt05` 记录。双 ABI JNI、应用和仪器测试 APK 均已成功构建，ELF `PT_LOAD` 与 APK 内两份实际 JNI 均验证 16 KiB 对齐、未压缩且字节一致。共同源码指纹为 `e304c30fe3e17104c2a712e93e7c6ac55320489381c0a879ff48c0136a6023f2`；逐文件源码、工具、供应 receipt 和最终字节见 `android-native-av-native-ready-20261015-attempt05.json` 及 `android-native-av-apk-ready-20261015-attempt05.json`。

| 产物 | 字节 | SHA-256 |
| --- | ---: | --- |
| ARM64 JNI | 18,438,584 | `d4894dd4931a9bd245438a0a58deef5d0a106f861cd24424d520746ca74f44ee` |
| x86_64 JNI | 20,624,344 | `236d7f93cd214bf9955ce96d1c806de006d509009894a0f3f03378fc6993e41c` |
| 调试应用 APK | 68,385,604 | `29333a89eb3d89b1bc0e142edca2af2f353e74a20531805ae9a2dfee517c110d` |
| 仪器测试 APK | 2,222,984 | `a9e80c1ca446459ad5f8c708ad048baec9a1ba1b952ad334d33080ae9f2e7452` |

APK attempt02 的主代码已编译，但仪器测试仍调用旧的 Host View 接口并缺少原会话 binding，实际编译失败原件保留。attempt03 按当前接口修正测试，并以合法的 fixture binding 验证无效句柄拒绝，另覆盖配置视频、采集 PTS、显示就绪三个真实 JNI 入口。方法总数仍为 12，不复用历史 3 项/版 APK 结果。

后续失败分别保留：MatrixAttempt01 的模拟器拒绝 2048 MiB 分区，未进入测试；分区改为 1536 MiB 后，MatrixAttempt02 的 11/12 暴露测试重复设置 MainActivity Compose root；改用 Activity 已有 ComposeView 的 attempt04 包在 MatrixAttempt03 仍为 11/12，因为状态变化后直接等待 latch 没有推进 Compose 测试时钟。attempt05 只修复测试同步：先等待重组并断言 Image 消失，再等待真实硬件提交回调。生产回收行为和迟到回调隔离断言均保留。

该历史 BuildAttempt05 在 API 35、36 的 MatrixAttempt04 和 API 30 的独立 attempt05 均已各通过 12/12，覆盖真实帧提交后的位图回收和迟到回调隔离。三版实际页大小均为 4096；16 KiB ELF/APK 静态对齐通过不等于已在 16 KiB 系统上运行。当时 API 31–34 的官方普通 AOSP 镜像仍在准备，该批尚未完成七版矩阵；后续已由上方最新七版结果覆盖。各版独立 `.verified.json` 记录相同 APK、源码指纹、实际设备事实及清理回执；汇总程序只有在全部七版满足这些条件并重新解析真实 instrumentation 日志后才生成 `android-native-av-seven-api-20261015-attempt01.json`。

MatrixAttempt04 在 API 30 下载阶段失败，保留原失败状态；API 32、33 的 SDKmanager 预取失败也分别保留。新的下载工具按精确 HTTP Range 保存进度，核对官方元数据中的完整文件长度和 SHA-1，再记录 SHA-256、安全解压并生成 SDK 本地包元数据。原停滞文件及其指纹不修改。API 30 使用 Google APIs 镜像；API 31–34 改用体积更小的普通 AOSP 镜像，API/ABI 与十二项应用检查不变，不使用删减系统服务的 ATD 镜像。所有镜像仅供私有开发验证，不进入产品分发。

调试构建及这些检查不代表正式证书、ARM64 真机、真实系统投影/SAF、跨网或完整产品验收。此前三项/版的历史 APK 结果继续单独保留。

## 2026-10-15 多屏与音画时序整合后的历史源码快照

共享音画时钟、原 MediaProjection grant 内的 View-only 几何刷新以及 16 字节采集头已经接入。当时完整 Kotlin 主源码/测试源码编译及 75 项 JVM 测试通过，0 failures/errors/skipped。逐项真实 XML 已保留在 `artifacts/core-verification/android-native-av-jvm-20261015-attempt01-results/`，同名前缀的 `-results.json` 与构建 receipt 记录源码稳定及临时目录回收。该任务显式排除 Cargo/JNI；双 ABI JNI/APK 和 API 30–36 运行矩阵当时尚待后续执行，完成情况见上方最新快照。

下文旧 JNI/APK 和仪器测试结果保留其原始输入，不覆盖本批新 ABI 或当前工作树。ARM64 真机、真实 MediaProjection/设备音频时基、签名及跨网验收仍待固定产物实测。Android 10/API 29 明确排除。

## 2026-10-15 服务管理页开发回归（历史记录）

当前 Android 服务页通过窄 JNI 接口调用真实 Rust Core 的查询、新建、修改和撤销操作。请求与响应均核验 handle、account、session ID 和 generation；登录或退出使 UI 请求 owner 失效，同账号重新登录不能接收旧响应。编辑草稿保留稳定 ID，仅与真实返回的同定义记录同步 revision。手机只管理其他设备的配置，不因保存配置自动获得本机公网出口权限。

本轮 Kotlin 主源码和测试编译通过，11 个测试类共 67 项 JVM 测试全部通过（0 failures/errors/skipped），其中服务管理类 10 项。原始 XML 已保全至 `artifacts/core-verification/android-services-jvm-20261015-attempt01-results/`，汇总为同名前缀的 `-results.json`；Gradle 日志与 `.receipt.json` 记录运行期间选定源码未变、独有测试 scratch 已回收。构建输出留在 D:，原生构建任务被显式排除。本结果不证明当时 JNI/APK、API 30–36 仪器矩阵、真实 SAF 提供方、ARM64 真机或正式签名通过；这些仍在后续冻结源码验收范围。

## 2026-10-15 最新 Kotlin/JVM 与 bridge 开发证据

加入 SAF/host 文件及剪贴板后的 Kotlin/JVM 回归通过 57 项（10 suites，0 failures/errors/skipped），原始 XML、日志和源码前后 hash receipt 保留在 `artifacts/core-verification/android-clipboard-jvm-20261015-attempt01*`。Android bridge Rust tests attempt02 通过 18 项；bridge/platform-clipboard strict Clippy attempt04 通过（all-targets，`-D warnings`）。上述命令都记录源码输入在各自运行期间未变化及本轮 scratch 已回收。

Android adapter 首轮 Rust 用例为 2/3；正常关闭用例暴露后端关闭返回早于真实线程 join 的生产问题，失败原件保留在 `android-clipboard-adapter-rust-tests-20261015-attempt01*`。随后修复 Shared 中唯一真实句柄、原清理期限、阻塞启动与未知析构 owner 有限保留，并新增 6 项通用生命周期回归；这批修改由主线程集中验证，前述 Clippy/bridge 结果不能作为修改后 platform-clipboard 的通过证据。当时 JNI 68 对公开参数及返回类型静态一致；没有因此声称真实 JNI、当时 APK、API 30–36 仪器测试、ARM64 真机或发布签名已经验收。

## Android SAF 文件页实现（2026-10-15）

Android 页面现已接入远端文件根目录和分页浏览、SAF `OpenDocument` 上传、任务进度/暂停/继续/取消，以及私有下载区到 SAF `CreateDocument` 的单独导出。上传选择器只在 Kotlin 持有临时 URI；回调先核对 ViewModel 保存的句柄、会话连接代次和 app-core 代次，再查询文件名并打开 FD。Rust 接管 detached FD 后运行上传 worker。下载先由 Rust 写入 app 私有区并完成来源校验，只有下载任务进入 `completed` 后才开放导出；导出以可读写、截断模式打开目标，并由 Rust worker 重读目标和校验哈希。UI 明确区分下载完成和导出完成。

选择器身份保存在 `NestLinkViewModel`，页面导航在 Activity 重建时保留。没有待处理 picker 身份的迟到结果会在访问 URI 前丢弃；URI 不进入 Rust、任务状态、日志或持久存储。会话身份变化、退出账号和 ViewModel 清理会撤销待处理选择并请求取消运行中的文件任务/导出。最低平台为 Android 11/API 30，Android 10/API 29 按用户要求排除。

SAF 生命周期补充实现：同一授权会话可暂存多个已校验下载，私有 artifact 数量和总字节有上限，并可从传输历史逐项导出或删除；新进程首次设置私有下载区时，会通过目录 capability 清理本实现命名的遗留子目录。JNI 任务 JSON 单独暴露 `owner_stopped`，UI 在上传源 FD、下载目的 FD 和 worker 真正结束前持续等待。导出失败/取消时尽力截断 SAF 目标并同步报告目标清理结果；仅 worker 线程已 join 后才清理私有 artifact。SAF worker 仍阻塞时 `nativeClose` 保留原句柄，界面提供重试，不允许新连接替换待清理句柄。该补充源码和新增/修改的 `NativeFileStateTest` 尚未构建或执行，不属于下文既有验收记录。

新增 `NativeFileStateTest` 覆盖会话身份解析、旧代次隔离、根目录/分页/任务/导出 JSON、路径与文件名边界。SAF owner 批次已重新编译 Kotlin 应用和测试，并通过 46 项 JVM 测试（0 failures/errors/skipped，`NativeFileStateTest` 11 项），日志为 `artifacts/core-verification/android-saf-owner-jvm-20261015-attempt01.log`。随后新增的 Android host 文件双方向实现尚未包含在这批结果中；此前 API 30–36 模拟器与 APK 结果当时尚不包含 SAF/host 文件源码；该代码已进入上方 1070 输入完整快照并由 127 项 JVM、119 项仪器测试复验。真实 SAF provider 验收仍待执行。

真实设备还需覆盖系统文件选择器取消、Activity 旋转后 picker 回调、提供方撤回访问、不可定位/管道式上传 FD 的拒绝、下载与任务取消竞态、不同 SAF 提供方的 `rwt` 读写回读，以及导出中切换远控会话。无法提供常规可定位文件描述符或不可读回的目标提供方会失败关闭，不会放宽文件校验契约。Windows Authenticode、新 Android 发布签名和 ARM64 Android 真机仍按项目验收表待配置。

## 2026-10-15 历史源码复核

最新 Kotlin/JVM 开发回归通过 35 项（7 个测试类，0 failures/0 errors），日志为 `artifacts/core-verification/android-audio-owner-jvm-20261015-attempt01.log`。新增音频 owner registry 保留 reset 超时和 attach 拒绝的端点，允许之后重试清理；登出/销毁等待协调器与所有 handle 的物理 owner 回收，投屏授权固定发起时的 handle/session binding。该回归没有运行 Cargo/JNI；其后的 `MainActivity.kt` 冗余空值判断已移除，下一批 Android 构建仍需覆盖该源码。35 项 JVM 结果不能替代新双 ABI JNI、APK、API 30–36 仪器测试或 ARM64 真机验收。

Android 10/API 29 按用户要求不属于支持或验收矩阵；最低目标为 Android 11/API 30，自动化模拟器矩阵为 API 30–36。当前源码的 ARM64 release JNI `cargo` 构建（attempt05）和 x86_64 attempt01 均已完成；ARM64 ELF 与 16 KiB `PT_LOAD` 对齐另经检查通过。该证据只覆盖原生库构建/二进制检查：没有据此声称当前源码已组装 APK、运行 API 30–36 仪器测试或通过设备验收。APK、模拟器矩阵、ARM64 真机和发布签名仍须在源码冻结后重新验证。attempt05/01 的本机原始日志不在仓库，因此这里仅保留上面的已报告结果，不伪造可复现日志链接。

用户明确排除 Android 10/API 29；API 30 对应 Android 11，仍属于最低支持版本。本记录中的 API 30–36 x86_64 模拟器 3 项基础仪器测试来自前一验收快照（七个 API 各 3/3，共 21/21）。2026-10-14 的后续布局源码已通过 Kotlin 主源码和单元测试编译；7 项 JVM layout/frame-packer 测试全通过，日志为本机 `artifacts/core-verification/android-layout-unit-20261014-passed.log`。Windows 可通过 `scripts/test-android-unit.ps1` 自动创建并回收临时盘符以绕开中文工作区路径下 Gradle JUnit worker 的类加载问题。该命令排除 Cargo/JNI 构建并原样继承 `CARGO_TARGET_DIR`。

后续尺寸/布局代次实现尚未包含在下表 APK 中：API 34+ 使用 `onCapturedContentResize`，API 30–33 使用默认显示器变更回调；重配时沿用同一 `VirtualDisplay`，更换有界 `ImageReader`/VP8 encoder、清空旧视频队列，并递增 source layout epoch。即使原内容大小改变后缩放仍得到相同编码尺寸，也会退休旧布局并更新 source binding；编码尺寸本身变化时才调用 `VirtualDisplay.resize`；相同尺寸重复通知保持幂等。当前源码的 Kotlin/Gradle 编译与 7 项 JVM 单元测试已经通过，但尚未用当前 JNI 双 ABI 产物重跑 APK 组装和 API 30–36 设备回归。工作树中保留的 JNI 库与旧 APK 哈希对应，不应作为新布局源码验收证据。系统授权弹窗、真实投影撤销、旋转和 Android 14+ 单应用共享尺寸变化仍需在真实系统授权下验收；API 29 不在支持范围。

| API | 模拟器 | 结果 | 本地 Gradle 日志 |
| --- | --- | --- | --- |
| 30 | NestLink-API30-temp-20261014 | 3/3 | `artifacts/core-verification/android-api30-final-source-retest-20261014.log` |
| 31 | NestLink-API31-temp-20261014 | 3/3 | `artifacts/core-verification/android-api31-final-source-20261014.log` |
| 32 | NestLink-API32-temp-20261014 | 3/3 | `artifacts/core-verification/android-api32-final-source-20261014.log` |
| 33 | NestLink-API33-temp-20261014 | 3/3 | `artifacts/core-verification/android-api33-final-source-20261014.log` |
| 34 | NestLink-API34-temp-20261014 | 3/3 | `artifacts/core-verification/android-api34-final-source-20261014.log` |
| 35 | HomeTunnel-API35-x64 | 3/3 | `artifacts/core-verification/android-api35-final-apk-20261014.log` |
| 36 | NestLink-API36 | 3/3 | `artifacts/core-verification/android-api36-final-apk-20261014.log` |

每个 API 均执行相同的三项仪器测试：启动后显示服务端身份验证页、安装种子只以 Keystore 保护的密文保留、远程请求列表抵达 JNI 并拒绝无效句柄。最终包为 `com.zhanry.nestlink` `15.0.0-dev.1`，`minSdk=30`、`targetSdk=36`。

| 产物 | 字节数 | SHA-256 |
| --- | ---: | --- |
| `app-debug.apk` | 42,284,256 | `637c5a10bf7b476616f3571f141127249375df558638eda0efb4956f80cf061a` |
| `app-debug-androidTest.apk` | 2,208,633 | `11d8098af3ee83ca28e086c562cc9d8bd91ea9a8aecf76947f2999680e1108b11` |
| ARM64 `libnestlink_android.so` | 6,149,600 | `8729a3ee5dcd33344d2f0e0a4c812ca770617cb9c86284de9c751d30d2922710` |
| x86_64 `libnestlink_android.so` | 7,027,400 | `c12a61814ce8d31a755c2eb543451802c1381f944517bf2154659240bc5c2b45` |

Android 构建输入由 `Cargo.toml`、`Cargo.lock`、`rust-toolchain.toml`、`apps/android`、`crates` 和 `protocol-spec` 共 372 个文件组成，忽略构建输出后合成的 SHA-256 为 `569be52a4dfba761e0c073f47d1b6655ab6e6579e04c897542b27732091d89cb`；逐文件哈希清单保存在本机 `artifacts/core-verification/android-source-inputs-20261014.sha256`。该快照对应基线 HEAD `1e43481ae4a872b946af9a0f11c9b15ac61a8721` 加当时工作树中的源码改动。

ARM64 和 x86_64 JNI 库均已包含在最终 APK 中；七版运行测试使用 x86_64 模拟器，ARM64 真机运行仍未验收。API 30–34 的临时 AVD 与本轮下载的 system image 已逐版删除；API 35/36 使用既有 AVD 并在验收后关闭。正式 Android 签名身份及发布签名包仍待配置。首次 API 30 重试期间 Gradle 环境缺少 `cargo`，导致生成目录被清空并产生一次缺少 JNI 的失败包；从成功构建留下的最终 `.so` 恢复并确认双 ABI 打包后，API 30–36 全部使用上表 APK 哈希完成通过回归。成功的 JNI/APK 组装日志为 `artifacts/core-verification/android-final-source-jni-assemble-unit-20261014.log`。

最终清理核对：API 30–34 临时 AVD 和对应 system image 均不存在；API 35/36 AVD 定义保留但已关机；ADB 无连接设备，emulator/QEMU 进程为零；C: 剩余空间 23.25 GiB。

矩阵日志和 APK 哈希对应上表记录的构建快照。之后全工作区 `cargo fmt` 规范化了 `crates/app-core/src/lib.rs` 的格式；同一时段 storage 浏览器端点代码与测试也有后续修改。storage 不属于 Android 依赖图，AppCore 变更仅为 rustfmt 排版；因此这里的通过结果仍是已测 APK 的真实开发回归，但其记录源码指纹不是现在工作树的全仓指纹。最终签名发布必须在全部实现冻结后从同一源码版本重建并验收。

## Native codec supply and 16 KiB page checks

Android 10/API 29 is outside the supported range. Codec and JNI builds target Android API 30 and package both `arm64-v8a` and `x86_64`. On 2026-10-14 the pinned libvpx 1.16.0 and Opus 1.6.1 sources were built locally for both ABIs with Google NDK r27c (`27.2.12479018`), Linux x86_64 host tools, CMake 3.28.3, Ninja 1.11.1, GNU Make 4.3, and NDK Clang 18.0.3. The NDK archive was matched to the repository lock: 663,987,688 bytes, SHA-1 `090e8083a715fdb1a3e402d0763c388abb03fb4e`, SHA-256 `59c2f6dc96743b5daf5d1626684640b20a6bd2b1d85b13156b90333741bad5cc`.

Both real supplier receipts passed `scripts/refactor-native-codecs.py verify`. Every member of each static archive was inspected as ELF64 before the receipt was written:

| ABI | libvpx object count / machine | libvpx SHA-256 | Opus object count / machine | Opus SHA-256 | receipt SHA-256 |
| --- | ---: | --- | ---: | --- | --- |
| `arm64-v8a` | 115 / AArch64 (183) | `b35828f213c284397f6c8c2000a97d06aa27ff8547794ee0331cb8f652985cbd` | 147 / AArch64 (183) | `00a5a9007228f3ce97bcecf90be42e0971957fdc1ed1c1f6c98d007a10d12d46` | `f999b290b1bcebd8174bcbe10cdd23b639f466cda0d7373b03c29560288b4236` |
| `x86_64` | 128 / x86_64 (62) | `e37684d12ad03850dc8929b6b535892aa27015c8804cc2a4b4cac5894f08a0d4` | 152 / x86_64 (62) | `22cd8ab4535dfeff65341e551cadf7a2a2052349456f7ee869fd35c8160da72f` | `235f83d9562bc3306387e879d466de442fc22fe893928efa7ce3d6ccc727d8cf` |

The receipts are in the WSL Linux filesystem under `/home/popdo/.cache/nestlink-android-codecs/builds/` on the C:-hosted WSL virtual disk. Each records the NDK revision, API, compiler/tool hashes and versions, full configuration, command logs, static archive hashes, and source-tree digests. The Opus compile commands include the Android API 30 target and sysroot plus `-D__BIONIC_NO_PAGE_SIZE_MACRO`; the checked CMake configuration enables `ANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON`. A local compatibility wrapper handles the GNU `strip -o` form emitted by libvpx when it invokes NDK `llvm-objcopy`; it does not modify upstream sources.

Gradle now builds Cargo once per ABI and supplies the matching codec receipt prefix to each invocation. After each JNI build, `scripts/verify-android-binary.py` checks ELF machine identity and every `PT_LOAD` alignment and offset congruence at 16 KiB or larger. The Android CI first builds and verifies the two prefixes, then reuses those prefixes across the API 30–36 emulator matrix; it also checks the assembled APK with Build Tools 36.0.0 `zipalign -c -P 16 -v 4`.

As a separate check of the previously recorded APK artifact, its ARM64 and x86_64 JNI libraries matched the hashes in the table above and each LOAD segment had 16 KiB alignment. The APK SHA-256 is `637c5a10bf7b476616f3571f141127249375df558638eda0efb4956f80cf061a`; local Build Tools 35.0.0 reported `zipalign -c -P 16 -v 4` successful. That binary predates the current codec-prefix wiring, so the updated end-to-end Cargo/Gradle path is enforced by the new CI job and must be rerun from the final source snapshot before release.
