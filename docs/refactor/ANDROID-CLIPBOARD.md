# Android 文本剪贴板

范围为 Android 11–16 / API 30–36。`ClipboardRead`（读取主机剪贴板）与 `ClipboardWrite`（写入主机剪贴板）分别申请、分别批准。业务权限不会自动开放任何一端的系统剪贴板。

## 精确授权与本机方向

复用 Core 的 `native_clipboard` 路由、真实双向 transport claim、mutual proof、当前业务 lease 和 `request_id + connection_generation + core_generation` 绑定。JNI 不创造授权。UI 事件携带原绑定，迟到点击不能给替换后的会话授予方向。

双方各自明确确认本机读取/写入，默认均关闭。主机本机读取对应 `ClipboardRead`，本机写入对应 `ClipboardWrite`；控制端本机读取对应 `ClipboardWrite`，本机写入对应 `ClipboardRead`。本机选择不能超出业务许可。初次确认后只能减少方向；增开或恢复已撤销方向需要新的会话。

主机仅在本机批准的方向响应请求；控制端通过“复制远端文本到本机”或“发送本机文本到远端”明确执行一次操作。没有剪贴板变更监听器、自动同步、启动读取或系统剪贴板轮询。界面每秒刷新的仅为 Core 授权和静态平台结果。

## 平台访问与结果

复用 `platform-clipboard::ClipboardDevice` 的真实 worker、原始期限、逐方向 guard、monitor 和唯一原 JoinHandle。Android `ClipboardManager` 在该 worker 的 JNI 调用中同步执行；没有向主线程或其他协程排队的脱离 owner 操作。阻塞 Binder 调用由原 worker 持有，超时不等于实际平台调用或清理已经停止。后端关闭及析构完成后，还必须实际 join 同一线程才能公开清理完成；清理逾期或失败不会因迟到 join 恢复成功。

启动失败且原线程清理无法及时证明时，`open` 交付 inactive failed owner；Core 在安装前调用 `check()`，收到原启动错误后继续保留原 owner。跨平台最多保留 32 个真实 worker owner，包括阻塞启动与析构 owner；成功 spawn 后仅实际 join 释放名额。析构超时的同一 Shared/JoinHandle 进入有限保留表，后续 open/close/monitor 对 finished 原线程实际 join；没有后台 reaper 或替换 worker。

每次系统读写前后都检查应用 resumed、实际窗口焦点、设备交互/解锁状态、原 native handle 和精确 Core 本机方向授权。后台、失焦和系统拒绝准确返回失败；不会通过无障碍、输入法或其他权限绕过 Android 剪贴板限制。

只读取单项纯文本，不调用 `coerceToText`，不解析 URI、Intent 或 provider。文本上限为 64 KiB UTF-8，拒绝 NUL、无效 UTF-8 与未配对 UTF-16 surrogate；编码前先计算字节上限。`getPrimaryClip` 返回空值只报告“未提供可读取文本”，不会承诺已成功读取空剪贴板。

`setPrimaryClip` 调用之后的异常、失焦、撤销或期限到达统一保留 `Unknown`/“可能已改变”事实，不能报告确定未写入。系统写入使用纯文本 ClipData，API 33+ 标记敏感内容。远端是否收到写入回执继续由现有协议决定；平台调用成功本身不构成远端交付成功。

## 内容和关闭

文本仅经过现有 SDK/协议与平台操作。NativeSdk 的状态/操作 JSON、MobileState、错误和日志只含绑定、方向与静态结果，不含剪贴板内容。JNI 异常只清除，不 describe 或转发异常消息。

JNI 读取在状态失败、无效长度、字段或复制失败时仍尝试同步清空结果对象的 byte[]；写入 byte[] 在 Kotlin finally 与 JNI 中清空。Rust 文本与字节使用 `Zeroizing`。Android 系统剪贴板及 ClipboardManager 接口要求的托管字符串由 Android/JVM 管理，不声称可以清零所有系统或托管副本。

撤销先降低 Kotlin 原 endpoint 的原子 gate，再调用 Core 降低该方向；没有可重新开启的旧 token。关闭先标记原 handle closing 并关闭 endpoint gate，保留已注册的真实 Kotlin Job；Core 继续负责真实剪贴板 worker/transport/monitor 清理。Job 在启动前登记到原平台 owner registry，清理未确认时不能关闭或替换原 native handle。

## 开发验证

新增 3 项 Android 平台 worker 回归，覆盖启动/健康检查不读写系统剪贴板、单方向撤销不触及 OS、真实阻塞线程超时撤销后保留同一 JoinHandle 且迟到清理仍报告失败；通用 worker 新增 6 项回归，覆盖后端关闭成功但析构仍阻塞、阻塞启动、未知析构 owner 有限保留、启动清理证明失败、原启动错误保留，以及仅在 callback 捕获资源释放后交付无 owner 的错误。正常关闭用例同时检查后端实际析构和同一线程实际 join。新增 8 项 JVM 回归覆盖默认关闭、角色方向映射、原绑定代次、前台焦点、单调撤销、Unicode 字节预算及无效文本。

当前 Kotlin/JVM 源码已通过 57 项测试（10 suites，0 failures/errors/skipped），日志为 `artifacts/core-verification/android-clipboard-jvm-20261015-attempt01.log`，原始 XML 和源码未变化 receipt 一并保留。Android bridge 18 项 Rust 测试与此前 bridge/platform-clipboard all-targets strict Clippy 通过，分别记录在 `android-bridge-owner-rust-tests-20261015-attempt02.log` 与 `android-native-clipboard-rust-clippy-20261015-attempt04.log`；这两份结果先于通用 worker 生命周期修复，不覆盖当前修改后的 platform-clipboard 源码。Android adapter 首轮 2/3 失败原件保留在 `android-clipboard-adapter-rust-tests-20261015-attempt01.log`，该失败暴露后端关闭返回早于真实 join 的生产问题。

通用 worker 生命周期修复和新增用例已准备供主线程集中验证，本子任务未运行本次 Rust 构建、JNI 链接、APK 或设备验收。68 对 NativeSdk/JNI 参数与返回类型静态一致不构成真实 JNI 通过。集中回归仍需从最终冻结源码运行 platform-clipboard Rust tests/strict Clippy、双 ABI JNI/APK 及 API 30–36 的前台/后台、锁屏、系统拒绝、方向撤销和真实端到端验收。
