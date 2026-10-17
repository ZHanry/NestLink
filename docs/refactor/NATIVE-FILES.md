# 原生文件能力实施状态

2026-10-15 下载跨进程恢复已合入 24 路径：持久记录精确任务、原目录/对象和已同步前缀事实，不存旧许可或本机同意。重启仅显示等待新批准；SDK/Core/daemon/认证 IPC/桌面接入新证明会话中的明确恢复操作、独立磁盘复验、有界跨重启保留预算及部分文件导出。Windows/Linux 平台恢复分别通过 15/16 项，SDK 真实进程终止后以新 TLS/QUIC 证明恢复各通过 3 项，同目录重新批准的 daemon owner 撤销组各通过 7 项。双平台 strict 与原失败/复验的精确范围见 [集中检查](NATIVE-INTEGRATION-CHECKS-2026-10-15.md)。实现边界见 [恢复说明](NATIVE-FILE-RECOVERY.md)；Android SAF、浏览器存储和上传重启仍有各自独立边界。

2026-10-15 配额维护增量已合入：`nestlink-daemon file-quota inspect|export|recover --state-dir ...` 只操作本实现的私有元数据，须取得既有稳定锁，拒绝活跃 owner。export 固定新建快照并保留原始字节/SHA；recover 对两个有效记录逐字段取最大，不明用量饱和到配置上限，拒绝损坏权限/链接/类型和不同配置，不扫描用户文件或清零额度。Windows strict 编译通过；本轮实际回归发现一个 Windows 锁下直接读 marker 的夹具错误，待调整时序复验，不能宣称整批通过。下载订阅现在由订阅 future 驱动原真实线程 owner 的非阻塞 join，保留此前 watch 更新；原八个完成通知失败正在集中复验。日志均保留各次源码与原始失败。

2026-10-15 当前接线：Core 已拥有每个原生会话的一次性 FileRead/FileWrite claim、串行浏览/下载/上传 actor 和最多 128 项任务状态。daemon 在获准宿主会话建立时先启动空的动态根目录服务，本机明确选择只增加对应的目录批准，撤销只关闭那个根的同意。尚未批准目录时可返回空清单，不因重复领取通道或无响应超时破坏观看会话。本机完整路径仅进入认证的用户 IPC 和平台适配；对方仅收到 root ID、用户给出的显示名和可移植相对路径。

桌面已加入目录选择、独立的目录元数据同意、根目录清单、分页浏览、单文件下载/上传、进度以及下载暂停/继续/取消。UI 回复同时匹配 daemon runtime、Core generation、request ID 和 connection generation，任务由 Core 持有，不随 IPC 请求 future 或窗口销毁丢弃。目录浏览回复丢失时回收当前浏览，并保留固定快照截止时间。清理超时后任务和服务继续持有实际工作线程，运行错误和物理清理结果分别记录。

Android 已加入 SAF 文件页和 JNI 接线：远端根目录/分页浏览、SAF 上传、Rust 任务控制与进度、私有目录中的多下载保留历史、逐项导出和删除。下载 artifact 的数量与总字节有界；Android 重启后首个会话清理应用私有下载区内本实现命名的遗留子目录。任务 UI 等待 `owner_stopped` 后才开放 artifact 操作。SAF 失败/取消的目标清理结果单独显示；关闭期间如果阻塞 worker 仍持有 detached FD，会保留 native handle 并允许用户重试清理，禁止新连接覆盖。Android 10/API 29 按用户要求排除，最低为 Android 11/API 30。以上 SAF 补充源码已纳入 2026-10-16 的 1070 输入 Android 快照；同批 127 项 Kotlin/JVM 与 API30–36 七版各 17 项 instrumentation 通过，双 ABI JNI/APK 和静态对齐也通过。该证据仍是开发签名的 x86_64 模拟器验证；真实 SAF provider、ARM64 真机与正式签名验收尚未完成，详见 [Android 验收记录](ANDROID-VERIFICATION.md)。

这些内容已有对应的开发编译与回归证据，但尚未据此宣布正式产品验收完成。Web 产品流程、跨平台端到端传输、真实 SAF provider、Android 固定签名与 ARM64 真机，以及固定产物安装和跨网验收仍待执行；通过项以最新原始测试记录为准，不沿用旧快照。

已接入 `nestlink-remote::files` 的有界文件读取服务、客户端、完整内容校验与续传验证器，以及 `nestlink-platform-files` 的本机目录批准和 Windows/Linux 句柄相对文件适配。完整协议、资源上限、撤销/缓存边界及阻塞文件系统清理语义见 [native-file-read.md](../../protocol-spec/native-file-read.md)。

当前已加入本地明确选择的私有下载区和 `LocalDownload` 存储适配，真实前缀/完整磁盘重读校验、精确客户端 owner/UUID 绑定、源完成与取消区分、同文件系统原子不覆盖发布，以及撤销/清理事实记录。行为及边界见 [native-download-storage.md](../../protocol-spec/native-download-storage.md)，本批冻结检查见 [download-storage-checkpoint-2026-10-14.json](download-storage-checkpoint-2026-10-14.json)。初次 Linux 回归发现直接同步 `O_PATH` 目录句柄的 EBADF，已改为从原能力打开可同步读句柄；原源码与失败日志保留。

目的端现已接入 owned std 工作线程，文件级取消不终止观看、异步等待取消不会复用迟到回执、确认暂停屏障后可对同一签名资源和源路径进行新连接接续，阻塞磁盘、注入磁盘满、实际发布与独立清理错误保留监控事实。源 Cancel 在网络确认前就使缓存目的端视图失效；旧块 snapshot 不能升级为 End。契约见 [native-download-worker.md](../../protocol-spec/native-download-worker.md)。2026-10-15 集中回归中的平台文件 63 项传输测试通过，原始日志为 `artifacts/core-verification/native-files-clipboard-regression-20261015-attempt04.log`；同批 Core/remote 尚有失败，此部分通过不代表整批或正式验收通过。

原生 SDK 已加入 `NativeFileDownload`：拥有式 actor 始终消费确切源 RPC，取消先停止本地保存，再消费慢源请求和源 Cancel；暂停后按真实已确认磁盘前缀接续。应用等待取消不会中断半个源协议请求。终态可取回带安全析构的原客户端，保留序号和 owner 继续同连接的下一文件；显式退休只封闭 FileRead 的原 claim，拒绝重新领取且丢弃迟到文件帧，观看保持当前授权。没有精确关闭所有源或仍有未消费请求时禁止这种退休。错误和各次源清理事实有界保留，见 [native-sdk-files.md](../../protocol-spec/native-sdk-files.md)。

本机目录元数据基础已加入独立目录同意、no-follow 能力查找、全目录有界固定快照、逐页重验、不可伪造本机 cursor、原操作及快照截止时间、单个 owned worker 和真实清理监控。目录批准不授予内容读取或上传权限；当前 cursor 不能序列化用于网络。详细边界见 [native-directory-storage.md](../../protocol-spec/native-directory-storage.md)。

桌面 Core/daemon/IPC 流程已接线，本机选择同时提供 Windows COM 文件/文件夹对话框和 Linux XDG FileChooser。选择器由当前桌面程序的独立子进程持有，路径经有界私有管道返回；会话或 daemon 身份改变时取消旧选择，迟到结果不能用于新会话。选择目录仅填写本机表单，读取内容、披露目录元数据或允许上传仍须分别明确批准。下载区和接收区在选中的父目录下生成新的私有目录名。选择器的编译与隔离测试、真实 GNOME/KDE/Windows 对话框验收按各自日志记录；详见 [系统选择器](NATIVE-SELECTION.md)。聚合文件配额、进程重启后的持久恢复、既有保存目录导出、Web 工作流及跨平台固定产物验收继续实现。下文历史日志仅覆盖各自冻结快照。

本批开发回归和精确源码归档记录在 [file-read-checkpoint-2026-10-14.json](file-read-checkpoint-2026-10-14.json)。Windows 完整 Rust 回归为 369 项，初次 Ubuntu 文件/协议专项为 30 项，两端各 37 项 Python 工具测试。初次 Ubuntu 所选核心测试另有提前停止失败，当前证据未确认该次停止原因。用户随后明确授权临时切换 WSL 时钟源并恢复；完整 Ubuntu 回归、切换/恢复核对及原失败分别记录在本批检查点，专项通过不替代完整 workspace 回归。

固定新增供应的完整源码归档、身份、校验和与所有 LICENSE/NOTICE 见 [供应材料](file-read-suppliers-2026-10-14.json)。`winx 0.36.4` 仅声明 `Apache-2.0 WITH LLVM-exception`；完整文本审查和限定版本的 cargo-deny 处理见 [许可审查](file-read-license-review-2026-10-14.json)。第一方继续采用 Apache-2.0，供应商许可不变。完整产品 SBOM/NOTICE、时钟、签名、真机、实际跨网和正式验收条件继续保留。
