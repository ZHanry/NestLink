# Android 被控端文件

范围为 Android 11–16（API 30–36）。文件两方向分别申请并批准；文本剪贴板的独立授权与本机方向见 [ANDROID-CLIPBOARD.md](ANDROID-CLIPBOARD.md)。业务方向授权不构成本机存储授权。

## 读取

本机明确确认共享名称、大小和快照内容后，通过 SAF 选择单个或多个文件。URI 和原父目录留在 Kotlin，JNI 只接收便携文件名、独占 detached FD 和原生会话身份。仅接受可定位常规文件。

Rust 保留真实快照线程及 FD，在新 UUID 私有目录复制所选文件，比较源复制哈希、源再次完整读取的哈希及元数据，再同步并完整重读私有副本。快照线程实际 `join` 后才把该单文件目录登记到动态 `FileReadDevice`。原目录不构成共享根。`FileRoots` 只允许所选文件名，`BrowseRoots` 只披露这一个私有快照。

所有读取、目录披露和交付继续检查真实 Core route/session permit、本机会话 flag 与独立文件 flag。撤销或原会话替换后的迟到线程不能登记；现有 source/browse 持有原 `ReadEntry`，其实际 handle 释放前不删除目录。

## 接收

本机单独批准本次新私有接收区后才披露可写 root。历史目录不接受为新 root；每个传入文件使用独立 UUID 子目录，仅接受单层常规文件名。同一本次接收 root 内，已预留、已发布或待清理的同名文件均拒绝重复写入；只有明确删除并确认清理后才可再次使用名称。权限批准不会复用主控下载区域批准。

真实 `WriteRoots` 平台 adapter 对完整对象重读、检查长度和哈希、同步，然后在应用私有文件系统以不覆盖方式发布。SAF 不参与远端 commit。包装 destination 在失败和 Unknown completion 路径保留实际 `published`、完整校验及暂存清理事实；真实 destination destructor 关闭 handle 后才公布本机 owner 停止。发布后的文件只能通过本机再次明确发起 SAF 导出，不自动开放原文件系统目录。

## 容量和退出

共享快照与接收共用 **8 artifacts / 4 GiB**。运行中的复制、声明大小的 staging、已完成文件和待清理数据都计入。准备快照在 `stat` 或复制前预留当前剩余上限；实际 `join` 后成功登记才缩小为已校验大小。接收在首次 staging I/O 前预留声明大小与一个槽，零字节文件也占一个槽。失败不能直接恢复额度，只有同一 retained cleanup thread 实际 `join` 并确认私有清理成功后才释放。

原会话结束或关闭时立即撤销本机 flags，并保留 Core 的真实 FileRead/FileWrite server monitors、实际 snapshot/cleanup/export JoinHandles 与全部私有记录。关闭必须同时确认 Core shutdown、两方向 monitor `finished` 和所有本机清理；Pending 或清理失败保留原 native handle，以同一句柄重试。Kotlin 的 provider 准备、状态刷新和保存目标清理 Job 注册后才启动，阻塞 I/O 不因 ViewModel cancellation 失去实际 owner。

## SAF 导出边界

导出沿用现有 `export_verified_file`：接受新建、可定位读写的空常规 FD，重读完整私有源，写入并同步，完整重读目标且检查实际长度。失败尝试清空目标并准确记录不能确认的清理事实。完成 phase 不等于 owner 已停止；保留 FD 和 JoinHandle，实际 join 后才公布退出凭据。导出后私有接收文件仍占额度，用户可明确删除。

不承诺 SAF provider 的原子不覆盖重命名。云端 provider、管道、特殊文件和不能提供定位读写的 provider 可能不支持本契约。实际 API 30–36 设备和 SAF provider 验收仍需完成。

## JNI 接口

`NativeSdk.kt` 与 JNI 成对提供：`nativeConfigureHostFileArea`、`nativeHostFilesAttach`、`nativeHostFilesStatus`、`nativeHostFileShare`、`nativeHostFileApproveReceive`、`nativeHostFileDiscard`、`nativeHostFileExport`、`nativeHostFileExportCancel`。统一 Status 返回绑定、真实 owner 状态、私有清理、容量和按创建顺序排列的导出凭据，不返回路径或 URI。

2026-10-15 对冻结的 Kotlin 源码强制重新编译并运行 `:app:testDebugUnitTest`，49 项全部通过，失败、错误与跳过均为 0；其中新增的 3 项覆盖 host 角色/精确绑定、默认关闭及缺失 owner 凭据时禁止导出。执行日志与源码哈希凭据保留于 `artifacts/core-verification/android-host-files-jvm-20261015-attempt01.log` 及同名前缀 `.receipt.json`，执行期间源码未变，本次 scratch、Java 进程与临时 SUBST 均已回收。

本轮 JVM 回归排除了原生 Cargo/JNI 构建，不作为 Rust、JNI 链接或设备验收依据。新增 Rust 存储用例覆盖真实单文件快照、共用容量、staging 前拒绝、真实发布后 Unknown completion、阻塞真实 FD 保留；集中 Rust 回归与 API 30–36 真机 SAF provider 验收仍需单独确认。
