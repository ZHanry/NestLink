# 原生下载进程重启恢复

Windows、Linux 原生 daemon 现在持有每个安装用户状态空间内的持久下载事实。下载被强制终止后，桌面可列出中断任务、重新批准并验证后恢复，或核对清理暂存、另存明确标记为 `.partial` 的已确认部分。

恢复不是原授权的延续。控制端与主机必须重新建立获准的 FileRead 会话并完成两端证明；主机要再次明确选择共享目录，控制端要在这个当前会话中勾选并点击恢复。SDK 比较新的真实客户端与保存的 deployment、security epoch、account、两端设备及公钥指纹、resource；源目录 ID、相对路径、长度和完整 SHA256 也必须完全相同。主机的稳定目录 ID 仅关联经 no-follow 打开的目录对象，不能使旧共享同意复活。

## 保存的事实与权限边界

`protocol-spec/native-file-recovery.rs` 是跨层类型的唯一来源。持久 JSON 只含任务事实和实际存储结果，没有 permit、旧 session/client binding、connection generation、endpoint proof、私钥、口令或 consent。保存的行只能用于展示、核对本机对象和构造需要再次授权的请求，不能自行产生网络传输。

SDK 通过当前 Core route 和正常有界下载队列创建新任务 ID。新源以原完整摘要和精确 durable checkpoint 重新 Open；平台目的端再次比较 sealed snapshot。旧 SDK actor、旧 Core taskbook、旧绑定和旧 consent 均不反序列化。每个磁盘步骤仍由 owned worker 上当前授权回调限制。

## 暂存、配额和崩溃

每个 store 有一个保持路径不变的 OS 独占锁，一个 committed ledger 和一个固定 pending 名称。JSON 最多 512 KiB，最多 128 个任务记录及 128 个经重新选择的读目录身份记录；每任务最多一个下载目录和一次导出目录尝试。达到容量时明确拒绝新任务，不分配额外暂存目录。终态记录和空私有目录保留，不执行任意递归删除。

下载在创建暂存对象之前持久预留完整 manifest 大小；尚未重新批准的中断任务、清理失败的暂存继续收费。导出另为其 checkpoint 长度预留第二份暂存预算，发布并确认移除导出暂存后才释放这份预算。已发布的完整文件和显式导出的 `.partial` 用户文件不再作为暂存收费。

写入先同步原文件，再提交 checkpoint 长度和前缀 SHA256。启动遇到有效的下一序号 pending 时采用旧 committed ledger，并移除 pending；不会把未提交长度当成已确认。损坏的 pending、丢失的已初始化 ledger、改变的配额参数、第二个活 owner、不可识别的序号均 fail closed，绝不静默清零。首次建立元数据的特定空 pending 可以完成初始化。

| 中断位置 | 重启后的行为 |
| --- | --- |
| 已预留，原对象身份尚未提交 | 保留预算；无法凭文件名猜测 ownership，等待精确核对 |
| 文件比 checkpoint 多出尾部 | 新授权后 no-follow 重开原对象，重读并核对所有 checkpoint 字节，再在同一原句柄上精确截回并同步；否则拒绝 |
| 实际前缀改变、变短、目录/文件被替换、额外硬链接或链接目录 | 拒绝恢复；保留未确认清理的占用和错误事实 |
| 同步文件后、提交 checkpoint 前 | 仅采用旧 checkpoint，多出的字节不算已确认 |
| 正式发布前 | 持久 Publishing 意图；发布采用同文件系统 hard-link no-clobber |
| 正式发布后、暂存移除前或移除后而结果未提交 | 核对原目录/对象身份及完整摘要，识别两链接或仅最终件状态，保留最终件并清理已识别暂存 |
| 部分导出创建/写入/发布/清理中断 | 保留独立导出对象事实和预算；“核对并清理暂存”同时处理原下载和导出暂存，保留已发布 `.partial` 最终件 |
| 磁盘写入、同步或元数据持久化失败 | 记录可确认的结果与错误；不把失败当作成功，不猜测释放占用；持久化失败的 owner 拒绝继续变更，需重启核对 |

恢复的目录路径逐组件 no-follow；Windows 只接收本地磁盘绝对路径。原目录、文件 dev/inode、regular file、链接数和摘要共同核对。文件系统对象 ID 可能被文件系统重用，不声称仅凭 ID 可抵御恶意同用户任意篡改；当前授权、私有状态目录及内容摘要仍是独立边界。原句柄仍在时发生的失败清理也先核对句柄及条目，不能仅凭相同文件名删除替换件。

Windows 报告真实文件同步结果，不声称目录 fsync 或断电持久性已验收。操作系统调用已发出后可能在撤销后完成；实际发布、暂存移除、同步与错误分别记录，既有最终件不会被回滚删除。

## 本机操作

经过用户级 TLS IPC 身份验证的 `NativeDownloadRecovery` 支持：

- `List`：不需要活远控会话，返回事实和聚合暂存预算。
- `Resume`：要求当前 request ID/connection generation、新 FileRead 权限与证明、`approve_local_resume=true`；成功排队仍不代表文件验证和下载已完成。
- `Cancel`：不依赖旧远控许可；仅清理核对过的原下载/导出暂存，失败占用继续显示，不删除任何最终件。
- `ExportPartial`：要求全新本机目录、`.partial` 文件名和明确未完成确认；只复制并复核 checkpoint 前缀，原下载保留且继续收费。每任务只有一次有记录的导出尝试，避免崩溃重试堆积目录。

桌面按当前 daemon runtime 和完整 FileSession 绑定恢复同意；普通事实刷新保留同会话勾选，会话换代、任务失效、断线或请求拒绝清除勾选。恢复排队后，新 task ID 接入正常文件进度轮询。

## 验证状态与范围

此增量包含平台真实文件系统的锁、配额、前缀/尾部、替换/硬链接、Unix 链接目录、pending、正式发布和部分导出崩溃矩阵 fixture；SDK 测试会启动一个独立子进程，经真实 TLS 或 QUIC 和两端证明写入部分后，由父进程强制结束，再用新随机 session ID、新 permit、新证明和新本机同意恢复。固定 seeds 仅用于测试进程之间保持公开的测试主体，不读取或持久化产品私钥。另含 daemon 缺少明确批准时无磁盘变更、离线 List 及桌面刷新/会话换代回归 fixture。

整合后的 Windows/Linux 开发回归已实际执行：平台恢复分别通过 15/16 项，SDK 强制结束子进程后以新 TLS/QUIC 证明恢复各通过 3 项；Core 原生会话各 4 项、IPC/桌面各 41 项通过。同目录重新批准的 daemon 真实 owner 撤销组修正读取样本长度后，两端各通过 7 项。首次夹具失败与后续通过分别保留，不能把原失败批次写成整批通过。双平台 all-target strict Clippy 和本次 server/daemon 复验通过。精确源码、日志、时钟观察和 scratch 回收记录见 [集中检查](NATIVE-INTEGRATION-CHECKS-2026-10-15.md)。

原生上传协议没有可在新会话中重新批准的远端 durable staging token，本增量明确要求重发上传，不报告上传重启恢复成功。Android 11–16 SAF 和浏览器文件存储保留各自已有实现，未接入本机文件系统 journal。真实跨网、签名安装包、ARM64 Android 真机、断电与完整 GUI 平台验收仍依赖主任务的实际环境证据。
