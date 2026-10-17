# 原生文件上传、独立同意与实际发布

`NativeFileWrite` 也提供独立的 `FileRootsRequest` / `FileRoots` 动作，因而
远程目的地发现只需要 FileWrite 权限，不依赖 FileRead。响应是最多
`FILE_WRITE_ROOTS` 个本机选择器标签的单页列表，按 root ID 排序；只发送
root ID 和 `display_name`，不发送本机路径。服务端在入队前及实际写入前
检查每个列出的 root 的当前同意；撤销会让队列中的旧列表被替换成拒绝回执。

`NativeFileWrite` 是 `protocol-spec/nestlink.proto` 中唯一的原生上传封包。它使用已经完成双方持钥证明的 `FileWrite` 可靠通道，逐次检查当前会话的 **FileWrite** 权限及连接代次；FileRead、目录浏览同意和观看权限不能代替写权限。上传消息包含严格递增的请求序号和传输 UUID，同一 UUID 在本运行中永不重新打开。

`nestlink-remote::upload::FileWriteClient` / `FileWriteServer` 分别拥有独占通道消费者；`nestlink-sdk::upload::NativeFileUpload` 提供应用拥有的实际文件流程。客户端队列入站字节或本地源已读取的字节都不算上传完成；只有收到匹配完整清单的 `Committed`，并且其中实际发布、文件关闭、暂存移除事实全部成立，才算成功。

## 两端本机选择

被控本机明确选择可信父目录下的**全新私有接收区**、本地目录 UUID、单文件上限和总接收配额，获得 `WriteRootSelection` / `WriteRootConsent`。选择器构造不访问磁盘；`WriteRoots` 由服务端磁盘线程初始化。Unix 新目录 0700、新文件 0600；Windows 使用现有第一方平台安全模块的 owner/SYSTEM 受保护 DACL，暂存文件继承私有接收区权限。既有公共目录不能自动成为这个接收区。

本机源文件由 `LocalUploadSelection` 明确选择，另持有独立的 `LocalUploadConsent`。源文件与远程目的名称没有路径推导关系。选择器只记录本机路径及限额；源工作线程才打开和持有该文件，复用现有 FileRead 平台适配的单组件 no-follow、普通单硬链接文件、文件系统边界、原句柄内容和元数据检查。这里的复用是本机读取实现，不需要远程 FileRead 权限，也不赋予对端任意读取本机文件的能力。

远端只提交批准目录 ID 和便携相对路径。现有目录层级由每个组件的 handle-relative no-follow 查找进入；不自动创建远端指定父目录，不使用 canonicalize 后按 ambient 路径重开。符号链接、Windows junction/reparse parent、不同文件系统、路径穿越、UNC/盘符、ADS、控制字符、设备名和歧义名称拒绝。批准的是实际已打开根对象，Unix 原路径被本机更名或替换不会重新选择新路径。Windows 暂存原读写句柄仅共享读取；其他写入/删除/重命名在原句柄持有期间由 OS 拒绝。

## 请求、背压与完整性

`Open` 声明目录 ID、相对路径、精确完整长度和完整 SHA-256。成功 `Ready` 必须原样保持长度/摘要，起点为零。每次 `Chunk` 含精确当前偏移、非空字节和块 SHA-256；数据最多 61440 字节，整个封包不超过 65536 字节。一次只读取、发送、等待一块。服务端在写盘前检查完整块摘要、精确偏移和清单范围；`Ack.offset` 只在适配实际确认该整块落入暂存文件后前进。

`Commit` 必须保持原完整长度和 SHA-256，确认字节数必须恰好等于原长度。服务端先检查收到字节的滚动完整摘要，再从**原暂存句柄重新读取实际完整磁盘内容**并核对摘要、对象和长度，再同步文件数据。源工作线程也从原源句柄再次验证完整内容及元数据；源变化不能以先前摘要通过上传。

完成时在同一文件系统中用原子 hard link 创建最终名称。既有普通文件、硬链接、符号链接或目录都不能被替换。目标在最初检查后被本机其他进程创建，同样在实际发布调用时拒绝覆盖。发布后关闭原文件句柄并删除本上传自己生成的随机暂存名称。Unix 从原目录能力打开可同步目录句柄并实际 fsync；Windows 不声称已经完成目录 fsync 或断电持久性验收。

`FileWriteState` 分别记录确认字节、已发布、文件关闭、暂存移除、目录同步和 poisoned 状态。实际发布系统调用返回成功后，先记录 `published=true`，再做后续同意检查；撤销/期限在发布调用中到来，异步调用会拒绝返回成功，但不能把已经发布的文件改称为未发布，也不能在清理时删除最终文件。失败回执保留这些实际事实，无 OS 路径或原始错误文本。

## 容量、取消、撤销和期限

最多 16 个写根、4 个活动目的端及 256 个传输记录；取消、失败和完成都保留 UUID 墓碑。清理尚未完成的目的端仍计入活动容量；不能用失败移除计数而继续打开无界暂存文件。本机根配额为声明中的活动字节加上本 owner 实际发布的字节；失败且实际清理/销毁后的预约才释放，发布字节继续计入本运行配额。

需要跨 daemon 重启保持的总接收配额必须由本机显式私有 state 目录打开 `WriteQuota::open_private_ledger`，并在该配额 owner 的整个生命周期内独占 ledger lock。`WriteQuota::new` 是内存 fixture/兼容入口，不提供跨重启容量保证。持久 ledger 只保存固定上限、已预留字节数和 artifact 数及校验值，不保存文件内容、传输 UUID、远端路径或授权事实；目录通过平台 owner 私有检查，lock 使用独立稳定文件，更新先同步完整临时 ledger，再在同一私有目录内原子替换并同步。每次 OS 暂存创建前先持久预留；只有能证明尚未发布、文件句柄已关闭且本上传暂存名已移除的预约才持久释放。已发布、创建结果未知或清理失败都继续占额，进程析构不代替清理证明。重开只读取并校验累计额度，不扫描或自动删除任何用户文件，也不恢复旧业务同意或未完成传输。配额配置不一致、lock 冲突、ledger 缺失/损坏/截断、更新或同步失败均拒绝打开或继续预约；一次持久写失败会使当前 quota owner sticky 拒绝后续预留和释放，不能退回旧用量继续工作。

每个服务端只有一个拥有式 std 磁盘线程和一个容量为一的工作槽。根初始化、所有目的端句柄、读写、完整摘要、同步、发布和清理均不在 Tokio 执行器或业务授权锁内执行。独立源线程也只持有一个有界工作槽。每个有界磁盘步骤前后检查当前权限/代次、本机同意、取消和原始提交时间起算的操作期限。默认预算 30 秒；应用可缩短，不能延长。无人继续使用的活动目的端在一个操作预算后自动清理，即使同一连接的观看仍在合法续租。

本机根或源同意 owner 析构与显式撤销都永久失效。线程在空闲时最多每 50 ms 检查本地事实；异步源等待也观察会话停止与本机同意，不等待阻塞磁盘调用才向应用报告撤销。已经发出的 OS 调用无法强行收回，其迟到结果继续记录在监控中，停止后不能开启新的磁盘步骤或交付迟到成功。

显式 `Cancel` 清理目的端自己的暂存，永不删除最终目标。清理失败返回 Failure 和实际未清理状态；客户端保存 unclean 记录，不能安全退休。随后同一客户端可提交新的精确 Cancel 请求重试清理，不能重开 UUID。精确最新请求重试返回缓存回执，不重复写入或推进偏移；变造重试、错序、跳号、错误代次或超过清单范围终止会话。

`shutdown` 清理等待预算 250 ms。monitor 只有在线程已经销毁 provider 和真实句柄后才记录 finished；清理系统调用尚阻塞时返回 TimedOut，并永久保留 cleanup_timed_out。实际临时文件清理失败、已发布后的错误和首个操作错误分别保留，不以线程析构代替暂存已移除。

持久配额的替换 metadata 使用唯一固定名 `native-file-write-quota.pending`，以 `create_new` 和 no-follow 打开；只有当前调用成功创建的 pending 才能尝试清理。重开时若 pending 仍存在，保留原文件并拒绝准入，不删除它、不分配新随机 metadata 名字。这样连续重启不会积累更多遗留项，也不会把未知写入结果误当作额度归零。Unix 在替换后同步原父目录句柄；Windows 同步替换前后文件内容，目前没有目录同步或断电恢复验收证据。显式 metadata 恢复与文件导出工具仍需完成。

daemon 在接受产品操作前打开一个持久 `WriteQuota`，由原生和浏览器接收根共同使用。两类会话也共享按读/写方向计数的根名额；撤销并移除注册表项后，实际源、浏览或写入对象仍持有原根 owner，最后一个对象销毁后才能释放根名额。这些共同容量不赋予任何共享业务同意：浏览器证明、原生会话、方向权限和本机根批准仍分别核对。

## SDK 拥有式流程

`NativeFileUpload::attach` / `start` 把实际源读取、逐块确认和提交交给原 actor。调用方取消或析构 owner 会立即撤销组合源同意；原 actor 继续消费当前确切 FileWrite 回执，然后执行文件级 Cancel。已经入队但尚未开始发送的源块/Commit，在真实 transport writer 出队前再次检查源同意；失效时替换为相同 generation/sequence/UUID 的 Cancel 请求，不泄露迟到字节。

monitor 的 confirmed_bytes 来自匹配 Ack，而不是本机读进度。NativeUploadOutcome 只有在所有确切回执及清理事实已消费后才带回 `NativeUploadClient`，可复用同一原客户端执行下一上传。析构或显式 retire 这个 guard 只永久退休 FileWrite：保留 claim、清空队列并丢弃迟到回执，不把它们交给 fallback 或阻塞 TLS/WSS 的观看通道。未消费响应或目的端清理不明时不能用安全退休伪造清理已完成。底层客户端普通析构仍遵循当前原生通道 owner 规则。

远端确切回执已消费和本机源实际关闭是分别报告的事实。源调用仍阻塞时，cancel 可以返回 TimedOut，actor_finished 和 remote_closed 也可以已经成立，但 finished 保持 false，原 actor 继续持有 writer；源实际销毁前不交回可复用 guard。直接使用底层客户端时，替代源请求同样返回 WouldBlock，防止重复取消累积不受限的源线程。源迟到关闭后，monitor 的订阅者也获得最终 finished 更新，cleanup_timed_out 保持原超时事实。

## 当前验证和后续产品范围

2026-10-14 本轮 Windows 开发验证实际通过如下定向测试；日志保存在仓库 `artifacts/`：

| 命令 | 实际结果 | 日志 |
|---|---|---|
| `cargo test -p nestlink-protocol upload::tests --lib --locked` | 2/2 | `native-upload-protocol-windows-20261014.log` |
| `cargo test -p nestlink-platform-files --test transfer uploads --locked` | 18/18 | `native-upload-platform-windows-20261014-fixed.log` |
| `cargo test -p nestlink-sdk --test uploads --locked` | 3/3 | `native-upload-sdk-windows-20261014-fixed.log` |
| `cargo test -p nestlink-remote queued_upload --lib --locked` | 2/2 | `native-upload-queue-windows-20261014.log` |

平台和 SDK 测试实际使用 TLS/QUIC 持钥证明、真实私有源和目的文件、空文件和多块字节，验证独立权限/根同意撤销、完整摘要、精确/变造重试、偏移和范围、4 个活动目的端及 256 个 UUID 上限、配额、既有目标竞态、Windows junction、Windows 写共享限制、闲置期限、阻塞源不能释放客户端用于替代线程、阻塞清理、持续清理失败的最终真实句柄关闭，以及迟到发布事实。Windows 测试验证 OS 拒绝其他写入者；Unix 实际暂存重写后的完整重读和 symlink 分支仍需 Linux 定向执行，不能由 Windows 的绿色结果代替。

阻塞和异常由明确测试适配注入，不在用户磁盘上制造容量故障；私有测试目录由 fixture owner 实际清理。本轮 SDK 成功测试未留下新测试目录，已有历史失败目录不属于本轮清理对象。上传专属 Rust 文件独立 `rustfmt --check` 已通过。

这批先完成原生新上传与 SDK 入口。上传跨连接校验续传/持久 partial 恢复、浏览器文件产品流程、Android SAF，以及 daemon/GUI 的真实目录选择和安全导出至既有目录仍需后续接入和验收。这些定向测试不代替 WSS/跨网、安装包、正式平台签名、异常存储/断电或 A12 全产品验收。
