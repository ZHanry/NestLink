# 原生下载目的端工作线程

`nestlink-remote::files::FileDownloadWorker` 从真实 `FileReadClient` 和仍有效的 `FileDownload` 获得当前 FileRead 权限、连接代次、已证明客户端绑定及源目录 ID/相对路径。`LocalDownloadSelection` 只记录本机明确选择的全新私有区、单个 portable 文件名和大小上限，不在构造时打开磁盘；本机同意 owner 必须保留，析构或撤销永久失效。

目的端的创建、所有文件/目录句柄、分块写入、实际前缀和完整文件重读、同步、原子不覆盖发布及清理都由一个 owned std thread 执行。工作槽容量为一，一块最多 61440 字节；Tokio 只提交工作和等待专属 oneshot。平台 callback 在每个有界磁盘步骤前后检查当前 FileRead 权限/连接代次、本机同意、确切源生命周期、取消和从最初提交起算的 30 秒操作预算；磁盘调用不在业务授权锁内执行。

`FileDownloadSnapshot` 是 sealed 只读视图，不能构造虚假客户端或可变下载副本。它携带当时的 manifest/offset 和不透明 owner/UUID 绑定，并共享原源取消事实。旧块视图不会因为稍后收到 End 而变成已验证 End。源 Cancel 在等待网络回执之前先使缓存视图失效；取消、错误或源对象析构不能授权迟到的目的端工作。

每次 async 等待监视授权停止和本机事实，最长以 50 毫秒轮询本机撤销。等待 future 析构会取消该次工作并保持 pause；迟到回执不能回答另一操作。`pause` 是显式屏障，只有此前的磁盘调用确实返回后才能确认实际 prefix。没有收到该屏障时禁止替代工作或 resume。初始化等待被取消则停止目的端线程。

应用可以缩短单次操作预算，不能为零或超过 30 秒。回执按时产生但迟到消费仍返回原期限超时，不能因 oneshot 已 ready 而延长预算。可暂停错误使用私有授权边界标记识别；provider 必须原样传递 callback 错误，真实磁盘 `PermissionDenied`/`Interrupted` 与 StorageFull/Other 一样终止并清理，不能因同时丢弃等待而改记为可续传。

暂停后的 partial 由仍有效的本机同意保留，不允许继续用原授权写入。TransportLost/NetworkChanged 可以使目的端暂停；撤销、过期、其他终止或本机保存同意撤销会关闭/清理。重新接续必须提供新的真实 FileReadClient/Open 结果及当前权限，部署/security epoch/session/account、两端设备和密钥、resource、policy、capability、权限集/支持能力/本机路径策略及源目录 ID/相对路径保持原值。连接代次不能倒退；同代次只能来自同一客户端实例。新 manifest 的长度和 SHA256 保持原值，起点精确等于实际已确认磁盘前缀，且适配重新读取/验证每个前缀字节。工作线程接纳 successor 后仍保持 pause，只有 async 调用消费其确切成功回执才允许新操作；取消的 resume 不能在迟到后自行释放 pause。

这层不签发新控制面同意、不重建网络连接。真实产品须先完成新的控制面授权和两端证明，再调用目的端 resume。开发测试用同一签名资源的真实 TLS/QUIC 连接和新证明模拟 successor；不把它当作实际跨网、安装产品或 GUI 接续验收。进程重启后的持久 partial 已通过独立事实 journal 接入平台、SDK、Core、daemon/IPC 与桌面；必须在新批准和新两端证明下重新 Open，并验证原对象和 durable prefix，详见 [NATIVE-FILE-RECOVERY.md](../docs/refactor/NATIVE-FILE-RECOVERY.md)。这不会复活旧客户端或同意。

目的端文件级停止不停止同一租约中的观看/输入。`shutdown` 的清理等待预算为 250 毫秒；系统磁盘调用无法强行回收，超时返回 TimedOut，并永久保留 `cleanup_timed_out`。只有观察线程完成后才 join，不在 Tokio 上等待未完成的阻塞磁盘线程。监控分别保留实际确认字节、发布/句柄关闭/暂存移除/目录同步/poisoned、首个操作错误及清理错误。`finished` 在销毁真实 provider 后发布；超时后的实际完成不会抹去曾经超时的事实。初始化失败也由原线程清理已经创建的暂存文件；空的私有目录可能保留，不冒充导出目标已保存。

已发出的磁盘写入或原子发布调用可能在撤销后返回。异步等待会停止返回成功，线程继续记录实际结果；已经发布的完整本地文件不会被清理误删，也不会改称从未写入。正常完成不调用会把成功文件标为 poisoned 的 cancel。Windows 仍不声称目录 fsync/断电持久性已验收。

开发测试覆盖 TLS/QUIC 的实际私有存储、空文件、同客户端和新连接续传、其他 resource/源路径拒绝、旧块视图、源 Cancel 未回执时失效、暂停时的本机/会话撤销、取消等待/取消 resume 后的迟到工作、阻塞初始化/写入/发布/清理、注入磁盘满和独立清理错误。阻塞和磁盘满使用明确测试适配注入，没有在用户磁盘上制造容量故障。

原生 SDK 已接入拥有式源 RPC、文件级取消和确切客户端回收复用，见 [native-sdk-files.md](native-sdk-files.md)；本机目录元数据基础见 [native-directory-storage.md](native-directory-storage.md)。应用级配额/队列、daemon/GUI 文件流程、网络目录浏览与原生上传已有各自接线；原生下载进程重启恢复见上述独立实现。已有目录导出、Android SAF、浏览器存储仍遵守各自能力边界；远端上传未提供可跨进程重新批准的 durable staging token，重启后必须重发。本层开发检查及新增未运行的 fixture 不替代产品完整平台验收。
