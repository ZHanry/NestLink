# Rust 产品状态内核

`nestlink-app-core` 是原生桌面和 Android Rust 层的管理状态所有者。Rust actor 单独拥有一个 SDK 和可选的安装身份，绑定只能观察 `Arc<Snapshot>` 或提交 `Action`。反序列化快照用于 IPC 展示，不构成 actor 输入或权限来源。WASM 构建只导出动作和视图模型；当前浏览器管理 SDK/Leptos 工作流独立运行。

## 真实管理工作流

- `switch_server(ApprovedServer)` 使用人工批准的部署 UUID/issuer；SDK 验证健康信息、随机 nonce 和绑定 exact origin 的签名证明。不能把待连接服务器报告的公钥直接当信任锚。
- `SignIn` 同时提交账号、密码和可选 TOTP/恢复码。服务端对密码和 MFA 失败返回同一个拒绝，内核不编造 MFA challenge。密码不缓存，access/refresh token 保留在 SDK 内部。
- 账号安全、设备、待主机处理的访问请求、账号列表、策略/scopes/中继配额、节点/计量和审计/保留期限通过现有 SDK 接口读取；页的 `None` 表示未加载，已加载空集合表示真实空结果。
- 本机登记、请求/批准/撤销、固定远控密码、受信设备、账号操作和策略/节点/审计配置使用真实 SDK 操作；写成功后重新读取相应实体。CAS revision、主机批准 nonce、逐项权限与部署安全代次仍由服务端和 SDK 校验。
- `ApproveRemote` 读取当前请求并检查 UI 选择时的 nonce/policy revision，然后用 actor 的本机身份签名。`IssueRemotePermit` 是控制端领取初始许可的独立步骤；SDK 验证实际 permit 后读取最新请求/lease。`TrustRemote` 必须针对已经发行许可的资源，由本机 host key 明确签名。
- 普通账号读取管理员页得到 403 时保留有效会话。账号安全重认证得到 401 时额外请求 `/auth/me`，区分错误密码/因子和真正的 access 失效。真正失效、密码变更、截止时间到达会清空账号状态并退休 SDK 凭据。

`approved`、permit 的签发与 `lease_sequence` 是控制面的真实状态，不能作为音视频、输入、服务发布或 Android 共享正在运行的证据。媒体和隧道的运行状态必须由真实 Rust/native lifecycle 提供。

## 接口

需要在 Tokio runtime 内创建 owner：

```rust,ignore
let mut core = AppCore::with_identity(Limits::default(), loaded_identity)?;
let handle = core.handle();
let verified = handle.switch_server(approved)?.wait().await?;
let logged_in = handle.submit(Action::SignIn {
    username, password, factor,
})?.wait().await?;
let views = handle.observe(); // watch::Receiver<Arc<Snapshot>>
let state = handle.snapshot();
let ticket = handle.submit_for_generation(state.generation, Action::Load {
    page: Page::Devices,
})?;
let operation_id = ticket.id();
let result = ticket.wait().await?;
let accepted = handle.cancel(operation_id)?.wait().await?;
let shutdown = core.shutdown(Duration::from_secs(5)).await;
```

仅管理端可以使用 `AppCore::start(Limits)`，涉及本机签名的动作会准确返回 `LocalIdentityRequired`。安装身份由 daemon/平台密钥管理层提供，内核不会因 UI 重建而静默生成新设备。

`Snapshot.installation` 公开 `InstallationView { device_id, public_key_sha256 }`，仅来自 `with_identity` 提供的真实安装身份。切服与清理账号保留这一安装事实；未提供身份时为 `None`，视图不包含私钥。绑定据此显示本机 ID/指纹并限定本机审批入口，不得从设备列表名称推断本机身份。

`Snapshot`、`Action` 和公开操作结果有 typed serde 契约。`Action` 使用 `action`/snake_case 标记、拒绝未知字段，不实现 Debug/Clone；秘密字段只有用于认证本地 IPC 的显式 serde 适配器。发送端和接收端必须限制 IPC frame 并清零含秘密的编码缓冲，不记录动作正文。

IPC 客户端必须使用 `submit_for_generation(expected, action)`、`switch_server_for_generation(expected, config)`、`logout_for_generation(expected)`，以快照中的代次作为 expected。提交比较、Envelope 标记和 actor 派发前检查共同防止另一客户端切换账号的竞态。旧动作不能因一次新的原子读取而附着到新账号。`SubmitError::StaleGeneration` 表示提交前已失效；提交后才失效的 ticket 得到 `Superseded`。

操作 ID 从本 owner 的单调计数器分配，终态历史淘汰后也不复用。跨 daemon 实例使用 IPC runtime UUID 区分 ID 域。调用方的幂等 UUID 必须由本地 IPC owner 去重，不得通过重新执行 Action 来找回不确定写结果。

## 代次、取消与生命周期

换服、注销、登录替换、会话失效和退出推进全局代次，立即清空账号页、principal、旧操作输出及尚未消费的敏感输出。配置切换先消费旧 active SDK 调用的准确结果，再真正 logout/销毁旧 SDK，最后连接新配置；只有一个 SDK job 活动。退休 SDK 仅用于收回已经开始的调用和注销，不能接新的用户动作。旧结果不会恢复当前页面、登录状态或新账号凭据。

每个 app-core 层 SDK 调用开始前检查代次、退出和取消信号。取消发生在“读取当前请求”期间时，之后的审批写入不会发送；写请求已经开始时继续消费真实响应。SDK 内部已经开始的多步证明操作按完整 SDK 调用收回，取消不能声称撤回其远端效果。`Cancelled` 和 `Superseded` 的 `remote_effect` 分别报告 `None`、`Committed`、`Unknown`；收到明确 4xx 拒绝与丢失响应/5xx 区分。取消已派发动作的期间显示 `Cancelling`，终态在真实调用收回后产生。

成功写入后如果刷新页面失败，结果可以为 `Failed` 且 `remote_effect=Committed`。绑定应显示刷新失败并安全重读，不得自动重发写操作。取消的当前代次写入不安装页面结果；用户可以根据效果重读页面。

actor 在发送操作完成或取消确认前先发布对应快照，因此跨线程 IPC 收到完成后读取状态时已经能观察到终态与实体变化。进入清理代次时先发布 SignedOut/Disconnected，再收回旧调用，避免出现 SignedIn 而 principal 已被清空的中间视图。

access 的 UTC 截止时间和最长五分钟的单调时钟 deadline 共同结束本地会话，系统墙钟后退不能延长本地凭据寿命。只有成功的真实 refresh 安装新的单调 deadline；本内核目前通过 `RefreshSession` 显式刷新，不自动保存或续登。

owner 应放在本用户 daemon/Android Rust runtime，不能放在主窗口或 Activity 中。窗口重建、隐藏到托盘只重建 binding。`AppCore::Drop` 触发独立退出信号；handle/watch/ticket 的 clone 和 UI waiter Drop 不延长用户业务，也不能释放正在进行的操作预算。actor 完成准确响应收回、SDK logout 与凭据销毁后才宣布 `Stopped`/finished。`shutdown(timeout)` 超时返回 `Pending`，此时 cleanup 仍受拥有，不能当作退出完成。SDK 每个 HTTP 请求有 15 秒上限，多步动作可能超过一个请求时限。Tokio runtime 终止会释放内存，但不能当作已确认远端撤销。

`logout_confirmed=Some(true)` 仅用于持有会话时真实 logout 成功；`Some(false)` 表示没有确认远端注销，SDK 的本地凭据仍已清除。登录退出与保存缓存是独立设置；目前不提供持久 token 缓存，后续平台安全存储必须明示保存行为。

## 有界预算和一次性秘密

默认普通操作 16、优先控制 4、历史/事件各 64、敏感输出 4；硬上限分别 32、8、256、8。普通操作 semaphore 同时计数 mailbox、内部队列和 active job，丢弃 waiter 不释放其 reservation。控制通道独立，普通负载无法占满注销/换服通道；owner 的退出 watch 不依赖任何队列容量。服务器响应沿用 SDK 256 KiB 限制；审计/节点页最多 100 项，本地输入另有字符串/集合上限。

TOTP seed 和恢复码只通过 `Completion::take_sensitive()` 一次性移出 `SensitiveMaterial`，不进入 snapshot、事件、日志或历史。没有可用 secret slot 时在任何远端调用之前拒绝新的敏感操作。owner 在换服、注销、过期和退出时主动清零尚未消费的 slot，即使其 completion/ticket 仍由 UI 持有。已经被 UI 消费的秘密由 UI/IPC 层负责在代次变化后清空；需要明确的一次性展示和恢复码保存流程。

## 验证与边界

窄集成测试使用真实 NestLink HTTP 服务、Store、签名 trust proof 和 SDK。响应屏障只暂停真实事务完成后的返回，不替换业务响应。覆盖账号/角色、登记、批准/permit/受信/固定密码、策略/配额/节点/计量/审计、TOTP/恢复码重放、密码变更、旧代次的跨客户端提交、迟到登录退休、读期间取消、已提交写入取消、总队列预算、owner Drop、截止时间、一次性输出清除、安装事实保留和跨线程完成前快照发布。短截止 fixture 只缩短真实 auth 响应宣布的 lifetime，用于独立验证本地截止时间。

当前 Android JNI 的 `AndroidManagementSession` 持有 `AppCore` 与 `CoreHandle`，管理入口通过真实 `Action` 和 actor 快照工作；Compose ViewModel 展示这些结果并承担 Android 生命周期和系统授权事实，不再直接调用管理 SDK 建立另一套权限状态机。Keystore 安装身份、MediaProjection/前台服务、本地停止、原生/浏览器主控与被控媒体、输入、文件、文本剪贴板、显示器选择和服务管理均已有平台桥接。对应入口为 `crates/android-bridge/src/management.rs`、`crates/android-bridge/src/management/services.rs` 以及 `apps/android/app/src/main/java/com/zhanry/nestlink/`。Android 10 按用户要求排除，最低 API 30 保持不变。

桌面工作台通过本用户 daemon 的认证 IPC 观察同一内核，独立远控窗口、托盘/退出、媒体/输入/附加通道和服务发布也已接入实际资源 owner。Web 的 Leptos/SDK 工作流仍独立运行，不因此改写为由原生 actor 持有。以上为当前源码职责与接线事实；最新开发验证的精确输入范围见 `docs/refactor/IMPLEMENTATION.md`、`ANDROID-VERIFICATION.md` 和当前检查索引。新增源码在其定向检查完成前不借用旧包回执，真实系统授权、平台视觉/输入法/无障碍、正式签名和跨网由用户最终验收。
