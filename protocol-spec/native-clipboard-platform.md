# 原生文本剪贴板平台适配

`nestlink-platform-clipboard` 提供 Windows、Linux X11 和 Wayland portal 的原生文本接口。平台适配只读取系统事实，不能授予 NestLink 业务权限。它不会在启动、状态观察或系统复制通知时自动读取明文，不会保存、恢复用户的旧内容。支持 UTF-8 文本和空文本；文本包含 NUL、非法编码或超过 65,536 字节时拒绝，不转换为 HTML、图片、文件列表或 OLE 数据。

## 本机批准与业务权限

每个设备绑定合法的业务 `session_id` 和非零 `connection_generation`。本机 GUI 或认证本地 IPC owner 在明确选择本次会话的读取、写入方向后创建 `LocalClipboardApproval`，独立持有不可 Clone 的 `LocalClipboardApprovalControl`。token 不能序列化，也不能通过远程设备 ID 或请求重建。`revoke_read`、`revoke_write`、`revoke_all` 和 control 析构只能撤销，不能重新启用原 token。读取批准不授予写入，写入批准不授予读取。

`ClipboardAuthority::check(binding, direction)` 必须核对共享内核的当前业务许可、精确会话与连接代次，不续租、不等待 OS、不把业务锁持有到平台调用。适配器在 dispatch、系统读取/写入前后和结果交付前再次核验权限。读取中撤销后不会把迟到明文交给调用方。当前业务许可或系统会话丢失会永久停止原适配器；重新获得许可必须创建新的 owner。

`NativeClipboard::direction_guard(direction)` 返回原方向的 `ClipboardDirectionGuard`。SDK 应让待发送文本与其 Read guard 共同存活，在进入队列、取出队列及实际发送前调用 `check_until(original_deadline)`，并继续执行共享通道自己的业务检查。只观察 `monitor.status().active` 不足以授权发送：读取可能已单独撤销，而另一个写入方向仍然批准。guard 的检查不读取剪贴板、不产生业务许可、不延长原操作期限；会核验方向同意、原 binding、当前 lease 及 worker 心跳。已经合法交付或已开始的 OS 副作用无法收回。

## 有界工作线程与清理

设备独占一个标准工作线程，最多一个待处理操作与一个最多 64 KiB 的选区文本。启动结果最多等待 2 秒；启动失败后另用首次停止时确定的 250 ms 清理期限回收原线程，不扩大任何已发起操作的期限。每个公开操作使用固定 250 ms 原始期限，后台每 20 ms 检查系统及授权并服务选区。读写、X11 流量、D-Bus RPC、FD 轮询和事件处理都受原截止时间、消息及事件数量约束；超时不是重试，也不刷新租约。网络封套的 64 KiB 限制还包含 protobuf/身份/状态开销，远程协议层必须采用更小文本预算或显式有界重组，不能直接把完整平台上限塞入一个封包。

`ClipboardMonitor` 分别记录是否 active、首个终态失败和真实 `ClipboardCleanup::{Pending, Complete, Failed}`。心跳逾期会停止交付。后端 `close` 返回仅是私有清理事实；只有后端及捕获资源析构完成、真实 worker 已结束、Shared 中唯一原 `JoinHandle` 的实际 join 返回且清理证明成功，才公开 `Complete`。显式 `close`、monitor 等待和析构都服从首次停止的原始清理期限；超时及清理失败保持终态，迟到实际 join 不会把失败改成成功。关闭只释放本次 owner 的窗口、连接、句柄和自有明文，不读取或恢复旧内容，不清除别人之后复制的数据。

所有平台的 `open` 返回 `io::Result<ClipboardDevice>`，其中 `Ok` 表示交付 owner，调用方必须先 `check()` 才能安装或宣布就绪。启动前失败、或启动失败后清理成功且实际 join 已证明完成时可以返回没有 owner 的 `Err`。已启动但清理仍未知、失败或逾期时返回 inactive failed owner，`check()` 始终返回原启动失败，读写不会触及平台。Core 的现有 factory 消费路径执行该检查，并在拒绝安装后保留未证实清理完成的 owner。

跨平台真实 worker owner 的公开上限是 `CLIPBOARD_WORKER_LIMIT = 32`，正常、阻塞启动及未知析构 owner 共用这 32 个名额。启动前预留，spawn 失败释放；成功启动后仅原线程实际 join 才释放。Device 析构时若原线程未 join，同一 Shared 与真实句柄进入最多 32 项的保留表；没有后台 reaper 或替换线程。后续 open、close、monitor/status 在观察到原句柄 finished 后完成实际 join 并移除表项。名额耗尽准确返回 `WouldBlock`；未知 OS 调用不能通过不断创建新 owner 变成无界线程。

## Windows

`WindowsClipboard::open(binding, approval, authority)` 在专属 worker 创建隐藏 message-only HWND，使用真实 `OpenClipboard`、`CF_UNICODETEXT`、`GlobalSize`/`GlobalLock`、`EmptyClipboard` 和 `SetClipboardData`。读取先校验有界 HGLOBAL 和 NUL 终止，再严格解析 UTF-16；写入使用有界 GMEM_MOVEABLE 内存，成功后才向系统转移所有权。

`WindowsSessionMonitor` 及原 `WindowsSessionSnapshot` 要求原本机登录会话和桌面仍有效，锁定、桌面或会话变化停止适配器。系统剪贴板被其他应用占用时仅在原预算内短暂重试。其他应用的 delayed rendering 可能阻塞已经开始的 `GetClipboardData`；调用方有界返回并拒绝迟到结果，但不能安全中止此 OS 调用或谎称线程已释放。全进程只允许一个仍存活的 Windows 剪贴板 worker，因此阻塞旧线程不能导致不断创建新线程。`EmptyClipboard` 已发生后的撤销不能撤回清空这一副作用；继续发布前仍会重新核验权限。

## Linux X11

`X11Clipboard::open_for_desktop(display, local_gui_pid, binding, approval, authority)` 只接受来自本机 GUI/认证 IPC 的显式 Unix display 和桌面 PID。`LinuxDesktopSession` 核验原 logind 会话，连接校验 Unix peer UID/PID/进程起点，使用 Xauthority，不连接远程 TCP display。第一方有界 X11 transport 来自新 NestLink `platform-input`，没有引用旧平台代码。

适配器只管理 `CLIPBOARD`，不管理 `PRIMARY` 或 `CLIPBOARD_MANAGER`。写入广告 `UTF8_STRING`、`text/plain;charset=utf-8`、`TARGETS` 和真实服务器 `TIMESTAMP`，工作线程继续服务请求。读取支持普通属性和累计不超过 64 KiB 的 ICCCM INCR，严格校验格式、长度、事件数量、前后 owner 与 UTF-8。XFixes owner 变化只更新元数据；用户随后复制会丢弃 NestLink 自有缓存。停止时只销毁自有选区窗口，不覆盖后来 owner。当前实现不保存退出后的选区内容，因此 X11 选区要求 owner 继续存活。

## Wayland 原 RemoteDesktop 会话

普通 `PortalInput::request` 及 `PortalView` 不请求剪贴板，不隐式提升系统权限。明确本机选择后调用 `PortalInput::request_with_clipboard(options, cancel)`：在原连接、原 pinned portal unique owner 和已核验的原 caller-owned RemoteDesktop session 上、Start 前调用 `RequestClipboard`，提前订阅 `SelectionOwnerChanged`/`SelectionTransfer`。只有原成功 Start 返回的布尔 `clipboard_enabled == true` 才形成 `PortalClipboardGrant`；false、遗漏、错误类型或接口不存在都返回实际失败，不猜测许可、不自动降级到 Xwayland、辅助进程或新会话。

`take_clipboard_grant()` 只转移一次。`PortalClipboard::open(grant, binding, approval, authority)` 仍需业务许可与独立方向本机批准。`PortalControl` 实现 `PortalSessionFacts`，共享原 READY、logind、portal owner 和 `Session.Closed` 观察。`SelectionRead` 使用有界 nonblocking FD 并严格解码 UTF-8；`SetSelection` 只广告批准的新文本，收到 `SelectionTransfer` 后才通过 `SelectionWrite` 的 owned FD 写入，实际成功才 `SelectionWriteDone(true)`。系统信号不会自动读取明文。

portal Clipboard 是 RemoteDesktop 原会话的扩展。停止此适配器会请求原 owner 的 Session.Close 并等待原清理结果，因此原 input/capture 同时结束；不能声称只关闭 clipboard 而原 portal 会话继续有效。关闭不执行 `SetSelection(empty)`，以免覆盖用户的新 owner。缺失 Clipboard 接口或未获系统批准属于该能力的实际限制，不能推导为整个 Wayland 不可用。

## 验证证据与剩余验收

证据目录为 `artifacts/core-verification/20261014-native-clipboard/`，保留首次失败与修复后的结果。Linux 私有 D-Bus 测试连接自己的 dbus-daemon，通过真实 RPC、owned FD、中文/emoji、空文本、撤销、期限及原 Session.Close 验证平台合约；不连接用户的桌面 bus。隔离 Xvfb fixture 校验独立 user/mount/net namespace，使用随机 Xauthority、TCP 关闭的自有服务器与选区，自动 kill/reap 并删除临时目录，不使用 WSLg 的用户选区。

`linux-tests-third.log` 当前记录 12 passed、3 个 Xvfb entrypoint ignored；这些 Xvfb entrypoint 已在 `linux-xvfb-second.log` 的独立隔离运行中得到 3 passed、0 ignored。`linux-clippy-second.log` 记录 Linux all-targets Clippy `-D warnings` 通过。Windows 原生 API fixture 在专属子进程创建唯一非交互 window station/desktop，绝不 `SwitchDesktop`，其测试明文只进入该私有 station 的剪贴板；子进程有 10 秒固定预算并 kill/reap。Windows 与原 RemoteDesktop 会话集成的最终窄验证结果将追加到同一目录。

这些合约测试不替代 Windows 10/11 已安装产品、Ubuntu 24.04 X11/GNOME/KDE 的固定 portal 版本、Android/Web SDK/UI、跨端双向文本、远程队列授权、安装签名或 G0–G6/A01–A21 完整验收。特别是 GNOME/KDE 的实际 Clipboard 接口和原 Start 用户批准必须由真实系统验收确认，不能用私有 D-Bus fixture 宣称通过。
