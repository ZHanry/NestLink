# Wayland 门户会话与输入

`nestlink-platform-input::portal` 实现 RemoteDesktop/ScreenCast 的真实 D-Bus 客户端。每次调用 `PortalInput::request` 都创建新会话，请求键盘、指针和显示器，设置 `persist_mode=0`，不用恢复令牌。系统授权是当前 NestLink 业务许可的附加条件；调用方仍须将适配器交给授权会话的 `InputController`。

只观看使用 `PortalView::request`，仅调用 ScreenCast 的 CreateSession、SelectSources、Start，不查询或请求 RemoteDesktop。该类型没有输入接口，也不能转换成 `PortalInput`；升级为控制必须重新取得系统同意。ScreenCast v4 起明确传入 `persist_mode=0`，v3 使用 API 的默认不持久化行为。控制会话只在 RemoteDesktop.SelectDevices 设置持久化选项。

两种流程均要求 ScreenCast v3 及 Embedded 光标模式，SelectSources 明确传入 `cursor_mode=2`。不支持嵌入光标时明确失败，避免默认 Hidden 模式产生没有光标的远程画面。

## 本地调用与系统身份

`PortalOptions` 接收导出的 `wayland:` 父窗口标识和桌面 GUI 的进程 ID。后者只能取自本地进程或认证 IPC 的本地对端，不能由远端指定。logind 的 `GetSessionByPID` 必须返回本用户、活动、未锁定的 Wayland 登录会话。UI 与守护进程不属于同一登录会话时，使用 GUI 的可信进程 ID。

用户与系统总线只允许本地 Unix 连接，使用 EXTERNAL 身份验证，并核对总线 peer UID。门户服务必须属于本用户，logind 服务必须属于 root；授权之后的调用和清理固定到原服务的唯一 D-Bus owner。服务更换不能恢复旧会话。

CreateSession、SelectDevices、SelectSources 和 Start 使用随机 128 位 token，并核对 sender、请求与会话路径。Response 在请求之前订阅；Session.Closed 在选择设备与 Start 之前订阅，避免快速撤销落入观察空隙。只接受实际返回的键盘和指针组合，以及有界的显示器 stream 元数据。

`request` 使用独立线程与 Tokio runtime。`watch::Receiver<bool>` 的 true 或观察者关闭会取消尚未完成的同意流程；false 更新继续等待。future 被取消也会停止专属总线客户端。已经交给适配器的会话通过业务停止、释放适配器或 `PortalControl::invalidate()` 终止。

## 输入、坐标与清理

物理键将 HID usage 独立映射为 Linux evdev keycode；指针按获准显示器选择 node ID，并传入该 stream 原点内的逻辑坐标。多显示器必须提供位置；镜像显示器可以重叠，按 node ID 稳定选择。桌面包围框中的屏间空隙不接受指针操作。

文本通过门户 Unicode keysym 成对提交，支持中文、emoji、换行与 Tab；拒绝其他控制字符、超长文本和本会话仍持有按钮时的文本提交。真实 compositor、应用输入法和本地修饰键交互仍须产品验收，私有 D-Bus 参数测试不能证明文字最终进入目标应用。

系统事实在操作之前检查，空闲状态每 250 ms 重新读取 logind。安全字段变更、锁屏、失活、Session.Closed、服务 owner 改变或观察者结束均使会话进入不可恢复的终态。同步输入通过容量为 1 的 IPC 队列等待，包含排队在内的预算为 150 ms；过期命令不再开始发送。

后端在发送之前登记本会话持有的键、按钮和 Unicode keysym，部分失败仍保留释放记录。未由本会话持有的抬键不发送。释放、Session.Close 和总线关闭共用最早的一轮清理期限，清理失败明确返回。关闭不能重新授权输入。

## 媒体接入边界

`take_pipewire_fd()` 只能移交一次门户返回的 PipeWire FD。`PortalInfo.streams` 中的 `size` 与 `position` 是 compositor 的逻辑布局，不能当作采集图像的像素尺寸。媒体适配器需要保留逻辑坐标与实际像素之间的变换，并在格式、缩放、布局或 PipeWire 权限变化时调用 `PortalControl::invalidate()`。

门户返回 `pipewire-serial` 时保留完整 64 位值，拒绝错误类型、零值或重复 serial；它标识原 PipeWire 对象，防止销毁后复用 node ID。旧门户没有该字段时仍保留 node ID 兼容路径。输入坐标调用继续使用门户返回的 node ID。

后续 `PortalCapture` 已接入 FD，读取协商的原始像素并将采集失败/像素格式尺寸变化反向通知门户终止，详见 [VIDEO-CAPTURE.md](VIDEO-CAPTURE.md)。真实 GNOME/KDE 门户、多屏/DPI/旋转/裁剪与产品 GUI 仍须完成；这些必选能力没有获得完成豁免。

## 已运行的开发验证

Linux workspace 包含 9 项门户测试，在自有临时 Unix socket 上启动真实私有 `dbus-daemon`。服务 fixture 在独立线程处理真实 D-Bus 请求；测试不使用当前桌面的门户，不打开当前屏幕，也不向当前应用输入。覆盖请求 token 与实际 grant、Unicode keysym/扩展键/负原点坐标、空闲锁屏业务停止与释放、系统拒绝/提前关闭/部分授权、服务 owner 替换、RPC 超时、终态输入拒绝、false 更新继续等待、取消后专属总线客户端实际断开，以及镜像布局/重复 node 检查。新增用例覆盖没有 RemoteDesktop 接口的 v3/v4/v6 仅观看服务、光标模式、只观看内部注入拒绝、一次 FD 移交、撤销及 64 位 serial 校验。

只读主机检查不创建门户会话：

```sh
cargo run -p nestlink-platform-input --locked --example portal-probe
```

当前 WSLg 主机返回 `org.freedesktop.login1.NoSessionForPID`，其进程不属于 logind 管理的桌面登录会话。该结果记录为环境阻碍，不作为正式 Wayland 平台验收通过。正式验收需在已安装产品的 GNOME/KDE Wayland 登录会话执行。
