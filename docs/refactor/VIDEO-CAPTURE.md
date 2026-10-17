# 原始画面采集与授权边界

`nestlink-remote::video` 提供 `VideoController`：每个会话至多附加一个采集器，附加与取帧都检查 View 权限及原连接代次。原始像素固定为 Rust 拥有的紧密 BGRA，尺寸与实际字节数核对，每帧上限 64 MiB。它是本地编码输入，不是线上视频帧；线上编码帧仍遵守 8 MiB 协议预算。

`CapturedVideo` 带有原布局/连接代次和获准显示器的逻辑布局。`logical_point` 将图像像素映射为输入坐标，支持负原点和逻辑/像素尺寸不相等。重复或未知 source、非法像素尺寸、未来时间和已有 source 的像素尺寸变化都会使会话终止；超过 250 ms 的帧丢弃。平台检查与取帧的 panic 在状态锁内部捕获，保留停止清理能力。

当前 `captured_at` 记录本地开始复制时刻，250 ms 检查约束采集后的本地队列。源端采集时间、PipeWire 时钟映射及编码/音画同步尚未接入，不能把此检查当作端到端画面年龄证明。

## Wayland / PipeWire

`nestlink-platform-capture::PortalCapture::open(&mut PortalInput)` 和只观看入口 `open_view(&mut PortalView)` 使用当前门户实际交付的 FD 和 stream 集合，不连接默认 PipeWire 服务，不选择其他设备。FD 必须是本地 Unix stream socket，其 peer 属于当前 OS 用户。门户 FD 只移交一次，门户已经终止时不能移交。

专用采集线程通过系统 `libpipewire-0.3` 创建 stream。窄 C 桥使用正式 PipeWire/SPA 头文件访问系统 ABI；Rust 拥有图像、队列、容量、失效事实和业务生命周期。没有第二套业务授权，也没有在 Tokio I/O 线程编码或复制画面。

`pipewire-serial` 存在时用完整 64 位十进制 `target.object` 和 `PW_ID_ANY` 连接，核对获准 node 的原 serial，失败不回退到 node ID。只证明 node 存在并不足以证明收到它的画面：适配器另外观察真实 Link，要求唯一连接的 input 是本 consumer、output 是对应获准 source。每帧在发布前通过 core sync 同步服务端图状态；错接、交叉接线、增加重复边、移除来源或连接都会终止并清空旧帧。legacy node ID 路径也执行连接两端校验。门户 remote 必须允许观察所用 Link；实际 GNOME/KDE 的权限可见性及每帧同步开销尚待验收，无法核验时不发布图像。

当前实现协商 MemPtr/MemFd 的 RGB、BGR、RGBx、BGRx、RGBA、BGRA 原始图像，检查映射类型、可读属性、偏移、长度、stride 和完整行预算；只在 buffer 未重新入队期间复制，不保留系统内存指针。损坏帧与没有有效数据的更新丢弃；`SPA_CHUNK_FLAG_EMPTY` / `SPA_META_HEADER_FLAG_GAP` 表示中性画面，生成受相同预算约束的不透明黑帧替换旧画面，不读取缺失的 payload。最多 64 个获准 stream，每源保留一帧，全队列与原始显示格式总量分别限制为 128 MiB；PipeWire 另外协商每源 2–4 个系统 buffer，不能把 Rust 队列预算说成整个进程内存上限。

门户关闭、授权观察者失效、采集异常、node 断开或像素格式/尺寸变化都会终止旧采集，并调用原门户的 `invalidate()`，因此原输入授权也结束。没有自动连接替换 node 或复用旧系统同意。C 线程每 50 ms 提供 heartbeat 并观察本地门户事实；超过 250 ms 没有工作线程心跳就终止，调用方轮询不能续期，迟到心跳也不能恢复。所有显示器须在 5 秒启动预算内提供首帧。停止先禁止入队并清空队列，再通过 eventfd 唤醒 worker；等待清理最多 150 ms，超时与 worker 错误明确返回。

回调使用统一的结果语义：0 继续，正数为正常取消，负数为真实错误。心跳、格式、原始像素和中性帧均经同一 C 交付入口停止；正常门户撤销不再因先到的是像素回调而误报 `ESTALE`。Rust 保留先观察到的坏帧或超时，后续 eventfd 正常取消不能将其覆盖成成功；原生来源删除的 `ESTALE` 也继续报告失败。确定性边界测试覆盖全部四种回调、复制后撤销、轮询先发现超时及错误后的取消，另以 ASan/UBSan 验证实际 C 桥。

CPU 图像支持正/负 stride 和行 padding；负 stride 的 offset 必须明确指向首显示行，反向跨度必须完整落在映射内。VideoCrop 先限定有效像素，再撤销 SPA VideoTransform 所述已作用于 buffer 的方向变换，支持全部 8 种方向，直接写入最终 BGRA。裁剪位置、大小及方向在首帧固定，后续改变终止旧会话；原 buffer 的内存预算不因裁剪缩小而放宽。EMPTY/GAP 按最终尺寸生成黑帧。重复、截断或非法 metadata 明确拒绝。

DMA-BUF、非原始格式和非单位像素宽高比仍需完整适配；当前会终止这些输入。Linux 系统依赖为 PipeWire >= 1.0.5；当前 Ubuntu 24.04 开发环境使用 `1.0.5-1ubuntu3.3`。最终软件包的依赖固定、SBOM 与完整安装验收仍待完成。

UI/SDK 接入顺序为：当前业务许可 → 新门户同意 → 从同一 PortalInput 取 FD 创建 PortalCapture → 使用原 lease、VideoEpoch 和获准布局附加 VideoController → 将 PortalInput 附加 InputController。业务停止会释放这两个资源。调用方不能把 portal 逻辑 size 当成 PipeWire 像素 size。

## Windows / GDI

`WindowsCapture::enumerate()` 只读取当前本地显示器事实，返回带原始快照的不可伪造选择句柄。调用方取得 View 权限与本地显示器选择后，使用 `open(selected_sources)` 启动采集，并附加到原 `VideoController`。重复选择、混用不同快照、空选择或超过总尺寸预算会失败。

专用线程使用所选显示设备的 DC、私有 top-down 32-bit DIB 和 BitBlt，复制后将未定义的 alpha 统一为 255。输入坐标保持 Windows 物理虚拟桌面坐标，可为负数。私有 DC/bitmap 留在创建线程，退出先恢复选中对象再销毁。每源一帧、队列 128 MiB、单帧 64 MiB；DIB 与复制过程另外占用内存，该预算不代表进程总内存。

显示器采集叠加当前可见的系统光标。工作线程复制光标句柄，验证尺寸与 hotspot，把其屏幕物理坐标转换到目标显示器局部坐标后绘制；部分跨屏的光标按目标 DIB 边界剪裁，隐藏或受系统抑制的光标不绘制。系统借出的共享句柄不销毁，私有图标和 `GetIconInfo` 返回的 bitmap 由本线程释放。测试使用自制光标，覆盖负原点、hotspot、透明与跨边界像素，不读取用户真实光标。

线程在复制前后核对交互桌面、活动且解锁的 WTS 会话及完整显示器/DPI/缩放快照；会话登录时间、连接时间也须匹配。自己的隐藏窗口接收显示与 WTS 通知，WinEventHook 观察桌面切换。窗口不显示、不抢焦点。事实改变使队列与会话终止，不能解锁后自动恢复。外部取帧检查 250 ms 心跳；停止先禁止入队、清空队列并唤醒线程，再按同一 150 ms 截止时间等待，超时明确失败。GDI 驱动调用本身不可由 Rust 安全强制中断，阻塞时保留线程资源至系统调用返回，不提前释放仍被原生代码使用的内存。

后续回归确定性复现首次 reset 超时后，worker 晚结束把结果改为成功的问题；现在首次超时写入终态结果，finish 不覆盖已有失败。原失败与修复日志保留。所有正常/错误退出在原 worker 显式关闭共享会话观察器；采集错误优先保留，正常停止时 unregister/unhook/DestroyWindow 错误也会进入清理结果，不再只依赖忽略错误的 Drop。

## X11 / GetImage

`X11CaptureSource::open_for_desktop` 使用本地 GUI 的可信 PID、Unix X11 连接与 logind 登录会话。RandR monitor atom 标识源；`X11Capture::open(source, selected)` 只接受该次枚举中的非空、唯一显示器选择，并交给独立工作线程。生产路径始终检查 logind，没有免会话验证的入口。

采集复用输入适配器的有界 X11 transport，GetImage 的 ZPixmap 回复每条不超过 256 KiB，分条带读取所选 root 区域。8/16/24/32 bpp TrueColor 按真实 RGB masks、端序和 scanline padding 转换为 BGRA，包括 16-bit 565 与 30-bit 颜色。整轮所有显示器、事实检查和像素复制共用 150 ms 截止时间。单帧最多 64 MiB；每源一帧的发布队列和待发布轮次分别最多 128 MiB，并非整个进程总内存。

完整 root/monitor/CRTC/旋转/transform 快照在采集前后核对，屏保、RandR 事件、连接故障或超时使源终止。`X11CaptureControl` 是只读失效事实句柄，采集前后、入队与出队直接检查原 logind 观察者，已经接收的锁屏通知不必等下一轮读取结束。250 ms 心跳只由真实检查与成功采集更新；迟到结果、解锁或反复轮询不能恢复旧会话。停止先禁止交付、清队列，再由原工作线程关闭连接，重复清理使用最早的 150 ms 截止时间。

XFixes GetCursorImage 返回预乘 ARGB 数值；实现核对当前 screen、尺寸、hotspot 与 payload，按屏幕坐标裁剪并合成到 BGRA，不重复乘 alpha。光标边长最多 256，光标读取与合成包含在整帧期限内。**XFixes 没有返回其他客户端 HideCursor 引用的可见性字段**：自有 Xvfb 已验证隐藏前后图像、位置和 serial 全部相同。因此当前 X11 路径仍未完成隐藏指针匹配；不能把普通光标合成成功当作这项能力完成。真实多座席、动画光标、HiDPI 与 compositor 行为也需继续适配和验收。

## 开发验证与未完成项

Linux 默认测试在 0700 临时目录启动自有 PipeWire daemon，只加载协议、节点、link、访问和合成 videotestsrc；不打开屏幕、摄像头、麦克风或当前用户服务。外部 fixture 工具有时间/输出预算，退出只回收自有子进程。真实读取了合成视频像素，验证撤销、仅删除 source、仅删除 link 和 daemon 退出后终态、consumer node 删除及队列清空。另验证带行 padding 的通道转换和截断 buffer 拒绝。C 桥缓冲区测试使用 ASan/UBSan，覆盖六种像素格式的 EMPTY/GAP、零 stride/缺失 payload、损坏及非法非空 payload；再把 C 输出送入实际 Rust 回调确认旧像素替换为黑色。

Windows/Ubuntu 的共享会话测试验证旧连接绑定拒绝、逻辑缩放与负原点、过期帧丢弃、撤销禁止出队、空闲采集事实改变、像素尺寸变化与 panic 后清理。测试记录适配器不作为实际平台画面能力。

Windows 的自有隐藏窗口测试验证真实 GDI 红绿像素、alpha、采集停止及显示/DPI/锁定/断开通知；自有窗口先向私有源 DC 绘图，再经过相同的 BitBlt→DIB→BGRA 路径，不读取用户桌面。默认测试验证队列替换、失效心跳、清理超时、停止后禁止入队及自制光标的透明合成。实际显示器 DC、多显卡、HDR、高帧率、混合 DPI、锁屏及 RDP 切换仍需固定产物验收。

隔离 Xvfb 另已真实验证自有红色窗口→XTEST 按键→目标重绘绿色→GetImage 读回绿色；Render 自建 2×2 ARGB 光标验证 hotspot、不透明/半透明/透明像素，以及屏保终态和本会话 Unicode 映射不会误停采集。协议单测与工作线程测试覆盖格式/预算/超时/公平性及并发失效。这些证据不能替代真实桌面输入法、动态多屏与混合 DPI 验收。

完整生产 API 联合开发测试使用独立 user/mount/net namespace 内的私有 system/session D-Bus 和合成 PipeWire source，经过 `PortalInput::request` / `PortalView::request`、真实 FD 移交、`PortalCapture` 和同一业务 lease 的视频/输入控制器。锁屏、门户撤销及来源删除均验证空闲会话停止、键鼠释放、Session.Close 一次、consumer node 消失和旧会话不可恢复；来源删除保留原 worker 错误，报告清理失败而不伪称成功。只观看 fixture 不注册 RemoteDesktop 接口，仍取得真实合成像素。

复现：`python3 scripts/refactor-portal-capture.py`；限制非特权 namespace 的 CI 可使用 `--namespace-launcher sudo`，编译仍由原用户执行。启动器在挂载私有 `/run/dbus` 前核对全部 namespace 已变化，不替换宿主总线；测试只管理其自有子进程，有时间与输出预算。原生 VP8/Opus 和授权可靠视频链已接入，见 [NATIVE-MEDIA.md](NATIVE-MEDIA.md)。正式 GNOME/KDE 门户和 PipeWire 权限行为、动态多屏/DPI、旋转/裁剪/DMA-BUF、隐藏指针、Android 采集、系统音频与产品 UI 继续实施。当前开发证据不表示 A01–A21 或完整正式产品验收已经通过。
