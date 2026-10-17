# 系统输入适配与开发验证

`nestlink-platform-input` 独立实现 Windows SendInput、显式本地 X11/XTEST 与 Wayland RemoteDesktop/ScreenCast 门户客户端。它通过 `InputController` 接入当前许可、输入/布局/连接代次、重放检查与停止清理，不自行签发权限。调用者必须把 OS 后端附加到授权会话；原生 SDK 和产品界面的端到端接入继续实施。

Windows 从 WinSta0/Default 的实际交互用户桌面读取键盘布局、物理虚拟桌面边界、显示器与 DPI。物理键使用 HID 对应扫描码/扩展位，指针使用物理坐标，文本使用 UTF-16 Unicode 按下/释放包。文本提交要求远端按钮和本地修饰键已释放，有 16 KiB/100 ms 预算；系统完整性或安全桌面拒绝输入时返回失败。未由适配器持有的抬键不发给 OS。布局、DPI 或锁屏事实变化会终止当前会话，不绕过安全桌面；无法释放时明确报告清理失败。

Windows 输入已接入共享 `nestlink-platform-session` 观察器的 transferable monitor。hidden HWND/WinEvent hook 留在独立只读工作线程，先订阅再固定 WTS session ID、登录时间、连接时间；快速锁定/解锁、断开、桌面/布局通知、通知窗口关闭及 WM_QUIT 为 sticky 终态。500 ms heartbeat 失联不能由晚查询恢复。调用方保留原键盘/显示器/DPI 快照并在每次操作核对。抬键也必须仍为原活动、解锁的登录与连接，不能把同名 Default 桌面当作重登录后的释放目标。

第一次 begin_reset 固定整轮 150 ms 截止时间，后续调用不能续期；停止后不恢复注入。按钮、Unicode pending 与监护资源清理保存首次失败或超时，重试不能改报成功。系统同步查询/SendInput 本身仍不能由 Rust 安全强制中断；真实目标窗口、IME、锁屏/RDP/热插拔及完整业务接入须继续验收。

X11 仅接收显式 `:display.screen`，使用本地 Unix socket 和正常 Xauthority。不会自动把 XWayland 当作 Wayland 后端。HID 位置通过真实 XKB key names 解析，输入由 XTEST 执行并检查回复。绑定显示服务的 PID、UID/GID 与进程启动时间；失败后的重连仅用于释放，并要求仍为同一服务。每轮请求 150 ms、单条回复 256 KiB、单轮读写各 512 KiB；超时或异常长度使连接终止。键盘映射/组、显示器或屏幕保护状态变化使会话终止；旧 keycode 仍可用于释放本会话按下的按钮。

生产 X11 输入还绑定当前 GUI PID（或已认证本地 GUI IPC 对端 PID）对应的 logind 会话。固定系统总线路径与 root 服务身份，锁定原 logind 唯一 owner，验证会话用户、Type=x11、Class=user/user-early、Display、Active 与 LockedHint；远端调用者不能指定本机 PID。独立 worker 每 250 ms 检查，即使没有远控输入，锁屏、会话失活或 owner 替换也会终止。输入前 logind 与 X11 检查、随后注入共用 150 ms 截止时间。隔离 Xvfb 绕过真实 logind 的构造器只存在于测试编译。

X11 文本使用会话内稳定的空闲 keycode 映射，已存在的字符复用原映射；中文与 emoji 使用 Unicode keysym。发送前要求全部按键/按钮已释放、无修饰/锁定状态、基础键盘组及固定有效目标焦点。不会立即恢复尚可能被目标异步读取的映射；停止时只恢复仍匹配自身记录的行，外部改写会保留并明确报告清理失败。全图比较只消除本模块的精确映射差异，不放过其他键盘布局变化。空闲 keycode 容量有限，发送前预算不足即失败；这一实现不等于已经满足任意长中文文本与所有 IME。

系统事实在输入前和空闲监护中检查。平台检查异常在输入状态锁内捕获，防止锁中毒阻止释放。清理先初始化整轮预算，逐个释放按钮，然后释放平台临时状态；失败继续尝试其余项并保留失败回执。最终资源释放会再次尝试清理，不恢复业务会话。

## 已运行的独立 X11 验证

```sh
python3 scripts/refactor-x11-input.py
```

脚本先按普通用户编译，创建独立用户、挂载与网络命名空间，再启动自有 Xvfb。它使用随机临时 Xauthority、关闭 TCP、由服务选择显示编号，测试再次核对服务 PID、父进程及实际进程名。不会连接用户的 DISPLAY；WSLg 的只读 socket 挂载也不作修改。退出只终止并回收自己创建的子进程。限制非特权命名空间的 CI 主机可使用 `--namespace-launcher sudo`，仅命名空间与测试运行使用 `sudo -n`。

实际测试覆盖普通键与右侧 Ctrl 的系统按下状态、指针坐标/按钮、授权撤销后的系统释放、没有业务操作时的键盘映射变化、未拥有的抬键不影响本地来源、Drop 释放。停止自有显示服务后，监护在预算内终止并如实报告释放失败；恢复服务后，只向相同服务重连释放，终止会话仍拒绝后续输入。

Windows 默认测试验证负虚拟原点、扩展键和 UTF-16 编码；另有只读实际交互桌面检查，需单独运行：

```powershell
cargo test -p nestlink-platform-input --locked --lib -- --ignored --exact windows::tests::actual_interactive_desktop_snapshot_is_bounded_without_injecting_input
```

这项只读取系统事实，不证明 SendInput 到真实目标应用的结果。另已运行只读输入 monitor/空 held set reset，及 session monitor 自有 hidden HWND 的 WM_CLOSE、快速 lock/unlock 通知、WM_QUIT 测试：原监护终止且窗口释放，没有触发实际 OS 锁屏或输入。真实系统效果不能由人工投递给自有窗口的通知替代。

## 尚未完成的必选项

Wayland 门户客户端已完成新系统同意、实际设备/显示器授权检查、物理键/Unicode keysym/逻辑绝对指针、logind 与服务撤销监护，以及终态清理。6 项真实私有 D-Bus 测试通过。后续已接入 PipeWire 原始像素读取与采集失效→门户终止；真实 compositor 的格式/DPI/旋转变化、产品 GUI 与 GNOME/KDE 输入法仍须完成。详见 [WAYLAND-PORTAL.md](WAYLAND-PORTAL.md) 和 [VIDEO-CAPTURE.md](VIDEO-CAPTURE.md)。

X11 `text_commit` 已启用上述有界稳定映射能力；完整中文长文本、真实 IBus/Fcitx/目标应用交互，以及 GNOME/KDE 锁屏变化仍须实际产品验证和补全。Android 无障碍继续实施。文本输入不会借用剪贴板权限，这些待办仍为必选交付。

Windows 自有目标窗口实际输入、中文/emoji/IME、多屏/DPI 切换、安全锁、权限变化，以及 GNOME/KDE 的安装产物验证仍须完成。Xvfb、编译和开发测试均不作为正式 A01–A21 通过证据。
