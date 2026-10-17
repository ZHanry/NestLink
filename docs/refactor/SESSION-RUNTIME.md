# 已建立会话的生命周期与输入

`LeaseControl` 在业务收发之外运行会话监护。控制观察者关闭、显式撤销、原网络代次失效、休眠恢复、墙钟倒退和单调期限到期都会终止当前会话；空闲状态每 250 ms 观察时钟。监护使用 Weak 所有权，最后一个句柄释放时清理并取消任务，不保留后台授权。网络和控制事实在每次同步输入操作、队列入队与业务 IO 前后重查，续租不增加通道或恢复终止会话。

SDK 成功的 `NativeConnection` / `ConnectedQuic` 返回 `network`，来自创建 endpoint 时的原本地代次。通过双方 native proof 后，将它放入 `SessionLifecycle.network`，再构造 `AuthorizedConnection::with_lifecycle`。被控接收路径使用 `NativeEndpoint::network_binding()`。端点须保持到会话结束；端点或 OS 监控释放后观察者失效。不能在握手之后捕获新代次来沿用旧连接。Android 仍需从 Kotlin 生命周期提供可信系统事实。

`AuthorizedConnection::into_channels()` 将两个传输半部交给独立收发任务，`sender()` 提供可克隆的入队句柄。业务调用者取消等待不会取消半个线上帧；续租与停止不使用业务队列。接收任务、发送任务失败或 panic 均触发终止；运行对象释放时清空队列并取消任务。`wait_stopped()` 同时等待同步清理报告与两个 IO 任务结束；单独订阅 StopReport 只能知道停止要求和已附加同步资源的清理结果，不能据此宣称外部 allocation 已清理。

每方向队列的临时开发预算：

| 通道 | 最大数量 | 满队列行为 |
| --- | ---: | --- |
| Input | 64 | 背压，可靠按钮不丢弃 |
| VideoFeedback | 8 | 可靠消息；恢复请求可延后入队，不消耗请求序号、不延长恢复期限 |
| Audio | 8 | 丢弃最旧；出队丢弃超过 100 ms 的数据 |
| Video | 1 | 可靠编码帧 FIFO 背压，保留全部参考帧 |
| FileRead / FileWrite | 各 4 | 背压 |
| ClipboardRead / ClipboardWrite | 各 1 | 背压 |

每帧使用协议的 16 KiB 输入、256 字节视频反馈、2 KiB 音频、64 KiB 文件、8 MiB 视频和 256 KiB 剪贴板上限。单方向队列载荷上限 10 MiB + 18 KiB，另计每个通道正在处理的帧与传输内部缓冲；应用调用者自己的载荷不在队列内。TLS/WSS 仍承载一个可靠字节流，文件会造成同向队头阻塞。QUIC 在双方证明后协商独立可靠业务流，并使用有界 Audio 数据报；协议与准确边界见 [native-channels.md](../../protocol-spec/native-channels.md)。View 权限下的视频反馈使用独立可靠流；缺关键帧/参考缺口/熵解码失败触发有界恢复，身份与重放错误保持终态。正式编码队列与真实压测验收继续实施。

`claim_channel` 支持唯一的业务通道消费者；默认接收跳过已分配通道，释放后终止旧会话，不重新分配旧队列。Opus 音频和 VP8 视频使用各自的独立消费者和 codec 线程，视频的本地文件事件 FIFO 满不阻塞已收到的视频/音频、视频恢复反馈和独立恢复监护。线上 TCP/WSS 队头阻塞仍然存在。授权、PCM 与缺口处理见 [NATIVE-AUDIO.md](NATIVE-AUDIO.md)。

`InputCommand` 是原生/WASM 共用的有界 protobuf 输入封装，包含 input/layout/connection epoch、单调 sequence 和键盘/带坐标按钮/文本 oneof。未知必要动作、未来 schema、零/溢出代次和超预算封装拒绝。`InputController::apply_frame()` 解析授权 Input 帧，检查当前布局范围与代次。最后一条完全相同的事件重试不再次注入（包括中文文本提交）；变更内容复用 sequence 或旧代次拒绝。局部布局/控制权交接先释放按钮再增加 input/layout epoch；新连接要求新授权。

每会话最多一个 InputController。平台 `InputDevice` 只执行有界同步系统注入；授权检查、注入与停止清理通过同一会话锁串行化，终止后不能注入。按下之前记录远端拥有的按钮，确保 OS 部分失败时仍有释放记录；停止逐个释放所有已记录按键/按钮，继续处理其余释放，记录失败并在最终释放资源时重试。适配器 panic 转为清理失败，不能报告成功。这个实现提供真实平台输入接入边界；开发测试的记录适配器不代表 Windows SendInput、X11/portal 或 Android 无障碍已接入。

开发用例覆盖真实 TCP/TLS→双方证明→原网络绑定→OS 监控关闭后空闲双方传输停止；还覆盖部分文件帧背压下反向输入与续租、主动撤销、过期视频、空闲到期、观察者关闭、中文提交幂等、布局更新释放以及 OS 注入/释放失败。输入 UTF-8 与负坐标 wire vectors 由独立 Python varint/zigzag 编码生成。正式产品的物理休眠、多屏、全端输入、72 小时负载和 allocation 撤销仍待验收。

后续已加入真实 Windows/X11 输入适配器和空闲平台事实检查，见 [PLATFORM-INPUT.md](PLATFORM-INPUT.md)。事实检查失败或 panic 终止为 `PlatformChanged`；检查在输入状态锁内部捕获异常，避免锁中毒阻止释放。清理初始化整轮预算，通用按钮释放后继续清理平台自身的 Unicode/原生持有状态。独立 Xvfb 的实际系统状态验证补充了记录适配器测试；未运行的平台/产品行为仍不能据此认定通过。

Wayland 门户使用独立线程处理异步系统 IPC，同步 InputDevice 在有限期限内等待，避免在调用方 runtime 中 block_on。OS 撤销先使 worker 终止，InputController 的空闲监护再使业务会话以 PlatformChanged 停止。持有输入由原门户 owner 清理，业务授权不会迁移给替换服务。PipeWire FD 与逻辑布局已提供给后续媒体适配，媒体格式/缩放/权限变化需要反向触发终止；实际媒体采集与变化观察尚未接入，见 [WAYLAND-PORTAL.md](WAYLAND-PORTAL.md)。

后续原始画面采集增量已加入 View/连接代次约束、布局坐标变换、过期帧丢弃与停止清理，并通过门户 FD 接入真实 PipeWire 原始图像读取。独立合成视频源、撤销与服务退出开发测试通过；像素格式/尺寸改变反向终止旧门户。真实 compositor、所有平台采集、VP8/Opus、线上媒体与产品界面仍未完成，见 [VIDEO-CAPTURE.md](VIDEO-CAPTURE.md)。
