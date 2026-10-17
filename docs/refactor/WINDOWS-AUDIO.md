# Windows 系统音频适配

`nestlink-platform-audio` 已加入独立实现的 WASAPI shared-mode loopback 采集和播放。调用者使用本机枚举产生的不透明 `WindowsAudioEndpoint` 选择**播放**设备；不能由远端名称制造选择，也不会切到麦克风或跟随 OS 默认设备。产品需要在同一批准 lease 的 `AudioSender/AudioReceiver` 下接入这些设备，平台库本身不签发业务权限。

## 格式、队列与原生所有权

独立 MTA 工作线程持有所有 COM 接口。初始化请求交错 i16、48 kHz、单/双声道，并启用系统 PCM 格式转换及采样率转换；只按实际 `IAudioClient::Initialize` 的成功结果接受格式。失败保留 HRESULT，不声称其他设备格式也已验证。第一方暂未实现独立软件重采样器、设备漂移或真实音画同步。

枚举与初始化不启动音频。第一次经 `AudioCaptureController` 检查的 poll 才启动 loopback；播放收到已授权的 PCM 入队后启动。采集按 WASAPI device position 组装 960-frame chunk；缺口丢弃未完成片段并对齐下一个 chunk，回退/溢出/坏时间戳终止。复制以实际 native buffer 容量检查，silence 显式置零，时间戳错误与未知 flags 拒绝。采集队列最多五个 chunk，出队丢弃超过 100 ms 的旧 PCM。

播放的软件队列最多两个 chunk，另有一个正在提交的 chunk；要求 WASAPI 返回的 stream buffer 最多 1920 frames。因此第一方待播 PCM 预算最多 60 ms + 原生 stream buffer 40 ms。队列满时丢旧，写入按实际 padding/可用 frames 分段。这个预算不等于驱动、硬件与远端链路的真实可听延迟。

## 失效与清理

枚举绑定当前活动且未锁定的 Windows 用户会话。音频 worker 复用从第一方画面采集提取的只读 `nestlink-platform-session` 观察器：先订阅、再比较会话/桌面，WTS lock/logoff/disconnect 与 desktop switch 保持 sticky，快速恢复不会让旧会话继续。画面采集同一观察器另订阅 display/DPI/setting 失效。消息泵有固定预算，消息洪流不能用持续 heartbeat 隐藏未处理的会话通知。

原选 endpoint 的移除、非 active state 或属性变化由 `IMMNotificationClient` latch 主动终止；其他 endpoint 和系统 default 改变不自动切换。每轮同时检查原设备与 WASAPI client。250 ms heartbeat 失联终止，晚 heartbeat 不复活旧设备。reset 立即禁止 PCM 出入队，清空待处理数据，由原 worker Stop/Reset/释放接口与观察器；整个等待使用首次 150 ms 截止时间。超时与首次原生清理错误在重试后仍保留，进入原会话 StopReport，不以稍后线程退出改报成功。

FFI 使用官方 SDK 的 C COM 宏。小 C++ 文件只从官方类型 metadata 取得 GUID，不包含另一套音频或授权实现。callback 不持有 Rust 指针；notification unregister 失败时保留独立的少量 endpoint/latch 与 enumerator，避免不能证明回调停止时释放其内存，并报告错误。工作线程卡住时由其继续拥有资源，调用者不会跨线程强制释放 COM。后续 Windows 输入已接入共享观察器的独立只读 monitor，见 [PLATFORM-INPUT.md](PLATFORM-INPUT.md)。观察器自身的 WM_CLOSE/DESTROY/QUIT 也使旧资源终止；通知窗口不能无声消失后继续声称会话健康。

## 开发检查与验收入口

默认测试验证 PCM 分段、缺口/大 clock jump、原生复制的 silence/坏 flags/长度预算、固定 endpoint 的通知 latch、队列年龄、终态 heartbeat、清理错误优先级及晚退出不覆盖超时。生产 worker 使用阻塞 Start 的本地替身，先确定性复现停止后仍发起一次取样的竞态，再验证 Start 返回后的停止/系统事实检查阻止全部后续取样；原失败日志单独保留。这不证明真实驱动卡死恢复。已在本机两个 active render endpoints 实际初始化单/双声道 capture/playback 并 reset；没有调用 Start、读取系统声音或向扬声器写入。自有隐藏窗口采集回归在观察器提取后重新运行。

只读设备探测与初始化可运行：

```powershell
cargo run --locked -p nestlink-platform-audio --example windows-audio-probe -- inventory
cargo run --locked -p nestlink-platform-audio --example windows-audio-probe -- initialize --device '本地 inventory 的完整 ID'
cargo test --locked -p nestlink-platform-audio --lib windows::tests::actual_selected_endpoints_initialize_without_starting_audio -- --ignored --exact --nocapture
```

操作者确认要读取选定设备的系统 playback mix 并播放两秒合成 440/880 Hz 信号时，可运行下面的本地检测。它不写 raw 音频文件，仅记录样本时钟、幅度与停止后拒绝结果。运行前关闭其他声音源；输出声明 `product_acceptance=false`，不能替代完整账号/许可、Opus/网络、多设备、锁屏、驱动热插拔或听感验收。

```powershell
cargo run --locked -p nestlink-platform-audio --example windows-audio-probe -- roundtrip --device '本地完整 ID' --allow-system-audio
```

本批未运行发声/系统声音读取检测。Windows 10/11 的实际音频、44.1 kHz/多声道 endpoint 转换、RDP/锁屏/热插拔、长时漂移、音画同步、Linux/Android/WebRTC、产品 UI 与正式 A01–A21 仍待实施和固定产物验收。没有把 COM 初始化或合成内存测试记为实际播放完成。当前 MSVC 安装缺少 x64 ASan runtime，这个 Windows C 桥尚未完成 sanitizer 检查；既有 Opus/PipeWire bridge sanitizer 证据不覆盖 WASAPI。
