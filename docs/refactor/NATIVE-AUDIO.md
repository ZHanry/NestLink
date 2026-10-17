# 原生 Opus 会话与本地 PCM 边界

本增量把独立 Opus 编解码接入已经通过双端持钥证明的原生会话。`AudioSender` 消费当前会话拥有的采集适配器，`AudioReceiver` 使用独立音频消费者和线程解析、解码并交付播放适配器。Windows WASAPI 与 Linux PipeWire 本地设备后端已实现，见 [WINDOWS-AUDIO.md](WINDOWS-AUDIO.md) 和 [LINUX-AUDIO.md](LINUX-AUDIO.md)；真实硬件与产品音频链路、扬声器验收及 Android 音频继续实施。开发合成音频与软件图不能代表完整平台能力已验收。

## 授权与生命周期

`nestlink_remote::audio` 定义固定 48 kHz、每通道 960 个交错 i16 样本的 20 ms PCM chunk。`AudioBinding` 固定同一 lease 的实际 connection generation、批准 source 和单/双声道。每会话每方向至多一个采集/播放控制器；附加前检查 Audio 权限和实际代次，操作时在原会话锁内再次检查。错误 source、尺寸、声道、非整帧/回退 sample clock 或未来采集时间终止旧会话。

系统适配器只实现本地事实检查、非阻塞取样/入队和有界 reset，不签发业务授权。编码和解码在这些锁之外的专用线程执行。工作线程重新检查授权后才能发送；播放入队与停止 reset 通过同一授权锁串行化。空闲设备事实变化、撤销、退出、许可到期或原网络失效清理两个方向的待处理 PCM。panic 在设备状态锁内捕获，仍可清理；reset 超时/失败进入原 `StopReport`，不伪报成功。codec 线程保留现有 250 ms join 预算与可见的 detach 状态。

`AudioCaptureController` 丢弃超过 100 ms 的原始 chunk，同时保留其已观察 sample clock，旧帧不能随后回放。格式固定；Windows 后端请求并实际初始化系统采样率转换，Linux 已验证实际 44.1kHz 六声道软件图至 48kHz 双声道 PCM 的系统转换；第一方独立重采样与设备漂移校正尚未实现。系统播放适配器的接口要求本地待播队列最多 100 ms、满时丢弃旧 PCM、停止清空；Windows/Linux 队列及原生 buffer 已按此约束，仍须在真实硬件音频与固定产物上验证。

## 独立消费与缺口策略

`ChannelRuntime::claim_channel(Channel::Audio)` 将当前 incoming Audio 永久分配给唯一 `ChannelReceiver`。默认 `receive()` 跳过已分配通道；重复分配、Control 或无权限通道失败。释放消费者终止整个旧会话，不把旧队列移交给新消费者。所有通道仍共用原控制观察者与连接；不会新建第二套授权。

`AudioReceiver::attach(&mut runtime, device, stream)` 在把 runtime 交给 `VideoReceiver` 或其他默认消费者前分配音频。视频的本地文件事件 FIFO 满时，已经收到的音频仍能由其独立线程消费。Audio 的 incoming/outgoing 队列各最多 8 包，满时丢最旧，出队丢弃超过 100 ms 的包。TCP/WSS 单一字节流或入站可靠队列背压仍可能阻止后面的音频到达；这里不宣称已实现 QUIC 独立流、无队头阻塞或端到端低延迟。

每包验证完整 protobuf、source、实际 generation、协商声道及 48 kHz sample clock。首个收到的 Opus 包允许之前已有队列丢包；其后 sequence 和 PTS 严格递增，sequence 增量不能超过经过的 20 ms 时间片数。采集跳帧可以使 PTS 增量大于 sequence 增量。sample clock 按 960 对齐，不使用墙钟推测远端丢包。

Opus 完整 framing、20 ms 时长和非零 coded frame 在任何 PLC/reset 前解析。1–3 个缺失时间片显式调用 PLC，最多补偿 60 ms；更大缺口只 reset 一次并解码当前包，禁止按攻击者提供的大 PTS 生成长循环。PLC 是合成历史音频，不是恢复经过认证的丢失包。暂存最多四个 PCM chunk，实际压缩解码成功后才播放这一批；坏 payload 不能触发补偿播放。重放、身份/时钟变化和解码错误终止旧流。恢复须建立新的已批准连接；不会默默重用旧授权。

## 开发验证与范围

合成 440/880 Hz 单/双声道通过实际双端持钥证明、owned duplex 线上包、Opus 编解码及记录播放，核对长度、幅度、频率和停止清空。另验证文件事件 FIFO 满时音频继续交付、真实发送 sequence/PTS 缺口的 bounded PLC/reset、初始队列丢包、坏包不触发播放、输入年龄/重复分配/权限/代次/设备失效、panic 后清理和失败报告。C 桥的无状态解析入口加入既有 ASan/UBSan 坏包 corpus；上游静态库本体未插桩。

```sh
cargo test --locked -p nestlink-media-codec -p nestlink-media-session -p nestlink-remote
```

运行前按 [NATIVE-MEDIA.md](NATIVE-MEDIA.md) 准备固定 native prefix。还未完成真实系统采集/扬声器、重采样/音画同步、WebRTC RTP/RTCP、Android/ARM64、跨网丢包和性能、安装签名与正式 A01–A21 验收。
