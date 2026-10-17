# 原生媒体编解码与会话接入

本批实现原生可靠通道上的 VP8 视频发送、解码和授权交付，以及独立 Opus 编解码边界。新代码为 Apache-2.0，使用官方编解码 API；没有迁入或机械翻译旧远控项目的媒体集成代码。线上字段与预算见 [native-media.md](../../protocol-spec/native-media.md)。

## 实际行为

`nestlink-media-codec` 使用 libvpx 1.16.0 的 VP8 encoder/decoder 和 Opus 1.6.1。Rust 持有 codec 状态，BGRA/I420 转换和缓冲预算；小型 C 桥使用官方头文件访问 opaque context。每个状态只有一个所有者，允许移入专用线程，不支持并发访问同一 context。VP8 限定可见帧、固定尺寸、首帧关键帧和严格递增外部时间戳；内部使用有界固定帧时钟。Opus 固定 48 kHz、每包 20 ms、单/双声道；严格解析包、时长和声道，空包不能隐式请求丢包恢复。

`nestlink-media-session::VideoSender::attach` 从同一个已授权 `ChannelRuntime` 创建 `VideoController` 和发送端，绑定实际 connection generation、layout epoch、批准 source 和固定像素尺寸。它按本次会话明确选中的 source 集合从共享采集队列逐路取帧；单路交互切屏仍由 `VideoController::poll` 只取当前 source。它自行消费平台 `CaptureDevice`，不提供外部原始图像提交入口。采集检查返回后才在专用线程编码；编码前可跳过过期或超过帧率的原始图像。编码后重新检查授权，再进入有界可靠视频队列。该队列满时背压，按线上顺序交付所有参考帧，不替换、不按年龄删除已编码帧。

`VideoReceiver::attach` 接管同一授权 runtime，在专用线程上逐 source 解码。它在修改解码历史前验证 source、连接、布局、尺寸、关键帧、序列和 PTS，在解码后及 UI 取出时再次校验授权。输出每个 source 保留最新已解码画面，待呈现 source 轮转，所选画面总大小最多 128 MiB；此预算不包含 codec 自身参考图像和当前工作缓冲。重放、异常时间戳、尺寸/代次改变仍终止；缺初始关键帧、前向参考缺口和合法封装内的熵解码失败改为丢弃未呈现图像/解码器、请求关键帧并等待新 decoder 恢复。每 source 两秒固定期限、30 秒内最多三次恢复开始或熵失败；后续 delta 与重试不延长期限。独立 Tokio 监护观察已经发布的恢复期限，迟到成功不能清除到期状态。

`VideoSender::attach` 现在可变借用 runtime 并独占 VideoFeedback 消费者，在等待视频队列时仍处理反馈。请求使用 View 权限、独立递增序号、原连接/布局/source 和最新已消费帧序号；最近完全相同请求幂等，冲突/旧请求/未来确认拒绝。每 source 强制关键帧至少间隔 250 ms，合并待处理请求。采集静止时重编码最近已授权像素，明确设置 `repeated_source`；重编码前仍检查 OS、lease 与布局，缓存合计受 128 MiB 选源上限约束。持续更新的屏幕不能占住静止屏幕的恢复编码机会。坏帧不呈现，反馈失败不能增加权限或复活终止会话。

其他获准且未独立分配的业务通道由独立异步分发器放入容量 4 的事件 FIFO，由 `poll_event` 交给上层输入、文件或剪贴板分发器；FIFO 满时等待，取出时再检查该通道权限，停止能中断等待。Video 独占消费者使该 FIFO 满不再堵塞已收到的视频解码与反馈。Opus 通过 `AudioReceiver` 的唯一音频消费者与专用线程接入本地 PCM 边界和有界缺口策略；系统适配进展与真实产品边界见 [NATIVE-AUDIO.md](NATIVE-AUDIO.md)、[WINDOWS-AUDIO.md](WINDOWS-AUDIO.md) 与 [LINUX-AUDIO.md](LINUX-AUDIO.md)。

停止不等待编码锁。发送、接收和呈现入口均拒绝终态授权，终态观察者清空输出。线程回收另有 250 ms 等待预算；实际 codec 卡住时明确返回 `TimedOutDetached`，`WorkerMonitor.cleanup_timed_out` 保持为真，不能据此报告原生资源已经释放。平台 reset 自身的有界清理另记于会话 `StopReport`。

## 固定源码供应

[native-codecs.lock.json](native-codecs.lock.json) 固定官方 commit、归档大小/SHA256、功能和目标。`scripts/refactor-native-codecs.py` 每次在新目录提取并构建，拒绝复用旧源码、链接/特殊文件、路径逃逸、大小超限和外部构建标志；构建前后重算源码树摘要。Opus 版本通过上游接受的 `OPUS_PACKAGE_VERSION` 传入，运行时再次精确检查版本。Windows 使用动态 MSVC CRT，并关闭 libvpx 的 MSVC `/GL`，避免静态库打包进 Rust rlib 后丢失符号索引。

安装 receipt 覆盖所有库、头文件、配置、许可证和工具信息。Cargo build script 在编译 C 桥、链接库之前校验目标、来源锁、功能及每个安装文件的大小和 SHA256，拒绝缺失、额外或修改的文件和目录链接。receipt 用于验证本地构建输入的一致性；能同时替换库和 receipt 的恶意本机账号不在其认证边界内。固定来源和记录工具不等于所有机器都产生逐字节相同二进制。

当前供应目标为 Windows x64 MSVC 和 Linux x64 GNU；ARM64/Android 供应配置尚未加入，禁止把 x64 receipt 改名冒充其他架构。原始许可证、专利声明和额外版权声明在 `packaging/notices/`，摘要和使用范围在 [source-ledger.json](source-ledger.json)。第一方构建不启用 H.264/H.265/AAC/VVC，libvpx VP9 及 Opus DRED/DEEP_PLC/OSCE/custom modes 均关闭。

Linux 需本机 x64 GCC、make、NASM、CMake、Ninja、Perl 与常规 POSIX 工具：

```sh
python3 scripts/refactor-native-codecs.py build \
  --target x86_64-unknown-linux-gnu \
  --cache-dir /tmp/nestlink-codec-source-cache \
  --work-dir /tmp/nestlink-codec-build-new
export NESTLINK_CODEC_PREFIX=/tmp/nestlink-codec-build-new/x86_64-unknown-linux-gnu
python3 scripts/refactor-native-codecs.py verify \
  --target x86_64-unknown-linux-gnu --prefix "$NESTLINK_CODEC_PREFIX"
cargo test -p nestlink-media-codec -p nestlink-media-session --locked
bash scripts/test-vp8-boundary-sanitizer.sh
```

Windows 需 VS 2022 x64 C++ 工具、CMake/Ninja、NASM 和包含 make/Perl/POSIX 工具的 MSYS。`--work-dir` 必须是尚不存在的 ASCII 无空格路径；工具自身可在含空格目录中。按实际安装位置指定 MSYS 和 NASM：

```powershell
python scripts/refactor-native-codecs.py build `
  --target x86_64-pc-windows-msvc `
  --cache-dir C:/nestlink-codec-source-cache `
  --work-dir C:/nestlink-codec-build-new `
  --msys-bin C:/tools/msys64/usr/bin `
  --nasm "C:/Program Files/NASM/nasm.exe"
$env:NESTLINK_CODEC_PREFIX='C:/nestlink-codec-build-new/x86_64-pc-windows-msvc'
python scripts/refactor-native-codecs.py verify `
  --target x86_64-pc-windows-msvc --prefix $env:NESTLINK_CODEC_PREFIX
cargo test -p nestlink-media-codec -p nestlink-media-session --locked
```

已核验缓存可加 `--offline`；缓存损坏时直接失败，不重新下载替换证据。既有构建目录不会被清空。

## 验证范围

开发测试包含真实 VP8 关键帧/连续帧、奇数和极小尺寸、颜色质量及时间戳极值；真实 Opus 音量/频率/声道、边界码率、显式 PLC/reset 和坏包。专用会话测试通过实际双端持钥证明、有界内存线上传输、所拥有的合成采集图像、VP8 编解码与逐显示器交付，同时检查业务事件分发、代次/重放拒绝、控制面撤销中断背压和卡住线程的失败报告。内存传输和合成像素不能替代已安装产品及真实跨网屏幕验收。

恢复测试另包含应用层刻意省略已编码参考帧后的 Sender→Receiver→反馈→缓存关键帧自动闭环，以及静止来源、请求幂等、持续变化的其他来源、文件 FIFO 满、坏反馈、连续熵失败和独立期限监护。静止来源请求/响应分别在真实回环 QUIC 与内存可靠通道测试；应用帧省略不是 QUIC 丢包实验，可靠传输会重传丢失字节。

Linux 的 ASan/UBSan 探针插桩第一方 C 桥；它们调用固定上游静态库，上游库本体未插桩。当前反馈增量未修改 native C/FFI/供应，历史探针原件明确复用。CI 已添加同一供应脚本和探针；远端工作流尚未运行。QUIC 独立可靠通道和有界 Audio 数据报已经接入；真实桌面/混合 DPI、全端 UI、WebRTC RTP/RTCP、音画同步、拥塞适应、ARM64/Android、性能、签名安装和正式媒体验收继续实施。
