# 原生音画时序实施状态

2026-10-15 的 23 文件增量已合入，原件为 `artifacts/native-av-timing-draft-20261015/`，整合记录为 `artifacts/core-verification/native-av-timing-draft-20261015-integration.json`。本记录描述代码边界；整合后的编译、行为和设备验收分别记录。

同一已证明会话创建唯一 `SessionMediaTiming`。Host 视频使用真实采集 Instant 换算 90 kHz PTS，系统音频以相同 origin 映射 48 kHz 样本位置。切屏和延迟打开设备保留时基，真实样本缺口继续保留。超过 60 ms 的音频漂移最多每秒校正一个 20 ms 帧；负校正丢帧，超过 250 ms 停止 worker。

Controller 共享 60 ms 的初始播放映射；超前 250 ms 或迟到 40 ms 的媒体丢弃呈现，解码器参考与认证反重放历史仍推进。视频待呈现队列最多 16 帧/128 MiB，切屏、几何刷新、恢复和撤销清空旧像素。音频等待可被撤销打断，入设备队列前再次核验原授权代次。

`AudioPlaybackTiming` 分别记录软件排队帧、硬件排队帧、硬件延迟及观察时间。未知保持未知，硬件快照超过 100 ms 失效。已知部分只用于有限提前入队；`played_chunks` 表示平台接受入队，不能证明已经发声或测得端到端时延。

- Windows 从真实 WASAPI padding 和 stream latency 获取时序，Rust 另记部分写入的软件队列。
- Linux PipeWire C/header/Rust callback 同时变更为含 16 字节时序结构的 ABI，并用实际 `pw_time.rate` 换算 graph delay；负值、无效 rate 和超预算值不作为已知延迟。
- Android Kotlin/JNI/Rust 同时把内部采集头从 8 改为 16 字节，加入首样本单调时间；优先 AudioRecord driver timestamp，尚不可用时明确使用读完成减 20 ms 的估计。AudioTrack 排队事实处理 32 位 head 回绕；扬声器硬件延迟保持未知。

Android 视频通过 `nativeHostCapturePts` 将最多 100 ms 的采集年龄交给 Core，同一原 MediaProjection 会话中的迟到像素直接丢弃。Image timestamp 与 `System.nanoTime` 的设备时基一致性仍须在 API 30–36 和 ARM64 真机确认。Android 10/API 29 不在范围。

独立稿执行了实际 timing 定义的 6 项 Rust 测试，以及实际 NativeAudio 源码的 9 项 Kotlin/JUnit 测试。整合后 Windows/Linux 媒体时序各 36 项、远控音频事实各 3 项、平台音频分别 8/5 项和 Core 原生会话各 4 项已实际通过；Linux 生产音频 C ABI 的 ASan/UBSan 另验证 100,000 个 PCM 边界输入。当前完整 Kotlin/JVM 75 项通过，JNI/APK 和 API 30–36 新构建另行记录，不能拿独立稿结果替代。精确源码与命令见 [集中检查](NATIVE-INTEGRATION-CHECKS-2026-10-15.md)。最终硬件音画偏差、系统设备重开及跨网质量仍待固定产物实测。
