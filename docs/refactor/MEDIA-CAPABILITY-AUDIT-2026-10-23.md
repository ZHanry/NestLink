# Windows 远控媒体能力审计（2026-10-23）

审计源码：`967ef9173f19e995d9af6a3e5b940dbd7e3abe6e`。本文件只记录现有生产代码的调用路径、能力缺口和对应验收要求，未执行新的采集、硬件探针、安装或性能测试。

需求依据为用户提供的《NestLink 对标 UU 远程研发改进方案 v1》（2026-10-20）第 6 节、第 9.3 节，以及 M01–M04、Q01 工作包。用户要求报告全部实现并验收后再发布 0.7.0 RC。当前源码尚未满足该完成条件。

## 现有能力与缺口

| 项目 | 已接通的生产能力 | 尚缺的部分 |
| --- | --- | --- |
| DXGI / WGC 采集 | Windows 显示器采集优先创建 Desktop Duplication，失败时回退 GDI；访问或设备丢失后，按有界周期尝试重建同一批准的显示器。 | 未发现 WGC 生产后端。DXGI 使用整帧 staging texture 回读，未使用 dirty/move rectangles。旋转显示器采用兼容回退；完整多屏、虚拟屏、热插拔和恢复矩阵仍需实际验收。 |
| Windows 原生 H.264 硬编硬解 | AppCore 在实际合成帧编码、解码探针通过后公告 H.264 能力。原生发送端确实构造 `VideoEncoder`，接收端确实构造 `VideoDecoder`；Windows 使用 Media Foundation，硬件创建失败时回退同编码格式的软件实现。 | 目前限定 H.264 Baseline、8 位、4:2:0。缺少完整的 profile/level、位深、色度、最大尺寸/帧率和适配器协商。320×240 探针不能证明目标显示尺寸、帧率或所有 GPU 组合达到性能门槛。Media Foundation 是报告允许的硬件方案，不应把未直接调用 NVENC/AMF/QSV 视为单独的缺陷。 |
| Windows 宿主 → Web / Edge | 生产 `SystemCaptureProvider` 使用 Windows 采集，并将 30 fps、4000 Kbps 的配置交给 WebRTC 媒体源。WebRTC 发送端注册 VP8 视频轨道，实际视频工作线程构造 `Vp8Encoder`。Web 页面通过原生 `<video>` 元素呈现。 | 原生 H.264 后端尚未接入 WebRTC 宿主编码链；当前实际宿主编码为软件 VP8。浏览器硬件解码由浏览器及驱动决定，现有导出诊断的 `hardware_decoder` 为 `null`，不能据此宣称硬解已验收。 |
| GPU 帧、零拷贝与呈现 | DXGI 采集和 Media Foundation 的 GPU 解码输出确实存在。 | 采集输出仍是 CPU `Vec<u8>`；没有携带 LUID、纹理与颜色信息的生产 `GpuFrame` 边界。硬解输出被复制到 staging texture 后回读、转换为 CPU BGRA，再经 IPC 发送完整像素，桌面端构造 `ColorImage` 并上传纹理。完整 GPU 采集—编码—解码—呈现链尚未接通。 |
| H.265 / 4:4:4 真彩 / 高位深 | 生产编码分派支持 VP8 和 H.264 Baseline。Media Foundation 使用 H.264/NV12，设置固定 BT.709 色彩属性。 | 未发现 H.265 生产编码、解码或协商路径。NV12 是 4:2:0，BGRA 输入与输出不能证明编码链保留 4:4:4。没有真彩、HDR、高位深的生产能力协商与对应档位。统计代码能够识别某个 codec 名称不代表该编码器已实现。 |
| 高帧与多 GPU | 原生 H.264 发送目标为 60 fps，软件编码回退限制至 30 fps；Windows 采集间隔约 16.667 ms，WebRTC 宿主配置为 30 fps。 | 没有接通 120/144 fps 生产档位。`VideoQuality` 接受最高 120 的数值不能替代生产调用方的 60/30 配置。采集设备按显示器适配器创建，MF 的 D3D11 设备按默认 GPU 创建；未通过共享 LUID 与纹理实现同适配器链路，HL 双 GPU 场景仍需实测。 |

## 生产接线证据

以下链接固定到审计提交，避免后续源码变化改变结论依据。

- **采集入口及回退：** [WindowsCapture 的 DXGI 选择](https://github.com/ZHanry/NestLink/blob/967ef9173f19e995d9af6a3e5b940dbd7e3abe6e/crates/platform-capture/src/windows.rs#L664)、[同一显示器恢复](https://github.com/ZHanry/NestLink/blob/967ef9173f19e995d9af6a3e5b940dbd7e3abe6e/crates/platform-capture/src/windows.rs#L729)、[DXGI staging 与整帧回读](https://github.com/ZHanry/NestLink/blob/967ef9173f19e995d9af6a3e5b940dbd7e3abe6e/crates/platform-capture/src/dxgi.cpp#L70)。DXGI 对旋转的兼容回退见同文件第 45 行。
- **实际原生编码路径：** [AppCore 公告真实探针结果](https://github.com/ZHanry/NestLink/blob/967ef9173f19e995d9af6a3e5b940dbd7e3abe6e/crates/app-core/src/native_session.rs#L63) → [daemon 选择编码格式并创建编码器](https://github.com/ZHanry/NestLink/blob/967ef9173f19e995d9af6a3e5b940dbd7e3abe6e/apps/daemon/src/native_video.rs#L957) → [MF 硬件优先与软件回退](https://github.com/ZHanry/NestLink/blob/967ef9173f19e995d9af6a3e5b940dbd7e3abe6e/crates/media-codec/src/video.rs#L135)。探针实际编码并解码自有合成像素，见 [h264_hardware_available](https://github.com/ZHanry/NestLink/blob/967ef9173f19e995d9af6a3e5b940dbd7e3abe6e/crates/media-codec/src/video.rs#L217)。
- **实际原生解码路径：** [生产接收器创建并调用 VideoDecoder](https://github.com/ZHanry/NestLink/blob/967ef9173f19e995d9af6a3e5b940dbd7e3abe6e/crates/media-session/src/receiver.rs#L1015)，在输出帧记录实际硬件解码标志。MF 的硬解标志以取得 GPU 输出为依据，见 [GPU 输出回读及 hardware_used](https://github.com/ZHanry/NestLink/blob/967ef9173f19e995d9af6a3e5b940dbd7e3abe6e/crates/media-codec/src/windows_mf.cpp#L263)。
- **实际浏览器宿主路径：** [daemon 的 30 fps 配置](https://github.com/ZHanry/NestLink/blob/967ef9173f19e995d9af6a3e5b940dbd7e3abe6e/apps/daemon/src/capture.rs#L345) → [WebRTC 注册 VP8](https://github.com/ZHanry/NestLink/blob/967ef9173f19e995d9af6a3e5b940dbd7e3abe6e/crates/sdk/src/webrtc_host.rs#L3281) → [video_worker 创建 Vp8Encoder](https://github.com/ZHanry/NestLink/blob/967ef9173f19e995d9af6a3e5b940dbd7e3abe6e/crates/sdk/src/webrtc_host.rs#L4234) → [Web video 呈现](https://github.com/ZHanry/NestLink/blob/967ef9173f19e995d9af6a3e5b940dbd7e3abe6e/apps/web/src/remote_panel.rs#L912)。[浏览器诊断](https://github.com/ZHanry/NestLink/blob/967ef9173f19e995d9af6a3e5b940dbd7e3abe6e/apps/web/src/remote_panel.rs#L67) 尚未提供硬解确认值。
- **CPU 往返链：** [RawFrame 仅携带 CPU 像素](https://github.com/ZHanry/NestLink/blob/967ef9173f19e995d9af6a3e5b940dbd7e3abe6e/crates/remote/src/video.rs#L17) → [MF 编码输入执行 CPU BGRA→NV12](https://github.com/ZHanry/NestLink/blob/967ef9173f19e995d9af6a3e5b940dbd7e3abe6e/crates/media-codec/src/windows_mf.cpp#L395)；解码侧 [GPU→staging→CPU BGRA](https://github.com/ZHanry/NestLink/blob/967ef9173f19e995d9af6a3e5b940dbd7e3abe6e/crates/media-codec/src/windows_mf.cpp#L276) → [IPC 完整像素](https://github.com/ZHanry/NestLink/blob/967ef9173f19e995d9af6a3e5b940dbd7e3abe6e/crates/app-ipc/src/video.rs#L424) → [ColorImage 纹理上传](https://github.com/ZHanry/NestLink/blob/967ef9173f19e995d9af6a3e5b940dbd7e3abe6e/apps/desktop/src/lib.rs#L943)。
- **格式与适配器限制：** [实际编码器分派](https://github.com/ZHanry/NestLink/blob/967ef9173f19e995d9af6a3e5b940dbd7e3abe6e/crates/media-codec/src/video.rs#L21)、[MF 固定 H.264/NV12/BT.709](https://github.com/ZHanry/NestLink/blob/967ef9173f19e995d9af6a3e5b940dbd7e3abe6e/crates/media-codec/src/windows_mf.cpp#L58)、[Baseline 固定 8 位/4:2:0 验证](https://github.com/ZHanry/NestLink/blob/967ef9173f19e995d9af6a3e5b940dbd7e3abe6e/crates/media-codec/src/h264.rs#L261)、[MF 默认 D3D11 GPU](https://github.com/ZHanry/NestLink/blob/967ef9173f19e995d9af6a3e5b940dbd7e3abe6e/crates/media-codec/src/windows_mf.cpp#L89)、[Windows 采集间隔](https://github.com/ZHanry/NestLink/blob/967ef9173f19e995d9af6a3e5b940dbd7e3abe6e/crates/platform-capture/src/windows.rs#L39)。

## 对应报告的完成条件

| 工作包 / 验收 | 当前审计判断 |
| --- | --- |
| M01：CPU/GPU 帧生命周期与真实能力 | CPU 帧、实际 H.264 探针已有生产调用；GPU 帧边界及完整能力协商尚缺。 |
| M02：DXGI/WGC 与恢复 | DXGI/GDI 及部分恢复已接通；WGC 和报告要求的完整设备、会话变化验收未完成。 |
| M03：H.264 硬编硬解、GPU 呈现、1080p60 | 原生 MF H.264 已接通；GPU 呈现、WebRTC H.264 以及实际 1080p60 达标证据尚缺。 |
| M04：H.265、真彩、高帧档 | 生产路径及硬件合格表尚缺。 |
| Q01：原网络故障、A/B、弱网、长稳 | 代码检查、布局测试和合成图像测试不提供这些现场测量结果，需分别完成并保留原始样本。 |

原报告第 9.3 节要求的关键证据包括：

- HL ↔ 原外部 Edge、Clash TUN 原场景至少 100 次连接，目标至少 99 次真实直连；中继成功单独统计。
- 原生动态 1080p60 实际呈现至少 58 fps，p95 帧间隔目标不超过 25 ms。
- 与用户安装的 UU 版本进行同口径输入到显示 A/B，分别核对 p50、p95；不能使用上传帧率或不同机器未经校准的时间戳代替。
- 弱网、文件并发、重连和授权退出各自达到门槛；单次 24 小时会话及跨日资源曲线通过。
- 4K60、120/144 Hz、4:4:4 建立独立硬件合格表，不由 1080p60 或单台机器的成功推断。

本文件没有将接口名称、编码枚举、设置值或 CI 通过数量计作上述媒体能力的现场验收。13 项真实 App::ui 布局回归验证界面稳定性；其结果应与媒体性能、原网络场景和发布验收分别记录。
