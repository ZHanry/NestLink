# Windows → Web H.264 接线与验证边界（2026-10-24）

本批把已有 Windows Media Foundation 编码器接到生产 WebRTC 宿主路径。只记录实现与
验证要求，不将尚未运行的 GitHub 检查、浏览器硬解、现场性能或长稳写成通过。

## 生产链路

1. Windows 预备采集阶段提供首次批准显示器的尺寸和实际工厂将使用的帧率、码率。
   此时不打开显示器采集设备；旧调用方未提供元数据时继续选择 VP8。
2. 在签名 answer 前解析真实 offer 的 payload、profile、packetization-mode 与 level。
   按该目标尺寸运行独占合成图像的 MF 探针，检查实际 SPS、独立 IDR 的软件解码、
   图像和 PTS；不使用显示器名称或创建编码器成功代替输出证据。
3. 仅在实际输出与 offer 存在能力交集时选择 H.264。产品使用对称 level 上限；
   常见 `42e01f` 仅允许 level 3.1，不能凭 `level-asymmetry-allowed=1` 宣称接收端
   能解码 1080p30。目标超限、奇数尺寸、不支持的参数或探针失败时，在 answer 前
   回退到 offer 中确实存在的 VP8。没有交集则拒绝。
4. 完成既有授权与端点证明后，媒体工厂才打开批准显示器。配置须与预检相符。
   编码 worker 在自己的线程上再准备实际编码器；若探针实际使用软件，运行实例
   固定为软件，避免重新选择探针失败的硬件。运行后不向 H.264 轨道写入 VP8。
5. 使用 `TrackLocalStaticRTP`，按编码器真实输出 PTS 产生 90 kHz RTP 时间戳，
   使用 H.264 SPS/PPS/FU-A 分包、连续序列号和最后一包 marker。保留 PLI/FIR
   关键帧恢复，逐包检查授权、路径与取消状态，并限制单包发送等待。
6. 切屏先在编码线程准备对应尺寸，再确认显示切换；旧 epoch 的画面不得继续写出。
   视频、音频、反馈及显示切换 worker 归属显式清理 owner；关闭有共同的两秒 join
   等待期限，超时和取消保留未完成任务的所有权，并报告清理失败。

MF 侧 `NOTACCEPTING` 先有界排空输出再重试。原生返回值明确区分输入是否被接受、
是否存在旧输出；只有接受输入才推进输入 PTS，输出必须匹配待处理队首。输出固定
两槽且按分配容量合计不超过 64 MiB，解码待处理和 in-flight PTS 同样有上限。

## GitHub 验证

产品编译与测试仅在 GitHub。Windows 普通业务进程 token 下显式运行
`windows_mf::tests:: --nocapture` 并保留 `nestlink-mf-target-output` 日志，其中
软件 1280×720@30 的真实编码、解码及 IDR 恢复必须通过。没有可用 GPU 时，硬件
项打印明确的 SKIP；创建成功却不产出有效帧属于失败，不能转记为硬件通过。

协议测试覆盖 profile/mode/level 和签名 answer 的 payload 绑定；SDK 测试覆盖实际
RTP 重组、MTU、序列号、PTS/wrap、旧接口回退、运行格式固定和 join 所有权。
Windows 真实目标探针与实际 PeerConnection 的 H.264 answer 另有集成回归。
生产 Web → 原生宿主的既有 VP8、音频、键鼠、文件、续租和清理检查继续保留。

公网入口测试首次 GitHub 运行 `40035244751` 返回 500 的原因独立于媒体：测试反向
代理把已路由请求再次交给 Router，Axum 累计两份 `id` 参数，`Path<String>` 在
业务 handler 前拒绝。两个 fixture 代理边界现在清空旧 extensions，由新 Router
重新匹配。服务端权限、DNS/origin 和版本冲突校验不变；真实集成仍须重新通过。

## 未完成的验收

本批仍为 CPU BGRA/NV12 路径，未完成 GPU 零 CPU 回读的全链路与原生 GPU 呈现。
H.265、4:4:4/HDR、高帧和多 GPU 合格表、原环境 100 次连接、1080p60、UU 同口径
A/B 与 24 小时长稳继续单独实施及验收。原环境 `4407106` 的已确认直连、画面和
键鼠基本功能通过，只能作为该版本、该场景的已有证据。
