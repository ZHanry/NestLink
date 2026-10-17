# WebRTC 视频反馈与码率调整（2026-10-16）

原生浏览器主机在完成双方证明、启动已授权媒体后读取真实 RTCP。VP8
协商增加 `goog-remb`，既有 NACK、PLI、FIR 保留。处理前核对视频 sender
实际 SSRC；其他流的估计、丢包报告和关键帧请求不能调整本视频。

有限且非负的 REMB 估计保留 15% 协议/音频余量，立即下调至接收端上限；
最小 64 kbps，最高仍为已批准采集配置。RR 只接受向前的扩展序号，拒绝重复、
旧值并处理回绕；丢包比例至少 26/256 时每 250 ms 最多降低 20%。恢复每秒
最多增加 5%，三秒内的接收端上限仍有效，长时间静默不会造成跳升。PLI/FIR
关键帧请求每 250 ms 最多接收一次。这些反馈只改变媒体质量，不携带权限、
续租、连接代次或路径变更的授权。

视频 worker 在编码前观察目标变更，以 `vpx_codec_enc_config_set` 原地更新
拥有的编码上下文；几何、时钟、参考帧和外部 PTS 历史保持不变。Rust 的
独占可变借用和原 worker 保持串行调用，非法标量不进入 C；实际桥调用失败
使编码器进入原有失败终态。

Windows 定向编解码 17 项、WebRTC 18 项通过，SDK/codec all-target strict02
通过。Linux 对应为 19/18 项，codec all-target strict 通过；SDK all-target
strict 随同签名中继批次通过。最终 Linux 运行包含与 Windows 首次运行相比
仅等价改写为 let-chain 的 Clippy 修复，原 strict01 失败继续保留。

新回环测试实际完成 SDP、ICE、DTLS 和加密 RTCP：错误 SSRC 不降码率，正确
REMB 使 4000 降至 850 kbps，随后 RR 使其降至 680 kbps，PLI 触发关键帧请求；
测试结束等待反馈任务并关闭两端。它不打开平台采集或代替业务权限批准。
VP8 第一方桥/边界夹具另以 ASan/UBSan 执行 96 个真实编码帧、3072 个变异包
和所有编码前缀截断；固定上游静态库未由该命令插桩。

最终七个改动文件、8 份通过回执和 776 个实际 Linux 测试输入已冻结在
`artifacts/browser-congestion-followup-20261016/FINAL_SOURCE_AND_CHECKS.json`，
SHA256 `993d8f8352c4e6f5dcd005ad68e50adebf8c2a5b58b20c5c36932ac672163ad0`。
其中 manifest/lock 保留测试时的原字节，随后 Foundation 的独立图替代另行
登记，没有把新依赖图冒充成该批运行输入。首次准备归档时发现旧媒体 Build02
归档早于 Web 依赖替代，已保留拒绝记录，改从精确 hash 匹配的原 manifest/lock
备份生成第二次归档。

主动网络损伤辅助脚本已准备，并通过四项计数边界测试。它只对自有 Chromium
页面使用 CDP 的 WebRTC 丢包、队列及吞吐条件，要求真实接收端丢包与新增
NACK/PLI、恢复后连续三段正常解码及十秒恢复预算，所有路径撤销条件并分离
CDP session。当前还未实际执行该浏览器损伤流程，不能以命令可用或单测通过
宣称网络恢复通过。

既有 Chrome 1080p30/Opus 短测使用更早的固定 Build02，并不含本增量。
新的 Android JNI/APK、三浏览器长测、实际网络损伤、真实采集与固定安装产物
验收仍需各自的输入和回执；旧 Android 112 项记录保持其历史范围。
