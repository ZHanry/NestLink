# 原 packet owner 的物理终态与既有媒体 producer 预算

状态：已接线，等待各自精确源码的 hosted 检查；不表示 W31 或目标设备验收完成。

packet carrier 继续复用 Quinn 0.11.12、Tokio 和既有 tracked socket/poller 析构回执。真实 server accept 延迟 6 秒后，QUIC RTT/PTO 的排空时间可以超过业务 owner 原定 5 秒物理清理期限。单独 close/drop 用户句柄仍会留下 Quinn endpoint/connection 后台 driver，因此不能把 close 请求当作端口已释放。

比较过修改 QUIC timer、延长业务清理等待和管理原 endpoint 的任务生命周期。选择通过 Quinn 已公开 Runtime 接口薄适配 Tokio，仅记录本单次 packet endpoint 创建的 driver；原 owner 终态先 close，再停止新 driver、abort/join 已有 driver，最后仍等待真实 socket 及全部 poller 析构回执。原 TLS/proof/协议时限、5 秒清理门限和失败断言均保留。清理取消或超时不会报告成功；Drop 也停止本 owner 的后台任务。scope 仅该原始 IP 端点，其他远控与 service carrier 仍保留各自资源 owner。

W31 复用现有每 channel 有界队列、QUIC stream priority、独立音频 DATAGRAM、关键帧反馈、VideoQuality 与成熟编解码器。审阅发现 VideoQuality 的初始化和降档 floor 会把已批准 5fps/256kbps 提升到 15fps/800kbps；初始化现在遵守现有合法配置范围，降档 floor 也取原最高值与通常 floor 的较小者。原降档和逐步恢复节奏保留，超过一秒的观测空窗会重置连续健康窗口，旧时间戳不参与调档。

生产 daemon 继续使用原 VideoQuality。通用 legacy fixed-source VideoSender 也复用同一控制器，以实际编码耗时与有界 enqueue 等待降码率/限帧；不跳过已编码参考帧，不改变获准尺寸/来源、会话代次、原撤销和清理语义。新协商格式仍由原 proposal/ACK owner 控制，这一适配不能绕过格式批准。

这是已有通用机制的产品接线，未自研拥塞控制或编解码器。局部 enqueue 耗时不代表接收端已呈现、真实丢包率或可用带宽。完整 W31 仍需生产接收反馈、协商分辨率降档、文件并发及实际 20→5Mbps/1%丢包验证；真实 Windows/GPU 与原 p95 门槛保留，不因这里的局部修复记为通过。
