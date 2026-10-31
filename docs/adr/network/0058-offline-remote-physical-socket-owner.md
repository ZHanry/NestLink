# 离线远控保留原始 UDP 物理释放归属

状态：源码实现，待 GitHub 托管 Actions 验证。

3f1eb6b 的真实 HTTP/SDK 用例已执行批准、一次性消费、中心监听停止、
原在线授权过期后的新 QUIC 证明和业务停止，但最后 UDP 端口重绑报
AddrInUse。ChannelRuntime 关闭业务任务并丢弃 Endpoint 不等于 Quinn
异步 driver 及 writable poller 已销毁；原离线路径未附加物理 carrier owner。

比较重试端口绑定或 sleep 与等待原 socket 生命周期回执，选择后者。
复用 transport-quic 已有 service::socket 的 tracked socket / poller，
给普通 pinned remote ALPN 增加 DirectEndpoint 薄 owner；不采用 service
ALPN 或服务授权替代远控授权，不重写 UDP runtime。连接和服务端均保留
同一个原始释放 receiver，接入原 ChannelRuntime::with_transport_owner。
业务任务和连接 clone 先结束，再等待 endpoint idle、丢弃 owner 的 endpoint，
最后等待实际 socket/poller 释放。复用 ChannelRuntime 的原绝对关闭时限；
取消等待不丢失 receiver，Drop 仍立即要求关闭。

增加取消等待期间保留 clone 的反例和解除后物理重绑；保留原离线远控
用例全部断言，并额外检查 controller 和 host 两端 UDP 端口。对管理 TCP
和两端 UDP 的错误分别附加上下文，避免无法区分资源。恢复循环使用
while let 修正 strict lint，未增加 lint 豁免。

此改动只补足已有离线 QUIC owner 的物理清理，不代表完整 AppCore 原生
采集/输入/文件接线、TLS fallback、产品 UI、多 resident 或目标设备验收。
