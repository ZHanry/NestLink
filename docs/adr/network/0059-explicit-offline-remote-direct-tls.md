# 离线远控使用显式批准的直连 TLS

状态：源码实现，待 GitHub 托管 Actions 验证。

完整离线授权格式已支持 QUIC 和 TLS，但原远控 SDK 只有 QUIC 承载。
复用 rustls/Tokio-rustls 的原安装密钥 pin、TLS1.3 与远控 ALPN，以及
现有 NativeEndpoint 的 authorize_stream、双方 Session 证明和业务队列，
新增 OfflineRemoteOwner::listen_tls/connect_tls。比较通过私有服务隧道
包装远控与直接使用原远控承载，选择后者，避免服务 ACL 代替远控授权。

TLS 必须在签名 bundle 的 direct_transports 内显式批准，连接前消费原
累计 attempt，成功 TLS 后仍检查协议、ALPN、单证书和精确对端 key。
独立离线 process proof 绑定本次 TLS transport，之后才以原未改动的
online permit 元数据激活独立离线 Session；不导出或续期 online permit。
所有操作保持原有限离线期限、权限子集和累计字节/连接预算。

监听只接受一次，接受后释放原 TcpListener；业务 read/write 属于原
ChannelRuntime，沿用其终态任务 join 和关闭时限。两种承载共用中心
恢复观察与本机停止，不引入新的全局轮询器或授权调度器。调用方显式
选择已批准承载，本改动不实现自动跨承载重试或 UI。

保留原完整 HTTP/SDK 离线测试，在中心停止且 online permit 过期后，
同时建立 QUIC 与 TLS，验证两边原业务队列、Input 拒绝、同 meter、
原 process.stop 后两种承载关闭，及 UDP/TCP 监听资源释放。完整原生
采集、输入、文件和产品 UI 接线仍需独立完成，字节测试不代表其验收。
