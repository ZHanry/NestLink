# 在原生产承载上显式协商能力

状态：已接入源码，待同源 GitHub 托管 Actions 编译、严格检查和实际承载验证。

原 CapabilityOffer/negotiate 只有解析和单元用例，不能构成生产混合版本
协商。复用原 Quinn mutual TLS、严格安装身份 pin、有界 bi stream、
现有 CapabilityOffer 和 negotiate；不另造发现、签名或传输调度器。
比较在旧 proof 后偷偷插入字节与选择独立 ALPN，采用后者。旧 ALPN
保留原字节和停止/重新证明/恢复语义，失败不重试更弱的协议。

原 raw-IP packet owner 默认只选择 network-packet/2，经实际 mTLS
验证对端后，将原 business grant digest 与 transport group 一起放入
最多 8KiB 的严格 envelope；既有 packet proof 保持原 64 字节。旧 /1
只能由显式 LegacyProofV1 策略选择，不在一次 TLS 握手中同时提供两种。

SDK 独立授权的 routed remote 由已验证的 RemoteControl purpose 选择
nestlink/network-remote/1 内层 ALPN。原 route/adjacency owner 在 await
前保留，协商精确绑定原 SessionPermit digest、签名 PathGrant 计算的
transport group 和 mTLS 端点身份，随后仍必须完成原双方业务持钥证明、
原生 profile 与各业务权限检查，才能暴露 ChannelRuntime。重放到另一
permit/路径组、必选未知能力、超限、错误 ALPN、超时或取消均关闭原
连接，并由同一 owner 等待物理释放。

该 remote 实现只声明并要求 network-core-v1；不声明 path-migration-v1。
接收 capability 不能扩大 membership、业务、路由、文件或输入权限，
不能延长期限。旧 NativeEndpoint 的直接连接与原 legacy relay 保持其
显式旧协议；它们不能因产品版本号相同而被视为理解新路径授权或迁移。
新 routed remote 和 raw-IP 的拒绝/选择矩阵分别记录，不能用单条路径
测试宣称完整旧客户端/服务器/节点混合矩阵通过。

验证复用原实际单 relay、多 hop、route-set、撤销和资源回收用例，及
新增真实 Quinn capability/packet ALPN 正反例。所有编译、格式、lint
和执行均由 GitHub 托管 runner 完成；最终状态以精确源码收据为准。
