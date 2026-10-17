# 原生候选联合竞速

`NativeEndpoint::new` 在建立端点前检查许可中的本地设备、双方公钥摘要和当前有效期。直接路径可用时建立同时用于 STUN 和 QUIC 的 UDP socket；relay_only 不建立 UDP 端点。`discovery_socket()` 因而返回 Option。

原生调用 `dial_native(local, relay_route, peer_generation, candidates, cancel)`，QUIC 专用调用 `dial`。双方本地批准与服务器策略已经在许可签发时求交；终端不能用候选声明增加路径权限。私网/ULA 直接拨号仍需配置允许的 CIDR，硬性危险地址始终拒绝。

候选在通过 `SignalCursor` 验签后使用。一个竞速总计最多 32 个候选、4 个并发、12 秒总预算和 6 秒单次预算。直接优先时保留中继并发槽，并在 2 秒后启动中继；relay_only 从开始只尝试中继。失败记录实际候选、阶段和错误码。

WSS 候选由 `Sdk::relay_route(permit)` 对已批准的管理 origin 一次解析生成，解析预算 3 秒，最多 32 个结果。`RelayRoute::candidates` 给出这些字面 socket 地址；竞速拒绝其他地址，并将外层 TCP 连接固定到选中的地址，保留原 URL 的 Host、SNI 和 TLS 域名验证。对端签名不允许修改登录凭据的目的服务器。路由绑定许可摘要，更新许可后重新解析。生产使用 WSS，开发用 WS 仅限实际回环。独立 relay 节点路由还需要独立签名的业务分配，此接口暂不把任意节点视为管理入口。

成功返回经过双向身份 TLS 的 `NativeTransport`；仍须运行 `controller_proof` / `host_proof`，之后由 `AuthorizedConnection` 逐通道检查许可。传输握手不代替本机批准、双方会话证明或续租。

成功结果同时返回原本地网络基线 `network`，在双方 proof 后传入 SessionLifecycle；通过 into_channels 建立独立收发与主动空闲监护。监控关闭、换网、恢复和到期会停止已建立会话，输入适配器释放已记录按钮，队列清空并结束持有传输的任务。具体预算、接入方法和当前可靠流限制见 [SESSION-RUNTIME.md](SESSION-RUNTIME.md)。

成功、取消、许可过期、墙钟回拨和网络代次变化都丢弃其余尝试；没有脱离竞速的后台连接任务。`invalidate_network` 同时使 QUIC、TCP 和 WSS 尝试失效，端点不可复活，需按新网络事实重建。桌面共享 NetworkMonitor 使用 Windows IP Helper 或 Linux route-netlink，检测 IPv4/IPv6 地址、路由与接口变化；250 ms 采样包含/排除休眠的系统时钟差。new_monitored 在创建 socket 前保存 OS 代次，事件同时清空 STUN pending 并使旧竞速终止；通知丢失、监控关闭、异常时钟及代次溢出均失效。新的监控端点沿用当前 OS 代次，不能将新网络降回 1。Android 网络/Service/Projection 的系统事实仍通过后续 Kotlin 桥接入。

Windows/Ubuntu 本地测试覆盖真实 UDP 黑洞下直接 TLS 获选和双方会话证明、实际等待中 TCP 握手的取消/换网关闭、强制中继无 UDP 端点和无直连、伪造中继地址不接收凭据，以及内层固定 TLS 的 WS 密文配对和服务器撤销。开发测试不代表正式 HTTPS WSS、公司网络、运营商网络、容量或媒体互通验收。

Linux 真实事件复现：`python3 scripts/refactor-network-events.py`。脚本以普通用户编译，仅在新网络命名空间内运行测试；需要 root 或可非交互 sudo 的 CAP_NET_ADMIN。默认 workspace test 将这一项标为 ignored，因为普通用户进程不能改网络；CI 独立任务及本地隔离运行会实际执行它。测试涵盖 IPv4/IPv6 地址、路由和 link 变更；它不替代 Windows 物理网卡变化、实际休眠或 Android 网络切换验收。
