# 原外部 Edge ↔ HL 连接整改

直连为核心验收项。中继可用不抵扣原场景的真实直连次数，不能据此发布 0.7.0RC。
发布继续受 [完整验收门禁](REMEDIATION-ACCEPTANCE.md) 约束。

## 仍失败的实际会话

`9d43797bce704afe79c5d09b36fdfb3f70353f3c2ab0b99246f943c619f894cd`
是部署受管 TURN 后的一次真实失败，用户确认仍无法看到桌面。
许可允许 Direct 和 Relay，30 秒 setup 许可在宿主首错时仍有效。
控制端有 mDNS、IPv4 srflx 和一个 relay 候选，宿主只有 IPv4 host/srflx，
未选出 candidate pair，未完成双端证明、运行授权或首帧。
宿主首错早于控制端撤销，不能再将本次错误解释为控制端撤销后的次生错误。

TURN 凭据被当前节点租约限制在约 7–9 秒，宿主完整收集耗时约 9 秒。
协商阶段原先不维护 TURN 分配，双方凭据在应答发布前已过期。
此缺陷影响可选中继，也会使仍在尝试的直连被后续绑定检查提前终止。
没有证据表明修正续租即可令当前网络的 IPv4 打洞成功。

当前同时允许 TURN 时使用完整 SDP 是明确的协议限制：
累计 ICE 候选的 TURN 双端绑定尚未单独完成资格验证。
本次不直接开启未经验证的 TURN trickle，也不扩大已签署许可。

## Windows IPv6 候选缺失

HL 物理接口有 IPv6 地址和默认路由，失败会话却没有 IPv6 候选。
锁定依赖 `webrtc-util 0.12.0` 的 Windows `v6_socket_from_adapter`
将 `IN6_ADDR.u.Word()` 的本机序 16 位整数直接转成 IPv6 段；
在 little-endian Windows 上颠倒网络序字节。物理接口过滤器将这些
与真实 OS 地址不同的 IPv6 候选排除；系统模式下也无法在错误地址 bind。

Windows 宿主改用现有 `if-addrs` 读取的正确地址构建 `Net::Ifs`。
该变体保留真实 OS UDP、DNS 和 mDNS；不启用模拟网络。
过滤掉停用、链路本地、未指定和多播地址，仍保留物理接口过滤和
在实际媒体 socket 上设置接口的路径，不改变代理或系统防火墙。

## 协商短租约维护

宿主在等待 offer、完整候选收集及 ICE 选路时维护同一 TURN allocation；
Web 在候选收集、轮询 answer、等待双端绑定和 ICE 选路时维护分配。
分配续租不等待尚未存在的 peer binding；绑定和分配各自核验。
Web 同时按照 Unix 到期时间和保守的 monotonic 截止提前续租。
固定操作预算仍保持，新的租期只能来自经过校验的管理响应。
直连已选中后撤回可选 TURN，后续连接不依赖中继续租。
已过期分配不复活，权限拒绝和签名/身份错误不降级成可用性故障。

## 验证范围

新增真实 IPv6 UDP/ICE/DTLS/SCTP 数据回归和 OS 地址字节核对；
新增真实 HTTP、签名凭据、生产宿主等待循环的短租约回归，覆盖跨过
首个 grant 到期时间、保持 allocation 和 setup 许可、拒绝及取消、固定预算。
新增测试的结果以对应提交的 GitHub CI 为准。
IPv6 loopback 回归不替代公网、Clash TUN 或原外部 Edge 的实际直连验收。
当前原场景直连与中继均仍为未通过，尚未发布正式 RC。
