# 子网固定授权与节点活性分离

状态：已接入，等待同源 GitHub Actions 回归。

W23 沿用已有 RouteExport 的两层时限。管理员批准的 mapping 签名期限最多为原请求期限与原 RouteExport 期限的交集。原 NetworkAccess 再与该 mapping、双方 membership 的原期限相交；不能把一次 10 秒节点 lease 的期限写成不可变业务期限。否则持续正常续租的同一节点也会在第一个 lease 到期后永久停止原业务。

选择固定授权与动态活性分离。每次 storage read/admit 和 SDK refresh 仍核验最新节点 key、同一 boot/runtime、当前 lease、原 export、mapping revision、policy epoch 和撤销。SDK 保留原 one-use owner、固定 monotonic deadline、累计字节计量及 5 秒 observation gap 终止。已观察到过期、重启、撤销或刷新失败的原 owner 不可恢复。续租不修改任何签名 bytes、不延长任何原授权、不重置预算，也不允许新的 boot 接管旧 mapping。

备选方案是把签名截断至首次 lease 后自动重签 mapping/business；不采用，因为这需要新的显式授权、one-use 与预算关联协议，容易把可用性续租误变成权限扩张。保持原截断则无法提供超过首次 10 秒 lease 的正常业务。

Linux root helper 校验原固定签名及独立的初始节点 proof。运行中的 latest 节点活性由持原 one-use OnlinePacketAccess 的普通 owner 定期查询；普通 owner 的失败/退出关闭精确绑定的 packet pipe，helper 回收 namespace。不能把普通 JSON 的 lease 字段当成 root 独立收到的中心签名；内核固定 deadline、quota 和受保护 consume marker 仍独立限制资源。

回归要求：真实 HTTP/SQLite 与 OnlinePacketAccess 连续运行超过首个 lease，在同 boot 续租后原 mapping/business 签名字节不变、累计预算不变、原期限不变；随后撤销必须关闭原 owner。原重启、终态与时钟回滚反例继续保留。该测试不代表 Linux LAN TCP/UDP 转发或现场验收通过。
