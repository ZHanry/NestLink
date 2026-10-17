# 独立数据节点控制

当前实现节点登记、专用持钥证明、短租约控制通道、签名节点地址发现及独立 WSS/QUIC 密文转发。QUIC 包通过外层数据报和有界虚拟 UDP 承载，TURN 和 edge 业务转发继续实施。节点策略租约只开启相应角色的全局开关；每条业务仍须单独验证具体资源/会话许可、授权路径和配额。

schema 15 增加独立用途签名的实际关闭回执。WSS 在读写、队列和承载 socket 全部清理后确认；QUIC 另等待 Quinn 共享 endpoint 的实际驱动排空，其他连接使其两秒排空等待超时则保留原容量承诺。最后一个资源与清理证明结束后，节点在至多 256 个活动/待清理/待确认分配的总预算内保存精确签名字节，失败按原字节轮转重试，业务停止后另有固定五秒收尾窗口。控制端只释放原精确分配，不赋予新权限；撤销节点可报告已结束事实，旧 UUID 不能复活。持久幂等、审计回滚、重启/恢复和开发验证边界见 [relay-close.md](../../protocol-spec/relay-close.md)。

共享 SDK 的 `recover_native_relay` 现可独立观察旧代空闲停止，保持最新许可的原单调期限，自动完成双方证明、当前签名发现、共同新 UUID 的分配和 QUIC/WSS 竞速/原生证明。退出、撤销、协议错误或清理失败会停止恢复；该入口明确恢复配置选定的单个节点。发现支持当前已预留分配在满额时的另一端配对，不能增加名额或复活旧分配。当前回归使用真实回环和合成业务帧，已安装产品与跨网/多节点验收继续实施，见 [native-recovery.md](../../protocol-spec/native-recovery.md)。

schema 13 增加默认空的节点地址批准表。管理员 `GET/PUT /nodes/{id}/endpoints` 比较配置代次，设备使用当前登录、完整会话许可及随机 nonce 申请 `POST /remote/{id}/relay/discovery`。共享 SDK 用原先固定的签发公钥验签，再取得匹配节点公钥/运行/地址代次的分配；`discovered_node_routes` 在 DNS 前复查全部绑定，一次解析并固定地址，响应和 route 共用原请求期限。配置更新会从资源快照移除旧代次分配，实际双端回归在两秒内停止，旧容量仍按原承诺保持。地址配置不能把 edge 节点变成 relay；详情见 [签名发现协议](../../protocol-spec/node-discovery.md)。

schema 12 为独立节点和现有组合 WSS 增加共用持久容量预留：管理员可查询占用，已批准的设备持钥申请签名分配，预留双方账号名额和节点的两个连接名额。撤销/节点接管不能提前释放已签发期限内的容量，组合 WSS 在两端实际关闭后释放；恢复及冷重启使用单调时钟等待旧期限，时钟异常停止新分配。具体期限、幂等/重放和容量边界见 [relay-allocations.md](../../protocol-spec/relay-allocations.md)。

WSS/QUIC 共用双端配对选择器及 256 个套接字、128 个等待分配和 120 次/IP/分钟预算。持钥证明通过后只准备候选，同一传输的双方到达才重查当前签发方、授权及原票据单调期限并提交角色；等待不计业务连接/字节。单端 UDP 黑洞和交叉到达不会把双方拆到不同通道，取消、超时和败选清理按 token 移除自身，获选通道继续传输。已提交后的失败仍需新分配，协调重试继续实现。调用两个 `serve_with_selector` 必须传同一个 `RelaySelector`；边界与实际回环回归见 [relay-selection.md](../../protocol-spec/relay-selection.md)。

节点现另以自己的签名每 250 ms 领取至多一秒的当前资源快照，响应由已批准的策略密钥签名并委托分配签发公钥；完整请求摘要防止响应错接。准入还验证原分配、端点公钥、所选传输与服务端挑战签名，双方共用速率/累计字节额度和节点总计量。guard 不可克隆，关闭、过期、撤销、资源查询失败或控制析构会通知空闲读写停止；失效 guard 不因晚到快照恢复，相同分配序号不延长期限。原全局租约/用量通道与资源授权分别执行，分配票据不单独授予业务权限。WSS 读写与空闲等待已接入这些 guard，写入复查授权且有独立期限定时器；QUIC 数据报准入、空闲等待与取消也使用同一资源 guard，边界与测试见 [node-resources.md](../../protocol-spec/node-resources.md)。

运行代次和计量增量使用 schema 11：每次启动有新的 UUID，签名证明和租约绑定持久代次，已退役或到期的 UUID 不能重新领取租约。并发新启动使旧控制连接失效。节点在每次交换后通过同源 HTTP 提交签名累计连接/入队字节报告；最新报告的相同字节重试返回原签名确认，不重复累计或释放其他业务容量。首次确认前不开放本地容量，确认失败终止授权。报告/确认用途与证明/租约隔离，不能延长期限。管理员可用 `GET /api/v3/nodes/{id}/usage` 或 `Sdk::node_usage` 分页查询持久记录。具体契约和容量边界见 [node-usage.md](../../protocol-spec/node-usage.md)。

所有角色共享本地连接容量及允许一秒突发的单调时钟令牌桶，非克隆 RAII reservation 只在成功入队时计量、析构一次关闭。WSS 与 QUIC 数据服务每次入队仍验证单独的资源/会话许可；TURN/edge 继续接入。当前数字是节点报告的最后已确认入队累计，不证明送达，也不假定崩溃或停止后的最终连接数为零。

在控制中心本机运行 `nestlink-server check --config <server.toml>` 获取 node policy issuer。它由部署根种子通过 HKDF-SHA256 的固定独立用途派生，与远控会话签发公钥不同，归档恢复原部署根种子即可恢复同一策略公钥。不得将网络响应中自报的公钥自动批准为新信任锚。

```text
nestlink-server node-init --directory <全新节点目录> --deployment <部署 UUID> --control-origin https://console.example.com --trusted-policy-issuer <批准的 base64url 策略公钥> --roles relay,edge
nestlink-server node-control --config <节点目录>/node.toml
nestlink-server relay --config <节点目录>/node.toml --listen 127.0.0.1:28746 --quic-listen 0.0.0.0:28743
```

`node-control` 为仅控制通道运行，`relay` 同时运行控制及独立 WSS/QUIC 数据服务，二者是同一登记节点的替代运行方式。节点数据入口需独立配置的 HTTPS/WSS origin，可使用 [Caddy 示例](../../packaging/caddy/Caddyfile.relay)。SDK 的 `node_relay_route` 使用管理员明确批准的本地 origin 和一次解析的固定地址；`node_quic_route` 固定批准的 QUIC URI/地址和签名分配中的节点公钥，两类独立 route 已接入 `dial_native_with_relays` 的统一竞速。不将对端候选当作节点地址，也不发送管理 bearer。签名地址发现也可产生这些固定 route；已准入后的跨传输重试协调仍须实现。真实回环联调已通过两端内层 TLS、原生证明和双向业务帧，以及空闲撤销、查询失联、配额/字节耗尽、挑战重放、监听取消和原期限之后的同连接续租；部署 TLS、持续负载和产品验收继续实施，见 [WSS 协议](../../protocol-spec/independent-wss-relay.md) 与 [QUIC 协议](../../protocol-spec/independent-quic-relay.md)。

`node-init` 生成独立随机 node.key，输出公共 NodeRegistration JSON。管理员使用共享 SDK 的 register_node，或带管理认证的 `POST /api/v3/nodes` 登记该公共描述。初始化拒绝已有目录；节点私密配置限制 16 KiB，秘密密钥使用与服务端相同的 OS 存储边界。节点只连接 HTTPS/WSS origin，测试时可显式允许 loopback HTTP；拒绝路径、账号密码、查询和 fragment。

`GET /api/v3/nodes/{id}/control` 进行 WS 升级后，控制中心发送新的 32 字节随机挑战和请求 UUID，节点用专用身份密钥签名，控制中心比对该连接的原始挑战和登记公钥，然后签发 10 秒节点策略租约。每 3 秒重新挑战并续租，租约绑定部署、安全代次、节点、公钥摘要、角色、策略代次、顺序号、请求、nonce、转发开关和连接/速率配额。挑战的重复消费持久化拒绝，已消费记录过期清除；提前续租拒绝。

默认最多 128 个登记中节点和 128 条控制连接，消息最多 4 KiB，挑战 5 秒内失效；节点连接使用独立 IP 速率桶。每 250 ms 重查撤销、最新顺序号、策略和安全代次，数据库检查及单次 WS 写入分别有 700 ms 预算。错密钥、重复证明、并发旧租约、失联和背压会关闭控制通道。客户端另每 100 ms 检查单调期限，即使 WS 仍保持连接但没有有效续租也会停止；墙钟回退、休眠差异、策略变化和显式退出均终止旧授权，旧响应不能恢复它。

默认 deny 时节点可完成认证和续租，但不能转发。登记角色不会越过本地角色限制；relay 不能凭节点租约成为公网 edge。配额来自管理员登记信息并签入租约；具体数据服务还需执行其业务配额。

SQLite 005 增量迁移保存节点记录和已消费挑战，不改旧迁移。备份恢复生成新安全代次并清除旧挑战，旧策略租约和证明失效；已登记节点必须重新完成当前代次的挑战。

开发验证覆盖真正的 HTTP 登记、签名累计报告/幂等确认和 WebSocket 持钥→续租→并发新运行接管→管理员撤销，在本地测试中 2 秒内终止旧节点授权；另有真实保持打开、HTTP 确认正常但不续租的 WS，证明计量不能延长期限。首次 poll 前析构不立即通知已先复现再修复；最终 Windows 220、Ubuntu 251 项 workspace 开发测试通过。上述验证不等于公网 TLS/Caddy、独立节点业务、负载或固定产物验收。
