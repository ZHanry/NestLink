# v15 控制中心运行

0.7.0 RC 提供账号、设备持钥登记、本机批准、签名会话许可、续租、策略、签名信令、管理事件、组合原生 WSS 中继及独立数据节点。TOTP 与恢复码已在 0.2.0 移除。跨网络部署和功能边界见[连接说明](../REMOTE-CONNECTION.md)，平台与真实网络验收状态见 Release 材料。

schema 15 的 `POST /nodes/{id}/close` 验证节点独立签名、分配与运行/安全代次及稳定许可绑定，原子关闭精确预留、缩短容量承诺、保存原 ACK 和 Node 操作者审计。回执不是业务权限，撤销后仍可清理原分配；关闭与续租任一提交顺序都不会复活旧 UUID。同一安全代次的已确认精确回执可在控制重启后返回原结果；新回执仍需当前签发该承诺的 control runtime，恢复安全代次拒绝旧回执。实现与实际 I/O 排空条件见 [relay-close.md](../../protocol-spec/relay-close.md)。

schema 14 增加双方安装证明的重连交换与持久回执：严格递增连接代次和租约序号，保留原权限、路径、密钥、能力与到期时间。控制方提交必须使用原申请登录，被控可使用自己的当前登录。重复提交仅在回执仍为完整当前许可时返回原结果，HTTP 响应丢失不会再次递增或延长期限。旧信令随事务清除，旧节点分配失效而已承诺容量不提前退款。SDK 提供双方协调、旧会话清理、原时钟保留与新端点构建，见 [reconnection.md](../../protocol-spec/reconnection.md)。

原生 SDK 现提供单节点的有界自动恢复流程，包括空闲故障检测、共同新分配、签名发现与 QUIC/WSS 竞速。控制服务的节点发现允许当前有效分配的另一端在满额时获取节点描述，额外分配仍需原容量事务准入；关闭、旧代次或配置失效的分配不采用此路径。实际条件与未完成的已安装产品验收见 [native-recovery.md](../../protocol-spec/native-recovery.md)。

组合 WSS 和独立节点使用同一份 schema 12 持久分配/账号名额预留。`POST /remote/{id}/relay/allocation` 验证当前许可和设备签名后签发节点绑定的短期预留；管理员 `GET /relay/reservations` 查看已承诺占用。WSS 实际连接结束、续租、请求取消和数据库响应丢失都有容量生命周期处理，冷重启/恢复先等待旧租约期限。计数包括未实际连接的承诺，不能用于宣称独立节点已开始业务转发，见 [relay-allocations.md](../../protocol-spec/relay-allocations.md)。

受信设备入口已接入控制服务和原生/WASM SDK：被控安装私钥在当前许可上单独签署信任期限，固定双方公钥、权限、路径和授权版本；后续通过 `/remote/trusted` 明确使用。删除信任会原子撤销关联会话，保留版本记录阻止旧签名重放；许可有效期不超过信任期限。具体请求、30 天期限和开发配额见 [trusted-devices.md](../../protocol-spec/trusted-devices.md)。

固定密码控制服务与 SDK 已加入独立的被控签名配置、主控签名使用、逐项权限/路径和明确期限。密码计算在数据库锁外进行，提交前重新检查登录、设备、配置版本和挑战；更改或撤销配置关闭旧版本会话。防爆破预算在计算前持久化，每被控设备每分钟 5 次、每主控账号每分钟 30 次，取消、改密和刷新登录不能重置。数据库 schema 7 不继承旧密码，恢复会清除配置的校验值。协议和验证范围见 [remote-password.md](../../protocol-spec/remote-password.md)。本机系统同意、全端 UI、一次性授权流程和正式验收继续实施。

审计查询和保存期限配置已接入管理员 API 与原生/WASM SDK；分页绑定部署安全代次，最多返回 100 条必要元数据。默认保存 30 天，可配置为一小时至 365 天；`control` 启动后每分钟清理最多 500 条过期记录，保留递增序号和清理游标。维护失败会返回服务监督入口。协议、清理边界和未完成的全量事件覆盖见 [audit.md](../../protocol-spec/audit.md)。

审计 schema 9 区分管理登录、已验签安装、用途绑定设备凭据、本地操作、未认证尝试和操作者未知的历史记录；事务核对账号/登录/设备关联。已实现业务的关键状态变化携带操作者，新增远控申请、首次许可、恢复码实际消费及固定密码计算前的尝试记录，重试不重复记录同一次状态转换。审计只保存必要身份 UUID，不保存登录名、密码、令牌、因子、签名或业务载荷；中继/edge/TURN allocation、公开服务与配额事件随对应业务继续实现。

使用 Rust 1.96.0，在 monorepo 根目录构建：

```text
cargo build --locked -p nestlink-server
nestlink-server init --directory <新目录> --management-origin https://console.example.com
nestlink-server bootstrap --config <新目录>/server.toml --username admin --password-file <私密密码文件>
nestlink-server check --config <新目录>/server.toml
nestlink-server control --config <新目录>/server.toml
nestlink-server stun --listen 0.0.0.0:28744
```

密码长度为 12–1024 字节，文件支持末尾换行。密码不放在命令行参数、日志或配置中。Linux 的目录和秘密文件必须属于服务用户，目录 0700、秘密文件 0600；Windows 密钥由当前运行用户的 DPAPI 保护，启动账户必须与初始化账户相同。不要用另一账号重新生成旧部署的密钥。

控制中心只绑定 loopback，默认 `127.0.0.1:28740`。生产入口使用 [Caddy 模板](../../packaging/caddy/Caddyfile)，设置 `NESTLINK_MANAGEMENT_HOST` 为与配置相同的管理主机。服务账号使用 [systemd 模板](../../packaging/systemd/nestlink-control.service)。Caddy admin 的 Unix socket 需要由安装步骤建立合适的用户组和目录权限；当前模板尚未通过完整安装验收。

默认策略为 `deny/direct_only/disabled`，不转发远控或公开服务。全局策略与账号、设备、资源、会话、双方本地限制求交。管理员更新全局或范围策略会撤销现有许可，端点必须重新获得授权。

仅开发可显式使用 `--allow-loopback-http` 与 `http://127.0.0.1:<端口>`。旧 `/api/v2` 与 hbbs/FRP/RustDesk 入口没有兼容回退。

`/api/v3/remote/{id}/signals` 交换当前许可绑定的签名候选及浏览器 SDP。服务端最多保存每会话两个端点的最新信令；候选最多 32 个，SDP 最多 64 KiB。接收端须用许可中的公钥摘要验签并维护 SignalCursor，不能将 JSON 中自报的公钥当作信任锚。中继路由来自核验过的部署/节点发现，不会把管理凭据发送到对端指定的地址。

`GET /api/v3/remote/native-ready/{host_device_id}` 仅向该设备所属登录账号返回当前有效、已批准且控制端近期发布原生信令的请求，不返回浏览器 SDP 请求。守护进程用其接续会话，随后仍重新核验许可、设备密钥和网络代次；此查询不授予访问权限。

`/api/v3/remote/{id}/relay` 是原生 WebSocket 字节中继，需当前许可包含 relay 路径，登录身份及端点私钥完成新挑战。SDK 在字节流内部建立双方终止的 TLS 1.3，随后仍需完成原生会话证明和逐通道授权。不能用于替代浏览器 WebRTC/TURN。默认最多 128 个会话、每账号 16 个端点、每方向 8 个 64 KiB 队列槽，每会话两方向合计 16 MiB/s 和 1 GiB 字节配额；超过配额或持续背压会终止。授权每 250 ms 重查，检查超时 700 ms 会关闭通道，许可的单调期限也独立生效。当前为同机组合角色的开发限额，独立节点配置和容量验收继续实现。

初始化拒绝覆盖旧配置、数据库和密钥；不读取 14.x 身份或配置。生产切换、历史导入、正式签名和旧环境停用尚未执行。

组合控制角色的 WSS 配额现在由管理员 `/relay/quota` 配置，数据库持久保存版本，事务同时写入操作者审计；范围和默认值见 [relay-quotas.md](../../protocol-spec/relay-quotas.md)。修改版本会停止现有分配，独立停止信号不会被数据队列占满阻塞，连接监督另重查持久版本。`/relay/usage` 返回当前容量和双向累计接纳字节，带本次运行 ID 与报告序号；独立节点的持久计量、全局/账号/设备/资源聚合额度、QUIC/TURN/edge 配额和完整 UI 继续实施。

加密备份和离线恢复使用 `backup`/`restore` 命令，详见 [BACKUP.md](BACKUP.md)。恢复只写新建目录，撤销旧登录和授权、清除旧恢复码，不启动服务；`check`、`control`、`bootstrap` 和 `backup` 均拒绝缺失或空白的数据库，配置文件按私密文件句柄读取并限制 16 KiB。

独立数据节点通过 `node-init`、管理员 `/nodes` 登记及 WSS 持钥控制通道取得短策略租约，详见 [NODES.md](NODES.md)。`node-control` 仅运行控制通道；`relay --config <node.toml>` 同时运行控制和独立 WSS/QUIC 数据服务：WSS 默认 loopback 28746，经另一个 Caddy origin 提供 WSS；QUIC 使用 `--quic-listen`，默认 0.0.0.0:28743，并按签名分配固定节点 TLS 公钥。数据节点不打开控制数据库，不接收管理 bearer；端点签名和当前资源快照共同准入，内层双向 TLS 与业务证明仍在两端完成。运行和验证边界见 [independent-wss-relay.md](../../protocol-spec/independent-wss-relay.md)。QUIC 由端点终止内层加密，通过有界虚拟 UDP 转发，见 [independent-quic-relay.md](../../protocol-spec/independent-quic-relay.md)。

受管 TURN 由 `node-turn --config <node.toml>` 运行，并从节点配置旁读取私密 `turn.toml`；`--turn-config` 可指定其他路径。该命令只接受启用 `relay` 角色的节点，等待 NodeControl 的第一份有效租约后再绑定 UDP/TCP/TLS 监听，并将 TURN grant 注册表和终止租约 watch 共用给 `nestlink-turn-service`。部署配置模板、PEM 证书链/私钥要求、官方证书续期和 relay public pool 防火墙说明见 [NODE-TURN-DEPLOYMENT.md](NODE-TURN-DEPLOYMENT.md) 与 [node-turn.toml](config-templates/node-turn.toml)。运行监听不会自动发布管理面 endpoint，也不代替真实公网 DNS、TLS 签发、NAT/防火墙和跨网验证。

STUN 进程独立监听配置的 UDP 地址，默认 28744；它仅返回实际源 IP/端口，不建立转发 allocation。请求最大 512 字节，每 IP 每秒最多 10 个、全局每秒最多 1000 个，速率缓存有界。用 `--listen [::]:28744` 可运行 IPv6 地址发现；是否双栈由 OS bind 行为决定，不能以监听成功代替 IPv4/IPv6 跨网验收。控制配置的 `stun_servers` 通过登录后的 `/api/v3/network/discovery` 提供给已核验部署的原生端点和 WebRTC 双方，默认空，不硬编码公共服务。桌面和 Android 的私网拨号范围只由本机用户批准和持久保存，部署响应不能授予该权限。详见 [原生网络设置](NATIVE-NETWORK-SETTINGS.md)；生产防火墙与跨网验收仍需实际环境。
