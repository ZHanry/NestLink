# 标准 WireGuard 客户端入口

该入口使用 Linux 内核 WireGuard 和发行版 `wg` 工具。一个客户端公钥对应一个原始、目标账号已批准的 NetworkAccess 业务；进入入口的完整 IP 包继续经过原来的 NestLink 包授权、加密承载和双向计量。WireGuard 密钥、客户端地址、门户节点、门户启动代次、原业务摘要和有效期均由独立签名绑定。

当前 Linux 提供程序要求一个精确 IPv4 客户端 `/32`、一个固定客户端 UDP 物理端点、一个门户专用额外 LAN 地址，以及明确批准的目标 IPv4 前缀。远程客户端需要显式指定同 LAN 下一跳。客户端 NAT 端口或物理地址改变后，需要重新批准入口；当前入口不自动接受漫游。一个入口的命名空间、WireGuard 接口和内核预算属于该次原始普通用户进程。

## 先准备原始业务

门户使用已经注册并接受当前启动租约的原安装身份。空间管理员为客户端地址批准单独的 RouteExport 和 SubnetMapping；原前缀和别名前缀必须都是同一个客户端 `/32`。该安装的拥有者再独立绑定这份映射。客户端不能借用门户的托管主机 IP，也不能通过宽子网继承权限。

目标账号先批准原 NetworkAccess、Connectivity 和 Path。源地址就是上述客户端 `/32`，目的地址、协议、端口、方向、字节额度和期限由这个原始业务决定。空间管理角色无法替另一个目标账号批准其业务，也无法替源账号绑定标准客户端。

源账号通过 `wireguard issue` 提交 owner-private 的 `WireGuardClientBindingRequest` JSON。请求包含当前策略版本、客户端稳定 ID 和期望修订、原安装 ID、门户节点和期望启动代次、原业务 ID、独立客户端公钥、客户端 `/32` 地址、客户端累计总额度和有限截止时间。字段类型以生成的 API 合同和 `crates/protocol/src/wireguard/management.rs` 为准。

```sh
nestlink-daemon wireguard issue \
  --state-dir /home/nl/.nestlink --space SPACE_ID --authority SPACE_AUTHORITY \
  --request /home/nl/wg/request.json --output /home/nl/wg/binding.json

nestlink-daemon wireguard show \
  --state-dir /home/nl/.nestlink --space SPACE_ID --authority SPACE_AUTHORITY \
  --binding BINDING_ID
```

`SPACE_AUTHORITY`、绑定摘要和原业务摘要采用 URL-safe、不带 padding 的 32 字节 base64；标准 WireGuard 公钥采用通常带 padding 的 base64。`show` 给出当前策略版本、客户端修订、门户启动代次、两份独立摘要、已承诺额度、总额度和截止时间。读取或创建凭证不等于批准本机建立接口或处理原业务。

## 分别保存客户端和门户密钥

可以在标准客户端软件中生成独立客户端密钥并只提供其公钥。需要本地配置/二维码导出时，也可以让普通用户使用成熟工具生成密钥到新建的私有文件；输出父目录必须已经属于该用户且权限为 `0700`。

```sh
nestlink-daemon wireguard generate-key \
  --private-key /home/nl/wg/client.key --public-key /home/nl/wg/client.pub
```

管理员为门户另外生成一个稳定的 root-private 密钥。此密钥与客户端密钥、门户安装的 Ed25519 身份均独立。生成和应用都不打印私钥。每个门户密钥文件应保存在原安装的受保护管理员目录中，并随安装备份政策管理。

```sh
sudo nestlink-daemon network-subnet-system init-journal \
  --journal-dir /var/lib/nestlink/wg-owner

sudo nestlink-daemon network-subnet-system generate-wireguard-server-key \
  --private-key /var/lib/nestlink/wg-owner/server.key \
  --public-key /var/lib/nestlink/wg-owner/server.pub
```

已有文件不会被覆盖。管理员需要预先创建上述目录的父目录。`server.pub` 是公开资料；发布这个公钥不需要公开 `server.key` 所在目录。`server.key` 不进入普通用户计划、恢复日志、诊断包、进程参数或二维码。

## 普通用户和管理员共同批准入口

下例中，原物理接口名为 `eth0`、索引为 `2`；主机原地址为 `192.168.50.2`；门户命名空间使用额外未占用地址 `192.168.50.10/24`；客户端物理端点为 `198.51.100.20:51821`；同 LAN 下一跳为 `192.168.50.1`。需要按实际部署替换这些示例值和所有大写占位符。门户额外地址不能是主机已经占用的地址。

先在管理员会话中批准已有业务、映射、绑定和固定物理暴露。`--wait-seconds 60` 允许管理员先批准这些固定参数，再等待普通用户创建新计划，从而不消耗短期捕获租约在人工切换窗口上的时间。

```sh
sudo nestlink-daemon network-subnet-system apply \
  --plan /home/nl/wg/portal.json --wait-seconds 60 \
  --journal-dir /var/lib/nestlink/wg-owner \
  --authority SPACE_AUTHORITY \
  --approve-access-digest ORIGINAL_BUSINESS_DIGEST \
  --approve-mapping-digest CLIENT_MAPPING_DIGEST \
  --lan-interface 2 --lan-gateway 192.168.50.10 \
  --approve-wireguard-binding-digest BINDING_DIGEST \
  --wireguard-client-endpoint 198.51.100.20:51821 \
  --wireguard-listen-port 51820 \
  --wireguard-underlay-next-hop 192.168.50.1 \
  --wireguard-server-private-key /var/lib/nestlink/wg-owner/server.key
```

然后在拥有原登录会话的普通用户会话中启动入口。原包承载的 `--bind`/`--dial` 是目标原安装的物理承载路径；WireGuard 客户端端点另由 `--client-endpoint` 指定。管理员和普通进程必须使用同一个可执行文件 inode。计划目录和管理员日志目录必须位于同一文件系统，供已记录 inode 的 Unix socket 原子交接使用；计划路径应保持足够短，以容纳原生 Unix socket 名称。

```sh
nestlink-daemon wireguard run-portal \
  --state-dir /home/nl/.nestlink --space SPACE_ID --grant ORIGINAL_ACCESS_ID \
  --authority SPACE_AUTHORITY \
  --approve-access-digest ORIGINAL_BUSINESS_DIGEST \
  --approve-mapping-digest CLIENT_MAPPING_DIGEST \
  --interface 2 --bind 192.168.50.2:0 --dial ORIGINAL_TARGET_PHYSICAL_ENDPOINT \
  --plan /home/nl/wg/portal.json \
  --lan-name eth0 --lan-interface 2 --lan-gateway 192.168.50.10 --lan-prefix-len 24 \
  --binding BINDING_ID --approve-binding-digest BINDING_DIGEST \
  --server-public-key WIREGUARD_SERVER_PUBLIC_KEY \
  --client-endpoint 198.51.100.20:51821 --listen-port 51820 \
  --underlay-next-hop 192.168.50.1
```

客户端与门户额外地址在同 LAN 时，两条命令都省略下一跳。内核地址冲突探测失败、实际接口身份改变、批准摘要不匹配、门户密钥不匹配或原始登录失效都会拒绝应用。管理员 helper 自己不登录源账号，也不能替源账号创建新包预算。

## 导出标准配置和二维码

导出操作重新获取并验证当前绑定，验证私钥派生的客户端公钥和两份明确批准的摘要。导出的 `AllowedIPs` 只含原业务目标前缀；不会添加默认路由、DNS 设置或任意执行 hook，也不能捕获物理端点或客户端源地址。`Endpoint` 是标准客户端实际能够访问的门户 UDP 地址；若通过 NAT 暴露，需要由部署方把这个端点精确转发到上面的额外门户地址和端口。

```sh
nestlink-daemon wireguard export-config \
  --state-dir /home/nl/.nestlink --space SPACE_ID --authority SPACE_AUTHORITY \
  --binding BINDING_ID --private-key /home/nl/wg/client.key \
  --server-public-key WIREGUARD_SERVER_PUBLIC_KEY --endpoint PORTAL_PUBLIC_ENDPOINT \
  --approve-binding-digest BINDING_DIGEST \
  --approve-access-digest ORIGINAL_BUSINESS_DIGEST \
  --approve-private-key-export \
  --output /home/nl/wg/client.conf --qr-svg /home/nl/wg/client-qr.svg
```

配置和二维码都含客户端私钥。它们只写入明确选择的新私有文件，并要求显式 `--approve-private-key-export`；不会输出到终端。二维码由发行版 `qrencode` CLI 生成，输入走有界私有 stdin。导入标准客户端后仍受原方向/端口/地址/额度/到期和在线观察约束。

## 撤销、轮换和恢复

撤销使用源账号的当前绑定视图提供的策略和客户端修订。

```sh
nestlink-daemon wireguard revoke \
  --state-dir /home/nl/.nestlink --space SPACE_ID --authority SPACE_AUTHORITY \
  --binding BINDING_ID --expected-revision POLICY_REVISION \
  --expected-client-revision CLIENT_REVISION
```

轮换需要新的独立客户端密钥、新的不冲突 `/32` 及对应映射、目标账号新批准的原业务，并在 `issue` 请求中保留稳定客户端 ID、提供上一客户端修订。成功轮换会原子关闭旧绑定和旧原业务的 access/connectivity/path；旧 key 和地址在旧凭证有限期限前保留，防止未知故障 helper 与新入口重叠。累计已承诺额度不会因轮换、崩溃、未启动或数据库重开而返还，也不能通过重新发行绑定提高总额度。

普通 owner 每秒刷新原授权，并在刷新成功后响应 root 发出的单调时钟挑战。响应不能延长挑战原截止时间；进程暂停后排队的旧响应不能续期。五秒观察缺口、原登录变化、维护请求、绑定/门户启动失效或授权刷新失败都会终止该 owner。固定签名期限和可续租同启动门户租约分别约束生命周期，续租不延长签名绑定也不补充字节。

普通关闭会停止原包 owner、关闭 carrier 和管道，删除精确原计划，并等待原命名空间实际消失。root helper 丢失后，其匿名控制管道关闭使 worker 结束；原 TUN 的文件描述符关闭会删除 TUN，默认拒绝的命名空间不能绕过原包 owner。管理员恢复再删除持有原 inode 的命名空间，连同其中的 WireGuard peer、路由、nft 状态和 conntrack。恢复不刷新共享 conntrack，也不修改另一个 VPN。

```sh
sudo nestlink-daemon network-subnet-system inspect \
  --journal-dir /var/lib/nestlink/wg-owner
sudo nestlink-daemon network-subnet-system recover \
  --journal-dir /var/lib/nestlink/wg-owner
```

恢复会保留仍属于原活进程、已被替换的命名空间、不同 inode 的 socket 或其他无法确认身份的资源，并返回明确错误。升级/卸载先通过原维护流程停止普通 owner 和 helper，再逐个处理该安装保存的管理员日志；必须获得实际资源不存在的读回后才能宣告清理完成。恢复不会删除稳定门户私钥；密钥保留/销毁由显式安装备份和卸载策略决定。

## 验证范围

真实 HTTP/SQLite SDK 测试覆盖源账号/目标账号/管理员权限边界、精确安装/地址/门户启动、原一次性 start、双向原包拒绝、撤销、轮换、累计额度和数据库重开。`wireguard-native.yml` 保留源码 SHA、可执行文件摘要、锁文件摘要、内核、发行版包版本和 copyright，以及实际测试命令和退出结果。工具实验使用真正的 `wg genkey/pubkey` 和 `qrencode`，内核实验使用隔离命名空间中的标准 WireGuard peer、真实 TCP/UDP、原加密包承载、错误 key/源地址/端口和原 helper 崩溃后的恢复。

只有对应精确源码的成功 receipt 才能作为通过证据。上述 Linux hosted 机制不能代替 Android/iOS 标准客户端设备、物理 NAT/防火墙暴露、实际安装升级卸载和跨机部署验收。

源码 `794d3d1f45258d182a9baffd05526316b586a18d` 的 [Actions 41207005912](https://github.com/ZHanry/NestLink/actions/runs/41207005912) 已通过三项 CLI/成熟工具用例和完整的实际内核场景，包含正常关闭与原 helper SIGKILL 后恢复。[精确源码证据](evidence/wireguard-kernel-794d3d1.json) 保存下载制品摘要、执行文件和日志摘要及范围限制。实验使用 1500 字节物理链路承载 1280 字节 WireGuard 内层包和封装开销；实际部署同样需要为外层开销预留 MTU，当前默认拒绝规则不会靠外层 IP 分片绕过这个要求。
