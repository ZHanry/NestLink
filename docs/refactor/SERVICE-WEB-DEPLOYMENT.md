# HTTP/HTTPS 服务发布部署

Web 入口由独立 Caddy 2.11.7 进程终止 HTTP/TLS，再转发到 `node-edge` 持有的随机回环监听地址。固定本地目标由主机本人批准，管理 API、访问者请求和 Caddy 配置都不能替换该目标。HTTP、HTTPS、TCP、UDP 使用同一套短租约、主机持有证明、来源 ACL、配额与撤销链路。

## 运行前准备

管理服务与 `node-edge` 已完成初始化、节点注册和服务命名空间配置。`--namespace` 文件必须是管理员 API `GET /api/v3/nodes/<node-id>/service-namespace` 返回的完整 JSON 视图，包含准确的节点 ID 与 revision。节点配置需要 edge 角色、同一部署 ID 和受信任的控制签名公钥。

为本节点分配独立服务域名后缀，例如 `svc.example.net`。管理域名例如 `control.example.net` 必须在该后缀之外。将管理域名与服务域名的公共 80/TCP、443/TCP 转发到该 Caddy；签名命名空间中的 QUIC 地址和端口转发到 `node-edge`。配置中的 `public_ips` 需要列出本实例使用的全部公网地址，最多 8 个；每个地址都必须能从节点所在网络经公网地址访问到 Caddy。部署在 NAT 后方时需要相应的回流路径。

每个服务主机名都必须有直接 A/AAAA 记录，二者合并后的集合与 `public_ips` 完全一致。不接受 CNAME、TTL=0、重复地址或额外指向别处的地址。还需要且只能有一条 TXT：

```text
_nestlink-service.<服务完整主机名> TXT "nestlink-v1:<部署 UUID>:<节点 UUID>:<服务 UUID>"
```

例如 `photos.svc.example.net` 的证明位于 `_nestlink-service.photos.svc.example.net`，各 UUID 均使用小写规范表示。服务 UUID 在创建服务定义时确定。DNS 通过管理员选择的 HTTPS DoH JSON 端点查询；不跟随重定向或系统代理。默认示例为 `https://dns.google/resolve`。

公网 HTTPS 使用正常受信任的证书、精确 SAN/SNI 和有效期验证。Caddy 的证书存储需要持久化且保持私有；ACME CA、DNS、出口和入站验证端口必须可用。生产路径没有跳过 TLS 验证、测试 CA 或伪造 DNS 的开关。

## 生成专用 Caddy JSON

从 `packaging/caddy/service-linux.example.toml` 或 `service-windows.example.toml` 复制配置到节点私有目录，替换部署 ID、公网 IP 和管理套接字地址。示例中的 `203.0.113.10` 是保留的文档地址，校验会拒绝它。

Linux 使用 Unix 管理套接字时，预先建立 `/run/nestlink-caddy` 私有运行目录，赋予 Caddy 与节点所需的所有权及访问权限，禁止其他账号访问。配置文件权限需要为 0600，私有目录使用 0700。Caddy 与节点可以在同一专用服务账号下运行；绑定公网端口所需权限由部署管理员设置。Windows 使用数值回环管理地址，配置目录限制为运行账号与 SYSTEM；本机管理端口也必须限制在可信本机账号边界之内。

先停止同一监听地址上已有的 Caddy 实例，再生成一个尚不存在的 JSON 路径。命令不会覆盖已有文件：

```sh
nestlink-server caddy-bootstrap \
  --caddy-config /etc/nestlink/edge/caddy-services.toml \
  --namespace /etc/nestlink/edge/service-namespace.json \
  --management-upstream 127.0.0.1:28740 \
  --web-root /usr/share/nestlink/web \
  --output /etc/nestlink/edge/Caddy.services.json
caddy validate --config /etc/nestlink/edge/Caddy.services.json
caddy run --config /etc/nestlink/edge/Caddy.services.json
```

Windows 下使用相同参数名，将目录换为实际安装包内的绝对路径，并通过受管服务启动 Caddy。`--management-upstream` 只接受数值回环地址，`--web-root` 必须是实际存在的绝对 Web 静态资源目录。原有 `packaging/caddy/Caddyfile` 仍适用于单独管理入口；启用此动态入口时，由生成的专用 JSON 统一持有 80/443，避免重复绑定端口。

生成的 JSON 将管理站点、管理 API 和两个服务子树分开。HTTPS 严格核对 Host/SNI；HTTP 服务显式使用明文 80 端口，不被自动重定向成 HTTPS。服务子树之外的未知域名返回 404。

JSON 中的以下 ID 属于该节点控制器，禁止其他工具写入或复制：

```text
nestlink-services-http-<节点 UUID>
nestlink-services-https-<节点 UUID>
nestlink-service-certificates-<节点 UUID>
nestlink-pub-<节点 UUID>-<随机 UUID>
```

节点启动时核验这些专用子树，清理旧节点进程留下的路由与显式证书自动申请域名。未知子树、未知路由 ID 或结构变更会阻止启动，避免错误接管其他应用的入口。

## 启动节点并发布

```sh
nestlink-server node-edge \
  --config /etc/nestlink/edge/node.toml \
  --namespace /etc/nestlink/edge/service-namespace.json \
  --quic-listen 0.0.0.0:29199 \
  --ingress-ip 0.0.0.0 \
  --caddy-config /etc/nestlink/edge/caddy-services.toml
```

`--ingress-ip` 用于原生 TCP/UDP；Web 私有入口始终绑定随机 `127.0.0.1` 端口。没有 `--caddy-config` 时 HTTP/HTTPS 发布失败，TCP/UDP 按原有入口运行。Caddy TOML 的部署 ID 必须与节点配置一致。

创建服务定义时选择完整 HTTP/HTTPS 主机名、来源网络和配额。主机在本地选择一个具体 IP:port，签名批准之后启动发布。HTTPS 本地后端还必须由主机提供明确的服务器名与信任根；公网证书与本地后端证书分别校验。

控制器先校验 DNS，安装只开放随机 readiness 路径的待就绪路由，普通请求暂时返回 503。HTTPS 显式加入专用证书自动申请列表。通过每个配置公网地址的实际 HTTP/TLS 探测后才启用后端转发。最多等待 90 秒，期间仍检查同一短租约并传送签名续租；超时不会延长授权。

每个私有 HTTP 请求都携带随机凭据、真实来源 socket、scheme 与 SNI；节点验证后移除内部凭据与伪造的转发头，再以每个流独立的签名证明访问固定本地目标。请求头限制为 32 KiB、128 项，读取期限 2 秒。上游禁用连接复用，普通请求使用 Connection: close；流式 HTTP 与 WebSocket 仍持续传输。无关路由更新保留已建立的升级连接，最长为 1 小时授权寿命；节点的撤销与过期检查仍立即关闭流。

## 停止与恢复

本地主机停止、短租约失效、节点停止、DNS 所有权或 TLS 探测失败时，先关闭私有监听和现有流，再清理 Caddy。每 5 秒复查公网所有权与可达性；DNS/TLS 请求本身具有独立的短超时。

控制器保留路由所有权，直到确切 ID 的 DELETE 与后续 GET 404 均成功，HTTPS 还要确认专用自动申请域名列表已撤回。Caddy 暂时不可达时持续保留清理任务并重试；节点不会把该清理提前标记为完成。Caddy 配置变更与证书准备按完整生命周期串行，避免相邻路由的 reload 取消正在申请的证书。

SDK 的 `ServiceHostWait::Stopped` 仅证明该主机本地 worker、流任务与 QUIC endpoint 已结束；启动取消的 Interrupted 也只在本地 endpoint 排空后返回。它们不包含远端 Caddy 删除 ACK。确认整个入口已经撤回时，还需要节点控制器完成清理或直接核验专用 Admin 子树为空；公网验收工具会分别检查这两层。

撤回自动申请域名不会删除 Caddy 已缓存的证书文件，也不会向 CA 吊销证书。证书缓存继续受 Caddy 的私有持久化存储管理，失去路由与固定后端授权后不能恢复本地转发。

Linux/Windows 安装包需要分别配置节点与独立 Caddy 进程的服务生命周期。OCI 镜像入口为 `nestlink-server`，Web 字节在 `/usr/share/nestlink/web`；通过明确的 `node-edge` 子命令及配置挂载启动节点，Caddy 是另一个受管进程，管理接口与私有后端需要共享可达的回环/Unix 边界。容器不会自动初始化部署、生成密钥或替换现有配置。

## 验收与证据

先阅读 [SERVICE-WEB-ACCEPTANCE.md](SERVICE-WEB-ACCEPTANCE.md)。`scripts/refactor-service-caddy-contract.py` 可离线验证已核验的 Windows/Linux amd64 Caddy 2.11.7 二进制契约，覆盖动态路由、真实 TLS、流式传输、WebSocket、配置 reload 与删除确认；该检查使用独立本地测试 CA，并明确禁止安装 OS 根证书。它不能替代公网 ACME 或 Rust 全链路验收。
