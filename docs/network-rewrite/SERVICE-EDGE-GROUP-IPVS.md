# 多 edge 服务与固定 IPVS 入口

本文对应 W26、F16/F17 和 AC43/AC44。当前提供 service-specific 首批生产入口和
GitHub-hosted L2 验收候选；必须以当前源码的 Actions 结果及目标环境证据判定通过。
配置导出、节点就绪、实验程序编译成功均不代表公网 HA 已完成验收。

## 选择原目标和每个接收 edge

先通过现有服务管理入口创建服务，选择已登记的主机安装、公网协议和来源 ACL。
管理员为每个 edge 登记原 `ServiceEdgeNamespace`，保存每个准确 revision、QUIC
地址、服务域名后缀及端口。组成员必须包含服务定义原先选择的主 edge，且按
node UUID 排序；同一组为 2–4 个成员，每个 ingress IP 唯一。

主机上使用普通安装原有登录和设备身份，创建受操作系统私有文件规则保护的
`ServiceEdgeGroupUpdate` JSON。`expected_revision` 首次为 0；
`expected_service_revision` 是当前服务 revision 加一，因为命令会先明确批准
新目标，再配置组。每个 member 的 `limits` 是原配额的一部分，连接数、速率和
累计字节三项的总和都不得超过原定义，空闲超时保持原值。不要向两个 edge
分别配置完整原预算。

```text
nestlink-daemon service-group --state-dir <原安装状态目录> --service <服务UUID> \
  --protocol tcp --target <固定本机数字IP:端口> \
  --allocation <绝对路径私有组分配JSON> --approval-seconds 600 \
  --approve-target-and-group
```

HTTP/UDP 选择相应 `--protocol`。HTTPS 还须显式指定固定后端的
`--backend-server-name` 与 1–8 个 `--backend-ca <私有DER文件>`；每个 CA 至多
16 KiB。后端 TLS 名称和信任根属于本机目标选择，不由管理响应或访客指定。

命令恢复原 SessionStore、持有原无图形安装 runtime lease，验证服务属于该主机，
并消耗不可从 JSON 反序列化的原目标及完整组选择。退出信号、原登录变化、
维护或原批准期限到达会停止同一个 owner 并等待物理回收。输出
`local_attachments` 只表示本地主机与各 edge 的真实连接；仍须验证外部固定入口。
一个 edge 失败不会撤销健康 sibling 的本地目标 owner。

管理契约使用原 `/api/v3/services/<id>/edge-group` 和
`/publication-group` 资源。组更新、发布和撤销都绑定准确 revision 和 allocation
digest。旧单 edge API 不会自动创建组，也不会降级解释新组签名。

## 部署每个 edge 的 Caddy 和健康入口

每个组使用专用 Caddy，80/443 由它原有的 HTTP/TLS 引擎持有。首批模式的本地
`CaddyServiceConfig.edge_group` 选择一个 service-specific group，字段包括准确
group ID、revision、allocation SHA-256、该 member ingress IP、独立配置的证书和
私钥绝对路径。证书与私钥遵循原私有文件规则。此模式不把独立组混入一个已由
其他部署持有的 80/443 实例。

每个 edge 均须持有可信且匹配服务 hostname 的证书链。不要把 HTTP-01 请求随机
分配到另一 edge。默认采用正常 WebPKI 根；专用私有 CA 部署可在 operator 本地
配置 `https_root` 指向一个受保护的绝对 DER 文件，最多 16 KiB，仅补充本地
DNS/readiness HTTPS 信任。它不会关闭 TLS 验证，也不能放入远程组请求。

精确 DNS A/AAAA 集合须等于组 `public_ips`，并设置一条 TXT：

```text
_nestlink-service.<服务hostname>
"nestlink-group-v1:<deploymentUUID>:<groupUUID>:<revision>:<serviceUUID>:<base64url无填充allocationSHA256>"
```

按现有 node-edge 命令运行原 edge，并追加
`--group-health-listen <该member精确ingressIP:独立高端口>`。健康端口不得使用
公网服务端口或控制保留范围。只向 director 开放该端口，管理 Caddy Admin 使用
原私有 Unix socket 或 loopback 入口。

健康 URL 为：

```text
/service-group/<groupUUID>/<revision>/<64位小写十六进制allocationSHA256>
```

返回 200 同时要求当前 node/组签名/原发布仍有效、主机 QUIC 附着存在及原
ingress/Caddy 路由已经就绪。单纯探测 Caddy 的 80/443 是否打开不满足这个条件。
每 edge 的 HTTPS readiness 直连该 member，并保留服务 hostname、SNI 和完整
TLS 校验，避免固定入口把 edge A 的探测转发给 edge B。

## 固定入口和路由

首批部署是独立 Ubuntu IPv4 director，使用成熟 kernel IPVS-NAT 和 keepalived。
选择一个真实可用的固定 VIP，提前配置到 director；两个 edge 的访客返回路由
必须经 director。HTTP/HTTPS/TCP/UDP 都保留真实访客源 IP，继续由原来源 ACL
检查。普通 TCP/UDP 代理会改变来源地址，不适用于这份部署配置。

把准确的 `FixedIngressConfig` 保存为私有 JSON，含 `schema_version:1`、deployment
UUID、原 `ServiceEdgeGroupView`、原批准 definition 及与组成员顺序相同的健康端口。
使用同源 Actions 发行制品导出新的私有目录：

```text
nestlink-server fixed-ingress-bootstrap --config <绝对路径私有JSON> \
  --output-directory <尚不存在的绝对路径目录>
```

导出目录包含 `keepalived.conf`、精确输入快照及边界说明。director 须由运维明确
准备：无其他 keepalived/IPVS owner，VIP 已配置，IPv4 forwarding 为 1，
`net.ipv4.vs.expire_nodest_conn=1`、
`net.ipv4.vs.expire_quiescent_template=1`，IPVS UDP timeout 不超过 5 秒。准备
路由时保留其他 VPN、管理网络和防火墙归属；安装脚本不会自动替运维修改这些设置。

以 director 管理员运行发行包内脚本：

```text
install-frontdoor.sh --dedicated-director <绝对路径导出目录>
```

脚本验证前置和真实 keepalived 配置，拒绝替换其他 owner，再创建准确 group UUID
对应的独立 systemd unit。每个 real server 初始为 down；只有准确健康 URL 返回
200 后才接收新连接。`delay_loop=1`、一次重试和 1 秒连接超时用于候选 30 秒
恢复门槛；真实时间以实际业务验收为准。

停止或撤销组时，先通过原服务 API 撤销准确 revision，等待每 edge 的原物理
清理和 Caddy DELETE 后 404/readback。确认 director 的 group unit 已停止并删除
其 systemd/配置归属文件；不要在共享主机运行 `ipvsadm --clear`。重启旧 edge
不得恢复旧组或获得新的全额预算。证书由 operator 管理，清理路由不会删除它。

## 配额、故障和验收证据

每 member 使用原持久用量账本和独立原 grant，account/device/resource 三类
累计总额一致，node scope 只记录实际 member 用量。续租不会重复预留；另一
member 的失败和新 node runtime 不会释放或重领旧 slice。

合作停止并完成原 drain、最终签名 report/ACK 和 seal 后，未结余额才能变为零。
进程崩溃或失联时，未知 grant 的未结余额须继续保留；等待租约到期、撤销组和
重新登录均不能代替原 seal。不要为了验收回收余额手工改账。已有 TCP、HTTP
升级和 UDP mapping 可能中断，本版本不复制连接状态，不承诺存量会话零中断。

专用 `service-group-ha.yml` 候选在 GitHub-hosted Ubuntu 上创建真实独立 visitor、
director、edge1 和 edge2 namespaces，构建同一 SHA 的原 SDK 验收角色，再使用
实际 Caddy、keepalived 和 kernel IPVS 执行业务。它记录双 real-server 连接计数、
四协议请求、允许及拒绝来源、精确旧健康 revision、HTTPS 错误根/名称、停止
原 edge owner 而 Caddy 仍存活、新连接恢复时间、全入口撤销、原 identity/账本
新 runtime 的旧组拒绝、双 Caddy 路由删除回读及原配额物理结算。另有真实 HTTPS
DoH 的旧组 TXT revision 反例。该合作停止案例不冒充 SIGKILL 案例。

产物保存 source/workflow/run/attempt、Cargo.lock 和可执行文件摘要、工具来源、
实际请求/失败/回收 receipt，以及有界脱敏日志。TLS 私钥、节点身份、原目标选择、
数据库和私有配置只留在临时私有目录并在 owner 退出后删除。全部编译、语法检查、
格式、依赖操作与实验执行遵循 R02，不能在开发电脑先运行。

真实目标验收仍须用已核验的 Actions 制品在实际固定 VIP、公开 DNS、可信证书
和两个独立 edge 上重复四协议业务、活动 edge 失效、来源 ACL、旧 revision/
错误证书、撤销和旧 edge 恢复，并记录路由及账本。L2 模拟 DNS/CA 不提供该
公网/目标证据；director HA、IPv6 VIP 和存量连接复制也没有在首批模式中承诺。
