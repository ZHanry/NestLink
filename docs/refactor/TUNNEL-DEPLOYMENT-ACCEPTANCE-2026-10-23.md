# 内网穿透部署与公网验收方案（2026-10-23）

**状态：部署及公网产品验收尚未运行；不能据此标记公网穿透或 RC 验收通过。** 本文基于源码
`967ef9173f19e995d9af6a3e5b940dbd7e3abe6e` 核对现有能力，部署时必须重新绑定实际
通过质量检查的完整提交、GitHub run/attempt、产物摘要与运行版本。

用户已确认产品定位为「内网穿透 + 远程桌面」，客户端只保留 Windows 和 Web。
Linux x64/ARM64 是后端部署目标。产品编译、安装包和容器组装全部在 GitHub；HL
及现有服务器只运行已核验成品。本文没有执行任何线上配置、注册、开放端口或发布操作。

## 已确认的缺口

现网只读盘点结果为：`data_nodes=1`、`node_endpoints=0`、
`service_edge_namespaces=0`，没有服务定义/发布；已有节点用于 managed TURN。
现有共享 Caddy 持有 80/443。

服务发布需要具有 edge 角色的运行节点、服务命名空间、主机本地批准及有效短租约。
`node_endpoints=0` 本身不是 TCP/UDP 发布的阻断点：这条路径使用
`ServiceEdgeNamespace.quic_address` 与已注册的节点公钥，不能用向远控 relay
发现表写入 edge 地址来替代服务命名空间。

新增 edge 必须使用独立节点 ID、密钥和私有目录。复用正在运行的 TURN 节点身份
启动第二个 `NodeControl` 会争用同一节点运行期，可能中断现有 TURN。

## 最小拓扑与参数

```text
独立公网访问者（固定一次运行的来源 IP）
  -> 服务器专用 TCP/UDP 高端口
  -> 独立 NestLink edge 节点
  -> 验证节点身份的 QUIC
  -> HL Windows 主机
  -> 本机明确批准的 127.0.0.1 自有验收服务
```

这条服务隧道路径与远控 ICE 直连验收分别记录。服务穿透成功不能替代原
「HL 开启 Clash TUN ↔ 外部 Edge」的画面、键鼠和实际直连路径验收。

| 参数 | 要求 / 建议初值 |
| --- | --- |
| `SOURCE_SHA` | GitHub 质量检查与 Windows/Web/服务端产物一致的完整 40 位提交 |
| 部署 ID | 现有部署的公开 UUID；不重新初始化部署或数据库 |
| 策略签名公钥 | 已信任部署的 node-policy issuer；不是会话 permit issuer |
| 控制 origin | `https://console.tunnel.hap.lat` |
| edge 私有目录 | 新目录，目录 0700、文件 0600，由独立服务账号拥有；持久化节点密钥和 usage ledger |
| 服务后缀 | 例如 `svc.tunnel.hap.lat`；管理域名必须在此后缀之外 |
| QUIC | 示例 `29199/udp`；签名地址必须是实际可达的规范数字 `IP:port` |
| TCP / UDP 入口 | 示例 `29101/tcp`、`29102/udp`；先核对进程监听、Docker 映射、主机及云防火墙冲突 |
| 公网访问者 | 独立 GitHub runner 或受控外网电脑；先核对该次进程的实际出口 IP |
| 来源 ACL | 此次访问者精确 `/32` 或 `/128`；不以 `/0` 代替出口确认 |
| 初始限制 | 2 个并发、65536 B/s、1048576 B 总预算、30 秒空闲期限 |

命名空间的 `public_ports` 必须有序、唯一，范围 1024…65535，排除 28743…29055。
TCP/UDP 仍要求语法有效的服务后缀，但不会执行 HTTP/HTTPS 的 DNS 所有权及 ACME
流程；仅部署原生 TCP/UDP 不要求为示例后缀新增 DNS 记录。

## 最小执行次序

1. 核对确切 GitHub 提交的质量检查及成品。按
   [回归部署说明](REGRESSION-DEPLOYMENT.md) 核验 archive、镜像、架构、二进制和
  源码标签。现网 ARM64 服务器只做下载、摘要验证、`docker load`、成品运行及健康检查。
2. 读取现有全局策略、节点配额、服务 restore fence、活动远控会话与端口占用。
   服务发布要求 `server_forwarding=allow`、`public_ingress=enabled`；保留当前
   `peer_path_mode`。若需修改策略，在没有活动会话时执行，因为策略更新会撤销已有
   permit。不能跳过授权、来源 ACL、配额、使用量记账或恢复栅栏。
3. 在服务器本地用已验证的成品创建全新 edge 身份。命令中的路径、UUID 与公钥是
   实际值；不读取或导出 `node.key` 内容。容器方式需让私有目录持久化并匹配成品运行 UID。

   ```sh
   nestlink-server node-init \
     --directory <NEW_PRIVATE_EDGE_DIRECTORY> \
     --deployment <EXISTING_DEPLOYMENT_UUID> \
     --control-origin https://console.tunnel.hap.lat \
     --trusted-policy-issuer <TRUSTED_PUBLIC_NODE_POLICY_KEY> \
     --roles edge
   ```

4. 使用当前管理员认证向 `POST /api/v3/nodes` 提交上一步输出的公共
   `NodeRegistration`。edge 角色数值为 2；可调低初始化输出的默认连接和速率配额。
   管理凭据只在现有受信任会话中使用，不放入 GitHub 访问者任务或证据文件。
5. 使用管理员 `PUT /api/v3/nodes/<NEW_EDGE_ID>/service-namespace` 配置首个 revision：

   ```json
   {
     "expected_revision": 0,
     "config": {
       "service_suffix": "svc.tunnel.hap.lat",
       "management_hostname": "console.tunnel.hap.lat",
       "public_ports": [29101, 29102],
       "quic_address": "<ACTUAL_PUBLIC_IPV4>:29199"
     }
   }
   ```

   将 API 返回的完整 JSON 视图保存到新节点私有目录，保留 `node_id`、`revision`
   和 `config`，不只保存 `config`。IPv6 地址使用规范 `[地址]:端口`。
6. 只为已检查的入口配置专用映射/防火墙规则，并启动独立受管服务：

   ```sh
   nestlink-server node-edge \
     --config <EDGE_DIRECTORY>/node.toml \
     --namespace <EDGE_DIRECTORY>/service-namespace.json \
     --quic-listen 0.0.0.0:29199 \
     --ingress-ip 0.0.0.0
   ```

   此处省略 `--caddy-config`：现有代码仍运行 TCP/UDP，不绑定 80/443，也不操作共享
   Caddy。同一 ID 不另开 `node-control` 进程。私有目录旁默认的 `service-usage`
   数据须持久化，不随容器删除。
7. 在独立访问者运行中确定出口，再创建带本次 UUID 的两条服务定义：协议分别为
   `{"protocol":"tcp","port":29101}`、`{"protocol":"udp","port":29102}`，
   `host_device_id` 为 HL，`edge_node_id` 为新节点，应用上表 ACL 与限额。
   API 为 `POST /api/v3/services`，载荷形状为 `ServiceCreate { id, definition }`。
   管理 API 只创建定义，不应指定或替主机伪造本地目标批准。
8. 在 HL 启动只绑定 `127.0.0.1` 随机端口的自有 TCP/UDP 验收服务，经 Windows
   产品实际服务发布入口选择准确协议和目标、在本机批准并启动。
   记录实际发布 ID、首个租约序号和公共入口。若本机产品流程尚未完成，该步骤失败，
   不能以直接 SDK 构造同意替代 Windows 产品验收。
9. 从同一独立访问者执行下表的公网检查，持续覆盖实际续租。随后在 HL 停止发布，
   核验主机 worker、QUIC endpoint、edge 入口与后续访问的行为。
10. 清理本次自有服务、目标进程和临时规则，核验其他站点和 TURN 健康。保留尚未 ACK
    的 usage 记录；不恢复旧数据库来清除配额或撤销历史。

## 现有 GitHub 与测试复用情况

下列命令中的 Cargo 编译只可在 GitHub runner 执行。现有机器不新增任何产品构建。

| 现有入口 | 真实覆盖 | 不能证明 |
| --- | --- | --- |
| `rust-core.yml` 的 Windows/Linux `cargo test --workspace --locked --no-fail-fast` | 含 `service_publication` 和启动取消集成；真实管理 HTTP、节点轮询、固定 QUIC、TCP/UDP | 独立公网访问者、现网部署、HL 产品 UI |
| `service_publication` 集成 | TCP FIN 后延迟回复、签名续租、撤销、端口可重绑定；UDP 两访问者隔离、0/1169 字节、1170/60000 字节丢弃、继续可用和停止 | 跨公网链路；测试的所有 socket 均在回环 |
| `refactor-service-caddy-contract.py` | 固定 Caddy 2.11.7 实进程、动态路由、测试 CA 的 TLS、流式/WebSocket/删除 ACK | 产品 QUIC、公网 DNS/ACME、现网共享 Caddy 整合 |
| `service_web_publication` 的 ignored 集成 | 真实公网 DNS/ACME、Caddy → 已批准固定后端、续租/删除确认 | 现有服务器的只访问测试；该 fixture 会在专用机器新建本地管理服务、节点及 Caddy |
| `regression-server.yml` | GitHub ARM64 编译/服务端测试/成品镜像与摘要清单 | 公网隧道、正式 RC 验收 |

本次检索未找到可直接针对**已有部署**运行的外部 TCP/UDP/HTTP visitor 脚本或独立
workflow。不能把 Caddy 本地契约工具或 ignored 公网 fixture 当作现网访问器。

可直接使用的最小工作流调用：

```sh
gh workflow run rust-core.yml --repo ZHanry/NestLink --ref main
gh workflow run regression-server.yml --repo ZHanry/NestLink --ref main
gh run view <RUN_ID> --repo ZHanry/NestLink --json headSha,status,conclusion,url
gh run download <SERVER_RUN_ID> --repo ZHanry/NestLink \
  --name nestlink-regression-server-arm64-<FULL_SOURCE_SHA> \
  --dir <NEW_LOCAL_ARTIFACT_DIRECTORY>
```

发起时 `main` 必须是选定提交；返回 run 的 `headSha` 必须再核对。已自动触发且完成的
同提交 run 可复用，无需重复执行。工作流令牌只需 `contents: read`；发起 dispatch 的
操作者需要仓库 Actions 写权限，读取日志/产物需要对应读权限。这些调用不创建分支或
Release。Web 与 Windows 包按同提交的现有候选流程取得，候选失败不能改成无门禁打包。

需要缩小定位时，GitHub runner 可执行：

```sh
cargo test --locked -p nestlink-sdk --test service_publication \
  actual_http_quic_tcp_publication_retains_half_close_renews_and_physically_stops \
  -- --exact --nocapture
cargo test --locked -p nestlink-sdk --test service_start_cancellation
```

Windows 必须保留 `refactor-windows-normal-user.py` 的普通业务进程 token 包装；
依赖和 native codec 准备复用现有 `rust-core.yml`，不把命令放到 HL 或生产服务器。

## 还需实现的最小独立访问器

此节是待实施接口，不宣称仓库已经存在相应命令。

- 使用 `workflow_dispatch` 的专用 GitHub runner；`contents: read` 即可，不授予
  生产 SSH、管理凭据、设备私钥或部署能力。按部署 ID 串行，`cancel-in-progress=false`，
  执行有明确超时且始终上传脱敏结果。
- 输入仅含确切源码/构建身份、运行 UUID、已核验数字公网 IP、两入口端口、预期响应
  哈希、超时/预算。限制为本次自有端点，不接收任意 URL 或可执行命令。
- 先确认该 runner 的真实访问出口；在其等待窗口内由管理端配置精确 ACL，再显式
  放行开始。下一台 runner 的出口不能沿用上次值。没有明确等待/同步机制前，不发起
  一次无法对应主机发布的探测。
- 使用 Python 标准库的 socket 足够完成数据面，不需要在生产服务器构建测试程序。
  TCP 发送随机 nonce、写半关闭后继续读取并核对完整响应；UDP 记录来源、长度和哈希，
  严格限制接收期限和报文数量。访问者不能替主机批准本地目标。
- 停止前后必须在同一会话/同一运行的证据中分别检查；预先收到的 echo 不算停止后
  回包。使用新 nonce，并结合主机目标计数器确认不再触达。

| 验收项 | 通过证据 |
| --- | --- |
| 公网 TCP | 独立公网访问者请求与 HL 目标的同一 nonce/hash；FIN 后仍收到完整延迟响应 |
| 公网 UDP | 0 字节、最大 1169 字节、多个 visitor 隔离；超限不触达目标，后续合法报文仍通 |
| 续租 | 主机与 edge 的有效签名租约序号前进，期间公网传输不中断 |
| ACL/限额 | 未准入来源没有目标命中；自有配额边界遵循配置，不影响其他服务 |
| 停止/撤销 | 本地 worker 结束、入口/流清理、全新后续探测不触达目标；usage 完成或明确待 ACK |
| 产品路径 | Windows 实际选择/批准/启动/停止；Web 查看相同服务状态和入口 |
| 原环境远控 | 原外部 Edge ↔ HL/TUN 的桌面、键鼠、真实候选路径及稳定性；单独记录 |

## HTTP/HTTPS 的独立后续条件

原生 TCP/UDP 验收不覆盖 HTTP/HTTPS。HTTP/HTTPS 需补齐专用服务域名的精确 A/AAAA
集合与 `_nestlink-service` TXT、可达 ACME、证书持久化和现有共享 Caddy 的专用子树。
应先导出并审查已有 Caddy 配置，再设计保留其他站点的配置合并与回退；不能直接在
占用 80/443 的现网运行 bootstrap 文档中的替换式命令。

已有 ignored 测试只适用于 80/443 独占、DNS/ACME 预置且允许自身公网回流的专用机器。
必需变量及调用见 [SERVICE-WEB-ACCEPTANCE.md](SERVICE-WEB-ACCEPTANCE.md)。如使用
GitHub runner，必须实际满足这些公网入站条件；普通托管 runner 出口可用不等于有
独占公网 80/443。此测试的部署身份、节点、域名和数据库全部自有，不借用生产身份。

## 应保存的证据

保存完整提交、run/attempt、产物哈希、部署版本、运行 UUID、服务/发布/节点 ID、
开始结束时间、来源 ACL、socket/目标计数、传输长度与 SHA-256、有效续租序号、
停止清理及健康检查结果。密钥、认证 token、原始业务数据不写入报告。

区分 `not_run`、`failed`、`passed`；本方案所有尚未执行的公网项目保持 `not_run`。
只有同提交产品经实际公网路径和产品流程全部通过后，才能成为 RC 发布证据。

源码依据：`apps/server/src/main.rs`（node-init/node-edge）、
`apps/server/src/service_edge.rs`（无 Caddy 的 TCP/UDP 路径）、
`crates/protocol/src/service_plane/publication.rs`（namespace）、
`protocol-spec/management.rs`（服务定义与来源 ACL）、
`crates/sdk/src/services.rs`（本机目标批准）、
`crates/sdk/tests/service_publication.rs`、`crates/sdk/tests/service_web_publication.rs`。

## 2026-10-24 工具与产品入口进展

本批已实现 Windows/Web 管理端的公网入口读取与保存，保留管理员授权、节点角色、
显式首次配置和 CAS；保存失败保留草稿，账号/节点切换隔离旧响应。
实际 GitHub 编译与浏览器验证仍以对应 run 为准。

独立访问器现已位于 [scripts/acceptance/tunnel-public](../../scripts/acceptance/tunnel-public/README.md)，
工作流为 `public-tunnel-acceptance.yml`。它按 TCP、UDP 两个全新运行顺序执行，
先由同一服务器 socket 认证回报实际来源并验证端口独占重绑，再经产品路径测量数据、
续租期间的持续流和停止后的新报文。工具不代替主机批准、产品租约或 ACL 证据。
此前“还需实现”的访问器清单作为设计依据保留；运行次序以工具 README 为准。
