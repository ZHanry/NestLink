# Web 发布验收

本清单将真实 Caddy 进程契约、Rust 自动测试和公网 DNS/ACME 全链路证据分别记录。仅有本地测试 CA 的成功结果不能证明公网证书申请成功。

## Caddy 进程契约

使用上游 Caddy v2.11.7 Windows amd64 或 Linux amd64 二进制，SHA-256 分别为：

```text
windows: 5f93a9bd555f3aac9d33af2756ba14b3519d8cca4ffd55256bdaeab444c9db2a
linux:   678ade3bfc088749c81a681adc603333ee0bb023b6a6cfe3c0f58bef8ff854e9
```

脚本需要 Python 3.11+ 与 `cryptography`；使用已有可信环境安装依赖。为 `--output` 提供尚不存在的目录，失败结果不会覆盖旧成功证据：

```sh
python3 -B scripts/refactor-service-caddy-contract.py \
  --caddy /absolute/path/to/caddy \
  --output /absolute/path/to/new-caddy-contract-run
```

所有真实进程检查通过后，顶层才会写入 `receipt.json`。其中包含二进制哈希、检查器哈希、完整检查列表和子收据哈希。明确记录 `rust_compilation_run=false`、`public_acme_run=false`。输出中的测试证书只用于这次本地 CA，脚本不安装系统根证书；进程退出后删除生成的私钥文件。运行目录与原始日志不作为生产配置发布。

## Rust 集成

父级集成流水线需先完成生产补丁合并和锁文件更新，再执行仓库的 Windows/Linux fmt、严格 Clippy 和定向测试。至少包括：

```sh
cargo test --locked -p nestlink-node service_plane::ingress::web
cargo test --locked -p nestlink-protocol attachment_status_keeps_the_ready_wire_and_rejects_mixed_envelopes
cargo test --locked -p nestlink-server service_edge::caddy
cargo test --locked -p nestlink-sdk --test service_start_cancellation
```

取消集成测试使用真实管理 HTTP、节点轮询、固定 QUIC 身份和实际持有证明，在尚未发送 Ready 时取消启动，要求 5 秒内返回 Interrupted、原客户端 UDP 端口可重新绑定、固定后端从未被连接。它不要求公网 DNS 或 Caddy。

设置 `NESTLINK_CADDY_BINARY` 后，单独运行真实 Rust bootstrap 与 Caddy schema 校验：

```sh
cargo test --locked -p nestlink-server \
  service_edge::caddy::config::tests::actual_caddy_validates_generated_bootstrap \
  -- --ignored --exact --nocapture
```

## 公网 DNS / ACME 全链路

使用专门验收机器和专门域名，80/443 无其他服务。Caddy 需要持久化输出目录权限和绑定 80/443 的权限；管理 HTTP、节点轮询与 QUIC 由测试本身在回环地址上启动。机器必须可以通过配置的每个公网 IP 访问自己，公网 ACME 必须能访问该 Caddy。

预先选择以下 UUID 与域名，在 DNS 中配置它们，然后为测试进程设置环境变量：

| 变量 | 内容 |
| --- | --- |
| `NESTLINK_CADDY_BINARY` | 实际 Caddy 可执行文件绝对路径 |
| `NESTLINK_WEB_DEPLOYMENT_ID` | 专用部署的小写 UUID |
| `NESTLINK_WEB_NODE_ID` | 专用 edge 节点的小写 UUID |
| `NESTLINK_WEB_HTTP_SERVICE_ID` | HTTP 服务的小写 UUID |
| `NESTLINK_WEB_HTTPS_SERVICE_ID` | HTTPS 服务的小写 UUID |
| `NESTLINK_WEB_SERVICE_SUFFIX` | 专用服务域名后缀 |
| `NESTLINK_WEB_MANAGEMENT_HOST` | 后缀之外的管理域名，A/AAAA 指向本 Caddy |
| `NESTLINK_WEB_HTTP_HOST` | 后缀之内的 HTTP 主机名 |
| `NESTLINK_WEB_HTTPS_HOST` | 后缀之内的 HTTPS 主机名 |
| `NESTLINK_WEB_PUBLIC_IPS` | 完整公网 IP 列表，英文逗号分隔 |
| `NESTLINK_WEB_VISITOR_SOURCE_IP` | 本机经公网回流访问 Caddy 时 Caddy 实际看到的来源 IP |
| `NESTLINK_WEB_ARTIFACT_DIRECTORY` | 测试可写的绝对输出目录 |
| `NESTLINK_WEB_DOH_URL` | 可选，默认 `https://dns.google/resolve` |

HTTP 与 HTTPS 主机名分别配置直接 A/AAAA 和准确的 `_nestlink-service` TXT，格式参见部署文档。服务 ID 必须分别对应上表的 HTTP/HTTPS UUID。管理域名也会由真实 Caddy 申请普通公网证书，不能占用其他部署的域名。

```sh
cargo test --locked -p nestlink-sdk --test service_web_publication \
  -- --ignored --exact \
  actual_public_caddy_http_https_retain_fixed_target_and_remove_routes --nocapture
```

该测试显式选择后才运行，缺少环境变量会失败，不会跳过。240 秒内执行真实管理 API → 节点轮询 → 固定 QUIC → Caddy → 已批准固定后端，分别覆盖明文 HTTP 与使用专门受信任本地根证书的 HTTPS 后端。公网 TLS 始终使用普通信任链；本地后端测试 CA 只由该主机的明确 TLS 配置持有。

测试检查请求体和 Host 保留、内部凭据移除、签名续租、停止后的本地任务结束、Caddy 子树实际清空及后续公网请求未触达后端。全部成功后才在唯一 `web-acceptance-<UUID>` 子目录生成 `acceptance-passed.json`。保留日志、运行环境、二进制哈希和该成功收据作为证据；失败或未运行时不得填写通过。

本机跨公网回流仍不能证明公司网络或手机流量访问成功；正式发布还需从所要求的独立外网执行访问、断网、撤销、重连验收，并记录真实客户端平台。Android 支持范围按用户确认收敛为 11–16，Android 10 不在验收范围内。
