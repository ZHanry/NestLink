# OCI 控制端与 Caddy 的参考拓扑

候选镜像内的控制端只监听 loopback，Web 文件位于 `/usr/share/nestlink/web`。Caddy 必须与控制端共享网络命名空间。两个普通桥接容器各自的 `127.0.0.1` 不能互相通信。下面方案适用于 Linux x64/ARM64 Docker Compose；真实公网安装、证书签发和跨网验收仍须按候选材料记录，本文不是已完成验收的声明。

## 固定输入并初始化

从同一 Release 下载对应架构 OCI tar，先核对 Release 清单 SHA256，再执行 `docker load -i <tar>`。将载入后的镜像 ID 写入 `.env` 的 `NESTLINK_IMAGE=sha256:...`，不要使用可漂移的 latest。Caddy 同样使用经过审阅的 `caddy:2@sha256:<对应架构或多架构摘要>`，写入 `CADDY_IMAGE`。设置 `NESTLINK_MANAGEMENT_HOST=console.example.com`，DNS 指向本机。

```sh
install -d -m 700 state web caddy-data caddy-config
sudo chown 65532:65532 state
docker run --rm --user 65532:65532 -v "$PWD/state:/data" "$NESTLINK_IMAGE" \
  init --directory /data/instance --management-origin https://console.example.com
```

将密码放入私密文件（0600、UID 65532 可读），以只读挂载传入；不要放进环境变量或命令行参数。

```sh
docker run --rm --user 65532:65532 -v "$PWD/state:/data" \
  -v "$PWD/admin-password:/run/admin-password:ro" "$NESTLINK_IMAGE" \
  bootstrap --config /data/instance/server.toml --username admin --password-file /run/admin-password
docker run --rm --user 65532:65532 -v "$PWD/state:/data" "$NESTLINK_IMAGE" \
  check --config /data/instance/server.toml
```

Web 必须来自相同镜像字节。使用临时容器复制，完成后删除临时容器：

```sh
container=$(docker create "$NESTLINK_IMAGE")
docker cp "$container:/usr/share/nestlink/web/." ./web/
docker rm "$container"
```

## Compose 与入口

将以下内容保存为 `compose.yaml`，将仓库的 `packaging/caddy/Caddyfile` 保存到同目录。

```yaml
services:
  control:
    image: ${NESTLINK_IMAGE:?Use the verified loaded image ID}
    user: "65532:65532"
    command: [control, --config, /data/instance/server.toml]
    restart: unless-stopped
    volumes:
      - ./state:/data
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
  caddy:
    image: ${CADDY_IMAGE:?Pin a reviewed Caddy digest}
    network_mode: service:control
    depends_on: [control]
    restart: unless-stopped
    environment:
      NESTLINK_MANAGEMENT_HOST: ${NESTLINK_MANAGEMENT_HOST:?Set the public DNS name}
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ./web:/usr/share/nestlink/web:ro
      - ./caddy-data:/data
      - ./caddy-config:/config
    tmpfs:
      - /run/nestlink:mode=0700
```

控制端的 28740 不发布到宿主机。只有 Caddy 的 80/TCP、443/TCP、443/UDP 对外发布。独立节点的 QUIC/TURN 端口另按节点文档配置，不要把它们当作管理 API 入口。Caddy 模板会覆盖转发来源头。

执行 `docker compose config` 核对展开结果，再 `docker compose up -d`。外部访问 HTTPS 登录，核对服务器部署身份，重启后核对同一部署和账号。失败时先检查 `docker compose logs control caddy`、DNS、证书和 state 文件 UID/0600/目录0700；不要用 `chmod 777` 或改成 `0.0.0.0:28740` 规避权限错误。

## 备份、升级与回滚

停止两个服务，再使用同一镜像的 `backup --help` 按 [BACKUP.md](BACKUP.md) 生成加密备份。保留原始备份、镜像 ID、产物 SHA256、配置和平台版本。升级先保存备份，再固定新镜像 ID，并从该镜像重新复制 Web；重建 control 后也重建共享其网络命名空间的 Caddy。保留 TLS 数据卷。

数据库会迁移到新 schema，禁止直接让旧二进制写入已迁移的数据库。回滚时停止服务，使用原镜像和升级前备份恢复到新目录，核对身份、重新登录和授权；恢复会撤销旧管理登录与远控许可。不要覆盖正在使用的 state 目录。
