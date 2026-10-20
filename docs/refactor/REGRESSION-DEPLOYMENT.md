# 回归服务器构建与部署

构建统一放在 GitHub Actions；现有服务器只接收成品、做备份迁移、启动和健康检查。
不得在现有服务器运行 Cargo、rustc、源码构建容器或 Docker build。

`regression-server.yml` 在 GitHub ARM64 runner 编译并测试服务端，使用固定 Ubuntu
24.04 多架构 index 组装镜像，保存锁定依赖的 notices，并输出 Docker archive 和
`regression-build.json`。清单绑定完整源码 SHA、二进制及归档摘要、镜像 ID、架构、
工作流 run/attempt；构建产物仅用于回归，完整验收仍为 pending。
本流程不发布 Release、不推送镜像到注册表，也不改变正式18角色候选发布门禁。

部署前必须检查目标 SHA 的全部规定质量工作流。Web 使用同一源码 SHA 的
`web-build.yml` 产物 `nestlink-web-dist`，不能混用其他提交的 Web。
下载前核对 GitHub run 的 repository、head SHA、conclusion 和 artifact 身份，
下载后校验清单、archive SHA-256、载入后的镜像 ID/架构/源码 label。
服务器只执行 `docker load` 和精确服务替换。

先备份现有程序、配置、Web、共享网关配置和数据库；用副本验证 schema23 到24的
迁移和新程序启动。保留 deployment ID、账号、设备、批准、撤销记录及密钥。
禁止执行清空数据或重新初始化命令。只更新 NestLink control/STUN 及对应静态资源，
保留共享网关/网络容器和其他站点配置。

正式迁移使用程序内置的认证加密备份和 `--defer-admission`，在解除迁移 fence 前
可用确切 transaction 的 `recover-migration --rollback` 恢复原目录。
新版本业务已经获准运行后，不得重放旧数据库快照进行降级，避免恢复已撤销授权；
该阶段的故障须保留当前 schema24 数据，修复前向兼容的程序。
