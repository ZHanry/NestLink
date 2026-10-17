# 加密备份与离线恢复

`nestlink-server backup` 通过 SQLite 在线 backup API 取得一致性快照，不直接复制仍在写入的数据库文件。每次最多复制 64 页，快照最多 64 MiB，总预算 10 秒；持续写入导致反复重启或超过预算时失败。配置、部署 ID、vault 密钥、许可签发种子与数据库一起加密。数据库和密钥的明文临时副本只保存在进程内存中；第一方秘密缓冲区退出时清零，Argon2 启用 zeroize。

```text
nestlink-server backup --config /var/lib/nestlink-v15/server.toml --output /private-backups/deployment.nlbackup --password-file /private-backups/backup-password
nestlink-server restore --input /private-backups/deployment.nlbackup --directory /var/lib/nestlink-v15-restored --expected-deployment <部署 UUID> --password-file /private-backups/backup-password
nestlink-server check --config /var/lib/nestlink-v15-restored/server.toml
```

密码通过私密文件读取，长度为 12–1024 字节，忽略末尾 CR/LF；不会写入命令行或日志。归档文件拒绝覆盖。Linux 文件需属当前运行用户、权限 0600；Windows 安装密钥经当前用户 DPAPI 解密后放入加密归档，恢复时由目标机器当前用户重新进行 DPAPI 保护。因此归档可跨机器恢复，无需复制 Windows 原 DPAPI 密文。

恢复要求目录不存在、父目录可信且不允许非受信用户修改。它创建私密目录：Linux 0700，Windows 在创建时指定禁止继承外部权限的 DACL，仅对象所有者和 SYSTEM 可访问，子文件继承。归档里的路径不参与文件系统操作：配置中的状态路径统一重建为 `control.sqlite3`、`vault.key`、`permit.key`，最后写入 `server.toml`。中途失败留下的目录不会覆盖或自动启动；排查后使用另一个新目录重试。

恢复保留部署 ID、许可签发公钥、账号与设备记录，生成新随机安全代次，撤销所有管理登录、设备凭据、远控请求、会话与租约，消费所有登记挑战，清除旧信令、幂等记录和全部恢复码，取消未完成的 TOTP 登记。已启用 TOTP 保留，但烧掉恢复时当前接受窗口，避免回滚最近消费记录；下一可用验证码通常需要等待最多约一分钟。管理员重新登录后生成新恢复码。已批准的业务不能靠恢复快照复活。旧部署与其磁盘文件不会被恢复命令修改。

命令不启动监听。切换前检查管理 origin、监听地址、Caddy 和服务用户；不能让两个相同部署 ID 的控制中心同时作为生产权威。加密备份不能替代旧系统留存、异地保全、密码托管和实际恢复演练。

## 归档格式 1

多字节整数为大端，无压缩，严禁追加数据。64 字节头全部参与 AEAD 认证：

| 偏移 | 长度 | 内容 |
| --- | --- | --- |
| 0 | 8 | ASCII `NL15BA01` |
| 8 | 4 | Argon2id 内存 65536 KiB |
| 12 | 4 | 迭代 3 |
| 16 | 4 | 并行度 1 |
| 20 | 16 | 独立随机 salt |
| 36 | 24 | 独立随机 XChaCha20 nonce |
| 60 | 4 | 密文与 16 字节认证 tag 的总长度 |
| 64 | 可变 | XChaCha20-Poly1305 密文与 tag |

KDF 为 Argon2id v19，输出 32 字节。未知格式、不同 KDF 参数、异常长度和截断在 KDF 前拒绝；解密认证成功前不解析 SQLite。明文依次为：36 字节部署 UUID、32 字节 vault key、32 字节 permit seed、4 字节配置长度、UTF-8 TOML 配置（最多 16 KiB）、8 字节数据库长度、一致性 SQLite image（最多 64 MiB）。恢复另校验数据库 application ID、schema version、部署 ID、quick_check 和外键。

当前验证包括真实 WAL 中已提交/未提交事务、错误密码/头部与密文篡改、截断与 KDF 预算、旧登录/租约/恢复码失效、Windows 重新保护密钥、拒绝已有目录，以及服务端可执行文件的 backup→restore→check。完整安装、跨架构固定产物和生产切换验收仍待执行。
