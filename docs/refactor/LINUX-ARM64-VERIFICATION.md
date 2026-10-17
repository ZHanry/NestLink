# Linux ARM64 开发验证（2026-10-15）

当前源码的 `nestlink-server` 已以 Rust 1.96.0、Ubuntu 24.04 GCC 13.3 交叉构建为 `aarch64-unknown-linux-gnu` release ELF，并通过 QEMU user mode 执行 13 项真实 CLI 检查。这只覆盖服务端离线命令；桌面/daemon、ARM64 原生硬件、安装包、性能和正式发布验收仍需分别执行。

产物为 `/mnt/d/NestLinkBuilds/linux-arm64-server-20261015/bin/attempt01/nestlink-server`（Windows 对应 `D:/NestLinkBuilds/linux-arm64-server-20261015/bin/attempt01/nestlink-server`），14,574,704 字节，SHA-256 为 `89d584ec82145de68837668956c4b9fa6a06a993dcc783c7ea2f8d468647ce7e`。实际 ELF 为 64 位小端 AArch64，machine 183；独立保全副本保留可执行权限。构建命令、逐文件输入、日志和产物字节分别保存在 `artifacts/core-verification/linux-arm64-server-build-20261015-attempt01.{log,receipt.json}` 与 `linux-arm64-server-ready-20261015-attempt01.json`。

交叉工具从现有可信 APT 元数据列出的 30 个包下载，逐包核对大小/SHA-256 后解包到本用户私有工具目录，没有安装或升级宿主 APT 包。GCC 为 `13.3.0-6ubuntu2~24.04.1`，目标 glibc 2.39。准备证据为 `linux-arm64-cross-tools-20261015-attempt01.json`。QEMU 同样私有解包，版本 `1:8.2.2+ds-0ubuntu1.18`；通过显式 `qemu-aarch64-static -L <guest-library-prefix> <binary>` 执行，不注册 binfmt，也不把宿主 x64 程序标记为 ARM64 结果。其包和可执行文件摘要见 `linux-arm64-qemu-tools-20261015-attempt01.json`。这些工具是开发输入，不是产品分发内容。

| 实际命令场景 | 结果 |
| --- | --- |
| CLI 帮助、新私有部署、配置/私钥/schema 检查 | 3/3 |
| Argon2 管理员初始化、拒绝第二次初始化 | 2/2 |
| 非恢复状态拒绝导出 quota 恢复请求且不创建文件 | 1/1 |
| 一致性加密备份、拒绝覆盖原备份且字节不变 | 2/2 |
| 解密到新私有目录、拒绝覆盖恢复目录 | 2/2 |
| 恢复后配置检查、导出恢复请求、拒绝覆盖请求 | 3/3 |

检查同时核对恢复保留 deployment ID、生成不同 security epoch、设置服务累计 quota fence，以及普通检查/请求导出不会解封。临时密码文件只在独有私有目录内使用，不写入日志；临时部署、密码和备份已回收。结果与命令 receipt 为 `linux-arm64-server-cli-20261015-attempt01.{result.json,log,receipt.json}`；命令 exit 0、选定源码前后不变、自有 scratch 已回收。

另一个隔离批次使用 Python cryptography 41.0.7 的独立 Ed25519 签名实现，通过 16 项真实 AArch64 CLI 调用。Python 对导出请求的紧凑 JSON 摘要先与 Rust CLI 的实际输出比对，再签署原签名域和 claims 字节；控制程序没有为自己生成证明。有效证明向 account/device/node/resource 四类各导入 97 字节的合成累计债务：四个 UUID 均不存在于恢复快照，实际 SQLite 重开检查确认 spent 为 97、可用限额为 0。该批另验证错误签名、其他签名域、旧恢复代次、不平衡四类总额、不完整账本声明、过期证明及恢复目录内自供公钥均拒绝；失败后 fence/账本不变，也不保留伪接受证明。成功只提交一次并保留原签名证据，重放与再导出请求拒绝，再次恢复后旧证明仍拒绝。证据为 `linux-arm64-external-quota-20261015-attempt01.{result.json,log,receipt.json}`，实际进程退出和私有夹具回收均通过。这 16 项是独立开发批次，包含其自身的准备命令，不表示额外 16 个完整产品验收场景，也不代表生产独立累计账本已经配置。

二进制构建 receipt 的 `arm64_execution_verified=false` 表示该步骤只构建、不执行；后续 QEMU 的实际执行单独记录。二者均不证明 ARM64 真机、真实 GNOME/KDE、系统音频/门户、已安装 DEB/OCI、外部网络或固定签名产物验收通过。

桌面与 daemon 的原生 ARM64 集中验证工具已准备于
`artifacts/linux-arm64-client-followup-20261015/`。只读审计确认现有 30 个 APT
归档、2260 个解包文件/链接、GCC/ar wrapper、QEMU 和既有 probe 的字节匹配；
本机仍缺 Linux ARM64 codec 与 ARM64 PipeWire sysroot，不具备客户端交叉构建
条件。正式工作流已有 `ubuntu-24.04-arm` 原生 runner，不改变供应库的 host/target
政策。工具会拒绝 x64 宿主，并在真正 ARM64 普通用户环境校验离线供应库，
一次执行两客户端 focused strict、release 构建及 15 项有界 CLI 检查，保留
machine 183 ELF 与 source/log/scratch 回执。当前仅完成工具准备、语法和拒绝路径
检查，尚未执行客户端构建、运行或安装验收，详见该目录 README 和 FROZEN.json。
