# Linux 无图形组网候选制品

W34 的新增 Linux 角色复用现有 `nestlink-daemon`，包括私有服务代理、私有 Web 网关、空间 DNS、host TUN、子网网关、LAN 发现和 WireGuard 命令。Linux 图形桌面客户端仍不在当前产品范围内。

完整候选工作流 `.github/workflows/v15-candidate-build.yml` 在同一源码 SHA 构建 Windows、Web、Linux x64 和 ARM64；每个 Linux 构建现在产生两个独立 DEB：

| 角色 | 包名 | 安装的入口 |
| --- | --- | --- |
| 控制服务 | `nestlink-rc-server` | `/opt/nestlink-rc/server/nestlink-server` |
| 无图形组网及网关 | `nestlink-rc-network` | `/opt/nestlink-rc/network/nestlink-daemon` |

组网 DEB 使用 Ubuntu 24.04 的 glibc、PipeWire、ALSA 和 iproute2；CPU 架构必须匹配。候选清单、原生 payload 清单、包清单、源码、SBOM 和许可证材料同时记录两个 Linux 架构的 `server` 与 `daemon`，任一包或原始可执行文件缺失都会阻止候选冻结及上传。OCI 镜像仍运行控制服务，组网 owner 需要显式宿主机权限及配置。

下载后先核对候选总清单的源码 SHA、包 SHA256 与架构。候选包尚无正式更新签名，不进入生产自动更新渠道；正式签名、安装 owner 和目标环境验收状态保留在候选清单中。安装本身不自动启动 daemon，不设置 capabilities，不安装全局 systemd 网络服务，不写入路由、DNS、TUN 或 WireGuard 配置。管理员明确安装之后，普通用户执行：

```sh
/opt/nestlink-rc/network/nestlink-daemon --help
/opt/nestlink-rc/network/nestlink-daemon network-tun --help
/opt/nestlink-rc/network/nestlink-daemon network-subnet --help
/opt/nestlink-rc/network/nestlink-daemon space-dns --help
/opt/nestlink-rc/network/nestlink-daemon wireguard --help
```

实际运行前需要当前普通用户受保护的 SessionStore、明确的空间/设备授权和对应私有配置目录。TUN、子网和 split DNS 的系统操作由同一安装映像的独立 `*-system` 命令审核和执行显式计划；root 不运行管理登录和业务 owner。系统 owner 的 journal 必须是受保护目录，不能把普通用户可替换的文件声明为受信任 helper。撤销、崩溃、退出和恢复遵循各自 owner 的真实回执。

升级或卸载前先停止实际启动的每个 owner，并完成其恢复/清理。DEB 不替代业务 owner 清理流程；卸载不会代替 TUN/DNS/WireGuard journal 的恢复，也不会删除身份、累计配额、受保护登录和用户数据。现有正式签名 v15 生命周期脚本尚未接收此候选 network 角色，不能将候选包冒充正式签名更新。

`.github/workflows/linux-network-package.yml` 在 GitHub 托管的原生 x64 和 ARM64 runner 上复用同一 DEB 构造器，构建并安装实际 daemon，逐个执行所有组网 CLI 的帮助入口，验证普通用户安装被拒绝、缺登录和 root 业务运行被拒绝、重装字节一致和卸载保留用户数据。日志、实际包、依赖锁和可执行文件摘要绑定执行的源码、workflow、run、attempt 和 runner。候选预检同时要求该矩阵与完整网络工作流在同一 SHA 成功。

该安装矩阵证明实验环境的实际 DEB 操作与入口拒绝行为。真实 TUN、子网、系统 DNS、LAN 和 WireGuard 使用各自独立网络实验及现场验收；签名资格、物理 ARM64、Android/iOS、其他 VPN 共存和中断升级恢复不能从这个矩阵推定通过。

新增 W34 异常场景沿用同一个候选 DEB 构造器和系统 dpkg，不实现另一套安装器。工作流同时构建同源 `nestlink-server`，安装原 server DEB，以普通用户用原 `init/control` 入口验证真实 TCP 端口占用必须明确失败、原占用者仍能传输、部署身份及配置不变。释放原端口后，必须由实际安装的控制服务返回 health，正常停机后端口才能重新绑定。network 包本身不自动启动监听，缺登录拒绝不能代替这项端口冲突验证。

中断升级场景先核对并安装 `c0fc249fc24c4bab389fe10690a2becb1b71257e` 的留存原生 DEB，x64/ARM64 分别固定官方 Actions artifact `13055507795`、`13055977059` 及 ZIP 摘要。当前同源 daemon 的字节不变，由原构造器生成明确标记为 `+hosted.interruption.1` 的故障注入包修订；真实 dpkg 必须确认该版本更高并完成实际 unpack。公开 `dpkg --pre-invoke` hook 仅用于确定配置前的中断点，报告实际 dpkg PID 和进程启动时间，经核对原映像及进程身份后定点 SIGKILL。中断必须留下明确的 unpacked 状态；随后用保留原 DEB 显式降级恢复，核对原版本、所有 payload 文件和目录权限、残留、用户数据，再恢复当前候选并卸载。

上述包修订仅是托管故障实验制品，不属于发行候选或生产更新，不进入更新渠道。它没有调用正式签名安装 owner，不证明正式签名更新、schema 准入后的回滚或 Windows 安装资格。新增场景在对应源码的 x64 和 ARM64 Actions 实际成功、回执及文件摘要完成复核前保持未通过；源码中存在用例不能替代执行证据。

源码 `2cb75d4d7e2a55ba703480fe2933e8fd46c95c74` 的 [Actions 41410131614](https://github.com/ZHanry/NestLink/actions/runs/41410131614) 已实际完成两个原生构建及两架构端口冲突检查：原 server 明确报告端口占用、原监听者保留、配置与身份保持、释放端口后的实际 health 和正常停止/端口重绑均通过。四份 build/package 官方 ZIP 的摘要和字节数一致，两套 package 回执各 37 个文件的摘要、大小和完整清单均已核对，完整证据在 `evidence/linux-package-attempt-2cb75d4.json`。

同一次运行的升级故障检查先完成原包核验、真实较高版本 unpack，但普通协调器错误地尝试读取 root dpkg 的 `/proc/<pid>/exe`，被内核以 `PermissionError` 拒绝；目标 SIGKILL 与显式回滚均未执行，整个 package job 保持失败。后续实现将进程镜像、starttime 和 hook 参数核验与信号操作放在同一个显式 sudo 故障注入器内执行，普通业务 owner 仍不提权。该修复需要新的对应源码 Actions 成功，不能使用先前的端口结果替代中断升级资格。
