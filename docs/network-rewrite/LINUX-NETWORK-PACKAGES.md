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
