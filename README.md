# NestLink

自托管远程控制与服务发布。当前版本为 **0.7.0 RC1**（`0.7.0-rc.1`）。本次集中整改登录恢复、后台资源边界、滚轮输入及桌面/Web/Android 任务流程，详见[整改记录](docs/0.7.0-remediation.md)和[更新记录](CHANGELOG.md)。

[English](README.en.md) · [候选发行](https://github.com/ZHanry/NestLink/releases) · [构建说明](docs/refactor/CANDIDATE-BUILD.md) · [实现与检查记录](docs/refactor/IMPLEMENTATION.md)

Rust 共享核心负责设备身份、授权、会话、媒体、文件与服务通道。桌面端使用 egui + egui_extras，Android 使用 Kotlin/JNI，Web 使用 Leptos/WASM。远控与服务发布分别授权、启停；支持本机批准、受信设备和密码授权。

| 平台 | 目标范围 | 交付内容 |
| --- | --- | --- |
| Windows x64 | Windows 10/11 | 桌面安装器、可选权限代理包 |
| Linux x64 / ARM64 | Ubuntu 24.04，X11 / GNOME / KDE | 桌面与服务端 DEB |
| Android ARM64 / x86_64 | Android 11–16，API 30–36 | 两种 ABI 的 APK |
| Web | 当前稳定 Chrome / Edge / Firefox | 管理、浏览器远控和静态站点 |
| Server / OCI | Linux x64 / ARM64 | 服务端与两种架构的容器归档 |

连接只需服务器地址、账号和密码；HTTPS 自动读取并校验服务器配置。TOTP 与恢复码功能已移除，升级会保留账号密码并要求重新登录。

同一账号可以在多台设备及多个浏览器页同时登录，各次登录独立续期，退出只结束当前登录。桌面被控时在右下角显示设备、权限与会话状态，主窗口收进托盘后仍可随时断开。

远控提供画面、输入、多屏、音频、文件和文本剪贴板的逐项授权。服务发布支持 HTTP、HTTPS、TCP 和 UDP，具有来源 ACL、配额及撤销控制。公司连接家里等跨网络场景需同时升级服务器和双方客户端；管理员须启用服务器转发，并为设备及会话允许中继。详见[跨网络连接说明](docs/REMOTE-CONNECTION.md)。部署和配置见[服务端说明](docs/refactor/SERVER.md)。

RC 用于后续实际验收。当前 Windows 包未配置 Authenticode，Android 包使用开发签名及独立的 `com.zhanry.nestlink.candidate` 身份；固定发行签名、ARM64 真机、真实桌面与跨网验收仍待完成。下载时请核对 Release 中的 SHA-256 和固定源码清单；完整验收按用户安排在发布后进行。

构建入口会从同一干净提交生成全部平台、源码、SBOM、许可证和材料包。协议与本地状态中的 `v15` 是内部隔离命名空间，独立于本次公开版本号。第一方源码使用 Apache-2.0；上游组件及原始许可证保留在对应目录和发行材料中。
