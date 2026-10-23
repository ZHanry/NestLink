# NestLink

**内网穿透 + 远程桌面。** NestLink 将内网 HTTP、HTTPS、TCP、UDP 服务发布和授权远控放在同一个工作台。客户端只保留 **Windows 桌面端与 Web 端**，产品名和既有 LOGO 保持不变。

[English](README.en.md) · [GitHub 构建说明](docs/refactor/CANDIDATE-BUILD.md) · [整改验收](docs/refactor/REMEDIATION-ACCEPTANCE.md) · [更新记录](CHANGELOG.md)

| 组件 | 目标范围 | 交付内容 |
| --- | --- | --- |
| Windows 桌面 | Windows 10/11 x64 | 桌面安装器、可选权限代理包 |
| Web | 当前稳定 Chrome / Edge / Firefox | 管理工作台、内网服务访问、浏览器远控 |
| Linux 后端 | Ubuntu 24.04 x64 / ARM64 | 服务端 DEB 与 OCI 镜像归档 |

Windows 端登记本机、发布内网服务并提供远程桌面；Web 端用于管理设备、访问获准的服务和发起远控。Rust 共享核心负责设备身份、授权、会话、媒体、文件及通道。远控和内网穿透分别授权、启停，支持本机批准、受信设备和密码授权。

使用服务器地址、账号和密码登录，HTTPS 自动读取并校验服务器配置。同一账号可在多台设备和浏览器页面独立登录、续期和退出。远控使用首次会话批准，画面、键鼠、音频、文件和剪贴板权限在会话中明确展示，宿主可随时停止。

远控优先自动选择物理网卡直连，受网络限制时保留受授权的中继能力；实际路径必须如实显示。HTTP、HTTPS、TCP、UDP 服务发布带来源 ACL、配额和撤销控制。部署见[服务端说明](docs/refactor/SERVER.md)，跨网配置见[连接说明](docs/REMOTE-CONNECTION.md)。

当前正在整改 **0.7.0 RC1**（`0.7.0-rc.1`）。候选构建成功不代表远控、安装或公网验收通过；必须完成绑定同一源码和产物的实际桌面画面、键鼠、直连及报告验收后，才发布 RC。Windows Authenticode、更新和 OCI 签名状态按构建材料如实记录，开发候选不能进入生产更新通道。

全部发行构建和打包在 GitHub Actions 执行，使用者电脑与部署服务器只运行下载并核验过的产物。工作流从同一干净提交生成 Windows、Web、后端、源码、SBOM、许可证与材料包。当前平台范围以 [product-scope.json](config/product-scope.json) 为准；Android 源码、JNI、APK 和 CI 已移除，旧平台记录仅作为历史证据保留。

内部协议与本地状态的 `v15` 是兼容性命名空间，独立于公开版本号。第一方源码采用 Apache-2.0；上游原文许可证保留在对应源码和发行材料中。
