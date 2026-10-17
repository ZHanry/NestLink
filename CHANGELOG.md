# 更新记录 / Changelog

## 0.2.0-rc.1

- 移除连接页面的部署 ID、策略签发公钥和所有端的 TOTP／恢复码功能。通过 HTTPS 自动获取服务器配置，并继续校验服务器和会话签名。
- Windows 使用 egui + egui_extras 重做侧栏导航、工作台工具栏、连接与登录表单、设备／账号表格、字体、图标和明暗主题；支持回车提交与键盘焦点。
- 5 个上游库改为普通版本依赖，并通过 `[patch.crates-io]` 指向独立 fork 分支。Cargo.lock 固定提交，主仓库删除 483 个上游文件，发行许可证继续核对原始来源与全部文件摘要。
- 数据库升级保留账号和密码，清除旧二次验证状态并撤销旧管理登录；需重新登录。
- 同步 Rust、Android、Web 与安装包版本为 `0.2.0-rc.1`。

这是候选预览版；平台签名和实际安装／跨网验收状态见发行材料。

## 0.1.0-rc.1

新仓库首次 RC 发布，从当前 Rust 工作区、Android 与 Web 实现建立独立 Git 历史。

- Windows、Linux 桌面，独立控制/节点服务，Android 11–16 和浏览器客户端。
- 设备身份、显式远控批准、密码与受信设备授权、会话撤销、文件与剪贴板、音视频及服务发布。
- Windows x64、Linux x64/ARM64、Android ARM64/x86_64、Web 静态站点和双架构 OCI 的固定构建材料。
- 本版本为预览版。Android 使用独立开发应用 ID；固定签名、真实安装、ARM64 真机及跨网完整验收仍为 pending。

下载与每项产物的 SHA-256 见 [GitHub Release](https://github.com/ZHanry/NestLink/releases/tag/v0.1.0-rc.1)。本仓库不迁入旧仓库的版本标签和下载记录。
