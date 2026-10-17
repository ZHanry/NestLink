NestLink 0.2.0 RC1

本次更新：

- 连接只需服务器地址、账号和密码。移除部署 ID、公钥手动输入、TOTP 与恢复码；通过 HTTPS 自动获取并校验服务器配置。
- Windows 桌面使用 egui + egui_extras 全面调整导航、连接登录、设备与账号列表、明暗主题、字体和键盘交互。
- 5 个上游补丁库迁到独立依赖 fork 分支，主仓库移除 483 个上游文件。Cargo.lock 固定 Git 提交，保留原始许可证与来源核验。
- 升级保留账号密码并清除旧二次验证状态，已有管理登录会失效，请重新登录。

版本：`0.2.0-rc.1`。下载包及 SHA-256 见发行附件与 candidate-build-manifest.json。

候选版沿用现有签名策略：Windows 尚未配置 Authenticode，Android 使用候选开发签名。实际安装、真机及跨网验收状态随发行材料记录。
