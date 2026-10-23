# 固定产物交接与验收

当前客户端范围为 Windows 桌面和 Web；Linux x64/ARM64 提供内网穿透、信令及中继等后端服务。平台来源以 [`config/product-scope.json`](../../config/product-scope.json) 为准。0.7.0 RC 的实际构建与发布规则见 [候选构建](CANDIDATE-BUILD.md) 和 [整改验收](REMEDIATION-ACCEPTANCE.md)。所有发行构建在 GitHub Actions 完成。

`refactor-release-handoff.py` 保留完整的固定字节、来源与历史材料交接校验。其旧仓库身份和保存对象用于历史托管，不代表 Android 仍是产品客户端。2026-10-23 之前的平台结果与交接说明保存在 [历史记录](history-audit/before-windows-web-2026-10-23-RELEASE-HANDOFF.md)。

当前清单必须包含 Windows 两种安装器、Linux 两架构服务端包、Web、两架构 OCI、源码、SBOM、许可证、构建材料、验收材料和 native payload/package 清单。Android APK、Linux 桌面不再是必需或允许的当前交付角色。历史归档保持独立，不能混入当前源码产物或覆盖原始证据。

填写 `config/release-handoff.template.json` 时，所有实际产物都要有固定源码、长度、SHA-256 与证据引用。验收包括 Windows 10/11、Windows 权限代理、Linux 两架构后端安装、当前三浏览器、公司/手机到家、长稳、TURN 容量及撤销、安装升级回滚卸载、重装身份、schema 迁移中断恢复和来源许可。缺失身份或 pending 项目不能变成成功结果。

保留历史正式 signed gate 的 72 小时要求；当前 RC 的候选平台清单保留 90 分钟检查，整改报告另有 24 小时跨日验收。这些范围分别如实记录。旧 SDK、模拟器或 mock 测试只说明当时的代码行为，不替代本次真实直连、桌面画面和键鼠结果。核验工具不重建、不重新签名、不修改或覆盖已有证据。
