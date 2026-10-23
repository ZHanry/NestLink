# 固定产物与签名生产器

当前 NestLink 产品是 **内网穿透 + 远程桌面**，仅交付 Windows 桌面、Web 与 Linux x64/ARM64 后端。0.7.0 RC 的实际构建入口是 [`v15-candidate-build.yml`](../../.github/workflows/v15-candidate-build.yml)，使用说明见 [候选构建](CANDIDATE-BUILD.md)。所有发行编译、打包都在 GitHub Actions 执行，用户电脑和部署服务器只消费固定产物。

`refactor-release-producer.py` 为候选生产器提供来源、归档、架构和许可证校验，同时保留严格签名生产接口。其正式配置仍绑定历史 v15 发布身份，不能将未配置的正式流程或旧仓库标识冒充本次 RC 成功。此前多平台说明及实际验证结果保存在 [历史记录](history-audit/before-windows-web-2026-10-23-RELEASE-PRODUCER.md)。

当前所有生产清单已删除 Android 与 Linux 桌面角色。Windows 原生 payload 包含 desktop、daemon、可选 privileged；Linux payload 仅为 server。Web、两架构 OCI、源码、SBOM、许可证、固定材料及 signed native manifest 继续完整绑定同一 cohort。原生 supplier 保留 Windows x64 和 Linux x64/ARM64 的来源、架构及特性校验，Android NDK 与 APK 分支已移除。

正式签名策略保留以下必填公开字段，未配置时必须返回 blocked：

| 字段 | 要求 |
| --- | --- |
| update_certificate_sha256 | 独立更新证书 DER SHA-256 |
| windows_certificate_sha256 | 固定 Authenticode 证书 DER SHA-256，与更新身份不同 |
| windows_timestamp_url | 固定 HTTPS RFC3161 时间戳端点 |
| debian_maintainer | 实际维护人 `Name <email>` |
| oci_base | 审阅后的 Ubuntu 24.04 多架构 index digest |

对应 Windows PFX、密码、独立更新证书与私钥只在 GitHub 专用签名环境中提供，不写入源码、日志、GITHUB_ENV 或产物。工具不生成临时发行证书，不把缺少的签名判为通过。Windows 签名仍要求系统信任、固定 signer、Code Signing EKU 和可信时间戳；更新 CMS 与平台签名分别校验。

cohort 固定源码 SHA、版本、递增序号、run ID/attempt、配置摘要、提交时间及状态兼容标识。每个 part 的角色、路径、长度、摘要、架构和证据都重新核验；不能混用提交、CI 执行、配置或产物。OCI 逐层回读实际 server/Web 文件、架构、标签、非 root 用户及系统包；Cargo 与原生来源许可证保留原文，材料缺失时不生成成功收据。

版本中立的校验工具可继续用于历史已安装产品的维护和回滚，但当前新发行的 Linux 包只能是后端服务。Windows/Web 与后端的实际安装、远控画面、键鼠、直连、内网穿透、恢复、撤销和长稳验收完成前，不能发布 0.7.0 RC。完整要求见[整改验收](REMEDIATION-ACCEPTANCE.md)。
