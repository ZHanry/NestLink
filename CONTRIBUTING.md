# 参与开发 / Contributing

NestLink 定位为内网穿透 + 远程桌面。产品客户端仅 Windows 桌面和 Web，Linux x64/ARM64 保留服务端部署。默认分支为 `main`，贡献按 [Apache-2.0](LICENSE) 提交；保留产品名和既有 LOGO。

说明要解决的问题、改动后的行为和实际验证范围。产品版本以 `Cargo.toml` 的 workspace package 为源，第一方依赖、`VERSION`、兼容性和 OpenAPI 元数据保持一致；内部协议命名空间独立于公开版本。

发行构建和打包统一在 GitHub Actions 完成，不在用户电脑或部署服务器编译、生成安装包。Rust 1.96.0 的格式、Clippy、相关包和 workspace 测试、`cargo xtask check`、原生编解码器检查及 Web 检查由 CI 执行。可在本机做源码审查、格式处理和不调用产品编译器的 Python/Node 边界检查。详见[编解码器锁定清单](docs/refactor/native-codecs.lock.json)、[Web](apps/web/README.md) 和 [RC 构建说明](docs/refactor/CANDIDATE-BUILD.md)。

运行 `python scripts/check-secrets.py`，CI 另外使用 Gitleaks。不要提交凭据、个人部署配置、构建缓存、安装包或设备诊断数据。保留源代码与验收证据的准确边界。

验收结论必须绑定实际源码或固定产物。开发回归不替代真实桌面画面、键鼠、直连、内网服务、安装维护和长稳验收；未执行的项目保持 pending。仅在全部适用验收完成后发布 0.7.0 RC。

English: contribute against `main`, describe the resulting behavior and actual validation, and retain the Apache-2.0 license. Windows and Web are the supported clients; Linux provides backend services. Distribution builds and packaging run on GitHub Actions. Keep versions consistent, secrets out of source, and acceptance claims limited to recorded evidence.
