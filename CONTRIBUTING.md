# 参与开发 / Contributing

NestLink 的 Rust、Android 和 Web 实现位于同一仓库。默认分支为 `main`，贡献按 [Apache-2.0](LICENSE) 提交。

说明要解决的问题、改动后的行为和实际验证范围。产品版本以 `Cargo.toml` 的 workspace package 为源；第一方依赖、`VERSION`、兼容性和 OpenAPI 元数据应保持一致，协议隔离命名空间独立于公开版本。

使用 Rust 1.96.0。提交前按变更范围运行 `cargo fmt --all -- --check`、相关包测试和 `cargo xtask check`。原生音视频依赖及各平台构建说明见 [编解码器锁定清单](docs/refactor/native-codecs.lock.json)、[Android](apps/android/README.md) 和 [Web](apps/web/README.md)。发布流程见 [RC 构建说明](docs/refactor/CANDIDATE-BUILD.md)。

运行 `python scripts/check-secrets.py`；CI 另外使用 Gitleaks。不要提交凭据、个人部署配置、构建缓存、安装包或设备诊断数据。源码与发布材料分开保存，清理每次检查产生的临时文件。

验收结论须绑定实际源码或固定产物。开发回归不替代真实安装、正式签名、ARM64 真机或跨网测试；未执行的项目保持 pending。

English: submit focused changes against `main`, describe the resulting behavior and actual validation, and retain the declared Apache-2.0 license. Keep public versions consistent, secrets out of source, and acceptance claims limited to the recorded evidence.
