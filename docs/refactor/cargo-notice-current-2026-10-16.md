# 当前 Cargo NOTICE 收集（2026-10-16）

针对当前工作树重新运行 `cargo metadata --format-version 1 --all-features --locked` 和 `scripts/refactor-cargo-notices.py`。此次 `Cargo.lock` SHA-256 为 `9a34ff54642f69de251808368609ff4251dfb1b572d4cef617a8d87f572a4bb7`，补充审查表 SHA-256 为 `f99e74017374479c6155bef41833a966455c91a70f42fda1199125ca44b4a2ab`。元数据精确覆盖 766 个锁定包：724 个 crates.io 包、38 个第一方 workspace 包和 4 个已审阅本地上游快照。

收集器从与锁文件校验和匹配的归档、第一方 LICENSE、已审阅本地快照和精确补充表收集原文。结果为 **complete**：1365 个 notice 文件、2176 个原始归属文件、0 个缺失完整许可证包。收集使用 `--locked`，没有改写 Cargo.lock；此结果仅表示完整原文与归属材料已收集，不表示许可证兼容性审查、发行包绑定或正式产品验收通过。

对同一份 `metadata.json` 另运行 cargo-deny 0.18.9 的 `check all`：advisories、bans、licenses、sources 均通过，退出码为 0。保留了 58 条多版本依赖警告；它们是警告，不被误记为检查失败或消失。二进制、advisory 数据库 commit、输入摘要与完整日志摘要记录在 `D:\NestLinkBuilds\cargo-deny-current-20261016-attempt01\receipt.json`，SHA-256 为 `85f6cf0dc8db858461188f1c78757ce8f9e38ab9b1397bd3f20c5c4f6e6f73ca`。这次自动策略检查不代替组织的许可证兼容批准。

当前可复核材料保存在 `D:\NestLinkBuilds\cargo-notice-current-20261016-attempt03\`：

- `metadata.json` SHA-256：`0ea50d5320da02bbb9842acc4a34eb3f045d374843a9e65529d53466cda505ed`
- `index.json` SHA-256：`201151c5a893802556beee1017fb04fa6860399e358fca1d4c85da715d0add86`
- `summary.json` SHA-256：`742476e62c02418d1fce803c1d27aa880c238114cf24041c7d5a8a8e27e26bf7`
- `notices/` 保存逐包原始 NOTICE/许可证/归属文本；`collect.sh` 保存可复跑入口。

当前锁定构建图的非 Cargo 来源核验（8 个 `protoc` 平台二进制和 SQLite 3.50.2）见[非 Cargo 构建输入来源核验](build-input-provenance-2026-10-16.md)。该核验不代表组织级许可证兼容批准、完整非 Cargo 运行时依赖清单、最终发行材料绑定或正式验收通过。

早先许可证审查文件和旧索引仍作为历史证据保留。它们绑定不同的 Cargo 锁定图，因此不再作为当前锁文件的完整性凭据。
