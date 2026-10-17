# Cargo 发行许可证收集审查（2026-10-16）

> **历史快照：** 本文件记录先前 Cargo 锁定图的 768 包收集；当时结果不完整，缺少三项 MIT 原文。它不代表当前工作树的锁文件状态。当前 `Cargo.lock` 的重新收集结果为 766 包、缺少项为 0，详见[当前 Cargo NOTICE 收集](cargo-notice-current-2026-10-16.md)。旧材料、错误和补充核查仍保留作审计历史。

发行 producer 现调用 `scripts/refactor-cargo-notices.py`，从完整的 `cargo metadata --all-features --locked` 清单和精确 Cargo.lock 收集原文。本次清单为 768 包，其中 730 个 crates.io 归档、36 个第一方 workspace 包、两个本地 WebRTC fork；没有把工作站上未锁定的缓存文件作为来源。

每个 registry 归档先核对 Cargo.lock 的 SHA-256，再直接读取 tar 内文件。原始 LICENSE、COPYING、NOTICE、COPYRIGHT、PATENTS、AUTHORS 和 LICENSES 目录保留原字节；逐文件长度与摘要进入索引。另保留原始 Cargo.toml、Cargo.toml.orig 和已有的 `.cargo_vcs_info.json`，并将归档 manifest 的名称、版本、许可、作者、仓库逐项与 Cargo metadata 对比。作者字段是上游声明，不自动变成版权人。拒绝路径越界、链接、重复成员、异常尺寸、未审阅 registry/Git 源及元数据缺包。

第一方包关联根 LICENSE；两个本地 fork 保留完整上游许可证和 UPSTREAM.md。缺少常规命名文件时，只有 [精确版本补充表](cargo-notice-supplements.json)中按名称、版本、归档摘要、原文摘要和固定上游提交登记的补充材料可以加入。普通 SPDX 字符串或 README 中的许可证名称不会自动替代完整原文。

本轮补充表包含 103 个包的逐项记录。原始 79 个包使用其归档嵌入的精确 Git 提交原文，另有 crc-catalog 的 LICENSES 和两版 r-efi AUTHORS 内完整 MIT 条款。后续补充明确区分以下依据：

- objc2 家族保留精确版本的许可说明和已核验祖先中的原始 Steven Sheldon MIT 文件。`objc2-foundation 0.2.2` 使用其精确提交的完整 MIT；其他版本保留上游删除 LICENSE.txt、改为许可说明及后续贡献规则的变更记录。Apple SDK 派生说明继续保留，收集完成不代表已批准 Apple 平台发行。
- 五个 Leptos 包的嵌入提交返回 HTTP 422，原错误保留。按锁定包内 MIT、Greg Johnston、同一 monorepo 的原始声明，附上可访问发行版本族提交的完整 Copyright 2022 Greg Johnston MIT 原文。十个可访问选定提交的原文一致；源码比对中的差异也保留，没有声称不可访问提交已验证或替换成另一份源码。
- 两个 winapi GNU 导入库在上游补入许可证的提交中分别有 1,388、1,417 个实际库文件与锁定包逐项一致，使用该提交的完整 MIT/Apache 原文。更早使用 0.3.9 对比产生的不一致结果保留，未计入成功证据。
- cesu8 的全部 Rust 源码、manifest、README 和 COPYRIGHT-RUST 与其 1.1.0 发布提交一致，原头部明确授权 Apache-2.0/MIT；选择 Apache 选项，附上 Rust 原始标准全文并保留 Rust/Eric Kidd 归属。drain_filter_polyfill 同样按其原始 manifest 的 Apache 选项保留 Rust 标准条款，作者为空时不补造。
- hexf-parse 0.2.1 的原声明为 CC0-1.0，附上逐字节核验的完整标准法律文本和原始作者/manifest。后来的 hexf LICENSE 实为 0BSD，parse/LICENSE 实为链接，均未当成该旧版的 CC0 原文。首次候选标准文本 URL 的 HTTP 404 也保留，使用实际 tree/blob 核验的 LICENSE-CC0。

仍有三项原始 MIT 版权/许可文件缺失：`convert_case_extras 0.2.0`、`dispatch 0.2.0`、`erased 0.1.2`。精确包及所查上游历史仅声明 MIT，未找到完整原文件；作者和原始声明仍保留，没有填造版权人、年份或许可书。当时的真实收集结果为 **incomplete**，producer 会保留 `evidence/cargo-notice-index.json`，然后失败，不生成成功的 metadata part receipt 或许可证归档。该状态与独立的许可证兼容性审查、G0、正式签名验收分别登记。

全部候选 GET 响应、原文、归档校验、Git blob/tree 对照、失败和更正记录位于 `artifacts/cargo-notice-review-20261016/`。这些是材料来源和工具边界证据，不代表尚未执行的正式 Release。九项收集器测试覆盖原字节、实际归属声明与 metadata 核对、精确补充约束、恶意 tar、缺包/篡改、失败索引保留，以及 LICENSE 仅含 SPDX/链接时继续拒绝。两项真实 producer/collector 集成测试验证最终归档和失败回执边界，并核对旧 Cargo 斜线声明转换为合法 SPDX OR、原始声明仍保留；实际库存共 39 项需要该语法转换。完整 Python 回归两端各收集 114 项，无失败，Windows/Linux 分别跳过 16/1 项；原日志和输入收据保留。

