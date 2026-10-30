# crab_nat 0.8.1 原始许可证核查（2026-10-31）

结论：精确 crate 与嵌入源码提交明确声明 `MIT`，但**没有找到上游完整 LICENSE 文件或版权通知**。本次为该精确归档增加逐项审阅的发行者补充：保留原始声明和作者元数据，另附官方 SPDX MIT 标准模板的完整原字节。标准模板的来源和身份在映射、发行 NOTICE 及本记录中明确披露；没有把它表述为上游文件，没有填入版权年份或将作者字段改称版权人。收集器及缺失门禁保持原样，实际收集结果须由后续同源 Actions 证明。本记录不构成许可证兼容性批准。没有向上游发送消息。

本次检查工作树基线为 NestLink `bd1f298c2babe601087176d1834a1fec2ef52b19`。触发核查的 regression-server run `41122085261`（arm64 job `124290445353`）使用的是较早源码 `0a6e72753f527cf26c7ebf1a423d9ca0f57064b2`；其 `Missing full Cargo license files: crab_nat-0.8.1` 不能写成本次基线的执行结果。

## 精确归档身份

- 官方元数据：<https://crates.io/api/v1/crates/crab_nat/0.8.1>。
- 官方归档：<https://static.crates.io/crates/crab_nat/crab_nat-0.8.1.crate>。
- 归档长度：29,841 字节。
- SHA-256：`b6571f33e3d6520c5b08e54b1202836c6ebe68b950f450951804d037a875c25c`，与根 `Cargo.lock` 及 crates.io 官方版本元数据一致。
- 发布者：`ryco117`；官方元数据的发布时间为 `2026-07-06T02:12:59.755665Z`，`yanked` 为 `false`。
- 归档中 `.cargo_vcs_info.json` 指向 `296cc168bb0805fe64b9378d0cc76a833e903ce0`，`path_in_vcs` 为空。
- 归档的 `Cargo.toml` 和 `Cargo.toml.orig` 均声明 `license = "MIT"`、作者 `Ryan Andersen <ryco117@gmail.com>` 及仓库 <https://github.com/ryco117/crab_nat>。作者字段保留为上游作者声明，不补造版权人或年份。

| 归档内原始文件 | 字节数 | SHA-256 |
| --- | ---: | --- |
| `.cargo_vcs_info.json` | 94 | `b59ce95a92a522e5680660646caf395efd5f465369a57e9fa9982a58e018ff88` |
| `Cargo.toml` | 1,714 | `1600f1e090d1e762598476d436b2724e6621a43dd6be3ca3610aca7c5190f74c` |
| `Cargo.toml.orig` | 833 | `c76f7337df0f1e8ee9b81083f57249295ca9d8ab49253da3f73eb0b86488ddf7` |
| `README.md` | 2,894 | `052160590be19f10fec2117b2551697568f660d2229ffe2603b0ad95d0d9c68f` |

归档完整成员清单仅含 `.cargo_vcs_info.json`、`.gitignore`、`Cargo.lock`、`Cargo.toml`、`Cargo.toml.orig`、`README.md`、`examples/client.rs`、`src/lib.rs`、`src/natpmp/mod.rs`、`src/natpmp/tests.rs`、`src/pcp/mod.rs`、`src/pcp/tests.rs`。没有 LICENSE、COPYING、NOTICE、COPYRIGHT、AUTHORS 或 LICENSES 目录，也没有 README 内的完整授权书。

## 官方源码及可达历史

通过官方仓库只读下载核查 <https://github.com/ryco117/crab_nat.git>，未运行其代码或构建工具。嵌入提交的实际根 tree 为 `74aeeceab9dbdadb19cd3aa5e6dec985c232b58c`：

<https://api.github.com/repos/ryco117/crab_nat/git/trees/296cc168bb0805fe64b9378d0cc76a833e903ce0>

该根目录仅有 `.gitignore`、`Cargo.toml`、`README.md`、`examples`、`src`。归档 `Cargo.toml.orig` 的 Git blob SHA-1 为 `3bade0d6ed50a86285e424b8ef4096171c8cf9e1`，`README.md` 为 `a8b49467944f32f58688bd0288834009d5152790`，均与精确上游 tree 一致。

核查时官方仓库 `main` 仍指向该嵌入提交。全部公开可下载 refs 共可达 62 个提交：

| ref | 提交 |
| --- | --- |
| `refs/heads/main` | `296cc168bb0805fe64b9378d0cc76a833e903ce0` |
| `refs/pull/1/head` | `39568b82f3f9e893789e337f77751c08802083cb` |
| `refs/pull/4/head` | `3cf1a8cdaeff67ff7c0b722e6cec3cbe7f8ccffe` |
| `refs/pull/5/head` | `b7a07261f95c38d25b24fe191eff41fa50ddbbdd` |

对这些 refs 的历史文件名检索没有发现原始许可证文件；对许可、版权和授权语句的历史内容检索仅找到提交 `3e97f1e59b51f5d9c2c84302fcbfcdf469724dcd` 为 `Cargo.toml` 添加 `license = "MIT"`、作者和仓库声明。这一变更没有添加许可证全文。官方 GitHub 仓库 API 的 `license` 为 `null`，`commits?path=LICENSE` 结果为空，核查时无 tags 或 releases 可补充授权材料。

官方只读查询入口：

- <https://api.github.com/repos/ryco117/crab_nat>
- <https://api.github.com/repos/ryco117/crab_nat/commits?path=LICENSE&per_page=100>
- <https://github.com/ryco117/crab_nat/commit/3e97f1e59b51f5d9c2c84302fcbfcdf469724dcd>

上述结果限定为核查时可达的官方材料，不声称检查了不可访问或未公开的历史。未使用其他软件项目的版权授权书替换该包的原始声明。

## 透明的 SPDX 标准全文补充

现有 `scripts/refactor-cargo-notices.py` 的补充机制按包名、版本、归档 SHA-256 和 `license_declared` 绑定；文件来源必须是固定 40 位提交的 raw GitHub URL，且全文摘要、路径与声明均经过检查。该机制不要求标准条款来自依赖自己的仓库。现有 `cesu8`、`drain_filter_polyfill` 和 `hexf-parse` 记录已分别披露原始声明与标准全文的独立来源。本次延续这种逐项透明绑定，不增加自动按 SPDX 填充文本的行为。

官方 SPDX 来源：

- 项目：<https://github.com/spdx/license-list-data>。
- 标准标识：`MIT`，<https://spdx.org/licenses/MIT.html>。
- 固定提交：`279b7e997a87c09be00dd6bdda189519ade502cf`。
- 完整原文：<https://raw.githubusercontent.com/spdx/license-list-data/279b7e997a87c09be00dd6bdda189519ade502cf/text/MIT.txt>。
- GitHub 原始文件元数据：<https://api.github.com/repos/spdx/license-list-data/contents/text/MIT.txt?ref=279b7e997a87c09be00dd6bdda189519ade502cf>。
- Git blob SHA-1：`d817195dad53ec992418c28ffca5fbd1cd86502a`，与下载原文的 Git blob 摘要一致。
- 字节数：1,078。
- SHA-256：`b05785f9f18e6716bab63424b11454513b9943a222595b70411009202fc592b5`。
- 提交路径：`packaging/notices/cargo-upstream/spdx/license-list-data/279b7e997a87c09be00dd6bdda189519ade502cf/text/MIT.txt`。

文件从官方固定来源直接下载、逐字节保留。其 `Copyright (c) <year> <copyright holders>` 是 SPDX 标准原文中的模板行；占位符未替换，不构成对 `crab_nat` 年份、版权人或额外授权事实的主张。原包的 `MIT` 声明是已核验的上游事实，`Ryan Andersen <ryco117@gmail.com>` 仅以原始作者声明保留。两者与标准模板分开记录，不能合称“找到了 crab_nat 上游 LICENSE”。

`packaging/notices/crab_nat-0.8.1-NOTICE.txt` 是 NestLink 发行者撰写的来源说明，明确标记为非上游文件。现有回归镜像和正式发行 producer 会复制 `packaging/notices`；collector 的 Cargo 包目录另收集标准全文，并在 `index.json` 的 `supplement_review_basis` 保留这一绑定说明。原始 archive manifest、可用的 `Cargo.toml.orig` 和 `.cargo_vcs_info.json` 仍由既有 attribution 路径收集。

## 发行处理与验证边界

`cargo-notice-supplements.json` 增加精确名称、版本、归档摘要、嵌入提交及标准原文映射。`full_license_text: true` 仅标记所附文件包含完整 MIT 标准条款；`source_kind: official_standard_license_template`、`review_basis` 和单独 NOTICE 明确其来源，不能解释为已发现上游版权文件。没有改动收集器、许可证兼容列表或缺失检查，历史三个 `unresolved_packages` 条目原样保留。

补充只覆盖此版本及校验和，不接受任意版本或自动套用其他包的 MIT 声明。若上游以后补充实际版权通知，应按其可追溯来源保留，并再次审阅该精确依赖的绑定。标准全文收集完成与许可证兼容性、网络组件安全或发行验收分别判定；后续在 GitHub-hosted Actions 执行完整 NOTICE 收集及适用打包门禁。

本次仅执行源码读取、搜索、官方材料下载、归档成员读取、摘要核对和人工审阅；未执行本地 formatter、lint、构建、测试或 NOTICE 收集器。不能将本记录当作新的 Actions 通过证据。
