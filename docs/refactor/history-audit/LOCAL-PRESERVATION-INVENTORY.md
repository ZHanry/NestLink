# 旧历史本地保存清单

核验日期：2026-10-13。机器可读结果见 [local-preservation-inventory-2026-10-13.json](local-preservation-inventory-2026-10-13.json)，复现工具为 [refactor-history-inventory.py](../../../scripts/refactor-history-inventory.py)。这是本地保存证据，**不代表历史已导入、允许新产品复用旧源码，或已满足删库前提**。

从 `D:\代码\远程控制\NestLink` 执行：

```powershell
python scripts/refactor-history-inventory.py --integration-root D:\home-tunnel-integration
```

脚本只读旧仓库；设置 `GIT_OPTIONAL_LOCKS=0`、`GIT_NO_LAZY_FETCH=1`、`GIT_NO_REPLACE_OBJECTS=1`、`GIT_TERMINAL_PROMPT=0`。输出只写入当前 NestLink 的 `docs/refactor/history-audit/` 和已忽略的 `artifacts/history-audit/`。脚本不 fetch、不访问云项目、不写原仓库、不改旧 worktree、不导入、不上传、不重写历史。输入内容相同的重复运行覆盖同名结果；refs 或文件变化会产生新的摘要。

## 本地 refs 和对象

范围为四个现存本地克隆的 refs、各自 HEAD 和固定 baseline。Hub 的 `refs/heads/codex/nestlink-v15-core` 仅记录观察值，排除在旧历史对象统计之外；该分支是正在开发的 NestLink。全部 refs 的对象 ID、对象类型、annotated tag 的剥离对象和候选保存名称已写入 JSON。候选名称采用 `refs/tags/legacy/<component>/<原 refs 后缀>`，只是映射建议，没有创建标签。

| 组件 | 旧历史候选 refs | 旧历史可达提交 | 本地 tags / annotated tags | 唯一许可证命名 blob | ≥10 MiB blob |
| --- | ---: | ---: | ---: | ---: | ---: |
| Hub | 37 | 145 | 32 / 14 | 1 | 0 |
| Server | 31 | 206 | 25 / 15 | 1 | 0 |
| Client | 21 | 11,501 | 15 / 10 | 40 | 0 |
| Android | 16 | 138 | 11 / 8 | 1 | 0 |

四个克隆均非 shallow；未发现 partial-clone 配置、alternates 文件、替换 refs、grafts 或缺失的可达 Git 对象。旧 refs 在各仓读取前后未变化。每个可达对象均读取类型和未压缩大小，全部可达 tree 均检查许可证命名项、`.gitmodules` 和 gitlink；未发现 ≥100 MiB blob。此大小结论只针对 Git blob，不包括 Release 附件。所有 ≤1,024 字节的可达 blob 均检查标准 LF 格式的 Git LFS pointer，未发现；没有检查自定义 LFS 存储或下载 LFS 对象。

完整提交 ID 列表、全历史 tree 条目、基线和 ref tip 的完整相对路径等较大证据保存在 `artifacts/history-audit/*-local-objects.json`，其 SHA256 写入主报告。这些忽略文件尚未成为持久归档。`rev-list` 路径仅为每个对象的一个代表路径；全 tree 记录标识父 tree 和条目名，没有声称给出每次历史出现的完整路径。

## 许可证和来源边界

四仓基线顶层 `LICENSE` 是同一 Apache-2.0 文本（SHA256 `06a4d0421042d3d1e428040475b124cde7f4f25c39a68a1898fa66a9c1fbf7cc`）。Client 的基线 `LICENSE-RUSTDESK` 与 `client/LICENCE` 是 AGPL-3.0 文本（SHA256 `8486a10c4393cee1c25392769ddd3b2d6c242d6ec7928e1414efff7dfb2f07ef`）。Android 的 `homedesk-core` 是另一个 Git 仓库边界，不能由 Android 顶层 Apache 文件覆盖。

Client 全历史识别到 AGPL、GPL、Apache、MIT 和 BSD 文本；40 个许可证命名 blob 中仍有 18 个未被简单文本签名识别，已保留对象 ID、文件名和 SHA256，不能将它们当作“无许可限制”。同一历史在 Android core 中再次出现。已检查的 hbb_common 本地仓库没有许可证命名 blob；本工具没有据此推导其授权。源文件内部 notices、依赖传递义务、二进制分发材料及完整许可兼容性仍需单独审查。

历史 `.gitmodules` 中出现的公开来源包括 `rustdesk/hbb_common` 与 `21pages/hbb_common`。报告仅记录文件中声明的来源，未验证远端归属或取得额外授权。沿用 [DISPOSITION.md](DISPOSITION.md)：原提交及原许可证可作为历史保存候选；旧 Firebase 配置、permit 测试向量、信任锚与旧源码都不能据此进入 NestLink 15 产品。此前 181 条 Hub/Client finding 分类没有重做。

## 子模块缺口

额外只读检查了现有 Client hbb_common、Android core、Android hbb_common、hbbs-upstream 及其 hbb_common，共 5 个辅助对象库。`hbbs-upstream` 本身是 **shallow，仅有 1 个可达提交**，不能作为其完整上游历史证明。

在全部已检查的历史 tree 中共有 118 个不同的 gitlink 提交 ID；113 个在这些本地对象库中存在 commit 对象，以下 5 个未找到，均出现在 Client 历史及其 Android core 副本：

| 历史 tree 条目名 | 未找到的 commit ID |
| --- | --- |
| `hbb_common` | `5a78ec42303ca046d808742e911a156636a2432b` |
| `hbb_common` | `93f9445c69f30487f1479a9e4e1882773e00c7f9` |
| `hbb_common` | `b0f50c8d55a015f3d49fe9e90fcefb585d74a25f` |
| `hbb_common` | `f857bbd3bc350c800d447eb0d809d21f101cd80b` |
| `shared-modules` | `cecc93886ce839ec49b0041f072a573327acdf08` |

主报告保留其父 tree ID；完整存在性表见 `artifacts/history-audit/gitlink-local-availability.json`。存在 commit 对象不等于证明来源，也不保证该提交的全部对象闭包；闭包检查仅覆盖本轮 refs/HEAD/baseline 可达对象。没有尝试猜测缺失对象的上游或联网补取。

## 旧附件的实际字节

读取原有 `D:\home-tunnel-integration\final-audit\{hub,server,client,android}.json`，重新对匹配文件名的本地候选文件计算 SHA256 和长度。**12 / 12 条记录均至少找到一份字节与旧记录一致的文件**，匹配路径、长度、摘要已写入主报告。主要文件位于 `downloads/candidate-11/`，Server 另有 `downloads/server-rc2/` 副本。

| 组件 | 旧元数据覆盖版本 | 已匹配附件数 |
| --- | --- | ---: |
| Hub | `v11.0.0-rc.1` | 2 |
| Server | `v11.0.0-rc.2` | 3 |
| Client | `v11.0.0-rc.1` | 4 |
| Android | `v11.0.0-rc.1` | 3 |

这些数字包括每仓的 `SHA256SUMS.txt`。例如 Android materials ZIP 为 1,127,137,868 字节，Client materials ZIP 为 655,691,974 字节；不能放入普通 Git 历史来替代 Release 归档。根下载目录另有 `HomeTunnel-Windows-10.1.0-x64.zip`，已记录其实际摘要，但没有验证它与完整远端发行清单的对应关系。

本轮没有访问 GitHub API、下载新附件或验证远端当前字节。旧 JSON 中的 `published_assets_match_verified_downloads=true` 只作为旧声明保留，没有提升为本轮结论。**以上 12 件不是所有历史 Releases 的完整清单**；其他版本、远端 release/asset ID、当前下载字节和持久归档位置仍未核验。

## 最终操作前仍缺的证据

四仓远端全部 refs / Releases / 附件清单与本地快照的对照尚未完成；隐藏 refs、已删除 refs、reflog-only 和 unreachable 对象均不在完整性声明内。5 个缺失 gitlink、许可来源复核、实际导入后的原提交映射、完整旧附件的持久保存和下载复验也未完成。

2026-10-15 后续已将 `work-14.1.0` 的未提交字节备份到隔离 ZIP：Server 38 个文件、Client 28 个文件，Hub/Android 无未提交文件。机器回执 [dirty-worktree-preservation-2026-10-15.json](dirty-worktree-preservation-2026-10-15.json) 逐文件记录长度和 SHA256；本轮重新核对四个 ZIP 摘要与回执一致，并核对 Server 38/38、Client 28/28 个 ZIP 条目摘要。原 worktree 未被修改；ignored 文件没有复制，仍留在原工作树。该本地备份尚未持久上传，历史导入、完整产品验收、远端改名/删除/发布仍受 [finalization.json](../finalization.json) 前提约束。
