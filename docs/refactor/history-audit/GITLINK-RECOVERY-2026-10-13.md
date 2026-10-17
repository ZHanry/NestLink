# 历史 gitlink 对象恢复补充

2026-10-17 补充做了公开 GitHub commit search 的精确 SHA 查询；剩余三个 hbb_common 对象均返回 0 个索引结果。证据见 [独立查询记录](gitlink-search-2026-10-17.json)。这不证明其他托管方、私有仓库或未索引存储中不存在这些对象，也没有下载或重写任何对象。

本次针对 [原清单](LOCAL-PRESERVATION-INVENTORY.md) 的 5 个缺失 gitlink，恢复并验证了 **2 个原始对象**；剩余 3 个保留明确的失败证据。原报告、原证据目录和四仓旧 worktree 均未覆盖。机器证据见 [gitlink-recovery-2026-10-13.json](gitlink-recovery-2026-10-13.json)，追加对象库后的全量本地清单见 [local-preservation-inventory-with-recovered-gitlinks-2026-10-13.json](local-preservation-inventory-with-recovered-gitlinks-2026-10-13.json)。

## 原始来源与结果

以下父提交均来自原 Client 历史，并逐项重新验证其中 `160000` gitlink 的完整路径与原 SHA。前四项对应父提交的完整 `.gitmodules` 都声明 `libs/hbb_common` 来自 `https://github.com/rustdesk/hbb_common`。

| 原 gitlink SHA | 包含该 gitlink 的 Client 父提交 | 结果 |
| --- | --- | --- |
| `5a78ec42303ca046d808742e911a156636a2432b` | `10f61ffdc28ca0b46dd0ab100e76bf08a0896527` | 从原声明 rustdesk URL 取得并验证 |
| `93f9445c69f30487f1479a9e4e1882773e00c7f9` | `7792ac148139d8aead7d205baa335dbfaac50b22` | rustdesk、21pages 候选均返回 `not our ref` |
| `b0f50c8d55a015f3d49fe9e90fcefb585d74a25f` | `838decccc44f83d7989fbcd1d404196d7783bbc3` | rustdesk、21pages 候选均返回 `not our ref` |
| `f857bbd3bc350c800d447eb0d809d21f101cd80b` | `2b40c61d8ed62c5de4eeadc5f555fb3b3a6b29ee` | rustdesk、21pages 候选均返回 `not our ref` |
| `cecc93886ce839ec49b0041f072a573327acdf08` | `2d9346087343c817b465e56276fb829adbd1f25f` | 从有历史依据的 flathub 候选取得并验证；原 origin 未证实 |

21pages 候选依据是 Client 提交 `9dd4fa86464a7a390716c9dada405d6ff9b81f09` 的完整 `.gitmodules`，blob 为 `5fc4a93920e37fe4efc9fbb058218317d5c47a07`，其中明确声明 `https://github.com/21pages/hbb_common`。这是该项目其他历史提交的来源声明，未替代上表三项自己的 rustdesk 声明。三个 SHA 分别向两个有依据的来源精确 fetch，均退出 128；六份日志原文为 `fatal: remote error: upload-pack: not our ref <原 SHA>`。日志及 SHA256 已保留；结论仅限这些来源不提供所请求对象，没有声称对象全球不存在。

第五项原路径为 `flatpak/shared-modules`。其父提交整棵 tree **没有任何 `.gitmodules`**。候选依据是后续 Client 提交 `2b40c61d8ed62c5de4eeadc5f555fb3b3a6b29ee` 的 `.github/workflows/flutter-build.yml` 第 2074 行：`git clone https://github.com/flathub/shared-modules.git --depth=1`。本次据此精确请求原 gitlink SHA，实际获取时**未使用 depth/filter**。匹配 SHA 并通过对象闭包验证，可以证明恢复了原 gitlink 内容；不能证明原提交的 origin URL 就是 flathub。没有补写或伪造原 `.gitmodules`。

## 实际保存与完整性验证

新建 bare 对象库位于当前工作区已忽略的隔离目录，没有 checkout 或将旧源码写入产品目录：

| 隔离对象库 | 原 gitlink SHA | 可达提交 / 对象 | 结果 |
| --- | --- | --- | --- |
| `artifacts/history-preservation/rustdesk-hbb-common.git` | `5a78ec42303ca046d808742e911a156636a2432b` | 302 / 1,101 | 非 shallow；无缺失对象；严格 fsck 通过 |
| `artifacts/history-preservation/flathub-shared-modules.git` | `cecc93886ce839ec49b0041f072a573327acdf08` | 243 / 1,079 | 非 shallow；无缺失对象；严格 fsck 通过 |

每次成功获取只建立 `refs/tags/preserved/<原 SHA>`。校验重新按 Git 对象格式计算了 commit SHA 与根 tree SHA，并执行 `git rev-list --objects --missing=print <SHA>` 以及 `git fsck --full --strict --no-reflogs --no-dangling <SHA>`。两份目标快照都没有嵌套 gitlink。失败的 `21pages-hbb-common.git` 隔离目录不包含本次恢复对象，没有作为成功对象库传给后续 inventory。

精确获取使用公开 HTTPS，禁用 credential helper、全局/系统 Git 配置和终端提示，使用 `--no-tags --no-recurse-submodules --no-write-fetch-head`，refspec 为 `<原 SHA>:refs/tags/preserved/<同一 SHA>`。没有访问第三方云项目、推送、修改旧仓库或删除操作。实际 8 次请求的 URL、SHA、退出码、日志路径和摘要保存在 `artifacts/history-preservation/fetch-attempts-2026-10-13.json`。

## 许可证保留

两份恢复目标快照均没有独立许可证命名文件，不能据此假定无限制授权。其源码、内嵌声明及完整原提交仍以原字节保存在 Git 对象库中。原 Client 父提交的完整顶层 AGPL `LICENCE` 和完整 `.gitmodules` 另存于 `artifacts/history-preservation/declarations/`，关联提交、blob ID 和 SHA256 已记入报告。保留父项目许可上下文不等于判定它自动覆盖子模块，也不批准旧源码进入 NestLink 15。

## 本地复验命令

从 `D:\代码\远程控制\NestLink` 执行以下命令，均不联网。第一条读取已有抓取日志、重新检查历史来源与恢复对象；第二条把两个对象库显式加入新清单，输出到不同目录，保留上一轮原报告与证据。

```powershell
python scripts/refactor-gitlink-recovery-audit.py --integration-root D:\home-tunnel-integration

python scripts/refactor-history-inventory.py `
  --integration-root D:\home-tunnel-integration `
  --additional-repository rustdesk-hbb-recovered=artifacts/history-preservation/rustdesk-hbb-common.git `
  --additional-repository flathub-shared-recovered=artifacts/history-preservation/flathub-shared-modules.git `
  --report docs/refactor/history-audit/local-preservation-inventory-with-recovered-gitlinks-2026-10-13.json `
  --artifact-dir artifacts/history-audit/gitlink-recovery-2026-10-13
```

追加库必须用 `NAME=PATH` 显式指定，支持 bare 仓库未设置 HEAD 但存在保存 refs 的情况。提供追加库而未指定独立 report/artifact 输出时，脚本会拒绝运行，避免覆盖原清单。

追加清单将原 118 个不同历史 gitlink 中的本地缺口从 5 降至 3。完整远端 refs、所有旧 Releases 和附件的核对、剩余 gitlink、许可来源复核、持久归档与完整产品验收仍未完成。本次对象保存不放行 [最终远程操作](../finalization.json)。
