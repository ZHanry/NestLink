# 2026-10-17 仓库交付与剩余步骤

本记录采用用户最新顺序：完成实现和必要的开发验证后，上传代码、保全历史、主仓更名、只留 `main`、上传候选 Release、删除三个组件仓库；最终全功能验收由用户在仓库交付后进行。没有执行的签名、硬件、真实外网和安装产品验收继续标为待完成，不能填写为通过。旧的“必须先完成所有正式签名产品验收，才能操作仓库”不再是仓库交付前提；正式生产发布仍使用其独立的签名和验收流程。

## 当前事实与责任边界

| 项目 | 当前状态与完成证据 |
| --- | --- |
| 原历史和旧 Release 字节 | 真实上传正在运行，父任务持有 session `19114`；以最终 JSON 回执为准。原 `history-archive` 上传脚本在本次进程结束前保持不变。 |
| 固定候选产品 | 独立 candidate producer 准备 18 个产品角色和 `candidate-build-manifest.json`；没有生产签名。所有新产品须来自最终合并后的同一完整源 SHA。 |
| 最终源码保全 | 新工具 `scripts/refactor-final-source-archive.py` 已完成真实临时 Git 仓库的 bundle、独立恢复、逐 ref 对比、严格 fsck 和 Windows 只读 pack 清理测试；真实最终源码归档待最终 clean commit。 |
| 候选发布 | `scripts/refactor-repository-delivery.py` 只发布 `v15.0.0-preview.1` prerelease，始终保留 `production_update_authorized: false` 和用户验收 pending；不删除任何远端内容。 |
| 上传、更名、分支整理 | 已核对当前身份有四仓 admin/push 权限，可继续。主仓观察到远端只有 `main`，本地多个分支/旧 worktree 仍需父任务收尾。 |
| 删除三个组件仓库 | 当前 OAuth scopes 为 `gist, read:org, repo, workflow`，缺 `delete_repo`。这是最后 DELETE 的凭据限制，不阻断前面的已授权工作。 |
| 最终用户验收 | pending；Android 11–16/API 30–36，Android 10/API 29 排除。每次测试最长 90 分钟。 |

这些状态的机器台账见 [finalization.json](finalization.json)。本记录不把其他任务尚未完成的实现或构建标为完成，也不代替父任务对实现、定向验证和保全审阅的判断。

## 仓库与保全身份

| 角色 | 当前仓库 | 固定 GitHub node ID |
| --- | --- | --- |
| 主仓 | `ZHanry/home-tunnel`，目标 `ZHanry/NestLink` | `R_kgDOTz-mRQ` |
| 待删 Server | `ZHanry/home-tunnel-server` | `R_kgDOUSDIiA` |
| 待删 Client | `ZHanry/home-tunnel-client` | `R_kgDOUSDI3Q` |
| 待删 Android | `ZHanry/home-tunnel-android` | `R_kgDOUSDJHw` |

2026-10-17 只读快照中四仓共 136 refs、66 Releases、799 assets，原附件共 `16,177,009,767` 字节；观察到的 136 个 ref-tip 对象都已进入独立恢复验证的旧源码材料。原附件在 `C:/Users/Popdo/NestLink-legacy-archive-20261014`，复用其既有完整 SHA-256 复核结果；每件实际上传前再核对该件字节，不再复制整份约 16 GB 原附件。

原始 bundle 是 `artifacts/history-preservation/unified-legacy-20261015/NestLink-legacy-source-20261015.bundle`，`85,678,333` 字节、SHA-256 `ebf6650beae9d180daa8b7dc7d48e9fb91283a28151d22c31865d3f71c9cb943`，保留 317 个原始引用和 annotated tag 对象。旧 dirty worktree 的 Server 38 项、Client 28 项内容、staged/unstaged patch、HEAD/status 与零修改的 Hub/Android 回执已独立保全；ignored 原件继续留在原目录。

用于唯一 `main` 可达历史的 filtered bundle 是 `artifacts/history-preservation/single-main-components-preview-20261015-attempt03/NestLink-components-single-main-20261015.bundle`，`80,581,573` 字节、SHA-256 `fccc862e45773b146e4429576fe8df9ee8ebb7165dc01fd46bdd88a932443557`。anchor 为 `27589bf88ee8df34d7883e607167438cd3a548d0`，保全 157 个组件标签和 11,845 个组件提交。父任务将最终产品提交作为 first parent，以 `ours` 合并 anchor，并比较两个 tree ID 相等；历史文件从历史和组件标签读取，不铺进当前产品 tree。**产品构建和源码归档都使用合并后的最终 SHA**。

三个历史外部 `hbb_common` gitlink 对象原本已不可取得：`93f9445c69f30487f1479a9e4e1882773e00c7f9`、`b0f50c8d55a015f3d49fe9e90fcefb585d74a25f`、`f857bbd3bc350c800d447eb0d809d21f101cd80b`。父 tree 和 gitlink SHA 原样保留；不能宣称所有历史均可递归独立 checkout/重建。此已记录的基线边界不再成为无限推迟已授权合并/上传的理由。

## 1. 先完成正在运行的旧材料归档

固定计划为 `artifacts/history-preservation/history-archive-plan-20261017-attempt01.json`，日志为 `artifacts/history-preservation/history-archive-upload-20261017-attempt01.log`。tag `history-archive-2026-10-17` 指向原远端 `main` 的 `da66975153385f9d92643daa4b7d9f1efbaa7a7d`。计划有 830 个 payload，加计划本身共 831 个远端资产；payload 共 `16,346,355,439` 字节，未另复制原大附件。

由父任务等待已有 session，完成后检查回执 `durable_remote_preservation_verified: true`、`missing_assets: []`、831 项身份/hash/size 映射及 published 状态。若有界批次未结束，可用同一计划和新的回执路径继续；同名同 hash/size 会复用，冲突拒绝，不覆盖/删除原件：

```powershell
python -B scripts/refactor-history-archive-publish.py publish --repository ZHanry/home-tunnel --plan artifacts/history-preservation/history-archive-plan-20261017-attempt01.json --max-seconds 5400 --output artifacts/history-preservation/history-archive-upload-20261017-attempt02.json
```

上面的 attempt02 仅为下一批示例；不能在 session 19114 尚运行时重启第二个并行上传。每批回执必须 create-new。若仓库已经更名，显式使用 `--repository ZHanry/NestLink`，node ID 不变。

**旧材料批次结束并发布后，再创建 final-source supplement Release。** 旧材料 publisher 的源清单比较只排除本次旧材料 archive tag；并行创建新的 final-source Release 会被其末次清单检查视为新增源资产。补充归档创建后，使用 candidate 的两份固定 archive receipt 验证路径检查旧归档，不要再把该老批次的原始源清单当作后来所有 Release 的完整清单。

## 2. 固定最终源码，并独立保全

父任务收齐实现、审阅定向结果、完成上述 `ours` 历史合并、检查当前 tree 和 clean HEAD 后，推送最终 `main` 和 157 个组件标签。不要 force 覆盖其他人的远端新增提交。下列每行从 `D:/代码/远程控制/NestLink` 执行；最终源码目录必须不存在，输出位于 ignored 的 `artifacts` 下：

```powershell
$taskSource = (git rev-parse HEAD).Trim()
$taskFinalArchive = Join-Path 'artifacts/history-preservation' ('final-source-' + $taskSource.Substring(0, 12))
python -B scripts/refactor-final-source-archive.py prepare --expected-source $taskSource --directory $taskFinalArchive --plan "$taskFinalArchive/plan.json"
python -B scripts/refactor-final-source-archive.py publish --repository ZHanry/home-tunnel --plan "$taskFinalArchive/plan.json" --output "$taskFinalArchive/published-receipt.json"
```

`prepare` 检查 exact clean HEAD（含未跟踪源码），创建 `git bundle --all HEAD`，在全新 bare store 恢复、比较全部 refs、最终 commit/tree、对象闭包和 strict fsck。只清理刚创建且已验证绝对路径的 `restore.git`；Windows 只读 Git pack 文件的清理重试仍限制在该目录。bundle/report/plan 保留。实际产品源码和旧大附件不修改、不复制。

`publish` 要求远端 `main` 精确等于最终源 SHA，使用 `history-archive-final-<SHA前12位>`，上传 bundle/report/plan 三项。匹配资产复用，冲突拒绝；优先核对 GitHub SHA-256，只有缺少 digest 才流式读回。不得在源码更改后复用之前的 plan 或假称之前的产物属于新 SHA。输出 source receipt 的 `final_product_source_preserved` 与 `durable_remote_preservation_verified` 必须都为 true，user acceptance 仍为 pending。

每个本地 Git 子命令有 300 秒上限。两个固定小型产物的传输使用有界网络超时和重试；若发生长时间外部故障，应停止该次批次、保留已上传字节后续继续，不做新的全项目回归。所有测试使用 5400 秒硬上限；不使用正式模板的长时 soak 字段延长本轮测试。

## 3. 完成候选 plan 的四份轻量归档元数据

candidate producer 输出 `files/` 下 18 个 `CURRENT_ROLES` 和初步 `repository-delivery.plan.json`。源模板为 [config/repository-delivery.template.json](../../config/repository-delivery.template.json)。本工具只把以下四份 JSON 元数据附入候选 Release；799 件原历史二进制留在已发布的独立 archive，不再二次上传，也不读取旧 blob 本地路径：

| artifact `role` / 建议 `id` | `path` | 原始输入 |
| --- | --- | --- |
| `history-archive-plan` | `files/history-archive-plan.json` | 第一步固定 archive plan |
| `history-archive-receipt` | `files/history-archive-receipt.json` | 第一步最终 published receipt |
| `final-source-archive-plan` | `files/final-source-archive-plan.json` | 第二步 final-source `plan.json` |
| `final-source-archive-receipt` | `files/final-source-archive-receipt.json` | 第二步 final-source `published-receipt.json` |

将这四份小文件按固定字节复制到 cohort 的 `files` 下，填其真实 `bytes`、`sha256`，各自 `source_revision` 保持 null。总计划 schema 必须恰好是：

```json
{
  "schema_version": 1,
  "product": "NestLink-v15",
  "purpose": "repository-delivery",
  "version": "15.0.0",
  "source_revision": "<40位最终合并SHA>",
  "repository_node_id": "R_kgDOTz-mRQ",
  "completion": {
    "implementation": "passed",
    "targeted_verification": "passed",
    "release_bytes_frozen": "passed",
    "legacy_preservation_review": "passed",
    "user_full_functional_acceptance": "pending"
  },
  "signing": {
    "windows": "not-configured",
    "android": "development-only",
    "linux_update": "not-configured",
    "oci": "not-configured"
  },
  "artifacts": ["<18个真实产品描述符和4个归档元数据描述符>"],
  "acceptance_cases": ["<模板中的30个case，每项保留真实passed/pending状态和evidence_artifact_id>"]
}
```

上面两个数组只说明结构，不能直接用作真实输入。单个 descriptor 必须恰好有 `id, role, path, bytes, sha256, source_revision` 六字段，id 唯一、相对路径唯一、不允许外逃或符号链接；18 个产品的 source 都等于最终 SHA，四个历史元数据的 source 为 null。所有文件长度必须大于零，每件不超过 2 GiB。30 个 acceptance case 必须恰好有 `id, status, evidence_artifact_id`；保持完整模板，用 `90-minute-soak`，不含 API 29。未知或 failed 状态会拒绝交付。

只有父任务实际审阅相应证据后才把前四个 completion 设为 passed，不能一键伪造通过。固定字节的 source/SBOM/许可证/materials/native 两清单和小型开发证据包也属于 18 个产品，必须由 producer 实际生成。未配置签名只允许 `not-configured/development-only/unverified`；此路径不接受生产签名已通过的声明。

## 4. 发布候选，核对后再收尾仓库

在最终 clean HEAD 的 checkout 中，替换 cohort 和完成后的 plan 路径，使用 create-new 输出：

```powershell
python -B scripts/refactor-repository-delivery.py verify --repository ZHanry/home-tunnel --bundle '<fixed-cohort>' --plan '<fixed-cohort>/repository-delivery.final.json' --expected-source $taskSource --output artifacts/repository-delivery-preflight-20261017-attempt01.json
python -B scripts/refactor-repository-delivery.py publish --repository ZHanry/home-tunnel --bundle '<fixed-cohort>' --plan '<fixed-cohort>/repository-delivery.final.json' --expected-source $taskSource --output artifacts/repository-delivery-published-20261017-attempt01.json
```

本工具上传 18 产品、4 archive 元数据和 plan 本身，共 23 项。两份 archive 必须均为 published Release，固定 tag、Release/asset ID、hash、size 与最终回执完整对应；final-source 的 source 必须等于当前产品源。验证和发布前后均核对 main/tag/archive，拒绝覆盖、额外资产、改名冲突或状态漂移。`verify` 只读核对本地计划与两份 archive、预检目标；它不把未上传的 candidate 自身伪称远端持久已验证。真正上传、逐件读回并完成公开 prerelease 后，才有 published receipt。

仓库更名、只留 `main`、删除仓库由父任务执行。更名前后、删除每个组件仓库之前，重新查询固定 node ID、仓库名和必要权限；核对真正发布的 candidate、两个历史 archive、最终 source 和 old dirty 工作内容已保全。当前凭据缺 `delete_repo` 时保留其他已经完成的交付，处理最后的认证限制，不反复重跑已通过测试。保全回执、日志、快照、历史原件、旧 worktree 和未知目录不得当作测试垃圾删除。

`repository_finalization_ready: false` 是各上传工具的职责边界：它们不证明父任务的最终 repository deletion 检查已执行，并不把 pending 的最终用户验收重新变成仓库交付门槛。父任务要独立写入真实更名/分支/DELETE 回执，不能修改上传回执中的原始事实。正式 `v15.0.0` 的签名和完整验收脚本继续保留，供用户完成验收且配置正式密钥后使用；本次候选发布不调用该正式入口。

## 本轮定向验证与清理

`artifacts/repository-handoff-targeted-20261017-attempt01.log`：33 项通过，2.697 秒，覆盖 formal handoff/publish、旧 archive resumable transfer、新 candidate delivery 和真实 final-source Git 恢复。后续核对发现动态 import 产生不同 `Missing` 异常类会影响真实首次候选创建，已统一复用实际客户端的 publisher 模块；`artifacts/repository-delivery-targeted-20261017-attempt02.log` 四项通过，0.384 秒，包含该新增回归。因此共有 34 个不同的定向用例通过，未运行 Cargo 或重复全平台测试。

本轮 Python 使用 `-B`，真实 Git 测试使用 `TemporaryDirectory`，自有临时恢复目录已删除；日志保留。运行中的 `refactor-history-archive-publish.py` 未被本轮修复改动。
