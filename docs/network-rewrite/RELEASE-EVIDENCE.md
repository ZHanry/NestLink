# 0.8.0RC 发布证据绑定

开发候选由原 `v15-candidate-build.yml` 在 GitHub 托管 runner 构建，产品 SemVer 为
`0.8.0-rc.1`。同一干净源码、required checks、完整平台角色、原安装核验和 freeze
继续适用。`v15` 协议、本机状态、安装 AppId 与发布历史不随产品版本重命名。

`network-version-lock.yml` 只在托管 runner 派生 product、browser-native-fixture 和
security-fuzz 三份锁。它先运行 Cargo 的 workspace resolver，保留每一原外部 package
身份、checksum 与依赖边，再用 `cargo metadata --locked` 验证实际图。任何外部包新增或
删除都拒绝该版本派生，须另外按原组件审阅流程处理。两个不发布的验收 harness 仍为
`0.0.0`；产品 crate 统一为 `0.8.0-rc.1`。锁派生和格式输出不代表编译或产品验收。

公开发布由原 `refactor-rc-publish.py` 执行，保留原候选和 25 项报告验收门禁。
本次另要求候选根目录的 `network-rewrite-acceptance.zip`，不能用 progress.json、
源码中的状态或一次 CI 通过代替。独立外置审阅包避免把最终源码 SHA 写回同一提交造成
循环引用；该包绑定原候选清单 SHA256、精确源码、完整规格和任务文件的 SHA256。
发布工具对两份审阅包使用同一有界 ZIP/path/重复字段/大小/摘要/声明清单校验，
实际上传和长时间回读后再检查两份包，任何变化都阻止公开发布。

新增包内元数据名为 `network-rewrite-acceptance.json`。除 `schema_version: 1`、
`kind: nestlink-network-rewrite-acceptance`、repository、version、source_revision、
manifest_sha256、specification_sha256、tasks_sha256、status、reviewer、reviewed_at 外，
还包含以下记录：

- `work_packages`：精确 W00–W40、无重复，包含 id 与状态。需要 L3/L4 的工作包须为
  verified_target，其余须为 verified_lab 或 verified_target；未完成和外部阻塞不算通过。
- `cases`：精确 AC01–AC70、无重复，每项 passed，task_ids 与原规格完全一致，
  evidence_levels 覆盖原要求。每项还包含 evidence、build_provenance、execution_provenance。
- `evidence`：声明所有 `evidence/` 内原始记录的相对路径、字节数、SHA256。路径不可逃逸，
  不允许符号链接、重复/大小写冲突、未声明文件或未被用例引用的文件。复用原审阅包的
  64 MiB 总上界、单文件 16 MiB、最多 256 份证据。

每个 case 的 build_provenance 包含 repository、source_revision、dependency_lock_sha256、
workflow（源码内 `.github/workflows/*.yml` 或 `.yaml`）、workflow_revision、run_id、
run_attempt、job_id、runner_environment、artifact_sha256。构建必须来自 github-hosted，
源码和 workflow revision 必须等于最终候选源码；artifact_sha256 必须是原冻结产品清单中的
实际制品摘要，不能填入另一次旧制品或独立探针摘要。

execution_provenance 是一个实际执行记录数组，每项包含 kind、source_revision、
artifact_sha256、evidence_levels、environment 和 evidence。kind 区分 hosted_actions 与
target_device；L3/L4 只接受 target_device。执行制品与 build_provenance 保持一致，
environment 必须描述实际平台/硬件/拓扑，证据引用须在该 case 的已核验文件内，
所有执行记录的等级并集须与该 case 声明的等级完全一致。

这些检查只验证完整性、来源绑定和资格记录的结构；不能证明人工测量真实，也不会生成
passed 审阅材料。独立审阅者仍须核对原始 samples、失败、硬件/驱动、实际拓扑、
构建及执行过程、各子场景和原门槛。真实未执行、失败或仅实现的用例保持原状态；
用户要求保留的 Luanti 25 秒失败也不会因为另外一份报告或版本号变化而通过。

`network-release-policy.yml` 执行候选/发布协议的合成回归，验证旧源码、缺失/失败的
70 用例、部分 41 工作包、伪目标来源、未绑定制品和上传期间替换证据均在远端写入前或
保留 draft 时被拒绝。测试中的合成全通过记录只存在于临时 fixture；不进入产品验收或发布。
