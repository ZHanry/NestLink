# 三个组件历史路径预演

2026-10-16 新增单一 `main` 图组装和独立恢复预演，已通过。三个组件的全部 157 个历史引用以 tag 保留，11,845 个组件提交全部从唯一的 `main` 可达；四个最小独立 parent 接到一个新 anchor 后，`main` 共可达 11,846 个提交。各组件固定 `remote/main` 的 subtree ID 未变，新 bundle 在独立空 bare 库中恢复后，再次核验全部引用、main 提交集合、组件 subtree 和完整严格 fsck。原预演/失败记录不变；此处没有导入产品历史或执行远端操作。

新 [组装及恢复原件](../../../artifacts/history-preservation/single-main-components-preview-20261015-attempt03/ASSEMBLY.json) 与同目录 `NestLink-components-single-main-20261015.bundle` 固定本批结果；bundle 为 80,581,573 字节，SHA-256 `fccc862e45773b146e4429576fe8df9ee8ebb7165dc01fd46bdd88a932443557`。仍缺的三个历史 gitlink 原提交及持久材料上传要求不变。这证明保留所有已取得历史并只保留一个分支的方案可行，不代表最终产品或签名验收完成。

2026-10-15 在全新隔离 Linux bare 库中，用固定的 git-filter-repo 2.47.0 将三个组件的全部保全引用改到 `legacy/server`、`legacy/client`、`legacy/android`。每个原提交的 root tree 与新提交中对应组件 subtree 的 Git ID 逐一相同；因此路径包装没有改变原源码、模式或 gitlink 字节。空提交与退化合并均不删减，原提交消息中的哈希和编码保留。

| 组件 | 引用 | 映射提交 | 独立过滤 bundle 字节 | bundle SHA-256 |
| --- | ---: | ---: | ---: | --- |
| server | 59 | 206 | 4,304,720 | `85db299be1e90e179c325ffae5086d44523b7cb4f8ba7a5bf0b3bcfef69ef898` |
| client | 68 | 11,501 | 75,086,716 | `082fc7182413bc6ee4d38a88a73e86e716f03a1fed2cd82b487d025aad589053` |
| android | 30 | 138 | 1,867,722 | `e89682764be7985024ed9007a01f15b2d55c6e7f1530676cfbb22481ce1c332b` |

共 157 个组件引用、11,845 个映射提交。原/新引用清单、逐组件 commit-map、过滤日志、严格 fsck 结果和 bundle 见 [机器记录](../../../artifacts/history-preservation/filtered-components-ext4-preview-20261015-attempt03/PREVIEW.json)，报告 SHA-256 为 `ff40d946096ced1f96075d5e20bbd269453cd49cb41a927fff65b005c5654495`。

独立空 bare 库恢复已通过：分别从三个过滤 bundle 恢复全部 157 个引用，再次逐一核验 11,845 个原 tree 与过滤后 subtree 相等，并通过完整严格 fsck 和可达提交数检查。[恢复记录](../../../artifacts/history-preservation/filtered-components-roundtrip-20261015-attempt01/ROUNDTRIP.json) SHA-256 为 `404db8e6e0601546833211858a0598a88be852755d60adb193d0cb4d7affe66a`。本次恢复未改动产品 HEAD、引用或当次选定源码输入，也未改动原始保全 bundle 和引用清单；该输入检查发生在后续 Android 深色文字修正之前，不代表之后的产品字节。

原始 317 引用保全 bundle 及其 annotated tag 签名对象保持原字节，见 [原始保全](UNIFIED-SOURCE-PRESERVATION-2026-10-15.md)。路径改写必然产生新提交和新 tag 对象，原签名只由未改写 bundle 保全，不能声称过滤后的 tag 仍有原签名。旧工作树和 dirty 备份未改动，三个缺失的 hbb_common gitlink 原提交仍缺失；最新原仓 Git object API 404 和公开 commit search 零精确匹配的原响应见 `artifacts/history-preservation/missing-gitlinks-api-20261015-attempt01/LOOKUP.json`，这不能证明其他位置不存在原提交。

Windows 预演 attempt01 在客户端历史包含冒号的旧文件名处失败，原日志保留。挂载盘上的 Linux attempt02 已完成服务端验证，在客户端重打包持续 I/O 等待；核验进程身份和自有 bare cwd 后，只向该自有 packer 发送 SIGTERM，保留全部文件。attempt03 使用 ext4 自有 bare 存储和官方 `--no-gc`，完成三个组件的过滤、严格 fsck、bundle 验证以及产品 HEAD/引用和选定源码输入字节不变检查。attempt02 仅比较产品 porcelain 路径的旧 guard 不代表完整内容核验，其范围及同期产品修复另有记录。

工具来自官方 PyPI 的 2.47.0 wheel，SHA-256 `2cd04929b9024e83e65db571cbe36aec65ead0cb5f9ec5abe42158654af5ad83`。已阅读随包 COPYING 与完整 COPYING.mit，工具本体按 MIT 使用；声明的 GPL-2.0 测试 harness 未包含在所用 wheel 中。完整许可、上游元数据、wheel 和展开文件摘要保留于 `artifacts/history-tools/git-filter-repo-2.47.0/`，仅供历史工程工具使用，不进入产品构建。

本轮仍为本地预演，没有导入/合并产品历史、上传、改名、删分支、创建 Release 或删除旧仓。正式切换仍需来源审查、持久材料上传、完整产品和固定签名产物验收。
