# 旧源码独立 bundle 保全

2026-10-17 已在全新独立 bare 仓库重新恢复该 bundle，317 个引用均恢复，完整严格 fsck 通过；读取前后 bundle 仍为 85,678,333 字节、SHA256 ebf6650beae9d180daa8b7dc7d48e9fb91283a28151d22c31865d3f71c9cb943。复核回执位于 D:/NestLinkBuilds/legacy-bundle-reverification-20261017-attempt01-logs/receipt.json，SHA256 cc5ff46eea7069912218ccc60c8735706a91ce704cef73160d5e52110e3d4bc5。三个 hbb_common gitlink 仍缺失；历史尚未导入产品仓库，也未上传持久远端。

2026-10-15 已将固定的四仓本地与远端清单保存为独立 bare 对象库，按组件区分 local/remote/snapshot 标签；原 annotated tag 对象与剥离后的提交均逐项保持一致。共保全 **317 个引用、115/118 个历史 gitlink 提交**，未 checkout 旧源码，未修改旧 worktree、index、HEAD 或引用。

独立 bundle 为 `artifacts/history-preservation/unified-legacy-20261015/NestLink-legacy-source-20261015.bundle`，85,678,333 字节，SHA256 `ebf6650beae9d180daa8b7dc7d48e9fb91283a28151d22c31865d3f71c9cb943`。它已在另一个全新空 bare 仓库中验证、恢复全部引用并通过严格 fsck；原对象库也已检查全部可达对象和严格 fsck。引用映射、输入摘要和限制见 [机器报告](unified-source-preservation-2026-10-15.json)。

这一步形成可独立恢复的本地源码材料，尚未导入产品仓库或上传远端。此前三个 hbb_common gitlink 的原始来源获取失败仍保留，未以其他提交替换。既有 799 件 Release 附件的本地原件继续保留。

另已独立备份旧 14.1.0 的 Server 38 个、Client 28 个修改或未跟踪文件，逐件核验 ZIP 读回字节与原文件 SHA256，并保存原 HEAD、staged/unstaged binary patch 及 NUL 分隔状态。Hub/Android 为零个修改文件；读取前后旧 worktree 状态保持一致。详情见 [dirty 工作内容报告](dirty-worktree-preservation-2026-10-15.json)。首轮因把读取引起的 access time 更新误判为变更而中止，其 partial 原件保留；修正为内容/身份/权限元数据检查后的第二轮完成。ignored 文件仍只留在原目录，未被宣称包含在备份或 bundle 中。

正式整理前仍需刷新远端清单、完成旧来源许可复核并上传持久历史、dirty 工作备份及旧发行材料。产品实现和固定产物验收尚未完成，[最终远程操作](../finalization.json) 的前提未满足。

此前 18 个未被简单文本签名识别的许可证命名 blob 现已逐件核对并分类：14 个是许可证密钥处理程序源码，2 个 RTF 是上游隐私政策，另有 ISC 许可和 GPL-3.0-or-later 短声明各 1 个。[本轮分类与原件摘要](LICENSE-NAMED-BLOB-REVIEW-2026-10-15.md) 不改变原许可、不批准产品复用，也不替代其余来源和依赖审查。

三个组件现已完成隔离路径预演：157 个引用、11,845 个提交逐件保持原源码 tree，逐提交映射和三个独立过滤 bundle 已保存。原 bundle 不变，仍未导入产品仓库；独立恢复检查状态和边界见 [历史路径预演](FILTERED-HISTORY-PREVIEW-2026-10-15.md)。
