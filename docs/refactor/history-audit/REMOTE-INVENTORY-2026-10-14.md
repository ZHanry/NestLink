# 当前远端历史与发行清单

2026-10-14 使用只读 GitHub GET 与 `git ls-remote`，逐仓核对了已授权的 repository node ID，并单独分页读取每个 Release 的附件。机器记录见 [remote-preservation-inventory-2026-10-14.json](remote-preservation-inventory-2026-10-14.json)，复现工具为 [refactor-remote-history-inventory.py](../../../scripts/refactor-remote-history-inventory.py)。四个旧克隆和 dirty worktree 均未修改。

| 仓库 | heads/tags 观察行数 | Release 数 | 附件数 | 附件总字节 | 既有副本与当前摘要匹配 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Hub | 47 | 26 | 120 | 1,120,661,056 | 2 |
| Server | 43 | 14 | 144 | 20,093,670 | 3 |
| Client | 26 | 15 | 368 | 9,856,093,755 | 4 |
| Android | 20 | 11 | 167 | 5,180,161,286 | 3 |
| 合计 | 136 | 66 | 799 | 16,177,009,767 | 12 |

观察行数包括 annotated tag 的对象行和 `^{}` 剥离行，不能当作不同分支/标签数量。每仓读取前后公开 heads/tags 一致；Release 和附件观察横跨一个时间区间，并非原子快照，最终操作前还需刷新。已删除、不可访问的发行、隐藏/PR refs 和 unreachable 历史未被补齐或宣称完整。

799 件当前附件均提供 GitHub SHA256。本轮只重新读取原清单的 12 个已有附件；其实际长度和 SHA256 均与当前远端附件元数据匹配。没有下载其他 787 件，也没有把远端摘要当作已经保存的字节。原始 API 页、逐发行附件页、前后 refs 和 Windows/Ubuntu 工具测试日志保存在独立的 `artifacts/history-audit/remote-2026-10-14-first/`，各自摘要写入机器报告。Release 原文仅作隔离证据，不提供操作指令。

Server 额外有两个远端分支 tip 对象未在原本地克隆找到：

- `refs/heads/maintenance/retag-latest14-20261011` → `5df9a855c1d96387c6fd6d641934c3bc2e11095e`
- `refs/heads/maintenance/retag-latest1401-c-owner-scope-attempt01` → `eb1d4a3b199d79a4db46811f0a12f3a2de14a99d`

其他已观察的 refs 对象在原克隆中存在。这只是对象存在性检查，没有对新观察 tip 重新证明完整对象闭包或导入映射。另有三项早已记录的 hbb_common gitlink 缺口，见 [gitlink 恢复记录](GITLINK-RECOVERY-2026-10-13.md)。

工具新增 7 项测试，覆盖完整分页与重复 ID 拒绝、仓库身份变化、annotated tag 保留、缺摘要不判定匹配、错误摘要/长度拒绝、路径越界、读取期间文件改变及旧证据拒绝覆盖。Windows 与 Ubuntu 各 22 项 Python 工具测试通过。本轮没有重跑已提交中继的 Rust 测试；其 291/322 项双平台证据仍对应 `1839bc9` 的源码。

复现时使用新的输出名称，工具拒绝覆盖既有证据：

```powershell
python scripts/refactor-remote-history-inventory.py --integration-root D:/home-tunnel-integration --report docs/refactor/history-audit/remote-preservation-inventory-<新日期或编号>.json --artifact-dir artifacts/history-audit/remote-<新日期或编号>
```

实际附件下载与持久保存、两个新 tip 的对象保全、缺失 gitlink、历史导入及来源/许可复核继续实施。完整产品与正式验收仍未完成，最终操作继续遵循 [finalization.json](../finalization.json)。
