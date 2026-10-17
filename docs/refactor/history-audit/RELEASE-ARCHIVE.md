# 旧发行附件本地归档

2026-10-17（Asia/Shanghai）已再次完整复核固定清单：799/799 件、16,177,009,767 字节全部通过。复核逐项比对当前 GitHub asset ID、长度、SHA256 与上传状态，并重新哈希归档字节；inventory SHA256 为 8710e82fde1ac829aa25246a7fb763ace1be4ff16e0c21fed263684b4e058ec7。报告路径为 C:/Users/Popdo/NestLink-legacy-archive-20261014/archive-20261016-211836-9df6cbcb.json，报告 SHA256 为 99f4fe861b0f9dd98d8d3a115de1d94b478991028530e3781f76240ad0f297b6。这仍是本地归档；durable_remote_archive_uploaded 与 finalization_ready 均为 false。

同日 08:49–08:52 的独立只读远端清单再次观察到 66 个 Release、799 件附件和 16,177,009,767 字节；136 个可见 heads/tags refs 在扫描期间稳定。按 asset ID 将新鲜远端元数据与上述全量本地字节复核报告比较，799 项全部匹配，无新增、缺失或变化。该步骤复用前一报告的本地字节校验，没有重复读取 16 GB；也没有把本地归档写到远端。见[当前远端 inventory](REMOTE-INVENTORY-2026-10-17.md)、[机器清单](remote-preservation-inventory-2026-10-17.json)和[asset ID 对照](remote-release-archive-crosscheck-2026-10-17.json)。

2026-10-14 全部六件大附件续传成功后，正式归档工具不带 `--asset-id` 对固定清单重新完整执行：**799/799 件、16,177,009,767 字节**，66 个 Release 的每个既有 blob 均重新计算完整 SHA256，并通过前后当前 GitHub 元数据核对。新独立报告为 `C:/Users/Popdo/NestLink-legacy-archive-20261014/archive-20261013-205332-fff54c53.json`，SHA256 `58405856dadaa5b6fca396ab3b600853469569a978cf4a285440ac2fc4ff5ce6`；原报告和 partial/范围分片保留。对应脚本 SHA256 `3ccc7fdb600d8680a769c013d96dda05524dae680d76e907d89af8314b72a5b8` 的精确副本也保存在归档根。完整本地字节证据见 [release-preservation-local-verification-2026-10-14.json](release-preservation-local-verification-2026-10-14.json)。持久远端上传、历史导入和正式切换仍未完成，`durable_remote_archive_uploaded` 与 `finalization_ready` 保持 false。

2026-10-14 原全量批次最终核验 727/799 件（6,138,414,937 字节），72 件失败的原件和报告保留。后续独立范围续传已核验两件 Client 大附件；排除四件 Client 大附件后的 68 件批次已核验 66 件，两件 Android Materials 超时后从保留 partial 独立续传。其余大附件继续恢复；子集成功不能标记全清单或持久远端保全完成。全量原脚本的固定 SHA256 为 `e41bbb8a41ba6887079fc90607cbd00f7da41737fcb82ff9f604b68289137989`，归档根已保留该脚本副本，原报告未改。全量/子集归档进程退出后，修复归档脚本的 Linux 竞争覆盖窗口：用同目录排他硬链接发布，保留竞争文件及失败 partial；已有 blob 也必须通过末次当前元数据检查。两个新增工具回归验证了真实竞争写入和末次元数据变化。正式字节进度与证据使用各独立报告，不从目录文件数推算成功数。

[当前远端清单](REMOTE-INVENTORY-2026-10-14.md) 包含 66 个 Release、799 件附件，合计 16,177,009,767 字节。归档使用独立目录 `C:/Users/Popdo/NestLink-legacy-archive-20261014` 保存字节，保留开发盘的构建空间。

[refactor-release-archive.py](../../../scripts/refactor-release-archive.py) 只创建本地归档，使用已核验四仓 ID 的固定清单与 `gh api` GET。每件附件先查当前 ID/长度/SHA256/上传状态，再下载或独立复制此前已核验的本地副本，复查实际字节与当前元数据后才将独占 partial 文件提升为 `.blob`。原文件名只保存为元数据，落盘名称使用数字 asset ID 与摘要，不执行或解压旧二进制。

既有归档必须重新核验；损坏的既有文件不会被覆盖。下载或末次元数据检查失败时保留 partial，标记失败，不计入完成。归档按每次运行保存独立报告与原清单快照，完整操作可复用已经核验的 blob，并需要所选未保存字节加 2 GiB 余量。并发数最多 4。显式 `--asset-id` 只做指定附件的试下载，不能宣称全部清单已保全。

```powershell
python scripts/refactor-release-archive.py --inventory docs/refactor/history-audit/remote-preservation-inventory-2026-10-14.json --archive-root C:/Users/Popdo/NestLink-legacy-archive-20261014 --integration-root D:/home-tunnel-integration --workers 4
```

首次真实试下载为 Hub `v7.0.0` 的 80 字节 `SHA256SUMS.txt`（asset ID `574934286`）。前后当前元数据与落盘字节均核验通过；试下载报告明确显示 `selected_asset_count=1`、`inventory_asset_count=799`、`all_inventory_bytes_verified=false`。完整归档结果须读取该目录的后续报告，不能由此次试下载推导。

工具新增 6 项测试，验证不可信文件名不影响目录、缺摘要/未完成上传拒绝、损坏下载不提升、下载后远端变化不提升、损坏既有归档不覆盖、本地独立复制保留原件，以及读取过程中变更拒绝。Windows/Ubuntu 工具验证与试下载摘要见 [release-archive-tool-verification-2026-10-14.json](release-archive-tool-verification-2026-10-14.json)。

另已将 Server 两个缺失分支 tip 保存到新的、非 shallow 隔离 bare 对象库，重算 commit SHA、验证对象闭包并通过严格 `fsck`，见 [server-extra-refs-preservation-2026-10-14.json](server-extra-refs-preservation-2026-10-14.json)。两提交分别可达 201/206 个提交、3,867/3,957 个对象；未修改原 Server 克隆，也没有导入产品。可在对象库对记录的 SHA 执行 `git rev-list --objects --missing=print <SHA>` 与 `git fsck --full --strict --no-reflogs --no-dangling <SHA>` 复验。

本地附件归档尚不能替代持久远端保全、历史导入、三项缺失 gitlink、来源/许可复核或完整产品验收。归档工具始终记录 `finalization_ready=false`，没有上传、改名、删仓或修改分支/Release 的接口。

## 有界断点续传

大型附件整文件下载失败后，使用 [refactor-release-resume.py](../../../scripts/refactor-release-resume.py) 单独恢复指定 asset。它复用同一份固定四仓清单和原附件摘要，原 partial 只读，先独立复制，再以最多 8 MiB 的 Range GET 下载余下内容；每次请求最多 300 秒，HTTP 必须为 206，Content-Range 的起止位置和总长度必须与请求完全一致。全文件 200 回退、编码过的响应、错误/重复响应头、截断和多余字节都会拒绝，不能直接追加到已保存前缀。

`--partial` 只接受该 asset ID/摘要在归档目录下的原独占 partial，或上次续传工具留下的 assembly partial。分片成功才追加并同步磁盘，原件不修改，已核对的分片和失败 assembly 保留。磁盘预算包括独立 assembly、保留分片和 2 GiB 余量。最后仍须验证完整原始 SHA256 与当前 GitHub 元数据，再用同目录的排他硬链接发布 `.blob`，目标在最后检查后出现也不会被覆盖。随后移除的只是不再需要的自有 assembly 链接；原 partial 与分片保留。

```powershell
python scripts/refactor-release-resume.py --inventory docs/refactor/history-audit/remote-preservation-inventory-2026-10-14.json --archive-root C:/Users/Popdo/NestLink-legacy-archive-20261014 --asset-id <失败的数字 asset ID> --partial <原报告所记 partial 的绝对路径>
```

续传保存独立报告、原清单快照与源码摘要，明确 `selected_asset_count=1`、`all_inventory_bytes_verified=false` 和 `durable_remote_archive_uploaded=false`。单件成功不改变原整批报告；完整下载结束后还须由整批工具重新核验全部 blob，才能形成完整清单的字节证据。

工具和测试按 v3 保全要求独立编写，只复用本仓第一方固定身份、元数据和字节校验函数，未复制旧产品实现。七项新增测试覆盖响应头/范围、实际流的精确长度、原前缀独立复制与恢复、完整摘要/元数据失败、任意前缀/既有损坏文件拒绝，以及最后发布阶段的竞争写入。正式源码另以真实 17 字节前缀完成 80 字节附件续传并核验完整摘要。双平台结果及明确的归档边界见 [release-resume-tool-verification-2026-10-14.json](release-resume-tool-verification-2026-10-14.json)。
