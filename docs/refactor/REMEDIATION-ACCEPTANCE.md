# 0.7 报告验收发布门禁

用户要求 2026-10-20 v1 报告全部实现且验收通过后发布。开发构建与正式 RC
发布分离：GitHub Actions 可以生成待测制品，不能据此创建 RC 标签或 Release。
`refactor-rc-publish.py` 的 verify、upload-draft、publish 都先检查本地报告证据包，
未通过时不访问 GitHub。现有 18 个产品制品、源码、摘要、签名披露和 main 门禁保持。

## 必需覆盖

报告原文件 SHA-256：
`c6cac00cef64627e023eabf78fa77750b2093e9e1138567ad3ecad112c49905c`。

15 个研发工作包：`N01 N02 N03 N04 M01 M02 M03 M04 T01 T02 R01 U01 U02 U03 Q01`。
每项须有代码/行为、适用条件、实际验证和限制的审阅证据，不能用一条 CI 成功替代。
M04 须提供高阶编解码、真彩、高帧组合的真实硬件合格表及不支持组合的回退结果。

| 体验 case ID | 报告门槛及证据要求 |
| --- | --- |
| original-edge-100 | HL ↔ 原外部 Edge，Clash TUN 对照；至少100次、至少99次真实直连，保留失败和候选路径证据；TURN不能抵扣 |
| stratified-uu-200 | UU 同期已验证直连的分层样本至少200次，直连率差距≤2个百分点；保留各层原始结果与置信区间 |
| first-frame-p95 | 双方批准且就绪后首个可交互画面p95≤3秒，批准等待单列 |
| native-1080p60 | 动态内容、合格硬件实际呈现≥58fps，帧间隔p95≤25ms，保留质量和冻结情况 |
| input-display-ab | 独立输入到显示测量；p50≤UU+10ms、p95≤UU+20ms，注明设备、同口径条件和测量精度 |
| weak-network-adaptation | 1%丢包及20→5Mbps阶跃，2秒内降档，过期视频不持续积累；保留恢复关键帧及画面观察 |
| concurrent-file-input | 文件并发输入延迟p95增幅≤10ms，无持续冻结；记录文件预算及媒体质量 |
| recovery-p95 | 断网、漫游、睡眠、换网卡恢复；有效授权下p95≤5秒恢复可交互，旧代次不回流 |
| cross-day-24h-soak | 多轮跨日、单次24小时，保留CPU/GPU/内存/队列曲线、崩溃和累计延迟记录 |
| revocation-and-exit | 撤销停止媒体和输入，无旧帧泄露、卡键和未授权重连 |

Q01 同时覆盖报告9.1的测量规则、9.2完整网络矩阵与适用平台。
UU 使用用户已安装的4.40.1.2090，保存参考版本和UI全状态、100/125/150%对照。
报告性能目标未经用户确认不得降低；不支持的硬件组合不能冒充合格结果。

## 证据包

冻结构建根目录额外放 `remediation-acceptance.zip`，作为第20项 Release 附件；
原18个产品和候选清单字节保持原样。包内只包含一个 `remediation-acceptance.json`
以及其声明的 `evidence/` 文件，不允许外部链接、目录条目、符号链接、穿越、重复、
加密或未声明文件。压缩和解压总量上限64MiB，单文件16MiB，证据最多256份。
大体积视频等可单独归档；包内必须保留可审阅的样本、摘要和归档定位，不能只给URL。

元数据字段固定为：

```json
{
  "schema_version": 1,
  "kind": "nestlink-remediation-acceptance",
  "repository": "ZHanry/NestLink",
  "version": "0.7.0-rc.1",
  "source_revision": "<40位候选源码SHA>",
  "manifest_sha256": "<原candidate-build-manifest.json的SHA256>",
  "report_sha256": "c6cac00cef64627e023eabf78fa77750b2093e9e1138567ad3ecad112c49905c",
  "status": "pending",
  "reviewer": "<实际审阅人>",
  "reviewed_at": "<实际审阅时间，UTC YYYY-MM-DDTHH:MM:SSZ>",
  "cases": [{"id": "N01", "status": "pending", "evidence": []}],
  "evidence": []
}
```

此例故意不具备发布资格。实际需完整25项，每项必须是 `passed` 且引用至少一份
已校验文件；每份文件的描述为 `{"path":"evidence/…","bytes":123,"sha256":"…"}`。
记录原始样本、环境、实测方法、失败和适用限制，经审阅后才填passed。
禁止自动把 pending 改成 passed。单纯修改状态不是验收。

脚本核验证据结构、摘要、完整覆盖及构建绑定，**不能自动证明实测数据或审阅的真实性**。
证据真实性仍须审阅人负责；没有真实测量时保持未发布。证据及全部产品在上传前后、
最终发布前重新校验，远端按asset ID与摘要读回，发生变化时保留草稿、拒绝公开发布。

冻结的开发清单保留原30项平台/签名测试的pending状态。这是历史构建记录，
独立报告验收不修改它、不宣称正式签名或生产自动更新资格。


2026-10-22实测更新：完整候选8/2d250ea在原外部Edge↔HL TUN环境仍连接失败，
真实“本机被控”弹窗底栏稳定性亦failed。见[失败证据](evidence/failed-original-edge-2d250ea-20261022.json)。
任何后续自动检查或UDP服务器echo均不能把这两项结果改成passed。

2026-10-23 基本功能复测：`440710625ef7707d579525edb9614e0631cac7b1`
在原外部家庭宽带 Edge ↔ HL、HL Clash TUN 开启的场景中，用户确认
“直连，画面和键鼠均正常”。同一次请求的宿主记录观察到实际直连候选对、
端点证明和媒体发送，并与本机验收页事件关联；终止后宿主清理及服务端撤销另有记录。
归档 `work/diagnostic-attempt-4407106-20261023-083909/request-146e98d3-final.json`
SHA-256 为 `4a823abde3952eac34fe15967dcab9db09e630fee420afa5fd8b49f560de5c4c`。
这次结果不更改前述失败历史，也不能替代 `original-edge-100`、性能、长稳或后续源码回归。

2026-10-24：签名方向能力、首次批准格式快照、原生格式 ACK、IPC 与 CPU provider
已完成一批接入。默认生产新格式继续关闭，实际执行 owner 接管及双端原生续租
驱动仍未完成。具体代码行为、测试边界及剩余条件见
[M04 接入记录](M04-SIGNED-MEDIA-INTEGRATION.md)，不得据此将 M04 或体验 case 改为通过。

2026-10-25：已整合软件编解码 owner broker、双端原生续租及 AppCore 消费者，
并增加真实服务签名租约的认证 IPC 观测。独立源码审查未发现具体阻断问题，
但 GitHub 编译、运行时回归、原生硬件和公网实测尚待完成。上一源 Windows
软件视频正向测试仍失败；新增诊断不算修复完成。M04、性能与长稳门禁保持 pending，
生产新格式签发标记仍关闭，未创建 RC 标签或 Release。
