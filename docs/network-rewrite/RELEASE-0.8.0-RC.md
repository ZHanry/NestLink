# 0.8.0RC 交付要求

本次用户明确要求实现 CODEX-START.md、NESTLINK-REWRITE-SPEC.md 和
NESTLINK-TASKS.json 的全部范围，公开发布 0.8.0RC，最终只保留 main 分支。
软件版本采用 SemVer `0.8.0-rc.1`，展示名为 `0.8.0RC`。

## 用户确认的预览版发布安排（2026-11-03）

用户对第二台 Windows、Android/iOS 标准 WireGuard、独立公网/NAT、固定入口、
跨日24小时和签名资源的询问回复：“这些发布后我再自己验收”。据此，本版公开发布为
尚待用户验收的 prerelease，允许先交付同源制品。以下历史“全部目标验收后才能公开
发布”的要求对本次预览版由该明确指令覆盖；正式资格、生产更新与任何 passed 结论
仍需要原证据。此安排不会把未实现、未运行或失败状态改成通过。

发布工具必须显式选择 `--deferred-target-acceptance`，随制品提供
`rc-acceptance-status.json`，绑定候选清单摘要、源码、原规格/任务和授权策略摘要。
文件包含全部41个工作包、70组用例的实际状态及原平台待验清单。默认发布模式仍要求
两份完整通过的独立审阅包。精确源码的 required checks、16类完整制品、摘要、干净
源码、上传前后回读与只发布 prerelease 的约束继续执行。

已知失败保留：Luanti 25秒断线显示检查，原硬件媒体/HDR与公网HTTPS现场失败。
软件4:4:4的单次有限探针成功不代表持续60fps、桌面采集、scanout或完整媒体资格。
正式签名未配置，`production_update_eligible=false`；请按预览软件安排试用。

发布后验收入口：

| 资源/项目 | 操作与证据入口 |
| --- | --- |
| Windows双端、媒体、GPU/HDR、输入、VPN共存 | `WINDOWS-MEDIA-TARGET-TOOLS.md`、`WINDOWS-MANAGED-TUN.md`、`NATIVE-RECOVERY-VIEWPORT.md` |
| Android/iOS标准WireGuard | `WIREGUARD-PORTAL.md` |
| 独立公网/NAT、固定双入口与子网 | `SERVICE-EDGE-GROUP-IPVS.md`、`HOST-PREFIX-OPERATIONS.md`、`LAN-DISCOVERY.md` |
| 原网络配对性能、容量及跨日长稳 | 原规格AC64–AC69、`CAPACITY-VALIDATION.md` |
| 升级、回滚、退出与卸载清理 | `COMPATIBILITY-AND-ROLLBACK.md`、`WINDOWS-CANDIDATE-PACKAGES.md`、`LINUX-NETWORK-PACKAGES.md` |

安装前备份数据库和配置；服务器、Web和客户端保持同版。升级后的授权数据库不得
用旧快照回滚，以免恢复已撤销权限；使用文档中的前向恢复和清理步骤。

新增需求以本目录的 1.1 版规格为准，包含全部 26 项功能、41 个工作包和 70 组验收。
config/product-scope.json 和 docs/refactor/ 中的旧结论保留其原适用源码及历史含义。
新增 Linux 无图形组网/子网网关角色，以及 Android/iOS 标准 WireGuard 客户端接入，
不等于恢复被移除平台的原生远控客户端。

## 发布条件

- 成熟组件优先复用；第一方源码、上游参考和运行依赖如实登记。
- 依赖安装、代码生成、格式、编译、自动验证、打包、摘要和 SBOM 均由 GitHub 托管 Actions 完成。
- 旧报告的性能、媒体、硬件、直连与长稳门槛继续适用。旧 Release 和旧 CI 结果不作为新功能证据。
- 所有适用验收引用对应源码、锁文件、构建及执行来源和制品。未执行、失败、外部阻塞均不计为 passed。
- 完整资格仍须满足真实功能与证据门禁；本次先公开预览版采用上面的明确用户安排，保持所有真实状态和失败证据。
- 发布制品须来自同一干净源码 SHA，并包含升级、回滚、清理、兼容和来源资料。
- 清理分支前核对所有远端分支和未合并工作；本次开始时本地及远端均只有 main。

## 当前事实

初次检出的 main 是 `82f1c8dfb31bdf0872ea7430b5608e205c1cbb08`，与研究基线一致。
GitHub 登录账号 ZHanry 的仓库 push 和 workflow 权限已验证，Actions 已启用。
`0.8.0-rc.1` 已于北京时间2026年11月3日22:36:23公开发布为
[NestLink 0.8.0RC](https://github.com/ZHanry/NestLink/releases/tag/v0.8.0-rc.1)。
标签和全部制品固定在 `06ea4d1096bb30baf3acfa32290519a1cb3bcee8`；七个必需工作流
均在该提交通过，完整候选构建41652302634和发布41655138643均成功。
16类制品及总清单、实际验收状态共18个附件已完成上传后回读与独立公开元数据核对。
本地、远程均只有main。发布后的文档补充不改变标签和制品源码。

第一方依赖和候选安装器版本已统一；三份Cargo锁文件由托管Actions派生，
原外部依赖身份、校验和与边已核对。公开预览版不代表全部功能或现场验收通过，
AC17、AC47、AC68和所有待验状态继续保留。下载、检查记录和后续验收入口见
[交付记录](DELIVERY-0.8.0-RC.md)。
W00 的源码、旧制品、实际发布和历史文档差异由 BASELINE.md 记录。

完整进度见 progress.json 与 NESTLINK-TASKS.json；二者不是验收证明。
