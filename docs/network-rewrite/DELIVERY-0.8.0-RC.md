# NestLink 0.8.0RC 交付记录

本次交付等级：待用户验收的公开预览版。按用户“这些发布后我再自己验收”的安排，
已于北京时间2026年11月3日22:36:23发布
[NestLink 0.8.0RC](https://github.com/ZHanry/NestLink/releases/tag/v0.8.0-rc.1)。
版本为 `0.8.0-rc.1`，标签为 `v0.8.0-rc.1`，发行源码固定为
`06ea4d1096bb30baf3acfa32290519a1cb3bcee8`。本地与远程均只有main；
发布后的交付文档补充不移动标签，也不替换任何已发布附件。

## 下载与使用

| 用途 | 已发布附件 |
| --- | --- |
| Windows x64主安装器 | [NestLink-candidate-windows-x64.exe](https://github.com/ZHanry/NestLink/releases/download/v0.8.0-rc.1/NestLink-candidate-windows-x64.exe) |
| Windows可选组件安装器 | [NestLink-candidate-windows-x64-privileged.exe](https://github.com/ZHanry/NestLink/releases/download/v0.8.0-rc.1/NestLink-candidate-windows-x64-privileged.exe) |
| Linux x64控制服务 / 无图形组网 | [server.deb](https://github.com/ZHanry/NestLink/releases/download/v0.8.0-rc.1/NestLink-candidate-linux-x64-server.deb) / [network.deb](https://github.com/ZHanry/NestLink/releases/download/v0.8.0-rc.1/NestLink-candidate-linux-x64-network.deb) |
| Linux ARM64控制服务 / 无图形组网 | [server.deb](https://github.com/ZHanry/NestLink/releases/download/v0.8.0-rc.1/NestLink-candidate-linux-arm64-server.deb) / [network.deb](https://github.com/ZHanry/NestLink/releases/download/v0.8.0-rc.1/NestLink-candidate-linux-arm64-network.deb) |
| Web | [NestLink-candidate-web.tar.gz](https://github.com/ZHanry/NestLink/releases/download/v0.8.0-rc.1/NestLink-candidate-web.tar.gz) |
| OCI x64 / ARM64 | [oci-x64.tar](https://github.com/ZHanry/NestLink/releases/download/v0.8.0-rc.1/NestLink-candidate-oci-x64.tar) / [oci-arm64.tar](https://github.com/ZHanry/NestLink/releases/download/v0.8.0-rc.1/NestLink-candidate-oci-arm64.tar) |

同页同时提供源码、SPDX SBOM、许可证、构建材料、原生payload/安装包清单和开发证据。
全部16类制品以及下面两份元数据共18个附件，均绑定同一发行源码。

- [candidate-build-manifest.json](https://github.com/ZHanry/NestLink/releases/download/v0.8.0-rc.1/candidate-build-manifest.json)：每个制品的源码、大小和SHA-256。
- [rc-acceptance-status.json](https://github.com/ZHanry/NestLink/releases/download/v0.8.0-rc.1/rc-acceptance-status.json)：全部41个工作包、70组用例和平台待验状态。

总清单SHA-256：`75fe7e71e08130f68a641c5ed418d25b0a5484854372a277b23350e379e624d8`。
验收状态SHA-256：`d4a620a31c6dedc9eaeff2d333ba6cf3cdb0f67940bdf821da7c1e9945cb65f8`。

本版未配置Windows Authenticode、Linux更新和OCI正式签名，
`production_update_eligible=false`。Windows可选组件字节已包含，正式签名的提权激活资格仍待验。
安装前备份数据库和配置，服务器、Web与双方客户端一起升级；已写入新授权状态后，
按文档执行前向修复，避免恢复旧授权数据库快照。

部署、安装与回滚分别见[远程连接部署](../REMOTE-CONNECTION.md)、
[Windows候选安装](WINDOWS-CANDIDATE-PACKAGES.md)、
[Linux无图形组网包](LINUX-NETWORK-PACKAGES.md)和
[兼容与回滚](COMPATIBILITY-AND-ROLLBACK.md)。

## 实际构建和验证

依赖、编译、格式、Clippy、测试、安装包、OCI和SBOM全部在GitHub托管Actions执行。
下列七个必需工作流均在发行提交成功；旧源码的通过记录没有替代这次检查。

| 检查 | Actions |
| --- | --- |
| Rust core，13/13作业，包括双系统完整工作区 | [41640973128](https://github.com/ZHanry/NestLink/actions/runs/41640973128) |
| 网络，9/9作业 | [41640978902](https://github.com/ZHanry/NestLink/actions/runs/41640978902) |
| Web，5/5作业，包括Chrome/Edge/Firefox实际业务 | [41640984370](https://github.com/ZHanry/NestLink/actions/runs/41640984370) |
| Secret scan | [41640991268](https://github.com/ZHanry/NestLink/actions/runs/41640991268) |
| CodeQL | [41640997325](https://github.com/ZHanry/NestLink/actions/runs/41640997325) |
| Linux x64/ARM64安装 | [41641002470](https://github.com/ZHanry/NestLink/actions/runs/41641002470) |
| 保留版本兼容、schema升级及回滚 | [41641007793](https://github.com/ZHanry/NestLink/actions/runs/41641007793) |

[完整候选41652302634](https://github.com/ZHanry/NestLink/actions/runs/41652302634)的8/8作业成功，
包括三路原生、Web、双架构OCI与冻结。Windows实际安装、重装、卸载及安装后payload字节核验通过。
官方候选artifact为13238238424，ZIP大小275049735字节，SHA-256为
`900bd9e04edd284f0b1866b3ee8cd690191dc078fb0f90765a793eef956444bd`。

[发布41655138643](https://github.com/ZHanry/NestLink/actions/runs/41655138643)成功。
发布器核验官方ZIP、精确源码检查和所有本地制品字节，上传后核验全部附件，再公开prerelease。
之后独立下载公开总清单和验收状态，核对摘要，以及全部18个公开附件的ID、大小和API SHA-256；
标签、源码、公开状态和仅main分支均一致。

可复核回执：

- [七个精确源码检查](evidence/rc-required-checks-06ea4d1.json)
- [候选和发布来源](evidence/rc-producer-provenance-06ea4d1.json)
- [Actions原发布回执](evidence/rc-publication-06ea4d1.json)
- [独立公开回读](evidence/rc-public-readback-06ea4d1.json)

## 保留的失败和后续验收

发布没有修改原任务和用例状态。发行清单中41个工作包为38个in_progress、
1个verified_lab、2个not_started；70组用例为63个not_run、3个failed、
2个running、1个in_progress、1个passed。这里是完整组的资格状态；
单个托管实验通过不能把包含真机或完整场景的整组记为通过。

| 保留失败 | 状态 |
| --- | --- |
| AC17：多relay身份与配额 | failed |
| AC47：异地应用与游戏发现，包含Luanti断线显示25秒检查 | failed，原25秒检查及失败证据保留 |
| AC68：容量和多节点资源 | failed |

原硬件媒体/HDR与公网HTTPS现场失败同样保留；软件4:4:4有限探针不代表持续60fps、
真实桌面采集、scanout或完整媒体资格。W37全功能端到端和W38原网络/媒体配对实测保持not_started，
W40完整交付资格保持in_progress。正式签名和生产更新资格尚未取得。

按用户安排，以下现场验收在发布后使用核验过的制品执行：

| 项目 | 入口 |
| --- | --- |
| 第二台Windows、GPU/显示/输入、媒体和VPN共存 | [媒体目标工具](WINDOWS-MEDIA-TARGET-TOOLS.md)、[Windows TUN](WINDOWS-MANAGED-TUN.md)、[原生恢复](NATIVE-RECOVERY-VIEWPORT.md) |
| Android/iOS标准WireGuard客户端 | [WireGuard入口](WIREGUARD-PORTAL.md) |
| 两处独立公网/NAT、子网、固定入口和双edge HA | [前缀运维](HOST-PREFIX-OPERATIONS.md)、[固定入口](SERVICE-EDGE-GROUP-IPVS.md)、[LAN发现](LAN-DISCOVERY.md) |
| 配对性能、容量、跨日24小时 | [容量验证](CAPACITY-VALIDATION.md)、原规格AC64–AC69 |

CI调度修复保留了旧失败：
[ca71ad7工作区单帧超时](evidence/ci-workspace-ca71ad7-failure.json)、
[abcbabb并发契约Conflict](evidence/ci-contract-abcbabb-failure.json)、
[354de25完整契约总时限](evidence/ci-contract-354de25-timeout.json)。
后续只隔离用例之间的调度、增加完整顺序套件的总执行预算；
生产代码、用例内部并发、原断言、每个用例的超时和性能门槛均未改变。
