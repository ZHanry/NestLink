# 服务、迁移与构建工具集中检查记录

本记录对应 2026-10-15 的已有开发检查，各 receipt 保存自己的精确源码输入。这些结果不合成为同一固定产物的正式验收。汇总与输入 SHA256 见 `artifacts/core-verification/service-host-producer-status-20261015.json`。

| 检查 | Windows | Ubuntu x64（WSL） |
| --- | --- | --- |
| 长路径/外来或缺失数据库 | 2/2 | 2/2 |
| 加密 schema 迁移 | 6/6 | 6/6 |
| 原 service-web-host-schema 十组 | 9 组通过；Core 新夹具超时 | 9 组通过；Core 新夹具超时 |
| 修正后的 Core services | 4/4 | 4/4 |
| Rust 真实 Caddy 私有 Admin 进程 | 回环 1/1 | 回环及 Unix 2/2 |
| server/Core all-target strict Clippy | 通过 | 通过 |
| producer/supplier/publisher Python 纯回归 | 36/36，零跳过 | 36/36，零跳过 |

整体 rustfmt 通过。原十组结果保留于 `service-web-host-schema-{windows,linux}-tests-20261015-attempt01.json`；修复后的两组结果在 `service-host-admin-followup-{windows,linux}-tests-20261015-attempt01.json`。每组记录源码稳定、独有临时目录回收及零墙钟回退。Linux 的 EXIT owner 恢复时钟后，另实际读取确认 clocksource 为 `tsc`。

Core 超时是新增测试没有启用本机服务发布策略，实际默认拒绝使 `/approval` gate 无法到达。测试现在通过真实 Core 加载并修改策略，验证服务端批准已提交但 logout 后晚回复仍被消费且不会启动本机转发。没有增大超时或改变生产默认策略。原失败不改写为整批通过。

Caddy 测试启动本次拥有的 2.11.7 进程，通过生产 Rust Admin client 执行 install/PATCH/GET/DELETE，再实际停止并等待进程退出。它与此前 Python Caddy 流式 body/WebSocket/TLS 合同互为补充；私有测试没有申请公网证书。真实 HTTP→Node poll→固定身份 QUIC→TCP 与取消启动回归在原十组中通过。

release producer 已合入 13 个路径。实际隔离 Gradle/AGP 检查覆盖配置、双 ABI release 任务图，以及真实 `preReleaseBuild` 拒绝 `15.0.0-dev.1`，三项通过；未编译新 JNI/APK，也未签名。最初 AGP 配置失败与后续成功分别保留于 `producer-gradle-configuration-20261015-attempt01/` 和 `attempt02/`。

新供应锁 SHA256 为 `bdba9f3336e1b36fafa57e6044c37e4b53aba28e780820d5fca179ab3e839b73`，供应脚本 SHA256 为 `0e969dae82e0160748cdf1dba436e1aa42f2e6f22f18ec69d9326de164db4449`。Windows/Linux x64 与 Android 双 ABI 的库已从固定官方源码重建，Android/Linux 静态归档逐成员 ELF 架构核查通过，详见 `producer-native-supplier-receipts-20261015/summary.json`。这不是 Linux ARM64 host 产品构建或运行结果。

Python 纯回归中的证书、产物及 GitHub 响应是明确的合成夹具/本地模型；没有执行真实签名、托管工作流或 GitHub 发布。本记录不包含尚在独立增量整合的多屏、文件跨进程恢复和累计配额，也不覆盖新 JNI/APK、Android API 30–36 最终矩阵、ARM64 真机、已安装产品、公网 ACME、跨网或 72 小时验收。
