# Hub / Client 历史告警分类（脱敏）

已逐条读取默认规则报告所指的原提交 blob，覆盖 Hub 38 条和 Client 143 条。没有执行历史代码、改动旧工作树、重写历史、使用凭据访问服务或执行撤销。报告不包含 token、API key、密码、私钥或测试 dummy 原值。

| 分类 | 数量 | 本地证据 |
| --- | ---: | --- |
| 契约 / 安装资产 SHA-256 | 32 | 核对字段、哈希形态和所属文件清单 |
| 签名测试向量中的公钥 | 12 | 两仓文件完全相同，test_only；permit 和两种 proof 离线验签通过 |
| 翻译帮助中的服务器公钥示例 | 124 | 所有命中均为同一 32 字节公钥，位于私网地址示例；代码将该类值作为 PublicKey 验签 |
| 声明的解析器 dummy | 7 | 位于 cfg(test)；离线解码与原测试注释声明完全一致 |
| 解析器测试中的同一公开公钥 | 1 | 与前述公钥示例相同 |
| libsodium API 导出标识符 | 2 | 函数 / 常量名称，没有密钥字节 |
| 上游 Firebase 公开客户端配置 | 3 | 确实存在 API key；公开上游来源已证实，当前限制和云账号归属未核实 |

逐条结果：`hub-client-classification-2026-10-13.json`。稳定 ID 使用组件和原报告序号，并绑定原报告 SHA-256；原 Gitleaks fingerprint 在同一编码行命中多个字段时不唯一，所以不独自用作 ID。每条记录包含路径、commit、rule、行列范围、原 blob SHA-256 和分类依据。

## 三条公开客户端配置

待记录明确保留 / 复用处置的 ID 是 `client-139`、`client-140`、`client-143`，没有剩余未分类 ID。这三条不是“已确认泄漏可滥用服务器凭据”。Firebase 客户端配置中的 API key 通常会公开分发；公开分发也不能单独证明 API 限制和 Firebase 数据规则充分。

三个原始 SHA 均经无需认证的 GitHub 公开 commit 元数据核对，在 `rustdesk/rustdesk` 上游存在：

- `client-139`：[2022-05-17 上游提交](https://github.com/rustdesk/rustdesk/commit/4887cdb7566c6231a3d1879e94d49c6d6a76b4ba)，路径 `flutter/web/index.html`。
- `client-140`：[2022-01-25 上游提交](https://github.com/rustdesk/rustdesk/commit/3fd0982af57fb62e8f994bedfc546310189df0c3)，路径 `web/index.html`。
- `client-143`：[2020-11-29 上游提交](https://github.com/rustdesk/rustdesk/commit/87343945237b5bbc21733dcbdf5409926f7f71d8)，路径 `flutter_hbb/android/app/google-services.json`。

公开查询只发送了 commit SHA，没有发送任何 key 值。保存的脱敏来源材料为 `firebase-upstream-provenance-2026-10-13.json`。原配置项目命名属于 RustDesk 谱系，时间早于 NestLink；没有证据表明当前用户新增了私密服务器凭据。报告不建议一律作废或强制重写这些公开上游历史。保留历史时应记录其来源，NestLink 产品不应复用上游云项目；如需复用，必须另行确认项目所有者授权及应用/API/数据规则限制。

## 签名向量的时间与范围

测试 permit 的时间窗为 **2033-05-18 03:33:20–03:34:05 UTC**，截至本次审查并未过期。命中项是公钥；离线验签通过并不证明整个测试 permit 或测试信任锚可用于生产环境。生产信任隔离尚未由这份历史分类报告验证。

本报告仅分类已有扫描结果，不代替新一轮完整历史扫描、许可证来源审计、凭据处置证明或总体历史导入批准。`history_import_cleared=false` 保留该范围界限，并非要求删除公开历史。可将本 JSON、说明及公开来源 JSON 作为脱敏材料纳入文档；不要复制原始未脱敏源码片段。核验脚本 `classify-existing-findings.py` 仅本地读取原提交及已保存的公开来源材料，生成报告时检查关键候选值没有进入输出。
