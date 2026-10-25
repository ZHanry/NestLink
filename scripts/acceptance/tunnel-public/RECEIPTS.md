# 实际产品租约证据

这组工具只采集和核验已经由用户批准、正在运行的单个服务。先按 README 完成
实际来源确认、精确 /32 ACL、本机目标批准和产品发布。TCP、UDP 使用独立新轮次。
所有产品编译、测试编译和打包在 GitHub。工具不执行批准、发布或停止操作。

将 `plan.template.json` 复制到私有证据目录，填写实际源码、Windows 二进制摘要、
批准回执摘要、服务/运行时代次、批准前后 revision、目标/定义摘要及独立固定的
部署 node-policy 公钥。全 null 模板不能运行。nonce 只保存 SHA256。
这些外部来源信息仍须独立核对，采集工具不会证明操作者填写的信息为真。

Windows 当前登录用户的既有 Python 需要 cryptography 和兼容的 pyOpenSSL；
认证传输使用现有 DPAPI IPC 状态，仅允许 Snapshot 和只读租约观测。没有安装
依赖的自动操作，不将账号 token、IPC 密钥、TLS 私钥或完整 snapshot 写入结果。

先做两次有界发现，随后将返回的 publication ID/generation 和经原始公开委托
核验的 service issuer 固定到新的流量计划：

```text
python -B collect_lease.py --plan PRIVATE_PLAN --phase traffic --samples 2 --interval 0.5 --output PRIVATE_DISCOVERY_JSON
```

服务器数据库路径必须来自当前真实部署配置。用只读采集器在私有目录记录本轮
精确原始租约字节；它只依赖 Python 3.10+ 标准库，最多 90 秒：

```text
python3 -B server_claims.py capture --db ACTUAL_DATABASE_PATH --plan PINNED_PLAN --seconds 90 --output PRIVATE_SERVER_CAPTURE_JSON
```

原始租约可能包含用量授权材料，采集文件以独占创建和 0600 权限写入，保留在
私有服务器目录，不放入公开 Web、GitHub artifact 或普通验收附件。读取 live WAL
失败就记录缺失，不修改权限或忽略 WAL。

将本轮 visitor 的 steady_seconds 设为 60。在解除现有 helper 流量门之前启动：

```text
python -B collect_lease.py --plan PINNED_PLAN --phase traffic --samples 100 --interval 0.5 --output PRIVATE_TRAFFIC_JSON
```

采集受 90 秒绝对预算约束。若排队耗尽窗口，开始新的完整采集轮次。两条真实递增
签名序号必须都落在使用实际时钟偏移边界收紧后的连续流量窗口内；仅看到两个
序号或计数增长不足以证明该条件。服务器覆盖旧序号前必须及时采到，缺失样本
不能重构。

在已有可信 cryptography 运行时离线配对。可以把脱敏的客户端和 visitor 结果
传到私有服务器目录；服务器没有该库时，用授权 SSH 转移到私有本地证据目录核验，
不在服务器安装包：

```text
python3 -B server_claims.py pair --plan PINNED_PLAN --capture PRIVATE_SERVER_CAPTURE_JSON --observations PRIVATE_TRAFFIC_JSON --visitor VISITOR_JSON --output PAIRING_RECEIPT_JSON
```

配对验证独立固定的策略公钥、原始公开委托、原始租约签名、精确数据库字节、
claims/envelope 两种摘要、服务范围与采样时间。它不是完整 Rust 协议验证器，
也不是对来源计划的签名证明。输出省略原始租约字节和签名。

完成 visitor 的 stop-arm 握手后，由用户停止同一产品服务，helper 继续回包。
使用相同固定计划采集拒绝结果：

```text
python -B collect_lease.py --plan PINNED_PLAN --phase after-stop --samples 3 --interval 0.5 --output PRIVATE_STOP_JSON
```

拒绝读取仅证明拒绝，仍须审阅本机实际停止结果、edge listener/flow 清理及用量确认。
配对输出始终保留 `public_tunnel_acceptance=not_assessed` 和
`stop_cleanup_usage_verified=false`。真实流量、清理、版本及批准证据完成后再由
审阅人判定公网验收，工具不会自动修改发布门禁。
