# 有限离线私有服务的驻留命令行

这是原有 `nestlink-daemon private-service-proxy` 的独立离线入口。两端必须先在线完成同一完整授权草案的审核、各自签名和一次性消费，再保持原来两个进程运行。仅使用直接 QUIC；当前接通 TCP、HTTP 和带本机可信 CA 校验的 HTTPS 后端。UDP、TLS 备用承载和离线远控仍分别记录后续验证，不能用此入口宣称全部 W27 完成。

两端先用本产品既有登录流程启用受保护的登录恢复，并注册本机设备。普通用户运行以下命令；每个进程只拥有原有的一个登录及安装运行锁：

```text
nestlink-daemon private-service-proxy --state-dir <本机私有状态目录> offline --space <空间 UUID> --role host --listen <可达的本机 IP:端口>
nestlink-daemon private-service-proxy --state-dir <另一台设备的私有状态目录> offline --space <同一空间 UUID> --role source --peer <宿主实际监听 IP:端口>
```

标准输入是一行一个 JSON 命令，最大 65536 字节。标准输出是一行一个 `{ "event": ..., "data": ... }` 事件；`command_failed` 表示当前命令失败，原始进程及已有 owner 的终态不会因此重建。交互终端直接粘贴 JSON 即可。脚本必须持续保留标准输入；EOF、Ctrl-C、本机退出登录、身份文件变化、安装维护、原定期限或累计额度耗尽都会停止原 owner 并等待实际清理。Unix 平台若状态目录过长，可为 source 显式传入 `--endpoint-dir <较短的现有私有目录>`；该目录须通过原有的本机所有权检查。

1. 空间管理员执行 `{"command":"policy"}`，根据返回的 revision 执行 `{"command":"enable","expected_revision":0,"enabled":true}`。已有 revision 必须原样传入，不能假定为零。
2. 宿主执行 `{"command":"service","service_id":"<服务 UUID>"}` 查看完整服务及 exposure，然后提交本机明确选择：

   ```json
   {"command":"target_review","service_id":"<服务 UUID>","protocol":"tcp","target":"127.0.0.1:8080","approval_ms":3600000,"private_maximum_bytes":1048576,"public_maximum_bytes":0}
   ```

   HTTPS 还必须提供 `backend_server_name` 和 1 至 8 个本机 DER CA 文件路径组成的 `backend_ca_der` 数组。此信任材料及地址由宿主用户选择并保留在内存中。确认输出的原始完整服务定义、固定地址、期限和预算后，执行 `{"command":"target_approve","target_digest":"<原样复制 target_review 的 target_digest>"}`。
3. 本机目标批准及 exposure 更新会撤销旧消费者 ACL、旧 lease 和旧 publication。宿主根据输出的新 exposure revision 明确重新授权消费者：

   ```json
   {"command":"grant","service_id":"<服务 UUID>","request":{"expected_exposure_revision":1,"subject":{"kind":"installation","installation_id":"<来源设备 UUID>"},"expires_at_unix_ms":<有限的未来 UTC 毫秒>}}
   ```

4. 完成本机目标和 ACL 后，两端分别执行 `{"command":"begin"}`。保存输出的 endpoint、device_id、process_nonce；nonce 只属于这个仍在运行的原始进程。再次 begin 被拒绝。进程退出后不能导入旧签名文件恢复它。
5. 任一有权端根据实际 policy、服务和 exposure revision 创建完整草案；`process_nonces[0]` 为来源，`process_nonces[1]` 为宿主，必须从这两个仍在运行的进程复制：

   ```json
   {"command":"draft","request":{"consumer_device_id":"<来源设备 UUID>","service_id":"<服务 UUID>","process_nonces":[[<来源的 32 个字节>],[<宿主的 32 个字节>]],"expected_policy_revision":<当前网络策略 revision>,"expected_service_revision":<批准后的服务 revision>,"expected_exposure_revision":<当前 exposure revision>,"direct_transports":["quic"],"maximum_bytes":65536,"maximum_connections":4,"expires_at_ms":<固定未来 UTC 毫秒>}}
   ```

6. 两端都执行 `{"command":"review","bundle_id":"<草案 UUID>"}`。`complete_bundle_review` 展示完整连接、双方设备/账号/公钥/进程 nonce、具体服务定义及目标摘要、原定期限、总字节和连接数限制、部署及权限 epoch 和完整 digest。两端用户各自确认后，分别执行 `{"command":"approve","draft_digest":[<原样复制审核事件的 32 个字节>]}`。不接受只审核部分字段，也不接受另一 digest。
7. 双方批准后，服务原有账号/设备/节点/资源总额度账本原子扣除整个承诺；第一个批准不扣额度。期限届满、撤销、断线和客户端报告均不退回这个承诺。两端分别执行 `{"command":"activate","draft_digest":[<相同 digest>]}`。每端只允许一次 activation 尝试；丢失响应时不会重试生成新 owner。
8. 宿主 `status.direct_address` 是原 QUIC 监听地址；来源 `status.native_endpoint` 是同用户认证的 Unix socket／Windows 字节管道。原有命令可将 stdin/stdout 接入该端点：

   ```text
   nestlink-daemon private-service-proxy --state-dir <来源状态目录> connect --endpoint <native_endpoint>
   ```

   HTTP/HTTPS 服务发送 HTTP 应用字节；HTTPS 后端由宿主用本机信任材料单独校验证书。Windows 字节管道没有独立的写半关闭 EOF，应用必须自带帧边界。
9. `{"command":"status"}` 显示 **离线仅直连**、固定失效时刻、剩余毫秒、累计剩余额度、累计连接、当前连接、恢复同步和清理状态。重连沿用同一累计 owner。每次 I/O 受同一锁及额度门禁控制，空闲时每 250ms 检查原定期限及本机进程终态。
10. 原运行时每两秒尝试受认证的中心探测；收到有效响应后先暂停所有业务 I/O，再从中心同步原授权、ACL、策略及最高撤销 epoch。同步失败永久停止。`{"command":"recover"}` 可主动执行同样的暂停和同步。中心失联期间无法立即获知中心撤销；界面始终显示最迟影响时刻为原定 expiry，且不会自动延长。
11. `{"command":"revoke","bundle_id":"<原授权 UUID>"}` 使用原有在线撤销 API；`{"command":"stop"}` 结束驻留。`cleanup_pending` 保留原来的 join 和 owner；只有实际 QUIC socket 释放回执及原私有端点移除完成才输出 `stopped`。`cleanup_failed` 必须处理，不能当作已完成清理。

所有编译、lint、格式化和业务验收由 `offline-authority.yml` 在 GitHub 托管 runner 上执行。本机不运行源码构建或测试。已验证范围以对应源码 SHA 的 Actions receipt 为准；命令行编译通过不等于目标机器全量验收。
