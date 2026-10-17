# 会话重连与双方证明

重连只替换同一已批准资源的连接。双方安装密钥分别签署 `RECONNECT` 用途的 `DeviceActionClaims`：挑战为完整当前许可的 SHA256，payload 为 `ReconnectionChoice` 的确定性 JSON 摘要，包含完整许可摘要、严格下一连接代次、严格下一租约序号和 32 字节随机 nonce。摘要、nonce 使用规范 base64url。签名中的 account 为原许可的控制账号；HTTP 登录仍分别核对当前设备归属，控制方提交必须使用原申请的登录。

schema 14 每资源保存一份 pending offer 和最新已提交 receipt。迁移默认空表，不改变授权。恢复删除两表，并轮换安全代次、撤销登录和会话。当前许可、remote_requests 和 sessions 的连接代次须一致。

| 接口 | 行为 |
| --- | --- |
| `POST /remote/{id}/reconnect/offer` | 原控制登录提交安装签名。相同 offer 幂等，同一当前许可的不同 offer 冲突。当前许可变化后可替换旧 pending offer。 |
| `GET /remote/{id}/reconnect` | 当前参与账号读取已验签证明，或仍为完整当前许可的最新签名回执。读取不延长期限。 |
| `POST /remote/{id}/reconnect/approve` | 被控当前登录及安装签名确认精确 choice。控制账号不能确认另一账号的被控。相同确认幂等。 |
| `POST /remote/{id}/reconnect` | 原控制登录提交精确双方签名，事务复查当前许可、设备/账号、策略、恢复代次、原登录、信任/密码授权和到期时间，比较更新请求与 session 连接代次、租约序号，清除旧信令，并保存回执及审计。 |

新许可只改变连接代次、租约序号和签发时间。权限、路径、双方密钥、能力、资源与原到期时间保持；重连不能延长访问。后续续租仍需现有双方续租证明。新代次使旧节点资源绑定失效；退役 allocation UUID 不复活，已承诺容量按原签发期限保持，新连接需要新 UUID 和独立容量准入。

`ReconnectionGrantClaims` 绑定完整旧许可摘要、包含双方签名的精确请求摘要、nonce 和完整新 `SignedPermit`。使用固定 permit issuer 的独立 `NestLink/v15/reconnection-grant/v1` 签名域，声明最多 32 KiB。内外签名都须验证；请求摘要或新许可任何其他字段变化均拒绝。

数据库提交但 HTTP 响应丢失时，相同请求只在 receipt 的 next 仍为完整当前许可时返回同一许可和确定性签名回执，不再写数据库或重算期限。续租、再次重连、策略变化、撤销、授权失效、退出、恢复或到期都会使旧重试失效。

共享原生/WASM SDK 经独立 HTTPS 控制通道交换证明。控制侧使用同一 attempt 重试；被控只确认固定 choice 并等待精确请求绑定的回执。读取旧交换回执可以等待新 offer，不能签署与本地当前许可不一致的 choice。双方核对固定签发方、部署、安全代次、当前 SDK 登录、peer 密钥和完整当前许可。HTTP 读取、确认和提交受原请求单调时钟及原到期时间约束；重试和结果复用不重启预算。

原生入口 `reconnect_native_controller/host` 消费并停止旧 `NativeSession`，等待现有停止处理器和有界通道清理后交换证明，关闭旧发送队列。`ReconnectedPermit` 携带原请求时钟；`reconnection_endpoint` 构建新候选端点并保留原单调授权截止时间；`runtime_clock` 将同一时钟带入新的 SessionSetup/native proof。系统网络监视器可随配置绑定到新端点。候选发现、新分配、传输选择和双方原生证明仍分别受现有授权检查。

开发验证包括不同账号及同账号独立被控登录、重复/坏签名/错代次、独立 SQLite 写者竞争、审计失败回滚、旧信令清除、恢复/撤销/到期，以及实际 HTTP 响应在提交后丢失。WSS 内层 TLS、外层与内层 QUIC 在旧两端停止后，以新 UUID、新代次完成双向合成业务帧。此范围不替代已安装应用的自动检测与调度、WebRTC 媒体、TURN、真实跨网、72 小时运行、容量或 G0–G6/A01–A21 正式验收。
