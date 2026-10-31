# W15 原生远控 owner 与空间路径接线

## 当前实现边界

原生远控只使用现有 `nestlink_connectivity::Scheduler`、原有
`NativeEndpoint` 的 UDP / ICE、原有 TLS 与 SessionPermit proof，以及同一个
`ChannelRuntime`。AppCore 的 `NativeConnection` 负责 legacy、signed direct、
signed original route-set 与一次安全恢复的产品生命周期；没有新增调度器或登录 Client。

没有选择空间的兼容连接仍使用原 `LegacyEndpoint`。程序不会从任意管理响应自动信任
空间公钥，也不会把加入空间解释为屏幕、输入、文件、剪贴板或原始 IP 许可。
W15 尚未完成全部默认部署迁移、全部业务现场验收或 W14 连续性验收。

## 实际生产调用链

1. desktop 和 daemon 通过 AppCore 发起或接收远控请求。受信设备、密码和本地批准仍由
   原管理授权路径完成。`runtime::establish_native_session` 获取当前 approved remote、
   当前 SessionPermit 以及固定的对端设备公钥。
2. `native_recovery::authorize_native_session` 绑定账户、部署、安全 epoch、双设备、
   business generation、lease sequence、独立 permissions / paths 及实际 capability。
3. 未选择空间时，`LegacyEndpoint` 继续使用原 NativeEndpoint / Scheduler。
   选择 `space_path` 时，`runtime/native_direct.rs` 为这个精确 permit 签发独立的
   connectivity / direct PathGrant，然后经认证 GET 与本机 authority pin 验证完整链。
   选择 `route_set` 时，使用原双节点组及其独立 TransitGrant。
4. signed direct 的 `VerifiedRemoteDirect::establish` 仅允许 `PathSet::DIRECT`，
   不发现或分配 relay。它把固定 PathGrant、transport-group 与原 SessionPermit
   绑定到原 QUIC 的只读观测；实际数据仍由原 proof 后的 ChannelRuntime 传输。
5. `runtime.rs` 对视频、音频、文件、剪贴板、输入和多屏都使用同一个
   `established.session.channels()`。真实媒体 provider 发布当前本机执行证据；输入
   继续绑定 request / connection generation / core generation / display epoch。
6. session task 持有业务通道及真实平台 owner。停止后逐项 shutdown / join 输入、
   音频、文件、剪贴板、解码器、视频反馈及运输；任一 cleanup 失败均阻止恢复。

## 独立期限、撤销与取消

signed direct 路径期限取当前 permit、双成员凭据及本次最多 30 秒的共同下界。
完整验证器再次检查成员 / connectivity / path 的嵌套期限。建立时使用原
`Session::cap_lifetime_deadline_ms`，并由原 LeaseControl supervisor 独立等待该
monotonic deadline；业务续期和 Actor 忙碌均不能延长空间路径权限。终止后同一
session task 等待业务与原物理 UDP owner 的释放回执。

Actor 原本的周期任务将唯一登录 Client 临时借给 session task，以认证 GET 读取当前
path。相同 pin、permit digest、成员和响应指纹必须保持一致；撤销、替换、读取失败或
原期限届满均停止。操作取消和 OS network generation 改变也被同一 owner 观察；取消
建立时发送 cancel 并等待原 SDK cleanup，不遗弃已经打开的运输 future。

signed direct 当前发生传输故障会明确停止，不自动改走 relay、不复用旧 input / 媒体、
不把 direct-only group 转为 relay group。双 relay route-set 的一次安全恢复另需新
business generation、新 allocation/path/transit、fresh node challenge 与新业务 proof；
该功能仍受 W14 待通过证据限制。

## 用户可操作入口

本机保存的 `NativeNetworkSettings.space_path` 与 `route_set` 互斥。
daemon 使用原私有文件读取及设置存储：

```text
nestlink-daemon --native-space-path <private-json-path>
nestlink-daemon --disable-native-space-path
```

JSON 是 `NativeSpacePathSettings`：`deployment_id`、`space_id`、32 字节
`authority_key` 数组、`controller_membership_grant_id` 与
`host_membership_grant_id`。这些是本机选定的空间与凭据标识，不能从对端信号填充。
两个成员凭据由已有空间管理流程签发，双方配置同一作用域。私有 LAN 目标仍需原本的
`private_network_prefixes` 本机批准。显式保存 direct 配置会清除旧 relay-set；反向亦然。

desktop 的「本机连接网络」提供三个互斥选择：原会话路径策略、空间仅直连、空间双中继。
用户可以编辑部署/空间、来自本机信任来源的 authority 公钥和双成员凭据编号；中继模式
另需双节点编号。任何编辑都会清除批准，只有再次明确批准才能用当前 revision 保存。
禁用空间路径会明确提示恢复原 SessionPermit 的路径策略，其中可能允许中继。
当前未提供从空间目录自动选择成员凭据或完整桌面空间成员管理。

## 自动验证与证据状态

以下测试已接到源码，必须消费对应新 SHA 的 Actions 结果才能声明通过：

- `network::routed::tests::signed_direct_readback_keeps_membership_business_pin_path_and_login_independent`：
  pin、peer key、双成员角色、request/path、relay-only path、错误 grant kind、陈旧读回反例。
- `native_tests::signed_direct_deadline_stops_idle_business_without_management_poll_and_releases_original_socket`：
  真实 QUIC / SessionPermit proof、独立短路径 deadline、无 HTTP 或 Actor 轮询仍 Expired、
  观测携带签名 group，以及原 UDP 地址可重绑的物理释放回执。
- `route_set::signed_direct_space_path_uses_original_media_and_input_owner_and_revocation_releases_pressed_keys`：
  真实管理签发、两个实际 AppCore actors、真实 VP8 编码与解码像素、真实 input owner、
  当前 path / transport-group、空间路径撤销后按键释放与终止，旧 input binding 失败。

`6602a70` 的 Network run `41163165105` / job `124424971645` 已证明原 SDK NRD2
两个真实业务测试和四个 registered-chain 测试通过，route-set recovery 三个测试仍在
提取恢复源时 `Remote(Stopped)`，产品 route-set 测试仍超时。源码随后修复了 observer
cleanup 无条件把已恢复性停止改成 revoke 的问题；尚不能把该修复视为已验证。

仍缺：新 signed direct 测试的 exact-source Actions 通过、W14 完整恢复证据、两个
Windows 目标设备上的完整附加通道 / UIPI / 锁屏、真实 GPU 与混合版本现场结果。
这些缺口分别保留；已有本机手动选择/保存 UI 不等于完整空间目录选择或连续迁移。
