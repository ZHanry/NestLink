# 三端建链诊断

Web 诊断导出的 `controller_timeline`、daemon 的私有
`browser-host-diagnostics.jsonl` 与服务端 JSON 日志可以按同一请求关联。
服务端记录验证和持久化成功后的 `SignalAccepted`，以及构造远端查询响应时的
`SignalResponsePrepared`。后者不能证明响应送达或对端已消费。
控制端在验证信令并匹配当前 offer 后记录 `SignalConsumed`，设置浏览器远端描述成功
另记 `RemoteDescriptionSet`；宿主在验证 offer 后记录远端信令摘要。

```text
python scripts/refactor-connection-timeline.py --controller controller.json --host browser-host-diagnostics.jsonl --server server.jsonl --output joined.json
```

输出文件必须不存在。每个输入上限 16 MiB，Web 时间线最多 128 项，日志各最多
10000 项；应先截取一次回归所需日志。工具只写白名单中的哈希、固定阶段、序号和时长，
不复制自由文本、SDP、候选地址、令牌、密钥或设备名称。

关联键包含请求 SHA-256、连接 generation、双端设备 SHA-256，以及信令的发送端、
network generation、sequence、description sequence 和 lease sequence。
新的候选快照不能证明旧快照已消费。宿主快照包含最新本地和远端信令序号，
中间快照或私有环缺失时，工具保留“未观察到消费”的状态，不能把缺日志判为连接失败。
服务端去重缓存最多 1024 项，旧项淘汰后可能重复记录。

各端使用本地单调时间，Unix 时间仅作为日志关联锚点。
报告只计算控制端同一单调时钟上的阶段间隔，不跨机器相减。
Web 首包、首解码是定时读取 WebRTC 统计时首次观察到计数增长的时间；
video 进度来自媒体时间推进。它们都不是 compositor 实际呈现时间，
也不能代替独立的输入到显示测量。

Web 的 `controller_preflight_timeline` 覆盖身份加载、创建请求、等待批准、宿主就绪、
获取许可及创建 peer。许可签发前 generation 为0；取得已验证许可后才能附加其关联键，
不能把不同请求、设备或 generation 的观察合并。前置与 peer 使用各自本地单调锚点，
不可直接相减。未创建 peer 的失败也能导出，不能据此判定 ICE 失败。
结束后的最后一份脱敏快照在当前设备页面保留，重新连接、换设备或退出登录时清除；
该快照不保留 peer、密钥、权限所有者或浏览器资源。导出无需等待首帧或接收统计。

错误使用固定分类，首个错误保留在 Web 有界环之外。SDK 区分登录、撤销、运行授权到期、
建链预算耗尽、信任失败、无效响应与管理网络失败；宿主沿用同一分类而不记录原始错误。
尚未有明确类型的底层失败保持 unclassified，不能从错误字符串猜测原因。
诊断采样失败、时钟缺失或本地存储失败不改变媒体权限、租约、
撤销或连接状态，也不延长运行期限。

## ICE 接收任务和 socket 边界

宿主 `peer_timeline.ice_ingress.sockets` 保留最多 16 个本地候选的
接收任务创建、等待初始化、初始化信号关闭/滞后、开始接收、正常关闭、
提前关闭、任务取消和接收错误。每个候选使用本地不透明 key、本地端口和地址族关联
系统 UDP 表，不导出候选 IP 或 ICE 凭据。时间从记录器创建起计算，不能跨端相减。
超出容量的事件计入 `dropped_events`，首个接收退出和首个错误不会被后续关闭覆盖。

`sends_accepted` 只表示发送调用接受了整个 STUN 消息；零字节/短写单记
`short_sends`，它们都不是物理网卡出口证据。`datagrams_received` 位于
`recv_from` 成功返回之后，协议校验之前。只有同时检查 receiver_ready、退出原因、
错误和接收计数，才能判断接收任务的状态。错误仅输出类型、固定分类及可用 OS 码；
上游已经转为自由文本的错误仍无法恢复其原始类型，不根据文本猜测 TURN 原因。

## 桌面弹窗诊断自检

已安装的 `nestlink-desktop.exe --check-diagnostics --state-dir <目录>`
只检验私有诊断文件的写入和读回，生成 `desktop-diagnostics-check.json`；
不启动窗口或远控，不修改安装身份、密码或会话。此自检通过仍不能证明 UI 路径已执行。

实际 App::ui 每秒记录一次 `frame_heartbeat`，即使弹窗未打开；
`local-session-layout.jsonl` 仍限制 96 条 / 64 KiB、每秒最多写入一次。
记录包含 viewport ID、DPI、快照 revision、弹窗请求状态及累计几何次数。
弹窗记录按钮 ID、可见矩形、交互矩形和启用状态；按下/松开记录指针坐标及点击结果。
无效坐标单记 `geometry_rejected`，空目录次数和写入错误保留到后续心跳；
写入恢复后仍可读到此前的 `write_failed`。

取证前分别确认存储自检和真实窗口心跳存在，再检查本次打开弹窗是否出现
`button_geometry` / `window_geometry`。缺文件或缺几何不能作为“按钮稳定”的依据。
这些记录不含桌面内容、键盘文本或用户授权凭据。
