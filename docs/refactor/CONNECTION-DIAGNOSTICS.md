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

错误使用固定分类，首个错误保留在 Web 有界环之外；部分前置管理/授权步骤和宿主错误
仍需细化分类。诊断采样失败、时钟缺失或本地存储失败不改变媒体权限、租约、
撤销或连接状态，也不延长运行期限。
