# Linux 系统音频适配

`nestlink-platform-audio` 已实现 PipeWire 播放设备的系统音频采集与播放。`LinuxAudioEndpoint` 只从本机 `Audio/Sink` 枚举产生，不接受远端 node ID 或麦克风，选择后固定端点身份。产品须在同一批准 lease 的 `AudioSender/AudioReceiver` 下使用设备。平台库仅验证系统事实。

## 会话、端点与真实图连接

`nestlink-platform-session` 共享原第一方 logind 观察器，X11 输入与音频使用同一实现；Wayland 音频只读取 GUI PID 对应的实际登录事实，不打开屏幕或输入门户。观察器固定 root-owned system bus 上 logind 的原 unique owner、会话路径、用户、类型与活动/锁定事实。快速锁定后解锁、owner 替换、监护心跳超时均保持终态。

音频保留私有 runtime 目录 FD，通过该 FD 连接 `pipewire-0`。检查目录属主/权限、socket 类型/属主、连接前后 inode、SO_PEERCRED；随后固定原 socket dev/inode、peer PID/UID、core cookie、node ID、64 位 object.serial 和 node.name。运行中继续检查原 socket。删除、替换、属性变化或服务退出禁止继续交付 PCM，也不会切换到默认输出。

`target.object` 是请求，不能证明 session manager 的实际连接。适配器检查每条涉及本流的 Link 两端，必须连接原 sink；每次处理 PCM 前 core sync 刷新 registry 事实。首次实际连接丢失或错误接线为终态。inactive stream 在激活后才协商 PCM 是合法行为：初始化只等待端点/连接事实，开始后仍需在 250 ms 内实际确认固定格式，否则停止。

## 格式、时间与队列

独立工作线程拥有原生资源。请求 48 kHz 交错 i16 单/双声道；系统 PipeWire 转换至实际驱动格式。适配器验证实际协商格式、映射权限、offset/stride/尺寸、flags/对齐，silence 显式置零。采集按真实 graph ticks/rate 转换 sample clock，允许不超过两样本的重采样舍入；缺口丢弃部分 chunk，回退/graph rate 改变终止旧流。

采集每包至多 1920 frames，组装为 960-frame/20 ms chunk，队列至多五个 chunk，超过 100 ms 的旧 PCM 丢弃。播放队列最多一个待播 chunk 与一个部分 chunk（40 ms），原生 queued+buffered+本次写入最多 2880 frames（60 ms）。这些是第一方排队预算，不能证明驱动、硬件或全链路可听延迟。等待 registry sync 时不排入未填充播放缓冲，避免重复旧 PCM。

枚举/初始化不 arm 音频；第一次经业务控制器检查的 poll 或 enqueue 才启动。250 ms 工作线程 heartbeat、原 session/socket/endpoint/Link 失效和业务撤销停止旧设备。socket 文件系统检查只在工作线程执行，位于共享状态与业务许可锁之外；阻塞的系统调用不能更新缓存 heartbeat。reset 立即禁止出入队、清空部分播放，由原 worker 停止/flush/释放资源，等待使用首次 150 ms deadline。首次清理错误和超时保留，晚完成不能改报成功。

## 开发验证与本机验收入口

私有 system bus 与独立 PipeWire 软件图验证生产 API：X11/Wayland × 单/双声道、实际 signed permit 与双方持钥证明下的采集/播放、业务撤销、快速锁/解锁、服务退出、socket 替换/恢复、同名 sink 重建和运行中错误 Link。44.1 kHz 六声道软件图实际 clock 被断言为 `1/44100`，验证转换出的 48 kHz 双声道合成音。测试不访问宿主声音、麦克风或显示服务。

```sh
python3 scripts/refactor-linux-audio.py
bash scripts/test-pipewire-audio-sanitizer.sh
```

生产 C 边界在 ASan/UBSan 下验证 100000 个对抗 PCM 输入、映射权限/尺寸/offset/stride/silence、真实 Link 规则和 64 位 serial 解析。动态系统 libpipewire 本体未插桩。

在真实图形会话终端中可以枚举或初始化选定输出。`--gui-pid` 默认当前 probe PID；守护场景必须传入经本机认证的 GUI PID。实际 logind/session manager 不可用时明确失败。

```sh
cargo run --locked -p nestlink-platform-audio --example linux-audio-probe -- inventory
cargo run --locked -p nestlink-platform-audio --example linux-audio-probe -- initialize --device 'inventory 的 node.name' --serial 123
```

操作者准备读取选定输出的 system mix 并播放两秒 440/880 Hz 合成信号时：

```sh
cargo run --locked -p nestlink-platform-audio --example linux-audio-probe -- roundtrip --device '实际 node.name' --serial 123 --channels 2 --allow-system-audio
```

检测仅记录聚合幅度、时钟与停止结果，不保存原始声音。本批没有在真实 GNOME/KDE 桌面运行此检测。真实硬件/热插拔、门户与音频的共同产品生命周期、Opus/跨网接入、长时漂移/音画同步、ARM64/Android、安装产物和正式 A01–A21 继续实施。软件图证据标记 `product_acceptance=false`。
