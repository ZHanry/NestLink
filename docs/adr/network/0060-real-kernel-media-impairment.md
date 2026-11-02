# 原媒体与文件并发使用真实内核弱网

状态：源码实现，等待 GitHub 托管 Actions 编译和实际执行；不构成 W31 或 AC53 完整通过。

现有媒体单元测试会注入接收报告、丢帧和背压，但不足以证明物理带宽
从 20Mbps 降至 5Mbps 时的真实发送队列、文件竞争和输入调度。比较手写
用户态代理、成熟网络模拟工具和 Linux 内核 tc，选择托管 Linux runner
自带内核的 HTB、netem 与 fq_codel。iproute2（GPL-2.0）仅作 Actions
验收工具，不链接或分发到产品；ethtool 只读取 loopback offload 状态。
不新增产品网络调度器或替换 Quinn 的拥塞控制。

复用原签名 Session、双方安装身份 pin、原 QUIC/mTLS、VideoSender/
VideoReceiver 的 VP8 编码解码与接收反馈、FileReadServer/FileReadClient
及整文件 SHA 验证、InputController 的 epoch 和序号检查。新增 feature
只启用 Linux 专用实验，普通测试库存与原 15 秒 fixture 保持不变；仅
本实验显式授予 Input，由独立 fixture authority 在固定 60 秒总期限内，
每 5 秒签发并验证原 15 秒租约的下一序号；不延长单张租约或产品门槛。
真实磁盘读取使用固定根 UUID
和唯一文件名；不把测试文件适配器暴露给产品。

driver 从已完成原身份和 Session 证明的两端获取实际 UDP 端口，只匹配
loopback 上这两个端口的 IPv4 UDP 包。其他流量进入独立高带宽类别。
两方向初始各 20Mbps，内核 netem 配置 1% 随机丢包，随后各降至 5Mbps。
保留 GSO/GRO 状态和实际队列计数；配置 1% 不等于独立测得每个 UDP
数据报恰好 1% 丢失。开始前拒绝覆盖任何非 noqueue 的既有根队列，退出
只删除自己建立并重新核对 handle/kind 的队列。只有 tc 子命令使用 sudo；
编译、业务进程和文件均由普通 runner UID 所有。

生产新增只读统计记录实际 codec.set_bitrate 成功后的码率、生产 cadence、
观察时间及已进入原队列的字节数。它不是网络交付、呈现帧率或可用带宽
估计。实验不得直接修改生产预算；降档必须来自原媒体自己的反馈和背压。
保留原物理限速操作至实际预算变化不超过 2 秒、输入分派 p95 相比独立
基线增加不超过 10ms 的门槛，每阶段至少 100 个实际投递输入样本，并
要求持续解码呈现和至少一次真实 4MiB 文件完整验证。任一不足均失败。

采集内容为动态伪随机像素，输入 adapter 只观察实际 InputController
分派时间，没有 OS 输入副作用。此实验覆盖托管 Linux 内核和原生产
调度机制，不覆盖 Windows 精确 H.264/AppCore、物理 GPU、OS 输入到
显示、独立 NAT 或完整 AC53。真实设备验收仍须由其独立证据结项。

性能实验构建口径修正：实际 source62bdafa/run41372314200 时间线显示，
未优化的 Rust 颜色转换/codec 开销使 cadence 降至20–25fps，进入视频
队列的实际负载可能低于5Mbps，而显示的目标仍为8000kbps。仅目标大于
5000不能证明阶跃前提。对比减少像素/负载、放宽2秒门槛和使用产品
优化构建，选择原 Cargo release profile；不改几何、随机图像、fps上限、
文件并发或任何时限。新增四秒并发窗口的实际视频payload速率必须
大于5Mbps，未满足即失败。该速率仍只证明原队列真实输入，不冒充
网络交付或显示帧率；原独立媒体回归和严格lint继续使用原构建口径。
此构建调整不是对原失败的重新判定，新源码仍须同源实际执行。

同源验证：source09fee9572e77d72a522a35dfcdc33a90327426a1 的
GitHub-hosted run41373125182 整轮success；原105媒体回归、严格lint与
真实内核实验通过，13个receipt引用文件SHA逐项核验。实际阶跃前
7.186Mbps，降档1134.747ms，输入dispatch p95分别596/570/453us，
两次4MiB整文件校验、614个输入和持续呈现，原qdisc已清理。该结果
仍限synthetic capture与dispatch observer，不是OS输入显示/Windows
精确Core/GPU或整组AC53。详见media-real-impairment-09fee95.json。
