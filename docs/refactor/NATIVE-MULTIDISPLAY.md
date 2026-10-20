# 原生多屏接线状态

2026-10-15 首批 26 个文件、后续 Android 兼容及共享音画时基已合入生产树。首批不可变交付为 `artifacts/native-multidisplay-av-draft-20261015/`；后续整合记录分别为 `artifacts/core-verification/android-native-displays-20261015-integration.json` 和 `artifacts/core-verification/native-av-timing-draft-20261015-integration.json`。已保留 runtime 和本地 IPC 的现有服务 host 修正。Windows/Linux 协议 41 项、媒体 36 项、输入生命周期 30 项、Core 4 项及 IPC/桌面 41 项所选回归均已执行并通过；精确输入与旧失败/后续修复见 [集中检查](NATIVE-INTEGRATION-CHECKS-2026-10-15.md)。真实系统/硬件验收尚未完成。时序边界见 [音画时序](NATIVE-AV-TIMING.md)。

Windows/X11 先进行有界只读枚举，由本机明确选择本次允许分享的集合和初始屏。Wayland 使用原 portal/用户系统选择返回的实际 grant 集合，保持原 session 与 PipeWire node，不替换授权。远端只收到这个已批准集合，并在其中请求切屏。单屏最多 64 MiB、集合最多 64 来源及 128 MiB。

唯一 wire 源为 `protocol-spec/native-displays.rs`。`NLDF` v1 的 BEGIN/ENTRY/COMMIT/ACK 事务绑定完整 request ID、connection generation、revision 和 SHA256；解析严格拒绝未知版本/种类、截断、尾随字节和超预算包，不猜测旧格式。编码恢复反馈使用同一个显式 envelope。每个证明会话批准的来源集合固定。Android host 仅分享原 MediaProjection 的 source 0；View-only 会话允许在同一来源集合、同一系统 grant 内通过新目录事务刷新几何，Input 会话旋转仍停止并等待真实清理，不能借几何刷新扩大授权。

切屏先暂停视频、丢弃旧排队帧，经同一真实 input owner 释放所有按键与指针，再推进 layout/input epoch；控制端先为精确目录版本和选中布局创建解码器，再发送 SelectionAck，宿主收到精确确认后才恢复视频。解码准备最多两秒且仍受原 lease 约束；重复 Selected 也必须检查当前就绪状态，不能借旧目录确认新选择。握手使用固定十秒期限，在持续繁忙的输入下也检查。每个物理来源保留自己的序号、PTS、反馈和关键帧历史，不把所有来源重编号为零。布局重叠的 portal 屏幕仍按获准 node 选择。

Core/IPC/桌面视频订阅固定完整 selection。旧订阅不能消费新来源或新布局代次的第一帧；切换中的输入被拒绝。会话或本机 generation 变化后，旧操作不能修改替代会话。静态库、实际 QUIC/私有 D-Bus 测试源码及 Windows/X11/Wayland 硬件验收的状态分别记录，不用编译结果代替实际系统能力。
