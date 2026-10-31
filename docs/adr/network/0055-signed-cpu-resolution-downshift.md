# 原授权显示源内的实测分辨率切换

状态：源码实现，待新的同源 GitHub 托管运行；W31/AC53 整体验收未通过。

复用原 FormatSet、方向探测、SoftwareH264Execution、VideoQuality、显示源 ACK、
格式 ACK、接收端代次隔离与桌面输入映射。比较 libyuv（新增独立原生构建与分发）
和 fast_image_resize（成熟 Rust SIMD packed-pixel 实现），选后者的有限 BGRA 适配。
固定 fast_image_resize 6.1.0，上游 v6.1.0 对应
6dc1fe2750a3f41a047ee69ca6fa4517d752d017，registry SHA256 为
e9c50201dc184ba6553da1695aac20a042efffbe2d84542cee31917c86c3ab1e，
许可 MIT OR Apache-2.0。仅启用 std，不引入 image/rayon/新线程池；复用已锁定
cfg-if、document-features、num-traits、thiserror。锁由 Actions 派生并逐文件核验。

原显式 CPU 上限下最多三个候选：全尺寸全速、全尺寸 3/4 帧率/码率，以及
半帧率/码率。只有宽高均能精确减半且减半后仍为偶数时，最后一档改用半宽半高。
不能整除时保留原尺寸，不裁剪、不改变长宽比、不补报未探测的缩放格式。
每档仍独立完成实际 encode/decode、SPS/几何、16 个输出、flush 和 close，
全部成功才出具原历史公告。原单 worker、30 秒探测预算与失败隔离保持。

每个捕获帧继续来自原已批准屏幕。缩放仅运行在原媒体 worker，复用上游
Nearest 算法，四个 BGRA 通道原样采样，不执行颜色转换或伪造高位深；相比
双线性存在锯齿取舍。该算法不创建上游中间像素缓存，并检查缓存字节数为零。
输入及缩放输出保持原 zeroizing 生命周期，尺寸均受原 64MiB 限制。

选择器只接受双方原签名交集内、同编码族/色彩/深度、长宽比一致且不大于原
显示源的完整格式。降档不修改输入坐标系、显示源授权或 layout epoch；恢复
仍以上限源为边界，且依赖原连续健康窗口。新格式先 checked close/join 旧编码器，
首个实际 sealed AU 经原提案/ACK 后才传输。原绑定校验仍要求物理源的完整尺寸，
wire 的图像尺寸来自当前已确认的实际执行 receipt，接收端按该签名格式配置
新的实际解码器。尺寸错误、签名集合外格式、长宽比变化和旧 receipt 均拒绝。

桌面已有 pointer_to_logical 依照图像显示矩形映射至原批准逻辑区域；不把缩小
后的编码尺寸当作新的输入权限。补充负原点及半尺寸图像映射回归。Windows
真实 Core 回归要求半尺寸实际 MF 解码像素、原显示源与选择保持、原 ACK 阻挡、
旧代次回收及错误源尺寸拒绝。此验证不替代实际 20→5Mbps、1% 丢包、文件并发、
2 秒降档和输入 p95 增幅 10ms 的完整 AC53 门槛。
