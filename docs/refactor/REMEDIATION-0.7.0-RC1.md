# 0.7.0 RC1 整改与验收证据

基线：`5abb94189012f6e5a18625def84bac6c584ec244`（`v0.6.0-rc.1`）。
需求输入：2026-10-20《NestLink 对标 UU 远程：研发改进方案》v1.0。
报告的性能值是研发目标，不能当成测量结果。本 RC 尚未完成报告全部工作包，
尤其不宣称 GPU 零拷贝、H.265/真彩或 UU 等效性能；以下逐项说明实现和缺口。

| 工作包 | 已实现 | 尚需完成或资格验证 |
| --- | --- | --- |
| N01 关联诊断 | 宿主单调时钟建链时间线、候选数量、选中路径、授权与首包阶段；request 哈希、generation；64KiB 私有诊断环 | 控制端与服务端消费时序的完整关联、所有新错误分类 |
| N02 媒体 socket 选路 | 系统/物理/指定接口策略；Windows index/LUID/地址/默认路由和 metric；真实 ICE、原生 QUIC 共享工厂 | 原 HL↔外部 Edge 的对等媒体与代理流量对照 |
| N03 Trickle ICE | 双端能力协商的累计快照；不可变 SDP、候选绑定/去重/大小上界/end；漏轮询恢复、同字节重试、旧代次拒绝 | 当前仅 direct-only 开启；TURN 继续完整 gather；真实公网 restart 矩阵 |
| N04 启动授权 | 签名能力启用 30s setup；媒体/输入禁止，双方证明与双签续租后15s运行；预算不足专用错误 | 原故障环境慢网、时钟偏差与长期资格复测 |
| M01 媒体能力 | VP8/H.264 codec 抽象、实际硬编硬解探针、同 key 受限能力升级、PTS 元数据生命周期 | 共用 GPU 纹理 frame API、GPU 资源跨适配器生命周期 |
| M02 采集 | DXGI Desktop Duplication、获准 HMONITOR/adapter、GDI 降级、2秒有界恢复；静态无新画面不伪造采集时间 | 多 GPU、混合 DPI、锁屏、热插拔与虚拟显示器完整矩阵 |
| M03 H.264 | Windows MF 硬编/硬解与同 codec 软件回退、Baseline420、IDR/SPS/PPS恢复、有界不可信码流校验、奇数可见尺寸裁切 | Web 仍 VP8；CPU 转换/读回/IPC/纹理上传仍存在；GPU 呈现、1080p60真实远控资格未完成 |
| M04 高阶画质 | 未声明支持 | H.265、4:4:4、HDR、4K/120/144Hz 与独立硬件合格表 |
| T01 视频期限 | 原始帧保留最新；可靠视频含排队500ms期限，过期终止generation；QUIC 512KiB发送缓冲 | datagram 视频、分片/FEC/参考链过期恢复和弱网实测 |
| T02 质量调节 | daemon 观测编码耗时/入队等待；500ms下调、健康4秒后缓升；硬件H.264尝试60fps，软件30fps上界；现有输入/反馈高优先级 | 完整带宽估计、接收端能力反馈、分辨率切换及文件剩余带宽动态预算 |
| R01 恢复 | 保留并回归已有 generation 隔离、按键释放、全新证明/许可、关键帧恢复；发送截止归类TransportLost | Wi-Fi漫游、睡眠、NAT变化、原公网环境及弱网恢复p95 |
| U01 视觉规格 | 蓝/浅灰/白统一token与布局说明，沿用自有linked-N品牌 | 冻结UU4.40完整状态册、100/125/150%截图对照 |
| U02 操作入口 | 设备进入桌面、原生/Web操作中心、现有切屏/输入/文件/剪贴板权限流程 | 全状态交互对照、设备偏好记忆、完整显示/画质分档 |
| U03 性能诊断 | Web每秒接收FPS/码率/RTT/丢包/解码/缓冲；原生实际codec/硬解与纹理上传率；缺失未知、脱敏导出 | 原生RTT/码率/采集后端完整呈现；真正present统计、独立输入到显示测量 |
| Q01 体验验收 | 自有合成画面、真实codec和本地UDP/QUIC回归；保留全部候选验收门禁 | 原HL↔Edge100次、分层200次、UU配对A/B、带宽阶跃/丢包、跨日24小时长稳 |

## 已完成的本机观察

通过生产 `NetworkPathManager` 工厂建立的同一 socket 连续两次 STUN：

| 策略 | 出口（脱敏） | 两次耗时 | 同 socket 映射 |
| --- | --- | --- | --- |
| system | `86.***.***.***` | 1576 / 353ms | 稳定 |
| physical（接口27，有物理默认路由） | `39.***.***.***` | 207 / 206ms | 稳定 |

这验证了选路差异，不代表外部 Edge 对等媒体已经通过。
本地 `media_socket_factory` 回归额外验证 STUN、UDP 连通性检查和数据使用同一 socket/port，工厂仅创建一次。

Windows 1080p 合成纯色探针已观察到实际硬件编码与 D3D11 解码输出，
也验证了同 codec 软件路径。它是 CPU BGRA/NV12 拷贝的调试构建探针，
不代表动态桌面 58fps、GPU 零拷贝或按键到画面时延。
H.264 生产 Sender/Receiver 的合成端到端测试包含参考帧缺口、IDR恢复和撤销停止。

## 可重跑的验证入口

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked --no-fail-fast
cargo check --locked --target wasm32-unknown-unknown -p nestlink-web
cargo xtask check
python -m unittest discover -s tests/refactor -p "test_*.py"
python scripts/refactor-ui-tokens.py --check
node --test tests/refactor/test_browser_response_observer.cjs tests/refactor/test_browser_native_metrics.cjs tests/refactor/test_browser_network_damage.cjs
cargo run --release -p nestlink-media-codec --example windows-h264-probe -- 1920 1080 120
cargo run -p nestlink-platform-network --example media-route-probe -- physical <STUN-IP:port>
```

本机 Python 220 项通过（19 项平台/环境跳过），Node 69 项通过。
完整 Rust/跨平台 CI 的最终结论以同一发布 SHA 的 required-checks 证据为准，
本文件不把运行中或跳过项目写成通过。候选发布保留18角色完整性、字节摘要、
相同源码提交和全部规定质量工作流门禁；手工验收状态继续为 pending。

## 升级和回退

服务器、Web和双端原生客户端一起升级。数据库为 schema24；先备份，
回滚旧服务端需要恢复升级前备份。已撤销身份不能借能力升级复活；
重连仍需新的双端证明，启动许可不会开启媒体或输入。
物理选路由明确设置启用，默认仍尊重系统/VPN，不修改防火墙或代理配置。
浏览器不能自行绑定Windows接口，不能宣称网页可绕过TUN。

候选签名保持 Windows/update/OCI未配置、Android开发签名，
`production_update_eligible=false`。运行性能、安装签名和人工验收缺口不被自动CI替代。
