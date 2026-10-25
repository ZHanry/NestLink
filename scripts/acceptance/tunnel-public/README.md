# 独立公网 TCP / UDP 顺序验收

工具只处理自有随机报文，不持有账号凭据，不创建服务、批准目标或启动产品发布。
工作流不编译产品。当前只有离线测试通过；没有启动 listener、运行公网访问器或判定产品通过。

产品只有一个本机 service owner，因此必须完整完成 TCP 一轮并清理，再以全新 run UUID、
nonce、config、输出目录运行 UDP。每个 config 的 `protocol` 必须是 `tcp` 或 `udp`，不能同时运行。
目的地固定为 `158.180.81.141`：TCP 29101，UDP 29102。单轮 visitor 与 HL helper 各有
600 秒硬上限，持续流量 30…90 秒。服务器 observer 只占同一轮选择的端口最多 90 秒。
所有工具均为 Python 标准库。

## 单轮操作

1. 离线生成配置：`python -B init_run.py --protocol tcp --output <new-private-config>`。
   UDP 后续另生成一份，禁止复用 TCP 的 run/nonce。配置含测试 HMAC nonce，不能上传到 artifact。
2. 在 HL 运行 `python -B responder.py serve --config <config> --output <new-directory>`。
   `ready.json` 只提供一个 `127.0.0.1` 随机 target 和私有本地 gate token。
   不能把 gate token 作为产品授权；不要上传 ready/control 文件。
3. 在服务器运行 `python3 -B source_observer.py --config <same-config> --output <new-source-receipt.json>`。
   启动前由 `ss` 检查选择的固定端口没有现有 listener；随后不带 reuse 选项独占绑定，
   若已有产品监听则失败，绝不替换。只对本次 run/nonce 的认证探测回应 `phase=source-only`。
   回包包含服务器实际 socket peer IP，不能使用 ipify、其他网站或另一 runner 的出口地址。
   observer 不运行目标、转发或授权产品；该回包不算产品通路。匹配一次后先关闭端口再写
   `observer_port_released=true` 回执。TCP visitor 读完整认证响应后主动 shutdown 写半部，
   observer 有界等待 EOF 再关闭，避免服务器主动关闭造成原端口 TIME_WAIT；超时/尾数据
   直接失败。关闭后还必须立即对同端口 exclusive bind→close 成功，回执标记
   `release_check=exclusive_rebind`。整个收尾必须在observer期限内完成，无成功回执不得发布。
   没有设置 SO_REUSEADDR/SO_REUSEPORT。错误 HMAC 不获得回包，没有匹配探测则限时退出。
4. 从已审核的 main 完整提交 dispatch `.github/workflows/public-tunnel-acceptance.yml`，
   输入该提交、选择的 protocol、同一 run UUID 与测试 nonce。工作流仅 `contents:read`；
   并发组阻止两个公网轮次重叠。访问器先发布 source-ready，再取得认证 source-only 回包，
   发布 `visitor-source-observed-<workflow run id>` artifact。
5. 对照服务器 source 回执与 source-observed artifact 的 run/protocol/nonce hash/IP/时间，
   确认 observer 已释放端口，随后才启动 edge 发布。通过产品管理端把**这一服务**的来源 ACL
   设为该实际 IPv4 的精确 `/32`，保留服务定义回读/ACL证据。用 Windows 产品选择 ready
   里的固定本地 target，人工完成本地批准并发布，记录 publication ID 与批准证据。
   工具不代替这些产品动作；定义创建会话及本地批准会话须保持有效。
6. 设置 HL gate：`python -B responder.py gate --ready <ready.json> --phase start --source-ip <observed-IP> --evidence <receipt-id>`。
   只有从真正产品路径读到 start 状态并核对同一来源，visitor 才开始协议测试。
   TCP 覆盖 FIN 后延迟回包及持久流；UDP 覆盖零长、1169 字节、第二 visitor 隔离、
   1170/60000 字节无回包及超限后合法报文恢复。HL 必须未收到认证超限报文。
   大 UDP 分片可能在 WAN 丢弃，工具只证明端到端事实，具体丢弃层须结合协议测试。
7. 收到 `visitor-ready-to-stop` artifact 后，只设置 helper `--phase stop-arm --marker <stop_marker>`。
   等 `visitor-stop-armed` artifact 确认同一 marker 已从产品路径返回，才通过 Windows 产品
   停止本轮真实发布，再设置 helper `--phase stopped --evidence <stop-receipt-id>`。
   **此时 helper 继续正常回包**，不能提前关闭 helper 制造撤回成功。
8. visitor 验证旧流消失、三个全新随机 nonce 的新连接/新 UDP socket 无响应，写入结果与
   `visitor-done` artifact。只有其完成后才设置 helper `--phase finish --marker <done_marker>`。
   两端结果必须保留，helper 若超时/故障退出不能判通过。
9. 离线配对：`python -B compare_results.py --visitor <visitor-result.json> --responder <responder-result.json> --source-observer <source-receipt.json> --output <paired.json>`。
   该结果只表示工具数据匹配；`public_tunnel_acceptance` 始终为 `not_assessed`。
   检查产品 listener/flow 清理后，才能开始另一协议的新一轮。

若 source observer/visitor 丢包、来源变化、ACL不匹配、批准会话失效、600秒期限不足，
这一轮失败或待补证，不扩大ACL或伪造阶段继续。

## 必须另保留的产品证据

- 本轮实际服务器 peer 与精确 `/32` 服务定义回读；发布 ID、目标摘要及本地批准。
- 持续数据期间同一发布的实际签名租约序号前进。visitor 和原始对比脚本仍不读取
  产品租约；使用 [租约证据采集](RECEIPTS.md) 将实际认证 IPC 观测与服务器原始
  租约字节配对。未配对的 `product_lease_renewal_verified=false` 保持不变。
- Windows 产品停止结果、edge listener/flow 清理、用量确认或明确的 pending 状态。
- 对比脚本把两端事件的序号、长度、hash、停止 marker 和结束时间对应；认证错误、
  格式损坏、helper提前退出、事件预算耗尽均不能算路径成功撤回。

只允许公开脱敏结果文件和 marker。nonce配置、ready/control、本地 gate token及任何产品
会话材料不得放入artifact或提交。source回执只包含run、protocol、source-only阶段、实际peer IP、
时间、nonce hash和端口已关闭/独占重绑事实，不记录payload或凭据。

## 离线验证

`python -B test_tools_offline.py` 的全部测试禁止创建socket及connect，涵盖HMAC篡改、
TCP帧边界/FIN、UDP边界/peer隔离、gate顺序、停止阶段helper仍回包、source-only认证、
已有listener拒绝、协议单选、源回执匹配/释放与产品证据未知边界。不是公网验收结果。

`python -B test_receipts_offline.py` 另外验证签名、精确原始字节、部署公钥、序号、
采样窗口、只读 SQLite 和 IPC publication 固定。它使用生成的测试密钥、模拟 IPC
及临时数据库；不能证明实际产品或公网已通过。GitHub 使用
`requirements-offline.txt` 安装这组测试的固定依赖，不在部署服务器安装包。
