# 源码扫描误报复核（2026-10-17）

`scripts/check-secrets.py` 改为读取 `git ls-files --cached --others --exclude-standard -z`：包含 staged/tracked 和未忽略的新源码，保留含空格/Unicode 的路径，不递归读取 `target`、`artifacts` 等 ignored 构建缓存。被 Git 跟踪的 ignored 路径仍扫描。不再使用整目录或图片后缀的静态忽略列表；二进制按 UTF-8 解码失败跳过。符号链接只扫描链接文本，拒绝通过父目录链接读取仓库外的文件。

父任务报告的 14 个源码文件逐一复核后，共有两处故意无效的 PEM parser fixture，以及 12 个路径内的 18 次固定公开测试凭据赋值。18 次赋值对应 17 组不同的“精确 POSIX 路径＋原 pattern-5 完整匹配文本 SHA-256”（ICE 上游测试重复使用同一值）。例外只作用于 generic credential-assignment 规则，不影响私钥/AWS/GitHub/Slack 规则；不能因为文件已获某个例外而加入新凭据。

| 文件 | 复核依据 |
| --- | --- |
| `apps/desktop/src/services.rs` | `local_ca_reader_rejects_malformed_and_unbounded_bundles`，测试 CA reader 拒绝无效 PEM；没有可解码的足够长 key body，不需路径例外。 |
| `apps/server/src/turn_node/tests.rs` | `missing_malformed_and_mismatched_private_keys_are_rejected`，固定 malformed key 输入；真实测试密钥另在运行时生成，不需路径例外。 |
| `crates/node/src/service_plane/ingress/web/tests.rs` | WebAuth 测试 helper 的固定测试 token。 |
| `crates/sdk/src/webrtc_host/tests/data_loopback_tests.rs` | 回环 SCTP/HTTP renewal/revocation 测试，在内存 Store bootstrap 使用的固定口令。 |
| `crates/sdk/tests/service_publication.rs` | 服务发布集成测试的内存 Store bootstrap 固定口令。 |
| `crates/sdk/tests/service_start_cancellation.rs` | 服务启动取消集成测试的内存 Store bootstrap 固定口令。 |
| `crates/sdk/tests/service_web_publication.rs` | Web 服务发布测试的内存 Store bootstrap 固定口令。 |
| `crates/storage/src/services/publication/tests.rs` | `Fixture::new` 的内存存储测试口令。 |
| `crates/traversal/vendor/ice/src/candidate/candidate_relay_test.rs` | 上游 `test_relay_only_connection` 的两次相同回环 TURN 测试赋值；vendor 原件不改。 |
| `crates/traversal/vendor/turn/src/auth/auth_test.rs` | 上游 `test_generate_auth_key` 的公开协议测试向量，与固定 expected key 比较；vendor 原件不改。 |
| `crates/turn-service/src/tests.rs` | 六个固定凭据用于本地 managed allocation 的 revoke、port budget、stream、lease/binding expiry 测试。 |
| `tests/refactor/test_browser_multidisplay_permit_observer.cjs` | 固定浏览器 permit-observer mock token。 |
| `apps/server/src/remote_password.rs` | `#[cfg(test)]` 内 `password_http_budget_rejects_unknown_bearers_and_survives_refresh` 的故意错误口令。 |
| `crates/storage/src/relay_reservations/tests/resources.rs` | `fixed_password_revocation_removes_the_associated_node_resources` 的资源撤销测试口令。 |

PEM 检查要求 begin marker 后有至少 32 个 base64 字符、可解码出至少 24 字节；允许正常/escaped 换行、不同折行宽度和传统加密 PEM 头。它会拒绝包含足够长 body 的截断私钥，即使 end marker 不存在；不会把单独 marker、短 invalid 文本当作私钥。此检查不依赖成功解密或密钥格式解析，以免遗漏加密/截断材料。

定向测试在 `scripts/test_check_secrets.py`，由既有 Pages CI 的 `scripts/test_*.py` 发现：验证所有已复核例外的路径/字节边界、真实 PEM 形状与变体、新 provider token 和通用凭据仍拒绝、Git 跟踪和 untracked/ignored 的边界，以及诊断只输出 path/line/rule、不打印内容。测试使用内存构造的公开固定向量和自动清理的临时 Git 仓库，不运行全平台回归。最终完整 staged Gitleaks 扫描仍由父任务执行。
