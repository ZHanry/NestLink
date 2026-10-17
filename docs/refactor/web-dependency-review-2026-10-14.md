# Web 依赖与许可审查（2026-10-14）

`apps/web` 使用锁定的 Leptos 0.8.19 CSR。最初的 0.8.6 pin 与 Cargo 兼容范围内选出的 0.8.19 组件宏在 Rust 1.96 上编译失败；将框架版本对齐到 0.8.19 后，WASM 编译和 Clippy 通过。SDK 请求通过本地异步互斥锁串行化，避免跨 await 持有 `RefCell` 借用。

Cargo.lock 校验的 crates.io 身份保持固定。`cargo-deny 0.20.2 --all-features --locked --offline check` 通过；现有多版本提示保留并逐项显示，不影响依赖校验。

| crate | 锁定版本 | Cargo 包 SHA256 | SPDX | 处理 |
| --- | --- | --- | --- | --- |
| `base16` | 0.2.1 | `d27c3610c36aee21ce8ac510e6224498de4228ad772a171ed65643a24693a5a8` | CC0-1.0 | 仅允许该固定 crate 版本；完整文本在 [`base16-0.2.1-LICENSE-CC0.txt`](../../packaging/notices/base16-0.2.1-LICENSE-CC0.txt)，SHA256 `a2010f343487d3f7618afff54e789f5487602331c0a8d03f49e9a7c547cf0499`。 |
| `xxhash-rust` | 0.8.19 | `550a2b930b62486a393c52d5c3b84bff264b28aa437ed64694d31e93b1757af7` | BSL-1.0 | 仅允许该固定 crate 版本；完整文本在 [`xxhash-rust-0.8.19-BSL-1.0.txt`](../../packaging/notices/xxhash-rust-0.8.19-BSL-1.0.txt)，SHA256 `c9bff75738922193e67fa726fa225535870d2aa1059f91452c411736284ad566`。保留许可证与版权文本。 |

Leptos 的传递依赖仍包含 `paste` 1.0.15（Cargo 包 SHA256 `57c0d7b74b563b49d38dae00a0c37d4d6de9b432382b2892f0574ddcae73fd0a`）。RustSec `RUSTSEC-2024-0436` 将它标为未维护，没有报告已知漏洞；Leptos 0.8.19 及其组件图仍通过 `paste::paste!` 调用它。当前在 `deny.toml` 中以此单条、可复查的原因例外，要求每次升级 Leptos 时重审，并在稳定版发布前再次检查。NestLink Web 没有直接调用该宏。

此审查只覆盖当前锁文件和依赖引入，不代表浏览器构建产物、SBOM 或正式产品已验收。
