# Tokio I/O safety 修复（2026-10-24）

GitHub `40035244728` 的依赖检查拒绝当前锁定的 Tokio 1.53.2：
[RUSTSEC-2026-0386](https://rustsec.org/advisories/RUSTSEC-2026-0386)
报告 `AsyncFd` 安全构造器对任意 `AsRawFd` 接受无效或被替换描述符，可能造成
I/O safety 违反和 use-after-free。上游修复线包括 1.53.3；本次选择该补丁版本，
不新增 advisory ignore，也不降低依赖检查。

工作区依赖下限改为 1.53.3，主锁文件及真实浏览器/原生宿主 fixture 的独立锁文件
均更新至该版本；fixture 的精确版本同步更新。没有在本机编译或打包产品。

生产源码中唯一直接调用被弃用构造器的地方是
`crates/platform-network/src/linux.rs::subscribe`。它在创建 nonblocking/CLOEXEC
netlink socket 后立即取得唯一 `OwnedFd`，现在将其移动到新的
`unsafe { AsyncFd::register(fd) }`，并说明安全前提：注册期间不复制、关闭或替换
描述符；接收只借用；析构先撤销注册，再由 `OwnedFd` 关闭描述符。

验证要求保持 GitHub 的 cargo-deny、Clippy、完整 Windows/Linux 套件、真实隔离
netlink IPv4/IPv6/路由事件测试和浏览器/原生宿主集成。只有修复后的同提交全部通过，
才可以生成候选成品；原版本的其他成功检查不替代新版本验证。

上游依据：[Tokio 修复 PR #8587](https://github.com/tokio-rs/tokio/pull/8587)，
[RustSec 公告源码](https://github.com/RustSec/advisory-db/blob/main/crates/tokio/RUSTSEC-2026-0386.md)。
