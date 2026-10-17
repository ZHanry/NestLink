# 非 Cargo 构建输入来源核验（2026-10-16）

本记录绑定当前 `Cargo.lock`，SHA-256 为 `9a34ff54642f69de251808368609ff4251dfb1b572d4cef617a8d87f572a4bb7`。来源回执位于 `D:\NestLinkBuilds\noncargo-provenance-current-20261016-attempt01\receipt.json`，SHA-256 为 `f16c55bc3aaf86b2288b0070d2df873919aa8ab267e86f600c3abcfdfd119edf`。

## Protocol Buffers 编译器

锁定的 `protoc-bin-vendored` Cargo crate 版本为 3.3.0，crate 仓库快照 commit 为 `d7cc7356ead5b0efd14c415103406b2221a3f8fb`。该 crate 携带的 protoc 报告版本为 `libprotoc 36.2`，上游发布为 [protobuf v36.2](https://github.com/protocolbuffers/protobuf/releases/tag/v36.2)，release commit `2c74169b34066ceb8ddb6b882fcb3fb32d737a55`，tag object `424e1b0a184baa5a3c75061a1febd5f60a0a3707`。上游许可证原文来自 [该 commit 的 LICENSE](https://raw.githubusercontent.com/protocolbuffers/protobuf/2c74169b34066ceb8ddb6b882fcb3fb32d737a55/LICENSE)，SHA-256 为 `6e5e117324afd944dcf67f36cf329843bc1a92229a8cd9bb573d7a83130fea7d`，与 tag 中许可证字节一致。

对 crate 内 8 个平台包，逐一将对应 protoc 二进制和 20 个 include 文件与上游 v36.2 release ZIP 解压内容比较；全部逐字节一致。下表的 release SHA-256 是官方发布资产摘要，protoc SHA-256 是 crate 内二进制摘要。

| Cargo 包 | 上游发布资产 | 发布 ZIP SHA-256 | 内嵌 protoc SHA-256 |
| --- | --- | --- | --- |
| `protoc-bin-vendored-linux-aarch_64` | `protoc-36.2-linux-aarch_64.zip` | `8b8f18bd2b30346efbc698dd5a73dd7c805f3ef8380f6dfc95c768f3f1852f6a` | `cb89a125fd3d6c1ee86ee65a2bcbd7c3ac7c3fab1a806e0c466f162882053cb7` |
| `protoc-bin-vendored-linux-ppcle_64` | `protoc-36.2-linux-ppcle_64.zip` | `0eb8eff1b90b1f06e5dc9aa29aa9e313daba51dd33a3166636d53ea1142228bc` | `3f807a99f5f494a6cb15f1aab7ddf411f3005a9be4330955dda8869902b9ef09` |
| `protoc-bin-vendored-linux-s390_64` | `protoc-36.2-linux-s390_64.zip` | `6ef625085cc7eb42521192f52185c4a9211d5b4721cd104f923494dffbe1c836` | `525e2d8b76559c73e2ca83b3ebb114b777fd22aecc4aab329ec4229be9375769` |
| `protoc-bin-vendored-linux-x86_32` | `protoc-36.2-linux-x86_32.zip` | `81eb44f4003ddd0626cb847e43a34350d73df23cd2fa9233adb5466ce8dd34a0` | `5bd5b505f5ec9fd26e27818a9cda2fa9d5aa60d1fdc9009ff33bc70276d78e39` |
| `protoc-bin-vendored-linux-x86_64` | `protoc-36.2-linux-x86_64.zip` | `121f6c7afe1d4d0e3ea6aab9432038599250134cbf4474cb1167d2c7decd4278` | `f6ee22d65361338459208da8bff801c9ca689741cba9187b34990dd45198f864` |
| `protoc-bin-vendored-macos-aarch_64` | `protoc-36.2-osx-aarch_64.zip` | `9cd98a532c5c5e0c4161314de0225de27e4c8a323917b6ea7b1b714d3ae23466` | `765ccb18be73e565bfc3e2ad94e85039ca28f928b3e62b487e51b7b8fdf1dcfb` |
| `protoc-bin-vendored-macos-x86_64` | `protoc-36.2-osx-x86_64.zip` | `228cc7add4616cc14ca5e80dee83209d44449a7aee95a914ae748fa374efb078` | `56ba0f583d8761975d177670a3375564fd2bf5a7d96182a9d0c3b818a893c0ff` |
| `protoc-bin-vendored-win32` | `protoc-36.2-win32.zip` | `031777688173e6414cfaead74da4c16d7cf2da490bca4e0d0c2458008587f105` | `ab254642d458b8f307f5a2aefd87f9f7ec426c5c1c5e551e68a845dc14113c0e` |

**信任链限制：** protobuf v36.2 Git tag 未签名。版本、上游 release ZIP、crate 内二进制/include 字节及许可证原文均已核对，但该比较不提供经签名 tag 建立的发布者身份认证。

## Bundled SQLite

Cargo 锁定 crate 为 `libsqlite3-sys 0.35.0`，crate 归档 SHA-256 为 `133c182a6a2c87864fe97778797e46c7e999672690dc9fa3ee8e241aa4a9c13f`，crate 上游源码 commit 为 `44e0ef965580b94d59c5dfe8874b57ab5993a8f7`。其中 SQLite amalgamation 与 [SQLite 3.50.2 官方归档](https://www.sqlite.org/2025/sqlite-amalgamation-3500200.zip)逐字节相同，官方 ZIP SHA-256 为 `387991de2834b5da2894119ff4173a9ea0779ea55ebcf53d9a40b24d1dc2484e`。

| 输入 | 值 |
| --- | --- |
| SQLite 版本 / source ID | `3.50.2` / `2025-06-28 14:00:48 2af157d77fb1304a74176eaee7fbc7c7e932d946bf25325e9c26c91db19e3079` |
| `sqlite3.c` SHA-256 | `c9a0b6829b81d5f1b78392181f09744c818117a725667411d517b98149fcd3be` |
| `sqlite3.h` SHA-256 | `7db44ac3e95c465c30eea8d45d81474c7cda49ab76e8a681e752e535d1560f2e` |
| SQLite 原始 public-domain blessing SHA-256 | `ad89cf5f9a0ca133418eae187ae954f2805fd3261aa00716642ed93fc7f3892d` |
| crate wrapper 的声明许可证 | MIT（与 SQLite amalgamation 的 public-domain 声明分开记录） |

## 结论与边界

上述结果核实了锁定构建图中 `protoc` 与 bundled SQLite 的版本、上游来源、精确字节及许可证声明。它不构成组织级许可证兼容批准，也不代替完整的非 Cargo/系统/发行运行时依赖清单、最终 SBOM/NOTICE 与发行材料的绑定、签名或已安装产品验收。G0 和正式产品验收因此仍未通过。
