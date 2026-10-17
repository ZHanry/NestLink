# NestLink v15 初始安全契约

原生 VP8/Opus 封包、来源/代次绑定和可靠视频队列行为见 [native-media.md](native-media.md)。
原生文件读取、目录同意、路径/句柄安全、分块校验和续传见 [native-file-read.md](native-file-read.md)。
本地私有下载区、真实磁盘校验、精确源完成事实和原子不覆盖发布见 [native-download-storage.md](native-download-storage.md)。

`nestlink.proto` 是消息、权限、路径和错误枚举的唯一源；`contract.json` 是版本与预算的唯一源。Cargo 从这两个文件生成 Rust 类型与常量，`cargo xtask contract --write` 生成 OpenAPI 3.1 安全模型。`management-routes.json` 定义当前管理端点，生成文件由 `cargo xtask check` 核对。

产品版本、ALPN、API 与 schema 独立。禁止旧协议探测或自动回退。未知必选能力拒绝；许可的未知枚举拒绝；Protobuf 未知可选字段跳过，但签名始终验证收到的原始 claims 字节。敏感业务禁止 0-RTT，端点必须完成持钥证明。

UUID 必须非零。摘要为 32 字节，签名为 64 字节。权限与路径必须非空且无重复；代次与序号从 1 开始。签发必须经过上游账号、资源归属与本机批准；本库不把签发密钥本身解释为已完成这些批准。

租约响应匹配当前请求、身份、资源、策略、代次与严格递增序号。使用请求发送时的单调时间作为寿命起点，将剩余绝对有效期与最多 15 秒寿命取最小值；传输延迟不能重新开始寿命。已撤销/过期会话不可续租复活。系统休眠/网络重建须显式失效，由后续平台适配提供该事件；普通 `std::time::Instant` 不被当作所有 OS 上都能累计休眠时间的证据。
