# RC 源码提交前的凭据检查

2026-10-17 对新仓完整暂存源码运行 Gitleaks 8.30.1 默认规则，并忽略内联放行注释。首次结果为五项；原始结果经过完全脱敏后保存在本地发布回执中。

两份上游 ICE/TURN Codecov 配置含上传 token。新仓副本已删除相应配置行，并在各自 UPSTREAM.md 登记；它们不参与产品构建。旧仓工作树未因这次导出而修改。

另外三项为已独立核验的公开测试向量：TURN 的 HMAC-SHA1/base64 固定输出、MD5(username:realm:password) 固定输出，以及 RFC 6455 示例 WebSocket 握手 nonce。Gitleaks 仅按两个精确文件路径与三个精确完整值联合放行，不忽略目录、规则或新增凭据。

对应完整值 SHA-256：

- HMAC 输出：`aeaf6e3c8244d19533b43208d2699aa8c39420070ae457b0e040dea312c15b70`
- MD5 输出：`5560dd37489908e778c10bd957fcb33b497b706719ccfa6d3a8d8aaf96ca85c8`
- RFC nonce：`15cef4b629cc2d07a4563df9516739d4c8d6097eb283e5260fd59299a3c99c56`

本仓不迁入旧仓 .gitleaksignore。`scripts/check-secrets.py` 另行检查 Git 源码候选，覆盖新密钥、provider token 和完整私钥内容。
