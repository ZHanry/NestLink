# 正式包签名检查

当前客户端只保留 Windows 桌面和 Web，Linux 交付后端。Android 的签名配置、APK 校验入口和 SDK 工具参数已移除。此前签名约束与验证事实保存在 [历史记录](history-audit/before-windows-web-2026-10-23-SIGNATURE-ACCEPTANCE.md)。

`config/release-signatures.template.json` 为 Windows 正式包检查模板，身份/源码/摘要未填写时必须返回 blocked。正式签名构建只能在 GitHub 的受控签名环境中进行。模板中的历史 v15 正式版本身份不等于本次 0.7.0 RC 候选状态；RC 候选未配置的 Windows、更新和 OCI 签名必须继续如实标记。

固定字节后记录完整源码 SHA、产物 SHA-256 与签名证书 DER SHA-256。签名者摘要是公开身份，密码、私钥和 PFX 内容不能写入计划。检查器在 Windows 上通过 `Get-AuthenticodeSignature` 核对系统信任、固定 signer、Code Signing EKU 和可信时间戳；校验前后字节必须不变，并要求 HEAD 等于固定源码、已跟踪文件干净。

缺工具、身份或产物为 blocked；签名、摘要或来源不匹配为 failed。退出码 0 为通过、1 为失败、2 为待配置。工具只读校验，不签名、不导入密钥、不上传。签名通过不代表真实安装、升级回滚、远程桌面画面和键鼠、直连或长稳已验收。
