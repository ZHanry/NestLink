# 正式包签名检查

用户于 2026-10-13 确认签名证书、Android ARM64 真机与跨网环境未配置，要求继续实现和准备工具。模板中的身份/源码/产物摘要保留为 null，运行结果必须是 blocked，不生成临时发行身份，也不使用旧 Android 身份代替新证书。

复制 `config/release-signatures.template.json` 到 `artifacts/release-signatures.json`，在最终源码提交与签名后的发行字节冻结后填写：完整源码 SHA、每个产物 SHA-256、Windows 与 Android 签名证书 DER 的 SHA-256，以及确认的新 Android applicationId。证书摘要是公开身份，不填密码、私钥或 keystore 内容。模板文件名是预留位置，最终清单要包括每个实际 Windows/APK 发行包。

```powershell
python scripts/refactor-signatures.py --plan artifacts/release-signatures.json --output artifacts/signature-verification.json --apksigner C:/Android/build-tools/36.0.0/lib/apksigner.jar --aapt2 C:/Android/build-tools/36.0.0/aapt2.exe
```

Windows 在 Windows 上通过 Get-AuthenticodeSignature 检查系统信任结果、固定签名者、Code Signing EKU 和时间戳。Android 用 apksigner 在 API 30–36 范围验证 APK 签名兼容性，并核对唯一签名者与 v2 签名；此范围只检查签名格式是否兼容相应安装 SDK，不是 Android 版本运行测试。再用 aapt2 核对 applicationId、15.0.0 版本、最低 API 30、目标 API 36 及逐包 ABI。Android 10/API 29 已从目标、运行验收和签名兼容检查中排除。Windows 用 Java 直接启动 apksigner.jar，避免批处理解释文件名；可用 --java 指定 Java 可执行文件。校验前后检查相同产物哈希，并要求当前 HEAD 等于固定源码 SHA、已跟踪文件干净。缺工具/身份/产物为 blocked，签名/哈希/应用身份不匹配为 failed。退出码为 0 通过、1 失败、2 待配置。工具只读校验，不签名、不导入密钥、不上传。

报告保存计划摘要、源码 SHA、产物摘要和公开签名身份；不代表安装/升级/回滚、Android ARM64 真机、Linux/OCI/更新签名、跨网或 72 小时验收。当前调试包各 API 的 instrumentation 检查与历史 APK 分别记录，详见 [Android 验证记录](ANDROID-VERIFICATION.md)，不能将历史模拟器结果当作最终固定签名产物验收。签名构建/密钥托管入口和其余平台检查见 [正式 producer](RELEASE-PRODUCER.md)。GitHub 正式 Release 与旧仓删除仍由完整产品验收关口约束。
