# v15 固定候选构建与正式提升

`v15-release-build.yml` 是手动执行的真实 producer。它从一份已经提交、版本一致的干净 `15.0.0` 源码构建 Windows x64、Ubuntu 24.04 x64/ARM64、Android ARM64/x86_64、Web 和两个架构的 OCI 归档，再冻结与签名最终字节。`refactor-release-publish.py` 提供实际 `upload-draft` / `publish`，完整验收后提升原有候选，不重新编译或重新签名。

构建工具已经接通不代表正式验收已通过。用户确认尚未配置固定签名身份、Android ARM64 真机及公司/手机网络到家里的环境；仓库配置的公开身份保留 `null`，preflight 返回 blocked。这里没有生成临时发行证书、复用旧 Android 身份或把模拟器替代真机。Android 范围是 API 30–36（Android 11–16）；API 29 不参与构建、签名或运行验收。

## 一、提交版本与公开策略

所有 Rust 第一方包继续继承 `Cargo.toml` 的版本。正式冻结前统一 workspace package、第一方精确依赖、Cargo.lock、compatibility、contract/OpenAPI 的版本，并运行已有 contract、格式、静态分析、测试及来源检查后提交。producer 校验精确 HEAD 和包含未跟踪文件的工作区状态；不会在构建中改版本、修改锁或把 dirty 源码包装成同一提交。

Android 的 `versionName` 直接读取 Cargo workspace package；`versionCode = major × 10000000 + minor × 100000 + patch × 1000 + release_sequence`。首个 `15.0.0` sequence 1 为 `150000001`。sequence 范围 1–999，不重复使用。Release 需要固定 keystore、alias、密码和公开证书 SHA256；缺少时 `preReleaseBuild` 拒绝生成正式包。producer 使用两个 ABI split，无 universal/debug APK 替代。普通 debug 构建保留两个 ABI。

填写并提交 `config/release-producer.json` 的公开字段：

| 字段 | 要求 |
| --- | --- |
| update_certificate_sha256 | 独立更新证书 DER 的 SHA256，小写 64 位 |
| windows_certificate_sha256 | 固定 Authenticode 证书 DER SHA256，与更新身份不同 |
| android_certificate_sha256 | 新 applicationId 固定证书 DER SHA256，与更新身份不同 |
| windows_timestamp_url | 实际可用的 HTTPS RFC3161 服务 |
| debian_maintainer | 实际维护人 `Name <email>` |
| oci_base | 审阅后的 `ubuntu:24.04@sha256:<multi-arch index digest>`；禁止浮动 tag |

仓库 node ID 固定为 `R_kgDOTz-mRQ`，允许主仓名称为 `ZHanry/home-tunnel` 或 `ZHanry/NestLink`。Android applicationId 固定 `com.zhanry.nestlink`。原生用户状态兼容性是显式 `v15-native-state1`；控制中心 schema 从已提交的 `storage::SCHEMA_VERSION` 生成 `v15-control-schema<N>-epoch1`，不会写死旧 schema 19。

OCI base 是实际再分发的操作系统文件集合，必须先审阅来源与义务后固定 digest。系统文件的原许可证保留；Cargo deny 的允许项不自动覆盖整个 Ubuntu rootfs。

## 二、配置已有固定签名输入

在专用 `nestlink-release` GitHub environment 中配置已有发行身份的 secrets。密码与私钥不写入 JSON、源码、构建日志、GITHUB_ENV 或产物；不要把内容发到聊天。

| secret | 内容 |
| --- | --- |
| NESTLINK_WINDOWS_PFX_BASE64 | 固定 Windows PFX 的 base64 |
| NESTLINK_WINDOWS_PFX_PASSWORD | PFX 密码 |
| NESTLINK_ANDROID_KEYSTORE_BASE64 | 固定新版 Android keystore 的 base64 |
| NESTLINK_ANDROID_STORE_PASSWORD | keystore 密码 |
| NESTLINK_ANDROID_KEY_ALIAS | 固定 alias |
| NESTLINK_ANDROID_KEY_PASSWORD | key 密码 |
| NESTLINK_UPDATE_CERTIFICATE_BASE64 | 独立更新公有 PEM 证书的 base64，仅一个证书 |
| NESTLINK_UPDATE_PRIVATE_KEY_BASE64 | 对应加密私钥的 base64 |
| NESTLINK_UPDATE_KEY_PASSWORD | 私钥密码 |

preflight 只检查这些输入是否配置，不输出值。签名任务只在所需 step 获得对应秘密，使用 runner.temp 下新建文件，私钥不进入缓存或 artifact，并在签名结束清理明确文件。Windows helper 在内存中核对证书 pin 和 Code Signing EKU，将固定证书临时加入当前用户 store；SDK 命令行使用公有 thumbprint，不使用 PFX 密码。签名后要求系统信任和可信时间戳；不会导入自建根证书。专用 runner/environment 的访问控制与密钥托管仍由实际发行环境负责。

## 三、执行手动构建

在 `Produce fixed NestLink v15 candidate` workflow 输入完整小写源码 SHA 和递增 sequence。输入仓库 node ID、最终版本、公开策略和 secret readiness 全部通过后才启动构建。缺配置时会保存 `v15-release-readiness-<attempt>`，退出 2，并阻止后续任务。

所有 checkout、构建和收据绑定同一个 `cohort.json`：源码 SHA、版本、sequence、run ID/attempt、公开配置摘要、源码提交时间、两个状态兼容串。每个任务输出不可覆盖的相对路径、字节数、SHA256 与工具/来源证据；混入另一提交、run attempt 或配置的 part 会被拒绝。artifact 名称带 attempt，重跑不会覆盖先前候选。

任务包含：

1. Windows 2022 x64、Ubuntu 24.04 x64、`ubuntu-24.04-arm` 的独立原生构建。ARM64 supplier 要求真实 ARM64 Linux host、aarch64 GNU/Linux compiler，并逐个检查 VP8/Opus 静态库 ELF object 的机器类型；不重标 x64。Rust fmt、strict Clippy、workspace tests、Python 边界测试、xtask 以及 Linux C sanitizers 都从该提交执行。
2. Android NDK `27.2.12479018`、cargo-ndk `3.5.4`、JDK 17、Gradle `8.13`、SDK/build-tools `36.0.0` 构建两个固定签名 Release APK 和 Release unit tests。随后核对唯一证书、v2 签名、API 30–36 签名格式兼容性、applicationId、精确 versionCode、单个 ABI，以及 APK/JNI 的 16 KiB 要求。这里的兼容性检查不是逐版本运行测试。
3. 固定 Trunk `0.21.14`、wasm-bindgen `0.2.129`、经 SHA256 核对的 Binaryen `133` 构建 Web；安全归档后读回全部文件摘要。另执行 WASM 编译、cargo-deny 与完整历史 secret scan。任何失败都会阻止最终候选任务。
4. 汇集全部 part 后冻结 native-payload，使用独立 update CMS 签名。Windows Inno `6.7.3` 从已经签名的 PE 构建并签名 setup/uninstaller；四个 DEB 使用精确受签名清单保护的 ELF。最终包另冻结 native-packages 并独立 CMS 签名，避免循环摘要。
5. x64/ARM64 原生 runner 用 Buildah 从固定 base 和已验证的 server/Web 字节构建 OCI。校验 index、manifest、config 和每层摘要；读取最终叠加后的 server/Web 文件与原 producing job 对比，拒绝改架构标签、覆盖、链接、白化删除和额外 Web 文件。镜像以 `65532:65532` 运行。两个最终 OCI 归档分别做 detached CMS 签名。
6. 生成源码归档、SPDX 2.3、许可证和 materials。SBOM 将 39 个包仍使用的旧 Cargo `/` 许可写法转换为 SPDX `OR`，同时在 sourceInfo、原 manifest 和 Cargo 索引中保留原声明；未知旧写法会拒绝。SBOM 包含 Cargo.lock 校验值、固定 libvpx/Opus 来源、Android 精确 Gradle 配置与两个实际 OCI 的 dpkg installed package inventory。Cargo 许可证收集器逐项核验锁定归档及原 manifest，保留完整原文、作者/来源声明和文件摘要，按精确版本补充表加入已审阅原文；缺材料时保留 incomplete 索引并拒绝成功回执，详见 [Cargo 审查](cargo-notice-review-2026-10-16.md)。许可证另合并原生/Android 已审阅材料与实际 OCI 的 `/usr/share/doc`、`/usr/share/common-licenses`、copyright、链接索引和 dpkg status，并重新比较镜像中的原字节。`NOASSERTION` 保留尚未自动判定的 license，不自动转成“来源审核通过”。材料保存工具摘要/版本、codec 收据、Web 读回清单、平台签名结果、OCI rootfs 与包/来源输入。

最终 artifact 为 `v15-fixed-signed-candidate-<attempt>`。其中 `release-cohort.json` 与 `.p7s` 冻结 16 个当前产物角色；安装验收明确为 pending。后续验收不修改这个声明，也不重新签名改包。

## 四、安装验收和完整 handoff

下载候选并验证独立 pin、CMS、PE/APK 签名、包摘要。对这些最终字节执行 Windows 10/11、Linux x64/ARM64 X11、GNOME/KDE Wayland、Android API 30–36、Android ARM64 真机、当前三浏览器、公司/手机到家、72 小时、TURN 容量与撤销、新装/升级/回滚/卸载、新实例身份、schema 迁移中断恢复和来源许可验收。结果关联最终源码和精确字节；不能把开发包、静态检查或 mock 的通过值抄成正式结果。

将原候选、实际 acceptance 证据与四项历史保全材料放入同一个受审阅 bundle；按 `RELEASE-HANDOFF.md` 填写全部 21 角色和 29 case refs。历史 Release inventory 要刷新到操作前的四仓真实状态，包含每一个 asset 的 release/asset ID、长度和 SHA256。保留原 source bundle restore/refmap/fsck 及三个不可得历史 gitlinks 的披露，不声称它们已恢复。dirty 工作树保全只使用已审阅归档，不收集忽略的凭据和构建目录。完整决策由独立更新身份签名，得到 `handoff.json` / `handoff.p7s`。

## 五、实际上传与正式提升

`refactor-release-publish.py` 是具有真实副作用的入口。`verify` 只读，`upload-draft` 真正创建 tag/draft 和上传固定字节，`publish` 在相同验证后真正发布；三个动作都要求已签完整 handoff，不能通过一个 `--force` 绕过。先前 custody 工具里的 `remote_upload_performed:false` 表示其自身没有上传；此入口成功时会返回真实 remote receipt。

在精确干净最终提交中运行，bundle、statement 与输出 receipt 使用绝对路径；`GITHUB_TOKEN` 由已有凭据环境提供，具有实际所需的 contents write（只读 verify 可使用 read）。不要把 token 放进命令参数：

```bash
python3 scripts/refactor-release-publish.py verify \
  --repository ZHanry/home-tunnel \
  --bundle /absolute/final-bundle \
  --cohort /absolute/final-bundle/release-cohort.json \
  --cohort-signature /absolute/final-bundle/release-cohort.p7s \
  --handoff /absolute/final-bundle/handoff.json \
  --handoff-signature /absolute/final-bundle/handoff.p7s \
  --certificate /absolute/final-bundle/update.crt \
  --certificate-sha256 <committed-independent-public-pin> \
  --output /absolute/new-readonly-receipt.json
```

完整 verify 后以相同固定输入调用 `upload-draft`，输出另一个 create-new receipt；所有远端逐项下载 SHA256 通过后，以相同输入调用 `publish` 并使用新的 receipt 路径。这些动作可以独立执行；`publish` 也会完成尚未上传的 draft 并执行所有检查。

入口在写入前验证主仓固定 node ID、远端 default/main、main 的精确提交、现有 tag 的最终指向，以及四仓历史源资产 inventory。不存在 tag 时才创建指向原提交的 tag；已存在的正确资产逐项下载验证并复用，长度/摘要不符或多出的资产会拒绝，绝不覆盖。不存在 Release 时先建 draft；即使中途失败也保留 draft 和源仓发行。上传完成后再次核对 main/tag、历史 inventory 和最终资产 ID 集合，才切换为正式 Release。最终 receipt 的 `durable_remote_preservation_verified:true` 基于实际读回，包含所有远端 asset ID 和摘要。

这个入口不删除仓库、分支、旧 tag/Release 或资产。用户已授权的三个组件仓删除、主仓更名和 main 收敛由集中最终操作执行，必须使用实际成功发布/读回 receipt 与重新刷新的 inventory；不能用 Actions retention 代替持久保全。主仓更名后此工具仍按原 node ID 验证新名。它不推送 GHCR、修改 Pages/域名或启动部署。

## OCI 运行边界与当前验证范围

OCI 中 Web 路径为 `/usr/share/nestlink/web`；Caddy 为独立进程，按 `SERVICE-WEB-DEPLOYMENT.md` 显式配置可达的私有 Unix/回环边界和相同 Web 字节。不要把不同容器里的 `127.0.0.1` 当成同一个回环。control 默认读取 `/data/server.toml`，数据目录由 operator 明确创建、私有持有、初始化与 bootstrap；镜像不自动生成部署密钥或接纳旧配置。运行 edge/relay 时显式替换 CLI 参数，不能用默认 control 进程冒充所有角色已部署。发布 OCI archive 的 CMS 签名覆盖原归档，不等同于已经配置 GHCR/OIDC。

交付工具已做 Python 纯边界/GitHub 本地模型测试、真实 PowerShell 5.1 AST/API 核查和 actionlint。此前集中合入的 Windows/Linux 各 36 项回归及真实隔离 Gradle/AGP 的配置、release 任务图、开发版本拒绝三项检查通过，延迟创建的 `preReleaseBuild` 接线已修正。2026-10-16 最新完整 Python 工具回归在两端各收集 114 项，无失败；Windows/Linux 分别显式跳过 16/1 项。新增九项 Cargo 收集边界和两项真实 producer/collector 集成检查，验证完整原文进入许可证归档，以及材料缺失时只保留 incomplete 索引并封锁成功回执。核心 CI 的 codec 路径改在 runner 启动后的步骤写入 GITHUB_ENV，修复作业级 env 中不允许使用 runner 上下文的问题；Rust core、Android、Web 和两个 Release 工作流均通过 actionlint。首次诊断和修复前文件保留。

固定 codec lock 对应 Windows/Linux x64 和 Android ARM64/x86_64 的供应库已从官方源码重建。最新完整 Android 源码 BuildAttempt01 / MatrixAttempt04 的双 ABI JNI/APK 与 API30–36 七版 119 项仪器回归、127 项 JVM 回归已完成，Linux 完整 workspace runtime 1100/0/12 及两端 workspace strict 另有精确 receipt；这些不替代最终固定签名产品、Linux ARM64 host、真机或安装/跨网验收。准确边界见 [Android 记录](ANDROID-VERIFICATION.md)、[socket 跟进](SERVICE-HOST-SOCKET-RELEASE.md)和[集中记录](SERVICE-HOST-PRODUCER-CHECKS-2026-10-15.md)。尚未执行正式 producer 工作流、导入证书、真实发行签名、安装、部署或 GitHub 发布，仍需在配置好的发行环境中完成。
