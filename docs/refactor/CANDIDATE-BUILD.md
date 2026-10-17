# 用户验收候选构建

`v15-candidate-build.yml` 从新仓库 `ZHanry/NestLink` 的干净源码提交构建 `0.2.0-rc.1`，供用户验收。入口与 `config/candidate-producer.json` 独立固定新仓 node ID `R_kgDOVNHMvg`，不会处理旧仓库。文件名中的 v15 是已有协议/实现名称，对外产品版本为 RC。产物保留 Windows x64 两套安装包、Linux x64/ARM64 桌面与服务端 DEB、Android arm64-v8a/x86_64 APK、Web、两种架构 OCI，以及源码、SBOM、许可证和验收材料。Android 范围为 API 30–36（Android 11–16）。每个 job 最长 90 分钟；这个入口只构建和检查产物，不重复整套产品测试。

所有对外产品版本需先统一提交为 `0.2.0-rc.1`。手动运行 **Build NestLink 0.2.0 RC development candidate**，填写：

- `source_revision`：新仓库完整 40 位小写源码提交 SHA。
- `candidate_sequence`：1–999 的构建序号；首次填写 `1`，Android versionCode 为 `200000 + sequence`（首次为 `200001`）。
- `oci_base`：已审阅的 `ubuntu:24.04@sha256:<multiarch-index-digest>`。preflight 按 digest 下载原始 index，核对摘要及 amd64/arm64 平台；原始 index 保留在材料包中。

成功后下载 `rc-development-candidate-<run_attempt>` artifact。`candidate-build-manifest.json` 绑定新仓身份、RC 版本、18 个交付角色的字节数、SHA256 和源码提交；任何平台、ABI、原生执行文件、构建证据缺失，跨提交/跨 CI 执行混用、字节变化或路径碰撞，都会阻止冻结。原生执行文件在 `files/NestLink-candidate-materials.zip` 的 `native/` 中，Linux 执行位保留。

候选签名状态明确为：Windows/更新/OCI `not-configured`，Android `development-only`，`production_update_eligible=false`。Windows 使用独立 AppId 和 `NestLink-RC` 安装/状态目录；普通版为当前用户安装，可选 broker 包只分发 broker 字节，未签名的正式特权激活仍需后续验收。Android 使用实际验证并记录的开发证书，应用 ID 为 `com.zhanry.nestlink.candidate`，versionName 为 `0.2.0-rc.1`；双 ABI 都执行 API 30–36 签名兼容、16 KiB ZIP 对齐及 ELF LOAD 检查。开发证书不作为固定 Release 身份，跨构建更新签名兼容不作承诺。

Windows 候选编译器固定为 Inno Setup `6.7.3`。它的安装引导程序为 x86 PE32，使用 `ArchitecturesAllowed=x64compatible` 和 `ArchitecturesInstallIn64BitMode=x64compatible` 限制目标系统并启用 64 位安装模式；这两项不改变引导程序本身的 PE 架构。收集器分别严格校验引导程序为 x86/PE32 Windows GUI 可执行文件、desktop/daemon/privileged 三个实际产品执行文件为 x64；全局 `pe_x64` 校验不变。官方文档说明[64 位安装模式可用于 32 位安装器](https://jrsoftware.org/ishelp/topic_32vs64bitinstalls.htm)，并明确[真正的 64 位安装器及 `SetupArchitecture=x64` 从 Inno Setup 7 才引入](https://jrsoftware.org/ishelp/topic_64bit.htm)。候选包不为引导程序更换已固定的工具链。

每个 Android 单 ABI APK 的原生库精确为 `libnestlink_android.so` 与 Compose 依赖携带的 `libandroidx.graphics.path.so`。后者固定来自 Gradle 已锁定并校验 AAR 摘要的 `androidx.graphics:graphics-path:1.0.1`；收集器核对该依赖锁、AAR 校验 pin，以及 APK 内对应 ABI 库的精确字节数和 SHA256。两项库都必须保持原有 ELF64 ABI 与 16 KiB LOAD 校验，并以未压缩、16 KiB ZIP 数据对齐方式打包；额外库、其它 ABI、字节变化、压缩或错位均会拒绝。各库摘要、对齐和依赖来源记录在对应的开发签名证据中。

Linux 包名为 `nestlink-rc-desktop` / `nestlink-rc-server`，安装在 `/opt/nestlink-rc/`；DEB 版本采用 Debian 预发行排序形式 `0.2.0~rc.1`。桌面入口为 `nestlink-rc`，独立状态目录为 `${XDG_STATE_HOME:-$HOME/.local/state}/NestLink-RC`；服务端安装后由操作者显式初始化配置和启动，不自动开放服务。候选安装器保留用户数据。真实安装维护、固定证书升级/回滚和特权激活验收仍待完成。

两种 OCI 在对应原生 runner 上从同一固定 Ubuntu index 构建，逐层回读检查架构、源码/版本标签、非 root 用户、入口及 server/Web 真实字节。镜像内实际 dpkg 软件清单追加到 SBOM；版权、common-licenses、dpkg/status 和文档链接清单按架构保存在许可证归档。Rust、原生编解码器和 Android 依赖锁、构建工具指纹与回读证据保存在 SBOM/许可证/材料中。

本地入口为 `python -B scripts/refactor-candidate-producer.py --help`。先运行 `preflight --source <SHA> --sequence <N> --run-id <ID> --run-attempt <N> --oci-base <fixed-base> --oci-index <raw-index.json> --output <outside-checkout>/cohort`；后续 `collect-native`、`collect-android`、`collect-web`、`metadata` 收集独立 part，`oci-context` / `collect-oci` 处理镜像，最后 `freeze --cohort <cohort.json> --bundle <merged-parts> --output <new-output>`。所有输出均需在源码目录外的新目录。可用 `--acceptance-evidence <directory>` 为 freeze 增加已经执行的开发检查日志；这些日志不自动变成产品验收通过。

冻结后的 `candidate-build-manifest.json` 可直接交独立 `refactor-rc-publish.py` 核验并发布新仓 `v0.2.0-rc.1` prerelease。所有 18 条 artifact 的 `source_revision` 相同，路径相对 bundle 根且包含 `files/`；30 条 `acceptance_cases` 均为 `{id,status:"pending",evidence_artifact_id:"acceptance"}`，含 90 分钟 soak。manifest 不含旧仓库归档角色或门槛。候选构建不改名、删仓库、删分支或发布 Release，也不读取/重传旧历史归档。用户随后对冻结字节做全功能验收。

正式 `v15-release-build.yml`、固定 Release 签名、生产安装/维护校验和正式发布门槛保持不变；候选的 manifest purpose 独立，不能代入生产更新授权。
