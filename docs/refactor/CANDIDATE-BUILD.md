# 用户验收候选构建

NestLink 定位为 **内网穿透 + 远程桌面**。当前客户端范围为 Windows 桌面和 Web；Linux x64/ARM64 继续提供后端服务。范围以 [`config/product-scope.json`](../../config/product-scope.json) 为准。Android 源码与 CI 已移除，Linux 桌面不再进入发行清单，历史证据不作为当前验收结果。

全部发行构建、编译和打包在 GitHub Actions 执行。用户电脑与性能有限的服务器只下载、核验并运行产物。`.github/workflows/v15-candidate-build.yml` 从 `ZHanry/NestLink` 的同一个干净提交构建 `0.7.0-rc.1`；node ID 固定为 `R_kgDOVNHMvg`。文件名和协议中的 v15 是内部兼容命名空间。

手动运行 **Build NestLink 0.7.0 RC development candidate**，填写：

- `source_revision`：40 位小写提交 SHA，公开产品版本须已统一为 `0.7.0-rc.1`。
- `candidate_sequence`：1–999 的候选序号。
- `oci_base`：已审阅的 `ubuntu:24.04@sha256:<multiarch-index-digest>`。preflight 核对原始 index 的摘要及 amd64/arm64 平台，材料包保留原始 index。

构建前及冻结前都要求同一源码的 Rust、Web、秘密扫描和 CodeQL 最新检查成功。矩阵包含 Windows 2022 x64、Ubuntu 24.04 x64 与原生 ARM64 runner。Windows 编译 desktop/daemon/privileged，Linux 仅编译服务端，Web 独立构建；最长单 job 90 分钟。构建工作流不发布 Release，不删除分支，不读取生产签名密钥。

成功后下载 `rc-development-candidate-<run_attempt>`。`candidate-build-manifest.json` 固定 **14 个交付角色**的长度、SHA-256 和源码提交：Windows 两套安装器、Linux 两架构服务端 DEB、Web 静态站点、两架构 OCI、源码、SBOM、许可证、材料、验收材料、native payload 与 package 清单。缺失角色、原生执行文件或构建证据，混用源码/CI 执行、字节变化或路径碰撞都阻止冻结。

Windows 候选使用独立 AppId 和 `NestLink-RC` 安装/状态目录。Inno Setup 固定为 `6.7.3`：安装引导程序是 x86 PE32 GUI，实际产品执行文件必须是 x64；`ArchitecturesAllowed=x64compatible` 与 `ArchitecturesInstallIn64BitMode=x64compatible` 限定目标安装。可选 broker 包分发权限代理字节，正式签名激活仍须独立验收。卸载保留用户数据。

Linux 包名为 `nestlink-rc-server`，安装在 `/opt/nestlink-rc/server/`，DEB 版本采用 `0.7.0~rc.1`。安装后由操作者初始化配置并启动，不自动开放服务。两种 OCI 从同一固定 Ubuntu index 在对应原生架构上构建，逐层检查架构、源码/版本标签、非 root 用户、入口及 server/Web 实际字节；OS 依赖和原文许可证随镜像回读证据进入材料包。

候选签名状态明确为 Windows、Linux 更新和 OCI `not-configured`，`production_update_eligible=false`。构建材料保留真实身份和摘要。未配置的正式签名不能写成通过，也不能把开发候选作为生产更新授权。

当前 **19 条平台、安装、签名和公网验收**在构建清单中初始保持 pending，包括 Windows 10/11、两个 Linux 后端架构、Chrome/Edge/Firefox、公司/手机网络、90 分钟稳定性、TURN 容量及撤销、安装升级回滚卸载、重装身份、迁移恢复与来源许可。Android 和 Linux 桌面验收按用户明确缩减的平台范围撤销；剩余门禁不降低。

在 GitHub runner 内，`preflight` 冻结 cohort，`collect-native`、`collect-web`、`metadata` 收集 part，`oci-context`/`collect-oci` 处理镜像，`freeze` 校验完整字节及证据。输出必须为源码外的新目录。`--acceptance-evidence` 只附带已执行的检查，不自动将产品验收标为通过。

冻结后必须完成[报告验收](REMEDIATION-ACCEPTANCE.md)，包含实际外部 Edge ↔ HL 的直连路径、持续桌面画面和键鼠结果，再由独立 `refactor-rc-publish.py` 对同一源码、构建和材料进行核验。构建成功不授权发布；0.7.0 RC 在全部适用整改及验收完成后发布。
