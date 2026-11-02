# Windows 候选安装制品核验

完整候选工作流 `.github/workflows/v15-candidate-build.yml` 的 Windows、Web、Linux x64 和 ARM64 构建使用同一个固定源码 cohort。原 Windows collector 验证三份 native payload 是 x64 PE，并确认两份 Inno 6 安装器使用预期的 x86 PE32 bootstrap。Bootstrap 的架构不能代替内嵌产品文件的架构与安装后字节核验。

`scripts/refactor-windows-candidate-install.py` 复用现有 `packaging/candidate/windows.iss` 编译出的原安装器与原卸载器。Windows collector 在写出成功的 part receipt 前，在 GitHub 托管 Windows runner 上逐一执行普通候选包和可选组件候选包的静默安装、重装与卸载。安装目录是各自新建的私有临时目录；每次安装后核对实际 desktop、daemon，以及适用时 privileged 可执行文件与同一 cohort 原生构建的 SHA256，拒绝多出、缺失或变化的产品可执行文件。卸载必须清除实际 executable 和候选注册信息。

用户数据检查使用脚本明确拥有的 `%LOCALAPPDATA%/NestLink-RC/hosted-install-retained-data` 随机 sentinel。任何已有候选用户数据目录或任一候选 AppId 的注册信息都会使实验提前拒绝执行。每次重装和卸载后都核对 sentinel 不变；实验最后只删除自己创建的 sentinel 及空目录。这是用户数据保留的 fixture，不能冒充已登记身份、累计配额或完整登录会话的迁移验收。

原始 Inno 日志、协调器进程日志和 `windows-candidate-installation.json` 随 native part 保留。回执记录实际源码、workflow 源码、run、attempt、runner 平台、实际管理员令牌状态、两份安装器摘要和安装后 payload 摘要。原生编译另在工具安装前记录请求源码和实际 checkout，并沿用现有 source readback/锁文件守卫保存编译日志；失败时同样上传诊断与已生成的部分制品。失败的 native job 不会进入候选 freeze。

这套检查仅覆盖 unsigned development candidate 的实际安装文件操作。它不启动 GUI、daemon、系统服务或 privileged broker，也不将开发候选接入正式更新渠道。GitHub Windows Server runner 上执行成功仍不能证明普通 Windows 用户、Windows 10/11 目标设备、提权输入、网卡/WireGuard 激活、正式 Authenticode、签名升级/回滚或完整远控业务验收。正式 `Manage-NestLink*.ps1` 安装 owner 的签名和维护门槛继续适用。

新增路径在对应源码的 Windows Actions 实际执行、官方 artifact ZIP 摘要和全部 receipt 条目核验之前保持**未验证**。候选总清单的原有现场验收与签名 case 继续保留 pending；源码实现不等于平台资格。
