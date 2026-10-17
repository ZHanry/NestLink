# 本机系统文件选择器

桌面文件页提供共享目录、接收区父目录、下载区父目录和上传源文件的系统选择按钮。选择仅填写当前会话的本机表单；目录内容访问、目录元数据披露、上传和下载另由明确用户操作触发。远端仅获得获准根目录的 ID、显示名和可移植相对路径。

`nestlink-platform-files::selection` 校验 UTF-8 绝对路径，不接收控制字符，最多 3072 字节。Windows 使用 STA apartment 中的 `IFileOpenDialog`，选择实际文件系统对象、不解析快捷方式、不改变进程当前目录且不写入最近文件记录。COM 接口先释放，路径字符串用 `CoTaskMemFree` 释放，最后平衡 `CoUninitialize`。取消返回空选择，不携带路径或系统错误详情。

Linux 使用 XDG FileChooser。先激活并固定 portal 的唯一 D-Bus owner，再使用随机 128 位 token 建立精确请求路径；订阅该路径的 Response 后才发送 OpenFile。返回 handle 必须等于该路径，仅接受单个本机 file URI，并拒绝查询、fragment 和凭据。初始化和调用有单独三秒预算，响应预算为五分钟；完成、取消、解析失败和超时均尽力 Close 精确请求。真实 GNOME/KDE portal 验收仍需执行。

选择由桌面程序自己的隐藏 helper 进程持有。helper 在普通状态目录、daemon 与 GUI 初始化前执行，仅经私有 stdout 返回有界原始路径。父进程再验证输出，完整 `request_id`、连接代次、Core 代次和 daemon runtime 必须仍相同。父进程预算为六分钟，进程退出前始终占用唯一全局选择槽；取消和会话替换回收该精确 Child，不查询或终止别人的 PID。未确认旧进程实际退出时不能启动新的选择器。

Windows 四个应用 package 的 all-target 编译记录为 `artifacts/core-verification/native-files-clipboard-check-20261015-attempt09.log`；它早于随后取消回收调整。Linux 同批 all-target 编译在修正 X11 参数所有权后通过，见 `artifacts/core-verification/native-files-clipboard-linux-check-20261015-attempt04.log`。隔离选择器回归、当前最终源码严格检查和真实系统界面验收仍分别记录，编译通过不代表全部平台验收完成。
