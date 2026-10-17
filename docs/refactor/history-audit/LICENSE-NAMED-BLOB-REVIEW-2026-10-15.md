# 旧历史中未识别的许可证命名对象

2026-10-15 已逐件读取、核对原 Git blob 长度与 SHA256，并完成固定 Client 清单中 18 个未被简单文本签名识别的对象分类。原清单未覆盖的来源不因此获得复用许可。[机器报告](license-named-blob-review-2026-10-15.json) 保留每件对象的摘要、代表路径、分类与处置。

| 对象 | 数量 | 识别结果 |
| --- | ---: | --- |
| `src/license.rs` 的历史版本 | 14 | 许可证密钥处理程序源码，不是软件版权许可文本 |
| MSI `License.rtf` 的两个历史版本 | 2 | RustDesk/Purslane 隐私政策，不是软件版权许可文本 |
| `web/ogvjs-1.8.6/LICENSE-nestegg.txt` | 1 | Mozilla Foundation 2010 的 ISC 许可与免责文本 |
| `libs/pulsectl/LICENSE.md` | 1 | GPL-3.0-or-later 短声明，完整许可仍由原历史材料保留 |

RTF 使用本机 Windows Forms RichTextBox 只读解码，没有显示窗口或访问剪贴板；原字节、解码可见文本、工具与摘要保存在 `artifacts/history-license-followup-20261015/`。两份隐私政策的可见文本分别为 6840/6850 字符；它们不能成为 NestLink 的隐私政策或版权许可。此前一次准备因程序函数改名而被过严的检查拒绝，保留已读回的相同原件后完成第二次准备，没有替换原对象。

本次闭合的是此前 18 个文件名命中对象的分类。原源码与原许可证只随旧历史保留；没有复制到新产品、改写旧许可或导入产品 Git 历史。源文件头部 notices、依赖义务及全部子模块来源仍按历史保全流程逐项复核。
