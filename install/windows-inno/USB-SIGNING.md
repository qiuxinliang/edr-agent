# USB 签名发布：一次交接、保留编译结果

默认仍为 `unsigned`。本改造不自动启用 USB，也不改变平台/Agent 的签名信任策略。

## 发布路径

1. 公共仓库 hosted Runner 原生编译、测试 AMD64/ARM64，保存 `release-input-{arch}`，USB 模式不上传这些未签名包到 Release。
2. 一个 `usb-finalize` job 只调用私有 `qiuxinliang/edr-agent-signing` 一次。私有 hosted admission 核对仓库、发布工作流、提交、当前 run attempt、版本、制品 ID 后才排队到硬件。
3. UTM 固定 Runner 串行完成两种架构：签一方 EXE → 用签后文件重新封装 Inno → 签 Setup/UI → 更新哈希并签 CMS 清单。不运行 CMake、vcpkg、Go、NuGet restore 或 dotnet publish。不对 ZIP 做 Authenticode；ZIP 由最终 CMS 清单中的 SHA-256 保护。
4. 公共 hosted Runner 独立验证原生 EXE 未被替换、签名/时间戳/发布者、清单、未改变的 DLL/规则/脚本及各包哈希。保存 `usb-verified-final` 后才上传草稿。
5. 继续运行原有原生安装、升级、回滚门禁，通过后发布。

## 首次部署顺序

- 先部署私有仓库的新 `sign.yml`、finalizer 和 `packaging-trust.json`，再部署公共仓库工作流。旧的三阶段私有协议与新协议不兼容。
- 公私仓库都保留 `USB_SIGNING_TOKEN`（只限这两个仓库的 Actions 权限）、`WINDOWS_USB_THUMBPRINT` 和 `WINDOWS_USB_SIGNER_SUBJECT`。
- Subject 必须是平台使用的 Go X509 规范化字符串，不能把 Windows 证书查看器中的顺序直接代入。私有/公共值应一致，证书指纹为大写 40 位十六进制。
- 私有仓库使用已有 `WINDOWS_USB_SIGNTOOL_PATH`；`WINDOWS_USB_INNO_PATH` 默认 `C:\EDRSigning\InnoSetup6\ISCC.exe`。使用微软 SDK SignTool 和已有 Inno Setup 6，不下载来源不明的工具。
- 私有签名机只执行私有脚本以及被私有 `packaging-trust.json` 逐文件批准的公共打包代码。普通 Agent 源码变化不需修改白名单；打包脚本变化需要同步审核该文件的哈希。不要自动接受新哈希。
- Runner 必须以证书所属 Windows 用户交互登录运行，不能用 guest/SYSTEM 服务替代。首次依赖下载需要网络；Python 固定 3.12.10，之后复用工具缓存。
- 先运行私有 `Signing host health`，再从公共 main 手动选择 `release_mode=usb` 做候选版本验收。完整验收通过后才考虑把仓库默认 `WINDOWS_RELEASE_MODE` 改为 `usb`。

## 日常使用与失败恢复

日常只需启动签名虚拟机、登录证书用户、连接 USB、发布版本。需要 PIN 时在 Windows 本机输入；不保存 PIN、不导出私钥。

| 失败处 | 操作 | 保留结果 |
| --- | --- | --- |
| 编译/原生测试 | 修复后新版本或重跑失败 job | 不跳过测试 |
| USB/时间戳/私有收尾 | 恢复 UTM/USB/网络，公共 run 选择 Re-run failed jobs | 两架构的待签编译制品 |
| 正式资产上传 | Re-run failed jobs | 完整签名包，避免新时间戳导致哈希冲突 |
| 安装/升级/回滚 | 查对应原生 runner 日志，不直接发布 | 已验证的签名草稿包 |

缓存限同一 run、提交、版本和模式，保留 14 天。过期或身份冲突应发布新版本，不覆盖现有资产。私有任务上限 25 分钟，桥接等待上限 30 分钟，单次签名命令上限 180 秒，取消会尽力取消关联私有任务。USB 故障不会降级为 unsigned。

调试依据：私有 run 各阶段 `[USB]` 日志及公共 run 的 bundle/signature 校验错误。私有临时包在任务结束清理；GitHub 待签/签后制品和 run 日志保留。重跑整个 workflow 仍可恢复同一 run 的已校验输入；不要另开新 run 冒用旧版本。

## 验证边界

本地 Python/源码契约测试与 UTM PowerShell 验证不等于硬件发布验收。新链路正式启用前，必须完成一次带 USB 的双架构候选发布，观察嵌入 Setup 内的签后文件、两架构 lifecycle 结果，并演练签名后上传失败的恢复。
