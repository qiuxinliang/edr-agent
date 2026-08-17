# Windows 部署与服务账户（AGT-006）

**关联**：[CLIENT_IMPROVEMENT_TASKS.md §AGT-006](CLIENT_IMPROVEMENT_TASKS.md)、[AGENT_INSTALLER.md](AGENT_INSTALLER.md)  
**设计对照**：[Cauld Design/EDR_端点详细设计_v1.0.md](../Cauld%20Design/EDR_端点详细设计_v1.0.md) **§1.1 / §13**（部署与服务）

本文说明 **注册写配置** 与 **生产运行（服务 / 账户 / 权限）** 的分工；**MSI / 管理端一键安装包** 以 **edr-backend** 的 [INSTALLER_AND_DOWNLOAD_DESIGN.md](../../edr-backend/docs/INSTALLER_AND_DOWNLOAD_DESIGN.md) 等为权威。

---

## 1. 范围划分

| 环节 | 本仓库提供 | 说明 |
|------|------------|------|
| 租户注册 + `agent.toml` | **`scripts/edr_agent_install.*`** | 见 [AGENT_INSTALLER.md](AGENT_INSTALLER.md) |
| 二进制分发与限时 zip | 平台 / **edr-backend** 构建流水线 | 非 `edr-agent` 单独交付 |
| Windows **服务**安装、账户、开机自启 | **`edr_agent.exe --service` + `scripts/windows_service_install.ps1`** | 需管理员；与现场组策略 / 运维规范对齐 |

---

## 2. 服务账户：LOCAL SERVICE 与设计 §13

- **设计意图**：在可行时以 **低权限** 服务账户运行，缩小被攻破后的影响面。
- **账户标识**：`NT AUTHORITY\LOCAL SERVICE`（常见写法 **`obj= "NT AUTHORITY\LocalService"`** 于 `sc.exe`）。
- **注意**：**完整 ETW 实时会话**、**WinDivert 驱动加载**、**对部分进程执行 forensic** 等能力，在真实环境中常需要 **管理员** 或 **附加特权**（如 **SeDebugPrivilege**、加载驱动权限）。**LOCAL SERVICE 能否满足全量采集**取决于：
  - 是否以 **用户态交互会话** 运行（通常服务无桌面）；
  - 组策略是否限制 **内核 ETW**、**防火墙/WFAS Provider**；
  - 首次开启 Shellcode 检测时，是否以 **管理员** 身份运行，以便随包 WinDivert 安装签名驱动。

**研发结论（草案）**：生产环境常见两种模式——**(A)** 服务账户 + 收窄功能集（仅上报、无 WinDivert）；**(B)** **LocalSystem / 管理员服务** + 全功能。选型需 **安全与产品** 联合签字，本文不强制单一方案。

---

## 3. 安装前预检清单（ETW / WinDivert）

在首次部署脚本或手册中建议逐项确认（**失败时 stderr / 事件日志应可诊断**）：

| 检查项 | 说明 |
|--------|------|
| **管理员** | 首次安装 WinDivert **驱动**、调整部分 ETW Provider 时常需提升权限 |
| **ETW** | `edr_collector_start` 失败时 stderr 含 ETW 相关错误；可选 Provider 跳过策略见 README「ETW 增强」 |
| **WinDivert** | x64 安装包自带官方签名 `WinDivert.dll` / `WinDivert64.sys`；首次 `WinDivertOpen()` 由提升权限的 Agent 按需安装驱动，健康状态必须显示 `windivert_source=appdir`、`driver_open=true` |
| **网络** | gRPC **`server.address`** 可达；证书与 mTLS 与平台一致 |
| **磁盘** | 离线队列路径、取证输出 **`EDR_FORENSIC_OUT`** 可写 |

---

## 4. 原生服务安装（推荐生产入口）

`edr_agent.exe` 已支持 Windows SCM 生命周期：服务安装时使用 **`--service`**，停止/关机时 SCM 会触发 Agent 优雅退出。

1. 放置二进制、脚本与配置：

```powershell
Copy-Item .\edr_agent.exe "C:\Program Files\EDR Agent\edr_agent.exe" -Force
Copy-Item .\scripts\windows_isolate_host.ps1 "C:\Program Files\EDR Agent\windows_isolate_host.ps1" -Force
```

2. 推荐入口：直接使用 `edr_agent.exe --install`。它会调用同目录或 `scripts\` 下的 `edr_agent_install.ps1` 生成生产配置，自动生成端侧私钥/CSR，调用 enroll 签发终端唯一客户端证书，并写入 mTLS 证书路径；传 `--install-service` 时继续注册并启动 Windows 服务：

```powershell
cd "C:\Program Files\EDR Agent"
.\edr_agent.exe --install `
  --api-base "https://edr.example.com:8080" `
  --enroll-token "<token>" `
  --trust-ca `
  --install-service `
  --enable-response-actions
```

输出的 `agent.toml` 只保留一行英文说明，便于现场排障并避免模板注释、中文编码和异常换行问题。便携测试可将 `--install-service` 换成 `--install-autorun`；二者不要同时启用，避免重复启动。

批量分发 zip 时，也可以调用包内 **`scripts\edr_agent_zip_deploy.ps1`**。该脚本会先把包复制到 `C:\Program Files\EDR Agent`，再执行同一套 `edr_agent.exe --install` 流程：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\edr_agent_zip_deploy.ps1 `
  -ApiBase "https://edr.example.com:8080" `
  -EnrollToken "<token>" `
  -TrustCa `
  -RuntimeMode service `
  -EnableResponseActions
```

3. 如需分步排查，可先只生成生产配置：

```powershell
.\scripts\edr_agent_install.ps1 `
  -ApiBase "https://edr.example.com:8080" `
  -EnrollToken "<token>" `
  -Output "C:\Program Files\EDR Agent\agent.toml" `
  -TrustCa
```

也可在便携部署中加 `-InstallAutorun`，脚本会在写入 `agent.toml` 后注册开机计划任务；Inno 安装包仍由向导任务完成同样动作。

4. 安装并启动服务：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows_service_install.ps1 -Action Install `
  -ExePath "C:\Program Files\EDR Agent\edr_agent.exe" `
  -ConfigPath "C:\Program Files\EDR Agent\agent.toml" `
  -EnableResponseActions
```

安装脚本会执行以下生产约束：

| 项 | 行为 |
|----|------|
| **真实 mTLS** | 设置 `EDR_GRPC_REQUIRE_MTLS=1`；缺少 `ca_cert` / `client_cert` / `client_key` 时 gRPC 不启动 |
| **服务自恢复** | `sc.exe failure` 配置失败重启 |
| **ACL** | `%ProgramFiles%\EDR Agent` 仅系统/管理员写；脚本会为服务账户授予队列、日志、取证缓存等运行时子目录写权限 |
| **自保护** | 生产模板启用 `[self_protect] anti_debug`、`job_object_windows`、watchdog 与事件总线压力告警 |
| **主机隔离** | 默认 `enforce`：随包 `windows_isolate_host.ps1` 自动生效（Defender 默认 Block + 放行管理服务器）。agent 会用后端 IP 自动填 `EDR_ISOLATE_ALLOW_REMOTE_ADDRS` 保证管理通道存活;需自定义可设 `EDR_ISOLATE_HOOK`,`EDR_ISOLATE_MODE=stamp` 退回纯标记。脚本须随包落到 agent 同目录或其 `scripts/`(或设 `EDR_ISOLATE_SCRIPT`),服务以可写防火墙的特权账户运行 |
| **取证上传可靠性** | 设置 `EDR_UPLOAD_FILE_RETRIES=3`；上传失败时保留本地 `bundle.tgz` 并在命令结果中返回路径 |

如需以 **LOCAL SERVICE** 运行，可传 `-Account "NT AUTHORITY\LocalService"`；全量 ETW、WinDivert、取证等能力仍可能需要 LocalSystem 或额外特权。

---

## 4.1 Inno `EDRAgentSetup.exe`：开机常驻与卸载（已实现）

安装包也可通过 **`install/windows-inno/edr_windows_autorun.ps1`** 注册计划任务，适合开发与兼容旧包的场景：

| 安装向导任务 | 行为 |
|--------------|------|
| **Run at startup (scheduled task as SYSTEM, survives reboot)**（默认勾选） | 注册名称为 **`EdrAgent`** 的计划任务：触发器 **系统启动**、主体 **`NT AUTHORITY\SYSTEM`**、无单次执行时限、失败可重试；安装结束时 **立即 Start-ScheduledTask** 一次。 |
| **Restrict install folder…**（默认不勾选） | 对 **`%ProgramFiles%\EDR Agent`** 执行 **`icacls`**：去掉继承；**`SYSTEM`** / **`Administrators`** 完全控制；**`Users`**（SID `S-1-5-32-545`）**读取+执行**，以便非管理员仍能运行 **`edr_agent.exe`** 并读取 **`agent.toml`**（不可写目录内文件，降低随意篡改）。若曾用旧脚本加固导致「拒绝访问」，请用**管理员**命令行执行卸载或手动 **`icacls "<安装目录>" /inheritance:e /T`** 恢复继承后重装。 |

**卸载**：使用「程序和功能」中的 **EDR Agent** 项（即 Inno 生成的 **`unins000.exe`**）。卸载阶段会先执行 **`edr_windows_autorun.ps1 -Action Remove`**：停止并注销计划任务、结束 **`edr_agent`** 进程、在删除文件前运行 **`edr_agent.exe --etw-uninstall-cleanup`** 按名 **`ControlTrace` STOP** 本程序使用的 ETW 实时会话（避免异常退出后会话名 **`EDR_Agent_RT_001`** 仍占用）；再对安装目录 **`icacls /inheritance:e`** 恢复继承，最后删除文件。随包的 WinDivert 文件也会删除；若没有其他进程使用该驱动，WinDivert 会在后续重启时自动卸载。安装器不会强制删除共享的 `WinDivert` 服务，避免影响同机其他软件。

## 4.2 Headless `uninstall.exe`：完整卸载（已实现）

Windows headless 安装完成后会在 `%ProgramFiles%\FDSecurity` 写入原生 **`uninstall.exe`**，并注册到 Windows“应用和功能”。双击会请求管理员权限并执行完整卸载：停止并删除 Agent 服务/计划任务、结束进程、清理 ETW、删除客户端证书和 Agent 专用机器环境变量，再删除配置、队列、证据、日志与程序目录。

- 交互卸载：`"C:\Program Files\FDSecurity\uninstall.exe"`
- 静默卸载：`"C:\Program Files\FDSecurity\uninstall.exe" /S`
- 卸载 Agent 并将日志、诊断数据归档到 `%ProgramData%\FDSecurity\UninstallArchive`：`"C:\Program Files\FDSecurity\uninstall.exe" /KEEPDATA`

`/KEEPDATA` 不会保留 Agent 服务、程序文件、身份证书、注册配置、私钥、队列或取证缓存；这些内容仍会随完整卸载清理。归档目录仅包含 `logs` 和 `diagnostics`。

`uninstall.ps1` 作为维护和故障恢复入口继续保留；正常卸载应优先使用 `uninstall.exe`。

若需 **Windows 服务**形态，优先使用上文 §4；与计划任务二选一，避免同一主机启动两个 Agent 实例。

**静默 + 命令行注册**：支持 **`/EDR_API_BASE=`** / **`/EDR_ENROLL_TOKEN=`**（或短写法 **`/API=`** / **`/TOK=`**），可选 **`/EDR_INSECURE_TLS=1`** 或 **`/TLS=1`**；须成对或均省略；与 Inno **`/VERYSILENT`** 等组合使用。完整说明与命令行敏感提示见 **[AGENT_INSTALLER.md](AGENT_INSTALLER.md)**「Release 一键安装」Windows 小节。

---

## 5. 与 edr-backend 安装包的关系

- **当前 CI / Inno 发布流程**：Windows Release 使用固定 VS2022、vcpkg 清单依赖和标准 CMake 产品构建；终端通信统一为 HTTPS HTTP/2 控制与上报。安装包不包含 gRPC 客户端、ONNX Runtime、模型 DLL 或端侧模型文件。
- **AVE 发布边界**：规则、IOC、证书信任、租户抑制与行为启发式都编译入 `FDSensor.exe`；无需 `models/` 目录或额外模型运行时。
- **路径约定**：Windows 运行时配置、证书、模型、队列、日志、取证缓存、隔离状态与 outbox 均固定在 **`%ProgramFiles%\EDR Agent`**；检测规则/测试样本中出现的 `ProgramData` 仅代表被检测对象路径，勿作为 Agent 自身存储目录。
- 平台下发的 zip 可能内含 **同一套** `edr_agent_install.ps1`；**服务注册** 可在 **首次运行向导** 或 **单独 GPO 脚本** 中完成。
- **24h 下载链接、安装包哈希** 等以 **edr-backend** 文档为准。

---

## 6. 验收建议（供 QA）

在 **干净 Windows VM** 上：

1. 完成 **enroll** → 生成 `agent.toml`；
2. 放置二进制并按选定账户安装服务或使用计划任务；
3. 确认 **ETW 会话建立**（无持续 Provider 失败）、按需确认 **WinDivert**；
4. 控制台可见 **上报 / 在线**（与 [SOAR_CONTRACT.md](SOAR_CONTRACT.md) §4 一致）。

---

**状态**：**AGT-006 已关闭**（以本文 + [deploy/README.md](../deploy/README.md) 为交付；**MSI/WiX** 与 **管理端集成** 在 **edr-backend** 迭代）。
