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
| Windows **服务**安装、账户、开机自启 | **本文 + 下方示例**（草案） | 需与现场组策略 / 运维规范对齐 |

---

## 2. 服务账户：LOCAL SERVICE 与设计 §13

- **设计意图**：在可行时以 **低权限** 服务账户运行，缩小被攻破后的影响面。
- **账户标识**：`NT AUTHORITY\LOCAL SERVICE`（常见写法 **`obj= "NT AUTHORITY\LocalService"`** 于 `sc.exe`）。
- **注意**：**完整 ETW 实时会话**、**WinDivert 驱动加载**、**对部分进程执行 forensic** 等能力，在真实环境中常需要 **管理员** 或 **附加特权**（如 **SeDebugPrivilege**、加载驱动权限）。**LOCAL SERVICE 能否满足全量采集**取决于：
  - 是否以 **用户态交互会话** 运行（通常服务无桌面）；
  - 组策略是否限制 **内核 ETW**、**防火墙/WFAS Provider**；
  - WinDivert 是否已以 **管理员** 预先安装驱动。

**研发结论（草案）**：生产环境常见两种模式——**(A)** 服务账户 + 收窄功能集（仅上报、无 WinDivert）；**(B)** **LocalSystem / 管理员服务** + 全功能。选型需 **安全与产品** 联合签字，本文不强制单一方案。

---

## 3. 安装前预检清单（ETW / WinDivert）

在首次部署脚本或手册中建议逐项确认（**失败时 stderr / 事件日志应可诊断**）：

| 检查项 | 说明 |
|--------|------|
| **管理员** | 首次安装 WinDivert **驱动**、调整部分 ETW Provider 时常需提升权限 |
| **ETW** | `edr_collector_start` 失败时 stderr 含 ETW 相关错误；可选 Provider 跳过策略见 README「ETW 增强」 |
| **WinDivert** | Shellcode 模块依赖 **已安装的 WinDivert.sys**；进程内会 **`log_windivert_service_hint`**（`windivert_capture.c`）探测服务是否存在 |
| **网络** | gRPC **`server.address`** 可达；证书与 mTLS 与平台一致 |
| **磁盘** | 离线队列路径、取证输出 **`EDR_FORENSIC_OUT`** 可写 |

---

## 4. 服务包装示例（**草案**，需按路径与版本修改）

以下 **不** 随仓库执行，仅供运维/打包参考；生产应使用 **签名的包装器** 或 **NSSM / 厂商服务框架**。

**PowerShell（节选，需管理员）**：

```powershell
# 假设 edr_agent.exe 已置于 C:\Program Files\EDR\edr_agent.exe
# 假设配置为 C:\ProgramData\EDR\agent.toml
$bin = '"C:\Program Files\EDR\edr_agent.exe" --config C:\ProgramData\EDR\agent.toml'
sc.exe create EdrAgent binPath= $bin obj= "NT AUTHORITY\LocalService" start= auto
# 按需: sc.exe description EdrAgent "EDR Agent"
# 首次需验证 LocalService 对配置路径、日志路径是否有 ACL
```

使用 **LOCAL SERVICE** 时，必须为 **`agent.toml`、日志、队列库、取证目录** 配置 **ACL**，否则进程启动即失败。

---

## 5. 与 edr-backend 安装包的关系

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
