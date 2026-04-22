# Windows 部署与服务账户（AGT-006）

**关联**：[CLIENT_IMPROVEMENT_TASKS.md §AGT-006](CLIENT_IMPROVEMENT_TASKS.md)、[AGENT_INSTALLER.md](AGENT_INSTALLER.md)  
**仅 Windows 发版打勾表**：[WINDOWS_RELEASE_CHECKLIST.md](WINDOWS_RELEASE_CHECKLIST.md)  
**设计对照**：[Cauld Design/EDR_端点详细设计_v1.0.md](../Cauld%20Design/EDR_端点详细设计_v1.0.md) **§1.1 / §13**（部署与服务）

**§P2c 深化**：**[WINDOWS_SERVICE_SHUTDOWN.md](WINDOWS_SERVICE_SHUTDOWN.md)**（服务 STOP vs Ctrl+C）、**[SELF_PROTECT_REGRESSION.md](SELF_PROTECT_REGRESSION.md)**（Job Object / anti_debug 清单）、**[PROMETHEUS_BUS_METRICS.md](PROMETHEUS_BUS_METRICS.md)**（总线指标与 Prometheus）。

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
| **网络** | gRPC **`server.address`** 可达；证书与 mTLS 与平台一致。**取证 / Webshell 上传**：该地址须为**已实现 `UploadFile`** 的 **EventIngest**（勿指向仅 stub 的 API gRPC）；见 **`docs/AGT009_FORENSIC_UPLOAD_E2E.md` §2.1（C4）** |
| **磁盘** | 离线队列路径、取证输出 **`EDR_FORENSIC_OUT`** 可写 |

### 3.0 排障顺序与默认值（§P2c **S4**）

现场「无事件 / 无上传 / 进程秒退」时建议按序缩小范围（**详细语义**见 **`README.md`**、**`agent.toml.example`**、**`docs/EVENT_BUS_BACKPRESSURE.md`**）：

1. **进程能否启动**：**`--help`**、同目录 **`agent.toml`** 路径、**ACL**（服务账户写 **ProgramData** / 队列库）。  
2. **配置指纹**：stderr **`[config] fingerprint=`** 是否随 **`EDR_CONFIG_RELOAD_S`** 热载变化。  
3. **gRPC**：**`[transport] gRPC target`**、证书或 **`EDR_GRPC_INSECURE=1`**（仅调试）；**`UploadFile`** 与 **MinIO** 见 **`docs/AGT009_FORENSIC_UPLOAD_E2E.md`**。  
4. **ETW**：管理员权限、Provider 跳过日志（README「ETW 增强」）。  
5. **WinDivert**：服务 **`WinDivert` / `WinDivert1.4`**、**`[shellcode_detector]`** 开关。  
6. **高危指令**：**`EDR_CMD_ENABLED`**、**`[command] allow_dangerous`**、**`forensic`/`kill`/`isolate`** 审计路径 **`EDR_CMD_AUDIT_PATH`**。  
7. **自保护 / 总线**：**`[self_protect] event_bus_pressure_warn_pct`**（默认 90）、退出 **`bus_dropped`**；**Job Object / anti_debug** 见 **[SELF_PROTECT_REGRESSION.md](SELF_PROTECT_REGRESSION.md)**。  
8. **Windows 服务停止**：**`--service`** 与 **`sc stop`** 见 **[WINDOWS_SERVICE_SHUTDOWN.md](WINDOWS_SERVICE_SHUTDOWN.md)**（与 **Ctrl+C** 同 **`edr_agent_shutdown`**）。

### 3.1 运行 exe 提示「与当前 Windows 版本不兼容」

该文案通常表示 **PE 机器类型与当前系统不匹配**，而不是「Windows 版本号太旧」一种情况：

| 情况 | 处理 |
|------|------|
| **64 位 exe 装在 32 位 Windows** | 在 **64 位 Windows** 上运行，或改用 **Win32（x86）** 目标重新编译（不推荐，Agent 默认按 x64 联调）。 |
| **ARM 版 Windows（如 Snapdragon 本）** 上放了 **x64-only** 的 exe | 需 **ARM64** 目标重编，或确认系统已开启 **x64 模拟**且使用该通道下的兼容构建。 |
| **exe 实际不是本机架构的 PE**（例如把 **macOS/Linux** 产物改名、或交叉编译用了 **i686** 却部署到纯 x64 策略环境） | 在 **本机 Windows** 用 **Visual Studio / CMake `-A x64`** 生成 **`edr_agent.exe`**，或用 **x86_64-w64-mingw32** 交叉产出 **x64 PE**，勿使用非 Windows PE。 |

在 **x64 Windows 10/11** 上本机编译时建议使用：

```powershell
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

再用 **`.\build\Release\edr_agent.exe --help`**（路径以生成器为准）验证。

### 3.2 Windows on ARM（**ARM64** 本机）

在 **ARM64 Windows** 上应生成 **ARM64 PE**，不要用 x64 的 `edr_agent.exe`（除非仅依赖 x64 模拟且 intentionally 使用 x64 构建）。

1. 安装 **Visual Studio 2022**（或 2019），工作负载勾选 **使用 C++ 的桌面开发**，并确保安装 **用于 ARM64 的 MSVC** 与 **Windows 11 SDK**（安装器中在单个组件里可搜 **ARM64**）。
2. 在 **`edr-agent`** 仓库根目录执行：

```powershell
.\scripts\build_windows_arm64.ps1
```

等价手动命令（与 CI **`windows-11-arm`** 一致，默认关闭 gRPC 以降低依赖）：

```powershell
cmake -B build-arm64 -G "Visual Studio 17 2022" -A ARM64 -DEDR_WITH_GRPC=OFF
cmake --build build-arm64 --config Release --parallel
.\build-arm64\Release\edr_agent.exe --help
```

**说明**：仓库内 **`./scripts/build_windows_mingw*.sh`** 面向 **x86_64 MinGW** PE，**不**用于产出 ARM64 Windows 二进制；ARM64 请以 **本机 MSVC** 或后续若增加的 **llvm-mingw aarch64** 工具链为准。

---

## 4. 服务包装示例（**草案**，需按路径与版本修改）

以下 **不** 随仓库执行，仅供运维/打包参考；亦可改用 **NSSM / 厂商服务框架**。自 **S1** 起，二进制支持内置 **`--service <与 sc create 同名>`**，**`sc stop`** 将触发 **`edr_agent_shutdown`**（与 **Ctrl+C** 同路径）；见 **`docs/WINDOWS_SERVICE_SHUTDOWN.md`**。注册命令也可用 **`scripts/edr_agent_install.ps1 -RegisterService -AgentExe …`**（见 **`docs/AGENT_INSTALLER.md`「方式三 · Windows 服务」**）。

**PowerShell（节选，需管理员）**：

```powershell
# 假设 edr_agent.exe 已置于 C:\Program Files\EDR\edr_agent.exe
# 假设配置为 C:\ProgramData\EDR\agent.toml
# --service 后的名称须与 sc create 的服务名一致（此处均为 EdrAgent）
$bin = '"C:\Program Files\EDR\edr_agent.exe" --service EdrAgent --config C:\ProgramData\EDR\agent.toml'
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
