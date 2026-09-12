# Agent 独立安装器（注册 + 写 agent.toml）

平台在租户下签发 **Enrollment Token** 后，终端上只需能访问 **`POST /api/v1/enroll`**（无需登录 JWT），即可领取 **`endpoint_id`、`tenant_id`、`server_addr`**（历史/gRPC 兼容字段）以及生产 REST 所需的 **Agent 专用 Bearer**，并生成本地 **`agent.toml`**。该 Bearer 是租户 + endpoint 绑定的最小权限 Agent 凭据，不应替换为平台管理员 JWT。

**与「管理端生成安装包 / 限时下载链接」的关系**（能力对照、24h 语义、目标架构）见 **`edr-backend/docs/INSTALLER_AND_DOWNLOAD_DESIGN.md`**。
**端到端发布主流程**（Agent 二进制、预生成安装包、租户下载的分工）见 **`edr-backend/docs/AGENT_TERMINAL_RELEASE_FLOW.md`**。

平台 **`GET .../admin/tenants/:id/installers/:buildId/download`** 返回的 **zip** 内含与本目录同名的 **`edr_agent_install.{py,ps1,sh}`**（由 **`edr-backend/platform/internal/installer/embedded/`** 嵌入构建；更新脚本时请与这里同步，见该目录下 **`SYNC_FROM_EDR_AGENT.md`**；**发版时**见 **`edr-backend/docs/RELEASE_AGENT_INSTALLER_BUNDLE.md`**）及 **`README.txt`**（不含 Token 明文）。

管理端前端入口与权限说明：**`edr-frontend/docs/AGENT_INSTALLER_ADMIN_UI.md`**。

## 前置条件

- 平台已创建租户，并已创建 **有效注册 Token**（与目标 OS 的 `os_type` 一致：windows / linux / all）。
- 终端能访问 **platform 的 HTTP(S) 根**（例如 `http://127.0.0.1:8080` 或公网域名），路径为 **`{EDR_API_BASE}/api/v1/enroll`**。
- **`server_addr` 解析**与平台部署一致（租户 `features.grpcServerAddress` → `ENROLL_PUBLIC_SERVER_ADDR` → `PUBLIC_API_BASE` → 兜底），见 `edr-backend` 中 `resolveAgentServerAddress`。

## 方式一：Python（跨平台，推荐）

仓库 **`scripts/edr_agent_install.py`**，仅标准库。

```bash
export EDR_API_BASE="http://127.0.0.1:8080"
export EDR_ENROLL_TOKEN="平台下发的明文 Token"
python3 scripts/edr_agent_install.py --output ./agent.toml
# 仍会生成/复用端侧私钥与 CSR 并请求 enroll；只不写 agent.toml 和返回的证书：python3 scripts/edr_agent_install.py --dry-run
```

默认写入前会查找输出目录、脚本/安装目录及已安装位置的 Agent，并用真实二进制执行 `--config <staged-path> --config-test`。也可用 `EDR_AGENT_EXECUTABLE=/path/to/edr_agent` 显式指定。解析失败或找不到 Agent 时不会覆盖旧 `agent.toml`。只下载了后端“脚本包”、尚未取得 Agent 二进制时，可显式使用 `--generate-only`；该模式会标明未运行 Agent parser，不应作为完成安装的验收证据。

自签证书调试：`export EDR_INSECURE_TLS=1`

## 方式二：Bash 薄封装

需 **`python3`**，调用同目录 `edr_agent_install.py`：

```bash
chmod +x scripts/edr_agent_install.sh
export EDR_API_BASE="..." EDR_ENROLL_TOKEN="..."
./scripts/edr_agent_install.sh -o ./agent.toml
```

## 方式三：PowerShell（Windows，一条命令）

**`scripts/edr_agent_install.ps1`**，使用 `Invoke-RestMethod`。默认会自动生成终端私钥和 CSR，调用 enroll 换取 `ca.pem` / `client.pem`，并写入紧凑可运行的 `agent.toml`；不再要求手工设置多条环境变量。

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\edr_agent_install.ps1 `
  -ApiBase "https://edr.example.com:8080" `
  -EnrollToken "<token>" `
  -Output "C:\Program Files\FDSecurity\agent.toml" `
  -TrustCa `
  -InstallAutorun
```

如果现场流程已预置并核实来源的 **`C:\Program Files\FDSecurity\certs\ca.pem`**，`-TrustCa` 可在注册前导入 Windows Root；不要把关闭 TLS 校验当作兼容性修复。Windows CNG 路径优先使用可用的原生 API，缺少 `CertificateRequest` 等能力时进入有超时边界的 `certreq` 兼容路径；实际密钥提供方和 TLS 能力以安装诊断为准，不能仅由 PowerShell 主版本判断。

## 方式四：Windows zip 一条 exe 命令（推荐便携包）

`FDSensor.exe` 是当前正式安装入口，可调用同目录或 `scripts\` 下的安装脚本。把 zip 解压到 **`C:\Program Files\FDSecurity`** 后，在管理员 PowerShell 执行：

```powershell
.\FDSensor.exe --install `
  --api-base "https://edr.example.com:8080" `
  --enroll-token "<token>" `
  --trust-ca `
  --install-service `
  --enable-response-actions
```

该入口会完成 enroll、端侧私钥/CSR、唯一客户端证书、紧凑 `agent.toml` 写入，并在 `--install-service` 模式下注册并启动 Windows 服务。开发或临时测试可把 `--install-service` 换成 `--install-autorun`；两者不要同时使用，避免同一主机启动两个 Agent 实例。常用可选参数：

| 参数 | 说明 |
|------|------|
| `--install-dir <dir>` | 默认使用 `FDSensor.exe` 所在目录；生产建议为 `C:\Program Files\FDSecurity` |
| `--output <path>` | 指定 `agent.toml` 输出路径；也可用 `--config <path>` 兼容指定 |
| `--ca-cert <path>` | 指定 CA 证书路径；默认 `<install-dir>\certs\ca.pem` |
| `--force-enroll` | 已存在 `agent.toml` 时仍重新 enroll，适合重装或换租户 |
| `--service-name <name>` | 与 `--install-service` 配合，指定 Windows 服务名 |

批量分发时可使用 zip 内 **`scripts\edr_agent_zip_deploy.ps1`**：它会把解压目录复制到 `C:\Program Files\FDSecurity`，再调用上面的 exe 安装入口，适合 Intune/SCCM/GPO 脚本化部署：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\edr_agent_zip_deploy.ps1 `
  -ApiBase "https://edr.example.com:8080" `
  -EnrollToken "<token>" `
  -TrustCa `
  -RuntimeMode service `
  -EnableResponseActions
```

## 生成内容说明

安装器会写入：

- **`[server].address`**：保留平台返回的 **`server_addr`**（`host:port`）兼容字段；当前产品通信走 HTTP(S)，不启用已退役的 gRPC 客户端。
- **`[agent].endpoint_id` / `tenant_id`**：注册结果。
- **`[platform].rest_base_url`**：`{EDR_API_BASE}/api/v1`，供 Agent REST 上报、控制与策略拉取。
- **`[platform].rest_bearer_token`**：后端 enroll 返回的 Agent 专用 Bearer（`platform_bearer_token` / `agent_access_token`）。安装器会自动写入；旧后端未返回时保持空值以兼容实验环境。生产不要把 `platform_ops_full`、`admin` 等平台用户 JWT 写入 Agent 配置。

**PowerShell（`edr_agent_install.ps1`，含 Windows 安装向导调用的版本）**：注册成功后默认写入紧凑配置，包含 **`[server]`、`[agent]`、`[platform]`、`[collection]`、`[ave]`、`[offline]`** 等运行必需段落，并只保留一行英文说明，避免中文编码、模板注释和异常换行污染现场配置。如确需旧版“合并完整模板”行为，可传 **`-UseTemplateToml`** 或设置 **`EDR_USE_TEMPLATE_TOML=1`**；调试模板注释可同时传 **`-KeepTemplateComments`**。`--dry-run` / `-DryRun` 输出会隐藏 Bearer 明文。

**mTLS**：enroll 使用端侧 CSR 签发唯一客户端证书，不从服务端接收私钥。PEM 模式使用本地私钥；Windows 原生证书存储模式使用证书存储位置、指纹和对应密钥提供方，不要求为已退役的 gRPC 通道导出 PEM 私钥。CNG/TPM/PKCS#11 的可用性需结合 OS、依赖及运行时诊断分别验收，不能因注册成功就断言所有传输分支均可用。

**RTR shell 签名**：`rtr_shell` / `shell_open` / `shell_close` 始终要求命令签名。推荐服务端使用 **`EDR_COMMAND_SIGNING_PRIVATE_KEY_PATH`** 保存 Ed25519 私钥，Agent 使用 **`[command] signing_public_key_path`** 或 **`EDR_COMMAND_VERIFY_PUBLIC_KEY_PATH`** 保存对应公钥；否则 Agent 会返回 `command sigv2 public key missing` 或 `missing command sigv2 signature`。旧版 HMAC **`EDR_COMMAND_SIGNING_KEY`** 仅作为灰度兼容。Windows 前台验证可临时设置：

```powershell
$env:EDR_COMMAND_VERIFY_PUBLIC_KEY_PATH="C:\Program Files\FDSecurity\certs\command-signing.pub.pem"
$env:EDR_RTR_SHELL_ALLOWLIST="whoami,hostname,ipconfig,tasklist,netstat,dir,powershell,cmd"
.\FDSensor.exe --config .\agent.toml
```

服务方式运行时请改为机器级环境变量并重启服务/计划任务；生产环境应由密钥管理或证书签名链路下发，不要把共享 HMAC 明文写入安装包。

## 与平台「安装包构建」接口的关系

`POST /admin/tenants/:id/installers` 当前可能返回占位脚本；**权威安装逻辑**以本目录 **`scripts/edr_agent_install.{py,ps1,sh}`** 为准，发布时可随 Windows **`FDSensor.exe`** 或 Linux **`edr_agent`** 二进制一并打包。

## Release 一键安装（GitHub Actions `edr-agent-client-release`）

打 **`linux_主.次.修订`** / **`win_主.次.修订`** 标签并推送后，Release 附件包含：

- **Windows**
  - **`EDRAgentSetup-<tag>.exe`**：图形安装向导（默认安装到 `%ProgramFiles%\FDSecurity`），内含 **`FDSensor.exe`**、**`agent.toml.example`** 及 **`edr_agent_install.ps1`**。向导首页下一步为 **「Platform enrollment」**：填写 **平台 REST 根 URL**（与 `EDR_API_BASE` 相同，如 `https://host:8080`）和 **注册 Token** 后，安装结束时会自动调用 **`POST /api/v1/enroll`**，并在安装目录生成紧凑 **`agent.toml`**（与 **`FDSensor.exe` 同目录**）。若两项均留空则跳过注册，并从示例复制出一份 **`agent.toml`** 便于本地改。可选任务 **「Skip TLS certificate verification…」** 对应自签/实验环境的 **`EDR_INSECURE_TLS=1`**。参数在安装收尾阶段经 **`%TEMP%\edr_wizard_enroll.json`** 传给 PowerShell，成功后即删除。另见 **Runtime** 任务：**开机计划任务（SYSTEM）** 与可选 **安装目录 ACL 加固**；卸载须走「程序和功能」中的卸载程序（会先移除任务与进程）。详见 **[WINDOWS_DEPLOY.md §4.1](WINDOWS_DEPLOY.md)**。
  - **静默安装 + 命令行传入 API 与 Token**（便于 Intune/SCCM，无需向导页）：在 Inno 标准静默参数之外增加（**两项须同时出现或同时省略**；仅传其一安装程序会报错退出）：
    - **`/EDR_API_BASE=`**`<平台 REST 根 URL>`（与向导、`EDR_API_BASE` 一致，勿带末尾 `/api/v1`）；**短参数**：**`/API=`**（与长参数二选一，**长参数优先**）
    - **`/EDR_ENROLL_TOKEN=`**`<注册 Token>`**；短参数：**`/TOK=`**
    - 可选 **`/EDR_INSECURE_TLS=1`**（或 `true` / `yes`）；短参数：**`/TLS=1`**；等价于勾选向导里的 **Skip TLS certificate verification**；也可继续用 Inno 的 **`/MERGETASKS=enrollinsecure`**。
    - 示例：`EDRAgentSetup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /API=https://platform.example:8080 /TOK=...`
    - **安全提示**：Token 会出现在**安装进程命令行**中，可能被本机管理员或日志采集看到；生产环境更稳妥的做法是由端管注入短期 Token、或装包后立刻调用 **`edr_agent_install.ps1`**（从密钥保管库取 secret，不写进 exe 参数）。
  - **`edr-agent-<tag>-windows-amd64-exe.zip`**：便携 **`FDSensor.exe`** + vcpkg 运行时 DLL（必须包含 **`libyara.dll` / `yara.dll`** 等 YARA runtime，或静态 triplet 下通过 vcpkg libyara 包件校验）+ `VERSION` + Windows 运维脚本 + 加密 P0 规则包 + 随包规则目录 **`rules/forensic`**、**`rules/shellcode`**、**`rules/webshell`**。Windows 发布包必须启用 vcpkg manifest feature **`yara`**；MSVC 使用 **`x64-windows`**，MinGW 使用 **`x64-mingw-dynamic`** 这类动态 triplet。`EDR_REQUIRE_YARA=ON` 在 Windows 上只接受 vcpkg **`unofficial::libyara::libyara`**。YARA runtime 与规则目录是两类资产：runtime 保证引擎可用，规则目录提供签名内容；`yara_scan` 规则来源优先级为 inline rules > `[command].forensic_yara_rules_dir` > `EDR_YARA_RULES_DIR` > `rules/forensic`。解压到 **`C:\Program Files\FDSecurity`** 后优先执行上文 **`FDSensor.exe --install ...`**；已生成 `agent.toml` 后可用 **`FDSensor.exe --config .\agent.toml`** 前台验证。旧包可能仍带 `edr_agent.exe` 或安装在 `C:\Program Files\EDR Agent`；现有发现、升级和卸载兼容保留，但不再把旧名称用于新装示例。
- **Linux**
  - **`edr-agent-<tag>-linux-amd64.zip`**：解压进入 **`edr-agent-<tag>-linux-amd64/`**，执行 **`sudo ./install.sh`**，将把二进制安装到 **`/usr/local/bin/edr_agent`**；若不存在 **`/etc/edr-agent/agent.toml`**，则从包内示例复制一份。注册与写全配置仍用上文 **`edr_agent_install`** 脚本或平台安装包流程。
