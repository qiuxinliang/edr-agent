# Agent 独立安装器（注册 + 写 agent.toml）

平台在租户下签发 **Enrollment Token** 后，终端上只需能访问 **`POST /api/v1/enroll`**（无需登录 JWT），即可领取 **`endpoint_id`、`tenant_id`、`server_addr`**（gRPC 接入），并生成本地 **`agent.toml`**。

**与「管理端生成安装包 / 限时下载链接」的关系**（能力对照、24h 语义、目标架构）见 **`edr-backend/docs/INSTALLER_AND_DOWNLOAD_DESIGN.md`**。

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
# 仅打印：python3 scripts/edr_agent_install.py --dry-run
```

自签证书调试：`export EDR_INSECURE_TLS=1`

## 方式二：Bash 薄封装

需 **`python3`**，调用同目录 `edr_agent_install.py`：

```bash
chmod +x scripts/edr_agent_install.sh
export EDR_API_BASE="..." EDR_ENROLL_TOKEN="..."
./scripts/edr_agent_install.sh -o ./agent.toml
```

## 方式三：PowerShell（Windows，无 Python）

**`scripts/edr_agent_install.ps1`**，使用 `Invoke-RestMethod`。

```powershell
Set-ExecutionPolicy -Scope Process Bypass
$env:EDR_API_BASE="http://127.0.0.1:8080"
$env:EDR_ENROLL_TOKEN="..."
.\scripts\edr_agent_install.ps1 -Output "C:\Program Files\EDR Agent\agent.toml"
```

调试自签：`$env:EDR_INSECURE_TLS="1"`（脚本内使用旧版证书回调，仅用于测试）。

## 生成内容说明

安装器会写入：

- **`[server].address`**：平台返回的 **`server_addr`**（`host:port`），供 gRPC EventIngest。
- **`[agent].endpoint_id` / `tenant_id`**：注册结果。
- **`[platform].rest_base_url`**：`{EDR_API_BASE}/api/v1`，供攻击面等 REST（需本机有 `curl` 时与现有逻辑一致）。

**PowerShell（`edr_agent_install.ps1`，含 Windows 安装向导调用的版本）**：若脚本同目录存在 **`agent.toml.example`**（安装包与 Inno 默认会带上），注册成功后会将上述三项 **合并进完整示例模板** 再写入目标路径，从而保留 **`[collection]`、`[ave]`、`[preprocessing]`** 等默认段落，无需手工拼接。若合并失败则回退为仅含 `[server]`/`[agent]`/`[platform]` 的精简文件。需要旧行为时可传 **`-MinimalTomlOnly`**。

**mTLS**：当前 enroll 响应中证书字段多为空（`mtls_deferred`）；生产需按运维流程下发 CA/客户端证书并补全 `agent.toml` 中 `ca_cert` / `client_cert` / `client_key`。

## 与平台「安装包构建」接口的关系

`POST /admin/tenants/:id/installers` 当前可能返回占位脚本；**权威安装逻辑**以本目录 **`scripts/edr_agent_install.{py,ps1,sh}`** 为准，发布时可随 **`edr_agent` 二进制**一并打包。

## Release 一键安装（GitHub Actions `edr-agent-client-release`）

打 **`linux_主.次.修订`** / **`win_主.次.修订`** 标签并推送后，Release 附件包含：

- **Windows**
  - **`EDRAgentSetup-<tag>.exe`**：图形安装向导（默认安装到 `%ProgramFiles%\EDR Agent`），内含 **`edr_agent.exe`**、**`agent.toml.example`** 及 **`edr_agent_install.ps1`**。向导首页下一步为 **「Platform enrollment」**：填写 **平台 REST 根 URL**（与 `EDR_API_BASE` 相同，如 `https://host:8080`）和 **注册 Token** 后，安装结束时会自动调用 **`POST /api/v1/enroll`**，并在安装目录生成 **`agent.toml`**（与 **`edr_agent.exe` 同目录**）：默认将注册结果 **合并进同目录的 `agent.toml.example`**，得到带 **collection / ave / preprocessing** 等默认节的完整配置。若两项均留空则跳过注册，并从示例复制出一份 **`agent.toml`** 便于本地改。可选任务 **「Skip TLS certificate verification…」** 对应自签/实验环境的 **`EDR_INSECURE_TLS=1`**。参数在安装收尾阶段经 **`%TEMP%\edr_wizard_enroll.json`** 传给 PowerShell，成功后即删除。另见 **Runtime** 任务：**开机计划任务（SYSTEM）** 与可选 **安装目录 ACL 加固**；卸载须走「程序和功能」中的卸载程序（会先移除任务与进程）。详见 **[WINDOWS_DEPLOY.md §4.1](WINDOWS_DEPLOY.md)**。
  - **静默安装 + 命令行传入 API 与 Token**（便于 Intune/SCCM，无需向导页）：在 Inno 标准静默参数之外增加（**两项须同时出现或同时省略**；仅传其一安装程序会报错退出）：
    - **`/EDR_API_BASE=`**`<平台 REST 根 URL>`（与向导、`EDR_API_BASE` 一致，勿带末尾 `/api/v1`）；**短参数**：**`/API=`**（与长参数二选一，**长参数优先**）
    - **`/EDR_ENROLL_TOKEN=`**`<注册 Token>`**；短参数：**`/TOK=`**
    - 可选 **`/EDR_INSECURE_TLS=1`**（或 `true` / `yes`）；短参数：**`/TLS=1`**；等价于勾选向导里的 **Skip TLS certificate verification**；也可继续用 Inno 的 **`/MERGETASKS=enrollinsecure`**。
    - 示例：`EDRAgentSetup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /API=https://platform.example:8080 /TOK=...`
    - **安全提示**：Token 会出现在**安装进程命令行**中，可能被本机管理员或日志采集看到；生产环境更稳妥的做法是由端管注入短期 Token、或装包后立刻调用 **`edr_agent_install.ps1`**（从密钥保管库取 secret，不写进 exe 参数）。
  - **`edr-agent-<tag>-windows-amd64.zip`**：便携 **`edr_agent.exe`** + **`agent.toml.example`**。解压后请复制为 **`agent.toml`** 并完成注册或编辑；运行须显式指定配置，例如 **`edr_agent.exe --config .\agent.toml`**。不带参数（或 **`--help`** / **`-h`** / **`/?`**）时进程会**打印用法说明后退出**，不会再用无参方式连接内置占位地址。
- **Linux**
  - **`edr-agent-<tag>-linux-amd64.zip`**：解压进入 **`edr-agent-<tag>-linux-amd64/`**，执行 **`sudo ./install.sh`**，将把二进制安装到 **`/usr/local/bin/edr_agent`**；若不存在 **`/etc/edr-agent/agent.toml`**，则从包内示例复制一份。注册与写全配置仍用上文 **`edr_agent_install`** 脚本或平台安装包流程。
