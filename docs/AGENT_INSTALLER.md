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
.\scripts\edr_agent_install.ps1 -Output "C:\ProgramData\EDR\agent.toml"
```

调试自签：`$env:EDR_INSECURE_TLS="1"`（脚本内使用旧版证书回调，仅用于测试）。

### 方式三 · Windows 服务（可选，`--service` 与 SCM 对齐）

与 **`docs/WINDOWS_SERVICE_SHUTDOWN.md`**、**`docs/WINDOWS_DEPLOY.md` §4** 一致：**`sc create` 的服务名**须与 **`binPath` 中 `--service` 后的名称**相同（脚本默认 **`EdrAgent`**，可用 **`-ServiceName`** 或 **`EDR_SERVICE_NAME`**）。

- **Enroll 并注册服务**（管理员 PowerShell）：

```powershell
.\scripts\edr_agent_install.ps1 -ApiBase "http://127.0.0.1:8080" -Token "enr_..." `
  -Output "C:\ProgramData\EDR\agent.toml" `
  -AgentExe "C:\Program Files\EDR\edr_agent.exe" -RegisterService -ServiceName EdrAgent
```

- **已有 `agent.toml`，仅注册**：**`-SkipEnroll`** + **`-RegisterService`** + **`-AgentExe`**（路径同 **`EDR_AGENT_EXE`**）。

- **卸载服务**（不删配置与二进制）：**`-UnregisterService -ServiceName EdrAgent`**。

- **服务已存在需重建**：加 **`-ReplaceService`**（先 **stop/delete** 再 **create**）。

**`edr-backend`** 内嵌 zip 使用的副本见 **`platform/internal/installer/embedded/`**；更新 **`edr-agent/scripts/edr_agent_install.ps1`** 后请执行仓库 **`edr-backend/scripts/sync_agent_installer_embedded.sh`**（或等价复制），见 **`embedded/SYNC_FROM_EDR_AGENT.md`**。

## 生成内容说明

安装器会写入：

- **`[server].address`**：平台返回的 **`server_addr`**（`host:port`），供 gRPC EventIngest。
- **`[agent].endpoint_id` / `tenant_id`**：注册结果。
- **`[platform].rest_base_url`**：`{EDR_API_BASE}/api/v1`，供攻击面等 REST（需本机有 `curl` 时与现有逻辑一致）。

**mTLS**：当前 enroll 响应中证书字段多为空（`mtls_deferred`）；生产需按运维流程下发 CA/客户端证书并补全 `agent.toml` 中 `ca_cert` / `client_cert` / `client_key`。

## 与平台「安装包构建」接口的关系

`POST /admin/tenants/:id/installers` 当前可能返回占位脚本；**权威安装逻辑**以本目录 **`scripts/edr_agent_install.{py,ps1,sh}`** 为准，发布时可随 **`edr_agent` 二进制**一并打包。
