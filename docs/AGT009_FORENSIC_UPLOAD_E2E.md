# AGT-009：取证 UploadFile 联调步骤（Windows 优先）

**关联**：[CLIENT_IMPROVEMENT_TASKS.md §AGT-009](CLIENT_IMPROVEMENT_TASKS.md)、[WINDOWS_SHELLCODE_FORENSIC_TODO.md](WINDOWS_SHELLCODE_FORENSIC_TODO.md)  

---

## 1. 范围

| 路径 | 客户端状态 | 本 E2E 文档覆盖 |
|------|------------|-----------------|
| **Webshell 命中** | `webshell_forensic.c` → **`edr_grpc_client_upload_file`**（分片，首片 `sha256`/`file_size`），失败落盘 | **是**（主路径） |
| **Shellcode / 远程 `forensic` 指令** | `do_forensic` 生成 manifest + `bundle.tgz`；**gRPC 就绪**时默认 **`UploadFile`**（**`EDR_FORENSIC_UPLOAD=0`** 关闭；**`FileChunk.alert_id`** = **`forensic-<command_id>`**，无 id 时为 **`forensic-job`**） | **是**（与 Webshell 同一 RPC；平台需已接 **UploadFile**） |

---

## 2. 前置条件

- Agent **Windows** 构建，`EDR_WITH_GRPC=ON`，`server.address` 指向可连通的 **EventIngest**。
- 平台侧 **ingest** 已实现 **`UploadFile`** 流式接收并落 **对象存储**（MinIO/S3 等），控制台或 API 可查到 **object key** 与元数据。
- 已 **enroll**，`agent.toml` 有效；Webshell 检测已启用（`[webshell_detector]` 与站点目录配置）。

### 2.1 gRPC 目标与 `UploadFile`（**C4**：勿连到未实现上传的 stub）

Agent 对 **`edr.v1.EventIngest`** 使用**同一** **`[server].address`**（及证书 / **`EDR_GRPC_INSECURE`**）建立通道，在该通道上并发调用 **`ReportEvents`**、**`Subscribe`** 与 **`UploadFile`**。因此：

1. **地址必须指向「已实现 `UploadFile` 流式接收」的 ingest 服务**（或经网关透明转发到该实现）。若仅指向只实现了 **`ReportEvents` / `Subscribe` / `ReportCommandResult`** 而 **`UploadFile` 仍为 stub** 的进程，客户端会收到 **`Unimplemented`**，取证包与 Webshell 文件**不会**进入对象存储。
2. **本仓库 edr-backend（便于排障）**：**`edr-api`** 在设置 **`INGEST_GRPC_ADDR`** 且配置 **S3/MinIO**（**`INGEST_ARTIFACT_MINIO_*`** 或回退 **`INSTALLER_MINIO_*`**）时，**`internal/ingestgrpc/upload_file.go`** 实现 **`UploadFile`** 流式落库，**`UploadResult.minio_key`** 为桶内对象键（前缀 **`agent-artifacts/`**）。若 **未** 配置对象存储，**`UploadResult.success=false`**（**`error`** 说明未配置）。若 Agent 连到**不含**本实现的旧二进制或其它 gRPC 占位服务，仍可能看到 **`Unimplemented`** 或 **`rpc_fail`** 上升。
3. **自检建议**：与平台同事确认 **ingest gRPC 监听地址**与 **HTTP API / 控制台** 地址**不是**同一端口时，勿把 Agent 配到仅 API 的 gRPC 占位端口；联调前用 **`grpcurl`**（若允许）或平台侧集成测试对 **`EventIngest/UploadFile`** 做一次空流探测，确认**非** `Unimplemented`。
4. **长期**：**C1** 在对外 EventIngest 上实现 **`UploadFile`**（或独立 **`ingest-file`** 服务）后，在 **`agent.toml` / 安装器** 中写清**唯一正确**的 gRPC 目标；本文与 **`WINDOWS_DEPLOY.md`** 预检表交叉引用。

---

## 3. 推荐联调步骤（Webshell）

1. 在监视目录下放置可触发规则的 **测试样本**（或按规则文档构造命中）。
2. 确认 Agent stderr / 日志出现 **命中** 与 **上传尝试**（成功或回退路径）。
3. 在 **平台** 侧验证：
   - 对象存储中存在对应 **key**；
   - **元数据**（`alert_id`、`tenant`、`sha256` 等）与 `ingest.proto` / 实现一致。
4. **失败路径**：断开 gRPC 或返回错误码，确认 **本地分层落盘**（`webshell/{tenant}/{date}/{alert_id}/...`）与 README 描述一致。
5. 记录 **`EDR_FORENSIC_OUT`**（若设置）与默认路径行为。

---

## 3.1 联调步骤（远程 `forensic`）

1. Agent **`EDR_WITH_GRPC=ON`**，高危策略允许（**`EDR_CMD_ENABLED=1`** 或 **`[command] allow_dangerous=true`**）；平台对终端下发 **`forensic`**（可选 payload 路径列表；**`EDR_FORENSIC_COPY_PATHS=1`** 时逐行复制）。
2. 作业目录（默认 **`%TEMP%\\edr_forensic\\<command_id>`** 或 **`/tmp/edr_forensic/...`**）下应有 **`manifest.txt`**；**`bundle.tgz`** 在 **`tar`** 成功时非空。
3. 未设置 **`EDR_FORENSIC_UPLOAD=0`** 且 **gRPC 已就绪**时，**`[command][audit]`** 中 **`detail`** 含 **`UploadFile key=…`** 或 **`UploadFile failed`** / **`skip UploadFile`** 及原因。
4. 平台 **`UploadFile`** 入账：**`FileChunk.alert_id`** = **`forensic-<command_id>`**（与 Webshell 告警 **`alert_id`** 区分；对象存储 key 命名以后端为准）。
5. **`EDR_FORENSIC_UPLOAD=0`**：确认不发起上传，本地 **`bundle.tgz`** 仍保留。

---

## 4. 观测与排障

- gRPC：**`[grpc] rpc_ok` / `rpc_fail`**（退出汇总）；上传失败时应有明确日志。
- 与 **SOAR**、**ReportCommandResult** 无强绑定；取证上传属 **ingest** 能力。

---

## 5. 后续（仍属产品 backlog）

- **自动化脚本**：可在 CI/专机增加「下发 `forensic` → 轮询对象存储 / 平台 API」的冒烟脚本（依赖 **edr-backend** 测试接口）。

---

**状态（AGT-009）**：**Webshell** 与 **`forensic` bundle** 均可走 **`UploadFile`**；取证自动上传开关见 **`EDR_FORENSIC_UPLOAD`**（**`README.md`** 环境变量表）。**C4**：**§2.1** 已写明 **`[server].address`** 与 **`UploadFile` stub** 误配排障。
