# AGT-009：取证 UploadFile 联调步骤（Windows 优先）

**关联**：[CLIENT_IMPROVEMENT_TASKS.md §AGT-009](CLIENT_IMPROVEMENT_TASKS.md)、[WINDOWS_SHELLCODE_FORENSIC_TODO.md](WINDOWS_SHELLCODE_FORENSIC_TODO.md)  

---

## 1. 范围

| 路径 | 客户端状态 | 本 E2E 文档覆盖 |
|------|------------|-----------------|
| **Webshell 命中** | `webshell_forensic.c` → **`edr_grpc_client_upload_file`**（分片，首片 `sha256`/`file_size`），失败落盘 | **是**（主路径） |
| **Shellcode / 远程 `forensic` 指令** | `do_forensic` 生成 manifest + `bundle.tgz`；**自动上传 bundle** 仍见 TODO | **部分**（本地产物与平台对象存储需后续迭代，见 **WINDOWS_SHELLCODE_FORENSIC_TODO** P1） |

---

## 2. 前置条件

- Agent **Windows** 构建，`EDR_WITH_GRPC=ON`，`server.address` 指向可连通的 **EventIngest**。
- 平台侧 **ingest** 已实现 **`UploadFile`** 流式接收并落 **对象存储**（MinIO/S3 等），控制台或 API 可查到 **object key** 与元数据。
- 已 **enroll**，`agent.toml` 有效；Webshell 检测已启用（`[webshell_detector]` 与站点目录配置）。

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

## 4. 观测与排障

- gRPC：**`[grpc] rpc_ok` / `rpc_fail`**（退出汇总）；上传失败时应有明确日志。
- 与 **SOAR**、**ReportCommandResult** 无强绑定；取证上传属 **ingest** 能力。

---

## 5. 后续（仍属产品 backlog）

- **`forensic` 指令完成后自动上传 `bundle.tgz`**：跟踪 **WINDOWS_SHELLCODE_FORENSIC_TODO**「上传」勾选项。
- **自动化脚本**：可在 CI/专机增加「放置样本 → 轮询平台 API」的冒烟脚本（依赖 **edr-backend** 测试接口）。

---

**状态（AGT-009）**：**Webshell UploadFile** 联调步骤与平台侧验收要点已文档化；**远程取证 bundle 流式上传** 以 **WINDOWS_SHELLCODE_FORENSIC_TODO** 为续跟踪入口。
