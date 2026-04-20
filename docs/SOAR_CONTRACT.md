# SOAR 协议级契约（edr-agent ↔ 管控 / 编排）

本文约定终端与 **EventIngest** gRPC 服务之间，在 **指令下发** 与 **执行结果回传** 上的字段语义，便于 SOAR、playbook 与工单系统对账。**权威定义**以 `proto/edr/v1/ingest.proto` 为准。

---

## 1. 下行：Subscribe → `CommandEnvelope`（服务端 → 终端）

每条流消息表示一条待执行指令。

| 字段 | 类型 | 说明 |
|------|------|------|
| `command_id` | string | 指令唯一标识（建议 UUID）；与回传结果 **必填** 对齐。 |
| `command_type` | string | 逻辑类型，如 `noop`、`ping`、`echo`、`isolate`、`kill`、`forensic`；**PMFE（§21）**：`pmfe_scan` / `CMD_PMFE_SCAN`（内存粗扫入队，见 `pmfe_engine.c`）；**AVE（§5）**：`ave_status` / `ave_fingerprint` / `ave_infer`；**自保护/健康**：`self_protect_status` / `agent_health` / `health_status`（见 `command_stub.c`）；**攻击面（§19）**：`GET_ATTACK_SURFACE` / `get_attack_surface` / `REFRESH_ATTACK_SURFACE`（采集并 `POST` 平台 `.../endpoints/:id/attack-surface`，见 `attack_surface_report.c`）。 |
| `payload` | bytes | 类型相关参数（如 kill 的 `{"pid":1234}` UTF-8 JSON）。 |
| **SOAR 扩展（可选，空表示非编排下发）** | | |
| `soar_correlation_id` | string | 与 SOAR **工单 / 全局 run** 关联，建议 UUID。 |
| `playbook_run_id` | string | 某次 playbook **实例** id。 |
| `playbook_step_id` | string | playbook 内 **步骤** id。 |
| `issued_at_unix_ms` | int64 | 服务端签发时间（Unix 毫秒）；`0` 表示未填。 |
| `deadline_ms` | uint32 | 建议最大执行耗时（毫秒）；`0` 表示未限制（终端当前为 **提示性**，未强制杀）。 |
| `idempotency_key` | string | 幂等键，便于服务端去重。 |

**C 侧结构体**：`EdrSoarCommandMeta`（`include/edr/command.h`）与上表一一对应（定长缓冲，由 gRPC 层截断写入）。

### AVE 指令 payload（UTF-8 JSON）

| command_type | payload | 说明 |
|--------------|---------|------|
| `ave_status` / `ave_model_status` | 可空 | 返回模型目录扫描摘要（`model_files` / `non_dir_files` / `ready`），见 `edr_ave_get_scan_counts`。 |
| `ave_fingerprint` / `ave_fp` | `{"path":"/abs/path"}` | 对文件做前 256B FNV-1a 指纹；**只读**，无需 `EDR_CMD_ENABLED`。 |
| `ave_infer` | `{"path":"/abs/path"}` | 调用 **`AVE_ScanFile`**（含 SHA256、`EDRVerdict`、`verification_layer`：可为 **L1**（证书信任）/ **L2**（文件哈希白名单）/ **L3**（IOC）/ **AI**（ONNX）等、耗时）；成功时 `detail` 形如 `final=... raw=... final_conf=... sha256=... dur_ms=...`。未接 ONNX 且未命中 L1–L3 时可能返回 **FAILED** + `EDR_ERR_NOT_IMPL`；联调可设 **`EDR_AVE_INFER_DRY_RUN=1`**。需进程已 **`edr_command_bind_config`** 且 **`AVE_InitFromEdrConfig`** 已完成（main 在 `edr_agent_init` 后绑定）。 |
| `self_protect_status` / `agent_health` / `health_status` | 可空 | 返回自保护快照：`debugger`、`bus_pct`、Windows `job_win`、总线 `hw_hits`/`dropped` 等（`edr_self_protect_format_status`）。**只读**，无需高危开关。 |

### PMFE 指令 payload（UTF-8 JSON）

| command_type | payload | 说明 |
|----------------|---------|------|
| `pmfe_scan` / `CMD_PMFE_SCAN` | `{"pid":1234}` | 将目标 PID 提交 PMFE 工作队列，**异步**执行：**Windows**：模块基线 + VAD 粗筛 + **高分区精读**（`EDR_PMFE_VAD_PEEK` 个区域，默认 8）：读首 512B 统计 **MZ 命中**、**Shannon 熵**；可选 **`EDR_PMFE_AVE_TEMPFILE=1`** 时对最多 3 个 MZ 区写入 `%TEMP%\\edr_pmfe_<pid>_<addr>.bin` 并调用 **`AVE_ScanFile`**（与主进程 **`AVE_InitFromEdrConfig`** 一致；需已 `edr_pmfe_bind_config` + 模型就绪 / 或 `EDR_AVE_INFER_DRY_RUN=1`）。**Linux**：`/proc/<pid>/maps` 基线统计。`ReportCommandResult` 的 **OK** 仅表示已入队。摘要写入 stderr / `EDR_CMD_AUDIT_PATH`。其它可选：`EDR_PMFE_STOMP_BYTES`、`EDR_PMFE_DISK_HASH_MAX`。 |

- **禁用 PMFE 线程**：`EDR_PMFE_DISABLED=1` 时 `edr_pmfe_init` 不启动工作线程，`pmfe_scan` 将因「未运行」入队失败。
- **预处理自动入队 PMFE**：**Windows**：`EDR_PMFE_ETW_AUTO=1` 且 PMFE 已初始化时，对 **`EDR_EVENT_PROTOCOL_SHELLCODE`**（WinDivert ETW1）：当 `score` ≥ **`EDR_PMFE_ETW_SHELLCODE_SCORE`**（默认 **0.65**）时，将 **`br.pid`**（或 ETW1 中 **`hint_pid`** → `epid` 覆盖后的 PID）或按 **`dpt`** 经 **`GetExtendedTcpTable`** 解析的本地 IPv4 端口属主 PID 提交 **`edr_pmfe_submit_etw_scan_ex`**（内部 `etw:shellcode`；**`slot.priority==0`→P0 否则 P1**；ETW1 可选 **`va=`/`hint=`** 为 VAD 精扫 hint）。**`EDR_PMFE_ETW_COOLDOWN_MS`** 同 PID 冷却，默认 **30000**。**不依赖** `EDR_CMD_ENABLED`。**Linux**：同变量下对 **`EDR_EVENT_WEBSHELL_DETECTED`** 提交 **`etw:webshell`**（P0/P1 由 `slot.priority`）。
- **监听表刷新（Windows / Linux）**：**`edr_pmfe_init`** 后 **60s** 周期 **`edr_pmfe_listen_table_refresh`**。**Windows**：ETW Kernel-Process 的 **`EDR_EVENT_PROCESS_CREATE` / `EDR_EVENT_PROCESS_TERMINATE`** 会触发 **`edr_pmfe_on_process_lifecycle_hint`**（约 **1s** 去抖）。**Linux**：同样 API，可由未来进程事件源调用；设 **`EDR_PMFE_LISTEN_REFRESH_ON_PROCESS=0`** 可关闭去抖。`EDR_PMFE_DISABLED=1` 时不登记延迟刷新。

### 高危指令策略

- **环境变量**：`EDR_CMD_ENABLED=1` 或 `EDR_CMD_DANGEROUS=1` 时允许 `kill` / `isolate` / `forensic` / **`pmfe_scan`**（读他进程内存，与取证同级敏感）。
- **配置**：`[command] allow_dangerous = true` 与上述环境变量等效（便于生产用 TOML 固定策略）。
- **kill 白名单**（可选）：设置 `EDR_CMD_KILL_ALLOWLIST=1234,5678` 后，仅允许终止列表内 PID（仍须先满足高危策略）。

---

## 2. 上行：ReportCommandResult（终端 → 服务端）

终端在指令 **执行结束后**（成功、拒绝或失败）调用 **`ReportCommandResult`**，携带 **`CommandExecutionResult`**。

| 字段 | 说明 |
|------|------|
| `command_id` | 与下行一致。 |
| `endpoint_id` | 终端身份（与配置 `agent.endpoint_id` 一致，由客户端填充）。 |
| `agent_version` | 代理版本字符串。 |
| `soar_correlation_id` / `playbook_run_id` / `playbook_step_id` | 自下行 **回显**，便于编排闭合。 |
| `status` | 见下节枚举。 |
| `exit_code` | 约定型整数：`0` 成功；非 `0` 为子错误码（见实现内注释）。 |
| `detail_utf8` | 短人类可读说明（英文或 UTF-8 中文均可，宜短）。 |
| `finished_unix_ms` | 终端完成时间（Unix 毫秒）。 |

### `CommandExecutionStatus`（与 `EdrCommandExecutionStatus` 数值一致）

| 枚举 | 值 | 含义 |
|------|---|------|
| `UNSPECIFIED` | 0 | 未分类 |
| `OK` | 1 | 已按语义成功完成 |
| `REJECTED` | 2 | 策略拒绝（如未启用 `EDR_CMD_ENABLED`） |
| `FAILED` | 3 | 已接受执行但失败（如 kill 失败） |
| `UNKNOWN_TYPE` | 4 | 未知 `command_type` |

---

## 3. 何时上报

默认：仅当 **`soar_correlation_id` 或 `playbook_run_id` 非空**（表示编排下发）时，终端会尝试 **`ReportCommandResult`**（需 gRPC 已连接）。

调试：设置环境变量 **`EDR_SOAR_REPORT_ALWAYS=1`** 时，对上述字段无要求也会尝试上报（便于联调）。

未连接 gRPC 时，上报 API 失败；不影响本地审计（`EDR_CMD_AUDIT_PATH` 等仍可用）。

---

## 4. 连接保活与「在线」语义（AGT-007）

本节约定 **终端行为**（§4.1）与 **平台「在线」判定契约**（§4.2）。**§4.2 的实现与落库在 edr-backend**；控制台 UI 以平台配置为准。

### 4.1 终端当前行为（已实现）

- **无** 独立「心跳」RPC；**无** 将空载荷 **`ReportEvents`** 作为心跳的设计。
- 使用 **gRPC 通道级 keepalive**：TOML **`[server].keepalive_interval_s`**（默认 **30**）映射为 **`GRPC_ARG_KEEPALIVE_TIME_MS`**，并设置 **`GRPC_ARG_KEEPALIVE_TIMEOUT_MS`**、**`GRPC_ARG_KEEPALIVE_PERMIT_WITHOUT_CALLS`** 等，见 **`src/transport/grpc_client_impl.cpp`**；README **`[server]`** 配置表。
- **`ReportEvents`**（事件批次 unary）与 **`Subscribe`**（指令 **server streaming**）共用同一 gRPC 通道时，由 gRPC 在空闲连接上按上述间隔维持存活（底层为 HTTP/2 级行为，以 gRPC 版本为准），用于减轻半开连接与中间设备超时。
- **`Subscribe`** 流断开后，终端按 **500ms 起指数退避（上限 60s）** 自动重连（见 README gRPC 小节）；与 keepalive **并存**，语义不同（一为流恢复，一为连接探测）。

### 4.2 平台「在线」判定（契约约定；**实现归属 edr-backend**）

以下为 **推荐默认语义**，供控制台、API 与 **edr-backend** 实现一致；产品可通过配置覆盖阈值或组合逻辑，但 **须在控制台或运维文档中可解释**。

#### 4.2.1 推荐：滑动时间窗内的「信号」

记 **`T_offline`** 为 **离线判定超时**（秒），建议 **90～180**（约为 **§4.1** 默认 keepalive **30s** 的 3～6 倍，降低短暂网络抖动导致的误判）；**具体值由 edr-backend / 产品配置**，非终端硬编码。

在任意时刻，若自 **最近一次有效信号** 起经过时间 **> `T_offline`**，则控制台展示 **离线**；否则 **在线**。

**有效信号**（满足 **任一** 即可刷新「最后在线时间」，推荐默认）：

1. **gRPC `EventIngest` 连接** 对该 `endpoint_id` **仍建立**（含 HTTP/2 keepalive 维持的空闲连接；实现上由 **网关或 ingest 服务** 维护 per-connection / per-endpoint 状态）。
2. **最近一次 `ReportEvents` unary RPC 返回成功**（已收到批次并校验通过；若环境仅走 **HTTP** `POST .../report-events`，可将 **同终端身份** 的 **最近一次成功 HTTP 上报时间** 等价计入，但须在 **edr-backend** 文档中写明映射关系）。

#### 4.2.2 `Subscribe` 服务端流

- **不推荐** 单独以「`Subscribe` 流是否建立」作为 **唯一** 在线条件：终端在流断开后会 **退避重连**（见 **§4.1**），短时间与 (1)/(2) 可能不一致。
- 若产品需要 **「可下发指令」** 与 **「在线」** 区分展示，可额外维护 **指令通道就绪**（例如 **Subscribe 流活跃**），与 **§4.2.1** 的 **在线** 并列展示。

#### 4.2.3 后端待实现（edr-backend）

| 工作项 | 说明 |
|--------|------|
| 时间戳 | 持久化或缓存 **`last_seen_at`**（或等价）：由 (1)/(2) 更新 |
| 连接生命周期 | 在 **EventIngest** 或前置网关记录 **gRPC 连接建立/断开**（若可获取 `endpoint_id`） |
| `T_offline` | 配置项；默认建议 **90～180** |
| 控制台 API | 列表/详情返回 **在线状态** 与 **last_seen_at**，与上述规则一致 |

**AGT-007（edr-agent 任务单）**：终端侧与 **§4.1 / §4.2 文档** 已关闭；**§4.2.3 代码与表结构** 在 **edr-backend** 跟踪。

---

## 5. 与服务端实现注意（AGT-008）

### 5.1 终端（edr-agent）

- **已实现**：指令执行结束后，在满足 [§3](#3-何时上报) 条件时调用 **`edr_grpc_client_report_command_result`**（`src/transport/grpc_client_impl.cpp`，由 `command_stub.c` 触发）。
- **`EDR_WITH_GRPC=OFF`** 或链接 **stub**（`grpc_client_stub.c`）时：该函数恒返回 **`-1`**（与「未连上服务」一致），**不**抛异常；本地审计仍可用（**`EDR_CMD_AUDIT_PATH`**）。
- **桩代码**：修改 `proto/edr/v1/ingest.proto` 后执行 **`chmod +x scripts/regen_ingest_proto.sh && ./scripts/regen_ingest_proto.sh`**（需 `protoc` 与 `grpc_cpp_plugin`）。

### 5.2 平台（edr-backend）

- **当前**：**HTTP** **`POST /api/v1/ingest/report-events`** 与 **BAT1** 解析已用于事件批次；**gRPC `EventIngest`** 若在目标环境**未注册** **`ReportCommandResult`**，则终端 unary 会失败，stderr 见 **`[grpc] ReportCommandResult 失败`**（**`grpc_client_impl.cpp`**）。
- **联调无完整 ingest gRPC 时**：仍可用 **`EDR_SOAR_REPORT_ALWAYS=1`** 验证客户端是否发起 RPC；服务端侧需后续在 **EventIngest** 实现 **`ReportCommandResult`** 并落库/对账，或先用 **grpcurl** / 自建 mock 监听同端口。

---

## 6. 与事件上报的关系

- **`ReportEvents`**：仍用于 **行为/事件批次**（BAT1/BLZ4），与指令结果 **独立**。
- **`ReportCommandResult`**：仅承载 **指令执行结果**，便于 SOAR 在 playbook 中 **等待步骤完成** 或 **分支**。
