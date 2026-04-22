# Windows Shellcode / 取证 — 按模块 TODO（优先）

本文档相对 `edr-agent` 当前实现整理后续工作，**优先级：Windows §17 Shellcode 与远程取证链路**，其次为与 SOAR/平台的衔接。实现状态基线见仓库根目录 `README.md` §17 与 `command_stub.c` 中 `forensic`。

**未完成项一页摘要**（与本文同步维护意图）：**`docs/REMAINING.md`**。**Shellcode 检测评估语料（合成 baselines + 变形方法论）**：**`docs/SHELLCODE_EVALUATION_CORPUS.md`**。

**Webshell `UploadFile` 联调步骤**见 **`docs/AGT009_FORENSIC_UPLOAD_E2E.md`**（**AGT-009**）。

---

## P0 — Shellcode 检测与证据留存（Windows）

### `src/shellcode_detector/windivert_capture.c`

- [x] **IPv6**：已支持 `ipv6` 头分支 + `InetNtopA`；`WSAStartup` 配对清理。
- [x] **PCAP（初版）**：`forensic_save_pcap` + 非空 `forensic_dir` 时，无环形则 **单包** raw IP（228/229）；**`forensic_ring_slots`>0** 时维护环形缓冲，告警写 **`shellcode_ring_*.pcap`（多帧，DLT=EN10MB 以太封装）**。
- [x] **环形增强（部分）**：告警 ETW1 增加 **`ring_trigger_slot`**、**`ring_oldest_ns` / `ring_newest_ns` / `ring_span_ns`**（触发帧槽位与缓冲内时间跨度）；**`shellcode_json=`** 单行结构化字段（**`score` / `dpt` / `spt` / `proto` / `det` / `det_layer` / `rule_confidence` / `rule`**）。**pcapng**、按时间窗 UI 高亮仍属后续。
- [x] **与 PMFE（T-SC-042）**：高危 shellcode 命中后 **`EDR_PMFE_ETW_AUTO`** 路径见 **`docs/SOAR_CONTRACT.md`** **§1**（**`hint_pid`** / 端口反查 **`GetExtendedTcpTable`**、**`EDR_PMFE_ETW_SHELLCODE_SCORE`** / **`EDR_PMFE_ETW_COOLDOWN_MS`**）；预处理消费 **`detector=known_exploit`** 与扩展 **`shellcode_json`** 无回归。
- [x] **载荷摘要**：告警 ETW1 增加 **SHA256(证据区)**；可选 **preview_hex**（`evidence_preview_bytes`，默认 0 关闭）。
- [x] **驱动/DLL 健康**：`OpenSCManager` / `OpenService` 查询 `WinDivert` / `WinDivert1.4` 状态一行日志。

### `src/shellcode_detector/proto_parse.c` / `shellcode_heuristic.c` / `shellcode_known.c`

- [x] **WinDivert 端口配置化**：`[shellcode_detector].windivert_tcp_ports` 逗号列表；空 = 内置 `kWdFilter`；非空 = 自定义过滤器 + `monitor_allows` 仅按列表匹配。
- [x] **协议覆盖扩展（部分）**：**明文 HTTP/1.x** 任意端口：识别请求/状态行 + 头部后的 body 区再扫描（`EDR_PROTO_KIND_HTTP`）。**HTTPS/TLS** 仍为密文，仅整体启发式（依赖样本与端口列表）。
- [x] **误报调优（部分）**：TOML **`heuristic_score_scale`**（默认 1.0）缩放启发式分数；**`yara_rules_reload_interval_s`**（秒，0=关闭）周期性重编译规则目录。现网权重与 YARA 规则内容仍依赖运营迭代。

### `src/preprocess/behavior_from_slot.c`（及与总线联动）

- [x] **高优告警 → 自动处置（可选端上）**：分数 ≥ **`auto_isolate_threshold`** 时仍为 **`priority=0`**；若 **`EDR_SHELLCODE_AUTO_ISOLATE=1`** 或 TOML **`auto_isolate_execute`**，且 **`EDR_CMD_ENABLED`/`allow_dangerous`**，则执行与 **`isolate`** 相同的标记 + **`EDR_ISOLATE_HOOK`**（**每进程最多一次**）。服务端 playbook / 人工确认仍推荐并行使用。
- [x] **告警字段（部分）**：ETW1 增补 `mitre=T1210`、`forensic_kind`、`pcap_stem`、`forensic_frames`（环形）；`behavior_from_slot` 将上述与 detector/rule/score 一并写入 `script_snippet` 摘要；`apply_mitre_hints` 仍写入 **T1210**。

---

## P1 — 远程取证指令与打包（Windows 为主，POSIX 对齐）

### `src/command/command_stub.c` — `do_forensic` / `forensic_copy_lines`

- [x] **`forensic_copy_lines` 去 `system(copy)`**：Windows **`CopyFileA`**、POSIX **`open`/`read`/`write`** 逐文件复制（`EDR_FORENSIC_COPY_PATHS=1`）。
- [x] **打包去 `system(tar …)`**：**Windows** **`CreateProcessW`** 调 **`System32\\tar.exe`**；**POSIX** **`fork`/`execvp("tar")`**。
- [x] **清单增强**：`manifest.txt` 已写 **hostname**、**endpoint_id** / **tenant_id**、**`payload_sha256`**；**Windows** 增补 **`windows_username`**（**`GetUserNameA`**）、**`boot_volume_serial_number`**（系统盘 **卷序列号**）；**POSIX** 可选 **`posix_user`**（**`USER`**）。**不再**把原始 payload 二进制写入 manifest。
- [x] **结构化 payload**：**`paths`[]** 同上行模式（**`EDR_FORENSIC_COPY_PATHS=1`**）；**Windows** 下 **`registry_keys`[]**（**`EDR_FORENSIC_REGISTRY_DUMP=1`**）→ **`registry_*.txt`**，**`memory_regions`[]**（**`EDR_FORENSIC_MEMORY_DUMP=1`**）→ **`mem_*.bin`**；**POSIX** 对后二者写 **`unsupported_platform`**。权威说明 **`docs/FORENSIC_STRUCTURED_PAYLOAD.md`**。
- [x] **上传**：**`do_forensic`** 在 **`bundle.tgz`** 非空且 **`edr_grpc_client_ready()`** 时调用 **`edr_grpc_client_upload_file`**（**`alert_id`** = **`forensic-<command_id>`**）；**`EDR_FORENSIC_UPLOAD=0`** 关闭；失败保留本地包。

### `include/edr/config.h` / `src/config/config.c` — `[shellcode_detector].forensic_dir`

- [x] **Shellcode 命中落盘（根路径）**：**WinDivert PCAP** 根路径为 **`forensic_dir`** 非空则用之；否则 **`EDR_FORENSIC_OUT\\shellcode`**；再否则 **`%TEMP%\\edr_forensic\\shellcode`**（**`windivert_capture.c`**）。**Webshell** 仍使用 **`forensic_dir`** 或各自回退路径（与 **`webshell_forensic.c`** 一致）。

---

## P2 — 平台、SOAR 与运维

- [x] **Playbook 模板**：Shellcode 高优 → **`forensic`** → **人工确认** → **`isolate`**；见 **`docs/SOAR_CONTRACT.md` §5.3**。

### P2a — 控制台 / 平台 / 对象存储（告警详情）

**依赖**：Agent **`UploadFile`** 须连到 **`edr-api` gRPC EventIngest**（**`INGEST_GRPC_ADDR`** 已启用），且平台配置 **S3/MinIO**（**`INGEST_ARTIFACT_MINIO_*`** 或回退 **`INSTALLER_MINIO_*`**）；见 **`edr-backend/docs/GRPC_INGEST.md`**。未配置对象存储时 **`UploadFile`** 仍返回 **gRPC OK**，**`UploadResult.success=false`**（**`error`** 字段说明原因），控制台仍依赖 **C2** 才能把 **key** 挂到告警 JSON。

| 子任务 | 说明 | 验收 |
|--------|------|------|
| [x] **C1 ingest** | **`internal/ingestgrpc/upload_file.go`**：**`UploadFile`** 流式合并 → **SigV4 PUT** → **`UploadResult{ success, minio_key }`** | 流结束 **`success` + `minio_key`**；桶内 **`agent-artifacts/...`** 可验证 |
| [x] **C2 告警 API** | **`GET /api/v1/alerts/:id`**：**`artifacts`** 合并 **`endpoint_command_results`** 中 **`UploadFile key=`**（与 **`forensic-` / `command_id`** 路径匹配） | JSON **`artifacts[].minio_key`**、**`command_id`**、**`source=report_command_result`** |
| [x] **C3 前端** | **`AlertDetailPage`**：**「取证 / 对象存储（指令回传）」**卡片 + **`artifacts`** 表列；**Webshell** 块展示 **`minio_key`** 与复制 | 与 C2 字段一致 |
| [x] **C4 文档** | **`AGT009` §2.1** + **`WINDOWS_DEPLOY`** 预检：**`[server].address`** 指向 **`INGEST_GRPC_ADDR`** 与 **MinIO 已配置** 的 ingest | 新同学不误连 |

### P2b — WinDivert 性能 / 背压 / 压测（终端 + 运维）

**P2-PERF-1（产品）**：SLO 指标框架见 **`docs/SHELLCODE_AGENT_SLO.md`**（总线、WinDivert、预处理、上传、资源；**数值 TBD**，由产品与运维填写并签署）。

**P2-PERF-3（背压语义）**：权威说明见 **`docs/EVENT_BUS_BACKPRESSURE.md`**（环形满则 **`try_push` 返回 false**、**`dropped` 累计**、各 producer 日志差异、退出 **`bus_dropped`/`bus_hw80`** 与 **`self_protect`** 阈值告警）。

| 子任务 | 说明 | 验收 |
|--------|------|------|
| [x] **P2-PERF-1 SLO** | 与业务方可填数值的一页框架（总线、WinDivert、全链延迟、资源） | **`docs/SHELLCODE_AGENT_SLO.md`** |
| [x] **P2-PERF-2 计数器** | **`windivert_capture.c`**：`recv` 包、**`recv` 错误**、**解析/非 TCP 跳过**、**`monitor_*` 过滤**、**告警入总线成功/失败**；**`EDR_SHELLCODE_WD_STATS=1`** 时 **`edr_windivert_capture_stop`** 打一行 **`[shellcode_detector] wd_stats …`** | stderr 可见单调计数；关机或模块停止时可观测 |
| [x] **P2-PERF-3 背压策略** | 文档化：**`edr_event_bus_try_push` 失败**时当前为**丢事件**（无阻塞重试）；可选开关（降采样 / 仅丢 `priority!=0`）属后续 | **`EVENT_BUS_BACKPRESSURE.md`** 与代码一致 |
| [x] **P2-PERF-4 压测** | 专机 **合成流量**（须合规）：扫 **`max_payload_inspect`**、**`forensic_ring_slots`**、**`WINDIVERT_PARAM_QUEUE_*`** | 主报告 **`docs/P2_PERF4_SYNTHETIC_TRAFFIC_REPORT.md`** 已填 §0–§5 框架与 §4 **格式示例**；**客户级专机**请另存 **`P2_PERF4_RUN_*`** 并替换 §4 为真实 stderr 粘贴 |

### P2c — README「P2 §9」自保护深化（与 §17 并行）

**现状**：**`main.c`** 已 **`SetConsoleCtrlHandler`**；**`self_protect.c`** 已有 **SIGTERM/SIGINT（POSIX）**、**pidfile**、**watchdog**、**`anti_debug`**、**总线背压告警**、**Job Object** 等。

| 子任务 | 说明 | 验收 |
|--------|------|------|
| [x] **S1 Windows 服务** | **`--service [<名>]`** + **`StartServiceCtrlDispatcher` / `RegisterServiceCtrlHandler`**：**`SERVICE_CONTROL_STOP`** → **`edr_agent_shutdown`**；见 **`docs/WINDOWS_SERVICE_SHUTDOWN.md`**、**`src/platform/edr_windows_service.c`** | **`sc create`/`sc start`/`sc stop`** 与 **`binPath`** 中 **`--service`** 名称一致 |
| [x] **S2 回归** | **`docs/SELF_PROTECT_REGRESSION.md`**：**Job Object** / **anti_debug** 手动清单（默认关） | 发版前专机勾选 |
| [x] **S3 可观测** | **`docs/PROMETHEUS_BUS_METRICS.md`**：stderr / 边车 / 未来内置 **metrics** 路径 | 与 **`EVENT_BUS_BACKPRESSURE.md`** 一致 |
| [x] **S4 文档** | **`WINDOWS_DEPLOY.md` §3.0** 排障顺序 + 顶部链至 S1–S3 专文 | 运维可独立闭环 |

---

## 非目标（本清单不展开）

- Linux 侧 §17（无 WinDivert）；见路线图 **P7 eBPF** 与 `README.md`。
- 纯内核无载荷攻击（需驱动/ETW 其它通道）。

---

## 参考路径

| 模块 | 路径 |
|------|------|
| WinDivert 捕获 | `src/shellcode_detector/windivert_capture.c` |
| 协议/启发式/YARA | `proto_parse.c`, `shellcode_heuristic.c`, `shellcode_known.c` |
| 远程取证指令 | `src/command/command_stub.c` (`do_forensic`) |
| Webshell 取证上传 | `src/webshell_detector/webshell_forensic.c`, `grpc_client` |
| 配置 | `agent.toml.example` `[shellcode_detector]` |
| 事件总线背压 / 丢弃 | **`docs/EVENT_BUS_BACKPRESSURE.md`**，`src/core/event_bus.c` |
| **`UploadFile` ingest（C1）** | **`edr-backend/platform/internal/ingestgrpc/upload_file.go`** |
| **告警详情合并上传（C2）** | **`edr-backend/platform/internal/handler/alert_upload_merge.go`**、`alerts.go` **GetOne** |
| **`forensic` JSON payload（P1）** | **`docs/FORENSIC_STRUCTURED_PAYLOAD.md`**，`command_stub.c` |
| **P2-PERF-4 压测报告** | **`docs/P2_PERF4_SYNTHETIC_TRAFFIC_REPORT.md`** |
| **服务 / 自保护 / 总线观测（P2c）** | **`WINDOWS_SERVICE_SHUTDOWN.md`**、**`SELF_PROTECT_REGRESSION.md`**、**`PROMETHEUS_BUS_METRICS.md`** |
| 产品 SLO 框架（WinDivert / 总线） | **`docs/SHELLCODE_AGENT_SLO.md`** |
