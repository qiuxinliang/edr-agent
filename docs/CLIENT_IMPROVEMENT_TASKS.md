# 客户端（edr-agent）改进任务单

> 依据：`Cauld Design/EDR_端点详细设计_v1.0.md`、`edr-agent/README.md` 实现快照、此前 Windows 满足度评审。  
> 维护：完成子任务后在本文件勾选，并在对应模块 `README.md` / 设计稿中同步一句「已关闭 AGT-xxx」。

## 总览

| ID | 标题 | 优先级 | 平台 |
|----|------|--------|------|
| [AGT-001](#agt-001-windows-etw-增补-1910-provider) | Windows ETW 增补 §19.10 Provider（**已完成**） | P1 | Windows |
| [x] [AGT-002](#agt-002-事件总线与背压) | 事件总线与背压（**`event_bus.h` + README 背压观测**） | P1 | 全平台 |
| [x] [AGT-003](#agt-003-线程模型与主循环) | 线程模型与主循环（**`docs/AGENT_THREAD_MODEL.md`**） | P2 | 全平台 |
| [x] [AGT-004](#agt-004-api--iat-监控层) | API / IAT 监控层（**正式 descope：`docs/AGT004_API_MONITOR_DESCope.md`**） | P3 | Windows |
| [x] [AGT-005](#agt-005-ave--onnx-联调路径) | AVE / ONNX 联调路径（**`docs/AVE_ONNX_LOCAL_STACK.md` + `scripts/onnx_local_stack_smoke.sh`**） | P1 | 全平台 |
| [x] [AGT-006](#agt-006-windows-安装与服务账户) | Windows 安装与服务账户（**`deploy/` + `docs/WINDOWS_DEPLOY.md`；MSI 见 edr-backend**） | P2 | Windows |
| [x] [AGT-007](#agt-007-心跳与在线语义) | 心跳与在线语义（**`SOAR_CONTRACT` §4.1 终端 + §4.2 平台契约**；**后端实现见 §4.2.3**） | P2 | 全平台 |
| [x] [AGT-008](#agt-008-soar--reportcommandresult) | SOAR / ReportCommandResult（**终端已调用；`SOAR_CONTRACT` §5 平台/mock 说明**） | P1 | 全平台 |
| [x] [AGT-009](#agt-009-取证上传-e2e) | 取证上传 E2E（**`docs/AGT009_FORENSIC_UPLOAD_E2E.md`**） | P1 | Windows 优先 |
| [x] [AGT-010](#agt-010-资源限制与预处理降载) | 资源限制与预处理降载（**`resource` + `preprocess` + README**） | P2 | 全平台 |
| [x] [AGT-011](#agt-011-文档与用语一致) | 文档与用语一致（**README 矩阵 + main 用语已对齐**） | P3 | 全平台 |
| [x] [AGT-012](#agt-012-linux-内核态采集-p7) | Linux 内核态采集（P7）（**`docs/AGT012_LINUX_EBPF_P7.md`**） | P3 | Linux |
| [x] [AGT-P2-SHELLCODE-SOAR](#agt-p2-shellcode-soar--取证根目录与-playbook) | **P2**：Shellcode PCAP 根与 **`EDR_FORENSIC_OUT`** 对齐 + **SOAR playbook** 示例（**`SOAR_CONTRACT` §5.3**；**`WINDOWS_SHELLCODE_FORENSIC_TODO` §P2**） | P2 | Windows |

---

### AGT-001 Windows ETW 增补 §19.10 Provider（已完成）

- **目标**：在设计要求的 ETW 集合上补齐 **Microsoft-Windows-TCPIP**、**Windows Firewall With Advanced Security**（或等价事件源），用于攻击面增量触发；与 `attack_surface_report` 的轮询路径并存或做去重。
- **交付物**：`etw_guids_win.h` + `collector_win.c` 启用逻辑；`[collection] etw_tcpip_provider` / `etw_firewall_provider`（默认 `true`）；`edr_collector_start(bus, cfg)` 传入完整配置；TDH 扩展；`EDR_EVENT_FIREWALL_RULE_CHANGE` + 预处理 MITRE；README 与 `agent.toml.example`。
- **延伸（已实现）**：`EdrEventSlot.attack_surface_hint` → 预处理 **`edr_attack_surface_etw_signal`** → 主线程 **`edr_attack_surface_take_etw_flush`** + **`[attack_surface] etw_refresh_debounce_s`** 去抖 → **`edr_attack_surface_execute("etw_tcpip_wf")`**。
- **验收**：在开启 ETW 的机器上，监听/连接/防火墙规则变更可产生带 `prov=tcpip` / `prov=wf` 的总线事件；无权限时可选 Provider 跳过、会话仍可建立。

---

### AGT-002 事件总线与背压

- **目标**：二选一并写清决策——(A) 实现与设计 §2.3 一致的 **无锁环形缓冲 + 水位背压**；(B) 保留互斥实现，在《端点详细设计》与 README 中**修订**为「当前实现为互斥环形队列」并补性能说明。
- **交付物**：代码或设计/README 补丁；若选 (A)，需单测或压测脚本说明。
- **验收**：高负载下 `bus_dropped`、高水位行为可解释；与设计文档无矛盾表述。
- **状态（已关闭 AGT-002，选项 B）**：**`include/edr/event_bus.h`** 标明设计目标为无锁环、**当前骨架为互斥保护环形队列**；API 含 **`edr_event_bus_dropped_total`**、**`edr_event_bus_high_water_hits`**（80% 水位）；**README**「实现状态快照」与退出 stderr 汇总含 **`bus_hw80`**、**`bus_dropped`**，与 **`event_bus_pressure_warn_pct`**（自保护）可观测背压。

---

### AGT-003 线程模型与主循环

- **目标**：对齐设计 §2.1 的意图：至少将 **上报（批次 flush）**、**Subscribe 消费**、**可选 watchdog** 与主循环职责分离说明；或输出《线程对照表》冻结当前「ETW 单线程 + 预处理单线程 + 主线程轮询」为 M2 架构并在设计侧标注阶段。
- **交付物**：`docs/` 或 README 架构小节 + 必要代码拆分（按评审取舍）。
- **验收**：新成员可从文档画出线程与锁边界；无隐藏死锁（gRPC 回调与总线 push 关系可查）。
- **状态（已关闭 AGT-003）**：独立文档 **`docs/AGENT_THREAD_MODEL.md`**（线程对照表、锁与并发、与设计 §2.1 差异说明）；**README** 文首与「实现状态快照」已链至该文档。

---

### AGT-004 API / IAT 监控层

- **目标**：对设计 §1.2「API 监控层（IAT Hook）」做 **实现 PoC** 或 **正式 descope**（在设计/README 标明「本期不做及原因」）。
- **交付物**：PoC 分支或文档决策记录。
- **验收**：路线图与 Cauld Design 交叉引用一致，无「图里有、实现无」的静默缺口。
- **状态（已关闭 AGT-004，正式 descope）**：**`docs/AGT004_API_MONITOR_DESCope.md`**（决策、原因、与设计 §1.2 关系、后续可选方向）；**README** 能力矩阵与「实现状态快照」已增加 §1.2 行并链至该文档。**无** PoC 代码分支。

---

### AGT-005 AVE / ONNX 联调路径

- **目标**：缩短「第一次能跑真推理」路径：`EDR_WITH_ONNXRUNTIME`、模型目录、`agent.toml.example` 与 `LOCAL_STACK_INTEGRATION` 对齐；CI 可选 job 或文档化的一键命令。
- **交付物**：README + 示例配置 +（可选）脚本。
- **验收**：按文档步骤可在本仓库联调栈上完成一次 `ave_infer` 或等效 RPC 验证。
- **状态（已关闭 AGT-005）**：**`docs/AVE_ONNX_LOCAL_STACK.md`**（CMake、`ONNXRUNTIME_ROOT`、`test_ave_infer` 与 **`EDR_AVE_INFER_DRY_RUN`**）；**`scripts/onnx_local_stack_smoke.sh`**；README CMake 表与 **`LOCAL_STACK_INTEGRATION`** 互链；**`test_ave_infer`** 仅在未设置 **`EDR_AVE_INFER_DRY_RUN`** 时默认 dry-run，便于真 ONNX 覆盖。

---

### AGT-006 Windows 安装与服务账户

- **目标**：向设计 §1.1 / §13 靠拢：安装器（或文档化 MSI/服务包装）、**LOCAL SERVICE**（或等价低权限）运行说明、ETW/WinDivert 所需权限预检与日志。
- **交付物**：`deploy/` 或独立 `installer/` 草案 + README「部署」章节。
- **验收**：干净 Windows VM 上按步骤安装后 Agent 可采集；失败原因可诊断。
- **状态（已关闭 AGT-006，以文档草案为准）**：**`deploy/README.md`** + **`docs/WINDOWS_DEPLOY.md`**（服务账户讨论、ETW/WinDivert **预检清单**、`sc.exe` 示例草案、与 **AGENT_INSTALLER** / **edr-backend** 分工）；**README**「构建」与「实现状态快照」已链至上述文档。**MSI/WiX** 与 **管理端限时 zip** 属 **edr-backend** 发版范围；上表「验收」建议在目标环境由运维/QA **抽检**，不作为本仓库关闭门槛。

---

### AGT-007 心跳与在线语义

- **目标**：明确 **30s 心跳** 是独立 RPC、仅 gRPC keepalive，还是复用 `ReportEvents` 空批；与平台「终端在线」定义对齐并写进 `SOAR_CONTRACT.md` / README。
- **交付物**：协议或行为说明 + 必要代码。
- **验收**：后端可据此实现一致的在线判定；断网重连行为可测。
- **状态（已关闭 AGT-007）**  
  - **终端**：**无**独立心跳 RPC、**无**空 `ReportEvents` 心跳；**gRPC keepalive**（默认 **30s**）见 **`src/transport/grpc_client_impl.cpp`**、README **`[server].keepalive_interval_s`**；**`Subscribe`** 重连退避见 README。  
  - **契约**：**`docs/SOAR_CONTRACT.md` §4.1**（终端行为）；**§4.2**（平台「在线」**推荐语义**、**`T_offline`**、**`ReportEvents`/连接** 与 **Subscribe** 关系、**§4.2.3 后端待实现表**）。  
  - **edr-backend**：**`§4.2.3` 表结构与代码** 在 **edr-backend** 迭代；**非** 本仓库关闭条件。

---

### AGT-008 SOAR / ReportCommandResult

- **目标**：指令执行结果与 `ingest.proto` 中 **ReportCommandResult** 全链路打通（含失败重试、与 `EDR_SOAR_REPORT_ALWAYS` 行为一致）；与 `docs/SOAR_CONTRACT.md` 同步。
- **交付物**：客户端实现 + 联调说明；缺失服务端时标注 mock 方式。
- **验收**：Subscribe 下发一条带 `soar_correlation_id` 的指令后，服务端可收到结果事件（或与本地 mock 对齐）。
- **状态（客户端侧已关闭 AGT-008）**：**`edr_grpc_client_report_command_result`** 已在 **`command_stub.c`** 路径接通；**`docs/SOAR_CONTRACT.md` §5** 区分 **终端 / 平台**：stub 与 **`EDR_SOAR_REPORT_ALWAYS`** 联调方式；**平台 gRPC `ReportCommandResult` 注册** 仍为后续后端任务（HTTP ingest 已存在）。

---

### AGT-009 取证上传 E2E

- **目标**：Webshell / Shellcode 命中后 **UploadFile** 分片上传与本地降级路径，对 Windows 做端到端验证；与 `WINDOWS_SHELLCODE_FORENSIC_TODO.md` 合并或关闭子项。
- **交付物**：测试步骤或自动化脚本；服务端对象存储配置说明。
- **验收**：平台侧可拿到对象键与元数据；失败有可观测日志。
- **状态（已关闭 AGT-009）**：**`docs/AGT009_FORENSIC_UPLOAD_E2E.md`**（Webshell / **`forensic`** **UploadFile**、**`EDR_FORENSIC_UPLOAD`**）；**`WINDOWS_SHELLCODE_FORENSIC_TODO.md`** 已互链。

---

### AGT-010 资源限制与预处理降载

- **目标**：落实 README 已承认缺口：在 `resource` 超限时 **预处理侧主动降载**（跳过低优先级、合并批次等），并向设计 §12 的指标靠拢（至少文档化当前可达与差距）。
- **交付物**：`resource.c` / `preprocess` 协同逻辑 + README。
- **验收**：压测场景下 CPU/队列可控，无静默 OOM。
- **状态（已关闭 AGT-010）**：**`edr_resource_preprocess_throttle_active()`**（`include/edr/resource.h`、`src/resource/resource.c`）：**POSIX** 在 CPU/RSS 超限时置位，恢复后清除；**`EDR_PREPROCESS_THROTTLE=1`** 强制降载（**Windows** 无 rusage 采样时联调）；**`preprocess_pipeline.c`** 在降载时 **跳过 `priority!=0` 且非 `attack_surface_hint`** 的槽位。**README**「实现状态快照」**P3 §12** 已更新。**合并批次** 仍为后续优化。

---

### AGT-011 文档与用语一致

- **目标**：统一 `main.c`「骨架」与 README「已接通初版」表述；在仓库根 `docs/ENGINEERING_PRINCIPLES.md` 原则下，保证 Windows/Linux 能力矩阵表与代码分支（`collector_win` / `collector_linux` / stub）一致。
- **交付物**：小范围文案与目录表更新。
- **验收**：新读者不会因矛盾用语误判交付边界。
- **状态（已关闭 AGT-011）**：`main.c --help` 改为「初版已接通」并指向 README「实现状态快照」；**README** 增加 **工程原则链接 + Windows/Linux 能力矩阵**；与 **`CLIENT_IMPROVEMENT_TASKS` 总览**交叉引用。

---

### AGT-012 Linux 内核态采集（P7）

- **目标**：按设计 §3.2：eBPF CO-RE（进程/网络等）或明确降级策略；与当前 inotify-only M1 区分版本里程碑。
- **交付物**：技术选型笔记 + 分阶段 PR 计划。
- **验收**：Linux 上关键遥测字段与 Windows ETW 路径可对齐映射表。
- **状态（已关闭 AGT-012，以路线图为准）**：**`docs/AGT012_LINUX_EBPF_P7.md`**（选型、**P7.0**–**P7.3** 分期、与 ETW 的**初稿映射表**）；**内核探针代码** 按 P7.x 在后续 PR 落地，**不**作为本任务单代码交付。

---

## 建议排期（仅供参考）

1. **短迭代（1～2 周）**：~~AGT-011 → AGT-005 → AGT-008~~ **（三项已在 edr-agent 文档/脚本侧落地；平台 gRPC `ReportCommandResult` 见 SOAR_CONTRACT §5.2）**  
2. **Windows 加固**：~~AGT-001~~ → ~~AGT-009~~ **（已关闭，见上节）**；~~AGT-006~~ **（已关闭，见上节）**  
3. **架构债**：~~AGT-002~~ **（已关闭，见上节）** / ~~AGT-003~~ **（已关闭：`AGENT_THREAD_MODEL.md`）**  
4. **中长期**：~~AGT-004~~ **（descope 已关闭）**、~~AGT-010~~ **（已关闭）**、~~AGT-012~~ **（路线图已关闭）**；~~AGT-007~~ **（已关闭：`SOAR_CONTRACT` §4.1/§4.2；后端实现见 §4.2.3）**  

在 issue 跟踪系统中可将标题复制为：`[AGT-001] Windows ETW 增补 §19.10 Provider`，便于与本文件交叉引用。

---

## 进度快照与联调准备（edr-agent ↔ 平台）

### 总览进度（截至本文件维护）

| 状态 | ID |
|------|-----|
| **已关闭 / 文档或代码已交付** | **AGT-002～012**（总览 **`[x]`**）；**AGT-001** 节内 **已完成** |
| **后续代码（非 AGT 未关项）** | **Linux eBPF 探针** 按 **`docs/AGT012_LINUX_EBPF_P7.md`** 分阶段 PR |

### P0（平台侧仓库门闸 — 已由脚本/CI 承担）

下列项在 **`edr-backend`** 由 **`make verify-p0-repo-gate`**（**`scripts/verify_p0_repo_gate.sh`**）与 **GitHub Actions「Backend CI」** 中 **`P0 release gate`** 步骤自动执行，**不必**在下表重复勾选：

- **`platform/internal/installer/embedded/`** 与 **`edr-agent/scripts/edr_agent_install.{py,ps1,sh}`** 一致且已提交  
- **`go test ./platform/internal/installer`**、**`go build`** **`edr-api`** / **`edr-worker`**

仍须在 **staging / 生产** 环境完成的 P0（TLS、CORS、**`wss`**、**`POST /enroll` 走公网 HTTPS**、**勿长期 `PLATFORM_SKIP_LICENSE_GATE`**）见 **`edr-backend/docs/RELEASE_PUBLISH_CHECKLIST.md` §2、§4**；网关 **`/healthz`/`/ready`** 可用 **`STAGING_HOST=https://… bash edr-backend/scripts/staging_gateway_health.sh`**；与 Agent 上行冒烟可用 **`API_ROOT=… bash edr-backend/scripts/smoke_i1_demo_ready.sh`**（需已起 **edr-api** + DB）。

### 联调前检查清单（建议）

**环境与身份**

- [ ] 平台栈可按 **`edr-backend/docs/LOCAL_STACK_INTEGRATION.md`**（或你们环境等价物）拉起；Agent **`[server].address`** 与 enroll 返回的 gRPC 地址一致。
- [ ] **`agent.toml`**：已通过 **`docs/AGENT_INSTALLER.md`** 脚本或手工 enroll；**mTLS** 字段与运维约定一致。

**上行（事件 / 指令结果）**

- [ ] **`ReportEvents`**（BAT1/批次）可达且后端可解析（HTTP 或 gRPC 以当前栈为准）。
- [ ] **注册表（Windows）**：**`EDR_BEHAVIOR_ENCODING=protobuf`** 时 **`BehaviorEvent.detail.registry`** 与平台 **`category=registry`** 一致；实机步骤见 **`docs/REGISTRY_ETW_ACCEPTANCE.md`**。
- [ ] **SOAR / `ReportCommandResult`**：终端已调用（**AGT-008**）；确认后端 **EventIngest** 是否已注册 **`ReportCommandResult`**，否则 unary 失败属预期，见 **`docs/SOAR_CONTRACT.md` §5**；联调可设 **`EDR_SOAR_REPORT_ALWAYS=1`**。
- [ ] **心跳 / 在线**：终端侧 **gRPC keepalive**（**`SOAR_CONTRACT` §4.1**）；平台默认 **滑动时间窗 + `T_offline`** 与 **连接 / `ReportEvents` 成功** 见 **§4.2**；**后端实现** 见 **§4.2.3**。

**下行（指令）**

- [ ] **`Subscribe`** 流建立；带 **`soar_correlation_id` / `playbook_run_id`** 的指令与 **`ReportCommandResult`** 对账方式与平台一致。

**可选 / 分项联调**

- [ ] **AVE / ONNX**：**`docs/AVE_ONNX_LOCAL_STACK.md`**、**`EDR_AVE_INFER_DRY_RUN`**。
- [x] **取证 / UploadFile**：步骤见 **`docs/AGT009_FORENSIC_UPLOAD_E2E.md`**；**`forensic`** 完成后 **`UploadFile`**（**`EDR_FORENSIC_UPLOAD`**，**`command_stub.c`**）。
- [x] **P2 Shellcode / SOAR**：**`SOAR_CONTRACT` §5.3**；**WinDivert PCAP** 根路径（**`windivert_capture.c`** + **`EDR_FORENSIC_OUT\\shellcode`** 回退）。
- [ ] **Windows 部署**：**`docs/WINDOWS_DEPLOY.md`** 预检；Shellcode/WinDivert 需驱动与权限。

### AGT-P2-Shellcode-SOAR — 取证根目录与 Playbook

- **目标**：**§17 WinDivert** PCAP 与远程取证根 **`EDR_FORENSIC_OUT`** 语义一致；为编排提供可复制的 **Shellcode → `forensic` → 确认 → `isolate`** 步骤说明。
- **交付物**：**`windivert_capture.c`** 根路径解析；**`docs/SOAR_CONTRACT.md` §5.3**；**`WINDOWS_SHELLCODE_FORENSIC_TODO.md`** §P2 勾选更新；**`README.md`** / **`agent.toml.example`** / **`config.h`** 注释。
- **仍属 P2 / 后端或控制台**：告警详情展示 **PCAP / MinIO key**（**`WINDOWS_SHELLCODE_FORENSIC_TODO`** 未关项）。

### P2 后续三项（控制台 · WinDivert 性能 · README §9 自保护）

**主文档（含 `[ ]` / `[x]` 子任务表）**：**`docs/WINDOWS_SHELLCODE_FORENSIC_TODO.md`** — **§P2a**（**C1–C4** 已关：**ingest UploadFile**、**GET /alerts/:id** 的 **artifacts** 合并、**AlertDetailPage** 展示、**`AGT009` §2.1** / **`WINDOWS_DEPLOY`**）、**§P2b**（**P2-PERF-1** SLO 框架见 **`docs/SHELLCODE_AGENT_SLO.md`**；**P2-PERF-2**、**P2-PERF-3** 已落地；**P2-PERF-3** 权威语义见 **`docs/EVENT_BUS_BACKPRESSURE.md`**）、**§P2c**（**S1** **`--service`** 已落地，见 **`WINDOWS_SERVICE_SHUTDOWN.md`**；**S2–S4** 已文档：**`SELF_PROTECT_REGRESSION.md`**、**`PROMETHEUS_BUS_METRICS.md`**、**`WINDOWS_DEPLOY.md` §3.0**）。

| 代号 | 内容 | 责任域 |
|------|------|--------|
| **C1** | **`UploadFile`** 流式落 MinIO/S3 | **edr-backend** ingest（**已交付**） |
| **C2** | **`GET /alerts/:id`** **`artifacts`** 合并 **`ReportCommandResult`** **`UploadFile key=`** | **edr-backend**（**已交付**） |
| **C3** | **`AlertDetailPage`** 取证/对象存储卡片 + **`AlertEvidenceSection`** 表列 | **edr-frontend**（**已交付**） |
| **C4** | **gRPC 目标 + MinIO 配置**（**`AGT009` §2.1**、**`WINDOWS_DEPLOY`**） | **文档（已交付）** |
| **P2-PERF-1** | SLO **框架** **`SHELLCODE_AGENT_SLO.md`**（指标 **TBD**、业务签署仍待） | 产品 + 运维 |
| **P2-PERF-2** | WinDivert **计数器** + **`EDR_SHELLCODE_WD_STATS`** | **edr-agent**（**`windivert_capture.c`**） |
| **P2-PERF-3** | 背压语义**已文档化**（**`EVENT_BUS_BACKPRESSURE.md`**）；**可选开关**（降采样 / 按 priority 丢）仍排期 | 文档（已实现）+ 后续产品 |
| **P2-PERF-4** | 生产压测报告 | 运维 + 专机 |
| **S1–S4** | **S1** **`--service`** 已落地；**S2–S4** 见 **`WINDOWS_SHELLCODE_FORENSIC_TODO.md` §P2c** 专文 | Agent + 运维 + 可观测栈 |

---

**结论**：**P1 级联调（注册、gRPC、批次上报、Subscribe、指令闭环）** 已具备 **AGT** 文档与客户端实现；**与控制台「在线」一致** 依 **`SOAR_CONTRACT` §4.2** 与 **edr-backend §4.2.3** 落地；**全链路 SOAR** 依赖后端 **`ReportCommandResult`** 注册或 mock。
