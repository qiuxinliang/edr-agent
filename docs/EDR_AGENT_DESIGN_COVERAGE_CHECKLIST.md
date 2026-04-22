# 端点客户端 — 设计覆盖核对表（相对《EDR_端点详细设计_v1.0》）

**用途**：评审或发版前按章节打勾；**状态**列含义：**Y**=已落地、**P**=部分/初版、**N**=未做、**—**=本仓库不实现或已由 descope 覆盖、**X**=主要落在 **edr-backend / edr-frontend** 或其它仓库。

**权威设计**：仓库根目录 **`Cauld Design/EDR_端点详细设计_v1.0.md`**。  
**能力矩阵（短）**：**`edr-agent/README.md`** 文首表 + **「实现状态快照」**。

---

## 图例

| 符号 | 含义 |
|------|------|
| **Y** | 行为与文档在 `edr-agent` 可对齐验收 |
| **P** | 有实现但与设计全文仍有差距（见「证据/备注」） |
| **N** | 当前分支无对应实现 |
| **—** | Descope、或设计项不适用于本阶段 |
| **X** | 控制台 / ingest / 平台 API 等，**非** `edr-agent` 独占交付 |

---

## 1 端点架构总览

| 小节 | 说明 | Win | Linux | 证据 / 备注 |
|------|------|-----|-------|-------------|
| §1.1 设计原则 | 模块化、可观测等 | Y | Y | `README.md`、目录与 DDD 对应表 |
| §1.2 组件关系（含 API/IAT） | 用户态 Hook 层 | — | — | **`docs/AGT004_API_MONITOR_DESCope.md`**（本期不做） |
| §1.3 支持平台矩阵 | 声明式矩阵 | P | P | **Win** 主路径完整；**Linux** 采集弱于 §3.2 全文（见 §3） |

---

## 2 进程模型与线程设计

| 小节 | 说明 | Win | Linux | 证据 / 备注 |
|------|------|-----|-------|-------------|
| §2.1 进程结构 | 主循环与模块边界 | Y | Y | `src/main.c`、`src/agent_main.c` |
| §2.2 线程优先级 | 调度意图 | P | P | **`docs/AGENT_THREAD_MODEL.md`**（M2 冻结说明） |
| §2.3 事件总线 | Lock-free ring 目标 | P | P | **`include/edr/event_bus.h`**：当前为**互斥环形队列**；背压计数 **AGT-002** |

---

## 3 ETW / 采集层

| 小节 | 说明 | Win | Linux | 证据 / 备注 |
|------|------|-----|-------|-------------|
| §3.1 Windows ETW | Kernel + 扩展 Provider + TDH | Y | — | `src/collector/collector_win.c`、`etw_tdh_win.c`、`etw_guids_win.h`；**§19.10** 见 README「ETW 增强」 |
| §3.2 Linux eBPF | CO-RE 等 | N | P | **实现**：**M1** `collector_linux.c`（inotify）；**路线图**：**`docs/AGT012_LINUX_EBPF_P7.md`** |
| §3.3 轮询快照 | 与设计「轮询层」对齐 | P | P | 攻击面/部分策略依赖周期任务；非独立「§3.3 模块」命名 |

---

## 4 本地预处理引擎

| 小节 | 说明 | Win | Linux | 证据 / 备注 |
|------|------|-----|-------|-------------|
| §4.1 流水线 | ETW1 → `EdrBehaviorRecord` | Y | Y | `src/preprocess/preprocess_pipeline.c`、`behavior_from_slot.c` |
| §4.2 白名单 | 子串/规则 | Y | Y | **`docs/PREPROCESS_RULES.md`**、`[[preprocessing.rules]]` |
| §4.3 去重窗口 | 时间窗去重 | Y | Y | `src/preprocess/dedup.c`、TOML |
| §4.15 Linux 开发任务 | 与 §3.2 联动 | P | P | 同 §3.2 |

---

## 5 AV Engine（AVE）

| 小节 | 说明 | Win | Linux | 证据 / 备注 |
|------|------|-----|-------|-------------|
| §5.1～5.3 | 加载、触发、结果 | Y | P | `src/ave/`、`AVE_ScanFile` L1–L4 路径；**Linux** 证书链等弱于 Windows |
| §5.4 模型热更新 | 运行时换模 | P | P | 模型目录扫描 + 配置；细粒度「热替换」见 **`docs/AVE_ENGINE_IMPLEMENTATION_PLAN.md`** |
| §5.5 与 §21 PMFE | 进程上下文 | Y | P | `src/pmfe/`、`pmfe_etw_preprocess.c`；**SOAR** **`docs/SOAR_CONTRACT.md`** §1 |
| §5.6 FL trainer ABI | 联邦学习边界 | P | P | **`EDR_WITH_FL_TRAINER`**、stub/可选栈；非默认启用 |

---

## 6～7 序列化、批次与 gRPC

| 小节 | 说明 | Win | Linux | 证据 / 备注 |
|------|------|-----|-------|-------------|
| §6.1 BehaviorEvent | protobuf / 字段 | Y | Y | `proto/edr/v1/event.proto`、`behavior_proto.c`、**RegistryDetail** |
| §6.2 批量 BAT1/BLZ4 | 批次头与上限 | Y | Y | `src/transport/event_batch.c`、`[upload]` |
| §7.1～7.3 | 连接、上报、Subscribe | Y | Y | `grpc_client_impl.cpp`；**`EDR_WITH_GRPC=OFF`** → `grpc_client_stub.c` |
| §7 平台侧在线/ingest | 持久化与 UI | X | X | **`docs/SOAR_CONTRACT.md`** §4.2.3（**edr-backend**） |

---

## 8 响应指令执行器

| 小节 | 说明 | Win | Linux | 证据 / 备注 |
|------|------|-----|-------|-------------|
| §8.1 指令类型 | ping/kill/isolate/forensic/pmfe/ave/… | Y | Y | `src/command/command_stub.c` |
| §8.2 审计 | 高危审计路径 | Y | Y | **`EDR_CMD_AUDIT_PATH`**、`SOAR_CONTRACT` |

---

## 9 自保护

| 小节 | 说明 | Win | Linux | 证据 / 备注 |
|------|------|-----|-------|-------------|
| §9.1～9.4 | 防终止/服务/看门狗/反调试 | P | P | `src/self_protect/`；**Windows** Job、**`--service`** 见 **`docs/WINDOWS_SERVICE_SHUTDOWN.md`** |
| §9 与 §14.3 | 进程内 Prometheus `/metrics` | N | N | **`README.md` 实现状态快照**、**`docs/REMAINING.md`** 仍排期 |

---

## 10～12 队列、配置、资源

| 小节 | 说明 | Win | Linux | 证据 / 备注 |
|------|------|-----|-------|-------------|
| §10 SQLite 队列 | 离线/补传 | Y | Y | `src/storage/queue_sqlite.c`（受 **`EDR_HAVE_SQLITE`**） |
| §11 配置 | TOML + 热更子集 | Y | Y | `src/config/config.c`、**`EDR_CONFIG_RELOAD_S`**、**`EDR_REMOTE_CONFIG_*`** |
| §12 资源限制 | CPU/RSS/预处理降载 | P | P | `src/resource/`；**带宽 §12.3** 为 **P** 或未完全对齐设计全文 |

---

## 13～15 安装、可观测性、测试

| 小节 | 说明 | Win | Linux | 证据 / 备注 |
|------|------|-----|-------|-------------|
| §13 安装部署 | 脚本、服务、预检 | P | P | **`docs/WINDOWS_DEPLOY.md`**、**`deploy/README.md`**、**`scripts/edr_agent_install.*`**；**MSI** 在 **edr-backend** |
| §14 错误与可观测 | 日志、指标 | P | P | stderr 结构化片段；**§14.3** 同 §9 `/metrics` 缺口 |
| §15 测试 | 单测/集成/压测 | P | P | **`ctest`**、**`.github/workflows/edr-agent-ci.yml`**；**P2-PERF-4** 专机模板 **`docs/P2_PERF4_SYNTHETIC_TRAFFIC_REPORT.md`** |

---

## 16 附录数据结构

| 小节 | 说明 | Win | Linux | 证据 / 备注 |
|------|------|-----|-------|-------------|
| §16.1 EventType | 枚举扩展 | P | P | `include/edr/types.h` 等与 proto 迭代对齐 |
| §16.2 TTP 映射 | 预处理初标 | Y | Y | `emit_rules.c`、`apply_mitre_hints` 等 |
| §16.3 与 §21 | 进程上下文字段 | P | P | 行为记录 + PMFE 路径逐步对齐 |

---

## 17 Shellcode（Windows）

| 小节 | 说明 | Win | Linux | 证据 / 备注 |
|------|------|-----|-------|-------------|
| §17 全文 | WinDivert + 解析 + 规则 | P | — | `src/shellcode_detector/`；默认 **`enabled=false`**；**TLS** 见 **`docs/SHELLCODE_TLS_GAP_ADR.md`** |
| 语料回归 | manifest + pipeline | Y | — | **`test_data/shellcode_corpus/`**、**`docs/SHELLCODE_EVALUATION_CORPUS.md`** |

---

## 18 Webshell

| 小节 | 说明 | Win | Linux | 证据 / 备注 |
|------|------|-----|-------|-------------|
| §18 核心路径 | 监控 + YARA/回退 + 告警 + 上传 | P | P | `src/webshell_detector/`；**Windows** 站点路径策略见 README §18 |
| §18.11 MinIO 规范 | 桶与 key 形态 | X | X | 平台 ingest + **`docs/AGT009_FORENSIC_UPLOAD_E2E.md`** |

---

## 19 攻击面快照

| 小节 | 说明 | Win | Linux | 证据 / 备注 |
|------|------|-----|-------|-------------|
| §19.3～19.4 采集与调度 | 监听/出站/周期/ETW 去抖 | Y | Y | `src/attack_surface/`、README §19 长段 |
| §19.5 上报 Proto | gRPC `ReportSnapshot` | N | N | 当前为 **REST `curl` POST**；差异见 **`docs/ATTACK_SURFACE_GRPC.md`** |
| §19.6～19.7 存储与 UI | 平台/控制台 | X | X | **edr-backend**、**edr-frontend** |

---

## 20 AI 模型管理页（v1.4）

| 小节 | 说明 | Win | Linux | 证据 / 备注 |
|------|------|-----|-------|-------------|
| §20 全文 | 前端 IA、Hook、WS | X | X | **edr-frontend**；与 Agent 通过 §5/§7 间接联动 |

---

## 21 PMFE（进程内存取证引擎）

| 小节 | 说明 | Win | Linux | 证据 / 备注 |
|------|------|-----|-------|-------------|
| §21 引擎与指令 | `pmfe_scan`、队列、VAD/AVE | P | P | `src/pmfe/pmfe_engine.c` 等；**Linux** 为 maps 粗扫路径 |
| §21 与 shellcode 自动入队 | ETW 联动 | Y | — | **`docs/SOAR_CONTRACT.md`** §1 **`EDR_PMFE_ETW_AUTO`** |

---

## 维护约定

1. **改代码**：同步更新本表对应行的 **证据** 列（路径或文档）。  
2. **发版评审**：至少勾选 **§3（Win）**、**§6–§8**、**§10–§11**、与产品开关相关的 **§17/§18**。  
3. **Linux 专版**：额外强制审 **§3.2 / §4.15 / §21** 三行。

---

## 修订记录

| 日期 | 变更 |
|------|------|
| 2026-04-20 | 首版：回应「按设计章节 RAG/Y/N + 证据」诉求，范围 **edr-agent** + 标注 **X** 外仓 |
