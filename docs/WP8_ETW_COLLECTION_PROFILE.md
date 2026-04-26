# WP-8：ETW / 采集「profile」+ 合规底线

> **目标**：为 **Windows ETW 采集**（及 Linux 总线/轮询）提供**可写进变更单**的 **profile** 名称、**与 P0/会签的边界**、**可量化观测**手段；与 **WP-2**（总线/预处理限载）区分职分——**先**在 **collection** 层保持合规，再谈「预处理丢事件」类策略。

> **相关**：`Cauld Design/EDR_P0_Field_Matrix_Signoff.md`、**`EDR_ETW_optimization_and_behavior_rule_engine_master_plan.md` §4**、**WP-2**、**WP-5**、**`config/profiles/README.md`**、**WP-9** 行为/AVE/回调（`docs/WP9_BEHAVIOR_AVE.md`）。

## 1. 合规底线（关 Provider / 开轻量 path 前必读）

1. **权威**：`Cauld Design/EDR_P0_Field_Matrix_Signoff.md` — 各 `event_type` 与 **ETW 槽字段** 的最小集；**扩「早返 / TDH 轻量 path / 关 Provider」** 必须：对表、回归、（按任务包）会签。  
2. **默认 TOML**：`agent.toml.example` 的 **`[collection]`** — Kernel 主路径**不可**用布尔开关关断（注释已说明）；**可选** Provider（DNS、PowerShell、Security-Auditing、WMI、TCPIP、WFAF 等）在关 **`true`→`false` 前** 须有**产品/安全**用例对表。  
3. **环境「轻量 path」**（`EDR_TDH_LIGHT_PATH*`，见 `etw_tdh_win.c` 注释）：**会签/任务包**门槛在代码与 Cauld 设计文内；**不得**在不知情下仅为主机「省 CPU」而长期开启扩面项。

## 2. 两档建议 profile

### 2.1 `compliance_baseline`（全量可观测、审计友好）

- **TOML**：`[collection]` 保持与 **`agent.toml.example` 同思路**（各 ETW 开关为 **true**、`max_event_queue_size` 用运营口径）。  
- **环境**：`config/profiles/wp8_compliance_baseline.env.example`（**`EDR_ETW_OBS=1`**、可选 `EDR_ETW_OBS_EXPORT_PATH`、与 heartbeat 同周期可观测行）。  
- **用途**：签核、P0/字段矩阵**回归**、**压测**前后对照（与 `bus_dropped`、A4.4 相变量一起读）。

### 2.2 `laboratory_cost_probe`（成本探测，不代替合规签字）

- **先** 用 **WP-2 实验室档** 放松预处理（`wp2_lab_e2e.env.example`），**勿**把「关 DNS/PS/Sec」当作第一手段。  
- 若**必须**缩减 ETW 面，走**正式变更**并更新 **P0/字段矩阵/任务包** 状态；本仓库不默认提供「关 Provider」的**一键** env 以免误用。

## 3. 启动时一行（与实现对账）

- 成功进入 `edr_agent_run`、预处理就绪后、**采集启动前** 打印：  
  **`[collection] etw_on=… tcpip=… fw=… dns=… ps=… secaudit=… wmi=… ebpf=… poll_s=… queue_size=… etw_buf_kb=… etw_flush_s=…`**（见 `agent.c`）。  
- 与 **`agent.toml` + 环境覆盖**（如 `EDR_ETW_BUFFER_KB` 在 `config.c` clamp 后）**交叉检查**；发现与预期不符时先查 **重载/路径** 再开 issue。

## 4. 常用观测环境变量（Windows 摘录）

| 变量 | 作用（摘要） |
|------|----------------|
| **`EDR_ETW_OBS=1`** | 与 heartbeat 同周期打 ETW/总线**观测**行（见 `etw_observability_win.h` / `edr_agent_print_console_heartbeat_line` 条件） |
| **`EDR_ETW_OBS_EXPORT_PATH=…`** | 同内容**追加**到本地文件，便于 shipper |
| **`EDR_ETW_BUFFER_KB` / `EDR_ETW_FLUSH_TIMER_S`** | 覆盖 **ETW 会话**缓冲/刷写（A4.2，见 README） |
| **`EDR_TDH_LIGHT_PATH` / `EDR_TDH_LIGHT_PATH_PS` / `EDR_TDH_LIGHT_PATH_TCPIP`** | **A3.3+** 轻量 path；**须**有会签/白名单再长期开 |

Linux：**`ebpf_enabled` / `poll_interval_s` / `max_event_queue_size`** 在同行中可见；详细能力见 **README 能力矩阵**。

## 5. 与 WP-2 的分工

| 层 | 典型手段 |
|----|----------|
| **WP-8（本页）** | 少订事件（少 Provider/轻量 path）= **少进总线** = 需 **P0/会签** |
| **WP-2** | 总线已进事件，**L2/L3/门控** 再限载 = **不**替代 P0 字段责任 |

**顺序**：先确认 **WP-8 合规** 与 **观测**（`EDR_ETW_OBS`、**`[collection]` 行**），再调 **WP-2**。

## 6. 完成标准（验收）

- [ ] 能指着 **`EDR_P0_Field_Matrix_Signoff.md`** 说明**为何**不能随意关 **DNS/PS/Sec** 等开关。  
- [ ] 启动日志里 **有一行 `[collection] …`**，与当前 **`agent.toml`**（及已知的 `EDR_ETW_*` 环境覆盖）**对得上**。  
- [ ] **审计/回归机** 至少跑过一次 **`wp8_compliance_baseline.env.example`** 思路 + **WP-2 实验室** 的**区隔**（文档或工单里写清目的）。

## 7. 交叉参考

- `edr-agent/agent.toml.example` — `[collection]`  
- `edr-agent/src/core/agent.c` — 打印与 **heartbeat** 条件中的 **ETW observability** 分支（Windows）  
- `edr-agent/src/collector/etw_tdh_win.c` — `EDR_TDH_LIGHT_PATH*`  
- `edr-agent/include/edr/etw_observability_win.h`  
- `Cauld Design/EDR_Task_Package_ETW_Rule_Engine_Sprints.md`  
