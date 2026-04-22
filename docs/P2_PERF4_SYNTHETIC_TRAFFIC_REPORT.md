# P2-PERF-4 — 合规合成流量压测报告

**清档**：**`docs/WINDOWS_SHELLCODE_FORENSIC_TODO.md` §P2b** 子项 **P2-PERF-4**。  
**SLO 对齐**：**`docs/SHELLCODE_AGENT_SLO.md`** **SLO-WD-1 / SLO-WD-2**、**`docs/EVENT_BUS_BACKPRESSURE.md`**。

**说明**：下文 **§1–§3、§5** 为仓库维护侧填写的 **可复现形态与结论框架**；**§4** 给出与当前代码 **日志格式一致** 的 **示例原始行**（来自同类构建的 smoke 形态）。若在客户或隔离实验室内做正式验收，请复制本文件为 **`P2_PERF4_RUN_<hostname>_<date>.md`** 并将 **§4** 整行替换为当次 **stderr** 粘贴，并在 **§0** 更新执行人与环境标识。

---

## 0. 合规与范围声明

- **流量性质**：实验室内 **自生成** TCP（目标端口在 **`windivert_tcp_ports`** / 默认 WinDivert 过滤器覆盖范围内）；**禁止**对未授权目标扫描。
- **执行人 / 日期 / 环境**：维护机器人 / **2026-04-20** / 开发用 VM 或 CI Windows runner（**非**生产租户专机）。
- **Agent 版本**：与主分支 **`edr_agent`** 一致；**Git** 以发布前 **`git rev-parse --short HEAD`** 为准。

---

## 1. 主机与 Agent 配置快照

| 项 | 值 |
|----|-----|
| **OS** | Windows 10/11 x64（具体 build 以专机 `winver` 为准） |
| **vCPU / RAM** | **≥4 vCPU / ≥8 GiB**（专机填写） |
| **`agent.toml` 路径** | 专机实际路径 |
| **`[shellcode_detector]` 要点** | `max_payload_inspect`（默认或团队约定）、`forensic_ring_slots`、`windivert_tcp_ports`、**`forensic_dir`** / **`EDR_FORENSIC_OUT`** |
| **WinDivert** | 系统 **`WinDivert.dll`**；队列 **`WINDIVERT_PARAM_QUEUE_LEN` / `WINDIVERT_PARAM_QUEUE_TIME`** 以运行环境为准（若代码或环境有覆盖，注明） |
| **`[collection].max_event_queue_size`** | 与 **`EVENT_BUS_BACKPRESSURE.md`** 推荐一致或专机实测值 |
| **其它环境变量** | **`EDR_SHELLCODE_WD_STATS=1`**（关机/停模块时 **`wd_stats`**）；可选 **`EDR_AGENT_METRICS_BIND=127.0.0.1:9123`** 抓取 **`/metrics`** |

---

## 2. 负载 Profile（可复现）

| Profile ID | 描述 | 持续时间 | 备注 |
|------------|------|----------|------|
| **P-A** | 基线：仅 Agent 常驻 + 正常业务背景 | **≥30 min** | 对照组 |
| **P-B** | 合成：对监听 **445 / 5985 / 3389** 等端口的 **短连接或持续流**（**pps** 与包长由专机记录） | **≥15 min** | 与 **P-A** 同机、同配置 |
| **P-C** | （可选）更短间隔、更大突发，观察 **`bus_dropped`** 是否 **>0** | | 与 **`max_event_queue_size`** 联合调参 |

**`proto_parse` / SMB2 扩展（T-SC-013）**：在变更 **`proto_parse.c` Command 白名单** 前后，建议仍用 **P-B** 与同一份 **`max_payload_inspect`**，对比 **`wd_stats`** 中 **`pushed` / `bus_drop` / `alert_dedup`** 与进程 CPU；专机微基准步骤见 **`docs/SHELLCODE_PROTO_PARSE_PERF.md`**。

**复现步骤**：

1. 安装/启动 Agent，确认 WinDivert 与 ETW 无持续报错。
2. 设置 **`EDR_SHELLCODE_WD_STATS=1`**，记录启动时间 **T0**。
3. 按 Profile 注入流量（**写清工具与参数**：如实验 HTTP/SMB 服务端、合规 replay）。
4. 在 **T0+窗口结束** 时停止 Shellcode 模块或**优雅退出 Agent**（**Ctrl+C** 或 **`sc stop`**），捕获 stderr 中 **`[shellcode_detector] wd_stats`** 行（整行粘贴到 §4）。
5. 保存进程退出前 **`[preprocess]`** 汇总行（**`bus_dropped` / `bus_hw80`** 等）。

---

## 3. CPU 与资源采样

| 采样方式 | 间隔 | 说明 |
|----------|------|------|
| **任务管理器 / perfmon** | **60 s** | 记录 **Agent 进程**平均 CPU% 与 **RSS** 峰值 |
| **（可选）** `typeperf` / 其它 | | 附原始 CSV 路径 |

---

## 4. 原始观测数据（必填）

### 4.1 **`wd_stats` 行**（**`EDR_SHELLCODE_WD_STATS=1`**，来自 **`edr_windivert_capture_stop`**）

```
[shellcode_detector] wd_stats recv=12480 recv_err=0 skip=210 mon_skip=11890 pushed=3 bus_drop=0 alert_dedup=0
```

（上行为 **形态示例**：专机关单请替换为当次完整粘贴。）

### 4.2 **进程退出 `[preprocess]` 汇总**（节选）

```
[preprocess] wire_events=0 wire_bytes=0 batches=0 batch_bytes=0 batch_lz4=0 batch_timeout_flushes=0 bus_hw80=0 bus_dropped=0 dedup_drops=0 rate_drops=0 queue_pending=0
```

（上行为 **低负载 idle** 形态示例；有上游事件时 **`wire_events`** 等会非零。）

### 4.3 **（可选）** 平台侧 ingest / 告警延迟

**N/A**（无全链 trace 时）。

---

## 5. 结论与建议

| 指标 | P-A 结果 | P-B 结果 | 是否满足内部目标（TBD） |
|------|-----------|-----------|-------------------------|
| **`bus_drop` / `pushed`（粗比）** | **0 / 0**（idle） | **示例 0 / 3** | 由产品与运维签署阈值 |
| **`recv_err` / `recv`** | **0 / 稳定** | **示例 0 / 1.2e4** | 关注 **`recv_err`** 非零是否与驱动/过滤相关 |
| **Agent CPU%（均值/峰值）** | 专机填写 | 专机填写 | |
| **是否触发 `bus_dropped` > 0** | 否（示例） | 否（示例） | 若 **是**，对照 **`EVENT_BUS_BACKPRESSURE.md`** 调 **`max_event_queue_size`** 或降载 |

**调参建议**（若有）：增大 **`max_event_queue_size`**、调整 **WinDivert 队列**、收紧 **`windivert_tcp_ports`** 等 — **须与产品/安全共同评审**。

---

## 6. 附录 — 虚构数字表（不得作为验收依据）

| 指标 | P-A | P-B |
|------|-----|-----|
| **`bus_drop`/`pushed`** | 0 / 12000 | 3 / 185000 |
| **CPU% 均值** | 1.2 | 4.8 |
| **`recv_err`** | 0 | 2 |

---

**维护**：每次新专机压测可复制本模板为新文件 **`P2_PERF4_RUN_<hostname>_<date>.md`** 存档，并在 **`WINDOWS_SHELLCODE_FORENSIC_TODO.md`** 的 **P2-PERF-4** 行备注链接。
