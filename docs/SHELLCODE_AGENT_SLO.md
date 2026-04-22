# Shellcode / WinDivert / 事件总线 — 产品 SLO 框架（P2-PERF-1）

本文提供**与业务方、运维可共同填写**的服务水平目标（SLO）表格与量纲说明；**具体数值为 TBD**，落地后在本页或内部看板更新版本与生效日期。

**关联**：**`docs/WINDOWS_SHELLCODE_FORENSIC_TODO.md` §P2b**、**`docs/P2_PERF4_SYNTHETIC_TRAFFIC_REPORT.md`**（P2-PERF-4 压测模板）、**`docs/EVENT_BUS_BACKPRESSURE.md`**（总线满丢弃语义）、**`docs/AGT009_FORENSIC_UPLOAD_E2E.md`**（取证上传链）。

---

## 1. 量纲与观测面

| 维度 | 含义 | 建议观测 |
|------|------|-----------|
| **A. 事件总线背压** | 环形队列满导致 **`edr_event_bus_try_push` 失败** 时事件丢弃（含 ETW、shellcode 告警等） | 进程退出 **`[preprocess] bus_dropped=`**、**`bus_hw80=`**；**`[self_protect]`** 占用 ≥ **`event_bus_pressure_warn_pct`** 时的 stderr；**`docs/EVENT_BUS_BACKPRESSURE.md`** |
| **B. Shellcode（WinDivert）路径** | 从 **`recv`** 到告警入总线的用户态处理；驱动队列由 **`WINDIVERT_PARAM_QUEUE_*`** 等配置 | **`EDR_SHELLCODE_WD_STATS=1`** 停止时 **`wd_stats`**（**`windivert_capture.c`**）；与 **A** 联合看 **`bus_drop`** 与 **`pushed`** |
| **C. 预处理与上报** | 总线 → 预处理 → 批次 → gRPC **ReportEvents** 的吞吐与尾部延迟 | **`[preprocess]`** 退出汇总、**`[grpc] rpc_ok`/`rpc_fail`**；平台 ingest 侧延迟（若可抓取） |
| **D. 取证上传** | **`UploadFile`** 成功率与尾部延迟（**C1** 已在 **`edr-backend`** ingest gRPC 落地；告警 JSON 关联仍依赖 **C2**） | Agent **`rpc_fail`**、**`ReportCommandResult.detail`** 中 **`UploadFile`** 文案；桶内 **`agent-artifacts/`** key 到账 SLA（平台定义） |
| **E. 端上资源** | Agent CPU、RSS、与 **`[resource]`** 降载触发 | **`edr_resource_emergency_count`**、**`EDR_PREPROCESS_THROTTLE`** 相关日志；主机监控 |

---

## 2. SLO 草案表（数值 TBD）

以下列为**占位**；产品与运维将 **TBD** 替换为承诺值或「仅内部目标、不对外承诺」。

| ID | 场景 / 负载 profile | 指标 | 目标（TBD） | 测量窗口 / 备注 |
|----|----------------------|------|-------------|-----------------|
| **SLO-BUS-1** | 稳态 ETW + 默认 Shellcode 配置 | **`bus_dropped` / (wire_events + 1)`** 上限 | TBD | 例如 24h 滚动；需定义「稳态」流量 |
| **SLO-BUS-2** | 总线占用触顶前预警 | **`self_protect` 压力日志** 出现频率上限 | TBD | 与 **`event_bus_pressure_warn_pct`** 联动 |
| **SLO-WD-1** | 专机合成流量（合规） | **`wd_stats`** 中 **`bus_drop`** 相对 **`pushed`**（字段名见 **`windivert_capture.c`** 日志） | TBD | 依赖 **P2-PERF-4** 压测报告（**`docs/P2_PERF4_SYNTHETIC_TRAFFIC_REPORT.md`**） |
| **SLO-WD-2** | 同上 | WinDivert **`recv` 错误** 占比 | TBD | 驱动/队列健康 |
| **SLO-E2E-1** | 告警从产生到平台可见（若全链打通） | p50 / p99 延迟 | TBD | 需平台 trace id；**C2/C3** 后细化 |
| **SLO-RES-1** | 常态 | Agent **RSS / CPU** 上限 | TBD | 与 **`[resource]`** 一致 |

---

## 3. 验收与签署

1. **基线**：在代表性终端配置下跑 **≥24h**（或 CI 冒烟 + 预发周），记录上表观测的**分位数或最大值**。  
2. **签署**：产品负责人 + 运维负责人确认表中 **TBD** 与**违约时的响应**（扩容、调 **`max_event_queue_size`**、调 WinDivert 参数、限流等）。  
3. **回归**：重大版本升级后重复 **§3** 基线测量，更新本页版本脚注。

---

**版本**：框架 v1（P2-PERF-1 文档交付）；指标数值待业务填写。
