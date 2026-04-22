# 事件总线 `bus_pct` / `dropped` 与 Prometheus（§P2c **S3**）

**现状**：**`bus_pct`**、**`dropped`**、**`hw_hits`** 由 **`edr_self_protect_format_status`** 与 **`edr_self_protect_poll`** 输出到 **stderr**；进程退出时 **`[preprocess]`** 行含 **`bus_hw80`**、**`bus_dropped`**（见 **`docs/EVENT_BUS_BACKPRESSURE.md`**）。

**可选进程内 `/metrics`（Windows）**：设置环境变量 **`EDR_AGENT_METRICS_BIND=127.0.0.1:9123`**（**IPv4 字面量:端口**）后，**`edr_agent`** 在初始化总线后启动后台线程，对 **`GET /metrics`** 返回 **Prometheus 文本**（总线 **`dropped` / `high_water_hits` / 槽位占用** 与 **§17 WinDivert** 累计计数）；**`GET /health`** 返回 **`ok`**。未设置该变量时**不监听**任何端口。实现见 **`src/core/metrics_http.c`**、**`include/edr/metrics_http.h`**。

---

## 1. 可选集成路径

| 方式 | 说明 |
|------|------|
| **进程内（Windows）** | 上节 **`EDR_AGENT_METRICS_BIND`**；适合本机 **Prometheus** 或运维 **`curl`** 抓取。 |
| **日志边车** | 用 **Promtail / Vector / Fluent Bit** 解析 stderr 正则，暴露 **`edr_bus_dropped_total`** 等计数。 |
| **主机代理** | **windows_exporter** / **node_exporter** 文本文件收集：由计划任务周期性 **`curl`/`Invoke-WebRequest`** 调只读健康接口。 |
| **进一步内置** | 更完整的 **OpenTelemetry Metrics**、鉴权、mTLS 等仍可与 **§2.3** 资源治理一并排期。 |

---

## 2. 建议标签

- **`endpoint_id`**、**`tenant_id`**（若日志或 sidecar 可解析 **TOML**/**enroll**）。  
- **`agent_version`**。

---

**关联**：**`docs/EVENT_BUS_BACKPRESSURE.md`**、**`docs/SHELLCODE_AGENT_SLO.md`**（SLO 占位）。
