/**
 * 可选进程内 Prometheus 文本指标（Windows：仅当设置 **`EDR_AGENT_METRICS_BIND`** 时启动）。
 * 见 **`docs/PROMETHEUS_BUS_METRICS.md`**。
 */
#ifndef EDR_METRICS_HTTP_H
#define EDR_METRICS_HTTP_H

struct EdrEventBus;

/** 解析 **`EDR_AGENT_METRICS_BIND`**（形如 **`127.0.0.1:9123`**）；未设置或非 Windows 则为空操作。 */
void edr_metrics_http_start_if_configured(struct EdrEventBus *bus);

/** 关闭监听并等待指标线程退出（须在销毁总线之前调用）。 */
void edr_metrics_http_stop(void);

#endif
