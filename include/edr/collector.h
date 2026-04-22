/**
 * 采集层入口（§3）— Windows：ETW 实时订阅；Linux：collector_linux（演进中）；其余 POSIX：stub。
 */
#ifndef EDR_COLLECTOR_H
#define EDR_COLLECTOR_H

#include "edr/error.h"

struct EdrEventBus;
struct EdrConfig;

/**
 * 启动采集：Windows 为 ETW 会话（Kernel-Process / File / Network 等）；Linux（M1）为 inotify 目录监视；其它 POSIX 为 stub。
 * 使用 `cfg->collection.etw_enabled`；Windows 另读 `etw_tcpip_provider` / `etw_firewall_provider`（§19.10）。
 * `cfg` 为空视为未启用采集。失败返回 EDR_ERR_ETW_*（常见原因：权限不足、会话名冲突）。
 */
EdrError edr_collector_start(struct EdrEventBus *bus, const struct EdrConfig *cfg);

/** 停止会话并 join 消费线程（可重复调用）。 */
void edr_collector_stop(void);

#endif
