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
 * 使用 `cfg->collection.etw_enabled`；Windows 另读 `etw_*_provider` 系列（见 `config.h` 与 §19.10，含 A4.3 四项可选 Provider）。
 * `cfg` 为空视为未启用采集。失败返回 EDR_ERR_ETW_*（常见原因：权限不足、会话名冲突）。
 */
EdrError edr_collector_start(struct EdrEventBus *bus, const struct EdrConfig *cfg);

/** 停止会话并 join 消费线程（可重复调用）。 */
void edr_collector_stop(void);

/**
 * 按固定会话名尝试停止可能残留的 ETW 实时会话（无需本进程曾 StartTrace）。
 * 供卸载 / 运维脚本调用，避免上次异常退出后内核仍占用 `EDR_Agent_RT_001` 等会话。
 * 非 Windows 为 no-op。
 */
void edr_collector_stop_orphan_etw_session(void);

#endif
