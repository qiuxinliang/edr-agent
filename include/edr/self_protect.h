#ifndef EDR_SELF_PROTECT_H
#define EDR_SELF_PROTECT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct EdrConfig;
struct EdrEventBus;

/** §9 自保护：信号审计、防调试、事件总线背压观测、可选 Windows Job Object、看门狗 tick */
/** 在 `edr_self_protect_init` 之前调用：收到 SIGINT/SIGTERM 时先审计再调用 cb（如 `edr_agent_shutdown`）。 */
void edr_self_protect_set_shutdown_hook(void (*cb)(int signo));
void edr_self_protect_init(void);
/** 在 `EdrConfig` 加载成功后调用；`edr_agent` 在创建 event_bus 之后调用 `edr_self_protect_set_event_bus`。 */
void edr_self_protect_apply_config(const struct EdrConfig *cfg);
void edr_self_protect_set_event_bus(struct EdrEventBus *bus);
void edr_self_protect_shutdown(void);
void edr_self_protect_poll(void);

/** 当前是否检测到调试器（1=是）。无配置或未启用 anti_debug 时仍可做一次性探测。 */
int edr_self_protect_debugger_attached(void);

/**
 * 短状态串，供 `self_protect_status` 指令与排障：`debugger=… bus_pct=… job=…`。
 */
void edr_self_protect_format_status(char *buf, size_t cap);

#ifdef __cplusplus
}
#endif

#endif
