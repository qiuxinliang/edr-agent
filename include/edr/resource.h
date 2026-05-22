#ifndef EDR_RESOURCE_H
#define EDR_RESOURCE_H

#include "edr/config.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** §12 资源限制：按配置轮询 CPU/内存占用并打日志；超限时进入 emergency 计数 */
void edr_resource_init(const EdrConfig *cfg);
void edr_resource_shutdown(void);
void edr_resource_poll(void);

unsigned long edr_resource_emergency_count(void);
unsigned edr_resource_cpu_percent(void);
unsigned long edr_resource_current_rss_mb(void);
uint32_t edr_resource_thread_count(void);
uint32_t edr_resource_handle_count(void);
uint64_t edr_resource_last_sample_ms(void);
void edr_resource_pressure_reason(char *buf, size_t cap);
uint64_t edr_resource_preprocess_throttle_drop_count(void);
void edr_resource_note_preprocess_throttle_drop(void);

/**
 * 资源压力下预处理是否应 **跳过低优先级** 事件（`EdrEventSlot.priority != 0`）。
 * CPU/RSS 超限时置位，恢复后清除；也可用 **`EDR_PREPROCESS_THROTTLE=1`** 强制开启（联调）。
 */
bool edr_resource_preprocess_throttle_active(void);

#ifdef __cplusplus
}
#endif

#endif
