#ifndef EDR_RESOURCE_H
#define EDR_RESOURCE_H

#include "edr/config.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** §12 资源限制：按配置轮询 CPU/内存占用并打日志；超限时进入 emergency 计数 */
void edr_resource_init(const EdrConfig *cfg);
void edr_resource_shutdown(void);
void edr_resource_poll(void);

unsigned long edr_resource_emergency_count(void);

/**
 * 资源压力下预处理是否应 **跳过低优先级** 事件（`EdrEventSlot.priority != 0`）。
 * POSIX：CPU/RSS 超限时置位，恢复后清除。**Windows**：当前无 rusage 采样，仅 **`EDR_PREPROCESS_THROTTLE=1`** 强制开启（联调）。
 */
bool edr_resource_preprocess_throttle_active(void);

#ifdef __cplusplus
}
#endif

#endif
