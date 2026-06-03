#ifndef EDR_RESOURCE_H
#define EDR_RESOURCE_H

#include "edr/config.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** §12 资源限制：按配置轮询 CPU/内存占用并打日志；超限时进入 emergency 计数 */
void edr_resource_init(const EdrConfig *cfg);
void edr_resource_shutdown(void);
void edr_resource_poll(void);

unsigned long edr_resource_emergency_count(void);

typedef struct {
  uint32_t cpu_percent;
  uint64_t rss_mb;
  uint32_t thread_count;
  uint32_t handle_count;
  uint32_t hot_thread_id;
  uint32_t hot_thread_cpu_percent;
  uint64_t hot_thread_kernel_delta_100ns;
  uint64_t hot_thread_user_delta_100ns;
  uint64_t hot_thread_total_delta_100ns;
  uint32_t throttle_active;
  uint32_t pressure_level;
  uint64_t sample_count;
  char pressure_reason[48];
} EdrResourceSample;

void edr_resource_get_sample(EdrResourceSample *out);

/**
 * 资源压力下预处理是否应 **跳过低优先级** 事件（`EdrEventSlot.priority != 0`）。
 * CPU/RSS 超限时置位，恢复后清除；`EDR_PREPROCESS_THROTTLE=1` 可强制开启。
 */
bool edr_resource_preprocess_throttle_active(void);

#ifdef __cplusplus
}
#endif

#endif
