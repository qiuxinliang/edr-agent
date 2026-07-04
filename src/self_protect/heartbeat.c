/* §9 子系统心跳（进程内）—— 见 include/edr/heartbeat.h */

#include "edr/heartbeat.h"

#include "edr/time_util.h"

/* x64 上对齐 64bit 读写本身原子；volatile 防止编译器缓存到寄存器。
 * 心跳只需“最近一次时间戳”，可容忍极端竞态下的一拍误差，无需锁。 */
static volatile uint64_t s_last_beat_ns[EDR_HEALTH_COMPONENT_COUNT];

void edr_health_beat(EdrHealthComponent id) {
  if ((unsigned)id >= (unsigned)EDR_HEALTH_COMPONENT_COUNT) {
    return;
  }
  uint64_t now = edr_monotonic_ns();
  /* 永不写 0：0 被语义化为“从未 beat”。极少数 now==0 时退化为 1。 */
  s_last_beat_ns[id] = now ? now : 1u;
}

uint64_t edr_health_age_ns(EdrHealthComponent id) {
  if ((unsigned)id >= (unsigned)EDR_HEALTH_COMPONENT_COUNT) {
    return 0;
  }
  uint64_t last = s_last_beat_ns[id];
  if (last == 0u) {
    return 0; /* 未启用 / 从未 beat */
  }
  uint64_t now = edr_monotonic_ns();
  return now > last ? (now - last) : 0u;
}

uint32_t edr_health_stale_mask(uint64_t max_age_ns) {
  if (max_age_ns == 0u) {
    return 0u;
  }
  uint32_t mask = 0u;
  for (unsigned i = 0; i < (unsigned)EDR_HEALTH_COMPONENT_COUNT; i++) {
    uint64_t last = s_last_beat_ns[i];
    if (last == 0u) {
      continue; /* 未启用的子系统不误报 */
    }
    uint64_t now = edr_monotonic_ns();
    if (now > last && (now - last) >= max_age_ns) {
      mask |= (1u << i);
    }
  }
  return mask;
}

const char *edr_health_component_name(EdrHealthComponent id) {
  switch (id) {
    case EDR_HEALTH_COLLECTOR:
      return "collector";
    case EDR_HEALTH_PREPROCESS:
      return "preprocess";
    case EDR_HEALTH_TRANSPORT:
      return "transport";
    case EDR_HEALTH_MAIN_LOOP:
      return "main_loop";
    default:
      return "?";
  }
}
