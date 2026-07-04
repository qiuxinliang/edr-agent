/* §B1 子系统心跳逻辑单测：beat / age / stale_mask 语义。 */

#include "edr/heartbeat.h"
#include "edr/time_util.h"

#include <stdint.h>
#include <stdio.h>

static int fail(const char *msg) {
  fprintf(stderr, "fail: %s\n", msg);
  return 1;
}

/* 自旋等待单调时钟前进 at_least_ns。 */
static void spin_ns(uint64_t at_least_ns) {
  uint64_t start = edr_monotonic_ns();
  for (;;) {
    uint64_t now = edr_monotonic_ns();
    if (now > start && (now - start) >= at_least_ns) {
      return;
    }
  }
}

int main(void) {
  /* 从未 beat：不计入超期，age=0。 */
  if (edr_health_stale_mask(1000000000ULL) != 0u) {
    return fail("no-beat should not be stale");
  }
  if (edr_health_age_ns(EDR_HEALTH_COLLECTOR) != 0u) {
    return fail("no-beat age must be 0");
  }

  edr_health_beat(EDR_HEALTH_COLLECTOR);

  /* 刚 beat：大阈值下不超期。 */
  if (edr_health_stale_mask(1000000000ULL) != 0u) {
    return fail("fresh beat must not be stale under 1s threshold");
  }

  /* max_age=0 一律返回 0（关闭语义）。 */
  if (edr_health_stale_mask(0u) != 0u) {
    return fail("zero threshold disables staleness");
  }

  /* 等待 ~20ms 后，用 10ms 阈值应判 COLLECTOR 超期；TRANSPORT 从未 beat 不计。 */
  spin_ns(20ULL * 1000000ULL);
  uint32_t mask = edr_health_stale_mask(10ULL * 1000000ULL);
  if ((mask & (1u << EDR_HEALTH_COLLECTOR)) == 0u) {
    return fail("collector should be stale after 20ms over 10ms threshold");
  }
  if ((mask & (1u << EDR_HEALTH_TRANSPORT)) != 0u) {
    return fail("never-beaten transport must not be flagged");
  }

  /* 再 beat 一次即恢复。 */
  edr_health_beat(EDR_HEALTH_COLLECTOR);
  if ((edr_health_stale_mask(10ULL * 1000000ULL) & (1u << EDR_HEALTH_COLLECTOR)) != 0u) {
    return fail("collector should recover after re-beat");
  }

  printf("ok: heartbeat beat/age/stale semantics\n");
  return 0;
}
