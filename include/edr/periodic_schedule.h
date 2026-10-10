#ifndef EDR_PERIODIC_SCHEDULE_H
#define EDR_PERIODIC_SCHEDULE_H
#include <stdint.h>
#include <stddef.h>

typedef struct {
  uint64_t next_ns;
  uint32_t interval_s;
} EdrPeriodicSchedule;

/* Stable endpoint/job phase, capped at 10% of the period and 30 seconds.
 * Liveness starts immediately. Its first recurring sample is brought forward,
 * never delayed beyond the configured cadence. Maintenance may defer its first
 * pull by this bounded phase. Later samples retain that endpoint phase. */
static inline uint32_t edr_periodic_phase_ms(const char *endpoint, const char *job,
                                            uint32_t interval_s) {
  uint32_t hash = 2166136261u;
  const char *parts[2] = {endpoint, job};
  for (size_t i = 0u; i < 2u; ++i) {
    for (const unsigned char *p = (const unsigned char *)(parts[i] ? parts[i] : ""); *p; ++p)
      hash = (hash ^ *p) * 16777619u;
    hash = (hash ^ 0xffu) * 16777619u;
  }
  uint32_t cap_ms = interval_s > 300u ? 30000u : interval_s * 100u;
  return cap_ms ? hash % (cap_ms + 1u) : 0u;
}

static inline int edr_periodic_schedule_due(EdrPeriodicSchedule *schedule,
                                           uint64_t now_ns, uint32_t interval_s,
                                           const char *endpoint, const char *job,
                                           int initial_immediate, int force) {
  if (!schedule || !interval_s) return 0;
  uint64_t period_ns = (uint64_t)interval_s * 1000000000ULL;
  uint64_t phase_ns = (uint64_t)edr_periodic_phase_ms(endpoint, job, interval_s) * 1000000ULL;
  if (!schedule->next_ns || schedule->interval_s != interval_s) {
    schedule->interval_s = interval_s;
    if (initial_immediate || force) {
      schedule->next_ns = now_ns + period_ns - phase_ns;
      return 1;
    }
    schedule->next_ns = now_ns + phase_ns;
  }
  if (!force && now_ns < schedule->next_ns) return 0;
  schedule->next_ns = now_ns + period_ns;
  return 1;
}
#endif
