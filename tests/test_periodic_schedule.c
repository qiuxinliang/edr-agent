#include "edr/periodic_schedule.h"
#include <assert.h>
int main(void) {
  const uint64_t now = 900000000000ULL;
  EdrPeriodicSchedule live = {0}, maintenance = {0};
  assert(edr_periodic_schedule_due(&live, now, 60u, "ep-one", "heartbeat", 1, 0));
  assert(live.next_ns > now + 54000000000ULL && live.next_ns <= now + 60000000000ULL);
  uint64_t deadline = live.next_ns;
  assert(!edr_periodic_schedule_due(&live, deadline - 1u, 60u, "ep-one", "heartbeat", 1, 0));
  assert(edr_periodic_schedule_due(&live, deadline, 60u, "ep-one", "heartbeat", 1, 0));
  assert(live.next_ns == deadline + 60000000000ULL);
  assert(edr_periodic_schedule_due(&live, deadline, 30u, "ep-one", "heartbeat", 1, 0));
  assert(live.next_ns <= deadline + 30000000000ULL);
  assert(!edr_periodic_schedule_due(&maintenance, now, 1800u, "ep-one", "p0", 0, 0));
  assert(maintenance.next_ns <= now + 30000000000ULL);
  assert(edr_periodic_schedule_due(&maintenance, maintenance.next_ns, 1800u, "ep-one", "p0", 0, 0));
  assert(edr_periodic_phase_ms("ep-one", "heartbeat", 60u) != edr_periodic_phase_ms("ep-two", "heartbeat", 60u));
  assert(edr_periodic_phase_ms("ep-one", "heartbeat", 60u) != edr_periodic_phase_ms("ep-one", "health", 60u));
  assert(edr_periodic_schedule_due(&live, now, 30u, "ep-one", "heartbeat", 1, 1));
  return 0;
}
