#ifndef EDR_PROCESS_CREATE_COALESCER_H
#define EDR_PROCESS_CREATE_COALESCER_H

#include "edr/behavior_record.h"

#include <stdint.h>

/* The ETW callback never uses this API.  It is owned by the preprocess
 * worker so a Security 4688 observation and a kernel create can be joined
 * without blocking the collector or evaluating a generation twice. */
typedef enum {
  EDR_PROCESS_COALESCE_PASS = 0,
  EDR_PROCESS_COALESCE_HOLD = 1,
  EDR_PROCESS_COALESCE_READY = 2
} EdrProcessCoalesceResult;

typedef struct {
  uint32_t slots_used;
  uint32_t capacity;
  uint64_t security_stored;
  uint64_t security_backpressure;
  uint64_t kernel_backpressure;
  uint64_t timed_out;
  uint64_t stale_rejects;
  uint64_t ambiguous_rejects;
} EdrProcessCoalescerMetrics;

void edr_process_coalescer_reset(void);
EdrProcessCoalesceResult edr_process_coalescer_submit(const EdrBehaviorRecord *record,
                                                       int p0_candidate,
                                                       uint64_t monotonic_ns,
                                                       EdrBehaviorRecord *out_ready);
/* Returns one expired kernel candidate at a time.  Security-only observations
 * expire silently: they are enrichment, never an independent process alert. */
int edr_process_coalescer_poll(uint64_t monotonic_ns, EdrBehaviorRecord *out_ready);
void edr_process_coalescer_get_metrics(EdrProcessCoalescerMetrics *out);

#endif
