/**
 * Windows endpoint collection policy.
 *
 * The collector still receives coarse ETW streams, but this policy keeps the
 * high-value Windows attack surface explicit before events are emitted or
 * persisted. It is intentionally metadata-only: no file content, packet
 * content, or memory dump is read here.
 */
#ifndef EDR_WINDOWS_EVENT_POLICY_H
#define EDR_WINDOWS_EVENT_POLICY_H

#include "edr/behavior_record.h"

#include <stdint.h>

typedef struct {
  uint8_t applies;
  uint8_t high_value;
  uint8_t suspicious;
  uint8_t noisy;
  uint8_t should_emit;
  uint8_t should_persist;
  char reason[96];
  char tags[192];
} EdrWindowsEventPolicy;

void edr_windows_event_policy_evaluate(const EdrBehaviorRecord *r,
                                       EdrWindowsEventPolicy *out);

/** Add policy tags to the behavior record and adjust priority for high-value Windows events. */
void edr_windows_event_policy_apply(EdrBehaviorRecord *r);

/** Return 0 for ordinary Windows file/registry noise that should not be sent upstream. */
int edr_windows_event_policy_should_emit(const EdrBehaviorRecord *r);

/** Return 0 for ordinary Windows file/registry noise that should stay ring-only. */
int edr_windows_event_policy_should_persist(const EdrBehaviorRecord *r);

#endif
