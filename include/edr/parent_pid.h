#ifndef EDR_PARENT_PID_H
#define EDR_PARENT_PID_H
#include <stdint.h>

/* UNKNOWN is also the legacy value: a legacy nonzero PID is known. */
typedef enum {
  EDR_PARENT_PID_UNKNOWN = 0,
  EDR_PARENT_PID_KNOWN = 1,
  EDR_PARENT_PID_EXPLICIT_ZERO = 2,
  EDR_PARENT_PID_INVALID = 3,
  EDR_PARENT_PID_CONFLICT = 4
} EdrParentPidState;

static inline uint8_t edr_parent_pid_effective_state(uint32_t pid, uint8_t state) {
  return state == EDR_PARENT_PID_UNKNOWN && pid != 0u ? EDR_PARENT_PID_KNOWN : state;
}

/* Merge only after the owner proves the same child generation. Unknown cache
 * metadata cannot erase a fact. A conflict keeps the original value and is
 * sticky for this lifetime; it is never permission to traverse a parent. */
static inline void edr_parent_pid_merge(uint32_t *pid, uint8_t *state,
                                       uint32_t incoming, uint8_t incoming_state) {
  uint8_t current = edr_parent_pid_effective_state(*pid, *state);
  incoming_state = edr_parent_pid_effective_state(incoming, incoming_state);
  if (current == EDR_PARENT_PID_CONFLICT) { *state = current; return; }
  if (incoming_state == EDR_PARENT_PID_CONFLICT) {
    if (current == EDR_PARENT_PID_UNKNOWN) *pid = incoming;
    *state = EDR_PARENT_PID_CONFLICT; return;
  }
  if (incoming_state == EDR_PARENT_PID_UNKNOWN) { *state = current; return; }
  if (current == EDR_PARENT_PID_UNKNOWN) {
    *pid = incoming; *state = incoming_state; return;
  }
  if ((current == EDR_PARENT_PID_KNOWN || current == EDR_PARENT_PID_EXPLICIT_ZERO) &&
      (incoming_state == EDR_PARENT_PID_KNOWN || incoming_state == EDR_PARENT_PID_EXPLICIT_ZERO) &&
      *pid != incoming) current = EDR_PARENT_PID_CONFLICT;
  *state = current;
}
#endif
