#ifndef EDR_AVE_PROCESS_IDENTITY_H
#define EDR_AVE_PROCESS_IDENTITY_H

#include "edr/parent_pid.h"

/* Internal event capture, not part of the public AVE SDK ABI. The queue owns
 * a copy from the same source event; a current PID lookup cannot create it. */
typedef struct {
  uint32_t pid;
  uint32_t parent_pid;
  uint8_t parent_pid_state;
  uint64_t process_start_key;
  uint64_t process_creation_filetime_100ns;
  char source_event_id[48];
} EdrAveProcessIdentity;

#endif
