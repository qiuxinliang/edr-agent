#ifndef EDR_COLLECTOR_SELF_IDENTITY_H
#define EDR_COLLECTOR_SELF_IDENTITY_H

#include "edr/process_generation.h"

/* `self` is captured from the Agent's live process handle before collection
 * starts. No event field may create or extend this authority. In particular,
 * parent PID, image name, command text and job markers are not ownership. */
static inline int edr_collector_self_identity_matches(
    const EdrLiveProcessGeneration *self, uint32_t pid, uint64_t start_key) {
  return self && self->pid != 0u && self->process_start_key != 0u &&
         self->creation_filetime_100ns != 0u && pid == self->pid &&
         start_key == self->process_start_key;
}

#endif
