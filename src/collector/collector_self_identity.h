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

/* Kernel-File Read identifies its actor in EventHeader.ProcessId, but the
 * optional ETW StartKey is absent on some supported Windows builds. While
 * this Agent process is live, its PID cannot be reused; source event time
 * must still belong to its verified creation lifetime. A supplied StartKey
 * must agree rather than being ignored. This is only for typed FileRead. */
static inline int edr_collector_self_identity_matches_file_read(
    const EdrLiveProcessGeneration *self, uint32_t pid, uint64_t event_unix_ns,
    uint64_t event_start_key) {
  return self && self->pid != 0u && self->process_start_key != 0u &&
         self->creation_filetime_100ns != 0u && pid == self->pid &&
         edr_process_generation_contains_event(self->creation_filetime_100ns,
                                               event_unix_ns) &&
         (event_start_key == 0u || event_start_key == self->process_start_key);
}

#endif
