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

typedef struct {
  uint8_t enabled;
  uint8_t agent_internal_forensic;
  uint8_t low_value_file_process;
  uint8_t low_value_file_suffix;
  uint8_t temp_xml;
  char version[64];
} EdrWindowsEventFilterConfig;

typedef struct {
  uint8_t enabled;
  char version[64];
  uint64_t evaluated;
  uint64_t dropped;
  uint64_t agent_internal_forensic;
  uint64_t low_value_file_process;
  uint64_t low_value_file_suffix;
  uint64_t temp_xml;
  char last_drop_reason[96];
  char last_drop_process[96];
  char last_drop_path[256];
  char last_drop_cmdline[256];
} EdrWindowsEventFilterStatus;

/** Configure the lightweight endpoint-side file/registry slimming policy. */
void edr_windows_event_policy_configure(const EdrWindowsEventFilterConfig *cfg);

/** Snapshot counters for health reporting. */
void edr_windows_event_policy_get_status(EdrWindowsEventFilterStatus *out);

void edr_windows_event_policy_evaluate(const EdrBehaviorRecord *r,
                                       EdrWindowsEventPolicy *out);

/** Add policy tags to the behavior record and adjust priority for high-value Windows events. */
void edr_windows_event_policy_apply(EdrBehaviorRecord *r);

/** Return 0 for ordinary Windows file/registry noise that should not be sent upstream. */
int edr_windows_event_policy_should_emit(const EdrBehaviorRecord *r);

/** Return 0 for ordinary Windows file/registry noise that should stay ring-only. */
int edr_windows_event_policy_should_persist(const EdrBehaviorRecord *r);

#endif
