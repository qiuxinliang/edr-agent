#ifndef EDR_PARENT_CONTEXT_SNAPSHOT_H
#define EDR_PARENT_CONTEXT_SNAPSHOT_H

#include <stdio.h>
#include <string.h>
#include "edr/behavior_record.h"
#include "edr/process_tree_cache.h"

/* Adopt one proved parent lifetime atomically at the record boundary. The
 * caller owns the native/cache proof; text presence is never that proof. */
static inline int p0_adopt_parent_snapshot(EdrBehaviorRecord *record,
                                            const ProcessTreeEntry *parent,
                                            uint64_t child_birth_ns,
                                            int from_live) {
  if (!edr_behavior_parent_pid_usable(record) || !parent || !child_birth_ns ||
      parent->pid != record->ppid || !parent->process_start_key ||
      !parent->creation_filetime_100ns || !parent->start_time_ns ||
      parent->generation_conflict || parent->start_time_ns > child_birth_ns ||
      parent->creation_filetime_100ns > record->process_creation_filetime_100ns ||
      (parent->exit_time_ns && parent->exit_time_ns < child_birth_ns) ||
      (parent->verified_alive_until_ns < child_birth_ns &&
       !(parent->exit_time_observed && parent->exit_time_ns >= child_birth_ns)))
    return 0;

  edr_behavior_clear_parent_context(record);
  record->parent_process_start_key = parent->process_start_key;
  record->parent_process_creation_filetime_100ns = parent->creation_filetime_100ns;
  snprintf(record->parent_name, sizeof(record->parent_name), "%s", parent->process_name);
  snprintf(record->parent_path, sizeof(record->parent_path), "%s", parent->exe_path);
  snprintf(record->parent_cmdline, sizeof(record->parent_cmdline), "%s", parent->cmdline);
  if ((parent->source_truncation_mask & EDR_PTC_SOURCE_TRUNC_EXE_PATH) ||
      strlen(parent->exe_path) >= sizeof(record->parent_path))
    edr_behavior_mark_source_truncated(record, "source.parent_path");
  if ((parent->source_truncation_mask & EDR_PTC_SOURCE_TRUNC_CMDLINE) ||
      strlen(parent->cmdline) >= sizeof(record->parent_cmdline))
    edr_behavior_mark_source_truncated(record, "source.parent_cmdline");
  edr_behavior_format_time_ns((int64_t)parent->start_time_ns,
      record->parent_creation_time, sizeof(record->parent_creation_time));
  snprintf(record->parent_resolution_source, sizeof(record->parent_resolution_source),
      "%s", from_live ? "live_parent_generation" : "process_tree_cache_verified");
  snprintf(record->parent_resolution_status, sizeof(record->parent_resolution_status),
      "%s", record->parent_name[0] && record->parent_path[0] &&
      record->parent_creation_time[0] &&
      !edr_behavior_source_field_truncated(record, "source.parent_path")
          ? "RESOLVED" : "NOT_EVALUABLE");
  return 1;
}

#endif
