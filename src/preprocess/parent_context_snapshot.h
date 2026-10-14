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
  if (!edr_behavior_parent_pid_usable(record) || !record->pid ||
      record->pid == record->ppid || !record->process_start_key ||
      !record->process_creation_filetime_100ns || !parent || !child_birth_ns ||
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
  edr_behavior_bind_parent_context(record);
  return 1;
}

static inline uint64_t p0_parent_birth_ns(uint64_t filetime) {
  const uint64_t epoch = UINT64_C(116444736000000000);
  return filetime > epoch && filetime - epoch <= UINT64_MAX / 100u
      ? (filetime - epoch) * 100u : 0u;
}

/* Fill only absent/incomplete text from the already proved generation. No
 * current-PID lookup or new lifetime witness is needed to improve metadata. */
static inline void p0_complete_retained_parent_snapshot(EdrBehaviorRecord *r) {
  const int need_path = !r->parent_path[0] ||
      edr_behavior_source_field_truncated(r, "source.parent_path");
  const int need_command = !r->parent_cmdline[0] ||
      edr_behavior_source_field_truncated(r, "source.parent_cmdline");
  ProcessTreeEntry parent;
  if ((!r->parent_name[0] || need_path || need_command) &&
      edr_pt_cache_snapshot_generation_at(r->ppid, r->parent_process_start_key,
          p0_parent_birth_ns(r->parent_process_creation_filetime_100ns), &parent) == 0 &&
      !parent.generation_conflict &&
      parent.creation_filetime_100ns == r->parent_process_creation_filetime_100ns) {
    if (!r->parent_name[0] && parent.process_name[0])
      snprintf(r->parent_name, sizeof(r->parent_name), "%s", parent.process_name);
    if (need_path && parent.exe_path[0] &&
        !(parent.source_truncation_mask & EDR_PTC_SOURCE_TRUNC_EXE_PATH) &&
        strlen(parent.exe_path) < sizeof(r->parent_path)) {
      snprintf(r->parent_path, sizeof(r->parent_path), "%s", parent.exe_path);
      edr_behavior_resolve_source_truncated(r, "source.parent_path");
    }
    if (need_command && parent.cmdline[0] &&
        !(parent.source_truncation_mask & EDR_PTC_SOURCE_TRUNC_CMDLINE) &&
        strlen(parent.cmdline) < sizeof(r->parent_cmdline)) {
      snprintf(r->parent_cmdline, sizeof(r->parent_cmdline), "%s", parent.cmdline);
      edr_behavior_resolve_source_truncated(r, "source.parent_cmdline");
    }
  }
  if (!r->parent_creation_time[0])
    edr_behavior_format_time_ns((int64_t)p0_parent_birth_ns(r->parent_process_creation_filetime_100ns),
        r->parent_creation_time, sizeof(r->parent_creation_time));
  snprintf(r->parent_resolution_status, sizeof(r->parent_resolution_status), "%s",
      r->parent_name[0] && r->parent_path[0] && r->parent_creation_time[0] &&
      !edr_behavior_source_field_truncated(r, "source.parent_path") ? "RESOLVED" : "NOT_EVALUABLE");
}

/* This is the production parent-selection stage. The callback isolates only
 * the Windows live query; all retained-proof and cache decisions are shared
 * with the native behavior tests. Other process enrichment still runs after it. */
static inline int p0_enrich_parent_context(EdrBehaviorRecord *r,
    int (*resolve_live)(EdrBehaviorRecord *, ProcessTreeEntry *)) {
  if (!r) return 0;
  const uint64_t child_birth_ns = p0_parent_birth_ns(r->process_creation_filetime_100ns);
  const int retained = edr_behavior_parent_context_bound(r) && child_birth_ns;
  int conflict = strcmp(r->parent_resolution_source, "parent_generation_conflict") == 0 ||
      strcmp(r->parent_resolution_status, "CONFLICT") == 0;
  ProcessTreeEntry parent;
  int parent_from_live = 0;
  int parent_snapshot = -1;
  if (edr_behavior_parent_pid_usable(r) && r->pid && r->pid != r->ppid &&
      r->process_start_key && child_birth_ns) {
    if (retained) {
      conflict |= edr_pt_cache_parent_binding_conflicts(
          r->pid, r->process_start_key, r->process_creation_filetime_100ns,
          r->ppid, r->parent_process_start_key, r->parent_process_creation_filetime_100ns);
      if (!conflict) {
        p0_complete_retained_parent_snapshot(r);
        return 1;
      }
    }
    if (!conflict)
      parent_snapshot = edr_pt_cache_snapshot_parent_at(r->ppid, child_birth_ns, &parent);
    if (!conflict && (parent_snapshot != 0 || !parent.process_start_key ||
        !parent.creation_filetime_100ns || !parent.start_time_ns) &&
        resolve_live && resolve_live(r, &parent)) {
      parent_snapshot = 0;
      parent_from_live = 1;
    }
    if (!conflict && parent_snapshot == 0 && parent.process_start_key &&
        parent.creation_filetime_100ns)
      conflict = edr_pt_cache_parent_binding_conflicts(
          r->pid, r->process_start_key, r->process_creation_filetime_100ns,
          r->ppid, parent.process_start_key, parent.creation_filetime_100ns);
    if (!conflict && parent_snapshot == 0 &&
        p0_adopt_parent_snapshot(r, &parent, child_birth_ns, parent_from_live))
      return 1;
  }
  edr_behavior_clear_parent_context(r);
  snprintf(r->parent_resolution_source, sizeof(r->parent_resolution_source), "%s",
      conflict ? "parent_generation_conflict" : "parent_generation_unproven");
  snprintf(r->parent_resolution_status, sizeof(r->parent_resolution_status), "%s", "NOT_EVALUABLE");
  return 0;
}

#endif
