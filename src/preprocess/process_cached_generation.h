#ifndef EDR_PROCESS_CACHED_GENERATION_H
#define EDR_PROCESS_CACHED_GENERATION_H

#include "edr/behavior_record.h"
#include "edr/process_generation.h"
#include "edr/process_tree_cache.h"
#include <stdio.h>
#include <string.h>

static inline int p0_command_line_is_cached_preview(const EdrBehaviorRecord *br) {
  return br->cmdline[0] && edr_behavior_source_field_truncated(br, "source.cmdline") &&
      (strcmp(br->command_line_origin, "collector_pid_cache_preview") == 0 ||
       strcmp(br->command_line_origin, "process_tree_cache_generation") == 0);
}

/* Call only after proving the fact belongs to this event's process lifetime.
 * Shared by retained-history and same-handle live-query paths, so a nonempty
 * preview cannot block one of them. Direct/conflicting facts are preserved. */
static inline int p0_adopt_generation_command_fact(EdrBehaviorRecord *br,
    const char *fact, int fact_truncated, const char *origin) {
  size_t current_len = strlen(br->cmdline);
  size_t fact_len = strlen(fact);
  if (!fact_len || fact_len >= sizeof(br->cmdline)) return 0;
  if (current_len && (!p0_command_line_is_cached_preview(br) ||
      fact_len < current_len || memcmp(fact, br->cmdline, current_len) != 0)) return 0;
  memcpy(br->cmdline, fact, fact_len + 1u);
  snprintf(br->command_line_origin, sizeof(br->command_line_origin), "%s", origin);
  if (fact_truncated) edr_behavior_mark_source_truncated(br, "source.cmdline");
  else edr_behavior_resolve_source_truncated(br, "source.cmdline");
  return 1;
}

/* Shared by live-query fallback and best-effort retention. This operation
 * performs no OS query and cannot assert a FileRead capability failure.
 * A source tuple, when present, must agree with the historical lifetime. */
static inline int p0_bind_file_read_cached_generation(EdrBehaviorRecord *br,
                                                      uint64_t source_start_key,
                                                      uint64_t source_creation) {
  ProcessTreeEntry snapshot;
  uint64_t event_unix_ns;
  int snapshot_result;
  const char *name;
  if (!edr_behavior_has_process_actor(br) || br->type == EDR_EVENT_PROCESS_CREATE ||
      !br->pid || br->event_time_ns <= 0) return 0;
  event_unix_ns = (uint64_t)br->event_time_ns;
  memset(&snapshot, 0, sizeof(snapshot));
  snapshot_result = source_start_key
      ? edr_pt_cache_snapshot_generation_at(br->pid, source_start_key, event_unix_ns, &snapshot)
      : edr_pt_cache_snapshot_at(br->pid, event_unix_ns, &snapshot);
  if (snapshot_result != 0 ||
      !snapshot.process_start_key || !snapshot.creation_filetime_100ns ||
      !snapshot.start_time_ns || !snapshot.exe_path[0] ||
      (snapshot.source_truncation_mask & EDR_PTC_SOURCE_TRUNC_EXE_PATH) ||
      (source_start_key && source_start_key != snapshot.process_start_key) ||
      (source_creation && source_creation != snapshot.creation_filetime_100ns)) return 0;
  if (!edr_process_generation_contains_event(snapshot.creation_filetime_100ns,
                                               event_unix_ns)) return 0;
  if ((br->type == EDR_EVENT_NET_CONNECT || br->type == EDR_EVENT_NET_LISTEN) &&
      !source_start_key && !source_creation && !snapshot.exit_time_ns) {
    /* Preserve the stricter network contract: an open PID interval alone
     * does not independently prove an unattributed network actor. */
    return 0;
  }
  br->process_start_key = snapshot.process_start_key;
  br->process_creation_filetime_100ns = snapshot.creation_filetime_100ns;
  br->ppid = snapshot.ppid;
  snprintf(br->exe_path, sizeof(br->exe_path), "%s", snapshot.exe_path);
  snprintf(br->image_path_canonical, sizeof(br->image_path_canonical), "%s", snapshot.exe_path);
  name = snapshot.process_name;
  if (!name[0]) {
    name = snapshot.exe_path;
    for (const char *p = snapshot.exe_path; *p; ++p)
      if (*p == '\\' || *p == '/') name = p + 1;
  }
  snprintf(br->process_name, sizeof(br->process_name), "%s", name);
  (void)p0_adopt_generation_command_fact(br, snapshot.cmdline,
      (snapshot.source_truncation_mask & EDR_PTC_SOURCE_TRUNC_CMDLINE) != 0u,
      "process_tree_cache_generation");
  if (!br->parent_name[0] && snapshot.parent_name[0])
    snprintf(br->parent_name, sizeof(br->parent_name), "%s", snapshot.parent_name);
  snprintf(br->image_path_resolution_status, sizeof(br->image_path_resolution_status), "%s", "RESOLVED");
  snprintf(br->image_path_resolution_source, sizeof(br->image_path_resolution_source), "%s",
           "process_tree_cache_generation");
  snprintf(br->process_generation_source, sizeof(br->process_generation_source), "%s",
           br->kernel_file_activity ? "file_activity_process_tree_cache_generation"
           : br->type == EDR_EVENT_FILE_READ ? "file_read_process_tree_cache_generation"
                                           : "network_process_tree_cache_generation");
  if (br->type == EDR_EVENT_FILE_READ || br->kernel_file_activity)
    br->file_actor_generation_validated = 1u;
  return 1;
}

#endif
