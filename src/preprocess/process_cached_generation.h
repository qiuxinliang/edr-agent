#ifndef EDR_PROCESS_CACHED_GENERATION_H
#define EDR_PROCESS_CACHED_GENERATION_H

#include "edr/behavior_record.h"
#include "edr/process_generation.h"
#include "edr/process_tree_cache.h"
#include "edr/validation_trace.h"
#include "edr/windows_file_identity.h"
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
static inline int p0_cached_generation_reject(const EdrBehaviorRecord *br,
                                             const char *reason) {
  edr_validation_trace_event(br, "cached_generation", reason);
  return 0;
}

static inline int p0_cached_actor_text_matches(const char *source,
                                              const char *cached) {
#ifdef _WIN32
  return edr_windows_utf8_path_compare_ci(source, cached) ==
      EDR_WINDOWS_UTF8_PATH_COMPARE_MATCH;
#else
  /* Non-Windows fixtures/consumers have no Windows ordinal API. Do not claim
   * its Unicode semantics or normalize a distinct local pathname. */
  return strcmp(source, cached) == 0;
#endif
}

static inline int p0_bind_file_read_cached_generation(EdrBehaviorRecord *br,
                                                      uint64_t source_start_key,
                                                      uint64_t source_creation) {
  ProcessTreeEntry snapshot;
  uint64_t event_unix_ns;
  int snapshot_result;
  const char *name;
  if (!edr_behavior_has_process_actor(br) || br->type == EDR_EVENT_PROCESS_CREATE ||
      !br->pid || br->event_time_ns <= 0)
    return p0_cached_generation_reject(br, "cache_actor_ineligible");
  /* The record may already contain a same-handle live tuple. A fallback must
   * not discard it merely because its caller retained the original empty
   * source tuple, nor may contradictory captures be joined. */
  if ((source_start_key && br->process_start_key &&
       source_start_key != br->process_start_key) ||
      (source_creation && br->process_creation_filetime_100ns &&
       source_creation != br->process_creation_filetime_100ns))
    return p0_cached_generation_reject(br, "cache_generation_mismatch");
  if (!source_start_key) source_start_key = br->process_start_key;
  if (!source_creation) source_creation = br->process_creation_filetime_100ns;
  event_unix_ns = (uint64_t)br->event_time_ns;
  memset(&snapshot, 0, sizeof(snapshot));
  snapshot_result = source_start_key
      ? edr_pt_cache_snapshot_generation_at(br->pid, source_start_key, event_unix_ns, &snapshot)
      : edr_pt_cache_snapshot_at(br->pid, event_unix_ns, &snapshot);
  /* -2 means an existing PID had no eligible key/lifetime, not necessarily
   * a pure timestamp failure. Diagnostics must not invent a narrower cause. */
  if (snapshot_result != 0)
    return p0_cached_generation_reject(br,
        snapshot_result == -2 ? "cache_lookup_rejected" : "cache_miss");
  if (!snapshot.process_start_key || !snapshot.creation_filetime_100ns ||
      !snapshot.start_time_ns)
    return p0_cached_generation_reject(br, "cache_generation_incomplete");
  if (!snapshot.exe_path[0])
    return p0_cached_generation_reject(br, "cache_image_unavailable");
  if (snapshot.source_truncation_mask & EDR_PTC_SOURCE_TRUNC_EXE_PATH)
    return p0_cached_generation_reject(br, "cache_image_truncated");
  if ((source_start_key && source_start_key != snapshot.process_start_key) ||
      (source_creation && source_creation != snapshot.creation_filetime_100ns))
    return p0_cached_generation_reject(br, "cache_generation_mismatch");
  if (!edr_process_generation_contains_event(snapshot.creation_filetime_100ns,
                                               event_unix_ns))
    return p0_cached_generation_reject(br, "cache_event_time_rejected");
  /* Exit bounds may be inferred from a later PID birth, and may omit an
   * intermediate generation. File actor recovery needs its own captured
   * StartKey, not a PID/time inference even when that interval is closed. */
  if ((br->type == EDR_EVENT_FILE_READ || br->kernel_file_activity) && !source_start_key)
    return p0_cached_generation_reject(br, "cache_actor_unproven");
  if ((br->type == EDR_EVENT_NET_CONNECT || br->type == EDR_EVENT_NET_LISTEN) &&
      !source_start_key && !source_creation)
    return p0_cached_generation_reject(br, "cache_network_unproven");
  const char *source_image = br->image_path_canonical[0]
      ? br->image_path_canonical : br->exe_path;
  if ((source_image[0] && !p0_cached_actor_text_matches(source_image, snapshot.exe_path)) ||
      (br->process_name[0] && strncmp(br->process_name, "pid:", 4u) != 0 &&
       snapshot.process_name[0] && !p0_cached_actor_text_matches(
          br->process_name, snapshot.process_name)))
    return p0_cached_generation_reject(br, "cache_actor_identity_mismatch");
  br->process_start_key = snapshot.process_start_key;
  br->process_creation_filetime_100ns = snapshot.creation_filetime_100ns;
  edr_parent_pid_merge(&br->ppid, &br->parent_pid_state,
                       snapshot.ppid, snapshot.parent_pid_state);
  if (br->parent_pid_state == EDR_PARENT_PID_CONFLICT &&
      snapshot.parent_pid_state != EDR_PARENT_PID_CONFLICT) {
    /* Make the owning tree remember the disagreement for this exact lifetime;
     * a later sparse event cannot silently re-enable its cached parent edge. */
    (void)edr_pt_cache_put_generation_with_parent_state(br->pid, snapshot.ppid,
        NULL, NULL, NULL, NULL, snapshot.last_seen_ns, snapshot.process_start_key,
        snapshot.creation_filetime_100ns, 0u, EDR_PARENT_PID_CONFLICT);
  }
  if (br->parent_pid_state == EDR_PARENT_PID_CONFLICT ||
      br->parent_pid_state == EDR_PARENT_PID_INVALID)
    edr_behavior_clear_parent_context(br);
  snprintf(br->exe_path, sizeof(br->exe_path), "%s", snapshot.exe_path);
  snprintf(br->image_path_raw, sizeof(br->image_path_raw), "%s", snapshot.exe_path);
  snprintf(br->image_path_canonical, sizeof(br->image_path_canonical), "%s", snapshot.exe_path);
  snprintf(br->image_path_namespace, sizeof(br->image_path_namespace), "%s",
           edr_windows_image_path_namespace(snapshot.exe_path));
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
  if (edr_behavior_parent_pid_usable(br) && snapshot.parent_pid_state == EDR_PARENT_PID_KNOWN &&
      snapshot.ppid == br->ppid && !br->parent_name[0] && snapshot.parent_name[0])
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
  /* The reason describes the selected cache fact; record state describes the
   * merged result, including a conflict against a known source value. */
  const char *parent_reason = "cache_parent_unknown";
  switch (edr_parent_pid_effective_state(snapshot.ppid, snapshot.parent_pid_state)) {
    case EDR_PARENT_PID_KNOWN: parent_reason = "cache_parent_known"; break;
    case EDR_PARENT_PID_EXPLICIT_ZERO: parent_reason = "cache_parent_explicit_zero"; break;
    case EDR_PARENT_PID_INVALID: parent_reason = "cache_parent_invalid"; break;
    case EDR_PARENT_PID_CONFLICT: parent_reason = "cache_parent_conflict"; break;
    default: break;
  }
  edr_validation_trace_event(br, "cached_generation", parent_reason);
  return 1;
}

#endif
