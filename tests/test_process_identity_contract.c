#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *read_file(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) return NULL;
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return NULL;
  }
  long size = ftell(f);
  if (size < 0) {
    fclose(f);
    return NULL;
  }
  rewind(f);
  char *data = (char *)calloc((size_t)size + 1u, 1u);
  if (!data) {
    fclose(f);
    return NULL;
  }
  if (fread(data, 1u, (size_t)size, f) != (size_t)size) {
    free(data);
    fclose(f);
    return NULL;
  }
  fclose(f);
  return data;
}

static char *read_source(const char *root, const char *relative) {
  char path[1400];
  snprintf(path, sizeof(path), "%s/%s", root, relative);
  char *data = read_file(path);
  if (!data) fprintf(stderr, "FAIL: cannot read %s\n", path);
  return data;
}

static char *slice_between(const char *src, const char *begin, const char *end) {
  const char *first = src ? strstr(src, begin) : NULL;
  if (!first) return NULL;
  const char *last = strstr(first, end);
  if (!last || last <= first) return NULL;
  size_t size = (size_t)(last - first);
  char *slice = (char *)calloc(size + 1u, 1u);
  if (!slice) return NULL;
  memcpy(slice, first, size);
  return slice;
}

static int require_contains(const char *text, const char *needle, const char *message) {
  if (text && strstr(text, needle)) return 1;
  fprintf(stderr, "FAIL: %s (missing %s)\n", message, needle);
  return 0;
}

static int require_absent(const char *text, const char *needle, const char *message) {
  if (!text || !strstr(text, needle)) return 1;
  fprintf(stderr, "FAIL: %s (unexpected %s)\n", message, needle);
  return 0;
}

static int require_before(const char *text, const char *first, const char *second,
                          const char *message) {
  const char *first_pos = text ? strstr(text, first) : NULL;
  const char *second_pos = text ? strstr(text, second) : NULL;
  if (first_pos && second_pos && first_pos < second_pos) return 1;
  fprintf(stderr, "FAIL: %s\n", message);
  return 0;
}

int main(void) {
  const char *root = getenv("EDR_SOURCE_DIR");
  if (!root || !root[0]) root = ".";
  int ok = 1;

  char *collector = read_source(root, "src/collector/collector_win.c");
  char *direct_feed = read_source(root, "src/collector/ave_etw_feed_win.c");
  char *alert_emit = read_source(root, "src/serialize/behavior_alert_emit.c");
  char *agent = read_source(root, "src/core/agent.c");
  if (!collector || !direct_feed || !alert_emit || !agent) {
    free(collector);
    free(direct_feed);
    free(alert_emit);
    free(agent);
    return 1;
  }

  char *callback = slice_between(collector, "static VOID WINAPI edr_event_record_callback(PEVENT_RECORD event_record) {",
                                 "static DWORD WINAPI edr_etw_consumer_thread(");
  char *admission = slice_between(collector, "static int edr_collector_should_admit_slot(EdrEventSlot *slot) {",
                                  "static void edr_collector_decode_mapped_event(");
  char *decode = slice_between(collector,
                               "static void edr_collector_decode_mapped_event(PEVENT_RECORD event_record,",
                               "void edr_collector_decode_from_a44_item(");
  if (!callback || !admission || !decode) {
    fprintf(stderr, "FAIL: cannot isolate collector lifecycle functions\n");
    ok = 0;
  }

  ok &= require_contains(callback, "edr_collector_decode_mapped_event(event_record, ty, tag, now_ns)",
                         "callback must send mapped events through the shared decode path");
  ok &= require_contains(decode, "edr_tdh_build_sensor_interest_event",
                         "terminate handling must use the TDH-parsed target PID");
  ok &= require_contains(decode, "edr_pt_cache_mark_exit(interest_event.pid, exit_time_ns)",
                         "terminate handling must mark the process-tree generation exited");
  ok &= require_contains(decode, "AVE_NotifyProcessExit(interest_event.pid)",
                         "terminate handling must notify AVE history from the collector path");
  ok &= require_before(decode, "edr_pt_cache_mark_exit(interest_event.pid, exit_time_ns)",
                       "edr_sensor_interest_should_admit(&interest_event)",
                       "terminate lifecycle marking must happen before sensor-interest filtering");

  ok &= require_contains(admission, "if (slot->type != EDR_EVENT_PROCESS_CREATE)",
                         "process-create admission must have a distinct identity path");
  ok &= require_before(admission, "if (slot->type != EDR_EVENT_PROCESS_CREATE)",
                       "edr_collector_pid_cache_enrich(&br)",
                       "collector cache enrichment must remain guarded for non-create events");
  ok &= require_absent(admission,
                       "if (slot->type == EDR_EVENT_PROCESS_CREATE) {\n    edr_collector_pid_cache_enrich(&br);",
                       "process-create must never inherit identity from a prior PID generation");

  ok &= require_contains(direct_feed, "if (ty == EDR_EVENT_PROCESS_TERMINATE)",
                         "direct ETW feed must bypass terminate events");
  ok &= require_absent(direct_feed, "AVE_NotifyProcessExit(",
                       "direct ETW feed must not duplicate collector exit notifications");
  ok &= require_absent(direct_feed, "edr_pt_cache_mark_exit(",
                       "direct ETW feed must not own process-tree lifecycle state");

  ok &= require_contains(alert_emit,
                         "edr_pt_cache_snapshot_at(alert->pid, event_time_ns, &snapshot)",
                         "alert enrichment must validate snapshots at the source event time");
  ok &= require_contains(alert_emit,
                         "alert->timestamp_ns > 0 ? (uint64_t)alert->timestamp_ns : 0u",
                         "alert enrichment must pass the original alert timestamp");

  static const char *health_keys[] = {
      "\\\"missing_create\\\"", "\\\"collector_cache_hits\\\"",
      "\\\"collector_cache_misses\\\"", "\\\"snapshot_hits\\\"",
      "\\\"snapshot_misses\\\"", "\\\"snapshot_rejects\\\"",
      "\\\"cache_put_rejects\\\"", "\\\"cache_exits\\\"",
      "\\\"parent_attempts\\\"", "\\\"parent_access_denied\\\"",
      "\\\"parent_exited\\\"", "\\\"parent_other_failed\\\"",
  };
  for (size_t i = 0; i < sizeof(health_keys) / sizeof(health_keys[0]); i++) {
    ok &= require_contains(agent, health_keys[i],
                           "engine health must expose process identity quality counters");
  }
  ok &= require_contains(agent, "edr_parent_enrichment_get_metrics(&parent_metrics)",
                         "engine health must snapshot parent-enrichment metrics");
  ok &= require_contains(agent, "edr_pt_cache_get_metrics(&process_cache_metrics)",
                         "engine health must snapshot process-tree cache metrics");

  free(callback);
  free(admission);
  free(decode);
  free(collector);
  free(direct_feed);
  free(alert_emit);
  free(agent);
  return ok ? 0 : 1;
}
