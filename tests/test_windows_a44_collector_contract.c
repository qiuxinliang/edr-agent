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

static int require_contains(const char *text, const char *needle, const char *message) {
  if (text && strstr(text, needle)) return 1;
  fprintf(stderr, "FAIL: %s (missing %s)\n", message, needle);
  return 0;
}

int main(void) {
  const char *root = getenv("EDR_SOURCE_DIR");
  if (!root || !root[0]) root = ".";
  int ok = 1;

  char *cmake = read_source(root, "CMakeLists.txt");
  char *collector = read_source(root, "src/collector/collector_win.c");
  char *a44 = read_source(root, "src/collector/edr_a44_split_path_win.c");
  char *tdh = read_source(root, "src/collector/etw_tdh_win.c");
  char *preprocess = read_source(root, "src/preprocess/preprocess_pipeline.c");
  if (!cmake || !collector || !a44 || !tdh || !preprocess) {
    free(cmake);
    free(collector);
    free(a44);
    free(tdh);
    free(preprocess);
    return 1;
  }

  ok &= require_contains(cmake, "src/collector/etw_observability_win.c",
                         "Windows Agent target must include ETW observability");
  ok &= require_contains(cmake, "src/collector/edr_a44_split_path_win.c",
                         "Windows Agent target must include A4.4 split-path implementation");
  ok &= require_contains(cmake, "src/collector/etw_tdh_win.c",
                         "Windows Agent target must include TDH implementation");
  ok &= require_contains(collector, "void edr_collector_decode_from_a44_item(",
                         "A4.4 worker callback must have a collector decode bridge");
  ok &= require_contains(collector, "edr_a44_item_to_event_record(item, &event_record)",
                         "A4.4 worker must rebuild an owned EVENT_RECORD before decode");
  ok &= require_contains(collector, "edr_collector_decode_mapped_event(event_record, ty, tag, now_ns)",
                         "synchronous callback must use the shared decode path");
  ok &= require_contains(collector, "edr_a44_split_path_start(s_bus)",
                         "A4.4 worker pool must start with the collector");
  ok &= require_contains(collector, "edr_a44_split_path_stop();",
                         "A4.4 worker pool must stop with the collector");
  ok &= require_contains(collector, "edr_a44_note_sync_fallback();",
                         "non-copyable or full-queue records must synchronously fall back");
  ok &= require_contains(a44, "static volatile LONG s_a44_current_depth;",
                         "queue depth must use the same width as its atomic operations");
  ok &= require_contains(a44, "InterlockedExchange(&s_a44_current_depth, (LONG)new_depth)",
                         "queue depth update must not perform a 64-bit write into a 32-bit field");
  ok &= require_contains(a44, "static uint32_t s_a44_queued_count;",
                         "queue state must distinguish full from empty");
  ok &= require_contains(a44, "static CRITICAL_SECTION s_a44_decode_lock;",
                         "parallel A4.4 workers must serialize shared collector state");
  ok &= require_contains(a44, "s_dynamic_config.enabled = 0;",
                         "A4.4 restart paths must reset dynamic-thread lock state after teardown");
  ok &= require_contains(tdh, "void edr_tdh_win_get_property_stats_ext(",
                         "ETW observability extended TDH statistics must be implemented");
  /* Source-contract only: macOS cannot compile the Windows EventLog callback. */
  ok &= require_contains(collector, "static void edr_security_emit_registry_4657(const char *xml)",
                         "4657 must retain a dedicated callback");
  ok &= require_contains(collector, "(void)edr_xml_get_data_utf8(xml, \"SubjectUserName\", user, sizeof(user));",
                         "4657 must preserve Subject actor identity");
  ok &= require_contains(collector, "TargetUserName\", user, sizeof(user));",
                         "4688 must parse Target Subject as effective identity");
  ok &= require_contains(collector, "SubjectUserName\", creator_user, sizeof(creator_user));",
                         "4688 must preserve Subject as creator identity");
  ok &= require_contains(collector, "char creator_user[256];",
                         "4688 creator variables must be declared in collector source");
  ok &= require_contains(collector, "EdrSlotKvResult rp = edr_collector_slot_append_kv",
                         "4688 must use checked atomic ETW1 field appends");
  ok &= require_contains(collector, "security_4688_required_overflow_dropped++",
                         "4688 must drop incomplete required payloads rather than truncate");
  ok &= require_contains(collector, "EDR_SLOT_KV_VALUE_TOO_LONG",
                         "ETW1 append helper must distinguish oversized values");
  ok &= require_contains(collector, "EdrSlotKvResult identity[]",
                         "4688 must append identity fields before image and command fields");
  ok &= require_contains(collector, "security_4688_identity_capacity_omitted_fields",
                         "4688 health must distinguish capacity identity omissions");
  ok &= require_contains(collector, "edr_security_identity_value_present(user_sid)",
                         "4688 identity presence must reject blank and dash placeholders");
  ok &= require_contains(preprocess, "edr_process_create_is_lifecycle_authoritative(br)",
                         "all Security 4688 observations must not overwrite process-tree generation");

  free(cmake);
  free(collector);
  free(a44);
  free(tdh);
  free(preprocess);
  return ok ? 0 : 1;
}
