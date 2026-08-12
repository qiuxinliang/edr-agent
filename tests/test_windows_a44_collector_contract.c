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
  if (!cmake || !collector || !a44 || !tdh) {
    free(cmake);
    free(collector);
    free(a44);
    free(tdh);
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

  free(cmake);
  free(collector);
  free(a44);
  free(tdh);
  return ok ? 0 : 1;
}
