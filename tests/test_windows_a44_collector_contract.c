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

static int require_absent(const char *text, const char *needle, const char *message) {
  if (text && !strstr(text, needle)) return 1;
  fprintf(stderr, "FAIL: %s (found %s)\n", message, needle);
  return 0;
}

static int require_before(const char *text, const char *first, const char *second,
                          const char *message) {
  const char *a = text ? strstr(text, first) : NULL;
  const char *b = text ? strstr(text, second) : NULL;
  if (a && b && a < b) return 1;
  fprintf(stderr, "FAIL: %s\n", message);
  return 0;
}

static int require_after(const char *text, const char *first, const char *second,
                         const char *message) {
  const char *a = text ? strstr(text, first) : NULL;
  const char *b = a ? strstr(a, second) : NULL;
  if (a && b && a < b) return 1;
  fprintf(stderr, "FAIL: %s\n", message);
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
  char *direct = read_source(root, "src/preprocess/p0_rule_direct_emit.c");
  char *mapper = read_source(root, "src/preprocess/behavior_from_slot.c");
  char *agent = read_source(root, "src/core/agent.c");
  char *collector_header = read_source(root, "include/edr/collector.h");
  char *event_bus = read_source(root, "src/core/event_bus.c");
  if (!cmake || !collector || !a44 || !tdh || !preprocess || !direct || !mapper || !agent ||
      !collector_header || !event_bus) {
    free(cmake);
    free(collector);
    free(a44);
    free(tdh);
    free(preprocess);
    free(direct);
    free(mapper);
    free(agent);
    free(collector_header);
    free(event_bus);
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
  ok &= require_contains(collector, "edr_collector_decode_mapped_event(event_record, ty, tag, event_ns)",
                         "synchronous callback must use the shared decode path with ETW event time");
  ok &= require_contains(collector, "edr_a44_split_path_start(s_bus)",
                         "A4.4 worker pool must start with the collector");
  ok &= require_contains(collector, "edr_a44_split_path_stop()",
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
  ok &= require_contains(a44, "wait_status != WAIT_OBJECT_0",
                         "A4.4 stop must retain resources when a decoder does not join");
  ok &= require_after(a44, "wait_status != WAIT_OBJECT_0", "free(s_a44_threads);",
                       "A4.4 frees its worker array only after every join succeeds");
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
  ok &= require_contains(collector, "edr_security_target_sid_present(user_sid)",
                         "4688 target SID presence must reject anonymous placeholders");
  ok &= require_contains(collector, "edr_security_target_logon_present(logon_id)",
                         "4688 target logon presence must reject zero placeholders");
  ok &= require_contains(preprocess, "edr_process_create_is_lifecycle_authoritative(br)",
                         "all Security 4688 observations must not overwrite process-tree generation");

  /* Kernel-File Read seam.  These assertions intentionally target the
   * callback boundary that cannot execute on this macOS test host. */
  ok &= require_contains(collector, "EDR_KERNEL_FILE_EVENT_READ 15u",
                         "Kernel-File Read must use the documented Id/Task 15");
  ok &= require_contains(collector, "EDR_ETW_CLIENT_CONTEXT_SYSTEM_TIME 2u",
                         "ETW System Time ClientContext must use the documented WNODE value");
  ok &= require_contains(collector, "EDR_KERNEL_FILE_READ_REQUIRED_KEYWORDS",
                         "Read classification must require FILEIO and READ keywords");
  ok &= require_contains(collector, "edr_kernel_file_read_descriptor",
                         "Read must be task/opcode/keyword classified, not text inferred");
  ok &= require_contains(collector, "edr_tdh_kernel_file_extract_name_binding",
                         "NameCreate must provide a typed FileKey/FileName binding");
  ok &= require_contains(collector, "edr_tdh_kernel_file_extract_file_key",
                         "Read must resolve its typed FileKey");
  ok &= require_contains(collector, "close_event_ns",
                         "Cleanup/Close must retain an event-time upper bound for FileKey reuse");
  ok &= require_contains(collector, "event_ns >= entry->close_event_ns",
                         "a Read at or after Cleanup/Close must not use the old binding");
  ok &= require_contains(collector, "entry->name_event_ns > best_name_event_ns",
                         "FileKey reuse must choose the matching newest event-time binding");
  ok &= require_contains(collector, "edr_collector_file_key_binding_exact",
                         "same-timestamp NameCreate delivery must compare the whole binding");
  ok &= require_contains(collector, "entry->session_epoch != session_epoch",
                         "a FileKey binding must never cross a provider session");
  ok &= require_contains(collector, "read_start_key != entry->process_start_key",
                         "a Read with a different ProcessStartKey must not resolve another actor path");
  ok &= require_absent(collector, "p0_snapshot_epoch",
                       "FileKey path facts must not be bound to a mutable rule epoch");
  ok &= require_contains(collector, "file_read_path_len >= sizeof(interest_event.path)",
                         "FileRead interest matching must reject a truncated canonical path");
  ok &= require_contains(collector, "EDR_COLLECTOR_FILE_KEY_CRITICAL_CACHE 256u",
                         "P0-interest FileKey bindings require a protected cache partition");
  ok &= require_contains(collector,
                         "edr_p0_rule_ir_file_read_path_may_match(canonical_path, NULL)",
                         "NameCreate must classify protected bindings from the active path projection");
  ok &= require_contains(collector, "edr_collector_file_key_cache_alloc_locked(int critical)",
                         "FileKey allocation must distinguish protected and ordinary bindings");
  ok &= require_contains(collector, "s_health.file_read_critical_binding_capacity_exhausted++",
                         "a full protected FileKey range must be observable rather than evicted");
  ok &= require_contains(collector, "if (critical) {\n    s_health.file_read_critical_binding_capacity_exhausted++",
                         "ordinary live bindings must never recycle a protected FileKey range");
  ok &= require_contains(collector_header, "file_read_critical_binding_capacity_exhausted",
                         "collector health must expose protected FileKey capacity exhaustion");
  ok &= require_contains(agent, "critical_binding_capacity_exhausted",
                         "agent health must serialize protected FileKey capacity pressure");
  ok &= require_contains(collector, "edr_collector_file_key_cache_reset(void)",
                         "the provider-session FileKey namespace needs an explicit reset");
  ok &= require_after(collector, "if (!edr_a44_split_path_stop()) {\n    return 0;\n  }",
                       "edr_collector_file_key_cache_reset();\n"
                       "  edr_collector_file_read_metadata_gate_session_reset();",
                       "stop must join A4.4 before clearing FileKey state");
  ok &= require_contains(collector,
                         "wait_status = WaitForSingleObject(s_consumer_thread, 30000);",
                         "collector stop must observe the ETW consumer join result");
  ok &= require_after(collector, "wait_status != WAIT_OBJECT_0",
                       "return 0;",
                       "a failed collector join must retain thread-owned resources");
  ok &= require_before(collector, "edr_collector_file_key_cache_reset();\n  memset(s_device_map",
                       "StartTraceW(&s_session_handle",
                       "start must clear FileKey state before a new ETW session can emit");
  ok &= require_contains(collector, "Keep a failed start from retaining a previous provider-session namespace",
                         "all failed starts must clear FileKey metadata before retry");
  ok &= require_before(collector,
                       "edr_collector_kernel_file_track_metadata(event_record, event_ns)",
                       "if (!edr_map_type_and_tag(event_record, &ty, &tag))",
                       "NameCreate/Cleanup metadata must run before type map and A4.4 queueing");
  ok &= require_contains(collector, "return EDR_KERNEL_FILE_PROVIDER_KEYWORDS;",
                         "Kernel-File must use its bounded provider keyword set");
  ok &= require_contains(collector, "if (is_kernel_process || is_kernel_file)",
                         "Kernel-File must request its own StartKey extended item");
  ok &= require_contains(collector, "params.EnableProperty = EVENT_ENABLE_PROPERTY_PROCESS_START_KEY;",
                         "Kernel-File StartKey must be requested through EnableTraceEx2");
  ok &= require_contains(collector, "s_health.kernel_file_start_key_requested = 1",
                         "Kernel-File StartKey request health must be independent");
  ok &= require_contains(collector, "s_health.kernel_file_start_key_enable_failures++",
                         "Kernel-File StartKey enable failure must be independently visible");
  ok &= require_contains(collector_header, "kernel_file_start_key_requested",
                         "collector health must expose Kernel-File StartKey request state");
  ok &= require_contains(agent, "\\\"kernel_file_start_key\\\":{\\\"requested\\\":%s",
                         "agent health must serialize Kernel-File StartKey state");
  ok &= require_contains(collector, "file_read_generation_unavailable++",
                         "missing File StartKey must be observable and fail closed");
  ok &= require_contains(collector, "file_read_actor_generation_unavailable++",
                         "missing exact actor cache generation must be observable");
  ok &= require_contains(preprocess, "p0_mark_file_read_collector_evidence",
                         "live StartKey validation failures must mark file reads source-only");
  ok &= require_contains(preprocess, "EDR_P0_FILE_READ_REASON_LIVE_GENERATION_UNAVAILABLE",
                         "unavailable live FileRead generations need a typed source-only reason");
  ok &= require_contains(preprocess, "EDR_P0_FILE_READ_REASON_GENERATION_MISMATCH",
                         "mismatched FileRead generations need a typed source-only reason");
  ok &= require_contains(preprocess, "p0_process_collector_evidence_gate(&br)",
                         "collector evidence must bypass generic matching and enforcement");
  ok &= require_contains(collector, "const char **out_gate_reason",
                         "FileKey resolver must surface an attribution-failure reason");
  ok &= require_contains(collector, "edr_collector_file_read_metadata_gate_stage(\n        event_record, timestamp_ns, file_read_key",
                         "unresolved FileReads must stage durable metadata evidence instead of dropping");
  ok &= require_contains(collector, "!entry->pid || !entry->process_start_key || !read_pid || !read_start_key",
                         "NameCreate and Read must both carry nonzero actor generation facts");
  ok &= require_contains(collector, "read_pid != entry->pid || read_start_key != entry->process_start_key",
                         "NameCreate and Read actor generation must be exact");
  ok &= require_contains(preprocess, "br.type == EDR_EVENT_FILE_READ",
                         "preprocess must live-validate the file-read actor generation");
  ok &= require_contains(direct, "br->type == EDR_EVENT_FILE_READ",
                         "direct P0 must gate file reads independently of process creates");
  ok &= require_contains(direct, "etw_start_key_live_telemetry",
                         "direct P0 must require a live StartKey/FILETIME binding");
  ok &= require_contains(mapper, "r->type == EDR_EVENT_FILE_READ ? \"read\" : \"event\"",
                         "typed record mapping must preserve read semantics");
  ok &= require_before(collector, "if (slot->type == EDR_EVENT_FILE_READ) {",
                       "edr_windows_event_policy_apply(&br)",
                       "FileRead IR path projection must retain candidates before Windows noise policy");
  ok &= require_contains(collector, "slot.p0_critical = 1u;",
                         "retained FileRead P0 candidates must use the event-bus critical lane");
  ok &= require_contains(event_bus, "p0_reserved",
                         "event bus must reserve capacity for P0-critical records");
  ok &= require_contains(event_bus, "ordinary_reserve_rejected",
                         "ordinary flood must be observable when it cannot consume the P0 reserve");
  ok &= require_contains(collector, "EDR_P0_FILE_READ_REASON_PAYLOAD_UNAVAILABLE",
                         "empty FileRead TDH payload must be source-only, not silently dropped");
  ok &= require_contains(collector, "EDR_P0_FILE_READ_REASON_EVENT_TIME_UNAVAILABLE",
                         "zero FileRead event time must be source-only, not callback-time substituted");
  ok &= require_contains(collector, "EDR_P0_FILE_READ_REASON_EVENT_BUS_UNAVAILABLE",
                         "exhausted P0 bus reserve must enter the FileRead source-only gate");
  ok &= require_contains(collector, "s_consumer_ready_event = CreateEventW",
                         "collector start must create a consumer readiness handshake");
  ok &= require_before(collector, "WaitForSingleObject(s_consumer_ready_event, 30000)",
                       "edr_collector_file_read_metadata_gate_start_succeeded();",
                       "only a ready OpenTrace consumer may clear the FileRead restart fuse");
  ok &= require_contains(collector, "file_read_metadata_consumer_open_trace_failed",
                         "OpenTrace failure must leave FileRead capability terminal-unhealthy");
  ok &= require_contains(collector, "file_read_metadata_consumer_terminated",
                         "an early ProcessTrace return must revoke FileRead readiness");
  ok &= require_contains(agent, "edr_collector_file_read_metadata_gate_restart_timeout();",
                         "a collector join timeout must block automatic epoch overlap");
  ok &= require_contains(agent, "if (!edr_collector_stop())",
                         "agent restart must require a complete collector join before a new epoch");

  free(cmake);
  free(collector);
  free(a44);
  free(tdh);
  free(preprocess);
  free(direct);
  free(mapper);
  free(agent);
  free(collector_header);
  free(event_bus);
  return ok ? 0 : 1;
}
