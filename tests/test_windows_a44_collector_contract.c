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

static int require_order_in_function(const char *text, const char *function_start,
                                     const char *function_end, const char *first,
                                     const char *second, const char *message) {
  const char *start = text ? strstr(text, function_start) : NULL;
  const char *end = start ? strstr(start, function_end) : NULL;
  const char *a = start ? strstr(start, first) : NULL;
  const char *b = start ? strstr(start, second) : NULL;
  if (start && end && a && b && a < end && b < end && a < b) return 1;
  fprintf(stderr, "FAIL: %s\n", message);
  return 0;
}

static int require_absent_in_function(const char *text, const char *function_start,
                                      const char *function_end, const char *needle,
                                      const char *message) {
  const char *start = text ? strstr(text, function_start) : NULL;
  const char *end = start ? strstr(start, function_end) : NULL;
  const char *match = start ? strstr(start, needle) : NULL;
  if (start && end && (!match || match >= end)) return 1;
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
  char *cached_generation = read_source(root, "src/preprocess/process_cached_generation.h");
  char *direct = read_source(root, "src/preprocess/p0_rule_direct_emit.c");
  char *mapper = read_source(root, "src/preprocess/behavior_from_slot.c");
  char *agent = read_source(root, "src/core/agent.c");
  char *collector_header = read_source(root, "include/edr/collector.h");
  char *event_bus = read_source(root, "src/core/event_bus.c");
  if (!cmake || !collector || !a44 || !tdh || !preprocess || !direct || !mapper || !agent ||
      !collector_header || !event_bus || !cached_generation) {
    free(cmake);
    free(collector);
    free(a44);
    free(tdh);
    free(preprocess);
    free(cached_generation);
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
  ok &= require_contains(cmake, "src/preprocess/process_generation.c",
                         "Windows Agent target must link native process-generation helpers");
  ok &= require_before(cmake, "src/preprocess/process_generation.c",
                       "src/collector/collector_win.c",
                       "collector and process-generation helper must share EDR_AGENT_SOURCES");
  ok &= require_contains(cmake, "add_executable(edr_agent ${EDR_AGENT_SOURCES})",
                         "the Windows product must link the complete authoritative source list");
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
  ok &= require_contains(a44,
                         "ty == EDR_EVENT_PROCESS_CREATE || r->ExtendedDataCount != 0",
                         "ProcessCreate must bypass ordinary A4.4 latency for live generation checks");
  ok &= require_contains(a44,
                         "valid sub-second processes to lose",
                         "A4.4 must document the short-lived ProcessCreate race");
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
  ok &= require_contains(collector, "cmd_status = edr_security_xml_get_data_utf8",
                         "4688 must retain the bounded XML extraction status");
  ok &= require_contains(collector, "cmd_status == EDR_SECURITY_XML_TEXT_TRUNCATED",
                         "4688 must distinguish a source-truncated command prefix");
  ok &= require_contains(collector, "\"source_truncated_fields\", \"source.cmdline\"",
                         "4688 must name a command omitted at the source boundary");
  ok &= require_contains(collector, "EdrSlotKvResult identity[]",
                         "4688 must append identity fields before image and command fields");
  ok &= require_before(collector, "EdrSlotKvResult optional[]", "EdrSlotKvResult rc =",
                       "4688 must reserve integrity and elevation before bounded command text");
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
  ok &= require_contains(collector, "EDR_KERNEL_FILE_EVENT_WRITE 16u",
                         "Write must use the documented descriptor, not localized task text");
  ok &= require_contains(collector, "edr_kernel_file_write_descriptor(descriptor)",
                         "Write must share the typed FileKey lifetime resolver");
  ok &= require_contains(collector,
                         "Only the typed CreateNewFile notification is exposed",
                         "ordinary Kernel File/Create opens must remain metadata-only");
  ok &= require_contains(collector, "edr_kernel_file_descriptor_is_create_new(",
                         "collector must consume the tested descriptor classifier");
  ok &= require_contains(collector,
                         "edr_kernel_file_create_descriptor(descriptor) ||\n                descriptor->Id == 18u",
                         "localized fallback must not reclassify ordinary Create opens");
  ok &= require_absent(tdh, "{L\"FileObject\", \"file\"}",
                       "opaque FileObject must never be decoded as a path");
  ok &= require_contains(collector, "if (is_read) edr_collector_file_read_metadata_gate_note_resolved();",
                         "Write must not clear a pending FileRead recovery gate");
  ok &= require_contains(collector, "file_write_payload_incomplete++",
                         "incomplete FileWrite evidence must have a diagnostic counter");
  ok &= require_contains(preprocess, "else if (br.kernel_file_activity)",
                         "all kernel file mutations and Create baselines must bind their event-time actor");
  ok &= require_contains(mapper, "r->kernel_file_activity = is_file_activity_event(slot->type)",
                         "kernel file identity boundary must include every counted file activity");
  ok &= require_order_in_function(preprocess, "static void process_one_record(EdrBehaviorRecord br, const EdrEventSlot *slot) {",
      "static void process_ready_record(EdrBehaviorRecord br, const EdrEventSlot *slot) {",
      "edr_local_evidence_cache_enrich_behavior(&br)", "edr_behavior_enrich_file_activity(&br)",
      "ransomware counters must run after generation-bound actor enrichment");
  ok &= require_contains(collector, "edr_tdh_kernel_file_extract_name_binding",
                         "NameCreate must provide a typed FileKey/FileName binding");
  ok &= require_order_in_function(
      collector, "static VOID WINAPI edr_event_record_callback(",
      "static DWORD WINAPI edr_etw_consumer_thread(",
      "edr_collector_kernel_file_track_metadata(event_record, event_ns)",
      "if (!edr_collector_keep_agent_self_events()",
      "provider-wide name metadata must precede Agent self-event filtering");
  ok &= require_order_in_function(
      collector, "static VOID WINAPI edr_event_record_callback(",
      "static DWORD WINAPI edr_etw_consumer_thread(",
      "edr_collector_kernel_file_track_metadata(event_record, event_ns)",
      "edr_agent_self_fuse_should_drop_event",
      "self-fuse must not drop shared FileKey NameDelete or NameCreate");
  ok &= require_contains(collector, "edr_tdh_kernel_file_extract_file_key",
                         "Read must resolve its typed FileKey");
  ok &= require_contains(collector, "name_end_event_ns",
                         "NameDelete and a newer name must retain an event-time upper bound");
  ok &= require_contains(collector, "other->name_end_event_ns = edr_file_key_lifetime_end(",
                         "a newer name must bound older history before its own history expires");
  ok &= require_contains(collector, "entry->name_end_event_ns = edr_file_key_lifetime_end(",
                         "a late older NameCreate must also be bounded by newer history");
  ok &= require_contains(collector, "edr_file_key_lifetime_contains(entry->name_event_ns",
                         "a Read at or after NameDelete must not use the old binding");
  ok &= require_contains(collector, "EDR_KERNEL_FILE_EVENT_NAME_DELETE 11u",
                         "name invalidation must use NameDelete, not another handle's Close");
  ok &= require_absent(collector, "edr_kernel_file_cleanup_or_close_descriptor",
                       "individual FileObject closure must not invalidate a shared FileKey name");
  ok &= require_order_in_function(
      collector, "static int edr_collector_kernel_file_io_resolve(",
      "static int edr_collector_append_file_io_binding(",
      "edr_file_key_lifetime_is_newer(entry->name_event_ns",
      "edr_file_key_lifetime_contains(entry->name_event_ns",
      "FileKey reuse must select the newest name before rejecting its closed lifetime");
  ok &= require_contains(collector, "edr_collector_file_key_binding_exact",
                         "same-timestamp NameCreate delivery must compare the whole binding");
  ok &= require_contains(collector, "edr_collector_file_read_metadata_gate_note_resolved",
                         "a complete post-reset FileKey binding must restore FileRead health");
  ok &= require_order_in_function(
      collector, "static void edr_collector_decode_mapped_event(",
      "static VOID WINAPI edr_event_record_callback(",
      "edr_collector_kernel_file_io_resolve(",
      "if (ty == EDR_EVENT_FILE_READ && !edr_collector_file_read_p0_capability_healthy())",
      "decode must resolve an exact FileKey NameCreate binding before observing gate state");
  ok &= require_contains(collector,
      "Preprocess retains matched snapshots",
      "resolved FileReads must be retained through live actor capture while the gate waits");
  ok &= require_absent(collector,
      "s_health.file_read_metadata_gate_paused_events++;\n    ReleaseSRWLockExclusive(&s_file_read_metadata_gate_lock);\n    return;\n  }\n  if (ty",
      "resolved FileReads must not disappear in the collector pending-gate branch");
  ok &= require_contains(preprocess, "edr_windows_process_image_path_utf8(process, actor_path",
      "FileRead actor path must be queried from the same validated live handle");
  ok &= require_order_in_function(preprocess,
      "if (br.type == EDR_EVENT_FILE_READ && !p0_file_read_evaluation_ready())",
      "static void process_ready_record(EdrBehaviorRecord br, const EdrEventSlot *slot) {",
      "edr_p0_rule_ir_file_read_path_may_match", "edr_p0_rule_try_emit(&br)",
      "gated FileReads must reach the P0 durable owner after signed path interest");
  ok &= require_contains(direct, "edr_storage_queue_p0_deferred_retain",
      "gated FileRead matches need restart-safe snapshot ownership");
  ok &= require_order_in_function(
      preprocess, "} else if (br.type == EDR_EVENT_FILE_READ) {",
      "static DWORD WINAPI preprocess_main(",
      "edr_p0_rule_ir_file_read_path_may_match(br.file_path, NULL)",
      "p0_bind_process_generation(&br)",
      "proven unrelated FileReads must be excluded before live actor failure can latch P0");
  ok &= require_order_in_function(
      preprocess, "static void process_one_slot(", "static DWORD WINAPI preprocess_main(",
      "if (br.collector_evidence_gate[0])", "\"verified_path_miss\"",
      "path filtering must never discard an existing collector failure assertion");
  ok &= require_contains(preprocess, "edr_p0_rule_source_only_capability_healthy_for_event(EDR_EVENT_FILE_READ",
      "deferred FileReads must also wait for the durable event-family gate");
  ok &= require_absent(preprocess, "edr_file_read_deferred_push",
      "gated reads must not depend on the superseded volatile TTL queue");
  ok &= require_contains(direct, "edr_collector_file_read_p0_capability_healthy()",
      "durable FileRead delivery must retain the independent collector gate");
  ok &= require_order_in_function(direct,
      "int edr_p0_rule_poll_deferred_match(void)", "static int p0_is_ruleset_evaluation_event",
      "p0_delivery_gate_reason(record->type)", "emit_for_rule(record",
      "durable replay must check both delivery gates before emitting or acting");
  ok &= require_absent_in_function(
      collector, "static VOID WINAPI edr_event_record_callback(",
      "static DWORD WINAPI edr_etw_consumer_thread(",
      "edr_collector_file_read_p0_capability_healthy()",
      "callback must delegate pending FileRead gate enforcement to decode after resolution");
  ok &= require_contains(collector, "post_reset_binding_observed",
                         "a bound Read during a pending post-reset gate must be retained as recovery evidence");
  ok &= require_contains(collector,
                         "s_file_read_metadata_gate.recovery_deadline_ns != 0u &&",
                         "only an active bounded post-reset recovery may suppress another epoch reset");
  ok &= require_contains(collector,
                         "int post_reset_recovery =",
                         "normal startup binding must not be counted as post-reset recovery evidence");
  ok &= require_contains(collector,
                         "file_read_metadata_post_reset_exact_binding_pending",
                         "post-reset recovery must remain pending until an exact binding arrives");
  ok &= require_contains(collector,
                         "file_read_metadata_post_reset_exact_binding_timeout",
                         "post-reset recovery must end in an explicit bounded terminal state");
  ok &= require_contains(collector,
                         "recovery_observe_locked(\"result\", \"timeout\")",
                         "post-reset recovery timeout must use the stable lifecycle observation");
  ok &= require_absent_in_function(
      collector, "static void edr_collector_file_read_metadata_gate_stage(",
      "void edr_collector_file_read_metadata_gate_retry(void)",
      "reason_requires_session_reset",
      "no per-binding FileRead disposition may classify itself as a provider restart");
  ok &= require_contains(
      collector, "s_file_read_metadata_gate.requires_session_reset = 0u;",
      "per-binding FileRead dispositions must explicitly leave provider restart disabled");
  ok &= require_contains(collector,
                         "ambiguous ? EDR_P0_FILE_READ_REASON_FILE_KEY_AMBIGUOUS",
                         "same-time FileKey ambiguity must have a distinct local disposition");
  ok &= require_contains(
      collector, "edr_collector_file_key_cache_invalidate_locked(file_key);",
      "a conflicting FileKey must be quarantined while the cache lock is still held");
  ok &= require_contains(collector,
                         "EDR_P0_FILE_READ_REASON_CRITICAL_BINDING_CAPACITY",
                         "protected cache exhaustion must have a distinct capacity disposition");
  ok &= require_contains(collector_header, "file_read_file_key_ambiguities",
                         "FileKey ambiguity must be independently observable");
  ok &= require_contains(collector_header, "file_read_metadata_gate_recovery_episodes",
                         "provider recovery episodes must survive healthy-state resets");
  ok &= require_contains(
      collector, "!s_file_read_metadata_gate.capacity_recovery_pending",
      "an unrelated cached Read must not claim that protected binding capacity recovered");
  ok &= require_contains(
      collector, "if (critical && allocated) {",
      "protected capacity recovery must require a successful new critical binding allocation");
  ok &= require_contains(
      collector, "edr_collector_file_read_metadata_gate_note_capacity_recovered();",
      "successful protected allocation must clear the capacity degradation");
  ok &= require_contains(collector_header,
                         "file_read_metadata_gate_post_reset_recovery_failures",
                         "collector health must expose post-reset exact-binding recovery failures");
  ok &= require_contains(agent, "post_reset_recovery",
                         "agent health must serialize post-reset FileRead recovery evidence");
  ok &= require_contains(collector, "file-read-metadata-coalesce-v1",
                         "repeated unresolved reads must share one epoch-scoped capability fact");
  ok &= require_contains(collector_header, "file_read_metadata_gate_coalesced",
                         "coalesced FileRead capability facts must be observable");
  ok &= require_contains(agent, "\\\"coalesced\\\":%llu",
                         "engine health must expose FileRead gate coalescing");
  ok &= require_order_in_function(
      collector, "static void edr_collector_file_read_metadata_gate_stage(",
      "void edr_collector_file_read_metadata_gate_retry(void)",
      "edr_collector_file_read_metadata_gate_coalesce_locked(coalesce_sha256)",
      "s_file_read_metadata_gate.state != EDR_FILE_READ_METADATA_GATE_HEALTHY",
      "same-subject FileRead failures must coalesce before the single-slot pending gate");
  ok &= require_order_in_function(
      collector, "static void edr_collector_file_read_metadata_gate_stage(",
      "void edr_collector_file_read_metadata_gate_retry(void)",
      "s_file_read_metadata_gate.state != EDR_FILE_READ_METADATA_GATE_HEALTHY",
      "edr_collector_file_read_metadata_gate_remember_locked(coalesce_sha256)",
      "a distinct FileRead failure must be remembered only after the gate accepts it");
  ok &= require_contains(agent, "\\\"write_budget\\\":{\\\"used\\\":%u",
                         "compact acceptance health must expose evidence-cache rate admission loss");
  ok &= require_contains(agent, "\\\"scope\\\":\\\"context_only\\\"",
                         "compact acceptance health must identify the minute budget as context-only");
  ok &= require_contains(agent, "\\\"candidate\\\":{\\\"mode\\\":\\\"exempt\\\"",
                         "compact acceptance health must expose P0 candidate soft-budget exemption");
  ok &= require_contains(agent, "\\\"critical_context\\\":{\\\"mode\\\":\\\"capacity_bound\\\",\\\"used\\\":%u",
                         "compact acceptance health must distinguish capacity-bound critical context from a minute quota");
  ok &= require_contains(agent, "\\\"ordinary_context\\\":{\\\"used\\\":%u",
                         "compact acceptance health must expose ordinary FileRead shedding");
  ok &= require_contains(collector, "edr_collector_file_read_metadata_gate_session_starting();",
                         "every new FileKey provider epoch must begin in degraded attribution mode");
  ok &= require_contains(collector, "file_read_metadata_new_session_degraded",
                         "initial FileRead health must expose missing pre-session handle names");
  ok &= require_contains(tdh, "&out_event->process_start_key",
                         "interest filtering must carry the Kernel-Process target generation");
  ok &= require_contains(collector,
                         "edr_agent_self_pid_seen(ev->pid, ev->process_start_key, now)",
                         "interest self-noise filtering must reject PID-only ancestry matches");
  ok &= require_contains(collector, "This is a metadata-only NameCreate, not an attributed Read",
                         "metadata-only schema misses must not globally fuse FileRead");
  ok &= require_contains(collector, "edr_collector_file_key_cache_invalidate(file_key)",
                         "a malformed metadata binding must invalidate any reused FileKey");
  ok &= require_contains(collector, "edr_collector_file_key_cache_invalidate(0u)",
                         "an unidentifiable NameDelete must invalidate the logical FileKey epoch");
  ok &= require_contains(collector, "raw[prefix_len] != '\\\\'",
                         "device-volume mapping must enforce a path-component boundary");
  ok &= require_contains(collector, "entry->session_epoch != session_epoch",
                         "a FileKey binding must never cross a provider session");
  ok &= require_absent(collector, "read_start_key != entry->process_start_key",
                       "NameCreate must not bind a later Read to the metadata event actor");
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
  ok &= require_before(collector,
                       "edr_collector_file_key_cache_reset();\n"
                       "  edr_collector_file_read_metadata_gate_session_starting();",
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
  ok &= require_contains(collector, "return EDR_KERNEL_PROCESS_PROVIDER_KEYWORDS;",
                         "Kernel-Process must request only process and image keyword classes");
  ok &= require_contains(collector, "return EDR_KERNEL_NETWORK_PROVIDER_KEYWORDS;",
                         "Kernel-Network must request its documented IPv4 and IPv6 keyword classes");
  ok &= require_contains(collector, "edr_kernel_network_connection_descriptor(descriptor)",
                         "Kernel-Network connection mapping must use stable manifest descriptors");
  ok &= require_contains(collector, "EDR_KERNEL_NETWORK_EVENT_CONNECT_IPV4 12u",
                         "Kernel-Network IPv4 connect must use its manifest event id");
  ok &= require_contains(collector, "EDR_KERNEL_NETWORK_EVENT_CONNECT_IPV6 28u",
                         "Kernel-Network IPv6 connect must use its manifest event id");
  ok &= require_contains(collector, "edr_kernel_network_inbound_accept_descriptor(descriptor)",
                         "inbound accepts must bypass outbound connection mapping");
  ok &= require_contains(collector, "Connectionaccepted is inbound",
                         "inbound accept direction must remain explicit and fail closed");
  ok &= require_before(collector,
                       "edr_kernel_network_inbound_accept_descriptor(descriptor)",
                       "TdhGetEventInformation(rec, 0u, NULL, NULL, &info_size)",
                       "inbound accepts must be rejected before localized TDH fallback");
  ok &= require_contains(collector, "Kernel-Network provider enable status=%lu",
                         "Kernel-Network provider setup must be observable at runtime");
  ok &= require_contains(collector, "Kernel-Network callback observed event_id=%u task=%u opcode=%u",
                         "the first Kernel-Network callback descriptor must be observable");
  ok &= require_before(collector,
                       "edr_kernel_network_connection_descriptor(descriptor)",
                       "TdhGetEventInformation(rec, 0u, NULL, NULL, &info_size)",
                       "stable network descriptors must be evaluated before localized TDH names");
  ok &= require_contains(collector, "edr_process_generation_query_live(process, &live",
                         "Kernel ProcessStart must capture target generation while the process is live");
  ok &= require_contains(collector,
                         "live.creation_filetime_100ns ==\n"
                         "            process_start.process_creation_filetime_100ns",
                         "live target generation must match the provider creation FILETIME exactly");
  ok &= require_contains(collector, "kernel_process_live_verified",
                         "verified Kernel ProcessStart generation must expose its provenance");
  ok &= require_contains(collector, "edr_process_command_line_query_live(process, command_line",
                         "Kernel ProcessStart must capture command line on the same verified handle");
  ok &= require_contains(collector, "\"live_same_generation\"",
                         "collector command line must retain the existing exact-generation contract");
  ok &= require_contains(collector, "edr_collector_requires_live_process_snapshot(event_record, ty)",
                         "Kernel ProcessStart must bypass queued decode for live handle capture");
  ok &= require_contains(collector, "Kernel ProcessStart is intentionally decoded on the callback thread",
                         "the short-lived process timing boundary must remain explicit");
  ok &= require_order_in_function(
      collector, "static VOID WINAPI edr_event_record_callback(",
      "static DWORD WINAPI edr_etw_consumer_thread(",
      "!edr_collector_requires_live_process_snapshot(event_record, ty)",
      "edr_collector_decode_mapped_event(event_record, ty, tag, event_ns);",
      "ProcessStart must select synchronous decode before the shared decoder runs");
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
  ok &= require_before(
      collector,
      "memcpy(slot.data, \"ETW1\\n\", sizeof(\"ETW1\\n\") - 1u);",
      "edr_collector_slot_append_kv(&slot, \"collector_event_id\", event_id)",
      "synthetic FileRead gate records must carry the ETW1 header before metadata fields");
  ok &= require_contains(collector, "slot.size = (uint32_t)(sizeof(\"ETW1\\n\") - 1u);",
                         "synthetic FileRead gate records must expose their ETW1 header length");
  ok &= require_contains(
      collector,
      "edr_sha256_hex((const uint8_t *)canonical_path, strlen(canonical_path), path_sha256) != 0",
      "successful path commitments must not be mistaken for hash failures");
  ok &= require_contains(
      collector,
      "edr_sha256_hex((const uint8_t *)commitment, (size_t)commitment_len,\n                       commitment_sha256) != 0",
      "successful event-identity commitments must pass the FileRead metadata gate");
  ok &= require_contains(collector, "if (!read_pid)",
                         "the attributed Read must carry an actor PID for live generation binding");
  ok &= require_absent_in_function(
      collector, "static int edr_collector_kernel_file_io_resolve(",
      "static int edr_collector_append_file_io_binding(",
      "if (!read_pid || !read_start_key)",
      "ARM64 FileRead schemas without an extended StartKey must reach live generation binding");
  ok &= require_contains(collector, "NameCreate binds the file object, not the process",
                         "FileKey path identity must be independent from the NameCreate actor");
  ok &= require_contains(preprocess, "br.type == EDR_EVENT_FILE_READ",
                         "preprocess must live-validate the file-read actor generation");
  ok &= require_contains(collector, "EDR_P0_FILE_READ_REASON_PAYLOAD_UNAVAILABLE);",
                         "a bound FileRead that cannot fit its slot must report payload capacity");
  ok &= require_contains(direct, "br->type == EDR_EVENT_FILE_READ",
                         "direct P0 must gate file reads independently of process creates");
  ok &= require_contains(direct, "etw_start_key_live_telemetry",
                         "direct P0 must require a live StartKey/FILETIME binding");
  ok &= require_contains(preprocess, "file_read_pid_event_time_live_telemetry",
                         "FileRead without an extended StartKey must use the timestamp-bound live tuple");
  ok &= require_contains(direct, "file_read_pid_event_time_live_telemetry",
                         "direct P0 must accept the timestamp-bound live FileRead generation");
  ok &= require_contains(cached_generation, "edr_pt_cache_snapshot_at(br->pid, event_unix_ns, &snapshot)",
                         "short-lived FileRead actors must use an event-time process generation snapshot");
  ok &= require_contains(cached_generation, "source_start_key != snapshot.process_start_key",
                         "cached FileRead generations must preserve the source StartKey boundary");
  ok &= require_contains(cached_generation, "source_creation != snapshot.creation_filetime_100ns",
                         "cached FileRead generations must preserve the creation FILETIME boundary");
  ok &= require_contains(cached_generation, "file_read_process_tree_cache_generation",
                         "preprocess must label an exact historical FileRead generation");
  ok &= require_contains(direct, "file_read_process_tree_cache_generation",
                         "direct P0 must accept only the explicit historical FileRead generation source");
  ok &= require_contains(
      preprocess,
      "br->type != EDR_EVENT_PROCESS_CREATE && !edr_p0_rule_ir_br_matches_any(br)",
      "only an authenticated-IR file-event match may reuse bounded actor evidence work");
  ok &= require_contains(mapper, "r->type == EDR_EVENT_FILE_READ ? \"read\" :",
                         "typed record mapping must preserve read semantics");
  ok &= require_contains(mapper, "r->type == EDR_EVENT_FILE_RENAME ? \"rename\" :",
                         "typed record mapping must preserve rename semantics");
  ok &= require_contains(mapper, "r->type == EDR_EVENT_FILE_DELETE ? \"delete\" :",
                         "typed record mapping must preserve delete semantics");
  ok &= require_before(collector, "if (slot->type == EDR_EVENT_FILE_READ) {",
                       "edr_windows_event_policy_apply(&br)",
                       "FileRead IR path projection must retain candidates before Windows noise policy");
  ok &= require_contains(collector, "slot.p0_critical = 1u;",
                         "retained FileRead P0 candidates must use the event-bus critical lane");
  ok &= require_contains(collector,
                         "slot->type == EDR_EVENT_PROCESS_CREATE &&\n"
                         "      edr_collector_valid_process_create_record(&br) &&\n"
                         "      edr_collector_process_is_suspicious(&br)",
                         "short-lived P0-interest processes must use the event-bus critical lane");
  ok &= require_contains(event_bus, "p0_reserved",
                         "event bus must reserve capacity for P0-critical records");
  ok &= require_contains(event_bus, "ordinary_reserve_rejected",
                         "ordinary flood must be observable when it cannot consume the P0 reserve");
  ok &= require_contains(collector, "EDR_P0_FILE_READ_REASON_PAYLOAD_UNAVAILABLE",
                         "empty FileRead TDH payload must be source-only, not silently dropped");
  ok &= require_contains(collector, "edr_collector_build_file_io_slot_payload",
                         "FileRead must reserve payload capacity for authoritative binding fields");
  ok &= require_contains(collector, "size_t plen = is_file_io",
                         "FileRead must use its compact payload path before checked field appends");
  ok &= require_before(collector, "edr_collector_build_file_io_slot_payload(",
                       "edr_collector_append_file_io_binding(&slot",
                       "FileRead base payload must be built before canonical binding append");
  ok &= require_contains(collector, "EDR_P0_FILE_READ_REASON_EVENT_TIME_UNAVAILABLE",
                         "zero FileRead event time must be source-only, not callback-time substituted");
  ok &= require_contains(collector, "EDR_P0_FILE_READ_REASON_EVENT_BUS_UNAVAILABLE",
                         "exhausted P0 bus reserve must enter the FileRead source-only gate");
  ok &= require_contains(collector, "s_consumer_ready_event = CreateEventW",
                         "collector start must create a consumer readiness handshake");
  ok &= require_order_in_function(
      collector, "EdrError edr_collector_start(EdrEventBus *bus, const EdrConfig *cfg) {",
      "int edr_collector_stop(void) {",
      "if (!cfg || !cfg->collection.etw_enabled)",
      "InterlockedCompareExchange(&s_started, 1, 0)",
      "a disabled collector must return before claiming the running lifecycle");
  ok &= require_order_in_function(
      collector, "EdrError edr_collector_start(EdrEventBus *bus, const EdrConfig *cfg) {",
      "int edr_collector_stop(void) {",
      "InterlockedExchange(&s_consumer_open_ok, 0);",
      "s_bus = bus;",
      "a new collector startup must begin with readiness revoked");
  ok &= require_order_in_function(
      collector, "static int edr_collector_file_read_consumer_ready(void) {",
      "static void edr_collector_file_read_metadata_gate_copy_health(",
      "InterlockedCompareExchange(&s_started, 0, 0) == 1",
      "InterlockedCompareExchange(&s_stopping, 0, 0) == 0",
      "an uninitialized, disabled, or stopping collector must not report FileRead healthy");
  ok &= require_order_in_function(
      collector, "static int edr_collector_file_read_consumer_ready(void) {",
      "static void edr_collector_file_read_metadata_gate_copy_health(",
      "InterlockedCompareExchange(&s_consumer_open_ok, 0, 0) == 1",
      "InterlockedCompareExchange(&s_consumer_running, 0, 0) == 1",
      "OpenTrace success and a running consumer are both required for FileRead health");
  ok &= require_contains(
      collector, "if (!edr_collector_file_read_consumer_ready()) {\n    return 0;\n  }",
      "FileRead admission must reject collector startup and terminal lifecycle states");
  ok &= require_contains(
      collector, "return healthy && edr_collector_file_read_consumer_ready();",
      "FileRead admission must recheck collector running state after reading the metadata gate");
  ok &= require_contains(
      collector, "s_file_read_metadata_gate.state == EDR_FILE_READ_METADATA_GATE_HEALTHY &&\n"
                 "      edr_collector_file_read_consumer_ready() ? 1 : 0;",
      "reported FileRead health must include collector running readiness");
  ok &= require_order_in_function(
      collector, "static void edr_collector_file_read_metadata_gate_consumer_unavailable(",
      "static int edr_collector_file_read_metadata_gate_reason_valid(",
      "InterlockedExchange(&s_consumer_running, 0);",
      "AcquireSRWLockExclusive(&s_file_read_metadata_gate_lock);",
      "consumer failure must revoke running readiness before updating gate diagnostics");
  ok &= require_order_in_function(
      collector, "static DWORD WINAPI edr_etw_consumer_thread(void *arg) {",
      "static void edr_stop_named_trace_session(",
      "if (th == INVALID_PROCESSTRACE_HANDLE)",
      "InterlockedExchange(&s_consumer_running, 1);",
      "consumer readiness must only be asserted after OpenTrace succeeds");
  ok &= require_order_in_function(
      collector, "int edr_collector_stop(void) {",
      "int edr_collector_get_health(EdrCollectorHealth *out_health) {",
      "InterlockedExchange(&s_stopping, 1);",
      "ControlTraceW(s_session_handle, g_session_name, &stop, EVENT_TRACE_CONTROL_STOP);",
      "collector stop must revoke health before stopping the ETW session");
  ok &= require_order_in_function(
      collector, "int edr_collector_stop(void) {",
      "int edr_collector_get_health(EdrCollectorHealth *out_health) {",
      "InterlockedExchange(&s_consumer_running, 0);",
      "InterlockedExchange(&s_started, 0);",
      "a joined collector stop must clear consumer readiness before clearing lifecycle ownership");
  ok &= require_before(collector, "WaitForSingleObject(s_consumer_ready_event, 30000)",
                       "edr_collector_file_read_metadata_gate_start_succeeded();",
                       "only a ready OpenTrace consumer may clear the FileRead restart fuse");
  ok &= require_contains(collector, "file_read_metadata_consumer_open_trace_failed",
                         "OpenTrace failure must leave FileRead capability terminal-unhealthy");
  ok &= require_contains(collector, "file_read_metadata_consumer_terminated",
                         "an early ProcessTrace return must revoke FileRead readiness");
  ok &= require_contains(agent, "edr_collector_file_read_metadata_gate_restart_timeout();",
                         "a collector join timeout must block automatic epoch overlap");
  ok &= require_contains(collector,
                         "EDR_FILE_READ_METADATA_MAX_CONSECUTIVE_RESTARTS",
                         "automatic FileRead recovery must have a bounded restart limit");
  ok &= require_contains(collector,
                         "file_read_metadata_epoch_restart_limit_reached",
                         "restart exhaustion must retain an explicit terminal reason");
  ok &= require_contains(agent, "file_read_metadata_recovery",
                         "collector restart logs must identify FileRead recovery");
  ok &= require_contains(collector,
                         "[file_read_metadata_recovery] phase=%s trigger_reason=%s",
                         "FileRead recovery must use one grep-stable observation schema");
  ok &= require_contains(collector,
                         "recovery_result=%s gate_state=%s breaker_state=%s pid=%lu",
                         "recovery observation must expose result, fuse, and affected PID");
  ok &= require_contains(collector, "recovery_event_id",
                         "recovery observation must retain its original source independently of staged events");
  ok &= require_contains(collector, "marker=%s event_id=%s attempt=%u/%u",
                         "recovery observation must correlate marker and source commitment");
  ok &= require_contains(collector, "{\"-Marker\", \"--edr-p0-case\"}",
                         "recovery observation must recognize both live and matrix markers");
  ok &= require_contains(collector,
                         "entry->pid == pid && entry->process_start_key == process_start_key",
                         "recovery marker must require an exact process generation");
  ok &= require_absent_in_function(
      collector, "static void edr_collector_file_read_metadata_recovery_observe_locked(\n"
                 "    const char *phase, const char *result) {",
      "static void edr_collector_file_read_metadata_gate_consumer_unavailable(",
      "cmdline",
      "recovery observation must never log the complete command line");
  ok &= require_contains(collector,
                         "recovery_observe_locked(\"trigger\", \"required\")",
                         "recovery trigger must be observable after durable source commit");
  ok &= require_contains(collector,
                         "recovery_observe_locked(\"start\", \"in_progress\")",
                         "recovery start must be observable with the attempt count");
  ok &= require_contains(collector,
                         "\"result\", \"provider_epoch_started\");",
                         "a ready replacement provider epoch must be observable");
  ok &= require_absent_in_function(
      collector, "static void edr_collector_file_read_metadata_gate_start_succeeded(void) {",
      "static EdrCollectorFileKeyCacheEntry *edr_collector_file_key_cache_alloc_locked(",
      "event_id[0] = '\\0'",
      "provider restart must retain the triggering event commitment until final recovery");
  ok &= require_contains(collector,
                         "recovery_observe_locked(\"result\", \"healthy\")",
                         "an exact post-reset binding must close the recovery observation");
  ok &= require_contains(collector,
                         "\"result\", \"stop_join_timeout\");",
                         "a join timeout must expose the open breaker result");
  ok &= require_contains(collector,
                         "recovery_observe_locked(\"result\", \"blocked\")",
                         "restart exhaustion must expose the open breaker result");
  ok &= require_contains(direct,
                         "[p0_rule_disposition] rule_id=%s disposition=%s reason=%s",
                         "every matched P0 rule must expose one stable final disposition");
  ok &= require_contains(direct,
                         "process_start_key=%llu source_event_id=%s marker=%s",
                         "P0 disposition must join to process generation and durable source evidence");
  ok &= require_contains(direct,
                         "candidate = strncmp(marker, \"P0CASE-\", 7u) == 0 ? marker + 7u : marker",
                         "validation must recognize both embedded and explicit rule markers");
  ok &= require_contains(direct, "return p0_copy_marker_rule_id(candidate",
                         "IR-not-ready observations must retain a bounded canonical rule id");
  ok &= require_contains(direct,
                         "[p0_rule_stage] target_rule=%s stage=%s reason=%s pid=%u",
                         "marked P0 validation must expose the rejecting stage and reason");
  ok &= require_contains(direct, "? \"target_match\" : \"target_no_match\"",
                         "matcher observation must distinguish a tested rule from other matches");
  ok &= require_absent_in_function(
      direct, "static void p0_observe_rule_disposition(",
      "static int emit_for_rule(", "cmdline",
      "P0 disposition observations must never log the complete command line");
  ok &= require_contains(agent, "remote_policy_changed",
                         "collector restart logs must identify policy changes separately");
  ok &= require_contains(agent, "if (!edr_collector_stop())",
                         "agent restart must require a complete collector join before a new epoch");

  free(cmake);
  free(collector);
  free(a44);
  free(tdh);
  free(preprocess);
  free(cached_generation);
  free(direct);
  free(mapper);
  free(agent);
  free(collector_header);
  free(event_bus);
  return ok ? 0 : 1;
}
