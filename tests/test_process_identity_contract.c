#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"

/* Mirrors the bounded append contract used by the private agent health
 * builder: callers discard a fragment after any failed append. */
static int append_json_fragment(char *dst, size_t capacity, size_t *used,
                                const char *format, ...) {
  va_list args;
  int written;
  if (!dst || !used || !format || capacity == 0u || *used >= capacity) return 0;
  va_start(args, format);
  written = vsnprintf(dst + *used, capacity - *used, format, args);
  va_end(args);
  if (written < 0 || (size_t)written >= capacity - *used) return 0;
  *used += (size_t)written;
  return 1;
}

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

static int need(int value, const char *message) {
  if (value) return 1;
  fprintf(stderr, "FAIL: %s\n", message);
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

static size_t agent_array_capacity(const char *source, const char *name) {
  const char *at;
  char *end = NULL;
  unsigned long parsed;
  if (!source || !name) return 0u;
  at = strstr(source, name);
  if (!at) return 0u;
  at += strlen(name);
  parsed = strtoul(at, &end, 10);
  return end && end != at && *end == ']' ? (size_t)parsed : 0u;
}

int main(void) {
  const char *root = getenv("EDR_SOURCE_DIR");
  if (!root || !root[0]) root = ".";
  int ok = 1;

  char *collector = read_source(root, "src/collector/collector_win.c");
  char *tdh = read_source(root, "src/collector/etw_tdh_win.c");
  char *direct_feed = read_source(root, "src/collector/ave_etw_feed_win.c");
  char *alert_emit = read_source(root, "src/serialize/behavior_alert_emit.c");
  char *agent = read_source(root, "src/core/agent.c");
  char *p0_rule_ir = read_source(root, "src/preprocess/p0_rule_ir.c");
  char *process_cache = read_source(root, "src/forensic/process_tree_cache.c");
  char *evidence_worker = read_source(root, "src/preprocess/process_evidence_worker.c");
  char *evidence_wait = slice_between(
      evidence_worker, "int edr_process_evidence_wait(",
      "void edr_process_evidence_worker_get_metrics(");
  if (!collector || !tdh || !direct_feed || !alert_emit || !agent || !p0_rule_ir ||
      !process_cache || !evidence_worker || !evidence_wait) {
    free(collector);
    free(tdh);
    free(direct_feed);
    free(alert_emit);
    free(agent);
    free(p0_rule_ir);
    free(process_cache);
    free(evidence_worker);
    free(evidence_wait);
    return 1;
  }

  ok &= require_contains(agent, "edr_p0_rule_ir_get_binding(&p0_ir_binding)",
                         "engine health must report the active P0 IR binding");
  ok &= require_contains(agent, "p0_ir_ready ? \"true\" : \"false\"",
                         "engine health must derive P0 enabled state from matcher readiness");
  ok &= require_contains(agent, "p0_ir_ready ? \"\" : \"p0_ir_not_ready\"",
                         "engine health must expose an unavailable P0 matcher as degraded");
  ok &= require_contains(agent, "\\\"preprocessing_rules\\\"",
                         "preprocessing-rule telemetry must not masquerade as P0 IR health");
  ok &= require_absent(agent, "\\\"p0_rule\\\":{\\\"enabled\\\":true",
                       "P0 health must not be reported enabled unconditionally");
  ok &= require_contains(p0_rule_ir, "GENERIC_READ | GENERIC_WRITE",
                         "Windows P0 IR durability flush must use a writable file handle");
  ok &= require_contains(p0_rule_ir, "staged bundle durability sync failed",
                         "Windows P0 IR hot publication failures must expose the Win32 cause");

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

  ok &= require_contains(callback, "edr_collector_decode_mapped_event(event_record, ty, tag, event_ns)",
                         "callback must send mapped events through the shared decode path");
  ok &= require_contains(decode, "edr_tdh_build_sensor_interest_event",
                         "terminate handling must use the TDH-parsed target PID");
  ok &= require_contains(decode,
                         "edr_collector_event_process_start_key(event_record, &exit_start_key)",
                         "terminate handling must capture the ETW ProcessStartKey");
  ok &= require_contains(decode,
                         "edr_pt_cache_mark_exit_generation(interest_event.pid, exit_start_key,",
                         "terminate handling must mark only the exact process-tree generation exited");
  ok &= require_absent(decode, "edr_pt_cache_mark_exit(interest_event.pid",
                          "terminate handling must not close a PID generation by PID alone");
  ok &= require_contains(decode, "AVE_NotifyProcessExit(interest_event.pid)",
                         "terminate handling must notify AVE history from the collector path");
  ok &= require_before(decode, "edr_pt_cache_mark_exit_generation(interest_event.pid, exit_start_key,",
                       "edr_sensor_interest_should_admit(&interest_event)",
                       "terminate lifecycle marking must happen before sensor-interest filtering");

  ok &= require_contains(admission, "if (slot->type == EDR_EVENT_PROCESS_CREATE)",
                         "process-create admission must have a generation-aware identity path");
  ok &= require_before(admission, "edr_collector_pid_cache_enrich(&br)",
                       "edr_collector_pid_cache_update(&br)",
                       "Security 4688 identity must merge before kernel process-create admission");
  ok &= require_contains(collector, "edr_collector_pid_cache_same_generation",
                         "collector PID enrichment must require a process-generation match");
  ok &= require_contains(collector, "edr_collector_event_process_start_key",
                         "collector must read the ETW actor ProcessStartKey extension for file-read binding");
  ok &= require_contains(tdh, "L\"UniqueProcessKey\"",
                         "Kernel-Process TDH must read the target process key from the payload");
  ok &= require_contains(tdh, "process_generation_source=%s",
                         "Kernel-Process TDH must report target-generation availability");
  ok &= require_contains(collector, "if (is_kernel_process)",
                         "Kernel-Process generation handling must have a target-specific branch");
  ok &= require_contains(collector, "Never overwrite it with the event",
                         "the target key must not be replaced by the logging process header key");
  ok &= require_contains(collector, "EVENT_ENABLE_PROPERTY_PROCESS_START_KEY",
                         "collector must request documented ProcessStartKey extended data");
  ok &= require_contains(collector, "EDR_ETW_CLIENT_CONTEXT_SYSTEM_TIME",
                         "collector must configure ETW header timestamps with the documented System Time local constant");
  ok &= require_contains(collector,
                         "prop->Wnode.ClientContext = EDR_ETW_CLIENT_CONTEXT_SYSTEM_TIME",
                         "collector must apply the System Time clock to the ETW session");
  ok &= require_contains(collector, "QueryDosDeviceA",
                         "NT device paths must use the startup device map");
  ok &= require_contains(collector, "NOT_EVALUABLE",
                         "unmapped NT device paths must be explicitly non-evaluable");
  ok &= require_contains(collector, "source_completeness\", \"ENRICHMENT_ONLY",
                         "late Security 4688 must be marked as enrichment-only evidence");
  ok &= require_absent(collector, "pid-%u",
                       "collector must not manufacture a parent name from a PID");

  char *pipeline = read_source(root, "src/preprocess/preprocess_pipeline.c");
  if (!pipeline) {
    ok = 0;
  } else {
    char *token_enrichment = slice_between(
        pipeline, "static int enrich_process_token_identity(EdrBehaviorRecord *br) {", "#endif");
    ok &= require_contains(pipeline, "p0_process_create_not_evaluable_reason",
                           "Windows P0 must classify incomplete process-create evidence before matching");
    ok &= require_contains(pipeline,
                           "edr_p0_rule_emit_pre_evaluation_gate(&br, not_evaluable_reason)",
                           "incomplete process-create evidence must use the production pre-evaluation source-only gate");
    ok &= require_contains(pipeline, "enrich_process_token_identity",
                           "Windows process identity must have a bounded token SID fallback");
    ok &= require_contains(pipeline, "edr_process_generation_query_live",
                           "target generation must be validated against a live target handle");
    ok &= require_contains(pipeline,
                           "edr_process_command_line_query_live(process, br->cmdline",
                           "Kernel ProcessStart must read command line from its validated handle");
    ok &= require_before(pipeline,
                         "edr_process_command_line_query_live(process, br->cmdline",
                         "CloseHandle(process);\n  br->process_start_key = live.process_start_key;",
                         "same-generation command line must be read before closing the validated handle");
    ok &= require_contains(pipeline, "live_same_generation_unavailable",
                           "failed live command-line queries must remain explicit and source-only");
    ok &= require_before(pipeline, "(void)enrich_process_token_identity(&br);",
                         "switch (edr_process_coalescer_submit",
                         "short-lived target token identity must be captured before the 4688 wait");
    ok &= require_contains(
        pipeline,
        "not_evaluable_reason && p0_process_create_candidate(&br) &&\n"
        "        !edr_p0_rule_ir_br_matches_any(&br)",
        "a complete authenticated-IR match must not be suppressed by unrelated short-lived-process enrichment loss");
    ok &= require_contains(pipeline, "LookupAccountSidA",
                           "token fallback must retain username and domain when Windows resolves the SID");
    ok &= require_contains(pipeline, "parent_creation_time",
                           "P0 parent matching must retain a parent generation timestamp");
    ok &= require_contains(pipeline, "missing_parent_generation",
                           "a missing parent generation must use the registered source-only reason");
    ok &= require_contains(pipeline, "p0_resolve_live_parent_generation",
                           "a warmup-only parent must use exact live generation recovery");
    ok &= require_contains(pipeline,
                           "live.creation_filetime_100ns > child->process_creation_filetime_100ns",
                           "a PID reused after child creation must be rejected as its parent");
    ok &= require_contains(pipeline, "observed.QuadPart != live.creation_filetime_100ns",
                           "live parent telemetry and GetProcessTimes must agree on one handle");
    ok &= require_contains(pipeline, "live_parent_generation",
                           "validated parent recovery must expose distinct provenance");
    ok &= require_absent(pipeline, "enrich_parent_info_by_pid(",
                           "P0 parent enrichment must not fall back to a PID-only live lookup");
    ok &= require_contains(pipeline, "edr_pt_cache_put_generation",
                           "authoritative process creates must retain an exact generation history");
    ok &= require_contains(pipeline, "edr_pt_cache_fill_record_at",
                           "parent-chain enrichment must traverse at the source event time");
    ok &= require_contains(pipeline, "parent.process_start_key != 0u",
                           "parent resolution must require the cached ProcessStartKey");
    ok &= require_contains(pipeline, "parent.creation_filetime_100ns != 0u",
                           "parent resolution must require the cached creation FILETIME");
    ok &= require_contains(pipeline, "filetime_100ns_to_unix_ns",
                           "parent generation timestamps must derive from real creation FILETIME");
    ok &= require_contains(pipeline, "post_event_path_snapshot",
                           "post-event process evidence must remain explicitly non-authoritative");
    ok &= require_contains(pipeline, "edr_windows_file_identity_valid(evidence.file_identity)",
                           "only the lossless v1 identity may be artifact-evaluable");
    ok &= require_contains(pipeline, "legacy_file_identity_non_authoritative",
                           "legacy XOR-shaped identity must remain telemetry only");
    ok &= require_contains(pipeline, "\"NOT_EVALUABLE\"",
                           "missing or degraded artifact identity must be explicitly not evaluable");
    ok &= require_absent(pipeline, "return \"file_identity_unavailable\";",
                           "a pathname snapshot must not blanket source-only pure process rules");
    ok &= need(token_enrichment != NULL,
               "cannot isolate the target-4688 live identity validation path");
    if (token_enrichment) {
      /* Raw 4688 Target Subject fields are provenance only.  Snapshot them,
       * clear every displayable identity field, then test completeness and
       * live equality.  This makes incomplete, access-denied, and mismatch
       * paths source-only instead of leaking an unvalidated SID into UI. */
      ok &= require_before(token_enrichment, "snprintf(correlated_target_sid",
                           "br->username[0] = '\\0';",
                           "target-4688 SID must be copied before raw identity is cleared");
      ok &= require_before(token_enrichment, "br->username[0] = '\\0';",
                           "if (!correlated_target_sid[0] || !correlated_target_logon[0])",
                           "target-4688 completeness must run after all raw identity fields are cleared");
      ok &= require_contains(token_enrichment, "br->domain[0] = '\\0';",
                             "target-4688 failure must clear raw domain");
      ok &= require_contains(token_enrichment, "br->user_sid[0] = '\\0';",
                             "target-4688 failure must clear raw SID");
      ok &= require_contains(token_enrichment, "br->logon_id[0] = '\\0';",
                             "target-4688 failure must clear raw logon ID");
      ok &= require_contains(token_enrichment, "target_4688_incomplete",
                             "target-4688 incomplete inputs must be explicitly non-evaluable");
      ok &= require_contains(token_enrichment, "target_4688_live_unavailable",
                             "target-4688 live-query failures must be explicitly non-evaluable");
      ok &= require_contains(token_enrichment, "target_4688_live_mismatch",
                             "target-4688 identity mismatches must be explicitly non-evaluable");
    }
    free(token_enrichment);
    free(pipeline);
  }

  ok &= require_contains(process_cache, "edr_pt_cache_put_generation",
                         "process cache must retain exact StartKey/FILETIME generations");
  ok &= require_contains(process_cache, "edr_pt_cache_mark_exit_generation",
                         "process cache must close only an exact StartKey generation");
  ok &= require_contains(agent, "\\\"p0_acceptance\\\":{",
                         "basic health must expose P0 acceptance counters");
  ok &= require_contains(agent, "\\\"evidence_cache\\\":{\\\"db_open\\\":%s,\\\"utilization_bps\\\":%u",
                         "basic health must expose evidence-cache utilization");
  ok &= require_before(
      agent,
      "\\\"process_evidence_worker\\\":{\\\"slots_used\\\":%u,\\\"capacity\\\":%u",
      "\\\"sensor_health\\\":{",
      "basic P0 acceptance health must expose evidence-worker cache occupancy and reuse metrics");
  ok &= require_contains(agent, "\\\"retry_pending\\\":%llu",
                         "basic health must expose restart-durable source-only backlog");
  ok &= require_contains(process_cache, "pt_get_at_locked",
                         "process cache must select historical generations at source event time");
  ok &= require_contains(process_cache, "Old and new generations intentionally coexist",
                         "PID reuse must retain history for delayed child events");
  ok &= require_contains(process_cache, "Wall-clock observation\n   * is not the process creation generation",
                         "warmup wall-clock data must not masquerade as a creation generation");
  ok &= require_contains(evidence_worker, "EDR_EVIDENCE_HASH_MAX_NS",
                         "evidence hashing needs a budget independent of queue latency");
  ok &= require_contains(evidence_worker, "EDR_EVIDENCE_QUEUE_MAX_NS",
                         "queued evidence jobs need a bounded burst budget");
  ok &= require_contains(evidence_worker, "EDR_EVIDENCE_STALL_NS",
                         "worker stall detection must not reuse the caller wait budget");
  ok &= require_contains(agent, "\\\"wait_timeouts\\\":%llu",
                         "health must distinguish caller evidence wait timeouts");
  ok &= require_contains(agent, "\\\"queue_deadlines\\\":%llu",
                         "health must distinguish expired queued evidence work");
  ok &= require_contains(evidence_worker, "WTD_CACHE_ONLY_URL_RETRIEVAL",
                         "WinVerifyTrust must not add certificate network latency to P0 preprocessing");
  ok &= require_contains(evidence_worker, "Do not reopen the pathname here",
                         "completed short-lived evidence must survive pathname cleanup");
  ok &= require_contains(evidence_wait, "Sleep(wait_ms);",
                         "evidence waiters must poll independently of the work event");
  ok &= require_absent(evidence_wait, "WaitForSingleObject(s_wake",
                       "only the evidence worker may consume the auto-reset work event");
  ok &= require_before(evidence_worker,
                       "if (evidence_find_snapshot_locked(path, generation, now, out, &ready))",
                       "if (!edr_windows_file_identity_open_readonly(path",
                       "generation snapshot retrieval must precede any pathname reopen");
  ok &= require_contains(evidence_worker, "EDR_EVIDENCE_RETAIN_NS",
                         "burst eviction must preserve snapshots through the coalescer window");
  ok &= require_before(pipeline,
                       "if (br.evidence_revision == 0u) br.evidence_revision = 1u;",
                       "switch (edr_process_coalescer_submit",
                       "kernel source needs an initial revision without a 4688 merge");
  ok &= require_contains(
      pipeline,
      "strcmp(requested.hash_reason, \"identity_revalidation_pending\") == 0",
      "preprocess must wait only when the requested file object has work in flight");
  ok &= require_absent(
      pipeline,
      "(void)edr_process_evidence_request(br->image_path_canonical",
      "preprocess must preserve the immediate ready/failed request disposition");

  char *parent_enrichment = read_source(root, "src/preprocess/enrich_parent_info.c");
  if (!parent_enrichment) {
    ok = 0;
  } else {
    ok &= require_absent(parent_enrichment, "pid-%u",
                         "unknown parent processes must remain unnamed");
    free(parent_enrichment);
  }

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
  ok &= require_contains(agent, "\\\"alerts_with_optional_omission\\\"",
                         "engine health must expose the per-alert P0 optional-context omission count");
  ok &= require_absent(agent, "\\\"optional_fields_omitted\\\"",
                       "engine health must not label a per-alert P0 count as fields omitted");
  ok &= require_contains(agent, "\\\"intermediate_upgrade_suppressed\\\"",
                         "engine health must expose non-material P0 identity upgrades separately");
  ok &= require_contains(agent, "\\\"pending_backpressure\\\"",
                         "engine health must expose P0 dedup pending backpressure");
  ok &= require_contains(agent, "\\\"process_create_coalescer\\\"",
                         "engine health must expose ProcessCreate coalescer occupancy and rejection metrics");
  ok &= require_contains(agent, "\\\"process_evidence_worker\\\"",
                         "engine health must expose bounded evidence-worker utilization and backpressure");
  ok &= require_contains(agent, "\\\"ambiguous_rejects\\\"",
                         "engine health must expose ambiguous PID-generation joins rejected for safety");
  ok &= require_contains(agent, "\\\"escape_overflow_values\\\"",
                         "engine health must expose P0 JSON escape-overflow degradation");
  ok &= need(agent_array_capacity(agent, "p0_health_json[") >= 8192u,
             "P0 health metrics must reserve at least 8192 bytes for all counters");
  ok &= require_contains(agent, "edr_agent_append_json_fragment",
                         "P0 health JSON must use checked all-or-nothing appends");
  ok &= require_contains(agent, "if (!p0_health_ok)",
                         "P0 health JSON must be omitted rather than truncated on append failure");
  ok &= require_contains(agent, "\\\"p0_enforcement_terminal_journal\\\"",
                         "engine health must expose durable terminal replay outcomes");
  ok &= require_contains(agent, "\\\"governor_suppressed\\\"",
                         "engine health must expose normal P0 governor suppression separately from queue failure");
  ok &= require_contains(agent, "\\\"outcome_unknown\\\"",
                         "engine health must expose terminal outcomes that cannot be safely replayed");
  ok &= require_contains(agent, "\\\"replay_metadata_corruption_failures\\\"",
                         "engine health must expose durable metadata corruption quarantines");
  ok &= require_contains(agent, "\\\"precreate_metadata_corruption_failures\\\"",
                         "engine health must expose corrupt-owner no-reexecution conflicts");
  ok &= require_contains(agent, "\\\"owner_metadata_unresolved\\\"",
                         "engine health must expose fail-closed legacy owner corruption");
  ok &= require_contains(agent, "\\\"p0_offline_queue_capacity\\\"",
                         "engine health must expose offline queue capacity metrics");
  ok &= require_contains(agent, "\\\"event_queue_metadata_corruption_failures\\\"",
                         "engine health must expose ordinary queue metadata quarantines");
  ok &= require_contains(agent, "\\\"admission_attempts\\\"",
                         "engine health must expose queue admission denominators");

  {
    char fragment[8192];
    char document[8400];
    char too_small[8];
    char p0_bundle_sha[65];
    char p0_artifact_reason[96];
    size_t used = 0u;
    const unsigned long long max = (unsigned long long)UINT64_MAX;
    memset(p0_bundle_sha, 'a', sizeof(p0_bundle_sha) - 1u);
    p0_bundle_sha[sizeof(p0_bundle_sha) - 1u] = '\0';
    memset(p0_artifact_reason, 'r', sizeof(p0_artifact_reason) - 1u);
    p0_artifact_reason[sizeof(p0_artifact_reason) - 1u] = '\0';
    fragment[0] = '\0';
    ok &= append_json_fragment(fragment, sizeof(fragment), &used,
                               ",\"p0_dedup\":{\"suppressed_total\":%llu,\"exact_suppressed\":%llu,\"equal_quality_suppressed\":%llu,\"identity_upgrade_allowed\":%llu,\"lower_quality_suppressed\":%llu,\"intermediate_upgrade_suppressed\":%llu,\"pre_rule_event_duplicates\":%llu,\"pending_backpressure\":%llu}",
                               max, max, max, max, max, max, max, max);
    ok &= append_json_fragment(fragment, sizeof(fragment), &used,
                               ",\"process_create_coalescer\":{\"slots_used\":%u,\"capacity\":%u,\"security_stored\":%llu,\"security_backpressure\":%llu,\"kernel_backpressure\":%llu,\"timeouts\":%llu,\"stale_rejects\":%llu,\"ambiguous_rejects\":%llu}",
                               UINT32_MAX, UINT32_MAX, max, max, max, max, max, max);
    ok &= append_json_fragment(fragment, sizeof(fragment), &used,
                               ",\"process_evidence_worker\":{\"slots_used\":%u,\"capacity\":%u,\"requests_total\":%llu,\"queued\":%llu,\"ready_hits\":%llu,\"pending_reuse\":%llu,\"misses\":%llu,\"backpressure\":%llu,\"evictions\":%llu,\"stale_rejected\":%llu,\"hash_admissions\":%llu,\"hash_attempts\":%llu,\"signature_admissions\":%llu,\"signature_attempts\":%llu,\"wait_timeouts\":%llu,\"queue_deadlines\":%llu,\"shutdown_timeouts\":%llu,\"terminal_unhealthy\":%u,\"worker_stalled\":%u}",
                               UINT32_MAX, UINT32_MAX, max, max, max, max, max, max, max, max,
                               max, max, max, max, max, max, max, UINT32_MAX, UINT32_MAX);
    ok &= append_json_fragment(
        fragment, sizeof(fragment), &used,
        ",\"p0_emit_context\":{\"user_subject_full\":%llu,\"user_subject_degraded\":%llu,\"alerts_with_optional_omission\":%llu,\"values_truncated\":%llu,\"escape_overflow_values\":%llu,\"minimal_failures\":%llu,\"emitted_without_full_context\":%llu}",
        max, max, max, max, max, max, max);
    ok &= append_json_fragment(
        fragment, sizeof(fragment), &used,
        ",\"p0_enforcement_admission\":{\"critical_reservations\":%llu,\"governor_suppressed\":%llu,\"source_only_backpressure_emitted\":%llu,\"source_only_backpressure_failed\":%llu}",
        max, max, max, max);
    ok &= append_json_fragment(
        fragment, sizeof(fragment), &used,
        ",\"p0_source_only_durability\":{\"retry_pending\":%llu,\"retry_attempts\":%llu,\"retry_committed\":%llu,\"retry_capacity_exhausted\":%llu,\"terminal_unhealthy\":true}",
        max, max, max, max);
    ok &= append_json_fragment(fragment, sizeof(fragment), &used,
                               ",\"p0_rule_bundle\":{\"plaintext_sha256\":\"%s\"}", p0_bundle_sha);
    ok &= append_json_fragment(fragment, sizeof(fragment), &used,
                               ",\"p0_artifact_recovery\":{\"healthy\":false,\"reason\":\"%s\"}",
                               p0_artifact_reason);
    ok &= append_json_fragment(fragment, sizeof(fragment), &used,
                               ",\"p0_queue_dead_letter\":%llu", max);
    ok &= append_json_fragment(
        fragment, sizeof(fragment), &used,
        ",\"p0_enforcement_terminal_journal\":{\"pending\":%llu,\"backpressure\":%llu,\"failed\":%llu,\"outcome_unknown\":%llu,\"replay_selection_transient_failures\":%llu,\"replay_metadata_corruption_failures\":%llu,\"precreate_metadata_corruption_failures\":%llu,\"owner_metadata_unresolved\":%llu,\"precreate\":{\"requests\":%llu,\"attempts\":%llu,\"created\":%llu,\"existing\":%llu,\"conflicts\":%llu,\"rejected\":%llu,\"transaction_failures\":%llu,\"commit_failures\":%llu}}",
        max, max, max, max, max, max, max, max, max, max, max, max, max, max, max, max);
    ok &= append_json_fragment(
        fragment, sizeof(fragment), &used,
        ",\"p0_offline_queue_capacity\":{\"used_bytes\":%llu,\"max_bytes\":%llu,\"utilization_bps\":%u,\"ordinary_limit_bytes\":%llu,\"critical_reserve_bytes\":%llu,\"terminal_reserve_bytes\":%llu,\"p0_source_only_reserve_bytes\":%llu,\"ordinary_rejected\":%llu,\"high_priority_rejected\":%llu,\"p0_source_only_rejected\":%llu,\"event_queue_metadata_corruption_failures\":%llu,\"retention_evicted_rows\":%llu,\"pending_rows\":%llu,\"oldest_pending_created_unix_s\":%llu,\"oldest_pending_age_s\":%llu,\"enqueue\":{\"requests\":%llu,\"reused\":%llu,\"conflicts\":%llu,\"admission_attempts\":%llu,\"admitted\":%llu,\"capacity_rejected\":%llu,\"transaction_failures\":%llu,\"commit_failures\":%llu},\"delivery\":{\"selected\":%llu,\"sent\":%llu,\"acked\":%llu,\"requeued\":%llu,\"failed\":%llu},\"db_bytes\":%llu,\"wal_bytes\":%llu,\"shm_bytes\":%llu,\"physical_bytes\":%llu,\"accounting_available\":%u}",
        max, max, UINT32_MAX, max, max, max, max,
        max, max, max, max, max, max, max,
        max, max, max, max, max, max, max,
        max, max, max, max, max, max, UINT32_MAX);
    ok &= require_contains(fragment, "18446744073709551615",
                           "maximum uint64 health counters must format without loss");
    {
      int documented = snprintf(document, sizeof(document), "{%s}", fragment + 1u);
      cJSON *parsed = documented > 0 && (size_t)documented < sizeof(document) ?
          cJSON_Parse(document) : NULL;
      ok &= need(parsed != NULL && cJSON_IsObject(parsed) &&
                 cJSON_IsObject(cJSON_GetObjectItemCaseSensitive(
                     parsed, "p0_enforcement_terminal_journal")) &&
                 cJSON_IsNumber(cJSON_GetObjectItemCaseSensitive(
                     cJSON_GetObjectItemCaseSensitive(
                         parsed, "p0_enforcement_terminal_journal"),
                     "precreate_metadata_corruption_failures")) &&
                 cJSON_IsNumber(cJSON_GetObjectItemCaseSensitive(
                     cJSON_GetObjectItemCaseSensitive(
                         parsed, "p0_enforcement_terminal_journal"),
                     "owner_metadata_unresolved")) &&
                 cJSON_IsObject(cJSON_GetObjectItemCaseSensitive(
                     parsed, "p0_offline_queue_capacity")) &&
                 cJSON_IsObject(cJSON_GetObjectItemCaseSensitive(
                     cJSON_GetObjectItemCaseSensitive(parsed, "p0_offline_queue_capacity"),
                     "enqueue")) &&
                 cJSON_IsNumber(cJSON_GetObjectItemCaseSensitive(
                     cJSON_GetObjectItemCaseSensitive(parsed, "p0_offline_queue_capacity"),
                     "event_queue_metadata_corruption_failures")),
                 "maximum counter health fragment must remain parseable with terminal and queue members");
      cJSON_Delete(parsed);
    }
    used = 0u;
    too_small[0] = '\0';
    ok &= need(!append_json_fragment(too_small, sizeof(too_small), &used,
                                     ",\"long_metric\":%llu", max),
               "health append reports truncation");
    if (too_small[0]) too_small[0] = '\0';
    ok &= need(too_small[0] == '\0', "truncated health fragment is discarded");
  }

  free(callback);
  free(admission);
  free(decode);
  free(collector);
  free(tdh);
  free(direct_feed);
  free(alert_emit);
  free(agent);
  free(p0_rule_ir);
  free(process_cache);
  free(evidence_worker);
  free(evidence_wait);
  return ok ? 0 : 1;
}
