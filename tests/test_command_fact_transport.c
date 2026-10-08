#include "edr/behavior_alert_emit.h"
#include "edr/local_evidence_cache.h"
#include "edr/process_generation.h"
#include "edr/process_tree_cache.h"
#include "edr/storage_queue.h"
#include "edr/sha256.h"
#include "edr/p0_deferred_snapshot.h"
#include "edr/p0_rule_ir.h"
#include "edr/egress_batch_policy.h"
#include "edr/evidence_projection.h"
#ifdef EDR_P0_TEST_REAL_IR
#include "edr/p0_rule_direct_emit.h"
#endif
#include "edr/v1/event.pb.h"
#include "pb_decode.h"
#include "cJSON.h"
#include <sqlite3.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

/* External I/O only is replaced. Cache, matcher, alert producer, encoder,
 * SQLite queue and replay are production code. No Agent, server or external
 * model is invoked. The explicit non-production matcher-stub configuration
 * exercises local retention and denial, and cannot claim a detected alert. */
bool edr_resource_preprocess_throttle_active(void) { return false; }
int edr_event_batch_push(const uint8_t *p, size_t n) { (void)p; (void)n; return -1; }
void edr_preprocess_copy_agent_ids(char *ep, size_t ec, char *tn, size_t tc) {
  if (ec) *ep = 0;
  if (tc) *tn = 0;
}
int edr_ingest_http_configured(void) { return 1; }
int edr_ingest_http_circuit_open(void) { return 0; }
int edr_ingest_http_telemetry_deferred(void) { return 0; }
static uint8_t *expected_wire;
static size_t expected_size;
static unsigned delivered;
int edr_transport_v2_report_events(const char *id, const uint8_t *header, size_t hn,
    const uint8_t *body, size_t bn) {
  assert(id && hn == 12 && hn + bn == expected_size);
  assert(!memcmp(header, expected_wire, hn) && !memcmp(body, expected_wire + hn, bn));
  ++delivered;
  return 0;
}

static void temp_file(char path[512]) {
#ifdef _WIN32
  char dir[MAX_PATH];
  DWORD n = GetTempPathA(sizeof(dir), dir);
  assert(n && n < sizeof(dir) && GetTempFileNameA(dir, "ecf", 0, path));
#else
  strcpy(path, "/tmp/edr-command-fact-XXXXXX");
  int fd = mkstemp(path); assert(fd >= 0); close(fd);
#endif
}
static void cleanup(const char *path) {
  char sidecar[520];
  assert(remove(path) == 0);
  snprintf(sidecar, sizeof(sidecar), "%s-wal", path); (void)remove(sidecar);
  snprintf(sidecar, sizeof(sidecar), "%s-shm", path); (void)remove(sidecar);
}
static void identity(EdrBehaviorRecord *r, uint32_t pid) {
  memset(r, 0, sizeof(*r));
  strcpy(r->endpoint_id, "ep-command-fact"); strcpy(r->tenant_id, "tenant-command-fact");
  r->pid = pid; r->process_start_key = UINT64_C(15481123719095963) + pid;
  r->process_creation_filetime_100ns = UINT64_C(134346261457945144) + pid;
}

static sqlite3 *read_queue(const char *path) {
  sqlite3 *db = NULL;
  assert(sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK);
  return db;
}
static int sql_number(const char *path, const char *sql) {
  sqlite3 *db = read_queue(path); sqlite3_stmt *st = NULL;
  assert(sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK);
  assert(sqlite3_step(st) == SQLITE_ROW);
  int result = sqlite3_column_int(st, 0);
  assert(sqlite3_step(st) == SQLITE_DONE);
  sqlite3_finalize(st); sqlite3_close(db); return result;
}
static void assert_retained_wire(const char *path, const char *sql,
                                 const uint8_t *wire, size_t size, const char *batch) {
  sqlite3 *db = read_queue(path); sqlite3_stmt *st = NULL;
  char before[65], after[65];
  assert(sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK);
  if (batch) assert(sqlite3_bind_text(st, 1, batch, -1, SQLITE_TRANSIENT) == SQLITE_OK);
  assert(sqlite3_step(st) == SQLITE_ROW);
  const void *stored = sqlite3_column_blob(st, 0);
  assert(sqlite3_column_bytes(st, 0) == (int)size && !memcmp(stored, wire, size));
  assert(edr_sha256_hex(wire, size, before) == 0);
  assert(edr_sha256_hex(stored, size, after) == 0 && !strcmp(before, after));
  assert(sqlite3_step(st) == SQLITE_DONE);
  sqlite3_finalize(st); sqlite3_close(db);
}

#ifdef EDR_P0_TEST_REAL_IR
/* Capture the real producer's immutable queue body, rather than constructing
 * a provenance string. The decoder only borrows that producer's alert for the
 * independent full-fact/deferred codec round trip below. */
static uint8_t *capture_produced_wire(const char *path, size_t *size,
                                      AVEBehaviorAlert *alert) {
  sqlite3 *db = read_queue(path); sqlite3_stmt *st = NULL;
  assert(sqlite3_prepare_v2(db, "SELECT payload FROM event_queue WHERE status='pending';",
      -1, &st, NULL) == SQLITE_OK);
  assert(sqlite3_step(st) == SQLITE_ROW);
  *size = (size_t)sqlite3_column_bytes(st, 0);
  uint8_t *wire = malloc(*size); assert(wire && *size > 16u);
  memcpy(wire, sqlite3_column_blob(st, 0), *size);
  assert(sqlite3_step(st) == SQLITE_DONE);
  sqlite3_finalize(st); sqlite3_close(db);
  edr_v1_BehaviorEvent *event = calloc(1, sizeof(*event)); assert(event);
  pb_istream_t in = pb_istream_from_buffer(wire + 16u, *size - 16u);
  assert(pb_decode(&in, edr_v1_BehaviorEvent_fields, event) && event->has_behavior_alert);
  const edr_v1_BehaviorAlert *a = &event->behavior_alert;
  memset(alert, 0, sizeof(*alert));
  alert->pid = a->pid; alert->ppid = a->ppid; alert->timestamp_ns = a->timestamp_ns;
  alert->anomaly_score = a->anomaly_score;
  alert->skip_ai_analysis = a->skip_ai_analysis; alert->needs_l2_review = a->needs_l2_review;
  memcpy(alert->tactic_probs, a->tactic_probs, sizeof(alert->tactic_probs));
  snprintf(alert->process_name, sizeof(alert->process_name), "%s", a->process_name);
  assert(strlen(a->process_path) < sizeof(alert->process_path));
  memcpy(alert->process_path, a->process_path, strlen(a->process_path) + 1u);
  snprintf(alert->triggered_tactics, sizeof(alert->triggered_tactics), "%s", a->triggered_tactics);
  snprintf(alert->user_subject_json, sizeof(alert->user_subject_json), "%s", a->user_subject_json);
  snprintf(alert->related_iocs_json, sizeof(alert->related_iocs_json), "%s", a->related_iocs_json);
  snprintf(alert->cmdline, sizeof(alert->cmdline), "%s", a->cmdline);
  cJSON *subject = cJSON_Parse(a->user_subject_json); assert(subject);
  assert(!strcmp(cJSON_GetObjectItemCaseSensitive(subject, "rule_id")->valuestring, "R-EXEC-001"));
  cJSON_Delete(subject); free(event);
  return wire;
}
static int has_rule(const EdrBehaviorRecord *record, const EdrCommandFacts *facts,
                    const char *rule_id) {
  EdrP0RuleIrEvaluation evaluation;
  int found = 0;
  assert(edr_p0_rule_ir_evaluate_record(record, facts, &evaluation));
  for (uint32_t i = 0; i < evaluation.match_count; ++i) {
    EdrP0RuleIrMatch match;
    assert(edr_p0_rule_ir_evaluation_get_match(&evaluation, i, &match));
    if (strcmp(match.rule_id, rule_id) == 0) found = 1;
  }
  edr_p0_rule_ir_evaluation_free(&evaluation);
  return found;
}
static void authorize_replayed_match(EdrBehaviorRecord *record, const EdrCommandFacts *facts,
                                     const EdrP0RuleIrBinding *binding, const char *rule_id) {
  EdrP0RuleIrEvaluation evaluation;
  unsigned found = 0;
  assert(edr_p0_rule_ir_evaluate_record(record, facts, &evaluation));
  assert(!strcmp(evaluation.binding.artifact_sha256, binding->artifact_sha256));
  assert(!strcmp(evaluation.binding.rules_bundle_version, binding->rules_bundle_version));
  for (uint32_t i = 0; i < evaluation.match_count; ++i) {
    EdrP0RuleIrMatch match;
    assert(edr_p0_rule_ir_evaluation_get_match(&evaluation, i, &match));
    if (strcmp(match.rule_id, rule_id)) continue;
    assert(match.effect == EDR_P0_EFFECT_SECURITY_ALERT);
    record->evidence_projection_version = EDR_EVIDENCE_PROJECTION_VERSION;
    record->required_evidence_fields = match.required_evidence_fields;
    record->tactic_probability_state = 1u;
    snprintf(record->operation_evidence, sizeof(record->operation_evidence), "%s", match.operation_evidence);
    ++found;
  }
  assert(found == 1);
  edr_p0_rule_ir_evaluation_free(&evaluation);
}
#endif

#ifdef EDR_P0_TEST_REAL_IR
static void verify_cookie_command_generation(void) {
  EdrBehaviorRecord *r=calloc(1,sizeof(*r));assert(r);identity(r,9701);
  r->type=EDR_EVENT_FILE_READ;r->event_time_ns=INT64_C(1790152545794514400);
  strcpy(r->event_id,"cookie-generation");strcpy(r->process_name,"mimikatz.exe");
  strcpy(r->exe_path,"C:\\Tools\\mimikatz.exe");
  strcpy(r->file_path,"C:\\Lab\\Cookies");strcpy(r->cmdline,"mimikatz.exe");
  const char *command="mimikatz.exe \"dpapi::chrome /in:C:\\Lab\\Cookies /unprotect\"";
  assert(edr_local_evidence_cache_save_command_fact(r,command)==0);
  edr_behavior_mark_source_truncated(r,"source.cmdline");
  char *complete=edr_local_evidence_cache_read_command_fact(r);assert(complete);
  EdrCommandFacts facts={complete,NULL};assert(has_rule(r,&facts,"R-CRED-017"));free(complete);
  /* A reused PID must not borrow the old full operation or object argument. */
  for(int variant=0;variant<2;variant++) {
    if(variant==0) r->process_start_key++; else r->process_creation_filetime_100ns++;
    complete=edr_local_evidence_cache_read_command_fact(r);assert(!complete);
    facts.subject=complete;assert(!has_rule(r,&facts,"R-CRED-017"));
    if(variant==0) r->process_start_key--; else r->process_creation_filetime_100ns--;
  }
  free(r);puts("Cookie operation: real SQLite command owner accepts same generation; rejects reused PID start key and birth");
}
#endif

int main(int argc, char **argv) {
#ifndef EDR_P0_TEST_REAL_IR
  if (argc == 2) {
    fprintf(stderr, "Matcher-stub build cannot export an admitted alert fixture.\n");
    return 2;
  }
#endif
  char db[512], queue[512];
  EdrBehaviorRecord *parent = calloc(1, sizeof(*parent)), *child = calloc(1, sizeof(*child));
  edr_v1_BehaviorEvent *decoded = calloc(1, sizeof(*decoded));
  char *command = malloc(EDR_PROCESS_COMMAND_FACT_CAP);
  assert(parent && child && decoded && command);
  temp_file(db); temp_file(queue);
  assert(edr_local_evidence_cache_open(db, 8, 24) == 0);
  identity(parent, 8740); identity(child, 9000);
  strcpy(parent->process_name, "inert-parent.exe");
  strcpy(child->process_name, "inert-child.exe");
  strcpy(child->exe_path, "C:/test/inert-child.exe");
  strcpy(child->image_path_resolution_status, "RESOLVED");
  strcpy(child->process_generation_source, "file_read_process_tree_cache_generation");
  strcpy(child->event_id, "command-fact-roundtrip");
  strcpy(child->file_path, "C:\\test\\Login Data"); strcpy(child->file_op, "read");
  child->event_time_ns = INT64_C(1790152545794514400);
  child->type = EDR_EVENT_FILE_READ; child->ppid = parent->pid;
  child->parent_process_start_key = parent->process_start_key;
  child->parent_process_creation_filetime_100ns = parent->process_creation_filetime_100ns;
  AVEBehaviorAlert bare_alert = {0};
  bare_alert.pid = child->pid; bare_alert.ppid = child->ppid; bare_alert.timestamp_ns = child->event_time_ns;
  bare_alert.anomaly_score = 0.91f;
  strcpy(bare_alert.user_subject_json, "{\"rule_id\":\"R-TEST-COMMAND-FACT\",\"severity\":\"P0\"}");
#ifdef EDR_P0_TEST_REAL_IR
  edr_p0_rule_test_set_file_read_collector_healthy(1);
  edr_p0_rule_test_reset_dedup();
  verify_cookie_command_generation();
#endif
  const size_t sizes[] = {8191u, 8192u, 12717u, EDR_PROCESS_COMMAND_FACT_CAP - 1u};
  for (size_t k = 0; k < sizeof(sizes)/sizeof(sizes[0]); ++k) {
    size_t n = sizes[k];
    child->type = EDR_EVENT_FILE_READ;
    strcpy(child->process_name, "inert-child.exe");
    strcpy(child->file_path, "C:\\test\\Login Data");
    strcpy(child->file_op, "read");
    parent->process_start_key++; child->process_start_key++;
    child->parent_process_start_key = parent->process_start_key;
    memset(command, 'x', n); memcpy(command, "inert.exe --BEGIN ", 18); memcpy(command + n - 4, " END", 4); command[n] = 0;
    /* Multibyte content immediately crosses the old preview boundary. */
    if (n > 8194u) memcpy(command + 8190, "\xe4\xb8\xad", 3);
    memcpy(command + n - 5u, " -enc", 5u);
    if (n == 12717u) {
      /* Keep syntax-significant bytes in the exact BAT1 fixture as well as
       * the long-tail predicate. The backend can consume this same output. */
      command[3000] = '\n'; command[5000] = '\t';
      memcpy(command + 6000, "   ", 3u);
    }
    assert(edr_local_evidence_cache_save_command_fact(parent, command) == 0);
    assert(edr_local_evidence_cache_save_command_fact(child, command) == 0);
    assert(edr_local_evidence_cache_save_command_fact(parent, command) == 0);
    /* Same PID, different generation / tenant / endpoint never borrows. */
    parent->process_start_key++;
    assert(!edr_local_evidence_cache_read_command_fact(parent)); parent->process_start_key--;
    parent->tenant_id[0] = 'X'; assert(!edr_local_evidence_cache_read_command_fact(parent)); parent->tenant_id[0] = 't';
    parent->endpoint_id[0] = 'X'; assert(!edr_local_evidence_cache_read_command_fact(parent)); parent->endpoint_id[0] = 'e';
    edr_local_evidence_cache_close();
    assert(edr_local_evidence_cache_open(db, 8, 24) == 0);
    char *fact = edr_local_evidence_cache_read_command_fact(parent);
    assert(fact && strlen(fact) == n && !strcmp(command, fact)); free(fact);
    /* Empty and nonempty preview must both resolve through the production
     * parent reference, even after the process-tree hot cache is gone. */
    strcpy(child->cmdline, "inert.exe"); strcpy(child->parent_cmdline, "inert.exe");
    edr_behavior_mark_source_truncated(child, "source.cmdline");
    edr_behavior_mark_source_truncated(child, "source.parent_cmdline");
    if (n == 12717u) {
      /* RTQ resolves the same parent generation, with honest preview metadata
       * when its caller cannot afford the complete body. */
      char *tree = malloc(256u*1024u); assert(tree);
      strcpy(parent->cmdline, "inert.exe"); parent->event_time_ns = child->event_time_ns - 1;
      parent->type = EDR_EVENT_PROCESS_CREATE;
      edr_behavior_mark_source_truncated(parent, "source.cmdline");
      edr_pt_cache_init();
      uint64_t birth = (parent->process_creation_filetime_100ns - UINT64_C(116444736000000000)) * 100u;
      assert(edr_pt_cache_put_generation(parent->pid, 0u, parent->process_name,
          parent->cmdline, "C:/test/inert-parent.exe", NULL, birth,
          parent->process_start_key, parent->process_creation_filetime_100ns) == 0);
      edr_local_evidence_cache_observe_process(parent);
      edr_local_evidence_cache_observe_process(child);
      assert(edr_local_evidence_cache_process_tree_generation_json(parent->pid, parent->endpoint_id,
          parent->process_start_key, parent->process_creation_filetime_100ns, tree, 256u*1024u) == 0);
      cJSON *view = cJSON_Parse(tree); assert(view);
      const cJSON *root = cJSON_GetObjectItemCaseSensitive(view, "root");
      assert(!strcmp(cJSON_GetObjectItemCaseSensitive(root, "cmdline")->valuestring, command));
      assert(cJSON_GetObjectItemCaseSensitive(view, "child_count")->valueint == 1);
      cJSON_Delete(view);
      assert(edr_local_evidence_cache_process_tree_generation_json(parent->pid, parent->endpoint_id,
          parent->process_start_key, parent->process_creation_filetime_100ns, tree, 16384u) == 0);
      view = cJSON_Parse(tree); assert(view);
      root = cJSON_GetObjectItemCaseSensitive(view, "root");
      assert(!strcmp(cJSON_GetObjectItemCaseSensitive(root, "cmdline_quality")->valuestring, "preview_full_fact_retained"));
      assert(cJSON_GetObjectItemCaseSensitive(root, "cmdline_fact_bytes")->valueint == 12717);
      assert(strlen(cJSON_GetObjectItemCaseSensitive(root, "cmdline_fact_sha256")->valuestring) == 64);
      cJSON_Delete(view); free(tree);
      edr_pt_cache_shutdown();
    }
    EdrCommandFacts captured = {0};
    edr_local_evidence_cache_resolve_commands(child, &captured.subject, &captured.parent);
#ifdef EDR_P0_TEST_REAL_IR
    assert(captured.subject && captured.parent);
    assert(has_rule(child, &captured, "R-CRED-003"));
    strcpy(child->file_path, "C:\\Chrome\\Network\\Cookies");
    strcpy(child->process_name, "powershell.exe");
    assert(has_rule(child, &captured, "R-CRED-011"));
    strcpy(child->file_path, "C:\\test\\Login Data");
    strcpy(child->process_name, "inert-child.exe");
    if (n == 8191u || n == 8192u || n == 12717u) {
      EdrBehaviorRecord *candidate = malloc(sizeof(*candidate));
      assert(candidate);
      *candidate = *child;
      candidate->type = EDR_EVENT_PROCESS_CREATE;
      strcpy(candidate->process_name, "powershell.exe");
      memcpy(candidate->cmdline, command, n < EDR_BR_STR_CMDLINE ? n + 1u : EDR_BR_STR_CMDLINE - 1u);
      candidate->cmdline[n < EDR_BR_STR_CMDLINE ? n : EDR_BR_STR_CMDLINE - 1u] = 0;
      if (n == 8191u) {
        edr_behavior_resolve_source_truncated(candidate, "source.cmdline");
        assert(has_rule(candidate, NULL, "R-EXEC-001"));
      } else {
        assert(!has_rule(candidate, NULL, "R-EXEC-001"));
        /* The raw interest shortcut sees only this preview. Preprocess must
         * retain it under pressure until the exact fact can be evaluated. */
        assert(!edr_p0_rule_ir_br_matches_any(candidate));
      }
      assert(has_rule(candidate, &captured, "R-EXEC-001"));
      if (n >= 8192u) {
        candidate->process_start_key++;
        char *wrong_generation = edr_local_evidence_cache_read_command_fact(candidate);
        assert(!wrong_generation);
        EdrCommandFacts missing = {wrong_generation, NULL};
        assert(!has_rule(candidate, &missing, "R-EXEC-001"));
      }
      free(candidate);
    }
    if (n == 12717u) {
      EdrBehaviorRecord *unknown = malloc(sizeof(*unknown));
      assert(unknown);
      *unknown = *child;
      edr_behavior_resolve_source_truncated(unknown, "source.cmdline");
      edr_behavior_mark_source_truncated(unknown, "source.cmdline_quality_unknown");
      EdrCommandFacts checked = {0};
      edr_local_evidence_cache_resolve_commands(unknown, &checked.subject, &checked.parent);
      assert(checked.subject && !strcmp(checked.subject, command));
      unknown->type = EDR_EVENT_PROCESS_CREATE;
      strcpy(unknown->process_name, "powershell.exe");
      assert(!has_rule(unknown, NULL, "R-EXEC-001"));
      assert(has_rule(unknown, &checked, "R-EXEC-001"));
      free(checked.subject); free(checked.parent); free(unknown);
    }
#endif
    EdrP0RuleIrBinding binding = {0};
    const char *snapshot_rule = "R-TEST-COMMAND-FACT";
    AVEBehaviorAlert alert = bare_alert;
    size_t bare_size = 0;
    uint8_t *bare_wire = edr_behavior_record_alloc_durable_wire(child, &bare_alert, &bare_size);
    char why[96];
    assert(bare_wire && bare_size > n*2 && bare_size < 256u*1024u);
    assert(!edr_egress_batch_validate(bare_wire, 12u, bare_wire+12u,
        bare_size-12u, why, sizeof(why)));
    memset(decoded, 0, sizeof(*decoded));
    pb_istream_t bare_input = pb_istream_from_buffer(bare_wire+16u, bare_size-16u);
    assert(pb_decode(&bare_input, edr_v1_BehaviorEvent_fields, decoded));
    assert(decoded->priority == 0 && !strcmp(decoded->cmdline, command) &&
        !strcmp(decoded->process_context.parent_cmdline, command));
    assert(edr_storage_queue_open(queue) == EDR_OK);
#ifdef EDR_P0_TEST_REAL_IR
    assert(edr_p0_rule_ir_get_binding(&binding));
    int proven_miss = 0;
    /* A browser-data read still matches its real local observation rule,
     * but has no independent alert or queue authority. Long facts do not
     * turn that observation into a security alert. */
    assert(edr_p0_rule_try_emit_with_command_facts_status(child, &captured, &proven_miss) == 0);
    assert(sql_number(queue, "SELECT COUNT(*) FROM event_queue;") == 0);
    /* The transport positive has an actual full-command predicate: the
     * encoded-command token at the tail must survive local/deferred replay.
     * Its unrelated parent command remains local, outside the projection. */
    snapshot_rule = "R-EXEC-001";
    child->type = EDR_EVENT_PROCESS_CREATE;
    strcpy(child->process_name, "powershell.exe");
    child->file_path[0] = child->file_op[0] = 0;
    assert(has_rule(child, &captured, snapshot_rule));
    assert(edr_p0_rule_try_emit_with_command_facts_status(child, &captured, &proven_miss) == 1);
    assert(!proven_miss);
    expected_wire = capture_produced_wire(queue, &expected_size, &alert);
    assert(edr_egress_batch_validate(expected_wire, 12u, expected_wire+12u,
        expected_size-12u, why, sizeof(why)));
#else
    /* No matcher authority exists in the explicit stub build. Preserve the
     * local full-fact regression and require both deliveries to stay held. */
    strcpy(binding.rules_bundle_version, "synthetic-r1"); memset(binding.artifact_sha256, 'a', 64u);
    expected_wire = edr_behavior_record_alloc_durable_wire(child, &alert, &expected_size);
    char batch[128];
    assert(edr_behavior_durable_wire_batch_id("command-fact", expected_wire, expected_size, batch, sizeof(batch)));
    assert(edr_storage_queue_enqueue(batch, expected_wire, expected_size, 0, 1) == EDR_OK);
#endif
    char *snapshot = NULL, deferred_key[65]; size_t snapshot_size = 0;
    assert(edr_p0_deferred_snapshot_encode_facts(child, &binding, snapshot_rule,
        &captured, &snapshot, &snapshot_size));
    assert(edr_sha256_hex((const uint8_t *)snapshot, snapshot_size, deferred_key) == 0);
    free(captured.subject); free(captured.parent);
    assert(expected_wire && expected_size < 256u*1024u);
    memset(decoded, 0, sizeof(*decoded));
    pb_istream_t input = pb_istream_from_buffer(expected_wire + 16u, expected_size - 16u);
    assert(pb_decode(&input, edr_v1_BehaviorEvent_fields, decoded));
    assert(!strcmp(decoded->cmdline, command));
#ifdef EDR_P0_TEST_REAL_IR
    assert(expected_size > n && expected_size < n*2);
    assert(decoded->evidence_projection_version == EDR_EVIDENCE_PROJECTION_VERSION);
    assert(!decoded->process_context.parent_cmdline[0] && !decoded->behavior_alert.cmdline[0]);
#else
    assert(expected_size > n*2 && !strcmp(decoded->process_context.parent_cmdline, command));
#endif
    assert(!decoded->truncated_fields[0] && !strcmp(decoded->transport_completeness, "COMPLETE"));
#ifndef EDR_P0_TEST_REAL_IR
    assert(!strcmp(decoded->detail.file.target_path, child->file_path));
#endif
    assert(edr_storage_queue_p0_deferred_retain(deferred_key, 1u,
        (const uint8_t *)snapshot, snapshot_size) == EDR_OK);
    free(snapshot);
    edr_storage_queue_close();
    edr_local_evidence_cache_close(); /* Delivery cannot rely on live cache. */
    assert(edr_storage_queue_open(queue) == EDR_OK);
    unsigned before = delivered;
    edr_storage_queue_poll_drain();
#ifdef EDR_P0_TEST_REAL_IR
    assert(delivered == before + 1);
#else
    assert(delivered == before);
    assert(sql_number(queue, "SELECT COUNT(*) FROM event_queue WHERE status='policy_held' AND retry_count=0;") == (int)(2u*k + 1u));
    assert(sql_number(queue, "SELECT COUNT(*) FROM event_queue;") == (int)(2u*k + 1u));
    assert_retained_wire(queue, "SELECT payload FROM event_queue WHERE batch_id=?;",
        expected_wire, expected_size, batch);
#endif
    assert(edr_storage_queue_pending_count() == 0);
    uint8_t *retained = NULL; size_t retained_size = 0;
    char selected_key[65], restored_rule[64];
    assert(edr_storage_queue_p0_deferred_peek(1u, selected_key, &retained, &retained_size) == 1);
    assert(!strcmp(selected_key, deferred_key));
    EdrBehaviorRecord *restored = calloc(1, sizeof(*restored)); assert(restored);
    EdrCommandFacts recovered = {0}; EdrP0RuleIrBinding restored_binding;
    assert(edr_p0_deferred_snapshot_decode_facts((const char *)retained, retained_size,
        restored, &restored_binding, restored_rule, sizeof(restored_rule), &recovered));
    free(retained);
    assert(!strcmp(restored_rule, snapshot_rule));
    assert(!strcmp(restored_binding.artifact_sha256, binding.artifact_sha256));
    assert(!strcmp(restored_binding.rules_bundle_version, binding.rules_bundle_version));
    assert(recovered.subject && !strcmp(recovered.subject, command));
    assert(recovered.parent && !strcmp(recovered.parent, command));
#ifdef EDR_P0_TEST_REAL_IR
    assert(has_rule(restored, &recovered, "R-EXEC-001"));
    /* Deferred facts are not a reusable alert grant. Without re-evaluating
     * the retained binding, the borrowed subject cannot authorize a frame. */
    size_t unauthorized_size = 0;
    uint8_t *unauthorized = edr_behavior_record_alloc_outbound_wire_facts(
        restored, &alert, &recovered, &unauthorized_size);
    assert(!unauthorized && !unauthorized_size);
    /* Reproduce the producer's descriptor copy from an actual match under
     * the same immutable bundle; never authorize from the alert's JSON. */
    authorize_replayed_match(restored, &recovered, &restored_binding, restored_rule);
#endif
    size_t replay_size = 0;
    uint8_t *replay =
#ifdef EDR_P0_TEST_REAL_IR
        edr_behavior_record_alloc_outbound_wire_facts(restored, &alert, &recovered, &replay_size);
#else
        edr_behavior_record_alloc_durable_wire_facts(restored, &alert, &recovered, &replay_size);
#endif
    assert(replay && replay_size == expected_size && !memcmp(replay, expected_wire, replay_size));
#ifdef EDR_P0_TEST_REAL_IR
    assert(edr_egress_batch_validate(replay, 12u, replay+12u,
        replay_size-12u, why, sizeof(why)));
#endif
    /* This is the same atomic handoff used after deferred matching. Give the
     * delivery a distinct id from the earlier deliberately identical test. */
    assert(edr_storage_queue_p0_deferred_complete(selected_key, selected_key,
        replay, replay_size, "queue_accepted") == EDR_OK);
    free(replay); free(restored); free(recovered.subject); free(recovered.parent);
    edr_storage_queue_close();
    assert(edr_storage_queue_open(queue) == EDR_OK);
    edr_storage_queue_poll_drain();
#ifdef EDR_P0_TEST_REAL_IR
    assert(delivered == before + 2);
#else
    assert(delivered == before);
    assert(sql_number(queue, "SELECT COUNT(*) FROM event_queue WHERE status='policy_held' AND retry_count=0;") == (int)(2u*k + 2u));
    assert(sql_number(queue, "SELECT COUNT(*) FROM event_queue;") == (int)(2u*k + 2u));
    assert_retained_wire(queue, "SELECT payload FROM event_queue WHERE batch_id=?;",
        expected_wire, expected_size, batch);
    assert_retained_wire(queue, "SELECT payload FROM event_queue WHERE batch_id=?;",
        expected_wire, expected_size, selected_key);
#endif
    assert(edr_storage_queue_pending_count() == 0);
    if (n == EDR_PROCESS_COMMAND_FACT_CAP - 1u) {
      EdrStorageQueueCapacityMetrics before_intent, after_intent;
      edr_storage_queue_get_capacity_metrics(&before_intent);
      assert(edr_storage_queue_enforcement_terminal_precreate("long-command-owner", "synthetic-event",
          "R-TEST", "synthetic-generation", "long-intent", bare_wire, bare_size) ==
          EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
      edr_storage_queue_get_capacity_metrics(&after_intent);
      assert(after_intent.used_bytes >= before_intent.used_bytes + bare_size + 2u*256u*1024u);
      assert(edr_storage_queue_enforcement_terminal_update("long-command-owner", "long-source",
          bare_wire, bare_size, "long-combined", bare_wire, bare_size) == EDR_OK);
      edr_storage_queue_close(); assert(edr_storage_queue_open(queue) == EDR_OK);
      unsigned before_bare = delivered;
      edr_storage_queue_poll_drain();
      assert(delivered == before_bare);
      assert(sql_number(queue, "SELECT COUNT(*) FROM enforcement_terminal_journal WHERE "
          "idempotency_key='long-command-owner' AND state='ready' AND "
          "intent_policy_held=1 AND source_policy_held=1 AND combined_policy_held=1 AND "
          "intent_acked=0 AND source_acked=0 AND combined_acked=0 AND "
          "intent_retry_count=0 AND source_retry_count=0 AND combined_retry_count=0 AND "
          "intent_batch_id='long-intent' AND source_batch_id='long-source' AND combined_batch_id='long-combined';") == 1);
      EdrEnforcementTerminalJournalMetrics journal;
      edr_storage_queue_enforcement_terminal_get_metrics(&journal);
      assert(journal.policy_held_frames == 3 && journal.pending == 1 && journal.local_retained == 0);
      assert_retained_wire(queue, "SELECT intent_wire FROM enforcement_terminal_journal WHERE idempotency_key='long-command-owner';", bare_wire, bare_size, NULL);
      assert_retained_wire(queue, "SELECT source_wire FROM enforcement_terminal_journal WHERE idempotency_key='long-command-owner';", bare_wire, bare_size, NULL);
      assert_retained_wire(queue, "SELECT combined_wire FROM enforcement_terminal_journal WHERE idempotency_key='long-command-owner';", bare_wire, bare_size, NULL);
    }
    edr_storage_queue_close();
    if (argc == 2 && n == 12717u) {
      FILE *f = fopen(argv[1], "wb"); assert(f);
      assert(fwrite(expected_wire, 1, expected_size, f) == expected_size); assert(fclose(f) == 0);
    }
    printf("command_fact bytes=%zu parent=exact restart=exact queue_replay=exact deferred_cache_closed=exact wire_bytes=%zu delivery=%s\n", n, expected_size,
#ifdef EDR_P0_TEST_REAL_IR
        "real_ir_alert"
#else
        "held_without_matcher_authority"
#endif
    );
    free(bare_wire);
    free(expected_wire);
    assert(edr_local_evidence_cache_open(db, 8, 24) == 0);
  }
  /* Conflict, missing generation and missing fact cannot clear loss markers. */
  char *subject = NULL, *parent_text = NULL;
  edr_behavior_mark_source_truncated(child, "source.parent_command_fact");
  edr_local_evidence_cache_resolve_commands(child, &subject, &parent_text);
  assert(subject && !parent_text); free(subject);
  /* Remove only the synthetic failure marker to independently test identity. */
  child->source_truncated_fields[0] = 0;
  edr_behavior_mark_source_truncated(child, "source.cmdline");
  edr_behavior_mark_source_truncated(child, "source.parent_cmdline");
  child->parent_process_start_key++;
  edr_local_evidence_cache_resolve_commands(child, &subject, &parent_text);
  assert(subject && !parent_text); free(subject);
  strcpy(child->cmdline, "conflicting.exe");
  edr_local_evidence_cache_resolve_commands(child, &subject, &parent_text);
  assert(!subject && !parent_text);
  child->process_start_key = 0;
  assert(edr_local_evidence_cache_save_command_fact(child, command) != 0);
  /* Identical 8KiB previews do not authorize choosing an earlier full tail.
   * A conflict survives restart and cannot be repaired by resubmitting either
   * observation under the same generation. Original artifact is retained. */
  command[strlen(command)-1u] = '!';
  assert(edr_local_evidence_cache_save_command_fact(parent, command) != 0);
  assert(!edr_local_evidence_cache_read_command_fact(parent));
  edr_local_evidence_cache_close();
  assert(edr_local_evidence_cache_open(db, 8, 24) == 0);
  assert(!edr_local_evidence_cache_read_command_fact(parent));
  assert(edr_local_evidence_cache_save_command_fact(parent, command) != 0);
  edr_local_evidence_cache_close();
  cleanup(db); cleanup(queue);
  free(parent); free(child); free(decoded); free(command);
  return 0;
}
