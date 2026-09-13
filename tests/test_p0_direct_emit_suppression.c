#define _DARWIN_C_SOURCE
#include "edr/behavior_record.h"
#include "edr/ave_sdk.h"
#include "edr/behavior_alert_emit.h"
#include "edr/p0_rule_direct_emit.h"
#include "edr/p0_rule_ir.h"
#include "edr/p0_source_only_contract.h"
#include "edr/policy_enforcement.h"
#include "edr/policy_v2.h"
#include "edr/config.h"
#include "edr/storage_queue.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <time.h>
#include "p0_deferred_queue_fake.h"

#if defined(_WIN32)
static int test_setenv(const char *name, const char *value, int overwrite) {
  if (!overwrite && getenv(name) != NULL) return 0;
  return _putenv_s(name, value);
}
#else
#include <pthread.h>
extern int setenv(const char *, const char *, int);
static int test_setenv(const char *name, const char *value, int overwrite) {
  return setenv(name, value, overwrite);
}
#endif

int edr_p0_test_should_suppress_known_false_positive(const char *rule_id,
                                                     const EdrBehaviorRecord *br,
                                                     const char *detail,
                                                     const char **out_reason);

static atomic_int g_adaptive_raises = 0;
void edr_adaptive_collection_raise(int severity, const char *rule_id, uint32_t pid,
                                   uint32_t parent_pid, const char *process_name) {
  (void)severity;
  (void)rule_id;
  (void)pid;
  (void)parent_pid;
  (void)process_name;
  atomic_fetch_add(&g_adaptive_raises,1);
}

static atomic_int g_emit_count = 0;
static atomic_int g_durable_count = 0;
static int g_combined_emit_allowed = 1;
static EdrBehaviorRecordAlertEmitOutcome g_combined_emit_outcome =
    EDR_BEHAVIOR_RECORD_ALERT_EMIT_ACCEPTED;
static int g_durable_emit_allowed = 1;
static int g_source_latch;
static int g_source_latch_recovery_required;
static int g_source_ack;
static uint64_t g_source_latch_counter = UINT64_C(0x1234);
static uint64_t g_source_latch_epoch = UINT64_C(1);
static char g_source_latch_batch[128];
static int g_terminal_update_allowed = 1;
static int g_terminal_source_enqueue_allowed = 1;
static int g_ir_ready = 1;
static int g_ir_evaluation_available = 1;
static atomic_int g_block_combined = 0;
static atomic_int g_combined_inflight = 0;
static atomic_int g_combined_release = 0;
static atomic_int g_combined_fail_after_release = 0;
/* A focused delayed producer lets rate-window tests keep one reservation
 * in flight while unrelated records continue through the ordinary path. */
static const char *g_block_combined_event_id;
static atomic_int g_parallel_mode = 0;
static atomic_int g_enforcement_side_effects = 0;
static atomic_int g_terminal_precreate_calls = 0;
static atomic_int g_terminal_update_calls = 0;
static atomic_flag g_terminal_lock = ATOMIC_FLAG_INIT;
static const char *g_required_intent_marker;

typedef struct {
  char key[96];
  char source[EDR_BR_ID_LEN];
  char rule[64];
  char generation[32];
  char intent_batch[128];
  uint8_t intent_value;
  size_t intent_wire_len;
  char intent_context[4096];
  int updated;
} TerminalJournalEntry;
static TerminalJournalEntry g_terminal_entries[256];

static void terminal_lock(void) {
  while (atomic_flag_test_and_set_explicit(&g_terminal_lock, memory_order_acquire)) { }
}

static void terminal_unlock(void) {
  atomic_flag_clear_explicit(&g_terminal_lock, memory_order_release);
}

static int terminal_intent_context_contains(const char *needle) {
  int found = 0;
  if (!needle || !needle[0]) return 0;
  terminal_lock();
  for (int i = 0; i < (int)(sizeof(g_terminal_entries) / sizeof(g_terminal_entries[0])); i++) {
    if (strstr(g_terminal_entries[i].intent_context, needle) != NULL) {
      found = 1;
      break;
    }
  }
  terminal_unlock();
  return found;
}

static void test_enforcement_execute_hook(const EdrBehaviorRecord *record,
                                          EdrPolicyEnforcementResult *result) {
  (void)record;
  if (g_required_intent_marker) {
    assert(terminal_intent_context_contains(g_required_intent_marker));
  }
  atomic_fetch_add_explicit(&g_enforcement_side_effects, 1, memory_order_relaxed);
  result->attempted = 1;
  result->succeeded = 1;
  snprintf(result->action, sizeof(result->action), "%s", "test_terminate");
  snprintf(result->message, sizeof(result->message), "%s", "test side effect");
}
static const char *g_bundle_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static AVEBehaviorAlert g_last_alert;
static EdrBehaviorRecord g_last_record;
EdrBehaviorRecordAlertEmitOutcome edr_behavior_record_alert_emit_deferred(
    const EdrBehaviorRecord *record,const AVEBehaviorAlert *alert,const char *key) {
  if (!g_combined_emit_allowed || deferred_complete_fails)
    return EDR_BEHAVIOR_RECORD_ALERT_EMIT_PREPARE_OR_QUEUE_FAILED;
  if (g_combined_emit_outcome != EDR_BEHAVIOR_RECORD_ALERT_EMIT_ACCEPTED) return g_combined_emit_outcome;
  if (edr_storage_queue_p0_deferred_complete(key,"fake-wire",NULL,0u,"queue_accepted")!=EDR_OK)
    return EDR_BEHAVIOR_RECORD_ALERT_EMIT_PREPARE_OR_QUEUE_FAILED;
  g_emit_count++; g_last_record=*record; g_last_alert=*alert;
  return EDR_BEHAVIOR_RECORD_ALERT_EMIT_ACCEPTED;
}
void edr_behavior_alert_emit_to_batch(const AVEBehaviorAlert *a) { g_emit_count++; if (a) g_last_alert=*a; }
int edr_behavior_record_alert_emit_to_batch(const EdrBehaviorRecord *record,
                                            const AVEBehaviorAlert *alert) {
  if (!g_combined_emit_allowed || !record || !alert) {
    return 0;
  }
  if (atomic_load_explicit(&g_block_combined, memory_order_acquire) &&
      (!g_block_combined_event_id ||
       strcmp(record->event_id, g_block_combined_event_id) == 0)) {
    atomic_fetch_add_explicit(&g_combined_inflight, 1, memory_order_acq_rel);
    while (atomic_load_explicit(&g_combined_release, memory_order_acquire) == 0) { }
    if (atomic_exchange_explicit(&g_combined_fail_after_release, 0,
                                 memory_order_acq_rel) != 0) {
      return 0;
    }
    g_emit_count++;
    return 1;
  }
  g_emit_count++;
  g_last_record = *record;
  g_last_alert = *alert;
  return 1;
}
EdrBehaviorRecordAlertEmitOutcome
edr_behavior_record_alert_emit_to_batch_with_prepare_outcome(
    const EdrBehaviorRecord *record, const AVEBehaviorAlert *alert,
    EdrBehaviorRecordAlertPrepareFn prepare, void *prepare_context) {
  if (g_combined_emit_outcome != EDR_BEHAVIOR_RECORD_ALERT_EMIT_ACCEPTED) {
    return g_combined_emit_outcome;
  }
  if (prepare && !prepare(prepare_context)) {
    return EDR_BEHAVIOR_RECORD_ALERT_EMIT_PREPARE_OR_QUEUE_FAILED;
  }
  return edr_behavior_record_alert_emit_to_batch(record, alert)
             ? EDR_BEHAVIOR_RECORD_ALERT_EMIT_ACCEPTED
             : EDR_BEHAVIOR_RECORD_ALERT_EMIT_PREPARE_OR_QUEUE_FAILED;
}
int edr_behavior_record_alert_emit_to_batch_with_prepare(
    const EdrBehaviorRecord *record, const AVEBehaviorAlert *alert,
    EdrBehaviorRecordAlertPrepareFn prepare, void *prepare_context) {
  return edr_behavior_record_alert_emit_to_batch_with_prepare_outcome(
             record, alert, prepare, prepare_context) ==
         EDR_BEHAVIOR_RECORD_ALERT_EMIT_ACCEPTED;
}
int edr_behavior_record_emit_durable(const EdrBehaviorRecord *record) {
  if (!g_durable_emit_allowed || !record) {
    return 0;
  }
  g_durable_count++;
  if (atomic_load_explicit(&g_parallel_mode, memory_order_acquire)) {
    return 1;
  }
  g_last_record = *record;
  return 1;
}

static size_t make_terminal_wire(uint8_t kind, uint8_t *wire, size_t wire_cap) {
  static const uint8_t header[] = {0x42, 0x41, 0x54, 0x31, 1, 0, 0, 0, 8, 0, 0, 0};
  if (!wire || wire_cap < 20u) return 0u;
  memcpy(wire, header, sizeof(header));
  wire[12] = 4u; wire[13] = 0u; wire[14] = 0u; wire[15] = 0u;
  wire[16] = kind; wire[17] = 0u; wire[18] = 0xa5u; wire[19] = 0x5au;
  return 20u;
}

size_t edr_behavior_record_encode_durable_wire(const EdrBehaviorRecord *record,
                                               uint8_t *wire, size_t wire_cap) {
  if (!record) return 0u;
  g_last_record = *record;
  return make_terminal_wire(0x51u, wire, wire_cap);
}

size_t edr_behavior_record_alert_encode_durable_wire(const EdrBehaviorRecord *record,
                                                      const AVEBehaviorAlert *alert,
                                                      uint8_t *wire, size_t wire_cap) {
  if (!record || !alert) return 0u;
  g_last_record = *record;
  g_last_alert = *alert;
  return make_terminal_wire(0x52u, wire, wire_cap);
}

int edr_behavior_durable_wire_batch_id(const char *kind, const uint8_t *wire, size_t wire_len,
                                       char *out, size_t out_cap) {
  (void)wire;
  if (!kind || !out || out_cap < 8u || wire_len == 0u) return 0;
  snprintf(out, out_cap, "%s-test", kind);
  return 1;
}

EdrEnforcementTerminalPrecreate edr_storage_queue_enforcement_terminal_precreate(
    const char *key, const char *source, const char *rule, const char *generation,
    const char *intent_batch, const uint8_t *intent_wire, size_t intent_wire_len) {
  int empty = -1;
  if (!g_durable_emit_allowed || !key || !source || !rule || !generation || !intent_batch ||
      !intent_wire || intent_wire_len != 20u) {
    return EDR_ENFORCEMENT_TERMINAL_PRECREATE_ERROR;
  }
  atomic_fetch_add_explicit(&g_terminal_precreate_calls, 1, memory_order_relaxed);
  terminal_lock();
  for (int i = 0; i < (int)(sizeof(g_terminal_entries) / sizeof(g_terminal_entries[0])); i++) {
    if (!g_terminal_entries[i].key[0]) {
      if (empty < 0) empty = i;
      continue;
    }
    if (strcmp(g_terminal_entries[i].key, key) == 0) {
      int exact = strcmp(g_terminal_entries[i].source, source) == 0 &&
                  strcmp(g_terminal_entries[i].rule, rule) == 0 &&
                  strcmp(g_terminal_entries[i].generation, generation) == 0 &&
                  strcmp(g_terminal_entries[i].intent_batch, intent_batch) == 0 &&
                  g_terminal_entries[i].intent_wire_len == intent_wire_len &&
                  g_terminal_entries[i].intent_value == intent_wire[16];
      terminal_unlock();
      return exact ? EDR_ENFORCEMENT_TERMINAL_PRECREATE_EXISTING
                   : EDR_ENFORCEMENT_TERMINAL_PRECREATE_CONFLICT;
    }
  }
  if (empty >= 0) {
    snprintf(g_terminal_entries[empty].key, sizeof(g_terminal_entries[empty].key), "%s", key);
    snprintf(g_terminal_entries[empty].source, sizeof(g_terminal_entries[empty].source), "%s", source);
    snprintf(g_terminal_entries[empty].rule, sizeof(g_terminal_entries[empty].rule), "%s", rule);
    snprintf(g_terminal_entries[empty].generation, sizeof(g_terminal_entries[empty].generation), "%s", generation);
    snprintf(g_terminal_entries[empty].intent_batch, sizeof(g_terminal_entries[empty].intent_batch), "%s", intent_batch);
    g_terminal_entries[empty].intent_wire_len = intent_wire_len;
    g_terminal_entries[empty].intent_value = intent_wire[16];
    snprintf(g_terminal_entries[empty].intent_context,
             sizeof(g_terminal_entries[empty].intent_context), "%s",
             g_last_record.detection_context);
    terminal_unlock();
    return EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED;
  }
  terminal_unlock();
  return EDR_ENFORCEMENT_TERMINAL_PRECREATE_ERROR;
}

EdrError edr_storage_queue_enforcement_terminal_update(
    const char *key, const char *source_batch_id, const uint8_t *source_wire, size_t source_wire_len,
    const char *combined_batch_id, const uint8_t *combined_wire, size_t combined_wire_len) {
  (void)source_batch_id;
  (void)source_wire;
  (void)source_wire_len;
  (void)combined_batch_id;
  (void)combined_wire;
  (void)combined_wire_len;
  if (!g_terminal_update_allowed || !key) return EDR_ERR_SQLITE_WRITE;
  terminal_lock();
  for (int i = 0; i < (int)(sizeof(g_terminal_entries) / sizeof(g_terminal_entries[0])); i++) {
    if (strcmp(g_terminal_entries[i].key, key) == 0) {
      g_terminal_entries[i].updated = 1;
      atomic_fetch_add_explicit(&g_terminal_update_calls, 1, memory_order_relaxed);
      terminal_unlock();
      return EDR_OK;
    }
  }
  terminal_unlock();
  return EDR_ERR_SQLITE_WRITE;
}

EdrError edr_storage_queue_enqueue(const char *batch_id, const uint8_t *wire, size_t wire_len,
                                   int compressed, int severity) {
  (void)wire;
  (void)wire_len;
  (void)compressed;
  (void)severity;
  if (!batch_id) return EDR_ERR_INVALID_ARG;
  if (strstr(batch_id, "combined") != NULL) {
    if (!g_combined_emit_allowed) return EDR_ERR_SQLITE_WRITE;
    if (atomic_load_explicit(&g_block_combined, memory_order_acquire)) {
      atomic_fetch_add_explicit(&g_combined_inflight, 1, memory_order_acq_rel);
      while (atomic_load_explicit(&g_combined_release, memory_order_acquire) == 0) { }
    }
    atomic_fetch_add_explicit(&g_emit_count, 1, memory_order_relaxed);
    return EDR_OK;
  }
  return g_terminal_source_enqueue_allowed ? EDR_OK : EDR_ERR_SQLITE_WRITE;
}

/* The focused direct-emit unit links no SQLite implementation. Its production
 * persistence contract is covered by test_storage_queue_sqlite; the stub
 * keeps the same ownership rule: local enqueue never clears a latch, and the
 * test must explicitly simulate the central ACK before recovery can pass. */
int edr_storage_queue_is_open(void) { return 1; }
int edr_storage_queue_p0_source_only_latch_is_set(void) { return g_source_latch; }
EdrError edr_storage_queue_p0_source_only_latch_prepare(
    EdrStorageQueueP0SourceOnlyLatch *out) {
  static const uint8_t nonce[16] = {
      0x10u, 0x32u, 0x54u, 0x76u, 0x98u, 0xbau, 0xdcu, 0xfeu,
      0x01u, 0x23u, 0x45u, 0x67u, 0x89u, 0xabu, 0xcdu, 0xefu,
  };
  if (!out) return EDR_ERR_INVALID_ARG;
  if (!g_source_latch) {
    g_source_latch = 1;
    g_source_latch_recovery_required = 0;
    g_source_ack = 0;
    g_source_latch_batch[0] = '\0';
  } else {
    g_source_latch_recovery_required = 1;
    g_source_latch_batch[0] = '\0';
  }
  memset(out, 0, sizeof(*out));
  memcpy(out->queue_nonce, nonce, sizeof(out->queue_nonce));
  out->latch_counter = g_source_latch_counter;
  out->latch_epoch = g_source_latch_epoch;
  out->latched = 1;
  out->recovery_required = g_source_latch_recovery_required;
  return EDR_OK;
}
EdrError edr_storage_queue_p0_source_only_latch_get(
    EdrStorageQueueP0SourceOnlyLatch *out) {
  static const uint8_t nonce[16] = {
      0x10u, 0x32u, 0x54u, 0x76u, 0x98u, 0xbau, 0xdcu, 0xfeu,
      0x01u, 0x23u, 0x45u, 0x67u, 0x89u, 0xabu, 0xcdu, 0xefu,
  };
  if (!out) return EDR_ERR_INVALID_ARG;
  if (g_source_latch && g_source_ack && g_source_latch_batch[0]) {
    g_source_latch = 0;
    g_source_latch_recovery_required = 0;
    g_source_latch_batch[0] = '\0';
  }
  memset(out, 0, sizeof(*out));
  out->latched = g_source_latch;
  memcpy(out->queue_nonce, nonce, sizeof(out->queue_nonce));
  out->latch_counter = g_source_latch_counter;
  out->latch_epoch = g_source_latch_epoch;
  out->recovery_required = g_source_latch_recovery_required;
  return EDR_OK;
}
EdrError edr_storage_queue_p0_source_only_enqueue_bound(
    const EdrStorageQueueP0SourceOnlyLatch *expected, const char *event_id,
    const char *batch_id, const uint8_t *wire, size_t wire_len,
    int compressed, int recovery_audit) {
  (void)event_id;
  (void)wire;
  (void)wire_len;
  (void)compressed;
  if (!expected || !expected->latched || !batch_id || !batch_id[0] || !g_source_latch ||
      expected->latch_counter != g_source_latch_counter ||
      expected->latch_epoch != g_source_latch_epoch ||
      (recovery_audit && !g_source_latch_recovery_required) ||
      !g_durable_emit_allowed) {
    return EDR_ERR_INVALID_ARG;
  }
  if (recovery_audit) g_source_latch_recovery_required = 0;
  snprintf(g_source_latch_batch, sizeof(g_source_latch_batch), "%s", batch_id);
  atomic_fetch_add_explicit(&g_durable_count, 1, memory_order_relaxed);
  return EDR_OK;
}
EdrError edr_storage_queue_p0_source_only_recovery_probe(void) { return EDR_OK; }

bool edr_resource_preprocess_throttle_active(void) { return false; }

int enrich_parent_info_by_pid(uint32_t ppid, char *parent_name, size_t name_len,
                              char *parent_path, size_t path_len) {
  assert(!"P0 emission must not resolve a parent by live PID alone");
  (void)ppid;
  if (parent_name && name_len > 0u) {
    parent_name[0] = '\0';
  }
  if (parent_path && path_len > 0u) {
    parent_path[0] = '\0';
  }
  return 1;
}

void edr_p0_rule_ir_lazy_init(void) {}
void edr_p0_rule_ir_reload(void) {}
void edr_p0_rule_ir_shutdown(void) {}
int edr_p0_rule_ir_install_staged_bundle(const char *staged_path, const char *destination_path) {
  (void)staged_path; (void)destination_path; return 0;
}
int edr_p0_bundle_dst_path(char *out, size_t cap) {
  if (out && cap > 0u) {
    out[0] = '\0';
  }
  return -1;
}
int edr_p0_rule_ir_is_ready(void) { return g_ir_ready; }
int edr_p0_rule_ir_artifact_healthy(char *out_reason, size_t out_reason_cap) {
  if (out_reason && out_reason_cap > 0u) out_reason[0] = '\0';
  return g_ir_ready;
}
int edr_p0_rule_ir_get_bundle_info(const char **out_source, size_t *out_plain_size,
                                   const char **out_plain_sha256) {
  if (out_source) {
    *out_source = "";
  }
  if (out_plain_size) {
    *out_plain_size = 0u;
  }
  if (out_plain_sha256) {
    *out_plain_sha256 = g_bundle_sha256;
  }
  return (g_bundle_sha256 && g_bundle_sha256[0]) ? 1 : 0;
}
int edr_p0_rule_ir_get_binding(EdrP0RuleIrBinding *out_binding) {
  if (!out_binding || !g_ir_ready) return 0;
  memset(out_binding, 0, sizeof(*out_binding));
  snprintf(out_binding->rules_bundle_version, sizeof(out_binding->rules_bundle_version),
           "%s", "test-p0-ir-v1");
  snprintf(out_binding->artifact_sha256, sizeof(out_binding->artifact_sha256),
           "%s", g_bundle_sha256);
  snprintf(out_binding->sensor_interest_manifest_sha256,
           sizeof(out_binding->sensor_interest_manifest_sha256),
           "%s", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  snprintf(out_binding->sensor_interest_manifest_hash_mode,
           sizeof(out_binding->sensor_interest_manifest_hash_mode),
           "%s", "raw-json-v1-p0-artifact-sha256-zeroed");
  out_binding->rule_count = 1u;
  out_binding->snapshot_epoch = 1u;
  return 1;
}
int edr_p0_rule_ir_evaluate_record(const EdrBehaviorRecord *br,
                                   EdrP0RuleIrEvaluation *out_evaluation) {
  if (!br || !out_evaluation) {
    return 0;
  }
  memset(out_evaluation, 0, sizeof(*out_evaluation));
  if (!g_ir_evaluation_available) {
    return 0;
  }
  if (!edr_p0_rule_ir_get_binding(&out_evaluation->binding)) {
    return 0;
  }
  if (strcmp(br->process_name, "dedup-test.exe") != 0) {
    return 1;
  }
  out_evaluation->match_indices[0] = 0u;
  out_evaluation->match_count = 1u;
  out_evaluation->snapshot = (void *)1;
  return 1;
}
int edr_p0_rule_ir_evaluation_get_match(const EdrP0RuleIrEvaluation *evaluation,
                                        uint32_t index,
                                        EdrP0RuleIrMatch *out_match) {
  if (!evaluation || !out_match || !evaluation->snapshot || index != 0u ||
      evaluation->match_count != 1u || evaluation->match_indices[0] != 0u) {
    return 0;
  }
  memset(out_match, 0, sizeof(*out_match));
  snprintf(out_match->rule_id, sizeof(out_match->rule_id), "%s", "R-TEST-DEDUP");
  snprintf(out_match->title, sizeof(out_match->title), "%s", "test");
  snprintf(out_match->mitre_csv, sizeof(out_match->mitre_csv), "%s", "T1059");
  out_match->severity = 3;
  return 1;
}
void edr_p0_rule_ir_evaluation_free(EdrP0RuleIrEvaluation *evaluation) {
  if (!evaluation) return;
  memset(evaluation, 0, sizeof(*evaluation));
}
int edr_p0_rule_ir_matches(const char *rule_id, const char *process_name, const char *cmdline,
                           const char *parent_name, int process_chain_depth) {
  (void)rule_id;
  (void)process_name;
  (void)cmdline;
  (void)parent_name;
  (void)process_chain_depth;
  return 0;
}
int edr_p0_rule_ir_get_meta(const char *rule_id, const char **out_title, const char **out_mitre_csv) {
  if (strcmp(rule_id, "R-TEST-DEDUP") != 0) return -1;
  if (out_title) *out_title = "test";
  if (out_mitre_csv) *out_mitre_csv = "T1059";
  return 1;
}
int edr_p0_rule_ir_get_severity(const char *rule_id) { return strcmp(rule_id,"R-TEST-DEDUP")==0 ? 3 : 0; }
int edr_p0_rule_ir_process_create_count(void) { return 0; }
int edr_p0_rule_ir_process_create_id_at(int index, const char **out_id) {
  (void)index;
  if (out_id) {
    *out_id = "";
  }
  return 0;
}
int edr_p0_rule_ir_rule_count(void) { return 1; }
int edr_p0_rule_ir_rule_id_at(int index, const char **out_id) {
  if (index != 0) {
    return 0;
  }
  if (out_id) {
    *out_id = "R-TEST-DEDUP";
  }
  return 1;
}
int edr_p0_rule_ir_br_matches_index(const EdrBehaviorRecord *br, int index) { return br && index==0 && strcmp(br->process_name,"dedup-test.exe")==0; }
int edr_p0_rule_ir_br_matches_any(const EdrBehaviorRecord *br) {
  (void)br;
  return 0;
}
int edr_p0_rule_ir_is_interesting_remote_port(uint32_t port) {
  (void)port;
  return 0;
}
int edr_p0_rule_ir_is_interesting_process_name(const char *process_name) {
  (void)process_name;
  return 0;
}
void edr_p0_rule_ir_stats_record(int rule_idx, int hit) {
  (void)rule_idx;
  (void)hit;
}
void edr_p0_rule_ir_stats_dump(void) {}
void edr_p0_rule_ir_stats_init(void) {}

static void init_record(EdrBehaviorRecord *r) {
  edr_behavior_record_init(r);
  r->type = EDR_EVENT_PROCESS_CREATE;
  r->priority = 0u;
  r->pid = 4242u;
  r->process_start_key = 0x4242u;
  r->process_creation_filetime_100ns = 1u;
  snprintf(r->event_id, sizeof(r->event_id), "%s", "test-source-event");
  snprintf(r->image_path_canonical, sizeof(r->image_path_canonical),
           "%s", "C:\\Test\\dedup-test.exe");
  snprintf(r->detection_context, sizeof(r->detection_context),
           "%s", "{\"evidence\":{\"artifact\":{\"source\":\"process_image_section\",\"quality\":\"action_authoritative\",\"reason\":\"fixture\"},\"file_identity\":\"win-fileid-v1:0000000000004242:0123456789abcdef0123456789abcdef\"}}");
}

static int suppressed(const char *rule_id, EdrBehaviorRecord *r, const char *detail,
                      const char *want_reason) {
  const char *reason = NULL;
  int ok = edr_p0_test_should_suppress_known_false_positive(rule_id, r, detail, &reason);
  if (want_reason) {
    assert(ok);
    assert(reason != NULL);
    assert(strcmp(reason, want_reason) == 0);
  }
  return ok;
}

static void init_signed_edge_update(EdrBehaviorRecord *r) {
  init_record(r);
  snprintf(r->process_name, sizeof(r->process_name), "MicrosoftEdgeUpdate.exe");
  snprintf(r->exe_path, sizeof(r->exe_path),
           "C:\\Program Files (x86)\\Microsoft\\Temp\\EU8AA.tmp\\MicrosoftEdgeUpdate.exe");
  snprintf(r->exe_hash, sizeof(r->exe_hash),
           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  snprintf(r->cmdline, sizeof(r->cmdline),
           "\"C:\\Program Files (x86)\\Microsoft\\Temp\\EU8AA.tmp\\MicrosoftEdgeUpdate.exe\" /update /sessionid \"{788F1F69-597A-44E0-B28D-F001647BB3BB}\"");
  snprintf(r->parent_name, sizeof(r->parent_name), "MicrosoftEdgeUpdateSetup_X86_1.3.239.19.exe");
  snprintf(r->parent_path, sizeof(r->parent_path),
           "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\Install\\x\\MicrosoftEdgeUpdateSetup_X86_1.3.239.19.exe");
  snprintf(r->detection_context, sizeof(r->detection_context),
           "{\"evidence\":{\"signature\":{\"status\":\"verified\","
           "\"signer\":\"Microsoft Corporation\",\"revocation\":\"checked\","
           "\"quality\":\"verified_chain\",\"reason\":\"verified\"}}}");
}

static void test_edge_update_signed_chain_is_suppressed(void) {
  EdrBehaviorRecord r;
  init_signed_edge_update(&r);
  assert(suppressed("R-LOLBIN-010", &r, r.cmdline, "microsoft_edge_update_temp_baseline"));
}

static void test_edge_update_without_signature_is_not_suppressed(void) {
  EdrBehaviorRecord r;
  init_signed_edge_update(&r);
  r.detection_context[0] = '\0';
  snprintf(r.script_snippet, sizeof(r.script_snippet),
           "signature_status=verified signer=Microsoft Corporation");
  assert(!suppressed("R-LOLBIN-010", &r, r.cmdline, NULL));
}

static void test_edge_update_malicious_command_is_not_suppressed(void) {
  EdrBehaviorRecord r;
  init_signed_edge_update(&r);
  strncat(r.cmdline, " -EncodedCommand AAAA", sizeof(r.cmdline) - strlen(r.cmdline) - 1u);
  assert(!suppressed("R-LOLBIN-010", &r, r.cmdline, NULL));
}

static void test_fdsecurity_sensor_task_is_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  snprintf(r.process_name, sizeof(r.process_name), "powershell.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
  snprintf(r.cmdline, sizeof(r.cmdline),
           "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"C:\\Program Files\\FDSecurity\\FDSensorTaskLaunch.ps1\"");
  assert(suppressed("R-EXEC-002", &r, r.cmdline, "fdsecurity_self_installer_baseline"));
}

static void test_fdsecurity_setup_diagnostics_is_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  r.type = EDR_EVENT_FILE_WRITE;
  snprintf(r.process_name, sizeof(r.process_name), "powershell.exe");
  snprintf(r.file_path, sizeof(r.file_path),
           "C:\\ProgramData\\FDSecurity\\setup-ui\\install-diagnostics.zip");
  snprintf(r.cmdline, sizeof(r.cmdline),
           "powershell.exe -NoProfile -Command Compress-Archive -Path logs -DestinationPath C:\\ProgramData\\FDSecurity\\setup-ui\\install-diagnostics.zip");
  assert(suppressed("R-EXFIL-001", &r, r.cmdline, "fdsecurity_self_installer_baseline"));
}

static void test_fdsecurity_arbitrary_dll_is_not_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  snprintf(r.process_name, sizeof(r.process_name), "rundll32.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Windows\\System32\\rundll32.exe");
  snprintf(r.cmdline, sizeof(r.cmdline),
           "rundll32.exe C:\\ProgramData\\FDSecurity\\evil.dll,Start");
  assert(!suppressed("R-LOLBIN-002", &r, r.cmdline, NULL));
}

static void test_rundll32_davclnt_localhost_is_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  snprintf(r.process_name, sizeof(r.process_name), "rundll32.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Windows\\System32\\rundll32.exe");
  snprintf(r.cmdline, sizeof(r.cmdline),
           "rundll32.exe C:\\WINDOWS\\system32\\davclnt.dll,DavSetCookie localhost@9843 http://localhost:9843/Desktop.ini");
  assert(suppressed("R-LOLBIN-002", &r, r.cmdline, "rundll32_davclnt_loopback_baseline"));
}

static void test_rundll32_davclnt_127_is_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  snprintf(r.process_name, sizeof(r.process_name), "rundll32.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Windows\\System32\\rundll32.exe");
  snprintf(r.cmdline, sizeof(r.cmdline),
           "rundll32.exe davclnt.dll,DavSetCookie http://127.0.0.1:9843/edr-agent-win_3.2.155-windows-amd64-setup-ui");
  assert(suppressed("R-LOLBIN-002", &r, r.cmdline, "rundll32_davclnt_loopback_baseline"));
}

static void test_rundll32_davclnt_external_is_not_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  snprintf(r.process_name, sizeof(r.process_name), "rundll32.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Windows\\System32\\rundll32.exe");
  snprintf(r.cmdline, sizeof(r.cmdline),
           "rundll32.exe davclnt.dll,DavSetCookie http://evil.example/Desktop.ini");
  assert(!suppressed("R-LOLBIN-002", &r, r.cmdline, NULL));
}

static void test_rundll32_davclnt_remote_ip_is_not_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  snprintf(r.process_name, sizeof(r.process_name), "rundll32.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Windows\\System32\\rundll32.exe");
  snprintf(r.cmdline, sizeof(r.cmdline),
           "rundll32.exe davclnt.dll,DavSetCookie http://10.0.0.5/Desktop.ini");
  assert(!suppressed("R-LOLBIN-002", &r, r.cmdline, NULL));
}

static void test_rundll32_davclnt_localhost_suffix_is_not_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  snprintf(r.process_name, sizeof(r.process_name), "rundll32.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Windows\\System32\\rundll32.exe");
  snprintf(r.cmdline, sizeof(r.cmdline),
           "rundll32.exe davclnt.dll,DavSetCookie http://localhost.evil.example/Desktop.ini");
  assert(!suppressed("R-LOLBIN-002", &r, r.cmdline, NULL));
}

static void test_rundll32_davclnt_127_prefix_is_not_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  snprintf(r.process_name, sizeof(r.process_name), "rundll32.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Windows\\System32\\rundll32.exe");
  snprintf(r.cmdline, sizeof(r.cmdline),
           "rundll32.exe davclnt.dll,DavSetCookie http://127.0.0.10/Desktop.ini");
  assert(!suppressed("R-LOLBIN-002", &r, r.cmdline, NULL));
}

static void test_t1091_local_fixed_desktop_ini_is_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  r.type = EDR_EVENT_FILE_WRITE;
  snprintf(r.file_path, sizeof(r.file_path),
           "\\Device\\HarddiskVolume3\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\desktop.ini");
  assert(suppressed("R-MITRE-WIN-T1091", &r, r.file_path, "local_fixed_disk_desktop_ini"));
}

static void test_t1091_autorun_inf_is_not_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  r.type = EDR_EVENT_FILE_WRITE;
  snprintf(r.file_path, sizeof(r.file_path), "E:\\autorun.inf");
  assert(!suppressed("R-MITRE-WIN-T1091", &r, r.file_path, NULL));
}

static void test_searchprotocolhost_indexing_is_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  snprintf(r.process_name, sizeof(r.process_name), "SearchProtocolHost.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Windows\\System32\\SearchProtocolHost.exe");
  snprintf(r.cmdline, sizeof(r.cmdline),
           "\"C:\\Windows\\System32\\SearchProtocolHost.exe\" Global\\UsGthrFltPipeMssGthrPipe45_ Global\\UsGthrCtrlFltPipeMssGthrPipe45 1 -2147483646 \"Software\\Microsoft\\Windows Search\"");
  assert(suppressed("R-LOLBIN-010", &r, r.cmdline, "searchprotocolhost_indexing_baseline"));
}

static void test_searchprotocolhost_user_path_is_not_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  snprintf(r.process_name, sizeof(r.process_name), "SearchProtocolHost.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Users\\Public\\SearchProtocolHost.exe");
  snprintf(r.cmdline, sizeof(r.cmdline),
           "\"C:\\Users\\Public\\SearchProtocolHost.exe\" Global\\UsGthrFltPipeMssGthrPipe45_");
  assert(!suppressed("R-LOLBIN-010", &r, r.cmdline, NULL));
}

static void test_searchprotocolhost_without_pipe_is_not_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  snprintf(r.process_name, sizeof(r.process_name), "SearchProtocolHost.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Windows\\System32\\SearchProtocolHost.exe");
  snprintf(r.cmdline, sizeof(r.cmdline),
           "\"C:\\Windows\\System32\\SearchProtocolHost.exe\" powershell -enc AAAA");
  assert(!suppressed("R-LOLBIN-010", &r, r.cmdline, NULL));
}

static void test_searchprotocolhost_no_cmdline_system32_is_suppressed(void) {
  /* behavior_70 缺字段场景：无命令行但 System32 标准路径 + 进程名 → 按正常索引降级。 */
  EdrBehaviorRecord r;
  init_record(&r);
  snprintf(r.process_name, sizeof(r.process_name), "SearchProtocolHost.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Windows\\System32\\SearchProtocolHost.exe");
  /* cmdline 留空 */
  assert(suppressed("R-LOLBIN-010", &r, "", "searchprotocolhost_indexing_baseline"));
}

static void test_searchprotocolhost_no_cmdline_user_path_not_suppressed(void) {
  /* 无命令行但伪装到用户目录：仍不豁免，保留检测能力。 */
  EdrBehaviorRecord r;
  init_record(&r);
  snprintf(r.process_name, sizeof(r.process_name), "SearchProtocolHost.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Users\\Public\\SearchProtocolHost.exe");
  assert(!suppressed("R-LOLBIN-010", &r, "", NULL));
}

static void test_real_p0_dedup_metric_matrix(void) {
  assert(test_setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_DEDUP_SEC", "3", 1) == 0);
  edr_p0_rule_test_reset_dedup(); edr_p0_rule_test_set_monotonic_ms(1000u); g_emit_count = 0;
  EdrBehaviorRecord r; init_record(&r); r.pid=99001u; r.event_time_ns=10; r.type=EDR_EVENT_PROCESS_CREATE;
  snprintf(r.endpoint_id,sizeof(r.endpoint_id),"ep-dedup"); snprintf(r.process_name,sizeof(r.process_name),"dedup-test.exe");
  snprintf(r.event_id, sizeof(r.event_id), "dedup-source-a");
  snprintf(r.cmdline, sizeof(r.cmdline), "dedup-test.exe --source-a");
  edr_p0_rule_try_emit(&r); assert(g_emit_count==1);
  EdrP0EmitMetrics emit_metrics; edr_p0_rule_get_emit_metrics(&emit_metrics); assert(emit_metrics.user_subject_full == 1u && emit_metrics.user_subject_degraded == 0u);
  /* Different source events may legitimately share PID, timestamp, and
   * event type.  Neither is a secondary admission key. */
  snprintf(r.event_id, sizeof(r.event_id), "dedup-source-b");
  snprintf(r.cmdline, sizeof(r.cmdline), "dedup-test.exe --source-b");
  edr_p0_rule_try_emit(&r); assert(g_emit_count==2);
  assert(strstr(g_last_alert.user_subject_json, "dedup-source-b"));
  assert(strstr(g_last_alert.user_subject_json,
                "\"process_start_key\":\"16962\""));
  assert(strstr(g_last_alert.user_subject_json,
                "\"process_creation_filetime_100ns\":\"1\""));
  assert(strstr(g_last_alert.user_subject_json,
                "\"canonical_image_path\":\"C:\\\\Test\\\\dedup-test.exe\""));
  assert(strstr(g_last_alert.user_subject_json,
                "\"file_identity\":\"win-fileid-v1:0000000000004242:0123456789abcdef0123456789abcdef\""));
  /* Only an exact source-ID + semantic-payload replay is suppressed. */
  edr_p0_rule_try_emit(&r); assert(g_emit_count==2);
  EdrP0DedupMetrics m; edr_p0_rule_get_dedup_metrics(&m);
  assert(m.exact_suppressed==1u && m.suppressed_total==1u);
  assert(m.equal_quality_suppressed==0u && m.identity_upgrade_seen==0u &&
         m.lower_quality_suppressed==0u && m.intermediate_upgrade_suppressed==0u &&
         m.pre_rule_event_duplicates==0u);
}

static void test_p0_exact_replay_window_rearms_only_that_source(void) {
  EdrBehaviorRecord r;
  EdrP0DedupMetrics before, after;
  assert(test_setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_DEDUP_SEC", "3", 1) == 0);
  edr_p0_rule_test_reset_dedup(); edr_p0_rule_test_set_monotonic_ms(1000u); g_emit_count = 0;
  init_record(&r); r.pid = 99005u; r.event_time_ns = 100;
  snprintf(r.endpoint_id, sizeof(r.endpoint_id), "ep-window"); snprintf(r.process_name, sizeof(r.process_name), "dedup-test.exe");
  snprintf(r.event_id, sizeof(r.event_id), "window-source");
  snprintf(r.cmdline, sizeof(r.cmdline), "dedup-test.exe --window");
  edr_p0_rule_try_emit(&r); assert(g_emit_count == 1);
  edr_p0_rule_try_emit(&r); assert(g_emit_count == 1);
  edr_p0_rule_get_dedup_metrics(&before);
  edr_p0_rule_test_set_monotonic_ms(4001u); /* exactly beyond the 3s window */
  edr_p0_rule_try_emit(&r); assert(g_emit_count == 2);
  edr_p0_rule_get_dedup_metrics(&after);
  assert(after.exact_suppressed == before.exact_suppressed);
  assert(after.suppressed_total == before.suppressed_total);
}

static void test_p0_dedup_never_suppresses_semantic_mutations(void) {
  EdrBehaviorRecord r;
  EdrP0DedupMetrics m;
  assert(test_setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_DEDUP_SEC", "3", 1) == 0);
  edr_p0_rule_test_reset_dedup();
  edr_p0_rule_test_set_monotonic_ms(1200u);
  g_emit_count = 0;
  init_record(&r);
  r.pid = 99006u;
  r.event_time_ns = 106u;
  snprintf(r.endpoint_id, sizeof(r.endpoint_id), "ep-semantic");
  snprintf(r.process_name, sizeof(r.process_name), "dedup-test.exe");
  snprintf(r.event_id, sizeof(r.event_id), "same-source-id");
  snprintf(r.cmdline, sizeof(r.cmdline), "dedup-test.exe --semantic");
  edr_p0_rule_try_emit(&r); assert(g_emit_count == 1);

  /* All of these can alter an IR match, evidence authority, or alert meaning
   * while preserving the old coarse PID/timestamp/type tuple. */
  snprintf(r.reg_value_data, sizeof(r.reg_value_data), "evil-value");
  edr_p0_rule_try_emit(&r); assert(g_emit_count == 2);
  r.net_dport = 445u;
  edr_p0_rule_try_emit(&r); assert(g_emit_count == 3);
  snprintf(r.parent_name, sizeof(r.parent_name), "winword.exe");
  edr_p0_rule_try_emit(&r); assert(g_emit_count == 4);
  r.process_chain_depth = 81u;
  edr_p0_rule_try_emit(&r); assert(g_emit_count == 5);
  snprintf(r.image_path_canonical, sizeof(r.image_path_canonical), "C:\\Temp\\dedup-test.exe");
  edr_p0_rule_try_emit(&r); assert(g_emit_count == 6);
  snprintf(r.user_sid, sizeof(r.user_sid), "S-1-5-21-semantic");
  edr_p0_rule_try_emit(&r); assert(g_emit_count == 7);
  r.process_start_key = 0x99006u;
  r.process_creation_filetime_100ns = 0x12345678u;
  edr_p0_rule_try_emit(&r); assert(g_emit_count == 8);

  /* The final record has no semantic mutation, so it is the only suppressed
   * replay in this sequence. */
  edr_p0_rule_try_emit(&r); assert(g_emit_count == 8);
  edr_p0_rule_get_dedup_metrics(&m);
  assert(m.exact_suppressed == 1u && m.suppressed_total == 1u);
}

static void test_source_only_direct_contract_uses_production_builder(void) {
  EdrBehaviorRecord input;
  EdrBehaviorRecord out;
  size_t i;
  g_bundle_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  init_record(&input);
  input.pid = 99007u;
  snprintf(input.process_name, sizeof(input.process_name), "dedup-test.exe");
  snprintf(input.detection_context, sizeof(input.detection_context),
           "{\"evidence\":{\"hash\":{\"value\":\"abc\",\"quality\":\"captured\"}}}");
  for (i = 0u; i < edr_p0_source_only_reason_count(); ++i) {
    const EdrP0SourceOnlyReason *reason = &edr_p0_source_only_reason_table[i];
    if (reason->stage != EDR_P0_SOURCE_ONLY_STAGE_DIRECT) continue;
    assert(edr_p0_rule_test_build_source_only_direct_record(
               &input, "R-TEST-DEDUP", reason->reason, &out) == 1);
    assert(strstr(out.detection_context, "\"p0_disposition\":\"NOT_EVALUABLE\"") != NULL);
  assert(strstr(out.detection_context,
                "\"source_contract_version\":\"" EDR_P0_SOURCE_ONLY_CONTRACT_VERSION "\"") != NULL);
    assert(strstr(out.detection_context, "\"stage\":\"direct\"") != NULL);
    assert(strstr(out.detection_context, "\"rule_id\":\"R-TEST-DEDUP\"") != NULL);
    assert(strstr(out.detection_context,
                  "\"rules_bundle_sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"") != NULL);
    assert(strstr(out.detection_context, reason->reason) != NULL);
  }
  assert(edr_p0_rule_test_build_source_only_direct_record(
             &input, "R-TEST-DEDUP", "missing_process_generation", &out) == 0);
  assert(edr_p0_rule_test_build_source_only_direct_record(
             &input, EDR_P0_PROCESS_EVIDENCE_GATE, "p0_alert_queue_backpressure", &out) == 0);
}

static void test_file_read_source_only_binds_rejected_field(void) {
  static const char marker[] = "\"rejected_field\":\"canonical_path\"";
  EdrBehaviorRecord input;
  EdrBehaviorRecord out;
  char *bound_field;

  init_record(&input);
  input.type = EDR_EVENT_FILE_READ;
  input.pid = 99008u;
  input.event_time_ns = 123456789;
  input.file_key = 0xabcULL;
  input.process_start_key = 0x6104u;
  input.file_path[0] = '\0';
  snprintf(input.collector_evidence_gate, sizeof(input.collector_evidence_gate), "%s",
           EDR_P0_FILE_READ_METADATA_GATE);
  snprintf(input.collector_evidence_reason, sizeof(input.collector_evidence_reason), "%s",
           EDR_P0_FILE_READ_REASON_CANONICAL_PATH_UNRESOLVED);

  assert(edr_p0_rule_test_build_source_only_collector_evidence_record(&input, &out) == 1);
  assert(strstr(out.detection_context, marker) != NULL);
  assert(edr_p0_source_only_validate_record(&out) == 1);

  bound_field = strstr(out.detection_context, marker);
  assert(bound_field != NULL);
  bound_field[strlen("\"rejected_field\":\"")] = 'x';
  assert(edr_p0_source_only_validate_record(&out) == 0);
}

static void fill_escaped(char *out, size_t cap) {
  size_t i;
  assert(cap > 2u);
  for (i = 0; i + 2u < cap; i++) out[i] = (i % 4u == 0u) ? '"' : (i % 4u == 1u) ? '\\' : (i % 4u == 2u) ? '\n' : 'X';
  out[i] = '\0';
}

static void test_p0_full_context_counts_capped_value_once(void) {
  EdrBehaviorRecord r;
  EdrP0EmitMetrics before, after;
  assert(test_setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_DEDUP_SEC", "0", 1) == 0);
  edr_p0_rule_test_reset_dedup(); edr_p0_rule_test_set_monotonic_ms(1500u); g_emit_count = 0;
  init_record(&r); r.pid = 99003u; r.event_time_ns = 88;
  snprintf(r.process_name, sizeof(r.process_name), "dedup-test.exe");
  memset(r.cmdline, 'A', 600u); r.cmdline[600] = '\0'; /* full JSON remains below its 4090-byte cap. */
  edr_p0_rule_get_emit_metrics(&before);
  edr_p0_rule_try_emit(&r);
  edr_p0_rule_get_emit_metrics(&after);
  assert(g_emit_count == 1);
  assert(after.user_subject_full == before.user_subject_full + 1u);
  assert(after.user_subject_degraded == before.user_subject_degraded);
  assert(after.values_truncated == before.values_truncated + 1u);
  assert(after.alerts_with_optional_omission == before.alerts_with_optional_omission);
}

static void test_p0_abi_fields_mark_omission_without_losing_record(void) {
  EdrBehaviorRecord r;
  EdrP0EmitMetrics before, after;
  const char *marker = "[omitted: exceeds ABI field]";

  assert(test_setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_DEDUP_SEC", "0", 1) == 0);
  edr_p0_rule_test_reset_dedup();
  edr_p0_rule_test_set_monotonic_ms(1550u);
  g_emit_count = 0;
  init_record(&r);
  r.pid = 990031u;
  r.event_time_ns = 881u;
  snprintf(r.process_name, sizeof(r.process_name), "dedup-test.exe");
  memset(r.exe_path, 'P', sizeof(r.exe_path) - 1u);
  r.exe_path[sizeof(r.exe_path) - 1u] = '\0';
  memset(r.cmdline, 'C', sizeof(r.cmdline) - 1u);
  r.cmdline[sizeof(r.cmdline) - 1u] = '\0';

  edr_p0_rule_get_emit_metrics(&before);
  assert(edr_p0_rule_try_emit(&r) == 1);
  edr_p0_rule_get_emit_metrics(&after);
  assert(g_emit_count == 1);
  assert(strcmp(g_last_alert.process_path, marker) == 0);
  assert(strcmp(g_last_alert.cmdline, marker) == 0);
  assert(strcmp(g_last_record.exe_path, r.exe_path) == 0);
  assert(strcmp(g_last_record.cmdline, r.cmdline) == 0);
  assert(after.values_truncated >= before.values_truncated + 2u);
}

static void test_p0_push_failure_does_not_commit_emit_counters(void) {
  EdrBehaviorRecord r;
  EdrP0EmitMetrics before, after;
  EdrP0DedupMetrics dedup_before, dedup_after;
  int durable_before;

  assert(test_setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_DEDUP_SEC", "0", 1) == 0);
  assert(test_setenv("EDR_P0_MAX_EMITS_PER_MIN", "1", 1) == 0);
  edr_p0_rule_test_reset_dedup();
  edr_p0_rule_test_set_monotonic_ms(2500u);
  g_emit_count = 0;
  durable_before = atomic_load(&g_durable_count);
  g_combined_emit_allowed = 0;
  init_record(&r);
  r.pid = 99006u;
  r.event_time_ns = 105u;
  snprintf(r.process_name, sizeof(r.process_name), "dedup-test.exe");
  edr_p0_rule_get_emit_metrics(&before);
  edr_p0_rule_get_dedup_metrics(&dedup_before);
  assert(edr_p0_rule_try_emit(&r) == 0);
  edr_p0_rule_get_emit_metrics(&after);
  edr_p0_rule_get_dedup_metrics(&dedup_after);
  assert(g_emit_count == 0);
  assert(after.user_subject_full == before.user_subject_full &&
         after.user_subject_degraded == before.user_subject_degraded &&
         after.alerts_with_optional_omission == before.alerts_with_optional_omission &&
         after.values_truncated == before.values_truncated &&
         after.escape_overflow_values == before.escape_overflow_values &&
         after.minimal_failures == before.minimal_failures &&
         after.emitted_without_full_context == before.emitted_without_full_context);
  assert(after.source_only_backpressure_emitted == before.source_only_backpressure_emitted + 1u &&
         after.source_only_backpressure_failed == before.source_only_backpressure_failed);
  assert(atomic_load(&g_durable_count) == durable_before + 1);
  assert(strstr(g_last_record.detection_context,
                "\"p0_disposition\":\"NOT_EVALUABLE\"") != NULL &&
         strstr(g_last_record.detection_context,
                "\"reason\":\"p0_alert_queue_backpressure\"") != NULL);
  assert(memcmp(&dedup_before, &dedup_after, sizeof(dedup_before)) == 0);
  {
    char source_reason[96];
    assert(edr_p0_rule_source_only_capability_healthy(source_reason, sizeof(source_reason)) == 0);
    assert(strcmp(source_reason, "source_only_delivery_pending_ack") == 0);
  }

  /* The local source-only queue insert is not acknowledgement. A matching
   * central ACK must clear queue_meta before the same semantic source may
   * re-enter the alert/action path. */
  g_source_ack = 1;
  assert(edr_p0_rule_source_only_recover_after_queue_open() == 1);
  g_combined_emit_allowed = 1;
  assert(edr_p0_rule_try_emit(&r) == 1);
  assert(g_emit_count == 1);
  assert(strcmp(g_last_record.event_id, r.event_id) == 0);
  assert(test_setenv("EDR_P0_MAX_EMITS_PER_MIN", "0", 1) == 0);
}

static void test_p0_governor_suppression_is_not_queue_backpressure(void) {
  EdrBehaviorRecord r;
  EdrP0EmitMetrics before, after;
  int durable_before;

  assert(test_setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_DEDUP_SEC", "3", 1) == 0);
  assert(test_setenv("EDR_P0_MAX_EMITS_PER_MIN", "0", 1) == 0);
  assert(test_setenv("EDR_P0_MAX_EMITS_PER_MIN_PER_TENANT", "0", 1) == 0);
  edr_p0_rule_test_reset_dedup();
  edr_p0_rule_test_set_monotonic_ms(2550u);
  g_emit_count = 0;
  g_combined_emit_allowed = 1;
  g_combined_emit_outcome = EDR_BEHAVIOR_RECORD_ALERT_EMIT_GOVERNOR_SUPPRESSED;
  durable_before = atomic_load(&g_durable_count);
  init_record(&r);
  r.pid = 990061u;
  r.event_time_ns = 1051u;
  snprintf(r.event_id, sizeof(r.event_id), "governor-suppressed-source");
  snprintf(r.process_name, sizeof(r.process_name), "dedup-test.exe");

  edr_p0_rule_get_emit_metrics(&before);
  assert(edr_p0_rule_try_emit(&r) == 0);
  edr_p0_rule_get_emit_metrics(&after);
  assert(g_emit_count == 0);
  assert(atomic_load(&g_durable_count) == durable_before);
  assert(after.governor_suppressed == before.governor_suppressed + 1u);
  assert(after.source_only_backpressure_emitted == before.source_only_backpressure_emitted);
  assert(after.source_only_backpressure_failed == before.source_only_backpressure_failed);

  /* The P0 reservation is committed on suppression. Replaying the exact
   * source must not retry as a fake queue failure once the governor recovers. */
  g_combined_emit_outcome = EDR_BEHAVIOR_RECORD_ALERT_EMIT_ACCEPTED;
  assert(edr_p0_rule_try_emit(&r) == 0);
  assert(g_emit_count == 0);
}

static void test_p0_miss_does_not_emit_combined_frame(void) {
  EdrBehaviorRecord r;

  assert(test_setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_DEDUP_SEC", "0", 1) == 0);
  edr_p0_rule_test_reset_dedup();
  edr_p0_rule_test_set_monotonic_ms(2600u);
  g_emit_count = 0;
  g_combined_emit_allowed = 1;
  init_record(&r);
  r.pid = 99007u;
  r.event_time_ns = 107u;
  snprintf(r.process_name, sizeof(r.process_name), "ordinary-miss.exe");
  assert(edr_p0_rule_try_emit(&r) == 0);
  assert(g_emit_count == 0);
}

static void test_source_truncation_never_emits_after_coalescer_status(void) {
  EdrBehaviorRecord r;

  assert(test_setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_DEDUP_SEC", "0", 1) == 0);
  assert(test_setenv("EDR_P0_MAX_EMITS_PER_MIN", "0", 1) == 0);
  assert(test_setenv("EDR_P0_MAX_EMITS_PER_MIN_PER_TENANT", "0", 1) == 0);
  edr_p0_rule_test_reset_dedup();
  edr_p0_rule_test_set_monotonic_ms(2625u);
  g_emit_count = 0;
  g_combined_emit_allowed = 1;
  g_ir_ready = 1;
  g_ir_evaluation_available = 1;
  init_record(&r);
  r.pid = 990071u;
  r.event_time_ns = 1071u;
  snprintf(r.event_id, sizeof(r.event_id), "source-truncated-coalesced");
  /* `COALESCED` is an expected later status, but the preserved source list is
   * still authoritative.  Keep a would-match process name here to prove that
   * missing evidence is not treated as benign by the direct action lane. */
  snprintf(r.process_name, sizeof(r.process_name), "dedup-test.exe");
  snprintf(r.source_completeness, sizeof(r.source_completeness), "COALESCED");
  snprintf(r.source_truncated_fields, sizeof(r.source_truncated_fields),
           "source.process_name,source.exe_hash");
  assert(edr_p0_rule_try_emit(&r) == 0);
  assert(g_emit_count == 0);
}

static void test_p0_bundle_sha256_is_required_and_attached(void) {
  EdrBehaviorRecord r;

  assert(test_setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_DEDUP_SEC", "0", 1) == 0);
  edr_p0_rule_test_reset_dedup();
  edr_p0_rule_test_set_monotonic_ms(2650u);
  g_emit_count = 0;
  g_combined_emit_allowed = 1;
  init_record(&r);
  r.pid = 99008u;
  r.event_time_ns = 108u;
  snprintf(r.process_name, sizeof(r.process_name), "dedup-test.exe");
  g_bundle_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  assert(edr_p0_rule_try_emit(&r) == 1);
  assert(g_emit_count == 1);
  assert(strstr(g_last_alert.user_subject_json,
                "\"rules_bundle_sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"") != NULL);

  r.pid = 99009u;
  r.event_time_ns = 109u;
  g_bundle_sha256 = "";
  assert(edr_p0_rule_try_emit(&r) == 0);
  assert(g_emit_count == 1);

  r.pid = 99010u;
  r.event_time_ns = 110u;
  g_bundle_sha256 = "not-a-sha256";
  assert(edr_p0_rule_try_emit(&r) == 0);
  assert(g_emit_count == 1);
  g_bundle_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
}

static void test_ir_evaluation_failure_durably_preserves_source_without_alert(void) {
  EdrBehaviorRecord r;
  assert(test_setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_DEDUP_SEC", "3", 1) == 0);
  edr_p0_rule_test_reset_dedup();
  edr_p0_rule_test_set_monotonic_ms(2700u);
  g_ir_ready = 1;
  g_ir_evaluation_available = 0;
  g_emit_count = 0;
  g_durable_count = 0;
  g_durable_emit_allowed = 1;
  init_record(&r);
  r.pid = 99011u;
  r.event_time_ns = 111u;
  snprintf(r.process_name, sizeof(r.process_name), "powershell.exe");
  snprintf(r.cmdline, sizeof(r.cmdline), "powershell.exe -enc SQBFAFgA");
  /* A durable source-only gate is not an alert/combined frame. */
  assert(edr_p0_rule_try_emit(&r) == 0);
  assert(g_emit_count == 0);
  assert(g_durable_count == 1);
  assert(strstr(g_last_record.detection_context,
                "\"stage\":\"ruleset_evaluation\"") != NULL);
  assert(strstr(g_last_record.detection_context,
                "\"gate_id\":\"P0_RULESET_EVALUATION_GATE\"") != NULL);
  assert(strstr(g_last_record.detection_context,
                "\"reason\":\"p0_ir_evaluation_unavailable\"") != NULL);
  assert(strstr(g_last_record.detection_context, "\"rule_id\"") == NULL);
  assert(strstr(g_last_record.detection_context, "\"rules_bundle_") == NULL);
  /* Only a true replay of the same source evidence is coalesced. */
  assert(edr_p0_rule_try_emit(&r) == 0);
  assert(g_durable_count == 1);
  g_ir_evaluation_available = 1;
}

/* A source-only assertion is never discarded merely because SQLite is
 * temporarily unavailable.  The fixed retry handoff keeps the exact record,
 * and an overflow remains latched even after unrelated later commits. */
static void test_source_only_retry_lane_is_exact_and_overflow_latched(void) {
  EdrBehaviorRecord r;
  EdrBehaviorRecord committed;
  EdrP0EmitMetrics metrics;
  char reason[96];

  assert(test_setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  edr_p0_rule_test_reset_dedup();
  g_source_latch = 0;
  edr_p0_rule_test_set_monotonic_ms(1000u);
  g_ir_ready = 1;
  g_ir_evaluation_available = 0;
  g_durable_emit_allowed = 0;
  g_emit_count = 0;
  g_durable_count = 0;
  init_record(&r);
  r.pid = 99110u;
  r.event_time_ns = 1110u;
  snprintf(r.process_name, sizeof(r.process_name), "%s", "powershell.exe");
  snprintf(r.event_id, sizeof(r.event_id), "%s", "source-retry-exact");
  assert(edr_p0_rule_try_emit(&r) == 0);
  edr_p0_rule_get_emit_metrics(&metrics);
  assert(metrics.source_only_retry_pending == 1u);
  assert(metrics.source_only_terminal_unhealthy == 1);
  assert(edr_p0_rule_poll_source_only_durable_retry(&committed) == 0);

  g_durable_emit_allowed = 1;
  edr_p0_rule_test_set_monotonic_ms(1300u);
  assert(edr_p0_rule_poll_source_only_durable_retry(&committed) == 1);
  assert(strcmp(committed.event_id, "source-retry-exact") == 0);
  /* A local retry reached SQLite but cannot clear queue_meta.  Only the
   * simulated central ACK is allowed to make lifecycle recovery healthy. */
  g_source_ack = 1;
  assert(edr_p0_rule_source_only_recover_after_queue_open() == 1);
  assert(edr_p0_rule_source_only_capability_healthy(reason, sizeof(reason)) == 1);
  edr_p0_rule_get_emit_metrics(&metrics);
  assert(metrics.source_only_retry_pending == 0u);
  assert(metrics.source_only_retry_committed == 1u);

  edr_p0_rule_test_reset_dedup();
  edr_p0_rule_test_set_monotonic_ms(2000u);
  g_durable_emit_allowed = 0;
  for (unsigned i = 0u; i < 9u; ++i) {
    init_record(&r);
    r.pid = 99120u + i;
    r.event_time_ns = 1120u + i;
    snprintf(r.process_name, sizeof(r.process_name), "%s", "powershell.exe");
    snprintf(r.event_id, sizeof(r.event_id), "source-retry-overflow-%u", i);
    assert(edr_p0_rule_try_emit(&r) == 0);
  }
  edr_p0_rule_get_emit_metrics(&metrics);
  assert(metrics.source_only_retry_pending == 8u);
  assert(metrics.source_only_retry_capacity_exhausted == 1u);
  assert(metrics.source_only_terminal_unhealthy == 1);
  g_durable_emit_allowed = 1;
  edr_p0_rule_test_set_monotonic_ms(2300u);
  while (edr_p0_rule_poll_source_only_durable_retry(&committed)) { }
  assert(edr_p0_rule_source_only_capability_healthy(reason, sizeof(reason)) == 0);
  assert(strcmp(reason, "source_only_retry_capacity_exhausted") == 0);
  g_ir_evaluation_available = 1;
  /* Keep the intentionally latched test fault from affecting unrelated
   * enforcement cases below; production never invokes this test-only reset. */
  edr_p0_rule_test_reset_dedup();
}

/* A restart cannot reconstruct a RAM-only source assertion. Its only legal
 * recovery is a deterministic capability audit through the existing durable
 * queue; an initial enqueue failure leaves the latch/fuse in place. */
static void test_restart_latch_requires_durable_loss_audit(void) {
  EdrP0EmitMetrics metrics;
  char reason[96];
  EdrBehaviorRecord committed;

  edr_p0_rule_test_reset_dedup();
  edr_p0_rule_test_force_source_only_startup();
  g_source_latch = 1;
  g_ir_ready = 1;
  g_ir_evaluation_available = 1;
  g_durable_count = 0;
  g_durable_emit_allowed = 0;
  edr_p0_rule_source_only_set_runtime_identity("tenant-loss-audit", "endpoint-loss-audit");
  assert(edr_p0_rule_source_only_recover_after_queue_open() == 0);
  assert(g_source_latch == 1);
  assert(edr_p0_rule_source_only_capability_healthy(reason, sizeof(reason)) == 0);
  edr_p0_rule_get_emit_metrics(&metrics);
  assert(metrics.source_only_terminal_unhealthy == 1);
  assert(metrics.source_only_loss_detected == 1);

  g_durable_emit_allowed = 1;
  edr_p0_rule_test_set_monotonic_ms(8000u);
  assert(edr_p0_rule_poll_source_only_durable_retry(&committed) == 1);
  assert(committed.type == EDR_EVENT_CAPABILITY_AUDIT);
  assert(strstr(committed.detection_context,
                "\"stage\":\"source_only_delivery\"") != NULL);
  assert(strstr(committed.detection_context,
                "\"gate_id\":\"P0_SOURCE_ONLY_DURABILITY_GATE\"") != NULL);
  assert(strstr(committed.detection_context, "\"loss_detected\":true") != NULL);
  assert(strstr(committed.detection_context, "\"rules_bundle_") == NULL);
  assert(strstr(committed.detection_context, "\"rule_id\"") == NULL);
  g_source_ack = 1;
  assert(edr_p0_rule_source_only_recover_after_queue_open() == 1);
  assert(g_source_latch == 0);
  assert(edr_p0_rule_source_only_capability_healthy(reason, sizeof(reason)) == 1);
  assert(g_durable_count == 1);
}

/* Every event group represented by the published P0 IR must leave a durable
 * source-only capability disposition when the authenticated snapshot is not
 * available.  Deliberately make FILE_READ incomplete and registry otherwise
 * unattributed: this proves the gate runs before normal completeness and
 * attribution shedding, while still never creating an alert or action. */
static void test_ir_not_ready_durably_preserves_every_p0_event_group(void) {
  static const EdrEventType event_types[] = {
      EDR_EVENT_PROCESS_CREATE,
      EDR_EVENT_FILE_READ,
      EDR_EVENT_FILE_WRITE,
      EDR_EVENT_NET_CONNECT,
      EDR_EVENT_REG_SET_VALUE,
  };
  size_t i;
  assert(test_setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_DEDUP_SEC", "3", 1) == 0);
  edr_p0_rule_test_reset_dedup();
  edr_p0_rule_test_set_monotonic_ms(2800u);
  g_ir_ready = 0;
  g_ir_evaluation_available = 1;
  g_emit_count = 0;
  g_durable_count = 0;
  g_durable_emit_allowed = 1;

  for (i = 0u; i < sizeof(event_types) / sizeof(event_types[0]); ++i) {
    EdrBehaviorRecord r;
    init_record(&r);
    r.type = event_types[i];
    r.pid = 99020u + (uint32_t)i;
    r.event_time_ns = 120 + (int64_t)i;
    snprintf(r.event_id, sizeof(r.event_id), "ir-not-ready-%zu", i);
    if (r.type == EDR_EVENT_REG_SET_VALUE) {
      r.pid = 0u;
      snprintf(r.reg_attribution, sizeof(r.reg_attribution), "%s", "unavailable");
    }
    if (r.type == EDR_EVENT_FILE_READ) {
      r.file_path[0] = '\0';
      r.process_start_key = 0u;
      r.process_creation_filetime_100ns = 0u;
    }
    assert(edr_p0_rule_try_emit(&r) == 0);
    assert(atomic_load(&g_emit_count) == 0);
    assert(atomic_load(&g_durable_count) == (int)i + 1);
    assert(strstr(g_last_record.detection_context,
                  "\"stage\":\"ruleset_evaluation\"") != NULL);
    assert(strstr(g_last_record.detection_context,
                  "\"gate_id\":\"P0_RULESET_EVALUATION_GATE\"") != NULL);
    assert(strstr(g_last_record.detection_context,
                  "\"reason\":\"p0_ir_not_ready\"") != NULL);
    assert(strstr(g_last_record.detection_context, "\"rule_id\"") == NULL);
    assert(strstr(g_last_record.detection_context, "\"rules_bundle_") == NULL);
    /* Exact replay is idempotent even while no active authority exists. */
    assert(edr_p0_rule_try_emit(&r) == 0);
    assert(atomic_load(&g_durable_count) == (int)i + 1);
  }
  g_ir_ready = 1;
}

/* A FileRead attribution fault must fail closed for file rules without
 * disabling an independently authoritative process rule. The persistent
 * global latch remains visible for operations/upgrade safety; only runtime
 * rule admission is scoped to the known owning event family. */
static void test_source_only_fault_is_scoped_to_owning_event_family(void) {
  EdrBehaviorRecord file_source;
  EdrBehaviorRecord process_match;
  EdrBehaviorRecord file_match;
  EdrP0EmitMetrics metrics;
  char reason[96];
  deferred_fake_reset();

  assert(test_setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_DEDUP_SEC", "0", 1) == 0);
  edr_p0_rule_test_reset_dedup();
  edr_p0_rule_test_set_monotonic_ms(2850u);
  edr_p0_rule_source_only_set_runtime_identity("tenant_default","ep-local");
  g_source_latch = 0;
  g_source_ack = 0;
  g_durable_emit_allowed = 1;
  g_combined_emit_allowed = 1;
  g_emit_count = 0;
  g_durable_count = 0;
  g_ir_ready = 1;
  g_ir_evaluation_available = 0;

  init_record(&file_source);
  file_source.type = EDR_EVENT_FILE_READ;
  file_source.pid = 99030u;
  file_source.event_time_ns = 130u;
  snprintf(file_source.event_id, sizeof(file_source.event_id), "%s", "file-source-only");
  snprintf(file_source.process_name, sizeof(file_source.process_name), "%s", "reader.exe");
  assert(edr_p0_rule_try_emit(&file_source) == 0);
  assert(atomic_load(&g_durable_count) == 1);
  assert(edr_p0_rule_source_only_capability_healthy(reason, sizeof(reason)) == 0);
  assert(edr_p0_rule_source_only_capability_healthy_for_event(
             EDR_EVENT_FILE_READ, reason, sizeof(reason)) == 0);
  assert(edr_p0_rule_source_only_capability_healthy_for_event(
             EDR_EVENT_PROCESS_CREATE, reason, sizeof(reason)) == 1);
  edr_p0_rule_get_emit_metrics(&metrics);
  assert(metrics.source_only_unhealthy_families == 2u);

  g_ir_evaluation_available = 1;
  init_record(&process_match);
  process_match.pid = 99031u;
  process_match.event_time_ns = 131u;
  snprintf(process_match.event_id, sizeof(process_match.event_id), "%s", "process-after-file-fault");
  snprintf(process_match.process_name, sizeof(process_match.process_name), "%s", "dedup-test.exe");
  assert(edr_p0_rule_try_emit(&process_match) == 1);
  assert(atomic_load(&g_emit_count) == 1);

  file_match = process_match;
  file_match.type = EDR_EVENT_FILE_READ;
  file_match.pid = 99032u;
  file_match.event_time_ns = 132u;
  snprintf(file_match.event_id, sizeof(file_match.event_id), "%s", "file-after-file-fault");
  assert(edr_p0_rule_try_emit(&file_match) == 0);
  assert(atomic_load(&g_emit_count) == 1);
  assert(deferred_count==1u && deferred_completions==0u);
  assert(edr_p0_rule_try_emit(&file_match)==0 && deferred_count==1u);
  assert(edr_p0_rule_poll_deferred_match()==0); /* cannot bypass the gate */

  g_source_ack = 1;
  assert(edr_p0_rule_source_only_recover_after_queue_open() == 1);
  assert(edr_p0_rule_source_only_capability_healthy_for_event(
             EDR_EVENT_FILE_READ, reason, sizeof(reason)) == 1);
  /* Healthy incoming exact replay must not race the retained owner. */
  assert(edr_p0_rule_try_emit(&file_match)==0 && deferred_completions==0u);
  edr_p0_rule_test_set_monotonic_ms(3000u);
  assert(test_setenv("EDR_P0_DIRECT_EMIT","0",1)==0);
  assert(edr_p0_rule_poll_deferred_match()==0 && deferred_completions==0u);
  assert(test_setenv("EDR_P0_DIRECT_EMIT","1",1)==0);
  assert(edr_p0_rule_poll_deferred_match()==1);
  assert(deferred_completions==1u && atomic_load(&g_emit_count)==2);
  assert(!strcmp(g_last_record.event_id,file_match.event_id));
  assert(g_last_record.process_start_key==file_match.process_start_key);
  /* Volatile dedup loss (restart) cannot reopen the completed durable owner. */
  edr_p0_rule_test_reset_dedup();
  assert(edr_p0_rule_try_emit(&file_match)==0);
  assert(edr_p0_rule_poll_deferred_match()==0 && atomic_load(&g_emit_count)==2);
  deferred_fake_reset();
}

static void retain_deferred_fixture(EdrBehaviorRecord *r, const char *event_id) {
  EdrBehaviorRecord source;
  deferred_fake_reset();
  edr_p0_rule_test_reset_dedup();
  edr_p0_rule_source_only_set_runtime_identity("tenant_default","ep-local");
  edr_p0_rule_test_set_monotonic_ms(3000u);
  g_ir_ready=1; g_ir_evaluation_available=0; g_source_latch=0; g_source_ack=0;
  g_durable_emit_allowed=1; g_combined_emit_allowed=1;
  g_combined_emit_outcome=EDR_BEHAVIOR_RECORD_ALERT_EMIT_ACCEPTED;
  g_emit_count=0;
  atomic_store(&g_adaptive_raises,0);
  init_record(&source); source.type=EDR_EVENT_FILE_READ;
  strcpy(source.event_id,"deferred-gate-source");
  assert(edr_p0_rule_try_emit(&source)==0);
  g_ir_evaluation_available=1;
  init_record(r); r->type=EDR_EVENT_FILE_WRITE; r->pid=77001u;
  snprintf(r->event_id,sizeof(r->event_id),"%s",event_id);
  strcpy(r->process_name,"dedup-test.exe");
  strcpy(r->parent_name,"captured-parent.exe");
  strcpy(r->parent_path,"C:\\captured-parent.exe");
  r->process_start_key=UINT64_C(11540474045138508);
  r->event_time_ns=INT64_C(1789309942708556400);
  assert(edr_p0_rule_try_emit(r)==0);
  assert(deferred_count==1u && g_emit_count==0);
}

static void test_deferred_retry_ruleset_change_and_action_owner(void) {
  EdrBehaviorRecord record;
  EdrConfig alert_policy={0}, block_policy={0};
  const char *original_sha=g_bundle_sha256;
  alert_policy.policy_v2.script_mode=EDR_POLICY_MODE_ALERT;
  block_policy.policy_v2.script_mode=EDR_POLICY_MODE_BLOCK;
  edr_policy_v2_configure(&alert_policy);
  assert(test_setenv("EDR_P0_DIRECT_EMIT","1",1)==0);
  assert(test_setenv("EDR_P0_DEDUP_SEC","0",1)==0);
  retain_deferred_fixture(&record,"deferred-commit-retry");
  g_source_ack=1;
  assert(edr_p0_rule_source_only_recover_after_queue_open()==1);
  deferred_complete_fails=1;
  assert(edr_p0_rule_poll_deferred_match()==0);
  assert(deferred_completions==0u && deferred_retries==1u && g_emit_count==0);
  assert(atomic_load(&g_adaptive_raises)==0);
  deferred_complete_fails=0;
  g_source_ack=1;
  assert(edr_p0_rule_source_only_recover_after_queue_open()==1);
  edr_p0_rule_test_set_monotonic_ms(3500u);
  assert(edr_p0_rule_poll_deferred_match()==1);
  assert(deferred_completions==1u && g_emit_count==1);
  assert(atomic_load(&g_adaptive_raises)==1);
  edr_p0_rule_test_set_monotonic_ms(3700u);
  assert(edr_p0_rule_poll_deferred_match()==0 && atomic_load(&g_adaptive_raises)==1);
  assert(!strcmp(g_last_record.parent_path,record.parent_path));
  assert(g_last_record.event_time_ns==record.event_time_ns);

  retain_deferred_fixture(&record,"deferred-rule-change");
  g_source_ack=1;
  assert(edr_p0_rule_source_only_recover_after_queue_open()==1);
  g_bundle_sha256="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  assert(edr_p0_rule_poll_deferred_match()==0);
  assert(deferred_rows[0].state==2 && deferred_rows[0].payload && g_emit_count==0);
  g_bundle_sha256=original_sha;

  retain_deferred_fixture(&record,"deferred-admission-boundary");
  deferred_write_fails=1;
  strcpy(record.event_id,"deferred-capacity-rejected");
  assert(edr_p0_rule_try_emit(&record)==0);
  EdrP0EmitMetrics loss_metrics;
  edr_p0_rule_get_emit_metrics(&loss_metrics);
  assert(loss_metrics.source_only_loss_detected && loss_metrics.source_only_terminal_unhealthy);
  assert(!strcmp(loss_metrics.source_only_terminal_reason,"p0_deferred_admission_failed"));
  assert(deferred_count==1u && deferred_rows[0].state==0); /* no overwrite */

  edr_policy_v2_configure(&block_policy);
  atomic_store(&g_enforcement_side_effects,0);
  edr_policy_enforcement_test_set_execute_hook(test_enforcement_execute_hook);
  retain_deferred_fixture(&record,"deferred-action-owner");
  assert(edr_p0_rule_poll_deferred_match()==0);
  assert(atomic_load(&g_enforcement_side_effects)==0);
  g_source_ack=1;
  assert(edr_p0_rule_source_only_recover_after_queue_open()==1);
  edr_p0_rule_test_set_monotonic_ms(3500u);
  deferred_complete_fails=1; /* journal commits but snapshot completion fails */
  assert(edr_p0_rule_poll_deferred_match()==1);
  assert(atomic_load(&g_enforcement_side_effects)==1 && deferred_completions==0u);
  edr_p0_rule_test_reset_dedup(); /* losing the volatile owner must not act again */
  deferred_complete_fails=0;
  edr_p0_rule_test_set_monotonic_ms(4000u);
  assert(edr_p0_rule_poll_deferred_match()==0 && deferred_completions==0u);
  edr_p0_rule_source_only_set_runtime_identity("tenant_default","ep-local");
  assert(edr_p0_rule_poll_deferred_match()==0);
  assert(atomic_load(&g_enforcement_side_effects)==1 && deferred_completions==1u);
  edr_policy_enforcement_test_set_execute_hook(NULL);
  edr_policy_v2_configure(&alert_policy);
  deferred_fake_reset();
}

static void test_deferred_storage_faults_are_retained_and_backed_off(void) {
  EdrBehaviorRecord record;
  EdrP0EmitMetrics metrics;
  const char *original_sha = g_bundle_sha256;
  retain_deferred_fixture(&record,"deferred-lookup-fault");
  g_source_ack=1;
  assert(edr_p0_rule_source_only_recover_after_queue_open()==1);
  strcpy(record.event_id,"healthy-lookup-fault");
  deferred_contains_fails=1;
  assert(edr_p0_rule_try_emit(&record)==0);
  assert(deferred_count==2u && deferred_rows[1].state==0 && g_emit_count==0);
  deferred_contains_fails=0;

  retain_deferred_fixture(&record,"deferred-fail-write-fault");
  g_source_ack=1;
  assert(edr_p0_rule_source_only_recover_after_queue_open()==1);
  g_bundle_sha256="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
  deferred_fail_fails=1;
  assert(edr_p0_rule_poll_deferred_match()==0 && deferred_peeks==1u);
  assert(deferred_rows[0].state==0 && deferred_rows[0].payload);
  edr_p0_rule_get_emit_metrics(&metrics);
  assert(metrics.deferred_storage_failures==1u && metrics.deferred_retry_degraded);
  edr_p0_rule_test_set_monotonic_ms(3999u);
  assert(edr_p0_rule_poll_deferred_match()==0 && deferred_peeks==1u);
  edr_p0_rule_test_set_monotonic_ms(4000u);
  assert(edr_p0_rule_poll_deferred_match()==0 && deferred_peeks==2u);
  deferred_fail_fails=0;
  edr_p0_rule_test_set_monotonic_ms(5999u);
  assert(edr_p0_rule_poll_deferred_match()==0 && deferred_peeks==2u);
  edr_p0_rule_test_set_monotonic_ms(6000u);
  assert(edr_p0_rule_poll_deferred_match()==0 && deferred_rows[0].state==2);
  edr_p0_rule_get_emit_metrics(&metrics);
  assert(metrics.deferred_storage_failures==2u && !metrics.deferred_retry_degraded);
  g_bundle_sha256=original_sha;

  retain_deferred_fixture(&record,"deferred-retry-write-fault");
  g_source_ack=1;
  assert(edr_p0_rule_source_only_recover_after_queue_open()==1);
  g_ir_evaluation_available=0;
  deferred_retry_fails=1;
  assert(edr_p0_rule_poll_deferred_match()==0 && deferred_retries==1u);
  edr_p0_rule_test_set_monotonic_ms(3999u);
  assert(edr_p0_rule_poll_deferred_match()==0 && deferred_retries==1u);
  assert(deferred_rows[0].state==0 && deferred_rows[0].payload);
  deferred_retry_fails=0;
  g_ir_evaluation_available=1;
  edr_p0_rule_test_set_monotonic_ms(4000u);
  assert(edr_p0_rule_poll_deferred_match()==1 && deferred_completions==1u);
  edr_p0_rule_get_emit_metrics(&metrics);
  assert(metrics.deferred_storage_failures==1u && !metrics.deferred_retry_degraded);
  deferred_fake_reset();
}

static void test_script_matches_obey_process_family_gate(void) {
  static const EdrEventType script_types[] = {EDR_EVENT_SCRIPT_POWERSHELL,EDR_EVENT_SCRIPT_WMI};
  for (size_t i=0;i<sizeof(script_types)/sizeof(script_types[0]);++i) {
    EdrBehaviorRecord source, record;
    deferred_fake_reset();
    edr_p0_rule_test_reset_dedup();
    edr_p0_rule_source_only_set_runtime_identity("tenant_default","ep-local");
    edr_p0_rule_test_set_monotonic_ms(5000u);
    g_source_latch=0; g_source_ack=0; g_durable_emit_allowed=1;
    g_ir_ready=1; g_ir_evaluation_available=0; g_emit_count=0;
    atomic_store(&g_adaptive_raises,0);
    init_record(&source);
    strcpy(source.process_name,"dedup-test.exe");
    assert(edr_p0_rule_try_emit(&source)==0);
    assert(!edr_p0_rule_source_only_capability_healthy_for_event(script_types[i],NULL,0u));
    g_ir_evaluation_available=1;
    init_record(&record);
    record.type=script_types[i];
    strcpy(record.process_name,"dedup-test.exe");
    snprintf(record.event_id,sizeof(record.event_id),"script-family-gate-%zu",i);
    assert(edr_p0_rule_try_emit(&record)==0 && deferred_count==1u && g_emit_count==0);
    assert(edr_p0_rule_poll_deferred_match()==0 && atomic_load(&g_adaptive_raises)==0);
    g_source_ack=1;
    assert(edr_p0_rule_source_only_recover_after_queue_open()==1);
    edr_p0_rule_test_set_monotonic_ms(5100u);
    assert(edr_p0_rule_poll_deferred_match()==1 && deferred_completions==1u);
    assert(atomic_load(&g_adaptive_raises)==1);
  }
  deferred_fake_reset();
}

static void test_p0_escape_overflow_degrades_without_silent_core_loss(void) {
  EdrBehaviorRecord r;
  EdrP0EmitMetrics before, after;
  assert(test_setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_DEDUP_SEC", "0", 1) == 0);
  edr_p0_rule_test_reset_dedup(); edr_p0_rule_test_set_monotonic_ms(1700u); g_emit_count = 0;
  init_record(&r); r.pid = 99004u; r.event_time_ns = 89;
  snprintf(r.process_name, sizeof(r.process_name), "dedup-test.exe");
  snprintf(r.event_id, sizeof(r.event_id), "escape-core-event");
  snprintf(r.user_sid, sizeof(r.user_sid), "S-1-5-18");
  snprintf(r.identity_source, sizeof(r.identity_source), "target_4688");
  snprintf(r.identity_quality, sizeof(r.identity_quality), "target_4688");
  memset(r.cmdline, '\1', 480u); r.cmdline[480] = '\0'; /* raw == max, escaped output exceeds esc buffer. */
  edr_p0_rule_get_emit_metrics(&before);
  edr_p0_rule_try_emit(&r);
  edr_p0_rule_get_emit_metrics(&after);
  assert(g_emit_count == 1);
  assert(strstr(g_last_alert.user_subject_json, "\"context_degraded\":true") != NULL);
  assert(strstr(g_last_alert.user_subject_json, "escape-core-event") != NULL);
  assert(strstr(g_last_alert.user_subject_json, "S-1-5-18") != NULL);
  assert(after.user_subject_full == before.user_subject_full);
  assert(after.user_subject_degraded == before.user_subject_degraded + 1u);
  assert(after.escape_overflow_values == before.escape_overflow_values + 1u);
  assert(after.values_truncated == before.values_truncated);
}

static void test_p0_user_subject_overflow_degrades_without_losing_alert(void) {
  EdrBehaviorRecord r;
  EdrP0EmitMetrics before, after;
  uint64_t expected_full_caps;
  uint64_t expected_abi_omissions;
  assert(test_setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_DEDUP_SEC", "0", 1) == 0);
  edr_p0_rule_test_reset_dedup(); edr_p0_rule_test_set_monotonic_ms(2000u); g_emit_count = 0;
  init_record(&r); r.pid = 99002u; r.event_time_ns = 99; r.type = EDR_EVENT_PROCESS_CREATE;
  snprintf(r.process_name, sizeof(r.process_name), "dedup-test.exe");
  snprintf(r.endpoint_id, sizeof(r.endpoint_id), "ep-overflow");
  snprintf(r.tenant_id, sizeof(r.tenant_id), "tenant-overflow");
  snprintf(r.event_id, sizeof(r.event_id), "source-event-\"\\\\-id");
  snprintf(r.user_sid, sizeof(r.user_sid), "S-1-5-21-quoted\\\\sid");
  snprintf(r.identity_quality, sizeof(r.identity_quality), "target_4688");
  snprintf(r.identity_source, sizeof(r.identity_source), "target_4688");
  fill_escaped(r.cmdline, sizeof(r.cmdline)); fill_escaped(r.parent_cmdline, sizeof(r.parent_cmdline));
  fill_escaped(r.powershell_script_block, sizeof(r.powershell_script_block)); fill_escaped(r.reg_old_value_data, sizeof(r.reg_old_value_data));
  fill_escaped(r.exe_path, sizeof(r.exe_path)); fill_escaped(r.parent_path, sizeof(r.parent_path));
  fill_escaped(r.current_directory, sizeof(r.current_directory)); fill_escaped(r.username, sizeof(r.username));
  fill_escaped(r.domain, sizeof(r.domain)); fill_escaped(r.creator_username, sizeof(r.creator_username));
  fill_escaped(r.creator_domain, sizeof(r.creator_domain)); fill_escaped(r.creator_sid, sizeof(r.creator_sid));
  /* exe_path is also compacted at a smaller limit. This exact full-pass count
   * proves compact reconstruction does not count it a second time. */
  expected_full_caps = (uint64_t)(strlen(r.cmdline) > 480u) +
                       (uint64_t)(strlen(r.parent_cmdline) > 480u) +
                       (uint64_t)(strlen(r.powershell_script_block) > 360u) +
                       (uint64_t)(strlen(r.reg_old_value_data) > 220u) +
                       (uint64_t)(strlen(r.exe_path) > 400u) +
                       (uint64_t)(strlen(r.parent_path) > 400u) +
                       (uint64_t)(strlen(r.current_directory) > 240u) +
                       (uint64_t)(strlen(r.username) > 160u) +
                       (uint64_t)(strlen(r.domain) > 128u) +
                       (uint64_t)(strlen(r.creator_username) > 160u) +
                       (uint64_t)(strlen(r.creator_domain) > 160u) +
                       (uint64_t)(strlen(r.creator_sid) > 256u);
  expected_abi_omissions =
      (uint64_t)(strlen(r.exe_path) >= sizeof(g_last_alert.process_path)) +
      (uint64_t)(strlen(r.cmdline) >= sizeof(g_last_alert.cmdline));
  edr_p0_rule_get_emit_metrics(&before);
  edr_p0_rule_try_emit(&r);
  edr_p0_rule_get_emit_metrics(&after);
  assert(g_emit_count == 1);
  assert(strlen(g_last_alert.user_subject_json) < sizeof(g_last_alert.user_subject_json));
  assert(strstr(g_last_alert.user_subject_json, "\"context_degraded\":true") != NULL);
  assert(strstr(g_last_alert.user_subject_json, "\"source_event_id\":\"source-event-\\\"\\\\\\\\-id\"") != NULL);
  assert(strstr(g_last_alert.user_subject_json, "\"user_sid\":\"S-1-5-21-quoted\\\\\\\\sid\"") != NULL);
  assert(strstr(g_last_alert.user_subject_json, "\"identity_quality\":\"target_4688\"") != NULL);
  assert(strstr(g_last_alert.user_subject_json,
                "\"process_start_key\":\"16962\"") != NULL);
  assert(strstr(g_last_alert.user_subject_json,
                "\"process_creation_filetime_100ns\":\"1\"") != NULL);
  assert(strstr(g_last_alert.user_subject_json,
                "\"file_identity\":\"win-fileid-v1:0000000000004242:0123456789abcdef0123456789abcdef\"") != NULL);
  assert(strstr(g_last_alert.user_subject_json, "powershell_script_block") == NULL);
  assert(strcmp(g_last_alert.process_path, "[omitted: exceeds ABI field]") == 0);
  assert(strcmp(g_last_alert.cmdline, "[omitted: exceeds ABI field]") == 0);
  assert(after.user_subject_degraded == before.user_subject_degraded + 1u);
  assert(after.emitted_without_full_context == before.emitted_without_full_context + 1u);
  assert(after.alerts_with_optional_omission == before.alerts_with_optional_omission + 1u);
  assert(after.values_truncated == before.values_truncated + expected_full_caps + expected_abi_omissions);
  assert(after.minimal_failures == before.minimal_failures);
}

#if !defined(_WIN32)
typedef struct {
  EdrBehaviorRecord record;
  atomic_int *start;
  int emitted;
} ConcurrentEmit;

static void *emit_same_p0_record(void *arg) {
  ConcurrentEmit *work = arg;
  while (atomic_load_explicit(work->start, memory_order_acquire) == 0) { }
  work->emitted = edr_p0_rule_try_emit(&work->record);
  return NULL;
}

static void test_p0_pending_claim_allows_one_same_key(void) {
  enum { workers = 20 };
  pthread_t threads[workers];
  ConcurrentEmit work[workers];
  atomic_int start = 0;
  int emitted = 0;
  assert(test_setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_DEDUP_SEC", "3", 1) == 0);
  edr_p0_rule_test_reset_dedup();
  edr_p0_rule_test_set_monotonic_ms(3000u);
  g_emit_count = 0;
  g_combined_emit_allowed = 1;
  for (int i = 0; i < workers; i++) {
    memset(&work[i], 0, sizeof(work[i]));
    init_record(&work[i].record);
    work[i].record.pid = 99100u;
    work[i].record.event_time_ns = 400u;
    snprintf(work[i].record.endpoint_id, sizeof(work[i].record.endpoint_id), "ep-concurrent");
    snprintf(work[i].record.process_name, sizeof(work[i].record.process_name), "dedup-test.exe");
    work[i].start = &start;
    assert(pthread_create(&threads[i], NULL, emit_same_p0_record, &work[i]) == 0);
  }
  atomic_store_explicit(&start, 1, memory_order_release);
  for (int i = 0; i < workers; i++) {
    assert(pthread_join(threads[i], NULL) == 0);
    emitted += work[i].emitted;
  }
  assert(emitted == 1);
  assert(g_emit_count == 1);
}

static void wait_for_delayed_combined(void) {
  for (int spins = 0; spins < 5000 && atomic_load(&g_combined_inflight) != 1; ++spins) {
    struct timespec pause = {0, 1000000L};
    (void)nanosleep(&pause, NULL);
  }
  assert(atomic_load(&g_combined_inflight) == 1);
}

/* A failed producer from an expired rate window must not return a newer
 * window's token.  This is deliberately concurrent: A keeps its reservation
 * while B rolls the clock and commits, then A's queue failure rolls back. */
static void test_rate_rollback_does_not_reopen_new_window(void) {
  EdrConfig alert_policy;
  EdrBehaviorRecord a, b, c;
  ConcurrentEmit delayed;
  pthread_t delayed_thread;
  atomic_int start = 0;

  memset(&alert_policy, 0, sizeof(alert_policy));
  alert_policy.policy_v2.script_mode = EDR_POLICY_MODE_ALERT;
  edr_policy_v2_configure(&alert_policy);
  assert(test_setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_DEDUP_SEC", "0", 1) == 0);
  assert(test_setenv("EDR_P0_MAX_EMITS_PER_MIN", "1", 1) == 0);
  assert(test_setenv("EDR_P0_MAX_EMITS_PER_MIN_PER_TENANT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_MAX_EMITS_PER_MIN_PER_ENDPOINT", "1", 1) == 0);
  edr_p0_rule_test_reset_dedup();
  edr_p0_rule_test_set_monotonic_ms(1000u);
  g_emit_count = 0;
  g_combined_emit_allowed = 1;
  g_block_combined_event_id = "rate-old-window";
  atomic_store(&g_block_combined, 1);
  atomic_store(&g_combined_inflight, 0);
  atomic_store(&g_combined_release, 0);
  atomic_store(&g_combined_fail_after_release, 0);

  init_record(&a);
  a.pid = 99300u;
  a.event_time_ns = 700u;
  snprintf(a.event_id, sizeof(a.event_id), "%s", "rate-old-window");
  snprintf(a.process_name, sizeof(a.process_name), "%s", "dedup-test.exe");
  snprintf(a.tenant_id, sizeof(a.tenant_id), "%s", "tenant-rate-window");
  snprintf(a.endpoint_id, sizeof(a.endpoint_id), "%s", "endpoint-rate-window");
  memset(&delayed, 0, sizeof(delayed));
  delayed.record = a;
  delayed.start = &start;
  assert(pthread_create(&delayed_thread, NULL, emit_same_p0_record, &delayed) == 0);
  atomic_store_explicit(&start, 1, memory_order_release);
  wait_for_delayed_combined();

  /* B gets the only new-window global, tenant, and endpoint token. */
  edr_p0_rule_test_set_monotonic_ms(61001u);
  init_record(&b);
  b.pid = 99301u;
  b.event_time_ns = 701u;
  snprintf(b.event_id, sizeof(b.event_id), "%s", "rate-new-window");
  snprintf(b.process_name, sizeof(b.process_name), "%s", "dedup-test.exe");
  snprintf(b.tenant_id, sizeof(b.tenant_id), "%s", "tenant-rate-window");
  snprintf(b.endpoint_id, sizeof(b.endpoint_id), "%s", "endpoint-rate-window");
  assert(edr_p0_rule_try_emit(&b) == 1);

  atomic_store(&g_combined_fail_after_release, 1);
  atomic_store_explicit(&g_combined_release, 1, memory_order_release);
  assert(pthread_join(delayed_thread, NULL) == 0);
  assert(delayed.emitted == 0);

  /* A's late rollback cannot let C exceed cap=1 in B's window. */
  init_record(&c);
  c.pid = 99302u;
  c.event_time_ns = 702u;
  snprintf(c.event_id, sizeof(c.event_id), "%s", "rate-new-window-c");
  snprintf(c.process_name, sizeof(c.process_name), "%s", "dedup-test.exe");
  snprintf(c.tenant_id, sizeof(c.tenant_id), "%s", "tenant-rate-window");
  snprintf(c.endpoint_id, sizeof(c.endpoint_id), "%s", "endpoint-rate-window");
  assert(edr_p0_rule_try_emit(&c) == 0);
  assert(atomic_load(&g_emit_count) == 1);

  atomic_store(&g_block_combined, 0);
  g_block_combined_event_id = NULL;
  assert(test_setenv("EDR_P0_MAX_EMITS_PER_MIN", "0", 1) == 0);
  assert(test_setenv("EDR_P0_MAX_EMITS_PER_MIN_PER_TENANT", "0", 1) == 0);
  assert(test_setenv("EDR_P0_MAX_EMITS_PER_MIN_PER_ENDPOINT", "0", 1) == 0);
}

/* A reservation must also fail closed when its physical tenant/endpoint
 * slots have wrapped to new owners before its delayed rollback executes. */
static void test_rate_rollback_does_not_decrement_reused_slot(void) {
  EdrConfig alert_policy;
  EdrBehaviorRecord a, b, c;
  ConcurrentEmit delayed;
  pthread_t delayed_thread;
  atomic_int start = 0;

  memset(&alert_policy, 0, sizeof(alert_policy));
  alert_policy.policy_v2.script_mode = EDR_POLICY_MODE_ALERT;
  edr_policy_v2_configure(&alert_policy);
  assert(test_setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_DEDUP_SEC", "0", 1) == 0);
  assert(test_setenv("EDR_P0_MAX_EMITS_PER_MIN", "0", 1) == 0);
  assert(test_setenv("EDR_P0_MAX_EMITS_PER_MIN_PER_TENANT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_MAX_EMITS_PER_MIN_PER_ENDPOINT", "1", 1) == 0);
  edr_p0_rule_test_reset_dedup();
  edr_p0_rule_test_set_monotonic_ms(1000u);
  g_emit_count = 0;
  g_combined_emit_allowed = 1;
  g_block_combined_event_id = "rate-slot-old";
  atomic_store(&g_block_combined, 1);
  atomic_store(&g_combined_inflight, 0);
  atomic_store(&g_combined_release, 0);
  atomic_store(&g_combined_fail_after_release, 0);

  init_record(&a);
  a.pid = 99400u;
  a.event_time_ns = 800u;
  snprintf(a.event_id, sizeof(a.event_id), "%s", "rate-slot-old");
  snprintf(a.process_name, sizeof(a.process_name), "%s", "dedup-test.exe");
  snprintf(a.tenant_id, sizeof(a.tenant_id), "%s", "tenant-slot-old");
  snprintf(a.endpoint_id, sizeof(a.endpoint_id), "%s", "endpoint-slot-old");
  memset(&delayed, 0, sizeof(delayed));
  delayed.record = a;
  delayed.start = &start;
  assert(pthread_create(&delayed_thread, NULL, emit_same_p0_record, &delayed) == 0);
  atomic_store_explicit(&start, 1, memory_order_release);
  wait_for_delayed_combined();

  edr_p0_rule_test_set_monotonic_ms(61001u);
  /* The 32nd/64th replacement wraps the old tenant/endpoint physical slot. */
  for (unsigned i = 0u; i < 64u; ++i) {
    init_record(&b);
    b.pid = 99410u + i;
    b.event_time_ns = 810u + (int64_t)i;
    snprintf(b.event_id, sizeof(b.event_id), "rate-slot-new-%u", i);
    snprintf(b.process_name, sizeof(b.process_name), "%s", "dedup-test.exe");
    snprintf(b.tenant_id, sizeof(b.tenant_id), "tenant-slot-new-%u", i);
    snprintf(b.endpoint_id, sizeof(b.endpoint_id), "endpoint-slot-new-%u", i);
    assert(edr_p0_rule_try_emit(&b) == 1);
  }

  atomic_store(&g_combined_fail_after_release, 1);
  atomic_store_explicit(&g_combined_release, 1, memory_order_release);
  assert(pthread_join(delayed_thread, NULL) == 0);
  assert(delayed.emitted == 0);

  /* tenant 31 and endpoint 63 occupy the old physical slots, each at cap. */
  init_record(&c);
  c.pid = 99500u;
  c.event_time_ns = 900u;
  snprintf(c.event_id, sizeof(c.event_id), "%s", "rate-slot-reused-c");
  snprintf(c.process_name, sizeof(c.process_name), "%s", "dedup-test.exe");
  snprintf(c.tenant_id, sizeof(c.tenant_id), "%s", "tenant-slot-new-31");
  snprintf(c.endpoint_id, sizeof(c.endpoint_id), "%s", "endpoint-slot-new-63");
  assert(edr_p0_rule_try_emit(&c) == 0);
  assert(atomic_load(&g_emit_count) == 64);

  atomic_store(&g_block_combined, 0);
  g_block_combined_event_id = NULL;
  assert(test_setenv("EDR_P0_MAX_EMITS_PER_MIN_PER_TENANT", "0", 1) == 0);
  assert(test_setenv("EDR_P0_MAX_EMITS_PER_MIN_PER_ENDPOINT", "0", 1) == 0);
}

static void test_enforcement_requires_durable_intent_and_one_owner(void) {
  enum { workers = 20 };
  pthread_t threads[workers];
  ConcurrentEmit work[workers];
  atomic_int start = 0;
  int emitted = 0;
  EdrConfig block_policy;
  memset(&block_policy, 0, sizeof(block_policy));
  block_policy.policy_v2.script_mode = EDR_POLICY_MODE_BLOCK;
  edr_policy_v2_configure(&block_policy);
  assert(test_setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_DEDUP_SEC", "3", 1) == 0);
  edr_p0_rule_test_reset_dedup();
  edr_p0_rule_test_set_monotonic_ms(3050u);
  g_combined_emit_allowed = 1;
  g_durable_emit_allowed = 0;
  atomic_store(&g_enforcement_side_effects, 0);
  edr_policy_enforcement_test_set_execute_hook(test_enforcement_execute_hook);
  EdrBehaviorRecord rejected;
  init_record(&rejected);
  rejected.pid = 99150u;
  rejected.event_time_ns = 450u;
  snprintf(rejected.process_name, sizeof(rejected.process_name), "dedup-test.exe");
  assert(edr_p0_rule_try_emit(&rejected) == 0);
  assert(atomic_load(&g_enforcement_side_effects) == 0);

  g_durable_emit_allowed = 1;
  /* Production preprocess polls the one source-only retry owner before it
   * accepts a later P0 action.  Model that recovery explicitly here: a
   * failed source assertion must not be bypassed by the next direct call. */
  {
    EdrBehaviorRecord committed;
    edr_p0_rule_test_set_monotonic_ms(3300u);
    while (edr_p0_rule_poll_source_only_durable_retry(&committed)) { }
    g_source_ack = 1;
    assert(edr_p0_rule_source_only_recover_after_queue_open() == 1);
  }
  for (int i = 0; i < workers; i++) {
    memset(&work[i], 0, sizeof(work[i]));
    init_record(&work[i].record);
    work[i].record.pid = 99151u;
    work[i].record.event_time_ns = 451u;
    snprintf(work[i].record.endpoint_id, sizeof(work[i].record.endpoint_id), "ep-enforce-owner");
    snprintf(work[i].record.process_name, sizeof(work[i].record.process_name), "dedup-test.exe");
    work[i].start = &start;
    assert(pthread_create(&threads[i], NULL, emit_same_p0_record, &work[i]) == 0);
  }
  atomic_store(&start, 1);
  for (int i = 0; i < workers; i++) {
    assert(pthread_join(threads[i], NULL) == 0);
    emitted += work[i].emitted;
  }
  assert(emitted == 1);
  assert(atomic_load(&g_enforcement_side_effects) == 1);
  edr_policy_enforcement_test_set_execute_hook(NULL);
}

/* Ordinary alert rate governance and irreversible-action ownership are
 * deliberately separate.  A decoy must be allowed to consume the former
 * without suppressing the durable intent/action/result of a later block. */
static void test_enforcement_critical_lane_bypasses_ordinary_alert_rate(void) {
  EdrConfig alert_policy;
  EdrConfig block_policy;
  EdrBehaviorRecord decoy;
  EdrBehaviorRecord target;
  EdrP0EmitMetrics before, after;
  int effects_before;
  int precreate_before;
  int update_before;

  memset(&alert_policy, 0, sizeof(alert_policy));
  alert_policy.policy_v2.script_mode = EDR_POLICY_MODE_ALERT;
  memset(&block_policy, 0, sizeof(block_policy));
  block_policy.policy_v2.script_mode = EDR_POLICY_MODE_BLOCK;
  assert(test_setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_DEDUP_SEC", "0", 1) == 0);
  assert(test_setenv("EDR_P0_MAX_EMITS_PER_MIN", "1", 1) == 0);
  assert(test_setenv("EDR_P0_MAX_EMITS_PER_MIN_PER_TENANT", "0", 1) == 0);
  assert(test_setenv("EDR_P0_MAX_EMITS_PER_MIN_PER_ENDPOINT", "0", 1) == 0);
  edr_p0_rule_test_reset_dedup();
  edr_p0_rule_test_set_monotonic_ms(3060u);
  g_combined_emit_allowed = 1;
  g_durable_emit_allowed = 1;
  g_terminal_update_allowed = 1;
  g_terminal_source_enqueue_allowed = 1;
  atomic_store(&g_enforcement_side_effects, 0);
  edr_policy_enforcement_test_set_execute_hook(test_enforcement_execute_hook);

  edr_policy_v2_configure(&alert_policy);
  init_record(&decoy);
  decoy.pid = 99160u;
  decoy.event_time_ns = 460u;
  snprintf(decoy.endpoint_id, sizeof(decoy.endpoint_id), "ep-rate-decoy");
  snprintf(decoy.process_name, sizeof(decoy.process_name), "dedup-test.exe");
  assert(edr_p0_rule_try_emit(&decoy) == 1);
  assert(atomic_load(&g_enforcement_side_effects) == 0);

  effects_before = atomic_load(&g_enforcement_side_effects);
  precreate_before = atomic_load(&g_terminal_precreate_calls);
  update_before = atomic_load(&g_terminal_update_calls);
  edr_p0_rule_get_emit_metrics(&before);
  edr_policy_v2_configure(&block_policy);
  init_record(&target);
  target.pid = 99161u;
  target.event_time_ns = 461u;
  snprintf(target.endpoint_id, sizeof(target.endpoint_id), "ep-rate-block");
  snprintf(target.process_name, sizeof(target.process_name), "dedup-test.exe");
  assert(edr_p0_rule_try_emit(&target) == 1);
  edr_p0_rule_get_emit_metrics(&after);
  assert(atomic_load(&g_enforcement_side_effects) == effects_before + 1);
  assert(atomic_load(&g_terminal_precreate_calls) == precreate_before + 1);
  assert(atomic_load(&g_terminal_update_calls) == update_before + 1);
  assert(after.critical_reservations == before.critical_reservations + 1u);

  assert(test_setenv("EDR_P0_MAX_EMITS_PER_MIN", "0", 1) == 0);
  edr_policy_enforcement_test_set_execute_hook(NULL);
}

static void test_enforcement_terminal_preserves_evidence_and_never_reexecutes(void) {
  EdrConfig block_policy;
  EdrBehaviorRecord record;
  memset(&block_policy, 0, sizeof(block_policy));
  block_policy.policy_v2.script_mode = EDR_POLICY_MODE_BLOCK;
  edr_policy_v2_configure(&block_policy);
  assert(test_setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_DEDUP_SEC", "3", 1) == 0);
  edr_p0_rule_test_reset_dedup();
  edr_p0_rule_test_set_monotonic_ms(3075u);
  g_durable_emit_allowed = 1;
  g_combined_emit_allowed = 1;
  g_terminal_update_allowed = 1;
  g_terminal_source_enqueue_allowed = 1;
  atomic_store(&g_enforcement_side_effects, 0);
  edr_policy_enforcement_test_set_execute_hook(test_enforcement_execute_hook);
  init_record(&record);
  record.pid = 99301u;
  record.event_time_ns = 475u;
  snprintf(record.endpoint_id, sizeof(record.endpoint_id), "ep-terminal-context");
  snprintf(record.tenant_id, sizeof(record.tenant_id), "tenant-terminal-context");
  snprintf(record.process_name, sizeof(record.process_name), "dedup-test.exe");
  snprintf(record.cmdline, sizeof(record.cmdline), "dedup-test.exe --terminal-context");
  snprintf(record.file_path, sizeof(record.file_path), "C:\\tmp\\terminal-context.exe");
  snprintf(record.image_path_canonical, sizeof(record.image_path_canonical),
           "C:\\Program Files\\Terminal Context\\dedup-test.exe");
  snprintf(record.detection_context, sizeof(record.detection_context),
           "{\"evidence\":{\"artifact\":{\"source\":\"process_image_section\",\"quality\":\"action_authoritative\",\"reason\":\"fixture\"},\"signature\":{\"status\":\"verified\",\"hash\":\"abc123\"}},"
           "\"identity_quality\":\"target_4688\",\"reason\":\"verified_chain\","
           "\"file_identity\":\"win-fileid-v1:000000000000a1b2:0123456789abcdef0123456789abcdef\",\"intent_test_marker\":\"before_execute\"}");
  g_required_intent_marker = "\"intent_test_marker\":\"before_execute\"";
  assert(edr_p0_rule_try_emit(&record) == 1);
  g_required_intent_marker = NULL;
  assert(atomic_load(&g_enforcement_side_effects) == 1);
  assert(terminal_intent_context_contains("\"planned_action\":\"terminate_process\""));
  assert(terminal_intent_context_contains("\"rules_bundle_version\":"));
  assert(terminal_intent_context_contains("\"rules_bundle_sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\""));
  assert(terminal_intent_context_contains("\"source_event_key\":\"test-source-event\""));
  assert(terminal_intent_context_contains("\"source_event_id\":\"test-source-event\""));
  assert(terminal_intent_context_contains("\"process_pid\":99301"));
  assert(terminal_intent_context_contains("\"generation_key\":\"startkey-0000000000004242\""));
  assert(terminal_intent_context_contains("\"creation_filetime_100ns\":1"));
  assert(terminal_intent_context_contains("\"canonical_image_path\":\"C:\\\\Program Files\\\\Terminal Context\\\\dedup-test.exe\""));
  assert(terminal_intent_context_contains("\"file_identity\":\"win-fileid-v1:000000000000a1b2:0123456789abcdef0123456789abcdef\""));
  assert(!terminal_intent_context_contains("\"succeeded\":true"));
  assert(strstr(g_last_record.detection_context,
                "\"signature\":{\"status\":\"verified\",\"hash\":\"abc123\"}") != NULL);
  assert(strstr(g_last_record.detection_context, "\"identity_quality\":\"target_4688\"") != NULL);
  assert(strstr(g_last_record.detection_context, "\"reason\":\"verified_chain\"") != NULL);
  assert(strstr(g_last_record.detection_context,
                "\"enforcement_terminal\":{\"phase\":\"result\"") != NULL);
  assert(strstr(g_last_record.detection_context,
                "\"rules_bundle_sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"") != NULL);
  assert(strstr(g_last_record.detection_context,
                "\"source_event_key\":\"test-source-event\",\"source_event_id\":\"test-source-event\",\"process_pid\":99301") != NULL);
  assert(strstr(g_last_alert.user_subject_json, "\"enforcement\":{\"requested\":true") != NULL);

  /* Simulate a process restart: the P0 dedup cache is gone, but the durable
   * journal owner remains. Exact replay records unknown/not-replayed instead
   * of invoking the irreversible executor a second time. */
  edr_p0_rule_test_reset_dedup();
  edr_p0_rule_test_set_monotonic_ms(3080u);
  assert(edr_p0_rule_try_emit(&record) == 0);
  assert(atomic_load(&g_enforcement_side_effects) == 1);
  edr_policy_enforcement_test_set_execute_hook(NULL);
}

static void test_enforcement_terminal_rejects_missing_authority(void) {
  EdrConfig block_policy;
  EdrBehaviorRecord record;
  EdrPolicyEnforcementResult policy_result;
  int precreate_before;
  memset(&block_policy, 0, sizeof(block_policy));
  block_policy.policy_v2.script_mode = EDR_POLICY_MODE_BLOCK;
  edr_policy_v2_configure(&block_policy);
  assert(test_setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_DEDUP_SEC", "0", 1) == 0);
  edr_p0_rule_test_reset_dedup();
  edr_p0_rule_test_set_monotonic_ms(3097u);
  g_durable_emit_allowed = 1;
  g_terminal_source_enqueue_allowed = 1;
  g_combined_emit_allowed = 1;
  g_terminal_update_allowed = 1;
  atomic_store(&g_enforcement_side_effects, 0);
  edr_policy_enforcement_test_set_execute_hook(test_enforcement_execute_hook);
  init_record(&record);
  record.pid = 99321u;
  record.event_id[0] = '\0';
  snprintf(record.endpoint_id, sizeof(record.endpoint_id), "%s", "ep-terminal-no-authority");
  snprintf(record.process_name, sizeof(record.process_name), "%s", "dedup-test.exe");
  assert(edr_p0_rule_try_emit(&record) == 0);
  assert(atomic_load(&g_enforcement_side_effects) == 0);

  /* A post-event path snapshot may still carry useful detection evidence, but
   * never owns a terminal action.  The rule alert survives; neither the
   * terminal journal nor even the test executor may observe an action. */
  edr_p0_rule_test_reset_dedup();
  init_record(&record);
  record.pid = 99322u;
  snprintf(record.endpoint_id, sizeof(record.endpoint_id), "%s", "ep-terminal-post-event-snapshot");
  snprintf(record.process_name, sizeof(record.process_name), "%s", "dedup-test.exe");
  snprintf(record.detection_context, sizeof(record.detection_context), "%s",
           "{\"evidence\":{\"artifact\":{\"source\":\"post_event_path_snapshot\",\"quality\":\"non_authoritative\",\"reason\":\"process_image_section_unavailable\"},\"file_identity\":\"win-fileid-v1:0000000000004242:0123456789abcdef0123456789abcdef\"}}");
  precreate_before = atomic_load(&g_terminal_precreate_calls);
  assert(edr_p0_rule_try_emit(&record) == 1);
  assert(atomic_load(&g_enforcement_side_effects) == 0);
  assert(atomic_load(&g_terminal_precreate_calls) == precreate_before);
  assert(strstr(g_last_alert.user_subject_json,
                "\"action\":\"artifact_authority_unavailable\"") != NULL);
  memset(&policy_result, 0, sizeof(policy_result));
  edr_policy_enforcement_plan(&record, "T1059", "R-EXEC-003", &policy_result);
  assert(policy_result.requested == 1);
  edr_policy_enforcement_execute(&record, &policy_result);
  assert(atomic_load(&g_enforcement_side_effects) == 0);
  assert(strcmp(policy_result.action, "artifact_authority_unavailable") == 0);

  /* A denied/reparse/missing file identity is explicitly NOT_EVALUABLE inside
   * the existing artifact evidence envelope. It still emits the pure process
   * rule alert, but must not create a terminal intent or reach policy action. */
  edr_p0_rule_test_reset_dedup();
  init_record(&record);
  record.pid = 99324u;
  snprintf(record.endpoint_id, sizeof(record.endpoint_id), "%s",
           "ep-terminal-identity-not-evaluable");
  snprintf(record.process_name, sizeof(record.process_name), "%s", "dedup-test.exe");
  snprintf(record.detection_context, sizeof(record.detection_context), "%s",
           "{\"evidence\":{\"artifact\":{\"source\":\"post_event_path_snapshot\",\"quality\":\"NOT_EVALUABLE\",\"reason\":\"file_identity_unavailable\"},\"file_identity\":\"\"}}");
  precreate_before = atomic_load(&g_terminal_precreate_calls);
  assert(edr_p0_rule_try_emit(&record) == 1);
  assert(atomic_load(&g_enforcement_side_effects) == 0);
  assert(atomic_load(&g_terminal_precreate_calls) == precreate_before);
  assert(strstr(g_last_alert.user_subject_json,
                "\"action\":\"artifact_authority_unavailable\"") != NULL);

  /* The legacy XOR-shaped value is telemetry only. It cannot become the
   * terminal authority even when every process-generation field is present. */
  edr_p0_rule_test_reset_dedup();
  init_record(&record);
  record.pid = 99323u;
  snprintf(record.endpoint_id, sizeof(record.endpoint_id), "%s", "ep-terminal-legacy-file-id");
  snprintf(record.process_name, sizeof(record.process_name), "%s", "dedup-test.exe");
  snprintf(record.detection_context, sizeof(record.detection_context), "%s",
           "{\"evidence\":{\"artifact\":{\"source\":\"process_image_section\",\"quality\":\"action_authoritative\",\"reason\":\"fixture\"},\"file_identity\":\"00004242\"}}");
  assert(edr_p0_rule_try_emit(&record) == 0);
  assert(atomic_load(&g_enforcement_side_effects) == 0);
  edr_policy_enforcement_test_set_execute_hook(NULL);
}

static void test_enforcement_terminal_survives_normal_enqueue_failures(void) {
  EdrConfig block_policy;
  EdrBehaviorRecord record;
  int updates_before;
  memset(&block_policy, 0, sizeof(block_policy));
  block_policy.policy_v2.script_mode = EDR_POLICY_MODE_BLOCK;
  edr_policy_v2_configure(&block_policy);
  assert(test_setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_DEDUP_SEC", "0", 1) == 0);
  edr_p0_rule_test_reset_dedup();
  edr_p0_rule_test_set_monotonic_ms(3090u);
  g_durable_emit_allowed = 1;
  g_terminal_update_allowed = 1;
  atomic_store(&g_enforcement_side_effects, 0);
  updates_before = atomic_load(&g_terminal_update_calls);
  edr_policy_enforcement_test_set_execute_hook(test_enforcement_execute_hook);

  init_record(&record);
  record.pid = 99310u;
  record.event_time_ns = 490u;
  snprintf(record.endpoint_id, sizeof(record.endpoint_id), "ep-terminal-source-fail");
  snprintf(record.process_name, sizeof(record.process_name), "dedup-test.exe");
  g_terminal_source_enqueue_allowed = 0;
  g_combined_emit_allowed = 1;
  assert(edr_p0_rule_try_emit(&record) == 0);
  assert(atomic_load(&g_enforcement_side_effects) == 1);
  assert(atomic_load(&g_terminal_update_calls) == updates_before + 1);

  edr_p0_rule_test_reset_dedup();
  record.pid = 99311u;
  record.event_time_ns = 491u;
  snprintf(record.endpoint_id, sizeof(record.endpoint_id), "ep-terminal-combined-fail");
  g_terminal_source_enqueue_allowed = 1;
  g_combined_emit_allowed = 0;
  assert(edr_p0_rule_try_emit(&record) == 0);
  assert(atomic_load(&g_enforcement_side_effects) == 2);
  assert(atomic_load(&g_terminal_update_calls) == updates_before + 2);

  edr_p0_rule_test_reset_dedup();
  record.pid = 99312u;
  record.event_time_ns = 492u;
  snprintf(record.endpoint_id, sizeof(record.endpoint_id), "ep-terminal-both-fail");
  g_terminal_source_enqueue_allowed = 0;
  g_combined_emit_allowed = 0;
  assert(edr_p0_rule_try_emit(&record) == 0);
  assert(atomic_load(&g_enforcement_side_effects) == 3);
  assert(atomic_load(&g_terminal_update_calls) == updates_before + 3);
  g_terminal_source_enqueue_allowed = 1;
  g_combined_emit_allowed = 1;
  edr_policy_enforcement_test_set_execute_hook(NULL);
}

static void test_enforcement_terminal_crash_window_never_reexecutes(void) {
  EdrConfig block_policy;
  EdrBehaviorRecord record;
  memset(&block_policy, 0, sizeof(block_policy));
  block_policy.policy_v2.script_mode = EDR_POLICY_MODE_BLOCK;
  edr_policy_v2_configure(&block_policy);
  assert(test_setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_DEDUP_SEC", "0", 1) == 0);
  edr_p0_rule_test_reset_dedup();
  edr_p0_rule_test_set_monotonic_ms(3095u);
  g_durable_emit_allowed = 1;
  g_terminal_source_enqueue_allowed = 1;
  g_combined_emit_allowed = 1;
  g_terminal_update_allowed = 0;
  atomic_store(&g_enforcement_side_effects, 0);
  edr_policy_enforcement_test_set_execute_hook(test_enforcement_execute_hook);
  init_record(&record);
  record.pid = 99320u;
  record.event_time_ns = 495u;
  snprintf(record.endpoint_id, sizeof(record.endpoint_id), "ep-terminal-crash-window");
  snprintf(record.process_name, sizeof(record.process_name), "dedup-test.exe");
  snprintf(record.image_path_canonical, sizeof(record.image_path_canonical),
           "C:\\Program Files\\Crash Window\\dedup-test.exe");
  snprintf(record.detection_context, sizeof(record.detection_context),
           "{\"evidence\":{\"artifact\":{\"source\":\"process_image_section\",\"quality\":\"action_authoritative\",\"reason\":\"fixture\"}},\"file_identity\":\"win-fileid-v1:0000000000abcd01:0123456789abcdef0123456789abcdef\",\"intent_test_marker\":\"crash_window\"}");
  g_required_intent_marker = "\"intent_test_marker\":\"crash_window\"";
  /* Models a crash/error after TerminateProcess but before terminal UPDATE:
   * the precommitted intent has a real planned action, never success. */
  assert(edr_p0_rule_try_emit(&record) == 0);
  g_required_intent_marker = NULL;
  assert(atomic_load(&g_enforcement_side_effects) == 1);
  assert(terminal_intent_context_contains("\"planned_action\":\"terminate_process\""));
  assert(!terminal_intent_context_contains("\"succeeded\":true"));

  /* Restarting with an empty in-memory dedup table must not rerun an outcome
   * that could have been in progress or completed when the process crashed. */
  edr_p0_rule_test_reset_dedup();
  edr_p0_rule_test_set_monotonic_ms(3096u);
  g_terminal_update_allowed = 1;
  assert(edr_p0_rule_try_emit(&record) == 0);
  assert(atomic_load(&g_enforcement_side_effects) == 1);
  edr_policy_enforcement_test_set_execute_hook(NULL);
}

/* The bounded in-memory table is an ordinary-alert replay convenience, not
 * the owner of an irreversible action.  Once it is full of unrelated normal
 * candidates, a block candidate still has to create its journal intent before
 * execution; the journal's unique key then remains the exactly-once owner. */
static void test_block_uses_terminal_journal_when_ordinary_pending_table_full(void) {
  enum { ordinary_workers = 64 };
  pthread_t ordinary_threads[ordinary_workers];
  pthread_t block_thread;
  ConcurrentEmit ordinary[ordinary_workers];
  ConcurrentEmit block_work;
  atomic_int ordinary_start = 0;
  atomic_int block_start = 0;
  EdrConfig alert_policy;
  EdrConfig block_policy;
  int ordinary_emitted = 0;
  int effects_before;
  int precreate_before;
  int update_before;

  memset(&alert_policy, 0, sizeof(alert_policy));
  alert_policy.policy_v2.script_mode = EDR_POLICY_MODE_ALERT;
  memset(&block_policy, 0, sizeof(block_policy));
  block_policy.policy_v2.script_mode = EDR_POLICY_MODE_BLOCK;
  assert(test_setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_DEDUP_SEC", "3", 1) == 0);
  assert(test_setenv("EDR_P0_MAX_EMITS_PER_MIN", "0", 1) == 0);
  assert(test_setenv("EDR_P0_MAX_EMITS_PER_MIN_PER_TENANT", "0", 1) == 0);
  assert(test_setenv("EDR_P0_MAX_EMITS_PER_MIN_PER_ENDPOINT", "0", 1) == 0);
  edr_p0_rule_test_reset_dedup();
  edr_p0_rule_test_set_monotonic_ms(3110u);
  edr_policy_v2_configure(&alert_policy);
  g_combined_emit_allowed = 1;
  g_durable_emit_allowed = 1;
  g_terminal_update_allowed = 1;
  g_terminal_source_enqueue_allowed = 1;
  atomic_store(&g_combined_inflight, 0);
  atomic_store(&g_combined_release, 0);
  atomic_store(&g_block_combined, 1);
  atomic_store(&g_parallel_mode, 1);
  atomic_store(&g_enforcement_side_effects, 0);
  edr_policy_enforcement_test_set_execute_hook(test_enforcement_execute_hook);

  for (int i = 0; i < ordinary_workers; i++) {
    memset(&ordinary[i], 0, sizeof(ordinary[i]));
    init_record(&ordinary[i].record);
    ordinary[i].record.pid = 99400u + (uint32_t)i;
    ordinary[i].record.event_time_ns = 600u + i;
    snprintf(ordinary[i].record.event_id, sizeof(ordinary[i].record.event_id),
             "ordinary-pending-%d", i);
    snprintf(ordinary[i].record.endpoint_id, sizeof(ordinary[i].record.endpoint_id),
             "ep-ordinary-pending-full");
    snprintf(ordinary[i].record.process_name, sizeof(ordinary[i].record.process_name),
             "dedup-test.exe");
    ordinary[i].start = &ordinary_start;
    assert(pthread_create(&ordinary_threads[i], NULL, emit_same_p0_record, &ordinary[i]) == 0);
  }
  atomic_store_explicit(&ordinary_start, 1, memory_order_release);
  for (int spins = 0; spins < 5000 && atomic_load(&g_combined_inflight) < ordinary_workers;
       spins++) {
    struct timespec pause = {0, 1000000L};
    (void)nanosleep(&pause, NULL);
  }
  assert(atomic_load(&g_combined_inflight) == ordinary_workers);

  effects_before = atomic_load(&g_enforcement_side_effects);
  precreate_before = atomic_load(&g_terminal_precreate_calls);
  update_before = atomic_load(&g_terminal_update_calls);
  edr_policy_v2_configure(&block_policy);
  memset(&block_work, 0, sizeof(block_work));
  init_record(&block_work.record);
  block_work.record.pid = 99500u;
  block_work.record.event_time_ns = 700u;
  snprintf(block_work.record.event_id, sizeof(block_work.record.event_id),
           "block-after-ordinary-pending-full");
  snprintf(block_work.record.endpoint_id, sizeof(block_work.record.endpoint_id),
           "ep-block-after-ordinary-pending-full");
  snprintf(block_work.record.process_name, sizeof(block_work.record.process_name),
           "dedup-test.exe");
  block_work.start = &block_start;
  assert(pthread_create(&block_thread, NULL, emit_same_p0_record, &block_work) == 0);
  atomic_store_explicit(&block_start, 1, memory_order_release);
  for (int spins = 0;
       spins < 5000 && (atomic_load(&g_enforcement_side_effects) != effects_before + 1 ||
                        atomic_load(&g_terminal_precreate_calls) != precreate_before + 1 ||
                        atomic_load(&g_terminal_update_calls) != update_before + 1);
       spins++) {
    struct timespec pause = {0, 1000000L};
    (void)nanosleep(&pause, NULL);
  }
  assert(atomic_load(&g_enforcement_side_effects) == effects_before + 1);
  assert(atomic_load(&g_terminal_precreate_calls) == precreate_before + 1);
  assert(atomic_load(&g_terminal_update_calls) == update_before + 1);

  atomic_store_explicit(&g_combined_release, 1, memory_order_release);
  for (int i = 0; i < ordinary_workers; i++) {
    assert(pthread_join(ordinary_threads[i], NULL) == 0);
    ordinary_emitted += ordinary[i].emitted;
  }
  assert(pthread_join(block_thread, NULL) == 0);
  atomic_store(&g_block_combined, 0);
  atomic_store(&g_parallel_mode, 0);
  assert(ordinary_emitted == ordinary_workers);
  assert(block_work.emitted == 1);
  assert(atomic_load(&g_enforcement_side_effects) == effects_before + 1);
  assert(atomic_load(&g_terminal_precreate_calls) == precreate_before + 1);
  assert(atomic_load(&g_terminal_update_calls) == update_before + 1);
  edr_policy_enforcement_test_set_execute_hook(NULL);
  edr_policy_v2_configure(&alert_policy);
}

static void test_p0_pending_table_backpressure_preserves_all_claims(void) {
  enum { workers = 65 };
  pthread_t threads[workers];
  ConcurrentEmit work[workers];
  atomic_int start = 0;
  int emitted = 0;
  assert(test_setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(test_setenv("EDR_P0_DEDUP_SEC", "3", 1) == 0);
  assert(test_setenv("EDR_P0_MAX_EMITS_PER_MIN", "0", 1) == 0);
  assert(test_setenv("EDR_P0_MAX_EMITS_PER_MIN_PER_TENANT", "0", 1) == 0);
  edr_p0_rule_test_reset_dedup();
  edr_p0_rule_test_set_monotonic_ms(3100u);
  g_emit_count = 0;
  g_combined_emit_allowed = 1;
  atomic_store(&g_combined_inflight, 0);
  atomic_store(&g_combined_release, 0);
  atomic_store(&g_block_combined, 1);
  atomic_store(&g_parallel_mode, 1);
  for (int i = 0; i < workers; i++) {
    memset(&work[i], 0, sizeof(work[i]));
    init_record(&work[i].record);
    work[i].record.pid = 99200u + (uint32_t)i;
    work[i].record.event_time_ns = 500u + i;
    snprintf(work[i].record.endpoint_id, sizeof(work[i].record.endpoint_id), "ep-pending-full");
    snprintf(work[i].record.process_name, sizeof(work[i].record.process_name), "dedup-test.exe");
    work[i].start = &start;
    assert(pthread_create(&threads[i], NULL, emit_same_p0_record, &work[i]) == 0);
  }
  atomic_store_explicit(&start, 1, memory_order_release);
  for (int spins = 0; spins < 5000 && atomic_load(&g_combined_inflight) < 64; spins++) {
    struct timespec pause = {0, 1000000L};
    (void)nanosleep(&pause, NULL);
  }
  assert(atomic_load(&g_combined_inflight) == 64);
  /* Give the final contender a scheduling window while every claim remains
   * pending; releasing first would legitimately let it reuse a committed
   * slot and would not exercise the full-table contract. */
  { struct timespec pause = {0, 100000000L}; (void)nanosleep(&pause, NULL); }
  EdrP0DedupMetrics pending_metrics;
  edr_p0_rule_get_dedup_metrics(&pending_metrics);
  assert(pending_metrics.pending_backpressure == 1u);
  atomic_store_explicit(&g_combined_release, 1, memory_order_release);
  for (int i = 0; i < workers; i++) {
    assert(pthread_join(threads[i], NULL) == 0);
    emitted += work[i].emitted;
  }
  atomic_store(&g_block_combined, 0);
  atomic_store(&g_parallel_mode, 0);
  EdrP0DedupMetrics metrics;
  edr_p0_rule_get_dedup_metrics(&metrics);
  assert(emitted == 64);
  assert(g_emit_count == 64);
  assert(metrics.pending_backpressure == 1u);
}
#endif

int main(void) {
  test_edge_update_signed_chain_is_suppressed();
  test_edge_update_without_signature_is_not_suppressed();
  test_edge_update_malicious_command_is_not_suppressed();
  test_fdsecurity_sensor_task_is_suppressed();
  test_fdsecurity_setup_diagnostics_is_suppressed();
  test_fdsecurity_arbitrary_dll_is_not_suppressed();
  test_rundll32_davclnt_localhost_is_suppressed();
  test_rundll32_davclnt_127_is_suppressed();
  test_rundll32_davclnt_external_is_not_suppressed();
  test_rundll32_davclnt_remote_ip_is_not_suppressed();
  test_rundll32_davclnt_localhost_suffix_is_not_suppressed();
  test_rundll32_davclnt_127_prefix_is_not_suppressed();
  test_t1091_local_fixed_desktop_ini_is_suppressed();
  test_t1091_autorun_inf_is_not_suppressed();
  test_searchprotocolhost_indexing_is_suppressed();
  test_searchprotocolhost_user_path_is_not_suppressed();
  test_searchprotocolhost_without_pipe_is_not_suppressed();
  test_searchprotocolhost_no_cmdline_system32_is_suppressed();
  test_searchprotocolhost_no_cmdline_user_path_not_suppressed();
  test_real_p0_dedup_metric_matrix();
  test_p0_exact_replay_window_rearms_only_that_source();
  test_p0_dedup_never_suppresses_semantic_mutations();
  test_source_only_direct_contract_uses_production_builder();
  test_file_read_source_only_binds_rejected_field();
  test_p0_full_context_counts_capped_value_once();
  test_p0_abi_fields_mark_omission_without_losing_record();
  test_p0_push_failure_does_not_commit_emit_counters();
  test_p0_governor_suppression_is_not_queue_backpressure();
  test_p0_miss_does_not_emit_combined_frame();
  test_source_truncation_never_emits_after_coalescer_status();
  test_p0_bundle_sha256_is_required_and_attached();
  test_ir_evaluation_failure_durably_preserves_source_without_alert();
  test_source_only_retry_lane_is_exact_and_overflow_latched();
  test_restart_latch_requires_durable_loss_audit();
  test_ir_not_ready_durably_preserves_every_p0_event_group();
  test_source_only_fault_is_scoped_to_owning_event_family();
  test_deferred_retry_ruleset_change_and_action_owner();
  test_deferred_storage_faults_are_retained_and_backed_off();
  test_script_matches_obey_process_family_gate();
  test_p0_escape_overflow_degrades_without_silent_core_loss();
  test_p0_user_subject_overflow_degrades_without_losing_alert();
#if !defined(_WIN32)
  test_p0_pending_claim_allows_one_same_key();
  test_rate_rollback_does_not_reopen_new_window();
  test_rate_rollback_does_not_decrement_reused_slot();
  test_enforcement_requires_durable_intent_and_one_owner();
  test_enforcement_critical_lane_bypasses_ordinary_alert_rate();
  test_enforcement_terminal_preserves_evidence_and_never_reexecutes();
  test_enforcement_terminal_survives_normal_enqueue_failures();
  test_enforcement_terminal_crash_window_never_reexecutes();
  test_enforcement_terminal_rejects_missing_authority();
  test_block_uses_terminal_journal_when_ordinary_pending_table_full();
  test_p0_pending_table_backpressure_preserves_all_claims();
#endif
  puts("test_p0_direct_emit_suppression: ok");
  return 0;
}
