#include "edr/alert_governor.h"
#include "edr/behavior_alert_emit.h"
#include "edr/behavior_record.h"
#include "edr/config.h"
#include "edr/p0_rule_direct_emit.h"
#include "edr/p0_rule_ir.h"
#include "edr/p0_source_only_contract.h"
#include "edr/policy_enforcement.h"
#include "edr/policy_v2.h"
#include "edr/process_tree_cache.h"
#include "edr/storage_queue.h"

#include "edr/v1/event.pb.h"
#include <pb_decode.h>

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SOURCE_FIXTURE_CASES 3u
#define RULESET_EVALUATION_FIXTURE_CASES 6u
#define COLLECTOR_EVIDENCE_FIXTURE_CASES 8u
#define SOURCE_ONLY_DELIVERY_FIXTURE_CASES 1u
#define TOTAL_SOURCE_FIXTURE_CASES \
  (SOURCE_FIXTURE_CASES + RULESET_EVALUATION_FIXTURE_CASES + \
   COLLECTOR_EVIDENCE_FIXTURE_CASES + SOURCE_ONLY_DELIVERY_FIXTURE_CASES)

typedef struct SourceFixtureCase {
  EdrEventType type;
  const char *event_id;
  const char *rule_id;
  const char *reason;
} SourceFixtureCase;

static const SourceFixtureCase k_cases[SOURCE_FIXTURE_CASES] = {
    {EDR_EVENT_REG_SET_VALUE, "source-contract-registry-1", "R-PERSIST-001",
     "p0_alert_queue_backpressure"},
    {EDR_EVENT_FILE_WRITE, "source-contract-file-1", "R-PERSIST-008",
     "p0_dedup_pending_backpressure"},
    {EDR_EVENT_NET_CONNECT, "source-contract-network-1", "R-LMOVE-001",
     "p0_alert_queue_backpressure"},
};
static const SourceFixtureCase k_ruleset_evaluation_cases[RULESET_EVALUATION_FIXTURE_CASES] = {
    {EDR_EVENT_PROCESS_CREATE, "source-contract-ruleset-evaluation-process-1", "",
     "p0_ir_evaluation_unavailable"},
    {EDR_EVENT_PROCESS_CREATE, "source-contract-ruleset-not-ready-process-1", "",
     "p0_ir_not_ready"},
    {EDR_EVENT_FILE_READ, "source-contract-ruleset-not-ready-read-1", "",
     "p0_ir_not_ready"},
    {EDR_EVENT_FILE_WRITE, "source-contract-ruleset-not-ready-write-1", "",
     "p0_ir_not_ready"},
    {EDR_EVENT_NET_CONNECT, "source-contract-ruleset-not-ready-network-1", "",
     "p0_ir_not_ready"},
    {EDR_EVENT_REG_SET_VALUE, "source-contract-ruleset-not-ready-registry-1", "",
     "p0_ir_not_ready"},
};
static const SourceFixtureCase k_collector_evidence_cases[COLLECTOR_EVIDENCE_FIXTURE_CASES] = {
    {EDR_EVENT_FILE_READ, "filemeta-backpressure-0001", "",
     EDR_P0_FILE_READ_REASON_METADATA_BACKPRESSURE},
    {EDR_EVENT_FILE_READ, "filemeta-start-key-missing-0001", "",
     EDR_P0_FILE_READ_REASON_START_KEY_MISSING},
    {EDR_EVENT_FILE_READ, "filemeta-live-generation-unavailable-0001", "",
     EDR_P0_FILE_READ_REASON_LIVE_GENERATION_UNAVAILABLE},
    {EDR_EVENT_FILE_READ, "filemeta-generation-mismatch-0001", "",
     EDR_P0_FILE_READ_REASON_GENERATION_MISMATCH},
    {EDR_EVENT_FILE_READ, "filemeta-canonical-path-unresolved-0001", "",
     EDR_P0_FILE_READ_REASON_CANONICAL_PATH_UNRESOLVED},
    {EDR_EVENT_FILE_READ, "filemeta-payload-unavailable-0001", "",
     EDR_P0_FILE_READ_REASON_PAYLOAD_UNAVAILABLE},
    {EDR_EVENT_FILE_READ, "filemeta-event-time-unavailable-0001", "",
     EDR_P0_FILE_READ_REASON_EVENT_TIME_UNAVAILABLE},
    {EDR_EVENT_FILE_READ, "filemeta-event-bus-unavailable-0001", "",
     EDR_P0_FILE_READ_REASON_EVENT_BUS_UNAVAILABLE},
};
static const uint8_t k_delivery_queue_nonce[16] = {
    0x10u, 0x32u, 0x54u, 0x76u, 0x98u, 0xbau, 0xdcu, 0xfeu,
    0x01u, 0x23u, 0x45u, 0x67u, 0x89u, 0xabu, 0xcdu, 0xefu,
};
static const uint64_t k_delivery_latch_counter = UINT64_C(0x123456);
static const uint64_t k_delivery_latch_epoch = UINT64_C(7);

static uint8_t s_wires[TOTAL_SOURCE_FIXTURE_CASES][65536u + 16u];
static size_t s_wire_lens[TOTAL_SOURCE_FIXTURE_CASES];
static char s_batch_ids[TOTAL_SOURCE_FIXTURE_CASES][128];
static size_t s_enqueue_count;
/* Every fixture is generated from the binding held by the production IR
 * snapshot.  Keeping this runtime copy makes a bundle update regenerate the
 * durable contract instead of silently combining a new artifact SHA with an
 * old compile-time version. */
static EdrP0RuleIrBinding s_binding;

enum {
  TERMINAL_AUTHORITY_FRAMES = 2,
  TERMINAL_FIXTURE_FRAMES = 3,
  TERMINAL_INTENT_FRAME = 0,
  TERMINAL_SOURCE_FRAME = 1,
  TERMINAL_COMBINED_FRAME = 2,
};
static EdrBehaviorRecord s_terminal_records[TERMINAL_AUTHORITY_FRAMES];
static uint8_t s_terminal_expected_wires[TERMINAL_AUTHORITY_FRAMES][65536u + 16u];
static size_t s_terminal_expected_wire_lens[TERMINAL_AUTHORITY_FRAMES];
static uint8_t s_terminal_wires[TERMINAL_FIXTURE_FRAMES][65536u + 16u];
static size_t s_terminal_wire_lens[TERMINAL_FIXTURE_FRAMES];
static char s_terminal_batch_ids[TERMINAL_FIXTURE_FRAMES][128];
static const char *s_terminal_json[TERMINAL_AUTHORITY_FRAMES];
static size_t s_terminal_json_lens[TERMINAL_AUTHORITY_FRAMES];
static int s_terminal_capture_active;
static int s_terminal_precreated;
static int s_terminal_updated;
static EdrStorageQueueP0SourceOnlyLatch s_source_latch;
static char s_delivery_event_id[EDR_BR_ID_LEN];

static const char k_terminal_rule_id[] = "R-EXEC-003";
static const char k_terminal_event_id[] = "terminal-contract-event-4242";
static const char k_terminal_tenant_id[] = "tenant-terminal-contract";
static const char k_terminal_endpoint_id[] = "endpoint-terminal-contract";
static const char k_terminal_raw_image_path[] =
    "\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
static const char k_terminal_canonical_image_path[] =
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
static const char k_terminal_file_identity[] =
    "win-fileid-v1:000000000000feed:0123456789abcdef0123456789abcdef";
static const char k_terminal_generation_key[] = "startkey-0000000000004242";

static uint32_t read_le32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8u) |
         ((uint32_t)p[2] << 16u) | ((uint32_t)p[3] << 24u);
}

static void print_base64(const uint8_t *input, size_t input_len) {
  static const char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t i;
  for (i = 0u; i < input_len; i += 3u) {
    uint32_t value = (uint32_t)input[i] << 16u;
    size_t remaining = input_len - i;
    if (remaining > 1u) value |= (uint32_t)input[i + 1u] << 8u;
    if (remaining > 2u) value |= input[i + 2u];
    putchar(alphabet[(value >> 18u) & 0x3fu]);
    putchar(alphabet[(value >> 12u) & 0x3fu]);
    putchar(remaining > 1u ? alphabet[(value >> 6u) & 0x3fu] : '=');
    putchar(remaining > 2u ? alphabet[value & 0x3fu] : '=');
  }
}

static void print_json_string(const char *value) {
  const unsigned char *p = (const unsigned char *)(value ? value : "");
  putchar('"');
  while (*p) {
    switch (*p) {
      case '"': fputs("\\\"", stdout); break;
      case '\\': fputs("\\\\", stdout); break;
      case '\b': fputs("\\b", stdout); break;
      case '\f': fputs("\\f", stdout); break;
      case '\n': fputs("\\n", stdout); break;
      case '\r': fputs("\\r", stdout); break;
      case '\t': fputs("\\t", stdout); break;
      default:
        if (*p < 0x20u) printf("\\u%04x", (unsigned)*p);
        else putchar(*p);
        break;
    }
    ++p;
  }
  putchar('"');
}

static int capture_terminal_wire(size_t index, const char *batch_id,
                                 const uint8_t *wire, size_t wire_len) {
  if (index >= TERMINAL_FIXTURE_FRAMES || !batch_id || !batch_id[0] || !wire ||
      wire_len == 0u || wire_len > sizeof(s_terminal_wires[index])) {
    return 0;
  }
  memcpy(s_terminal_wires[index], wire, wire_len);
  s_terminal_wire_lens[index] = wire_len;
  snprintf(s_terminal_batch_ids[index], sizeof(s_terminal_batch_ids[index]), "%s", batch_id);
  return 1;
}

/* Test-local queue capture preserves the actual production BAT1 bytes; it
 * deliberately does not synthesize a fake wire or JSON context. */
int edr_storage_queue_is_open(void) { return 1; }
EdrError edr_storage_queue_p0_source_only_latch_prepare(
    EdrStorageQueueP0SourceOnlyLatch *out) {
  if (!out) return EDR_ERR_INVALID_ARG;
  if (!s_source_latch.latched) {
    memset(&s_source_latch, 0, sizeof(s_source_latch));
    memcpy(s_source_latch.queue_nonce, k_delivery_queue_nonce,
           sizeof(s_source_latch.queue_nonce));
    s_source_latch.latch_counter = k_delivery_latch_counter;
    s_source_latch.latch_epoch = k_delivery_latch_epoch;
    s_source_latch.latched = 1;
  } else {
    s_source_latch.recovery_required = 1;
  }
  *out = s_source_latch;
  return EDR_OK;
}
int edr_storage_queue_p0_source_only_latch_is_set(void) {
  return s_source_latch.latched;
}
EdrError edr_storage_queue_p0_source_only_latch_get(
    EdrStorageQueueP0SourceOnlyLatch *out) {
  if (!out) return EDR_ERR_INVALID_ARG;
  *out = s_source_latch;
  return EDR_OK;
}
EdrError edr_storage_queue_p0_source_only_recovery_probe(void) { return EDR_OK; }

EdrError edr_storage_queue_enqueue(const char *batch_id, const uint8_t *wire,
                                   size_t wire_len, int compressed, int severity) {
  (void)compressed;
  if (s_terminal_capture_active) {
    return batch_id && batch_id[0] && wire && wire_len > 0u && severity == 1 ?
        EDR_OK : EDR_ERR_SQLITE_WRITE;
  }
  if (!batch_id || !wire || wire_len == 0u ||
      severity != EDR_STORAGE_QUEUE_SEVERITY_P0_SOURCE_ONLY ||
      s_enqueue_count >= TOTAL_SOURCE_FIXTURE_CASES || wire_len > sizeof(s_wires[0])) {
    return EDR_ERR_SQLITE_WRITE;
  }
  memcpy(s_wires[s_enqueue_count], wire, wire_len);
  s_wire_lens[s_enqueue_count] = wire_len;
  snprintf(s_batch_ids[s_enqueue_count], sizeof(s_batch_ids[s_enqueue_count]), "%s", batch_id);
  s_enqueue_count++;
  return EDR_OK;
}

EdrError edr_storage_queue_p0_source_only_enqueue_bound(
    const EdrStorageQueueP0SourceOnlyLatch *expected, const char *event_id,
    const char *batch_id, const uint8_t *wire, size_t wire_len,
    int compressed, int recovery_audit) {
  (void)event_id;
  (void)recovery_audit;
  if (!expected || !expected->latched || !s_source_latch.latched ||
      expected->latch_counter != s_source_latch.latch_counter ||
      expected->latch_epoch != s_source_latch.latch_epoch ||
      memcmp(expected->queue_nonce, s_source_latch.queue_nonce,
             sizeof(expected->queue_nonce)) != 0) {
    return EDR_ERR_INVALID_ARG;
  }
  return edr_storage_queue_enqueue(batch_id, wire, wire_len, compressed,
                                   EDR_STORAGE_QUEUE_SEVERITY_P0_SOURCE_ONLY);
}

EdrEnforcementTerminalPrecreate edr_storage_queue_enforcement_terminal_precreate(
    const char *idempotency_key, const char *source_event_key, const char *rule_id,
    const char *process_generation_key, const char *intent_batch_id, const uint8_t *intent_wire,
    size_t intent_wire_len) {
  if (!s_terminal_capture_active || s_terminal_precreated || !idempotency_key ||
      !source_event_key || !rule_id || !process_generation_key || !intent_batch_id ||
      !intent_wire || intent_wire_len == 0u || strcmp(rule_id, k_terminal_rule_id) != 0 ||
      strcmp(source_event_key, k_terminal_event_id) != 0 ||
      strcmp(process_generation_key, k_terminal_generation_key) != 0 ||
      !capture_terminal_wire(TERMINAL_INTENT_FRAME, intent_batch_id, intent_wire,
                             intent_wire_len)) {
    return EDR_ENFORCEMENT_TERMINAL_PRECREATE_ERROR;
  }
  s_terminal_precreated = 1;
  return EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED;
}

EdrError edr_storage_queue_enforcement_terminal_update(
    const char *idempotency_key, const char *source_batch_id, const uint8_t *source_wire,
    size_t source_wire_len, const char *combined_batch_id, const uint8_t *combined_wire,
    size_t combined_wire_len) {
  if (!s_terminal_capture_active || !s_terminal_precreated || s_terminal_updated ||
      !idempotency_key || !source_batch_id || !source_wire || !combined_batch_id ||
      !combined_wire || !capture_terminal_wire(TERMINAL_SOURCE_FRAME, source_batch_id,
                                               source_wire, source_wire_len) ||
      !capture_terminal_wire(TERMINAL_COMBINED_FRAME, combined_batch_id, combined_wire,
                             combined_wire_len)) {
    return EDR_ERR_SQLITE_WRITE;
  }
  s_terminal_updated = 1;
  return EDR_OK;
}

int edr_event_batch_push(const uint8_t *wire, size_t wire_len) {
  (void)wire; (void)wire_len;
  return -1;
}

void edr_preprocess_copy_agent_ids(char *endpoint_id, size_t endpoint_cap,
                                   char *tenant_id, size_t tenant_cap) {
  if (endpoint_id && endpoint_cap) endpoint_id[0] = '\0';
  if (tenant_id && tenant_cap) tenant_id[0] = '\0';
}

int edr_pt_cache_snapshot_at(uint32_t pid, uint64_t event_time_ns, ProcessTreeEntry *out) {
  (void)pid; (void)event_time_ns; (void)out;
  return -1;
}

void edr_adaptive_collection_raise(int severity, const char *rule_id, uint32_t pid,
                                   uint32_t parent_pid, const char *process_name) {
  (void)severity; (void)rule_id; (void)pid; (void)parent_pid; (void)process_name;
}

int enrich_parent_info_by_pid(uint32_t ppid, char *parent_name, size_t name_len,
                              char *parent_path, size_t path_len) {
  (void)ppid;
  if (parent_name && name_len) parent_name[0] = '\0';
  if (parent_path && path_len) parent_path[0] = '\0';
  return 1;
}

static void make_record(EdrBehaviorRecord *record, const SourceFixtureCase *fixture, size_t ordinal) {
  memset(record, 0, sizeof(*record));
  record->type = fixture->type;
  record->event_time_ns = 1720000000000000000LL + (int64_t)ordinal;
  record->pid = 6100u + (uint32_t)ordinal;
  record->ppid = 6000u;
  snprintf(record->event_id, sizeof(record->event_id), "%s", fixture->event_id);
  snprintf(record->tenant_id, sizeof(record->tenant_id), "tenant-source-contract");
  snprintf(record->endpoint_id, sizeof(record->endpoint_id), "endpoint-source-contract");
  snprintf(record->process_name, sizeof(record->process_name), "source-contract.exe");
  snprintf(record->exe_path, sizeof(record->exe_path), "C:\\Program Files\\Source Contract\\source-contract.exe");
  snprintf(record->image_path_canonical, sizeof(record->image_path_canonical), "%s", record->exe_path);
  snprintf(record->cmdline, sizeof(record->cmdline), "source-contract.exe --fixture=%zu", ordinal);
  snprintf(record->detection_context, sizeof(record->detection_context),
           "{\"evidence\":{\"file_identity\":\"win-fileid-v1:000000000000feed:0123456789abcdef0123456789ab%04zx\",\"hash\":{\"value\":\"abc%zu\",\"quality\":\"captured\",\"reason\":\"verified\"},\"signature\":{\"status\":\"unknown\",\"quality\":\"unknown\",\"reason\":\"not_requested\"}}}",
           ordinal, ordinal);
  if (fixture->type == EDR_EVENT_REG_SET_VALUE) {
    snprintf(record->reg_key_path, sizeof(record->reg_key_path),
             "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    snprintf(record->reg_value_name, sizeof(record->reg_value_name), "SourceContract");
    snprintf(record->reg_value_data, sizeof(record->reg_value_data), "C:\\Temp\\payload.exe");
  } else if (fixture->type == EDR_EVENT_FILE_WRITE || fixture->type == EDR_EVENT_FILE_READ) {
    snprintf(record->file_path, sizeof(record->file_path),
             "C:\\Users\\x\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.ps1");
  } else if (fixture->type == EDR_EVENT_NET_CONNECT) {
    snprintf(record->net_src, sizeof(record->net_src), "10.0.0.10");
    snprintf(record->net_dst, sizeof(record->net_dst), "10.0.0.20");
    record->net_dport = 445u;
    snprintf(record->net_proto, sizeof(record->net_proto), "tcp");
  }
}

static void make_terminal_record(EdrBehaviorRecord *record) {
  memset(record, 0, sizeof(*record));
  record->type = EDR_EVENT_PROCESS_CREATE;
  record->event_time_ns = 1720000000000000000LL;
  record->pid = 4242u;
  record->process_start_key = 0x4242u;
  record->process_creation_filetime_100ns = 133444555666777888ULL;
  snprintf(record->event_id, sizeof(record->event_id), "%s", k_terminal_event_id);
  snprintf(record->tenant_id, sizeof(record->tenant_id), "%s", k_terminal_tenant_id);
  snprintf(record->endpoint_id, sizeof(record->endpoint_id), "%s", k_terminal_endpoint_id);
  snprintf(record->process_name, sizeof(record->process_name), "%s", "powershell.exe");
  snprintf(record->exe_path, sizeof(record->exe_path), "%s", k_terminal_raw_image_path);
  snprintf(record->image_path_raw, sizeof(record->image_path_raw), "%s",
           k_terminal_raw_image_path);
  snprintf(record->image_path_canonical, sizeof(record->image_path_canonical), "%s",
           k_terminal_canonical_image_path);
  snprintf(record->image_path_namespace, sizeof(record->image_path_namespace), "%s", "win32");
  snprintf(record->image_path_resolution_status, sizeof(record->image_path_resolution_status),
           "%s", "RESOLVED");
  snprintf(record->image_path_resolution_source, sizeof(record->image_path_resolution_source),
           "%s", "volume_mapping");
  snprintf(record->process_generation_source, sizeof(record->process_generation_source), "%s",
           "live_process_identity");
  snprintf(record->source_completeness, sizeof(record->source_completeness), "%s", "COMPLETE");
  record->evidence_revision = 7u;
  snprintf(record->parent_name, sizeof(record->parent_name), "%s", "winword.exe");
  snprintf(record->parent_resolution_status, sizeof(record->parent_resolution_status), "%s",
           "RESOLVED");
  snprintf(record->parent_resolution_source, sizeof(record->parent_resolution_source), "%s",
           "generation_cache");
  snprintf(record->parent_creation_time, sizeof(record->parent_creation_time), "%s",
           "2026-08-31T01:02:03.456Z");
  snprintf(record->cmdline, sizeof(record->cmdline), "%s",
           "powershell.exe -NoProfile -Command Get-ChildItem");
  snprintf(record->detection_context, sizeof(record->detection_context),
           "{\"evidence\":{\"artifact\":{\"source\":\"process_image_section\",\"quality\":\"action_authoritative\",\"reason\":\"fixture\"},\"file_identity\":\"%s\",\"hash\":{\"value\":\"fixture\","
           "\"quality\":\"captured\",\"reason\":\"verified\"},\"signature\":{"
           "\"status\":\"unknown\",\"quality\":\"unknown\","
           "\"reason\":\"not_requested\"}}}",
           k_terminal_file_identity);
}

static void terminal_execute_hook(const EdrBehaviorRecord *record,
                                  EdrPolicyEnforcementResult *result) {
  if (!record || !result) return;
  result->attempted = 1;
  result->succeeded = 1;
  snprintf(result->action, sizeof(result->action), "%s", "terminate_process");
  snprintf(result->message, sizeof(result->message), "%s", "terminated");
}

static int set_fixture_env(const char *name, const char *value) {
#if defined(_WIN32)
  return _putenv_s(name, value) == 0;
#else
  return setenv(name, value, 1) == 0;
#endif
}

static const char *terminal_object(const char *context, size_t *out_len) {
  static const char marker[] = "\"enforcement_terminal\":";
  const char *value;
  size_t i;
  int depth = 0;
  int in_string = 0;
  int escaped = 0;
  if (!context || !out_len || !(value = strstr(context, marker))) return NULL;
  value += sizeof(marker) - 1u;
  if (*value != '{') return NULL;
  for (i = 0u; value[i]; ++i) {
    const unsigned char c = (unsigned char)value[i];
    if (in_string) {
      if (escaped) escaped = 0;
      else if (c == '\\') escaped = 1;
      else if (c == '"') in_string = 0;
    } else if (c == '"') {
      in_string = 1;
    } else if (c == '{') {
      depth++;
    } else if (c == '}') {
      if (--depth == 0) {
        *out_len = i + 1u;
        return value;
      }
      if (depth < 0) return NULL;
    }
  }
  return NULL;
}

static int terminal_record_hits_published_rule(const EdrBehaviorRecord *record) {
  int count;
  int i;
  if (!record) return 0;
  count = edr_p0_rule_ir_rule_count();
  for (i = 0; i < count; ++i) {
    const char *id = NULL;
    if (edr_p0_rule_ir_rule_id_at(i, &id) && id &&
        strcmp(id, k_terminal_rule_id) == 0) {
      return edr_p0_rule_ir_br_matches_index(record, i) == 1;
    }
  }
  return 0;
}

static int verify_terminal_fixture(void) {
  EdrBehaviorRecord input;
  EdrPolicyEnforcementResult result;
  EdrConfig block_policy;
  const char *batch_kinds[TERMINAL_FIXTURE_FRAMES] = {
      "p0-enforcement-intent", "p0-enforcement-source", "p0-enforcement-combined"};
  const char *expected_phases[TERMINAL_AUTHORITY_FRAMES] = {
      "\"phase\":\"intent\"", "\"phase\":\"result\""};
  size_t i;

  make_terminal_record(&input);
  if (!terminal_record_hits_published_rule(&input)) return 0;
  memset(&result, 0, sizeof(result));
  result.requested = 1;
  result.attempted = 1;
  result.succeeded = 1;
  snprintf(result.planned_action, sizeof(result.planned_action), "%s", "terminate_process");
  snprintf(result.action, sizeof(result.action), "%s", "terminate_process");
  snprintf(result.message, sizeof(result.message), "%s", "terminated");
  if (!edr_p0_rule_test_build_terminal_authority_records(
          &input, k_terminal_rule_id, &result,
          &s_terminal_records[0], &s_terminal_records[1])) {
    return 0;
  }
  for (i = 0u; i < TERMINAL_AUTHORITY_FRAMES; ++i) {
    s_terminal_expected_wire_lens[i] = edr_behavior_record_encode_durable_wire(
        &s_terminal_records[i], s_terminal_expected_wires[i], sizeof(s_terminal_expected_wires[i]));
    if (s_terminal_expected_wire_lens[i] <= 20u) {
      return 0;
    }
  }

  memset(s_terminal_wires, 0, sizeof(s_terminal_wires));
  memset(s_terminal_wire_lens, 0, sizeof(s_terminal_wire_lens));
  memset(s_terminal_batch_ids, 0, sizeof(s_terminal_batch_ids));
  s_terminal_capture_active = 1;
  s_terminal_precreated = 0;
  s_terminal_updated = 0;
  memset(&block_policy, 0, sizeof(block_policy));
  block_policy.policy_v2.script_mode = EDR_POLICY_MODE_BLOCK;
  edr_policy_v2_configure(&block_policy);
  if (!set_fixture_env("EDR_P0_DIRECT_EMIT", "1") ||
      !set_fixture_env("EDR_P0_DEDUP_SEC", "0")) {
    s_terminal_capture_active = 0;
    return 0;
  }
  edr_p0_rule_test_reset_dedup();
  edr_p0_rule_test_set_monotonic_ms(4242000u);
  edr_policy_enforcement_test_set_execute_hook(terminal_execute_hook);
  if (edr_p0_rule_try_emit(&input) != 1 || !s_terminal_precreated || !s_terminal_updated) {
    edr_policy_enforcement_test_set_execute_hook(NULL);
    s_terminal_capture_active = 0;
    return 0;
  }
  edr_policy_enforcement_test_set_execute_hook(NULL);
  s_terminal_capture_active = 0;

  for (i = 0u; i < TERMINAL_FIXTURE_FRAMES; ++i) {
    edr_v1_BehaviorEvent decoded = edr_v1_BehaviorEvent_init_zero;
    pb_istream_t stream;
    if (s_terminal_wire_lens[i] <= 20u ||
        s_terminal_wires[i][0] != 'B' || s_terminal_wires[i][1] != 'A' ||
        s_terminal_wires[i][2] != 'T' || s_terminal_wires[i][3] != '1' ||
        read_le32(s_terminal_wires[i] + 4u) != 1u ||
        read_le32(s_terminal_wires[i] + 8u) != s_terminal_wire_lens[i] - 12u ||
        read_le32(s_terminal_wires[i] + 12u) != s_terminal_wire_lens[i] - 16u ||
        !edr_behavior_durable_wire_batch_id(batch_kinds[i], s_terminal_wires[i],
                                            s_terminal_wire_lens[i], s_terminal_batch_ids[i],
                                            sizeof(s_terminal_batch_ids[i]))) {
      return 0;
    }
    stream = pb_istream_from_buffer(s_terminal_wires[i] + 16u,
                                    s_terminal_wire_lens[i] - 16u);
    if (!pb_decode(&stream, edr_v1_BehaviorEvent_fields, &decoded) ||
        decoded.pid != input.pid || strcmp(decoded.event_id, input.event_id) != 0 ||
        strcmp(decoded.tenant_id, input.tenant_id) != 0 ||
        strcmp(decoded.endpoint_id, input.endpoint_id) != 0) {
      return 0;
    }
    if (i < TERMINAL_AUTHORITY_FRAMES) {
      if (decoded.has_behavior_alert ||
          strcmp(decoded.exe_path, input.exe_path) != 0 ||
          s_terminal_wire_lens[i] != s_terminal_expected_wire_lens[i] ||
          memcmp(s_terminal_wires[i], s_terminal_expected_wires[i],
                 s_terminal_wire_lens[i]) != 0 ||
          strcmp(decoded.ave_result_json, s_terminal_records[i].detection_context) != 0 ||
          strstr(decoded.ave_result_json, expected_phases[i]) == NULL ||
          strstr(decoded.ave_result_json, "\"terminal_key\":\"") == NULL ||
          strstr(decoded.ave_result_json, s_binding.rules_bundle_version) == NULL ||
          strstr(decoded.ave_result_json, s_binding.artifact_sha256) == NULL ||
          strstr(decoded.ave_result_json,
                 "\"source_event_key\":\"terminal-contract-event-4242\"") == NULL ||
          strstr(decoded.ave_result_json,
                 "\"source_event_id\":\"terminal-contract-event-4242\"") == NULL ||
          strstr(decoded.ave_result_json, "\"process_pid\":4242") == NULL ||
          !(s_terminal_json[i] = terminal_object(s_terminal_records[i].detection_context,
                                                  &s_terminal_json_lens[i]))) {
        return 0;
      }
      if (i == TERMINAL_SOURCE_FRAME &&
          (decoded.process_start_key != s_terminal_records[i].process_start_key ||
           decoded.process_creation_filetime_100ns !=
               s_terminal_records[i].process_creation_filetime_100ns ||
           strcmp(decoded.process_generation_source,
                  s_terminal_records[i].process_generation_source) != 0 ||
           strcmp(decoded.image_path_raw, s_terminal_records[i].image_path_raw) != 0 ||
           strcmp(decoded.image_path_canonical,
                  s_terminal_records[i].image_path_canonical) != 0 ||
           strcmp(decoded.image_path_namespace,
                  s_terminal_records[i].image_path_namespace) != 0 ||
           strcmp(decoded.image_path_resolution_status,
                  s_terminal_records[i].image_path_resolution_status) != 0 ||
           strcmp(decoded.image_path_resolution_source,
                  s_terminal_records[i].image_path_resolution_source) != 0 ||
           strcmp(decoded.source_completeness,
                  s_terminal_records[i].source_completeness) != 0 ||
           decoded.evidence_revision != s_terminal_records[i].evidence_revision ||
           strcmp(decoded.parent_resolution_status,
                  s_terminal_records[i].parent_resolution_status) != 0 ||
           strcmp(decoded.parent_resolution_source,
                  s_terminal_records[i].parent_resolution_source) != 0 ||
           strcmp(decoded.parent_creation_time,
                  s_terminal_records[i].parent_creation_time) != 0 ||
           strcmp(decoded.transport_completeness, "COMPLETE") != 0 ||
           decoded.truncated_fields[0] != '\0')) {
        return 0;
      }
    } else if (!decoded.has_behavior_alert ||
               strcmp(decoded.exe_path, input.exe_path) != 0 ||
               strcmp(decoded.ave_result_json, s_terminal_records[TERMINAL_SOURCE_FRAME].detection_context) != 0 ||
               strcmp(decoded.behavior_alert.process_path,
                      k_terminal_canonical_image_path) != 0 ||
               strstr(decoded.behavior_alert.user_subject_json,
                      "\"process_path\":\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\"") == NULL ||
               strstr(decoded.behavior_alert.user_subject_json,
                      "\\\\Device\\\\HarddiskVolume3") != NULL) {
      return 0;
    }
  }
  return s_terminal_json_lens[0] > 0u && s_terminal_json_lens[1] > 0u &&
         s_terminal_wire_lens[TERMINAL_COMBINED_FRAME] > 20u;
}

static int verify_fixture_case(const SourceFixtureCase *fixture, size_t index) {
  EdrBehaviorRecord input;
  EdrBehaviorRecord built;
  edr_v1_BehaviorEvent decoded = edr_v1_BehaviorEvent_init_zero;
  pb_istream_t stream;
  make_record(&input, fixture, index);
  if (!edr_p0_rule_test_build_source_only_direct_record(&input, fixture->rule_id,
                                                         fixture->reason, &built) ||
      !edr_behavior_record_emit_durable(&built)) {
    return 0;
  }
  if (s_enqueue_count != index + 1u || s_wire_lens[index] <= 20u ||
      s_wires[index][0] != 'B' || s_wires[index][1] != 'A' ||
      s_wires[index][2] != 'T' || s_wires[index][3] != '1' ||
      read_le32(s_wires[index] + 4u) != 1u ||
      read_le32(s_wires[index] + 8u) != s_wire_lens[index] - 12u ||
      read_le32(s_wires[index] + 12u) != s_wire_lens[index] - 16u ||
      strncmp(s_batch_ids[index], "p0-source-", 10u) != 0) {
    return 0;
  }
  stream = pb_istream_from_buffer(s_wires[index] + 16u, s_wire_lens[index] - 16u);
  if (!pb_decode(&stream, edr_v1_BehaviorEvent_fields, &decoded) || decoded.has_behavior_alert ||
      decoded.pid != input.pid || strcmp(decoded.event_id, input.event_id) != 0 ||
      strcmp(decoded.ave_result_json, built.detection_context) != 0 ||
      strstr(decoded.ave_result_json, "\"stage\":\"direct\"") == NULL ||
      strstr(decoded.ave_result_json, fixture->rule_id) == NULL ||
      strstr(decoded.ave_result_json, s_binding.rules_bundle_version) == NULL ||
      strstr(decoded.ave_result_json, s_binding.artifact_sha256) == NULL ||
      strstr(decoded.ave_result_json, fixture->reason) == NULL) {
    return 0;
  }
  return 1;
}

static const char *fixture_event_type_name(EdrEventType type) {
  switch (type) {
  case EDR_EVENT_PROCESS_CREATE: return "process_create";
  case EDR_EVENT_FILE_READ: return "file_read";
  case EDR_EVENT_FILE_WRITE: return "file_write";
  case EDR_EVENT_NET_CONNECT: return "network_connect";
  case EDR_EVENT_REG_SET_VALUE: return "registry_set";
  case EDR_EVENT_CAPABILITY_AUDIT: return "capability_audit";
  default: return "unknown";
  }
}

static int verify_ruleset_evaluation_fixture(const SourceFixtureCase *fixture,
                                             size_t ruleset_index) {
  const size_t index = SOURCE_FIXTURE_CASES + ruleset_index;
  EdrBehaviorRecord input;
  EdrBehaviorRecord built;
  edr_v1_BehaviorEvent decoded = edr_v1_BehaviorEvent_init_zero;
  pb_istream_t stream;
  make_record(&input, fixture, index);
  input.process_start_key = 0x6103u;
  input.process_creation_filetime_100ns = 133444555666777888ULL;
  if (!edr_p0_rule_test_build_source_only_ruleset_evaluation_record(
          &input, fixture->reason, &built) ||
      !edr_behavior_record_emit_durable(&built)) {
    return 0;
  }
  if (s_enqueue_count != index + 1u || s_wire_lens[index] <= 20u ||
      strncmp(s_batch_ids[index], "p0-source-", 10u) != 0) {
    return 0;
  }
  stream = pb_istream_from_buffer(s_wires[index] + 16u, s_wire_lens[index] - 16u);
  if (!pb_decode(&stream, edr_v1_BehaviorEvent_fields, &decoded) || decoded.has_behavior_alert ||
      decoded.pid != input.pid || strcmp(decoded.event_id, input.event_id) != 0 ||
      strcmp(decoded.ave_result_json, built.detection_context) != 0 ||
      strstr(decoded.ave_result_json, "\"stage\":\"ruleset_evaluation\"") == NULL ||
      strstr(decoded.ave_result_json,
             "\"gate_id\":\"P0_RULESET_EVALUATION_GATE\"") == NULL ||
      strstr(decoded.ave_result_json, fixture->reason) == NULL ||
      strstr(decoded.ave_result_json, "\"rule_id\"") != NULL ||
      strstr(decoded.ave_result_json, "\"rules_bundle_") != NULL) {
    return 0;
  }
  return 1;
}

static int verify_collector_evidence_fixture(const SourceFixtureCase *fixture,
                                             size_t collector_index) {
  const size_t index = SOURCE_FIXTURE_CASES + RULESET_EVALUATION_FIXTURE_CASES +
                       collector_index;
  EdrBehaviorRecord input;
  EdrBehaviorRecord built;
  edr_v1_BehaviorEvent decoded = edr_v1_BehaviorEvent_init_zero;
  pb_istream_t stream;
  make_record(&input, fixture, index);
  input.file_key = 0xabcULL;
  input.process_start_key = 0x6104u;
  input.process_creation_filetime_100ns = 0u;
  if (strcmp(fixture->reason, EDR_P0_FILE_READ_REASON_START_KEY_MISSING) == 0) {
    input.process_start_key = 0u;
  } else if (strcmp(fixture->reason,
                    EDR_P0_FILE_READ_REASON_CANONICAL_PATH_UNRESOLVED) == 0 ||
             strcmp(fixture->reason,
                    EDR_P0_FILE_READ_REASON_PAYLOAD_UNAVAILABLE) == 0 ||
             strcmp(fixture->reason,
                    EDR_P0_FILE_READ_REASON_EVENT_TIME_UNAVAILABLE) == 0) {
    input.file_path[0] = '\0';
    input.file_key = 0u;
    input.process_start_key = 0u;
    if (strcmp(fixture->reason,
               EDR_P0_FILE_READ_REASON_EVENT_TIME_UNAVAILABLE) == 0) {
      input.event_time_ns = 0;
    }
  }
  snprintf(input.collector_evidence_gate, sizeof(input.collector_evidence_gate), "%s",
           EDR_P0_FILE_READ_METADATA_GATE);
  snprintf(input.collector_evidence_reason, sizeof(input.collector_evidence_reason), "%s",
           fixture->reason);
  if (!edr_p0_rule_test_build_source_only_collector_evidence_record(&input, &built) ||
      !edr_behavior_record_emit_durable(&built)) {
    return 0;
  }
  if (s_enqueue_count != index + 1u || s_wire_lens[index] <= 20u ||
      strncmp(s_batch_ids[index], "p0-source-", 10u) != 0) {
    return 0;
  }
  stream = pb_istream_from_buffer(s_wires[index] + 16u, s_wire_lens[index] - 16u);
  if (!pb_decode(&stream, edr_v1_BehaviorEvent_fields, &decoded) || decoded.has_behavior_alert ||
      decoded.pid != input.pid || strcmp(decoded.event_id, input.event_id) != 0 ||
      strcmp(decoded.ave_result_json, built.detection_context) != 0 ||
      strstr(decoded.ave_result_json, "\"stage\":\"collector_evidence_gate\"") == NULL ||
      strstr(decoded.ave_result_json,
             "\"gate_id\":\"P0_FILE_READ_METADATA_GATE\"") == NULL ||
      strstr(decoded.ave_result_json, fixture->reason) == NULL ||
      strstr(decoded.ave_result_json, "\"canonical_path\":") == NULL ||
      strstr(decoded.ave_result_json, "\"rule_id\"") != NULL ||
      strstr(decoded.ave_result_json, "\"rules_bundle_") != NULL) {
    return 0;
  }
  if (strcmp(fixture->reason, EDR_P0_FILE_READ_REASON_CANONICAL_PATH_UNRESOLVED) == 0 ||
      strcmp(fixture->reason, EDR_P0_FILE_READ_REASON_PAYLOAD_UNAVAILABLE) == 0 ||
      strcmp(fixture->reason, EDR_P0_FILE_READ_REASON_EVENT_TIME_UNAVAILABLE) == 0) {
    if (strstr(decoded.ave_result_json, "\"canonical_path\":null") == NULL ||
        strstr(decoded.ave_result_json, "\"file_key\":null") == NULL ||
        strstr(decoded.ave_result_json, "\"process_start_key\":null") == NULL) {
      return 0;
    }
    if (strcmp(fixture->reason,
               EDR_P0_FILE_READ_REASON_EVENT_TIME_UNAVAILABLE) == 0 &&
        strstr(decoded.ave_result_json, "\"event_time_ns\":\"0\"") == NULL) {
      return 0;
    }
  } else if (strstr(decoded.ave_result_json,
                    "\"file_key\":\"0x0000000000000abc\"") == NULL ||
             (strcmp(fixture->reason, EDR_P0_FILE_READ_REASON_START_KEY_MISSING) == 0
                  ? strstr(decoded.ave_result_json, "\"process_start_key\":null") == NULL
                  : strstr(decoded.ave_result_json,
                           "\"process_start_key\":\"24836\"") == NULL)) {
    return 0;
  }
  return 1;
}

static int verify_source_only_delivery_fixture(void) {
  const size_t index = SOURCE_FIXTURE_CASES + RULESET_EVALUATION_FIXTURE_CASES +
                       COLLECTOR_EVIDENCE_FIXTURE_CASES;
  EdrBehaviorRecord built;
  edr_v1_BehaviorEvent decoded = edr_v1_BehaviorEvent_init_zero;
  pb_istream_t stream;

  /* This is the production builder, not a hand-written JSON shortcut. The
   * runtime endpoint identity is part of the durable source event, while the
   * queue tuple makes retry/restart batch bytes stable. */
  edr_p0_rule_source_only_set_runtime_identity("tenant-source-contract",
                                                "endpoint-source-contract");
  if (!edr_p0_rule_test_build_source_only_delivery_record(
          k_delivery_queue_nonce, k_delivery_latch_counter, k_delivery_latch_epoch, &built) ||
      !edr_behavior_record_emit_durable(&built)) {
    return 0;
  }
  if (s_enqueue_count != index + 1u || s_wire_lens[index] <= 20u ||
      strncmp(s_batch_ids[index], "p0-source-", 10u) != 0 ||
      built.type != EDR_EVENT_CAPABILITY_AUDIT || built.pid != 0u ||
      built.event_time_ns != 0 ||
      strncmp(built.event_id, "p0sl-", 5u) != 0 || strlen(built.event_id) != 45u) {
    return 0;
  }
  snprintf(s_delivery_event_id, sizeof(s_delivery_event_id), "%s", built.event_id);
  stream = pb_istream_from_buffer(s_wires[index] + 16u, s_wire_lens[index] - 16u);
  if (!pb_decode(&stream, edr_v1_BehaviorEvent_fields, &decoded) ||
      decoded.has_behavior_alert || decoded.type != EDR_EVENT_CAPABILITY_AUDIT ||
      decoded.pid != 0u || decoded.event_time_ns != 0 ||
      strcmp(decoded.event_id, built.event_id) != 0 ||
      strcmp(decoded.ave_result_json, built.detection_context) != 0 ||
      strstr(decoded.ave_result_json, "\"stage\":\"source_only_delivery\"") == NULL ||
      strstr(decoded.ave_result_json,
             "\"gate_id\":\"P0_SOURCE_ONLY_DURABILITY_GATE\"") == NULL ||
      strstr(decoded.ave_result_json,
             "\"reason\":\"pending_assertion_lost_on_restart\"") == NULL ||
      strstr(decoded.ave_result_json, "\"loss_detected\":true") == NULL ||
      strstr(decoded.ave_result_json,
             "\"queue_nonce\":\"1032547698badcfe0123456789abcdef\"") == NULL ||
      strstr(decoded.ave_result_json, "\"latch_counter\":\"1193046\"") == NULL ||
      strstr(decoded.ave_result_json, "\"latch_epoch\":\"7\"") == NULL ||
      strstr(decoded.ave_result_json, "\"commitment_sha256\":\"") == NULL ||
      strstr(decoded.ave_result_json, "\"rule_id\"") != NULL ||
      strstr(decoded.ave_result_json, "\"rules_bundle_") != NULL ||
      strstr(decoded.ave_result_json, "\"alert\"") != NULL ||
      strstr(decoded.ave_result_json, "\"action\"") != NULL) {
    return 0;
  }
  return 1;
}

static int verify_source_truncation_pre_evaluation_durable(void) {
  static const SourceFixtureCase fixture = {
      EDR_EVENT_PROCESS_CREATE, "source-contract-truncated-process-1", "", ""};
  EdrBehaviorRecord input;
  EdrBehaviorRecord built;
  uint8_t wire[65536u + 16u];
  edr_v1_BehaviorEvent decoded = edr_v1_BehaviorEvent_init_zero;
  pb_istream_t stream;
  size_t wire_len;

  make_record(&input, &fixture, 99u);
  input.process_start_key = UINT64_C(0x6001);
  input.process_creation_filetime_100ns = UINT64_C(133444555666777888);
  snprintf(input.source_completeness, sizeof(input.source_completeness), "%s", "TRUNCATED");
  snprintf(input.source_truncated_fields, sizeof(input.source_truncated_fields), "%s",
           "source.process_name,source.exe_hash,source.parent_path");
  input.process_name[0] = '\0';
  input.exe_hash[0] = '\0';
  input.parent_path[0] = '\0';
  if (!edr_p0_source_only_build_pre_evaluation_record(
          &input, "source_fields_truncated", &built) ||
      strcmp(built.source_completeness, "NOT_EVALUABLE") != 0 ||
      strcmp(built.source_truncated_fields, input.source_truncated_fields) != 0) {
    return 0;
  }
  wire_len = edr_behavior_record_encode_durable_wire(&built, wire, sizeof(wire));
  if (wire_len <= 16u || wire[0] != 'B' || wire[1] != 'A' || wire[2] != 'T' ||
      wire[3] != '1') {
    return 0;
  }
  stream = pb_istream_from_buffer(wire + 16u, wire_len - 16u);
  if (!pb_decode(&stream, edr_v1_BehaviorEvent_fields, &decoded) ||
      decoded.has_behavior_alert ||
      strcmp(decoded.source_completeness, "NOT_EVALUABLE") != 0 ||
      strcmp(decoded.transport_completeness, "COMPLETE") != 0 ||
      strcmp(decoded.truncated_fields, input.source_truncated_fields) != 0 ||
      strstr(decoded.ave_result_json, "\"stage\":\"pre_evaluation\"") == NULL ||
      strstr(decoded.ave_result_json, "\"reason\":\"source_fields_truncated\"") == NULL ||
      strstr(decoded.ave_result_json, "\"gate_id\":\"P0_PROCESS_EVIDENCE_GATE\"") == NULL) {
    return 0;
  }
  return 1;
}

static void print_authority_contract(void) {
  size_t i;
  int first;
  printf("{\n  \"schema\": \"edr.p0_source_only_contract.v2\",\n");
  printf("  \"source_contract_version\": \"%s\",\n", EDR_P0_SOURCE_ONLY_CONTRACT_VERSION);
  printf("  \"stages\": {\n");
  printf("    \"pre_evaluation\": {\"event_type\": \"process_create\", \"gate_id\": \"%s\", \"reasons\": [",
         EDR_P0_PROCESS_EVIDENCE_GATE);
  first = 1;
  for (i = 0u; i < edr_p0_source_only_reason_count(); ++i) {
    const EdrP0SourceOnlyReason *reason = &edr_p0_source_only_reason_table[i];
    if (reason->stage != EDR_P0_SOURCE_ONLY_STAGE_PRE_EVALUATION) continue;
    printf("%s\"%s\"", first ? "" : ", ", reason->reason);
    first = 0;
  }
  printf("]},\n");
  printf("    \"direct\": {\"requires\": [\"rule_id\", \"rules_bundle_version\", \"rules_bundle_sha256\"], \"rule_binding\": \"published_p0_ir\", \"reasons\": [");
  {
    first = 1;
    for (i = 0u; i < edr_p0_source_only_reason_count(); ++i) {
      const EdrP0SourceOnlyReason *reason = &edr_p0_source_only_reason_table[i];
      if (reason->stage != EDR_P0_SOURCE_ONLY_STAGE_DIRECT) continue;
      printf("%s\"%s\"", first ? "" : ", ", reason->reason);
      first = 0;
    }
  }
  printf("]},\n");
  printf("    \"ruleset_evaluation\": {\"event_types\": [\"process_create\", \"file_read\", \"file_write\", \"network_connect\", \"registry_set\"], \"gate_id\": \"%s\", \"forbids\": [\"rule_id\", \"rules_bundle_version\", \"rules_bundle_sha256\", \"alert\", \"action\"], \"reasons\": [",
         EDR_P0_RULESET_EVALUATION_GATE);
  first = 1;
  for (i = 0u; i < edr_p0_source_only_reason_count(); ++i) {
    const EdrP0SourceOnlyReason *reason = &edr_p0_source_only_reason_table[i];
    if (reason->stage != EDR_P0_SOURCE_ONLY_STAGE_RULESET_EVALUATION) continue;
    printf("%s\"%s\"", first ? "" : ", ", reason->reason);
    first = 0;
  }
  printf("]},\n");
  printf("    \"collector_evidence_gate\": {\"event_types\": [\"file_read\"], \"gate_id\": \"%s\", \"forbids\": [\"rule_id\", \"rules_bundle_version\", \"rules_bundle_sha256\", \"alert\", \"action\"], \"collector_metadata\": {\"canonical_path\":\"required_or_null_only_for_registered_unresolved_reason\",\"null_canonical_path_reasons\":[\"file_read_canonical_path_unresolved\",\"file_read_payload_unavailable\",\"file_read_event_time_unavailable\"],\"file_key\":\"nullable_hex64\",\"pid\":\"nullable_uint32\",\"process_start_key\":\"nullable_decimal_u64\",\"event_time_ns\":\"required_decimal_i64_zero_only_for_file_read_event_time_unavailable\"}, \"reasons\": [",
         EDR_P0_FILE_READ_METADATA_GATE);
  first = 1;
  for (i = 0u; i < edr_p0_source_only_reason_count(); ++i) {
    const EdrP0SourceOnlyReason *reason = &edr_p0_source_only_reason_table[i];
    if (reason->stage != EDR_P0_SOURCE_ONLY_STAGE_COLLECTOR_EVIDENCE_GATE) continue;
    printf("%s\"%s\"", first ? "" : ", ", reason->reason);
    first = 0;
  }
  printf("]},\n");
  printf("    \"source_only_delivery\": {\"event_type\": \"capability_audit\", \"gate_id\": \"%s\", \"requires\": [\"loss_detected=true\", \"source_only_delivery.queue_nonce\", \"source_only_delivery.latch_counter\", \"source_only_delivery.latch_epoch\", \"source_only_delivery.commitment_sha256\", \"source_only_delivery.latch_id\"], \"forbids\": [\"rule_id\", \"rules_bundle_version\", \"rules_bundle_sha256\", \"alert\", \"action\"], \"reasons\": [",
         EDR_P0_SOURCE_ONLY_DURABILITY_GATE);
  first = 1;
  for (i = 0u; i < edr_p0_source_only_reason_count(); ++i) {
    const EdrP0SourceOnlyReason *reason = &edr_p0_source_only_reason_table[i];
    if (reason->stage != EDR_P0_SOURCE_ONLY_STAGE_SOURCE_ONLY_DELIVERY) continue;
    printf("%s\"%s\"", first ? "" : ", ", reason->reason);
    first = 0;
  }
  printf("]}\n  }\n}\n");
}

static void print_durable_fixture(void) {
  size_t i;
  int first = 1;
  printf("{\n  \"fixture_version\": 1,\n");
  printf("  \"source_contract_version\": \"%s\",\n", EDR_P0_SOURCE_ONLY_CONTRACT_VERSION);
  printf("  \"agent_builder\": \"p0_build_source_only_direct_record+p0_build_source_only_ruleset_evaluation_record+p0_build_source_only_collector_evidence_record+p0_build_source_only_delivery_record\",\n");
  printf("  \"agent_encoder\": \"edr_behavior_record_encode_durable_wire\",\n");
  printf("  \"bat1_version\": 1,\n  \"bat1_length_byte_order\": \"little_endian\",\n");
  printf("  \"reproduce_with\": \"edr-agent/tests/test_p0_source_only_durable_contract --emit-p0-source-only-durable-fixture\",\n");
  printf("  \"fixtures\": [\n");
  for (i = 0u; i < SOURCE_FIXTURE_CASES; ++i) {
    const char *event_type = fixture_event_type_name(k_cases[i].type);
    printf("%s    {\"stage\":\"direct\",\"event_type\":\"%s\",\"event_id\":\"%s\",\"rule_id\":\"%s\",\"reason\":\"%s\",\"rules_bundle_version\":\"%s\",\"rules_bundle_sha256\":\"%s\",\"batch_id\":\"%s\",\"bat1_base64\":\"",
           first ? "" : ",\n",
           event_type, k_cases[i].event_id, k_cases[i].rule_id, k_cases[i].reason,
           s_binding.rules_bundle_version, s_binding.artifact_sha256, s_batch_ids[i]);
    print_base64(s_wires[i], s_wire_lens[i]);
    printf("\"}");
    first = 0;
  }
  for (i = 0u; i < RULESET_EVALUATION_FIXTURE_CASES; ++i) {
    const SourceFixtureCase *fixture = &k_ruleset_evaluation_cases[i];
    const size_t index = SOURCE_FIXTURE_CASES + i;
    printf("%s    {\"stage\":\"ruleset_evaluation\",\"event_type\":\"%s\",\"event_id\":\"%s\",\"reason\":\"%s\",\"gate_id\":\"%s\",\"batch_id\":\"%s\",\"bat1_base64\":\"",
           first ? "" : ",\n", fixture_event_type_name(fixture->type), fixture->event_id,
           fixture->reason, EDR_P0_RULESET_EVALUATION_GATE, s_batch_ids[index]);
    print_base64(s_wires[index], s_wire_lens[index]);
    printf("\"}");
    first = 0;
  }
  for (i = 0u; i < COLLECTOR_EVIDENCE_FIXTURE_CASES; ++i) {
    const SourceFixtureCase *fixture = &k_collector_evidence_cases[i];
    const size_t index = SOURCE_FIXTURE_CASES + RULESET_EVALUATION_FIXTURE_CASES + i;
    printf("%s    {\"stage\":\"collector_evidence_gate\",\"event_type\":\"file_read\",\"event_id\":\"%s\",\"reason\":\"%s\",\"gate_id\":\"%s\",\"batch_id\":\"%s\",\"bat1_base64\":\"",
           first ? "" : ",\n",
           fixture->event_id, fixture->reason,
           EDR_P0_FILE_READ_METADATA_GATE, s_batch_ids[index]);
    print_base64(s_wires[index], s_wire_lens[index]);
    printf("\"}");
    first = 0;
  }
  {
    const size_t index = SOURCE_FIXTURE_CASES + RULESET_EVALUATION_FIXTURE_CASES +
                         COLLECTOR_EVIDENCE_FIXTURE_CASES;
    printf("%s    {\"stage\":\"source_only_delivery\",\"event_type\":\"capability_audit\",\"event_id\":",
           first ? "" : ",\n");
    print_json_string(s_delivery_event_id);
    printf(",\"reason\":\"pending_assertion_lost_on_restart\",\"gate_id\":\"%s\",\"loss_detected\":true,\"queue_nonce\":\"1032547698badcfe0123456789abcdef\",\"latch_counter\":\"%llu\",\"latch_epoch\":\"%llu\",\"batch_id\":\"%s\",\"bat1_base64\":\"",
           EDR_P0_SOURCE_ONLY_DURABILITY_GATE,
           (unsigned long long)k_delivery_latch_counter,
           (unsigned long long)k_delivery_latch_epoch, s_batch_ids[index]);
    print_base64(s_wires[index], s_wire_lens[index]);
    printf("\"}\n");
  }
  printf("  ]\n}\n");
}

static void print_terminal_authority_golden(void) {
  printf("{\n");
  printf("  \"tenant_id\": \"%s\",\n", k_terminal_tenant_id);
  printf("  \"endpoint_id\": \"%s\",\n", k_terminal_endpoint_id);
  printf("  \"event_id\": \"%s\",\n", k_terminal_event_id);
  printf("  \"pid\": 4242,\n");
  printf("  \"source_record\": {\"raw_exe_path\":");
  print_json_string(k_terminal_raw_image_path);
  printf(",\"canonical_image_path\":");
  print_json_string(k_terminal_canonical_image_path);
  printf("},\n");
  printf("  \"intent\": ");
  fwrite(s_terminal_json[0], 1u, s_terminal_json_lens[0], stdout);
  printf(",\n  \"result\": ");
  fwrite(s_terminal_json[1], 1u, s_terminal_json_lens[1], stdout);
  printf(",\n  \"combined_expectations\": {\"outer_exe_path\":");
  print_json_string(k_terminal_raw_image_path);
  printf(",\"alert_process_path\":");
  print_json_string(k_terminal_canonical_image_path);
  printf(",\"subject_process_path\":");
  print_json_string(k_terminal_canonical_image_path);
  printf("}");
  printf("\n}\n");
}

static void print_terminal_durable_fixture(void) {
  size_t i;
  int first = 1;
  printf("{\n  \"fixture_version\": 1,\n");
  printf("  \"agent_builder\": \"edr_p0_rule_try_emit+p0_build_terminal_intent_record+p0_build_terminal_result_record\",\n");
  printf("  \"agent_encoder\": \"edr_behavior_record_encode_durable_wire\",\n");
  printf("  \"bat1_version\": 1,\n  \"bat1_length_byte_order\": \"little_endian\",\n");
  printf("  \"reproduce_with\": \"EDR_P0_IR_PATH=edr-agent/config/p0_rule_bundle_ir_v1.json edr-agent/tests/test_p0_source_only_durable_contract --emit-terminal-authority-durable-fixture\",\n");
  printf("  \"not_evaluable_reasons\": [");
  for (i = 0u; i < edr_p0_source_only_reason_count(); ++i) {
    const EdrP0SourceOnlyReason *reason = &edr_p0_source_only_reason_table[i];
    if (reason->stage != EDR_P0_SOURCE_ONLY_STAGE_PRE_EVALUATION) continue;
    printf("%s\n    \"%s\"", first ? "" : ",", reason->reason);
    first = 0;
  }
  printf("\n  ],\n");
  printf("  \"outer\": {\"tenant_id\":\"%s\",\"endpoint_id\":\"%s\",\"event_id\":\"%s\",\"pid\":4242,\"raw_exe_path\":",
         k_terminal_tenant_id, k_terminal_endpoint_id, k_terminal_event_id);
  print_json_string(k_terminal_raw_image_path);
  printf(",\"canonical_image_path\":");
  print_json_string(k_terminal_canonical_image_path);
  printf("},\n");
  printf("  \"authority\": ");
  fwrite(s_terminal_json[0], 1u, s_terminal_json_lens[0], stdout);
  printf(",\n");
  printf("  \"intent_batch_id\": \"%s\",\n", s_terminal_batch_ids[0]);
  printf("  \"result_batch_id\": \"%s\",\n", s_terminal_batch_ids[1]);
  printf("  \"combined_batch_id\": \"%s\",\n", s_terminal_batch_ids[2]);
  printf("  \"intent_bat1_base64\": \"");
  print_base64(s_terminal_wires[0], s_terminal_wire_lens[0]);
  printf("\",\n  \"result_bat1_base64\": \"");
  print_base64(s_terminal_wires[1], s_terminal_wire_lens[1]);
  printf("\",\n  \"combined_bat1_base64\": \"");
  print_base64(s_terminal_wires[2], s_terminal_wire_lens[2]);
  printf("\",\n  \"combined_expectations\": {\"outer_exe_path\":");
  print_json_string(k_terminal_raw_image_path);
  printf(",\"alert_process_path\":");
  print_json_string(k_terminal_canonical_image_path);
  printf(",\"subject_process_path\":");
  print_json_string(k_terminal_canonical_image_path);
  printf("}\n}\n");
}

int main(int argc, char **argv) {
  size_t i;
  int emit_contract = argc == 2 && strcmp(argv[1], "--emit-p0-source-only-contract") == 0;
  int emit_fixture = argc == 2 && strcmp(argv[1], "--emit-p0-source-only-durable-fixture") == 0;
  int emit_terminal_golden = argc == 2 && strcmp(argv[1], "--emit-terminal-authority-golden") == 0;
  int emit_terminal_fixture =
      argc == 2 && strcmp(argv[1], "--emit-terminal-authority-durable-fixture") == 0;
  if (argc > 1 && !emit_contract && !emit_fixture && !emit_terminal_golden &&
      !emit_terminal_fixture) return 2;
  edr_p0_rule_ir_lazy_init();
  {
    const char *loaded_sha256 = NULL;
    if (!edr_p0_rule_ir_is_ready() || !edr_p0_rule_ir_get_binding(&s_binding) ||
        edr_p0_rule_ir_get_bundle_info(NULL, NULL, &loaded_sha256) <= 0 ||
        !loaded_sha256 || strcmp(loaded_sha256, s_binding.artifact_sha256) != 0) {
      fprintf(stderr, "published P0 IR fixture authority unavailable or mismatched\n");
      return 1;
    }
  }
  for (i = 0u; i < SOURCE_FIXTURE_CASES; ++i) {
    if (!verify_fixture_case(&k_cases[i], i)) {
      fprintf(stderr, "p0 source-only durable fixture %zu failed\n", i);
      return 1;
    }
  }
  for (i = 0u; i < RULESET_EVALUATION_FIXTURE_CASES; ++i) {
    if (!verify_ruleset_evaluation_fixture(&k_ruleset_evaluation_cases[i], i)) {
      fprintf(stderr, "p0 ruleset-evaluation durable fixture %zu failed\n", i);
      return 1;
    }
  }
  for (i = 0u; i < COLLECTOR_EVIDENCE_FIXTURE_CASES; ++i) {
    if (!verify_collector_evidence_fixture(&k_collector_evidence_cases[i], i)) {
      fprintf(stderr, "p0 collector-evidence durable fixture %zu failed\n", i);
      return 1;
    }
  }
  if (!verify_source_only_delivery_fixture()) {
    fprintf(stderr, "p0 source-only-delivery durable fixture failed\n");
    return 1;
  }
  if (!verify_source_truncation_pre_evaluation_durable()) {
    fprintf(stderr, "source truncation pre-evaluation durable fixture failed\n");
    return 1;
  }
  if (!verify_terminal_fixture()) {
    fprintf(stderr, "terminal authority durable fixture failed\n");
    return 1;
  }
  if (emit_contract) print_authority_contract();
  if (emit_fixture) print_durable_fixture();
  if (emit_terminal_golden) print_terminal_authority_golden();
  if (emit_terminal_fixture) print_terminal_durable_fixture();
  return 0;
}
