#include "edr/alert_governor.h"
#include "edr/behavior_alert_emit.h"
#include "edr/event_batch.h"
#include "edr/policy_v2.h"
#include "edr/p0_source_only_contract.h"
#include "edr/preprocess.h"
#include "edr/process_tree_cache.h"
#include "edr/storage_queue.h"

#include "edr/v1/event.pb.h"
#include <pb_decode.h>

#include <stdio.h>
#include <string.h>

static int s_queue_open;
static EdrError s_enqueue_result;
static unsigned s_enqueue_calls;
static int s_enqueue_severity;
static char s_batch_id[128];
static uint8_t s_wire[edr_v1_BehaviorEvent_size];
static size_t s_wire_len;

int edr_policy_v2_alert_allowed(const char *triggered_tactics, const char *subject_json) {
  (void)triggered_tactics;
  (void)subject_json;
  return 1;
}

int edr_pt_cache_snapshot_at(uint32_t pid, uint64_t event_time_ns, ProcessTreeEntry *out) {
  (void)pid;
  (void)event_time_ns;
  (void)out;
  return -1;
}

void edr_preprocess_copy_agent_ids(char *endpoint_id, size_t endpoint_cap, char *tenant_id,
                                   size_t tenant_cap) {
  if (endpoint_cap > 0u) endpoint_id[0] = '\0';
  if (tenant_cap > 0u) tenant_id[0] = '\0';
}

int edr_event_batch_push(const uint8_t *wire, size_t wire_len) {
  (void)wire;
  (void)wire_len;
  return -1;
}

int edr_storage_queue_is_open(void) { return s_queue_open; }

EdrError edr_storage_queue_enqueue(const char *batch_id, const uint8_t *wire,
                                   size_t wire_len, int compressed, int severity) {
  (void)compressed;
  s_enqueue_calls++;
  snprintf(s_batch_id, sizeof(s_batch_id), "%s", batch_id ? batch_id : "");
  s_enqueue_severity = severity;
  if (s_enqueue_result == EDR_OK && wire_len >= 16u && wire_len - 16u <= sizeof(s_wire)) {
    uint32_t n = (uint32_t)wire[12] | ((uint32_t)wire[13] << 8) |
                 ((uint32_t)wire[14] << 16) | ((uint32_t)wire[15] << 24);
    if ((size_t)n == wire_len - 16u) {
      memcpy(s_wire, wire + 16u, n);
      s_wire_len = n;
    }
  }
  return s_enqueue_result;
}

int main(void) {
  EdrBehaviorRecord record;
  AVEBehaviorAlert alert;
  edr_v1_BehaviorEvent decoded = edr_v1_BehaviorEvent_init_zero;

  memset(&record, 0, sizeof(record));
  snprintf(record.event_id, sizeof(record.event_id), "source-frame");
  snprintf(record.exe_path, sizeof(record.exe_path), "C:/source.exe");
  record.pid = 8080u;

  memset(&alert, 0, sizeof(alert));
  alert.pid = 8080u;
  snprintf(alert.process_name, sizeof(alert.process_name), "source.exe");
  snprintf(alert.user_subject_json, sizeof(alert.user_subject_json),
           "{\"rule_id\":\"R-TEST\"}");

  edr_alert_governor_reset_for_test();
  s_queue_open = 0;
  s_enqueue_result = EDR_OK;
  if (edr_behavior_record_alert_emit_to_batch(&record, &alert) != 0 || s_enqueue_calls != 0u) {
    fprintf(stderr, "closed durable queue was reported as a successful combined frame\n");
    return 1;
  }

  s_queue_open = 1;
  s_enqueue_result = EDR_ERR_QUEUE_FULL;
  if (edr_behavior_record_alert_emit_to_batch(&record, &alert) != 0 || s_enqueue_calls != 1u) {
    fprintf(stderr, "queue-full durable handoff was reported as successful\n");
    return 2;
  }
  s_enqueue_result = EDR_ERR_SQLITE_WRITE;
  if (edr_behavior_record_alert_emit_to_batch(&record, &alert) != 0 || s_enqueue_calls != 2u) {
    fprintf(stderr, "storage write failure was reported as successful\n");
    return 3;
  }
  s_enqueue_result = EDR_OK;
  if (edr_behavior_record_alert_emit_to_batch(&record, &alert) != 1 || s_enqueue_calls != 3u ||
      s_enqueue_severity != 1) {
    fprintf(stderr, "combined frame was not durably accepted at high priority\n");
    return 4;
  }
  if (strncmp(s_batch_id, "p0-", 3u) != 0 || strlen(s_batch_id) != 67u) {
    fprintf(stderr, "combined P0 batch id is not a full durable payload SHA-256\n");
    return 5;
  }
  {
    EdrAlertGovernorStats stats;
    edr_alert_governor_get_stats(&stats);
    if (stats.admitted != 1u || stats.suppressed != 0u) {
      fprintf(stderr, "failed push polluted governor state\n");
      return 5;
    }
  }
  pb_istream_t stream = pb_istream_from_buffer(s_wire, s_wire_len);
  if (!pb_decode(&stream, edr_v1_BehaviorEvent_fields, &decoded) ||
      strcmp(decoded.event_id, record.event_id) != 0 || !decoded.has_behavior_alert ||
      strcmp(decoded.behavior_alert.user_subject_json, alert.user_subject_json) != 0) {
    fprintf(stderr, "combined frame did not preserve source and nested alert\n");
    return 6;
  }
  memset(&decoded, 0, sizeof(decoded));
  record.type = EDR_EVENT_PROCESS_CREATE;
  if (!edr_p0_source_only_build_pre_evaluation_record(
          &record, "missing_process_identity", &record)) {
    fprintf(stderr, "production pre-evaluation source-only builder rejected valid input\n");
    return 7;
  }
  if (edr_behavior_record_emit_durable(&record) != 1 || s_enqueue_calls != 4u ||
      s_enqueue_severity != EDR_STORAGE_QUEUE_SEVERITY_P0_SOURCE_ONLY) {
    fprintf(stderr, "source-only P0 disposition was not durably accepted\n");
    return 7;
  }
  if (strncmp(s_batch_id, "p0-source-", 10u) != 0 || strlen(s_batch_id) != 74u) {
    fprintf(stderr, "source-only P0 batch id is not a full durable payload SHA-256\n");
    return 8;
  }
  stream = pb_istream_from_buffer(s_wire, s_wire_len);
  if (!pb_decode(&stream, edr_v1_BehaviorEvent_fields, &decoded) ||
      decoded.has_behavior_alert || strcmp(decoded.event_id, record.event_id) != 0 ||
      strcmp(decoded.ave_result_json, record.detection_context) != 0) {
    fprintf(stderr, "source-only P0 disposition did not preserve source evidence\n");
    return 8;
  }
  snprintf(record.detection_context, sizeof(record.detection_context),
           "{\"p0_disposition\":\"NOT_EVALUABLE\",\"reason\":\"missing_process_identity\"}");
  if (edr_behavior_record_emit_durable(&record) != 0 || s_enqueue_calls != 4u) {
    fprintf(stderr, "malformed source-only P0 disposition bypassed the durable contract\n");
    return 9;
  }
  return 0;
}
