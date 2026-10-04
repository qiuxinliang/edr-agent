/**
 * 最小化 AVE SDK 自检：AVE_Init / AVE_GetVersion / AVE_ScanFile（首个可选参数为待扫文件）。
 */
#include "edr/ave_sdk.h"
#include "edr/ingest_http.h"
#include "edr/preprocess.h"
#include "edr/behavior_proto.h"
#include "edr/egress_batch_policy.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdatomic.h>
#ifdef _WIN32
#include <windows.h>
static void pause_ms(void) { Sleep(1); }
#else
#include <time.h>
static void pause_ms(void) { struct timespec d = {0, 1000000L}; nanosleep(&d, NULL); }
#endif

static atomic_int s_block_callback;
static atomic_uint s_callbacks;
static void AVE_CALL on_behavior(const AVEBehaviorAlert *alert, void *user_data) {
  (void)user_data;
  assert(alert->pid >= 5000u && alert->pid <= 5020u);
  cJSON *subject = cJSON_ParseWithOpts(alert->user_subject_json, NULL, 1);
  const cJSON *type = cJSON_GetObjectItemCaseSensitive(subject, "subject_type");
  const cJSON *basis = cJSON_GetObjectItemCaseSensitive(subject, "evaluation_basis");
  const cJSON *owner = cJSON_GetObjectItemCaseSensitive(basis, "owner");
  const cJSON *pid = cJSON_GetObjectItemCaseSensitive(basis, "pid");
  const cJSON *threshold = cJSON_GetObjectItemCaseSensitive(basis, "threshold");
  const cJSON *count = cJSON_GetObjectItemCaseSensitive(basis, "event_count");
  const cJSON *flags = cJSON_GetObjectItemCaseSensitive(basis, "behavior_flags");
  const cJSON *timestamp = cJSON_GetObjectItemCaseSensitive(basis, "timestamp_ns");
  char expected_time[32];
  snprintf(expected_time, sizeof(expected_time), "%lld", (long long)alert->timestamp_ns);
  assert(cJSON_IsString(type) && strcmp(type->valuestring, "detection_context") == 0);
  assert(cJSON_IsString(owner) && strcmp(owner->valuestring, "ave_behavior_pipeline") == 0);
  assert(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(basis, "predicate_matched")));
  assert(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(basis, "threshold_met")));
  assert(cJSON_IsNumber(pid) && pid->valuedouble == alert->pid);
  assert(cJSON_IsNumber(threshold) && alert->anomaly_score >= threshold->valuedouble);
  assert(cJSON_IsNumber(count) && count->valuedouble == 1.0);
  assert(cJSON_IsNumber(flags) && flags->valuedouble == UINT32_MAX);
  assert(cJSON_IsString(timestamp) && strcmp(timestamp->valuestring, expected_time) == 0);
  assert(alert->triggered_tactics[0] == '\0'); /* Labels are not identity. */
  if (alert->pid == 5020u) {
    const cJSON *ctx = cJSON_GetObjectItemCaseSensitive(subject, "detection_context");
    const cJSON *process = cJSON_GetObjectItemCaseSensitive(ctx, "process");
    assert(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(ctx, "context_degraded")));
    assert(cJSON_IsArray(cJSON_GetObjectItemCaseSensitive(ctx, "projection_omissions")));
    assert(cJSON_GetObjectItemCaseSensitive(process, "cmdline") == NULL);
    assert(strlen(alert->process_name) == sizeof(alert->process_name) - 1u);
    assert(strlen(alert->process_path) == sizeof(alert->process_path) - 1u);
    assert(strlen(alert->cmdline) == 1023u);
    for (size_t i = 0; i < strlen(alert->cmdline); ++i) assert(alert->cmdline[i] == '"');
    assert(cJSON_IsObject(cJSON_GetObjectItemCaseSensitive(ctx, "file")));
    assert(cJSON_IsObject(cJSON_GetObjectItemCaseSensitive(ctx, "network")));
  }
  EdrBehaviorRecord *record = calloc(1, sizeof(*record));
  uint8_t *frame = malloc(EDR_EGRESS_FRAME_MAX);
  assert(record && frame);
  record->type = EDR_EVENT_BEHAVIOR_ONNX_ALERT;
  record->pid = alert->pid;
  record->event_time_ns = alert->timestamp_ns;
  snprintf(record->event_id, sizeof(record->event_id), "actual-ave-callback-%u", alert->pid);
  snprintf(record->endpoint_id, sizeof(record->endpoint_id), "synthetic-ave-endpoint");
  snprintf(record->tenant_id, sizeof(record->tenant_id), "synthetic-ave-tenant");
  size_t n = edr_behavior_record_alert_encode_protobuf(record, alert, frame, EDR_EGRESS_FRAME_MAX);
  char reason[96] = "producer_projection_failed";
  int admitted=n && edr_egress_frame_validate(frame,n,reason,sizeof(reason));
  if (!admitted) {
    const cJSON *ctx=cJSON_GetObjectItemCaseSensitive(subject,"detection_context");
    const cJSON *rule=cJSON_GetObjectItemCaseSensitive(ctx,"rule_id");
    fprintf(stderr,"synthetic AVE admission failed pid=%u bytes=%zu rule=%s reason=%s\n",
      alert->pid,n,cJSON_IsString(rule)?rule->valuestring:"unavailable",reason);
  }
  assert(admitted);
  free(frame);
  free(record);
  cJSON_Delete(subject);
  atomic_fetch_add(&s_callbacks, 1u);
  while (atomic_load(&s_block_callback)) pause_ms();
}

static void test_behavior_drain(void) {
  AVECallbacks callbacks = {0};
  AVEBehaviorEvent event = {0};
  AVEStatus status;
#ifdef _WIN32
  assert(_putenv_s("EDR_BEHAVIOR_USER_SUBJECT_JSON",
                  "{\"subject_type\":\"edr_dynamic_rule\",\"rule_id\":\"untrusted-debug-override\"}") == 0);
#else
  assert(setenv("EDR_BEHAVIOR_USER_SUBJECT_JSON",
                "{\"subject_type\":\"edr_dynamic_rule\",\"rule_id\":\"untrusted-debug-override\"}", 1) == 0);
#endif
  callbacks.on_behavior_alert = on_behavior;
  assert(AVE_RegisterCallbacks(&callbacks) == AVE_OK);
  assert(AVE_StartBehaviorMonitor() == AVE_OK);
  event.event_type = AVE_EVT_LSASS_ACCESS;
  event.pid = 5000u;
  event.severity_hint = 255u;
  event.behavior_flags = UINT32_MAX;
  atomic_store(&s_block_callback, 1);
  assert(AVE_FeedEventEx(&event, sizeof(event)) == AVE_OK);
  for (unsigned i = 0; i < 5000u && !atomic_load(&s_callbacks); ++i) pause_ms();
  assert(atomic_load(&s_callbacks) == 1u);
  for (unsigned i = 1; i <= 20; ++i) {
    event.pid = 5000u + i;
    if (i == 20u) {
      memset(event.process_name, 'x', sizeof(event.process_name) - 1u);
      memset(event.process_path, 'p', sizeof(event.process_path) - 1u);
      /* JSON escaping doubles these 1023 bytes, overflowing the optional
       * process projection independently of final subject capacity. */
      memset(event.cmdline, '"', sizeof(event.cmdline) - 1u);
      memset(event.target_path, 'f', sizeof(event.target_path) - 1u);
      memset(event.target_domain, 'd', sizeof(event.target_domain) - 1u);
      memset(event.file_sha256_hex, 'a', 64u);
      snprintf(event.target_ip, sizeof(event.target_ip), "2001:db8:1234:5678:1234:5678:1234:5678");
      event.target_port = 443u;
    }
    assert(AVE_FeedEventEx(&event, sizeof(event)) == AVE_OK);
  }
  assert(AVE_DrainBehaviorMonitor(5u) == AVE_ERR_TIMEOUT);
  assert(AVE_GetStatus(&status) == AVE_OK);
  assert(status.behavior_queue_enqueued == 21u);
  assert(status.behavior_worker_dequeued == 1u);
  assert(status.behavior_event_queue_size == 20);
  assert(AVE_FeedEventEx(&event, sizeof(event)) == AVE_ERR_NOT_INITIALIZED);
  assert(AVE_StartBehaviorMonitor() != AVE_OK);
  atomic_store(&s_block_callback, 0);
  assert(AVE_DrainBehaviorMonitor(5000u) == AVE_OK);
  assert(AVE_DrainBehaviorMonitor(0u) == AVE_OK);
  assert(AVE_GetStatus(&status) == AVE_OK);
  assert(status.behavior_worker_dequeued == 21u);
  assert(status.behavior_event_queue_size == 0);
  assert(!status.behavior_monitor_running);
  assert(atomic_load(&s_callbacks) == 21u);
#ifdef _WIN32
  assert(_putenv_s("EDR_BEHAVIOR_USER_SUBJECT_JSON", "") == 0);
#else
  assert(unsetenv("EDR_BEHAVIOR_USER_SUBJECT_JSON") == 0);
#endif
}

int main(int argc, char **argv) {
  /* Exercise the real transport caller and the explicit test boundary. This
   * must link without compiler-specific weak fallback implementations. */
  edr_ingest_http_apply_telemetry_profile(NULL, NULL, NULL, -1, -1,
                                          NULL, 37u, NULL, -1);
  assert(edr_preprocess_sampling_pct() == 37u);
  edr_ingest_http_apply_telemetry_profile(NULL, NULL, NULL, -1, -1,
                                          NULL, 100u, NULL, -1);
  assert(edr_preprocess_sampling_pct() == 100u);
  AVEConfig cfg = {0};
  cfg.max_concurrent_scans = 2;
  cfg.behavior_monitor_enabled = true;

  int r = AVE_Init(&cfg);
  if (r != AVE_OK) {
    fprintf(stderr, "AVE_Init failed: %d\n", r);
    return 1;
  }

  printf("AVE_GetVersion: %s\n", AVE_GetVersion());

  if (argc > 1) {
    AVEScanResult res;
    r = AVE_ScanFile(argv[1], &res);
    printf("AVE_ScanFile -> %d final_verdict=%d confidence=%.4f path=%s\n", r, (int)res.final_verdict,
           res.final_confidence, res.scanned_path);
  }

  test_behavior_drain();
  AVE_Shutdown();
  assert(AVE_Init(&cfg) == AVE_OK);
  AVE_Shutdown();
  return 0;
}
