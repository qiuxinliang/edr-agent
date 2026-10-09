/**
 * 最小化 AVE SDK 自检：AVE_Init / AVE_GetVersion / AVE_ScanFile（首个可选参数为待扫文件）。
 */
#include "edr/ave_sdk.h"
#include "edr/ave_cross_engine_feed.h"
#include "edr/ingest_http.h"
#include "edr/preprocess.h"
#include "edr/behavior_proto.h"
#include "edr/egress_batch_policy.h"
#include "ave_behavior_pipeline.h"
#include "edr/v1/event.pb.h"
#include <pb_decode.h>
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
static atomic_uint s_parent_callbacks;
static atomic_uint s_generation_callbacks;

static void AVE_CALL on_generation_behavior(const AVEBehaviorAlert *alert, void *unused) {
  (void)unused;
  EdrAveProcessIdentity capture;
  assert(alert->pid==7000u&&edr_behavior_alert_process_identity(alert,&capture)==1);
  unsigned index=atomic_fetch_add(&s_generation_callbacks,1u);
  assert(index<2u&&capture.process_start_key==(index?222u:111u));
  assert(capture.parent_pid==(index?0u:299u));
  assert(capture.parent_pid_state==(index?EDR_PARENT_PID_UNKNOWN:EDR_PARENT_PID_KNOWN));
}

static void test_captured_generation_reuse(void) {
  AVECallbacks callbacks={0};callbacks.on_behavior_alert=on_generation_behavior;
  assert(AVE_RegisterCallbacks(&callbacks)==AVE_OK&&AVE_StartBehaviorMonitor()==AVE_OK);
  AVEBehaviorEvent event={0};EdrAveProcessIdentity capture={0};
  capture.pid=event.pid=7000u;event.timestamp_ns=1700000000000000000LL;
  event.event_type=AVE_EVT_FILE_WRITE;event.behavior_flags=UINT32_MAX;
  capture.parent_pid=299;capture.parent_pid_state=EDR_PARENT_PID_KNOWN;
  capture.process_start_key=111;capture.process_creation_filetime_100ns=133444736000000000ULL;
  strcpy(capture.source_event_id,"synthetic-generation-first");
  assert(edr_ave_feed_event_captured(&event,&capture)==AVE_OK);
  event.timestamp_ns+=1000;event.behavior_flags=0;
  capture.parent_pid=0;capture.parent_pid_state=EDR_PARENT_PID_UNKNOWN;
  capture.process_start_key=222;capture.process_creation_filetime_100ns++;
  strcpy(capture.source_event_id,"synthetic-generation-reused");
  assert(edr_ave_feed_event_captured(&event,&capture)==AVE_OK);
  event.timestamp_ns++;event.behavior_flags=UINT32_MAX;
  assert(edr_ave_feed_event_captured(&event,&capture)==AVE_OK);
  assert(AVE_DrainBehaviorMonitor(10000u)==AVE_OK&&atomic_load(&s_generation_callbacks)==2u);
  puts("captured PID reuse: new exact lifetime reset, parent not inherited, attack detection retained");
}

static void AVE_CALL on_parent_behavior(const AVEBehaviorAlert *alert, void *unused) {
  (void)unused;
  assert(alert->pid >= 6000u && alert->pid <= 6005u);
  unsigned state = alert->pid - 6000u;
  if (state == 5u) state = EDR_PARENT_PID_CONFLICT;
  uint32_t parent = (state == EDR_PARENT_PID_KNOWN || alert->pid == 6004u) ? 299u : 0u;
  EdrAveProcessIdentity captured;
  assert(edr_behavior_alert_process_identity(alert, &captured) == 1);
  assert(captured.parent_pid == parent && captured.parent_pid_state == state);
  assert(captured.process_start_key == 991122u + alert->pid);
  assert(captured.process_creation_filetime_100ns == 133444736000000000ULL);
  assert(strncmp(captured.source_event_id, "synthetic-parent-", 17u) == 0);
  uint8_t *frame = malloc(EDR_EGRESS_FRAME_MAX);
  edr_v1_BehaviorEvent *wire = calloc(1u, sizeof(*wire));
  assert(frame && wire);
  size_t n = edr_behavior_alert_encode_protobuf(alert, "synthetic-endpoint", "synthetic-tenant",
                                               frame, EDR_EGRESS_FRAME_MAX);
  assert(n);
  pb_istream_t stream = pb_istream_from_buffer(frame, n);
  assert(pb_decode(&stream, edr_v1_BehaviorEvent_fields, wire));
  assert(wire->ppid == parent && wire->has_parent_pid_state && wire->parent_pid_state == state);
  assert(wire->process_start_key == captured.process_start_key);
  assert(wire->process_creation_filetime_100ns == captured.process_creation_filetime_100ns);
  assert(strstr(wire->behavior_alert.user_subject_json, "captured_process") == NULL);
  assert(strstr(wire->behavior_alert.user_subject_json, "synthetic-parent-") == NULL);
  cJSON *subject = cJSON_Parse(wire->behavior_alert.user_subject_json);
  const cJSON *ctx = cJSON_GetObjectItemCaseSensitive(subject, "detection_context");
  const cJSON *process = cJSON_GetObjectItemCaseSensitive(ctx, "process");
  assert(cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(process, "parent_pid")) == parent);
  assert(edr_egress_frame_validate(frame, n, NULL, 0));
  cJSON_Delete(subject); free(wire); free(frame);
  atomic_fetch_add(&s_parent_callbacks, 1u);
}

static void test_captured_parent_states_through_real_pipeline(void) {
  AVECallbacks callbacks = {0};
  callbacks.on_behavior_alert = on_parent_behavior;
  assert(AVE_RegisterCallbacks(&callbacks) == AVE_OK);
  assert(AVE_StartBehaviorMonitor() == AVE_OK);
  for (unsigned value = 0; value < 6u; ++value) {
    AVEBehaviorEvent event = {0};
    EdrAveProcessIdentity capture = {0};
    capture.pid = event.pid = 6000u + value;
    capture.parent_pid_state = value == 5u ? EDR_PARENT_PID_CONFLICT : (uint8_t)value;
    capture.parent_pid = (value == 1u || value == 4u) ? 299u : 0u;
    capture.process_start_key = 991122u + event.pid;
    capture.process_creation_filetime_100ns = 133444736000000000ULL;
    snprintf(capture.source_event_id, sizeof(capture.source_event_id), "synthetic-parent-%u", event.pid);
    event.ppid = capture.parent_pid;
    event.event_type = AVE_EVT_LSASS_ACCESS;
    event.timestamp_ns = 1700000000000000000LL;
    event.behavior_flags = UINT32_MAX; /* Synthetic detector facts; never execute a command. */
    snprintf(event.process_name, sizeof(event.process_name), "synthetic.exe");
    assert(edr_ave_feed_event_captured(&event, &capture) == AVE_OK);
    memset(&event, 0xff, sizeof(event));
    memset(&capture, 0xff, sizeof(capture)); /* The queue must own both copies. */
  }
  assert(AVE_DrainBehaviorMonitor(10000u) == AVE_OK);
  assert(atomic_load(&s_parent_callbacks) == 6u);
  puts("captured AVE parent states: real feed/queue/detector/callback/codec/gate passed");
}
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

/* The native collector reserves priority 0 for these four IR observations.
 * Ordinary browser HTTPS retains scheduling priority 1 (or 2 after local
 * noise policy). Neither scheduling level is a positive detection fact. */
static atomic_uint normal_callbacks, normal_frames;
static void AVE_CALL on_normal_behavior(const AVEBehaviorAlert *alert, void *unused) {
  (void)unused;
  EdrBehaviorRecord *record=calloc(1,sizeof(*record));
  uint8_t *frame=malloc(EDR_EGRESS_FRAME_MAX);assert(record && frame);
  record->type=EDR_EVENT_BEHAVIOR_ONNX_ALERT;record->pid=alert->pid;
  record->event_time_ns=alert->timestamp_ns;
  strcpy(record->event_id,"normal-window");strcpy(record->tenant_id,"fixture");strcpy(record->endpoint_id,"fixture");
  size_t size=edr_behavior_record_alert_encode_protobuf(record,alert,frame,EDR_EGRESS_FRAME_MAX);
  char reason[128];
  if(size && edr_egress_frame_validate(frame,size,reason,sizeof(reason))) atomic_fetch_add(&normal_frames,1u);
  atomic_fetch_add(&normal_callbacks,1u);free(record);free(frame);
}
static void normal_feed_drain(void) {
  AVEStatus status;
  for(unsigned i=0;i<5000;i++){assert(AVE_GetStatus(&status)==AVE_OK);if(status.behavior_worker_dequeued==status.behavior_queue_enqueued)return;pause_ms();}
  assert(!"normal feed drain timed out");
}
static void test_normal_observation_windows(void) {
  AVECallbacks callbacks={0};callbacks.on_behavior_alert=on_normal_behavior;
  assert(AVE_RegisterCallbacks(&callbacks)==AVE_OK);assert(AVE_StartBehaviorMonitor()==AVE_OK);
  EdrBehaviorRecord *r=calloc(1,sizeof(*r));assert(r);
  strcpy(r->exe_path,"C:\\Windows\\explorer.exe");strcpy(r->process_name,"explorer.exe");strcpy(r->cmdline,"explorer.exe");
  strcpy(r->source_completeness,"COMPLETE");strcpy(r->net_src,"192.0.2.2");strcpy(r->net_dst,"192.0.2.10");
  r->pid=6100;r->process_start_key=6100;r->process_creation_filetime_100ns=133600000000000000ULL;
  const unsigned ports[]={445,3389,5985,5986};
  for(unsigned i=0;i<4;i++){r->type=EDR_EVENT_NET_CONNECT;r->pid=6100+i;r->net_dport=ports[i];r->priority=0;
    for(unsigned j=0;j<256;j++){r->event_time_ns=1700000000000000000LL+j*1000000000LL;edr_ave_cross_engine_feed_from_record(r);if((j%64u)==63u)normal_feed_drain();}}
  r->type=EDR_EVENT_FILE_READ;r->pid=6104;strcpy(r->process_name,"chrome.exe");strcpy(r->exe_path,"C:\\Browser\\chrome.exe");strcpy(r->cmdline,"chrome.exe");strcpy(r->file_path,"C:\\Lab\\Login Data");
  edr_ave_cross_engine_feed_from_record(r); /* Unsupported by AVE: remains local P0 observation. */
  r->pid=6105;strcpy(r->process_name,"backup.exe");strcpy(r->cmdline,"backup.exe --daily");strcpy(r->file_path,"C:\\Lab\\logins.json");edr_ave_cross_engine_feed_from_record(r);
  r->type=EDR_EVENT_NET_CONNECT;r->pid=6104;r->net_dport=443;strcpy(r->process_name,"chrome.exe");strcpy(r->cmdline,"chrome.exe");r->file_path[0]=0;
  for(unsigned priority=1;priority<=2;priority++){r->priority=priority;r->pid=6104+priority;
    for(unsigned j=0;j<2048;j++){r->event_time_ns=1700000000000000000LL+j*1000000000LL;edr_ave_cross_engine_feed_from_record(r);if((j%64u)==63u)normal_feed_drain();}}
  assert(AVE_DrainBehaviorMonitor(5000)==AVE_OK);
  AVEStatus status;assert(AVE_GetStatus(&status)==AVE_OK);
  printf("normal AVE windows: fed=%llu callbacks=%u accepted_frames=%u\n",(unsigned long long)status.behavior_queue_enqueued,atomic_load(&normal_callbacks),atomic_load(&normal_frames));
  assert(status.behavior_queue_enqueued==5120u);
  assert(atomic_load(&normal_callbacks)==0u && atomic_load(&normal_frames)==0u);free(r);
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
  test_captured_parent_states_through_real_pipeline();
  AVE_Shutdown();
  assert(AVE_Init(&cfg) == AVE_OK);
  test_captured_generation_reuse();
  AVE_Shutdown();
  assert(AVE_Init(&cfg) == AVE_OK);
  test_normal_observation_windows();
  AVE_Shutdown();
  return 0;
}
