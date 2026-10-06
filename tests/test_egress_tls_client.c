/* Synthetic inputs through the real AVE detector, production codec, SQLite
 * delivery owner, HTTPS transport and receipt validation. No native sensors or
 * service loop start; the detector callback only captures its actual alert. */
#include "edr/ingest_http.h"
#include "edr/behavior_proto.h"
#include "edr/ave_sdk.h"
#include "edr/storage_queue.h"
#include "edr/transport_sink.h"
#include "edr/types.h"
#include "sqlite3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <time.h>
#ifdef EDR_TEST_EXTENDED_EGRESS
#include "edr/egress_batch_policy.h"
#include "edr/detection_decision.h"
#include "edr/local_evidence_cache.h"
#include "edr/behavior_from_slot.h"
#include "edr/behavior_alert_emit.h"
#include "edr/event_bus.h"
#include "pmfe_association_fixture.h"
#include "p0_terminal_association_fixture.h"
#endif
#ifdef _WIN32
#include <windows.h>
static void pause_retry(void) { Sleep(1200u); }
#else
#include <time.h>
static void pause_retry(void) { struct timespec t = {1, 200000000L}; nanosleep(&t, NULL); }
#endif

static unsigned failed;
#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "synthetic TLS check failed: %s\n", #expr); failed++; } } while (0)
static void wr(uint8_t *p, uint32_t value) { for (unsigned i = 0; i < 4u; ++i) p[i] = (uint8_t)(value >> (i * 8u)); }
static int row_count(const char *db_path, const char *batch_id, const char *status) {
  sqlite3 *db = NULL; sqlite3_stmt *stmt = NULL; int count = -1;
  if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK &&
      sqlite3_prepare_v2(db, status ? "SELECT COUNT(*) FROM event_queue WHERE batch_id=? AND status=?" :
          "SELECT COUNT(*) FROM event_queue WHERE batch_id=?", -1, &stmt, NULL) == SQLITE_OK) {
    sqlite3_bind_text(stmt, 1, batch_id, -1, SQLITE_TRANSIENT);
    if (status) sqlite3_bind_text(stmt, 2, status, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) == SQLITE_ROW) count = sqlite3_column_int(stmt, 0);
  }
  sqlite3_finalize(stmt); if (db) sqlite3_close(db); return count;
}
static void synthetic_record(EdrBehaviorRecord *r) {
  memset(r, 0, sizeof(*r)); r->type = EDR_EVENT_NET_CONNECT; r->pid = 42; r->ppid = 21;
  r->priority = 0; r->event_time_ns = 1700000000000000000LL;
  strcpy(r->event_id, "synthetic-source"); strcpy(r->endpoint_id, "synthetic-endpoint");
  strcpy(r->tenant_id, "synthetic-tenant"); strcpy(r->cmdline, "synthetic.exe --required-alert-context");
  strcpy(r->process_name, "synthetic.exe"); strcpy(r->net_dst, "127.0.0.1"); r->net_dport = 443;
}
typedef struct DetectorCapture {
  AVEBehaviorAlert alert;
  atomic_uint detected;
  unsigned accepted_inputs;
} DetectorCapture;
static void AVE_CALL capture_detection(const AVEBehaviorAlert *alert, void *user_data) {
  DetectorCapture *capture = user_data;
  capture->alert = *alert;
  atomic_fetch_add_explicit(&capture->detected, 1u, memory_order_release);
}
static int detect_synthetic_input(const EdrBehaviorRecord *r, DetectorCapture *capture) {
  AVEConfig config = {0};
  AVECallbacks callbacks = {0};
  AVEBehaviorEvent event = {0};
  config.max_concurrent_scans = 2;
  config.behavior_monitor_enabled = true;
  callbacks.on_behavior_alert = capture_detection;
  callbacks.user_data = capture;
  event.event_type = AVE_EVT_LSASS_ACCESS;
  event.pid = r->pid;
  event.ppid = r->ppid;
  event.timestamp_ns = r->event_time_ns;
  event.severity_hint = UINT8_MAX;
  event.behavior_flags = UINT32_MAX;
  snprintf(event.process_name, sizeof(event.process_name), "%s", r->process_name);
  snprintf(event.cmdline, sizeof(event.cmdline), "%s", r->cmdline);
  snprintf(event.target_ip, sizeof(event.target_ip), "%s", r->net_dst);
  event.target_port = r->net_dport;
  if (AVE_Init(&config) != AVE_OK) {
    fprintf(stderr, "synthetic detector initialization failed\n");
    return 0;
  }
  int ok = AVE_RegisterCallbacks(&callbacks) == AVE_OK &&
           AVE_StartBehaviorMonitor() == AVE_OK;
  if (ok) {
    ok = AVE_FeedEventEx(&event, sizeof(event)) == AVE_OK;
    if (ok) capture->accepted_inputs++;
    ok = ok && AVE_DrainBehaviorMonitor(5000u) == AVE_OK;
  }
  AVE_Shutdown();
  return ok && atomic_load_explicit(&capture->detected, memory_order_acquire) == 1u &&
         capture->alert.pid == r->pid && capture->alert.timestamp_ns == r->event_time_ns;
}
static size_t make_wire(EdrBehaviorRecord *r, const AVEBehaviorAlert *alert, uint8_t *wire, size_t cap) {
  size_t n;
  if (alert) {
    n = edr_behavior_record_alert_encode_protobuf(r, alert, wire + 16u, cap - 16u);
  } else n = edr_behavior_record_encode_protobuf(r, wire + 16u, cap - 16u);
  if (!n) return 0;
  wr(wire, EDR_TRANSPORT_BATCH_MAGIC_RAW); wr(wire + 4u, 1u); wr(wire + 8u, (uint32_t)n + 4u);
  wr(wire + 12u, (uint32_t)n); return n + 16u;
}
#ifdef EDR_TEST_EXTENDED_EGRESS
static int artifact_state_count(const char *path,const char *state) {
  sqlite3 *db=NULL; sqlite3_stmt *statement=NULL; int count=-1;
  if(sqlite3_open_v2(path,&db,SQLITE_OPEN_READONLY,NULL)==SQLITE_OK &&
     sqlite3_prepare_v2(db,"SELECT COUNT(*) FROM artifacts WHERE artifact_type='pmfe_followup_local_v1' AND upload_status=?",-1,&statement,NULL)==SQLITE_OK) {
    sqlite3_bind_text(statement,1,state,-1,SQLITE_TRANSIENT);
    if(sqlite3_step(statement)==SQLITE_ROW) count=sqlite3_column_int(statement,0);
  }
  sqlite3_finalize(statement); if(db) sqlite3_close(db); return count;
}
static int pmfe_receipt_scenario(const char *queue_path) {
  char cache_path[1200],batch_id[128];
  if(snprintf(cache_path,sizeof(cache_path),"%s.evidence",queue_path)>=(int)sizeof(cache_path)) return 2;
  EdrBehaviorRecord *original=calloc(1,sizeof(*original)),*result=calloc(1,sizeof(*result));
  uint8_t *wire=malloc(256u*1024u); if(!original || !result || !wire) return 2;
  edr_test_pmfe_original(original,1,(int64_t)time(NULL)*1000000000LL);
  strcpy(original->endpoint_id,"synthetic-endpoint"); strcpy(original->tenant_id,"synthetic-tenant");
  size_t original_len=make_wire(original,NULL,wire,256u*1024u);
  edr_storage_queue_configure(4,72);
  CHECK(edr_storage_queue_open(queue_path)==EDR_OK);
  CHECK(edr_local_evidence_cache_open(cache_path,8,24)==0);
  EdrPmfeFollowupTask task;
  CHECK(edr_local_evidence_cache_pmfe_prepare(original,"sc-local-1",wire+16,original_len-16,
        EDR_PMFE_BAND_P0,0,&task)==0);
  CHECK(edr_storage_queue_enqueue("tls-pmfe-original",wire,original_len,0,1)==EDR_OK);
  edr_storage_queue_poll_drain(); CHECK(row_count(queue_path,"tls-pmfe-original",NULL)==0);
  /* Actual worker, with a deliberately impossible synthetic process generation.
   * It must report failure/inconclusive before reading any reused process. */
#ifdef _WIN32
  _putenv_s("EDR_PMFE_ENABLED","1");
#else
  setenv("EDR_PMFE_ENABLED","1",1);
#endif
  EdrEventBus *bus=edr_event_bus_create(16); CHECK(bus!=NULL);
  edr_pmfe_set_event_bus(bus); CHECK(edr_pmfe_init()==EDR_OK);
  CHECK(edr_local_evidence_cache_pmfe_take_task(&task)==1);
  CHECK(edr_pmfe_submit_associated_scan(&task)==0);
  EdrEventSlot slot; int popped=0;
  for(unsigned attempt=0;attempt<5u && !popped;++attempt) {
    if(!(popped=edr_event_bus_try_pop(bus,&slot))) (void)edr_event_bus_wait(bus,1000u);
  }
  if(!popped) popped=edr_event_bus_try_pop(bus,&slot);
  edr_pmfe_shutdown(); edr_pmfe_set_event_bus(NULL); CHECK(popped);
  if(popped) edr_behavior_from_slot(&slot,result);
  strcpy(result->event_id,"synthetic-pmfe-worker-result");
  CHECK(result->type==EDR_EVENT_PMFE_SCAN_RESULT);
  CHECK(edr_local_evidence_cache_pmfe_apply_scope(result)==1);
  EdrDetectionDecision decision;
  edr_detection_decision_evaluate(result,&decision);
  size_t result_len=make_wire(result,NULL,wire,256u*1024u);
  CHECK(result_len>16 && edr_local_evidence_cache_pmfe_bind_result(result,wire+16,result_len-16)==0);
  char why[128]; CHECK(edr_egress_batch_validate(wire,12,wire+12,result_len-12,why,sizeof(why)));
  CHECK(edr_behavior_durable_wire_batch_id("pmfe-result-v1",wire,result_len,batch_id,sizeof(batch_id)));
  CHECK(edr_storage_queue_enqueue(batch_id,wire,result_len,0,1)==EDR_OK);
  pause_retry(); edr_storage_queue_poll_drain();
  CHECK(row_count(queue_path,batch_id,"pending")==1);
  CHECK(artifact_state_count(cache_path,"result_bound")==1);
  pause_retry(); edr_storage_queue_poll_drain();
  CHECK(row_count(queue_path,batch_id,NULL)==0);
  CHECK(artifact_state_count(cache_path,"completed")==1);
  CHECK(artifact_state_count(cache_path,"result_acked")==0);
  edr_storage_queue_close(); edr_local_evidence_cache_close(); edr_event_bus_destroy(bus);
  free(original); free(result); free(wire);
  printf("{\"mode\":\"positive-pmfe\",\"synthetic_original_alerts\":1,\"actual_worker_results\":%d,\"enqueued\":2,\"distinct_queue_acks\":2,\"failed_checks\":%u}\n",popped,failed);
  return failed?1:0;
}
static int journal_receipt_scenario(const char *queue_path) {
  EdrBehaviorRecord *record=calloc(1,sizeof(*record));
  uint8_t *ordinary=malloc(256u*1024u),*alert=malloc(256u*1024u);
  if(!record || !ordinary || !alert) return 2;
  synthetic_record(record); DetectorCapture capture={0};
  size_t ordinary_len=make_wire(record,NULL,ordinary,256u*1024u);
  CHECK(detect_synthetic_input(record,&capture)); record->type=EDR_EVENT_BEHAVIOR_ONNX_ALERT;
  size_t alert_len=make_wire(record,&capture.alert,alert,256u*1024u);
  edr_storage_queue_configure(4,72); CHECK(edr_storage_queue_open(queue_path)==EDR_OK);
  CHECK(edr_storage_queue_enforcement_terminal_precreate("synthetic-action","synthetic-source", "synthetic-rule","synthetic-generation","tls-journal-intent",ordinary,ordinary_len)==EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  CHECK(edr_storage_queue_enforcement_terminal_update("synthetic-action","tls-journal-source",ordinary,ordinary_len,"tls-journal-combined",alert,alert_len)==EDR_OK);
  edr_storage_queue_poll_drain(); EdrEnforcementTerminalJournalMetrics status;
  edr_storage_queue_enforcement_terminal_get_metrics(&status);
  CHECK(status.policy_held_frames==2 && status.pending==1);
  sqlite3 *db=NULL; sqlite3_stmt *row=NULL;
  CHECK(sqlite3_open_v2(queue_path,&db,SQLITE_OPEN_READONLY,NULL)==SQLITE_OK);
  CHECK(sqlite3_prepare_v2(db,"SELECT source_acked,combined_acked,state,source_wire,combined_wire FROM enforcement_terminal_journal WHERE idempotency_key='synthetic-action'",-1,&row,NULL)==SQLITE_OK);
  if(row && sqlite3_step(row)==SQLITE_ROW) {
    CHECK(sqlite3_column_int(row,0)==0 && sqlite3_column_int(row,1)==1);
    CHECK(!strcmp((const char*)sqlite3_column_text(row,2),"ready"));
    CHECK(sqlite3_column_bytes(row,3)==(int)ordinary_len && !memcmp(sqlite3_column_blob(row,3),ordinary,ordinary_len));
    CHECK(sqlite3_column_bytes(row,4)==(int)alert_len && !memcmp(sqlite3_column_blob(row,4),alert,alert_len));
  } else CHECK(0);
  sqlite3_finalize(row); if(db) sqlite3_close(db); edr_storage_queue_close();
  free(record); free(ordinary); free(alert);
  printf("{\"mode\":\"positive-journal\",\"detector_inputs\":%u,\"detected\":%u,\"source_acked\":0,\"combined_acked\":1,\"failed_checks\":%u}\n",capture.accepted_inputs,atomic_load(&capture.detected),failed);
  return failed?1:0;
}
static int p0_journal_receipt_scenario(const char *queue_path) {
  EdrTestP0TerminalFixture fixture;
  if (!edr_test_p0_terminal_fixture_init(&fixture,1,"synthetic-tenant","synthetic-endpoint")) return 2;
  edr_storage_queue_configure(4,72); CHECK(edr_storage_queue_open(queue_path)==EDR_OK);
  CHECK(edr_storage_queue_enforcement_terminal_precreate(fixture.terminal_key,fixture.source_event_id,
      fixture.rule_id,fixture.generation_key,"tls-p0-intent",fixture.wire[0],fixture.length[0])==EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  /* The source tuple or pre-action intent alone is never an alert owner. */
  char reason[128];
  CHECK(!edr_egress_batch_validate(fixture.wire[0],12,fixture.wire[0]+12,fixture.length[0]-12,reason,sizeof(reason)));
  edr_storage_queue_poll_drain();
  CHECK(edr_storage_queue_enforcement_terminal_update(fixture.terminal_key,"tls-p0-source",
      fixture.wire[1],fixture.length[1],"tls-p0-combined",fixture.wire[2],fixture.length[2])==EDR_OK);
  CHECK(edr_egress_batch_validate(fixture.wire[0],12,fixture.wire[0]+12,fixture.length[0]-12,reason,sizeof(reason)));
  pause_retry(); edr_storage_queue_poll_drain();
  EdrEnforcementTerminalJournalMetrics status;
  edr_storage_queue_enforcement_terminal_get_metrics(&status);
  CHECK(status.pending==1); /* The receiver deliberately loses the intent ACK. */
  for(unsigned attempt=0;attempt<4u && status.pending;++attempt) {
    pause_retry(); edr_storage_queue_poll_drain();
    edr_storage_queue_enforcement_terminal_get_metrics(&status);
  }
  CHECK(status.pending==0 && status.local_retained==1);
  int observed_ack[3]={0,0,0};
  sqlite3 *db=NULL; sqlite3_stmt *row=NULL;
  CHECK(sqlite3_open_v2(queue_path,&db,SQLITE_OPEN_READONLY,NULL)==SQLITE_OK);
  CHECK(sqlite3_prepare_v2(db,"SELECT intent_acked,source_acked,combined_acked,state,intent_wire,source_wire,combined_wire FROM enforcement_terminal_journal WHERE idempotency_key=?",-1,&row,NULL)==SQLITE_OK);
  if(row) sqlite3_bind_text(row,1,fixture.terminal_key,-1,SQLITE_TRANSIENT);
  if(row && sqlite3_step(row)==SQLITE_ROW) {
    for(unsigned i=0;i<3;i++) observed_ack[i]=sqlite3_column_int(row,(int)i);
    CHECK(sqlite3_column_int(row,0)==1 && sqlite3_column_int(row,1)==0 && sqlite3_column_int(row,2)==1);
    CHECK(!strcmp((const char*)sqlite3_column_text(row,3),"local_retained"));
    for(unsigned i=0;i<3;i++)
      CHECK(sqlite3_column_bytes(row,4+(int)i)==(int)fixture.length[i] &&
        !memcmp(sqlite3_column_blob(row,4+(int)i),fixture.wire[i],fixture.length[i]));
  } else CHECK(0);
  sqlite3_finalize(row); if(db) sqlite3_close(db); edr_storage_queue_close();
  edr_test_p0_terminal_fixture_free(&fixture);
  printf("{\"mode\":\"positive-p0-journal\",\"detection_basis\":\"production_schema_fixture\",\"detector_executed\":false,\"enqueued_terminal_frames\":3,\"intent_acked\":%d,\"source_acked\":%d,\"combined_acked\":%d,\"distinct_queue_acks\":%d,\"failed_checks\":%u}\n",observed_ack[0],observed_ack[1],observed_ack[2],observed_ack[0]+observed_ack[2],failed);
  return failed?1:0;
}
#endif

int main(int argc, char **argv) {
  if (argc != 7) {
    fprintf(stderr, "usage: test_egress_tls_client BASE_URL CA CLIENT_CERT CLIENT_KEY QUEUE_PATH MODE\n"); return 2;
  }
  edr_ingest_http_configure(argv[1], "synthetic-tenant", "", "", "synthetic-endpoint", "test-v1",
      argv[2], argv[3], argv[4], "pem", "", "", "direct", "", "");
  edr_ingest_http_set_policy_version("synthetic-p1");
  int v2 = !strcmp(argv[6], "positive-v2");
  edr_ingest_http_configure_transport_options(0, 0, 0, 0, v2, "protobuf", v2 ? "zstd" : "none");
#ifdef EDR_TEST_EXTENDED_EGRESS
  if (!strcmp(argv[6], "positive-pmfe")) return pmfe_receipt_scenario(argv[5]);
  if (!strcmp(argv[6], "positive-journal")) return journal_receipt_scenario(argv[5]);
  if (!strcmp(argv[6], "positive-p0-journal")) return p0_journal_receipt_scenario(argv[5]);
#endif
  if (!strcmp(argv[6], "resume-after-crash")) {
    /* Reopen the actual crashed delivery owner without recollecting or
     * rebuilding the immutable queued alert. Its held ordinary row remains. */
    edr_storage_queue_configure(4u, 72u);
    CHECK(edr_storage_queue_open(argv[5]) == EDR_OK);
    CHECK(row_count(argv[5], "tls-ordinary", "policy_held") == 1);
    CHECK(row_count(argv[5], "tls-alert", NULL) == 0);
    CHECK(row_count(argv[5], "tls-ack-lost", "pending") == 1);
    for (unsigned attempt = 0; attempt < 3u && row_count(argv[5], "tls-ack-lost", NULL); ++attempt) {
      pause_retry();
      edr_storage_queue_poll_drain();
    }
    CHECK(row_count(argv[5], "tls-ack-lost", NULL) == 0);
    CHECK(row_count(argv[5], "tls-ordinary", "policy_held") == 1);
    edr_storage_queue_close();
    printf("{\"mode\":\"resume-after-crash\",\"collected\":0,\"detected\":0,\"enqueued\":0,\"failed_checks\":%u}\n", failed);
    return failed ? 1 : 0;
  }
  if (strcmp(argv[6], "positive") && strcmp(argv[6], "positive-ip") && !v2) {
    int rc = edr_ingest_http_post_heartbeat();
    printf("{\"mode\":\"%s\",\"tls_rejected\":%s}\n", argv[6], rc != 0 ? "true" : "false");
    return rc != 0 ? 0 : 1;
  }
  EdrBehaviorRecord *r = calloc(1, sizeof(*r));
  uint8_t *ordinary = malloc(256u * 1024u), *alert = malloc(256u * 1024u);
  if (!r || !ordinary || !alert) return 2;
  DetectorCapture capture = {0};
  synthetic_record(r);
  size_t ordinary_len = make_wire(r, NULL, ordinary, 256u * 1024u);
  CHECK(detect_synthetic_input(r, &capture));
  r->type = EDR_EVENT_BEHAVIOR_ONNX_ALERT;
  size_t alert_len = make_wire(r, &capture.alert, alert, 256u * 1024u);
  CHECK(ordinary_len && alert_len);
  unsigned enqueued = 0;
  EdrError queue_result;
  edr_storage_queue_configure(4u, 72u);
  CHECK(edr_storage_queue_open(argv[5]) == EDR_OK);
  queue_result = edr_storage_queue_enqueue("tls-ordinary", ordinary, ordinary_len, 0, 0);
  CHECK(queue_result == EDR_OK); if (queue_result == EDR_OK) enqueued++;
  queue_result = edr_storage_queue_enqueue("tls-alert", alert, alert_len, 0, 1);
  CHECK(queue_result == EDR_OK); if (queue_result == EDR_OK) enqueued++;
  edr_storage_queue_poll_drain();
  CHECK(row_count(argv[5], "tls-ordinary", "policy_held") == 1);
  CHECK(row_count(argv[5], "tls-alert", NULL) == 0);
  CHECK(edr_ingest_http_post_heartbeat() == 0);
  /* Exercise the actual receipt serializer through strict egress and mTLS.
   * The authenticated request header owns the suppression capability. */
  CHECK(edr_ingest_http_post_config_status(NULL, NULL, NULL, "synthetic-p2",
      "synthetic-hash2", "42", "bm9uY2U=", "c2lnbmF0dXJl", "synthetic-key",
      1, NULL, "synthetic-p2", "synthetic-hash2", "applied", 0) == 0);
  CHECK(edr_ingest_http_post_config_status(NULL, NULL, NULL, "synthetic-p1",
      "synthetic-hash1", "43", "bm9uY2U=", "c2lnbmF0dXJl", "synthetic-key",
      0, "synthetic-secret-validation-detail", "synthetic-p2", "synthetic-hash2", "failed", 0) == 0);
  CHECK(edr_ingest_http_post_config_status("foreign-tenant", NULL, NULL, "synthetic-p2",
      "synthetic-hash2", "42", "bm9uY2U=", "c2lnbmF0dXJl", "synthetic-key",
      1, NULL, "synthetic-p2", "synthetic-hash2", "applied", 0) != 0);
  CHECK(edr_ingest_http_post_json_suffix("ingest/config-status",
      "{\"tenant_id\":\"synthetic-tenant\",\"endpoint_id\":\"synthetic-endpoint\","
      "\"agent_version\":\"test-v1\",\"policy_version\":\"synthetic-p2\","
      "\"payload\":{\"source\":\"agent-runtime-policy\",\"verified\":true,\"suppression_contract\":\"2\"}}",
      NULL, 0u) != 0);
  queue_result = edr_storage_queue_enqueue("tls-ack-lost", alert, alert_len, 0, 1);
  CHECK(queue_result == EDR_OK); if (queue_result == EDR_OK) enqueued++;
  pause_retry(); edr_storage_queue_poll_drain();
  CHECK(row_count(argv[5], "tls-ack-lost", "pending") == 1);
  if (getenv("EDR_TEST_CRASH_AFTER_LOST_ACK")) {
    /* A test-only executable checkpoint. The harness SIGKILLs this exact
     * child; a bounded deadline fails if the harness does not terminate it. */
    if (failed) return 1;
    printf("{\"crash_checkpoint\":\"lost_ack_pending\",\"detector_inputs\":%u,\"detected\":%u,\"enqueued\":%u}\n",
           capture.accepted_inputs, atomic_load(&capture.detected), enqueued);
    fflush(stdout);
    for (unsigned wait = 0; wait < 10u; ++wait) pause_retry();
    fprintf(stderr, "synthetic crash harness did not terminate its child\n");
    return 2;
  }
  edr_storage_queue_close();
  pause_retry(); CHECK(edr_storage_queue_open(argv[5]) == EDR_OK);
  CHECK(row_count(argv[5], "tls-ordinary", "policy_held") == 1);
  edr_storage_queue_poll_drain();
  CHECK(row_count(argv[5], "tls-ack-lost", NULL) == 0);
  /* Server duplicate delivery is acknowledged for the exact original body. */
  CHECK(edr_ingest_http_post_report_events("tls-alert", alert, 12u, alert + 12u, alert_len - 12u) == 0);
  CHECK(edr_ingest_http_post_report_events("tls-ack-mismatch", alert, 12u, alert + 12u, alert_len - 12u) != 0);
  const char *health = "{\"endpoint_id\":\"synthetic-endpoint\",\"agent_version\":\"test-v1\",\"policy_version\":\"synthetic-p1\",\"engine_health\":{\"reported_at_unix_ms\":1700000000000,\"sensor_health\":{\"file_read_collection\":{\"metadata_gate\":{\"healthy\":false,\"durable_failures\":2,\"reason\":\"synthetic-secret-user\"}}},\"p0_acceptance\":{\"source_only\":{\"terminal_unhealthy\":true,\"retry_pending\":3,\"reason\":\"process_generation_or_correlation_unavailable\"}},\"resource\":{\"rss_mb\":12,\"cpu_percent\":1},\"config_recovery\":{\"active\":true,\"source\":\"synthetic-secret-path\"},\"capability_manifest\":{\"schema\":\"edr.agent.capabilities.v1\",\"features\":{\"pmfe\":{\"code_supported\":true,\"build_supported\":true,\"policy_enabled\":true,\"runtime_status\":\"healthy\"},\"sqlite\":{\"code_supported\":true,\"build_supported\":true,\"policy_enabled\":true,\"runtime_status\":\"healthy\"}}},\"raw_event\":{\"cmdline\":\"synthetic-secret-command\"}}}";
  CHECK(edr_ingest_http_post_engine_health_json(health) == 0);
  CHECK(edr_ingest_http_post_engine_health_json(health) == 0);
  CHECK(edr_ingest_http_post_json_suffix("ingest/engine-health", health, NULL, 0u) != 0);
  CHECK(edr_ingest_http_post_command_result_typed("synthetic-command", "rtq_execute", NULL, 0, 0, "synthetic-secret-result") != 0);
  int retryable = 1; char error[160];
  edr_ingest_http_get_last_command_result_delivery_error(error, sizeof(error), &retryable);
  CHECK(retryable == 0);
  const char *blocked[] = {"endpoints/synthetic-endpoint/attack-surface", "ingest/agent-upgrade-event", "ingest/unknown"};
  for (size_t i = 0; i < 3u; ++i) CHECK(edr_ingest_http_post_json_suffix(blocked[i], "{\"raw\":\"synthetic-secret\"}", NULL, 0u) != 0);
  char key[256];
  CHECK(edr_ingest_http_upload_file_multipart("synthetic-upload", argv[5], "", key, sizeof(key)) != 0);
  CHECK(row_count(argv[5], "tls-ordinary", "policy_held") == 1);
  edr_storage_queue_close(); free(r); free(ordinary); free(alert);
  printf("{\"mode\":\"%s\",\"collected\":2,\"collection_source\":\"synthetic_fixture\",\"detector_inputs\":%u,\"detected\":%u,\"enqueued\":%u,\"ordinary_bytes\":%zu,\"alert_bytes\":%zu,\"failed_checks\":%u}\n", argv[6], capture.accepted_inputs, atomic_load(&capture.detected), enqueued, ordinary_len, alert_len, failed);
  return failed ? 1 : 0;
}
