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
#include "edr/command_state.h"
#include "edr/command_signature.h"
#include "edr/agent_update_command.h"
#include "cJSON.h"
#include "edr/command_result_json.h"
#include "edr/command_executor.h"
#include "edr/config.h"
#include "edr/egress_batch_policy.h"
#include "edr/egress_request_policy.h"
#include "edr/detection_decision.h"
#include "edr/local_evidence_cache.h"
#include "edr/p0_source_only_contract.h"
#include "lz4.h"
#include <pb_decode.h>
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
#include <unistd.h>
static void pause_retry(void) { struct timespec t = {1, 200000000L}; nanosleep(&t, NULL); }
#endif

static unsigned failed;
#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "synthetic TLS check failed: %s\n", #expr); failed++; } } while (0)

#ifdef EDR_TEST_EXTENDED_EGRESS
static void rule_file_downloads(const char *base, const char *queue_path) {
  static const char *routes[] = {"/agent/p0-bundle.enc", "/agent/sensor-interest.json"};
  static const char expected[] = "synthetic-rule-artifact";
  unsigned verified = 0u;
  for (size_t i = 0u; i < sizeof(routes) / sizeof(routes[0]); ++i) {
    char url[1024], output[1400], bytes[64] = {0};
    int url_size = snprintf(url, sizeof(url), "%s%s", base, routes[i]);
    int path_size = snprintf(output, sizeof(output), "%s.rule-download", queue_path);
    CHECK(url_size > 0 && (size_t)url_size < sizeof(url) &&
          path_size > 0 && (size_t)path_size < sizeof(output));
    if (url_size <= 0 || (size_t)url_size >= sizeof(url) || path_size <= 0 ||
        (size_t)path_size >= sizeof(output)) continue;
    /* Use the exact bounded native file GET consumer called by both polls.
     * Downloading synthetic bytes proves transport, never rule activation. */
    int rc = edr_ingest_http_get_url_to_file_meta_bounded(url, output, 4096u, NULL, 2000, 1);
    CHECK(rc == 0);
    FILE *file = fopen(output, "rb");
    if (rc == 0) {
      CHECK(file);
      if (file) {
        size_t size = fread(bytes, 1u, sizeof(bytes), file);
        int exact = !ferror(file) && size == sizeof(expected) - 1u &&
                    !memcmp(bytes, expected, sizeof(expected) - 1u);
        CHECK(exact);
        if (exact) verified++;
      }
    } else {
      CHECK(!file); /* Failed/412 downloads must not retain a partial file. */
    }
    if (file) CHECK(fclose(file) == 0);
    if (rc == 0) CHECK(remove(output) == 0);
  }
  printf("{\"rule_file_downloads\":%u,\"rule_activation_claimed\":false}\n", verified);
}
#endif
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

#ifdef EDR_TEST_EXTENDED_EGRESS
/* Clock-boundary fault injection into this scenario's isolated file only.
 * Production finish is immutable and must not become a test expiry setter. */
static int fixture_expire_result(const char *dir,const char *id,int64_t expiry) {
  char path[1200];snprintf(path,sizeof(path),"%s/command_state.jsonl",dir);
  FILE *f=fopen(path,"r+b");if(!f)return 0;
  char *line=malloc(131072);if(!line){fclose(f);return 0;}
  int changed=0,ok=1;
  for(;;) {
    long offset=ftell(f);if(!fgets(line,131072,f))break;long next=ftell(f);
    cJSON *row=cJSON_Parse(line),*key=cJSON_GetObjectItemCaseSensitive(row,"command_id");
    cJSON *grant=cJSON_GetObjectItemCaseSensitive(row,"result_authorization");
    cJSON *old=cJSON_GetObjectItemCaseSensitive(grant,"expires_unix_ms");
    if(cJSON_IsString(key)&&!strcmp(key->valuestring,id)&&cJSON_IsNumber(old)) {
      char *value=strstr(line,"\"expires_unix_ms\":");
      char before[32],after[32];snprintf(before,sizeof(before),"%lld",(long long)old->valuedouble);snprintf(after,sizeof(after),"%lld",(long long)expiry);
      if(!value||strlen(before)!=strlen(after)){ok=0;cJSON_Delete(row);break;}
      value+=strlen("\"expires_unix_ms\":");
      if(strncmp(value,before,strlen(before))||fseek(f,offset+(long)(value-line),SEEK_SET)||fwrite(after,1,strlen(after),f)!=strlen(after)||fflush(f)||fseek(f,next,SEEK_SET)){ok=0;cJSON_Delete(row);break;}
      changed++;
    }
    cJSON_Delete(row);
  }
  if(ferror(f))ok=0;free(line);if(fclose(f))ok=0;return ok&&changed;
}

/* Reuse the complete production command receiver/executor already linked by
 * this fixture. Internal group admission must reach the existing egress hold;
 * accepting a selector never authorizes attack-surface collection or upload. */
static void attack_surface_command_admission(const EdrSoarCommandMeta *signed_meta) {
  const char *groups[] = {"full", "networkOnly", "inventoryOnly", "policyOnly"};
  EdrCommandStateRecord *record = calloc(1u, sizeof(*record));
  CHECK(record); if (!record) return;
  for (size_t i = 0; i < sizeof(groups)/sizeof(groups[0]); ++i) {
    char id[128], payload[160];
    snprintf(id, sizeof(id), "auto-asurf-synthetic-%s", groups[i]);
    snprintf(payload, sizeof(payload), "{\"reason\":\"periodic_attack_surface\",\"collection_group\":\"%s\"}", groups[i]);
    edr_command_on_internal_envelope(id, "GET_ATTACK_SURFACE", (const uint8_t *)payload, strlen(payload), NULL);
    for (unsigned wait = 0; wait < 4u && !edr_command_state_has_final(id, NULL); ++wait) pause_retry();
    memset(record, 0, sizeof(*record));
    CHECK(edr_command_state_begin(id, "GET_ATTACK_SURFACE", NULL, NULL, record) == EDR_COMMAND_STATE_BEGIN_DUP_FINAL);
    CHECK(record->execution_status == EdrCmdExecFailed && record->exit_code == EDR_EGRESS_REQUEST_DENIED);
    CHECK(strstr(record->detail, "attack_surface_policy_held") && !record->report_pending);
    CHECK(record->result_authorization.expires_unix_ms == 0);
  }
  const char *invalid[] = {
      "{\"collection_group\":\"listenersOnly\"}",
      "{\"collection_group\":\"networkOnly\",\"unknown\":true}"
  };
  for (size_t i = 0; i < sizeof(invalid)/sizeof(invalid[0]); ++i) {
    char id[128]; snprintf(id, sizeof(id), "auto-asurf-synthetic-invalid-%zu", i);
    edr_command_on_internal_envelope(id, "GET_ATTACK_SURFACE", (const uint8_t *)invalid[i], strlen(invalid[i]), NULL);
    memset(record, 0, sizeof(*record));
    CHECK(edr_command_state_begin(id, "GET_ATTACK_SURFACE", NULL, NULL, record) == EDR_COMMAND_STATE_BEGIN_DUP_FINAL);
    CHECK(record->execution_status == EdrCmdExecRejected && record->exit_code == 19);
  }
  const char *payload = "{\"collection_group\":\"networkOnly\"}";
  EdrSoarCommandMeta forged = *signed_meta;
  snprintf(forged.initiated_by, sizeof(forged.initiated_by), "agent_auto");
  forged.idempotency_key[0] = '\0';
  CHECK(edr_command_receive_envelope("auto-asurf-synthetic-external", "GET_ATTACK_SURFACE",
      (const uint8_t *)payload, strlen(payload), &forged) == 0);
  CHECK(!edr_command_state_has_final("auto-asurf-synthetic-external", &forged));
  edr_command_on_internal_envelope("cmd-synthetic-not-internal", "GET_ATTACK_SURFACE",
      (const uint8_t *)payload, strlen(payload), NULL);
  CHECK(!edr_command_state_has_final("cmd-synthetic-not-internal", NULL));
  EdrCommandInboxRecord *inbox = calloc(16u, sizeof(*inbox));
  CHECK(inbox);
  if (inbox) {
    int count = edr_command_state_collect_inbox(inbox, 16u);
    CHECK(count >= 0);
    for (int i = 0; i < count; ++i) {
      CHECK(strcmp(inbox[i].command_id, "auto-asurf-synthetic-external"));
      CHECK(strcmp(inbox[i].command_id, "cmd-synthetic-not-internal"));
      edr_command_state_free_inbox_record(&inbox[i]);
    }
    free(inbox);
  }
  free(record);
}

static int command_result_scenario(const char *path) {
#ifdef _WIN32
  _putenv_s("EDR_COMMAND_STATE_DIR", path);
#else
  setenv("EDR_COMMAND_STATE_DIR", path, 1);
#endif
  EdrConfig cfg = {0};
  strcpy(cfg.agent.tenant_id, "synthetic-tenant");
  strcpy(cfg.agent.endpoint_id, "synthetic-endpoint");
  edr_command_bind_config(&cfg);
  EdrSoarCommandMeta meta = {0};
  const char *signature = getenv("EDR_TEST_COMMAND_SIGNATURE");
  const char *issued = getenv("EDR_TEST_COMMAND_ISSUED");
  CHECK(signature && issued);
  if (!signature || !issued) return 1;
  snprintf(meta.idempotency_key, sizeof(meta.idempotency_key), "%s", signature);
  meta.issued_at_unix_ms = (int64_t)strtoll(issued, NULL, 10);
  meta.deadline_ms = 30000;
  /* Changed identity invalidates the actual Ed25519 signature. */
  CHECK(edr_command_receive_envelope("cmd_synthetic_forged", "noop", (const uint8_t *)"{}", 2, &meta) == 0);
  CHECK(edr_ingest_http_post_command_result_typed("cmd_synthetic_forged", "noop", &meta, 1, 0, "forged") != 0);
  CHECK(edr_command_receive_envelope("cmd_synthetic_noop", "noop", (const uint8_t *)"[]", 2, &meta) == 0);
  char owner_limit[64];
  snprintf(owner_limit,sizeof(owner_limit),"%u",5u*EDR_COMMAND_STATE_SERIALIZED_RECORD_CAP);
#ifdef _WIN32
  CHECK(_putenv_s("EDR_COMMAND_STATE_OWNER_BUDGET_BYTES",owner_limit)==0);
#else
  CHECK(setenv("EDR_COMMAND_STATE_OWNER_BUDGET_BYTES",owner_limit,1)==0);
#endif
  CHECK(edr_command_state_begin("synthetic-capacity-owner","noop",NULL,NULL,NULL)==EDR_COMMAND_STATE_BEGIN_READY);
  EdrCommandExecutorHealth before_capacity,after_capacity;
  edr_command_executor_get_health(&before_capacity);
  /* This is the real signed receive path, durable inbox and executor. A full
   * owner budget leaves the receipt unacknowledged and performs no noop. */
  CHECK(edr_command_receive_envelope("cmd_synthetic_noop", "noop", (const uint8_t *)"{}", 2, &meta) == -1);
  edr_command_executor_wake();pause_retry();
  edr_command_executor_get_health(&after_capacity);
  CHECK(after_capacity.executed_count==before_capacity.executed_count);
  CHECK(!edr_command_state_has_final("cmd_synthetic_noop",&meta));
  EdrCommandStateCapacityStats capacity;
  CHECK(edr_command_state_get_capacity_stats(&capacity)==0);
  CHECK(capacity.admission_rejected>0 && !strcmp(capacity.last_error,"state_owner_budget_exhausted"));
  EdrCommandInboxRecord *retained_inbox=calloc(8u,sizeof(*retained_inbox));CHECK(retained_inbox);
  int retained_command=0;
  if(retained_inbox) {
    int count=edr_command_state_collect_inbox(retained_inbox,8u);
    for(int i=0;i<count;i++) {
      if(!strcmp(retained_inbox[i].command_id,"cmd_synthetic_noop"))retained_command=1;
      edr_command_state_free_inbox_record(&retained_inbox[i]);
    }
    free(retained_inbox);
  }
  CHECK(retained_command);
#ifdef _WIN32
  CHECK(_putenv_s("EDR_COMMAND_STATE_OWNER_BUDGET_BYTES","0")==0);
#else
  CHECK(setenv("EDR_COMMAND_STATE_OWNER_BUDGET_BYTES","0",1)==0);
#endif
  /* Restoring admission lets the same durable inbox execute exactly once;
   * the rejected receive did not need to recreate or replace its payload. */
  edr_command_executor_wake();
  EdrCommandStateRecord *pending = calloc(8u, sizeof(*pending)); CHECK(pending);
  int found = -1;
  for (unsigned attempt = 0; pending && attempt < 5u && found < 0; ++attempt) {
    pause_retry();
    int count = edr_command_state_collect_pending(pending, 8u);
    for (int i = 0; i < count; ++i)
      if (!strcmp(pending[i].command_id, "cmd_synthetic_noop")) found = i;
  }
  CHECK(found >= 0);
  pause_retry();edr_command_executor_get_health(&after_capacity);
  CHECK(after_capacity.executed_count==before_capacity.executed_count+1u);
  if (found >= 0) {
    EdrCommandStateRecord *record = &pending[found];
    CHECK(record->execution_status == 1 && record->result_authorization.expires_unix_ms > 0);
    char *original_detail=malloc(strlen(record->detail)+1u);CHECK(original_detail);
    if(!original_detail){free(pending);return 1;}strcpy(original_detail,record->detail);
    EdrSoarCommandMeta expired=meta;expired.result_authorization=record->result_authorization;
    expired.result_authorization.expires_unix_ms=(int64_t)time(NULL)*1000-1;
    /* Force only the clock boundary in durable state; the original command and
     * renewal both traverse the real Ed25519 admission and executor owners. */
    CHECK(fixture_expire_result(path,record->command_id,expired.result_authorization.expires_unix_ms));
    record->result_authorization=expired.result_authorization;
    CHECK(edr_command_state_mark_report_held(record,"result_authorization_expired")==0);
    const char *renew_payload=getenv("EDR_TEST_RENEWAL_PAYLOAD");
    const char *renew_signature=getenv("EDR_TEST_RENEWAL_SIGNATURE");
    const char *renew_issued=getenv("EDR_TEST_RENEWAL_ISSUED");
    CHECK(renew_payload && renew_signature && renew_issued);
    if(renew_payload && renew_signature && renew_issued) {
      EdrSoarCommandMeta renewal={0};
      snprintf(renewal.idempotency_key,sizeof(renewal.idempotency_key),"%s",renew_signature);
      renewal.issued_at_unix_ms=strtoll(renew_issued,NULL,10);renewal.deadline_ms=30000;
      CHECK(edr_command_receive_envelope("cmd_forged_renewal","result_delivery_renewal",
          (const uint8_t *)renew_payload,strlen(renew_payload),&renewal)==0);
      CHECK(edr_command_receive_envelope("cmd_synthetic_renewal","result_delivery_renewal",
          (const uint8_t *)renew_payload,strlen(renew_payload),&renewal)==1);
      edr_command_executor_wake();int renewed=0;
      for(unsigned attempt=0;attempt<5u && !renewed;attempt++) {
        pause_retry();int count=edr_command_state_collect_pending(pending,8u);
        for(int j=0;j<count;j++)if(!strcmp(pending[j].command_id,"cmd_synthetic_noop")) {
          record=&pending[j];renewed=1;CHECK(record->result_authorization.expires_unix_ms>(int64_t)time(NULL)*1000);
          CHECK(!strcmp(record->detail,original_detail) && record->execution_status==1 && record->exit_code==0);
        }
      }
      CHECK(renewed);
      CHECK(edr_command_receive_envelope("cmd_synthetic_noop","noop",(const uint8_t *)"{}",2,&meta)==0);
      EdrCommandStateRecord *duplicate=calloc(1,sizeof(*duplicate));CHECK(duplicate);
      if(duplicate) {
        CHECK(edr_command_state_begin("cmd_synthetic_noop","noop",&meta,NULL,duplicate)==EDR_COMMAND_STATE_BEGIN_DUP_FINAL);
        CHECK(!strcmp(duplicate->detail,original_detail));free(duplicate);
      }
    }
    free(original_detail);

    CHECK(edr_ingest_http_post_command_result_typed(record->command_id, record->command_type, &meta,
        record->execution_status, record->exit_code, "replacement bytes") != 0);
    /* Receiver deliberately returns an incomplete ACK once. */
    CHECK(edr_ingest_http_post_command_result_typed(record->command_id, record->command_type, &meta,
        record->execution_status, record->exit_code, record->detail) != 0);
    CHECK(edr_ingest_http_post_command_result_typed(record->command_id, record->command_type, &meta,
        record->execution_status, record->exit_code, record->detail) == 0);
    CHECK(edr_command_state_mark_reported(record) == 0);
    CHECK(edr_ingest_http_post_command_result_typed(record->command_id, record->command_type, &meta,
        record->execution_status, record->exit_code, record->detail) != 0);
  }
  /* Authenticated rejection results must remain reportable; no execution occurs. */
  const char *kinds[] = {"EXPIRED", "INVALID"};
  const char *ids[] = {"cmd_synthetic_expired", "cmd_synthetic_invalid"};
  const char *types[] = {"noop", "rtq_execute"};
  for (size_t k = 0; k < 2; ++k) {
    char key[96]; EdrSoarCommandMeta rejected = {0};
    snprintf(key, sizeof(key), "EDR_TEST_%s_SIGNATURE", kinds[k]);
    const char *sig = getenv(key);
    snprintf(key, sizeof(key), "EDR_TEST_%s_ISSUED", kinds[k]);
    const char *when = getenv(key);
    CHECK(sig && when); if (!sig || !when) continue;
    snprintf(rejected.idempotency_key, sizeof(rejected.idempotency_key), "%s", sig);
    rejected.issued_at_unix_ms = strtoll(when, NULL, 10); rejected.deadline_ms = 30000;
    CHECK(edr_command_receive_envelope(ids[k], types[k], (const uint8_t *)"{}", 2, &rejected) == 0);
    int count = edr_command_state_collect_pending(pending, 8u), match = 0;
    for (int i = 0; i < count; ++i) if (!strcmp(pending[i].command_id, ids[k])) {
      EdrCommandStateRecord *r = &pending[i]; match = 1;
      CHECK(r->execution_status == (k == 0 ? EdrCmdExecFailed : EdrCmdExecRejected));
      char *body = edr_command_result_http_json("synthetic-endpoint", "test-v1", r->command_id,
          r->command_type, r->execution_status, r->exit_code, r->detail,
          (int64_t)time(NULL)*1000, "", "", "");
      CHECK(body && edr_command_state_result_authorized("synthetic-tenant", "synthetic-endpoint", body, strlen(body)));
      free(body);
    }
    CHECK(match);
  }
  attack_surface_command_admission(&meta);
  CHECK(edr_command_executor_shutdown_timeout(5000) == 1);
  edr_command_bind_config(NULL); free(pending);
  printf("{\"mode\":\"positive-command\",\"signed_admission\":true,\"capacity_rejection_no_execution\":true,\"retained_inbox_replayed_once\":true,\"signed_renewal\":true,\"original_result_retained\":true,\"failed_checks\":%u}\n", failed);
  return failed ? 1 : 0;
}

/* Only the result-delivery boundary is synthetic: completed RTQ records are
 * persisted by the real owner and sent by its actual background thread. The
 * receiver requires real mTLS and complete application ACKs. No collector or
 * service loop is started, and these are not historical endpoint replays. */
static void delivery_env(const char *name, const char *value) {
#ifdef _WIN32
  CHECK(_putenv_s(name, value) == 0);
#else
  CHECK(setenv(name, value, 1) == 0);
#endif
}
static uint64_t delivery_clock_ms(void) {
#ifdef _WIN32
  return GetTickCount64();
#else
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
#endif
}
static void delivery_pause(void) {
#ifdef _WIN32
  Sleep(20u);
#else
  struct timespec interval = {0, 20000000L};
  nanosleep(&interval, NULL);
#endif
}
static int delivery_record(const char *id, EdrCommandStateRecord *record) {
  return edr_command_state_begin(id, "rtq_execute", NULL, NULL, record) ==
      EDR_COMMAND_STATE_BEGIN_DUP_FINAL;
}
static int delivery_wait(const char *id, int reported, uint32_t timeout_ms) {
  EdrCommandStateRecord *record = calloc(1u, sizeof(*record));
  CHECK(record);
  if (!record) return 0;
  uint64_t deadline = delivery_clock_ms() + timeout_ms;
  int ready = 0;
  do {
    if (delivery_record(id, record)) {
      ready = reported ? !record->report_pending : record->report_attempts > 0u;
      if (ready) break;
    }
    delivery_pause();
  } while (delivery_clock_ms() < deadline);
  free(record);
  return ready;
}
static void delivery_finish(const char *id) {
  const char *query = "{\"process_pid_min\":1000}";
  const char *detail = "{\"results\":[{\"type\":\"process\",\"pid\":1000,\"name\":\"synthetic.exe\"}],"
      "\"total\":1,\"truncated\":false,\"errors\":[],\"error\":null}";
  EdrSoarCommandMeta meta = {0};
  meta.issued_at_unix_ms = (int64_t)time(NULL) * 1000;
  meta.deadline_ms = 30000u;
  EdrCommandResultAuthorization *authority = &meta.result_authorization;
  snprintf(authority->command_id, sizeof(authority->command_id), "%s", id);
  snprintf(authority->command_type, sizeof(authority->command_type), "%s", "rtq_execute");
  snprintf(authority->tenant_id, sizeof(authority->tenant_id), "%s", "synthetic-tenant");
  snprintf(authority->endpoint_id, sizeof(authority->endpoint_id), "%s", "synthetic-endpoint");
  authority->expires_unix_ms = meta.issued_at_unix_ms + 120000;
  CHECK(edr_command_result_bind_contract(authority, (const uint8_t *)query,
      strlen(query), meta.issued_at_unix_ms) == 0);
  CHECK(edr_command_state_finish(id, "rtq_execute", &meta, "ok", 1, 0, detail, "", 1) == 0);
}
static int delivery_wait_poll_complete(uint32_t timeout_ms) {
  uint64_t deadline = delivery_clock_ms() + timeout_ms;
  EdrCommandDeliveryHealth health = {0};
  do {
    edr_command_get_delivery_health(&health);
    if (health.last_result_ms > 0u) return 1;
    delivery_pause();
  } while (delivery_clock_ms() < deadline);
  return 0;
}
static int command_delivery_scenario(const char *path, const char *mode) {
  delivery_env("EDR_COMMAND_STATE_DIR", path);
  delivery_env("EDR_COMMAND_DELIVERY_POLL_MS", "1000");
  delivery_env("EDR_COMMAND_RESULT_PRESSURE_INTERVAL_MS",
      !strcmp(mode, "positive-command-delivery-recovered") ||
      !strcmp(mode, "positive-command-delivery-batch") ? "60000" : "1000");
  delivery_env("EDR_COMMAND_DELIVERY_SLOW_MS", "100");
  delivery_env("EDR_PREPROCESS_THROTTLE", "1");
  delivery_env("EDR_COMMAND_RESULT_RETRY_BASE_MS", "8000");
  delivery_env("EDR_COMMAND_RESULT_RETRY_MAX_MS", "8000");
  EdrConfig cfg = {0};
  snprintf(cfg.agent.tenant_id, sizeof(cfg.agent.tenant_id), "%s", "synthetic-tenant");
  snprintf(cfg.agent.endpoint_id, sizeof(cfg.agent.endpoint_id), "%s", "synthetic-endpoint");
  edr_command_bind_config(&cfg);
  uint64_t started = delivery_clock_ms();
  if (!strcmp(mode, "positive-command-delivery-batch")) {
    for (unsigned i = 0u; i < 18u; ++i) {
      char id[128];
      snprintf(id, sizeof(id), "cmd_delivery_batch_%02u", i);
      delivery_finish(id);
    }
    edr_command_poll_reliable_delivery();
    CHECK(delivery_wait_poll_complete(4000u));
    EdrCommandStateRecord *record = calloc(1u, sizeof(*record));
    CHECK(record);
    unsigned reported = 0u;
    if (record) {
      for (unsigned i = 0u; i < 18u; ++i) {
        char id[128];
        snprintf(id, sizeof(id), "cmd_delivery_batch_%02u", i);
        CHECK(delivery_record(id, record));
        reported += !record->report_pending;
      }
      free(record);
    }
    CHECK(reported == 16u);
    delivery_env("EDR_PREPROCESS_THROTTLE", "0");
    CHECK(delivery_wait("cmd_delivery_batch_17", 1, 4000u));
  } else if (!strcmp(mode, "positive-command-delivery-invariants")) {
    delivery_finish("cmd_delivery_held");
    delivery_finish("cmd_delivery_acked");
    EdrCommandStateRecord *record = calloc(1u, sizeof(*record));
    CHECK(record);
    if (record) {
      CHECK(delivery_record("cmd_delivery_held", record));
      CHECK(edr_command_state_mark_report_held(record, "synthetic_policy_hold") == 0);
      CHECK(delivery_record("cmd_delivery_acked", record));
      CHECK(edr_command_state_mark_reported(record) == 0);
    }
    delivery_finish("cmd_delivery_retry");
    delivery_finish("cmd_delivery_rate_limited");
    edr_command_poll_reliable_delivery();
    CHECK(delivery_wait("cmd_delivery_retry", 0, 4000u));
    CHECK(delivery_wait("cmd_delivery_rate_limited", 0, 4000u));
    delivery_finish("cmd_delivery_fresh");
    CHECK(delivery_wait("cmd_delivery_fresh", 1, 4000u));
    if (record) {
      CHECK(delivery_record("cmd_delivery_retry", record));
      CHECK(record->report_pending && record->report_attempts == 1u &&
          record->report_next_retry_unix_ms > (int64_t)time(NULL) * 1000);
      CHECK(delivery_record("cmd_delivery_rate_limited", record));
      CHECK(record->report_pending && record->report_attempts == 1u &&
          record->report_next_retry_unix_ms > (int64_t)time(NULL) * 1000);
      CHECK(delivery_record("cmd_delivery_held", record));
      CHECK(record->report_policy_held && record->report_attempts == 0u);
      CHECK(delivery_record("cmd_delivery_acked", record));
      CHECK(!record->report_pending && record->report_attempts == 0u);
      free(record);
    }
    CHECK(delivery_wait("cmd_delivery_retry", 1, 10000u));
    CHECK(delivery_wait("cmd_delivery_rate_limited", 1, 10000u));
  } else {
    delivery_finish("cmd_delivery_slow");
    edr_command_poll_reliable_delivery();
    CHECK(delivery_wait("cmd_delivery_slow", 1, 4000u));
    CHECK(delivery_wait_poll_complete(4000u));
    EdrCommandDeliveryHealth health = {0};
    edr_command_get_delivery_health(&health);
    CHECK(health.last_result_ms >= 100u);
    if (!strcmp(mode, "positive-command-delivery-recovered"))
      delivery_env("EDR_PREPROCESS_THROTTLE", "0");
    delivery_finish("cmd_delivery_fresh");
    CHECK(delivery_wait("cmd_delivery_fresh", 1, 4000u));
  }
  CHECK(edr_command_delivery_shutdown_timeout(5000u) == 1);
  CHECK(edr_command_executor_shutdown_timeout(5000u) == 1);
  edr_command_bind_config(NULL);
  printf("{\"mode\":\"%s\",\"real_delivery_thread\":true,\"historical_replay\":false,"
      "\"elapsed_ms\":%llu,\"failed_checks\":%u}\n", mode,
      (unsigned long long)(delivery_clock_ms() - started), failed);
  return failed ? 1 : 0;
}
static unsigned download_scope_calls, download_expire_at;
static int download_clock_boundary(const char *id,EdrEgressTaskScope *scope) {
  int rc=edr_command_state_task_scope(id,scope);
  if(rc)return rc;
  return ++download_scope_calls>=download_expire_at?EDR_EGRESS_AUTHORIZATION_EXPIRED:0;
}
static int file_absent(const char *path) {FILE *f=fopen(path,"rb");if(f){fclose(f);return 0;}return 1;}
static int download_bytes_match(const char *path) {
  char bytes[64]={0};FILE *f=fopen(path,"rb");if(!f)return 0;
  size_t n=fread(bytes,1,sizeof(bytes),f);int ok=!ferror(f)&&n==16&&!memcmp(bytes,"synthetic-update",16);
  if(fclose(f))ok=0;return ok;
}
static int update_download_scenario(const char *path,int bad_tls) {
#ifdef _WIN32
  _putenv_s("EDR_COMMAND_STATE_DIR",path);
#else
  setenv("EDR_COMMAND_STATE_DIR",path,1);
#endif
  const char *payload=getenv("EDR_TEST_UPDATE_PAYLOAD"),*signature=getenv("EDR_TEST_UPDATE_SIGNATURE"),
             *issued=getenv("EDR_TEST_UPDATE_ISSUED");
  CHECK(payload&&signature&&issued);if(!payload||!signature||!issued)return 1;
  const char *id="cmd_synthetic_update";EdrSoarCommandMeta meta={0};
  snprintf(meta.idempotency_key,sizeof(meta.idempotency_key),"%s",signature);
  meta.issued_at_unix_ms=strtoll(issued,NULL,10);meta.deadline_ms=30000;
  CommandSignaturePolicy policy={1};char reason[256];EdrAgentUpdateRequest request={0};
  /* The real Ed25519 verifier precedes the protected receipt, using exactly
   * the same authority binding as command admission. No updater is launched. */
  CHECK(edr_command_signature_verify(id,"agent_update",(const uint8_t *)payload,strlen(payload),&meta,&policy,reason,sizeof(reason))==1);
  CHECK(edr_command_signature_verify("cmd_forged_update","agent_update",(const uint8_t *)payload,strlen(payload),&meta,&policy,reason,sizeof(reason))==0);
  CHECK(edr_agent_update_parse_request((const uint8_t *)payload,strlen(payload),&request,reason,sizeof(reason))==1);
  char output[1400];snprintf(output,sizeof(output),"%s.download",path);
  CHECK(edr_ingest_http_get_agent_update_url_to_file(id,request.artifact_url,output,4096)==EDR_EGRESS_REQUEST_DENIED);
  CHECK(file_absent(output));
  EdrCommandResultAuthorization *a=&meta.result_authorization;
  snprintf(a->tenant_id,sizeof(a->tenant_id),"synthetic-tenant");
  snprintf(a->endpoint_id,sizeof(a->endpoint_id),"synthetic-endpoint");
  snprintf(a->command_id,sizeof(a->command_id),"%s",id);
  snprintf(a->command_type,sizeof(a->command_type),"agent_update");
  a->expires_unix_ms=meta.issued_at_unix_ms+86400000;
  CHECK(edr_command_result_bind_contract(a,(const uint8_t *)payload,strlen(payload),meta.issued_at_unix_ms)==0);
  CHECK(edr_command_state_store_inbox(id,"agent_update",(const uint8_t *)payload,strlen(payload),&meta)==0);
  if(bad_tls) {
    CHECK(edr_ingest_http_get_agent_update_url_to_file(id,request.artifact_url,output,4096)!=0);
    CHECK(file_absent(output));
  } else {
    CHECK(edr_ingest_http_get_agent_update_url_to_file("cmd_forged_update",request.artifact_url,output,4096)==EDR_EGRESS_REQUEST_DENIED);
    CHECK(edr_ingest_http_get_url_to_file(request.artifact_url,output,4096)!=0 && file_absent(output));
    char altered[2300];snprintf(altered,sizeof(altered),"%s&extra=1",request.artifact_url);
    CHECK(edr_ingest_http_get_agent_update_url_to_file(id,altered,output,4096)==EDR_EGRESS_REQUEST_DENIED);
    CHECK(file_absent(output));
    CHECK(edr_ingest_http_get_agent_update_url_to_file(id,request.artifact_url,output,4096)==0);
    CHECK(download_bytes_match(output));remove(output);
    CHECK(edr_ingest_http_get_agent_update_url_to_file(id,request.runtime_manifest_url,output,4096)==0);
    CHECK(download_bytes_match(output));remove(output);
    /* Real transport failures must not become success just because the next
     * purpose check passed. The synthetic receiver closes both retry sockets. */
    CHECK(edr_ingest_http_get_agent_update_url_to_file(id,request.artifact_url,output,4096)!=0);
    CHECK(file_absent(output));
    EdrIngestHttpRuntime before,after;
    for(unsigned expire=2;expire<=4;expire++) {
      download_scope_calls=0;download_expire_at=expire;
      edr_egress_set_task_scope_lookup(download_clock_boundary);
      edr_ingest_http_get_runtime(&before);
      CHECK(edr_ingest_http_get_agent_update_url_to_file(id,request.artifact_url,output,4096)==EDR_EGRESS_AUTHORIZATION_EXPIRED);
      edr_ingest_http_get_runtime(&after);
      CHECK(download_scope_calls==expire && file_absent(output));
      CHECK(after.http_request_fail_count==before.http_request_fail_count && after.circuit_open==before.circuit_open);
      CHECK(strstr(after.last_error,"egress_denied:task_authorization_expired"));
    }
    edr_egress_set_task_scope_lookup(edr_command_state_task_scope);
  }
  edr_command_state_delete_inbox(id);
  printf("{\"mode\":\"signed-update-download\",\"signed_admission\":true,\"tls_rejection\":%s,\"failed_checks\":%u}\n",bad_tls?"true":"false",failed);
  return failed?1:0;
}

/* Runs real storage, RAW/BLZ4 codec, frozen request purpose, durable result
 * owner and final HTTP gate. Signature admission and TLS remain covered by
 * the existing signed loopback suite; this mode opens no network connection. */
static void local_query_source(unsigned number,int compressed,int mismatch) {
  EdrBehaviorRecord *source=calloc(1,sizeof(*source)),*record=calloc(1,sizeof(*record));
  uint8_t *raw=malloc(1048576u),*wire=malloc(1048576u);
  CHECK(source && record && raw && wire); if(!source||!record||!raw||!wire) goto done;
  edr_behavior_record_init(source); source->type=EDR_EVENT_PROCESS_CREATE;
  source->pid=42+number; source->ppid=21; source->process_start_key=1000+number;
  source->process_creation_filetime_100ns=133700000000000000ULL+number;
  source->event_time_ns=(int64_t)time(NULL)*1000000000LL;
  snprintf(source->endpoint_id,sizeof(source->endpoint_id),"synthetic-endpoint");
  snprintf(source->tenant_id,sizeof(source->tenant_id),"%s",number==2 ? "other-tenant" : "synthetic-tenant");
  snprintf(source->event_id,sizeof(source->event_id),"local-query-source-%u",number);
  snprintf(source->process_name,sizeof(source->process_name),"query-visible.exe");
  snprintf(source->cmdline,sizeof(source->cmdline),"private-unrequested-command");
  CHECK(edr_p0_source_only_build_pre_evaluation_record(source,"coalescer_backpressure",record));
  CHECK(edr_p0_source_only_validate_record(record));
  char command[6001]; memset(command,'x',6000); command[6000]=0;
  memcpy(command,"query-visible ",14); memcpy(command+5989,"tail-needle",11);
  size_t n=edr_behavior_record_encode_protobuf_full_facts(record,NULL,number==1 ? command : NULL,NULL,raw+4,1048572u);
  CHECK(n>0); if(!n) goto done; wr(raw,(uint32_t)n);
  size_t body=n+4;
  wr(wire,compressed ? EDR_TRANSPORT_BATCH_MAGIC_LZ4 : EDR_TRANSPORT_BATCH_MAGIC_RAW);
  wr(wire+4,1); wr(wire+8,(uint32_t)body);
  if(compressed) { int z=LZ4_compress_default((const char*)raw,(char*)wire+12,(int)body,1048564);CHECK(z>0);body=(size_t)z; }
  else memcpy(wire+12,raw,body);
  char why[128]; CHECK(!edr_egress_batch_validate(wire,12,wire+12,body,why,sizeof(why)));
  EdrStorageQueueP0SourceOnlyLatch latch;
  CHECK(edr_storage_queue_p0_source_only_latch_prepare_local(&latch)==EDR_OK);
  EdrStorageQueueLocalEvidenceOwner owner={0}; owner.version=1; owner.diagnostic_reason="coalescer_backpressure";
  owner.endpoint_id=record->endpoint_id; owner.tenant_id=record->tenant_id;owner.event_time_ns=record->event_time_ns;
  owner.event_type=record->type;owner.pid=mismatch ? 99u : record->pid;owner.parent_pid=record->ppid;
  owner.process_start_key=record->process_start_key;owner.process_creation_filetime_100ns=record->process_creation_filetime_100ns;
  CHECK(edr_storage_queue_p0_source_only_commit_local_typed(&latch,record->event_id,record->event_id,wire,body+12,compressed,0,&owner)==EDR_OK);
done:
  free(source);free(record);free(raw);free(wire);
}

static void local_query_terminal_source(unsigned number,int mismatch) {
  EdrTestP0TerminalFixture fixture;
  int initialized=edr_test_p0_terminal_fixture_init(&fixture,number,"synthetic-tenant","synthetic-endpoint");
  CHECK(initialized); if(!initialized) return;
  edr_v1_BehaviorEvent *event=calloc(1,sizeof(*event)); CHECK(event);
  if(!event) { edr_test_p0_terminal_fixture_free(&fixture); return; }
  int64_t stamp=(int64_t)time(NULL)*1000000000LL;
  for(unsigned kind=0;kind<3;++kind) {
    memset(event,0,sizeof(*event));
    pb_istream_t in=pb_istream_from_buffer(fixture.wire[kind]+16,fixture.length[kind]-16);
    CHECK(pb_decode(&in,edr_v1_BehaviorEvent_fields,event));
    event->event_time_ns=stamp;
    if(event->has_behavior_alert)event->behavior_alert.timestamp_ns=stamp;
    if(mismatch && kind==1) {
      char *birth=strstr(event->ave_result_json,"133444000000000000"); CHECK(birth);
      if(birth) birth[17]='1'; /* Same double, different exact uint64 lexeme. */
    }
    pb_ostream_t out=pb_ostream_from_buffer(fixture.wire[kind]+16,65520);
    CHECK(pb_encode(&out,edr_v1_BehaviorEvent_fields,event));
    fixture.length[kind]=out.bytes_written+16;
    wr(fixture.wire[kind]+8,(uint32_t)out.bytes_written+4);wr(fixture.wire[kind]+12,(uint32_t)out.bytes_written);
  }
  char intent[64],source[64],combined[64];
  snprintf(intent,sizeof(intent),"query-terminal-intent-%u",number);
  snprintf(source,sizeof(source),"query-terminal-source-%u",number);
  snprintf(combined,sizeof(combined),"query-terminal-combined-%u",number);
  CHECK(edr_storage_queue_enforcement_terminal_precreate(fixture.terminal_key,fixture.source_event_id,
      fixture.rule_id,fixture.generation_key,intent,fixture.wire[0],fixture.length[0])==EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  EdrStorageQueueLocalEvidenceOwner owner={0};owner.version=1;owner.diagnostic_reason="enforcement_terminal_result";
  owner.tenant_id="synthetic-tenant";owner.endpoint_id="synthetic-endpoint";owner.event_time_ns=stamp;
  owner.event_type=EDR_EVENT_PROCESS_CREATE;owner.pid=4242;owner.process_start_key=UINT64_C(0xfedcba9876543210);
  owner.process_creation_filetime_100ns=UINT64_C(133444000000000000);
  CHECK(edr_storage_queue_enforcement_terminal_update_local_source(fixture.terminal_key,source,fixture.wire[1],
      fixture.length[1],combined,fixture.wire[2],fixture.length[2],fixture.source_event_id,&owner)==EDR_OK);
  free(event);edr_test_p0_terminal_fixture_free(&fixture);
}

static int local_query_contract_scenario(const char *prefix) {
  char queue[1400],cache[1400],state[1400];
  snprintf(queue,sizeof(queue),"%s.queue",prefix);snprintf(cache,sizeof(cache),"%s.cache",prefix);
  /* A CTest rerun is a new authorization session. Never overwrite a previous
   * frozen owner or relax its conflict check just to make the fixture repeat. */
#ifdef _WIN32
  snprintf(state,sizeof(state),"%s.state-%lu-%llu",prefix,(unsigned long)GetCurrentProcessId(),
      (unsigned long long)GetTickCount64());
  int state_created=CreateDirectoryA(state,NULL)!=0;
  CHECK(state_created);if(!state_created)return 1;
  CHECK(_putenv_s("EDR_COMMAND_STATE_DIR",state)==0);
#else
  snprintf(state,sizeof(state),"%s.state.XXXXXX",prefix);
  char *state_created=mkdtemp(state);CHECK(state_created);if(!state_created)return 1;
  CHECK(setenv("EDR_COMMAND_STATE_DIR",state,1)==0);
#endif
  EdrConfig cfg={0};snprintf(cfg.agent.tenant_id,sizeof(cfg.agent.tenant_id),"synthetic-tenant");
  snprintf(cfg.agent.endpoint_id,sizeof(cfg.agent.endpoint_id),"synthetic-endpoint");edr_command_bind_config(&cfg);
  edr_egress_set_command_result_validator(edr_command_state_result_authorized);
  edr_storage_queue_configure(16,1);CHECK(edr_storage_queue_open(queue)==EDR_OK);
  CHECK(edr_local_evidence_cache_open_with_policy(cache,16,1,4)==0);
  for(unsigned i=0;i<3;++i)local_query_source(i,i==1,0);
  EdrSoarCommandMeta meta={0};meta.issued_at_unix_ms=(int64_t)time(NULL)*1000;meta.deadline_ms=60000;
  EdrCommandResultAuthorization *a=&meta.result_authorization;
  snprintf(a->command_id,sizeof(a->command_id),"local-query-contract");snprintf(a->command_type,sizeof(a->command_type),"rtq_query");
  snprintf(a->tenant_id,sizeof(a->tenant_id),"synthetic-tenant");snprintf(a->endpoint_id,sizeof(a->endpoint_id),"synthetic-endpoint");
  a->expires_unix_ms=meta.issued_at_unix_ms+60000;
  const char *request="{\"event_type\":\"1\",\"process_name\":\"query-visible\",\"limit\":10}";
  CHECK(edr_command_result_bind_contract(a,(const uint8_t*)request,strlen(request),meta.issued_at_unix_ms)==0);
  char output[16384],projected[16384],reason[128];
  int queried=edr_local_evidence_cache_query_authorized_json(a->command_id,&meta,output,sizeof(output));CHECK(queried==0);
  cJSON *result=queried==0 ? cJSON_Parse(output) : NULL;CHECK(result);
  if(result)CHECK(cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(result,"rows"))==2);
  CHECK(!strstr(output,"private-unrequested-command") && !strstr(output,"tail-needle") && !strstr(output,"other-tenant"));
  CHECK(strstr(output,"event_queue"));cJSON_Delete(result);
  CHECK(edr_command_result_project_detail(a,"rtq_query",1,0,output,projected,sizeof(projected))==0);
  CHECK(edr_command_state_finish(a->command_id,"rtq_query",&meta,"ok",1,0,projected,"",1)==0);
  CHECK(edr_command_state_finish(a->command_id,"rtq_query",&meta,"ok",1,0,projected,"",1)==0);
  CHECK(edr_command_state_finish(a->command_id,"rtq_query",&meta,"failed",0,1,"conflicting-result","",1)<0);
  char *body=edr_command_result_http_json(a->endpoint_id,"test-v1",a->command_id,"rtq_query",1,0,projected,meta.issued_at_unix_ms,"","","");CHECK(body);
  if(body) { int gate=edr_egress_request_validate_for_scope("POST","ingest/report-command-result","application/json",body,strlen(body),a->tenant_id,a->endpoint_id,reason,sizeof(reason));
    if(gate)fprintf(stderr,"local query final gate cause=%s\n",reason);
    CHECK(gate==0);free(body); }
  request="{\"pid\":43,\"process_cmdline\":\"tail-needle\"}";
  CHECK(edr_command_result_bind_contract(a,(const uint8_t*)request,strlen(request),meta.issued_at_unix_ms)==0);
  CHECK(edr_local_evidence_cache_query_authorized_json(a->command_id,&meta,output,sizeof(output))==0);
  result=cJSON_Parse(output);CHECK(result);
  if(result) {
    cJSON *rows=cJSON_GetObjectItemCaseSensitive(result,"rows");CHECK(cJSON_GetArraySize(rows)==1);
    const cJSON *command=cJSON_GetObjectItemCaseSensitive(cJSON_GetArrayItem(rows,0),"cmdline");
    CHECK(cJSON_IsString(command) && strlen(command->valuestring)==6000 && strstr(command->valuestring,"tail-needle"));cJSON_Delete(result);
  }
  CHECK(edr_command_result_project_detail(a,"rtq_query",1,0,output,projected,sizeof(projected))==0);
  CHECK(edr_local_evidence_cache_query_authorized_json(a->command_id,&meta,output,512)<0 && strstr(output,"byte budget"));
  local_query_terminal_source(1,0);
  snprintf(a->command_id,sizeof(a->command_id),"local-query-terminal");
  request="{\"pid\":4242}";
  CHECK(edr_command_result_bind_contract(a,(const uint8_t*)request,strlen(request),meta.issued_at_unix_ms)==0);
  CHECK(edr_local_evidence_cache_query_authorized_json(a->command_id,&meta,output,sizeof(output))==0);
  result=cJSON_Parse(output);CHECK(result);
  if(result)CHECK(cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(result,"rows"))==1);
  cJSON_Delete(result);
  CHECK(!strstr(output,"synthetic-required-rule-fact") && !strstr(output,"terminal_key"));
  CHECK(edr_command_result_project_detail(a,"rtq_query",1,0,output,projected,sizeof(projected))==0);
  CHECK(edr_command_state_finish(a->command_id,"rtq_query",&meta,"ok",1,0,projected,"",1)==0);
  body=edr_command_result_http_json(a->endpoint_id,"test-v1",a->command_id,"rtq_query",1,0,projected,meta.issued_at_unix_ms,"","","");CHECK(body);
  if(body) { CHECK(edr_egress_request_validate_for_scope("POST","ingest/report-command-result","application/json",body,
      strlen(body),a->tenant_id,a->endpoint_id,reason,sizeof(reason))==0);free(body); }
  local_query_terminal_source(2,1);
  CHECK(edr_local_evidence_cache_query_authorized_json(a->command_id,&meta,output,sizeof(output))<0 && strstr(output,"identity"));
  local_query_source(3,0,1);
  request="{\"pid\":99}";CHECK(edr_command_result_bind_contract(a,(const uint8_t*)request,strlen(request),meta.issued_at_unix_ms)==0);
  CHECK(edr_local_evidence_cache_query_authorized_json(a->command_id,&meta,output,sizeof(output))<0 && strstr(output,"identity"));
  edr_storage_queue_close();edr_local_evidence_cache_close();remove(queue);remove(cache);
  char fixture_file[1500];
  const char *sidecars[]={"-wal","-shm"};
  for(unsigned i=0;i<2;++i) {
    snprintf(fixture_file,sizeof(fixture_file),"%s%s",queue,sidecars[i]);remove(fixture_file);
    snprintf(fixture_file,sizeof(fixture_file),"%s%s",cache,sidecars[i]);remove(fixture_file);
  }
  snprintf(fixture_file,sizeof(fixture_file),"%s/command_state.jsonl",state);CHECK(remove(fixture_file)==0);
  snprintf(fixture_file,sizeof(fixture_file),"%s/command_state.jsonl.lock",state);CHECK(remove(fixture_file)==0);
#ifdef _WIN32
  CHECK(RemoveDirectoryA(state)!=0);
#else
  CHECK(rmdir(state)==0);
#endif
  printf("{\"mode\":\"local-query-contract\",\"raw_lz4_scope_projection_final_gate\":true,\"terminal_source_scope_projection_final_gate\":true,\"network_started\":false,\"failed_checks\":%u}\n",failed);
  return failed ? 1 : 0;
}

#endif

int main(int argc, char **argv) {
#ifdef EDR_TEST_EXTENDED_EGRESS
  if(argc==3 && !strcmp(argv[1],"--local-query-contract"))return local_query_contract_scenario(argv[2]);
  if (argc == 3 && !strcmp(argv[1], "--attack-surface-admission")) {
    char path[1200], state[1280];
#ifdef _WIN32
    unsigned pid = (unsigned)GetCurrentProcessId();
#else
    unsigned pid = (unsigned)getpid();
#endif
    CHECK(snprintf(path, sizeof(path), "%s-%lld-%u", argv[2], (long long)time(NULL), pid) < (int)sizeof(path));
    snprintf(state, sizeof(state), "%s/command_state.jsonl", path);
    FILE *existing = fopen(state, "rb");
    CHECK(!existing); if (existing) { fclose(existing); return 1; }
#ifdef _WIN32
    CHECK(_putenv_s("EDR_COMMAND_STATE_DIR", path) == 0);
    CHECK(_putenv_s("EDR_COMMAND_REQUIRE_SIGNATURE", "1") == 0);
#else
    CHECK(setenv("EDR_COMMAND_STATE_DIR", path, 1) == 0);
    CHECK(setenv("EDR_COMMAND_REQUIRE_SIGNATURE", "1", 1) == 0);
#endif
    EdrConfig cfg = {0};
    snprintf(cfg.agent.endpoint_id, sizeof(cfg.agent.endpoint_id), "synthetic-endpoint");
    snprintf(cfg.agent.tenant_id, sizeof(cfg.agent.tenant_id), "synthetic-tenant");
    edr_command_bind_config(&cfg);
    EdrSoarCommandMeta meta = {0};
    meta.issued_at_unix_ms = (int64_t)time(NULL) * 1000;
    meta.deadline_ms = 30000u;
    attack_surface_command_admission(&meta);
    CHECK(edr_command_executor_shutdown_timeout(5000u) == 1);
    edr_command_bind_config(NULL);
    printf("{\"mode\":\"attack-surface-admission\",\"received_groups\":4,\"egress_policy\":\"held\",\"failed_checks\":%u}\n", failed);
    return failed ? 1 : 0;
  }
#endif
  if (argc != 7) {
    fprintf(stderr, "usage: test_egress_tls_client BASE_URL CA CLIENT_CERT CLIENT_KEY QUEUE_PATH MODE\n"); return 2;
  }
  edr_ingest_http_configure(argv[1], "synthetic-tenant", "", "", "synthetic-endpoint", "test-v1",
      argv[2], argv[3], argv[4], "pem", "", "", "direct", "", "");
  edr_ingest_http_set_policy_version("synthetic-p1");
  int v2 = !strcmp(argv[6], "positive-v2");
  edr_ingest_http_configure_transport_options(0, 0, 0, 0, v2, "protobuf", v2 ? "zstd" : "none");
#ifdef EDR_TEST_EXTENDED_EGRESS
  if (strstr(argv[6], "update-download")) return update_download_scenario(argv[5],!strncmp(argv[6],"wrong-",6));
  if (!strcmp(argv[6], "positive-command")) return command_result_scenario(argv[5]);
  if (!strncmp(argv[6], "positive-command-delivery-", 26u))
    return command_delivery_scenario(argv[5], argv[6]);
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
#ifdef EDR_TEST_EXTENDED_EGRESS
  if (!strcmp(argv[6], "positive") && !getenv("EDR_TEST_CRASH_AFTER_LOST_ACK"))
    rule_file_downloads(argv[1], argv[5]);
#endif
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
