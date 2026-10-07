#include "edr/storage_queue.h"
#include "edr/egress_batch_policy.h"
#include "edr/evidence_projection.h"
#include "edr/report_events_ack.h"
#include "edr/transport_sink.h"
#include "edr/sha256.h"
#include "edr/types.h"
#include "edr/v1/event.pb.h"
#include "cJSON.h"
#include "lz4.h"
#include "p0_terminal_association_fixture.h"
#include <pb_encode.h>
#include <pb_decode.h>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#if defined(_WIN32)
#include <windows.h>
#include <process.h>
#define TEST_PID _getpid()
#else
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#define TEST_PID getpid()
#endif

void edr_storage_queue_test_stop_recovery_phase(int phase);
void edr_storage_queue_test_fail_egress_allocation(unsigned failures);
static unsigned sends;
static int receipt_mode;
static char sent_id[128];
static uint8_t sent_wire[65536];
static size_t sent_len;
static void test_path(char *out,size_t cap,const char *name,int suffix) {
#ifdef _WIN32
  char directory[MAX_PATH]; DWORD n=GetTempPathA(sizeof(directory),directory);
  assert(n>0 && n<sizeof(directory));
  int used=snprintf(out,cap,"%sedr-%s-%ld-%d.db",directory,name,(long)TEST_PID,suffix);
#else
  int used=snprintf(out,cap,"/private/tmp/edr-%s-%ld-%d.db",name,(long)TEST_PID,suffix);
#endif
  assert(used>0 && (size_t)used<cap);
}
int edr_ingest_http_configured(void) { return 1; }
int edr_ingest_http_circuit_open(void) { return 0; }
int edr_ingest_http_telemetry_deferred(void) { return 0; }
int edr_transport_v2_report_events(const char *id,const uint8_t *header,size_t hlen,
    const uint8_t *payload,size_t plen) {
  char why[96]; assert(hlen==12 && hlen+plen<=sizeof(sent_wire));
  assert(edr_egress_batch_validate(header,hlen,payload,plen,why,sizeof(why)));
  snprintf(sent_id,sizeof(sent_id),"%s",id); sent_len=hlen+plen;
  memcpy(sent_wire,header,hlen); memcpy(sent_wire+hlen,payload,plen); sends++;
  if (receipt_mode==3) return EDR_REPORT_EVENTS_POLICY_HELD;
  if (!receipt_mode) return -1; /* No network in this storage contract. */
  char sha[65],body[640]; edr_sha256_hex(sent_wire,sent_len,sha);
  snprintf(body,sizeof(body),"{\"code\":\"OK\",\"data\":{\"accepted\":1,\"invalid_frames\":0,"
    "\"ack\":{\"version\":1,\"state\":\"processed\","
    "\"endpoint_id\":\"synthetic-endpoint\",\"batch_id\":\"%s\",\"payload_sha256\":\"%s\","
    "\"frame_count\":1}}}",receipt_mode==2?"wrong-batch":id,sha);
  return edr_report_events_acknowledged(body,"synthetic-endpoint",id,header,hlen,payload,plen)?0:-1;
}
static void wr(uint8_t *p,uint32_t n) { for (unsigned i=0;i<4;i++) p[i]=(uint8_t)(n>>(i*8)); }
static uint32_t rd(const uint8_t *p) {
  return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
static void file_sha(const char *path,char out[65]) {
  FILE *file=fopen(path,"rb"); assert(file); EdrSha256Ctx hash; edr_sha256_init(&hash);
  uint8_t block[4096],digest[32]; size_t n;
  while ((n=fread(block,1,sizeof(block),file))>0) edr_sha256_update(&hash,block,n);
  assert(!ferror(file)); fclose(file); edr_sha256_final(&hash,digest);
  static const char hex[]="0123456789abcdef";
  for (size_t i=0;i<32;i++) { out[i*2]=hex[digest[i]>>4]; out[i*2+1]=hex[digest[i]&15]; }
  out[64]=0;
}
static uint8_t *make_wire(int alert,int mixed,int compressed,const char *endpoint,size_t *len) {
  edr_v1_BehaviorEvent *ev=calloc(1,sizeof(*ev)); uint8_t *frame=malloc(65536),*raw=malloc(131072);
  assert(ev && frame && raw);
  strcpy(ev->event_id,"synthetic-source"); strcpy(ev->tenant_id,"synthetic-tenant");
  snprintf(ev->endpoint_id,sizeof(ev->endpoint_id),"%s",endpoint);
  ev->type=EDR_EVENT_NET_CONNECT; ev->pid=42; ev->event_time_ns=1700000000000000000LL;
  ev->priority=0;
  strcpy(ev->cmdline,"synthetic-required-fact");
  strcpy(ev->exe_path,"synthetic-required-path");
  size_t raw_len=0;
  for (int i=0;i<(mixed?2:1);i++) {
    ev->has_behavior_alert=alert && i==0;
    if (ev->has_behavior_alert) {
      ev->behavior_alert.pid=42; ev->behavior_alert.timestamp_ns=ev->event_time_ns;
      ev->behavior_alert.anomaly_score=0.7f;
      snprintf(ev->behavior_alert.user_subject_json,sizeof(ev->behavior_alert.user_subject_json),
        "{\"subject_type\":\"detection_context\",\"evaluation_basis\":{"
        "\"schema\":\"agent_detection_basis_v1\",\"owner\":\"ave_behavior_pipeline\","
        "\"predicate_matched\":true,\"threshold_met\":true,\"pid\":42,"
        "\"timestamp_ns\":\"1700000000000000000\",\"threshold\":0.65,\"event_count\":1,"
        "\"behavior_flags\":1,\"last_event_type\":9},\"detection_context\":{"
        "\"engine\":\"ave\",\"rule_id\":\"behavior_anomaly\",\"confidence\":0.7,"
        "\"process\":{\"pid\":42},\"engine_signals\":{\"script_content_score\":0.7}}}");
    }
    pb_ostream_t output=pb_ostream_from_buffer(frame,65536);
    assert(pb_encode(&output,edr_v1_BehaviorEvent_fields,ev));
    wr(raw+raw_len,(uint32_t)output.bytes_written); memcpy(raw+raw_len+4,frame,output.bytes_written);
    raw_len+=output.bytes_written+4;
  }
  uint8_t *wire=malloc(raw_len+32); assert(wire);
  wr(wire,compressed?EDR_TRANSPORT_BATCH_MAGIC_LZ4:EDR_TRANSPORT_BATCH_MAGIC_RAW);
  wr(wire+4,mixed?2:1); wr(wire+8,(uint32_t)raw_len);
  if (compressed) {
    int n=LZ4_compress_default((const char *)raw,(char *)wire+12,(int)raw_len,(int)raw_len+20);
    assert(n>0); *len=(size_t)n+12;
  } else { memcpy(wire+12,raw,raw_len); *len=raw_len+12; }
  free(ev); free(frame); free(raw); return wire;
}
static sqlite3 *db_open(const char *path) {
  sqlite3 *db=NULL; assert(sqlite3_open(path,&db)==SQLITE_OK); return db;
}
static uint64_t sql_number(const char *path,const char *sql) {
  sqlite3 *db=db_open(path); sqlite3_stmt *st=NULL;
  assert(sqlite3_prepare_v2(db,sql,-1,&st,NULL)==SQLITE_OK);
  assert(sqlite3_step(st)==SQLITE_ROW); uint64_t n=(uint64_t)sqlite3_column_int64(st,0);
  sqlite3_finalize(st); sqlite3_close(db); return n;
}
static void sql_exec(const char *path,const char *sql) {
  sqlite3 *db=db_open(path); assert(sqlite3_exec(db,sql,NULL,NULL,NULL)==SQLITE_OK); sqlite3_close(db);
}
static void original_equal(const char *path,const char *id,const uint8_t *wire,size_t len) {
  sqlite3 *db=db_open(path); sqlite3_stmt *st=NULL;
  assert(sqlite3_prepare_v2(db,"SELECT payload FROM event_queue WHERE batch_id=?;",-1,&st,NULL)==SQLITE_OK);
  sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT); assert(sqlite3_step(st)==SQLITE_ROW);
  assert(sqlite3_column_bytes(st,0)==(int)len && !memcmp(sqlite3_column_blob(st,0),wire,len));
  sqlite3_finalize(st); sqlite3_close(db);
}
static void initialize(const char *path,const uint8_t *wire,size_t len,int remote) {
  remove(path); sends=0; receipt_mode=0;
  edr_storage_queue_configure(16,72); assert(edr_storage_queue_open(path)==EDR_OK);
  if (remote) {
    EdrStorageQueueP0SourceOnlyLatch owner;
    assert(edr_storage_queue_p0_source_only_latch_prepare(&owner)==EDR_OK);
    assert(edr_storage_queue_p0_source_only_enqueue_bound(&owner,"legacy-source","legacy-batch",wire,len,0,0)==EDR_OK);
  } else assert(edr_storage_queue_enqueue("legacy-batch",wire,len,0,0)==EDR_OK);
  edr_storage_queue_close(); assert(sends==0);
}
static EdrStorageQueueRecoveryRequest checked(const char *path,EdrStorageQueueRecoveryReport *report) {
  EdrStorageQueueRecoveryRequest request; memset(&request,0,sizeof(request));
  request.version=1; request.max_batches=32; request.target_owner_version=3;
  request.tenant_id="synthetic-tenant"; request.endpoint_id="synthetic-endpoint";
  assert(edr_storage_queue_recover_v1(path,&request,report)==EDR_OK);
  assert(!report->applied && strlen(report->inventory_sha256)==64);
  request.expected_owner=report->current_owner;
  memcpy(request.expected_inventory_sha256,report->inventory_sha256,65); request.apply=1;
  return request;
}
static void terminal_hold_and_independent_retry(void) {
  const int64_t retry_time = 1999999999;
  /* Pin retry eligibility across FULL commits and reopen; wall-clock seconds
   * can advance while the intent is supposed to remain in independent backoff. */
  edr_storage_queue_test_set_delivery_time(retry_time);
  char path[512]; test_path(path,sizeof(path),"real-terminal",0);
  EdrTestP0TerminalFixture f;
  assert(edr_test_p0_terminal_fixture_init(&f,1,"synthetic-tenant","synthetic-endpoint"));
  remove(path); edr_storage_queue_configure(16,72); assert(edr_storage_queue_open(path)==EDR_OK);
  char why[96],before_sha[65],after_sha[65];
  assert(!edr_egress_batch_validate(f.wire[0],12,f.wire[0]+12,f.length[0]-12,why,sizeof(why)));
  assert(!edr_egress_batch_validate(f.wire[2],12,f.wire[2]+12,f.length[2]-12,why,sizeof(why)));
  assert(edr_storage_queue_enforcement_terminal_precreate(f.terminal_key,f.source_event_id,f.rule_id,
      f.generation_key,"p0-intent",f.wire[0],f.length[0])==EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  /* The pre-action intent remains denied; its phase cannot establish an alert. */
  sends=0; receipt_mode=1; edr_storage_queue_poll_drain(); assert(sends==0);
  assert(sql_number(path,"SELECT intent_policy_held FROM enforcement_terminal_journal;")==1);
  assert(edr_storage_queue_enqueue("p0-intent",f.wire[0],f.length[0],0,1)==EDR_OK);
  edr_storage_queue_close(); assert(edr_storage_queue_open(path)==EDR_OK);
  edr_storage_queue_poll_drain(); assert(sends==0);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE batch_id='p0-intent' AND status='policy_held';")==1);
  edr_storage_queue_test_fail_next_terminal_commits(1);
  assert(edr_storage_queue_enforcement_terminal_update(f.terminal_key,"p0-source",f.wire[1],f.length[1],
      "p0-combined",f.wire[2],f.length[2])==EDR_ERR_SQLITE_WRITE);
  assert(!edr_egress_batch_validate(f.wire[0],12,f.wire[0]+12,f.length[0]-12,why,sizeof(why)));
  assert(sql_number(path,"SELECT COUNT(*) FROM enforcement_terminal_journal WHERE combined_wire IS NULL;")==1);
  assert(edr_storage_queue_enforcement_terminal_update(f.terminal_key,"p0-source",f.wire[1],f.length[1],
      "p0-combined",f.wire[2],f.length[2])==EDR_OK);
  assert(edr_egress_batch_validate(f.wire[0],12,f.wire[0]+12,f.length[0]-12,why,sizeof(why)));
  assert(edr_egress_batch_validate(f.wire[2],12,f.wire[2]+12,f.length[2]-12,why,sizeof(why)));
  /* Byte differences, even schema-valid event time differences, cannot use the owner. */
  EdrTestP0TerminalFixture foreign;
  assert(edr_test_p0_terminal_fixture_init(&foreign,2,"synthetic-tenant","synthetic-endpoint"));
  assert(!edr_egress_batch_validate(foreign.wire[0],12,foreign.wire[0]+12,foreign.length[0]-12,why,sizeof(why)));
  edr_test_p0_terminal_fixture_free(&foreign);
  edr_sha256_hex(f.wire[0],f.length[0],before_sha);
  edr_storage_queue_close(); assert(edr_storage_queue_open(path)==EDR_OK);
  /* Resetting a held bit must itself be FULL durable. Failure sends nothing. */
  edr_storage_queue_test_fail_next_terminal_commits(1); sends=0; edr_storage_queue_poll_drain();
  assert(sends==0 && sql_number(path,"SELECT intent_policy_held FROM enforcement_terminal_journal;")==1);
  assert(sql_number(path,"SELECT intent_acked FROM enforcement_terminal_journal;")==0);
  edr_storage_queue_close(); assert(edr_storage_queue_open(path)==EDR_OK);
  receipt_mode=2; sends=0; edr_storage_queue_poll_drain();
  assert(sends==1 && !strcmp(sent_id,"p0-intent")); /* Wrong actual-parser ACK cannot release intent. */
  assert(sql_number(path,"SELECT intent_acked FROM enforcement_terminal_journal;")==0);
  assert(sql_number(path,"SELECT intent_next_retry_at FROM enforcement_terminal_journal;")==
         (uint64_t)(retry_time+1));
  /* Intent's independent backoff permits combined-first confirmation. */
  edr_storage_queue_close(); assert(edr_storage_queue_open(path)==EDR_OK);
  receipt_mode=1; sends=0; edr_storage_queue_poll_drain();
  assert(sends==1 && !strcmp(sent_id,"p0-combined"));
  assert(sql_number(path,"SELECT source_policy_held FROM enforcement_terminal_journal;")==1);
  assert(sql_number(path,"SELECT source_acked FROM enforcement_terminal_journal;")==0);
  assert(sql_number(path,"SELECT combined_acked FROM enforcement_terminal_journal;")==1);
  assert(sql_number(path,"SELECT source_retry_count FROM enforcement_terminal_journal;")==0);
  EdrEnforcementTerminalJournalMetrics metrics;
  edr_storage_queue_enforcement_terminal_get_metrics(&metrics);
  assert(metrics.policy_held_frames==1 && metrics.pending==1 && metrics.local_retained==0);
  edr_storage_queue_close(); assert(edr_storage_queue_open(path)==EDR_OK);
  edr_storage_queue_test_set_delivery_time(retry_time+1); sends=0; edr_storage_queue_poll_drain();
  assert(sends==1 && !strcmp(sent_id,"p0-intent"));
  assert(sql_number(path,"SELECT intent_acked FROM enforcement_terminal_journal;")==1);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE batch_id='p0-intent';")==0);
  assert(sql_number(path,"SELECT source_acked FROM enforcement_terminal_journal;")==0);
  edr_storage_queue_enforcement_terminal_get_metrics(&metrics);
  assert(metrics.policy_held_frames==1 && metrics.pending==0 && metrics.local_retained==1);
  edr_sha256_hex(sent_wire,sent_len,after_sha); assert(!strcmp(before_sha,after_sha));
  edr_storage_queue_test_set_delivery_time(-1); edr_storage_queue_close();
  EdrStorageQueueRecoveryReport report; EdrStorageQueueRecoveryRequest request=checked(path,&report);
  assert(report.selected_batches==1); assert(edr_storage_queue_recover_v1(path,&request,&report)==EDR_OK);
  assert(report.resumed_terminal_frames==0); /* Still-denied original source is retained. */
  assert(edr_storage_queue_open(path)==EDR_OK); sends=0; edr_storage_queue_poll_drain(); assert(sends==0);
  assert(edr_storage_queue_enforcement_terminal_precreate(f.terminal_key,f.source_event_id,f.rule_id,
      f.generation_key,"p0-intent",f.wire[0],f.length[0])==EDR_ENFORCEMENT_TERMINAL_PRECREATE_EXISTING);
  edr_storage_queue_test_run_cleanup();
  assert(sql_number(path,"SELECT COUNT(*) FROM enforcement_terminal_journal WHERE state='local_retained';")==1);
  /* Retained evidence consumes bytes, without starving new action slots. */
  sql_exec(path,"WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1024) "
    "INSERT INTO enforcement_terminal_journal(idempotency_key,source_event_key,rule_id,process_generation_key,"
    "state,intent_batch_id,intent_wire,intent_acked,source_batch_id,source_wire,source_acked,combined_batch_id,combined_wire,"
    "combined_acked,source_policy_held,source_policy_reason,created_at,updated_at) "
    "SELECT 'retained-'||x,source_event_key,rule_id,process_generation_key,state,intent_batch_id,intent_wire,intent_acked,"
    "source_batch_id,source_wire,source_acked,combined_batch_id,combined_wire,combined_acked,source_policy_held,"
    "source_policy_reason,created_at,updated_at FROM enforcement_terminal_journal,n WHERE state='local_retained';");
  assert(edr_storage_queue_enforcement_terminal_precreate("next-action","next-source","rule", "next-generation",
      "next-intent",f.wire[0],f.length[0])==EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  EdrStorageQueueCapacityMetrics bytes; edr_storage_queue_get_capacity_metrics(&bytes);
  assert(bytes.used_bytes>1024*1024 && bytes.used_bytes<bytes.max_bytes);
  assert(sql_number(path,"SELECT COUNT(*) FROM enforcement_terminal_journal WHERE source_acked=0 AND combined_acked=1 AND intent_acked=1;")==1025);
  edr_storage_queue_close(); remove(path); edr_test_p0_terminal_fixture_free(&f);
}
static void historical_paired_alert_requires_original_intent_owner(void) {
  char path[512]; test_path(path,sizeof(path),"paired-history",0);
  EdrTestP0TerminalFixture f;
  assert(edr_test_p0_terminal_fixture_init(&f,3,"synthetic-tenant","synthetic-endpoint"));
  size_t ordinary_len; uint8_t *ordinary=make_wire(0,0,0,"synthetic-endpoint",&ordinary_len);
  size_t len=f.length[2]+ordinary_len-12; uint8_t *mixed=malloc(len); assert(mixed);
  memcpy(mixed,f.wire[2],f.length[2]); memcpy(mixed+f.length[2],ordinary+12,ordinary_len-12);
  wr(mixed+4,2); wr(mixed+8,(uint32_t)len-12);
  assert(edr_egress_batch_has_p0_combined(mixed,len)==1);
  initialize(path,mixed,len,1);
  EdrStorageQueueRecoveryReport report; EdrStorageQueueRecoveryRequest request=checked(path,&report);
  assert(report.retained_unresolved==1 && report.projected_batches==0);
  assert(edr_storage_queue_recover_v1(path,&request,&report)==EDR_OK);
  original_equal(path,"legacy-batch",mixed,len);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE recovery_state='retained_unresolved';")==1);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE origin_row_id>0;")==0);
  assert(edr_storage_queue_open(path)==EDR_OK); sends=0; receipt_mode=1;
  edr_storage_queue_poll_drain(); assert(sends==0);
  /* A complete authentic local owner later permits an explicit bounded
   * recheck. No action is rerun, no original ID/body is rewritten. */
  assert(edr_storage_queue_enforcement_terminal_precreate(f.terminal_key,f.source_event_id,f.rule_id,
      f.generation_key,"historical-intent",f.wire[0],f.length[0])==EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  assert(edr_storage_queue_enforcement_terminal_update(f.terminal_key,"historical-source",f.wire[1],f.length[1],
      "historical-combined",f.wire[2],f.length[2])==EDR_OK);
  edr_storage_queue_close(); request=checked(path,&report);
  assert(report.projected_batches==1 && report.retained_unresolved==0);
  assert(edr_storage_queue_recover_v1(path,&request,&report)==EDR_OK);
  original_equal(path,"legacy-batch",mixed,len);
  assert(edr_storage_queue_open(path)==EDR_OK); sends=0; receipt_mode=1;
  edr_storage_queue_poll_drain(); assert(sends==3); /* Intent, combined, fresh independent projection. */
  assert(sql_number(path,"SELECT intent_acked FROM enforcement_terminal_journal;")==1);
  assert(sql_number(path,"SELECT combined_acked FROM enforcement_terminal_journal;")==1);
  assert(sql_number(path,"SELECT source_acked FROM enforcement_terminal_journal;")==0);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE recovery_state='projection_acked';")==1);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE origin_row_id>0;")==0);
  original_equal(path,"legacy-batch",mixed,len);
  EdrStorageQueueCapacityMetrics metrics; edr_storage_queue_get_capacity_metrics(&metrics);
  assert(metrics.legacy_owner_unacknowledged==1);
  edr_storage_queue_close(); remove(path); free(mixed); free(ordinary); edr_test_p0_terminal_fixture_free(&f);
}
static void historical_known_outcome_missing_intent_receipt(void) {
  const char *states[]={"completed","local_retained"};
  for (unsigned shape=0;shape<2;shape++) {
    char path[512],sql[512]; test_path(path,sizeof(path),"old-intent-receipt",(int)shape);
    EdrTestP0TerminalFixture f;
    assert(edr_test_p0_terminal_fixture_init(&f,20+shape,"synthetic-tenant","synthetic-endpoint"));
    remove(path); assert(edr_storage_queue_open(path)==EDR_OK);
    assert(edr_storage_queue_enforcement_terminal_precreate(f.terminal_key,f.source_event_id,f.rule_id,
        f.generation_key,"old-intent",f.wire[0],f.length[0])==EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
    assert(edr_storage_queue_enforcement_terminal_update(f.terminal_key,"old-source",f.wire[1],f.length[1],
        "old-combined",f.wire[2],f.length[2])==EDR_OK);
    /* Model the exact historical metadata shape. These persisted receipt flags
     * are input evidence, never returned as new transport confirmation. */
    snprintf(sql,sizeof(sql),"UPDATE enforcement_terminal_journal SET state='%s',intent_acked=0,"
      "source_acked=%u,combined_acked=1,intent_policy_held=1,source_policy_held=%u,updated_at=1,created_at=1;",
      states[shape],shape?0:1,shape?1:0); sql_exec(path,sql);
    edr_storage_queue_close(); assert(edr_storage_queue_open(path)==EDR_OK);
    edr_storage_queue_test_run_cleanup();
    EdrEnforcementTerminalJournalMetrics metrics;
    edr_storage_queue_enforcement_terminal_get_metrics(&metrics); assert(metrics.pending==1);
    assert(sql_number(path,"SELECT COUNT(*) FROM enforcement_terminal_journal;")==1);
    receipt_mode=2; sends=0; edr_storage_queue_test_set_delivery_time(2000000000);
    edr_storage_queue_poll_drain(); assert(sends==1 && !strcmp(sent_id,"old-intent"));
    assert(sql_number(path,"SELECT intent_acked FROM enforcement_terminal_journal;")==0);
    edr_storage_queue_close(); assert(edr_storage_queue_open(path)==EDR_OK);
    receipt_mode=1; sends=0; edr_storage_queue_test_set_delivery_time(2000000002);
    /* The real parser accepts the receipt, but a storage commit failure still
     * leaves the original context unconfirmed and restart-replayable. */
    edr_storage_queue_test_fail_next_terminal_commits(1); edr_storage_queue_poll_drain();
    assert(sends==1 && sql_number(path,"SELECT intent_acked FROM enforcement_terminal_journal;")==0);
    edr_storage_queue_close(); assert(edr_storage_queue_open(path)==EDR_OK);
    sends=0; edr_storage_queue_poll_drain(); assert(sends==1 && !strcmp(sent_id,"old-intent"));
    assert(sql_number(path,"SELECT intent_acked FROM enforcement_terminal_journal;")==1);
    assert(sql_number(path,"SELECT source_acked FROM enforcement_terminal_journal;")==(shape?0:1));
    assert(sql_number(path,"SELECT combined_acked FROM enforcement_terminal_journal;")==1);
    snprintf(sql,sizeof(sql),"SELECT COUNT(*) FROM enforcement_terminal_journal WHERE state='%s';",states[shape]);
    assert(sql_number(path,sql)==1); /* Existing action state is never changed. */
    char original_sha[65],sent_sha[65]; edr_sha256_hex(f.wire[0],f.length[0],original_sha);
    edr_sha256_hex(sent_wire,sent_len,sent_sha); assert(!strcmp(original_sha,sent_sha));
    edr_storage_queue_enforcement_terminal_get_metrics(&metrics); assert(metrics.pending==0);
    edr_storage_queue_test_set_delivery_time(-1); edr_storage_queue_close(); remove(path);
    edr_test_p0_terminal_fixture_free(&f);
  }
  /* A historical completion label with corrupt pair provenance stays local;
   * it is not permission to reconstruct intent, change action state or ACK. */
  char path[512]; test_path(path,sizeof(path),"old-intent-unavailable",0);
  EdrTestP0TerminalFixture f;
  assert(edr_test_p0_terminal_fixture_init(&f,30,"synthetic-tenant","synthetic-endpoint"));
  remove(path); assert(edr_storage_queue_open(path)==EDR_OK);
  assert(edr_storage_queue_enforcement_terminal_precreate(f.terminal_key,f.source_event_id,f.rule_id,
      f.generation_key,"unavailable-intent",f.wire[0],f.length[0])==EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  assert(edr_storage_queue_enforcement_terminal_update(f.terminal_key,"unavailable-source",f.wire[1],f.length[1],
      "unavailable-combined",f.wire[2],f.length[2])==EDR_OK);
  sql_exec(path,"UPDATE enforcement_terminal_journal SET state='completed',intent_acked=0,"
    "source_acked=1,combined_acked=1,combined_wire=zeroblob(16),created_at=1,updated_at=1;");
  edr_storage_queue_close(); assert(edr_storage_queue_open(path)==EDR_OK);
  sends=0; receipt_mode=1; edr_storage_queue_poll_drain(); assert(sends==0);
  assert(sql_number(path,"SELECT intent_policy_held FROM enforcement_terminal_journal;")==1);
  assert(sql_number(path,"SELECT intent_acked FROM enforcement_terminal_journal;")==0);
  assert(sql_number(path,"SELECT COUNT(*) FROM enforcement_terminal_journal WHERE state='completed';")==1);
  edr_storage_queue_test_run_cleanup();
  assert(sql_number(path,"SELECT COUNT(*) FROM enforcement_terminal_journal;")==1);
  edr_storage_queue_close(); remove(path); edr_test_p0_terminal_fixture_free(&f);
}
static void historic_projection_and_receipt(int compressed) {
  char path[512]; test_path(path,sizeof(path),"real-recover",compressed);
  size_t len; uint8_t *wire=make_wire(1,1,compressed,"synthetic-endpoint",&len);
  initialize(path,wire,len,1);
  uint64_t owner_before=sql_number(path,"SELECT source_latch_owner FROM queue_meta;");
  char before_sha[65],after_sha[65]; file_sha(path,before_sha);
  EdrStorageQueueRecoveryReport report; EdrStorageQueueRecoveryRequest request=checked(path,&report);
  file_sha(path,after_sha); assert(!strcmp(before_sha,after_sha));
  assert(owner_before==2 && sql_number(path,"SELECT source_latch_owner FROM queue_meta;")==2);
  assert(report.projected_batches==1 && report.selected_batches==1 && sends==0);
  EdrStorageQueueRecoveryRequest stale=request; stale.expected_owner.latch_epoch++;
  assert(edr_storage_queue_recover_v1(path,&stale,&report)==EDR_ERR_INVALID_ARG);
  assert(sql_number(path,"SELECT source_latch_owner FROM queue_meta;")==2);
  assert(edr_storage_queue_recover_v1(path,&request,&report)==EDR_OK && report.applied);
  assert(report.current_owner.owner_version==3 && report.current_owner.recovery_required);
  assert(report.legacy_owner_unacknowledged==1);
  original_equal(path,"legacy-batch",wire,len);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue;")==2);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE recovery_state='projection_pending';")==1);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE projector_version='" EDR_EGRESS_PROJECTOR_VERSION "';")==1);
  assert(edr_storage_queue_recover_v1(path,&request,&report)==EDR_OK && report.applied);
  assert(strstr(report.reason,"already_committed"));
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue;")==2);
  /* A genuine linked alert remains replayable for service lifetime across
   * ordinary TTL/retry limits. No local cleanup can become a remote ACK. */
  sql_exec(path,"UPDATE event_queue SET created_at=1,retry_count=1000,next_retry_at=0 WHERE origin_row_id>0;");
  assert(edr_storage_queue_open(path)==EDR_OK); edr_storage_queue_test_run_cleanup();
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE origin_row_id>0 AND status='pending';")==1);
  sends=0; receipt_mode=0; edr_storage_queue_poll_drain(); assert(sends==1);
  assert(sql_number(path,"SELECT retry_count FROM event_queue WHERE origin_row_id>0;")==1001);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE recovery_state='projection_acked';")==0);
  char projected_id[128],projected_sha[65];
  snprintf(projected_id,sizeof(projected_id),"%s",sent_id); edr_sha256_hex(sent_wire,sent_len,projected_sha);
  edr_storage_queue_close();
  sql_exec(path,"UPDATE event_queue SET status='policy_held',terminal_reason='synthetic_proof_unavailable' "
    "WHERE origin_row_id>0;");
  request=checked(path,&report); assert(report.selected_batches==1 && report.projected_batches==0);
  EdrStorageQueueRecoveryRequest foreign=request; foreign.apply=0; foreign.endpoint_id="foreign-endpoint";
  assert(edr_storage_queue_recover_v1(path,&foreign,&report)==EDR_ERR_INVALID_ARG);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE origin_row_id>0 AND status='policy_held';")==1);
  assert(edr_storage_queue_recover_v1(path,&request,&report)==EDR_OK && report.resumed_projections==1);
  assert(sql_number(path,"SELECT retry_count FROM event_queue WHERE origin_row_id>0;")==1001);
  assert(edr_storage_queue_open(path)==EDR_OK);
  EdrStorageQueueCapacityMetrics capacity; edr_storage_queue_get_capacity_metrics(&capacity);
  assert(capacity.legacy_owner_unacknowledged==1 && capacity.projection_pending_rows==1);
  sends=0; receipt_mode=2; edr_storage_queue_poll_drain(); assert(sends==1);
  char resumed_sha[65]; edr_sha256_hex(sent_wire,sent_len,resumed_sha);
  assert(!strcmp(projected_id,sent_id) && !strcmp(projected_sha,resumed_sha));
  assert(strcmp(sent_id,"legacy-batch") && sql_number(path,"SELECT COUNT(*) FROM event_queue;")==2);
  assert(edr_storage_queue_batch_presence(sent_id,sent_wire,sent_len)==1);
  edr_storage_queue_close(); sql_exec(path,"UPDATE event_queue SET next_retry_at=0 WHERE origin_row_id>0;");
  assert(edr_storage_queue_open(path)==EDR_OK); sends=0; receipt_mode=1;
  edr_storage_queue_poll_drain(); assert(sends==1);
  assert(rd(sent_wire+4)==1 && rd(sent_wire+8)==sent_len-12);
  edr_v1_BehaviorEvent *sent=calloc(1,sizeof(*sent)); assert(sent);
  pb_istream_t in=pb_istream_from_buffer(sent_wire+16,rd(sent_wire+12));
  assert(pb_decode(&in,edr_v1_BehaviorEvent_fields,sent));
  assert(sent->has_behavior_alert && sent->pid==42 && !sent->cmdline[0]);
  assert(!strcmp(sent->exe_path,"synthetic-required-path") &&
    strstr(sent->behavior_alert.user_subject_json,"ave_behavior_pipeline") &&
    strstr(sent->behavior_alert.user_subject_json,"script_content_score"));
  free(sent);
  assert(edr_storage_queue_batch_presence(sent_id,sent_wire,sent_len)==0);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue;")==1);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE recovery_state='projection_acked';")==1);
  assert(sql_number(path,"SELECT source_latch_owner FROM queue_meta;")==3);
  assert(sql_number(path,"SELECT source_latch_loss_detected FROM queue_meta;")==1);
  original_equal(path,"legacy-batch",wire,len);
  /* Only a NEW explicit local audit, not the projection's receipt, resolves
   * current-v3 durability loss. The production P0 owner additionally requires
   * healthy authenticated IR and its FULL probe before invoking this. */
  EdrStorageQueueP0SourceOnlyLatch current;
  size_t audit_len; uint8_t *audit=make_wire(0,0,0,"synthetic-endpoint",&audit_len);
  assert(edr_storage_queue_p0_source_only_latch_get(&current)==EDR_OK && current.recovery_required);
  assert(edr_storage_queue_p0_source_only_commit_local(&current,"new-audit","local-audit",audit,audit_len,0,0)==EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_is_set());
  assert(edr_storage_queue_p0_source_only_recovery_probe()==EDR_OK);
  assert(edr_storage_queue_p0_source_only_commit_local(&current,"new-audit","local-audit",audit,audit_len,0,1)==EDR_OK);
  assert(!edr_storage_queue_p0_source_only_latch_is_set());
  assert(sql_number(path,"SELECT length(legacy_lineage)>0 FROM queue_meta;")==1);
  edr_storage_queue_close(); remove(path); free(wire); free(audit);
}
static int resource_authority_available=1;
static int resource_projection_owner(const char *rule,const char *sha,uint64_t mask,const char *operation,void *user) {
  (void)user;
  if(!resource_authority_available)return -1;
  return !strcmp(rule,"resource-rule") && !strcmp(sha,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") &&
    mask==EDR_EVIDENCE_COMMAND && !operation[0];
}
static uint8_t *resource_projection_wire(size_t *len) {
  size_t old_len;uint8_t *old=make_wire(1,0,0,"synthetic-endpoint",&old_len);
  edr_v1_BehaviorEvent *ev=calloc(1,sizeof(*ev));uint8_t *wire=malloc(65536);assert(ev&&wire);
  pb_istream_t input=pb_istream_from_buffer(old+16,rd(old+12));
  assert(pb_decode(&input,edr_v1_BehaviorEvent_fields,ev));
  ev->evidence_projection_version=EDR_EVIDENCE_PROJECTION_VERSION;
  ev->required_evidence_fields=EDR_EVIDENCE_COMMAND;
  ev->has_tactic_probs_computed=true;ev->tactic_probs_computed=false;
  snprintf(ev->behavior_alert.user_subject_json,sizeof(ev->behavior_alert.user_subject_json),
    "{\"subject_type\":\"edr_dynamic_rule\",\"rule_id\":\"resource-rule\","
    "\"rules_bundle_version\":\"resource-bundle\",\"rules_bundle_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
    "\"context\":{\"pid\":42,\"event_type\":%d,\"source_event_id\":\"synthetic-source\","
    "\"endpoint_id\":\"synthetic-endpoint\",\"tenant_id\":\"synthetic-tenant\"}}",(int)ev->type);
  char why[96];assert(edr_egress_event_project(ev,why,sizeof(why)));
  pb_ostream_t output=pb_ostream_from_buffer(wire+16,65520);
  assert(pb_encode(&output,edr_v1_BehaviorEvent_fields,ev));
  wr(wire,EDR_TRANSPORT_BATCH_MAGIC_RAW);wr(wire+4,1);wr(wire+8,(uint32_t)output.bytes_written+4);wr(wire+12,(uint32_t)output.bytes_written);
  *len=output.bytes_written+16;
  assert(edr_egress_batch_validate(wire,12,wire+12,*len-12,why,sizeof(why)));
  free(old);free(ev);return wire;
}
static void resource_preflight_defers_original_bytes(void) {
  edr_egress_set_rule_projection_validator(resource_projection_owner,NULL);
  for(unsigned kind=0;kind<2;kind++) {
    char path[512];test_path(path,sizeof(path),"resource-preflight",(int)kind);
    size_t len;uint8_t *wire=resource_projection_wire(&len);
    initialize(path,wire,len,0);assert(edr_storage_queue_open(path)==EDR_OK);
    EdrStorageQueueCapacityMetrics before,after;
    edr_storage_queue_get_capacity_metrics(&before);sends=0;receipt_mode=1;
    if(kind==0)resource_authority_available=0;
    for(unsigned i=0;i<3;i++) {
      if(kind==1)edr_storage_queue_test_fail_egress_allocation(1);
      edr_storage_queue_poll_drain();assert(sends==0);
      assert(sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE batch_id='legacy-batch' AND status='pending' AND retry_count=0 AND next_retry_at=0;")==1);
      assert(sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE status IN ('policy_held','dead_letter');")==0);
      original_equal(path,"legacy-batch",wire,len);
      /* Reopen starts a new drain generation without sleeping through the
       * production minimum 200ms poll throttle or altering durable metadata. */
      if(i<2){edr_storage_queue_close();assert(edr_storage_queue_open(path)==EDR_OK);}
    }
    edr_storage_queue_get_capacity_metrics(&after);
    assert(after.delivery_resource_deferred==before.delivery_resource_deferred+3);
    assert(after.delivery_sent==before.delivery_sent && after.delivery_failed==before.delivery_failed);
    edr_storage_queue_close();assert(edr_storage_queue_open(path)==EDR_OK);
    if(kind==1)edr_storage_queue_test_fail_egress_allocation(1);
    edr_storage_queue_poll_drain();assert(sends==0);
    original_equal(path,"legacy-batch",wire,len);
    assert(sql_number(path,"SELECT retry_count FROM event_queue WHERE batch_id='legacy-batch';")==0);
    resource_authority_available=1;
    edr_storage_queue_close();assert(edr_storage_queue_open(path)==EDR_OK);
    edr_storage_queue_poll_drain();assert(sends==1);
    assert(!strcmp(sent_id,"legacy-batch") && sent_len==len && !memcmp(sent_wire,wire,len));
    assert(edr_storage_queue_batch_presence("legacy-batch",wire,len)==0);
    assert(sql_number(path,"SELECT COUNT(*) FROM event_queue;")==0);
    edr_storage_queue_close();remove(path);free(wire);
  }
  edr_egress_set_rule_projection_validator(NULL,NULL);
  puts("queue preflight resource failures: no hold/retry mutation across reopen; exact original bytes ACKed after recovery");
}
static void server_policy_hold_retains_lineage(void) {
  char path[512]; test_path(path,sizeof(path),"server-policy-hold",0);
  size_t len; uint8_t *wire=make_wire(1,1,0,"synthetic-endpoint",&len);
  initialize(path,wire,len,1);
  EdrStorageQueueRecoveryReport report; EdrStorageQueueRecoveryRequest request=checked(path,&report);
  assert(edr_storage_queue_recover_v1(path,&request,&report)==EDR_OK);
  assert(edr_storage_queue_open(path)==EDR_OK); sends=0;receipt_mode=3;
  edr_storage_queue_poll_drain();assert(sends==1);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE origin_row_id>0 AND status='policy_held' AND terminal_reason='server_evidence_projection_unproven' AND retry_count=0;")==1);
  assert(sql_number(path,"SELECT COUNT(*) FROM queue_projection_relations WHERE receipt_state='acked';")==0);
  assert(sql_number(path,"SELECT source_latch_loss_detected FROM queue_meta;")==1);
  original_equal(path,"legacy-batch",wire,len);original_equal(path,sent_id,sent_wire,sent_len);
  for (unsigned i=0;i<3;i++) edr_storage_queue_poll_drain();assert(sends==1);
  edr_storage_queue_close();assert(edr_storage_queue_open(path)==EDR_OK);
  receipt_mode=1;edr_storage_queue_poll_drain();assert(sends==1);
  original_equal(path,"legacy-batch",wire,len);original_equal(path,sent_id,sent_wire,sent_len);
  assert(sql_number(path,"SELECT COUNT(*) FROM queue_projection_relations WHERE receipt_state='pending';")==1);
  edr_storage_queue_close();remove(path);free(wire);
}
/* Storage relation migration fixture. Both children contain already eligible
 * wire; this tests relation/receipt versions, not old sensor semantics. Actual
 * legacy frame minimization is exercised above through the production codec. */
static void multiversion_projection_receipts(int newest_first) {
  char path[512]; test_path(path,sizeof(path),"projection-versions",newest_first);
  size_t len; uint8_t *wire=make_wire(1,1,0,"synthetic-endpoint",&len);
  initialize(path,wire,len,1);
  EdrStorageQueueRecoveryReport report; EdrStorageQueueRecoveryRequest request=checked(path,&report);
  assert(edr_storage_queue_recover_v1(path,&request,&report)==EDR_OK);
  /* Shape of a 612 database: only its original pointer and existing child.
   * Never change either payload. A startup migration must preserve the pair. */
  sql_exec(path,"UPDATE event_queue SET batch_id='legacy-v1-child' WHERE origin_row_id>0;"
    "UPDATE event_queue SET projector_version='alert-fields-v1',projection_batch_id='legacy-v1-child' "
    "WHERE origin_row_id=0; DROP TABLE queue_projection_relations;");
  char old_sha[65],after_sha[65]; file_sha(path,old_sha);
  request=checked(path,&report);
  assert(report.projected_batches==1);
  file_sha(path,after_sha); assert(!strcmp(old_sha,after_sha));
  assert(edr_storage_queue_recover_v1(path,&request,&report)==EDR_OK);
  assert(sql_number(path,"SELECT COUNT(*) FROM queue_projection_relations;")==2);
  assert(sql_number(path,"SELECT COUNT(*) FROM queue_projection_relations WHERE receipt_state='pending';")==2);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE projection_batch_id='legacy-v1-child' "
    "AND projector_version='alert-fields-v1';")==1);
  original_equal(path,"legacy-batch",wire,len);
  /* Restart preserves both relations. Wrong ACK acknowledges neither. */
  assert(edr_storage_queue_open(path)==EDR_OK); sends=0;receipt_mode=2;
  edr_storage_queue_poll_drain();assert(sends>=1);
  assert(sql_number(path,"SELECT COUNT(*) FROM queue_projection_relations WHERE receipt_state='acked';")==0);
  edr_storage_queue_close();
  sql_exec(path,newest_first ?
    "UPDATE event_queue SET next_retry_at=CASE WHEN batch_id='legacy-v1-child' THEN CAST(strftime('%s','now') AS INTEGER)+120 ELSE 0 END WHERE origin_row_id>0;" :
    "UPDATE event_queue SET next_retry_at=CASE WHEN batch_id='legacy-v1-child' THEN 0 ELSE CAST(strftime('%s','now') AS INTEGER)+120 END WHERE origin_row_id>0;");
  assert(edr_storage_queue_open(path)==EDR_OK); sends=0;receipt_mode=1;
  edr_storage_queue_poll_drain();assert(sends==1);
  assert(sql_number(path,"SELECT COUNT(*) FROM queue_projection_relations WHERE receipt_state='acked';")==1);
  assert(sql_number(path,"SELECT COUNT(*) FROM queue_projection_relations WHERE receipt_state='pending';")==1);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE recovery_state='projection_acked';")==!newest_first);
  edr_storage_queue_close();
  sql_exec(path,"UPDATE event_queue SET next_retry_at=0 WHERE origin_row_id>0;");
  assert(edr_storage_queue_open(path)==EDR_OK); sends=0;
  edr_storage_queue_poll_drain();assert(sends==1);
  assert(sql_number(path,"SELECT COUNT(*) FROM queue_projection_relations WHERE receipt_state='acked';")==2);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue;")==1);
  assert(sql_number(path,"SELECT source_latch_loss_detected FROM queue_meta;")==1);
  original_equal(path,"legacy-batch",wire,len);
  edr_storage_queue_close();
  request=checked(path,&report);assert(report.selected_batches==0);
  assert(edr_storage_queue_open(path)==EDR_OK);sends=0;edr_storage_queue_poll_drain();assert(sends==0);
  edr_storage_queue_close();remove(path);free(wire);
}
static void unresolved_foreign_capacity(void) {
  char path[512]; test_path(path,sizeof(path),"real-unresolved",0);
  size_t len; uint8_t *wire=make_wire(0,0,0,"synthetic-endpoint",&len);
  wr(wire,0x01020304); initialize(path,wire,len,1);
  EdrStorageQueueRecoveryReport report; EdrStorageQueueRecoveryRequest request=checked(path,&report);
  assert(report.retained_unresolved==1);
  assert(edr_storage_queue_recover_v1(path,&request,&report)==EDR_OK);
  assert(report.current_owner.owner_version==3 && report.current_owner.recovery_required);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE recovery_state='retained_unresolved';")==1);
  original_equal(path,"legacy-batch",wire,len);
  assert(edr_storage_queue_open(path)==EDR_OK);
  EdrStorageQueueCapacityMetrics before_bytes,after_bytes;
  edr_storage_queue_get_capacity_metrics(&before_bytes); edr_storage_queue_close();
  request=checked(path,&report); /* Versioned unresolved rows can be rechecked. */
  assert(report.selected_batches==1 && report.retained_unresolved==1);
  assert(edr_storage_queue_recover_v1(path,&request,&report)==EDR_OK);
  assert(edr_storage_queue_open(path)==EDR_OK);
  edr_storage_queue_get_capacity_metrics(&after_bytes);
  assert(before_bytes.used_bytes==after_bytes.used_bytes); /* No double overhead. */
  size_t next_len; uint8_t *next=make_wire(0,0,0,"synthetic-endpoint",&next_len);
  assert(edr_storage_queue_enqueue("later-normal",next,next_len,0,0)==EDR_OK); edr_storage_queue_close();
  request=checked(path,&report); request.apply=0; request.after_row_id=1; request.max_batches=1;
  assert(edr_storage_queue_recover_v1(path,&request,&report)==EDR_OK);
  assert(report.last_event_row_id==2 && report.selected_batches==1 && report.retained_unresolved==0);
  request.expected_owner=report.current_owner; memcpy(request.expected_inventory_sha256,report.inventory_sha256,65);
  request.apply=1; assert(edr_storage_queue_recover_v1(path,&request,&report)==EDR_OK);
  original_equal(path,"legacy-batch",wire,len); original_equal(path,"later-normal",next,next_len);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE recovery_state='local_only';")==1);
  /* Recheck rejects stored original SHA corruption without replacing it. */
  sql_exec(path,"UPDATE event_queue SET original_sha256=printf('%064d',1) WHERE batch_id='legacy-batch';");
  request.apply=0; request.after_row_id=0;
  assert(edr_storage_queue_recover_v1(path,&request,&report)!=EDR_OK);
  original_equal(path,"legacy-batch",wire,len); free(next);
  free(wire); wire=make_wire(1,1,0,"foreign-endpoint",&len); initialize(path,wire,len,1);
  memset(&request,0,sizeof(request)); request.version=1; request.max_batches=32;
  request.tenant_id="synthetic-tenant"; request.endpoint_id="synthetic-endpoint";
  assert(edr_storage_queue_recover_v1(path,&request,&report)==EDR_ERR_INVALID_ARG);
  assert(sql_number(path,"SELECT source_latch_owner FROM queue_meta;")==2);
  assert(sql_number(path,"SELECT length(legacy_lineage) FROM queue_meta;")==0);
  free(wire); wire=make_wire(1,1,0,"synthetic-endpoint",&len); initialize(path,wire,len,1);
  request=checked(path,&report);
  /* Logical capacity admission includes original+projection+fixed lineage;
   * exceeding the new cap leaves every original byte and owner unchanged. */
  sql_exec(path,"UPDATE event_queue SET payload=CAST(payload||zeroblob(1048576) AS BLOB);");
  request=checked(path,&report); edr_storage_queue_configure(1,72);
  assert(edr_storage_queue_recover_v1(path,&request,&report)==EDR_ERR_QUEUE_FULL);
  assert(sql_number(path,"SELECT source_latch_owner FROM queue_meta;")==2);
  assert(sql_number(path,"SELECT length(legacy_lineage) FROM queue_meta;")==0);
  edr_storage_queue_configure(16,72); remove(path); free(wire);
}
static void process_crash_boundaries(void) {
  for (int phase=1;phase<=3;phase++) {
    char path[512]; test_path(path,sizeof(path),"recovery-crash",phase);
    size_t len; uint8_t *wire=make_wire(1,1,0,"synthetic-endpoint",&len); initialize(path,wire,len,1);
    EdrStorageQueueRecoveryReport report; EdrStorageQueueRecoveryRequest request=checked(path,&report);
#ifdef _WIN32
    char executable[MAX_PATH],command[1600];
    DWORD n=GetModuleFileNameA(NULL,executable,sizeof(executable));
    assert(n>0 && n<sizeof(executable));
    int used=snprintf(command,sizeof(command),"\"%s\" --crash-child %d \"%s\"",executable,phase,path);
    assert(used>0 && (size_t)used<sizeof(command));
    STARTUPINFOA start; PROCESS_INFORMATION child; memset(&start,0,sizeof(start));
    memset(&child,0,sizeof(child)); start.cb=sizeof(start);
    assert(CreateProcessA(NULL,command,NULL,NULL,FALSE,0,NULL,NULL,&start,&child));
    DWORD waited=WaitForSingleObject(child.hProcess,60000);
    if (waited!=WAIT_OBJECT_0) TerminateProcess(child.hProcess,96);
    assert(waited==WAIT_OBJECT_0); DWORD exit_code=0;
    assert(GetExitCodeProcess(child.hProcess,&exit_code) && exit_code==95);
    CloseHandle(child.hThread); CloseHandle(child.hProcess);
#else
    pid_t child=fork(); assert(child>=0);
    if (!child) {
      alarm(30);
      edr_storage_queue_test_stop_recovery_phase(phase);
      (void)edr_storage_queue_recover_v1(path,&request,&report); _exit(90);
    }
    int status; assert(waitpid(child,&status,WUNTRACED)==child && WIFSTOPPED(status));
    assert(kill(child,SIGKILL)==0); assert(waitpid(child,&status,0)==child && WIFSIGNALED(status));
#endif
    original_equal(path,"legacy-batch",wire,len);
    assert(sql_number(path,"SELECT source_latch_owner FROM queue_meta;")==(phase==3?3u:2u));
    assert(sql_number(path,"SELECT COUNT(*) FROM event_queue;")==(phase==3?2u:1u));
    assert(sql_number(path,"SELECT length(legacy_lineage)>0 FROM queue_meta;")==(phase==3?1u:0u));
    assert(edr_storage_queue_recover_v1(path,&request,&report)==EDR_OK);
    assert(sql_number(path,"SELECT COUNT(*) FROM event_queue;")==2);
    assert(report.applied && report.current_owner.recovery_required && sends==0);
    remove(path); free(wire);
  }
}
int main(int argc,char **argv) {
  if (argc==4 && !strcmp(argv[1],"--crash-child")) {
    EdrStorageQueueRecoveryReport report;
    EdrStorageQueueRecoveryRequest request=checked(argv[3],&report);
    edr_storage_queue_test_stop_recovery_phase(atoi(argv[2]));
    (void)edr_storage_queue_recover_v1(argv[3],&request,&report); return 90;
  }
#ifndef _WIN32
  assert(setenv("EDR_QUEUE_DRAIN_INTERVAL_MS","0",1)==0);
#else
  assert(_putenv_s("EDR_QUEUE_DRAIN_INTERVAL_MS","0")==0);
#endif
  terminal_hold_and_independent_retry();
  historical_paired_alert_requires_original_intent_owner();
  historical_known_outcome_missing_intent_receipt();
  historic_projection_and_receipt(0); historic_projection_and_receipt(1);
  resource_preflight_defers_original_bytes();
  server_policy_hold_retains_lineage();
  multiversion_projection_receipts(0); multiversion_projection_receipts(1);
  unresolved_foreign_capacity();
  process_crash_boundaries();
  puts("queue recovery: real codecs, immutable lineage, independent receipts, FULL rollback/restart passed");
  return 0;
}
