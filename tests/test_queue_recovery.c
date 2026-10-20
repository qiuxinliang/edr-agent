#include "edr/storage_queue.h"
#include "edr/behavior_proto.h"
#include "edr/behavior_record.h"
#include "edr/ave_sdk.h"
#include "edr/event_batch.h"
#include "edr/process_generation.h"
#include <stdatomic.h>
#include <time.h>
#include "edr/egress_batch_policy.h"
#include "edr/evidence_projection.h"
#include "edr/report_events_ack.h"
#include "edr/transport_sink.h"
#include "edr/sha256.h"
#include "edr/types.h"
#include "edr/time_util.h"
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
#include <pthread.h>
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
static int load_active;
static int load_transport(const char *,const uint8_t *,size_t,const uint8_t *,size_t);
int edr_ingest_http_configured(void) { return 1; }
int edr_ingest_http_circuit_open(void) { return 0; }
int edr_ingest_http_telemetry_deferred(void) { return 0; }
int edr_transport_v2_report_events(const char *id,const uint8_t *header,size_t hlen,
    const uint8_t *payload,size_t plen) {
  if(load_active)return load_transport(id,header,hlen,payload,plen);
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
  uint64_t retention_class_before=sql_number(path,
      "SELECT retention_class FROM event_queue WHERE batch_id='legacy-batch';");
  uint64_t retention_policy_before=sql_number(path,
      "SELECT retention_policy_version FROM event_queue WHERE batch_id='legacy-batch';");
  assert(retention_class_before==2 && retention_policy_before==1);
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
  assert(sql_number(path,"SELECT retention_class FROM event_queue WHERE batch_id='legacy-batch';")==retention_class_before);
  assert(sql_number(path,"SELECT retention_policy_version FROM event_queue WHERE batch_id='legacy-batch';")==retention_policy_before);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE origin_row_id>0 AND retention_class=3 "
      "AND retention_policy_version=1 AND local_retention_state='retained';")==1);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE recovery_state='projection_pending';")==1);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE projector_version='" EDR_EGRESS_PROJECTOR_VERSION "';")==1);
  assert(edr_storage_queue_recover_v1(path,&request,&report)==EDR_OK && report.applied);
  assert(strstr(report.reason,"already_committed"));
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue;")==2);
  EdrStorageQueueRecoveryRequest pending_again=checked(path,&report);
  assert(report.selected_batches==0 && report.projected_batches==0);
  assert(edr_storage_queue_recover_v1(path,&pending_again,&report)==EDR_OK);
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
  assert(capacity.accounting_available && capacity.retention_delivery_rows==1 && capacity.retention_recovery_rows==1);
  uint64_t retained_original_bytes=capacity.retention_delivery_bytes;
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
  /* The projection's real parsed receipt releases its own delivery owner.
   * It neither changes the original creation class nor retires original bytes. */
  assert(sql_number(path,"SELECT retention_class FROM event_queue WHERE batch_id='legacy-batch';")==retention_class_before);
  assert(sql_number(path,"SELECT retention_policy_version FROM event_queue WHERE batch_id='legacy-batch';")==retention_policy_before);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE batch_id='legacy-batch' "
      "AND local_retention_state='retained';")==1);
  edr_storage_queue_get_capacity_metrics(&capacity);
  assert(capacity.accounting_available && capacity.retention_recovery_rows==0 && capacity.retention_delivery_rows==1);
  assert(capacity.retention_delivery_bytes==retained_original_bytes);
  assert(capacity.projection_acked_rows==1 && capacity.projection_pending_rows==0);
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
/* A retained receipt is not a request to deliver the same fact using a newer
 * projector. Cover a legacy acknowledged row and both shapes of v1 receipts. */
static void acknowledged_history_is_not_redelivered(int shape) {
  char path[512]; test_path(path,sizeof(path),"acked-history",shape);
  size_t len; uint8_t *wire=make_wire(1,1,0,"synthetic-endpoint",&len);
  initialize(path,wire,len,1);
  EdrStorageQueueRecoveryReport report; EdrStorageQueueRecoveryRequest request;
  if (shape==0) {
    /* Legacy state fixture: retained original marked ACKed, no child receipt. */
    sql_exec(path,"UPDATE event_queue SET status='acked' WHERE batch_id='legacy-batch';");
  } else {
    request=checked(path,&report);
    assert(edr_storage_queue_recover_v1(path,&request,&report)==EDR_OK);
    assert(edr_storage_queue_open(path)==EDR_OK); sends=0;receipt_mode=1;
    edr_storage_queue_poll_drain();assert(sends==1);
    edr_storage_queue_close();
    assert(sql_number(path,"SELECT COUNT(*) FROM event_queue;")==1);
    assert(sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE recovery_state='projection_acked';")==1);
    sql_exec(path,"UPDATE event_queue SET projector_version='alert-fields-v1' WHERE origin_row_id=0;"
      "UPDATE queue_projection_relations SET projector_version='alert-fields-v1';");
    if (shape==1) sql_exec(path,"DROP TABLE queue_projection_relations;");
  }
  char before_sha[65],after_sha[65];file_sha(path,before_sha);
  request=checked(path,&report);file_sha(path,after_sha);
  assert(!strcmp(before_sha,after_sha));
  assert(report.selected_batches==0 && report.projected_batches==0);
  assert(edr_storage_queue_recover_v1(path,&request,&report)==EDR_OK);
  assert(report.projected_batches==0 && report.resumed_projections==0);
  original_equal(path,"legacy-batch",wire,len);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue;")==1);
  assert(sql_number(path,"SELECT source_latch_loss_detected FROM queue_meta;")==1);
  assert(edr_storage_queue_recover_v1(path,&request,&report)==EDR_OK);
  assert(edr_storage_queue_open(path)==EDR_OK);sends=0;receipt_mode=1;
  edr_storage_queue_poll_drain();assert(sends==0);
  edr_storage_queue_close();
  request=checked(path,&report);assert(report.selected_batches==0);
  original_equal(path,"legacy-batch",wire,len);
  remove(path);free(wire);
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
static void typed_local_real_codec(int compressed) {
  char path[512],reason[96];test_path(path,sizeof(path),"typed-local-codec",compressed);remove(path);
  edr_v1_BehaviorEvent *event=calloc(1,sizeof(*event)),*decoded=calloc(1,sizeof(*decoded));
  uint8_t *frame=malloc(EDR_EGRESS_FRAME_MAX),*raw=malloc(EDR_EGRESS_FRAME_MAX+4u);
  uint8_t *wire=malloc(EDR_EGRESS_FRAME_MAX+64u);assert(event && decoded && frame && raw && wire);
  strcpy(event->event_id,"typed-real-source");strcpy(event->endpoint_id,"synthetic-endpoint");
  strcpy(event->tenant_id,"synthetic-tenant");event->type=EDR_EVENT_PROCESS_CREATE;
  event->event_time_ns=INT64_C(1700000000000000000);event->pid=42u;event->ppid=4u;
  event->process_start_key=UINT64_MAX;event->process_creation_filetime_100ns=UINT64_C(133444444444444444);
  event->has_parent_pid_state=true;event->parent_pid_state=1u;
  strcpy(event->parent_name,"ordinary-parent");strcpy(event->parent_path,"synthetic-parent-path");
  event->has_process_context=true;event->process_context.has_parent_cmdline=true;
  strcpy(event->process_context.parent_cmdline,"ordinary-parent --necessary-local-context");
  memset(event->cmdline,'x',90000u);event->cmdline[90000]='\0';
  strcpy(event->ave_result_json,"{\"p0_disposition\":\"NOT_EVALUABLE\",\"source_contract_version\":\"p0-source-only-v2\","
      "\"stage\":\"pre_evaluation\",\"gate_id\":\"P0_PROCESS_EVIDENCE_GATE\",\"reason\":\"evidence_enrichment_timeout\"}");
  pb_ostream_t output=pb_ostream_from_buffer(frame,EDR_EGRESS_FRAME_MAX);
  assert(pb_encode(&output,edr_v1_BehaviorEvent_fields,event));
  wr(raw,(uint32_t)output.bytes_written);memcpy(raw+4,frame,output.bytes_written);
  size_t raw_length=output.bytes_written+4u,wire_length;
  wr(wire,compressed?EDR_TRANSPORT_BATCH_MAGIC_LZ4:EDR_TRANSPORT_BATCH_MAGIC_RAW);
  wr(wire+4,1u);wr(wire+8,(uint32_t)raw_length);
  if(compressed) {
    int length=LZ4_compress_default((const char *)raw,(char *)wire+12,(int)raw_length,EDR_EGRESS_FRAME_MAX+52);
    assert(length>0);wire_length=(size_t)length+12u;
  } else {memcpy(wire+12,raw,raw_length);wire_length=raw_length+12u;}
  assert(!edr_egress_batch_validate(wire,12,wire+12,wire_length-12,reason,sizeof(reason)));
  assert(!strcmp(reason,"source_only_requires_local_owner_v3"));
  /* Independent full frame decoding proves this is not a dictionary/delta
   * requiring another queue row; long command and ordinary parent survive. */
  memset(raw,0,raw_length);
  if(compressed) assert(LZ4_decompress_safe((const char *)wire+12,(char *)raw,(int)(wire_length-12),(int)raw_length)==(int)raw_length);
  else memcpy(raw,wire+12,raw_length);
  pb_istream_t input=pb_istream_from_buffer(raw+4,rd(raw));
  assert(pb_decode(&input,edr_v1_BehaviorEvent_fields,decoded));
  assert(strlen(decoded->cmdline)==90000u && !strcmp(decoded->cmdline,event->cmdline));
  assert(decoded->ppid==4u && decoded->has_parent_pid_state && decoded->parent_pid_state==1u);
  assert(decoded->process_start_key==UINT64_MAX && !strcmp(decoded->process_context.parent_cmdline,event->process_context.parent_cmdline));
  EdrStorageQueueLocalEvidenceOwner owner={0};EdrStorageQueueP0SourceOnlyLatch latch;
  owner.version=1u;owner.diagnostic_reason="evidence_enrichment_timeout";
  owner.endpoint_id=event->endpoint_id;owner.tenant_id=event->tenant_id;owner.event_time_ns=event->event_time_ns;
  owner.event_type=event->type;owner.pid=event->pid;owner.parent_pid=event->ppid;
  owner.process_start_key=event->process_start_key;owner.process_creation_filetime_100ns=event->process_creation_filetime_100ns;
  owner.parent_process_start_key=111u;owner.parent_process_creation_filetime_100ns=UINT64_C(133444444000000000);
  edr_storage_queue_configure(4u,1u);edr_storage_queue_test_set_delivery_time(1700000000);
  edr_storage_queue_test_set_local_retention_elapsed(0u);assert(edr_storage_queue_open(path)==EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch)==EDR_OK);
  assert(edr_storage_queue_p0_source_only_commit_local_typed(&latch,event->event_id,"typed-real-batch",wire,wire_length,compressed,0,&owner)==EDR_OK);
  original_equal(path,"typed-real-batch",wire,wire_length);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE local_parent_start_key='111' AND local_parent_pid=4 AND local_start_key='18446744073709551615';")==1u);
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch)==EDR_OK);
  owner.tenant_id="";
  assert(edr_storage_queue_p0_source_only_commit_local_typed(&latch,event->event_id,"unclassified-real-batch",wire,wire_length,compressed,0,&owner)==EDR_ERR_INVALID_ARG);
  assert(edr_storage_queue_p0_source_only_commit_local(&latch,event->event_id,"unclassified-real-batch",wire,wire_length,compressed,0)==EDR_OK);
  sends=0;receipt_mode=1;edr_storage_queue_poll_drain();assert(sends==0);
  edr_storage_queue_test_set_delivery_time(1700003601);edr_storage_queue_test_set_local_retention_elapsed(3601u);
  edr_storage_queue_test_run_cleanup();
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE batch_id='typed-real-batch';")==0u);
  assert(sql_number(path,"SELECT COUNT(*) FROM delivery_receipts_v1;")==0u);
  original_equal(path,"unclassified-real-batch",wire,wire_length);
  edr_storage_queue_close();assert(edr_storage_queue_open(path)==EDR_OK);
  edr_storage_queue_poll_drain();assert(sends==0);
  original_equal(path,"unclassified-real-batch",wire,wire_length);
  edr_storage_queue_close();edr_storage_queue_test_set_delivery_time(-1);
  edr_storage_queue_test_set_local_retention_elapsed(UINT64_MAX);edr_storage_queue_configure(0u,0u);
  free(event);free(decoded);free(frame);free(raw);free(wire);remove(path);
}

typedef struct TerminalLocalQueryFixture {
  const EdrTestP0TerminalFixture *frame;
  unsigned visits;
} TerminalLocalQueryFixture;
static int terminal_local_query_visit(const char *event,const EdrStorageQueueLocalEvidenceOwner *owner,
    const uint8_t *wire,size_t len,void *arg) {
  TerminalLocalQueryFixture *state=arg;const EdrTestP0TerminalFixture *f=state->frame;
  assert(!strcmp(event,f->source_event_id) && !strcmp(owner->diagnostic_reason,"enforcement_terminal_result"));
  assert(owner->pid==4242u && owner->process_start_key==UINT64_C(0xfedcba9876543210) &&
      owner->process_creation_filetime_100ns==UINT64_C(133444000000000000));
  assert(len==f->length[1] && !memcmp(wire,f->wire[1],len));state->visits++;return 1;
}
static void terminal_typed_source_lifecycle(void) {
  char path[512],why[96];test_path(path,sizeof(path),"typed-terminal",0);remove(path);
  EdrTestP0TerminalFixture f;assert(edr_test_p0_terminal_fixture_init(&f,41u,"synthetic-tenant","synthetic-endpoint"));
  EdrStorageQueueLocalEvidenceOwner owner={0};owner.version=1u;owner.diagnostic_reason="enforcement_terminal_result";
  owner.endpoint_id="synthetic-endpoint";owner.tenant_id="synthetic-tenant";owner.event_type=EDR_EVENT_PROCESS_CREATE;
  owner.event_time_ns=1700000000000000041LL;owner.pid=4242u;owner.process_start_key=UINT64_C(0xfedcba9876543210);
  owner.process_creation_filetime_100ns=UINT64_C(133444000000000000);
  const int64_t started=1700000100;edr_storage_queue_configure(8u,1u);
  edr_storage_queue_test_set_delivery_time(started);edr_storage_queue_test_set_local_retention_elapsed(0u);
  assert(edr_storage_queue_open(path)==EDR_OK);
  assert(edr_storage_queue_enforcement_terminal_precreate(f.terminal_key,f.source_event_id,f.rule_id,
      f.generation_key,"typed-intent",f.wire[0],f.length[0])==EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  uint64_t reserved=sql_number(path,"SELECT reserved_bytes FROM enforcement_terminal_journal;");
  assert(reserved>=f.length[1]+f.length[2]+strlen("typed-source")+strlen("typed-combined")+2048u);
  assert(sql_number(path,"SELECT local_owner_reserved FROM enforcement_terminal_journal;")==2048u);
  EdrStorageQueueCapacityMetrics before,after;edr_storage_queue_get_capacity_metrics(&before);
  edr_storage_queue_test_fail_next_terminal_commits(1u);
  assert(edr_storage_queue_enforcement_terminal_update_local_source(f.terminal_key,"typed-source",f.wire[1],f.length[1],
      "typed-combined",f.wire[2],f.length[2],f.source_event_id,&owner)==EDR_ERR_SQLITE_WRITE);
  assert(sql_number(path,"SELECT COUNT(*) FROM enforcement_terminal_journal WHERE retention_policy_version=0 AND source_wire IS NULL AND local_owner_reserved=2048;")==1u);
  edr_storage_queue_get_capacity_metrics(&after);assert(before.used_bytes==after.used_bytes);
  edr_storage_queue_close();assert(edr_storage_queue_open(path)==EDR_OK);
  /* Recovered intent ownership never authorizes the side effect again. */
  assert(edr_storage_queue_enforcement_terminal_precreate(f.terminal_key,f.source_event_id,f.rule_id,
      f.generation_key,"typed-intent",f.wire[0],f.length[0])==EDR_ENFORCEMENT_TERMINAL_PRECREATE_EXISTING);
  assert(edr_storage_queue_enforcement_terminal_update_local_source(f.terminal_key,"typed-source",f.wire[1],f.length[1],
      "typed-combined",f.wire[2],f.length[2],f.source_event_id,&owner)==EDR_OK);
  edr_storage_queue_get_capacity_metrics(&after);assert(after.used_bytes<=before.used_bytes);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue;")==0u);
  assert(sql_number(path,"SELECT COUNT(*) FROM enforcement_terminal_journal WHERE retention_policy_version=3 AND local_owner_reserved=0 AND reserved_bytes=0 AND source_acked=0 AND source_policy_held=0;")==1u);
  assert(edr_egress_batch_validate(f.wire[0],12,f.wire[0]+12,f.length[0]-12,why,sizeof(why)));
  assert(edr_egress_batch_validate(f.wire[2],12,f.wire[2]+12,f.length[2]-12,why,sizeof(why)));
  assert(!edr_egress_batch_validate(f.wire[1],12,f.wire[1]+12,f.length[1]-12,why,sizeof(why)));
  assert(edr_storage_queue_enforcement_terminal_update_local_source(f.terminal_key,"typed-source",f.wire[1],f.length[1],
      "typed-combined",f.wire[2],f.length[2],f.source_event_id,&owner)==EDR_OK);
  owner.process_start_key++;
  assert(edr_storage_queue_enforcement_terminal_update_local_source(f.terminal_key,"typed-source",f.wire[1],f.length[1],
      "typed-combined",f.wire[2],f.length[2],f.source_event_id,&owner)==EDR_ERR_INVALID_ARG);
  owner.process_start_key--;
  assert(edr_storage_queue_enforcement_terminal_precreate(f.terminal_key,f.source_event_id,f.rule_id,
      "startkey-fedcba9876543211","typed-intent",f.wire[0],f.length[0])==EDR_ENFORCEMENT_TERMINAL_PRECREATE_CONFLICT);
  assert(edr_storage_queue_enforcement_terminal_precreate(f.terminal_key,f.source_event_id,f.rule_id,
      f.generation_key,"typed-intent",f.wire[1],f.length[1])==EDR_ENFORCEMENT_TERMINAL_PRECREATE_CONFLICT);
  TerminalLocalQueryFixture qf={&f,0u};EdrStorageQueueLocalQuery q={0};EdrStorageQueueLocalQueryStats qs;
  q.tenant_id=owner.tenant_id;q.endpoint_id=owner.endpoint_id;q.from_ns=owner.event_time_ns;q.until_ns=owner.event_time_ns;
  q.max_rows=4u;q.max_scan=8u;q.max_payload_bytes=65536u;q.until_mono_ns=edr_monotonic_ns()+UINT64_C(60000000000);
  q.pid=owner.pid;q.has_process_start_key=q.has_process_creation_filetime_100ns=1;
  q.process_start_key=owner.process_start_key;q.process_creation_filetime_100ns=owner.process_creation_filetime_100ns;
  assert(edr_storage_queue_query_local_snapshot(&q,terminal_local_query_visit,NULL,&qf,&qs)==0 && qf.visits==1u);
  /* Wrong receipt keeps the exact intent; combined can independently finish. */
  sends=0;receipt_mode=2;edr_storage_queue_poll_drain();assert(sends==1u && !strcmp(sent_id,"typed-intent"));
  assert(sql_number(path,"SELECT intent_acked FROM enforcement_terminal_journal;")==0u);
  edr_storage_queue_close();assert(edr_storage_queue_open(path)==EDR_OK);
  receipt_mode=1;sends=0;edr_storage_queue_poll_drain();assert(sends==1u && !strcmp(sent_id,"typed-combined"));
  assert(sql_number(path,"SELECT COUNT(*) FROM enforcement_terminal_journal WHERE state='ready' AND source_acked=0 AND source_policy_held=0 AND combined_acked=1;")==1u);
  edr_storage_queue_close();assert(edr_storage_queue_open(path)==EDR_OK);
  edr_storage_queue_test_set_delivery_time(started+2);sends=0;edr_storage_queue_poll_drain();
  assert(sends==1u && !strcmp(sent_id,"typed-intent"));
  assert(sql_number(path,"SELECT COUNT(*) FROM enforcement_terminal_journal WHERE state='local_retained' AND intent_acked=1 AND combined_acked=1 AND source_acked=0 AND source_policy_held=0;")==1u);
  assert(sql_number(path,"SELECT completed_at FROM enforcement_terminal_journal;")==(uint64_t)started+2u);
  char receipt_sha[65],receipt_sql[256];
  edr_sha256_hex((const uint8_t *)"typed-source",strlen("typed-source"),receipt_sha);
  snprintf(receipt_sql,sizeof(receipt_sql),"SELECT COUNT(*) FROM delivery_receipts_v1 WHERE batch_id_sha256='%s';",receipt_sha);
  assert(sql_number(path,receipt_sql)==0u);
  assert(sql_number(path,"SELECT COUNT(*) FROM delivery_receipts_v1;")==2u);
  edr_sha256_hex((const uint8_t *)"typed-intent",strlen("typed-intent"),receipt_sha);
  snprintf(receipt_sql,sizeof(receipt_sql),"SELECT COUNT(*) FROM delivery_receipts_v1 WHERE batch_id_sha256='%s';",receipt_sha);
  assert(sql_number(path,receipt_sql)==1u);
  edr_sha256_hex((const uint8_t *)"typed-combined",strlen("typed-combined"),receipt_sha);
  snprintf(receipt_sql,sizeof(receipt_sql),"SELECT COUNT(*) FROM delivery_receipts_v1 WHERE batch_id_sha256='%s';",receipt_sha);
  assert(sql_number(path,receipt_sql)==1u);
  assert(edr_storage_queue_enforcement_terminal_precreate(f.terminal_key,f.source_event_id,f.rule_id,
      f.generation_key,"typed-intent",f.wire[0],f.length[0])==EDR_ENFORCEMENT_TERMINAL_PRECREATE_EXISTING);
  edr_storage_queue_get_capacity_metrics(&before);
  /* Same-process wall-clock jump alone cannot expire the retained bytes. */
  edr_storage_queue_test_set_delivery_time(started+10000);edr_storage_queue_test_set_local_retention_elapsed(0u);
  for(unsigned i=0;i<5u;i++) edr_storage_queue_test_run_cleanup();
  assert(sql_number(path,"SELECT COUNT(*) FROM enforcement_terminal_journal;")==1u);
  edr_storage_queue_test_set_delivery_time(started-10000);edr_storage_queue_test_set_local_retention_elapsed(10000u);
  for(unsigned i=0;i<5u;i++) edr_storage_queue_test_run_cleanup();
  assert(sql_number(path,"SELECT COUNT(*) FROM enforcement_terminal_journal;")==1u);
  edr_storage_queue_test_set_delivery_time(started+3601);edr_storage_queue_test_set_local_retention_elapsed(3601u);
  for(unsigned i=0;i<5u;i++) edr_storage_queue_test_run_cleanup();
  assert(sql_number(path,"SELECT COUNT(*) FROM enforcement_terminal_journal;")==1u); /* delivery was +2 */
  edr_storage_queue_test_set_delivery_time(started+3603);edr_storage_queue_test_set_local_retention_elapsed(3603u);
  sql_exec(path,"UPDATE queue_meta SET source_latch_recovery_batch_id='typed-source';");
  for(unsigned i=0;i<5u;i++) edr_storage_queue_test_run_cleanup();
  assert(sql_number(path,"SELECT COUNT(*) FROM enforcement_terminal_journal;")==1u);
  sql_exec(path,"UPDATE queue_meta SET source_latch_recovery_batch_id='';"
      "CREATE TRIGGER test_retirement_abort BEFORE DELETE ON enforcement_terminal_journal BEGIN SELECT RAISE(ABORT,'synthetic retirement rollback'); END;");
  for(unsigned i=0;i<5u;i++) edr_storage_queue_test_run_cleanup();
  assert(sql_number(path,"SELECT COUNT(*) FROM enforcement_terminal_journal WHERE local_retention_state='retained';")==1u);
  assert(sql_number(path,"SELECT terminal_local_retired_rows FROM queue_meta;")==0u);
  edr_storage_queue_get_capacity_metrics(&after);assert(before.used_bytes==after.used_bytes);
  sql_exec(path,"DROP TRIGGER test_retirement_abort;");
  qf.visits=0u;assert(edr_storage_queue_query_local_snapshot(&q,terminal_local_query_visit,NULL,&qf,&qs)==0 && qf.visits==1u);
  for(unsigned i=0;i<5u;i++) edr_storage_queue_test_run_cleanup();
  assert(sql_number(path,"SELECT COUNT(*) FROM enforcement_terminal_journal;")==0u);
  edr_storage_queue_get_capacity_metrics(&after);assert(after.used_bytes==0u);
  assert(sql_number(path,"SELECT terminal_local_retired_rows FROM queue_meta;")==1u);
  assert(sql_number(path,"SELECT terminal_local_retired_bytes FROM queue_meta;")==before.used_bytes);
  qf.visits=0u;assert(edr_storage_queue_query_local_snapshot(&q,terminal_local_query_visit,NULL,&qf,&qs)==0 && qf.visits==0u);
  sends=0;edr_storage_queue_poll_drain();assert(sends==0u);
  edr_storage_queue_close();assert(edr_storage_queue_open(path)==EDR_OK);
  edr_storage_queue_get_capacity_metrics(&after);assert(after.used_bytes==0u);
  assert(sql_number(path,"SELECT terminal_local_retired_rows FROM queue_meta;")==1u);
  edr_storage_queue_close();edr_storage_queue_configure(0u,0u);edr_storage_queue_test_set_delivery_time(-1);
  edr_storage_queue_test_set_local_retention_elapsed(UINT64_MAX);edr_test_p0_terminal_fixture_free(&f);remove(path);
}

/* The producer-linked capacity fixture separately verifies the real record
 * builder. This direct frozen-wire fixture exercises hostile fields and exact
 * identity at the queue/codec boundary with no producer minimization. */
static size_t local_recovery_wire(const EdrStorageQueueP0SourceOnlyLatch *latch,
    const char *endpoint,const char *tenant,int extra,uint8_t wire[1040],char id[48],char batch[80]) {
  edr_v1_BehaviorEvent *event=calloc(1,sizeof(*event));assert(event);
  uint8_t number[8],digest[32],prefix[4];char commitment[65],nonce[33],shahex[65];
  static const char hex[]="0123456789abcdef",domain[]="edr-p0-source-only-delivery-v2";
  EdrSha256Ctx sha;edr_sha256_init(&sha);wr(prefix,(uint32_t)strlen(domain));
  edr_sha256_update(&sha,prefix,4u);edr_sha256_update(&sha,(const uint8_t *)domain,strlen(domain));
  edr_sha256_update(&sha,latch->queue_nonce,16u);
  for(unsigned field=0;field<2u;field++) {
    uint64_t n=field?latch->latch_epoch:latch->latch_counter;
    for(unsigned i=0;i<8u;i++) number[i]=(uint8_t)(n>>(8u*i));
    edr_sha256_update(&sha,number,8u);
  }
  edr_sha256_final(&sha,digest);
  for(unsigned i=0;i<32u;i++) {commitment[i*2u]=hex[digest[i]>>4];commitment[i*2u+1u]=hex[digest[i]&15u];}
  commitment[64]=0;
  for(unsigned i=0;i<16u;i++) {nonce[i*2u]=hex[latch->queue_nonce[i]>>4];nonce[i*2u+1u]=hex[latch->queue_nonce[i]&15u];}
  nonce[32]=0;snprintf(id,48,"p0sl-%.40s",commitment);
  snprintf(event->event_id,sizeof(event->event_id),"%s",id);
  snprintf(event->endpoint_id,sizeof(event->endpoint_id),"%s",endpoint);
  snprintf(event->tenant_id,sizeof(event->tenant_id),"%s",tenant);
  event->type=EDR_EVENT_CAPABILITY_AUDIT;event->has_parent_pid_state=true;
  strcpy(event->identity_source,"source_only_delivery");strcpy(event->identity_quality,"unknown");
  strcpy(event->source_completeness,"NOT_EVALUABLE");strcpy(event->transport_completeness,"COMPLETE");
  snprintf(event->ave_result_json,sizeof(event->ave_result_json),
    "{\"p0_disposition\":\"NOT_EVALUABLE\",\"reason\":\"pending_assertion_lost_on_restart\","
    "\"source_contract_version\":\"p0-source-only-v2\",\"stage\":\"source_only_delivery\","
    "\"gate_id\":\"P0_SOURCE_ONLY_DURABILITY_GATE\",\"loss_detected\":true,"
    "\"source_only_delivery\":{\"queue_nonce\":\"%s\",\"latch_counter\":\"%llu\",\"latch_epoch\":\"%llu\","
    "\"commitment_sha256\":\"%s\",\"latch_id\":\"%s\"}}",nonce,
    (unsigned long long)latch->latch_counter,(unsigned long long)latch->latch_epoch,commitment,id);
  if(extra==1) strcpy(event->cmdline,"unnecessary full command");
  if(extra==2) {cJSON *ctx=cJSON_Parse(event->ave_result_json);assert(ctx);cJSON_AddBoolToObject(ctx,"extra",1);
    char *text=cJSON_PrintUnformatted(ctx);assert(text);strcpy(event->ave_result_json,text);free(text);cJSON_Delete(ctx);}
  if(extra==3) event->pid=42u;
  pb_ostream_t output=pb_ostream_from_buffer(wire+16,1024u);
  assert(pb_encode(&output,edr_v1_BehaviorEvent_fields,event));free(event);
  size_t len=output.bytes_written+16u;wr(wire,EDR_TRANSPORT_BATCH_MAGIC_RAW);wr(wire+4,1u);
  wr(wire+8,(uint32_t)len-12u);wr(wire+12,(uint32_t)len-16u);
  assert(edr_sha256_hex(wire,len,shahex)==0);snprintf(batch,80,"p0-source-%s",shahex);return len;
}
static EdrStorageQueueLocalEvidenceOwner local_audit_owner(void) {
  EdrStorageQueueLocalEvidenceOwner owner={0};owner.version=1u;
  owner.diagnostic_reason="pending_assertion_lost_on_restart";owner.event_type=EDR_EVENT_CAPABILITY_AUDIT;
  owner.endpoint_id="synthetic-endpoint";owner.tenant_id="synthetic-tenant";return owner;
}
static int local_audit_visit(const char *id,const EdrStorageQueueLocalEvidenceOwner *owner,
    const uint8_t *wire,size_t len,void *arg) {
  unsigned *count=arg;char batch[80],sha[65];EdrEgressP0LocalRecoveryAudit decoded;
  assert(edr_sha256_hex(wire,len,sha)==0);snprintf(batch,sizeof(batch),"p0-source-%s",sha);
  assert(edr_egress_p0_local_recovery_audit_decode(wire,len,id,batch,owner->endpoint_id,owner->tenant_id,&decoded));
  (*count)++;return 1;
}
typedef struct { uint8_t *wire; size_t length; EdrError result; } LocalAuditWriter;
#ifdef _WIN32
static DWORD WINAPI local_audit_other_writer(LPVOID arg) {
#else
static void *local_audit_other_writer(void *arg) {
#endif
  LocalAuditWriter *writer=arg;
  writer->result=edr_storage_queue_enqueue("parallel-terminal",writer->wire,writer->length,0,1);
#ifdef _WIN32
  return 0;
#else
  return NULL;
#endif
}
static void local_audit_counter_matches(const char *path) {
  uint64_t expected=sql_number(path,
    "SELECT COALESCE(SUM(length(CAST(batch_id AS BLOB))+length(payload)+512+CASE WHEN recovery_version>0 THEN 512 ELSE 0 END+"
    "512+length(CAST(local_source_event_id AS BLOB))+length(CAST(local_reason AS BLOB))+"
    "4*(length(CAST(local_endpoint_id AS BLOB))+length(CAST(local_tenant_id AS BLOB)))+"
    "2*(length(CAST(local_start_key AS BLOB))+length(CAST(local_birth AS BLOB)))+"
    "length(CAST(local_parent_start_key AS BLOB))+length(CAST(local_parent_birth AS BLOB))+"
    "length(CAST(local_payload_sha256 AS BLOB))+length(CAST(local_owner_sha256 AS BLOB))),0) FROM event_queue "
    "WHERE terminal_reason='source_only_local_recovery_v3' AND retention_class=1 AND retention_policy_version=2;");
  assert(sql_number(path,"SELECT source_audit_bytes FROM queue_meta;")==expected);
  assert(sql_number(path,"SELECT source_audit_rows FROM queue_meta;")==sql_number(path,
      "SELECT COUNT(*) FROM event_queue WHERE terminal_reason='source_only_local_recovery_v3' AND retention_class=1 AND retention_policy_version=2;"));
}
static void local_replay_retired_before_write(void *arg) {
  const char *path=arg;
  sql_exec(path,"BEGIN IMMEDIATE;UPDATE event_queue SET local_retention_state='retirement_eligible' WHERE batch_id='race-original';"
    "UPDATE event_queue SET local_retention_state='retired' WHERE batch_id='race-original';"
    "DELETE FROM event_queue WHERE batch_id='race-original';COMMIT;");
}
static void local_group_capacity_replay_and_owner(void) {
  char path[512],ids[8][32];test_path(path,sizeof(path),"local-group",0);remove(path);
  edr_storage_queue_configure(1u,1u);edr_storage_queue_test_set_delivery_time(100000);
  edr_storage_queue_test_set_local_retention_elapsed(0u);
  assert(edr_storage_queue_open(path)==EDR_OK);
  uint8_t *wire=calloc(1,128u*1024u);assert(wire);
  EdrStorageQueueLocalEntry entries[8]={0};
  for(unsigned i=0;i<8u;++i) {
    snprintf(ids[i],sizeof(ids[i]),"group-owner-%u",i);
    entries[i].event_id=entries[i].batch_id=ids[i];
    entries[i].payload=wire;entries[i].payload_len=128u*1024u;
    entries[i].owner.version=1u;entries[i].owner.diagnostic_reason="missing_cmdline";
    entries[i].owner.endpoint_id="synthetic-endpoint";entries[i].owner.tenant_id="synthetic-tenant";
    entries[i].owner.event_type=EDR_EVENT_PROCESS_CREATE;
    entries[i].owner.event_time_ns=INT64_C(100000000000000);
  }
  EdrStorageQueueP0SourceOnlyLatch latch,after;
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch)==EDR_OK);
  assert(edr_storage_queue_p0_source_only_commit_local_group(&latch,entries,8u,NULL)==EDR_ERR_QUEUE_FULL);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue;")==0u);
  assert(sql_number(path,"SELECT SUM(logical_bytes) FROM queue_capacity_ledger_v1;")==0u);
  assert(edr_storage_queue_p0_source_only_latch_get(&after)==EDR_OK && after.latched &&
      after.latch_counter==latch.latch_counter && !after.recovery_required);
  EdrStorageQueueP0SourceOnlyLatch legacy=latch;legacy.owner_version=2u;
  assert(edr_storage_queue_p0_source_only_commit_local_group(&legacy,entries,1u,NULL)==EDR_ERR_INVALID_ARG);
  assert(edr_storage_queue_p0_source_only_commit_local_group(&latch,entries,0u,NULL)==EDR_ERR_INVALID_ARG);
  assert(edr_storage_queue_p0_source_only_commit_local_group(&latch,entries,9u,NULL)==EDR_ERR_INVALID_ARG);
  assert(edr_storage_queue_p0_source_only_commit_local_group(&latch,entries,3u,NULL)==EDR_OK);
  for(unsigned i=0;i<3u;++i) original_equal(path,ids[i],wire,128u*1024u);
  /* A pure replay needs no extra ordinary allocation, even after TTL. */
  edr_storage_queue_test_set_local_retention_elapsed(7200u);
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch)==EDR_OK);
  assert(edr_storage_queue_p0_source_only_commit_local_group(&latch,entries,3u,NULL)==EDR_OK);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue;")==3u);
  for(unsigned i=0;i<3u;++i) original_equal(path,ids[i],wire,128u*1024u);
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch)==EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch)==EDR_OK && latch.recovery_required);
  assert(edr_storage_queue_p0_source_only_commit_local_group(&latch,entries,1u,NULL)==EDR_ERR_INVALID_ARG);
  assert(edr_storage_queue_p0_source_only_latch_get(&after)==EDR_OK && after.recovery_required);
  edr_storage_queue_close();assert(remove(path)==0);free(wire);
  puts("local group: per-row budget rolls back whole batch; pure replay preserves expired bytes; legacy/loss owner rejected");
}
static void local_recovery_audit_capacity_and_handoff(void) {
  char path[512],id[48],batch[80],other_id[48],other_batch[80];uint8_t wire[1040],other[1040];
  test_path(path,sizeof(path),"local-audit-capacity",0);remove(path);
  edr_storage_queue_configure(1u,1u);edr_storage_queue_test_set_delivery_time(100000);
  edr_storage_queue_test_set_local_retention_elapsed(0u);assert(edr_storage_queue_open(path)==EDR_OK);
  EdrStorageQueueLocalEvidenceOwner ordinary={0},audit=local_audit_owner();
  ordinary.version=1u;ordinary.diagnostic_reason="missing_cmdline";ordinary.endpoint_id=audit.endpoint_id;
  ordinary.tenant_id=audit.tenant_id;ordinary.event_type=EDR_EVENT_PROCESS_CREATE;ordinary.event_time_ns=INT64_C(100000000000000);
  uint8_t *large=calloc(1,8192u);assert(large);EdrStorageQueueP0SourceOnlyLatch latch,after,successor;
  unsigned admitted=0u;
  for(unsigned i=0;i<100u;i++) {
    char key[48];snprintf(key,sizeof(key),"ordinary-pressure-%u",i);
    assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch)==EDR_OK);
    EdrError result=edr_storage_queue_p0_source_only_commit_local_typed(&latch,key,key,large,8192u,0,0,&ordinary);
    if(result==EDR_ERR_QUEUE_FULL) break;
    assert(result==EDR_OK);admitted++;
  }
  assert(admitted>1u);free(large);
  /* Consume the sub-8KiB tail with a real ordinary owner so a much smaller
   * audit cannot accidentally fit below the ordinary ceiling. */
  uint8_t tail[20]={0};
  assert(edr_storage_queue_p0_source_only_commit_local_typed(&latch,"ordinary-tail","ordinary-tail",tail,sizeof(tail),0,0,&ordinary)==EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch)==EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch)==EDR_OK && latch.recovery_required);
  size_t len=local_recovery_wire(&latch,audit.endpoint_id,audit.tenant_id,0,wire,id,batch);
  EdrEgressP0LocalRecoveryAudit decoded;
  assert(edr_egress_p0_local_recovery_audit_decode(wire,len,id,batch,audit.endpoint_id,audit.tenant_id,&decoded));
  assert(!edr_egress_batch_validate(wire,12,wire+12,len-12,NULL,0));
  assert(edr_storage_queue_p0_source_only_commit_local_typed(&latch,id,batch,wire,len,0,0,&audit)==EDR_ERR_QUEUE_FULL);
  for(int extra=1;extra<=3;extra++) {
    size_t n=local_recovery_wire(&latch,audit.endpoint_id,audit.tenant_id,extra,other,other_id,other_batch);
    assert(edr_storage_queue_p0_source_only_commit_local_typed(&latch,other_id,other_batch,other,n,0,1,&audit)==EDR_ERR_INVALID_ARG);
  }
  EdrStorageQueueP0SourceOnlyLatch wrong=latch;wrong.queue_nonce[0]^=1u;
  size_t n=local_recovery_wire(&wrong,audit.endpoint_id,audit.tenant_id,0,other,other_id,other_batch);
  assert(edr_storage_queue_p0_source_only_commit_local_typed(&latch,other_id,other_batch,other,n,0,1,&audit)==EDR_ERR_INVALID_ARG);
  audit.endpoint_id="other-endpoint";
  assert(edr_storage_queue_p0_source_only_commit_local_typed(&latch,id,batch,wire,len,0,1,&audit)==EDR_ERR_INVALID_ARG);
  audit=local_audit_owner();
  EdrStorageQueueCapacityMetrics before,metrics;edr_storage_queue_get_capacity_metrics(&before);
  edr_storage_queue_test_fail_next_p0_latch_commits(1u);memset(&successor,0xa5,sizeof(successor));
  assert(edr_storage_queue_p0_source_only_commit_local_typed_handoff(&latch,id,batch,wire,len,0,1,&audit,&successor)==EDR_ERR_SQLITE_WRITE);
  assert(!successor.latched && !successor.latch_counter);
  assert(edr_storage_queue_p0_source_only_latch_get(&after)==EDR_OK && after.recovery_required && after.latch_counter==latch.latch_counter);
  edr_storage_queue_get_capacity_metrics(&metrics);assert(metrics.used_bytes==before.used_bytes);
  assert(sql_number(path,"SELECT source_audit_rows FROM queue_meta;")==0u);
  assert(edr_storage_queue_p0_source_only_commit_local_typed_handoff(&latch,id,batch,wire,len,0,1,&audit,&successor)==EDR_OK);
  assert(successor.latched && !successor.recovery_required && successor.latch_counter>latch.latch_counter);
  original_equal(path,batch,wire,len);local_audit_counter_matches(path);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE retention_class=1 AND status='local_evidence' AND retention_policy_version=2 AND terminal_reason='source_only_local_recovery_v3';")==1u);
  assert(edr_storage_queue_pending_count()==0u && sql_number(path,"SELECT COUNT(*) FROM delivery_receipts_v1;")==0u);
  EdrStorageQueueLocalQuery query={0};EdrStorageQueueLocalQueryStats stats;unsigned visits=0u;
  query.endpoint_id=audit.endpoint_id;query.tenant_id=audit.tenant_id;query.has_type=1;query.event_type=72u;
  query.max_rows=8u;query.max_scan=8u;query.max_payload_bytes=4096u;query.until_mono_ns=edr_monotonic_ns()+UINT64_C(1000000000);
  assert(edr_storage_queue_query_local_snapshot(&query,local_audit_visit,NULL,&visits,&stats)==0 && visits==1u);
  uint8_t terminal[20]={0};wr(terminal,EDR_TRANSPORT_BATCH_MAGIC_RAW);wr(terminal+4,1u);wr(terminal+8,8u);wr(terminal+12,4u);
  assert(edr_storage_queue_enqueue("terminal-20",terminal,sizeof(terminal),0,1)==EDR_OK);
  sqlite3 *external=db_open(path);
  assert(sqlite3_exec(external,"BEGIN IMMEDIATE;UPDATE event_queue SET recovery_version=1 WHERE terminal_reason='source_only_local_recovery_v3';",NULL,NULL,NULL)==SQLITE_OK);
  LocalAuditWriter writer={terminal,sizeof(terminal),EDR_ERR_SQLITE_WRITE};
#ifdef _WIN32
  HANDLE thread=CreateThread(NULL,0,local_audit_other_writer,&writer,0,NULL);assert(thread);Sleep(10);
#else
  pthread_t thread;assert(pthread_create(&thread,NULL,local_audit_other_writer,&writer)==0);usleep(10000);
#endif
  assert(sqlite3_exec(external,"COMMIT;",NULL,NULL,NULL)==SQLITE_OK);assert(sqlite3_close(external)==SQLITE_OK);
#ifdef _WIN32
  assert(WaitForSingleObject(thread,5000)==WAIT_OBJECT_0);CloseHandle(thread);
#else
  assert(pthread_join(thread,NULL)==0);
#endif
  assert(writer.result==EDR_OK);local_audit_counter_matches(path);original_equal(path,batch,wire,len);
  EdrTestP0TerminalFixture f;assert(edr_test_p0_terminal_fixture_init(&f,92u,audit.tenant_id,audit.endpoint_id));
  assert(edr_storage_queue_enforcement_terminal_precreate(f.terminal_key,f.source_event_id,f.rule_id,
      f.generation_key,"audit-terminal-intent",f.wire[0],f.length[0])==EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  edr_storage_queue_get_capacity_metrics(&metrics);assert(metrics.used_bytes<=metrics.max_bytes);
  assert(metrics.used_bytes==sql_number(path,"SELECT SUM(logical_bytes) FROM queue_capacity_ledger_v1;"));
  edr_test_p0_terminal_fixture_free(&f);edr_storage_queue_close();assert(edr_storage_queue_open(path)==EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_get(&after)==EDR_OK && after.latched);
  original_equal(path,batch,wire,len);edr_storage_queue_close();remove(path);

  /* Audit reserve exhaustion is finite, even when every input has priority 0.
   * No terminal slot or global ceiling is borrowed to append another audit. */
  test_path(path,sizeof(path),"local-audit-capacity",1);remove(path);assert(edr_storage_queue_open(path)==EDR_OK);
  unsigned audits=0u;
  for(unsigned i=0;i<1000u;i++) {
    assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch)==EDR_OK);
    assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch)==EDR_OK && latch.recovery_required);
    len=local_recovery_wire(&latch,audit.endpoint_id,audit.tenant_id,0,wire,id,batch);
    EdrError result=edr_storage_queue_p0_source_only_commit_local_typed(&latch,id,batch,wire,len,0,1,&audit);
    if(result==EDR_ERR_QUEUE_FULL) break;
    assert(result==EDR_OK);audits++;
  }
  assert(audits>1u && audits<1000u);edr_storage_queue_get_capacity_metrics(&metrics);
  assert(sql_number(path,"SELECT source_audit_bytes FROM queue_meta;")<=metrics.p0_source_only_reserve_bytes);
  assert(edr_storage_queue_enqueue("terminal-20",terminal,sizeof(terminal),0,1)==EDR_OK);
  assert(edr_storage_queue_enforcement_terminal_precreate("audit-full-terminal","audit-full-source","rule","generation",
      "audit-full-intent",terminal,sizeof(terminal))==EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  edr_storage_queue_get_capacity_metrics(&metrics);assert(metrics.used_bytes<=metrics.max_bytes);
  edr_storage_queue_close();remove(path);

  /* Canonical audit TTL is local policy, with no delivery receipt. Prepared
   * successor protects the remaining RAM owner across a clean close. */
  test_path(path,sizeof(path),"local-audit-capacity",2);remove(path);assert(edr_storage_queue_open(path)==EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch)==EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch)==EDR_OK);
  len=local_recovery_wire(&latch,audit.endpoint_id,audit.tenant_id,0,wire,id,batch);
  assert(edr_storage_queue_p0_source_only_commit_local_typed_handoff(&latch,id,batch,wire,len,0,1,&audit,&successor)==EDR_OK);
  local_audit_counter_matches(path);edr_storage_queue_close();
  sql_exec(path,"UPDATE queue_meta SET source_audit_bytes=0,source_audit_rows=0;");
  edr_storage_queue_test_fail_next_capacity_calibration_commits(1u);
  assert(edr_storage_queue_open(path)!=EDR_OK);
  assert(sql_number(path,"SELECT source_audit_bytes FROM queue_meta;")==0u);
  assert(sql_number(path,"SELECT source_audit_rows FROM queue_meta;")==0u);
  original_equal(path,batch,wire,len);
  assert(edr_storage_queue_open(path)==EDR_OK);local_audit_counter_matches(path);
  edr_storage_queue_test_set_delivery_time(103601);edr_storage_queue_test_set_local_retention_elapsed(3601u);
  edr_storage_queue_test_run_cleanup();
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue;")==0u);
  assert(sql_number(path,"SELECT local_retired_rows FROM queue_meta;")==1u);
  assert(sql_number(path,"SELECT COUNT(*) FROM delivery_receipts_v1;")==0u);
  edr_storage_queue_get_capacity_metrics(&metrics);assert(metrics.used_bytes==0u);
  edr_storage_queue_close();assert(edr_storage_queue_open(path)==EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_get(&after)==EDR_OK && after.latched &&
      after.latch_counter==successor.latch_counter);
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&after)==EDR_OK && after.recovery_required &&
      after.latch_counter==successor.latch_counter);
  edr_storage_queue_close();remove(path);
  test_path(path,sizeof(path),"local-audit-capacity",3);remove(path);
  assert(edr_storage_queue_open(path)==EDR_OK);
  uint8_t *terminal_large=calloc(1,8192u);assert(terminal_large);unsigned terminals=0u;
  for(unsigned i=0;i<200u;i++) {
    char key[48];snprintf(key,sizeof(key),"terminal-flood-%u",i);
    EdrError result=edr_storage_queue_enqueue(key,terminal_large,8192u,0,1);
    if(result==EDR_ERR_QUEUE_FULL) break;
    assert(result==EDR_OK);terminals++;
  }
  assert(terminals>1u && terminals<200u);edr_storage_queue_get_capacity_metrics(&metrics);
  assert(metrics.used_bytes<=metrics.max_bytes-metrics.p0_source_only_reserve_bytes);
  assert(sql_number(path,"SELECT source_audit_bytes FROM queue_meta;")==0u);
  assert(sql_number(path,"SELECT COUNT(*) FROM pragma_table_info('queue_capacity_ledger_v1');")==3u);
  free(terminal_large);edr_storage_queue_close();remove(path);
  /* A corrupt marker cannot make valid metadata/hash authorize noncanonical
   * detailed fields through the local reader or retirement. Bypass the marker
   * immutability trigger only in this deliberately hostile isolated fixture. */
  test_path(path,sizeof(path),"local-audit-capacity",4);remove(path);assert(edr_storage_queue_open(path)==EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch)==EDR_OK);
  len=local_recovery_wire(&latch,audit.endpoint_id,audit.tenant_id,1,wire,id,batch);
  assert(edr_storage_queue_p0_source_only_commit_local_typed(&latch,id,batch,wire,len,0,0,&audit)==EDR_OK);
  sql_exec(path,"DROP TRIGGER event_queue_local_audit_marker_immutable;UPDATE event_queue SET terminal_reason='source_only_local_recovery_v3';");
  visits=0u;query.until_mono_ns=edr_monotonic_ns()+UINT64_C(1000000000);
  assert(edr_storage_queue_query_local_snapshot(&query,local_audit_visit,NULL,&visits,&stats)==-3 && visits==0u);
  edr_storage_queue_test_set_delivery_time(107202);edr_storage_queue_test_set_local_retention_elapsed(7202u);
  edr_storage_queue_test_run_cleanup();assert(sql_number(path,"SELECT COUNT(*) FROM event_queue;")==1u);
  assert(sql_number(path,"SELECT local_retention_integrity_failures FROM queue_meta;")>0u);
  edr_storage_queue_close();remove(path);edr_storage_queue_configure(0u,0u);
  edr_storage_queue_test_set_delivery_time(-1);edr_storage_queue_test_set_local_retention_elapsed(UINT64_MAX);
  test_path(path,sizeof(path),"local-audit-capacity",5);remove(path);assert(edr_storage_queue_open(path)==EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch)==EDR_OK);
  assert(edr_storage_queue_p0_source_only_commit_local_typed(&latch,"race-original","race-original",tail,sizeof(tail),0,0,&ordinary)==EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch)==EDR_OK);
  edr_storage_queue_test_before_source_replay_transaction(local_replay_retired_before_write,path);
  memset(&successor,0xa5,sizeof(successor));
  assert(edr_storage_queue_p0_source_only_commit_local_typed_handoff(&latch,"race-original","race-original",tail,sizeof(tail),0,0,&ordinary,&successor)==EDR_ERR_SQLITE_WRITE);
  assert(!successor.latched && !successor.latch_counter);
  assert(edr_storage_queue_p0_source_only_latch_get(&after)==EDR_OK && after.latched && after.latch_counter==latch.latch_counter);
  assert(sql_number(path,"SELECT COUNT(*) FROM event_queue;")==0u);
  edr_storage_queue_close();remove(path);
  puts("local recovery audit: canonical scope/tuple/field proof, finite reserve, terminal20+journal, FULL rollback/handoff, TTL and zero ACK passed");
}

/* Opt-in synthetic load for the existing real-codec/SQLite target only.
 * No matcher/action/HTTP runs. Only necessary intent/combined frames can get
 * synthetic receipts through the production ACK parser. Local sources never do.
 */
#define LOAD_OWNERS 64u
static int load_receipt_mode;
static unsigned load_attempts,load_exact_acks,load_bad_acks;
static uint64_t load_started,load_peak_observed;
static unsigned load_ordinary_rows;
static const char *load_profile;
typedef struct {
  EdrTestP0TerminalFixture f;
  size_t local_intent_len,command_bytes;
  EdrStorageQueueLocalEvidenceOwner local;
  char intent_id[64],source_id[64],combined_id[64];
  int created,enqueue_result;
} LoadOwner;
static LoadOwner load_owners[LOAD_OWNERS+2u];
static atomic_uint load_ready,load_go;
static void load_poll(void) {
  /* The production drain clamps its interval to at least 200ms. */
#ifdef _WIN32
  Sleep(210u);
#else
  usleep(210000u);
#endif
  edr_storage_queue_poll_drain();
}
static void load_bound(void) {
  assert(edr_monotonic_ns()-load_started<UINT64_C(120000000000));
}
static int load_transport(const char *id,const uint8_t *header,size_t hlen,const uint8_t *body,size_t len) {
  if(strncmp(id,"load-i-",7u) && strncmp(id,"load-c-",7u)) return -1;
  char why[96],sha[65],receipt[640];
  assert(hlen==12u && len>4u && hlen+len<=EDR_EVENT_BATCH_CAP);
  assert(edr_egress_batch_validate(header,hlen,body,len,why,sizeof(why)));
  edr_v1_BehaviorEvent *event=calloc(1,sizeof(*event));assert(event);
  pb_istream_t input=pb_istream_from_buffer(body+4u,len-4u);
  assert(pb_decode(&input,edr_v1_BehaviorEvent_fields,event));
  assert(!event->cmdline[0] && !event->process_context.parent_cmdline[0]);free(event);
  uint8_t *wire=malloc(hlen+len);assert(wire);memcpy(wire,header,hlen);memcpy(wire+hlen,body,len);
  assert(!edr_sha256_hex(wire,hlen+len,sha));free(wire);load_attempts++;
  if(!load_receipt_mode)return -1;
  snprintf(receipt,sizeof(receipt),"{\"code\":\"OK\",\"data\":{\"accepted\":1,\"invalid_frames\":0,\"ack\":{\"version\":1,\"state\":\"processed\",\"endpoint_id\":\"synthetic-endpoint\",\"batch_id\":\"%s\",\"payload_sha256\":\"%s\",\"frame_count\":1}}}",load_receipt_mode==2?"wrong-owned-batch":id,sha);
  int ok=edr_report_events_acknowledged(receipt,"synthetic-endpoint",id,header,hlen,body,len);
  if(load_receipt_mode==2){assert(!ok);load_bad_acks++;}else{assert(ok);load_exact_acks++;}
  return ok?0:-1;
}
static uint8_t *load_encode(const EdrBehaviorRecord *r,const AVEBehaviorAlert *a,
    const char *subject,const char *parent,int outbound,size_t *length) {
  uint8_t *wire=malloc(EDR_EVENT_BATCH_CAP);assert(wire);
  size_t n=outbound?edr_behavior_record_encode_protobuf_facts(r,a,subject,parent,wire+16u,EDR_EVENT_BATCH_CAP-16u):
      edr_behavior_record_encode_protobuf_full_facts(r,a,subject,parent,wire+16u,EDR_EVENT_BATCH_CAP-16u);
  assert(n>0u);wr(wire,EDR_TRANSPORT_BATCH_MAGIC_RAW);wr(wire+4u,1u);wr(wire+8u,(uint32_t)n+4u);wr(wire+12u,(uint32_t)n);
  *length=n+16u;return wire;
}
static void load_make_owner(LoadOwner *o,unsigned index,size_t command_bytes) {
  assert(edr_test_p0_terminal_fixture_init(&o->f,10000u+index,"synthetic-tenant","synthetic-endpoint"));
  o->command_bytes=command_bytes;
  char *subject=malloc(command_bytes+1u),*parent=malloc(command_bytes+1u);assert(subject && parent);
  memset(subject,'S',command_bytes);subject[command_bytes]=0;memset(parent,'P',command_bytes);parent[command_bytes]=0;
  for(unsigned kind=0u;kind<3u;kind++) {
    edr_v1_BehaviorEvent *event=calloc(1,sizeof(*event));EdrBehaviorRecord *r=calloc(1,sizeof(*r));
    AVEBehaviorAlert *alert=calloc(1,sizeof(*alert));assert(event && r && alert);
    pb_istream_t input=pb_istream_from_buffer(o->f.wire[kind]+16u,o->f.length[kind]-16u);
    assert(pb_decode(&input,edr_v1_BehaviorEvent_fields,event));
    r->type=(EdrEventType)event->type;r->pid=event->pid;r->ppid=4u;r->event_time_ns=event->event_time_ns;
    r->priority=0u;r->parent_pid_state=EDR_PARENT_PID_KNOWN;r->process_start_key=event->process_start_key;
    r->process_creation_filetime_100ns=event->process_creation_filetime_100ns;
    r->parent_process_start_key=4u;r->parent_process_creation_filetime_100ns=UINT64_C(133444000000000001);
    r->evidence_projection_version=EDR_EVIDENCE_PROJECTION_VERSION;r->required_evidence_fields=0u;
    snprintf(r->event_id,sizeof(r->event_id),"%s",event->event_id);
    snprintf(r->endpoint_id,sizeof(r->endpoint_id),"%s",event->endpoint_id);snprintf(r->tenant_id,sizeof(r->tenant_id),"%s",event->tenant_id);
    snprintf(r->process_name,sizeof(r->process_name),"synthetic.exe");snprintf(r->parent_name,sizeof(r->parent_name),"parent.exe");
    snprintf(r->exe_path,sizeof(r->exe_path),"%s",event->exe_path);snprintf(r->image_path_canonical,sizeof(r->image_path_canonical),"%s",event->image_path_canonical);
    snprintf(r->detection_context,sizeof(r->detection_context),"%s",event->ave_result_json);
    alert->pid=event->pid;alert->timestamp_ns=event->event_time_ns;alert->anomaly_score=0.9f;
    snprintf(alert->process_path,sizeof(alert->process_path),"%s",event->behavior_alert.process_path);
    snprintf(alert->user_subject_json,sizeof(alert->user_subject_json),"%s",event->behavior_alert.user_subject_json);
    if(kind==0u){size_t n=0u;uint8_t *full=load_encode(r,NULL,subject,parent,0,&n);o->local_intent_len=n;free(full);}
    free(o->f.wire[kind]);o->f.wire[kind]=load_encode(r,kind==2u?alert:NULL,subject,parent,kind!=1u,&o->f.length[kind]);
    if(kind==1u) {
      edr_v1_BehaviorEvent *decoded=calloc(1,sizeof(*decoded));assert(decoded);
      input=pb_istream_from_buffer(o->f.wire[kind]+16u,o->f.length[kind]-16u);
      assert(pb_decode(&input,edr_v1_BehaviorEvent_fields,decoded));
      assert(strlen(decoded->cmdline)==command_bytes && !strcmp(decoded->cmdline,subject));
      assert(strlen(decoded->process_context.parent_cmdline)==command_bytes && !strcmp(decoded->process_context.parent_cmdline,parent));free(decoded);
      o->local=(EdrStorageQueueLocalEvidenceOwner){1u,"enforcement_terminal_result","synthetic-endpoint","synthetic-tenant",r->event_time_ns,(uint32_t)r->type,r->pid,r->ppid,r->process_start_key,r->process_creation_filetime_100ns,r->parent_process_start_key,r->parent_process_creation_filetime_100ns};
    }
    free(alert);free(r);free(event);
  }
  free(subject);free(parent);
  snprintf(o->intent_id,sizeof(o->intent_id),"load-i-%05u",index);snprintf(o->source_id,sizeof(o->source_id),"load-s-%05u",index);snprintf(o->combined_id,sizeof(o->combined_id),"load-c-%05u",index);
}
static uint8_t *load_ordinary(unsigned index,size_t count,size_t *length) {
  EdrBehaviorRecord *r=calloc(1,sizeof(*r));assert(r);assert(count>0u && count<EDR_PROCESS_COMMAND_FACT_CAP);
  char *command=malloc(count+1u);assert(command);memset(command,'O',count);command[count]=0;
  r->type=EDR_EVENT_PROCESS_CREATE;r->pid=1234u;r->ppid=4u;r->event_time_ns=1700000000000000000LL+index;
  r->process_start_key=1234u;r->process_creation_filetime_100ns=UINT64_C(133444000000000000);
  snprintf(r->event_id,sizeof(r->event_id),"ordinary-source-%05u",index);strcpy(r->tenant_id,"synthetic-tenant");strcpy(r->endpoint_id,"synthetic-endpoint");
  uint8_t *wire=load_encode(r,NULL,command,command,0,length);free(command);free(r);return wire;
}
static uint64_t load_inventory(const char *path) {
  assert(!sql_number(path,"SELECT COUNT(*) FROM event_queue WHERE retention_policy_version=2;"));
  assert(!sql_number(path,"SELECT COUNT(*) FROM p0_deferred_match;"));
  assert(!sql_number(path,"SELECT COUNT(*) FROM queue_projection_relations;"));
  uint64_t total=sql_number(path,"SELECT COALESCE(SUM(length(CAST(batch_id AS BLOB))+length(payload)+512+CASE WHEN recovery_version>0 THEN 512 ELSE 0 END),0) FROM event_queue;");
  total+=sql_number(path,"SELECT COALESCE(SUM(length(CAST(idempotency_key AS BLOB))+length(CAST(source_event_key AS BLOB))+length(CAST(rule_id AS BLOB))+length(CAST(process_generation_key AS BLOB))+15+length(CAST(intent_batch_id AS BLOB))+COALESCE(length(intent_wire),0)+1024+MAX(length(CAST(source_batch_id AS BLOB))+COALESCE(length(source_wire),0)+length(CAST(combined_batch_id AS BLOB))+COALESCE(length(combined_wire),0),reserved_bytes)+CASE WHEN retention_policy_version=3 THEN 2048 ELSE 0 END),0) FROM enforcement_terminal_journal;");
  EdrStorageQueueCapacityMetrics m;edr_storage_queue_get_capacity_metrics(&m);assert(m.accounting_available && m.used_bytes==total);return total;
}
static void load_ordinary_digest(const char *path,char out[65]) {
  sqlite3 *db=db_open(path);sqlite3_stmt *st=NULL;assert(sqlite3_prepare_v2(db,"SELECT batch_id,payload FROM event_queue WHERE batch_id LIKE 'load-o-%' ORDER BY batch_id;",-1,&st,NULL)==SQLITE_OK);
  EdrSha256Ctx hash;edr_sha256_init(&hash);unsigned count=0u;int rc;
  while((rc=sqlite3_step(st))==SQLITE_ROW) {const uint8_t *id=sqlite3_column_text(st,0);size_t n=(size_t)sqlite3_column_bytes(st,1);uint8_t size[8];
    for(unsigned i=0;i<8u;i++)size[i]=(uint8_t)(n>>(i*8u));edr_sha256_update(&hash,id,strlen((const char *)id)+1u);edr_sha256_update(&hash,size,sizeof(size));edr_sha256_update(&hash,sqlite3_column_blob(st,1),n);count++;}
  assert(rc==SQLITE_DONE && count==load_ordinary_rows);sqlite3_finalize(st);sqlite3_close(db);
  uint8_t digest[32];edr_sha256_final(&hash,digest);static const char hex[]="0123456789abcdef";
  for(unsigned i=0;i<32u;i++){out[2u*i]=hex[digest[i]>>4u];out[2u*i+1u]=hex[digest[i]&15u];}out[64]=0;
}
static EdrStorageQueueCapacityMetrics load_point(const char *path,const char *stage,unsigned accepted,unsigned rejected) {
  load_bound();EdrStorageQueueCapacityMetrics m;edr_storage_queue_get_capacity_metrics(&m);assert(m.used_bytes==load_inventory(path));
  assert(!m.physical_admission_failures && !m.enqueue_transaction_failures && !m.enqueue_commit_failures);
  assert(m.used_bytes<=m.max_bytes && m.physical_bytes<=UINT64_C(2147483648));
  if(m.physical_bytes>load_peak_observed)load_peak_observed=m.physical_bytes;
  printf("{\"kind\":\"critical_load_point\",\"profile\":\"%s\",\"stage\":\"%s\",\"elapsed_s\":%.6f,\"accepted\":%u,\"rejected\":%u,\"max\":%llu,\"used\":%llu,\"ordinary_limit\":%llu,\"terminal_reserve\":%llu,\"source_reserve\":%llu,\"journal\":%llu,\"db\":%llu,\"wal\":%llu,\"shm\":%llu,\"physical\":%llu,\"intent_acked\":%llu,\"combined_acked\":%llu,\"source_acked\":%llu}\n",load_profile,stage,(double)(edr_monotonic_ns()-load_started)/1e9,accepted,rejected,(unsigned long long)m.max_bytes,(unsigned long long)m.used_bytes,(unsigned long long)m.ordinary_limit_bytes,(unsigned long long)m.terminal_reserve_bytes,(unsigned long long)m.p0_source_only_reserve_bytes,(unsigned long long)m.terminal_journal_bytes,(unsigned long long)m.db_bytes,(unsigned long long)m.wal_bytes,(unsigned long long)m.shm_bytes,(unsigned long long)m.physical_bytes,(unsigned long long)sql_number(path,"SELECT COALESCE(SUM(intent_acked),0) FROM enforcement_terminal_journal;"),(unsigned long long)sql_number(path,"SELECT COALESCE(SUM(combined_acked),0) FROM enforcement_terminal_journal;"),(unsigned long long)sql_number(path,"SELECT COALESCE(SUM(source_acked),0) FROM enforcement_terminal_journal;"));fflush(stdout);return m;
}
static void load_source_check(const char *path,LoadOwner *o) {
  sqlite3 *db=db_open(path);sqlite3_stmt *st=NULL;
  assert(sqlite3_prepare_v2(db,"SELECT source_wire,source_acked,source_policy_held,retention_policy_version FROM enforcement_terminal_journal WHERE idempotency_key=?;",-1,&st,NULL)==SQLITE_OK);
  sqlite3_bind_text(st,1,o->f.terminal_key,-1,SQLITE_STATIC);assert(sqlite3_step(st)==SQLITE_ROW);
  assert(sqlite3_column_bytes(st,0)==(int)o->f.length[1] && !memcmp(sqlite3_column_blob(st,0),o->f.wire[1],o->f.length[1]));
  assert(!sqlite3_column_int(st,1) && !sqlite3_column_int(st,2) && sqlite3_column_int(st,3)==3);assert(sqlite3_step(st)==SQLITE_DONE);sqlite3_finalize(st);sqlite3_close(db);
}
static void load_update(LoadOwner *o) {
  assert(edr_storage_queue_enforcement_terminal_update_local_source(o->f.terminal_key,o->source_id,o->f.wire[1],o->f.length[1],o->combined_id,o->f.wire[2],o->f.length[2],o->f.source_event_id,&o->local)==EDR_OK);
  int result=edr_storage_queue_enqueue(o->combined_id,o->f.wire[2],o->f.length[2],0,EDR_STORAGE_QUEUE_SEVERITY_TERMINAL);
  assert(result==EDR_OK || result==EDR_ERR_QUEUE_FULL);
}
#ifdef _WIN32
static DWORD WINAPI load_producer(void *opaque) {
#else
static void *load_producer(void *opaque) {
#endif
  unsigned lane=*(unsigned *)opaque;atomic_fetch_add_explicit(&load_ready,1u,memory_order_release);
  while(!atomic_load_explicit(&load_go,memory_order_acquire)){load_bound();
#ifdef _WIN32
    Sleep(1u);
#else
    usleep(1000u);
#endif
  }
  for(unsigned i=lane;i<LOAD_OWNERS;i+=4u){LoadOwner *o=&load_owners[i];load_bound();
    EdrEnforcementTerminalPrecreate result=edr_storage_queue_enforcement_terminal_precreate_local_source_bound(o->f.terminal_key,o->f.source_event_id,o->f.rule_id,o->f.generation_key,o->intent_id,o->f.wire[0],o->f.length[0],o->local_intent_len);
    assert(result==EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED || result==EDR_ENFORCEMENT_TERMINAL_PRECREATE_ERROR);o->created=result==EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED;
    if(o->created){o->enqueue_result=edr_storage_queue_enqueue(o->intent_id,o->f.wire[0],o->f.length[0],0,EDR_STORAGE_QUEUE_SEVERITY_TERMINAL);assert(o->enqueue_result==EDR_OK || o->enqueue_result==EDR_ERR_QUEUE_FULL);}
    else break;
  }
  return 0;
}
/* Isolated immutable rule descriptor, as in the existing egress fixture.
 * This is test authority, not a published/signed production IR evaluation. */
static int load_rule_authority(const char *rule,const char *bundle,uint64_t mask,const char *operation,void *user) {
  (void)user;
  return rule && !strcmp(rule,"synthetic-p0-rule") && bundle &&
      !strcmp(bundle,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") &&
      mask==0u && (!operation || !*operation);
}
static int critical_reserve_load(const char *profile) {
  unsigned q=!strcmp(profile,"mixed512")?512u:32u;assert(!strcmp(profile,"short32") || !strcmp(profile,"max32") || !strcmp(profile,"mixed512"));
  load_profile=profile;load_started=edr_monotonic_ns();load_active=1;load_receipt_mode=0;
  assert(!load_rule_authority("wrong-rule","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",0u,"",NULL));
  assert(!load_rule_authority("synthetic-p0-rule","wrong-bundle",0u,"",NULL));
  assert(!load_rule_authority("synthetic-p0-rule","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",1u,"",NULL));
  edr_egress_set_rule_projection_validator(load_rule_authority,NULL);
#ifndef _WIN32
  assert(!setenv("EDR_QUEUE_DRAIN_INTERVAL_MS","0",1));assert(!setenv("EDR_QUEUE_DRAIN_MAX_ROWS","128",1));
#else
  assert(!_putenv_s("EDR_QUEUE_DRAIN_INTERVAL_MS","0"));assert(!_putenv_s("EDR_QUEUE_DRAIN_MAX_ROWS","128"));
#endif
  char path[512];test_path(path,sizeof(path),"critical-reserve-load",(int)q);FILE *prior=fopen(path,"rb");assert(!prior);
  printf("{\"kind\":\"critical_load_begin\",\"profile\":\"%s\",\"database\":\"%s\",\"command_fact_cap\":%u}\n",profile,path,EDR_PROCESS_COMMAND_FACT_CAP);fflush(stdout);
  edr_storage_queue_configure(q,72u);assert(edr_storage_queue_open(path)==EDR_OK);int64_t delivery=(int64_t)time(NULL);edr_storage_queue_test_set_delivery_time(delivery);
  EdrStorageQueueCapacityMetrics initial=load_point(path,"empty",0u,0u);assert(initial.terminal_reserve_bytes==4194304u);
  for(unsigned i=0;i<4096u;i++) {load_bound();size_t n=0u;uint8_t *wire=load_ordinary(i,EDR_PROCESS_COMMAND_FACT_CAP-1u,&n);char id[64];snprintf(id,sizeof(id),"load-o-%05u",i);
    EdrError result=edr_storage_queue_enqueue(id,wire,n,0,0);free(wire);
    if(result==EDR_ERR_QUEUE_FULL)break;assert(result==EDR_OK);load_ordinary_rows++;
    if(!(i%64u)){EdrStorageQueueCapacityMetrics m;edr_storage_queue_get_capacity_metrics(&m);assert(m.physical_bytes<=UINT64_C(2147483648));if(m.physical_bytes>load_peak_observed)load_peak_observed=m.physical_bytes;}
  }
  assert(load_ordinary_rows>0u && load_ordinary_rows<4096u);
  EdrStorageQueueCapacityMetrics large=load_point(path,"large_ordinary_saturated",0u,0u);
  uint64_t gap=large.ordinary_limit_bytes-large.used_bytes;
  unsigned low=1u,high=EDR_PROCESS_COMMAND_FACT_CAP-1u,best=0u;
  char tail_id[64];snprintf(tail_id,sizeof(tail_id),"load-o-%05u",load_ordinary_rows);
  while(low<=high){unsigned mid=low+(high-low)/2u;size_t n=0u;uint8_t *wire=load_ordinary(load_ordinary_rows,mid,&n);free(wire);
    uint64_t cost=512u+strlen(tail_id)+n;if(cost<=gap){best=mid;low=mid+1u;}else high=mid-1u;}
  if(best){size_t n=0u;uint8_t *wire=load_ordinary(load_ordinary_rows,best,&n);
    assert(edr_storage_queue_enqueue(tail_id,wire,n,0,0)==EDR_OK);free(wire);load_ordinary_rows++;}
  size_t smallest_len=0u;uint8_t *smallest=load_ordinary(load_ordinary_rows,1u,&smallest_len);
  snprintf(tail_id,sizeof(tail_id),"load-o-%05u",load_ordinary_rows);
  assert(edr_storage_queue_enqueue(tail_id,smallest,smallest_len,0,0)==EDR_ERR_QUEUE_FULL);free(smallest);
  EdrStorageQueueCapacityMetrics saturated=load_point(path,"ordinary_saturated",0u,0u);
  assert(saturated.ordinary_rejected>0u && saturated.used_bytes<=saturated.ordinary_limit_bytes);
  char original[65],after[65];load_ordinary_digest(path,original);
  size_t max=EDR_PROCESS_COMMAND_FACT_CAP-1u;
  for(unsigned i=0u;i<LOAD_OWNERS+2u;i++){size_t n=!strcmp(profile,"short32")?32u:!strcmp(profile,"max32")?max:(i%2u?max:32u);load_make_owner(&load_owners[i],i,n);}
  for(unsigned example=0u;example<2u;example++){LoadOwner *o=&load_owners[example];
    size_t frame=o->local_intent_len+65552u;if(frame>EDR_EVENT_BATCH_CAP)frame=EDR_EVENT_BATCH_CAP;
    uint64_t precreate=1024u+15u+strlen(o->f.terminal_key)+strlen(o->f.source_event_id)+strlen(o->f.rule_id)+strlen(o->f.generation_key)+strlen(o->intent_id)+o->f.length[0]+2u*(frame+255u)+2048u;
    printf("{\"kind\":\"critical_load_encoding\",\"profile\":\"%s\",\"command_bytes_each\":%zu,\"intent_wire\":%zu,\"local_intent\":%zu,\"local_source\":%zu,\"combined\":%zu,\"precreate_charged\":%llu,\"immediate_intent_copy_charged\":%llu}\n",profile,o->command_bytes,o->f.length[0],o->local_intent_len,o->f.length[1],o->f.length[2],(unsigned long long)precreate,(unsigned long long)(512u+strlen(o->intent_id)+o->f.length[0]));fflush(stdout);}
  /* The first rejected command size is derived from the encoder's real cap. */
  EdrBehaviorRecord *invalid=calloc(1,sizeof(*invalid));char *too_large=malloc(EDR_PROCESS_COMMAND_FACT_CAP+1u);uint8_t *tmp=malloc(EDR_EVENT_BATCH_CAP);assert(invalid && too_large && tmp);
  memset(too_large,'X',EDR_PROCESS_COMMAND_FACT_CAP);too_large[EDR_PROCESS_COMMAND_FACT_CAP]=0;
  assert(!edr_behavior_record_encode_protobuf_full_facts(invalid,NULL,too_large,NULL,tmp,EDR_EVENT_BATCH_CAP));free(invalid);free(too_large);free(tmp);
  unsigned lanes[4]={0u,1u,2u,3u};
#ifdef _WIN32
  HANDLE threads[4];for(unsigned i=0;i<4u;i++){threads[i]=CreateThread(NULL,0,load_producer,&lanes[i],0,NULL);assert(threads[i]);}
#else
  pthread_t threads[4];for(unsigned i=0;i<4u;i++)assert(!pthread_create(&threads[i],NULL,load_producer,&lanes[i]));
#endif
  while(atomic_load_explicit(&load_ready,memory_order_acquire)!=4u){load_bound();}
  atomic_store_explicit(&load_go,1u,memory_order_release);
  for(unsigned i=0;i<4u;i++){
#ifdef _WIN32
    assert(WaitForMultipleObjects(1u,&threads[i],TRUE,30000u)==WAIT_OBJECT_0);assert(CloseHandle(threads[i]));
#else
    assert(!pthread_join(threads[i],NULL));
#endif
  }
  unsigned accepted=0u,rejected=0u,shorts=0u,longs=0u;LoadOwner *retry=NULL;
  for(unsigned i=0;i<LOAD_OWNERS;i++){LoadOwner *o=&load_owners[i];if(o->created){accepted++;if(o->command_bytes==32u)shorts++;else longs++;}
    else if(!retry)retry=o;
  }
  EdrEnforcementTerminalJournalMetrics jm;edr_storage_queue_enforcement_terminal_get_metrics(&jm);rejected=(unsigned)jm.precreate_rejected;
  assert(accepted>0u && rejected>0u && accepted<LOAD_OWNERS && jm.precreate_created==accepted && !jm.precreate_transaction_failures && !jm.precreate_commit_failures && !jm.precreate_conflicts && jm.pending==accepted);
  EdrStorageQueueCapacityMetrics held=load_point(path,"four_producer_intents_held",accepted,rejected);assert(held.high_priority_rejected>=rejected);
  printf("{\"kind\":\"critical_load_geometry\",\"profile\":\"%s\",\"ordinary_rows\":%u,\"ordinary_remaining_gap\":%llu,\"short_accepted\":%u,\"max_accepted\":%u,\"short_or_max_command_bytes\":%zu,\"intent_wire\":%zu,\"local_intent\":%zu,\"local_source\":%zu,\"combined\":%zu,\"held_used_increment\":%llu}\n",profile,load_ordinary_rows,(unsigned long long)(saturated.ordinary_limit_bytes-saturated.used_bytes),shorts,longs,load_owners[0].command_bytes,load_owners[0].f.length[0],load_owners[0].local_intent_len,load_owners[0].f.length[1],load_owners[0].f.length[2],(unsigned long long)(held.used_bytes-saturated.used_bytes));fflush(stdout);
  edr_storage_queue_close();assert(edr_storage_queue_open(path)==EDR_OK);assert(load_inventory(path)==held.used_bytes);load_point(path,"held_reopened_no_ack",accepted,rejected);
  for(unsigned i=0;i<LOAD_OWNERS;i++)if(load_owners[i].created){load_update(&load_owners[i]);load_source_check(path,&load_owners[i]);}
  load_point(path,"results_ready_no_ack",accepted,rejected);unsigned prior_attempts=load_attempts;
  for(unsigned poll=0u;poll<(load_ordinary_rows+127u)/128u+3u && load_attempts==prior_attempts;poll++)load_poll();assert(load_attempts>prior_attempts && !load_exact_acks);assert(!sql_number(path,"SELECT COALESCE(SUM(intent_acked+combined_acked+source_acked),0) FROM enforcement_terminal_journal;"));load_point(path,"no_ack_poll_retained",accepted,rejected);
  load_receipt_mode=2;edr_storage_queue_test_set_delivery_time(delivery+2);load_poll();assert(load_bad_acks>0u && !load_exact_acks);assert(!sql_number(path,"SELECT COALESCE(SUM(intent_acked+combined_acked+source_acked),0) FROM enforcement_terminal_journal;"));load_point(path,"wrong_ack_retained",accepted,rejected);
  edr_storage_queue_close();assert(edr_storage_queue_open(path)==EDR_OK);load_point(path,"wrong_ack_reopened",accepted,rejected);
  load_receipt_mode=1;
  for(unsigned poll=0u;poll<64u && sql_number(path,"SELECT COUNT(*) FROM enforcement_terminal_journal WHERE intent_acked=0 OR combined_acked=0;");poll++){load_bound();edr_storage_queue_test_set_delivery_time(delivery+3600+(int64_t)poll*60);load_poll();}
  assert(sql_number(path,"SELECT COUNT(*) FROM enforcement_terminal_journal WHERE state='local_retained' AND retention_policy_version=3 AND source_acked=0;")==accepted);assert(load_exact_acks==accepted*2u);
  for(unsigned i=0;i<LOAD_OWNERS;i++)if(load_owners[i].created)load_source_check(path,&load_owners[i]);
  load_point(path,"delayed_exact_ack_sources_retained",accepted,rejected);
  assert(retry);assert(edr_storage_queue_enforcement_terminal_precreate_local_source_bound(retry->f.terminal_key,retry->f.source_event_id,retry->f.rule_id,retry->f.generation_key,retry->intent_id,retry->f.wire[0],retry->f.length[0],retry->local_intent_len)==EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  retry->created=1;load_update(retry);load_source_check(path,retry);load_point(path,"rejected_owner_readmitted",accepted+1u,rejected);
  edr_storage_queue_close();assert(edr_storage_queue_open(path)==EDR_OK);load_source_check(path,retry);load_ordinary_digest(path,after);assert(!strcmp(original,after));load_point(path,"final_reopen_preserved",accepted+1u,rejected);
  printf("{\"kind\":\"critical_load_end\",\"profile\":\"%s\",\"producers\":4,\"attempts_bound\":64,\"ordinary_rows\":%u,\"accepted_before_results\":%u,\"rejected\":%u,\"readmitted\":1,\"necessary_exact_acks\":%u,\"wrong_acks_rejected\":%u,\"local_sources_acknowledged\":0,\"ordinary_sha256_before_after\":\"%s\",\"physical_observed_peak\":%llu,\"elapsed_s\":%.6f,\"ack_delay_seconds_virtual\":3600,\"network\":false,\"rule_or_action_executed\":false}\n",profile,load_ordinary_rows,accepted,rejected,load_exact_acks,load_bad_acks,original,(unsigned long long)load_peak_observed,(double)(edr_monotonic_ns()-load_started)/1e9);fflush(stdout);
  edr_storage_queue_close();edr_storage_queue_test_set_delivery_time(-1);for(unsigned i=0;i<LOAD_OWNERS+2u;i++)edr_test_p0_terminal_fixture_free(&load_owners[i].f);
  /* Preserve the synthetic DB for independent raw inventory/hash review. */
  return 0;
}

int main(int argc,char **argv) {
  if(argc==3 && !strcmp(argv[1],"--critical-reserve-load")) return critical_reserve_load(argv[2]);
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
  local_recovery_audit_capacity_and_handoff();
  local_group_capacity_replay_and_owner();
  terminal_typed_source_lifecycle();
  typed_local_real_codec(0);typed_local_real_codec(1);
  terminal_hold_and_independent_retry();
  historical_paired_alert_requires_original_intent_owner();
  historical_known_outcome_missing_intent_receipt();
  historic_projection_and_receipt(0); historic_projection_and_receipt(1);
  resource_preflight_defers_original_bytes();
  server_policy_hold_retains_lineage();
  multiversion_projection_receipts(0); multiversion_projection_receipts(1);
  for(int shape=0;shape<3;shape++) acknowledged_history_is_not_redelivered(shape);
  unresolved_foreign_capacity();
  process_crash_boundaries();
  puts("queue recovery: real codecs, immutable lineage, independent receipts, FULL rollback/restart passed");
  return 0;
}
