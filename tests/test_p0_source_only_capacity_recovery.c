/* Real producer + SQLite regression. Only authenticated-IR readiness and
 * unrelated action/network consumers are isolated. No installed Agent data. */
#include "edr/behavior_record.h"
#include "edr/behavior_alert_emit.h"
#include "edr/behavior_proto.h"
#include "edr/egress_batch_policy.h"
#include "edr/p0_rule_direct_emit.h"
#include "edr/p0_rule_ir.h"
#include "edr/sha256.h"
#include "edr/storage_queue.h"
#include "edr/transport_sink.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>
#ifdef _WIN32
#include <windows.h>
#include <process.h>
#define TEST_PID _getpid()
#else
#include <pthread.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#define TEST_PID getpid()
#endif

#ifdef _WIN32
static SRWLOCK barrier_mutex=SRWLOCK_INIT;
static CONDITION_VARIABLE barrier_condition=CONDITION_VARIABLE_INIT;
static void barrier_lock(void) {AcquireSRWLockExclusive(&barrier_mutex);}
static void barrier_unlock(void) {ReleaseSRWLockExclusive(&barrier_mutex);}
static void barrier_notify(void) {WakeAllConditionVariable(&barrier_condition);}
static void barrier_wait(void) {assert(SleepConditionVariableSRW(&barrier_condition,&barrier_mutex,30000,0));}
typedef HANDLE TestThread;
#define THREAD_ENTRY DWORD WINAPI
static TestThread start_thread(DWORD (WINAPI *entry)(void *),void *arg) {
  HANDLE h=CreateThread(NULL,0,entry,arg,0,NULL);assert(h);return h;
}
static void join_thread(TestThread h) {assert(WaitForSingleObject(h,30000)==WAIT_OBJECT_0);assert(CloseHandle(h));}
#else
static pthread_mutex_t barrier_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t barrier_condition=PTHREAD_COND_INITIALIZER;
static void barrier_lock(void) {assert(!pthread_mutex_lock(&barrier_mutex));}
static void barrier_unlock(void) {assert(!pthread_mutex_unlock(&barrier_mutex));}
static void barrier_notify(void) {assert(!pthread_cond_broadcast(&barrier_condition));}
static void barrier_wait(void) {
  struct timespec deadline;assert(timespec_get(&deadline,TIME_UTC)==TIME_UTC);deadline.tv_sec+=30;
  assert(!pthread_cond_timedwait(&barrier_condition,&barrier_mutex,&deadline));
}
typedef pthread_t TestThread;
#define THREAD_ENTRY void *
static TestThread start_thread(void *(*entry)(void *),void *arg) {
  pthread_t h;assert(!pthread_create(&h,NULL,entry,arg));return h;
}
static void join_thread(TestThread h) {assert(!pthread_join(h,NULL));}
#endif
static char pause_event[EDR_BR_ID_LEN];
static int wire_entered,release_wire,source_started;
#define AUDIT_ROW "retention_class=1 AND retention_policy_version=2 AND terminal_reason='source_only_local_recovery_v3'"
#define ORDINARY_ROW "retention_class=1 AND terminal_reason='source_only_local_v3'"

/* Reuse the existing explicitly non-production rule evaluator. Readiness is
 * available to the recovery probe, but no rule match or action is fabricated. */
#define edr_p0_rule_ir_is_ready unused_ir_is_ready
#define edr_p0_rule_ir_artifact_healthy unused_ir_artifact_healthy
#include "../src/preprocess/p0_rule_ir_stub.c"
#undef edr_p0_rule_ir_is_ready
#undef edr_p0_rule_ir_artifact_healthy
int edr_p0_rule_ir_is_ready(void) { return 1; }
int edr_p0_rule_ir_artifact_healthy(char *reason,size_t cap) {
  if(reason && cap) reason[0]=0;
  return 1;
}
void edr_adaptive_collection_raise(int severity,const char *rule,uint32_t pid,
    uint32_t parent,const char *name) {
  (void)severity;(void)rule;(void)pid;(void)parent;(void)name;
  assert(!"source-only capacity recovery cannot emit an alert");
}
void edr_local_evidence_cache_record_behavior(const EdrBehaviorRecord *r) { (void)r; }
bool edr_resource_preprocess_throttle_active(void) { return false; }
static unsigned sends;
int edr_ingest_http_configured(void) { return 1; }
int edr_ingest_http_circuit_open(void) { return 0; }
int edr_ingest_http_telemetry_deferred(void) { return 0; }
int edr_transport_v2_report_events(const char *id,const uint8_t *head,size_t hlen,
    const uint8_t *body,size_t len) {
  (void)id;(void)head;(void)hlen;(void)body;(void)len;
  ++sends; assert(!"local source facts must not be uploaded"); return -1;
}

/* Real protobuf/full-fact encoding with BAT1 framing. This adapter isolates
 * unrelated alert batching; its exact bytes are compared with durable rows. */
uint8_t *edr_behavior_record_alloc_durable_wire_facts(const EdrBehaviorRecord *r,
    const AVEBehaviorAlert *alert,const EdrCommandFacts *facts,size_t *length) {
  (void)facts;
  barrier_lock();
  if(pause_event[0] && !strcmp(pause_event,r->event_id)) {
    pause_event[0]=0;wire_entered=1;barrier_notify();
    while(!release_wire) barrier_wait();
  }
  barrier_unlock();
  uint8_t *wire=malloc(256u*1024u); assert(wire && !alert);
  size_t n=edr_behavior_record_encode_protobuf_full_facts(r,NULL,NULL,NULL,
      wire+16u,256u*1024u-16u); assert(n);
  uint32_t words[]={UINT32_C(0x31544142),1u,(uint32_t)n+4u,(uint32_t)n};
  for(unsigned i=0;i<4u;++i) for(unsigned j=0;j<4u;++j)
    wire[i*4u+j]=(uint8_t)(words[i]>>(j*8u));
  *length=n+16u; return wire;
}
uint8_t *edr_behavior_record_alloc_durable_wire(const EdrBehaviorRecord *r,
    const AVEBehaviorAlert *alert,size_t *length) {
  return edr_behavior_record_alloc_durable_wire_facts(r,alert,NULL,length);
}
uint8_t *edr_behavior_record_alloc_outbound_wire_facts(const EdrBehaviorRecord *r,
    const AVEBehaviorAlert *alert,const EdrCommandFacts *facts,size_t *length) {
  (void)r;(void)alert;(void)facts;(void)length;
  assert(!"source-only recovery cannot request an outbound projection"); return NULL;
}
int edr_behavior_durable_wire_batch_id(const char *kind,const uint8_t *wire,
    size_t length,char *out,size_t cap) {
  char hash[65]; assert(edr_sha256_hex(wire,length,hash)==0);
  int n=snprintf(out,cap,"%s-%s",kind,hash); return n>0 && (size_t)n<cap;
}
EdrBehaviorRecordAlertEmitOutcome edr_behavior_record_alert_emit_deferred(
    const EdrBehaviorRecord *r,const AVEBehaviorAlert *a,const char *key,const EdrCommandFacts *facts) {
  (void)r;(void)a;(void)key;(void)facts;
  assert(!"source-only recovery cannot publish a deferred alert");
  return EDR_BEHAVIOR_RECORD_ALERT_EMIT_PREPARE_OR_QUEUE_FAILED;
}
EdrBehaviorRecordAlertEmitOutcome edr_behavior_record_alert_emit_to_batch_with_prepare_outcome(
    const EdrBehaviorRecord *r,const AVEBehaviorAlert *a,EdrBehaviorRecordAlertPrepareFn fn,void *ctx) {
  (void)r;(void)a;(void)fn;(void)ctx;
  assert(!"source-only recovery cannot execute an alert action");
  return EDR_BEHAVIOR_RECORD_ALERT_EMIT_PREPARE_OR_QUEUE_FAILED;
}

static void record(EdrBehaviorRecord *r,unsigned index,int64_t now) {
  edr_behavior_record_init(r);r->type=EDR_EVENT_PROCESS_CREATE;r->priority=3;
  r->pid=1000u+index;r->ppid=4;r->event_time_ns=now*INT64_C(1000000000);
  r->process_start_key=10000u+index;
  r->process_creation_filetime_100ns=UINT64_C(133444444444444444)+index;
  snprintf(r->event_id,sizeof(r->event_id),"capacity-source-%u",index);
  strcpy(r->endpoint_id,"synthetic-endpoint");strcpy(r->tenant_id,"synthetic-tenant");
  strcpy(r->process_name,"synthetic.exe");
  memset(r->cmdline,'x',sizeof(r->cmdline)-1u);
  strcpy(r->detection_context,"{\"p0_disposition\":\"NOT_EVALUABLE\",\"source_contract_version\":\"p0-source-only-v2\",\"stage\":\"pre_evaluation\",\"gate_id\":\"P0_PROCESS_EVIDENCE_GATE\",\"reason\":\"evidence_enrichment_timeout\"}");
}
static int64_t scalar(sqlite3 *db,const char *sql) {
  sqlite3_stmt *st=NULL;assert(sqlite3_prepare_v2(db,sql,-1,&st,NULL)==SQLITE_OK);
  assert(sqlite3_step(st)==SQLITE_ROW);int64_t n=sqlite3_column_int64(st,0);
  assert(sqlite3_finalize(st)==SQLITE_OK);return n;
}
static void sql_exec(sqlite3 *db,const char *sql) {
  assert(sqlite3_exec(db,sql,NULL,NULL,NULL)==SQLITE_OK);
}
/* Hash every stored value, including its SQLite type and length. This is a
 * preservation witness for the frozen row and owner, not an ACK surrogate. */
static void source_row_sha(sqlite3 *db,const char *event_id,char sha[65]) {
  sqlite3_stmt *st=NULL;EdrSha256Ctx hash;uint8_t digest[32],number[8];
  assert(sqlite3_prepare_v2(db,"SELECT * FROM event_queue WHERE local_source_event_id=?",-1,&st,NULL)==SQLITE_OK);
  assert(sqlite3_bind_text(st,1,event_id,-1,SQLITE_STATIC)==SQLITE_OK);
  assert(sqlite3_step(st)==SQLITE_ROW);edr_sha256_init(&hash);
  for(int col=0;col<sqlite3_column_count(st);++col) {
    unsigned kind=(unsigned)sqlite3_column_type(st,col);
    const void *value=sqlite3_column_blob(st,col);int length=sqlite3_column_bytes(st,col);
    for(unsigned i=0;i<4u;++i) {number[i]=(uint8_t)(kind>>(i*8u));number[i+4u]=(uint8_t)((unsigned)length>>(i*8u));}
    edr_sha256_update(&hash,number,sizeof(number));
    if(length) edr_sha256_update(&hash,value,(size_t)length);
  }
  assert(sqlite3_step(st)==SQLITE_DONE);assert(sqlite3_finalize(st)==SQLITE_OK);
  edr_sha256_final(&hash,digest);static const char hex[]="0123456789abcdef";
  for(unsigned i=0;i<32u;++i) {sha[i*2u]=hex[digest[i]>>4];sha[i*2u+1u]=hex[digest[i]&15u];}sha[64]=0;
}
static void assert_local_only(sqlite3 *db) {
  assert(sends==0u && edr_storage_queue_pending_count()==0u);
  assert(scalar(db,"SELECT COUNT(*) FROM delivery_receipts_v1")==0);
  assert(scalar(db,"SELECT COUNT(*) FROM event_queue WHERE status!='local_evidence'")==0);
  sqlite3_stmt *st=NULL;assert(sqlite3_prepare_v2(db,"PRAGMA integrity_check",-1,&st,NULL)==SQLITE_OK);
  assert(sqlite3_step(st)==SQLITE_ROW && !strcmp((const char *)sqlite3_column_text(st,0),"ok"));
  assert(sqlite3_step(st)==SQLITE_DONE && sqlite3_finalize(st)==SQLITE_OK);
}
static void open_synthetic(const char *path,int64_t now) {
  FILE *prior=fopen(path,"rb");assert(!prior);
  edr_storage_queue_configure(1,1);edr_storage_queue_test_set_delivery_time(now);
  edr_storage_queue_test_set_local_retention_elapsed(0);
  assert(edr_storage_queue_open(path)==EDR_OK);
  edr_p0_rule_test_reset_dedup();edr_p0_rule_test_set_monotonic_ms(1000);
  edr_p0_rule_source_only_set_runtime_identity("synthetic-tenant","synthetic-endpoint");
  assert(edr_p0_rule_source_only_recover_after_queue_open()==1);
}
static unsigned fill_until_pending(int64_t now,EdrBehaviorRecord *record_out) {
  for(unsigned i=0;i<400u;++i) {
    record(record_out,i,now);
    int result=edr_p0_rule_emit_pre_evaluation_gate(record_out,"evidence_enrichment_timeout");
    if(result==2) {assert(i>0);return i;}
    assert(result==1 && edr_p0_rule_source_only_recover_after_queue_open()==1);
  }
  assert(!"synthetic ordinary lane must eventually refuse");return 0;
}
static void assert_exact_source(sqlite3 *db,const EdrBehaviorRecord *expected) {
  size_t length=0;uint8_t *wire=edr_behavior_record_alloc_durable_wire(expected,NULL,&length);
  sqlite3_stmt *st=NULL;
  assert(sqlite3_prepare_v2(db,"SELECT payload,local_pid,local_start_key,local_birth,local_endpoint_id,local_tenant_id,status "
      "FROM event_queue WHERE local_source_event_id=? AND retention_policy_version=2",-1,&st,NULL)==SQLITE_OK);
  assert(sqlite3_bind_text(st,1,expected->event_id,-1,SQLITE_STATIC)==SQLITE_OK);
  assert(sqlite3_step(st)==SQLITE_ROW);
  assert(sqlite3_column_bytes(st,0)==(int)length && !memcmp(sqlite3_column_blob(st,0),wire,length));
  char key[32],birth[32];snprintf(key,sizeof(key),"%llu",(unsigned long long)expected->process_start_key);
  snprintf(birth,sizeof(birth),"%llu",(unsigned long long)expected->process_creation_filetime_100ns);
  assert(sqlite3_column_int64(st,1)==expected->pid);
  assert(!strcmp((const char *)sqlite3_column_text(st,2),key));
  assert(!strcmp((const char *)sqlite3_column_text(st,3),birth));
  assert(!strcmp((const char *)sqlite3_column_text(st,4),expected->endpoint_id));
  assert(!strcmp((const char *)sqlite3_column_text(st,5),expected->tenant_id));
  assert(!strcmp((const char *)sqlite3_column_text(st,6),"local_evidence"));
  assert(sqlite3_step(st)==SQLITE_DONE);assert(sqlite3_finalize(st)==SQLITE_OK);free(wire);
}
typedef struct {EdrBehaviorRecord *record;int result,retry;} ProducerCall;
static THREAD_ENTRY producer_thread(void *opaque) {
  ProducerCall *call=opaque;
  if(!call->retry) {
    barrier_lock();source_started=1;barrier_notify();barrier_unlock();
  }
  call->result=call->retry ? edr_p0_rule_poll_source_only_durable_retry(call->record) :
    edr_p0_rule_emit_pre_evaluation_gate(call->record,"evidence_enrichment_timeout");
  return 0;
}
static void run_case(int concurrent,int overflow) {
  char path[256];snprintf(path,sizeof(path),"p0_capacity_recovery_%ld_%d_%d.db",(long)TEST_PID,concurrent,overflow);
  FILE *prior=fopen(path,"rb");assert(!prior);
  int64_t now=(int64_t)time(NULL);
  edr_storage_queue_configure(1,1);
  edr_storage_queue_test_set_delivery_time(now);
  edr_storage_queue_test_set_local_retention_elapsed(0);
  assert(edr_storage_queue_open(path)==EDR_OK);
  edr_p0_rule_test_reset_dedup();edr_p0_rule_test_set_monotonic_ms(1000);
  edr_p0_rule_source_only_set_runtime_identity("synthetic-tenant","synthetic-endpoint");
  assert(edr_p0_rule_source_only_recover_after_queue_open()==1);
  EdrBehaviorRecord *r=calloc(1,sizeof(*r)),*failed=calloc(9,sizeof(*failed));assert(r && failed);
  unsigned i;
  for(i=0;i<400u;++i) {
    record(r,i,now);
    int result=edr_p0_rule_emit_pre_evaluation_gate(r,"evidence_enrichment_timeout");
    if(result==2) {failed[0]=*r;break;}
    assert(result==1);
    assert(edr_p0_rule_source_only_recover_after_queue_open()==1);
  }
  assert(i>0 && i<400u);
  record(&failed[1],i+1u,now);
  if(!concurrent) assert(edr_p0_rule_emit_pre_evaluation_gate(&failed[1],"evidence_enrichment_timeout")==2);
  if(overflow) for(unsigned extra=2;extra<9u;++extra) {
    record(&failed[extra],i+extra,now);
    assert(edr_p0_rule_emit_pre_evaluation_gate(&failed[extra],"evidence_enrichment_timeout")== (extra==8u?0:2));
  }
  EdrP0EmitMetrics metrics;edr_p0_rule_get_emit_metrics(&metrics);
  assert(metrics.source_only_retry_pending==(overflow?8u:concurrent?1u:2u));
  if(overflow) assert(metrics.source_only_retry_capacity_exhausted==1u && metrics.source_only_loss_detected && metrics.source_only_terminal_unhealthy);
  assert(edr_p0_rule_poll_source_only_durable_retry(r)==0); /* Not due. */
  EdrStorageQueueP0SourceOnlyLatch latch;
  assert(edr_storage_queue_p0_source_only_latch_get(&latch)==EDR_OK);
  printf("before-expiry admitted=%u pending=%llu recovery_required=%d\n",i,
      (unsigned long long)metrics.source_only_retry_pending,latch.recovery_required);fflush(stdout);
  sqlite3 *db=NULL;assert(sqlite3_open(path,&db)==SQLITE_OK);
  int64_t original_rows=scalar(db,"SELECT COUNT(*) FROM event_queue WHERE retention_policy_version=2");
  assert(original_rows==(int64_t)i);
  if(!concurrent && !overflow) for(unsigned turn=0;turn<6u;++turn) {
    edr_p0_rule_test_set_monotonic_ms(1300u+turn*300u);
    assert(edr_p0_rule_poll_source_only_durable_retry(r)==0);
    assert(edr_storage_queue_p0_source_only_latch_get(&latch)==EDR_OK);
    assert(latch.latched && !latch.recovery_required);
    assert(scalar(db,"SELECT COUNT(*) FROM event_queue WHERE retention_policy_version=2")==original_rows);
  }
  if(overflow) {
    EdrStorageQueueP0SourceOnlyLatch before=latch;
    sql_exec(db,"CREATE TABLE test_source_latch_writes(n INTEGER NOT NULL); INSERT INTO test_source_latch_writes VALUES(0);"
        "CREATE TRIGGER test_source_latch_writes AFTER UPDATE OF source_latch_state ON queue_meta BEGIN "
        "UPDATE test_source_latch_writes SET n=n+1; END;");
    for(unsigned lost=0;lost<4u;++lost) {
      record(r,i+9u+lost,now);
      assert(edr_p0_rule_emit_pre_evaluation_gate(r,"evidence_enrichment_timeout")==0);
    }
    assert(scalar(db,"SELECT n FROM test_source_latch_writes")==0); /* No repeated FULL writes. */
    edr_p0_rule_get_emit_metrics(&metrics);assert(metrics.source_only_retry_capacity_exhausted==5u);
    edr_storage_queue_test_fail_next_p0_latch_commits(1u);
    assert(edr_p0_rule_source_only_recover_after_queue_open()==0);
    assert(edr_storage_queue_p0_source_only_latch_get(&latch)==EDR_OK);
    assert(latch.recovery_required && latch.latch_counter==before.latch_counter &&
        latch.latch_epoch==before.latch_epoch && !memcmp(latch.queue_nonce,before.queue_nonce,16u));
    assert(scalar(db,"SELECT COUNT(*) FROM event_queue WHERE " AUDIT_ROW)==0);
    edr_p0_rule_get_emit_metrics(&metrics);assert(metrics.source_only_retry_pending==8u);
    uint64_t failures=metrics.source_only_backpressure_failed;
    assert(edr_p0_rule_source_only_recover_after_queue_open()==0); /* Bounded backoff. */
    edr_p0_rule_get_emit_metrics(&metrics);assert(metrics.source_only_backpressure_failed==failures);
    edr_p0_rule_test_set_monotonic_ms(1300u);
    assert(edr_p0_rule_source_only_recover_after_queue_open()==0);
    assert(edr_storage_queue_p0_source_only_latch_get(&latch)==EDR_OK);
    assert(latch.latched && !latch.recovery_required && latch.latch_counter>before.latch_counter);
    assert(scalar(db,"SELECT COUNT(*) FROM event_queue WHERE " AUDIT_ROW)==1);
    assert(scalar(db,"SELECT COUNT(*) FROM event_queue WHERE " ORDINARY_ROW)==original_rows);
    edr_p0_rule_get_emit_metrics(&metrics);
    assert(metrics.source_only_retry_pending==8u && metrics.source_only_terminal_unhealthy);
  }
  edr_storage_queue_test_set_delivery_time(now+7200);
  edr_storage_queue_test_set_local_retention_elapsed(7200);
  if(concurrent) {
    edr_storage_queue_test_run_cleanup();
    edr_p0_rule_test_set_monotonic_ms(1300u);
    barrier_lock();strcpy(pause_event,failed[0].event_id);wire_entered=release_wire=source_started=0;barrier_unlock();
    ProducerCall retry={r,0,1},source={&failed[1],0,0};
    TestThread first=start_thread(producer_thread,&retry);
    barrier_lock();while(!wire_entered) barrier_wait();barrier_unlock();
    /* The state mutex remains available while durable I/O is in flight. */
    edr_p0_rule_get_emit_metrics(&metrics);assert(metrics.source_only_retry_pending==1u);
    TestThread second=start_thread(producer_thread,&source);
    barrier_lock();while(!source_started) barrier_wait();release_wire=1;barrier_notify();barrier_unlock();
    join_thread(first);join_thread(second);
    assert(retry.result==1 && source.result==1);
  }
  for(unsigned turn=0;turn<16u;++turn) {
    edr_storage_queue_test_run_cleanup();
    edr_p0_rule_test_set_monotonic_ms(10000u+turn*300u);
    (void)edr_p0_rule_source_only_recover_after_queue_open();
    while(edr_p0_rule_poll_source_only_durable_retry(r)) {}
    (void)edr_p0_rule_source_only_recover_after_queue_open();
  }
  edr_p0_rule_get_emit_metrics(&metrics);
  assert(edr_storage_queue_p0_source_only_latch_get(&latch)==EDR_OK);
  printf("after-expiry pending=%llu retry_committed=%llu recovery_required=%d rows=%lld\n",
      (unsigned long long)metrics.source_only_retry_pending,
      (unsigned long long)metrics.source_only_retry_committed,latch.recovery_required,
      (long long)scalar(db,"SELECT COUNT(*) FROM event_queue WHERE retention_policy_version=2"));fflush(stdout);
  if(overflow) {
    assert(metrics.source_only_retry_pending==0u && metrics.source_only_retry_committed==8u);
    assert(metrics.source_only_retry_capacity_exhausted==5u && metrics.source_only_loss_detected && !metrics.source_only_terminal_unhealthy);
    assert(!latch.latched);
    for(unsigned source=0u;source<8u;++source) assert_exact_source(db,&failed[source]);
    /* The audit was committed before the 2h advance. It shares the bounded
     * 1h local policy and may now retire after its successor is resolved. */
    assert(scalar(db,"SELECT COUNT(*) FROM event_queue WHERE " AUDIT_ROW)==0);
    assert(scalar(db,"SELECT local_retired_rows FROM queue_meta")>=original_rows+1);
    assert(scalar(db,"SELECT COUNT(*) FROM event_queue WHERE " ORDINARY_ROW)==8);
  } else {
    assert(metrics.source_only_retry_pending==0u);
    assert(metrics.source_only_retry_committed==(concurrent?1u:2u));
    assert(!latch.latched);
    assert_exact_source(db,&failed[0]);assert_exact_source(db,&failed[1]);
  }
  assert_local_only(db);
  sqlite3_close(db);edr_storage_queue_close();free(r);free(failed);
  assert(remove(path)==0);
}
/* A successful retry with another exact record still in RAM must leave its
 * successor prepared in that same FULL transaction, including a clean close. */
static void clean_close_with_pending(void) {
  char path[256],before[65],after[65];int64_t now=(int64_t)time(NULL);
  snprintf(path,sizeof(path),"p0_capacity_clean_close_%ld.db",(long)TEST_PID);open_synthetic(path,now);
  EdrBehaviorRecord *first=calloc(1,sizeof(*first)),*second=calloc(1,sizeof(*second)),*out=calloc(1,sizeof(*out));assert(first&&second&&out);
  unsigned admitted=fill_until_pending(now,first);record(second,admitted+1u,now);
  assert(edr_p0_rule_emit_pre_evaluation_gate(second,"evidence_enrichment_timeout")==2);
  edr_storage_queue_test_set_delivery_time(now+7200);edr_storage_queue_test_set_local_retention_elapsed(7200);
  edr_storage_queue_test_run_cleanup();edr_p0_rule_test_set_monotonic_ms(1300u);
  assert(edr_p0_rule_poll_source_only_durable_retry(out)==1 && !strcmp(out->event_id,first->event_id));
  EdrStorageQueueP0SourceOnlyLatch latch;EdrP0EmitMetrics metrics;
  assert(edr_storage_queue_p0_source_only_latch_get(&latch)==EDR_OK && latch.latched && !latch.recovery_required);
  edr_p0_rule_get_emit_metrics(&metrics);assert(metrics.source_only_retry_pending==1u && metrics.source_only_terminal_unhealthy);
  sqlite3 *db=NULL;assert(sqlite3_open(path,&db)==SQLITE_OK);
  assert_exact_source(db,first);source_row_sha(db,first->event_id,before);
  assert(scalar(db,"SELECT COUNT(*) FROM event_queue WHERE " AUDIT_ROW)==0);
  assert(sqlite3_close(db)==SQLITE_OK);edr_storage_queue_close();
  edr_p0_rule_test_reset_dedup();edr_p0_rule_test_force_source_only_startup();
  edr_p0_rule_test_set_monotonic_ms(2000u);
  edr_p0_rule_source_only_set_runtime_identity("synthetic-tenant","synthetic-endpoint");
  edr_storage_queue_test_set_local_retention_elapsed(0u); /* New monotonic lifetime. */
  assert(edr_storage_queue_open(path)==EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_get(&latch)==EDR_OK && latch.latched);
  assert(edr_p0_rule_source_only_recover_after_queue_open()==0);
  assert(edr_p0_rule_source_only_recover_after_queue_open()==1);
  assert(sqlite3_open(path,&db)==SQLITE_OK);source_row_sha(db,first->event_id,after);assert(!strcmp(before,after));
  assert_exact_source(db,first);assert(scalar(db,"SELECT COUNT(*) FROM event_queue WHERE " AUDIT_ROW)==1);
  assert(scalar(db,"SELECT COUNT(*) FROM event_queue WHERE " ORDINARY_ROW)==1);
  edr_p0_rule_get_emit_metrics(&metrics);assert(metrics.source_only_loss_detected && !metrics.source_only_terminal_unhealthy);
  assert_local_only(db);assert(sqlite3_close(db)==SQLITE_OK);edr_storage_queue_close();assert(remove(path)==0);
  free(first);free(second);free(out);
  puts("clean-close: pending successor survived; committed source row unchanged; missing RAM owner audited");
}

typedef struct {
  int64_t now;
  unsigned admitted;
  EdrStorageQueueP0SourceOnlyLatch successor;
  char audit_id[EDR_BR_ID_LEN],audit_row_sha[65];
} CrashCheckpoint;
static void crash_after_audit(const char *path) {
  int64_t now=(int64_t)time(NULL);open_synthetic(path,now);
  EdrBehaviorRecord *r=calloc(1,sizeof(*r));assert(r);CrashCheckpoint checkpoint={0};
  checkpoint.now=now;
  checkpoint.admitted=fill_until_pending(now,r);
  for(unsigned extra=1u;extra<9u;++extra) {
    record(r,checkpoint.admitted+extra,now);
    assert(edr_p0_rule_emit_pre_evaluation_gate(r,"evidence_enrichment_timeout")== (extra==8u?0:2));
  }
  assert(edr_p0_rule_source_only_recover_after_queue_open()==0);
  EdrP0EmitMetrics metrics;edr_p0_rule_get_emit_metrics(&metrics);
  assert(metrics.source_only_retry_pending==8u && metrics.source_only_loss_detected && metrics.source_only_terminal_unhealthy);
  assert(edr_storage_queue_p0_source_only_latch_get(&checkpoint.successor)==EDR_OK);
  assert(checkpoint.successor.latched && !checkpoint.successor.recovery_required);
  sqlite3 *db=NULL;sqlite3_stmt *st=NULL;assert(sqlite3_open(path,&db)==SQLITE_OK);
  assert(sqlite3_prepare_v2(db,"SELECT local_source_event_id FROM event_queue WHERE " AUDIT_ROW,-1,&st,NULL)==SQLITE_OK);
  assert(sqlite3_step(st)==SQLITE_ROW);snprintf(checkpoint.audit_id,sizeof(checkpoint.audit_id),"%s",sqlite3_column_text(st,0));
  assert(sqlite3_step(st)==SQLITE_DONE && sqlite3_finalize(st)==SQLITE_OK);
  source_row_sha(db,checkpoint.audit_id,checkpoint.audit_row_sha);assert_local_only(db);
  char receipt[280];snprintf(receipt,sizeof(receipt),"%s.checkpoint",path);FILE *file=fopen(receipt,"wb");assert(file);
  assert(fwrite(&checkpoint,sizeof(checkpoint),1,file)==1 && fclose(file)==0);
  /* Deliberately skip queue close, SQLite connection destruction, RAM drain
   * and all atexit handlers after the canonical audit FULL commit. */
  _Exit(95);
}
static void abrupt_restart_with_pending(void) {
  char path[256],receipt[280];snprintf(path,sizeof(path),"p0_capacity_crash_%ld.db",(long)TEST_PID);
  snprintf(receipt,sizeof(receipt),"%s.checkpoint",path);assert(!fopen(path,"rb") && !fopen(receipt,"rb"));
#ifdef _WIN32
  char executable[MAX_PATH],command[1600];DWORD n=GetModuleFileNameA(NULL,executable,sizeof(executable));
  assert(n && n<sizeof(executable));int length=snprintf(command,sizeof(command),"\"%s\" --crash-child \"%s\"",executable,path);
  assert(length>0 && (size_t)length<sizeof(command));STARTUPINFOA start={0};PROCESS_INFORMATION child={0};start.cb=sizeof(start);
  assert(CreateProcessA(executable,command,NULL,NULL,FALSE,0,NULL,NULL,&start,&child));
  DWORD waited=WaitForSingleObject(child.hProcess,30000);if(waited!=WAIT_OBJECT_0) assert(TerminateProcess(child.hProcess,96));
  assert(waited==WAIT_OBJECT_0);DWORD status=0;assert(GetExitCodeProcess(child.hProcess,&status) && status==95);
  assert(CloseHandle(child.hThread) && CloseHandle(child.hProcess));
#else
  pid_t child=fork();assert(child>=0);if(!child) {alarm(30);crash_after_audit(path);}
  int status=0;assert(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==95);
#endif
  CrashCheckpoint checkpoint={0};FILE *file=fopen(receipt,"rb");assert(file);
  assert(fread(&checkpoint,sizeof(checkpoint),1,file)==1 && fgetc(file)==EOF && fclose(file)==0);
  edr_p0_rule_test_reset_dedup();edr_p0_rule_test_force_source_only_startup();
  edr_p0_rule_test_set_monotonic_ms(10000u);edr_p0_rule_source_only_set_runtime_identity("synthetic-tenant","synthetic-endpoint");
  edr_storage_queue_configure(1,1);edr_storage_queue_test_set_delivery_time(checkpoint.now);
  edr_storage_queue_test_set_local_retention_elapsed(0u);assert(edr_storage_queue_open(path)==EDR_OK);
  EdrStorageQueueP0SourceOnlyLatch latch;assert(edr_storage_queue_p0_source_only_latch_get(&latch)==EDR_OK);
  assert(latch.latched && latch.latch_counter==checkpoint.successor.latch_counter &&
      latch.latch_epoch==checkpoint.successor.latch_epoch && !memcmp(latch.queue_nonce,checkpoint.successor.queue_nonce,16u));
  assert(edr_p0_rule_source_only_recover_after_queue_open()==0);
  assert(edr_p0_rule_source_only_recover_after_queue_open()==1);
  sqlite3 *db=NULL;assert(sqlite3_open(path,&db)==SQLITE_OK);char after[65];source_row_sha(db,checkpoint.audit_id,after);
  assert(!strcmp(after,checkpoint.audit_row_sha));
  assert(scalar(db,"SELECT COUNT(*) FROM event_queue WHERE " AUDIT_ROW)==2);
  assert(scalar(db,"SELECT COUNT(*) FROM event_queue WHERE " ORDINARY_ROW)==checkpoint.admitted);
  EdrP0EmitMetrics metrics;edr_p0_rule_get_emit_metrics(&metrics);
  assert(metrics.source_only_loss_detected && !metrics.source_only_terminal_unhealthy && !metrics.source_only_retry_pending);
  assert_local_only(db);assert(sqlite3_close(db)==SQLITE_OK);edr_storage_queue_close();
  assert(remove(path)==0 && remove(receipt)==0);
  puts("abrupt-restart: audit successor survived; first audit bytes/owner unchanged; eight lost RAM owners explicitly audited");
}
static void recreated_queue_with_pending(void) {
  char old_path[256],new_path[256];int64_t now=(int64_t)time(NULL);
  snprintf(old_path,sizeof(old_path),"p0_capacity_recreated_%ld_old.db",(long)TEST_PID);
  snprintf(new_path,sizeof(new_path),"p0_capacity_recreated_%ld_new.db",(long)TEST_PID);
  assert(!fopen(new_path,"rb"));open_synthetic(old_path,now);
  EdrBehaviorRecord *sources=calloc(9u,sizeof(*sources)),*out=calloc(1,sizeof(*out));assert(sources&&out);
  unsigned admitted=fill_until_pending(now,&sources[0]);
  for(unsigned i=1u;i<8u;++i) {
    record(&sources[i],admitted+i,now);
    assert(edr_p0_rule_emit_pre_evaluation_gate(&sources[i],"evidence_enrichment_timeout")==2);
  }
  EdrStorageQueueP0SourceOnlyLatch old_owner,latch;
  assert(edr_storage_queue_p0_source_only_latch_get(&old_owner)==EDR_OK);
  edr_storage_queue_close();
  /* The ninth assertion is genuinely lost while persistence is unavailable.
   * Reopening a new synthetic queue retains the same eight original records
   * in RAM, but supplies a new nonce and no durable loss owner yet. */
  record(&sources[8],admitted+8u,now);
  assert(edr_p0_rule_emit_pre_evaluation_gate(&sources[8],"evidence_enrichment_timeout")==0);
  assert(edr_storage_queue_open(new_path)==EDR_OK);
  sqlite3 *db=NULL;assert(sqlite3_open(new_path,&db)==SQLITE_OK);
  sql_exec(db,"CREATE TRIGGER test_second_prepare_abort BEFORE UPDATE OF source_latch_state ON queue_meta "
      "WHEN OLD.source_latch_state='prepared' AND NEW.source_latch_state='recovery_required' "
      "BEGIN SELECT RAISE(ABORT,'synthetic second prepare rollback'); END;");
  assert(edr_p0_rule_source_only_recover_after_queue_open()==0);
  assert(edr_storage_queue_p0_source_only_latch_get(&latch)==EDR_OK);
  assert(latch.latched && !latch.recovery_required && memcmp(latch.queue_nonce,old_owner.queue_nonce,16u));
  assert(scalar(db,"SELECT COUNT(*) FROM event_queue")==0);
  EdrP0EmitMetrics metrics;edr_p0_rule_get_emit_metrics(&metrics);
  assert(metrics.source_only_retry_pending==8u && metrics.source_only_loss_detected && metrics.source_only_terminal_unhealthy);
  edr_p0_rule_test_set_monotonic_ms(1300u);
  assert(edr_p0_rule_poll_source_only_durable_retry(out)==0); /* Failed second FULL is still fused. */
  sql_exec(db,"DROP TRIGGER test_second_prepare_abort;");
  assert(edr_p0_rule_source_only_recover_after_queue_open()==0);
  assert(scalar(db,"SELECT COUNT(*) FROM event_queue WHERE " AUDIT_ROW)==1);
  assert(edr_storage_queue_p0_source_only_latch_get(&latch)==EDR_OK && latch.latched && !latch.recovery_required);
  while(edr_p0_rule_poll_source_only_durable_retry(out)) {}
  assert(edr_p0_rule_source_only_recover_after_queue_open()==1);
  edr_p0_rule_get_emit_metrics(&metrics);
  assert(metrics.source_only_retry_committed==8u && !metrics.source_only_retry_pending && metrics.source_only_loss_detected);
  for(unsigned i=0;i<8u;++i) assert_exact_source(db,&sources[i]);
  assert(scalar(db,"SELECT COUNT(*) FROM event_queue WHERE " ORDINARY_ROW)==8);assert_local_only(db);
  assert(sqlite3_close(db)==SQLITE_OK);edr_storage_queue_close();
  assert(sqlite3_open(old_path,&db)==SQLITE_OK);
  assert(scalar(db,"SELECT COUNT(*) FROM event_queue")==admitted);
  assert(scalar(db,"SELECT source_latch_owner FROM queue_meta")==3);
  assert((uint64_t)scalar(db,"SELECT source_latch_counter FROM queue_meta")==old_owner.latch_counter);
  assert(sqlite3_close(db)==SQLITE_OK);assert(remove(old_path)==0 && remove(new_path)==0);
  free(sources);free(out);
  puts("queue-recreated: failed second FULL retained fuse; new nonce audited before eight exact RAM originals drained");
}
static void legacy_remote_owner_remains_protected(void) {
  char path[256];snprintf(path,sizeof(path),"p0_capacity_legacy_owner_%ld.db",(long)TEST_PID);
  int64_t now=(int64_t)time(NULL);open_synthetic(path,now);
  EdrStorageQueueP0SourceOnlyLatch before,after;
  assert(edr_storage_queue_p0_source_only_latch_prepare(&before)==EDR_OK && before.owner_version==2u);
  EdrBehaviorRecord *r=calloc(1,sizeof(*r));assert(r);
  for(unsigned i=0;i<9u;++i) {
    record(r,800u+i,now);
    assert(edr_p0_rule_emit_pre_evaluation_gate(r,"evidence_enrichment_timeout")== (i==8u?0:2));
  }
  edr_p0_rule_test_set_monotonic_ms(1300u);
  assert(edr_p0_rule_source_only_recover_after_queue_open()==0);
  assert(edr_p0_rule_poll_source_only_durable_retry(r)==0);
  assert(edr_storage_queue_p0_source_only_latch_get(&after)==EDR_OK);
  assert(after.latched && after.owner_version==2u && after.latch_counter==before.latch_counter &&
      after.latch_epoch==before.latch_epoch && !memcmp(after.queue_nonce,before.queue_nonce,16u));
  EdrP0EmitMetrics metrics;edr_p0_rule_get_emit_metrics(&metrics);
  assert(metrics.source_only_retry_pending==8u && metrics.source_only_loss_detected && metrics.source_only_terminal_unhealthy);
  sqlite3 *db=NULL;assert(sqlite3_open(path,&db)==SQLITE_OK);assert(scalar(db,"SELECT COUNT(*) FROM event_queue")==0);
  assert_local_only(db);assert(sqlite3_close(db)==SQLITE_OK);edr_storage_queue_close();assert(remove(path)==0);free(r);
  puts("legacy-v2: local retry/loss recovery preserved remote owner; no fabricated ACK or local conversion");
}
static void maximum_canonical_audit(void) {
  char endpoint[48],tenant[64],batch[128];uint8_t nonce[16];
  memset(endpoint,'e',sizeof(endpoint)-1u);endpoint[sizeof(endpoint)-1u]=0;
  memset(tenant,'t',sizeof(tenant)-1u);tenant[sizeof(tenant)-1u]=0;
  for(unsigned i=0;i<sizeof(nonce);++i) nonce[i]=(uint8_t)(i+1u);
  EdrBehaviorRecord *record_out=calloc(1,sizeof(*record_out));assert(record_out);
  edr_p0_rule_source_only_set_runtime_identity(tenant,endpoint);
  assert(edr_p0_rule_test_build_source_only_delivery_record(nonce,INT64_MAX,INT64_MAX,record_out));
  size_t length=0;uint8_t *wire=edr_behavior_record_alloc_durable_wire(record_out,NULL,&length);assert(length<=1040u);
  assert(edr_behavior_durable_wire_batch_id("p0-source",wire,length,batch,sizeof(batch)));
  EdrEgressP0LocalRecoveryAudit decoded;
  assert(edr_egress_p0_local_recovery_audit_decode(wire,length,record_out->event_id,batch,endpoint,tenant,&decoded));
  assert(decoded.latch_counter==INT64_MAX && decoded.latch_epoch==INT64_MAX && !memcmp(decoded.queue_nonce,nonce,sizeof(nonce)));
  printf("maximum canonical audit: tenant=%zu endpoint=%zu JSON=%zu RAW-BAT1=%zu bytes\n",strlen(tenant),strlen(endpoint),strlen(record_out->detection_context),length);
  free(wire);free(record_out);
}
int main(int argc,char **argv) {
  if(argc==3 && !strcmp(argv[1],"--crash-child")) {crash_after_audit(argv[2]);return 96;}
  assert(argc==1);
  run_case(0,0);run_case(1,0);run_case(0,1);
  clean_close_with_pending();abrupt_restart_with_pending();recreated_queue_with_pending();
  legacy_remote_owner_remains_protected();maximum_canonical_audit();
  puts("source-only capacity: exact retries, in-flight handoff and bounded loss-audit recovery converge without ACK/upload");
  return 0;
}
