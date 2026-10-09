#include "cJSON.h"
static int s_fail_parent_print;
static char *parent_print(const cJSON *object) {
  return s_fail_parent_print ? NULL : cJSON_PrintUnformatted(object);
}
/* Only the embedded production enrichment operation uses this I/O boundary.
 * The real encoder and JSON parser below remain unmodified. */
#define cJSON_PrintUnformatted parent_print
#include "../src/serialize/behavior_alert_emit.c"
#undef cJSON_PrintUnformatted
#include "edr/egress_batch_policy.h"
#include "edr/v1/event.pb.h"
#include "cJSON.h"
#include "pb_decode.h"
#include <assert.h>
int edr_policy_v2_alert_allowed(const char*a,const char*b){(void)a;(void)b;return 1;}
void edr_preprocess_copy_agent_ids(char*a,size_t an,char*b,size_t bn){snprintf(a,an,"synthetic-endpoint");snprintf(b,bn,"synthetic-tenant");}
static unsigned s_batch_calls, s_enqueue_calls;
int edr_event_batch_push(const uint8_t*a,size_t n){(void)a;(void)n;s_batch_calls++;return -1;}
int edr_storage_queue_is_open(void){return 0;}
EdrError edr_storage_queue_enqueue(const char*a,const uint8_t*b,size_t c,int d,int e){(void)a;(void)b;(void)c;(void)d;(void)e;s_enqueue_calls++;return EDR_ERR_SQLITE_WRITE;}
EdrError edr_storage_queue_p0_deferred_complete(const char*a,const char*b,const uint8_t*c,size_t d,const char*e){(void)a;(void)b;(void)c;(void)d;(void)e;return EDR_ERR_SQLITE_WRITE;}
#include "../src/ave/ave_lf_mpmc.h"

static const uint64_t now = 1700000000000000000ULL;
static const uint64_t birth = 133444735990000000ULL;
static void make_alert(AVEBehaviorAlert *a, uint32_t parent, uint8_t state,
                        uint64_t key, uint64_t created, int capture) {
  memset(a, 0, sizeof(*a));
  a->pid=42; a->ppid=parent; a->timestamp_ns=now; a->anomaly_score=.9f;
  snprintf(a->process_name,sizeof(a->process_name),"synthetic.exe");
  snprintf(a->process_path,sizeof(a->process_path),"C:/Synthetic/child.exe");
  strcpy(a->user_subject_json,"{\"subject_type\":\"detection_context\",\"detection_context\":{\"engine\":\"ave\",\"rule_id\":\"behavior_anomaly\",\"process\":{\"pid\":42,\"parent_pid\":0},\"engine_signals\":{}},\"evaluation_basis\":{\"schema\":\"agent_detection_basis_v1\",\"owner\":\"ave_behavior_pipeline\",\"predicate_matched\":true,\"threshold_met\":true,\"tactic_probs_computed\":false,\"pid\":42,\"timestamp_ns\":\"1700000000000000000\",\"threshold\":0.65,\"event_count\":1,\"last_event_type\":9,\"behavior_flags\":4294967295}}");
  cJSON *json=cJSON_Parse(a->user_subject_json); assert(json);
  cJSON *ctx=cJSON_GetObjectItemCaseSensitive(json,"detection_context");
  cJSON *process=cJSON_GetObjectItemCaseSensitive(ctx,"process");
  assert(cJSON_ReplaceItemInObjectCaseSensitive(process,"parent_pid",cJSON_CreateNumber(parent)));
  if(capture) {
    cJSON *p=cJSON_AddObjectToObject(json,"captured_process");assert(p);
    cJSON_AddNumberToObject(p,"pid",42);
    cJSON_AddNumberToObject(p,"parent_pid",parent);
    cJSON_AddNumberToObject(p,"parent_pid_state",state);
    char value[32];snprintf(value,sizeof(value),"%llu",(unsigned long long)key);
    cJSON_AddStringToObject(p,"process_start_key",value);
    snprintf(value,sizeof(value),"%llu",(unsigned long long)created);
    cJSON_AddStringToObject(p,"process_creation_filetime_100ns",value);
    cJSON_AddStringToObject(p,"source_event_id","synthetic-parent-source");
  }
  char *text=cJSON_PrintUnformatted(json);assert(text&&strlen(text)<sizeof(a->user_subject_json));
  memcpy(a->user_subject_json,text,strlen(text)+1);free(text);cJSON_Delete(json);
}
static void run_relation(const char *name, uint32_t source, uint8_t state,
                          uint64_t key, uint64_t created, int captured,
                          uint32_t cached, uint8_t cache_state, int expired,
                          uint32_t expected, uint8_t expected_state) {
  edr_pt_cache_init();
  assert(edr_pt_cache_put_generation_with_parent_state(42,cached,"synthetic.exe",NULL,
    "C:/Synthetic/child.exe",NULL,now-1000000000ULL,111,birth,0,cache_state)==0);
  if(expired) assert(edr_pt_cache_mark_exit_generation(42,111,now-1u)==0);
  AVEBehaviorAlert a;make_alert(&a,source,state,key,created,captured);
  assert(enrich_alert_process_snapshot(&a));
  uint8_t *frame=malloc(EDR_EGRESS_FRAME_MAX);edr_v1_BehaviorEvent *wire=calloc(1,sizeof(*wire));assert(frame&&wire);
  size_t n=edr_behavior_alert_encode_protobuf(&a,"synthetic-endpoint","synthetic-tenant",frame,EDR_EGRESS_FRAME_MAX);assert(n);
  pb_istream_t stream=pb_istream_from_buffer(frame,n);assert(pb_decode(&stream,edr_v1_BehaviorEvent_fields,wire));
  assert(a.ppid==expected&&wire->ppid==expected&&wire->has_parent_pid_state&&wire->parent_pid_state==expected_state);
  cJSON *json=cJSON_Parse(wire->behavior_alert.user_subject_json);assert(json);
  cJSON *ctx=cJSON_GetObjectItemCaseSensitive(json,"detection_context");
  cJSON *process=cJSON_GetObjectItemCaseSensitive(ctx,"process");
  assert(cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(process,"parent_pid"))==expected);
  assert(!cJSON_GetObjectItemCaseSensitive(json,"captured_process"));
  assert(!strstr(wire->behavior_alert.user_subject_json,"synthetic-parent-source"));
  assert(edr_egress_frame_validate(frame,n,NULL,0));
  assert(!wire->process_context.has_parent_cmdline&&!wire->process_context.has_current_directory);
  printf("parent %s: source=%u/%u cache=%u/%u wire=%u/%u json=%u bytes=%zu\n",
    name,source,state,cached,cache_state,wire->ppid,wire->parent_pid_state,expected,n);
  cJSON_Delete(json);free(wire);free(frame);edr_pt_cache_shutdown();
}
static void queue_capture_is_owned_and_bounded(void) {
  AveMpmcQueue *q=NULL;assert(ave_mpmc_init(&q,2u)==0);
  EdrAveQueuedEvent a={0},b={0},out={0};
  a.event.pid=a.process.pid=42;a.process.parent_pid=299;a.process.parent_pid_state=EDR_PARENT_PID_CONFLICT;
  a.process.process_start_key=111;a.process.process_creation_filetime_100ns=birth;
  snprintf(a.process.source_event_id,sizeof(a.process.source_event_id),"captured-a");
  b=a;b.process.parent_pid_state=EDR_PARENT_PID_KNOWN;b.process.process_start_key=222;
  assert(ave_mpmc_try_push(q,&a)==0);assert(ave_mpmc_try_push(q,&b)==0);
  assert(ave_mpmc_try_push(q,&a)==-1);assert(ave_mpmc_approx_depth(q)==2u);
  memset(&a,0xff,sizeof(a));memset(&b,0xff,sizeof(b));
  assert(ave_mpmc_try_pop(q,&out)==0&&out.event.pid==42&&out.process.process_start_key==111&&
    out.process.parent_pid_state==EDR_PARENT_PID_CONFLICT&&!strcmp(out.process.source_event_id,"captured-a"));
  assert(ave_mpmc_try_pop(q,&out)==0&&out.process.process_start_key==222&&out.process.parent_pid_state==EDR_PARENT_PID_KNOWN);
  assert(ave_mpmc_try_pop(q,&out)==-1);ave_mpmc_destroy(q);
  puts("queue capture: copies, FIFO, full refusal passed");
}
static void conflict_remains_with_tree_owner(void) {
  edr_pt_cache_init();
  assert(edr_pt_cache_put_generation_with_parent_state(42,299,"synthetic.exe",NULL,
    "C:/Synthetic/child.exe",NULL,now-1000000000ULL,111,birth,0,EDR_PARENT_PID_KNOWN)==0);
  AVEBehaviorAlert first, next;
  make_alert(&first,777,EDR_PARENT_PID_KNOWN,111,birth,1);
  assert(enrich_alert_process_snapshot(&first));
  EdrAveProcessIdentity identity;
  assert(edr_behavior_alert_process_identity(&first,&identity)==1&&
    identity.parent_pid==777&&identity.parent_pid_state==EDR_PARENT_PID_CONFLICT);
  ProcessTreeEntry snapshot;
  assert(edr_pt_cache_snapshot_generation_at(42,111,now,&snapshot)==0&&
    snapshot.ppid==299&&snapshot.parent_pid_state==EDR_PARENT_PID_CONFLICT);
  make_alert(&next,0,EDR_PARENT_PID_UNKNOWN,111,birth,1);
  assert(enrich_alert_process_snapshot(&next));
  assert(edr_behavior_alert_process_identity(&next,&identity)==1&&
    identity.parent_pid==299&&identity.parent_pid_state==EDR_PARENT_PID_CONFLICT);
  puts("sticky conflict: first=777/CONFLICT cache=299/CONFLICT next=299/CONFLICT");
  edr_pt_cache_shutdown();
}
static void failed_parent_projection_cannot_emit(int capacity_failure) {
  edr_pt_cache_init();
  assert(edr_pt_cache_put_generation_with_parent_state(42,capacity_failure?UINT32_MAX:299,
    "synthetic.exe",NULL,"C:/Synthetic/child.exe",NULL,now-1000000000ULL,
    111,birth,0,EDR_PARENT_PID_KNOWN)==0);
  AVEBehaviorAlert alert;
  make_alert(&alert,capacity_failure?0:777,capacity_failure?EDR_PARENT_PID_UNKNOWN:EDR_PARENT_PID_KNOWN,
    111,birth,1);
  if (capacity_failure) {
    cJSON *json=cJSON_Parse(alert.user_subject_json);assert(json);
    cJSON_AddStringToObject(json,"padding","");
    char *base=cJSON_PrintUnformatted(json);assert(base);
    size_t padding_size=sizeof(alert.user_subject_json)-5u-strlen(base);
    free(base);
    char *padding=malloc(padding_size+1u);assert(padding);
    memset(padding,'x',padding_size);padding[padding_size]=0;
    assert(cJSON_ReplaceItemInObjectCaseSensitive(json,"padding",cJSON_CreateString(padding)));
    free(padding);
    char *text=cJSON_PrintUnformatted(json);assert(text&&strlen(text)<sizeof(alert.user_subject_json));
    memcpy(alert.user_subject_json,text,strlen(text)+1u);free(text);cJSON_Delete(json);
  }
  s_fail_parent_print=!capacity_failure;
  AVEBehaviorAlert copy=alert;
  assert(!enrich_alert_process_snapshot(&copy));
  assert(!memcmp(&alert,&copy,sizeof(alert)));
  EdrBehaviorRecord *record=calloc(1,sizeof(*record));assert(record);
  record->pid=42;record->event_time_ns=now;
  unsigned before_batch=s_batch_calls,before_enqueue=s_enqueue_calls;
  edr_alert_governor_reset_for_test();
  edr_behavior_alert_emit_to_batch(&alert);
  assert(edr_behavior_record_alert_emit_to_batch_with_prepare_outcome(record,&alert,NULL,NULL)==
    EDR_BEHAVIOR_RECORD_ALERT_EMIT_PREPARE_OR_QUEUE_FAILED);
  assert(s_batch_calls==before_batch&&s_enqueue_calls==before_enqueue);
  if (!capacity_failure) {
    ProcessTreeEntry snapshot;
    assert(edr_pt_cache_snapshot_generation_at(42,111,now,&snapshot)==0&&
      snapshot.ppid==299&&snapshot.parent_pid_state==EDR_PARENT_PID_CONFLICT);
  }
  s_fail_parent_print=0;
  free(record);edr_pt_cache_shutdown();
  printf("parent projection %s: helper rejected, raw/combined queued=0, no fallback success\n",
    capacity_failure?"capacity failure":"JSON allocation failure");
}
static unsigned s_json_allocations, s_json_fail_allocation;
static void *parent_json_allocate(size_t bytes) {
  return ++s_json_allocations == s_json_fail_allocation ? NULL : malloc(bytes);
}
static void begin_parent_json_allocation_failure(unsigned nth) {
  cJSON_Hooks hooks={parent_json_allocate,free};
  s_json_allocations=0;s_json_fail_allocation=nth;cJSON_InitHooks(&hooks);
}
static void parser_allocation_failure_is_not_legacy_absence(void) {
  AVEBehaviorAlert alert;
  make_alert(&alert,299,EDR_PARENT_PID_CONFLICT,111,birth,1);
  AVEBehaviorAlert original=alert;
  uint8_t *frame=malloc(EDR_EGRESS_FRAME_MAX);assert(frame);
  begin_parent_json_allocation_failure(1u);
  size_t bytes=edr_behavior_alert_encode_protobuf(&alert,"synthetic-endpoint",
    "synthetic-tenant",frame,EDR_EGRESS_FRAME_MAX);
  cJSON_InitHooks(NULL);
  assert(bytes==0u&&!memcmp(&alert,&original,sizeof(alert)));
  free(frame);
  puts("capture parser allocation failure: CONFLICT rejected, no legacy KNOWN frame");
}
static void real_parent_allocation_failure_cannot_emit(void) {
  edr_pt_cache_init();
  assert(edr_pt_cache_put_generation_with_parent_state(42,299,"synthetic.exe",NULL,
    "C:/Synthetic/child.exe",NULL,now-1000000000ULL,111,birth,0,EDR_PARENT_PID_KNOWN)==0);
  AVEBehaviorAlert alert;
  make_alert(&alert,777,EDR_PARENT_PID_KNOWN,111,birth,1);
  AVEBehaviorAlert copy=alert;
  /* Fail the first actual allocation after the initial capture parse. Derive
   * its position so the regression does not depend on parser allocation count. */
  EdrAveProcessIdentity identity;
  begin_parent_json_allocation_failure(0u);
  int captured=edr_behavior_alert_process_identity(&alert,&identity);
  unsigned rebuild_allocation=s_json_allocations+1u;
  cJSON_InitHooks(NULL);
  assert(captured==1);
  begin_parent_json_allocation_failure(rebuild_allocation);
  int enriched=enrich_alert_process_snapshot(&copy);
  cJSON_InitHooks(NULL);
  assert(!enriched&&!memcmp(&alert,&copy,sizeof(alert)));
  ProcessTreeEntry snapshot;
  assert(edr_pt_cache_snapshot_generation_at(42,111,now,&snapshot)==0&&
    snapshot.ppid==299&&snapshot.parent_pid_state==EDR_PARENT_PID_CONFLICT);
  unsigned before_batch=s_batch_calls,before_enqueue=s_enqueue_calls;
  edr_alert_governor_reset_for_test();
  begin_parent_json_allocation_failure(rebuild_allocation);
  edr_behavior_alert_emit_to_batch(&alert);
  cJSON_InitHooks(NULL);
  EdrBehaviorRecord *record=calloc(1,sizeof(*record));assert(record);
  record->pid=42;record->event_time_ns=now;
  begin_parent_json_allocation_failure(rebuild_allocation);
  EdrBehaviorRecordAlertEmitOutcome outcome=
    edr_behavior_record_alert_emit_to_batch_with_prepare_outcome(record,&alert,NULL,NULL);
  cJSON_InitHooks(NULL);
  assert(outcome==EDR_BEHAVIOR_RECORD_ALERT_EMIT_PREPARE_OR_QUEUE_FAILED&&
    s_batch_calls==before_batch&&s_enqueue_calls==before_enqueue);
  free(record);edr_pt_cache_shutdown();
  printf("actual cJSON allocation %u failed: helper rejected, sticky CONFLICT, raw/combined queued=0\n",
    rebuild_allocation);
}
int main(void) {
  run_relation("legacy_no_capture",0,0,0,0,0,299,EDR_PARENT_PID_KNOWN,0,0,EDR_PARENT_PID_UNKNOWN);
  run_relation("legacy_conflict_cache",0,0,0,0,0,299,EDR_PARENT_PID_CONFLICT,0,0,EDR_PARENT_PID_UNKNOWN);
  run_relation("exact_unknown_completion",0,0,111,birth,1,299,EDR_PARENT_PID_KNOWN,0,299,EDR_PARENT_PID_KNOWN);
  run_relation("exact_conflict_cache",0,0,111,birth,1,299,EDR_PARENT_PID_CONFLICT,0,299,EDR_PARENT_PID_CONFLICT);
  run_relation("source_conflict_retained",299,4,111,birth,1,299,EDR_PARENT_PID_KNOWN,0,299,EDR_PARENT_PID_CONFLICT);
  run_relation("cache_unknown_not_erasing",299,1,111,birth,1,0,EDR_PARENT_PID_UNKNOWN,0,299,EDR_PARENT_PID_KNOWN);
  run_relation("known_disagreement",299,1,111,birth,1,777,EDR_PARENT_PID_KNOWN,0,299,EDR_PARENT_PID_CONFLICT);
  run_relation("explicit_zero_disagreement",0,2,111,birth,1,299,EDR_PARENT_PID_KNOWN,0,0,EDR_PARENT_PID_CONFLICT);
  run_relation("invalid_retained",0,3,111,birth,1,299,EDR_PARENT_PID_KNOWN,0,0,EDR_PARENT_PID_INVALID);
  run_relation("no_birth",0,0,111,0,1,299,EDR_PARENT_PID_KNOWN,0,0,EDR_PARENT_PID_UNKNOWN);
  run_relation("no_key",0,0,0,birth,1,299,EDR_PARENT_PID_KNOWN,0,0,EDR_PARENT_PID_UNKNOWN);
  run_relation("wrong_key",0,0,222,birth,1,299,EDR_PARENT_PID_KNOWN,0,0,EDR_PARENT_PID_UNKNOWN);
  run_relation("wrong_birth",0,0,111,birth+1,1,299,EDR_PARENT_PID_KNOWN,0,0,EDR_PARENT_PID_UNKNOWN);
  run_relation("event_before_birth",0,0,111,birth+20000000,1,299,EDR_PARENT_PID_KNOWN,0,0,EDR_PARENT_PID_UNKNOWN);
  run_relation("expired_lifetime",0,0,111,birth,1,299,EDR_PARENT_PID_KNOWN,1,0,EDR_PARENT_PID_UNKNOWN);
  queue_capture_is_owned_and_bounded();
  conflict_remains_with_tree_owner();
  failed_parent_projection_cannot_emit(0);
  failed_parent_projection_cannot_emit(1);
  parser_allocation_failure_is_not_legacy_absence();
  real_parent_allocation_failure_cannot_emit();
  return 0;
}
