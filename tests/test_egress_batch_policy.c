#include "edr/egress_batch_policy.h"
#include "edr/behavior_proto.h"
#include "edr/detection_decision.h"
#include "edr/ave_sdk.h"
#include "edr/types.h"
#include "edr/transport_sink.h"
#include "cJSON.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "lz4.h"

static void wr(uint8_t *p, uint32_t n) {
  for (unsigned i=0; i<4; i++) p[i]=(uint8_t)(n>>(8*i));
}
static void make_record(EdrBehaviorRecord *r) {
  memset(r,0,sizeof(*r));
  r->type=EDR_EVENT_NET_CONNECT; r->pid=42; r->ppid=21;
  r->event_time_ns=1700000000000000000LL; r->priority=0;
  snprintf(r->event_id,sizeof(r->event_id),"synthetic-source");
  snprintf(r->endpoint_id,sizeof(r->endpoint_id),"synthetic-endpoint");
  snprintf(r->tenant_id,sizeof(r->tenant_id),"synthetic-tenant");
  snprintf(r->cmdline,sizeof(r->cmdline),"synthetic.exe --test-evidence");
  snprintf(r->parent_cmdline,sizeof(r->parent_cmdline),"synthetic-parent.exe --test");
  snprintf(r->net_dst,sizeof(r->net_dst),"127.0.0.1"); r->net_dport=443;
}
static void make_alert(AVEBehaviorAlert *a, const EdrBehaviorRecord *r) {
  memset(a,0,sizeof(*a)); a->pid=r->pid; a->timestamp_ns=r->event_time_ns;
  a->anomaly_score=0.7f; strcpy(a->triggered_tactics,"T1059");
  snprintf(a->user_subject_json,sizeof(a->user_subject_json),
    "{\"subject_type\":\"edr_dynamic_rule\",\"rule_id\":\"synthetic-rule\","
    "\"rules_bundle_version\":\"synthetic-v1\",\"rules_bundle_sha256\":\"%064d\","
    "\"context\":{\"pid\":42,\"event_type\":%d,\"source_event_id\":\"synthetic-source\","
    "\"endpoint_id\":\"synthetic-endpoint\",\"tenant_id\":\"synthetic-tenant\"}}",1,(int)r->type);
}
static void matrix(void) {
  EdrBehaviorRecord *r=calloc(1,sizeof(*r)); AVEBehaviorAlert a;
  uint8_t *frame=malloc(EDR_EGRESS_FRAME_MAX), *body=malloc(EDR_EGRESS_BATCH_MAX);
  uint8_t header[12]; char reason[128]; assert(r && frame && body);
  make_record(r); make_alert(&a,r);
  size_t ordinary=edr_behavior_record_encode_protobuf(r,frame,EDR_EGRESS_FRAME_MAX);
  assert(ordinary && !edr_egress_frame_validate(frame,ordinary,reason,sizeof(reason)));
  assert(!strcmp(reason,"alert_provenance_unavailable"));
  const char *negative[]={
    "{\"schema\":\"agent_decision_v1\",\"event_quality\":{\"score\":100,\"selection_action\":\"emit_alert\"}}",
    "{\"pmfe_scan\":false}","{\"pmfe_snapshot\":\"\"}","{\"notes\":\"pmfe\"}",
    "{\"p0_rule\":true}"};
  for (size_t i=0;i<sizeof(negative)/sizeof(negative[0]);i++) {
    strcpy(r->detection_context,negative[i]);
    size_t n=edr_behavior_record_encode_protobuf(r,frame,EDR_EGRESS_FRAME_MAX);
    assert(n && !edr_egress_frame_validate(frame,n,reason,sizeof(reason)));
  }
  r->detection_context[0]=0;
  size_t n=edr_behavior_record_alert_encode_protobuf(r,&a,frame,EDR_EGRESS_FRAME_MAX);
  assert(n && edr_egress_frame_validate(frame,n,reason,sizeof(reason)));
  /* The entire necessary context is retained byte-for-byte, including a real
   * loopback alert and both synthetic captured commands. */
  uint8_t *saved=malloc(n); assert(saved); memcpy(saved,frame,n);
  assert(edr_egress_frame_validate(frame,n,reason,sizeof(reason)) && !memcmp(saved,frame,n));
  strcpy(r->detection_context,"{\"schema\":\"agent_decision_v1\",\"reason\":\"prefix\\u0000hidden\"}");
  size_t invalid=edr_behavior_record_alert_encode_protobuf(r,&a,frame,EDR_EGRESS_FRAME_MAX);
  assert(!edr_egress_frame_validate(frame,invalid,reason,sizeof(reason)));
  assert(!strcmp(reason,"detection_context_invalid"));
  strcpy(r->detection_context,"{\"schema\":\"agent_decision_v1\",\"reason\":\"literal\\\\u0000\"}");
  invalid=edr_behavior_record_alert_encode_protobuf(r,&a,frame,EDR_EGRESS_FRAME_MAX);
  assert(edr_egress_frame_validate(frame,invalid,reason,sizeof(reason)));
  r->detection_context[0]=0;
  r->type=(EdrEventType)999;
  make_alert(&a,r);
  invalid=edr_behavior_record_alert_encode_protobuf(r,&a,frame,EDR_EGRESS_FRAME_MAX);
  assert(!edr_egress_frame_validate(frame,invalid,reason,sizeof(reason)));
  assert(!strcmp(reason,"event_purpose_unknown"));
  make_record(r); make_alert(&a,r); memcpy(frame,saved,n);
  cJSON *extra=cJSON_Parse(a.user_subject_json); assert(extra);
  cJSON_AddStringToObject(extra,"arbitrary_raw_event","synthetic-unrelated-context");
  char *extra_text=cJSON_PrintUnformatted(extra); assert(extra_text);
  snprintf(a.user_subject_json,sizeof(a.user_subject_json),"%s",extra_text);
  free(extra_text); cJSON_Delete(extra);
  invalid=edr_behavior_record_alert_encode_protobuf(r,&a,frame,EDR_EGRESS_FRAME_MAX);
  assert(!edr_egress_frame_validate(frame,invalid,reason,sizeof(reason)));
  make_alert(&a,r);
  strcpy(a.related_iocs_json,"{\"raw_event\":\"synthetic-unrelated-context\"}");
  invalid=edr_behavior_record_alert_encode_protobuf(r,&a,frame,EDR_EGRESS_FRAME_MAX);
  assert(!edr_egress_frame_validate(frame,invalid,reason,sizeof(reason)));
  make_alert(&a,r); memcpy(frame,saved,n);
  wr(header,EDR_TRANSPORT_BATCH_MAGIC_RAW); wr(header+4,1); wr(header+8,(uint32_t)n+4);
  wr(body,(uint32_t)n); memcpy(body+4,frame,n);
  assert(edr_egress_batch_validate(header,12,body,n+4,reason,sizeof(reason)));
  uint8_t *compressed=malloc(LZ4_compressBound((int)EDR_EGRESS_BATCH_MAX)); assert(compressed);
  int c=LZ4_compress_default((const char *)body,(char *)compressed,(int)n+4,LZ4_compressBound((int)n+4));
  assert(c>0); wr(header,EDR_TRANSPORT_BATCH_MAGIC_LZ4);
  assert(edr_egress_batch_validate(header,12,compressed,(size_t)c,reason,sizeof(reason)));
  wr(header,EDR_TRANSPORT_BATCH_MAGIC_RAW);
  /* Historical mixed batches are indivisible: no partial payload rewriting,
   * no silent loss of the admitted alert, and no old-ID replacement. */
  make_record(r); ordinary=edr_behavior_record_encode_protobuf(r,frame,EDR_EGRESS_FRAME_MAX);
  wr(body+n+4,(uint32_t)ordinary); memcpy(body+n+8,frame,ordinary);
  wr(header+4,2); wr(header+8,(uint32_t)(n+8+ordinary));
  assert(!edr_egress_batch_validate(header,12,body,n+8+ordinary,reason,sizeof(reason)));
  assert(!memcmp(body+4,saved,n));
  c=LZ4_compress_default((const char *)body,(char *)compressed,(int)(n+8+ordinary),LZ4_compressBound((int)EDR_EGRESS_BATCH_MAX));
  assert(c>0); wr(header,EDR_TRANSPORT_BATCH_MAGIC_LZ4);
  assert(!edr_egress_batch_validate(header,12,compressed,(size_t)c,reason,sizeof(reason)));
  wr(header,0xdeadbeef); assert(!edr_egress_batch_validate(header,12,body,n+4,reason,sizeof(reason)));
  assert(!strcmp(reason,"unknown_batch_format"));
  wr(header,EDR_TRANSPORT_BATCH_MAGIC_RAW); wr(header+4,1); wr(header+8,(uint32_t)n+4);
  memcpy(frame,saved,n); frame[n]=0xf8; frame[n+1]=0x07; frame[n+2]=0x01; /* unknown tag127 */
  assert(!edr_egress_frame_validate(frame,n+3,reason,sizeof(reason)));
  strcpy(r->detection_context,"{\"p0_disposition\":\"NOT_EVALUABLE\",\"stage\":\"pre_evaluation\"}");
  n=edr_behavior_record_alert_encode_protobuf(r,&a,frame,EDR_EGRESS_FRAME_MAX);
  assert(!edr_egress_frame_validate(frame,n,reason,sizeof(reason)));
  assert(!strcmp(reason,"source_only_requires_local_owner_v3"));
  r->detection_context[0]=0;
  strcpy(a.user_subject_json,"{\"subject_type\":\"p0_rule\",\"rule_id\":\"label-only\"}");
  n=edr_behavior_record_alert_encode_protobuf(r,&a,frame,EDR_EGRESS_FRAME_MAX);
  assert(!edr_egress_frame_validate(frame,n,reason,sizeof(reason)));
  strcpy(a.user_subject_json,
    "{\"subject_type\":\"detection_context\",\"detection_context\":{\"engine\":\"pmfe\","
    "\"rule_id\":\"pmfe_signal\",\"process\":{\"pid\":42},\"engine_signals\":{\"pmfe_confidence\":0,\"pmfe_pe_found\":false}}}");
  n=edr_behavior_record_alert_encode_protobuf(r,&a,frame,EDR_EGRESS_FRAME_MAX);
  assert(!edr_egress_frame_validate(frame,n,reason,sizeof(reason)));
  strcpy(a.user_subject_json,
    "{\"subject_type\":\"detection_context\",\"detection_context\":{\"engine\":\"pmfe\","
    "\"rule_id\":\"pmfe_signal\",\"process\":{\"pid\":42},\"engine_signals\":{\"pmfe_confidence\":0.9}}}");
  cJSON *subject=cJSON_Parse(a.user_subject_json); assert(subject);
  cJSON *basis=cJSON_AddObjectToObject(subject,"evaluation_basis"); assert(basis);
  cJSON_AddStringToObject(basis,"schema","agent_detection_basis_v1");
  cJSON_AddStringToObject(basis,"owner","ave_behavior_pipeline");
  cJSON_AddTrueToObject(basis,"predicate_matched"); cJSON_AddTrueToObject(basis,"threshold_met");
  cJSON_AddNumberToObject(basis,"pid",42); cJSON_AddStringToObject(basis,"timestamp_ns","1700000000000000000");
  cJSON_AddNumberToObject(basis,"threshold",0.65); cJSON_AddNumberToObject(basis,"event_count",5);
  cJSON_AddNumberToObject(basis,"last_event_type",13);
  cJSON_AddNumberToObject(basis,"behavior_flags",0);
  char *text=cJSON_PrintUnformatted(subject); assert(text);
  snprintf(a.user_subject_json,sizeof(a.user_subject_json),"%s",text); free(text); cJSON_Delete(subject);
  n=edr_behavior_record_alert_encode_protobuf(r,&a,frame,EDR_EGRESS_FRAME_MAX);
  assert(edr_egress_frame_validate(frame,n,reason,sizeof(reason)));
  /* A current zero hint cannot erase a real accumulated window detection. */
  subject=cJSON_Parse(a.user_subject_json); assert(subject);
  cJSON *ctx=cJSON_GetObjectItemCaseSensitive(subject,"detection_context");
  cJSON *signals=cJSON_GetObjectItemCaseSensitive(ctx,"engine_signals");
  cJSON_SetNumberValue(cJSON_GetObjectItemCaseSensitive(signals,"pmfe_confidence"),0);
  text=cJSON_PrintUnformatted(subject); assert(text);
  snprintf(a.user_subject_json,sizeof(a.user_subject_json),"%s",text); free(text); cJSON_Delete(subject);
  n=edr_behavior_record_alert_encode_protobuf(r,&a,frame,EDR_EGRESS_FRAME_MAX);
  assert(edr_egress_frame_validate(frame,n,reason,sizeof(reason)));
  subject=cJSON_Parse(a.user_subject_json); assert(subject);
  basis=cJSON_GetObjectItemCaseSensitive(subject,"evaluation_basis");
  cJSON_ReplaceItemInObjectCaseSensitive(basis,"predicate_matched",cJSON_CreateFalse());
  text=cJSON_PrintUnformatted(subject); assert(text);
  snprintf(a.user_subject_json,sizeof(a.user_subject_json),"%s",text); free(text); cJSON_Delete(subject);
  n=edr_behavior_record_alert_encode_protobuf(r,&a,frame,EDR_EGRESS_FRAME_MAX);
  assert(!edr_egress_frame_validate(frame,n,reason,sizeof(reason)));
  a.pid=43; n=edr_behavior_record_alert_encode_protobuf(r,&a,frame,EDR_EGRESS_FRAME_MAX);
  assert(!edr_egress_frame_validate(frame,n,reason,sizeof(reason)));
  /* No embedded alert is required when a typed local engine verdict contains
   * positive findings. A follow-up ID alone is insufficient. */
  make_record(r); r->type=EDR_EVENT_PMFE_SCAN_RESULT;
  strcpy(r->detection_context,
    "{\"rule_id\":\"agent_decision_v1\",\"process\":{\"pid\":42},\"engine_evidence\":{"
    "\"schema\":\"pmfe_result_v1\",\"detector\":\"pmfe\",\"status\":\"completed_suspicious\","
    "\"verdict\":\"suspicious\",\"signals\":{\"stomp_suspicious\":1}}}");
  n=edr_behavior_record_encode_protobuf(r,frame,EDR_EGRESS_FRAME_MAX);
  assert(edr_egress_frame_validate(frame,n,reason,sizeof(reason)));
  subject=cJSON_Parse(r->detection_context); assert(subject);
  ctx=cJSON_GetObjectItemCaseSensitive(subject,"engine_evidence");
  cJSON_ReplaceItemInObjectCaseSensitive(ctx,"status",cJSON_CreateString("completed_clean"));
  text=cJSON_PrintUnformatted(subject); assert(text);
  snprintf(r->detection_context,sizeof(r->detection_context),"%s",text); free(text); cJSON_Delete(subject);
  n=edr_behavior_record_encode_protobuf(r,frame,EDR_EGRESS_FRAME_MAX);
  assert(!edr_egress_frame_validate(frame,n,reason,sizeof(reason)));
  strcpy(r->detection_context,
    "{\"rule_id\":\"agent_decision_v1\",\"process\":{\"pid\":42},\"engine_evidence\":{"
    "\"schema\":\"pmfe_result_v1\",\"detector\":\"pmfe\",\"status\":\"completed_clean\","
    "\"verdict\":\"clean\",\"followup_only\":true,\"source_alert_id\":\"synthetic-verified-original-alert\"}}");
  n=edr_behavior_record_encode_protobuf(r,frame,EDR_EGRESS_FRAME_MAX);
  assert(!edr_egress_frame_validate(frame,n,reason,sizeof(reason)));
  /* Verify the actual context owner, whose root rule_id is its schema marker.
   * Do not hand-build a schema field absent from the production builder. */
  make_record(r); r->type=EDR_EVENT_PMFE_SCAN_RESULT;
  strcpy(r->script_snippet,"detector=pmfe\npmfe_status=completed_suspicious\npmfe_verdict=suspicious\nstomp_suspicious=1\n");
  EdrDetectionDecision decision;
  edr_detection_decision_evaluate(r,&decision);
  assert(!decision.drop);
  n=edr_behavior_record_encode_protobuf(r,frame,EDR_EGRESS_FRAME_MAX);
  assert(n && edr_egress_frame_validate(frame,n,reason,sizeof(reason)));
  strcpy(r->script_snippet,"detector=pmfe\npmfe_status=completed_clean\npmfe_verdict=clean\nstomp_suspicious=0\n");
  edr_detection_decision_evaluate(r,&decision);
  n=edr_behavior_record_encode_protobuf(r,frame,EDR_EGRESS_FRAME_MAX);
  assert(n && !edr_egress_frame_validate(frame,n,reason,sizeof(reason)));
  free(r); free(frame); free(body); free(saved); free(compressed);
}
int main(void) { matrix(); puts("egress batch policy: synthetic matrix passed"); return 0; }
