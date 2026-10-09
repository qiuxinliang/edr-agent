#include "edr/egress_batch_policy.h"
#include "edr/evidence_projection.h"
#include "edr/behavior_proto.h"
#include "edr/detection_decision.h"
#include "edr/ave_sdk.h"
#include "edr/types.h"
#include "edr/transport_sink.h"
#include "edr/v1/event.pb.h"
#include "cJSON.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "lz4.h"
#include <pb_decode.h>
#include <pb_encode.h>

static int synthetic_projection_owner(const char *,const char *,uint64_t,const char *,void *);

static edr_v1_BehaviorEvent *decode_frame(const uint8_t *frame,size_t len) {
  edr_v1_BehaviorEvent *event=calloc(1,sizeof(*event)); assert(event);
  pb_istream_t stream=pb_istream_from_buffer(frame,len);
  assert(pb_decode(&stream,edr_v1_BehaviorEvent_fields,event)); return event;
}
/* Immutable historical wire tests deliberately bypass the new producer
 * projector. Otherwise removing an injected extra before serialization would
 * not exercise the final send-time whitelist. */
static size_t immutable_encode(edr_v1_BehaviorEvent *event,uint8_t *frame) {
  pb_ostream_t stream=pb_ostream_from_buffer(frame,EDR_EGRESS_FRAME_MAX);
  assert(pb_encode(&stream,edr_v1_BehaviorEvent_fields,event)); return stream.bytes_written;
}

static void wr(uint8_t *p, uint32_t n) {
  for (unsigned i=0; i<4; i++) p[i]=(uint8_t)(n>>(8*i));
}
static void make_record(EdrBehaviorRecord *r) {
  memset(r,0,sizeof(*r));
  r->tactic_probability_state=1;
  r->evidence_projection_version=EDR_EVIDENCE_PROJECTION_VERSION;
  r->required_evidence_fields=EDR_EVIDENCE_COMMAND|EDR_EVIDENCE_PARENT_COMMAND|EDR_EVIDENCE_NETWORK;
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
  assert(invalid && edr_egress_frame_validate(frame,invalid,reason,sizeof(reason)));
  edr_v1_BehaviorEvent *decoded=decode_frame(frame,invalid);
  assert(!strstr(decoded->behavior_alert.user_subject_json,"arbitrary_raw_event"));
  /* Sending the old opaque bytes is still forbidden. */
  strcpy(decoded->behavior_alert.user_subject_json,a.user_subject_json);
  invalid=immutable_encode(decoded,frame); free(decoded);
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
static void overwrite_json(char *dest,size_t cap,cJSON *root) {
  char *text=cJSON_PrintUnformatted(root); assert(text && strlen(text)<cap);
  strcpy(dest,text); free(text);
}
static void purpose_masks(void) {
  EdrBehaviorRecord *r=calloc(1,sizeof(*r)); AVEBehaviorAlert a;
  uint8_t *frame=malloc(EDR_EGRESS_FRAME_MAX); char reason[128]; assert(r && frame);
  make_record(r); make_alert(&a,r);
  strcpy(r->detection_context,"{\"engine\":\"agent\",\"reason\":\"synthetic-local-only-diagnostic\"}");
  cJSON *subject=cJSON_Parse(a.user_subject_json); assert(subject);
  cJSON *ctx=cJSON_GetObjectItemCaseSensitive(subject,"context");
  cJSON_AddStringToObject(ctx,"cmdline","synthetic-duplicate-command");
  cJSON_AddStringToObject(ctx,"hostname","synthetic-unnecessary-host");
  cJSON_AddStringToObject(ctx,"file_identity","synthetic-volume:file");
  cJSON_AddStringToObject(ctx,"process_start_key","18446744073709551615");
  r->process_start_key=UINT64_MAX;
  cJSON_AddStringToObject(ctx,"powershell_script_block","synthetic-rule-trigger");
  cJSON *enforcement=cJSON_AddObjectToObject(subject,"enforcement");
  cJSON_AddTrueToObject(enforcement,"requested"); cJSON_AddFalseToObject(enforcement,"succeeded");
  cJSON_AddStringToObject(enforcement,"action","terminate_process");
  cJSON_AddNumberToObject(enforcement,"error_code",5);
  cJSON_AddStringToObject(enforcement,"message","synthetic-local-only-error-detail");
  overwrite_json(a.user_subject_json,sizeof(a.user_subject_json),subject); cJSON_Delete(subject);
  size_t n=edr_behavior_record_alert_encode_protobuf(r,&a,frame,EDR_EGRESS_FRAME_MAX);
  assert(n && edr_egress_frame_validate(frame,n,reason,sizeof(reason)));
  edr_v1_BehaviorEvent *ev=decode_frame(frame,n);
  assert(!ev->ave_result_json[0] && !ev->has_ave_behavior_feed);
  assert(!strcmp(ev->cmdline,r->cmdline));
  assert(ev->has_process_context && !strcmp(ev->process_context.parent_cmdline,r->parent_cmdline));
  assert(ev->process_start_key==UINT64_MAX);
  assert(strstr(ev->behavior_alert.user_subject_json,"synthetic-volume:file"));
  assert(!strstr(ev->behavior_alert.user_subject_json,"synthetic-rule-trigger"));
  assert(strstr(ev->behavior_alert.user_subject_json,"18446744073709551615"));
  assert(!strstr(ev->behavior_alert.user_subject_json,"synthetic-duplicate-command"));
  assert(!strstr(ev->behavior_alert.user_subject_json,"synthetic-unnecessary-host"));
  assert(!strstr(ev->behavior_alert.user_subject_json,"synthetic-local-only-error-detail"));
  assert(strstr(r->detection_context,"synthetic-local-only-diagnostic"));
  subject=cJSON_Parse(ev->behavior_alert.user_subject_json); assert(subject);
  ctx=cJSON_GetObjectItemCaseSensitive(subject,"context");
  cJSON_ReplaceItemInObjectCaseSensitive(ctx,"file_identity",cJSON_CreateObject());
  overwrite_json(ev->behavior_alert.user_subject_json,sizeof(ev->behavior_alert.user_subject_json),subject);
  cJSON_Delete(subject); n=immutable_encode(ev,frame);
  assert(!edr_egress_frame_validate(frame,n,reason,sizeof(reason)));
  assert(!strcmp(reason,"alert_field_purpose_invalid")); free(ev);

  make_record(r); make_alert(&a,r);
  strcpy(r->domain,"synthetic-extra-logon-domain"); strcpy(r->creator_username,"synthetic-extra-creator");
  strcpy(a.user_subject_json,
    "{\"subject_type\":\"detection_context\",\"evaluation_basis\":{"
    "\"schema\":\"agent_detection_basis_v1\",\"owner\":\"ave_behavior_pipeline\","
    "\"predicate_matched\":true,\"threshold_met\":true,\"pid\":42,"
    "\"timestamp_ns\":\"1700000000000000000\",\"threshold\":0.65,\"event_count\":1,"
    "\"behavior_flags\":1,\"last_event_type\":9},\"detection_context\":{"
    "\"engine\":\"ave\",\"rule_id\":\"behavior_anomaly\",\"confidence\":0.7,"
    "\"process\":{\"pid\":42,\"parent_pid\":21,\"cmdline\":\"synthetic-duplicate-command\"},"
    "\"engine_signals\":{\"script_content_score\":0.7,\"raw_event\":{\"secret\":\"synthetic-local-only\"}},"
    "\"network\":{\"remote_ip\":\"127.0.0.1\",\"dst_port\":443},"
    "\"recommended_forensics\":[\"process_tree\",\"pmfe_scan\"]}}" );
  n=edr_behavior_record_alert_encode_protobuf(r,&a,frame,EDR_EGRESS_FRAME_MAX);
  assert(n && edr_egress_frame_validate(frame,n,reason,sizeof(reason)));
  ev=decode_frame(frame,n); assert(!ev->domain[0] && !ev->creator_username[0]);
  assert(!ev->cmdline[0] && !ev->process_context.has_parent_cmdline);
  assert(!strstr(ev->behavior_alert.user_subject_json,"raw_event"));
  assert(!strstr(ev->behavior_alert.user_subject_json,"synthetic-duplicate-command"));
  assert(strstr(ev->behavior_alert.user_subject_json,"script_content_score"));
  subject=cJSON_Parse(ev->behavior_alert.user_subject_json); assert(subject);
  ctx=cJSON_GetObjectItemCaseSensitive(subject,"detection_context");
  cJSON *signals=cJSON_GetObjectItemCaseSensitive(ctx,"engine_signals");
  cJSON_AddStringToObject(signals,"raw_event","synthetic-local-only");
  overwrite_json(ev->behavior_alert.user_subject_json,sizeof(ev->behavior_alert.user_subject_json),subject);
  cJSON_Delete(subject); n=immutable_encode(ev,frame);
  assert(!edr_egress_frame_validate(frame,n,reason,sizeof(reason)));
  /* A known leaf also cannot carry an arbitrary object or array. */
  subject=cJSON_Parse(ev->behavior_alert.user_subject_json); assert(subject);
  ctx=cJSON_GetObjectItemCaseSensitive(subject,"detection_context");
  signals=cJSON_GetObjectItemCaseSensitive(ctx,"engine_signals");
  cJSON_DeleteItemFromObjectCaseSensitive(signals,"raw_event");
  cJSON_ReplaceItemInObjectCaseSensitive(signals,"script_content_score",cJSON_CreateObject());
  overwrite_json(ev->behavior_alert.user_subject_json,sizeof(ev->behavior_alert.user_subject_json),subject);
  cJSON_Delete(subject); n=immutable_encode(ev,frame);
  assert(!edr_egress_frame_validate(frame,n,reason,sizeof(reason))); free(ev);

  make_record(r); make_alert(&a,r);
  strcpy(a.user_subject_json,"{\"subject_type\":\"edr_correlation\",\"rule_id\":\"synthetic-correlation\","
    "\"rules_bundle_version\":\"synthetic-v1\",\"evaluation_basis\":{\"schema\":\"agent_detection_basis_v1\","
    "\"owner\":\"correlation_engine\",\"predicate_matched\":true,\"pid\":42,"
    "\"timestamp_ns\":\"1700000000000000000\",\"kind\":\"threshold\",\"threshold\":2,"
    "\"matched_count\":3,\"window_ms\":1000,\"ordered\":false},\"window_ms\":1000,"
    "\"count\":3,\"distinct\":0,\"evidence_chain\":[{\"type\":21,\"pid\":42,"
    "\"event_time_ns\":\"1700000000000000000\",\"detail\":\"synthetic-matched-key\"}]}" );
  n=edr_behavior_record_alert_encode_protobuf(r,&a,frame,EDR_EGRESS_FRAME_MAX);
  assert(n && edr_egress_frame_validate(frame,n,reason,sizeof(reason)));
  ev=decode_frame(frame,n); assert(strstr(ev->behavior_alert.user_subject_json,"synthetic-matched-key"));
  subject=cJSON_Parse(ev->behavior_alert.user_subject_json); assert(subject);
  ctx=cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(subject,"evidence_chain"),0);
  cJSON_ReplaceItemInObjectCaseSensitive(ctx,"detail",cJSON_CreateObject());
  overwrite_json(ev->behavior_alert.user_subject_json,sizeof(ev->behavior_alert.user_subject_json),subject);
  cJSON_Delete(subject); n=immutable_encode(ev,frame);
  assert(!edr_egress_frame_validate(frame,n,reason,sizeof(reason))); free(ev);

  make_record(r); make_alert(&a,r);
  strcpy(a.user_subject_json,"{\"subject_type\":\"net_fanout\",\"evaluation_basis\":{"
    "\"schema\":\"agent_detection_basis_v1\",\"owner\":\"net_fanout_detector\","
    "\"predicate_matched\":true,\"pid\":42,\"timestamp_ns\":\"1700000000000000000\","
    "\"threshold\":2,\"distinct_ips\":3,\"window_s\":60,\"dport\":443,"
    "\"source_event_id\":\"synthetic-source\"}}" );
  strcpy(a.related_iocs_json,"{\"detector\":\"net_fanout\",\"dport\":443,\"distinct_ips\":3,\"window_s\":60}");
  n=edr_behavior_record_alert_encode_protobuf(r,&a,frame,EDR_EGRESS_FRAME_MAX);
  assert(n && edr_egress_frame_validate(frame,n,reason,sizeof(reason)));
  ev=decode_frame(frame,n); subject=cJSON_Parse(ev->behavior_alert.related_iocs_json); assert(subject);
  cJSON_AddObjectToObject(subject,"raw_connections");
  overwrite_json(ev->behavior_alert.related_iocs_json,sizeof(ev->behavior_alert.related_iocs_json),subject);
  cJSON_Delete(subject); n=immutable_encode(ev,frame);
  assert(!edr_egress_frame_validate(frame,n,reason,sizeof(reason))); free(ev);

  make_record(r); r->type=EDR_EVENT_PROTOCOL_SHELLCODE;
  strcpy(r->detection_context,"{\"rule_id\":\"agent_decision_v1\",\"process\":{\"pid\":42},"
    "\"engine_evidence\":{\"schema\":\"shellcode_result_v1\",\"alert_id\":\"synthetic-shellcode\","
    "\"owner\":{\"pid\":42},\"detection\":{\"detector\":\"shellcode\",\"rule\":\"synthetic-rule\",\"score\":0.9},"
    "\"payload\":{\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
    "\"preview_hex\":\"synthetic-local-only-payload\"},\"pcap\":{\"stem\":\"synthetic-local-only-pcap\"},"
    "\"detail\":\"synthetic-local-only-raw-event\"}}" );
  n=edr_behavior_record_encode_protobuf(r,frame,EDR_EGRESS_FRAME_MAX);
  assert(n && edr_egress_frame_validate(frame,n,reason,sizeof(reason)));
  ev=decode_frame(frame,n); assert(strstr(ev->ave_result_json,"synthetic-shellcode"));
  assert(!strstr(ev->ave_result_json,"synthetic-local-only"));
  subject=cJSON_Parse(ev->ave_result_json); assert(subject);
  ctx=cJSON_GetObjectItemCaseSensitive(subject,"engine_evidence");
  cJSON_AddObjectToObject(ctx,"pcap"); overwrite_json(ev->ave_result_json,sizeof(ev->ave_result_json),subject);
  cJSON_Delete(subject); n=immutable_encode(ev,frame);
  assert(!edr_egress_frame_validate(frame,n,reason,sizeof(reason))); free(ev);

  make_record(r); r->type=EDR_EVENT_WEBSHELL_DETECTED;
  strcpy(r->detection_context,"{\"rule_id\":\"agent_decision_v1\",\"process\":{\"pid\":42},"
    "\"engine_evidence\":{\"schema\":\"webshell_result_v1\","
    "\"file\":{\"path\":\"synthetic-webshell.php\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},"
    "\"detection\":{\"detector\":\"webshell\",\"rule\":\"synthetic-rule\",\"score\":0.9,\"ast_score\":0.8,\"token_score\":0.7},"
    "\"sample\":{\"local_path\":\"synthetic-local-only-sample\"}}}" );
  n=edr_behavior_record_encode_protobuf(r,frame,EDR_EGRESS_FRAME_MAX);
  assert(n && edr_egress_frame_validate(frame,n,reason,sizeof(reason)));
  ev=decode_frame(frame,n); assert(strstr(ev->ave_result_json,"synthetic-webshell.php"));
  assert(!strstr(ev->ave_result_json,"synthetic-local-only-sample")); free(ev);
  free(r); free(frame);
}

static int synthetic_authority_unavailable;
static int synthetic_projection_owner(const char *rule,const char *bundle,uint64_t mask,const char *operation,void *user) {
  (void)user;
  if (synthetic_authority_unavailable) return -1;
  if (strlen(bundle)!=64 || bundle[63]!='1') return 0;
  if (!strcmp(rule,"synthetic-operation")) return mask==EDR_EVIDENCE_OPERATION &&
    !strcmp(operation,"{\"kind\":\"credential_tool_attempt\"}");
  if (operation[0]) return 0;
  if (!strcmp(rule,"synthetic-network")) return mask==EDR_EVIDENCE_NETWORK;
  if (!strcmp(rule,"synthetic-parent")) return mask==(EDR_EVIDENCE_NETWORK|EDR_EVIDENCE_PARENT_NAME|EDR_EVIDENCE_PARENT_PATH|EDR_EVIDENCE_PARENT_COMMAND);
  if (!strcmp(rule,"synthetic-user")) return mask==EDR_EVIDENCE_USER;
  return !strcmp(rule,"synthetic-rule") &&
    mask==(EDR_EVIDENCE_COMMAND|EDR_EVIDENCE_PARENT_COMMAND|EDR_EVIDENCE_NETWORK);
}
static void operation_without_user_purpose(void) {
  EdrBehaviorRecord *r=calloc(1,sizeof(*r));AVEBehaviorAlert a;
  uint8_t *wire=malloc(EDR_EGRESS_FRAME_MAX);assert(r&&wire);
  make_record(r);r->type=EDR_EVENT_PROCESS_CREATE;make_alert(&a,r);
  r->required_evidence_fields=EDR_EVIDENCE_OPERATION;
  strcpy(r->operation_evidence,"{\"kind\":\"credential_tool_attempt\"}");
  strcpy(r->username,"synthetic-user");strcpy(r->identity_source,"token_query");strcpy(r->identity_quality,"token_sid");
  cJSON *subject=cJSON_Parse(a.user_subject_json);assert(subject);
  cJSON_ReplaceItemInObjectCaseSensitive(subject,"rule_id",cJSON_CreateString("synthetic-operation"));
  overwrite_json(a.user_subject_json,sizeof(a.user_subject_json),subject);cJSON_Delete(subject);
  size_t n=edr_behavior_record_alert_encode_protobuf(r,&a,wire,EDR_EGRESS_FRAME_MAX);
  assert(n&&edr_egress_frame_validate(wire,n,NULL,0));
  edr_v1_BehaviorEvent *event=decode_frame(wire,n);
  assert(!event->username[0]&&!event->cmdline[0]&&!event->identity_source[0]);
  event->required_evidence_fields|=EDR_EVIDENCE_USER;
  n=immutable_encode(event,wire);assert(!edr_egress_frame_validate(wire,n,NULL,0));
  free(event);free(wire);free(r);
}
static void historical_projection(void) {
  edr_egress_set_rule_projection_validator(synthetic_projection_owner,NULL);
  EdrBehaviorRecord *r=calloc(1,sizeof(*r)); AVEBehaviorAlert a;
  uint8_t *frame=malloc(EDR_EGRESS_FRAME_MAX),*body=malloc(EDR_EGRESS_BATCH_MAX),*selected=NULL;
  char reason[128]; uint8_t header[12]; uint32_t count=0; size_t selected_len=0; assert(r && frame && body);
  make_record(r); make_alert(&a,r);
  size_t ordinary=edr_behavior_record_encode_protobuf(r,frame,EDR_EGRESS_FRAME_MAX);
  wr(body,(uint32_t)ordinary); memcpy(body+4,frame,ordinary);
  size_t alert=edr_behavior_record_alert_encode_protobuf(r,&a,frame,EDR_EGRESS_FRAME_MAX);
  wr(body+ordinary+4,(uint32_t)alert); memcpy(body+ordinary+8,frame,alert);
  size_t n=ordinary+alert+8; uint8_t *saved=malloc(n); assert(saved); memcpy(saved,body,n);
  wr(header,EDR_TRANSPORT_BATCH_MAGIC_RAW); wr(header+4,2); wr(header+8,(uint32_t)n);
  assert(edr_egress_batch_project_alerts(header,12,body,n,r->tenant_id,r->endpoint_id,
    &selected,&selected_len,&count,reason,sizeof(reason)));
  assert(count==1 && selected_len==alert+16 && !memcmp(selected+16,frame,alert));
  assert(!memcmp(body,saved,n));
  assert(edr_egress_batch_validate(selected,12,selected+12,selected_len-12,reason,sizeof(reason)));
  assert(edr_egress_batch_validate_scope(selected,12,selected+12,selected_len-12,
    r->tenant_id,r->endpoint_id,reason,sizeof(reason)));
  assert(!edr_egress_batch_validate_scope(selected,12,selected+12,selected_len-12,
    "foreign-tenant",r->endpoint_id,reason,sizeof(reason)));
  assert(!edr_egress_batch_validate_scope(selected,12,selected+12,selected_len-12,
    r->tenant_id,"foreign-endpoint",reason,sizeof(reason)));
  free(selected); selected=NULL;
  uint8_t *compressed=malloc(LZ4_compressBound((int)n)); assert(compressed);
  int c=LZ4_compress_default((const char*)body,(char*)compressed,(int)n,LZ4_compressBound((int)n)); assert(c>0);
  wr(header,EDR_TRANSPORT_BATCH_MAGIC_LZ4);
  assert(edr_egress_batch_project_alerts(header,12,compressed,(size_t)c,r->tenant_id,r->endpoint_id,
    &selected,&selected_len,&count,reason,sizeof(reason)));
  assert(count==1 && !memcmp(selected+16,frame,alert)); free(selected); selected=NULL;
  assert(!edr_egress_batch_project_alerts(header,12,compressed,(size_t)c,"foreign-tenant",r->endpoint_id,
    &selected,&selected_len,&count,reason,sizeof(reason)) && !selected && !selected_len && !count);
  assert(!strcmp(reason,"historical_scope_mismatch"));
  wr(header,0xdeadbeef);
  assert(!edr_egress_batch_project_alerts(header,12,body,n,r->tenant_id,r->endpoint_id,
    &selected,&selected_len,&count,reason,sizeof(reason)) && !selected);
  wr(header,EDR_TRANSPORT_BATCH_MAGIC_RAW); wr(header+4,1); wr(header+8,(uint32_t)ordinary+4);
  assert(edr_egress_batch_project_alerts(header,12,body,ordinary+4,r->tenant_id,r->endpoint_id,
    &selected,&selected_len,&count,reason,sizeof(reason)));
  assert(count==0 && selected_len==12); free(selected); selected=NULL;
  edr_v1_BehaviorEvent *ev=decode_frame(body+4,ordinary);
  strcpy(ev->ave_result_json,"{\"schema\":\"unknown-future-v99\"}");
  ordinary=immutable_encode(ev,frame); free(ev); wr(body,(uint32_t)ordinary); memcpy(body+4,frame,ordinary);
  wr(header+8,(uint32_t)ordinary+4);
  assert(!edr_egress_batch_project_alerts(header,12,body,ordinary+4,r->tenant_id,r->endpoint_id,
    &selected,&selected_len,&count,reason,sizeof(reason)) && !selected);
  /* Compatibility is explicit and creates NEW bytes/identity. Keep the old
   * full payload unchanged while projecting a proven old detector context. */
  make_record(r); make_alert(&a,r); r->process_start_key=123;
  alert=edr_behavior_record_alert_encode_protobuf(r,&a,frame,EDR_EGRESS_FRAME_MAX);
  ev=decode_frame(frame,alert);
  ev->has_ave_behavior_feed=true;
  strcpy(ev->ave_behavior_feed.target_domain,"synthetic-local-only-redundant-feed");
  strcpy(ev->ave_result_json,"{\"schema\":\"agent_decision_v1\",\"reason\":\"synthetic-local-only-generic-score\"}");
  cJSON *subject=cJSON_Parse(ev->behavior_alert.user_subject_json); assert(subject);
  cJSON *ctx=cJSON_GetObjectItemCaseSensitive(subject,"context");
  cJSON_AddStringToObject(ctx,"cmdline","synthetic-local-only-duplicate-command");
  cJSON *raw=cJSON_AddObjectToObject(ctx,"unknown_environment");
  cJSON_AddStringToObject(raw,"secret","synthetic-local-only-environment");
  overwrite_json(ev->behavior_alert.user_subject_json,sizeof(ev->behavior_alert.user_subject_json),subject);
  cJSON_Delete(subject); alert=immutable_encode(ev,frame); free(ev);
  assert(!edr_egress_frame_validate(frame,alert,reason,sizeof(reason)));
  wr(body,(uint32_t)alert); memcpy(body+4,frame,alert); wr(header+4,1); wr(header+8,(uint32_t)alert+4);
  uint8_t *original=malloc(alert+4); assert(original); memcpy(original,body,alert+4);
  assert(edr_egress_batch_project_alerts(header,12,body,alert+4,r->tenant_id,r->endpoint_id,
    &selected,&selected_len,&count,reason,sizeof(reason)));
  assert(count==1 && selected_len<alert+16 && !memcmp(original,body,alert+4));
  assert(edr_egress_batch_validate(selected,12,selected+12,selected_len-12,reason,sizeof(reason)));
  ev=decode_frame(selected+16,selected_len-16);
  assert(ev->process_start_key==123 && !strcmp(ev->cmdline,r->cmdline));
  assert(ev->has_process_context && !strcmp(ev->process_context.parent_cmdline,r->parent_cmdline));
  assert(!strstr(ev->behavior_alert.user_subject_json,"synthetic-local-only"));
  assert(!ev->ave_result_json[0] && !ev->has_ave_behavior_feed);
  free(ev); free(selected); selected=NULL; free(original);
  /* A display label/score never gets upgraded to a proven historical alert. */
  make_alert(&a,r); strcpy(a.user_subject_json,"{\"subject_type\":\"edr_dynamic_rule\",\"rule_id\":\"label-only\"}");
  alert=edr_behavior_record_alert_encode_protobuf(r,&a,frame,EDR_EGRESS_FRAME_MAX);
  wr(body,(uint32_t)alert); memcpy(body+4,frame,alert); wr(header+8,(uint32_t)alert+4);
  assert(!edr_egress_batch_project_alerts(header,12,body,alert+4,r->tenant_id,r->endpoint_id,
    &selected,&selected_len,&count,reason,sizeof(reason)) && !selected);
  free(compressed); free(saved); free(body); free(frame); free(r);
}
typedef struct {
  uint8_t *frame; size_t len; unsigned validations,receipts,removals;
  int state,fail_receipt;
} TestAssociationOwner;
static int tuple_matches(const char *source,const char *endpoint,const char *tenant,
    const char *event,uint32_t pid,uint64_t start,uint64_t birth,int64_t time,
    const char *status,const char *verdict,const uint8_t *frame,size_t len,void *user) {
  TestAssociationOwner *owner=user;
  return !strcmp(source,"synthetic-original-alert") && !strcmp(endpoint,"synthetic-endpoint") &&
    !strcmp(tenant,"synthetic-tenant") && !strcmp(event,"synthetic-source") && pid==42 && start==123 &&
    birth==456 && time==1700000000000000000LL && !strcmp(status,"completed_clean") &&
    !strcmp(verdict,"clean") && owner->frame && len==owner->len && !memcmp(frame,owner->frame,len);
}
static int association_validate(const char *source,const char *endpoint,const char *tenant,
    const char *event,uint32_t pid,uint64_t start,uint64_t birth,int64_t time,
    const char *status,const char *verdict,const uint8_t *frame,size_t len,void *user) {
  TestAssociationOwner *owner=user; owner->validations++;
  return owner->state<2 && tuple_matches(source,endpoint,tenant,event,pid,start,birth,time,status,verdict,frame,len,user);
}
static int association_receipt(const char *source,const char *endpoint,const char *tenant,
    const char *event,uint32_t pid,uint64_t start,uint64_t birth,int64_t time,
    const char *status,const char *verdict,const uint8_t *frame,size_t len,void *user) {
  TestAssociationOwner *owner=user; owner->receipts++;
  if (owner->fail_receipt || !tuple_matches(source,endpoint,tenant,event,pid,start,birth,time,status,verdict,frame,len,user)) return -1;
  owner->state=1; return 1;
}
static int association_removed(const char *source,const char *endpoint,const char *tenant,
    const char *event,uint32_t pid,uint64_t start,uint64_t birth,int64_t time,
    const char *status,const char *verdict,const uint8_t *frame,size_t len,void *user) {
  TestAssociationOwner *owner=user; owner->removals++;
  if (!owner->state || !tuple_matches(source,endpoint,tenant,event,pid,start,birth,time,status,verdict,frame,len,user)) return -1;
  owner->state=2; return 1;
}
static void association_boundary(void) {
  EdrBehaviorRecord *r=calloc(1,sizeof(*r)); uint8_t *frame=malloc(EDR_EGRESS_FRAME_MAX);
  uint8_t *body=malloc(EDR_EGRESS_FRAME_MAX+4),header[12]; char reason[128]; assert(r && frame && body);
  make_record(r); r->type=EDR_EVENT_PMFE_SCAN_RESULT; r->process_start_key=123;
  r->process_creation_filetime_100ns=456;
  strcpy(r->detection_context,"{\"rule_id\":\"agent_decision_v1\",\"process\":{\"pid\":42},"
    "\"engine_evidence\":{\"schema\":\"pmfe_result_v1\",\"detector\":\"pmfe\","
    "\"source_alert_id\":\"synthetic-original-alert\",\"followup_only\":true,"
    "\"status\":\"completed_clean\",\"verdict\":\"clean\",\"signals\":{\"regions_scanned\":3},"
    "\"evidence\":{\"pmfe_snapshot\":\"synthetic-local-only-snapshot\"}}}" );
  TestAssociationOwner owner={0};
  edr_egress_set_pmfe_association_validator(NULL,NULL);
  size_t n=edr_behavior_record_encode_protobuf(r,frame,EDR_EGRESS_FRAME_MAX);
  assert(n && !edr_egress_frame_validate(frame,n,reason,sizeof(reason)));
  edr_egress_set_pmfe_association_validator(association_validate,&owner);
  n=edr_behavior_record_encode_protobuf(r,frame,EDR_EGRESS_FRAME_MAX);
  assert(n && !owner.validations); /* Pure minimization never authorizes. */
  owner.frame=malloc(n); assert(owner.frame); memcpy(owner.frame,frame,n); owner.len=n;
  assert(edr_egress_frame_validate(frame,n,reason,sizeof(reason)) && owner.validations==1);
  edr_v1_BehaviorEvent *ev=decode_frame(frame,n);
  assert(!strstr(ev->ave_result_json,"synthetic-local-only-snapshot"));
  assert(ev->process_start_key==123 && ev->process_creation_filetime_100ns==456 && !ev->cmdline[0]);
  strcpy(ev->event_id,"different-source"); size_t changed=immutable_encode(ev,frame);
  assert(!edr_egress_frame_validate(frame,changed,reason,sizeof(reason))); free(ev);
  memcpy(frame,owner.frame,n); wr(body,(uint32_t)n); memcpy(body+4,frame,n);
  wr(header,EDR_TRANSPORT_BATCH_MAGIC_RAW); wr(header+4,1); wr(header+8,(uint32_t)n+4);
  edr_egress_set_pmfe_receipt_handler(NULL,NULL);
  assert(!edr_egress_batch_note_receipt(header,12,body,n+4,reason,sizeof(reason)) && owner.state==0);
  edr_egress_set_pmfe_queue_removed_handler(association_removed,&owner);
  assert(!edr_egress_batch_note_queue_removed(header,12,body,n+4,reason,sizeof(reason)) && owner.state==0);
  edr_egress_set_pmfe_receipt_handler(association_receipt,&owner); owner.fail_receipt=1;
  assert(!edr_egress_batch_note_receipt(header,12,body,n+4,reason,sizeof(reason)) && owner.state==0);
  owner.fail_receipt=0;
  /* API ownership test only; the separate TLS test validates a real receipt. */
  assert(edr_egress_batch_note_receipt(header,12,body,n+4,reason,sizeof(reason)) && owner.state==1);
  assert(edr_egress_batch_note_queue_removed(header,12,body,n+4,reason,sizeof(reason)) && owner.state==2);
  assert(edr_egress_batch_note_queue_removed(header,12,body,n+4,reason,sizeof(reason)) && owner.state==2);
  assert(!edr_egress_frame_validate(frame,n,reason,sizeof(reason)));
  edr_egress_set_pmfe_association_validator(NULL,NULL);
  edr_egress_set_pmfe_receipt_handler(NULL,NULL); edr_egress_set_pmfe_queue_removed_handler(NULL,NULL);
  free(owner.frame); free(body); free(frame); free(r);
}
static void paired_batch_classification(void) {
  EdrBehaviorRecord *r=calloc(1,sizeof(*r)); AVEBehaviorAlert alert;
  uint8_t *wire=malloc(EDR_EGRESS_FRAME_MAX+16u),*compressed=malloc(EDR_EGRESS_FRAME_MAX+16u);
  assert(r && wire && compressed); make_record(r); make_alert(&alert,r);
  size_t n=edr_behavior_record_alert_encode_protobuf(r,&alert,wire+16,EDR_EGRESS_FRAME_MAX);
  assert(n); wr(wire,EDR_TRANSPORT_BATCH_MAGIC_RAW); wr(wire+4,1); wr(wire+8,(uint32_t)n+4u); wr(wire+12,(uint32_t)n);
  assert(edr_egress_batch_has_p0_combined(wire,n+16u)==0);
  int zipped=LZ4_compress_default((const char*)wire+12,(char*)compressed+12,(int)n+4,EDR_EGRESS_FRAME_MAX);
  assert(zipped>0); memcpy(compressed,wire,12); wr(compressed,EDR_TRANSPORT_BATCH_MAGIC_LZ4);
  assert(edr_egress_batch_has_p0_combined(compressed,(size_t)zipped+12u)==0);
  wr(wire,0x51515151u); assert(edr_egress_batch_has_p0_combined(wire,n+16u)==-1);
  wr(wire,EDR_TRANSPORT_BATCH_MAGIC_RAW);
  assert(edr_egress_batch_has_p0_combined(wire,n+15u)==-1);
  edr_v1_BehaviorEvent *ev=decode_frame(wire+16,n);
  strcpy(ev->ave_result_json,"{\"enforcement_terminal\":{\"phase\":\"result\"}}");
  n=immutable_encode(ev,wire+16); wr(wire+8,(uint32_t)n+4u); wr(wire+12,(uint32_t)n);
  /* Detection of a pairing dependency confers no egress permission. */
  assert(edr_egress_batch_has_p0_combined(wire,n+16u)==1);
  assert(!edr_egress_frame_validate(wire+16,n,NULL,0));
  free(ev); free(compressed); free(wire); free(r);
}
static void evidence_projection_v2(void) {
 EdrBehaviorRecord *r=calloc(1,sizeof(*r));AVEBehaviorAlert a;
 uint8_t *plain=malloc(EDR_EGRESS_FRAME_MAX),*rich=malloc(EDR_EGRESS_FRAME_MAX);assert(r&&plain&&rich);
 char why[128];make_record(r);make_alert(&a,r);r->required_evidence_fields=EDR_EVIDENCE_NETWORK;
 cJSON *contract=cJSON_Parse(a.user_subject_json);assert(contract);
 cJSON_ReplaceItemInObjectCaseSensitive(contract,"rule_id",cJSON_CreateString("synthetic-network"));
 overwrite_json(a.user_subject_json,sizeof(a.user_subject_json),contract);cJSON_Delete(contract);
 size_t minimum=edr_behavior_record_alert_encode_protobuf(r,&a,plain,EDR_EGRESS_FRAME_MAX);assert(minimum);
 strcpy(r->username,"unrelated-user");strcpy(r->user_sid,"unrelated-sid");strcpy(r->domain,"unrelated-domain");
 strcpy(r->identity_source,"synthetic");strcpy(r->identity_quality,"synthetic");r->session_id=77;
 strcpy(r->creator_username,"unrelated-creator");strcpy(r->current_directory,"C:\\unrelated");
 strcpy(r->grandparent_name,"unrelated-grandparent");r->grandparent_pid=700;
 strcpy(a.process_name,"duplicate-name");strcpy(a.process_path,"duplicate-path");strcpy(a.cmdline,"duplicate-command");a.ppid=21;
 size_t injected=edr_behavior_record_alert_encode_protobuf(r,&a,rich,EDR_EGRESS_FRAME_MAX);
 assert(injected==minimum&&!memcmp(plain,rich,minimum));
 assert(edr_egress_frame_validate(rich,injected,why,sizeof(why)));
 synthetic_authority_unavailable=1;
 assert(!edr_egress_frame_validate(rich,injected,why,sizeof(why)) && !strcmp(why,"rule_projection_authority_unavailable"));
 synthetic_authority_unavailable=0;
 assert(edr_egress_frame_validate(rich,injected,why,sizeof(why)));
 edr_v1_BehaviorEvent *ev=decode_frame(rich,injected);
 assert(ev->has_tactic_probs_computed&&!ev->tactic_probs_computed&&ev->behavior_alert.tactic_probs_count==0);
 assert(ev->has_process_context&&!ev->process_context.has_parent_cmdline&&ev->which_detail==edr_v1_BehaviorEvent_network_tag);
 /* Re-encoding immutable bytes bypasses the producer. Widening a mask
  * together with its field must still fail the trusted purpose descriptor. */
 ev->required_evidence_fields |= EDR_EVIDENCE_COMMAND;
 strcpy(ev->cmdline,"injected-after-freeze-command");
 size_t invalid=immutable_encode(ev,rich);
 assert(!edr_egress_frame_validate(rich,invalid,why,sizeof(why)));
 assert(!strcmp(why,"rule_projection_authority_unproven"));
 ev->required_evidence_fields &= ~EDR_EVIDENCE_COMMAND;ev->cmdline[0]=0;
 strcpy(ev->domain,"injected-after-freeze");invalid=immutable_encode(ev,rich);
 assert(!edr_egress_frame_validate(rich,invalid,why,sizeof(why)));free(ev);
 r->tactic_probability_state=2;size_t calculated=edr_behavior_record_alert_encode_protobuf(r,&a,rich,EDR_EGRESS_FRAME_MAX);
 ev=decode_frame(rich,calculated);assert(ev->has_tactic_probs_computed&&ev->tactic_probs_computed&&ev->behavior_alert.tactic_probs_count==14);
 assert(calculated==minimum+58&&edr_egress_frame_validate(rich,calculated,why,sizeof(why)));free(ev);
 r->required_evidence_fields=EDR_EVIDENCE_USER;r->tactic_probability_state=1;
 contract=cJSON_Parse(a.user_subject_json);assert(contract);
 cJSON_ReplaceItemInObjectCaseSensitive(contract,"rule_id",cJSON_CreateString("synthetic-user"));
 overwrite_json(a.user_subject_json,sizeof(a.user_subject_json),contract);cJSON_Delete(contract);
 /* An arbitrary/creator label cannot assert target attribution even when the
  * detector explicitly declared the user consumer purpose. */
 const char *rejected[][2]={{"synthetic","synthetic"},{"creator_fallback","creator_fallback"},
   {"unknown","unknown"},{"token_access_denied","access_denied"},{"target_4688_live_mismatch","unavailable"}};
 for (size_t i=0;i<sizeof(rejected)/sizeof(rejected[0]);i++) {
   strcpy(r->identity_source,rejected[i][0]);strcpy(r->identity_quality,rejected[i][1]);
   size_t n=edr_behavior_record_alert_encode_protobuf(r,&a,rich,EDR_EGRESS_FRAME_MAX);ev=decode_frame(rich,n);
   assert(!ev->username[0]&&!ev->identity_source[0]&&!ev->identity_quality[0]);
   assert(edr_egress_frame_validate(rich,n,why,sizeof(why)));free(ev);
 }
 const char *accepted[]={"kernel_process_token","token_query","token_cache","token_query_4688_validated","token_cache_4688_validated","target_4688"};
 for (size_t i=0;i<sizeof(accepted)/sizeof(accepted[0]);i++) {
   strcpy(r->identity_source,accepted[i]);strcpy(r->identity_quality,i==5?"target_4688":"token_sid");
   size_t n=edr_behavior_record_alert_encode_protobuf(r,&a,rich,EDR_EGRESS_FRAME_MAX);ev=decode_frame(rich,n);
   assert(!strcmp(ev->username,r->username)&&!strcmp(ev->identity_source,r->identity_source));
   assert(edr_egress_frame_validate(rich,n,why,sizeof(why)));free(ev);
 }
 size_t user=edr_behavior_record_alert_encode_protobuf(r,&a,rich,EDR_EGRESS_FRAME_MAX);ev=decode_frame(rich,user);
 assert(!strcmp(ev->username,r->username)&&!strcmp(ev->identity_source,r->identity_source)&&!strcmp(ev->identity_quality,r->identity_quality));
 assert(!ev->domain[0]&&!ev->user_sid[0]&&!ev->creator_username[0]);free(ev);
 printf("evidence v2 minimal=%zu unrelated_injection=%zu computed_zero=%zu\n",minimum,injected,calculated);
 free(r);free(plain);free(rich);
}
/* The synthetic projection owner isolates rule lookup only. Real encoder,
 * decoder and final gate preserve the NETWORK purpose's actual object. */
static void network_detail_competition(void) {
 EdrBehaviorRecord *r=calloc(1,sizeof(*r));AVEBehaviorAlert a;
 uint8_t *wire=malloc(EDR_EGRESS_FRAME_MAX),*baseline=malloc(EDR_EGRESS_FRAME_MAX),*full=malloc(EDR_EGRESS_FRAME_MAX);
 assert(r&&wire&&baseline&&full);make_record(r);make_alert(&a,r);r->required_evidence_fields=EDR_EVIDENCE_NETWORK;
 cJSON *subject=cJSON_Parse(a.user_subject_json);assert(subject);
 cJSON_ReplaceItemInObjectCaseSensitive(subject,"rule_id",cJSON_CreateString("synthetic-network"));
 overwrite_json(a.user_subject_json,sizeof(a.user_subject_json),subject);cJSON_Delete(subject);
 r->net_dst[0]=0;strcpy(r->dns_query,"fixture.example.invalid");size_t baseline_size=0;
 for(int variant=0;variant<4;variant++) {
  if(variant==1) strcpy(r->net_src,"198.51.100.1");
  if(variant==2) strcpy(r->network_aux_path,"UNRELATED-AUX");
  if(variant==3) strcpy(r->net_dst,"192.0.2.10");
  size_t n=edr_behavior_record_alert_encode_protobuf(r,&a,wire,EDR_EGRESS_FRAME_MAX);assert(n);
  assert(edr_egress_frame_validate(wire,n,NULL,0));edr_v1_BehaviorEvent *e=decode_frame(wire,n);
  if(variant<3) {
   assert(e->which_detail==edr_v1_BehaviorEvent_dns_tag && !strcmp(e->detail.dns.query_name,r->dns_query));
   if(!variant) {memcpy(baseline,wire,n);baseline_size=n;} else assert(n==baseline_size&&!memcmp(baseline,wire,n));
  } else assert(e->which_detail==edr_v1_BehaviorEvent_network_tag && !strcmp(e->detail.network.dst_ip,r->net_dst));
  free(e);
  size_t f=edr_behavior_record_encode_protobuf_full_facts(r,&a,NULL,NULL,full,EDR_EGRESS_FRAME_MAX);assert(f);
  r->evidence_projection_version=0;r->required_evidence_fields=0;
  size_t legacy=edr_behavior_record_encode_protobuf_full_facts(r,&a,NULL,NULL,wire,EDR_EGRESS_FRAME_MAX);
  assert(f==legacy&&!memcmp(full,wire,f));
  r->evidence_projection_version=EDR_EVIDENCE_PROJECTION_VERSION;r->required_evidence_fields=EDR_EVIDENCE_NETWORK;
 }
 free(r);free(wire);free(baseline);free(full);
}
static void parent_relation_projection(void) {
 EdrBehaviorRecord *r=calloc(1,sizeof(*r));AVEBehaviorAlert a;assert(r);
 uint8_t *wire=malloc(EDR_EGRESS_FRAME_MAX),*local=malloc(EDR_EGRESS_FRAME_MAX);assert(wire&&local);
 char why[128];make_record(r);make_alert(&a,r);r->ppid=4242;a.ppid=4242;
 r->required_evidence_fields=EDR_EVIDENCE_NETWORK;
 cJSON *subject=cJSON_Parse(a.user_subject_json);assert(subject);
 cJSON_ReplaceItemInObjectCaseSensitive(subject,"rule_id",cJSON_CreateString("synthetic-network"));
 overwrite_json(a.user_subject_json,sizeof(a.user_subject_json),subject);cJSON_Delete(subject);
 size_t full=edr_behavior_record_encode_protobuf_full_facts(r,&a,NULL,NULL,local,EDR_EGRESS_FRAME_MAX);
 size_t n=edr_behavior_record_alert_encode_protobuf(r,&a,wire,EDR_EGRESS_FRAME_MAX);assert(full&&n);
 edr_v1_BehaviorEvent *ev=decode_frame(wire,n),*facts=decode_frame(local,full);
 assert(facts->ppid==4242&&facts->behavior_alert.ppid==4242);
 assert(ev->evidence_projection_version==3&&ev->ppid==4242&&ev->behavior_alert.ppid==0);
 assert(ev->has_parent_pid_state&&ev->parent_pid_state==EDR_PARENT_PID_KNOWN);
 assert(!ev->process_context.has_parent_cmdline&&!ev->process_context.has_current_directory);
 assert(edr_egress_frame_validate(wire,n,why,sizeof(why)));
 ev->has_parent_pid_state=false;size_t bad=immutable_encode(ev,local);
 assert(!edr_egress_frame_validate(local,bad,why,sizeof(why)));
 ev->has_parent_pid_state=true;ev->parent_pid_state=EDR_PARENT_PID_UNKNOWN;bad=immutable_encode(ev,local);
 assert(!edr_egress_frame_validate(local,bad,why,sizeof(why)));free(ev);free(facts);
 printf("parent relation local_full=%zu projected_v3=%zu ppid=4242\n",full,n);
 r->ppid=0;r->parent_pid_state=EDR_PARENT_PID_EXPLICIT_ZERO;edr_behavior_clear_parent_context(r);
 n=edr_behavior_record_alert_encode_protobuf(r,&a,wire,EDR_EGRESS_FRAME_MAX);ev=decode_frame(wire,n);
 assert(ev->ppid==0&&ev->has_parent_pid_state&&ev->parent_pid_state==EDR_PARENT_PID_EXPLICIT_ZERO);
 assert(edr_egress_frame_validate(wire,n,why,sizeof(why)));free(ev);
 r->ppid=4242;r->parent_pid_state=EDR_PARENT_PID_CONFLICT;
 n=edr_behavior_record_alert_encode_protobuf(r,&a,wire,EDR_EGRESS_FRAME_MAX);ev=decode_frame(wire,n);
 assert(ev->ppid==4242&&ev->parent_pid_state==EDR_PARENT_PID_CONFLICT);
 assert(edr_egress_frame_validate(wire,n,why,sizeof(why)));free(ev);
 r->required_evidence_fields|=EDR_EVIDENCE_PARENT_NAME;
 assert(edr_behavior_record_alert_encode_protobuf(r,&a,wire,EDR_EGRESS_FRAME_MAX));
 strcpy(r->parent_name,"unbound-parent.exe");
 assert(!edr_behavior_record_alert_encode_protobuf(r,&a,wire,EDR_EGRESS_FRAME_MAX));
 edr_behavior_clear_parent_context(r);r->ppid=0;r->parent_pid_state=EDR_PARENT_PID_UNKNOWN;
 assert(edr_behavior_record_alert_encode_protobuf(r,&a,wire,EDR_EGRESS_FRAME_MAX));
 r->ppid=4242;
 r->required_evidence_fields=EDR_EVIDENCE_NETWORK;r->parent_pid_state=EDR_PARENT_PID_KNOWN;
 r->evidence_projection_version=EDR_EVIDENCE_PROJECTION_LEGACY_VERSION;
 n=edr_behavior_record_alert_encode_protobuf(r,&a,wire,EDR_EGRESS_FRAME_MAX);assert(n);ev=decode_frame(wire,n);
 assert(ev->evidence_projection_version==2&&ev->ppid==0&&!ev->has_parent_pid_state);
 memcpy(local,wire,n);assert(edr_egress_frame_validate(wire,n,why,sizeof(why)));
 assert(!memcmp(local,wire,n)); /* Validation never edits a frozen v2 body. */
 printf("parent relation legacy_v2=%zu ppid=0 frozen_bytes_unchanged=1\n",n);
 free(ev);free(r);free(wire);free(local);
}

static void unavailable_parent_purpose(void) {
 EdrBehaviorRecord *r=calloc(1,sizeof(*r));AVEBehaviorAlert a;
 uint8_t *wire=malloc(EDR_EGRESS_FRAME_MAX);assert(r&&wire);
 for(unsigned state=0;state<=EDR_PARENT_PID_CONFLICT;state++) if(state!=EDR_PARENT_PID_KNOWN) for(int purpose=0;purpose<2;purpose++) {
  make_record(r);r->parent_pid_state=(uint8_t)state;r->ppid=state==EDR_PARENT_PID_CONFLICT?21:0;
  edr_behavior_clear_parent_context(r);r->required_evidence_fields=EDR_EVIDENCE_NETWORK;
  if(purpose)r->required_evidence_fields|=EDR_EVIDENCE_PARENT_NAME|EDR_EVIDENCE_PARENT_PATH|EDR_EVIDENCE_PARENT_COMMAND;
  strcpy(r->parent_resolution_status,"NOT_EVALUABLE");strcpy(r->parent_resolution_source,"generation_unavailable");
  make_alert(&a,r);cJSON *subject=cJSON_Parse(a.user_subject_json);assert(subject);
  cJSON_ReplaceItemInObjectCaseSensitive(subject,"rule_id",cJSON_CreateString(purpose?"synthetic-parent":"synthetic-network"));
  overwrite_json(a.user_subject_json,sizeof(a.user_subject_json),subject);cJSON_Delete(subject);
  size_t n=edr_behavior_record_alert_encode_protobuf(r,&a,wire,EDR_EGRESS_FRAME_MAX);assert(n);
  assert(edr_egress_frame_validate(wire,n,NULL,0));
  edr_v1_BehaviorEvent *ev=decode_frame(wire,n);
  strcpy(ev->parent_name,"unbound-parent.exe");n=immutable_encode(ev,wire);
  assert(!edr_egress_frame_validate(wire,n,NULL,0));free(ev);
  for(unsigned field=0;field<4;field++) {
   if(field==0)strcpy(r->parent_name,"unbound-parent.exe");
   if(field==1)strcpy(r->parent_path,"C:\\unbound-parent.exe");
   if(field==2)strcpy(r->parent_cmdline,"unbound-parent.exe --untrusted");
   if(field==3)r->process_chain_depth=2;
   assert(!edr_behavior_record_alert_encode_protobuf(r,&a,wire,EDR_EGRESS_FRAME_MAX));
   edr_behavior_clear_parent_context(r);
  }
 }
 free(r);free(wire);
 puts("v3 optional parent purpose: unavailable edges emit without borrowed text; raw and producer violations reject");
}

static void parent_resolution_diagnostics(void) {
 EdrBehaviorRecord *r=calloc(1,sizeof(*r));AVEBehaviorAlert a;
 uint8_t *wire=malloc(EDR_EGRESS_FRAME_MAX),*frozen=malloc(EDR_EGRESS_FRAME_MAX);assert(r&&wire&&frozen);
 for(unsigned version=2;version<=3;version++) for(unsigned state=0;state<=EDR_PARENT_PID_CONFLICT;state++) {
  make_record(r);r->evidence_projection_version=version;r->required_evidence_fields=EDR_EVIDENCE_NETWORK;
  r->parent_pid_state=(uint8_t)state;r->ppid=(state==EDR_PARENT_PID_KNOWN||state==EDR_PARENT_PID_CONFLICT)?21:0;
  if(state!=EDR_PARENT_PID_KNOWN) edr_behavior_clear_parent_context(r);
  strcpy(r->parent_resolution_status,"NOT_EVALUABLE");
  strcpy(r->parent_resolution_source,"generation_unavailable");
  make_alert(&a,r);cJSON *subject=cJSON_Parse(a.user_subject_json);assert(subject);
  cJSON_ReplaceItemInObjectCaseSensitive(subject,"rule_id",cJSON_CreateString("synthetic-network"));
  overwrite_json(a.user_subject_json,sizeof(a.user_subject_json),subject);cJSON_Delete(subject);
  size_t n=edr_behavior_record_alert_encode_protobuf(r,&a,wire,EDR_EGRESS_FRAME_MAX);assert(n);
  edr_v1_BehaviorEvent *ev=decode_frame(wire,n);
  assert(!ev->parent_name[0]&&!ev->parent_path[0]&&!ev->process_context.has_parent_cmdline);
  assert(!strcmp(ev->parent_resolution_status,version==3?"NOT_EVALUABLE":""));
  assert(!strcmp(ev->parent_resolution_source,version==3?"generation_unavailable":""));
  assert(!ev->parent_creation_time[0]); /* Never invent a creation value. */
  memcpy(frozen,wire,n);assert(edr_egress_frame_validate(wire,n,NULL,0));assert(!memcmp(frozen,wire,n));free(ev);
  r->parent_resolution_status[0]=r->parent_resolution_source[0]=0;
  n=edr_behavior_record_alert_encode_protobuf(r,&a,wire,EDR_EGRESS_FRAME_MAX);assert(n);
  ev=decode_frame(wire,n);assert(!ev->parent_resolution_status[0]&&!ev->parent_resolution_source[0]);free(ev);
 }
 make_record(r);r->required_evidence_fields=EDR_EVIDENCE_NETWORK;
 strcpy(r->parent_resolution_status,"RESOLVED");strcpy(r->parent_resolution_source,"live_parent_generation");
 strcpy(r->parent_creation_time,"2026-10-09T08:00:08.063129700Z");
 make_alert(&a,r);cJSON *subject=cJSON_Parse(a.user_subject_json);assert(subject);
 cJSON_ReplaceItemInObjectCaseSensitive(subject,"rule_id",cJSON_CreateString("synthetic-network"));
 overwrite_json(a.user_subject_json,sizeof(a.user_subject_json),subject);cJSON_Delete(subject);
 size_t n=edr_behavior_record_alert_encode_protobuf(r,&a,wire,EDR_EGRESS_FRAME_MAX);assert(n);
 edr_v1_BehaviorEvent *ev=decode_frame(wire,n);assert(!strcmp(ev->parent_creation_time,r->parent_creation_time));
 assert(!strcmp(ev->parent_resolution_status,"RESOLVED")&&!ev->process_context.has_parent_cmdline);
 assert(edr_egress_frame_validate(wire,n,NULL,0));free(ev);
 r->evidence_projection_version=2;n=edr_behavior_record_alert_encode_protobuf(r,&a,wire,EDR_EGRESS_FRAME_MAX);assert(n);
 memcpy(frozen,wire,n);r->parent_resolution_status[0]=r->parent_resolution_source[0]=r->parent_creation_time[0]=0;
 size_t legacy=edr_behavior_record_alert_encode_protobuf(r,&a,wire,EDR_EGRESS_FRAME_MAX);
 assert(n==legacy&&!memcmp(frozen,wire,n)); /* Frozen v2 commitment remains byte-identical. */
 free(r);free(wire);free(frozen);
 puts("parent collection diagnostics: v3 preserves captured values without text purpose; v2 bytes unchanged");
}

/* Shared v3 contract: top-level is canonical, alias is optional but exact
 * when present, including zero. Nonoptional tag7 presence supplies no state. */
static void engine_parent_alias_contract(void) {
 EdrBehaviorRecord *r=calloc(1,sizeof(*r));AVEBehaviorAlert a={0};
 uint8_t *wire=malloc(EDR_EGRESS_FRAME_MAX);assert(r&&wire);
 r->type=EDR_EVENT_BEHAVIOR_ONNX_ALERT;r->pid=42;r->ppid=4242;r->parent_pid_state=EDR_PARENT_PID_KNOWN;
 r->event_time_ns=1700000000000000000LL;strcpy(r->event_id,"synthetic-engine-parent");
 strcpy(r->endpoint_id,"synthetic-endpoint");strcpy(r->tenant_id,"synthetic-tenant");
 a.pid=r->pid;a.ppid=r->ppid;a.timestamp_ns=r->event_time_ns;a.anomaly_score=.9f;
 strcpy(a.user_subject_json,"{\"subject_type\":\"detection_context\",\"detection_context\":{\"engine\":\"ave\",\"rule_id\":\"behavior_anomaly\",\"process\":{\"pid\":42,\"parent_pid\":4242},\"engine_signals\":{}},\"evaluation_basis\":{\"schema\":\"agent_detection_basis_v1\",\"owner\":\"ave_behavior_pipeline\",\"predicate_matched\":true,\"threshold_met\":true,\"tactic_probs_computed\":false,\"pid\":42,\"timestamp_ns\":\"1700000000000000000\",\"threshold\":0.65,\"event_count\":1,\"last_event_type\":9,\"behavior_flags\":4294967295}}");
 size_t n=edr_behavior_record_alert_encode_protobuf(r,&a,wire,EDR_EGRESS_FRAME_MAX);assert(n);
 edr_v1_BehaviorEvent *ev=decode_frame(wire,n);
 unsigned accepted=0;
 for(int state=-1;state<=EDR_PARENT_PID_CONFLICT;++state) for(int mode=0;mode<3;++mode) for(int alias=0;alias<4;++alias) {
  const uint32_t values[]={0,0,4242,99};
  ev->has_parent_pid_state=state>=0;ev->parent_pid_state=state<0?0:(uint32_t)state;ev->ppid=mode==2?4242:0;
  cJSON *json=cJSON_Parse(a.user_subject_json);assert(json);
  cJSON *ctx=cJSON_GetObjectItemCaseSensitive(json,"detection_context");cJSON *process=cJSON_GetObjectItemCaseSensitive(ctx,"process");
  cJSON_DeleteItemFromObjectCaseSensitive(process,"parent_pid");
  if(alias) cJSON_AddNumberToObject(process,"parent_pid",values[alias]);
  overwrite_json(ev->behavior_alert.user_subject_json,sizeof(ev->behavior_alert.user_subject_json),json);cJSON_Delete(json);
  n=immutable_encode(ev,wire);if(mode==1){wire[n++]=0x38;wire[n++]=0;}
  int expected=state>=0 && (state==EDR_PARENT_PID_CONFLICT ||
   (state==EDR_PARENT_PID_KNOWN?ev->ppid!=0:ev->ppid==0)) && (!alias || values[alias]==ev->ppid);
  int actual=edr_egress_frame_validate(wire,n,NULL,0);assert(actual==expected);accepted+=(unsigned)actual;
 }
 assert(accepted==20u);
 puts("v3 engine parent contract: 72 cases, 20 valid, absent/explicit zero distinguished");
 free(ev);free(wire);free(r);
}

int main(void) { engine_parent_alias_contract(); edr_egress_set_rule_projection_validator(synthetic_projection_owner,NULL); parent_relation_projection(); unavailable_parent_purpose(); parent_resolution_diagnostics(); network_detail_competition(); evidence_projection_v2(); operation_without_user_purpose(); matrix(); purpose_masks(); historical_projection(); association_boundary(); paired_batch_classification();
  puts("egress batch policy: synthetic matrix passed"); return 0; }
