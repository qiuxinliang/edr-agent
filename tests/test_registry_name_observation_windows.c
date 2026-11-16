#include "edr/etw_guids_win.h"
#include "edr/etw_tdh_win.h"
#include "edr/behavior_from_slot.h"

#include "edr/behavior_proto.h"
#include "edr/preprocess.h"
#include "edr/detection_decision.h"
#include <tdh.h>
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

/* Only the OS property lookup is replaced. UTF-16 conversion, production
 * payload building and delayed behavior normalization run unchanged. */
typedef struct { PCWSTR name; const void *data; ULONG bytes; } Property;
static Property s_properties[16];
static size_t s_count;
static PEVENT_RECORD s_record;

#include <stdbool.h>
bool edr_resource_preprocess_throttle_active(void){return false;}
uint64_t edr_monotonic_ns(void){return 1000000000;}
int edr_ingest_http_configured(void){return 0;}
int edr_ingest_http_circuit_open(void){return 0;}
int edr_ingest_http_telemetry_deferred(void){return 0;}
int edr_transport_v2_report_events(const char *id,const uint8_t *header,size_t h,const uint8_t *body,size_t n){(void)id;(void)header;(void)h;(void)body;(void)n;abort();}
void edr_isolate_auto_from_ransom_alarm(const EdrBehaviorRecord *record){(void)record;}




static Property *find_property(PCWSTR name) {
  for (size_t i = 0; i < s_count; ++i)
    if (wcscmp(name, s_properties[i].name) == 0) return &s_properties[i];
  return NULL;
}

static void add(PCWSTR name, const void *data, size_t bytes) {
  assert(s_count < sizeof(s_properties) / sizeof(s_properties[0]));
  assert(bytes <= ULONG_MAX);
  s_properties[s_count++] = (Property){name, data, (ULONG)bytes};
}

ULONG WINAPI edr_test_tdh_get_property_size(PEVENT_RECORD record, ULONG count,
    PTDH_CONTEXT context, ULONG property_count, PPROPERTY_DATA_DESCRIPTOR descriptors,
    PULONG size) {
  (void)count; (void)context;
  assert(record == s_record && property_count == 1u && descriptors && size);
  Property *p = find_property((PCWSTR)(ULONG_PTR)descriptors[0].PropertyName);
  if (!p) return ERROR_NOT_FOUND;
  *size = p->bytes;
  return ERROR_SUCCESS;
}

ULONG WINAPI edr_test_tdh_get_property(PEVENT_RECORD record, ULONG count,
    PTDH_CONTEXT context, ULONG property_count, PPROPERTY_DATA_DESCRIPTOR descriptors,
    ULONG bytes, PBYTE buffer) {
  (void)count; (void)context;
  assert(record == s_record && property_count == 1u && descriptors && buffer);
  Property *p = find_property((PCWSTR)(ULONG_PTR)descriptors[0].PropertyName);
  if (!p) return ERROR_NOT_FOUND;
  if (bytes < p->bytes) return ERROR_INSUFFICIENT_BUFFER;
  memcpy(buffer, p->data, p->bytes);
  return ERROR_SUCCESS;
}

static void check(const WCHAR *name, const WCHAR *alias, uint8_t observation,
                  const char *expected) {
  EVENT_RECORD event={0}; EdrEventSlot slot={0}; EdrBehaviorRecord r;
  event.EventHeader.ProviderId=EDR_ETW_GUID_KERNEL_REGISTRY;
  event.EventHeader.ProcessId=42; event.EventHeader.EventDescriptor.Opcode=6;
  s_count=0; s_record=&event;
  const WCHAR key[]=L"\\REGISTRY\\MACHINE\\Software\\EDRLab";
  add(L"KeyName",key,sizeof(key));
  const ULONG actor=42; add(L"ProcessId",&actor,sizeof(actor));
  if(name) add(L"ValueName",name,(wcslen(name)+1)*sizeof(WCHAR));
  if(alias) add(L"CapturedValueName",alias,(wcslen(alias)+1)*sizeof(WCHAR));
  EdrEventSlot old={0}; EdrBehaviorRecord prior;
  old.type=EDR_EVENT_REG_SET_VALUE;
  old.size=(uint32_t)edr_tdh_build_slot_payload(&event,"kreg",old.data,sizeof(old.data));
  assert(old.size>0); edr_behavior_from_slot(&old,&prior);
  if(name && !wcscmp(name,L"A")) {
    printf("old counterexample A decoded=%s\n",prior.reg_value_name);
    assert(strcmp(prior.reg_value_name,"A")!=0);
  }
  slot.type=EDR_EVENT_REG_SET_VALUE;
  slot.size=(uint32_t)edr_tdh_build_slot_payload_observed(&event,"kreg",slot.data,
      sizeof(slot.data),slot.type,&slot.registry_name_observation);
  assert(slot.size>0); assert(slot.registry_name_observation==observation);
  edr_behavior_from_slot(&slot,&r);
  assert(r.pid==42 && prior.pid==42);
  if(expected) assert(strcmp(r.reg_value_name,expected)==0);
  if(observation==EDR_REG_NAME_LOSS || observation==EDR_REG_NAME_CONFLICT) {
    assert(edr_behavior_source_field_truncated(&r,"source.reg_value_name"));
  }
  if(observation==EDR_REG_NAME_UNKNOWN)
    assert(!edr_behavior_source_field_truncated(&r,"source.reg_value_name"));
  if(observation==EDR_REG_NAME_OBSERVED || observation==EDR_REG_NAME_DEFAULT)
    assert(!edr_behavior_source_field_truncated(&r,"source.reg_value_name"));
  /* Apply the same verified actor enrichment to each input, never rewrite
   * decoder quality. A known P0 miss is the admission API's input contract. */
  EdrDetectionDecision decision={0}; unsigned char pb[65536];
  r.pid=42; r.process_start_key=1; r.process_creation_filetime_100ns=1;
  strcpy(r.event_id,"registry-source-fixture");
  strcpy(decision.reason,"baseline");
 strcpy(r.detection_context,"{\"signals\":{\"remote\":false,\"ransom_note\":false,\"tls_anomaly\":false,\"ransom_canary\":false,\"script_sensor\":false,\"process_context\":false,\"ransom_behavior\":false,\"rmm_policy_match\":false,\"extension_changed\":false,\"ransom_note_burst\":false,\"suspicious_parent\":false,\"webshell_semantic\":false,\"persistence_change\":false,\"high_content_entropy\":false,\"cert_revoked_ancestor\":false,\"security_product_kill\":false,\"ransom_recovery_tamper\":false,\"silverfox_attack_chain\":false,\"ransom_chain_score\":0},\"ransom_control\":{\"phase\":\"baseline\",\"kind\":\"\",\"file_rate_per_min\":0,\"canary\":false,\"extension_changed\":false},\"event_quality\":{\"signal_reasons\":[]}}");
  prior.pid=r.pid; prior.process_start_key=r.process_start_key;
  prior.process_creation_filetime_100ns=r.process_creation_filetime_100ns;
  strcpy(prior.event_id,r.event_id); strcpy(prior.detection_context,r.detection_context);
  int old_admitted=edr_preprocess_upload_admit(&prior,&decision,1,0);
  size_t old_encoded=edr_behavior_record_encode_protobuf(&prior,pb,sizeof(pb));
  assert(old_encoded>0);
  int admitted=edr_preprocess_upload_admit(&r,&decision,1,0);
  size_t encoded=edr_behavior_record_encode_protobuf(&r,pb,sizeof(pb));
  assert(encoded>0);
  if(observation==EDR_REG_NAME_LOSS || observation==EDR_REG_NAME_CONFLICT)
    assert(admitted); /* Never suppress wrong ordinary facts for zero bytes. */
  printf("same_input old_admit=%d new_admit=%d old_pb=%zu new_pb=%zu delta=%lld\n",
      old_admitted,admitted,old_encoded,encoded,(long long)encoded-(long long)old_encoded);
  /* This bounded line is also a replay input for the real host IR matcher;
   * absence is represented by observation, never synthesized as a name. */
  printf("IR_REPLAY observation=%u name_hex=",observation);
  for(const unsigned char *q=(const unsigned char *)r.reg_value_name;*q;q++) printf("%02x",*q);
  puts("");
  printf("observation=%u decoded=%s ordinary=%d pb=%zu admitted_pb=%zu quality=%s\n",
      observation,r.reg_value_name,admitted,encoded,admitted?encoded:0,r.source_completeness);

}
int main(void) {
  check(L"A",NULL,EDR_REG_NAME_OBSERVED,"A");
  check(L"65",NULL,EDR_REG_NAME_OBSERVED,"65");
  check(L"\x4e2d",NULL,EDR_REG_NAME_OBSERVED,"\xe4\xb8\xad");
  check(L"",NULL,EDR_REG_NAME_DEFAULT,"");
  check(NULL,NULL,EDR_REG_NAME_UNKNOWN,NULL);
  check(NULL,L"alias",EDR_REG_NAME_OBSERVED,"alias");
  check(L"same",L"same",EDR_REG_NAME_OBSERVED,"same");
  check(L"first",L"other",EDR_REG_NAME_CONFLICT,NULL);
  check(L"bad\nname",NULL,EDR_REG_NAME_LOSS,NULL);
  const WCHAR invalid[]={0xd800,0};
  check(invalid,NULL,EDR_REG_NAME_LOSS,NULL);
  /* Numeric-looking UTF-16 names must never share the TDH integer path. */
  check(L"1234",NULL,EDR_REG_NAME_OBSERVED,"1234");
  WCHAR huge[1025]; for(size_t i=0;i<1024;i++) huge[i]=L'x'; huge[1024]=0;
  check(huge,NULL,EDR_REG_NAME_LOSS,NULL);
  EVENT_RECORD event={0}; uint8_t bytes[4096], observation=99;
  event.EventHeader.ProviderId=EDR_ETW_GUID_KERNEL_REGISTRY;
  event.EventHeader.EventDescriptor.Opcode=6;
  s_record=&event; s_count=0;
  const WCHAR key[]=L"\\REGISTRY\\MACHINE\\Software\\EDRLab";
  add(L"KeyName",key,sizeof(key)); add(L"ValueName",L"A",2*sizeof(WCHAR));
  assert(edr_tdh_build_slot_payload_observed(&event,"kreg",bytes,sizeof(bytes),
      EDR_EVENT_REG_DELETE_KEY,&observation)>0);
  assert(observation==EDR_REG_NAME_UNKNOWN);
  assert(edr_tdh_build_slot_payload_observed(&event,"kreg",bytes,16,
      EDR_EVENT_REG_SET_VALUE,&observation)==0);
  puts("registry observation decoder: PASS"); return 0;
}

int edr_preprocess_should_emit(const EdrBehaviorRecord *r){(void)r;abort();}
