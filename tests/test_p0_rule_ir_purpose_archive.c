#include "edr/p0_rule_ir.h"
#include "edr/encrypt_p0_rules.h"
#include "edr/sha256.h"
#include "edr/ave_sdk.h"
#include "edr/behavior_proto.h"
#include "edr/egress_batch_policy.h"
#include "edr/v1/event.pb.h"
#include <pb_decode.h>
#include <pb_encode.h>
#include "cJSON.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#define make_directory(p) _mkdir(p)
#define remove_directory(p) _rmdir(p)
#define setenv(k,v,o) _putenv_s(k,v)
#else
#include <unistd.h>
#include <sys/stat.h>
#define make_directory(p) mkdir(p,0700)
#define remove_directory(p) rmdir(p)
#endif
static void save(const char *path,const void *bytes,size_t size){FILE *f=fopen(path,"wb");assert(f);assert(fwrite(bytes,1,size,f)==size);assert(!fclose(f));}
static unsigned char *read_bytes(const char *path,size_t *size){FILE *f=fopen(path,"rb");assert(f);assert(!fseek(f,0,SEEK_END));long n=ftell(f);assert(n>0);rewind(f);unsigned char *p=malloc((size_t)n);assert(p && fread(p,1,(size_t)n,f)==(size_t)n);fclose(f);*size=(size_t)n;return p;}
static int retained_projection_owner(const char *rule,const char *sha,uint64_t fields,const char *operation,void *user) {
 (void)user;return edr_p0_rule_ir_projection_matches(rule,sha,fields,operation);
}
static uint64_t consumer_expected_fields(const cJSON *bundle,const char *id,uint64_t predicates) {
 const cJSON *rules=cJSON_GetObjectItemCaseSensitive(bundle,"rules"),*rule=NULL,*item;
 assert(cJSON_IsArray(rules));
 cJSON_ArrayForEach(item,rules) {
  const cJSON *rule_id=cJSON_GetObjectItemCaseSensitive(item,"id");
  if(cJSON_IsString(rule_id)&&!strcmp(rule_id->valuestring,id)){assert(!rule);rule=item;}
 }
 assert(rule);
 const cJSON *condition=cJSON_GetObjectItemCaseSensitive(rule,"condition");
 const cJSON *purposes=cJSON_GetObjectItemCaseSensitive(condition,"evidence_purposes");
 assert(cJSON_IsArray(purposes));
 uint64_t fields=predicates;unsigned seen=0;
 /* The external frozen bundle owns optional disclosure. Keep this oracle
  * independent of the matcher: fixed case predicates plus only the explicit
  * purposes reviewed here. New/duplicate purposes or missing actor require
  * review, rather than silently learning authority from the runtime mask. */
 cJSON_ArrayForEach(item,purposes) {
  unsigned bit=0;uint64_t field=0;assert(cJSON_IsString(item));
  if(!strcmp(item->valuestring,"actor_attribution")){bit=1u;field=EDR_EVIDENCE_USER;}
  else if(!strcmp(item->valuestring,"parent_context")) {
   bit=2u;field=EDR_EVIDENCE_PARENT_NAME|EDR_EVIDENCE_PARENT_PATH|EDR_EVIDENCE_PARENT_COMMAND;
  } else if(!strcmp(item->valuestring,"subject_command")){bit=4u;field=EDR_EVIDENCE_COMMAND;}
  else if(!strcmp(item->valuestring,"parent_identity")){bit=8u;field=EDR_EVIDENCE_PARENT_NAME;}
  if(!bit || (seen&bit))fprintf(stderr,"consumer purpose requires review: rule=%s purpose=%.64s\n",id,item->valuestring);
  assert(bit && !(seen&bit));seen|=bit;fields|=field;
 }
 assert(seen&1u);
 return fields;
}
static void current_consumer_projection_contract(const unsigned char *plain,size_t size) {
 static const struct {const char *rule,*name,*path,*command;uint64_t predicates;} cases[]={
  {"R-EXEC-002","powershell.exe","C:\\Windows\\System32\\powershell.exe","powershell.exe -w hidden -nop",EDR_EVIDENCE_COMMAND},
  {"R-SIGN-001","signtool.exe","C:\\Tools\\signtool.exe","signtool.exe sign C:\\Temp\\sample.exe",EDR_EVIDENCE_COMMAND},
  {"R-MITRE-WIN-T1044","icacls.exe","C:\\Windows\\System32\\icacls.exe","icacls.exe C:\\Temp\\sample.exe /grant Everyone:F",EDR_EVIDENCE_COMMAND},
  {"R-LOLBIN-010","cmd.exe","C:\\Temp\\cmd.exe","cmd.exe /c echo fixture",0},
  {"R-DISC-001","cmd.exe","C:\\Windows\\System32\\cmd.exe","cmd.exe /c whoami & hostname",EDR_EVIDENCE_COMMAND},
  {"R-EXFIL-001","powershell.exe","C:\\Windows\\System32\\powershell.exe","powershell.exe Compress-Archive C:\\Temp\\fixture C:\\Temp\\fixture.zip",EDR_EVIDENCE_COMMAND}
 };
 cJSON *bundle=cJSON_ParseWithLength((const char*)plain,size);assert(bundle);
 EdrBehaviorRecord *r=calloc(1,sizeof(*r));edr_v1_BehaviorEvent *event=calloc(1,sizeof(*event));
 uint8_t *wire=malloc(EDR_EGRESS_FRAME_MAX),*frozen=malloc(EDR_EGRESS_FRAME_MAX);assert(r&&event&&wire&&frozen);
 edr_egress_set_rule_projection_validator(retained_projection_owner,NULL);
 for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
  const uint64_t expected=consumer_expected_fields(bundle,cases[i].rule,cases[i].predicates);
  printf("consumer projection rule=%s expected_mask=0x%llx\n",cases[i].rule,(unsigned long long)expected);
  for(unsigned state=0;state<=4;state++)
  for(unsigned command=0;command<(i==3?2u:1u);command++) {
   const unsigned parent=state==EDR_PARENT_PID_KNOWN;
   edr_behavior_record_init(r);r->type=EDR_EVENT_PROCESS_CREATE;r->pid=42;
   r->process_start_key=456;r->process_creation_filetime_100ns=789;r->event_time_ns=1700000000000000000LL;
   r->ppid=(parent||state==EDR_PARENT_PID_CONFLICT)?21:0;r->parent_pid_state=(EdrParentPidState)state;
   strcpy(r->event_id,"consumer-projection-fixture");strcpy(r->endpoint_id,"fixture-endpoint");strcpy(r->tenant_id,"fixture-tenant");
   strcpy(r->process_name,cases[i].name);strcpy(r->exe_path,cases[i].path);
   if(!command)strcpy(r->cmdline,cases[i].command);
   strcpy(r->parent_resolution_status,parent?"RESOLVED":"NOT_EVALUABLE");
   strcpy(r->parent_resolution_source,parent?"process_tree_cache_verified":"generation_unavailable");
   if(parent) {
    strcpy(r->parent_name,"launcher.exe");strcpy(r->parent_path,"C:\\Tools\\launcher.exe");
    strcpy(r->parent_cmdline,"launcher.exe --captured");strcpy(r->parent_creation_time,"2026-10-09T08:00:08.063129700Z");
   }
   EdrP0RuleIrEvaluation eval;EdrP0RuleIrMatch match={0};int found=0;
   assert(edr_p0_rule_ir_evaluate_record(r,NULL,&eval));
   for(uint32_t m=0;m<eval.match_count;m++) {
    assert(edr_p0_rule_ir_evaluation_get_match(&eval,m,&match));
    if(!strcmp(match.rule_id,cases[i].rule)){found=1;break;}
   }
   if(!found || match.required_evidence_fields!=expected)
    fprintf(stderr,"consumer projection contract: rule=%s parent=%u command_missing=%u found=%d expected_mask=0x%llx actual_mask=0x%llx\n",
     cases[i].rule,parent,command,found,(unsigned long long)expected,(unsigned long long)match.required_evidence_fields);
   assert(found&&match.required_evidence_fields==expected);
   r->evidence_projection_version=EDR_EVIDENCE_PROJECTION_VERSION;r->required_evidence_fields=match.required_evidence_fields;
   AVEBehaviorAlert alert={0};alert.pid=r->pid;alert.timestamp_ns=r->event_time_ns;alert.anomaly_score=.7f;
   int written=snprintf(alert.user_subject_json,sizeof(alert.user_subject_json),
    "{\"subject_type\":\"edr_dynamic_rule\",\"rule_id\":\"%s\",\"rules_bundle_version\":\"%s\","
    "\"rules_bundle_sha256\":\"%s\",\"context\":{\"pid\":42,\"event_type\":%d,"
    "\"source_event_id\":\"consumer-projection-fixture\",\"endpoint_id\":\"fixture-endpoint\",\"tenant_id\":\"fixture-tenant\"}}",
    match.rule_id,eval.binding.rules_bundle_version,eval.binding.artifact_sha256,(int)r->type);
   assert(written>0&&(size_t)written<sizeof(alert.user_subject_json));edr_p0_rule_ir_evaluation_free(&eval);
   size_t n=edr_behavior_record_alert_encode_protobuf(r,&alert,wire,EDR_EGRESS_FRAME_MAX);assert(n);
   pb_istream_t in=pb_istream_from_buffer(wire,n);memset(event,0,sizeof(*event));
   assert(pb_decode(&in,edr_v1_BehaviorEvent_fields,event));
   assert(event->required_evidence_fields==expected);
   assert(!strcmp(event->cmdline,(expected&EDR_EVIDENCE_COMMAND)?r->cmdline:""));
   assert(event->has_process_context&&event->process_context.has_parent_name==(bool)(parent&&(expected&EDR_EVIDENCE_PARENT_NAME)));
   assert(event->process_context.has_parent_path==(bool)(parent&&(expected&EDR_EVIDENCE_PARENT_PATH)));
   assert(event->process_context.has_parent_cmdline==(bool)(parent&&(expected&EDR_EVIDENCE_PARENT_COMMAND)));
   assert(!strcmp(event->process_context.parent_name,(expected&EDR_EVIDENCE_PARENT_NAME)?r->parent_name:""));
   assert(!strcmp(event->process_context.parent_path,(expected&EDR_EVIDENCE_PARENT_PATH)?r->parent_path:""));
   assert(!strcmp(event->process_context.parent_cmdline,(expected&EDR_EVIDENCE_PARENT_COMMAND)?r->parent_cmdline:""));
   assert(!strcmp(event->parent_resolution_status,r->parent_resolution_status)&&!strcmp(event->parent_resolution_source,r->parent_resolution_source));
   assert(!strcmp(event->parent_creation_time,r->parent_creation_time)&&event->ppid==r->ppid);
   assert(event->process_start_key==r->process_start_key&&event->process_creation_filetime_100ns==r->process_creation_filetime_100ns);
   assert(strstr(event->behavior_alert.user_subject_json,cases[i].rule));
   memcpy(frozen,wire,n);assert(edr_egress_frame_validate(wire,n,NULL,0));
   assert(edr_egress_frame_validate(wire,n,NULL,0)&&!memcmp(wire,frozen,n));
   /* Self-reported masks cannot extend the retained rule's authority, even
    * when the newly requested field is absent from these exact bytes. */
   const uint64_t unauthorized[]={EDR_EVIDENCE_FILE,EDR_EVIDENCE_COMMAND,
    EDR_EVIDENCE_PARENT_NAME,EDR_EVIDENCE_PARENT_PATH,EDR_EVIDENCE_PARENT_COMMAND};
   for(unsigned field=0;field<sizeof(unauthorized)/sizeof(unauthorized[0]);field++) {
    if(expected&unauthorized[field])continue;
    event->required_evidence_fields=expected|unauthorized[field];
    pb_ostream_t out=pb_ostream_from_buffer(wire,EDR_EGRESS_FRAME_MAX);
    assert(pb_encode(&out,edr_v1_BehaviorEvent_fields,event));
    assert(!edr_egress_frame_validate(wire,out.bytes_written,NULL,0));
   }
  }
 }
 edr_egress_set_rule_projection_validator(NULL,NULL);free(r);free(event);free(wire);free(frozen);
 cJSON_Delete(bundle);
 puts("six current rules and five parent states: exact declared authority -> serializer -> immutable egress; name-only defaults, unauthorized text omitted, parent gaps explicit, LOLBIN missing command still matches");
}
static void legacy_purpose_contract(const char *base,const unsigned char *plain,size_t size,
                                    const EdrP0RuleIrMatch *valid) {
 cJSON *j=cJSON_ParseWithLength((const char*)plain,size);assert(j);
 cJSON *rules=cJSON_GetObjectItemCaseSensitive(j,"rules"),*r,*old=NULL;
 cJSON_SetNumberValue(cJSON_GetObjectItemCaseSensitive(j,"ir_schema_version"),5);
 cJSON_ArrayForEach(r,rules) cJSON_DeleteItemFromObjectCaseSensitive(cJSON_GetObjectItemCaseSensitive(r,"condition"),"evidence_purposes");
 cJSON_ArrayForEach(r,rules) if(!strcmp(cJSON_GetObjectItemCaseSensitive(r,"id")->valuestring,"R-CRED-010")) old=r;
 assert(old);
 cJSON *condition=cJSON_CreateObject(),*patterns=cJSON_AddArrayToObject(condition,"command_regex_any");assert(patterns);
 assert(cJSON_AddItemToArray(patterns,cJSON_CreateString("(?i)(lazagne|sharpdpapi|seatbelt).*?(password|cred|vault|dpapi|cookie|browser)")));
 assert(cJSON_AddItemToArray(patterns,cJSON_CreateString("(?i)(dpapi::|vault::|chrome.*login data|firefox.*logins\\.json)")));
 assert(cJSON_AddItemToArray(patterns,cJSON_CreateString("(?i)(cookies|login data|key4\\.db).*?(copy|dump|decrypt)")));
 assert(cJSON_ReplaceItemInObjectCaseSensitive(old,"condition",condition));
 for(int renamed=0;renamed<2;renamed++) {
  const char *id=renamed?"RENAMED-CREDENTIAL-PREDICATE":"R-CRED-010";
  assert(cJSON_ReplaceItemInObjectCaseSensitive(old,"id",cJSON_CreateString(id)));
  char *json=cJSON_PrintUnformatted(j),sha[65],archive[400];unsigned char *encrypted=NULL;size_t encrypted_size=0;assert(json);
  assert(edr_sha256_hex((const uint8_t*)json,strlen(json),sha)==0);
  assert(edr_p0_encrypt_encrypt_edr1_for_test((const uint8_t*)json,strlen(json),&encrypted,&encrypted_size)==0);
  snprintf(archive,sizeof(archive),"%s.purpose-%s.edr1",base,sha);save(archive,encrypted,encrypted_size);
  /* A legacy purpose archive can never be installed for new matching. */
  assert(!edr_p0_rule_ir_validate_candidate_path(archive));
  for(int replay=0;replay<3;replay++) {
   assert(edr_p0_rule_ir_projection_matches(valid->rule_id,sha,valid->required_evidence_fields,valid->operation_evidence)==1);
   assert(edr_p0_rule_ir_projection_matches(id,sha,EDR_EVIDENCE_USER|EDR_EVIDENCE_COMMAND,"")==0);
  }
  edr_p0_rule_ir_shutdown();edr_p0_rule_ir_lazy_init();assert(edr_p0_rule_ir_is_ready());
  assert(edr_p0_rule_ir_projection_matches(valid->rule_id,sha,valid->required_evidence_fields,valid->operation_evidence)==1);
  assert(edr_p0_rule_ir_projection_matches(id,sha,EDR_EVIDENCE_USER|EDR_EVIDENCE_COMMAND,"")==0);
  size_t after_size;unsigned char *after=read_bytes(archive,&after_size);
  assert(after_size==encrypted_size && !memcmp(after,encrypted,after_size));free(after);free(encrypted);cJSON_free(json);
 }
 cJSON_Delete(j);
 puts("IR5 frozen authority: preserved other rules; exact weak predicate held even renamed; archive bytes unchanged after replay/restart");
}
static void dump_purpose_contract(const char *base,const unsigned char *plain,size_t size,
                                  const EdrP0RuleIrMatch *valid) {
 cJSON *j=cJSON_ParseWithLength((const char*)plain,size);assert(j);
 cJSON *rules=cJSON_GetObjectItemCaseSensitive(j,"rules"),*r,*old=NULL;
 cJSON_SetNumberValue(cJSON_GetObjectItemCaseSensitive(j,"ir_schema_version"),6);
 cJSON_ArrayForEach(r,rules) cJSON_DeleteItemFromObjectCaseSensitive(cJSON_GetObjectItemCaseSensitive(r,"condition"),"evidence_purposes");
 cJSON_ArrayForEach(r,rules) if(!strcmp(cJSON_GetObjectItemCaseSensitive(r,"id")->valuestring,"R-CRED-009")) old=r;
 assert(old);assert(cJSON_ReplaceItemInObjectCaseSensitive(old,"effect",cJSON_CreateString("security_alert")));
 char *json=cJSON_PrintUnformatted(j),sha[65],archive[400];unsigned char *encrypted=NULL;size_t encrypted_size=0;assert(json);
 assert(edr_sha256_hex((const uint8_t*)json,strlen(json),sha)==0);
 assert(edr_p0_encrypt_encrypt_edr1_for_test((const uint8_t*)json,strlen(json),&encrypted,&encrypted_size)==0);
 snprintf(archive,sizeof(archive),"%s.purpose-%s.edr1",base,sha);save(archive,encrypted,encrypted_size);
 assert(!edr_p0_rule_ir_validate_candidate_path(archive));
 for(int restart=0;restart<2;restart++) {
  assert(edr_p0_rule_ir_projection_matches(valid->rule_id,sha,valid->required_evidence_fields,valid->operation_evidence)==1);
  assert(edr_p0_rule_ir_projection_matches("R-CRED-009",sha,EDR_EVIDENCE_USER|EDR_EVIDENCE_COMMAND,"")==0);
  edr_p0_rule_ir_shutdown();edr_p0_rule_ir_lazy_init();assert(edr_p0_rule_ir_is_ready());
 }
 size_t after_size;unsigned char *after=read_bytes(archive,&after_size);
 assert(after_size==encrypted_size && !memcmp(after,encrypted,after_size));
 free(after);free(encrypted);cJSON_free(json);cJSON_Delete(j);
 puts("IR6 archive: denied active downgrade; exact weak dump purpose held; safe owner and original bytes survive restart");
}
static void cookie_purpose_contract(const char *base,const unsigned char *plain,size_t size,
                                    const EdrP0RuleIrMatch *valid) {
 const char *ids[]={"R-LMOVE-012","R-CRED-011"};
 for(unsigned i=0;i<3;i++) for(int renamed=0;renamed<2;renamed++) {
  EdrP0RuleIrBinding active_before,active_after;assert(edr_p0_rule_ir_get_binding(&active_before));
  cJSON *j=cJSON_ParseWithLength((const char*)plain,size);assert(j);
  cJSON *r,*old=NULL; cJSON_ArrayForEach(r,cJSON_GetObjectItemCaseSensitive(j,"rules"))
   if(!strcmp(cJSON_GetObjectItemCaseSensitive(r,"id")->valuestring,ids[i%2])) old=r;
  assert(old);const char *id=renamed?"R-RENAMED-COOKIE":ids[i%2];
  assert(cJSON_ReplaceItemInObjectCaseSensitive(old,"id",cJSON_CreateString(id)));
  assert(cJSON_ReplaceItemInObjectCaseSensitive(old,"effect",cJSON_CreateString("security_alert")));
  cJSON *purposes=cJSON_AddArrayToObject(cJSON_GetObjectItemCaseSensitive(old,"condition"),"evidence_purposes");
  assert(purposes && cJSON_AddItemToArray(purposes,cJSON_CreateString("actor_attribution")));
  if(i==2) {
   cJSON_ArrayForEach(r,cJSON_GetObjectItemCaseSensitive(j,"rules"))
    if(!strcmp(cJSON_GetObjectItemCaseSensitive(r,"id")->valuestring,"R-CRED-011")) {
     assert(cJSON_ReplaceItemInObjectCaseSensitive(r,"effect",cJSON_CreateString("security_alert")));
     cJSON *p=cJSON_AddArrayToObject(cJSON_GetObjectItemCaseSensitive(r,"condition"),"evidence_purposes");
     assert(p && cJSON_AddItemToArray(p,cJSON_CreateString("actor_attribution")));
    }
  }
  char *json=cJSON_PrintUnformatted(j),sha[65],archive[400];unsigned char *encrypted=NULL;size_t encrypted_size=0;assert(json);
  assert(edr_sha256_hex((const uint8_t*)json,strlen(json),sha)==0);
  assert(edr_p0_encrypt_encrypt_edr1_for_test((const uint8_t*)json,strlen(json),&encrypted,&encrypted_size)==0);
  snprintf(archive,sizeof(archive),"%s.purpose-%s.edr1",base,sha);save(archive,encrypted,encrypted_size);
  assert(!edr_p0_rule_ir_validate_candidate_path(archive));
  assert(!edr_p0_rule_ir_install_staged_bundle(archive,base));
  assert(edr_p0_rule_ir_get_binding(&active_after));
  assert(!strcmp(active_before.artifact_sha256,active_after.artifact_sha256));
  for(int restart=0;restart<2;restart++) {
   assert(edr_p0_rule_ir_projection_matches(valid->rule_id,sha,valid->required_evidence_fields,valid->operation_evidence)==1);
   assert(edr_p0_rule_ir_projection_matches(id,sha,EDR_EVIDENCE_USER|EDR_EVIDENCE_FILE,"")==0);
   edr_p0_rule_ir_shutdown();edr_p0_rule_ir_lazy_init();assert(edr_p0_rule_ir_is_ready());
  }
  size_t after_size;unsigned char *after=read_bytes(archive,&after_size);
  assert(after_size==encrypted_size && !memcmp(after,encrypted,after_size));
  if(i<2) {
   assert(cJSON_AddStringToObject(cJSON_GetObjectItemCaseSensitive(old,"condition"),"operation","credential_db_decrypt"));
   char *strong=cJSON_PrintUnformatted(j);unsigned char *sealed=NULL;size_t sealed_size=0;assert(strong);
   assert(edr_p0_encrypt_encrypt_edr1_for_test((const uint8_t*)strong,strlen(strong),&sealed,&sealed_size)==0);
   char candidate[420];snprintf(candidate,sizeof(candidate),"%s.strong",archive);save(candidate,sealed,sealed_size);
   assert(edr_p0_rule_ir_validate_candidate_path(candidate));free(sealed);cJSON_free(strong);
  }
  free(after);free(encrypted);cJSON_free(json);cJSON_Delete(j);
 }
 puts("IR7 Cookie predicate: old active package refused; renamed historical purpose held; safe sibling and original archive survive restart");
}
static void parent_purpose_contract(const char *base,const unsigned char *plain,size_t size) {
 const uint64_t actor=EDR_EVIDENCE_USER|EDR_EVIDENCE_COMMAND;
 const uint64_t parent=EDR_EVIDENCE_PARENT_NAME|EDR_EVIDENCE_PARENT_PATH|EDR_EVIDENCE_PARENT_COMMAND;
 for(unsigned schema=7;schema<=8;schema++) {
  cJSON *j=cJSON_ParseWithLength((const char*)plain,size),*rule=NULL,*item;assert(j);
  cJSON_SetNumberValue(cJSON_GetObjectItemCaseSensitive(j,"ir_schema_version"),schema);
  cJSON_ArrayForEach(item,cJSON_GetObjectItemCaseSensitive(j,"rules"))
   if(!strcmp(cJSON_GetObjectItemCaseSensitive(item,"id")->valuestring,"R-EXEC-001"))rule=item;
  assert(rule);
  /* Freeze this historical rule independently of newer purposes on unrelated
   * current rules; relabeling an entire IR9 bundle as IR7/8 is not a fixture. */
  cJSON *single=cJSON_CreateArray(),*frozen_rule=cJSON_Duplicate(rule,1);assert(single&&frozen_rule);
  assert(cJSON_AddItemToArray(single,frozen_rule));
  assert(cJSON_ReplaceItemInObjectCaseSensitive(j,"rules",single));
  cJSON_SetNumberValue(cJSON_GetObjectItemCaseSensitive(j,"rule_count"),1);
  cJSON *condition=cJSON_GetObjectItemCaseSensitive(frozen_rule,"condition");
  cJSON_DeleteItemFromObjectCaseSensitive(condition,"evidence_purposes");
  cJSON *purposes=cJSON_AddArrayToObject(condition,"evidence_purposes");assert(purposes);
  assert(cJSON_AddItemToArray(purposes,cJSON_CreateString("actor_attribution")));
  if(schema==8)assert(cJSON_AddItemToArray(purposes,cJSON_CreateString("parent_context")));
  char *json=cJSON_PrintUnformatted(j),sha[65],archive[400];unsigned char *encrypted=NULL;size_t encrypted_size=0;assert(json);
  assert(edr_sha256_hex((const uint8_t*)json,strlen(json),sha)==0);
  assert(edr_p0_encrypt_encrypt_edr1_for_test((const uint8_t*)json,strlen(json),&encrypted,&encrypted_size)==0);
  snprintf(archive,sizeof(archive),"%s.purpose-%s.edr1",base,sha);save(archive,encrypted,encrypted_size);
  assert(edr_p0_rule_ir_validate_candidate_path(archive));
  uint64_t expected=actor|(schema==8?parent:0);
  for(int restart=0;restart<2;restart++) {
   assert(edr_p0_rule_ir_projection_matches("R-EXEC-001",sha,expected,"")==1);
   assert(edr_p0_rule_ir_projection_matches("R-EXEC-001",sha,expected^parent,"")==0);
   edr_p0_rule_ir_shutdown();edr_p0_rule_ir_lazy_init();assert(edr_p0_rule_ir_is_ready());
  }
  size_t after_size;unsigned char *after=read_bytes(archive,&after_size);
  assert(after_size==encrypted_size&&!memcmp(after,encrypted,after_size));
  free(after);free(encrypted);cJSON_free(json);cJSON_Delete(j);
 }
 puts("IR7 and IR8 parent purpose archives: exact independent masks and frozen bytes survive restart");
}
static void subject_command_purpose_contract(const char *base) {
 for(unsigned schema=7;schema<=9;schema++) {
  char json[1024],sha[65],archive[400];unsigned char *encrypted=NULL;size_t encrypted_size=0;
  int n=snprintf(json,sizeof(json),
   "{\"kind\":\"" EDR_P0_RULE_IR_BUNDLE_KIND "\",\"ir_schema_version\":%u,"
   "\"rules_bundle_version\":\"synthetic-subject-purpose\",\"rule_count\":1,"
   "\"sensor_interest_manifest_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
   "\"sensor_interest_manifest_hash_mode\":\"raw-json-v1-p0-artifact-sha256-zeroed\","
   "\"rules\":[{\"effect\":\"security_alert\",\"id\":\"synthetic-subject\",\"event_type\":\"process_create\","
   "\"condition\":{\"process_name_in\":[\"tool.exe\"]%s}}]}",schema,
   schema==9?",\"evidence_purposes\":[\"subject_command\"]":"");
  assert(n>0&&(size_t)n<sizeof(json));
  assert(edr_sha256_hex((const uint8_t*)json,(size_t)n,sha)==0);
  assert(edr_p0_encrypt_encrypt_edr1_for_test((const uint8_t*)json,(size_t)n,&encrypted,&encrypted_size)==0);
  snprintf(archive,sizeof(archive),"%s.purpose-%s.edr1",base,sha);save(archive,encrypted,encrypted_size);
  assert(edr_p0_rule_ir_validate_candidate_path(archive));
  const uint64_t expected=schema==9?EDR_EVIDENCE_COMMAND:0;
  for(int restart=0;restart<2;restart++) {
   assert(edr_p0_rule_ir_projection_matches("synthetic-subject",sha,expected,"")==1);
   assert(edr_p0_rule_ir_projection_matches("synthetic-subject",sha,expected^EDR_EVIDENCE_COMMAND,"")==0);
   edr_p0_rule_ir_shutdown();edr_p0_rule_ir_lazy_init();assert(edr_p0_rule_ir_is_ready());
  }
  size_t after_size;unsigned char *after=read_bytes(archive,&after_size);
  assert(after_size==encrypted_size&&!memcmp(after,encrypted,after_size));free(after);free(encrypted);
 }
 puts("IR7/8/9 subject-command authority: historical zero masks and IR9 command mask remain exact after restart; archive bytes unchanged");
}
static void parent_identity_purpose_contract(const char *base) {
 for(unsigned schema=7;schema<=10;schema++) for(unsigned identity=0;identity<2;identity++) {
  char json[1024],sha[65],archive[400];unsigned char *encrypted=NULL;size_t encrypted_size=0;
  int n=snprintf(json,sizeof(json),
   "{\"kind\":\"" EDR_P0_RULE_IR_BUNDLE_KIND "\",\"ir_schema_version\":%u,"
   "\"rules_bundle_version\":\"synthetic-parent-identity\",\"rule_count\":1,"
   "\"sensor_interest_manifest_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
   "\"sensor_interest_manifest_hash_mode\":\"raw-json-v1-p0-artifact-sha256-zeroed\","
   "\"rules\":[{\"effect\":\"security_alert\",\"id\":\"synthetic-parent\",\"event_type\":\"process_create\","
   "\"condition\":{\"process_name_in\":[\"tool.exe\"],\"evidence_purposes\":[\"actor_attribution\"%s]}}]}",schema,
   identity?",\"parent_identity\"":"");
  assert(n>0&&(size_t)n<sizeof(json));
  assert(edr_sha256_hex((const uint8_t*)json,(size_t)n,sha)==0);
  assert(edr_p0_encrypt_encrypt_edr1_for_test((const uint8_t*)json,(size_t)n,&encrypted,&encrypted_size)==0);
  snprintf(archive,sizeof(archive),"%s.purpose-%s.edr1",base,sha);save(archive,encrypted,encrypted_size);
  assert(edr_p0_rule_ir_validate_candidate_path(archive)==(int)(!identity||schema==10));
  if(!identity||schema==10) {
   const uint64_t expected=EDR_EVIDENCE_USER|(identity?EDR_EVIDENCE_PARENT_NAME:0);
   for(int restart=0;restart<2;restart++) {
    assert(edr_p0_rule_ir_projection_matches("synthetic-parent",sha,expected,"")==1);
    assert(edr_p0_rule_ir_projection_matches("synthetic-parent",sha,expected|EDR_EVIDENCE_PARENT_PATH,"")==0);
    if(!identity)assert(!edr_p0_rule_ir_projection_matches("synthetic-parent",sha,expected|EDR_EVIDENCE_PARENT_NAME,""));
    edr_p0_rule_ir_shutdown();edr_p0_rule_ir_lazy_init();assert(edr_p0_rule_ir_is_ready());
   }
  }
  size_t after_size;unsigned char *after=read_bytes(archive,&after_size);
  assert(after_size==encrypted_size&&!memcmp(after,encrypted,after_size));free(after);free(encrypted);
 }
 puts("IR7/8/9 frozen actor masks unchanged; only IR10 accepts explicit name-only purpose; archive bytes survive restart");
}
int main(void){
 static const struct {const char *id;unsigned schema;int retired;const char *rule;} corpus[]={
#include "../src/preprocess/p0_retired_purpose_vectors.inc"
 };
 for(size_t i=0;i<sizeof(corpus)/sizeof(corpus[0]);i++) {
  int actual=edr_p0_rule_ir_test_retired_purpose(corpus[i].schema,corpus[i].rule);
  if(actual!=corpus[i].retired) {fprintf(stderr,"retired predicate corpus %s expected=%d actual=%d\n",corpus[i].id,corpus[i].retired,actual);return 1;}
 }
 printf("shared retired predicate corpus: %zu cases passed\n",sizeof(corpus)/sizeof(corpus[0]));
 const char *source=getenv("EDR_P0_IR_PATH");assert(source);size_t size;unsigned char *raw=read_bytes(source,&size),*plain=NULL;size_t plain_size=0;
 assert(edr_p0_encrypt_decrypt_edr1(raw,size,&plain,&plain_size)==0);
 char base[256],stage[256];
#ifdef _WIN32
 unsigned long pid=(unsigned long)GetCurrentProcessId();
#else
 unsigned long pid=(unsigned long)getpid();
#endif
 snprintf(base,sizeof(base),"p0-purpose-test-%lu.edr1",pid);snprintf(stage,sizeof(stage),"p0-purpose-stage-%lu.edr1",pid);
 assert(setenv("EDR_P0_IR_PATH",base,1)==0);assert(setenv("EDR_P0_PURPOSE_ARCHIVE_BASE",base,1)==0);save(base,raw,size);
 edr_p0_rule_ir_lazy_init();assert(edr_p0_rule_ir_is_ready());
 current_consumer_projection_contract(plain,plain_size);
 EdrBehaviorRecord br;edr_behavior_record_init(&br);br.type=EDR_EVENT_PROCESS_CREATE;strcpy(br.process_name,"procdump.exe");strcpy(br.cmdline,"procdump.exe -ma lsass C:\\Temp\\lsass.dmp");
 EdrP0RuleIrEvaluation eval;assert(edr_p0_rule_ir_evaluate_record(&br,NULL,&eval));assert(eval.match_count);EdrP0RuleIrMatch match;assert(edr_p0_rule_ir_evaluation_get_match(&eval,0,&match));char sha[65];strcpy(sha,eval.binding.artifact_sha256);edr_p0_rule_ir_evaluation_free(&eval);
 assert(edr_p0_rule_ir_projection_matches(match.rule_id,sha,match.required_evidence_fields,match.operation_evidence));
 parent_purpose_contract(base,plain,plain_size);
 subject_command_purpose_contract(base);
 parent_identity_purpose_contract(base);
 EdrP0RuleIrMatch historical=match;historical.required_evidence_fields&=~EDR_EVIDENCE_PARENT_NAME;
 legacy_purpose_contract(base,plain,plain_size,&historical);
 dump_purpose_contract(base,plain,plain_size,&historical);
 cookie_purpose_contract(base,plain,plain_size,&match);
 assert(!edr_p0_rule_ir_projection_matches(match.rule_id,sha,match.required_evidence_fields|EDR_EVIDENCE_PARENT_PATH,match.operation_evidence));
 unsigned char *changed=malloc(plain_size+1),*encrypted=NULL;size_t encrypted_size=0;assert(changed);memcpy(changed,plain,plain_size);changed[plain_size]='\n';assert(edr_p0_encrypt_encrypt_edr1_for_test(changed,plain_size+1,&encrypted,&encrypted_size)==0);save(stage,encrypted,encrypted_size);
 assert(edr_p0_rule_ir_install_staged_bundle(stage,base));
 assert(edr_p0_rule_ir_projection_matches(match.rule_id,sha,match.required_evidence_fields,match.operation_evidence));
 edr_p0_rule_ir_shutdown();edr_p0_rule_ir_lazy_init();assert(edr_p0_rule_ir_is_ready());
 assert(edr_p0_rule_ir_projection_matches(match.rule_id,sha,match.required_evidence_fields,match.operation_evidence));
 char missing[400];snprintf(missing,sizeof(missing),"%s.purpose-missing",base);
 assert(setenv("EDR_P0_PURPOSE_ARCHIVE_BASE",missing,1)==0);
 assert(!edr_p0_rule_ir_projection_matches(match.rule_id,sha,match.required_evidence_fields,match.operation_evidence));
 assert(setenv("EDR_P0_PURPOSE_ARCHIVE_BASE",base,1)==0);
 char archived[400];snprintf(archived,sizeof(archived),"%s.purpose-%s.edr1",base,sha);raw[20]^=1;save(archived,raw,size);
 assert(!edr_p0_rule_ir_projection_matches(match.rule_id,sha,match.required_evidence_fields,match.operation_evidence));raw[20]^=1;save(archived,raw,size);
 assert(edr_p0_rule_ir_projection_matches(match.rule_id,sha,match.required_evidence_fields,match.operation_evidence));
 char saved[420];snprintf(saved,sizeof(saved),"%s.saved",archived);assert(!rename(archived,saved));assert(!make_directory(archived));
 assert(edr_p0_rule_ir_projection_matches(match.rule_id,sha,match.required_evidence_fields,match.operation_evidence)==-1);
 assert(!remove_directory(archived));assert(!rename(saved,archived));
 /* The altered envelope cannot be activated or replace the last valid one. */
 encrypted[20]^=1;save(stage,encrypted,encrypted_size);assert(!edr_p0_rule_ir_install_staged_bundle(stage,base));
 assert(edr_p0_rule_ir_projection_matches(match.rule_id,sha,match.required_evidence_fields,match.operation_evidence));
 /* Fill the bounded archive with named fixtures; no prior owner is evicted. */
 for(unsigned i=0;i<64u;i++){char held[400];snprintf(held,sizeof(held),"%s.purpose-capacity-%u",base,i);save(held,"x",1);}
 changed[plain_size]=' ';free(encrypted);encrypted=NULL;assert(edr_p0_encrypt_encrypt_edr1_for_test(changed,plain_size+1,&encrypted,&encrypted_size)==0);save(stage,encrypted,encrypted_size);
 assert(!edr_p0_rule_ir_install_staged_bundle(stage,base));
 assert(edr_p0_rule_ir_projection_matches(match.rule_id,sha,match.required_evidence_fields,match.operation_evidence));
 edr_p0_rule_ir_shutdown();free(raw);free(plain);free(changed);free(encrypted);
 puts("purpose authority: exact mask, hot update, restart, tampered archive and retained active bundle passed");return 0;
}
