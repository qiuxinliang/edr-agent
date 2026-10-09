#include "edr/p0_rule_ir.h"
#include "edr/encrypt_p0_rules.h"
#include "edr/sha256.h"
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
  assert(rule);cJSON *condition=cJSON_GetObjectItemCaseSensitive(rule,"condition");
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
 EdrBehaviorRecord br;edr_behavior_record_init(&br);br.type=EDR_EVENT_PROCESS_CREATE;strcpy(br.process_name,"procdump.exe");strcpy(br.cmdline,"procdump.exe -ma lsass C:\\Temp\\lsass.dmp");
 EdrP0RuleIrEvaluation eval;assert(edr_p0_rule_ir_evaluate_record(&br,NULL,&eval));assert(eval.match_count);EdrP0RuleIrMatch match;assert(edr_p0_rule_ir_evaluation_get_match(&eval,0,&match));char sha[65];strcpy(sha,eval.binding.artifact_sha256);edr_p0_rule_ir_evaluation_free(&eval);
 assert(edr_p0_rule_ir_projection_matches(match.rule_id,sha,match.required_evidence_fields,match.operation_evidence));
 parent_purpose_contract(base,plain,plain_size);
 legacy_purpose_contract(base,plain,plain_size,&match);
 dump_purpose_contract(base,plain,plain_size,&match);
 cookie_purpose_contract(base,plain,plain_size,&match);
 assert(!edr_p0_rule_ir_projection_matches(match.rule_id,sha,match.required_evidence_fields|EDR_EVIDENCE_PARENT_NAME,match.operation_evidence));
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
