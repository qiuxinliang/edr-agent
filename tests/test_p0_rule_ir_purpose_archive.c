#include "edr/p0_rule_ir.h"
#include "edr/encrypt_p0_rules.h"
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
int main(void){
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
