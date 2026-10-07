#include "edr/p0_rule_ir.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
typedef struct {const char *id,*rule,*type,*name,*image,*command,*file,*ip;unsigned port;int want;} Case;
static const Case cases[]={
#include "../src/preprocess/p0_operation_vectors.inc"
};
int main(void) {
 edr_p0_rule_ir_lazy_init();assert(edr_p0_rule_ir_is_ready());
 for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
  const Case *c=&cases[i];EdrBehaviorRecord br;edr_behavior_record_init(&br);
  EdrEventType type=!strcmp(c->type,"file_read")?EDR_EVENT_FILE_READ:
      !strcmp(c->type,"process_create")?EDR_EVENT_PROCESS_CREATE:EDR_EVENT_NET_CONNECT;
  br.type=type;
  br.pid=123;br.process_start_key=456;br.process_creation_filetime_100ns=789;
  strcpy(br.endpoint_id,"fixture-endpoint");strcpy(br.tenant_id,"fixture-tenant");
  snprintf(br.process_name,sizeof(br.process_name),"%s",c->name);snprintf(br.exe_path,sizeof(br.exe_path),"%s",c->image);
  snprintf(br.cmdline,sizeof(br.cmdline),"%s",c->command);snprintf(br.file_path,sizeof(br.file_path),"%s",c->file);
  snprintf(br.net_dst,sizeof(br.net_dst),"%s",c->ip);br.net_dport=c->port;
  for(int variant=0;variant<5;variant++) {
   if(variant==1) br.process_start_key=0;
   if(variant==2) {br.process_start_key=456;edr_behavior_mark_source_truncated(&br,"source.cmdline");}
   if(variant==3) {edr_behavior_resolve_source_truncated(&br,"source.cmdline");br.type=EDR_EVENT_NET_LISTEN;}
   if(variant==4) {br.type=type;snprintf(br.script_snippet,sizeof(br.script_snippet),"%s",br.cmdline);br.cmdline[0]=0;}
   EdrP0RuleIrEvaluation evaluation;assert(edr_p0_rule_ir_evaluate_record(&br,NULL,&evaluation));int found=0;
   for(uint32_t j=0;j<evaluation.match_count;j++) {EdrP0RuleIrMatch match;assert(edr_p0_rule_ir_evaluation_get_match(&evaluation,j,&match));
    if(!strcmp(c->rule,match.rule_id)) {found=1;assert(match.effect==EDR_P0_EFFECT_SECURITY_ALERT);assert(!(match.required_evidence_fields&EDR_EVIDENCE_COMMAND));assert(match.required_evidence_fields&EDR_EVIDENCE_OPERATION);assert(!strstr(match.operation_evidence,"0123456789abcdef"));}
   }
   edr_p0_rule_ir_evaluation_free(&evaluation);
   if(found!=(variant==0?c->want:0)) {fprintf(stderr,"%s variant%d found%d want%d\n",c->id,variant,found,variant==0?c->want:0);return 1;}
  }
 }
 printf("strict operation corpus: %zu cases x 5 completeness/generation/type variants passed\n",sizeof(cases)/sizeof(cases[0]));return 0;
}
