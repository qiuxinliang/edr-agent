#include "edr/command_state.h"
#include "edr/command_result_json.h"
#include "edr/egress_request_policy.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <process.h>
#define pid _getpid
#define env(k,v) _putenv_s(k,v)
#else
#include <unistd.h>
#define pid getpid
#define env(k,v) setenv(k,v,1)
#endif
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); exit(1); } } while(0)
void edr_local_evidence_cache_record_command_result(const char *id,const char *type,const char *status,
    int execution,int code,const char *detail,const char *artifacts) {
  (void)id;(void)type;(void)status;(void)execution;(void)code;(void)detail;(void)artifacts;
}
static int allowed(const char *tenant,const char *endpoint,const char *body) {
  char why[128];
  return edr_egress_request_validate_for_scope("POST","ingest/report-command-result","application/json",
      body,strlen(body),tenant,endpoint,why,sizeof(why)) == 0;
}
static char *wire(const char *id,const char *type,const char *detail,const char *correlation) {
  char *body=edr_command_result_http_json("ep","test",id,type,1,0,detail,
      (int64_t)time(NULL)*1000,correlation,"",""); CHECK(body);return body;
}
static EdrSoarCommandMeta task(const char *id,const char *type) {
  EdrSoarCommandMeta m={0};
  snprintf(m.result_authorization.command_id,128,"%s",id);
  snprintf(m.result_authorization.command_type,64,"%s",type);
  snprintf(m.result_authorization.tenant_id,128,"tenant");
  snprintf(m.result_authorization.endpoint_id,128,"ep");
  m.result_authorization.expires_unix_ms=(int64_t)time(NULL)*1000+60000;
  return m;
}
int main(void) {
  char path[256];snprintf(path,sizeof(path),"./command-egress-%ld",(long)pid());
  env("EDR_COMMAND_STATE_DIR",path);
  EdrSoarCommandMeta m=task("cmd-query","rtq_execute");
  const char *detail="{\"rows\":[{\"pid\":12}]}";
  char *body=wire("cmd-query","rtq_execute",detail,"");
  CHECK(!allowed("tenant","ep",body));
  edr_egress_set_command_result_validator(edr_command_state_result_authorized);
  CHECK(!allowed("tenant","ep",body)); /* A plausible ID is not authority. */
  CHECK(edr_command_state_finish("cmd-query","rtq_execute",NULL,"ok",1,0,detail,"",1)==0);
  CHECK(!allowed("tenant","ep",body)); /* Legacy/unsigned terminal remains local. */
  CHECK(edr_command_state_store_inbox("cmd-query","rtq_execute",(const uint8_t *)"{}",2,&m)==0);
  EdrCommandInboxRecord inbox[2];int n=edr_command_state_collect_inbox(inbox,2);
  /* Existing final state suppresses inbox execution; use a fresh admitted task for reopen. */
  for(int i=0;i<n;i++) edr_command_state_free_inbox_record(&inbox[i]);
  EdrSoarCommandMeta saved=task("cmd-reopen","rtq_execute");
  CHECK(edr_command_state_store_inbox("cmd-reopen","rtq_execute",(const uint8_t *)"{}",2,&saved)==0);
  n=edr_command_state_collect_inbox(inbox,2);CHECK(n==1);
  CHECK(!strcmp(inbox[0].meta.result_authorization.tenant_id,"tenant"));
  CHECK(inbox[0].meta.result_authorization.expires_unix_ms==saved.result_authorization.expires_unix_ms);
  edr_command_state_free_inbox_record(&inbox[0]);
  CHECK(edr_command_state_finish("cmd-query","rtq_execute",&m,"ok",1,0,detail,"",1)==0);
  CHECK(allowed("tenant","ep",body));
  CHECK(!allowed("other","ep",body));CHECK(!allowed("tenant","other",body));
  char *tampered=wire("cmd-query","rtq_execute","unowned bytes","");
  CHECK(!allowed("tenant","ep",tampered));free(tampered);
  tampered=wire("cmd-query","shell_open",detail,"");CHECK(!allowed("tenant","ep",tampered));free(tampered);
  cJSON *root=cJSON_Parse(body);CHECK(root);CHECK(cJSON_AddStringToObject(root,"raw_inventory","no"));
  tampered=cJSON_PrintUnformatted(root);CHECK(tampered);CHECK(!allowed("tenant","ep",tampered));free(tampered);cJSON_Delete(root);
  EdrCommandStateRecord pending[4];n=edr_command_state_collect_pending(pending,4);CHECK(n==1);
  CHECK(edr_command_state_mark_report_retry(&pending[0],"transient",0)==0);
  CHECK(allowed("tenant","ep",body)); /* Disk reread, including retry metadata. */
  CHECK(edr_command_state_mark_reported(&pending[0])==0);CHECK(!allowed("tenant","ep",body));
  m.result_authorization.expires_unix_ms=(int64_t)time(NULL)*1000-1;
  CHECK(edr_command_state_finish("cmd-query","rtq_execute",&m,"ok",1,0,detail,"",1)==0);
  CHECK(!allowed("tenant","ep",body));free(body);
  EdrSoarCommandMeta shell=task("cmd-shell","shell_open");
  snprintf(shell.soar_correlation_id,sizeof(shell.soar_correlation_id),"cmd-shell");
  const char *chunk="{\"schema\":\"edr.shell.stream.v1\",\"session_id\":\"cmd-shell\",\"seq\":1,\"stream\":\"stdout\",\"data\":\"hello\\n\",\"exit_code\":0,\"closed\":false}";
  CHECK(edr_command_state_finish("cmd-shell.s000001","shell_stream",&shell,"ok",1,0,chunk,"",1)==0);
  body=wire("cmd-shell.s000001","shell_stream",chunk,"cmd-shell");CHECK(allowed("tenant","ep",body));
  shell.result_authorization.command_id[0]=0;
  CHECK(edr_command_state_finish("cmd-shell.s000001","shell_stream",&shell,"ok",1,0,chunk,"",1)==0);
  CHECK(!allowed("tenant","ep",body));free(body);
  char why[128];
  CHECK(edr_egress_request_validate_for_scope("POST","ingest/upload-file","multipart/form-data","x",1,"tenant","ep",why,sizeof(why))!=0);
  /* Compaction must retain complete >8KiB result lines and their authority. */
  env("EDR_COMMAND_STATE_MAX_BYTES","65536");
  char large[12001];memset(large,'x',sizeof(large)-1);large[sizeof(large)-1]=0;
  for (int i=0;i<16;i++) {
    char id[48];snprintf(id,sizeof(id),"cmd-large-%d",i);
    EdrSoarCommandMeta large_task=task(id,"rtq_execute");
    CHECK(edr_command_state_finish(id,"rtq_execute",&large_task,"ok",1,0,large,"",1)==0);
  }
  edr_command_state_compact_if_needed();
  body=wire("cmd-large-15","rtq_execute",large,"");
  CHECK(allowed("tenant","ep",body));free(body);
  puts("PASS: admitted task scope, exact terminal, durable retry, expiry, session binding, attachment denial");
  return 0;
}
