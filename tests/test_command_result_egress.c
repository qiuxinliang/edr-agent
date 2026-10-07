#include "edr/command_state.h"
#include "edr/command_result_json.h"
#include "edr/egress_request_policy.h"
#include "cJSON.h"
#include "edr/sha256.h"
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
static char *renewal(const char *id,const char *type,const char *kind,const char *content,int64_t expires) {
  char hash[65];CHECK(edr_sha256_hex((const uint8_t *)content,strlen(content),hash)==0);
  cJSON *o=cJSON_CreateObject();CHECK(o);
  cJSON_AddStringToObject(o,"schema","edr.result_delivery_renewal.v1");
  cJSON_AddStringToObject(o,"initiated_by","operator");
  cJSON_AddStringToObject(o,"tenant_id","tenant");cJSON_AddStringToObject(o,"endpoint_id","ep");
  cJSON_AddStringToObject(o,"target_command_id",id);cJSON_AddStringToObject(o,"target_command_type",type);
  cJSON_AddStringToObject(o,"target_kind",kind);cJSON_AddStringToObject(o,"target_sha256",hash);
  cJSON_AddNumberToObject(o,"expires_unix_ms",(double)expires);
  char *wire=cJSON_PrintUnformatted(o);cJSON_Delete(o);CHECK(wire);return wire;
}
static int renew(const char *request,const EdrSoarCommandMeta *meta) {
  return edr_command_state_renew_delivery("renew-1",(const uint8_t *)request,strlen(request),meta);
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
  CHECK(!allowed("tenant","ep",body));
  CHECK(edr_command_state_result_authorized("tenant","ep",body,strlen(body))==EDR_EGRESS_AUTHORIZATION_EXPIRED);
  n=edr_command_state_collect_pending(pending,4);CHECK(n==1);
  CHECK(edr_command_state_mark_report_held(&pending[0],"result_authorization_expired")==0);
  for(int i=0;i<3;i++)CHECK(edr_command_state_collect_pending(pending,4)==0);
  CHECK(edr_command_state_result_authorized("tenant","ep",body,strlen(body))==EDR_EGRESS_AUTHORIZATION_EXPIRED);
  /* Explicit delivery renewal does not re-execute or rewrite the terminal. */
  EdrCommandStateRecord original;CHECK(edr_command_state_begin("cmd-query","rtq_execute",NULL,NULL,&original)==EDR_COMMAND_STATE_BEGIN_DUP_FINAL);
  EdrSoarCommandMeta grant=task("renew-1","result_delivery_renewal");
  char *request=renewal("cmd-query","rtq_execute","result",detail,grant.result_authorization.expires_unix_ms);
  EdrSoarCommandMeta no_grant={0};CHECK(renew(request,&no_grant)==EDR_EGRESS_REQUEST_DENIED);
  EdrSoarCommandMeta other=grant;snprintf(other.result_authorization.endpoint_id,128,"wrong");
  CHECK(renew(request,&other)==EDR_EGRESS_REQUEST_DENIED);
  char *wrong=renewal("cmd-query","rtq_execute","result","changed",grant.result_authorization.expires_unix_ms);
  CHECK(renew(wrong,&grant)==EDR_EGRESS_REQUEST_DENIED);free(wrong);
  wrong=renewal("cmd-query","rtq_execute","result",detail,(int64_t)time(NULL)*1000-1);
  CHECK(renew(wrong,&grant)==EDR_EGRESS_REQUEST_DENIED);free(wrong);
  wrong=renewal("cmd-query","rtq_execute","result",detail,grant.result_authorization.expires_unix_ms+86400000LL);
  CHECK(renew(wrong,&grant)==EDR_EGRESS_REQUEST_DENIED);free(wrong);
  CHECK(renew(request,&grant)==0);CHECK(renew(request,&grant)==EDR_EGRESS_REQUEST_DENIED);free(request);
  CHECK(edr_command_state_mark_report_held(&original,"stale authorization expiry")==0);
  CHECK(allowed("tenant","ep",body));
  n=edr_command_state_collect_pending(pending,4);CHECK(n==1);
  CHECK(!pending[0].report_policy_held && pending[0].report_attempts==original.report_attempts);
  CHECK(pending[0].execution_status==original.execution_status && pending[0].exit_code==original.exit_code);
  CHECK(!strcmp(pending[0].detail,original.detail) && !strcmp(pending[0].agent_boot_id,original.agent_boot_id));
  EdrSoarCommandMeta duplicate_meta=task("cmd-query","rtq_execute");
  snprintf(duplicate_meta.idempotency_key,sizeof(duplicate_meta.idempotency_key),"new-signed-idempotency");
  CHECK(edr_command_state_begin("cmd-query","rtq_execute",&duplicate_meta,NULL,&original)==EDR_COMMAND_STATE_BEGIN_DUP_FINAL);
  CHECK(!strcmp(original.detail,detail) && original.result_authorization.expires_unix_ms==grant.result_authorization.expires_unix_ms);
  CHECK(edr_command_state_mark_reported(&pending[0])==0);
  request=renewal("cmd-query","rtq_execute","result",detail,grant.result_authorization.expires_unix_ms+1);
  grant.result_authorization.expires_unix_ms+=1000;
  CHECK(renew(request,&grant)==EDR_EGRESS_REQUEST_DENIED);free(request); /* ACK cannot be reopened. */
  free(body);
  EdrSoarCommandMeta upgrade=task("cmd-upgrade","agent_update");
  upgrade.issued_at_unix_ms=(int64_t)time(NULL)*1000;upgrade.deadline_ms=42;
  upgrade.result_authorization.expires_unix_ms=(int64_t)time(NULL)*1000-1;
  const char *pin="{\"task_id\":\"task-1\",\"artifact_id\":\"artifact-1\",\"hash\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"version\":\"2.1.0\",\"operation\":\"upgrade\",\"upgrade_class\":\"installer_required\"}";
  CHECK(edr_command_state_store_inbox("cmd-upgrade","agent_update",(const uint8_t*)pin,strlen(pin),&upgrade)==0);
  EdrEgressTaskScope expired_scope;
  CHECK(edr_command_state_task_scope("cmd-upgrade",&expired_scope)==EDR_EGRESS_AUTHORIZATION_EXPIRED);
  /* Duplicate delivery retains the existing payload and grant, even a newer expiry. */
  EdrSoarCommandMeta repeated=upgrade;repeated.result_authorization.expires_unix_ms+=100000;
  CHECK(edr_command_state_store_inbox("cmd-upgrade","agent_update",(const uint8_t*)pin,strlen(pin),&repeated)==0);
  request=renewal("cmd-upgrade","agent_update","upgrade_payload",pin,grant.result_authorization.expires_unix_ms);
  CHECK(renew(request,&grant)==0);CHECK(renew(request,&grant)==EDR_EGRESS_REQUEST_DENIED);free(request);
  CHECK(edr_command_state_store_inbox("cmd-upgrade","agent_update",(const uint8_t*)"{}",2,&repeated)!=0);
  EdrEgressTaskScope scope;CHECK(edr_command_state_task_scope("cmd-upgrade",&scope)==0);
  CHECK(!strcmp(scope.task_id,"task-1") && !strcmp(scope.upgrade_class,"installer_required"));
  n=edr_command_state_collect_inbox(inbox,2);int found_upgrade=0;
  for(int i=0;i<n;i++) {
    if(!strcmp(inbox[i].command_id,"cmd-upgrade")) {
      found_upgrade=1;CHECK(inbox[i].payload_len==strlen(pin) && !memcmp(inbox[i].payload,pin,strlen(pin)));
      CHECK(inbox[i].meta.issued_at_unix_ms==upgrade.issued_at_unix_ms && inbox[i].meta.deadline_ms==42);
      CHECK(inbox[i].meta.result_authorization.expires_unix_ms==grant.result_authorization.expires_unix_ms);
    }
    edr_command_state_free_inbox_record(&inbox[i]);
  }
  CHECK(found_upgrade);
  request=renewal("cmd-upgrade","agent_update","upgrade_payload",pin,grant.result_authorization.expires_unix_ms+1);
  grant.result_authorization.expires_unix_ms+=1000;
  char blocked[300];snprintf(blocked,sizeof(blocked),"%s/block",path);FILE *block=fopen(blocked,"wb");CHECK(block);CHECK(fclose(block)==0);
  env("EDR_COMMAND_STATE_DIR",blocked);CHECK(renew(request,&grant)==EDR_EGRESS_LOCAL_STATE_FAILURE);
  env("EDR_COMMAND_STATE_DIR",path);free(request);
  CHECK(edr_command_state_task_scope("cmd-upgrade",&scope)==0);
  CHECK(edr_command_state_task_scope("unowned",&scope)==EDR_EGRESS_REQUEST_DENIED);
  CHECK(edr_command_state_finish("cmd-upgrade","agent_update",&upgrade,"ok",1,0,"terminal acknowledged","",1)==0);
  EdrCommandStateRecord recovered;CHECK(edr_command_state_begin("cmd-upgrade","agent_update",NULL,NULL,&recovered)==EDR_COMMAND_STATE_BEGIN_DUP_FINAL);
  CHECK(recovered.result_authorization.expires_unix_ms>upgrade.result_authorization.expires_unix_ms);
  edr_command_state_delete_inbox("cmd-upgrade");CHECK(edr_command_state_task_scope("cmd-upgrade",&scope)==EDR_EGRESS_REQUEST_DENIED);
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
