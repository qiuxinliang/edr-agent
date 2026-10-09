#include "edr/command_state.h"
#include "edr/command_result_json.h"
#include "edr/forensic_result_contract.h"
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
  const char *request=!strcmp(type,"rtq_execute")?"{\"process_name\":\"foo\"}":"{}";
  CHECK(edr_command_result_bind_contract(&m.result_authorization,(const uint8_t*)request,strlen(request),(int64_t)time(NULL)*1000)==0);
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
static char *persisted_body(const char *id,const char *type) {
  EdrCommandStateRecord *r=calloc(1,sizeof(*r));CHECK(r);
  CHECK(edr_command_state_begin(id,type,NULL,NULL,r)==EDR_COMMAND_STATE_BEGIN_DUP_FINAL);
  char *b=wire(id,type,r->detail,r->soar_correlation_id);free(r);return b;
}
static void typed_owner_case(const char *id,const char *type,const char *request,const char *detail,int allowed_result) {
  EdrSoarCommandMeta m=task(id,type);
  CHECK(edr_command_result_bind_contract(&m.result_authorization,(const uint8_t*)request,strlen(request),(int64_t)time(NULL)*1000)==0);
  CHECK(edr_command_state_finish(id,type,&m,"ok",1,0,detail,"",1)==0);
  char *body=persisted_body(id,type);CHECK(allowed("tenant","ep",body)==allowed_result);
  if(allowed_result)CHECK(!strstr(body,"UNRELATED-TEXT"));
  EdrCommandStateRecord *record=calloc(1,sizeof(*record));CHECK(record);
  CHECK(edr_command_state_begin(id,type,NULL,NULL,record)==EDR_COMMAND_STATE_BEGIN_DUP_FINAL);
  CHECK(record->report_pending && record->report_policy_held==!allowed_result);
  CHECK(!strcmp(record->result_authorization.content_contract,m.result_authorization.content_contract));
  free(record);free(body);
}
static void typed_owner_tests(void) {
  const char *process="{\"schema\":\"edr.process_response.v1\",\"action\":\"kill_process\",\"pid\":42,\"process_creation_filetime_100ns\":\"133700001\",\"reason\":\"process_exit_verified\",\"enforcement_verified\":true,\"stdout\":\"UNRELATED-TEXT\"}";
  typed_owner_case("typed-kill","kill_process","{\"pid\":42,\"process_creation_filetime_100ns\":\"133700001\"}",process,1);
  typed_owner_case("typed-kill-wrong","kill_process","{\"pid\":42,\"process_creation_filetime_100ns\":\"133700002\"}",process,0);
  const char *iso="{\"schema\":\"edr.isolation.status.v1\",\"isolated\":true,\"restored\":false,\"enforcement_verified\":true,\"management_reachable\":null,\"password\":\"UNRELATED-TEXT\"}";
  typed_owner_case("typed-isolate","isolate_host","{}",iso,1);
  typed_owner_case("typed-restore-wrong","restore_host","{}",iso,0);
  const char *forensic="{\"schema\":\"edr.forensic.result.v1\",\"status\":\"success\",\"source\":\"builtin\",\"sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"object_key\":\"tenant/ep/artifact\",\"artifact\":\"C:/Users/UNRELATED-TEXT/dump.bin\",\"upload_status\":\"ok\",\"truncated\":false,\"raw_detail\":\"UNRELATED-TEXT\"}";
  typed_owner_case("typed-forensic","forensic","{}",forensic,1);
  const char *yara="{\"schema\":\"edr.yara_scan.result.v1\",\"status\":\"success\",\"source\":\"libyara\",\"engine\":\"libyara\",\"scan_status\":\"completed\",\"target_type\":\"file\",\"target_path\":\"C:/Lab/a.bin\",\"sha256\":\"\",\"object_key\":\"\",\"upload_status\":\"not_requested\",\"matches\":[{\"path\":\"C:/Lab/a.bin\",\"rules\":[\"test_rule\"],\"memory\":\"UNRELATED-TEXT\"}]}";
  typed_owner_case("typed-yara","yara_scan","{\"target_path\":\"C:/Lab/a.bin\"}",yara,1);
  const char *pmfe="{\"schema\":\"pmfe_result_v1\",\"status\":\"completed_clean\",\"verdict\":\"clean\",\"task_id\":\"typed-pmfe\",\"target\":{\"pid\":42,\"path\":\"C:/Lab/app.exe\",\"stdout\":\"UNRELATED-TEXT\"},\"scan\":{\"started_unix_ms\":1000,\"finished_unix_ms\":1100,\"duration_ms\":100,\"regions_read\":2},\"signals\":{\"stomp_suspicious\":0,\"entropy_max\":0,\"dns_sample\":\"UNRELATED-TEXT\",\"yara_status\":\"completed\"},\"regions\":[],\"artifacts\":[],\"raw_detail\":\"UNRELATED-TEXT\"}";
  typed_owner_case("typed-pmfe","pmfe_scan","{\"pid\":42}",pmfe,1);
  /* Actual engine states: Windows missing YARA session, and non-Windows
   * injection correlation. Neither is arbitrary diagnostic prose. */
  const char *pmfe_ids[]={"typed-pmfe-unavailable","typed-pmfe-platform","typed-pmfe-unknown"};
  for(unsigned i=0;i<3;i++) {
    cJSON *sample=cJSON_Parse(pmfe);CHECK(sample);
    CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(sample,"task_id"),pmfe_ids[i]));
    cJSON *signals=cJSON_GetObjectItemCaseSensitive(sample,"signals");
    CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(signals,"yara_status"),i==2?"arbitrary_status":"unavailable"));
    if(i==1) {
      cJSON *correlation=cJSON_AddObjectToObject(sample,"correlation");CHECK(correlation);
      cJSON *injection=cJSON_AddObjectToObject(correlation,"injection_signal");CHECK(injection);
      CHECK(cJSON_AddStringToObject(injection,"status","unsupported_platform"));
      CHECK(cJSON_AddBoolToObject(injection,"observed",0));
    }
    char *detail=cJSON_PrintUnformatted(sample);CHECK(detail);
    typed_owner_case(pmfe_ids[i],"pmfe_scan","{\"pid\":42}",detail,i!=2);
    free(detail);cJSON_Delete(sample);
  }

  const char *receipt="{\"manifest_path\":\"C:/Synthetic/manifest.json\",\"bundle_path\":\"C:/Synthetic/bundle.tgz\",\"sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"upload_status\":\"ok\",\"minio_key\":\"tenant/endpoint/task/bundle\",\"outbox\":\"none\"}";
  char normalized[8192];
  const char *normal=edr_command_normalize_forensic_result("forensic",EdrCmdExecOk,0,receipt,normalized,sizeof(normalized));
  CHECK(normal==normalized && strstr(normal,"tenant/endpoint/task/bundle"));
  typed_owner_case("typed-real-forensic","forensic","{}",normal,1);
  char *wire_receipt=persisted_body("typed-real-forensic","forensic");
  CHECK(strstr(wire_receipt,"tenant/endpoint/task/bundle") && !strstr(wire_receipt,"C:/Synthetic"));free(wire_receipt);
  puts("PASS: typed kill/isolation/forensic/YARA/PMFE through durable owner, serialization and final guard; wrong generation and reverse action held without ACK");
}

static void shell_open_purpose_tests(void) {
  EdrSoarCommandMeta m=task("opened-session","shell_open");
  const char *raw="{\"schema\":\"edr.shell.session.v1\",\"session_id\":\"opened-session\",\"status\":\"ok\",\"exit_code\":0,\"closed\":false}";
  const char *injected="{\"schema\":\"edr.shell.session.v1\",\"session_id\":\"opened-session\",\"status\":\"ok\",\"exit_code\":0,\"closed\":false,\"shell_type\":\"UNRELATED_SHELL\",\"stdout\":\"UNRELATED_OUTPUT\",\"raw_detail\":\"UNRELATED_TEXT\"}";
  char projected[16384],wrapped_projection[16384],canonical_projection[16384];
  CHECK(edr_command_result_project_detail(&m.result_authorization,"shell_open",1,0,raw,projected,sizeof(projected))==0);
  CHECK(strstr(projected,"shell session opened:") && strstr(projected,"\"status\":\"ok\""));
  cJSON *wrapper=cJSON_CreateObject();CHECK(wrapper);
  CHECK(cJSON_AddStringToObject(wrapper,"task_id","opened-session") &&
        cJSON_AddStringToObject(wrapper,"status","ok") && cJSON_AddNumberToObject(wrapper,"exit_code",0) &&
        cJSON_AddStringToObject(wrapper,"raw_detail",injected));
  char *wrapped=cJSON_PrintUnformatted(wrapper);CHECK(wrapped);cJSON_Delete(wrapper);
  CHECK(edr_command_result_project_detail(&m.result_authorization,"shell_open",1,0,wrapped,wrapped_projection,sizeof(wrapped_projection))==0);
  CHECK(!strcmp(projected,wrapped_projection) && !strstr(projected,"UNRELATED"));
  CHECK(edr_command_result_project_detail(&m.result_authorization,"shell_open",1,0,projected,canonical_projection,sizeof(canonical_projection))==0);
  CHECK(!strcmp(projected,canonical_projection));
  CHECK(edr_command_state_finish("opened-session","shell_open",&m,"ok",1,0,wrapped,"",1)==0);
  char *body=persisted_body("opened-session","shell_open");
  CHECK(allowed("tenant","ep",body) && !allowed("wrong","ep",body) && !allowed("tenant","wrong",body));
  CHECK(strstr(body,"shell session opened:") && !strstr(body,"UNRELATED"));
  char *tampered=wire("opened-session","shell_open",injected,"");CHECK(!allowed("tenant","ep",tampered));free(tampered);
  EdrCommandStateRecord *record=calloc(1,sizeof(*record));CHECK(record);
  CHECK(edr_command_state_begin("opened-session","shell_open",NULL,NULL,record)==EDR_COMMAND_STATE_BEGIN_DUP_FINAL);
  CHECK(!strcmp(record->detail,projected) && !record->report_policy_held && record->report_pending);
  CHECK(edr_command_state_mark_reported(record)==0);
  CHECK(edr_command_state_finish("opened-session","shell_open",&m,"ok",1,0,wrapped,"",1)==0);
  CHECK(!allowed("tenant","ep",body));free(record);free(body);free(wrapped);
  const char *invalid[]={
      "shell session opened: cmd.exe",
      "{\"schema\":\"edr.command.status.v1\",\"status\":1,\"exit_code\":0,\"diagnostic\":\"command_completed\"}",
      "{\"task_id\":\"opened-session\",\"status\":\"ok\",\"raw_detail\":\"shell session opened: cmd.exe\"}",
      "{\"schema\":\"edr.shell.session.v1\",\"session_id\":\"other-session\",\"status\":\"ok\",\"exit_code\":0,\"closed\":false}",
      "{\"schema\":\"edr.shell.session.v1\",\"session_id\":\"opened-session\",\"status\":\"failed\",\"exit_code\":0,\"closed\":false}",
      "{\"schema\":\"edr.shell.session.v1\",\"session_id\":\"opened-session\",\"status\":1,\"exit_code\":0,\"closed\":false}",
      "{\"schema\":\"edr.shell.session.v1\",\"session_id\":\"opened-session\",\"status\":\"ok\",\"exit_code\":1,\"closed\":false}",
      "{\"schema\":\"edr.shell.session.v1\",\"session_id\":\"opened-session\",\"status\":\"ok\",\"exit_code\":0,\"closed\":true}",
      "{\"schema\":\"edr.shell.session.v1\",\"session_id\":\"opened-session\",\"status\":\"ok\",\"exit_code\":0}"};
  for(size_t i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++)
    CHECK(edr_command_result_project_detail(&m.result_authorization,"shell_open",1,0,invalid[i],canonical_projection,sizeof(canonical_projection))!=0);
  CHECK(edr_command_result_project_detail(&m.result_authorization,"shell_open",1,1,raw,canonical_projection,sizeof(canonical_projection))!=0);
  CHECK(edr_command_result_project_detail(&m.result_authorization,"shell_input",1,0,raw,canonical_projection,sizeof(canonical_projection))!=0);
  CHECK(edr_command_result_project_detail(&m.result_authorization,"shell_open",2,1,raw,canonical_projection,sizeof(canonical_projection))==0 &&
        strstr(canonical_projection,"command_rejected") && !strstr(canonical_projection,"opened"));
  EdrCommandResultAuthorization wrong=m.result_authorization;
  snprintf(wrong.command_type,sizeof(wrong.command_type),"rtr_shell");
  CHECK(edr_command_result_project_detail(&wrong,"shell_open",1,0,raw,canonical_projection,sizeof(canonical_projection))!=0);
  wrong=m.result_authorization;
  cJSON *contract=cJSON_Parse(wrong.content_contract);CHECK(contract);
  cJSON_SetNumberValue(cJSON_GetObjectItemCaseSensitive(contract,"max_bytes"),64);
  CHECK(cJSON_PrintPreallocated(contract,wrong.content_contract,sizeof(wrong.content_contract),0));cJSON_Delete(contract);
  CHECK(edr_command_result_project_detail(&wrong,"shell_open",1,0,raw,canonical_projection,sizeof(canonical_projection))!=0);
  m=task("expired-open","shell_open");m.result_authorization.expires_unix_ms=(int64_t)time(NULL)*1000-1;
  const char *expired="{\"schema\":\"edr.shell.session.v1\",\"session_id\":\"expired-open\",\"status\":\"ok\",\"exit_code\":0,\"closed\":false}";
  CHECK(edr_command_state_finish("expired-open","shell_open",&m,"ok",1,0,expired,"",1)==0);
  body=persisted_body("expired-open","shell_open");CHECK(!allowed("tenant","ep",body));free(body);
  puts("PASS: typed shell-open control survives real owner, serializer and final gate; legacy/generic success never becomes opened; binding, projection, expiry and ACK remain enforced");
}

static void rtq_diagnostic_purpose_tests(void) {
  static const struct { const char *request; const char *row; } cases[] = {
    {"{\"process_name\":\"foo\"}", "{\"type\":\"process\",\"name\":\"foo\",\"pid\":1}"},
    {"{\"network_remote_port\":443}", "{\"type\":\"network\",\"remote_port\":443}"},
    {"{\"file_path\":\"/tmp/foo\"}", "{\"type\":\"file\",\"path\":\"/tmp/foo\",\"size\":1}"},
    {"{\"registry_path\":\"HKLM\\\\Software\\\\Allowed\"}", "{\"type\":\"registry\",\"key\":\"HKLM\\\\Software\\\\Allowed\",\"value\":\"v\"}"},
    {"{\"eventlog_channel\":\"Security\"}", "{\"type\":\"eventlog\",\"channel\":\"Security\",\"query\":\"*\",\"provider\":\"Synthetic\",\"timestamp\":\"2026-10-09T18:58:14Z\",\"event_id\":4624,\"record_id\":1}"},
    {"{\"script_content\":\"foo\"}", "{\"type\":\"process\",\"name\":\"powershell\",\"cmdline\":\"foo\",\"pid\":1}"}
  };
  char detail[2048], projected[16384], canonical[16384], id[64];
  for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
    snprintf(id,sizeof(id),"rtq-warning-%zu",i);
    EdrSoarCommandMeta m=task(id,"rtq_execute");
    CHECK(edr_command_result_bind_contract(&m.result_authorization,(const uint8_t*)cases[i].request,
        strlen(cases[i].request),(int64_t)time(NULL)*1000)==0);
    snprintf(detail,sizeof(detail),"{\"results\":[%s],\"truncated\":true,\"error\":null,\"errors\":[{\"source\":\"command_result_transport\",\"code\":\"result_truncated\",\"severity\":\"warning\",\"retryable\":false,\"message\":\"UNRELATED diagnostic text\"}]}",cases[i].row);
    CHECK(edr_command_result_project_detail(&m.result_authorization,"rtq_execute",1,0,detail,projected,sizeof(projected))==0);
    CHECK(strstr(projected,"\"severity\":\"warning\"") && strstr(projected,"\"error\":null") &&
        strstr(projected,"\"warning_count\":1") && !strstr(projected,"UNRELATED"));
    CHECK(edr_command_result_project_detail(&m.result_authorization,"rtq_execute",1,0,projected,canonical,sizeof(canonical))==0 && !strcmp(projected,canonical));
    CHECK(edr_command_state_finish(id,"rtq_execute",&m,"ok",1,0,detail,"",1)==0);
    char *body=persisted_body(id,"rtq_execute");CHECK(allowed("tenant","ep",body));free(body);
  }
  EdrSoarCommandMeta m=task("rtq-hard-diagnostic","rtq_execute");
  const char *failure="{\"results\":[],\"truncated\":false,\"errors\":[{\"source\":\"process\",\"code\":\"snapshot_failed\",\"severity\":\"warning\",\"retryable\":true}]}";
  CHECK(edr_command_result_project_detail(&m.result_authorization,"rtq_execute",1,0,failure,projected,sizeof(projected))==0);
  CHECK(strstr(projected,"\"severity\":\"error\"") && strstr(projected,"collector_diagnostic") && strstr(projected,"\"retryable\":true"));
  const char *invalid="{\"results\":[],\"errors\":[{\"source\":\"process\",\"code\":\"snapshot_failed\",\"retryable\":\"false\"}]}";
  CHECK(edr_command_result_project_detail(&m.result_authorization,"rtq_execute",1,0,invalid,projected,sizeof(projected))!=0);
  puts("PASS: RTQ bounded diagnostics preserve warnings across projection, durable owner and final gate for all six query categories; real errors cannot be downgraded");
}

static void purpose_tests(void) {
  shell_open_purpose_tests();
  rtq_diagnostic_purpose_tests();
  EdrSoarCommandMeta q=task("purpose-query","rtq_execute");
  const char *injected="{\"results\":[{\"type\":\"process\",\"pid\":12,\"name\":\"foo\",\"user\":\"UNRELATED_IDENTITY\",\"cmdline\":\"UNRELATED_COMMAND\",\"extra\":{\"secret\":\"UNRELATED_NESTED\"}}],\"total\":1,\"raw_extra\":\"UNRELATED_TOP\"}";
  CHECK(edr_command_state_finish("purpose-query","rtq_execute",&q,"ok",1,0,injected,"",1)==0);
  char *b=persisted_body("purpose-query","rtq_execute");
  CHECK(!strstr(b,"UNRELATED") && allowed("tenant","ep",b));
  char *raw=wire("purpose-query","rtq_execute",injected,"");CHECK(!allowed("tenant","ep",raw));free(raw);
  free(b);
  q=task("wrong-query-row","rtq_execute");
  const char *wrong="{\"results\":[{\"type\":\"process\",\"pid\":12,\"name\":\"unrequested\"}]}";
  CHECK(edr_command_state_finish("wrong-query-row","rtq_execute",&q,"ok",1,0,wrong,"",1)==0);
  b=persisted_body("wrong-query-row","rtq_execute");CHECK(!allowed("tenant","ep",b));free(b);
  char rows[16384]="{\"results\":[";
  for(int i=0;i<501;i++)strcat(rows,i?",{\"type\":\"process\",\"name\":\"foo\"}":"{\"type\":\"process\",\"name\":\"foo\"}");
  strcat(rows,"]}");char projected[16384];CHECK(edr_command_result_project_detail(&q.result_authorization,"rtq_execute",1,0,rows,projected,sizeof(projected))!=0);
  q=task("cached-purpose","rtq_query");
  const char *request="{\"process_name\":\"foo\",\"limit\":2,\"time_window_s\":60}";
  int64_t now=(int64_t)time(NULL)*1000;
  CHECK(edr_command_result_bind_contract(&q.result_authorization,(const uint8_t*)request,strlen(request),now)==0);
  char cached[1024];snprintf(cached,sizeof(cached),"{\"rows\":[{\"source\":\"ring\",\"event_time_ns\":%.0f,\"type\":1,\"pid\":12,\"endpoint_id\":\"ep\",\"process_name\":\"foo\",\"cmdline\":\"UNREQUESTED_CMD\"}],\"partial\":false}",(double)now*1000000);
  CHECK(edr_command_state_finish("cached-purpose","rtq_query",&q,"ok",1,0,cached,"",1)==0);
  b=persisted_body("cached-purpose","rtq_query");CHECK(!strstr(b,"UNREQUESTED")&&allowed("tenant","ep",b));free(b);
  snprintf(cached,sizeof(cached),"{\"rows\":[{\"event_time_ns\":%.0f,\"type\":1,\"pid\":12,\"endpoint_id\":\"ep\",\"process_name\":\"foo\"}]}",(double)(now-120000)*1000000);
  CHECK(edr_command_result_project_detail(&q.result_authorization,"rtq_query",1,0,cached,projected,sizeof(projected))!=0);
  q=task("status-purpose","noop");
  CHECK(edr_command_state_finish("status-purpose","noop",&q,"ok",1,0,"UNRELATED arbitrary stdout and diagnostic","",1)==0);
  b=persisted_body("status-purpose","noop");CHECK(!strstr(b,"UNRELATED")&&strstr(b,"command_completed")&&allowed("tenant","ep",b));
  raw=wire("status-purpose","noop","{\"stdout\":\"UNRELATED\"}","");CHECK(!allowed("tenant","ep",raw));free(raw);free(b);
  q=task("shell-purpose","rtr_shell");request="{\"command\":\"echo synthetic\"}";
  CHECK(edr_command_result_bind_contract(&q.result_authorization,(const uint8_t*)request,strlen(request),now)==0);
  const char *output="{\"command\":\"echo synthetic\",\"output\":\"synthetic stdout\",\"exit_code\":0,\"timeout_sec\":30,\"output_truncated\":false,\"unrelated\":\"DROP_THIS\"}";
  CHECK(edr_command_state_finish("shell-purpose","rtr_shell",&q,"ok",1,0,output,"",1)==0);
  b=persisted_body("shell-purpose","rtr_shell");CHECK(strstr(b,"synthetic stdout")&&!strstr(b,"DROP_THIS")&&allowed("tenant","ep",b));free(b);
  q=task("bounded-session","shell_open");snprintf(q.soar_correlation_id,sizeof(q.soar_correlation_id),"bounded-session");
  const char *chunk="{\"schema\":\"edr.shell.stream.v1\",\"session_id\":\"bounded-session\",\"seq\":1,\"stream\":\"stdout\",\"data\":\"first\",\"exit_code\":0,\"closed\":false}";
  const char *changed="{\"schema\":\"edr.shell.stream.v1\",\"session_id\":\"bounded-session\",\"seq\":1,\"stream\":\"stdout\",\"data\":\"changed\",\"exit_code\":0,\"closed\":false}";
  CHECK(edr_command_state_finish("bounded-session.s000001","shell_stream",&q,"ok",1,0,chunk,"",1)==0);
  CHECK(edr_command_state_finish("bounded-session.s000001","shell_stream",&q,"ok",1,0,changed,"",1)==-2);
  b=persisted_body("bounded-session.s000001","shell_stream");CHECK(allowed("tenant","ep",b));
  EdrCommandStateRecord *r=calloc(1,sizeof(*r));CHECK(r);
  CHECK(edr_command_state_begin("bounded-session.s000001","shell_stream",NULL,NULL,r)==EDR_COMMAND_STATE_BEGIN_DUP_FINAL);
  CHECK(edr_command_state_mark_reported(r)==0);
  CHECK(edr_command_state_finish("bounded-session.s000001","shell_stream",&q,"ok",1,0,chunk,"",1)==0);
  CHECK(!allowed("tenant","ep",b));free(r);free(b);
  const char *over="{\"schema\":\"edr.shell.stream.v1\",\"session_id\":\"bounded-session\",\"seq\":64,\"stream\":\"stdout\",\"data\":\"over budget\",\"exit_code\":0,\"closed\":false}";
  CHECK(edr_command_state_finish("bounded-session.s000064","shell_stream",&q,"ok",1,0,over,"",1)==0);
  b=persisted_body("bounded-session.s000064","shell_stream");CHECK(!allowed("tenant","ep",b));free(b);
  const char *registry_request="{\"registry_path\":\"HKLM\\\\Software\\\\Allowed\",\"registry_mode\":\"subtree\"}";
  q=task("registry-scope","rtq_execute");
  CHECK(edr_command_result_bind_contract(&q.result_authorization,(const uint8_t*)registry_request,strlen(registry_request),now)==0);
  const char *registry_rows[]={
    "{\"results\":[{\"type\":\"registry\",\"key\":\"hklm\\\\software\\\\allowed\\\\child\",\"value\":\"v\",\"data\":\"synthetic\",\"reg_type\":1}]}",
    "{\"results\":[{\"type\":\"registry\",\"key\":\"HKLM\\\\Software\\\\AllowedSibling\",\"value\":\"v\",\"reg_type\":1}]}",
    "{\"results\":[{\"type\":\"registry\",\"key\":\"xHKLM\\\\Software\\\\Allowed\",\"value\":\"v\",\"reg_type\":1}]}"};
  for(int i=0;i<3;i++)CHECK((edr_command_result_project_detail(&q.result_authorization,"rtq_execute",1,0,registry_rows[i],projected,sizeof(projected))==0)==(i==0));
  const char *invalid_requests[]={"{\"limit\":1,\"limit\":2}","{\"process_name\":\"a\",\"process_name_contains\":\"b\"}","{\"limit\":1001}","{\"time_window_s\":604801}","{\"type\":\"network\\u0000file\"}","{} {}"};
  q=task("query-json-boundary","rtq_query");
  for(size_t i=0;i<sizeof(invalid_requests)/sizeof(invalid_requests[0]);i++)CHECK(edr_command_result_bind_contract(&q.result_authorization,(const uint8_t*)invalid_requests[i],strlen(invalid_requests[i]),now)!=0);
  const char *network_request="{\"event_type\":\"network\",\"limit\":1000,\"time_window_s\":604800}";
  CHECK(edr_command_result_bind_contract(&q.result_authorization,(const uint8_t*)network_request,strlen(network_request),now)==0);
  snprintf(cached,sizeof(cached),"{\"rows\":[{\"source\":\"ring\",\"event_time_ns\":%.0f,\"type\":20,\"pid\":12,\"endpoint_id\":\"ep\",\"process_name\":\"foo\",\"remote_ip\":\"192.0.2.1\",\"dst_port\":445}]}",(double)now*1000000);
  CHECK(edr_command_result_project_detail(&q.result_authorization,"rtq_query",1,0,cached,projected,sizeof(projected))==0&&strstr(projected,"192.0.2.1")&&strstr(projected,"445"));
  cJSON *wrong_type=cJSON_Parse(cached);CHECK(wrong_type);cJSON_SetNumberValue(cJSON_GetObjectItemCaseSensitive(cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(wrong_type,"rows"),0),"type"),1);
  char *wrong_type_json=cJSON_PrintUnformatted(wrong_type);CHECK(wrong_type_json);
  CHECK(edr_command_result_project_detail(&q.result_authorization,"rtq_query",1,0,wrong_type_json,projected,sizeof(projected))!=0);free(wrong_type_json);cJSON_Delete(wrong_type);


  q=task("cached-generation","rtq_query");
  request="{\"process_name_contains\":\"foo\",\"process_start_key\":\"99\"}";
  CHECK(edr_command_result_bind_contract(&q.result_authorization,(const uint8_t*)request,strlen(request),now)==0);
  snprintf(cached,sizeof(cached),"{\"rows\":[{\"event_time_ns\":%.0f,\"type\":1,\"pid\":12,\"endpoint_id\":\"ep\",\"process_name\":\"foo\",\"process_start_key\":\"99\"}],\"partial\":false}",(double)now*1000000);
  CHECK(edr_command_result_project_detail(&q.result_authorization,"rtq_query",1,0,cached,projected,sizeof(projected))==0);
  char *birth=strstr(cached,"\"process_start_key\":\"99\"");CHECK(birth);birth[strlen("\"process_start_key\":\"9")]='8';
  CHECK(edr_command_result_project_detail(&q.result_authorization,"rtq_query",1,0,cached,projected,sizeof(projected))!=0);
  request="{\"file_sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}";
  CHECK(edr_command_result_bind_contract(&q.result_authorization,(const uint8_t*)request,strlen(request),now)==0);
  CHECK(edr_command_result_project_detail(&q.result_authorization,"rtq_query",1,0,cached,projected,sizeof(projected))!=0);
  /* Existing script-only queries select process rows, and require the same
   * effective command predicate and engine OR match as the live collector. */
  typed_owner_case("script-query","rtq_execute","{\"script_content\":\"Write-Output\",\"script_engine\":\"powershell\"}",
      "{\"results\":[{\"type\":\"process\",\"pid\":42,\"name\":\"powershell.exe\",\"cmdline\":\"powershell Write-Output synthetic\",\"user\":\"UNRELATED-TEXT\"}],\"truncated\":false}",1);
  typed_owner_case("script-query-wrong","rtq_execute","{\"script_content\":\"Write-Output\"}",
      "{\"results\":[{\"type\":\"process\",\"pid\":42,\"name\":\"powershell.exe\",\"cmdline\":\"powershell Get-Date\"}],\"truncated\":false}",0);
  typed_owner_case("unknown-query-key","rtq_execute","{\"process_unrelated\":\"x\"}",
      "{\"results\":[{\"type\":\"process\",\"pid\":42,\"name\":\"foo\"}],\"truncated\":false}",0);
  typed_owner_case("eventlog-query","rtq_execute","{\"eventlog_channel\":\"System\"}",
      "{\"results\":[{\"type\":\"eventlog\",\"channel\":\"System\",\"query\":\"*\",\"provider\":\"Synthetic\",\"timestamp\":\"2026-10-08T00:00:00Z\",\"event_id\":10,\"record_id\":1,\"xml\":\"UNRELATED-TEXT\"}],\"truncated\":false}",1);
  typed_owner_case("eventlog-metadata-missing","rtq_execute","{\"eventlog_channel\":\"System\"}",
      "{\"results\":[{\"type\":\"eventlog\",\"channel\":\"System\",\"query\":\"*\"}],\"truncated\":false}",0);
  typed_owner_case("invalid-completeness","rtq_execute","{\"process_name\":\"foo\"}",
      "{\"results\":[{\"type\":\"process\",\"name\":\"foo\"}],\"truncated\":\"false\"}",0);
  const char *unsupported_types[]={"rtr_process_tree","velo_query"};
  const char *uncontracted="{\"rows\":[{\"field\":\"ORIGINAL-LOCAL-EVIDENCE\"}]}";
  for(int i=0;i<2;i++) {
    char id[64];snprintf(id,sizeof(id),"unsupported-%s",unsupported_types[i]);
    typed_owner_case(id,unsupported_types[i],"{}",uncontracted,0);
    EdrCommandStateRecord *held=calloc(1,sizeof(*held));CHECK(held);
    CHECK(edr_command_state_begin(id,unsupported_types[i],NULL,NULL,held)==EDR_COMMAND_STATE_BEGIN_DUP_FINAL);
    CHECK(!strcmp(held->detail,uncontracted) && held->report_pending && held->report_policy_held);
    free(held);
  }

  typed_owner_tests();
  puts("PASS: real RTQ categories/filters/row and time bounds; unrelated data projected before freeze; final guard rejects injection; stdout owner and durable slot budget/ACK invariants");
}

int main(void) {
  char path[256];snprintf(path,sizeof(path),"./command-egress-%ld",(long)pid());
  env("EDR_COMMAND_STATE_DIR",path);
  EdrSoarCommandMeta m=task("cmd-query","rtq_execute");
  const char *detail="{\"results\":[{\"type\":\"process\",\"pid\":12,\"name\":\"foo\"}],\"total\":1,\"truncated\":false,\"errors\":[],\"error\":null}";
  char *body=wire("cmd-query","rtq_execute",detail,"");
  CHECK(!allowed("tenant","ep",body));
  edr_egress_set_command_result_validator(edr_command_state_result_authorized);
  CHECK(!allowed("tenant","ep",body)); /* A plausible ID is not authority. */
  CHECK(edr_command_state_finish("cmd-legacy","rtq_execute",NULL,"ok",1,0,detail,"",0)==0);
  CHECK(!allowed("tenant","ep",body)); /* Legacy/unsigned terminal remains local. */
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
  CHECK(edr_command_state_finish("cmd-query","rtq_execute",&m,"ok",1,0,detail,"",1)==0);
  CHECK(!allowed("tenant","ep",body)); /* Identical finish cannot reopen ACK. */
  free(body);body=wire("cmd-expired","rtq_execute",detail,"");
  m=task("cmd-expired","rtq_execute");
  m.result_authorization.expires_unix_ms=(int64_t)time(NULL)*1000-1;
  CHECK(edr_command_state_finish("cmd-expired","rtq_execute",&m,"ok",1,0,detail,"",1)==0);
  CHECK(!allowed("tenant","ep",body));
  CHECK(edr_command_state_result_authorized("tenant","ep",body,strlen(body))==EDR_EGRESS_AUTHORIZATION_EXPIRED);
  n=edr_command_state_collect_pending(pending,4);CHECK(n==1);
  CHECK(edr_command_state_mark_report_held(&pending[0],"result_authorization_expired")==0);
  for(int i=0;i<3;i++)CHECK(edr_command_state_collect_pending(pending,4)==0);
  CHECK(edr_command_state_result_authorized("tenant","ep",body,strlen(body))==EDR_EGRESS_AUTHORIZATION_EXPIRED);
  /* Explicit delivery renewal does not re-execute or rewrite the terminal. */
  EdrCommandStateRecord original;CHECK(edr_command_state_begin("cmd-expired","rtq_execute",NULL,NULL,&original)==EDR_COMMAND_STATE_BEGIN_DUP_FINAL);
  EdrSoarCommandMeta grant=task("renew-1","result_delivery_renewal");
  char *request=renewal("cmd-expired","rtq_execute","result",detail,grant.result_authorization.expires_unix_ms);
  EdrSoarCommandMeta no_grant={0};CHECK(renew(request,&no_grant)==EDR_EGRESS_REQUEST_DENIED);
  EdrSoarCommandMeta other=grant;snprintf(other.result_authorization.endpoint_id,128,"wrong");
  CHECK(renew(request,&other)==EDR_EGRESS_REQUEST_DENIED);
  char *wrong=renewal("cmd-expired","rtq_execute","result","changed",grant.result_authorization.expires_unix_ms);
  CHECK(renew(wrong,&grant)==EDR_EGRESS_REQUEST_DENIED);free(wrong);
  wrong=renewal("cmd-expired","rtq_execute","result",detail,(int64_t)time(NULL)*1000-1);
  CHECK(renew(wrong,&grant)==EDR_EGRESS_REQUEST_DENIED);free(wrong);
  wrong=renewal("cmd-expired","rtq_execute","result",detail,grant.result_authorization.expires_unix_ms+86400000LL);
  CHECK(renew(wrong,&grant)==EDR_EGRESS_REQUEST_DENIED);free(wrong);
  CHECK(renew(request,&grant)==0);CHECK(renew(request,&grant)==EDR_EGRESS_REQUEST_DENIED);free(request);
  CHECK(edr_command_state_mark_report_held(&original,"stale authorization expiry")==0);
  CHECK(allowed("tenant","ep",body));
  n=edr_command_state_collect_pending(pending,4);CHECK(n==1);
  CHECK(!pending[0].report_policy_held && pending[0].report_attempts==original.report_attempts);
  CHECK(pending[0].execution_status==original.execution_status && pending[0].exit_code==original.exit_code);
  CHECK(!strcmp(pending[0].detail,original.detail) && !strcmp(pending[0].agent_boot_id,original.agent_boot_id));
  EdrSoarCommandMeta duplicate_meta=task("cmd-expired","rtq_execute");
  snprintf(duplicate_meta.idempotency_key,sizeof(duplicate_meta.idempotency_key),"new-signed-idempotency");
  CHECK(edr_command_state_begin("cmd-expired","rtq_execute",&duplicate_meta,NULL,&original)==EDR_COMMAND_STATE_BEGIN_DUP_FINAL);
  CHECK(!strcmp(original.detail,detail) && original.result_authorization.expires_unix_ms==grant.result_authorization.expires_unix_ms);
  CHECK(edr_command_state_mark_reported(&pending[0])==0);
  request=renewal("cmd-expired","rtq_execute","result",detail,grant.result_authorization.expires_unix_ms+1);
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
  CHECK(allowed("tenant","ep",body));free(body); /* Existing immutable grant is not overwritten. */
  char why[128];
  CHECK(edr_egress_request_validate_for_scope("POST","ingest/upload-file","multipart/form-data","x",1,"tenant","ep",why,sizeof(why))!=0);
  /* Compaction must retain complete >8KiB result lines and their authority. */
  env("EDR_COMMAND_STATE_MAX_BYTES","65536");
  char name[6004],pathpart[5001],large[12500];
  memcpy(name,"foo",3);memset(name+3,'x',6000);name[6003]=0;
  memset(pathpart,'p',5000);pathpart[5000]=0;
  snprintf(large,sizeof(large),"{\"results\":[{\"type\":\"process\",\"pid\":12,\"name\":\"%s\",\"path\":\"%s\"}],\"total\":1,\"truncated\":false,\"errors\":[],\"error\":null}",name,pathpart);
  for (int i=0;i<16;i++) {
    char id[48];snprintf(id,sizeof(id),"cmd-large-%d",i);
    EdrSoarCommandMeta large_task=task(id,"rtq_execute");
    CHECK(edr_command_state_finish(id,"rtq_execute",&large_task,"ok",1,0,large,"",1)==0);
  }
  edr_command_state_compact_if_needed();
  body=wire("cmd-large-15","rtq_execute",large,"");
  CHECK(allowed("tenant","ep",body));free(body);
  purpose_tests();
  puts("PASS: admitted task scope, exact terminal, durable retry, expiry, session binding, attachment denial");
  return 0;
}
