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

static void rtq_eventlog_batch_purpose_tests(void) {
  const char *request="{\"eventlog_channel\":\"Security\",\"eventlog_query\":\"*[System[EventID=4624]]\"}";
  const char *detail="{\"results\":[{\"type\":\"eventlog\",\"provider\":\"Synthetic\",\"timestamp\":\"2026-10-10T06:24:44.000Z\",\"event_id\":4624,\"record_id\":2998278,\"level\":0,\"process_id\":12,\"thread_id\":34,\"xml\":\"UNRELATED-TEXT\"}],\"total\":1,\"truncated\":true,\"partial\":true,\"meta\":{\"eventlog\":{\"schema\":\"edr.rtq.eventlog-batch.v1\",\"channel\":\"Security\",\"query\":\"*[System[EventID=4624]]\",\"raw_xml\":\"UNRELATED-TEXT\"}},\"errors\":[{\"source\":\"command_result_transport\",\"code\":\"result_truncated\",\"severity\":\"warning\",\"retryable\":false},{\"source\":\"eventlog\",\"code\":\"enumeration_failed\",\"severity\":\"warning\",\"retryable\":true}]}";
  char projected[16384],canonical[16384];
  EdrSoarCommandMeta m=task("eventlog-compact","rtq_execute");
  CHECK(edr_command_result_bind_contract(&m.result_authorization,(const uint8_t*)request,strlen(request),(int64_t)time(NULL)*1000)==0);
  CHECK(edr_command_result_project_detail(&m.result_authorization,"rtq_execute",1,0,detail,projected,sizeof(projected))==0);
  CHECK(!strstr(projected,"UNRELATED") && strstr(projected,"collector_diagnostic"));
  cJSON *root=cJSON_Parse(projected);CHECK(root);
  const cJSON *row=cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(root,"results"),0);
  const cJSON *batch=cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(root,"meta"),"eventlog");
  CHECK(cJSON_IsObject(batch) && !strcmp(cJSON_GetObjectItemCaseSensitive(batch,"schema")->valuestring,"edr.rtq.eventlog-batch.v1"));
  CHECK(!cJSON_HasObjectItem(row,"channel") && !cJSON_HasObjectItem(row,"query"));
  CHECK(cJSON_GetObjectItemCaseSensitive(row,"record_id")->valuedouble==2998278);
  CHECK(cJSON_GetObjectItemCaseSensitive(row,"event_id")->valueint==4624);
  CHECK(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root,"partial")) && cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root,"truncated")));
  CHECK(cJSON_GetObjectItemCaseSensitive(root,"warning_count")->valueint==1);
  cJSON_Delete(root);
  CHECK(edr_command_result_project_detail(&m.result_authorization,"rtq_execute",1,0,projected,canonical,sizeof(canonical))==0 && !strcmp(projected,canonical));
  CHECK(edr_command_state_finish("eventlog-compact","rtq_execute",&m,"ok",1,0,detail,"",1)==0);
  edr_command_state_compact_if_needed();
  EdrCommandStateRecord *stored=calloc(1,sizeof(*stored));CHECK(stored);
  CHECK(edr_command_state_begin("eventlog-compact","rtq_execute",NULL,NULL,stored)==EDR_COMMAND_STATE_BEGIN_DUP_FINAL);
  CHECK(!strcmp(stored->detail,projected) && !strcmp(stored->result_authorization.content_contract,m.result_authorization.content_contract));
  char *body=persisted_body("eventlog-compact","rtq_execute");
  CHECK(allowed("tenant","ep",body) && !allowed("other-tenant","ep",body) && !allowed("tenant","other-endpoint",body));
  free(body);free(stored);
  for(int variant=0;variant<14;variant++) {
    root=cJSON_Parse(detail);CHECK(root);
    cJSON *meta=cJSON_GetObjectItemCaseSensitive(root,"meta");
    cJSON *scope=cJSON_GetObjectItemCaseSensitive(meta,"eventlog");
    cJSON *item=cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(root,"results"),0);
    switch(variant) {
      case 0: CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(scope,"channel"),"System"));break;
      case 1: CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(scope,"query"),"*"));break;
      case 2: CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(scope,"schema"),"edr.rtq.eventlog-batch.v2"));break;
      case 3: cJSON_DeleteItemFromObjectCaseSensitive(scope,"channel");break;
      case 4: cJSON_DeleteItemFromObjectCaseSensitive(scope,"query");break;
      case 5: CHECK(cJSON_ReplaceItemInObjectCaseSensitive(meta,"eventlog",cJSON_CreateArray()));break;
      case 6: cJSON_DeleteItemFromObjectCaseSensitive(root,"meta");break;
      case 7: CHECK(cJSON_AddStringToObject(item,"channel","System"));break;
      case 8: CHECK(cJSON_AddStringToObject(item,"query","*"));break;
      case 9: CHECK(cJSON_AddNumberToObject(item,"channel",1));break;
      case 10: CHECK(cJSON_ReplaceItemInObjectCaseSensitive(scope,"query",cJSON_CreateNull()));break;
      /* Keep the unsafe boundary literal exact instead of letting the fixture
       * serializer round a large double back into the accepted range. */
      case 11: CHECK(cJSON_ReplaceItemInObjectCaseSensitive(item,"record_id",cJSON_CreateRaw("9007199254740992")));break;
      case 12: cJSON_SetNumberValue(cJSON_GetObjectItemCaseSensitive(item,"event_id"),65536);break;
      case 13: cJSON_DeleteItemFromObjectCaseSensitive(item,"timestamp");break;
    }
    char *invalid=cJSON_PrintUnformatted(root);CHECK(invalid);
    int rc=edr_command_result_project_detail(&m.result_authorization,"rtq_execute",1,0,invalid,canonical,sizeof(canonical));
    if(rc==0)fprintf(stderr,"FAIL: compact eventlog negative variant %d admitted\n",variant);
    CHECK(rc!=0);
    free(invalid);cJSON_Delete(root);
  }
  root=cJSON_Parse(detail);CHECK(root);
  cJSON *compatible=cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(root,"results"),0);
  CHECK(cJSON_AddStringToObject(compatible,"channel","Security") && cJSON_AddStringToObject(compatible,"query","*[System[EventID=4624]]"));
  char *compatible_detail=cJSON_PrintUnformatted(root);CHECK(compatible_detail);
  CHECK(edr_command_result_project_detail(&m.result_authorization,"rtq_execute",1,0,compatible_detail,canonical,sizeof(canonical))==0 && !strcmp(canonical,projected));
  free(compatible_detail);cJSON_Delete(root);
  EdrSoarCommandMeta process=task("eventlog-unrequested-batch","rtq_execute");
  CHECK(edr_command_result_project_detail(&process.result_authorization,"rtq_execute",1,0,detail,canonical,sizeof(canonical))!=0);
  const char *defaults="{\"results\":[],\"truncated\":false,\"meta\":{\"eventlog\":{\"schema\":\"edr.rtq.eventlog-batch.v1\",\"channel\":\"System\",\"query\":\"*\"}}}";
  const char *default_request="{\"eventlog_query\":\"*\"}";
  CHECK(edr_command_result_bind_contract(&m.result_authorization,(const uint8_t*)default_request,strlen(default_request),(int64_t)time(NULL)*1000)==0);
  CHECK(edr_command_result_project_detail(&m.result_authorization,"rtq_execute",1,0,defaults,canonical,sizeof(canonical))==0);
  const char *mixed_request="{\"eventlog_channel\":\"Security\",\"file_path\":\"/tmp/foo\"}";
  const char *mixed="{\"results\":[{\"type\":\"file\",\"path\":\"/tmp/foo\",\"size\":1}],\"truncated\":false,\"meta\":{\"eventlog\":{\"schema\":\"edr.rtq.eventlog-batch.v1\",\"channel\":\"Security\",\"query\":\"*\"},\"file_hash\":{\"scope\":\"path_scan\",\"cache_status\":\"not_requested\",\"path_scanned\":true}}}";
  CHECK(edr_command_result_bind_contract(&m.result_authorization,(const uint8_t*)mixed_request,strlen(mixed_request),(int64_t)time(NULL)*1000)==0);
  CHECK(edr_command_result_project_detail(&m.result_authorization,"rtq_execute",1,0,mixed,canonical,sizeof(canonical))==0);
  root=cJSON_Parse(canonical);CHECK(root);
  cJSON *mixed_meta=cJSON_GetObjectItemCaseSensitive(root,"meta");
  CHECK(cJSON_IsObject(cJSON_GetObjectItemCaseSensitive(mixed_meta,"eventlog")) && cJSON_IsObject(cJSON_GetObjectItemCaseSensitive(mixed_meta,"file_hash")));
  cJSON_Delete(root);
  puts("PASS: compact eventlog scope is signed-request-bound, compatible, idempotent and durable; wrong scopes/types and unrequested batches are held; diagnostics and mixed file metadata survive");
}

static void rtq_file_metadata_purpose_tests(void) {
  const char *sha="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  char request[200],detail[1600],projected[16384],canonical[16384];
  snprintf(request,sizeof(request),"{\"file_sha256\":\"%s\"}",sha);
  EdrSoarCommandMeta m=task("rtq-cache-metadata","rtq_execute");
  CHECK(edr_command_result_bind_contract(&m.result_authorization,(const uint8_t*)request,strlen(request),(int64_t)time(NULL)*1000)==0);
  snprintf(detail,sizeof(detail),"{\"results\":[{\"type\":\"file\",\"path\":\"/tmp/cached.exe\",\"sha256\":\"%s\",\"size\":3,\"cache_hit\":true}],\"total\":1,\"truncated\":false,\"partial\":true,\"meta\":{\"file_hash\":{\"scope\":\"cache_only\",\"cache_status\":\"hit\",\"cache_attempted\":true,\"cache_hits\":1,\"cache_candidates_scanned\":7,\"path_scanned\":false,\"local_database\":\"UNRELATED-PATH\"},\"raw_cache\":\"UNRELATED-TEXT\"},\"errors\":[{\"source\":\"file\",\"code\":\"scan_limit\",\"severity\":\"warning\",\"retryable\":false}]}",sha);
  CHECK(edr_command_result_project_detail(&m.result_authorization,"rtq_execute",1,0,detail,projected,sizeof(projected))==0);
  cJSON *root=cJSON_Parse(projected);CHECK(root);
  cJSON *hash=cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(root,"meta"),"file_hash");CHECK(cJSON_IsObject(hash));
  CHECK(!strcmp(cJSON_GetObjectItemCaseSensitive(hash,"scope")->valuestring,"cache_only"));
  CHECK(!strcmp(cJSON_GetObjectItemCaseSensitive(hash,"cache_status")->valuestring,"hit"));
  CHECK(cJSON_GetObjectItemCaseSensitive(hash,"cache_hits")->valueint==1);
  CHECK(cJSON_GetObjectItemCaseSensitive(hash,"cache_candidates_scanned")->valueint==7);
  CHECK(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(hash,"cache_attempted")));
  CHECK(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(hash,"path_scanned")));
  CHECK(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root,"partial")));
  CHECK(!strstr(projected,"UNRELATED"));cJSON_Delete(root);
  CHECK(edr_command_result_project_detail(&m.result_authorization,"rtq_execute",1,0,projected,canonical,sizeof(canonical))==0 && !strcmp(projected,canonical));
  CHECK(edr_command_state_finish("rtq-cache-metadata","rtq_execute",&m,"ok",1,0,detail,"",1)==0);
  char *body=persisted_body("rtq-cache-metadata","rtq_execute");CHECK(allowed("tenant","ep",body));
  CHECK(strstr(body,"cache_candidates_scanned") && strstr(body,"cache_only") && !strstr(body,"UNRELATED"));free(body);
  const char *invalid_hash[]={
    "{\"scope\":\"unbounded_full_disk\",\"cache_status\":\"miss\"}",
    "{\"scope\":\"cache_only\",\"cache_status\":\"unknown\"}",
    "{\"scope\":\"cache_only\",\"cache_status\":\"miss\",\"cache_hits\":-1}",
    "{\"scope\":\"cache_only\",\"cache_status\":\"miss\",\"cache_hits\":\"1\"}",
    "{\"scope\":\"cache_only\",\"cache_status\":\"miss\",\"path_scanned\":1}",
    "{\"scope\":\"cache_only\",\"cache_status\":\"miss\",\"cache_candidates_scanned\":0.5}"};
  for(size_t i=0;i<sizeof(invalid_hash)/sizeof(invalid_hash[0]);i++) {
    snprintf(detail,sizeof(detail),"{\"results\":[],\"truncated\":false,\"meta\":{\"file_hash\":%s}}",invalid_hash[i]);
    CHECK(edr_command_result_project_detail(&m.result_authorization,"rtq_execute",1,0,detail,projected,sizeof(projected))!=0);
  }
  /* Metadata is purpose-bound; unrelated process queries never gain cache data. */
  m=task("rtq-unrequested-metadata","rtq_execute");
  snprintf(detail,sizeof(detail),"{\"results\":[],\"truncated\":false,\"meta\":{\"file_hash\":{\"scope\":\"cache_only\",\"cache_status\":\"hit\",\"cache_hits\":1}}}");
  CHECK(edr_command_result_project_detail(&m.result_authorization,"rtq_execute",1,0,detail,projected,sizeof(projected))==0 && !strstr(projected,"file_hash"));
  m=task("rtq-extension-contract","rtq_execute");
  const char *extension="{\"file_ext\":\".exe\"}";
  CHECK(edr_command_result_bind_contract(&m.result_authorization,(const uint8_t*)extension,strlen(extension),(int64_t)time(NULL)*1000)==0);
  const char *rows[]={"{\"results\":[{\"type\":\"file\",\"path\":\"/tmp/exact.EXE\",\"size\":3}],\"truncated\":false}",
      "{\"results\":[{\"type\":\"file\",\"path\":\"/tmp/prefix.exec\",\"size\":3}],\"truncated\":false}"};
  CHECK(edr_command_result_project_detail(&m.result_authorization,"rtq_execute",1,0,rows[0],projected,sizeof(projected))==0);
  CHECK(edr_command_result_project_detail(&m.result_authorization,"rtq_execute",1,0,rows[1],projected,sizeof(projected))!=0);
  puts("PASS: RTQ cache completeness metadata survives projection, durable replay and final guard; unrequested metadata, invalid counters and extension-prefix rows remain rejected");
}

static void rtq_alias_and_sentinel_purpose_tests(void) {
  static const struct {const char *request;const char *row;} cases[]={
    {"{\"network_proto\":\"tcp\",\"network_state\":\"ESTAB\"}", "{\"type\":\"network\",\"proto\":\"TCP\",\"state\":\"ESTABLISHED\",\"local_ip\":\"::1\",\"remote_ip\":\"2001:db8::1\"}"},
    {"{\"network_state\":\"SYN-RECV\"}","{\"type\":\"network\",\"proto\":\"tcp\",\"state\":\"SYN_RCVD\"}"},
    {"{\"registry_path\":\"HKLM\\\\Software\\\\Allowed\",\"registry_mode\":\"SUBTREE\"}","{\"type\":\"registry\",\"key\":\"HKLM\\\\Software\\\\Allowed\\\\Child\",\"value\":\"number\",\"data\":\"1234\",\"reg_type\":4}"},
    {"{\"file_ext\":\".exe\",\"process_pid_min\":0,\"process_pid_max\":0,\"network_remote_port\":0}","{\"type\":\"file\",\"path\":\"/tmp/fixture.exe\",\"size\":3}"},
    {"{\"process_name\":\"foo\",\"process_pid_max\":0}","{\"type\":\"process\",\"name\":\"foo\",\"pid\":42}"}
  };
  char detail[1200],projected[16384],id[64];
  for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
    snprintf(id,sizeof(id),"rtq-direct-alias-%zu",i);
    EdrSoarCommandMeta m=task(id,"rtq_execute");
    CHECK(edr_command_result_bind_contract(&m.result_authorization,(const uint8_t*)cases[i].request,strlen(cases[i].request),(int64_t)time(NULL)*1000)==0);
    snprintf(detail,sizeof(detail),"{\"results\":[%s],\"truncated\":false,\"errors\":[]}",cases[i].row);
    CHECK(edr_command_result_project_detail(&m.result_authorization,"rtq_execute",1,0,detail,projected,sizeof(projected))==0);
    CHECK(edr_command_state_finish(id,"rtq_execute",&m,"ok",1,0,detail,"",1)==0);
    char *body=persisted_body(id,"rtq_execute");CHECK(allowed("tenant","ep",body));free(body);
  }
  puts("PASS: supported direct state/mode aliases and unset numeric sentinels agree across projection and final authorization");
}

static void purpose_tests(void) {
  shell_open_purpose_tests();
  rtq_diagnostic_purpose_tests();
  rtq_eventlog_batch_purpose_tests();
  rtq_file_metadata_purpose_tests();
  rtq_alias_and_sentinel_purpose_tests();
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
  typed_owner_case("process-control-query","rtq_execute","{\"process_name\":\"foo\\u0001bar\"}",
      "{\"results\":[{\"type\":\"process\",\"pid\":42,\"name\":\"foo\\u0001bar\"}],\"truncated\":false}",1);
  EdrCommandStateRecord *control_record=calloc(1,sizeof(*control_record));CHECK(control_record);
  CHECK(edr_command_state_begin("process-control-query","rtq_execute",NULL,NULL,control_record)==EDR_COMMAND_STATE_BEGIN_DUP_FINAL);
  cJSON *control_detail=cJSON_Parse(control_record->detail);CHECK(control_detail);
  const cJSON *control_rows=cJSON_GetObjectItemCaseSensitive(control_detail,"results");
  CHECK(cJSON_IsArray(control_rows)&&cJSON_GetArraySize(control_rows)==1);
  const cJSON *control_name=cJSON_GetObjectItemCaseSensitive(control_rows->child,"name");
  CHECK(cJSON_IsString(control_name)&&!strcmp(control_name->valuestring,"foo\001bar"));
  cJSON_Delete(control_detail);free(control_record);
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

/* QueueCommand's signed payload uses x64 while its URL uses amd64. These
 * fixtures exercise the real protected-inbox owner, not a permissive callback. */
static cJSON *download_payload(const char *arch) {
  cJSON *o=cJSON_CreateObject();CHECK(o);
  cJSON_AddStringToObject(o,"task_id","task-654");
  cJSON_AddStringToObject(o,"artifact_id","artifact-654");
  cJSON_AddStringToObject(o,"hash","0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
  cJSON_AddStringToObject(o,"version","3.2.654");
  cJSON_AddStringToObject(o,"operation","upgrade");
  cJSON_AddStringToObject(o,"upgrade_class","installer_required");
  cJSON_AddStringToObject(o,"arch",arch);
  char url[512];
  snprintf(url,sizeof(url),"https://192.0.2.1:8080/api/v1/agent/download/3.2.654?platform=windows&arch=%s&task_id=task-654&artifact_id=artifact-654",!strcmp(arch,"x64")?"amd64":"arm64");
  cJSON_AddStringToObject(o,"artifact_url",url);
  snprintf(url,sizeof(url),"https://192.0.2.1:8080/api/v1/agent/runtime/3.2.654?platform=windows&arch=%s&task_id=task-654&artifact_id=artifact-654&package_id=7",!strcmp(arch,"x64")?"amd64":"arm64");
  cJSON_AddStringToObject(o,"runtime_manifest_url",url);
  return o;
}
static void download_store_raw(const char *id,const char *json,int expired,int unsigned_task) {
  EdrSoarCommandMeta m=task(id,"agent_update");
  m.issued_at_unix_ms=(int64_t)time(NULL)*1000-(expired?60000:0);m.deadline_ms=30000;
  CHECK(edr_command_result_bind_contract(&m.result_authorization,(const uint8_t *)json,strlen(json),m.issued_at_unix_ms)==0);
  if(unsigned_task)memset(&m.result_authorization,0,sizeof(m.result_authorization));
  CHECK(edr_command_state_store_inbox(id,"agent_update",(const uint8_t *)json,strlen(json),&m)==0);
}
static char *download_store(const char *id,cJSON *payload,int expired,int unsigned_task) {
  char *json=cJSON_PrintUnformatted(payload);CHECK(json);
  download_store_raw(id,json,expired,unsigned_task);return json;
}
static int download_allowed(const char *id,const char *url) {
  char why[128];return edr_egress_upgrade_download_validate(id,url,"tenant","ep",why,sizeof(why));
}
static void download_authority_tests(void) {
  edr_egress_set_task_scope_lookup(edr_command_state_task_scope);
  for(unsigned i=0;i<2;i++) {
    const char *id=i?"download-arm64":"download-x64";
    cJSON *o=download_payload(i?"arm64":"x64");char *json=download_store(id,o,0,0);
    const char *raw=cJSON_GetObjectItemCaseSensitive(o,"artifact_url")->valuestring;
    const char *runtime=cJSON_GetObjectItemCaseSensitive(o,"runtime_manifest_url")->valuestring;
    CHECK(download_allowed(id,raw)==0 && download_allowed(id,runtime)==0);
    char why[128];EdrEgressTaskScope scope;
    CHECK(edr_egress_request_validate_for_scope("GET",raw,NULL,NULL,0,"tenant","ep",why,sizeof(why))==EDR_EGRESS_REQUEST_DENIED);
    CHECK(edr_egress_request_validate_for_scope("GET",runtime,NULL,NULL,0,"tenant","ep",why,sizeof(why))==EDR_EGRESS_REQUEST_DENIED);
    CHECK(edr_egress_task_preflight(EDR_EGRESS_ARTIFACT,id,&scope)==EDR_EGRESS_REQUEST_DENIED);
    CHECK(download_allowed(NULL,raw)==EDR_EGRESS_REQUEST_DENIED);
    CHECK(download_allowed("unowned-download",raw)==EDR_EGRESS_REQUEST_DENIED);
    CHECK(edr_egress_upgrade_download_validate(id,raw,"wrong","ep",why,sizeof(why))==EDR_EGRESS_REQUEST_DENIED);
    CHECK(edr_egress_upgrade_download_validate(id,raw,"tenant","wrong",why,sizeof(why))==EDR_EGRESS_REQUEST_DENIED);
    char altered[1024];snprintf(altered,sizeof(altered),"%s&extra=1",raw);
    CHECK(download_allowed(id,altered)==EDR_EGRESS_REQUEST_DENIED);
    snprintf(altered,sizeof(altered),"%s",raw);altered[8]='x';
    CHECK(download_allowed(id,altered)==EDR_EGRESS_REQUEST_DENIED);
    edr_command_state_delete_inbox(id);free(json);cJSON_Delete(o);
  }
  /* Even exact bytes in a signed fixture cannot authorize malformed queries,
   * route confusion, credentials, percent escapes, fragments or oversized IDs. */
  static const struct {const char *url;const char *version;} invalid[]={
    {"https://host/api/v1/agent/download/3.2.654",NULL},
    {"https://host/api/v1/agent/download/3.2.654?platform=windows&arch=arm64&task_id=task-654",NULL},
    {"https://host/api/v1/agent/download/3.2.654?platform=windows&arch=arm64&task_id=task-654&artifact_id=artifact-654&arch=arm64",NULL},
    {"https://host/api/v1/agent/download/3.2.654?platform=windows&arch=arm64&task_id=task-654&artifact_id=artifact-654&extra=1",NULL},
    {"https://host/api/v1/agent/download/3.2.654?platform=windows&arch=arm64&task_id=task%2D654&artifact_id=artifact-654",NULL},
    {"https://host/api/v1/agent/download/3.2.654?platform=linux&arch=arm64&task_id=task-654&artifact_id=artifact-654",NULL},
    {"https://host/api/v1/agent/download/3.2.654?platform=windows&arch=amd64&task_id=task-654&artifact_id=artifact-654",NULL},
    {"https://host/api/v1/agent/download/3.2.654?platform=windows&arch=arm64&task_id=wrong&artifact_id=artifact-654",NULL},
    {"https://host/api/v1/agent/download/3.2.654?platform=windows&arch=arm64&task_id=task-654&artifact_id=wrong",NULL},
    {"https://host/api/v1/agent/download/3.2.654?platform=windows&arch=arm64&task_id=task-654&artifact_id=artifact-654&package_id=7",NULL},
    {"https://host/api/v1/agent/runtime/3.2.654?platform=windows&arch=arm64&task_id=task-654&artifact_id=artifact-654",NULL},
    {"http://host/api/v1/agent/download/3.2.654?platform=windows&arch=arm64&task_id=task-654&artifact_id=artifact-654",NULL},
    {"https://user@host/api/v1/agent/download/3.2.654?platform=windows&arch=arm64&task_id=task-654&artifact_id=artifact-654",NULL},
    {"https://host:bad/api/v1/agent/download/3.2.654?platform=windows&arch=arm64&task_id=task-654&artifact_id=artifact-654",NULL},
    {"https://host:0/api/v1/agent/download/3.2.654?platform=windows&arch=arm64&task_id=task-654&artifact_id=artifact-654",NULL},
    {"https://host:65536/api/v1/agent/download/3.2.654?platform=windows&arch=arm64&task_id=task-654&artifact_id=artifact-654",NULL},
    {"https://host/api/v1/agent/download/3.2.654?platform=windows&arch=arm64&task_id=task-654&artifact_id=artifact-654#x",NULL},
    {"https://host/api/v1/agent/download/3.2.654?platform=windows&arch=arm64&task_id=task-654&artifact_id=artifact-654&",NULL},
    {"https://host/api/v1/agent/download/../x?platform=windows&arch=arm64&task_id=task-654&artifact_id=artifact-654","../x"},
    {"https://host/api/v1/agent/download/3.2.654/../x?platform=windows&arch=arm64&task_id=task-654&artifact_id=artifact-654","3.2.654/../x"},
    {"https://host/api/v1/agent/download/3.2.654%2Fx?platform=windows&arch=arm64&task_id=task-654&artifact_id=artifact-654","3.2.654%2Fx"},
    {"https://host/api/v1/agent/download/.?platform=windows&arch=arm64&task_id=task-654&artifact_id=artifact-654","."},
    {"https://host/api/v1/agent/download/..?platform=windows&arch=arm64&task_id=task-654&artifact_id=artifact-654",".."},
    {"https://host/api/v1/agent/download/3.2.654?x?platform=windows&arch=arm64&task_id=task-654&artifact_id=artifact-654","3.2.654?x"}
  };
  for(size_t i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++) {
    cJSON *o=download_payload("arm64");char id[64];snprintf(id,sizeof(id),"bad-download-%zu",i);
    CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(o,"artifact_url"),invalid[i].url));
    if(invalid[i].version)CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(o,"version"),invalid[i].version));
    char *json=download_store(id,o,0,0);CHECK(download_allowed(id,invalid[i].url)==EDR_EGRESS_REQUEST_DENIED);
    edr_command_state_delete_inbox(id);free(json);cJSON_Delete(o);
  }
  const char *packages[]={"0","-1","1.5","01","9223372036854775808","1x",""};
  for(size_t i=0;i<sizeof(packages)/sizeof(packages[0]);i++) {
    cJSON *o=download_payload("arm64");char id[64],url[512];snprintf(id,sizeof(id),"bad-package-%zu",i);
    snprintf(url,sizeof(url),"https://host/api/v1/agent/runtime/3.2.654?platform=windows&arch=arm64&task_id=task-654&artifact_id=artifact-654&package_id=%s",packages[i]);
    CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(o,"runtime_manifest_url"),url));
    char *json=download_store(id,o,0,0);CHECK(download_allowed(id,url)==EDR_EGRESS_REQUEST_DENIED);
    edr_command_state_delete_inbox(id);free(json);cJSON_Delete(o);
  }
  for(unsigned i=0;i<6;i++) {
    cJSON *o=download_payload("arm64");char id[64];snprintf(id,sizeof(id),"unready-download-%u",i);
    char raw[2300];snprintf(raw,sizeof(raw),"%s",cJSON_GetObjectItemCaseSensitive(o,"artifact_url")->valuestring);
    if(i==2)cJSON_DeleteItemFromObjectCaseSensitive(o,"artifact_url");
    if(i==3)cJSON_ReplaceItemInObjectCaseSensitive(o,"artifact_url",cJSON_CreateNumber(1));
    if(i==4)cJSON_ReplaceItemInObjectCaseSensitive(o,"arch",cJSON_CreateBool(1));
    if(i==5) {memset(raw,'x',sizeof(raw)-1);raw[sizeof(raw)-1]=0;CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(o,"artifact_url"),raw));}
    char *json=download_store(id,o,i==0,i==1);
    CHECK(download_allowed(id,raw)==(i==0?EDR_EGRESS_AUTHORIZATION_EXPIRED:EDR_EGRESS_REQUEST_DENIED));
    if(i==0) {
      /* An actual signed-delivery renewal changes only the result grant. */
      EdrSoarCommandMeta grant=task("renew-1","result_delivery_renewal");
      grant.result_authorization.expires_unix_ms+=60000;
      char *request=renewal(id,"agent_update","upgrade_payload",json,grant.result_authorization.expires_unix_ms);
      CHECK(renew(request,&grant)==0);free(request);
      CHECK(download_allowed(id,raw)==EDR_EGRESS_AUTHORIZATION_EXPIRED);
      EdrEgressTaskScope scope;CHECK(edr_egress_task_preflight(EDR_EGRESS_UPGRADE_EVENT,id,&scope)==0);
    }
    edr_command_state_delete_inbox(id);free(json);cJSON_Delete(o);
  }
  cJSON *source=download_payload("arm64");char *source_json=cJSON_PrintUnformatted(source);CHECK(source_json);
  const char *source_url=cJSON_GetObjectItemCaseSensitive(source,"artifact_url")->valuestring;
  for(unsigned i=0;i<3;i++) {
    char id[64],malformed[4096];snprintf(id,sizeof(id),"ambiguous-payload-%u",i);
    if(i==0)snprintf(malformed,sizeof(malformed),"%.*s,\"artifact_url\":\"%s\"}",(int)strlen(source_json)-1,source_json,source_url);
    else if(i==1)snprintf(malformed,sizeof(malformed),"%s{}",source_json);
    else {
      const char *field=strstr(source_json,"\"artifact_url\":\"");CHECK(field);
      const char *end=strchr(field+strlen("\"artifact_url\":\""),'"');CHECK(end);
      snprintf(malformed,sizeof(malformed),"%.*s\\u0000hidden%s",(int)(end-source_json),source_json,end);
    }
    /* Actual admission already rejects these bytes. Model a malformed old
     * protected receipt explicitly to ensure the download owner also denies. */
    EdrSoarCommandMeta receipt=task(id,"agent_update");
    receipt.issued_at_unix_ms=(int64_t)time(NULL)*1000;receipt.deadline_ms=30000;
    CHECK(edr_command_result_bind_contract(&receipt.result_authorization,(const uint8_t *)malformed,strlen(malformed),receipt.issued_at_unix_ms)!=0);
    CHECK(edr_command_state_store_inbox(id,"agent_update",(const uint8_t *)malformed,strlen(malformed),&receipt)==0);
    CHECK(download_allowed(id,source_url)==EDR_EGRESS_REQUEST_DENIED);
    edr_command_state_delete_inbox(id);
  }
  free(source_json);cJSON_Delete(source);
  cJSON *legacy=download_payload("arm64");cJSON_DeleteItemFromObjectCaseSensitive(legacy,"artifact_url");
  cJSON_DeleteItemFromObjectCaseSensitive(legacy,"runtime_manifest_url");
  char *json=download_store("legacy-update-event",legacy,0,0);EdrEgressTaskScope scope;
  CHECK(edr_egress_task_preflight(EDR_EGRESS_UPGRADE_EVENT,"legacy-update-event",&scope)==0);
  CHECK(download_allowed("legacy-update-event","https://host/api/v1/agent/download/3.2.654")==EDR_EGRESS_REQUEST_DENIED);
  edr_command_state_delete_inbox("legacy-update-event");free(json);cJSON_Delete(legacy);
  puts("PASS: exact task-pinned QueueCommand downloads for both architectures; generic GET, malformed scope/query/version, unsigned and renewed-but-expired execution denied");
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
  download_authority_tests();
  puts("PASS: admitted task scope, exact terminal, durable retry, expiry, session binding, attachment denial");
  return 0;
}
