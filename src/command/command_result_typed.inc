/* Purpose-specific result projections. Included by the durable result owner;
 * these routines inspect synthetic/producer JSON, never perform the action.
 * Unknown members stay local. No diagnostic prose, stdout, memory bytes or
 * arbitrary nested objects are copied through a schema label. */
static int typed_text_valid(const char *s,size_t cap) {
  if(!s || strlen(s)>cap)return 0;
  for(const unsigned char *p=(const unsigned char*)s;*p;p++)if(*p<32u)return 0;
  return 1;
}
static int typed_hex(const char *s,size_t count) {
  return s && strlen(s)==count && strspn(s,"0123456789abcdefABCDEF")==count;
}
static int typed_address(const char *s) {
  size_t n=s?strlen(s):0;
  return n>=3 && n<=18 && s[0]=='0' && s[1]=='x' && strspn(s+2,"0123456789abcdefABCDEF")==n-2;
}
static int typed_decimal(const char *s) {
  return s && *s && strlen(s)<=20 && strspn(s,"0123456789")==strlen(s);
}
static cJSON *typed_fields(const cJSON *src,const char *strings,const char *numbers,const char *booleans) {
  if(!cJSON_IsObject(src))return NULL;
  cJSON *out=cJSON_CreateObject();if(!out)return NULL;
  if(!result_copy_fields(out,src,strings,numbers,booleans)){cJSON_Delete(out);return NULL;}
  for(const cJSON *v=out->child;v;v=v->next)if(cJSON_IsString(v)&&!typed_text_valid(v->valuestring,4096)){cJSON_Delete(out);return NULL;}
  return out;
}
static int typed_add_object(cJSON *dst,const char *key,cJSON *value) {
  if(!value)return 0;
  if(!cJSON_AddItemToObject(dst,key,value)){cJSON_Delete(value);return 0;}return 1;
}
static int typed_real(cJSON *out,const cJSON *src,const char *key,double cap) {
  const cJSON *n=cJSON_GetObjectItemCaseSensitive(src,key);if(!n)return 1;
  return cJSON_IsNumber(n) && n->valuedouble>=0 && n->valuedouble<=cap && cJSON_AddNumberToObject(out,key,n->valuedouble)!=NULL;
}
static int typed_enum(const cJSON *src,const char *key,const char *values,int optional) {
  const cJSON *v=cJSON_GetObjectItemCaseSensitive(src,key);
  return (!v&&optional) || (cJSON_IsString(v) && result_member(v->valuestring,values));
}
static cJSON *typed_names(const cJSON *src,unsigned limit,size_t width) {
  if(!cJSON_IsArray(src)||cJSON_GetArraySize(src)>(int)limit)return NULL;
  cJSON *out=cJSON_CreateArray();if(!out)return NULL;
  for(const cJSON *v=src->child;v;v=v->next) {
    if(!cJSON_IsString(v)||!v->valuestring[0]||strlen(v->valuestring)>width||strspn(v->valuestring,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")!=strlen(v->valuestring)||!cJSON_AddItemToArray(out,cJSON_Duplicate(v,1))){cJSON_Delete(out);return NULL;}
  }return out;
}
static cJSON *typed_receipt(const cJSON *src) {
  cJSON *out=typed_fields(src,"sha256|object_key|upload_status|type|content_type","","");if(!out)return NULL;
  const char *hash=result_text(out,"sha256"),*key=result_text(out,"object_key");
  int ok=(!*hash||typed_hex(hash,64))&&strlen(key)<=1024u&&strpbrk(key,"?@\r\n")==NULL;
  if(cJSON_HasObjectItem(out,"upload_status"))ok=ok&&typed_enum(out,"upload_status","ok|failed|not_requested|pending|policy_held",0);
  if(cJSON_HasObjectItem(out,"type"))ok=ok&&typed_enum(out,"type","pmfe_region|pmfe_result|pmfe_reconstructed_pe",0);
  if(cJSON_HasObjectItem(out,"content_type"))ok=ok&&!strcmp(result_text(out,"content_type"),"application/json");
  if(!strcmp(result_text(out,"upload_status"),"ok"))ok=ok&&typed_hex(hash,64)&&*key;
  if(!ok){cJSON_Delete(out);return NULL;}return out;
}
static cJSON *typed_pmfe_region(const cJSON *src,const cJSON *request) {
  cJSON *out=typed_fields(src,"base|allocation_base|protection|allocation_protection|kind|mapped_path|sha256","size_bytes|bytes_sampled","read_ok|image_header_valid|private_executable");if(!out)return NULL;
  int ok=typed_address(result_text(out,"base"))&&typed_address(result_text(out,"allocation_base"))&&typed_real(out,src,"score",1)&&typed_real(out,src,"entropy",8);
  const char *hash=result_text(out,"sha256");ok=ok&&(!*hash||typed_hex(hash,64));
  ok=ok&&typed_enum(out,"kind","private_exec|private|image|mapped|memfd_exec|deleted_exec",0);
  const char *protections="UNKNOWN|NOACCESS|R|RW|WC|X|RX|RWX|RXWC|UNKNOWN+GUARD|NOACCESS+GUARD|R+GUARD|RW+GUARD|WC+GUARD|X+GUARD|RX+GUARD|RWX+GUARD|RXWC+GUARD";
  ok=ok&&typed_enum(out,"protection",protections,0)&&typed_enum(out,"allocation_protection",protections,0);
  const cJSON *pe=cJSON_GetObjectItemCaseSensitive(src,"pe");
  if(pe){cJSON *v=typed_fields(pe,"arch","sections|timestamp|entrypoint_rva","");if(v&&!typed_enum(v,"arch","x86|x64|arm64|arm64ec|other",0)){cJSON_Delete(v);v=NULL;}ok=typed_add_object(out,"pe",v)&&ok;}
  const cJSON *threads=cJSON_GetObjectItemCaseSensitive(src,"thread_starts");
  if(threads){cJSON *a=cJSON_CreateArray();ok=ok&&cJSON_IsArray(threads)&&cJSON_GetArraySize(threads)<=8;for(const cJSON *v=threads->child;v&&ok;v=v->next){cJSON *t=typed_fields(v,"start_address","tid","");if(!t||!typed_address(result_text(t,"start_address"))||!cJSON_AddItemToArray(a,t)){cJSON_Delete(t);ok=0;}}ok=typed_add_object(out,"thread_starts",a)&&ok;}
  const cJSON *hits=cJSON_GetObjectItemCaseSensitive(src,"yara_hits");
  if(hits)ok=typed_add_object(out,"yara_hits",typed_names(hits,4,128))&&ok;
  for(unsigned i=0;i<2;i++){const char *name=i?"reconstruction":"evidence";const cJSON *v=cJSON_GetObjectItemCaseSensitive(src,name);if(v){cJSON *r=typed_receipt(v);if(i&&r){if(!typed_enum(v,"status","not_pe|invalid_pe|invalid_headers|unsupported_pe|invalid_sections|size_limit|allocation_failed|path_failed|write_failed|partial|complete",0)||!cJSON_AddStringToObject(r,"status",result_text(v,"status"))){cJSON_Delete(r);r=NULL;}}ok=typed_add_object(out,name,r)&&ok;}}
  (void)request; /* extraction/upload permissions remain with the artifact owner */
  if(!ok){cJSON_Delete(out);return NULL;}return out;
}
static cJSON *typed_pmfe(const char *command_id,const cJSON *body,const cJSON *request) {
  if(strcmp(result_text(body,"task_id"),command_id)||!typed_enum(body,"status","completed_clean|completed_suspicious|partial|failed",0)||!typed_enum(body,"verdict","clean|inconclusive|suspicious",0))return NULL;
  const cJSON *target=cJSON_GetObjectItemCaseSensitive(body,"target");double pid,want;
  if(!result_integer(target,"pid",1,2147483647,&pid)||!result_integer(request,"pid",1,2147483647,&want)||pid!=want)return NULL;
  cJSON *out=typed_fields(body,"schema|status|verdict|task_id","","artifact_upload_failed");if(!out)return NULL;
  int ok=typed_add_object(out,"target",typed_fields(target,"path","pid",""));
  const cJSON *scan=cJSON_GetObjectItemCaseSensitive(body,"scan");
  ok=typed_add_object(out,"scan",typed_fields(scan,"","started_unix_ms|finished_unix_ms|duration_ms|regions_total|regions_read|read_failures|threads_total|thread_start_matches|thread_query_failures|bytes_sampled","truncated"))&&ok;
  const cJSON *signals=cJSON_GetObjectItemCaseSensitive(body,"signals");
  cJSON *s=typed_fields(signals,"yara_status|ave_status|dns_status|module_consistency|module_integrity_scope","stomp_suspicious|mz_hits|dns_hits|regions_scanned|private_exec|private_exec_image_hits|private_exec_thread_starts|memfd_exec|deleted_exec","");
  if(s){ok=typed_real(s,signals,"dns_best",1)&&typed_real(s,signals,"ave_max_score",1)&&typed_real(s,signals,"entropy_max",8)&&ok;const char *names[]={"yara_status","ave_status","dns_status"};for(unsigned i=0;i<3;i++)ok=typed_enum(s,names[i],i==0?"disabled|no_candidate|running|failed|completed|unsupported|unavailable":"disabled|no_candidate|running|failed|completed|unsupported",1)&&ok;}
  if(s){const char *consistency=result_text(s,"module_consistency"),*scope=result_text(s,"module_integrity_scope");ok=(!*consistency||result_member(consistency,"ok|mismatch|unknown"))&&(!*scope||result_member(scope,"module_header_prefix|file_header_prefix|not_requested"))&&ok;}
  ok=typed_add_object(out,"signals",s)&&ok;
  const cJSON *regions=cJSON_GetObjectItemCaseSensitive(body,"regions");
  if(regions){cJSON *a=cJSON_CreateArray();ok=ok&&cJSON_IsArray(regions)&&cJSON_GetArraySize(regions)<=8;for(const cJSON *v=regions->child;v&&ok;v=v->next){cJSON *r=typed_pmfe_region(v,request);if(!r||!cJSON_AddItemToArray(a,r)){cJSON_Delete(r);ok=0;}}ok=typed_add_object(out,"regions",a)&&ok;}
  const cJSON *artifacts=cJSON_GetObjectItemCaseSensitive(body,"artifacts");
  if(artifacts){cJSON *a=cJSON_CreateArray();ok=ok&&cJSON_IsArray(artifacts)&&cJSON_GetArraySize(artifacts)<=17;for(const cJSON *v=artifacts->child;v&&ok;v=v->next){cJSON *r=typed_receipt(v);if(!r||!cJSON_AddItemToArray(a,r)){cJSON_Delete(r);ok=0;}}ok=typed_add_object(out,"artifacts",a)&&ok;}
  const cJSON *evidence=cJSON_GetObjectItemCaseSensitive(body,"evidence");if(evidence)ok=typed_add_object(out,"evidence",typed_receipt(evidence))&&ok;
  /* Keep the observed correlation state; arbitrary explanation prose stays local. */
  const cJSON *correlation=cJSON_GetObjectItemCaseSensitive(body,"correlation");
  if(correlation){cJSON *c=cJSON_CreateObject();const cJSON *cross=cJSON_GetObjectItemCaseSensitive(correlation,"cross_process_write");if(cross){cJSON *v=typed_fields(cross,"status","","");if(v&&!typed_enum(v,"status","not_observed|unknown|observed",0)){cJSON_Delete(v);v=NULL;}ok=typed_add_object(c,"cross_process_write",v)&&ok;}const cJSON *inj=cJSON_GetObjectItemCaseSensitive(correlation,"injection_signal");if(inj){cJSON *i=typed_fields(inj,"status|event_time_ns","age_ms","observed");if(i&&(!typed_enum(i,"status","observed|not_observed|generation_unavailable|unsupported|unsupported_platform",0)||(*result_text(i,"event_time_ns")&&!typed_decimal(result_text(i,"event_time_ns"))))){cJSON_Delete(i);i=NULL;}if(i&&cJSON_HasObjectItem(inj,"scope")){if(strcmp(result_text(inj,"scope"),"process_level_correlation_not_region_writer_attribution")||!cJSON_AddStringToObject(i,"scope","process_level_correlation_not_region_writer_attribution")){cJSON_Delete(i);i=NULL;}}ok=typed_add_object(c,"injection_signal",i)&&ok;}ok=typed_add_object(out,"correlation",c)&&ok;}
  if(!ok){cJSON_Delete(out);return NULL;}return out;
}
static cJSON *typed_forensic(const cJSON *body,const cJSON *request,int exit_code) {
  if(!typed_enum(body,"status","success|partial_success|failed|cancelled",0)||!typed_enum(body,"source","agent_builtin|external_collector|velociraptor|builtin|pmfe|local_fallback|libyara|builtin_substring_heuristic|unavailable",0))return NULL;
  cJSON *out=typed_fields(body,"schema|status|source|sha256|object_key|upload_status","total|cpu_limit_percent","truncated|download");if(!out)return NULL;
  cJSON *receipt=typed_receipt(body);if(!receipt){cJSON_Delete(out);return NULL;}cJSON_Delete(receipt);
  /* Artifact paths are local diagnostics; a named requested artifact is a
   * purpose identifier and may be returned only when it equals the request. */
  const char *artifact=result_text(body,"artifact"),*requested=result_text(request,"artifact");
  int ok=cJSON_AddStringToObject(out,"artifact",*requested&&!strcmp(artifact,requested)?artifact:"")!=NULL;
  ok=cJSON_AddStringToObject(out,"error",exit_code?"operation_failed":"")!=NULL&&ok;
  if(!ok){cJSON_Delete(out);return NULL;}return out;
}
static int typed_path_in_request(const char *path,const cJSON *request) {
  const char *wanted=result_text(request,"target_path");size_t n=strlen(wanted);
  if(!n||!typed_text_valid(path,4096)||strncmp(path,wanted,n))return 0;
  for(const char *p=path;*p;p++)if((p==path||p[-1]=='/'||p[-1]=='\\')&&p[0]=='.'&&p[1]=='.'&&(p[2]==0||p[2]=='/'||p[2]=='\\'))return 0;
  if(!strcmp(result_text(request,"target_type"),"directory"))return path[n]==0||path[n]=='/'||path[n]=='\\'||wanted[n-1]=='/'||wanted[n-1]=='\\';
  return path[n]==0;
}
static cJSON *typed_yara(const cJSON *body,const cJSON *request,int exit_code) {
  cJSON *out=typed_forensic(body,request,exit_code);if(!out)return NULL;
  int ok=result_copy_fields(out,body,"engine|scan_status|target_type|target_path","files_scanned|files_matched|files_completed|scan_errors|files_skipped|bytes_scanned|matches_returned","matched|matches_truncated");
  ok=ok&&typed_enum(out,"engine","libyara|builtin_substring_heuristic|unavailable|external_collector|velociraptor|builtin",1)&&typed_enum(out,"scan_status","completed|failed|degraded|artifact_only",0);
  if(cJSON_HasObjectItem(out,"target_path"))ok=typed_path_in_request(result_text(out,"target_path"),request)&&ok;
  double max_files=1,requested_limit=0;
  if(!strcmp(result_text(request,"target_type"),"directory")) {
    max_files=1000;
    if(result_integer(request,"max_files",1,10000,&requested_limit))max_files=requested_limit;
  }
  const cJSON *scanned=cJSON_GetObjectItemCaseSensitive(body,"files_scanned");
  if(scanned)ok=result_integer(body,"files_scanned",0,max_files,NULL)&&ok;
  const cJSON *matches=cJSON_GetObjectItemCaseSensitive(body,"matches");
  if(matches){cJSON *a=cJSON_CreateArray();ok=ok&&cJSON_IsArray(matches)&&cJSON_GetArraySize(matches)<=64&&cJSON_GetArraySize(matches)<=max_files;for(const cJSON *v=matches->child;v&&ok;v=v->next){cJSON *m=typed_fields(v,"path","","");if(!m||!typed_path_in_request(result_text(m,"path"),request)||!typed_add_object(m,"rules",typed_names(cJSON_GetObjectItemCaseSensitive(v,"rules"),64,128))||!cJSON_AddItemToArray(a,m)){cJSON_Delete(m);ok=0;}}ok=typed_add_object(out,"matches",a)&&ok;}
  if(!ok){cJSON_Delete(out);return NULL;}return out;
}
static int result_typed(const char *type,const char *command_id,const cJSON *body,const cJSON *request,int status,int exit_code,cJSON **out) {
  *out=NULL;
  if(!result_member(type,"kill_process|isolate_host|restore_host|isolate_status|pmfe_scan|yara_scan|collect_forensic|forensic|deep_forensic|forensic_deep|targeted_forensic|forensic_targeted|memory_dump|memdump"))return 0;
  if(!cJSON_IsObject(body))return status==1?-1:0;
  const char *schema=result_text(body,"schema");
  if(!strcmp(type,"kill_process")) {
    if(strcmp(schema,"edr.process_response.v1")||strcmp(result_text(body,"action"),"kill_process"))return -1;
    const char *reason=result_text(body,"reason"),*creation=result_text(body,"process_creation_filetime_100ns");double pid,want;
    const char *reasons="process_exit_verified|observed_process_identity_required|policy_disabled|protected_or_disallowed_process|cancelled_before_execution|process_already_gone|process_generation_mismatch|invalid_or_self_process_target|protected_process_target|verified_termination_unsupported_platform|process_termination_unverified|process_open_failed|process_identity_query_failed|process_protection_query_failed|process_terminate_failed|process_exit_wait_failed|process_exit_timeout";
    const cJSON *verified=cJSON_GetObjectItemCaseSensitive(body,"enforcement_verified");
    if(!result_member(reason,reasons)||!cJSON_IsBool(verified)||!typed_decimal(creation)||!result_integer(body,"pid",0,2147483647,&pid))return -1;
    if(strcmp(reason,"observed_process_identity_required") && (!result_integer(request,"pid",1,2147483647,&want)||pid!=want||strcmp(creation,result_text(request,"process_creation_filetime_100ns"))))return -1;
    if(cJSON_IsTrue(verified)!=(status==1&&exit_code==0&&!strcmp(reason,"process_exit_verified")))return -1;
    if(status==1&&(!cJSON_IsTrue(verified)||!pid||!strcmp(creation,"0")))return -1;
    *out=typed_fields(body,"schema|action|process_creation_filetime_100ns|reason","pid","enforcement_verified");return *out?1:-1;
  }
  if(result_member(type,"isolate_host|restore_host|isolate_status")) {
    if(!strcmp(schema,"edr.isolation.status.v1")) {
      const cJSON *isolated=cJSON_GetObjectItemCaseSensitive(body,"isolated"),*restored=cJSON_GetObjectItemCaseSensitive(body,"restored"),*verified=cJSON_GetObjectItemCaseSensitive(body,"enforcement_verified");
      if(!cJSON_IsBool(isolated)||!cJSON_IsBool(restored)||!cJSON_IsTrue(verified)||cJSON_IsTrue(isolated)==cJSON_IsTrue(restored)||status!=1||exit_code)return -1;
      if((!strcmp(type,"isolate_host")&&!cJSON_IsTrue(isolated))||(!strcmp(type,"restore_host")&&!cJSON_IsTrue(restored)))return -1;
      *out=typed_fields(body,"schema","","isolated|restored|enforcement_verified");
      const cJSON *reachable=cJSON_GetObjectItemCaseSensitive(body,"management_reachable");if(reachable&&(!cJSON_IsBool(reachable)&&!cJSON_IsNull(reachable))){cJSON_Delete(*out);*out=NULL;return -1;}
      if(*out&&reachable&&!typed_add_object(*out,"management_reachable",cJSON_Duplicate(reachable,1))){cJSON_Delete(*out);*out=NULL;}
      return *out?1:-1;
    }
    if(!strcmp(type,"isolate_status")&&!strcmp(schema,"edr.isolation.observation.v2")) {
      const cJSON *restored=cJSON_GetObjectItemCaseSensitive(body,"restoration_verified");
      if(!typed_enum(body,"state","normal|isolated|unknown",0)||!cJSON_IsBool(restored)||(cJSON_IsTrue(restored)&&strcmp(result_text(body,"state"),"normal")))return -1;
      *out=typed_fields(body,"schema|state","","restoration_verified");const char *reason=result_text(body,"reason");if(*reason&&!result_member(reason,"recovery_baseline_missing|os_state_unverified"))reason="os_state_unverified";
      if(*out&&!cJSON_AddStringToObject(*out,"reason",reason)){cJSON_Delete(*out);*out=NULL;}return *out?1:-1;
    }return -1;
  }
  if(!strcmp(type,"pmfe_scan")){if(strcmp(schema,"pmfe_result_v1") || (status==1&&!strcmp(result_text(body,"status"),"failed")))return -1;*out=typed_pmfe(command_id,body,request);return *out?1:-1;}
  if(!strcmp(type,"yara_scan")){if(strcmp(schema,"edr.yara_scan.result.v1") || (status==1&&!result_member(result_text(body,"status"),"success|partial_success")))return -1;*out=typed_yara(body,request,exit_code);return *out?1:-1;}
  if(result_member(type,"collect_forensic|forensic|deep_forensic|forensic_deep|targeted_forensic|forensic_targeted|memory_dump|memdump")) {
    if(strcmp(schema,"edr.forensic.result.v1") || (status==1&&!result_member(result_text(body,"status"),"success|partial_success")))return -1;*out=typed_forensic(body,request,exit_code);return *out?1:-1;
  }
  return 0;
}
