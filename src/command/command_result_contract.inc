/* The durable command owner owns both request-derived purposes and projection.
 * This file is compiled only as part of command_state.c. */
#include "edr/shell_session.h"
static const char *result_text(const cJSON *o, const char *key) {
  const cJSON *v=cJSON_GetObjectItemCaseSensitive(o,key);
  return cJSON_IsString(v) && v->valuestring ? v->valuestring : "";
}
static int result_integer(const cJSON *o,const char *key,double min,double max,double *out) {
  const cJSON *v=cJSON_GetObjectItemCaseSensitive(o,key);
  if(!cJSON_IsNumber(v) || v->valuedouble<min || v->valuedouble>max ||
      v->valuedouble!=(double)(int64_t)v->valuedouble)return 0;
  if(out)*out=v->valuedouble;return 1;
}
static int result_member(const char *name,const char *list) {
  if(!name || !*name)return 0;
  size_t n=strlen(name);
  for(const char *p=list;*p;) {
    const char *end=strchr(p,'|');size_t len=end?(size_t)(end-p):strlen(p);
    if(len==n && !memcmp(p,name,n))return 1;
    if(!end)break;p=end+1;
  }
  return 0;
}
static int result_contains(const char *value,const char *needle) {
  if(!needle[0])return 1;
  for(const char *p=value;*p;p++) {
    size_t i=0;while(needle[i] && p[i] && tolower((unsigned char)needle[i])==tolower((unsigned char)p[i]))i++;
    if(!needle[i])return 1;
  }
  return 0;
}
static int result_equal_icase(const char *a,const char *b) {
  return strlen(a)==strlen(b) && result_contains(a,b);
}
static int result_registry_key(const char *key,const char *root,int subtree) {
  size_t n=strlen(root);
  if(!n || strlen(key)<n)return 0;
  for(size_t i=0;i<n;i++)if(tolower((unsigned char)key[i])!=tolower((unsigned char)root[i]))return 0;
  return key[n]==0 || (subtree && (root[n-1]=='\\'||key[n]=='\\'));
}
static int result_filter_text(const cJSON *request,const char *key,const cJSON *row,const char *field,int exact) {
  const char *want=result_text(request,key);if(!*want)return 1;
  const char *actual=result_text(row,field);
  return exact ? !strcmp(want,actual) : result_contains(actual,want);
}
static int result_filter_number(const cJSON *request,const char *key,const cJSON *row,const char *field,int compare) {
  const cJSON *want=cJSON_GetObjectItemCaseSensitive(request,key);if(!want)return 1;
  const cJSON *actual=cJSON_GetObjectItemCaseSensitive(row,field);
  return cJSON_IsNumber(want) && cJSON_IsNumber(actual) &&
      (compare<0 ? actual->valuedouble>=want->valuedouble : compare>0 ? actual->valuedouble<=want->valuedouble : actual->valuedouble==want->valuedouble);
}
static int result_filter_generation(const cJSON *q,const char *key,const cJSON *row) {
  const cJSON *want=cJSON_GetObjectItemCaseSensitive(q,key);
  if(!want)return 1;
  char numeric[32];const char *expected=NULL;
  if(cJSON_IsString(want))expected=want->valuestring;
  else if(cJSON_IsNumber(want)&&want->valuedouble>=0&&want->valuedouble<=9007199254740991.0&&want->valuedouble==(double)(uint64_t)want->valuedouble) {
    snprintf(numeric,sizeof(numeric),"%.0f",want->valuedouble);expected=numeric;
  }
  if(!expected||!*expected||strlen(expected)>20||strspn(expected,"0123456789")!=strlen(expected))return 0;
  while(expected[0]=='0'&&expected[1])expected++;
  if(!strcmp(expected,"0"))return 1; /* existing cache: zero means no generation predicate */
  return !strcmp(expected,result_text(row,key));
}
/* Scalars have a type and byte bound; arbitrary nested objects cannot smuggle
 * new data through a field whose name alone appears to be permitted. */
static int result_copy_fields(cJSON *dst,const cJSON *src,const char *strings,
                              const char *numbers,const char *booleans) {
  for(const cJSON *v=src?src->child:NULL;v;v=v->next) {
    if(!v->string)return 0;
    int take=result_member(v->string,strings)||result_member(v->string,numbers)||result_member(v->string,booleans);
    if(!take)continue;
    if(cJSON_HasObjectItem(dst,v->string))return 0;
    if(result_member(v->string,strings) && (!cJSON_IsString(v)||!v->valuestring||strlen(v->valuestring)>8192u))return 0;
    if(result_member(v->string,numbers) && (!cJSON_IsNumber(v)||v->valuedouble<(!strcmp(v->string,"exit_code")?INT_MIN:0)||v->valuedouble>9007199254740991.0||v->valuedouble!=(double)(int64_t)v->valuedouble))return 0;
    if(result_member(v->string,booleans) && !cJSON_IsBool(v))return 0;
    if(!cJSON_AddItemToObject(dst,v->string,cJSON_Duplicate(v,1)))return 0;
  }
  return 1;
}

static int result_cached_type(const cJSON *request,uint32_t *out) {
  const char *s=result_text(request,"event_type");if(!*s)s=result_text(request,"type");
  if(!*s)return 0;
  static const struct {const char *names;uint32_t type;} names[]={
    {"process|process_create",EDR_EVENT_PROCESS_CREATE},{"network|net|connect",EDR_EVENT_NET_CONNECT},
    {"dns",EDR_EVENT_NET_DNS_QUERY},{"tls",EDR_EVENT_NET_TLS_HANDSHAKE},{"file|file_write",EDR_EVENT_FILE_WRITE},
    {"registry|reg",EDR_EVENT_REG_SET_VALUE},{"script|powershell",EDR_EVENT_SCRIPT_POWERSHELL},
    {"webshell",EDR_EVENT_WEBSHELL_DETECTED},{"shellcode",EDR_EVENT_PROTOCOL_SHELLCODE},{"pmfe",EDR_EVENT_PMFE_SCAN_RESULT}
  };
  for(size_t i=0;i<sizeof(names)/sizeof(names[0]);i++)if(result_member(s,names[i].names)){*out=names[i].type;return 1;}
  char *end=NULL;errno=0;unsigned long value=strtoul(s,&end,10);
  if(!errno && end!=s && !*end && value<=UINT32_MAX){*out=(uint32_t)value;return 1;}
  return -1;
}

int edr_command_result_bind_contract(EdrCommandResultAuthorization *a,const uint8_t *payload,
                                      size_t len,int64_t issued_ms) {
  if(!a||!a->command_id[0]||!a->command_type[0]||issued_ms<=0)return -1;
  /* A malformed/over-budget request can still receive a finite rejection;
   * it never receives query or raw-output authority. */
  snprintf(a->content_contract,sizeof(a->content_contract),"{\"schema\":\"edr.command.result-purpose.v1\",\"kind\":\"status\",\"max_bytes\":1024}");
  cJSON *request=payload && len ? edr_egress_parse_purpose_object(payload,len) : cJSON_CreateObject();
  if(!cJSON_IsObject(request)){cJSON_Delete(request);return -1;}
  const char *kind=!strcmp(a->command_type,"rtq_execute")?"rtq":
      !strcmp(a->command_type,"rtq_query")?"cached_rtq":
      !strcmp(a->command_type,"shell_open")?"shell_stream":
      !strcmp(a->command_type,"rtr_shell")?"shell_output":
      result_member(a->command_type,"kill_process|isolate_host|restore_host|isolate_status|pmfe_scan|yara_scan|collect_forensic|forensic|deep_forensic|targeted_forensic|memory_dump|velo_query")?"typed":
      result_member(a->command_type,"noop|echo|telemetry_profile_update|put_file|forensic_cancel|rtr_rm_file|quarantine_file|unquarantine_file|shell_open|shell_input|shell_close|update_server_address|result_delivery_renewal|agent_update|agent_restart_service|agent_offboard|agent_uninstall")?"status":"unsupported";
  cJSON *contract=cJSON_CreateObject();int ok=contract!=NULL;
  unsigned rows=500,window=600;uint32_t event_type=0;int has_type=0;
  if(!strcmp(kind,"cached_rtq")) {
    static const char *aliases[][2]={{"process_name","process_name_contains"},{"process_cmdline","cmdline_contains"},{"file_path","file_path_contains"},{"file_sha256","sha256"},{"event_type","type"}};
    for(size_t i=0;i<sizeof(aliases)/sizeof(aliases[0]);i++) {
      const cJSON *v=cJSON_GetObjectItemCaseSensitive(request,aliases[i][0]),*old=cJSON_GetObjectItemCaseSensitive(request,aliases[i][1]);
      if((v && !cJSON_IsString(v)) || (old && !cJSON_IsString(old)) || (v && old && strcmp(v->valuestring,old->valuestring))) {
        cJSON_Delete(contract);cJSON_Delete(request);return -1;
      }
      if(!v && old && !cJSON_AddStringToObject(request,aliases[i][0],old->valuestring)){cJSON_Delete(contract);cJSON_Delete(request);return -1;}
      cJSON_DeleteItemFromObjectCaseSensitive(request,aliases[i][1]);
    }
    double n;rows=50;has_type=result_cached_type(request,&event_type);
    if(has_type<0){cJSON_Delete(contract);cJSON_Delete(request);return -1;}
    if(cJSON_HasObjectItem(request,"limit")) {
      if(!result_integer(request,"limit",1,1000,&n)){cJSON_Delete(contract);cJSON_Delete(request);return -1;}rows=(unsigned)n;
    }
    if(cJSON_HasObjectItem(request,"time_window_s")) {
      if(!result_integer(request,"time_window_s",1,604800,&n)){cJSON_Delete(contract);cJSON_Delete(request);return -1;}window=(unsigned)n;
    }
  }
  if(ok)ok=cJSON_AddStringToObject(contract,"schema","edr.command.result-purpose.v1") &&
      cJSON_AddStringToObject(contract,"kind",kind) &&
      cJSON_AddNumberToObject(contract,"max_bytes",!strcmp(kind,"status")?1024:16383) &&
      cJSON_AddNumberToObject(contract,"max_rows",rows) &&
      cJSON_AddNumberToObject(contract,"max_chunks",63) &&
      cJSON_AddNumberToObject(contract,"window_s",window) &&
      cJSON_AddNumberToObject(contract,"issued_unix_ms",(double)issued_ms);
  if(ok && has_type)ok=cJSON_AddNumberToObject(contract,"event_type",event_type)!=NULL;
  if(ok && !strcmp(kind,"typed")) {
    cJSON *scope=cJSON_CreateObject();
    ok=scope && result_copy_fields(scope,request,
        "process_creation_filetime_100ns|region_base|target_path|target_type|artifact|preset|mode|source",
        "pid|region_size|max_files|max_depth|max_file_mb", "run_yara|extract_region");
    if(ok){cJSON_Delete(request);request=scope;}else cJSON_Delete(scope);
  }
  if(ok && strcmp(kind,"status") && strcmp(kind,"unsupported")) {
    ok=cJSON_AddItemToObject(contract,"request",request);if(ok)request=NULL;
  }
  if(ok)ok=cJSON_PrintPreallocated(contract,a->content_contract,sizeof(a->content_contract),0);
  cJSON_Delete(contract);cJSON_Delete(request);
  if(!ok)a->content_contract[0]=0;
  return ok?0:-1;
}

static cJSON *result_status(int status,int code) {
  cJSON *o=cJSON_CreateObject();if(!o)return NULL;
  if(!cJSON_AddStringToObject(o,"schema","edr.command.status.v1")||
     !cJSON_AddNumberToObject(o,"status",status)||!cJSON_AddNumberToObject(o,"exit_code",code)||
     !cJSON_AddStringToObject(o,"diagnostic",status==1?"command_completed":status==2?"command_rejected":"command_failed")) {
    cJSON_Delete(o);return NULL;
  }
  return o;
}
static int result_query_category(const cJSON *q,const char *type) {
  const char *keys=!strcmp(type,"process")?"process_name|process_path|process_cmdline|process_user|process_pid_min|process_pid_max|script_content|script_engine":
      !strcmp(type,"network")?"network_remote_ip|network_remote_port|network_state|network_proto":
      !strcmp(type,"file")?"file_path|file_sha256|file_ext":
      !strcmp(type,"registry")?"registry_path|registry_value":
      !strcmp(type,"eventlog")?"eventlog_channel|eventlog_query":"";
  for(const cJSON *v=q?q->child:NULL;v;v=v->next)
    if(result_member(v->string,keys) &&
       ((cJSON_IsString(v)&&v->valuestring&&v->valuestring[0])||cJSON_IsNumber(v)))return 1;
  return 0;
}
static cJSON *result_live_row(const cJSON *q,const cJSON *row) {
  const char *type=result_text(row,"type");
  if(!cJSON_IsObject(row)||!result_query_category(q,type))return NULL;
  cJSON *out=cJSON_CreateObject();if(!out)return NULL;
  int ok=0;
  if(!strcmp(type,"process")) {
    const char *cmd=result_text(q,"process_cmdline"),*engine=result_text(q,"script_engine");
    if(!*cmd)cmd=result_text(q,"script_content");
    ok=result_contains(result_text(row,"cmdline"),cmd) &&
       (!*engine || result_contains(result_text(row,"name"),engine) || result_contains(result_text(row,"cmdline"),engine)) &&result_filter_text(q,"process_name",row,"name",0) && result_filter_text(q,"process_path",row,"path",0) &&
       result_filter_text(q,"process_cmdline",row,"cmdline",0) && result_filter_text(q,"process_user",row,"user",0) &&
       result_filter_number(q,"process_pid_min",row,"pid",-1) && result_filter_number(q,"process_pid_max",row,"pid",1) &&
       result_copy_fields(out,row,"type|name|path","pid","");
    if(ok && (*cmd || *engine))ok=result_copy_fields(out,row,"cmdline","","");
    if(ok && *result_text(q,"process_user"))ok=result_copy_fields(out,row,"user","","");
  } else if(!strcmp(type,"network")) {
    ok=result_filter_text(q,"network_remote_ip",row,"remote_ip",0) && result_filter_number(q,"network_remote_port",row,"remote_port",0) &&
       result_filter_text(q,"network_state",row,"state",0) && result_filter_text(q,"network_proto",row,"proto",0) &&
       result_copy_fields(out,row,"type|proto|state|local_ip|remote_ip","pid|local_port|remote_port","");
  } else if(!strcmp(type,"file")) {
    const char *path=result_text(row,"path"),*ext=result_text(q,"file_ext");size_t pn=strlen(path),en=strlen(ext);
    ok=result_filter_text(q,"file_path",row,"path",0) && (!*result_text(q,"file_sha256")||result_equal_icase(result_text(q,"file_sha256"),result_text(row,"sha256"))) &&
       (!en||(pn>=en && result_contains(path+pn-en,ext))) &&
       result_copy_fields(out,row,"type|path|sha256|source","size","cache_hit");
  } else if(!strcmp(type,"registry")) {
    const char *path=result_text(q,"registry_path");
    ok=*path && result_registry_key(result_text(row,"key"),path,!strcmp(result_text(q,"registry_mode"),"subtree")) &&
       result_filter_text(q,"registry_value",row,"value",0) &&
       result_copy_fields(out,row,"type|key|value|data","reg_type","");
  } else if(!strcmp(type,"eventlog")) {
    const char *channel=result_text(q,"eventlog_channel"),*query=result_text(q,"eventlog_query");
    ok=*result_text(row,"provider") && *result_text(row,"timestamp") &&
       result_integer(row,"event_id",0,65535,NULL) && result_integer(row,"record_id",1,9007199254740991.0,NULL) &&
       !strcmp(result_text(row,"channel"),*channel?channel:"System") &&
       !strcmp(result_text(row,"query"),*query?query:"*") &&
       result_copy_fields(out,row,"type|channel|query|provider|timestamp","event_id|record_id|level|process_id|thread_id","");
  }
  if(!ok){cJSON_Delete(out);return NULL;}return out;
}
static cJSON *result_cached_row(const cJSON *q,const cJSON *row,const cJSON *contract,const EdrCommandResultAuthorization *a) {
  if(!cJSON_IsObject(row))return NULL;
  if(!strcmp(result_text(row,"type"),"file")) {
    /* Hash-cache records use the same file purpose and no event timestamp. */
    if(!*result_text(q,"file_sha256"))return NULL;
    cJSON *request=cJSON_CreateObject();if(!request)return NULL;
    cJSON_AddStringToObject(request,"file_sha256",result_text(q,"file_sha256"));
    cJSON_AddStringToObject(request,"file_path",result_text(q,"file_path"));
    cJSON_AddStringToObject(request,"file_ext",result_text(q,"file_ext"));
    cJSON *out=result_live_row(request,row);cJSON_Delete(request);return out;
  }
  double ts,issued,window;
  if(*result_text(q,"file_sha256"))return NULL; /* this scope selects only the hash-cache result shape */
  if(!result_filter_generation(q,"process_start_key",row) ||
      !result_filter_generation(q,"process_creation_filetime_100ns",row) ||
      !result_filter_text(q,"registry_key_contains",row,"registry_key",0) ||
      !result_integer(row,"event_time_ns",1,9007199254740991.0*1000,&ts) ||
      !result_integer(contract,"issued_unix_ms",1,9007199254740991.0,&issued) ||
      !result_integer(contract,"window_s",1,604800,&window) ||
      ts < (issued-window*1000)*1000000 || ts>(issued+300000)*1000000 ||
      strcmp(result_text(row,"endpoint_id"),a->endpoint_id) ||
      !result_filter_number(contract,"event_type",row,"type",0) ||
      !result_filter_number(q,"pid",row,"pid",0) ||
      !result_filter_number(q,"remote_port",row,"dst_port",0) ||
      !result_filter_text(q,"process_name",row,"process_name",0) ||
      !result_filter_text(q,"process_path",row,"exe_path",0) ||
      !result_filter_text(q,"process_cmdline",row,"cmdline",0) ||
      !result_filter_text(q,"remote_ip",row,"remote_ip",1) ||
      !result_filter_text(q,"file_path",row,"file_path",0))return NULL;
  cJSON *out=cJSON_CreateObject();if(!out)return NULL;
  int ok=result_copy_fields(out,row,"source|endpoint_id|process_name|exe_path|process_start_key|process_creation_filetime_100ns|process_generation_source|source_completeness|source_truncated_fields","type|pid|ppid","");
  /* Nanosecond event time is an existing JSON double field. Preserve its
   * representation after checking the signed query time window above. */
  if(ok)ok=cJSON_AddItemToObject(out,"event_time_ns",cJSON_Duplicate(cJSON_GetObjectItemCaseSensitive(row,"event_time_ns"),1));
  if(ok && *result_text(q,"process_cmdline"))ok=result_copy_fields(out,row,"cmdline","","");
  const cJSON *event_kind=cJSON_GetObjectItemCaseSensitive(contract,"event_type");
  int file_kind=cJSON_IsNumber(event_kind)&&event_kind->valuedouble==EDR_EVENT_FILE_WRITE;
  int dns_kind=cJSON_IsNumber(event_kind)&&event_kind->valuedouble==EDR_EVENT_NET_DNS_QUERY;
  int registry_kind=cJSON_IsNumber(event_kind)&&event_kind->valuedouble==EDR_EVENT_REG_SET_VALUE;
  if(ok && dns_kind)ok=result_copy_fields(out,row,"dns_query","","");
  if(ok && (registry_kind || *result_text(q,"registry_key_contains")))ok=result_copy_fields(out,row,"registry_key|registry_value|registry_op","","");
  int network_kind=cJSON_IsNumber(event_kind)&&event_kind->valuedouble==EDR_EVENT_NET_CONNECT;
  if(ok && (*result_text(q,"file_path")||*result_text(q,"file_sha256")||file_kind))ok=result_copy_fields(out,row,"file_path","","");
  if(ok && (*result_text(q,"remote_ip")||cJSON_HasObjectItem(q,"remote_port")||network_kind))ok=result_copy_fields(out,row,"remote_ip","dst_port","");
  if(!ok){cJSON_Delete(out);return NULL;}return out;
}
static cJSON *result_query(const cJSON *root,const cJSON *contract,const EdrCommandResultAuthorization *a,int cached) {
  const cJSON *q=cJSON_GetObjectItemCaseSensitive(contract,"request");
  const cJSON *rows=cJSON_GetObjectItemCaseSensitive(root,cached?"rows":"results");
  double max_rows;if(!cJSON_IsObject(q)||!cJSON_IsArray(rows)||!result_integer(contract,"max_rows",1,cached?1000:500,&max_rows)||cJSON_GetArraySize(rows)>max_rows)return NULL;
  cJSON *out=cJSON_CreateObject(),*projected=cJSON_CreateArray();
  if(!out||!projected){cJSON_Delete(out);cJSON_Delete(projected);return NULL;}
  cJSON_AddItemToObject(out,cached?"rows":"results",projected);
  for(const cJSON *row=rows->child;row;row=row->next) {
    cJSON *item=cached?result_cached_row(q,row,contract,a):result_live_row(q,row);
    if(!item||!cJSON_AddItemToArray(projected,item)){cJSON_Delete(item);cJSON_Delete(out);return NULL;}
  }
  const cJSON *incomplete=cJSON_GetObjectItemCaseSensitive(root,cached?"partial":"truncated");
  if(incomplete && !cJSON_IsBool(incomplete)){cJSON_Delete(out);return NULL;}
  /* Missing completeness is unknown, never silently reported as complete. */
  int partial=!incomplete || cJSON_IsTrue(incomplete);
  if(cached) {
    cJSON_AddStringToObject(out,"source","mixed");
    cJSON_AddBoolToObject(out,"partial",partial);
    cJSON_AddNumberToObject(out,"rows_returned",cJSON_GetArraySize(rows));
  } else {
    cJSON_AddNumberToObject(out,"total",cJSON_GetArraySize(rows));
    cJSON_AddBoolToObject(out,"truncated",partial);
    /* Errors are finite diagnostics. Free text and sampler detail stay local. */
    cJSON *errors=cJSON_CreateArray();if(!errors){cJSON_Delete(out);return NULL;}
    cJSON_AddItemToObject(out,"errors",errors);
    const cJSON *input=cJSON_GetObjectItemCaseSensitive(root,"errors");
    if(input && (!cJSON_IsArray(input)||cJSON_GetArraySize(input)>32)){cJSON_Delete(out);return NULL;}
    int warnings=0;
    for(const cJSON *error=input?input->child:NULL;error;error=error->next) {
      const char *source=result_text(error,"source"),*code=result_text(error,"code");
      if(!result_member(source,"process|process_cmdline|parent_cmdline|network|registry|eventlog|file_hash_cache|command_result_transport") ||
         !result_member(code,"snapshot_failed|too_long|collector_unavailable|partial_access|collector_failed|partial_failure|invalid_hive|access_denied|key_not_found|invalid_utf8|query_failed|render_context_failed|enumeration_failed|oom|sampler_timeout|sampler_failed|process_path_unsupported|cache_query_failed|platform_unsupported|result_truncated")) {cJSON_Delete(out);return NULL;}
      cJSON *item=cJSON_CreateObject();if(!item){cJSON_Delete(out);return NULL;}
      const cJSON *retryable=cJSON_GetObjectItemCaseSensitive(error,"retryable");
      if(retryable && !cJSON_IsBool(retryable)){cJSON_Delete(item);cJSON_Delete(out);return NULL;}
      /* Classify finite codes here so free text or a forged severity cannot
       * downgrade a real collection failure. This survives durable replay. */
      int warning=result_member(code,"partial_access|result_truncated");
      cJSON_AddStringToObject(item,"source",source);cJSON_AddStringToObject(item,"code",code);
      cJSON_AddStringToObject(item,"severity",warning?"warning":"error");
      cJSON_AddBoolToObject(item,"retryable",cJSON_IsTrue(retryable));
      cJSON_AddItemToArray(errors,item);
      if(warning)warnings++;
    }
    if(cJSON_GetArraySize(errors))cJSON_AddNumberToObject(out,"warning_count",warnings);
    cJSON_AddItemToObject(out,"error",cJSON_GetArraySize(errors)>warnings?cJSON_CreateString("collector_diagnostic"):cJSON_CreateNull());
  }
  return out;
}
/* The open receipt is a control fact from the session owner, not stdout.
 * Keep a fixed banner for supported consumers without copying the requested
 * shell or accepting a generic successful command as an opened session. */
static cJSON *result_shell_open(const cJSON *root,const EdrCommandResultAuthorization *a,int exit_code) {
  if(exit_code || strcmp(a->command_type,"shell_open") || !a->command_id[0] ||
      strlen(a->command_id)>=EDR_SS_ID_LEN || strcmp(result_text(root,"schema"),"edr.shell.session.v1") ||
      strcmp(result_text(root,"session_id"),a->command_id) || strcmp(result_text(root,"status"),"ok") ||
      !result_integer(root,"exit_code",0,0,NULL) ||
      !cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(root,"closed")))return NULL;
  cJSON *out=cJSON_CreateObject();if(!out)return NULL;
  if(!cJSON_AddStringToObject(out,"schema","edr.shell.session.v1") ||
      !cJSON_AddStringToObject(out,"session_id",a->command_id) ||
      !cJSON_AddStringToObject(out,"status","ok") || !cJSON_AddNumberToObject(out,"exit_code",0) ||
      !cJSON_AddBoolToObject(out,"closed",0) ||
      !cJSON_AddStringToObject(out,"raw_detail","shell session opened: authorized session")) {
    cJSON_Delete(out);return NULL;
  }
  return out;
}
static cJSON *result_shell(const cJSON *root,const cJSON *contract,const EdrCommandResultAuthorization *a,int stream) {
  if(!cJSON_IsObject(root))return NULL;
  const char *data=result_text(root,stream?"data":"output");
  if(strlen(data)>(stream?2048u:8191u))return NULL;
  cJSON *out=cJSON_CreateObject();if(!out)return NULL;int ok;
  if(stream) {
    double seq,chunks;
    ok=!strcmp(result_text(root,"schema"),"edr.shell.stream.v1") && !strcmp(result_text(root,"session_id"),a->command_id) &&
       !strcmp(result_text(root,"stream"),"stdout") && result_integer(contract,"max_chunks",1,63,&chunks) &&
       result_integer(root,"seq",1,chunks,&seq) &&
       result_copy_fields(out,root,"schema|session_id|stream|data","seq|exit_code","closed");
  } else {
    const cJSON *q=cJSON_GetObjectItemCaseSensitive(contract,"request");
    const char *command=result_text(q,"command");if(!*command)command=result_text(q,"cmd");
    char digest[65];
    ok=*command && edr_sha256_hex((const uint8_t *)command,strlen(command),digest)==0 &&
        (!strcmp(result_text(root,"command"),command)||!strcmp(result_text(root,"command_sha256"),digest)) &&
        result_copy_fields(out,root,"output","exit_code|timeout_sec","output_truncated") &&
        cJSON_AddStringToObject(out,"command_sha256",digest);
  }
  if(!ok){cJSON_Delete(out);return NULL;}return out;
}
#include "command_result_typed.inc"

int edr_command_result_project_detail(const EdrCommandResultAuthorization *a,const char *type,
    int status,int exit_code,const char *detail,char *out,size_t cap) {
  if(!a||!type||!detail||!out||!cap||!a->content_contract[0]||strlen(detail)>=EDR_COMMAND_STATE_DETAIL_CAP)return -1;
  cJSON *contract=edr_egress_parse_purpose_object(a->content_contract,strlen(a->content_contract)),*raw=edr_egress_parse_purpose_object(detail,strlen(detail)),*inner=NULL,*projected=NULL;
  const char *kind=result_text(contract,"kind");double max_bytes;
  if(strcmp(result_text(contract,"schema"),"edr.command.result-purpose.v1")||!result_integer(contract,"max_bytes",1,16383,&max_bytes))goto done;
  const cJSON *wrapper_raw=cJSON_GetObjectItemCaseSensitive(raw,"raw_detail");
  const cJSON *body=raw;
  if(cJSON_IsString(wrapper_raw) && !*result_text(raw,"schema") && cJSON_HasObjectItem(raw,"task_id")) {
    if(strcmp(result_text(raw,"task_id"),a->command_id))goto done;
    inner=edr_egress_parse_purpose_object(wrapper_raw->valuestring,strlen(wrapper_raw->valuestring));body=inner;}
  if(status!=1 && !strcmp(result_text(body,"schema"),"edr.command.status.v1"))projected=result_status(status,exit_code);
  else if(status==1 && !strcmp(type,"shell_open") && !strcmp(kind,"shell_stream"))projected=result_shell_open(body,a,exit_code);
  else if(!strcmp(type,"shell_stream") && !strcmp(kind,"shell_stream"))projected=result_shell(body,contract,a,1);
  else if(!strcmp(type,"rtr_shell") && !strcmp(kind,"shell_output") && body && cJSON_HasObjectItem(body,"output"))projected=result_shell(body,contract,a,0);
  else if(status==1 && !strcmp(type,"rtq_execute") && !strcmp(kind,"rtq"))projected=result_query(body,contract,a,0);
  else if(status==1 && !strcmp(type,"rtq_query") && !strcmp(kind,"cached_rtq"))projected=result_query(body,contract,a,1);
  else if(!strcmp(type,a->command_type) && !strcmp(kind,"typed")) {
    int rc=result_typed(type,a->command_id,body,cJSON_GetObjectItemCaseSensitive(contract,"request"),status,exit_code,&projected);
    if(rc<0 || (rc==0&&status==1))goto done;
    if(rc==0)projected=result_status(status,exit_code);
  }
  else if(!strcmp(type,a->command_type) && (!strcmp(kind,"status") || status!=1))projected=result_status(status,exit_code);
  if(projected && cJSON_PrintPreallocated(projected,out,(int)cap,0) && strlen(out)<=(size_t)max_bytes) {
    cJSON_Delete(projected);cJSON_Delete(inner);cJSON_Delete(raw);cJSON_Delete(contract);return 0;
  }
done:
  cJSON_Delete(projected);cJSON_Delete(inner);cJSON_Delete(raw);cJSON_Delete(contract);return -1;
}
