/* Test adapter: all storage/query implementation is the pinned version's owner. */
#define main compat_unused_original_main
#include COMPAT_TEST_SOURCE
#undef main
#include "compat_common.h"

static void compat_record(EdrBehaviorRecord *r,unsigned generation,unsigned item) {
  memset(r,0,sizeof(*r));r->type=EDR_EVENT_NET_CONNECT;r->priority=0;
  r->pid=96000u+generation*10u+item;r->ppid=4u;
  r->event_time_ns=compat_epoch*INT64_C(1000000000)+(int64_t)(generation*10u+item);
  r->process_start_key=UINT64_C(18446744073709551000)+generation*10u+item;
  r->process_creation_filetime_100ns=UINT64_C(133444000000000000)+generation*10u+item;
  r->parent_pid_state=EDR_PARENT_PID_KNOWN;
  snprintf(r->event_id,sizeof(r->event_id),"storage-compat-%u-%u",generation,item);
  strcpy(r->tenant_id,compat_tenant);strcpy(r->endpoint_id,compat_endpoint);
  strcpy(r->process_name,"storage-compat.exe");strcpy(r->exe_path,"C:\\synthetic\\storage-compat.exe");
  snprintf(r->cmdline,sizeof(r->cmdline),"storage-compat.exe --generation=%u --item=%u --utf8=\xe5\x85\xbc\xe5\xae\xb9",generation,item);
  snprintf(r->file_path,sizeof(r->file_path),"C:\\synthetic\\record-%u-%u.bin",generation,item);
  strcpy(r->process_generation_source,"etw_start_key_live_telemetry");
  strcpy(r->source_completeness,"COMPLETE");strcpy(r->net_dst,"192.0.2.20");strcpy(r->net_proto,"tcp");r->net_dport=445;
}
static cJSON *compat_cache_facts(const EdrBehaviorRecord *r) {
  cJSON *o=cJSON_CreateObject();char key[32],creation[32];
  snprintf(key,sizeof(key),"%llu",(unsigned long long)r->process_start_key);
  snprintf(creation,sizeof(creation),"%llu",(unsigned long long)r->process_creation_filetime_100ns);
  cJSON_AddNumberToObject(o,"pid",r->pid);cJSON_AddNumberToObject(o,"ppid",r->ppid);
  cJSON_AddNumberToObject(o,"event_time_ns",(double)r->event_time_ns);
  cJSON_AddNumberToObject(o,"type",r->type);cJSON_AddStringToObject(o,"endpoint_id",r->endpoint_id);
  cJSON_AddStringToObject(o,"process_start_key",key);cJSON_AddStringToObject(o,"process_creation_filetime_100ns",creation);
  cJSON_AddStringToObject(o,"process_name",r->process_name);cJSON_AddStringToObject(o,"exe_path",r->exe_path);
  cJSON_AddStringToObject(o,"cmdline",r->cmdline);cJSON_AddStringToObject(o,"file_path",r->file_path);
  cJSON_AddStringToObject(o,"process_generation_source",r->process_generation_source);
  cJSON_AddStringToObject(o,"source_completeness",r->source_completeness);return o;
}
int main(int argc,char **argv) {
  compat_args(argc,argv);s_test_real_monotonic=1;
  /* No fixture clock, identity override or legacy schema switch is enabled. */
  compat_need(edr_local_evidence_cache_open_with_policy(argv[2],compat_max_mb,compat_retention,compat_selected)==0,"cache_owner_open");
  edr_pt_cache_init();cJSON *records=cJSON_CreateArray();
  if(strcmp(compat_stage,"read")) {
    unsigned generation=!strcmp(compat_stage,"append")?2u:1u;
    for(unsigned item=0;item<2u;item++) {
      EdrBehaviorRecord *r=calloc(1,sizeof(*r));compat_need(r!=NULL,"record_alloc");compat_record(r,generation,item);
      char filter[256],prior[32768];snprintf(filter,sizeof(filter),"{\"endpoint_id\":\"%s\",\"pid\":%u,\"limit\":10,\"time_window_s\":3600}",compat_endpoint,r->pid);
      compat_need(edr_local_evidence_cache_query_json(filter,prior,sizeof(prior))==0,"pre_write_query");
      cJSON *before=cJSON_Parse(prior),*rows=before?cJSON_GetObjectItemCaseSensitive(before,"rows"):NULL;
      compat_need(cJSON_IsArray(rows)&&cJSON_GetArraySize(rows)==0,"fixture_already_present");cJSON_Delete(before);
      EdrCommandFacts commands={r->cmdline,NULL};
      compat_need(edr_local_evidence_cache_record_alert_context(r,&commands)==0,"cache_owner_write");
      cJSON_AddItemToArray(records,compat_cache_facts(r));free(r);
    }
  } else {
    /* This process never wrote records: a ring hit cannot satisfy the check. */
    for(unsigned generation=1u;generation<=compat_generations;generation++)for(unsigned item=0;item<2u;item++) {
      EdrBehaviorRecord *r=calloc(1,sizeof(*r));compat_need(r!=NULL,"record_alloc");compat_record(r,generation,item);
      char filter[512],out[32768];snprintf(filter,sizeof(filter),"{\"endpoint_id\":\"%s\",\"pid\":%u,\"process_start_key\":\"%llu\",\"process_creation_filetime_100ns\":\"%llu\",\"limit\":10,\"time_window_s\":3600}",r->endpoint_id,r->pid,(unsigned long long)r->process_start_key,(unsigned long long)r->process_creation_filetime_100ns);
      compat_need(edr_local_evidence_cache_query_json(filter,out,sizeof(out))==0,"cache_query");
      char exact_time[80];snprintf(exact_time,sizeof(exact_time),"\"event_time_ns\":%lld,",(long long)r->event_time_ns);
      compat_need(strstr(out,exact_time)!=NULL,"exact_persisted_event_time_ns");
      cJSON *doc=cJSON_Parse(out);compat_need(doc!=NULL,"cache_query_json");
      compat_need(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(doc,"partial")),"cache_partial");
      cJSON *rows=cJSON_GetObjectItemCaseSensitive(doc,"rows");compat_need(cJSON_IsArray(rows)&&cJSON_GetArraySize(rows)==1,"cache_expected_one_row");
      cJSON *row=cJSON_GetArrayItem(rows,0),*expected=compat_cache_facts(r),*field=NULL;
      compat_equal(row,"source","p0_candidates");
      cJSON_ArrayForEach(field,expected) {cJSON *actual=cJSON_GetObjectItemCaseSensitive(row,field->string);compat_need(actual&&cJSON_Compare(actual,field,1),field->string);}
      cJSON_AddItemToArray(records,expected);cJSON_Delete(doc);free(r);
    }
  }
  EdrEvidenceCacheStatus status;edr_local_evidence_cache_get_status(&status);compat_need(status.db_open,"cache_db_open");
  edr_local_evidence_cache_close();edr_pt_cache_shutdown();
  cJSON *receipt=compat_receipt("evidence_cache",records);cJSON_AddNumberToObject(receipt,"storage_format",status.storage_format);
  cJSON_AddBoolToObject(receipt,"read_from_reopened_sqlite",!strcmp(compat_stage,"read"));compat_print(receipt);return 0;
}
