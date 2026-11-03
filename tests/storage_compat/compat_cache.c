/* Test adapter: all storage/query implementation is the pinned version's owner. */
#define main compat_unused_original_main
#include COMPAT_TEST_SOURCE
#undef main
#include "compat_common.h"

enum { COMPAT_CACHE_QUERY_LIMIT=1000, COMPAT_CACHE_SCAN_BOUND=20100,
       COMPAT_CACHE_NOISE_RECORDS=320 };

/* At most 15 fixed milestones per invocation; stdout remains the receipt.
 * Flush before owner calls so a terminated child retains its last boundary. */
static void compat_cache_phase(const char *phase,unsigned generation,unsigned item) {
  static uint64_t started_ns;
  static int started;
  const uint64_t now=edr_monotonic_ns();
  if(!started){started_ns=now;started=1;}
  compat_need(now>=started_ns,"diagnostic_monotonic_clock_regressed");
  /* Existing real monotonic owner; subtract before dividing to avoid overflow.
   * Integer milliseconds are rounded down and exclude process/argument setup. */
  const uint64_t elapsed_ms=(now-started_ns)/UINT64_C(1000000);
  fprintf(stderr,"storage_compat_cache phase=%s generation=%u item=%u elapsed_ms=%llu\n",
      phase,generation,item,(unsigned long long)elapsed_ms);
  fflush(stderr);
}

static cJSON *compat_cache_query_result(const char *out,const EdrBehaviorRecord *expected,int before_write) {
  cJSON *doc=cJSON_Parse(out);compat_need(doc!=NULL,"cache_query_json");
  cJSON *rows=cJSON_GetObjectItemCaseSensitive(doc,"rows");
  cJSON *scanned=cJSON_GetObjectItemCaseSensitive(doc,"rows_scanned");
  cJSON *returned=cJSON_GetObjectItemCaseSensitive(doc,"rows_returned");
  cJSON *partial=cJSON_GetObjectItemCaseSensitive(doc,"partial");
  compat_need(cJSON_IsArray(rows)&&cJSON_IsNumber(scanned)&&scanned->valuedouble>=0&&
      scanned->valuedouble==scanned->valueint&&cJSON_IsNumber(returned)&&
      returned->valuedouble==cJSON_GetArraySize(rows),"cache_query_observation");
  compat_need(cJSON_IsFalse(partial),"cache_partial");
  if(cJSON_GetArraySize(rows)==0) {
    if(!before_write||scanned->valueint>=COMPAT_CACHE_SCAN_BOUND)
      fprintf(stderr,"storage_compat_query expected_event_time_ns=%lld rows_scanned=%d rows_returned=%d query_limit=%d scan_bound=%d\n",
          (long long)expected->event_time_ns,scanned->valueint,returned->valueint,COMPAT_CACHE_QUERY_LIMIT,COMPAT_CACHE_SCAN_BOUND);
    /* The frozen owner bounds SQL before filtering identity. An empty bounded
     * scan cannot prove absence, especially before a potentially duplicate write. */
    compat_need(scanned->valueint<COMPAT_CACHE_SCAN_BOUND,
        before_write?"pre_write_query_scan_exhausted":"cache_query_scan_exhausted");
    compat_need(before_write,"cache_query_target_not_found");
  }
  compat_need(cJSON_GetArraySize(rows)==(before_write?0:1),
      before_write?"fixture_already_present":"cache_expected_one_row");
  return doc;
}

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
  compat_cache_phase("starting",0,0);
  /* No fixture clock, identity override or legacy schema switch is enabled. */
  compat_cache_phase("open_begin",0,0);
  compat_need(edr_local_evidence_cache_open_with_policy(argv[2],compat_max_mb,compat_retention,compat_selected)==0,"cache_owner_open");
  compat_cache_phase("open_end",0,0);
  edr_pt_cache_init();cJSON *records=cJSON_CreateArray(),*counterfactual=NULL;
  unsigned noise_records_written=0;
  if(strcmp(compat_stage,"read")) {
    unsigned generation=!strcmp(compat_stage,"append")?2u:1u;
    EdrBehaviorRecord *pending[2]={NULL,NULL};
    /* Establish absence for both fixtures before either owner write. */
    for(unsigned item=0;item<2u;item++) {
      EdrBehaviorRecord *r=calloc(1,sizeof(*r));compat_need(r!=NULL,"record_alloc");compat_record(r,generation,item);
      pending[item]=r;
      char filter[256],prior[32768];snprintf(filter,sizeof(filter),"{\"endpoint_id\":\"%s\",\"pid\":%u,\"limit\":%u,\"time_window_s\":3600}",compat_endpoint,r->pid,COMPAT_CACHE_QUERY_LIMIT);
      compat_cache_phase("query_begin",generation,item);
      compat_need(edr_local_evidence_cache_query_json(filter,prior,sizeof(prior))==0,"pre_write_query");
      compat_cache_phase("query_end",generation,item);
      cJSON *before=compat_cache_query_result(prior,r,1);cJSON_Delete(before);
    }
    for(unsigned item=0;item<2u;item++) {
      EdrBehaviorRecord *r=pending[item];
      EdrCommandFacts commands={r->cmdline,NULL};
      compat_need(edr_local_evidence_cache_record_alert_context(r,&commands)==0,"cache_owner_write");
      cJSON_AddItemToArray(records,compat_cache_facts(r));free(r);
    }
    if(!strcmp(compat_stage,"create")) {
      /* Only new standalone test DBs receive unrelated API-generated records.
       * Installed seed/append paths never inject these background fixtures. */
      for(unsigned item=0;item<COMPAT_CACHE_NOISE_RECORDS;item++) {
        EdrBehaviorRecord *r=calloc(1,sizeof(*r));compat_need(r!=NULL,"noise_record_alloc");compat_record(r,1u,item);
        r->pid=100000u+item;r->event_time_ns=compat_epoch*INT64_C(1000000000)+1000+(int64_t)item;
        snprintf(r->event_id,sizeof(r->event_id),"storage-noise-%u",item);
        EdrCommandFacts commands={r->cmdline,NULL};
        compat_need(edr_local_evidence_cache_record_alert_context(r,&commands)==0,"noise_owner_write");
        noise_records_written++;free(r);
      }
      compat_cache_phase("reopen_begin",0,0);
      edr_local_evidence_cache_close();
      compat_need(edr_local_evidence_cache_open_with_policy(argv[2],compat_max_mb,compat_retention,compat_selected)==0,"noise_owner_reopen");
      compat_cache_phase("reopen_end",0,0);
      char filter[256],out[32768];snprintf(filter,sizeof(filter),"{\"endpoint_id\":\"%s\",\"pid\":96010,\"limit\":10,\"time_window_s\":3600}",compat_endpoint);
      compat_cache_phase("noise_query_begin",0,0);
      compat_need(edr_local_evidence_cache_query_json(filter,out,sizeof(out))==0,"noise_counterfactual_query");
      compat_cache_phase("noise_query_end",0,0);
      counterfactual=cJSON_Parse(out);compat_need(counterfactual!=NULL,"noise_counterfactual_json");
      cJSON *rows=cJSON_GetObjectItemCaseSensitive(counterfactual,"rows");
      cJSON *scanned=cJSON_GetObjectItemCaseSensitive(counterfactual,"rows_scanned");
      compat_need(cJSON_IsArray(rows)&&cJSON_GetArraySize(rows)==0&&cJSON_IsNumber(scanned)&&
          scanned->valuedouble==300&&cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(counterfactual,"partial")),"noise_counterfactual_must_miss_target");
    }
  } else {
    /* This process never wrote records: a ring hit cannot satisfy the check. */
    for(unsigned generation=1u;generation<=compat_generations;generation++)for(unsigned item=0;item<2u;item++) {
      EdrBehaviorRecord *r=calloc(1,sizeof(*r));compat_need(r!=NULL,"record_alloc");compat_record(r,generation,item);
      char filter[512],out[32768];snprintf(filter,sizeof(filter),"{\"endpoint_id\":\"%s\",\"pid\":%u,\"process_start_key\":\"%llu\",\"process_creation_filetime_100ns\":\"%llu\",\"limit\":%u,\"time_window_s\":3600}",r->endpoint_id,r->pid,(unsigned long long)r->process_start_key,(unsigned long long)r->process_creation_filetime_100ns,COMPAT_CACHE_QUERY_LIMIT);
      compat_cache_phase("query_begin",generation,item);
      compat_need(edr_local_evidence_cache_query_json(filter,out,sizeof(out))==0,"cache_query");
      compat_cache_phase("query_end",generation,item);
      cJSON *doc=compat_cache_query_result(out,r,0);
      char exact_time[80];snprintf(exact_time,sizeof(exact_time),"\"event_time_ns\":%lld,",(long long)r->event_time_ns);
      compat_need(strstr(out,exact_time)!=NULL,"exact_persisted_event_time_ns");
      cJSON *rows=cJSON_GetObjectItemCaseSensitive(doc,"rows");
      cJSON *row=cJSON_GetArrayItem(rows,0),*expected=compat_cache_facts(r),*field=NULL;
      compat_equal(row,"source","p0_candidates");
      cJSON_ArrayForEach(field,expected) {cJSON *actual=cJSON_GetObjectItemCaseSensitive(row,field->string);compat_need(actual&&cJSON_Compare(actual,field,1),field->string);}
      cJSON_AddItemToArray(records,expected);cJSON_Delete(doc);free(r);
    }
  }
  compat_cache_phase("status_begin",0,0);
  EdrEvidenceCacheStatus status;edr_local_evidence_cache_get_status(&status);compat_need(status.db_open,"cache_db_open");
  compat_cache_phase("status_end",0,0);
  if(noise_records_written)compat_need(status.p0_candidate_rows==noise_records_written+2u,"noise_persisted_candidate_count");
  compat_cache_phase("close_begin",0,0);
  edr_local_evidence_cache_close();edr_pt_cache_shutdown();
  compat_cache_phase("close_end",0,0);
  cJSON *receipt=compat_receipt("evidence_cache",records);cJSON_AddNumberToObject(receipt,"storage_format",status.storage_format);
  cJSON_AddNumberToObject(receipt,"query_limit",COMPAT_CACHE_QUERY_LIMIT);
  cJSON_AddNumberToObject(receipt,"query_scan_bound",COMPAT_CACHE_SCAN_BOUND);
  cJSON_AddNumberToObject(receipt,"standalone_noise_records_written",noise_records_written);
  if(counterfactual)cJSON_AddItemToObject(receipt,"standalone_limit10_counterfactual",counterfactual);
  cJSON_AddBoolToObject(receipt,"read_from_reopened_sqlite",!strcmp(compat_stage,"read"));compat_print(receipt);return 0;
}
