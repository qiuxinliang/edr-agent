/* Counterfactual storage experiment. No sensor, rule engine, network or live DB.
 * Expected actions below are authored before observing the cache response. */
#define main inherited_retention_main
#include "evidence_retention_comparison.c"
#undef main

static const int64_t demand_base = INT64_C(1793100000000000000);
static void demand_clock(int64_t stamp) {
  edr_local_evidence_cache_test_set_now_unix_ns(stamp);
  s_test_monotonic_ns = UINT64_C(1000000000) + (uint64_t)(stamp-demand_base);
  benchmark_sync_retention_clock();
}
static void demand_record(EdrBehaviorRecord *r, const char *id, const char *file,
                          int64_t offset) {
  init_record(r, EDR_EVENT_FILE_WRITE);
  r->pid=97000;set_record_generation(r,97000);
  snprintf(r->tenant_id,sizeof(r->tenant_id),"demand-tenant");
  snprintf(r->endpoint_id,sizeof(r->endpoint_id),"demand-endpoint");
  snprintf(r->process_name,sizeof(r->process_name),"validation.exe");
  snprintf(r->exe_path,sizeof(r->exe_path),"C:\\Validation\\validation.exe");
  snprintf(r->source_completeness,sizeof(r->source_completeness),"COMPLETE");
  snprintf(r->event_id,sizeof(r->event_id),"%s",id);
  snprintf(r->file_path,sizeof(r->file_path),"C:\\UserData\\%s",file);
  r->event_time_ns=demand_base+offset;r->file_key=(uint64_t)(offset+2000000000LL);
}
static void demand_write(EdrBehaviorRecord *r) {
  benchmark_input(r);edr_local_evidence_cache_record_behavior(r);
}
static cJSON *demand_query(int64_t stamp,const char *scope,const char *extra,const char *label) {
  EdrSoarCommandMeta meta={0};char out[16384];
  meta.issued_at_unix_ms=stamp/1000000;meta.deadline_ms=60000;
  EdrCommandResultAuthorization *a=&meta.result_authorization;
  strcpy(a->command_id,"demand-query");strcpy(a->command_type,"rtq_query");
  snprintf(a->tenant_id,sizeof(a->tenant_id),"%s",scope);strcpy(a->endpoint_id,"demand-endpoint");
  a->expires_unix_ms=meta.issued_at_unix_ms+60000;
  snprintf(a->content_contract,sizeof(a->content_contract),
    "{\"schema\":\"edr.command.result-purpose.v1\",\"kind\":\"cached_rtq\",\"max_bytes\":16383,"
    "\"max_rows\":50,\"window_s\":21600,\"issued_unix_ms\":%lld,\"request\":{"
    "\"time_window_s\":21600,\"event_type\":\"file_write\"%s}}",(long long)meta.issued_at_unix_ms,extra);
  int rc=edr_local_evidence_cache_query_authorized_json(a->command_id,&meta,out,sizeof(out));
  if(rc)fprintf(stderr,"query %s failed: %s\n",label,out);
  assert(rc==0);cJSON *root=cJSON_Parse(out);assert(root);
  assert(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(root,"absence_is_evidence")));
  char path[96];snprintf(path,sizeof(path),"query-%s.json",label);
  FILE *f=fopen(path,"wx");assert(f);assert(fwrite(out,1,strlen(out),f)==strlen(out));assert(fclose(f)==0);
  return root;
}
static int demand_count(cJSON *root,const char *expected_path) {
  const cJSON *row=NULL,*rows=cJSON_GetObjectItemCaseSensitive(root,"rows");int count=0;
  cJSON_ArrayForEach(row,rows) {
    const cJSON *p=cJSON_GetObjectItemCaseSensitive(row,"file_path");
    if(cJSON_IsString(p) && !strcmp(p->valuestring,expected_path))++count;
  }
  return count;
}
static void demand_check(cJSON *checks,const char *stage,const char *fact,int expected,int actual) {
  cJSON *v=cJSON_CreateObject();assert(v);
  cJSON_AddStringToObject(v,"stage",stage);cJSON_AddStringToObject(v,"fact",fact);
  cJSON_AddNumberToObject(v,"expected",expected);cJSON_AddNumberToObject(v,"actual",actual);
  cJSON_AddBoolToObject(v,"pass",expected==actual);cJSON_AddItemToArray(checks,v);
}
static void demand_facts(cJSON *checks,cJSON *root,const char *stage,int has_anchor) {
  demand_check(checks,stage,"required-pre.bin",1,demand_count(root,"C:\\UserData\\required-pre.bin"));
  if(has_anchor)demand_check(checks,stage,"required-anchor.exe",1,demand_count(root,"C:\\Temp\\required-anchor.exe"));
  demand_check(checks,stage,"required-post.bin independent occurrences",2,demand_count(root,"C:\\UserData\\required-post.bin"));
  const cJSON *row=NULL,*rows=cJSON_GetObjectItemCaseSensitive(root,"rows");
  int bad=0,post_times=0;
  cJSON_ArrayForEach(row,rows) {
    const cJSON *pid=cJSON_GetObjectItemCaseSensitive(row,"pid"),
      *type=cJSON_GetObjectItemCaseSensitive(row,"type"),
      *endpoint=cJSON_GetObjectItemCaseSensitive(row,"endpoint_id"),
      *key=cJSON_GetObjectItemCaseSensitive(row,"process_start_key"),
      *birth=cJSON_GetObjectItemCaseSensitive(row,"process_creation_filetime_100ns"),
      *stamp=cJSON_GetObjectItemCaseSensitive(row,"event_time_ns"),
      *path=cJSON_GetObjectItemCaseSensitive(row,"file_path");
    if(!cJSON_IsNumber(pid)||pid->valueint!=97000||!cJSON_IsNumber(type)||type->valueint!=EDR_EVENT_FILE_WRITE||
       !cJSON_IsString(endpoint)||strcmp(endpoint->valuestring,"demand-endpoint")||
       !cJSON_IsString(key)||strcmp(key->valuestring,"97000")||
       !cJSON_IsString(birth)||strcmp(birth->valuestring,"133700000000097000")||
       !cJSON_IsNumber(stamp)||!cJSON_IsString(path)) {++bad;continue;}
    /* These actions are 1 ms apart. This does not claim end-to-end ns precision. */
    if(!strcmp(path->valuestring,"C:\\UserData\\required-post.bin")) {
      if(stamp->valuedouble==(double)(demand_base+INT64_C(1000000000)))post_times|=1;
      else if(stamp->valuedouble==(double)(demand_base+INT64_C(1001000000)))post_times|=2;
      else ++bad;
    } else if(!strcmp(path->valuestring,"C:\\UserData\\required-pre.bin") &&
              stamp->valuedouble!=(double)(demand_base-INT64_C(1000000000))) ++bad;
    else if(!strcmp(path->valuestring,"C:\\Temp\\required-anchor.exe") && stamp->valuedouble!=(double)demand_base) ++bad;
    else if(!strcmp(path->valuestring,"C:\\Temp\\second-anchor.exe") &&
            stamp->valuedouble!=(double)(demand_base+INT64_C(100000000))) ++bad;
    else if(strcmp(path->valuestring,"C:\\UserData\\required-pre.bin") &&
            strcmp(path->valuestring,"C:\\UserData\\required-post.bin") &&
            strcmp(path->valuestring,"C:\\Temp\\required-anchor.exe") &&
            strcmp(path->valuestring,"C:\\Temp\\second-anchor.exe")) ++bad;
  }
  demand_check(checks,stage,"returned identity/type/time field violations",0,bad);
  demand_check(checks,stage,"post action times present bitmask",3,post_times);
}
int main(int argc,char **argv) {
  assert(argc==4);const char *scene=argv[1];unsigned selected=(unsigned)atoi(argv[2]);
  unsigned delay_minutes=(unsigned)atoi(argv[3]);
  assert(selected>=1 && selected<=4 && delay_minutes<=300);
  int strong=!strcmp(scene,"priority_anchor"),network=!strcmp(scene,"network_anchor"),
      no_anchor=!strcmp(scene,"no_anchor"),shared=!strcmp(scene,"shared_anchor"),
      replay=!strcmp(scene,"replay_anchor");
  assert(strong||network||no_anchor||shared||replay||!strcmp(scene,"file_anchor"));
  const char *path="evidence.db",*queue="queue.db";
  struct stat st;assert(stat(path,&st)!=0 && stat(queue,&st)!=0);
  edr_sha256_init(&benchmark_input_hash);benchmark_input_bytes=0;
  retention_bench_vfs_parent=sqlite3_vfs_find(NULL);assert(retention_bench_vfs_parent);
  sqlite3_vfs vfs=*retention_bench_vfs_parent;vfs.zName="demand-experiment";vfs.pNext=NULL;
  vfs.szOsFile+=(int)sizeof(RetentionBenchFile);vfs.xOpen=retention_bench_open;
  assert(sqlite3_vfs_register(&vfs,1)==SQLITE_OK);
  retention_bench_reads=retention_bench_writes=retention_bench_syncs=0;
  demand_clock(demand_base);edr_pt_cache_init();edr_storage_queue_configure(16,1);
  assert(edr_storage_queue_open(queue)==EDR_OK);
  assert(edr_local_evidence_cache_open_with_policy(path,16,1,selected)==0);
  RetentionBenchMetrics begin=retention_bench_metrics();
  EdrBehaviorRecord r,owner;demand_record(&r,"pre","required-pre.bin",-INT64_C(1000000000));demand_write(&r);
  demand_record(&owner,"anchor","required-anchor.exe",0);
  /* A non-priority executable drop in a staging path is an actual existing
   * policy candidate. An .exe suffix in arbitrary UserData alone is not. */
  strcpy(owner.file_path,"C:\\Temp\\required-anchor.exe");
  if(strong)strcpy(owner.detection_context,"{\"priority\":\"P1\"}");
  if(network){owner.type=EDR_EVENT_NET_CONNECT;owner.net_dport=445;strcpy(owner.net_dst,"192.0.2.40");owner.file_path[0]=0;}
  int requested_candidate=edr_local_evidence_cache_is_candidate(&owner);
  if(!no_anchor)demand_write(&owner);
  if(shared){EdrBehaviorRecord other=owner;strcpy(other.event_id,"second-anchor");strcpy(other.file_path,"C:\\Temp\\second-anchor.exe");other.event_time_ns+=100000000;demand_write(&other);}
  if(replay)demand_write(&owner);
  demand_record(&r,"post-one","required-post.bin",INT64_C(1000000000));demand_write(&r);
  demand_record(&r,"post-two","required-post.bin",INT64_C(1001000000));demand_write(&r);
  RetentionBenchMetrics produced=retention_bench_metrics();
  uint64_t producer_writes=retention_bench_writes,producer_syncs=retention_bench_syncs;
  edr_local_evidence_cache_close();edr_pt_cache_shutdown();
  sqlite3 *initial_db=NULL;assert(sqlite3_open(path,&initial_db)==SQLITE_OK);
  int64_t initial_candidates=compact_scalar(initial_db,"SELECT COUNT(*) FROM p0_candidates"),
    initial_class2=compact_scalar(initial_db,"SELECT COUNT(*) FROM p0_candidates WHERE retention_value_class=2"),
    initial_refs=compact_scalar(initial_db,"SELECT COUNT(*) FROM context_reference_projection");
  sqlite3_close(initial_db);
  demand_clock(demand_base+INT64_C(2000000000));
  assert(edr_local_evidence_cache_open_with_policy(path,16,1,selected)==0);
  cJSON *result=cJSON_CreateObject(),*checks=cJSON_AddArrayToObject(result,"checks");assert(result&&checks);
  cJSON_AddStringToObject(result,"scene",scene);cJSON_AddNumberToObject(result,"selected_hours",selected);
  cJSON_AddStringToObject(result,"sqlite_version",sqlite3_libversion());
  cJSON_AddNumberToObject(result,"delay_minutes",delay_minutes);cJSON_AddBoolToObject(result,"anchor_candidate",requested_candidate);
  cJSON_AddNumberToObject(result,"initial_candidate_rows",initial_candidates);
  cJSON_AddNumberToObject(result,"initial_class2_rows",initial_class2);
  cJSON_AddNumberToObject(result,"initial_reference_rows",initial_refs);
  cJSON *q=demand_query(demand_base+INT64_C(2000000000),"demand-tenant","","reopened");
  demand_facts(checks,q,"reopened",!network&&!no_anchor);cJSON_Delete(q);
  q=demand_query(demand_base+INT64_C(2000000000),"wrong-tenant","","wrong-scope");
  demand_check(checks,"isolation","wrong tenant rows",0,cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(q,"rows")));cJSON_Delete(q);
  q=demand_query(demand_base+INT64_C(2000000000),"demand-tenant",",\"pid\":97000,\"process_start_key\":\"97001\"","wrong-generation");
  demand_check(checks,"isolation","wrong generation rows",0,cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(q,"rows")));cJSON_Delete(q);
  for(unsigned minute=1;minute<=delay_minutes;++minute){demand_clock(demand_base+(int64_t)minute*60000000000LL);edr_local_evidence_cache_poll_maintenance();}
  if(delay_minutes){int64_t now=demand_base+(int64_t)delay_minutes*60000000000LL;
    edr_local_evidence_cache_close();assert(edr_local_evidence_cache_open_with_policy(path,16,1,selected)==0);
    q=demand_query(now,"demand-tenant","","delayed");demand_facts(checks,q,"delayed",!network&&!no_anchor);cJSON_Delete(q);}
  EdrEvidenceCacheStatus status;edr_local_evidence_cache_get_status(&status);edr_local_evidence_cache_close();edr_storage_queue_close();
  sqlite3 *db=NULL;assert(sqlite3_open(path,&db)==SQLITE_OK);
  cJSON_AddNumberToObject(result,"candidate_rows",compact_scalar(db,"SELECT COUNT(*) FROM p0_candidates"));
  cJSON_AddNumberToObject(result,"class2_rows",compact_scalar(db,"SELECT COUNT(*) FROM p0_candidates WHERE retention_value_class=2"));
  cJSON_AddNumberToObject(result,"reference_rows",compact_scalar(db,"SELECT COUNT(*) FROM context_reference_projection"));
  /* A broken compact integer key is hidden by the projection's inner join. */
  int64_t legacy_refs=0,compact_refs=0;
  int64_t dangling=retention_reference_errors(db,&legacy_refs,&compact_refs);
  cJSON_AddNumberToObject(result,"legacy_refs",legacy_refs);
  cJSON_AddNumberToObject(result,"compact_refs",compact_refs);
  demand_check(checks,"integrity","projection versus physical refs",(int)(legacy_refs+compact_refs),
      (int)compact_scalar(db,"SELECT COUNT(*) FROM context_reference_projection"));
  demand_check(checks,"integrity","all-layout dangling references",0,(int)dangling);
  sqlite3_close(db);
  uint8_t hash[32];char digest[65];edr_sha256_final(&benchmark_input_hash,hash);
  for(unsigned i=0;i<32;++i)snprintf(digest+2*i,3,"%02x",hash[i]);
  cJSON_AddStringToObject(result,"input_sha256",digest);cJSON_AddNumberToObject(result,"input_bytes",benchmark_input_bytes);
  cJSON_AddNumberToObject(result,"startup_plus_producer_sqlite_write_bytes",producer_writes);
  cJSON_AddNumberToObject(result,"startup_plus_producer_sqlite_syncs",producer_syncs);
  cJSON_AddNumberToObject(result,"producer_cpu_seconds",produced.user_seconds+produced.system_seconds-begin.user_seconds-begin.system_seconds);
  cJSON_AddNumberToObject(result,"all_phases_sqlite_write_bytes",retention_bench_writes);
  cJSON_AddNumberToObject(result,"all_phases_sqlite_syncs",retention_bench_syncs);
  cJSON_AddNumberToObject(result,"final_db_bytes",benchmark_physical_bytes(path)+benchmark_physical_bytes(queue));
  cJSON_AddNumberToObject(result,"candidate_rejected",status.candidate_rejected);
  char *encoded=cJSON_PrintUnformatted(result);assert(encoded);puts(encoded);cJSON_free(encoded);cJSON_Delete(result);
  assert(sqlite3_vfs_register(retention_bench_vfs_parent,1)==SQLITE_OK);assert(sqlite3_vfs_unregister(&vfs)==SQLITE_OK);
  return 0; /* A failed policy hypothesis is data; runner labels it FAIL. */
}
