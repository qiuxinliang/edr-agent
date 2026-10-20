/* Public synthetic diagnostics. No Agent/config/control/collector initialization. */
#include <sqlite3.h>
#include "edr/sha256.h"
#include "edr/behavior_proto.h"
#include "edr/policy_enforcement.h"
#include "edr/policy_v2.h"
#include "edr/p0_source_only_contract.h"
#include "retention_benchmark_support.h"
#include <sys/stat.h>
#ifndef EDR_DIAG_PUBLIC_UNIX_NS
#define EDR_DIAG_PUBLIC_UNIX_NS UINT64_C(1700000000000000000)
#endif
#ifndef EDR_DIAG_RULE_ENVELOPE_PATH
#error Explicit public fixture EDR1 bundle required
#endif
static unsigned diag_external_actions;
static int diag_missing_ir;
static void diag_deny_action(const EdrBehaviorRecord *r,EdrPolicyEnforcementResult *e){(void)r;diag_external_actions++;e->attempted=0;e->succeeded=0;snprintf(e->action,sizeof(e->action),"diagnostic_denied");}
static void diag_hex(const void *v,size_t n,char out[65]){EdrSha256Ctx h;uint8_t raw[32];edr_sha256_init(&h);edr_sha256_update(&h,v,n);edr_sha256_final(&h,raw);for(unsigned i=0;i<32;i++)snprintf(out+2*i,3,"%02x",raw[i]);}
static void diag_set_env(const char *k,const char *v){
#ifdef _WIN32
assert(!_putenv_s(k,v));
#else
assert(!setenv(k,v,1));
#endif
}
static void diag_copy_public_rule(void){FILE *in=fopen(EDR_DIAG_RULE_ENVELOPE_PATH,"rb");assert(in);FILE *out=fopen("rule.enc","wbx");assert(out);unsigned char buf[4096];size_t count=0,n;while((n=fread(buf,1,sizeof(buf),in))){assert(count+n<=4194336u);assert(fwrite(buf,1,n,out)==n);count+=n;}assert(feof(in)&&count);assert(!fclose(in));assert(!fclose(out));diag_set_env("EDR_P0_IR_PATH","rule.enc");diag_set_env("EDR_P0_PURPOSE_ARCHIVE_BASE","rule.enc");}
static uint64_t diag_scalar(sqlite3 *db,const char *sql){sqlite3_stmt *s=NULL;assert(sqlite3_prepare_v2(db,sql,-1,&s,NULL)==SQLITE_OK);assert(sqlite3_step(s)==SQLITE_ROW);uint64_t n=(uint64_t)sqlite3_column_int64(s,0);sqlite3_finalize(s);return n;}
static void diag_queue_owners(char ids[16][256],char hashes[16][65],unsigned *count,int compare){sqlite3 *db=NULL;sqlite3_stmt *s=NULL;assert(sqlite3_open_v2("queue.db",&db,SQLITE_OPEN_READONLY,NULL)==SQLITE_OK);if(!compare){assert(sqlite3_prepare_v2(db,"SELECT batch_id,payload FROM event_queue ORDER BY batch_id;",-1,&s,NULL)==SQLITE_OK);*count=0;int rc;while((rc=sqlite3_step(s))==SQLITE_ROW){assert(*count<16u);const char *id=(const char*)sqlite3_column_text(s,0);assert(id&&strlen(id)<256u);strcpy(ids[*count],id);diag_hex(sqlite3_column_blob(s,1),(size_t)sqlite3_column_bytes(s,1),hashes[*count]);(*count)++;}assert(rc==SQLITE_DONE);}else{assert(sqlite3_prepare_v2(db,"SELECT payload FROM event_queue WHERE batch_id=?;",-1,&s,NULL)==SQLITE_OK);for(unsigned i=0;i<*count;i++){sqlite3_reset(s);sqlite3_clear_bindings(s);assert(sqlite3_bind_text(s,1,ids[i],-1,SQLITE_STATIC)==SQLITE_OK);assert(sqlite3_step(s)==SQLITE_ROW);char sha[65];diag_hex(sqlite3_column_blob(s,0),(size_t)sqlite3_column_bytes(s,0),sha);assert(!strcmp(sha,hashes[i]));}}sqlite3_finalize(s);sqlite3_close(db);}
static int diag_worker16(void){
 const uint64_t begun=edr_monotonic_ns();assert(fopen("queue.db","rb")==NULL && fopen("evidence.db","rb")==NULL);
 if(diag_missing_ir){assert(fopen("absent-rule.enc","rb")==NULL);diag_set_env("EDR_P0_IR_PATH","absent-rule.enc");}else diag_copy_public_rule();diag_set_env("EDR_P0_DIRECT_EMIT","1");diag_set_env("EDR_P0_MAX_EMITS_PER_MIN","2000");diag_set_env("EDR_AUTO_RECOMMENDED_FORENSICS","0");
 edr_p0_rule_ir_lazy_init();int ir_ready=edr_p0_rule_ir_is_ready();assert(ir_ready==!diag_missing_ir);edr_p0_rule_register_projection_authority();
 retention_bench_vfs_parent=sqlite3_vfs_find(NULL);assert(retention_bench_vfs_parent);sqlite3_vfs v=*retention_bench_vfs_parent;v.zName="pipeline-private-real-io";v.pNext=NULL;v.szOsFile+=(int)sizeof(RetentionBenchFile);v.xOpen=retention_bench_open;assert(sqlite3_vfs_register(&v,1)==SQLITE_OK);
 assert(edr_local_evidence_cache_open_with_policy("evidence.db",16u,1u,1u)==0);edr_storage_queue_configure(16u,72u);assert(edr_storage_queue_open("queue.db")==EDR_OK);
 EdrConfig *cfg=calloc(1,sizeof(*cfg));assert(cfg);edr_config_apply_defaults(cfg);strcpy(cfg->agent.endpoint_id,"diag-public-endpoint");strcpy(cfg->agent.tenant_id,"diag-public-tenant");cfg->policy_v2.script_mode=EDR_POLICY_MODE_ALERT;edr_policy_v2_configure(cfg);edr_policy_enforcement_test_set_execute_hook(diag_deny_action);
 sync_agent_ids_from_cfg(cfg);edr_dedup_configure(1u,1000u);edr_dedup_init();edr_emit_rules_configure(cfg);edr_pt_cache_init();edr_process_coalescer_reset();assert(edr_process_evidence_worker_start());assert(edr_event_batch_init(1024u*1024u,100u,30)==EDR_OK);
 EdrEventBus *bus=edr_event_bus_create(32u);assert(bus);s_bus=bus;
 uint32_t pid=424242u,ppid=4u;uint64_t key=1000001u,ft=UINT64_C(116444736000000000)+EDR_DIAG_PUBLIC_UNIX_NS/100u;char image[4096]="C:\\PublicFixture\\diag-child.exe";
#ifdef _WIN32
 EdrLiveProcessGeneration live;char reason[96];HANDLE process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,GetCurrentProcessId());assert(process && process!=INVALID_HANDLE_VALUE);assert(edr_process_generation_query_live(process,&live,reason,sizeof(reason)));pid=live.pid;key=live.process_start_key;ft=live.creation_filetime_100ns;uint8_t state=0;assert(edr_process_parent_pid_query_live(process,&live,&ppid,&state,reason,sizeof(reason)));assert(edr_windows_process_image_path_utf8(process,image,sizeof(image)));assert(CloseHandle(process));
 EdrProcessEvidence initial_evidence;diag_enabled=1;int cold_ready=DIAG_INT(33,edr_process_evidence_request(image,key,edr_monotonic_ns(),&initial_evidence));diag_enabled=0;
 unsigned cold_reason=cold_ready?2u:!strcmp(initial_evidence.hash_reason,"queued")?1u:!strcmp(initial_evidence.hash_reason,"identity_revalidation_pending")?3u:0u;
 printf("{\"kind\":\"pipeline_diag_cold_request\",\"calls\":%llu,\"request_sync_ns\":%llu,\"ready\":%d,\"reason_enum\":%u,\"scope\":\"separate_component_first_request_not_loop\",\"async_hash_signature_timed\":false}\n",(unsigned long long)diag_metrics[33].calls,(unsigned long long)diag_metrics[33].total_ns,cold_ready,cold_reason);
 assert(diag_metrics[33].calls==1u);memset(diag_metrics,0,sizeof(diag_metrics));
#endif
 uint64_t birth=(ft-UINT64_C(116444736000000000))*100u;uint64_t observed_now=EDR_DIAG_PUBLIC_UNIX_NS;
#ifdef _WIN32
FILETIME observed_ft;GetSystemTimeAsFileTime(&observed_ft);observed_now=((((uint64_t)observed_ft.dwHighDateTime<<32u)|observed_ft.dwLowDateTime)-UINT64_C(116444736000000000))*100u;
#endif
EdrSha256Ctx offered;edr_sha256_init(&offered);
 for(unsigned i=0;i<16u;i++){EdrEventSlot slot={0};slot.type=(i%4u)==0u?EDR_EVENT_PROCESS_CREATE:(i%4u)==1u?EDR_EVENT_NET_CONNECT:(i%4u)==2u?EDR_EVENT_FILE_WRITE:EDR_EVENT_FILE_READ;slot.priority=3u;slot.p0_critical=1u;slot.timestamp_ns=(slot.type==EDR_EVENT_PROCESS_CREATE?birth:observed_now)+i;int n=snprintf((char*)slot.data,sizeof(slot.data),"ETW1\nprov=%s\npid=%u\nppid=%u\nimg=%s\nprocess_start_key=%llu\nprocess_creation_filetime_100ns=%llu\ndst=192.0.2.1\ndport=443\nfile=C:\\PublicFixture\\ordinary.txt\nfile_key=1\n",(slot.type==EDR_EVENT_FILE_READ||slot.type==EDR_EVENT_FILE_WRITE)?"kfile":slot.type==EDR_EVENT_NET_CONNECT?"tcpip":"kproc",pid,ppid,image,(unsigned long long)key,(unsigned long long)ft);assert(n>0&&(size_t)n<sizeof(slot.data));slot.size=(uint32_t)n;edr_sha256_update(&offered,(const uint8_t*)&slot,sizeof(slot));assert(edr_event_bus_try_push(bus,&slot));}
 /* One true local-v3 source-only durable owner, separately timed before drain. */
 EdrBehaviorRecord *seed=calloc(1,sizeof(*seed));assert(seed);edr_behavior_record_init(seed);seed->type=EDR_EVENT_PROCESS_CREATE;seed->pid=pid;seed->ppid=ppid;seed->priority=0;seed->process_start_key=key;seed->process_creation_filetime_100ns=ft;seed->event_time_ns=(int64_t)birth;strcpy(seed->event_id,"diag-public-necessary-source");strcpy(seed->endpoint_id,cfg->agent.endpoint_id);strcpy(seed->tenant_id,cfg->agent.tenant_id);strcpy(seed->process_name,"diag-public.exe");strcpy(seed->exe_path,image);
 p0_mark_not_evaluable(seed,"process_generation_or_correlation_unavailable");
 diag_enabled=1;int seeded=edr_p0_rule_emit_pre_evaluation_gate(seed,"process_generation_or_correlation_unavailable");diag_enabled=0;assert(seeded==1);free(seed);
 for(unsigned i=1;i<39;i++)if(diag_metrics[i].calls)printf("{\"kind\":\"pipeline_diag_seed_stage\",\"stage\":%u,\"calls\":%llu,\"inclusive_total_ns\":%llu,\"max_ns\":%llu}\n",i,(unsigned long long)diag_metrics[i].calls,(unsigned long long)diag_metrics[i].total_ns,(unsigned long long)diag_metrics[i].max_ns);
 memset(diag_metrics,0,sizeof(diag_metrics));
 uint8_t offered_sha_raw[32];char offered_sha[65];edr_sha256_final(&offered,offered_sha_raw);for(unsigned j=0;j<32u;j++)snprintf(offered_sha+2*j,3,"%02x",offered_sha_raw[j]);
 char owner_ids[16][256],owner_hashes[16][65];unsigned owner_count=0;diag_queue_owners(owner_ids,owner_hashes,&owner_count,0);assert(owner_count>0);
 assert(fflush(stdout)==0);
 uint64_t read0=retention_bench_reads,write0=retention_bench_writes,sync0=retention_bench_syncs;uint64_t started=edr_monotonic_ns();atomic_store(&s_stop_preprocess,1);atomic_store(&s_preprocess_exited,0);diag_enabled=1;
#ifdef _WIN32
 assert(preprocess_main(NULL)==0);
#else
 assert(preprocess_main(NULL)==NULL);
#endif
 diag_enabled=0;uint64_t elapsed=edr_monotonic_ns()-started;assert(!diag_depth && atomic_load(&s_preprocess_exited));
#ifdef _WIN32
 assert(diag_metrics[27].calls>0u && diag_metrics[28].calls>0u && diag_metrics[7].calls>0u && diag_metrics[8].calls>0u);
#endif
assert(edr_event_bus_used_approx(bus)==0u);assert(atomic_load(&s_worker_completed_slots)==16u);diag_queue_owners(owner_ids,owner_hashes,&owner_count,1);assert(!diag_external_actions);EdrStorageQueueCapacityMetrics metrics;edr_storage_queue_get_capacity_metrics(&metrics);assert(metrics.accounting_available);
 printf("{\"kind\":\"pipeline_diag_drain_end\",\"slots\":16,\"input_sha256\":\"%s\",\"stop_set_before_worker\":true,\"loop_returned\":true,\"completed_slots\":%llu,\"completed_loops\":%llu,\"elapsed_ns\":%llu,\"vfs_read_bytes\":%llu,\"vfs_write_bytes\":%llu,\"vfs_syncs\":%llu,\"necessary_source_owners_seeded\":%u,\"necessary_source_bytes_unchanged\":true,\"all_input_dispositions_verified\":false,\"source_ack_inferred\":false,\"real_ir_ready\":%s,\"real_sqlite\":true,\"process_evidence_worker_start_api_ok\":true,\"process_evidence_worker_windows_thread_started\":%s,\"actions_observed\":%u,\"network_transport_initialized\":false,\"ave_initialized\":false,\"incoming_slot_type_only\":true,\"timings_inclusive\":true,\"win_actor_branch_compiled\":%s}\n",offered_sha,(unsigned long long)atomic_load(&s_worker_completed_slots),(unsigned long long)atomic_load(&s_worker_completed_loops),(unsigned long long)elapsed,(unsigned long long)(retention_bench_reads-read0),(unsigned long long)(retention_bench_writes-write0),(unsigned long long)(retention_bench_syncs-sync0),owner_count,ir_ready?"true":"false",
#ifdef _WIN32
 "true",
#else
 "false",
#endif
 diag_external_actions,
#ifdef _WIN32
 "true"
#else
 "false"
#endif
 );
 for(unsigned i=1;i<39;i++)printf("{\"kind\":\"pipeline_diag_stage\",\"stage\":%u,\"calls\":%llu,\"inclusive_total_ns\":%llu,\"max_ns\":%llu}\n",i,(unsigned long long)diag_metrics[i].calls,(unsigned long long)diag_metrics[i].total_ns,(unsigned long long)diag_metrics[i].max_ns);
 assert(edr_event_batch_shutdown()==0);edr_process_evidence_worker_stop();
#ifdef _WIN32
 EdrProcessEvidenceMetrics stopped_metrics={0};edr_process_evidence_worker_get_metrics(&stopped_metrics);
 printf("{\"kind\":\"pipeline_diag_evidence_stop\",\"shutdown_timeouts\":%llu,\"terminal_unhealthy\":%u,\"slots_used\":%u}\n",(unsigned long long)stopped_metrics.shutdown_timeouts,(unsigned)stopped_metrics.terminal_unhealthy,(unsigned)stopped_metrics.slots_used);
 assert(fflush(stdout)==0);
 assert(!stopped_metrics.shutdown_timeouts && !stopped_metrics.terminal_unhealthy && !stopped_metrics.slots_used);
#endif
 edr_local_evidence_cache_close();edr_storage_queue_close();edr_event_bus_destroy(bus);edr_pt_cache_shutdown();edr_p0_rule_ir_shutdown();free(cfg);assert(edr_monotonic_ns()-begun<UINT64_C(90000000000));puts("{\"kind\":\"pipeline_diag_worker_complete\",\"cleanup_returned\":true}");return 0;
}
#ifdef _WIN32
#include "windows_parent.inc"
#endif
int main(int argc,char **argv){
#ifdef _WIN32
 if(argc==1)return diag_windows_supervise();if(argc==2&&!strcmp(argv[1],"--worker16-ready"))return diag_worker16();if(argc==2&&!strcmp(argv[1],"--worker16-missing")){diag_missing_ir=1;return diag_worker16();}return 2;
#else
 if(argc==1)return diag_worker16();if(argc==2&&!strcmp(argv[1],"--ir-missing")){diag_missing_ir=1;return diag_worker16();}return 2;
#endif
}
