/* Fixed-input, same-policy cost comparison. No transport or live endpoint data.
 * Reuse the established clock, codec, VFS and process metrics boundaries. */
#define main historical_retention_comparison_main
#include "evidence_retention_comparison.c"
#undef main
#ifdef BENCH_HAS_STORAGE_RESERVATION
#include "edr/storage_reservation.h"
#endif

static int cost_double_compare(const void *a, const void *b) {
  double x=*(const double *)a,y=*(const double *)b;
  return (x>y)-(x<y);
}
static double cost_percentile(double *samples, unsigned count, unsigned pct) {
  assert(count && pct<=100);
  qsort(samples,count,sizeof(*samples),cost_double_compare);
  unsigned index=(count*pct+99u)/100u;
  return samples[(index?index:1u)-1u];
}
static double cost_now(void) { return retention_bench_metrics().wall_seconds; }
typedef struct { uint64_t reads, writes, syncs; } CostIoSnapshot;
static CostIoSnapshot cost_io_snapshot(void) {
  CostIoSnapshot value={retention_bench_reads,retention_bench_writes,retention_bench_syncs};
  return value;
}
static CostIoSnapshot cost_io_difference(CostIoSnapshot end, CostIoSnapshot begin) {
  CostIoSnapshot value={end.reads-begin.reads,end.writes-begin.writes,end.syncs-begin.syncs};
  return value;
}

static void cost_hash_column(EdrSha256Ctx *hash, sqlite3_stmt *st, int column) {
  int n=sqlite3_column_bytes(st,column);
  const unsigned char *value=sqlite3_column_text(st,column);
  assert(n>=0 && value);
  unsigned char length[8]; uint64_t bytes=(uint64_t)n;
  for(unsigned i=0;i<8u;++i)length[i]=(unsigned char)(bytes>>(56u-8u*i));
  edr_sha256_update(hash,length,sizeof(length));
  edr_sha256_update(hash,value,(size_t)n);
}

/* Normalize historical and compact layouts before comparing owner/fact
 * attribution. Counting only the legacy table silently measured zero compact
 * edges. Compare post-context owner/fact attribution independently of layout,
 * and report the full physical reference count separately. */
static int64_t cost_context_inventory(sqlite3 *db, int64_t *references,
                                      int64_t *dangling, char digest[65]) {
  const char *relation=compact_scalar(db,"SELECT COUNT(*) FROM sqlite_master WHERE type='view' AND name='context_reference_projection'")
      ? "context_reference_projection" : "candidate_context_refs";
  char sql[768];
  snprintf(sql,sizeof(sql),"SELECT COUNT(*) FROM %s",relation);
  *references=compact_scalar(db,sql);
  int64_t physical_refs=compact_scalar(db,"SELECT COUNT(*) FROM candidate_context_refs");
  if(compact_scalar(db,"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='compact_context_refs'"))
    physical_refs+=compact_scalar(db,"SELECT COUNT(*) FROM compact_context_refs");
  assert(*references==physical_refs);
  snprintf(sql,sizeof(sql),"SELECT COUNT(*) FROM %s r LEFT JOIN p0_candidates p ON p.candidate_id=r.candidate_id "
      "LEFT JOIN context_facts f ON f.fact_id=r.fact_id WHERE p.candidate_id IS NULL OR f.fact_id IS NULL",relation);
  *dangling=compact_scalar(db,sql);
  snprintf(sql,sizeof(sql),"SELECT r.candidate_id,f.manifest_template_json FROM %s r "
      "JOIN context_facts f ON f.fact_id=r.fact_id WHERE json_extract(f.manifest_template_json,'$.schema')='p0_post_context_event.v1' "
      "ORDER BY r.candidate_id,f.fact_id",relation);
  sqlite3_stmt *st=NULL; assert(sqlite3_prepare_v2(db,sql,-1,&st,NULL)==SQLITE_OK);
  EdrSha256Ctx hash; edr_sha256_init(&hash); int64_t rows=0; int rc;
  while((rc=sqlite3_step(st))==SQLITE_ROW) {
    cost_hash_column(&hash,st,0); cost_hash_column(&hash,st,1); ++rows;
  }
  assert(rc==SQLITE_DONE); sqlite3_finalize(st);
  uint8_t value[32]; edr_sha256_final(&hash,value);
  for(unsigned i=0;i<32u;++i)snprintf(digest+2u*i,3,"%02x",value[i]);
  return rows;
}

int main(int argc, char **argv) {
  assert(argc==2);
  const char *profile=argv[1];
  int ordinary=!strcmp(profile,"ordinary"), replay=!strcmp(profile,"replay"),
      fanout=!strcmp(profile,"fanout"), unique=!strcmp(profile,"unique");
  assert(ordinary || replay || fanout || unique);
  const int64_t now=INT64_C(1700000000000000000);
  const unsigned inputs=ordinary?50000u:512u,queries=64;
  double *entry=calloc(inputs,sizeof(*entry)),query[64];assert(entry);
  char path[512],queue_path[512],output[16384];
  assert(make_test_sqlite_path(path,sizeof(path))==0);
  assert(make_test_sqlite_path(queue_path,sizeof(queue_path))==0);
  retention_bench_vfs_parent=sqlite3_vfs_find(NULL);assert(retention_bench_vfs_parent);
  sqlite3_vfs vfs=*retention_bench_vfs_parent;
  vfs.zName="evidence-cost-comparison";vfs.pNext=NULL;
  vfs.szOsFile+=(int)sizeof(RetentionBenchFile);vfs.xOpen=retention_bench_open;
  assert(sqlite3_vfs_register(&vfs,1)==SQLITE_OK);
  edr_local_evidence_cache_test_set_now_unix_ns(now);
  benchmark_sync_retention_clock();
  edr_sha256_init(&benchmark_input_hash);benchmark_input_bytes=0;
  retention_bench_reads=retention_bench_writes=retention_bench_syncs=0;
  EdrBehaviorRecord *r=calloc(1,sizeof(*r));assert(r);
  /* Production startup attaches the existing owner lock before writers.
   * Include the real mapped-zero read in current hot paths, not the unattached
   * test fallback. Startup mapping is outside the producer/query timer. */
#ifdef BENCH_HAS_STORAGE_RESERVATION
  FILE *reservation=fopen("synthetic-owner.lock","w+b");assert(reservation);
  assert(edr_storage_reservation_attach(fileno(reservation),"synthetic-owner.lock")==0);
  edr_storage_reservation_publish(0);
#endif
  RetentionBenchMetrics started=retention_bench_metrics();
  edr_storage_queue_configure(8,1);
  assert(edr_storage_queue_open(queue_path)==EDR_OK);
  assert(edr_local_evidence_cache_open_with_policy(path,8,1,1)==0);
  CostIoSnapshot startup_io=cost_io_snapshot();
  RetentionBenchMetrics producer_start=retention_bench_metrics();
  uint64_t physical_peak=0;
  for(unsigned i=0;i<inputs;++i) {
    init_record(r,EDR_EVENT_NET_CONNECT);
    r->pid=(replay||fanout)?4242u:4242u+i;
    set_record_generation(r,r->pid);
    r->priority=ordinary || (fanout && i>=32)?1:3;
    r->net_dport=r->priority==1?80:445;
    r->event_time_ns=now+(replay?0:(int64_t)i*1000000);
    strcpy(r->endpoint_id,"cost-endpoint");strcpy(r->tenant_id,"cost-tenant");
    strcpy(r->process_name,"cost-fixture.exe");strcpy(r->net_dst,"192.0.2.1");
    strcpy(r->source_completeness,"COMPLETE");
    snprintf(r->event_id,sizeof(r->event_id),"cost-source-%u",replay?0:i);
    benchmark_input(r);
    double begin=cost_now();edr_local_evidence_cache_record_behavior(r);
    entry[i]=(cost_now()-begin)*1000000.0;
    uint64_t bytes=benchmark_physical_bytes(path)+benchmark_physical_bytes(queue_path);
    if(bytes>physical_peak)physical_peak=bytes;
  }
  RetentionBenchMetrics producer_end=retention_bench_metrics();
  CostIoSnapshot producer_io_end=cost_io_snapshot();
  EdrSoarCommandMeta meta={0};meta.issued_at_unix_ms=now/1000000LL;meta.deadline_ms=60000;
  EdrCommandResultAuthorization *auth=&meta.result_authorization;
  strcpy(auth->command_id,"cost-recall");strcpy(auth->command_type,"rtq_query");
  strcpy(auth->tenant_id,"cost-tenant");strcpy(auth->endpoint_id,"cost-endpoint");
  auth->expires_unix_ms=meta.issued_at_unix_ms+60000;
  snprintf(auth->content_contract,sizeof(auth->content_contract),
      "{\"schema\":\"edr.command.result-purpose.v1\",\"kind\":\"cached_rtq\",\"max_bytes\":16383,"
      "\"max_rows\":50,\"window_s\":600,\"issued_unix_ms\":%lld,\"request\":{}}",
      (long long)meta.issued_at_unix_ms);
  unsigned rows=0;size_t response_bytes=0;
  for(unsigned i=0;i<queries;++i) {
    double begin=cost_now();
    assert(edr_local_evidence_cache_query_authorized_json(auth->command_id,&meta,output,sizeof(output))==0);
    query[i]=(cost_now()-begin)*1000000.0;
    response_bytes=strlen(output);
    cJSON *root=cJSON_Parse(output);assert(root);
    rows=(unsigned)cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(root,"rows"));
    assert(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(root,"absence_is_evidence")));
    cJSON_Delete(root);
  }
  CostIoSnapshot recall_io_end=cost_io_snapshot();
  EdrEvidenceCacheStatus status;edr_local_evidence_cache_get_status(&status);
  edr_local_evidence_cache_close();edr_storage_queue_close();
  RetentionBenchMetrics finished=retention_bench_metrics();
  uint64_t reads=retention_bench_reads,writes=retention_bench_writes,syncs=retention_bench_syncs;
  CostIoSnapshot total_io={reads,writes,syncs};
  CostIoSnapshot producer_io=cost_io_difference(producer_io_end,startup_io);
  CostIoSnapshot recall_io=cost_io_difference(recall_io_end,producer_io_end);
  CostIoSnapshot close_io=cost_io_difference(total_io,recall_io_end);
  sqlite3 *db=NULL;assert(sqlite3_open(path,&db)==SQLITE_OK);
  sqlite3_stmt *check=NULL;assert(sqlite3_prepare_v2(db,"PRAGMA integrity_check",-1,&check,NULL)==SQLITE_OK);
  assert(sqlite3_step(check)==SQLITE_ROW && !strcmp((const char *)sqlite3_column_text(check,0),"ok"));
  sqlite3_finalize(check);
  int64_t candidates=compact_scalar(db,"SELECT COUNT(*) FROM p0_candidates");
  int64_t references=0,dangling=0; char post_inventory_sha[65];
  int64_t post_refs=cost_context_inventory(db,&references,&dangling,post_inventory_sha);
  assert(dangling==0);sqlite3_close(db);
  uint8_t hash[32];char input_sha[65];edr_sha256_final(&benchmark_input_hash,hash);
  for(unsigned i=0;i<32;++i)snprintf(input_sha+2*i,3,"%02x",hash[i]);
  uint64_t rss=0;
#ifndef _WIN32
  struct rusage usage;assert(getrusage(RUSAGE_SELF,&usage)==0);
  rss=(uint64_t)usage.ru_maxrss;
#ifndef __APPLE__
  rss*=1024u;
#endif
#endif
  printf("evidence_cost profile=%s input_count=%u input_sha256=%s cpu_seconds=%.6f wall_seconds=%.6f "
      "producer_cpu_seconds=%.6f producer_wall_seconds=%.6f "
      "entry_p95_us=%.3f entry_p99_us=%.3f recall_p95_us=%.3f recall_p99_us=%.3f "
      "lock_wait_p95_ns=%llu lock_wait_p99_ns=%llu lock_hold_p95_ns=%llu lock_hold_p99_ns=%llu "
      "sqlite_read_bytes=%llu sqlite_write_bytes=%llu sqlite_syncs=%llu physical_peak_bytes=%llu peak_rss_bytes=%llu "
      "startup_sqlite_read_bytes=%llu startup_sqlite_write_bytes=%llu startup_sqlite_syncs=%llu "
      "producer_sqlite_read_bytes=%llu producer_sqlite_write_bytes=%llu producer_sqlite_syncs=%llu "
      "recall_sqlite_read_bytes=%llu recall_sqlite_write_bytes=%llu recall_sqlite_syncs=%llu "
      "close_sqlite_read_bytes=%llu close_sqlite_write_bytes=%llu close_sqlite_syncs=%llu "
      "candidates=%lld refs=%lld post_refs=%lld post_inventory_sha256=%s rejected=%llu recall_rows=%u response_bytes=%zu dangling_refs=%lld sqlite_version=%s\n",
      profile,inputs,input_sha,finished.user_seconds+finished.system_seconds-started.user_seconds-started.system_seconds,
      finished.wall_seconds-started.wall_seconds,
      producer_end.user_seconds+producer_end.system_seconds-producer_start.user_seconds-producer_start.system_seconds,
      producer_end.wall_seconds-producer_start.wall_seconds,
      cost_percentile(entry,inputs,95),cost_percentile(entry,inputs,99),
      cost_percentile(query,queries,95),cost_percentile(query,queries,99),
      (unsigned long long)status.mutex_wait_p95_ns,(unsigned long long)status.mutex_wait_p99_ns,
      (unsigned long long)status.mutex_hold_p95_ns,(unsigned long long)status.mutex_hold_p99_ns,
      (unsigned long long)reads,(unsigned long long)writes,(unsigned long long)syncs,
      (unsigned long long)physical_peak,(unsigned long long)rss,
      (unsigned long long)startup_io.reads,(unsigned long long)startup_io.writes,(unsigned long long)startup_io.syncs,
      (unsigned long long)producer_io.reads,(unsigned long long)producer_io.writes,(unsigned long long)producer_io.syncs,
      (unsigned long long)recall_io.reads,(unsigned long long)recall_io.writes,(unsigned long long)recall_io.syncs,
      (unsigned long long)close_io.reads,(unsigned long long)close_io.writes,(unsigned long long)close_io.syncs,
      (long long)candidates,(long long)references,(long long)post_refs,post_inventory_sha,
      (unsigned long long)status.candidate_rejected,rows,response_bytes,(long long)dangling,sqlite3_libversion());
  cleanup_test_sqlite_path(path);cleanup_test_sqlite_path(queue_path);free(r);free(entry);
#ifdef BENCH_HAS_STORAGE_RESERVATION
  assert(fclose(reservation)==0);
#endif
  assert(sqlite3_vfs_register(retention_bench_vfs_parent,1)==SQLITE_OK);
  assert(sqlite3_vfs_unregister(&vfs)==SQLITE_OK);
  return 0;
}
