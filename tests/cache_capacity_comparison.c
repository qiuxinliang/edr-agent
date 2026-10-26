/* Synthetic capacity sensitivity, not a replay of an endpoint workload.
 * All data enters through production alert/command persistence APIs. The
 * protected working set intentionally exceeds the smallest capacity. */
#define main retention_reference_main
#include "evidence_retention_comparison.c"
#undef main

static void capacity_record(EdrBehaviorRecord *r, unsigned item, int64_t stamp) {
  init_record(r, EDR_EVENT_PROCESS_CREATE);
  strcpy(r->tenant_id, "capacity-test-tenant");
  strcpy(r->endpoint_id, "capacity-test-endpoint");
  snprintf(r->event_id, sizeof(r->event_id), "capacity-source-%u", item);
  r->pid = 10000u + item * 2u; r->ppid = r->pid + 1u;
  r->process_start_key = r->pid; r->parent_process_start_key = r->ppid;
  r->process_creation_filetime_100ns = test_unix_ns_to_filetime((uint64_t)stamp - 1000000000u);
  r->parent_process_creation_filetime_100ns = r->process_creation_filetime_100ns - 10000000u;
  r->parent_pid_state = EDR_PARENT_PID_KNOWN; r->event_time_ns = stamp;
  strcpy(r->process_name, "capacity-child.exe");
  strcpy(r->exe_path, "C:/synthetic/capacity-child.exe");
  strcpy(r->parent_name, "capacity-parent.exe");
  strcpy(r->parent_path, "C:/synthetic/capacity-parent.exe");
  strcpy(r->parent_resolution_source, "live_parent_generation");
  strcpy(r->parent_resolution_status, "RESOLVED");
  edr_behavior_bind_parent_context(r);
}

static void capacity_parent_check(const EdrBehaviorRecord *r, int64_t now) {
  char output[4096];
  EdrParentContextQuery q = {r->tenant_id, r->endpoint_id, r->event_id,
      r->pid, r->process_start_key, r->process_creation_filetime_100ns,
      r->event_time_ns - 1000000000LL, r->event_time_ns + 1000000000LL,
      now / 1000000LL + 30000, EDR_PARENT_CONTEXT_FIELD_NAME};
  assert(edr_local_evidence_cache_query_parent_context_json(&q, output, sizeof(output)) == 0);
  cJSON *root = cJSON_Parse(output); assert(root);
  const cJSON *reason = cJSON_GetObjectItemCaseSensitive(root, "availability_reason");
  const cJSON *parent = cJSON_GetObjectItemCaseSensitive(root, "parent");
  assert(cJSON_IsString(reason) && !strcmp(reason->valuestring, "available"));
  assert(cJSON_IsObject(parent));
  const cJSON *pid = cJSON_GetObjectItemCaseSensitive(parent, "pid");
  const cJSON *name = cJSON_GetObjectItemCaseSensitive(parent, "name");
  assert(cJSON_IsNumber(pid) && pid->valuedouble == r->ppid);
  assert(cJSON_IsString(name) && !strcmp(name->valuestring, "capacity-parent.exe"));
  cJSON_Delete(root);
}

int main(int argc, char **argv) {
  assert(argc == 3);
  char *end = NULL;
  unsigned capacity = (unsigned)strtoul(argv[1], &end, 10);
  assert(end && !*end && (capacity == 512u || capacity == 768u || capacity == 1024u));
  unsigned count = (unsigned)strtoul(argv[2], &end, 10);
  assert(end && !*end && count >= 2u && count <= 6000u);
  char path[512], input_sha[65], first_command_sha[65], restored_sha[65];
  char *subject = malloc(96001u), *parent = malloc(96001u);
  EdrBehaviorRecord *r = calloc(1, sizeof(*r)), *first = calloc(1, sizeof(*first)), *last = calloc(1, sizeof(*last));
  assert(subject && parent && r && first && last);
  const int64_t base = INT64_C(1700000000000000000);
  assert(make_test_sqlite_path(path, sizeof(path)) == 0);
  retention_bench_vfs_parent = sqlite3_vfs_find(NULL); assert(retention_bench_vfs_parent);
  sqlite3_vfs vfs = *retention_bench_vfs_parent;
  vfs.zName = "capacity-benchmark"; vfs.pNext = NULL;
  vfs.szOsFile += (int)sizeof(RetentionBenchFile); vfs.xOpen = retention_bench_open;
  assert(sqlite3_vfs_register(&vfs, 1) == SQLITE_OK);
  edr_local_evidence_cache_test_set_now_unix_ns(base);
  benchmark_sync_retention_clock();
  assert(edr_local_evidence_cache_open_with_policy(path, capacity, 72u, 72u) == 0);
  retention_bench_reads = retention_bench_writes = retention_bench_syncs = 0;
  edr_sha256_init(&benchmark_input_hash); benchmark_input_bytes = 0;
  RetentionBenchMetrics begin = retention_bench_metrics();
  unsigned committed = 0, partial = 0, refused = 0;
  uint64_t peak = 0;
  for (unsigned i = 0; i < count; ++i) {
    int64_t stamp = base + (int64_t)i * 1000000000LL;
    edr_local_evidence_cache_test_set_now_unix_ns(stamp);
    s_test_monotonic_ns += 1000000000ULL; benchmark_sync_retention_clock();
    capacity_record(r, i, stamp);
    fill_text(subject, 96001u, 96000u, 'A'); fill_text(parent, 96001u, 96000u, 'a');
    char prefix[64]; int n = snprintf(prefix, sizeof(prefix), "child-%08u --synthetic ", i);
    memcpy(subject, prefix, (size_t)n);
    n = snprintf(prefix, sizeof(prefix), "parent-%08u --synthetic ", i);
    memcpy(parent, prefix, (size_t)n);
    snprintf(r->cmdline, sizeof(r->cmdline), "%s", subject);
    snprintf(r->parent_cmdline, sizeof(r->parent_cmdline), "%s", parent);
    benchmark_input(r);
    edr_sha256_update(&benchmark_input_hash, (const uint8_t *)subject, 96000u);
    edr_sha256_update(&benchmark_input_hash, (const uint8_t *)parent, 96000u);
    benchmark_input_bytes += 192000u;
    EdrCommandFacts facts = {subject, parent};
    int result = edr_local_evidence_cache_record_alert_context(r, &facts);
    if (result >= 0) {
      if (!committed) {
        *first = *r;
        assert(edr_sha256_hex((const uint8_t *)subject, 96000u, first_command_sha) == 0);
      }
      *last = *r; ++committed; partial += result != 0;
    } else ++refused;
    edr_local_evidence_cache_poll_maintenance();
    uint64_t physical = benchmark_physical_bytes(path); if (physical > peak) peak = physical;
    if (!(i % 500u)) { fprintf(stderr, "capacity_progress mib=%u inputs=%u committed=%u refused=%u\n", capacity, i+1u, committed, refused); fflush(stderr); }
  }
  assert(committed > 0u);
  EdrEvidenceCacheStatus before_drain, after;
  edr_local_evidence_cache_get_status(&before_drain);
  RetentionBenchMetrics drain_begin = retention_bench_metrics();
  for (unsigned i = 0; i < 180u; ++i) {
    s_test_monotonic_ns += 1000000000ULL; benchmark_sync_retention_clock();
    edr_local_evidence_cache_test_set_now_unix_ns(base + ((int64_t)count + i) * 1000000000LL);
    edr_local_evidence_cache_poll_maintenance();
    uint64_t physical = benchmark_physical_bytes(path); if (physical > peak) peak = physical;
  }
  RetentionBenchMetrics finish = retention_bench_metrics();
  edr_local_evidence_cache_get_status(&after);
  assert(after.retention_clock_valid && after.retention_failures == 0u);
  int64_t now = base + ((int64_t)count + 180) * 1000000000LL;
  capacity_parent_check(first, now); capacity_parent_check(last, now);
  char *restored = edr_local_evidence_cache_read_command_fact(first);
  assert(restored && edr_sha256_hex((const uint8_t *)restored, strlen(restored), restored_sha) == 0);
  assert(!strcmp(first_command_sha, restored_sha)); free(restored);
  uint8_t hash[32]; edr_sha256_final(&benchmark_input_hash, hash);
  for (unsigned i=0; i<32; ++i) snprintf(input_sha+2*i, 3, "%02x", hash[i]);
  uint64_t writes = retention_bench_writes, reads = retention_bench_reads;
  edr_local_evidence_cache_close();
  sqlite3 *db = NULL; assert(sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK);
  assert(compact_scalar(db, "SELECT COUNT(*) FROM p0_candidates") == (int64_t)committed);
  assert(compact_scalar(db, "SELECT COUNT(*) FROM pragma_integrity_check WHERE integrity_check<>'ok'") == 0);
  assert(compact_scalar(db, "SELECT COUNT(*) FROM compact_context_refs r LEFT JOIN context_candidates c ON c.id=r.candidate_key LEFT JOIN context_fact_keys f ON f.id=r.fact_key WHERE c.id IS NULL OR f.id IS NULL") == 0);
  assert(sqlite3_close(db) == SQLITE_OK);
  printf("capacity_benchmark capacity_mib=%u retention_hours=72 input_candidates=%u committed=%u partial=%u refused=%u candidate_requests=%llu candidate_admitted=%llu candidate_rejected=%llu peak_physical_bytes=%llu final_physical_bytes=%llu drain_wall_seconds=%.6f wall_seconds=%.6f cpu_seconds=%.6f sqlite_vfs_write_bytes=%llu sqlite_vfs_read_bytes=%llu maintenance_runs=%llu drain_maintenance_runs=%llu input_sha256=%s input_bytes=%llu protected_parent_queries=2 command_hash_equal=1 integrity_ok=1 simulated_seconds=%u",
      capacity,count,committed,partial,refused,(unsigned long long)after.candidate_requests,
      (unsigned long long)after.candidate_admitted,(unsigned long long)after.candidate_rejected,
      (unsigned long long)peak,(unsigned long long)after.physical_bytes,
      finish.wall_seconds-drain_begin.wall_seconds,finish.wall_seconds-begin.wall_seconds,
      finish.user_seconds+finish.system_seconds-begin.user_seconds-begin.system_seconds,
      (unsigned long long)writes,(unsigned long long)reads,(unsigned long long)after.maintenance_runs,
      (unsigned long long)(after.maintenance_runs-before_drain.maintenance_runs),input_sha,
      (unsigned long long)benchmark_input_bytes,count+180u);
  static const char *causes[] = {"unknown","db_wal_limit","wal_busy","wal_error",
      "physical_guard","maintenance_deferred","maintenance_failed","postwrite_page_limit"};
  _Static_assert(sizeof(causes)/sizeof(causes[0]) == EDR_EVIDENCE_CAPACITY_CAUSE_COUNT, "capacity reason coverage");
  for (unsigned i=0; i<EDR_EVIDENCE_CAPACITY_CAUSE_COUNT; ++i)
    printf(" candidate_%s=%llu context_%s=%llu",causes[i],
        (unsigned long long)after.candidate_capacity_causes[i],causes[i],
        (unsigned long long)after.context_capacity_causes[i]);
  puts("");
  cleanup_test_sqlite_path(path);
  assert(sqlite3_vfs_register(retention_bench_vfs_parent,1)==SQLITE_OK);
  assert(sqlite3_vfs_unregister(&vfs)==SQLITE_OK);
  free(subject); free(parent); free(r); free(first); free(last); return 0;
}
