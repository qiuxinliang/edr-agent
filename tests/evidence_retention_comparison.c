/* Synthetic-only fixed workload used by run_evidence_retention_comparison.py.
 * Real storage/codec code; fake clock and disabled unrelated network/action
 * side effects are explicit below. VFS bytes are issued I/O, not device I/O. */
#include "edr/behavior_record.h"
#include "edr/behavior_from_slot.h"
#include "edr/detection_decision.h"
#include "edr/local_evidence_cache.h"
#include "edr/command.h"
#include "edr/behavior_proto.h"
#include "edr/v1/event.pb.h"
#include <pb_decode.h>
#include "edr/egress_batch_policy.h"
#include "edr/p0_rule_match.h"
#include "edr/process_tree_cache.h"
#include "src/preprocess/process_cached_generation.h"
#include "src/preprocess/parent_context_snapshot.h"
#include "src/collector/process_command_preview.h"
#include "cJSON.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include "edr/sha256.h"

#if defined(_WIN32)
#include <windows.h>
static void test_setenv(const char *name, const char *value) {
  assert(_putenv_s(name, value) == 0);
}
static void test_unsetenv(const char *name) { assert(_putenv_s(name, "") == 0); }
#else
#include <pthread.h>
#include <spawn.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
extern char **environ;
static const char *s_test_executable;
static void test_setenv(const char *name, const char *value) {
  assert(setenv(name, value, 1) == 0);
}
static void test_unsetenv(const char *name) { assert(unsetenv(name) == 0); }
#endif

#if defined(EDR_HAVE_SQLITE)
#include <sqlite3.h>
#include "src/storage/evidence_context_store.h"
#endif

#ifdef BENCH_REAL_QUEUE
#include "edr/storage_queue.h"
#include "edr/transport_sink.h"
int edr_ingest_http_configured(void) { return 0; }
int edr_ingest_http_circuit_open(void) { return 0; }
int edr_ingest_http_telemetry_deferred(void) { return 0; }
int edr_transport_v2_report_events(const char *id,const uint8_t *head,size_t hlen,
    const uint8_t *body,size_t len) {
  (void)id;(void)head;(void)hlen;(void)body;(void)len;
  assert(!"unexpected network attempt in local retention comparison"); return -1;
}
#endif

static bool s_test_pressure;
bool edr_resource_preprocess_throttle_active(void) { return s_test_pressure; }
static uint64_t s_test_monotonic_ns = 1000000000ull;
uint64_t edr_monotonic_ns(void) { return s_test_monotonic_ns; }
/* The parser's unrelated enforcement side effect is outside this fixture. */
void edr_isolate_auto_from_ransom_alarm(const EdrBehaviorRecord *record) { (void)record; }

static int make_test_sqlite_path(char *out, size_t cap) {
#if defined(_WIN32)
  char temp[MAX_PATH];
  char file[MAX_PATH];
  DWORD temp_len = GetTempPathA((DWORD)sizeof(temp), temp);
  if (!out || cap == 0u || !temp_len || temp_len >= sizeof(temp) ||
      !GetTempFileNameA(temp, "edr", 0u, file)) {
    return -1;
  }
  if ((size_t)snprintf(out, cap, "%s", file) >= cap) {
    (void)remove(file);
    return -1;
  }
  return 0;
#else
  char pattern[] = "/tmp/edr-local-evidence-XXXXXX";
  int fd;
  if (!out || cap == 0u || (fd = mkstemp(pattern)) < 0) return -1;
  close(fd);
  if ((size_t)snprintf(out, cap, "%s", pattern) >= cap) {
    (void)remove(pattern);
    return -1;
  }
  return 0;
#endif
}

static void cleanup_test_sqlite_path(const char *db) {
  char sidecar[640];
  int n;
  if (!db || !db[0]) return;
  (void)remove(db);
  n = snprintf(sidecar, sizeof(sidecar), "%s-wal", db);
  if (n > 0 && (size_t)n < sizeof(sidecar)) (void)remove(sidecar);
  n = snprintf(sidecar, sizeof(sidecar), "%s-shm", db);
  if (n > 0 && (size_t)n < sizeof(sidecar)) (void)remove(sidecar);
}

static void init_record(EdrBehaviorRecord *r, EdrEventType t) {
  edr_behavior_record_init(r);
  r->type = t;
  r->priority = 1u;
  r->pid = 4242u;
}

/* Local-cache enrichment requires the same authoritative tuple as production
 * P0 records.  Legacy PID-only process-tree entries are deliberately unknown
 * and must not make these tests accidentally prove a cross-generation copy. */
static int put_generation(uint32_t pid, uint32_t ppid, const char *name,
                          const char *cmdline, const char *path,
                          const char *parent_name, uint64_t start_time_ns,
                          uint64_t start_key) {
  return edr_pt_cache_put_generation(
      pid, ppid, name, cmdline, path, parent_name, start_time_ns, start_key,
      133700000000000000ULL + start_key);
}

static void set_record_generation(EdrBehaviorRecord *r, uint64_t start_key) {
  assert(r != NULL);
  r->process_start_key = start_key;
  r->process_creation_filetime_100ns = 133700000000000000ULL + start_key;
}

static uint64_t test_filetime_unix_ns(uint64_t creation_filetime_100ns) {
  const uint64_t epoch = UINT64_C(116444736000000000);
  assert(creation_filetime_100ns > epoch);
  assert(creation_filetime_100ns - epoch <= UINT64_MAX / 100u);
  return (creation_filetime_100ns - epoch) * 100u;
}

static uint64_t test_unix_ns_to_filetime(uint64_t unix_ns) {
  return UINT64_C(116444736000000000) + unix_ns / 100u;
}

static void fill_text(char *out, size_t cap, size_t length, char seed) {
  assert(out != NULL && length < cap);
  for (size_t i = 0u; i < length; ++i) {
    out[i] = (char)(seed + (char)(i % 17u));
  }
  out[length] = '\0';
}


static uint64_t benchmark_physical_bytes(const char *path) {
  const char *suffixes[]={"","-wal","-shm"}; uint64_t total=0;
  for(unsigned i=0;i<3;++i) { char file[640]; struct stat st;
    snprintf(file,sizeof(file),"%s%s",path,suffixes[i]);
    if(stat(file,&st)==0) total+=(uint64_t)st.st_size;
  }
  return total;
}

static EdrSha256Ctx benchmark_input_hash;
static uint64_t benchmark_input_bytes;
static void benchmark_input(const EdrBehaviorRecord *r) {
  static uint8_t wire[EDR_EGRESS_FRAME_MAX];
  size_t n=edr_behavior_record_encode_protobuf_full_facts(r,NULL,NULL,NULL,wire,sizeof(wire));
  assert(n>0);
  edr_sha256_update(&benchmark_input_hash,wire,n); benchmark_input_bytes+=n;
}
static int64_t compact_scalar(sqlite3 *db, const char *sql) {
  sqlite3_stmt *st = NULL;
  assert(sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK);
  assert(sqlite3_step(st) == SQLITE_ROW);
  int64_t value = sqlite3_column_int64(st, 0);
  sqlite3_finalize(st); return value;
}


#ifndef BENCH_SOURCE
#define BENCH_SOURCE "old_head"
#define BENCH_SELECTED_HOURS 1
#define BENCH_OPEN(path,selected) edr_local_evidence_cache_open(path,8,1)
#else
#define BENCH_OPEN(path,selected) edr_local_evidence_cache_open_with_policy(path,8,1,selected)
#endif
#include "retention_benchmark_support.h"

static void test_retention_value_benchmark(void) {
  const int64_t base=INT64_C(1700000000000000000);
  retention_bench_vfs_parent=sqlite3_vfs_find(NULL); assert(retention_bench_vfs_parent);
  sqlite3_vfs vfs=*retention_bench_vfs_parent;
  vfs.zName="retention-benchmark"; vfs.pNext=NULL;
  vfs.szOsFile+=(int)sizeof(RetentionBenchFile); vfs.xOpen=retention_bench_open;
  assert(sqlite3_vfs_register(&vfs,1)==SQLITE_OK);
  for (unsigned selected=BENCH_SELECTED_HOURS;selected<=BENCH_SELECTED_HOURS;++selected) {
    char path[512]; sqlite3 *db=NULL; uint64_t physical_peak=0;
    EdrBehaviorRecord *r=calloc(1,sizeof(*r)); assert(r);
    assert(make_test_sqlite_path(path,sizeof(path))==0);
    edr_local_evidence_cache_test_set_now_unix_ns(base);
    retention_bench_reads=retention_bench_writes=retention_bench_syncs=0;
    edr_sha256_init(&benchmark_input_hash); benchmark_input_bytes=0;
    RetentionBenchMetrics metrics_begin=retention_bench_metrics();
    assert(BENCH_OPEN(path,selected)==0);
    for (unsigned hour=0;hour<8;++hour) {
      int64_t stamp=base+(int64_t)hour*3600000000000LL;
      edr_local_evidence_cache_test_set_now_unix_ns(stamp);
      s_test_monotonic_ns+=60000000000ULL;
      edr_local_evidence_cache_poll_maintenance(); { uint64_t sampled=benchmark_physical_bytes(path); if (sampled>physical_peak) physical_peak=sampled; }
      for (unsigned item=0;item<24;++item) {
        init_record(r,EDR_EVENT_NET_CONNECT); r->priority=3; r->pid=5000u+hour*24u+item; set_record_generation(r,r->pid);
        r->event_time_ns=stamp+(int64_t)item*1000000000LL; r->ppid=4000u+hour*24u+item; r->net_dport=445;
        snprintf(r->endpoint_id,sizeof(r->endpoint_id),"bench-endpoint"); snprintf(r->tenant_id,sizeof(r->tenant_id),"bench-tenant");
        snprintf(r->event_id,sizeof(r->event_id),"bench-%u-%u",hour,item);
        snprintf(r->process_name,sizeof(r->process_name),"candidate.exe"); snprintf(r->net_dst,sizeof(r->net_dst),"10.2.3.4");
        r->parent_process_start_key=r->ppid; r->parent_process_creation_filetime_100ns=133700000000000000ULL+r->ppid;
        snprintf(r->parent_resolution_source,sizeof(r->parent_resolution_source),"live_parent_generation");
        snprintf(r->parent_name,sizeof(r->parent_name),"ordinary-parent.exe"); snprintf(r->parent_path,sizeof(r->parent_path),"C:\\ordinary-parent.exe");
        edr_behavior_bind_parent_context(r);
        if (!(item%4)) r->type=EDR_EVENT_PMFE_SCAN_RESULT;
        benchmark_input(r); edr_local_evidence_cache_record_behavior(r);
        if (!(item%4)) {
          r->priority=1; r->type=EDR_EVENT_NET_CONNECT; r->net_dport=80; r->event_time_ns++;
          snprintf(r->event_id,sizeof(r->event_id),"bench-context-%u-%u",hour,item);
          benchmark_input(r); edr_local_evidence_cache_record_behavior(r);
        }
        EdrEvidenceCacheStatus status; edr_local_evidence_cache_get_status(&status);
        if (status.physical_bytes>physical_peak) physical_peak=status.physical_bytes;
      }
      for(unsigned minute=1;minute<60;++minute) {
        edr_local_evidence_cache_test_set_now_unix_ns(stamp+(int64_t)minute*60000000000LL);
        s_test_monotonic_ns+=60000000000ULL; edr_local_evidence_cache_poll_maintenance(); { uint64_t sampled=benchmark_physical_bytes(path); if (sampled>physical_peak) physical_peak=sampled; }
      }
    }
    EdrEvidenceCacheStatus status; edr_local_evidence_cache_get_status(&status);
    if (status.physical_bytes>physical_peak) physical_peak=status.physical_bytes;
    edr_local_evidence_cache_close();
    RetentionBenchMetrics metrics_end=retention_bench_metrics();
    double cpu_seconds=metrics_end.user_seconds+metrics_end.system_seconds-metrics_begin.user_seconds-metrics_begin.system_seconds;
    uint64_t reads=retention_bench_reads,writes=retention_bench_writes,syncs=retention_bench_syncs;
    assert(sqlite3_open(path,&db)==SQLITE_OK);
    char sql[256];
    snprintf(sql,sizeof(sql),"SELECT COUNT(*) FROM p0_candidates WHERE type<>%d",(int)EDR_EVENT_PMFE_SCAN_RESULT);
    int recent=(int)compact_scalar(db,sql);
    snprintf(sql,sizeof(sql),"SELECT COUNT(*) FROM p0_candidates WHERE type=%d",(int)EDR_EVENT_PMFE_SCAN_RESULT);
    int valuable=(int)compact_scalar(db,sql);
    sqlite3_stmt *st=NULL;
    assert(sqlite3_prepare_v2(db,"PRAGMA integrity_check",-1,&st,NULL)==SQLITE_OK);
    assert(sqlite3_step(st)==SQLITE_ROW && !strcmp((const char *)sqlite3_column_text(st,0),"ok"));
    sqlite3_finalize(st);
    int64_t orphan_refs=compact_scalar(db,"SELECT COUNT(*) FROM candidate_context_refs r LEFT JOIN p0_candidates p ON p.candidate_id=r.candidate_id LEFT JOIN context_facts f ON f.fact_id=r.fact_id WHERE p.candidate_id IS NULL OR f.fact_id IS NULL");
    assert(orphan_refs==0);
    snprintf(sql,sizeof(sql),"SELECT MIN(event_time_ns),MAX(event_time_ns) FROM p0_candidates WHERE type=%d",(int)EDR_EVENT_PMFE_SCAN_RESULT);
    assert(sqlite3_prepare_v2(db,sql,-1,&st,NULL)==SQLITE_OK);
    assert(sqlite3_step(st)==SQLITE_ROW);
    int64_t earliest=sqlite3_column_int64(st,0),latest=sqlite3_column_int64(st,1); sqlite3_finalize(st);
    assert(sqlite3_prepare_v2(db,"SELECT a.manifest_json,pc.parent_process_start_key,pc.parent_process_creation_filetime_100ns,pc.parent_name FROM materialized_artifacts a JOIN p0_candidates p ON p.candidate_id=a.candidate_id LEFT JOIN process_cache pc ON pc.endpoint_id=p.endpoint_id AND pc.tenant_id=p.tenant_id AND pc.pid=p.pid AND pc.process_start_key=p.process_start_key AND pc.process_creation_filetime_100ns=p.process_creation_filetime_100ns WHERE a.artifact_type='post_context'",-1,&st,NULL)==SQLITE_OK);
    unsigned intact=0, retained_post_context=0, reconstructable=0;
    while(sqlite3_step(st)==SQLITE_ROW) {
      cJSON *fact=cJSON_Parse((const char *)sqlite3_column_text(st,0)); assert(fact);
      const cJSON *parent=cJSON_GetObjectItemCaseSensitive(fact,"parent_process_start_key");
      const cJSON *name=cJSON_GetObjectItemCaseSensitive(fact,"parent_process_name");
      const cJSON *creation=cJSON_GetObjectItemCaseSensitive(fact,"parent_creation_filetime_100ns");
      unsigned previous_intact=intact;
      ++retained_post_context;
      if (cJSON_IsString(parent) && strtoul(parent->valuestring,NULL,10)>=4000 && strtoul(parent->valuestring,NULL,10)<4192 &&
          cJSON_IsString(name) && !strcmp(name->valuestring,"ordinary-parent.exe") &&
          cJSON_IsString(creation) && strtoull(creation->valuestring,NULL,10)==133700000000000000ULL+strtoull(parent->valuestring,NULL,10)) ++intact;
      const char *cached_parent=(const char *)sqlite3_column_text(st,1);
      const char *cached_creation=(const char *)sqlite3_column_text(st,2);
      const char *cached_name=(const char *)sqlite3_column_text(st,3);
      int cached_complete=cached_parent && cached_creation && cached_name &&
          strtoul(cached_parent,NULL,10)>=4000 && strtoul(cached_parent,NULL,10)<4192 &&
          strtoull(cached_creation,NULL,10)==133700000000000000ULL+strtoull(cached_parent,NULL,10) &&
          !strcmp(cached_name,"ordinary-parent.exe");
      if (intact>previous_intact || cached_complete) ++reconstructable;
      cJSON_Delete(fact);
    }
    sqlite3_finalize(st);
    uint8_t digest[32]; char input_sha[65]; edr_sha256_final(&benchmark_input_hash,digest);
    for (unsigned j=0;j<32;++j) snprintf(input_sha+2*j,3,"%02x",digest[j]);
    printf("retention_value_benchmark source=%s selected_hours=%u input_candidates=192 low_context=48 recent=%d selected=%d selected_min_ns=%lld selected_max_ns=%lld complete_parent_chains=%u retained_post_context=%u reconstructable_chains_with_process_cache=%u physical_peak_bytes=%llu final_db_wal_shm_bytes=%llu cpu_seconds=%.6f sqlite_vfs_read_bytes=%llu sqlite_vfs_write_bytes=%llu sqlite_vfs_syncs=%llu input_protobuf_bytes=%llu input_sha256=%s sqlite_write_amplification=%.6f wall_seconds=%.6f cpu_user_seconds=%.6f cpu_system_seconds=%.6f process_io_available=%d process_read_bytes=%llu process_write_bytes=%llu native_machine=%u process_machine=%u integrity_ok=1 orphan_references=%lld candidate_requests=%llu candidate_admitted=%llu candidate_rejected=%llu candidate_deduped=%llu sqlite_version=%s\n",
      BENCH_SOURCE,selected,recent,valuable,(long long)earliest,(long long)latest,intact,retained_post_context,reconstructable,(unsigned long long)physical_peak,
      (unsigned long long)status.physical_bytes,cpu_seconds,(unsigned long long)reads,(unsigned long long)writes,(unsigned long long)syncs,(unsigned long long)benchmark_input_bytes,input_sha,(double)writes/(double)benchmark_input_bytes,
      metrics_end.wall_seconds-metrics_begin.wall_seconds,metrics_end.user_seconds-metrics_begin.user_seconds,
      metrics_end.system_seconds-metrics_begin.system_seconds,metrics_end.process_io_available,
      (unsigned long long)(metrics_end.process_read_bytes-metrics_begin.process_read_bytes),
      (unsigned long long)(metrics_end.process_write_bytes-metrics_begin.process_write_bytes),
      metrics_end.native_machine,metrics_end.process_machine,(long long)orphan_refs,
      (unsigned long long)status.candidate_requests,(unsigned long long)status.candidate_admitted,
      (unsigned long long)status.candidate_rejected,(unsigned long long)status.candidate_deduped,sqlite3_libversion());
    sqlite3_close(db); cleanup_test_sqlite_path(path); free(r);
  }
  assert(sqlite3_vfs_register(retention_bench_vfs_parent,1)==SQLITE_OK);
  assert(sqlite3_vfs_unregister(&vfs)==SQLITE_OK);
  edr_local_evidence_cache_test_set_now_unix_ns(0);
}


int main(void) { test_retention_value_benchmark(); return 0; }
