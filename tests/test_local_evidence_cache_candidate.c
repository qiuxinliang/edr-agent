#include "edr/behavior_record.h"
#include "edr/local_evidence_cache.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

bool edr_resource_preprocess_throttle_active(void) { return false; }
uint64_t edr_monotonic_ns(void) { return 1000000000ull; }

static void init_record(EdrBehaviorRecord *r, EdrEventType t) {
  edr_behavior_record_init(r);
  r->type = t;
  r->priority = 1u;
  r->pid = 4242u;
}

static void test_checknetisolation_standard_low_risk_is_not_candidate(void) {
  EdrBehaviorRecord r;
  init_record(&r, EDR_EVENT_NET_CONNECT);
  snprintf(r.process_name, sizeof(r.process_name), "CheckNetIsolation.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Windows\\System32\\CheckNetIsolation.exe");
  snprintf(r.cmdline, sizeof(r.cmdline), "CheckNetIsolation.exe LoopbackExempt -a -n=Microsoft.Test");
  snprintf(r.net_dst, sizeof(r.net_dst), "127.0.0.1");
  r.net_dport = 80u;
  assert(edr_local_evidence_cache_is_candidate(&r) == 0);
}

static void test_checknetisolation_high_risk_port_is_candidate(void) {
  EdrBehaviorRecord r;
  init_record(&r, EDR_EVENT_NET_CONNECT);
  snprintf(r.process_name, sizeof(r.process_name), "CheckNetIsolation.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Windows\\System32\\CheckNetIsolation.exe");
  snprintf(r.net_dst, sizeof(r.net_dst), "10.0.0.5");
  r.net_dport = 445u;
  assert(edr_local_evidence_cache_is_candidate(&r) == 1);
}

static void test_checknetisolation_p1_context_is_candidate(void) {
  EdrBehaviorRecord r;
  init_record(&r, EDR_EVENT_NET_CONNECT);
  snprintf(r.process_name, sizeof(r.process_name), "CheckNetIsolation.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Windows\\System32\\CheckNetIsolation.exe");
  snprintf(r.detection_context, sizeof(r.detection_context), "{\"severity\":\"P1\"}");
  r.net_dport = 80u;
  assert(edr_local_evidence_cache_is_candidate(&r) == 1);
}

static void test_weak_file_event_is_not_candidate(void) {
  EdrBehaviorRecord r;
  init_record(&r, EDR_EVENT_FILE_WRITE);
  r.pid = 0u;
  snprintf(r.file_path, sizeof(r.file_path), "badname");
  assert(edr_local_evidence_cache_is_candidate(&r) == 0);
}

static void test_weak_file_event_p1_context_is_candidate(void) {
  EdrBehaviorRecord r;
  init_record(&r, EDR_EVENT_FILE_WRITE);
  r.pid = 0u;
  snprintf(r.file_path, sizeof(r.file_path), "badname");
  snprintf(r.detection_context, sizeof(r.detection_context), "{\"priority\":\"P1\"}");
  assert(edr_local_evidence_cache_is_candidate(&r) == 1);
}

static void test_high_signal_process_is_candidate(void) {
  EdrBehaviorRecord r;
  init_record(&r, EDR_EVENT_PROCESS_CREATE);
  snprintf(r.process_name, sizeof(r.process_name), "powershell.exe");
  snprintf(r.cmdline, sizeof(r.cmdline), "powershell.exe -NoProfile -EncodedCommand SQBFAFgA");
  assert(edr_local_evidence_cache_is_candidate(&r) == 1);
}

static void test_nonstandard_checknetisolation_path_not_suppressed_by_p1_noise(void) {
  EdrBehaviorRecord r;
  init_record(&r, EDR_EVENT_NET_CONNECT);
  snprintf(r.process_name, sizeof(r.process_name), "CheckNetIsolation.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Users\\Public\\CheckNetIsolation.exe");
  snprintf(r.cmdline, sizeof(r.cmdline), "CheckNetIsolation.exe LoopbackExempt");
  snprintf(r.detection_context, sizeof(r.detection_context), "{\"confidence\":0.9}");
  r.net_dport = 80u;
  assert(edr_local_evidence_cache_is_candidate(&r) == 1);
}

static int g_summary_count;
static EdrBehaviorRecord g_summary_last;

static void summary_capture(const EdrBehaviorRecord *r) {
  g_summary_count++;
  if (r) {
    g_summary_last = *r;
  }
}

static void test_behavior_summary_flush_coalesced_events(void) {
  g_summary_count = 0;
  memset(&g_summary_last, 0, sizeof(g_summary_last));
  const int64_t base_ns = 1779338600000000000LL; /* 固定时间，分钟对齐确定 */
  for (int i = 0; i < 6; i++) {
    EdrBehaviorRecord r;
    init_record(&r, EDR_EVENT_NET_CONNECT);
    r.pid = 7777u;
    r.event_time_ns = base_ns + (int64_t)i * 1000000LL; /* 同一分钟内 */
    snprintf(r.endpoint_id, sizeof(r.endpoint_id), "ep-sum-1");
    snprintf(r.process_name, sizeof(r.process_name), "telemetry.exe");
    snprintf(r.net_dst, sizeof(r.net_dst), "93.184.216.34");
    r.net_dport = 80u; /* 非高危端口 -> 普通事件 -> 进入聚合 */
    edr_local_evidence_cache_record_behavior(&r);
  }
  /* 窗口未关闭：当前分钟内 flush 不应产出。 */
  edr_local_evidence_cache_flush_summaries(base_ns + 1000000000LL, summary_capture);
  assert(g_summary_count == 0);
  /* 推进到下一分钟，窗口关闭：应产出一条摘要，count>=5。 */
  edr_local_evidence_cache_flush_summaries(base_ns + 60000000000LL, summary_capture);
  assert(g_summary_count == 1);
  assert(g_summary_last.type == EDR_EVENT_BEHAVIOR_SUMMARY);
  assert(g_summary_last.priority == 2u);
  assert(g_summary_last.pid == 7777u);
  assert(strstr(g_summary_last.detection_context, "\"type\":\"behavior_summary\"") != NULL);
  assert(strstr(g_summary_last.detection_context, "\"count\":6") != NULL);
  /* 再次 flush，槽位已清空，不应重复产出。 */
  edr_local_evidence_cache_flush_summaries(base_ns + 120000000000LL, summary_capture);
  assert(g_summary_count == 1);
}

static void test_behavior_summary_below_threshold_no_emit(void) {
  g_summary_count = 0;
  const int64_t base_ns = 1779341600000000000LL;
  for (int i = 0; i < 3; i++) { /* 低于默认阈值 5 */
    EdrBehaviorRecord r;
    init_record(&r, EDR_EVENT_NET_CONNECT);
    r.pid = 8888u;
    r.event_time_ns = base_ns + (int64_t)i * 1000000LL;
    snprintf(r.endpoint_id, sizeof(r.endpoint_id), "ep-sum-2");
    snprintf(r.process_name, sizeof(r.process_name), "telemetry.exe");
    snprintf(r.net_dst, sizeof(r.net_dst), "93.184.216.34");
    r.net_dport = 80u;
    edr_local_evidence_cache_record_behavior(&r);
  }
  edr_local_evidence_cache_flush_summaries(base_ns + 60000000000LL, summary_capture);
  assert(g_summary_count == 0);
}

static void test_file_sha256_query_uses_file_evidence_cache(void) {
#if defined(EDR_HAVE_SQLITE)
  const char *db = "rtq_file_hash_cache_test.sqlite";
  const char *hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const char *miss = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  (void)remove(db);
  (void)remove("rtq_file_hash_cache_test.sqlite-wal");
  (void)remove("rtq_file_hash_cache_test.sqlite-shm");
  assert(edr_local_evidence_cache_open(db, 8u, 24u) == 0);

  EdrBehaviorRecord r;
  init_record(&r, EDR_EVENT_FILE_WRITE);
  r.pid = 5151u;
  r.priority = 3u;
  snprintf(r.endpoint_id, sizeof(r.endpoint_id), "ep-hash-1");
  snprintf(r.file_path, sizeof(r.file_path), "C:\\Users\\Public\\dropper.exe");
  snprintf(r.exe_hash, sizeof(r.exe_hash), "%s", hash);
  snprintf(r.detection_context, sizeof(r.detection_context), "{\"priority\":\"P1\"}");
  edr_local_evidence_cache_record_behavior(&r);

  char rows[4096];
  uint32_t returned = 0;
  uint32_t scanned = 0;
  assert(edr_local_evidence_cache_query_file_hash_json(hash, "", ".exe", 10u, rows,
                                                       sizeof(rows), &returned, &scanned) == 0);
  assert(returned == 1u);
  assert(scanned >= 1u);
  assert(strstr(rows, "\"source\":\"file_evidence\"") != NULL);
  assert(strstr(rows, "\"cache_hit\":true") != NULL);
  assert(strstr(rows, "dropper.exe") != NULL);
  assert(strstr(rows, hash) != NULL);

  returned = 99u;
  scanned = 99u;
  assert(edr_local_evidence_cache_query_file_hash_json(miss, "", ".exe", 10u, rows,
                                                       sizeof(rows), &returned, &scanned) == 0);
  assert(returned == 0u);
  assert(strcmp(rows, "[]") == 0);

  char qout[8192];
  char payload[256];
  snprintf(payload, sizeof(payload), "{\"file_sha256\":\"%s\",\"file_ext\":\".exe\"}", hash);
  assert(edr_local_evidence_cache_query_json(payload, qout, sizeof(qout)) == 0);
  assert(strstr(qout, "\"rows_returned\":1") != NULL);
  assert(strstr(qout, "\"source\":\"file_evidence\"") != NULL);

  snprintf(payload, sizeof(payload), "{\"file_sha256\":\"%s\",\"file_ext\":\".dll\"}", hash);
  assert(edr_local_evidence_cache_query_json(payload, qout, sizeof(qout)) == 0);
  assert(strstr(qout, "\"rows_returned\":0") != NULL);

  edr_local_evidence_cache_close();
  (void)remove(db);
  (void)remove("rtq_file_hash_cache_test.sqlite-wal");
  (void)remove("rtq_file_hash_cache_test.sqlite-shm");
#endif
}

int main(void) {
  test_checknetisolation_standard_low_risk_is_not_candidate();
  test_checknetisolation_high_risk_port_is_candidate();
  test_checknetisolation_p1_context_is_candidate();
  test_weak_file_event_is_not_candidate();
  test_weak_file_event_p1_context_is_candidate();
  test_high_signal_process_is_candidate();
  test_nonstandard_checknetisolation_path_not_suppressed_by_p1_noise();
  test_behavior_summary_flush_coalesced_events();
  test_behavior_summary_below_threshold_no_emit();
  test_file_sha256_query_uses_file_evidence_cache();
  puts("test_local_evidence_cache_candidate: ok");
  return 0;
}
