#include "edr/behavior_record.h"
#include "edr/local_evidence_cache.h"
#include "edr/process_tree_cache.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

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

static void test_identity_status_counter_basics(void) {
  assert(edr_local_evidence_cache_open(":memory:", 8u, 24u) == 0);
  struct timespec ts;
  assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  const int64_t generation_start = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec - 1000LL;
  edr_pt_cache_init();
  assert(edr_pt_cache_put(91002u, 1u, "identity.exe", "", "", "", (uint64_t)generation_start) == 0);
  EdrEvidenceCacheStatus st;
  edr_local_evidence_cache_get_status(&st);
  assert(st.identity_observations_total == 0u && st.process_slots_used <= st.process_slots_capacity);
  EdrBehaviorRecord miss;
  init_record(&miss, EDR_EVENT_PROCESS_CREATE);
  miss.pid = 91001u;
  edr_local_evidence_cache_enrich_behavior(&miss);
  edr_local_evidence_cache_get_status(&st);
  assert(st.process_cache_misses == 1u && st.identity_enrich_attempts == 1u && st.identity_cache_misses == 1u);
  EdrBehaviorRecord observed;
  init_record(&observed, EDR_EVENT_PROCESS_CREATE);
  observed.pid = 91002u;
  observed.event_time_ns = generation_start + 1000000LL;
  snprintf(observed.username, sizeof(observed.username), "SYSTEM");
  snprintf(observed.identity_quality, sizeof(observed.identity_quality), "target_4688");
  edr_local_evidence_cache_observe_process(&observed);
  EdrBehaviorRecord hit;
  init_record(&hit, EDR_EVENT_PROCESS_CREATE);
  hit.pid = 91002u;
  hit.event_time_ns = generation_start + 2000000LL;
  edr_local_evidence_cache_enrich_behavior(&hit);
  edr_local_evidence_cache_get_status(&st);
  assert(st.identity_observations_total == 1u && st.identity_target_4688 == 1u);
  assert(st.process_cache_hits == 1u && st.identity_cache_hits == 1u && st.identity_cache_misses == 1u);
  char json[4096];
  edr_local_evidence_cache_status_json(json, sizeof(json));
  assert(strstr(json, "\"observations_total\":1") != NULL);
  assert(strstr(json, "\"generation_unknown_rejects\"") != NULL);
  edr_local_evidence_cache_close();
}

static void test_identity_generation_match_delta(void) {
  assert(edr_local_evidence_cache_open(":memory:", 8u, 24u) == 0);
  struct timespec ts;
  assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  uint64_t now = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
  edr_pt_cache_init();
  assert(edr_pt_cache_put(92001u, 1u, "x.exe", "x", "x", "p", now - 1000u) == 0);
  EdrBehaviorRecord observed;
  init_record(&observed, EDR_EVENT_PROCESS_CREATE);
  observed.pid = 92001u; observed.event_time_ns = (int64_t)now;
  snprintf(observed.username, sizeof(observed.username), "ACME\\alice");
  snprintf(observed.identity_quality, sizeof(observed.identity_quality), "target_4688");
  edr_local_evidence_cache_observe_process(&observed);
  EdrBehaviorRecord hit;
  init_record(&hit, EDR_EVENT_NET_CONNECT);
  hit.pid = 92001u; hit.event_time_ns = (int64_t)now;
  edr_local_evidence_cache_enrich_behavior(&hit);
  EdrEvidenceCacheStatus st;
  edr_local_evidence_cache_get_status(&st);
  assert(strcmp(hit.username, "ACME\\alice") == 0);
  assert(strcmp(hit.identity_source, "cache") == 0 && strcmp(hit.identity_quality, "target_4688") == 0);
  assert(st.identity_cache_hits == 1u && st.identity_cache_misses == 0u);
  edr_pt_cache_shutdown();
  edr_local_evidence_cache_close();
}

static void test_sid_only_identity_enriches_same_generation(void) {
  assert(edr_local_evidence_cache_open(":memory:", 8u, 24u) == 0);
  struct timespec ts; assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  uint64_t now = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
  edr_pt_cache_init();
  assert(edr_pt_cache_put(92501u, 1u, "sid.exe", "sid", "sid", "p", now - 1000u) == 0);
  EdrBehaviorRecord observed; init_record(&observed, EDR_EVENT_PROCESS_CREATE);
  observed.pid = 92501u; observed.event_time_ns = (int64_t)now;
  snprintf(observed.user_sid, sizeof(observed.user_sid), "S-1-5-18");
  snprintf(observed.identity_quality, sizeof(observed.identity_quality), "target_4688");
  snprintf(observed.identity_source, sizeof(observed.identity_source), "target_4688");
  edr_local_evidence_cache_observe_process(&observed);
  EdrBehaviorRecord hit; init_record(&hit, EDR_EVENT_FILE_WRITE); hit.pid = 92501u; hit.event_time_ns = (int64_t)now;
  edr_local_evidence_cache_enrich_behavior(&hit);
  assert(!hit.username[0] && strcmp(hit.user_sid, "S-1-5-18") == 0);
  assert(strcmp(hit.identity_quality, "target_4688") == 0 && strcmp(hit.identity_source, "cache") == 0);
  EdrEvidenceCacheStatus st; edr_local_evidence_cache_get_status(&st); assert(st.identity_cache_hits == 1u);
  edr_pt_cache_shutdown(); edr_local_evidence_cache_close();
}

static void test_unknown_generation_identity_never_survives_to_later_kernel_generation(void) {
  assert(edr_local_evidence_cache_open(":memory:", 8u, 24u) == 0);
  struct timespec ts; assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  uint64_t now = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
  edr_pt_cache_init();
  EdrBehaviorRecord security; init_record(&security, EDR_EVENT_PROCESS_CREATE);
  security.pid = 92502u; security.event_time_ns = (int64_t)now;
  snprintf(security.user_sid, sizeof(security.user_sid), "S-1-5-21-unknown");
  snprintf(security.identity_quality, sizeof(security.identity_quality), "target_4688");
  edr_local_evidence_cache_observe_process(&security);
  assert(edr_pt_cache_put(92502u, 1u, "kernel.exe", "", "", "", now + 1000u) == 0);
  EdrBehaviorRecord later; init_record(&later, EDR_EVENT_NET_CONNECT);
  later.pid = 92502u; later.event_time_ns = (int64_t)(now + 2000u);
  edr_local_evidence_cache_enrich_behavior(&later);
  EdrEvidenceCacheStatus st; edr_local_evidence_cache_get_status(&st);
  assert(!later.user_sid[0]);
  assert(st.generation_unknown_update_rejects == 1u && st.identity_cache_misses == 1u);
  edr_pt_cache_shutdown(); edr_local_evidence_cache_close();
}

static void test_security_4688_identity_none_is_not_lifecycle_authoritative(void) {
  struct timespec ts; assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  uint64_t start = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec - 1000u;
  edr_pt_cache_init();
  assert(edr_pt_cache_put(92503u, 1u, "kernel.exe", "", "", "", start) == 0);
  EdrBehaviorRecord security; init_record(&security, EDR_EVENT_PROCESS_CREATE);
  security.pid = 92503u; security.event_time_ns = (int64_t)(start + 10u); security.is_security_4688 = 1u;
  /* Target/Subject placeholders have already parsed to empty fields. */
  assert(!security.username[0] && !security.user_sid[0]);
  assert(!edr_process_create_is_lifecycle_authoritative(&security));
  ProcessTreeEntry before, after;
  assert(edr_pt_cache_snapshot_at(92503u, start + 10u, &before) == 0);
  assert(edr_pt_cache_snapshot_at(92503u, start + 10u, &after) == 0);
  assert(before.start_time_ns == after.start_time_ns);
  security.is_security_4688 = 0u;
  assert(edr_process_create_is_lifecycle_authoritative(&security));
  edr_pt_cache_shutdown();
}

static void test_known_generation_rejects_late_and_zero_time_identity_updates(void) {
  assert(edr_local_evidence_cache_open(":memory:", 8u, 24u) == 0);
  struct timespec ts; assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  uint64_t start = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec - 1000000000ULL;
  edr_pt_cache_init(); assert(edr_pt_cache_put(94501u, 1u, "b.exe", "b", "b", "p", start) == 0);
  EdrBehaviorRecord b; init_record(&b, EDR_EVENT_PROCESS_CREATE); b.pid=94501u; b.event_time_ns=(int64_t)(start+1000u);
  snprintf(b.user_sid,sizeof(b.user_sid),"S-B"); snprintf(b.creator_sid,sizeof(b.creator_sid),"C-B"); snprintf(b.exe_path,sizeof(b.exe_path),"B-path"); snprintf(b.identity_quality,sizeof(b.identity_quality),"target_4688"); edr_local_evidence_cache_observe_process(&b);
  EdrEvidenceCacheStatus before; edr_local_evidence_cache_get_status(&before);
  EdrBehaviorRecord late=b; late.event_time_ns=(int64_t)(start-1000u); snprintf(late.user_sid,sizeof(late.user_sid),"S-A"); snprintf(late.creator_sid,sizeof(late.creator_sid),"C-A"); snprintf(late.exe_path,sizeof(late.exe_path),"A-path"); edr_local_evidence_cache_observe_process(&late);
  EdrEvidenceCacheStatus after; edr_local_evidence_cache_get_status(&after);
  assert(after.late_generation_rejects == before.late_generation_rejects + 1u);
  assert(after.generation_unknown_update_rejects == before.generation_unknown_update_rejects);
  EdrBehaviorRecord hit; init_record(&hit, EDR_EVENT_NET_CONNECT); hit.pid=94501u; hit.event_time_ns=(int64_t)(start+2000u); edr_local_evidence_cache_enrich_behavior(&hit);
  assert(strcmp(hit.user_sid,"S-B")==0 && strcmp(hit.creator_sid,"C-B")==0 && strcmp(hit.exe_path,"B-path")==0);
  EdrBehaviorRecord zero=b; zero.event_time_ns=0; snprintf(zero.user_sid,sizeof(zero.user_sid),"S-zero"); edr_local_evidence_cache_observe_process(&zero);
  edr_local_evidence_cache_get_status(&after); assert(after.generation_unknown_update_rejects == before.generation_unknown_update_rejects + 1u);
  edr_pt_cache_shutdown(); edr_local_evidence_cache_close();
}

static void test_identity_generation_mismatch_and_quality_order(void) {
  assert(edr_local_evidence_cache_open(":memory:", 8u, 24u) == 0);
  struct timespec ts; assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  uint64_t now = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
  edr_pt_cache_init();
  assert(edr_pt_cache_put(93001u, 1u, "a.exe", "a", "a", "p", now - 3000000000ULL) == 0);
  EdrBehaviorRecord creator;
  init_record(&creator, EDR_EVENT_PROCESS_CREATE); creator.pid = 93001u; creator.event_time_ns = (int64_t)(now - 2000000000ULL);
  snprintf(creator.username, sizeof(creator.username), "ACME\\creator");
  snprintf(creator.user_sid, sizeof(creator.user_sid), "S-creator");
  snprintf(creator.identity_quality, sizeof(creator.identity_quality), "creator_fallback");
  edr_local_evidence_cache_observe_process(&creator);
  EdrBehaviorRecord target = creator;
  snprintf(target.username, sizeof(target.username), "ACME\\target");
  snprintf(target.user_sid, sizeof(target.user_sid), "S-target");
  snprintf(target.identity_quality, sizeof(target.identity_quality), "target_4688");
  edr_local_evidence_cache_observe_process(&target);
  EdrBehaviorRecord lower = creator;
  snprintf(lower.username, sizeof(lower.username), "ACME\\lower");
  snprintf(lower.identity_quality, sizeof(lower.identity_quality), "token_sid");
  edr_local_evidence_cache_observe_process(&lower);
  EdrBehaviorRecord same;
  init_record(&same, EDR_EVENT_NET_CONNECT); same.pid = 93001u; same.event_time_ns = (int64_t)(now - 500000000ULL);
  edr_local_evidence_cache_enrich_behavior(&same);
  assert(strcmp(same.username, "ACME\\target") == 0 && strcmp(same.user_sid, "S-target") == 0);
  assert(strcmp(same.identity_quality, "target_4688") == 0);
  assert(edr_pt_cache_mark_exit(93001u, now - 1000000000ULL) == 0);
  assert(edr_pt_cache_put(93001u, 2u, "b.exe", "b", "b", "p", now) == 0);
  EdrBehaviorRecord reused;
  init_record(&reused, EDR_EVENT_NET_CONNECT); reused.pid = 93001u; reused.event_time_ns = (int64_t)(now + 1000u);
  edr_local_evidence_cache_enrich_behavior(&reused);
  EdrEvidenceCacheStatus st; edr_local_evidence_cache_get_status(&st);
  assert(!reused.username[0]);
  assert(st.identity_generation_mismatch_rejects == 1u && st.identity_cache_misses == 1u);
  /* Slot retains target evidence despite later lower-quality observation. */
  /* Only creator->target is a quality upgrade; later token must not add one. */
  assert(st.identity_upgrades == 1u);
  edr_pt_cache_shutdown(); edr_local_evidence_cache_close();
}

static void test_kernel_generation_a_to_b_resets_cached_identity_once(void) {
  assert(edr_local_evidence_cache_open(":memory:", 8u, 24u) == 0);
  struct timespec ts; assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  uint64_t now = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
  const uint32_t pid = 93002u;
  edr_pt_cache_init();
  assert(edr_pt_cache_put(pid, 1u, "a.exe", "cmd-A", "A-path", "p", now - 3000000000ULL) == 0);
  EdrBehaviorRecord a; init_record(&a, EDR_EVENT_PROCESS_CREATE);
  a.pid = pid; a.event_time_ns = (int64_t)(now - 2000000000ULL);
  snprintf(a.username, sizeof(a.username), "A-user"); snprintf(a.user_sid, sizeof(a.user_sid), "S-A");
  snprintf(a.creator_sid, sizeof(a.creator_sid), "C-A"); snprintf(a.exe_path, sizeof(a.exe_path), "A-path");
  snprintf(a.cmdline, sizeof(a.cmdline), "cmd-A"); snprintf(a.identity_quality, sizeof(a.identity_quality), "target_4688");
  edr_local_evidence_cache_observe_process(&a);
  assert(edr_pt_cache_mark_exit(pid, now - 1000000000ULL) == 0);
  assert(edr_pt_cache_put(pid, 2u, "b.exe", "cmd-B", "B-path", "p", now) == 0);
  EdrEvidenceCacheStatus before, after; edr_local_evidence_cache_get_status(&before);
  EdrBehaviorRecord b; init_record(&b, EDR_EVENT_PROCESS_CREATE);
  b.pid = pid; b.event_time_ns = (int64_t)(now + 1000u);
  snprintf(b.user_sid, sizeof(b.user_sid), "S-B"); snprintf(b.creator_sid, sizeof(b.creator_sid), "C-B");
  snprintf(b.exe_path, sizeof(b.exe_path), "B-path"); snprintf(b.cmdline, sizeof(b.cmdline), "cmd-B");
  snprintf(b.identity_quality, sizeof(b.identity_quality), "target_4688");
  edr_local_evidence_cache_observe_process(&b);
  EdrBehaviorRecord hit; init_record(&hit, EDR_EVENT_NET_CONNECT);
  hit.pid = pid; hit.event_time_ns = (int64_t)(now + 2000u);
  edr_local_evidence_cache_enrich_behavior(&hit);
  edr_local_evidence_cache_get_status(&after);
  assert(after.generation_resets == before.generation_resets + 1u);
  assert(after.process_slots_used == before.process_slots_used && after.process_cache_evictions == before.process_cache_evictions);
  assert(!hit.username[0] && strcmp(hit.user_sid, "S-B") == 0 && strcmp(hit.creator_sid, "C-B") == 0);
  assert(strcmp(hit.exe_path, "B-path") == 0 && strcmp(hit.cmdline, "cmd-B") == 0);
  assert(strstr(hit.user_sid, "S-A") == NULL && strstr(hit.creator_sid, "C-A") == NULL && strstr(hit.exe_path, "A-path") == NULL);
  edr_pt_cache_shutdown(); edr_local_evidence_cache_close();
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
  int truncated = 0;
  assert(edr_local_evidence_cache_query_file_hash_json(hash, "", ".exe", 10u, rows,
                                                        sizeof(rows), &returned, &scanned,
                                                        &truncated) == 0);
  assert(truncated == 0);
  assert(returned == 1u);
  assert(scanned >= 1u);
  assert(strstr(rows, "\"source\":\"file_evidence\"") != NULL);
  assert(strstr(rows, "\"cache_hit\":true") != NULL);
  assert(strstr(rows, "dropper.exe") != NULL);
  assert(strstr(rows, hash) != NULL);

  char tiny_rows[96];
  returned = 99u;
  scanned = 0u;
  truncated = 0;
  assert(edr_local_evidence_cache_query_file_hash_json(hash, "", ".exe", 10u, tiny_rows,
                                                        sizeof(tiny_rows), &returned, &scanned,
                                                        &truncated) == 0);
  assert(truncated == 1);
  assert(returned == 0u);
  assert(strcmp(tiny_rows, "[]") == 0);

  returned = 99u;
  scanned = 99u;
  truncated = 0;
  assert(edr_local_evidence_cache_query_file_hash_json(miss, "", ".exe", 10u, rows,
                                                        sizeof(rows), &returned, &scanned,
                                                        &truncated) == 0);
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
  test_identity_status_counter_basics();
  test_identity_generation_match_delta();
  test_sid_only_identity_enriches_same_generation();
  test_unknown_generation_identity_never_survives_to_later_kernel_generation();
  test_security_4688_identity_none_is_not_lifecycle_authoritative();
  test_known_generation_rejects_late_and_zero_time_identity_updates();
  test_identity_generation_mismatch_and_quality_order();
  test_kernel_generation_a_to_b_resets_cached_identity_once();
  test_file_sha256_query_uses_file_evidence_cache();
  puts("test_local_evidence_cache_candidate: ok");
  return 0;
}
