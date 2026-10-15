#include "edr/error.h"
#include "edr/sha256.h"
#include "edr/time_util.h"
#include "edr/report_events_ack.h"
#include "edr/storage_queue.h"
#include "edr/egress_batch_policy.h"
#include "../src/core/queue_retention_health_json.h"
#include "cJSON.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sqlite3.h>

/* Test-only inventory fault; no production API or runtime switch. */
void edr_storage_queue_test_fail_source_owner_inventory_reads(unsigned count);

#if defined(_WIN32)
#include <windows.h>
#include <process.h>
#define TEST_PID _getpid()
#else
#include <pthread.h>
#include <unistd.h>
#define TEST_PID getpid()
#endif

static int test_setenv(const char *name, const char *value) {
#ifdef _WIN32
  return _putenv_s(name, value);
#else
  return setenv(name, value, 1);
#endif
}

static int test_unsetenv(const char *name) {
#ifdef _WIN32
  return _putenv_s(name, "");
#else
  return unsetenv(name);
#endif
}

static void test_sleep_ms(unsigned milliseconds) {
#ifdef _WIN32
  Sleep(milliseconds);
#else
  assert(usleep(milliseconds * 1000u) == 0);
#endif
}

static int s_policy_reject_value = -1;
/* Queue state tests isolate the semantic codec; the real-codec acceptance
 * matrix is test_egress_batch_policy. Rejection here drives durable states. */
int edr_egress_batch_validate(const uint8_t *header, size_t header_len,
    const uint8_t *payload, size_t payload_len, char *reason, size_t reason_cap) {
  (void)header; (void)header_len;
  int accepted = !(payload && payload_len >= 5u && payload[4] == s_policy_reject_value);
  if (reason && reason_cap) snprintf(reason, reason_cap, "%s",
                                     accepted ? "eligible" : "synthetic_policy_rejected");
  return accepted;
}
/* This suite cannot assert recovery semantic admission. The separate
 * queue_recovery_v1_contract links the real projector and protobuf parser. */
int edr_egress_batch_project_alerts(const uint8_t *header,size_t header_len,
    const uint8_t *payload,size_t payload_len,const char *tenant,const char *endpoint,
    uint8_t **out,size_t *out_len,uint32_t *frames,char *reason,size_t cap) {
  (void)tenant; (void)endpoint;
  *out=NULL; *out_len=0; *frames=0;
  (void)header; (void)header_len; (void)payload; (void)payload_len;
  snprintf(reason,cap,"test_projection_semantics_unavailable"); return 0;
}
int edr_egress_batch_note_queue_removed(const uint8_t *header,size_t header_len,
    const uint8_t *payload,size_t len,char *reason,size_t cap) {
  (void)header; (void)header_len; (void)payload; (void)len;
  if (reason && cap) snprintf(reason,cap,"no_test_finalizer"); return 1;
}
void edr_egress_set_p0_pair_validator(EdrEgressP0PairValidator fn,void *user) {
  (void)fn; (void)user; /* Actual association semantics covered by the real codec suite. */
}
int edr_egress_p0_combined_matches(const EdrEgressP0PairAssociation *tuple,
    const uint8_t *wire,size_t len) { (void)tuple; (void)wire; (void)len; return 0; }
int edr_egress_p0_intent_matches(const EdrEgressP0PairAssociation *tuple,
    const uint8_t *wire,size_t len) { (void)tuple; (void)wire; (void)len; return 0; }
static int s_send_ok;
static int s_configured = 1;
static int s_circuit_open;
static int s_reject_value = -1;
static const char *s_receipt_body;
static int s_telemetry_deferred;
static int s_defer_during_send;
static unsigned s_send_calls;
static unsigned s_send_value_calls[256];
static uint8_t s_last_payload[131072];
static size_t s_last_payload_len;

#if !defined(_WIN32)
static int s_block_send;
static int s_send_started;
static pthread_mutex_t s_send_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t s_send_cond = PTHREAD_COND_INITIALIZER;

static void reset_send_state(int send_ok) {
  pthread_mutex_lock(&s_send_lock);
  s_send_ok = send_ok;
  s_configured = 1;
  s_circuit_open = 0;
  s_reject_value = -1;
  s_receipt_body = NULL;
  s_telemetry_deferred = s_defer_during_send = 0;
  s_send_calls = 0u;
  memset(s_send_value_calls, 0, sizeof(s_send_value_calls));
  s_last_payload_len = 0u;
  s_block_send = 0;
  s_send_started = 0;
  pthread_mutex_unlock(&s_send_lock);
}

static void block_next_send(void) {
  pthread_mutex_lock(&s_send_lock);
  s_block_send = 1;
  s_send_started = 0;
  pthread_mutex_unlock(&s_send_lock);
}

static void wait_for_send(void) {
  pthread_mutex_lock(&s_send_lock);
  while (!s_send_started) pthread_cond_wait(&s_send_cond, &s_send_lock);
  pthread_mutex_unlock(&s_send_lock);
}

static void release_send(void) {
  pthread_mutex_lock(&s_send_lock);
  s_block_send = 0;
  pthread_cond_broadcast(&s_send_cond);
  pthread_mutex_unlock(&s_send_lock);
}

static unsigned send_calls_for(uint8_t value) {
  unsigned calls;
  pthread_mutex_lock(&s_send_lock);
  calls = s_send_value_calls[value];
  pthread_mutex_unlock(&s_send_lock);
  return calls;
}

static unsigned total_send_calls(void) {
  unsigned calls;
  pthread_mutex_lock(&s_send_lock);
  calls = s_send_calls;
  pthread_mutex_unlock(&s_send_lock);
  return calls;
}
#else
static void reset_send_state(int send_ok) {
  s_send_ok = send_ok;
  s_configured = 1;
  s_circuit_open = 0;
  s_reject_value = -1;
  s_receipt_body = NULL;
  s_telemetry_deferred = s_defer_during_send = 0;
  s_send_calls = 0u;
  memset(s_send_value_calls, 0, sizeof(s_send_value_calls));
  s_last_payload_len = 0u;
}

static unsigned send_calls_for(uint8_t value) { return s_send_value_calls[value]; }
static unsigned total_send_calls(void) { return s_send_calls; }
#endif

int edr_ingest_http_configured(void) { return s_configured; }
int edr_ingest_http_circuit_open(void) { return s_circuit_open; }
int edr_ingest_http_telemetry_deferred(void) { return s_telemetry_deferred; }
int edr_transport_v2_report_events(const char *batch_id, const uint8_t *header12,
                                   size_t header_len, const uint8_t *payload,
                                   size_t payload_len) {
  (void)batch_id;
  assert(header_len == 12u);
  assert(payload_len + header_len <= sizeof(s_last_payload));
#if !defined(_WIN32)
  pthread_mutex_lock(&s_send_lock);
#endif
  /* Force allocator churn after queue finalized its SQLite statement. */
  void *churn = malloc(32768u);
  assert(churn != NULL);
  memset(churn, 0x5a, 32768u);
  memcpy(s_last_payload, header12, header_len);
  memcpy(s_last_payload + header_len, payload, payload_len);
  s_last_payload_len = header_len + payload_len;
  if (s_defer_during_send) s_telemetry_deferred = 1;
  free(churn);
#if !defined(_WIN32)
  s_send_calls++;
  if (payload_len >= 5u) s_send_value_calls[payload[4]]++;
  if (s_block_send) {
    s_send_started = 1;
    pthread_cond_broadcast(&s_send_cond);
    while (s_block_send) pthread_cond_wait(&s_send_cond, &s_send_lock);
  }
  int result = (s_send_ok && (payload_len < 5u || payload[4] != s_reject_value) &&
      (!s_receipt_body || edr_report_events_acknowledged(s_receipt_body, "test-endpoint", batch_id, header12, header_len, payload, payload_len))) ? 0 : -1;
  pthread_mutex_unlock(&s_send_lock);
  return result;
#else
  s_send_calls++;
  if (payload_len >= 5u) s_send_value_calls[payload[4]]++;
  return (s_send_ok && (payload_len < 5u || payload[4] != s_reject_value) &&
      (!s_receipt_body || edr_report_events_acknowledged(s_receipt_body, "test-endpoint", batch_id, header12, header_len, payload, payload_len))) ? 0 : -1;
#endif
}

static void make_wire(uint8_t out[20], uint8_t value) {
  static const uint8_t header[] = {0x42, 0x41, 0x54, 0x31, 1, 0, 0, 0, 8, 0, 0, 0};
  memcpy(out, header, sizeof(header));
  out[12] = 4; out[13] = 0; out[14] = 0; out[15] = 0;
  out[16] = value; out[17] = (uint8_t)(value + 1u); out[18] = 0xa5u; out[19] = 0x5au;
}

static void make_large_wire(uint8_t *out, size_t out_len, uint8_t value) {
  uint32_t body_len;
  uint32_t frame_len;
  assert(out != NULL && out_len >= 20u && out_len <= UINT32_MAX);
  body_len = (uint32_t)(out_len - 12u);
  frame_len = (uint32_t)(out_len - 16u);
  memset(out, 0, out_len);
  out[0] = 0x42u; out[1] = 0x41u; out[2] = 0x54u; out[3] = 0x31u;
  out[4] = 1u;
  out[8] = (uint8_t)body_len;
  out[9] = (uint8_t)(body_len >> 8u);
  out[10] = (uint8_t)(body_len >> 16u);
  out[11] = (uint8_t)(body_len >> 24u);
  out[12] = (uint8_t)frame_len;
  out[13] = (uint8_t)(frame_len >> 8u);
  out[14] = (uint8_t)(frame_len >> 16u);
  out[15] = (uint8_t)(frame_len >> 24u);
  out[16] = value;
}

static int status_count(const char *path, const char *status) {
  sqlite3 *db = NULL;
  sqlite3_stmt *st = NULL;
  int count = -1;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM event_queue WHERE status=?;", -1, &st, NULL) == SQLITE_OK);
  sqlite3_bind_text(st, 1, status, -1, SQLITE_TRANSIENT);
  if (sqlite3_step(st) == SQLITE_ROW) count = sqlite3_column_int(st, 0);
  sqlite3_finalize(st);
  sqlite3_close(db);
  return count;
}

static int event_queue_id_status_reason_payload_is(const char *path, sqlite3_int64 id,
                                                   const char *want_status,
                                                   const char *want_reason,
                                                   int want_payload_len) {
  sqlite3 *db = NULL;
  sqlite3_stmt *st = NULL;
  int matches = 0;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(
             db, "SELECT status,terminal_reason,COALESCE(length(payload),0),terminal_at "
                 "FROM event_queue WHERE id=?;",
             -1, &st, NULL) == SQLITE_OK);
  sqlite3_bind_int64(st, 1, id);
  if (sqlite3_step(st) == SQLITE_ROW) {
    const char *status = (const char *)sqlite3_column_text(st, 0);
    const char *reason = (const char *)sqlite3_column_text(st, 1);
    matches = status && reason && strcmp(status, want_status) == 0 &&
              strcmp(reason, want_reason) == 0 &&
              sqlite3_column_int(st, 2) == want_payload_len && sqlite3_column_int64(st, 3) > 0;
  }
  sqlite3_finalize(st);
  sqlite3_close(db);
  return matches;
}

static sqlite3_int64 batch_retry_count(const char *path, const char *batch_id) {
  sqlite3 *db = NULL;
  sqlite3_stmt *st = NULL;
  sqlite3_int64 count = -1;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(db, "SELECT retry_count FROM event_queue WHERE batch_id=?;", -1,
                            &st, NULL) == SQLITE_OK);
  sqlite3_bind_text(st, 1, batch_id, -1, SQLITE_TRANSIENT);
  if (sqlite3_step(st) == SQLITE_ROW) count = sqlite3_column_int64(st, 0);
  sqlite3_finalize(st);
  sqlite3_close(db);
  return count;
}

static void sqlite_exec_path(const char *path, const char *sql) {
  sqlite3 *db = NULL;
  char *err = NULL;
  int rc;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  rc = sqlite3_exec(db, sql, NULL, NULL, &err);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "sqlite test setup failed rc=%d path=%s error=%s sql=%s\n", rc, path,
            err ? err : sqlite3_errmsg(db), sql);
  }
  assert(rc == SQLITE_OK);
  sqlite3_free(err);
  assert(sqlite3_close(db) == SQLITE_OK);
}

static uint64_t sqlite_scalar_path(const char *path, const char *sql) {
  sqlite3 *db = NULL;
  sqlite3_stmt *st = NULL;
  sqlite3_int64 value;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK);
  assert(sqlite3_step(st) == SQLITE_ROW);
  value = sqlite3_column_int64(st, 0);
  assert(value >= 0);
  sqlite3_finalize(st);
  assert(sqlite3_close(db) == SQLITE_OK);
  return (uint64_t)value;
}

static void assert_sqlite_write_rejected(const char *path, const char *sql) {
  sqlite3 *db = NULL;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_CONSTRAINT);
  assert(sqlite3_close(db) == SQLITE_OK);
}

/* Independent inventory oracle: deliberately scan the retained owner tables
 * in tests, including reservations and metadata. Production admission must
 * obtain this same total without visiting every retained payload. Text is charged as
 * stored UTF-8 bytes, matching admission; this is not physical SQLite allocation. */
static uint64_t assert_capacity_matches_inventory(const char *path) {
  EdrStorageQueueCapacityMetrics metrics;
  uint64_t expected = sqlite_scalar_path(path,
      "SELECT COALESCE(SUM(length(CAST(batch_id AS BLOB))+length(payload)+512+"
      "CASE WHEN recovery_version>0 THEN 512 ELSE 0 END),0) FROM event_queue;");
  uint64_t typed_cost=sqlite_scalar_path(path,
      "SELECT COALESCE(SUM(512+length(CAST(local_source_event_id AS BLOB))+length(CAST(local_reason AS BLOB))+"
      "4*(length(CAST(local_endpoint_id AS BLOB))+length(CAST(local_tenant_id AS BLOB)))+"
      "2*(length(CAST(local_start_key AS BLOB))+length(CAST(local_birth AS BLOB)))+"
      "length(CAST(local_parent_start_key AS BLOB))+length(CAST(local_parent_birth AS BLOB))+"
      "length(CAST(local_payload_sha256 AS BLOB))+length(CAST(local_owner_sha256 AS BLOB))),0) "
      "FROM event_queue WHERE retention_policy_version=2;");
  expected+=typed_cost;
  expected += sqlite_scalar_path(path,
      "SELECT COALESCE(SUM(length(CAST(idempotency_key AS BLOB))+length(CAST(source_event_key AS BLOB))+length(CAST(rule_id AS BLOB))+"
      "length(CAST(process_generation_key AS BLOB))+15+length(CAST(intent_batch_id AS BLOB))+"
      "COALESCE(length(intent_wire),0)+1024+"
      "MAX(length(CAST(source_batch_id AS BLOB))+COALESCE(length(source_wire),0)+"
      "length(CAST(combined_batch_id AS BLOB))+COALESCE(length(combined_wire),0),reserved_bytes)+"
      "CASE WHEN retention_policy_version=3 THEN 2048 ELSE 0 END),0) "
      "FROM enforcement_terminal_journal;");
  expected += sqlite_scalar_path(path,
      "SELECT COALESCE(SUM(length(CAST(key_sha256 AS BLOB))+length(CAST(payload_sha256 AS BLOB))+COALESCE(length(payload),0)+"
      "512+CASE WHEN state='completed' THEN length(CAST(terminal_reason AS BLOB)) ELSE 255 END),0) "
      "FROM p0_deferred_match;");
  expected += sqlite_scalar_path(path, "SELECT COUNT(*)*512 FROM queue_projection_relations;");
  expected += sqlite_scalar_path(path,
      "SELECT CASE WHEN length(CAST(legacy_lineage AS BLOB))>0 THEN 2048 ELSE 0 END+"
      "CASE WHEN length(CAST(last_recovery_snapshot AS BLOB))>0 THEN 2048 ELSE 0 END FROM queue_meta WHERE id=1;");
  edr_storage_queue_get_capacity_metrics(&metrics);
  assert(metrics.accounting_available == 1u);
  if (metrics.used_bytes != expected) {
    fprintf(stderr, "ledger mismatch: reported=%llu inventory=%llu\n",
            (unsigned long long)metrics.used_bytes, (unsigned long long)expected);
  }
  assert(metrics.used_bytes == expected);
  assert(metrics.ledger_version == 1u);
  {
    const uint64_t rows[] = {metrics.retention_legacy_rows, metrics.retention_local_rows,
                            metrics.retention_delivery_rows, metrics.retention_recovery_rows};
    const uint64_t bytes[] = {metrics.retention_legacy_bytes, metrics.retention_local_bytes,
                             metrics.retention_delivery_bytes, metrics.retention_recovery_bytes};
    char query[256];
    for (unsigned i = 0u; i < 4u; ++i) {
      snprintf(query, sizeof(query), "SELECT COUNT(*) FROM event_queue WHERE retention_class=%u;", i);
      assert(rows[i] == sqlite_scalar_path(path, query));
      snprintf(query, sizeof(query), "SELECT COALESCE(SUM(length(CAST(batch_id AS BLOB))+length(payload)+512+"
               "CASE WHEN recovery_version>0 THEN 512 ELSE 0 END),0) FROM event_queue WHERE retention_class=%u;", i);
      assert(bytes[i] == sqlite_scalar_path(path, query)+(i==1u?typed_cost:0u));
    }
  }
  return expected;
}

static void assert_retention_health_projection(void) {
  EdrStorageQueueCapacityMetrics metrics;
  char json[2048], small[8];
  cJSON *root, *field, *local;
  edr_storage_queue_get_capacity_metrics(&metrics);
  assert(metrics.accounting_available && metrics.ledger_version == 1u);
  assert(edr_queue_retention_health_json(&metrics, json, sizeof(json)) == 0);
  root = cJSON_Parse(json); assert(cJSON_IsObject(root));
  assert(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root, "accounting_available")));
  assert(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root, "retirement_enabled")));
  field=cJSON_GetObjectItemCaseSensitive(root,"local_retention_policy_version");
  assert(cJSON_IsNumber(field) && field->valueint==2);
  assert(cJSON_GetObjectItemCaseSensitive(root,"typed_rows")->valuedouble==(double)metrics.local_retention_typed_rows);
  assert(cJSON_GetObjectItemCaseSensitive(root,"retired_rows")->valuedouble==(double)metrics.local_retired_rows);
  field = cJSON_GetObjectItemCaseSensitive(root, "state");
  assert(cJSON_IsString(field) && strcmp(field->valuestring, "retained") == 0);
  local = cJSON_GetObjectItemCaseSensitive(root, "local_v3");
  assert(cJSON_IsObject(local));
  field = cJSON_GetObjectItemCaseSensitive(local, "rows");
  assert(cJSON_IsNumber(field) && field->valuedouble == (double)metrics.retention_local_rows);
  field = cJSON_GetObjectItemCaseSensitive(local, "bytes");
  assert(cJSON_IsNumber(field) && field->valuedouble == (double)metrics.retention_local_bytes);
  /* Fixed aggregate keys, no raw batch identifiers or payload fields. */
  assert(!strstr(json,"source_event_id") && !strstr(json,"payload") && !strstr(json,"cmdline"));
  assert(cJSON_GetArraySize(local) == 2);
  cJSON_Delete(root);
  assert(edr_queue_retention_health_json(&metrics, small, sizeof(small)) == -1 && small[0] == '\0');
  metrics.accounting_available = 0u;
  assert(edr_queue_retention_health_json(&metrics, json, sizeof(json)) == 0);
  root = cJSON_Parse(json); assert(cJSON_IsObject(root));
  assert(cJSON_GetArraySize(root) == 1);
  assert(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(root, "accounting_available")));
  cJSON_Delete(root);
  metrics.accounting_available = 1u; metrics.ledger_version = 0u;
  assert(edr_queue_retention_health_json(&metrics, json, sizeof(json)) == 0);
  assert(strcmp(json, "{\"accounting_available\":false}") == 0);
  metrics.ledger_version = 1u;
  metrics.retention_legacy_rows = metrics.retention_legacy_bytes = UINT64_MAX;
  metrics.retention_local_rows = metrics.retention_local_bytes = UINT64_MAX;
  metrics.retention_delivery_rows = metrics.retention_delivery_bytes = UINT64_MAX;
  metrics.retention_recovery_rows = metrics.retention_recovery_bytes = UINT64_MAX;
  metrics.terminal_journal_bytes = metrics.deferred_bytes = UINT64_MAX;
  metrics.projection_relation_bytes = metrics.recovery_metadata_bytes = UINT64_MAX;
  metrics.local_retention_typed_rows = metrics.local_retention_unclassified_rows = UINT64_MAX;
  metrics.local_retired_rows = metrics.local_retired_bytes = UINT64_MAX;
  metrics.local_retention_protected_slices = metrics.local_retention_integrity_failures = UINT64_MAX;
  metrics.terminal_local_retired_rows = metrics.terminal_local_retired_bytes = UINT64_MAX;
  metrics.maintenance_oversize_holds = metrics.maintenance_failures = UINT64_MAX;
  metrics.physical_admission_failures = metrics.physical_available_bytes = UINT64_MAX;
  metrics.physical_required_bytes = metrics.physical_min_free_bytes = UINT64_MAX;
  metrics.physical_failure_kind = UINT32_MAX;
  assert(edr_queue_retention_health_json(&metrics, json, sizeof(json)) == 0);
  assert(strlen(json) < sizeof(json));
  assert(strstr(json, "18446744073709551615"));
  root = cJSON_Parse(json); assert(cJSON_IsObject(root)); cJSON_Delete(root);
}

static sqlite3_int64 batch_row_id(const char *path, const char *batch_id) {
  sqlite3 *db = NULL;
  sqlite3_stmt *st = NULL;
  sqlite3_int64 id = -1;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(db, "SELECT id FROM event_queue WHERE batch_id=?;", -1, &st, NULL) == SQLITE_OK);
  sqlite3_bind_text(st, 1, batch_id, -1, SQLITE_TRANSIENT);
  if (sqlite3_step(st) == SQLITE_ROW) id = sqlite3_column_int64(st, 0);
  sqlite3_finalize(st);
  sqlite3_close(db);
  return id;
}

static void snapshot_key(const uint8_t *payload, size_t payload_len, char key[65]) {
  assert(payload != NULL && payload_len > 0u);
  assert(edr_sha256_hex(payload, payload_len, key) == 0);
}

static int p0_deferred_state_matches(const char *path, const char *key,
                                     const char *state, int payload_len,
                                     const char *reason) {
  sqlite3 *db = NULL;
  sqlite3_stmt *st = NULL;
  int matches = 0;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(
             db,
             "SELECT state,COALESCE(length(payload),0),terminal_reason,last_error "
             "FROM p0_deferred_match WHERE key_sha256=?;",
             -1, &st, NULL) == SQLITE_OK);
  sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
  if (sqlite3_step(st) == SQLITE_ROW) {
    const char *actual_state = (const char *)sqlite3_column_text(st, 0);
    const char *terminal_reason = (const char *)sqlite3_column_text(st, 2);
    const char *last_error = (const char *)sqlite3_column_text(st, 3);
    const char *actual_reason = strcmp(state, "completed") == 0 ? terminal_reason : last_error;
    matches = actual_state && actual_reason && strcmp(actual_state, state) == 0 &&
        sqlite3_column_int(st, 1) == payload_len && strcmp(actual_reason, reason) == 0;
  }
  sqlite3_finalize(st);
  sqlite3_close(db);
  return matches;
}

static int p0_deferred_count(const char *path, const char *state) {
  sqlite3 *db = NULL;
  sqlite3_stmt *st = NULL;
  int count = -1;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(
             db, "SELECT COUNT(*) FROM p0_deferred_match WHERE state=?;",
             -1, &st, NULL) == SQLITE_OK);
  sqlite3_bind_text(st, 1, state, -1, SQLITE_TRANSIENT);
  if (sqlite3_step(st) == SQLITE_ROW) count = sqlite3_column_int(st, 0);
  sqlite3_finalize(st);
  sqlite3_close(db);
  return count;
}

static void p0_deferred_retry_values(const char *path, const char *key,
                                     sqlite3_int64 *retry_count,
                                     sqlite3_int64 *next_retry_at) {
  sqlite3 *db = NULL;
  sqlite3_stmt *st = NULL;
  assert(retry_count && next_retry_at);
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(
             db,
             "SELECT retry_count,next_retry_at FROM p0_deferred_match WHERE key_sha256=?;",
             -1, &st, NULL) == SQLITE_OK);
  sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
  assert(sqlite3_step(st) == SQLITE_ROW);
  *retry_count = sqlite3_column_int64(st, 0);
  *next_retry_at = sqlite3_column_int64(st, 1);
  sqlite3_finalize(st);
  sqlite3_close(db);
}

static void p0_deferred_exec_sql(const char *path, const char *sql) {
  sqlite3 *db = NULL;
  char *error = NULL;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_exec(db, sql, NULL, NULL, &error) == SQLITE_OK);
  sqlite3_free(error);
  assert(sqlite3_close(db) == SQLITE_OK);
}

#if !defined(_WIN32)
typedef struct { unsigned id; } EnqueueWork;
static void *enqueue_worker(void *arg) {
  EnqueueWork *work = arg;
  uint8_t wire[20];
  char batch_id[64];
  make_wire(wire, (uint8_t)work->id);
  snprintf(batch_id, sizeof(batch_id), "concurrent-%u", work->id);
  assert(edr_storage_queue_enqueue(batch_id, wire, sizeof(wire), 0, 0) == EDR_OK);
  return NULL;
}

static void *drain_worker(void *arg) {
  (void)arg;
  edr_storage_queue_poll_drain();
  return NULL;
}

typedef struct {
  const char *key;
  uint32_t family_mask;
  const uint8_t *payload;
  size_t payload_len;
  EdrError result;
} DeferredRetainWork;

static void *deferred_retain_worker(void *arg) {
  DeferredRetainWork *work = (DeferredRetainWork *)arg;
  work->result = edr_storage_queue_p0_deferred_retain(
      work->key, work->family_mask, work->payload, work->payload_len);
  return NULL;
}
#endif

static int terminal_journal_count(const char *path) {
  sqlite3 *db = NULL;
  sqlite3_stmt *st = NULL;
  int count = -1;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM enforcement_terminal_journal;", -1, &st,
                            NULL) == SQLITE_OK);
  if (sqlite3_step(st) == SQLITE_ROW) count = sqlite3_column_int(st, 0);
  sqlite3_finalize(st);
  sqlite3_close(db);
  return count;
}

static int terminal_journal_state_is(const char *path, const char *key, const char *want) {
  sqlite3 *db = NULL;
  sqlite3_stmt *st = NULL;
  int matches = 0;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(
             db, "SELECT state FROM enforcement_terminal_journal WHERE idempotency_key=?;", -1,
             &st, NULL) == SQLITE_OK);
  sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
  if (sqlite3_step(st) == SQLITE_ROW) {
    const unsigned char *state = sqlite3_column_text(st, 0);
    matches = state && strcmp((const char *)state, want) == 0;
  }
  sqlite3_finalize(st);
  sqlite3_close(db);
  return matches;
}

static int terminal_journal_id_state_error_is(const char *path, sqlite3_int64 id,
                                              const char *want_state,
                                              const char *want_error) {
  sqlite3 *db = NULL;
  sqlite3_stmt *st = NULL;
  int matches = 0;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(
             db, "SELECT state,last_error FROM enforcement_terminal_journal WHERE id=?;", -1,
             &st, NULL) == SQLITE_OK);
  sqlite3_bind_int64(st, 1, id);
  if (sqlite3_step(st) == SQLITE_ROW) {
    const char *state = (const char *)sqlite3_column_text(st, 0);
    const char *error = (const char *)sqlite3_column_text(st, 1);
    matches = state && error && strcmp(state, want_state) == 0 &&
              strcmp(error, want_error) == 0;
  }
  sqlite3_finalize(st);
  sqlite3_close(db);
  return matches;
}

/* A permanent terminal failure frees only the future-frame reservation. The
 * row and its durable audit wires remain available for forensic inspection. */
static int terminal_journal_id_failed_releases_reservation_with_wires(
    const char *path, sqlite3_int64 id, int expect_intent, int expect_source,
    int expect_combined) {
  sqlite3 *db = NULL;
  sqlite3_stmt *st = NULL;
  int matches = 0;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(
             db,
             "SELECT state,reserved_bytes,COALESCE(length(intent_wire),0),"
             "COALESCE(length(source_wire),0),COALESCE(length(combined_wire),0) "
             "FROM enforcement_terminal_journal WHERE id=?;",
             -1, &st, NULL) == SQLITE_OK);
  sqlite3_bind_int64(st, 1, id);
  if (sqlite3_step(st) == SQLITE_ROW) {
    const char *state = (const char *)sqlite3_column_text(st, 0);
    sqlite3_int64 reserved = sqlite3_column_int64(st, 1);
    int has_intent = sqlite3_column_int64(st, 2) > 0;
    int has_source = sqlite3_column_int64(st, 3) > 0;
    int has_combined = sqlite3_column_int64(st, 4) > 0;
    matches = state && strcmp(state, "failed") == 0 && reserved == 0 &&
              has_intent == expect_intent && has_source == expect_source &&
              has_combined == expect_combined;
  }
  sqlite3_finalize(st);
  sqlite3_close(db);
  return matches;
}

static int terminal_journal_id_owner_digest_is(const char *path, sqlite3_int64 id) {
  sqlite3 *db = NULL;
  sqlite3_stmt *st = NULL;
  int matches = 0;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(
             db, "SELECT owner_key_sha256 FROM enforcement_terminal_journal WHERE id=?;", -1,
             &st, NULL) == SQLITE_OK);
  sqlite3_bind_int64(st, 1, id);
  if (sqlite3_step(st) == SQLITE_ROW) {
    const unsigned char *digest = sqlite3_column_text(st, 0);
    int len = sqlite3_column_bytes(st, 0);
    matches = digest && len == 64;
    for (int i = 0; matches && i < len; ++i) {
      unsigned char c = digest[i];
      matches = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    }
  }
  sqlite3_finalize(st);
  sqlite3_close(db);
  return matches;
}

static int terminal_journal_owner_digest_unique_index_exists(const char *path) {
  sqlite3 *db = NULL;
  sqlite3_stmt *st = NULL;
  int found = 0;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(db, "PRAGMA index_list(enforcement_terminal_journal);", -1, &st,
                            NULL) == SQLITE_OK);
  while (sqlite3_step(st) == SQLITE_ROW) {
    const char *name = (const char *)sqlite3_column_text(st, 1);
    if (name && strcmp(name, "idx_enforcement_terminal_owner_digest_unique") == 0 &&
        sqlite3_column_int(st, 2) == 1) {
      found = 1;
      break;
    }
  }
  sqlite3_finalize(st);
  sqlite3_close(db);
  return found;
}

static int terminal_owner_corruption_latch_is(const char *path, int want_unresolved,
                                              const char *want_reason) {
  sqlite3 *db = NULL;
  sqlite3_stmt *st = NULL;
  int matches = 0;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(
             db, "SELECT unresolved,reason FROM terminal_owner_corruption_latch WHERE id=1;", -1,
             &st, NULL) == SQLITE_OK);
  if (sqlite3_step(st) == SQLITE_ROW) {
    const char *reason = (const char *)sqlite3_column_text(st, 1);
    matches = sqlite3_column_int(st, 0) == want_unresolved && reason &&
              strcmp(reason, want_reason) == 0;
  }
  sqlite3_finalize(st);
  sqlite3_close(db);
  return matches;
}

static sqlite3_int64 terminal_journal_id_for_key(const char *path, const char *key) {
  sqlite3 *db = NULL;
  sqlite3_stmt *st = NULL;
  sqlite3_int64 id = -1;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(
             db, "SELECT id FROM enforcement_terminal_journal WHERE idempotency_key=?;", -1,
             &st, NULL) == SQLITE_OK);
  sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
  if (sqlite3_step(st) == SQLITE_ROW) id = sqlite3_column_int64(st, 0);
  sqlite3_finalize(st);
  sqlite3_close(db);
  return id;
}

static int terminal_journal_intent_acked(const char *path, const char *key) {
  sqlite3 *db = NULL;
  sqlite3_stmt *st = NULL;
  int acknowledged = -1;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(
             db, "SELECT intent_acked FROM enforcement_terminal_journal WHERE idempotency_key=?;",
             -1, &st, NULL) == SQLITE_OK);
  sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
  if (sqlite3_step(st) == SQLITE_ROW) acknowledged = sqlite3_column_int(st, 0);
  sqlite3_finalize(st);
  sqlite3_close(db);
  return acknowledged;
}

static int terminal_journal_final_acks(const char *path, const char *key,
                                       int *source_acked, int *combined_acked) {
  sqlite3 *db = NULL;
  sqlite3_stmt *st = NULL;
  int found = 0;
  if (source_acked) *source_acked = -1;
  if (combined_acked) *combined_acked = -1;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(
             db, "SELECT source_acked,combined_acked FROM enforcement_terminal_journal "
                 "WHERE idempotency_key=?;", -1, &st, NULL) == SQLITE_OK);
  sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
  if (sqlite3_step(st) == SQLITE_ROW) {
    if (source_acked) *source_acked = sqlite3_column_int(st, 0);
    if (combined_acked) *combined_acked = sqlite3_column_int(st, 1);
    found = 1;
  }
  sqlite3_finalize(st);
  sqlite3_close(db);
  return found;
}

static int terminal_journal_frame_retry_count(const char *path, const char *key,
                                              int source_frame) {
  sqlite3 *db = NULL;
  sqlite3_stmt *st = NULL;
  int count = -1;
  const char *sql = source_frame
                        ? "SELECT source_retry_count FROM enforcement_terminal_journal "
                          "WHERE idempotency_key=?;"
                        : "SELECT combined_retry_count FROM enforcement_terminal_journal "
                          "WHERE idempotency_key=?;";
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK);
  sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
  if (sqlite3_step(st) == SQLITE_ROW) count = sqlite3_column_int(st, 0);
  sqlite3_finalize(st);
  sqlite3_close(db);
  return count;
}

static int terminal_journal_delivery_state_is(const char *path, const char *key,
                                             const char *error, int64_t updated_at) {
  sqlite3 *db = NULL;
  sqlite3_stmt *st = NULL;
  int matches = 0;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(db,
      "SELECT last_error,updated_at FROM enforcement_terminal_journal WHERE idempotency_key=?;",
      -1, &st, NULL) == SQLITE_OK);
  sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
  if (sqlite3_step(st) == SQLITE_ROW) {
    const char *actual = (const char *)sqlite3_column_text(st, 0);
    matches = actual && strcmp(actual, error) == 0 &&
              sqlite3_column_int64(st, 1) == updated_at;
  }
  sqlite3_finalize(st);
  sqlite3_close(db);
  return matches;
}

static void terminal_journal_age_for_retention(const char *path, const char *key) {
  sqlite3 *db = NULL;
  sqlite3_stmt *st = NULL;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(
             db,
             "UPDATE enforcement_terminal_journal SET created_at=1,updated_at=1,"
             "intent_next_retry_at=1,source_next_retry_at=1,combined_next_retry_at=1 "
             "WHERE idempotency_key=?;",
             -1, &st, NULL) == SQLITE_OK);
  sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
  assert(sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(db) == 1);
  sqlite3_finalize(st);
  sqlite3_close(db);
}

static int queue_batch_pending(const char *path, const char *batch_id) {
  sqlite3 *db = NULL;
  sqlite3_stmt *st = NULL;
  int pending = 0;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(db, "SELECT status FROM event_queue WHERE batch_id=?;", -1, &st,
                            NULL) == SQLITE_OK);
  sqlite3_bind_text(st, 1, batch_id, -1, SQLITE_TRANSIENT);
  if (sqlite3_step(st) == SQLITE_ROW) {
    const unsigned char *status = sqlite3_column_text(st, 0);
    pending = status && strcmp((const char *)status, "pending") == 0;
  }
  sqlite3_finalize(st);
  sqlite3_close(db);
  return pending;
}

static int terminal_result_wires_missing(const char *path, const char *key) {
  sqlite3 *db = NULL;
  sqlite3_stmt *st = NULL;
  int missing = 0;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(
             db,
             "SELECT source_wire,combined_wire FROM enforcement_terminal_journal "
             "WHERE idempotency_key=?;",
             -1, &st, NULL) == SQLITE_OK);
  sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
  if (sqlite3_step(st) == SQLITE_ROW) {
    missing = sqlite3_column_type(st, 0) == SQLITE_NULL && sqlite3_column_type(st, 1) == SQLITE_NULL;
  }
  sqlite3_finalize(st);
  sqlite3_close(db);
  return missing;
}

static void test_terminal_journal_durable_commits_and_exact_replay(void) {
  char path[256];
  uint8_t intent[20], source[20], combined[20];
  EdrEnforcementTerminalJournalMetrics metrics;
  snprintf(path, sizeof(path), "edr-terminal-journal-commit-%ld.db", (long)TEST_PID);
  (void)remove(path);
  make_wire(intent, 0x61u);
  make_wire(source, 0x62u);
  make_wire(combined, 0x63u);
  assert(edr_storage_queue_open(path) == EDR_OK);

  edr_storage_queue_test_fail_next_terminal_commits(1u);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "commit-create", "event-create", "R-TERMINAL", "generation-create", "intent-create",
             intent, sizeof(intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_ERROR);
  assert(terminal_journal_count(path) == 0);

  assert(edr_storage_queue_enforcement_terminal_precreate(
             "exact", "event-exact", "R-TERMINAL", "generation-exact", "intent-exact", intent,
             sizeof(intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  edr_storage_queue_enforcement_terminal_get_metrics(&metrics);
  assert(metrics.pending == 1u && metrics.backpressure == 0u && metrics.failed == 0u);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "exact", "event-exact", "R-TERMINAL", "generation-exact", "intent-exact", intent,
             sizeof(intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_EXISTING);
  assert(terminal_journal_count(path) == 1);
  /* A restarted exact generation must never execute again; it is made
   * explicit that the prior action's terminal outcome is unknown. */
  assert(terminal_journal_state_is(path, "exact", "outcome_unknown"));
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "exact", "event-exact", "R-OTHER", "generation-exact", "intent-exact", intent,
             sizeof(intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_CONFLICT);

  assert(edr_storage_queue_enforcement_terminal_precreate(
             "commit-update", "event-update", "R-TERMINAL", "generation-update", "intent-update",
             intent, sizeof(intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  edr_storage_queue_test_fail_next_terminal_commits(1u);
  assert(edr_storage_queue_enforcement_terminal_update(
             "commit-update", "source-update", source, sizeof(source), "combined-update", combined,
             sizeof(combined)) == EDR_ERR_SQLITE_WRITE);
  assert(terminal_journal_state_is(path, "commit-update", "pending_intent"));
  assert(terminal_result_wires_missing(path, "commit-update"));
  assert(edr_storage_queue_enforcement_terminal_update(
             "commit-update", "source-update", source, sizeof(source), "combined-update", combined,
             sizeof(combined)) == EDR_OK);
  assert(terminal_journal_state_is(path, "commit-update", "ready"));
  edr_storage_queue_close();
  (void)remove(path);
}

static int ack_receipt_count(const char *, const char *, const uint8_t *, size_t);

static void test_terminal_journal_recovery_and_independent_acks(void) {
  char path[256];
  uint8_t intent[20], source[20], combined[20];
  snprintf(path, sizeof(path), "edr-terminal-journal-recovery-%ld.db", (long)TEST_PID);
  (void)remove(path);
  make_wire(intent, 0x71u);
  make_wire(source, 0x72u);
  make_wire(combined, 0x73u);
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "crash", "event-crash", "R-TERMINAL", "generation-crash", "intent-crash", intent,
             sizeof(intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  /* Close/reopen models a crash between the durable pre-action intent and the
   * executor/final update. Recovery sends the intent first. */
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  reset_send_state(1);
  edr_storage_queue_poll_drain();
  assert(total_send_calls() == 1u && send_calls_for(0x71u) == 1u);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "crash", "event-crash", "R-TERMINAL", "generation-crash", "intent-crash", intent,
             sizeof(intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_EXISTING);
  assert(terminal_journal_state_is(path, "crash", "outcome_unknown"));
  assert(ack_receipt_count(path, "intent-crash", intent, sizeof(intent)) == 1);

  assert(edr_storage_queue_enforcement_terminal_precreate(
             "final", "event-final", "R-TERMINAL", "generation-final", "intent-final", intent,
             sizeof(intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  assert(edr_storage_queue_enforcement_terminal_update(
             "final", "source-final", source, sizeof(source), "combined-final", combined,
             sizeof(combined)) == EDR_OK);
  /* Simulate source enqueue success and combined enqueue failure. The journal
   * direct replayer sends the unqueued combined frame, then the ordinary
   * source acknowledgement completes the same journal row. */
  assert(edr_storage_queue_enqueue("source-final", source, sizeof(source), 0, 1) == EDR_OK);
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  reset_send_state(1);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0x72u) == 1u && send_calls_for(0x73u) == 1u);
  assert(terminal_journal_state_is(path, "final", "completed"));
  assert(ack_receipt_count(path, "source-final", source, sizeof(source)) == 1);
  assert(ack_receipt_count(path, "combined-final", combined, sizeof(combined)) == 1);

  assert(edr_storage_queue_enforcement_terminal_precreate(
             "both-failed", "event-both", "R-TERMINAL", "generation-both", "intent-both", intent,
             sizeof(intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  assert(edr_storage_queue_enforcement_terminal_update(
             "both-failed", "source-both", source, sizeof(source), "combined-both", combined,
             sizeof(combined)) == EDR_OK);
  /* No ordinary queue copies exist: both final frames still recover from the
   * journal and are independently acknowledged. */
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  reset_send_state(1);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0x72u) == 1u && send_calls_for(0x73u) == 1u);
  assert(terminal_journal_state_is(path, "both-failed", "completed"));
  assert(ack_receipt_count(path, "source-both", source, sizeof(source)) == 1);
  assert(ack_receipt_count(path, "combined-both", combined, sizeof(combined)) == 1);
  edr_storage_queue_close();
  (void)remove(path);
}

/* Exercise the selected terminal-frame handoff itself: the SQLite statement
 * is finalized before transport, a failed send records retry state, and a
 * later selected replay acknowledges both final durable frames. */
static void test_terminal_selected_frame_retry_then_ack(void) {
  char path[256];
  uint8_t intent[20], source[20], combined[20];
  snprintf(path, sizeof(path), "edr-terminal-selected-frame-%ld.db", (long)TEST_PID);
  (void)remove(path);
  make_wire(intent, 0x74u);
  make_wire(source, 0x75u);
  make_wire(combined, 0x76u);
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "selected-frame", "selected-source", "R-TERMINAL", "selected-generation",
             "selected-intent", intent, sizeof(intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  reset_send_state(1);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0x74u) == 1u);
  assert(edr_storage_queue_enforcement_terminal_update(
             "selected-frame", "selected-source-final", source, sizeof(source),
             "selected-combined-final", combined, sizeof(combined)) == EDR_OK);

  /* Reopen resets the poll interval and forces the selected source frame
   * through the transport-error branch before any acknowledgement. */
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  reset_send_state(0);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0x75u) == 1u);
  assert(terminal_journal_frame_retry_count(path, "selected-frame", 1) == 1);
  assert(terminal_journal_state_is(path, "selected-frame", "ready"));

  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  reset_send_state(1);
  edr_storage_queue_test_set_delivery_time((int64_t)time(NULL) + 301);
  edr_storage_queue_poll_drain();
  edr_storage_queue_test_set_delivery_time(-1);
  assert(send_calls_for(0x75u) == 1u && send_calls_for(0x76u) == 1u);
  assert(terminal_journal_state_is(path, "selected-frame", "completed"));
  edr_storage_queue_close();
  (void)remove(path);
}

/* Each selected-frame copy allocation is transient. It must not turn a valid
 * durable final frame into `failed`: the state stays ready, the resource failure is
 * visible, and a later allocation-successful poll sends the same frame. */
static void test_terminal_selected_frame_allocation_failures_preserve_retry(void) {
  for (unsigned kind = 0u; kind < 3u; ++kind) {
    char path[256], key[64], intent_batch[64], source_batch[64], combined_batch[64];
    uint8_t intent[20], source[20], combined[20];
    EdrEnforcementTerminalJournalMetrics before, after;
    uint8_t intent_value = (uint8_t)(0x80u + kind);
    uint8_t source_value = (uint8_t)(0x90u + kind);
    uint8_t combined_value = (uint8_t)(0xa0u + kind);
    snprintf(path, sizeof(path), "edr-terminal-select-alloc-%ld-%u.db",
             (long)TEST_PID, kind);
    snprintf(key, sizeof(key), "select-alloc-%u", kind);
    snprintf(intent_batch, sizeof(intent_batch), "select-alloc-intent-%u", kind);
    snprintf(source_batch, sizeof(source_batch), "select-alloc-source-%u", kind);
    snprintf(combined_batch, sizeof(combined_batch), "select-alloc-combined-%u", kind);
    (void)remove(path);
    make_wire(intent, intent_value);
    make_wire(source, source_value);
    make_wire(combined, combined_value);
    assert(edr_storage_queue_open(path) == EDR_OK);
    assert(edr_storage_queue_enforcement_terminal_precreate(
               key, "select-alloc-event", "R-TERMINAL", "select-alloc-generation",
               intent_batch, intent, sizeof(intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
    reset_send_state(1);
    edr_storage_queue_poll_drain();
    assert(send_calls_for(intent_value) == 1u);
    assert(edr_storage_queue_enforcement_terminal_update(
               key, source_batch, source, sizeof(source), combined_batch, combined,
               sizeof(combined)) == EDR_OK);

    edr_storage_queue_close();
    assert(edr_storage_queue_open(path) == EDR_OK);
    edr_storage_queue_enforcement_terminal_get_metrics(&before);
    edr_storage_queue_test_fail_next_terminal_select_allocations(
        kind == 0u ? 1u : 0u, kind == 1u ? 1u : 0u, kind == 2u ? 1u : 0u);
    reset_send_state(1);
    edr_storage_queue_poll_drain();
    assert(send_calls_for(source_value) == 0u && send_calls_for(combined_value) == 0u);
    assert(terminal_journal_state_is(path, key, "ready"));
    assert(terminal_journal_frame_retry_count(path, key, 1) == 0);
    edr_storage_queue_enforcement_terminal_get_metrics(&after);
    assert(after.replay_selection_transient_failures ==
           before.replay_selection_transient_failures + 1u);

    edr_storage_queue_close();
    assert(edr_storage_queue_open(path) == EDR_OK);
    reset_send_state(1);
    edr_storage_queue_poll_drain();
    assert(send_calls_for(source_value) == 1u && send_calls_for(combined_value) == 1u);
    assert(terminal_journal_state_is(path, key, "completed"));
    edr_storage_queue_close();
    (void)remove(path);
  }
}

/* A genuinely malformed durable wire is distinct from a local copy failure.
 * It must become an explicit terminal failure, which also proves selection
 * retained the durable key needed by the state transition. */
static void test_terminal_selected_frame_invalid_durable_wire_fails(void) {
  char path[256];
  uint8_t intent[20], source[20], combined[20];
  sqlite3_int64 source_failure_id;
  EdrEnforcementTerminalJournalMetrics metrics;
  snprintf(path, sizeof(path), "edr-terminal-invalid-wire-%ld.db", (long)TEST_PID);
  (void)remove(path);
  make_wire(intent, 0xb1u);
  make_wire(source, 0xb2u);
  make_wire(combined, 0xb3u);
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "invalid-wire", "invalid-wire-event", "R-TERMINAL", "invalid-wire-generation",
             "invalid-wire-intent", intent, sizeof(intent)) ==
         EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  reset_send_state(1);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0xb1u) == 1u);
  assert(edr_storage_queue_enforcement_terminal_update(
             "invalid-wire", "invalid-wire-source", source, sizeof(source),
             "invalid-wire-combined", combined, sizeof(combined)) == EDR_OK);
  source_failure_id = terminal_journal_id_for_key(path, "invalid-wire");
  assert(source_failure_id > 0);
  edr_storage_queue_close();

  sqlite_exec_path(path,
                   "UPDATE enforcement_terminal_journal SET source_wire=x'00',reserved_bytes=1 "
                   "WHERE idempotency_key='invalid-wire';");
  assert(edr_storage_queue_open(path) == EDR_OK);
  reset_send_state(1);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0xb2u) == 0u && send_calls_for(0xb3u) == 0u);
  assert(terminal_journal_state_is(path, "invalid-wire", "failed"));
  assert(terminal_journal_id_failed_releases_reservation_with_wires(
      path, source_failure_id, 1, 1, 1));
  edr_storage_queue_enforcement_terminal_get_metrics(&metrics);
  assert(metrics.failed == 1u);
  edr_storage_queue_close();
  (void)remove(path);

  /* The intent-only path uses a different state predicate. A malformed
   * pre-action frame must likewise release its future-frame reservation. */
  snprintf(path, sizeof(path), "edr-terminal-invalid-intent-%ld.db", (long)TEST_PID);
  (void)remove(path);
  make_wire(intent, 0xb4u);
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "invalid-intent", "invalid-intent-event", "R-TERMINAL", "invalid-intent-generation",
             "invalid-intent-batch", intent, sizeof(intent)) ==
         EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  source_failure_id = terminal_journal_id_for_key(path, "invalid-intent");
  assert(source_failure_id > 0);
  edr_storage_queue_close();
  sqlite_exec_path(path,
                   "UPDATE enforcement_terminal_journal SET intent_wire=x'00' "
                   "WHERE idempotency_key='invalid-intent';");
  assert(edr_storage_queue_open(path) == EDR_OK);
  reset_send_state(1);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0xb4u) == 0u);
  assert(terminal_journal_id_state_error_is(
      path, source_failure_id, "failed", "intent_invalid_durable_wire"));
  assert(terminal_journal_id_failed_releases_reservation_with_wires(
      path, source_failure_id, 1, 0, 0));
  edr_storage_queue_close();
  (void)remove(path);
}

/* Empty metadata can exist in an upgraded/corrupted database because the
 * historic schema required NOT NULL but allowed ''. It is durable corruption,
 * not a retryable allocation failure: quarantine the poison row by id and
 * prove the next valid terminal evidence still drains in this same pass. */
static void test_terminal_metadata_corruption_quarantines_without_starvation(void) {
  {
    char path[256];
    uint8_t poison_intent[20], valid_intent[20], valid_source[20], valid_combined[20];
    sqlite3_int64 poison_id;
    EdrEnforcementTerminalJournalMetrics before, after;
    snprintf(path, sizeof(path), "edr-terminal-empty-key-%ld.db", (long)TEST_PID);
    (void)remove(path);
    make_wire(poison_intent, 0xc1u);
    make_wire(valid_intent, 0xc2u);
    make_wire(valid_source, 0xc3u);
    make_wire(valid_combined, 0xc4u);
    assert(edr_storage_queue_open(path) == EDR_OK);
    assert(edr_storage_queue_enforcement_terminal_precreate(
               "poison-key", "poison-event", "R-TERMINAL", "poison-generation",
               "poison-intent", poison_intent, sizeof(poison_intent)) ==
           EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
    assert(edr_storage_queue_enforcement_terminal_precreate(
               "valid-key", "valid-event", "R-TERMINAL", "valid-generation",
               "valid-intent", valid_intent, sizeof(valid_intent)) ==
           EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
    assert(edr_storage_queue_enforcement_terminal_update(
               "valid-key", "valid-source", valid_source, sizeof(valid_source),
               "valid-combined", valid_combined, sizeof(valid_combined)) == EDR_OK);
    poison_id = terminal_journal_id_for_key(path, "poison-key");
    assert(poison_id > 0);
    edr_storage_queue_close();
    sqlite_exec_path(path,
                     "UPDATE enforcement_terminal_journal SET idempotency_key='' "
                     "WHERE idempotency_key='poison-key';");
    assert(edr_storage_queue_open(path) == EDR_OK);
    edr_storage_queue_enforcement_terminal_get_metrics(&before);
    reset_send_state(1);
    edr_storage_queue_poll_drain();
    assert(send_calls_for(0xc1u) == 0u);
    assert(send_calls_for(0xc3u) == 1u && send_calls_for(0xc4u) == 1u);
    assert(terminal_journal_id_state_error_is(
        path, poison_id, "failed", "intent_durable_metadata_invalid"));
    assert(terminal_journal_id_failed_releases_reservation_with_wires(
        path, poison_id, 1, 0, 0));
    assert(terminal_journal_state_is(path, "valid-key", "completed"));
    edr_storage_queue_enforcement_terminal_get_metrics(&after);
    assert(after.replay_metadata_corruption_failures ==
           before.replay_metadata_corruption_failures + 1u);
    assert(after.failed == 1u);
    edr_storage_queue_close();
    (void)remove(path);
  }

  {
    char path[256];
    uint8_t poison_intent[20], poison_source[20], poison_combined[20];
    uint8_t valid_intent[20], valid_source[20], valid_combined[20];
    sqlite3_int64 poison_id;
    EdrEnforcementTerminalJournalMetrics before, after;
    snprintf(path, sizeof(path), "edr-terminal-empty-source-batch-%ld.db", (long)TEST_PID);
    (void)remove(path);
    make_wire(poison_intent, 0xd1u);
    make_wire(poison_source, 0xd2u);
    make_wire(poison_combined, 0xd3u);
    make_wire(valid_intent, 0xd4u);
    make_wire(valid_source, 0xd5u);
    make_wire(valid_combined, 0xd6u);
    assert(edr_storage_queue_open(path) == EDR_OK);
    assert(edr_storage_queue_enforcement_terminal_precreate(
               "poison-source", "poison-source-event", "R-TERMINAL", "poison-source-generation",
               "poison-source-intent", poison_intent, sizeof(poison_intent)) ==
           EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
    assert(edr_storage_queue_enforcement_terminal_precreate(
               "valid-source", "valid-source-event", "R-TERMINAL", "valid-source-generation",
               "valid-source-intent", valid_intent, sizeof(valid_intent)) ==
           EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
    assert(edr_storage_queue_enforcement_terminal_update(
               "poison-source", "poison-source-frame", poison_source, sizeof(poison_source),
               "poison-combined-frame", poison_combined, sizeof(poison_combined)) == EDR_OK);
    assert(edr_storage_queue_enforcement_terminal_update(
               "valid-source", "valid-source-frame", valid_source, sizeof(valid_source),
               "valid-combined-frame", valid_combined, sizeof(valid_combined)) == EDR_OK);
    poison_id = terminal_journal_id_for_key(path, "poison-source");
    assert(poison_id > 0);
    edr_storage_queue_close();
    sqlite_exec_path(path,
                     "UPDATE enforcement_terminal_journal SET source_batch_id='' "
                     "WHERE idempotency_key='poison-source';");
    assert(edr_storage_queue_open(path) == EDR_OK);
    edr_storage_queue_enforcement_terminal_get_metrics(&before);
    reset_send_state(1);
    edr_storage_queue_poll_drain();
    assert(send_calls_for(0xd2u) == 0u && send_calls_for(0xd3u) == 0u);
    assert(send_calls_for(0xd5u) == 1u && send_calls_for(0xd6u) == 1u);
    assert(terminal_journal_id_state_error_is(
        path, poison_id, "failed", "source_durable_metadata_invalid"));
    assert(terminal_journal_id_failed_releases_reservation_with_wires(
        path, poison_id, 1, 1, 1));
    assert(terminal_journal_state_is(path, "valid-source", "completed"));
    edr_storage_queue_enforcement_terminal_get_metrics(&after);
    assert(after.replay_metadata_corruption_failures ==
           before.replay_metadata_corruption_failures + 1u);
    assert(after.failed == 1u);
    edr_storage_queue_close();
    (void)remove(path);
  }
}

/* SQLite TEXT can contain NUL bytes and exceed the production terminal-text
 * bound. Four poisoned intents must be quarantined by row id without C-string
 * truncation, while the later valid terminal completes in this same drain. */
static void test_terminal_failed_rows_release_reserved_capacity(void) {
  enum { poison_rows = 4, ordinary_wire_len = 200000 };
  char path[256];
  uint8_t intent[20], valid_intent[20], valid_source[20], valid_combined[20];
  uint8_t *ordinary_wire;
  sqlite3_int64 poison_ids[poison_rows];
  EdrStorageQueueCapacityMetrics before_fail, after_fail, after_reopen;
  EdrEnforcementTerminalJournalMetrics before_corruption, after_corruption;

  snprintf(path, sizeof(path), "edr-terminal-failed-reserve-%ld.db", (long)TEST_PID);
  (void)remove(path);
  /* The five setup rows need more than the final 1 MiB terminal lane. Reopen
   * under that production-size cap to prove poisoned reservations cannot keep
   * capacity stranded. */
  assert(test_setenv("EDR_QUEUE_MAX_DB_MB", "2") == 0);
  assert(test_setenv("EDR_QUEUE_DRAIN_MAX_ROWS", "8") == 0);
  ordinary_wire = (uint8_t *)malloc(ordinary_wire_len);
  assert(ordinary_wire != NULL);
  make_wire(intent, 0xe1u);
  make_wire(valid_intent, 0xe3u);
  make_wire(valid_source, 0xe4u);
  make_wire(valid_combined, 0xe5u);
  make_large_wire(ordinary_wire, ordinary_wire_len, 0xe2u);

  assert(edr_storage_queue_open(path) == EDR_OK);
  for (unsigned i = 0u; i < poison_rows; ++i) {
    char key[64], event_key[64], generation[64], batch_id[64];
    snprintf(key, sizeof(key), "reserve-poison-%u", i);
    snprintf(event_key, sizeof(event_key), "reserve-poison-event-%u", i);
    snprintf(generation, sizeof(generation), "reserve-poison-generation-%u", i);
    snprintf(batch_id, sizeof(batch_id), "reserve-poison-intent-%u", i);
    assert(edr_storage_queue_enforcement_terminal_precreate(
               key, event_key, "R-TERMINAL", generation, batch_id, intent, sizeof(intent)) ==
           EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
    poison_ids[i] = terminal_journal_id_for_key(path, key);
    assert(poison_ids[i] > 0);
  }
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "reserve-valid", "reserve-valid-event", "R-TERMINAL", "reserve-valid-generation",
             "reserve-valid-intent", valid_intent, sizeof(valid_intent)) ==
         EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  assert(edr_storage_queue_enforcement_terminal_update(
             "reserve-valid", "reserve-valid-source", valid_source, sizeof(valid_source),
             "reserve-valid-combined", valid_combined, sizeof(valid_combined)) == EDR_OK);
  edr_storage_queue_close();
  assert(test_setenv("EDR_QUEUE_MAX_DB_MB", "1") == 0);

  /* Exercise key and batch metadata independently: embedded NUL would be
   * truncated by sqlite3_bind_text(..., -1), and 256-byte TEXT exceeds the
   * producer contract. Each must fail before any copy or transport send. */
  for (unsigned i = 0u; i < poison_rows; ++i) {
    static const char *const corrupt_sql[poison_rows] = {
        "UPDATE enforcement_terminal_journal SET "
        "idempotency_key=CAST(X'706F69736F6E006B6579' AS TEXT) WHERE id=%lld;",
        "UPDATE enforcement_terminal_journal SET "
        "intent_batch_id=CAST(X'6261746368006964' AS TEXT) WHERE id=%lld;",
        "UPDATE enforcement_terminal_journal SET "
        "idempotency_key=replace(hex(zeroblob(128)),'0','k') WHERE id=%lld;",
        "UPDATE enforcement_terminal_journal SET "
        "intent_batch_id=replace(hex(zeroblob(128)),'0','b') WHERE id=%lld;"};
    char sql[256];
    int n = snprintf(sql, sizeof(sql), corrupt_sql[i], (long long)poison_ids[i]);
    assert(n > 0 && (size_t)n < sizeof(sql));
    sqlite_exec_path(path, sql);
  }

  assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_get_capacity_metrics(&before_fail);
  assert(before_fail.accounting_available == 1u);
  assert(before_fail.used_bytes > before_fail.ordinary_limit_bytes);
  /* The stranded reservations suppress ordinary admission before quarantine. */
  assert(edr_storage_queue_enqueue("reserve-capacity-before", ordinary_wire, ordinary_wire_len,
                                   0, EDR_STORAGE_QUEUE_SEVERITY_ORDINARY) == EDR_ERR_QUEUE_FULL);
  assert(status_count(path, "pending") == 0);

  edr_storage_queue_enforcement_terminal_get_metrics(&before_corruption);
  reset_send_state(1);
  edr_storage_queue_poll_drain();
  for (unsigned i = 0u; i < poison_rows; ++i) {
    assert(terminal_journal_id_state_error_is(
        path, poison_ids[i], "failed", "intent_durable_metadata_invalid"));
    assert(terminal_journal_id_failed_releases_reservation_with_wires(
        path, poison_ids[i], 1, 0, 0));
  }
  assert(send_calls_for(0xe1u) == 0u);
  assert(send_calls_for(0xe4u) == 1u && send_calls_for(0xe5u) == 1u);
  assert(terminal_journal_state_is(path, "reserve-valid", "completed"));
  edr_storage_queue_enforcement_terminal_get_metrics(&after_corruption);
  assert(after_corruption.replay_metadata_corruption_failures ==
         before_corruption.replay_metadata_corruption_failures + poison_rows);
  edr_storage_queue_get_capacity_metrics(&after_fail);
  assert(after_fail.accounting_available == 1u);
  assert(before_fail.used_bytes > after_fail.used_bytes + 400000u);
  assert(after_fail.used_bytes < after_fail.ordinary_limit_bytes);

  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_get_capacity_metrics(&after_reopen);
  assert(after_reopen.accounting_available == 1u);
  assert(after_reopen.used_bytes == after_fail.used_bytes);
  /* Both a normal batch and a new terminal owner can now admit; retained
   * failed rows still contain their original intent wires. */
  assert(edr_storage_queue_enqueue("reserve-capacity-after", ordinary_wire, ordinary_wire_len,
                                   0, EDR_STORAGE_QUEUE_SEVERITY_ORDINARY) == EDR_OK);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "reserve-capacity-terminal", "reserve-capacity-event", "R-TERMINAL",
             "reserve-capacity-generation", "reserve-capacity-intent", intent,
             sizeof(intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  assert(terminal_journal_state_is(path, "reserve-capacity-terminal", "pending_intent"));
  edr_storage_queue_close();
  free(ordinary_wire);
  (void)remove(path);
  assert(test_unsetenv("EDR_QUEUE_MAX_DB_MB") == 0);
  assert(test_unsetenv("EDR_QUEUE_DRAIN_MAX_ROWS") == 0);
}

/* Replay/update idempotency comparisons also read SQLite TEXT. A corrupt raw
 * value must not compare equal to its prefix through strcmp-style semantics. */
static void test_terminal_corrupt_sql_text_never_matches_exact_replay(void) {
  char path[256];
  uint8_t intent[20], source[20], combined[20];

  snprintf(path, sizeof(path), "edr-terminal-raw-text-%ld.db", (long)TEST_PID);
  (void)remove(path);
  make_wire(intent, 0xe6u);
  make_wire(source, 0xe7u);
  make_wire(combined, 0xe8u);
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "raw-precreate", "raw-source", "R-TERMINAL", "raw-generation", "raw-intent",
             intent, sizeof(intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  edr_storage_queue_close();
  sqlite_exec_path(path,
                   "UPDATE enforcement_terminal_journal SET "
                   "source_event_key=CAST(X'7261772D736F757263650078' AS TEXT) "
                   "WHERE idempotency_key='raw-precreate';");
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "raw-precreate", "raw-source", "R-TERMINAL", "raw-generation", "raw-intent",
             intent, sizeof(intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_CONFLICT);
  assert(terminal_journal_state_is(path, "raw-precreate", "pending_intent"));
  edr_storage_queue_close();
  (void)remove(path);

  snprintf(path, sizeof(path), "edr-terminal-raw-update-%ld.db", (long)TEST_PID);
  (void)remove(path);
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "raw-update", "raw-update-event", "R-TERMINAL", "raw-update-generation",
             "raw-update-intent", intent, sizeof(intent)) ==
         EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  assert(edr_storage_queue_enforcement_terminal_update(
             "raw-update", "raw-update-source", source, sizeof(source), "raw-update-combined",
             combined, sizeof(combined)) == EDR_OK);
  edr_storage_queue_close();
  sqlite_exec_path(path,
                   "UPDATE enforcement_terminal_journal SET "
                   "source_batch_id=CAST(X'7261772D7570646174652D736F757263650078' AS TEXT) "
                   "WHERE idempotency_key='raw-update';");
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_enforcement_terminal_update(
             "raw-update", "raw-update-source", source, sizeof(source), "raw-update-combined",
             combined, sizeof(combined)) == EDR_ERR_INVALID_ARG);
  edr_storage_queue_close();
  (void)remove(path);
}

/* `idempotency_key` is the action owner. SQLite TEXT corruption must not turn
 * that owner into a missing row: the immutable digest returns CONFLICT before
 * an executor can see CREATED, releases only the future reserve, and retains
 * the original intent as audit evidence. */
static void test_terminal_corrupt_owner_never_recreates_action(void) {
  char path[256];
  uint8_t nul_intent[20], overlong_intent[20], other_intent[20];
  sqlite3_int64 nul_id, overlong_id;
  EdrEnforcementTerminalJournalMetrics before, after, after_reopen;

  snprintf(path, sizeof(path), "edr-terminal-owner-corrupt-%ld.db", (long)TEST_PID);
  (void)remove(path);
  make_wire(nul_intent, 0xb6u);
  make_wire(overlong_intent, 0xb7u);
  make_wire(other_intent, 0xb8u);
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "owner-nul", "owner-nul-event", "R-TERMINAL", "owner-nul-generation",
             "owner-nul-intent", nul_intent, sizeof(nul_intent)) ==
         EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "owner-overlong", "owner-overlong-event", "R-TERMINAL",
             "owner-overlong-generation", "owner-overlong-intent", overlong_intent,
             sizeof(overlong_intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  nul_id = terminal_journal_id_for_key(path, "owner-nul");
  overlong_id = terminal_journal_id_for_key(path, "owner-overlong");
  assert(nul_id > 0 && overlong_id > 0);
  assert(terminal_journal_id_owner_digest_is(path, nul_id));
  assert(terminal_journal_id_owner_digest_is(path, overlong_id));
  edr_storage_queue_close();

  {
    char sql[256];
    int n = snprintf(sql, sizeof(sql),
                     "UPDATE enforcement_terminal_journal SET "
                     "idempotency_key=CAST(X'6F776E65722D6E756C007461696C' AS TEXT) "
                     "WHERE id=%lld;", (long long)nul_id);
    assert(n > 0 && (size_t)n < sizeof(sql));
    sqlite_exec_path(path, sql);
  }
  {
    char sql[256];
    int n = snprintf(sql, sizeof(sql),
                     "UPDATE enforcement_terminal_journal SET "
                     "idempotency_key=replace(hex(zeroblob(128)),'0','z') WHERE id=%lld;",
                     (long long)overlong_id);
    assert(n > 0 && (size_t)n < sizeof(sql));
    sqlite_exec_path(path, sql);
  }

  assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_enforcement_terminal_get_metrics(&before);
  assert(before.owner_metadata_unresolved == 0u);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "owner-nul", "owner-nul-event", "R-TERMINAL", "owner-nul-generation",
             "owner-nul-intent", nul_intent, sizeof(nul_intent)) ==
         EDR_ENFORCEMENT_TERMINAL_PRECREATE_CONFLICT);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "owner-overlong", "owner-overlong-event", "R-TERMINAL",
             "owner-overlong-generation", "owner-overlong-intent", overlong_intent,
             sizeof(overlong_intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_CONFLICT);
  assert(terminal_journal_id_state_error_is(
      path, nul_id, "failed", "owner_durable_metadata_invalid"));
  assert(terminal_journal_id_state_error_is(
      path, overlong_id, "failed", "owner_durable_metadata_invalid"));
  assert(terminal_journal_id_failed_releases_reservation_with_wires(path, nul_id, 1, 0, 0));
  assert(terminal_journal_id_failed_releases_reservation_with_wires(
      path, overlong_id, 1, 0, 0));
  /* A distinct owner remains actionable: one corrupt owner cannot become a
   * global terminal queue starvation point. */
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "owner-other", "owner-other-event", "R-TERMINAL", "owner-other-generation",
             "owner-other-intent", other_intent, sizeof(other_intent)) ==
         EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  edr_storage_queue_enforcement_terminal_get_metrics(&after);
  assert(after.precreate_created == before.precreate_created + 1u);
  assert(after.precreate_conflicts == before.precreate_conflicts + 2u);
  assert(after.precreate_metadata_corruption_failures ==
         before.precreate_metadata_corruption_failures + 2u);
  assert(after.owner_metadata_unresolved == 0u);
  reset_send_state(1);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0xb6u) == 0u && send_calls_for(0xb7u) == 0u);
  assert(send_calls_for(0xb8u) == 1u);

  /* The retained digest, failed state, and no-CREATED result all survive
   * restart. Repeating the same owner cannot produce another action. */
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "owner-nul", "owner-nul-event", "R-TERMINAL", "owner-nul-generation",
             "owner-nul-intent", nul_intent, sizeof(nul_intent)) ==
         EDR_ENFORCEMENT_TERMINAL_PRECREATE_CONFLICT);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "owner-overlong", "owner-overlong-event", "R-TERMINAL",
             "owner-overlong-generation", "owner-overlong-intent", overlong_intent,
             sizeof(overlong_intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_CONFLICT);
  edr_storage_queue_enforcement_terminal_get_metrics(&after_reopen);
  assert(after_reopen.precreate_created == after.precreate_created);
  assert(after_reopen.precreate_conflicts == after.precreate_conflicts + 2u);
  assert(after_reopen.precreate_metadata_corruption_failures ==
         after.precreate_metadata_corruption_failures + 2u);
  assert(after_reopen.owner_metadata_unresolved == 0u);
  edr_storage_queue_close();
  (void)remove(path);
}

/* Existing valid terminal databases get an immutable digest in one durable
 * migration. A truly pre-digest corrupt owner is unidentifiable, so the
 * durable latch prevents every new terminal action instead of accepting an
 * ambiguous duplicate after a restart. */
static void test_terminal_owner_digest_migration_and_unresolved_legacy_latch(void) {
  char valid_path[256];
  char corrupt_path[256];
  uint8_t intent[20];
  sqlite3_int64 valid_id;
  EdrEnforcementTerminalJournalMetrics before, after, reopened;
  static const char legacy_schema[] =
      "CREATE TABLE enforcement_terminal_journal ("
      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "idempotency_key TEXT NOT NULL UNIQUE,"
      "source_event_key TEXT NOT NULL,rule_id TEXT NOT NULL,"
      "process_generation_key TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'pending_intent',"
      "intent_batch_id TEXT NOT NULL DEFAULT '',intent_wire BLOB,"
      "intent_acked INTEGER NOT NULL DEFAULT 0,intent_retry_count INTEGER NOT NULL DEFAULT 0,"
      "source_batch_id TEXT NOT NULL DEFAULT '',source_wire BLOB,"
      "source_acked INTEGER NOT NULL DEFAULT 0,source_retry_count INTEGER NOT NULL DEFAULT 0,"
      "combined_batch_id TEXT NOT NULL DEFAULT '',combined_wire BLOB,"
      "combined_acked INTEGER NOT NULL DEFAULT 0,combined_retry_count INTEGER NOT NULL DEFAULT 0,"
      "reserved_bytes INTEGER NOT NULL DEFAULT 0,last_error TEXT NOT NULL DEFAULT '',"
      "created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,completed_at INTEGER NOT NULL DEFAULT 0"
      ");";
  static const char legacy_valid_row[] =
      "INSERT INTO enforcement_terminal_journal("
      "idempotency_key,source_event_key,rule_id,process_generation_key,state,intent_batch_id,"
      "intent_wire,intent_acked,intent_retry_count,reserved_bytes,last_error,created_at,updated_at,completed_at) "
      "VALUES('legacy-owner','legacy-event','R-TERMINAL','legacy-generation','pending_intent',"
      "'legacy-intent',X'42415431010000000800000004000000B9BAA55A',0,0,131584,'',1,1,0);";
  static const char legacy_corrupt_row[] =
      "INSERT INTO enforcement_terminal_journal("
      "idempotency_key,source_event_key,rule_id,process_generation_key,state,intent_batch_id,"
      "intent_wire,intent_acked,intent_retry_count,reserved_bytes,last_error,created_at,updated_at,completed_at) "
      "VALUES(CAST(X'006C65676163792D706F69736F6E' AS TEXT),'legacy-poison-event',"
      "'R-TERMINAL','legacy-poison-generation','pending_intent','legacy-poison-intent',"
      "X'42415431010000000800000004000000BBBCA55A',0,0,131584,'',1,1,0);";

  snprintf(valid_path, sizeof(valid_path), "edr-terminal-owner-migrate-%ld.db", (long)TEST_PID);
  snprintf(corrupt_path, sizeof(corrupt_path), "edr-terminal-owner-unresolved-%ld.db",
           (long)TEST_PID);
  (void)remove(valid_path);
  (void)remove(corrupt_path);
  make_wire(intent, 0xb9u);

  sqlite_exec_path(valid_path, legacy_schema);
  sqlite_exec_path(valid_path, legacy_valid_row);
  assert(edr_storage_queue_open(valid_path) == EDR_OK);
  valid_id = terminal_journal_id_for_key(valid_path, "legacy-owner");
  assert(valid_id > 0 && terminal_journal_id_owner_digest_is(valid_path, valid_id));
  assert(terminal_journal_owner_digest_unique_index_exists(valid_path));
  assert(terminal_owner_corruption_latch_is(valid_path, 0, ""));
  edr_storage_queue_close();
  sqlite_exec_path(valid_path,
                   "UPDATE enforcement_terminal_journal SET "
                   "idempotency_key=CAST(X'6C65676163792D6F776E65720078' AS TEXT) WHERE id=1;");
  assert(edr_storage_queue_open(valid_path) == EDR_OK);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "legacy-owner", "legacy-event", "R-TERMINAL", "legacy-generation",
             "legacy-intent", intent, sizeof(intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_CONFLICT);
  assert(terminal_journal_id_state_error_is(
      valid_path, valid_id, "failed", "owner_durable_metadata_invalid"));
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "legacy-other", "legacy-other-event", "R-TERMINAL", "legacy-other-generation",
             "legacy-other-intent", intent, sizeof(intent)) ==
         EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  edr_storage_queue_close();
  (void)remove(valid_path);

  sqlite_exec_path(corrupt_path, legacy_schema);
  sqlite_exec_path(corrupt_path, legacy_corrupt_row);
  assert(edr_storage_queue_open(corrupt_path) == EDR_OK);
  edr_storage_queue_enforcement_terminal_get_metrics(&before);
  assert(before.owner_metadata_unresolved == 1u);
  assert(terminal_owner_corruption_latch_is(
      corrupt_path, 1, "legacy_owner_digest_unrecoverable"));
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "unrelated-owner", "unrelated-event", "R-TERMINAL", "unrelated-generation",
             "unrelated-intent", intent, sizeof(intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_ERROR);
  edr_storage_queue_enforcement_terminal_get_metrics(&after);
  assert(after.precreate_created == before.precreate_created);
  assert(after.precreate_rejected == before.precreate_rejected + 1u);
  assert(after.precreate_metadata_corruption_failures ==
         before.precreate_metadata_corruption_failures + 1u);
  assert(terminal_journal_count(corrupt_path) == 1);
  edr_storage_queue_close();
  assert(edr_storage_queue_open(corrupt_path) == EDR_OK);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "unrelated-owner-after-reopen", "unrelated-event-after-reopen", "R-TERMINAL",
             "unrelated-generation-after-reopen", "unrelated-intent-after-reopen", intent,
             sizeof(intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_ERROR);
  edr_storage_queue_enforcement_terminal_get_metrics(&reopened);
  assert(reopened.owner_metadata_unresolved == 1u);
  assert(reopened.precreate_created == after.precreate_created);
  assert(reopened.precreate_rejected == after.precreate_rejected + 1u);
  assert(reopened.precreate_metadata_corruption_failures ==
         after.precreate_metadata_corruption_failures + 1u);
  assert(terminal_journal_count(corrupt_path) == 1);
  edr_storage_queue_close();
  (void)remove(corrupt_path);
}

/* event_queue batch ids are sent and later rebound as C strings. A durable
 * SQLite TEXT NUL or overlong value is therefore terminal metadata corruption,
 * not a retryable transport outcome. It must leave the row auditable without
 * starving a later row. Its retained payload still consumes admission capacity. */
static void test_event_queue_batch_metadata_corruption_quarantines_without_starvation(void) {
  enum { large_wire_len = 200000 };
  char path[256];
  char producer_overlong[257];
  uint8_t valid_wire[20], transient_wire[20];
  uint8_t *large_wire;
  sqlite3_int64 nul_id, overlong_id;
  EdrStorageQueueCapacityMetrics before, after, after_reopen, after_transient;

  snprintf(path, sizeof(path), "edr-event-queue-batch-metadata-%ld.db", (long)TEST_PID);
  (void)remove(path);
  assert(test_setenv("EDR_QUEUE_MAX_DB_MB", "1") == 0);
  assert(test_setenv("EDR_QUEUE_DRAIN_MAX_ROWS", "8") == 0);
  large_wire = (uint8_t *)malloc(large_wire_len);
  assert(large_wire != NULL);
  make_large_wire(large_wire, large_wire_len, 0xe9u);
  make_wire(valid_wire, 0xebu);
  make_wire(transient_wire, 0xecu);
  memset(producer_overlong, 'q', sizeof(producer_overlong) - 1u);
  producer_overlong[sizeof(producer_overlong) - 1u] = '\0';

  assert(edr_storage_queue_open(path) == EDR_OK);
  /* New producers cannot persist a batch outside the same 1..255 contract. */
  assert(edr_storage_queue_enqueue(producer_overlong, valid_wire, sizeof(valid_wire), 0,
                                   EDR_STORAGE_QUEUE_SEVERITY_ORDINARY) == EDR_ERR_INVALID_ARG);
  assert(edr_storage_queue_enqueue("ordinary-poison-nul", large_wire, large_wire_len, 0,
                                   EDR_STORAGE_QUEUE_SEVERITY_ORDINARY) == EDR_OK);
  assert(edr_storage_queue_enqueue("ordinary-poison-overlong", large_wire, large_wire_len, 0,
                                   EDR_STORAGE_QUEUE_SEVERITY_ORDINARY) == EDR_OK);
  assert(edr_storage_queue_enqueue("ordinary-valid", valid_wire, sizeof(valid_wire), 0,
                                   EDR_STORAGE_QUEUE_SEVERITY_ORDINARY) == EDR_OK);
  nul_id = batch_row_id(path, "ordinary-poison-nul");
  overlong_id = batch_row_id(path, "ordinary-poison-overlong");
  assert(nul_id > 0 && overlong_id > 0);
  edr_storage_queue_close();

  {
    char sql[256];
    int n = snprintf(sql, sizeof(sql),
                     "UPDATE event_queue SET batch_id=CAST(X'6F7264696E617279006E756C' AS TEXT) "
                     "WHERE id=%lld;", (long long)nul_id);
    assert(n > 0 && (size_t)n < sizeof(sql));
    sqlite_exec_path(path, sql);
    n = snprintf(sql, sizeof(sql),
                 "UPDATE event_queue SET batch_id=replace(hex(zeroblob(128)),'0','q') "
                 "WHERE id=%lld;", (long long)overlong_id);
    assert(n > 0 && (size_t)n < sizeof(sql));
    sqlite_exec_path(path, sql);
  }

  assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_get_capacity_metrics(&before);
  assert(before.accounting_available == 1u);
  /* The raw pending rows still charge capacity until the drain quarantines
   * them. A third large admission is rejected before that state transition. */
  assert(edr_storage_queue_enqueue("ordinary-before-quarantine", large_wire, large_wire_len, 0,
                                   EDR_STORAGE_QUEUE_SEVERITY_ORDINARY) == EDR_ERR_QUEUE_FULL);
  reset_send_state(1);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0xe9u) == 0u);
  assert(send_calls_for(0xebu) == 1u);
  assert(event_queue_id_status_reason_payload_is(
      path, nul_id, "dead_letter", "invalid_batch_id_metadata", large_wire_len));
  assert(event_queue_id_status_reason_payload_is(
      path, overlong_id, "dead_letter", "invalid_batch_id_metadata", large_wire_len));
  assert(status_count(path, "pending") == 0);
  assert(status_count(path, "dead_letter") == 2);
  assert(edr_storage_queue_dead_letter_count() == 2u);
  edr_storage_queue_get_capacity_metrics(&after);
  assert(after.event_queue_metadata_corruption_failures ==
         before.event_queue_metadata_corruption_failures + 2u);
  assert(after.delivery_selected == before.delivery_selected + 3u);
  assert(after.delivery_sent == before.delivery_sent + 1u);
  assert(after.delivery_acked == before.delivery_acked + 1u);
  assert(after.delivery_requeued == before.delivery_requeued);
  assert(after.delivery_failed == before.delivery_failed + 2u);
  assert(after.used_bytes >= 400000u && before.used_bytes > after.used_bytes);
  assert(after.retained_nonpending_bytes == after.used_bytes);

  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_get_capacity_metrics(&after_reopen);
  assert(after_reopen.used_bytes == after.used_bytes);
  assert(after_reopen.event_queue_metadata_corruption_failures ==
         after.event_queue_metadata_corruption_failures);
  assert(edr_storage_queue_dead_letter_count() == 2u);
  assert(event_queue_id_status_reason_payload_is(
      path, nul_id, "dead_letter", "invalid_batch_id_metadata", large_wire_len));

  /* A valid transport failure stays pending and increments retry; it must not
   * be classified as metadata corruption or moved to dead-letter. */
  assert(edr_storage_queue_enqueue("ordinary-transient", transient_wire, sizeof(transient_wire),
                                   0, EDR_STORAGE_QUEUE_SEVERITY_ORDINARY) == EDR_OK);
  reset_send_state(0);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0xecu) == 1u);
  assert(batch_retry_count(path, "ordinary-transient") == 1);
  assert(status_count(path, "pending") == 1);
  assert(status_count(path, "dead_letter") == 2);
  edr_storage_queue_get_capacity_metrics(&after_transient);
  assert(after_transient.event_queue_metadata_corruption_failures ==
         after_reopen.event_queue_metadata_corruption_failures);
  assert(after_transient.delivery_selected == after_reopen.delivery_selected + 1u);
  assert(after_transient.delivery_sent == after_reopen.delivery_sent + 1u);
  assert(after_transient.delivery_acked == after_reopen.delivery_acked);
  assert(after_transient.delivery_requeued == after_reopen.delivery_requeued + 1u);
  assert(after_transient.delivery_failed == after_reopen.delivery_failed);

  /* A later ordinary batch can use remaining budget, but quarantine must
   * not reset retained usage and allow an unlimited sequence of new writes. */
  assert(edr_storage_queue_enqueue("ordinary-after-quarantine", valid_wire, sizeof(valid_wire), 0,
                                   EDR_STORAGE_QUEUE_SEVERITY_ORDINARY) == EDR_OK);
  assert(edr_storage_queue_enqueue("ordinary-over-retained-budget", large_wire, large_wire_len, 0,
                                   EDR_STORAGE_QUEUE_SEVERITY_ORDINARY) == EDR_ERR_QUEUE_FULL);
  assert(status_count(path, "dead_letter") == 2);
  edr_storage_queue_close();
  free(large_wire);
  (void)remove(path);
  assert(test_unsetenv("EDR_QUEUE_MAX_DB_MB") == 0);
  assert(test_unsetenv("EDR_QUEUE_DRAIN_MAX_ROWS") == 0);
}

/* Final terminal frames have a different failure contract from ordinary
 * telemetry: they are proof of an action that already ran.  The test suite
 * sets EDR_QUEUE_MAX_RETRIES=1, so two failed transports exercise retry
 * exhaustion, close/open recovery, retention cleanup, and later success. */
static void test_terminal_final_frames_survive_retry_limit_and_retention(void) {
  char path[256];
  uint8_t intent[20], source[20], combined[20];
  const int64_t now = (int64_t)time(NULL);
  EdrEnforcementTerminalJournalMetrics metrics;
  snprintf(path, sizeof(path), "edr-terminal-journal-final-retry-%ld.db", (long)TEST_PID);
  edr_storage_queue_test_set_delivery_time(now);
  (void)remove(path);
  make_wire(intent, 0xa1u);
  make_wire(source, 0xa2u);
  make_wire(combined, 0xa3u);
  assert(test_setenv("EDR_QUEUE_RETENTION_HOURS", "1") == 0);
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "final-retry", "event-final-retry", "R-TERMINAL", "generation-final-retry",
             "intent-final-retry", intent, sizeof(intent)) ==
         EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  reset_send_state(1);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0xa1u) == 1u);
  assert(edr_storage_queue_enforcement_terminal_update(
             "final-retry", "source-final-retry", source, sizeof(source),
             "combined-final-retry", combined, sizeof(combined)) == EDR_OK);

  reset_send_state(0);
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0xa2u) == 1u);
  assert(terminal_journal_frame_retry_count(path, "final-retry", 1) == 1);
  assert(terminal_journal_state_is(path, "final-retry", "ready"));

  /* Reopening alone must not defeat the failed frame's durable backoff. */
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0xa2u) == 1u);
  assert(terminal_journal_frame_retry_count(path, "final-retry", 1) == 1);
  edr_storage_queue_test_set_delivery_time(now + 2);

  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0xa2u) == 2u);
  assert(terminal_journal_frame_retry_count(path, "final-retry", 1) == 2);
  assert(terminal_journal_state_is(path, "final-retry", "ready"));
  edr_storage_queue_enforcement_terminal_get_metrics(&metrics);
  assert(metrics.pending == 1u && metrics.failed == 0u);

  edr_storage_queue_close();
  terminal_journal_age_for_retention(path, "final-retry");
  assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_test_run_cleanup();
  assert(terminal_journal_count(path) == 1);
  assert(terminal_journal_state_is(path, "final-retry", "ready"));
  assert(terminal_journal_frame_retry_count(path, "final-retry", 1) == 2);

  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  reset_send_state(1);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0xa2u) == 1u);
  assert(send_calls_for(0xa3u) == 1u);
  assert(terminal_journal_state_is(path, "final-retry", "completed"));
  assert(terminal_journal_final_acks(path, "final-retry", NULL, NULL));
  /* ACK progress clears the obsolete shared transport error. Both frames
   * use the same delivery clock, irrespective of native runner speed. */
  assert(terminal_journal_delivery_state_is(path, "final-retry", "", now + 2));

  /* A completed terminal never replays on restart; the action was owned by
   * the precreated journal record and no re-execution path is involved. */
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  reset_send_state(1);
  edr_storage_queue_poll_drain();
  assert(total_send_calls() == 0u);
  edr_storage_queue_close();
  edr_storage_queue_test_set_delivery_time(-1);
  (void)remove(path);
}

static void test_terminal_journal_ordinary_ack_is_atomic_and_reconciles(void) {
  char path[256];
  uint8_t intent[20], source[20], combined[20];
  int source_acked, combined_acked;
  EdrEnforcementTerminalJournalMetrics metrics;
  snprintf(path, sizeof(path), "edr-terminal-journal-ack-%ld.db", (long)TEST_PID);
  (void)remove(path);
  make_wire(intent, 0x91u);
  make_wire(source, 0x92u);
  make_wire(combined, 0x93u);
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "atomic-ack", "event-atomic-ack", "R-TERMINAL", "generation-atomic-ack",
             "intent-atomic-ack", intent, sizeof(intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  /* Production writes an ordinary intent copy too. Ack it before exercising
   * a final-frame commit failure so the injected commit is the source ACK. */
  assert(edr_storage_queue_enqueue("intent-atomic-ack", intent, sizeof(intent), 0, 1) == EDR_OK);
  reset_send_state(1);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0x91u) == 1u);
  assert(edr_storage_queue_enforcement_terminal_update(
             "atomic-ack", "source-atomic-ack", source, sizeof(source),
             "combined-atomic-ack", combined, sizeof(combined)) == EDR_OK);
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);

  /* First inject a checked ACK statement fault after the DELETE statement
   * has run inside its transaction. The rollback must restore both. */
  assert(edr_storage_queue_enqueue("source-atomic-ack", source, sizeof(source), 0, 1) == EDR_OK);
  edr_storage_queue_test_fail_next_terminal_ack_steps(1u);
  reset_send_state(1);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0x92u) == 1u);
  assert(queue_batch_pending(path, "source-atomic-ack"));
  assert(terminal_journal_final_acks(path, "atomic-ack", &source_acked, &combined_acked));
  assert(source_acked == 0 && combined_acked == 1);
  assert(terminal_journal_state_is(path, "atomic-ack", "ready"));

  /* Then inject failure at the FULL commit containing normal-queue DELETE
   * and matching source ACK. Neither side may become durable alone. */
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_test_fail_next_terminal_commits(1u);
  reset_send_state(1);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0x92u) == 1u);
  assert(queue_batch_pending(path, "source-atomic-ack"));
  assert(terminal_journal_final_acks(path, "atomic-ack", &source_acked, &combined_acked));
  /* The journal may have delivered the unqueued combined frame first, but
   * the failed source normal ACK remains wholly uncommitted. */
  assert(source_acked == 0 && combined_acked == 1);
  assert(terminal_journal_state_is(path, "atomic-ack", "ready"));

  /* A reopened queue replays exactly the still-pending source frame, then
   * the combined frame. No completed terminal row is replayed after reopen. */
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  reset_send_state(1);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0x92u) == 1u);
  assert(terminal_journal_final_acks(path, "atomic-ack", &source_acked, &combined_acked));
  assert(source_acked == 1 && combined_acked == 1);
  assert(terminal_journal_state_is(path, "atomic-ack", "completed"));
  edr_storage_queue_enforcement_terminal_get_metrics(&metrics);
  assert(metrics.pending == 0u);
  edr_storage_queue_close();

  /* Model the historical crash state: queue rows were gone and both ACK
   * flags persisted, but the final state update had not. Open reconciles it
   * without redelivery or another terminal action. */
  {
    sqlite3 *db = NULL;
    assert(sqlite3_open(path, &db) == SQLITE_OK);
    assert(sqlite3_exec(db,
                        "UPDATE enforcement_terminal_journal SET state='ready',source_acked=1,"
                        "combined_acked=1,completed_at=0 WHERE idempotency_key='atomic-ack';",
                        NULL, NULL, NULL) == SQLITE_OK);
    sqlite3_close(db);
  }
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(terminal_journal_state_is(path, "atomic-ack", "completed"));
  edr_storage_queue_enforcement_terminal_get_metrics(&metrics);
  assert(metrics.pending == 0u);
  reset_send_state(1);
  edr_storage_queue_poll_drain();
  assert(total_send_calls() == 0u);
  edr_storage_queue_close();
  (void)remove(path);
}

static void test_terminal_journal_backpressure_cap(void) {
  char path[256];
  uint8_t intent[20];
  EdrEnforcementTerminalJournalMetrics metrics;
  snprintf(path, sizeof(path), "edr-terminal-journal-cap-%ld.db", (long)TEST_PID);
  (void)remove(path);
  make_wire(intent, 0x7au);
  assert(edr_storage_queue_open(path) == EDR_OK);
  for (unsigned i = 0u; i < 1024u; i++) {
    char key[64], source[64], generation[64], batch[64];
    snprintf(key, sizeof(key), "cap-key-%u", i);
    snprintf(source, sizeof(source), "cap-event-%u", i);
    snprintf(generation, sizeof(generation), "cap-generation-%u", i);
    snprintf(batch, sizeof(batch), "cap-intent-%u", i);
    assert(edr_storage_queue_enforcement_terminal_precreate(
               key, source, "R-TERMINAL", generation, batch, intent, sizeof(intent)) ==
           EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  }
  edr_storage_queue_enforcement_terminal_get_metrics(&metrics);
  assert(metrics.pending == 1024u && metrics.backpressure == 0u);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "cap-key-overflow", "cap-event-overflow", "R-TERMINAL", "cap-generation-overflow",
             "cap-intent-overflow", intent, sizeof(intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_ERROR);
  edr_storage_queue_enforcement_terminal_get_metrics(&metrics);
  assert(metrics.pending == 1024u && metrics.backpressure == 1u);
  edr_storage_queue_close();
  (void)remove(path);
}

/* SQLite's page and WAL files retain a high-water mark after DELETE. Capacity
 * must instead follow live durable records, while ordinary telemetry still
 * leaves enough space for one pre-action terminal intent and both result
 * frames. No pending record is discarded to create that room. */
static void test_logical_capacity_recovers_and_reserves_terminal(void) {
  char path[256];
  uint8_t intent[20];
  uint8_t *large_wire;
  EdrStorageQueueCapacityMetrics before_drain, after_drain, before_terminal, after_terminal;
  unsigned ordinary_before_drain = 0u;
  unsigned ordinary_before_terminal = 0u;
  int saw_full = 0;
  snprintf(path, sizeof(path), "edr-storage-queue-capacity-%ld.db", (long)TEST_PID);
  (void)remove(path);
  assert(test_setenv("EDR_QUEUE_MAX_DB_MB", "1") == 0);
  assert(test_setenv("EDR_QUEUE_DRAIN_MAX_ROWS", "128") == 0);
  large_wire = (uint8_t *)malloc(65536u);
  assert(large_wire != NULL);
  make_large_wire(large_wire, 65536u, 0xd1u);
  make_wire(intent, 0xd2u);
  assert(edr_storage_queue_open(path) == EDR_OK);

  for (unsigned i = 0u; i < 64u; i++) {
    char batch_id[64];
    EdrError rc;
    snprintf(batch_id, sizeof(batch_id), "capacity-normal-%u", i);
    rc = edr_storage_queue_enqueue(batch_id, large_wire, 65536u, 0, 0);
    if (rc == EDR_ERR_QUEUE_FULL) {
      saw_full = 1;
      break;
    }
    assert(rc == EDR_OK);
    ordinary_before_drain++;
  }
  assert(saw_full && ordinary_before_drain > 0u);
  edr_storage_queue_get_capacity_metrics(&before_drain);
  assert(before_drain.accounting_available == 1u);
  assert(before_drain.max_bytes == 1024u * 1024u);
  assert(before_drain.used_bytes <= before_drain.ordinary_limit_bytes);
  assert(before_drain.ordinary_rejected > 0u);
  assert(before_drain.terminal_reserve_bytes > 0u);
  assert(before_drain.p0_source_only_reserve_bytes > 0u);

  /* Terminal and source-only assertions own different reserved lanes.  A
   * normal flood cannot consume either, and neither admission deletes an
   * ordinary row to make room. */
  assert(edr_storage_queue_enqueue("capacity-terminal", large_wire, 65536u, 0,
                                   EDR_STORAGE_QUEUE_SEVERITY_TERMINAL) == EDR_OK);
  assert(edr_storage_queue_enqueue("capacity-source-only", large_wire, 65536u, 0,
                                   EDR_STORAGE_QUEUE_SEVERITY_P0_SOURCE_ONLY) == EDR_OK);
  assert(edr_storage_queue_pending_count() == ordinary_before_drain + 2u);

  reset_send_state(1);
  test_sleep_ms(250u);
  edr_storage_queue_poll_drain();
  assert(edr_storage_queue_pending_count() == 0u);
  edr_storage_queue_get_capacity_metrics(&after_drain);
  assert(after_drain.accounting_available == 1u);
  assert(after_drain.used_bytes == 0u);
  assert(after_drain.delivery_selected - before_drain.delivery_selected ==
         ordinary_before_drain + 2u);
  assert(after_drain.delivery_sent - before_drain.delivery_sent ==
         ordinary_before_drain + 2u);
  assert(after_drain.delivery_acked - before_drain.delivery_acked ==
         ordinary_before_drain + 2u);
  assert(after_drain.delivery_requeued == before_drain.delivery_requeued);
  assert(after_drain.delivery_failed == before_drain.delivery_failed);
  /* Physical sidecars may remain allocated, which is precisely why they are
   * only diagnostics; a fresh ordinary event must be accepted now. */
  assert(edr_storage_queue_enqueue("capacity-after-drain", large_wire, 65536u, 0, 0) == EDR_OK);
  reset_send_state(1);
  test_sleep_ms(250u);
  edr_storage_queue_poll_drain();
  assert(edr_storage_queue_pending_count() == 0u);

  for (unsigned i = 0u; i < 64u; i++) {
    char batch_id[64];
    EdrError rc;
    snprintf(batch_id, sizeof(batch_id), "capacity-terminal-normal-%u", i);
    rc = edr_storage_queue_enqueue(batch_id, large_wire, 65536u, 0, 0);
    if (rc == EDR_ERR_QUEUE_FULL) break;
    assert(rc == EDR_OK);
    ordinary_before_terminal++;
  }
  assert(ordinary_before_terminal > 0u);
  edr_storage_queue_get_capacity_metrics(&before_terminal);
  assert(before_terminal.used_bytes <= before_terminal.ordinary_limit_bytes);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "capacity-terminal-1", "capacity-event-1", "R-TERMINAL", "capacity-generation-1",
             "capacity-intent-1", intent, sizeof(intent)) ==
         EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  edr_storage_queue_get_capacity_metrics(&after_terminal);
  assert(after_terminal.used_bytes <= after_terminal.max_bytes);
  assert(after_terminal.used_bytes > before_terminal.used_bytes);
  assert(terminal_journal_count(path) == 1);
  /* A second owner cannot overrun the same logical cap, and the first owner
   * plus all pending ordinary evidence remain intact. */
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "capacity-terminal-2", "capacity-event-2", "R-TERMINAL", "capacity-generation-2",
             "capacity-intent-2", intent, sizeof(intent)) ==
         EDR_ENFORCEMENT_TERMINAL_PRECREATE_ERROR);
  edr_storage_queue_get_capacity_metrics(&after_terminal);
  assert(after_terminal.used_bytes <= after_terminal.max_bytes);
  assert(after_terminal.high_priority_rejected > before_drain.high_priority_rejected);
  assert(terminal_journal_count(path) == 1);
  assert(status_count(path, "pending") == (int)ordinary_before_terminal);

  edr_storage_queue_close();
  free(large_wire);
  (void)remove(path);
  assert(test_unsetenv("EDR_QUEUE_MAX_DB_MB") == 0);
  assert(test_unsetenv("EDR_QUEUE_DRAIN_MAX_ROWS") == 0);
}

/* P0 source-only evidence may consume its own reserve, but it is still
 * bounded by the same logical queue authority.  A full source lane is an
 * explicit failure for the caller to fuse on, not a silent admission. */
static void test_source_only_capacity_is_distinct_and_bounded(void) {
  char path[256];
  uint8_t *large_wire;
  EdrStorageQueueCapacityMetrics metrics;
  unsigned admitted = 0u;
  int saw_full = 0;
  snprintf(path, sizeof(path), "edr-storage-queue-source-capacity-%ld.db", (long)TEST_PID);
  (void)remove(path);
  assert(test_setenv("EDR_QUEUE_MAX_DB_MB", "1") == 0);
  large_wire = (uint8_t *)malloc(65536u);
  assert(large_wire != NULL);
  make_large_wire(large_wire, 65536u, 0xd3u);
  assert(edr_storage_queue_open(path) == EDR_OK);
  for (unsigned i = 0u; i < 64u; ++i) {
    char batch_id[64];
    EdrError rc;
    snprintf(batch_id, sizeof(batch_id), "source-only-capacity-%u", i);
    rc = edr_storage_queue_enqueue(batch_id, large_wire, 65536u, 0,
                                   EDR_STORAGE_QUEUE_SEVERITY_P0_SOURCE_ONLY);
    if (rc == EDR_ERR_QUEUE_FULL) {
      saw_full = 1;
      break;
    }
    assert(rc == EDR_OK);
    admitted++;
  }
  assert(saw_full && admitted > 0u);
  edr_storage_queue_get_capacity_metrics(&metrics);
  assert(metrics.used_bytes <= metrics.max_bytes);
  assert(metrics.p0_source_only_rejected > 0u);
  edr_storage_queue_close();
  free(large_wire);
  (void)remove(path);
  assert(test_unsetenv("EDR_QUEUE_MAX_DB_MB") == 0);
}

static void test_p0_source_only_latch_persists_until_central_ack(void) {
  char path[256];
  uint8_t wire[20];
  EdrStorageQueueP0SourceOnlyLatch latch;
  EdrStorageQueueP0SourceOnlyLatch wrong;
  snprintf(path, sizeof(path), "edr-source-only-latch-%ld.db", (long)TEST_PID);
  (void)remove(path);
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_is_set() == 0);

  /* A failed FULL commit may not report a persisted capability latch. The
   * caller must remain fused in memory and retry this exact metadata write. */
  edr_storage_queue_test_fail_next_p0_latch_commits(1u);
  assert(edr_storage_queue_p0_source_only_latch_prepare(&latch) == EDR_ERR_SQLITE_WRITE);
  assert(edr_storage_queue_p0_source_only_latch_is_set() == 0);

  assert(edr_storage_queue_p0_source_only_latch_prepare(&latch) == EDR_OK);
  assert(latch.latched == 1 && latch.latch_counter != 0u && latch.latch_epoch != 0u);
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  {
    EdrStorageQueueP0SourceOnlyLatch reopened;
    assert(edr_storage_queue_p0_source_only_latch_get(&reopened) == EDR_OK);
    assert(reopened.latched == 1 &&
           memcmp(reopened.queue_nonce, latch.queue_nonce, sizeof(latch.queue_nonce)) == 0 &&
           reopened.latch_counter == latch.latch_counter &&
           reopened.latch_epoch == latch.latch_epoch);
  }

  /* A probe is not an acknowledgement and cannot make a local source insert
   * healthy. The batch remains replayable until its central 2xx delete. */
  assert(edr_storage_queue_p0_source_only_recovery_probe() == EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_is_set() == 1);
  make_wire(wire, 0xe1u);
  wrong = latch;
  wrong.latch_epoch++;
  assert(edr_storage_queue_p0_source_only_enqueue_bound(
             &wrong, "source-only-event", "source-only-batch", wire, sizeof(wire), 0, 0) ==
         EDR_ERR_SQLITE_WRITE);
  assert(edr_storage_queue_p0_source_only_latch_is_set() == 1);

  assert(edr_storage_queue_p0_source_only_enqueue_bound(
             &latch, "source-only-event", "source-only-batch", wire, sizeof(wire), 0, 0) ==
         EDR_OK);
  assert(status_count(path, "pending") == 1);
  assert(edr_storage_queue_p0_source_only_latch_is_set() == 1);

  reset_send_state(1);
  s_telemetry_deferred = 1;
  edr_storage_queue_poll_drain();
  assert(total_send_calls() == 0u && batch_retry_count(path, "source-only-batch") == 0);
  assert(edr_storage_queue_p0_source_only_latch_is_set() == 1);
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);

  /* An ACK transaction failure rolls back both DELETE and queue_meta clear. */
  edr_storage_queue_test_fail_next_p0_latch_commits(1u);
  reset_send_state(1);
  edr_storage_queue_poll_drain();
  assert(status_count(path, "pending") == 1);
  assert(edr_storage_queue_p0_source_only_latch_is_set() == 1);

  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  reset_send_state(1);
  edr_storage_queue_poll_drain();
  assert(status_count(path, "pending") == 0);
  assert(edr_storage_queue_p0_source_only_latch_is_set() == 0);
  edr_storage_queue_close();
  (void)remove(path);
}

static void test_p0_source_only_multiple_durable_rows_do_not_create_false_loss(void) {
  char path[256];
  uint8_t first_wire[20];
  uint8_t second_wire[20];
  EdrStorageQueueP0SourceOnlyLatch first;
  EdrStorageQueueP0SourceOnlyLatch second;
  EdrStorageQueueP0SourceOnlyLatch reopened;
  snprintf(path, sizeof(path), "edr-source-only-multi-%ld.db", (long)TEST_PID);
  (void)remove(path);
  make_wire(first_wire, 0xe8u);
  make_wire(second_wire, 0xe9u);

  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_prepare(&first) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_enqueue_bound(
             &first, "source-only-event-a", "source-only-batch-a", first_wire,
             sizeof(first_wire), 0, 0) == EDR_OK);

  /* A prior bound row is already durable. Preparing a second assertion must
   * rotate to a new crash-gap tuple, not manufacture a delivery loss. */
  assert(edr_storage_queue_p0_source_only_latch_prepare(&second) == EDR_OK);
  assert(second.latched == 1 && second.recovery_required == 0 &&
         second.latch_counter > first.latch_counter);
  assert(edr_storage_queue_p0_source_only_enqueue_bound(
             &second, "source-only-event-b", "source-only-batch-b", second_wire,
             sizeof(second_wire), 0, 0) == EDR_OK);
  assert(status_count(path, "pending") == 2);

  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_get(&reopened) == EDR_OK);
  assert(reopened.latched == 1 && reopened.recovery_required == 0 &&
         strcmp(reopened.recovery_batch_id, "source-only-batch-b") == 0);

  reset_send_state(1);
  edr_storage_queue_poll_drain();
  edr_storage_queue_poll_drain();
  assert(status_count(path, "pending") == 0);
  assert(edr_storage_queue_p0_source_only_latch_get(&reopened) == EDR_OK);
  assert(reopened.latched == 0 && reopened.recovery_required == 0);
  edr_storage_queue_close();
  (void)remove(path);
}

/* Source-only evidence is a capability assertion, not disposable telemetry.
 * It must survive the ordinary retry and retention policies, and a malformed
 * durable wire must preserve an explicit recovery-required latch instead of
 * disappearing into dead-letter cleanup. */
static void test_p0_source_only_retry_retention_corruption_and_identity(void) {
  char path[256];
  char recreated_path[256];
  uint8_t wire[20];
  EdrStorageQueueP0SourceOnlyLatch latch;
  EdrStorageQueueP0SourceOnlyLatch rotated;
  EdrStorageQueueP0SourceOnlyLatch recreated;
  uint8_t prior_nonce[EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_NONCE_BYTES];
  snprintf(path, sizeof(path), "edr-source-only-retention-%ld.db", (long)TEST_PID);
  snprintf(recreated_path, sizeof(recreated_path), "edr-source-only-recreated-%ld.db",
           (long)TEST_PID);
  (void)remove(path);
  (void)remove(recreated_path);
  make_wire(wire, 0xe2u);

  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_prepare(&latch) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_enqueue_bound(
             &latch, "source-only-retained-event", "source-only-retained-batch", wire,
             sizeof(wire), 0, 0) == EDR_OK);
  edr_storage_queue_close();

  /* The test process globally sets MAX_RETRIES=1. A source row at that limit
   * must still be selected and retried, rather than moved to dead-letter. */
  sqlite_exec_path(path,
                   "UPDATE event_queue SET retry_count=1 WHERE batch_id='source-only-retained-batch';");
  assert(edr_storage_queue_open(path) == EDR_OK);
  reset_send_state(0);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0xe2u) == 1u);
  assert(batch_retry_count(path, "source-only-retained-batch") == 2);
  assert(status_count(path, "pending") == 1);
  assert(status_count(path, "dead_letter") == 0);
  edr_storage_queue_close();

  /* The durable retry counter is accounting only. At signed-64 saturation it
   * stays an integer and the source is still selected; no implicit terminal
   * policy may convert this capability assertion into a dead letter. */
  sqlite_exec_path(path,
                   "UPDATE event_queue SET next_retry_at=0,retry_count=9223372036854775807 "
                   "WHERE batch_id='source-only-retained-batch';");
  assert(edr_storage_queue_open(path) == EDR_OK);
  reset_send_state(0);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0xe2u) == 1u);
  assert(batch_retry_count(path, "source-only-retained-batch") == 9223372036854775807LL);
  assert(status_count(path, "pending") == 1);
  edr_storage_queue_close();

  /* Retention only deletes ordinary rows / terminals; an aged severity-2 row
   * remains replayable until an acknowledged transport deletes it. */
  sqlite_exec_path(path,
                   "UPDATE event_queue SET next_retry_at=0,created_at=1 WHERE batch_id='source-only-retained-batch';");
  assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_test_run_cleanup();
  assert(status_count(path, "pending") == 1);
  assert(status_count(path, "dead_letter") == 0);
  edr_storage_queue_close();

  /* A corrupt source wire cannot be retried or purged. Open-time validation
   * quarantines it and atomically changes the latch to recovery-required. */
  sqlite_exec_path(path,
                   "UPDATE event_queue SET payload=X'00' WHERE batch_id='source-only-retained-batch';");
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(status_count(path, "pending") == 0);
  assert(status_count(path, "corrupt") == 1);
  assert(status_count(path, "dead_letter") == 0);
  assert(edr_storage_queue_p0_source_only_latch_get(&latch) == EDR_OK);
  assert(latch.latched == 1 && latch.recovery_required == 1);

  /* A recovery audit gets a new exact binding. Its central ACK is the only
   * transition that can clear the capability fuse; the corrupt source stays
   * retained for operator inspection. */
  make_wire(wire, 0xe3u);
  assert(edr_storage_queue_p0_source_only_enqueue_bound(
             &latch, "source-only-recovery-event", "source-only-recovery-batch", wire,
             sizeof(wire), 0, 1) == EDR_OK);
  reset_send_state(1);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0xe3u) == 1u);
  assert(status_count(path, "pending") == 0);
  assert(status_count(path, "corrupt") == 1);
  assert(edr_storage_queue_p0_source_only_latch_is_set() == 0);
  assert(edr_storage_queue_p0_source_only_latch_get(&latch) == EDR_OK);
  memcpy(prior_nonce, latch.queue_nonce, sizeof(prior_nonce));
  edr_storage_queue_close();

  /* Counter wrap may rotate only after the severity-2 pending set is empty,
   * and it must rotate the CSPRNG nonce before issuing the next identity. */
  sqlite_exec_path(path,
                   "UPDATE queue_meta SET source_latch_counter=9223372036854775807,"
                   "source_latch_epoch=0,source_latch_state='clear',"
                   "source_latch_recovery_event_id='',source_latch_recovery_batch_id='',"
                   "source_latch_loss_detected=0,session_state='clean';");
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_prepare(&rotated) == EDR_OK);
  assert(rotated.latch_counter == 1u && rotated.latch_epoch == 1u);
  assert(memcmp(prior_nonce, rotated.queue_nonce, sizeof(prior_nonce)) != 0);
  edr_storage_queue_close();
  (void)remove(path);

  /* A recreated database receives a fresh nonce even if its first latch uses
   * the same counter/epoch as an earlier file. */
  assert(edr_storage_queue_open(recreated_path) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_prepare(&recreated) == EDR_OK);
  assert(recreated.latch_counter == 1u && recreated.latch_epoch == 1u);
  assert(memcmp(rotated.queue_nonce, recreated.queue_nonce, sizeof(rotated.queue_nonce)) != 0);
  edr_storage_queue_close();
  (void)remove(recreated_path);
}

static void test_p0_source_only_legacy_and_corrupt_meta_recover(void) {
  char legacy_path[256];
  char corrupt_path[256];
  uint8_t wire[20];
  EdrStorageQueueP0SourceOnlyLatch latch;
  EdrStorageQueueP0SourceOnlyLatch stale_latch;
  snprintf(legacy_path, sizeof(legacy_path), "edr-source-only-legacy-%ld.db", (long)TEST_PID);
  snprintf(corrupt_path, sizeof(corrupt_path), "edr-source-only-meta-corrupt-%ld.db",
           (long)TEST_PID);
  (void)remove(legacy_path);
  (void)remove(corrupt_path);

  /* Legacy header bits had a lossy 31/30-bit identity. They are never reused:
   * migration creates a new nonce and forces a capability recovery audit. */
  sqlite_exec_path(legacy_path, "PRAGMA user_version=1073741824; PRAGMA application_id=7;");
  assert(edr_storage_queue_open(legacy_path) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_get(&latch) == EDR_OK);
  assert(latch.latched == 1 && latch.recovery_required == 1 && latch.latch_counter == 1u);
  edr_storage_queue_close();
  (void)remove(legacy_path);

  assert(edr_storage_queue_open(corrupt_path) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_prepare(&stale_latch) == EDR_OK);
  assert(stale_latch.latched == 1 && stale_latch.recovery_required == 0);
  edr_storage_queue_close();
  /* A length-correct all-zero nonce is equally corrupt: it would otherwise
   * alias a non-CSPRNG source identity. Runtime validation repairs it even
   * for an older table that did not have the new CHECK expression. */
  sqlite_exec_path(corrupt_path,
                   "PRAGMA ignore_check_constraints=ON;"
                   "UPDATE queue_meta SET queue_nonce=zeroblob(16),session_state='clean';");
  assert(edr_storage_queue_open(corrupt_path) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_get(&latch) == EDR_OK);
  assert(latch.latched == 1 && latch.recovery_required == 1 && latch.latch_counter == 1u);
  assert(memcmp(latch.queue_nonce, stale_latch.queue_nonce, sizeof(latch.queue_nonce)) != 0);
  make_wire(wire, 0xe4u);
  /* A pre-repair tuple cannot bind or ACK the newly generated capability
   * identity, even where its old counter/epoch values happen to match. */
  assert(edr_storage_queue_p0_source_only_enqueue_bound(
             &stale_latch, "stale-zero-nonce-event", "stale-zero-nonce-batch", wire,
             sizeof(wire), 0, 0) == EDR_ERR_SQLITE_WRITE);
  edr_storage_queue_close();
  (void)remove(corrupt_path);
}

static void test_queue_and_terminal_metric_denominators(void) {
  char path[256];
  uint8_t wire_a[20], wire_b[20], intent[20];
  EdrStorageQueueCapacityMetrics before_queue, after_queue;
  EdrEnforcementTerminalJournalMetrics before_terminal, after_terminal;
  snprintf(path, sizeof(path), "edr-storage-queue-metrics-%ld.db", (long)TEST_PID);
  (void)remove(path);
  assert(test_setenv("EDR_QUEUE_MAX_DB_MB", "1") == 0);
  make_wire(wire_a, 0xf1u);
  make_wire(wire_b, 0xf2u);
  make_wire(intent, 0xf3u);
  assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_get_capacity_metrics(&before_queue);
  edr_storage_queue_enforcement_terminal_get_metrics(&before_terminal);
  assert(before_queue.pending_rows == 0u);
  assert(before_queue.oldest_pending_created_unix_s == 0u);
  assert(before_queue.oldest_pending_age_s == 0u);
  assert(before_queue.utilization_bps == 0u);

  assert(edr_storage_queue_enqueue("metrics-direct", wire_a, sizeof(wire_a), 0,
                                   EDR_STORAGE_QUEUE_SEVERITY_ORDINARY) == EDR_OK);
  assert(edr_storage_queue_enqueue("metrics-direct", wire_a, sizeof(wire_a), 0,
                                   EDR_STORAGE_QUEUE_SEVERITY_ORDINARY) == EDR_OK);
  assert(edr_storage_queue_enqueue("metrics-direct", wire_b, sizeof(wire_b), 0,
                                   EDR_STORAGE_QUEUE_SEVERITY_ORDINARY) == EDR_ERR_INVALID_ARG);
  edr_storage_queue_test_fail_next_enqueue_commits(1u);
  assert(edr_storage_queue_enqueue("metrics-commit", wire_b, sizeof(wire_b), 0,
                                   EDR_STORAGE_QUEUE_SEVERITY_TERMINAL) == EDR_ERR_SQLITE_WRITE);
  edr_storage_queue_get_capacity_metrics(&after_queue);
  assert(after_queue.enqueue_requests - before_queue.enqueue_requests == 4u);
  assert(after_queue.enqueue_reused - before_queue.enqueue_reused == 1u);
  assert(after_queue.enqueue_conflicts - before_queue.enqueue_conflicts == 1u);
  assert(after_queue.enqueue_admission_attempts - before_queue.enqueue_admission_attempts == 2u);
  assert(after_queue.enqueue_admitted - before_queue.enqueue_admitted == 1u);
  assert(after_queue.enqueue_capacity_rejected - before_queue.enqueue_capacity_rejected == 0u);
  assert(after_queue.enqueue_transaction_failures - before_queue.enqueue_transaction_failures == 1u);
  assert(after_queue.enqueue_commit_failures - before_queue.enqueue_commit_failures == 1u);
  assert(after_queue.enqueue_requests - before_queue.enqueue_requests ==
         (after_queue.enqueue_reused - before_queue.enqueue_reused) +
         (after_queue.enqueue_conflicts - before_queue.enqueue_conflicts) +
         (after_queue.enqueue_admission_attempts - before_queue.enqueue_admission_attempts));
  assert(after_queue.enqueue_admission_attempts - before_queue.enqueue_admission_attempts ==
         (after_queue.enqueue_admitted - before_queue.enqueue_admitted) +
         (after_queue.enqueue_capacity_rejected - before_queue.enqueue_capacity_rejected) +
         (after_queue.enqueue_transaction_failures - before_queue.enqueue_transaction_failures));
  assert(after_queue.pending_rows == 1u);
  assert(after_queue.oldest_pending_created_unix_s > 0u);
  assert(after_queue.utilization_bps > 0u);

  edr_storage_queue_test_fail_next_terminal_commits(1u);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "metrics-terminal-failed", "metrics-source-failed", "R-METRIC", "metrics-gen-failed",
             "metrics-intent-failed", intent, sizeof(intent)) ==
         EDR_ENFORCEMENT_TERMINAL_PRECREATE_ERROR);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "metrics-terminal", "metrics-source", "R-METRIC", "metrics-gen", "metrics-intent",
             intent, sizeof(intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  /* EXISTING is the durable no-reexecution result consumed by the executor. */
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "metrics-terminal", "metrics-source", "R-METRIC", "metrics-gen", "metrics-intent",
             intent, sizeof(intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_EXISTING);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "metrics-terminal", "metrics-source", "R-OTHER", "metrics-gen", "metrics-intent",
             intent, sizeof(intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_CONFLICT);
  edr_storage_queue_enforcement_terminal_get_metrics(&after_terminal);
  assert(after_terminal.precreate_requests - before_terminal.precreate_requests == 4u);
  assert(after_terminal.precreate_attempts - before_terminal.precreate_attempts == 4u);
  assert(after_terminal.precreate_created - before_terminal.precreate_created == 1u);
  assert(after_terminal.precreate_existing - before_terminal.precreate_existing == 1u);
  assert(after_terminal.precreate_conflicts - before_terminal.precreate_conflicts == 1u);
  assert(after_terminal.precreate_rejected - before_terminal.precreate_rejected == 0u);
  assert(after_terminal.precreate_transaction_failures -
             before_terminal.precreate_transaction_failures == 1u);
  assert(after_terminal.precreate_commit_failures - before_terminal.precreate_commit_failures == 1u);
  assert(after_terminal.precreate_attempts - before_terminal.precreate_attempts ==
         (after_terminal.precreate_created - before_terminal.precreate_created) +
         (after_terminal.precreate_existing - before_terminal.precreate_existing) +
         (after_terminal.precreate_conflicts - before_terminal.precreate_conflicts) +
         (after_terminal.precreate_rejected - before_terminal.precreate_rejected) +
         (after_terminal.precreate_transaction_failures -
          before_terminal.precreate_transaction_failures));
  assert(after_terminal.outcome_unknown >= before_terminal.outcome_unknown + 1u);

  edr_storage_queue_close();
  (void)remove(path);
  assert(test_unsetenv("EDR_QUEUE_MAX_DB_MB") == 0);
}

static int batch_retained_exact(const char *path, const char *batch_id,
                                const char *status, const uint8_t *wire, size_t len);

static void test_zero_or_invalid_limit_remains_finite(void) {
  char path[256];
  uint8_t wire[20];
  EdrStorageQueueCapacityMetrics metrics;
  const char *invalid[] = {"0", "not-a-number", "1suffix", "999999", "-1"};
  snprintf(path, sizeof(path), "edr-storage-queue-default-cap-%ld.db", (long)TEST_PID);
  (void)remove(path);
  assert(test_unsetenv("EDR_QUEUE_MAX_DB_MB") == 0);
  edr_storage_queue_configure(0u, 0u);
  make_wire(wire, 0xf4u);
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_enqueue("finite-default", wire, sizeof(wire), 0,
                                   EDR_STORAGE_QUEUE_SEVERITY_ORDINARY) == EDR_OK);
  edr_storage_queue_get_capacity_metrics(&metrics);
  assert(metrics.accounting_available == 1u);
  assert(metrics.max_bytes == 512u * 1024u * 1024u);
  assert(metrics.capacity_limit_defaulted == 1u);
  assert(metrics.pending_rows == 1u && metrics.oldest_pending_created_unix_s > 0u);
  edr_storage_queue_close();
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
    assert(test_setenv("EDR_QUEUE_MAX_DB_MB", invalid[i]) == 0);
    assert(edr_storage_queue_open(path) == EDR_OK);
    edr_storage_queue_get_capacity_metrics(&metrics);
    assert(metrics.max_bytes == 512u * 1024u * 1024u && metrics.capacity_limit_defaulted == 1u);
    assert(batch_retained_exact(path, "finite-default", "pending", wire, sizeof(wire)));
    edr_storage_queue_close();
  }
  assert(test_setenv("EDR_QUEUE_MAX_DB_MB", "1") == 0);
  assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_get_capacity_metrics(&metrics);
  assert(metrics.max_bytes == 1024u * 1024u && metrics.capacity_limit_defaulted == 0u);
  edr_storage_queue_close();
  assert(test_unsetenv("EDR_QUEUE_MAX_DB_MB") == 0);
  (void)remove(path);
}

#if !defined(_WIN32)
static void test_terminal_journal_stale_generation_cannot_ack_reopened_row(void) {
  char old_path[256];
  char new_path[256];
  uint8_t intent[20];
  pthread_t stale_drain;
  snprintf(old_path, sizeof(old_path), "edr-terminal-journal-old-%ld.db", (long)TEST_PID);
  snprintf(new_path, sizeof(new_path), "edr-terminal-journal-new-%ld.db", (long)TEST_PID);
  (void)remove(old_path);
  (void)remove(new_path);
  make_wire(intent, 0x81u);
  assert(edr_storage_queue_open(old_path) == EDR_OK);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "same-terminal-key", "old-event", "R-TERMINAL", "old-generation",
             "same-terminal-intent", intent, sizeof(intent)) ==
         EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  reset_send_state(1);
  block_next_send();
  test_sleep_ms(250u);
  assert(pthread_create(&stale_drain, NULL, drain_worker, NULL) == 0);
  wait_for_send();

  /* The new database deliberately reuses row id, idempotency key, and wire.
   * Only the open generation proves that the in-flight old transport ACK is
   * not acknowledgement of the new journal row. */
  edr_storage_queue_close();
  assert(edr_storage_queue_open(new_path) == EDR_OK);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "same-terminal-key", "new-event", "R-TERMINAL", "new-generation",
             "same-terminal-intent", intent, sizeof(intent)) ==
         EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  release_send();
  assert(pthread_join(stale_drain, NULL) == 0);
  assert(terminal_journal_state_is(new_path, "same-terminal-key", "pending_intent"));
  assert(terminal_journal_intent_acked(new_path, "same-terminal-key") == 0);

  test_sleep_ms(250u);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0x81u) == 2u);
  assert(terminal_journal_intent_acked(new_path, "same-terminal-key") == 1);
  edr_storage_queue_close();
  (void)remove(old_path);
  (void)remove(new_path);
}
#endif

static void test_retry_backoff_and_fairness_survive_reopen(void) {
  char path[256];
  uint8_t low[20], poison[20], high[20];
  const int64_t now = (int64_t)time(NULL);
  snprintf(path, sizeof(path), "edr-queue-fairness-%ld.db", (long)TEST_PID);
  remove(path);
  /* Upgrade a real pre-deadline database, preserving its records and identity. */
  sqlite_exec_path(path, "CREATE TABLE event_queue (id INTEGER PRIMARY KEY AUTOINCREMENT,"
                        "batch_id TEXT NOT NULL UNIQUE,payload BLOB NOT NULL,created_at INTEGER NOT NULL,"
                        "compressed INTEGER NOT NULL DEFAULT 0,severity INTEGER NOT NULL DEFAULT 0,"
                        "retry_count INTEGER NOT NULL DEFAULT 0,status TEXT NOT NULL DEFAULT 'pending',"
                        "terminal_reason TEXT NOT NULL DEFAULT '',terminal_at INTEGER NOT NULL DEFAULT 0);");
  assert(edr_storage_queue_open(path) == EDR_OK);
  make_wire(low, 0xf0u); make_wire(poison, 0xf1u); make_wire(high, 0xf2u);
  assert(edr_storage_queue_enqueue("old-low", low, sizeof(low), 0, 0) == EDR_OK);
  assert(edr_storage_queue_enqueue("poison", poison, sizeof(poison), 0, 2) == EDR_OK);
  for (int i = 0; i < 16; ++i) {
    char id[32]; snprintf(id, sizeof(id), "new-high-%d", i);
    assert(edr_storage_queue_enqueue(id, high, sizeof(high), 0, 2) == EDR_OK);
  }
  reset_send_state(1);
  s_reject_value = 0xf1;
  edr_storage_queue_test_set_delivery_time(now);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0xf1u) == 1u);
  assert(batch_retry_count(path, "poison") == 1);
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0xf1u) == 1u); /* reopen does not defeat backoff */
  assert(send_calls_for(0xf0u) == 1u); /* progress within eight eligible selections */
  for (int i = 0; i < 3; ++i) {
    edr_storage_queue_close();
    assert(edr_storage_queue_open(path) == EDR_OK);
    edr_storage_queue_poll_drain();
  }
  assert(send_calls_for(0xf2u) == 16u);
  assert(status_count(path, "pending") == 1);
  assert(edr_storage_queue_pending_count() == 1u); /* delayed is not empty */
  assert(status_count(path, "dead_letter") == 0);
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_test_set_delivery_time(now + 1);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0xf1u) == 2u);
  assert(batch_retry_count(path, "poison") == 2); /* protected despite MAX_RETRIES=1 */
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_test_set_delivery_time(now + 3);
  s_reject_value = -1;
  s_receipt_body = NULL;
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0xf1u) == 3u);
  assert(status_count(path, "pending") == 0);
  edr_storage_queue_close();
  edr_storage_queue_test_set_delivery_time(-1);
  remove(path);
}

static void test_terminal_rejection_allows_other_journals(void) {
  char path[256];
  uint8_t intent[20], bad[20], good[20];
  snprintf(path, sizeof(path), "edr-terminal-fairness-%ld.db", (long)TEST_PID);
  remove(path);
  make_wire(intent, 0xd0u); make_wire(bad, 0xd1u); make_wire(good, 0xd2u);
  assert(edr_storage_queue_open(path) == EDR_OK);
  for (int i = 0; i < 2; ++i) {
    const char *key = i ? "good-journal" : "bad-journal";
    const char *src = i ? "good-source" : "bad-source";
    const char *combined = i ? "good-combined" : "bad-combined";
    assert(edr_storage_queue_enforcement_terminal_precreate(
               key, key, "R-TERMINAL", key, key, intent, sizeof(intent)) ==
           EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
    assert(edr_storage_queue_enforcement_terminal_update(
               key, src, i ? good : bad, sizeof(good), combined, good, sizeof(good)) == EDR_OK);
  }
  reset_send_state(1);
  s_reject_value = 0xd1;
  edr_storage_queue_test_set_delivery_time((int64_t)time(NULL));
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0xd1u) == 1u);
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0xd1u) == 1u);
  assert(terminal_journal_state_is(path, "bad-journal", "ready"));
  assert(terminal_journal_state_is(path, "good-journal", "completed"));
  edr_storage_queue_close();
  edr_storage_queue_test_set_delivery_time(-1);
  remove(path);
}

static void test_queue_requires_bound_receipt_after_lost_response(void) {
  char path[256], hash[65], receipt[1024];
  uint8_t wire[20];
  int64_t now = (int64_t)time(NULL);
  snprintf(path, sizeof(path), "edr-receipt-queue-%ld.db", (long)TEST_PID);
  remove(path); make_wire(wire, 0xb9u);
  assert(edr_sha256_hex(wire, sizeof(wire), hash) == 0);
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_enqueue("receipt-batch", wire, sizeof(wire), 0, 2) == EDR_OK);
  reset_send_state(0); /* server response never arrived */
  edr_storage_queue_test_set_delivery_time(now);
  edr_storage_queue_poll_drain();
  assert(status_count(path, "pending") == 1);
  assert(ack_receipt_count(path, "receipt-batch", wire, sizeof(wire)) == 0);
  edr_storage_queue_close(); assert(edr_storage_queue_open(path) == EDR_OK);
  reset_send_state(1); s_receipt_body = "{}"; /* HTTP success without a receipt */
  edr_storage_queue_test_set_delivery_time(now + 301);
  edr_storage_queue_poll_drain();
  assert(status_count(path, "pending") == 1);
  assert(ack_receipt_count(path, "receipt-batch", wire, sizeof(wire)) == 0);
  edr_storage_queue_close(); assert(edr_storage_queue_open(path) == EDR_OK);
  snprintf(receipt, sizeof(receipt),
           "{\"code\":\"OK\",\"data\":{\"accepted\":true,\"ack\":{\"version\":1,\"state\":\"durable\","
           "\"endpoint_id\":\"test-endpoint\",\"batch_id\":\"receipt-batch\",\"payload_sha256\":\"%s\"}}}", hash);
  s_receipt_body = receipt;
  edr_storage_queue_test_set_delivery_time(now + 602);
  edr_storage_queue_poll_drain();
  assert(status_count(path, "pending") == 0);
  assert(ack_receipt_count(path, "receipt-batch", wire, sizeof(wire)) == 1);
  edr_storage_queue_close(); edr_storage_queue_test_set_delivery_time(-1);
  s_receipt_body = NULL; remove(path);
}

static void test_event_selection_oom_preserves_durable_payload(void) {
  for (unsigned kind = 0; kind < 2; ++kind) for (int severity = 0; severity <= 2; ++severity) {
    char path[256]; uint8_t wire[20];
    EdrStorageQueueCapacityMetrics before, after;
    snprintf(path, sizeof(path), "edr-event-oom-%u-%d-%ld.db", kind, severity, (long)TEST_PID);
    remove(path); make_wire(wire, (uint8_t)(0xa0 + severity));
    assert(edr_storage_queue_open(path) == EDR_OK);
    assert(edr_storage_queue_enqueue("oom-batch", wire, sizeof(wire), 0, severity) == EDR_OK);
    reset_send_state(1);
    edr_storage_queue_get_capacity_metrics(&before);
    edr_storage_queue_test_fail_event_alloc(kind, 1u);
    edr_storage_queue_poll_drain();
    assert(total_send_calls() == 0u);
    assert(status_count(path, "pending") == 1);
    assert(status_count(path, "dead_letter") == 0 && status_count(path, "corrupt") == 0);
    assert(batch_retry_count(path, "oom-batch") == 0);
    edr_storage_queue_get_capacity_metrics(&after);
    assert(after.delivery_resource_deferred == before.delivery_resource_deferred + 1u);
    assert(after.delivery_failed == before.delivery_failed);
    edr_storage_queue_close(); assert(edr_storage_queue_open(path) == EDR_OK);
    edr_storage_queue_poll_drain();
    assert(total_send_calls() == 1u && status_count(path, "pending") == 0);
    assert(s_last_payload_len == sizeof(wire) && !memcmp(s_last_payload, wire, sizeof(wire)));
    edr_storage_queue_close(); remove(path);
  }
}

static void test_retention_runs_while_transport_circuit_is_open(void) {
  char path[256]; uint8_t wire[20]; EdrStorageQueueCapacityMetrics metrics;
  snprintf(path, sizeof(path), "edr-offline-retention-%ld.db", (long)TEST_PID);
  remove(path); make_wire(wire, 0x81u);
  assert(test_setenv("EDR_QUEUE_RETENTION_HOURS", "1") == 0);
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_enqueue("old-ordinary", wire, sizeof(wire), 0, 0) == EDR_OK);
  assert(edr_storage_queue_enqueue("old-terminal", wire, sizeof(wire), 0, 1) == EDR_OK);
  assert(edr_storage_queue_enqueue("old-source", wire, sizeof(wire), 0, 2) == EDR_OK);
  edr_storage_queue_close();
  sqlite_exec_path(path, "UPDATE event_queue SET created_at=1;");
  assert(edr_storage_queue_open(path) == EDR_OK);
  reset_send_state(1); s_circuit_open = 1;
  edr_storage_queue_poll_drain();
  assert(total_send_calls() == 0u);
  assert(batch_row_id(path, "old-ordinary") > 0);
  assert(status_count(path, "dead_letter") == 2);
  assert(queue_batch_pending(path, "old-source"));
  edr_storage_queue_get_capacity_metrics(&metrics);
  assert(metrics.retained_nonpending_bytes > 0u);
  assert(metrics.used_bytes > metrics.retained_nonpending_bytes);
  edr_storage_queue_close(); remove(path); s_circuit_open = 0;
  assert(test_unsetenv("EDR_QUEUE_RETENTION_HOURS") == 0);
}

static void test_pinned_wal_is_visible_beyond_logical_budget(void) {
  char path[256]; sqlite3 *reader = NULL;
  uint8_t *wire = malloc(65536u); EdrStorageQueueCapacityMetrics metrics;
  assert(wire); make_large_wire(wire, 65536u, 0x82u);
  snprintf(path, sizeof(path), "edr-pinned-wal-%ld.db", (long)TEST_PID);
  remove(path); assert(test_setenv("EDR_QUEUE_MAX_DB_MB", "1") == 0);
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(sqlite3_open(path, &reader) == SQLITE_OK);
  assert(sqlite3_exec(reader, "BEGIN; SELECT COUNT(*) FROM event_queue;", NULL, NULL, NULL) == SQLITE_OK);
  reset_send_state(1);
  for (int i = 0; i < 18; ++i) {
    char id[48]; snprintf(id, sizeof(id), "wal-retained-history-%d", i);
    assert(edr_storage_queue_enqueue(id, wire, 65536u, 0, 0) == EDR_OK);
    edr_storage_queue_poll_drain();
    assert(edr_storage_queue_pending_count() == 0u);
    /* A second reader keeps the WAL generation alive across owner reopen. */
    edr_storage_queue_close(); assert(edr_storage_queue_open(path) == EDR_OK);
  }
  edr_storage_queue_get_capacity_metrics(&metrics);
  assert(metrics.used_bytes == 0u && metrics.wal_bytes > metrics.max_bytes);
  assert(metrics.physical_bytes == metrics.db_bytes + metrics.wal_bytes + metrics.shm_bytes);
  assert(sqlite3_exec(reader, "ROLLBACK;", NULL, NULL, NULL) == SQLITE_OK);
  sqlite3_close(reader); edr_storage_queue_close();
  remove(path); free(wire); assert(test_unsetenv("EDR_QUEUE_MAX_DB_MB") == 0);
}

static void test_unconfigured_transport_preserves_retry_budget(void) {
  for (int severity = 0; severity <= 2; ++severity) {
    char path[256];
    uint8_t wire[20];
    snprintf(path, sizeof(path), "edr-unconfigured-%d-%ld.db", severity, (long)TEST_PID);
    remove(path);
    make_wire(wire, (uint8_t)(0xb0 + severity));
    assert(edr_storage_queue_open(path) == EDR_OK);
    assert(edr_storage_queue_enqueue("not-sent", wire, sizeof(wire), 0, severity) == EDR_OK);
    reset_send_state(0);
    s_configured = 0;
    for (int poll = 0; poll < 3; ++poll) {
      edr_storage_queue_poll_drain();
      assert(total_send_calls() == 0u);
      assert(batch_retry_count(path, "not-sent") == 0);
      assert(status_count(path, "pending") == 1);
      edr_storage_queue_close();
      assert(edr_storage_queue_open(path) == EDR_OK);
    }
    reset_send_state(1);
    edr_storage_queue_poll_drain();
    assert(total_send_calls() == 1u);
    assert(status_count(path, "pending") == 0);
    assert(status_count(path, "dead_letter") == 0);
    edr_storage_queue_close();
    remove(path);
  }
}

static void test_budget_deferral_preserves_terminal_frames(void) {
  char path[256];
  uint8_t intent[20], source[20], combined[20];
  snprintf(path, sizeof(path), "edr-budget-terminal-%ld.db", (long)TEST_PID);
  (void)remove(path);
  make_wire(intent, 0xc9u);
  make_wire(source, 0xcau);
  make_wire(combined, 0xcbu);
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "budget-terminal", "budget-event", "R-TERMINAL", "budget-generation",
             "budget-intent", intent, sizeof(intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  assert(edr_storage_queue_enforcement_terminal_update(
             "budget-terminal", "budget-source", source, sizeof(source),
             "budget-combined", combined, sizeof(combined)) == EDR_OK);
  reset_send_state(0);
  s_configured = 0;
  edr_storage_queue_poll_drain();
  assert(total_send_calls() == 0u);
  assert(terminal_journal_frame_retry_count(path, "budget-terminal", 1) == 0);
  assert(terminal_journal_frame_retry_count(path, "budget-terminal", 0) == 0);
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  s_configured = 1;
  s_circuit_open = 0;
  s_reject_value = -1;
  s_receipt_body = NULL;
  s_defer_during_send = 1;
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0xc9u) == 1u && send_calls_for(0xcau) == 0u && send_calls_for(0xcbu) == 0u);
  assert(terminal_journal_intent_acked(path, "budget-terminal") == 0);
  assert(terminal_journal_frame_retry_count(path, "budget-terminal", 1) == 0);
  assert(terminal_journal_frame_retry_count(path, "budget-terminal", 0) == 0);
  assert(terminal_journal_state_is(path, "budget-terminal", "ready"));
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_poll_drain();
  assert(total_send_calls() == 1u);
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  reset_send_state(1);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0xcau) == 1u && send_calls_for(0xcbu) == 1u);
  assert(terminal_journal_state_is(path, "budget-terminal", "completed"));
  edr_storage_queue_close();
  (void)remove(path);
}

static void test_budget_deferral_preserves_ordinary_retry_allowance(void) {
  char path[256];
  uint8_t wire[20];
  snprintf(path, sizeof(path), "edr-budget-queue-%ld.db", (long)TEST_PID);
  (void)remove(path);
  assert(edr_storage_queue_open(path) == EDR_OK);
  make_wire(wire, 0xceu);
  assert(edr_storage_queue_enqueue("budget-wait", wire, sizeof(wire), 0, 0) == EDR_OK);
  reset_send_state(0);
  s_defer_during_send = 1;
  edr_storage_queue_poll_drain();
  assert(total_send_calls() == 1u && s_telemetry_deferred);
  assert(batch_retry_count(path, "budget-wait") == 0);
  assert(status_count(path, "pending") == 1);
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_poll_drain();
  assert(total_send_calls() == 1u && status_count(path, "pending") == 1);
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  reset_send_state(1);
  edr_storage_queue_poll_drain();
  assert(total_send_calls() == 1u && status_count(path, "pending") == 0);
  edr_storage_queue_close();
  (void)remove(path);
}

static void test_p0_deferred_match_durable_lifecycle(void) {
  char path[256];
  const uint8_t snapshot_a[] = "{\"schema\":1,\"rule\":\"R-A\",\"binding\":\"cold\"}";
  const uint8_t snapshot_b[] = "{\"schema\":1,\"rule\":\"R-B\",\"binding\":\"warm\"}";
  const uint8_t snapshot_c[] = "{\"schema\":1,\"rule\":\"R-C\",\"binding\":\"late\"}";
  const uint8_t snapshot_d[] = "{\"schema\":1,\"rule\":\"R-D\",\"binding\":\"poison\"}";
  const uint8_t snapshot_e[] = "{\"schema\":1,\"rule\":\"R-E\",\"binding\":\"healthy\"}";
  const uint8_t snapshot_f[] = "{\"schema\":1,\"rule\":\"R-F\",\"binding\":\"bad-family\"}";
  char key_a[65], key_b[65], key_c[65], key_d[65], key_e[65], key_f[65];
  char selected_key[65];
  uint8_t *selected_payload = NULL;
  size_t selected_len = 0u;
  const int64_t retry_now = (int64_t)time(NULL);
  uint8_t wire[20];
  EdrStorageQueueCapacityMetrics metrics;
  sqlite3 *legacy = NULL;
  snprintf(path, sizeof(path), "edr-p0-deferred-lifecycle-%ld.db", (long)TEST_PID);
  (void)remove(path);
  snapshot_key(snapshot_a, sizeof(snapshot_a) - 1u, key_a);
  snapshot_key(snapshot_b, sizeof(snapshot_b) - 1u, key_b);
  snapshot_key(snapshot_c, sizeof(snapshot_c) - 1u, key_c);
  snapshot_key(snapshot_d, sizeof(snapshot_d) - 1u, key_d);
  snapshot_key(snapshot_e, sizeof(snapshot_e) - 1u, key_e);
  snapshot_key(snapshot_f, sizeof(snapshot_f) - 1u, key_f);
  make_wire(wire, 71u);

  assert(sqlite3_open(path, &legacy) == SQLITE_OK);
  assert(sqlite3_exec(legacy, "CREATE TABLE legacy_probe(id INTEGER PRIMARY KEY);",
                      NULL, NULL, NULL) == SQLITE_OK);
  assert(sqlite3_close(legacy) == SQLITE_OK);
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_p0_deferred_contains(key_a) == 0);
  assert(edr_storage_queue_p0_deferred_retain(
             key_a, 16u, snapshot_a, sizeof(snapshot_a) - 1u) == EDR_ERR_INVALID_ARG);
  assert(edr_storage_queue_p0_deferred_peek(
             16u, selected_key, &selected_payload, &selected_len) == -1);
  edr_storage_queue_test_fail_next_p0_deferred_commits(1u);
  assert(edr_storage_queue_p0_deferred_retain(
             key_a, 4u, snapshot_a, sizeof(snapshot_a) - 1u) == EDR_ERR_SQLITE_WRITE);
  assert(edr_storage_queue_p0_deferred_contains(key_a) == 0);
  assert(edr_storage_queue_p0_deferred_retain(
             key_a, 4u, snapshot_a, sizeof(snapshot_a) - 1u) == EDR_OK);
  assert(edr_storage_queue_p0_deferred_retain(
             key_a, 4u, snapshot_a, sizeof(snapshot_a) - 1u) == EDR_OK);
  assert(edr_storage_queue_p0_deferred_retain(
             key_a, 8u, snapshot_a, sizeof(snapshot_a) - 1u) == EDR_ERR_INVALID_ARG);
  assert(edr_storage_queue_p0_deferred_retain(
             key_a, 4u, snapshot_b, sizeof(snapshot_b) - 1u) == EDR_ERR_INVALID_ARG);
  assert(edr_storage_queue_p0_deferred_contains(key_a) == 1);
  edr_storage_queue_get_capacity_metrics(&metrics);
  assert(metrics.accounting_available == 1u);
  assert(metrics.p0_deferred_pending_rows == 1u);
  assert(metrics.p0_deferred_failed_rows == 0u);
  assert(edr_storage_queue_p0_deferred_peek(
             2u, selected_key, &selected_payload, &selected_len) == 0);
  assert(edr_storage_queue_p0_deferred_peek(
             4u, selected_key, &selected_payload, &selected_len) == 1);
  assert(strcmp(selected_key, key_a) == 0);
  assert(selected_len == sizeof(snapshot_a) - 1u);
  assert(memcmp(selected_payload, snapshot_a, selected_len) == 0);
  free(selected_payload);
  selected_payload = NULL;

#if !defined(_WIN32)
  {
    enum { workers = 12 };
    pthread_t threads[workers];
    DeferredRetainWork work[workers];
    for (unsigned i = 0u; i < workers; ++i) {
      work[i].key = key_a;
      work[i].family_mask = 4u;
      work[i].payload = snapshot_a;
      work[i].payload_len = sizeof(snapshot_a) - 1u;
      work[i].result = EDR_ERR_INTERNAL;
      assert(pthread_create(&threads[i], NULL, deferred_retain_worker, &work[i]) == 0);
    }
    for (unsigned i = 0u; i < workers; ++i) {
      assert(pthread_join(threads[i], NULL) == 0);
      assert(work[i].result == EDR_OK);
    }
    assert(p0_deferred_count(path, "pending") == 1);
  }
#endif

  reset_send_state(1);
  test_sleep_ms(250u);
  edr_storage_queue_poll_drain();
  assert(total_send_calls() == 0u);
  assert(p0_deferred_count(path, "pending") == 1);
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_p0_deferred_contains(key_a) == 1);

  /* FULL commits and a separate SQLite read may cross a wall-clock second.
   * Freeze only retry/peek time so these assertions test the durable deadline,
   * not whether this runner completes the intervening I/O within one second. */
  edr_storage_queue_test_set_p0_deferred_time(retry_now);
  assert(edr_storage_queue_p0_deferred_retry(key_a, "family_still_unhealthy") == EDR_OK);
  {
    sqlite3_int64 retry_count = 0;
    sqlite3_int64 next_retry_at = 0;
    p0_deferred_retry_values(path, key_a, &retry_count, &next_retry_at);
    assert(retry_count == 1 && next_retry_at == retry_now + 1);
  }
  assert(edr_storage_queue_p0_deferred_peek(
             4u, selected_key, &selected_payload, &selected_len) == 0);
  assert(selected_key[0] == '\0' && selected_payload == NULL && selected_len == 0u);
  edr_storage_queue_test_fail_next_p0_deferred_commits(1u);
  assert(edr_storage_queue_p0_deferred_retry(key_a, "failed_retry_commit") == EDR_ERR_SQLITE_WRITE);
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  {
    sqlite3_int64 retry_count = 0;
    sqlite3_int64 next_retry_at = 0;
    p0_deferred_retry_values(path, key_a, &retry_count, &next_retry_at);
    assert(retry_count == 1 && next_retry_at == retry_now + 1);
    assert(p0_deferred_state_matches(path, key_a, "pending",
                                     (int)(sizeof(snapshot_a) - 1u),
                                     "family_still_unhealthy"));
  }
  assert(edr_storage_queue_p0_deferred_peek(
             4u, selected_key, &selected_payload, &selected_len) == 0);
  edr_storage_queue_test_set_p0_deferred_time(retry_now + 1);
  assert(edr_storage_queue_p0_deferred_peek(
             4u, selected_key, &selected_payload, &selected_len) == 1);
  assert(strcmp(selected_key, key_a) == 0);
  assert(selected_len == sizeof(snapshot_a) - 1u);
  assert(memcmp(selected_payload, snapshot_a, selected_len) == 0);
  free(selected_payload);
  selected_payload = NULL;
  p0_deferred_exec_sql(path,
      "UPDATE p0_deferred_match SET retry_count=9,next_retry_at=0 WHERE state='pending';");
  assert(edr_storage_queue_p0_deferred_retry(key_a, "backoff_cap") == EDR_OK);
  {
    sqlite3_int64 retry_count = 0;
    sqlite3_int64 next_retry_at = 0;
    p0_deferred_retry_values(path, key_a, &retry_count, &next_retry_at);
    assert(retry_count == 10 && next_retry_at == retry_now + 61);
  }
  edr_storage_queue_test_set_p0_deferred_time(retry_now + 60);
  assert(edr_storage_queue_p0_deferred_peek(
             4u, selected_key, &selected_payload, &selected_len) == 0);
  edr_storage_queue_test_set_p0_deferred_time(retry_now + 61);
  assert(edr_storage_queue_p0_deferred_peek(
             4u, selected_key, &selected_payload, &selected_len) == 1);
  assert(strcmp(selected_key, key_a) == 0);
  free(selected_payload);
  selected_payload = NULL;
  edr_storage_queue_test_set_p0_deferred_time(-1);

  edr_storage_queue_test_fail_next_p0_deferred_commits(1u);
  assert(edr_storage_queue_p0_deferred_complete(
             key_a, "p0-deferred-batch-a", wire, sizeof(wire),
             "queue_accepted") == EDR_ERR_SQLITE_WRITE);
  assert(p0_deferred_state_matches(path, key_a, "pending",
                                   (int)(sizeof(snapshot_a) - 1u),
                                   "backoff_cap"));
  assert(batch_row_id(path, "p0-deferred-batch-a") == -1);
  assert(edr_storage_queue_p0_deferred_complete(
             key_a, "p0-deferred-batch-a", wire, sizeof(wire),
             "queue_accepted") == EDR_OK);
  assert(p0_deferred_state_matches(path, key_a, "completed", 0, "queue_accepted"));
  assert(batch_row_id(path, "p0-deferred-batch-a") > 0);
  reset_send_state(1);
  test_sleep_ms(250u);
  edr_storage_queue_poll_drain();
  assert(batch_row_id(path, "p0-deferred-batch-a") == -1);
  assert(edr_storage_queue_p0_deferred_contains(key_a) == 1);
  edr_storage_queue_get_capacity_metrics(&metrics);
  assert(metrics.p0_deferred_pending_rows == 0u);
  assert(metrics.used_bytes >= 512u + 64u + 64u);
  assert(edr_storage_queue_p0_deferred_retain(
             key_a, 4u, snapshot_a, sizeof(snapshot_a) - 1u) == EDR_OK);
  assert(edr_storage_queue_p0_deferred_complete(
             key_a, "must-not-reinsert", wire, sizeof(wire),
             "queue_accepted") == EDR_OK);
  assert(batch_row_id(path, "must-not-reinsert") == -1);

  assert(edr_storage_queue_p0_deferred_retain(
             key_b, 4u, snapshot_b, sizeof(snapshot_b) - 1u) == EDR_OK);
  assert(edr_storage_queue_p0_deferred_complete(
             key_b, NULL, NULL, 0u, "policy_denied") == EDR_OK);
  assert(p0_deferred_state_matches(path, key_b, "completed", 0, "policy_denied"));
  assert(edr_storage_queue_p0_deferred_retain(
             key_c, 4u, snapshot_c, sizeof(snapshot_c) - 1u) == EDR_OK);
  assert(edr_storage_queue_p0_deferred_fail(key_c, "ir_bundle_changed") == EDR_OK);
  assert(edr_storage_queue_p0_deferred_fail(
             key_c, "ignored_idempotent_reason") == EDR_OK);
  assert(p0_deferred_state_matches(path, key_c, "failed",
                                   (int)(sizeof(snapshot_c) - 1u),
                                   "ir_bundle_changed"));

  assert(edr_storage_queue_p0_deferred_retain(
             key_d, 4u, snapshot_d, sizeof(snapshot_d) - 1u) == EDR_OK);
  assert(edr_storage_queue_p0_deferred_retain(
             key_f, 8u, snapshot_f, sizeof(snapshot_f) - 1u) == EDR_OK);
  {
    char corrupt_sql[768];
    snprintf(corrupt_sql, sizeof(corrupt_sql),
             "UPDATE p0_deferred_match SET payload_sha256='%064d',created_at=1 "
             "WHERE key_sha256='%s';"
             "PRAGMA ignore_check_constraints=ON;"
             "UPDATE p0_deferred_match SET family_mask=16,created_at=1 "
             "WHERE key_sha256='%s';"
             "PRAGMA ignore_check_constraints=OFF;",
             0, key_d, key_f);
    p0_deferred_exec_sql(path, corrupt_sql);
  }
  assert(edr_storage_queue_p0_deferred_retain(
             key_e, 4u, snapshot_e, sizeof(snapshot_e) - 1u) == EDR_OK);
  assert(edr_storage_queue_p0_deferred_peek(
             4u, selected_key, &selected_payload, &selected_len) == 1);
  assert(strcmp(selected_key, key_e) == 0);
  assert(memcmp(selected_payload, snapshot_e, selected_len) == 0);
  free(selected_payload);
  selected_payload = NULL;
  assert(p0_deferred_state_matches(path, key_d, "failed",
                                   (int)(sizeof(snapshot_d) - 1u),
                                   "deferred_snapshot_sha256_mismatch"));
  assert(p0_deferred_state_matches(path, key_f, "failed",
                                   (int)(sizeof(snapshot_f) - 1u),
                                   "invalid_deferred_snapshot_metadata"));
  edr_storage_queue_get_capacity_metrics(&metrics);
  assert(metrics.p0_deferred_failed_rows == 3u);
  assert(metrics.p0_deferred_pending_rows == 1u);

  p0_deferred_exec_sql(
      path,
      "UPDATE p0_deferred_match SET completed_at=1,updated_at=1 WHERE state='completed';"
      "UPDATE p0_deferred_match SET created_at=1,updated_at=1 WHERE state IN ('pending','failed');");
  /* A raw keyset may first finish the protected suffix before wrapping to
   * newly aged tombstones. Each call remains bounded; all original owner
   * preservation assertions below still apply. */
  for(unsigned pass=0;pass<6u && p0_deferred_count(path,"completed")>0;++pass)
    edr_storage_queue_test_run_cleanup();
  assert(p0_deferred_count(path, "completed") == 0);
  assert(p0_deferred_count(path, "pending") == 1);
  assert(p0_deferred_count(path, "failed") == 3);
  edr_storage_queue_close();
  (void)remove(path);
}

static void test_p0_deferred_capacity_atomic_handoff(void) {
  char path[256];
  uint8_t *snapshot = (uint8_t *)malloc(EDR_STORAGE_QUEUE_P0_DEFERRED_MAX_PAYLOAD_BYTES);
  uint8_t *ordinary_wire = (uint8_t *)malloc(65536u);
  uint8_t *alert_wire = (uint8_t *)malloc(65536u);
  char key[65];
  EdrStorageQueueCapacityMetrics before;
  EdrStorageQueueCapacityMetrics after;
  assert(snapshot && ordinary_wire && alert_wire);
  memset(snapshot, 'x', EDR_STORAGE_QUEUE_P0_DEFERRED_MAX_PAYLOAD_BYTES);
  make_large_wire(ordinary_wire, 65536u, 81u);
  make_large_wire(alert_wire, 65536u, 82u);
  snapshot_key(snapshot, EDR_STORAGE_QUEUE_P0_DEFERRED_MAX_PAYLOAD_BYTES, key);
  snprintf(path, sizeof(path), "edr-p0-deferred-capacity-%ld.db", (long)TEST_PID);
  (void)remove(path);
  edr_storage_queue_configure(1u, 1u);
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_enqueue("deferred-capacity-ordinary", ordinary_wire,
                                   65536u, 0, 0) == EDR_OK);
  assert(edr_storage_queue_p0_deferred_retain(
             key, 1u, snapshot,
             EDR_STORAGE_QUEUE_P0_DEFERRED_MAX_PAYLOAD_BYTES) == EDR_OK);
  edr_storage_queue_get_capacity_metrics(&before);
  assert(before.p0_deferred_pending_rows == 1u);
  assert(edr_storage_queue_p0_deferred_complete(
             key, "deferred-capacity-alert", alert_wire, 65536u,
             "queue_accepted") == EDR_OK);
  edr_storage_queue_get_capacity_metrics(&after);
  assert(after.p0_deferred_pending_rows == 0u);
  assert(after.used_bytes < before.used_bytes);
  assert(batch_row_id(path, "deferred-capacity-alert") > 0);
  edr_storage_queue_close();
  edr_storage_queue_configure(0u, 0u);
  (void)remove(path);
  free(snapshot);
  free(ordinary_wire);
  free(alert_wire);
}

static void test_p0_deferred_retained_payload_cap(void) {
  char path[256];
  sqlite3 *db = NULL;
  sqlite3_stmt *st = NULL;
  char payload[64];
  char key[65];
  char first_key[65];
  EdrStorageQueueCapacityMetrics before_fail;
  EdrStorageQueueCapacityMetrics after_fail;
  const uint8_t overflow[] = "{\"overflow\":true}";
  char overflow_key[65];
  snprintf(path, sizeof(path), "edr-p0-deferred-cap-%ld.db", (long)TEST_PID);
  (void)remove(path);
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_exec(db, "BEGIN IMMEDIATE;", NULL, NULL, NULL) == SQLITE_OK);
  assert(sqlite3_prepare_v2(
             db,
             "INSERT INTO p0_deferred_match("
             "key_sha256,family_mask,payload,payload_len,payload_sha256,state,"
             "created_at,updated_at,next_retry_at,retry_count,last_error,terminal_reason,completed_at) "
             "VALUES(?,1,?,?,?,'pending',1,1,0,0,'','',0);",
             -1, &st, NULL) == SQLITE_OK);
  for (unsigned i = 0u; i < EDR_STORAGE_QUEUE_P0_DEFERRED_MAX_RETAINED; ++i) {
    int payload_len = snprintf(payload, sizeof(payload), "{\"fixture\":%u}", i);
    assert(payload_len > 0);
    snapshot_key((const uint8_t *)payload, (size_t)payload_len, key);
    if (i == 0u) memcpy(first_key, key, sizeof(first_key));
    sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 2, payload, payload_len, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, payload_len);
    sqlite3_bind_text(st, 4, key, -1, SQLITE_TRANSIENT);
    assert(sqlite3_step(st) == SQLITE_DONE);
    assert(sqlite3_reset(st) == SQLITE_OK);
    assert(sqlite3_clear_bindings(st) == SQLITE_OK);
  }
  sqlite3_finalize(st);
  assert(sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL) == SQLITE_OK);
  assert(sqlite3_close(db) == SQLITE_OK);
  snapshot_key(overflow, sizeof(overflow) - 1u, overflow_key);
  assert(edr_storage_queue_p0_deferred_retain(
             overflow_key, 1u, overflow, sizeof(overflow) - 1u) == EDR_ERR_QUEUE_FULL);
  assert(p0_deferred_count(path, "pending") ==
         (int)EDR_STORAGE_QUEUE_P0_DEFERRED_MAX_RETAINED);

  /* Real FULL fail at the cap keeps its existing owner and payload, without
   * requiring another slot or making room for another retain. */
  edr_storage_queue_get_capacity_metrics(&before_fail);
  assert(edr_storage_queue_p0_deferred_fail(key, "ir_bundle_changed") == EDR_OK);
  edr_storage_queue_get_capacity_metrics(&after_fail);
  assert(after_fail.p0_deferred_pending_rows ==
         EDR_STORAGE_QUEUE_P0_DEFERRED_MAX_RETAINED - 1u);
  assert(after_fail.p0_deferred_failed_rows == 1u);
  assert(after_fail.used_bytes == before_fail.used_bytes);
  assert(p0_deferred_state_matches(path, key, "failed", (int)strlen(payload),
                                   "ir_bundle_changed"));
  assert(edr_storage_queue_p0_deferred_retain(
             overflow_key, 1u, overflow, sizeof(overflow) - 1u) == EDR_ERR_QUEUE_FULL);
  assert(edr_storage_queue_p0_deferred_contains(overflow_key) == 0);
  /* Existing failed ownership can still be acknowledged exactly at the cap. */
  assert(edr_storage_queue_p0_deferred_retain(
             key, 1u, (const uint8_t *)payload, strlen(payload)) == EDR_OK);
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_test_run_cleanup();
  assert(p0_deferred_count(path, "pending") ==
         (int)EDR_STORAGE_QUEUE_P0_DEFERRED_MAX_RETAINED - 1);
  assert(p0_deferred_count(path, "failed") == 1);
  assert(p0_deferred_state_matches(path, key, "failed", (int)strlen(payload),
                                   "ir_bundle_changed"));
  assert(edr_storage_queue_p0_deferred_retain(
             overflow_key, 1u, overflow, sizeof(overflow) - 1u) == EDR_ERR_QUEUE_FULL);

  /* Only an explicit completion releases a retained-payload slot. Its
   * metadata tombstone remains owned and counted in the byte budget. */
  assert(edr_storage_queue_p0_deferred_complete(
             first_key, NULL, NULL, 0u, "policy_denied") == EDR_OK);
  assert(edr_storage_queue_p0_deferred_contains(first_key) == 1);
  assert(edr_storage_queue_p0_deferred_retain(
             overflow_key, 1u, overflow, sizeof(overflow) - 1u) == EDR_OK);
  assert(p0_deferred_count(path, "pending") ==
         (int)EDR_STORAGE_QUEUE_P0_DEFERRED_MAX_RETAINED - 1);
  assert(p0_deferred_count(path, "failed") == 1);
  assert(p0_deferred_count(path, "completed") == 1);
  edr_storage_queue_close();
  (void)remove(path);
}

static int batch_retained_exact(const char *path, const char *batch_id,
                                const char *status, const uint8_t *wire, size_t len) {
  sqlite3 *db = NULL; sqlite3_stmt *st = NULL; int ok = 0;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(db, "SELECT status,payload FROM event_queue WHERE batch_id=?;",
                           -1, &st, NULL) == SQLITE_OK);
  sqlite3_bind_text(st, 1, batch_id, -1, SQLITE_TRANSIENT);
  if (sqlite3_step(st) == SQLITE_ROW) {
    const char *actual = (const char *)sqlite3_column_text(st, 0);
    const void *body = sqlite3_column_blob(st, 1);
    ok = actual && !strcmp(actual, status) && body &&
         sqlite3_column_bytes(st, 1) == (int)len && !memcmp(body, wire, len);
  }
  sqlite3_finalize(st); sqlite3_close(db); return ok;
}

static void test_local_v3_source_evidence_is_not_remote_ack(void) {
  char path[256]; uint8_t wire[20], different[20];
  EdrStorageQueueP0SourceOnlyLatch latch, current, wrong;
  EdrStorageQueueCapacityMetrics metrics, before;
  snprintf(path, sizeof(path), "edr-local-v3-%ld.db", (long)TEST_PID);
  remove(path); make_wire(wire, 0x91u); make_wire(different, 0x92u);
  assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_get_capacity_metrics(&before);
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch) == EDR_OK);
  assert(latch.owner_version == 3u && latch.latched);
  wrong = latch; wrong.owner_version = 2u;
  assert(edr_storage_queue_p0_source_only_commit_local(&wrong, "local-event", "local-batch",
                                                      wire, sizeof(wire), 0, 0) != EDR_OK);
  edr_storage_queue_test_fail_next_p0_latch_commits(1u);
  assert(edr_storage_queue_p0_source_only_commit_local(&latch, "local-event", "local-batch",
                                                      wire, sizeof(wire), 0, 0) == EDR_ERR_SQLITE_WRITE);
  assert(batch_row_id(path, "local-batch") < 0);
  assert(edr_storage_queue_p0_source_only_latch_is_set() == 1);
  assert(edr_storage_queue_p0_source_only_commit_local(&latch, "local-event", "local-batch",
                                                      wire, sizeof(wire), 0, 0) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_get(&current) == EDR_OK);
  assert(!current.latched && current.owner_version == 3u);
  assert(edr_storage_queue_pending_count() == 0u);
  assert(batch_retained_exact(path, "local-batch", "local_evidence", wire, sizeof(wire)));
  reset_send_state(1); edr_storage_queue_poll_drain();
  assert(total_send_calls() == 0u);
  edr_storage_queue_get_capacity_metrics(&metrics);
  assert(metrics.local_evidence_rows == 1u && metrics.delivery_acked == before.delivery_acked);
  assert(metrics.used_bytes == metrics.retained_nonpending_bytes && metrics.used_bytes > sizeof(wire));
  edr_storage_queue_close(); assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_is_set() == 0);
  assert(batch_retained_exact(path, "local-batch", "local_evidence", wire, sizeof(wire)));
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_commit_local(&latch, "local-event", "local-batch",
                                                      different, sizeof(different), 0, 0) != EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_is_set() == 1);
  assert(edr_storage_queue_p0_source_only_commit_local(&latch, "local-event", "local-batch",
                                                      wire, sizeof(wire), 0, 0) == EDR_OK);
  /* Simulate the persistent crash gap after local prepare and before commit. */
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch) == EDR_OK);
  edr_storage_queue_close(); assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&current) == EDR_OK);
  assert(current.owner_version == 3u && current.recovery_required);
  /* Another ordinary diagnostic may be retained, never stand in for a loss audit. */
  assert(edr_storage_queue_p0_source_only_commit_local(&current, "other-source", "other-source-batch",
                                                      wire, sizeof(wire), 0, 0) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_is_set() == 1);
  assert(edr_storage_queue_p0_source_only_commit_local(&current, "loss-audit", "loss-audit-batch",
                                                      different, sizeof(different), 0, 1) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_is_set() == 0);
  assert(status_count(path, "local_evidence") == 3);
  edr_storage_queue_close(); remove(path);
}

static void test_policy_hold_preserves_legacy_identity_and_latch(void) {
  char path[256]; uint8_t wire[20]; EdrStorageQueueP0SourceOnlyLatch legacy, local;
  EdrStorageQueueCapacityMetrics metrics, before;
  snprintf(path, sizeof(path), "edr-policy-hold-%ld.db", (long)TEST_PID);
  remove(path); make_wire(wire, 0x93u);
  assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_get_capacity_metrics(&before);
  assert(edr_storage_queue_p0_source_only_latch_prepare(&legacy) == EDR_OK);
  assert(legacy.owner_version == 2u);
  assert(edr_storage_queue_p0_source_only_enqueue_bound(&legacy, "legacy-event", "legacy-batch",
                                                       wire, sizeof(wire), 0, 0) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&local) == EDR_ERR_INVALID_ARG);
  assert(local.owner_version == 2u && local.latched);
  assert(edr_storage_queue_p0_source_only_commit_local(&legacy, "legacy-event", "legacy-batch",
                                                      wire, sizeof(wire), 0, 0) != EDR_OK);
  s_policy_reject_value = 0x93; reset_send_state(1);
  edr_storage_queue_test_fail_next_p0_latch_commits(1u);
  edr_storage_queue_poll_drain();
  assert(total_send_calls() == 0u);
  assert(batch_retained_exact(path, "legacy-batch", "pending", wire, sizeof(wire)));
  assert(edr_storage_queue_p0_source_only_latch_is_set() == 1);
  edr_storage_queue_close(); assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_poll_drain();
  assert(total_send_calls() == 0u);
  assert(batch_retained_exact(path, "legacy-batch", "policy_held", wire, sizeof(wire)));
  assert(batch_retry_count(path, "legacy-batch") == 0);
  assert(edr_storage_queue_p0_source_only_latch_is_set() == 1);
  edr_storage_queue_get_capacity_metrics(&metrics);
  assert(metrics.policy_held_rows == 1u && metrics.delivery_acked == before.delivery_acked);
  edr_storage_queue_close(); assert(edr_storage_queue_open(path) == EDR_OK);
  assert(batch_retained_exact(path, "legacy-batch", "policy_held", wire, sizeof(wire)));
  assert(edr_storage_queue_p0_source_only_latch_get(&legacy) == EDR_OK);
  assert(legacy.latched && legacy.owner_version == 2u);
  assert(edr_storage_queue_p0_source_only_recovery_probe() == EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_is_set() == 1);
  edr_storage_queue_close(); remove(path); s_policy_reject_value = -1;
}

static void test_unknown_historical_wire_is_retained(void) {
  char path[256]; uint8_t old_wire[20];
  snprintf(path, sizeof(path), "edr-unknown-history-%ld.db", (long)TEST_PID);
  remove(path); make_wire(old_wire, 0x94u); old_wire[3] = '9';
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_enqueue("old-encoding", old_wire, sizeof(old_wire), 0, 0) == EDR_OK);
  edr_storage_queue_close(); assert(edr_storage_queue_open(path) == EDR_OK);
  assert(batch_retained_exact(path, "old-encoding", "dead_letter", old_wire, sizeof(old_wire)));
  reset_send_state(1); edr_storage_queue_poll_drain();
  assert(total_send_calls() == 0u && batch_retry_count(path, "old-encoding") == 0);
  edr_storage_queue_close(); remove(path);
}

static void test_local_v3_retention_has_bounded_backpressure(void) {
  char path[256], batch[48]; EdrStorageQueueP0SourceOnlyLatch latch;
  EdrStorageQueueCapacityMetrics before, metrics, reopened;
  uint8_t terminal[20], intent[20], source[20], combined[20];
  uint8_t *wire = malloc(131072u), *tail;
  size_t tail_len;
  unsigned retained = 0u; int full = 0;
  assert(wire); make_large_wire(wire, 131072u, 0x95u);
  make_wire(terminal, 0xa0u); make_wire(intent, 0xa1u);
  make_wire(source, 0xa2u); make_wire(combined, 0xa3u);
  snprintf(path, sizeof(path), "edr-local-v3-capacity-%ld.db", (long)TEST_PID);
  remove(path); edr_storage_queue_configure(1u, 1u);
  assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_get_capacity_metrics(&before);
  for (unsigned i = 0u; i < 12u; ++i) {
    EdrError result;
    snprintf(batch, sizeof(batch), "local-capacity-%u", i);
    assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch) == EDR_OK);
    result = edr_storage_queue_p0_source_only_commit_local(&latch, "local-capacity-event", batch,
                                                          wire, 131072u, 0, 0);
    if (result == EDR_ERR_QUEUE_FULL) { full = 1; break; }
    assert(result == EDR_OK); retained++;
  }
  assert(full && retained > 0u && edr_storage_queue_p0_source_only_latch_is_set() == 1);
  edr_storage_queue_get_capacity_metrics(&metrics);
  assert(metrics.local_evidence_rows == retained && metrics.used_bytes <= metrics.ordinary_limit_bytes);
  assert(metrics.ordinary_rejected == before.ordinary_rejected + 1u);
  assert(metrics.p0_source_only_rejected == before.p0_source_only_rejected);
  /* Exact replay remains durable and may resolve its matching local latch
   * even when the next 128 KiB fact does not fit. It never creates an ACK. */
  assert(edr_storage_queue_p0_source_only_commit_local(&latch, "local-capacity-event", "local-capacity-0",
                                                      wire, 131072u, 0, 0) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_is_set() == 0);
  /* Use the remaining ordinary space exactly so the following terminal
   * admission cannot accidentally depend on a gap between large facts. */
  assert(metrics.ordinary_limit_bytes > metrics.used_bytes + 512u + strlen("local-tail") + 20u);
  tail_len = (size_t)(metrics.ordinary_limit_bytes - metrics.used_bytes - 512u - strlen("local-tail"));
  tail = malloc(tail_len); assert(tail); make_large_wire(tail, tail_len, 0x96u);
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_commit_local(&latch, "local-tail-event", "local-tail",
                                                      tail, tail_len, 0, 0) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_commit_local(&latch, "local-full-event", "local-full",
                                                      terminal, sizeof(terminal), 0, 0) == EDR_ERR_QUEUE_FULL);
  edr_storage_queue_get_capacity_metrics(&metrics);
  assert(metrics.used_bytes == metrics.ordinary_limit_bytes);
  assert(metrics.local_evidence_rows == retained + 1u);
  sqlite_exec_path(path, "UPDATE event_queue SET created_at=1;");
  edr_storage_queue_test_run_cleanup();
  assert(status_count(path, "local_evidence") == (int)retained + 1);
  reset_send_state(1); edr_storage_queue_poll_drain(); assert(total_send_calls() == 0u);
  edr_storage_queue_close(); assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_get_capacity_metrics(&reopened);
  assert(reopened.used_bytes == metrics.used_bytes);
  assert(reopened.delivery_acked == before.delivery_acked);
  assert(edr_storage_queue_p0_source_only_latch_is_set() == 1);
  for (unsigned i = 0u; i < retained; ++i) {
    snprintf(batch, sizeof(batch), "local-capacity-%u", i);
    assert(batch_retained_exact(path, batch, "local_evidence", wire, 131072u));
    assert(ack_receipt_count(path, batch, wire, 131072u) == 0);
  }
  assert(batch_retained_exact(path, "local-tail", "local_evidence", tail, tail_len));
  free(tail);

  /* The same full local inventory must allow the original 20-byte terminal
   * regression and reserve final result bytes before an action can run. */
  assert(edr_storage_queue_enqueue("local-pressure-terminal-20", terminal, sizeof(terminal), 0,
                                   EDR_STORAGE_QUEUE_SEVERITY_TERMINAL) == EDR_OK);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "local-pressure-journal", "local-pressure-event", "R-TERMINAL", "local-pressure-generation",
             "local-pressure-intent", intent, sizeof(intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  edr_storage_queue_get_capacity_metrics(&metrics);
  assert(metrics.used_bytes < metrics.max_bytes - metrics.p0_source_only_reserve_bytes);
  tail_len = (size_t)(metrics.max_bytes - metrics.p0_source_only_reserve_bytes -
                     metrics.used_bytes - 512u - strlen("terminal-tail"));
  assert(tail_len >= 20u);
  tail = malloc(tail_len); assert(tail); make_large_wire(tail, tail_len, 0xa4u);
  assert(edr_storage_queue_enqueue("terminal-tail", tail, tail_len, 0,
                                   EDR_STORAGE_QUEUE_SEVERITY_TERMINAL) == EDR_OK);
  free(tail);
  assert(edr_storage_queue_enqueue("terminal-full", terminal, sizeof(terminal), 0,
                                   EDR_STORAGE_QUEUE_SEVERITY_TERMINAL) == EDR_ERR_QUEUE_FULL);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "local-pressure-extra", "local-pressure-event-extra", "R-TERMINAL", "local-pressure-generation-extra",
             "local-pressure-intent-extra", intent, sizeof(intent)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_ERROR);
  /* The owner admitted before pressure still freezes its result using the
   * reservation; rejecting the next owner never authorizes repeat execution. */
  assert(edr_storage_queue_enforcement_terminal_update(
             "local-pressure-journal", "local-pressure-source", source, sizeof(source),
             "local-pressure-combined", combined, sizeof(combined)) == EDR_OK);
  assert(terminal_journal_state_is(path, "local-pressure-journal", "ready"));
  edr_storage_queue_get_capacity_metrics(&metrics);
  assert(metrics.used_bytes <= metrics.max_bytes - metrics.p0_source_only_reserve_bytes);
  assert(metrics.high_priority_rejected >= before.high_priority_rejected + 2u);
  reset_send_state(1); test_sleep_ms(250u); edr_storage_queue_poll_drain();
  assert(send_calls_for(0xa0u) == 1u && send_calls_for(0xa4u) == 1u);
  assert(send_calls_for(0xa1u) == 1u && send_calls_for(0xa2u) == 1u && send_calls_for(0xa3u) == 1u);
  assert(send_calls_for(0x95u) == 0u && send_calls_for(0x96u) == 0u);
  assert(status_count(path, "local_evidence") == (int)retained + 1);
  assert(edr_storage_queue_p0_source_only_latch_is_set() == 1);
  edr_storage_queue_close(); free(wire); remove(path); edr_storage_queue_configure(0u, 0u);
}

static void test_lowered_limit_preserves_overcapacity_evidence(void) {
  char path[256], batch[48]; EdrStorageQueueP0SourceOnlyLatch latch;
  EdrStorageQueueCapacityMetrics before, after; uint8_t *wire = malloc(131072u);
  assert(wire); make_large_wire(wire, 131072u, 0x96u);
  snprintf(path, sizeof(path), "edr-local-v3-lowered-cap-%ld.db", (long)TEST_PID);
  /* Start with enough ordinary capacity under both admission policies. The
   * lower configured limit is not permission to rewrite or discard owners. */
  remove(path); edr_storage_queue_configure(4u, 1u);
  assert(edr_storage_queue_open(path) == EDR_OK);
  for (unsigned i = 0; i < 10u; ++i) {
    snprintf(batch, sizeof(batch), "overcapacity-%u", i);
    assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch) == EDR_OK);
    assert(edr_storage_queue_p0_source_only_commit_local(&latch, "retained-overcapacity", batch,
                                                        wire, 131072u, 0, 0) == EDR_OK);
  }
  edr_storage_queue_get_capacity_metrics(&before);
  assert(before.local_evidence_rows == 10u && before.used_bytes > 1024u * 1024u);
  edr_storage_queue_close(); edr_storage_queue_configure(1u, 1u);
  assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_get_capacity_metrics(&after);
  assert(after.used_bytes == before.used_bytes && after.used_bytes > after.max_bytes);
  assert(after.utilization_bps > 10000u && after.local_evidence_rows == 10u);
  assert(after.capacity_limit_defaulted == 0u);
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_commit_local(&latch, "new-overcapacity", "new-overcapacity",
                                                      wire, 131072u, 0, 0) == EDR_ERR_QUEUE_FULL);
  edr_storage_queue_test_run_cleanup();
  for (unsigned i = 0; i < 10u; ++i) {
    snprintf(batch, sizeof(batch), "overcapacity-%u", i);
    assert(batch_retained_exact(path, batch, "local_evidence", wire, 131072u));
  }
  assert(batch_row_id(path, "new-overcapacity") < 0);
  edr_storage_queue_get_capacity_metrics(&after);
  assert(after.used_bytes == before.used_bytes && after.ordinary_rejected > before.ordinary_rejected);
  reset_send_state(1); edr_storage_queue_poll_drain(); assert(total_send_calls() == 0u);
  edr_storage_queue_close(); free(wire); remove(path); edr_storage_queue_configure(0u, 0u);
}

static void test_missing_source_meta_preserves_owner_recovery(void) {
  const char *statuses[] = {"pending", "policy_held", "corrupt"};
  char path[256], sql[256]; uint8_t wire[20];
  EdrStorageQueueP0SourceOnlyLatch original, recovered, local;
  EdrStorageQueueCapacityMetrics before, after;
  make_wire(wire, 0x97u);
  for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
    snprintf(path, sizeof(path), "edr-source-missing-meta-%zu-%ld.db", i, (long)TEST_PID);
    remove(path); assert(edr_storage_queue_open(path) == EDR_OK);
    assert(edr_storage_queue_p0_source_only_latch_prepare(&original) == EDR_OK);
    assert(edr_storage_queue_p0_source_only_enqueue_bound(&original, "missing-meta-event",
                                                         "missing-meta-batch", wire, sizeof(wire), 0, 0) == EDR_OK);
    edr_storage_queue_get_capacity_metrics(&before);
    edr_storage_queue_close();
    /* Missing singleton is metadata loss, not proof that its remote owner
     * ACKed. A retained nonpending source is equally significant. */
    snprintf(sql, sizeof(sql), "UPDATE event_queue SET status='%s'; DELETE FROM queue_meta;", statuses[i]);
    sqlite_exec_path(path, sql);
    edr_storage_queue_test_fail_source_owner_inventory_reads(1u);
    assert(edr_storage_queue_open(path) == EDR_ERR_SQLITE_WRITE);
    assert(!edr_storage_queue_is_open());
    assert(batch_retained_exact(path, "missing-meta-batch", statuses[i], wire, sizeof(wire)));
    assert(edr_storage_queue_open(path) == EDR_OK);
    assert(edr_storage_queue_p0_source_only_latch_get(&recovered) == EDR_OK);
    assert(recovered.latched && recovered.recovery_required && recovered.owner_version == 2u);
    assert(memcmp(recovered.queue_nonce, original.queue_nonce, sizeof(original.queue_nonce)) != 0);
    assert(edr_storage_queue_p0_source_only_latch_prepare_local(&local) == EDR_ERR_INVALID_ARG);
    assert(local.latched && local.owner_version == 2u);
    assert(edr_storage_queue_p0_source_only_recovery_probe() == EDR_OK);
    assert(edr_storage_queue_p0_source_only_latch_is_set() == 1);
    assert(batch_retained_exact(path, "missing-meta-batch", statuses[i], wire, sizeof(wire)));
    edr_storage_queue_get_capacity_metrics(&after);
    assert(after.delivery_acked == before.delivery_acked && after.delivery_sent == before.delivery_sent);
    edr_storage_queue_close(); remove(path);
  }

  snprintf(path, sizeof(path), "edr-local-source-missing-meta-%ld.db", (long)TEST_PID);
  remove(path); assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&original) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_commit_local(&original, "local-missing-meta-event",
                                                      "local-missing-meta-batch", wire, sizeof(wire), 0, 0) == EDR_OK);
  edr_storage_queue_get_capacity_metrics(&before);
  edr_storage_queue_close(); sqlite_exec_path(path, "DELETE FROM queue_meta;");
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_get(&recovered) == EDR_OK);
  assert(recovered.latched && recovered.recovery_required && recovered.owner_version == 3u);
  assert(edr_storage_queue_p0_source_only_commit_local(&recovered, "local-missing-meta-audit",
                                                      "local-missing-meta-audit", wire, sizeof(wire), 0, 1) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_is_set() == 0);
  assert(batch_retained_exact(path, "local-missing-meta-batch", "local_evidence", wire, sizeof(wire)));
  edr_storage_queue_get_capacity_metrics(&after);
  assert(after.local_evidence_rows == 2u && after.delivery_acked == before.delivery_acked);
  assert(after.delivery_sent == before.delivery_sent);
  edr_storage_queue_close(); remove(path);
}

static void test_terminal_policy_hold_does_not_block_combined_alert(void) {
  char path[256]; uint8_t intent[20], source[20], combined[20]; int source_ack, combined_ack;
  snprintf(path, sizeof(path), "edr-terminal-policy-independent-%ld.db", (long)TEST_PID);
  remove(path); make_wire(intent, 0xa1u); make_wire(source, 0xa2u); make_wire(combined, 0xa3u);
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_enforcement_terminal_precreate("policy-independent", "synthetic-source",
      "SYNTHETIC-RULE", "synthetic-generation", "policy-intent", intent, sizeof(intent)) ==
      EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  assert(edr_storage_queue_enforcement_terminal_update("policy-independent", "policy-source",
      source, sizeof(source), "policy-combined", combined, sizeof(combined)) == EDR_OK);
  s_policy_reject_value = 0xa2; reset_send_state(1);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0xa2u) == 0u && send_calls_for(0xa3u) == 1u);
  assert(terminal_journal_final_acks(path, "policy-independent", &source_ack, &combined_ack));
  assert(source_ack == 0 && combined_ack == 1);
  assert(terminal_journal_state_is(path, "policy-independent", "local_retained"));
  assert(terminal_journal_frame_retry_count(path, "policy-independent", 1) == 0);
  edr_storage_queue_close(); assert(edr_storage_queue_open(path) == EDR_OK);
  reset_send_state(1); edr_storage_queue_poll_drain();
  assert(total_send_calls() == 0u);
  assert(edr_storage_queue_enforcement_terminal_precreate("policy-independent", "synthetic-source",
      "SYNTHETIC-RULE", "synthetic-generation", "policy-intent", intent, sizeof(intent)) ==
      EDR_ENFORCEMENT_TERMINAL_PRECREATE_EXISTING);
  edr_storage_queue_close(); remove(path); s_policy_reject_value = -1;
}

static int ack_receipt_count(const char *path, const char *batch, const uint8_t *wire, size_t length) {
  sqlite3 *db = NULL; sqlite3_stmt *st = NULL; char batch_sha[65], payload_sha[65];
  assert(edr_sha256_hex((const uint8_t *)batch, strlen(batch), batch_sha) == 0);
  assert(edr_sha256_hex(wire, length, payload_sha) == 0);
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(db, "SELECT count(*) FROM delivery_receipts_v1 WHERE batch_id_sha256=? AND payload_sha256=? AND payload_bytes=?", -1, &st, NULL) == SQLITE_OK);
  sqlite3_bind_text(st, 1, batch_sha, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 2, payload_sha, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 3, (sqlite3_int64)length);
  assert(sqlite3_step(st) == SQLITE_ROW); int n = sqlite3_column_int(st, 0);
  sqlite3_finalize(st); sqlite3_close(db); return n;
}

static void test_exact_ack_receipt_atomic_recovery(void) {
  char path[256]; uint8_t wire[20];
  snprintf(path, sizeof(path), "edr-receipt-%ld.db", (long)TEST_PID); remove(path); make_wire(wire, 0x51u);
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_enqueue("receipt-batch", wire, sizeof(wire), 0, 0) == EDR_OK);
  assert(ack_receipt_count(path, "receipt-batch", wire, sizeof(wire)) == 0);
  /* Supported upgrade: old queue rows survive addition of an empty witness
   * table; no earlier row or local source-only retention becomes an ACK. */
  edr_storage_queue_close(); sqlite_exec_path(path, "DROP TABLE delivery_receipts_v1;");
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(queue_batch_pending(path, "receipt-batch"));
  assert(ack_receipt_count(path, "receipt-batch", wire, sizeof(wire)) == 0);
  /* An actual validated transport success cannot delete its row if the local
   * witness cannot commit. This is a local fault, not a fabricated remote NACK. */
  sqlite_exec_path(path, "CREATE TRIGGER receipt_fail BEFORE INSERT ON delivery_receipts_v1 BEGIN SELECT RAISE(ABORT,'synthetic receipt failure'); END;");
  reset_send_state(1); edr_storage_queue_poll_drain();
  assert(queue_batch_pending(path, "receipt-batch"));
  assert(ack_receipt_count(path, "receipt-batch", wire, sizeof(wire)) == 0);
  sqlite_exec_path(path, "DROP TRIGGER receipt_fail;");
  /* Failed FULL commit cannot leave a witness ahead of its queue deletion. */
  edr_storage_queue_close(); assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_test_fail_next_terminal_commits(1u);
  reset_send_state(1); edr_storage_queue_poll_drain();
  assert(queue_batch_pending(path, "receipt-batch"));
  assert(ack_receipt_count(path, "receipt-batch", wire, sizeof(wire)) == 0);
  /* Fill only synthetic metadata to exercise the exact bounded-retention edge. */
  sqlite_exec_path(path, "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<1024) "
      "INSERT INTO delivery_receipts_v1(batch_id_sha256,payload_sha256,payload_bytes,acked_at) "
      "SELECT printf('%064d',x),printf('%064d',x),1,1 FROM n;");

  edr_storage_queue_close(); assert(edr_storage_queue_open(path) == EDR_OK);
  reset_send_state(1); edr_storage_queue_poll_drain();
  assert(!queue_batch_pending(path, "receipt-batch"));
  assert(ack_receipt_count(path, "receipt-batch", wire, sizeof(wire)) == 1);
  edr_storage_queue_close(); assert(edr_storage_queue_open(path) == EDR_OK);
  assert(ack_receipt_count(path, "receipt-batch", wire, sizeof(wire)) == 1);
  assert(ack_receipt_count(path, "foreign-batch", wire, sizeof(wire)) == 0);
  { sqlite3 *db = NULL; sqlite3_stmt *st = NULL;
    assert(sqlite3_open(path, &db) == SQLITE_OK);
    assert(sqlite3_prepare_v2(db, "SELECT count(*) FROM delivery_receipts_v1", -1, &st, NULL) == SQLITE_OK);
    assert(sqlite3_step(st) == SQLITE_ROW && sqlite3_column_int(st, 0) == 1024);
    sqlite3_finalize(st); sqlite3_close(db);
  }

  wire[19] ^= 1u; assert(ack_receipt_count(path, "receipt-batch", wire, sizeof(wire)) == 0);
  edr_storage_queue_close(); remove(path);
}

static void test_capacity_ledger_owner_transitions_and_rollback(void) {
  char path[256], key[65];
  uint8_t wire[20], source[20], combined[20];
  const uint8_t snapshot[] = "{\"ledger\":\"durable-owner\"}";
  EdrStorageQueueP0SourceOnlyLatch latch;
  uint64_t before;
  snprintf(path, sizeof(path), "edr-capacity-ledger-owners-%ld.db", (long)TEST_PID);
  remove(path);
  make_wire(wire, 0xe1u); make_wire(source, 0xe2u); make_wire(combined, 0xe3u);
  snapshot_key(snapshot, sizeof(snapshot) - 1u, key);
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(assert_capacity_matches_inventory(path) == 0u);
  assert(edr_storage_queue_enqueue("ledger-delivery", wire, sizeof(wire), 0, 1) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch) == EDR_OK);
  assert(edr_storage_queue_p0_source_only_commit_local(&latch, "ledger-event", "ledger-local",
                                                       wire, sizeof(wire), 0, 0) == EDR_OK);
  assert(sqlite_scalar_path(path, "SELECT COUNT(*) FROM event_queue WHERE retention_class=1 "
                                   "AND retention_policy_version=1 AND local_retention_state='retained';") == 1u);
  assert(sqlite_scalar_path(path, "SELECT COUNT(*) FROM event_queue WHERE retention_class=2 "
                                   "AND retention_policy_version=1 AND local_retention_state='retained';") == 1u);
  before = assert_capacity_matches_inventory(path);
  assert_retention_health_projection();
  edr_storage_queue_test_fail_next_enqueue_commits(1u);
  assert(edr_storage_queue_enqueue("ledger-rollback", wire, sizeof(wire), 0, 1) == EDR_ERR_SQLITE_WRITE);
  assert(assert_capacity_matches_inventory(path) == before);
  assert(batch_row_id(path, "ledger-rollback") < 0);

  assert(edr_storage_queue_p0_deferred_retain(key, 1u, snapshot, sizeof(snapshot) - 1u) == EDR_OK);
  before = assert_capacity_matches_inventory(path);
  edr_storage_queue_test_fail_next_p0_deferred_commits(1u);
  assert(edr_storage_queue_p0_deferred_complete(key, "ledger-handoff", source, sizeof(source),
                                               "queue_accepted") == EDR_ERR_SQLITE_WRITE);
  assert(assert_capacity_matches_inventory(path) == before);
  assert(p0_deferred_state_matches(path, key, "pending", sizeof(snapshot) - 1u, ""));
  assert(batch_row_id(path, "ledger-handoff") < 0);
  assert(edr_storage_queue_p0_deferred_complete(key, "ledger-handoff", source, sizeof(source),
                                               "queue_accepted") == EDR_OK);
  assert(p0_deferred_state_matches(path, key, "completed", 0, "queue_accepted"));
  assert_capacity_matches_inventory(path);

  edr_storage_queue_test_fail_next_terminal_commits(1u);
  before = assert_capacity_matches_inventory(path);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "ledger-journal", "ledger-source", "R-LEDGER", "generation-ledger", "ledger-intent",
             wire, sizeof(wire)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_ERROR);
  assert(assert_capacity_matches_inventory(path) == before);
  assert(edr_storage_queue_enforcement_terminal_precreate(
             "ledger-journal", "ledger-source", "R-LEDGER", "generation-ledger", "ledger-intent",
             wire, sizeof(wire)) == EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  before = assert_capacity_matches_inventory(path);
  edr_storage_queue_test_fail_next_terminal_commits(1u);
  assert(edr_storage_queue_enforcement_terminal_update(
             "ledger-journal", "ledger-source-final", source, sizeof(source),
             "ledger-combined-final", combined, sizeof(combined)) == EDR_ERR_SQLITE_WRITE);
  assert(assert_capacity_matches_inventory(path) == before);
  assert(terminal_result_wires_missing(path, "ledger-journal"));
  assert(edr_storage_queue_enforcement_terminal_update(
             "ledger-journal", "ledger-source-final", source, sizeof(source),
             "ledger-combined-final", combined, sizeof(combined)) == EDR_OK);
  /* Freezing replaces the larger pre-action result reservation with the
   * actual two wires; later state changes must not allocate new state bytes. */
  assert(assert_capacity_matches_inventory(path) < before);
  before = assert_capacity_matches_inventory(path);
  sqlite_exec_path(path, "UPDATE enforcement_terminal_journal SET state='outcome_unknown' "
                        "WHERE idempotency_key='ledger-journal';");
  assert(assert_capacity_matches_inventory(path) == before);
  assert_sqlite_write_rejected(path, "UPDATE enforcement_terminal_journal SET state='state_exceeds_reserved_bytes' "
                                    "WHERE idempotency_key='ledger-journal';");
  assert(terminal_journal_state_is(path, "ledger-journal", "outcome_unknown"));
  sqlite_exec_path(path, "UPDATE enforcement_terminal_journal SET state='ready' "
                        "WHERE idempotency_key='ledger-journal';");
  assert(assert_capacity_matches_inventory(path) == before);

  /* Delivery disposition does not retire a local owner or release its bytes. */
  sqlite_exec_path(path, "UPDATE event_queue SET status='dead_letter',terminal_reason='synthetic_retry_exhausted' "
                        "WHERE batch_id='ledger-delivery';");
  before = assert_capacity_matches_inventory(path);
  sqlite_exec_path(path, "BEGIN IMMEDIATE;"
                        "UPDATE event_queue SET payload=zeroblob(4096) WHERE batch_id='ledger-local';"
                        "UPDATE enforcement_terminal_journal SET reserved_bytes=reserved_bytes+65536;"
                        "DELETE FROM p0_deferred_match;ROLLBACK;");
  assert(assert_capacity_matches_inventory(path) == before);
  assert(batch_retained_exact(path, "ledger-local", "local_evidence", wire, sizeof(wire)));
  assert(sqlite_scalar_path(path, "SELECT COUNT(*) FROM event_queue WHERE local_retention_state<>'retained';") == 0u);
  /* REPLACE would otherwise bypass implicit-delete triggers on default
   * SQLite connections. It cannot rewrite the frozen identity or its cost. */
  assert_sqlite_write_rejected(path,
      "INSERT OR REPLACE INTO event_queue(batch_id,payload,created_at,status) "
      "VALUES('ledger-local',zeroblob(4096),1,'local_evidence');");
  assert_sqlite_write_rejected(path,
      "INSERT OR REPLACE INTO enforcement_terminal_journal(idempotency_key,owner_key_sha256,"
      "source_event_key,rule_id,process_generation_key,state,created_at,updated_at) "
      "SELECT 'conflicting-owner',owner_key_sha256,source_event_key,rule_id,process_generation_key,"
      "state,created_at,updated_at FROM enforcement_terminal_journal WHERE idempotency_key='ledger-journal';");
  assert(assert_capacity_matches_inventory(path) == before);
  assert(terminal_journal_state_is(path, "ledger-journal", "ready"));

  /* Recovery relations and bounded lineage overhead share the transaction.
   * These synthetic mutations test accounting, not projection authorization. */
  sqlite_exec_path(path, "INSERT INTO queue_projection_relations(origin_row_id,projector_version,batch_id,"
                        "payload_sha256,receipt_state,created_at) SELECT id,'ledger-test','ledger-projection',"
                        "printf('%064d',0),'pending',1 FROM event_queue WHERE batch_id='ledger-local';"
                        "UPDATE queue_meta SET legacy_lineage='synthetic',last_recovery_snapshot='synthetic';");
  assert(assert_capacity_matches_inventory(path) == before + 512u + 4096u);
  sqlite_exec_path(path, "INSERT INTO queue_projection_relations(origin_row_id,projector_version,batch_id,"
                        "payload_sha256,receipt_state,created_at) SELECT id,'ledger-test','ledger-projection',"
                        "printf('%064d',0),'pending',1 FROM event_queue WHERE batch_id='ledger-local' "
                        "ON CONFLICT(origin_row_id,projector_version) DO NOTHING;");
  assert(assert_capacity_matches_inventory(path) == before + 512u + 4096u);
  assert_sqlite_write_rejected(path,
      "INSERT OR REPLACE INTO queue_projection_relations(origin_row_id,projector_version,batch_id,"
      "payload_sha256,receipt_state,created_at) SELECT id,'ledger-test','ledger-projection',"
      "printf('%064d',1),'pending',1 FROM event_queue WHERE batch_id='ledger-local';");
  sqlite_exec_path(path,
      "INSERT OR REPLACE INTO queue_projection_relations(origin_row_id,projector_version,batch_id,"
      "payload_sha256,receipt_state,created_at,acked_at) SELECT id,'ledger-test','ledger-projection',"
      "printf('%064d',0),'acked',2,2 FROM event_queue WHERE batch_id='ledger-local';");
  assert(sqlite_scalar_path(path, "SELECT COUNT(*) FROM queue_projection_relations "
                                   "WHERE receipt_state='pending' AND acked_at=0;") == 1u);
  sqlite_exec_path(path, "UPDATE queue_projection_relations SET receipt_state='acked',acked_at=2;"
                        "UPDATE event_queue SET recovery_version=1 WHERE batch_id='ledger-local';");
  assert(assert_capacity_matches_inventory(path) == before + 1024u + 4096u);
  sqlite_exec_path(path, "DELETE FROM queue_projection_relations;"
                        "UPDATE queue_meta SET legacy_lineage='',last_recovery_snapshot='';"
                        "UPDATE event_queue SET recovery_version=0 WHERE batch_id='ledger-local';");
  assert(assert_capacity_matches_inventory(path) == before);
  reset_send_state(1);
  edr_storage_queue_poll_drain();
  assert(batch_row_id(path, "ledger-handoff") < 0);
  assert(ack_receipt_count(path, "ledger-handoff", source, sizeof(source)) == 1);
  assert(batch_retained_exact(path, "ledger-delivery", "dead_letter", wire, sizeof(wire)));
  assert(batch_retained_exact(path, "ledger-local", "local_evidence", wire, sizeof(wire)));
  assert_capacity_matches_inventory(path);
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert_capacity_matches_inventory(path);
  edr_storage_queue_close(); remove(path);
}

static void synthetic_database_hash(const char *path,char out[65]) {
  FILE *file=fopen(path,"rb");assert(file);EdrSha256Ctx ctx;edr_sha256_init(&ctx);
  uint8_t bytes[4096],digest[32];size_t n;
  while((n=fread(bytes,1,sizeof(bytes),file)))edr_sha256_update(&ctx,bytes,n);
  assert(!ferror(file) && fclose(file)==0);edr_sha256_final(&ctx,digest);
  for(unsigned i=0;i<32u;++i)snprintf(out+2u*i,3,"%02x",digest[i]);
}

static void test_retention_upgrade_preserves_legacy_identity(void) {
  for (unsigned partial = 0u; partial < 2u; ++partial) {
    char path[256], hash[65];
    uint8_t wire[20];
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    snprintf(path, sizeof(path), "edr-retention-upgrade-%u-%ld.db", partial, (long)TEST_PID);
    remove(path); make_wire(wire, 0xe4u);
    assert(edr_sha256_hex(wire, sizeof(wire), hash) == 0);
    sqlite_exec_path(path,
        "CREATE TABLE event_queue(id INTEGER PRIMARY KEY AUTOINCREMENT,batch_id TEXT UNIQUE,"
        "payload BLOB,created_at INTEGER NOT NULL,compressed INTEGER NOT NULL DEFAULT 0,"
        "severity INTEGER NOT NULL DEFAULT 0,retry_count INTEGER NOT NULL DEFAULT 0,"
        "status TEXT NOT NULL DEFAULT 'pending',terminal_reason TEXT NOT NULL DEFAULT '',"
        "terminal_at INTEGER NOT NULL DEFAULT 0,recovery_version INTEGER NOT NULL DEFAULT 0,"
        "original_sha256 TEXT NOT NULL DEFAULT '',projection_batch_id TEXT NOT NULL DEFAULT '',"
        "projection_sha256 TEXT NOT NULL DEFAULT '',projector_version TEXT NOT NULL DEFAULT '',"
        "recovery_state TEXT NOT NULL DEFAULT '',origin_row_id INTEGER NOT NULL DEFAULT 0);");
    if (partial) {
      /* Models an upgrade interrupted after the first additive column. */
      sqlite_exec_path(path, "ALTER TABLE event_queue ADD COLUMN retention_class INTEGER NOT NULL DEFAULT 0;");
    }
    assert(sqlite3_open(path, &db) == SQLITE_OK);
    assert(sqlite3_prepare_v2(db,
        "INSERT INTO event_queue(batch_id,payload,created_at,severity,status,terminal_reason,"
        "recovery_version,original_sha256) VALUES(?,?,1,2,'local_evidence',?,?,?);",
        -1, &st, NULL) == SQLITE_OK);
    for (unsigned i = 0; i < 2u; ++i) {
      sqlite3_bind_text(st, 1, i ? "legacy-recovery" : "legacy-local", -1, SQLITE_STATIC);
      sqlite3_bind_blob(st, 2, wire, sizeof(wire), SQLITE_STATIC);
      sqlite3_bind_text(st, 3, i ? "retained_unresolved" : "source_only_local_v3", -1, SQLITE_STATIC);
      sqlite3_bind_int(st, 4, i ? 1 : 0);
      sqlite3_bind_text(st, 5, i ? hash : "", -1, SQLITE_TRANSIENT);
      assert(sqlite3_step(st) == SQLITE_DONE);
      assert(sqlite3_reset(st) == SQLITE_OK);
    }
    sqlite3_finalize(st); assert(sqlite3_close(db) == SQLITE_OK);
    char before_hash[65],after_hash[65];synthetic_database_hash(path,before_hash);
    assert(test_setenv("EDR_STORAGE_MIN_FREE_MB","4294967295")==0);
    assert(edr_storage_queue_open(path)==EDR_ERR_QUEUE_FULL && !edr_storage_queue_is_open());
    synthetic_database_hash(path,after_hash);assert(!strcmp(before_hash,after_hash));
    assert(test_unsetenv("EDR_STORAGE_MIN_FREE_MB")==0);
    assert(edr_storage_queue_open(path) == EDR_OK);
    assert(sqlite_scalar_path(path, "SELECT COUNT(*) FROM event_queue WHERE retention_class=0 "
                                     "AND retention_policy_version=0 AND local_retention_state='retained';") == 2u);
    assert_capacity_matches_inventory(path);
    assert_sqlite_write_rejected(path,
        "UPDATE event_queue SET local_retention_state='retirement_eligible' WHERE id=1;");
    assert_sqlite_write_rejected(path,
        "UPDATE event_queue SET local_retention_state='retired' WHERE id=2;");
    assert_sqlite_write_rejected(path,
        "UPDATE event_queue SET retention_class=1,retention_policy_version=1 WHERE id=1;");
    /* Old nullable schemas must not let a NULL cost disappear from SUM or
     * skip the ledger update trigger. Rejected writes leave the owner intact. */
    assert_sqlite_write_rejected(path, "UPDATE event_queue SET payload=NULL WHERE id=1;");
    assert_sqlite_write_rejected(path, "UPDATE event_queue SET batch_id=NULL WHERE id=2;");
    for (unsigned reopen = 0u; reopen < 2u; ++reopen) {
      edr_storage_queue_test_run_cleanup();
      reset_send_state(1); edr_storage_queue_poll_drain();
      assert(total_send_calls() == 0u);
      assert(batch_row_id(path, "legacy-local") == 1);
      assert(batch_row_id(path, "legacy-recovery") == 2);
      assert(batch_retained_exact(path, "legacy-local", "local_evidence", wire, sizeof(wire)));
      assert(batch_retained_exact(path, "legacy-recovery", "local_evidence", wire, sizeof(wire)));
      assert(sqlite_scalar_path(path, "SELECT COUNT(*) FROM event_queue WHERE id=2 AND recovery_version=1 "
                                       "AND length(original_sha256)=64 AND origin_row_id=0;") == 1u);
      {
        char query[256];
        snprintf(query, sizeof(query), "SELECT COUNT(*) FROM event_queue WHERE id=2 AND original_sha256='%s';", hash);
        assert(sqlite_scalar_path(path, query) == 1u);
      }
      assert(ack_receipt_count(path, "legacy-local", wire, sizeof(wire)) == 0);
      edr_storage_queue_close();
      assert(edr_storage_queue_open(path) == EDR_OK);
      assert_capacity_matches_inventory(path);
      assert(sqlite_scalar_path(path, "SELECT COUNT(*) FROM event_queue WHERE retention_class=0 "
                                       "AND retention_policy_version=0 AND local_retention_state='retained';") == 2u);
    }
    edr_storage_queue_close(); remove(path);
  }
  {
    char path[256];
    snprintf(path, sizeof(path), "edr-retention-null-cost-%ld.db", (long)TEST_PID);
    remove(path);
    sqlite_exec_path(path,
        "CREATE TABLE event_queue(id INTEGER PRIMARY KEY,batch_id TEXT UNIQUE,payload BLOB,"
        "created_at INTEGER NOT NULL,compressed INTEGER NOT NULL DEFAULT 0,"
        "severity INTEGER NOT NULL DEFAULT 0,retry_count INTEGER NOT NULL DEFAULT 0,"
        "status TEXT NOT NULL DEFAULT 'pending');"
        "INSERT INTO event_queue(id,batch_id,payload,created_at,status) "
        "VALUES(1,'unclassifiable-null',NULL,1,'local_evidence');");
    /* A malformed old owner is an explicit unavailable-accounting failure,
     * not a zero-byte record that permits new writes or automatic deletion. */
    assert(edr_storage_queue_open(path) == EDR_ERR_SQLITE_WRITE);
    assert(edr_storage_queue_is_open() == 0);
    assert(sqlite_scalar_path(path, "SELECT COUNT(*) FROM event_queue WHERE id=1 "
                                     "AND batch_id='unclassifiable-null' AND payload IS NULL;") == 1u);
    edr_storage_queue_close(); remove(path);
  }
}

uint64_t edr_storage_queue_test_last_capacity_vm_steps(void);
static void test_capacity_ledger_calibration_and_bounded_admission(void) {
  char path[256]; uint8_t wire[20]; uint64_t steps_small, steps_large, expected;
  EdrStorageQueueCapacityMetrics metrics;
  snprintf(path, sizeof(path), "edr-ledger-calibration-%ld.db", (long)TEST_PID);
  remove(path); make_wire(wire, 0xe5u);
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_enqueue("ledger-small", wire, sizeof(wire), 0, 1) == EDR_OK);
  steps_small = edr_storage_queue_test_last_capacity_vm_steps();
  assert(steps_small > 0u);
  /* Large retained inventory is fixture-only, with old unknown classification.
   * It must not make the next admission scan thousands of frozen payloads. */
  sqlite_exec_path(path, "WITH RECURSIVE n(i) AS(SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<5000) "
                        "INSERT INTO event_queue(batch_id,payload,created_at,status) "
                        "SELECT 'legacy-flood-'||i,zeroblob(1024),1,'local_evidence' FROM n;");
  assert(edr_storage_queue_enqueue("ledger-large", wire, sizeof(wire), 0, 1) == EDR_OK);
  steps_large = edr_storage_queue_test_last_capacity_vm_steps();
  assert(steps_large <= steps_small + 32u);
  fprintf(stderr, "[queue-test] capacity admission vm_steps small=%llu retained_5000=%llu\n",
          (unsigned long long)steps_small, (unsigned long long)steps_large);
  expected = assert_capacity_matches_inventory(path);
  /* SQLite length(TEXT) stops at NUL and counts Unicode characters. Frozen
   * legacy identifiers are charged for all stored bytes, without rewriting. */
  sqlite_exec_path(path, "INSERT INTO event_queue(batch_id,payload,created_at,status) "
                        "VALUES(CAST(x'F09F92BE00C3A9' AS TEXT),x'0001ff',1,'local_evidence');");
  assert(assert_capacity_matches_inventory(path) == expected + 512u + 7u + 3u);
  expected += 512u + 7u + 3u;
  assert_sqlite_write_rejected(path, "UPDATE queue_capacity_ledger_v1 SET logical_bytes=-1 WHERE category=0;");
  assert_sqlite_write_rejected(path, "UPDATE queue_capacity_ledger_v1 SET logical_bytes=1.5 WHERE category=0;");
  assert_sqlite_write_rejected(path, "UPDATE queue_capacity_ledger_v1 SET logical_bytes=9223372036854775807+1 WHERE category=0;");
  assert(assert_capacity_matches_inventory(path) == expected);
  edr_storage_queue_close();
  sqlite_exec_path(path, "UPDATE queue_capacity_ledger_v1 SET logical_bytes=0,row_count=0;");
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(assert_capacity_matches_inventory(path) == expected);
  /* Runtime damage must deny new admissions. Reopen recalibrates from owners,
   * without deleting or rewriting any of their retained bytes. */
  sqlite_exec_path(path, "DELETE FROM queue_capacity_ledger_v1 WHERE category=2;");
  edr_storage_queue_get_capacity_metrics(&metrics);
  assert(metrics.accounting_available == 0u);
  assert(edr_storage_queue_enqueue("ledger-missing-row", wire, sizeof(wire), 0, 1) != EDR_OK);
  assert(batch_row_id(path, "ledger-missing-row") < 0);
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(assert_capacity_matches_inventory(path) == expected);
  assert(sqlite_scalar_path(path, "SELECT COUNT(*) FROM event_queue WHERE batch_id LIKE 'legacy-flood-%';") == 5000u);
  assert(batch_retained_exact(path, "ledger-small", "pending", wire, sizeof(wire)));
  edr_storage_queue_close(); remove(path);
}

static EdrStorageQueueLocalEvidenceOwner diagnostic_owner(void) {
  EdrStorageQueueLocalEvidenceOwner owner={0};
  owner.version=1u;owner.diagnostic_reason="missing_cmdline";
  owner.endpoint_id="synthetic-endpoint";owner.tenant_id="synthetic-tenant";
  owner.event_time_ns=INT64_C(100000000000000);owner.event_type=1u;
  owner.pid=42u;owner.parent_pid=4u;owner.process_start_key=UINT64_MAX;
  owner.process_creation_filetime_100ns=UINT64_C(133444444444444444);
  owner.parent_process_start_key=99u;owner.parent_process_creation_filetime_100ns=UINT64_C(133444444000000000);
  return owner;
}
static void typed_local_write(const char *batch,const uint8_t *wire,size_t bytes) {
  EdrStorageQueueP0SourceOnlyLatch latch;EdrStorageQueueLocalEvidenceOwner owner=diagnostic_owner();
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch)==EDR_OK);
  assert(edr_storage_queue_p0_source_only_commit_local_typed(&latch,batch,batch,wire,bytes,0,0,&owner)==EDR_OK);
}
static void test_typed_local_rotation_and_owner_guards(void) {
  char path[256];uint8_t wire[20];EdrStorageQueueCapacityMetrics before,after;
  EdrStorageQueueP0SourceOnlyLatch latch;EdrStorageQueueLocalEvidenceOwner owner=diagnostic_owner();
  snprintf(path,sizeof(path),"edr-local-typed-%ld.db",(long)TEST_PID);remove(path);make_wire(wire,0xc1u);
  edr_storage_queue_configure(8u,1u);edr_storage_queue_test_set_delivery_time(100000);
  edr_storage_queue_test_set_local_retention_elapsed(0u);
  assert(edr_storage_queue_open(path)==EDR_OK);
  typed_local_write("typed-0",wire,sizeof(wire));
  assert(sqlite_scalar_path(path,"SELECT COUNT(*) FROM event_queue WHERE retention_policy_version=2 AND local_start_key='18446744073709551615';")==1u);
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch)==EDR_OK);
  owner.pid++;
  assert(edr_storage_queue_p0_source_only_commit_local_typed(&latch,"typed-0","typed-0",wire,sizeof(wire),0,0,&owner)==EDR_ERR_INVALID_ARG);
  owner=diagnostic_owner();
  assert(edr_storage_queue_p0_source_only_commit_local_typed(&latch,"typed-0","typed-0",wire,sizeof(wire),0,0,&owner)==EDR_OK);
  owner.event_time_ns=INT64_C(107200000000000);
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch)==EDR_OK);
  assert(edr_storage_queue_p0_source_only_commit_local_typed(&latch,"typed-future","typed-future",wire,sizeof(wire),0,0,&owner)==EDR_OK);
  owner.event_time_ns=INT64_MAX;
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch)==EDR_OK);
  assert(edr_storage_queue_p0_source_only_commit_local_typed(&latch,"typed-future-max","typed-future-max",wire,sizeof(wire),0,0,&owner)==EDR_OK);
  owner=diagnostic_owner();
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch)==EDR_OK);
  owner.diagnostic_reason="terminal_journal_unavailable";
  assert(edr_storage_queue_p0_source_only_commit_local_typed(&latch,"direct","direct",wire,sizeof(wire),0,0,&owner)==EDR_ERR_INVALID_ARG);
  owner.diagnostic_reason="unknown-future-reason";
  assert(edr_storage_queue_p0_source_only_commit_local_typed(&latch,"unknown","unknown",wire,sizeof(wire),0,0,&owner)==EDR_ERR_INVALID_ARG);
  assert(edr_storage_queue_p0_source_only_commit_local(&latch,"protected-direct","protected-direct",wire,sizeof(wire),0,0)==EDR_OK);
  assert_capacity_matches_inventory(path);
  edr_storage_queue_get_capacity_metrics(&before);
  /* Wall clock steps do not consume the recent window while this process is
   * alive; a rewind is conservative. Advance both clocks for actual ageing. */
  edr_storage_queue_test_set_delivery_time(107200);edr_storage_queue_test_run_cleanup();
  assert(batch_row_id(path,"typed-0")>0);
  edr_storage_queue_test_set_delivery_time(99000);edr_storage_queue_test_run_cleanup();
  assert(batch_row_id(path,"typed-0")>0);
  edr_storage_queue_test_set_delivery_time(103601);edr_storage_queue_test_set_local_retention_elapsed(3601u);
  /* Opaque pending and failed deferred snapshots conservatively protect the
   * whole set. Completing their real owner releases that protection. */
  const uint8_t deferred[]={ '{','}' };char key[65];assert(edr_sha256_hex(deferred,sizeof(deferred),key)==0);
  assert(edr_storage_queue_p0_deferred_retain(key,1u,deferred,sizeof(deferred))==EDR_OK);
  edr_storage_queue_test_run_cleanup();assert(batch_row_id(path,"typed-0")>0);
  assert(edr_storage_queue_p0_deferred_complete(key,NULL,NULL,0u,"synthetic-completed")==EDR_OK);
  /* Recovery and lineage metadata are not overridden by local expiry. */
  sqlite_exec_path(path,"UPDATE queue_meta SET legacy_lineage='synthetic-lineage';");
  edr_storage_queue_test_run_cleanup();assert(batch_row_id(path,"typed-0")>0);
  sqlite_exec_path(path,"UPDATE queue_meta SET legacy_lineage='';");
  sqlite_exec_path(path,"UPDATE event_queue SET recovery_version=1,recovery_state='retained_unresolved' WHERE batch_id='typed-0';");
  edr_storage_queue_test_run_cleanup();assert(batch_row_id(path,"typed-0")>0);
  sqlite_exec_path(path,"UPDATE event_queue SET recovery_version=0,recovery_state='' WHERE batch_id='typed-0';");
  sqlite_exec_path(path,"INSERT INTO queue_projection_relations(origin_row_id,projector_version,batch_id,payload_sha256,receipt_state,created_at,acked_at) "
      "SELECT id,'synthetic-test','synthetic-projection','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','acked',100000,103601 "
      "FROM event_queue WHERE batch_id='typed-0';");
  edr_storage_queue_test_run_cleanup();assert(batch_row_id(path,"typed-0")>0);
  /* Only the synthetic fixture releases this relation. A real projection ACK
   * above did not confer local retirement authority. */
  sqlite_exec_path(path,"DELETE FROM queue_projection_relations WHERE batch_id='synthetic-projection';");
  sqlite_exec_path(path,"INSERT INTO event_queue(batch_id,payload,created_at,severity,status,origin_row_id) "
      "SELECT 'synthetic-child',zeroblob(20),100000,2,'local_evidence',id FROM event_queue WHERE batch_id='typed-0';");
  edr_storage_queue_test_run_cleanup();assert(batch_row_id(path,"typed-0")>0);
  sqlite_exec_path(path,"DELETE FROM event_queue WHERE batch_id='synthetic-child';");
  edr_storage_queue_test_fail_next_local_retention_commits(1u);edr_storage_queue_test_run_cleanup();
  assert(batch_row_id(path,"typed-0")>0);assert_capacity_matches_inventory(path);
  edr_storage_queue_get_capacity_metrics(&after);assert(after.local_retired_rows==0u);
  assert(after.local_retention_protected_slices>=3u);
  edr_storage_queue_test_run_cleanup();assert(batch_row_id(path,"typed-0")<0);
  assert(batch_retained_exact(path,"typed-future","local_evidence",wire,sizeof(wire)));
  assert(batch_retained_exact(path,"typed-future-max","local_evidence",wire,sizeof(wire)));
  assert(batch_retained_exact(path,"protected-direct","local_evidence",wire,sizeof(wire)));
  assert(ack_receipt_count(path,"typed-0",wire,sizeof(wire))==0);
  edr_storage_queue_get_capacity_metrics(&after);
  assert(after.local_retired_rows==1u && after.local_retired_bytes>sizeof(wire));
  assert(after.delivery_acked==before.delivery_acked && after.local_retention_unclassified_rows==1u);
  assert_capacity_matches_inventory(path);
  typed_local_write("typed-failed-deferred",wire,sizeof(wire));
  const uint8_t failed_snapshot[]={'[',']'};
  assert(edr_sha256_hex(failed_snapshot,sizeof(failed_snapshot),key)==0);
  assert(edr_storage_queue_p0_deferred_retain(key,1u,failed_snapshot,sizeof(failed_snapshot))==EDR_OK);
  assert(edr_storage_queue_p0_deferred_fail(key,"synthetic-held")==EDR_OK);
  edr_storage_queue_test_set_delivery_time(107202);edr_storage_queue_test_set_local_retention_elapsed(7202u);
  edr_storage_queue_test_run_cleanup();assert(batch_row_id(path,"typed-failed-deferred")>0);
  edr_storage_queue_close();assert(edr_storage_queue_open(path)==EDR_OK);
  edr_storage_queue_get_capacity_metrics(&after);assert(after.local_retired_rows==1u);
  assert(batch_retained_exact(path,"protected-direct","local_evidence",wire,sizeof(wire)));
  edr_storage_queue_close();remove(path);edr_storage_queue_configure(0u,0u);
  edr_storage_queue_test_set_delivery_time(-1);edr_storage_queue_test_set_local_retention_elapsed(UINT64_MAX);
}
static void test_typed_local_bounded_slices_and_pressure(void) {
  char path[256],batch[64];uint8_t wire[20],*large=malloc(131072u);
  EdrStorageQueueCapacityMetrics metrics,before;unsigned inserted=0u;
  EdrStorageQueueP0SourceOnlyLatch latch;EdrStorageQueueLocalEvidenceOwner owner=diagnostic_owner();
  assert(large);make_large_wire(large,131072u,0xc2u);make_wire(wire,0xc3u);
  snprintf(path,sizeof(path),"edr-local-typed-slice-%ld.db",(long)TEST_PID);remove(path);
  edr_storage_queue_configure(8u,1u);edr_storage_queue_test_set_delivery_time(200000);
  edr_storage_queue_test_set_local_retention_elapsed(0u);assert(edr_storage_queue_open(path)==EDR_OK);
  for(unsigned i=0;i<300u;++i) {snprintf(batch,sizeof(batch),"typed-slice-%u",i);typed_local_write(batch,wire,sizeof(wire));}
  edr_storage_queue_test_set_delivery_time(203601);edr_storage_queue_test_set_local_retention_elapsed(3601u);
  edr_storage_queue_test_run_cleanup();edr_storage_queue_get_capacity_metrics(&metrics);
  assert(metrics.local_retired_rows>0u && metrics.local_retired_rows<=128u);
  assert(metrics.local_retention_typed_rows+metrics.local_retired_rows==300u);
  for(unsigned slice=0;slice<20u && metrics.local_retention_typed_rows;++slice) {
    uint64_t previous=metrics.local_retired_rows;edr_storage_queue_test_run_cleanup();
    edr_storage_queue_get_capacity_metrics(&metrics);assert(metrics.local_retired_rows-previous<=128u);
  }
  assert(metrics.local_retired_rows==300u && metrics.local_retention_typed_rows==0u);
  assert_capacity_matches_inventory(path);edr_storage_queue_close();remove(path);
  snprintf(path,sizeof(path),"edr-local-typed-pressure-%ld.db",(long)TEST_PID);remove(path);
  edr_storage_queue_configure(1u,1u);edr_storage_queue_test_set_delivery_time(300000);
  edr_storage_queue_test_set_local_retention_elapsed(0u);assert(edr_storage_queue_open(path)==EDR_OK);
  edr_storage_queue_get_capacity_metrics(&before);
  for(unsigned i=0;i<12u;++i) {
    snprintf(batch,sizeof(batch),"typed-pressure-%u",i);
    assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch)==EDR_OK);
    EdrError result=edr_storage_queue_p0_source_only_commit_local_typed(&latch,batch,batch,large,131072u,0,0,&owner);
    if(result==EDR_ERR_QUEUE_FULL) break;assert(result==EDR_OK);inserted++;
  }
  assert(inserted>0u && inserted<12u);
  assert(edr_storage_queue_p0_source_only_commit_local_typed(&latch,"typed-pressure-0","typed-pressure-0",large,131072u,0,0,&owner)==EDR_OK);
  /* Expiry is committed independently before a new admission, so a failed
   * admission cannot roll its cursor backwards or starve an expired prefix. */
  for(unsigned round=1u;round<=12u;++round) {
    edr_storage_queue_test_set_delivery_time(300000+(int64_t)round*3601);
    edr_storage_queue_test_set_local_retention_elapsed((uint64_t)round*3601u);
    snprintf(batch,sizeof(batch),"typed-new-%u",round);typed_local_write(batch,large,131072u);
    edr_storage_queue_get_capacity_metrics(&metrics);assert(metrics.used_bytes<=metrics.ordinary_limit_bytes);
  }
  assert(metrics.local_retired_rows>=inserted);
  assert(edr_storage_queue_enqueue("typed-terminal-20",wire,sizeof(wire),0,1)==EDR_OK);
  reset_send_state(1);edr_storage_queue_poll_drain();assert(send_calls_for(0xc2u)==0u);
  assert(metrics.delivery_acked==before.delivery_acked);
  assert_capacity_matches_inventory(path);
  edr_storage_queue_close();remove(path);free(large);edr_storage_queue_configure(0u,0u);
  edr_storage_queue_test_set_delivery_time(-1);edr_storage_queue_test_set_local_retention_elapsed(UINT64_MAX);
}

static void test_typed_local_snapshot_busy_and_physical_guard(void) {
  char path[256];uint8_t wire[20];sqlite3 *reader=NULL,*writer=NULL;sqlite3_stmt *st=NULL;
  EdrStorageQueueCapacityMetrics metrics;make_wire(wire,0xc4u);
  snprintf(path,sizeof(path),"edr-local-typed-read-%ld.db",(long)TEST_PID);remove(path);
  assert(test_setenv("EDR_QUEUE_BUSY_TIMEOUT_MS","100")==0);
  edr_storage_queue_configure(8u,1u);edr_storage_queue_test_set_delivery_time(400000);
  edr_storage_queue_test_set_local_retention_elapsed(0u);assert(edr_storage_queue_open(path)==EDR_OK);
  typed_local_write("typed-read",wire,sizeof(wire));
  assert(sqlite3_open(path,&reader)==SQLITE_OK && sqlite3_exec(reader,"BEGIN;",NULL,NULL,NULL)==SQLITE_OK);
  assert(sqlite3_prepare_v2(reader,"SELECT payload FROM event_queue WHERE batch_id='typed-read';",-1,&st,NULL)==SQLITE_OK);
  assert(sqlite3_step(st)==SQLITE_ROW && sqlite3_column_bytes(st,0)==sizeof(wire));
  sqlite3_finalize(st);st=NULL;
  assert(sqlite3_open(path,&writer)==SQLITE_OK && sqlite3_exec(writer,"BEGIN IMMEDIATE;",NULL,NULL,NULL)==SQLITE_OK);
  edr_storage_queue_test_set_delivery_time(403601);edr_storage_queue_test_set_local_retention_elapsed(3601u);
  edr_storage_queue_test_run_cleanup();assert(batch_row_id(path,"typed-read")>0);
  assert(sqlite3_exec(writer,"ROLLBACK;",NULL,NULL,NULL)==SQLITE_OK && sqlite3_close(writer)==SQLITE_OK);
  assert(test_setenv("EDR_STORAGE_MIN_FREE_MB","4294967295")==0);
  edr_storage_queue_test_run_cleanup();assert(batch_row_id(path,"typed-read")>0);
  edr_storage_queue_get_capacity_metrics(&metrics);
  assert(metrics.physical_failure_kind==1u && metrics.physical_admission_failures>0u);
  assert(test_unsetenv("EDR_STORAGE_MIN_FREE_MB")==0);
  edr_storage_queue_test_run_cleanup();assert(batch_row_id(path,"typed-read")<0);
  /* A read/export that already has a SQLite snapshot retains the complete
   * original until its transaction ends, even after writer retirement. */
  assert(sqlite3_prepare_v2(reader,"SELECT payload FROM event_queue WHERE batch_id='typed-read';",-1,&st,NULL)==SQLITE_OK);
  assert(sqlite3_step(st)==SQLITE_ROW && sqlite3_column_bytes(st,0)==sizeof(wire) && !memcmp(sqlite3_column_blob(st,0),wire,sizeof(wire)));
  sqlite3_finalize(st);assert(sqlite3_exec(reader,"COMMIT;",NULL,NULL,NULL)==SQLITE_OK && sqlite3_close(reader)==SQLITE_OK);
  assert_capacity_matches_inventory(path);
  assert(edr_storage_queue_enforcement_terminal_precreate("reserved-physical","physical-source","physical-rule","physical-generation",
      "physical-intent",wire,sizeof(wire))==EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  typed_local_write("typed-held-journal",wire,sizeof(wire));
  edr_storage_queue_test_set_delivery_time(407202);edr_storage_queue_test_set_local_retention_elapsed(7202u);
  edr_storage_queue_test_run_cleanup();assert(batch_row_id(path,"typed-held-journal")>0);
  /* A synthetic floor above the volume's free bytes denies new owners but
   * does not spend an existing journal result reservation a second time. */
  assert(test_setenv("EDR_STORAGE_MIN_FREE_MB","4294967295")==0);
  assert(edr_storage_queue_enqueue("physical-denied",wire,sizeof(wire),0,1)==EDR_ERR_QUEUE_FULL);
  edr_storage_queue_get_capacity_metrics(&metrics);
  assert(metrics.physical_failure_kind==1u && metrics.physical_admission_failures>0u);
  assert(metrics.physical_required_bytes>metrics.physical_available_bytes);
  assert(edr_storage_queue_enforcement_terminal_update("reserved-physical","physical-source-batch",wire,sizeof(wire),
      "physical-combined",wire,sizeof(wire))==EDR_OK);
  assert(terminal_journal_state_is(path,"reserved-physical","ready"));
  assert(test_setenv("EDR_STORAGE_MIN_FREE_MB","invalid")==0);
  assert(edr_storage_queue_enqueue("physical-invalid",wire,sizeof(wire),0,1)==EDR_ERR_QUEUE_FULL);
  edr_storage_queue_get_capacity_metrics(&metrics);assert(metrics.physical_failure_kind==2u);
  assert(batch_row_id(path,"physical-denied")<0 && batch_row_id(path,"physical-invalid")<0);
  assert(test_unsetenv("EDR_STORAGE_MIN_FREE_MB")==0 && test_unsetenv("EDR_QUEUE_BUSY_TIMEOUT_MS")==0);
  edr_storage_queue_close();remove(path);edr_storage_queue_configure(0u,0u);
  edr_storage_queue_test_set_delivery_time(-1);edr_storage_queue_test_set_local_retention_elapsed(UINT64_MAX);
}

static uint64_t synthetic_count(const char *path,const char *sql) {
  sqlite3 *db=NULL;sqlite3_stmt *st=NULL;uint64_t result;
  assert(sqlite3_open(path,&db)==SQLITE_OK);
  assert(sqlite3_prepare_v2(db,sql,-1,&st,NULL)==SQLITE_OK && sqlite3_step(st)==SQLITE_ROW);
  result=(uint64_t)sqlite3_column_int64(st,0);sqlite3_finalize(st);sqlite3_close(db);return result;
}
static void test_legacy_maintenance_bounded_slices(void) {
  char path[256];sqlite3 *db=NULL;uint8_t wire[20];make_wire(wire,0xc5u);
  EdrStorageQueueCapacityMetrics before,after;
  snprintf(path,sizeof(path),"edr-legacy-slices-%ld.db",(long)TEST_PID);remove(path);
  edr_storage_queue_configure(32u,1u);assert(edr_storage_queue_open(path)==EDR_OK);
  assert(sqlite3_open(path,&db)==SQLITE_OK);
  /* Synthetic old-schema inventory: completed tombstones plus a deliberately
   * oversized indivisible ACKed journal owner. No real cache is opened. */
  assert(sqlite3_exec(db,
      "BEGIN;WITH RECURSIVE n(i) AS(SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<300) "
      "INSERT INTO p0_deferred_match(key_sha256,family_mask,payload,payload_len,payload_sha256,state,created_at,updated_at,completed_at) "
      "SELECT printf('%064d',i),1,NULL,1,printf('%064d',i),'completed',1,1,1 FROM n;"
      "WITH RECURSIVE n(i) AS(SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<8) "
      "INSERT INTO enforcement_terminal_journal(idempotency_key,source_event_key,rule_id,process_generation_key,state,"
      "intent_wire,intent_acked,source_acked,combined_acked,created_at,updated_at) "
      "SELECT printf('synthetic-bounded-%d',i),'synthetic-source','synthetic-rule','synthetic-generation',"
      "'completed',zeroblob(1048576),1,1,1,1,1 FROM n;"
      "INSERT INTO enforcement_terminal_journal(idempotency_key,source_event_key,rule_id,process_generation_key,state,"
      "intent_wire,intent_acked,source_acked,combined_acked,created_at,updated_at) "
      "VALUES('synthetic-oversize','synthetic-source','synthetic-rule','synthetic-generation','completed',zeroblob(4194305),1,1,1,1,1);"
      "COMMIT;",NULL,NULL,NULL)==SQLITE_OK);
  sqlite3_close(db);edr_storage_queue_get_capacity_metrics(&before);
  assert(test_setenv("EDR_STORAGE_MIN_FREE_MB","4294967295")==0);
  edr_storage_queue_test_run_cleanup();
  assert(synthetic_count(path,"SELECT count(*) FROM p0_deferred_match;")==300u);
  assert(test_unsetenv("EDR_STORAGE_MIN_FREE_MB")==0);
  edr_storage_queue_test_run_cleanup();edr_storage_queue_get_capacity_metrics(&after);
  assert(after.retention_evicted_rows-before.retention_evicted_rows<=128u);
  assert(before.used_bytes-after.used_bytes<=4u*1024u*1024u);
  assert(synthetic_count(path,"SELECT count(*) FROM p0_deferred_match;")>=172u);
  for(unsigned pass=0;pass<40u && (synthetic_count(path,"SELECT count(*) FROM p0_deferred_match;") ||
      synthetic_count(path,"SELECT count(*) FROM enforcement_terminal_journal WHERE idempotency_key LIKE 'synthetic-bounded-%';"));++pass) {
    before=after;edr_storage_queue_test_run_cleanup();edr_storage_queue_get_capacity_metrics(&after);
    assert(after.retention_evicted_rows-before.retention_evicted_rows<=128u);
    assert(before.used_bytes-after.used_bytes<=4u*1024u*1024u);
  }
  assert(synthetic_count(path,"SELECT count(*) FROM p0_deferred_match;")==0u);
  assert(synthetic_count(path,"SELECT count(*) FROM enforcement_terminal_journal WHERE idempotency_key LIKE 'synthetic-bounded-%';")==0u);
  assert(synthetic_count(path,"SELECT count(*) FROM enforcement_terminal_journal WHERE idempotency_key='synthetic-oversize';")==1u);
  assert(after.maintenance_oversize_holds>0u);
  assert_capacity_matches_inventory(path);
  edr_storage_queue_close();remove(path);edr_storage_queue_configure(0u,0u);
}

typedef struct LocalQueryFixture {
  unsigned visits;int retire,fail,cancel;
  uint8_t wire[20];const char *path;EdrStorageQueueLocalQuery query;
} LocalQueryFixture;
static int local_query_test_cancel(void *arg) {return ((LocalQueryFixture *)arg)->cancel;}
static int local_query_test_visit(const char *event,const EdrStorageQueueLocalEvidenceOwner *owner,
    const uint8_t *wire,size_t len,void *arg) {
  LocalQueryFixture *fixture=arg;EdrStorageQueueLocalQueryStats stats;
  assert(strstr(event,"query-")==event && owner->pid==42u && owner->parent_pid==4u &&
         owner->process_start_key==UINT64_MAX && owner->parent_process_start_key==99u);
  assert(len==sizeof(fixture->wire) && !memcmp(wire,fixture->wire,len));
  fixture->visits++;
  /* Callback owns a copied snapshot, not the queue mutex or an unbounded pin.
   * A recursive query is a finite refusal, while maintenance can complete. */
  assert(edr_storage_queue_query_local_snapshot(&fixture->query,local_query_test_visit,NULL,fixture,&stats)==-2);
  if(fixture->retire && fixture->visits==1u) {
    edr_storage_queue_test_set_delivery_time(703601);edr_storage_queue_test_set_local_retention_elapsed(3601u);
    edr_storage_queue_test_run_cleanup();
    assert(batch_row_id(fixture->path,"query-0")<0);
  }
  return fixture->fail?-1:1;
}
static void test_typed_local_query_snapshot(void) {
  char path[256];LocalQueryFixture fixture={0};EdrStorageQueueLocalQueryStats stats;
  snprintf(path,sizeof(path),"edr-local-query-%ld.db",(long)TEST_PID);remove(path);fixture.path=path;
  make_wire(fixture.wire,0xc6u);
  edr_storage_queue_configure(8u,1u);edr_storage_queue_test_set_delivery_time(700000);
  edr_storage_queue_test_set_local_retention_elapsed(0u);assert(edr_storage_queue_open(path)==EDR_OK);
  for(unsigned i=0;i<3u;++i) {char name[32];snprintf(name,sizeof(name),"query-%u",i);typed_local_write(name,fixture.wire,sizeof(fixture.wire));}
  EdrStorageQueueLocalEvidenceOwner owner=diagnostic_owner();
  EdrStorageQueueLocalQuery *query=&fixture.query;
  query->tenant_id=owner.tenant_id;query->endpoint_id=owner.endpoint_id;
  query->from_ns=owner.event_time_ns-1;query->until_ns=owner.event_time_ns+1;
  query->max_rows=1000u;query->max_scan=100u;query->max_payload_bytes=4096u;
  query->until_mono_ns=edr_monotonic_ns()+UINT64_C(10000000000);
  assert(edr_storage_queue_query_local_snapshot(query,local_query_test_visit,local_query_test_cancel,&fixture,&stats)==0);
  assert(fixture.visits==3u && stats.copied==3u && stats.payload_bytes==60u);
  query->has_type=1;query->event_type=owner.event_type;query->pid=owner.pid;
  query->has_process_start_key=query->has_process_creation_filetime_100ns=1;
  query->process_start_key=owner.process_start_key;query->process_creation_filetime_100ns=owner.process_creation_filetime_100ns;
  fixture.visits=0;
  assert(edr_storage_queue_query_local_snapshot(query,local_query_test_visit,NULL,&fixture,&stats)==0 && fixture.visits==3u);
  query->process_start_key--;
  assert(edr_storage_queue_query_local_snapshot(query,local_query_test_visit,NULL,&fixture,&stats)==0 && stats.copied==0u);
  query->process_start_key++;query->tenant_id="different-tenant";
  assert(edr_storage_queue_query_local_snapshot(query,local_query_test_visit,NULL,&fixture,&stats)==0 && stats.copied==0u);
  query->tenant_id=owner.tenant_id;query->event_type++;
  assert(edr_storage_queue_query_local_snapshot(query,local_query_test_visit,NULL,&fixture,&stats)==0 && stats.copied==0u);
  query->event_type--;query->max_rows=1u;fixture.visits=0;
  assert(edr_storage_queue_query_local_snapshot(query,local_query_test_visit,NULL,&fixture,&stats)==1 && fixture.visits==1u);
  query->max_rows=1000u;query->max_payload_bytes=19u;
  assert(edr_storage_queue_query_local_snapshot(query,local_query_test_visit,NULL,&fixture,&stats)==-4);
  query->max_payload_bytes=40u;fixture.visits=0;
  assert(edr_storage_queue_query_local_snapshot(query,local_query_test_visit,NULL,&fixture,&stats)==1 && fixture.visits==2u);
  query->max_payload_bytes=4096u;query->has_process_start_key=0;query->max_scan=1u;query->pid=43u;
  assert(edr_storage_queue_query_local_snapshot(query,local_query_test_visit,NULL,&fixture,&stats)==1 && stats.scanned==1u && stats.copied==0u);
  query->max_scan=100u;query->pid=42u;fixture.fail=1;
  assert(edr_storage_queue_query_local_snapshot(query,local_query_test_visit,NULL,&fixture,&stats)==-6);
  fixture.fail=0;fixture.cancel=1;
  assert(edr_storage_queue_query_local_snapshot(query,local_query_test_visit,local_query_test_cancel,&fixture,&stats)==-5);
  fixture.cancel=0;fixture.retire=1;fixture.visits=0;
  assert(edr_storage_queue_query_local_snapshot(query,local_query_test_visit,NULL,&fixture,&stats)==0 && fixture.visits==3u);
  assert(stats.copied==3u && batch_row_id(path,"query-1")<0 && batch_row_id(path,"query-2")<0);
  typed_local_write("query-corrupt",fixture.wire,sizeof(fixture.wire));fixture.retire=0;
  sqlite_exec_path(path,"DROP TRIGGER event_queue_local_owner_v2_immutable;"
      "UPDATE event_queue SET local_owner_sha256=printf('%064d',0) WHERE batch_id='query-corrupt';");
  assert(edr_storage_queue_query_local_snapshot(query,local_query_test_visit,NULL,&fixture,&stats)==-3);
  edr_storage_queue_close();remove(path);edr_storage_queue_configure(0u,0u);
  edr_storage_queue_test_set_delivery_time(-1);edr_storage_queue_test_set_local_retention_elapsed(UINT64_MAX);
}

static void test_terminal_local_reserved_bound_and_event_time(void) {
  char path[256],scope[96];uint8_t intent[20],source[20],combined[20];
  uint8_t *large=malloc(90000u);assert(large);make_large_wire(large,90000u,0xb0u);
  make_wire(intent,0xb1u);make_wire(source,0xb2u);make_wire(combined,0xb3u);
  memset(scope,'s',sizeof(scope)-1u);scope[sizeof(scope)-1u]=0;
  snprintf(path,sizeof(path),"edr-terminal-owner-budget-%ld.db",(long)TEST_PID);remove(path);
  EdrStorageQueueLocalEvidenceOwner owner=diagnostic_owner();
  owner.diagnostic_reason="enforcement_terminal_result";owner.endpoint_id=scope;owner.tenant_id=scope;
  owner.event_time_ns=INT64_C(900000000000001);
  edr_storage_queue_configure(8u,1u);edr_storage_queue_test_set_delivery_time(800000);
  edr_storage_queue_test_set_local_retention_elapsed(0u);assert(edr_storage_queue_open(path)==EDR_OK);
  assert(edr_storage_queue_enforcement_terminal_precreate("typed-budget",scope,"synthetic-rule","startkey-ffffffffffffffff",
      "typed-budget-intent",intent,sizeof(intent))==EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  uint64_t before=assert_capacity_matches_inventory(path);
  /* Metadata was reserved before action. A caller exceeding the bounded
   * frozen-frame promise cannot spend unrelated free capacity after action. */
  assert(edr_storage_queue_enforcement_terminal_update_local_source("typed-budget","typed-budget-source",large,90000u,
      "typed-budget-combined",large,90000u,scope,&owner)==EDR_ERR_QUEUE_FULL);
  assert(assert_capacity_matches_inventory(path)==before);
  assert(sqlite_scalar_path(path,"SELECT COUNT(*) FROM enforcement_terminal_journal WHERE source_wire IS NULL AND local_owner_reserved=2048;")==1u);
  assert(edr_storage_queue_enforcement_terminal_update_local_source("typed-budget","typed-budget-source",source,sizeof(source),
      "typed-budget-combined",combined,sizeof(combined),scope,&owner)==EDR_OK);
  assert(assert_capacity_matches_inventory(path)<before);
  assert(edr_storage_queue_enforcement_terminal_precreate_local_source_bound("typed-sized",scope,"synthetic-rule",
      "startkey-ffffffffffffffff","typed-sized-intent",intent,sizeof(intent),90000u)==EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  before=assert_capacity_matches_inventory(path);
  assert(edr_storage_queue_enforcement_terminal_update_local_source("typed-sized","typed-sized-source",large,90000u,
      "typed-sized-combined",large,90000u,scope,&owner)==EDR_OK);
  assert(assert_capacity_matches_inventory(path)<before);
  reset_send_state(1);edr_storage_queue_poll_drain();
  assert(send_calls_for(0xb1u)==2u && send_calls_for(0xb3u)==1u && send_calls_for(0xb2u)==0u && send_calls_for(0xb0u)==1u);
  assert(terminal_journal_state_is(path,"typed-budget","local_retained"));
  edr_storage_queue_test_set_delivery_time(803601);edr_storage_queue_test_set_local_retention_elapsed(3601u);
  for(unsigned i=0;i<5u;++i) edr_storage_queue_test_run_cleanup();
  assert(terminal_journal_state_is(path,"typed-budget","local_retained"));
  /* Arrival/delivery TTL alone is insufficient for an event in the future.
   * The one-nanosecond boundary survives the inclusive seconds cutoff. */
  edr_storage_queue_test_set_delivery_time(903600);edr_storage_queue_test_set_local_retention_elapsed(103600u);
  for(unsigned i=0;i<5u;++i) edr_storage_queue_test_run_cleanup();
  assert(terminal_journal_state_is(path,"typed-budget","local_retained"));
  assert_capacity_matches_inventory(path);
  edr_storage_queue_test_set_delivery_time(903601);edr_storage_queue_test_set_local_retention_elapsed(103601u);
  for(unsigned i=0;i<5u;++i) edr_storage_queue_test_run_cleanup();
  assert(sqlite_scalar_path(path,"SELECT COUNT(*) FROM enforcement_terminal_journal;")==0u);
  assert(assert_capacity_matches_inventory(path)==0u);
  edr_storage_queue_close();remove(path);free(large);edr_storage_queue_configure(0u,0u);
  edr_storage_queue_test_set_delivery_time(-1);edr_storage_queue_test_set_local_retention_elapsed(UINT64_MAX);
}

uint64_t edr_storage_queue_test_last_terminal_vm_steps(void);
static void assert_terminal_state_counts(const char *path) {
  EdrEnforcementTerminalJournalMetrics metrics;
  edr_storage_queue_enforcement_terminal_get_metrics(&metrics);
  assert(metrics.pending==sqlite_scalar_path(path,"SELECT COUNT(*) FROM enforcement_terminal_journal WHERE state IN('pending_intent','outcome_unknown','ready') OR (state IN('completed','local_retained') AND intent_acked=0);"));
  assert(metrics.failed==sqlite_scalar_path(path,"SELECT COUNT(*) FROM enforcement_terminal_journal WHERE state='failed';"));
  assert(metrics.outcome_unknown==sqlite_scalar_path(path,"SELECT COUNT(*) FROM enforcement_terminal_journal WHERE state='outcome_unknown';"));
  assert(metrics.policy_held_frames==sqlite_scalar_path(path,"SELECT COALESCE(SUM(intent_policy_held+source_policy_held+combined_policy_held),0) FROM enforcement_terminal_journal;"));
  assert(metrics.local_retained==sqlite_scalar_path(path,"SELECT COUNT(*) FROM enforcement_terminal_journal WHERE state='local_retained' AND intent_acked=1 AND combined_acked=1 AND source_acked=0;"));
}
static void test_terminal_state_ledger_transaction_and_constant_read(void) {
  char path[256];uint8_t wire[20];EdrEnforcementTerminalJournalMetrics metrics;
  snprintf(path,sizeof(path),"edr-terminal-state-ledger-%ld.db",(long)TEST_PID);remove(path);make_wire(wire,0xe8u);
  assert(edr_storage_queue_open(path)==EDR_OK);
  edr_storage_queue_test_fail_next_terminal_commits(1u);
  assert(edr_storage_queue_enforcement_terminal_precreate("state-ledger-rollback","state-event","state-rule","generation","state-intent",wire,sizeof(wire))==EDR_ENFORCEMENT_TERMINAL_PRECREATE_ERROR);
  assert(terminal_journal_count(path)==0);assert_terminal_state_counts(path);
  assert(edr_storage_queue_enforcement_terminal_precreate("state-ledger-owner","state-event","state-rule","generation","state-intent",wire,sizeof(wire))==EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  assert_terminal_state_counts(path);uint64_t small=edr_storage_queue_test_last_terminal_vm_steps();assert(small>0u);
  /* An independent legacy-style SQL writer also updates all state counts.
   * Rollback must undo the owner and counters as one SQLite transaction. */
  sqlite_exec_path(path,"BEGIN IMMEDIATE;UPDATE enforcement_terminal_journal SET state='failed',intent_policy_held=1;ROLLBACK;");
  assert_terminal_state_counts(path);edr_storage_queue_enforcement_terminal_get_metrics(&metrics);assert(metrics.pending==1u && metrics.failed==0u && metrics.policy_held_frames==0u);
  sqlite_exec_path(path,"UPDATE enforcement_terminal_journal SET state='outcome_unknown',intent_policy_held=1,source_policy_held=1;");
  assert_terminal_state_counts(path);edr_storage_queue_enforcement_terminal_get_metrics(&metrics);assert(metrics.outcome_unknown==1u && metrics.policy_held_frames==2u);
  sqlite_exec_path(path,"WITH RECURSIVE n(i) AS(SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<5000) "
      "INSERT INTO enforcement_terminal_journal(idempotency_key,source_event_key,rule_id,process_generation_key,state,created_at,updated_at) "
      "SELECT 'state-legacy-'||i,'source-'||i,'legacy-rule','generation','failed',1,1 FROM n;");
  assert_terminal_state_counts(path);uint64_t large=edr_storage_queue_test_last_terminal_vm_steps();assert(large<=small+4u);
  edr_storage_queue_enforcement_terminal_get_metrics(&metrics);assert(metrics.failed==5000u);
  sqlite_exec_path(path,"UPDATE enforcement_terminal_journal SET state='local_retained',intent_acked=1,combined_acked=1,source_acked=0 WHERE idempotency_key='state-legacy-1';");
  assert_terminal_state_counts(path);edr_storage_queue_enforcement_terminal_get_metrics(&metrics);assert(metrics.local_retained==1u && metrics.failed==4999u);
  sqlite_exec_path(path,"DELETE FROM enforcement_terminal_journal WHERE idempotency_key='state-legacy-1';");assert_terminal_state_counts(path);
  /* Type corruption is never silently read as zero and used to authorize an
   * action. Restore the synthetic damage before exercising restart calibration. */
  sqlite_exec_path(path,"PRAGMA ignore_check_constraints=ON;UPDATE queue_meta SET terminal_count_pending='invalid';");
  assert(edr_storage_queue_enforcement_terminal_precreate("state-ledger-denied","state-event-2","state-rule","generation","state-intent-2",wire,sizeof(wire))==EDR_ENFORCEMENT_TERMINAL_PRECREATE_ERROR);
  assert(sqlite_scalar_path(path,"SELECT COUNT(*) FROM enforcement_terminal_journal WHERE idempotency_key='state-ledger-denied';")==0u);
  sqlite_exec_path(path,"UPDATE queue_meta SET terminal_count_pending=1;");assert_terminal_state_counts(path);
  edr_storage_queue_close();
  sqlite_exec_path(path,"UPDATE queue_meta SET terminal_count_pending=0,terminal_count_failed=0,terminal_count_unknown=0,terminal_count_policy_held=0,terminal_count_local_retained=0;");
  assert(edr_storage_queue_open(path)==EDR_OK);assert_terminal_state_counts(path);
  edr_storage_queue_enforcement_terminal_get_metrics(&metrics);assert(metrics.pending==1u && metrics.failed==4999u && metrics.outcome_unknown==1u && metrics.policy_held_frames==2u);
  fprintf(stderr,"[queue-test] terminal state refresh vm_steps small=%llu retained_5000=%llu; rollback/legacy writer/reopen calibration passed\n",(unsigned long long)small,(unsigned long long)large);
  edr_storage_queue_close();remove(path);
}

uint64_t edr_storage_queue_test_startup_growth_bytes(void);
uint64_t edr_storage_queue_test_open_shm_growth(uint64_t bytes);
static void test_startup_physical_migration_and_current_schema(void) {
  assert(edr_storage_queue_test_open_shm_growth(0u)==65536u);
  assert(edr_storage_queue_test_open_shm_growth(512u*1024u*1024u)==258u*32768u);
  assert(edr_storage_queue_test_open_shm_growth(UINT64_MAX)>0u);
  char path[256],before_hash[65],after_hash[65];uint8_t wire[20];
  snprintf(path,sizeof(path),"edr-startup-space-%ld.db",(long)TEST_PID);remove(path);make_wire(wire,0xc8u);
  assert(edr_storage_queue_open(path)==EDR_OK);
  assert(edr_storage_queue_enqueue("startup-preserved",wire,sizeof(wire),0,1)==EDR_OK);
  assert(edr_storage_queue_enforcement_terminal_precreate("startup-owner","startup-event","startup-rule","startup-generation",
      "startup-intent",wire,sizeof(wire))==EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  edr_storage_queue_close();
  /* Extra allocated pages cannot inflate the current-schema metadata bound. */
  sqlite_exec_path(path,"CREATE TABLE startup_space_fixture(payload BLOB);INSERT INTO startup_space_fixture VALUES(zeroblob(2097152));");
  assert(edr_storage_queue_open(path)==EDR_OK);
  uint64_t current=edr_storage_queue_test_startup_growth_bytes();
  assert(current==128u*sqlite_scalar_path(path,"PRAGMA page_size;"));
  edr_storage_queue_close();
  sqlite_exec_path(path,"DROP INDEX idx_queue_local_time_v2;");
  synthetic_database_hash(path,before_hash);
  assert(test_setenv("EDR_STORAGE_MIN_FREE_MB","4294967295")==0);
  assert(edr_storage_queue_open(path)==EDR_ERR_QUEUE_FULL && !edr_storage_queue_is_open());
  synthetic_database_hash(path,after_hash);assert(!strcmp(before_hash,after_hash));
  assert(test_unsetenv("EDR_STORAGE_MIN_FREE_MB")==0);
  uint64_t image=sqlite_scalar_path(path,"SELECT page_count*page_size FROM pragma_page_count,pragma_page_size;");
  assert(edr_storage_queue_open(path)==EDR_OK);
  uint64_t migration=edr_storage_queue_test_startup_growth_bytes();
  assert(migration>=current+image*4u);
  assert(batch_retained_exact(path,"startup-preserved","pending",wire,sizeof(wire)));
  assert(edr_storage_queue_enforcement_terminal_precreate("startup-owner","startup-event","startup-rule","startup-generation",
      "startup-intent",wire,sizeof(wire))==EDR_ENFORCEMENT_TERMINAL_PRECREATE_EXISTING);
  /* Once safely reopened, an existing reservation still freezes its result
   * under ordinary-floor pressure. No source byte or ACK is rewritten. */
  assert(test_setenv("EDR_STORAGE_MIN_FREE_MB","4294967295")==0);
  assert(edr_storage_queue_enforcement_terminal_update("startup-owner","startup-source",wire,sizeof(wire),
      "startup-combined",wire,sizeof(wire))==EDR_OK);
  assert(terminal_journal_state_is(path,"startup-owner","ready"));
  assert_capacity_matches_inventory(path);
  assert(test_unsetenv("EDR_STORAGE_MIN_FREE_MB")==0);
  edr_storage_queue_close();assert(edr_storage_queue_open(path)==EDR_OK);
  assert(edr_storage_queue_test_startup_growth_bytes()==current);
  printf("startup physical: current=%llu migration=%llu visible=%llu bytes; refusal preserves frozen database\n",
      (unsigned long long)current,(unsigned long long)migration,(unsigned long long)image);
  edr_storage_queue_close();remove(path);
}

void edr_storage_queue_test_set_physical_available(uint64_t bytes);
static void test_runtime_physical_retry_ack_and_checkpoint(void) {
  char path[256],main_before[65],main_after[65],key[65];sqlite3 *reader=NULL;
  uint8_t wire[20],*large=malloc(32768u);EdrStorageQueueCapacityMetrics before,after;
  EdrStorageQueueP0SourceOnlyLatch latch;
  const uint8_t deferred[]={123,34,120,34,58,49,125};
  assert(large);make_large_wire(large,32768u,0xa9u);make_wire(wire,0xa8u);
  snprintf(path,sizeof(path),"edr-runtime-space-%ld.db",(long)TEST_PID);remove(path);
  assert(test_setenv("EDR_QUEUE_MAX_DB_MB","32")==0);
  assert(edr_storage_queue_open(path)==EDR_OK);
  assert(sqlite3_open(path,&reader)==SQLITE_OK);
  assert(sqlite3_db_config(reader,SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,1,NULL)==SQLITE_OK);
  assert(sqlite3_exec(reader,"BEGIN; SELECT count(*) FROM event_queue;",NULL,NULL,NULL)==SQLITE_OK);
  assert(edr_sha256_hex(deferred,sizeof(deferred),key)==0);
  assert(edr_storage_queue_p0_deferred_retain(key,1u,deferred,sizeof(deferred))==EDR_OK);
  assert(edr_storage_queue_enforcement_terminal_precreate("space-owner","space-event","space-rule","space-generation",
      "space-intent",wire,sizeof(wire))==EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED);
  unsigned inserted=0u;
  do {
    char batch[64];snprintf(batch,sizeof(batch),"space-event-%u",inserted++);
    assert(edr_storage_queue_enqueue(batch,large,32768u,0,1)==EDR_OK);
    edr_storage_queue_get_capacity_metrics(&before);
  } while(before.wal_bytes<6u*1024u*1024u && inserted<256u);
  assert(before.wal_bytes>=6u*1024u*1024u);
  assert(test_setenv("EDR_STORAGE_MIN_FREE_MB","4294967295")==0);
  assert(edr_storage_queue_p0_source_only_latch_prepare_local(&latch)!=EDR_OK);
  assert(edr_storage_queue_enforcement_terminal_precreate("space-new","space-new-event","space-rule","space-generation",
      "space-new-intent",wire,sizeof(wire))==EDR_ENFORCEMENT_TERMINAL_PRECREATE_ERROR);
  assert(edr_storage_queue_enforcement_terminal_update("space-owner","space-source",wire,sizeof(wire),
      "space-combined",wire,sizeof(wire))==EDR_OK);
  edr_storage_queue_get_capacity_metrics(&before);
  reset_send_state(0); /* Generic transport failure; HTTP 429 is covered at transport owner, not this stub. */
  for(unsigned i=0;i<4u;++i) {
    test_sleep_ms(210u);edr_storage_queue_poll_drain();
    assert(edr_storage_queue_p0_deferred_retry(key,"synthetic_retry")!=EDR_OK);
  }
  edr_storage_queue_get_capacity_metrics(&after);
  assert(after.wal_bytes==before.wal_bytes && after.db_bytes==before.db_bytes);
  assert(batch_retry_count(path,"space-event-0")==0);
  assert(sqlite_scalar_path(path,"SELECT intent_retry_count+source_retry_count+combined_retry_count FROM enforcement_terminal_journal WHERE idempotency_key='space-owner';")==0u);
  assert(sqlite_scalar_path(path,"SELECT count(*) FROM delivery_receipts_v1;")==0u);
  /* Even reserved completion must refuse real insufficient bytes. No ACK
   * witness or in-memory success may survive that refusal. */
  edr_storage_queue_test_set_physical_available(0u);reset_send_state(1);
  test_sleep_ms(210u);edr_storage_queue_poll_drain();
  assert(edr_storage_queue_pending_count()==inserted);
  assert(sqlite_scalar_path(path,"SELECT intent_acked+source_acked+combined_acked FROM enforcement_terminal_journal WHERE idempotency_key='space-owner';")==0u);
  assert(sqlite_scalar_path(path,"SELECT count(*) FROM delivery_receipts_v1;")==0u);
  edr_storage_queue_get_capacity_metrics(&after);assert(after.wal_bytes==before.wal_bytes);
  edr_storage_queue_test_set_physical_available(UINT64_MAX);
  assert(sqlite3_exec(reader,"ROLLBACK;",NULL,NULL,NULL)==SQLITE_OK);assert(sqlite3_close(reader)==SQLITE_OK);reader=NULL;
  synthetic_database_hash(path,main_before);
  /* Release the reader: a default auto/close checkpoint would now copy the
   * accumulated WAL into DB despite the ordinary floor. Guarded hooks defer it. */
  test_sleep_ms(210u);edr_storage_queue_poll_drain();
  assert(terminal_journal_state_is(path,"space-owner","completed"));
  assert(sqlite_scalar_path(path,"SELECT count(*) FROM delivery_receipts_v1;")>0u);
  assert(edr_storage_queue_p0_deferred_complete(key,NULL,NULL,0u,"complete_without_delivery")==EDR_OK);
  assert_capacity_matches_inventory(path);
  synthetic_database_hash(path,main_after);assert(!strcmp(main_before,main_after));
  edr_storage_queue_get_capacity_metrics(&after);
  assert(after.physical_admission_failures>before.physical_admission_failures);
  edr_storage_queue_close();synthetic_database_hash(path,main_after);assert(!strcmp(main_before,main_after));
  assert(test_unsetenv("EDR_STORAGE_MIN_FREE_MB")==0);
  assert(edr_storage_queue_open(path)==EDR_OK);assert_capacity_matches_inventory(path);
  assert(terminal_journal_state_is(path,"space-owner","completed"));
  printf("runtime physical: pinned_wal=%llu retry_wal_growth=0 denied_ack_receipts=0 reserved_completion=1 guarded_auto_close_checkpoint=1\n",(unsigned long long)before.wal_bytes);
  edr_storage_queue_close();remove(path);free(large);
  assert(test_unsetenv("EDR_QUEUE_MAX_DB_MB")==0);
}

int main(void) {
  char path[256];
  char old_path[256];
  char new_path[256];
  uint8_t wire_a[20], wire_b[20];
  snprintf(path, sizeof(path), "edr-storage-queue-%ld.db", (long)TEST_PID);
  (void)remove(path);
  assert(test_setenv("EDR_QUEUE_DRAIN_INTERVAL_MS", "200") == 0);
  assert(test_setenv("EDR_QUEUE_MAX_RETRIES", "1") == 0);
  test_startup_physical_migration_and_current_schema();
  test_runtime_physical_retry_ack_and_checkpoint();
  test_typed_local_rotation_and_owner_guards();
  test_typed_local_bounded_slices_and_pressure();
  test_typed_local_snapshot_busy_and_physical_guard();
  test_legacy_maintenance_bounded_slices();
  test_typed_local_query_snapshot();
  test_capacity_ledger_owner_transitions_and_rollback();
  test_retention_upgrade_preserves_legacy_identity();
  test_capacity_ledger_calibration_and_bounded_admission();
  test_exact_ack_receipt_atomic_recovery();
  test_missing_source_meta_preserves_owner_recovery();
  test_terminal_policy_hold_does_not_block_combined_alert();
  assert(edr_storage_queue_open(path) == EDR_OK);
  make_wire(wire_a, 1u);
  make_wire(wire_b, 9u);

  assert(edr_storage_queue_enqueue("exact", wire_a, sizeof(wire_a), 0, 1) == EDR_OK);
  assert(edr_storage_queue_enqueue("exact", wire_a, sizeof(wire_a), 0, 1) == EDR_OK);
  assert(edr_storage_queue_pending_count() == 1u);
  assert(edr_storage_queue_enqueue("exact", wire_b, sizeof(wire_b), 0, 1) != EDR_OK);
  assert(edr_storage_queue_enqueue("exact", wire_a, sizeof(wire_a), 1, 1) != EDR_OK);
  assert(edr_storage_queue_enqueue("exact", wire_a, sizeof(wire_a), 0,
                                   EDR_STORAGE_QUEUE_SEVERITY_P0_SOURCE_ONLY) != EDR_OK);

  assert(edr_storage_queue_enqueue("restart", wire_b, sizeof(wire_b), 0, 0) == EDR_OK);
  edr_storage_queue_close();
  assert(edr_storage_queue_enqueue("closed", wire_a, sizeof(wire_a), 0, 1) != EDR_OK);
  assert(edr_storage_queue_open(path) == EDR_OK);
  reset_send_state(1);
  test_sleep_ms(1100u);
  edr_storage_queue_poll_drain();
  assert(total_send_calls() == 2u && s_last_payload_len == sizeof(wire_b));
  assert(memcmp(s_last_payload, wire_b, sizeof(wire_b)) == 0);

  assert(edr_storage_queue_enqueue("p0-dead", wire_b, sizeof(wire_b), 0, 1) == EDR_OK);
  reset_send_state(0);
  test_sleep_ms(1100u);
  edr_storage_queue_poll_drain();
  test_sleep_ms(1100u);
  edr_storage_queue_poll_drain();
  assert(status_count(path, "dead_letter") == 1);

#if !defined(_WIN32)
  enum { workers = 20 };
  pthread_t threads[workers];
  EnqueueWork work[workers];
  for (unsigned i = 0u; i < workers; i++) {
    work[i].id = i + 32u;
    assert(pthread_create(&threads[i], NULL, enqueue_worker, &work[i]) == 0);
  }
  for (unsigned i = 0u; i < workers; i++) assert(pthread_join(threads[i], NULL) == 0);
  assert(edr_storage_queue_pending_count() >= workers);
  reset_send_state(1);
  test_sleep_ms(250u);
  pthread_t draining[workers];
  for (unsigned i = 0u; i < workers; i++) {
    assert(pthread_create(&draining[i], NULL, drain_worker, NULL) == 0);
  }
  for (unsigned i = 0u; i < workers; i++) assert(pthread_join(draining[i], NULL) == 0);
  for (unsigned i = 0u; i < workers; i++) assert(send_calls_for((uint8_t)(i + 32u)) <= 1u);
  for (unsigned round = 0u; round < 3u; round++) {
    test_sleep_ms(250u);
    edr_storage_queue_poll_drain();
  }
  for (unsigned i = 0u; i < workers; i++) assert(send_calls_for((uint8_t)(i + 32u)) == 1u);
  assert(total_send_calls() == workers);
  assert(edr_storage_queue_pending_count() == 0u);

  edr_storage_queue_close();
  snprintf(old_path, sizeof(old_path), "edr-storage-queue-old-%ld.db", (long)TEST_PID);
  snprintf(new_path, sizeof(new_path), "edr-storage-queue-new-%ld.db", (long)TEST_PID);
  (void)remove(old_path);
  (void)remove(new_path);
  assert(edr_storage_queue_open(old_path) == EDR_OK);
  assert(edr_storage_queue_enqueue("old-p0", wire_a, sizeof(wire_a), 0, 1) == EDR_OK);
  assert(batch_row_id(old_path, "old-p0") == 1);
  reset_send_state(1);
  block_next_send();
  test_sleep_ms(250u);
  pthread_t stale_drain;
  assert(pthread_create(&stale_drain, NULL, drain_worker, NULL) == 0);
  wait_for_send();
  edr_storage_queue_close();
  assert(edr_storage_queue_open(new_path) == EDR_OK);
  assert(edr_storage_queue_enqueue("new-p0", wire_b, sizeof(wire_b), 0, 1) == EDR_OK);
  assert(batch_row_id(new_path, "new-p0") == 1);
  release_send();
  assert(pthread_join(stale_drain, NULL) == 0);
  assert(status_count(new_path, "pending") == 1);
  assert(send_calls_for(1u) == 1u);
  test_sleep_ms(250u);
  edr_storage_queue_poll_drain();
  assert(edr_storage_queue_pending_count() == 0u);
  assert(send_calls_for(9u) == 1u);
  test_sleep_ms(250u);
  edr_storage_queue_poll_drain();
  assert(total_send_calls() == 2u);
  for (unsigned cycle = 0u; cycle < 4u; cycle++) {
    edr_storage_queue_close();
    assert(edr_storage_queue_open(new_path) == EDR_OK);
    assert(edr_storage_queue_pending_count() == 0u);
  }
  edr_storage_queue_close();
  (void)remove(old_path);
  (void)remove(new_path);
#endif
  edr_storage_queue_close();
  (void)remove(path);
  test_terminal_journal_durable_commits_and_exact_replay();
  test_terminal_rejection_allows_other_journals();
  test_retry_backoff_and_fairness_survive_reopen();
  test_queue_requires_bound_receipt_after_lost_response();
  test_event_selection_oom_preserves_durable_payload();
  test_retention_runs_while_transport_circuit_is_open();
  test_pinned_wal_is_visible_beyond_logical_budget();
  test_unconfigured_transport_preserves_retry_budget();
  test_budget_deferral_preserves_ordinary_retry_allowance();
  test_budget_deferral_preserves_terminal_frames();
  test_terminal_journal_recovery_and_independent_acks();
  test_terminal_selected_frame_retry_then_ack();
  test_terminal_selected_frame_allocation_failures_preserve_retry();
  test_terminal_selected_frame_invalid_durable_wire_fails();
  test_terminal_metadata_corruption_quarantines_without_starvation();
  test_terminal_failed_rows_release_reserved_capacity();
  test_terminal_corrupt_sql_text_never_matches_exact_replay();
  test_terminal_corrupt_owner_never_recreates_action();
  test_terminal_owner_digest_migration_and_unresolved_legacy_latch();
  test_event_queue_batch_metadata_corruption_quarantines_without_starvation();
  test_terminal_final_frames_survive_retry_limit_and_retention();
  test_terminal_journal_ordinary_ack_is_atomic_and_reconciles();
  test_terminal_journal_backpressure_cap();
  test_logical_capacity_recovers_and_reserves_terminal();
  test_source_only_capacity_is_distinct_and_bounded();
  test_queue_and_terminal_metric_denominators();
  test_zero_or_invalid_limit_remains_finite();
  test_local_v3_source_evidence_is_not_remote_ack();
  test_policy_hold_preserves_legacy_identity_and_latch();
  test_unknown_historical_wire_is_retained();
  test_local_v3_retention_has_bounded_backpressure();
  test_lowered_limit_preserves_overcapacity_evidence();
  test_p0_source_only_latch_persists_until_central_ack();
  test_p0_source_only_multiple_durable_rows_do_not_create_false_loss();
  test_p0_source_only_retry_retention_corruption_and_identity();
  test_p0_source_only_legacy_and_corrupt_meta_recover();
  test_p0_deferred_match_durable_lifecycle();
  test_p0_deferred_capacity_atomic_handoff();
  test_p0_deferred_retained_payload_cap();
#if !defined(_WIN32)
  test_terminal_journal_stale_generation_cannot_ack_reopened_row();
#endif
  test_terminal_local_reserved_bound_and_event_time();
  test_terminal_state_ledger_transaction_and_constant_read();
  return 0;
}
