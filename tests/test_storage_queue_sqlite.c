#include "edr/error.h"
#include "edr/storage_queue.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sqlite3.h>

#if !defined(_WIN32)
#include <pthread.h>
#include <unistd.h>
#endif

static int s_send_ok;
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
  s_send_calls = 0u;
  memset(s_send_value_calls, 0, sizeof(s_send_value_calls));
  s_last_payload_len = 0u;
}

static unsigned send_calls_for(uint8_t value) { return s_send_value_calls[value]; }
static unsigned total_send_calls(void) { return s_send_calls; }
#endif

int edr_ingest_http_configured(void) { return 1; }
int edr_ingest_http_circuit_open(void) { return 0; }
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
  free(churn);
#if !defined(_WIN32)
  s_send_calls++;
  if (payload_len >= 5u) s_send_value_calls[payload[4]]++;
  if (s_block_send) {
    s_send_started = 1;
    pthread_cond_broadcast(&s_send_cond);
    while (s_block_send) pthread_cond_wait(&s_send_cond, &s_send_lock);
  }
  int result = s_send_ok ? 0 : -1;
  pthread_mutex_unlock(&s_send_lock);
  return result;
#else
  s_send_calls++;
  if (payload_len >= 5u) s_send_value_calls[payload[4]]++;
  return s_send_ok ? 0 : -1;
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

static void terminal_journal_age_for_retention(const char *path, const char *key) {
  sqlite3 *db = NULL;
  sqlite3_stmt *st = NULL;
  assert(sqlite3_open(path, &db) == SQLITE_OK);
  assert(sqlite3_prepare_v2(
             db,
             "UPDATE enforcement_terminal_journal SET created_at=1,updated_at=1 "
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
  snprintf(path, sizeof(path), "/tmp/edr-terminal-journal-commit-%ld.db", (long)getpid());
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

static void test_terminal_journal_recovery_and_independent_acks(void) {
  char path[256];
  uint8_t intent[20], source[20], combined[20];
  snprintf(path, sizeof(path), "/tmp/edr-terminal-journal-recovery-%ld.db", (long)getpid());
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
  edr_storage_queue_close();
  (void)remove(path);
}

/* Exercise the selected terminal-frame handoff itself: the SQLite statement
 * is finalized before transport, a failed send records retry state, and a
 * later selected replay acknowledges both final durable frames. */
static void test_terminal_selected_frame_retry_then_ack(void) {
  char path[256];
  uint8_t intent[20], source[20], combined[20];
  snprintf(path, sizeof(path), "/tmp/edr-terminal-selected-frame-%ld.db", (long)getpid());
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
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0x75u) == 1u && send_calls_for(0x76u) == 1u);
  assert(terminal_journal_state_is(path, "selected-frame", "completed"));
  edr_storage_queue_close();
  (void)remove(path);
}

/* Each selected-frame copy allocation is transient. It must not turn a valid
 * durable final frame into `failed`: the state stays ready, the retry is
 * visible, and a later allocation-successful poll sends the same frame. */
static void test_terminal_selected_frame_allocation_failures_preserve_retry(void) {
  for (unsigned kind = 0u; kind < 3u; ++kind) {
    char path[256], key[64], intent_batch[64], source_batch[64], combined_batch[64];
    uint8_t intent[20], source[20], combined[20];
    EdrEnforcementTerminalJournalMetrics before, after;
    uint8_t intent_value = (uint8_t)(0x80u + kind);
    uint8_t source_value = (uint8_t)(0x90u + kind);
    uint8_t combined_value = (uint8_t)(0xa0u + kind);
    snprintf(path, sizeof(path), "/tmp/edr-terminal-select-alloc-%ld-%u.db",
             (long)getpid(), kind);
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
    assert(terminal_journal_frame_retry_count(path, key, 1) == 1);
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
  snprintf(path, sizeof(path), "/tmp/edr-terminal-invalid-wire-%ld.db", (long)getpid());
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
  snprintf(path, sizeof(path), "/tmp/edr-terminal-invalid-intent-%ld.db", (long)getpid());
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
    snprintf(path, sizeof(path), "/tmp/edr-terminal-empty-key-%ld.db", (long)getpid());
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
    snprintf(path, sizeof(path), "/tmp/edr-terminal-empty-source-batch-%ld.db", (long)getpid());
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

  snprintf(path, sizeof(path), "/tmp/edr-terminal-failed-reserve-%ld.db", (long)getpid());
  (void)remove(path);
  /* The five setup rows need more than the final 1 MiB terminal lane. Reopen
   * under that production-size cap to prove poisoned reservations cannot keep
   * capacity stranded. */
  assert(setenv("EDR_QUEUE_MAX_DB_MB", "2", 1) == 0);
  assert(setenv("EDR_QUEUE_DRAIN_MAX_ROWS", "8", 1) == 0);
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
  assert(setenv("EDR_QUEUE_MAX_DB_MB", "1", 1) == 0);

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
  assert(unsetenv("EDR_QUEUE_MAX_DB_MB") == 0);
  assert(unsetenv("EDR_QUEUE_DRAIN_MAX_ROWS") == 0);
}

/* Replay/update idempotency comparisons also read SQLite TEXT. A corrupt raw
 * value must not compare equal to its prefix through strcmp-style semantics. */
static void test_terminal_corrupt_sql_text_never_matches_exact_replay(void) {
  char path[256];
  uint8_t intent[20], source[20], combined[20];

  snprintf(path, sizeof(path), "/tmp/edr-terminal-raw-text-%ld.db", (long)getpid());
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

  snprintf(path, sizeof(path), "/tmp/edr-terminal-raw-update-%ld.db", (long)getpid());
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

  snprintf(path, sizeof(path), "/tmp/edr-terminal-owner-corrupt-%ld.db", (long)getpid());
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

  snprintf(valid_path, sizeof(valid_path), "/tmp/edr-terminal-owner-migrate-%ld.db", (long)getpid());
  snprintf(corrupt_path, sizeof(corrupt_path), "/tmp/edr-terminal-owner-unresolved-%ld.db",
           (long)getpid());
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
 * permanently consuming pending admission capacity or starving a later row. */
static void test_event_queue_batch_metadata_corruption_quarantines_without_starvation(void) {
  enum { large_wire_len = 200000 };
  char path[256];
  char producer_overlong[257];
  uint8_t valid_wire[20], transient_wire[20];
  uint8_t *large_wire;
  sqlite3_int64 nul_id, overlong_id;
  EdrStorageQueueCapacityMetrics before, after, after_reopen, after_transient;

  snprintf(path, sizeof(path), "/tmp/edr-event-queue-batch-metadata-%ld.db", (long)getpid());
  (void)remove(path);
  assert(setenv("EDR_QUEUE_MAX_DB_MB", "1", 1) == 0);
  assert(setenv("EDR_QUEUE_DRAIN_MAX_ROWS", "8", 1) == 0);
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
  assert(after.used_bytes == 0u);
  assert(before.used_bytes > after.used_bytes + 400000u);

  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  edr_storage_queue_get_capacity_metrics(&after_reopen);
  assert(after_reopen.used_bytes == 0u);
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

  /* Dead-letter audit payloads are excluded from logical admission, so a
   * later ordinary batch can admit despite their retained physical bytes. */
  assert(edr_storage_queue_enqueue("ordinary-after-quarantine", large_wire, large_wire_len, 0,
                                   EDR_STORAGE_QUEUE_SEVERITY_ORDINARY) == EDR_OK);
  edr_storage_queue_close();
  free(large_wire);
  (void)remove(path);
  assert(unsetenv("EDR_QUEUE_MAX_DB_MB") == 0);
  assert(unsetenv("EDR_QUEUE_DRAIN_MAX_ROWS") == 0);
}

/* Final terminal frames have a different failure contract from ordinary
 * telemetry: they are proof of an action that already ran.  The test suite
 * sets EDR_QUEUE_MAX_RETRIES=1, so two failed transports exercise retry
 * exhaustion, close/open recovery, retention cleanup, and later success. */
static void test_terminal_final_frames_survive_retry_limit_and_retention(void) {
  char path[256];
  uint8_t intent[20], source[20], combined[20];
  EdrEnforcementTerminalJournalMetrics metrics;
  snprintf(path, sizeof(path), "/tmp/edr-terminal-journal-final-retry-%ld.db", (long)getpid());
  (void)remove(path);
  make_wire(intent, 0xa1u);
  make_wire(source, 0xa2u);
  make_wire(combined, 0xa3u);
  assert(setenv("EDR_QUEUE_RETENTION_HOURS", "1", 1) == 0);
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

  /* A completed terminal never replays on restart; the action was owned by
   * the precreated journal record and no re-execution path is involved. */
  edr_storage_queue_close();
  assert(edr_storage_queue_open(path) == EDR_OK);
  reset_send_state(1);
  edr_storage_queue_poll_drain();
  assert(total_send_calls() == 0u);
  edr_storage_queue_close();
  (void)remove(path);
}

static void test_terminal_journal_ordinary_ack_is_atomic_and_reconciles(void) {
  char path[256];
  uint8_t intent[20], source[20], combined[20];
  int source_acked, combined_acked;
  EdrEnforcementTerminalJournalMetrics metrics;
  snprintf(path, sizeof(path), "/tmp/edr-terminal-journal-ack-%ld.db", (long)getpid());
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
  snprintf(path, sizeof(path), "/tmp/edr-terminal-journal-cap-%ld.db", (long)getpid());
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
  snprintf(path, sizeof(path), "/tmp/edr-storage-queue-capacity-%ld.db", (long)getpid());
  (void)remove(path);
  assert(setenv("EDR_QUEUE_MAX_DB_MB", "1", 1) == 0);
  assert(setenv("EDR_QUEUE_DRAIN_MAX_ROWS", "128", 1) == 0);
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
#if !defined(_WIN32)
  usleep(250000u);
#endif
  edr_storage_queue_poll_drain();
  assert(edr_storage_queue_pending_count() == 0u);
  edr_storage_queue_get_capacity_metrics(&after_drain);
  assert(after_drain.accounting_available == 1u);
  assert(after_drain.used_bytes == 0u);
  /* Physical sidecars may remain allocated, which is precisely why they are
   * only diagnostics; a fresh ordinary event must be accepted now. */
  assert(edr_storage_queue_enqueue("capacity-after-drain", large_wire, 65536u, 0, 0) == EDR_OK);
  reset_send_state(1);
#if !defined(_WIN32)
  usleep(250000u);
#endif
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
  assert(unsetenv("EDR_QUEUE_MAX_DB_MB") == 0);
  assert(unsetenv("EDR_QUEUE_DRAIN_MAX_ROWS") == 0);
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
  snprintf(path, sizeof(path), "/tmp/edr-storage-queue-source-capacity-%ld.db", (long)getpid());
  (void)remove(path);
  assert(setenv("EDR_QUEUE_MAX_DB_MB", "1", 1) == 0);
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
  assert(unsetenv("EDR_QUEUE_MAX_DB_MB") == 0);
}

static void test_p0_source_only_latch_persists_until_central_ack(void) {
  char path[256];
  uint8_t wire[20];
  EdrStorageQueueP0SourceOnlyLatch latch;
  EdrStorageQueueP0SourceOnlyLatch wrong;
  snprintf(path, sizeof(path), "/tmp/edr-source-only-latch-%ld.db", (long)getpid());
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
  snprintf(path, sizeof(path), "/tmp/edr-source-only-retention-%ld.db", (long)getpid());
  snprintf(recreated_path, sizeof(recreated_path), "/tmp/edr-source-only-recreated-%ld.db",
           (long)getpid());
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
                   "UPDATE event_queue SET retry_count=9223372036854775807 "
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
                   "UPDATE event_queue SET created_at=1 WHERE batch_id='source-only-retained-batch';");
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
  snprintf(legacy_path, sizeof(legacy_path), "/tmp/edr-source-only-legacy-%ld.db", (long)getpid());
  snprintf(corrupt_path, sizeof(corrupt_path), "/tmp/edr-source-only-meta-corrupt-%ld.db",
           (long)getpid());
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
  snprintf(path, sizeof(path), "/tmp/edr-storage-queue-metrics-%ld.db", (long)getpid());
  (void)remove(path);
  assert(setenv("EDR_QUEUE_MAX_DB_MB", "1", 1) == 0);
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
  assert(unsetenv("EDR_QUEUE_MAX_DB_MB") == 0);
}

static void test_unbounded_queue_reports_no_utilization_percentage(void) {
  char path[256];
  uint8_t wire[20];
  EdrStorageQueueCapacityMetrics metrics;
  snprintf(path, sizeof(path), "/tmp/edr-storage-queue-unbounded-%ld.db", (long)getpid());
  (void)remove(path);
  assert(unsetenv("EDR_QUEUE_MAX_DB_MB") == 0);
  make_wire(wire, 0xf4u);
  assert(edr_storage_queue_open(path) == EDR_OK);
  assert(edr_storage_queue_enqueue("unbounded", wire, sizeof(wire), 0,
                                   EDR_STORAGE_QUEUE_SEVERITY_ORDINARY) == EDR_OK);
  edr_storage_queue_get_capacity_metrics(&metrics);
  assert(metrics.accounting_available == 1u);
  assert(metrics.max_bytes == 0u);
  /* max_bytes=0 means capacity is disabled, not a 0% full bounded queue. */
  assert(metrics.utilization_bps == 0u);
  assert(metrics.pending_rows == 1u && metrics.oldest_pending_created_unix_s > 0u);
  edr_storage_queue_close();
  (void)remove(path);
}

#if !defined(_WIN32)
static void test_terminal_journal_stale_generation_cannot_ack_reopened_row(void) {
  char old_path[256];
  char new_path[256];
  uint8_t intent[20];
  pthread_t stale_drain;
  snprintf(old_path, sizeof(old_path), "/tmp/edr-terminal-journal-old-%ld.db", (long)getpid());
  snprintf(new_path, sizeof(new_path), "/tmp/edr-terminal-journal-new-%ld.db", (long)getpid());
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
  usleep(250000u);
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

  usleep(250000u);
  edr_storage_queue_poll_drain();
  assert(send_calls_for(0x81u) == 2u);
  assert(terminal_journal_intent_acked(new_path, "same-terminal-key") == 1);
  edr_storage_queue_close();
  (void)remove(old_path);
  (void)remove(new_path);
}
#endif

int main(void) {
  char path[256];
  char old_path[256];
  char new_path[256];
  uint8_t wire_a[20], wire_b[20];
  snprintf(path, sizeof(path), "/tmp/edr-storage-queue-%ld.db", (long)getpid());
  (void)remove(path);
  assert(setenv("EDR_QUEUE_DRAIN_INTERVAL_MS", "200", 1) == 0);
  assert(setenv("EDR_QUEUE_MAX_RETRIES", "1", 1) == 0);
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
#if !defined(_WIN32)
  usleep(1100000u);
#endif
  edr_storage_queue_poll_drain();
  assert(total_send_calls() == 2u && s_last_payload_len == sizeof(wire_b));
  assert(memcmp(s_last_payload, wire_b, sizeof(wire_b)) == 0);

  assert(edr_storage_queue_enqueue("p0-dead", wire_b, sizeof(wire_b), 0, 1) == EDR_OK);
  reset_send_state(0);
#if !defined(_WIN32)
  usleep(1100000u);
#endif
  edr_storage_queue_poll_drain();
#if !defined(_WIN32)
  usleep(1100000u);
#endif
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
  usleep(250000u);
  pthread_t draining[workers];
  for (unsigned i = 0u; i < workers; i++) {
    assert(pthread_create(&draining[i], NULL, drain_worker, NULL) == 0);
  }
  for (unsigned i = 0u; i < workers; i++) assert(pthread_join(draining[i], NULL) == 0);
  for (unsigned i = 0u; i < workers; i++) assert(send_calls_for((uint8_t)(i + 32u)) <= 1u);
  for (unsigned round = 0u; round < 3u; round++) {
    usleep(250000u);
    edr_storage_queue_poll_drain();
  }
  for (unsigned i = 0u; i < workers; i++) assert(send_calls_for((uint8_t)(i + 32u)) == 1u);
  assert(total_send_calls() == workers);
  assert(edr_storage_queue_pending_count() == 0u);

  edr_storage_queue_close();
  snprintf(old_path, sizeof(old_path), "/tmp/edr-storage-queue-old-%ld.db", (long)getpid());
  snprintf(new_path, sizeof(new_path), "/tmp/edr-storage-queue-new-%ld.db", (long)getpid());
  (void)remove(old_path);
  (void)remove(new_path);
  assert(edr_storage_queue_open(old_path) == EDR_OK);
  assert(edr_storage_queue_enqueue("old-p0", wire_a, sizeof(wire_a), 0, 1) == EDR_OK);
  assert(batch_row_id(old_path, "old-p0") == 1);
  reset_send_state(1);
  block_next_send();
  usleep(250000u);
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
  usleep(250000u);
  edr_storage_queue_poll_drain();
  assert(edr_storage_queue_pending_count() == 0u);
  assert(send_calls_for(9u) == 1u);
  usleep(250000u);
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
  test_unbounded_queue_reports_no_utilization_percentage();
  test_p0_source_only_latch_persists_until_central_ack();
  test_p0_source_only_retry_retention_corruption_and_identity();
  test_p0_source_only_legacy_and_corrupt_meta_recover();
#if !defined(_WIN32)
  test_terminal_journal_stale_generation_cannot_ack_reopened_row();
#endif
  return 0;
}
