#include "edr/storage_queue.h"

#include "edr/ingest_http.h"
#include "edr/sha256.h"
#include "edr/time_util.h"
#include "edr/transport_sink.h"
#include "edr/transport_v2.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>

#if defined(EDR_HAVE_SQLITE)
#include <sqlite3.h>
#include <sys/stat.h>
#if defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>
#if defined(_MSC_VER)
#include <stdlib.h>
#endif
#else
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <pthread.h>
#include <unistd.h>
#endif

static sqlite3 *s_db;
static char s_path[512];
static char s_lock_path[600];
static uint64_t s_pending;
static uint64_t s_terminal_pending;
static uint64_t s_terminal_backpressure;
static uint64_t s_terminal_failed;
static uint64_t s_terminal_precreate_requests;
static uint64_t s_terminal_precreate_attempts;
static uint64_t s_terminal_precreate_created;
static uint64_t s_terminal_precreate_existing;
static uint64_t s_terminal_precreate_conflicts;
static uint64_t s_terminal_precreate_rejected;
static uint64_t s_terminal_precreate_transaction_failures;
static uint64_t s_terminal_precreate_commit_failures;
static uint64_t s_terminal_precreate_metadata_corruption_failures;
static uint64_t s_terminal_outcome_unknown;
static uint64_t s_terminal_replay_selection_transient_failures;
static uint64_t s_terminal_replay_metadata_corruption_failures;
enum {
  EDR_TERMINAL_SELECT_ALLOC_KEY = 0,
  EDR_TERMINAL_SELECT_ALLOC_BATCH_ID = 1,
  EDR_TERMINAL_SELECT_ALLOC_WIRE = 2,
  EDR_TERMINAL_SELECT_ALLOC_COUNT = 3
};
#ifdef EDR_STORAGE_QUEUE_TESTING
static unsigned s_test_terminal_commit_failures;
static unsigned s_test_terminal_ack_step_failures;
static unsigned s_test_terminal_select_alloc_failures[EDR_TERMINAL_SELECT_ALLOC_COUNT];
static int s_test_terminal_commit_active;
static unsigned s_test_enqueue_commit_failures;
static int s_test_enqueue_commit_active;
static unsigned s_test_p0_latch_commit_failures;
static int s_test_p0_latch_commit_active;
static unsigned s_test_p0_deferred_commit_failures;
static int s_test_p0_deferred_commit_active;

/* SQLite invokes this synchronously during COMMIT. Returning nonzero makes
 * SQLite abort the actual commit and roll the transaction back, exercising
 * the same error path as a VFS/durable-storage commit failure. */
static int terminal_journal_test_commit_hook(void *opaque) {
  (void)opaque;
  if (s_test_terminal_commit_active && s_test_terminal_commit_failures > 0u) {
    s_test_terminal_commit_failures--;
    return 1;
  }
  if (s_test_enqueue_commit_active && s_test_enqueue_commit_failures > 0u) {
    s_test_enqueue_commit_failures--;
    return 1;
  }
  if (s_test_p0_latch_commit_active && s_test_p0_latch_commit_failures > 0u) {
    s_test_p0_latch_commit_failures--;
    return 1;
  }
  if (s_test_p0_deferred_commit_active && s_test_p0_deferred_commit_failures > 0u) {
    s_test_p0_deferred_commit_failures--;
    return 1;
  }
  return 0;
}
#endif
static uint64_t s_max_db_bytes;
static uint32_t s_cfg_max_db_mb;
static uint32_t s_cfg_retention_hours;
static uint64_t s_capacity_ordinary_rejected;
static uint64_t s_capacity_high_priority_rejected;
static uint64_t s_capacity_p0_source_only_rejected;
static uint64_t s_enqueue_requests;
static uint64_t s_enqueue_reused;
static uint64_t s_enqueue_conflicts;
static uint64_t s_enqueue_admission_attempts;
static uint64_t s_enqueue_admitted;
static uint64_t s_enqueue_capacity_rejected;
static uint64_t s_enqueue_transaction_failures;
static uint64_t s_enqueue_commit_failures;
static uint64_t s_delivery_selected;
static uint64_t s_delivery_sent;
static uint64_t s_delivery_acked;
static uint64_t s_delivery_requeued;
static uint64_t s_delivery_failed;
static uint64_t s_event_queue_metadata_corruption_failures;
static uint64_t s_retention_evicted_rows;
static uint64_t s_last_cleanup_ns;
static uint64_t s_legacy_drop_log_until_ns;
static uint64_t s_legacy_drop_suppressed;
/* Each successful open owns a distinct generation. Drain sends are deliberately
 * outside s_queue_state_lock, so acknowledgements must prove that they still
 * belong to this exact open database before changing durable state. */
static uint64_t s_db_generation;
static uint64_t s_drain_generation;
static uint64_t s_last_drain_ns;
#define EDR_ENFORCEMENT_TERMINAL_MAX_PENDING 1024u
static int exec_simple(sqlite3 *db, const char *sql);
static void queue_lock_release(void);
static void terminal_journal_refresh_locked(void);
static int terminal_journal_begin_durable_locked(void);
static int terminal_journal_end_durable_locked(int commit);
static int terminal_journal_ack_batch_id_locked(sqlite3 *db, const char *batch_id);
static int terminal_journal_batch_exists_locked(sqlite3 *db, const char *batch_id);
static int terminal_journal_reconcile_completed_locked(void);
static int queue_p0_latch_begin_durable_locked(void);
static int queue_p0_latch_end_durable_locked(int commit);
static int queue_meta_ack_source_batch_locked(sqlite3 *db, const char *batch_id);
static int queue_meta_quarantine_source_only_locked(sqlite3_int64 id, const char *reason);
static void queue_meta_mark_clean_before_close_locked(void);
#if defined(_WIN32)
static SRWLOCK s_queue_state_lock = SRWLOCK_INIT;
static void queue_state_lock(void) { AcquireSRWLockExclusive(&s_queue_state_lock); }
static void queue_state_unlock(void) { ReleaseSRWLockExclusive(&s_queue_state_lock); }
#else
static pthread_mutex_t s_queue_state_lock = PTHREAD_MUTEX_INITIALIZER;
static void queue_state_lock(void) { pthread_mutex_lock(&s_queue_state_lock); }
static void queue_state_unlock(void) { pthread_mutex_unlock(&s_queue_state_lock); }
#endif
#if defined(_WIN32)
static HANDLE s_lock_handle = INVALID_HANDLE_VALUE;
#else
static int s_lock_fd = -1;
#endif

void edr_storage_queue_configure(uint32_t max_db_mb, uint32_t retention_hours) {
  queue_state_lock();
  s_cfg_max_db_mb = max_db_mb;
  s_cfg_retention_hours = retention_hours;
  queue_state_unlock();
}

static int max_retry_limit(void) {
  static int cached = -999;
  if (cached != -999) {
    return cached;
  }
  const char *e = getenv("EDR_QUEUE_MAX_RETRIES");
  if (!e || !e[0]) {
    cached = 100;
  } else {
    cached = atoi(e);
    if (cached < 0) {
      cached = 0;
    }
  }
  return cached;
}

static void load_queue_db_limit(void) {
  s_max_db_bytes = 0;
  const char *e = getenv("EDR_QUEUE_MAX_DB_MB");
  if (!e || !e[0]) {
    if (s_cfg_max_db_mb == 0u) {
      return;
    }
    s_max_db_bytes = (uint64_t)s_cfg_max_db_mb * 1024ULL * 1024ULL;
    return;
  }
  unsigned long mb = strtoul(e, NULL, 10);
  if (mb == 0 || mb > 65535UL) {
    return;
  }
  s_max_db_bytes = mb * 1024UL * 1024UL;
}

static uint64_t queue_file_size_bytes(const char *path) {
  if (!path || !path[0]) return 0u;
#if defined(_WIN32) && defined(_MSC_VER)
  {
    struct __stat64 stbuf;
    return _stat64(path, &stbuf) == 0 && stbuf.st_size > 0 ?
        (uint64_t)stbuf.st_size : 0u;
  }
#else
  {
    struct stat stbuf;
    return stat(path, &stbuf) == 0 && stbuf.st_size > 0 ?
        (uint64_t)stbuf.st_size : 0u;
  }
#endif
}

static uint64_t queue_add_bytes(uint64_t total, uint64_t value) {
  return UINT64_MAX - total < value ? UINT64_MAX : total + value;
}

#define EDR_QUEUE_EVENT_LOGICAL_OVERHEAD 512ULL
#define EDR_P0_DEFERRED_LOGICAL_OVERHEAD 512ULL
#define EDR_P0_DEFERRED_REASON_RESERVE_BYTES 255ULL
#define EDR_TERMINAL_LOGICAL_OVERHEAD 1024ULL
#define EDR_TERMINAL_FRAME_MAX_BYTES (65536ULL + 16ULL)
#define EDR_TERMINAL_TEXT_MAX_BYTES 255u
#define EDR_TERMINAL_OWNER_DIGEST_HEX_LEN 64u
/* Intent and final records are serialized by p0_rule_direct_emit into one
 * BAT1 frame each. Keep the terminal recovery reservation tied to that
 * bounded wire contract rather than to SQLite's non-reclaiming file size. */
#define EDR_TERMINAL_INTENT_RESERVE_BYTES (EDR_TERMINAL_FRAME_MAX_BYTES + 255ULL)
/* p0_rule_direct_emit serializes each final BAT1 into a 65536+16 byte buffer;
 * batch IDs are bounded by terminal_text_valid (255 bytes). Reserving both
 * final frames before execution prevents an ordinary backlog from consuming
 * their only durable recovery space. */
#define EDR_TERMINAL_FINAL_RESERVE_BYTES \
  (2ULL * (EDR_TERMINAL_FRAME_MAX_BYTES + 255ULL))
#define EDR_TERMINAL_CRITICAL_RESERVE_MIN \
  (EDR_TERMINAL_LOGICAL_OVERHEAD + EDR_TERMINAL_INTENT_RESERVE_BYTES + \
   EDR_TERMINAL_FINAL_RESERVE_BYTES + 4096ULL)
#define EDR_P0_SOURCE_ONLY_RETRY_RESERVE_SLOTS 8ULL
#define EDR_P0_SOURCE_ONLY_RESERVE_MIN \
  (EDR_P0_SOURCE_ONLY_RETRY_RESERVE_SLOTS * \
   (EDR_QUEUE_EVENT_LOGICAL_OVERHEAD + EDR_TERMINAL_FRAME_MAX_BYTES + 255ULL))
/* Legacy builds used these SQLite-header bits. They are read once during the
 * queue_meta upgrade only; no current path writes or trusts either header. */
#define EDR_QUEUE_P0_SOURCE_ONLY_LEGACY_LATCH_BIT UINT32_C(0x40000000)

#define EDR_QUEUE_META_STATE_CLEAR "clear"
#define EDR_QUEUE_META_STATE_PREPARED "prepared"
#define EDR_QUEUE_META_STATE_BOUND "bound"
#define EDR_QUEUE_META_STATE_RECOVERY_REQUIRED "recovery_required"
#define EDR_QUEUE_META_SESSION_CLEAN "clean"
#define EDR_QUEUE_META_SESSION_OPEN "open"
#define EDR_QUEUE_META_ERROR_MAX 96u

typedef enum QueueCapacityPriority {
  QUEUE_CAPACITY_ORDINARY = 0,
  QUEUE_CAPACITY_TERMINAL = 1,
  QUEUE_CAPACITY_P0_SOURCE_ONLY = 2
} QueueCapacityPriority;

static uint64_t queue_terminal_reserve_bytes(void) {
  uint64_t reserve;
  if (s_max_db_bytes == 0u) return 0u;
  reserve = s_max_db_bytes / 8u;
  /* The ordinary ceiling must leave room for one full terminal intent plus
   * both final frames. Otherwise a full ordinary queue can still authorize an
   * action but fail to preserve its result. */
  if (reserve < EDR_TERMINAL_CRITICAL_RESERVE_MIN) {
    reserve = EDR_TERMINAL_CRITICAL_RESERVE_MIN;
  }
  if (reserve > 4u * 1024u * 1024u) reserve = 4u * 1024u * 1024u;
  if (reserve >= s_max_db_bytes) reserve = s_max_db_bytes / 2u;
  return reserve;
}

/* A P0 source-only disposition is the final durable assertion available when
 * a collector/ruleset capability cannot prove a rule hit.  Terminal records
 * have their own reservation, so reserve a separate bounded lane here: a
 * terminal backlog may use its lane but cannot consume this one. */
static uint64_t queue_p0_source_only_reserve_bytes(uint64_t terminal_reserve) {
  uint64_t available;
  uint64_t reserve;
  if (s_max_db_bytes == 0u || terminal_reserve >= s_max_db_bytes) return 0u;
  available = s_max_db_bytes - terminal_reserve;
  reserve = EDR_P0_SOURCE_ONLY_RESERVE_MIN;
  /* Keep at least half of the post-terminal space available to ordinary
   * traffic. Configured limits are whole MiB, but this makes the arithmetic
   * safe for a future smaller test/configuration value too. */
  if (reserve > available / 2u) reserve = available / 2u;
  return reserve;
}

static int queue_sql_sum_locked(const char *sql, uint64_t *out) {
  sqlite3_stmt *st = NULL;
  sqlite3_int64 value;
  int rc;
  if (!s_db || !sql || !out || sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    return 0;
  }
  rc = sqlite3_step(st);
  if (rc != SQLITE_ROW) {
    sqlite3_finalize(st);
    return 0;
  }
  value = sqlite3_column_int64(st, 0);
  sqlite3_finalize(st);
  if (value < 0) return 0;
  *out = (uint64_t)value;
  return 1;
}

static int queue_logical_live_bytes_locked(uint64_t *out) {
  static const char event_sql[] =
      "SELECT COALESCE(SUM(length(batch_id)+length(payload)+512),0) "
      "FROM event_queue WHERE status='pending';";
  static const char terminal_sql[] =
      "SELECT COALESCE(SUM("
      "length(idempotency_key)+length(source_event_key)+length(rule_id)+"
      "length(process_generation_key)+length(state)+length(intent_batch_id)+"
      "COALESCE(length(intent_wire),0)+1024+"
      "CASE WHEN length(source_batch_id)+COALESCE(length(source_wire),0)+"
      "length(combined_batch_id)+COALESCE(length(combined_wire),0)>reserved_bytes "
      "THEN length(source_batch_id)+COALESCE(length(source_wire),0)+"
      "length(combined_batch_id)+COALESCE(length(combined_wire),0) "
      "ELSE reserved_bytes END),0) FROM enforcement_terminal_journal;";
  static const char deferred_sql[] =
      "SELECT COALESCE(SUM(length(key_sha256)+length(payload_sha256)+"
      "COALESCE(length(payload),0)+512+CASE WHEN state='completed' "
      "THEN length(terminal_reason) ELSE 255 END),0) "
      "FROM p0_deferred_match;";
  uint64_t events;
  uint64_t terminals;
  uint64_t deferred;
  if (!out || !queue_sql_sum_locked(event_sql, &events) ||
      !queue_sql_sum_locked(terminal_sql, &terminals) ||
      !queue_sql_sum_locked(deferred_sql, &deferred)) {
    return 0;
  }
  *out = queue_add_bytes(queue_add_bytes(events, terminals), deferred);
  return *out != UINT64_MAX;
}

static uint32_t queue_utilization_bps(uint64_t used, uint64_t max) {
  uint64_t whole;
  uint64_t remainder;
  uint64_t bps;
  uint64_t fractional;
  if (max == 0u) return 0u;
  whole = used / max;
  remainder = used % max;
  bps = whole >= UINT32_MAX / 10000u ? UINT32_MAX : whole * 10000u;
  fractional = remainder >= UINT64_MAX / 10000u ? UINT32_MAX :
      (remainder * 10000u) / max;
  if (UINT32_MAX - bps < fractional) return UINT32_MAX;
  bps += fractional;
  return bps > UINT32_MAX ? UINT32_MAX : (uint32_t)bps;
}

static int queue_pending_inventory_locked(uint64_t *rows, uint64_t *oldest_created) {
  sqlite3_stmt *st = NULL;
  sqlite3_int64 count;
  sqlite3_int64 oldest;
  if (!rows || !oldest_created || !s_db ||
      sqlite3_prepare_v2(
          s_db,
          "SELECT COUNT(*),COALESCE(MIN(created_at),0) FROM event_queue WHERE status='pending';",
          -1, &st, NULL) != SQLITE_OK) {
    return 0;
  }
  if (sqlite3_step(st) != SQLITE_ROW) {
    sqlite3_finalize(st);
    return 0;
  }
  count = sqlite3_column_int64(st, 0);
  oldest = sqlite3_column_int64(st, 1);
  sqlite3_finalize(st);
  *rows = count > 0 ? (uint64_t)count : 0u;
  *oldest_created = oldest > 0 ? (uint64_t)oldest : 0u;
  return 1;
}

static int p0_deferred_inventory_locked(uint64_t *pending, uint64_t *failed) {
  sqlite3_stmt *st = NULL;
  sqlite3_int64 pending_value;
  sqlite3_int64 failed_value;
  if (!pending || !failed || !s_db ||
      sqlite3_prepare_v2(
          s_db,
          "SELECT COALESCE(SUM(state='pending'),0),COALESCE(SUM(state='failed'),0) "
          "FROM p0_deferred_match;",
          -1, &st, NULL) != SQLITE_OK) {
    return 0;
  }
  if (sqlite3_step(st) != SQLITE_ROW) {
    sqlite3_finalize(st);
    return 0;
  }
  pending_value = sqlite3_column_int64(st, 0);
  failed_value = sqlite3_column_int64(st, 1);
  sqlite3_finalize(st);
  *pending = pending_value > 0 ? (uint64_t)pending_value : 0u;
  *failed = failed_value > 0 ? (uint64_t)failed_value : 0u;
  return 1;
}

static int queue_capacity_snapshot_locked(EdrStorageQueueCapacityMetrics *out) {
  char wal_path[sizeof(s_path) + 8u];
  char shm_path[sizeof(s_path) + 8u];
  int n;
  if (!out) return 0;
  memset(out, 0, sizeof(*out));
  out->max_bytes = s_max_db_bytes;
  out->terminal_reserve_bytes = queue_terminal_reserve_bytes();
  out->p0_source_only_reserve_bytes =
      queue_p0_source_only_reserve_bytes(out->terminal_reserve_bytes);
  out->critical_reserve_bytes =
      queue_add_bytes(out->terminal_reserve_bytes, out->p0_source_only_reserve_bytes);
  out->ordinary_limit_bytes = s_max_db_bytes > out->critical_reserve_bytes ?
      s_max_db_bytes - out->critical_reserve_bytes : 0u;
  out->ordinary_rejected = s_capacity_ordinary_rejected;
  out->high_priority_rejected = s_capacity_high_priority_rejected;
  out->p0_source_only_rejected = s_capacity_p0_source_only_rejected;
  out->enqueue_requests = s_enqueue_requests;
  out->enqueue_reused = s_enqueue_reused;
  out->enqueue_conflicts = s_enqueue_conflicts;
  out->enqueue_admission_attempts = s_enqueue_admission_attempts;
  out->enqueue_admitted = s_enqueue_admitted;
  out->enqueue_capacity_rejected = s_enqueue_capacity_rejected;
  out->enqueue_transaction_failures = s_enqueue_transaction_failures;
  out->enqueue_commit_failures = s_enqueue_commit_failures;
  out->delivery_selected = s_delivery_selected;
  out->delivery_sent = s_delivery_sent;
  out->delivery_acked = s_delivery_acked;
  out->delivery_requeued = s_delivery_requeued;
  out->delivery_failed = s_delivery_failed;
  out->event_queue_metadata_corruption_failures =
      s_event_queue_metadata_corruption_failures;
  out->retention_evicted_rows = s_retention_evicted_rows;
  if (!s_path[0]) return 0;
  out->db_bytes = queue_file_size_bytes(s_path);
  n = snprintf(wal_path, sizeof(wal_path), "%s-wal", s_path);
  if (n > 0 && (size_t)n < sizeof(wal_path)) {
    out->wal_bytes = queue_file_size_bytes(wal_path);
  }
  n = snprintf(shm_path, sizeof(shm_path), "%s-shm", s_path);
  if (n > 0 && (size_t)n < sizeof(shm_path)) {
    out->shm_bytes = queue_file_size_bytes(shm_path);
  }
  out->physical_bytes = queue_add_bytes(queue_add_bytes(out->db_bytes, out->wal_bytes),
                                        out->shm_bytes);
  if (!queue_logical_live_bytes_locked(&out->used_bytes) ||
      !queue_pending_inventory_locked(&out->pending_rows, &out->oldest_pending_created_unix_s) ||
      !p0_deferred_inventory_locked(&out->p0_deferred_pending_rows,
                                    &out->p0_deferred_failed_rows)) {
    return 0;
  }
  if (out->oldest_pending_created_unix_s > 0u) {
    time_t now = time(NULL);
    if (now > 0 && (uint64_t)now > out->oldest_pending_created_unix_s) {
      out->oldest_pending_age_s = (uint64_t)now - out->oldest_pending_created_unix_s;
    }
  }
  out->utilization_bps = queue_utilization_bps(out->used_bytes, out->max_bytes);
  out->accounting_available = 1u;
  return 1;
}

static uint64_t queue_event_live_cost(const char *batch_id, size_t payload_len) {
  uint64_t total = EDR_QUEUE_EVENT_LOGICAL_OVERHEAD;
  total = queue_add_bytes(total, batch_id ? (uint64_t)strlen(batch_id) : 0u);
  return queue_add_bytes(total, (uint64_t)payload_len);
}

static uint64_t p0_deferred_live_cost(size_t payload_len) {
  uint64_t total = EDR_P0_DEFERRED_LOGICAL_OVERHEAD;
  total = queue_add_bytes(total, EDR_STORAGE_QUEUE_P0_DEFERRED_KEY_HEX_LEN);
  total = queue_add_bytes(total, EDR_STORAGE_QUEUE_P0_DEFERRED_KEY_HEX_LEN);
  total = queue_add_bytes(total, (uint64_t)payload_len);
  /* Pending/failed rows reserve the largest bounded retry/failure reason so
   * a later state transition cannot grow beyond its original admission. */
  return queue_add_bytes(total, EDR_P0_DEFERRED_REASON_RESERVE_BYTES);
}

static uint64_t queue_terminal_precreate_live_cost(const char *idempotency_key,
                                                    const char *source_event_key,
                                                    const char *rule_id,
                                                    const char *process_generation_key,
                                                    const char *intent_batch_id,
                                                    size_t intent_wire_len) {
  uint64_t total = EDR_TERMINAL_LOGICAL_OVERHEAD;
  total = queue_add_bytes(total, (uint64_t)strlen(idempotency_key));
  total = queue_add_bytes(total, (uint64_t)strlen(source_event_key));
  total = queue_add_bytes(total, (uint64_t)strlen(rule_id));
  total = queue_add_bytes(total, (uint64_t)strlen(process_generation_key));
  total = queue_add_bytes(total, (uint64_t)strlen(intent_batch_id));
  total = queue_add_bytes(total, (uint64_t)intent_wire_len);
  return queue_add_bytes(total, EDR_TERMINAL_FINAL_RESERVE_BYTES);
}

static uint64_t queue_terminal_final_live_cost(const char *source_batch_id,
                                                size_t source_wire_len,
                                                const char *combined_batch_id,
                                                size_t combined_wire_len) {
  uint64_t total = source_batch_id ? (uint64_t)strlen(source_batch_id) : 0u;
  total = queue_add_bytes(total, (uint64_t)source_wire_len);
  total = queue_add_bytes(total, combined_batch_id ? (uint64_t)strlen(combined_batch_id) : 0u);
  return queue_add_bytes(total, (uint64_t)combined_wire_len);
}

static int queue_capacity_admit_locked(uint64_t incoming, QueueCapacityPriority priority) {
  EdrStorageQueueCapacityMetrics capacity;
  uint64_t limit;
  if (!queue_capacity_snapshot_locked(&capacity)) {
    if (priority == QUEUE_CAPACITY_P0_SOURCE_ONLY) s_capacity_p0_source_only_rejected++;
    else if (priority == QUEUE_CAPACITY_TERMINAL) s_capacity_high_priority_rejected++;
    else s_capacity_ordinary_rejected++;
    fprintf(stderr, "[queue] logical capacity accounting unavailable; enqueue denied priority=%d\n",
            (int)priority);
    return 0;
  }
  if (s_max_db_bytes == 0u) return 1;
  if (priority == QUEUE_CAPACITY_P0_SOURCE_ONLY) {
    limit = capacity.max_bytes;
  } else if (priority == QUEUE_CAPACITY_TERMINAL) {
    /* Terminal journal capacity cannot eat the P0 source-only reserve. */
    limit = capacity.max_bytes > capacity.p0_source_only_reserve_bytes ?
        capacity.max_bytes - capacity.p0_source_only_reserve_bytes : 0u;
  } else {
    limit = capacity.ordinary_limit_bytes;
  }
  if (incoming > limit || capacity.used_bytes > limit - incoming) {
    if (priority == QUEUE_CAPACITY_P0_SOURCE_ONLY) {
      s_capacity_p0_source_only_rejected++;
    } else if (priority == QUEUE_CAPACITY_TERMINAL) {
      s_capacity_high_priority_rejected++;
    } else {
      s_capacity_ordinary_rejected++;
    }
    fprintf(stderr,
            "[queue] capacity denied priority=%d used=%llu incoming=%llu limit=%llu max=%llu\n",
            (int)priority, (unsigned long long)capacity.used_bytes,
            (unsigned long long)incoming, (unsigned long long)limit,
            (unsigned long long)capacity.max_bytes);
    return 0;
  }
  return 1;
}

static uint32_t retention_hours_effective(void) {
  const char *e = getenv("EDR_QUEUE_RETENTION_HOURS");
  if (e && e[0]) {
    unsigned long h = strtoul(e, NULL, 10);
    if (h > 0UL && h <= 87600UL) {
      return (uint32_t)h;
    }
  }
  return s_cfg_retention_hours ? s_cfg_retention_hours : 72u;
}

static unsigned queue_drain_interval_ms(void) {
  const char *e = getenv("EDR_QUEUE_DRAIN_INTERVAL_MS");
  unsigned long v = e && e[0] ? strtoul(e, NULL, 10) : 1000UL;
  if (v < 200UL) v = 200UL;
  if (v > 30000UL) v = 30000UL;
  return (unsigned)v;
}

static unsigned queue_circuit_backoff_ms(void) {
  const char *e = getenv("EDR_QUEUE_CIRCUIT_BACKOFF_MS");
  unsigned long v = e && e[0] ? strtoul(e, NULL, 10) : 5000UL;
  if (v < 500UL) v = 500UL;
  if (v > 60000UL) v = 60000UL;
  return (unsigned)v;
}

static unsigned queue_drain_max_rows(void) {
  const char *e = getenv("EDR_QUEUE_DRAIN_MAX_ROWS");
  unsigned long v = e && e[0] ? strtoul(e, NULL, 10) : 8UL;
  if (v < 1UL) v = 1UL;
  if (v > 128UL) v = 128UL;
  return (unsigned)v;
}

static uint32_t rd_u32_le(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static int batch_header_valid(const uint8_t *h) {
  uint32_t m = rd_u32_le(h);
  return m == EDR_TRANSPORT_BATCH_MAGIC_RAW || m == EDR_TRANSPORT_BATCH_MAGIC_LZ4;
}

static int terminal_wire_valid(const uint8_t *wire, size_t wire_len) {
  uint32_t body_len;
  uint32_t frame_len;
  if (!wire || wire_len < 16u || wire_len > EDR_TERMINAL_FRAME_MAX_BYTES ||
      !batch_header_valid(wire) || wire_len > UINT32_MAX ||
      wire_len > (size_t)INT_MAX) {
    return 0;
  }
  body_len = rd_u32_le(wire + 8u);
  frame_len = rd_u32_le(wire + 12u);
  return body_len == frame_len + 4u && (size_t)body_len + 12u == wire_len;
}

static int p0_deferred_key_normalize(const char *key, char out[65]) {
  size_t i;
  if (!key || !out || strlen(key) != EDR_STORAGE_QUEUE_P0_DEFERRED_KEY_HEX_LEN) return 0;
  for (i = 0u; i < EDR_STORAGE_QUEUE_P0_DEFERRED_KEY_HEX_LEN; ++i) {
    unsigned char c = (unsigned char)key[i];
    if (c >= 'A' && c <= 'F') c = (unsigned char)(c - 'A' + 'a');
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    out[i] = (char)c;
  }
  out[EDR_STORAGE_QUEUE_P0_DEFERRED_KEY_HEX_LEN] = '\0';
  return 1;
}

static int p0_deferred_digest_valid(const unsigned char *digest, int digest_len) {
  int i;
  if (!digest || digest_len != (int)EDR_STORAGE_QUEUE_P0_DEFERRED_KEY_HEX_LEN ||
      memchr(digest, '\0', (size_t)digest_len) != NULL) {
    return 0;
  }
  for (i = 0; i < digest_len; ++i) {
    unsigned char c = digest[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
  }
  return 1;
}

static int p0_deferred_begin_durable_locked(void) {
  if (!s_db || exec_simple(s_db, "PRAGMA synchronous=FULL;") != SQLITE_OK) return -1;
  if (exec_simple(s_db, "BEGIN IMMEDIATE;") != SQLITE_OK) {
    (void)exec_simple(s_db, "PRAGMA synchronous=NORMAL;");
    return -1;
  }
  return 0;
}

static int p0_deferred_end_durable_locked(int commit) {
  int rc;
  if (!s_db) return -1;
  if (!commit) {
    (void)exec_simple(s_db, "ROLLBACK;");
    (void)exec_simple(s_db, "PRAGMA synchronous=NORMAL;");
    return 0;
  }
#ifdef EDR_STORAGE_QUEUE_TESTING
  s_test_p0_deferred_commit_active = 1;
#endif
  rc = exec_simple(s_db, "COMMIT;");
#ifdef EDR_STORAGE_QUEUE_TESTING
  s_test_p0_deferred_commit_active = 0;
#endif
  if (rc != SQLITE_OK) (void)exec_simple(s_db, "ROLLBACK;");
  (void)exec_simple(s_db, "PRAGMA synchronous=NORMAL;");
  return rc == SQLITE_OK ? 0 : -1;
}

/* Producer batch ids are C strings; durable SQLite TEXT must be checked by
 * raw byte length before it crosses that boundary. An embedded NUL would make
 * later sqlite3_bind_text(..., -1) operate on only a prefix. */
static int queue_text_valid(const char *value) {
  return value && value[0] && strlen(value) <= EDR_TERMINAL_TEXT_MAX_BYTES;
}

static int queue_sql_text_valid(const unsigned char *value, int value_len) {
  return value && value_len > 0 && (unsigned)value_len <= EDR_TERMINAL_TEXT_MAX_BYTES &&
         memchr(value, '\0', (size_t)value_len) == NULL;
}

/* The immutable owner digest is committed alongside the terminal owner.  It
 * remains usable if a later SQLite TEXT corruption makes the owner key unsafe
 * to bind as a C string, so precreate cannot treat that durable owner as
 * absent and authorize the action again. */
static int terminal_owner_digest_from_key(const char *key,
                                          char out[EDR_TERMINAL_OWNER_DIGEST_HEX_LEN + 1u]) {
  return queue_text_valid(key) && out &&
         edr_sha256_hex((const uint8_t *)key, strlen(key), out) == 0;
}

static int terminal_owner_digest_valid(const unsigned char *value, int value_len) {
  if (!value || value_len != (int)EDR_TERMINAL_OWNER_DIGEST_HEX_LEN ||
      memchr(value, '\0', (size_t)value_len) != NULL) {
    return 0;
  }
  for (int i = 0; i < value_len; ++i) {
    unsigned char c = value[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
  }
  return 1;
}

static int delete_row_by_id(sqlite3_int64 id) {
  sqlite3_stmt *st = NULL;
  const char *sql = "DELETE FROM event_queue WHERE id=?;";
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    return -1;
  }
  sqlite3_bind_int64(st, 1, id);
  int rc = sqlite3_step(st);
  sqlite3_finalize(st);
  if (rc == SQLITE_DONE) {
    if (s_pending > 0u) {
      s_pending--;
    }
    return 0;
  }
  return -1;
}

static int delete_selected_row(sqlite3 *db, sqlite3_int64 id, const char *batch_id,
                               const uint8_t *payload, int payload_len, int severity) {
  sqlite3_stmt *st = NULL;
  int is_terminal;
  int durable_transaction = 0;
  int source_only = severity == EDR_STORAGE_QUEUE_SEVERITY_P0_SOURCE_ONLY;
  const char *sql = "DELETE FROM event_queue "
                    "WHERE id=? AND batch_id=? AND payload=? AND status='pending';";
  if (!db || !batch_id || !payload || payload_len <= 0 ||
      sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
    return -1;
  }
  is_terminal = terminal_journal_batch_exists_locked(db, batch_id);
  if (is_terminal < 0) {
    sqlite3_finalize(st);
    return -1;
  }
  if (is_terminal || source_only) {
    /* A severity-2 source record clears its matching capability latch only
     * with this central 2xx ACK DELETE. This is the same FULL crash boundary
     * used for terminal journal acknowledgements. */
    if (source_only) {
      if (queue_p0_latch_begin_durable_locked() != 0) {
        sqlite3_finalize(st);
        return -1;
      }
    } else if (terminal_journal_begin_durable_locked() != 0) {
      sqlite3_finalize(st);
      return -1;
    }
    durable_transaction = 1;
  }
  sqlite3_bind_int64(st, 1, id);
  sqlite3_bind_text(st, 2, batch_id, -1, SQLITE_TRANSIENT);
  sqlite3_bind_blob(st, 3, payload, payload_len, SQLITE_TRANSIENT);
  int rc = sqlite3_step(st);
  int changed = sqlite3_changes(db);
  sqlite3_finalize(st);
  if (rc == SQLITE_DONE && changed == 1) {
    /* A terminal journal frame and its ordinary-queue copy share the stable
     * batch id.  Delete, acknowledgement flags and the final completed CASE
     * are one FULL transaction, so no crash can strand a ready dual-acked row
     * after its ordinary queue copy disappeared. */
    if (durable_transaction) {
      if (source_only) {
        if (queue_meta_ack_source_batch_locked(db, batch_id) != 0) {
          (void)queue_p0_latch_end_durable_locked(0);
          return -1;
        }
      } else if (terminal_journal_ack_batch_id_locked(db, batch_id) != 0) {
        (void)terminal_journal_end_durable_locked(0);
        return -1;
      }
      if (source_only) {
        if (queue_p0_latch_end_durable_locked(1) != 0) {
          /* Commit failure rolls the DELETE and latch transition together. */
          return -1;
        }
      } else {
        if (terminal_journal_end_durable_locked(1) != 0) {
          /* Commit failure rolls the DELETE and acknowledgement together. */
          return -1;
        }
      }
    }
    if (s_pending > 0u) s_pending--;
    if (is_terminal) terminal_journal_refresh_locked();
    return 0;
  }
  if (durable_transaction) {
    if (source_only) (void)queue_p0_latch_end_durable_locked(0);
    else (void)terminal_journal_end_durable_locked(0);
  }
  return -1;
}

static int dead_letter_row_by_id(sqlite3_int64 id, const char *reason) {
  sqlite3_stmt *st = NULL;
  const char *sql = "UPDATE event_queue SET status='dead_letter', terminal_reason=?, terminal_at=? "
                    "WHERE id=? AND status='pending';";
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    return -1;
  }
  sqlite3_bind_text(st, 1, reason ? reason : "terminal", -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 2, (sqlite3_int64)time(NULL));
  sqlite3_bind_int64(st, 3, id);
  int rc = sqlite3_step(st);
  int changed = sqlite3_changes(s_db);
  sqlite3_finalize(st);
  if (rc == SQLITE_DONE && changed == 1) {
    if (s_pending > 0u) s_pending--;
    fprintf(stderr, "[queue] moved P0 batch id=%lld to durable dead-letter: %s\n", (long long)id,
            reason ? reason : "terminal");
    return 0;
  }
  return -1;
}

static int delete_bad_wire_rows(unsigned max_rows, unsigned *deleted_out) {
  sqlite3_stmt *st = NULL;
  const char *sql = "SELECT id, payload, severity FROM event_queue WHERE status='pending' ORDER BY id ASC LIMIT ?;";
  sqlite3_int64 ids[512];
  int severities[512];
  unsigned id_count = 0u;
  unsigned deleted = 0u;
  if (deleted_out) {
    *deleted_out = 0u;
  }
  if (!s_db || max_rows == 0u) {
    return 0;
  }
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    return -1;
  }
  if (max_rows > (unsigned)(sizeof(ids) / sizeof(ids[0]))) {
    max_rows = (unsigned)(sizeof(ids) / sizeof(ids[0]));
  }
  sqlite3_bind_int(st, 1, (int)max_rows);
  while (sqlite3_step(st) == SQLITE_ROW) {
    sqlite3_int64 id = sqlite3_column_int64(st, 0);
    const void *blob = sqlite3_column_blob(st, 1);
    int blob_len = sqlite3_column_bytes(st, 1);
    const uint8_t *b = (const uint8_t *)blob;
    if (!blob || blob_len < 12 || !batch_header_valid(b)) {
      ids[id_count++] = id;
      severities[id_count - 1u] = sqlite3_column_int(st, 2);
      if (id_count >= max_rows) {
        break;
      }
    }
  }
  sqlite3_finalize(st);
  for (unsigned i = 0u; i < id_count; i++) {
    int rc;
    if (severities[i] == EDR_STORAGE_QUEUE_SEVERITY_P0_SOURCE_ONLY) {
      rc = queue_meta_quarantine_source_only_locked(ids[i], "source_only_invalid_wire_header");
    } else {
      rc = severities[i] > EDR_STORAGE_QUEUE_SEVERITY_ORDINARY ?
               dead_letter_row_by_id(ids[i], "invalid_wire_header") :
               delete_row_by_id(ids[i]);
    }
    if (rc == 0) {
      deleted++;
    }
  }
  if (deleted_out) {
    *deleted_out = deleted;
  }
  return 0;
}

static void log_legacy_drop(sqlite3_int64 id) {
  uint64_t now = edr_monotonic_ns();
  if (s_legacy_drop_log_until_ns > now) {
    s_legacy_drop_suppressed++;
    return;
  }
  if (s_legacy_drop_suppressed > 0u) {
    fprintf(stderr,
            "[queue] dropping legacy batch without v6.2 header id=%lld (suppressed=%llu; old rows are auto-purged)\n",
            (long long)id, (unsigned long long)s_legacy_drop_suppressed);
    s_legacy_drop_suppressed = 0u;
  } else {
    fprintf(stderr, "[queue] dropping legacy batch without v6.2 header id=%lld (old rows are auto-purged)\n",
            (long long)id);
  }
  s_legacy_drop_log_until_ns = now + 60000000000ULL;
}

static void bump_selected_retry(sqlite3 *db, sqlite3_int64 id, const char *batch_id,
                                const uint8_t *payload, int payload_len) {
  sqlite3_stmt *st = NULL;
  /* Severity-2 source assertions intentionally remain replayable without a
   * retry ceiling. Saturate the stored accounting counter instead of letting
   * SQLite promote an overflowing signed INTEGER to REAL, which would make a
   * future exact replay / audit query ambiguous. */
  const char *sql = "UPDATE event_queue SET retry_count=CASE "
                    "WHEN retry_count<9223372036854775807 THEN retry_count+1 ELSE retry_count END "
                    "WHERE id=? AND batch_id=? AND payload=? AND status='pending';";
  if (!db || !batch_id || !payload || payload_len <= 0 ||
      sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
    return;
  }
  sqlite3_bind_int64(st, 1, id);
  sqlite3_bind_text(st, 2, batch_id, -1, SQLITE_TRANSIENT);
  sqlite3_bind_blob(st, 3, payload, payload_len, SQLITE_TRANSIENT);
  (void)sqlite3_step(st);
  sqlite3_finalize(st);
}

static void cleanup_terminal_journal_rows(void) {
  sqlite3_stmt *st = NULL;
  sqlite3_int64 now;
  sqlite3_int64 cutoff;
  uint32_t hours;
  if (!s_db) return;
  hours = retention_hours_effective();
  if (hours == 0u) return;
  now = (sqlite3_int64)time(NULL);
  cutoff = now - (sqlite3_int64)hours * 3600;
  /* A pre-execution intent is the only proof available after a crash. Keep it
   * replayable indefinitely (the 1024 admission cap bounds this set), and
   * make its unknown outcome explicit instead of silently expiring it. */
  if (sqlite3_prepare_v2(
          s_db,
          "UPDATE enforcement_terminal_journal SET state='outcome_unknown',"
          "last_error='outcome_unknown_retained_for_replay',updated_at=? "
          "WHERE state='pending_intent' AND created_at < ?;",
          -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_int64(st, 2, cutoff);
    (void)sqlite3_step(st);
    sqlite3_finalize(st);
  }
  st = NULL;
  if (sqlite3_prepare_v2(
          s_db,
          /* A failed terminal record is retained for operator forensics: it
           * may be the sole durable proof of an already executed action.
           * Transport failures never enter this state, but corrupt frames
           * must not disappear merely because retention elapsed. */
          "DELETE FROM enforcement_terminal_journal "
          "WHERE state='completed' AND updated_at < ?;",
          -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_int64(st, 1, cutoff);
    if (sqlite3_step(st) == SQLITE_DONE) {
      int changed = sqlite3_changes(s_db);
      if (changed > 0) s_retention_evicted_rows += (uint64_t)changed;
    }
    sqlite3_finalize(st);
  }
  terminal_journal_refresh_locked();
}

static void cleanup_p0_deferred_completed_rows(void) {
  sqlite3_stmt *st = NULL;
  sqlite3_int64 cutoff;
  uint32_t hours;
  if (!s_db) return;
  hours = retention_hours_effective();
  if (hours == 0u) return;
  cutoff = (sqlite3_int64)time(NULL) - (sqlite3_int64)hours * 3600;
  /* Pending snapshots are replay work and failed snapshots are retained
   * forensic evidence. Only payload-free completed dedup tombstones expire. */
  if (sqlite3_prepare_v2(
          s_db,
          "DELETE FROM p0_deferred_match WHERE state='completed' AND completed_at < ?;",
          -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_int64(st, 1, cutoff);
    if (sqlite3_step(st) == SQLITE_DONE) {
      int changed = sqlite3_changes(s_db);
      if (changed > 0) s_retention_evicted_rows += (uint64_t)changed;
    }
    sqlite3_finalize(st);
  }
}

static void cleanup_expired_rows(void) {
  if (!s_db) {
    return;
  }
  uint64_t now_ns = edr_monotonic_ns();
  if (now_ns - s_last_cleanup_ns < 60000000000ULL) {
    return;
  }
  s_last_cleanup_ns = now_ns;
  uint32_t hours = retention_hours_effective();
  if (hours == 0u) {
    return;
  }
  time_t cutoff = time(NULL) - (time_t)hours * 3600;
  sqlite3_stmt *st = NULL;
  const char *sql = "DELETE FROM event_queue WHERE created_at < ? AND severity=0;";
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_int64(st, 1, (sqlite3_int64)cutoff);
    if (sqlite3_step(st) == SQLITE_DONE) {
      int changed = sqlite3_changes(s_db);
      if (changed > 0) s_retention_evicted_rows += (uint64_t)changed;
    }
    sqlite3_finalize(st);
  }
  st = NULL;
  if (sqlite3_prepare_v2(s_db,
                         "UPDATE event_queue SET status='dead_letter', terminal_reason='retention_expired', "
                         "terminal_at=? WHERE created_at < ? AND severity=1 AND status='pending';",
                         -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_int64(st, 1, (sqlite3_int64)time(NULL));
    sqlite3_bind_int64(st, 2, (sqlite3_int64)cutoff);
    (void)sqlite3_step(st);
    sqlite3_finalize(st);
  }
  st = NULL;
  if (sqlite3_prepare_v2(s_db, "SELECT COUNT(*) FROM event_queue WHERE status='pending';", -1, &st, NULL) ==
      SQLITE_OK) {
    if (sqlite3_step(st) == SQLITE_ROW) {
      s_pending = (uint64_t)sqlite3_column_int64(st, 0);
    }
    sqlite3_finalize(st);
  }
  {
    unsigned deleted = 0u;
    if (delete_bad_wire_rows(256u, &deleted) == 0 && deleted > 0u) {
      /* Severity-2 bad wires are quarantined, never purged.  The count here
       * includes legacy rows removed and high-priority/source-only rows moved
       * to an operator-visible terminal state. */
      fprintf(stderr, "[queue] reconciled %u legacy/corrupt pending batches\n", deleted);
    }
  }
  cleanup_terminal_journal_rows();
  cleanup_p0_deferred_completed_rows();
}

/**
 * 返回：0 已处理一行（成功删除、丢弃坏行、或失败已 bump_retry），1 无待处理行，2 上传失败应停止本轮连续 drain
 */
static int drain_one_row(void) {
  queue_state_lock();
  if (!s_db) {
    queue_state_unlock();
    return 1;
  }
  sqlite3 *selected_db = s_db;
  uint64_t selected_generation = s_db_generation;
  sqlite3_stmt *st = NULL;
  const char *sql = "SELECT id, batch_id, payload, retry_count, severity FROM event_queue WHERE status='pending' "
                    "ORDER BY severity DESC, id ASC LIMIT 1;";
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    queue_state_unlock();
    return 1;
  }
  int step = sqlite3_step(st);
  if (step != SQLITE_ROW) {
    sqlite3_finalize(st);
    if (step == SQLITE_DONE) {
      s_pending = 0;
    }
    queue_state_unlock();
    return 1;
  }

  sqlite3_int64 id = sqlite3_column_int64(st, 0);
  const unsigned char *batch_id = sqlite3_column_text(st, 1);
  int batch_id_len = sqlite3_column_bytes(st, 1);
  const void *blob = sqlite3_column_blob(st, 2);
  int blob_len = sqlite3_column_bytes(st, 2);
  int retry_count = sqlite3_column_int(st, 3);
  int severity = sqlite3_column_int(st, 4);
  uint8_t *blob_copy = NULL;
  char *batch_id_copy = NULL;
  s_delivery_selected++;
  int metadata_invalid = !queue_sql_text_valid(batch_id, batch_id_len);
  if (metadata_invalid) {
    int quarantined;
    sqlite3_finalize(st);
    /* This is durable metadata corruption, not a transport failure. Keep the
     * payload and audit fields, move it out of pending by immutable row id,
     * and let the same drain pass reach later valid rows. */
    quarantined = severity == EDR_STORAGE_QUEUE_SEVERITY_P0_SOURCE_ONLY
                      ? queue_meta_quarantine_source_only_locked(
                            id, "source_only_invalid_batch_id_metadata")
                      : dead_letter_row_by_id(id, "invalid_batch_id_metadata");
    if (quarantined == 0) {
      s_event_queue_metadata_corruption_failures++;
      s_delivery_failed++;
    }
    queue_state_unlock();
    return quarantined == 0 ? 0 : 2;
  }
  if (batch_id && batch_id_len > 0) {
    batch_id_copy = (char *)malloc((size_t)batch_id_len + 1u);
    if (batch_id_copy) {
      memcpy(batch_id_copy, batch_id, (size_t)batch_id_len);
      batch_id_copy[batch_id_len] = '\0';
    }
  }
  /* sqlite column pointers become invalid at finalize/reset. Copy while the
   * statement owns the row, then release SQLite before any transport I/O. */
  if (blob && blob_len > 0) {
    blob_copy = (uint8_t *)malloc((size_t)blob_len);
    if (blob_copy) {
      memcpy(blob_copy, blob, (size_t)blob_len);
    }
  }
  sqlite3_finalize(st);

  {
    int lim = max_retry_limit();
    /* Severity 2 is the sole durable fail-closed disposition after a
     * collector/ruleset source cannot be evaluated. It never expires through
     * the ordinary retry policy: only a central ACK may remove it. */
    if (severity != EDR_STORAGE_QUEUE_SEVERITY_P0_SOURCE_ONLY && lim > 0 && retry_count >= lim) {
      int disposed;
      if (severity > EDR_STORAGE_QUEUE_SEVERITY_ORDINARY) {
        disposed = dead_letter_row_by_id(id, "max_retries") == 0;
      } else {
        disposed = delete_row_by_id(id) == 0;
      }
      if (disposed) s_delivery_failed++;
      free(batch_id_copy);
      free(blob_copy);
      queue_state_unlock();
      return disposed ? 0 : 2;
    }
  }

  if (!batch_id_copy || !blob_copy || blob_len < 12) {
    int disposed;
    if (severity == EDR_STORAGE_QUEUE_SEVERITY_P0_SOURCE_ONLY) {
      disposed = queue_meta_quarantine_source_only_locked(
                     id, "source_only_corrupt_payload") == 0;
    } else {
      disposed = dead_letter_row_by_id(id, "corrupt_payload") == 0;
    }
    if (disposed) s_delivery_failed++;
    free(batch_id_copy);
    free(blob_copy);
    queue_state_unlock();
    return disposed ? 0 : 2;
  }

  const uint8_t *b = blob_copy;
  if (!batch_header_valid(b)) {
    int disposed;
    if (severity == EDR_STORAGE_QUEUE_SEVERITY_P0_SOURCE_ONLY) {
      disposed = queue_meta_quarantine_source_only_locked(
                     id, "source_only_invalid_wire_header") == 0;
    } else {
      log_legacy_drop(id);
      disposed = dead_letter_row_by_id(id, "invalid_wire_header") == 0;
    }
    if (disposed) s_delivery_failed++;
    free(batch_id_copy);
    free(blob_copy);
    queue_state_unlock();
    return disposed ? 0 : 2;
  }

  /* Network transport is intentionally outside the queue lock. `blob_copy`
   * owns the row bytes across this boundary and close cannot invalidate it. */
  if (severity == EDR_STORAGE_QUEUE_SEVERITY_TERMINAL) {
    fprintf(stderr, "[queue_delivery] state=selected row_id=%lld batch_id=%s retry=%d\n",
            (long long)id, batch_id_copy, retry_count);
  }
  queue_state_unlock();
  int send = -1;
  if (edr_ingest_http_configured()) {
    if (edr_ingest_http_circuit_open() || edr_ingest_http_telemetry_deferred()) {
      queue_state_lock();
      s_delivery_requeued++;
      queue_state_unlock();
      if (severity == EDR_STORAGE_QUEUE_SEVERITY_TERMINAL) {
        fprintf(stderr,
                "[queue_delivery] state=requeued row_id=%lld batch_id=%s send=transport_deferred\n",
                (long long)id, batch_id_copy);
      }
      free(batch_id_copy);
      free(blob_copy);
      return 2;
    }
    queue_state_lock();
    s_delivery_sent++;
    queue_state_unlock();
    if (severity == EDR_STORAGE_QUEUE_SEVERITY_TERMINAL) {
      fprintf(stderr, "[queue_delivery] state=sent row_id=%lld batch_id=%s\n",
              (long long)id, batch_id_copy);
    }
    send = edr_transport_v2_report_events(batch_id_copy, b, 12u, b + 12,
                                          (size_t)blob_len - 12u);
  }
  if (send == 0) {
    int acknowledged = 0;
    queue_state_lock();
    if (s_db == selected_db && s_db_generation == selected_generation) {
      acknowledged =
          delete_selected_row(selected_db, id, batch_id_copy, blob_copy, blob_len, severity) == 0;
      if (acknowledged) s_delivery_acked++;
    }
    queue_state_unlock();
    if (severity == EDR_STORAGE_QUEUE_SEVERITY_TERMINAL) {
      fprintf(stderr, "[queue_delivery] state=%s row_id=%lld batch_id=%s\n",
              acknowledged ? "acked" : "ack_state_race", (long long)id,
              batch_id_copy);
    }
    free(batch_id_copy);
    free(blob_copy);
    /* A close/reopen can install a new queue while this send is in flight.
     * It owns a different drain generation and must select its own rows. */
    return acknowledged ? 0 : 2;
  }
  queue_state_lock();
  int requeued = 0;
  if (s_db == selected_db && s_db_generation == selected_generation) {
    /* Local budget refusal did not send the bytes. It must not consume the
     * retry allowance and eventually discard a durable ordinary batch. */
    if (!edr_ingest_http_telemetry_deferred())
      bump_selected_retry(selected_db, id, batch_id_copy, blob_copy, blob_len);
    s_delivery_requeued++;
    requeued = 1;
  }
  queue_state_unlock();
  if (severity == EDR_STORAGE_QUEUE_SEVERITY_TERMINAL) {
    fprintf(stderr, "[queue_delivery] state=%s row_id=%lld batch_id=%s send=%d\n",
            requeued ? "requeued" : "retry_state_race", (long long)id,
            batch_id_copy, send);
  }
  free(batch_id_copy);
  free(blob_copy);
  return 2;
}

static int exec_simple(sqlite3 *db, const char *sql) {
  char *err = NULL;
  int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
  if (rc != SQLITE_OK) {
    sqlite3_free(err);
    return rc;
  }
  return SQLITE_OK;
}

typedef struct QueueMetaRow {
  uint8_t nonce[EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_NONCE_BYTES];
  uint64_t counter;
  uint64_t epoch;
  int loss_detected;
  char latch_state[32];
  char recovery_event_id[EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_EVENT_ID_MAX];
  char recovery_batch_id[EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_BATCH_ID_MAX];
  char session_state[16];
  char last_error[EDR_QUEUE_META_ERROR_MAX];
} QueueMetaRow;

static int queue_meta_legacy_header_value_locked(const char *pragma, uint32_t *out) {
  sqlite3_stmt *st = NULL;
  sqlite3_int64 value;
  char sql[64];
  if (!s_db || !pragma || !out ||
      snprintf(sql, sizeof(sql), "PRAGMA %s;", pragma) <= 0 ||
      sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    return -1;
  }
  if (sqlite3_step(st) != SQLITE_ROW) {
    sqlite3_finalize(st);
    return -1;
  }
  value = sqlite3_column_int64(st, 0);
  sqlite3_finalize(st);
  if (value < INT32_MIN || value > UINT32_MAX) return -1;
  *out = (uint32_t)value;
  return 0;
}

static int queue_meta_state_valid(const char *state) {
  return state &&
         (strcmp(state, EDR_QUEUE_META_STATE_CLEAR) == 0 ||
          strcmp(state, EDR_QUEUE_META_STATE_PREPARED) == 0 ||
          strcmp(state, EDR_QUEUE_META_STATE_BOUND) == 0 ||
          strcmp(state, EDR_QUEUE_META_STATE_RECOVERY_REQUIRED) == 0);
}

static int queue_meta_session_valid(const char *state) {
  return state &&
         (strcmp(state, EDR_QUEUE_META_SESSION_CLEAN) == 0 ||
          strcmp(state, EDR_QUEUE_META_SESSION_OPEN) == 0);
}

static int queue_meta_is_latched(const QueueMetaRow *row) {
  return row && strcmp(row->latch_state, EDR_QUEUE_META_STATE_CLEAR) != 0;
}

static int queue_meta_nonce_is_nonzero(
    const uint8_t nonce[EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_NONCE_BYTES]) {
  uint8_t any = 0u;
  size_t i;
  if (!nonce) return 0;
  for (i = 0u; i < EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_NONCE_BYTES; ++i) any |= nonce[i];
  return any != 0u;
}

static int queue_meta_validate_row(const QueueMetaRow *row) {
  if (!row || !queue_meta_state_valid(row->latch_state) ||
      !queue_meta_session_valid(row->session_state) || row->counter > (uint64_t)INT64_MAX ||
      row->epoch > (uint64_t)INT64_MAX || !queue_meta_nonce_is_nonzero(row->nonce)) {
    return -1;
  }
  if (!queue_meta_is_latched(row)) {
    return row->epoch == 0u && row->loss_detected == 0 &&
           !row->recovery_event_id[0] && !row->recovery_batch_id[0] ? 0 : -1;
  }
  if (row->counter == 0u || row->epoch == 0u || row->epoch > row->counter) return -1;
  if (strcmp(row->latch_state, EDR_QUEUE_META_STATE_PREPARED) == 0) {
    return !row->loss_detected && !row->recovery_event_id[0] &&
                   !row->recovery_batch_id[0] ? 0 : -1;
  }
  if (strcmp(row->latch_state, EDR_QUEUE_META_STATE_BOUND) == 0) {
    return !row->loss_detected && row->recovery_event_id[0] &&
                   row->recovery_batch_id[0] ? 0 : -1;
  }
  /* A recovery-required latch represents an assertion whose original source
   * cannot be named safely.  It may not carry a stale bound batch/event: the
   * next capability audit receives a new, exact binding in the same FULL
   * transaction as its severity-2 queue row. */
  return row->loss_detected && !row->recovery_event_id[0] &&
                 !row->recovery_batch_id[0] ? 0 : -1;
}

static int queue_meta_random_nonce(uint8_t out[EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_NONCE_BYTES]) {
  if (!out) return -1;
#if defined(_WIN32)
  HCRYPTPROV provider = 0;
  if (!CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
    memset(out, 0, EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_NONCE_BYTES);
    return -1;
  }
  {
    unsigned attempt;
    for (attempt = 0u; attempt < 8u; ++attempt) {
      BOOL ok = CryptGenRandom(provider, EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_NONCE_BYTES, out);
      if (ok && queue_meta_nonce_is_nonzero(out)) {
        CryptReleaseContext(provider, 0);
        return 0;
      }
    }
    CryptReleaseContext(provider, 0);
  }
#else
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd >= 0) {
    unsigned attempt;
    for (attempt = 0u; attempt < 8u; ++attempt) {
      size_t used = 0u;
      while (used < EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_NONCE_BYTES) {
        ssize_t n = read(fd, out + used,
                         EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_NONCE_BYTES - used);
        if (n <= 0) break;
        used += (size_t)n;
      }
      if (used == EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_NONCE_BYTES &&
          queue_meta_nonce_is_nonzero(out)) {
        close(fd);
        return 0;
      }
      if (used != EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_NONCE_BYTES) break;
    }
    close(fd);
  }
#endif
  memset(out, 0, EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_NONCE_BYTES);
  return -1;
}

static void queue_meta_init_clean(QueueMetaRow *row) {
  memset(row, 0, sizeof(*row));
  snprintf(row->latch_state, sizeof(row->latch_state), "%s", EDR_QUEUE_META_STATE_CLEAR);
  snprintf(row->session_state, sizeof(row->session_state), "%s", EDR_QUEUE_META_SESSION_CLEAN);
}

static int queue_meta_read_locked(QueueMetaRow *out) {
  sqlite3_stmt *st = NULL;
  const void *nonce;
  int nonce_len;
  const unsigned char *text;
  int rc;
  if (!s_db || !out ||
      sqlite3_prepare_v2(
          s_db,
          "SELECT queue_nonce,source_latch_counter,source_latch_epoch,source_latch_state,"
          "source_latch_recovery_event_id,source_latch_recovery_batch_id,"
          "source_latch_loss_detected,session_state,last_error FROM queue_meta WHERE id=1;",
          -1, &st, NULL) != SQLITE_OK) {
    return -1;
  }
  rc = sqlite3_step(st);
  if (rc == SQLITE_DONE) {
    sqlite3_finalize(st);
    return 1;
  }
  if (rc != SQLITE_ROW) {
    sqlite3_finalize(st);
    return -1;
  }
  memset(out, 0, sizeof(*out));
  nonce = sqlite3_column_blob(st, 0);
  nonce_len = sqlite3_column_bytes(st, 0);
  if (!nonce || nonce_len != (int)sizeof(out->nonce) ||
      sqlite3_column_int64(st, 1) < 0 || sqlite3_column_int64(st, 2) < 0) {
    sqlite3_finalize(st);
    return -1;
  }
  memcpy(out->nonce, nonce, sizeof(out->nonce));
  out->counter = (uint64_t)sqlite3_column_int64(st, 1);
  out->epoch = (uint64_t)sqlite3_column_int64(st, 2);
  text = sqlite3_column_text(st, 3);
  snprintf(out->latch_state, sizeof(out->latch_state), "%s", text ? (const char *)text : "");
  text = sqlite3_column_text(st, 4);
  snprintf(out->recovery_event_id, sizeof(out->recovery_event_id), "%s",
           text ? (const char *)text : "");
  text = sqlite3_column_text(st, 5);
  snprintf(out->recovery_batch_id, sizeof(out->recovery_batch_id), "%s",
           text ? (const char *)text : "");
  out->loss_detected = sqlite3_column_int(st, 6) ? 1 : 0;
  text = sqlite3_column_text(st, 7);
  snprintf(out->session_state, sizeof(out->session_state), "%s",
           text ? (const char *)text : "");
  text = sqlite3_column_text(st, 8);
  snprintf(out->last_error, sizeof(out->last_error), "%s", text ? (const char *)text : "");
  sqlite3_finalize(st);
  return queue_meta_validate_row(out);
}

static int queue_meta_write_locked(const QueueMetaRow *row) {
  sqlite3_stmt *st = NULL;
  int rc;
  if (!s_db || queue_meta_validate_row(row) != 0 ||
      sqlite3_prepare_v2(
          s_db,
          "UPDATE queue_meta SET queue_nonce=?,source_latch_counter=?,source_latch_epoch=?,"
          "source_latch_state=?,source_latch_recovery_event_id=?,source_latch_recovery_batch_id=?,"
          "source_latch_loss_detected=?,session_state=?,last_error=? WHERE id=1;",
          -1, &st, NULL) != SQLITE_OK) {
    return -1;
  }
  sqlite3_bind_blob(st, 1, row->nonce, (int)sizeof(row->nonce), SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 2, (sqlite3_int64)row->counter);
  sqlite3_bind_int64(st, 3, (sqlite3_int64)row->epoch);
  sqlite3_bind_text(st, 4, row->latch_state, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 5, row->recovery_event_id, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 6, row->recovery_batch_id, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(st, 7, row->loss_detected ? 1 : 0);
  sqlite3_bind_text(st, 8, row->session_state, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 9, row->last_error, -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  sqlite3_finalize(st);
  return rc == SQLITE_DONE && sqlite3_changes(s_db) == 1 ? 0 : -1;
}

static int queue_meta_insert_locked(const QueueMetaRow *row) {
  sqlite3_stmt *st = NULL;
  int rc;
  if (!s_db || queue_meta_validate_row(row) != 0 ||
      sqlite3_prepare_v2(
          s_db,
          "INSERT INTO queue_meta(id,queue_nonce,source_latch_counter,source_latch_epoch,"
          "source_latch_state,source_latch_recovery_event_id,source_latch_recovery_batch_id,"
          "source_latch_loss_detected,session_state,last_error) VALUES(1,?,?,?,?,?,?,?,?,?);",
          -1, &st, NULL) != SQLITE_OK) {
    return -1;
  }
  sqlite3_bind_blob(st, 1, row->nonce, (int)sizeof(row->nonce), SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 2, (sqlite3_int64)row->counter);
  sqlite3_bind_int64(st, 3, (sqlite3_int64)row->epoch);
  sqlite3_bind_text(st, 4, row->latch_state, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 5, row->recovery_event_id, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 6, row->recovery_batch_id, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(st, 7, row->loss_detected ? 1 : 0);
  sqlite3_bind_text(st, 8, row->session_state, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 9, row->last_error, -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  sqlite3_finalize(st);
  return rc == SQLITE_DONE && sqlite3_changes(s_db) == 1 ? 0 : -1;
}

static int queue_p0_latch_begin_durable_locked(void) {
  if (!s_db || exec_simple(s_db, "PRAGMA synchronous=FULL;") != SQLITE_OK) {
    return -1;
  }
  if (exec_simple(s_db, "BEGIN IMMEDIATE;") != SQLITE_OK) {
    (void)exec_simple(s_db, "PRAGMA synchronous=NORMAL;");
    return -1;
  }
  return 0;
}

static int queue_p0_latch_end_durable_locked(int commit) {
  int rc = SQLITE_OK;
  if (!s_db) return -1;
  if (commit) {
#ifdef EDR_STORAGE_QUEUE_TESTING
    s_test_p0_latch_commit_active = 1;
#endif
    rc = exec_simple(s_db, "COMMIT;");
#ifdef EDR_STORAGE_QUEUE_TESTING
    s_test_p0_latch_commit_active = 0;
#endif
    if (rc != SQLITE_OK) {
      (void)exec_simple(s_db, "ROLLBACK;");
      (void)exec_simple(s_db, "PRAGMA synchronous=NORMAL;");
      return -1;
    }
  } else {
    (void)exec_simple(s_db, "ROLLBACK;");
  }
  (void)exec_simple(s_db, "PRAGMA synchronous=NORMAL;");
  return 0;
}

static int queue_meta_pending_source_only_locked(void) {
  sqlite3_stmt *st = NULL;
  sqlite3_int64 count = -1;
  if (!s_db || sqlite3_prepare_v2(
                   s_db,
                   "SELECT COUNT(*) FROM event_queue WHERE severity=2 AND status='pending';",
                   -1, &st, NULL) != SQLITE_OK) {
    return -1;
  }
  if (sqlite3_step(st) == SQLITE_ROW) count = sqlite3_column_int64(st, 0);
  sqlite3_finalize(st);
  return count < 0 ? -1 : (count > 0 ? 1 : 0);
}

static int queue_meta_bound_batch_pending_locked(const QueueMetaRow *row) {
  sqlite3_stmt *st = NULL;
  sqlite3_int64 count = -1;
  if (!s_db || !row || strcmp(row->latch_state, EDR_QUEUE_META_STATE_BOUND) != 0 ||
      !row->recovery_batch_id[0] ||
      sqlite3_prepare_v2(
          s_db,
          "SELECT COUNT(*) FROM event_queue WHERE batch_id=? AND severity=2 AND status='pending';",
          -1, &st, NULL) != SQLITE_OK) {
    return -1;
  }
  sqlite3_bind_text(st, 1, row->recovery_batch_id, -1, SQLITE_TRANSIENT);
  if (sqlite3_step(st) == SQLITE_ROW) count = sqlite3_column_int64(st, 0);
  sqlite3_finalize(st);
  return count == 1 ? 1 : (count == 0 ? 0 : -1);
}

static void queue_meta_clear_latch_locked(QueueMetaRow *row) {
  if (!row) return;
  row->epoch = 0u;
  row->loss_detected = 0;
  snprintf(row->latch_state, sizeof(row->latch_state), "%s", EDR_QUEUE_META_STATE_CLEAR);
  row->recovery_event_id[0] = '\0';
  row->recovery_batch_id[0] = '\0';
  row->last_error[0] = '\0';
}

/* Only a clean severity-2 backlog may rotate a saturated counter.  The nonce
 * changes first, so a database recreation or counter wrap cannot replay an
 * old capability-audit identity into the new latch. */
static int queue_meta_begin_new_latch_locked(QueueMetaRow *row, int recovery_required,
                                             const char *reason) {
  int pending;
  if (!row || queue_meta_is_latched(row)) return -1;
  if (row->counter == (uint64_t)INT64_MAX) {
    pending = queue_meta_pending_source_only_locked();
    if (pending != 0 || queue_meta_random_nonce(row->nonce) != 0) return -1;
    row->counter = 1u;
  } else {
    row->counter++;
  }
  row->epoch = row->counter;
  row->loss_detected = recovery_required ? 1 : 0;
  snprintf(row->latch_state, sizeof(row->latch_state), "%s",
           recovery_required ? EDR_QUEUE_META_STATE_RECOVERY_REQUIRED :
                               EDR_QUEUE_META_STATE_PREPARED);
  row->recovery_event_id[0] = '\0';
  row->recovery_batch_id[0] = '\0';
  snprintf(row->last_error, sizeof(row->last_error), "%s",
           reason ? reason : "");
  return 0;
}

static int queue_meta_convert_to_recovery_locked(QueueMetaRow *row, const char *reason) {
  if (!row) return -1;
  if (!queue_meta_is_latched(row)) {
    return queue_meta_begin_new_latch_locked(row, 1, reason);
  }
  row->loss_detected = 1;
  snprintf(row->latch_state, sizeof(row->latch_state), "%s",
           EDR_QUEUE_META_STATE_RECOVERY_REQUIRED);
  row->recovery_event_id[0] = '\0';
  row->recovery_batch_id[0] = '\0';
  snprintf(row->last_error, sizeof(row->last_error), "%s",
           reason ? reason : "source_only_delivery_unresolved");
  return 0;
}

static int queue_meta_legacy_latch_active_locked(int *out_active) {
  uint32_t version = 0u;
  uint32_t generation = 0u;
  if (!out_active || queue_meta_legacy_header_value_locked("user_version", &version) != 0 ||
      queue_meta_legacy_header_value_locked("application_id", &generation) != 0) {
    return -1;
  }
  /* A latch bit with either a valid or partial generation was once a source
   * durability assertion. The old 31/30-bit identity is not reusable, so
   * migrate it to a new CSPRNG identity and force a capability audit. */
  *out_active = (version & EDR_QUEUE_P0_SOURCE_ONLY_LEGACY_LATCH_BIT) != 0u ||
                (generation != 0u && (version & EDR_QUEUE_P0_SOURCE_ONLY_LEGACY_LATCH_BIT) != 0u);
  return 0;
}

static int queue_meta_ensure_open_locked(void) {
  QueueMetaRow row;
  int read_result;
  int legacy_active = 0;
  int repaired = 0;
  read_result = queue_meta_read_locked(&row);
  if (read_result == 1) {
    queue_meta_init_clean(&row);
    if (queue_meta_random_nonce(row.nonce) != 0 ||
        queue_meta_legacy_latch_active_locked(&legacy_active) != 0) {
      return -1;
    }
    if (legacy_active && queue_meta_begin_new_latch_locked(
                             &row, 1, "legacy_header_latch_migrated") != 0) {
      return -1;
    }
    if (queue_p0_latch_begin_durable_locked() != 0) return -1;
    if (queue_meta_insert_locked(&row) != 0 || queue_p0_latch_end_durable_locked(1) != 0) {
      (void)queue_p0_latch_end_durable_locked(0);
      return -1;
    }
  } else if (read_result != 0) {
    /* Corrupt/partial metadata is an auditable lost-assertion boundary. Do
     * not borrow fields from a malformed row; install a fresh nonce/counter
     * only if a FULL repair commit succeeds. */
    queue_meta_init_clean(&row);
    if (queue_meta_random_nonce(row.nonce) != 0 ||
        queue_meta_begin_new_latch_locked(&row, 1, "queue_meta_partial_repaired") != 0 ||
        queue_p0_latch_begin_durable_locked() != 0) {
      return -1;
    }
    if (queue_meta_write_locked(&row) != 0 || queue_p0_latch_end_durable_locked(1) != 0) {
      (void)queue_p0_latch_end_durable_locked(0);
      return -1;
    }
    repaired = 1;
  }
  if (repaired) return 0;

  read_result = queue_meta_read_locked(&row);
  if (read_result != 0) return -1;
  /* A prior process that died after queue open might have failed before its
   * pre-intent latch reached SQLite. Its session marker turns that otherwise
   * unnameable loss into a deterministic recovery audit. */
  if (strcmp(row.session_state, EDR_QUEUE_META_SESSION_OPEN) == 0 &&
      !queue_meta_is_latched(&row) &&
      queue_meta_begin_new_latch_locked(&row, 1, "unclean_queue_session") != 0) {
    return -1;
  }
  if (strcmp(row.session_state, EDR_QUEUE_META_SESSION_OPEN) != 0) {
    snprintf(row.session_state, sizeof(row.session_state), "%s", EDR_QUEUE_META_SESSION_OPEN);
  }
  if (queue_p0_latch_begin_durable_locked() != 0) return -1;
  if (queue_meta_write_locked(&row) != 0 || queue_p0_latch_end_durable_locked(1) != 0) {
    (void)queue_p0_latch_end_durable_locked(0);
    return -1;
  }
  return 0;
}

static void queue_meta_mark_clean_before_close_locked(void) {
  QueueMetaRow row;
  int bound_pending;
  if (!s_db || queue_meta_read_locked(&row) != 0 ||
      strcmp(row.session_state, EDR_QUEUE_META_SESSION_CLEAN) == 0) {
    return;
  }
  bound_pending = queue_meta_bound_batch_pending_locked(&row);
  if (queue_meta_is_latched(&row) && bound_pending != 1) return;
  snprintf(row.session_state, sizeof(row.session_state), "%s", EDR_QUEUE_META_SESSION_CLEAN);
  if (queue_p0_latch_begin_durable_locked() != 0) return;
  if (queue_meta_write_locked(&row) != 0 || queue_p0_latch_end_durable_locked(1) != 0) {
    (void)queue_p0_latch_end_durable_locked(0);
  }
}

static int queue_meta_matches_latch(const QueueMetaRow *row,
                                    const EdrStorageQueueP0SourceOnlyLatch *expected) {
  return row && expected && expected->latched && queue_meta_is_latched(row) &&
         row->counter == expected->latch_counter && row->epoch == expected->latch_epoch &&
         memcmp(row->nonce, expected->queue_nonce, sizeof(row->nonce)) == 0;
}

static void queue_meta_export_latch(const QueueMetaRow *row,
                                    EdrStorageQueueP0SourceOnlyLatch *out) {
  memset(out, 0, sizeof(*out));
  if (!row) return;
  memcpy(out->queue_nonce, row->nonce, sizeof(out->queue_nonce));
  out->latch_counter = row->counter;
  out->latch_epoch = row->epoch;
  out->latched = queue_meta_is_latched(row) ? 1 : 0;
  out->recovery_required =
      strcmp(row->latch_state, EDR_QUEUE_META_STATE_RECOVERY_REQUIRED) == 0 ? 1 : 0;
  snprintf(out->recovery_event_id, sizeof(out->recovery_event_id), "%s",
           row->recovery_event_id);
  snprintf(out->recovery_batch_id, sizeof(out->recovery_batch_id), "%s",
           row->recovery_batch_id);
}

/* Called inside the FULL transaction that already deleted a centrally
 * acknowledged severity-2 row. A nonmatching row is still a valid source
 * delivery (for example a secondary record while a recovery audit owns the
 * latch); it simply cannot re-enable P0 capability. */
static int queue_meta_ack_source_batch_locked(sqlite3 *db, const char *batch_id) {
  QueueMetaRow row;
  if (!db || db != s_db || !batch_id || !batch_id[0] || queue_meta_read_locked(&row) != 0) {
    return -1;
  }
  if (strcmp(row.latch_state, EDR_QUEUE_META_STATE_BOUND) != 0 ||
      strcmp(row.recovery_batch_id, batch_id) != 0) {
    return 0;
  }
  row.epoch = 0u;
  row.loss_detected = 0;
  snprintf(row.latch_state, sizeof(row.latch_state), "%s", EDR_QUEUE_META_STATE_CLEAR);
  row.recovery_event_id[0] = '\0';
  row.recovery_batch_id[0] = '\0';
  row.last_error[0] = '\0';
  return queue_meta_write_locked(&row);
}

/* Invalid source-only wire can never become a successful transport retry.
 * Preserve the bytes as `corrupt`, advance no automatic retention/dead-letter
 * path, and require a fresh capability audit before the FileRead/ruleset
 * capability can recover. */
static int queue_meta_quarantine_source_only_locked(sqlite3_int64 id, const char *reason) {
  QueueMetaRow row;
  sqlite3_stmt *st = NULL;
  int rc;
  int changed;
  if (!s_db || queue_meta_read_locked(&row) != 0 ||
      queue_p0_latch_begin_durable_locked() != 0) {
    return -1;
  }
  if (queue_meta_convert_to_recovery_locked(&row,
                                             reason ? reason : "source_only_corrupt_wire") != 0 ||
      sqlite3_prepare_v2(
          s_db,
          "UPDATE event_queue SET status='corrupt',terminal_reason=?,terminal_at=? "
          "WHERE id=? AND severity=2 AND status='pending';",
          -1, &st, NULL) != SQLITE_OK) {
    (void)queue_p0_latch_end_durable_locked(0);
    return -1;
  }
  sqlite3_bind_text(st, 1, reason ? reason : "source_only_corrupt_wire", -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 2, (sqlite3_int64)time(NULL));
  sqlite3_bind_int64(st, 3, id);
  rc = sqlite3_step(st);
  changed = sqlite3_changes(s_db);
  sqlite3_finalize(st);
  if (rc != SQLITE_DONE || changed != 1 || queue_meta_write_locked(&row) != 0 ||
      queue_p0_latch_end_durable_locked(1) != 0) {
    (void)queue_p0_latch_end_durable_locked(0);
    return -1;
  }
  if (s_pending > 0u) s_pending--;
  return 0;
}

static void terminal_journal_refresh_locked(void) {
  sqlite3_stmt *st = NULL;
  if (!s_db) {
    s_terminal_pending = 0u;
    s_terminal_failed = 0u;
    s_terminal_outcome_unknown = 0u;
    return;
  }
  if (sqlite3_prepare_v2(
          s_db,
          "SELECT "
          "SUM(CASE WHEN state IN ('pending_intent','outcome_unknown','ready') THEN 1 ELSE 0 END),"
          "SUM(CASE WHEN state='failed' THEN 1 ELSE 0 END),"
          "SUM(CASE WHEN state='outcome_unknown' THEN 1 ELSE 0 END) "
          "FROM enforcement_terminal_journal;",
          -1, &st, NULL) == SQLITE_OK) {
    if (sqlite3_step(st) == SQLITE_ROW) {
      s_terminal_pending = (uint64_t)sqlite3_column_int64(st, 0);
      s_terminal_failed = (uint64_t)sqlite3_column_int64(st, 1);
      s_terminal_outcome_unknown = (uint64_t)sqlite3_column_int64(st, 2);
    }
    sqlite3_finalize(st);
  }
}

static int terminal_journal_begin_durable_locked(void) {
  if (!s_db || exec_simple(s_db, "PRAGMA synchronous=FULL;") != SQLITE_OK) {
    return -1;
  }
  if (exec_simple(s_db, "BEGIN IMMEDIATE;") != SQLITE_OK) {
    (void)exec_simple(s_db, "PRAGMA synchronous=NORMAL;");
    return -1;
  }
  return 0;
}

static int terminal_journal_end_durable_locked(int commit) {
  int rc = SQLITE_OK;
  if (!s_db) return -1;
  if (commit) {
#ifdef EDR_STORAGE_QUEUE_TESTING
    s_test_terminal_commit_active = 1;
#endif
    rc = exec_simple(s_db, "COMMIT;");
#ifdef EDR_STORAGE_QUEUE_TESTING
    s_test_terminal_commit_active = 0;
#endif
    if (rc != SQLITE_OK) {
      (void)exec_simple(s_db, "ROLLBACK;");
      (void)exec_simple(s_db, "PRAGMA synchronous=NORMAL;");
      return -1;
    }
  } else {
    (void)exec_simple(s_db, "ROLLBACK;");
  }
  (void)exec_simple(s_db, "PRAGMA synchronous=NORMAL;");
  return 0;
}

/* The owner digest was added after the first terminal journal schema.  Probe
 * before ALTER so an interrupted upgrade can simply reopen and finish without
 * dropping a journal row or relying on duplicate-column error text. */
static int terminal_journal_has_column_locked(const char *column) {
  sqlite3_stmt *st = NULL;
  int found = 0;
  if (!s_db || !column ||
      sqlite3_prepare_v2(s_db, "PRAGMA table_info(enforcement_terminal_journal);", -1, &st,
                         NULL) != SQLITE_OK) {
    return -1;
  }
  while (sqlite3_step(st) == SQLITE_ROW) {
    const unsigned char *name = sqlite3_column_text(st, 1);
    if (name && strcmp((const char *)name, column) == 0) {
      found = 1;
      break;
    }
  }
  sqlite3_finalize(st);
  return found;
}

/* A missing digest on already-corrupt legacy metadata has no safe owner
 * identity to compare at precreate time. Keep that condition durable instead
 * of silently treating the row as absent after a restart. */
static int terminal_journal_owner_corruption_unresolved_locked(void) {
  sqlite3_stmt *st = NULL;
  int unresolved = -1;
  if (!s_db ||
      sqlite3_prepare_v2(s_db,
                         "SELECT unresolved FROM terminal_owner_corruption_latch WHERE id=1;",
                         -1, &st, NULL) != SQLITE_OK) {
    return -1;
  }
  if (sqlite3_step(st) == SQLITE_ROW) {
    int value = sqlite3_column_int(st, 0);
    unresolved = value == 0 ? 0 : value == 1 ? 1 : -1;
  }
  sqlite3_finalize(st);
  return unresolved;
}

static int terminal_journal_mark_owner_corruption_unresolved_locked(void) {
  sqlite3_stmt *st = NULL;
  int rc;
  if (!s_db ||
      sqlite3_prepare_v2(
          s_db,
          "UPDATE terminal_owner_corruption_latch SET unresolved=1,"
          "reason='legacy_owner_digest_unrecoverable',updated_at=? WHERE id=1;",
          -1, &st, NULL) != SQLITE_OK) {
    return -1;
  }
  sqlite3_bind_int64(st, 1, (sqlite3_int64)time(NULL));
  rc = sqlite3_step(st);
  sqlite3_finalize(st);
  return rc == SQLITE_DONE && sqlite3_changes(s_db) == 1 ? 0 : -1;
}

/* Backfill only absent/invalid digests from a valid raw owner.  Once a
 * digest is valid it is intentionally immutable: a later key mutation must
 * not overwrite the commitment that lets precreate detect the corruption. */
static int terminal_journal_ensure_owner_digest_locked(void) {
  sqlite3_stmt *read = NULL;
  sqlite3_stmt *write = NULL;
  int has_column;
  int unresolved;
  int changed = 0;
  int rc = SQLITE_OK;

  has_column = terminal_journal_has_column_locked("owner_key_sha256");
  if (has_column < 0 ||
      (has_column == 0 &&
       exec_simple(s_db,
                   "ALTER TABLE enforcement_terminal_journal "
                   "ADD COLUMN owner_key_sha256 TEXT NOT NULL DEFAULT '';") != SQLITE_OK) ||
      exec_simple(s_db,
                  "CREATE INDEX IF NOT EXISTS idx_enforcement_terminal_owner_digest "
                  "ON enforcement_terminal_journal(owner_key_sha256);") != SQLITE_OK) {
    return -1;
  }
  unresolved = terminal_journal_owner_corruption_unresolved_locked();
  if (unresolved < 0) return -1;
  if (terminal_journal_begin_durable_locked() != 0) return -1;
  if (sqlite3_prepare_v2(s_db,
                         "SELECT id,idempotency_key,owner_key_sha256 "
                         "FROM enforcement_terminal_journal;",
                         -1, &read, NULL) != SQLITE_OK ||
      sqlite3_prepare_v2(s_db,
                         "UPDATE enforcement_terminal_journal SET owner_key_sha256=? "
                         "WHERE id=?;",
                         -1, &write, NULL) != SQLITE_OK) {
    if (read) sqlite3_finalize(read);
    if (write) sqlite3_finalize(write);
    (void)terminal_journal_end_durable_locked(0);
    return -1;
  }
  while ((rc = sqlite3_step(read)) == SQLITE_ROW) {
    sqlite3_int64 id = sqlite3_column_int64(read, 0);
    const unsigned char *raw_key = sqlite3_column_text(read, 1);
    int raw_key_len = sqlite3_column_bytes(read, 1);
    const unsigned char *stored_digest = sqlite3_column_text(read, 2);
    int stored_digest_len = sqlite3_column_bytes(read, 2);
    char key[EDR_TERMINAL_TEXT_MAX_BYTES + 1u];
    char digest[EDR_TERMINAL_OWNER_DIGEST_HEX_LEN + 1u];

    if (!queue_sql_text_valid(raw_key, raw_key_len)) {
      if (!terminal_owner_digest_valid(stored_digest, stored_digest_len) && !unresolved) {
        if (terminal_journal_mark_owner_corruption_unresolved_locked() != 0) {
          rc = SQLITE_ERROR;
          break;
        }
        unresolved = 1;
        changed = 1;
      }
      continue;
    }
    if (terminal_owner_digest_valid(stored_digest, stored_digest_len)) {
      continue;
    }
    memcpy(key, raw_key, (size_t)raw_key_len);
    key[raw_key_len] = '\0';
    if (!terminal_owner_digest_from_key(key, digest)) {
      rc = SQLITE_ERROR;
      break;
    }
    sqlite3_reset(write);
    sqlite3_clear_bindings(write);
    sqlite3_bind_text(write, 1, digest, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(write, 2, id);
    if (sqlite3_step(write) != SQLITE_DONE || sqlite3_changes(s_db) != 1) {
      rc = SQLITE_ERROR;
      break;
    }
    changed = 1;
  }
  sqlite3_finalize(read);
  sqlite3_finalize(write);
  if (rc != SQLITE_DONE || terminal_journal_end_durable_locked(changed) != 0 ||
      exec_simple(s_db,
                  "CREATE UNIQUE INDEX IF NOT EXISTS idx_enforcement_terminal_owner_digest_unique "
                  "ON enforcement_terminal_journal(owner_key_sha256) "
                  "WHERE owner_key_sha256<>'';") != SQLITE_OK) {
    return -1;
  }
  return 0;
}

#ifdef EDR_STORAGE_QUEUE_TESTING
void edr_storage_queue_test_fail_next_terminal_commits(unsigned count) {
  queue_state_lock();
  s_test_terminal_commit_failures = count;
  queue_state_unlock();
}

void edr_storage_queue_test_fail_next_enqueue_commits(unsigned count) {
  queue_state_lock();
  s_test_enqueue_commit_failures = count;
  queue_state_unlock();
}

void edr_storage_queue_test_fail_next_p0_latch_commits(unsigned count) {
  queue_state_lock();
  s_test_p0_latch_commit_failures = count;
  queue_state_unlock();
}

void edr_storage_queue_test_fail_next_p0_deferred_commits(unsigned count) {
  queue_state_lock();
  s_test_p0_deferred_commit_failures = count;
  queue_state_unlock();
}

void edr_storage_queue_test_fail_next_terminal_ack_steps(unsigned count) {
  queue_state_lock();
  s_test_terminal_ack_step_failures = count;
  queue_state_unlock();
}

void edr_storage_queue_test_fail_next_terminal_select_allocations(
    unsigned key_count, unsigned batch_id_count, unsigned wire_count) {
  queue_state_lock();
  s_test_terminal_select_alloc_failures[EDR_TERMINAL_SELECT_ALLOC_KEY] = key_count;
  s_test_terminal_select_alloc_failures[EDR_TERMINAL_SELECT_ALLOC_BATCH_ID] =
      batch_id_count;
  s_test_terminal_select_alloc_failures[EDR_TERMINAL_SELECT_ALLOC_WIRE] = wire_count;
  queue_state_unlock();
}

void edr_storage_queue_test_run_cleanup(void) {
  queue_state_lock();
  s_last_cleanup_ns = 0u;
  cleanup_expired_rows();
  queue_state_unlock();
}

static int terminal_journal_test_fail_ack_step(void) {
  if (s_test_terminal_ack_step_failures == 0u) return 0;
  s_test_terminal_ack_step_failures--;
  return 1;
}
#endif

/* The selected row has to outlive sqlite3_finalize() and unlocked transport.
 * Keeping this narrow wrapper test-only lets the test force each ownership
 * handoff failure without replacing libc allocation for unrelated paths. */
static void *terminal_journal_select_alloc(size_t bytes, unsigned allocation_kind) {
#ifdef EDR_STORAGE_QUEUE_TESTING
  if (allocation_kind < EDR_TERMINAL_SELECT_ALLOC_COUNT &&
      s_test_terminal_select_alloc_failures[allocation_kind] > 0u) {
    s_test_terminal_select_alloc_failures[allocation_kind]--;
    return NULL;
  }
#else
  (void)allocation_kind;
#endif
  return malloc(bytes);
}

static int terminal_journal_batch_exists_locked(sqlite3 *db, const char *batch_id) {
  sqlite3_stmt *st = NULL;
  int result = -1;
  static const char sql[] =
      "SELECT 1 FROM enforcement_terminal_journal "
      "WHERE intent_batch_id=? OR source_batch_id=? OR combined_batch_id=? LIMIT 1;";
  if (!db || !batch_id || !batch_id[0] ||
      sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
    return -1;
  }
  sqlite3_bind_text(st, 1, batch_id, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 2, batch_id, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 3, batch_id, -1, SQLITE_TRANSIENT);
  {
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) result = 1;
    else if (rc == SQLITE_DONE) result = 0;
  }
  sqlite3_finalize(st);
  return result;
}

static int terminal_journal_reconcile_completed_locked(void) {
  int rc;
  if (terminal_journal_begin_durable_locked() != 0) return -1;
  rc = exec_simple(s_db,
                   "UPDATE enforcement_terminal_journal SET state='completed',completed_at=updated_at,"
                   "reserved_bytes=0 "
                   "WHERE state='ready' AND source_acked=1 AND combined_acked=1;");
  if (rc != SQLITE_OK) {
    (void)terminal_journal_end_durable_locked(0);
    return -1;
  }
  return terminal_journal_end_durable_locked(1);
}

/* Runs inside the caller's terminal FULL transaction.  Every statement is
 * checked: an ACK is not durable unless its final completed state is too. */
static int terminal_journal_ack_batch_id_locked(sqlite3 *db, const char *batch_id) {
  sqlite3_stmt *st = NULL;
  sqlite3_int64 now;
  int rc;
  const char *intent_sql =
      "UPDATE enforcement_terminal_journal SET intent_acked=1,updated_at=? "
      "WHERE state IN ('pending_intent','outcome_unknown','ready') "
      "AND intent_acked=0 AND intent_batch_id=?;";
  const char *source_sql =
      "UPDATE enforcement_terminal_journal SET source_acked=1,updated_at=? "
      "WHERE state='ready' AND source_acked=0 AND source_batch_id=?;";
  const char *combined_sql =
      "UPDATE enforcement_terminal_journal SET combined_acked=1,updated_at=? "
      "WHERE state='ready' AND combined_acked=0 AND combined_batch_id=?;";
  if (!db || !batch_id || !batch_id[0]) return -1;
  now = (sqlite3_int64)time(NULL);
#ifdef EDR_STORAGE_QUEUE_TESTING
  if (terminal_journal_test_fail_ack_step()) return -1;
#endif
  if (sqlite3_prepare_v2(db, intent_sql, -1, &st, NULL) != SQLITE_OK) return -1;
  sqlite3_bind_int64(st, 1, now);
  sqlite3_bind_text(st, 2, batch_id, -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  sqlite3_finalize(st);
  if (rc != SQLITE_DONE) return -1;
  st = NULL;
#ifdef EDR_STORAGE_QUEUE_TESTING
  if (terminal_journal_test_fail_ack_step()) return -1;
#endif
  if (sqlite3_prepare_v2(db, source_sql, -1, &st, NULL) != SQLITE_OK) return -1;
  sqlite3_bind_int64(st, 1, now);
  sqlite3_bind_text(st, 2, batch_id, -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  sqlite3_finalize(st);
  if (rc != SQLITE_DONE) return -1;
  st = NULL;
#ifdef EDR_STORAGE_QUEUE_TESTING
  if (terminal_journal_test_fail_ack_step()) return -1;
#endif
  if (sqlite3_prepare_v2(db, combined_sql, -1, &st, NULL) != SQLITE_OK) return -1;
  sqlite3_bind_int64(st, 1, now);
  sqlite3_bind_text(st, 2, batch_id, -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  sqlite3_finalize(st);
  if (rc != SQLITE_DONE) return -1;
#ifdef EDR_STORAGE_QUEUE_TESTING
  if (terminal_journal_test_fail_ack_step()) return -1;
#endif
  rc = exec_simple(
      db,
      "UPDATE enforcement_terminal_journal SET state='completed',completed_at=updated_at,"
      "reserved_bytes=0 "
      "WHERE state='ready' AND source_acked=1 AND combined_acked=1;");
  return rc == SQLITE_OK ? 0 : -1;
}

/* 锁等待上限(ms):重装/重启时旧实例可能在数秒内才释放锁;有界重试避免新实例瞬时秒退。
 * EDR_QUEUE_LOCK_WAIT_MS 可调(默认 3000,范围 0~30000);真被占用则等满后再放弃。 */
static long queue_lock_wait_ms(void) {
  const char *e = getenv("EDR_QUEUE_LOCK_WAIT_MS");
  long v = e && e[0] ? strtol(e, NULL, 10) : 3000L;
  if (v < 0) v = 0;
  if (v > 30000) v = 30000;
  return v;
}

static EdrError queue_lock_acquire(const char *path) {
  if (!path || !path[0]) {
    return EDR_ERR_INVALID_ARG;
  }
  snprintf(s_lock_path, sizeof(s_lock_path), "%s.lock", path);
  const long wait_ms = queue_lock_wait_ms();
#if defined(_WIN32)
  /* 独占打开(share=0):持有者进程退出时 OS 自动释放句柄,故真陈旧锁不阻塞;
   * 仅在另一活实例持有(SHARING_VIOLATION)时按上限重试;ACL 拒绝(ACCESS_DENIED)直接报权限,重试无益。 */
  const DWORD step = 250;
  long waited = 0;
  for (;;) {
    s_lock_handle = CreateFileA(s_lock_path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, NULL);
    if (s_lock_handle != INVALID_HANDLE_VALUE) {
      return EDR_OK;
    }
    DWORD err = GetLastError();
    if (err == ERROR_ACCESS_DENIED) {
      fprintf(stderr,
              "[queue] lock open denied (ACL/权限不足,Agent 须以 SYSTEM 经计划任务运行;勿手动前台跑): %s\n",
              s_lock_path);
      return EDR_ERR_QUEUE_PERMISSION;
    }
    if (err != ERROR_SHARING_VIOLATION && err != ERROR_LOCK_VIOLATION) {
      fprintf(stderr, "[queue] cannot open queue lock file (winerr=%lu): %s\n",
              (unsigned long)err, s_lock_path);
      return EDR_ERR_SQLITE_OPEN;
    }
    if (waited >= wait_ms) {
      fprintf(stderr,
              "[queue] cannot acquire queue file lock after %ldms (另一实例持有): %s\n",
              wait_ms, s_lock_path);
      return EDR_ERR_QUEUE_LOCKED;
    }
    Sleep(step);
    waited += (long)step;
  }
#else
  s_lock_fd = open(s_lock_path, O_CREAT | O_RDWR, 0600);
  if (s_lock_fd < 0) {
    if (errno == EACCES || errno == EPERM) {
      fprintf(stderr, "[queue] lock open denied (权限不足,须以服务身份运行): %s\n", s_lock_path);
      return EDR_ERR_QUEUE_PERMISSION;
    } else {
      fprintf(stderr, "[queue] cannot open queue lock file (errno=%d): %s\n", errno, s_lock_path);
      return EDR_ERR_SQLITE_OPEN;
    }
  }
  const long step_us = 250000; /* 250ms */
  long waited = 0;
  for (;;) {
    if (flock(s_lock_fd, LOCK_EX | LOCK_NB) == 0) {
      return EDR_OK;
    }
    if (errno != EWOULDBLOCK && errno != EAGAIN) {
      fprintf(stderr, "[queue] flock failed (errno=%d): %s\n", errno, s_lock_path);
      close(s_lock_fd);
      s_lock_fd = -1;
      return EDR_ERR_SQLITE_OPEN;
    }
    if (waited >= wait_ms) {
      close(s_lock_fd);
      s_lock_fd = -1;
      fprintf(stderr, "[queue] cannot acquire queue file lock after %ldms (另一实例持有): %s\n",
              wait_ms, s_lock_path);
      return EDR_ERR_QUEUE_LOCKED;
    }
    usleep(step_us);
    waited += 250;
  }
#endif
}

static void storage_queue_close_unlocked(void) {
  if (s_db) {
    /* A clean close is the only way a later open may distinguish an ordinary
     * restart from a crash between pre-intent latch and source insertion. If
     * this FULL update fails we deliberately leave the session open, forcing
     * a recovery audit next time. */
    queue_meta_mark_clean_before_close_locked();
    sqlite3_close(s_db);
    s_db = NULL;
  }
  queue_lock_release();
  s_pending = 0;
  s_terminal_pending = 0;
  s_terminal_failed = 0;
  s_terminal_outcome_unknown = 0;
  s_last_drain_ns = 0u;
}

static void queue_lock_release(void) {
#if defined(_WIN32)
  if (s_lock_handle != INVALID_HANDLE_VALUE) {
    CloseHandle(s_lock_handle);
    s_lock_handle = INVALID_HANDLE_VALUE;
  }
#else
  if (s_lock_fd >= 0) {
    (void)flock(s_lock_fd, LOCK_UN);
    close(s_lock_fd);
    s_lock_fd = -1;
  }
#endif
  if (s_lock_path[0]) {
    (void)remove(s_lock_path);
    s_lock_path[0] = '\0';
  }
}

static int queue_busy_timeout_ms(void) {
  const char *e = getenv("EDR_QUEUE_BUSY_TIMEOUT_MS");
  long v = e && e[0] ? strtol(e, NULL, 10) : 5000L;
  if (v < 100) v = 100;
  if (v > 60000) v = 60000;
  return (int)v;
}

EdrError edr_storage_queue_open(const char *path) {
  queue_state_lock();
  storage_queue_close_unlocked();
  load_queue_db_limit();
  if (path && path[0]) {
    snprintf(s_path, sizeof(s_path), "%s", path);
  } else {
    snprintf(s_path, sizeof(s_path), "%s", "edr_queue.db");
  }

  EdrError lock_error = queue_lock_acquire(s_path);
  if (lock_error != EDR_OK) {
    queue_state_unlock();
    return lock_error;
  }

  int rc = sqlite3_open(s_path, &s_db);
  if (rc != SQLITE_OK || !s_db) {
    int extended_rc = s_db ? sqlite3_extended_errcode(s_db) : rc;
    int system_errno = s_db ? sqlite3_system_errno(s_db) : 0;
    const char *message = s_db ? sqlite3_errmsg(s_db) : "sqlite handle unavailable";
    fprintf(stderr,
            "[queue] sqlite open failed rc=%d extended_rc=%d system_errno=%d message=%s path=%s\n",
            rc, extended_rc, system_errno, message ? message : "unknown", s_path);
    if (s_db) {
      sqlite3_close(s_db);
    }
    s_db = NULL;
    queue_lock_release();
    queue_state_unlock();
    return EDR_ERR_SQLITE_OPEN;
  }
  sqlite3_busy_timeout(s_db, queue_busy_timeout_ms());
#ifdef EDR_STORAGE_QUEUE_TESTING
  (void)sqlite3_commit_hook(s_db, terminal_journal_test_commit_hook, NULL);
#endif
  (void)exec_simple(s_db, "PRAGMA journal_mode=WAL;");
  (void)exec_simple(s_db, "PRAGMA synchronous=NORMAL;");
  (void)exec_simple(s_db, "PRAGMA wal_autocheckpoint=1000;");
  (void)exec_simple(s_db, "PRAGMA temp_store=MEMORY;");

  const char *schema =
      "CREATE TABLE IF NOT EXISTS event_queue ("
      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "batch_id TEXT NOT NULL UNIQUE,"
      "payload BLOB NOT NULL,"
      "created_at INTEGER NOT NULL,"
      "compressed INTEGER NOT NULL DEFAULT 0,"
      "severity INTEGER NOT NULL DEFAULT 0 CHECK(severity IN (0,1,2)),"
      "retry_count INTEGER NOT NULL DEFAULT 0,"
      "status TEXT NOT NULL DEFAULT 'pending',"
      "terminal_reason TEXT NOT NULL DEFAULT '',"
      "terminal_at INTEGER NOT NULL DEFAULT 0"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_event_queue_status ON event_queue(status, created_at);"
      "CREATE TABLE IF NOT EXISTS queue_meta ("
      "id INTEGER PRIMARY KEY CHECK(id=1),"
      "queue_nonce BLOB NOT NULL CHECK(length(queue_nonce)=16 AND queue_nonce<>zeroblob(16)),"
      "source_latch_counter INTEGER NOT NULL CHECK(source_latch_counter>=0),"
      "source_latch_epoch INTEGER NOT NULL CHECK(source_latch_epoch>=0),"
      "source_latch_state TEXT NOT NULL CHECK(source_latch_state IN "
      "('clear','prepared','bound','recovery_required')),"
      "source_latch_recovery_event_id TEXT NOT NULL DEFAULT '',"
      "source_latch_recovery_batch_id TEXT NOT NULL DEFAULT '',"
      "source_latch_loss_detected INTEGER NOT NULL DEFAULT 0 "
      "CHECK(source_latch_loss_detected IN (0,1)),"
      "session_state TEXT NOT NULL DEFAULT 'clean' CHECK(session_state IN ('clean','open')),"
      "last_error TEXT NOT NULL DEFAULT ''"
      ");"
      "CREATE TABLE IF NOT EXISTS p0_deferred_match ("
      "key_sha256 TEXT PRIMARY KEY NOT NULL CHECK(length(key_sha256)=64),"
      "family_mask INTEGER NOT NULL CHECK(family_mask>0 AND family_mask<=15),"
      "payload BLOB,"
      "payload_len INTEGER NOT NULL CHECK(payload_len>0 AND payload_len<=524288),"
      "payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256)=64),"
      "state TEXT NOT NULL DEFAULT 'pending' "
      "CHECK(state IN ('pending','completed','failed')),"
      "created_at INTEGER NOT NULL,"
      "updated_at INTEGER NOT NULL,"
      "next_retry_at INTEGER NOT NULL DEFAULT 0,"
      "retry_count INTEGER NOT NULL DEFAULT 0 CHECK(retry_count>=0),"
      "last_error TEXT NOT NULL DEFAULT '',"
      "terminal_reason TEXT NOT NULL DEFAULT '',"
      "completed_at INTEGER NOT NULL DEFAULT 0,"
      "CHECK((state='completed' AND payload IS NULL) OR "
      "(state IN ('pending','failed') AND payload IS NOT NULL))"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_p0_deferred_due "
      "ON p0_deferred_match(state,next_retry_at,created_at,key_sha256);"
      "CREATE TABLE IF NOT EXISTS enforcement_terminal_journal ("
      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "idempotency_key TEXT NOT NULL UNIQUE,"
      "owner_key_sha256 TEXT NOT NULL DEFAULT '',"
      "source_event_key TEXT NOT NULL,"
      "rule_id TEXT NOT NULL,"
      "process_generation_key TEXT NOT NULL,"
      "state TEXT NOT NULL DEFAULT 'pending_intent',"
      "intent_batch_id TEXT NOT NULL DEFAULT '',"
      "intent_wire BLOB,"
      "intent_acked INTEGER NOT NULL DEFAULT 0,"
      "intent_retry_count INTEGER NOT NULL DEFAULT 0,"
      "source_batch_id TEXT NOT NULL DEFAULT '',"
      "source_wire BLOB,"
      "source_acked INTEGER NOT NULL DEFAULT 0,"
      "source_retry_count INTEGER NOT NULL DEFAULT 0,"
      "combined_batch_id TEXT NOT NULL DEFAULT '',"
      "combined_wire BLOB,"
      "combined_acked INTEGER NOT NULL DEFAULT 0,"
      "combined_retry_count INTEGER NOT NULL DEFAULT 0,"
      "reserved_bytes INTEGER NOT NULL DEFAULT 0,"
      "last_error TEXT NOT NULL DEFAULT '',"
      "created_at INTEGER NOT NULL,"
      "updated_at INTEGER NOT NULL,"
      "completed_at INTEGER NOT NULL DEFAULT 0"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_enforcement_terminal_pending "
      "ON enforcement_terminal_journal(state, created_at);"
      "CREATE TABLE IF NOT EXISTS terminal_owner_corruption_latch ("
      "id INTEGER PRIMARY KEY CHECK(id=1),"
      "unresolved INTEGER NOT NULL DEFAULT 0 CHECK(unresolved IN (0,1)),"
      "reason TEXT NOT NULL DEFAULT '',"
      "updated_at INTEGER NOT NULL DEFAULT 0"
      ");"
      "INSERT OR IGNORE INTO terminal_owner_corruption_latch(id,unresolved,reason,updated_at) "
      "VALUES(1,0,'',0);";

  if (exec_simple(s_db, schema) != SQLITE_OK) {
    sqlite3_close(s_db);
    s_db = NULL;
    queue_lock_release();
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }
  (void)exec_simple(s_db, "ALTER TABLE event_queue ADD COLUMN severity INTEGER NOT NULL DEFAULT 0;");
  (void)exec_simple(s_db, "ALTER TABLE event_queue ADD COLUMN terminal_reason TEXT NOT NULL DEFAULT '';");
  (void)exec_simple(s_db, "ALTER TABLE event_queue ADD COLUMN terminal_at INTEGER NOT NULL DEFAULT 0;");
  /* Databases created before the dedicated P0 source-only lane stored only
   * 0/1. Preserve those exact values explicitly; any other historical value
   * is an unknown priority contract and must fail open rather than be silently
   * relabelled into a protected lane. A trigger supplies the same CHECK for
   * upgraded SQLite tables, whose original CREATE SQL cannot be altered. */
  {
    sqlite3_stmt *severity_check = NULL;
    int invalid_severity = 0;
    if (sqlite3_prepare_v2(s_db,
                           "SELECT COUNT(*) FROM event_queue WHERE severity NOT IN (0,1,2);",
                           -1, &severity_check, NULL) != SQLITE_OK ||
        sqlite3_step(severity_check) != SQLITE_ROW) {
      if (severity_check) sqlite3_finalize(severity_check);
      sqlite3_close(s_db);
      s_db = NULL;
      queue_lock_release();
      queue_state_unlock();
      return EDR_ERR_SQLITE_WRITE;
    }
    invalid_severity = sqlite3_column_int(severity_check, 0);
    sqlite3_finalize(severity_check);
    if (invalid_severity != 0 ||
        exec_simple(s_db,
                    "UPDATE event_queue SET severity=CASE severity WHEN 0 THEN 0 WHEN 1 THEN 1 "
                    "ELSE severity END WHERE severity IN (0,1);") != SQLITE_OK ||
        exec_simple(s_db,
                    "CREATE TRIGGER IF NOT EXISTS event_queue_severity_v2_insert "
                    "BEFORE INSERT ON event_queue WHEN NEW.severity NOT IN (0,1,2) "
                    "BEGIN SELECT RAISE(ABORT,'invalid event queue severity'); END;") != SQLITE_OK ||
        exec_simple(s_db,
                    "CREATE TRIGGER IF NOT EXISTS event_queue_severity_v2_update "
                    "BEFORE UPDATE OF severity ON event_queue WHEN NEW.severity NOT IN (0,1,2) "
                    "BEGIN SELECT RAISE(ABORT,'invalid event queue severity'); END;") != SQLITE_OK) {
      fprintf(stderr, "[queue] event_queue severity migration/constraint failed invalid=%d\n",
              invalid_severity);
      sqlite3_close(s_db);
      s_db = NULL;
      queue_lock_release();
      queue_state_unlock();
      return EDR_ERR_SQLITE_WRITE;
    }
  }
  /* Upgrade journals created by a process that had the initial terminal
   * schema but stopped before durable intent payloads were added. Duplicate
   * column errors are expected on a current database. */
  (void)exec_simple(s_db,
                    "ALTER TABLE enforcement_terminal_journal "
                    "ADD COLUMN intent_batch_id TEXT NOT NULL DEFAULT ''; ");
  (void)exec_simple(s_db,
                    "ALTER TABLE enforcement_terminal_journal ADD COLUMN intent_wire BLOB;");
  (void)exec_simple(s_db,
                    "ALTER TABLE enforcement_terminal_journal "
                    "ADD COLUMN intent_acked INTEGER NOT NULL DEFAULT 0;");
  (void)exec_simple(s_db,
                    "ALTER TABLE enforcement_terminal_journal "
                    "ADD COLUMN intent_retry_count INTEGER NOT NULL DEFAULT 0;");
  (void)exec_simple(s_db,
                    "ALTER TABLE enforcement_terminal_journal "
                    "ADD COLUMN reserved_bytes INTEGER NOT NULL DEFAULT 0;");

  /* The source-only latch is a strict singleton in this same database. It is
   * initialized or migrated before any producer can enqueue evidence; a
   * malformed old header/metadata becomes a recovery-required audit rather
   * than a silently healthy capability. */
  if (queue_meta_ensure_open_locked() != 0) {
    sqlite3_close(s_db);
    s_db = NULL;
    queue_lock_release();
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }
  if (terminal_journal_ensure_owner_digest_locked() != 0) {
    sqlite3_close(s_db);
    s_db = NULL;
    queue_lock_release();
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }

  /* Recover the only old crash shape that could otherwise be invisible to
   * the replay selectors: both final frames were acknowledged, but a former
   * implementation crashed before changing ready -> completed. */
  if (terminal_journal_reconcile_completed_locked() != 0) {
    sqlite3_close(s_db);
    s_db = NULL;
    queue_lock_release();
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }

  sqlite3_stmt *st = NULL;
  const char *cnt = "SELECT COUNT(*) FROM event_queue WHERE status='pending';";
  if (sqlite3_prepare_v2(s_db, cnt, -1, &st, NULL) == SQLITE_OK) {
    if (sqlite3_step(st) == SQLITE_ROW) {
      s_pending = (uint64_t)sqlite3_column_int64(st, 0);
    }
    sqlite3_finalize(st);
  }
  s_db_generation++;
  if (s_db_generation == 0u) s_db_generation++;
  terminal_journal_refresh_locked();
  {
    unsigned deleted = 0u;
    if (delete_bad_wire_rows(2048u, &deleted) == 0 && deleted > 0u) {
      fprintf(stderr, "[queue] reconciled %u legacy/corrupt pending batches on open\n", deleted);
      st = NULL;
      if (sqlite3_prepare_v2(s_db, cnt, -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW) {
          s_pending = (uint64_t)sqlite3_column_int64(st, 0);
        }
        sqlite3_finalize(st);
      }
    }
  }
  queue_state_unlock();
  return EDR_OK;
}

void edr_storage_queue_close(void) {
  queue_state_lock();
  storage_queue_close_unlocked();
  queue_state_unlock();
}

int edr_storage_queue_is_open(void) {
  int is_open;
  queue_state_lock();
  is_open = s_db ? 1 : 0;
  queue_state_unlock();
  return is_open;
}

EdrError edr_storage_queue_p0_source_only_latch_prepare(
    EdrStorageQueueP0SourceOnlyLatch *out) {
  QueueMetaRow row;
  int changed = 0;
  int bound_pending = 0;
  if (!out) return EDR_ERR_INVALID_ARG;
  memset(out, 0, sizeof(*out));
  queue_state_lock();
  if (!s_db || queue_meta_read_locked(&row) != 0) {
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }
  if (!queue_meta_is_latched(&row)) {
    if (queue_meta_begin_new_latch_locked(&row, 0, "") != 0) {
      queue_state_unlock();
      return EDR_ERR_SQLITE_WRITE;
    }
    changed = 1;
  } else if (strcmp(row.latch_state, EDR_QUEUE_META_STATE_BOUND) == 0 &&
             (bound_pending = queue_meta_bound_batch_pending_locked(&row)) == 1) {
    /* The prior assertion already has an immutable severity-2 queue owner.
     * Rotate the single crash-gap latch to the next assertion instead of
     * declaring the durable prior row lost.  A later ACK for the older row
     * cannot clear the new tuple because ACK clearing is batch-id bound. */
    queue_meta_clear_latch_locked(&row);
    if (queue_meta_begin_new_latch_locked(&row, 0, "") != 0) {
      queue_state_unlock();
      return EDR_ERR_SQLITE_WRITE;
    }
    changed = 1;
  } else if (bound_pending >= 0) {
    /* Prepared/recovery metadata has no exact durable queue owner. */
    if (queue_meta_convert_to_recovery_locked(&row,
                                              "source_only_assertion_unresolved") != 0) {
      queue_state_unlock();
      return EDR_ERR_SQLITE_WRITE;
    }
    changed = 1;
  } else {
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }
  if (changed) {
    if (queue_p0_latch_begin_durable_locked() != 0 || queue_meta_write_locked(&row) != 0 ||
        queue_p0_latch_end_durable_locked(1) != 0) {
      (void)queue_p0_latch_end_durable_locked(0);
      queue_state_unlock();
      return EDR_ERR_SQLITE_WRITE;
    }
  }
  queue_meta_export_latch(&row, out);
  queue_state_unlock();
  return EDR_OK;
}

int edr_storage_queue_p0_source_only_latch_is_set(void) {
  EdrStorageQueueP0SourceOnlyLatch info;
  return edr_storage_queue_p0_source_only_latch_get(&info) == EDR_OK ? info.latched : -1;
}

EdrError edr_storage_queue_p0_source_only_latch_get(
    EdrStorageQueueP0SourceOnlyLatch *out) {
  QueueMetaRow row;
  if (!out) return EDR_ERR_INVALID_ARG;
  memset(out, 0, sizeof(*out));
  queue_state_lock();
  if (!s_db || queue_meta_read_locked(&row) != 0) {
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }
  queue_meta_export_latch(&row, out);
  queue_state_unlock();
  return EDR_OK;
}

EdrError edr_storage_queue_p0_source_only_recovery_probe(void) {
  QueueMetaRow row;
  EdrError result = EDR_ERR_SQLITE_WRITE;
  queue_state_lock();
  if (!s_db || queue_meta_read_locked(&row) != 0 ||
      queue_p0_latch_begin_durable_locked() != 0) {
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }
  /* A FULL no-op update verifies the precise persistent boundary but never
   * clears a live latch. ACK ownership remains solely in delete_selected_row. */
  result = queue_meta_write_locked(&row) == 0 && queue_p0_latch_end_durable_locked(1) == 0
               ? EDR_OK
               : EDR_ERR_SQLITE_WRITE;
  if (result != EDR_OK) (void)queue_p0_latch_end_durable_locked(0);
  queue_state_unlock();
  return result;
}

EdrError edr_storage_queue_enqueue(const char *batch_id, const uint8_t *payload,
                                   size_t payload_len, int compressed, int severity) {
  EdrError result = EDR_ERR_SQLITE_WRITE;
  int stored_severity;
  int rc;
  int inserted = 0;
  queue_state_lock();
  if (!s_db || !queue_text_valid(batch_id) || !payload || payload_len == 0 ||
      severity < EDR_STORAGE_QUEUE_SEVERITY_ORDINARY ||
      severity > EDR_STORAGE_QUEUE_SEVERITY_P0_SOURCE_ONLY) {
    queue_state_unlock();
    return EDR_ERR_INVALID_ARG;
  }
  cleanup_expired_rows();
  sqlite3_stmt *st = NULL;
  s_enqueue_requests++;
  stored_severity = severity;
  const int high_priority = severity > EDR_STORAGE_QUEUE_SEVERITY_ORDINARY ? 1 : 0;
  const QueueCapacityPriority capacity_priority =
      severity == EDR_STORAGE_QUEUE_SEVERITY_P0_SOURCE_ONLY ?
          QUEUE_CAPACITY_P0_SOURCE_ONLY :
      (high_priority ? QUEUE_CAPACITY_TERMINAL : QUEUE_CAPACITY_ORDINARY);
  /* Exact replays do not need new logical capacity. Checking this before
   * admission preserves idempotence even while the queue is full. */
  if (sqlite3_prepare_v2(
          s_db,
          "SELECT payload,compressed,severity,status FROM event_queue WHERE batch_id=?;", -1, &st,
          NULL) != SQLITE_OK) {
    s_enqueue_admission_attempts++;
    s_enqueue_transaction_failures++;
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }
  sqlite3_bind_text(st, 1, batch_id, -1, SQLITE_TRANSIENT);
  {
    int existing_step = sqlite3_step(st);
    if (existing_step == SQLITE_ROW) {
    const void *old_payload = sqlite3_column_blob(st, 0);
    int old_len = sqlite3_column_bytes(st, 0);
    int old_compressed = sqlite3_column_int(st, 1);
    int old_severity = sqlite3_column_int(st, 2);
    const unsigned char *old_status = sqlite3_column_text(st, 3);
    int exact = old_payload && old_len == (int)payload_len &&
                memcmp(old_payload, payload, payload_len) == 0 &&
                old_compressed == (compressed ? 1 : 0) && old_severity == stored_severity &&
                old_status && strcmp((const char *)old_status, "pending") == 0;
      sqlite3_finalize(st);
      if (exact) {
        s_enqueue_reused++;
        queue_state_unlock();
        return EDR_OK;
      }
      s_enqueue_conflicts++;
      queue_state_unlock();
      return EDR_ERR_INVALID_ARG;
    }
    if (existing_step != SQLITE_DONE) {
      sqlite3_finalize(st);
      s_enqueue_admission_attempts++;
      s_enqueue_transaction_failures++;
      queue_state_unlock();
      return EDR_ERR_SQLITE_WRITE;
    }
  }
  sqlite3_finalize(st);
  st = NULL;
  s_enqueue_admission_attempts++;
  /* Keep a logical reserve for P0 source evidence. We never reclaim a
   * pending ordinary row to make space: ordinary producers receive explicit
   * backpressure while terminal/high-priority evidence can consume the lane. */
  if (!queue_capacity_admit_locked(queue_event_live_cost(batch_id, payload_len),
                                   capacity_priority)) {
    s_enqueue_capacity_rejected++;
    queue_state_unlock();
    return EDR_ERR_QUEUE_FULL;
  }
  if (high_priority && exec_simple(s_db, "PRAGMA synchronous=FULL;") != SQLITE_OK) {
    s_enqueue_transaction_failures++;
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }
  if (high_priority && exec_simple(s_db, "BEGIN IMMEDIATE;") != SQLITE_OK) {
    (void)exec_simple(s_db, "PRAGMA synchronous=NORMAL;");
    s_enqueue_transaction_failures++;
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }
  const char *ins =
      "INSERT INTO event_queue(batch_id,payload,created_at,compressed,severity,status) "
      "VALUES(?,?,?,?,?,'pending');";
  if (sqlite3_prepare_v2(s_db, ins, -1, &st, NULL) != SQLITE_OK) {
    if (high_priority) {
      (void)exec_simple(s_db, "ROLLBACK;");
      (void)exec_simple(s_db, "PRAGMA synchronous=NORMAL;");
    }
    s_enqueue_transaction_failures++;
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }

  time_t now = time(NULL);
  sqlite3_bind_text(st, 1, batch_id, -1, SQLITE_TRANSIENT);
  sqlite3_bind_blob(st, 2, payload, (int)payload_len, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 3, (sqlite3_int64)now);
  sqlite3_bind_int(st, 4, compressed ? 1 : 0);
  sqlite3_bind_int(st, 5, stored_severity);

  rc = sqlite3_step(st);
  sqlite3_finalize(st);
  if (rc != SQLITE_DONE) {
    s_enqueue_transaction_failures++;
  } else {
    inserted = 1;
    result = EDR_OK;
  }
  if (high_priority) {
    int commit_rc = SQLITE_OK;
    if (result == EDR_OK) {
#ifdef EDR_STORAGE_QUEUE_TESTING
      s_test_enqueue_commit_active = 1;
#endif
      commit_rc = exec_simple(s_db, "COMMIT;");
#ifdef EDR_STORAGE_QUEUE_TESTING
      s_test_enqueue_commit_active = 0;
#endif
    }
    if (result == EDR_OK && commit_rc != SQLITE_OK) {
      (void)exec_simple(s_db, "ROLLBACK;");
      s_enqueue_transaction_failures++;
      s_enqueue_commit_failures++;
      result = EDR_ERR_SQLITE_WRITE;
    } else if (result != EDR_OK) {
      (void)exec_simple(s_db, "ROLLBACK;");
    }
    (void)exec_simple(s_db, "PRAGMA synchronous=NORMAL;");
  }
  if (result == EDR_OK && inserted) {
    s_pending++;
    s_enqueue_admitted++;
  }
  queue_state_unlock();
  return result;
}

static int p0_deferred_mark_failed_by_id_locked(sqlite3_int64 row_id,
                                                const char *reason) {
  sqlite3_stmt *st = NULL;
  int rc;
  int changed;
  if (!s_db || !reason || p0_deferred_begin_durable_locked() != 0) return -1;
  if (sqlite3_prepare_v2(
          s_db,
          "UPDATE p0_deferred_match SET state='failed',last_error=?,updated_at=? "
          "WHERE rowid=? AND state='pending';",
          -1, &st, NULL) != SQLITE_OK) {
    (void)p0_deferred_end_durable_locked(0);
    return -1;
  }
  sqlite3_bind_text(st, 1, reason, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 2, (sqlite3_int64)time(NULL));
  sqlite3_bind_int64(st, 3, row_id);
  rc = sqlite3_step(st);
  changed = sqlite3_changes(s_db);
  sqlite3_finalize(st);
  if (rc != SQLITE_DONE || changed != 1 || p0_deferred_end_durable_locked(1) != 0) {
    (void)p0_deferred_end_durable_locked(0);
    return -1;
  }
  return 0;
}

EdrError edr_storage_queue_p0_deferred_retain(const char *key_hex,
                                               uint32_t family_mask,
                                               const uint8_t *payload_json,
                                               size_t payload_len) {
  char key[EDR_STORAGE_QUEUE_P0_DEFERRED_KEY_BUFSIZE];
  char payload_sha[EDR_STORAGE_QUEUE_P0_DEFERRED_KEY_BUFSIZE];
  sqlite3_stmt *st = NULL;
  EdrError result = EDR_ERR_SQLITE_WRITE;
  int rc;
  if (!p0_deferred_key_normalize(key_hex, key) || family_mask == 0u ||
      (family_mask & ~UINT32_C(0x0f)) != 0u || !payload_json ||
      payload_len == 0u ||
      payload_len > EDR_STORAGE_QUEUE_P0_DEFERRED_MAX_PAYLOAD_BYTES ||
      payload_len > (size_t)INT_MAX ||
      edr_sha256_hex(payload_json, payload_len, payload_sha) != 0 ||
      memcmp(key, payload_sha, EDR_STORAGE_QUEUE_P0_DEFERRED_KEY_BUFSIZE) != 0) {
    return EDR_ERR_INVALID_ARG;
  }
  queue_state_lock();
  if (!s_db) {
    queue_state_unlock();
    return EDR_ERR_SQLITE_OPEN;
  }
  cleanup_expired_rows();
  if (sqlite3_prepare_v2(
          s_db,
          "SELECT family_mask,payload,payload_len,payload_sha256,state "
          "FROM p0_deferred_match WHERE key_sha256=?;",
          -1, &st, NULL) != SQLITE_OK) {
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }
  sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  if (rc == SQLITE_ROW) {
    sqlite3_int64 stored_family = sqlite3_column_int64(st, 0);
    const void *stored_payload = sqlite3_column_blob(st, 1);
    int stored_bytes = sqlite3_column_bytes(st, 1);
    sqlite3_int64 stored_len = sqlite3_column_int64(st, 2);
    const unsigned char *stored_sha = sqlite3_column_text(st, 3);
    int stored_sha_len = sqlite3_column_bytes(st, 3);
    const unsigned char *stored_state = sqlite3_column_text(st, 4);
    int completed = stored_state && strcmp((const char *)stored_state, "completed") == 0;
    int retained = stored_state &&
        (strcmp((const char *)stored_state, "pending") == 0 ||
         strcmp((const char *)stored_state, "failed") == 0);
    int exact = stored_family == (sqlite3_int64)(uint64_t)family_mask &&
        stored_len == (sqlite3_int64)payload_len &&
        p0_deferred_digest_valid(stored_sha, stored_sha_len) &&
        memcmp(stored_sha, payload_sha, EDR_STORAGE_QUEUE_P0_DEFERRED_KEY_HEX_LEN) == 0 &&
        ((completed && !stored_payload && stored_bytes == 0) ||
         (retained && stored_payload && stored_bytes == (int)payload_len &&
          memcmp(stored_payload, payload_json, payload_len) == 0));
    sqlite3_finalize(st);
    queue_state_unlock();
    return exact ? EDR_OK : EDR_ERR_INVALID_ARG;
  }
  sqlite3_finalize(st);
  st = NULL;
  if (rc != SQLITE_DONE) {
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }
  {
    uint64_t retained_count = 0u;
    /* Failed snapshots retain forensic payloads indefinitely. They own the
     * same slot as pending snapshots, so fail cannot reopen admission while
     * accumulating an unbounded set of non-expiring evidence. */
    if (!queue_sql_sum_locked(
            "SELECT COUNT(*) FROM p0_deferred_match WHERE state IN ('pending','failed');",
            &retained_count)) {
      queue_state_unlock();
      return EDR_ERR_SQLITE_WRITE;
    }
    if (retained_count >= EDR_STORAGE_QUEUE_P0_DEFERRED_MAX_RETAINED) {
      queue_state_unlock();
      return EDR_ERR_QUEUE_FULL;
    }
  }
  if (!queue_capacity_admit_locked(p0_deferred_live_cost(payload_len),
                                   QUEUE_CAPACITY_TERMINAL)) {
    queue_state_unlock();
    return EDR_ERR_QUEUE_FULL;
  }
  if (p0_deferred_begin_durable_locked() != 0) {
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }
  if (sqlite3_prepare_v2(
          s_db,
          "INSERT INTO p0_deferred_match("
          "key_sha256,family_mask,payload,payload_len,payload_sha256,state,"
          "created_at,updated_at,next_retry_at,retry_count,last_error,terminal_reason,completed_at) "
          "VALUES(?,?,?,?,?,'pending',?,?,0,0,'','',0);",
          -1, &st, NULL) != SQLITE_OK) {
    (void)p0_deferred_end_durable_locked(0);
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }
  sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 2, (sqlite3_int64)(uint64_t)family_mask);
  sqlite3_bind_blob(st, 3, payload_json, (int)payload_len, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 4, (sqlite3_int64)payload_len);
  sqlite3_bind_text(st, 5, payload_sha, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 6, (sqlite3_int64)time(NULL));
  sqlite3_bind_int64(st, 7, (sqlite3_int64)time(NULL));
  rc = sqlite3_step(st);
  sqlite3_finalize(st);
  if (rc == SQLITE_DONE && p0_deferred_end_durable_locked(1) == 0) result = EDR_OK;
  else (void)p0_deferred_end_durable_locked(0);
  queue_state_unlock();
  return result;
}

int edr_storage_queue_p0_deferred_contains(const char *key_hex) {
  char key[EDR_STORAGE_QUEUE_P0_DEFERRED_KEY_BUFSIZE];
  sqlite3_stmt *st = NULL;
  int result = -1;
  int rc;
  if (!p0_deferred_key_normalize(key_hex, key)) return -1;
  queue_state_lock();
  if (!s_db || sqlite3_prepare_v2(
          s_db, "SELECT 1 FROM p0_deferred_match WHERE key_sha256=?;",
          -1, &st, NULL) != SQLITE_OK) {
    queue_state_unlock();
    return -1;
  }
  sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  if (rc == SQLITE_ROW) result = 1;
  else if (rc == SQLITE_DONE) result = 0;
  sqlite3_finalize(st);
  queue_state_unlock();
  return result;
}

int edr_storage_queue_p0_deferred_peek(uint32_t healthy_family_mask,
                                       char key_out[65], uint8_t **payload_out,
                                       size_t *payload_len_out) {
  unsigned inspected = 0u;
  if (!key_out || !payload_out || !payload_len_out) return -1;
  key_out[0] = '\0';
  *payload_out = NULL;
  *payload_len_out = 0u;
  if (healthy_family_mask == 0u) return 0;
  if ((healthy_family_mask & ~UINT32_C(0x0f)) != 0u) return -1;
  queue_state_lock();
  if (!s_db) {
    queue_state_unlock();
    return -1;
  }
  while (inspected++ < EDR_STORAGE_QUEUE_P0_DEFERRED_MAX_RETAINED) {
    sqlite3_stmt *st = NULL;
    sqlite3_int64 row_id;
    const unsigned char *stored_key;
    int stored_key_len;
    sqlite3_int64 stored_family;
    const void *stored_payload;
    int stored_bytes;
    sqlite3_int64 stored_len;
    const unsigned char *stored_sha;
    int stored_sha_len;
    char normalized_key[65];
    char actual_sha[65];
    int rc;
    const char *corruption_reason = NULL;
    if (sqlite3_prepare_v2(
            s_db,
            "SELECT rowid,key_sha256,family_mask,payload,payload_len,payload_sha256 "
            "FROM p0_deferred_match WHERE state='pending' AND next_retry_at<=? "
            "AND ((family_mask & -16)!=0 OR family_mask<=0 OR (family_mask & ?)!=0) "
            "ORDER BY created_at,key_sha256 LIMIT 1;",
            -1, &st, NULL) != SQLITE_OK) {
      queue_state_unlock();
      return -1;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)time(NULL));
    sqlite3_bind_int64(st, 2, (sqlite3_int64)(uint64_t)healthy_family_mask);
    rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) {
      sqlite3_finalize(st);
      queue_state_unlock();
      return 0;
    }
    if (rc != SQLITE_ROW) {
      sqlite3_finalize(st);
      queue_state_unlock();
      return -1;
    }
    row_id = sqlite3_column_int64(st, 0);
    stored_key = sqlite3_column_text(st, 1);
    stored_key_len = sqlite3_column_bytes(st, 1);
    stored_family = sqlite3_column_int64(st, 2);
    stored_payload = sqlite3_column_blob(st, 3);
    stored_bytes = sqlite3_column_bytes(st, 3);
    stored_len = sqlite3_column_int64(st, 4);
    stored_sha = sqlite3_column_text(st, 5);
    stored_sha_len = sqlite3_column_bytes(st, 5);
    if (!stored_key || stored_key_len != 64 ||
        !p0_deferred_key_normalize((const char *)stored_key, normalized_key) ||
        stored_family <= 0 || (uint64_t)stored_family > UINT32_C(0x0f) ||
        (((uint64_t)stored_family & ~UINT64_C(0x0f)) != 0u) ||
        !stored_payload || stored_bytes <= 0 ||
        stored_len != (sqlite3_int64)stored_bytes ||
        stored_len > EDR_STORAGE_QUEUE_P0_DEFERRED_MAX_PAYLOAD_BYTES) {
      corruption_reason = "invalid_deferred_snapshot_metadata";
    } else if (!p0_deferred_digest_valid(stored_sha, stored_sha_len) ||
               edr_sha256_hex((const uint8_t *)stored_payload,
                              (size_t)stored_bytes, actual_sha) != 0 ||
               memcmp(stored_sha, actual_sha, 64u) != 0 ||
               memcmp(normalized_key, actual_sha, 65u) != 0) {
      corruption_reason = "deferred_snapshot_sha256_mismatch";
    }
    if (corruption_reason) {
      sqlite3_finalize(st);
      if (p0_deferred_mark_failed_by_id_locked(row_id, corruption_reason) != 0) {
        queue_state_unlock();
        return -1;
      }
      continue;
    }
    *payload_out = (uint8_t *)malloc((size_t)stored_bytes);
    if (!*payload_out) {
      sqlite3_finalize(st);
      queue_state_unlock();
      return -1;
    }
    memcpy(*payload_out, stored_payload, (size_t)stored_bytes);
    memcpy(key_out, normalized_key, sizeof(normalized_key));
    *payload_len_out = (size_t)stored_bytes;
    sqlite3_finalize(st);
    queue_state_unlock();
    return 1;
  }
  queue_state_unlock();
  return 0;
}

EdrError edr_storage_queue_p0_deferred_complete(const char *key_hex,
                                                 const char *batch_id,
                                                 const uint8_t *wire,
                                                 size_t wire_len,
                                                 const char *reason) {
  char key[65];
  sqlite3_stmt *st = NULL;
  int has_wire = batch_id != NULL || wire != NULL || wire_len != 0u;
  int inserted = 0;
  int rc;
  int compressed = 0;
  EdrError result = EDR_ERR_SQLITE_WRITE;
  if (!p0_deferred_key_normalize(key_hex, key) || !queue_text_valid(reason) ||
      (has_wire && (!queue_text_valid(batch_id) || !wire || wire_len == 0u ||
                    !terminal_wire_valid(wire, wire_len))) ||
      (!has_wire && (batch_id || wire || wire_len != 0u))) {
    return EDR_ERR_INVALID_ARG;
  }
  if (has_wire) compressed = rd_u32_le(wire) == EDR_TRANSPORT_BATCH_MAGIC_LZ4 ? 1 : 0;
  queue_state_lock();
  if (!s_db) {
    queue_state_unlock();
    return EDR_ERR_SQLITE_OPEN;
  }
  if (sqlite3_prepare_v2(s_db,
                         "SELECT state FROM p0_deferred_match WHERE key_sha256=?;",
                         -1, &st, NULL) != SQLITE_OK) {
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }
  sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  if (rc == SQLITE_ROW) {
    const unsigned char *state = sqlite3_column_text(st, 0);
    if (state && strcmp((const char *)state, "completed") == 0) {
      sqlite3_finalize(st);
      queue_state_unlock();
      return EDR_OK;
    }
    if (!state || strcmp((const char *)state, "pending") != 0) {
      sqlite3_finalize(st);
      queue_state_unlock();
      return EDR_ERR_INVALID_ARG;
    }
  } else {
    sqlite3_finalize(st);
    queue_state_unlock();
    return rc == SQLITE_DONE ? EDR_ERR_INVALID_ARG : EDR_ERR_SQLITE_WRITE;
  }
  sqlite3_finalize(st);
  st = NULL;
  if (p0_deferred_begin_durable_locked() != 0) {
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }
  if (sqlite3_prepare_v2(
          s_db,
          "UPDATE p0_deferred_match SET state='completed',payload=NULL,updated_at=?,"
          "completed_at=?,terminal_reason=?,last_error='' "
          "WHERE key_sha256=? AND state='pending';",
          -1, &st, NULL) != SQLITE_OK) {
    (void)p0_deferred_end_durable_locked(0);
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }
  sqlite3_bind_int64(st, 1, (sqlite3_int64)time(NULL));
  sqlite3_bind_int64(st, 2, (sqlite3_int64)time(NULL));
  sqlite3_bind_text(st, 3, reason, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 4, key, -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  {
    int changed = sqlite3_changes(s_db);
    sqlite3_finalize(st);
    st = NULL;
    if (rc != SQLITE_DONE || changed != 1) {
      (void)p0_deferred_end_durable_locked(0);
      queue_state_unlock();
      return EDR_ERR_SQLITE_WRITE;
    }
  }
  if (has_wire) {
    if (sqlite3_prepare_v2(
            s_db,
            "SELECT payload,compressed,severity,status FROM event_queue WHERE batch_id=?;",
            -1, &st, NULL) != SQLITE_OK) {
      (void)p0_deferred_end_durable_locked(0);
      queue_state_unlock();
      return EDR_ERR_SQLITE_WRITE;
    }
    sqlite3_bind_text(st, 1, batch_id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
      const void *old_wire = sqlite3_column_blob(st, 0);
      int old_len = sqlite3_column_bytes(st, 0);
      const unsigned char *status = sqlite3_column_text(st, 3);
      int exact = old_wire && old_len == (int)wire_len &&
          memcmp(old_wire, wire, wire_len) == 0 &&
          sqlite3_column_int(st, 1) == compressed &&
          sqlite3_column_int(st, 2) == EDR_STORAGE_QUEUE_SEVERITY_TERMINAL &&
          status && strcmp((const char *)status, "pending") == 0;
      sqlite3_finalize(st);
      st = NULL;
      if (!exact) {
        (void)p0_deferred_end_durable_locked(0);
        queue_state_unlock();
        return EDR_ERR_INVALID_ARG;
      }
    } else if (rc == SQLITE_DONE) {
      sqlite3_finalize(st);
      st = NULL;
      if (!queue_capacity_admit_locked(queue_event_live_cost(batch_id, wire_len),
                                       QUEUE_CAPACITY_TERMINAL)) {
        (void)p0_deferred_end_durable_locked(0);
        queue_state_unlock();
        return EDR_ERR_QUEUE_FULL;
      }
      if (sqlite3_prepare_v2(
              s_db,
              "INSERT INTO event_queue(batch_id,payload,created_at,compressed,severity,status) "
              "VALUES(?,?,?,?,1,'pending');",
              -1, &st, NULL) != SQLITE_OK) {
        (void)p0_deferred_end_durable_locked(0);
        queue_state_unlock();
        return EDR_ERR_SQLITE_WRITE;
      }
      sqlite3_bind_text(st, 1, batch_id, -1, SQLITE_TRANSIENT);
      sqlite3_bind_blob(st, 2, wire, (int)wire_len, SQLITE_TRANSIENT);
      sqlite3_bind_int64(st, 3, (sqlite3_int64)time(NULL));
      sqlite3_bind_int(st, 4, compressed);
      rc = sqlite3_step(st);
      sqlite3_finalize(st);
      st = NULL;
      if (rc != SQLITE_DONE) {
        (void)p0_deferred_end_durable_locked(0);
        queue_state_unlock();
        return EDR_ERR_SQLITE_WRITE;
      }
      inserted = 1;
    } else {
      sqlite3_finalize(st);
      (void)p0_deferred_end_durable_locked(0);
      queue_state_unlock();
      return EDR_ERR_SQLITE_WRITE;
    }
  }
  if (p0_deferred_end_durable_locked(1) == 0) {
    if (inserted) s_pending++;
    result = EDR_OK;
  } else {
    (void)p0_deferred_end_durable_locked(0);
  }
  queue_state_unlock();
  return result;
}

EdrError edr_storage_queue_p0_deferred_fail(const char *key_hex,
                                             const char *reason) {
  char key[65];
  sqlite3_stmt *st = NULL;
  int rc;
  if (!p0_deferred_key_normalize(key_hex, key) || !queue_text_valid(reason))
    return EDR_ERR_INVALID_ARG;
  queue_state_lock();
  if (!s_db) {
    queue_state_unlock();
    return EDR_ERR_SQLITE_OPEN;
  }
  if (sqlite3_prepare_v2(s_db,
                         "SELECT rowid,state FROM p0_deferred_match WHERE key_sha256=?;",
                         -1, &st, NULL) != SQLITE_OK) {
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }
  sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  if (rc == SQLITE_ROW) {
    sqlite3_int64 row_id = sqlite3_column_int64(st, 0);
    const unsigned char *state = sqlite3_column_text(st, 1);
    if (state && strcmp((const char *)state, "failed") == 0) {
      sqlite3_finalize(st);
      queue_state_unlock();
      return EDR_OK;
    }
    if (!state || strcmp((const char *)state, "pending") != 0) {
      sqlite3_finalize(st);
      queue_state_unlock();
      return EDR_ERR_INVALID_ARG;
    }
    sqlite3_finalize(st);
    rc = p0_deferred_mark_failed_by_id_locked(row_id, reason);
    queue_state_unlock();
    return rc == 0 ? EDR_OK : EDR_ERR_SQLITE_WRITE;
  }
  sqlite3_finalize(st);
  queue_state_unlock();
  return rc == SQLITE_DONE ? EDR_ERR_INVALID_ARG : EDR_ERR_SQLITE_WRITE;
}

EdrError edr_storage_queue_p0_deferred_retry(const char *key_hex,
                                              const char *reason) {
  char key[65];
  sqlite3_stmt *st = NULL;
  sqlite3_int64 retry_count;
  sqlite3_int64 next_count;
  sqlite3_int64 delay;
  int rc;
  if (!p0_deferred_key_normalize(key_hex, key) || !queue_text_valid(reason))
    return EDR_ERR_INVALID_ARG;
  queue_state_lock();
  if (!s_db) {
    queue_state_unlock();
    return EDR_ERR_SQLITE_OPEN;
  }
  if (sqlite3_prepare_v2(s_db,
                         "SELECT retry_count FROM p0_deferred_match "
                         "WHERE key_sha256=? AND state='pending';",
                         -1, &st, NULL) != SQLITE_OK) {
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }
  sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  if (rc != SQLITE_ROW) {
    sqlite3_finalize(st);
    queue_state_unlock();
    return rc == SQLITE_DONE ? EDR_ERR_INVALID_ARG : EDR_ERR_SQLITE_WRITE;
  }
  retry_count = sqlite3_column_int64(st, 0);
  sqlite3_finalize(st);
  if (retry_count < 0 || retry_count == INT64_MAX) {
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }
  next_count = retry_count + 1;
  delay = retry_count >= 6 ? 60 : ((sqlite3_int64)1 << retry_count);
  if (delay > 60) delay = 60;
  if (p0_deferred_begin_durable_locked() != 0 ||
      sqlite3_prepare_v2(
          s_db,
          "UPDATE p0_deferred_match SET retry_count=?,next_retry_at=?,last_error=?,updated_at=? "
          "WHERE key_sha256=? AND state='pending';",
          -1, &st, NULL) != SQLITE_OK) {
    (void)p0_deferred_end_durable_locked(0);
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }
  sqlite3_bind_int64(st, 1, next_count);
  sqlite3_bind_int64(st, 2, (sqlite3_int64)time(NULL) + delay);
  sqlite3_bind_text(st, 3, reason, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 4, (sqlite3_int64)time(NULL));
  sqlite3_bind_text(st, 5, key, -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  {
    int changed = sqlite3_changes(s_db);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE || changed != 1 || p0_deferred_end_durable_locked(1) != 0) {
      (void)p0_deferred_end_durable_locked(0);
      queue_state_unlock();
      return EDR_ERR_SQLITE_WRITE;
    }
  }
  queue_state_unlock();
  return EDR_OK;
}

/* The only severity-2 insert path that may discharge a prepared/recovery
 * latch. Event queue insertion and its meta binding are one FULL transaction;
 * a crash before commit leaves the latch recovery-required rather than making
 * a locally accepted source look centrally acknowledged. */
EdrError edr_storage_queue_p0_source_only_enqueue_bound(
    const EdrStorageQueueP0SourceOnlyLatch *expected, const char *event_id,
    const char *batch_id, const uint8_t *payload, size_t payload_len,
    int compressed, int recovery_audit) {
  QueueMetaRow row;
  sqlite3_stmt *st = NULL;
  int existing = 0;
  int add_pending = 0;
  int should_bind = 0;
  int rc;
  EdrError result = EDR_ERR_SQLITE_WRITE;
  if (!expected || !expected->latched || !event_id || !event_id[0] || !batch_id ||
      !batch_id[0] || !payload || payload_len == 0u ||
      strlen(event_id) >= EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_EVENT_ID_MAX ||
      strlen(batch_id) >= EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_BATCH_ID_MAX) {
    return EDR_ERR_INVALID_ARG;
  }
  queue_state_lock();
  if (!s_db || queue_meta_read_locked(&row) != 0 || !queue_meta_matches_latch(&row, expected)) {
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }
  if (recovery_audit) {
    if (strcmp(row.latch_state, EDR_QUEUE_META_STATE_RECOVERY_REQUIRED) != 0) {
      queue_state_unlock();
      return EDR_ERR_INVALID_ARG;
    }
    should_bind = 1;
  } else if (strcmp(row.latch_state, EDR_QUEUE_META_STATE_PREPARED) == 0) {
    should_bind = 1;
  }

  /* Exact durable replay may bind a latch that survived a crash after the
   * event_queue INSERT but before its old process could update queue_meta. */
  if (sqlite3_prepare_v2(
          s_db,
          "SELECT payload,compressed,severity,status FROM event_queue WHERE batch_id=?;",
          -1, &st, NULL) != SQLITE_OK) {
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }
  sqlite3_bind_text(st, 1, batch_id, -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  if (rc == SQLITE_ROW) {
    const void *old_payload = sqlite3_column_blob(st, 0);
    int old_len = sqlite3_column_bytes(st, 0);
    int old_compressed = sqlite3_column_int(st, 1);
    int old_severity = sqlite3_column_int(st, 2);
    const unsigned char *old_status = sqlite3_column_text(st, 3);
    existing = old_payload && old_len == (int)payload_len &&
               memcmp(old_payload, payload, payload_len) == 0 &&
               old_compressed == (compressed ? 1 : 0) &&
               old_severity == EDR_STORAGE_QUEUE_SEVERITY_P0_SOURCE_ONLY &&
               old_status && strcmp((const char *)old_status, "pending") == 0;
    sqlite3_finalize(st);
    if (!existing) {
      queue_state_unlock();
      return EDR_ERR_INVALID_ARG;
    }
  } else if (rc == SQLITE_DONE) {
    sqlite3_finalize(st);
    st = NULL;
    if (!queue_capacity_admit_locked(queue_event_live_cost(batch_id, payload_len),
                                     QUEUE_CAPACITY_P0_SOURCE_ONLY)) {
      queue_state_unlock();
      return EDR_ERR_QUEUE_FULL;
    }
    add_pending = 1;
  } else {
    sqlite3_finalize(st);
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }

  if (queue_p0_latch_begin_durable_locked() != 0) {
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }
  if (add_pending) {
    if (sqlite3_prepare_v2(
            s_db,
            "INSERT INTO event_queue(batch_id,payload,created_at,compressed,severity,status) "
            "VALUES(?,?,?,?,2,'pending');",
            -1, &st, NULL) != SQLITE_OK) {
      (void)queue_p0_latch_end_durable_locked(0);
      queue_state_unlock();
      return EDR_ERR_SQLITE_WRITE;
    }
    sqlite3_bind_text(st, 1, batch_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 2, payload, (int)payload_len, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)time(NULL));
    sqlite3_bind_int(st, 4, compressed ? 1 : 0);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    st = NULL;
    if (rc != SQLITE_DONE) {
      (void)queue_p0_latch_end_durable_locked(0);
      queue_state_unlock();
      return EDR_ERR_SQLITE_WRITE;
    }
  }
  if (should_bind) {
    snprintf(row.latch_state, sizeof(row.latch_state), "%s", EDR_QUEUE_META_STATE_BOUND);
    row.loss_detected = 0;
    snprintf(row.recovery_event_id, sizeof(row.recovery_event_id), "%s", event_id);
    snprintf(row.recovery_batch_id, sizeof(row.recovery_batch_id), "%s", batch_id);
    row.last_error[0] = '\0';
  }
  if (queue_meta_write_locked(&row) != 0 || queue_p0_latch_end_durable_locked(1) != 0) {
    (void)queue_p0_latch_end_durable_locked(0);
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }
  if (add_pending) s_pending++;
  result = EDR_OK;
  queue_state_unlock();
  return result;
}

static int terminal_text_valid(const char *value) { return queue_text_valid(value); }

static int terminal_sql_text_equal(const unsigned char *stored, int stored_len,
                                   const char *incoming) {
  size_t incoming_len;
  if (!queue_sql_text_valid(stored, stored_len) || !terminal_text_valid(incoming)) return 0;
  incoming_len = strlen(incoming);
  return incoming_len == (size_t)stored_len && memcmp(stored, incoming, incoming_len) == 0;
}

static int terminal_blob_equal(const void *stored, int stored_len, const uint8_t *incoming,
                               size_t incoming_len) {
  return stored && incoming && stored_len >= 0 && (size_t)stored_len == incoming_len &&
         memcmp(stored, incoming, incoming_len) == 0;
}

/* The normal idempotency-key lookup is intentionally exact. If a corrupted
 * SQLite TEXT owner can no longer be represented by that C string, this
 * indexed immutable digest is the only safe alternative to creating a second
 * owner and re-executing its action. */
static int terminal_journal_owner_digest_conflict_locked(
    const char owner_digest[EDR_TERMINAL_OWNER_DIGEST_HEX_LEN + 1u],
    int *newly_quarantined) {
  sqlite3_stmt *scan = NULL;
  sqlite3_stmt *quarantine = NULL;
  sqlite3_int64 id = 0;
  int raw_owner_invalid = 0;
  int found = 0;
  int step;

  if (newly_quarantined) *newly_quarantined = 0;
  if (!s_db || !owner_digest ||
      sqlite3_prepare_v2(
          s_db,
          "SELECT id,idempotency_key FROM enforcement_terminal_journal "
          "WHERE owner_key_sha256=?;",
          -1, &scan, NULL) != SQLITE_OK) {
    return -1;
  }
  sqlite3_bind_text(scan, 1, owner_digest, EDR_TERMINAL_OWNER_DIGEST_HEX_LEN,
                    SQLITE_TRANSIENT);
  while ((step = sqlite3_step(scan)) == SQLITE_ROW) {
    const unsigned char *raw_key = sqlite3_column_text(scan, 1);
    int raw_key_len = sqlite3_column_bytes(scan, 1);
    id = sqlite3_column_int64(scan, 0);
    raw_owner_invalid = !queue_sql_text_valid(raw_key, raw_key_len);
    /* A valid but different key with the same immutable digest is either an
     * impossible hash collision or durable tampering. Both must resolve as a
     * conflict rather than authorize another action. */
    found = 1;
    break;
  }
  sqlite3_finalize(scan);
  if (!found) return step == SQLITE_DONE ? 0 : -1;
  if (!raw_owner_invalid) return 1;

  if (sqlite3_prepare_v2(
          s_db,
          "UPDATE enforcement_terminal_journal SET state='failed',reserved_bytes=0,"
          "last_error='owner_durable_metadata_invalid',updated_at=? "
          "WHERE id=? AND state<>'failed';",
          -1, &quarantine, NULL) != SQLITE_OK) {
    return -1;
  }
  sqlite3_bind_int64(quarantine, 1, (sqlite3_int64)time(NULL));
  sqlite3_bind_int64(quarantine, 2, id);
  step = sqlite3_step(quarantine);
  if (step == SQLITE_DONE && sqlite3_changes(s_db) == 1 && newly_quarantined) {
    *newly_quarantined = 1;
  }
  sqlite3_finalize(quarantine);
  return step == SQLITE_DONE ? 1 : -1;
}

EdrEnforcementTerminalPrecreate edr_storage_queue_enforcement_terminal_precreate(
    const char *idempotency_key, const char *source_event_key, const char *rule_id,
    const char *process_generation_key, const char *intent_batch_id, const uint8_t *intent_wire,
    size_t intent_wire_len) {
  sqlite3_stmt *st = NULL;
  EdrEnforcementTerminalPrecreate result = EDR_ENFORCEMENT_TERMINAL_PRECREATE_ERROR;
  int commit = 0;
  int step;
  int rejected = 0;
  int owner_corruption_blocked = 0;
  int owner_unresolved;
  char owner_digest[EDR_TERMINAL_OWNER_DIGEST_HEX_LEN + 1u];
  if (!terminal_text_valid(idempotency_key) || !terminal_text_valid(source_event_key) ||
      !terminal_text_valid(rule_id) || !terminal_text_valid(process_generation_key) ||
      !terminal_text_valid(intent_batch_id) || !terminal_wire_valid(intent_wire, intent_wire_len) ||
      !terminal_owner_digest_from_key(idempotency_key, owner_digest)) {
    return EDR_ENFORCEMENT_TERMINAL_PRECREATE_ERROR;
  }
  queue_state_lock();
  if (!s_db) {
    queue_state_unlock();
    return EDR_ENFORCEMENT_TERMINAL_PRECREATE_ERROR;
  }
  s_terminal_precreate_requests++;
  s_terminal_precreate_attempts++;
  owner_unresolved = terminal_journal_owner_corruption_unresolved_locked();
  if (owner_unresolved != 0) {
    if (owner_unresolved > 0) {
      s_terminal_precreate_rejected++;
      s_terminal_precreate_metadata_corruption_failures++;
    } else {
      s_terminal_precreate_transaction_failures++;
    }
    queue_state_unlock();
    return EDR_ENFORCEMENT_TERMINAL_PRECREATE_ERROR;
  }
  if (terminal_journal_begin_durable_locked() != 0) {
    s_terminal_precreate_transaction_failures++;
    queue_state_unlock();
    return EDR_ENFORCEMENT_TERMINAL_PRECREATE_ERROR;
  }

  /* Exact replays are admitted even while the bounded pending journal is full;
   * only a new terminal owner consumes another slot. The select and insert are
   * one FULL-synchronous transaction, so no action can run without its intent
   * wire surviving a process crash. */
  if (sqlite3_prepare_v2(
          s_db,
          "SELECT source_event_key,rule_id,process_generation_key,intent_batch_id,intent_wire,state "
          "FROM enforcement_terminal_journal WHERE idempotency_key=?;",
          -1, &st, NULL) != SQLITE_OK) {
    (void)terminal_journal_end_durable_locked(0);
    s_terminal_precreate_transaction_failures++;
    queue_state_unlock();
    return EDR_ENFORCEMENT_TERMINAL_PRECREATE_ERROR;
  }
  sqlite3_bind_text(st, 1, idempotency_key, -1, SQLITE_TRANSIENT);
  step = sqlite3_step(st);
  if (step == SQLITE_ROW) {
    const unsigned char *stored_source = sqlite3_column_text(st, 0);
    int stored_source_len = sqlite3_column_bytes(st, 0);
    const unsigned char *stored_rule = sqlite3_column_text(st, 1);
    int stored_rule_len = sqlite3_column_bytes(st, 1);
    const unsigned char *stored_generation = sqlite3_column_text(st, 2);
    int stored_generation_len = sqlite3_column_bytes(st, 2);
    const unsigned char *stored_intent_id = sqlite3_column_text(st, 3);
    int stored_intent_id_len = sqlite3_column_bytes(st, 3);
    const void *stored_intent_wire = sqlite3_column_blob(st, 4);
    int stored_intent_len = sqlite3_column_bytes(st, 4);
    const unsigned char *state = sqlite3_column_text(st, 5);
    int state_len = sqlite3_column_bytes(st, 5);
    int was_pending = terminal_sql_text_equal(state, state_len, "pending_intent");
    int exact = queue_sql_text_valid(state, state_len) &&
                terminal_sql_text_equal(stored_source, stored_source_len, source_event_key) &&
                terminal_sql_text_equal(stored_rule, stored_rule_len, rule_id) &&
                terminal_sql_text_equal(stored_generation, stored_generation_len,
                                        process_generation_key) &&
                terminal_sql_text_equal(stored_intent_id, stored_intent_id_len, intent_batch_id) &&
                terminal_blob_equal(stored_intent_wire, stored_intent_len, intent_wire,
                                    intent_wire_len);
    sqlite3_finalize(st);
    st = NULL;
    if (!exact) {
      result = EDR_ENFORCEMENT_TERMINAL_PRECREATE_CONFLICT;
    } else if (was_pending) {
      if (sqlite3_prepare_v2(
              s_db,
              "UPDATE enforcement_terminal_journal SET state='outcome_unknown',"
              "last_error='outcome_unknown_not_replayed',updated_at=? "
              "WHERE idempotency_key=? AND state='pending_intent';",
              -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)time(NULL));
        sqlite3_bind_text(st, 2, idempotency_key, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(s_db) == 1) {
          result = EDR_ENFORCEMENT_TERMINAL_PRECREATE_EXISTING;
          commit = 1;
        }
        sqlite3_finalize(st);
        st = NULL;
      }
    } else {
      result = EDR_ENFORCEMENT_TERMINAL_PRECREATE_EXISTING;
      commit = 1;
    }
  } else if (step == SQLITE_DONE) {
    sqlite3_finalize(st);
    st = NULL;
    {
      int owner_quarantined = 0;
      int owner_conflict = terminal_journal_owner_digest_conflict_locked(
          owner_digest, &owner_quarantined);
      if (owner_conflict < 0) {
        result = EDR_ENFORCEMENT_TERMINAL_PRECREATE_ERROR;
      } else if (owner_conflict > 0) {
        /* Never downgrade a corrupt owner to "missing": CONFLICT is the
         * executor-visible no-reexecution outcome. */
        result = EDR_ENFORCEMENT_TERMINAL_PRECREATE_CONFLICT;
        commit = owner_quarantined;
        owner_corruption_blocked = 1;
      } else {
        terminal_journal_refresh_locked();
        if (s_terminal_pending >= EDR_ENFORCEMENT_TERMINAL_MAX_PENDING) {
          s_terminal_backpressure++;
          rejected = 1;
        } else if (!queue_capacity_admit_locked(
                       queue_terminal_precreate_live_cost(
                           idempotency_key, source_event_key, rule_id, process_generation_key,
                           intent_batch_id, intent_wire_len),
                       QUEUE_CAPACITY_TERMINAL)) {
          /* Pre-action capacity is a hard safety boundary: do not create an
           * executor owner if the intent and both eventual result frames cannot
           * coexist durably with all already-pending evidence. */
          s_terminal_backpressure++;
          rejected = 1;
        } else if (sqlite3_prepare_v2(
                       s_db,
                       "INSERT INTO enforcement_terminal_journal("
                       "idempotency_key,owner_key_sha256,source_event_key,rule_id,"
                       "process_generation_key,state,intent_batch_id,intent_wire,intent_acked,"
                       "intent_retry_count,reserved_bytes,created_at,updated_at) "
                       "VALUES(?,?,?,?,?, 'pending_intent', ?, ?, 0, 0, ?, ?, ?);",
                       -1, &st, NULL) == SQLITE_OK) {
          sqlite3_int64 now = (sqlite3_int64)time(NULL);
          sqlite3_bind_text(st, 1, idempotency_key, -1, SQLITE_TRANSIENT);
          sqlite3_bind_text(st, 2, owner_digest, -1, SQLITE_TRANSIENT);
          sqlite3_bind_text(st, 3, source_event_key, -1, SQLITE_TRANSIENT);
          sqlite3_bind_text(st, 4, rule_id, -1, SQLITE_TRANSIENT);
          sqlite3_bind_text(st, 5, process_generation_key, -1, SQLITE_TRANSIENT);
          sqlite3_bind_text(st, 6, intent_batch_id, -1, SQLITE_TRANSIENT);
          sqlite3_bind_blob(st, 7, intent_wire, (int)intent_wire_len, SQLITE_TRANSIENT);
          sqlite3_bind_int64(st, 8, (sqlite3_int64)EDR_TERMINAL_FINAL_RESERVE_BYTES);
          sqlite3_bind_int64(st, 9, now);
          sqlite3_bind_int64(st, 10, now);
          if (sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(s_db) == 1) {
            result = EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED;
            commit = 1;
          }
          sqlite3_finalize(st);
          st = NULL;
        }
      }
    }
  } else {
    sqlite3_finalize(st);
    st = NULL;
  }
  if (st) sqlite3_finalize(st);
  if (terminal_journal_end_durable_locked(commit) != 0 && commit) {
    result = EDR_ENFORCEMENT_TERMINAL_PRECREATE_ERROR;
    s_terminal_precreate_commit_failures++;
  }
  if (commit && result != EDR_ENFORCEMENT_TERMINAL_PRECREATE_ERROR) {
    terminal_journal_refresh_locked();
  }
  if (result == EDR_ENFORCEMENT_TERMINAL_PRECREATE_CREATED) {
    s_terminal_precreate_created++;
  } else if (result == EDR_ENFORCEMENT_TERMINAL_PRECREATE_EXISTING) {
    s_terminal_precreate_existing++;
  } else if (result == EDR_ENFORCEMENT_TERMINAL_PRECREATE_CONFLICT) {
    s_terminal_precreate_conflicts++;
    if (owner_corruption_blocked) s_terminal_precreate_metadata_corruption_failures++;
  } else if (rejected) {
    s_terminal_precreate_rejected++;
  } else {
    s_terminal_precreate_transaction_failures++;
  }
  queue_state_unlock();
  return result;
}

EdrError edr_storage_queue_enforcement_terminal_update(
    const char *idempotency_key, const char *source_batch_id, const uint8_t *source_wire,
    size_t source_wire_len, const char *combined_batch_id, const uint8_t *combined_wire,
    size_t combined_wire_len) {
  sqlite3_stmt *st = NULL;
  EdrError result = EDR_ERR_SQLITE_WRITE;
  int commit = 0;
  if (!terminal_text_valid(idempotency_key) || !terminal_text_valid(source_batch_id) ||
      !terminal_text_valid(combined_batch_id) || !terminal_wire_valid(source_wire, source_wire_len) ||
      !terminal_wire_valid(combined_wire, combined_wire_len)) {
    return EDR_ERR_INVALID_ARG;
  }
  queue_state_lock();
  if (!s_db || terminal_journal_begin_durable_locked() != 0) {
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }
  if (sqlite3_prepare_v2(
          s_db,
          "SELECT state,source_batch_id,source_wire,combined_batch_id,combined_wire,reserved_bytes "
          "FROM enforcement_terminal_journal WHERE idempotency_key=?;",
          -1, &st, NULL) != SQLITE_OK) {
    terminal_journal_end_durable_locked(0);
    queue_state_unlock();
    return EDR_ERR_SQLITE_WRITE;
  }
  sqlite3_bind_text(st, 1, idempotency_key, -1, SQLITE_TRANSIENT);
  if (sqlite3_step(st) == SQLITE_ROW) {
    const unsigned char *state = sqlite3_column_text(st, 0);
    int state_len = sqlite3_column_bytes(st, 0);
    const unsigned char *stored_source_id = sqlite3_column_text(st, 1);
    int stored_source_id_len = sqlite3_column_bytes(st, 1);
    const void *stored_source_wire = sqlite3_column_blob(st, 2);
    int stored_source_len = sqlite3_column_bytes(st, 2);
    const unsigned char *stored_combined_id = sqlite3_column_text(st, 3);
    int stored_combined_id_len = sqlite3_column_bytes(st, 3);
    const void *stored_combined_wire = sqlite3_column_blob(st, 4);
    int stored_combined_len = sqlite3_column_bytes(st, 4);
    sqlite3_int64 stored_reservation = sqlite3_column_int64(st, 5);
    if (terminal_sql_text_equal(state, state_len, "pending_intent") ||
        terminal_sql_text_equal(state, state_len, "outcome_unknown")) {
      uint64_t final_cost = queue_terminal_final_live_cost(
          source_batch_id, source_wire_len, combined_batch_id, combined_wire_len);
      uint64_t reservation = stored_reservation > 0 ? (uint64_t)stored_reservation : 0u;
      uint64_t additional = final_cost > reservation ? final_cost - reservation : 0u;
      sqlite3_finalize(st);
      st = NULL;
      if (final_cost == UINT64_MAX ||
          (additional > 0u && !queue_capacity_admit_locked(
                                  additional, QUEUE_CAPACITY_TERMINAL))) {
        if (additional > 0u) s_terminal_backpressure++;
        result = EDR_ERR_QUEUE_FULL;
      } else if (sqlite3_prepare_v2(
              s_db,
              "UPDATE enforcement_terminal_journal SET state='ready',source_batch_id=?,source_wire=?,"
              "source_acked=0,source_retry_count=0,combined_batch_id=?,combined_wire=?,"
              "combined_acked=0,combined_retry_count=0,reserved_bytes=0,last_error='',updated_at=? "
              "WHERE idempotency_key=? AND state IN ('pending_intent','outcome_unknown');",
              -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, source_batch_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 2, source_wire, (int)source_wire_len, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, combined_batch_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 4, combined_wire, (int)combined_wire_len, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 5, (sqlite3_int64)time(NULL));
        sqlite3_bind_text(st, 6, idempotency_key, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(s_db) == 1) {
          result = EDR_OK;
          commit = 1;
        }
        sqlite3_finalize(st);
        st = NULL;
      }
    } else if (queue_sql_text_valid(state, state_len) &&
               terminal_sql_text_equal(stored_source_id, stored_source_id_len,
                                       source_batch_id) &&
               terminal_sql_text_equal(stored_combined_id, stored_combined_id_len,
                                       combined_batch_id) &&
               terminal_blob_equal(stored_source_wire, stored_source_len, source_wire, source_wire_len) &&
               terminal_blob_equal(stored_combined_wire, stored_combined_len, combined_wire,
                                   combined_wire_len)) {
      result = EDR_OK;
      commit = 1;
      sqlite3_finalize(st);
      st = NULL;
    } else {
      result = EDR_ERR_INVALID_ARG;
      sqlite3_finalize(st);
      st = NULL;
    }
  } else {
    sqlite3_finalize(st);
    st = NULL;
    result = EDR_ERR_INVALID_ARG;
  }
  if (terminal_journal_end_durable_locked(commit) != 0 && commit) {
    result = EDR_ERR_SQLITE_WRITE;
  }
  if (result == EDR_OK && commit) terminal_journal_refresh_locked();
  queue_state_unlock();
  return result;
}

void edr_storage_queue_enforcement_terminal_get_metrics(
    EdrEnforcementTerminalJournalMetrics *out) {
  if (!out) return;
  memset(out, 0, sizeof(*out));
  queue_state_lock();
  terminal_journal_refresh_locked();
  out->pending = s_terminal_pending;
  out->backpressure = s_terminal_backpressure;
  out->failed = s_terminal_failed;
  out->precreate_requests = s_terminal_precreate_requests;
  out->precreate_attempts = s_terminal_precreate_attempts;
  out->precreate_created = s_terminal_precreate_created;
  out->precreate_existing = s_terminal_precreate_existing;
  out->precreate_conflicts = s_terminal_precreate_conflicts;
  out->precreate_rejected = s_terminal_precreate_rejected;
  out->precreate_transaction_failures = s_terminal_precreate_transaction_failures;
  out->precreate_commit_failures = s_terminal_precreate_commit_failures;
  out->precreate_metadata_corruption_failures =
      s_terminal_precreate_metadata_corruption_failures;
  out->owner_metadata_unresolved =
      terminal_journal_owner_corruption_unresolved_locked() == 0 ? 0u : 1u;
  out->outcome_unknown = s_terminal_outcome_unknown;
  out->replay_selection_transient_failures =
      s_terminal_replay_selection_transient_failures;
  out->replay_metadata_corruption_failures =
      s_terminal_replay_metadata_corruption_failures;
  queue_state_unlock();
}

void edr_storage_queue_get_capacity_metrics(EdrStorageQueueCapacityMetrics *out) {
  if (!out) return;
  queue_state_lock();
  queue_capacity_snapshot_locked(out);
  queue_state_unlock();
}

uint64_t edr_storage_queue_pending_count(void) {
  uint64_t pending;
  queue_state_lock();
  pending = s_pending;
  queue_state_unlock();
  return pending;
}

uint64_t edr_storage_queue_dead_letter_count(void) {
  uint64_t count = 0u;
  sqlite3_stmt *st = NULL;
  queue_state_lock();
  if (s_db && sqlite3_prepare_v2(s_db,
                                 "SELECT COUNT(*) FROM event_queue WHERE status='dead_letter';",
                                 -1, &st, NULL) == SQLITE_OK) {
    if (sqlite3_step(st) == SQLITE_ROW) count = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
  }
  queue_state_unlock();
  return count;
}

static void terminal_journal_fail_frame_locked(sqlite3 *db, sqlite3_int64 id, const char *key,
                                               int source_frame, const char *reason) {
  sqlite3_stmt *st = NULL;
  const char *sql =
      "UPDATE enforcement_terminal_journal SET state='failed',reserved_bytes=0,"
      "last_error=?,updated_at=? "
      "WHERE id=? AND idempotency_key=? AND state='ready';";
  if (!db || !key) return;
  if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
    char bounded_reason[96];
    snprintf(bounded_reason, sizeof(bounded_reason), "%s_%s",
             source_frame ? "source" : "combined", reason ? reason : "failed");
    sqlite3_bind_text(st, 1, bounded_reason, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)time(NULL));
    sqlite3_bind_int64(st, 3, id);
    sqlite3_bind_text(st, 4, key, -1, SQLITE_TRANSIENT);
    (void)sqlite3_step(st);
    sqlite3_finalize(st);
  }
  terminal_journal_refresh_locked();
}

static void terminal_journal_fail_intent_locked(sqlite3 *db, sqlite3_int64 id, const char *key,
                                                const char *reason) {
  sqlite3_stmt *st = NULL;
  const char *sql =
      "UPDATE enforcement_terminal_journal SET state='failed',reserved_bytes=0,"
      "last_error=?,updated_at=? "
      "WHERE id=? AND idempotency_key=? AND state IN ('pending_intent','outcome_unknown');";
  if (!db || !key) return;
  if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
    char bounded_reason[96];
    snprintf(bounded_reason, sizeof(bounded_reason), "intent_%s",
             reason ? reason : "invalid_durable_wire");
    sqlite3_bind_text(st, 1, bounded_reason, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)time(NULL));
    sqlite3_bind_int64(st, 3, id);
    sqlite3_bind_text(st, 4, key, -1, SQLITE_TRANSIENT);
    (void)sqlite3_step(st);
    sqlite3_finalize(st);
  }
  terminal_journal_refresh_locked();
}

static void terminal_journal_bump_intent_retry_locked(sqlite3 *db, sqlite3_int64 id,
                                                       const char *key, const uint8_t *wire,
                                                       int wire_len) {
  sqlite3_stmt *st = NULL;
  const char *sql =
      "UPDATE enforcement_terminal_journal SET intent_retry_count=intent_retry_count+1,"
      "last_error='intent_transport_failed',updated_at=? "
      "WHERE id=? AND idempotency_key=? AND state IN ('pending_intent','outcome_unknown') "
      "AND intent_acked=0 AND intent_wire=?;";
  if (!db || !key || !wire || wire_len <= 0) return;
  if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_int64(st, 1, (sqlite3_int64)time(NULL));
    sqlite3_bind_int64(st, 2, id);
    sqlite3_bind_text(st, 3, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 4, wire, wire_len, SQLITE_TRANSIENT);
    (void)sqlite3_step(st);
    sqlite3_finalize(st);
  }
}

static int terminal_journal_ack_intent_locked(sqlite3 *db, sqlite3_int64 id, const char *key,
                                              const uint8_t *wire, int wire_len) {
  sqlite3_stmt *st = NULL;
  int acknowledged = 0;
  const char *sql =
      "UPDATE enforcement_terminal_journal SET intent_acked=1,last_error='',updated_at=? "
      "WHERE id=? AND idempotency_key=? AND state IN ('pending_intent','outcome_unknown') "
      "AND intent_acked=0 AND intent_wire=?;";
  if (!db || !key || !wire || wire_len <= 0) return 0;
  if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_int64(st, 1, (sqlite3_int64)time(NULL));
    sqlite3_bind_int64(st, 2, id);
    sqlite3_bind_text(st, 3, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 4, wire, wire_len, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(db) == 1) acknowledged = 1;
    sqlite3_finalize(st);
  }
  if (acknowledged) terminal_journal_refresh_locked();
  return acknowledged;
}

static void terminal_journal_bump_frame_retry_locked(sqlite3 *db, sqlite3_int64 id,
                                                      const char *key, int source_frame,
                                                      const uint8_t *wire, int wire_len) {
  sqlite3_stmt *st = NULL;
  const char *sql = source_frame
                        ? "UPDATE enforcement_terminal_journal SET "
                          "source_retry_count=source_retry_count+1,last_error='source_transport_failed',"
                          "updated_at=? WHERE id=? AND idempotency_key=? AND state='ready' "
                          "AND source_acked=0 AND source_wire=?;"
                        : "UPDATE enforcement_terminal_journal SET "
                          "combined_retry_count=combined_retry_count+1,last_error='combined_transport_failed',"
                          "updated_at=? WHERE id=? AND idempotency_key=? AND state='ready' "
                          "AND combined_acked=0 AND combined_wire=?;";
  if (!db || !key || !wire || wire_len <= 0) return;
  if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_int64(st, 1, (sqlite3_int64)time(NULL));
    sqlite3_bind_int64(st, 2, id);
    sqlite3_bind_text(st, 3, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 4, wire, wire_len, SQLITE_TRANSIENT);
    (void)sqlite3_step(st);
    sqlite3_finalize(st);
  }
}

/* A selected frame can be durable and valid while allocation or SQLite's
 * read path is briefly unavailable. This update intentionally identifies the
 * row by its immutable id rather than a copied key/wire, so the failure does
 * not need the very allocation that failed. It never changes terminal state.
 */
static void terminal_journal_note_selection_transient_locked(sqlite3 *db,
                                                              sqlite3_int64 id,
                                                              int frame_kind) {
  sqlite3_stmt *st = NULL;
  const char *sql = frame_kind == 0
                        ? "UPDATE enforcement_terminal_journal SET "
                          "intent_retry_count=intent_retry_count+1,"
                          "last_error='intent_selection_transient',updated_at=? "
                          "WHERE id=? AND state IN ('pending_intent','outcome_unknown') "
                          "AND intent_acked=0;"
                        : frame_kind == 1
                            ? "UPDATE enforcement_terminal_journal SET "
                              "source_retry_count=source_retry_count+1,"
                              "last_error='source_selection_transient',updated_at=? "
                              "WHERE id=? AND state='ready' AND source_acked=0;"
                            : "UPDATE enforcement_terminal_journal SET "
                              "combined_retry_count=combined_retry_count+1,"
                              "last_error='combined_selection_transient',updated_at=? "
                              "WHERE id=? AND state='ready' AND combined_acked=0;";
  if (!db || id <= 0 || frame_kind < 0 || frame_kind > 2) return;
  if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_int64(st, 1, (sqlite3_int64)time(NULL));
    sqlite3_bind_int64(st, 2, id);
    (void)sqlite3_step(st);
    sqlite3_finalize(st);
  }
}

/* Required idempotency/batch metadata is part of a terminal frame's durable
 * identity. If it is absent on disk, no safe retry key exists and leaving the
 * oldest row pending would permanently starve every later frame. Quarantine
 * by immutable row id; unlike allocation/SQLite selection failures this is
 * corruption, not a transient local resource condition. */
static int terminal_journal_quarantine_metadata_locked(sqlite3 *db,
                                                        sqlite3_int64 id,
                                                        int frame_kind) {
  sqlite3_stmt *st = NULL;
  const char *sql = frame_kind == 0
                        ? "UPDATE enforcement_terminal_journal SET state='failed',reserved_bytes=0,"
                          "last_error='intent_durable_metadata_invalid',updated_at=? "
                          "WHERE id=? AND state IN ('pending_intent','outcome_unknown') "
                          "AND intent_acked=0;"
                        : frame_kind == 1
                            ? "UPDATE enforcement_terminal_journal SET state='failed',reserved_bytes=0,"
                              "last_error='source_durable_metadata_invalid',updated_at=? "
                              "WHERE id=? AND state='ready' AND source_acked=0;"
                            : "UPDATE enforcement_terminal_journal SET state='failed',reserved_bytes=0,"
                              "last_error='combined_durable_metadata_invalid',updated_at=? "
                              "WHERE id=? AND state='ready' AND combined_acked=0;";
  int quarantined = 0;
  if (!db || id <= 0 || frame_kind < 0 || frame_kind > 2) return 0;
  if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_int64(st, 1, (sqlite3_int64)time(NULL));
    sqlite3_bind_int64(st, 2, id);
    if (sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(db) == 1) {
      quarantined = 1;
    }
    sqlite3_finalize(st);
  }
  if (quarantined) terminal_journal_refresh_locked();
  return quarantined;
}

static int terminal_journal_ack_frame_locked(sqlite3 *db, sqlite3_int64 id, const char *key,
                                             int source_frame, const uint8_t *wire, int wire_len) {
  sqlite3_stmt *st = NULL;
  const char *sql = source_frame
                        ? "UPDATE enforcement_terminal_journal SET source_acked=1,updated_at=?,"
                          "state=CASE WHEN combined_acked=1 THEN 'completed' ELSE 'ready' END,"
                          "completed_at=CASE WHEN combined_acked=1 THEN ? ELSE completed_at END,"
                          "reserved_bytes=CASE WHEN combined_acked=1 THEN 0 ELSE reserved_bytes END "
                          "WHERE id=? AND idempotency_key=? AND state='ready' AND source_acked=0 "
                          "AND source_wire=?;"
                        : "UPDATE enforcement_terminal_journal SET combined_acked=1,updated_at=?,"
                          "state=CASE WHEN source_acked=1 THEN 'completed' ELSE 'ready' END,"
                          "completed_at=CASE WHEN source_acked=1 THEN ? ELSE completed_at END,"
                          "reserved_bytes=CASE WHEN source_acked=1 THEN 0 ELSE reserved_bytes END "
                          "WHERE id=? AND idempotency_key=? AND state='ready' AND combined_acked=0 "
                          "AND combined_wire=?;";
  int acknowledged = 0;
  if (!db || !key || !wire || wire_len <= 0) return 0;
  if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
    sqlite3_int64 now = (sqlite3_int64)time(NULL);
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_int64(st, 2, now);
    sqlite3_bind_int64(st, 3, id);
    sqlite3_bind_text(st, 4, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 5, wire, wire_len, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(db) == 1) acknowledged = 1;
    sqlite3_finalize(st);
  }
  if (acknowledged) terminal_journal_refresh_locked();
  return acknowledged;
}

/* Returns 0 after consuming one state transition, 1 when no replayable frame
 * exists, and 2 after a transient selection/transport failure (caller stops
 * this drain pass). Allocation/SQLite read failures preserve durable state;
 * only impossible durable metadata or an invalid persisted wire becomes
 * terminally failed. */
static int drain_one_terminal_journal_frame(void) {
  static const char *const select_sql[3] = {
      "SELECT id,idempotency_key,intent_batch_id,intent_wire "
      "FROM enforcement_terminal_journal j "
      "WHERE state IN ('pending_intent','outcome_unknown') AND intent_acked=0 "
      "AND intent_wire IS NOT NULL AND NOT EXISTS (SELECT 1 FROM event_queue q "
      "WHERE q.batch_id=j.intent_batch_id AND q.status='pending') ORDER BY id ASC LIMIT 1;",
      "SELECT id,idempotency_key,source_batch_id,source_wire "
      "FROM enforcement_terminal_journal j WHERE state='ready' AND source_acked=0 "
      "AND source_wire IS NOT NULL AND NOT EXISTS (SELECT 1 FROM event_queue q "
      "WHERE q.batch_id=j.source_batch_id AND q.status='pending') ORDER BY id ASC LIMIT 1;",
      "SELECT id,idempotency_key,combined_batch_id,combined_wire "
      "FROM enforcement_terminal_journal j WHERE state='ready' AND combined_acked=0 "
      "AND combined_wire IS NOT NULL AND NOT EXISTS (SELECT 1 FROM event_queue q "
      "WHERE q.batch_id=j.combined_batch_id AND q.status='pending') ORDER BY id ASC LIMIT 1;"};
  sqlite3_stmt *st = NULL;
  sqlite3 *selected_db;
  sqlite3_int64 id = 0;
  uint64_t selected_generation;
  uint8_t *wire = NULL;
  char *key = NULL;
  char *batch_id = NULL;
  int wire_len = 0;
  int frame_kind = -1; /* 0=intent, 1=source/result, 2=combined alert */
  int selected = 0;
  int selection_transient = 0;
  int durable_wire_invalid = 0;
  int durable_metadata_invalid = 0;
  int allocation_failed = 0;

  queue_state_lock();
  if (!s_db) {
    queue_state_unlock();
    return 1;
  }
  selected_db = s_db;
  selected_generation = s_db_generation;
  for (frame_kind = 0; frame_kind < 3; frame_kind++) {
    if (sqlite3_prepare_v2(s_db, select_sql[frame_kind], -1, &st, NULL) != SQLITE_OK) {
      s_terminal_replay_selection_transient_failures++;
      queue_state_unlock();
      return 2;
    }
    int step_rc = sqlite3_step(st);
    if (step_rc == SQLITE_ROW) {
      const unsigned char *stored_key = sqlite3_column_text(st, 1);
      int key_len = sqlite3_column_bytes(st, 1);
      const unsigned char *stored_batch_id = sqlite3_column_text(st, 2);
      int batch_id_len = sqlite3_column_bytes(st, 2);
      const void *stored_wire = sqlite3_column_blob(st, 3);
      wire_len = sqlite3_column_bytes(st, 3);
      id = sqlite3_column_int64(st, 0);
      durable_wire_invalid = !stored_wire || wire_len <= 0 ||
                             !terminal_wire_valid((const uint8_t *)stored_wire,
                                                  (size_t)wire_len);
      durable_metadata_invalid = !queue_sql_text_valid(stored_key, key_len) ||
                                 !queue_sql_text_valid(stored_batch_id, batch_id_len);
      /* Copy the key before checking the wire payload: an invalid durable
       * wire is the one case that must transition the selected row to failed,
       * and that transition is keyed by its durable idempotency key.  Any
       * failure to make that local copy is transient, never corruption. */
      if (!durable_metadata_invalid) {
        key = (char *)terminal_journal_select_alloc((size_t)key_len + 1u,
                                                     EDR_TERMINAL_SELECT_ALLOC_KEY);
        if (!key) {
          allocation_failed = 1;
        } else {
          memcpy(key, stored_key, (size_t)key_len);
          key[key_len] = '\0';
        }
        if (!allocation_failed && !durable_wire_invalid) {
          batch_id = (char *)terminal_journal_select_alloc(
              (size_t)batch_id_len + 1u, EDR_TERMINAL_SELECT_ALLOC_BATCH_ID);
          if (!batch_id) allocation_failed = 1;
        }
        if (!allocation_failed && batch_id) {
          memcpy(batch_id, stored_batch_id, (size_t)batch_id_len);
          batch_id[batch_id_len] = '\0';
        }
        if (!allocation_failed && key && batch_id && !durable_wire_invalid) {
          wire = (uint8_t *)terminal_journal_select_alloc(
              (size_t)wire_len, EDR_TERMINAL_SELECT_ALLOC_WIRE);
          if (!wire) allocation_failed = 1;
        }
        if (!allocation_failed && wire) memcpy(wire, stored_wire, (size_t)wire_len);
      }
      selected = 1;
    } else if (step_rc != SQLITE_DONE) {
      selection_transient = 1;
    }
    /* This loop owns exactly one statement at a time. Finalize it once after
     * copying the row, before either continuing to the next frame kind or
     * releasing the queue lock for transport. */
    sqlite3_finalize(st);
    st = NULL;
    if (selected || selection_transient) break;
  }
  if (selection_transient) {
    s_terminal_replay_selection_transient_failures++;
    queue_state_unlock();
    return 2;
  }
  if (!selected) {
    queue_state_unlock();
    return 1;
  }
  if (durable_metadata_invalid) {
    int quarantined = terminal_journal_quarantine_metadata_locked(s_db, id, frame_kind);
    if (quarantined) {
      s_terminal_replay_metadata_corruption_failures++;
      free(key);
      free(batch_id);
      free(wire);
      queue_state_unlock();
      return 0;
    }
    /* A failed quarantine write is transient. Do not pretend the corrupt row
     * was transitioned when SQLite could not make that durable state change. */
    terminal_journal_note_selection_transient_locked(s_db, id, frame_kind);
    s_terminal_replay_selection_transient_failures++;
    free(key);
    free(batch_id);
    free(wire);
    queue_state_unlock();
    return 2;
  }
  if (allocation_failed) {
    /* Allocation failure must preserve a valid durable row for later replay. */
    terminal_journal_note_selection_transient_locked(s_db, id, frame_kind);
    s_terminal_replay_selection_transient_failures++;
    free(key);
    free(batch_id);
    free(wire);
    queue_state_unlock();
    return 2;
  }
  if (durable_wire_invalid) {
    if (frame_kind == 0) {
      terminal_journal_fail_intent_locked(s_db, id, key ? key : "", "invalid_durable_wire");
    } else {
      terminal_journal_fail_frame_locked(s_db, id, key ? key : "", frame_kind == 1,
                                         "invalid_durable_wire");
    }
    free(key);
    free(batch_id);
    free(wire);
    queue_state_unlock();
    return 0;
  }
  if (!key || !batch_id || !wire) {
    /* Missing copies are local/transient, not proof of a corrupt durable
     * frame. Leave it replayable and make the selected retry visible. */
    terminal_journal_note_selection_transient_locked(s_db, id, frame_kind);
    s_terminal_replay_selection_transient_failures++;
    free(key);
    free(batch_id);
    free(wire);
    queue_state_unlock();
    return 2;
  }
  /* The ordinary queue's max-retry policy is intentionally inapplicable to
   * terminal source/result and combined frames. Once the action exists, its
   * final audit must remain replayable across any number of transport
   * failures; pending state and retry counters stay visible in health. */
  queue_state_unlock();

  int send = -1;
  if (edr_ingest_http_configured() && !edr_ingest_http_circuit_open() &&
      !edr_ingest_http_telemetry_deferred()) {
    send = edr_transport_v2_report_events(batch_id, wire, 12u, wire + 12u,
                                          (size_t)wire_len - 12u);
  }
  if (send == 0) {
    int acknowledged = 0;
    queue_state_lock();
    if (s_db == selected_db && s_db_generation == selected_generation) {
      acknowledged = frame_kind == 0
                         ? terminal_journal_ack_intent_locked(s_db, id, key, wire, wire_len)
                         : terminal_journal_ack_frame_locked(s_db, id, key, frame_kind == 1,
                                                             wire, wire_len);
    }
    queue_state_unlock();
    free(key);
    free(batch_id);
    free(wire);
    return acknowledged ? 0 : 2;
  }
  queue_state_lock();
  if (s_db == selected_db && s_db_generation == selected_generation &&
      !edr_ingest_http_telemetry_deferred()) {
    if (frame_kind == 0) {
      /* The only pre-action evidence must remain replayable. Unlike final
       * frames, retry exhaustion may not discard this unknown outcome. */
      terminal_journal_bump_intent_retry_locked(s_db, id, key, wire, wire_len);
    } else {
      terminal_journal_bump_frame_retry_locked(s_db, id, key, frame_kind == 1, wire, wire_len);
    }
  }
  queue_state_unlock();
  free(key);
  free(batch_id);
  free(wire);
  return 2;
}

void edr_storage_queue_poll_drain(void) {
  uint64_t now = edr_monotonic_ns();
  uint64_t interval_ns = (uint64_t)queue_drain_interval_ms() * 1000000ULL;
  uint64_t drain_generation;

  queue_state_lock();
  if (!s_db) {
    queue_state_unlock();
    return;
  }
  drain_generation = s_db_generation;
  if (s_drain_generation == drain_generation) {
    queue_state_unlock();
    return;
  }
  if (edr_ingest_http_circuit_open() || edr_ingest_http_telemetry_deferred()) {
    uint64_t circuit_interval_ns = (uint64_t)queue_circuit_backoff_ms() * 1000000ULL;
    if (now - s_last_drain_ns < circuit_interval_ns) {
      queue_state_unlock();
      return;
    }
    s_last_drain_ns = now;
    queue_state_unlock();
    return;
  }
  if (now - s_last_drain_ns < interval_ns) {
    queue_state_unlock();
    return;
  }
  int has_pending = s_pending > 0u || s_terminal_pending > 0u;
  if (!has_pending) {
    s_last_drain_ns = now;
    cleanup_expired_rows();
    queue_state_unlock();
    return;
  }
  s_last_drain_ns = now;
  /* Claim this open generation before releasing the state mutex. Cleanup and
   * selection use the same handle, but transport below remains unlocked. */
  s_drain_generation = drain_generation;
  cleanup_expired_rows();
  queue_state_unlock();

  /* A recovered pre-action intent is audit evidence for an unknown side
   * effect, so it precedes ordinary backlog delivery after every reopen. */
  for (unsigned k = 0; k < queue_drain_max_rows(); k++) {
    int r = drain_one_terminal_journal_frame();
    if (r == 1) {
      break;
    }
    if (r == 2) {
      break;
    }
  }
  for (unsigned k = 0; k < queue_drain_max_rows(); k++) {
    int r = drain_one_row();
    if (r == 1) {
      break;
    }
    if (r == 2) {
      break;
    }
  }
  queue_state_lock();
  if (s_drain_generation == drain_generation) s_drain_generation = 0u;
  queue_state_unlock();
}

#else /* !EDR_HAVE_SQLITE */

void edr_storage_queue_configure(uint32_t max_db_mb, uint32_t retention_hours) {
  (void)max_db_mb;
  (void)retention_hours;
}

EdrError edr_storage_queue_open(const char *path) {
  (void)path;
  return EDR_ERR_SQLITE_OPEN;
}

EdrError edr_storage_queue_p0_deferred_retain(const char *key_hex,
                                               uint32_t family_mask,
                                               const uint8_t *payload_json,
                                               size_t payload_len) {
  (void)key_hex;
  (void)family_mask;
  (void)payload_json;
  (void)payload_len;
  return EDR_ERR_SQLITE_OPEN;
}

int edr_storage_queue_p0_deferred_contains(const char *key_hex) {
  (void)key_hex;
  return -1;
}

int edr_storage_queue_p0_deferred_peek(uint32_t healthy_family_mask,
                                       char key_out[65], uint8_t **payload_out,
                                       size_t *payload_len_out) {
  (void)healthy_family_mask;
  if (key_out) key_out[0] = '\0';
  if (payload_out) *payload_out = NULL;
  if (payload_len_out) *payload_len_out = 0u;
  return -1;
}

EdrError edr_storage_queue_p0_deferred_complete(const char *key_hex,
                                                 const char *batch_id,
                                                 const uint8_t *wire,
                                                 size_t wire_len,
                                                 const char *reason) {
  (void)key_hex;
  (void)batch_id;
  (void)wire;
  (void)wire_len;
  (void)reason;
  return EDR_ERR_SQLITE_OPEN;
}

EdrError edr_storage_queue_p0_deferred_fail(const char *key_hex,
                                             const char *reason) {
  (void)key_hex;
  (void)reason;
  return EDR_ERR_SQLITE_OPEN;
}

EdrError edr_storage_queue_p0_deferred_retry(const char *key_hex,
                                              const char *reason) {
  (void)key_hex;
  (void)reason;
  return EDR_ERR_SQLITE_OPEN;
}

void edr_storage_queue_close(void) {}

EdrError edr_storage_queue_enqueue(const char *batch_id, const uint8_t *payload,
                                   size_t payload_len, int compressed, int severity) {
  (void)batch_id;
  (void)payload;
  (void)payload_len;
  (void)compressed;
  (void)severity;
  return EDR_ERR_SQLITE_OPEN;
}

EdrEnforcementTerminalPrecreate edr_storage_queue_enforcement_terminal_precreate(
    const char *idempotency_key, const char *source_event_key, const char *rule_id,
    const char *process_generation_key, const char *intent_batch_id, const uint8_t *intent_wire,
    size_t intent_wire_len) {
  (void)idempotency_key;
  (void)source_event_key;
  (void)rule_id;
  (void)process_generation_key;
  (void)intent_batch_id;
  (void)intent_wire;
  (void)intent_wire_len;
  return EDR_ENFORCEMENT_TERMINAL_PRECREATE_ERROR;
}

EdrError edr_storage_queue_enforcement_terminal_update(
    const char *idempotency_key, const char *source_batch_id, const uint8_t *source_wire,
    size_t source_wire_len, const char *combined_batch_id, const uint8_t *combined_wire,
    size_t combined_wire_len) {
  (void)idempotency_key;
  (void)source_batch_id;
  (void)source_wire;
  (void)source_wire_len;
  (void)combined_batch_id;
  (void)combined_wire;
  (void)combined_wire_len;
  return EDR_ERR_SQLITE_OPEN;
}

void edr_storage_queue_enforcement_terminal_get_metrics(
    EdrEnforcementTerminalJournalMetrics *out) {
  if (out) memset(out, 0, sizeof(*out));
}

void edr_storage_queue_get_capacity_metrics(EdrStorageQueueCapacityMetrics *out) {
  if (out) memset(out, 0, sizeof(*out));
}

uint64_t edr_storage_queue_pending_count(void) { return 0; }
uint64_t edr_storage_queue_dead_letter_count(void) { return 0; }

void edr_storage_queue_poll_drain(void) {}

int edr_storage_queue_is_open(void) { return 0; }

int edr_storage_queue_p0_source_only_latch_is_set(void) { return -1; }

EdrError edr_storage_queue_p0_source_only_latch_prepare(
    EdrStorageQueueP0SourceOnlyLatch *out) {
  if (out) memset(out, 0, sizeof(*out));
  return EDR_ERR_SQLITE_OPEN;
}

EdrError edr_storage_queue_p0_source_only_latch_get(
    EdrStorageQueueP0SourceOnlyLatch *out) {
  if (out) memset(out, 0, sizeof(*out));
  return EDR_ERR_SQLITE_OPEN;
}

EdrError edr_storage_queue_p0_source_only_enqueue_bound(
    const EdrStorageQueueP0SourceOnlyLatch *expected, const char *event_id,
    const char *batch_id, const uint8_t *payload, size_t payload_len,
    int compressed, int recovery_audit) {
  (void)expected;
  (void)event_id;
  (void)batch_id;
  (void)payload;
  (void)payload_len;
  (void)compressed;
  (void)recovery_audit;
  return EDR_ERR_SQLITE_OPEN;
}

EdrError edr_storage_queue_p0_source_only_recovery_probe(void) {
  return EDR_ERR_SQLITE_OPEN;
}

#ifdef EDR_STORAGE_QUEUE_TESTING
void edr_storage_queue_test_fail_next_enqueue_commits(unsigned count) { (void)count; }
void edr_storage_queue_test_fail_next_p0_latch_commits(unsigned count) { (void)count; }
void edr_storage_queue_test_fail_next_p0_deferred_commits(unsigned count) { (void)count; }
void edr_storage_queue_test_fail_next_terminal_select_allocations(
    unsigned key_count, unsigned batch_id_count, unsigned wire_count) {
  (void)key_count;
  (void)batch_id_count;
  (void)wire_count;
}
#endif

#endif
