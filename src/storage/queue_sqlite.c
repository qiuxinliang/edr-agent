#include "edr/storage_queue.h"

#include "edr/ingest_http.h"
#include "edr/event_batch.h"
#include "edr/sha256.h"
#include "edr/time_util.h"
#include "edr/transport_sink.h"
#include "edr/transport_v2.h"
#include "edr/egress_batch_policy.h"
#include "edr/report_events_ack.h"
#include "cJSON.h"

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
#include <signal.h>
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
static uint64_t s_terminal_policy_held_frames;
static uint64_t s_terminal_local_retained;
static sqlite3_int64 s_terminal_recheck_cursor;
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
static int64_t s_test_p0_deferred_time = -1;
static int64_t s_test_delivery_time = -1;
static unsigned s_test_event_alloc_failures[2];
static unsigned s_test_egress_allocation_failures;
static unsigned s_test_source_owner_inventory_read_failures;

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
#define EDR_QUEUE_DEFAULT_MAX_DB_MB 512u
static uint32_t s_cfg_max_db_mb = EDR_QUEUE_DEFAULT_MAX_DB_MB;
static uint32_t s_cfg_capacity_limit_defaulted = 1u;
static uint32_t s_capacity_limit_defaulted;
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
static uint64_t s_delivery_receipt_failures;
static uint64_t s_delivery_requeued;
static uint64_t s_delivery_failed;
static uint64_t s_delivery_resource_deferred;
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
static int recovery_projection_ack_locked(sqlite3_int64 origin_id, const char *batch_id,
                                          const uint8_t *wire, size_t wire_len);
static int recovery_projection_origin_valid_locked(sqlite3_int64 origin_id,
    const char *batch_id,const uint8_t *wire,size_t wire_len);
#if defined(_WIN32)
static SRWLOCK s_queue_state_lock = SRWLOCK_INIT;
static void queue_state_lock(void) { AcquireSRWLockExclusive(&s_queue_state_lock); }
static void queue_state_unlock(void) { ReleaseSRWLockExclusive(&s_queue_state_lock); }
#else
static pthread_mutex_t s_queue_state_lock = PTHREAD_MUTEX_INITIALIZER;
static void queue_state_lock(void) { pthread_mutex_lock(&s_queue_state_lock); }
static void queue_state_unlock(void) { pthread_mutex_unlock(&s_queue_state_lock); }
#endif
/* Independent lifetime lock: the final guard is also called while the queue
 * mutex is held. Its owner reads committed state through a separate read-only
 * connection, and must never recursively acquire the queue mutex. */
#if defined(_WIN32)
static SRWLOCK s_intent_owner_lock = SRWLOCK_INIT;
static void intent_owner_lock(void) { AcquireSRWLockExclusive(&s_intent_owner_lock); }
static void intent_owner_unlock(void) { ReleaseSRWLockExclusive(&s_intent_owner_lock); }
#else
static pthread_mutex_t s_intent_owner_lock = PTHREAD_MUTEX_INITIALIZER;
static void intent_owner_lock(void) { pthread_mutex_lock(&s_intent_owner_lock); }
static void intent_owner_unlock(void) { pthread_mutex_unlock(&s_intent_owner_lock); }
#endif
static char s_intent_owner_path[512];
static uint8_t s_intent_owner_nonce[16];
static void terminal_intent_owner_unregister_locked(void) {
  edr_egress_set_p0_pair_validator(NULL,NULL);
  intent_owner_lock();
  s_intent_owner_path[0]='\0';
  memset(s_intent_owner_nonce,0,sizeof(s_intent_owner_nonce));
  intent_owner_unlock();
}
static int terminal_intent_association_validate(const EdrEgressP0PairAssociation *tuple,
    const uint8_t *frame,size_t frame_len,void *user);

#if defined(_WIN32)
static HANDLE s_lock_handle = INVALID_HANDLE_VALUE;
#else
static int s_lock_fd = -1;
#endif

void edr_storage_queue_configure(uint32_t max_db_mb, uint32_t retention_hours) {
  queue_state_lock();
  s_cfg_max_db_mb = max_db_mb ? max_db_mb : EDR_QUEUE_DEFAULT_MAX_DB_MB;
  s_cfg_capacity_limit_defaulted = max_db_mb == 0u;
  s_cfg_retention_hours = retention_hours;
  queue_state_unlock();
}

#ifdef EDR_STORAGE_QUEUE_TESTING
/* Test-only fault at the inventory authority; no production configuration. */
void edr_storage_queue_test_fail_source_owner_inventory_reads(unsigned count) {
  queue_state_lock();
  s_test_source_owner_inventory_read_failures = count;
  queue_state_unlock();
}
#endif

/* Wall-clock deadline is durable across restart. Clamp apparent future
 * deadlines to one backoff cap when the clock moves backwards. */
static sqlite3_int64 delivery_time(void) {
#ifdef EDR_STORAGE_QUEUE_TESTING
  if (s_test_delivery_time >= 0) return s_test_delivery_time;
#endif
  return (sqlite3_int64)time(NULL);
}
#ifdef EDR_STORAGE_QUEUE_TESTING
void edr_storage_queue_test_set_delivery_time(int64_t seconds) {
  queue_state_lock();
  s_test_delivery_time = seconds;
  queue_state_unlock();
}
#endif
static unsigned s_delivery_priority_streak;

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
  uint64_t mb = s_cfg_max_db_mb;
  const char *cause = "zero_or_unspecified_configuration";
  s_capacity_limit_defaulted = s_cfg_capacity_limit_defaulted;
  const char *e = getenv("EDR_QUEUE_MAX_DB_MB");
  if (e && e[0]) {
    char *end = NULL;
    errno = 0;
    unsigned long parsed = strtoul(e, &end, 10);
    if (errno == 0 && end && !*end && parsed > 0u && parsed <= 65535UL) {
      mb = parsed;
      s_capacity_limit_defaulted = 0u;
    } else {
      s_capacity_limit_defaulted = 1u;
      cause = "invalid_environment_override";
    }
  }
  s_max_db_bytes = mb * 1024ULL * 1024ULL;
  if (s_capacity_limit_defaulted) {
    fprintf(stderr, "[queue] capacity_limit_defaulted reason=%s effective_mb=%llu\n",
            cause, (unsigned long long)mb);
  }
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
#define EDR_TERMINAL_FRAME_MAX_BYTES ((uint64_t)EDR_EVENT_BATCH_CAP)
#define EDR_TERMINAL_BASE_FRAME_BYTES (65536ULL + 16ULL)
#define EDR_TERMINAL_TEXT_MAX_BYTES 255u
#define EDR_TERMINAL_OWNER_DIGEST_HEX_LEN 64u
/* Intent and final records are serialized by p0_rule_direct_emit into one
 * BAT1 frame each. Keep the terminal recovery reservation tied to that
 * bounded wire contract rather than to SQLite's non-reclaiming file size. */
#define EDR_TERMINAL_INTENT_RESERVE_BYTES (EDR_TERMINAL_BASE_FRAME_BYTES + 255ULL)
/* The lane minimum still supports the existing short-command frame bound;
 * batch IDs are bounded by terminal_text_valid (255 bytes). Reserving both
 * final frames before execution prevents an ordinary backlog from consuming
 * their only durable recovery space. Long commands increase only their own
 * owner's reservation, not every ordinary event's reserved lane. */
#define EDR_TERMINAL_FINAL_RESERVE_BYTES \
  (2ULL * (EDR_TERMINAL_BASE_FRAME_BYTES + 255ULL))
#define EDR_TERMINAL_CRITICAL_RESERVE_MIN \
  (EDR_TERMINAL_LOGICAL_OVERHEAD + EDR_TERMINAL_INTENT_RESERVE_BYTES + \
   EDR_TERMINAL_FINAL_RESERVE_BYTES + 4096ULL)
#define EDR_P0_SOURCE_ONLY_RETRY_RESERVE_SLOTS 8ULL
#define EDR_P0_SOURCE_ONLY_RESERVE_MIN \
  (EDR_P0_SOURCE_ONLY_RETRY_RESERVE_SLOTS * \
   (EDR_QUEUE_EVENT_LOGICAL_OVERHEAD + EDR_TERMINAL_BASE_FRAME_BYTES + 255ULL))
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

static int queue_logical_retained_bytes_locked(uint64_t *out) {
  static const char event_sql[] =
      "SELECT COALESCE(SUM(length(batch_id)+length(payload)+512+"
      "CASE WHEN recovery_version>0 THEN 512 ELSE 0 END),0) "
      "FROM event_queue;";
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
  uint64_t lineage, projections;
  if (!out || !queue_sql_sum_locked(event_sql, &events) ||
      !queue_sql_sum_locked(terminal_sql, &terminals) ||
      !queue_sql_sum_locked(deferred_sql, &deferred) ||
      !queue_sql_sum_locked("SELECT COUNT(*)*512 FROM queue_projection_relations;", &projections) ||
      !queue_sql_sum_locked("SELECT CASE WHEN length(legacy_lineage)>0 THEN 2048 ELSE 0 END+"
                            "CASE WHEN length(last_recovery_snapshot)>0 THEN 2048 ELSE 0 END "
                            "FROM queue_meta WHERE id=1;", &lineage)) {
    return 0;
  }
  *out = queue_add_bytes(queue_add_bytes(queue_add_bytes(queue_add_bytes(events, terminals), deferred), lineage), projections);
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
  out->capacity_limit_defaulted = s_capacity_limit_defaulted;
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
  out->delivery_receipt_failures = s_delivery_receipt_failures;
  out->delivery_requeued = s_delivery_requeued;
  out->delivery_failed = s_delivery_failed;
  out->delivery_resource_deferred = s_delivery_resource_deferred;
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
  if (!queue_logical_retained_bytes_locked(&out->used_bytes) ||
      !queue_sql_sum_locked("SELECT COALESCE(SUM(length(batch_id)+length(payload)+512+"
                            "CASE WHEN recovery_version>0 THEN 512 ELSE 0 END),0) "
                            "FROM event_queue WHERE status!='pending';",
                            &out->retained_nonpending_bytes) ||
      !queue_sql_sum_locked("SELECT COUNT(*) FROM event_queue WHERE status='local_evidence';",
                            &out->local_evidence_rows) ||
      !queue_sql_sum_locked("SELECT COUNT(*) FROM event_queue WHERE status='policy_held';",
                            &out->policy_held_rows) ||
      !queue_sql_sum_locked("SELECT COUNT(*) FROM queue_meta WHERE length(legacy_lineage)>0;",
                            &out->legacy_owner_unacknowledged) ||
      !queue_sql_sum_locked("SELECT COUNT(*) FROM event_queue WHERE recovery_state='retained_unresolved';",
                            &out->retained_unresolved_rows) ||
      !queue_sql_sum_locked("SELECT COUNT(*) FROM queue_projection_relations WHERE receipt_state='pending';",
                            &out->projection_pending_rows) ||
      !queue_sql_sum_locked("SELECT COUNT(*) FROM queue_projection_relations WHERE receipt_state='acked';",
                            &out->projection_acked_rows) ||
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

static uint64_t terminal_final_reserve_for_intent(size_t intent_wire_len) {
  /* Final source and alert keep the intent's immutable command facts. The
   * extra base-frame bound covers all non-command terminal/alert fields; cap
   * at the same maximum the encoder and terminal_wire_valid actually accept.
   * Existing small-intent rows keep almost the old cost, and reservation is
   * committed before any side effect. */
  uint64_t frame = queue_add_bytes((uint64_t)intent_wire_len, EDR_TERMINAL_BASE_FRAME_BYTES);
  if (frame > EDR_TERMINAL_FRAME_MAX_BYTES) frame = EDR_TERMINAL_FRAME_MAX_BYTES;
  return 2ULL * (frame + EDR_TERMINAL_TEXT_MAX_BYTES);
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
  return queue_add_bytes(total, terminal_final_reserve_for_intent(intent_wire_len));
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

/* Local commit witness, never an input to admission or a substitute for a
 * server receipt. Fixed hashes bound metadata to 1024 rows; no source bodies,
 * paths or user facts. Call only inside the actual ACK owner's FULL transaction.
 * Upgrades create an empty table; historical deletes are never backfilled. */
static int delivery_receipt_record_locked(sqlite3 *db, const char *batch_id,
                                           const uint8_t *wire, int length) {
  char batch_sha[65], payload_sha[65]; sqlite3_stmt *st = NULL;
  int ok = db && batch_id && wire && length > 0 && !sqlite3_get_autocommit(db) &&
      edr_sha256_hex((const uint8_t *)batch_id, strlen(batch_id), batch_sha) == 0 &&
      edr_sha256_hex(wire, (size_t)length, payload_sha) == 0;
  if (ok) ok = sqlite3_prepare_v2(db,
      "INSERT INTO delivery_receipts_v1(batch_id_sha256,payload_sha256,payload_bytes,acked_at) "
      "VALUES(?,?,?,?) ON CONFLICT(batch_id_sha256,payload_sha256) DO NOTHING;", -1, &st, NULL) == SQLITE_OK;
  if (ok) {
    sqlite3_bind_text(st, 1, batch_sha, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, payload_sha, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, length); sqlite3_bind_int64(st, 4, delivery_time());
    ok = sqlite3_step(st) == SQLITE_DONE;
  }
  sqlite3_finalize(st);
  if (ok) ok = sqlite3_exec(db,
      "DELETE FROM delivery_receipts_v1 WHERE id NOT IN "
      "(SELECT id FROM delivery_receipts_v1 ORDER BY id DESC LIMIT 1024);", NULL, NULL, NULL) == SQLITE_OK;
  if (!ok) {
    s_delivery_receipt_failures++;
    fprintf(stderr, "[queue] local_ack_receipt_commit_failed; original delivery state retained\n");
  }
  return ok ? 0 : -1;
}

static int delete_selected_row(sqlite3 *db, sqlite3_int64 id, const char *batch_id,
                               const uint8_t *payload, int payload_len, int severity) {
  sqlite3_stmt *st = NULL;
  int is_terminal;
  int durable_transaction = 0;
  sqlite3_int64 origin_id = 0;
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
  {
    sqlite3_stmt *link = NULL;
    if (sqlite3_prepare_v2(db, "SELECT origin_row_id FROM event_queue WHERE id=?;", -1,
                          &link, NULL) != SQLITE_OK) { sqlite3_finalize(st); return -1; }
    sqlite3_bind_int64(link,1,id);
    int link_rc=sqlite3_step(link);
    if (link_rc==SQLITE_ROW) origin_id=sqlite3_column_int64(link,0);
    sqlite3_finalize(link);
    if (link_rc!=SQLITE_ROW || origin_id<0) { sqlite3_finalize(st); return -1; }
  }
  { /* Every remote ACK and its local witness share one FULL transaction. */
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
    if (delivery_receipt_record_locked(db, batch_id, payload, payload_len) != 0) {
      if (source_only) (void)queue_p0_latch_end_durable_locked(0);
      else (void)terminal_journal_end_durable_locked(0);
      return -1;
    }
    /* A terminal journal frame and its ordinary-queue copy share the stable
     * batch id.  Delete, acknowledgement flags and the final completed CASE
     * are one FULL transaction, so no crash can strand a ready dual-acked row
     * after its ordinary queue copy disappeared. */
    if (durable_transaction) {
      if (origin_id>0 && recovery_projection_ack_locked(origin_id,batch_id,payload,
                                                       (size_t)payload_len) != 0) {
        (void)terminal_journal_end_durable_locked(0);
        return -1;
      }
      if (source_only) {
        if (queue_meta_ack_source_batch_locked(db, batch_id) != 0) {
          (void)queue_p0_latch_end_durable_locked(0);
          return -1;
        }
      } else if (is_terminal && terminal_journal_ack_batch_id_locked(db, batch_id) != 0) {
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
      rc = dead_letter_row_by_id(ids[i], "invalid_wire_header");
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
            "[queue] retaining legacy batch without v6.2 header id=%lld (suppressed=%llu; wire retained for compatibility review)\n",
            (long long)id, (unsigned long long)s_legacy_drop_suppressed);
    s_legacy_drop_suppressed = 0u;
  } else {
    fprintf(stderr, "[queue] retaining legacy batch without v6.2 header id=%lld (wire retained for compatibility review)\n",
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
                    "WHEN retry_count<9223372036854775807 THEN retry_count+1 ELSE retry_count END, "
                    "next_retry_at=?4 + CASE WHEN retry_count>=8 THEN 300 "
                    "WHEN retry_count<0 THEN 1 ELSE (1 << retry_count) END "
                    "WHERE id=?1 AND batch_id=?2 AND payload=?3 AND status='pending';";
  if (!db || !batch_id || !payload || payload_len <= 0 ||
      sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
    return;
  }
  sqlite3_bind_int64(st, 1, id);
  sqlite3_bind_text(st, 2, batch_id, -1, SQLITE_TRANSIENT);
  sqlite3_bind_blob(st, 3, payload, payload_len, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 4, delivery_time());
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
          "WHERE state='completed' AND intent_acked=1 AND source_acked=1 AND combined_acked=1 AND updated_at < ?;",
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
  const char *sql = "UPDATE event_queue SET status='dead_letter', "
                    "terminal_reason='retention_expired',terminal_at=strftime('%s','now') "
                    "WHERE id IN (SELECT id FROM event_queue "
                    "WHERE created_at < ? AND severity=0 AND status='pending' ORDER BY id LIMIT 256);";
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_int64(st, 1, (sqlite3_int64)cutoff);
    (void)sqlite3_step(st);
    sqlite3_finalize(st);
  }
  st = NULL;
  if (sqlite3_prepare_v2(s_db,
                         "UPDATE event_queue SET status='dead_letter', terminal_reason='retention_expired', "
                         "terminal_at=? WHERE id IN (SELECT id FROM event_queue WHERE created_at < ? "
                         "AND severity=1 AND origin_row_id=0 AND status='pending' ORDER BY id LIMIT 256);",
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
       * includes legacy and high-priority/source-only rows moved
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
#ifdef EDR_STORAGE_QUEUE_TESTING
/* Inject only the final gate's temporary allocation verdict. The unchanged
 * queue transition below is shared with real preflight failures. */
void edr_storage_queue_test_fail_egress_allocation(unsigned failures) {
  queue_state_lock(); s_test_egress_allocation_failures=failures; queue_state_unlock();
}
void edr_storage_queue_test_fail_event_alloc(unsigned kind, unsigned failures) {
  queue_state_lock();
  if (kind < 2u) s_test_event_alloc_failures[kind] = failures;
  queue_state_unlock();
}
#endif
static void *event_select_alloc(size_t size, unsigned kind) {
#ifdef EDR_STORAGE_QUEUE_TESTING
  if (kind < 2u && s_test_event_alloc_failures[kind]) {
    --s_test_event_alloc_failures[kind];
    return NULL;
  }
#else
  (void)kind;
#endif
  return malloc(size);
}

static int hold_selected_row_locked(sqlite3_int64 id,const char *batch_id,
    const uint8_t *wire,int wire_len,const char *policy_reason) {
  sqlite3_stmt *hold = NULL;
  int held = 0;
  int durable_started = queue_p0_latch_begin_durable_locked() == 0;
  if (durable_started && sqlite3_prepare_v2(s_db,
      "UPDATE event_queue SET status='policy_held',terminal_reason=?,terminal_at=? "
      "WHERE id=? AND batch_id=? AND payload=? AND status='pending';",
      -1, &hold, NULL) == SQLITE_OK) {
    sqlite3_bind_text(hold, 1, policy_reason, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(hold, 2, (sqlite3_int64)time(NULL));
    sqlite3_bind_int64(hold, 3, id);
    sqlite3_bind_text(hold, 4, batch_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(hold, 5, wire, wire_len, SQLITE_TRANSIENT);
    held = sqlite3_step(hold) == SQLITE_DONE && sqlite3_changes(s_db) == 1;
  }
  sqlite3_finalize(hold);
  if (durable_started) {
    if (held) held = queue_p0_latch_end_durable_locked(1) == 0;
    else (void)queue_p0_latch_end_durable_locked(0);
  }
  if (held) { if (s_pending) s_pending--; s_delivery_failed++; }
  return held;
}

static int drain_one_row(void) {
  queue_state_lock();
  if (!s_db) {
    queue_state_unlock();
    return 1;
  }
  sqlite3 *selected_db = s_db;
  uint64_t selected_generation = s_db_generation;
  sqlite3_stmt *st = NULL;
  char sql[512];
  /* Seven priority selections followed by an oldest-eligible selection prevent
   * an ongoing high-priority arrival stream from starving an older batch. */
  int fair_turn = s_delivery_priority_streak >= 7u;
  snprintf(sql, sizeof(sql),
           "SELECT id,batch_id,payload,retry_count,severity,origin_row_id FROM event_queue "
           "WHERE status='pending' AND (next_retry_at<=?1 OR next_retry_at>?1+300) "
           "ORDER BY %s LIMIT 1;", fair_turn ? "id ASC" : "severity DESC,id ASC");
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    queue_state_unlock();
    return 2;
  }
  sqlite3_bind_int64(st, 1, delivery_time());
  int step = sqlite3_step(st);
  if (step != SQLITE_ROW) {
    sqlite3_finalize(st);
    /* No due row does not mean the durable pending queue is empty. */
    queue_state_unlock();
    return step == SQLITE_DONE ? 1 : 2;
  }
  s_delivery_priority_streak = fair_turn ? 0u : s_delivery_priority_streak + 1u;

  sqlite3_int64 id = sqlite3_column_int64(st, 0);
  const unsigned char *batch_id = sqlite3_column_text(st, 1);
  int batch_id_len = sqlite3_column_bytes(st, 1);
  const void *blob = sqlite3_column_blob(st, 2);
  int blob_len = sqlite3_column_bytes(st, 2);
  int retry_count = sqlite3_column_int(st, 3);
  int severity = sqlite3_column_int(st, 4);
  sqlite3_int64 origin_id=sqlite3_column_int64(st,5);
  uint8_t *blob_copy = NULL;
  char *batch_id_copy = NULL;
  int allocation_failed = 0;
  s_delivery_selected++;
  if (sqlite3_errcode(s_db) == SQLITE_NOMEM) {
    sqlite3_finalize(st);
    s_delivery_resource_deferred++;
    s_delivery_requeued++;
    queue_state_unlock();
    return 2;
  }
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
    batch_id_copy = (char *)event_select_alloc((size_t)batch_id_len + 1u, 0u);
    if (!batch_id_copy) allocation_failed = 1;
    if (batch_id_copy) {
      memcpy(batch_id_copy, batch_id, (size_t)batch_id_len);
      batch_id_copy[batch_id_len] = '\0';
    }
  }
  /* sqlite column pointers become invalid at finalize/reset. Copy while the
   * statement owns the row, then release SQLite before any transport I/O. */
  if (blob && blob_len > 0) {
    blob_copy = (uint8_t *)event_select_alloc((size_t)blob_len, 1u);
    if (!blob_copy) allocation_failed = 1;
    if (blob_copy) {
      memcpy(blob_copy, blob, (size_t)blob_len);
    }
  }
  sqlite3_finalize(st);
  if (allocation_failed) {
    /* A valid committed record is still owned by SQLite. Local OOM must not
     * consume retry budget or quarantine/delete it as corrupt. */
    free(batch_id_copy);
    free(blob_copy);
    s_delivery_resource_deferred++;
    s_delivery_requeued++;
    queue_state_unlock();
    return 2;
  }

  {
    int lim = max_retry_limit();
    /* Severity 2 is the sole durable fail-closed disposition after a
     * collector/ruleset source cannot be evaluated. It never expires through
     * the ordinary retry policy: only a central ACK may remove it. */
    if (origin_id==0 && severity != EDR_STORAGE_QUEUE_SEVERITY_P0_SOURCE_ONLY && lim > 0 && retry_count >= lim) {
      int disposed;
      disposed = dead_letter_row_by_id(id, "max_retries") == 0;
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

  int linked=origin_id>0?recovery_projection_origin_valid_locked(origin_id,batch_id_copy,
                                                                blob_copy,(size_t)blob_len):1;
  if (linked<0) {
    s_delivery_resource_deferred++; s_delivery_requeued++;
    free(batch_id_copy); free(blob_copy); queue_state_unlock(); return 2;
  }
  if (origin_id<0 || !linked) {
    int retained=dead_letter_row_by_id(id,"projection_lineage_integrity_failed")==0;
    if (retained) s_delivery_failed++;
    free(batch_id_copy); free(blob_copy); queue_state_unlock(); return retained?0:2;
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

  {
    char policy_reason[96];
    int policy_valid;
#ifdef EDR_STORAGE_QUEUE_TESTING
    if (s_test_egress_allocation_failures) {
      --s_test_egress_allocation_failures;
      snprintf(policy_reason,sizeof(policy_reason),"egress_validation_allocation_failed");
      policy_valid=0;
    } else
#endif
    policy_valid=edr_egress_batch_validate(b, 12u, b + 12u, (size_t)blob_len - 12u,
                                         policy_reason, sizeof(policy_reason));
    if (!policy_valid) {
      if (!strcmp(policy_reason,"rule_projection_authority_unavailable") ||
          !strcmp(policy_reason,"egress_validation_allocation_failed")) {
        s_delivery_resource_deferred++; s_delivery_requeued++;
        free(batch_id_copy); free(blob_copy); queue_state_unlock(); return 2;
      }
      int held=hold_selected_row_locked(id,batch_id_copy,blob_copy,blob_len,policy_reason);
      free(batch_id_copy); free(blob_copy); queue_state_unlock();
      return held ? 0 : 2;
    }
  }
  /* Network transport is intentionally outside the queue lock. `blob_copy`
   * owns the row bytes across this boundary and close cannot invalidate it. */
  if (severity == EDR_STORAGE_QUEUE_SEVERITY_TERMINAL) {
    fprintf(stderr, "[queue_delivery] state=selected row_id=%lld batch_id=%s retry=%d\n",
            (long long)id, batch_id_copy, retry_count);
  }
  queue_state_unlock();
  int send = -1;
  int attempted = 0;
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
    attempted = 1;
    send = edr_transport_v2_report_events(batch_id_copy, b, 12u, b + 12,
                                          (size_t)blob_len - 12u);
  }
  if (send == EDR_REPORT_EVENTS_POLICY_HELD) {
    int held=0;
    queue_state_lock();
    if (s_db==selected_db && s_db_generation==selected_generation)
      held=hold_selected_row_locked(id,batch_id_copy,blob_copy,blob_len,
          "server_evidence_projection_unproven");
    queue_state_unlock();
    free(batch_id_copy); free(blob_copy);
    return held ? 0 : 2;
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
    if (acknowledged) {
      char finalize_reason[96];
      if (!edr_egress_batch_note_queue_removed(blob_copy,12,blob_copy+12,(size_t)blob_len-12,
                                              finalize_reason,sizeof(finalize_reason)))
        fprintf(stderr,"[queue] acknowledged payload removed; durable consumer finalize deferred\n");
    }
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
    if (attempted && !edr_ingest_http_telemetry_deferred())
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
  unsigned owner_version;
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
      !queue_meta_session_valid(row->session_state) ||
      (row->owner_version != 2u && row->owner_version != 3u) || row->counter > (uint64_t)INT64_MAX ||
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
  row->owner_version = EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_OWNER_REMOTE_V2;
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
          "source_latch_loss_detected,session_state,last_error,source_latch_owner FROM queue_meta WHERE id=1;",
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
  out->owner_version = (unsigned)sqlite3_column_int(st, 9);
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
          "source_latch_loss_detected=?,session_state=?,last_error=?,source_latch_owner=? WHERE id=1;",
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
  sqlite3_bind_int(st, 10, (int)row->owner_version);
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
          "source_latch_loss_detected,session_state,last_error,source_latch_owner) VALUES(1,?,?,?,?,?,?,?,?,?,?);",
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
  sqlite3_bind_int(st, 10, (int)row->owner_version);
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

/* Missing ownership metadata is not proof of confirmation. Count retained
 * sources in every status; only the local-v3 status AND reason prove local
 * retention ownership. Unknown/legacy sources retain remote recovery authority. */
static int queue_meta_retained_source_owners_locked(int *any, int *remote) {
  sqlite3_stmt *st = NULL;
  sqlite3_int64 total, local;
  if (!any || !remote || !s_db) return -1;
#ifdef EDR_STORAGE_QUEUE_TESTING
  if (s_test_source_owner_inventory_read_failures) {
    s_test_source_owner_inventory_read_failures--;
    return -1;
  }
#endif
  if (sqlite3_prepare_v2(s_db,
      "SELECT COUNT(*),COALESCE(SUM(status='local_evidence' "
      "AND terminal_reason='source_only_local_v3'),0) "
      "FROM event_queue WHERE severity=2;", -1, &st, NULL) != SQLITE_OK) return -1;
  if (sqlite3_step(st) != SQLITE_ROW) { sqlite3_finalize(st); return -1; }
  total = sqlite3_column_int64(st, 0);
  local = sqlite3_column_int64(st, 1);
  sqlite3_finalize(st);
  if (total < 0 || local < 0 || local > total) return -1;
  *any = total > 0;
  *remote = total > local;
  return 0;
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
    int retained_source = 0, remote_source = 0;
    queue_meta_init_clean(&row);
    if (queue_meta_random_nonce(row.nonce) != 0 ||
        queue_meta_legacy_latch_active_locked(&legacy_active) != 0 ||
        queue_meta_retained_source_owners_locked(&retained_source, &remote_source) != 0) {
      fprintf(stderr, "[queue] missing ownership metadata inventory unavailable; open denied\n");
      return -1;
    }
    /* A genuinely new database starts with the local owner. Retained sources
     * require a loss audit; legacy/unknown sources cannot resolve it locally. */
    if (!legacy_active && !remote_source)
      row.owner_version = EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_OWNER_LOCAL_V3;
    if ((legacy_active || retained_source) && queue_meta_begin_new_latch_locked(
        &row, 1, legacy_active ? "legacy_header_latch_migrated" :
                                "source_only_ownership_meta_missing") != 0) {
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
         row->owner_version == expected->owner_version &&
         row->counter == expected->latch_counter && row->epoch == expected->latch_epoch &&
         memcmp(row->nonce, expected->queue_nonce, sizeof(row->nonce)) == 0;
}

static void queue_meta_export_latch(const QueueMetaRow *row,
                                    EdrStorageQueueP0SourceOnlyLatch *out) {
  memset(out, 0, sizeof(*out));
  if (!row) return;
  memcpy(out->queue_nonce, row->nonce, sizeof(out->queue_nonce));
  out->owner_version = row->owner_version;
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
  if (row.owner_version != EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_OWNER_REMOTE_V2 ||
      strcmp(row.latch_state, EDR_QUEUE_META_STATE_BOUND) != 0 ||
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
    s_terminal_policy_held_frames = 0u;
    s_terminal_local_retained = 0u;
    return;
  }
  if (sqlite3_prepare_v2(
          s_db,
          "SELECT "
          "SUM(CASE WHEN state IN ('pending_intent','outcome_unknown','ready') OR (state IN ('completed','local_retained') AND intent_acked=0) THEN 1 ELSE 0 END),"
          "SUM(CASE WHEN state='failed' THEN 1 ELSE 0 END),"
          "SUM(CASE WHEN state='outcome_unknown' THEN 1 ELSE 0 END),"
          "SUM(intent_policy_held+source_policy_held+combined_policy_held),"
          "SUM(state='local_retained' AND intent_acked=1 AND combined_acked=1 AND source_acked=0) "
          "FROM enforcement_terminal_journal;",
          -1, &st, NULL) == SQLITE_OK) {
    if (sqlite3_step(st) == SQLITE_ROW) {
      s_terminal_pending = (uint64_t)sqlite3_column_int64(st, 0);
      s_terminal_failed = (uint64_t)sqlite3_column_int64(st, 1);
      s_terminal_outcome_unknown = (uint64_t)sqlite3_column_int64(st, 2);
      s_terminal_policy_held_frames = (uint64_t)sqlite3_column_int64(st, 3);
      s_terminal_local_retained = (uint64_t)sqlite3_column_int64(st,4);
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

void edr_storage_queue_test_set_p0_deferred_time(int64_t unix_seconds) {
  queue_state_lock();
  s_test_p0_deferred_time = unix_seconds;
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

static int terminal_journal_finish_ready_locked(sqlite3 *db) {
  if (exec_simple(db,"UPDATE enforcement_terminal_journal SET state='completed',completed_at=updated_at,"
      "reserved_bytes=0 WHERE state='ready' AND intent_acked=1 AND source_acked=1 AND combined_acked=1;")!=SQLITE_OK)
    return -1;
  /* ready is written only after a known final outcome. This local delivery
   * disposition frees a pending slot, never acknowledges its source bytes,
   * never discards evidence, and never resolves an outcome_unknown action. */
  return exec_simple(db,"UPDATE enforcement_terminal_journal SET state='local_retained' "
      "WHERE state='ready' AND intent_acked=1 AND source_policy_held=1 AND source_acked=0 AND combined_acked=1;")
      ==SQLITE_OK ? 0 : -1;
}
static int terminal_journal_reconcile_completed_locked(void) {
  int rc;
  if (terminal_journal_begin_durable_locked() != 0) return -1;
  rc = terminal_journal_finish_ready_locked(s_db);
  if (rc != 0) {
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
      "UPDATE enforcement_terminal_journal SET intent_acked=1,last_error='',updated_at=? "
      "WHERE state IN ('pending_intent','outcome_unknown','ready','completed','local_retained') "
      "AND intent_acked=0 AND intent_batch_id=?;";
  const char *source_sql =
      "UPDATE enforcement_terminal_journal SET source_acked=1,last_error='',updated_at=? "
      "WHERE state='ready' AND source_acked=0 AND source_batch_id=?;";
  const char *combined_sql =
      "UPDATE enforcement_terminal_journal SET combined_acked=1,last_error='',updated_at=? "
      "WHERE state='ready' AND combined_acked=0 AND combined_batch_id=?;";
  if (!db || !batch_id || !batch_id[0]) return -1;
  now = delivery_time();
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
  return terminal_journal_finish_ready_locked(db);
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
  terminal_intent_owner_unregister_locked();
  s_terminal_recheck_cursor=0;
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
  s_last_cleanup_ns = 0u;
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

/* Owned metadata only; callers supply fixed table/column names. No payload or
 * identity is rewritten. Each ALTER is restart-safe through table_info. */
static int queue_ensure_metadata_column_locked(const char *table, const char *name,
                                                const char *definition) {
  char sql[512]; sqlite3_stmt *st = NULL; int found = 0, rc;
  if (snprintf(sql, sizeof(sql), "PRAGMA table_info(%s);", table) <= 0 ||
      sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
  while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
    const unsigned char *column = sqlite3_column_text(st, 1);
    if (column && !strcmp((const char *)column, name)) found = 1;
  }
  sqlite3_finalize(st);
  if (rc != SQLITE_DONE) return -1;
  if (found) return 0;
  int n = snprintf(sql, sizeof(sql), "ALTER TABLE %s ADD COLUMN %s %s;", table, name, definition);
  return n > 0 && (size_t)n < sizeof(sql) && exec_simple(s_db, sql) == SQLITE_OK ? 0 : -1;
}

static int terminal_frame_metadata_ensure_locked(void) {
  static const char *prefixes[] = {"intent", "source", "combined"};
  for (size_t i = 0; i < 3u; ++i) {
    char name[64], definition[128];
    snprintf(name, sizeof(name), "%s_policy_held", prefixes[i]);
    snprintf(definition, sizeof(definition), "INTEGER NOT NULL DEFAULT 0 CHECK(%s IN (0,1))", name);
    if (queue_ensure_metadata_column_locked("enforcement_terminal_journal", name,
        definition) != 0) return -1;
    snprintf(name, sizeof(name), "%s_policy_reason", prefixes[i]);
    if (queue_ensure_metadata_column_locked("enforcement_terminal_journal", name,
        "TEXT NOT NULL DEFAULT ''") != 0) return -1;
    snprintf(name, sizeof(name), "%s_next_retry_at", prefixes[i]);
    int existed=terminal_journal_has_column_locked(name);
    if (existed<0) return -1;
    if (queue_ensure_metadata_column_locked("enforcement_terminal_journal", name,
        "INTEGER NOT NULL DEFAULT 0") != 0) return -1;
    if (!existed) {
      char sql[512];
      snprintf(sql,sizeof(sql),"UPDATE enforcement_terminal_journal SET %s=updated_at+"
        "CASE WHEN %s_retry_count>=9 THEN 300 ELSE 1<<MAX(0,%s_retry_count-1) END "
        "WHERE %s_retry_count>0 AND %s_acked=0;",name,prefixes[i],prefixes[i],prefixes[i],prefixes[i]);
      if (exec_simple(s_db,sql)!=SQLITE_OK) return -1;
    }
  }
  return 0;
}

static int queue_recovery_metadata_ensure_locked(void) {
  static const struct { const char *name; const char *type; } columns[] = {
    {"recovery_version", "INTEGER NOT NULL DEFAULT 0"},
    {"original_sha256", "TEXT NOT NULL DEFAULT ''"},
    {"projection_batch_id", "TEXT NOT NULL DEFAULT ''"},
    {"projection_sha256", "TEXT NOT NULL DEFAULT ''"},
    {"projector_version", "TEXT NOT NULL DEFAULT ''"},
    {"recovery_state", "TEXT NOT NULL DEFAULT ''"},
    {"origin_row_id", "INTEGER NOT NULL DEFAULT 0"}
  };
  for (size_t i=0; i<sizeof(columns)/sizeof(columns[0]); ++i)
    if (queue_ensure_metadata_column_locked("event_queue",columns[i].name,
                                           columns[i].type) != 0) return -1;
  if (queue_ensure_metadata_column_locked("queue_meta","legacy_lineage",
                                         "TEXT NOT NULL DEFAULT ''") != 0) return -1;
  if (queue_ensure_metadata_column_locked("queue_meta","last_recovery_owner",
                                         "TEXT NOT NULL DEFAULT ''") != 0) return -1;
  if (queue_ensure_metadata_column_locked("queue_meta","last_recovery_snapshot",
                                          "TEXT NOT NULL DEFAULT ''") != 0) return -1;
  /* One relation per immutable projection. The legacy pointer remains a
   * compatibility witness; it must never be overwritten by a newer version.
   * Backfill only an existing committed relation, never fabricate an ACK. */
  const char *sql =
    "CREATE TABLE IF NOT EXISTS queue_projection_relations ("
    "origin_row_id INTEGER NOT NULL,projector_version TEXT NOT NULL,"
    "batch_id TEXT NOT NULL UNIQUE,payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256)=64),"
    "receipt_state TEXT NOT NULL CHECK(receipt_state IN ('pending','acked')),"
    "created_at INTEGER NOT NULL,acked_at INTEGER NOT NULL DEFAULT 0,"
    "PRIMARY KEY(origin_row_id,projector_version),"
    "FOREIGN KEY(origin_row_id) REFERENCES event_queue(id) ON DELETE RESTRICT);"
    "INSERT INTO queue_projection_relations(origin_row_id,projector_version,batch_id,payload_sha256,"
    "receipt_state,created_at,acked_at) "
    "SELECT id,projector_version,projection_batch_id,projection_sha256,"
    "CASE WHEN recovery_state='projection_acked' THEN 'acked' ELSE 'pending' END,terminal_at,0 "
    "FROM event_queue WHERE recovery_version=1 AND origin_row_id=0 "
    "AND projection_batch_id<>'' AND projector_version<>'' AND length(projection_sha256)=64 "
    "ON CONFLICT(origin_row_id,projector_version) DO NOTHING;";
  if (exec_simple(s_db,sql)!=SQLITE_OK) return -1;
  sqlite3_stmt *check=NULL;
  if (sqlite3_prepare_v2(s_db,"SELECT COUNT(*) FROM event_queue o "
      "LEFT JOIN queue_projection_relations p ON p.origin_row_id=o.id AND p.projector_version=o.projector_version "
      "WHERE o.projection_batch_id<>'' AND (p.batch_id IS NULL OR p.batch_id<>o.projection_batch_id "
      "OR p.payload_sha256<>o.projection_sha256);",-1,&check,NULL)!=SQLITE_OK) return -1;
  int rc=sqlite3_step(check);
  int valid=rc==SQLITE_ROW && sqlite3_column_int64(check,0)==0;
  sqlite3_finalize(check); return valid?0:-1;
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
      "last_error TEXT NOT NULL DEFAULT '',"
      "source_latch_owner INTEGER NOT NULL DEFAULT 2 CHECK(source_latch_owner IN (2,3))"
      ");"
      "CREATE TABLE IF NOT EXISTS delivery_receipts_v1 ("
      "id INTEGER PRIMARY KEY,"
      "batch_id_sha256 TEXT NOT NULL CHECK(length(batch_id_sha256)=64),"
      "payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256)=64),"
      "payload_bytes INTEGER NOT NULL CHECK(payload_bytes>0),"
      "acked_at INTEGER NOT NULL,UNIQUE(batch_id_sha256,payload_sha256));"
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
  {
    sqlite3_stmt *column = NULL;
    int present = 0, rc;
    rc = sqlite3_prepare_v2(s_db, "PRAGMA table_info(event_queue);", -1, &column, NULL);
    if (rc == SQLITE_OK) {
      while ((rc = sqlite3_step(column)) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(column, 1);
        if (name && !strcmp((const char *)name, "next_retry_at")) present = 1;
      }
    }
    sqlite3_finalize(column);
    if (rc != SQLITE_DONE ||
        (!present && exec_simple(s_db, "ALTER TABLE event_queue ADD COLUMN "
                                     "next_retry_at INTEGER NOT NULL DEFAULT 0;") != SQLITE_OK) ||
        exec_simple(s_db, "CREATE INDEX IF NOT EXISTS idx_event_queue_due "
                         "ON event_queue(status,next_retry_at);") != SQLITE_OK) {
      fprintf(stderr, "[queue] retry deadline migration failed\n");
      sqlite3_close(s_db); s_db = NULL;
      queue_lock_release(); queue_state_unlock();
      return EDR_ERR_SQLITE_WRITE;
    }
  }
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

  {
    sqlite3_stmt *column = NULL;
    int present = 0, rc = sqlite3_prepare_v2(s_db, "PRAGMA table_info(queue_meta);", -1, &column, NULL);
    if (rc == SQLITE_OK) {
      while ((rc = sqlite3_step(column)) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(column, 1);
        if (name && !strcmp((const char *)name, "source_latch_owner")) present = 1;
      }
    }
    sqlite3_finalize(column);
    if (rc != SQLITE_DONE || (!present && exec_simple(s_db,
        "ALTER TABLE queue_meta ADD COLUMN source_latch_owner INTEGER NOT NULL DEFAULT 2 "
        "CHECK(source_latch_owner IN (2,3));") != SQLITE_OK)) {
      sqlite3_close(s_db); s_db = NULL; queue_lock_release(); queue_state_unlock();
      return EDR_ERR_SQLITE_WRITE;
    }
  }
  /* The source-only latch is a strict singleton in this same database. It is
   * initialized or migrated before any producer can enqueue evidence; a
   * malformed old header/metadata becomes a recovery-required audit rather
   * than a silently healthy capability. */
  if (terminal_frame_metadata_ensure_locked() != 0 ||
      queue_recovery_metadata_ensure_locked() != 0 || queue_meta_ensure_open_locked() != 0) {
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
  {
    QueueMetaRow owner;
    if (queue_meta_read_locked(&owner)!=0) {
      storage_queue_close_unlocked(); queue_state_unlock(); return EDR_ERR_SQLITE_WRITE;
    }
    intent_owner_lock();
    snprintf(s_intent_owner_path,sizeof(s_intent_owner_path),"%s",s_path);
    memcpy(s_intent_owner_nonce,owner.nonce,sizeof(s_intent_owner_nonce));
    intent_owner_unlock();
    edr_egress_set_p0_pair_validator(terminal_intent_association_validate,NULL);
  }
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

static EdrError source_only_latch_prepare(
    EdrStorageQueueP0SourceOnlyLatch *out, unsigned owner) {
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
  if (queue_meta_is_latched(&row) && row.owner_version != owner) {
    queue_meta_export_latch(&row, out);
    queue_state_unlock();
    return EDR_ERR_INVALID_ARG;
  }
  if (!queue_meta_is_latched(&row)) {
    row.owner_version = owner;
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

EdrError edr_storage_queue_p0_source_only_latch_prepare(
    EdrStorageQueueP0SourceOnlyLatch *out) {
  return source_only_latch_prepare(out, EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_OWNER_REMOTE_V2);
}
EdrError edr_storage_queue_p0_source_only_latch_prepare_local(
    EdrStorageQueueP0SourceOnlyLatch *out) {
  return source_only_latch_prepare(out, EDR_STORAGE_QUEUE_P0_SOURCE_ONLY_OWNER_LOCAL_V3);
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

static sqlite3_int64 p0_deferred_now_locked(void) {
#ifdef EDR_STORAGE_QUEUE_TESTING
  if (s_test_p0_deferred_time >= 0) return (sqlite3_int64)s_test_p0_deferred_time;
#endif
  return (sqlite3_int64)time(NULL);
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
    sqlite3_bind_int64(st, 1, p0_deferred_now_locked());
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
  sqlite3_bind_int64(st, 2, p0_deferred_now_locked() + delay);
  sqlite3_bind_text(st, 3, reason, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 4, p0_deferred_now_locked());
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

/* The remote-v2 and local-v3 insert paths share immutable storage, but their
 * ownership resolution is explicit and distinct. FULL commit makes evidence
 * retention and its own latch transition atomic without inventing a remote ACK. */
static EdrError source_only_enqueue(
    const EdrStorageQueueP0SourceOnlyLatch *expected, const char *event_id,
    const char *batch_id, const uint8_t *payload, size_t payload_len,
    int compressed, int recovery_audit, int local_owner) {
  QueueMetaRow row;
  sqlite3_stmt *st = NULL;
  int existing = 0;
  int add_pending = 0;
  int should_bind = 0;
  int rc;
  EdrError result = EDR_ERR_SQLITE_WRITE;
  if (!expected || expected->owner_version != (local_owner ? 3u : 2u) ||
      !expected->latched || !event_id || !event_id[0] || !batch_id ||
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
               old_status && strcmp((const char *)old_status, local_owner ? "local_evidence" : "pending") == 0;
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
            "INSERT INTO event_queue(batch_id,payload,created_at,compressed,severity,status,terminal_reason) "
            "VALUES(?,?,?,?,2,?,?);",
            -1, &st, NULL) != SQLITE_OK) {
      (void)queue_p0_latch_end_durable_locked(0);
      queue_state_unlock();
      return EDR_ERR_SQLITE_WRITE;
    }
    sqlite3_bind_text(st, 1, batch_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 2, payload, (int)payload_len, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)time(NULL));
    sqlite3_bind_int(st, 4, compressed ? 1 : 0);
    sqlite3_bind_text(st, 5, local_owner ? "local_evidence" : "pending", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 6, local_owner ? "source_only_local_v3" : "", -1, SQLITE_STATIC);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    st = NULL;
    if (rc != SQLITE_DONE) {
      (void)queue_p0_latch_end_durable_locked(0);
      queue_state_unlock();
      return EDR_ERR_SQLITE_WRITE;
    }
  }
  if (local_owner && should_bind) {
    /* A different normal source cannot resolve a recorded loss audit. */
    queue_meta_clear_latch_locked(&row);
  } else if (should_bind) {
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
  if (add_pending && !local_owner) s_pending++;
  result = EDR_OK;
  queue_state_unlock();
  return result;
}

EdrError edr_storage_queue_p0_source_only_enqueue_bound(
    const EdrStorageQueueP0SourceOnlyLatch *expected, const char *event_id,
    const char *batch_id, const uint8_t *payload, size_t payload_len,
    int compressed, int recovery_audit) {
  return source_only_enqueue(expected, event_id, batch_id, payload, payload_len,
                             compressed, recovery_audit, 0);
}
EdrError edr_storage_queue_p0_source_only_commit_local(
    const EdrStorageQueueP0SourceOnlyLatch *expected, const char *event_id,
    const char *batch_id, const uint8_t *payload, size_t payload_len,
    int compressed, int recovery_audit) {
  return source_only_enqueue(expected, event_id, batch_id, payload, payload_len,
                             compressed, recovery_audit, 1);
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

/* Only the persisted original intent for a known, proven final alert may be
 * sent as necessary association context. A label, source-only disposition or
 * an action intent without the matching combined alert cannot authorize it. */
static int terminal_intent_association_validate(const EdrEgressP0PairAssociation *tuple,
    const uint8_t *frame,size_t frame_len,void *user) {
  sqlite3 *db=NULL; sqlite3_stmt *st=NULL; int valid=0;
  (void)user;
  if (!tuple || !tuple->terminal_key || !tuple->source_event_id || !tuple->rule_id ||
      !frame || !frame_len || frame_len>EDR_EGRESS_FRAME_MAX) return 0;
  intent_owner_lock();
  if (!s_intent_owner_path[0] || sqlite3_open_v2(s_intent_owner_path,&db,
        SQLITE_OPEN_READONLY|SQLITE_OPEN_NOMUTEX,NULL)!=SQLITE_OK) goto done;
  sqlite3_busy_timeout(db,100);
  if (sqlite3_prepare_v2(db,
      "SELECT j.source_event_key,j.rule_id,j.process_generation_key,j.intent_wire,j.combined_wire,"
      "j.owner_key_sha256,m.queue_nonce FROM enforcement_terminal_journal j CROSS JOIN queue_meta m "
      "WHERE j.idempotency_key=? AND j.state IN ('ready','local_retained','completed') AND m.id=1;",
      -1,&st,NULL)!=SQLITE_OK) goto done;
  sqlite3_bind_text(st,1,tuple->terminal_key,-1,SQLITE_TRANSIENT);
  if (sqlite3_step(st)!=SQLITE_ROW) goto done;
  char generation[32],key_sha[65],stored_frame_sha[65],incoming_frame_sha[65];
  snprintf(generation,sizeof(generation),"startkey-%016llx",(unsigned long long)tuple->process_start_key);
  edr_sha256_hex((const uint8_t*)tuple->terminal_key,strlen(tuple->terminal_key),key_sha);
  const uint8_t *intent=sqlite3_column_blob(st,3),*combined=sqlite3_column_blob(st,4);
  int intent_len=sqlite3_column_bytes(st,3),combined_len=sqlite3_column_bytes(st,4);
  const void *nonce=sqlite3_column_blob(st,6);
  if (!terminal_sql_text_equal(sqlite3_column_text(st,0),sqlite3_column_bytes(st,0),tuple->source_event_id) ||
      !terminal_sql_text_equal(sqlite3_column_text(st,1),sqlite3_column_bytes(st,1),tuple->rule_id) ||
      !terminal_sql_text_equal(sqlite3_column_text(st,2),sqlite3_column_bytes(st,2),generation) ||
      !terminal_sql_text_equal(sqlite3_column_text(st,5),sqlite3_column_bytes(st,5),key_sha) ||
      !nonce || sqlite3_column_bytes(st,6)!=16 || memcmp(nonce,s_intent_owner_nonce,16) ||
      !intent || intent_len<16 || !combined || combined_len<16 ||
      rd_u32_le(intent)!=EDR_TRANSPORT_BATCH_MAGIC_RAW || rd_u32_le(intent+4)!=1u ||
      rd_u32_le(intent+8)!=(uint32_t)intent_len-12u || rd_u32_le(intent+12)!=(uint32_t)intent_len-16u ||
      rd_u32_le(combined)!=EDR_TRANSPORT_BATCH_MAGIC_RAW || rd_u32_le(combined+4)!=1u ||
      rd_u32_le(combined+8)!=(uint32_t)combined_len-12u || rd_u32_le(combined+12)!=(uint32_t)combined_len-16u)
    goto done;
  const uint8_t *original=NULL;
  if ((size_t)intent_len==frame_len+16u && !memcmp(intent+16,frame,frame_len)) original=intent;
  else if ((size_t)combined_len==frame_len+16u && !memcmp(combined+16,frame,frame_len)) original=combined;
  if (!original) goto done;
  edr_sha256_hex(original+16,frame_len,stored_frame_sha);
  edr_sha256_hex(frame,frame_len,incoming_frame_sha);
  valid=!strcmp(stored_frame_sha,incoming_frame_sha) &&
    edr_egress_p0_intent_matches(tuple,intent,(size_t)intent_len) &&
    edr_egress_p0_combined_matches(tuple,combined,(size_t)combined_len);
done:
  sqlite3_finalize(st); if (db) sqlite3_close(db);
  intent_owner_unlock(); return valid;
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
          sqlite3_bind_int64(st, 8, (sqlite3_int64)terminal_final_reserve_for_intent(intent_wire_len));
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
  out->policy_held_frames = s_terminal_policy_held_frames;
  out->local_retained = s_terminal_local_retained;
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

int edr_storage_queue_batch_presence(const char *batch_id,const uint8_t *wire,size_t wire_len) {
  if (!queue_text_valid(batch_id) || !wire || !wire_len || wire_len>INT_MAX) return -1;
  sqlite3_stmt *st=NULL; int result=-1;
  queue_state_lock();
  if (s_db && sqlite3_prepare_v2(s_db,"SELECT payload FROM event_queue WHERE batch_id=?;",
      -1,&st,NULL)==SQLITE_OK) {
    sqlite3_bind_text(st,1,batch_id,-1,SQLITE_TRANSIENT); int rc=sqlite3_step(st);
    if (rc==SQLITE_DONE) result=0;
    else if (rc==SQLITE_ROW) {
      const void *p=sqlite3_column_blob(st,0); int n=sqlite3_column_bytes(st,0);
      result=p && n==(int)wire_len && !memcmp(p,wire,wire_len) ? 1 : -1;
    }
  }
  sqlite3_finalize(st); queue_state_unlock(); return result;
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
      "WHERE id=? AND idempotency_key=? AND state IN ('pending_intent','outcome_unknown','ready');";
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
      "last_error='intent_transport_failed',updated_at=?1,"
      "intent_next_retry_at=?1+CASE WHEN intent_retry_count>=8 THEN 300 "
      "ELSE (1 << MAX(0,intent_retry_count)) END "
      "WHERE id=? AND idempotency_key=? AND state IN ('pending_intent','outcome_unknown','ready','completed','local_retained') "
      "AND intent_acked=0 AND intent_wire=?;";
  if (!db || !key || !wire || wire_len <= 0) return;
  if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_int64(st, 1, delivery_time());
    sqlite3_bind_int64(st, 2, id);
    sqlite3_bind_text(st, 3, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 4, wire, wire_len, SQLITE_TRANSIENT);
    (void)sqlite3_step(st);
    sqlite3_finalize(st);
  }
}

/* A journal delivery can confirm the exact ordinary held copy too. Deletion
 * is in the same FULL transaction as the real journal ACK; legacy source
 * owners and recovery lineage rows keep their separate owner contracts. */
static int terminal_journal_remove_ordinary_copy_locked(sqlite3 *db,sqlite3_int64 id,
    const char *key,const char *prefix,const uint8_t *wire,int wire_len) {
  sqlite3_stmt *st=NULL; char sql[512];
  int n=snprintf(sql,sizeof(sql),"DELETE FROM event_queue WHERE batch_id=(SELECT %s_batch_id "
    "FROM enforcement_terminal_journal WHERE id=? AND idempotency_key=?) AND payload=? "
    "AND severity<>2 AND origin_row_id=0 AND recovery_version=0;",prefix);
  if (n<0 || (size_t)n>=sizeof(sql) || sqlite3_prepare_v2(db,sql,-1,&st,NULL)!=SQLITE_OK) return -1;
  sqlite3_bind_int64(st,1,id); sqlite3_bind_text(st,2,key,-1,SQLITE_TRANSIENT);
  sqlite3_bind_blob(st,3,wire,wire_len,SQLITE_TRANSIENT);
  int rc=sqlite3_step(st); sqlite3_finalize(st); return rc==SQLITE_DONE?0:-1;
}

static int terminal_journal_ack_intent_locked(sqlite3 *db, sqlite3_int64 id, const char *key, const char *batch_id,
                                              const uint8_t *wire, int wire_len) {
  sqlite3_stmt *st = NULL;
  int acknowledged = 0;
  const char *sql =
      "UPDATE enforcement_terminal_journal SET intent_acked=1,last_error='',updated_at=? "
      "WHERE id=? AND idempotency_key=? AND state IN ('pending_intent','outcome_unknown','ready','completed','local_retained') "
      "AND intent_acked=0 AND intent_wire=?;";
  if (!db || !key || !wire || wire_len <= 0) return 0;
  if (terminal_journal_begin_durable_locked()!=0) return 0;
  if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_int64(st, 1, delivery_time());
    sqlite3_bind_int64(st, 2, id);
    sqlite3_bind_text(st, 3, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 4, wire, wire_len, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(db) == 1) acknowledged = 1;
    sqlite3_finalize(st);
  }
  if (acknowledged && terminal_journal_remove_ordinary_copy_locked(db,id,key,"intent",wire,wire_len)!=0)
    acknowledged=0;
  if (acknowledged && delivery_receipt_record_locked(db,batch_id,wire,wire_len)!=0) acknowledged=0;
  if (acknowledged && terminal_journal_finish_ready_locked(db)!=0) acknowledged=0;
  if (!acknowledged) (void)terminal_journal_end_durable_locked(0);
  else acknowledged=terminal_journal_end_durable_locked(1)==0;
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
                          "updated_at=?1,source_next_retry_at=?1+CASE WHEN source_retry_count>=8 THEN 300 "
                          "ELSE (1 << MAX(0,source_retry_count)) END WHERE id=? AND idempotency_key=? AND state='ready' "
                          "AND source_acked=0 AND source_wire=?;"
                        : "UPDATE enforcement_terminal_journal SET "
                          "combined_retry_count=combined_retry_count+1,last_error='combined_transport_failed',"
                          "updated_at=?1,combined_next_retry_at=?1+CASE WHEN combined_retry_count>=8 THEN 300 "
                          "ELSE (1 << MAX(0,combined_retry_count)) END WHERE id=? AND idempotency_key=? AND state='ready' "
                          "AND combined_acked=0 AND combined_wire=?;";
  if (!db || !key || !wire || wire_len <= 0) return;
  if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_int64(st, 1, delivery_time());
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
                          "last_error='intent_selection_transient',updated_at=? "
                          "WHERE id=? AND state IN ('pending_intent','outcome_unknown','ready','completed','local_retained') "
                          "AND intent_acked=0;"
                        : frame_kind == 1
                            ? "UPDATE enforcement_terminal_journal SET "
                              "last_error='source_selection_transient',updated_at=? "
                              "WHERE id=? AND state='ready' AND source_acked=0;"
                            : "UPDATE enforcement_terminal_journal SET "
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
                          "WHERE id=? AND state IN ('pending_intent','outcome_unknown','ready') "
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

static int terminal_journal_ack_frame_locked(sqlite3 *db, sqlite3_int64 id, const char *key, const char *batch_id,
                                             int source_frame, const uint8_t *wire, int wire_len) {
  sqlite3_stmt *st = NULL;
  const char *sql = source_frame
                        ? "UPDATE enforcement_terminal_journal SET source_acked=1,last_error='',updated_at=?,"
                          "state=CASE WHEN combined_acked=1 AND intent_acked=1 THEN 'completed' ELSE 'ready' END,"
                          "completed_at=CASE WHEN combined_acked=1 AND intent_acked=1 THEN ? ELSE completed_at END,"
                          "reserved_bytes=CASE WHEN combined_acked=1 AND intent_acked=1 THEN 0 ELSE reserved_bytes END "
                          "WHERE id=? AND idempotency_key=? AND state='ready' AND source_acked=0 "
                          "AND source_wire=?;"
                        : "UPDATE enforcement_terminal_journal SET combined_acked=1,last_error='',updated_at=?,"
                          "state=CASE WHEN source_acked=1 AND intent_acked=1 THEN 'completed' ELSE 'ready' END,"
                          "completed_at=CASE WHEN source_acked=1 AND intent_acked=1 THEN ? ELSE completed_at END,"
                          "reserved_bytes=CASE WHEN source_acked=1 AND intent_acked=1 THEN 0 ELSE reserved_bytes END "
                          "WHERE id=? AND idempotency_key=? AND state='ready' AND combined_acked=0 "
                          "AND combined_wire=?;";
  int acknowledged = 0;
  if (!db || !key || !wire || wire_len <= 0) return 0;
  if (terminal_journal_begin_durable_locked()!=0) return 0;
  if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
    /* A verified receipt changes only this frame's ACK under FULL durability.
     * Independent retry counters/deadlines remain diagnostic evidence. */
    sqlite3_int64 now = delivery_time();
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_int64(st, 2, now);
    sqlite3_bind_int64(st, 3, id);
    sqlite3_bind_text(st, 4, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 5, wire, wire_len, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(db) == 1) acknowledged = 1;
    sqlite3_finalize(st);
  }
  if (acknowledged && terminal_journal_remove_ordinary_copy_locked(db,id,key,
      source_frame?"source":"combined",wire,wire_len)!=0) acknowledged=0;
  if (acknowledged && delivery_receipt_record_locked(db,batch_id,wire,wire_len)!=0) acknowledged=0;
  if (acknowledged && terminal_journal_finish_ready_locked(db)!=0) acknowledged=0;
  if (!acknowledged) (void)terminal_journal_end_durable_locked(0);
  else acknowledged=terminal_journal_end_durable_locked(1)==0;
  if (acknowledged) terminal_journal_refresh_locked();
  return acknowledged;
}

static int terminal_journal_hold_frame_locked(sqlite3_int64 id, const char *key,
    int frame_kind, const char *batch_id, const uint8_t *wire, int wire_len, const char *reason) {
  static const char *prefixes[] = {"intent", "source", "combined"};
  char sql[768]; sqlite3_stmt *st = NULL; int held = 0;
  if (frame_kind < 0 || frame_kind > 2 || !key || !batch_id || !wire || wire_len <= 0) return 0;
  const char *prefix = prefixes[frame_kind];
  int n = snprintf(sql, sizeof(sql), "UPDATE enforcement_terminal_journal SET "
      "%s_policy_held=1,%s_policy_reason=?,updated_at=? "
      "WHERE id=? AND idempotency_key=? AND %s_batch_id=? AND %s_wire=? "
      "AND %s_acked=0 AND %s_policy_held=0;", prefix, prefix, prefix, prefix, prefix, prefix);
  if (n <= 0 || (size_t)n >= sizeof(sql) || terminal_journal_begin_durable_locked() != 0) return 0;
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_text(st, 1, reason, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, delivery_time()); sqlite3_bind_int64(st, 3, id);
    sqlite3_bind_text(st, 4, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, batch_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 6, wire, wire_len, SQLITE_TRANSIENT);
    held = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(s_db) == 1;
  }
  sqlite3_finalize(st);
  if (held && terminal_journal_finish_ready_locked(s_db)!=0) held=0;
  if (!held) (void)terminal_journal_end_durable_locked(0);
  else held = terminal_journal_end_durable_locked(1) == 0;
  if (held) terminal_journal_refresh_locked();
  return held;
}

static int terminal_journal_recheck_intents_locked(void) {
  for (unsigned examined=0;examined<32;examined++) {
    sqlite3_stmt *st=NULL; uint8_t *wire=NULL; sqlite3_int64 id=0; int len=0,rc;
    if (sqlite3_prepare_v2(s_db,"SELECT id,intent_wire FROM enforcement_terminal_journal "
        "WHERE state IN ('ready','completed','local_retained') AND intent_acked=0 AND intent_policy_held=1 AND id>? "
        "ORDER BY id LIMIT 1;",-1,&st,NULL)!=SQLITE_OK) return -1;
    sqlite3_bind_int64(st,1,s_terminal_recheck_cursor); rc=sqlite3_step(st);
    if (rc==SQLITE_ROW) {
      id=sqlite3_column_int64(st,0); len=sqlite3_column_bytes(st,1);
      if (len>0 && (size_t)len<=EDR_EGRESS_BATCH_MAX && sqlite3_column_blob(st,1)) {
        wire=malloc((size_t)len);
        if (wire) memcpy(wire,sqlite3_column_blob(st,1),(size_t)len);
      }
    }
    sqlite3_finalize(st); st=NULL;
    if (rc==SQLITE_DONE) { s_terminal_recheck_cursor=0; terminal_journal_refresh_locked(); return 0; }
    if (rc!=SQLITE_ROW || !wire) { free(wire); return -1; }
    s_terminal_recheck_cursor=id; char reason[96];
    if (len<16 || !edr_egress_batch_validate(wire,12,wire+12,(size_t)len-12,reason,sizeof(reason))) {
      free(wire); continue;
    }
    if (terminal_journal_begin_durable_locked()!=0) { free(wire); return -1; }
    if (sqlite3_prepare_v2(s_db,"UPDATE enforcement_terminal_journal SET intent_policy_held=0,"
        "intent_policy_reason='',intent_next_retry_at=0 WHERE id=? AND state IN ('ready','completed','local_retained') "
        "AND intent_acked=0 AND intent_policy_held=1 AND intent_wire=?;",-1,&st,NULL)!=SQLITE_OK) {
      (void)terminal_journal_end_durable_locked(0); free(wire); return -1;
    }
    sqlite3_bind_int64(st,1,id); sqlite3_bind_blob(st,2,wire,len,SQLITE_TRANSIENT);
    int updated=sqlite3_step(st)==SQLITE_DONE && sqlite3_changes(s_db)==1;
    sqlite3_finalize(st); free(wire);
    if (terminal_journal_end_durable_locked(updated)!=0 || !updated) return -1;
  }
  terminal_journal_refresh_locked(); return 0;
}

static int terminal_journal_hold_corrupt_legacy_intent_locked(sqlite3_int64 id,const char *reason) {
  sqlite3_stmt *st=NULL; int held=0;
  if (terminal_journal_begin_durable_locked()!=0) return -1;
  if (sqlite3_prepare_v2(s_db,"UPDATE enforcement_terminal_journal SET intent_policy_held=1,"
      "intent_policy_reason=?,last_error=?,updated_at=? WHERE id=? AND intent_acked=0 "
      "AND state IN ('completed','local_retained');",-1,&st,NULL)!=SQLITE_OK) {
    (void)terminal_journal_end_durable_locked(0); return -1;
  }
  sqlite3_bind_text(st,1,reason,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,2,reason,-1,SQLITE_TRANSIENT);
  sqlite3_bind_int64(st,3,delivery_time()); sqlite3_bind_int64(st,4,id);
  int rc=sqlite3_step(st); held=rc==SQLITE_DONE && sqlite3_changes(s_db)==1;
  sqlite3_finalize(st);
  if (rc!=SQLITE_DONE || terminal_journal_end_durable_locked(held)!=0) return -1;
  if (held) terminal_journal_refresh_locked();
  return held;
}

/* Returns 0 after consuming one state transition, 1 when no replayable frame
 * exists, and 2 after a transient selection/transport failure (caller stops
 * this drain pass). Allocation/SQLite read failures preserve durable state;
 * only impossible durable metadata or an invalid persisted wire becomes
 * terminally failed. */
#define TERMINAL_RETRY_DUE(prefix) \
  " AND " prefix "_policy_held=0 AND (" prefix "_next_retry_at<=?1 " \
  "OR " prefix "_next_retry_at>?1+300) "

static int drain_one_terminal_journal_frame(void) {
  static const char *const select_sql[3] = {
      "SELECT id,idempotency_key,intent_batch_id,intent_wire "
      "FROM enforcement_terminal_journal j "
      "WHERE state IN ('pending_intent','outcome_unknown','ready','completed','local_retained') AND intent_acked=0 "
      "AND intent_wire IS NOT NULL " TERMINAL_RETRY_DUE("intent") " AND NOT EXISTS (SELECT 1 FROM event_queue q "
      "WHERE q.batch_id=j.intent_batch_id AND q.status='pending') ORDER BY id ASC LIMIT 1;",
      "SELECT id,idempotency_key,source_batch_id,source_wire "
      "FROM enforcement_terminal_journal j WHERE state='ready' AND source_acked=0 "
      "AND source_wire IS NOT NULL " TERMINAL_RETRY_DUE("source") " AND NOT EXISTS (SELECT 1 FROM event_queue q "
      "WHERE q.batch_id=j.source_batch_id AND q.status='pending') ORDER BY id ASC LIMIT 1;",
      "SELECT id,idempotency_key,combined_batch_id,combined_wire "
      "FROM enforcement_terminal_journal j WHERE state='ready' AND combined_acked=0 "
      "AND combined_wire IS NOT NULL " TERMINAL_RETRY_DUE("combined") " AND NOT EXISTS (SELECT 1 FROM event_queue q "
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
    sqlite3_bind_int64(st, 1, delivery_time());
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
    int legacy_held=frame_kind==0?terminal_journal_hold_corrupt_legacy_intent_locked(id,
                                             "intent_durable_metadata_invalid"):0;
    if (legacy_held!=0) {
      if (legacy_held>0) s_terminal_replay_metadata_corruption_failures++;
      free(key); free(batch_id); free(wire); queue_state_unlock(); return legacy_held>0?0:2;
    }
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
    int legacy_held=frame_kind==0?terminal_journal_hold_corrupt_legacy_intent_locked(id,
                                             "intent_invalid_durable_wire"):0;
    if (legacy_held!=0) {
      free(key); free(batch_id); free(wire); queue_state_unlock(); return legacy_held>0?0:2;
    }
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
  {
    char reason[96];
    if (!edr_egress_batch_validate(wire, 12u, wire + 12u, (size_t)wire_len - 12u,
                                  reason, sizeof(reason))) {
      int held = terminal_journal_hold_frame_locked(id, key, frame_kind, batch_id, wire,
                                                    wire_len, reason);
      free(key); free(batch_id); free(wire); queue_state_unlock();
      return held ? 0 : 2;
    }
  }
  /* The ordinary queue's max-retry policy is intentionally inapplicable to
   * terminal source/result and combined frames. Once the action exists, its
   * final audit must remain replayable across any number of transport
   * failures; pending state and retry counters stay visible in health. */
  queue_state_unlock();

  int send = -1;
  int attempted = 0;
  if (edr_ingest_http_configured() && !edr_ingest_http_circuit_open() &&
      !edr_ingest_http_telemetry_deferred()) {
    attempted = 1;
    send = edr_transport_v2_report_events(batch_id, wire, 12u, wire + 12u,
                                          (size_t)wire_len - 12u);
  }
  if (send == 0) {
    int acknowledged = 0;
    queue_state_lock();
    if (s_db == selected_db && s_db_generation == selected_generation) {
      acknowledged = frame_kind == 0
                         ? terminal_journal_ack_intent_locked(s_db, id, key, batch_id, wire, wire_len)
                         : terminal_journal_ack_frame_locked(s_db, id, key, batch_id, frame_kind == 1,
                                                             wire, wire_len);
    }
    queue_state_unlock();
    free(key);
    free(batch_id);
    free(wire);
    return acknowledged ? 0 : 2;
  }
  queue_state_lock();
  if (attempted && s_db == selected_db && s_db_generation == selected_generation &&
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

/* Recovery is a bounded offline consumer of the existing immutable queue.
 * It does not initialize an agent or transport. Original rows and archived
 * remote ownership remain evidence; only newly identified projections send. */
#define EDR_QUEUE_RECOVERY_MAX_BYTES (128u * 1024u * 1024u)
typedef struct {
  sqlite3_int64 id;
  int terminal_kind; /* -2 linked projection, -1 original, otherwise journal */
  sqlite3_int64 origin_id;
  int previous_recovery_version;
  char batch_id[256];
  uint8_t *wire;
  size_t wire_len;
  char original_sha[65];
  uint8_t *projection;
  size_t projection_len;
  uint32_t frames;
  char reason[96];
  int understood;
} QueueRecoveryBatch;

static int recovery_column_present(const char *table, const char *name) {
  char sql[96]; sqlite3_stmt *st=NULL; int present=0, rc;
  snprintf(sql,sizeof(sql),"PRAGMA table_info(%s);",table);
  if (sqlite3_prepare_v2(s_db,sql,-1,&st,NULL)!=SQLITE_OK) return -1;
  while ((rc=sqlite3_step(st))==SQLITE_ROW) {
    const unsigned char *value=sqlite3_column_text(st,1);
    if (value && !strcmp((const char *)value,name)) present=1;
  }
  sqlite3_finalize(st); return rc==SQLITE_DONE ? present : -1;
}

static void recovery_hash_text(EdrSha256Ctx *sha,const char *text) {
  uint8_t length[8]; uint64_t n=text ? strlen(text) : 0;
  for (unsigned i=0;i<8;i++) length[i]=(uint8_t)(n>>(i*8));
  edr_sha256_update(sha,length,8);
  if (n) edr_sha256_update(sha,(const uint8_t *)text,(size_t)n);
}
static void recovery_hash_number(EdrSha256Ctx *sha,uint64_t number) {
  uint8_t bytes[8];
  for (unsigned i=0;i<8;i++) bytes[i]=(uint8_t)(number>>(i*8));
  edr_sha256_update(sha,bytes,8);
}
static void recovery_hex(const uint8_t *bytes,size_t n,char *out) {
  static const char hex[]="0123456789abcdef";
  for (size_t i=0;i<n;i++) { out[i*2]=hex[bytes[i]>>4]; out[i*2+1]=hex[bytes[i]&15]; }
  out[n*2]='\0';
}
static int recovery_owner_equal(const QueueMetaRow *row,
                                const EdrStorageQueueP0SourceOnlyLatch *expected) {
  return row->owner_version==expected->owner_version && row->counter==expected->latch_counter &&
    row->epoch==expected->latch_epoch && !memcmp(row->nonce,expected->queue_nonce,16) &&
    queue_meta_is_latched(row)==!!expected->latched &&
    !strcmp(row->recovery_event_id,expected->recovery_event_id) &&
    !strcmp(row->recovery_batch_id,expected->recovery_batch_id) &&
    (!strcmp(row->latch_state,EDR_QUEUE_META_STATE_RECOVERY_REQUIRED))==!!expected->recovery_required;
}
static int recovery_add_row(sqlite3_stmt *st,int kind,QueueRecoveryBatch *batch,
                            uint64_t *total,EdrSha256Ctx *sha) {
  memset(batch,0,sizeof(*batch)); batch->terminal_kind=kind;
  batch->id=sqlite3_column_int64(st,0);
  const unsigned char *id=sqlite3_column_text(st,1);
  int id_len=sqlite3_column_bytes(st,1), n=sqlite3_column_bytes(st,2);
  const uint8_t *wire=sqlite3_column_blob(st,2);
  if (batch->id<=0 || !queue_sql_text_valid(id,id_len) || id_len>=256 || !wire || n<=0 ||
      (uint64_t)n>EDR_QUEUE_RECOVERY_MAX_BYTES || *total>EDR_QUEUE_RECOVERY_MAX_BYTES-(uint64_t)n)
    return -1;
  memcpy(batch->batch_id,id,(size_t)id_len); batch->batch_id[id_len]='\0';
  batch->wire=malloc((size_t)n);
  if (!batch->wire) return -1;
  memcpy(batch->wire,wire,(size_t)n); batch->wire_len=(size_t)n;
  edr_sha256_hex(wire,(size_t)n,batch->original_sha); *total+=(uint64_t)n;
  if (kind<0) {
    batch->previous_recovery_version=sqlite3_column_int(st,8);
    if (batch->previous_recovery_version!=0 && batch->previous_recovery_version!=1) return -1;
    if (batch->previous_recovery_version==1) {
      const unsigned char *stored_sha=sqlite3_column_text(st,9);
      if (!stored_sha || sqlite3_column_bytes(st,9)!=64 ||
          memcmp(stored_sha,batch->original_sha,64)) return -1;
    }
    if (kind==-2) {
      batch->origin_id=sqlite3_column_int64(st,11);
      if (batch->origin_id<=0 || recovery_projection_origin_valid_locked(batch->origin_id,
          batch->batch_id,batch->wire,batch->wire_len)!=1) return -1;
    }
  }
  recovery_hash_number(sha,(uint64_t)batch->id);
  recovery_hash_number(sha,(uint64_t)(kind+1));
  recovery_hash_text(sha,batch->batch_id); recovery_hash_text(sha,batch->original_sha);
  /* Include status/retry/compression/severity and policy reason in the
   * inventory so a stale operator authorization cannot silently match. */
  for (int col=3;col<sqlite3_column_count(st);col++) {
    const unsigned char *v=sqlite3_column_text(st,col);
    if (v && strlen((const char *)v)!=(size_t)sqlite3_column_bytes(st,col)) return -1;
    recovery_hash_text(sha,(const char *)v);
  }
  return 0;
}
static int recovery_read_lineage(char **out) {
  *out=NULL; int column=recovery_column_present("queue_meta","legacy_lineage");
  if (column<0) return -1;
  if (!column) { *out=calloc(1,1); return *out ? 0 : -1; }
  sqlite3_stmt *st=NULL;
  if (sqlite3_prepare_v2(s_db,"SELECT legacy_lineage FROM queue_meta WHERE id=1;",-1,&st,NULL)
      !=SQLITE_OK) return -1;
  int rc=sqlite3_step(st); const unsigned char *v=rc==SQLITE_ROW ? sqlite3_column_text(st,0) : NULL;
  int len=v ? sqlite3_column_bytes(st,0) : -1;
  if (!v || len<0 || len>=2048 || strlen((const char *)v)!=(size_t)len) {
    sqlite3_finalize(st); return -1;
  }
  *out=malloc((size_t)len+1);
  if (*out) memcpy(*out,v,(size_t)len+1);
  sqlite3_finalize(st); return *out ? 0 : -1;
}

static int recovery_bound_sha(const QueueMetaRow *row,char out[65]) {
  out[0]='\0'; if (!row->recovery_batch_id[0]) return 0;
  sqlite3_stmt *st=NULL;
  if (sqlite3_prepare_v2(s_db,"SELECT payload FROM event_queue WHERE batch_id=?;",-1,&st,NULL)
      !=SQLITE_OK) return -1;
  sqlite3_bind_text(st,1,row->recovery_batch_id,-1,SQLITE_TRANSIENT);
  int rc=sqlite3_step(st);
  if (rc==SQLITE_ROW) {
    const uint8_t *wire=sqlite3_column_blob(st,0); int n=sqlite3_column_bytes(st,0);
    if (!wire || n<=0 || (uint64_t)n>EDR_QUEUE_RECOVERY_MAX_BYTES) {
      sqlite3_finalize(st); return -1;
    }
    edr_sha256_hex(wire,(size_t)n,out);
    if (sqlite3_step(st)!=SQLITE_DONE) { sqlite3_finalize(st); return -1; }
  } else if (rc!=SQLITE_DONE) { sqlite3_finalize(st); return -1; }
  sqlite3_finalize(st); return 0;
}
static char *recovery_lineage_create(const QueueMetaRow *old,const char *bound_sha,
                                     const EdrStorageQueueRecoveryRequest *request,
                                     const char *snapshot) {
  cJSON *obj=cJSON_CreateObject(); if (!obj) return NULL;
  char nonce[33],number[32]; recovery_hex(old->nonce,16,nonce);
  cJSON_AddNumberToObject(obj,"version",1);
  cJSON_AddNumberToObject(obj,"owner",old->owner_version);
  cJSON_AddBoolToObject(obj,"unacknowledged",old->owner_version==2 && queue_meta_is_latched(old));
  cJSON_AddStringToObject(obj,"nonce",nonce);
  snprintf(number,sizeof(number),"%llu",(unsigned long long)old->counter);
  cJSON_AddStringToObject(obj,"counter",number);
  snprintf(number,sizeof(number),"%llu",(unsigned long long)old->epoch);
  cJSON_AddStringToObject(obj,"epoch",number);
  cJSON_AddStringToObject(obj,"state",old->latch_state);
  cJSON_AddStringToObject(obj,"event_id",old->recovery_event_id);
  cJSON_AddStringToObject(obj,"batch_id",old->recovery_batch_id);
  cJSON_AddStringToObject(obj,"bound_wire_sha256",bound_sha);
  cJSON_AddStringToObject(obj,"bound_wire_status",bound_sha[0]?"retained":"unavailable");
  cJSON_AddStringToObject(obj,"inventory_sha256",snapshot);
  cJSON_AddStringToObject(obj,"operator_tenant",request->tenant_id);
  cJSON_AddStringToObject(obj,"operator_endpoint",request->endpoint_id);
  cJSON_AddNumberToObject(obj,"max_batches",request->max_batches);
  snprintf(number,sizeof(number),"%llu",(unsigned long long)request->after_row_id);
  cJSON_AddStringToObject(obj,"after_row_id",number);
  char *json=cJSON_GetArraySize(obj)==16?cJSON_PrintUnformatted(obj):NULL;
  cJSON_Delete(obj);
  if (json && strlen(json)>=2048) { free(json); json=NULL; }
  return json;
}
static int recovery_authorization_equal(const char *json,const EdrStorageQueueRecoveryRequest *request) {
  const EdrStorageQueueP0SourceOnlyLatch *expected=&request->expected_owner;
  cJSON *obj=cJSON_Parse(json); if (!obj) return 0;
  cJSON *nonce=cJSON_GetObjectItemCaseSensitive(obj,"nonce");
  cJSON *counter=cJSON_GetObjectItemCaseSensitive(obj,"counter");
  cJSON *epoch=cJSON_GetObjectItemCaseSensitive(obj,"epoch");
  cJSON *owner=cJSON_GetObjectItemCaseSensitive(obj,"owner");
  cJSON *tenant=cJSON_GetObjectItemCaseSensitive(obj,"operator_tenant");
  cJSON *endpoint=cJSON_GetObjectItemCaseSensitive(obj,"operator_endpoint");
  cJSON *limit=cJSON_GetObjectItemCaseSensitive(obj,"max_batches");
  cJSON *cursor=cJSON_GetObjectItemCaseSensitive(obj,"after_row_id");
  char hex[33],c[32],e[32]; recovery_hex(expected->queue_nonce,16,hex);
  snprintf(c,sizeof(c),"%llu",(unsigned long long)expected->latch_counter);
  snprintf(e,sizeof(e),"%llu",(unsigned long long)expected->latch_epoch);
  char cursor_text[32]; snprintf(cursor_text,sizeof(cursor_text),"%llu",(unsigned long long)request->after_row_id);
  int same=cJSON_IsNumber(owner) && owner->valuedouble==(double)expected->owner_version &&
    cJSON_IsString(nonce) && !strcmp(nonce->valuestring,hex) &&
    cJSON_IsString(counter) && !strcmp(counter->valuestring,c) &&
    cJSON_IsString(epoch) && !strcmp(epoch->valuestring,e) &&
    cJSON_IsString(tenant) && !strcmp(tenant->valuestring,request->tenant_id) &&
    cJSON_IsString(endpoint) && !strcmp(endpoint->valuestring,request->endpoint_id) &&
    cJSON_IsNumber(limit) && limit->valuedouble==(double)request->max_batches &&
    cJSON_IsString(cursor) && !strcmp(cursor->valuestring,cursor_text);
  cJSON_Delete(obj); return same;
}
static int recovery_store_lineage(const char *lineage) {
  sqlite3_stmt *st=NULL;
  if (sqlite3_prepare_v2(s_db,"UPDATE queue_meta SET legacy_lineage=? WHERE id=1 AND legacy_lineage='';",
      -1,&st,NULL)!=SQLITE_OK) return -1;
  sqlite3_bind_text(st,1,lineage,-1,SQLITE_TRANSIENT);
  int rc=sqlite3_step(st), changed=sqlite3_changes(s_db); sqlite3_finalize(st);
  return rc==SQLITE_DONE && changed==1 ? 0 : -1;
}

static int recovery_projection_origin_valid_locked(sqlite3_int64 origin_id,const char *batch_id,
                                                    const uint8_t *wire,size_t wire_len) {
  char received_sha[65],actual_sha[65]; sqlite3_stmt *st=NULL;
  edr_sha256_hex(wire,wire_len,received_sha);
  /* Read-only maintenance must also understand an unmigrated v1 database. */
  int relations=recovery_column_present("queue_projection_relations","origin_row_id");
  if (relations<0) return -1;
  const char *query=relations ?
    "SELECT o.payload,o.original_sha256 FROM event_queue o JOIN queue_projection_relations p "
    "ON p.origin_row_id=o.id WHERE o.id=? AND o.recovery_version=1 AND p.batch_id=? "
    "AND p.payload_sha256=? AND p.receipt_state='pending' AND o.status='local_evidence';" :
    "SELECT payload,original_sha256 FROM event_queue WHERE id=? "
    "AND recovery_version=1 AND recovery_state='projection_pending' AND projection_batch_id=? "
    "AND projection_sha256=? AND status='local_evidence';";
  if (sqlite3_prepare_v2(s_db,query,-1,&st,NULL)!=SQLITE_OK) return -1;
  sqlite3_bind_int64(st,1,origin_id); sqlite3_bind_text(st,2,batch_id,-1,SQLITE_TRANSIENT);
  sqlite3_bind_text(st,3,received_sha,-1,SQLITE_TRANSIENT);
  int rc=sqlite3_step(st); const uint8_t *original=rc==SQLITE_ROW ? sqlite3_column_blob(st,0) : NULL;
  int n=rc==SQLITE_ROW ? sqlite3_column_bytes(st,0) : 0;
  const unsigned char *expected=rc==SQLITE_ROW ? sqlite3_column_text(st,1) : NULL;
  int valid=original && n>0 && expected && sqlite3_column_bytes(st,1)==64 &&
    edr_sha256_hex(original,(size_t)n,actual_sha)==0 && !strcmp(actual_sha,(const char *)expected);
  sqlite3_finalize(st); return rc==SQLITE_ROW || rc==SQLITE_DONE ? valid : -1;
}
static int recovery_projection_ack_locked(sqlite3_int64 origin_id,const char *batch_id,
                                           const uint8_t *wire,size_t wire_len) {
  if (recovery_projection_origin_valid_locked(origin_id,batch_id,wire,wire_len)!=1) return -1;
  char received_sha[65]; sqlite3_stmt *st=NULL; int rc;
  edr_sha256_hex(wire,wire_len,received_sha);
  if (sqlite3_prepare_v2(s_db,"UPDATE queue_projection_relations SET receipt_state='acked',acked_at=? "
      "WHERE origin_row_id=? AND receipt_state='pending' AND batch_id=? "
      "AND payload_sha256=?;",-1,&st,NULL)!=SQLITE_OK) return -1;
  sqlite3_bind_int64(st,1,delivery_time()); sqlite3_bind_int64(st,2,origin_id);
  sqlite3_bind_text(st,3,batch_id,-1,SQLITE_TRANSIENT);
  sqlite3_bind_text(st,4,received_sha,-1,SQLITE_TRANSIENT);
  rc=sqlite3_step(st); int changed=sqlite3_changes(s_db); sqlite3_finalize(st);
  if (rc!=SQLITE_DONE || changed!=1) return -1;
  /* Only the exact legacy child changes its compatibility status. A v2 ACK
   * neither acknowledges the v1 child nor clears the independent health latch. */
  if (sqlite3_prepare_v2(s_db,"UPDATE event_queue SET recovery_state='projection_acked' "
      "WHERE id=? AND projection_batch_id=? AND projection_sha256=?;",-1,&st,NULL)!=SQLITE_OK) return -1;
  sqlite3_bind_int64(st,1,origin_id); sqlite3_bind_text(st,2,batch_id,-1,SQLITE_TRANSIENT);
  sqlite3_bind_text(st,3,received_sha,-1,SQLITE_TRANSIENT);
  rc=sqlite3_step(st); sqlite3_finalize(st); return rc==SQLITE_DONE?0:-1;
}

#ifdef EDR_STORAGE_QUEUE_TESTING
static int s_test_recovery_stop_phase;
void edr_storage_queue_test_stop_recovery_phase(int phase) { s_test_recovery_stop_phase=phase; }
static void recovery_test_stop(int phase) {
#ifndef _WIN32
  if (s_test_recovery_stop_phase==phase) { kill(getpid(),SIGSTOP); }
#else
  if (s_test_recovery_stop_phase==phase) {
    /* Native Windows fixture kills the real child process at this durable
     * boundary. No SQLite close/rollback handler can run first. */
    TerminateProcess(GetCurrentProcess(),95);
  }
#endif
}
#else
static void recovery_test_stop(int phase) { (void)phase; }
#endif

EdrError edr_storage_queue_recover_v1(const char *path,const EdrStorageQueueRecoveryRequest *request,
                                     EdrStorageQueueRecoveryReport *report) {
  QueueRecoveryBatch batches[EDR_STORAGE_QUEUE_RECOVERY_MAX_BATCHES];
  QueueMetaRow old; char *lineage=NULL,*new_lineage=NULL,*authorization=NULL; char bound_sha[65];
  sqlite3_stmt *st=NULL; unsigned count=0; uint64_t total=0; int transaction=0;
  int handle_owned=0,lock_owned=0;
  EdrError result=EDR_ERR_SQLITE_WRITE; EdrSha256Ctx inventory;
  memset(batches,0,sizeof(batches));
  if (!report) return EDR_ERR_INVALID_ARG;
  memset(report,0,sizeof(*report)); report->version=1;
  snprintf(report->reason,sizeof(report->reason),"invalid_recovery_arguments");
  if (!path || !path[0] || strlen(path)>=sizeof(s_path) || !request || request->version!=1 ||
      !request->max_batches || request->max_batches>32 || !request->tenant_id ||
      request->after_row_id>(uint64_t)INT64_MAX ||
      !request->tenant_id[0] || strlen(request->tenant_id)>127 || !request->endpoint_id ||
      !request->endpoint_id[0] || strlen(request->endpoint_id)>127 ||
#ifdef _WIN32
      !((strlen(path)>=3 && path[1]==':' && (path[2]=='\\'||path[2]=='/')) ||
        (path[0]=='\\' && path[1]=='\\')) ||
#else
      path[0]!='/' ||
#endif
      (request->apply && (request->target_owner_version!=3 ||
                         strlen(request->expected_inventory_sha256)!=64))) return EDR_ERR_INVALID_ARG;
  queue_state_lock();
  if (s_db) { result=EDR_ERR_QUEUE_LOCKED; snprintf(report->reason,96,"agent_queue_must_be_closed"); goto done; }
  load_queue_db_limit(); memcpy(s_path,path,strlen(path)+1);
  result=queue_lock_acquire(path); if (result!=EDR_OK) { snprintf(report->reason,96,"exclusive_queue_lock_unavailable"); goto done; }
  lock_owned=1;
  result=EDR_ERR_SQLITE_OPEN;
  handle_owned=1;
  if (sqlite3_open_v2(path,&s_db,request->apply?SQLITE_OPEN_READWRITE:SQLITE_OPEN_READONLY,NULL)
      !=SQLITE_OK) { snprintf(report->reason,96,"existing_queue_open_failed"); goto done; }
  sqlite3_busy_timeout(s_db,2000);
  /* Snapshot authorization and every subsequent mutation share one SQLite
   * writer transaction. The cooperative file lock alone cannot stop an
   * unrelated SQLite client changing metadata between check and commit. */
  if (request->apply) {
    if (terminal_journal_begin_durable_locked()!=0) goto write_failed;
    transaction=1;
  } else {
    if (exec_simple(s_db,"BEGIN;")!=SQLITE_OK) goto read_failed;
    transaction=2; /* Consistent read snapshot on a READONLY handle. */
  }
  if (queue_meta_read_locked(&old)!=0 || recovery_read_lineage(&lineage)!=0 ||
      recovery_bound_sha(&old,bound_sha)!=0) { snprintf(report->reason,96,"ownership_inventory_read_failed"); goto done; }
  intent_owner_lock();
  snprintf(s_intent_owner_path,sizeof(s_intent_owner_path),"%s",s_path);
  memcpy(s_intent_owner_nonce,old.nonce,sizeof(s_intent_owner_nonce));
  intent_owner_unlock();
  edr_egress_set_p0_pair_validator(terminal_intent_association_validate,NULL);
  queue_meta_export_latch(&old,&report->current_owner);
  report->legacy_owner_unacknowledged=lineage[0]?1:0;
  int previous_column=recovery_column_present("queue_meta","last_recovery_snapshot");
  int previous_snapshot=0;
  if (previous_column<0) goto read_failed;
  if (previous_column==1) {
    if (sqlite3_prepare_v2(s_db,"SELECT last_recovery_snapshot,last_recovery_owner FROM queue_meta WHERE id=1;",
        -1,&st,NULL)!=SQLITE_OK || sqlite3_step(st)!=SQLITE_ROW) goto read_failed;
    const unsigned char *previous=sqlite3_column_text(st,0);
    const unsigned char *previous_owner=sqlite3_column_text(st,1);
    previous_snapshot=previous && sqlite3_column_bytes(st,0)>0;
    if (request->apply && previous && sqlite3_column_bytes(st,0)==64 &&
        !memcmp(previous,request->expected_inventory_sha256,64) && previous_owner &&
        recovery_authorization_equal((const char *)previous_owner,request)) {
      sqlite3_finalize(st); st=NULL;
      memcpy(report->inventory_sha256,request->expected_inventory_sha256,65);
      report->applied=1; snprintf(report->reason,96,"matching_inventory_already_committed_no_remote_ack");
      result=EDR_OK; goto done;
    }
    sqlite3_finalize(st); st=NULL;
  }
  edr_sha256_init(&inventory); recovery_hash_text(&inventory,"queue-recovery-v1");
  recovery_hash_text(&inventory,request->tenant_id); recovery_hash_text(&inventory,request->endpoint_id);
  recovery_hash_number(&inventory,request->max_batches);
  recovery_hash_number(&inventory,request->after_row_id);
  recovery_hash_text(&inventory,EDR_EGRESS_PROJECTOR_VERSION);
  edr_sha256_update(&inventory,old.nonce,16);
  recovery_hash_number(&inventory,old.owner_version); recovery_hash_number(&inventory,old.counter);
  recovery_hash_number(&inventory,old.epoch); recovery_hash_text(&inventory,old.latch_state);
  recovery_hash_text(&inventory,old.recovery_event_id); recovery_hash_text(&inventory,old.recovery_batch_id);
  recovery_hash_text(&inventory,bound_sha); recovery_hash_text(&inventory,lineage);
  int recovery_columns=recovery_column_present("event_queue","recovery_version");
  int projection_relations=recovery_column_present("queue_projection_relations","origin_row_id");
  if (projection_relations<0) goto read_failed;
  const char *query=recovery_columns==1 && projection_relations ?
    "SELECT id,batch_id,payload,status,compressed,severity,retry_count,terminal_reason,"
    "recovery_version,original_sha256,recovery_state FROM event_queue o "
    "WHERE origin_row_id=0 AND (recovery_version=0 OR recovery_state='retained_unresolved' OR "
    "(recovery_version=1 AND projector_version<>?4 AND projection_batch_id<>'' AND NOT EXISTS "
    "(SELECT 1 FROM queue_projection_relations p WHERE p.origin_row_id=o.id AND p.projector_version=?4))) "
    "AND (id>?3 OR batch_id=?1) AND (status!='local_evidence' OR terminal_reason!='source_only_local_v3') "
    "ORDER BY CASE WHEN batch_id=?1 THEN 0 ELSE 1 END,id LIMIT ?2;" : recovery_columns==1 ?
    "SELECT id,batch_id,payload,status,compressed,severity,retry_count,terminal_reason,"
    "recovery_version,original_sha256,recovery_state FROM event_queue "
    "WHERE (recovery_version=0 OR recovery_state='retained_unresolved' OR "
    "(recovery_version=1 AND projector_version<>?4 AND projection_batch_id<>'')) AND origin_row_id=0 "
    "AND (id>?3 OR batch_id=?1) AND "
    "(status!='local_evidence' OR terminal_reason!='source_only_local_v3') "
    "ORDER BY CASE WHEN batch_id=?1 THEN 0 ELSE 1 END,id LIMIT ?2;" :
    "SELECT id,batch_id,payload,status,compressed,severity,retry_count,terminal_reason,0,'','' FROM event_queue "
    "WHERE (id>?3 OR batch_id=?1) AND (status!='local_evidence' OR terminal_reason!='source_only_local_v3') "
    "ORDER BY CASE WHEN batch_id=?1 THEN 0 ELSE 1 END,id LIMIT ?2;";
  result=EDR_ERR_SQLITE_WRITE;
  if (recovery_columns<0 || sqlite3_prepare_v2(s_db,query,-1,&st,NULL)!=SQLITE_OK) goto read_failed;
  sqlite3_bind_text(st,1,old.recovery_batch_id,-1,SQLITE_TRANSIENT);
  sqlite3_bind_int(st,2,(int)request->max_batches);
  sqlite3_bind_int64(st,3,(sqlite3_int64)request->after_row_id);
  if (recovery_columns==1) sqlite3_bind_text(st,4,EDR_EGRESS_PROJECTOR_VERSION,-1,SQLITE_STATIC);
  int rc;
  report->last_event_row_id=request->after_row_id;
  while ((rc=sqlite3_step(st))==SQLITE_ROW) {
    if (recovery_add_row(st,-1,&batches[count],&total,&inventory)!=0) goto read_failed;
    if ((uint64_t)batches[count].id>report->last_event_row_id)
      report->last_event_row_id=(uint64_t)batches[count].id;
    count++;
  }
  sqlite3_finalize(st); st=NULL; if (rc!=SQLITE_DONE) goto read_failed;
  if (recovery_columns==1 && count<request->max_batches) {
    const char *resume_query=projection_relations ?
      "SELECT q.id,q.batch_id,q.payload,q.status,q.compressed,q.severity,"
      "q.retry_count,q.terminal_reason,q.recovery_version,p.payload_sha256,q.recovery_state,q.origin_row_id "
      "FROM event_queue q JOIN queue_projection_relations p ON p.origin_row_id=q.origin_row_id AND p.batch_id=q.batch_id "
      "WHERE q.origin_row_id>0 AND q.status IN ('policy_held','dead_letter') AND q.id>?1 "
      "ORDER BY q.id LIMIT ?2;" : "SELECT q.id,q.batch_id,q.payload,q.status,q.compressed,q.severity,"
      "q.retry_count,q.terminal_reason,q.recovery_version,o.projection_sha256,q.recovery_state,q.origin_row_id "
      "FROM event_queue q JOIN event_queue o ON o.id=q.origin_row_id "
      "WHERE q.origin_row_id>0 AND q.status IN ('policy_held','dead_letter') AND q.id>?1 "
      "ORDER BY q.id LIMIT ?2;";
    if (sqlite3_prepare_v2(s_db,resume_query,-1,&st,NULL)!=SQLITE_OK) goto read_failed;
    sqlite3_bind_int64(st,1,(sqlite3_int64)request->after_row_id);
    sqlite3_bind_int(st,2,(int)(request->max_batches-count));
    while ((rc=sqlite3_step(st))==SQLITE_ROW) {
      if (recovery_add_row(st,-2,&batches[count],&total,&inventory)!=0) goto read_failed;
      if ((uint64_t)batches[count].id>report->last_event_row_id)
        report->last_event_row_id=(uint64_t)batches[count].id;
      count++;
    }
    sqlite3_finalize(st); st=NULL; if (rc!=SQLITE_DONE) goto read_failed;
  }
  static const char *prefixes[]={"intent","source","combined"};
  int terminal_columns=recovery_column_present("enforcement_terminal_journal","intent_policy_held");
  if (terminal_columns<0) goto read_failed;
  for (int kind=0;terminal_columns==1 && kind<3 && count<request->max_batches;kind++) {
    char sql[640]; const char *p=prefixes[kind];
    snprintf(sql,sizeof(sql),"SELECT id,%s_batch_id,%s_wire,state,%s_retry_count,%s_policy_reason "
      "FROM enforcement_terminal_journal WHERE %s_policy_held=1 AND %s_acked=0 "
      "AND state IN ('ready','local_retained','pending_intent','outcome_unknown') ORDER BY id LIMIT ?;",p,p,p,p,p,p);
    if (sqlite3_prepare_v2(s_db,sql,-1,&st,NULL)!=SQLITE_OK) goto read_failed;
    sqlite3_bind_int(st,1,(int)(request->max_batches-count));
    while ((rc=sqlite3_step(st))==SQLITE_ROW) {
      if (recovery_add_row(st,kind,&batches[count],&total,&inventory)!=0) goto read_failed;
      count++;
    }
    sqlite3_finalize(st); st=NULL; if (rc!=SQLITE_DONE) goto read_failed;
  }
  report->selected_batches=count; report->selected_bytes=total;
  for (unsigned i=0;i<count;i++) {
    QueueRecoveryBatch *b=&batches[i];
    if (b->terminal_kind>=0 || b->terminal_kind==-2) {
      /* Scope-check the whole decoded frame before deciding whether this
       * original immutable journal frame can resume under its existing ID. */
      int scoped=b->wire_len>12 && edr_egress_batch_project_alerts(b->wire,12,b->wire+12,
        b->wire_len-12,request->tenant_id,request->endpoint_id,&b->projection,
        &b->projection_len,&b->frames,b->reason,sizeof(b->reason));
      b->understood=scoped && edr_egress_batch_validate(b->wire,12,b->wire+12,
        b->wire_len-12,b->reason,sizeof(b->reason));
    } else if (b->wire_len>12) {
      b->understood=edr_egress_batch_project_alerts(b->wire,12,b->wire+12,b->wire_len-12,
        request->tenant_id,request->endpoint_id,&b->projection,&b->projection_len,&b->frames,
        b->reason,sizeof(b->reason));
    } else snprintf(b->reason,sizeof(b->reason),"unknown_batch_format");
    if (!strcmp(b->reason,"historical_scope_mismatch")) {
      snprintf(report->reason,96,"historical_scope_mismatch_no_transition"); result=EDR_ERR_INVALID_ARG; goto done;
    }
    if (!strcmp(b->reason,"egress_validation_allocation_failed")) {
      snprintf(report->reason,96,"projection_resources_unavailable"); result=EDR_ERR_MEM_LIMIT; goto done;
    }
    if (b->terminal_kind==-1 && !b->understood) report->retained_unresolved++;
    if (b->terminal_kind==-1 && b->understood && b->frames) report->projected_batches++;
    recovery_hash_number(&inventory,(uint64_t)b->understood);
    recovery_hash_number(&inventory,b->frames); recovery_hash_text(&inventory,b->reason);
    if (b->projection) {
      char projection_hash[65]; edr_sha256_hex(b->projection,b->projection_len,projection_hash);
      recovery_hash_text(&inventory,projection_hash);
    } else recovery_hash_text(&inventory,"");
  }
  uint8_t digest[32]; edr_sha256_final(&inventory,digest);
  recovery_hex(digest,32,report->inventory_sha256);
  if (!request->apply) { snprintf(report->reason,96,"read_only_inventory_checked"); result=EDR_OK; goto done; }
  if (!recovery_owner_equal(&old,&request->expected_owner) ||
      strcmp(report->inventory_sha256,request->expected_inventory_sha256)) {
    snprintf(report->reason,96,"stale_owner_or_inventory_no_transition"); result=EDR_ERR_INVALID_ARG; goto done;
  }
  authorization=recovery_lineage_create(&old,bound_sha,request,report->inventory_sha256);
  if (!authorization) { snprintf(report->reason,96,"recovery_authorization_unavailable"); goto done; }
  if (old.owner_version==2 && queue_meta_is_latched(&old)) {
    if (lineage[0]) { snprintf(report->reason,96,"different_legacy_owner_already_retained"); goto done; }
    new_lineage=recovery_lineage_create(&old,bound_sha,request,report->inventory_sha256);
    if (!new_lineage) { snprintf(report->reason,96,"legacy_lineage_capacity_invalid"); goto done; }
  }
  if (old.owner_version==2 && old.counter==(uint64_t)INT64_MAX) {
    snprintf(report->reason,96,"owner_counter_exhausted"); goto done;
  }
  if (queue_recovery_metadata_ensure_locked()!=0 || terminal_frame_metadata_ensure_locked()!=0) goto write_failed;
  uint64_t incoming=(new_lineage?2048:0)+(previous_snapshot?0:2048);
  for (unsigned i=0;i<count;i++) if (batches[i].terminal_kind==-1) {
    if (!batches[i].previous_recovery_version) incoming=queue_add_bytes(incoming,512);
    if (batches[i].understood && batches[i].frames)
      incoming=queue_add_bytes(incoming,queue_event_live_cost("min-v1-0000000000000000000000000000000000000000000000000000000000000000",
        batches[i].projection_len)+1024);
  }
  uint64_t used;
  if (!queue_logical_retained_bytes_locked(&used) || incoming>s_max_db_bytes ||
      used>s_max_db_bytes-incoming) { result=EDR_ERR_QUEUE_FULL; snprintf(report->reason,96,"recovery_capacity_backpressure"); goto done; }
  recovery_test_stop(1); /* Fully prepared transaction, no irreversible mutation. */
  if (new_lineage && recovery_store_lineage(new_lineage)!=0) goto write_failed;
  for (unsigned i=0;i<count;i++) {
    QueueRecoveryBatch *b=&batches[i];
    if (b->terminal_kind==-2) {
      if (!b->understood) continue;
      if (sqlite3_prepare_v2(s_db,"UPDATE event_queue SET status='pending',next_retry_at=0,"
          "terminal_reason='',terminal_at=0 WHERE id=? AND batch_id=? AND payload=? "
          "AND origin_row_id=? AND status IN ('policy_held','dead_letter');",-1,&st,NULL)!=SQLITE_OK)
        goto write_failed;
      sqlite3_bind_int64(st,1,b->id); sqlite3_bind_text(st,2,b->batch_id,-1,SQLITE_TRANSIENT);
      sqlite3_bind_blob(st,3,b->wire,(int)b->wire_len,SQLITE_TRANSIENT);
      sqlite3_bind_int64(st,4,b->origin_id);
      rc=sqlite3_step(st); int changed=sqlite3_changes(s_db); sqlite3_finalize(st); st=NULL;
      if (rc!=SQLITE_DONE || changed!=1) goto write_failed;
      report->resumed_projections++; continue;
    }
    if (b->terminal_kind>=0) {
      if (!b->understood) continue;
      char sql[512]; const char *p=prefixes[b->terminal_kind];
      snprintf(sql,sizeof(sql),"UPDATE enforcement_terminal_journal SET %s_policy_held=0,"
        "%s_policy_reason='',%s_next_retry_at=0,state=CASE WHEN state='local_retained' THEN 'ready' ELSE state END "
        "WHERE id=? AND %s_batch_id=? AND %s_wire=? "
        "AND %s_acked=0 AND %s_policy_held=1;",p,p,p,p,p,p,p);
      if (sqlite3_prepare_v2(s_db,sql,-1,&st,NULL)!=SQLITE_OK) goto write_failed;
      sqlite3_bind_int64(st,1,b->id); sqlite3_bind_text(st,2,b->batch_id,-1,SQLITE_TRANSIENT);
      sqlite3_bind_blob(st,3,b->wire,(int)b->wire_len,SQLITE_TRANSIENT);
      rc=sqlite3_step(st); int changed=sqlite3_changes(s_db); sqlite3_finalize(st); st=NULL;
      if (rc!=SQLITE_DONE || changed!=1) goto write_failed;
      report->resumed_terminal_frames++; continue;
    }
    char projection_id[80]="",projection_sha[65]="";
    const char *state=b->understood?(b->frames?"projection_pending":"local_only"):"retained_unresolved";
    if (b->understood && b->frames) {
      edr_sha256_hex(b->projection,b->projection_len,projection_sha);
      EdrSha256Ctx identity; uint8_t id_digest[32]; char id_hex[65]; edr_sha256_init(&identity);
      recovery_hash_text(&identity,"historical-alert-projection");
      recovery_hash_text(&identity,EDR_EGRESS_PROJECTOR_VERSION);
      recovery_hash_number(&identity,(uint64_t)b->id);
      edr_sha256_update(&identity,old.nonce,16); recovery_hash_text(&identity,b->original_sha);
      recovery_hash_text(&identity,projection_sha); recovery_hash_text(&identity,request->tenant_id);
      recovery_hash_text(&identity,request->endpoint_id); edr_sha256_final(&identity,id_digest);
      recovery_hex(id_digest,32,id_hex); snprintf(projection_id,sizeof(projection_id),"min-v2-%s",id_hex);
      if (!strcmp(projection_id,b->batch_id)) goto write_failed;
      if (sqlite3_prepare_v2(s_db,"INSERT INTO event_queue(batch_id,payload,created_at,compressed,severity,"
          "status,recovery_version,origin_row_id) VALUES(?,?,?,0,1,'pending',1,?);",-1,&st,NULL)!=SQLITE_OK)
        goto write_failed;
      sqlite3_bind_text(st,1,projection_id,-1,SQLITE_TRANSIENT);
      sqlite3_bind_blob(st,2,b->projection,(int)b->projection_len,SQLITE_TRANSIENT);
      sqlite3_bind_int64(st,3,(sqlite3_int64)time(NULL)); sqlite3_bind_int64(st,4,b->id);
      rc=sqlite3_step(st); sqlite3_finalize(st); st=NULL; if (rc!=SQLITE_DONE) goto write_failed;
      if (sqlite3_prepare_v2(s_db,"INSERT INTO queue_projection_relations(origin_row_id,projector_version,"
          "batch_id,payload_sha256,receipt_state,created_at) VALUES(?,?,?,?,'pending',?);",-1,&st,NULL)!=SQLITE_OK)
        goto write_failed;
      sqlite3_bind_int64(st,1,b->id); sqlite3_bind_text(st,2,EDR_EGRESS_PROJECTOR_VERSION,-1,SQLITE_STATIC);
      sqlite3_bind_text(st,3,projection_id,-1,SQLITE_TRANSIENT);
      sqlite3_bind_text(st,4,projection_sha,-1,SQLITE_TRANSIENT);
      sqlite3_bind_int64(st,5,(sqlite3_int64)time(NULL));
      rc=sqlite3_step(st); sqlite3_finalize(st); st=NULL; if (rc!=SQLITE_DONE) goto write_failed;
    }
    if (sqlite3_prepare_v2(s_db,"UPDATE event_queue SET status='local_evidence',recovery_version=1,"
        "original_sha256=?,projection_batch_id=CASE WHEN projection_batch_id='' THEN ? ELSE projection_batch_id END,"
        "projection_sha256=CASE WHEN projection_batch_id='' THEN ? ELSE projection_sha256 END,"
        "recovery_state=CASE WHEN projection_batch_id='' THEN ? ELSE recovery_state END,terminal_reason=?,"
        "terminal_at=?,projector_version=CASE WHEN projection_batch_id='' THEN '" EDR_EGRESS_PROJECTOR_VERSION "' ELSE projector_version END "
        "WHERE id=? AND batch_id=? AND payload=? "
        "AND recovery_version=? AND (recovery_version=0 OR "
        "(original_sha256=? AND (recovery_state='retained_unresolved' OR projector_version<>'" EDR_EGRESS_PROJECTOR_VERSION "')));",-1,&st,NULL)!=SQLITE_OK)
      goto write_failed;
    sqlite3_bind_text(st,1,b->original_sha,-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(st,2,projection_id,-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(st,3,projection_sha,-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(st,4,state,-1,SQLITE_STATIC); sqlite3_bind_text(st,5,b->reason,-1,SQLITE_TRANSIENT);
    sqlite3_bind_int64(st,6,(sqlite3_int64)time(NULL)); sqlite3_bind_int64(st,7,b->id);
    sqlite3_bind_text(st,8,b->batch_id,-1,SQLITE_TRANSIENT);
    sqlite3_bind_blob(st,9,b->wire,(int)b->wire_len,SQLITE_TRANSIENT);
    sqlite3_bind_int(st,10,b->previous_recovery_version);
    sqlite3_bind_text(st,11,b->original_sha,-1,SQLITE_TRANSIENT);
    rc=sqlite3_step(st); int changed=sqlite3_changes(s_db); sqlite3_finalize(st); st=NULL;
    if (rc!=SQLITE_DONE || changed!=1) goto write_failed;
  }
  if (old.owner_version==2) {
    old.owner_version=3; old.counter++; old.epoch=old.counter; old.loss_detected=1;
    old.recovery_event_id[0]=old.recovery_batch_id[0]='\0';
    snprintf(old.latch_state,sizeof(old.latch_state),"recovery_required");
    snprintf(old.last_error,sizeof(old.last_error),"explicit_legacy_owner_retained_v1");
    if (queue_meta_write_locked(&old)!=0) goto write_failed;
  }
  if (sqlite3_prepare_v2(s_db,"UPDATE queue_meta SET last_recovery_snapshot=?,last_recovery_owner=? WHERE id=1;",
      -1,&st,NULL)!=SQLITE_OK) goto write_failed;
  sqlite3_bind_text(st,1,report->inventory_sha256,-1,SQLITE_TRANSIENT);
  sqlite3_bind_text(st,2,authorization,-1,SQLITE_TRANSIENT);
  rc=sqlite3_step(st); int meta_changed=sqlite3_changes(s_db); sqlite3_finalize(st); st=NULL;
  if (rc!=SQLITE_DONE || meta_changed!=1) goto write_failed;
  recovery_test_stop(2); /* Original lineage + new owner/projections, before FULL commit. */
  if (terminal_journal_end_durable_locked(1)!=0) goto write_failed;
  transaction=0; recovery_test_stop(3);
  intent_owner_lock();
  snprintf(s_intent_owner_path,sizeof(s_intent_owner_path),"%s",s_path);
  memcpy(s_intent_owner_nonce,old.nonce,sizeof(s_intent_owner_nonce));
  intent_owner_unlock();
  edr_egress_set_p0_pair_validator(terminal_intent_association_validate,NULL);
  queue_meta_export_latch(&old,&report->current_owner);
  report->legacy_owner_unacknowledged=(lineage[0]||new_lineage)?1:0;
  report->applied=1; snprintf(report->reason,96,"local_transition_committed_no_remote_ack"); result=EDR_OK;
  goto done;
read_failed:
  snprintf(report->reason,96,"immutable_inventory_read_failed"); goto done;
write_failed:
  snprintf(report->reason,96,"durable_recovery_transaction_failed"); result=EDR_ERR_SQLITE_WRITE;
done:
  if (st) sqlite3_finalize(st);
  if (transaction==1) (void)terminal_journal_end_durable_locked(0);
  else if (transaction==2) (void)exec_simple(s_db,"ROLLBACK;");
  for (unsigned i=0;i<32;i++) { free(batches[i].wire); free(batches[i].projection); }
  free(lineage); free(new_lineage); free(authorization);
  /* Maintenance close never claims a clean agent session or changes a latch. */
  if (handle_owned) terminal_intent_owner_unregister_locked();
  if (handle_owned && s_db && sqlite3_close(s_db)==SQLITE_OK) s_db=NULL;
  if (lock_owned) queue_lock_release();
  if (handle_owned || lock_owned) s_path[0]='\0';
  queue_state_unlock(); return result;
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
  if (!edr_ingest_http_configured()) {
    /* Configuration absence is not a delivery attempt. Normal retention
     * maintenance still runs, but retry disposition must wait for transport. */
    if (now - s_last_drain_ns >= interval_ns) {
      s_last_drain_ns = now;
      cleanup_expired_rows();
    }
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
    cleanup_expired_rows();
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
  if (terminal_journal_recheck_intents_locked()!=0) {
    s_terminal_replay_selection_transient_failures++;
    s_drain_generation=0; queue_state_unlock(); return;
  }
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

int edr_storage_queue_batch_presence(const char *id,const uint8_t *wire,size_t len) {
  (void)id; (void)wire; (void)len; return -1;
}

EdrError edr_storage_queue_recover_v1(const char *path,const EdrStorageQueueRecoveryRequest *request,
                                     EdrStorageQueueRecoveryReport *report) {
  (void)path; (void)request;
  if (report) { memset(report,0,sizeof(*report)); snprintf(report->reason,sizeof(report->reason),
                                                         "sqlite_unavailable"); }
  return EDR_ERR_NOT_IMPL;
}

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
EdrError edr_storage_queue_p0_source_only_latch_prepare_local(
    EdrStorageQueueP0SourceOnlyLatch *out) {
  if (out) memset(out, 0, sizeof(*out));
  return EDR_ERR_SQLITE_OPEN;
}
EdrError edr_storage_queue_p0_source_only_commit_local(
    const EdrStorageQueueP0SourceOnlyLatch *expected, const char *event_id,
    const char *batch_id, const uint8_t *payload, size_t payload_len,
    int compressed, int recovery_audit) {
  (void)expected; (void)event_id; (void)batch_id; (void)payload;
  (void)payload_len; (void)compressed; (void)recovery_audit;
  return EDR_ERR_SQLITE_OPEN;
}


#ifdef EDR_STORAGE_QUEUE_TESTING
void edr_storage_queue_test_fail_next_enqueue_commits(unsigned count) { (void)count; }
void edr_storage_queue_test_fail_next_p0_latch_commits(unsigned count) { (void)count; }
void edr_storage_queue_test_fail_next_p0_deferred_commits(unsigned count) { (void)count; }
void edr_storage_queue_test_set_p0_deferred_time(int64_t unix_seconds) { (void)unix_seconds; }
void edr_storage_queue_test_fail_next_terminal_select_allocations(
    unsigned key_count, unsigned batch_id_count, unsigned wire_count) {
  (void)key_count;
  (void)batch_id_count;
  (void)wire_count;
}
#endif

#endif
