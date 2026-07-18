#include "edr/storage_queue.h"

#include "edr/ingest_http.h"
#include "edr/time_util.h"
#include "edr/transport_sink.h"
#include "edr/transport_v2.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(EDR_HAVE_SQLITE)
#include <sqlite3.h>
#include <sys/stat.h>
#if defined(_WIN32)
#include <windows.h>
#if defined(_MSC_VER)
#include <stdlib.h>
#endif
#else
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

static sqlite3 *s_db;
static char s_path[512];
static char s_lock_path[600];
static uint64_t s_pending;
static uint64_t s_max_db_bytes;
static uint32_t s_cfg_max_db_mb;
static uint32_t s_cfg_retention_hours;
static uint64_t s_last_cleanup_ns;
static uint64_t s_legacy_drop_log_until_ns;
static uint64_t s_legacy_drop_suppressed;
#if defined(_WIN32)
static HANDLE s_lock_handle = INVALID_HANDLE_VALUE;
#else
static int s_lock_fd = -1;
#endif

void edr_storage_queue_configure(uint32_t max_db_mb, uint32_t retention_hours) {
  s_cfg_max_db_mb = max_db_mb;
  s_cfg_retention_hours = retention_hours;
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

static int delete_bad_wire_rows(unsigned max_rows, unsigned *deleted_out) {
  sqlite3_stmt *st = NULL;
  const char *sql = "SELECT id, payload FROM event_queue WHERE status='pending' ORDER BY id ASC LIMIT ?;";
  sqlite3_int64 ids[512];
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
      if (id_count >= max_rows) {
        break;
      }
    }
  }
  sqlite3_finalize(st);
  for (unsigned i = 0u; i < id_count; i++) {
    if (delete_row_by_id(ids[i]) == 0) {
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

static void bump_retry(sqlite3_int64 id) {
  sqlite3_stmt *st = NULL;
  const char *sql = "UPDATE event_queue SET retry_count = retry_count + 1 WHERE id=?;";
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    return;
  }
  sqlite3_bind_int64(st, 1, id);
  (void)sqlite3_step(st);
  sqlite3_finalize(st);
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
  const char *sql = "DELETE FROM event_queue WHERE created_at < ?;";
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) == SQLITE_OK) {
    sqlite3_bind_int64(st, 1, (sqlite3_int64)cutoff);
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
      fprintf(stderr, "[queue] auto-purged %u legacy/corrupt pending batches\n", deleted);
    }
  }
}

/**
 * 返回：0 已处理一行（成功删除、丢弃坏行、或失败已 bump_retry），1 无待处理行，2 上传失败应停止本轮连续 drain
 */
static int drain_one_row(void) {
  sqlite3_stmt *st = NULL;
  const char *sql = "SELECT id, batch_id, payload, retry_count FROM event_queue WHERE status='pending' "
                    "ORDER BY severity DESC, id ASC LIMIT 1;";
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    return 1;
  }
  int step = sqlite3_step(st);
  if (step != SQLITE_ROW) {
    sqlite3_finalize(st);
    if (step == SQLITE_DONE) {
      s_pending = 0;
    }
    return 1;
  }

  sqlite3_int64 id = sqlite3_column_int64(st, 0);
  const char *batch_id = (const char *)sqlite3_column_text(st, 1);
  char batch_id_copy[128];
  const void *blob = sqlite3_column_blob(st, 2);
  int blob_len = sqlite3_column_bytes(st, 2);
  int retry_count = sqlite3_column_int(st, 3);
  batch_id_copy[0] = '\0';
  if (batch_id) {
    snprintf(batch_id_copy, sizeof(batch_id_copy), "%s", batch_id);
  }
  sqlite3_finalize(st);

  {
    int lim = max_retry_limit();
    if (lim > 0 && retry_count >= lim) {
      fprintf(stderr, "[queue] max retries reached (%d), dropping batch_id=%s id=%lld\n", lim, batch_id_copy,
              (long long)id);
      (void)delete_row_by_id(id);
      return 0;
    }
  }

  if (!batch_id_copy[0] || !blob || blob_len < 12) {
    fprintf(stderr, "[queue] deleted corrupt queue row id=%lld\n", (long long)id);
    (void)delete_row_by_id(id);
    return 0;
  }

  const uint8_t *b = (const uint8_t *)blob;
  if (!batch_header_valid(b)) {
    log_legacy_drop(id);
    (void)delete_row_by_id(id);
    return 0;
  }

  int send = -1;
  if (edr_ingest_http_configured()) {
    if (edr_ingest_http_circuit_open()) {
      return 2;
    }
    send = edr_transport_v2_report_events(batch_id_copy, b, 12u, b + 12, (size_t)blob_len - 12u);
  }
  if (send == 0) {
    (void)delete_row_by_id(id);
    return 0;
  }
  bump_retry(id);
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
  edr_storage_queue_close();
  load_queue_db_limit();
  if (path && path[0]) {
    snprintf(s_path, sizeof(s_path), "%s", path);
  } else {
    snprintf(s_path, sizeof(s_path), "%s", "edr_queue.db");
  }

  EdrError lock_error = queue_lock_acquire(s_path);
  if (lock_error != EDR_OK) {
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
    return EDR_ERR_SQLITE_OPEN;
  }
  sqlite3_busy_timeout(s_db, queue_busy_timeout_ms());
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
      "severity INTEGER NOT NULL DEFAULT 0,"
      "retry_count INTEGER NOT NULL DEFAULT 0,"
      "status TEXT NOT NULL DEFAULT 'pending'"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_event_queue_status ON event_queue(status, created_at);";

  if (exec_simple(s_db, schema) != SQLITE_OK) {
    sqlite3_close(s_db);
    s_db = NULL;
    queue_lock_release();
    return EDR_ERR_SQLITE_WRITE;
  }
  (void)exec_simple(s_db, "ALTER TABLE event_queue ADD COLUMN severity INTEGER NOT NULL DEFAULT 0;");

  sqlite3_stmt *st = NULL;
  const char *cnt = "SELECT COUNT(*) FROM event_queue WHERE status='pending';";
  if (sqlite3_prepare_v2(s_db, cnt, -1, &st, NULL) == SQLITE_OK) {
    if (sqlite3_step(st) == SQLITE_ROW) {
      s_pending = (uint64_t)sqlite3_column_int64(st, 0);
    }
    sqlite3_finalize(st);
  }
  {
    unsigned deleted = 0u;
    if (delete_bad_wire_rows(2048u, &deleted) == 0 && deleted > 0u) {
      fprintf(stderr, "[queue] auto-purged %u legacy/corrupt pending batches on open\n", deleted);
      st = NULL;
      if (sqlite3_prepare_v2(s_db, cnt, -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW) {
          s_pending = (uint64_t)sqlite3_column_int64(st, 0);
        }
        sqlite3_finalize(st);
      }
    }
  }
  return EDR_OK;
}

void edr_storage_queue_close(void) {
  if (s_db) {
    sqlite3_close(s_db);
    s_db = NULL;
  }
  queue_lock_release();
  s_pending = 0;
}

int edr_storage_queue_is_open(void) { return s_db ? 1 : 0; }

EdrError edr_storage_queue_enqueue(const char *batch_id, const uint8_t *payload,
                                   size_t payload_len, int compressed, int severity) {
  if (!s_db || !batch_id || !payload || payload_len == 0) {
    return EDR_ERR_INVALID_ARG;
  }
  cleanup_expired_rows();

  if (s_max_db_bytes > 0u) {
#if defined(_WIN32) && defined(_MSC_VER)
    struct __stat64 stbuf;
    if (_stat64(s_path, &stbuf) == 0 && (uint64_t)stbuf.st_size >= s_max_db_bytes) {
      fprintf(stderr, "[queue] db file exceeds EDR_QUEUE_MAX_DB_MB, enqueue denied\n");
      return EDR_ERR_QUEUE_FULL;
    }
#else
    struct stat stbuf;
    if (stat(s_path, &stbuf) == 0 && (uint64_t)stbuf.st_size >= s_max_db_bytes) {
      fprintf(stderr, "[queue] db file exceeds EDR_QUEUE_MAX_DB_MB, enqueue denied\n");
      return EDR_ERR_QUEUE_FULL;
    }
#endif
  }

  sqlite3_stmt *st = NULL;
  const char *ins =
      "INSERT INTO event_queue(batch_id,payload,created_at,compressed,severity,status) "
      "VALUES(?,?,?,?,?,'pending');";
  if (sqlite3_prepare_v2(s_db, ins, -1, &st, NULL) != SQLITE_OK) {
    return EDR_ERR_SQLITE_WRITE;
  }

  time_t now = time(NULL);
  sqlite3_bind_text(st, 1, batch_id, -1, SQLITE_TRANSIENT);
  sqlite3_bind_blob(st, 2, payload, (int)payload_len, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 3, (sqlite3_int64)now);
  sqlite3_bind_int(st, 4, compressed ? 1 : 0);
  sqlite3_bind_int(st, 5, severity > 0 ? 1 : 0);

  int rc = sqlite3_step(st);
  sqlite3_finalize(st);
  if (rc != SQLITE_DONE) {
    if (rc == SQLITE_CONSTRAINT) {
      return EDR_OK;
    }
    return EDR_ERR_SQLITE_WRITE;
  }
  s_pending++;
  return EDR_OK;
}

uint64_t edr_storage_queue_pending_count(void) { return s_pending; }

void edr_storage_queue_poll_drain(void) {
  static uint64_t last_ns;
  uint64_t now = edr_monotonic_ns();
  uint64_t interval_ns = (uint64_t)queue_drain_interval_ms() * 1000000ULL;
  if (edr_ingest_http_circuit_open()) {
    uint64_t circuit_interval_ns = (uint64_t)queue_circuit_backoff_ms() * 1000000ULL;
    if (now - last_ns < circuit_interval_ns) {
      return;
    }
    last_ns = now;
    return;
  }
  if (now - last_ns < interval_ns) {
    return;
  }
  if (!s_db || s_pending == 0u) {
    last_ns = now;
    cleanup_expired_rows();
    return;
  }
  last_ns = now;
  cleanup_expired_rows();

  for (unsigned k = 0; k < queue_drain_max_rows(); k++) {
    int r = drain_one_row();
    if (r == 1) {
      break;
    }
    if (r == 2) {
      break;
    }
  }
}

#else /* !EDR_HAVE_SQLITE */

void edr_storage_queue_configure(uint32_t max_db_mb, uint32_t retention_hours) {
  (void)max_db_mb;
  (void)retention_hours;
}

EdrError edr_storage_queue_open(const char *path) {
  (void)path;
  return EDR_OK;
}

void edr_storage_queue_close(void) {}

EdrError edr_storage_queue_enqueue(const char *batch_id, const uint8_t *payload,
                                   size_t payload_len, int compressed, int severity) {
  (void)batch_id;
  (void)payload;
  (void)payload_len;
  (void)compressed;
  (void)severity;
  return EDR_OK;
}

uint64_t edr_storage_queue_pending_count(void) { return 0; }

void edr_storage_queue_poll_drain(void) {}

int edr_storage_queue_is_open(void) { return 0; }

#endif
