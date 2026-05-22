#include "edr/storage_queue.h"

#include "edr/grpc_client.h"
#include "edr/time_util.h"
#include "edr/transport_sink.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(EDR_HAVE_SQLITE)
#include <sqlite3.h>
#include <sys/stat.h>
#if defined(_WIN32) && defined(_MSC_VER)
#include <stdlib.h>
#endif

static sqlite3 *s_db;
static char s_path[512];
static uint64_t s_pending;
static uint64_t s_max_db_bytes;
static uint32_t s_cfg_max_db_mb;
static uint32_t s_cfg_retention_hours;
static uint64_t s_last_cleanup_ns;

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
  const void *blob = sqlite3_column_blob(st, 2);
  int blob_len = sqlite3_column_bytes(st, 2);
  int retry_count = sqlite3_column_int(st, 3);
  sqlite3_finalize(st);

  {
    int lim = max_retry_limit();
    if (lim > 0 && retry_count >= lim) {
      fprintf(stderr, "[queue] 达最大重试 %d，丢弃 batch_id=%s id=%lld\n", lim, batch_id ? batch_id : "",
              (long long)id);
      (void)delete_row_by_id(id);
      return 0;
    }
  }

  if (!batch_id || !blob || blob_len < 12) {
    fprintf(stderr, "[queue] 删除损坏队列行 id=%lld\n", (long long)id);
    (void)delete_row_by_id(id);
    return 0;
  }

  const uint8_t *b = (const uint8_t *)blob;
  if (!batch_header_valid(b)) {
    fprintf(stderr, "[queue] 丢弃无 §6.2 头的历史批次 id=%lld（请清空旧库或重新落盘）\n", (long long)id);
    (void)delete_row_by_id(id);
    return 0;
  }

  int send = edr_grpc_client_send_batch(batch_id, b, 12u, b + 12, (size_t)blob_len - 12u);
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

EdrError edr_storage_queue_open(const char *path) {
  edr_storage_queue_close();
  load_queue_db_limit();
  if (path && path[0]) {
    snprintf(s_path, sizeof(s_path), "%s", path);
  } else {
    snprintf(s_path, sizeof(s_path), "%s", "edr_queue.db");
  }

  int rc = sqlite3_open(s_path, &s_db);
  if (rc != SQLITE_OK || !s_db) {
    s_db = NULL;
    return EDR_ERR_SQLITE_OPEN;
  }

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
  return EDR_OK;
}

void edr_storage_queue_close(void) {
  if (s_db) {
    sqlite3_close(s_db);
    s_db = NULL;
  }
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
      fprintf(stderr, "[queue] 库文件超过 EDR_QUEUE_MAX_DB_MB 上限，拒绝入队\n");
      return EDR_ERR_QUEUE_FULL;
    }
#else
    struct stat stbuf;
    if (stat(s_path, &stbuf) == 0 && (uint64_t)stbuf.st_size >= s_max_db_bytes) {
      fprintf(stderr, "[queue] 库文件超过 EDR_QUEUE_MAX_DB_MB 上限，拒绝入队\n");
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
  if (now - last_ns < 200000000ULL) {
    return;
  }
  if (!s_db || s_pending == 0u) {
    last_ns = now;
    cleanup_expired_rows();
    return;
  }
  last_ns = now;
  cleanup_expired_rows();

  for (unsigned k = 0; k < 32u; k++) {
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
