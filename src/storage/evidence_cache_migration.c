#include "edr/local_evidence_cache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#if defined(EDR_HAVE_SQLITE)
#include "evidence_context_store.h"
#include <sys/stat.h>
#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/statvfs.h>
#include <time.h>
#endif

typedef struct {
  uint64_t deadline;
  int (*cancelled)(void *);
  void *context;
} MigrationDeadline;

typedef struct {
  sqlite3 *db;
  const char *path, *wal;
  uint64_t cap;
  int rejected;
} MigrationBudget;

static uint64_t migration_clock_ms(void) {
#if defined(_WIN32)
  return (uint64_t)GetTickCount64();
#else
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return UINT64_MAX;
  return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
#endif
}

static int interrupted(void *arg) {
  MigrationDeadline *d = (MigrationDeadline *)arg;
  return migration_clock_ms() >= d->deadline || (d->cancelled && d->cancelled(d->context));
}

static int scalar(sqlite3 *db, const char *sql, sqlite3_int64 *out) {
  sqlite3_stmt *st = NULL;
  int ok = sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW;
  if (ok) *out = sqlite3_column_int64(st, 0);
  sqlite3_finalize(st);
  return ok ? 0 : -1;
}

static uint64_t file_bytes(const char *path) {
#if defined(_WIN32)
  struct _stat64 st;
  int rc = _stat64(path, &st);
#else
  struct stat st;
  int rc = stat(path, &st);
#endif
  return rc == 0 ? (uint64_t)st.st_size : errno == ENOENT ? 0 : UINT64_MAX;
}

/* cache_spill is disabled for this exclusive maintenance connection. Before
 * commit, reserve both a WAL frame and main-file space for every cached page
 * (including clean pages), plus headers. This intentionally overestimates
 * growth so a wide historical row fails before publishing an oversized batch. */
static int budget_before_commit(void *arg) {
  MigrationBudget *b = (MigrationBudget *)arg;
  int used = 0, high = 0;
  uint64_t main_bytes = file_bytes(b->path), wal_bytes = file_bytes(b->wal);
  if (sqlite3_db_status(b->db, SQLITE_DBSTATUS_CACHE_USED, &used, &high, 0) != SQLITE_OK ||
      used < 0 || main_bytes > b->cap || wal_bytes > b->cap ||
      main_bytes + wal_bytes + 2u * (uint64_t)used + 131072u > b->cap) {
    b->rejected = 1; return 1;
  }
  return 0;
}

static int disk_room(const char *path, uint64_t required) {
#if defined(_WIN32)
  size_t n = strlen(path) + 1;
  char *parent = (char *)malloc(n);
  if (!parent) return 0;
  memcpy(parent, path, n);
  char *a = strrchr(parent, '\\'), *b = strrchr(parent, '/');
  char *slash = a && b ? (a > b ? a : b) : a ? a : b;
  if (slash) slash[1] = 0; else strcpy(parent, ".");
  ULARGE_INTEGER available;
  int ok = GetDiskFreeSpaceExA(parent, &available, NULL, NULL) && available.QuadPart >= required;
  free(parent); return ok;
#else
  struct statvfs fs;
  return statvfs(path, &fs) == 0 && (uint64_t)fs.f_bavail * fs.f_frsize >= required;
#endif
}

static int physical_bound(sqlite3 *db, const char *wal, uint64_t *out) {
  sqlite3_int64 bytes;
  /* page_count includes committed WAL growth not yet copied to the main file.
   * Counting it together with the whole WAL also covers checkpoint's overlap. */
  if (scalar(db, "SELECT page_count*page_size FROM pragma_page_count,pragma_page_size", &bytes) != 0 || bytes < 0) return -1;
  uint64_t wal_bytes = file_bytes(wal);
  if (wal_bytes == UINT64_MAX) return -1;
  *out = (uint64_t)bytes + wal_bytes;
  return 0;
}
#endif

int edr_local_evidence_cache_migrate(const char *path, uint32_t max_db_mb,
                                    uint32_t timeout_ms,
                                    int (*cancelled)(void *), void *cancel_context,
                                    EdrEvidenceMigrationResult *result) {
  if (!result) return -1;
  memset(result, 0, sizeof(*result));
#if defined(EDR_HAVE_SQLITE)
  sqlite3 *db = NULL;
  EdrContextStore store;
  MigrationBudget budget = {0};
  int rc = -1;
  uint64_t start = migration_clock_ms();
  uint64_t cap = (uint64_t)max_db_mb * 1024u * 1024u;
  char *wal = NULL;
  memset(&store, 0, sizeof(store));
  if (!path || !path[0] || max_db_mb < 4 || timeout_ms == 0 || timeout_ms > 600000) {
    snprintf(result->error, sizeof(result->error), "migration requires existing path, >=4 MiB budget, and 1..600000 ms deadline");
    return -1;
  }
  wal = sqlite3_mprintf("%s-wal", path);
  if (!wal) { snprintf(result->error, sizeof(result->error), "allocate migration path failed"); return -1; }
  if (!disk_room(path, 2u * 1024u * 1024u)) {
    snprintf(result->error, sizeof(result->error), "migration needs at least 2 MiB free disk space"); goto done;
  }
  if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) goto sqlite_error;
  sqlite3_busy_timeout(db, 200);
  MigrationDeadline deadline = { start + timeout_ms, cancelled, cancel_context };
  sqlite3_progress_handler(db, 1000, interrupted, &deadline);
  if (interrupted(&deadline)) goto cancelled_out;
  sqlite3_int64 v = -1, mode = -1, page_size = 0;
  if (scalar(db, "PRAGMA user_version", &v) != 0 || v < 0 || v > 2) {
    snprintf(result->error, sizeof(result->error), "unsupported evidence cache format"); goto done;
  }
  sqlite3_stmt *journal = NULL;
  int wal_mode = sqlite3_prepare_v2(db, "PRAGMA journal_mode", -1, &journal, NULL) == SQLITE_OK &&
                 sqlite3_step(journal) == SQLITE_ROW && sqlite3_column_text(journal, 0) &&
                 strcmp((const char *)sqlite3_column_text(journal, 0), "wal") == 0;
  sqlite3_finalize(journal);
  if (!wal_mode) { snprintf(result->error, sizeof(result->error), "migration requires the existing WAL cache format"); goto done; }
  /* Must acquire exclusive ownership before any schema or row changes. */
  if (sqlite3_exec(db, "PRAGMA locking_mode=EXCLUSIVE;BEGIN EXCLUSIVE;COMMIT;", NULL, NULL, NULL) != SQLITE_OK) {
    snprintf(result->error, sizeof(result->error), "cache is busy; stop its Agent/readers before migration"); goto done;
  }
  /* A near-full cache can have only 1 MiB of migration headroom. Keep clean
   * read pages below 128 KiB so the commit reserve reflects dirty work rather
   * than filling the runtime's 1 MiB read cache within each small batch.
   * Spill stays disabled; unusually large dirty batches still fail closed. */
  if (sqlite3_exec(db, "PRAGMA synchronous=FULL;PRAGMA wal_autocheckpoint=0;PRAGMA cache_size=-128;PRAGMA cache_spill=OFF;PRAGMA mmap_size=0;",
                   NULL, NULL, NULL) != SQLITE_OK) goto sqlite_error;
  if (scalar(db, "PRAGMA auto_vacuum", &mode) != 0 || mode != 2) {
    snprintf(result->error, sizeof(result->error), "upgrade the cache to incremental vacuum before context migration"); goto done;
  }
  if (scalar(db, "PRAGMA page_size", &page_size) != 0 || page_size <= 0) goto sqlite_error;
  if (sqlite3_wal_checkpoint_v2(db, NULL, SQLITE_CHECKPOINT_TRUNCATE, NULL, NULL) != SQLITE_OK) goto sqlite_error;
  uint64_t bytes = 0;
  if (physical_bound(db, wal, &bytes) != 0) goto sqlite_error;
  result->peak_physical_bytes = bytes;
  if (bytes + 1024u * 1024u > cap) {
    snprintf(result->error, sizeof(result->error), "cache has less than 1 MiB migration headroom; preserve data and retry after normal reclaim"); goto done;
  }
  char limit_sql[96];
  snprintf(limit_sql, sizeof(limit_sql), "PRAGMA max_page_count=%llu;",
           (unsigned long long)((cap - 1024u * 1024u) / (uint64_t)page_size));
  if (sqlite3_exec(db, limit_sql, NULL, NULL, NULL) != SQLITE_OK) goto sqlite_error;
  budget.db = db; budget.path = path; budget.wal = wal; budget.cap = cap;
  sqlite3_commit_hook(db, budget_before_commit, &budget);
  if (edr_context_store_open(&store, db) != 0 || edr_context_store_begin_upgrade(&store) != 0) goto store_error;
  for (;;) {
    if (interrupted(&deadline)) goto cancelled_out;
    /* All statements from the previous batch are finalized. Drop only clean
     * cached pages before the next transaction: retaining read pages from
     * earlier batches can consume the conservative reserve at a nearly full
     * cache, even though those pages need neither WAL nor main-file writes. */
    if (sqlite3_db_release_memory(db) != SQLITE_OK) goto sqlite_error;
    if (physical_bound(db, wal, &bytes) != 0) goto sqlite_error;
    if (bytes > result->peak_physical_bytes) result->peak_physical_bytes = bytes;
    if (bytes > cap) { snprintf(result->error, sizeof(result->error), "migration reached physical budget; committed batches remain resumable"); goto done; }
    if (sqlite3_wal_checkpoint_v2(db, NULL, SQLITE_CHECKPOINT_TRUNCATE, NULL, NULL) != SQLITE_OK) goto sqlite_error;
    if (sqlite3_exec(db, "PRAGMA incremental_vacuum(256)", NULL, NULL, NULL) != SQLITE_OK) goto sqlite_error;
    if (physical_bound(db, wal, &bytes) != 0) goto sqlite_error;
    if (bytes > result->peak_physical_bytes) result->peak_physical_bytes = bytes;
    if (bytes > cap) { snprintf(result->error, sizeof(result->error), "migration reclaim reached physical budget"); goto done; }
    if (sqlite3_wal_checkpoint_v2(db, NULL, SQLITE_CHECKPOINT_TRUNCATE, NULL, NULL) != SQLITE_OK) goto sqlite_error;
    if (sqlite3_db_release_memory(db) != SQLITE_OK) goto sqlite_error;
    if (physical_bound(db, wal, &bytes) != 0) goto sqlite_error;
    if (!disk_room(path, 2u * 1024u * 1024u)) { snprintf(result->error, sizeof(result->error), "migration disk reserve exhausted; resume after freeing space"); goto done; }
    /* The commit hook measures the actual working set before any dirty pages
     * spill. Start at the bounded maximum and split a rejected transaction,
     * instead of paying FULL commit/checkpoint latency for a guessed five-row
     * batch on Windows. At most seven attempts (64..1); each failed attempt
     * must have rolled back completely before retrying. */
    unsigned batch = 64;
    unsigned moved = 0; int complete = 0;
    for (;;) {
      budget.rejected = 0;
      if (edr_context_store_migrate_batch(&store, batch, &moved, &complete) == 0) break;
      if (!budget.rejected || batch == 1 || !sqlite3_get_autocommit(db)) goto store_error;
      if (interrupted(&deadline)) goto cancelled_out;
      batch /= 2;
      if (sqlite3_db_release_memory(db) != SQLITE_OK) goto sqlite_error;
    }
    result->moved_refs += moved; ++result->batches;
    if (complete) {
      if (physical_bound(db, wal, &bytes) != 0) goto sqlite_error;
      if (bytes > result->peak_physical_bytes) result->peak_physical_bytes = bytes;
      if (bytes > cap) { snprintf(result->error, sizeof(result->error), "migration exceeded physical budget"); goto done; }
      result->complete = 1; rc = 0; break;
    }
  }
  goto done;
store_error:
  if (interrupted(&deadline)) goto cancelled_out;
  snprintf(result->error, sizeof(result->error), "%s", store.error);
  goto done;
sqlite_error:
  snprintf(result->error, sizeof(result->error), "migration SQLite failure: %s", db ? sqlite3_errmsg(db) : "open failed");
  goto done;
cancelled_out:
  snprintf(result->error, sizeof(result->error), "migration cancelled or deadline exceeded; resume from committed batches");
done:
  if (db) {
    sqlite3_commit_hook(db, NULL, NULL);
    sqlite3_progress_handler(db, 0, NULL, NULL);
    sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    sqlite3_int64 current = -1;
    if (scalar(db, "PRAGMA user_version", &current) == 0 && current >= 0) result->format = (uint32_t)current;
    /* Cleanup is best effort after failure; never replace the first cause. */
    int checkpoint_rc = sqlite3_wal_checkpoint_v2(db, NULL, SQLITE_CHECKPOINT_TRUNCATE, NULL, NULL);
    if (rc == 0 && checkpoint_rc != SQLITE_OK) { rc = -1; result->complete = 0;
      snprintf(result->error, sizeof(result->error), "migration final checkpoint failed"); }
    /* max_page_count is a connection-local migration limit. */
    sqlite3_close(db);
  }
  if (budget.rejected) snprintf(result->error, sizeof(result->error), "migration transaction exceeds physical reserve; committed batches remain resumable");
  sqlite3_free(wal);
  result->elapsed_ms = migration_clock_ms() - start;
  return rc;
#else
  (void)path; (void)max_db_mb; (void)timeout_ms; (void)cancelled; (void)cancel_context;
  snprintf(result->error, sizeof(result->error), "SQLite evidence cache is unavailable");
  return -1;
#endif
}
