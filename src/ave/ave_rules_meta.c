#include "ave_rules_meta.h"

#include <stdio.h>
#include <string.h>

#ifdef EDR_HAVE_SQLITE
#include <sqlite3.h>
#endif

#ifdef EDR_HAVE_SQLITE

static int open_ro(const char *path, sqlite3 **out) {
  if (!path || !path[0]) {
    return -1;
  }
  if (sqlite3_open_v2(path, out, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
    if (*out) {
      sqlite3_close(*out);
      *out = NULL;
    }
    return -1;
  }
  return 0;
}

int edr_ave_db_meta_get(const char *db_path, const char *key, char *out, size_t out_cap) {
  if (!out || out_cap == 0 || !key || !key[0]) {
    return -1;
  }
  out[0] = '\0';
  sqlite3 *db = NULL;
  if (open_ro(db_path, &db) != 0) {
    return -1;
  }
  sqlite3_stmt *st = NULL;
  int rc = -1;
  if (sqlite3_prepare_v2(db, "SELECT value FROM ave_db_meta WHERE key = ? LIMIT 1", -1, &st, NULL) !=
      SQLITE_OK) {
    sqlite3_close(db);
    return -1;
  }
  sqlite3_bind_text(st, 1, key, -1, SQLITE_STATIC);
  if (sqlite3_step(st) == SQLITE_ROW) {
    const char *txt = (const char *)sqlite3_column_text(st, 0);
    if (txt) {
      snprintf(out, out_cap, "%s", txt);
      rc = 0;
    }
  }
  sqlite3_finalize(st);
  sqlite3_close(db);
  return rc;
}

static int count_where_active(const char *db_path, const char *sql_fixed) {
  sqlite3 *db = NULL;
  if (open_ro(db_path, &db) != 0) {
    return -1;
  }
  sqlite3_stmt *st = NULL;
  int n = -1;
  if (sqlite3_prepare_v2(db, sql_fixed, -1, &st, NULL) != SQLITE_OK) {
    sqlite3_close(db);
    return -1;
  }
  if (sqlite3_step(st) == SQLITE_ROW) {
    n = sqlite3_column_int(st, 0);
  }
  sqlite3_finalize(st);
  sqlite3_close(db);
  return n;
}

int edr_ave_db_count_ioc_rows(const char *db_path) {
  return count_where_active(db_path,
                            "SELECT COUNT(*) FROM ioc_file_hash WHERE COALESCE(is_active,1)=1");
}

int edr_ave_db_count_file_whitelist_rows(const char *db_path) {
  return count_where_active(db_path,
                            "SELECT COUNT(*) FROM file_hash_whitelist WHERE COALESCE(is_active,1)=1");
}

#else

int edr_ave_db_meta_get(const char *db_path, const char *key, char *out, size_t out_cap) {
  (void)db_path;
  (void)key;
  if (out && out_cap > 0) {
    out[0] = '\0';
  }
  return -1;
}

int edr_ave_db_count_ioc_rows(const char *db_path) {
  (void)db_path;
  return -1;
}

int edr_ave_db_count_file_whitelist_rows(const char *db_path) {
  (void)db_path;
  return -1;
}

#endif
