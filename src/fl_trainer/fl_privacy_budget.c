#include "edr/fl_privacy_budget.h"

#include <stdio.h>
#include <string.h>

#ifdef EDR_HAVE_SQLITE
#include <sqlite3.h>
#else
typedef struct sqlite3 sqlite3;
#endif

static sqlite3 *s_pb;
static int s_mem_participated;

static int pb_exec(sqlite3 *db, const char *sql) {
#ifdef EDR_HAVE_SQLITE
  char *err = NULL;
  int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
  if (err) {
    sqlite3_free(err);
  }
  return rc;
#else
  (void)db;
  (void)sql;
  return -1;
#endif
}

int fl_privacy_budget_open(const char *path) {
#ifndef EDR_HAVE_SQLITE
  (void)path;
  s_mem_participated = 0;
  return 0;
#else
  if (!path || !path[0]) {
    s_pb = NULL;
    s_mem_participated = 0;
    return 0;
  }
  fl_privacy_budget_close();
  if (sqlite3_open(path, &s_pb) != SQLITE_OK) {
    if (s_pb) {
      sqlite3_close(s_pb);
      s_pb = NULL;
    }
    return -1;
  }
  if (pb_exec(s_pb,
              "CREATE TABLE IF NOT EXISTS fl_privacy_budget (id INTEGER PRIMARY KEY CHECK (id=1), "
              "participated_rounds INTEGER NOT NULL DEFAULT 0);") != SQLITE_OK) {
    sqlite3_close(s_pb);
    s_pb = NULL;
    return -1;
  }
  if (pb_exec(s_pb, "INSERT OR IGNORE INTO fl_privacy_budget (id, participated_rounds) VALUES (1, 0);") !=
      SQLITE_OK) {
    sqlite3_close(s_pb);
    s_pb = NULL;
    return -1;
  }
  return 0;
#endif
}

void fl_privacy_budget_close(void) {
#ifdef EDR_HAVE_SQLITE
  if (s_pb) {
    sqlite3_close(s_pb);
    s_pb = NULL;
  }
#endif
}

int fl_privacy_budget_get(int *participated_out, int max_rounds_cap) {
#ifdef EDR_HAVE_SQLITE
  sqlite3_stmt *st = NULL;
  int v = 0;
  if (!participated_out) {
    return -1;
  }
  if (!s_pb) {
    *participated_out = s_mem_participated;
    (void)max_rounds_cap;
    return 0;
  }
  if (sqlite3_prepare_v2(s_pb, "SELECT participated_rounds FROM fl_privacy_budget WHERE id=1", -1, &st,
                         NULL) != SQLITE_OK) {
    return -1;
  }
  if (sqlite3_step(st) != SQLITE_ROW) {
    sqlite3_finalize(st);
    return -1;
  }
  v = sqlite3_column_int(st, 0);
  sqlite3_finalize(st);
  *participated_out = v;
  (void)max_rounds_cap;
  return 0;
#else
  if (!participated_out) {
    return -1;
  }
  *participated_out = s_mem_participated;
  (void)max_rounds_cap;
  return 0;
#endif
}

int fl_privacy_budget_try_consume_one(int max_rounds) {
#ifdef EDR_HAVE_SQLITE
  sqlite3_stmt *st = NULL;
  if (max_rounds < 1) {
    return 1;
  }
  if (!s_pb) {
    if (s_mem_participated >= max_rounds) {
      return 1;
    }
    s_mem_participated++;
    return 0;
  }
  if (sqlite3_prepare_v2(
          s_pb,
          "UPDATE fl_privacy_budget SET participated_rounds = participated_rounds + 1 WHERE id=1 AND "
          "participated_rounds < ?",
          -1, &st, NULL) != SQLITE_OK) {
    return -1;
  }
  sqlite3_bind_int(st, 1, max_rounds);
  if (sqlite3_step(st) != SQLITE_DONE) {
    sqlite3_finalize(st);
    return -1;
  }
  if (sqlite3_changes(s_pb) != 1) {
    sqlite3_finalize(st);
    return 1;
  }
  sqlite3_finalize(st);
  return 0;
#else
  if (max_rounds < 1) {
    return 1;
  }
  if (s_mem_participated >= max_rounds) {
    return 1;
  }
  s_mem_participated++;
  return 0;
#endif
}
