#include "fl_samples_db.h"

#include "edr/fl_feature_provider.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef EDR_HAVE_SQLITE
#include <sqlite3.h>
#else
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
#endif

static sqlite3 *s_db;

static void lower_hex_inplace(char *s) {
  for (; *s; s++) {
    if (*s >= 'A' && *s <= 'F') {
      *s = (char)(*s - 'A' + 'a');
    }
  }
}

int fl_samples_db_open(const char *path) {
#ifndef EDR_HAVE_SQLITE
  (void)path;
  return -1;
#else
  if (!path || !path[0]) {
    return -1;
  }
  fl_samples_db_close();
  if (sqlite3_open_v2(path, &s_db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
    if (s_db) {
      sqlite3_close(s_db);
      s_db = NULL;
    }
    return -1;
  }
  return 0;
#endif
}

void fl_samples_db_close(void) {
#ifdef EDR_HAVE_SQLITE
  if (s_db) {
    sqlite3_close(s_db);
    s_db = NULL;
  }
#else
#endif
}

int fl_samples_db_list_static_sha256(char *out_sha256_rows, size_t row_stride, size_t max_rows,
                                     size_t *out_count) {
#ifndef EDR_HAVE_SQLITE
  (void)out_sha256_rows;
  (void)row_stride;
  (void)max_rows;
  if (out_count) {
    *out_count = 0;
  }
  return -1;
#else
  sqlite3_stmt *st = NULL;
  const char *sql =
      "SELECT sha256 FROM fl_samples WHERE model_target = 'static' ORDER BY created_ts ASC LIMIT ?";
  int rc;

  if (!s_db || !out_sha256_rows || row_stride < 65u || !out_count) {
    return -1;
  }
  *out_count = 0;
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    return -1;
  }
  sqlite3_bind_int64(st, 1, (sqlite3_int64)max_rows);
  while (*out_count < max_rows && (rc = sqlite3_step(st)) == SQLITE_ROW) {
    const unsigned char *txt = sqlite3_column_text(st, 0);
    size_t i = *out_count;
    if (!txt) {
      continue;
    }
    snprintf(out_sha256_rows + i * row_stride, row_stride, "%s", (const char *)txt);
    (*out_count)++;
  }
  sqlite3_finalize(st);
  return 0;
#endif
}

int fl_samples_db_read_feature(const char *sha256_64hex, float *out, size_t dim) {
#ifndef EDR_HAVE_SQLITE
  (void)sha256_64hex;
  (void)out;
  (void)dim;
  return 1;
#else
  sqlite3_stmt *st = NULL;
  char key[72];
  const char *sql = "SELECT feature_blob FROM fl_samples WHERE sha256 = ? LIMIT 1";
  int rc;

  if (!s_db || !sha256_64hex || !out || dim == 0u) {
    return 1;
  }
  snprintf(key, sizeof(key), "%s", sha256_64hex);
  lower_hex_inplace(key);
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    return -2;
  }
  sqlite3_bind_text(st, 1, key, -1, SQLITE_STATIC);
  rc = sqlite3_step(st);
  if (rc != SQLITE_ROW) {
    sqlite3_finalize(st);
    return 1;
  }
  {
    int blen = sqlite3_column_bytes(st, 0);
    const void *blob = sqlite3_column_blob(st, 0);
    if (!blob || blen != (int)(dim * sizeof(float))) {
      sqlite3_finalize(st);
      return 1;
    }
    memcpy(out, blob, dim * sizeof(float));
    sqlite3_finalize(st);
  }
  return 0;
#endif
}

static int fl_samples_lookup_bridge(const char *sha256_64hex, float *out, size_t dim, int target,
                                    void *user) {
  (void)user;
  if (!sha256_64hex || !out) {
    return 1;
  }
  (void)target;
  switch (fl_samples_db_read_feature(sha256_64hex, out, dim)) {
    case 0:
      return 0;
    case 1:
      return 1;
    default:
      return 1;
  }
}

void fl_samples_db_register_ave_bridge(void) {
#ifdef EDR_HAVE_SQLITE
  edr_fl_register_feature_lookup(fl_samples_lookup_bridge, NULL);
#endif
}

void fl_samples_db_unregister_ave_bridge(void) {
  edr_fl_unregister_feature_lookup();
}
