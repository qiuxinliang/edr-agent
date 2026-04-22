#include "ave_db_update.h"

#include "edr/config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(EDR_HAVE_SQLITE)
#include <sqlite3.h>

typedef struct {
  char sha256[65];
  int severity;
} IocEntry;

static const char *skip_ws(const char *p) {
  while (*p && isspace((unsigned char)*p)) {
    p++;
  }
  return p;
}

static int is_xdigit64_lower(const char *p, char out65[65]) {
  int i;
  for (i = 0; i < 64; i++) {
    unsigned char c = (unsigned char)p[i];
    if (!isxdigit(c)) {
      return 0;
    }
    out65[i] = (char)(isupper(c) ? tolower(c) : c);
  }
  out65[64] = '\0';
  return 1;
}

/** 自 `{` 起找到与之匹配的 `}` 之后第一个字符位置 */
static const char *object_end_brace(const char *p) {
  if (*p != '{') {
    return NULL;
  }
  int depth = 0;
  for (const char *q = p; *q; q++) {
    if (*q == '{') {
      depth++;
    } else if (*q == '}') {
      depth--;
      if (depth == 0) {
        return q + 1;
      }
    }
  }
  return NULL;
}

/** 在 [start,end) 内查找 `"key" :` 后的值起始（不含） */
static const char *value_after_key(const char *start, const char *end, const char *key) {
  char pat[40];
  snprintf(pat, sizeof(pat), "\"%s\"", key);
  size_t L = strlen(pat);
  for (const char *p = start; p + L <= end; p++) {
    if (memcmp(p, pat, L) != 0) {
      continue;
    }
    const char *q = skip_ws(p + L);
    if (q >= end || *q != ':') {
      continue;
    }
    return skip_ws(q + 1);
  }
  return NULL;
}

static int parse_hex_value(const char *val, const char *end, char out65[65]) {
  if (!val || val >= end) {
    return -1;
  }
  val = skip_ws(val);
  if (val >= end) {
    return -1;
  }
  if (*val == '"') {
    val++;
    if (val + 64 > end) {
      return -1;
    }
    if (!is_xdigit64_lower(val, out65)) {
      return -1;
    }
    if (val[64] != '"') {
      return -1;
    }
    return 0;
  }
  if (val + 64 > end) {
    return -1;
  }
  if (!is_xdigit64_lower(val, out65)) {
    return -1;
  }
  return 0;
}

/** severity：1–3，缺省或非法为 3 */
static int parse_severity_value(const char *val, const char *end) {
  if (!val || val >= end) {
    return 3;
  }
  val = skip_ws(val);
  if (val >= end) {
    return 3;
  }
  const char *q = val;
  if (*q == '"') {
    q++;
  }
  int v = 0;
  int got = 0;
  while (q < end && isdigit((unsigned char)*q)) {
    v = v * 10 + (*q - '0');
    got = 1;
    q++;
  }
  if (!got) {
    return 3;
  }
  if (v < 1) {
    v = 1;
  }
  if (v > 3) {
    v = 3;
  }
  return v;
}

static int parse_one_hash_element(const char **pp, char out65[65]) {
  const char *p = skip_ws(*pp);
  if (*p == '\0' || *p == ']') {
    return 0;
  }
  if (*p == '"') {
    p++;
    if (!is_xdigit64_lower(p, out65)) {
      return -1;
    }
    if (p[64] != '"') {
      return -1;
    }
    *pp = p + 65;
    return 1;
  }
  if (!is_xdigit64_lower(p, out65)) {
    return -1;
  }
  *pp = p + 64;
  return 1;
}

static int tokenize_flat(const char *src, char (*hashes)[65], int max_hashes) {
  int n = 0;
  const char *p = skip_ws(src);
  while (*p && n < max_hashes) {
    if (!is_xdigit64_lower(p, hashes[n])) {
      return -1;
    }
    p += 64;
    n++;
    p = skip_ws(p);
    if (*p == ',' || *p == ';') {
      p++;
      p = skip_ws(p);
      continue;
    }
    if (*p == '\0') {
      break;
    }
    if (isxdigit((unsigned char)*p)) {
      continue;
    }
    return -1;
  }
  if (*p && n >= max_hashes) {
    return -1;
  }
  return n;
}

static int collect_array_strings(const char *json, char (*hashes)[65], int max_hashes, int *out_count) {
  const char *p = skip_ws(json);
  if (*p != '[') {
    return -1;
  }
  p = skip_ws(p + 1);
  int n = 0;
  for (;;) {
    p = skip_ws(p);
    if (*p == ']' || *p == '\0') {
      break;
    }
    char h[65];
    int r = parse_one_hash_element(&p, h);
    if (r < 0) {
      return -1;
    }
    if (r == 0) {
      break;
    }
    if (n >= max_hashes) {
      return -1;
    }
    memcpy(hashes[n], h, 65);
    n++;
    p = skip_ws(p);
    if (*p == ',') {
      p++;
      continue;
    }
    if (*p == ']') {
      break;
    }
    return -1;
  }
  *out_count = n;
  return 0;
}

static int collect_object_array_whitelist(const char *json, char (*hashes)[65], int max, int *n_out) {
  const char *p = skip_ws(json);
  if (*p != '[') {
    return -1;
  }
  p = skip_ws(p + 1);
  int n = 0;
  const char *eos = json + strlen(json);
  while (p < eos) {
    p = skip_ws(p);
    if (*p == ']') {
      break;
    }
    if (*p != '{') {
      return -1;
    }
    const char *oe = object_end_brace(p);
    if (!oe || oe > eos) {
      return -1;
    }
    const char *vs = value_after_key(p, oe, "sha256");
    if (!vs) {
      return -1;
    }
    char h[65];
    if (parse_hex_value(vs, oe, h) != 0) {
      return -1;
    }
    if (n >= max) {
      return -1;
    }
    memcpy(hashes[n++], h, 65);
    p = skip_ws(oe);
    if (*p == ',') {
      p++;
      continue;
    }
    if (*p == ']') {
      break;
    }
    return -1;
  }
  *n_out = n;
  return 0;
}

static int collect_whitelist_json(const char *json, char (*hashes)[65], int max, int *n_out) {
  const char *p = skip_ws(json);
  if (*p == '[') {
    const char *inner = skip_ws(p + 1);
    if (*inner == '{') {
      return collect_object_array_whitelist(json, hashes, max, n_out);
    }
    return collect_array_strings(json, hashes, max, n_out);
  }
  int tn = tokenize_flat(p, hashes, max);
  if (tn < 0) {
    return -1;
  }
  *n_out = tn;
  return 0;
}

static int collect_object_array_ioc(const char *json, IocEntry *entries, int max, int *n_out) {
  const char *p = skip_ws(json);
  if (*p != '[') {
    return -1;
  }
  p = skip_ws(p + 1);
  int n = 0;
  const char *eos = json + strlen(json);
  while (p < eos) {
    p = skip_ws(p);
    if (*p == ']') {
      break;
    }
    if (*p != '{') {
      return -1;
    }
    const char *oe = object_end_brace(p);
    if (!oe || oe > eos) {
      return -1;
    }
    const char *vs = value_after_key(p, oe, "sha256");
    if (!vs) {
      return -1;
    }
    char h[65];
    if (parse_hex_value(vs, oe, h) != 0) {
      return -1;
    }
    int sev = 3;
    const char *vsev = value_after_key(p, oe, "severity");
    if (vsev) {
      sev = parse_severity_value(vsev, oe);
    }
    if (n >= max) {
      return -1;
    }
    memcpy(entries[n].sha256, h, 65);
    entries[n].severity = sev;
    n++;
    p = skip_ws(oe);
    if (*p == ',') {
      p++;
      continue;
    }
    if (*p == ']') {
      break;
    }
    return -1;
  }
  *n_out = n;
  return 0;
}

static int collect_ioc_json(const char *json, IocEntry *entries, int max, int *n_out) {
  const char *p = skip_ws(json);
  if (*p == '[') {
    const char *inner = skip_ws(p + 1);
    if (*inner == '{') {
      return collect_object_array_ioc(json, entries, max, n_out);
    }
    /* 字符串数组：severity=3 */
    char (*tmp)[65] = (char (*)[65])calloc((size_t)max, sizeof(*tmp));
    if (!tmp) {
      return -1;
    }
    int ns = 0;
    if (collect_array_strings(json, tmp, max, &ns) != 0) {
      free(tmp);
      return -1;
    }
    for (int i = 0; i < ns; i++) {
      memcpy(entries[i].sha256, tmp[i], 65);
      entries[i].severity = 3;
    }
    free(tmp);
    *n_out = ns;
    return 0;
  }
  char (*tmp)[65] = (char (*)[65])calloc((size_t)max, sizeof(*tmp));
  if (!tmp) {
    return -1;
  }
  int tn = tokenize_flat(p, tmp, max);
  if (tn < 0) {
    free(tmp);
    return -1;
  }
  for (int i = 0; i < tn; i++) {
    memcpy(entries[i].sha256, tmp[i], 65);
    entries[i].severity = 3;
  }
  free(tmp);
  *n_out = tn;
  return 0;
}

static EdrError open_rw_db(const char *path, sqlite3 **out) {
  if (!path || !path[0]) {
    return EDR_ERR_INVALID_ARG;
  }
  if (sqlite3_open(path, out) != SQLITE_OK) {
    if (*out) {
      sqlite3_close(*out);
      *out = NULL;
    }
    return EDR_ERR_INTERNAL;
  }
  return EDR_OK;
}

static EdrError ensure_whitelist_schema(sqlite3 *db) {
  const char *sql =
      "CREATE TABLE IF NOT EXISTS file_hash_whitelist (sha256 TEXT PRIMARY KEY, is_active INTEGER NOT "
      "NULL DEFAULT 1);";
  char *err = NULL;
  if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
    sqlite3_free(err);
    return EDR_ERR_INTERNAL;
  }
  return EDR_OK;
}

static EdrError ensure_ioc_schema(sqlite3 *db) {
  const char *sql =
      "CREATE TABLE IF NOT EXISTS ioc_file_hash (sha256 TEXT PRIMARY KEY, is_active INTEGER "
      "NOT NULL DEFAULT 1, severity INTEGER DEFAULT 3);"
      "CREATE TABLE IF NOT EXISTS ioc_ip (ip TEXT PRIMARY KEY, is_active INTEGER NOT NULL DEFAULT 1);"
      "CREATE TABLE IF NOT EXISTS ioc_domain (domain TEXT PRIMARY KEY, is_active INTEGER NOT NULL DEFAULT 1);";
  char *err = NULL;
  if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
    sqlite3_free(err);
    return EDR_ERR_INTERNAL;
  }
  return EDR_OK;
}

EdrError edr_ave_update_whitelist_json(const EdrConfig *cfg, const char *entries_json) {
  if (!cfg || !entries_json) {
    return EDR_ERR_INVALID_ARG;
  }
  if (!cfg->ave.file_whitelist_db_path[0]) {
    return EDR_ERR_INVALID_ARG;
  }
  enum { MAX_H = 4096 };
  char (*hashes)[65] = (char (*)[65])calloc((size_t)MAX_H, sizeof(*hashes));
  if (!hashes) {
    return EDR_ERR_INTERNAL;
  }
  int n = 0;
  if (collect_whitelist_json(entries_json, hashes, MAX_H, &n) != 0) {
    free(hashes);
    return EDR_ERR_INVALID_ARG;
  }
  if (n == 0) {
    free(hashes);
    return EDR_ERR_INVALID_ARG;
  }
  sqlite3 *db = NULL;
  EdrError oe = open_rw_db(cfg->ave.file_whitelist_db_path, &db);
  if (oe != EDR_OK) {
    free(hashes);
    return oe;
  }
  oe = ensure_whitelist_schema(db);
  if (oe != EDR_OK) {
    sqlite3_close(db);
    free(hashes);
    return oe;
  }
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(db,
                         "INSERT OR REPLACE INTO file_hash_whitelist (sha256, is_active) VALUES (?, 1)",
                         -1, &st, NULL) != SQLITE_OK) {
    sqlite3_close(db);
    free(hashes);
    return EDR_ERR_INTERNAL;
  }
  char *err = NULL;
  if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
    sqlite3_free(err);
    sqlite3_finalize(st);
    sqlite3_close(db);
    free(hashes);
    return EDR_ERR_INTERNAL;
  }
  for (int i = 0; i < n; i++) {
    sqlite3_reset(st);
    sqlite3_bind_text(st, 1, hashes[i], -1, SQLITE_STATIC);
    if (sqlite3_step(st) != SQLITE_DONE) {
      sqlite3_finalize(st);
      sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
      sqlite3_close(db);
      free(hashes);
      return EDR_ERR_INTERNAL;
    }
  }
  sqlite3_finalize(st);
  if (sqlite3_exec(db, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
    sqlite3_free(err);
    sqlite3_close(db);
    free(hashes);
    return EDR_ERR_INTERNAL;
  }
  sqlite3_close(db);
  free(hashes);
  return EDR_OK;
}

EdrError edr_ave_update_ioc_json(const EdrConfig *cfg, const char *ioc_json) {
  if (!cfg || !ioc_json) {
    return EDR_ERR_INVALID_ARG;
  }
  if (!cfg->ave.ioc_db_path[0]) {
    return EDR_ERR_INVALID_ARG;
  }
  enum { MAX_H = 4096 };
  IocEntry *entries = (IocEntry *)calloc((size_t)MAX_H, sizeof(IocEntry));
  if (!entries) {
    return EDR_ERR_INTERNAL;
  }
  int n = 0;
  if (collect_ioc_json(ioc_json, entries, MAX_H, &n) != 0) {
    free(entries);
    return EDR_ERR_INVALID_ARG;
  }
  if (n == 0) {
    free(entries);
    return EDR_ERR_INVALID_ARG;
  }
  sqlite3 *db = NULL;
  EdrError oe = open_rw_db(cfg->ave.ioc_db_path, &db);
  if (oe != EDR_OK) {
    free(entries);
    return oe;
  }
  oe = ensure_ioc_schema(db);
  if (oe != EDR_OK) {
    sqlite3_close(db);
    free(entries);
    return oe;
  }
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(db,
                         "INSERT OR REPLACE INTO ioc_file_hash (sha256, is_active, severity) VALUES (?, 1, ?)",
                         -1, &st, NULL) != SQLITE_OK) {
    sqlite3_close(db);
    free(entries);
    return EDR_ERR_INTERNAL;
  }
  char *err = NULL;
  if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
    sqlite3_free(err);
    sqlite3_finalize(st);
    sqlite3_close(db);
    free(entries);
    return EDR_ERR_INTERNAL;
  }
  for (int i = 0; i < n; i++) {
    sqlite3_reset(st);
    sqlite3_bind_text(st, 1, entries[i].sha256, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, entries[i].severity);
    if (sqlite3_step(st) != SQLITE_DONE) {
      sqlite3_finalize(st);
      sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
      sqlite3_close(db);
      free(entries);
      return EDR_ERR_INTERNAL;
    }
  }
  sqlite3_finalize(st);
  if (sqlite3_exec(db, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
    sqlite3_free(err);
    sqlite3_close(db);
    free(entries);
    return EDR_ERR_INTERNAL;
  }
  sqlite3_close(db);
  free(entries);
  return EDR_OK;
}

#else /* !EDR_HAVE_SQLITE */

EdrError edr_ave_update_whitelist_json(const EdrConfig *cfg, const char *entries_json) {
  (void)cfg;
  (void)entries_json;
  return EDR_ERR_NOT_IMPL;
}

EdrError edr_ave_update_ioc_json(const EdrConfig *cfg, const char *ioc_json) {
  (void)cfg;
  (void)ioc_json;
  return EDR_ERR_NOT_IMPL;
}

#endif
