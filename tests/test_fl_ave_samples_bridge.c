/**
 * FL + AVE：临时 fl_samples.db → fl_samples_db_register_ave_bridge → AVE_ExportFeatureVector
 * 与 fl_samples_db_read_feature 一致性自检（macOS/Linux，须 SQLite）。
 */
#include "edr/ave_sdk.h"
#include "edr/fl_feature_provider.h"
#include "fl_samples_db.h"

#include <sqlite3.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <io.h>
#include <process.h>
#else
#include <unistd.h>
#endif

static int fail(const char *msg) {
  fprintf(stderr, "FAIL: %s\n", msg);
  return 1;
}

/** 512×float32 的确定性字节模式（便于 memcmp 与 SQLite BLOB 往返对照） */
static unsigned char g_blob_expect[512u * sizeof(float)];

static void fill_blob_pattern(unsigned char *out, size_t nbytes) {
  for (size_t i = 0; i < nbytes; i++) {
    out[i] = (unsigned char)((i * 131u + 7u) & 0xffu);
  }
}

/** 在 `path` 创建与 `tests/fixtures/fl_samples_schema.sql` / `FL_SAMPLES_SCHEMA.md` 一致的表并插入一行 static 样本。 */
static int seed_db(const char *path, const char *sha256_lower64, const unsigned char *blob,
                   size_t blob_len) {
  sqlite3 *db = NULL;
  if (sqlite3_open(path, &db) != SQLITE_OK || !db) {
    return -1;
  }
  const char *ddl =
      "CREATE TABLE IF NOT EXISTS fl_samples ("
      "sha256 TEXT PRIMARY KEY NOT NULL,"
      "label INTEGER NOT NULL DEFAULT 0,"
      "model_target TEXT NOT NULL DEFAULT 'static',"
      "feature_blob BLOB NOT NULL,"
      "created_ts INTEGER NOT NULL DEFAULT 0"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_fl_samples_target ON fl_samples(model_target);";
  if (sqlite3_exec(db, ddl, NULL, NULL, NULL) != SQLITE_OK) {
    sqlite3_close(db);
    return -1;
  }
  sqlite3_stmt *st = NULL;
  const char *ins =
      "INSERT INTO fl_samples(sha256, label, model_target, feature_blob, created_ts) VALUES(?,?,?,?,?)";
  if (sqlite3_prepare_v2(db, ins, -1, &st, NULL) != SQLITE_OK) {
    sqlite3_close(db);
    return -1;
  }
  sqlite3_bind_text(st, 1, sha256_lower64, -1, SQLITE_STATIC);
  sqlite3_bind_int(st, 2, 0);
  sqlite3_bind_text(st, 3, "static", -1, SQLITE_STATIC);
  sqlite3_bind_blob(st, 4, blob, (int)blob_len, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 5, (sqlite3_int64)1700000000);
  if (sqlite3_step(st) != SQLITE_DONE) {
    sqlite3_finalize(st);
    sqlite3_close(db);
    return -1;
  }
  sqlite3_finalize(st);
  sqlite3_close(db);
  return 0;
}

int main(void) {
#ifndef EDR_HAVE_SQLITE
  fprintf(stderr, "SKIP: EDR_HAVE_SQLITE\n");
  return 0;
#else
  char path[512];
#if defined(_WIN32)
  const char *tmp = getenv("TEMP");
  if (!tmp || !tmp[0]) {
    tmp = ".";
  }
  snprintf(path, sizeof(path), "%s\\edr_fl_ave_bridge_%d_%lu.db", tmp, (int)_getpid(),
           (unsigned long)time(NULL));
#else
  const char *tmp = getenv("TMPDIR");
  if (!tmp || !tmp[0]) {
    tmp = "/tmp";
  }
  snprintf(path, sizeof(path), "%s/edr_fl_ave_bridge_XXXXXX", tmp);
  {
    int fd = mkstemp(path);
    if (fd < 0) {
      return fail("mkstemp");
    }
    close(fd);
  }
#endif
  remove(path);

  fill_blob_pattern(g_blob_expect, sizeof(g_blob_expect));

  const char *sha_db =
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  if (seed_db(path, sha_db, g_blob_expect, sizeof(g_blob_expect)) != 0) {
    return fail("seed_db");
  }

  /* 先打开只读库并校验 BLOB，再 AVE_Init */
  if (fl_samples_db_open(path) != 0) {
    remove(path);
    return fail("fl_samples_db_open");
  }

  float via_export[512];
  float via_db[512];
  /* 大小写混合输入，验证规范化后与库中行为一致 */
  const char *sha_query_mixed =
      "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

  memset(via_db, 0, sizeof(via_db));
  if (fl_samples_db_read_feature(sha_query_mixed, via_db, 512u) != 0) {
    fl_samples_db_close();
    remove(path);
    return fail("fl_samples_db_read_feature before AVE_Init (DB/path)");
  }
  if (memcmp(via_db, g_blob_expect, sizeof(g_blob_expect)) != 0) {
    fl_samples_db_close();
    remove(path);
    return fail("read_feature before AVE_Init memcmp vs g_blob_expect");
  }

  fl_samples_db_close();

  AVEConfig cfg = {0};
  cfg.model_dir = ".";
  cfg.max_concurrent_scans = 1;
  if (AVE_Init(&cfg) != AVE_OK) {
    remove(path);
    return fail("AVE_Init");
  }

  if (fl_samples_db_open(path) != 0) {
    AVE_Shutdown();
    remove(path);
    return fail("fl_samples_db_open after AVE_Init");
  }

  fl_samples_db_register_ave_bridge();

  memset(via_export, 0, sizeof(via_export));
  if (AVE_ExportFeatureVector(sha_query_mixed, via_export) != AVE_OK) {
    fl_samples_db_unregister_ave_bridge();
    fl_samples_db_close();
    AVE_Shutdown();
    remove(path);
    return fail("AVE_ExportFeatureVector with bridge");
  }
  {
    if (memcmp(via_export, g_blob_expect, sizeof(g_blob_expect)) != 0) {
      fl_samples_db_unregister_ave_bridge();
      fl_samples_db_close();
      AVE_Shutdown();
      remove(path);
      return fail("export vector mismatch");
    }
  }

  memset(via_db, 0, sizeof(via_db));
  if (fl_samples_db_read_feature(sha_query_mixed, via_db, 512u) != 0) {
    fl_samples_db_unregister_ave_bridge();
    fl_samples_db_close();
    AVE_Shutdown();
    remove(path);
    return fail("fl_samples_db_read_feature");
  }
  {
    if (memcmp(via_db, g_blob_expect, sizeof(g_blob_expect)) != 0) {
      fl_samples_db_unregister_ave_bridge();
      fl_samples_db_close();
      AVE_Shutdown();
      remove(path);
      return fail("read_feature mismatch");
    }
  }

  {
    float ex[512];
    if (AVE_ExportFeatureVectorEx(sha_query_mixed, ex, 512u, EDR_FL_TARGET_STATIC) != AVE_OK) {
      fl_samples_db_unregister_ave_bridge();
      fl_samples_db_close();
      AVE_Shutdown();
      remove(path);
      return fail("ExportFeatureVectorEx static 512");
    }
    if (memcmp(ex, g_blob_expect, sizeof(g_blob_expect)) != 0) {
      fl_samples_db_unregister_ave_bridge();
      fl_samples_db_close();
      AVE_Shutdown();
      remove(path);
      return fail("ExportFeatureVectorEx mismatch");
    }
  }

  {
    const char *sha_missing =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    float z[512];
    if (AVE_ExportFeatureVector(sha_missing, z) != AVE_ERR_FL_SAMPLE_NOT_FOUND) {
      fl_samples_db_unregister_ave_bridge();
      fl_samples_db_close();
      AVE_Shutdown();
      remove(path);
      return fail("expected FL_SAMPLE_NOT_FOUND for missing sha");
    }
  }

  fl_samples_db_unregister_ave_bridge();
  fl_samples_db_close();
  AVE_Shutdown();
  remove(path);
  return 0;
#endif
}
