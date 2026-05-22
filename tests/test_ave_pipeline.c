/**
 * AVE_ScanFile 管线：IOC 预检关闭 + ONNX 后 IOC 二次核对；依赖 EDR_AVE_INFER_DRY_RUN。
 * （L4 命中见 tests/test_ave_suppression.c）
 */
#include "edr/ave_sdk.h"
#include "edr/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef EDR_HAVE_SQLITE
int main(void) {
  printf("test_ave_pipeline: skipped (no EDR_HAVE_SQLITE)\n");
  return 0;
}
#else

#include <sqlite3.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

static int make_temp_path(char *out, size_t cap) {
#ifdef _WIN32
  char tmp[MAX_PATH];
  if (GetTempPathA(MAX_PATH, tmp) == 0) {
    return -1;
  }
  if (GetTempFileNameA(tmp, "edr", 0, out) == 0) {
    return -1;
  }
  return 0;
#else
  char tmpl[] = "/tmp/edr_ave_pipe_XXXXXX";
  int fd = mkstemp(tmpl);
  if (fd < 0) {
    return -1;
  }
  (void)close(fd);
  snprintf(out, cap, "%s", tmpl);
  return 0;
#endif
}

static int init_ioc_db(const char *path) {
  sqlite3 *db = NULL;
  if (sqlite3_open(path, &db) != SQLITE_OK) {
    return -1;
  }
  const char *sql =
      "CREATE TABLE IF NOT EXISTS ioc_file_hash (sha256 TEXT PRIMARY KEY, is_active INTEGER NOT NULL "
      "DEFAULT 1, severity INTEGER DEFAULT 3);"
      "INSERT OR REPLACE INTO ioc_file_hash (sha256,is_active,severity) VALUES ("
      "'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',1,3);";
  char *err = NULL;
  if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
    sqlite3_free(err);
    sqlite3_close(db);
    return -1;
  }
  sqlite3_close(db);
  return 0;
}

int main(void) {
#ifdef _WIN32
  (void)_putenv("EDR_AVE_INFER_DRY_RUN=1");
#else
  (void)setenv("EDR_AVE_INFER_DRY_RUN", "1", 1);
#endif

  char tdb[512], tempty[512];
  if (make_temp_path(tdb, sizeof(tdb)) != 0 || make_temp_path(tempty, sizeof(tempty)) != 0) {
    return 1;
  }
  if (init_ioc_db(tdb) != 0) {
    remove(tdb);
    remove(tempty);
    return 1;
  }

  FILE *f = fopen(tempty, "wb");
  if (!f) {
    remove(tdb);
    remove(tempty);
    return 1;
  }
  fclose(f);

  EdrConfig cfg;
  edr_config_apply_defaults(&cfg);
  cfg.ave.cert_whitelist_enabled = false;
  snprintf(cfg.ave.model_dir, sizeof(cfg.ave.model_dir), ".");
  snprintf(cfg.ave.ioc_db_path, sizeof(cfg.ave.ioc_db_path), "%s", tdb);
  cfg.ave.ioc_precheck_enabled = false;

  if (AVE_InitFromEdrConfig(&cfg) != AVE_OK) {
    remove(tdb);
    remove(tempty);
    fprintf(stderr, "AVE_InitFromEdrConfig failed\n");
    return 1;
  }

  AVEScanResult res;
  memset(&res, 0, sizeof(res));
  if (AVE_ScanFile(tempty, &res) != AVE_OK) {
    AVE_Shutdown();
    remove(tdb);
    remove(tempty);
    fprintf(stderr, "AVE_ScanFile failed\n");
    return 1;
  }

  if (res.final_verdict != VERDICT_IOC_CONFIRMED) {
    fprintf(stderr, "expected IOC_CONFIRMED got %d layer=%s rule=%s\n", (int)res.final_verdict,
            res.verification_layer, res.rule_name);
    AVE_Shutdown();
    remove(tdb);
    remove(tempty);
    return 1;
  }
  if (strcmp(res.rule_name, "ioc_file_hash_post") != 0) {
    fprintf(stderr, "expected ioc_file_hash_post rule\n");
    AVE_Shutdown();
    remove(tdb);
    remove(tempty);
    return 1;
  }

  AVE_Shutdown();
  remove(tdb);
  remove(tempty);
  printf("test_ave_pipeline: ok\n");
  return 0;
}
#endif /* EDR_HAVE_SQLITE */
