/**
 * SQLite 抑制层单元测试：临时库 + 固定 SHA256（空文件）。
 * 需 CMake 启用 SQLite（EDR_HAVE_SQLITE）。
 */
#include "ave_rules_meta.h"
#include "ave_suppression.h"
#include "edr/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef EDR_HAVE_SQLITE
int main(void) {
  printf("test_ave_suppression: skipped (no EDR_HAVE_SQLITE)\n");
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
  char tmpl[] = "/tmp/edr_ave_sup_XXXXXX";
  int fd = mkstemp(tmpl);
  if (fd < 0) {
    return -1;
  }
  (void)close(fd);
  snprintf(out, cap, "%s", tmpl);
  return 0;
#endif
}

static int init_db_ioc_meta(const char *path) {
  sqlite3 *db = NULL;
  if (sqlite3_open(path, &db) != SQLITE_OK) {
    return -1;
  }
  const char *sql =
      "CREATE TABLE IF NOT EXISTS ave_db_meta (key TEXT PRIMARY KEY, value TEXT);"
      "INSERT OR REPLACE INTO ave_db_meta (key,value) VALUES ('rules_version','utest-2026-04-18');"
      "CREATE TABLE IF NOT EXISTS ioc_file_hash (sha256 TEXT PRIMARY KEY, is_active INTEGER NOT NULL "
      "DEFAULT 1, severity INTEGER DEFAULT 3);"
      "INSERT OR REPLACE INTO ioc_file_hash (sha256,is_active,severity) VALUES ("
      "'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',1,3);"
      "CREATE TABLE IF NOT EXISTS file_hash_whitelist (sha256 TEXT PRIMARY KEY, is_active INTEGER NOT "
      "NULL DEFAULT 1);"
      "CREATE TABLE IF NOT EXISTS file_behavior_non_exempt (sha256 TEXT PRIMARY KEY, is_active INTEGER "
      "NOT NULL DEFAULT 1, escalate INTEGER NOT NULL DEFAULT 1);";
  char *err = NULL;
  if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
    sqlite3_free(err);
    sqlite3_close(db);
    return -1;
  }
  sqlite3_close(db);
  return 0;
}

static int init_db_l4_only(const char *path) {
  sqlite3 *db = NULL;
  if (sqlite3_open(path, &db) != SQLITE_OK) {
    return -1;
  }
  const char *sql =
      "CREATE TABLE IF NOT EXISTS file_behavior_non_exempt (sha256 TEXT PRIMARY KEY, is_active INTEGER "
      "NOT NULL DEFAULT 1, escalate INTEGER NOT NULL DEFAULT 1);"
      "INSERT OR REPLACE INTO file_behavior_non_exempt (sha256,is_active,escalate) VALUES ("
      "'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',1,0);";
  char *err = NULL;
  if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
    sqlite3_free(err);
    sqlite3_close(db);
    return -1;
  }
  sqlite3_close(db);
  return 0;
}

static int init_db_tenant_noise(const char *path) {
  sqlite3 *db = NULL;
  if (sqlite3_open(path, &db) != SQLITE_OK) {
    return -1;
  }
  const char *sql =
      "CREATE TABLE IF NOT EXISTS ave_tenant_noise_policy ("
      "tenant_id TEXT NOT NULL, model_version TEXT NOT NULL, rule_name TEXT NOT NULL,"
      "min_confidence REAL DEFAULT 0, max_confidence REAL DEFAULT 1, action TEXT NOT NULL,"
      "score_delta REAL DEFAULT 0, policy_version TEXT, gray_percent INTEGER DEFAULT 0,"
      "is_active INTEGER DEFAULT 1, updated_at TEXT DEFAULT CURRENT_TIMESTAMP);"
      "INSERT INTO ave_tenant_noise_policy (tenant_id,model_version,rule_name,min_confidence,max_confidence,"
      "action,score_delta,policy_version,gray_percent,is_active) VALUES "
      "('tenant-a','ave-bhv-v3','rmm_remote_admin',0.4,0.95,'suppress',-0.55,'tenant-noise-v7',15,1),"
      "('*','ave-bhv-v3','powershell_download',0.6,1.0,'review',-0.10,'global-noise-v2',5,1);";
  char *err = NULL;
  if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
    sqlite3_free(err);
    sqlite3_close(db);
    return -1;
  }
  sqlite3_close(db);
  return 0;
}

static int count_gray_eval_rows(const char *path) {
  sqlite3 *db = NULL;
  if (sqlite3_open(path, &db) != SQLITE_OK) {
    return -1;
  }
  sqlite3_stmt *st = NULL;
  int n = -1;
  if (sqlite3_prepare_v2(db, "SELECT COUNT(1) FROM ave_model_gray_eval", -1, &st, NULL) == SQLITE_OK &&
      sqlite3_step(st) == SQLITE_ROW) {
    n = sqlite3_column_int(st, 0);
  }
  sqlite3_finalize(st);
  sqlite3_close(db);
  return n;
}

int main(void) {
  char dbpath[512];
  if (make_temp_path(dbpath, sizeof(dbpath)) != 0) {
    fprintf(stderr, "make_temp_path failed\n");
    return 1;
  }
  if (init_db_ioc_meta(dbpath) != 0) {
    fprintf(stderr, "init_db failed\n");
    remove(dbpath);
    return 1;
  }

  EdrConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  snprintf(cfg.ave.ioc_db_path, sizeof(cfg.ave.ioc_db_path), "%s", dbpath);
  cfg.ave.file_whitelist_db_path[0] = '\0';
  cfg.ave.behavior_policy_db_path[0] = '\0';

  const char *empty_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  int sev = 0;
  if (!edr_ave_ioc_file_hit(&cfg, empty_sha, &sev)) {
    fprintf(stderr, "expected IOC hit\n");
    remove(dbpath);
    return 1;
  }
  if (sev != 3) {
    fprintf(stderr, "expected severity 3 got %d\n", sev);
    remove(dbpath);
    return 1;
  }

  char ver[64];
  if (edr_ave_db_meta_get(dbpath, "rules_version", ver, sizeof(ver)) != 0 ||
      strcmp(ver, "utest-2026-04-18") != 0) {
    fprintf(stderr, "meta rules_version mismatch: [%s]\n", ver);
    remove(dbpath);
    return 1;
  }
  int cnt = edr_ave_db_count_ioc_rows(dbpath);
  if (cnt != 1) {
    fprintf(stderr, "ioc count expected 1 got %d\n", cnt);
    remove(dbpath);
    return 1;
  }

  char db2[512];
  if (make_temp_path(db2, sizeof(db2)) != 0) {
    remove(dbpath);
    return 1;
  }
  if (init_db_l4_only(db2) != 0) {
    remove(dbpath);
    remove(db2);
    return 1;
  }
  snprintf(cfg.ave.behavior_policy_db_path, sizeof(cfg.ave.behavior_policy_db_path), "%s", db2);
  int esc = -1;
  if (!edr_ave_l4_non_exempt_hit(&cfg, empty_sha, &esc) || esc != 0) {
    fprintf(stderr, "L4 hit/escalate mismatch\n");
    remove(dbpath);
    remove(db2);
    return 1;
  }

  char db3[512];
  if (make_temp_path(db3, sizeof(db3)) != 0) {
    remove(dbpath);
    remove(db2);
    return 1;
  }
  if (init_db_tenant_noise(db3) != 0) {
    remove(dbpath);
    remove(db2);
    remove(db3);
    return 1;
  }
  snprintf(cfg.ave.behavior_policy_db_path, sizeof(cfg.ave.behavior_policy_db_path), "%s", db3);
  EdrAveTenantNoiseDecision dec;
  if (!edr_ave_tenant_noise_lookup(&cfg, "tenant-a", "ave-bhv-v3", "rmm_remote_admin", 0.80f, &dec) ||
      !dec.suppress || dec.gray_percent != 15u || strcmp(dec.policy_version, "tenant-noise-v7") != 0 ||
      dec.adjusted_confidence > 0.26f) {
    fprintf(stderr, "tenant noise suppress mismatch action=%s policy=%s adj=%.3f gray=%u\n", dec.action,
            dec.policy_version, dec.adjusted_confidence, dec.gray_percent);
    remove(dbpath);
    remove(db2);
    remove(db3);
    return 1;
  }
  if (!edr_ave_tenant_noise_lookup(&cfg, "tenant-b", "ave-bhv-v3", "powershell_download", 0.82f, &dec) ||
      !dec.needs_review || strcmp(dec.policy_version, "global-noise-v2") != 0) {
    fprintf(stderr, "global noise review mismatch\n");
    remove(dbpath);
    remove(db2);
    remove(db3);
    return 1;
  }
  if (edr_ave_gray_eval_record(&cfg, "tenant-a", "ave-bhv-v3-canary", dec.policy_version, "powershell_download",
                               0.82f, dec.adjusted_confidence, dec.action, "would_alert") != 0 ||
      count_gray_eval_rows(db3) != 1) {
    fprintf(stderr, "gray eval record mismatch\n");
    remove(dbpath);
    remove(db2);
    remove(db3);
    return 1;
  }

  remove(dbpath);
  remove(db2);
  remove(db3);
  printf("test_ave_suppression: ok\n");
  return 0;
}
#endif /* EDR_HAVE_SQLITE */
