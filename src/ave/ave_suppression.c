#include "ave_suppression.h"

#include "edr/ave_sdk.h"
#include "edr/config.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

#ifdef EDR_HAVE_SQLITE
#include <sqlite3.h>
#endif

static int path_ok(const char *p) { return p && p[0] != '\0'; }

#ifdef EDR_HAVE_SQLITE

static int open_ro(const char *path, sqlite3 **out) {
  if (sqlite3_open_v2(path, out, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
    if (*out) {
      sqlite3_close(*out);
      *out = NULL;
    }
    return -1;
  }
  return 0;
}

static int open_rw(const char *path, sqlite3 **out) {
  if (sqlite3_open_v2(path, out, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK) {
    if (*out) {
      sqlite3_close(*out);
      *out = NULL;
    }
    return -1;
  }
  return 0;
}

int edr_ave_file_hash_whitelist_hit(const struct EdrConfig *cfg, const char sha256_hex[65]) {
  if (!cfg || !sha256_hex || !sha256_hex[0]) {
    return 0;
  }
  if (!path_ok(cfg->ave.file_whitelist_db_path)) {
    return 0;
  }
  sqlite3 *db = NULL;
  if (open_ro(cfg->ave.file_whitelist_db_path, &db) != 0) {
    return 0;
  }
  sqlite3_stmt *st = NULL;
  int hit = 0;
  if (sqlite3_prepare_v2(db,
                         "SELECT 1 FROM file_hash_whitelist WHERE sha256 = ? AND "
                         "COALESCE(is_active,1) = 1 LIMIT 1",
                         -1, &st, NULL) != SQLITE_OK) {
    sqlite3_close(db);
    return 0;
  }
  sqlite3_bind_text(st, 1, sha256_hex, -1, SQLITE_STATIC);
  if (sqlite3_step(st) == SQLITE_ROW) {
    hit = 1;
  }
  sqlite3_finalize(st);
  sqlite3_close(db);
  return hit;
}

int edr_ave_ioc_file_hit(const struct EdrConfig *cfg, const char sha256_hex[65], int *severity_out) {
  if (!cfg || !sha256_hex || !sha256_hex[0]) {
    return 0;
  }
  if (!path_ok(cfg->ave.ioc_db_path)) {
    return 0;
  }
  sqlite3 *db = NULL;
  if (open_ro(cfg->ave.ioc_db_path, &db) != 0) {
    return 0;
  }
  sqlite3_stmt *st = NULL;
  int hit = 0;
  if (sqlite3_prepare_v2(db,
                         "SELECT COALESCE(severity,3) FROM ioc_file_hash WHERE sha256 = ? AND "
                         "COALESCE(is_active,1) = 1 LIMIT 1",
                         -1, &st, NULL) != SQLITE_OK) {
    sqlite3_close(db);
    return 0;
  }
  sqlite3_bind_text(st, 1, sha256_hex, -1, SQLITE_STATIC);
  if (sqlite3_step(st) == SQLITE_ROW) {
    hit = 1;
    if (severity_out) {
      int s = sqlite3_column_int(st, 0);
      if (s < 1) {
        s = 1;
      }
      if (s > 3) {
        s = 3;
      }
      *severity_out = s;
    }
  }
  sqlite3_finalize(st);
  sqlite3_close(db);
  return hit;
}

static void edr_normalize_ip_for_ioc(const char *in, char *out, size_t cap) {
  if (!in || !out || cap < 4u) {
    if (out && cap) {
      out[0] = '\0';
    }
    return;
  }
  size_t i = 0;
  while (in[i] == ' ' || in[i] == '\t') {
    i++;
  }
  if (in[i] == '[') {
    i++;
  }
  size_t j = 0;
  while (in[i] && j + 1u < cap) {
    if (in[i] == ']') {
      break;
    }
    if (in[i] == '%') {
      break;
    }
    char c = in[i++];
    if (c >= 'A' && c <= 'F') {
      c = (char)(c - 'A' + 'a');
    }
    out[j++] = c;
  }
  out[j] = '\0';
}

static void edr_normalize_domain_for_ioc(const char *in, char *out, size_t cap) {
  if (!in || !out || cap < 2u) {
    if (out && cap) {
      out[0] = '\0';
    }
    return;
  }
  size_t j = 0;
  for (size_t i = 0; in[i] && j + 1u < cap; i++) {
    char c = in[i];
    if (c >= 'A' && c <= 'Z') {
      c = (char)(c - 'A' + 'a');
    }
    out[j++] = c;
  }
  out[j] = '\0';
  while (j > 0u && out[j - 1u] == '.') {
    out[--j] = '\0';
  }
}

int edr_ave_ioc_ip_hit(const struct EdrConfig *cfg, const char *ip_utf8) {
  if (!cfg || !ip_utf8 || !ip_utf8[0]) {
    return 0;
  }
  if (!path_ok(cfg->ave.ioc_db_path)) {
    return 0;
  }
  char norm[80];
  edr_normalize_ip_for_ioc(ip_utf8, norm, sizeof(norm));
  if (!norm[0]) {
    return 0;
  }
  sqlite3 *db = NULL;
  if (open_ro(cfg->ave.ioc_db_path, &db) != 0) {
    return 0;
  }
  sqlite3_stmt *st = NULL;
  int hit = 0;
  if (sqlite3_prepare_v2(db,
                         "SELECT 1 FROM ioc_ip WHERE ip = ? AND COALESCE(is_active,1) = 1 LIMIT 1", -1,
                         &st, NULL) != SQLITE_OK) {
    sqlite3_close(db);
    return 0;
  }
  sqlite3_bind_text(st, 1, norm, -1, SQLITE_STATIC);
  if (sqlite3_step(st) == SQLITE_ROW) {
    hit = 1;
  }
  sqlite3_finalize(st);
  sqlite3_close(db);
  return hit;
}

int edr_ave_ioc_domain_hit(const struct EdrConfig *cfg, const char *domain_utf8) {
  if (!cfg || !domain_utf8 || !domain_utf8[0]) {
    return 0;
  }
  if (!path_ok(cfg->ave.ioc_db_path)) {
    return 0;
  }
  char norm[260];
  edr_normalize_domain_for_ioc(domain_utf8, norm, sizeof(norm));
  if (!norm[0]) {
    return 0;
  }
  sqlite3 *db = NULL;
  if (open_ro(cfg->ave.ioc_db_path, &db) != 0) {
    return 0;
  }
  sqlite3_stmt *st = NULL;
  int h = 0;
  if (sqlite3_prepare_v2(db,
                         "SELECT 1 FROM ioc_domain WHERE domain = ? AND COALESCE(is_active,1) = 1 LIMIT 1",
                         -1, &st, NULL) != SQLITE_OK) {
    sqlite3_close(db);
    return 0;
  }
  sqlite3_bind_text(st, 1, norm, -1, SQLITE_STATIC);
  if (sqlite3_step(st) == SQLITE_ROW) {
    h = 1;
  }
  sqlite3_finalize(st);
  sqlite3_close(db);
  return h;
}

void edr_ave_behavior_event_apply_ioc(const struct EdrConfig *cfg, struct AVEBehaviorEvent *ev) {
  if (!cfg || !ev) {
    return;
  }
  if (!path_ok(cfg->ave.ioc_db_path)) {
    return;
  }
  char norm[320];
  if (ev->target_ip[0]) {
    edr_normalize_ip_for_ioc(ev->target_ip, norm, sizeof(norm));
    if (norm[0] && edr_ave_ioc_ip_hit(cfg, norm)) {
      ev->ioc_ip_hit = 1;
    }
  }
  if (ev->target_domain[0]) {
    edr_normalize_domain_for_ioc(ev->target_domain, norm, sizeof(norm));
    if (norm[0] && edr_ave_ioc_domain_hit(cfg, norm)) {
      ev->ioc_domain_hit = 1;
    }
  }
  if (ev->file_sha256_hex[0]) {
    int sev = 0;
    if (edr_ave_ioc_file_hit(cfg, ev->file_sha256_hex, &sev)) {
      ev->ioc_sha256_hit = 1;
    }
  }
}

int edr_ave_l4_non_exempt_hit(const struct EdrConfig *cfg, const char sha256_hex[65],
                              int *escalate_malware_out) {
  if (!cfg || !sha256_hex || !sha256_hex[0]) {
    return 0;
  }
  if (!path_ok(cfg->ave.behavior_policy_db_path)) {
    return 0;
  }
  if (escalate_malware_out) {
    *escalate_malware_out = 1;
  }
  sqlite3 *db = NULL;
  if (open_ro(cfg->ave.behavior_policy_db_path, &db) != 0) {
    return 0;
  }
  sqlite3_stmt *st = NULL;
  int hit = 0;
  if (sqlite3_prepare_v2(db,
                         "SELECT COALESCE(escalate,1) FROM file_behavior_non_exempt WHERE sha256 = ? AND "
                         "COALESCE(is_active,1) = 1 LIMIT 1",
                         -1, &st, NULL) != SQLITE_OK) {
    sqlite3_close(db);
    return 0;
  }
  sqlite3_bind_text(st, 1, sha256_hex, -1, SQLITE_STATIC);
  if (sqlite3_step(st) == SQLITE_ROW) {
    hit = 1;
    if (escalate_malware_out) {
      *escalate_malware_out = sqlite3_column_int(st, 0) ? 1 : 0;
    }
  }
  sqlite3_finalize(st);
  sqlite3_close(db);
  return hit;
}

static void fill_noise_decision(EdrAveTenantNoiseDecision *out, const char *action, const char *policy_version,
                                float score_delta, float raw_confidence, int gray_percent) {
  memset(out, 0, sizeof(*out));
  snprintf(out->action, sizeof(out->action), "%s", action && action[0] ? action : "observe");
  snprintf(out->policy_version, sizeof(out->policy_version), "%s",
           policy_version && policy_version[0] ? policy_version : "tenant-noise-policy");
  out->score_delta = score_delta;
  out->adjusted_confidence = raw_confidence + score_delta;
  if (out->adjusted_confidence < 0.0f) {
    out->adjusted_confidence = 0.0f;
  } else if (out->adjusted_confidence > 1.0f) {
    out->adjusted_confidence = 1.0f;
  }
  out->gray_percent = gray_percent < 0 ? 0u : (gray_percent > 100 ? 100u : (uint32_t)gray_percent);
  out->suppress = strcmp(out->action, "suppress") == 0;
  out->needs_review = strcmp(out->action, "review") == 0;
  out->observe_only = strcmp(out->action, "observe") == 0;
}

int edr_ave_tenant_noise_lookup(const struct EdrConfig *cfg, const char *tenant_id, const char *model_version,
                                const char *rule_name, float raw_confidence, EdrAveTenantNoiseDecision *out) {
  if (out) {
    memset(out, 0, sizeof(*out));
  }
  if (!cfg || !out || !path_ok(cfg->ave.behavior_policy_db_path)) {
    return 0;
  }
  sqlite3 *db = NULL;
  if (open_ro(cfg->ave.behavior_policy_db_path, &db) != 0) {
    return 0;
  }
  const char *sql =
      "SELECT action, COALESCE(score_delta,0), COALESCE(policy_version,''), COALESCE(gray_percent,0) "
      "FROM ave_tenant_noise_policy "
      "WHERE COALESCE(is_active,1)=1 "
      "AND tenant_id IN (?, '*') "
      "AND model_version IN (?, '*') "
      "AND rule_name IN (?, '*') "
      "AND ? >= COALESCE(min_confidence,0) "
      "AND ? <= COALESCE(max_confidence,1) "
      "ORDER BY CASE WHEN tenant_id=? THEN 0 ELSE 1 END, "
      "CASE WHEN model_version=? THEN 0 ELSE 1 END, "
      "CASE WHEN rule_name=? THEN 0 ELSE 1 END, updated_at DESC LIMIT 1";
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
    sqlite3_close(db);
    return 0;
  }
  const char *tenant = tenant_id && tenant_id[0] ? tenant_id : "*";
  const char *model = model_version && model_version[0] ? model_version : "*";
  const char *rule = rule_name && rule_name[0] ? rule_name : "*";
  sqlite3_bind_text(st, 1, tenant, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 2, model, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 3, rule, -1, SQLITE_TRANSIENT);
  sqlite3_bind_double(st, 4, raw_confidence);
  sqlite3_bind_double(st, 5, raw_confidence);
  sqlite3_bind_text(st, 6, tenant, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 7, model, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 8, rule, -1, SQLITE_TRANSIENT);
  int hit = 0;
  if (sqlite3_step(st) == SQLITE_ROW) {
    const char *action = (const char *)sqlite3_column_text(st, 0);
    float delta = (float)sqlite3_column_double(st, 1);
    const char *policy = (const char *)sqlite3_column_text(st, 2);
    int gray = sqlite3_column_int(st, 3);
    fill_noise_decision(out, action, policy, delta, raw_confidence, gray);
    hit = 1;
  }
  sqlite3_finalize(st);
  sqlite3_close(db);
  return hit;
}

int edr_ave_gray_eval_record(const struct EdrConfig *cfg, const char *tenant_id, const char *model_version,
                             const char *policy_version, const char *rule_name, float raw_confidence,
                             float adjusted_confidence, const char *decision, const char *shadow_verdict) {
  if (!cfg || !path_ok(cfg->ave.behavior_policy_db_path)) {
    return -1;
  }
  sqlite3 *db = NULL;
  if (open_rw(cfg->ave.behavior_policy_db_path, &db) != 0) {
    return -1;
  }
  const char *ddl =
      "CREATE TABLE IF NOT EXISTS ave_model_gray_eval ("
      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "tenant_id TEXT, model_version TEXT, policy_version TEXT, rule_name TEXT,"
      "raw_confidence REAL, adjusted_confidence REAL, decision TEXT, shadow_verdict TEXT,"
      "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)";
  char *err = NULL;
  if (sqlite3_exec(db, ddl, NULL, NULL, &err) != SQLITE_OK) {
    sqlite3_free(err);
    sqlite3_close(db);
    return -1;
  }
  sqlite3_stmt *st = NULL;
  const char *sql =
      "INSERT INTO ave_model_gray_eval (tenant_id,model_version,policy_version,rule_name,raw_confidence,"
      "adjusted_confidence,decision,shadow_verdict) VALUES (?,?,?,?,?,?,?,?)";
  if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
    sqlite3_close(db);
    return -1;
  }
  sqlite3_bind_text(st, 1, tenant_id ? tenant_id : "", -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 2, model_version ? model_version : "", -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 3, policy_version ? policy_version : "", -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 4, rule_name ? rule_name : "", -1, SQLITE_TRANSIENT);
  sqlite3_bind_double(st, 5, raw_confidence);
  sqlite3_bind_double(st, 6, adjusted_confidence);
  sqlite3_bind_text(st, 7, decision ? decision : "", -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 8, shadow_verdict ? shadow_verdict : "", -1, SQLITE_TRANSIENT);
  int rc = sqlite3_step(st) == SQLITE_DONE ? 0 : -1;
  sqlite3_finalize(st);
  sqlite3_close(db);
  return rc;
}

#else

int edr_ave_file_hash_whitelist_hit(const struct EdrConfig *cfg, const char sha256_hex[65]) {
  (void)cfg;
  (void)sha256_hex;
  return 0;
}

int edr_ave_ioc_file_hit(const struct EdrConfig *cfg, const char sha256_hex[65], int *severity_out) {
  (void)cfg;
  (void)sha256_hex;
  (void)severity_out;
  return 0;
}

int edr_ave_ioc_ip_hit(const struct EdrConfig *cfg, const char *ip_utf8) {
  (void)cfg;
  (void)ip_utf8;
  return 0;
}

int edr_ave_ioc_domain_hit(const struct EdrConfig *cfg, const char *domain_utf8) {
  (void)cfg;
  (void)domain_utf8;
  return 0;
}

void edr_ave_behavior_event_apply_ioc(const struct EdrConfig *cfg, struct AVEBehaviorEvent *ev) {
  (void)cfg;
  (void)ev;
}

int edr_ave_l4_non_exempt_hit(const struct EdrConfig *cfg, const char sha256_hex[65],
                              int *escalate_malware_out) {
  (void)cfg;
  (void)sha256_hex;
  (void)escalate_malware_out;
  return 0;
}

int edr_ave_tenant_noise_lookup(const struct EdrConfig *cfg, const char *tenant_id, const char *model_version,
                                const char *rule_name, float raw_confidence, EdrAveTenantNoiseDecision *out) {
  (void)cfg;
  (void)tenant_id;
  (void)model_version;
  (void)rule_name;
  (void)raw_confidence;
  if (out) {
    memset(out, 0, sizeof(*out));
  }
  return 0;
}

int edr_ave_gray_eval_record(const struct EdrConfig *cfg, const char *tenant_id, const char *model_version,
                             const char *policy_version, const char *rule_name, float raw_confidence,
                             float adjusted_confidence, const char *decision, const char *shadow_verdict) {
  (void)cfg;
  (void)tenant_id;
  (void)model_version;
  (void)policy_version;
  (void)rule_name;
  (void)raw_confidence;
  (void)adjusted_confidence;
  (void)decision;
  (void)shadow_verdict;
  return -1;
}

#endif

void edr_ave_overlay_ioc_post_ai(AVEScanResult *out, int severity) {
  (void)severity;
  if (!out) {
    return;
  }
  out->final_verdict = VERDICT_IOC_CONFIRMED;
  out->final_confidence = fmaxf(out->final_confidence, 0.99f);
  snprintf(out->verification_layer, sizeof(out->verification_layer), "L3");
  snprintf(out->rule_name, sizeof(out->rule_name), "ioc_file_hash_post");
}

void edr_ave_apply_l4_non_exempt(AVEScanResult *out, int escalate_malware, float fp_floor,
                                 float l3_trigger) {
  if (!out) {
    return;
  }
  out->sig_behavior_override = true;
  out->needs_l2_review = true;
  if (out->final_verdict == VERDICT_IOC_CONFIRMED) {
    return;
  }
  if (escalate_malware) {
    out->final_verdict = VERDICT_MALWARE;
    out->final_confidence = fmaxf(out->final_confidence, l3_trigger);
  } else {
    if (out->final_verdict == VERDICT_CLEAN) {
      out->final_verdict = VERDICT_SUSPICIOUS;
      out->final_confidence = fmaxf(out->final_confidence, fp_floor);
    }
  }
  snprintf(out->verification_layer, sizeof(out->verification_layer), "L4");
  snprintf(out->rule_name, sizeof(out->rule_name), "behavior_non_exempt");
}

void edr_ave_apply_l4_realtime_behavior(AVEScanResult *out, int escalate_malware, float fp_floor,
                                        float l3_trigger) {
  if (!out) {
    return;
  }
  out->sig_behavior_override = true;
  out->needs_l2_review = true;
  if (out->final_verdict == VERDICT_IOC_CONFIRMED) {
    return;
  }
  if (escalate_malware) {
    out->final_verdict = VERDICT_MALWARE;
    out->final_confidence = fmaxf(out->final_confidence, l3_trigger);
  } else {
    if (out->final_verdict == VERDICT_CLEAN) {
      out->final_verdict = VERDICT_SUSPICIOUS;
      out->final_confidence = fmaxf(out->final_confidence, fp_floor);
    }
  }
  snprintf(out->verification_layer, sizeof(out->verification_layer), "L4");
  snprintf(out->rule_name, sizeof(out->rule_name), "behavior_realtime");
}
