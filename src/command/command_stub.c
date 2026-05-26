/* §8 响应指令执行器 — Subscribe 分发；高危操作需 EDR_CMD_ENABLED=1；AVE 见 ave_* */

#ifdef _MSC_VER
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef _CRT_NONSTDC_NO_WARNINGS
#define _CRT_NONSTDC_NO_WARNINGS
#endif
#endif

#include "edr/attack_surface_report.h"
#include "edr/command.h"
#include "edr/command_state.h"
#include "edr/ave.h"
#include "edr/ave_sdk.h"
#include "edr/config.h"
#include "edr/error.h"
#include "edr/grpc_client.h"
#include "edr/ingest_http.h"
#include "edr/local_evidence_cache.h"
#include "edr/pmfe.h"
#include "edr/response.h"
#include "edr/self_protect.h"
#include "edr/sha256.h"
#include "edr/shell_exec.h"
#include "edr/shell_session.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(EDR_HAVE_OPENSSL_HTTP) || defined(EDR_HAVE_OPENSSL_FL)
#define EDR_HAVE_COMMAND_SIGNATURE_OPENSSL 1
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#endif

#ifdef _WIN32
#include <windows.h>
#include <winevt.h>
#else
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

static unsigned long s_handled;
static unsigned long s_unknown;
static unsigned long s_rejected;
static unsigned long s_exec_ok;
static unsigned long s_exec_fail;
static const char *s_active_command_type;
unsigned long g_cmd_handled;
unsigned long g_cmd_rejected;
unsigned long g_cmd_exec_ok;
unsigned long g_cmd_exec_fail;

/** main 在 edr_agent_init 后绑定，供 ave_infer 使用 */
static const EdrConfig *s_bound_cfg;

static int64_t command_now_ms(void);

void edr_command_bind_config(const struct EdrConfig *cfg) { s_bound_cfg = cfg; }

static int streq(const char *a, const char *b) { return a && b && strcmp(a, b) == 0; }

static int dangerous_enabled(void) {
  const char *e = getenv("EDR_CMD_ENABLED");
  if (e && e[0] == '1') {
    return 1;
  }
  e = getenv("EDR_CMD_DANGEROUS");
  if (e && e[0] == '1') {
    return 1;
  }
  if (s_bound_cfg && s_bound_cfg->command.allow_dangerous) {
    return 1;
  }
  return 0;
}

/** 未设置 `EDR_CMD_KILL_ALLOWLIST` 时不限制；设置后仅允许列表内 pid（逗号分隔） */
static int kill_pid_allowed(long pid) {
  const char *list = getenv("EDR_CMD_KILL_ALLOWLIST");
  if (!list || !list[0]) {
    return 1;
  }
  char buf[1024];
  size_t n = strlen(list);
  if (n >= sizeof(buf)) {
    n = sizeof(buf) - 1u;
  }
  memcpy(buf, list, n);
  buf[n] = 0;
  char *p = buf;
  while (p && *p) {
    char *comma = strchr(p, ',');
    if (comma) {
      *comma++ = 0;
    }
    while (*p == ' ' || *p == '\t') {
      p++;
    }
    char *end = NULL;
    long v = strtol(p, &end, 10);
    if (end != p && v == pid) {
      return 1;
    }
    p = comma;
  }
  return 0;
}

static void audit_both(const char *cmd_id, const char *msg) {
  fprintf(stderr, "[command][audit] id=%s %s\n", cmd_id ? cmd_id : "", msg);
  const char *ap = getenv("EDR_CMD_AUDIT_PATH");
  if (!ap || !ap[0]) {
    return;
  }
  FILE *f = fopen(ap, "a");
  if (!f) {
    return;
  }
  time_t t = time(NULL);
#ifdef _WIN32
  struct tm tmst;
  localtime_s(&tmst, &t);
#else
  struct tm tmst;
  localtime_r(&t, &tmst);
#endif
  char ts[40];
  strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tmst);
  fprintf(f, "%s id=%s %s\n", ts, cmd_id ? cmd_id : "", msg);
  fclose(f);
}

static int soar_want_report(const EdrSoarCommandMeta *m) {
  const char *a = getenv("EDR_SOAR_REPORT_ALWAYS");
  if (a && a[0] == '1') {
    return 1;
  }
  if (!m) {
    return 0;
  }
  return m->soar_correlation_id[0] || m->playbook_run_id[0];
}

static int command_should_report(const char *cmd_id, const EdrSoarCommandMeta *m) {
  if (soar_want_report(m)) {
    return 1;
  }
  return cmd_id && strncmp(cmd_id, "cmd_", 4u) == 0;
}

static const char *response_status_label(EdrCommandExecutionStatus st) {
  switch (st) {
    case EdrCmdExecOk:
      return "ok";
    case EdrCmdExecRejected:
      return "denied";
    case EdrCmdExecFailed:
      return "failed";
    case EdrCmdExecUnknownType:
      return "failed";
    default:
      return "failed";
  }
}

static void json_escape_to(char *dst, size_t cap, const char *s) {
  if (!dst || cap == 0u) {
    return;
  }
  size_t o = 0;
  dst[o++] = '"';
  if (!s) {
    s = "";
  }
  for (; *s && o + 2u < cap; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') {
      dst[o++] = '\\';
      dst[o++] = (char)c;
    } else if (c == '\n') {
      dst[o++] = '\\';
      dst[o++] = 'n';
    } else if (c == '\r') {
      dst[o++] = '\\';
      dst[o++] = 'r';
    } else if (c == '\t') {
      dst[o++] = '\\';
      dst[o++] = 't';
    } else if (c < 0x20u) {
      if (o + 7u >= cap) {
        break;
      }
      o += (size_t)snprintf(dst + o, cap - o, "\\u%04x", (unsigned)c);
    } else {
      dst[o++] = (char)c;
    }
  }
  if (o + 1u < cap) {
    dst[o++] = '"';
  }
  dst[o < cap ? o : cap - 1u] = '\0';
}

static void soar_emit_ex(const char *cmd_id, const EdrSoarCommandMeta *sm, EdrCommandExecutionStatus st,
                         int exit_code, const char *detail, const char *response_status,
                         const char *artifacts) {
  char detail_json[16384];
  char taskj[300];
  char statusj[96];
  char raw[12000];
  char err[1600];
  const char *rstatus = response_status && response_status[0] ? response_status : response_status_label(st);
  int retryable = (st == EdrCmdExecFailed && exit_code != 1 && exit_code != 2 && exit_code != 7) ? 1 : 0;
  json_escape_to(taskj, sizeof(taskj), cmd_id ? cmd_id : "");
  json_escape_to(statusj, sizeof(statusj), rstatus);
  json_escape_to(raw, sizeof(raw), detail ? detail : "");
  json_escape_to(err, sizeof(err), st == EdrCmdExecOk ? "" : (detail ? detail : response_status_label(st)));
  snprintf(detail_json, sizeof(detail_json),
           "{\"task_id\":%s,\"status\":%s,\"exit_code\":%d,"
           "\"evidence_refs\":[],\"upload_refs\":[],\"artifacts\":%s,\"error\":%s,"
           "\"retryable\":%s,\"raw_detail\":%s}",
           taskj, statusj, exit_code, artifacts && artifacts[0] ? artifacts : "[]", err,
           retryable ? "true" : "false", raw);
  int report_pending = 0;
  if (command_should_report(cmd_id, sm)) {
    int rc = edr_grpc_client_report_command_result(cmd_id, sm, (int)st, exit_code, detail_json);
    if (rc != 0) {
      rc = edr_ingest_http_post_command_result(cmd_id, sm, (int)st, exit_code, detail_json);
    }
    report_pending = (rc != 0);
  }
  edr_command_state_finish(cmd_id, s_active_command_type ? s_active_command_type : "", sm, rstatus,
                           (int)st, exit_code, detail ? detail : "", artifacts ? artifacts : "",
                           report_pending);
}

static void soar_emit(const char *cmd_id, const EdrSoarCommandMeta *sm, EdrCommandExecutionStatus st,
                      int exit_code, const char *detail) {
  soar_emit_ex(cmd_id, sm, st, exit_code, detail, NULL, NULL);
}

int edr_command_dangerous_enabled(void) { return dangerous_enabled(); }

void edr_command_audit_both(const char *cmd_id, const char *msg) {
  audit_both(cmd_id, msg ? msg : "");
}

void edr_command_emit_always(const char *cmd_id, const EdrSoarCommandMeta *sm,
                             EdrCommandExecutionStatus st, int exit_code, const char *detail) {
  audit_both(cmd_id, detail ? detail : "");
  soar_emit(cmd_id, sm, st, exit_code, detail);
}

static int parse_json_string_field(const uint8_t *p, size_t len, const char *key,
                                   char *out, size_t outcap) {
  if (!p || len == 0u || !key || !out || outcap < 2u) {
    return -1;
  }
  char tmp[8192];
  if (len >= sizeof(tmp)) {
    len = sizeof(tmp) - 1u;
  }
  memcpy(tmp, p, len);
  tmp[len] = 0;
  char pat[96];
  snprintf(pat, sizeof(pat), "\"%s\"", key);
  char *keyp = strstr(tmp, pat);
  if (!keyp) {
    return -1;
  }
  char *colon = strchr(keyp + strlen(pat), ':');
  if (!colon) {
    return -1;
  }
  char *q = strchr(colon + 1, '"');
  if (!q) {
    return -1;
  }
  q++;
  size_t o = 0;
  while (*q && *q != '"' && o + 1u < outcap) {
    if (*q == '\\' && q[1]) {
      q++;
      if (*q == 'n' || *q == 'r' || *q == 't') {
        out[o++] = ' ';
      } else {
        out[o++] = *q;
      }
      q++;
      continue;
    }
    out[o++] = *q++;
  }
  out[o] = 0;
  return out[0] ? 0 : -1;
}

static int parse_pid_json(const uint8_t *p, size_t len, long *out_pid) {
  *out_pid = -1;
  if (!p || len == 0u) {
    return -1;
  }
  char tmp[4096];
  if (len >= sizeof(tmp)) {
    len = sizeof(tmp) - 1u;
  }
  memcpy(tmp, p, len);
  tmp[len] = 0;
  char *q = strstr(tmp, "\"pid\"");
  if (!q) {
    q = strstr(tmp, "pid");
  }
  if (!q) {
    return -1;
  }
  char *colon = strchr(q, ':');
  char *start = colon ? colon + 1 : q;
  while (*start && (isspace((unsigned char)*start) || *start == '"' || *start == '\'')) {
    start++;
  }
  *out_pid = strtol(start, NULL, 10);
  if (*out_pid <= 0 || *out_pid > 0x7fffffffL) {
    return -1;
  }
  return 0;
}

/** payload UTF-8 JSON：`{"path":"C:\\file.exe"}` 或含 `"path":"..."` */
static int parse_path_json(const uint8_t *p, size_t len, char *out, size_t outcap) {
  return parse_json_string_field(p, len, "path", out, outcap);
}

static int parse_server_address_json(const uint8_t *p, size_t len, char *out, size_t outcap) {
  if (!p || len == 0u || !out || outcap < 8u) {
    return -1;
  }
  char tmp[2048];
  if (len >= sizeof(tmp)) {
    len = sizeof(tmp) - 1u;
  }
  memcpy(tmp, p, len);
  tmp[len] = 0;
  const char *keys[] = {"\"server_address\"", "\"server_addr\"", "\"address\""};
  for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
    char *k = strstr(tmp, keys[i]);
    if (!k) {
      continue;
    }
    char *colon = strchr(k, ':');
    if (!colon) {
      continue;
    }
    char *q = strchr(colon + 1, '"');
    if (!q) {
      continue;
    }
    q++;
    char *end = strchr(q, '"');
    if (!end) {
      continue;
    }
    size_t n = (size_t)(end - q);
    if (n == 0u || n >= outcap) {
      return -1;
    }
    memcpy(out, q, n);
    out[n] = 0;
    return 0;
  }
  return -1;
}

static int ctx_has(const EdrBehaviorRecord *r, const char *needle) {
  return r && needle && needle[0] && strstr(r->detection_context, needle) != NULL;
}

static int env_truthy_cmd(const char *name) {
  const char *v = getenv(name);
  if (!v || !v[0]) {
    return 0;
  }
  return strcmp(v, "1") == 0 || streq(v, "true") || streq(v, "TRUE") || streq(v, "yes") || streq(v, "on");
}

static int env_falsy_cmd(const char *name) {
  const char *v = getenv(name);
  if (!v || !v[0]) {
    return 0;
  }
  return strcmp(v, "0") == 0 || streq(v, "false") || streq(v, "FALSE") || streq(v, "no") || streq(v, "off");
}

static uint32_t env_u32_cmd(const char *name, uint32_t defv, uint32_t minv, uint32_t maxv) {
  const char *v = getenv(name);
  if (!v || !v[0]) {
    return defv;
  }
  char *end = NULL;
  unsigned long n = strtoul(v, &end, 10);
  if (end == v) {
    return defv;
  }
  if (n < minv) {
    n = minv;
  }
  if (n > maxv) {
    n = maxv;
  }
  return (uint32_t)n;
}

static int auto_recommended_rate_allow(uint32_t pid) {
  static int64_t s_global_last_ms;
  static uint32_t s_last_pid;
  static int64_t s_last_pid_ms;
  static int64_t s_hour_start_ms;
  static uint32_t s_hour_count;
  int64_t now = command_now_ms();
  uint32_t global_cd_s = s_bound_cfg ? s_bound_cfg->forensic_auto.cooldown_s : 30u;
  uint32_t pid_cd_s = s_bound_cfg ? s_bound_cfg->forensic_auto.per_pid_cooldown_s : 300u;
  uint32_t max_per_hour = s_bound_cfg ? s_bound_cfg->forensic_auto.max_per_hour : 20u;
  global_cd_s = env_u32_cmd("EDR_AUTO_RECOMMENDED_FORENSICS_COOLDOWN_S", global_cd_s, 0u, 3600u);
  pid_cd_s = env_u32_cmd("EDR_AUTO_RECOMMENDED_FORENSICS_PER_PID_COOLDOWN_S", pid_cd_s, 0u, 86400u);
  max_per_hour = env_u32_cmd("EDR_AUTO_RECOMMENDED_FORENSICS_MAX_PER_HOUR", max_per_hour, 0u, 10000u);
  if (s_hour_start_ms == 0 || now - s_hour_start_ms >= 3600000LL) {
    s_hour_start_ms = now;
    s_hour_count = 0;
  }
  if (max_per_hour > 0u && s_hour_count >= max_per_hour) {
    return 0;
  }
  if (global_cd_s > 0u && s_global_last_ms > 0 &&
      now - s_global_last_ms < (int64_t)global_cd_s * 1000LL) {
    return 0;
  }
  if (pid != 0u && pid_cd_s > 0u && s_last_pid == pid && s_last_pid_ms > 0 &&
      now - s_last_pid_ms < (int64_t)pid_cd_s * 1000LL) {
    return 0;
  }
  s_global_last_ms = now;
  s_hour_count++;
  if (pid != 0u) {
    s_last_pid = pid;
    s_last_pid_ms = now;
  }
  return 1;
}

static int auto_pmfe_recommended_enabled(void) {
  if (env_falsy_cmd("EDR_AUTO_RECOMMENDED_PMFE")) {
    return 0;
  }
  if (env_truthy_cmd("EDR_AUTO_RECOMMENDED_PMFE")) {
    return 1;
  }
  return edr_pmfe_is_running();
}

int edr_command_dispatch_recommended_forensics(const EdrBehaviorRecord *r) {
  if (!r || !r->detection_context[0] || !ctx_has(r, "\"recommended_forensics\"")) {
    return 0;
  }
  if (env_falsy_cmd("EDR_AUTO_RECOMMENDED_FORENSICS")) {
    return 0;
  }
  if (!env_truthy_cmd("EDR_AUTO_RECOMMENDED_FORENSICS") && s_bound_cfg && !s_bound_cfg->forensic_auto.enabled) {
    return 0;
  }
  if (!dangerous_enabled()) {
    return 0;
  }
  if (!auto_recommended_rate_allow(r->pid)) {
    return 0;
  }
  EdrSoarCommandMeta sm;
  memset(&sm, 0, sizeof(sm));
  snprintf(sm.soar_correlation_id, sizeof(sm.soar_correlation_id), "%s", "agent_auto_recommended_forensics");
  snprintf(sm.playbook_run_id, sizeof(sm.playbook_run_id), "%s", r->event_id[0] ? r->event_id : "local_event");
  sm.issued_at_unix_ms = (int64_t)time(NULL) * 1000LL;

  int dispatched = 0;
  if (r->pid != 0u && ctx_has(r, "pmfe_scan") && auto_pmfe_recommended_enabled()) {
    char id[96];
    char payload[96];
    snprintf(id, sizeof(id), "auto-pmfe-%s", r->event_id[0] ? r->event_id : "event");
    snprintf(payload, sizeof(payload), "{\"pid\":%u,\"reason\":\"recommended_forensics\"}", (unsigned)r->pid);
    edr_command_on_envelope(id, "pmfe_scan", (const uint8_t *)payload, strlen(payload), &sm);
    dispatched++;
  }

  if (ctx_has(r, "process_tree") || ctx_has(r, "timeline_window") || ctx_has(r, "targeted_files") ||
      ctx_has(r, "webshell_files") || ctx_has(r, "single_process_minidump")) {
    char id[96];
    char payload[4096];
    char ev[192];
    char pname[256];
    char exe[512];
    char cmd[768];
    char file[512];
    char rip[160];
    char rurl[512];
    json_escape_to(ev, sizeof(ev), r->event_id);
    json_escape_to(pname, sizeof(pname), r->process_name);
    json_escape_to(exe, sizeof(exe), r->exe_path);
    json_escape_to(cmd, sizeof(cmd), r->cmdline);
    json_escape_to(file, sizeof(file), r->file_path);
    json_escape_to(rip, sizeof(rip), r->net_dst);
    json_escape_to(rurl, sizeof(rurl), r->dns_query);
    snprintf(id, sizeof(id), "auto-forensic-%s", r->event_id[0] ? r->event_id : "event");
    snprintf(payload, sizeof(payload),
             "{"
             "\"pid\":%u,\"ppid\":%u,\"event_id\":%s,\"process_name\":%s,"
             "\"exe_path\":%s,\"cmdline\":%s,\"file_path\":%s,"
             "\"remote_ip\":%s,\"remote_url\":%s,"
             "\"recommended_from_detection_context\":true,"
             "\"recommended_forensics\":\"%s%s%s%s%s\""
             "}",
             (unsigned)r->pid, (unsigned)r->ppid, ev, pname,
             exe, cmd, file, rip, rurl,
             ctx_has(r, "process_tree") ? "process_tree," : "",
             ctx_has(r, "timeline_window") ? "timeline_window," : "",
             ctx_has(r, "targeted_files") || ctx_has(r, "webshell_files") ? "targeted_files," : "",
             ctx_has(r, "ioc_lookup") ? "ioc_lookup," : "",
             ctx_has(r, "single_process_minidump") ? "single_process_minidump_if_needed" : "");
    edr_command_on_envelope(id, "forensic", (const uint8_t *)payload, strlen(payload), &sm);
    dispatched++;
  }
  return dispatched;
}

static void do_ave_status(const char *cmd_id, const EdrSoarCommandMeta *sm) {
  int mf = 0, nf = 0, rd = 0;
  edr_ave_get_scan_counts(&mf, &nf, &rd);
  char detail[256];
  snprintf(detail, sizeof(detail), "model_files=%d non_dir_files=%d ready=%d", mf, nf, rd);
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, detail);
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

static const char *ave_verdict_tag(EDRVerdict v) {
  switch (v) {
    case VERDICT_CLEAN:
      return "CLEAN";
    case VERDICT_SUSPICIOUS:
      return "SUSPICIOUS";
    case VERDICT_MALWARE:
      return "MALWARE";
    case VERDICT_TRUSTED_CERT:
      return "TRUSTED_CERT";
    case VERDICT_WHITELISTED:
      return "WHITELISTED";
    case VERDICT_IOC_CONFIRMED:
      return "IOC_CONFIRMED";
    case VERDICT_CERT_REVOKED:
      return "CERT_REVOKED";
    case VERDICT_CERT_TAMPERED:
      return "CERT_TAMPERED";
    case VERDICT_TIMEOUT:
      return "TIMEOUT";
    case VERDICT_ERROR:
      return "ERROR";
    default:
      return "UNKNOWN";
  }
}

static void do_ave_fingerprint(const char *cmd_id, const uint8_t *pl, size_t len,
                                const EdrSoarCommandMeta *sm) {
  char path[4096];
  if (parse_path_json(pl, len, path, sizeof(path)) != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "ave_fingerprint: payload 需 JSON {\"path\":\"...\"}");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 10, "invalid path payload");
    return;
  }
  char hex[32];
  if (edr_ave_file_fingerprint(path, hex, sizeof(hex)) != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "ave_fingerprint: 读文件或指纹失败");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 11, "fingerprint failed");
    return;
  }
  char detail[220];
  snprintf(detail, sizeof(detail), "fp=%s", hex);
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, detail);
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

static void do_ave_infer(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!s_bound_cfg) {
    s_exec_fail++;
    audit_both(cmd_id, "ave_infer: 未绑定配置（内部错误）");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 20, "config not bound");
    return;
  }
  char path[4096];
  if (parse_path_json(pl, len, path, sizeof(path)) != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "ave_infer: payload 需 JSON {\"path\":\"...\"}");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 10, "invalid path payload");
    return;
  }
  AVEScanResult res;
  memset(&res, 0, sizeof(res));
  int ar = AVE_ScanFile(path, &res);
  if (ar == AVE_ERR_NOT_INITIALIZED) {
    s_exec_fail++;
    audit_both(cmd_id, "ave_infer: AVE 未初始化（需先 edr_agent_init）");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 22, "ave not initialized");
    return;
  }
  if (ar == AVE_ERR_NOT_IMPL) {
    s_exec_fail++;
    audit_both(cmd_id, "ave_infer: 推理后端未实现（可设 EDR_AVE_INFER_DRY_RUN=1）");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, (int)EDR_ERR_NOT_IMPL, "infer not implemented");
    return;
  }
  if (ar == AVE_ERR_FILE_NOT_FOUND) {
    s_exec_fail++;
    audit_both(cmd_id, "ave_infer: 文件不存在");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 23, "file not found");
    return;
  }
  if (ar == AVE_ERR_ACCESS_DENIED) {
    s_exec_fail++;
    audit_both(cmd_id, "ave_infer: 无读取权限");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 24, "access denied");
    return;
  }
  if (ar != AVE_OK) {
    s_exec_fail++;
    audit_both(cmd_id, "ave_infer: 扫描失败");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 21, "scan error");
    return;
  }

  char detail[512];
  snprintf(detail, sizeof(detail),
           "final=%s raw=%s final_conf=%.4f raw_conf=%.4f layer=%.3s sha256=%s dur_ms=%lld",
           ave_verdict_tag(res.final_verdict), ave_verdict_tag(res.raw_ai_verdict),
           (double)res.final_confidence, (double)res.raw_confidence, res.verification_layer, res.sha256,
           (long long)res.scan_duration_ms);
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, detail);
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

static void do_self_protect_status(const char *cmd_id, const EdrSoarCommandMeta *sm) {
  char detail[512];
  edr_self_protect_format_status(detail, sizeof(detail));
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, detail);
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

static void do_update_server_address(const char *cmd_id, const uint8_t *pl, size_t len,
                                     const EdrSoarCommandMeta *sm) {
  char addr[256];
  if (parse_server_address_json(pl, len, addr, sizeof(addr)) != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "update_server_address: payload 需 JSON {\"server_address\":\"host:port\"}");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 12, "invalid server address payload");
    return;
  }
  if (strstr(addr, "://") || strchr(addr, '/')) {
    s_exec_fail++;
    audit_both(cmd_id, "update_server_address: 仅支持 host:port");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 13, "server address must be host:port");
    return;
  }
  int rc = edr_grpc_client_reconnect_to_target(addr);
  if (rc != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "update_server_address: gRPC 重连失败");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 14, "grpc reconnect failed");
    return;
  }
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, "update_server_address: gRPC 目标已切换");
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, "grpc target switched");
}

static void do_kill(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject kill: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  long pid;
  if (parse_pid_json(pl, len, &pid) != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "kill: payload 无有效 pid（JSON 示例 {\"pid\":1234}）");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "invalid pid payload");
    return;
  }
  if (!kill_pid_allowed(pid)) {
    s_rejected++;
    audit_both(cmd_id, "kill: pid 不在 EDR_CMD_KILL_ALLOWLIST 中");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 7, "pid not in allowlist");
    return;
  }
#ifdef _WIN32
  if ((DWORD)pid == GetCurrentProcessId()) {
    s_rejected++;
    audit_both(cmd_id, "kill: 拒绝结束本进程");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 5, "refuse self");
    return;
  }
  {
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid);
    if (!h) {
      s_exec_fail++;
      audit_both(cmd_id, "kill: OpenProcess 失败");
      soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "OpenProcess failed");
      return;
    }
    BOOL ok = TerminateProcess(h, 1);
    CloseHandle(h);
    if (ok) {
      s_exec_ok++;
      audit_both(cmd_id, "kill: TerminateProcess 已执行");
      soar_emit(cmd_id, sm, EdrCmdExecOk, 0, "TerminateProcess ok");
    } else {
      s_exec_fail++;
      audit_both(cmd_id, "kill: TerminateProcess 失败");
      soar_emit(cmd_id, sm, EdrCmdExecFailed, 4, "TerminateProcess failed");
    }
  }
#else
  if (pid == (long)getpid()) {
    s_rejected++;
    audit_both(cmd_id, "kill: 拒绝结束本进程");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 5, "refuse self");
    return;
  }
  if (kill((pid_t)pid, SIGTERM) == 0) {
    s_exec_ok++;
    audit_both(cmd_id, "kill: 已发送 SIGTERM");
    soar_emit(cmd_id, sm, EdrCmdExecOk, 0, "SIGTERM sent");
  } else {
    s_exec_fail++;
    audit_both(cmd_id, "kill: kill() 失败");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 6, "kill() failed");
  }
#endif
}

static void isolate_stamp_path(char *path, size_t cap) {
  const char *stamp = getenv("EDR_ISOLATE_STAMP_PATH");
  if (stamp && stamp[0]) {
    snprintf(path, cap, "%s", stamp);
  } else {
#ifdef _WIN32
    const char *tmp = getenv("TEMP");
    if (!tmp || !tmp[0]) {
      tmp = getenv("TMP");
    }
    if (!tmp || !tmp[0]) {
      tmp = ".";
    }
    snprintf(path, cap, "%s\\edr_isolated.state", tmp);
#else
    snprintf(path, cap, "%s", "/tmp/edr_isolated.state");
#endif
  }
}

static void do_isolate(const char *cmd_id, const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject isolate: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char path[512];
  isolate_stamp_path(path, sizeof(path));
  FILE *f = fopen(path, "w");
  if (f) {
    fprintf(f, "isolated=1\ncommand_id=%s\nupdated_unix_ms=%lld\n", cmd_id ? cmd_id : "",
            (long long)command_now_ms());
    fclose(f);
    s_exec_ok++;
    audit_both(cmd_id, "isolate: 已写标记文件");
  } else {
    s_exec_fail++;
    audit_both(cmd_id, "isolate: 写文件失败");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "stamp write failed");
    return;
  }
  const char *hook = getenv("EDR_ISOLATE_HOOK");
  if (hook && hook[0]) {
#ifdef _WIN32
    (void)_putenv_s("EDR_CMD_ID", cmd_id ? cmd_id : "");
#else
    (void)setenv("EDR_CMD_ID", cmd_id ? cmd_id : "", 1);
#endif
    int r = system(hook);
    if (r == 0) {
      audit_both(cmd_id, "isolate: EDR_ISOLATE_HOOK 执行成功");
    } else {
      audit_both(cmd_id, "isolate: EDR_ISOLATE_HOOK 返回非零");
      (void)remove(path);
      soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "isolate hook non-zero");
      return;
    }
  }
  {
    char pathj[700], detail[1024];
    json_escape_to(pathj, sizeof(pathj), path);
    snprintf(detail, sizeof(detail), "{\"status\":\"isolated\",\"stamp_path\":%s,\"hook\":\"%s\"}",
             pathj, (hook && hook[0]) ? "executed" : "not_configured");
    soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
  }
}

static void do_restore_host(const char *cmd_id, const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject restore_host: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char path[512];
  isolate_stamp_path(path, sizeof(path));
  const char *hook = getenv("EDR_RESTORE_HOOK");
  if (!hook || !hook[0]) {
    hook = getenv("EDR_ISOLATE_RESTORE_HOOK");
  }
  if (hook && hook[0]) {
#ifdef _WIN32
    (void)_putenv_s("EDR_CMD_ID", cmd_id ? cmd_id : "");
#else
    (void)setenv("EDR_CMD_ID", cmd_id ? cmd_id : "", 1);
#endif
    int r = system(hook);
    if (r != 0) {
      s_exec_fail++;
      audit_both(cmd_id, "restore_host: restore hook non-zero");
      soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "restore hook non-zero");
      return;
    }
  }
  if (remove(path) != 0 && errno != ENOENT) {
    s_exec_fail++;
    audit_both(cmd_id, "restore_host: stamp remove failed");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "stamp remove failed");
    return;
  }
  s_handled++;
  s_exec_ok++;
  {
    char pathj[700], detail[1024];
    json_escape_to(pathj, sizeof(pathj), path);
    snprintf(detail, sizeof(detail), "{\"status\":\"restored\",\"stamp_path\":%s,\"hook\":\"%s\"}",
             pathj, (hook && hook[0]) ? "executed" : "not_configured");
    audit_both(cmd_id, "restore_host: ok");
    soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
  }
}

static void do_isolate_status(const char *cmd_id, const EdrSoarCommandMeta *sm) {
  char path[512];
  isolate_stamp_path(path, sizeof(path));
  int exists = 0;
  FILE *f = fopen(path, "r");
  if (f) {
    exists = 1;
    fclose(f);
  }
  char pathj[700], detail[1024];
  json_escape_to(pathj, sizeof(pathj), path);
  snprintf(detail, sizeof(detail), "{\"isolated\":%s,\"stamp_path\":%s}", exists ? "true" : "false", pathj);
  s_handled++;
  s_exec_ok++;
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

void edr_isolate_auto_from_shellcode_alarm(void) {
#if !defined(_WIN32)
  return;
#else
  int want = 0;
  const char *eo = getenv("EDR_SHELLCODE_AUTO_ISOLATE");
  if (eo && eo[0] == '1') {
    want = 1;
  } else if (s_bound_cfg && s_bound_cfg->shellcode_detector.auto_isolate_execute) {
    want = 1;
  }
  if (!want) {
    return;
  }
  if (!dangerous_enabled()) {
    return;
  }
  static volatile LONG s_shellcode_auto_iso_once;
  if (InterlockedCompareExchange(&s_shellcode_auto_iso_once, 1, 0) != 0) {
    return;
  }
  do_isolate("auto-shellcode", NULL);
#endif
}

static int forensic_copy_one_file(const char *src, const char *dst) {
#ifdef _WIN32
  return CopyFileA(src, dst, FALSE) ? 0 : -1;
#else
  int fi = open(src, O_RDONLY);
  if (fi < 0) {
    return -1;
  }
  int fo = open(dst, O_CREAT | O_WRONLY | O_TRUNC, 0644);
  if (fo < 0) {
    close(fi);
    return -1;
  }
  char buf[65536];
  ssize_t nr;
  while ((nr = read(fi, buf, sizeof(buf))) > 0) {
    ssize_t off = 0;
    while (off < nr) {
      ssize_t nw = write(fo, buf + off, (size_t)(nr - off));
      if (nw <= 0) {
        close(fi);
        close(fo);
        return -1;
      }
      off += nw;
    }
  }
  close(fi);
  close(fo);
  return nr < 0 ? -1 : 0;
#endif
}

static int mkdir_one_quiet(const char *path) {
  if (!path || !path[0]) {
    return -1;
  }
#ifdef _WIN32
  if (CreateDirectoryA(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
    return 0;
  }
  return -1;
#else
  if (mkdir(path, 0755) == 0 || errno == EEXIST) {
    return 0;
  }
  return -1;
#endif
}

static int mkdir_p_quiet(char *path) {
  if (!path || !path[0]) {
    return -1;
  }
  char tmp[700];
  snprintf(tmp, sizeof(tmp), "%s", path);
  size_t n = strlen(tmp);
  while (n > 1u && (tmp[n - 1u] == '/' || tmp[n - 1u] == '\\')) {
    tmp[--n] = '\0';
  }
  for (char *p = tmp + 1; *p; p++) {
    if (*p == '/' || *p == '\\') {
      char save = *p;
      *p = '\0';
#ifdef _WIN32
      if (!(strlen(tmp) == 2u && tmp[1] == ':')) {
        (void)mkdir_one_quiet(tmp);
      }
#else
      (void)mkdir_one_quiet(tmp);
#endif
      *p = save;
    }
  }
  return mkdir_one_quiet(tmp);
}

static const char *path_basename_c(const char *path) {
  const char *b = path && path[0] ? path : "file";
  for (const char *p = b; *p; p++) {
    if (*p == '/' || *p == '\\') {
      b = p + 1;
    }
  }
  return b && b[0] ? b : "file";
}

static void sanitize_component(char *s) {
  if (!s) {
    return;
  }
  for (; *s; s++) {
    unsigned char c = (unsigned char)*s;
    if (!isalnum(c) && *s != '-' && *s != '_' && *s != '.') {
      *s = '_';
    }
  }
}

static int file_exists_c(const char *path) {
  if (!path || !path[0]) {
    return 0;
  }
#ifdef _WIN32
  DWORD a = GetFileAttributesA(path);
  return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
#else
  struct stat st;
  return stat(path, &st) == 0 && S_ISREG(st.st_mode);
#endif
}

static int file_size_mtime(const char *path, unsigned long long *size_out, long long *mtime_out) {
  if (!path || !path[0]) {
    return -1;
  }
#ifdef _WIN32
  WIN32_FILE_ATTRIBUTE_DATA d;
  if (!GetFileAttributesExA(path, GetFileExInfoStandard, &d) || (d.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
    return -1;
  }
  ULARGE_INTEGER sz;
  sz.HighPart = d.nFileSizeHigh;
  sz.LowPart = d.nFileSizeLow;
  if (size_out) {
    *size_out = sz.QuadPart;
  }
  if (mtime_out) {
    ULARGE_INTEGER ft;
    ft.HighPart = d.ftLastWriteTime.dwHighDateTime;
    ft.LowPart = d.ftLastWriteTime.dwLowDateTime;
    *mtime_out = (long long)((ft.QuadPart / 10000000ULL) - 11644473600ULL);
  }
  return 0;
#else
  struct stat st;
  if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
    return -1;
  }
  if (size_out) {
    *size_out = (unsigned long long)st.st_size;
  }
  if (mtime_out) {
    *mtime_out = (long long)st.st_mtime;
  }
  return 0;
#endif
}

static int file_sha256_hex(const char *path, char out65[65]) {
  FILE *f = fopen(path, "rb");
  if (!f) {
    if (out65) {
      out65[0] = '\0';
    }
    return -1;
  }
  EdrSha256Ctx ctx;
  uint8_t digest[EDR_SHA256_DIGEST_LEN];
  uint8_t buf[65536];
  edr_sha256_init(&ctx);
  for (;;) {
    size_t n = fread(buf, 1, sizeof(buf), f);
    if (n > 0u) {
      edr_sha256_update(&ctx, buf, n);
    }
    if (n < sizeof(buf)) {
      if (ferror(f)) {
        fclose(f);
        out65[0] = '\0';
        return -1;
      }
      break;
    }
  }
  fclose(f);
  edr_sha256_final(&ctx, digest);
  static const char *hex = "0123456789abcdef";
  for (size_t i = 0; i < EDR_SHA256_DIGEST_LEN; i++) {
    out65[i * 2u] = hex[(digest[i] >> 4) & 0x0f];
    out65[i * 2u + 1u] = hex[digest[i] & 0x0f];
  }
  out65[64] = '\0';
  return 0;
}

static void quarantine_base_dir(char *out, size_t cap) {
  const char *e = getenv("EDR_QUARANTINE_DIR");
  if (e && e[0]) {
    snprintf(out, cap, "%s", e);
    return;
  }
#ifdef _WIN32
  snprintf(out, cap, "%s", "C:\\Program Files\\EDR Agent\\quarantine");
#else
  snprintf(out, cap, "%s", "/tmp/edr_quarantine");
#endif
}

static int move_file_cross_volume(const char *src, const char *dst) {
#ifdef _WIN32
  return MoveFileExA(src, dst, MOVEFILE_COPY_ALLOWED) ? 0 : -1;
#else
  if (rename(src, dst) == 0) {
    return 0;
  }
  if (errno == EXDEV && forensic_copy_one_file(src, dst) == 0 && remove(src) == 0) {
    return 0;
  }
  return -1;
#endif
}

static void do_file_stat(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  char path[1024];
  if (parse_path_json(pl, len, path, sizeof(path)) != 0) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "invalid path payload");
    return;
  }
  unsigned long long sz = 0;
  long long mt = 0;
  char sha[65];
  sha[0] = '\0';
  if (file_size_mtime(path, &sz, &mt) != 0) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "file not found or not regular");
    return;
  }
  (void)file_sha256_hex(path, sha);
  char detail[1800];
  snprintf(detail, sizeof(detail),
           "{\"path\":\"%s\",\"size\":%llu,\"mtime\":%lld,\"sha256\":\"%s\"}",
           path, sz, mt, sha);
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, "rtr_file_stat: ok");
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

static int parse_int_json_default(const uint8_t *p, size_t len, const char *key, int defv) {
  if (!p || len == 0u || !key) {
    return defv;
  }
  char tmp[4096];
  if (len >= sizeof(tmp)) {
    len = sizeof(tmp) - 1u;
  }
  memcpy(tmp, p, len);
  tmp[len] = 0;
  char pat[96];
  snprintf(pat, sizeof(pat), "\"%s\"", key);
  char *k = strstr(tmp, pat);
  if (!k) {
    return defv;
  }
  char *colon = strchr(k + strlen(pat), ':');
  if (!colon) {
    return defv;
  }
  char *v = colon + 1;
  while (*v && isspace((unsigned char)*v)) {
    v++;
  }
  return (int)strtol(v, NULL, 10);
}

static int ascii_case_equal(const char *a, const char *b) {
  if (!a || !b) {
    return 0;
  }
  while (*a && *b) {
    if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
      return 0;
    }
    a++;
    b++;
  }
  return *a == '\0' && *b == '\0';
}

static int env_int_default(const char *name, int defv) {
  const char *e = getenv(name);
  if (!e || !e[0]) {
    return defv;
  }
  char *end = NULL;
  long v = strtol(e, &end, 10);
  if (end == e) {
    return defv;
  }
  if (v < 1) {
    return 1;
  }
  if (v > 300) {
    return 300;
  }
  return (int)v;
}

static void rtr_shell_normalize_token(const char *raw, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  if (!raw) {
    return;
  }
  while (*raw && isspace((unsigned char)*raw)) {
    raw++;
  }
  char tmp[256];
  size_t n = 0;
  while (raw[n] && !isspace((unsigned char)raw[n]) && raw[n] != ',' && raw[n] != ';' && n + 1u < sizeof(tmp)) {
    tmp[n] = raw[n];
    n++;
  }
  tmp[n] = '\0';
  while (n > 0u && isspace((unsigned char)tmp[n - 1u])) {
    tmp[--n] = '\0';
  }
  if (n >= 2u && ((tmp[0] == '"' && tmp[n - 1u] == '"') || (tmp[0] == '\'' && tmp[n - 1u] == '\''))) {
    memmove(tmp, tmp + 1u, n - 2u);
    tmp[n - 2u] = '\0';
  }
  const char *base = tmp;
  for (const char *p = tmp; *p; p++) {
    if (*p == '/' || *p == '\\') {
      base = p + 1;
    }
  }
  size_t o = 0;
  for (const char *p = base; *p && o + 1u < cap; p++) {
    out[o++] = (char)tolower((unsigned char)*p);
  }
  out[o] = '\0';
  size_t olen = strlen(out);
  if (olen > 4u && strcmp(out + olen - 4u, ".exe") == 0) {
    out[olen - 4u] = '\0';
  } else if (olen > 4u && strcmp(out + olen - 4u, ".com") == 0) {
    out[olen - 4u] = '\0';
  }
}

static void rtr_shell_first_token(const char *command, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  if (!command) {
    return;
  }
  while (*command && isspace((unsigned char)*command)) {
    command++;
  }
  char raw[256];
  size_t n = 0;
  if (*command == '"' || *command == '\'') {
    char quote = *command++;
    while (*command && *command != quote && n + 1u < sizeof(raw)) {
      raw[n++] = *command++;
    }
  } else {
    while (*command && !isspace((unsigned char)*command) && n + 1u < sizeof(raw)) {
      raw[n++] = *command++;
    }
  }
  raw[n] = '\0';
  rtr_shell_normalize_token(raw, out, cap);
}

static int rtr_shell_has_control_operator(const char *command) {
  if (!command) {
    return 1;
  }
  for (const char *p = command; *p; p++) {
    if (*p == '\n' || *p == '\r' || *p == ';' || *p == '|' || *p == '`' || *p == '<' || *p == '>') {
      return 1;
    }
    if (*p == '&') {
      return 1;
    }
    if (*p == '$' && p[1] == '(') {
      return 1;
    }
  }
  return 0;
}

static void lower_copy(char *dst, size_t cap, const char *src) {
  if (!dst || cap == 0u) {
    return;
  }
  size_t i = 0;
  if (!src) {
    src = "";
  }
  for (; src[i] && i + 1u < cap; i++) {
    dst[i] = (char)tolower((unsigned char)src[i]);
  }
  dst[i] = '\0';
}

static int rtr_shell_matches_block_term(const char *lower_cmd, const char *term) {
  if (!lower_cmd || !term || !term[0]) {
    return 0;
  }
  char padded[2300];
  snprintf(padded, sizeof(padded), " %s ", lower_cmd);
  return strstr(padded, term) != NULL || strstr(lower_cmd, term) != NULL;
}

static int rtr_shell_blocked(const char *command, char *reason, size_t reason_cap) {
  char lower[2200];
  lower_copy(lower, sizeof(lower), command);
  static const char *const defaults[] = {
      " rm ", " del ", " erase ", " rmdir ", " rd ", " format ", " fdisk ",
      " shutdown", " reboot", " halt", " poweroff", " logoff", " taskkill",
      " pkill ", " kill ", " reg delete", " reg add", " reg import", " sc delete",
      " net user", " net localgroup", " wevtutil cl", " vssadmin delete", " cipher /w",
      " bcdedit", "-encodedcommand", " encodedcommand", " frombase64string",
      " invoke-expression", " iex ", " downloadstring", " downloadfile", NULL};
  for (int i = 0; defaults[i]; i++) {
    if (rtr_shell_matches_block_term(lower, defaults[i])) {
      snprintf(reason, reason_cap, "blocked term: %s", defaults[i]);
      return 1;
    }
  }
  const char *extra = getenv("EDR_RTR_SHELL_BLOCKLIST");
  if (!extra || !extra[0]) {
    return 0;
  }
  char list[2048];
  snprintf(list, sizeof(list), "%s", extra);
  char *p = list;
  while (p && *p) {
    char *sep = strpbrk(p, ",;");
    if (sep) {
      *sep++ = '\0';
    }
    while (*p && isspace((unsigned char)*p)) {
      p++;
    }
    char term[256];
    lower_copy(term, sizeof(term), p);
    size_t n = strlen(term);
    while (n > 0u && isspace((unsigned char)term[n - 1u])) {
      term[--n] = '\0';
    }
    if (term[0] && rtr_shell_matches_block_term(lower, term)) {
      snprintf(reason, reason_cap, "blocked by EDR_RTR_SHELL_BLOCKLIST: %s", term);
      return 1;
    }
    p = sep;
  }
  return 0;
}

static int rtr_shell_token_allowed(const char *token, char *matched, size_t matched_cap,
                                   char *reason, size_t reason_cap) {
  if (matched && matched_cap > 0u) {
    matched[0] = '\0';
  }
  if (!token || !token[0]) {
    snprintf(reason, reason_cap, "missing executable token");
    return 0;
  }
  const char *list_src = NULL;
  const char *source = "policy";
  if (s_bound_cfg && s_bound_cfg->command.rtr_shell_allowlist[0]) {
    list_src = s_bound_cfg->command.rtr_shell_allowlist;
  }
  if (!list_src || !list_src[0]) {
    list_src = getenv("EDR_RTR_SHELL_ALLOWLIST");
    source = "EDR_RTR_SHELL_ALLOWLIST";
  }
  if (!list_src || !list_src[0]) {
    list_src = getenv("EDR_SHELL_ALLOWLIST");
    source = "EDR_SHELL_ALLOWLIST";
  }
  if (!list_src || !list_src[0]) {
    snprintf(reason, reason_cap, "rtr_shell allowlist not configured");
    return 0;
  }
  char list_buf[2048];
  snprintf(list_buf, sizeof(list_buf), "%s", list_src);
  char *p = list_buf;
  while (p && *p) {
    char *sep = strpbrk(p, ",;");
    if (sep) {
      *sep++ = '\0';
    }
    while (*p && isspace((unsigned char)*p)) {
      p++;
    }
    char item[128];
    rtr_shell_normalize_token(p, item, sizeof(item));
    if (item[0] && ascii_case_equal(token, item)) {
      if (matched && matched_cap > 0u) {
        snprintf(matched, matched_cap, "%s", item);
      }
      return 1;
    }
    p = sep;
  }
  snprintf(reason, reason_cap, "command token not in allowlist (%s): %s", source, token);
  return 0;
}

#ifdef _WIN32
static void rtr_shell_output_to_utf8(char *s, size_t cap) {
  if (!s || !s[0] || cap == 0u) {
    return;
  }
  int wlen = MultiByteToWideChar(CP_ACP, 0, s, -1, NULL, 0);
  if (wlen <= 0) {
    return;
  }
  wchar_t *wbuf = (wchar_t *)malloc((size_t)wlen * sizeof(wchar_t));
  if (!wbuf) {
    return;
  }
  if (MultiByteToWideChar(CP_ACP, 0, s, -1, wbuf, wlen) > 0) {
    int u8len = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, NULL, 0, NULL, NULL);
    if (u8len > 0 && (size_t)u8len < cap) {
      (void)WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, s, u8len, NULL, NULL);
    }
  }
  free(wbuf);
}
#endif

static void do_rtr_shell(const char *cmd_id, const uint8_t *pl, size_t len,
                         const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject rtr_shell: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit_ex(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled", "denied", NULL);
    return;
  }
  char command[2048];
  if (parse_json_string_field(pl, len, "command", command, sizeof(command)) != 0 &&
      parse_json_string_field(pl, len, "cmd", command, sizeof(command)) != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "rtr_shell: payload 缺少 command");
    soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, 2, "missing command", "failed", NULL);
    return;
  }
  if (rtr_shell_has_control_operator(command)) {
    s_rejected++;
    audit_both(cmd_id, "rtr_shell: rejected control operator");
    soar_emit_ex(cmd_id, sm, EdrCmdExecRejected, 3, "control operators are not allowed", "denied", NULL);
    return;
  }
  char token[128];
  char allow_item[128];
  char reason[256];
  rtr_shell_first_token(command, token, sizeof(token));
  reason[0] = '\0';
  if (!rtr_shell_token_allowed(token, allow_item, sizeof(allow_item), reason, sizeof(reason))) {
    s_rejected++;
    audit_both(cmd_id, reason[0] ? reason : "rtr_shell: command not allowlisted");
    soar_emit_ex(cmd_id, sm, EdrCmdExecRejected, 4,
                 reason[0] ? reason : "command not allowlisted", "denied", NULL);
    return;
  }
  reason[0] = '\0';
  if (rtr_shell_blocked(command, reason, sizeof(reason))) {
    s_rejected++;
    audit_both(cmd_id, reason[0] ? reason : "rtr_shell: blocked command");
    soar_emit_ex(cmd_id, sm, EdrCmdExecRejected, 5,
                 reason[0] ? reason : "command blocked", "denied", NULL);
    return;
  }
  int timeout_sec = parse_int_json_default(pl, len, "timeout_sec", 30);
  timeout_sec = parse_int_json_default(pl, len, "timeout_s", timeout_sec);
  int max_timeout = s_bound_cfg && s_bound_cfg->command.rtr_shell_max_timeout_sec > 0u
                        ? (int)s_bound_cfg->command.rtr_shell_max_timeout_sec
                        : env_int_default("EDR_RTR_SHELL_MAX_TIMEOUT_SEC", 60);
  if (timeout_sec <= 0) {
    timeout_sec = 30;
  }
  if (timeout_sec > max_timeout) {
    timeout_sec = max_timeout;
  }
  if (sm && sm->issued_at_unix_ms > 0 && sm->deadline_ms > 0u) {
    int64_t remaining_ms = sm->issued_at_unix_ms + (int64_t)sm->deadline_ms - command_now_ms();
    if (remaining_ms <= 0) {
      s_rejected++;
      audit_both(cmd_id, "rtr_shell: deadline expired before execution");
      soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, 124, "deadline expired before execution", "timeout", NULL);
      return;
    }
    int remaining_sec = (int)((remaining_ms + 999) / 1000);
    if (remaining_sec > 0 && timeout_sec > remaining_sec) {
      timeout_sec = remaining_sec;
    }
  }
  char audit_msg[2400];
  snprintf(audit_msg, sizeof(audit_msg), "rtr_shell: start token=%s timeout_sec=%d command=%.2000s",
           token, timeout_sec, command);
  audit_both(cmd_id, audit_msg);

  char out[8192];
  int exit_code = 0;
  int rc = edr_shell_exec(command, timeout_sec, out, sizeof(out), &exit_code);
#ifdef _WIN32
  rtr_shell_output_to_utf8(out, sizeof(out));
#endif
  char commandj[4300], tokenj[300], outputj[10000], detail[16000];
  json_escape_to(commandj, sizeof(commandj), command);
  json_escape_to(tokenj, sizeof(tokenj), token);
  json_escape_to(outputj, sizeof(outputj), out);
  snprintf(detail, sizeof(detail),
           "{\"command\":%s,\"allowed_token\":%s,\"timeout_sec\":%d,"
           "\"exit_code\":%d,\"output_truncated\":%s,\"output\":%s}",
           commandj, tokenj, timeout_sec, exit_code,
           strlen(out) + 1u >= sizeof(out) ? "true" : "false", outputj);
  s_handled++;
  if (rc != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "rtr_shell: exec failed");
    soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, exit_code ? exit_code : 6, detail, "failed", NULL);
    return;
  }
  if (exit_code == 124) {
    s_exec_fail++;
    audit_both(cmd_id, "rtr_shell: timeout");
    soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, 124, detail, "timeout", NULL);
    return;
  }
  if (exit_code != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "rtr_shell: command returned non-zero");
    soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, exit_code, detail, "failed", NULL);
    return;
  }
  s_exec_ok++;
  audit_both(cmd_id, "rtr_shell: ok");
  soar_emit_ex(cmd_id, sm, EdrCmdExecOk, 0, detail, "ok", NULL);
}

static void shell_stream_output_cb(const char *sid, const char *data, size_t len,
                                   int exit_code, bool closed, void *user) {
  (void)user;
  char detail[4096];
  if (closed && !data) {
    snprintf(detail, sizeof(detail), "shell session %s closed, exit=%d", sid ? sid : "", exit_code);
  } else if (data && len > 0u) {
    size_t cp = len < sizeof(detail) - 1u ? len : sizeof(detail) - 1u;
    memcpy(detail, data, cp);
    detail[cp] = '\0';
  } else {
    return;
  }
  EdrSoarCommandMeta dummy;
  memset(&dummy, 0, sizeof(dummy));
  if (sid) {
    snprintf(dummy.soar_correlation_id, sizeof(dummy.soar_correlation_id), "%s", sid);
  }
  soar_emit(sid ? sid : "shell_session", &dummy, EdrCmdExecOk, exit_code, detail);
}

static void ensure_shell_session_initialized(void) {
  static int initialized = 0;
  if (!initialized) {
    edr_shell_session_init(EDR_SS_MAX_SESSIONS, 600u, EDR_SS_BUF_KB, shell_stream_output_cb, NULL);
    initialized = 1;
  }
}

static void do_shell_open(const char *cmd_id, const uint8_t *pl, size_t len,
                          const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "shell_open: rejected (allow_dangerous=false)");
    soar_emit_ex(cmd_id, sm, EdrCmdExecRejected, 1,
                 "interactive shell disabled: enable TOML [command] allow_dangerous=true via Agent policy",
                 "denied", NULL);
    return;
  }
  char shell_type[128];
#ifdef _WIN32
  snprintf(shell_type, sizeof(shell_type), "%s", "cmd.exe /Q /K chcp 65001 > nul");
#else
  snprintf(shell_type, sizeof(shell_type), "%s", "/bin/sh");
#endif
  if (pl && len > 0u && len < sizeof(shell_type) - 1u && pl[0] != '{') {
    memcpy(shell_type, pl, len);
    shell_type[len] = '\0';
  }
  ensure_shell_session_initialized();
  int rc = edr_shell_session_open(cmd_id, shell_type);
  if (rc != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "shell_open: failed");
    soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, rc, "shell_open failed", "failed", NULL);
    return;
  }
  s_handled++;
  s_exec_ok++;
  char detail[180];
  snprintf(detail, sizeof(detail), "shell session opened: %s", shell_type);
  audit_both(cmd_id, "shell_open: ok");
  soar_emit_ex(cmd_id, sm, EdrCmdExecOk, 0, detail, "ok", NULL);
}

static void do_shell_input(const char *cmd_id, const uint8_t *pl, size_t len,
                           const EdrSoarCommandMeta *sm) {
  char session_id[EDR_SS_ID_LEN];
  char input[4096];
  session_id[0] = '\0';
  input[0] = '\0';
  (void)edr_parse_json_string(pl, len, "session_id", session_id, sizeof(session_id));
  (void)edr_parse_json_string(pl, len, "input", input, sizeof(input));
  if (!session_id[0] || !input[0]) {
    s_exec_fail++;
    audit_both(cmd_id, "shell_input: missing session_id or input");
    soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, 1, "missing session_id or input", "failed", NULL);
    return;
  }
  size_t ilen = strlen(input);
#ifdef _WIN32
  if (ilen + 2u <= sizeof(input)) {
    input[ilen++] = '\r';
    input[ilen++] = '\n';
  }
#else
  if (ilen + 1u <= sizeof(input)) {
    input[ilen++] = '\n';
  }
#endif
  int rc = edr_shell_session_input(session_id, input, ilen);
  if (rc != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "shell_input: write failed");
    soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, rc,
                 "shell_input write failed: shell session not open or stdin unavailable",
                 "failed", NULL);
    return;
  }
  s_handled++;
  s_exec_ok++;
  char detail[160];
  snprintf(detail, sizeof(detail), "shell_input sent %zu bytes to session %s", ilen, session_id);
  soar_emit_ex(cmd_id, sm, EdrCmdExecOk, 0, detail, "ok", NULL);
}

static void do_shell_close(const char *cmd_id, const uint8_t *pl, size_t len,
                           const EdrSoarCommandMeta *sm) {
  char session_id[EDR_SS_ID_LEN];
  session_id[0] = '\0';
  (void)edr_parse_json_string(pl, len, "session_id", session_id, sizeof(session_id));
  if (!session_id[0]) {
    s_exec_fail++;
    audit_both(cmd_id, "shell_close: missing session_id");
    soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, 1, "missing session_id", "failed", NULL);
    return;
  }
  edr_shell_session_close(session_id);
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, "shell_close: ok");
  soar_emit_ex(cmd_id, sm, EdrCmdExecOk, 0, "shell session closed", "ok", NULL);
}

static void do_rtr_get_file(const char *cmd_id, const uint8_t *pl, size_t len,
                            const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject rtr_get_file: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char path[1024];
  if (parse_path_json(pl, len, path, sizeof(path)) != 0) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "invalid path payload");
    return;
  }
  unsigned long long sz = 0;
  long long mt = 0;
  if (file_size_mtime(path, &sz, &mt) != 0) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "file not found or not regular");
    return;
  }
  int max_size = parse_int_json_default(pl, len, "max_size_bytes", 100 * 1024 * 1024);
  if (max_size <= 0) {
    max_size = 100 * 1024 * 1024;
  }
  if (sz > (unsigned long long)max_size) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 4, "file size exceeds max_size_bytes");
    return;
  }
  char sha[65];
  sha[0] = '\0';
  if (file_sha256_hex(path, sha) != 0) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 5, "sha256 failed");
    return;
  }
  char minio_key[1024];
  minio_key[0] = '\0';
  int upload_rc = edr_grpc_client_upload_file(cmd_id ? cmd_id : "rtr_get_file", path, sha,
                                              minio_key, sizeof(minio_key));
  if (upload_rc != 0) {
    upload_rc = edr_ingest_http_upload_file_multipart(cmd_id ? cmd_id : "rtr_get_file", path, sha,
                                                      minio_key, sizeof(minio_key));
  }
  char pathj[1400], keyj[1400], artifacts[3600], detail[4096];
  json_escape_to(pathj, sizeof(pathj), path);
  json_escape_to(keyj, sizeof(keyj), minio_key);
  snprintf(artifacts, sizeof(artifacts),
           "[{\"type\":\"rtr_file\",\"path\":%s,\"sha256\":\"%s\",\"size\":%llu,"
           "\"mtime\":%lld,\"upload_status\":\"%s\",\"minio_key\":%s}]",
           pathj, sha, sz, mt, upload_rc == 0 ? "ok" : "failed", keyj);
  snprintf(detail, sizeof(detail),
           "{\"path\":%s,\"sha256\":\"%s\",\"size\":%llu,\"mtime\":%lld,"
           "\"upload_status\":\"%s\",\"minio_key\":%s}",
           pathj, sha, sz, mt, upload_rc == 0 ? "ok" : "failed", keyj);
  s_handled++;
  if (upload_rc == 0) {
    s_exec_ok++;
    audit_both(cmd_id, "rtr_get_file: upload ok");
    soar_emit_ex(cmd_id, sm, EdrCmdExecOk, 0, detail, "ok", artifacts);
  } else {
    s_exec_fail++;
    audit_both(cmd_id, "rtr_get_file: file readable but upload failed");
    soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, 6, detail, "partial_success", artifacts);
  }
}

static void do_rtr_rm_file(const char *cmd_id, const uint8_t *pl, size_t len,
                           const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject rtr_rm_file: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char path[1024];
  if (parse_path_json(pl, len, path, sizeof(path)) != 0) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "invalid path payload");
    return;
  }
  if (!file_exists_c(path)) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "file not found or not regular");
    return;
  }
  if (remove(path) != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "rtr_rm_file: remove failed");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 4, "remove failed");
    return;
  }
  char pathj[1400], detail[1600];
  json_escape_to(pathj, sizeof(pathj), path);
  snprintf(detail, sizeof(detail), "{\"removed\":true,\"path\":%s}", pathj);
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, "rtr_rm_file: ok");
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

static void command_artifact_path(const char *cmd_id, const char *prefix, const char *ext,
                                  char *out, size_t cap) {
  const char *base = getenv("EDR_RESPONSE_ARTIFACT_DIR");
  char root[700];
  if (base && base[0]) {
    snprintf(root, sizeof(root), "%s", base);
  } else {
#ifdef _WIN32
    const char *tmp = getenv("TEMP");
    if (!tmp || !tmp[0]) {
      tmp = getenv("TMP");
    }
    if (!tmp || !tmp[0]) {
      tmp = ".";
    }
    snprintf(root, sizeof(root), "%s\\edr_response", tmp);
#else
    snprintf(root, sizeof(root), "%s", "/tmp/edr_response");
#endif
  }
  (void)mkdir_p_quiet(root);
  char safe[180];
  snprintf(safe, sizeof(safe), "%s", (cmd_id && cmd_id[0]) ? cmd_id : "cmd");
  sanitize_component(safe);
#ifdef _WIN32
  snprintf(out, cap, "%s\\%s_%s_%lld.%s", root, prefix ? prefix : "artifact", safe,
           (long long)time(NULL), ext ? ext : "json");
#else
  snprintf(out, cap, "%s/%s_%s_%lld.%s", root, prefix ? prefix : "artifact", safe,
           (long long)time(NULL), ext ? ext : "json");
#endif
}

static void fprint_json_escaped(FILE *f, const char *s) {
  if (!f) {
    return;
  }
  if (!s) {
    s = "";
  }
  for (const char *p = s; *p; p++) {
    unsigned char c = (unsigned char)*p;
    if (c == '"' || c == '\\') {
      fputc('\\', f);
      fputc(c, f);
    } else if (c == '\n') {
      fputs("\\n", f);
    } else if (c == '\r') {
      fputs("\\r", f);
    } else if (c == '\t') {
      fputs("\\t", f);
    } else if (c >= 32u) {
      fputc(c, f);
    } else {
      fputc(' ', f);
    }
  }
}

#ifdef _WIN32
#define EDR_EVENTLOG_XML_MAX (256u * 1024u)
static int eventlog_query_to_file(const char *channel, int max_events, FILE *f) {
  wchar_t wchannel[256];
  if (!channel || !channel[0]) {
    channel = "Security";
  }
  MultiByteToWideChar(CP_UTF8, 0, channel, -1, wchannel, 256);
  EVT_HANDLE hq = EvtQuery(NULL, wchannel, L"*", EvtQueryChannelPath);
  if (!hq) {
    return -1;
  }
  EVT_HANDLE events[16];
  DWORD returned = 0;
  int total = 0;
  int first = 1;
  while (total < max_events && EvtNext(hq, 16, events, 1000, 0, &returned)) {
    for (DWORD i = 0; i < returned && total < max_events; i++) {
      DWORD used = 0;
      DWORD props = 0;
      (void)EvtRender(NULL, events[i], EvtRenderEventXml, 0, NULL, &used, &props);
      if (used > 0u && used < EDR_EVENTLOG_XML_MAX) {
        WCHAR *wxml = (WCHAR *)calloc(1, (size_t)used + sizeof(WCHAR));
        if (wxml && EvtRender(NULL, events[i], EvtRenderEventXml, used, wxml, &used, &props)) {
          int need = WideCharToMultiByte(CP_UTF8, 0, wxml, -1, NULL, 0, NULL, NULL);
          if (need > 1) {
            char *utf8 = (char *)malloc((size_t)need);
            if (utf8) {
              WideCharToMultiByte(CP_UTF8, 0, wxml, -1, utf8, need, NULL, NULL);
              if (!first) {
                fputs(",\n", f);
              }
              first = 0;
              fputc('"', f);
              fprint_json_escaped(f, utf8);
              fputc('"', f);
              total++;
              free(utf8);
            }
          }
        }
        free(wxml);
      }
      EvtClose(events[i]);
    }
  }
  EvtClose(hq);
  return total;
}
#else
static int eventlog_query_to_file(const char *channel, int max_events, FILE *f) {
  (void)channel;
  if (max_events <= 0) {
    max_events = 100;
  }
  char cmd[160];
  snprintf(cmd, sizeof(cmd), "journalctl --output=json -n %d 2>/dev/null", max_events);
  FILE *p = popen(cmd, "r");
  if (!p) {
    return -1;
  }
  char line[8192];
  int first = 1;
  int count = 0;
  while (fgets(line, sizeof(line), p) && count < max_events) {
    line[strcspn(line, "\r\n")] = '\0';
    if (!first) {
      fputs(",\n", f);
    }
    first = 0;
    fputs(line, f);
    count++;
  }
  (void)pclose(p);
  return count;
}
#endif

static void do_eventlog_view(const char *cmd_id, const uint8_t *pl, size_t len,
                             const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject eventlog_view: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char channel[96];
  if (parse_json_string_field(pl, len, "channel", channel, sizeof(channel)) != 0) {
    snprintf(channel, sizeof(channel), "%s", "Security");
  }
  int max_events = parse_int_json_default(pl, len, "max_events", 100);
  if (max_events <= 0 || max_events > 1000) {
    max_events = 100;
  }
  char path[900];
  command_artifact_path(cmd_id, "eventlog", "json", path, sizeof(path));
  FILE *f = fopen(path, "w");
  if (!f) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "cannot create eventlog artifact");
    return;
  }
  fputs("{\"channel\":\"", f);
  fprint_json_escaped(f, channel);
  fputs("\",\"events\":[\n", f);
  int count = eventlog_query_to_file(channel, max_events, f);
  if (count < 0) {
    count = 0;
  }
  fprintf(f, "\n],\"total\":%d}\n", count);
  fclose(f);
  char sha[65];
  sha[0] = '\0';
  (void)file_sha256_hex(path, sha);
  char minio_key[1024];
  minio_key[0] = '\0';
  int upload_rc = edr_grpc_client_upload_file(cmd_id ? cmd_id : "eventlog", path, sha, minio_key, sizeof(minio_key));
  if (upload_rc != 0) {
    upload_rc = edr_ingest_http_upload_file_multipart(cmd_id ? cmd_id : "eventlog", path, sha,
                                                      minio_key, sizeof(minio_key));
  }
  char pathj[1200], channelj[256], keyj[1200], artifacts[3200], detail[4096];
  json_escape_to(pathj, sizeof(pathj), path);
  json_escape_to(channelj, sizeof(channelj), channel);
  json_escape_to(keyj, sizeof(keyj), minio_key);
  snprintf(artifacts, sizeof(artifacts),
           "[{\"type\":\"eventlog\",\"path\":%s,\"sha256\":\"%s\",\"upload_status\":\"%s\",\"minio_key\":%s}]",
           pathj, sha, upload_rc == 0 ? "ok" : "failed", keyj);
  snprintf(detail, sizeof(detail),
           "{\"channel\":%s,\"count\":%d,\"artifact_path\":%s,\"sha256\":\"%s\","
           "\"upload_status\":\"%s\",\"minio_key\":%s}",
           channelj, count, pathj, sha, upload_rc == 0 ? "ok" : "failed", keyj);
  s_handled++;
  if (upload_rc == 0) {
    s_exec_ok++;
    soar_emit_ex(cmd_id, sm, EdrCmdExecOk, 0, detail, "ok", artifacts);
  } else {
    s_exec_fail++;
    soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, 6, detail, "partial_success", artifacts);
  }
}

#ifdef _WIN32
static HKEY registry_parse_root(const char *key_path, const char **subkey_out) {
  if (!key_path || !subkey_out) {
    return NULL;
  }
  if (strncmp(key_path, "HKLM\\", 5) == 0 || strncmp(key_path, "HKLM/", 5) == 0) {
    *subkey_out = key_path + 5;
    return HKEY_LOCAL_MACHINE;
  }
  if (strncmp(key_path, "HKCU\\", 5) == 0 || strncmp(key_path, "HKCU/", 5) == 0) {
    *subkey_out = key_path + 5;
    return HKEY_CURRENT_USER;
  }
  if (strncmp(key_path, "HKU\\", 4) == 0 || strncmp(key_path, "HKU/", 4) == 0) {
    *subkey_out = key_path + 4;
    return HKEY_USERS;
  }
  if (strncmp(key_path, "HKCR\\", 5) == 0 || strncmp(key_path, "HKCR/", 5) == 0) {
    *subkey_out = key_path + 5;
    return HKEY_CLASSES_ROOT;
  }
  if (strncmp(key_path, "HKCC\\", 5) == 0 || strncmp(key_path, "HKCC/", 5) == 0) {
    *subkey_out = key_path + 5;
    return HKEY_CURRENT_CONFIG;
  }
  return NULL;
}

static void registry_format_data(FILE *f, DWORD type, const BYTE *data, DWORD size) {
  if (!f || !data) {
    return;
  }
  if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) {
    char *tmp = (char *)calloc(1, (size_t)size + 1u);
    if (tmp) {
      memcpy(tmp, data, size);
      fprint_json_escaped(f, tmp);
      free(tmp);
    }
  } else if (type == REG_DWORD && size >= sizeof(DWORD)) {
    DWORD v = 0;
    memcpy(&v, data, sizeof(v));
    fprintf(f, "0x%08lx", (unsigned long)v);
  } else if (type == REG_QWORD && size >= 8u) {
    unsigned long long v = 0;
    memcpy(&v, data, sizeof(v));
    fprintf(f, "0x%016llx", v);
  } else {
    fputs("hex:", f);
    DWORD n = size < 128u ? size : 128u;
    for (DWORD i = 0; i < n; i++) {
      fprintf(f, "%02x", data[i]);
    }
  }
}

static int registry_values_to_file(const char *key_path, int max_values, FILE *f) {
  const char *subkey = NULL;
  HKEY root = registry_parse_root(key_path, &subkey);
  if (!root || !subkey) {
    return -1;
  }
  HKEY hkey;
  if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hkey) != ERROR_SUCCESS) {
    return -1;
  }
  int first = 1;
  int count = 0;
  for (DWORD idx = 0; count < max_values; idx++) {
    char name[512];
    BYTE data[8192];
    DWORD name_size = sizeof(name);
    DWORD data_size = sizeof(data);
    DWORD type = 0;
    LONG lr = RegEnumValueA(hkey, idx, name, &name_size, NULL, &type, data, &data_size);
    if (lr != ERROR_SUCCESS) {
      break;
    }
    if (!first) {
      fputs(",\n", f);
    }
    first = 0;
    fputs("{\"name\":\"", f);
    fprint_json_escaped(f, name);
    fprintf(f, "\",\"type\":%lu,\"data\":\"", (unsigned long)type);
    registry_format_data(f, type, data, data_size);
    fputs("\"}", f);
    count++;
  }
  RegCloseKey(hkey);
  return count;
}
#endif

static void do_registry_query(const char *cmd_id, const uint8_t *pl, size_t len,
                              const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject registry_query: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char key[1024];
  if (parse_json_string_field(pl, len, "key", key, sizeof(key)) != 0 &&
      parse_json_string_field(pl, len, "path", key, sizeof(key)) != 0) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "missing registry key");
    return;
  }
  int max_values = parse_int_json_default(pl, len, "max_values", 200);
  if (max_values <= 0 || max_values > 1000) {
    max_values = 200;
  }
#ifndef _WIN32
  char keyj[1400], detail[1800];
  json_escape_to(keyj, sizeof(keyj), key);
  snprintf(detail, sizeof(detail), "{\"key\":%s,\"supported\":false,\"platform\":\"non_windows\"}", keyj);
  s_handled++;
  s_exec_ok++;
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
#else
  char path[900];
  command_artifact_path(cmd_id, "registry", "json", path, sizeof(path));
  FILE *f = fopen(path, "w");
  if (!f) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "cannot create registry artifact");
    return;
  }
  fputs("{\"key\":\"", f);
  fprint_json_escaped(f, key);
  fputs("\",\"values\":[\n", f);
  int count = registry_values_to_file(key, max_values, f);
  if (count < 0) {
    count = 0;
  }
  fprintf(f, "\n],\"total\":%d}\n", count);
  fclose(f);
  char sha[65];
  sha[0] = '\0';
  (void)file_sha256_hex(path, sha);
  char minio_key[1024];
  minio_key[0] = '\0';
  int upload_rc = edr_grpc_client_upload_file(cmd_id ? cmd_id : "registry", path, sha, minio_key, sizeof(minio_key));
  if (upload_rc != 0) {
    upload_rc = edr_ingest_http_upload_file_multipart(cmd_id ? cmd_id : "registry", path, sha,
                                                      minio_key, sizeof(minio_key));
  }
  char pathj[1200], keyj[1400], minioj[1200], artifacts[4800], detail[4800];
  json_escape_to(pathj, sizeof(pathj), path);
  json_escape_to(keyj, sizeof(keyj), key);
  json_escape_to(minioj, sizeof(minioj), minio_key);
  snprintf(artifacts, sizeof(artifacts),
           "[{\"type\":\"registry\",\"path\":%s,\"registry_key\":%s,\"sha256\":\"%s\","
           "\"upload_status\":\"%s\",\"minio_key\":%s}]",
           pathj, keyj, sha, upload_rc == 0 ? "ok" : "failed", minioj);
  snprintf(detail, sizeof(detail),
           "{\"key\":%s,\"count\":%d,\"artifact_path\":%s,\"sha256\":\"%s\","
           "\"upload_status\":\"%s\",\"minio_key\":%s}",
           keyj, count, pathj, sha, upload_rc == 0 ? "ok" : "failed", minioj);
  s_handled++;
  if (upload_rc == 0) {
    s_exec_ok++;
    soar_emit_ex(cmd_id, sm, EdrCmdExecOk, 0, detail, "ok", artifacts);
  } else {
    s_exec_fail++;
    soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, 6, detail, "partial_success", artifacts);
  }
#endif
}

static void do_quarantine_file(const char *cmd_id, const uint8_t *pl, size_t len,
                               const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject quarantine_file: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char path[1024];
  if (parse_path_json(pl, len, path, sizeof(path)) != 0 || !file_exists_c(path)) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "invalid path or file not found");
    return;
  }
  char reason[256];
  if (parse_json_string_field(pl, len, "reason", reason, sizeof(reason)) != 0) {
    snprintf(reason, sizeof(reason), "%s", "manual");
  }
  char base[700];
  quarantine_base_dir(base, sizeof(base));
  if (mkdir_p_quiet(base) != 0) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "quarantine directory create failed");
    return;
  }
  char stem[512];
  char safe_cmd[128];
  char safe_base[256];
  const char *cmd_name = (cmd_id && cmd_id[0]) ? cmd_id : "cmd";
  const char *base_name = path_basename_c(path);
  size_t cmd_n = strlen(cmd_name);
  size_t base_n = strlen(base_name);
  if (cmd_n >= sizeof(safe_cmd)) {
    cmd_n = sizeof(safe_cmd) - 1u;
  }
  if (base_n >= sizeof(safe_base)) {
    base_n = sizeof(safe_base) - 1u;
  }
  memcpy(safe_cmd, cmd_name, cmd_n);
  safe_cmd[cmd_n] = '\0';
  memcpy(safe_base, base_name, base_n);
  safe_base[base_n] = '\0';
  snprintf(stem, sizeof(stem), "%lld_%s_%s", (long long)time(NULL),
           safe_cmd, safe_base);
  sanitize_component(stem);
  char qpath[1400], meta[1400];
#ifdef _WIN32
  snprintf(qpath, sizeof(qpath), "%s\\%s.bin", base, stem);
  snprintf(meta, sizeof(meta), "%s\\%s.meta", base, stem);
#else
  snprintf(qpath, sizeof(qpath), "%s/%s.bin", base, stem);
  snprintf(meta, sizeof(meta), "%s/%s.meta", base, stem);
#endif
  unsigned long long sz = 0;
  long long mt = 0;
  char sha[65];
  sha[0] = '\0';
  (void)file_size_mtime(path, &sz, &mt);
  (void)file_sha256_hex(path, sha);
  if (move_file_cross_volume(path, qpath) != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "quarantine_file: move failed");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 4, "quarantine move failed");
    return;
  }
  FILE *mf = fopen(meta, "w");
  if (mf) {
    fprintf(mf, "quarantine_id=%s\noriginal_path=%s\nquarantine_path=%s\nsha256=%s\nsize=%llu\nmtime=%lld\nreason=%s\n",
            stem, path, qpath, sha, sz, mt, reason);
    fclose(mf);
  }
  char stemj[700], pathj[1400], qpathj[1600], metaj[1600], detail[5600];
  json_escape_to(stemj, sizeof(stemj), stem);
  json_escape_to(pathj, sizeof(pathj), path);
  json_escape_to(qpathj, sizeof(qpathj), qpath);
  json_escape_to(metaj, sizeof(metaj), meta);
  snprintf(detail, sizeof(detail),
           "{\"quarantine_id\":%s,\"original_path\":%s,\"quarantine_path\":%s,"
           "\"meta_path\":%s,\"sha256\":\"%s\",\"size\":%llu}",
           stemj, pathj, qpathj, metaj, sha, sz);
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, "quarantine_file: ok");
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

static int read_meta_value(const char *meta, const char *key, char *out, size_t cap) {
  FILE *f = fopen(meta, "r");
  if (!f) {
    return -1;
  }
  char line[1400];
  size_t kn = strlen(key);
  int ok = -1;
  while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, key, kn) == 0 && line[kn] == '=') {
      char *v = line + kn + 1u;
      v[strcspn(v, "\r\n")] = '\0';
      snprintf(out, cap, "%s", v);
      ok = 0;
      break;
    }
  }
  fclose(f);
  return ok;
}

static void do_unquarantine_file(const char *cmd_id, const uint8_t *pl, size_t len,
                                 const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject unquarantine_file: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char qid[256];
  if (parse_json_string_field(pl, len, "quarantine_id", qid, sizeof(qid)) != 0 &&
      parse_json_string_field(pl, len, "id", qid, sizeof(qid)) != 0) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "missing quarantine_id");
    return;
  }
  sanitize_component(qid);
  char base[700], meta[1200];
  quarantine_base_dir(base, sizeof(base));
#ifdef _WIN32
  snprintf(meta, sizeof(meta), "%s\\%s.meta", base, qid);
#else
  snprintf(meta, sizeof(meta), "%s/%s.meta", base, qid);
#endif
  char qpath[1024], original[1024], restore[1024];
  if (read_meta_value(meta, "quarantine_path", qpath, sizeof(qpath)) != 0 ||
      read_meta_value(meta, "original_path", original, sizeof(original)) != 0) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "quarantine metadata not found");
    return;
  }
  if (parse_json_string_field(pl, len, "restore_path", restore, sizeof(restore)) != 0) {
    snprintf(restore, sizeof(restore), "%s", original);
  }
  if (file_exists_c(restore)) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 4, "restore target already exists");
    return;
  }
  if (move_file_cross_volume(qpath, restore) != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "unquarantine_file: restore failed");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 5, "restore move failed");
    return;
  }
  (void)remove(meta);
  char qidj[700], restorej[1400], originalj[1400], detail[4200];
  json_escape_to(qidj, sizeof(qidj), qid);
  json_escape_to(restorej, sizeof(restorej), restore);
  json_escape_to(originalj, sizeof(originalj), original);
  snprintf(detail, sizeof(detail),
           "{\"quarantine_id\":%s,\"restored_path\":%s,\"original_path\":%s}",
           qidj, restorej, originalj);
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, "unquarantine_file: ok");
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

static void forensic_copy_lines(const char *jobdir, const uint8_t *pl, size_t len) {
  const char *e = getenv("EDR_FORENSIC_COPY_PATHS");
  if (!e || e[0] != '1' || !pl || len == 0u) {
    return;
  }
  char work[8192];
  if (len >= sizeof(work)) {
    len = sizeof(work) - 1u;
  }
  memcpy(work, pl, len);
  work[len] = 0;
  char *p = work;
  int idx = 0;
  for (;;) {
    char *line = p;
    char *nl = strchr(p, '\n');
    if (nl) {
      *nl = 0;
    }
    while (*line == ' ' || *line == '\r') {
      line++;
    }
    if (line[0] && line[0] != '#') {
      char dst[900];
#ifdef _WIN32
      snprintf(dst, sizeof(dst), "%s\\copied_%02d", jobdir, idx++);
#else
      snprintf(dst, sizeof(dst), "%s/copied_%02d", jobdir, idx++);
#endif
      (void)forensic_copy_one_file(line, dst);
    }
    if (!nl) {
      break;
    }
    p = nl + 1;
  }
}

static void upload_outbox_dir(char *out, size_t cap) {
  const char *e = getenv("EDR_UPLOAD_OUTBOX_DIR");
  if (!e || !e[0]) {
    e = getenv("EDR_COMMAND_OUTBOX_DIR");
  }
  if (e && e[0]) {
    snprintf(out, cap, "%s", e);
    return;
  }
#ifdef _WIN32
  snprintf(out, cap, "%s", "C:\\Program Files\\EDR Agent\\upload_outbox");
#else
  snprintf(out, cap, "%s", "/tmp/edr_upload_outbox");
#endif
}

static void write_upload_outbox(const char *cmd_id, const char *bundle, const char *sha,
                                const char *manifest) {
  char dir[700];
  upload_outbox_dir(dir, sizeof(dir));
  if (mkdir_p_quiet(dir) != 0) {
    return;
  }
  char safe[180];
  snprintf(safe, sizeof(safe), "%s", (cmd_id && cmd_id[0]) ? cmd_id : "cmd");
  sanitize_component(safe);
  char path[900];
#ifdef _WIN32
  snprintf(path, sizeof(path), "%s\\upload_%s_%lld.pending", dir, safe, (long long)time(NULL));
#else
  snprintf(path, sizeof(path), "%s/upload_%s_%lld.pending", dir, safe, (long long)time(NULL));
#endif
  FILE *f = fopen(path, "w");
  if (!f) {
    return;
  }
  fprintf(f, "command_id=%s\nbundle_path=%s\nsha256=%s\nmanifest_path=%s\ncreated_unix_ms=%lld\n",
          cmd_id ? cmd_id : "", bundle ? bundle : "", sha ? sha : "", manifest ? manifest : "",
          (long long)command_now_ms());
  fclose(f);
}

static int read_kv_file_value(const char *path, const char *key, char *out, size_t cap) {
  return read_meta_value(path, key, out, cap);
}

static void flush_upload_outbox_one(const char *pending_path) {
  char cmd_id[128], bundle[1024], sha[65];
  if (read_kv_file_value(pending_path, "command_id", cmd_id, sizeof(cmd_id)) != 0 ||
      read_kv_file_value(pending_path, "bundle_path", bundle, sizeof(bundle)) != 0 ||
      read_kv_file_value(pending_path, "sha256", sha, sizeof(sha)) != 0) {
    return;
  }
  if (!file_exists_c(bundle)) {
    return;
  }
  char minio_key[1024];
  minio_key[0] = '\0';
  if (edr_grpc_client_upload_file(cmd_id[0] ? cmd_id : "upload_outbox", bundle, sha, minio_key, sizeof(minio_key)) == 0 ||
      edr_ingest_http_upload_file_multipart(cmd_id[0] ? cmd_id : "upload_outbox", bundle, sha, minio_key, sizeof(minio_key)) == 0) {
    char done[1100];
    snprintf(done, sizeof(done), "%s.done", pending_path);
    (void)rename(pending_path, done);
  }
}

static void flush_upload_outbox(void) {
  char dir[700];
  upload_outbox_dir(dir, sizeof(dir));
#ifdef _WIN32
  char pattern[900];
  snprintf(pattern, sizeof(pattern), "%s\\*.pending", dir);
  WIN32_FIND_DATAA fd;
  HANDLE h = FindFirstFileA(pattern, &fd);
  if (h == INVALID_HANDLE_VALUE) {
    return;
  }
  do {
    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
      char path[1000];
      snprintf(path, sizeof(path), "%s\\%s", dir, fd.cFileName);
      flush_upload_outbox_one(path);
    }
  } while (FindNextFileA(h, &fd));
  FindClose(h);
#else
  DIR *d = opendir(dir);
  if (!d) {
    return;
  }
  struct dirent *ent;
  while ((ent = readdir(d)) != NULL) {
    const char *name = ent->d_name;
    size_t n = strlen(name);
    if (n > 8u && strcmp(name + n - 8u, ".pending") == 0) {
      char path[1000];
      snprintf(path, sizeof(path), "%s/%s", dir, name);
      flush_upload_outbox_one(path);
    }
  }
  closedir(d);
#endif
}

static void do_forensic(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject forensic: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char base[512];
  const char *o = getenv("EDR_FORENSIC_OUT");
  if (o && o[0]) {
    snprintf(base, sizeof(base), "%s", o);
  } else {
#ifdef _WIN32
    const char *tmp = getenv("TEMP");
    if (!tmp || !tmp[0]) {
      tmp = getenv("TMP");
    }
    if (!tmp || !tmp[0]) {
      tmp = ".";
    }
    snprintf(base, sizeof(base), "%s\\edr_forensic", tmp);
#else
    snprintf(base, sizeof(base), "%s", "/tmp/edr_forensic");
#endif
  }
  const char *job = (cmd_id && cmd_id[0]) ? cmd_id : "job";
  char dir[700];
#ifdef _WIN32
  snprintf(dir, sizeof(dir), "%s\\%s", base, job);
  {
    char cmdline[900];
    snprintf(cmdline, sizeof(cmdline), "cmd /c mkdir \"%s\" 2>nul", dir);
    (void)system(cmdline);
  }
#else
  snprintf(dir, sizeof(dir), "%s/%s", base, job);
  {
    char cmdline[800];
    snprintf(cmdline, sizeof(cmdline), "mkdir -p \"%s\" 2>/dev/null", dir);
    (void)system(cmdline);
  }
#endif
  char manifest[800];
#ifdef _WIN32
  snprintf(manifest, sizeof(manifest), "%s\\manifest.txt", dir);
#else
  snprintf(manifest, sizeof(manifest), "%s/manifest.txt", dir);
#endif
  FILE *f = fopen(manifest, "w");
  if (!f) {
    s_exec_fail++;
    audit_both(cmd_id, "forensic: 写 manifest 失败");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "manifest write failed");
    return;
  }
  fprintf(f, "command_id=%s\npayload_len=%zu\n", cmd_id ? cmd_id : "", len);
  {
    char shahex[65];
    if (pl && len > 0u) {
      (void)edr_sha256_hex(pl, len, shahex);
      fprintf(f, "payload_sha256=%s\n", shahex);
    } else {
      fprintf(f, "payload_sha256=\n");
    }
  }
#ifdef _WIN32
  fprintf(f, "platform=windows\n");
  {
    char hn[256];
    DWORD hnl = sizeof(hn);
    if (GetComputerNameA(hn, &hnl)) {
      fprintf(f, "hostname=%s\n", hn);
    }
  }
#else
  fprintf(f, "platform=posix\n");
  {
    char hn[256];
    if (gethostname(hn, sizeof(hn)) == 0) {
      hn[sizeof(hn) - 1] = '\0';
      fprintf(f, "hostname=%s\n", hn);
    }
  }
#endif
  if (s_bound_cfg) {
    fprintf(f, "endpoint_id=%s\ntenant_id=%s\n", s_bound_cfg->agent.endpoint_id[0] ? s_bound_cfg->agent.endpoint_id : "",
            s_bound_cfg->agent.tenant_id[0] ? s_bound_cfg->agent.tenant_id : "");
  }
  fclose(f);
  forensic_copy_lines(dir, pl, len);
  char bundle[800];
#ifdef _WIN32
  snprintf(bundle, sizeof(bundle), "%s\\bundle.tgz", dir);
  {
    char tarcmd[1800];
    snprintf(tarcmd, sizeof(tarcmd), "cmd /c tar czf \"%s\" -C \"%s\" . 2>nul", bundle, dir);
    (void)system(tarcmd);
  }
#else
  snprintf(bundle, sizeof(bundle), "%s/bundle.tgz", dir);
  {
    char tarcmd[1700];
    snprintf(tarcmd, sizeof(tarcmd), "tar czf \"%s\" -C \"%s\" . 2>/dev/null", bundle, dir);
    (void)system(tarcmd);
  }
#endif
  if (!file_exists_c(bundle)) {
    s_exec_fail++;
    audit_both(cmd_id, "forensic: bundle.tgz 生成失败");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "forensic bundle create failed");
    return;
  }
  char bundle_sha[65];
  bundle_sha[0] = '\0';
  (void)file_sha256_hex(bundle, bundle_sha);
  char upload_key[1024];
  upload_key[0] = '\0';
  int upload_rc = edr_grpc_client_upload_file(cmd_id ? cmd_id : "forensic", bundle, bundle_sha,
                                              upload_key, sizeof(upload_key));
  if (upload_rc != 0) {
    upload_rc = edr_ingest_http_upload_file_multipart(cmd_id ? cmd_id : "forensic", bundle, bundle_sha,
                                                      upload_key, sizeof(upload_key));
  }
  if (upload_rc != 0) {
    write_upload_outbox(cmd_id, bundle, bundle_sha, manifest);
  }
  char manifest_json[900];
#ifdef _WIN32
  snprintf(manifest_json, sizeof(manifest_json), "%s\\artifact_manifest.json", dir);
#else
  snprintf(manifest_json, sizeof(manifest_json), "%s/artifact_manifest.json", dir);
#endif
  {
    FILE *af = fopen(manifest_json, "w");
    if (af) {
      char mj[1200], bj[1200], kj[1200];
      json_escape_to(mj, sizeof(mj), manifest);
      json_escape_to(bj, sizeof(bj), bundle);
      json_escape_to(kj, sizeof(kj), upload_key);
      fprintf(af,
              "{\"command_id\":\"%s\",\"manifest_path\":%s,\"bundle_path\":%s,"
              "\"bundle_sha256\":\"%s\",\"upload_status\":\"%s\",\"minio_key\":%s}\n",
              cmd_id ? cmd_id : "", mj, bj, bundle_sha, upload_rc == 0 ? "ok" : "failed", kj);
      fclose(af);
    }
  }
  s_handled++;
  audit_both(cmd_id, upload_rc == 0
                         ? "forensic: manifest + bundle.tgz + grpc upload ok"
                         : "forensic: manifest + bundle.tgz ok; grpc upload failed, queued outbox");
  {
    char manifestj[1200], bundlej[1200], keyj[1200], artifacts[4200], detail[4800];
    json_escape_to(manifestj, sizeof(manifestj), manifest);
    json_escape_to(bundlej, sizeof(bundlej), bundle);
    json_escape_to(keyj, sizeof(keyj), upload_key);
    snprintf(artifacts, sizeof(artifacts),
             "[{\"type\":\"forensic_bundle\",\"path\":%s,\"manifest_path\":%s,\"sha256\":\"%s\","
             "\"upload_status\":\"%s\",\"minio_key\":%s}]",
             bundlej, manifestj, bundle_sha, upload_rc == 0 ? "ok" : "failed", keyj);
    snprintf(detail, sizeof(detail),
             "{\"manifest_path\":%s,\"bundle_path\":%s,\"sha256\":\"%s\",\"upload_status\":\"%s\","
             "\"minio_key\":%s,\"outbox\":\"%s\"}",
             manifestj, bundlej, bundle_sha, upload_rc == 0 ? "ok" : "failed", keyj,
             upload_rc == 0 ? "none" : "queued");
    if (upload_rc == 0) {
      s_exec_ok++;
      soar_emit_ex(cmd_id, sm, EdrCmdExecOk, 0, detail, "ok", artifacts);
    } else {
      s_exec_fail++;
      soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, 4, detail, "partial_success", artifacts);
    }
  }
}

static void do_rtq_query(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  char payload[4096];
  if (pl && len > 0u) {
    if (len >= sizeof(payload)) {
      len = sizeof(payload) - 1u;
    }
    memcpy(payload, pl, len);
    payload[len] = '\0';
  } else {
    snprintf(payload, sizeof(payload), "{\"limit\":50,\"time_window_s\":600}");
  }
  char detail[12000];
  if (edr_local_evidence_cache_query_json(payload, detail, sizeof(detail)) != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "rtq_query: failed");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "rtq query failed");
    return;
  }
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, "rtq_query: ok");
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

static void do_rtr_process_tree(const char *cmd_id, const uint8_t *pl, size_t len,
                                const EdrSoarCommandMeta *sm) {
  long pid = -1;
  if (parse_pid_json(pl, len, &pid) != 0) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "invalid pid payload");
    return;
  }
  char endpoint_id[64];
  if (parse_json_string_field(pl, len, "endpoint_id", endpoint_id, sizeof(endpoint_id)) != 0) {
    endpoint_id[0] = '\0';
  }
  char detail[12000];
  int r = edr_local_evidence_cache_process_tree_json((uint32_t)pid, endpoint_id, detail, sizeof(detail));
  if (r != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "rtr_process_tree: no cached process");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "process not found in local evidence cache");
    return;
  }
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, "rtr_process_tree: ok");
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

static void do_rtr_list_connections(const char *cmd_id, const uint8_t *pl, size_t len,
                                    const EdrSoarCommandMeta *sm) {
  char payload[4096];
  if (pl && len > 0u) {
    if (len >= sizeof(payload)) {
      len = sizeof(payload) - 1u;
    }
    memcpy(payload, pl, len);
    payload[len] = '\0';
  } else {
    snprintf(payload, sizeof(payload), "{\"event_type\":\"network\",\"limit\":50,\"time_window_s\":600}");
  }
  if (!strstr(payload, "\"event_type\"") && !strstr(payload, "\"type\"")) {
    char wrapped[4096];
    const char *body = payload;
    while (*body && isspace((unsigned char)*body)) {
      body++;
    }
    if (*body == '{') {
      body++;
      snprintf(wrapped, sizeof(wrapped), "{\"event_type\":\"network\",%s", body);
    } else {
      snprintf(wrapped, sizeof(wrapped), "{\"event_type\":\"network\",\"limit\":50,\"time_window_s\":600}");
    }
    snprintf(payload, sizeof(payload), "%s", wrapped);
  }
  char detail[12000];
  if (edr_local_evidence_cache_query_json(payload, detail, sizeof(detail)) != 0) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "connection query failed");
    return;
  }
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, "rtr_list_connections: ok");
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

static void do_pmfe_scan(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject pmfe_scan: enable EDR_CMD_ENABLED=1 or TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  long pid = -1;
  if (parse_pid_json(pl, len, &pid) != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "pmfe_scan: payload missing valid pid (JSON requires \"pid\")");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "invalid pid json");
    return;
  }
  if (edr_pmfe_submit_server_scan(cmd_id, (uint32_t)pid) != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "pmfe_scan: queue failed (PMFE not running or queue full)");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "pmfe queue full or not running");
    return;
  }
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, "pmfe_scan: queued (async coarse scan)");
  soar_emit_ex(cmd_id, sm, EdrCmdExecOk, 0, "pmfe_scan queued", "queued", NULL);
}

static void hex_from_bytes(const uint8_t *in, size_t len, char *out, size_t cap) {
  static const char *hx = "0123456789abcdef";
  if (!out || cap == 0u) {
    return;
  }
  size_t o = 0;
  for (size_t i = 0; i < len && o + 2u < cap; i++) {
    out[o++] = hx[in[i] >> 4];
    out[o++] = hx[in[i] & 15u];
  }
  out[o] = 0;
}

static void hmac_sha256_hex(const char *key, const uint8_t *data, size_t len, char out65[65]) {
  uint8_t key_block[64];
  uint8_t digest[EDR_SHA256_DIGEST_LEN];
  uint8_t ipad[64];
  uint8_t opad[64];
  memset(key_block, 0, sizeof(key_block));
  if (!key) {
    key = "";
  }
  size_t key_len = strlen(key);
  if (key_len > sizeof(key_block)) {
    EdrSha256Ctx kh;
    edr_sha256_init(&kh);
    edr_sha256_update(&kh, (const uint8_t *)key, key_len);
    edr_sha256_final(&kh, key_block);
  } else if (key_len > 0u) {
    memcpy(key_block, key, key_len);
  }
  for (size_t i = 0; i < sizeof(key_block); i++) {
    ipad[i] = key_block[i] ^ 0x36u;
    opad[i] = key_block[i] ^ 0x5cu;
  }
  EdrSha256Ctx inner;
  edr_sha256_init(&inner);
  edr_sha256_update(&inner, ipad, sizeof(ipad));
  edr_sha256_update(&inner, data, len);
  edr_sha256_final(&inner, digest);

  EdrSha256Ctx outer;
  edr_sha256_init(&outer);
  edr_sha256_update(&outer, opad, sizeof(opad));
  edr_sha256_update(&outer, digest, sizeof(digest));
  edr_sha256_final(&outer, digest);
  hex_from_bytes(digest, sizeof(digest), out65, 65u);
}

static int command_signature_extract_sigv1(const char *idempotency_key, char sig65[65]) {
  if (!idempotency_key || !sig65) {
    return 0;
  }
  const char *mark = strstr(idempotency_key, "|sigv1|");
  if (!mark) {
    return 0;
  }
  const char *keyid = mark + strlen("|sigv1|");
  const char *bar = strchr(keyid, '|');
  if (!bar || strlen(bar + 1) != 64u) {
    return 0;
  }
  for (size_t i = 0; i < 64u; i++) {
    char c = bar[1 + i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
      return 0;
    }
    sig65[i] = (char)tolower((unsigned char)c);
  }
  sig65[64] = 0;
  return 1;
}

static int b64url_value(unsigned char c) {
  if (c >= 'A' && c <= 'Z') return (int)(c - 'A');
  if (c >= 'a' && c <= 'z') return (int)(c - 'a' + 26);
  if (c >= '0' && c <= '9') return (int)(c - '0' + 52);
  if (c == '-') return 62;
  if (c == '_') return 63;
  return -1;
}

static int b64url_decode_raw(const char *s, uint8_t *out, size_t out_cap, size_t *out_len) {
  if (!s || !out || !out_len) {
    return -1;
  }
  uint32_t acc = 0;
  unsigned bits = 0;
  size_t o = 0;
  for (; *s; s++) {
    if (*s == '=') {
      break;
    }
    int v = b64url_value((unsigned char)*s);
    if (v < 0) {
      return -1;
    }
    acc = (acc << 6) | (uint32_t)v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (o >= out_cap) {
        return -1;
      }
      out[o++] = (uint8_t)((acc >> bits) & 0xffu);
    }
  }
  *out_len = o;
  return 0;
}

static int command_signature_extract_sigv2(const char *idempotency_key, char *alg, size_t alg_cap,
                                           uint8_t *sig, size_t sig_cap, size_t *sig_len) {
  if (!idempotency_key || !alg || alg_cap == 0u || !sig || !sig_len) {
    return 0;
  }
  const char *mark = strstr(idempotency_key, "|sigv2|");
  if (!mark) {
    return 0;
  }
  const char *algp = mark + strlen("|sigv2|");
  const char *bar1 = strchr(algp, '|');
  if (!bar1 || bar1 == algp) {
    return 0;
  }
  size_t alg_len = (size_t)(bar1 - algp);
  if (alg_len >= alg_cap) {
    alg_len = alg_cap - 1u;
  }
  memcpy(alg, algp, alg_len);
  alg[alg_len] = '\0';
  const char *keyid = bar1 + 1;
  const char *bar2 = strchr(keyid, '|');
  if (!bar2 || bar2 == keyid || !bar2[1]) {
    return 0;
  }
  if (b64url_decode_raw(bar2 + 1, sig, sig_cap, sig_len) != 0) {
    return 0;
  }
  return *sig_len > 0u;
}

static void normalize_pem_newlines(char *s) {
  if (!s) {
    return;
  }
  char *r = s;
  char *w = s;
  while (*r) {
    if (r[0] == '\\' && r[1] == 'n') {
      *w++ = '\n';
      r += 2;
    } else {
      *w++ = *r++;
    }
  }
  *w = '\0';
}

static int read_text_file_small(const char *path, char *out, size_t cap) {
  if (!path || !path[0] || !out || cap < 2u) {
    return -1;
  }
  FILE *f = fopen(path, "rb");
  if (!f) {
    return -1;
  }
  size_t n = fread(out, 1, cap - 1u, f);
  fclose(f);
  out[n] = '\0';
  return n > 0u ? 0 : -1;
}

static int command_public_key_pem(char *out, size_t cap) {
  if (!out || cap < 2u) {
    return 0;
  }
  out[0] = '\0';
  const char *inline_pem = getenv("EDR_COMMAND_SIGNING_PUBLIC_KEY");
  if (!inline_pem || !inline_pem[0]) {
    inline_pem = getenv("EDR_COMMAND_VERIFY_PUBLIC_KEY");
  }
  if (inline_pem && inline_pem[0]) {
    snprintf(out, cap, "%s", inline_pem);
    normalize_pem_newlines(out);
    return out[0] != '\0';
  }
  const char *path = getenv("EDR_COMMAND_SIGNING_PUBLIC_KEY_PATH");
  if (!path || !path[0]) {
    path = getenv("EDR_COMMAND_VERIFY_PUBLIC_KEY_PATH");
  }
  if (path && path[0] && read_text_file_small(path, out, cap) == 0) {
    normalize_pem_newlines(out);
    return 1;
  }
  if (s_bound_cfg && s_bound_cfg->command.signing_public_key_pem[0]) {
    snprintf(out, cap, "%s", s_bound_cfg->command.signing_public_key_pem);
    normalize_pem_newlines(out);
    return out[0] != '\0';
  }
  if (s_bound_cfg && s_bound_cfg->command.signing_public_key_path[0] &&
      read_text_file_small(s_bound_cfg->command.signing_public_key_path, out, cap) == 0) {
    normalize_pem_newlines(out);
    return 1;
  }
  return 0;
}

static int command_verify_ed25519_pem(const char *public_key_pem, const uint8_t *msg, size_t msg_len,
                                      const uint8_t *sig, size_t sig_len) {
#ifdef EDR_HAVE_COMMAND_SIGNATURE_OPENSSL
  if (!public_key_pem || !public_key_pem[0] || !msg || !sig || sig_len == 0u) {
    return 0;
  }
  BIO *bio = BIO_new_mem_buf(public_key_pem, -1);
  if (!bio) {
    return 0;
  }
  EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  BIO_free(bio);
  if (!pkey) {
    return 0;
  }
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  int ok = 0;
  if (ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) == 1 &&
      EVP_DigestVerify(ctx, sig, sig_len, msg, msg_len) == 1) {
    ok = 1;
  }
  if (ctx) {
    EVP_MD_CTX_free(ctx);
  }
  EVP_PKEY_free(pkey);
  return ok;
#else
  (void)public_key_pem;
  (void)msg;
  (void)msg_len;
  (void)sig;
  (void)sig_len;
  return -1;
#endif
}

static void command_signature_idempotency_value(const char *idempotency_key, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  if (!idempotency_key || !idempotency_key[0]) {
    return;
  }
  const char *mark = strstr(idempotency_key, "|sigv1|");
  const char *mark2 = strstr(idempotency_key, "|sigv2|");
  if (!mark || (mark2 && mark2 < mark)) {
    mark = mark2;
  }
  size_t n = mark ? (size_t)(mark - idempotency_key) : strlen(idempotency_key);
  if (n >= cap) {
    n = cap - 1u;
  }
  memcpy(out, idempotency_key, n);
  out[n] = '\0';
}

static int is_internal_auto_command(const char *cmd_id) {
  return cmd_id && (strncmp(cmd_id, "auto-", 5) == 0 || strcmp(cmd_id, "auto-shellcode") == 0);
}

static int is_rtr_shell_command_type(const char *t) {
  return streq(t, "rtr_shell") || streq(t, "RTR_SHELL") ||
         streq(t, "remote_shell") || streq(t, "shell_exec") ||
         streq(t, "shell_open") || streq(t, "shell_input") || streq(t, "shell_close");
}

static int is_dangerous_command_type(const char *t) {
  return streq(t, "isolate_host") || streq(t, "isolate") ||
         streq(t, "restore_host") || streq(t, "host_restore") ||
         streq(t, "kill_process") || streq(t, "kill") ||
         streq(t, "collect_forensic") || streq(t, "forensic") ||
         streq(t, "rtr_get_file") || streq(t, "rtr_file_get") || streq(t, "get_file") ||
         streq(t, "RTR_GET_FILE") || streq(t, "rtr_rm_file") || streq(t, "rtr_file_rm") ||
         streq(t, "remove_file") || streq(t, "delete_file") || streq(t, "RTR_RM_FILE") ||
         streq(t, "quarantine_file") || streq(t, "file_quarantine") ||
         streq(t, "rtr_quarantine_file") || streq(t, "RTR_QUARANTINE_FILE") ||
         streq(t, "unquarantine_file") || streq(t, "restore_file") ||
         streq(t, "file_unquarantine") || streq(t, "rtr_unquarantine_file") ||
         streq(t, "RTR_UNQUARANTINE_FILE") ||
         streq(t, "pmfe_scan") || streq(t, "CMD_PMFE_SCAN") ||
         streq(t, "eventlog_view") || streq(t, "rtr_eventlog") || streq(t, "RTR_EVENTLOG") ||
         streq(t, "reg_query") || streq(t, "registry_query") || streq(t, "RTR_REG_QUERY") ||
         is_rtr_shell_command_type(t);
}

static int command_signature_verify(const char *cmd_id, const char *cmd_type, const uint8_t *payload,
                                    size_t payload_len, const EdrSoarCommandMeta *sm,
                                    char *reason, size_t reason_cap) {
  const char *require = getenv("EDR_COMMAND_REQUIRE_SIGNATURE");
  int required = require && require[0] == '1';
  int force_shell_signature = is_rtr_shell_command_type(cmd_type);
  const char *allow_unsigned = getenv("EDR_COMMAND_ALLOW_UNSIGNED_DANGEROUS");
  if (force_shell_signature) {
    required = 1;
  }
  if (!required && is_dangerous_command_type(cmd_type) && !is_internal_auto_command(cmd_id) &&
      !(allow_unsigned && allow_unsigned[0] == '1')) {
    required = 1;
  }
  if (force_shell_signature && (!sm || sm->issued_at_unix_ms <= 0 || sm->deadline_ms == 0u)) {
    snprintf(reason, reason_cap, "rtr_shell requires issued_at_unix_ms and deadline_ms");
    return 0;
  }

  char idem[512];
  command_signature_idempotency_value(sm ? sm->idempotency_key : NULL, idem, sizeof(idem));
  if (required && !idem[0]) {
    snprintf(reason, reason_cap, "missing idempotency key");
    return 0;
  }
  char payload_hash[65];
  (void)edr_sha256_hex(payload ? payload : (const uint8_t *)"", payload_len, payload_hash);
  char canonical[1024];
  snprintf(canonical, sizeof(canonical), "%s\n%s\n%s\n%lld\n%u\n%s",
           cmd_id ? cmd_id : "", cmd_type ? cmd_type : "",
           idem,
           (long long)(sm ? sm->issued_at_unix_ms : 0), (unsigned)(sm ? sm->deadline_ms : 0),
           payload_hash);

  char alg[32];
  uint8_t sig2[96];
  size_t sig2_len = 0u;
  if (command_signature_extract_sigv2(sm ? sm->idempotency_key : NULL, alg, sizeof(alg),
                                      sig2, sizeof(sig2), &sig2_len)) {
    if (strcmp(alg, "ed25519") != 0) {
      snprintf(reason, reason_cap, "unsupported command signature algorithm: %s", alg);
      return 0;
    }
    if (sig2_len != 64u) {
      snprintf(reason, reason_cap, "invalid command sigv2 signature length");
      return 0;
    }
    char public_key_pem[4096];
    if (!command_public_key_pem(public_key_pem, sizeof(public_key_pem))) {
      snprintf(reason, reason_cap, "command sigv2 public key missing");
      return 0;
    }
    int ok = command_verify_ed25519_pem(public_key_pem, (const uint8_t *)canonical,
                                        strlen(canonical), sig2, sig2_len);
    if (ok == -1) {
      snprintf(reason, reason_cap, "command sigv2 requires OpenSSL verification support");
      return 0;
    }
    if (!ok) {
      snprintf(reason, reason_cap, "invalid command sigv2 signature");
      return 0;
    }
    return 1;
  }

  char configured_public_key[4096];
  int has_public_key = command_public_key_pem(configured_public_key, sizeof(configured_public_key));
  const char *accept_legacy = getenv("EDR_COMMAND_ACCEPT_LEGACY_HMAC");
  if (required && has_public_key && !(accept_legacy && accept_legacy[0] == '1')) {
    snprintf(reason, reason_cap, "missing command sigv2 signature");
    return 0;
  }

  const char *key = getenv("EDR_COMMAND_SIGNING_KEY");
  if ((!key || !key[0]) && !required) {
    return 1;
  }
  if (!key || !key[0]) {
    snprintf(reason, reason_cap, "command signature required but no sigv2 public key or EDR_COMMAND_SIGNING_KEY configured");
    return 0;
  }

  char got[65];
  if (!command_signature_extract_sigv1(sm ? sm->idempotency_key : NULL, got)) {
    if (required) {
      snprintf(reason, reason_cap, "missing command signature");
      return 0;
    }
    return 1;
  }
  char want[65];
  hmac_sha256_hex(key, (const uint8_t *)canonical, strlen(canonical), want);
  if (strcmp(got, want) != 0) {
    snprintf(reason, reason_cap, "invalid command signature");
    return 0;
  }
  return 1;
}

static int64_t command_now_ms(void) {
  return (int64_t)time(NULL) * 1000LL;
}

static int command_deadline_expired(const EdrSoarCommandMeta *sm, char *reason, size_t cap) {
  if (!sm || sm->issued_at_unix_ms <= 0 || sm->deadline_ms == 0u) {
    return 0;
  }
  int64_t deadline = sm->issued_at_unix_ms + (int64_t)sm->deadline_ms;
  int64_t now = command_now_ms();
  if (now <= deadline) {
    return 0;
  }
  snprintf(reason, cap, "command expired issued_at=%lld deadline_ms=%u now=%lld",
           (long long)sm->issued_at_unix_ms, (unsigned)sm->deadline_ms, (long long)now);
  return 1;
}

static void flush_command_result_outbox(void) {
  EdrCommandStateRecord pending[16];
  int n = edr_command_state_collect_pending(pending, sizeof(pending) / sizeof(pending[0]));
  if (n <= 0) {
    return;
  }
  for (int i = 0; i < n; i++) {
    EdrSoarCommandMeta sm;
    memset(&sm, 0, sizeof(sm));
    snprintf(sm.soar_correlation_id, sizeof(sm.soar_correlation_id), "%s", pending[i].soar_correlation_id);
    snprintf(sm.playbook_run_id, sizeof(sm.playbook_run_id), "%s", pending[i].playbook_run_id);
    snprintf(sm.playbook_step_id, sizeof(sm.playbook_step_id), "%s", pending[i].playbook_step_id);
    if (!command_should_report(pending[i].command_id, &sm)) {
      continue;
    }
    int rc = -1;
    if (edr_grpc_client_ready()) {
      rc = edr_grpc_client_report_command_result(pending[i].command_id, &sm,
                                                 pending[i].execution_status,
                                                 pending[i].exit_code,
                                                 pending[i].detail);
    }
    if (rc != 0) {
      rc = edr_ingest_http_post_command_result(pending[i].command_id, &sm,
                                               pending[i].execution_status,
                                               pending[i].exit_code,
                                               pending[i].detail);
    }
    if (rc == 0) {
      edr_command_state_mark_reported(&pending[i]);
    }
  }
}

void edr_command_poll_reliable_delivery(void) {
  static int64_t last_poll_ms;
  int64_t now = command_now_ms();
  if (last_poll_ms > 0 && now - last_poll_ms < 5000) {
    return;
  }
  last_poll_ms = now;
  flush_upload_outbox();
  flush_command_result_outbox();
  edr_command_state_compact_if_needed();
}

void edr_command_on_envelope(const char *command_id, const char *command_type, const uint8_t *payload,
                             size_t payload_len, const EdrSoarCommandMeta *soar_meta) {
  EdrSoarCommandMeta empty;
  memset(&empty, 0, sizeof(empty));
  const EdrSoarCommandMeta *sm = soar_meta ? soar_meta : &empty;
  const char *t = command_type ? command_type : "";
  const char *id = command_id ? command_id : "";
  s_active_command_type = t;

  char sig_reason[160];
  sig_reason[0] = 0;
  if (!command_signature_verify(id, t, payload, payload_len, sm, sig_reason, sizeof(sig_reason))) {
    s_rejected++;
    audit_both(id, sig_reason[0] ? sig_reason : "command signature rejected");
    soar_emit(id, sm, EdrCmdExecRejected, 15, sig_reason[0] ? sig_reason : "command signature rejected");
    return;
  }

  char deadline_reason[180];
  deadline_reason[0] = '\0';
  if (command_deadline_expired(sm, deadline_reason, sizeof(deadline_reason))) {
    s_rejected++;
    audit_both(id, deadline_reason);
    soar_emit_ex(id, sm, EdrCmdExecFailed, 16, deadline_reason, "timeout", NULL);
    return;
  }

  edr_command_poll_reliable_delivery();

  int retry_count = 0;
  EdrCommandStateRecord dup;
  int dup_rc = edr_command_state_begin(id, t, sm, &retry_count, &dup);
  (void)retry_count;
  if (dup_rc == 1) {
    char detail[2600];
    snprintf(detail, sizeof(detail), "duplicate command suppressed previous_status=%s previous_exit=%d previous_detail=%s",
             dup.response_status[0] ? dup.response_status : "unknown", dup.exit_code,
             dup.detail[0] ? dup.detail : "");
    audit_both(id, "duplicate command suppressed by local idempotency state");
    soar_emit_ex(id, sm, (EdrCommandExecutionStatus)(dup.execution_status ? dup.execution_status : EdrCmdExecOk),
                 dup.exit_code, detail, dup.response_status[0] ? dup.response_status : "ok", NULL);
    return;
  }

  if (streq(t, "noop") || streq(t, "ping")) {
    fprintf(stderr, "[command] ok id=%s type=%s\n", id, t);
    s_handled++;
    soar_emit(id, sm, EdrCmdExecOk, 0, t);
    return;
  }

  if (streq(t, "echo")) {
    fprintf(stderr, "[command] echo id=%s len=%zu\n", id, payload_len);
    if (payload && payload_len > 0u && payload_len < 4096u) {
      fwrite(payload, 1, payload_len, stderr);
      fputc('\n', stderr);
    }
    s_handled++;
    soar_emit(id, sm, EdrCmdExecOk, 0, "echo");
    return;
  }

  if (streq(t, "isolate_host") || streq(t, "isolate")) {
    do_isolate(id, sm);
    return;
  }
  if (streq(t, "restore_host") || streq(t, "host_restore")) {
    do_restore_host(id, sm);
    return;
  }
  if (streq(t, "isolate_status") || streq(t, "host_isolation_status")) {
    do_isolate_status(id, sm);
    return;
  }
  if (streq(t, "kill_process") || streq(t, "kill")) {
    do_kill(id, payload, payload_len, sm);
    return;
  }
  if (streq(t, "collect_forensic") || streq(t, "forensic")) {
    do_forensic(id, payload, payload_len, sm);
    return;
  }
  if (streq(t, "rtq_execute") || streq(t, "RTQ_EXECUTE")) {
    edr_response_rtq_execute(id, payload, payload_len, sm);
    return;
  }
  if (streq(t, "rtq_query") || streq(t, "RTQ_QUERY")) {
    do_rtq_query(id, payload, payload_len, sm);
    return;
  }
  if (streq(t, "rtr_process_tree") || streq(t, "RTR_PROCESS_TREE")) {
    do_rtr_process_tree(id, payload, payload_len, sm);
    return;
  }
  if (streq(t, "rtr_list_connections") || streq(t, "RTR_LIST_CONNECTIONS")) {
    do_rtr_list_connections(id, payload, payload_len, sm);
    return;
  }
  if (streq(t, "rtr_file_stat") || streq(t, "file_stat") || streq(t, "RTR_FILE_STAT")) {
    do_file_stat(id, payload, payload_len, sm);
    return;
  }
  if (streq(t, "rtr_get_file") || streq(t, "rtr_file_get") || streq(t, "get_file") ||
      streq(t, "RTR_GET_FILE")) {
    do_rtr_get_file(id, payload, payload_len, sm);
    return;
  }
  if (streq(t, "rtr_rm_file") || streq(t, "rtr_file_rm") || streq(t, "remove_file") ||
      streq(t, "delete_file") || streq(t, "RTR_RM_FILE")) {
    do_rtr_rm_file(id, payload, payload_len, sm);
    return;
  }
  if (streq(t, "eventlog_view") || streq(t, "rtr_eventlog") || streq(t, "RTR_EVENTLOG")) {
    do_eventlog_view(id, payload, payload_len, sm);
    return;
  }
  if (streq(t, "reg_query") || streq(t, "registry_query") || streq(t, "RTR_REG_QUERY")) {
    do_registry_query(id, payload, payload_len, sm);
    return;
  }
  if (streq(t, "quarantine_file") || streq(t, "file_quarantine") ||
      streq(t, "rtr_quarantine_file") || streq(t, "RTR_QUARANTINE_FILE")) {
    do_quarantine_file(id, payload, payload_len, sm);
    return;
  }
  if (streq(t, "unquarantine_file") || streq(t, "restore_file") ||
      streq(t, "file_unquarantine") || streq(t, "rtr_unquarantine_file") ||
      streq(t, "RTR_UNQUARANTINE_FILE")) {
    do_unquarantine_file(id, payload, payload_len, sm);
    return;
  }
  if (streq(t, "pmfe_scan") || streq(t, "CMD_PMFE_SCAN")) {
    do_pmfe_scan(id, payload, payload_len, sm);
    return;
  }
  if (streq(t, "shell_open")) {
    do_shell_open(id, payload, payload_len, sm);
    return;
  }
  if (streq(t, "shell_input")) {
    do_shell_input(id, payload, payload_len, sm);
    return;
  }
  if (streq(t, "shell_close")) {
    do_shell_close(id, payload, payload_len, sm);
    return;
  }
  if (is_rtr_shell_command_type(t)) {
    do_rtr_shell(id, payload, payload_len, sm);
    return;
  }

  if (streq(t, "ave_status") || streq(t, "ave_model_status")) {
    do_ave_status(id, sm);
    return;
  }
  if (streq(t, "ave_fingerprint") || streq(t, "ave_fp")) {
    do_ave_fingerprint(id, payload, payload_len, sm);
    return;
  }
  if (streq(t, "ave_infer")) {
    do_ave_infer(id, payload, payload_len, sm);
    return;
  }

  if (streq(t, "self_protect_status") || streq(t, "agent_health") || streq(t, "health_status")) {
    do_self_protect_status(id, sm);
    return;
  }

  if (streq(t, "update_server_address") || streq(t, "set_server_address")) {
    do_update_server_address(id, payload, payload_len, sm);
    return;
  }

  if (streq(t, "GET_ATTACK_SURFACE") || streq(t, "get_attack_surface") || streq(t, "REFRESH_ATTACK_SURFACE")) {
    char detail[256];
    int r = edr_attack_surface_execute(id, s_bound_cfg, detail, sizeof(detail));
    if (r != 0) {
      s_exec_fail++;
      audit_both(id, "GET_ATTACK_SURFACE: failed");
      soar_emit(id, sm, EdrCmdExecFailed, r, detail[0] ? detail : "attack_surface_failed");
    } else {
      s_handled++;
      s_exec_ok++;
      audit_both(id, "GET_ATTACK_SURFACE: ok");
      soar_emit(id, sm, EdrCmdExecOk, 0, detail[0] ? detail : "attack_surface_ok");
    }
    return;
  }

  fprintf(stderr, "[command] 未知类型 id=%s type=%s\n", id, t);
  s_unknown++;
  soar_emit(id, sm, EdrCmdExecUnknownType, 1, "unknown command_type");
}

unsigned long edr_command_handled_count(void) { return s_handled; }

unsigned long edr_command_unknown_count(void) { return s_unknown; }

unsigned long edr_command_rejected_count(void) { return s_rejected; }

unsigned long edr_command_exec_ok_count(void) { return s_exec_ok; }

unsigned long edr_command_exec_fail_count(void) { return s_exec_fail; }
