/* §8 响应指令执行器 — Subscribe 分发；高危操作需 EDR_CMD_ENABLED=1；AVE 见 ave_* */

#include "edr/attack_surface_report.h"
#include "edr/command.h"
#include "edr/ave.h"
#include "edr/ave_sdk.h"
#include "edr/config.h"
#include "edr/error.h"
#include "edr/grpc_client.h"
#include "edr/local_evidence_cache.h"
#include "edr/pmfe.h"
#include "edr/self_protect.h"
#include "edr/sha256.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
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

/** main 在 edr_agent_init 后绑定，供 ave_infer 使用 */
static const EdrConfig *s_bound_cfg;

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

static const char *exec_status_label(EdrCommandExecutionStatus st) {
  switch (st) {
    case EdrCmdExecOk:
      return "ok";
    case EdrCmdExecRejected:
      return "rejected";
    case EdrCmdExecFailed:
      return "failed";
    case EdrCmdExecUnknownType:
      return "unknown_type";
    default:
      return "unknown";
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
    } else if (c < 0x20u) {
      dst[o++] = ' ';
    } else {
      dst[o++] = (char)c;
    }
  }
  if (o + 1u < cap) {
    dst[o++] = '"';
  }
  dst[o < cap ? o : cap - 1u] = '\0';
}

static void soar_emit(const char *cmd_id, const EdrSoarCommandMeta *sm, EdrCommandExecutionStatus st,
                      int exit_code, const char *detail) {
  if (!soar_want_report(sm)) {
    return;
  }
  char detail_json[16384];
  char raw[12000];
  char err[1600];
  int retryable = (st == EdrCmdExecFailed && exit_code != 1 && exit_code != 2 && exit_code != 7) ? 1 : 0;
  json_escape_to(raw, sizeof(raw), detail ? detail : "");
  json_escape_to(err, sizeof(err), st == EdrCmdExecOk ? "" : (detail ? detail : exec_status_label(st)));
  snprintf(detail_json, sizeof(detail_json),
           "{\"task_id\":\"%s\",\"status\":\"%s\",\"exit_code\":%d,"
           "\"evidence_refs\":[],\"upload_refs\":[],\"error\":%s,"
           "\"retryable\":%s,\"raw_detail\":%s}",
           cmd_id ? cmd_id : "", exec_status_label(st), exit_code, err,
           retryable ? "true" : "false", raw);
  (void)edr_grpc_client_report_command_result(cmd_id, sm, (int)st, exit_code, detail_json);
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

int edr_command_dispatch_recommended_forensics(const EdrBehaviorRecord *r) {
  if (!r || !r->detection_context[0] || !ctx_has(r, "\"recommended_forensics\"")) {
    return 0;
  }
  const char *off = getenv("EDR_AUTO_RECOMMENDED_FORENSICS");
  if (off && off[0] == '0') {
    return 0;
  }
  if (!dangerous_enabled()) {
    return 0;
  }
  EdrSoarCommandMeta sm;
  memset(&sm, 0, sizeof(sm));
  snprintf(sm.soar_correlation_id, sizeof(sm.soar_correlation_id), "%s", "agent_auto_recommended_forensics");
  snprintf(sm.playbook_run_id, sizeof(sm.playbook_run_id), "%s", r->event_id[0] ? r->event_id : "local_event");
  sm.issued_at_unix_ms = (int64_t)time(NULL) * 1000LL;

  int dispatched = 0;
  if (r->pid != 0u && ctx_has(r, "pmfe_scan")) {
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
    char payload[1800];
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

static void do_isolate(const char *cmd_id, const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject isolate: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char path[512];
  const char *stamp = getenv("EDR_ISOLATE_STAMP_PATH");
  if (stamp && stamp[0]) {
    snprintf(path, sizeof(path), "%s", stamp);
  } else {
#ifdef _WIN32
    const char *tmp = getenv("TEMP");
    if (!tmp || !tmp[0]) {
      tmp = getenv("TMP");
    }
    if (!tmp || !tmp[0]) {
      tmp = ".";
    }
    snprintf(path, sizeof(path), "%s\\edr_isolated_%s", tmp,
             (cmd_id && cmd_id[0]) ? cmd_id : "cmd");
#else
    snprintf(path, sizeof(path), "/tmp/edr_isolated_%s",
             (cmd_id && cmd_id[0]) ? cmd_id : "cmd");
#endif
  }
  FILE *f = fopen(path, "w");
  if (f) {
    (void)fwrite("1", 1, 1, f);
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
#ifndef _WIN32
    (void)setenv("EDR_CMD_ID", cmd_id ? cmd_id : "", 1);
#endif
    int r = system(hook);
    if (r == 0) {
      audit_both(cmd_id, "isolate: EDR_ISOLATE_HOOK 执行成功");
    } else {
      audit_both(cmd_id, "isolate: EDR_ISOLATE_HOOK 返回非零");
      soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "isolate hook non-zero");
      return;
    }
  }
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, "isolate ok");
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
  const char *pd = getenv("ProgramData");
  if (!pd || !pd[0]) {
    pd = getenv("TEMP");
  }
  if (!pd || !pd[0]) {
    pd = ".";
  }
  snprintf(out, cap, "%s\\EDR\\quarantine", pd);
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
  char stem[180];
  snprintf(stem, sizeof(stem), "%lld_%s_%s", (long long)time(NULL),
           (cmd_id && cmd_id[0]) ? cmd_id : "cmd", path_basename_c(path));
  sanitize_component(stem);
  char qpath[900], meta[900];
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
  char detail[2200];
  snprintf(detail, sizeof(detail),
           "{\"quarantine_id\":\"%s\",\"original_path\":\"%s\",\"quarantine_path\":\"%s\","
           "\"meta_path\":\"%s\",\"sha256\":\"%s\",\"size\":%llu}",
           stem, path, qpath, meta, sha, sz);
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
  char base[700], meta[900];
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
  char detail[1800];
  snprintf(detail, sizeof(detail),
           "{\"quarantine_id\":\"%s\",\"restored_path\":\"%s\",\"original_path\":\"%s\"}",
           qid, restore, original);
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
    char tarcmd[1100];
    snprintf(tarcmd, sizeof(tarcmd), "cmd /c tar czf \"%s\" -C \"%s\" . 2>nul", bundle, dir);
    (void)system(tarcmd);
  }
#else
  snprintf(bundle, sizeof(bundle), "%s/bundle.tgz", dir);
  {
    char tarcmd[1000];
    snprintf(tarcmd, sizeof(tarcmd), "tar czf \"%s\" -C \"%s\" . 2>/dev/null", bundle, dir);
    (void)system(tarcmd);
  }
#endif
  s_exec_ok++;
  audit_both(cmd_id, "forensic: manifest + bundle.tgz（可选路径复制见 EDR_FORENSIC_COPY_PATHS）");
  {
    char detail[1800];
    snprintf(detail, sizeof(detail), "forensic bundle ok manifest_path=\"%s\" bundle_path=\"%s\"", manifest, bundle);
    soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
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
    audit_both(cmd_id, "reject pmfe_scan: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  long pid = -1;
  if (parse_pid_json(pl, len, &pid) != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "pmfe_scan: payload 缺少有效 pid（JSON 需含 \"pid\"）");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "invalid pid json");
    return;
  }
  if (edr_pmfe_submit_server_scan(cmd_id, (uint32_t)pid) != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "pmfe_scan: 入队失败（PMFE 未启动或队列满）");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "pmfe queue full or not running");
    return;
  }
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, "pmfe_scan: 已入队（异步粗扫）");
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, "pmfe_scan queued");
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

static int command_signature_extract(const char *idempotency_key, char sig65[65]) {
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

static int command_signature_verify(const char *cmd_id, const char *cmd_type, const uint8_t *payload,
                                    size_t payload_len, const EdrSoarCommandMeta *sm,
                                    char *reason, size_t reason_cap) {
  const char *require = getenv("EDR_COMMAND_REQUIRE_SIGNATURE");
  const int required = require && require[0] == '1';
  const char *key = getenv("EDR_COMMAND_SIGNING_KEY");
  if ((!key || !key[0]) && !required) {
    return 1;
  }
  if (!key || !key[0]) {
    snprintf(reason, reason_cap, "command signature required but EDR_COMMAND_SIGNING_KEY missing");
    return 0;
  }
  char got[65];
  if (!command_signature_extract(sm ? sm->idempotency_key : NULL, got)) {
    if (required) {
      snprintf(reason, reason_cap, "missing command signature");
      return 0;
    }
    return 1;
  }
  char payload_hash[65];
  (void)edr_sha256_hex(payload ? payload : (const uint8_t *)"", payload_len, payload_hash);
  char canonical[512];
  snprintf(canonical, sizeof(canonical), "%s\n%s\n%lld\n%u\n%s",
           cmd_id ? cmd_id : "", cmd_type ? cmd_type : "",
           (long long)(sm ? sm->issued_at_unix_ms : 0), (unsigned)(sm ? sm->deadline_ms : 0),
           payload_hash);
  char want[65];
  hmac_sha256_hex(key, (const uint8_t *)canonical, strlen(canonical), want);
  if (strcmp(got, want) != 0) {
    snprintf(reason, reason_cap, "invalid command signature");
    return 0;
  }
  return 1;
}

void edr_command_on_envelope(const char *command_id, const char *command_type, const uint8_t *payload,
                             size_t payload_len, const EdrSoarCommandMeta *soar_meta) {
  EdrSoarCommandMeta empty;
  memset(&empty, 0, sizeof(empty));
  const EdrSoarCommandMeta *sm = soar_meta ? soar_meta : &empty;
  const char *t = command_type ? command_type : "";
  const char *id = command_id ? command_id : "";

  char sig_reason[160];
  sig_reason[0] = 0;
  if (!command_signature_verify(id, t, payload, payload_len, sm, sig_reason, sizeof(sig_reason))) {
    s_rejected++;
    audit_both(id, sig_reason[0] ? sig_reason : "command signature rejected");
    soar_emit(id, sm, EdrCmdExecRejected, 15, sig_reason[0] ? sig_reason : "command signature rejected");
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
  if (streq(t, "kill_process") || streq(t, "kill")) {
    do_kill(id, payload, payload_len, sm);
    return;
  }
  if (streq(t, "collect_forensic") || streq(t, "forensic")) {
    do_forensic(id, payload, payload_len, sm);
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
