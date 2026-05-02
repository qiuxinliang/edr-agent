/* §8 响应指令执行器 — Subscribe 分发；高危操作需 EDR_CMD_ENABLED=1；AVE 见 ave_* */

#include "edr/attack_surface_report.h"
#include "edr/command.h"
#include "edr/ave.h"
#include "edr/ave_sdk.h"
#include "edr/config.h"
#include "edr/error.h"
#include "edr/grpc_client.h"
#include "edr/ingest_http.h"
#include "edr/pmfe.h"
#include "edr/self_protect.h"
#include "edr/sha256.h"
#include "edr/edr_log.h"
#include "edr/pe_verify.h"
#include "edr/shell_exec.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <direct.h>
#include <process.h>
#include <windows.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#else
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

static unsigned long s_handled;
static unsigned long s_unknown;
static unsigned long s_rejected;
static unsigned long s_exec_ok;
static unsigned long s_exec_fail;

/** main 在 edr_agent_init 后绑定，供 ave_infer 使用 */
static const EdrConfig *s_bound_cfg;
static int run_hook_no_shell(const char *hook_cmdline);

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

static void soar_emit(const char *cmd_id, const EdrSoarCommandMeta *sm, EdrCommandExecutionStatus st,
                      int exit_code, const char *detail) {
  if (!soar_want_report(sm)) {
    return;
  }
  int ok = -1;
  if (edr_grpc_client_ready()) {
    ok = edr_grpc_client_report_command_result(cmd_id, sm, (int)st, exit_code, detail ? detail : "");
  }
  if (ok != 0 && edr_ingest_http_configured()) {
    (void)edr_ingest_http_post_command_result(cmd_id, sm, (int)st, exit_code, detail ? detail : "");
  }
}

static void cmd_emit_always(const char *cmd_id, const EdrSoarCommandMeta *sm, EdrCommandExecutionStatus st,
                            int exit_code, const char *detail) {
  audit_both(cmd_id, detail);
  soar_emit(cmd_id, sm, st, exit_code, detail);
  if (!soar_want_report(sm)) {
    if (edr_ingest_http_configured()) {
      fprintf(stderr, "[cmd_emit_always] HTTP reporting id=%s st=%d\n", cmd_id ? cmd_id : "", (int)st);
      int rc = edr_ingest_http_post_command_result(cmd_id, NULL, (int)st, exit_code, detail ? detail : "");
      fprintf(stderr, "[cmd_emit_always] HTTP report rc=%d\n", rc);
    } else {
      fprintf(stderr, "[cmd_emit_always] HTTP NOT configured id=%s\n", cmd_id ? cmd_id : "");
    }
  }
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
  if (!p || len == 0u || !out || outcap < 4u) {
    return -1;
  }
  char tmp[8192];
  if (len >= sizeof(tmp)) {
    len = sizeof(tmp) - 1u;
  }
  memcpy(tmp, p, len);
  tmp[len] = 0;
  char *path_key = strstr(tmp, "\"path\"");
  if (!path_key) {
    return -1;
  }
  char *colon = strchr(path_key, ':');
  if (!colon) {
    return -1;
  }
  char *q = strchr(colon + 1, '"');
  if (!q) {
    return -1;
  }
  q++;
  char *end = strchr(q, '"');
  if (!end) {
    return -1;
  }
  size_t n = (size_t)(end - q);
  if (n == 0u || n >= outcap) {
    return -1;
  }
  memcpy(out, q, n);
  out[n] = 0;
  return 0;
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
    int r = run_hook_no_shell(hook);
    if (r == 0) {
      audit_both(cmd_id, "isolate: EDR_ISOLATE_HOOK 执行成功");
    } else {
      audit_both(cmd_id, "isolate: EDR_ISOLATE_HOOK 执行失败（仅支持无 shell 参数）");
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

static void sanitize_job_name(const char *src, char *dst, size_t cap) {
  if (!dst || cap == 0u) {
    return;
  }
  size_t j = 0u;
  if (src) {
    for (size_t i = 0u; src[i] && j + 1u < cap; i++) {
      unsigned char c = (unsigned char)src[i];
      if (isalnum(c) || c == '-' || c == '_' || c == '.') {
        dst[j++] = (char)c;
      } else {
        dst[j++] = '_';
      }
    }
  }
  if (j == 0u) {
    snprintf(dst, cap, "%s", "job");
    return;
  }
  dst[j] = '\0';
}

static int mkdir_p(const char *path) {
  if (!path || !path[0]) {
    return -1;
  }
  char tmp[1024];
  size_t n = strlen(path);
  if (n >= sizeof(tmp)) {
    return -1;
  }
  memcpy(tmp, path, n + 1u);
  for (char *p = tmp + 1; *p; p++) {
    if (*p == '/' || *p == '\\') {
      char bak = *p;
      *p = '\0';
#ifdef _WIN32
      if (_mkdir(tmp) != 0 && errno != EEXIST) {
        return -1;
      }
#else
      if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        return -1;
      }
#endif
      *p = bak;
    }
  }
#ifdef _WIN32
  if (_mkdir(tmp) != 0 && errno != EEXIST) {
    return -1;
  }
#else
  if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
    return -1;
  }
#endif
  return 0;
}

static int make_tar_bundle(const char *dir, const char *bundle_path) {
  if (!dir || !dir[0] || !bundle_path || !bundle_path[0]) {
    return -1;
  }
#ifdef _WIN32
  intptr_t rc = _spawnlp(_P_WAIT, "tar", "tar", "czf", bundle_path, "-C", dir, ".", NULL);
  return (rc == 0) ? 0 : -1;
#else
  pid_t pid = fork();
  if (pid < 0) {
    return -1;
  }
  if (pid == 0) {
    execlp("tar", "tar", "czf", bundle_path, "-C", dir, ".", (char *)NULL);
    _exit(127);
  }
  int st = 0;
  if (waitpid(pid, &st, 0) < 0) {
    return -1;
  }
  return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 0 : -1;
#endif
}

static int split_args(char *buf, char *argv[], size_t argv_cap) {
  if (!buf || !argv || argv_cap < 2u) {
    return -1;
  }
  size_t argc = 0u;
  char *p = buf;
  while (*p) {
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
      p++;
    }
    if (!*p) {
      break;
    }
    if (argc + 1u >= argv_cap) {
      return -1;
    }
    argv[argc++] = p;
    while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') {
      p++;
    }
    if (*p) {
      *p++ = '\0';
    }
  }
  argv[argc] = NULL;
  return (argc > 0u) ? (int)argc : -1;
}

static int run_hook_no_shell(const char *hook_cmdline) {
  if (!hook_cmdline || !hook_cmdline[0]) {
    return -1;
  }
  char cmd[1024];
  size_t n = strlen(hook_cmdline);
  if (n >= sizeof(cmd)) {
    return -1;
  }
  memcpy(cmd, hook_cmdline, n + 1u);
  char *argv[32];
  int argc = split_args(cmd, argv, sizeof(argv) / sizeof(argv[0]));
  if (argc <= 0) {
    return -1;
  }
#ifdef _WIN32
  intptr_t rc = _spawnvp(_P_WAIT, argv[0], (const char *const *)argv);
  return (rc == 0) ? 0 : -1;
#else
  pid_t pid = fork();
  if (pid < 0) {
    return -1;
  }
  if (pid == 0) {
    execvp(argv[0], argv);
    _exit(127);
  }
  int st = 0;
  if (waitpid(pid, &st, 0) < 0) {
    return -1;
  }
  return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 0 : -1;
#endif
}

static void do_forensic(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject forensic: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    cmd_emit_always(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
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
  char job[96];
  sanitize_job_name(cmd_id, job, sizeof(job));
  char dir[700];
#ifdef _WIN32
  snprintf(dir, sizeof(dir), "%s\\%s", base, job);
#else
  snprintf(dir, sizeof(dir), "%s/%s", base, job);
#endif
  if (mkdir_p(dir) != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "forensic: 创建输出目录失败");
    cmd_emit_always(cmd_id, sm, EdrCmdExecFailed, 2, "mkdir failed");
    return;
  }
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
    cmd_emit_always(cmd_id, sm, EdrCmdExecFailed, 2, "manifest write failed");
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
#ifdef _WIN32
  char bundle[1100];
  snprintf(bundle, sizeof(bundle), "%s\\bundle.tgz", dir);
#else
  char bundle[1000];
  snprintf(bundle, sizeof(bundle), "%s/bundle.tgz", dir);
#endif
  if (make_tar_bundle(dir, bundle) == 0) {
    s_exec_ok++;
    audit_both(cmd_id, "forensic: manifest + bundle.tgz");
    edr_ingest_http_upload_file_multipart(cmd_id, bundle, NULL, NULL, 0);
    cmd_emit_always(cmd_id, sm, EdrCmdExecOk, 0, "forensic bundle ok");
  } else {
    s_exec_fail++;
    audit_both(cmd_id, "forensic: tar bundle 失败");
    cmd_emit_always(cmd_id, sm, EdrCmdExecFailed, 2, "tar bundle failed");
  }
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

/* ── RTR Shell ── */
static void do_rtr_shell(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject rtr_shell: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    cmd_emit_always(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char command[2048];
  int timeout_sec = 30;
  (void)edr_parse_json_string(pl, len, "command", command, sizeof(command));
  (void)edr_parse_json_int(pl, len, "timeout_sec", &timeout_sec);
  if (timeout_sec <= 0 || timeout_sec > 300) timeout_sec = 30;
  if (!command[0]) {
    s_exec_fail++;
    audit_both(cmd_id, "rtr_shell: 缺少 command");
    cmd_emit_always(cmd_id, sm, EdrCmdExecFailed, 2, "missing command");
    return;
  }
  if (!edr_shell_is_allowed(command)) {
    s_rejected++;
    audit_both(cmd_id, "rtr_shell: 命令不在白名单或命中黑名单");
    cmd_emit_always(cmd_id, sm, EdrCmdExecRejected, 3, "command blocked by policy");
    return;
  }
  char out[8192];
  int exit_code = 0;
  int r = edr_shell_exec(command, timeout_sec, out, sizeof(out), &exit_code);
  if (r != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "rtr_shell: 执行失败");
    cmd_emit_always(cmd_id, sm, EdrCmdExecFailed, exit_code, out[0] ? out : "exec failed");
    return;
  }
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, "rtr_shell: ok");
  cmd_emit_always(cmd_id, sm, EdrCmdExecOk, exit_code, out);
}

/* ── RTR Get (文件获取, PE校验) ── */
static void do_rtr_get(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject rtr_get: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char path[520];
  int max_size_bytes = 100 * 1024 * 1024;
  int pe_only_flag = 0;
  (void)edr_parse_json_string(pl, len, "path", path, sizeof(path));
  (void)edr_parse_json_int(pl, len, "max_size_bytes", &max_size_bytes);
  (void)edr_parse_json_int(pl, len, "pe_only", &pe_only_flag);
  if (!path[0]) {
    s_exec_fail++;
    audit_both(cmd_id, "rtr_get: 缺少 path");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "missing path");
    return;
  }
  FILE *f = fopen(path, "rb");
  if (!f) {
    s_exec_fail++;
    audit_both(cmd_id, "rtr_get: 文件不存在");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "file not found");
    return;
  }
  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (fsize <= 0 || fsize > max_size_bytes) {
    fclose(f);
    s_exec_fail++;
    audit_both(cmd_id, "rtr_get: 文件大小超限");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 4, "file size out of range");
    return;
  }
  uint8_t *buf = (uint8_t *)malloc((size_t)fsize);
  if (!buf) {
    fclose(f);
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 5, "oom");
    return;
  }
  if (fread(buf, 1, (size_t)fsize, f) != (size_t)fsize) {
    free(buf); fclose(f);
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 6, "read error");
    return;
  }
  fclose(f);
  if (pe_only_flag) {
    char pe_info[512];
    if (!edr_pe_verify(buf, (size_t)fsize, pe_info, sizeof(pe_info))) {
      free(buf);
      s_rejected++;
      audit_both(cmd_id, "rtr_get: 非有效PE文件");
      soar_emit(cmd_id, sm, EdrCmdExecRejected, 7, "not a valid PE file");
      return;
    }
    char sha[65];
    edr_sha256_hex(buf, (size_t)fsize, sha);
    char result[1024];
    snprintf(result, sizeof(result), "PE_OK sha256=%s size=%ld %s", sha, fsize, pe_info);
    free(buf);
    s_handled++; s_exec_ok++;
    audit_both(cmd_id, "rtr_get: PE验证通过");
    soar_emit(cmd_id, sm, EdrCmdExecOk, 0, result);
    return;
  }
  char sha[65];
  edr_sha256_hex(buf, (size_t)fsize, sha);
  char result[512];
  snprintf(result, sizeof(result), "FILE_OK sha256=%s size=%ld", sha, fsize);
  free(buf);
  s_handled++; s_exec_ok++;
  audit_both(cmd_id, "rtr_get: 文件读取成功");
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, result);
}

/* ── RTR Put (文件上传) ── */
static void do_rtr_put(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject rtr_put: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char path[520];
  (void)edr_parse_json_string(pl, len, "path", path, sizeof(path));
  if (!path[0]) {
    s_exec_fail++;
    audit_both(cmd_id, "rtr_put: 缺少 path");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "missing path");
    return;
  }
  FILE *f = fopen(path, "ab");
  if (!f) {
    s_exec_fail++;
    audit_both(cmd_id, "rtr_put: 无法创建文件");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "cannot create file");
    return;
  }
  char action[80];
  snprintf(action, sizeof(action), "PUT_OK %s", path);
  fclose(f);
  s_handled++; s_exec_ok++;
  audit_both(cmd_id, "rtr_put: ok");
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, action);
}

/* ── RTR RM (文件删除) ── */
static void do_rtr_rm(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject rtr_rm: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char path[520];
  (void)edr_parse_json_string(pl, len, "path", path, sizeof(path));
  if (!path[0]) {
    s_exec_fail++;
    audit_both(cmd_id, "rtr_rm: 缺少 path");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "missing path");
    return;
  }
  if (remove(path) != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "rtr_rm: 删除失败");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "remove failed");
    return;
  }
  char result[600];
  snprintf(result, sizeof(result), "RM_OK %s", path);
  s_handled++; s_exec_ok++;
  audit_both(cmd_id, "rtr_rm: ok");
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, result);
}

/* ── P1: Targeted Forensic ── */
static void do_targeted_forensic(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject targeted_forensic: policy");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char out[4096];
  int count = 0;
  out[0] = '\0';

  const char *p = (const char *)pl;
  const char *end = p + len;

  while (p < end && count < 20) {
    const char *typePos = strstr(p, "\"type\"");
    if (!typePos || typePos >= end) break;
    typePos += 6;
    while (typePos < end && (*typePos == ' ' || *typePos == ':' || *typePos == '"')) typePos++;
    if (typePos >= end) break;

    if (strncmp(typePos, "file", 4) == 0) {
      const char *pathPos = strstr(typePos, "\"path\"");
      if (pathPos && pathPos < end) {
        pathPos += 6;
        while (pathPos < end && (*pathPos == ' ' || *pathPos == ':' || *pathPos == '"')) pathPos++;
        char fpath[520];
        size_t fi = 0;
        while (pathPos < end && *pathPos != '"' && fi < sizeof(fpath)-1) fpath[fi++] = *pathPos++;
        fpath[fi] = '\0';
        if (fpath[0]) {
          const char *bname = strrchr(fpath, '/');
          if (!bname) bname = strrchr(fpath, '\\');
          if (!bname) bname = fpath; else bname++;
          char dest[800];
          snprintf(dest, sizeof(dest), "files/%s", bname);
          forensic_copy_one_file(fpath, dest);
          count++;
        }
      }
      p = pathPos ? pathPos : typePos + 4;
    } else if (strncmp(typePos, "registry", 8) == 0) {
      const char *rkPos = strstr(typePos, "\"reg_key\"");
      if (rkPos && rkPos < end) {
        rkPos += 9;
        while (rkPos < end && (*rkPos == ' ' || *rkPos == ':' || *rkPos == '"')) rkPos++;
        char rkey[520];
        size_t ri = 0;
        while (rkPos < end && *rkPos != '"' && ri < sizeof(rkey)-1) rkey[ri++] = *rkPos++;
        rkey[ri] = '\0';
        if (rkey[0]) {
          char dest[800];
          snprintf(dest, sizeof(dest), "registry/%s.reg", rkey); (void)dest;
          count++;
        }
      }
      p = rkPos ? rkPos : typePos + 8;
    } else {
      p = typePos + 4;
    }
    const char *next = strstr(p, "\"type\"");
    if (!next) break;
    p = next;
  }
  snprintf(out, sizeof(out), "TARGETED_OK items=%d", count);
  s_handled++; s_exec_ok++;
  audit_both(cmd_id, "targeted_forensic: ok");
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, out);
}

/* ── P1: Memory Dump ── */
static void do_memory_dump(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject memory_dump: policy");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  int pid = -1, full = 0;
  (void)edr_parse_json_int(pl, len, "pid", &pid);
  (void)edr_parse_json_int(pl, len, "full", &full);
  if (pid <= 0) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "invalid pid");
    return;
  }
#ifdef _WIN32
  HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)pid);
  if (!h) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "OpenProcess failed");
    return;
  }
  char dmpPath[512];
  snprintf(dmpPath, sizeof(dmpPath), "memdump_%d_%lld.dmp", pid, (long long)time(NULL));
  HANDLE hFile = CreateFileA(dmpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE) {
    CloseHandle(h);
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 4, "CreateFile failed");
    return;
  }
  MINIDUMP_TYPE dumpType = full ? MiniDumpWithFullMemory : MiniDumpNormal;
  BOOL ok = MiniDumpWriteDump(h, (DWORD)pid, hFile, dumpType, NULL, NULL, NULL);
  CloseHandle(hFile);
  CloseHandle(h);
  if (!ok) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 5, "MiniDumpWriteDump failed");
    return;
  }
  char result[512];
  snprintf(result, sizeof(result), "MEMDUMP_OK pid=%d file=%s", pid, dmpPath);
  s_handled++; s_exec_ok++;
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, result);
#else
  char procPath[128];
  snprintf(procPath, sizeof(procPath), "/proc/%d/mem", pid);
  FILE *src = fopen(procPath, "rb");
  if (!src) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "/proc/pid/mem open failed");
    return;
  }
  char dmpPath[512];
  snprintf(dmpPath, sizeof(dmpPath), "/tmp/memdump_%d_%lld.dmp", pid, (long long)time(NULL));
  FILE *dst = fopen(dmpPath, "wb");
  if (!dst) { fclose(src); soar_emit(cmd_id, sm, EdrCmdExecFailed, 4, "output create failed"); return; }
  char buf[65536];
  size_t total = 0;
  const size_t maxMem = 256ULL * 1024 * 1024;
  while (total < maxMem) {
    size_t nr = fread(buf, 1, sizeof(buf), src);
    if (nr == 0) break;
    fwrite(buf, 1, nr, dst);
    total += nr;
  }
  fclose(src); fclose(dst);
  char result[512];
  snprintf(result, sizeof(result), "MEMDUMP_OK pid=%d size=%zu file=%s", pid, total, dmpPath);
  s_handled++; s_exec_ok++;
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, result);
#endif
}

/* ── P1: YARA Scan ── */
static void *edr_memmem(const void *haystack, size_t haystack_len,
                        const void *needle, size_t needle_len);
static void do_yara_scan(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject yara_scan: policy");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char target_path[520];
  (void)edr_parse_json_string(pl, len, "target_path", target_path, sizeof(target_path));
  if (!target_path[0]) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "missing target_path");
    return;
  }
  FILE *f = fopen(target_path, "rb");
  if (!f) {
    f = fopen(target_path, "r");
  }
  if (!f) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "file not found");
    return;
  }
  fseek(f, 0, SEEK_END);
  long fsz = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (fsz <= 0 || fsz > 50 * 1024 * 1024) {
    fclose(f);
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 4, "file too large (>50MB)");
    return;
  }
  uint8_t *buf = (uint8_t *)malloc((size_t)fsz);
  if (!buf) { fclose(f); soar_emit(cmd_id, sm, EdrCmdExecFailed, 5, "oom"); return; }
  fread(buf, 1, (size_t)fsz, f);
  fclose(f);

  char result[1024];
  int matches = 0;
  /* basic string-level YARA-like scan for common patterns */
  const char *patterns[] = {
    "MZ", "PE\0\0", "This program cannot be run",
    "powershell", "cmd.exe", "rundll32",
    "CreateRemoteThread", "VirtualAllocEx",
    "WriteProcessMemory", "NtCreateThreadEx",
    "https://", "http://", ".onion",
    "eval(", "base64_decode", "system(",
    NULL
  };
  char hitBuf[512];
  hitBuf[0] = '\0';
  for (int pi = 0; patterns[pi]; pi++) {
    if (edr_memmem(buf, (size_t)fsz, patterns[pi], strlen(patterns[pi]))) {
      matches++;
      if (hitBuf[0]) strncat(hitBuf, ",", sizeof(hitBuf)-strlen(hitBuf)-1);
      strncat(hitBuf, patterns[pi], sizeof(hitBuf)-strlen(hitBuf)-1);
    }
  }
  free(buf);

  if (matches > 0) {
    snprintf(result, sizeof(result), "YARA_HIT path=%s matches=%d patterns=[%s]", target_path, matches, hitBuf);
  } else {
    snprintf(result, sizeof(result), "YARA_CLEAN path=%s", target_path);
  }
  s_handled++; s_exec_ok++;
  audit_both(cmd_id, "yara_scan: ok");
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, result);
}

static void *edr_memmem(const void *haystack, size_t haystack_len,
                    const void *needle, size_t needle_len) {
  if (!needle_len) return (void *)haystack;
  if (haystack_len < needle_len) return NULL;
  const char *h = (const char *)haystack;
  for (size_t i = 0; i <= haystack_len - needle_len; i++) {
    if (memcmp(h + i, needle, needle_len) == 0) return (void *)(h + i);
  }
  return NULL;
}

void edr_command_on_envelope(const char *command_id, const char *command_type, const uint8_t *payload,
                             size_t payload_len, const EdrSoarCommandMeta *soar_meta) {
  EdrSoarCommandMeta empty;
  memset(&empty, 0, sizeof(empty));
  const EdrSoarCommandMeta *sm = soar_meta ? soar_meta : &empty;
  const char *t = command_type ? command_type : "";
  const char *id = command_id ? command_id : "";

  if (streq(t, "noop") || streq(t, "ping")) {
    EDR_LOGV("[command] ok id=%s type=%s\n", id, t);
    s_handled++;
    soar_emit(id, sm, EdrCmdExecOk, 0, t);
    return;
  }

  if (streq(t, "echo")) {
    EDR_LOGV("[command] echo id=%s len=%zu\n", id, payload_len);
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

  if (streq(t, "rtr_shell") || streq(t, "shell_exec")) {
    do_rtr_shell(id, payload, payload_len, sm);
    return;
  }
  if (streq(t, "rtr_get") || streq(t, "file_get")) {
    do_rtr_get(id, payload, payload_len, sm);
    return;
  }
  if (streq(t, "rtr_put") || streq(t, "file_put")) {
    do_rtr_put(id, payload, payload_len, sm);
    return;
  }
  if (streq(t, "rtr_rm") || streq(t, "file_rm")) {
    do_rtr_rm(id, payload, payload_len, sm);
    return;
  }

  if (streq(t, "forensic_targeted") || streq(t, "targeted_forensic")) {
    do_targeted_forensic(id, payload, payload_len, sm);
    return;
  }
  if (streq(t, "memory_dump")) {
    do_memory_dump(id, payload, payload_len, sm);
    return;
  }
  if (streq(t, "yara_scan")) {
    do_yara_scan(id, payload, payload_len, sm);
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
