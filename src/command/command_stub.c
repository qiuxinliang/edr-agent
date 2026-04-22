/* §8 响应指令执行器 — Subscribe 分发；高危操作需 EDR_CMD_ENABLED=1；AVE 见 ave_* */

#include "edr/attack_surface_report.h"
#include "edr/command.h"
#include "edr/ave.h"
#include "edr/ave_sdk.h"
#include "edr/config.h"
#include "edr/error.h"
#include "edr/grpc_client.h"
#include "edr/pmfe.h"
#include "edr/self_protect.h"
#include "edr/sha256.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <winreg.h>
#include <wchar.h>
#else
#include <errno.h>
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

void edr_command_bind_config(const struct EdrConfig *cfg) { s_bound_cfg = cfg; }

static int streq(const char *a, const char *b) { return a && b && strcmp(a, b) == 0; }

#ifdef _WIN32
/** 递归创建目录（等价 mkdir -p），不经 shell。 */
static int edr_mkdir_p_win(const char *path) {
  char t[768];
  if (!path || !path[0] || snprintf(t, sizeof(t), "%s", path) >= (int)sizeof(t)) {
    return -1;
  }
  size_t i = 0;
  if (t[0] && t[1] == ':' && (t[2] == '\\' || t[2] == '/')) {
    i = 3;
  }
  for (;;) {
    char *slash = strchr(t + i, '\\');
    if (!slash) {
      break;
    }
    *slash = '\0';
    if (t[0] && !CreateDirectoryA(t, NULL)) {
      DWORD e = GetLastError();
      if (e != ERROR_ALREADY_EXISTS) {
        *slash = '\\';
        return -1;
      }
    }
    *slash = '\\';
    i = (size_t)(slash - t + 1u);
  }
  if (!CreateDirectoryA(t, NULL)) {
    DWORD e = GetLastError();
    if (e != ERROR_ALREADY_EXISTS) {
      return -1;
    }
  }
  return 0;
}

/** 取证打包：直接拉起 System32\\tar.exe，避免经 cmd /c 拼接命令行。 */
static int edr_forensic_run_tar_czf(const char *job_dir) {
  if (!job_dir || !job_dir[0]) {
    return -1;
  }
  wchar_t wdir[768];
  if (MultiByteToWideChar(CP_UTF8, 0, job_dir, -1, wdir, 768) == 0 &&
      MultiByteToWideChar(CP_ACP, 0, job_dir, -1, wdir, 768) == 0) {
    return -1;
  }
  wchar_t sys[MAX_PATH];
  UINT nd = GetSystemDirectoryW(sys, MAX_PATH);
  if (nd == 0 || nd >= MAX_PATH) {
    return -1;
  }
  wchar_t tar_exe[MAX_PATH + 16];
  if (nd + 9u >= sizeof(tar_exe) / sizeof(tar_exe[0])) {
    return -1;
  }
  memcpy(tar_exe, sys, (size_t)nd * sizeof(wchar_t));
  tar_exe[nd] = L'\\';
  wcscpy(tar_exe + nd + 1u, L"tar.exe");

  char tar_exe_utf8[MAX_PATH * 3];
  char bundle_utf8[900];
  char cmd8[2048];
  if (WideCharToMultiByte(CP_UTF8, 0, tar_exe, -1, tar_exe_utf8, (int)sizeof(tar_exe_utf8), NULL, NULL) == 0) {
    return -1;
  }
  if (snprintf(bundle_utf8, sizeof(bundle_utf8), "%s\\bundle.tgz", job_dir) >= (int)sizeof(bundle_utf8)) {
    return -1;
  }
  if (snprintf(cmd8, sizeof(cmd8), "\"%s\" czf \"%s\" -C \"%s\" .", tar_exe_utf8, bundle_utf8, job_dir) >=
      (int)sizeof(cmd8)) {
    return -1;
  }
  wchar_t cmdw[2048];
  if (MultiByteToWideChar(CP_UTF8, 0, cmd8, -1, cmdw, 2048) == 0) {
    return -1;
  }

  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  memset(&pi, 0, sizeof(pi));
  if (!CreateProcessW(NULL, cmdw, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, wdir, &si, &pi)) {
    return -1;
  }
  (void)WaitForSingleObject(pi.hProcess, 120000);
  DWORD code = 1;
  (void)GetExitCodeProcess(pi.hProcess, &code);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return code == 0 ? 0 : -1;
}
#else
/** 递归创建目录（等价 mkdir -p），不经 shell。 */
static int edr_mkdir_p_posix(const char *path) {
  char buf[768];
  if (!path || !path[0]) {
    return -1;
  }
  size_t len = strlen(path);
  if (len >= sizeof(buf)) {
    return -1;
  }
  memcpy(buf, path, len + 1u);
  for (char *p = buf + 1u; *p; p++) {
    if (*p != '/') {
      continue;
    }
    *p = '\0';
    if (buf[0] && mkdir(buf, 0755) != 0 && errno != EEXIST) {
      return -1;
    }
    *p = '/';
  }
  if (mkdir(buf, 0755) != 0 && errno != EEXIST) {
    return -1;
  }
  return 0;
}

/** 取证打包：execvp("tar", …)，不经 shell（与 Windows CreateProcess 路径对齐）。 */
static int edr_forensic_run_tar_czf_posix(const char *job_dir) {
  if (!job_dir || !job_dir[0]) {
    return -1;
  }
  char bundle[900];
  if (snprintf(bundle, sizeof(bundle), "%s/bundle.tgz", job_dir) >= (int)sizeof(bundle)) {
    return -1;
  }
  char cwd_arg[700];
  if (snprintf(cwd_arg, sizeof(cwd_arg), "%s", job_dir) >= (int)sizeof(cwd_arg)) {
    return -1;
  }
  pid_t pid = fork();
  if (pid < 0) {
    return -1;
  }
  if (pid == 0) {
    int fd = open("/dev/null", O_WRONLY);
    if (fd >= 0) {
      (void)dup2(fd, STDERR_FILENO);
      (void)close(fd);
    }
    char *argv[] = {"tar", "czf", bundle, "-C", cwd_arg, ".", NULL};
    (void)execvp("tar", argv);
    _exit(127);
  }
  int st = 0;
  if (waitpid(pid, &st, 0) < 0) {
    return -1;
  }
  return WIFEXITED(st) && WEXITSTATUS(st) == 0 ? 0 : -1;
}
#endif

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
  (void)edr_grpc_client_report_command_result(cmd_id, sm, (int)st, exit_code, detail ? detail : "");
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

/** JSON 字符串片段内 **`\\` `"`** 等常见转义（§P1 结构化 payload 路径）。 */
static void forensic_unescape_json_string(char *out, size_t outcap, const char *in, size_t inlen) {
  size_t w = 0;
  for (size_t i = 0; i < inlen && w + 1u < outcap; i++) {
    if (in[i] == '\\' && i + 1u < inlen) {
      unsigned char c = (unsigned char)in[i + 1u];
      if (c == '\\' || c == '"') {
        out[w++] = (char)c;
        i++;
        continue;
      }
      if (c == 'n') {
        out[w++] = '\n';
        i++;
        continue;
      }
      if (c == 'r') {
        out[w++] = '\r';
        i++;
        continue;
      }
      if (c == 't') {
        out[w++] = '\t';
        i++;
        continue;
      }
    }
    out[w++] = in[i];
  }
  out[w] = '\0';
}

static int forensic_payload_trimmed_starts_json(const uint8_t *p, size_t len) {
  size_t i = 0;
  while (i < len && (p[i] == ' ' || p[i] == '\t' || p[i] == '\r' || p[i] == '\n')) {
    i++;
  }
  return i < len && p[i] == '{';
}

static void forensic_manifest_declared_extensions(FILE *f, const uint8_t *pl, size_t len) {
  if (!f || !pl || len == 0u) {
    return;
  }
  char tmp[4096];
  if (len >= sizeof(tmp)) {
    len = sizeof(tmp) - 1u;
  }
  memcpy(tmp, pl, len);
  tmp[len] = '\0';
  if (strstr(tmp, "\"registry_keys\"")) {
    fprintf(f, "registry_keys_declared_in_payload=1\n");
  }
  if (strstr(tmp, "\"memory_regions\"")) {
    fprintf(f, "memory_regions_declared_in_payload=1\n");
  }
}

static void forensic_manifest_user_volume(FILE *f) {
  if (!f) {
    return;
  }
#ifdef _WIN32
  {
    char un[256];
    DWORD ul = sizeof(un);
    if (GetUserNameA(un, &ul)) {
      un[sizeof(un) - 1u] = '\0';
      fprintf(f, "windows_username=%s\n", un);
    }
  }
  {
    char sysdir[MAX_PATH];
    if (GetWindowsDirectoryA(sysdir, (UINT)sizeof(sysdir)) > 0 && sysdir[0] && sysdir[1] == ':') {
      char root[8];
      (void)snprintf(root, sizeof(root), "%c:\\", sysdir[0]);
      DWORD vsn = 0, maxcomp = 0, fsflags = 0;
      char vn[MAX_PATH], fsn[MAX_PATH];
      if (GetVolumeInformationA(root, vn, (DWORD)sizeof(vn), &vsn, &maxcomp, &fsflags, fsn, (DWORD)sizeof(fsn))) {
        fprintf(f, "boot_volume_serial_number=0x%08lx\n", (unsigned long)vsn);
      }
    }
  }
#else
  {
    const char *u = getenv("USER");
    if (u && u[0]) {
      fprintf(f, "posix_user=%s\n", u);
    }
  }
#endif
}

/** 从 **`{"paths":["a","b"]}`** 复制文件（需 **`EDR_FORENSIC_COPY_PATHS=1`**）。 */
static void forensic_copy_paths_from_json(const char *jobdir, const uint8_t *pl, size_t len) {
  const char *e = getenv("EDR_FORENSIC_COPY_PATHS");
  if (!e || e[0] != '1' || !pl || len == 0u) {
    return;
  }
  char tmp[8192];
  if (len >= sizeof(tmp)) {
    len = sizeof(tmp) - 1u;
  }
  memcpy(tmp, pl, len);
  tmp[len] = '\0';
  char *paths = strstr(tmp, "\"paths\"");
  if (!paths) {
    return;
  }
  char *lb = strchr(paths, '[');
  if (!lb) {
    return;
  }
  char *p = lb + 1;
  int idx = 0;
  for (;;) {
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
      p++;
    }
    if (*p == '\0' || *p == ']') {
      break;
    }
    if (*p == ',') {
      p++;
      continue;
    }
    if (*p != '"') {
      break;
    }
    p++;
    char *end = strchr(p, '"');
    if (!end) {
      break;
    }
    size_t rawn = (size_t)(end - p);
    char pathbuf[2048];
    forensic_unescape_json_string(pathbuf, sizeof(pathbuf), p, rawn);
    p = end + 1;
    if (!pathbuf[0]) {
      continue;
    }
    if (idx >= 100) {
      break;
    }
    char dst[900];
#ifdef _WIN32
    (void)snprintf(dst, sizeof(dst), "%s\\copied_json_%02d", jobdir, idx++);
#else
    (void)snprintf(dst, sizeof(dst), "%s/copied_json_%02d", jobdir, idx++);
#endif
    (void)forensic_copy_one_file(pathbuf, dst);
  }
}

#ifdef _WIN32
static void forensic_manifest_append_line(const char *manifest_path, const char *line) {
  if (!manifest_path || !line) {
    return;
  }
  FILE *a = fopen(manifest_path, "a");
  if (!a) {
    return;
  }
  fputs(line, a);
  if (line[0] && line[strlen(line) - 1u] != '\n') {
    fputc('\n', a);
  }
  fclose(a);
}

static int forensic_registry_split_root(const char *path_in, HKEY *root, char *sub, size_t subsz, char *tag, size_t tagsz) {
  char p[1024];
  if (!path_in || !path_in[0] || !root || !sub || subsz < 2u || !tag || tagsz < 4u) {
    return -1;
  }
  (void)snprintf(p, sizeof(p), "%s", path_in);
  for (char *c = p; *c; c++) {
    if (*c == '/') {
      *c = '\\';
    }
  }
  static const struct {
    const char *pfx;
    HKEY hk;
    const char *tg;
  } map[] = {
      {"HKEY_LOCAL_MACHINE\\", HKEY_LOCAL_MACHINE, "HKLM"},
      {"HKLM\\", HKEY_LOCAL_MACHINE, "HKLM"},
      {"HKEY_CURRENT_USER\\", HKEY_CURRENT_USER, "HKCU"},
      {"HKCU\\", HKEY_CURRENT_USER, "HKCU"},
      {"HKEY_CLASSES_ROOT\\", HKEY_CLASSES_ROOT, "HKCR"},
      {"HKCR\\", HKEY_CLASSES_ROOT, "HKCR"},
      {"HKEY_USERS\\", HKEY_USERS, "HKU"},
      {"HKU\\", HKEY_USERS, "HKU"},
      {"HKEY_CURRENT_CONFIG\\", HKEY_CURRENT_CONFIG, "HKCC"},
      {"HKCC\\", HKEY_CURRENT_CONFIG, "HKCC"},
  };
  for (size_t k = 0; k < sizeof(map) / sizeof(map[0]); k++) {
    size_t n = strlen(map[k].pfx);
    if (_strnicmp(p, map[k].pfx, n) == 0) {
      *root = map[k].hk;
      (void)snprintf(tag, tagsz, "%s", map[k].tg);
      (void)snprintf(sub, subsz, "%s", p + n);
      return 0;
    }
  }
  return -1;
}

static void forensic_reg_sanitize_filename(const char *path_in, char *out, size_t outsz) {
  size_t w = 0;
  for (const char *s = path_in; *s && w + 2u < outsz; s++) {
    char c = *s;
    if (c == '\\' || c == '/' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|') {
      out[w++] = '_';
    } else {
      out[w++] = c;
    }
  }
  out[w] = '\0';
}

#ifndef KEY_WOW64_64KEY
#define KEY_WOW64_64KEY 0x0100
#endif
#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

static void forensic_reg_dump_recursive(FILE *out, HKEY parent, const char *disp_path, int depth, unsigned *nodes_budget) {
  if (!out || !nodes_budget || *nodes_budget > 400u || depth > 8) {
    return;
  }
  HKEY hk = NULL;
  REGSAM sam = KEY_READ;
#if defined(_WIN64)
  sam |= KEY_WOW64_64KEY;
#endif
  if (RegOpenKeyExA(parent, disp_path, 0, sam, &hk) != ERROR_SUCCESS) {
    fprintf(out, "# open failed: %s\n", disp_path);
    (*nodes_budget)++;
    return;
  }
  fprintf(out, "==== %s ====\n", disp_path);
  (*nodes_budget)++;

  DWORD nvals = 0, maxdata = 0;
  (void)RegQueryInfoKeyA(hk, NULL, NULL, NULL, NULL, NULL, NULL, &nvals, NULL, &maxdata, NULL, NULL);
  if (maxdata > 65536u) {
    maxdata = 65536u;
  }
  char vname[512];
  for (DWORD vi = 0u; vi < nvals && *nodes_budget <= 400u; vi++) {
    DWORD vnlen = (DWORD)sizeof(vname);
    DWORD typ = 0;
    DWORD dsz = maxdata + 1u;
    if (dsz < 4u) {
      dsz = 4u;
    }
    uint8_t *buf = (uint8_t *)malloc(dsz);
    if (!buf) {
      continue;
    }
    LONG rr = RegEnumValueA(hk, vi, vname, &vnlen, NULL, &typ, buf, &dsz);
    if (rr != ERROR_SUCCESS) {
      free(buf);
      continue;
    }
    fprintf(out, "  value name=\"%s\" type=%lu size=%lu\n", vname[0] ? vname : "(default)", (unsigned long)typ,
            (unsigned long)dsz);
    if (typ == REG_SZ || typ == REG_EXPAND_SZ) {
      buf[dsz < 4095u ? dsz : 4095u] = '\0';
      fprintf(out, "    data=\"%s\"\n", (char *)buf);
    } else if (typ == REG_DWORD && dsz >= 4u) {
      fprintf(out, "    dword=0x%08lx\n", (unsigned long)*(const uint32_t *)buf);
    } else if (typ == REG_QWORD && dsz >= 8u) {
      uint64_t q = *(const uint64_t *)buf;
      fprintf(out, "    qword=0x%016llx\n", (unsigned long long)q);
    } else {
      fprintf(out, "    (binary truncated)\n");
    }
    free(buf);
  }

  char sk[256];
  DWORD kidx = 0;
  while (*nodes_budget <= 400u && kidx < 80u) {
    DWORD sklen = (DWORD)sizeof(sk);
    FILETIME ft;
    LONG rk = RegEnumKeyExA(hk, kidx, sk, &sklen, NULL, NULL, NULL, &ft);
    if (rk == ERROR_NO_MORE_ITEMS) {
      break;
    }
    if (rk != ERROR_SUCCESS) {
      kidx++;
      continue;
    }
    kidx++;
    char child_disp[768];
    if (disp_path[0]) {
      (void)snprintf(child_disp, sizeof(child_disp), "%s\\%s", disp_path, sk);
    } else {
      (void)snprintf(child_disp, sizeof(child_disp), "%s", sk);
    }
    forensic_reg_dump_recursive(out, parent, child_disp, depth + 1, nodes_budget);
  }
  RegCloseKey(hk);
}

static void forensic_copy_registry_keys_from_json(const char *jobdir, const char *manifest_path, const uint8_t *pl,
                                                  size_t len, int *out_files, int *had_error) {
  (void)manifest_path;
  const char *e = getenv("EDR_FORENSIC_REGISTRY_DUMP");
  if (!e || e[0] != '1' || !pl || len == 0u || !jobdir || !out_files || !had_error) {
    return;
  }
  char tmp[8192];
  if (len >= sizeof(tmp)) {
    len = sizeof(tmp) - 1u;
  }
  memcpy(tmp, pl, len);
  tmp[len] = '\0';
  if (!strstr(tmp, "\"registry_keys\"")) {
    return;
  }
  char *keys = strstr(tmp, "\"registry_keys\"");
  if (!keys) {
    return;
  }
  char *lb = strchr(keys, '[');
  if (!lb) {
    *had_error = 1;
    return;
  }
  char *p = lb + 1;
  int idx = 0;
  for (;;) {
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
      p++;
    }
    if (*p == '\0' || *p == ']') {
      break;
    }
    if (*p == ',') {
      p++;
      continue;
    }
    if (*p != '"') {
      break;
    }
    p++;
    char *end = strchr(p, '"');
    if (!end) {
      break;
    }
    size_t rawn = (size_t)(end - p);
    char pathbuf[2048];
    forensic_unescape_json_string(pathbuf, sizeof(pathbuf), p, rawn);
    p = end + 1;
    if (!pathbuf[0]) {
      continue;
    }
    if (idx >= 32) {
      break;
    }
    HKEY root = NULL;
    char sub[1024];
    char tag[16];
    if (forensic_registry_split_root(pathbuf, &root, sub, sizeof(sub), tag, sizeof(tag)) != 0) {
      *had_error = 1;
      idx++;
      continue;
    }
    if (!sub[0]) {
      *had_error = 1;
      idx++;
      continue;
    }
    char safe[180];
    forensic_reg_sanitize_filename(pathbuf, safe, sizeof(safe));
    char outpath[900];
    (void)snprintf(outpath, sizeof(outpath), "%s\\registry_%02d_%s.txt", jobdir, idx++, safe);
    FILE *out = fopen(outpath, "w");
    if (!out) {
      *had_error = 1;
      continue;
    }
    fprintf(out, "# edr forensic registry export\n# source=%s\n# hive=%s\n\n", pathbuf, tag);
    unsigned budget = 0;
    forensic_reg_dump_recursive(out, root, sub[0] ? sub : "", 0, &budget);
    fclose(out);
    (*out_files)++;
  }
}

static int forensic_mem_parse_one(const char *obj_start, const char *obj_end, DWORD *pid, uint64_t *base, size_t *sz) {
  const char *slice_end = obj_end;
  char slice[512];
  size_t n = (size_t)(slice_end - obj_start);
  if (n >= sizeof(slice)) {
    n = sizeof(slice) - 1u;
  }
  memcpy(slice, obj_start, n);
  slice[n] = '\0';

  *pid = 0;
  *base = 0u;
  *sz = 0u;
  const char *kp = strstr(slice, "\"pid\"");
  if (!kp) {
    return -1;
  }
  kp = strchr(kp, ':');
  if (!kp) {
    return -1;
  }
  kp++;
  while (*kp == ' ' || *kp == '\t') {
    kp++;
  }
  *pid = (DWORD)strtoul(kp, (char **)&kp, 10);
  const char *bp = strstr(slice, "\"base\"");
  if (!bp) {
    return -1;
  }
  bp = strchr(bp, ':');
  if (!bp) {
    return -1;
  }
  bp++;
  while (*bp == ' ' || *bp == '\t') {
    bp++;
  }
  if (*bp == '"') {
    bp++;
  }
  *base = strtoull(bp, (char **)&bp, 0);
  const char *sp = strstr(slice, "\"size\"");
  if (!sp) {
    return -1;
  }
  sp = strchr(sp, ':');
  if (!sp) {
    return -1;
  }
  sp++;
  while (*sp == ' ' || *sp == '\t') {
    sp++;
  }
  *sz = (size_t)strtoull(sp, NULL, 10);
  if (*pid == 0u || *sz == 0u || *sz > (size_t)(16u * 1024u * 1024u)) {
    return -1;
  }
  return 0;
}

static void forensic_dump_memory_regions_from_json(const char *jobdir, const uint8_t *pl, size_t len, int *out_files,
                                                   int *had_error) {
  const char *e = getenv("EDR_FORENSIC_MEMORY_DUMP");
  if (!e || e[0] != '1' || !pl || len == 0u || !jobdir || !out_files || !had_error) {
    return;
  }
  char tmp[8192];
  if (len >= sizeof(tmp)) {
    len = sizeof(tmp) - 1u;
  }
  memcpy(tmp, pl, len);
  tmp[len] = '\0';
  if (!strstr(tmp, "\"memory_regions\"")) {
    return;
  }
  char *mr = strstr(tmp, "\"memory_regions\"");
  if (!mr) {
    return;
  }
  char *lb = strchr(mr, '[');
  if (!lb) {
    *had_error = 1;
    return;
  }
  const char *p = lb + 1;
  int idx = 0;
  for (;;) {
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ',') {
      p++;
    }
    if (*p == '\0' || *p == ']') {
      break;
    }
    if (*p != '{') {
      break;
    }
    const char *obj = p;
    const char *brace = strchr(obj + 1, '}');
    if (!brace) {
      *had_error = 1;
      break;
    }
    DWORD pid = 0;
    uint64_t base = 0;
    size_t sz = 0;
    if (forensic_mem_parse_one(obj, brace + 1, &pid, &base, &sz) != 0) {
      p = brace + 1;
      continue;
    }
    if (idx >= 32) {
      break;
    }
    HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) {
      h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    }
    if (!h) {
      *had_error = 1;
      p = brace + 1;
      idx++;
      continue;
    }
    void *buf = malloc(sz);
    if (!buf) {
      CloseHandle(h);
      *had_error = 1;
      p = brace + 1;
      continue;
    }
    SIZE_T got = 0;
    int ok = ReadProcessMemory(h, (LPCVOID)(ULONG_PTR)base, buf, sz, &got) ? 1 : 0;
    CloseHandle(h);
    char outpath[900];
    (void)snprintf(outpath, sizeof(outpath), "%s\\mem_%02u_0x%llx_%llu.bin", jobdir, (unsigned)idx,
                   (unsigned long long)base, (unsigned long long)sz);
    idx++;
    FILE *bf = fopen(outpath, "wb");
    if (!bf) {
      free(buf);
      *had_error = 1;
      p = brace + 1;
      continue;
    }
    if (ok && got > 0u) {
      fwrite(buf, 1, got, bf);
    }
    fclose(bf);
    free(buf);
    (*out_files)++;
    p = brace + 1;
  }
}

static void forensic_post_json_extensions_win(const char *jobdir, const char *manifest_path, const uint8_t *pl,
                                              size_t len) {
  if (!pl || len == 0u || !forensic_payload_trimmed_starts_json(pl, len)) {
    return;
  }
  int reg_decl = (strstr((const char *)pl, "\"registry_keys\"") != NULL);
  int mem_decl = (strstr((const char *)pl, "\"memory_regions\"") != NULL);
  const char *re = getenv("EDR_FORENSIC_REGISTRY_DUMP");
  const char *me = getenv("EDR_FORENSIC_MEMORY_DUMP");
  int reg_files = 0, mem_files = 0;
  int reg_err = 0, mem_err = 0;
  if (reg_decl && re && re[0] == '1') {
    forensic_copy_registry_keys_from_json(jobdir, manifest_path, pl, len, &reg_files, &reg_err);
  }
  if (mem_decl && me && me[0] == '1') {
    forensic_dump_memory_regions_from_json(jobdir, pl, len, &mem_files, &mem_err);
  }
  if (reg_decl) {
    if (!re || re[0] != '1') {
      forensic_manifest_append_line(manifest_path, "registry_dump_status=disabled_set_EDR_FORENSIC_REGISTRY_DUMP=1\n");
    } else if (reg_err && reg_files == 0) {
      forensic_manifest_append_line(manifest_path, "registry_dump_status=error\n");
    } else if (reg_err) {
      forensic_manifest_append_line(manifest_path, "registry_dump_status=partial\n");
    } else {
      forensic_manifest_append_line(manifest_path, "registry_dump_status=ok\n");
    }
    {
      char ln[80];
      (void)snprintf(ln, sizeof(ln), "registry_dump_files=%d\n", reg_files);
      forensic_manifest_append_line(manifest_path, ln);
    }
  }
  if (mem_decl) {
    if (!me || me[0] != '1') {
      forensic_manifest_append_line(manifest_path, "memory_dump_status=disabled_set_EDR_FORENSIC_MEMORY_DUMP=1\n");
    } else if (mem_err && mem_files == 0) {
      forensic_manifest_append_line(manifest_path, "memory_dump_status=error\n");
    } else if (mem_err) {
      forensic_manifest_append_line(manifest_path, "memory_dump_status=partial\n");
    } else {
      forensic_manifest_append_line(manifest_path, "memory_dump_status=ok\n");
    }
    {
      char ln[80];
      (void)snprintf(ln, sizeof(ln), "memory_dump_files=%d\n", mem_files);
      forensic_manifest_append_line(manifest_path, ln);
    }
  }
}
#else
static void forensic_manifest_append_line(const char *manifest_path, const char *line) {
  if (!manifest_path || !line) {
    return;
  }
  FILE *a = fopen(manifest_path, "a");
  if (!a) {
    return;
  }
  fputs(line, a);
  if (line[0] && line[strlen(line) - 1u] != '\n') {
    fputc('\n', a);
  }
  fclose(a);
}

static void forensic_post_json_extensions_posix(const char *manifest_path, const uint8_t *pl, size_t len) {
  if (!manifest_path || !pl || len == 0u || !forensic_payload_trimmed_starts_json(pl, len)) {
    return;
  }
  char tmp[4096];
  if (len >= sizeof(tmp)) {
    len = sizeof(tmp) - 1u;
  }
  memcpy(tmp, pl, len);
  tmp[len] = '\0';
  if (strstr(tmp, "\"registry_keys\"")) {
    forensic_manifest_append_line(manifest_path, "registry_dump_status=unsupported_platform\n");
  }
  if (strstr(tmp, "\"memory_regions\"")) {
    forensic_manifest_append_line(manifest_path, "memory_dump_status=unsupported_platform\n");
  }
}
#endif

static void forensic_post_json_extensions(const char *jobdir, const char *manifest_path, const uint8_t *pl, size_t len) {
#ifdef _WIN32
  forensic_post_json_extensions_win(jobdir, manifest_path, pl, len);
#else
  (void)jobdir;
  forensic_post_json_extensions_posix(manifest_path, pl, len);
#endif
}

static int forensic_bundle_nonempty(const char *path) {
  FILE *fp = fopen(path, "rb");
  if (!fp) {
    return 0;
  }
  if (fseek(fp, 0, SEEK_END) != 0) {
    fclose(fp);
    return 0;
  }
  long z = ftell(fp);
  fclose(fp);
  return z > 0L;
}

static void forensic_digest_to_hex(const uint8_t d[EDR_SHA256_DIGEST_LEN], char out65[65]) {
  static const char hx[] = "0123456789abcdef";
  for (int i = 0; i < 32; i++) {
    out65[i * 2] = (char)hx[(d[i] >> 4) & 15u];
    out65[i * 2 + 1] = (char)hx[d[i] & 15u];
  }
  out65[64] = '\0';
}

static int forensic_sha256_file_hex(const char *path, char out65[65]) {
  FILE *fp = fopen(path, "rb");
  if (!fp) {
    return -1;
  }
  EdrSha256Ctx ctx;
  edr_sha256_init(&ctx);
  uint8_t buf[65536];
  for (;;) {
    size_t n = fread(buf, 1, sizeof(buf), fp);
    if (n > 0u) {
      edr_sha256_update(&ctx, buf, n);
    }
    if (n < sizeof(buf)) {
      break;
    }
  }
  fclose(fp);
  uint8_t d[EDR_SHA256_DIGEST_LEN];
  edr_sha256_final(&ctx, d);
  forensic_digest_to_hex(d, out65);
  return 0;
}

/** 默认开启：`EDR_FORENSIC_UPLOAD=0` 关闭自动 **UploadFile**（`ingest.proto`）。 */
static int forensic_auto_upload_enabled(void) {
  const char *e = getenv("EDR_FORENSIC_UPLOAD");
  if (!e || !e[0]) {
    return 1;
  }
  return !(e[0] == '0' && e[1] == '\0');
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
  (void)edr_mkdir_p_win(dir);
#else
  snprintf(dir, sizeof(dir), "%s/%s", base, job);
  (void)edr_mkdir_p_posix(dir);
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
  if (pl && len > 0u && forensic_payload_trimmed_starts_json(pl, len)) {
    fprintf(f, "payload_format=json\n");
    forensic_manifest_declared_extensions(f, pl, len);
  } else if (pl && len > 0u) {
    fprintf(f, "payload_format=lines\n");
  }
  forensic_manifest_user_volume(f);
  fclose(f);
  if (pl && len > 0u) {
    if (forensic_payload_trimmed_starts_json(pl, len)) {
      forensic_copy_paths_from_json(dir, pl, len);
    } else {
      forensic_copy_lines(dir, pl, len);
    }
  }
  forensic_post_json_extensions(dir, manifest, pl, len);
#ifdef _WIN32
  (void)edr_forensic_run_tar_czf(dir);
#else
  (void)edr_forensic_run_tar_czf_posix(dir);
#endif
  char bundle_path[800];
#ifdef _WIN32
  snprintf(bundle_path, sizeof(bundle_path), "%s\\bundle.tgz", dir);
#else
  snprintf(bundle_path, sizeof(bundle_path), "%s/bundle.tgz", dir);
#endif

  char detail[384];
  snprintf(detail, sizeof(detail), "forensic bundle ok");
  if (forensic_auto_upload_enabled()) {
    if (!edr_grpc_client_ready()) {
      snprintf(detail, sizeof(detail), "forensic bundle ok; skip UploadFile (grpc not ready)");
    } else if (!forensic_bundle_nonempty(bundle_path)) {
      snprintf(detail, sizeof(detail), "forensic bundle ok; skip UploadFile (missing or empty bundle.tgz)");
    } else {
      char shahex[65];
      if (forensic_sha256_file_hex(bundle_path, shahex) != 0) {
        snprintf(detail, sizeof(detail), "forensic bundle ok; skip UploadFile (sha256 failed)");
      } else {
        char alert_id[288];
        {
          const char *id = (cmd_id && cmd_id[0]) ? cmd_id : "job";
          (void)snprintf(alert_id, sizeof(alert_id), "forensic-%s", id);
        }
        char minio_key[256];
        minio_key[0] = '\0';
        if (edr_grpc_client_upload_file(alert_id, bundle_path, shahex, minio_key, sizeof(minio_key)) == 0) {
          snprintf(detail, sizeof(detail), "forensic bundle ok; UploadFile key=%.220s", minio_key[0] ? minio_key : "(ok)");
        } else {
          snprintf(detail, sizeof(detail), "forensic bundle ok; UploadFile failed (local=%.200s)", bundle_path);
        }
      }
    }
  }

  s_exec_ok++;
  audit_both(cmd_id, detail);
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

void edr_command_on_envelope(const char *command_id, const char *command_type, const uint8_t *payload,
                             size_t payload_len, const EdrSoarCommandMeta *soar_meta) {
  EdrSoarCommandMeta empty;
  memset(&empty, 0, sizeof(empty));
  const EdrSoarCommandMeta *sm = soar_meta ? soar_meta : &empty;
  const char *t = command_type ? command_type : "";
  const char *id = command_id ? command_id : "";

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
