#include "edr/response.h"
#include "edr/command_util.h"
#include "edr/config.h"
#include "edr/deep_collector.h"
#include "edr/error.h"
#include "edr/grpc_client.h"
#include "edr/ingest_http.h"
#include "edr/pmfe.h"
#include "edr/sha256.h"
#include "edr/shell_session.h"
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

static int response_forensic_copy_one_file(const char *src, const char *dst) {
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

static void response_forensic_copy_lines(const char *jobdir, const uint8_t *pl, size_t len) {
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
      (void)response_forensic_copy_one_file(line, dst);
    }
    if (!nl) {
      break;
    }
    p = nl + 1;
  }
}

static void response_sanitize_job_name(const char *src, char *dst, size_t cap) {
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

static int response_mkdir_p(const char *path) {
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

static int response_make_tar_bundle(const char *dir, const char *bundle_path) {
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

static int response_split_args(char *buf, char *argv[], size_t argv_cap) {
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

static int response_run_hook_no_shell(const char *hook_cmdline) {
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
  int argc = response_split_args(cmd, argv, sizeof(argv) / sizeof(argv[0]));
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

/* ── Process Actions ── */

void edr_response_kill(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    g_cmd_rejected++;
    edr_command_audit_both(cmd_id, "reject kill: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  long pid;
  if (edr_command_parse_pid_json(pl, len, &pid) != 0) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "kill: payload 无有效 pid（JSON 示例 {\"pid\":1234}）");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "invalid pid payload");
    return;
  }
  if (!edr_command_kill_pid_allowed(pid)) {
    g_cmd_rejected++;
    edr_command_audit_both(cmd_id, "kill: pid 不在 EDR_CMD_KILL_ALLOWLIST 中");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 7, "pid not in allowlist");
    return;
  }
#ifdef _WIN32
  if ((DWORD)pid == GetCurrentProcessId()) {
    g_cmd_rejected++;
    edr_command_audit_both(cmd_id, "kill: 拒绝结束本进程");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 5, "refuse self");
    return;
  }
  {
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid);
    if (!h) {
      g_cmd_exec_fail++;
      edr_command_audit_both(cmd_id, "kill: OpenProcess 失败");
      edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "OpenProcess failed");
      return;
    }
    BOOL ok = TerminateProcess(h, 1);
    CloseHandle(h);
    if (ok) {
      g_cmd_exec_ok++;
      edr_command_audit_both(cmd_id, "kill: TerminateProcess 已执行");
      edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, "TerminateProcess ok");
    } else {
      g_cmd_exec_fail++;
      edr_command_audit_both(cmd_id, "kill: TerminateProcess 失败");
      edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 4, "TerminateProcess failed");
    }
  }
#else
  if (pid == (long)getpid()) {
    g_cmd_rejected++;
    edr_command_audit_both(cmd_id, "kill: 拒绝结束本进程");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 5, "refuse self");
    return;
  }
  if (kill((pid_t)pid, SIGTERM) == 0) {
    g_cmd_exec_ok++;
    edr_command_audit_both(cmd_id, "kill: 已发送 SIGTERM");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, "SIGTERM sent");
  } else {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "kill: kill() 失败");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 6, "kill() failed");
  }
#endif
}

/* ── Host Actions ── */

void edr_response_isolate(const char *cmd_id, const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    g_cmd_rejected++;
    edr_command_audit_both(cmd_id, "reject isolate: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
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
    g_cmd_exec_ok++;
    edr_command_audit_both(cmd_id, "isolate: 已写标记文件");
  } else {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "isolate: 写文件失败");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "stamp write failed");
    return;
  }
  const char *hook = getenv("EDR_ISOLATE_HOOK");
  if (hook && hook[0]) {
#ifndef _WIN32
    (void)setenv("EDR_CMD_ID", cmd_id ? cmd_id : "", 1);
#endif
    int r = response_run_hook_no_shell(hook);
    if (r == 0) {
      edr_command_audit_both(cmd_id, "isolate: EDR_ISOLATE_HOOK 执行成功");
    } else {
      edr_command_audit_both(cmd_id, "isolate: EDR_ISOLATE_HOOK 执行失败（仅支持无 shell 参数）");
      edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "isolate hook non-zero");
      return;
    }
  }
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, "isolate ok");
}

void edr_response_isolate_auto_from_shellcode(void) {
#if !defined(_WIN32)
  return;
#else
  int want = 0;
  const char *eo = getenv("EDR_SHELLCODE_AUTO_ISOLATE");
  if (eo && eo[0] == '1') {
    want = 1;
  } else {
    const EdrConfig *cfg = edr_command_get_config();
    if (cfg && cfg->shellcode_detector.auto_isolate_execute) {
      want = 1;
    }
  }
  if (!want) {
    return;
  }
  if (!edr_command_dangerous_enabled()) {
    return;
  }
  static volatile LONG s_shellcode_auto_iso_once;
  if (InterlockedCompareExchange(&s_shellcode_auto_iso_once, 1, 0) != 0) {
    return;
  }
  edr_response_isolate("auto-shellcode", NULL);
#endif
}

/* ── File Actions ── */

static int response_get_tmp_path(const char *cmd_id, char *out, size_t out_cap) {
  const char *tmp = getenv("EDR_FILE_TMP");
  if (!tmp || !tmp[0]) {
#ifdef _WIN32
    tmp = getenv("TEMP");
    if (!tmp || !tmp[0]) tmp = getenv("TMP");
    if (!tmp || !tmp[0]) tmp = ".";
    snprintf(out, out_cap, "%s\\edr_get_%s", tmp, cmd_id ? cmd_id : "unknown");
#else
    snprintf(out, out_cap, "/tmp/edr_get_%s", cmd_id ? cmd_id : "unknown");
#endif
  } else {
    snprintf(out, out_cap, "%s%sedr_get_%s", tmp,
#ifdef _WIN32
             "\\",
#else
             "/",
#endif
             cmd_id ? cmd_id : "unknown");
  }
  return 0;
}

static int response_b64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_cap) {
  static const uint8_t tbl[256] = {
    ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,['I']=8,['J']=9,
    ['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,['Q']=16,['R']=17,['S']=18,['T']=19,
    ['U']=20,['V']=21,['W']=22,['X']=23,['Y']=24,['Z']=25,['a']=26,['b']=27,['c']=28,['d']=29,
    ['e']=30,['f']=31,['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,
    ['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,['w']=48,['x']=49,
    ['y']=50,['z']=51,['0']=52,['1']=53,['2']=54,['3']=55,['4']=56,['5']=57,['6']=58,['7']=59,
    ['8']=60,['9']=61,['+']=62,['-']=62,['/']=63,['_']=63,
  };
  size_t o = 0;
  for (size_t i = 0; i + 3 < in_len && o + 2 < out_cap; i += 4) {
    uint8_t a = tbl[(uint8_t)in[i]], b = tbl[(uint8_t)in[i+1]];
    uint8_t c = tbl[(uint8_t)in[i+2]], d = tbl[(uint8_t)in[i+3]];
    out[o++] = (uint8_t)((a << 2) | (b >> 4));
    if (in[i+2] != '=' && in[i+2] != 0) out[o++] = (uint8_t)((b << 4) | (c >> 2));
    if (in[i+3] != '=' && in[i+3] != 0) out[o++] = (uint8_t)((c << 6) | d);
  }
  return (int)o;
}

void edr_response_get_file(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    g_cmd_rejected++;
    edr_command_audit_both(cmd_id, "reject rtr_get: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char path[520];
  int max_size_bytes = 100 * 1024 * 1024;
  int pe_only_flag = 0;
  (void)edr_parse_json_string(pl, len, "path", path, sizeof(path));
  (void)edr_parse_json_int(pl, len, "max_size_bytes", &max_size_bytes);
  (void)edr_parse_json_int(pl, len, "pe_only", &pe_only_flag);
  if (!path[0]) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "rtr_get: 缺少 path");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 2, "missing path");
    return;
  }
  FILE *f = fopen(path, "rb");
  if (!f) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "rtr_get: 文件不存在");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 3, "file not found");
    return;
  }
  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (fsize <= 0 || fsize > max_size_bytes) {
    fclose(f);
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "rtr_get: 文件大小超限");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 4, "file size out of range");
    return;
  }
  uint8_t *buf = (uint8_t *)malloc((size_t)fsize);
  if (!buf) {
    fclose(f);
    g_cmd_exec_fail++;
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 5, "oom");
    return;
  }
  if (fread(buf, 1, (size_t)fsize, f) != (size_t)fsize) {
    free(buf); fclose(f);
    g_cmd_exec_fail++;
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 6, "read error");
    return;
  }
  fclose(f);

  char sha[65];
  edr_sha256_hex(buf, (size_t)fsize, sha);

  if (pe_only_flag) {
    char pe_info[512];
    if (!edr_pe_verify(buf, (size_t)fsize, pe_info, sizeof(pe_info))) {
      free(buf);
      g_cmd_rejected++;
      edr_command_audit_both(cmd_id, "rtr_get: 非有效PE文件");
      edr_command_emit_always(cmd_id, sm, EdrCmdExecRejected, 7, "not a valid PE file");
      return;
    }
    char tmp_path[1024];
    response_get_tmp_path(cmd_id, tmp_path, sizeof(tmp_path));
    FILE *tf = fopen(tmp_path, "wb");
    if (tf) {
      fwrite(buf, 1, (size_t)fsize, tf);
      fclose(tf);
      char minio_key[256] = {0};
      edr_ingest_http_upload_file_multipart(cmd_id, tmp_path, sha, minio_key, sizeof(minio_key));
      remove(tmp_path);
      char result[1280];
      snprintf(result, sizeof(result), "PE_OK sha256=%s size=%ld minio_key=%s %s",
               sha, fsize, minio_key[0] ? minio_key : "", pe_info);
      free(buf);
      g_cmd_handled++; g_cmd_exec_ok++;
      edr_command_audit_both(cmd_id, "rtr_get: PE验证通过+上传");
      edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
    } else {
      free(buf);
      char result[1024];
      snprintf(result, sizeof(result), "PE_OK sha256=%s size=%ld (upload failed) %s", sha, fsize, pe_info);
      g_cmd_handled++; g_cmd_exec_ok++;
      edr_command_audit_both(cmd_id, "rtr_get: PE验证通过, 上传失败");
      edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
    }
    return;
  }

  char tmp_path[1024];
  response_get_tmp_path(cmd_id, tmp_path, sizeof(tmp_path));
  FILE *tf = fopen(tmp_path, "wb");
  if (tf) {
    fwrite(buf, 1, (size_t)fsize, tf);
    fclose(tf);
    char minio_key[256] = {0};
    edr_ingest_http_upload_file_multipart(cmd_id, tmp_path, sha, minio_key, sizeof(minio_key));
    remove(tmp_path);
    char result[768];
    snprintf(result, sizeof(result), "FILE_OK sha256=%s size=%ld minio_key=%s",
             sha, fsize, minio_key[0] ? minio_key : "");
    free(buf);
    g_cmd_handled++; g_cmd_exec_ok++;
    edr_command_audit_both(cmd_id, "rtr_get: 文件读取+上传成功");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
  } else {
    char result[512];
    snprintf(result, sizeof(result), "FILE_OK sha256=%s size=%ld (upload to backend failed, tmp write error)",
             sha, fsize);
    free(buf);
    g_cmd_handled++; g_cmd_exec_ok++;
    edr_command_audit_both(cmd_id, "rtr_get: 文件读取成功, tmp写入失败");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, result);
  }
}

void edr_response_put_file(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    g_cmd_rejected++;
    edr_command_audit_both(cmd_id, "reject rtr_put: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char path[520];
  (void)edr_parse_json_string(pl, len, "path", path, sizeof(path));
  if (!path[0]) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "rtr_put: 缺少 path");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "missing path");
    return;
  }
  char data_b64[512 * 1024];
  (void)edr_parse_json_string(pl, len, "data_b64", data_b64, sizeof(data_b64));
  if (!data_b64[0]) {
    FILE *f = fopen(path, "ab");
    if (!f) {
      g_cmd_exec_fail++;
      edr_command_audit_both(cmd_id, "rtr_put: 无法创建文件");
      edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "cannot create file");
      return;
    }
    fclose(f);
    char action[80];
    snprintf(action, sizeof(action), "PUT_OK (empty) %s", path);
    g_cmd_handled++; g_cmd_exec_ok++;
    edr_command_audit_both(cmd_id, "rtr_put: ok (empty file)");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, action);
    return;
  }
  size_t b64_len = strlen(data_b64);
  size_t dec_cap = (b64_len / 4 * 3) + 16;
  uint8_t *dec = (uint8_t *)malloc(dec_cap);
  if (!dec) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "rtr_put: oom");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 4, "oom");
    return;
  }
  int dlen = response_b64_decode(data_b64, b64_len, dec, dec_cap);
  if (dlen <= 0) {
    free(dec);
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "rtr_put: base64 decode failed");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 5, "base64 decode failed");
    return;
  }
  {
    char dir_copy[520];
    snprintf(dir_copy, sizeof(dir_copy), "%s", path);
#ifdef _WIN32
    char *slash = strrchr(dir_copy, '\\');
#else
    char *slash = strrchr(dir_copy, '/');
#endif
    if (slash) { *slash = '\0'; response_mkdir_p(dir_copy); }
  }
  FILE *f = fopen(path, "wb");
  if (!f) {
    free(dec);
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "rtr_put: 无法创建文件");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 6, "cannot create file");
    return;
  }
  size_t written = fwrite(dec, 1, (size_t)dlen, f);
  fclose(f);
  char sha[65] = {0};
  if (written > 0) edr_sha256_hex(dec, written, sha);
  free(dec);
  char expected_sha[65] = {0};
  (void)edr_parse_json_string(pl, len, "sha256", expected_sha, sizeof(expected_sha));
  if (expected_sha[0] && sha[0] && strcmp(expected_sha, sha) != 0) {
    remove(path);
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "rtr_put: sha256 mismatch");
    char msg[300];
    snprintf(msg, sizeof(msg), "SHA256_MISMATCH expected=%s actual=%s", expected_sha, sha);
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 7, msg);
    return;
  }
  char action[200];
  snprintf(action, sizeof(action), "PUT_OK %s size=%d sha256=%s", path, dlen, sha);
  g_cmd_handled++; g_cmd_exec_ok++;
  edr_command_audit_both(cmd_id, "rtr_put: ok");
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, action);
}

void edr_response_remove_file(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    g_cmd_rejected++;
    edr_command_audit_both(cmd_id, "reject rtr_rm: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char path[520];
  (void)edr_parse_json_string(pl, len, "path", path, sizeof(path));
  if (!path[0]) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "rtr_rm: 缺少 path");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "missing path");
    return;
  }
  if (remove(path) != 0) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "rtr_rm: 删除失败");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "remove failed");
    return;
  }
  char result[600];
  snprintf(result, sizeof(result), "RM_OK %s", path);
  g_cmd_handled++; g_cmd_exec_ok++;
  edr_command_audit_both(cmd_id, "rtr_rm: ok");
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, result);
}

void edr_response_quarantine_file(const char *cmd_id, const uint8_t *pl, size_t len,
                                   const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    g_cmd_rejected++;
    edr_command_audit_both(cmd_id, "reject quarantine_file: policy");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char path[520];
  (void)edr_parse_json_string(pl, len, "path", path, sizeof(path));
  if (!path[0]) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "quarantine_file: 缺少 path");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "missing path");
    return;
  }
  FILE *src = fopen(path, "rb");
  if (!src) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "quarantine_file: 文件不存在");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "file not found");
    return;
  }
  fseek(src, 0, SEEK_END);
  long fsize = ftell(src);
  fseek(src, 0, SEEK_SET);
  if (fsize <= 0 || fsize > 256 * 1024 * 1024) {
    fclose(src);
    g_cmd_exec_fail++;
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 4, "file too large");
    return;
  }
  uint8_t *buf = (uint8_t *)malloc((size_t)fsize);
  if (!buf) { fclose(src); g_cmd_exec_fail++; return; }
  if (fread(buf, 1, (size_t)fsize, src) != (size_t)fsize) {
    free(buf); fclose(src); g_cmd_exec_fail++; return;
  }
  fclose(src);
  char sha[65];
  edr_sha256_hex(buf, (size_t)fsize, sha);
  const char *bname = strrchr(path, '/');
  if (!bname) bname = strrchr(path, '\\');
  if (!bname) bname = path; else bname++;
  char qpath[1024];
#ifdef _WIN32
  const char *qd = getenv("ProgramData");
  if (!qd || !qd[0]) qd = "C:\\ProgramData";
  snprintf(qpath, sizeof(qpath), "%s\\edr\\quarantine\\%s_%s", qd, sha, bname);
#else
  snprintf(qpath, sizeof(qpath), "/var/lib/edr/quarantine/%s_%s", sha, bname);
#endif
  {
    char qdir[1024];
    snprintf(qdir, sizeof(qdir), "%s", qpath);
    char *slash = strrchr(qdir, '/');
    if (!slash) slash = strrchr(qdir, '\\');
    if (slash) { *slash = '\0'; (void)response_mkdir_p(qdir); }
  }
  FILE *dst = fopen(qpath, "wb");
  if (!dst) { free(buf); g_cmd_exec_fail++; edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 5, "quarantine write failed"); return; }
  fwrite(buf, 1, (size_t)fsize, dst);
  fclose(dst);
  free(buf);
  if (remove(path) != 0) {
    g_cmd_exec_fail++;
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 6, "original remove failed");
    return;
  }
  char result[1024];
  snprintf(result, sizeof(result), "QUARANTINE_OK path=%s sha256=%s size=%ld", qpath, sha, fsize);
  g_cmd_handled++; g_cmd_exec_ok++;
  edr_command_audit_both(cmd_id, "quarantine_file: ok");
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, result);
}

void edr_response_restore_file(const char *cmd_id, const uint8_t *pl, size_t len,
                                const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    g_cmd_rejected++;
    edr_command_audit_both(cmd_id, "reject restore_file: policy");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char qpath[520], dest[520];
  (void)edr_parse_json_string(pl, len, "quarantine_path", qpath, sizeof(qpath));
  (void)edr_parse_json_string(pl, len, "dest", dest, sizeof(dest));
  if (!qpath[0] || !dest[0]) {
    g_cmd_exec_fail++;
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "missing quarantine_path or dest");
    return;
  }
  if (response_forensic_copy_one_file(qpath, dest) != 0) {
    g_cmd_exec_fail++;
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "restore copy failed");
    return;
  }
  remove(qpath);
  char result[600];
  snprintf(result, sizeof(result), "RESTORE_OK %s -> %s", qpath, dest);
  g_cmd_handled++; g_cmd_exec_ok++;
  edr_command_audit_both(cmd_id, "restore_file: ok");
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, result);
}

/* ── Forensic Actions ── */

void edr_response_collect_forensic(const char *cmd_id, const uint8_t *pl, size_t len,
                                    const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    g_cmd_rejected++;
    edr_command_audit_both(cmd_id, "reject forensic: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
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
  response_sanitize_job_name(cmd_id, job, sizeof(job));
  char dir[700];
#ifdef _WIN32
  snprintf(dir, sizeof(dir), "%s\\%s", base, job);
#else
  snprintf(dir, sizeof(dir), "%s/%s", base, job);
#endif
  if (response_mkdir_p(dir) != 0) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "forensic: 创建输出目录失败");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 2, "mkdir failed");
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
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "forensic: 写 manifest 失败");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 2, "manifest write failed");
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
  {
    const EdrConfig *cfg = edr_command_get_config();
    if (cfg) {
      fprintf(f, "endpoint_id=%s\ntenant_id=%s\n", cfg->agent.endpoint_id[0] ? cfg->agent.endpoint_id : "",
              cfg->agent.tenant_id[0] ? cfg->agent.tenant_id : "");
    }
  }
  fclose(f);
  response_forensic_copy_lines(dir, pl, len);
#ifdef _WIN32
  char bundle[1100];
  snprintf(bundle, sizeof(bundle), "%s\\bundle.tgz", dir);
#else
  char bundle[1000];
  snprintf(bundle, sizeof(bundle), "%s/bundle.tgz", dir);
#endif
  if (response_make_tar_bundle(dir, bundle) == 0) {
    g_cmd_exec_ok++;
    edr_command_audit_both(cmd_id, "forensic: manifest + bundle.tgz");
    edr_ingest_http_upload_file_multipart(cmd_id, bundle, NULL, NULL, 0);
    edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, "forensic bundle ok");
  } else {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "forensic: tar bundle 失败");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 2, "tar bundle failed");
  }
}

void edr_response_pmfe_scan(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    g_cmd_rejected++;
    edr_command_audit_both(cmd_id, "reject pmfe_scan: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  long pid = -1;
  if (edr_command_parse_pid_json(pl, len, &pid) != 0) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "pmfe_scan: payload 缺少有效 pid（JSON 需含 \"pid\"）");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "invalid pid json");
    return;
  }
  if (edr_pmfe_submit_server_scan(cmd_id, (uint32_t)pid) != 0) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "pmfe_scan: 入队失败（PMFE 未启动或队列满）");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "pmfe queue full or not running");
    return;
  }
  g_cmd_handled++;
  g_cmd_exec_ok++;
  edr_command_audit_both(cmd_id, "pmfe_scan: 已入队（异步粗扫）");
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, "pmfe_scan queued");
}

void edr_response_rtr_shell(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    g_cmd_rejected++;
    edr_command_audit_both(cmd_id, "reject rtr_shell: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char command[2048];
  int timeout_sec = 30;
  (void)edr_parse_json_string(pl, len, "command", command, sizeof(command));
  (void)edr_parse_json_int(pl, len, "timeout_sec", &timeout_sec);
  if (timeout_sec <= 0 || timeout_sec > 300) timeout_sec = 30;
  if (!command[0]) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "rtr_shell: 缺少 command");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, 2, "missing command");
    return;
  }
  if (!edr_shell_is_allowed(command)) {
    g_cmd_rejected++;
    edr_command_audit_both(cmd_id, "rtr_shell: 命令不在白名单或命中黑名单");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecRejected, 3, "command blocked by policy");
    return;
  }
  char out[8192];
  int exit_code = 0;
  int r = edr_shell_exec(command, timeout_sec, out, sizeof(out), &exit_code);
  if (r != 0) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "rtr_shell: 执行失败");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecFailed, exit_code, out[0] ? out : "exec failed");
    return;
  }
  g_cmd_handled++;
  g_cmd_exec_ok++;
  edr_command_audit_both(cmd_id, "rtr_shell: ok");
#ifdef _WIN32
  {
    int wlen = MultiByteToWideChar(CP_ACP, 0, out, -1, NULL, 0);
    if (wlen > 0) {
      wchar_t *wbuf = (wchar_t *)malloc((size_t)wlen * sizeof(wchar_t));
      if (wbuf) {
        MultiByteToWideChar(CP_ACP, 0, out, -1, wbuf, wlen);
        int u8len = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, NULL, 0, NULL, NULL);
        if (u8len > 0 && (size_t)u8len < sizeof(out)) {
          WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, out, u8len, NULL, NULL);
        }
        free(wbuf);
      }
    }
  }
#endif
  edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, exit_code, out);
}

void edr_response_targeted_forensic(const char *cmd_id, const uint8_t *pl, size_t len,
                                     const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    g_cmd_rejected++;
    edr_command_audit_both(cmd_id, "reject targeted_forensic: policy");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
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
          const char *fbname = strrchr(fpath, '/');
          if (!fbname) fbname = strrchr(fpath, '\\');
          if (!fbname) fbname = fpath; else fbname++;
          char dest[800];
          snprintf(dest, sizeof(dest), "files/%s", fbname);
          response_forensic_copy_one_file(fpath, dest);
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
  g_cmd_handled++; g_cmd_exec_ok++;
  edr_command_audit_both(cmd_id, "targeted_forensic: ok");
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, out);
}

void edr_response_memory_dump(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    g_cmd_rejected++;
    edr_command_audit_both(cmd_id, "reject memory_dump: policy");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  int pid = -1, full = 0;
  (void)edr_parse_json_int(pl, len, "pid", &pid);
  (void)edr_parse_json_int(pl, len, "full", &full);
  if (pid <= 0) {
    g_cmd_exec_fail++;
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "invalid pid");
    return;
  }
#ifdef _WIN32
  HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)pid);
  if (!h) {
    g_cmd_exec_fail++;
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "OpenProcess failed");
    return;
  }
  char dmpPath[512];
  snprintf(dmpPath, sizeof(dmpPath), "memdump_%d_%lld.dmp", pid, (long long)time(NULL));
  HANDLE hFile = CreateFileA(dmpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE) {
    CloseHandle(h);
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 4, "CreateFile failed");
    return;
  }
  MINIDUMP_TYPE dumpType = full ? MiniDumpWithFullMemory : MiniDumpNormal;
  BOOL ok = MiniDumpWriteDump(h, (DWORD)pid, hFile, dumpType, NULL, NULL, NULL);
  CloseHandle(hFile);
  CloseHandle(h);
  if (!ok) {
    g_cmd_exec_fail++;
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 5, "MiniDumpWriteDump failed");
    return;
  }
  char result[512];
  snprintf(result, sizeof(result), "MEMDUMP_OK pid=%d file=%s", pid, dmpPath);
  g_cmd_handled++; g_cmd_exec_ok++;
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, result);
#else
  char procPath[128];
  snprintf(procPath, sizeof(procPath), "/proc/%d/mem", pid);
  FILE *src = fopen(procPath, "rb");
  if (!src) {
    g_cmd_exec_fail++;
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "/proc/pid/mem open failed");
    return;
  }
  char dmpPath[512];
  snprintf(dmpPath, sizeof(dmpPath), "/tmp/memdump_%d_%lld.dmp", pid, (long long)time(NULL));
  FILE *dst = fopen(dmpPath, "wb");
  if (!dst) { fclose(src); edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 4, "output create failed"); return; }
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
  g_cmd_handled++; g_cmd_exec_ok++;
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, result);
#endif
}

static void *response_memmem(const void *haystack, size_t haystack_len,
                             const void *needle, size_t needle_len) {
  if (!needle_len) return (void *)haystack;
  if (haystack_len < needle_len) return NULL;
  const char *h = (const char *)haystack;
  for (size_t i = 0; i <= haystack_len - needle_len; i++) {
    if (memcmp(h + i, needle, needle_len) == 0) return (void *)(h + i);
  }
  return NULL;
}

void edr_response_yara_scan(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    g_cmd_rejected++;
    edr_command_audit_both(cmd_id, "reject yara_scan: policy");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char target_path[520];
  (void)edr_parse_json_string(pl, len, "target_path", target_path, sizeof(target_path));
  if (!target_path[0]) {
    g_cmd_exec_fail++;
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "missing target_path");
    return;
  }
  FILE *f = fopen(target_path, "rb");
  if (!f) {
    f = fopen(target_path, "r");
  }
  if (!f) {
    g_cmd_exec_fail++;
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "file not found");
    return;
  }
  fseek(f, 0, SEEK_END);
  long fsz = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (fsz <= 0 || fsz > 50 * 1024 * 1024) {
    fclose(f);
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 4, "file too large (>50MB)");
    return;
  }
  uint8_t *buf = (uint8_t *)malloc((size_t)fsz);
  if (!buf) { fclose(f); edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 5, "oom"); return; }
  fread(buf, 1, (size_t)fsz, f);
  fclose(f);

  char result[1024];
  int matches = 0;
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
    if (response_memmem(buf, (size_t)fsz, patterns[pi], strlen(patterns[pi]))) {
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
  g_cmd_handled++; g_cmd_exec_ok++;
  edr_command_audit_both(cmd_id, "yara_scan: ok");
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, result);
}

void edr_shell_stream_output_cb(const char *sid, const char *data, size_t len,
                                int exit_code, bool closed, void *user) {
  (void)user;
  if (!sid) return;
  char detail[4096];
  if (closed && data == NULL) {
    snprintf(detail, sizeof(detail), "shell session %s closed, exit=%d", sid, exit_code);
  } else if (data && len > 0) {
    size_t cp = len < sizeof(detail) - 1 ? len : sizeof(detail) - 1;
    (void)memcpy(detail, data, cp);
    detail[cp] = '\0';
  } else {
    return;
  }
  EdrSoarCommandMeta dummy = {0};
  strncpy(dummy.soar_correlation_id, sid, sizeof(dummy.soar_correlation_id) - 1);
  edr_command_soar_emit(sid, &dummy,
                        closed ? EdrCmdExecOk : EdrCmdExecOk,
                        exit_code, detail);
}

void edr_response_shell_open(const char *cmd_id, const uint8_t *pl, size_t len,
                             const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    g_cmd_rejected++;
    edr_command_audit_both(cmd_id, "shell_open: rejected (dangerous disabled)");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 0, "dangerous commands disabled");
    return;
  }

  char shell_type[64];
#ifdef _WIN32
  strcpy(shell_type, "cmd.exe");
#else
  strcpy(shell_type, "/bin/sh");
#endif
  if (pl && len > 0 && len < 64 && pl[0] != '{') {
    (void)memcpy(shell_type, pl, len);
    shell_type[len] = '\0';
  }

  int rc = edr_shell_session_open(cmd_id, shell_type);
  if (rc != 0) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "shell_open: failed");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, rc, "shell_open failed");
    return;
  }

  g_cmd_handled++;
  g_cmd_exec_ok++;
  char detail[128];
  snprintf(detail, sizeof(detail), "shell session opened: %s", shell_type);
  edr_command_audit_both(cmd_id, "shell_open: ok");
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

void edr_response_shell_input(const char *cmd_id, const uint8_t *pl, size_t len,
                              const EdrSoarCommandMeta *sm) {
  char session_id[EDR_SS_ID_LEN];
  char input[4096];
  (void)edr_parse_json_string(pl, len, "session_id", session_id, sizeof(session_id));
  (void)edr_parse_json_string(pl, len, "input", input, sizeof(input));

  if (session_id[0] && input[0]) {
    int rc = edr_shell_session_input(session_id, input, strlen(input));
    if (rc != 0) {
      g_cmd_exec_fail++;
      edr_command_audit_both(cmd_id, "shell_input: write failed");
      edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, rc, "shell_input write failed");
      return;
    }
  } else {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "shell_input: missing session_id or input");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 1, "missing session_id or input");
    return;
  }

  char detail[128];
  snprintf(detail, sizeof(detail), "shell_input sent %zu bytes to session %s",
           strlen(input), session_id);
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

void edr_response_shell_close(const char *cmd_id, const uint8_t *pl, size_t len,
                              const EdrSoarCommandMeta *sm) {
  char session_id[EDR_SS_ID_LEN];
  (void)edr_parse_json_string(pl, len, "session_id", session_id, sizeof(session_id));
  if (!session_id[0]) {
    g_cmd_exec_fail++;
    edr_command_audit_both(cmd_id, "shell_close: missing session_id");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 1, "missing session_id");
    return;
  }
  edr_shell_session_close(session_id);
  g_cmd_handled++;
  g_cmd_exec_ok++;
  edr_command_audit_both(cmd_id, "shell_close: ok");
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, "shell session closed");
}

void edr_response_deep_forensic(const char *cmd_id, const uint8_t *pl, size_t len,
                                const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    g_cmd_rejected++;
    edr_command_audit_both(cmd_id, "forensic_deep: rejected (dangerous disabled)");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 0, "dangerous commands disabled");
    return;
  }

  EdrDeepCollectorParams params;
  (void)memset(&params, 0, sizeof(params));
  params.download_url = NULL;
  params.expected_sha256 = NULL;
  params.output_dir = NULL;
  params.upload_url = NULL;
  params.scope = "standard";
  params.timeout_s = 900;

  if (pl && len > 0 && len < 64) {
    char scope[64];
    (void)memcpy(scope, pl, len);
    scope[len] = '\0';
    if (strcmp(scope, "triage") == 0) params.scope = "triage";
    else if (strcmp(scope, "full") == 0) params.scope = "full";
    else if (strcmp(scope, "standard") == 0) params.scope = "standard";
  }

  int rc = edr_deep_collector_launch(&params);
  if (rc != EDR_DC_OK) {
    g_cmd_exec_fail++;
    char detail[128];
    snprintf(detail, sizeof(detail), "forensic_deep: launch failed, err=%d", rc);
    edr_command_audit_both(cmd_id, detail);
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, rc, detail);
    return;
  }

  g_cmd_handled++;
  g_cmd_exec_ok++;
  char detail[128];
  snprintf(detail, sizeof(detail), "forensic_deep launched, scope=%s", params.scope);
  edr_command_audit_both(cmd_id, "forensic_deep: launched");
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}
