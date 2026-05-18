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

#include "edr/response_utils.h"

/* ── Process Actions ── */

void edr_response_kill(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "reject kill: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  long pid;
  if (edr_command_parse_pid_json(pl, len, &pid) != 0) {
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "kill: payload 无有效 pid（JSON 示例 {\"pid\":1234}）");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "invalid pid payload");
    return;
  }
  if (!edr_command_kill_pid_allowed(pid)) {
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "kill: pid 不在 EDR_CMD_KILL_ALLOWLIST 中");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 7, "pid not in allowlist");
    return;
  }
#ifdef _WIN32
  if ((DWORD)pid == GetCurrentProcessId()) {
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "kill: 拒绝结束本进程");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 5, "refuse self");
    return;
  }
  {
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid);
    if (!h) {
      edr_cmd_inc_exec_fail();
      edr_command_audit_both(cmd_id, "kill: OpenProcess 失败");
      edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "OpenProcess failed");
      return;
    }
    BOOL ok = TerminateProcess(h, 1);
    CloseHandle(h);
    if (ok) {
      edr_cmd_inc_exec_ok();
      edr_command_audit_both(cmd_id, "kill: TerminateProcess 已执行");
      edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, "TerminateProcess ok");
    } else {
      edr_cmd_inc_exec_fail();
      edr_command_audit_both(cmd_id, "kill: TerminateProcess 失败");
      edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 4, "TerminateProcess failed");
    }
  }
#else
  if (pid == (long)getpid()) {
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "kill: 拒绝结束本进程");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 5, "refuse self");
    return;
  }
  if (kill((pid_t)pid, SIGTERM) == 0) {
    edr_cmd_inc_exec_ok();
    edr_command_audit_both(cmd_id, "kill: 已发送 SIGTERM");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, "SIGTERM sent");
  } else {
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "kill: kill() 失败");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 6, "kill() failed");
  }
#endif
}

/* ── Host Actions ── */

void edr_response_isolate(const char *cmd_id, const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    edr_cmd_inc_rejected();
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
    edr_cmd_inc_exec_ok();
    edr_command_audit_both(cmd_id, "isolate: 已写标记文件");
  } else {
    edr_cmd_inc_exec_fail();
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
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "shell_open: rejected (dangerous disabled)");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecRejected, 0, "dangerous commands disabled");
    return;
  }

  char shell_type[64];
#ifdef _WIN32
  strcpy(shell_type, "cmd.exe /Q /K chcp 65001 > nul");
#else
  strcpy(shell_type, "/bin/sh");
#endif
  if (pl && len > 0 && len < 64 && pl[0] != '{') {
    (void)memcpy(shell_type, pl, len);
    shell_type[len] = '\0';
  }

  int rc = edr_shell_session_open(cmd_id, shell_type);
  if (rc != 0) {
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "shell_open: failed");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, rc, "shell_open failed");
    return;
  }

  edr_cmd_inc_handled();
  edr_cmd_inc_exec_ok();

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
    size_t ilen = strlen(input);
    if (ilen + 2 <= sizeof(input)) {
      input[ilen] = '\n';
      ilen++;
    }
    int rc = edr_shell_session_input(session_id, input, ilen);
    if (rc != 0) {
      edr_cmd_inc_exec_fail();
      edr_command_audit_both(cmd_id, "shell_input: write failed");
      edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, rc, "shell_input write failed");
      return;
    }
  } else {
    edr_cmd_inc_exec_fail();
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
    edr_cmd_inc_exec_fail();
    edr_command_audit_both(cmd_id, "shell_close: missing session_id");
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, 1, "missing session_id");
    return;
  }
  edr_shell_session_close(session_id);
  edr_cmd_inc_handled();
  edr_cmd_inc_exec_ok();
  edr_command_audit_both(cmd_id, "shell_close: ok");
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, "shell session closed");
}

void edr_response_deep_forensic(const char *cmd_id, const uint8_t *pl, size_t len,
                                const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    edr_cmd_inc_rejected();
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
    edr_cmd_inc_exec_fail();
    char detail[128];
    snprintf(detail, sizeof(detail), "forensic_deep: launch failed, err=%d", rc);
    edr_command_audit_both(cmd_id, detail);
    edr_command_soar_emit(cmd_id, sm, EdrCmdExecFailed, rc, detail);
    return;
  }

  edr_cmd_inc_handled();
  edr_cmd_inc_exec_ok();
  char detail[128];
  snprintf(detail, sizeof(detail), "forensic_deep launched, scope=%s", params.scope);
  edr_command_audit_both(cmd_id, "forensic_deep: launched");
  edr_command_soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

static int collector_escape_append(char *buf, int off, int cap, const char *s) {
    int w = off;
    for (; s && *s && w < cap - 8; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"') { w += snprintf(buf + w, (size_t)(cap - w), "\\\""); }
        else if (c == '\\') { w += snprintf(buf + w, (size_t)(cap - w), "\\\\"); }
        else if (c == '\n') { w += snprintf(buf + w, (size_t)(cap - w), "\\n"); }
        else if (c == '\r') { w += snprintf(buf + w, (size_t)(cap - w), "\\r"); }
        else if (c == '\t') { w += snprintf(buf + w, (size_t)(cap - w), "\\t"); }
        else if (c < 0x20) { w += snprintf(buf + w, (size_t)(cap - w), "\\u%04x", (unsigned)c); }
        else { buf[w++] = (char)c; }
    }
    return w;
}

void edr_response_collector_start(const char *cmd_id, const uint8_t *pl, size_t len,
                                  const EdrSoarCommandMeta *sm) {
  if (!edr_command_dangerous_enabled()) {
    edr_cmd_inc_rejected();
    edr_command_audit_both(cmd_id, "collector:start rejected (dangerous disabled)");
    edr_command_emit_always(cmd_id, sm, EdrCmdExecRejected, 1, "dangerous commands disabled");
    return;
  }

  char scope[64];
  scope[0] = '\0';
  if (pl && len > 0) {
    (void)edr_parse_json_string(pl, len, "scope", scope, sizeof(scope));
  }
  if (!scope[0]) {
    snprintf(scope, sizeof(scope), "all");
  }

  char buf[16384];
  int off = 0;
  off += snprintf(buf + off, sizeof(buf) - off, "{\"scope\":\"%s\",", scope);

#ifdef _WIN32
  if (strcmp(scope, "all") == 0 || strcmp(scope, "process") == 0) {
    off += snprintf(buf + off, sizeof(buf) - off, "\"processes\":\"");
    FILE *pp = _popen("tasklist /FO CSV /NH 2>nul", "r");
    if (pp) {
      char lb[512];
      while (fgets(lb, sizeof(lb), pp) && off < (int)sizeof(buf) - 512) {
        size_t lb_len = strlen(lb);
        if (off + (int)lb_len + 2 < (int)sizeof(buf)) {
          off = collector_escape_append(buf, off, (int)sizeof(buf), lb);
        }
      }
      _pclose(pp);
    }
    off += snprintf(buf + off, sizeof(buf) - off, "\",");
  }
  if (strcmp(scope, "all") == 0 || strcmp(scope, "network") == 0) {
    off += snprintf(buf + off, sizeof(buf) - off, "\"network\":\"");
    FILE *pp = _popen("netstat -ano 2>nul", "r");
    if (pp) {
      char lb[512];
      while (fgets(lb, sizeof(lb), pp) && off < (int)sizeof(buf) - 512) {
        size_t lb_len = strlen(lb);
        if (off + (int)lb_len + 2 < (int)sizeof(buf)) {
          off = collector_escape_append(buf, off, (int)sizeof(buf), lb);
        }
      }
      _pclose(pp);
    }
    off += snprintf(buf + off, sizeof(buf) - off, "\",");
  }
  if (strcmp(scope, "all") == 0 || strcmp(scope, "files") == 0) {
    off += snprintf(buf + off, sizeof(buf) - off, "\"files\":\"");
    FILE *pp = _popen("dir /s /b C:\\Users 2>nul", "r");
    if (pp) {
      char lb[512];
      int line = 0;
      while (fgets(lb, sizeof(lb), pp) && off < (int)sizeof(buf) - 512 && line < 200) {
        size_t lb_len = strlen(lb);
        if (off + (int)lb_len + 2 < (int)sizeof(buf)) {
          off = collector_escape_append(buf, off, (int)sizeof(buf), lb);
        }
        line++;
      }
      _pclose(pp);
    }
    off += snprintf(buf + off, sizeof(buf) - off, "\",");
  }
  if (strcmp(scope, "all") == 0 || strcmp(scope, "memory") == 0) {
    off += snprintf(buf + off, sizeof(buf) - off, "\"memory\":\"");
    FILE *pp = _popen("systeminfo 2>nul", "r");
    if (pp) {
      char lb[512];
      while (fgets(lb, sizeof(lb), pp) && off < (int)sizeof(buf) - 512) {
        size_t lb_len = strlen(lb);
        if (off + (int)lb_len + 2 < (int)sizeof(buf)) {
          off = collector_escape_append(buf, off, (int)sizeof(buf), lb);
        }
      }
      _pclose(pp);
    }
    off += snprintf(buf + off, sizeof(buf) - off, "\",");
  }
#else
  if (strcmp(scope, "all") == 0 || strcmp(scope, "process") == 0) {
    off += snprintf(buf + off, sizeof(buf) - off, "\"processes\":\"");
    FILE *pp = popen("ps aux --no-headers 2>/dev/null | head -200", "r");
    if (pp) {
      char lb[512];
      while (fgets(lb, sizeof(lb), pp) && off < (int)sizeof(buf) - 512) {
        size_t lb_len = strlen(lb);
        if (off + (int)lb_len + 2 < (int)sizeof(buf)) {
          off = collector_escape_append(buf, off, (int)sizeof(buf), lb);
        }
      }
      pclose(pp);
    }
    off += snprintf(buf + off, sizeof(buf) - off, "\",");
  }
  if (strcmp(scope, "all") == 0 || strcmp(scope, "network") == 0) {
    off += snprintf(buf + off, sizeof(buf) - off, "\"network\":\"");
    FILE *pp = popen("ss -tunap 2>/dev/null || netstat -an 2>/dev/null | head -200", "r");
    if (pp) {
      char lb[512];
      while (fgets(lb, sizeof(lb), pp) && off < (int)sizeof(buf) - 512) {
        size_t lb_len = strlen(lb);
        if (off + (int)lb_len + 2 < (int)sizeof(buf)) {
          off = collector_escape_append(buf, off, (int)sizeof(buf), lb);
        }
      }
      pclose(pp);
    }
    off += snprintf(buf + off, sizeof(buf) - off, "\",");
  }
  if (strcmp(scope, "all") == 0 || strcmp(scope, "files") == 0) {
    off += snprintf(buf + off, sizeof(buf) - off, "\"files\":\"");
    FILE *pp = popen("find /etc /var/log /home -type f -maxdepth 3 2>/dev/null | head -200", "r");
    if (pp) {
      char lb[512];
      while (fgets(lb, sizeof(lb), pp) && off < (int)sizeof(buf) - 512) {
        size_t lb_len = strlen(lb);
        if (off + (int)lb_len + 2 < (int)sizeof(buf)) {
          off = collector_escape_append(buf, off, (int)sizeof(buf), lb);
        }
      }
      pclose(pp);
    }
    off += snprintf(buf + off, sizeof(buf) - off, "\",");
  }
  if (strcmp(scope, "all") == 0 || strcmp(scope, "memory") == 0) {
    off += snprintf(buf + off, sizeof(buf) - off, "\"memory\":\"");
    FILE *pp = popen("free -h 2>/dev/null || vm_stat 2>/dev/null", "r");
    if (pp) {
      char lb[512];
      while (fgets(lb, sizeof(lb), pp) && off < (int)sizeof(buf) - 512) {
        size_t lb_len = strlen(lb);
        if (off + (int)lb_len + 2 < (int)sizeof(buf)) {
          off = collector_escape_append(buf, off, (int)sizeof(buf), lb);
        }
      }
      pclose(pp);
    }
    off += snprintf(buf + off, sizeof(buf) - off, "\",");
  }
#endif

  off += snprintf(buf + off, sizeof(buf) - off, "\"collected_at\":%lld}", (long long)time(NULL));

  edr_cmd_inc_handled();
  edr_cmd_inc_exec_ok();
  edr_command_audit_both(cmd_id, "collector:start ok");
  edr_command_emit_always(cmd_id, sm, EdrCmdExecOk, 0, buf);
}
