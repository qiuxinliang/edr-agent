#include "edr/shell_exec.h"
#include "edr/collector.h"
#include "cJSON.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#endif

static const char *g_shell_allow_default[] = {
  "whoami", "hostname", "systeminfo", "uname",
  "tasklist", "ps", "top",
  "netstat", "ss", "lsof",
  "dir", "ls", "cat", "type", "find", "grep",
  "net", "sc", "reg", "wmic",
  "ipconfig", "ifconfig", "route", "arp",
  "df", "du", "free", "mount",
  "last", "w", "users",
  "crontab", "schtasks",
  "systemctl", "service",
  "docker", "kubectl",
  "cmd", "powershell", "bash", "sh",
  NULL
};

static const char *g_shell_block_default[] = {
  "rm ", "del ", "erase ", "rmdir ", "rd ",
  "format ", "fdisk ",
  "shutdown", "reboot", "halt", "poweroff", "logoff",
  NULL
};

static const char **g_shell_allow = NULL;
static const char **g_shell_block = NULL;

void edr_shell_load_policy(const char **allow, const char **block) {
  g_shell_allow = allow;
  g_shell_block = block;
}

void edr_shell_reset_policy(void) {
  g_shell_allow = NULL;
  g_shell_block = NULL;
}

static const char *const *shell_allow(void) {
  return g_shell_allow ? g_shell_allow : g_shell_allow_default;
}

static const char *const *shell_block(void) {
  return g_shell_block ? g_shell_block : g_shell_block_default;
}

int edr_shell_is_allowed(const char *command) {
  if (!command || !command[0]) return 0;
  char lower[1024];
  size_t n = strlen(command);
  if (n >= sizeof(lower)) n = sizeof(lower) - 1;
  for (size_t i = 0; i < n; i++) lower[i] = (char)tolower((unsigned char)command[i]);
  lower[n] = '\0';

  for (int i = 0; shell_block()[i]; i++) {
    if (strstr(lower, shell_block()[i])) return 0;
  }

  char *low = lower;
  while (*low == ' ' || *low == '\t') low++;
  char cmd[64];
  size_t j = 0;
  while (low[j] && low[j] != ' ' && low[j] != '\t' && j < sizeof(cmd) - 1) {
    cmd[j] = low[j];
    j++;
  }
  cmd[j] = '\0';

  while (cmd[0] == '.' || cmd[0] == '/' || cmd[0] == '\\') {
    memmove(cmd, cmd + 1, strlen(cmd));
  }

  for (int i = 0; shell_allow()[i]; i++) {
    if (strcmp(cmd, shell_allow()[i]) == 0) return 1;
  }
  return 0;
}

int edr_shell_exec_cancellable(const char *command, int timeout_sec,
                               char *output, size_t output_size, int *exit_code,
                               EdrShellCancelCheck cancel_check, void *cancel_user) {
  if (!command || !output || output_size == 0) return -1;
  if (timeout_sec <= 0) timeout_sec = 1;
  output[0] = '\0';

#ifdef _WIN32
  HANDLE hRead, hWrite;
  SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
  if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return -1;
  SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);
  STARTUPINFOA si;
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdOutput = hWrite;
  si.hStdError = hWrite;
  char cmdline[3072];
  snprintf(cmdline, sizeof(cmdline), "cmd.exe /c \"%s\"", command);
  PROCESS_INFORMATION pi = { 0 };
  if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW | CREATE_SUSPENDED,
                      NULL, NULL, &si, &pi)) {
    CloseHandle(hWrite); CloseHandle(hRead);
    return -1;
  }
  edr_collector_register_policy_canary_process((uint32_t)pi.dwProcessId, command);
  if (ResumeThread(pi.hThread) == (DWORD)-1) {
    TerminateProcess(pi.hProcess, 125);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hWrite);
    CloseHandle(hRead);
    return -1;
  }
  CloseHandle(hWrite);
  ULONGLONG deadline = GetTickCount64() + (ULONGLONG)timeout_sec * 1000ull;
  size_t total = 0;
  int timed_out = 0;
  int cancelled = 0;
  for (;;) {
    DWORD avail = 0;
    if (PeekNamedPipe(hRead, NULL, 0, NULL, &avail, NULL) && avail > 0) {
      char buf[4096];
      DWORD toread = avail < (DWORD)sizeof(buf) ? avail : (DWORD)sizeof(buf);
      DWORD read = 0;
      if (ReadFile(hRead, buf, toread, &read, NULL) && read > 0) {
        size_t rem = output_size - total - 1u;
        if (rem > 0u) {
          size_t tocopy = (size_t)read < rem ? (size_t)read : rem;
          memcpy(output + total, buf, tocopy);
          total += tocopy;
          output[total] = '\0';
        }
      }
    }
    DWORD waited = WaitForSingleObject(pi.hProcess, 50);
    if (waited == WAIT_OBJECT_0) {
      break;
    }
    if (cancel_check && cancel_check(cancel_user)) {
      cancelled = 1;
      TerminateProcess(pi.hProcess, 130);
      WaitForSingleObject(pi.hProcess, 3000);
      break;
    }
    if (GetTickCount64() >= deadline) {
      timed_out = 1;
      TerminateProcess(pi.hProcess, 124);
      WaitForSingleObject(pi.hProcess, 3000);
      break;
    }
  }
  for (;;) {
    DWORD avail = 0;
    if (!PeekNamedPipe(hRead, NULL, 0, NULL, &avail, NULL) || avail == 0) {
      break;
    }
    char buf[4096];
    DWORD toread = avail < (DWORD)sizeof(buf) ? avail : (DWORD)sizeof(buf);
    DWORD read = 0;
    if (!ReadFile(hRead, buf, toread, &read, NULL) || read == 0) {
      break;
    }
    size_t rem = output_size - total - 1u;
    if (rem > 0u) {
      size_t tocopy = (size_t)read < rem ? (size_t)read : rem;
      memcpy(output + total, buf, tocopy);
      total += tocopy;
      output[total] = '\0';
    }
  }
  DWORD ec = 0;
  GetExitCodeProcess(pi.hProcess, &ec);
  if (exit_code) *exit_code = cancelled ? 130 : (timed_out ? 124 : (int)ec);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  CloseHandle(hRead);
  return 0;
#else
  int pipefd[2];
  if (pipe(pipefd) != 0) return -1;
  fcntl(pipefd[0], F_SETFL, O_NONBLOCK);
  pid_t pid = fork();
  if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return -1; }
  if (pid == 0) {
    (void)setpgid(0, 0);
    dup2(pipefd[1], STDOUT_FILENO);
    dup2(pipefd[1], STDERR_FILENO);
    close(pipefd[0]);
    close(pipefd[1]);
    execl("/bin/sh", "sh", "-c", command, (char *)NULL);
    _exit(127);
  }
  (void)setpgid(pid, pid);
  close(pipefd[1]);
  time_t start = time(NULL);
  size_t total = 0;
  int completed = 0;
  int cancelled = 0;
  for (;;) {
    for (;;) {
      char buf[4096];
      ssize_t nread = read(pipefd[0], buf, sizeof(buf));
      if (nread > 0) {
        size_t rem = output_size - total - 1u;
        if (rem > 0u) {
          size_t tocopy = (size_t)nread < rem ? (size_t)nread : rem;
          memcpy(output + total, buf, tocopy);
          total += tocopy;
          output[total] = '\0';
        }
        continue;
      }
      if (nread == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
        break;
      }
      break;
    }
    int status;
    pid_t w = waitpid(pid, &status, WNOHANG);
    if (w > 0) {
      if (exit_code) *exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
      completed = 1;
      break;
    }
    if (cancel_check && cancel_check(cancel_user)) {
      cancelled = 1;
      break;
    }
    if ((int)(time(NULL) - start) >= timeout_sec) {
      break;
    }
    usleep(100000);
  }
  if (!completed) {
    if (kill(-pid, SIGKILL) != 0) {
      (void)kill(pid, SIGKILL);
    }
    waitpid(pid, NULL, 0);
    if (exit_code) *exit_code = cancelled ? 130 : 124;
    for (;;) {
      char buf[4096];
      ssize_t nread = read(pipefd[0], buf, sizeof(buf));
      if (nread <= 0) {
        break;
      }
      size_t rem = output_size - total - 1u;
      if (rem > 0u) {
        size_t tocopy = (size_t)nread < rem ? (size_t)nread : rem;
        memcpy(output + total, buf, tocopy);
        total += tocopy;
        output[total] = '\0';
      }
    }
  }
  close(pipefd[0]);
  return 0;
#endif
}

int edr_shell_exec(const char *command, int timeout_sec,
                   char *output, size_t output_size, int *exit_code) {
  return edr_shell_exec_cancellable(command, timeout_sec, output, output_size,
                                    exit_code, NULL, NULL);
}

static cJSON *parse_json_object(const uint8_t *payload, size_t len) {
  if (!payload || len == 0u) {
    return NULL;
  }
  char *json = (char *)malloc(len + 1u);
  if (!json) {
    return NULL;
  }
  memcpy(json, payload, len);
  json[len] = '\0';
  const char *parse_end = NULL;
  cJSON *root = cJSON_ParseWithLengthOpts(json, len + 1u, &parse_end, 1);
  while (parse_end && parse_end < json + len && isspace((unsigned char)*parse_end)) {
    parse_end++;
  }
  if (!cJSON_IsObject(root) || parse_end != json + len) {
    cJSON_Delete(root);
    root = NULL;
  }
  free(json);
  return root;
}

int edr_parse_json_string(const uint8_t *payload, size_t len,
                          const char *key, char *out, size_t out_size) {
  if (!key || !out || out_size == 0u) {
    return 0;
  }
  out[0] = '\0';
  cJSON *root = parse_json_object(payload, len);
  const cJSON *value = root ? cJSON_GetObjectItemCaseSensitive(root, key) : NULL;
  if (!cJSON_IsString(value) || !value->valuestring) {
    cJSON_Delete(root);
    return 0;
  }
  size_t value_len = strlen(value->valuestring);
  if (value_len >= out_size) {
    cJSON_Delete(root);
    return 0;
  }
  memcpy(out, value->valuestring, value_len + 1u);
  cJSON_Delete(root);
  return 1;
}

int edr_parse_json_int(const uint8_t *payload, size_t len,
                       const char *key, int *out) {
  if (!key || !out) {
    return 0;
  }
  cJSON *root = parse_json_object(payload, len);
  const cJSON *value = root ? cJSON_GetObjectItemCaseSensitive(root, key) : NULL;
  if (!cJSON_IsNumber(value) || value->valuedouble < (double)INT_MIN ||
      value->valuedouble > (double)INT_MAX) {
    cJSON_Delete(root);
    return 0;
  }
  int parsed = (int)value->valuedouble;
  if ((double)parsed != value->valuedouble) {
    cJSON_Delete(root);
    return 0;
  }
  *out = parsed;
  cJSON_Delete(root);
  return 1;
}

int edr_parse_json_bool(const uint8_t *payload, size_t len,
                        const char *key, int *out) {
  if (!key || !out) {
    return 0;
  }
  cJSON *root = parse_json_object(payload, len);
  const cJSON *value = root ? cJSON_GetObjectItemCaseSensitive(root, key) : NULL;
  if (!cJSON_IsBool(value)) {
    cJSON_Delete(root);
    return 0;
  }
  *out = cJSON_IsTrue(value) ? 1 : 0;
  cJSON_Delete(root);
  return 1;
}
