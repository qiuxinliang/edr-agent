#include "edr/shell_exec.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#endif

static const char *g_shell_allow[] = {
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

static const char *g_shell_block[] = {
  "rm ", "del ", "erase ", "rmdir ", "rd ",
  "format ", "fdisk ",
  "shutdown", "reboot", "halt", "poweroff", "logoff",
  NULL
};

int edr_shell_is_allowed(const char *command) {
  if (!command || !command[0]) return 0;
  char lower[1024];
  size_t n = strlen(command);
  if (n >= sizeof(lower)) n = sizeof(lower) - 1;
  for (size_t i = 0; i < n; i++) lower[i] = (char)tolower((unsigned char)command[i]);
  lower[n] = '\0';

  for (int i = 0; g_shell_block[i]; i++) {
    if (strstr(lower, g_shell_block[i])) return 0;
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

  for (int i = 0; g_shell_allow[i]; i++) {
    if (strcmp(cmd, g_shell_allow[i]) == 0) return 1;
  }
  return 0;
}

int edr_shell_exec(const char *command, int timeout_sec,
                   char *output, size_t output_size, int *exit_code) {
  if (!command || !output || output_size == 0) return -1;
  output[0] = '\0';

#ifdef _WIN32
  HANDLE hRead, hWrite;
  SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
  if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return -1;
  SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 1);
  STARTUPINFOA si = { sizeof(si) };
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdOutput = hWrite;
  si.hStdError = hWrite;
  char cmdline[3072];
  snprintf(cmdline, sizeof(cmdline), "cmd.exe /c \"%s\"", command);
  PROCESS_INFORMATION pi = { 0 };
  if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
    CloseHandle(hWrite); CloseHandle(hRead);
    return -1;
  }
  CloseHandle(hWrite);
  DWORD waited = WaitForSingleObject(pi.hProcess, (DWORD)(timeout_sec * 1000));
  if (waited == WAIT_TIMEOUT) {
    TerminateProcess(pi.hProcess, 1);
    WaitForSingleObject(pi.hProcess, 3000);
  }
  DWORD avail = 0;
  PeekNamedPipe(hRead, NULL, 0, NULL, &avail, NULL);
  if (avail > 0) {
    DWORD toread = avail < (DWORD)(output_size - 1) ? avail : (DWORD)(output_size - 1);
    DWORD read = 0;
    ReadFile(hRead, output, toread, &read, NULL);
    output[read] = '\0';
  }
  DWORD ec = 0;
  GetExitCodeProcess(pi.hProcess, &ec);
  if (exit_code) *exit_code = (int)ec;
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
    dup2(pipefd[1], STDOUT_FILENO);
    dup2(pipefd[1], STDERR_FILENO);
    close(pipefd[0]);
    close(pipefd[1]);
    execl("/bin/sh", "sh", "-c", command, (char *)NULL);
    _exit(127);
  }
  close(pipefd[1]);
  int elapsed = 0;
  size_t total = 0;
  while (elapsed < timeout_sec) {
    char buf[4096];
    ssize_t nread = read(pipefd[0], buf, sizeof(buf) - 1);
    if (nread > 0) {
      buf[nread] = '\0';
      size_t rem = output_size - total - 1;
      if (rem > 0) {
        size_t tocopy = (size_t)nread < rem ? (size_t)nread : rem;
        memcpy(output + total, buf, tocopy);
        total += tocopy;
        output[total] = '\0';
      }
    } else if (nread == 0) {
      break;
    }
    int status;
    pid_t w = waitpid(pid, &status, WNOHANG);
    if (w > 0) {
      if (exit_code) *exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
      break;
    }
    usleep(500000);
    elapsed++;
  }
  if (elapsed >= timeout_sec) {
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    if (exit_code) *exit_code = 124;
  }
  close(pipefd[0]);
  return 0;
#endif
}

int edr_parse_json_string(const uint8_t *payload, size_t len,
                          const char *key, char *out, size_t out_size) {
  if (!payload || !key || !out || out_size == 0) return 0;
  out[0] = '\0';
  char search[128];
  snprintf(search, sizeof(search), "\"%s\"", key);
  const char *p = (const char *)payload;
  const char *end = p + len;
  const char *pos = NULL;
  for (const char *s = p; s + strlen(search) <= end; s++) {
    if (strncmp(s, search, strlen(search)) == 0) {
      pos = s + strlen(search);
      break;
    }
  }
  if (!pos) return 0;
  while (pos < end && (*pos == ' ' || *pos == ':' || *pos == '\t')) pos++;
  if (pos >= end || *pos != '"') return 0;
  pos++;
  size_t i = 0;
  while (pos < end && *pos != '"' && i + 1 < out_size) {
    if (*pos == '\\' && pos + 1 < end) {
      pos++;
      if (*pos == 'n') out[i++] = '\n';
      else if (*pos == 'r') out[i++] = '\r';
      else if (*pos == 't') out[i++] = '\t';
      else out[i++] = *pos;
    } else {
      out[i++] = *pos;
    }
    pos++;
  }
  out[i] = '\0';
  return 1;
}

int edr_parse_json_int(const uint8_t *payload, size_t len,
                       const char *key, int *out) {
  if (!payload || !key || !out) return 0;
  char search[128];
  snprintf(search, sizeof(search), "\"%s\"", key);
  const char *p = (const char *)payload;
  const char *end = p + len;
  const char *pos = NULL;
  for (const char *s = p; s + strlen(search) <= end; s++) {
    if (strncmp(s, search, strlen(search)) == 0) {
      pos = s + strlen(search);
      break;
    }
  }
  if (!pos) return 0;
  while (pos < end && (*pos == ' ' || *pos == ':' || *pos == '\t')) pos++;
  if (pos >= end) return 0;
  if (*pos == '"') {
    pos++;
    char buf[32];
    size_t i = 0;
    while (pos < end && *pos != '"' && i < sizeof(buf) - 1) buf[i++] = *pos++;
    buf[i] = '\0';
    *out = atoi(buf);
    return 1;
  }
  char buf[32];
  size_t i = 0;
  while (pos < end && (isdigit((unsigned char)*pos) || *pos == '-') && i < sizeof(buf) - 1)
    buf[i++] = *pos++;
  buf[i] = '\0';
  if (i > 0) { *out = atoi(buf); return 1; }
  if (strncmp(pos, "true", 4) == 0) { *out = 1; return 1; }
  if (strncmp(pos, "false", 5) == 0) { *out = 0; return 1; }
  return 0;
}
