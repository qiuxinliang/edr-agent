#include "edr/shell_exec.h"
#include <ctype.h>
#include <errno.h>
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

static int json_hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
  if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
  return -1;
}

static int append_utf8_codepoint(uint32_t cp, char *out, size_t out_size, size_t *idx) {
  if (!out || !idx || out_size == 0) return 0;
  if (cp <= 0x7Fu) {
    if (*idx + 1 >= out_size) return 0;
    out[(*idx)++] = (char)cp;
    return 1;
  }
  if (cp <= 0x7FFu) {
    if (*idx + 2 >= out_size) return 0;
    out[(*idx)++] = (char)(0xC0u | ((cp >> 6) & 0x1Fu));
    out[(*idx)++] = (char)(0x80u | (cp & 0x3Fu));
    return 1;
  }
  if (cp >= 0xD800u && cp <= 0xDFFFu) {
    cp = 0xFFFDu;
  }
  if (cp <= 0xFFFFu) {
    if (*idx + 3 >= out_size) return 0;
    out[(*idx)++] = (char)(0xE0u | ((cp >> 12) & 0x0Fu));
    out[(*idx)++] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
    out[(*idx)++] = (char)(0x80u | (cp & 0x3Fu));
    return 1;
  }
  if (cp > 0x10FFFFu) cp = 0xFFFDu;
  if (*idx + 4 >= out_size) return 0;
  out[(*idx)++] = (char)(0xF0u | ((cp >> 18) & 0x07u));
  out[(*idx)++] = (char)(0x80u | ((cp >> 12) & 0x3Fu));
  out[(*idx)++] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
  out[(*idx)++] = (char)(0x80u | (cp & 0x3Fu));
  return 1;
}

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

int edr_shell_exec(const char *command, int timeout_sec,
                   char *output, size_t output_size, int *exit_code) {
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
  if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
    CloseHandle(hWrite); CloseHandle(hRead);
    return -1;
  }
  CloseHandle(hWrite);
  ULONGLONG deadline = GetTickCount64() + (ULONGLONG)timeout_sec * 1000ull;
  size_t total = 0;
  int timed_out = 0;
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
  if (exit_code) *exit_code = timed_out ? 124 : (int)ec;
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
    if (exit_code) *exit_code = 124;
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
      else if (*pos == 'b') out[i++] = '\b';
      else if (*pos == 'f') out[i++] = '\f';
      else if (*pos == 'u' && pos + 4 < end) {
        int h0 = json_hex_value(pos[1]);
        int h1 = json_hex_value(pos[2]);
        int h2 = json_hex_value(pos[3]);
        int h3 = json_hex_value(pos[4]);
        if (h0 >= 0 && h1 >= 0 && h2 >= 0 && h3 >= 0) {
          uint32_t cp = (uint32_t)((h0 << 12) | (h1 << 8) | (h2 << 4) | h3);
          (void)append_utf8_codepoint(cp, out, out_size, &i);
          pos += 4;
        } else {
          out[i++] = *pos;
        }
      }
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
