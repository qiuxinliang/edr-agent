#include "edr/shell_session.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>

typedef struct {
  char session_id[EDR_SS_ID_LEN];
  HANDLE process;
  HANDLE stdin_w;
  HANDLE stdout_r;
  HANDLE job;
  uint64_t start_ms;
  bool active;
} ShellSession;

static ShellSession g_sessions[EDR_SS_MAX_SESSIONS];
static uint32_t g_max_sessions;
static uint32_t g_timeout_s;
static uint32_t g_max_output_kb;
static edr_ss_write_fn g_write_fn;
static void *g_write_user;
static bool g_initialized;

static ShellSession *find_free_slot(void) {
  for (uint32_t i = 0; i < g_max_sessions; i++) {
    if (!g_sessions[i].active) return &g_sessions[i];
  }
  return NULL;
}

static ShellSession *find_by_id(const char *id) {
  if (!id) return NULL;
  for (uint32_t i = 0; i < g_max_sessions; i++) {
    if (g_sessions[i].active &&
        strcmp(g_sessions[i].session_id, id) == 0) {
      return &g_sessions[i];
    }
  }
  return NULL;
}

static void close_session_handles(ShellSession *s) {
  if (s->stdin_w)  { CloseHandle(s->stdin_w);  s->stdin_w = NULL; }
  if (s->stdout_r) { CloseHandle(s->stdout_r); s->stdout_r = NULL; }
  if (s->process)  { CloseHandle(s->process);  s->process = NULL; }
  if (s->job)      { CloseHandle(s->job);      s->job = NULL; }
}

void edr_shell_session_init(uint32_t max_sessions, uint32_t timeout_s,
                            uint32_t max_output_kb,
                            edr_ss_write_fn write_fn, void *write_user) {
  if (max_sessions > EDR_SS_MAX_SESSIONS) max_sessions = EDR_SS_MAX_SESSIONS;
  g_max_sessions = max_sessions;
  g_timeout_s = timeout_s;
  g_max_output_kb = max_output_kb;
  g_write_fn = write_fn;
  g_write_user = write_user;
  (void)memset(g_sessions, 0, sizeof(g_sessions));
  g_initialized = true;
}

void edr_shell_session_shutdown(void) {
  for (uint32_t i = 0; i < g_max_sessions; i++) {
    if (g_sessions[i].active) {
      if (g_sessions[i].process) {
        TerminateProcess(g_sessions[i].process, 1);
      }
      close_session_handles(&g_sessions[i]);
    }
  }
  (void)memset(g_sessions, 0, sizeof(g_sessions));
  g_initialized = false;
}

int edr_shell_session_open(const char *session_id, const char *shell) {
  if (!g_initialized || !session_id || !shell) return -1;

  ShellSession *s = find_free_slot();
  if (!s) return -1;

  HANDLE stdin_r = NULL, stdin_w = NULL;
  HANDLE stdout_r = NULL, stdout_w = NULL;
  SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };

  if (!CreatePipe(&stdin_r, &stdin_w, &sa, 0) ||
      !CreatePipe(&stdout_r, &stdout_w, &sa, 0)) {
    if (stdin_r)  CloseHandle(stdin_r);
    if (stdin_w)  CloseHandle(stdin_w);
    if (stdout_r) CloseHandle(stdout_r);
    if (stdout_w) CloseHandle(stdout_w);
    return -1;
  }
  SetHandleInformation(stdin_w, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(stdout_r, HANDLE_FLAG_INHERIT, 0);

  size_t shell_wlen = strlen(shell) + 1;
  wchar_t *wshell = (wchar_t *)malloc(shell_wlen * sizeof(wchar_t));
  if (!wshell) {
    CloseHandle(stdin_r);  CloseHandle(stdin_w);
    CloseHandle(stdout_r); CloseHandle(stdout_w);
    return -1;
  }
  MultiByteToWideChar(CP_UTF8, 0, shell, -1, wshell, (int)shell_wlen);

  PROCESS_INFORMATION pi = {0};
  STARTUPINFOW si = { sizeof(si) };
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  si.hStdInput  = stdin_r;
  si.hStdOutput = stdout_w;
  si.hStdError  = stdout_w;

  HANDLE job = CreateJobObject(NULL, NULL);
  if (job) {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {0};
    jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                            &jeli, sizeof(jeli));
  }

  BOOL cr = CreateProcessW(NULL, wshell, NULL, NULL, TRUE,
                           CREATE_NO_WINDOW | CREATE_SUSPENDED,
                           NULL, NULL, &si, &pi);
  free(wshell);
  CloseHandle(stdin_r);
  CloseHandle(stdout_w);

  if (!cr) {
    CloseHandle(stdin_w);
    CloseHandle(stdout_r);
    if (job) CloseHandle(job);
    return -1;
  }

  if (job) {
    AssignProcessToJobObject(job, pi.hProcess);
  }

  ResumeThread(pi.hThread);
  CloseHandle(pi.hThread);

  strncpy(s->session_id, session_id, EDR_SS_ID_LEN - 1);
  s->session_id[EDR_SS_ID_LEN - 1] = '\0';
  s->process = pi.hProcess;
  s->stdin_w = stdin_w;
  s->stdout_r = stdout_r;
  s->job = job;
  s->start_ms = GetTickCount64();
  s->active = true;
  return 0;
}

int edr_shell_session_input(const char *session_id,
                            const char *data, size_t len) {
  if (!g_initialized || !session_id || !data || len == 0) return -1;
  ShellSession *s = find_by_id(session_id);
  if (!s) return -1;

  DWORD written = 0;
  if (!WriteFile(s->stdin_w, data, (DWORD)len, &written, NULL)) {
    return -1;
  }
  return 0;
}

void edr_shell_session_close(const char *session_id) {
  ShellSession *s = find_by_id(session_id);
  if (!s) return;

  if (s->process) TerminateProcess(s->process, 0);
  close_session_handles(s);
  (void)memset(s, 0, sizeof(*s));
}

void edr_shell_session_poll(void) {
  if (!g_initialized) return;

  uint64_t now = GetTickCount64();

  for (uint32_t i = 0; i < g_max_sessions; i++) {
    ShellSession *s = &g_sessions[i];
    if (!s->active) continue;

    DWORD avail = 0;
    if (!PeekNamedPipe(s->stdout_r, NULL, 0, NULL, &avail, NULL)) {
      if (g_write_fn) {
        DWORD ec = 0;
        GetExitCodeProcess(s->process, &ec);
        g_write_fn(s->session_id, NULL, 0, (int)ec, true, g_write_user);
      }
      close_session_handles(s);
      (void)memset(s, 0, sizeof(*s));
      continue;
    }

    if (avail > 0) {
      uint32_t cap = g_max_output_kb * 1024;
      if (avail > cap) avail = cap;
      char *buf = (char *)malloc(avail + 1);
      if (buf) {
        DWORD got = 0;
        if (ReadFile(s->stdout_r, buf, avail, &got, NULL) && got > 0) {
          if (g_write_fn) {
            g_write_fn(s->session_id, buf, got, 0, false, g_write_user);
          }
        }
        free(buf);
      }
    }

    DWORD ec = 0;
    if (GetExitCodeProcess(s->process, &ec) && ec != STILL_ACTIVE) {
      if (g_write_fn) {
        g_write_fn(s->session_id, NULL, 0, (int)ec, true, g_write_user);
      }
      close_session_handles(s);
      (void)memset(s, 0, sizeof(*s));
      continue;
    }

    uint64_t elapsed = now - s->start_ms;
    if (g_timeout_s > 0 && elapsed > (uint64_t)g_timeout_s * 1000ULL) {
      TerminateProcess(s->process, 1);
      if (g_write_fn) {
        g_write_fn(s->session_id, NULL, 0, 1, true, g_write_user);
      }
      close_session_handles(s);
      (void)memset(s, 0, sizeof(*s));
    }
  }
}

uint32_t edr_shell_session_active_count(void) {
  uint32_t c = 0;
  for (uint32_t i = 0; i < g_max_sessions; i++) {
    if (g_sessions[i].active) c++;
  }
  return c;
}

#else /* POSIX */

#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>

typedef struct {
  char session_id[EDR_SS_ID_LEN];
  pid_t child_pid;
  int stdin_fd;
  int stdout_fd;
  uint64_t start_ms;
  bool active;
} ShellSession;

static ShellSession g_sessions[EDR_SS_MAX_SESSIONS];
static uint32_t g_max_sessions;
static uint32_t g_timeout_s;
static uint32_t g_max_output_kb;
static edr_ss_write_fn g_write_fn;
static void *g_write_user;
static bool g_initialized;

static ShellSession *find_free_slot(void) {
  for (uint32_t i = 0; i < g_max_sessions; i++) {
    if (!g_sessions[i].active) return &g_sessions[i];
  }
  return NULL;
}

static ShellSession *find_by_id(const char *id) {
  if (!id) return NULL;
  for (uint32_t i = 0; i < g_max_sessions; i++) {
    if (g_sessions[i].active &&
        strcmp(g_sessions[i].session_id, id) == 0) {
      return &g_sessions[i];
    }
  }
  return NULL;
}

static uint64_t ms_now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

void edr_shell_session_init(uint32_t max_sessions, uint32_t timeout_s,
                            uint32_t max_output_kb,
                            edr_ss_write_fn write_fn, void *write_user) {
  if (max_sessions > EDR_SS_MAX_SESSIONS) max_sessions = EDR_SS_MAX_SESSIONS;
  g_max_sessions = max_sessions;
  g_timeout_s = timeout_s;
  g_max_output_kb = max_output_kb;
  g_write_fn = write_fn;
  g_write_user = write_user;
  (void)memset(g_sessions, 0, sizeof(g_sessions));
  g_initialized = true;
}

void edr_shell_session_shutdown(void) {
  for (uint32_t i = 0; i < g_max_sessions; i++) {
    if (g_sessions[i].active) {
      kill(g_sessions[i].child_pid, SIGKILL);
      waitpid(g_sessions[i].child_pid, NULL, WNOHANG);
      if (g_sessions[i].stdin_fd >= 0)  close(g_sessions[i].stdin_fd);
      if (g_sessions[i].stdout_fd >= 0) close(g_sessions[i].stdout_fd);
    }
  }
  (void)memset(g_sessions, 0, sizeof(g_sessions));
  g_initialized = false;
}

int edr_shell_session_open(const char *session_id, const char *shell) {
  if (!g_initialized || !session_id || !shell) return -1;

  ShellSession *s = find_free_slot();
  if (!s) return -1;

  int stdin_pipe[2], stdout_pipe[2];
  if (pipe(stdin_pipe) < 0 || pipe(stdout_pipe) < 0) {
    return -1;
  }

  pid_t pid = fork();
  if (pid < 0) {
    close(stdin_pipe[0]); close(stdin_pipe[1]);
    close(stdout_pipe[0]); close(stdout_pipe[1]);
    return -1;
  }

  if (pid == 0) {
    dup2(stdin_pipe[0], STDIN_FILENO);
    dup2(stdout_pipe[1], STDOUT_FILENO);
    dup2(stdout_pipe[1], STDERR_FILENO);
    close(stdin_pipe[0]); close(stdin_pipe[1]);
    close(stdout_pipe[0]); close(stdout_pipe[1]);
    execl(shell, shell, (char *)NULL);
    _exit(127);
  }

  close(stdin_pipe[0]);
  close(stdout_pipe[1]);

  fcntl(stdout_pipe[0], F_SETFL, O_NONBLOCK);

  strncpy(s->session_id, session_id, EDR_SS_ID_LEN - 1);
  s->session_id[EDR_SS_ID_LEN - 1] = '\0';
  s->child_pid = pid;
  s->stdin_fd = stdin_pipe[1];
  s->stdout_fd = stdout_pipe[0];
  s->start_ms = ms_now();
  s->active = true;
  return 0;
}

int edr_shell_session_input(const char *session_id,
                            const char *data, size_t len) {
  if (!g_initialized || !session_id || !data || len == 0) return -1;
  ShellSession *s = find_by_id(session_id);
  if (!s || s->stdin_fd < 0) return -1;
  (void)!write(s->stdin_fd, data, len);
  return 0;
}

void edr_shell_session_close(const char *session_id) {
  ShellSession *s = find_by_id(session_id);
  if (!s) return;
  kill(s->child_pid, SIGKILL);
  waitpid(s->child_pid, NULL, WNOHANG);
  if (s->stdin_fd >= 0)  { close(s->stdin_fd);  s->stdin_fd = -1; }
  if (s->stdout_fd >= 0) { close(s->stdout_fd); s->stdout_fd = -1; }
  (void)memset(s, 0, sizeof(*s));
}

void edr_shell_session_poll(void) {
  if (!g_initialized) return;

  uint64_t now = ms_now();

  for (uint32_t i = 0; i < g_max_sessions; i++) {
    ShellSession *s = &g_sessions[i];
    if (!s->active) continue;

    uint32_t cap = g_max_output_kb * 1024;
    char *buf = (char *)malloc(cap);
    if (!buf) continue;

    ssize_t n = read(s->stdout_fd, buf, cap);
    if (n > 0) {
      if (g_write_fn) {
        g_write_fn(s->session_id, buf, (size_t)n, 0, false, g_write_user);
      }
    }

    int status = 0;
    pid_t wr = waitpid(s->child_pid, &status, WNOHANG);
    if (wr > 0) {
      int ec = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
      if (g_write_fn) {
        g_write_fn(s->session_id, NULL, 0, ec, true, g_write_user);
      }
      if (s->stdin_fd >= 0)  { close(s->stdin_fd);  s->stdin_fd = -1; }
      if (s->stdout_fd >= 0) { close(s->stdout_fd); s->stdout_fd = -1; }
      (void)memset(s, 0, sizeof(*s));
      free(buf);
      continue;
    }

    if (n <= 0 && g_timeout_s > 0) {
      uint64_t elapsed = now - s->start_ms;
      if (elapsed > (uint64_t)g_timeout_s * 1000ULL) {
        kill(s->child_pid, SIGKILL);
        waitpid(s->child_pid, NULL, WNOHANG);
        if (g_write_fn) {
          g_write_fn(s->session_id, NULL, 0, 1, true, g_write_user);
        }
        if (s->stdin_fd >= 0)  { close(s->stdin_fd);  s->stdin_fd = -1; }
        if (s->stdout_fd >= 0) { close(s->stdout_fd); s->stdout_fd = -1; }
        (void)memset(s, 0, sizeof(*s));
      }
    }
    free(buf);
  }
}

uint32_t edr_shell_session_active_count(void) {
  uint32_t c = 0;
  for (uint32_t i = 0; i < g_max_sessions; i++) {
    if (g_sessions[i].active) c++;
  }
  return c;
}

#endif
