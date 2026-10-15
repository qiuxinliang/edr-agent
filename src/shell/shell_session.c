#include "edr/shell_session.h"
#include "edr/windows_spawn_lock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* One volatile chunk per bounded session, never an unbounded result queue.
 * Durable command-state admission owns completion. On pressure stop reading
 * the pipe and reject new input; retry the exact sequence with capped backoff.
 * Explicit cancellation/shutdown reports any undurable bytes. */
typedef struct {
  char data[EDR_SS_STREAM_CHUNK_BYTES];
  size_t len;
  uint64_t retry_after_ms;
  unsigned refusals;
  bool ready, closed;
  int exit_code;
} ShellPending;

static int flush_pending(ShellPending *p, const char *id, uint64_t *sequence,
    const EdrCommandResultAuthorization *authority, uint64_t now,
    edr_ss_write_fn write_fn, void *user) {
  if (!p->ready) return 0;
  if (now < p->retry_after_ms) return -1;
  if (!write_fn || write_fn(id, *sequence, p->closed ? NULL : p->data, p->len,
      p->exit_code, p->closed, authority, user) != 0) {
    if (!p->refusals) fprintf(stderr,
        "[shell] durable output refused; input and pipe reads paused seq=%llu bytes=%zu closed=%d\n",
        (unsigned long long)*sequence,p->len,p->closed ? 1 : 0);
    if (p->refusals < 5u) p->refusals++;
    p->retry_after_ms=now+(250u << (p->refusals-1u));
    return -1;
  }
  ++*sequence;
  memset(p,0,sizeof(*p));
  return 0;
}
static void cancel_pending(const ShellPending *p) {
  if (p->ready) fprintf(stderr,
      "[shell] explicit cancellation discarded undurable output bytes=%zu closed=%d\n",
      p->len,p->closed ? 1 : 0);
}

#ifdef _WIN32
#include <windows.h>

typedef struct {
  char session_id[EDR_SS_ID_LEN];
  EdrCommandResultAuthorization result_authorization;
  HANDLE process;
  HANDLE stdin_w;
  HANDLE stdout_r;
  HANDLE job;
  uint64_t start_ms;
  uint64_t next_seq;
  bool active;
  bool exited;
  bool pipe_failure_reported;
  int exit_code;
  ShellPending pending;
} ShellSession;

static ShellSession g_sessions[EDR_SS_MAX_SESSIONS];
static uint32_t g_max_sessions;
static uint32_t g_timeout_s;
static uint32_t g_max_output_kb;
static edr_ss_write_fn g_write_fn;
static void *g_write_user;
static bool g_initialized;
static SRWLOCK g_sessions_lock = SRWLOCK_INIT;

static void sessions_lock(void) { AcquireSRWLockExclusive(&g_sessions_lock); }
static void sessions_unlock(void) { ReleaseSRWLockExclusive(&g_sessions_lock); }

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
  sessions_lock();
  if (g_initialized) {
    sessions_unlock();
    return;
  }
  if (max_sessions > EDR_SS_MAX_SESSIONS) max_sessions = EDR_SS_MAX_SESSIONS;
  g_max_sessions = max_sessions;
  g_timeout_s = timeout_s;
  g_max_output_kb = max_output_kb;
  g_write_fn = write_fn;
  g_write_user = write_user;
  (void)memset(g_sessions, 0, sizeof(g_sessions));
  g_initialized = true;
  sessions_unlock();
}

void edr_shell_session_shutdown(void) {
  sessions_lock();
  for (uint32_t i = 0; i < g_max_sessions; i++) {
    if (g_sessions[i].active) {
      if (g_sessions[i].process) {
        TerminateProcess(g_sessions[i].process, 1);
      }
      cancel_pending(&g_sessions[i].pending);
      close_session_handles(&g_sessions[i]);
    }
  }
  (void)memset(g_sessions, 0, sizeof(g_sessions));
  g_initialized = false;
  sessions_unlock();
}

int edr_shell_session_open(const char *session_id, const char *shell,
                            const EdrCommandResultAuthorization *authorization) {
  sessions_lock();
  if (!g_initialized || !session_id || !shell) {
    sessions_unlock();
    return -1;
  }

  ShellSession *s = find_free_slot();
  if (!s) {
    sessions_unlock();
    return -1;
  }

  HANDLE stdin_r = NULL, stdin_w = NULL;
  HANDLE stdout_r = NULL, stdout_w = NULL;
  SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
  EdrWindowsSpawnLock spawn_lock = { 0 };

  if (!edr_windows_spawn_lock_acquire(&spawn_lock) ||
      !CreatePipe(&stdin_r, &stdin_w, &sa, 0) ||
      !SetHandleInformation(stdin_w, HANDLE_FLAG_INHERIT, 0) ||
      !CreatePipe(&stdout_r, &stdout_w, &sa, 0) ||
      !SetHandleInformation(stdout_r, HANDLE_FLAG_INHERIT, 0)) {
    if (stdin_r)  CloseHandle(stdin_r);
    if (stdin_w)  CloseHandle(stdin_w);
    if (stdout_r) CloseHandle(stdout_r);
    if (stdout_w) CloseHandle(stdout_w);
    edr_windows_spawn_lock_release(&spawn_lock);
    sessions_unlock();
    return -1;
  }

  size_t shell_wlen = strlen(shell) + 1;
  wchar_t *wshell = (wchar_t *)malloc(shell_wlen * sizeof(wchar_t));
  if (!wshell) {
    CloseHandle(stdin_r);  CloseHandle(stdin_w);
    CloseHandle(stdout_r); CloseHandle(stdout_w);
    edr_windows_spawn_lock_release(&spawn_lock);
    sessions_unlock();
    return -1;
  }
  MultiByteToWideChar(CP_UTF8, 0, shell, -1, wshell, (int)shell_wlen);

  PROCESS_INFORMATION pi = {0};
  STARTUPINFOW si;
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
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
  edr_windows_spawn_lock_release(&spawn_lock);

  if (!cr) {
    CloseHandle(stdin_w);
    CloseHandle(stdout_r);
    if (job) CloseHandle(job);
    sessions_unlock();
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
  s->next_seq = 1u;
  memset(&s->result_authorization, 0, sizeof(s->result_authorization));
  if (authorization) s->result_authorization = *authorization;
  s->active = true;
  sessions_unlock();
  return 0;
}

int edr_shell_session_input(const char *session_id,
                            const char *data, size_t len) {
  sessions_lock();
  if (!g_initialized || !session_id || !data || len == 0) {
    sessions_unlock();
    return -1;
  }
  ShellSession *s = find_by_id(session_id);
  if (!s || s->pending.ready || s->exited) {
    sessions_unlock();
    return -1;
  }

  DWORD written = 0;
  if (!WriteFile(s->stdin_w, data, (DWORD)len, &written, NULL)) {
    sessions_unlock();
    return -1;
  }
  sessions_unlock();
  return 0;
}

void edr_shell_session_close(const char *session_id) {
  sessions_lock();
  ShellSession *s = find_by_id(session_id);
  if (!s) {
    sessions_unlock();
    return;
  }

  if (s->process) TerminateProcess(s->process, 0);
  cancel_pending(&s->pending);
  close_session_handles(s);
  (void)memset(s, 0, sizeof(*s));
  sessions_unlock();
}

void edr_shell_session_poll(void) {
  sessions_lock();
  if (!g_initialized) { sessions_unlock(); return; }
  uint64_t now=GetTickCount64();
  for(uint32_t i=0;i<g_max_sessions;i++) {
    ShellSession *s=&g_sessions[i];
    if(!s->active) continue;
    if(!s->exited && g_timeout_s && now-s->start_ms>(uint64_t)g_timeout_s*1000u) {
      /* TerminateProcess is asynchronous; observe actual exit below before
       * emitting a close marker or releasing the pipe handles. */
      TerminateProcess(s->process,1);
    }
    if(s->pending.ready) {
      bool closing=s->pending.closed;
      if(flush_pending(&s->pending,s->session_id,&s->next_seq,&s->result_authorization,
          now,g_write_fn,g_write_user)!=0) continue;
      if(closing) {close_session_handles(s);memset(s,0,sizeof(*s));continue;}
    }
    DWORD ec=0,avail=0;
    if(!s->exited && GetExitCodeProcess(s->process,&ec) && ec!=STILL_ACTIVE) {
      s->exited=true;s->exit_code=(int)ec;
    }
    BOOL pipe_ok=PeekNamedPipe(s->stdout_r,NULL,0,NULL,&avail,NULL);
    if(!pipe_ok && !s->exited && !s->pipe_failure_reported) {
      DWORD pipe_error=GetLastError();
      s->pipe_failure_reported=true;
      fprintf(stderr,"[shell] output pipe unavailable while process is active; "
          "waiting for actual exit or timeout error=%lu\n",(unsigned long)pipe_error);
    }
    if(pipe_ok && avail>0) {
      uint32_t cap=g_max_output_kb>=2u?EDR_SS_STREAM_CHUNK_BYTES:g_max_output_kb*1024u;
      if(avail>cap) avail=cap;
      DWORD got=0;
      if(avail && ReadFile(s->stdout_r,s->pending.data,avail,&got,NULL) && got>0) {
        s->pending.len=got;s->pending.ready=true;
        (void)flush_pending(&s->pending,s->session_id,&s->next_seq,&s->result_authorization,
            now,g_write_fn,g_write_user);
        continue; /* Drain all remaining pipe bytes before the close marker. */
      }
    }
    /* A child may close stdout before it finishes. Pipe EOF/failure is not
     * process completion and must not release the Job or invent exit code 0. */
    if(s->exited) {
      s->pending.ready=true;s->pending.closed=true;s->pending.exit_code=s->exit_code;
      if(flush_pending(&s->pending,s->session_id,&s->next_seq,&s->result_authorization,
          now,g_write_fn,g_write_user)==0) {close_session_handles(s);memset(s,0,sizeof(*s));}
    }
  }
  sessions_unlock();
}

uint32_t edr_shell_session_active_count(void) {
  sessions_lock();
  uint32_t c = 0;
  for (uint32_t i = 0; i < g_max_sessions; i++) {
    if (g_sessions[i].active) c++;
  }
  sessions_unlock();
  return c;
}

#else /* POSIX */

#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>

typedef struct {
  char session_id[EDR_SS_ID_LEN];
  EdrCommandResultAuthorization result_authorization;
  pid_t child_pid;
  int stdin_fd;
  int stdout_fd;
  uint64_t start_ms;
  uint64_t next_seq;
  bool active;
  bool exited;
  int exit_code;
  ShellPending pending;
} ShellSession;

static ShellSession g_sessions[EDR_SS_MAX_SESSIONS];
static uint32_t g_max_sessions;
static uint32_t g_timeout_s;
static uint32_t g_max_output_kb;
static edr_ss_write_fn g_write_fn;
static void *g_write_user;
static bool g_initialized;
static pthread_mutex_t g_sessions_lock = PTHREAD_MUTEX_INITIALIZER;

static void sessions_lock(void) { (void)pthread_mutex_lock(&g_sessions_lock); }
static void sessions_unlock(void) { (void)pthread_mutex_unlock(&g_sessions_lock); }

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
  sessions_lock();
  if (g_initialized) {
    sessions_unlock();
    return;
  }
  if (max_sessions > EDR_SS_MAX_SESSIONS) max_sessions = EDR_SS_MAX_SESSIONS;
  g_max_sessions = max_sessions;
  g_timeout_s = timeout_s;
  g_max_output_kb = max_output_kb;
  g_write_fn = write_fn;
  g_write_user = write_user;
  (void)memset(g_sessions, 0, sizeof(g_sessions));
  g_initialized = true;
  sessions_unlock();
}

void edr_shell_session_shutdown(void) {
  sessions_lock();
  for (uint32_t i = 0; i < g_max_sessions; i++) {
    if (g_sessions[i].active) {
      if(!g_sessions[i].exited) {
        kill(g_sessions[i].child_pid, SIGKILL);
        waitpid(g_sessions[i].child_pid, NULL, WNOHANG);
      }
      cancel_pending(&g_sessions[i].pending);
      if (g_sessions[i].stdin_fd >= 0)  close(g_sessions[i].stdin_fd);
      if (g_sessions[i].stdout_fd >= 0) close(g_sessions[i].stdout_fd);
    }
  }
  (void)memset(g_sessions, 0, sizeof(g_sessions));
  g_initialized = false;
  sessions_unlock();
}

int edr_shell_session_open(const char *session_id, const char *shell,
                            const EdrCommandResultAuthorization *authorization) {
  sessions_lock();
  if (!g_initialized || !session_id || !shell) {
    sessions_unlock();
    return -1;
  }

  ShellSession *s = find_free_slot();
  if (!s) {
    sessions_unlock();
    return -1;
  }

  int stdin_pipe[2], stdout_pipe[2];
  if (pipe(stdin_pipe) < 0 || pipe(stdout_pipe) < 0) {
    sessions_unlock();
    return -1;
  }

  pid_t pid = fork();
  if (pid < 0) {
    close(stdin_pipe[0]); close(stdin_pipe[1]);
    close(stdout_pipe[0]); close(stdout_pipe[1]);
    sessions_unlock();
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
  s->next_seq = 1u;
  memset(&s->result_authorization, 0, sizeof(s->result_authorization));
  if (authorization) s->result_authorization = *authorization;
  s->active = true;
  sessions_unlock();
  return 0;
}

int edr_shell_session_input(const char *session_id,
                            const char *data, size_t len) {
  sessions_lock();
  if (!g_initialized || !session_id || !data || len == 0) {
    sessions_unlock();
    return -1;
  }
  ShellSession *s = find_by_id(session_id);
  if (!s || s->stdin_fd < 0 || s->pending.ready || s->exited) {
    sessions_unlock();
    return -1;
  }
  (void)!write(s->stdin_fd, data, len);
  sessions_unlock();
  return 0;
}

void edr_shell_session_close(const char *session_id) {
  sessions_lock();
  ShellSession *s = find_by_id(session_id);
  if (!s) {
    sessions_unlock();
    return;
  }
  if(!s->exited) {
    kill(s->child_pid, SIGKILL);
    waitpid(s->child_pid, NULL, WNOHANG);
  }
  cancel_pending(&s->pending);
  if (s->stdin_fd >= 0)  { close(s->stdin_fd);  s->stdin_fd = -1; }
  if (s->stdout_fd >= 0) { close(s->stdout_fd); s->stdout_fd = -1; }
  (void)memset(s, 0, sizeof(*s));
  sessions_unlock();
}

void edr_shell_session_poll(void) {
  sessions_lock();
  if(!g_initialized) {sessions_unlock();return;}
  uint64_t now=ms_now();
  for(uint32_t i=0;i<g_max_sessions;i++) {
    ShellSession *s=&g_sessions[i];
    if(!s->active) continue;
    if(!s->exited && g_timeout_s && now-s->start_ms>(uint64_t)g_timeout_s*1000u) {
      kill(s->child_pid,SIGKILL); /* waitpid below records the actual exit. */
    }
    if(!s->exited) {
      int status=0;pid_t wr=waitpid(s->child_pid,&status,WNOHANG);
      if(wr>0) {s->exited=true;s->exit_code=WIFEXITED(status)?WEXITSTATUS(status):1;}
    }
    if(s->pending.ready) {
      bool closing=s->pending.closed;
      if(flush_pending(&s->pending,s->session_id,&s->next_seq,&s->result_authorization,
          now,g_write_fn,g_write_user)!=0) continue;
      if(closing) {
        if(s->stdin_fd>=0) close(s->stdin_fd);
        if(s->stdout_fd>=0) close(s->stdout_fd);
        memset(s,0,sizeof(*s));continue;
      }
    }
    uint32_t cap=g_max_output_kb>=2u?EDR_SS_STREAM_CHUNK_BYTES:g_max_output_kb*1024u;
    ssize_t n=read(s->stdout_fd,s->pending.data,cap);
    if(n>0) {
      s->pending.len=(size_t)n;s->pending.ready=true;
      (void)flush_pending(&s->pending,s->session_id,&s->next_seq,&s->result_authorization,
          now,g_write_fn,g_write_user);
      continue; /* Never lose buffered output when the producer has exited. */
    }
    if(s->exited) {
      s->pending.ready=true;s->pending.closed=true;s->pending.exit_code=s->exit_code;
      if(flush_pending(&s->pending,s->session_id,&s->next_seq,&s->result_authorization,
          now,g_write_fn,g_write_user)==0) {
        if(s->stdin_fd>=0) close(s->stdin_fd);
        if(s->stdout_fd>=0) close(s->stdout_fd);
        memset(s,0,sizeof(*s));
      }
    }
  }
  sessions_unlock();
}

uint32_t edr_shell_session_active_count(void) {
  sessions_lock();
  uint32_t c = 0;
  for (uint32_t i = 0; i < g_max_sessions; i++) {
    if (g_sessions[i].active) c++;
  }
  sessions_unlock();
  return c;
}

#endif
