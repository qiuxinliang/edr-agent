/* §B2 伴生 watchdog 进程（抗 kill，互守）—— 见 include/edr/watchdog.h */

#include "edr/watchdog.h"

#include "edr/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

/* ---- 跨进程一致的执行上下文 ---- */
static char s_argv0[1024];
static char s_config_path[1024];

/* agent 侧伴生状态 */
static long s_companion_pid;     /* 我方 watchdog 伴生进程 pid（0=无） */
static int s_companion_enabled;  /* 本次是否启用了伴生进程 */
static uint64_t s_hb_last_write_s;

void edr_self_protect_set_exec_context(const char *argv0, const char *config_path) {
  if (argv0 && argv0[0]) {
    snprintf(s_argv0, sizeof(s_argv0), "%s", argv0);
  }
  if (config_path && config_path[0]) {
    snprintf(s_config_path, sizeof(s_config_path), "%s", config_path);
  }
}

/* 解析当前可执行文件的绝对路径；失败回退到 argv0。 */
static void resolve_self_exe(char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
#if defined(_WIN32)
  wchar_t wbuf[1024];
  DWORD n = GetModuleFileNameW(NULL, wbuf, (DWORD)(sizeof(wbuf) / sizeof(wbuf[0])));
  if (n > 0 && n < (DWORD)(sizeof(wbuf) / sizeof(wbuf[0]))) {
    WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, out, (int)cap, NULL, NULL);
    return;
  }
#elif defined(__linux__)
  ssize_t n = readlink("/proc/self/exe", out, cap - 1u);
  if (n > 0) {
    out[n] = '\0';
    return;
  }
#elif defined(__APPLE__)
  uint32_t sz = (uint32_t)cap;
  extern int _NSGetExecutablePath(char *buf, uint32_t *bufsize);
  if (_NSGetExecutablePath(out, &sz) == 0) {
    return;
  }
#endif
  snprintf(out, cap, "%s", s_argv0[0] ? s_argv0 : "edr_agent");
}

/* 心跳文件路径（agent 与 watchdog 须算出同一路径）。 */
static void derive_heartbeat_path(const EdrConfig *cfg, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  if (cfg && cfg->self_protect.watchdog_heartbeat_path[0]) {
    snprintf(out, cap, "%s", cfg->self_protect.watchdog_heartbeat_path);
    return;
  }
  const char *env = getenv("EDR_SELF_PROTECT_HEARTBEAT");
  if (env && env[0]) {
    snprintf(out, cap, "%s", env);
    return;
  }
  const char *pidf = getenv("EDR_SELF_PROTECT_PIDFILE");
  if (pidf && pidf[0]) {
    snprintf(out, cap, "%s.hb", pidf);
    return;
  }
#if defined(_WIN32)
  const char *tmp = getenv("TEMP");
  if (!tmp || !tmp[0]) {
    tmp = "C:\\Windows\\Temp";
  }
  snprintf(out, cap, "%s\\edr_agent.hb", tmp);
#else
  snprintf(out, cap, "/tmp/edr_agent.hb");
#endif
}

static void stop_stamp_path(const char *hb_path, char *out, size_t cap) {
  snprintf(out, cap, "%s.stop", hb_path ? hb_path : "");
}

/* 进程存活判定（pid>0）。 */
static int pid_alive(long pid) {
  if (pid <= 0) {
    return 0;
  }
#if defined(_WIN32)
  HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, (DWORD)pid);
  if (!h) {
    return 0;
  }
  DWORD w = WaitForSingleObject(h, 0);
  CloseHandle(h);
  return (w == WAIT_TIMEOUT) ? 1 : 0;
#else
  if (kill((pid_t)pid, 0) == 0) {
    return 1;
  }
  return (errno == EPERM) ? 1 : 0; /* 存在但非本用户也算活 */
#endif
}

static uint64_t now_unix_s(void) { return (uint64_t)time(NULL); }

static void write_heartbeat(const char *path, long pid) {
  FILE *f = fopen(path, "w");
  if (!f) {
    return;
  }
  fprintf(f, "%llu %ld\n", (unsigned long long)now_unix_s(), pid);
  fclose(f);
}

/* 读心跳文件里的 epoch 秒；失败返回 0。 */
static uint64_t read_heartbeat_epoch(const char *path) {
  FILE *f = fopen(path, "r");
  if (!f) {
    return 0;
  }
  unsigned long long epoch = 0ull;
  int got = fscanf(f, "%llu", &epoch);
  fclose(f);
  return (got == 1) ? (uint64_t)epoch : 0u;
}

static int file_exists(const char *path) {
#if defined(_WIN32)
  DWORD a = GetFileAttributesA(path);
  return (a != INVALID_FILE_ATTRIBUTES) ? 1 : 0;
#else
  struct stat st;
  return (stat(path, &st) == 0) ? 1 : 0;
#endif
}

/*
 * spawn 同一二进制的某个角色。
 *  as_watchdog=1：spawn watchdog（aux_pid=要监控的 agent pid）。
 *  as_watchdog=0：spawn agent（aux_pid=已存在 watchdog pid，写入子进程 env 防止重复 spawn）。
 * 返回子进程 pid，失败 -1。
 */
static long spawn_role(int as_watchdog, long aux_pid) {
  char exe[1024];
  resolve_self_exe(exe, sizeof(exe));
  const char *cfg = s_config_path[0] ? s_config_path : "";

#if defined(_WIN32)
  char parent_buf[32];
  char cmd[4096];
  if (as_watchdog) {
    snprintf(parent_buf, sizeof(parent_buf), "%ld", aux_pid);
    snprintf(cmd, sizeof(cmd), "\"%s\" --watchdog --parent-pid %s --config \"%s\"", exe, parent_buf, cfg);
  } else {
    snprintf(cmd, sizeof(cmd), "\"%s\" --config \"%s\"", exe, cfg);
    char existing[32];
    snprintf(existing, sizeof(existing), "%ld", aux_pid);
    SetEnvironmentVariableA("EDR_WATCHDOG_EXISTING_PID", existing);
  }
  wchar_t wcmd[4096];
  MultiByteToWideChar(CP_UTF8, 0, cmd, -1, wcmd, (int)(sizeof(wcmd) / sizeof(wcmd[0])));
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  memset(&pi, 0, sizeof(pi));
  BOOL ok = CreateProcessW(NULL, wcmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
  if (!as_watchdog) {
    SetEnvironmentVariableA("EDR_WATCHDOG_EXISTING_PID", NULL); /* 还原，勿污染本进程 */
  }
  if (!ok) {
    fprintf(stderr, "[watchdog] CreateProcess failed (%lu) cmd=%s\n", (unsigned long)GetLastError(), cmd);
    return -1;
  }
  long child = (long)pi.dwProcessId;
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return child;
#else
  char parent_buf[32];
  char existing_buf[32];
  pid_t child = fork();
  if (child < 0) {
    fprintf(stderr, "[watchdog] fork failed: %s\n", strerror(errno));
    return -1;
  }
  if (child == 0) {
    /* 子进程：关闭继承自父进程的非标准 fd（SQLite 队列锁、socket 等），
     * 否则 watchdog 会持有 agent 的队列锁 fd，导致被杀 agent 的锁不释放、重启实例误判“已在运行”而退出。
     * watchdog / 重启后的 agent 仅需 stdio，其它资源都会自行重开。 */
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0 || maxfd > 4096) {
      maxfd = 4096;
    }
    for (int fd = 3; fd < (int)maxfd; fd++) {
      close(fd);
    }
    if (as_watchdog) {
      snprintf(parent_buf, sizeof(parent_buf), "%ld", aux_pid);
      char *const argv[] = {exe, (char *)"--watchdog", (char *)"--parent-pid", parent_buf,
                            (char *)"--config", (char *)cfg, NULL};
      execv(exe, argv);
    } else {
      snprintf(existing_buf, sizeof(existing_buf), "%ld", aux_pid);
      setenv("EDR_WATCHDOG_EXISTING_PID", existing_buf, 1);
      char *const argv[] = {exe, (char *)"--config", (char *)cfg, NULL};
      execv(exe, argv);
    }
    fprintf(stderr, "[watchdog] execv failed: %s (%s)\n", strerror(errno), exe);
    _exit(127);
  }
  return (long)child;
#endif
}

/* ============================ agent 侧 ============================ */

int edr_watchdog_maybe_spawn_companion(const EdrConfig *cfg) {
  int enabled = (cfg && cfg->self_protect.watchdog_process) ? 1 : 0;
  const char *env = getenv("EDR_SELF_PROTECT_WATCHDOG_PROCESS");
  if (env && env[0] == '1') {
    enabled = 1;
  }
  if (!enabled) {
    s_companion_enabled = 0;
    return 0;
  }
  s_companion_enabled = 1;

  /* 若本进程是被 watchdog 重启起来的，直接 adopt 既有 watchdog，避免重复 spawn。 */
  const char *existing = getenv("EDR_WATCHDOG_EXISTING_PID");
  if (existing && existing[0]) {
    long wp = strtol(existing, NULL, 10);
    if (wp > 0 && pid_alive(wp)) {
      s_companion_pid = wp;
      fprintf(stderr, "[watchdog] adopted existing companion pid=%ld\n", wp);
      return 1;
    }
  }

  long self_pid;
#if defined(_WIN32)
  self_pid = (long)GetCurrentProcessId();
#else
  self_pid = (long)getpid();
#endif
  long wp = spawn_role(1 /*watchdog*/, self_pid);
  if (wp > 0) {
    s_companion_pid = wp;
    fprintf(stderr, "[watchdog] companion spawned pid=%ld\n", wp);
    return 1;
  }
  return 0;
}

void edr_watchdog_agent_tick(const EdrConfig *cfg) {
  if (!s_companion_enabled) {
    return;
  }
  char hb[1100];
  derive_heartbeat_path(cfg, hb, sizeof(hb));

  /* 心跳节流：按 watchdog_heartbeat_interval_s 写盘，证明主循环存活。 */
  uint32_t interval = (cfg && cfg->self_protect.watchdog_heartbeat_interval_s > 0u)
                          ? cfg->self_protect.watchdog_heartbeat_interval_s
                          : 5u;
  uint64_t now = now_unix_s();
  if (s_hb_last_write_s == 0u || (now - s_hb_last_write_s) >= (uint64_t)interval) {
    long self_pid;
#if defined(_WIN32)
    self_pid = (long)GetCurrentProcessId();
#else
    self_pid = (long)getpid();
#endif
    write_heartbeat(hb, self_pid);
    s_hb_last_write_s = now;
  }

  /* 互守：伴生 watchdog 死了就重新拉起（去重：仅当确无存活伴生时）。 */
  if (s_companion_pid > 0 && !pid_alive(s_companion_pid)) {
    fprintf(stderr, "[watchdog] companion pid=%ld gone, respawning\n", s_companion_pid);
    s_companion_pid = 0;
    long self_pid;
#if defined(_WIN32)
    self_pid = (long)GetCurrentProcessId();
#else
    self_pid = (long)getpid();
#endif
    long wp = spawn_role(1, self_pid);
    if (wp > 0) {
      s_companion_pid = wp;
      fprintf(stderr, "[watchdog] companion respawned pid=%ld\n", wp);
    }
  }
}

void edr_watchdog_agent_on_shutdown(const EdrConfig *cfg) {
  if (!s_companion_enabled) {
    return;
  }
  char hb[1100];
  char stop[1160];
  derive_heartbeat_path(cfg, hb, sizeof(hb));
  stop_stamp_path(hb, stop, sizeof(stop));
  FILE *f = fopen(stop, "w");
  if (f) {
    fprintf(f, "%llu\n", (unsigned long long)now_unix_s());
    fclose(f);
    fprintf(stderr, "[watchdog] shutdown stamp written %s (companion will not restart)\n", stop);
  }
}

/* ============================ watchdog 角色 ============================ */

/* 重启风暴防护：环形记录最近重启时间，判定 60s 内是否超额。 */
#define EDR_WD_RING 64
typedef struct {
  uint64_t ts[EDR_WD_RING];
  int head;
  int count;
} RestartRing;

static int restart_allowed(RestartRing *r, uint32_t max_per_min) {
  if (max_per_min == 0u) {
    return 1; /* 0=不限速 */
  }
  uint64_t now = now_unix_s();
  unsigned recent = 0;
  for (int i = 0; i < r->count; i++) {
    if (now - r->ts[i] < 60u) {
      recent++;
    }
  }
  return (recent < max_per_min) ? 1 : 0;
}

static void restart_note(RestartRing *r) {
  r->ts[r->head] = now_unix_s();
  r->head = (r->head + 1) % EDR_WD_RING;
  if (r->count < EDR_WD_RING) {
    r->count++;
  }
}

static void wd_sleep_s(unsigned s) {
#if defined(_WIN32)
  Sleep(s * 1000u);
#else
  sleep(s);
#endif
}

int edr_watchdog_run(long parent_pid, const char *argv0, const char *config_path) {
  edr_self_protect_set_exec_context(argv0, config_path);

  /* watchdog 自身极简：加载 config 仅为算心跳路径与阈值。
   * 必须先 memset：edr_config_load 会按既有指针释放/重置堆成员，未清零栈结构会触发 abort。 */
  EdrConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  int have_cfg = 0;
  if (config_path && config_path[0] && edr_config_load(config_path, &cfg) == EDR_OK) {
    have_cfg = 1;
  }
  char hb[1100];
  char stop[1160];
  derive_heartbeat_path(have_cfg ? &cfg : NULL, hb, sizeof(hb));
  stop_stamp_path(hb, stop, sizeof(stop));

  uint32_t interval = (have_cfg && cfg.self_protect.watchdog_heartbeat_interval_s > 0u)
                          ? cfg.self_protect.watchdog_heartbeat_interval_s
                          : 5u;
  uint32_t stale_to = (have_cfg && cfg.self_protect.watchdog_stale_timeout_s > 0u)
                          ? cfg.self_protect.watchdog_stale_timeout_s
                          : 30u;
  uint32_t max_restarts = 5u;
  if (have_cfg) {
    max_restarts = cfg.self_protect.watchdog_max_restarts_per_min;
  }
  /* 阈值/路径均已拷入局部变量，后续循环不再引用 cfg，可立即释放堆成员。 */
  if (have_cfg) {
    edr_config_free_heap(&cfg);
  }
  const char *env_mr = getenv("EDR_WATCHDOG_MAX_RESTARTS_PER_MIN");
  if (env_mr && env_mr[0]) {
    long v = strtol(env_mr, NULL, 10);
    if (v >= 0 && v <= 1000) {
      max_restarts = (uint32_t)v;
    }
  }

  /* 启动即清理可能残留的 stop stamp（上一周期干净退出留下的），否则会误判不重启。 */
  if (file_exists(stop)) {
    remove(stop);
  }

  fprintf(stderr, "[watchdog] running: parent=%ld hb=%s interval=%us stale=%us max_restarts/min=%u\n",
          parent_pid, hb, interval, stale_to, max_restarts);

  RestartRing ring;
  memset(&ring, 0, sizeof(ring));
  long watched = parent_pid;

  for (;;) {
    wd_sleep_s(interval);

    /* 干净退出信号：agent 主动 shutdown 写了 stop stamp，则 watchdog 不再重启并自退。 */
    if (file_exists(stop)) {
      fprintf(stderr, "[watchdog] stop stamp present, exiting (no restart)\n");
      remove(stop);
      return 0;
    }

    int alive = pid_alive(watched);
    int fresh = 1;
    if (alive) {
      uint64_t hb_epoch = read_heartbeat_epoch(hb);
      if (hb_epoch != 0u) {
        uint64_t age = now_unix_s() - hb_epoch;
        fresh = (age <= (uint64_t)stale_to) ? 1 : 0;
      }
    }

    if (alive && fresh) {
      continue; /* 一切正常 */
    }

    fprintf(stderr, "[watchdog] agent pid=%ld %s; attempting restart\n", watched,
            alive ? "heartbeat stale (hang)" : "not alive (killed)");

    if (!restart_allowed(&ring, max_restarts)) {
      fprintf(stderr, "[watchdog] restart storm guard tripped (>=%u/min), backing off 60s\n", max_restarts);
      wd_sleep_s(60u);
      continue;
    }

    /* 若 agent 还活着但僵死（hang），先尝试结束它再重启，避免双实例抢 SQLite 队列锁。 */
    if (alive) {
#if defined(_WIN32)
      HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)watched);
      if (h) {
        TerminateProcess(h, 1);
        CloseHandle(h);
      }
#else
      kill((pid_t)watched, SIGKILL);
#endif
      wd_sleep_s(1u);
    }

    long self_pid;
#if defined(_WIN32)
    self_pid = (long)GetCurrentProcessId();
#else
    self_pid = (long)getpid();
#endif
    long child = spawn_role(0 /*agent*/, self_pid);
    if (child > 0) {
      restart_note(&ring);
      watched = child;
      fprintf(stderr, "[watchdog] agent restarted pid=%ld\n", child);
      /* 给新 agent 一点启动+写首个心跳的时间，避免立刻又判 stale。 */
      wd_sleep_s(interval);
    } else {
      fprintf(stderr, "[watchdog] restart failed; retrying next cycle\n");
    }
  }
}
