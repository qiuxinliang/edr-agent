/* §9 自保护 — 信号审计、防调试、总线背压、可选 Windows Job Object、看门狗 */

#include "edr/self_protect.h"

#include "edr/config.h"
#include "edr/event_bus.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <signal.h>
#include <unistd.h>
#endif

#ifdef _WIN32
#include <windows.h>
#endif

static int s_active;
static char s_pidfile_path[1024];
static int s_pidfile_written;
static void (*s_shutdown_hook)(int);

static const EdrConfig *s_cfg;
static EdrEventBus *s_bus;

#ifdef _WIN32
static HANDLE s_job;
#endif

static int s_dbg_last;
static unsigned s_poll_tick;
static unsigned s_pressure_warn_count;

void edr_self_protect_set_shutdown_hook(void (*cb)(int signo)) { s_shutdown_hook = cb; }

#ifndef _WIN32
static void edr_sp_on_signal(int s) {
  fprintf(stderr, "[self_protect] 收到信号 %d（审计）\n", s);
  if (s_shutdown_hook) {
    s_shutdown_hook(s);
  }
}
#endif

int edr_self_protect_debugger_attached(void) {
#ifdef _WIN32
  if (IsDebuggerPresent()) {
    return 1;
  }
  BOOL remote = FALSE;
  if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote) {
    return 1;
  }
  return 0;
#else
  FILE *f = fopen("/proc/self/status", "r");
  if (!f) {
    return 0;
  }
  char line[256];
  while (fgets(line, sizeof(line), f)) {
    int tracer = 0;
    if (sscanf(line, "TracerPid: %d", &tracer) == 1) {
      fclose(f);
      return tracer != 0;
    }
  }
  fclose(f);
  return 0;
#endif
}

void edr_self_protect_format_status(char *buf, size_t cap) {
  if (!buf || cap < 32u) {
    return;
  }
  unsigned pct = 0;
  if (s_bus) {
    uint32_t c = edr_event_bus_capacity(s_bus);
    if (c > 0u) {
      pct = (unsigned)(100u * edr_event_bus_used_approx(s_bus) / c);
    }
  }
#ifdef _WIN32
  int job = (s_job != NULL && s_job != INVALID_HANDLE_VALUE) ? 1 : 0;
#else
  int job = 0;
#endif
  int ac = s_active ? 1 : 0;
  int adcfg = (s_cfg && s_cfg->self_protect.anti_debug) ? 1 : 0;
  snprintf(buf, cap, "active=%d debugger=%d bus_pct=%u job_win=%d anti_debug_cfg=%d hw_hits=%llu dropped=%llu",
           ac, edr_self_protect_debugger_attached(), pct, job, adcfg,
           (unsigned long long)(s_bus ? edr_event_bus_high_water_hits(s_bus) : 0ull),
           (unsigned long long)(s_bus ? edr_event_bus_dropped_total(s_bus) : 0ull));
}

static void try_install_job_windows(void) {
#ifdef _WIN32
  if (!s_cfg || !s_cfg->self_protect.job_object_windows) {
    return;
  }
  if (s_job && s_job != INVALID_HANDLE_VALUE) {
    return;
  }
  s_job = CreateJobObjectW(NULL, NULL);
  if (!s_job || s_job == INVALID_HANDLE_VALUE) {
    fprintf(stderr, "[self_protect] CreateJobObject 失败 (%lu)\n", (unsigned long)GetLastError());
    s_job = NULL;
    return;
  }
  if (!AssignProcessToJobObject(s_job, GetCurrentProcess())) {
    fprintf(stderr, "[self_protect] AssignProcessToJobObject 失败 (%lu)\n", (unsigned long)GetLastError());
    CloseHandle(s_job);
    s_job = NULL;
    return;
  }
  fprintf(stderr, "[self_protect] 已绑定 Windows Job Object\n");
#else
  (void)0;
#endif
}

void edr_self_protect_apply_config(const EdrConfig *cfg) {
  s_cfg = cfg;
  try_install_job_windows();
}

void edr_self_protect_set_event_bus(EdrEventBus *bus) { s_bus = bus; }

void edr_self_protect_init(void) {
  if (s_active) {
    return;
  }
  s_pidfile_written = 0;
  s_pidfile_path[0] = '\0';
  const char *pf = getenv("EDR_SELF_PROTECT_PIDFILE");
  if (pf && pf[0]) {
    size_t n = 0;
    while (n + 1u < sizeof(s_pidfile_path) && pf[n]) {
      s_pidfile_path[n] = pf[n];
      n++;
    }
    s_pidfile_path[n] = '\0';
    FILE *f = fopen(s_pidfile_path, "w");
    if (f) {
#ifdef _WIN32
      fprintf(f, "%lu\n", (unsigned long)GetCurrentProcessId());
#else
      fprintf(f, "%d\n", (int)getpid());
#endif
      fclose(f);
      s_pidfile_written = 1;
      fprintf(stderr, "[self_protect] 已写 PID 文件 %s\n", s_pidfile_path);
    } else {
      fprintf(stderr, "[self_protect] 无法写入 PID 文件 %s\n", s_pidfile_path);
    }
  }
#ifndef _WIN32
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = edr_sp_on_signal;
  sigemptyset(&sa.sa_mask);
  (void)sigaction(SIGTERM, &sa, NULL);
  (void)sigaction(SIGINT, &sa, NULL);
#endif
  s_active = 1;
  fprintf(stderr, "[self_protect] 已启用（SIGTERM/SIGINT 审计）\n");
}

void edr_self_protect_shutdown(void) {
#ifdef _WIN32
  if (s_job && s_job != INVALID_HANDLE_VALUE) {
    CloseHandle(s_job);
    s_job = NULL;
  }
#endif
  if (s_pidfile_written && s_pidfile_path[0]) {
    if (remove(s_pidfile_path) == 0) {
      fprintf(stderr, "[self_protect] 已删除 PID 文件 %s\n", s_pidfile_path);
    }
    s_pidfile_written = 0;
  }
  s_active = 0;
  s_bus = NULL;
  s_cfg = NULL;
}

void edr_self_protect_poll(void) {
  if (!s_active) {
    return;
  }
  s_poll_tick++;

  if (s_cfg && s_cfg->self_protect.anti_debug) {
    int d = edr_self_protect_debugger_attached();
    if (d && !s_dbg_last) {
      fprintf(stderr, "[self_protect] 告警：检测到调试器附着（审计，不退出）\n");
    }
    s_dbg_last = d;
  }

  if (s_bus && s_cfg && s_cfg->self_protect.event_bus_pressure_warn_pct > 0u) {
    uint32_t cap = edr_event_bus_capacity(s_bus);
    if (cap > 0u) {
      uint32_t used = edr_event_bus_used_approx(s_bus);
      unsigned pct = (unsigned)(100u * used / cap);
      if (pct >= s_cfg->self_protect.event_bus_pressure_warn_pct) {
        if ((s_pressure_warn_count++ % 25u) == 0u) {
          fprintf(stderr, "[self_protect] 事件总线占用 %u%%（阈值 %u%%）hw_hits=%llu dropped=%llu\n", pct,
                  (unsigned)s_cfg->self_protect.event_bus_pressure_warn_pct,
                  (unsigned long long)edr_event_bus_high_water_hits(s_bus),
                  (unsigned long long)edr_event_bus_dropped_total(s_bus));
        }
      }
    }
  }

  if (s_cfg && s_cfg->self_protect.watchdog_log_interval_s > 0u) {
    unsigned ticks_per_s = 5u;
    unsigned period = s_cfg->self_protect.watchdog_log_interval_s * ticks_per_s;
    if (period > 0u && (s_poll_tick % period) == 0u) {
      char st[160];
      edr_self_protect_format_status(st, sizeof(st));
      fprintf(stderr, "[self_protect] watchdog %s\n", st);
    }
  }

  const char *w = getenv("EDR_SELF_PROTECT_WATCHDOG");
  if (w && w[0] == '1') {
    if ((s_poll_tick % 600u) == 0u) {
      fprintf(stderr, "[self_protect] watchdog tick (EDR_SELF_PROTECT_WATCHDOG=1)\n");
    }
  }
}
