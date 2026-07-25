/* §12 资源限制 — CPU/内存粗采样与超限告警 */

#include "edr/resource.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#ifndef THREAD_QUERY_LIMITED_INFORMATION
#define THREAD_QUERY_LIMITED_INFORMATION 0x0800
#endif
#else
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>
#endif

static const EdrConfig *s_cfg;
static unsigned long s_emergency;
/** 1：预处理应跳过低优先级（AGT-010；POSIX 由 resource_poll 置位） */
static int s_preprocess_throttle;
static EdrResourceSample s_sample;
static struct {
#ifdef _WIN32
  FILETIME wall;
  FILETIME kernel;
  FILETIME user;
#else
  struct timeval wall;
  struct rusage ru;
#endif
} s_last;

#ifdef _WIN32
typedef struct {
  DWORD tid;
  uint64_t kernel_100ns;
  uint64_t user_100ns;
} EdrThreadCpuPoint;

#define EDR_THREAD_CPU_POINTS_MAX 512u
static EdrThreadCpuPoint s_thread_cpu_prev[EDR_THREAD_CPU_POINTS_MAX];
static size_t s_thread_cpu_prev_count;
static uint64_t s_last_working_set_trim_ms;

static long resource_env_long(const char *name, long fallback, long minv, long maxv) {
  const char *v = getenv(name);
  long out = fallback;
  if (v && v[0]) {
    out = strtol(v, NULL, 10);
  }
  if (out < minv) {
    out = minv;
  }
  if (out > maxv) {
    out = maxv;
  }
  return out;
}
#endif

static void sample_init(void) {
#ifdef _WIN32
  FILETIME create_time, exit_time;
  GetSystemTimeAsFileTime(&s_last.wall);
  if (!GetProcessTimes(GetCurrentProcess(), &create_time, &exit_time, &s_last.kernel, &s_last.user)) {
    memset(&s_last.kernel, 0, sizeof(s_last.kernel));
    memset(&s_last.user, 0, sizeof(s_last.user));
  }
#else
  gettimeofday(&s_last.wall, NULL);
  getrusage(RUSAGE_SELF, &s_last.ru);
#endif
}

static int preprocess_throttle_forced(void) {
  const char *force = getenv("EDR_PREPROCESS_THROTTLE");
  return force && force[0] == '1';
}

static void set_pressure_sample(uint32_t active, uint32_t level, const char *reason) {
  s_sample.throttle_active = active;
  s_sample.pressure_level = level;
  snprintf(s_sample.pressure_reason, sizeof(s_sample.pressure_reason), "%s",
           reason && reason[0] ? reason : "ok");
}

void edr_resource_init(const EdrConfig *cfg) {
  s_cfg = cfg;
  s_emergency = 0;
  s_preprocess_throttle = 0;
  memset(&s_sample, 0, sizeof(s_sample));
#ifdef _WIN32
  s_thread_cpu_prev_count = 0u;
  s_last_working_set_trim_ms = 0u;
#endif
  set_pressure_sample(0u, 0u, "ok");
  sample_init();
}

void edr_resource_shutdown(void) { s_cfg = NULL; }

unsigned long edr_resource_emergency_count(void) { return s_emergency; }

bool edr_resource_preprocess_throttle_active(void) {
  if (preprocess_throttle_forced()) {
    return true;
  }
  return s_preprocess_throttle != 0;
}

#ifdef _WIN32
static uint64_t filetime_u64(FILETIME ft) {
  ULARGE_INTEGER u;
  u.LowPart = ft.dwLowDateTime;
  u.HighPart = ft.dwHighDateTime;
  return u.QuadPart;
}

static int thread_cpu_prev_find(DWORD tid, uint64_t *kernel_100ns, uint64_t *user_100ns) {
  for (size_t i = 0; i < s_thread_cpu_prev_count; i++) {
    if (s_thread_cpu_prev[i].tid == tid) {
      if (kernel_100ns) {
        *kernel_100ns = s_thread_cpu_prev[i].kernel_100ns;
      }
      if (user_100ns) {
        *user_100ns = s_thread_cpu_prev[i].user_100ns;
      }
      return 1;
    }
  }
  return 0;
}

static uint32_t sample_threads_for_pid(DWORD pid, uint64_t wall_delta_100ns, DWORD ncpu,
                                       uint32_t *hot_thread_id, uint32_t *hot_thread_cpu_percent,
                                       uint64_t *hot_kernel_delta_100ns,
                                       uint64_t *hot_user_delta_100ns) {
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snap == INVALID_HANDLE_VALUE) {
    return 0u;
  }
  EdrThreadCpuPoint current[EDR_THREAD_CPU_POINTS_MAX];
  size_t current_count = 0u;
  uint64_t best_delta_100ns = 0u;
  uint64_t best_kernel_delta_100ns = 0u;
  uint64_t best_user_delta_100ns = 0u;
  DWORD best_tid = 0u;
  THREADENTRY32 te;
  memset(&te, 0, sizeof(te));
  te.dwSize = sizeof(te);
  uint32_t n = 0u;
  if (Thread32First(snap, &te)) {
    do {
      if (te.th32OwnerProcessID == pid) {
        n++;
        if (current_count < EDR_THREAD_CPU_POINTS_MAX) {
          HANDLE th = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
          if (th) {
            FILETIME create_time, exit_time, kernel_time, user_time;
            if (GetThreadTimes(th, &create_time, &exit_time, &kernel_time, &user_time)) {
              uint64_t kernel_100ns = filetime_u64(kernel_time);
              uint64_t user_100ns = filetime_u64(user_time);
              uint64_t prev_kernel_100ns = 0u;
              uint64_t prev_user_100ns = 0u;
              if (thread_cpu_prev_find(te.th32ThreadID, &prev_kernel_100ns, &prev_user_100ns)) {
                uint64_t kernel_delta_100ns = kernel_100ns >= prev_kernel_100ns
                                                  ? kernel_100ns - prev_kernel_100ns
                                                  : 0u;
                uint64_t user_delta_100ns = user_100ns >= prev_user_100ns ? user_100ns - prev_user_100ns : 0u;
                uint64_t total_delta_100ns = kernel_delta_100ns + user_delta_100ns;
                if (total_delta_100ns > best_delta_100ns) {
                  best_delta_100ns = total_delta_100ns;
                  best_kernel_delta_100ns = kernel_delta_100ns;
                  best_user_delta_100ns = user_delta_100ns;
                  best_tid = te.th32ThreadID;
                }
              }
              current[current_count].tid = te.th32ThreadID;
              current[current_count].kernel_100ns = kernel_100ns;
              current[current_count].user_100ns = user_100ns;
              current_count++;
            }
            CloseHandle(th);
          }
        }
      }
    } while (Thread32Next(snap, &te));
  }
  CloseHandle(snap);
  if (current_count > 0u) {
    memcpy(s_thread_cpu_prev, current, current_count * sizeof(current[0]));
    s_thread_cpu_prev_count = current_count;
  }
  if (hot_thread_id) {
    *hot_thread_id = best_tid;
  }
  if (hot_thread_cpu_percent) {
    uint64_t denom = wall_delta_100ns * (uint64_t)(ncpu ? ncpu : 1u);
    *hot_thread_cpu_percent = denom > 0u ? (uint32_t)((best_delta_100ns * 100ULL) / denom) : 0u;
  }
  if (hot_kernel_delta_100ns) {
    *hot_kernel_delta_100ns = best_kernel_delta_100ns;
  }
  if (hot_user_delta_100ns) {
    *hot_user_delta_100ns = best_user_delta_100ns;
  }
  return n;
}

static uint64_t resource_monotonic_ms(void) {
  return (uint64_t)GetTickCount64();
}

static void maybe_trim_working_set(unsigned pct, unsigned long *rss_mb) {
  long threshold_mb = resource_env_long("EDR_WORKING_SET_TRIM_MB", 128, 0, 4096);
  long interval_s = resource_env_long("EDR_WORKING_SET_TRIM_INTERVAL_S", 120, 10, 3600);
  uint64_t now_ms;
  PROCESS_MEMORY_COUNTERS_EX pmc;
  if (!rss_mb || threshold_mb <= 0 || *rss_mb <= (unsigned long)threshold_mb || pct > 5u) {
    return;
  }
  now_ms = resource_monotonic_ms();
  if (s_last_working_set_trim_ms != 0u &&
      now_ms - s_last_working_set_trim_ms < (uint64_t)interval_s * 1000ULL) {
    return;
  }
  s_last_working_set_trim_ms = now_ms;
  (void)HeapCompact(GetProcessHeap(), 0);
  if (SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1)) {
    memset(&pmc, 0, sizeof(pmc));
    if (GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS *)&pmc, sizeof(pmc))) {
      *rss_mb = (unsigned long)(pmc.WorkingSetSize / (1024ULL * 1024ULL));
    }
    fprintf(stderr, "[resource] working set trimmed threshold_mb=%ld rss_mb=%lu\n",
            threshold_mb, *rss_mb);
  }
}
#endif

void edr_resource_poll(void) {
  if (!s_cfg || s_cfg->resource_limit.cpu_limit_percent == 0u) {
    return;
  }
  int enforce_limits = 1;
  /* 默认 TOML 中 cpu_limit_percent=1 仅作占位，仍采样但不触发降载；需严格监控时设 EDR_RESOURCE_STRICT=1 */
  if (s_cfg->resource_limit.cpu_limit_percent < 5u) {
    const char *st = getenv("EDR_RESOURCE_STRICT");
    if (!st || st[0] != '1') {
      enforce_limits = 0;
    }
  }

#ifdef _WIN32
  FILETIME now_wall, create_time, exit_time, now_kernel, now_user;
  GetSystemTimeAsFileTime(&now_wall);
  if (!GetProcessTimes(GetCurrentProcess(), &create_time, &exit_time, &now_kernel, &now_user)) {
    return;
  }
  uint64_t wall_delta = filetime_u64(now_wall) - filetime_u64(s_last.wall);
  if (wall_delta < 5000000ULL) {
    return;
  }
  uint64_t cpu_delta = (filetime_u64(now_kernel) - filetime_u64(s_last.kernel)) +
                       (filetime_u64(now_user) - filetime_u64(s_last.user));
  SYSTEM_INFO si;
  GetSystemInfo(&si);
  DWORD ncpu = si.dwNumberOfProcessors ? si.dwNumberOfProcessors : 1u;
  unsigned pct = (unsigned)((cpu_delta * 100ULL) / (wall_delta * (uint64_t)ncpu));
  PROCESS_MEMORY_COUNTERS_EX pmc;
  memset(&pmc, 0, sizeof(pmc));
  unsigned long rss_mb = 0;
  unsigned long private_mb = 0;
  unsigned long pagefile_mb = 0;
  if (GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS *)&pmc, sizeof(pmc))) {
    rss_mb = (unsigned long)(pmc.WorkingSetSize / (1024ULL * 1024ULL));
    private_mb = (unsigned long)(pmc.PrivateUsage / (1024ULL * 1024ULL));
    pagefile_mb = (unsigned long)(pmc.PagefileUsage / (1024ULL * 1024ULL));
  }
  maybe_trim_working_set(pct, &rss_mb);
  DWORD handles = 0;
  (void)GetProcessHandleCount(GetCurrentProcess(), &handles);
  uint32_t hot_thread_id = 0u;
  uint32_t hot_thread_cpu_percent = 0u;
  uint64_t hot_thread_kernel_delta_100ns = 0u;
  uint64_t hot_thread_user_delta_100ns = 0u;
  uint32_t thread_count =
      sample_threads_for_pid(GetCurrentProcessId(), wall_delta, ncpu, &hot_thread_id,
                             &hot_thread_cpu_percent, &hot_thread_kernel_delta_100ns,
                             &hot_thread_user_delta_100ns);

  s_last.wall = now_wall;
  s_last.kernel = now_kernel;
  s_last.user = now_user;

  bool cpu_soft = enforce_limits && pct > s_cfg->resource_limit.cpu_limit_percent;
  bool cpu_bad = cpu_soft && pct > s_cfg->resource_limit.emergency_cpu_limit;
  bool mem_bad = enforce_limits && s_cfg->resource_limit.memory_limit_mb > 0u &&
                 rss_mb > (unsigned long)s_cfg->resource_limit.memory_limit_mb;
  s_sample.cpu_percent = pct;
  s_sample.rss_mb = rss_mb;
  s_sample.working_set_mb = rss_mb;
  s_sample.private_bytes_mb = private_mb;
  s_sample.pagefile_mb = pagefile_mb;
  s_sample.thread_count = thread_count;
  s_sample.handle_count = (uint32_t)handles;
  s_sample.hot_thread_id = hot_thread_id;
  s_sample.hot_thread_cpu_percent = hot_thread_cpu_percent;
  s_sample.hot_thread_kernel_delta_100ns = hot_thread_kernel_delta_100ns;
  s_sample.hot_thread_user_delta_100ns = hot_thread_user_delta_100ns;
  s_sample.hot_thread_total_delta_100ns = hot_thread_kernel_delta_100ns + hot_thread_user_delta_100ns;
  s_sample.sample_count++;
  if (cpu_bad) {
    s_emergency++;
    fprintf(stderr, "[resource] CPU approx %u%% exceeds limit %u%% (emergency=%lu)\n", pct,
            s_cfg->resource_limit.cpu_limit_percent, s_emergency);
    s_preprocess_throttle = 1;
    set_pressure_sample(1u, 2u, "cpu");
  } else if (cpu_soft) {
    s_preprocess_throttle = 1;
    set_pressure_sample(1u, 1u, "cpu_soft");
  } else if (mem_bad) {
    fprintf(stderr, "[resource] RSS approx %lu MB exceeds memory_limit_mb=%u\n", rss_mb,
            s_cfg->resource_limit.memory_limit_mb);
    s_preprocess_throttle = 1;
    set_pressure_sample(1u, 2u, "memory");
  } else {
    s_preprocess_throttle = 0;
    set_pressure_sample(preprocess_throttle_forced() ? 1u : 0u,
                        preprocess_throttle_forced() ? 1u : 0u,
                        preprocess_throttle_forced() ? "forced" : "ok");
  }
#else
  struct timeval now;
  struct rusage ru;
  gettimeofday(&now, NULL);
  getrusage(RUSAGE_SELF, &ru);

  double wall_s = (double)(now.tv_sec - s_last.wall.tv_sec) +
                  (double)(now.tv_usec - s_last.wall.tv_usec) / 1e6;
  if (wall_s < 0.5) {
    return;
  }

  double ut = (double)(ru.ru_utime.tv_sec - s_last.ru.ru_utime.tv_sec) +
              (double)(ru.ru_utime.tv_usec - s_last.ru.ru_utime.tv_usec) / 1e6;
  double st = (double)(ru.ru_stime.tv_sec - s_last.ru.ru_stime.tv_sec) +
              (double)(ru.ru_stime.tv_usec - s_last.ru.ru_stime.tv_usec) / 1e6;
  double cpu_frac = (ut + st) / wall_s;
  unsigned pct = (unsigned)(cpu_frac * 100.0);
  long rss = ru.ru_maxrss;

  s_last.wall = now;
  s_last.ru = ru;

  bool cpu_soft = enforce_limits && pct > s_cfg->resource_limit.cpu_limit_percent;
  bool cpu_bad = cpu_soft && pct > s_cfg->resource_limit.emergency_cpu_limit;
  bool mem_bad = false;
  unsigned long rss_mb = 0;

  if (s_cfg->resource_limit.memory_limit_mb > 0u) {
#if defined(__APPLE__)
    rss_mb = (unsigned long)rss / (1024ul * 1024ul);
#else
    rss_mb = (unsigned long)rss / 1024ul;
#endif
    if (enforce_limits && rss_mb > (unsigned long)s_cfg->resource_limit.memory_limit_mb) {
      mem_bad = true;
      fprintf(stderr, "[resource] RSS approx %lu MB exceeds memory_limit_mb=%u\n", rss_mb,
              s_cfg->resource_limit.memory_limit_mb);
    }
  }

  if (cpu_bad) {
    s_emergency++;
    fprintf(stderr, "[resource] CPU approx %u%% exceeds limit %u%% (emergency=%lu)\n", pct,
            s_cfg->resource_limit.cpu_limit_percent, s_emergency);
    s_preprocess_throttle = 1;
    set_pressure_sample(1u, 2u, "cpu");
  } else if (cpu_soft) {
    s_preprocess_throttle = 1;
    set_pressure_sample(1u, 1u, "cpu_soft");
  } else if (mem_bad) {
    s_preprocess_throttle = 1;
    set_pressure_sample(1u, 2u, "memory");
  } else {
    s_preprocess_throttle = 0;
    set_pressure_sample(preprocess_throttle_forced() ? 1u : 0u,
                        preprocess_throttle_forced() ? 1u : 0u,
                        preprocess_throttle_forced() ? "forced" : "ok");
  }
  s_sample.cpu_percent = pct;
  s_sample.rss_mb = rss_mb;
  s_sample.working_set_mb = rss_mb;
  s_sample.private_bytes_mb = 0u;
  s_sample.pagefile_mb = 0u;
  s_sample.thread_count = 0u;
  s_sample.handle_count = 0u;
  s_sample.hot_thread_id = 0u;
  s_sample.hot_thread_cpu_percent = 0u;
  s_sample.hot_thread_kernel_delta_100ns = 0u;
  s_sample.hot_thread_user_delta_100ns = 0u;
  s_sample.hot_thread_total_delta_100ns = 0u;
  s_sample.sample_count++;
#endif
}

void edr_resource_get_sample(EdrResourceSample *out) {
  if (!out) {
    return;
  }
  *out = s_sample;
  if (preprocess_throttle_forced() && !out->throttle_active) {
    out->throttle_active = 1u;
    out->pressure_level = 1u;
    snprintf(out->pressure_reason, sizeof(out->pressure_reason), "%s", "forced");
  }
}
