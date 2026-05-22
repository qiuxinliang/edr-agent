/* §12 资源限制 — CPU/内存粗采样与超限告警 */

#include "edr/resource.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <mach/mach.h>
#include <mach/task.h>
#endif
#else
#include <psapi.h>
#include <tlhelp32.h>
#include <windows.h>
#pragma comment(lib, "psapi.lib")
#endif

static const EdrConfig *s_cfg;
static unsigned long s_emergency;
/** 1：预处理应跳过低优先级（AGT-010；POSIX 由 resource_poll 置位） */
static int s_preprocess_throttle;
static unsigned s_last_cpu_pct;
static unsigned long s_last_rss_mb;
static uint32_t s_last_thread_count;
static uint32_t s_last_handle_count;
static uint64_t s_last_sample_ms;
static uint64_t s_throttle_drop_count;
static char s_pressure_reason[160];
static struct {
#ifndef _WIN32
  struct timeval wall;
  struct rusage ru;
#else
  FILETIME wall;
  FILETIME kernel;
  FILETIME user;
#endif
} s_last;

static uint64_t wall_time_ms(void) {
#ifdef _WIN32
  FILETIME ft;
  GetSystemTimeAsFileTime(&ft);
  uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | (uint32_t)ft.dwLowDateTime;
  return t >= 116444736000000000ULL ? (t - 116444736000000000ULL) / 10000ULL : 0ULL;
#else
  struct timeval tv;
  if (gettimeofday(&tv, NULL) != 0) {
    return (uint64_t)time(NULL) * 1000ULL;
  }
  return (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)tv.tv_usec / 1000ULL;
#endif
}

#ifdef _WIN32
static uint64_t ft_to_u64(FILETIME ft) {
  return ((uint64_t)ft.dwHighDateTime << 32) | (uint32_t)ft.dwLowDateTime;
}

static uint32_t current_thread_count(void) {
  DWORD pid = GetCurrentProcessId();
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) {
    return 0;
  }
  PROCESSENTRY32W pe;
  memset(&pe, 0, sizeof(pe));
  pe.dwSize = sizeof(pe);
  uint32_t n = 0;
  if (Process32FirstW(snap, &pe)) {
    do {
      if (pe.th32ProcessID == pid) {
        n = (uint32_t)pe.cntThreads;
        break;
      }
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  return n;
}
#endif

static unsigned long current_rss_mb(void) {
#ifdef _WIN32
  PROCESS_MEMORY_COUNTERS_EX pmc;
  memset(&pmc, 0, sizeof(pmc));
  pmc.cb = sizeof(pmc);
  if (GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS *)&pmc, sizeof(pmc))) {
    return (unsigned long)(pmc.WorkingSetSize / (1024ULL * 1024ULL));
  }
  return 0ul;
#elif defined(__APPLE__)
  mach_task_basic_info_data_t info;
  mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
  if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info, &count) == KERN_SUCCESS) {
    return (unsigned long)(info.resident_size / (1024ULL * 1024ULL));
  }
  return 0ul;
#elif defined(__linux__)
  FILE *f = fopen("/proc/self/statm", "r");
  if (!f) {
    return 0ul;
  }
  unsigned long pages = 0, rss_pages = 0;
  int ok = fscanf(f, "%lu %lu", &pages, &rss_pages);
  fclose(f);
  if (ok < 2) {
    return 0ul;
  }
  long page = sysconf(_SC_PAGESIZE);
  if (page <= 0) {
    page = 4096;
  }
  return (unsigned long)(((uint64_t)rss_pages * (uint64_t)page) / (1024ULL * 1024ULL));
#else
  return 0ul;
#endif
}

static void sample_init(void) {
#ifndef _WIN32
  gettimeofday(&s_last.wall, NULL);
  getrusage(RUSAGE_SELF, &s_last.ru);
#else
  FILETIME create_time, exit_time;
  GetSystemTimeAsFileTime(&s_last.wall);
  if (!GetProcessTimes(GetCurrentProcess(), &create_time, &exit_time, &s_last.kernel, &s_last.user)) {
    memset(&s_last.kernel, 0, sizeof(s_last.kernel));
    memset(&s_last.user, 0, sizeof(s_last.user));
  }
#endif
  s_last_rss_mb = current_rss_mb();
  s_last_sample_ms = wall_time_ms();
}

void edr_resource_init(const EdrConfig *cfg) {
  s_cfg = cfg;
  s_emergency = 0;
  s_preprocess_throttle = 0;
  s_last_cpu_pct = 0;
  s_last_thread_count = 0;
  s_last_handle_count = 0;
  s_throttle_drop_count = 0;
  snprintf(s_pressure_reason, sizeof(s_pressure_reason), "%s", "ok");
  sample_init();
}

void edr_resource_shutdown(void) { s_cfg = NULL; }

unsigned long edr_resource_emergency_count(void) { return s_emergency; }
unsigned edr_resource_cpu_percent(void) { return s_last_cpu_pct; }
unsigned long edr_resource_current_rss_mb(void) { return s_last_rss_mb; }
uint32_t edr_resource_thread_count(void) { return s_last_thread_count; }
uint32_t edr_resource_handle_count(void) { return s_last_handle_count; }
uint64_t edr_resource_last_sample_ms(void) { return s_last_sample_ms; }
uint64_t edr_resource_preprocess_throttle_drop_count(void) { return s_throttle_drop_count; }

void edr_resource_note_preprocess_throttle_drop(void) { s_throttle_drop_count++; }

void edr_resource_pressure_reason(char *buf, size_t cap) {
  if (!buf || cap == 0u) {
    return;
  }
  snprintf(buf, cap, "%s", s_pressure_reason[0] ? s_pressure_reason : "ok");
}

bool edr_resource_preprocess_throttle_active(void) {
  const char *force = getenv("EDR_PREPROCESS_THROTTLE");
  if (force && force[0] == '1') {
    return true;
  }
  return s_preprocess_throttle != 0;
}

void edr_resource_poll(void) {
  if (!s_cfg) {
    return;
  }
  int enforce_cpu_limit = s_cfg->resource_limit.cpu_limit_percent != 0u;
  /* 默认 TOML 中 cpu_limit_percent=1 仅作占位，仍采样但不触发 CPU 降载；需严格监控时设 EDR_RESOURCE_STRICT=1 */
  if (s_cfg->resource_limit.cpu_limit_percent < 5u) {
    const char *st = getenv("EDR_RESOURCE_STRICT");
    if (!st || st[0] != '1') {
      enforce_cpu_limit = 0;
    }
  }

#ifndef _WIN32
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
  unsigned long rss_mb = current_rss_mb();

  s_last.wall = now;
  s_last.ru = ru;
  s_last_cpu_pct = pct;
  s_last_rss_mb = rss_mb;
  s_last_thread_count = 0;
  s_last_handle_count = 0;
  s_last_sample_ms = wall_time_ms();

  bool cpu_bad = enforce_cpu_limit && pct > s_cfg->resource_limit.cpu_limit_percent &&
                 pct > s_cfg->resource_limit.emergency_cpu_limit;
  bool mem_bad = false;

  if (s_cfg->resource_limit.memory_limit_mb > 0u) {
    if (rss_mb > (unsigned long)s_cfg->resource_limit.memory_limit_mb) {
      mem_bad = true;
      fprintf(stderr, "[resource] RSS 约 %lu MB 超过 memory_limit_mb=%u\n", rss_mb,
              s_cfg->resource_limit.memory_limit_mb);
    }
  }

  if (cpu_bad) {
    s_emergency++;
    fprintf(stderr, "[resource] CPU 约 %u%% 超过上限 %u%%（emergency=%lu）\n", pct,
            s_cfg->resource_limit.cpu_limit_percent, s_emergency);
    s_preprocess_throttle = 1;
    snprintf(s_pressure_reason, sizeof(s_pressure_reason), "cpu_%u_over_%u", pct,
             s_cfg->resource_limit.cpu_limit_percent);
  } else if (mem_bad) {
    s_preprocess_throttle = 1;
    snprintf(s_pressure_reason, sizeof(s_pressure_reason), "rss_%lu_mb_over_%u", rss_mb,
             s_cfg->resource_limit.memory_limit_mb);
  } else {
    s_preprocess_throttle = 0;
    snprintf(s_pressure_reason, sizeof(s_pressure_reason), "%s", "ok");
  }
#else
  FILETIME now_wall, create_time, exit_time, kernel, user;
  GetSystemTimeAsFileTime(&now_wall);
  if (!GetProcessTimes(GetCurrentProcess(), &create_time, &exit_time, &kernel, &user)) {
    return;
  }
  uint64_t wall_delta = ft_to_u64(now_wall) - ft_to_u64(s_last.wall);
  if (wall_delta < 5000000ULL) {
    return;
  }
  uint64_t cpu_delta = (ft_to_u64(kernel) - ft_to_u64(s_last.kernel)) +
                       (ft_to_u64(user) - ft_to_u64(s_last.user));
  unsigned pct = wall_delta > 0 ? (unsigned)((cpu_delta * 100ULL) / wall_delta) : 0u;
  s_last.wall = now_wall;
  s_last.kernel = kernel;
  s_last.user = user;
  s_last_cpu_pct = pct;
  s_last_rss_mb = current_rss_mb();
  s_last_thread_count = current_thread_count();
  {
    DWORD hc = 0;
    if (GetProcessHandleCount(GetCurrentProcess(), &hc)) {
      s_last_handle_count = (uint32_t)hc;
    }
  }
  s_last_sample_ms = wall_time_ms();

  bool cpu_bad = enforce_cpu_limit && pct > s_cfg->resource_limit.cpu_limit_percent &&
                 pct > s_cfg->resource_limit.emergency_cpu_limit;
  bool mem_bad = s_cfg->resource_limit.memory_limit_mb > 0u &&
                 s_last_rss_mb > (unsigned long)s_cfg->resource_limit.memory_limit_mb;
  if (cpu_bad) {
    s_emergency++;
    s_preprocess_throttle = 1;
    fprintf(stderr, "[resource] CPU 约 %u%% 超过上限 %u%%（emergency=%lu）\n", pct,
            s_cfg->resource_limit.cpu_limit_percent, s_emergency);
    snprintf(s_pressure_reason, sizeof(s_pressure_reason), "cpu_%u_over_%u", pct,
             s_cfg->resource_limit.cpu_limit_percent);
  } else if (mem_bad) {
    s_preprocess_throttle = 1;
    fprintf(stderr, "[resource] RSS 约 %lu MB 超过 memory_limit_mb=%u\n", s_last_rss_mb,
            s_cfg->resource_limit.memory_limit_mb);
    snprintf(s_pressure_reason, sizeof(s_pressure_reason), "rss_%lu_mb_over_%u", s_last_rss_mb,
             s_cfg->resource_limit.memory_limit_mb);
  } else {
    s_preprocess_throttle = 0;
    snprintf(s_pressure_reason, sizeof(s_pressure_reason), "%s", "ok");
  }
#endif
}
