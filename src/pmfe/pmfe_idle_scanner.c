#include "edr/pmfe_idle_scanner.h"
#include "edr/pmfe_engine_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <powrprof.h>
#include <tlhelp32.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "powrprof.lib")
#else
#include <unistd.h>
#include <time.h>
#endif

static const EdrConfig *s_cfg = NULL;
#ifdef _WIN32
static volatile LONG s_stop;
static volatile LONG s_running;
#else
static volatile int s_stop;
static volatile int s_running;
#define InterlockedExchange(a, b) (*(a) = (b))
#endif
static uint64_t s_last_scan_ms;
static uint64_t s_last_idle_time;
static int s_idle_ticks;
static int s_busy_ticks;

static const char *g_system_services[] = {
  "svchost.exe", "lsass.exe",   "spoolsv.exe", "services.exe",
  "winlogon.exe", "csrss.exe",  "dwm.exe",     "taskhostw.exe",
  "wlms.exe",     "wininit.exe","WmiPrvSE.exe", "msdtc.exe",
  "VSSVC.exe",    NULL
};

static int is_system_service(const char *name) {
  if (!name) return 0;
  const char *base = strrchr(name, '\\');
  base = base ? base + 1 : name;
  for (int i = 0; g_system_services[i]; i++) {
#ifdef _WIN32
    if (_stricmp(base, g_system_services[i]) == 0) return 1;
#else
    if (strcasecmp(base, g_system_services[i]) == 0) return 1;
#endif
  }
  return 0;
}

#ifdef _WIN32
static int build_tcp_pid_set(uint8_t *pid_set, size_t pid_set_cap) {
  memset(pid_set, 0, pid_set_cap);
  ULONG size = 0;
  GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
  if (size == 0) return 0;
  MIB_TCPTABLE_OWNER_PID *t = (MIB_TCPTABLE_OWNER_PID *)malloc(size);
  if (!t) return 0;
  if (GetExtendedTcpTable(t, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
    free(t);
    return 0;
  }
  int count = 0;
  for (DWORD i = 0; i < t->dwNumEntries; i++) {
    if (t->table[i].dwState == MIB_TCP_STATE_ESTAB) {
      DWORD pid = t->table[i].dwOwningPid;
      if (pid < (DWORD)pid_set_cap) {
        pid_set[pid] = 1;
        count++;
      }
    }
  }
  free(t);
  return count;
}

static double cpu_usage_60s(void) {
  static FILETIME prev_idle, prev_kernel, prev_user;
  static int first = 1;
  FILETIME idle, kernel, user;
  if (!GetSystemTimes(&idle, &kernel, &user)) return 0.0;
  if (first) {
    prev_idle = idle; prev_kernel = kernel; prev_user = user;
    first = 0;
    return 0.0;
  }
  ULARGE_INTEGER d_idle, d_kernel, d_user;
  d_idle.QuadPart = *(ULONGLONG *)&idle - *(ULONGLONG *)&prev_idle;
  d_kernel.QuadPart = *(ULONGLONG *)&kernel - *(ULONGLONG *)&prev_kernel;
  d_user.QuadPart = *(ULONGLONG *)&user - *(ULONGLONG *)&prev_user;
  prev_idle = idle; prev_kernel = kernel; prev_user = user;
  ULONGLONG total_sys = d_kernel.QuadPart + d_user.QuadPart;
  if (total_sys == 0) return 0.0;
  return 100.0 * (1.0 - (double)d_idle.QuadPart / (double)total_sys);
}

static int is_on_battery(void) {
  SYSTEM_POWER_STATUS sps;
  if (!GetSystemPowerStatus(&sps)) return 0;
  return (sps.ACLineStatus == 0);
}

static int is_fullscreen(void) {
  HWND fg = GetForegroundWindow();
  if (!fg) return 0;
  RECT r;
  if (!GetWindowRect(fg, &r)) return 0;
  int w = r.right - r.left;
  int h = r.bottom - r.top;
  int sw = GetSystemMetrics(SM_CXSCREEN);
  int sh = GetSystemMetrics(SM_CYSCREEN);
  return (w >= sw && h >= sh);
}
#else
static int build_tcp_pid_set(uint8_t *pid_set, size_t pid_set_cap) {
  (void)pid_set; (void)pid_set_cap;
  return 0;
}
static double cpu_usage_60s(void) { return 0.0; }
static int is_on_battery(void) { return 0; }
static int is_fullscreen(void) { return 0; }
#endif

static int is_idle(const EdrConfig *cfg) {
  double cpu = cpu_usage_60s();
  if (cpu < 0.001 && s_last_idle_time == 0) {
    s_last_idle_time = 1; /* first call, skip */
    return 0;
  }
  if (cpu > cfg->pmfe.idle_cpu_threshold) {
    s_busy_ticks++;
    s_idle_ticks = 0;
    return 0;
  }
  s_idle_ticks++;
  s_busy_ticks = 0;
  if (s_idle_ticks < 2) return 0;
  if (cfg->pmfe.idle_skip_on_battery && is_on_battery()) return 0;
  if (is_fullscreen()) return 0;
  return 1;
}

extern int edr_pmfe_submit_etw_scan(const char *reason, uint32_t pid);

void pmfe_idle_scanner_init(const EdrConfig *cfg) {
  s_cfg = cfg;
  s_last_scan_ms = 0;
  s_idle_ticks = 0;
  s_busy_ticks = 0;
  s_last_idle_time = 0;
  InterlockedExchange(&s_running, cfg->pmfe.idle_scan_enabled ? 1 : 0);
  InterlockedExchange(&s_stop, 0);
  if (cfg->pmfe.idle_scan_enabled) {
    fprintf(stderr, "[pmfe] idle scanner init: interval=%umin max_procs=%u cpu_thr=%.1f%%\n",
            cfg->pmfe.idle_scan_interval_min, cfg->pmfe.idle_scan_max_procs, cfg->pmfe.idle_cpu_threshold);
  }
}

void pmfe_idle_scanner_tick(void) {
  if (!s_running || !s_cfg) return;
  if (s_cfg->detection.pmfe_mode == 0 && !s_cfg->pmfe.idle_scan_enabled) return;

  uint64_t now_ms = 0;
#ifdef _WIN32
  now_ms = GetTickCount64();
#else
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  now_ms = (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
#endif

  uint64_t interval_ms = (uint64_t)s_cfg->pmfe.idle_scan_interval_min * 60000ull;
  if (s_last_scan_ms != 0 && now_ms - s_last_scan_ms < interval_ms) return;
  if (!is_idle(s_cfg)) return;

  s_last_scan_ms = now_ms;

  uint8_t tcp_pids[65536 / 8];
  int tcp_count = build_tcp_pid_set(tcp_pids, sizeof(tcp_pids));

  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return;
  PROCESSENTRY32W pe;
  pe.dwSize = sizeof(pe);
  uint32_t submitted = 0;
  uint32_t max_procs = s_cfg->pmfe.idle_scan_max_procs;

  if (Process32FirstW(snap, &pe)) {
    do {
      if (submitted >= max_procs) break;
      if (pe.th32ProcessID <= 100) continue;
      BYTE tcp_off = pe.th32ProcessID / 8;
      BYTE tcp_bit = 1 << (pe.th32ProcessID % 8);
      if (!(tcp_pids[tcp_off] & tcp_bit)) continue;
      char name_lower[260];
      WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, name_lower, (int)sizeof(name_lower), NULL, NULL);
      if (!is_system_service(name_lower)) continue;
      edr_pmfe_submit_etw_scan("idle_scan", pe.th32ProcessID);
      submitted++;
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);

  if (submitted > 0) {
    fprintf(stderr, "[pmfe] idle scan round: tcp_procs=%d submitted=%u\n", tcp_count, submitted);
  }
}

void pmfe_idle_scanner_stop(void) {
  InterlockedExchange(&s_stop, 1);
  InterlockedExchange(&s_running, 0);
}

bool pmfe_idle_scanner_running(void) {
  return s_running != 0;
}
