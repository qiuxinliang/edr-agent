/* §21 PMFE（Windows）：监听进程表 + 宿主优先级 — 对齐《07_进程内存取证引擎PMFE设计-1》§2.2
 * 监听枚举与 §19 共用 `edr_win_listen_collect_rows`（listen_table_win.c）。 */

#include "edr/pmfe.h"
#include "edr/listen_table_win.h"
#include "edr/edr_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winsvc.h>

#define PMFE_LISTEN_CAP 512
#define PMFE_LISTEN_ROW_BUF 2048
#define PMFE_PORTS_PER_PID 64
/** 运行中 Win32 服务 PID 去重表（与监听表同刷新周期） */
#define PMFE_SVC_PID_CAP 2048

typedef struct {
  uint32_t pid;
  uint16_t ports[PMFE_PORTS_PER_PID];
  uint8_t nports;
  uint8_t has_external;
  uint8_t has_inaddr_any;
  uint8_t has_privileged;
} PmfeListenAgg;

static PmfeListenAgg s_agg[PMFE_LISTEN_CAP];
static int s_nagg;
static uint32_t s_svc_pids[PMFE_SVC_PID_CAP];
static int s_nsvc;
static CRITICAL_SECTION s_listen_mu;

static int pmfe_u32_cmp(const void *a, const void *b) {
  uint32_t x = *(const uint32_t *)a;
  uint32_t y = *(const uint32_t *)b;
  if (x < y) {
    return -1;
  }
  if (x > y) {
    return 1;
  }
  return 0;
}

/** 枚举 SERVICE_WIN32 且 SERVICE_ACTIVE，收集 SERVICE_RUNNING 的 PID，排序去重。失败返回 0。 */
static int pmfe_enum_running_service_pids(uint32_t *out, int max_out) {
  SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
  if (!scm) {
    return 0;
  }
  DWORD need = 0;
  DWORD nret = 0;
  DWORD resume = 0;
  SetLastError(0);
  (void)EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, NULL, 0, &need, &nret, NULL,
                              NULL);
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || need < sizeof(ENUM_SERVICE_STATUS_PROCESSW)) {
    need = 4u * 1024u * 1024u;
  }
  BYTE *buf = (BYTE *)malloc(need);
  if (!buf) {
    CloseServiceHandle(scm);
    return 0;
  }
  int total = 0;
  resume = 0;
  do {
    nret = 0;
    DWORD cb = need;
    if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, buf, cb, &cb, &nret, &resume,
                               NULL)) {
      DWORD er = GetLastError();
      if (er == ERROR_MORE_DATA && cb > need) {
        void *nb = realloc(buf, cb);
        if (!nb) {
          break;
        }
        buf = (BYTE *)nb;
        need = cb;
        resume = 0;
        continue;
      }
      break;
    }
    ENUM_SERVICE_STATUS_PROCESSW *entries = (ENUM_SERVICE_STATUS_PROCESSW *)buf;
    for (DWORD i = 0; i < nret; i++) {
      if (entries[i].ServiceStatusProcess.dwCurrentState != SERVICE_RUNNING) {
        continue;
      }
      DWORD spid = entries[i].ServiceStatusProcess.dwProcessId;
      if (spid == 0) {
        continue;
      }
      if (total < max_out) {
        out[total++] = (uint32_t)spid;
      }
    }
  } while (resume != 0);
  free(buf);
  CloseServiceHandle(scm);
  if (total == 0) {
    return 0;
  }
  qsort(out, (size_t)total, sizeof(uint32_t), pmfe_u32_cmp);
  int w = 0;
  for (int i = 0; i < total; i++) {
    if (i == 0 || out[i] != out[w - 1]) {
      out[w++] = out[i];
    }
  }
  return w;
}

static int pmfe_svc_pid_in_sorted(const uint32_t *sorted, int n, uint32_t pid) {
  int lo = 0;
  int hi = n - 1;
  while (lo <= hi) {
    int mid = (lo + hi) / 2;
    if (sorted[mid] == pid) {
      return 1;
    }
    if (sorted[mid] < pid) {
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return 0;
}

static PmfeListenAgg *pmfe_find_or_add_agg(uint32_t pid) {
  for (int i = 0; i < s_nagg; i++) {
    if (s_agg[i].pid == pid) {
      return &s_agg[i];
    }
  }
  if (s_nagg >= PMFE_LISTEN_CAP) {
    return NULL;
  }
  PmfeListenAgg *a = &s_agg[s_nagg++];
  memset(a, 0, sizeof(*a));
  a->pid = pid;
  return a;
}

static void pmfe_agg_note_row(PmfeListenAgg *a, const EdrWinListenRow *row) {
  if (row->port <= 0 || row->port > 65535) {
    return;
  }
  uint16_t port = (uint16_t)row->port;
  if (a->nports < PMFE_PORTS_PER_PID) {
    a->ports[a->nports++] = port;
  }
  if (port < 1024u) {
    a->has_privileged = 1u;
  }
  if (strcmp(row->bind, "0.0.0.0") == 0 || strcmp(row->bind, "::") == 0) {
    a->has_inaddr_any = 1u;
    a->has_external = 1u;
  } else if (strcmp(row->scope, "loopback") != 0) {
    a->has_external = 1u;
  }
}

void edr_pmfe_listen_table_refresh(void) {
  EdrWinListenRow *rows = (EdrWinListenRow *)malloc((size_t)PMFE_LISTEN_ROW_BUF * sizeof(EdrWinListenRow));
  if (!rows) {
    return;
  }
  uint32_t svc_tmp[PMFE_SVC_PID_CAP];
  int nsvc = pmfe_enum_running_service_pids(svc_tmp, PMFE_SVC_PID_CAP);
  int truncated = 0;
  int n = edr_win_listen_collect_rows(rows, PMFE_LISTEN_ROW_BUF, &truncated);
  EnterCriticalSection(&s_listen_mu);
  s_nagg = 0;
  memset(s_agg, 0, sizeof(s_agg));
  for (int i = 0; i < n; i++) {
    PmfeListenAgg *a = pmfe_find_or_add_agg((uint32_t)rows[i].pid);
    if (a) {
      pmfe_agg_note_row(a, &rows[i]);
    }
  }
  s_nsvc = nsvc;
  if (nsvc > 0) {
    memcpy(s_svc_pids, svc_tmp, (size_t)nsvc * sizeof(uint32_t));
  }
  LeaveCriticalSection(&s_listen_mu);
  free(rows);
  if (truncated) {
    const char *q = getenv("EDR_PMFE_LISTEN_TRUNC_QUIET");
    if (!q || q[0] != '1') {
      EDR_LOGE("[pmfe][listen] rows truncated (cap=%d), priority table may miss listeners\n", PMFE_LISTEN_ROW_BUF);
    }
  }
}

static const PmfeListenAgg *pmfe_listen_lookup_locked(uint32_t pid) {
  for (int i = 0; i < s_nagg; i++) {
    if (s_agg[i].pid == pid) {
      return &s_agg[i];
    }
  }
  return NULL;
}

static int pmfe_pid_image_base(uint32_t pid, char *out, size_t out_cap) {
  HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
  if (!ph) {
    return -1;
  }
  wchar_t wpath[1024];
  DWORD n = 1024u;
  if (!QueryFullProcessImageNameW(ph, 0, wpath, &n)) {
    CloseHandle(ph);
    return -1;
  }
  CloseHandle(ph);
  char narrow[1024];
  if (WideCharToMultiByte(CP_UTF8, 0, wpath, -1, narrow, (int)sizeof(narrow), NULL, NULL) <= 0) {
    return -1;
  }
  const char *base = narrow;
  for (const char *p = narrow; *p; p++) {
    if (*p == '\\' || *p == '/') {
      base = p + 1;
    }
  }
  snprintf(out, out_cap, "%s", base);
  return 0;
}

typedef struct {
  const char *name;
  EdrPmfeScanPriority pr;
} PmfeCritProc;

static const PmfeCritProc s_crit[] = {
    {"lsass.exe", EDR_PMFE_PRIO_HIGH},   {"lsaiso.exe", EDR_PMFE_PRIO_HIGH}, {"spoolsv.exe", EDR_PMFE_PRIO_HIGH},
    {"wmiprvse.exe", EDR_PMFE_PRIO_HIGH}, {"csrss.exe", EDR_PMFE_PRIO_HIGH},  {"MsMpEng.exe", EDR_PMFE_PRIO_HIGH},
    {"dllhost.exe", EDR_PMFE_PRIO_MED},   {"taskhost.exe", EDR_PMFE_PRIO_MED}, {"taskhostw.exe", EDR_PMFE_PRIO_MED},
    {"wmiapsrv.exe", EDR_PMFE_PRIO_MED},  {NULL, EDR_PMFE_PRIO_LOW}};

static EdrPmfeScanPriority pmfe_match_crit(const char *base) {
  for (unsigned i = 0; s_crit[i].name; i++) {
    if (_stricmp(base, s_crit[i].name) == 0) {
      return s_crit[i].pr;
    }
  }
  return EDR_PMFE_PRIO_LOW;
}

static int pmfe_pid_is_system(uint32_t pid) {
  HANDLE ph = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);
  if (!ph) {
    return 0;
  }
  HANDLE tok = NULL;
  int ok = 0;
  if (OpenProcessToken(ph, TOKEN_QUERY, &tok)) {
    BYTE buf[256];
    DWORD ret = 0;
    if (GetTokenInformation(tok, TokenUser, buf, (DWORD)sizeof(buf), &ret)) {
      SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
      PSID sys = NULL;
      if (AllocateAndInitializeSid(&nt, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &sys)) {
        TOKEN_USER *tu = (TOKEN_USER *)buf;
        if (EqualSid(tu->User.Sid, sys)) {
          ok = 1;
        }
        FreeSid(sys);
      }
    }
    CloseHandle(tok);
  }
  CloseHandle(ph);
  return ok;
}

EdrPmfeScanPriority edr_pmfe_compute_priority(uint32_t pid) {
  if (pid == 0u) {
    return EDR_PMFE_PRIO_IGNORE;
  }
  if (pid == (uint32_t)GetCurrentProcessId()) {
    return EDR_PMFE_PRIO_IGNORE;
  }

  EnterCriticalSection(&s_listen_mu);
  const PmfeListenAgg *lp = pmfe_listen_lookup_locked(pid);
  int has_listen = lp && lp->nports > 0;
  uint8_t hex = lp ? lp->has_external : 0u;
  uint8_t h0 = lp ? lp->has_inaddr_any : 0u;
  uint8_t hp = lp ? lp->has_privileged : 0u;
  int is_svc = (s_nsvc > 0) ? pmfe_svc_pid_in_sorted(s_svc_pids, s_nsvc, pid) : 0;
  LeaveCriticalSection(&s_listen_mu);

  const char *dis_svc = getenv("EDR_PMFE_SERVICE_PRIORITY");
  int svc_rule_on = !(dis_svc && dis_svc[0] == '0');

  if (has_listen) {
    int sys = pmfe_pid_is_system(pid);
    if (hex && sys && hp) {
      return EDR_PMFE_PRIO_CRITICAL;
    }
    if (hex && sys) {
      return EDR_PMFE_PRIO_HIGH;
    }
    /* 规则3：注册为 Windows 服务 + 有监听 → HIGH（§2.2.4） */
    if (svc_rule_on && is_svc) {
      return EDR_PMFE_PRIO_HIGH;
    }
    /* 无 Token 查询时：特权端口上的对外监听仍抬升到 HIGH */
    if (hex && hp) {
      return EDR_PMFE_PRIO_HIGH;
    }
    if (h0) {
      return EDR_PMFE_PRIO_MED;
    }
    if (!hex) {
      return EDR_PMFE_PRIO_LOW;
    }
    return EDR_PMFE_PRIO_MED;
  }

  char base[260];
  if (pmfe_pid_image_base(pid, base, sizeof(base)) == 0) {
    return pmfe_match_crit(base);
  }
  return EDR_PMFE_PRIO_LOW;
}

void edr_pmfe_host_policy_init(void) {
  InitializeCriticalSection(&s_listen_mu);
}

void edr_pmfe_host_policy_shutdown(void) {
  DeleteCriticalSection(&s_listen_mu);
}
