/* Windows：共享监听表枚举 — §19 攻击面 + §21 PMFE（进程内 TTL 缓存） */

#ifdef _WIN32

#include "edr/listen_table_win.h"
#include "edr/config.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "edr/attack_surface_win_util.h"

/** 与 PMFE `PMFE_LISTEN_ROW_BUF` 对齐并留余量，缓存完整快照后再按调用方 max_out 拷贝。 */
#define EDR_WIN_LISTEN_CACHE_MAX_ROWS 4096

static void row_fill_v4_tcp(MIB_TCPROW_OWNER_PID *row, EdrWinListenRow *L) {
  memset(L, 0, sizeof(*L));
  snprintf(L->proto, sizeof(L->proto), "%s", "tcp");
  edr_asurf_win_ipv4_to_string(row->dwLocalAddr, L->bind, sizeof(L->bind));
  L->port = (int)ntohs((u_short)row->dwLocalPort);
  edr_asurf_win_bind_scope_v4(L->bind, L->scope, sizeof(L->scope));
  L->pid = (int)row->dwOwningPid;
}

static void row_fill_v4_udp(MIB_UDPROW_OWNER_PID *row, EdrWinListenRow *L) {
  memset(L, 0, sizeof(*L));
  snprintf(L->proto, sizeof(L->proto), "%s", "udp");
  edr_asurf_win_ipv4_to_string(row->dwLocalAddr, L->bind, sizeof(L->bind));
  L->port = (int)ntohs((u_short)row->dwLocalPort);
  edr_asurf_win_bind_scope_v4(L->bind, L->scope, sizeof(L->scope));
  L->pid = (int)row->dwOwningPid;
}

static void row_fill_v6_tcp(MIB_TCP6ROW_OWNER_PID *row, EdrWinListenRow *L) {
  memset(L, 0, sizeof(*L));
  snprintf(L->proto, sizeof(L->proto), "%s", "tcp6");
  edr_asurf_win_ipv6_to_string(row->ucLocalAddr, L->bind, sizeof(L->bind));
  L->port = (int)ntohs((u_short)row->dwLocalPort);
  edr_asurf_win_bind_scope_v6(L->bind, L->scope, sizeof(L->scope));
  L->pid = (int)row->dwOwningPid;
}

static void row_fill_v6_udp(MIB_UDP6ROW_OWNER_PID *row, EdrWinListenRow *L) {
  memset(L, 0, sizeof(*L));
  snprintf(L->proto, sizeof(L->proto), "%s", "udp6");
  edr_asurf_win_ipv6_to_string(row->ucLocalAddr, L->bind, sizeof(L->bind));
  L->port = (int)ntohs((u_short)row->dwLocalPort);
  edr_asurf_win_bind_scope_v6(L->bind, L->scope, sizeof(L->scope));
  L->pid = (int)row->dwOwningPid;
}

static int collect_rows_impl(EdrWinListenRow *out, int max_out, int *truncated) {
  int n = 0;
  *truncated = 0;
  if (!out || max_out <= 0) {
    return 0;
  }
  edr_asurf_win_ensure_wsa();

  DWORD sz = 0;
  PMIB_TCPTABLE_OWNER_PID tcp = NULL;
  if (GetExtendedTcpTable(NULL, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0) == ERROR_INSUFFICIENT_BUFFER &&
      sz > 0) {
    tcp = (PMIB_TCPTABLE_OWNER_PID)malloc((size_t)sz);
    if (tcp) {
      DWORD req = sz;
      if (GetExtendedTcpTable((PVOID)tcp, &req, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0) != NO_ERROR) {
        free(tcp);
        tcp = NULL;
      }
    }
  }
  if (tcp) {
    for (DWORD i = 0; i < tcp->dwNumEntries; i++) {
      if (n >= max_out) {
        *truncated = 1;
        break;
      }
      MIB_TCPROW_OWNER_PID *row = &tcp->table[i];
      if ((int)row->dwState != 2) {
        continue;
      }
      row_fill_v4_tcp(row, &out[n]);
      n++;
    }
    free(tcp);
  }

  sz = 0;
  PMIB_UDPTABLE_OWNER_PID udp = NULL;
  if (GetExtendedUdpTable(NULL, &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER &&
      sz > 0) {
    udp = (PMIB_UDPTABLE_OWNER_PID)malloc((size_t)sz);
    if (udp) {
      DWORD req = sz;
      if (GetExtendedUdpTable((PVOID)udp, &req, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) != NO_ERROR) {
        free(udp);
        udp = NULL;
      }
    }
  }
  if (udp) {
    for (DWORD i = 0; i < udp->dwNumEntries; i++) {
      if (n >= max_out) {
        *truncated = 1;
        break;
      }
      row_fill_v4_udp(&udp->table[i], &out[n]);
      n++;
    }
    free(udp);
  }

  sz = 0;
  PMIB_TCP6TABLE_OWNER_PID tcp6 = NULL;
  if (GetExtendedTcpTable(NULL, &sz, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_LISTENER, 0) == ERROR_INSUFFICIENT_BUFFER &&
      sz > 0) {
    tcp6 = (PMIB_TCP6TABLE_OWNER_PID)malloc((size_t)sz);
    if (tcp6) {
      DWORD req6 = sz;
      if (GetExtendedTcpTable((PVOID)tcp6, &req6, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_LISTENER, 0) != NO_ERROR) {
        free(tcp6);
        tcp6 = NULL;
      }
    }
  }
  if (tcp6) {
    for (DWORD i = 0; i < tcp6->dwNumEntries; i++) {
      if (n >= max_out) {
        *truncated = 1;
        break;
      }
      MIB_TCP6ROW_OWNER_PID *row = &tcp6->table[i];
      if ((int)row->dwState != 2) {
        continue;
      }
      row_fill_v6_tcp(row, &out[n]);
      n++;
    }
    free(tcp6);
  }

  sz = 0;
  PMIB_UDP6TABLE_OWNER_PID udp6 = NULL;
  if (GetExtendedUdpTable(NULL, &sz, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER &&
      sz > 0) {
    udp6 = (PMIB_UDP6TABLE_OWNER_PID)malloc((size_t)sz);
    if (udp6) {
      DWORD req6 = sz;
      if (GetExtendedUdpTable((PVOID)udp6, &req6, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) != NO_ERROR) {
        free(udp6);
        udp6 = NULL;
      }
    }
  }
  if (udp6) {
    for (DWORD i = 0; i < udp6->dwNumEntries; i++) {
      if (n >= max_out) {
        *truncated = 1;
        break;
      }
      row_fill_v6_udp(&udp6->table[i], &out[n]);
      n++;
    }
    free(udp6);
  }

  return n;
}

static CRITICAL_SECTION g_listen_cache_cs;
static volatile LONG g_listen_cs_ready;

static void listen_cache_lock(void) {
  if (InterlockedCompareExchange(&g_listen_cs_ready, 1, 0) == 0) {
    InitializeCriticalSection(&g_listen_cache_cs);
#if defined(_MSC_VER)
    MemoryBarrier();
#else
    __sync_synchronize();
#endif
    InterlockedExchange(&g_listen_cs_ready, 2);
  } else {
    while (InterlockedCompareExchange(&g_listen_cs_ready, 0, 0) != 2) {
      Sleep(0);
    }
  }
  EnterCriticalSection(&g_listen_cache_cs);
}

static void listen_cache_unlock(void) {
  LeaveCriticalSection(&g_listen_cache_cs);
}

static EdrWinListenRow g_listen_cache_rows[EDR_WIN_LISTEN_CACHE_MAX_ROWS];
static ULONGLONG g_listen_cache_tick_ms;
static int g_listen_cache_n;
static int g_listen_cache_trunc_internal;
static int g_listen_cache_filled;
static uint32_t g_listen_cache_ttl_effective_ms = 2000u;

void edr_win_listen_apply_config(const EdrConfig *cfg) {
  uint32_t ms = cfg ? cfg->attack_surface.win_listen_cache_ttl_ms : 2000u;
  const char *e = getenv("EDR_WIN_LISTEN_CACHE_TTL_MS");
  if (e && e[0]) {
    char *end = NULL;
    unsigned long v = strtoul(e, &end, 10);
    if (end != e && v <= 0xffffffffUL) {
      ms = (uint32_t)v;
    }
  }
  if (ms > 300000u) {
    ms = 300000u;
  }
  listen_cache_lock();
  g_listen_cache_ttl_effective_ms = ms;
  g_listen_cache_filled = 0;
  listen_cache_unlock();
}

int edr_win_listen_collect_rows(EdrWinListenRow *out, int max_out, int *truncated) {
  if (!truncated) {
    return 0;
  }
  *truncated = 0;
  if (!out || max_out <= 0) {
    return 0;
  }

  listen_cache_lock();

  ULONGLONG now = GetTickCount64();
  int need_refresh = 1;
  if (g_listen_cache_filled && g_listen_cache_ttl_effective_ms > 0u) {
    ULONGLONG elapsed = now - g_listen_cache_tick_ms;
    if (elapsed <= (ULONGLONG)g_listen_cache_ttl_effective_ms) {
      need_refresh = 0;
    }
  }

  if (need_refresh) {
    int tr = 0;
    int n = collect_rows_impl(g_listen_cache_rows, EDR_WIN_LISTEN_CACHE_MAX_ROWS, &tr);
    g_listen_cache_n = n;
    g_listen_cache_trunc_internal = tr;
    g_listen_cache_tick_ms = now;
    g_listen_cache_filled = 1;
  }

  int total = g_listen_cache_n;
  int copy_n = total;
  if (copy_n > max_out) {
    copy_n = max_out;
    *truncated = 1;
  } else if (g_listen_cache_trunc_internal) {
    *truncated = 1;
  }

  if (copy_n > 0) {
    memcpy(out, g_listen_cache_rows, (size_t)copy_n * sizeof(EdrWinListenRow));
  }

  listen_cache_unlock();
  return copy_n;
}

#endif
