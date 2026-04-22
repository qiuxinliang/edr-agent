/* §21 PMFE：预处理阶段自动入队 — Windows：ETW shellcode；Linux：`EDR_PMFE_ETW_AUTO` + webshell 检测 */

#include "edr/pmfe.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if defined(__linux__) && !defined(_WIN32)
#include <stdio.h>
#include <unistd.h>
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>

/** 在 ETW1 文本中查找 `key=value` 行（key 不含 '='） */
static int etw1_line_value(const uint8_t *data, uint32_t len, const char *key, char *out, size_t out_cap) {
  if (!data || len == 0u || !key || !out || out_cap == 0u) {
    return -1;
  }
  char buf[8192];
  size_t n = len;
  if (n >= sizeof(buf)) {
    n = sizeof(buf) - 1u;
  }
  memcpy(buf, data, n);
  buf[n] = '\0';

  size_t kl = strlen(key);
  if (kl + 2u >= sizeof(buf)) {
    return -1;
  }
  char pfx[96];
  if (kl + 2u > sizeof(pfx)) {
    return -1;
  }
  memcpy(pfx, key, kl);
  pfx[kl] = '=';
  pfx[kl + 1u] = '\0';

  for (char *p = buf; *p;) {
    char *nl = strchr(p, '\n');
    size_t linelen = nl ? (size_t)(nl - p) : strlen(p);
    if (linelen > kl + 1u && strncmp(p, pfx, kl + 1u) == 0) {
      size_t vl = linelen - (kl + 1u);
      if (vl >= out_cap) {
        vl = out_cap - 1u;
      }
      memcpy(out, p + kl + 1u, vl);
      out[vl] = '\0';
      return 0;
    }
    if (!nl) {
      break;
    }
    p = nl + 1;
  }
  return -1;
}

static uint32_t pmfe_tcp_owner_for_local_port_v4(uint16_t port_host_order) {
  DWORD size = 0;
  if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER ||
      size == 0) {
    return 0u;
  }
  MIB_TCPTABLE_OWNER_PID *tab = (MIB_TCPTABLE_OWNER_PID *)malloc(size);
  if (!tab) {
    return 0u;
  }
  if (GetExtendedTcpTable(tab, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
    free(tab);
    return 0u;
  }
  uint32_t listen_pid = 0u;
  uint32_t estab_pid = 0u;
  for (DWORD i = 0; i < tab->dwNumEntries; i++) {
    MIB_TCPROW_OWNER_PID *r = &tab->table[i];
    uint16_t lp = (uint16_t)ntohs((u_short)r->dwLocalPort);
    if (lp != port_host_order) {
      continue;
    }
    /* 与 attack_surface_report / attack_surface_egress 一致：LISTEN=2、ESTABLISHED=5 */
    if ((int)r->dwState == 2) {
      listen_pid = r->dwOwningPid;
    } else if ((int)r->dwState == 5) {
      estab_pid = r->dwOwningPid;
    }
  }
  free(tab);
  if (listen_pid != 0u) {
    return listen_pid;
  }
  return estab_pid;
}
#endif

void edr_pmfe_on_preprocess_slot(const EdrEventSlot *slot, const EdrBehaviorRecord *br) {
  if (!slot || !br) {
    return;
  }
#if defined(__linux__) && !defined(_WIN32)
  const char *en = getenv("EDR_PMFE_ETW_AUTO");
  if (!en || en[0] != '1') {
    return;
  }
  if (br->type != EDR_EVENT_WEBSHELL_DETECTED) {
    return;
  }
  if (br->pid == 0u || br->pid == (uint32_t)getpid()) {
    return;
  }
  EdrPmfeTriggerBand band = (slot->priority == 0u) ? EDR_PMFE_BAND_P0 : EDR_PMFE_BAND_P1;
  if (edr_pmfe_submit_etw_scan_ex("webshell", br->pid, band, 0) == 0) {
    fprintf(stderr, "[pmfe][pre] linux auto_queued webshell pid=%u band=%u\n", (unsigned)br->pid, (unsigned)band);
  }
#elif defined(_WIN32)
  const char *en = getenv("EDR_PMFE_ETW_AUTO");
  if (!en || en[0] != '1') {
    return;
  }
  if (br->type != EDR_EVENT_PROTOCOL_SHELLCODE) {
    return;
  }

  char score_s[40];
  char dpt_s[24];
  if (etw1_line_value(slot->data, slot->size, "score", score_s, sizeof(score_s)) != 0) {
    return;
  }
  double score = strtod(score_s, NULL);
  double th = 0.65;
  const char *ts = getenv("EDR_PMFE_ETW_SHELLCODE_SCORE");
  if (ts && ts[0]) {
    th = strtod(ts, NULL);
  }
  if (score < th) {
    return;
  }

  uint32_t target = br->pid;
  if (target == 0u && etw1_line_value(slot->data, slot->size, "dpt", dpt_s, sizeof(dpt_s)) == 0) {
    unsigned long dpt = strtoul(dpt_s, NULL, 10);
    if (dpt > 0ul && dpt <= 65535ul) {
      target = pmfe_tcp_owner_for_local_port_v4((uint16_t)dpt);
    }
  }

  DWORD self = GetCurrentProcessId();
  if (target == 0u || target == (uint32_t)self) {
    return;
  }

  char va_s[48];
  uint64_t hint_va = 0ull;
  if (etw1_line_value(slot->data, slot->size, "va", va_s, sizeof(va_s)) == 0) {
    hint_va = strtoull(va_s, NULL, 0);
  } else if (etw1_line_value(slot->data, slot->size, "hint", va_s, sizeof(va_s)) == 0) {
    hint_va = strtoull(va_s, NULL, 0);
  }

  EdrPmfeTriggerBand band = (slot->priority == 0u) ? EDR_PMFE_BAND_P0 : EDR_PMFE_BAND_P1;

  if (edr_pmfe_submit_etw_scan_ex("shellcode", target, band, hint_va) == 0) {
    fprintf(stderr, "[pmfe][etw] auto_queued shellcode score=%.4f target_pid=%u band=%u hint=0x%llx\n", score,
            (unsigned)target, (unsigned)band, (unsigned long long)hint_va);
  }
#else
  (void)slot;
  (void)br;
#endif
}

