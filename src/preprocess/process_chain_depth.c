#include "edr/process_chain_depth.h"

#include <string.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>
#endif

#define EDR_PCHAIN_MAX_REASONABLE 10u
#define EDR_PCHAIN_MAX_TRACE 32u

static int is_untrusted_depth(const char *exe_path) {
  if (!exe_path || !exe_path[0]) {
    return 0;
  }
  const char *lower_system32 = "\\system32\\";
  const char *lower_syswow64 = "\\syswow64\\";
  char buf[512];
  size_t len = strlen(exe_path);
  if (len >= sizeof(buf)) {
    len = sizeof(buf) - 1;
  }
  for (size_t i = 0; i < len; i++) {
    char c = exe_path[i];
    if (c >= 'A' && c <= 'Z') {
      c = (char)(c + ('a' - 'A'));
    }
    buf[i] = c;
  }
  buf[len] = '\0';
  if (strstr(buf, lower_system32) || strstr(buf, lower_syswow64)) {
    return 1;
  }
  return 0;
}

#ifdef _WIN32
static uint32_t win_ppid_of(uint32_t pid) {
  if (pid == 0u) {
    return 0u;
  }
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) {
    return 0u;
  }
  PROCESSENTRY32W pe;
  pe.dwSize = (DWORD)sizeof(pe);
  uint32_t out = 0u;
  if (Process32FirstW(snap, &pe)) {
    do {
      if (pe.th32ProcessID == (DWORD)pid) {
        out = (uint32_t)pe.th32ParentProcessID;
        break;
      }
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  return out;
}

static uint32_t count_parent_hops(uint32_t pid) {
  uint32_t hops = 0u;
  uint32_t cur = pid;
  for (int n = 0; n < (int)EDR_PCHAIN_MAX_TRACE; n++) {
    uint32_t pp = win_ppid_of(cur);
    if (pp == 0u) {
      break;
    }
    if (pp == cur) {
      break;
    }
    hops++;
    cur = pp;
  }
  return hops;
}
#endif

void edr_behavior_record_fill_process_chain_depth(EdrBehaviorRecord *r) {
  if (!r) {
    return;
  }
  r->process_chain_depth = 0u;
#ifdef _WIN32
  if (r->pid != 0u) {
    uint32_t depth = count_parent_hops(r->pid);
    if (depth > EDR_PCHAIN_MAX_REASONABLE && is_untrusted_depth(r->exe_path)) {
      depth = EDR_PCHAIN_MAX_REASONABLE;
    }
    r->process_chain_depth = depth;
  }
#endif
}
