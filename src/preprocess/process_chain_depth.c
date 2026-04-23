#include "edr/process_chain_depth.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>
#endif

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
  for (int n = 0; n < 256; n++) {
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
    r->process_chain_depth = count_parent_hops(r->pid);
  }
#endif
}
