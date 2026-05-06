#include "edr/process_chain_depth.h"
#include "edr/behavior_record.h"

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

static const char *basename_c(const char *path) {
  if (!path || !path[0]) return "";
  const char *p = path;
  for (const char *c = path; *c; c++) {
    if (*c == '\\' || *c == '/') p = c + 1;
  }
  return p;
}

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
static int lookup_process_name_path(uint32_t pid, char *name_out, size_t name_cap,
                                     char *path_out, size_t path_cap) {
  if (pid == 0u) {
    if (name_out && name_cap > 0) name_out[0] = '\0';
    if (path_out && path_cap > 0) path_out[0] = '\0';
    return -1;
  }
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return -1;
  PROCESSENTRY32W pe;
  pe.dwSize = (DWORD)sizeof(pe);
  int found = 0;
  if (Process32FirstW(snap, &pe)) {
    do {
      if (pe.th32ProcessID == (DWORD)pid) {
        if (path_out && path_cap > 0) {
          WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, path_out, (int)path_cap - 1, NULL, NULL);
          path_out[path_cap - 1] = '\0';
        }
        if (name_out && name_cap > 0) {
          if (path_out && path_out[0]) {
            snprintf(name_out, name_cap, "%s", basename_c(path_out));
          } else {
            name_out[0] = '\0';
          }
        }
        found = 1;
        break;
      }
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  return found ? 0 : -1;
}

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

static uint32_t count_parent_hops(uint32_t pid, uint32_t *out_grandparent_pid) {
  uint32_t hops = 0u;
  uint32_t cur = pid;
  uint32_t gp = 0u;
  for (int n = 0; n < (int)EDR_PCHAIN_MAX_TRACE; n++) {
    uint32_t pp = win_ppid_of(cur);
    if (pp == 0u) {
      break;
    }
    if (pp == cur) {
      break;
    }
    hops++;
    if (hops == 2u) {
      gp = pp;
    }
    cur = pp;
  }
  if (out_grandparent_pid) {
    *out_grandparent_pid = gp;
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
    uint32_t gp_pid = 0;
    uint32_t depth = count_parent_hops(r->pid, &gp_pid);
    if (depth > EDR_PCHAIN_MAX_REASONABLE && is_untrusted_depth(r->exe_path)) {
      depth = EDR_PCHAIN_MAX_REASONABLE;
    }
    r->process_chain_depth = depth;
    if (gp_pid != 0u) {
      char gp_name[EDR_BR_STR_SHORT];
      char gp_path[EDR_BR_STR_MID];
      if (lookup_process_name_path(gp_pid, gp_name, sizeof(gp_name),
                                   gp_path, sizeof(gp_path)) == 0) {
        snprintf(r->grandparent_name, sizeof(r->grandparent_name), "%s", gp_name);
        snprintf(r->grandparent_path, sizeof(r->grandparent_path), "%s", gp_path);
      }
    }
  }
#endif
}
