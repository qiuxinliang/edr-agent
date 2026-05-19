#include "edr/process_tree_cache.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>
#endif

#define PT_HT_CAPACITY 4096u

typedef struct {
  ProcessTreeEntry entry;
  bool occupied;
} PTHashSlot;

static PTHashSlot g_pt_table[PT_HT_CAPACITY];
static uint64_t g_pt_oldest_ns;
static bool g_pt_initialized;

#ifdef _WIN32
static const char *g_key_proc_names[] = {
    "System", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "winlogon.exe",
    "svchost.exe", "explorer.exe", "spoolsv.exe",
    "taskhostw.exe", "dwm.exe",
};
static EdrKeyProcSlot g_key_procs[EDR_KEY_PROC_MAX];
#endif

static size_t pt_hash(uint32_t pid) {
  return ((size_t)pid * 2654435761u) % PT_HT_CAPACITY;
}

static void pt_evict_lru(void) {
  uint64_t oldest = UINT64_MAX;
  size_t oldest_i = 0;
  for (size_t i = 0; i < PT_HT_CAPACITY; i++) {
    if (g_pt_table[i].occupied && g_pt_table[i].entry.last_seen_ns < oldest) {
      oldest = g_pt_table[i].entry.last_seen_ns;
      oldest_i = i;
    }
  }
  if (oldest != UINT64_MAX) {
    g_pt_table[oldest_i].occupied = false;
    g_pt_oldest_ns = 0;
    for (size_t i = 0; i < PT_HT_CAPACITY; i++) {
      if (g_pt_table[i].occupied && g_pt_table[i].entry.last_seen_ns > g_pt_oldest_ns) {
        g_pt_oldest_ns = g_pt_table[i].entry.last_seen_ns;
      }
    }
  }
}

void edr_pt_cache_init(void) {
  (void)memset(g_pt_table, 0, sizeof(g_pt_table));
  g_pt_oldest_ns = 0;
  g_pt_initialized = true;
}

void edr_pt_cache_shutdown(void) {
  (void)memset(g_pt_table, 0, sizeof(g_pt_table));
  g_pt_oldest_ns = 0;
  g_pt_initialized = false;
}

int edr_pt_cache_put(uint32_t pid, uint32_t ppid,
                     const char *process_name, const char *cmdline,
                     const char *exe_path, const char *parent_name,
                     uint64_t start_time_ns) {
  if (!g_pt_initialized) return -1;

  size_t idx = pt_hash(pid);
  for (size_t i = 0; i < PT_HT_CAPACITY; i++) {
    size_t probe = (idx + i) % PT_HT_CAPACITY;
    if (!g_pt_table[probe].occupied || g_pt_table[probe].entry.pid == pid) {
      ProcessTreeEntry *e = &g_pt_table[probe].entry;
      e->pid = pid;
      e->ppid = ppid;
      e->start_time_ns = start_time_ns;
      e->last_seen_ns = start_time_ns;
      if (process_name) {
        strncpy(e->process_name, process_name, EDR_PTC_STR_SHORT - 1);
        e->process_name[EDR_PTC_STR_SHORT - 1] = '\0';
      } else {
        e->process_name[0] = '\0';
      }
      if (cmdline) {
        strncpy(e->cmdline, cmdline, EDR_PTC_STR_LONG - 1);
        e->cmdline[EDR_PTC_STR_LONG - 1] = '\0';
      } else {
        e->cmdline[0] = '\0';
      }
      if (exe_path) {
        strncpy(e->exe_path, exe_path, EDR_PTC_STR_PATH - 1);
        e->exe_path[EDR_PTC_STR_PATH - 1] = '\0';
      } else {
        e->exe_path[0] = '\0';
      }
      if (parent_name) {
        strncpy(e->parent_name, parent_name, EDR_PTC_STR_SHORT - 1);
        e->parent_name[EDR_PTC_STR_SHORT - 1] = '\0';
      } else {
        e->parent_name[0] = '\0';
      }
      g_pt_table[probe].occupied = true;
      if (start_time_ns > g_pt_oldest_ns || g_pt_oldest_ns == 0) {
        g_pt_oldest_ns = start_time_ns;
      }
      return 0;
    }
  }
  pt_evict_lru();
  return edr_pt_cache_put(pid, ppid, process_name, cmdline,
                          exe_path, parent_name, start_time_ns);
}

const ProcessTreeEntry *edr_pt_cache_get(uint32_t pid) {
  if (!g_pt_initialized) return NULL;
  size_t idx = pt_hash(pid);
  for (size_t i = 0; i < PT_HT_CAPACITY; i++) {
    size_t probe = (idx + i) % PT_HT_CAPACITY;
    if (!g_pt_table[probe].occupied) return NULL;
    if (g_pt_table[probe].entry.pid == pid) return &g_pt_table[probe].entry;
  }
  return NULL;
}

int edr_pt_cache_remove(uint32_t pid) {
  if (!g_pt_initialized) return -1;
  size_t idx = pt_hash(pid);
  for (size_t i = 0; i < PT_HT_CAPACITY; i++) {
    size_t probe = (idx + i) % PT_HT_CAPACITY;
    if (!g_pt_table[probe].occupied) return -1;
    if (g_pt_table[probe].entry.pid == pid) {
      g_pt_table[probe].occupied = false;
      return 0;
    }
  }
  return -1;
}

uint32_t edr_pt_cache_chain_depth(uint32_t pid) {
  uint32_t depth = 0;
  uint32_t cur = pid;
  for (int hop = 0; hop < 32; hop++) {
    const ProcessTreeEntry *e = edr_pt_cache_get(cur);
    if (!e || e->ppid == 0 || e->ppid == cur) {
      depth++;
      break;
    }
    depth++;
    cur = e->ppid;
  }
  return depth;
}

void edr_pt_cache_fill_record(uint32_t pid,
                              char *grandparent_name, size_t gn_cap,
                              char *grandparent_path, size_t gp_cap,
                              char *parent_cmdline,    size_t pc_cap,
                              uint32_t *out_chain_depth) {
  if (grandparent_name) grandparent_name[0] = '\0';
  if (grandparent_path) grandparent_path[0] = '\0';
  if (parent_cmdline)  parent_cmdline[0] = '\0';
  if (out_chain_depth) *out_chain_depth = 0;

  const ProcessTreeEntry *self = edr_pt_cache_get(pid);
  if (!self) return;

  if (parent_cmdline && self->cmdline[0]) {
    strncpy(parent_cmdline, self->cmdline, pc_cap - 1);
    parent_cmdline[pc_cap - 1] = '\0';
  }

  if (self->ppid == 0 || self->ppid == pid) {
    if (out_chain_depth) *out_chain_depth = 1;
    return;
  }

  const ProcessTreeEntry *parent = edr_pt_cache_get(self->ppid);
  if (!parent || parent->ppid == 0 || parent->ppid == self->ppid) {
    if (out_chain_depth) *out_chain_depth = parent ? 2 : 1;
    return;
  }

  const ProcessTreeEntry *grandparent = edr_pt_cache_get(parent->ppid);
  if (grandparent) {
    if (grandparent_name) {
      strncpy(grandparent_name, grandparent->process_name, gn_cap - 1);
      grandparent_name[gn_cap - 1] = '\0';
    }
    if (grandparent_path) {
      strncpy(grandparent_path, grandparent->exe_path, gp_cap - 1);
      grandparent_path[gp_cap - 1] = '\0';
    }
  }
  if (out_chain_depth) {
    *out_chain_depth = edr_pt_cache_chain_depth(pid);
  }
}

#ifdef _WIN32
static const char *basename_pt(const char *path) {
  if (!path || !path[0]) return "";
  const char *p = path;
  for (const char *c = path; *c; c++) {
    if (*c == '\\' || *c == '/') p = c + 1;
  }
  return p;
}

static void edr_pt_cache_refresh_key_procs(void) {
  (void)memset(g_key_procs, 0, sizeof(g_key_procs));
  for (int i = 0; i < EDR_KEY_PROC_MAX && i < (int)(sizeof(g_key_procs) / sizeof(g_key_procs[0])); i++) {
    g_key_procs[i].valid = 0;
  }
  size_t found = 0;
  for (size_t si = 0; si < PT_HT_CAPACITY && found < EDR_KEY_PROC_MAX; si++) {
    if (!g_pt_table[si].occupied) continue;
    const char *name = g_pt_table[si].entry.process_name;
    if (!name[0]) continue;
    const char *exe_name = basename_pt(g_pt_table[si].entry.exe_path);
    for (int k = 0; k < EDR_KEY_PROC_MAX; k++) {
      if (g_key_procs[k].valid) continue;
#ifdef _MSC_VER
      int match = (_stricmp(name, g_key_proc_names[k]) == 0 ||
                   (exe_name[0] && _stricmp(exe_name, g_key_proc_names[k]) == 0));
#else
      int match = (strcasecmp(name, g_key_proc_names[k]) == 0);
#endif
      if (match) {
        g_key_procs[k].pid = g_pt_table[si].entry.pid;
        g_key_procs[k].ppid = g_pt_table[si].entry.ppid;
        snprintf(g_key_procs[k].name, sizeof(g_key_procs[k].name), "%s", name);
        g_key_procs[k].valid = 1;
        found++;
        break;
      }
    }
  }
}

static int edr_pt_cache_put_raw(uint32_t pid, uint32_t ppid,
                                const wchar_t *process_name_w, const wchar_t *exe_path_w) {
  if (!g_pt_initialized) return -1;
  char name_buf[EDR_PTC_STR_SHORT] = {0};
  char path_buf[EDR_PTC_STR_PATH] = {0};
  if (process_name_w && process_name_w[0]) {
    WideCharToMultiByte(CP_UTF8, 0, process_name_w, -1, name_buf,
                        (int)sizeof(name_buf) - 1, NULL, NULL);
  }
  if (exe_path_w && exe_path_w[0]) {
    WideCharToMultiByte(CP_UTF8, 0, exe_path_w, -1, path_buf,
                        (int)sizeof(path_buf) - 1, NULL, NULL);
  }
  uint64_t now = 0;
  {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    now = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
  }
  return edr_pt_cache_put(pid, ppid, name_buf[0] ? name_buf : NULL,
                          NULL, path_buf[0] ? path_buf : NULL, NULL, now);
}

int edr_pt_cache_warmup(void) {
  if (!g_pt_initialized) return -1;
  int count = 0;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return -1;
  PROCESSENTRY32W pe;
  pe.dwSize = (DWORD)sizeof(pe);
  if (Process32FirstW(snap, &pe)) {
    do {
      uint32_t pid = (uint32_t)pe.th32ProcessID;
      uint32_t ppid = (uint32_t)pe.th32ParentProcessID;
      if (pid != 0) {
        int r = edr_pt_cache_put_raw(pid, ppid, pe.szExeFile, NULL);
        if (r == 0) count++;
      }
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  edr_pt_cache_refresh_key_procs();
  fprintf(stderr, "[pt_cache] 预热完成: %d 进程入缓存, %zu 关键进程已识别\n",
          count, (size_t)EDR_KEY_PROC_MAX);
  for (int k = 0; k < EDR_KEY_PROC_MAX; k++) {
    if (g_key_procs[k].valid) {
      fprintf(stderr, "[pt_cache]   key[%d] %s pid=%u ppid=%u\n",
              k, g_key_procs[k].name, (unsigned)g_key_procs[k].pid,
              (unsigned)g_key_procs[k].ppid);
    }
  }
  return count;
}

void edr_pt_cache_get_key_procs(EdrKeyProcSlot *out, int max) {
  if (!out || max <= 0) return;
  int n = max < EDR_KEY_PROC_MAX ? max : EDR_KEY_PROC_MAX;
  for (int i = 0; i < n; i++) {
    memcpy(&out[i], &g_key_procs[i], sizeof(EdrKeyProcSlot));
  }
}

int edr_pt_cache_find_key_proc(const char *name, uint32_t *out_pid) {
  if (!name || !out_pid) return -1;
  for (int k = 0; k < EDR_KEY_PROC_MAX; k++) {
    if (!g_key_procs[k].valid) continue;
    if (strcmp(g_key_procs[k].name, name) == 0) {
      *out_pid = g_key_procs[k].pid;
      return 0;
    }
  }
  return -1;
}
#else
int edr_pt_cache_warmup(void) { return 0; }
void edr_pt_cache_get_key_procs(EdrKeyProcSlot *out, int max) {
  if (out && max > 0) { (void)memset(out, 0, (size_t)max * sizeof(EdrKeyProcSlot)); }
}
int edr_pt_cache_find_key_proc(const char *name, uint32_t *out_pid) {
  (void)name;
  (void)out_pid;
  return -1;
}
#endif
