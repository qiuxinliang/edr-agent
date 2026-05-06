#include "edr/process_tree_cache.h"

#include <stdio.h>
#include <string.h>

#define PT_HT_CAPACITY 4096u

typedef struct {
  ProcessTreeEntry entry;
  bool occupied;
} PTHashSlot;

static PTHashSlot g_pt_table[PT_HT_CAPACITY];
static uint64_t g_pt_oldest_ns;
static bool g_pt_initialized;

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
