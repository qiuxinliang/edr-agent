#include "edr/process_tree_cache.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>
#else
#include <pthread.h>
#include <strings.h>
#endif

#define PT_HT_CAPACITY 4096u
#define PT_INLINE_CMDLINE_CAP 256u
#define PT_INLINE_PATH_CAP 512u

/* Keep the common short values inline.  Only entries which actually exceed
 * the former capacities allocate an extension, bounded by the public
 * ProcessTreeEntry/BehaviorRecord contract. */
typedef struct {
  uint32_t pid;
  uint32_t ppid;
  uint64_t process_start_key;
  uint64_t creation_filetime_100ns;
  uint64_t start_time_ns;
  uint64_t last_seen_ns;
  uint64_t exit_time_ns;
  char process_name[EDR_PTC_STR_SHORT];
  char cmdline_inline[PT_INLINE_CMDLINE_CAP];
  char exe_path_inline[PT_INLINE_PATH_CAP];
  char parent_name[EDR_PTC_STR_SHORT];
  char *cmdline_extended;
  char *exe_path_extended;
  uint8_t source_truncation_mask;
} PTStoredEntry;

typedef struct {
  PTStoredEntry entry;
  bool occupied;
} PTHashSlot;

static PTHashSlot g_pt_table[PT_HT_CAPACITY];
static uint64_t g_pt_oldest_ns;
static bool g_pt_initialized;
static EdrProcessTreeCacheMetrics g_pt_metrics;

#ifdef _WIN32
static SRWLOCK g_pt_lock = SRWLOCK_INIT;
static void pt_lock(void) { AcquireSRWLockExclusive(&g_pt_lock); }
static void pt_unlock(void) { ReleaseSRWLockExclusive(&g_pt_lock); }
#else
static pthread_mutex_t g_pt_lock = PTHREAD_MUTEX_INITIALIZER;
static void pt_lock(void) { (void)pthread_mutex_lock(&g_pt_lock); }
static void pt_unlock(void) { (void)pthread_mutex_unlock(&g_pt_lock); }
#endif

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

static const char *pt_entry_cmdline(const PTStoredEntry *entry) {
  return entry && entry->cmdline_extended ? entry->cmdline_extended
                                          : (entry ? entry->cmdline_inline : "");
}

static const char *pt_entry_exe_path(const PTStoredEntry *entry) {
  return entry && entry->exe_path_extended ? entry->exe_path_extended
                                           : (entry ? entry->exe_path_inline : "");
}

static void pt_release_entry(PTStoredEntry *entry) {
  if (!entry) return;
  free(entry->cmdline_extended);
  free(entry->exe_path_extended);
  entry->cmdline_extended = NULL;
  entry->exe_path_extended = NULL;
}

static void pt_clear_entry(PTStoredEntry *entry) {
  if (!entry) return;
  pt_release_entry(entry);
  memset(entry, 0, sizeof(*entry));
}

static void pt_clear_table_locked(void) {
  for (size_t i = 0u; i < PT_HT_CAPACITY; ++i) {
    pt_release_entry(&g_pt_table[i].entry);
  }
  memset(g_pt_table, 0, sizeof(g_pt_table));
}

static void pt_store_fact(char *inline_value, size_t inline_cap,
                          char **extended_value, size_t full_cap,
                          uint8_t *truncation_mask, uint8_t field_mask,
                          const char *source, int source_was_truncated) {
  size_t source_len;
  size_t copied;
  char *replacement = NULL;
  if (!inline_value || inline_cap == 0u || !extended_value || full_cap == 0u ||
      !truncation_mask || !source || !source[0]) {
    return;
  }
  source_len = strlen(source);
  if (source_len < inline_cap) {
    free(*extended_value);
    *extended_value = NULL;
    memcpy(inline_value, source, source_len + 1u);
    if (source_was_truncated)
      *truncation_mask |= field_mask;
    else
      *truncation_mask &= (uint8_t)~field_mask;
    return;
  }
  copied = source_len < full_cap ? source_len : full_cap - 1u;
  replacement = (char *)malloc(copied + 1u);
  if (replacement) {
    memcpy(replacement, source, copied);
    replacement[copied] = '\0';
    free(*extended_value);
    *extended_value = replacement;
    inline_value[0] = '\0';
    if (copied == source_len && !source_was_truncated) {
      *truncation_mask &= (uint8_t)~field_mask;
    } else {
      *truncation_mask |= field_mask;
    }
    return;
  }
  /* Allocation pressure must remain observable as a field omission rather
   * than silently turning a complete source into a shorter trusted value. */
  free(*extended_value);
  *extended_value = NULL;
  copied = inline_cap - 1u;
  memcpy(inline_value, source, copied);
  inline_value[copied] = '\0';
  *truncation_mask |= field_mask;
}

static uint64_t pt_wall_ns(void) {
#ifdef _WIN32
  FILETIME ft;
  GetSystemTimeAsFileTime(&ft);
  uint64_t ticks = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
  return ticks > 116444736000000000ULL ? (ticks - 116444736000000000ULL) * 100ULL : 0ULL;
#else
  struct timespec ts;
  if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return 0ULL;
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
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
    pt_clear_entry(&g_pt_table[oldest_i].entry);
    g_pt_table[oldest_i].occupied = false;
    if (g_pt_metrics.entries > 0u) g_pt_metrics.entries--;
    g_pt_metrics.evictions++;
    g_pt_oldest_ns = 0;
    for (size_t i = 0; i < PT_HT_CAPACITY; i++) {
      if (g_pt_table[i].occupied && g_pt_table[i].entry.last_seen_ns > g_pt_oldest_ns) {
        g_pt_oldest_ns = g_pt_table[i].entry.last_seen_ns;
      }
    }
  }
}

void edr_pt_cache_init(void) {
  pt_lock();
  pt_clear_table_locked();
  (void)memset(&g_pt_metrics, 0, sizeof(g_pt_metrics));
  g_pt_oldest_ns = 0;
  g_pt_initialized = true;
  pt_unlock();
}

void edr_pt_cache_shutdown(void) {
  pt_lock();
  pt_clear_table_locked();
  g_pt_oldest_ns = 0;
  g_pt_initialized = false;
  pt_unlock();
}

static int pt_generation_equal(const PTStoredEntry *entry,
                               uint64_t process_start_key,
                               uint64_t creation_filetime_100ns) {
  return entry && entry->process_start_key == process_start_key &&
         entry->creation_filetime_100ns == creation_filetime_100ns;
}

static int pt_creation_birth_unix_ns(uint64_t creation_filetime_100ns,
                                     uint64_t *out) {
  const uint64_t epoch = UINT64_C(116444736000000000);
  if (!out || creation_filetime_100ns <= epoch ||
      creation_filetime_100ns - epoch > UINT64_MAX / 100u) {
    return 0;
  }
  *out = (creation_filetime_100ns - epoch) * 100u;
  return *out != 0u;
}

/* Exact generations form non-overlapping PID-lifetime intervals.  This is
 * called only for a newly inserted generation: one scan finds its next birth,
 * and one scan closes older overlapping occupants at this birth. */
static void pt_bound_new_exact_interval_locked(size_t new_index) {
  PTStoredEntry *inserted = &g_pt_table[new_index].entry;
  uint64_t next_birth = 0u;
  for (size_t i = 0u; i < PT_HT_CAPACITY; ++i) {
    const PTStoredEntry *other = &g_pt_table[i].entry;
    if (i == new_index || !g_pt_table[i].occupied ||
        other->pid != inserted->pid || other->process_start_key == 0u ||
        other->creation_filetime_100ns == 0u ||
        other->start_time_ns <= inserted->start_time_ns) {
      continue;
    }
    if (next_birth == 0u || other->start_time_ns < next_birth) {
      next_birth = other->start_time_ns;
    }
  }
  if (next_birth != 0u &&
      (inserted->exit_time_ns == 0u || inserted->exit_time_ns > next_birth)) {
    inserted->exit_time_ns = next_birth;
  }
  for (size_t i = 0u; i < PT_HT_CAPACITY; ++i) {
    PTStoredEntry *older = &g_pt_table[i].entry;
    if (i == new_index || !g_pt_table[i].occupied ||
        older->pid != inserted->pid || older->process_start_key == 0u ||
        older->creation_filetime_100ns == 0u ||
        older->start_time_ns >= inserted->start_time_ns) {
      continue;
    }
    if (older->exit_time_ns == 0u ||
        older->exit_time_ns > inserted->start_time_ns) {
      older->exit_time_ns = inserted->start_time_ns;
    }
  }
}

static const PTStoredEntry *pt_get_latest_locked(uint32_t pid) {
  const PTStoredEntry *best = NULL;
  if (!g_pt_initialized) return NULL;
  for (size_t i = 0u; i < PT_HT_CAPACITY; ++i) {
    const PTStoredEntry *entry = &g_pt_table[i].entry;
    if (!g_pt_table[i].occupied || entry->pid != pid) continue;
    if (!best ||
        (best->exit_time_ns != 0u && entry->exit_time_ns == 0u) ||
        (best->exit_time_ns == entry->exit_time_ns &&
         (entry->start_time_ns > best->start_time_ns ||
          (entry->start_time_ns == best->start_time_ns &&
           entry->last_seen_ns > best->last_seen_ns)))) {
      best = entry;
    }
  }
  return best;
}

static int pt_entry_matches_event_time(const PTStoredEntry *entry,
                                       uint64_t event_time_ns, uint64_t now_ns) {
  if (!entry) return 0;
  if (entry->exit_time_ns != 0u && now_ns != 0u &&
      now_ns > entry->exit_time_ns + EDR_PTC_EXIT_GRACE_NS) {
    return 0;
  }
  if (event_time_ns == 0u) return entry->exit_time_ns == 0u;
  if (entry->start_time_ns != 0u && event_time_ns < entry->start_time_ns) return 0;
  if (entry->exit_time_ns != 0u && event_time_ns > entry->exit_time_ns) return 0;
  return 1;
}

/* Select the one PID generation whose source-time interval contains the
 * event.  Old and new generations intentionally coexist: a delayed child
 * that predates PID reuse must see A, not the later B entry. */
static const PTStoredEntry *pt_get_at_locked(uint32_t pid, uint64_t event_time_ns,
                                             uint64_t process_start_key,
                                             int *out_had_pid) {
  const PTStoredEntry *best = NULL;
  uint64_t now_ns = pt_wall_ns();
  int had_pid = 0;
  for (size_t i = 0u; i < PT_HT_CAPACITY; ++i) {
    const PTStoredEntry *entry = &g_pt_table[i].entry;
    if (!g_pt_table[i].occupied || entry->pid != pid) continue;
    had_pid = 1;
    if (process_start_key && entry->process_start_key != process_start_key) continue;
    /* A delayed exact-key observation is not a fresh PID-only inference.
     * Still validate birth/exit, but never discard its retained identity just
     * because queue processing took longer than the inference grace period. */
    if (!pt_entry_matches_event_time(entry, event_time_ns,
                                      process_start_key ? 0u : now_ns)) continue;
    if (!best || entry->start_time_ns > best->start_time_ns ||
        (entry->start_time_ns == best->start_time_ns &&
         entry->last_seen_ns > best->last_seen_ns)) {
      best = entry;
    }
  }
  if (out_had_pid) *out_had_pid = had_pid;
  return best;
}

static int pt_put_locked(uint32_t pid, uint32_t ppid,
                         const char *process_name, const char *cmdline,
                         const char *exe_path, const char *parent_name,
                         uint64_t birth_time_ns, uint64_t observation_time_ns,
                         uint64_t process_start_key,
                         uint64_t creation_filetime_100ns,
                         uint8_t source_truncation_mask) {
  if (!g_pt_initialized) return -1;
  if ((process_start_key == 0u) != (creation_filetime_100ns == 0u)) return -1;
  size_t idx = pt_hash(pid);
  size_t target = PT_HT_CAPACITY;
  for (size_t i = 0; i < PT_HT_CAPACITY; i++) {
    size_t probe = (idx + i) % PT_HT_CAPACITY;
    const PTStoredEntry *entry = &g_pt_table[probe].entry;
    if (g_pt_table[probe].occupied && entry->pid == pid) {
      if (pt_generation_equal(entry, process_start_key, creation_filetime_100ns)) {
        target = probe;
        break;
      }
    }
    if (!g_pt_table[probe].occupied && target == PT_HT_CAPACITY) {
      target = probe;
    }
  }
  if (target == PT_HT_CAPACITY) {
    pt_evict_lru();
    return pt_put_locked(pid, ppid, process_name, cmdline, exe_path, parent_name,
                         birth_time_ns, observation_time_ns, process_start_key,
                         creation_filetime_100ns, source_truncation_mask);
  }
  bool was_occupied = g_pt_table[target].occupied;
  PTStoredEntry *e = &g_pt_table[target].entry;
  const int exact_generation = process_start_key != 0u &&
                               creation_filetime_100ns != 0u;
  if (was_occupied && !exact_generation && birth_time_ns != 0u &&
      e->start_time_ns != 0u &&
      birth_time_ns < e->start_time_ns) {
    g_pt_metrics.put_time_rejects++;
    return -2;
  }
  if (was_occupied) {
    g_pt_metrics.updates++;
  } else {
    g_pt_metrics.puts++;
    g_pt_metrics.entries++;
  }
  if (!was_occupied) {
    pt_clear_entry(e);
    e->pid = pid;
    e->ppid = ppid;
    e->process_start_key = process_start_key;
    e->creation_filetime_100ns = creation_filetime_100ns;
    e->start_time_ns = birth_time_ns;
    e->last_seen_ns = observation_time_ns != 0u ? observation_time_ns
                                                : birth_time_ns;
  } else if (exact_generation) {
    /* Once exact generation birth/exit is present, later metadata may update
     * observation recency but must neither move birth nor resurrect exit. */
    if (ppid != 0u) e->ppid = ppid;
    if (observation_time_ns > e->last_seen_ns)
      e->last_seen_ns = observation_time_ns;
  } else {
    e->pid = pid;
    e->ppid = ppid;
    e->start_time_ns = birth_time_ns;
    e->last_seen_ns = observation_time_ns;
    e->exit_time_ns = 0u;
  }
  if (process_name && process_name[0])
    snprintf(e->process_name, sizeof(e->process_name), "%s", process_name);
  if (cmdline && cmdline[0])
    pt_store_fact(e->cmdline_inline, sizeof(e->cmdline_inline),
                  &e->cmdline_extended, EDR_PTC_STR_LONG,
                  &e->source_truncation_mask, EDR_PTC_SOURCE_TRUNC_CMDLINE,
                  cmdline,
                  (source_truncation_mask & EDR_PTC_SOURCE_TRUNC_CMDLINE) != 0u);
  if (exe_path && exe_path[0])
    pt_store_fact(e->exe_path_inline, sizeof(e->exe_path_inline),
                  &e->exe_path_extended, EDR_PTC_STR_PATH,
                  &e->source_truncation_mask, EDR_PTC_SOURCE_TRUNC_EXE_PATH,
                  exe_path,
                  (source_truncation_mask & EDR_PTC_SOURCE_TRUNC_EXE_PATH) != 0u);
  if (parent_name && parent_name[0])
    snprintf(e->parent_name, sizeof(e->parent_name), "%s", parent_name);
  g_pt_table[target].occupied = true;
  if (exact_generation && !was_occupied)
    pt_bound_new_exact_interval_locked(target);
  if (e->last_seen_ns > g_pt_oldest_ns || g_pt_oldest_ns == 0) {
    g_pt_oldest_ns = e->last_seen_ns;
  }
  return 0;
}

int edr_pt_cache_put(uint32_t pid, uint32_t ppid,
                     const char *process_name, const char *cmdline,
                     const char *exe_path, const char *parent_name,
                     uint64_t start_time_ns) {
  pt_lock();
  int rc = pt_put_locked(pid, ppid, process_name, cmdline, exe_path, parent_name,
                         start_time_ns, start_time_ns, 0u, 0u, 0u);
  pt_unlock();
  return rc;
}

int edr_pt_cache_put_generation(uint32_t pid, uint32_t ppid,
                                const char *process_name, const char *cmdline,
                                const char *exe_path, const char *parent_name,
                                uint64_t observation_time_ns,
                                uint64_t process_start_key,
                                uint64_t creation_filetime_100ns) {
  return edr_pt_cache_put_generation_with_provenance(
      pid, ppid, process_name, cmdline, exe_path, parent_name,
      observation_time_ns, process_start_key, creation_filetime_100ns, 0u);
}

int edr_pt_cache_put_generation_with_provenance(
    uint32_t pid, uint32_t ppid,
    const char *process_name, const char *cmdline,
    const char *exe_path, const char *parent_name,
    uint64_t observation_time_ns,
    uint64_t process_start_key,
    uint64_t creation_filetime_100ns,
    uint8_t source_truncation_mask) {
  int rc;
  uint64_t birth_time_ns;
  if (!pid || !process_start_key || !creation_filetime_100ns) return -1;
  if (!pt_creation_birth_unix_ns(creation_filetime_100ns, &birth_time_ns))
    return -1;
  pt_lock();
  rc = pt_put_locked(pid, ppid, process_name, cmdline, exe_path, parent_name,
                     birth_time_ns, observation_time_ns, process_start_key,
                     creation_filetime_100ns, source_truncation_mask);
  pt_unlock();
  return rc;
}

const ProcessTreeEntry *edr_pt_cache_get(uint32_t pid) {
#ifdef _MSC_VER
  static __declspec(thread) ProcessTreeEntry snapshot;
#else
  static __thread ProcessTreeEntry snapshot;
#endif
  return edr_pt_cache_snapshot(pid, &snapshot) == 0 ? &snapshot : NULL;
}

static int pt_snapshot_locked(uint32_t pid, uint64_t event_time_ns,
                              uint64_t process_start_key,
                              bool validate_time, ProcessTreeEntry *out) {
  const PTStoredEntry *entry;
  int had_pid = 0;
  if (validate_time) {
    entry = pt_get_at_locked(pid, event_time_ns, process_start_key, &had_pid);
  } else {
    entry = pt_get_latest_locked(pid);
    had_pid = entry != NULL;
  }
  if (!entry) {
    memset(out, 0, sizeof(*out));
    if (validate_time && had_pid) {
      g_pt_metrics.snapshot_time_rejects++;
      return -2;
    }
    g_pt_metrics.snapshot_misses++;
    return -1;
  }
  memset(out, 0, sizeof(*out));
  out->pid = entry->pid;
  out->ppid = entry->ppid;
  out->process_start_key = entry->process_start_key;
  out->creation_filetime_100ns = entry->creation_filetime_100ns;
  out->start_time_ns = entry->start_time_ns;
  out->last_seen_ns = entry->last_seen_ns;
  out->exit_time_ns = entry->exit_time_ns;
  snprintf(out->process_name, sizeof(out->process_name), "%s", entry->process_name);
  snprintf(out->cmdline, sizeof(out->cmdline), "%s", pt_entry_cmdline(entry));
  snprintf(out->exe_path, sizeof(out->exe_path), "%s", pt_entry_exe_path(entry));
  snprintf(out->parent_name, sizeof(out->parent_name), "%s", entry->parent_name);
  out->source_truncation_mask = entry->source_truncation_mask;
  g_pt_metrics.snapshot_hits++;
  return 0;
}

int edr_pt_cache_snapshot(uint32_t pid, ProcessTreeEntry *out) {
  if (!out) return -1;
  pt_lock();
  int rc = pt_snapshot_locked(pid, 0u, 0u, false, out);
  pt_unlock();
  return rc;
}

int edr_pt_cache_snapshot_at(uint32_t pid, uint64_t event_time_ns, ProcessTreeEntry *out) {
  if (!out) return -1;
  pt_lock();
  int rc = pt_snapshot_locked(pid, event_time_ns, 0u, true, out);
  pt_unlock();
  return rc;
}

int edr_pt_cache_snapshot_generation_at(uint32_t pid, uint64_t process_start_key,
                                        uint64_t event_time_ns, ProcessTreeEntry *out) {
  if (!out) return -1;
  if (!pid || !process_start_key || !event_time_ns) {
    memset(out, 0, sizeof(*out));
    return -1;
  }
  pt_lock();
  int rc = pt_snapshot_locked(pid, event_time_ns, process_start_key, true, out);
  pt_unlock();
  return rc;
}

int edr_pt_cache_mark_exit(uint32_t pid, uint64_t exit_time_ns) {
  int rc = -1;
  pt_lock();
  PTStoredEntry *entry = (PTStoredEntry *)(void *)pt_get_latest_locked(pid);
  if (entry) {
    if (exit_time_ns == 0u) exit_time_ns = pt_wall_ns();
    if (entry->start_time_ns == 0u || exit_time_ns >= entry->start_time_ns) {
      entry->exit_time_ns = exit_time_ns;
      entry->last_seen_ns = exit_time_ns;
      g_pt_metrics.exits_marked++;
      rc = 0;
    }
  }
  pt_unlock();
  return rc;
}

int edr_pt_cache_mark_exit_generation(uint32_t pid, uint64_t process_start_key,
                                      uint64_t exit_time_ns) {
  int rc = -1;
  if (!pid || !process_start_key) return -1;
  pt_lock();
  for (size_t i = 0u; i < PT_HT_CAPACITY; ++i) {
    PTStoredEntry *entry = &g_pt_table[i].entry;
    if (!g_pt_table[i].occupied || entry->pid != pid ||
        entry->process_start_key != process_start_key) {
      continue;
    }
    if (exit_time_ns == 0u) exit_time_ns = pt_wall_ns();
    if (entry->start_time_ns == 0u || exit_time_ns >= entry->start_time_ns) {
      entry->exit_time_ns = exit_time_ns;
      entry->last_seen_ns = exit_time_ns;
      g_pt_metrics.exits_marked++;
      rc = 0;
    }
    break;
  }
  pt_unlock();
  return rc;
}

int edr_pt_cache_remove(uint32_t pid) {
  int rc = -1;
  pt_lock();
  if (g_pt_initialized) {
    for (size_t i = 0u; i < PT_HT_CAPACITY; ++i) {
      if (g_pt_table[i].occupied && g_pt_table[i].entry.pid == pid) {
        pt_clear_entry(&g_pt_table[i].entry);
        g_pt_table[i].occupied = false;
        if (g_pt_metrics.entries > 0u) g_pt_metrics.entries--;
        rc = 0;
      }
    }
  }
  pt_unlock();
  return rc;
}

static uint32_t pt_chain_depth_locked(uint32_t pid) {
  uint32_t depth = 0;
  uint32_t cur = pid;
  for (int hop = 0; hop < 32; hop++) {
    const PTStoredEntry *e = pt_get_latest_locked(cur);
    if (!e || e->ppid == 0 || e->ppid == cur) {
      depth++;
      break;
    }
    depth++;
    cur = e->ppid;
  }
  return depth;
}

static uint32_t pt_chain_depth_at_locked(uint32_t pid, uint64_t event_time_ns) {
  uint32_t depth = 0u;
  uint32_t cur = pid;
  for (int hop = 0; hop < 32; ++hop) {
    const PTStoredEntry *entry = pt_get_at_locked(cur, event_time_ns, 0u, NULL);
    if (!entry || entry->ppid == 0u || entry->ppid == cur) {
      depth++;
      break;
    }
    depth++;
    cur = entry->ppid;
  }
  return depth;
}

uint32_t edr_pt_cache_chain_depth(uint32_t pid) {
  pt_lock();
  uint32_t depth = pt_chain_depth_locked(pid);
  pt_unlock();
  return depth;
}

static void pt_fill_record_locked(uint32_t pid, uint64_t event_time_ns,
                                  int use_event_time,
                                  char *grandparent_name, size_t gn_cap,
                                  char *grandparent_path, size_t gp_cap,
                                  uint32_t *out_grandparent_pid,
                                  char *parent_cmdline, size_t pc_cap,
                                  uint32_t *out_chain_depth,
                                  uint8_t *out_source_truncation_mask) {
  const PTStoredEntry *self;
  const PTStoredEntry *parent;
  const PTStoredEntry *grandparent;
  self = use_event_time ? pt_get_at_locked(pid, event_time_ns, 0u, NULL)
                        : pt_get_latest_locked(pid);
  if (!self) return;
  if (self->ppid == 0u || self->ppid == pid) {
    if (out_chain_depth) *out_chain_depth = 1u;
    return;
  }
  parent = use_event_time ? pt_get_at_locked(self->ppid, event_time_ns, 0u, NULL)
                          : pt_get_latest_locked(self->ppid);
  if (parent && parent_cmdline && pt_entry_cmdline(parent)[0] && pc_cap > 0u) {
    const char *value = pt_entry_cmdline(parent);
    const size_t length = strlen(value);
    strncpy(parent_cmdline, value, pc_cap - 1u);
    parent_cmdline[pc_cap - 1u] = '\0';
    if (out_source_truncation_mask &&
        (length >= pc_cap ||
         (parent->source_truncation_mask & EDR_PTC_SOURCE_TRUNC_CMDLINE) != 0u)) {
      *out_source_truncation_mask |= EDR_PTC_RECORD_TRUNC_PARENT_CMDLINE;
    }
  }
  if (!parent || parent->ppid == 0u || parent->ppid == self->ppid) {
    if (out_chain_depth) *out_chain_depth = parent ? 2u : 1u;
    return;
  }
  grandparent = use_event_time ? pt_get_at_locked(parent->ppid, event_time_ns, 0u, NULL)
                               : pt_get_latest_locked(parent->ppid);
  if (grandparent) {
    if (out_grandparent_pid) *out_grandparent_pid = grandparent->pid;
    if (grandparent_name && gn_cap > 0u) {
      strncpy(grandparent_name, grandparent->process_name, gn_cap - 1u);
      grandparent_name[gn_cap - 1u] = '\0';
    }
    if (grandparent_path && gp_cap > 0u) {
      const char *value = pt_entry_exe_path(grandparent);
      const size_t length = strlen(value);
      strncpy(grandparent_path, value, gp_cap - 1u);
      grandparent_path[gp_cap - 1u] = '\0';
      if (out_source_truncation_mask &&
          (length >= gp_cap ||
           (grandparent->source_truncation_mask & EDR_PTC_SOURCE_TRUNC_EXE_PATH) != 0u)) {
        *out_source_truncation_mask |= EDR_PTC_RECORD_TRUNC_GRANDPARENT_PATH;
      }
    }
  }
  if (out_chain_depth) {
    *out_chain_depth = use_event_time ? pt_chain_depth_at_locked(pid, event_time_ns)
                                      : pt_chain_depth_locked(pid);
  }
}

static void pt_clear_record_fields(char *grandparent_name, size_t gn_cap,
                                   char *grandparent_path, size_t gp_cap,
                                   uint32_t *out_grandparent_pid,
                                   char *parent_cmdline, size_t pc_cap,
                                   uint32_t *out_chain_depth,
                                   uint8_t *out_source_truncation_mask) {
  if (grandparent_name) grandparent_name[0] = '\0';
  if (grandparent_path) grandparent_path[0] = '\0';
  if (out_grandparent_pid) *out_grandparent_pid = 0;
  if (parent_cmdline)  parent_cmdline[0] = '\0';
  if (out_chain_depth) *out_chain_depth = 0;
  if (out_source_truncation_mask) *out_source_truncation_mask = 0u;
  (void)gn_cap;
  (void)gp_cap;
  (void)pc_cap;
}

void edr_pt_cache_fill_record(uint32_t pid,
                              char *grandparent_name, size_t gn_cap,
                              char *grandparent_path, size_t gp_cap,
                              uint32_t *out_grandparent_pid,
                              char *parent_cmdline, size_t pc_cap,
                              uint32_t *out_chain_depth) {
  pt_clear_record_fields(grandparent_name, gn_cap, grandparent_path, gp_cap,
                         out_grandparent_pid, parent_cmdline, pc_cap,
                         out_chain_depth, NULL);
  pt_lock();
  pt_fill_record_locked(pid, 0u, 0, grandparent_name, gn_cap, grandparent_path,
                        gp_cap, out_grandparent_pid, parent_cmdline, pc_cap,
                        out_chain_depth, NULL);
  pt_unlock();
}

void edr_pt_cache_fill_record_at(uint32_t pid, uint64_t event_time_ns,
                                 char *grandparent_name, size_t gn_cap,
                                 char *grandparent_path, size_t gp_cap,
                                 uint32_t *out_grandparent_pid,
                                 char *parent_cmdline, size_t pc_cap,
                                 uint32_t *out_chain_depth) {
  edr_pt_cache_fill_record_at_with_provenance(
      pid, event_time_ns, grandparent_name, gn_cap, grandparent_path, gp_cap,
      out_grandparent_pid, parent_cmdline, pc_cap, out_chain_depth, NULL);
}

void edr_pt_cache_fill_record_at_with_provenance(
    uint32_t pid, uint64_t event_time_ns,
    char *grandparent_name, size_t gn_cap,
    char *grandparent_path, size_t gp_cap,
    uint32_t *out_grandparent_pid,
    char *parent_cmdline, size_t pc_cap,
    uint32_t *out_chain_depth,
    uint8_t *out_source_truncation_mask) {
  pt_clear_record_fields(grandparent_name, gn_cap, grandparent_path, gp_cap,
                         out_grandparent_pid, parent_cmdline, pc_cap,
                         out_chain_depth, out_source_truncation_mask);
  pt_lock();
  pt_fill_record_locked(pid, event_time_ns, 1, grandparent_name, gn_cap,
                        grandparent_path, gp_cap, out_grandparent_pid,
                        parent_cmdline, pc_cap, out_chain_depth,
                        out_source_truncation_mask);
  pt_unlock();
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
    const char *exe_name = basename_pt(pt_entry_exe_path(&g_pt_table[si].entry));
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
  /* Toolhelp exposes only a PID/PPID/name snapshot.  Wall-clock observation
   * is not the process creation generation and must never be used as one. */
  return edr_pt_cache_put(pid, ppid, name_buf[0] ? name_buf : NULL,
                          NULL, path_buf[0] ? path_buf : NULL, NULL, 0u);
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
  pt_lock();
  edr_pt_cache_refresh_key_procs();
  EdrKeyProcSlot key_snapshot[EDR_KEY_PROC_MAX];
  memcpy(key_snapshot, g_key_procs, sizeof(key_snapshot));
  pt_unlock();
  fprintf(stderr, "[pt_cache] warmup complete: cached=%d key_procs=%zu\n",
          count, (size_t)EDR_KEY_PROC_MAX);
  for (int k = 0; k < EDR_KEY_PROC_MAX; k++) {
    if (key_snapshot[k].valid) {
      fprintf(stderr, "[pt_cache]   key[%d] %s pid=%u ppid=%u\n",
              k, key_snapshot[k].name, (unsigned)key_snapshot[k].pid,
              (unsigned)key_snapshot[k].ppid);
    }
  }
  return count;
}

void edr_pt_cache_get_key_procs(EdrKeyProcSlot *out, int max) {
  if (!out || max <= 0) return;
  int n = max < EDR_KEY_PROC_MAX ? max : EDR_KEY_PROC_MAX;
  pt_lock();
  for (int i = 0; i < n; i++) {
    memcpy(&out[i], &g_key_procs[i], sizeof(EdrKeyProcSlot));
  }
  pt_unlock();
}

int edr_pt_cache_find_key_proc(const char *name, uint32_t *out_pid) {
  if (!name || !out_pid) return -1;
  int rc = -1;
  pt_lock();
  for (int k = 0; k < EDR_KEY_PROC_MAX; k++) {
    if (!g_key_procs[k].valid) continue;
    if (strcmp(g_key_procs[k].name, name) == 0) {
      *out_pid = g_key_procs[k].pid;
      rc = 0;
      break;
    }
  }
  pt_unlock();
  return rc;
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

/* stub: PPID 推断预案未实现 */
void edr_pt_cache_get_metrics(EdrProcessTreeCacheMetrics *out) {
  if (!out) return;
  pt_lock();
  *out = g_pt_metrics;
  pt_unlock();
}

int edr_pt_cache_infer_parent(uint32_t pid, uint64_t event_time_ns,
                              uint32_t *out_ppid, char *out_parent_name,
                              size_t name_cap) {
  (void)pid;
  (void)event_time_ns;
  (void)out_ppid;
  (void)out_parent_name;
  (void)name_cap;
  return -1;
}
