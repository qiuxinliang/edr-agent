#include "edr/adaptive_collection.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#define EDR_ADAPTIVE_PID_CACHE 96u
#define EDR_ADAPTIVE_BUDGET_WINDOW_MS 60000ULL
#define EDR_ADAPTIVE_DEFAULT_ADMIT_BUDGET_PER_MIN 1200L
#define EDR_ADAPTIVE_DEFAULT_SCRIPT_BUDGET_PER_MIN 240L

typedef struct {
  uint32_t pid;
  uint64_t until_ms;
  char process_name[128];
} EdrAdaptivePidEntry;

static volatile long s_enabled = 1;
static volatile long s_ttl_s = 180;
static volatile long s_min_severity = 3;
static volatile long s_level;
static volatile uint64_t s_until_ms;
static volatile uint64_t s_boosts;
static volatile uint64_t s_last_boost_unix_ms;
static volatile uint64_t s_budget_window_ms;
static volatile uint64_t s_budget_used;
static volatile uint64_t s_script_budget_used;
static volatile long s_admit_budget_per_min = EDR_ADAPTIVE_DEFAULT_ADMIT_BUDGET_PER_MIN;
static volatile long s_script_budget_per_min = EDR_ADAPTIVE_DEFAULT_SCRIPT_BUDGET_PER_MIN;
static EdrAdaptivePidEntry s_pid_cache[EDR_ADAPTIVE_PID_CACHE];
static volatile uint32_t s_pid_next;
static char s_last_rule_id[64];

/* Sensor-interest matching must never run against a prefix that looks like a
 * complete record value. */
static int adaptive_copy_cstr_exact(char *out, size_t out_cap, const char *source,
                                    size_t source_cap) {
  const char *end;
  size_t length;
  if (!out || out_cap == 0u || !source || source_cap == 0u) {
    return 0;
  }
  end = (const char *)memchr(source, '\0', source_cap);
  if (!end) {
    return 0;
  }
  length = (size_t)(end - source);
  if (length >= out_cap) {
    return 0;
  }
  memcpy(out, source, length + 1u);
  return 1;
}

static int adaptive_env_bool(const char *name, int fallback) {
  const char *v = getenv(name);
  if (!v || !v[0]) {
    return fallback;
  }
  return !(v[0] == '0' || v[0] == 'n' || v[0] == 'N' || v[0] == 'f' || v[0] == 'F');
}

static long adaptive_env_long(const char *name, long fallback, long minv, long maxv) {
  const char *v = getenv(name);
  long out = fallback;
  if (v && v[0]) {
    out = strtol(v, NULL, 10);
  }
  if (out < minv) {
    out = minv;
  }
  if (out > maxv) {
    out = maxv;
  }
  return out;
}

static uint64_t adaptive_monotonic_ms(void) {
#if defined(_WIN32)
  return (uint64_t)GetTickCount64();
#else
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
#endif
}

static uint64_t adaptive_unix_ms(void) {
#if defined(_WIN32)
  FILETIME ft;
  ULARGE_INTEGER u;
  GetSystemTimeAsFileTime(&ft);
  u.LowPart = ft.dwLowDateTime;
  u.HighPart = ft.dwHighDateTime;
  if (u.QuadPart < 116444736000000000ULL) {
    return 0;
  }
  return (u.QuadPart - 116444736000000000ULL) / 10000ULL;
#else
  struct timespec ts;
  if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
#endif
}

static uint64_t adaptive_load64(volatile uint64_t *p) {
#if defined(_WIN32)
  return (uint64_t)InterlockedCompareExchange64((volatile LONG64 *)p, 0, 0);
#elif defined(__GNUC__) || defined(__clang__)
  return __atomic_load_n(p, __ATOMIC_RELAXED);
#else
  return *p;
#endif
}

static void adaptive_store64(volatile uint64_t *p, uint64_t v) {
#if defined(_WIN32)
  (void)InterlockedExchange64((volatile LONG64 *)p, (LONG64)v);
#elif defined(__GNUC__) || defined(__clang__)
  __atomic_store_n(p, v, __ATOMIC_RELAXED);
#else
  *p = v;
#endif
}

static uint64_t adaptive_inc64(volatile uint64_t *p) {
#if defined(_WIN32)
  return (uint64_t)InterlockedIncrement64((volatile LONG64 *)p);
#elif defined(__GNUC__) || defined(__clang__)
  return __atomic_add_fetch(p, 1, __ATOMIC_RELAXED);
#else
  return ++(*p);
#endif
}

static uint64_t adaptive_exchange64(volatile uint64_t *p, uint64_t v) {
#if defined(_WIN32)
  return (uint64_t)InterlockedExchange64((volatile LONG64 *)p, (LONG64)v);
#elif defined(__GNUC__) || defined(__clang__)
  return __atomic_exchange_n(p, v, __ATOMIC_RELAXED);
#else
  uint64_t old = *p;
  *p = v;
  return old;
#endif
}

static long adaptive_load_long(volatile long *p) {
#if defined(_WIN32)
  return InterlockedCompareExchange(p, 0, 0);
#elif defined(__GNUC__) || defined(__clang__)
  return __atomic_load_n(p, __ATOMIC_RELAXED);
#else
  return *p;
#endif
}

static void adaptive_store_long(volatile long *p, long v) {
#if defined(_WIN32)
  (void)InterlockedExchange(p, v);
#elif defined(__GNUC__) || defined(__clang__)
  __atomic_store_n(p, v, __ATOMIC_RELAXED);
#else
  *p = v;
#endif
}

static uint32_t adaptive_next_pid_slot(void) {
#if defined(_WIN32)
  return (uint32_t)InterlockedIncrement((volatile LONG *)&s_pid_next);
#elif defined(__GNUC__) || defined(__clang__)
  return __atomic_add_fetch(&s_pid_next, 1u, __ATOMIC_RELAXED);
#else
  return ++s_pid_next;
#endif
}

static int adaptive_contains_ci(const char *s, const char *needle) {
  size_t n;
  if (!s || !needle || !needle[0]) {
    return 0;
  }
  n = strlen(needle);
  for (; *s; s++) {
    size_t i = 0u;
    while (i < n && s[i]) {
      char a = s[i], b = needle[i];
      if (a >= 'A' && a <= 'Z') {
        a = (char)(a - 'A' + 'a');
      }
      if (b >= 'A' && b <= 'Z') {
        b = (char)(b - 'A' + 'a');
      }
      if (a != b) {
        break;
      }
      i++;
    }
    if (i == n) {
      return 1;
    }
  }
  return 0;
}

static int adaptive_process_interesting(const char *name) {
  static const char *items[] = {
      "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
      "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe",
      "psexec.exe", "psexesvc.exe", "curl.exe", "wget.exe", "rclone.exe", "ngrok.exe",
      "frpc.exe", "chisel.exe", "plink.exe", "anydesk.exe", "teamviewer.exe",
  };
  if (!name || !name[0]) {
    return 0;
  }
  for (size_t i = 0; i < sizeof(items) / sizeof(items[0]); i++) {
    if (adaptive_contains_ci(name, items[i])) {
      return 1;
    }
  }
  return 0;
}

static int adaptive_remote_admin_port(uint32_t port) {
  switch (port) {
    case 22:
    case 135:
    case 139:
    case 445:
    case 3389:
    case 5985:
    case 5986:
    case 47001:
      return 1;
    default:
      return 0;
  }
}

static int adaptive_event_is_script(EdrEventType type) {
  return type == EDR_EVENT_SCRIPT_POWERSHELL || type == EDR_EVENT_SCRIPT_WMI;
}

static int adaptive_budget_allow(EdrEventType type, uint64_t now_ms) {
  long limit = adaptive_load_long(&s_admit_budget_per_min);
  long script_limit = adaptive_load_long(&s_script_budget_per_min);
  uint64_t window = adaptive_load64(&s_budget_window_ms);
  uint64_t used;
  if (limit <= 0) {
    return 1;
  }
  if (window == 0u || now_ms < window || now_ms - window >= EDR_ADAPTIVE_BUDGET_WINDOW_MS) {
    adaptive_store64(&s_budget_window_ms, now_ms);
    adaptive_exchange64(&s_budget_used, 0u);
    adaptive_exchange64(&s_script_budget_used, 0u);
  }
  if (adaptive_event_is_script(type) && script_limit > 0) {
    used = adaptive_inc64(&s_script_budget_used);
    if (used > (uint64_t)script_limit) {
      return 0;
    }
  }
  used = adaptive_inc64(&s_budget_used);
  return used <= (uint64_t)limit;
}

static int adaptive_pid_boosted(uint32_t pid, uint64_t now_ms) {
  if (pid == 0u) {
    return 0;
  }
  for (size_t i = 0; i < EDR_ADAPTIVE_PID_CACHE; i++) {
    if (s_pid_cache[i].pid != pid) {
      continue;
    }
    if (now_ms <= s_pid_cache[i].until_ms) {
      return 1;
    }
    s_pid_cache[i].pid = 0u;
    s_pid_cache[i].until_ms = 0u;
    s_pid_cache[i].process_name[0] = '\0';
    return 0;
  }
  return 0;
}

static void adaptive_mark_pid(uint32_t pid, const char *process_name, uint64_t until_ms) {
  if (pid == 0u) {
    return;
  }
  for (size_t i = 0; i < EDR_ADAPTIVE_PID_CACHE; i++) {
    if (s_pid_cache[i].pid == pid) {
      s_pid_cache[i].until_ms = until_ms;
      if (process_name && process_name[0]) {
        snprintf(s_pid_cache[i].process_name, sizeof(s_pid_cache[i].process_name), "%s", process_name);
      }
      return;
    }
  }
  uint32_t idx = adaptive_next_pid_slot() % EDR_ADAPTIVE_PID_CACHE;
  s_pid_cache[idx].pid = pid;
  s_pid_cache[idx].until_ms = until_ms;
  snprintf(s_pid_cache[idx].process_name, sizeof(s_pid_cache[idx].process_name), "%s",
           process_name ? process_name : "");
}

void edr_adaptive_collection_configure(const EdrConfig *cfg) {
  long enabled = 1;
  long ttl = 180;
  long minsev = 3;
  if (cfg) {
    enabled = cfg->collection.adaptive_enabled ? 1 : 0;
    ttl = (long)cfg->collection.adaptive_boost_seconds;
    minsev = (long)cfg->collection.adaptive_min_severity;
  }
  enabled = adaptive_env_bool("EDR_ADAPTIVE_COLLECTION", (int)enabled) ? 1 : 0;
  ttl = adaptive_env_long("EDR_ADAPTIVE_COLLECTION_TTL_S", ttl, 30, 1800);
  minsev = adaptive_env_long("EDR_ADAPTIVE_COLLECTION_MIN_SEVERITY", minsev, 1, 5);
  adaptive_store_long(&s_admit_budget_per_min,
                      adaptive_env_long("EDR_ADAPTIVE_COLLECTION_ADMIT_BUDGET_PER_MIN",
                                        EDR_ADAPTIVE_DEFAULT_ADMIT_BUDGET_PER_MIN, 0, 100000));
  adaptive_store_long(&s_script_budget_per_min,
                      adaptive_env_long("EDR_ADAPTIVE_COLLECTION_SCRIPT_BUDGET_PER_MIN",
                                        EDR_ADAPTIVE_DEFAULT_SCRIPT_BUDGET_PER_MIN, 0, 100000));
  adaptive_store64(&s_budget_window_ms, 0u);
  adaptive_exchange64(&s_budget_used, 0u);
  adaptive_exchange64(&s_script_budget_used, 0u);
  adaptive_store_long(&s_enabled, enabled);
  adaptive_store_long(&s_ttl_s, ttl);
  adaptive_store_long(&s_min_severity, minsev);
}

void edr_adaptive_collection_raise(int severity, const char *rule_id, uint32_t pid,
                                   uint32_t parent_pid, const char *process_name) {
  if (!adaptive_load_long(&s_enabled) || severity < adaptive_load_long(&s_min_severity)) {
    return;
  }
  uint64_t now = adaptive_monotonic_ms();
  uint64_t ttl_ms = (uint64_t)adaptive_load_long(&s_ttl_s) * 1000ULL;
  uint64_t until = now + ttl_ms;
  uint64_t current = adaptive_load64(&s_until_ms);
  if (until > current) {
    adaptive_store64(&s_until_ms, until);
  }
  if (severity > adaptive_load_long(&s_level)) {
    adaptive_store_long(&s_level, severity);
  }
  adaptive_mark_pid(pid, process_name, until);
  adaptive_mark_pid(parent_pid, NULL, until);
  adaptive_store64(&s_last_boost_unix_ms, adaptive_unix_ms());
  adaptive_inc64(&s_boosts);
  if (rule_id && rule_id[0]) {
    snprintf(s_last_rule_id, sizeof(s_last_rule_id), "%s", rule_id);
  }
}

int edr_adaptive_collection_active(void) {
  if (!adaptive_load_long(&s_enabled)) {
    return 0;
  }
  return adaptive_monotonic_ms() <= adaptive_load64(&s_until_ms);
}

int edr_adaptive_collection_should_admit_interest(const EdrSensorInterestEvent *event) {
  uint64_t now;
  int pid_hit;
  if (!event || !edr_adaptive_collection_active()) {
    return 0;
  }
  now = adaptive_monotonic_ms();
  pid_hit = adaptive_pid_boosted(event->pid, now) || adaptive_pid_boosted(event->parent_pid, now);
  if (pid_hit && event->parent_pid && event->pid) {
    adaptive_mark_pid(event->pid, event->process_name, adaptive_load64(&s_until_ms));
  }
  if (!pid_hit &&
      !(event->type == EDR_EVENT_NET_CONNECT || event->type == EDR_EVENT_NET_LISTEN ||
        event->type == EDR_EVENT_NET_DNS_QUERY || event->type == EDR_EVENT_NET_TLS_HANDSHAKE) &&
      !(event->type == EDR_EVENT_PROTOCOL_SHELLCODE || event->type == EDR_EVENT_WEBSHELL_DETECTED ||
        event->type == EDR_EVENT_BEHAVIOR_ONNX_ALERT)) {
    return 0;
  }
  if (!adaptive_budget_allow(event->type, now)) {
    return 0;
  }
  switch (event->type) {
    case EDR_EVENT_PROCESS_CREATE:
    case EDR_EVENT_SCRIPT_POWERSHELL:
    case EDR_EVENT_SCRIPT_WMI:
    case EDR_EVENT_PROTOCOL_SHELLCODE:
    case EDR_EVENT_WEBSHELL_DETECTED:
    case EDR_EVENT_BEHAVIOR_ONNX_ALERT:
      return 1;
    case EDR_EVENT_NET_CONNECT:
    case EDR_EVENT_NET_LISTEN:
    case EDR_EVENT_NET_DNS_QUERY:
    case EDR_EVENT_NET_TLS_HANDSHAKE:
      return pid_hit || adaptive_process_interesting(event->process_name) ||
             adaptive_remote_admin_port(event->remote_port) ||
             adaptive_env_bool("EDR_ADAPTIVE_COLLECTION_KEEP_ALL_NET", 0);
    case EDR_EVENT_FILE_CREATE:
    case EDR_EVENT_FILE_WRITE:
    case EDR_EVENT_FILE_DELETE:
    case EDR_EVENT_FILE_RENAME:
    case EDR_EVENT_FILE_PERMISSION_CHANGE:
    case EDR_EVENT_FILE_READ:
    case EDR_EVENT_REG_CREATE_KEY:
    case EDR_EVENT_REG_SET_VALUE:
    case EDR_EVENT_REG_DELETE_KEY:
      return pid_hit;
    case EDR_EVENT_PROCESS_TERMINATE:
    case EDR_EVENT_DLL_LOAD:
      return pid_hit && adaptive_env_bool("EDR_ADAPTIVE_COLLECTION_KEEP_LIFECYCLE", 0);
    case EDR_EVENT_AUTH_LOGIN:
    case EDR_EVENT_AUTH_LOGOUT:
    case EDR_EVENT_AUTH_FAILED:
      return adaptive_env_bool("EDR_ADAPTIVE_COLLECTION_KEEP_AUTH", 0);
    default:
      return 0;
  }
}

int edr_adaptive_collection_should_admit_record(const EdrBehaviorRecord *record) {
  EdrSensorInterestEvent event;
  const char *path;
  size_t path_cap;
  if (!record) {
    return 0;
  }
  memset(&event, 0, sizeof(event));
  event.type = record->type;
  event.pid = record->pid;
  event.parent_pid = record->ppid;
  event.remote_port = (uint32_t)record->net_dport;
  if (record->file_path[0]) {
    path = record->file_path;
    path_cap = sizeof(record->file_path);
  } else if (record->network_aux_path[0]) {
    path = record->network_aux_path;
    path_cap = sizeof(record->network_aux_path);
  } else {
    path = record->exe_path;
    path_cap = sizeof(record->exe_path);
  }
  if (!adaptive_copy_cstr_exact(event.process_name, sizeof(event.process_name),
                                record->process_name, sizeof(record->process_name)) ||
      !adaptive_copy_cstr_exact(event.path, sizeof(event.path), path, path_cap) ||
      !adaptive_copy_cstr_exact(event.registry_path, sizeof(event.registry_path),
                                record->reg_key_path, sizeof(record->reg_key_path))) {
    fprintf(stderr, "[adaptive_collection] record rejected: interest field is not losslessly representable\n");
    return 0;
  }
  return edr_adaptive_collection_should_admit_interest(&event);
}

void edr_adaptive_collection_get_status(EdrAdaptiveCollectionStatus *out_status) {
  uint64_t now;
  uint64_t until;
  if (!out_status) {
    return;
  }
  memset(out_status, 0, sizeof(*out_status));
  now = adaptive_monotonic_ms();
  until = adaptive_load64(&s_until_ms);
  out_status->enabled = adaptive_load_long(&s_enabled) ? 1 : 0;
  out_status->active = out_status->enabled && now <= until;
  out_status->ttl_s = (uint32_t)adaptive_load_long(&s_ttl_s);
  out_status->min_severity = (uint32_t)adaptive_load_long(&s_min_severity);
  out_status->level = (int)adaptive_load_long(&s_level);
  out_status->boosts = adaptive_load64(&s_boosts);
  out_status->last_boost_unix_ms = adaptive_load64(&s_last_boost_unix_ms);
  if (out_status->active && until > now) {
    out_status->remaining_s = (uint32_t)((until - now + 999ULL) / 1000ULL);
  }
  snprintf(out_status->last_rule_id, sizeof(out_status->last_rule_id), "%s", s_last_rule_id);
}
