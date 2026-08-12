/**
 * Windows ETW 实时采集（§3.1）
 * 需具备足够权限（通常需管理员；Security-Auditing 还需审计策略开启）。
 */

#if !defined(_WIN32)
#error collector_win.c is Windows-only
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <evntcons.h>
#include <evntrace.h>
#include <tdh.h>
#include <winevt.h>

#include "edr/collector.h"
#include "edr/adaptive_collection.h"
#include "edr/behavior_from_slot.h"
#include "edr/config.h"
#include "edr/etw_guids_win.h"
#include "edr/etw_observability_win.h"
#include "edr/etw_tdh_win.h"
#include "edr/edr_a44_split_path_win.h"
#include "edr/event_bus.h"
#include "edr/p0_rule_ir.h"
#include "edr/pmfe.h"
#include "edr/process_tree_cache.h"
#include "edr/sensor_interest.h"
#include "edr/ave_sdk.h"
#include "edr/types.h"
#include "edr/windows_event_policy.h"

#include "ave_etw_feed_win.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

static WCHAR g_session_name[] = L"EDR_Agent_RT_001";
static WCHAR g_registry_session_name[] = L"EDR_Agent_KReg_001";

static EdrEventBus *s_bus;
static DWORD s_agent_pid;
static TRACEHANDLE s_session_handle = INVALID_PROCESSTRACE_HANDLE;
static HANDLE s_consumer_thread;
static DWORD s_consumer_thread_id;
static HANDLE s_registry_watch_thread;
static HANDLE s_registry_watch_stop_event;
static DWORD s_registry_watch_thread_id;
static EVT_HANDLE s_security_sub;
static volatile LONG s_started;
static EdrCollectorHealth s_health;
static const EdrConfig *s_collector_cfg;

#define EDR_COLLECTOR_PID_CACHE 512u
#define EDR_AGENT_SELF_PID_CACHE 128u
#define EDR_POLICY_CANARY_PID_CACHE 32u

typedef struct {
  uint32_t pid;
  uint64_t last_seen_ns;
  char process_name[256];
  char exe_path[512];
  char cmdline[1024];
} EdrCollectorPidCacheEntry;

static EdrCollectorPidCacheEntry s_pid_cache[EDR_COLLECTOR_PID_CACHE];
static uint32_t s_pid_cache_next;
static uint32_t s_agent_self_pid_cache[EDR_AGENT_SELF_PID_CACHE];
static uint64_t s_agent_self_seen_ns[EDR_AGENT_SELF_PID_CACHE];
static uint32_t s_agent_self_pid_next;
static uint32_t s_policy_canary_pid_cache[EDR_POLICY_CANARY_PID_CACHE];
static uint64_t s_policy_canary_seen_ns[EDR_POLICY_CANARY_PID_CACHE];
static uint32_t s_policy_canary_pid_next;
static char s_agent_exe_path[MAX_PATH];
static uint64_t s_agent_self_minute_unix;
static uint64_t s_agent_self_minute_count;
static uint64_t s_agent_self_fuse_until_ns;
static uint64_t s_agent_self_fuse_trips;
static uint64_t s_agent_self_fuse_suppressed;
static uint64_t s_agent_self_fuse_last_cooldown_ns;
static int s_agent_self_fuse_fast_drop;

#define EDR_ETW_SEMANTIC_CACHE_SIZE 256u

typedef struct {
  uint8_t valid;
  uint8_t provider_kind;
  uint8_t version;
  uint8_t opcode;
  uint16_t event_id;
  uint16_t task;
  EdrEventType event_type;
} EdrEtwSemanticCacheEntry;

static EdrEtwSemanticCacheEntry s_etw_semantic_cache[EDR_ETW_SEMANTIC_CACHE_SIZE];

static int edr_collector_should_admit_slot(EdrEventSlot *slot);
static int edr_collector_registry_event_type(EdrEventType t);
static void edr_collector_decode_mapped_event(PEVENT_RECORD event_record, EdrEventType ty,
                                              const char *tag, uint64_t timestamp_ns);

static const char *edr_provider_tag(const GUID *g) {
  if (!g) return "unk";
  if (memcmp(g, &EDR_ETW_GUID_KERNEL_PROCESS, sizeof(GUID)) == 0) return "kproc";
  if (memcmp(g, &EDR_ETW_GUID_KERNEL_FILE, sizeof(GUID)) == 0) return "kfile";
  if (memcmp(g, &EDR_ETW_GUID_KERNEL_NETWORK, sizeof(GUID)) == 0) return "knet";
  if (memcmp(g, &EDR_ETW_GUID_KERNEL_REGISTRY, sizeof(GUID)) == 0 ||
      memcmp(g, &EDR_ETW_GUID_SYSTEM_REGISTRY, sizeof(GUID)) == 0 ||
      memcmp(g, &EDR_ETW_GUID_LEGACY_REGISTRY, sizeof(GUID)) == 0) return "kreg";
  if (memcmp(g, &EDR_ETW_GUID_DNS_CLIENT, sizeof(GUID)) == 0) return "dns";
  if (memcmp(g, &EDR_ETW_GUID_POWERSHELL, sizeof(GUID)) == 0) return "ps";
  if (memcmp(g, &EDR_ETW_GUID_SECURITY_AUDIT, sizeof(GUID)) == 0) return "sec";
  if (memcmp(g, &EDR_ETW_GUID_WMI_ACTIVITY, sizeof(GUID)) == 0) return "wmi";
  if (memcmp(g, &EDR_ETW_GUID_MICROSOFT_TCPIP, sizeof(GUID)) == 0) return "tcpip";
  if (memcmp(g, &EDR_ETW_GUID_WINFIREWALL_WFAS, sizeof(GUID)) == 0) return "wf";
  return "other";
}

static void edr_note_provider_callback(const GUID *g) {
  s_health.etw_callbacks_total++;
  if (memcmp(g, &EDR_ETW_GUID_KERNEL_PROCESS, sizeof(GUID)) == 0) {
    s_health.etw_callbacks_process++;
  } else if (memcmp(g, &EDR_ETW_GUID_KERNEL_FILE, sizeof(GUID)) == 0) {
    s_health.etw_callbacks_file++;
  } else if (memcmp(g, &EDR_ETW_GUID_KERNEL_NETWORK, sizeof(GUID)) == 0) {
    s_health.etw_callbacks_network++;
  } else if (memcmp(g, &EDR_ETW_GUID_KERNEL_REGISTRY, sizeof(GUID)) == 0 ||
             memcmp(g, &EDR_ETW_GUID_SYSTEM_REGISTRY, sizeof(GUID)) == 0 ||
             memcmp(g, &EDR_ETW_GUID_LEGACY_REGISTRY, sizeof(GUID)) == 0) {
    s_health.etw_callbacks_registry++;
  }
}

static uint64_t edr_unix_ns(void) {
  FILETIME ft;
  GetSystemTimePreciseAsFileTime(&ft);
  ULARGE_INTEGER u;
  u.LowPart = ft.dwLowDateTime;
  u.HighPart = ft.dwHighDateTime;
  const uint64_t epoch_100ns = 116444736000000000ULL;
  uint64_t t = u.QuadPart;
  if (t < epoch_100ns) {
    return 0;
  }
  return (t - epoch_100ns) * 100ULL;
}

static WCHAR edr_wide_fold_ascii(WCHAR c) {
  if (c >= L'A' && c <= L'Z') {
    return (WCHAR)(c - L'A' + L'a');
  }
  return c;
}

static int edr_tdh_field_contains(const TRACE_EVENT_INFO *info, ULONG info_size,
                                  ULONG offset, const WCHAR *needle) {
  if (!info || !needle || !needle[0] || offset == 0u || offset >= info_size) {
    return 0;
  }
  const WCHAR *text = (const WCHAR *)((const uint8_t *)info + offset);
  size_t text_cap = (size_t)(info_size - offset) / sizeof(WCHAR);
  size_t needle_len = wcslen(needle);
  if (needle_len == 0u || text_cap < needle_len) {
    return 0;
  }
  for (size_t i = 0u; i + needle_len <= text_cap && text[i] != L'\0'; i++) {
    size_t j = 0u;
    while (j < needle_len && i + j < text_cap && text[i + j] != L'\0' &&
           edr_wide_fold_ascii(text[i + j]) == edr_wide_fold_ascii(needle[j])) {
      j++;
    }
    if (j == needle_len) {
      return 1;
    }
  }
  return 0;
}

static int edr_tdh_info_contains(const TRACE_EVENT_INFO *info, ULONG info_size,
                                 const WCHAR *needle) {
  return edr_tdh_field_contains(info, info_size, info->TaskNameOffset, needle) ||
         edr_tdh_field_contains(info, info_size, info->OpcodeNameOffset, needle) ||
         edr_tdh_field_contains(info, info_size, info->EventMessageOffset, needle);
}

static int edr_classify_manifest_semantics(PEVENT_RECORD rec, uint8_t provider_kind,
                                           EdrEventType *out_type) {
  const EVENT_DESCRIPTOR *descriptor = &rec->EventHeader.EventDescriptor;
  uint32_t cache_key = (uint32_t)provider_kind * 16777619u;
  cache_key ^= (uint32_t)descriptor->Id * 2166136261u;
  cache_key ^= (uint32_t)descriptor->Task * 2246822519u;
  cache_key ^= ((uint32_t)descriptor->Version << 8u) | descriptor->Opcode;
  EdrEtwSemanticCacheEntry *entry =
      &s_etw_semantic_cache[cache_key % EDR_ETW_SEMANTIC_CACHE_SIZE];
  if (entry->valid && entry->provider_kind == provider_kind &&
      entry->event_id == descriptor->Id && entry->version == descriptor->Version &&
      entry->opcode == descriptor->Opcode && entry->task == descriptor->Task) {
    if (entry->event_type == 0) {
      return 0;
    }
    *out_type = entry->event_type;
    return 1;
  }

  EdrEventType event_type = 0;
  ULONG info_size = 0u;
  ULONG status = TdhGetEventInformation(rec, 0u, NULL, NULL, &info_size);
  if (status == ERROR_INSUFFICIENT_BUFFER && info_size >= sizeof(TRACE_EVENT_INFO) &&
      info_size <= (256u * 1024u)) {
    TRACE_EVENT_INFO *info = (TRACE_EVENT_INFO *)malloc(info_size);
    if (info) {
      status = TdhGetEventInformation(rec, 0u, NULL, info, &info_size);
      if (status == ERROR_SUCCESS) {
        if (provider_kind == 1u) {
          if (edr_tdh_info_contains(info, info_size, L"delete")) {
            event_type = EDR_EVENT_FILE_DELETE;
          } else if (edr_tdh_info_contains(info, info_size, L"write")) {
            event_type = EDR_EVENT_FILE_WRITE;
          } else if (edr_tdh_info_contains(info, info_size, L"create")) {
            event_type = EDR_EVENT_FILE_CREATE;
          }
        } else if (provider_kind == 2u) {
          int disconnect = edr_tdh_info_contains(info, info_size, L"disconnect");
          int connect = edr_tdh_info_contains(info, info_size, L"connect") ||
                        edr_tdh_info_contains(info, info_size, L"connection");
          if (connect && !disconnect) {
            event_type = EDR_EVENT_NET_CONNECT;
          }
        }
      }
      free(info);
    }
  }

  entry->valid = 1u;
  entry->provider_kind = provider_kind;
  entry->event_id = descriptor->Id;
  entry->version = descriptor->Version;
  entry->opcode = descriptor->Opcode;
  entry->task = descriptor->Task;
  entry->event_type = event_type;
  if (event_type == 0) {
    return 0;
  }
  *out_type = event_type;
  return 1;
}

static int edr_map_type_and_tag(PEVENT_RECORD rec, EdrEventType *out_type,
                                const char **out_tag) {
  const GUID *g = &rec->EventHeader.ProviderId;
  USHORT ev_id = rec->EventHeader.EventDescriptor.Id;
  UCHAR op = rec->EventHeader.EventDescriptor.Opcode;

  if (memcmp(g, &EDR_ETW_GUID_KERNEL_PROCESS, sizeof(GUID)) == 0) {
    *out_tag = "kproc";
    if (op == 1) {
      *out_type = EDR_EVENT_PROCESS_CREATE;
      return 1;
    }
    if (op == 2) {
      *out_type = EDR_EVENT_PROCESS_TERMINATE;
      return 1;
    }
    if (op == 3 || op == 4 || op == 5) {
      *out_type = EDR_EVENT_DLL_LOAD;
      return 1;
    }
    (void)ev_id;
    return 0;
  }
  if (memcmp(g, &EDR_ETW_GUID_KERNEL_FILE, sizeof(GUID)) == 0) {
    *out_tag = "kfile";
    if (edr_classify_manifest_semantics(rec, 1u, out_type)) {
      return 1;
    }
    return 0;
  }
  if (memcmp(g, &EDR_ETW_GUID_KERNEL_NETWORK, sizeof(GUID)) == 0) {
    *out_tag = "knet";
    if (edr_classify_manifest_semantics(rec, 2u, out_type)) {
      return 1;
    }
    return 0;
  }
  if (memcmp(g, &EDR_ETW_GUID_KERNEL_REGISTRY, sizeof(GUID)) == 0) {
    *out_tag = "kreg";
    /* Keep only mutating registry operations. Open/read-style events are too noisy
     * and previously caused sensitive-policy false positives. */
    if (op == 1u) {
      *out_type = EDR_EVENT_REG_CREATE_KEY;
      return 1;
    }
    if (op == 3u || op == 7u) {
      *out_type = EDR_EVENT_REG_DELETE_KEY;
      return 1;
    }
    if (op == 6u) {
      *out_type = EDR_EVENT_REG_SET_VALUE;
      return 1;
    }
    (void)ev_id;
    return 0;
  }
  if (memcmp(g, &EDR_ETW_GUID_SYSTEM_REGISTRY, sizeof(GUID)) == 0 ||
      memcmp(g, &EDR_ETW_GUID_LEGACY_REGISTRY, sizeof(GUID)) == 0) {
    s_health.registry_provider_events++;
    *out_tag = "kreg";
    /* System/legacy registry providers normally expose the operation in Opcode;
     * some builds preserve it in EventDescriptor.Id instead. */
    unsigned operation = op != 0u ? (unsigned)op : (unsigned)ev_id;
    if (operation == 1u || operation == 10u) {
      *out_type = EDR_EVENT_REG_CREATE_KEY;
      return 1;
    }
    if (operation == 3u || operation == 7u || operation == 12u || operation == 15u) {
      *out_type = EDR_EVENT_REG_DELETE_KEY;
      return 1;
    }
    if (operation == 6u || operation == 14u) {
      *out_type = EDR_EVENT_REG_SET_VALUE;
      return 1;
    }
    s_health.registry_provider_unmapped++;
    return 0;
  }
  if (memcmp(g, &EDR_ETW_GUID_DNS_CLIENT, sizeof(GUID)) == 0) {
    *out_tag = "dns";
    *out_type = EDR_EVENT_NET_DNS_QUERY;
    (void)ev_id;
    return 1;
  }
  if (memcmp(g, &EDR_ETW_GUID_POWERSHELL, sizeof(GUID)) == 0) {
    s_health.powershell_visible = 1;
    *out_tag = "ps";
    *out_type = EDR_EVENT_SCRIPT_POWERSHELL;
    return 1;
  }
  if (memcmp(g, &EDR_ETW_GUID_AMSI, sizeof(GUID)) == 0) {
    s_health.amsi_visible = 1;
    *out_tag = "amsi";
    *out_type = EDR_EVENT_SCRIPT_POWERSHELL;
    return 1;
  }
  if (memcmp(g, &EDR_ETW_GUID_SCHANNEL, sizeof(GUID)) == 0) {
    *out_tag = "schannel";
    *out_type = EDR_EVENT_NET_TLS_HANDSHAKE;
    return 1;
  }
  if (memcmp(g, &EDR_ETW_GUID_SECURITY_AUDIT, sizeof(GUID)) == 0) {
    s_health.security_audit_visible = 1;
    *out_tag = "sec";
    if (ev_id == 4624) {
      *out_type = EDR_EVENT_AUTH_LOGIN;
      return 1;
    }
    if (ev_id == 4688) {
      *out_type = EDR_EVENT_PROCESS_CREATE;
      return 1;
    }
    return 0;
  }
  if (memcmp(g, &EDR_ETW_GUID_WMI_ACTIVITY, sizeof(GUID)) == 0) {
    *out_tag = "wmi";
    *out_type = EDR_EVENT_SCRIPT_WMI;
    (void)op;
    return 1;
  }
  if (memcmp(g, &EDR_ETW_GUID_MICROSOFT_TCPIP, sizeof(GUID)) == 0) {
    *out_tag = "tcpip";
    /* 设计 §19.10：1001 新连接 / 1002 端口绑定等；其余按连接类处理 */
    if (ev_id == 1002u) {
      *out_type = EDR_EVENT_NET_LISTEN;
    } else {
      *out_type = EDR_EVENT_NET_CONNECT;
    }
    (void)op;
    return 1;
  }
  if (memcmp(g, &EDR_ETW_GUID_WINFIREWALL_WFAS, sizeof(GUID)) == 0) {
    *out_tag = "wf";
    *out_type = EDR_EVENT_FIREWALL_RULE_CHANGE;
    (void)op;
    (void)ev_id;
    return 1;
  }

  return 0;
}

static uint8_t edr_priority_from_utf8_payload(const uint8_t *data, uint32_t len) {
  if (!data || len == 0) {
    return 1;
  }
  char tmp[4096];
  if (len >= sizeof(tmp)) {
    len = (uint32_t)(sizeof(tmp) - 1u);
  }
  memcpy(tmp, data, len);
  tmp[len] = '\0';
  /* §4 高危特征初筛：EncodedCommand（T1059.001 等） */
  if (strstr(tmp, "EncodedCommand") != NULL || strstr(tmp, "-Enc") != NULL) {
    return 0;
  }
  return 1;
}

static int edr_env_bool_default(const char *name, int fallback) {
  const char *v = getenv(name);
  if (!v || !v[0]) {
    return fallback;
  }
  if ((v[0] == '0' || v[0] == 'n' || v[0] == 'N' || v[0] == 'o' || v[0] == 'O') &&
      (v[1] == '\0' || v[1] == ' ' || v[1] == '\t' || v[1] == '\r' || v[1] == '\n')) {
    return 0;
  }
  return 1;
}

static char edr_fold_ascii_path_char(char c) {
  if (c == '/') {
    c = '\\';
  }
  if (c >= 'A' && c <= 'Z') {
    c = (char)(c - 'A' + 'a');
  }
  return c;
}

static int edr_contains_ci_path(const char *hay, const char *needle) {
  if (!needle || !needle[0]) {
    return 1;
  }
  if (!hay || !hay[0]) {
    return 0;
  }
  for (; *hay; hay++) {
    const char *a = hay;
    const char *b = needle;
    while (*a && *b && edr_fold_ascii_path_char(*a) == edr_fold_ascii_path_char(*b)) {
      a++;
      b++;
    }
    if (!*b) {
      return 1;
    }
  }
  return 0;
}

static void edr_copy_trunc(char *dst, size_t cap, const char *src) {
  if (!dst || cap == 0u) {
    return;
  }
  if (!src) {
    dst[0] = '\0';
    return;
  }
  size_t len = 0u;
  while (len + 1u < cap && src[len] != '\0') {
    len++;
  }
  memcpy(dst, src, len);
  dst[len] = '\0';
}

static int edr_collector_keep_agent_self_events(void) {
  return edr_env_bool_default("EDR_COLLECTOR_KEEP_AGENT_SELF", 0);
}

static uint64_t edr_env_u64_clamped(const char *name, uint64_t defv, uint64_t minv, uint64_t maxv) {
  const char *e = getenv(name);
  uint64_t v = defv;
  if (e && e[0]) {
    char *end = NULL;
    unsigned long long parsed = strtoull(e, &end, 10);
    if (end && *end == '\0') {
      v = (uint64_t)parsed;
    }
  }
  if (v < minv) {
    v = minv;
  }
  if (v > maxv) {
    v = maxv;
  }
  return v;
}

static uint64_t edr_agent_self_ttl_ns(void) {
  const char *e = getenv("EDR_AGENT_SELF_SUPPRESS_TTL_S");
  long v = e && e[0] ? strtol(e, NULL, 10) : 600L;
  if (v < 60L) {
    v = 60L;
  }
  if (v > 86400L) {
    v = 86400L;
  }
  return (uint64_t)v * 1000000000ULL;
}

static uint64_t edr_agent_self_fuse_threshold_per_min(void) {
  return edr_env_u64_clamped("EDR_AGENT_SELF_FUSE_PER_MIN", 10000ULL, 1000ULL, 10000000ULL);
}

static uint64_t edr_agent_self_fuse_cooldown_ns(void) {
  uint64_t s = edr_env_u64_clamped("EDR_AGENT_SELF_FUSE_COOLDOWN_S", 600ULL, 30ULL, 3600ULL);
  return s * 1000000000ULL;
}

static uint64_t edr_agent_self_fuse_effective_cooldown_ns(void) {
  uint64_t base = edr_agent_self_fuse_cooldown_ns();
  uint64_t max_s = edr_env_u64_clamped("EDR_AGENT_SELF_FUSE_MAX_COOLDOWN_S", 1800ULL, 60ULL, 86400ULL);
  uint64_t max_ns = max_s * 1000000000ULL;
  uint64_t next_trip = s_agent_self_fuse_trips + 1u;
  uint64_t multiplier = 1u;
  if (next_trip >= 3u) {
    multiplier = 3u;
  } else if (next_trip == 2u) {
    multiplier = 2u;
  }
  if (base > max_ns / multiplier) {
    return max_ns;
  }
  uint64_t ns = base * multiplier;
  return ns > max_ns ? max_ns : ns;
}

static void edr_agent_self_fuse_degrade_providers(void) {
  if (s_agent_self_fuse_fast_drop || edr_collector_keep_agent_self_events()) {
    return;
  }
  /* Keep every provider enabled. The fuse only activates the callback's
   * PID-cache fast path so external process/file/network coverage is retained. */
  s_agent_self_fuse_fast_drop = 1;
}

static void edr_agent_self_fuse_restore_providers(void) {
  if (!s_agent_self_fuse_fast_drop) {
    return;
  }
  s_agent_self_fuse_fast_drop = 0;
}

static int edr_agent_self_fuse_active(uint64_t now_ns) {
  if (edr_collector_keep_agent_self_events()) {
    return 0;
  }
  if (s_agent_self_fuse_until_ns == 0u) {
    return 0;
  }
  if (s_agent_self_fuse_until_ns <= now_ns) {
    s_agent_self_fuse_until_ns = 0u;
    edr_agent_self_fuse_restore_providers();
    return 0;
  }
  return 1;
}

static void edr_agent_self_note_suppressed(uint64_t now_ns, int fuse_eligible) {
  if (!fuse_eligible) {
    (void)edr_agent_self_fuse_active(now_ns);
    return;
  }
  uint64_t minute = (now_ns / 1000000000ULL) / 60ULL;
  if (s_agent_self_minute_unix != minute) {
    s_agent_self_minute_unix = minute;
    s_agent_self_minute_count = 0u;
  }
  s_agent_self_minute_count++;
  if (edr_agent_self_fuse_active(now_ns)) {
    return;
  }
  uint64_t threshold = edr_agent_self_fuse_threshold_per_min();
  if (s_agent_self_minute_count >= threshold) {
    uint64_t cooldown_ns = edr_agent_self_fuse_effective_cooldown_ns();
    s_agent_self_fuse_last_cooldown_ns = cooldown_ns;
    s_agent_self_fuse_until_ns = now_ns + cooldown_ns;
    s_agent_self_fuse_trips++;
    edr_agent_self_fuse_degrade_providers();
    fprintf(stderr,
            "[collector_win] agent self-noise fuse active count=%llu threshold=%llu cooldown_s=%llu\n",
            (unsigned long long)s_agent_self_minute_count, (unsigned long long)threshold,
            (unsigned long long)(cooldown_ns / 1000000000ULL));
  }
}

typedef enum {
  EDR_AGENT_SELF_DROP_DIRECT_PID = 1,
  EDR_AGENT_SELF_DROP_SECURITY_EVENT = 2,
  EDR_AGENT_SELF_DROP_RECORD = 3,
  EDR_AGENT_SELF_DROP_INTEREST = 4,
} EdrAgentSelfDropSource;

static void edr_agent_self_count_drop_source(uint64_t now_ns, EdrAgentSelfDropSource source) {
  s_health.agent_self_suppressed++;
  s_health.collector_dropped++;
  switch (source) {
  case EDR_AGENT_SELF_DROP_DIRECT_PID:
    s_health.agent_self_direct_pid_suppressed++;
    break;
  case EDR_AGENT_SELF_DROP_SECURITY_EVENT:
    s_health.agent_self_security_event_suppressed++;
    break;
  case EDR_AGENT_SELF_DROP_RECORD:
    s_health.agent_self_record_suppressed++;
    break;
  case EDR_AGENT_SELF_DROP_INTEREST:
    s_health.agent_self_interest_suppressed++;
    break;
  default:
    break;
  }
  edr_agent_self_note_suppressed(now_ns, 1);
}

static void edr_agent_self_mark_pid(uint32_t pid, uint64_t now_ns) {
  if (pid == 0u) {
    return;
  }
  for (size_t i = 0; i < EDR_AGENT_SELF_PID_CACHE; i++) {
    if (s_agent_self_pid_cache[i] == pid) {
      s_agent_self_seen_ns[i] = now_ns;
      return;
    }
  }
  uint32_t idx = s_agent_self_pid_next++ % EDR_AGENT_SELF_PID_CACHE;
  s_agent_self_pid_cache[idx] = pid;
  s_agent_self_seen_ns[idx] = now_ns;
}

static int edr_agent_self_pid_seen(uint32_t pid, uint64_t now_ns) {
  uint64_t ttl = edr_agent_self_ttl_ns();
  if (pid == 0u) {
    return 0;
  }
  if (pid == s_agent_pid) {
    return 1;
  }
  for (size_t i = 0; i < EDR_AGENT_SELF_PID_CACHE; i++) {
    if (s_agent_self_pid_cache[i] != pid) {
      continue;
    }
    if (now_ns >= s_agent_self_seen_ns[i] && now_ns - s_agent_self_seen_ns[i] <= ttl) {
      return 1;
    }
    s_agent_self_pid_cache[i] = 0u;
    s_agent_self_seen_ns[i] = 0u;
    return 0;
  }
  return 0;
}

static int edr_agent_self_text_marker(const char *s) {
  if (!s || !s[0]) {
    return 0;
  }
  if (s_agent_exe_path[0] && edr_contains_ci_path(s, s_agent_exe_path)) {
    return 1;
  }
  if (edr_contains_ci_path(s, "\\FDSecurity\\FDSensor.exe") ||
      edr_contains_ci_path(s, "/FDSecurity/FDSensor.exe") ||
      edr_contains_ci_path(s, "\\EDR Agent\\edr_agent.exe") ||
      edr_contains_ci_path(s, "/EDR Agent/edr_agent.exe")) {
    return 1;
  }
  if (edr_contains_ci_path(s, "/api/v1/agent/runtime-policy.toml") ||
      edr_contains_ci_path(s, "/api/v1/agent/sensor-interest.json") ||
      edr_contains_ci_path(s, "/api/v1/agent/rules.toml") ||
      edr_contains_ci_path(s, "/api/v1/agent/p0-bundle") ||
      edr_contains_ci_path(s, "/api/v1/agent/version/latest") ||
      edr_contains_ci_path(s, "/api/v1/agent/download/latest") ||
      edr_contains_ci_path(s, "/api/v1/ingest/engine-health") ||
      edr_contains_ci_path(s, "\\edr_sensor_interest_") ||
      edr_contains_ci_path(s, "\\edr_remote_") ||
      edr_contains_ci_path(s, "/edr_sensor_interest_") ||
      edr_contains_ci_path(s, "/edr_remote_") ||
      edr_contains_ci_path(s, "\\edr_forensic\\") ||
      edr_contains_ci_path(s, "/edr_forensic/") ||
      edr_contains_ci_path(s, "cmd_forensic_") ||
      edr_contains_ci_path(s, "auto-forensic-")) {
    return 1;
  }
  return 0;
}

static int edr_agent_self_process_name(const char *s) {
  return edr_contains_ci_path(s, "FDSensor.exe") || edr_contains_ci_path(s, "edr_agent.exe") ||
         edr_contains_ci_path(s, "edr_agent_setup.exe") ||
         edr_contains_ci_path(s, "edr_agent_install.ps1");
}

static int edr_policy_canary_marker(const char *s) {
  return s && s[0] && edr_contains_ci_path(s, "EDR_POLICY_CANARY_");
}

static uint64_t edr_policy_canary_ttl_ns(void) {
  return edr_env_u64_clamped("EDR_POLICY_CANARY_TTL_S", 120ULL, 30ULL, 600ULL) *
         1000000000ULL;
}

static void edr_policy_canary_mark_pid(uint32_t pid, uint64_t now_ns) {
  if (pid == 0u) {
    return;
  }
  for (uint32_t i = 0; i < EDR_POLICY_CANARY_PID_CACHE; i++) {
    if (s_policy_canary_pid_cache[i] == pid) {
      s_policy_canary_seen_ns[i] = now_ns;
      return;
    }
  }
  uint32_t idx = s_policy_canary_pid_next++ % EDR_POLICY_CANARY_PID_CACHE;
  s_policy_canary_pid_cache[idx] = pid;
  s_policy_canary_seen_ns[idx] = now_ns;
}

static int edr_policy_canary_pid_seen(uint32_t pid, uint64_t now_ns) {
  const uint64_t ttl_ns = edr_policy_canary_ttl_ns();
  if (pid == 0u) {
    return 0;
  }
  for (uint32_t i = 0; i < EDR_POLICY_CANARY_PID_CACHE; i++) {
    if (s_policy_canary_pid_cache[i] != pid) {
      continue;
    }
    if (now_ns >= s_policy_canary_seen_ns[i] && now_ns - s_policy_canary_seen_ns[i] <= ttl_ns) {
      return 1;
    }
    s_policy_canary_pid_cache[i] = 0u;
    s_policy_canary_seen_ns[i] = 0u;
    return 0;
  }
  return 0;
}

void edr_collector_register_policy_canary_process(uint32_t pid, const char *command) {
  if (pid == 0u || !edr_policy_canary_marker(command)) {
    return;
  }
  edr_policy_canary_mark_pid(pid, edr_unix_ns());
}

static uint32_t edr_parse_pid_text(const char *s) {
  if (!s || !s[0]) {
    return 0u;
  }
  return (uint32_t)strtoul(s, NULL, 0);
}

static int edr_agent_self_suppress_interest(const EdrSensorInterestEvent *ev) {
  if (!ev || edr_collector_keep_agent_self_events()) {
    return 0;
  }
  uint64_t now = edr_unix_ns();
  if (edr_policy_canary_marker(ev->path) || edr_policy_canary_marker(ev->registry_path)) {
    edr_policy_canary_mark_pid(ev->pid, now);
    return 0;
  }
  if (edr_policy_canary_pid_seen(ev->pid, now) ||
      edr_policy_canary_pid_seen(ev->parent_pid, now)) {
    edr_policy_canary_mark_pid(ev->pid, now);
    return 0;
  }
  if (ev->pid == s_agent_pid || ev->parent_pid == s_agent_pid ||
      edr_agent_self_pid_seen(ev->pid, now) || edr_agent_self_pid_seen(ev->parent_pid, now)) {
    edr_agent_self_mark_pid(ev->pid, now);
    return 1;
  }
  if (edr_agent_self_process_name(ev->process_name) || edr_agent_self_text_marker(ev->path) ||
      edr_agent_self_text_marker(ev->registry_path)) {
    edr_agent_self_mark_pid(ev->pid, now);
    return 1;
  }
  return 0;
}

static int edr_agent_self_suppress_security_event(const char *img, const char *cmd,
                                                  const char *epid, const char *ppid,
                                                  const char *parent_img) {
  if (edr_collector_keep_agent_self_events()) {
    return 0;
  }
  uint64_t now = edr_unix_ns();
  uint32_t pid = edr_parse_pid_text(epid);
  uint32_t parent_pid = edr_parse_pid_text(ppid);
  if (edr_policy_canary_marker(cmd)) {
    edr_policy_canary_mark_pid(pid, now);
    return 0;
  }
  if (edr_policy_canary_pid_seen(pid, now) || edr_policy_canary_pid_seen(parent_pid, now)) {
    edr_policy_canary_mark_pid(pid, now);
    return 0;
  }
  if (pid == s_agent_pid || parent_pid == s_agent_pid ||
      edr_agent_self_pid_seen(pid, now) || edr_agent_self_pid_seen(parent_pid, now)) {
    edr_agent_self_mark_pid(pid, now);
    return 1;
  }
  if (edr_agent_self_process_name(img) || edr_agent_self_process_name(parent_img) ||
      edr_agent_self_text_marker(img) || edr_agent_self_text_marker(cmd) ||
      edr_agent_self_text_marker(parent_img)) {
    edr_agent_self_mark_pid(pid, now);
    return 1;
  }
  return 0;
}

static int edr_agent_self_suppress_record(const EdrBehaviorRecord *br) {
  if (!br || edr_collector_keep_agent_self_events()) {
    return 0;
  }
  uint64_t now = br->event_time_ns > 0 ? (uint64_t)br->event_time_ns : edr_unix_ns();
  if (edr_policy_canary_marker(br->cmdline)) {
    edr_policy_canary_mark_pid(br->pid, now);
    return 0;
  }
  if (edr_policy_canary_pid_seen(br->pid, now) || edr_policy_canary_pid_seen(br->ppid, now)) {
    edr_policy_canary_mark_pid(br->pid, now);
    return 0;
  }
  if (br->pid == s_agent_pid || br->ppid == s_agent_pid ||
      edr_agent_self_pid_seen(br->pid, now) || edr_agent_self_pid_seen(br->ppid, now)) {
    edr_agent_self_mark_pid(br->pid, now);
    return 1;
  }
  if (edr_agent_self_process_name(br->process_name) || edr_agent_self_text_marker(br->exe_path) ||
      edr_agent_self_text_marker(br->cmdline) || edr_agent_self_text_marker(br->file_path) ||
      edr_agent_self_text_marker(br->reg_key_path) || edr_agent_self_text_marker(br->network_aux_path)) {
    edr_agent_self_mark_pid(br->pid, now);
    return 1;
  }
  return 0;
}

static int edr_agent_self_fuse_should_drop_event(PEVENT_RECORD event_record,
                                                 uint64_t now_ns) {
  if (!event_record || s_agent_self_fuse_until_ns == 0u) {
    return 0;
  }
  if (!edr_agent_self_fuse_active(now_ns)) {
    return 0;
  }
  const GUID *g = &event_record->EventHeader.ProviderId;
  UCHAR op = event_record->EventHeader.EventDescriptor.Opcode;
  if (memcmp(g, &EDR_ETW_GUID_KERNEL_PROCESS, sizeof(GUID)) == 0 && op == 1u) {
    return 0;
  }
  return edr_agent_self_pid_seen((uint32_t)event_record->EventHeader.ProcessId,
                                 now_ns);
}

static int edr_ends_with_ci(const char *s, const char *suffix) {
  if (!s || !suffix) {
    return 0;
  }
  size_t n = strlen(s);
  size_t m = strlen(suffix);
  if (m == 0u || n < m) {
    return 0;
  }
  s += n - m;
  for (size_t i = 0; i < m; i++) {
    char a = s[i];
    char b = suffix[i];
    if (a >= 'A' && a <= 'Z') {
      a = (char)(a - 'A' + 'a');
    }
    if (b >= 'A' && b <= 'Z') {
      b = (char)(b - 'A' + 'a');
    }
    if (a != b) {
      return 0;
    }
  }
  return 1;
}

static int edr_collector_valid_process_create_record(const EdrBehaviorRecord *br) {
  const char *name;
  if (!br || br->type != EDR_EVENT_PROCESS_CREATE) {
    return 1;
  }
  if (br->pid == 0u) {
    return 0;
  }
  if (!br->process_name[0] && !br->exe_path[0] && !br->cmdline[0]) {
    return 0;
  }
  name = br->process_name[0] ? br->process_name : br->exe_path;
  if (edr_ends_with_ci(name, ".dll") || edr_ends_with_ci(name, ".sys")) {
    return 0;
  }
  return 1;
}

static int edr_collector_debug_tdh_enabled(void) {
  static int cached = -1;
  if (cached < 0) {
    const char *e = getenv("EDR_TDH_DEBUG");
    cached = (e && e[0] && strcmp(e, "0") != 0) ? 1 : 0;
  }
  return cached;
}

static int edr_collector_debug_tdh_tag_allowed(const char *tag) {
  const char *filter = getenv("EDR_TDH_DEBUG_TAG");
  if (!filter || !filter[0] || strcmp(filter, "*") == 0) {
    return 1;
  }
  return tag && strstr(filter, tag) != NULL;
}

static uint64_t edr_collector_debug_tdh_limit(void) {
  static uint64_t cached;
  static int inited;
  if (!inited) {
    const char *e = getenv("EDR_TDH_DEBUG_LIMIT");
    cached = (e && e[0]) ? strtoull(e, NULL, 10) : 80ull;
    inited = 1;
  }
  return cached;
}

static void edr_collector_debug_tdh_payload(const EdrEventSlot *slot, const char *tag) {
  static uint64_t printed;
  uint64_t limit;
  if (!edr_collector_debug_tdh_enabled() || !slot || slot->size == 0u) {
    return;
  }
  if (!edr_collector_debug_tdh_tag_allowed(tag)) {
    return;
  }
  if (slot->type != EDR_EVENT_PROCESS_CREATE && slot->type != EDR_EVENT_SCRIPT_POWERSHELL &&
      slot->type != EDR_EVENT_SCRIPT_WMI) {
    return;
  }
  limit = edr_collector_debug_tdh_limit();
  if (limit != 0u && printed >= limit) {
    if (printed == limit) {
      fprintf(stderr, "[TDH DEBUG] limit reached (%llu); suppressing further TDH debug\n",
              (unsigned long long)limit);
    }
    printed++;
    return;
  }
  printed++;
  fprintf(stderr, "[TDH DEBUG] tag=%s type=%d payload:\n%.*s\n",
          tag ? tag : "unknown", (int)slot->type, (int)slot->size, (const char *)slot->data);
}

static int edr_xml_entity_append(char *out, size_t cap, size_t *off, const char *s, size_t n) {
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    if (c == '&') {
      if (i + 5u <= n && memcmp(s + i, "&amp;", 5) == 0) {
        c = '&';
        i += 4u;
      } else if (i + 4u <= n && memcmp(s + i, "&lt;", 4) == 0) {
        c = '<';
        i += 3u;
      } else if (i + 4u <= n && memcmp(s + i, "&gt;", 4) == 0) {
        c = '>';
        i += 3u;
      } else if (i + 6u <= n && memcmp(s + i, "&quot;", 6) == 0) {
        c = '"';
        i += 5u;
      } else if (i + 6u <= n && memcmp(s + i, "&apos;", 6) == 0) {
        c = '\'';
        i += 5u;
      }
    }
    if (*off + 1u >= cap) {
      out[cap - 1u] = '\0';
      return 0;
    }
    out[(*off)++] = c;
  }
  if (*off < cap) {
    out[*off] = '\0';
  }
  return 1;
}

static int edr_xml_get_data_utf8(const char *xml, const char *name, char *out, size_t cap) {
  if (!xml || !name || !out || cap == 0u) {
    return 0;
  }
  out[0] = '\0';
  char needle1[160];
  char needle2[160];
  snprintf(needle1, sizeof(needle1), "<Data Name='%s'>", name);
  snprintf(needle2, sizeof(needle2), "<Data Name=\"%s\">", name);
  const char *p = strstr(xml, needle1);
  size_t prefix = strlen(needle1);
  if (!p) {
    p = strstr(xml, needle2);
    prefix = strlen(needle2);
  }
  if (!p) {
    return 0;
  }
  p += prefix;
  const char *e = strstr(p, "</Data>");
  if (!e || e <= p) {
    return 0;
  }
  size_t off = 0u;
  (void)edr_xml_entity_append(out, cap, &off, p, (size_t)(e - p));
  return out[0] ? 1 : 0;
}

static int edr_evt_render_xml_utf8(EVT_HANDLE event, char **out_xml) {
  DWORD used = 0;
  DWORD props = 0;
  if (!out_xml) {
    return 0;
  }
  *out_xml = NULL;
  (void)EvtRender(NULL, event, EvtRenderEventXml, 0, NULL, &used, &props);
  if (used == 0u || used > 262144u) {
    return 0;
  }
  WCHAR *wxml = (WCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)used + sizeof(WCHAR));
  if (!wxml) {
    return 0;
  }
  if (!EvtRender(NULL, event, EvtRenderEventXml, used, wxml, &used, &props)) {
    HeapFree(GetProcessHeap(), 0, wxml);
    return 0;
  }
  int need = WideCharToMultiByte(CP_UTF8, 0, wxml, -1, NULL, 0, NULL, NULL);
  if (need <= 1) {
    HeapFree(GetProcessHeap(), 0, wxml);
    return 0;
  }
  char *utf8 = (char *)malloc((size_t)need);
  if (!utf8) {
    HeapFree(GetProcessHeap(), 0, wxml);
    return 0;
  }
  WideCharToMultiByte(CP_UTF8, 0, wxml, -1, utf8, need, NULL, NULL);
  HeapFree(GetProcessHeap(), 0, wxml);
  *out_xml = utf8;
  return 1;
}

static int edr_push_slot_after_policy(EdrEventSlot *slot, const char *debug_tag) {
  if (!slot) {
    return 0;
  }
  edr_collector_debug_tdh_payload(slot, debug_tag);
  slot->priority = edr_priority_from_utf8_payload(slot->data, slot->size);
  if (!edr_collector_should_admit_slot(slot)) {
    s_health.collector_dropped++;
    return 0;
  }
  if (!edr_event_bus_try_push(s_bus, slot)) {
    s_health.queue_dropped++;
    return 0;
  }
  return 1;
}

#define EDR_REGISTRY_WATCH_MAX 32u
#define EDR_REGISTRY_WATCH_VALUE_MAX 128u
#define EDR_REGISTRY_VALUE_NAME_MAX 512u
#define EDR_REGISTRY_VALUE_DATA_MAX 1024u

typedef struct {
  char *name;
  char *data;
  DWORD type;
  uint64_t hash;
} EdrRegistryValueSnapshot;

typedef struct {
  HKEY key;
  HANDLE event;
  char path[1024];
  EdrRegistryValueSnapshot *values;
  DWORD value_count;
  int snapshot_available;
} EdrRegistryWatch;

static void edr_etw1_sanitize_value(char *dst, size_t cap, const char *src) {
  size_t off = 0u;
  if (!dst || cap == 0u) {
    return;
  }
  dst[0] = '\0';
  if (!src) {
    return;
  }
  while (*src && off + 1u < cap) {
    unsigned char c = (unsigned char)*src++;
    dst[off++] = (c == '\r' || c == '\n' || c == '\0') ? ' ' : (char)c;
  }
  dst[off] = '\0';
}

static void edr_registry_value_data_text(DWORD type, const BYTE *data, DWORD size,
                                         char *out, size_t out_cap) {
  if (!out || out_cap == 0u) {
    return;
  }
  out[0] = '\0';
  if (!data || size == 0u) {
    return;
  }
  if (type == REG_SZ || type == REG_EXPAND_SZ) {
    char raw[EDR_REGISTRY_VALUE_DATA_MAX];
    size_t copy = size < sizeof(raw) - 1u ? (size_t)size : sizeof(raw) - 1u;
    memcpy(raw, data, copy);
    raw[copy] = '\0';
    edr_etw1_sanitize_value(out, out_cap, raw);
    return;
  }
  if (type == REG_MULTI_SZ) {
    size_t off = 0u;
    for (DWORD i = 0u; i < size && off + 1u < out_cap; ++i) {
      unsigned char c = data[i];
      if (c == '\0') {
        if (i + 1u >= size || data[i + 1u] == '\0') {
          break;
        }
        c = ';';
      }
      out[off++] = (c == '\r' || c == '\n') ? ' ' : (char)c;
    }
    out[off] = '\0';
    return;
  }
  if (type == REG_DWORD && size >= sizeof(DWORD)) {
    DWORD value = 0u;
    memcpy(&value, data, sizeof(value));
    snprintf(out, out_cap, "%lu (0x%08lX)", (unsigned long)value, (unsigned long)value);
    return;
  }
  if (type == REG_QWORD && size >= sizeof(ULONGLONG)) {
    ULONGLONG value = 0u;
    memcpy(&value, data, sizeof(value));
    snprintf(out, out_cap, "%llu (0x%016llX)",
             (unsigned long long)value, (unsigned long long)value);
    return;
  }
  {
    size_t off = 0u;
    DWORD limit = size < 128u ? size : 128u;
    for (DWORD i = 0u; i < limit && off + 3u < out_cap; ++i) {
      int n = snprintf(out + off, out_cap - off, "%02X", (unsigned)data[i]);
      if (n <= 0) {
        break;
      }
      off += (size_t)n;
    }
    if (limit < size && off + 4u < out_cap) {
      snprintf(out + off, out_cap - off, "...");
    }
  }
}

static uint64_t edr_registry_snapshot_hash(const char *name, DWORD type,
                                           const char *data) {
  uint64_t hash = 1469598103934665603ULL;
  const unsigned char *p;
  for (p = (const unsigned char *)(name ? name : ""); *p; ++p) {
    hash = (hash ^ *p) * 1099511628211ULL;
  }
  for (size_t i = 0u; i < sizeof(type); ++i) {
    hash = (hash ^ (unsigned char)((type >> (i * 8u)) & 0xffu)) *
           1099511628211ULL;
  }
  for (p = (const unsigned char *)(data ? data : ""); *p; ++p) {
    hash = (hash ^ *p) * 1099511628211ULL;
  }
  return hash;
}

static void edr_registry_snapshot_free(EdrRegistryValueSnapshot *values,
                                       DWORD count) {
  if (!values) {
    return;
  }
  for (DWORD i = 0u; i < count; ++i) {
    free(values[i].name);
    free(values[i].data);
  }
  free(values);
}

static int edr_registry_snapshot_capture(HKEY key,
                                         EdrRegistryValueSnapshot **out_values,
                                         DWORD *out_count) {
  DWORD value_total = 0u;
  DWORD max_name = 0u;
  DWORD max_data = 0u;
  DWORD cap = 0u;
  EdrRegistryValueSnapshot *values = NULL;
  char *name = NULL;
  BYTE *data = NULL;
  DWORD captured = 0u;
  if (!key || !out_values || !out_count) {
    return 0;
  }
  *out_values = NULL;
  *out_count = 0u;
  if (RegQueryInfoKeyA(key, NULL, NULL, NULL, NULL, NULL, NULL, &value_total,
                       &max_name, &max_data, NULL, NULL) != ERROR_SUCCESS) {
    return 0;
  }
  cap = value_total < EDR_REGISTRY_WATCH_VALUE_MAX
            ? value_total
            : EDR_REGISTRY_WATCH_VALUE_MAX;
  if (cap == 0u) {
    return 1;
  }
  values = (EdrRegistryValueSnapshot *)calloc(cap, sizeof(*values));
  if (!values) {
    return 0;
  }
  max_name = max_name < 1u ? 1u : max_name + 1u;
  max_data = max_data < 1u ? 1u : max_data + 1u;
  if (max_name > 4096u) max_name = 4096u;
  if (max_data > 65536u) max_data = 65536u;
  name = (char *)malloc((size_t)max_name + 1u);
  data = (BYTE *)malloc((size_t)max_data + 1u);
  if (!name || !data) {
    free(name);
    free(data);
    free(values);
    return 0;
  }
  for (DWORD i = 0u; i < value_total && captured < cap; ++i) {
    DWORD name_len = max_name;
    DWORD data_len = max_data;
    DWORD type = REG_NONE;
    memset(name, 0, (size_t)max_name + 1u);
    memset(data, 0, (size_t)max_data + 1u);
    if (RegEnumValueA(key, i, name, &name_len, NULL, &type, data, &data_len) != ERROR_SUCCESS) {
      continue;
    }
    char rendered[EDR_REGISTRY_VALUE_DATA_MAX];
    const char *display_name = name[0] ? name : "(Default)";
    edr_registry_value_data_text(type, data, data_len, rendered,
                                 sizeof(rendered));
    values[captured].name = _strdup(display_name);
    values[captured].data = _strdup(rendered);
    if (!values[captured].name || !values[captured].data) {
      free(name);
      free(data);
      edr_registry_snapshot_free(values, captured + 1u);
      return 0;
    }
    values[captured].type = type;
    values[captured].hash = edr_registry_snapshot_hash(
        values[captured].name, type, values[captured].data);
    captured++;
  }
  free(name);
  free(data);
  *out_values = values;
  *out_count = captured;
  return 1;
}

static int edr_registry_snapshot_find(const EdrRegistryValueSnapshot *values,
                                      DWORD count, const char *name) {
  if (!values || !name) {
    return -1;
  }
  for (DWORD i = 0u; i < count; ++i) {
    if (_stricmp(values[i].name, name) == 0) {
      return (int)i;
    }
  }
  return -1;
}

static int edr_registry_watch_add(EdrRegistryWatch *watches, DWORD *count,
                                  HKEY root, const char *subkey,
                                  const char *display_path, REGSAM view) {
  HKEY key = NULL;
  HANDLE event = NULL;
  if (!watches || !count || *count >= EDR_REGISTRY_WATCH_MAX ||
      !subkey || !display_path) {
    return 0;
  }
  if (RegOpenKeyExA(root, subkey, 0, KEY_NOTIFY | KEY_QUERY_VALUE | view, &key) != ERROR_SUCCESS) {
    if (RegOpenKeyExA(root, subkey, 0, KEY_NOTIFY | view, &key) != ERROR_SUCCESS) {
      return 0;
    }
  }
  event = CreateEventW(NULL, FALSE, FALSE, NULL);
  if (!event || RegNotifyChangeKeyValue(key, FALSE,
                                        REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                                        event, TRUE) != ERROR_SUCCESS) {
    if (event) CloseHandle(event);
    RegCloseKey(key);
    return 0;
  }
  watches[*count].key = key;
  watches[*count].event = event;
  snprintf(watches[*count].path, sizeof(watches[*count].path), "%s", display_path);
  watches[*count].snapshot_available = edr_registry_snapshot_capture(
      key, &watches[*count].values, &watches[*count].value_count);
  (*count)++;
  return 1;
}

static void edr_registry_watch_emit(const char *path, const char *value_name,
                                    const char *value_data, const char *operation,
                                    const char *detail_status) {
  EdrSensorInterestEvent interest;
  EdrEventSlot slot;
  char safe_name[EDR_REGISTRY_VALUE_NAME_MAX];
  char safe_data[EDR_REGISTRY_VALUE_DATA_MAX];
  int n;
  if (!path || !path[0] || !s_bus) {
    return;
  }
  s_health.registry_provider_events++;
  s_health.registry_unattributed_events++;
  memset(&interest, 0, sizeof(interest));
  interest.type = EDR_EVENT_REG_SET_VALUE;
  snprintf(interest.provider, sizeof(interest.provider), "%s", "regnotify");
  snprintf(interest.path, sizeof(interest.path), "%s", path);
  snprintf(interest.registry_path, sizeof(interest.registry_path), "%s", path);
  if (!edr_sensor_interest_should_admit(&interest)) {
    s_health.collector_dropped++;
    return;
  }

  memset(&slot, 0, sizeof(slot));
  edr_etw1_sanitize_value(safe_name, sizeof(safe_name), value_name);
  edr_etw1_sanitize_value(safe_data, sizeof(safe_data), value_data);
  slot.timestamp_ns = edr_unix_ns();
  slot.type = operation && strcmp(operation, "delete_value") == 0
                  ? EDR_EVENT_REG_DELETE_KEY
                  : EDR_EVENT_REG_SET_VALUE;
  slot.priority = 0u;
  n = snprintf((char *)slot.data, sizeof(slot.data),
               "ETW1\nprov=regnotify_snapshot\npid=0\nregkey=%s\nregname=%s\n"
               "regdata=%s\nregop=%s\nregistry_source=regnotify_snapshot\n"
               "registry_attribution=unavailable\nregistry_detail_status=%s\n",
               path, safe_name, safe_data,
               operation && operation[0] ? operation : "change_notify",
               detail_status && detail_status[0] ? detail_status : "captured");
  if (n <= 0 || (size_t)n >= sizeof(slot.data)) {
    s_health.registry_payload_missing++;
    return;
  }
  slot.size = (uint32_t)n + 1u;
  if (edr_push_slot_after_policy(&slot, "regnotify")) {
    s_health.registry_events_admitted++;
  }
}

static void edr_registry_watch_process(EdrRegistryWatch *watch) {
  EdrRegistryValueSnapshot *next = NULL;
  DWORD next_count = 0u;
  if (!watch) {
    return;
  }
  if (!edr_registry_snapshot_capture(watch->key, &next, &next_count)) {
    edr_registry_snapshot_free(next, next_count);
    edr_registry_watch_emit(watch->path, "", "", "change_notify", "snapshot_unavailable");
    return;
  }
  if (!watch->snapshot_available) {
    edr_registry_snapshot_free(watch->values, watch->value_count);
    watch->values = next;
    watch->value_count = next_count;
    watch->snapshot_available = 1;
    edr_registry_watch_emit(watch->path, "", "", "change_notify", "baseline_initialized");
    return;
  }
  for (DWORD i = 0u; i < next_count; ++i) {
    int old_idx = edr_registry_snapshot_find(watch->values, watch->value_count, next[i].name);
    if (old_idx < 0 || watch->values[old_idx].hash != next[i].hash ||
        watch->values[old_idx].type != next[i].type ||
        strcmp(watch->values[old_idx].data, next[i].data) != 0) {
      edr_registry_watch_emit(watch->path, next[i].name, next[i].data,
                              "set_value", "captured");
    }
  }
  for (DWORD i = 0u; i < watch->value_count; ++i) {
    if (edr_registry_snapshot_find(next, next_count, watch->values[i].name) < 0) {
      edr_registry_watch_emit(watch->path, watch->values[i].name,
                              watch->values[i].data, "delete_value", "captured");
    }
  }
  edr_registry_snapshot_free(watch->values, watch->value_count);
  watch->values = next;
  watch->value_count = next_count;
}

static DWORD WINAPI edr_registry_watch_thread_main(void *arg) {
  EdrRegistryWatch watches[EDR_REGISTRY_WATCH_MAX];
  HANDLE wait_handles[EDR_REGISTRY_WATCH_MAX + 1u];
  DWORD count = 0u;
  DWORD wait_count;
  (void)arg;
  memset(watches, 0, sizeof(watches));
  memset(wait_handles, 0, sizeof(wait_handles));

  (void)edr_registry_watch_add(watches, &count, HKEY_LOCAL_MACHINE,
      "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", KEY_WOW64_64KEY);
  (void)edr_registry_watch_add(watches, &count, HKEY_LOCAL_MACHINE,
      "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
      "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", KEY_WOW64_64KEY);
  (void)edr_registry_watch_add(watches, &count, HKEY_LOCAL_MACHINE,
      "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
      "HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", KEY_WOW64_64KEY);
  (void)edr_registry_watch_add(watches, &count, HKEY_LOCAL_MACHINE,
      "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
      "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", KEY_WOW64_64KEY);

  HKEY users = NULL;
  if (RegOpenKeyExA(HKEY_USERS, "", 0, KEY_ENUMERATE_SUB_KEYS, &users) == ERROR_SUCCESS) {
    for (DWORD i = 0u; count + 2u < EDR_REGISTRY_WATCH_MAX; ++i) {
      char sid[256];
      DWORD sid_len = (DWORD)sizeof(sid);
      if (RegEnumKeyExA(users, i, sid, &sid_len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
        break;
      }
      if (strncmp(sid, "S-1-5-", 6u) != 0 || strstr(sid, "_Classes") != NULL) {
        continue;
      }
      char subkey[768];
      char display[1024];
      snprintf(subkey, sizeof(subkey), "%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", sid);
      snprintf(display, sizeof(display), "HKU\\%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", sid);
      (void)edr_registry_watch_add(watches, &count, HKEY_USERS, subkey, display, 0);
      snprintf(subkey, sizeof(subkey), "%s\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", sid);
      snprintf(display, sizeof(display), "HKU\\%s\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", sid);
      (void)edr_registry_watch_add(watches, &count, HKEY_USERS, subkey, display, 0);
    }
    RegCloseKey(users);
  }

  wait_handles[0] = s_registry_watch_stop_event;
  for (DWORD i = 0u; i < count; ++i) {
    wait_handles[i + 1u] = watches[i].event;
  }
  wait_count = count + 1u;
  while (s_registry_watch_stop_event && wait_count > 1u) {
    DWORD wr = WaitForMultipleObjects(wait_count, wait_handles, FALSE, INFINITE);
    if (wr == WAIT_OBJECT_0) {
      break;
    }
    if (wr >= WAIT_OBJECT_0 + 1u && wr < WAIT_OBJECT_0 + wait_count) {
      DWORD idx = wr - WAIT_OBJECT_0 - 1u;
      if (RegNotifyChangeKeyValue(watches[idx].key, FALSE,
                                  REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                                  watches[idx].event, TRUE) != ERROR_SUCCESS) {
        break;
      }
      edr_registry_watch_process(&watches[idx]);
      continue;
    }
    break;
  }
  for (DWORD i = 0u; i < count; ++i) {
    if (watches[i].event) CloseHandle(watches[i].event);
    if (watches[i].key) RegCloseKey(watches[i].key);
    edr_registry_snapshot_free(watches[i].values, watches[i].value_count);
  }
  return 0u;
}

static int edr_start_registry_watch(void) {
  s_registry_watch_stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
  if (!s_registry_watch_stop_event) {
    return 0;
  }
  s_registry_watch_thread = CreateThread(NULL, 0, edr_registry_watch_thread_main,
                                          NULL, 0, &s_registry_watch_thread_id);
  if (!s_registry_watch_thread) {
    CloseHandle(s_registry_watch_stop_event);
    s_registry_watch_stop_event = NULL;
    return 0;
  }
  return 1;
}

static unsigned edr_xml_event_id(const char *xml) {
  const char *p;
  if (!xml) {
    return 0u;
  }
  p = strstr(xml, "<EventID");
  if (!p) {
    return 0u;
  }
  p = strchr(p, '>');
  if (!p) {
    return 0u;
  }
  return (unsigned)strtoul(p + 1, NULL, 10);
}

static void edr_registry_normalize_security_path(char *out, size_t out_cap,
                                                 const char *path) {
  static const char machine_prefix[] = "\\REGISTRY\\MACHINE\\";
  static const char user_prefix[] = "\\REGISTRY\\USER\\";
  if (!out || out_cap == 0u) {
    return;
  }
  out[0] = '\0';
  if (!path) {
    return;
  }
  if (_strnicmp(path, machine_prefix, sizeof(machine_prefix) - 1u) == 0) {
    snprintf(out, out_cap, "HKLM\\%s", path + sizeof(machine_prefix) - 1u);
  } else if (_strnicmp(path, user_prefix, sizeof(user_prefix) - 1u) == 0) {
    snprintf(out, out_cap, "HKU\\%s", path + sizeof(user_prefix) - 1u);
  } else {
    snprintf(out, out_cap, "%s", path);
  }
}

static void edr_security_emit_registry_4657(const char *xml) {
  char pid[64];
  char img[1024];
  char key_raw[2048];
  char key[2048];
  char value_name[512];
  char old_value[1024];
  char new_value[1024];
  char user[256];
  char domain[256];
  char safe_img[1024];
  char safe_key[2048];
  char safe_name[512];
  char safe_old[1024];
  char safe_new[1024];
  EdrEventSlot slot;
  int n;
  int has_process_id;
  s_health.security_4657_received++;
  (void)edr_xml_get_data_utf8(xml, "ProcessId", pid, sizeof(pid));
  (void)edr_xml_get_data_utf8(xml, "ProcessName", img, sizeof(img));
  (void)edr_xml_get_data_utf8(xml, "ObjectName", key_raw, sizeof(key_raw));
  (void)edr_xml_get_data_utf8(xml, "ObjectValueName", value_name, sizeof(value_name));
  (void)edr_xml_get_data_utf8(xml, "OldValue", old_value, sizeof(old_value));
  (void)edr_xml_get_data_utf8(xml, "NewValue", new_value, sizeof(new_value));
  (void)edr_xml_get_data_utf8(xml, "SubjectUserName", user, sizeof(user));
  (void)edr_xml_get_data_utf8(xml, "SubjectDomainName", domain, sizeof(domain));
  has_process_id = pid[0] && strtoul(pid, NULL, 0) > 0u;
  edr_registry_normalize_security_path(key, sizeof(key), key_raw);
  if (!key[0]) {
    s_health.registry_payload_missing++;
    return;
  }
  edr_etw1_sanitize_value(safe_img, sizeof(safe_img), img);
  edr_etw1_sanitize_value(safe_key, sizeof(safe_key), key);
  edr_etw1_sanitize_value(safe_name, sizeof(safe_name), value_name);
  edr_etw1_sanitize_value(safe_old, sizeof(safe_old), old_value);
  edr_etw1_sanitize_value(safe_new, sizeof(safe_new), new_value);

  memset(&slot, 0, sizeof(slot));
  slot.timestamp_ns = edr_unix_ns();
  slot.type = EDR_EVENT_REG_SET_VALUE;
  n = snprintf((char *)slot.data, sizeof(slot.data),
               "ETW1\nprov=security_4657\npid=%s\neid=4657\nimg=%s\nuser=%s\n"
               "user_domain=%s\nregkey=%s\nregname=%s\nregold=%s\nregdata=%s\n"
               "regop=set_value\nregistry_source=security_4657\n"
               "registry_attribution=%s\nregistry_detail_status=captured\n",
               pid[0] ? pid : "0", safe_img, user, domain, safe_key, safe_name,
               safe_old, safe_new, has_process_id ? "process_id" : "unavailable");
  if (n <= 0 || (size_t)n >= sizeof(slot.data)) {
    s_health.registry_payload_missing++;
    return;
  }
  slot.size = (uint32_t)n + 1u;
  s_health.registry_provider_events++;
  if (has_process_id) {
    s_health.registry_attributed_events++;
  } else {
    s_health.registry_unattributed_events++;
  }
  s_health.security_audit_visible = 1;
  if (edr_push_slot_after_policy(&slot, "security_4657")) {
    s_health.registry_events_admitted++;
  }
}

static DWORD WINAPI edr_security_eventlog_callback(EVT_SUBSCRIBE_NOTIFY_ACTION action,
                                                   PVOID user_context,
                                                   EVT_HANDLE event) {
  (void)user_context;
  if (action != EvtSubscribeActionDeliver || !s_bus || !event) {
    return ERROR_SUCCESS;
  }
  char *xml = NULL;
  if (!edr_evt_render_xml_utf8(event, &xml)) {
    s_health.collector_dropped++;
    return ERROR_SUCCESS;
  }
  {
    unsigned event_id = edr_xml_event_id(xml);
    if (event_id == 4657u) {
      edr_security_emit_registry_4657(xml);
      free(xml);
      return ERROR_SUCCESS;
    }
    if (event_id != 4688u) {
      free(xml);
      s_health.collector_dropped++;
      return ERROR_SUCCESS;
    }
    s_health.security_4688_received++;
  }
  char img[1024];
  char cmd[2048];
  char epid[64];
  char ppid[64];
  char user[256];
  char domain[256];
  char parent_img[1024];
  char integrity[256];
  char token_elev[64];
  (void)edr_xml_get_data_utf8(xml, "NewProcessName", img, sizeof(img));
  (void)edr_xml_get_data_utf8(xml, "CommandLine", cmd, sizeof(cmd));
  (void)edr_xml_get_data_utf8(xml, "NewProcessId", epid, sizeof(epid));
  (void)edr_xml_get_data_utf8(xml, "ProcessId", ppid, sizeof(ppid));
  (void)edr_xml_get_data_utf8(xml, "SubjectUserName", user, sizeof(user));
  (void)edr_xml_get_data_utf8(xml, "SubjectDomainName", domain, sizeof(domain));
  (void)edr_xml_get_data_utf8(xml, "ParentProcessName", parent_img, sizeof(parent_img));
  (void)edr_xml_get_data_utf8(xml, "MandatoryLabel", integrity, sizeof(integrity));
  (void)edr_xml_get_data_utf8(xml, "TokenElevationType", token_elev, sizeof(token_elev));
  free(xml);
  if (!img[0] && !cmd[0]) {
    s_health.collector_dropped++;
    return ERROR_SUCCESS;
  }
  if (edr_agent_self_suppress_security_event(img, cmd, epid, ppid, parent_img)) {
    edr_agent_self_count_drop_source(edr_unix_ns(), EDR_AGENT_SELF_DROP_SECURITY_EVENT);
    return ERROR_SUCCESS;
  }

  EdrEventSlot slot;
  memset(&slot, 0, sizeof(slot));
  slot.timestamp_ns = edr_unix_ns();
  slot.type = EDR_EVENT_PROCESS_CREATE;
  slot.consumed = false;
  int n = snprintf((char *)slot.data, EDR_MAX_EVENT_PAYLOAD,
                   "ETW1\nprov=sec\npid=%s\neid=4688\nop=0\nimg=%s\ncmd=%s\nepid=%s\nppid=%s\nuser=%s\nuser_domain=%s\nparent_img=%s\nintegrity=%s\ntoken_elevation=%s\n",
                   epid[0] ? epid : "0", img, cmd, epid, ppid, user, domain, parent_img, integrity, token_elev);
  if (n <= 0) {
    s_health.collector_dropped++;
    return ERROR_SUCCESS;
  }
  if ((size_t)n >= EDR_MAX_EVENT_PAYLOAD) {
    n = (int)EDR_MAX_EVENT_PAYLOAD - 1;
    slot.data[n] = '\0';
  }
  slot.size = (uint32_t)n + 1u;
  s_health.security_audit_visible = 1;
  (void)edr_push_slot_after_policy(&slot, "sec");
  return ERROR_SUCCESS;
}

static void edr_collector_pid_cache_update(const EdrBehaviorRecord *br) {
  if (!br || br->pid == 0u) {
    return;
  }
  if (!edr_collector_valid_process_create_record(br)) {
    return;
  }
  if (!br->process_name[0] && !br->exe_path[0] && !br->cmdline[0]) {
    return;
  }
  EdrCollectorPidCacheEntry *slot = NULL;
  for (size_t i = 0; i < EDR_COLLECTOR_PID_CACHE; i++) {
    if (s_pid_cache[i].pid == br->pid) {
      slot = &s_pid_cache[i];
      break;
    }
  }
  if (!slot) {
    slot = &s_pid_cache[s_pid_cache_next++ % EDR_COLLECTOR_PID_CACHE];
    memset(slot, 0, sizeof(*slot));
    slot->pid = br->pid;
  }
  slot->last_seen_ns = br->event_time_ns > 0 ? (uint64_t)br->event_time_ns : edr_unix_ns();
  if (br->process_name[0]) {
    edr_copy_trunc(slot->process_name, sizeof(slot->process_name), br->process_name);
  }
  if (br->exe_path[0]) {
    edr_copy_trunc(slot->exe_path, sizeof(slot->exe_path), br->exe_path);
  }
  if (br->cmdline[0]) {
    edr_copy_trunc(slot->cmdline, sizeof(slot->cmdline), br->cmdline);
  }
}

static void edr_collector_pid_cache_enrich(EdrBehaviorRecord *br) {
  if (!br || br->pid == 0u) {
    return;
  }
  for (size_t i = 0; i < EDR_COLLECTOR_PID_CACHE; i++) {
    EdrCollectorPidCacheEntry *slot = &s_pid_cache[i];
    if (slot->pid != br->pid) {
      continue;
    }
    s_health.process_identity_cache_hits++;
    if (!br->process_name[0] && slot->process_name[0]) {
      edr_copy_trunc(br->process_name, sizeof(br->process_name), slot->process_name);
    }
    if (!br->exe_path[0] && slot->exe_path[0]) {
      edr_copy_trunc(br->exe_path, sizeof(br->exe_path), slot->exe_path);
    }
    if (!br->cmdline[0] && slot->cmdline[0]) {
      edr_copy_trunc(br->cmdline, sizeof(br->cmdline), slot->cmdline);
    }
    return;
  }
  s_health.process_identity_cache_misses++;
}

static void edr_collector_slot_append_kv(EdrEventSlot *slot, const char *key,
                                         const char *value) {
  char safe[2048];
  size_t used;
  int n;
  if (!slot || !key || !key[0] || !value || !value[0]) {
    return;
  }
  used = strnlen((const char *)slot->data, sizeof(slot->data));
  if (used >= sizeof(slot->data) - 4u) {
    return;
  }
  edr_etw1_sanitize_value(safe, sizeof(safe), value);
  if (!safe[0]) {
    return;
  }
  if (used > 0u && slot->data[used - 1u] != '\n') {
    slot->data[used++] = '\n';
    slot->data[used] = '\0';
  }
  n = snprintf((char *)slot->data + used, sizeof(slot->data) - used,
               "%s=%s\n", key, safe);
  if (n <= 0 || (size_t)n >= sizeof(slot->data) - used) {
    return;
  }
  slot->size = (uint32_t)(used + (size_t)n + 1u);
}

static void edr_collector_registry_writeback_identity(EdrEventSlot *slot,
                                                      const EdrBehaviorRecord *br) {
  const char *raw;
  if (!slot || !br || br->pid == 0u ||
      !edr_collector_registry_event_type(slot->type)) {
    return;
  }
  raw = (const char *)slot->data;
  if (!strstr(raw, "\nimg=")) {
    edr_collector_slot_append_kv(slot, "img",
                                 br->exe_path[0] ? br->exe_path : br->process_name);
  }
  raw = (const char *)slot->data;
  if (!strstr(raw, "\ncmd=")) {
    edr_collector_slot_append_kv(slot, "cmd", br->cmdline);
  }
}

static int edr_is_p0_network_port(uint32_t port) {
  static const uint16_t ports[] = {
      22, 88, 135, 139, 389, 445, 464, 593, 636, 1080, 1433, 3128, 3306,
      3389, 5432, 5938, 5985, 5986, 6379, 7070, 8080, 8118, 8443, 9001,
      9050, 9200, 9300, 11211, 27017, 47001,
  };
  for (size_t i = 0; i < sizeof(ports) / sizeof(ports[0]); i++) {
    if (port == ports[i]) {
      return 1;
    }
  }
  return 0;
}

static int edr_collector_process_is_suspicious(const EdrBehaviorRecord *br) {
  static const char *const names[] = {
      "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
      "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe",
      "wmic.exe", "odbcconf.exe", "msbuild.exe", "installutil.exe", "regasm.exe",
      "regsvcs.exe", "psexec.exe", "psexesvc.exe", "paexec.exe", "anydesk.exe",
      "teamviewer.exe", "screenconnect", "connectwise", "ngrok.exe", "frpc.exe",
      "chisel.exe", "plink.exe", "rclone.exe", "curl.exe", "wget.exe",
  };
  const char *pn = br ? br->process_name : "";
  const char *xp = br ? br->exe_path : "";
  const char *cmd = br ? br->cmdline : "";
  if (!br) {
    return 0;
  }
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
    if (edr_contains_ci_path(pn, names[i]) || edr_contains_ci_path(xp, names[i]) ||
        edr_contains_ci_path(cmd, names[i])) {
      return 1;
    }
  }
  if (edr_p0_rule_ir_is_interesting_process_name(pn) ||
      edr_p0_rule_ir_is_interesting_process_name(xp)) {
    return 1;
  }
  return 0;
}

static int edr_network_dest_is_lateral_or_remote_admin(const EdrBehaviorRecord *br) {
  if (!br || br->net_dport == 0u || !br->net_dst[0]) {
    return 0;
  }
  if (br->net_dport == 445u || br->net_dport == 135u || br->net_dport == 139u ||
      br->net_dport == 3389u || br->net_dport == 5985u || br->net_dport == 5986u ||
      br->net_dport == 47001u) {
    return 1;
  }
  return 0;
}

static int edr_collector_file_event_type(EdrEventType t) {
  return t == EDR_EVENT_FILE_CREATE || t == EDR_EVENT_FILE_WRITE ||
         t == EDR_EVENT_FILE_DELETE || t == EDR_EVENT_FILE_RENAME ||
         t == EDR_EVENT_FILE_PERMISSION_CHANGE || t == EDR_EVENT_FILE_READ;
}

static int edr_collector_registry_event_type(EdrEventType t) {
  return t == EDR_EVENT_REG_CREATE_KEY || t == EDR_EVENT_REG_SET_VALUE ||
         t == EDR_EVENT_REG_DELETE_KEY;
}

static int edr_collector_known_low_value_file_record(const EdrBehaviorRecord *br) {
  if (!br) {
    return 0;
  }
  if (!edr_collector_file_event_type(br->type)) {
    return 0;
  }
  const char *path = br->file_path[0] ? br->file_path : br->exe_path;
  if (!path || !path[0]) {
    return 0;
  }
  if (edr_contains_ci_path(path, "__PSScriptPolicyTest_")) {
    return 1;
  }
  if (edr_contains_ci_path(path,
                           "\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Windows\\Caches\\")) {
    return 1;
  }
  if (edr_contains_ci_path(path,
                           "\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\InstallService\\") &&
      edr_contains_ci_path(path, ".catalogItem")) {
    return 1;
  }
  if (edr_contains_ci_path(path,
                           "\\Windows\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\MetaData\\") ||
      edr_contains_ci_path(path,
                           "\\Windows\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\Content\\")) {
    return 1;
  }
  if (edr_contains_ci_path(path,
                           "\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\WindowsApps")) {
    return 1;
  }
  if (edr_contains_ci_path(br->process_name, "svchost.exe") &&
      edr_contains_ci_path(path, "\\Program Files\\WindowsApps\\MicrosoftWindows.Client.WebExperience_") &&
      edr_contains_ci_path(path, "\\Dashboard\\WebContent\\wwwroot\\")) {
    return 1;
  }
  if (edr_contains_ci_path(br->process_name, "MicrosoftEdgeUpdate.exe") &&
      (edr_contains_ci_path(path, "\\Program Files (x86)\\Microsoft\\Temp\\EUF") ||
       edr_contains_ci_path(br->exe_path, "\\Program Files (x86)\\Microsoft\\Temp\\EUF") ||
       edr_contains_ci_path(br->cmdline, "\\Program Files (x86)\\Microsoft\\Temp\\EUF"))) {
    return 1;
  }
  if (edr_contains_ci_path(br->process_name, "MoUsoCoreWorker.exe") &&
      edr_contains_ci_path(path, "\\Windows\\System32\\drivers\\UMDF\\") &&
      edr_contains_ci_path(path, ".dll.mui")) {
    return 1;
  }
  if (edr_contains_ci_path(br->process_name, "backgroundTaskHost.exe") &&
      edr_contains_ci_path(path, "\\Windows\\System32\\Tasks\\Microsoft\\Windows\\InstallService\\SmartRetry")) {
    return 1;
  }
  return 0;
}

static int edr_collector_should_admit_slot(EdrEventSlot *slot) {
  EdrBehaviorRecord br;
  if (!slot) {
    return 0;
  }
  if (edr_env_bool_default("EDR_COLLECTOR_ADMIT_ALL", 0)) {
    return 1;
  }
  edr_behavior_from_slot(slot, &br);
  if (slot->type != EDR_EVENT_PROCESS_CREATE) {
    edr_collector_pid_cache_enrich(&br);
    edr_collector_registry_writeback_identity(slot, &br);
  }
  if ((slot->type == EDR_EVENT_NET_CONNECT || slot->type == EDR_EVENT_NET_LISTEN) &&
      br.exe_path[0] && !br.network_aux_path[0]) {
    edr_copy_trunc(br.network_aux_path, sizeof(br.network_aux_path), br.exe_path);
  }
  if (slot->type == EDR_EVENT_PROCESS_CREATE && edr_collector_valid_process_create_record(&br)) {
    edr_collector_pid_cache_update(&br);
  }
  if (edr_agent_self_suppress_record(&br)) {
    edr_agent_self_count_drop_source(br.event_time_ns > 0 ? (uint64_t)br.event_time_ns : edr_unix_ns(),
                                     EDR_AGENT_SELF_DROP_RECORD);
    return 0;
  }
  if (edr_collector_file_event_type(slot->type) ||
      edr_collector_registry_event_type(slot->type)) {
    edr_windows_event_policy_apply(&br);
    slot->priority = br.priority;
    if (!edr_windows_event_policy_should_emit(&br)) {
      if (edr_collector_registry_event_type(slot->type)) {
        s_health.ordinary_registry_dropped++;
      } else {
        s_health.ordinary_file_dropped++;
      }
      return 0;
    }
    if (edr_p0_rule_ir_br_matches_any(&br)) {
      slot->priority = 0u;
    }
    return 1;
  }
  if (edr_collector_known_low_value_file_record(&br)) {
    s_health.ordinary_file_dropped++;
    return 0;
  }
  if (slot->type == EDR_EVENT_PROCESS_TERMINATE || slot->type == EDR_EVENT_DLL_LOAD) {
    if (edr_adaptive_collection_should_admit_record(&br)) {
      slot->priority = br.priority ? br.priority : 1u;
      return 1;
    }
    int keep = edr_env_bool_default("EDR_COLLECTOR_KEEP_LIFECYCLE", 0);
    if (!keep) {
      s_health.lifecycle_dropped++;
    }
    return keep;
  }
  if (slot->type == EDR_EVENT_AUTH_LOGIN || slot->type == EDR_EVENT_AUTH_LOGOUT) {
    if (edr_adaptive_collection_should_admit_record(&br)) {
      slot->priority = br.priority ? br.priority : 1u;
      return 1;
    }
    int keep = edr_env_bool_default("EDR_COLLECTOR_KEEP_AUTH", 0);
    if (!keep) {
      s_health.auth_dropped++;
    }
    return keep;
  }
  if (br.priority == 0u) {
    slot->priority = 0u;
    return 1;
  }
  if (edr_p0_rule_ir_br_matches_any(&br)) {
    slot->priority = 0u;
    return 1;
  }
  if (edr_adaptive_collection_should_admit_record(&br)) {
    slot->priority = br.priority ? br.priority : 1u;
    return 1;
  }
  if (slot->type == EDR_EVENT_PROCESS_CREATE) {
    if (!edr_collector_valid_process_create_record(&br)) {
      s_health.invalid_process_dropped++;
      if (br.pid != 0u && !br.process_name[0] && !br.exe_path[0] && !br.cmdline[0]) {
        s_health.process_create_missing_identity++;
      }
      return 0;
    }
    return (br.process_name[0] || br.cmdline[0]) ? 1 : 0;
  }
  if (slot->type == EDR_EVENT_FILE_CREATE || slot->type == EDR_EVENT_FILE_WRITE ||
      slot->type == EDR_EVENT_FILE_DELETE || slot->type == EDR_EVENT_FILE_RENAME ||
      slot->type == EDR_EVENT_FILE_PERMISSION_CHANGE || slot->type == EDR_EVENT_FILE_READ ||
      slot->type == EDR_EVENT_REG_CREATE_KEY || slot->type == EDR_EVENT_REG_SET_VALUE ||
      slot->type == EDR_EVENT_REG_DELETE_KEY) {
    edr_windows_event_policy_apply(&br);
    slot->priority = br.priority;
    if (!edr_windows_event_policy_should_emit(&br)) {
      if (slot->type == EDR_EVENT_REG_CREATE_KEY || slot->type == EDR_EVENT_REG_SET_VALUE ||
          slot->type == EDR_EVENT_REG_DELETE_KEY) {
        s_health.ordinary_registry_dropped++;
      } else {
        s_health.ordinary_file_dropped++;
      }
      return 0;
    }
    return 1;
  }
  if (slot->type == EDR_EVENT_NET_CONNECT || slot->type == EDR_EVENT_NET_LISTEN) {
    if (br.net_dport != 0u &&
        (edr_p0_rule_ir_is_interesting_remote_port(br.net_dport) ||
         edr_is_p0_network_port(br.net_dport) ||
         edr_collector_process_is_suspicious(&br) ||
         edr_network_dest_is_lateral_or_remote_admin(&br))) {
      return 1;
    }
    int keep = edr_env_bool_default("EDR_COLLECTOR_KEEP_ALL_NET", 0);
    if (!keep) {
      s_health.ordinary_network_dropped++;
    }
    return keep;
  }
  if (slot->type == EDR_EVENT_SCRIPT_POWERSHELL || slot->type == EDR_EVENT_SCRIPT_WMI ||
      slot->type == EDR_EVENT_NET_DNS_QUERY || slot->type == EDR_EVENT_NET_TLS_HANDSHAKE ||
      slot->type == EDR_EVENT_FIREWALL_RULE_CHANGE || slot->type == EDR_EVENT_PROTOCOL_SHELLCODE ||
      slot->type == EDR_EVENT_WEBSHELL_DETECTED || slot->type == EDR_EVENT_PMFE_SCAN_RESULT ||
      slot->type == EDR_EVENT_BEHAVIOR_ONNX_ALERT) {
    return 1;
  }
  {
    int keep = edr_env_bool_default("EDR_COLLECTOR_KEEP_METADATA", 0);
    if (!keep) {
      s_health.metadata_dropped++;
    }
    return keep;
  }
}

static void edr_collector_decode_mapped_event(PEVENT_RECORD event_record, EdrEventType ty,
                                              const char *tag, uint64_t timestamp_ns) {
  if (!s_bus || !event_record || !tag) {
    return;
  }
  if (ty == EDR_EVENT_PROCESS_CREATE || ty == EDR_EVENT_PROCESS_TERMINATE) {
    edr_pmfe_on_process_lifecycle_hint();
  }
  {
    EdrSensorInterestEvent interest_event;
    if (edr_tdh_build_sensor_interest_event(event_record, ty, tag, &interest_event)) {
      if (ty == EDR_EVENT_PROCESS_TERMINATE && interest_event.pid != 0u) {
        uint64_t exit_time_ns = edr_unix_ns();
        (void)edr_pt_cache_mark_exit(interest_event.pid, exit_time_ns);
        AVE_NotifyProcessExit(interest_event.pid);
      }
      if ((ty == EDR_EVENT_REG_CREATE_KEY || ty == EDR_EVENT_REG_SET_VALUE ||
           ty == EDR_EVENT_REG_DELETE_KEY) && !interest_event.registry_path[0]) {
        s_health.registry_payload_missing++;
      }
      if (edr_agent_self_suppress_interest(&interest_event)) {
        edr_agent_self_count_drop_source(edr_unix_ns(), EDR_AGENT_SELF_DROP_INTEREST);
        return;
      }
      if (!edr_sensor_interest_should_admit(&interest_event)) {
        s_health.collector_dropped++;
        return;
      }
    }
  }

  EdrEventSlot slot;
  memset(&slot, 0, sizeof(slot));
  slot.timestamp_ns = timestamp_ns ? timestamp_ns : edr_unix_ns();
  slot.type = ty;
  slot.consumed = false;

  size_t plen =
      edr_tdh_build_slot_payload(event_record, tag, slot.data, EDR_MAX_EVENT_PAYLOAD);
  if (plen == 0) {
    edr_etw_observability_on_slot_payload_empty();
    return;
  }
  if (plen > EDR_MAX_EVENT_PAYLOAD) {
    plen = EDR_MAX_EVENT_PAYLOAD;
  }
  slot.size = (uint32_t)plen;
  edr_collector_debug_tdh_payload(&slot, tag);
  slot.priority = edr_priority_from_utf8_payload(slot.data, slot.size);
  {
    const GUID *g = &event_record->EventHeader.ProviderId;
    if (memcmp(g, &EDR_ETW_GUID_MICROSOFT_TCPIP, sizeof(GUID)) == 0) {
      USHORT eid = event_record->EventHeader.EventDescriptor.Id;
      slot.priority = (eid == 1002u) ? 1u : 2u;
      slot.attack_surface_hint = 1u;
    } else if (memcmp(g, &EDR_ETW_GUID_WINFIREWALL_WFAS, sizeof(GUID)) == 0) {
      slot.priority = 0u;
      slot.attack_surface_hint = 1u;
    }
  }

  if (!edr_collector_should_admit_slot(&slot)) {
    s_health.collector_dropped++;
    return;
  }

  {
    char ave_ip[46];
    char ave_dom[256];
    edr_tdh_extract_ave_net_fields(event_record, ty, ave_ip, sizeof(ave_ip), ave_dom, sizeof(ave_dom));
    edr_ave_etw_feed_from_event(event_record, ty, slot.timestamp_ns, ave_ip[0] ? ave_ip : NULL,
                                ave_dom[0] ? ave_dom : NULL);
  }

  if (!edr_event_bus_try_push(s_bus, &slot)) {
    s_health.queue_dropped++;
  } else if (ty == EDR_EVENT_REG_CREATE_KEY || ty == EDR_EVENT_REG_SET_VALUE ||
             ty == EDR_EVENT_REG_DELETE_KEY) {
    s_health.registry_events_admitted++;
  }
}

/*
 * A4.4 decoder threads use an owned copy of EVENT_RECORD::UserData.  They
 * deliberately enter below the callback-only self-event filter and type map:
 * those decisions are made before the copy is queued, while all TDH parsing,
 * policy admission, AVE feed and event-bus publication remain identical.
 */
void edr_collector_decode_from_a44_item(const EdrA44QueueItem *item) {
  EVENT_RECORD event_record;
  if (!item || !s_bus) {
    return;
  }
  edr_a44_item_to_event_record(item, &event_record);
  edr_collector_decode_mapped_event(&event_record, item->ty, item->tag, item->ts_ns);
}

static VOID WINAPI edr_event_record_callback(PEVENT_RECORD event_record) {
  if (!s_bus || !event_record) {
    return;
  }
  const GUID *provider = &event_record->EventHeader.ProviderId;
  const char *provider_tag = edr_provider_tag(provider);
  uint64_t now_ns = edr_unix_ns();
  edr_note_provider_callback(provider);
  edr_etw_observability_on_callback(provider_tag);

  if (!edr_collector_keep_agent_self_events() &&
      event_record->EventHeader.ProcessId == (ULONG)s_agent_pid &&
      !(memcmp(provider, &EDR_ETW_GUID_KERNEL_PROCESS, sizeof(GUID)) == 0 &&
        event_record->EventHeader.EventDescriptor.Opcode == 1u)) {
    edr_agent_self_count_drop_source(now_ns, EDR_AGENT_SELF_DROP_DIRECT_PID);
    return;
  }
  if (edr_agent_self_fuse_should_drop_event(event_record, now_ns)) {
    s_agent_self_fuse_suppressed++;
    s_health.agent_self_fuse_provider_suppressed++;
    edr_agent_self_count_drop_source(now_ns, EDR_AGENT_SELF_DROP_DIRECT_PID);
    return;
  }
  EdrEventType ty;
  const char *tag;
  if (!edr_map_type_and_tag(event_record, &ty, &tag)) {
    s_health.etw_prefilter_dropped++;
    s_health.collector_dropped++;
    return;
  }

  if (edr_a44_split_path_enabled()) {
    EdrA44QueueItem item;
    int reason_sync = 0;
    int packed = edr_a44_item_pack(event_record, now_ns, ty, tag, &item, &reason_sync);
    if (packed == 0 && edr_a44_try_push(&item)) {
      return;
    }
    /*
     * The queue is intentionally lossless: records which cannot safely be
     * copied (ExtendedData/oversized payload) and transient full-queue cases
     * stay on the ETW consumer thread and take the exact same decode path.
     */
    (void)reason_sync;
    edr_a44_note_sync_fallback();
  }
  edr_collector_decode_mapped_event(event_record, ty, tag, now_ns);
}

static DWORD WINAPI edr_etw_consumer_thread(void *arg) {
  (void)arg;
  EVENT_TRACE_LOGFILEW logfile;
  memset(&logfile, 0, sizeof(logfile));
  logfile.LoggerName = g_session_name;
  logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME |
                             PROCESS_TRACE_MODE_EVENT_RECORD;
  logfile.EventRecordCallback = edr_event_record_callback;

  TRACEHANDLE th = OpenTraceW(&logfile);
  if (th == INVALID_PROCESSTRACE_HANDLE) {
    return 1u;
  }

  (void)ProcessTrace(&th, 1, NULL, NULL);

  CloseTrace(th);
  return 0;
}

static void edr_stop_named_trace_session(const WCHAR *session_name) {
  ULONG name_bytes;
  ULONG buffer_size;
  EVENT_TRACE_PROPERTIES *prop;
  ULONG status;
  if (!session_name || !session_name[0]) {
    return;
  }
  name_bytes = (ULONG)((wcslen(session_name) + 1u) * sizeof(WCHAR));
  buffer_size = (ULONG)sizeof(EVENT_TRACE_PROPERTIES) + name_bytes;
  prop =
      (EVENT_TRACE_PROPERTIES *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buffer_size);
  if (!prop) {
    return;
  }
  prop->Wnode.BufferSize = buffer_size;
  prop->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
  memcpy((BYTE *)prop + prop->LoggerNameOffset, session_name, name_bytes);
  status = ControlTraceW((TRACEHANDLE)0, session_name, prop, EVENT_TRACE_CONTROL_STOP);
  if (status != ERROR_SUCCESS && status != ERROR_WMI_INSTANCE_NOT_FOUND) {
    fprintf(stderr, "[collector_win] orphan ETW cleanup failed status=%lu\n", (unsigned long)status);
  }
  HeapFree(GetProcessHeap(), 0, prop);
}

void edr_collector_stop_orphan_etw_session(void) {
  edr_stop_named_trace_session(g_session_name);
  edr_stop_named_trace_session(g_registry_session_name);
}

static UCHAR edr_trace_provider_level(const GUID *guid) {
  if (edr_env_bool_default("EDR_ETW_KERNEL_VERBOSE", 0)) {
    return TRACE_LEVEL_VERBOSE;
  }
  if (memcmp(guid, &EDR_ETW_GUID_KERNEL_PROCESS, sizeof(GUID)) == 0 ||
      memcmp(guid, &EDR_ETW_GUID_KERNEL_FILE, sizeof(GUID)) == 0 ||
      memcmp(guid, &EDR_ETW_GUID_KERNEL_NETWORK, sizeof(GUID)) == 0 ||
      memcmp(guid, &EDR_ETW_GUID_KERNEL_REGISTRY, sizeof(GUID)) == 0) {
    return TRACE_LEVEL_INFORMATION;
  }
  return TRACE_LEVEL_VERBOSE;
}

static ULONG edr_enable_trace_provider(TRACEHANDLE session, const GUID *guid) {
  return EnableTraceEx2(session, guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                        edr_trace_provider_level(guid),
                        0xFFFFFFFFFFFFFFFFULL, 0, 0, NULL);
}

static ULONG edr_enable_providers(TRACEHANDLE session, const EdrConfig *cfg) {
  memset(&s_health, 0, sizeof(s_health));
  s_health.etw_or_inotify_enabled = 1;
  const GUID *mandatory[] = {
      &EDR_ETW_GUID_KERNEL_PROCESS,
      &EDR_ETW_GUID_KERNEL_FILE,
      &EDR_ETW_GUID_KERNEL_NETWORK,
      &EDR_ETW_GUID_KERNEL_REGISTRY,
  };
  for (size_t i = 0; i < sizeof(mandatory) / sizeof(mandatory[0]); i++) {
    ULONG err = edr_enable_trace_provider(session, mandatory[i]);
    if (err != ERROR_SUCCESS) {
      return err;
    }
  }

  typedef struct {
    const GUID *guid;
    int want;
	  } OptProv;
	  OptProv optional[] = {
	      {&EDR_ETW_GUID_DNS_CLIENT, cfg && cfg->collection.etw_dns_client_provider},
	      {&EDR_ETW_GUID_POWERSHELL, cfg && cfg->collection.etw_powershell_provider},
	      {&EDR_ETW_GUID_AMSI, cfg && cfg->collection.etw_amsi_provider},
	      {&EDR_ETW_GUID_SCHANNEL, cfg && cfg->collection.etw_schannel_provider},
	      {&EDR_ETW_GUID_SECURITY_AUDIT, cfg && cfg->collection.etw_security_audit_provider},
	      {&EDR_ETW_GUID_WMI_ACTIVITY, cfg && cfg->collection.etw_wmi_provider},
	      {&EDR_ETW_GUID_MICROSOFT_TCPIP, cfg && cfg->collection.etw_tcpip_provider},
	      {&EDR_ETW_GUID_WINFIREWALL_WFAS, cfg && cfg->collection.etw_firewall_provider},
	  };
  for (size_t i = 0; i < sizeof(optional) / sizeof(optional[0]); i++) {
    if (!optional[i].want) {
      continue;
    }
    ULONG err = edr_enable_trace_provider(session, optional[i].guid);
    if (err != ERROR_SUCCESS) {
      fprintf(stderr, "[collector_win] optional ETW provider enable skip guid=%p err=%lu\n",
              (void *)optional[i].guid, (unsigned long)err);
    } else if (memcmp(optional[i].guid, &EDR_ETW_GUID_POWERSHELL, sizeof(GUID)) == 0) {
      s_health.powershell_visible = 1;
    } else if (memcmp(optional[i].guid, &EDR_ETW_GUID_AMSI, sizeof(GUID)) == 0) {
      s_health.amsi_visible = 1;
    } else if (memcmp(optional[i].guid, &EDR_ETW_GUID_SECURITY_AUDIT, sizeof(GUID)) == 0) {
      s_health.security_audit_visible = 1;
    }
  }
  return ERROR_SUCCESS;
}

static void edr_start_security_eventlog_subscription(void) {
  if (s_security_sub) {
    return;
  }
  s_security_sub = EvtSubscribe(NULL, NULL, L"Security",
                                L"*[System[(EventID=4688 or EventID=4657)]]",
                                NULL, NULL, edr_security_eventlog_callback,
                                EvtSubscribeToFutureEvents);
  if (!s_security_sub) {
    DWORD err = GetLastError();
    fprintf(stderr,
            "[collector_win] Security 4688/4657 eventlog subscription disabled err=%lu "
            "(run elevated and enable Audit Process Creation / Audit Registry)\n",
            (unsigned long)err);
  } else {
    s_health.security_subscription_ready = 1;
    s_health.security_audit_visible = 1;
  }
}

EdrError edr_collector_start(EdrEventBus *bus, const EdrConfig *cfg) {
  if (!bus) {
    return EDR_ERR_INVALID_ARG;
  }
  if (!cfg || !cfg->collection.etw_enabled) {
    return EDR_OK;
  }
  if (InterlockedCompareExchange(&s_started, 1, 0) != 0) {
    return EDR_OK;
  }

  s_bus = bus;
  s_collector_cfg = cfg;
  s_agent_pid = GetCurrentProcessId();
  s_agent_exe_path[0] = '\0';
  (void)GetModuleFileNameA(NULL, s_agent_exe_path, (DWORD)sizeof(s_agent_exe_path));
  memset(s_pid_cache, 0, sizeof(s_pid_cache));
  s_pid_cache_next = 0u;
  memset(s_agent_self_pid_cache, 0, sizeof(s_agent_self_pid_cache));
  memset(s_agent_self_seen_ns, 0, sizeof(s_agent_self_seen_ns));
  s_agent_self_pid_next = 0u;
  memset(s_policy_canary_pid_cache, 0, sizeof(s_policy_canary_pid_cache));
  memset(s_policy_canary_seen_ns, 0, sizeof(s_policy_canary_seen_ns));
  s_policy_canary_pid_next = 0u;
  s_agent_self_minute_unix = 0u;
  s_agent_self_minute_count = 0u;
  s_agent_self_fuse_until_ns = 0u;
  s_agent_self_fuse_trips = 0u;
  s_agent_self_fuse_suppressed = 0u;
  s_agent_self_fuse_last_cooldown_ns = 0u;
  s_agent_self_fuse_fast_drop = 0;
  edr_sensor_interest_lazy_init();

  ULONG name_bytes =
      (ULONG)((wcslen(g_session_name) + 1u) * sizeof(WCHAR));
  ULONG buffer_size = (ULONG)sizeof(EVENT_TRACE_PROPERTIES) + name_bytes;
  EVENT_TRACE_PROPERTIES *prop =
      (EVENT_TRACE_PROPERTIES *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buffer_size);
  if (!prop) {
    InterlockedExchange(&s_started, 0);
    return EDR_ERR_INTERNAL;
  }

  prop->Wnode.BufferSize = buffer_size;
  prop->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
  prop->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
  memcpy((BYTE *)prop + prop->LoggerNameOffset, g_session_name, name_bytes);
  prop->BufferSize = 64;
  prop->MinimumBuffers = 32;
  prop->MaximumBuffers = 128;
  prop->FlushTimer = 1;
  prop->LogFileMode =
      EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING;

  ULONG status = StartTraceW(&s_session_handle, g_session_name, prop);
  if (status == ERROR_ALREADY_EXISTS) {
    fprintf(stderr, "[collector_win] ETW session already exists; stopping stale session and retrying\n");
    edr_collector_stop_orphan_etw_session();
    status = StartTraceW(&s_session_handle, g_session_name, prop);
  }
  HeapFree(GetProcessHeap(), 0, prop);

  if (status != ERROR_SUCCESS) {
    fprintf(stderr, "[collector_win] StartTraceW failed session=EDR_Agent_RT_001 status=%lu\n",
            (unsigned long)status);
    s_session_handle = INVALID_PROCESSTRACE_HANDLE;
    InterlockedExchange(&s_started, 0);
    return EDR_ERR_ETW_SESSION_CREATE;
  }

  status = edr_enable_providers(s_session_handle, cfg);
  if (status != ERROR_SUCCESS) {
    fprintf(stderr, "[collector_win] EnableTraceEx2 failed session=EDR_Agent_RT_001 status=%lu\n",
            (unsigned long)status);
    EVENT_TRACE_PROPERTIES stop = {0};
    stop.Wnode.BufferSize = sizeof(stop);
    ControlTraceW(s_session_handle, g_session_name, &stop, EVENT_TRACE_CONTROL_STOP);
    s_session_handle = INVALID_PROCESSTRACE_HANDLE;
    InterlockedExchange(&s_started, 0);
    return EDR_ERR_ETW_PROVIDER_ENABLE;
  }

  /* Remove a stale full-kernel registry session from older Agent builds. */
  edr_stop_named_trace_session(g_registry_session_name);
  if (!edr_start_registry_watch()) {
    fprintf(stderr, "[collector_win] high-value registry watch unavailable err=%lu\n",
            (unsigned long)GetLastError());
  }

  edr_start_security_eventlog_subscription();

  if (edr_a44_split_path_enabled()) {
    EdrError a44_err = edr_a44_split_path_start(s_bus);
    if (a44_err != EDR_OK) {
      /* A4.4 is an optional latency optimization; synchronous ETW decode remains safe. */
      fprintf(stderr, "[collector_win] A4.4 split-path unavailable err=%d; using synchronous decode\n",
              (int)a44_err);
    }
  }

  s_consumer_thread =
      CreateThread(NULL, 0, edr_etw_consumer_thread, NULL, 0, &s_consumer_thread_id);
  if (!s_consumer_thread) {
    EVENT_TRACE_PROPERTIES stop = {0};
    stop.Wnode.BufferSize = sizeof(stop);
    ControlTraceW(s_session_handle, g_session_name, &stop, EVENT_TRACE_CONTROL_STOP);
    s_session_handle = INVALID_PROCESSTRACE_HANDLE;
    if (s_registry_watch_stop_event) {
      SetEvent(s_registry_watch_stop_event);
    }
    if (s_registry_watch_thread) {
      WaitForSingleObject(s_registry_watch_thread, 30000);
      CloseHandle(s_registry_watch_thread);
      s_registry_watch_thread = NULL;
    }
    if (s_registry_watch_stop_event) {
      CloseHandle(s_registry_watch_stop_event);
      s_registry_watch_stop_event = NULL;
    }
    edr_a44_split_path_stop();
    InterlockedExchange(&s_started, 0);
    return EDR_ERR_INTERNAL;
  }

  return EDR_OK;
}

void edr_collector_stop(void) {
  if (InterlockedCompareExchange(&s_started, 0, 1) != 1) {
    return;
  }

  if (s_session_handle != INVALID_PROCESSTRACE_HANDLE) {
    EVENT_TRACE_PROPERTIES stop = {0};
    stop.Wnode.BufferSize = sizeof(stop);
    ControlTraceW(s_session_handle, g_session_name, &stop, EVENT_TRACE_CONTROL_STOP);
    s_session_handle = INVALID_PROCESSTRACE_HANDLE;
  }

  if (s_registry_watch_stop_event) {
    SetEvent(s_registry_watch_stop_event);
  }

  if (s_security_sub) {
    EvtClose(s_security_sub);
    s_security_sub = NULL;
  }

  if (s_consumer_thread) {
    WaitForSingleObject(s_consumer_thread, 30000);
    CloseHandle(s_consumer_thread);
    s_consumer_thread = NULL;
  }

  /* No decoder can retain ETW-owned UserData: it only owns queue copies. */
  edr_a44_split_path_stop();

  if (s_registry_watch_thread) {
    WaitForSingleObject(s_registry_watch_thread, 30000);
    CloseHandle(s_registry_watch_thread);
    s_registry_watch_thread = NULL;
  }
  if (s_registry_watch_stop_event) {
    CloseHandle(s_registry_watch_stop_event);
    s_registry_watch_stop_event = NULL;
  }

  s_agent_self_fuse_fast_drop = 0;
  s_consumer_thread_id = 0u;
  s_registry_watch_thread_id = 0u;
  s_bus = NULL;
  s_collector_cfg = NULL;
}

int edr_collector_get_health(EdrCollectorHealth *out_health) {
  EdrSensorInterestStatus si;
  EdrAdaptiveCollectionStatus adaptive;
  if (!out_health) {
    return -1;
  }
  *out_health = s_health;
  {
    uint64_t now = edr_unix_ns();
    out_health->agent_self_fuse_active = edr_agent_self_fuse_active(now);
    out_health->agent_self_fuse_provider_degraded = 0;
    out_health->agent_self_fuse_fast_drop = s_agent_self_fuse_fast_drop;
    out_health->agent_self_fuse_until_unix_ms =
        s_agent_self_fuse_until_ns > 0u ? (s_agent_self_fuse_until_ns / 1000000ULL) : 0u;
    out_health->agent_self_fuse_trips = s_agent_self_fuse_trips;
    out_health->agent_self_fuse_suppressed = s_agent_self_fuse_suppressed;
    out_health->agent_self_fuse_current_minute_count = s_agent_self_minute_count;
    out_health->agent_self_fuse_threshold_per_min = edr_agent_self_fuse_threshold_per_min();
    out_health->agent_self_fuse_cooldown_s =
        s_agent_self_fuse_last_cooldown_ns > 0u ? s_agent_self_fuse_last_cooldown_ns / 1000000000ULL : 0u;
  }
  out_health->etw_or_inotify_enabled = InterlockedCompareExchange(&s_started, 0, 0) ? 1 : out_health->etw_or_inotify_enabled;
  out_health->collector_thread_id = (uint32_t)s_consumer_thread_id;
  if (s_bus) {
    out_health->queue_dropped = edr_event_bus_dropped_total(s_bus);
  }
  memset(&si, 0, sizeof(si));
  edr_sensor_interest_get_status(&si);
  out_health->sensor_interest_enabled = si.enabled;
  out_health->sensor_interest_loaded = si.loaded;
  snprintf(out_health->sensor_interest_version, sizeof(out_health->sensor_interest_version), "%s", si.version);
  snprintf(out_health->sensor_interest_rules_version, sizeof(out_health->sensor_interest_rules_version), "%s", si.rules_version);
  out_health->sensor_interest_process_names = si.process_name_count;
  out_health->sensor_interest_process_prefixes = si.process_prefix_count;
  out_health->sensor_interest_ports = si.port_count;
  out_health->sensor_interest_file_prefixes = si.file_prefix_count;
  out_health->sensor_interest_file_contains = si.file_contains_count;
  out_health->sensor_interest_registry_prefixes = si.registry_prefix_count;
  out_health->sensor_interest_registry_contains = si.registry_contains_count;
  out_health->sensor_interest_cmd_tokens = si.cmd_token_count;
  out_health->sensor_interest_parent_child_pairs = si.parent_child_pair_count;
  out_health->sensor_interest_required_fields = si.attack_stage_required_field_count;
  out_health->sensor_interest_checked = si.checked;
  out_health->sensor_interest_matched = si.matched;
  out_health->sensor_interest_dropped = si.dropped;
  out_health->sensor_interest_provider_hits = si.provider_hits;
  out_health->sensor_interest_adaptive_hits = si.adaptive_hits;
  out_health->sensor_interest_process_hits = si.process_hits;
  out_health->sensor_interest_port_hits = si.port_hits;
  out_health->sensor_interest_path_hits = si.path_hits;
  out_health->sensor_interest_registry_hits = si.registry_hits;
  out_health->sensor_interest_parent_child_hits = si.parent_child_hits;
  memset(&adaptive, 0, sizeof(adaptive));
  edr_adaptive_collection_get_status(&adaptive);
  out_health->adaptive_collection_enabled = adaptive.enabled;
  out_health->adaptive_collection_active = adaptive.active;
  out_health->adaptive_collection_ttl_s = adaptive.ttl_s;
  out_health->adaptive_collection_remaining_s = adaptive.remaining_s;
  out_health->adaptive_collection_min_severity = adaptive.min_severity;
  out_health->adaptive_collection_level = adaptive.level;
  out_health->adaptive_collection_boosts = adaptive.boosts;
  out_health->adaptive_collection_last_boost_unix_ms = adaptive.last_boost_unix_ms;
  snprintf(out_health->adaptive_collection_last_rule_id,
           sizeof(out_health->adaptive_collection_last_rule_id), "%s", adaptive.last_rule_id);
  return 0;
}
