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
#include <winevt.h>

#include "edr/collector.h"
#include "edr/adaptive_collection.h"
#include "edr/behavior_from_slot.h"
#include "edr/config.h"
#include "edr/etw_guids_win.h"
#include "edr/etw_tdh_win.h"
#include "edr/event_bus.h"
#include "edr/p0_rule_ir.h"
#include "edr/pmfe.h"
#include "edr/sensor_interest.h"
#include "edr/types.h"
#include "edr/windows_event_policy.h"

#include "ave_etw_feed_win.h"
#include "edr/etw_tdh_win.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

static WCHAR g_session_name[] = L"EDR_Agent_RT_001";

static EdrEventBus *s_bus;
static DWORD s_agent_pid;
static TRACEHANDLE s_session_handle = INVALID_PROCESSTRACE_HANDLE;
static HANDLE s_consumer_thread;
static DWORD s_consumer_thread_id;
static EVT_HANDLE s_security_sub;
static volatile LONG s_started;
static EdrCollectorHealth s_health;
static const EdrConfig *s_collector_cfg;

#define EDR_COLLECTOR_PID_CACHE 512u
#define EDR_AGENT_SELF_PID_CACHE 128u

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
static char s_agent_exe_path[MAX_PATH];
static uint64_t s_agent_self_minute_unix;
static uint64_t s_agent_self_minute_count;
static uint64_t s_agent_self_fuse_until_ns;
static uint64_t s_agent_self_fuse_trips;
static uint64_t s_agent_self_fuse_suppressed;
static uint64_t s_agent_self_fuse_last_cooldown_ns;
static int s_agent_self_fuse_provider_degraded;

static int edr_collector_should_admit_slot(EdrEventSlot *slot);

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
    if (op == 12) {
      *out_type = EDR_EVENT_FILE_CREATE;
      return 1;
    }
    if (op == 14) {
      *out_type = EDR_EVENT_FILE_WRITE;
      return 1;
    }
    if (op == 16) {
      *out_type = EDR_EVENT_FILE_DELETE;
      return 1;
    }
    *out_type = EDR_EVENT_FILE_WRITE;
    return 1;
  }
  if (memcmp(g, &EDR_ETW_GUID_KERNEL_NETWORK, sizeof(GUID)) == 0) {
    *out_tag = "knet";
    if (op == 15) {
      *out_type = EDR_EVENT_NET_DNS_QUERY;
      return 1;
    }
    *out_type = EDR_EVENT_NET_CONNECT;
    return 1;
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
  snprintf(dst, cap, "%s", src ? src : "");
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

static ULONG edr_control_trace_provider(const GUID *guid, ULONG control_code) {
  if (!guid || s_session_handle == INVALID_PROCESSTRACE_HANDLE) {
    return ERROR_INVALID_HANDLE;
  }
  return EnableTraceEx2(s_session_handle, guid, control_code, TRACE_LEVEL_VERBOSE,
                        0xFFFFFFFFFFFFFFFFULL, 0, 0, NULL);
}

static int edr_optional_provider_wanted(const GUID *guid) {
  if (!guid || !s_collector_cfg) {
    return 0;
  }
  if (memcmp(guid, &EDR_ETW_GUID_MICROSOFT_TCPIP, sizeof(GUID)) == 0) {
    return s_collector_cfg->collection.etw_tcpip_provider ? 1 : 0;
  }
  if (memcmp(guid, &EDR_ETW_GUID_WINFIREWALL_WFAS, sizeof(GUID)) == 0) {
    return s_collector_cfg->collection.etw_firewall_provider ? 1 : 0;
  }
  return 0;
}

static void edr_agent_self_fuse_control_noise_providers(ULONG control_code) {
  typedef struct {
    const GUID *guid;
    int mandatory;
  } NoiseProvider;
  /* During a self-noise fuse we temporarily drop kernel process as well:
   * Security 4688/EventLog remains enabled and keeps ProcessCreate coverage. */
  const NoiseProvider providers[] = {
      {&EDR_ETW_GUID_KERNEL_PROCESS, 1},
      {&EDR_ETW_GUID_KERNEL_FILE, 1},
      {&EDR_ETW_GUID_KERNEL_NETWORK, 1},
      {&EDR_ETW_GUID_KERNEL_REGISTRY, 1},
      {&EDR_ETW_GUID_MICROSOFT_TCPIP, 0},
      {&EDR_ETW_GUID_WINFIREWALL_WFAS, 0},
  };
  for (size_t i = 0; i < sizeof(providers) / sizeof(providers[0]); i++) {
    if (control_code == EVENT_CONTROL_CODE_ENABLE_PROVIDER &&
        !providers[i].mandatory && !edr_optional_provider_wanted(providers[i].guid)) {
      continue;
    }
    (void)edr_control_trace_provider(providers[i].guid, control_code);
  }
}

static void edr_agent_self_fuse_degrade_providers(void) {
  if (s_agent_self_fuse_provider_degraded || edr_collector_keep_agent_self_events()) {
    return;
  }
  edr_agent_self_fuse_control_noise_providers(EVENT_CONTROL_CODE_DISABLE_PROVIDER);
  s_agent_self_fuse_provider_degraded = 1;
}

static void edr_agent_self_fuse_restore_providers(void) {
  if (!s_agent_self_fuse_provider_degraded) {
    return;
  }
  edr_agent_self_fuse_control_noise_providers(EVENT_CONTROL_CODE_ENABLE_PROVIDER);
  s_agent_self_fuse_provider_degraded = 0;
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
  /* Direct PID and sensor-interest self events are already dropped before
   * payload admission; they should not degrade unrelated providers. */
  edr_agent_self_note_suppressed(now_ns,
                                 source != EDR_AGENT_SELF_DROP_DIRECT_PID &&
                                     source != EDR_AGENT_SELF_DROP_INTEREST);
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
  if (edr_contains_ci_path(s, "\\EDR Agent\\edr_agent.exe") ||
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
  return edr_contains_ci_path(s, "edr_agent.exe") || edr_contains_ci_path(s, "edr_agent_setup.exe") ||
         edr_contains_ci_path(s, "edr_agent_install.ps1");
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

static int edr_agent_self_fuse_should_drop_provider(PEVENT_RECORD event_record) {
  if (!event_record || s_agent_self_fuse_until_ns == 0u) {
    return 0;
  }
  if (!edr_agent_self_fuse_active(edr_unix_ns())) {
    return 0;
  }
  const GUID *g = &event_record->EventHeader.ProviderId;
  UCHAR op = event_record->EventHeader.EventDescriptor.Opcode;
  if (memcmp(g, &EDR_ETW_GUID_KERNEL_FILE, sizeof(GUID)) == 0 ||
      memcmp(g, &EDR_ETW_GUID_KERNEL_REGISTRY, sizeof(GUID)) == 0 ||
      memcmp(g, &EDR_ETW_GUID_KERNEL_NETWORK, sizeof(GUID)) == 0 ||
      memcmp(g, &EDR_ETW_GUID_MICROSOFT_TCPIP, sizeof(GUID)) == 0 ||
      memcmp(g, &EDR_ETW_GUID_WINFIREWALL_WFAS, sizeof(GUID)) == 0) {
    return 1;
  }
  if (memcmp(g, &EDR_ETW_GUID_KERNEL_PROCESS, sizeof(GUID)) == 0 && op != 1u) {
    return 1;
  }
  return 0;
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

static int edr_collector_known_low_value_file_record(const EdrBehaviorRecord *br) {
  if (!br) {
    return 0;
  }
  if (!(br->type == EDR_EVENT_FILE_CREATE || br->type == EDR_EVENT_FILE_WRITE ||
        br->type == EDR_EVENT_FILE_DELETE || br->type == EDR_EVENT_FILE_RENAME ||
        br->type == EDR_EVENT_FILE_PERMISSION_CHANGE || br->type == EDR_EVENT_FILE_READ)) {
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
  edr_collector_pid_cache_enrich(&br);
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

static VOID WINAPI edr_event_record_callback(PEVENT_RECORD event_record) {
  if (!s_bus || !event_record) {
    return;
  }
  if (!edr_collector_keep_agent_self_events() &&
      event_record->EventHeader.ProcessId == (ULONG)s_agent_pid) {
    edr_agent_self_count_drop_source(edr_unix_ns(), EDR_AGENT_SELF_DROP_DIRECT_PID);
    return;
  }
  if (edr_agent_self_fuse_should_drop_provider(event_record)) {
    s_agent_self_fuse_suppressed++;
    s_health.agent_self_fuse_provider_suppressed++;
    s_health.collector_dropped++;
    return;
  }
  EdrEventType ty;
  const char *tag;
  if (!edr_map_type_and_tag(event_record, &ty, &tag)) {
    s_health.collector_dropped++;
    return;
  }
  if (ty == EDR_EVENT_PROCESS_CREATE || ty == EDR_EVENT_PROCESS_TERMINATE) {
    edr_pmfe_on_process_lifecycle_hint();
  }
  {
    EdrSensorInterestEvent interest_event;
    if (edr_tdh_build_sensor_interest_event(event_record, ty, tag, &interest_event)) {
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
  slot.timestamp_ns = edr_unix_ns();
  slot.type = ty;
  slot.consumed = false;

  size_t plen =
      edr_tdh_build_slot_payload(event_record, tag, slot.data, EDR_MAX_EVENT_PAYLOAD);
  if (plen == 0) {
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
  }
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

void edr_collector_stop_orphan_etw_session(void) {
  ULONG name_bytes = (ULONG)((wcslen(g_session_name) + 1u) * sizeof(WCHAR));
  ULONG buffer_size = (ULONG)sizeof(EVENT_TRACE_PROPERTIES) + name_bytes;
  EVENT_TRACE_PROPERTIES *prop =
      (EVENT_TRACE_PROPERTIES *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buffer_size);
  if (!prop) {
    return;
  }
  prop->Wnode.BufferSize = buffer_size;
  prop->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
  memcpy((BYTE *)prop + prop->LoggerNameOffset, g_session_name, name_bytes);
  ULONG status = ControlTraceW((TRACEHANDLE)0, g_session_name, prop, EVENT_TRACE_CONTROL_STOP);
  if (status != ERROR_SUCCESS && status != ERROR_WMI_INSTANCE_NOT_FOUND) {
    fprintf(stderr, "[collector_win] orphan ETW cleanup failed session=EDR_Agent_RT_001 status=%lu\n",
            (unsigned long)status);
  }
  HeapFree(GetProcessHeap(), 0, prop);
}

static ULONG edr_enable_trace_provider(TRACEHANDLE session, const GUID *guid) {
  return EnableTraceEx2(session, guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                        TRACE_LEVEL_VERBOSE, 0xFFFFFFFFFFFFFFFFULL, 0, 0, NULL);
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
  s_security_sub = EvtSubscribe(NULL, NULL, L"Security", L"*[System[(EventID=4688)]]",
                                NULL, NULL, edr_security_eventlog_callback,
                                EvtSubscribeToFutureEvents);
  if (!s_security_sub) {
    DWORD err = GetLastError();
    fprintf(stderr,
            "[collector_win] Security 4688 eventlog subscription disabled err=%lu "
            "(run elevated and enable Audit Process Creation)\n",
            (unsigned long)err);
  } else {
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
  s_agent_self_minute_unix = 0u;
  s_agent_self_minute_count = 0u;
  s_agent_self_fuse_until_ns = 0u;
  s_agent_self_fuse_trips = 0u;
  s_agent_self_fuse_suppressed = 0u;
  s_agent_self_fuse_last_cooldown_ns = 0u;
  s_agent_self_fuse_provider_degraded = 0;
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

  edr_start_security_eventlog_subscription();

  s_consumer_thread =
      CreateThread(NULL, 0, edr_etw_consumer_thread, NULL, 0, &s_consumer_thread_id);
  if (!s_consumer_thread) {
    EVENT_TRACE_PROPERTIES stop = {0};
    stop.Wnode.BufferSize = sizeof(stop);
    ControlTraceW(s_session_handle, g_session_name, &stop, EVENT_TRACE_CONTROL_STOP);
    s_session_handle = INVALID_PROCESSTRACE_HANDLE;
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

  if (s_security_sub) {
    EvtClose(s_security_sub);
    s_security_sub = NULL;
  }

  if (s_consumer_thread) {
    WaitForSingleObject(s_consumer_thread, 30000);
    CloseHandle(s_consumer_thread);
    s_consumer_thread = NULL;
  }

  s_agent_self_fuse_provider_degraded = 0;
  s_consumer_thread_id = 0u;
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
    out_health->agent_self_fuse_provider_degraded = s_agent_self_fuse_provider_degraded;
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
