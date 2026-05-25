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

#include "edr/collector.h"
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
static volatile LONG s_started;
static EdrCollectorHealth s_health;

#define EDR_COLLECTOR_PID_CACHE 512u

typedef struct {
  uint32_t pid;
  uint64_t last_seen_ns;
  char process_name[256];
  char exe_path[512];
  char cmdline[1024];
} EdrCollectorPidCacheEntry;

static EdrCollectorPidCacheEntry s_pid_cache[EDR_COLLECTOR_PID_CACHE];
static uint32_t s_pid_cache_next;

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
    /*
     * Kernel-Process opcode/id varies across Windows builds and manifests. Do
     * not drop unknown process-provider records here; TDH + P0 validation will
     * reject DLL-only/noise records, while real cmd/powershell starts must keep
     * their chance to be parsed.
     */
    (void)ev_id;
    *out_type = EDR_EVENT_PROCESS_CREATE;
    return 1;
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
    /* Kernel-Registry manifest：Opcode 常见为 Task 序号（Create=1 Open=2 DeleteKey=3 SetValue=6 DeleteValue=7） */
    if (op == 1u) {
      *out_type = EDR_EVENT_REG_CREATE_KEY;
      return 1;
    }
    if (op == 2u) {
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
    *out_type = EDR_EVENT_REG_SET_VALUE;
    return 1;
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

static void edr_collector_debug_tdh_payload(const EdrEventSlot *slot, const char *tag) {
  if (!edr_collector_debug_tdh_enabled() || !slot || slot->size == 0u) {
    return;
  }
  if (slot->type != EDR_EVENT_PROCESS_CREATE && slot->type != EDR_EVENT_SCRIPT_POWERSHELL &&
      slot->type != EDR_EVENT_SCRIPT_WMI) {
    return;
  }
  fprintf(stderr, "[TDH DEBUG] tag=%s type=%d payload:\n%.*s\n",
          tag ? tag : "unknown", (int)slot->type, (int)slot->size, (const char *)slot->data);
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

static int edr_collector_should_admit_slot(EdrEventSlot *slot) {
  if (!slot) {
    return 0;
  }
  if (edr_env_bool_default("EDR_COLLECTOR_ADMIT_ALL", 0)) {
    return 1;
  }
  if (slot->type == EDR_EVENT_PROCESS_TERMINATE || slot->type == EDR_EVENT_DLL_LOAD) {
    return edr_env_bool_default("EDR_COLLECTOR_KEEP_LIFECYCLE", 0);
  }
  if (slot->type == EDR_EVENT_AUTH_LOGIN || slot->type == EDR_EVENT_AUTH_LOGOUT) {
    return edr_env_bool_default("EDR_COLLECTOR_KEEP_AUTH", 0);
  }

  EdrBehaviorRecord br;
  edr_behavior_from_slot(slot, &br);
  edr_collector_pid_cache_enrich(&br);
  if ((slot->type == EDR_EVENT_NET_CONNECT || slot->type == EDR_EVENT_NET_LISTEN) &&
      br.exe_path[0] && !br.network_aux_path[0]) {
    edr_copy_trunc(br.network_aux_path, sizeof(br.network_aux_path), br.exe_path);
  }
  if (slot->type == EDR_EVENT_PROCESS_CREATE && edr_collector_valid_process_create_record(&br)) {
    edr_collector_pid_cache_update(&br);
  }
  if (br.priority == 0u) {
    slot->priority = 0u;
    return 1;
  }
  if (edr_p0_rule_ir_br_matches_any(&br)) {
    slot->priority = 0u;
    return 1;
  }
  if (slot->type == EDR_EVENT_PROCESS_CREATE) {
    if (!edr_collector_valid_process_create_record(&br)) {
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
    return edr_windows_event_policy_should_emit(&br);
  }
  if (slot->type == EDR_EVENT_NET_CONNECT || slot->type == EDR_EVENT_NET_LISTEN) {
    if (br.net_dport != 0u &&
        (edr_p0_rule_ir_is_interesting_remote_port(br.net_dport) ||
         edr_is_p0_network_port(br.net_dport) ||
         edr_collector_process_is_suspicious(&br) ||
         edr_network_dest_is_lateral_or_remote_admin(&br))) {
      return 1;
    }
    return edr_env_bool_default("EDR_COLLECTOR_KEEP_ALL_NET", 0);
  }
  if (slot->type == EDR_EVENT_SCRIPT_POWERSHELL || slot->type == EDR_EVENT_SCRIPT_WMI ||
      slot->type == EDR_EVENT_NET_DNS_QUERY || slot->type == EDR_EVENT_NET_TLS_HANDSHAKE ||
      slot->type == EDR_EVENT_FIREWALL_RULE_CHANGE || slot->type == EDR_EVENT_PROTOCOL_SHELLCODE ||
      slot->type == EDR_EVENT_WEBSHELL_DETECTED || slot->type == EDR_EVENT_PMFE_SCAN_RESULT ||
      slot->type == EDR_EVENT_BEHAVIOR_ONNX_ALERT) {
    return 1;
  }
  return edr_env_bool_default("EDR_COLLECTOR_KEEP_METADATA", 0);
}

static VOID WINAPI edr_event_record_callback(PEVENT_RECORD event_record) {
  if (!s_bus || !event_record) {
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
  if (event_record->EventHeader.ProcessId == (ULONG)s_agent_pid) {
    return;
  }
  {
    EdrSensorInterestEvent interest_event;
    if (edr_tdh_build_sensor_interest_event(event_record, ty, tag, &interest_event) &&
        !edr_sensor_interest_should_admit(&interest_event)) {
      s_health.collector_dropped++;
      return;
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
      {&EDR_ETW_GUID_DNS_CLIENT, 1},
      {&EDR_ETW_GUID_POWERSHELL, 1},
      {&EDR_ETW_GUID_AMSI, 1},
      {&EDR_ETW_GUID_SCHANNEL, 1},
      {&EDR_ETW_GUID_SECURITY_AUDIT, 1},
      {&EDR_ETW_GUID_WMI_ACTIVITY, 1},
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
  s_agent_pid = GetCurrentProcessId();
  memset(s_pid_cache, 0, sizeof(s_pid_cache));
  s_pid_cache_next = 0u;
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

  s_consumer_thread =
      CreateThread(NULL, 0, edr_etw_consumer_thread, NULL, 0, NULL);
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

  if (s_consumer_thread) {
    WaitForSingleObject(s_consumer_thread, 30000);
    CloseHandle(s_consumer_thread);
    s_consumer_thread = NULL;
  }

  s_bus = NULL;
}

int edr_collector_get_health(EdrCollectorHealth *out_health) {
  EdrSensorInterestStatus si;
  if (!out_health) {
    return -1;
  }
  *out_health = s_health;
  out_health->etw_or_inotify_enabled = InterlockedCompareExchange(&s_started, 0, 0) ? 1 : out_health->etw_or_inotify_enabled;
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
  out_health->sensor_interest_checked = si.checked;
  out_health->sensor_interest_matched = si.matched;
  out_health->sensor_interest_dropped = si.dropped;
  out_health->sensor_interest_provider_hits = si.provider_hits;
  out_health->sensor_interest_process_hits = si.process_hits;
  out_health->sensor_interest_port_hits = si.port_hits;
  out_health->sensor_interest_path_hits = si.path_hits;
  out_health->sensor_interest_registry_hits = si.registry_hits;
  return 0;
}
