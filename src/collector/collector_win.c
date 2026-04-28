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

#include <guiddef.h>
#include <basetsd.h>
#include <initguid.h>

#include <evntcons.h>
#include <evnttrace.h>

#include "edr/collector.h"
#include "edr/config.h"
#include "edr/etw_guids_win.h"
#include "edr/etw_tdh_win.h"
#include "edr/etw_observability_win.h"
#include "edr/edr_a44_split_path_win.h"
#include "edr/event_bus.h"
#include "edr/pmfe.h"
#include "edr/types.h"

#include "ave_etw_feed_win.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <wchar.h>

static volatile LONG s_filter_initialized;
static EdrCollectorEventFilterConfig s_filter_config;
static volatile LONG64 s_filter_stats_dns_client;
static volatile LONG64 s_filter_stats_powershell;
static volatile LONG64 s_filter_stats_tcpip;
static volatile LONG64 s_filter_stats_wmi_activity;

static int edr_parse_uint16_list_with_ranges(const char *str, uint16_t *out_ids, uint32_t max_ids, uint32_t *out_id_count,
                                              EdrEventIdRange *out_ranges, uint32_t max_ranges, uint32_t *out_range_count) {
  if (!str || !str[0]) {
    *out_id_count = 0;
    *out_range_count = 0;
    return 0;
  }
  uint32_t id_count = 0;
  uint32_t range_count = 0;
  const char *p = str;
  while (*p) {
    while (*p == ' ' || *p == '\t') {
      p++;
    }
    if (*p == '\0') {
      break;
    }
    char *end = NULL;
    unsigned long start_val = strtoul(p, &end, 10);
    if (end == p || start_val > 65535) {
      break;
    }
    if (*end == '-') {
      p = end + 1;
      unsigned long end_val = strtoul(p, &end, 10);
      if (end == p || end_val > 65535) {
        break;
      }
      if (range_count < max_ranges) {
        out_ranges[range_count].start = (uint16_t)start_val;
        out_ranges[range_count].end = (uint16_t)end_val;
        range_count++;
      }
    } else {
      if (id_count < max_ids) {
        out_ids[id_count++] = (uint16_t)start_val;
      }
    }
    p = end;
    while (*p == ' ' || *p == '\t') {
      p++;
    }
    if (*p == ',') {
      p++;
    }
  }
  *out_id_count = id_count;
  *out_range_count = range_count;
  return 0;
}

static void edr_init_filter_config(void) {
  if (InterlockedCompareExchange(&s_filter_initialized, 1, 0) != 0) {
    return;
  }
  memset(&s_filter_config, 0, sizeof(s_filter_config));
  const char *mode_str = getenv("EDR_COLLECTOR_EVENTID_FILTER_MODE");
  if (!mode_str || !mode_str[0]) {
    s_filter_config.filtering_enabled = 0;
    return;
  }
  s_filter_config.filtering_enabled = 1;
  if (strcmp(mode_str, "whitelist") == 0 || strcmp(mode_str, "WHITELIST") == 0) {
    s_filter_config.dns_client.mode = EDR_EVENT_FILTER_MODE_WHITELIST;
    s_filter_config.powershell.mode = EDR_EVENT_FILTER_MODE_WHITELIST;
    s_filter_config.tcpip.mode = EDR_EVENT_FILTER_MODE_WHITELIST;
    s_filter_config.wmi_activity.mode = EDR_EVENT_FILTER_MODE_WHITELIST;
  } else if (strcmp(mode_str, "blacklist") == 0 || strcmp(mode_str, "BLACKLIST") == 0) {
    s_filter_config.dns_client.mode = EDR_EVENT_FILTER_MODE_BLACKLIST;
    s_filter_config.powershell.mode = EDR_EVENT_FILTER_MODE_BLACKLIST;
    s_filter_config.tcpip.mode = EDR_EVENT_FILTER_MODE_BLACKLIST;
    s_filter_config.wmi_activity.mode = EDR_EVENT_FILTER_MODE_BLACKLIST;
  }
  const char *dns_list = getenv("EDR_COLLECTOR_EVENTID_DNS_CLIENT_LIST");
  if (dns_list) {
    edr_parse_uint16_list_with_ranges(dns_list, s_filter_config.dns_client.event_ids,
                                      EDR_COLLECTOR_MAX_EVENTID_FILTER, &s_filter_config.dns_client.event_id_count,
                                      s_filter_config.dns_client.ranges,
                                      EDR_COLLECTOR_MAX_EVENTID_RANGES, &s_filter_config.dns_client.range_count);
  }
  const char *ps_list = getenv("EDR_COLLECTOR_EVENTID_POWERSHELL_LIST");
  if (ps_list) {
    edr_parse_uint16_list_with_ranges(ps_list, s_filter_config.powershell.event_ids,
                                      EDR_COLLECTOR_MAX_EVENTID_FILTER, &s_filter_config.powershell.event_id_count,
                                      s_filter_config.powershell.ranges,
                                      EDR_COLLECTOR_MAX_EVENTID_RANGES, &s_filter_config.powershell.range_count);
  }
  const char *tcp_list = getenv("EDR_COLLECTOR_EVENTID_TCPIP_LIST");
  if (tcp_list) {
    edr_parse_uint16_list_with_ranges(tcp_list, s_filter_config.tcpip.event_ids,
                                      EDR_COLLECTOR_MAX_EVENTID_FILTER, &s_filter_config.tcpip.event_id_count,
                                      s_filter_config.tcpip.ranges,
                                      EDR_COLLECTOR_MAX_EVENTID_RANGES, &s_filter_config.tcpip.range_count);
  }
  const char *wmi_list = getenv("EDR_COLLECTOR_EVENTID_WMI_LIST");
  if (wmi_list) {
    edr_parse_uint16_list_with_ranges(wmi_list, s_filter_config.wmi_activity.event_ids,
                                      EDR_COLLECTOR_MAX_EVENTID_FILTER, &s_filter_config.wmi_activity.event_id_count,
                                      s_filter_config.wmi_activity.ranges,
                                      EDR_COLLECTOR_MAX_EVENTID_RANGES, &s_filter_config.wmi_activity.range_count);
  }
  fprintf(stderr, "[collector_win] EventId filter enabled: mode=%s dns=%u/%u ps=%u/%u tcp=%u/%u wmi=%u/%u\n",
          mode_str,
          (unsigned)s_filter_config.dns_client.event_id_count, (unsigned)s_filter_config.dns_client.range_count,
          (unsigned)s_filter_config.powershell.event_id_count, (unsigned)s_filter_config.powershell.range_count,
          (unsigned)s_filter_config.tcpip.event_id_count, (unsigned)s_filter_config.tcpip.range_count,
          (unsigned)s_filter_config.wmi_activity.event_id_count, (unsigned)s_filter_config.wmi_activity.range_count);
}

int edr_collector_get_event_filter_config(EdrCollectorEventFilterConfig *out_config) {
  if (!out_config) {
    return -1;
  }
  if (InterlockedCompareExchange(&s_filter_initialized, 0, 0) == 0) {
    edr_init_filter_config();
  }
  memcpy(out_config, &s_filter_config, sizeof(s_filter_config));
  return 0;
}

static int edr_event_id_in_range(uint16_t event_id, const EdrEventIdRange *ranges, uint32_t range_count) {
  for (uint32_t i = 0; i < range_count; i++) {
    if (event_id >= ranges[i].start && event_id <= ranges[i].end) {
      return 1;
    }
  }
  return 0;
}

int edr_collector_should_filter_event(const char *provider_name, uint16_t event_id) {
  if (InterlockedCompareExchange(&s_filter_initialized, 0, 0) == 0) {
    edr_init_filter_config();
  }
  if (!s_filter_config.filtering_enabled) {
    return 0;
  }
  const EdrEventIdFilter *filter = NULL;
  int provider_index = -1;
  if (provider_name) {
    if (strcmp(provider_name, "DNS_CLIENT") == 0 || strcmp(provider_name, "Microsoft-Windows-DNS-Client") == 0) {
      filter = &s_filter_config.dns_client;
      provider_index = 0;
    } else if (strcmp(provider_name, "POWERSHELL") == 0 || strcmp(provider_name, "Microsoft-Windows-PowerShell") == 0) {
      filter = &s_filter_config.powershell;
      provider_index = 1;
    } else if (strcmp(provider_name, "TCPIP") == 0 || strcmp(provider_name, "Microsoft-Windows-TCPIP") == 0) {
      filter = &s_filter_config.tcpip;
      provider_index = 2;
    } else if (strcmp(provider_name, "WMI_ACTIVITY") == 0 || strcmp(provider_name, "Microsoft-Windows-WMI-Activity") == 0) {
      filter = &s_filter_config.wmi_activity;
      provider_index = 3;
    }
  }
  if (!filter || filter->mode == EDR_EVENT_FILTER_MODE_NONE) {
    return 0;
  }
  if (filter->event_id_count == 0 && filter->range_count == 0) {
    return 0;
  }
  int found = 0;
  for (uint32_t i = 0; i < filter->event_id_count; i++) {
    if (filter->event_ids[i] == event_id) {
      found = 1;
      break;
    }
  }
  if (!found) {
    found = edr_event_id_in_range(event_id, filter->ranges, filter->range_count);
  }
  int should_filter = 0;
  if (filter->mode == EDR_EVENT_FILTER_MODE_WHITELIST) {
    should_filter = found ? 0 : 1;
  } else {
    should_filter = found ? 1 : 0;
  }
  if (should_filter && provider_index >= 0) {
    switch (provider_index) {
      case 0:
        (void)InterlockedIncrement64(&s_filter_stats_dns_client);
        break;
      case 1:
        (void)InterlockedIncrement64(&s_filter_stats_powershell);
        break;
      case 2:
        (void)InterlockedIncrement64(&s_filter_stats_tcpip);
        break;
      case 3:
        (void)InterlockedIncrement64(&s_filter_stats_wmi_activity);
        break;
    }
  }
  return should_filter;
}

int edr_collector_get_filter_stats(EdrCollectorFilterStats *out_stats) {
  if (!out_stats) {
    return -1;
  }
  memset(out_stats, 0, sizeof(*out_stats));
  out_stats->dns_client_filtered = (uint64_t)s_filter_stats_dns_client;
  out_stats->powershell_filtered = (uint64_t)s_filter_stats_powershell;
  out_stats->tcpip_filtered = (uint64_t)s_filter_stats_tcpip;
  out_stats->wmi_activity_filtered = (uint64_t)s_filter_stats_wmi_activity;
  out_stats->total_filtered = out_stats->dns_client_filtered + out_stats->powershell_filtered +
                              out_stats->tcpip_filtered + out_stats->wmi_activity_filtered;
  return 0;
}

/* A4.4 第一期：QPC 差分 → 纳秒（`EDR_A44_CB_PHASE_MEAS=1`） */
static int64_t edr_win_qpc_elapsed_ns(const LARGE_INTEGER *a, const LARGE_INTEGER *b, const LARGE_INTEGER *freq) {
  if (!a || !b || !freq || freq->QuadPart == 0) {
    return 0;
  }
  if (b->QuadPart <= a->QuadPart) {
    return 0;
  }
  return (int64_t)((b->QuadPart - a->QuadPart) * 1000000000LL / freq->QuadPart);
}

static WCHAR g_session_name[] = L"EDR_Agent_RT_001";

static EdrEventBus *s_bus;
static DWORD s_agent_pid;
static TRACEHANDLE s_session_handle = INVALID_PROCESSTRACE_HANDLE;
static HANDLE s_consumer_thread;
static volatile LONG s_started;

/**
 * Stop an ETW session by handle and/or name. Buffer must include LoggerName at LoggerNameOffset;
 * otherwise ControlTraceW often returns ERROR_MORE_DATA (234) with only sizeof(EVENT_TRACE_PROPERTIES).
 */
static ULONG edr_etw_control_trace_stop(TRACEHANDLE session_handle, const WCHAR *session_name) {
  ULONG name_bytes = (ULONG)((wcslen(session_name) + 1u) * sizeof(WCHAR));
  ULONG buffer_size = (ULONG)sizeof(EVENT_TRACE_PROPERTIES) + name_bytes;
  EVENT_TRACE_PROPERTIES *p =
      (EVENT_TRACE_PROPERTIES *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buffer_size);
  if (!p) {
    return ERROR_OUTOFMEMORY;
  }
  p->Wnode.BufferSize = buffer_size;
  p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
  memcpy((BYTE *)p + p->LoggerNameOffset, session_name, name_bytes);
  ULONG stc = ControlTraceW(session_handle, session_name, p, EVENT_TRACE_CONTROL_STOP);
  HeapFree(GetProcessHeap(), 0, p);
  return stc;
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

static void edr_map_type_and_tag(PEVENT_RECORD rec, EdrEventType *out_type,
                                 const char **out_tag) {
  const GUID *g = &rec->EventHeader.ProviderId;
  USHORT ev_id = rec->EventHeader.EventDescriptor.Id;
  UCHAR op = rec->EventHeader.EventDescriptor.Opcode;

  if (memcmp(g, &EDR_ETW_GUID_KERNEL_PROCESS, sizeof(GUID)) == 0) {
    *out_tag = "kproc";
    if (op == 1) {
      *out_type = EDR_EVENT_PROCESS_CREATE;
      return;
    }
    if (op == 2) {
      *out_type = EDR_EVENT_PROCESS_TERMINATE;
      return;
    }
    if (op == 3 || op == 4 || op == 5) {
      *out_type = EDR_EVENT_DLL_LOAD;
      return;
    }
    *out_type = EDR_EVENT_PROCESS_CREATE;
    return;
  }
  if (memcmp(g, &EDR_ETW_GUID_KERNEL_FILE, sizeof(GUID)) == 0) {
    *out_tag = "kfile";
    /* Kernel-File：15=Read（Task 值；12/14/16 为既有 create/write/delete 口径） */
    if (op == 12) {
      *out_type = EDR_EVENT_FILE_CREATE;
      return;
    }
    if (op == 15) {
      *out_type = EDR_EVENT_FILE_READ;
      return;
    }
    if (op == 14) {
      *out_type = EDR_EVENT_FILE_WRITE;
      return;
    }
    if (op == 16) {
      *out_type = EDR_EVENT_FILE_DELETE;
      return;
    }
    *out_type = EDR_EVENT_FILE_WRITE;
    return;
  }
  if (memcmp(g, &EDR_ETW_GUID_KERNEL_NETWORK, sizeof(GUID)) == 0) {
    *out_tag = "knet";
    if (op == 15) {
      *out_type = EDR_EVENT_NET_DNS_QUERY;
      return;
    }
    *out_type = EDR_EVENT_NET_CONNECT;
    return;
  }
  if (memcmp(g, &EDR_ETW_GUID_KERNEL_REGISTRY, sizeof(GUID)) == 0) {
    *out_tag = "kreg";
    /* Kernel-Registry manifest：Opcode 常见为 Task 序号（Create=1 Open=2 DeleteKey=3 SetValue=6 DeleteValue=7） */
    if (op == 1u) {
      *out_type = EDR_EVENT_REG_CREATE_KEY;
      return;
    }
    if (op == 2u) {
      *out_type = EDR_EVENT_REG_CREATE_KEY;
      return;
    }
    if (op == 3u || op == 7u) {
      *out_type = EDR_EVENT_REG_DELETE_KEY;
      return;
    }
    if (op == 6u) {
      *out_type = EDR_EVENT_REG_SET_VALUE;
      return;
    }
    (void)ev_id;
    *out_type = EDR_EVENT_REG_SET_VALUE;
    return;
  }
  if (memcmp(g, &EDR_ETW_GUID_DNS_CLIENT, sizeof(GUID)) == 0) {
    *out_tag = "dns";
    *out_type = EDR_EVENT_NET_DNS_QUERY;
    (void)ev_id;
    return;
  }
  if (memcmp(g, &EDR_ETW_GUID_POWERSHELL, sizeof(GUID)) == 0) {
    *out_tag = "ps";
    *out_type = EDR_EVENT_SCRIPT_POWERSHELL;
    return;
  }
  if (memcmp(g, &EDR_ETW_GUID_SECURITY_AUDIT, sizeof(GUID)) == 0) {
    *out_tag = "sec";
    if (ev_id == 4624) {
      *out_type = EDR_EVENT_AUTH_LOGIN;
      return;
    }
    if (ev_id == 4688) {
      *out_type = EDR_EVENT_PROCESS_CREATE;
      return;
    }
    /* 其他审计事件占位：后续按 ID 细分（如 4625 失败登录） */
    *out_type = EDR_EVENT_AUTH_LOGIN;
    return;
  }
  if (memcmp(g, &EDR_ETW_GUID_WMI_ACTIVITY, sizeof(GUID)) == 0) {
    *out_tag = "wmi";
    *out_type = EDR_EVENT_SCRIPT_WMI;
    (void)op;
    return;
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
    return;
  }
  if (memcmp(g, &EDR_ETW_GUID_WINFIREWALL_WFAS, sizeof(GUID)) == 0) {
    *out_tag = "wf";
    *out_type = EDR_EVENT_FIREWALL_RULE_CHANGE;
    (void)op;
    (void)ev_id;
    return;
  }

  *out_tag = "unk";
  *out_type = EDR_EVENT_PROCESS_CREATE;
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

/**
 * A4.4：解线程/同线程 共用（不再跑 map/pmfe/可观测 回调 计数）。
 * `edr_collector_decode_from_a44_item` 在 edr_a44_split_path_win.c 侧声明。
 */
static int env_file_read_filter_enabled(void) {
  const char *e = getenv("EDR_ETW_FILE_READ_FILTER");
  if (e && (e[0] == '0' || e[0] == 'n' || e[0] == 'N')) {
    return 0;
  }
  return 1;
}

static int env_file_write_filter_enabled(void) {
  const char *e = getenv("EDR_ETW_FILE_WRITE_FILTER");
  if (e && (e[0] == '0' || e[0] == 'n' || e[0] == 'N')) {
    return 0;
  }
  return 1;
}

static int is_high_risk_file_read_path(const char *path) {
  if (!path || !path[0]) return 0;
  const char *high_risk_paths[] = {
    "\\Chrome\\User Data\\",
    "\\Chromium\\User Data\\",
    "\\Microsoft\\Edge\\User Data\\",
    "\\Mozilla\\Firefox\\",
    "\\Opera Software\\",
    "\\NTDS\\",
    "\\config\\sam",
    "\\config\\system",
    "\\config\\security",
    "\\AppData\\Local\\Microsoft\\Credentials\\",
    "\\AppData\\Roaming\\Microsoft\\Credentials\\",
  };
  for (size_t i = 0; i < sizeof(high_risk_paths) / sizeof(high_risk_paths[0]); i++) {
    if (strstr(path, high_risk_paths[i]) != NULL) {
      return 1;
    }
  }
  return 0;
}

static int is_low_value_file_write_path(const char *path) {
  if (!path || !path[0]) return 0;
  const char *low_value_paths[] = {
    "\\Temp\\",
    "\\tmp\\",
    "\\Windows\\Temp\\",
    "\\AppData\\Local\\Temp\\",
    "\\Microsoft\\Windows\\INetCache\\",
    "\\Microsoft\\Windows\\WER\\",
    "\\config\\Update\\",
    "\\SoftwareDistribution\\Update\\",
    "\\SoftwareDistribution\\DataStore\\",
    "\\Windows\\SoftwareDistribution\\",
    "\\$Recycle.Bin\\",
    "\\Recycler\\",
    "\\System Volume Information\\",
    "\\Windows\\WinSxS\\",
    "\\Microsoft\\Windows\Installer\\",
    "\\Prefetch\\",
    "\\Offline Web Pages\\",
  };
  for (size_t i = 0; i < sizeof(low_value_paths) / sizeof(low_value_paths[0]); i++) {
    if (strstr(path, low_value_paths[i]) != NULL) {
      return 1;
    }
  }
  return 0;
}

static int should_collect_file_read(const char *payload, size_t payload_len) {
  if (!env_file_read_filter_enabled()) {
    return 1;
  }
  const char *file_prefix = "\nfile=";
  const char *p = strstr(payload, file_prefix);
  if (!p) {
    return 0;
  }
  p += strlen(file_prefix);
  size_t remaining = payload_len - (size_t)(p - payload);
  char file_path[1024];
  size_t copy_len = remaining < sizeof(file_path) - 1 ? remaining : sizeof(file_path) - 1;
  memcpy(file_path, p, copy_len);
  file_path[copy_len] = '\0';
  char *newline = strchr(file_path, '\n');
  if (newline) *newline = '\0';
  return is_high_risk_file_read_path(file_path);
}

static int should_collect_file_write(const char *payload, size_t payload_len) {
  if (!env_file_write_filter_enabled()) {
    return 1;
  }
  const char *file_prefix = "\nfile=";
  const char *p = strstr(payload, file_prefix);
  if (!p) {
    return 0;
  }
  p += strlen(file_prefix);
  size_t remaining = payload_len - (size_t)(p - payload);
  char file_path[1024];
  size_t copy_len = remaining < sizeof(file_path) - 1 ? remaining : sizeof(file_path) - 1;
  memcpy(file_path, p, copy_len);
  file_path[copy_len] = '\0';
  char *newline = strchr(file_path, '\n');
  if (newline) *newline = '\0';
  return !is_low_value_file_write_path(file_path);
}

static int env_registry_filter_enabled(void) {
  const char *e = getenv("EDR_ETW_REGISTRY_FILTER");
  if (e && (e[0] == '0' || e[0] == 'n' || e[0] == 'N')) {
    return 0;
  }
  return 1;
}

static int is_high_risk_registry_path(const char *path) {
  if (!path || !path[0]) return 0;
  const char *high_risk_paths[] = {
    "\\Services\\",
    "\\Run\\",
    "\\RunOnce\\",
    "\\CurrentVersion\\Run\\",
    "\\CurrentVersion\\RunOnce\\",
    "\\Windows\\CurrentVersion\\Run\\",
    "\\Windows\\CurrentVersion\\RunOnce\\",
    "\\Group Policy\\",
    "\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\",
    "\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\",
    "\\System\\CurrentControlSet\\Services\\",
    "\\Control\\Session Manager\\",
    "\\Environment\\",
    "\\Windows\\CurrentVersion\\Explorer\\",
    "\\AppInit_DLLs\\",
    "\\LoadAppInit_DLLs\\",
    "\\CodeIdentities\\",
    "\\Windows Defender\\",
    "\\Microsoft\\Antimalware\\",
    "\\Symantec\\",
    "\\McAfee\\",
    "\\Norton\\",
    "\\Kaspersky\\",
    "\\ESET\\",
  };
  for (size_t i = 0; i < sizeof(high_risk_paths) / sizeof(high_risk_paths[0]); i++) {
    if (strstr(path, high_risk_paths[i]) != NULL) {
      return 1;
    }
  }
  return 0;
}

static int should_collect_registry(const char *payload, size_t payload_len) {
  if (!env_registry_filter_enabled()) {
    return 1;
  }
  const char *reg_prefix = "\nreg=";
  const char *p = strstr(payload, reg_prefix);
  if (!p) {
    return 0;
  }
  p += strlen(reg_prefix);
  size_t remaining = payload_len - (size_t)(p - payload);
  char reg_path[1024];
  size_t copy_len = remaining < sizeof(reg_path) - 1 ? remaining : sizeof(reg_path) - 1;
  memcpy(reg_path, p, copy_len);
  reg_path[copy_len] = '\0';
  char *newline = strchr(reg_path, '\n');
  if (newline) *newline = '\0';
  return is_high_risk_registry_path(reg_path);
}

#define DNS_DEDUP_SLOTS 256
#define DNS_DEDUP_WINDOW_MS 5000

typedef struct {
  uint32_t pid;
  char qname[256];
  uint64_t last_ts;
} DnsDedupSlot;

static DnsDedupSlot s_dns_dedup[DNS_DEDUP_SLOTS];
static uint32_t s_dns_dedup_next;

static int env_dns_dedup_enabled(void) {
  const char *e = getenv("EDR_ETW_DNS_DEDUP");
  if (e && (e[0] == '0' || e[0] == 'n' || e[0] == 'N')) {
    return 0;
  }
  return 1;
}

static int env_dns_suspicious_only(void) {
  const char *e = getenv("EDR_ETW_DNS_SUSPICIOUS_ONLY");
  if (e && (e[0] == '0' || e[0] == 'n' || e[0] == 'N')) {
    return 0;
  }
  return 1;
}

static int is_suspicious_dns_process(const char *procname) {
  if (!procname || !procname[0]) return 0;
  const char *suspicious_procs[] = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "msiexec.exe",
    "cmstp.exe",
    "msbuild.exe",
    "ftp.exe",
    "telnet.exe",
    "nslookup.exe",
    "nc.exe",
    "netcat.exe",
    "nmap.exe",
    "python.exe",
    "python3.exe",
    "perl.exe",
    "ruby.exe",
    "java.exe",
    "javaw.exe",
    "node.exe",
    "npm.cmd",
    "nodejs",
    "curl.exe",
    "wget.exe",
    "iexplore.exe",
    "edge.exe",
    "chrome.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "svchost.exe",
    "services.exe",
    "lsass.exe",
    "winlogon.exe",
    "explorer.exe",
    "taskhostw.exe",
    "dllhost.exe",
    "conhost.exe",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "fontdrvhost.exe",
    "dwm.exe",
    "runtimebroker.exe",
    "searchui.exe",
    "shellExperienceHost.exe",
    "StartMenuExperienceHost.exe",
    "TextInputHost.exe",
    "SystemSettings.exe",
    "LockApp.exe",
    "UserService.exe",
    "TimeService.exe",
    "WpnService.exe",
    "PushToInstall.exe",
    "OneDrive.exe",
    "SkypeApp.exe",
    "Teams.exe",
    "Outlook.exe",
    "WINWORD.EXE",
    "EXCEL.EXE",
    "POWERPNT.EXE",
    "OUTLOOK.EXE",
    "Lync.exe",
    "EQNEDT32.EXE",
    "fltMC.exe",
    "psinfo.exe",
    "psexec.exe",
    "PsExec64.exe",
    "wmic.exe",
    "cmdex.exe",
    "atbroker.exe",
    "pkgmgr.exe",
    "infdefaultinstall.exe",
    "spoolsv.exe",
    "jucheck.exe",
    "jusched.exe",
    "GoogleUpdate.exe",
    "OneDriveStandaloneUpdater.exe",
    "AVP.exe",
    "avp.exe",
    "ekrn.exe",
    "Ntrtscan.exe",
    "FMiser.exe",
    "McShield.exe",
    "engineserver.exe",
    "mcuihost.exe",
    "mcshield.exe",
    "vstskmgr.exe",
    "workfolders.exe",
    "wmiadap.exe",
    "wmiprvse.exe",
    "repadmin.exe",
    "adInsight.exe",
    "ldifde.exe",
    "csvde.exe",
    "dsquery.exe",
    "ntdsutil.exe",
    "dnscmd.exe",
    "nltest.exe",
    "portqry.exe",
    "qwinsta.exe",
    "quser.exe",
    "tasklist.exe",
    "sc.exe",
    "net.exe",
    "net1.exe",
    "netsh.exe",
    "ipconfig.exe",
    "arp.exe",
    "route.exe",
    "hostname.exe",
    "whoami.exe",
    "gpresult.exe",
    "gpupdate.exe",
    "dir.exe",
    "type.exe",
    "copy.exe",
    "move.exe",
    "del.exe",
    "rd.exe",
    "mkdir.exe",
    "rmdir.exe",
    "icacls.exe",
    "cacls.exe",
    "takeown.exe",
    "cipher.exe",
    "fsutil.exe",
    "compact.exe",
    "attrib.exe",
    "findstr.exe",
    "find.exe",
    "where.exe",
    "set.exe",
    "setlocal.exe",
    "endlocal.exe",
    "cd.exe",
    "pushd.exe",
    "popd.exe",
    "prompt.exe",
    "title.exe",
    "ver.exe",
    "color.exe",
    "cls.exe",
    "pause.exe",
    "exit.exe",
    "cmd.exe",
  };
  for (size_t i = 0; i < sizeof(suspicious_procs) / sizeof(suspicious_procs[0]); i++) {
#ifdef _WIN32
    if (_stricmp(procname, suspicious_procs[i]) == 0) {
      return 1;
    }
#else
    if (strcasecmp(procname, suspicious_procs[i]) == 0) {
      return 1;
    }
#endif
  }
  return 0;
}

static int should_collect_dns_query(uint32_t pid, const char *qname, uint64_t ts_ns) {
  if (!env_dns_dedup_enabled()) {
    return 1;
  }
  if (!qname || !qname[0]) {
    return 1;
  }
  uint64_t window_ms = DNS_DEDUP_WINDOW_MS;
  const char *win_env = getenv("EDR_ETW_DNS_DEDUP_WINDOW_MS");
  if (win_env) {
    window_ms = (uint64_t)atoi(win_env);
    if (window_ms == 0) window_ms = DNS_DEDUP_WINDOW_MS;
  }
  uint64_t now_ms = ts_ns / 1000000ULL;
  for (int i = 0; i < DNS_DEDUP_SLOTS; i++) {
    DnsDedupSlot *s = &s_dns_dedup[i];
    if (s->pid == pid && strcmp(s->qname, qname) == 0) {
      if (now_ms < s->last_ts + window_ms) {
        return 0;
      }
      s->last_ts = now_ms;
      return 1;
    }
  }
  DnsDedupSlot *s = &s_dns_dedup[s_dns_dedup_next % DNS_DEDUP_SLOTS];
  s_dns_dedup_next++;
  s->pid = pid;
  snprintf(s->qname, sizeof(s->qname), "%s", qname);
  s->last_ts = now_ms;
  return 1;
}

static void edr_collector_tdh_to_bus(PEVENT_RECORD rec, EdrEventType ty, const char *tag, uint64_t ts_ns) {
  int a44_meas = edr_etw_observability_a44_cb_phase_meas_enabled();
  LARGE_INTEGER a44_freq;
  LARGE_INTEGER t_a44_pre0;
  LARGE_INTEGER t_a44_pre1;
  LARGE_INTEGER t_a44_tdh1;
  if (a44_meas) {
    (void)QueryPerformanceFrequency(&a44_freq);
    (void)QueryPerformanceCounter(&t_a44_pre0);
  }
  char ave_ip[46];
  char ave_dom[256];
  edr_tdh_extract_ave_net_fields(rec, ty, ave_ip, sizeof(ave_ip), ave_dom, sizeof(ave_dom));
  edr_ave_etw_feed_from_event(rec, ty, ts_ns, ave_ip[0] ? ave_ip : NULL, ave_dom[0] ? ave_dom : NULL);

  EdrEventSlot slot;
  memset(&slot, 0, sizeof(slot));
  slot.timestamp_ns = ts_ns;
  slot.type = ty;
  slot.consumed = false;
  if (a44_meas) {
    (void)QueryPerformanceCounter(&t_a44_pre1);
  }
  size_t plen = edr_tdh_build_slot_payload(rec, tag, slot.data, EDR_MAX_EVENT_PAYLOAD);
  if (a44_meas) {
    (void)QueryPerformanceCounter(&t_a44_tdh1);
    (void)edr_etw_observability_add_a44_phase_ns(0u, edr_win_qpc_elapsed_ns(&t_a44_pre0, &t_a44_pre1, &a44_freq));
    (void)edr_etw_observability_add_a44_phase_ns(1u, edr_win_qpc_elapsed_ns(&t_a44_pre1, &t_a44_tdh1, &a44_freq));
  }
  if (plen == 0) {
    edr_etw_observability_on_slot_payload_empty();
    return;
  }
  if (plen > EDR_MAX_EVENT_PAYLOAD) {
    plen = EDR_MAX_EVENT_PAYLOAD;
  }
  if (ty == EDR_EVENT_FILE_READ && !should_collect_file_read((const char *)slot.data, plen)) {
    return;
  }
  if ((ty == EDR_EVENT_FILE_WRITE || ty == EDR_EVENT_FILE_DELETE) &&
      !should_collect_file_write((const char *)slot.data, plen)) {
    return;
  }
  if ((ty == EDR_EVENT_REG_CREATE_KEY || ty == EDR_EVENT_REG_SET_VALUE || ty == EDR_EVENT_REG_DELETE_KEY) &&
      !should_collect_registry((const char *)slot.data, plen)) {
    return;
  }
  if (ty == EDR_EVENT_NET_DNS_QUERY) {
    if (env_dns_suspicious_only()) {
      const char *proc_prefix = "\nproc=";
      const char *p = strstr((const char *)slot.data, proc_prefix);
      if (!p) {
        return;
      }
      p += strlen(proc_prefix);
      char *newline = strchr(p, '\n');
      size_t proc_len = newline ? (size_t)(newline - p) : strlen(p);
      char procname[64];
      if (proc_len >= sizeof(procname)) proc_len = sizeof(procname) - 1;
      memcpy(procname, p, proc_len);
      procname[proc_len] = '\0';
      if (!is_suspicious_dns_process(procname)) {
        return;
      }
    }
    uint32_t pid = 0;
    const char *pid_prefix = "\nepid=";
    const char *p = strstr((const char *)slot.data, pid_prefix);
    if (p) {
      pid = (uint32_t)atoi(p + strlen(pid_prefix));
    }
    const char *qname_prefix = "\nqname=";
    p = strstr((const char *)slot.data, qname_prefix);
    if (p) {
      p += strlen(qname_prefix);
      char *newline = strchr(p, '\n');
      size_t qname_len = newline ? (size_t)(newline - p) : strlen(p);
      char qname[256];
      if (qname_len >= sizeof(qname)) qname_len = sizeof(qname) - 1;
      memcpy(qname, p, qname_len);
      qname[qname_len] = '\0';
      if (!should_collect_dns_query(pid, qname, ts_ns)) {
        return;
      }
    }
  }
  slot.size = (uint32_t)plen;
  slot.priority = edr_priority_from_utf8_payload(slot.data, slot.size);
  {
    const GUID *g = &rec->EventHeader.ProviderId;
    if (memcmp(g, &EDR_ETW_GUID_MICROSOFT_TCPIP, sizeof(GUID)) == 0) {
      USHORT eid = rec->EventHeader.EventDescriptor.Id;
      slot.priority = (eid == 1002u) ? 1u : 2u;
      slot.attack_surface_hint = 1u;
    } else if (memcmp(g, &EDR_ETW_GUID_WINFIREWALL_WFAS, sizeof(GUID)) == 0) {
      slot.priority = 0u;
      slot.attack_surface_hint = 1u;
    }
  }
  LARGE_INTEGER t_a44_b0, t_a44_b1;
  if (a44_meas) {
    (void)QueryPerformanceCounter(&t_a44_b0);
  }
  (void)edr_event_bus_try_push(s_bus, &slot);
  if (a44_meas) {
    (void)QueryPerformanceCounter(&t_a44_b1);
    (void)edr_etw_observability_add_a44_phase_ns(2u, edr_win_qpc_elapsed_ns(&t_a44_b0, &t_a44_b1, &a44_freq));
  }
}

void edr_collector_decode_from_a44_item(const EdrA44QueueItem *it) {
  if (!it || !s_bus) {
    return;
  }
  EVENT_RECORD ev;
  edr_a44_item_to_event_record(it, &ev);
  edr_collector_tdh_to_bus(&ev, it->ty, it->tag, it->ts_ns);
}

static VOID WINAPI edr_event_record_callback(PEVENT_RECORD event_record) {
  if (!s_bus || !event_record) {
    return;
  }
  EdrEventType ty;
  const char *tag;
  edr_map_type_and_tag(event_record, &ty, &tag);
  if (ty == EDR_EVENT_PROCESS_CREATE || ty == EDR_EVENT_PROCESS_TERMINATE) {
    edr_pmfe_on_process_lifecycle_hint();
  }
  if (event_record->EventHeader.ProcessId == (ULONG)s_agent_pid) {
    return;
  }
  const GUID *provider_g = &event_record->EventHeader.ProviderId;
  int is_mandatory_channel = 0;
  if (memcmp(provider_g, &EDR_ETW_GUID_KERNEL_PROCESS, sizeof(GUID)) == 0 ||
      memcmp(provider_g, &EDR_ETW_GUID_KERNEL_FILE, sizeof(GUID)) == 0 ||
      memcmp(provider_g, &EDR_ETW_GUID_KERNEL_NETWORK, sizeof(GUID)) == 0 ||
      memcmp(provider_g, &EDR_ETW_GUID_KERNEL_REGISTRY, sizeof(GUID)) == 0) {
    is_mandatory_channel = 1;
  }
  if (!is_mandatory_channel) {
    const char *provider_name = NULL;
    if (memcmp(provider_g, &EDR_ETW_GUID_DNS_CLIENT, sizeof(GUID)) == 0) {
      provider_name = "DNS_CLIENT";
    } else if (memcmp(provider_g, &EDR_ETW_GUID_POWERSHELL, sizeof(GUID)) == 0) {
      provider_name = "POWERSHELL";
    } else if (memcmp(provider_g, &EDR_ETW_GUID_MICROSOFT_TCPIP, sizeof(GUID)) == 0) {
      provider_name = "TCPIP";
    } else if (memcmp(provider_g, &EDR_ETW_GUID_WMI_ACTIVITY, sizeof(GUID)) == 0) {
      provider_name = "WMI_ACTIVITY";
    }
    if (provider_name) {
      USHORT ev_id = event_record->EventHeader.EventDescriptor.Id;
      if (edr_collector_should_filter_event(provider_name, ev_id)) {
        return;
      }
    }
  }
  edr_etw_observability_on_callback(tag);

  const uint64_t ts_ns = edr_unix_ns();
  if (edr_a44_split_path_enabled()) {
    EdrA44QueueItem qit;
    int rsn = 0;
    if (edr_a44_item_pack(event_record, ts_ns, ty, tag, &qit, &rsn) == 0) {
      if (edr_a44_try_push(&qit)) {
        return; /* 解线程 继续 Tdh+总线；满队时 try_push=0 则同线程 回落 */
      }
    }
  }
  edr_collector_tdh_to_bus(event_record, ty, tag, ts_ns);
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

static ULONG edr_enable_trace_provider(TRACEHANDLE session, const GUID *guid) {
  return EnableTraceEx2(session, guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                        TRACE_LEVEL_VERBOSE, 0xFFFFFFFFFFFFFFFFULL, 0, 0, NULL);
}

static ULONG edr_enable_providers(TRACEHANDLE session, const EdrConfig *cfg) {
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
  /* Do not set WNODE_FLAG_TRACED_GUID without initializing Wnode.Guid; that yields StartTrace
   * ERROR_INVALID_NAME (123). LoggerName at LoggerNameOffset identifies the session. */
  prop->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
  memcpy((BYTE *)prop + prop->LoggerNameOffset, g_session_name, name_bytes);
  {
    ULONG kb = cfg->collection.etw_buffer_kb;
    if (kb < 4u) {
      kb = 64u;
    }
    if (kb > 1024u) {
      kb = 1024u;
    }
    prop->BufferSize = kb;
  }
  prop->MinimumBuffers = 32;
  prop->MaximumBuffers = 128;
  {
    ULONG fts = cfg->collection.etw_flush_timer_s;
    if (fts < 1u) {
      fts = 1u;
    }
    if (fts > 300u) {
      fts = 300u;
    }
    prop->FlushTimer = fts;
  }
  prop->LogFileMode =
      EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING;

  /* Pass session name explicitly; some builds mis-handle NULL SessionName with LoggerNameOffset. */
  ULONG status = StartTraceW(&s_session_handle, g_session_name, prop);
  if (status != ERROR_SUCCESS) {
    /* 上次进程未正常 StopTrace 时，内核仍占用同名实时会话 -> ERROR_ALREADY_EXISTS (183)。 */
    if (status == ERROR_ALREADY_EXISTS) {
      ULONG stc = edr_etw_control_trace_stop((TRACEHANDLE)0, g_session_name);
      status = StartTraceW(&s_session_handle, g_session_name, prop);
      if (status == ERROR_SUCCESS) {
        fprintf(stderr,
                "[collector_win] ETW session %ls was stale (183); ControlTrace STOP winerr=%lu; "
                "StartTrace OK\n",
                g_session_name, (unsigned long)stc);
      } else {
        fprintf(stderr,
                "[collector_win] StartTrace failed: stale session (183), STOP winerr=%lu, retry "
                "StartTrace winerr=%lu (session=%ls). Common: "
                "123=invalid name/properties, 5=access denied.\n",
                (unsigned long)stc, (unsigned long)status, g_session_name);
      }
    } else {
      fprintf(stderr,
              "[collector_win] StartTrace failed winerr=%lu (session=%ls). Common: "
              "123=invalid name/properties, 183=stale session name, 5=access denied.\n",
              (unsigned long)status, g_session_name);
    }
  }
  HeapFree(GetProcessHeap(), 0, prop);

  if (status != ERROR_SUCCESS) {
    s_session_handle = INVALID_PROCESSTRACE_HANDLE;
    InterlockedExchange(&s_started, 0);
    return EDR_ERR_ETW_SESSION_CREATE;
  }

  status = edr_enable_providers(s_session_handle, cfg);
  if (status != ERROR_SUCCESS) {
    (void)edr_etw_control_trace_stop(s_session_handle, g_session_name);
    s_session_handle = INVALID_PROCESSTRACE_HANDLE;
    InterlockedExchange(&s_started, 0);
    return EDR_ERR_ETW_PROVIDER_ENABLE;
  }

  {
    EdrError a44e = edr_a44_split_path_start(bus);
    if (a44e != EDR_OK) {
      fprintf(stderr, "[collector_win] edr_a44_split_path_start failed: %d (A4.4 收/解 不启用，仍走同线程 Tdh)\n",
              (int)a44e);
    }
  }
  s_consumer_thread =
      CreateThread(NULL, 0, edr_etw_consumer_thread, NULL, 0, NULL);
  if (!s_consumer_thread) {
    edr_a44_split_path_stop();
    (void)edr_etw_control_trace_stop(s_session_handle, g_session_name);
    s_session_handle = INVALID_PROCESSTRACE_HANDLE;
    InterlockedExchange(&s_started, 0);
    return EDR_ERR_INTERNAL;
  }

  return EDR_OK;
}

void edr_collector_stop_orphan_etw_session(void) {
  ULONG st = edr_etw_control_trace_stop((TRACEHANDLE)0, g_session_name);
  if (st != ERROR_SUCCESS) {
    fprintf(stderr,
            "[collector_win] ETW uninstall cleanup ControlTrace STOP winerr=%lu (session=%ls; "
            "nonzero often means session already absent)\n",
            (unsigned long)st, g_session_name);
  }
}

void edr_collector_stop(void) {
  if (InterlockedCompareExchange(&s_started, 0, 1) != 1) {
    return;
  }

  if (s_session_handle != INVALID_PROCESSTRACE_HANDLE) {
    (void)edr_etw_control_trace_stop(s_session_handle, g_session_name);
    s_session_handle = INVALID_PROCESSTRACE_HANDLE;
  }

  if (s_consumer_thread) {
    WaitForSingleObject(s_consumer_thread, 30000);
    CloseHandle(s_consumer_thread);
    s_consumer_thread = NULL;
  }
  edr_a44_split_path_stop();

  s_bus = NULL;
}
