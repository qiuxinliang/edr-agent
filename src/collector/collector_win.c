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
#include "edr/config.h"
#include "edr/etw_guids_win.h"
#include "edr/etw_tdh_win.h"
#include "edr/event_bus.h"
#include "edr/pmfe.h"
#include "edr/types.h"

#include "ave_etw_feed_win.h"
#include "edr/etw_tdh_win.h"

#include <string.h>
#include <stdio.h>
#include <wchar.h>

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
    if (op == 12) {
      *out_type = EDR_EVENT_FILE_CREATE;
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

  const uint64_t ts_ns = edr_unix_ns();
  char ave_ip[46];
  char ave_dom[256];
  edr_tdh_extract_ave_net_fields(event_record, ty, ave_ip, sizeof(ave_ip), ave_dom, sizeof(ave_dom));
  edr_ave_etw_feed_from_event(event_record, ty, ts_ns, ave_ip[0] ? ave_ip : NULL, ave_dom[0] ? ave_dom : NULL);

  EdrEventSlot slot;
  memset(&slot, 0, sizeof(slot));
  slot.timestamp_ns = ts_ns;
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

  (void)edr_event_bus_try_push(s_bus, &slot);
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
      {&EDR_ETW_GUID_DNS_CLIENT, 1},
      {&EDR_ETW_GUID_POWERSHELL, 1},
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
  prop->BufferSize = 64;
  prop->MinimumBuffers = 32;
  prop->MaximumBuffers = 128;
  prop->FlushTimer = 1;
  prop->LogFileMode =
      EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING;

  /* Pass session name explicitly; some builds mis-handle NULL SessionName with LoggerNameOffset. */
  ULONG status = StartTraceW(&s_session_handle, g_session_name, prop);
  if (status != ERROR_SUCCESS) {
    fprintf(stderr,
            "[collector_win] StartTrace failed winerr=%lu (session=%ls). Common: "
            "123=invalid name/properties, 183=stale session name, 5=access denied.\n",
            (unsigned long)status, g_session_name);
    /* 上次进程未正常 StopTrace 时，内核仍占用同名实时会话，导致 ERROR_ALREADY_EXISTS。 */
    if (status == ERROR_ALREADY_EXISTS) {
      ULONG stc = edr_etw_control_trace_stop((TRACEHANDLE)0, g_session_name);
      fprintf(stderr, "[collector_win] ControlTrace STOP stale session winerr=%lu, retry StartTrace\n",
              (unsigned long)stc);
      status = StartTraceW(&s_session_handle, g_session_name, prop);
      if (status == ERROR_SUCCESS) {
        fprintf(stderr, "[collector_win] StartTrace OK after cleanup\n");
      }
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

  s_consumer_thread =
      CreateThread(NULL, 0, edr_etw_consumer_thread, NULL, 0, NULL);
  if (!s_consumer_thread) {
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

  s_bus = NULL;
}
