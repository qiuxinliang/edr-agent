/**
 * TDH：TdhGetPropertySize / TdhGetProperty 提取字段并格式化为 UTF-8（§3.1.3）。
 */

#if !defined(_WIN32)
#error etw_tdh_win.c is Windows-only
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <evntcons.h>
#include <tdh.h>

#include "edr/etw_guids_win.h"
#include "edr/etw_tdh_win.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* Kept at the TDH boundary so the observability path can distinguish an
 * expected missing property from a failed TDH call without inspecting event
 * payloads a second time. */
static volatile LONG64 s_tdh_property_api_errors;
static volatile LONG64 s_tdh_property_lines_ok;
static volatile LONG64 s_tdh_property_not_found;

static void edr_tdh_note_property_status(ULONG status) {
  if (status == ERROR_SUCCESS) {
    (void)InterlockedIncrement64(&s_tdh_property_lines_ok);
  } else if (status == ERROR_NOT_FOUND) {
    (void)InterlockedIncrement64(&s_tdh_property_not_found);
  } else {
    (void)InterlockedIncrement64(&s_tdh_property_api_errors);
  }
}

void edr_tdh_win_get_property_stats(int64_t *out_tdh_api_err, int64_t *out_tdh_line_ok) {
  if (out_tdh_api_err) {
    *out_tdh_api_err = (int64_t)InterlockedCompareExchange64(&s_tdh_property_api_errors, 0, 0);
  }
  if (out_tdh_line_ok) {
    *out_tdh_line_ok = (int64_t)InterlockedCompareExchange64(&s_tdh_property_lines_ok, 0, 0);
  }
}

void edr_tdh_win_get_property_stats_ext(int64_t *out_api_err, int64_t *out_line_ok,
                                        int64_t *out_prop_not_found) {
  edr_tdh_win_get_property_stats(out_api_err, out_line_ok);
  if (out_prop_not_found) {
    *out_prop_not_found = (int64_t)InterlockedCompareExchange64(&s_tdh_property_not_found, 0, 0);
  }
}

static size_t append_utf8(char *base, size_t cap, size_t *off, const char *fmt, ...) {
  if (*off >= cap) {
    return 0;
  }
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(base + *off, cap - *off, fmt, ap);
  va_end(ap);
  if (n < 0 || (size_t)n >= cap - *off) {
    *off = cap - 1;
    base[cap - 1] = '\0';
    return 0;
  }
  *off += (size_t)n;
  return (size_t)n;
}

static int utf8_looks_text(const char *s) {
  if (!s || !s[0]) {
    return 0;
  }
  size_t printable = 0;
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    if (*p < 0x20u && *p != '\t') {
      return 0;
    }
    if (*p >= 0x20u && *p != 0x7fu) {
      printable++;
    }
  }
  return printable >= 2u ? 1 : 0;
}

static ULONG edr_prop_utf8(PEVENT_RECORD rec, PCWSTR prop_name, char *out,
                           size_t out_cap) {
  if (!rec || !prop_name || !out || out_cap == 0) {
    return ERROR_INVALID_PARAMETER;
  }
  PROPERTY_DATA_DESCRIPTOR pdd;
  memset(&pdd, 0, sizeof(pdd));
  pdd.PropertyName = (ULONGLONG)(ULONG_PTR)prop_name;
  pdd.ArrayIndex = ULONG_MAX;

  ULONG cb = 0;
  ULONG st = TdhGetPropertySize(rec, 0, NULL, 1, &pdd, &cb);
  if (st != ERROR_SUCCESS || cb == 0 || cb > 65536) {
    ULONG result = st != ERROR_SUCCESS ? st : ERROR_NOT_FOUND;
    edr_tdh_note_property_status(result);
    return result;
  }

  BYTE stack_tmp[4096];
  BYTE *tmp = stack_tmp;
  int heap_tmp = 0;
  if (cb > sizeof(stack_tmp)) {
    tmp = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb);
    if (!tmp) {
      return ERROR_NOT_ENOUGH_MEMORY;
    }
    heap_tmp = 1;
  } else {
    memset(stack_tmp, 0, cb);
  }

  st = TdhGetProperty(rec, 0, NULL, 1, &pdd, cb, tmp);
  if (st != ERROR_SUCCESS) {
    edr_tdh_note_property_status(st);
    if (heap_tmp) {
      HeapFree(GetProcessHeap(), 0, tmp);
    }
    return st;
  }

  if (cb == 4) {
    ULONG v = *(ULONG *)tmp;
    snprintf(out, out_cap, "%lu", (unsigned long)v);
    edr_tdh_note_property_status(ERROR_SUCCESS);
    if (heap_tmp) {
      HeapFree(GetProcessHeap(), 0, tmp);
    }
    return ERROR_SUCCESS;
  }

  if (cb >= 2 && (cb % 2u) == 0) {
    int nchars = (int)(cb / sizeof(WCHAR));
    int n = WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)tmp, nchars, out, (int)out_cap - 1,
                                NULL, NULL);
    if (n > 0) {
      out[n] = '\0';
      if (!utf8_looks_text(out)) {
        if (heap_tmp) {
          HeapFree(GetProcessHeap(), 0, tmp);
        }
        out[0] = '\0';
        edr_tdh_note_property_status(ERROR_NOT_FOUND);
        return ERROR_NOT_FOUND;
      }
      edr_tdh_note_property_status(ERROR_SUCCESS);
      if (heap_tmp) {
        HeapFree(GetProcessHeap(), 0, tmp);
      }
      return ERROR_SUCCESS;
    }
  }

  if (heap_tmp) {
    HeapFree(GetProcessHeap(), 0, tmp);
  }
  edr_tdh_note_property_status(ERROR_NOT_FOUND);
  return ERROR_NOT_FOUND;
}

typedef struct {
  PCWSTR name;
  const char *key;
} EdrPropTry;

static void edr_try_append_all(PEVENT_RECORD rec, const EdrPropTry *tries, size_t n,
                               char *line_buf, size_t line_cap, char *out, size_t out_cap,
                               size_t *off) {
  for (size_t i = 0; i < n; i++) {
    if (edr_prop_utf8(rec, tries[i].name, line_buf, line_cap) == ERROR_SUCCESS &&
        line_buf[0]) {
      append_utf8(out, out_cap, off, "%s=%s\n", tries[i].key, line_buf);
    }
  }
}

static int edr_prop_first_utf8(PEVENT_RECORD rec, const PCWSTR *names, size_t n,
                               char *out, size_t out_cap) {
  if (!out || out_cap == 0u) {
    return 0;
  }
  out[0] = '\0';
  for (size_t i = 0; i < n; i++) {
    if (edr_prop_utf8(rec, names[i], out, out_cap) == ERROR_SUCCESS && out[0]) {
      return 1;
    }
  }
  return 0;
}

static int edr_legacy_registry_key_utf8(PEVENT_RECORD rec, char *out, size_t out_cap) {
  size_t pointer_bytes;
  size_t key_offset;
  size_t wchar_count;
  const WCHAR *key_name;
  int n;
  if (!rec || !out || out_cap < 2u ||
      memcmp(&rec->EventHeader.ProviderId, &EDR_ETW_GUID_LEGACY_REGISTRY, sizeof(GUID)) != 0 ||
      !rec->UserData) {
    return 0;
  }
  out[0] = '\0';
  pointer_bytes = (rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4u : 8u;
  /* Registry_TypeGroup1: InitialTime(8), Status(4), Index(4), KeyHandle(pointer), KeyName(WCHAR[]). */
  key_offset = 16u + pointer_bytes;
  if ((size_t)rec->UserDataLength < key_offset + sizeof(WCHAR)) {
    return 0;
  }
  key_name = (const WCHAR *)((const BYTE *)rec->UserData + key_offset);
  wchar_count = ((size_t)rec->UserDataLength - key_offset) / sizeof(WCHAR);
  size_t len = 0u;
  while (len < wchar_count && key_name[len] != L'\0') {
    len++;
  }
  if (len == 0u || len == wchar_count || len > 32767u) {
    return 0;
  }
  n = WideCharToMultiByte(CP_UTF8, 0, key_name, (int)len, out,
                          (int)out_cap - 1, NULL, NULL);
  if (n <= 0) {
    out[0] = '\0';
    return 0;
  }
  out[n] = '\0';
  if (!utf8_looks_text(out)) {
    out[0] = '\0';
    return 0;
  }
  return 1;
}

static uint32_t edr_parse_u32_ascii(const char *s) {
  uint32_t v = 0;
  if (!s) {
    return 0;
  }
  while (*s == ' ' || *s == '\t') {
    s++;
  }
  if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
    s += 2;
    while ((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'f') || (*s >= 'A' && *s <= 'F')) {
      uint32_t d = 0;
      if (*s >= '0' && *s <= '9') {
        d = (uint32_t)(*s - '0');
      } else if (*s >= 'a' && *s <= 'f') {
        d = (uint32_t)(*s - 'a' + 10);
      } else {
        d = (uint32_t)(*s - 'A' + 10);
      }
      uint32_t nv = (v << 4) | d;
      if (nv < v) {
        return v;
      }
      v = nv;
      s++;
    }
    return v;
  }
  while (*s >= '0' && *s <= '9') {
    uint32_t nv = v * 10u + (uint32_t)(*s - '0');
    if (nv < v) {
      return v;
    }
    v = nv;
    s++;
  }
  return v;
}

int edr_tdh_build_sensor_interest_event(PEVENT_RECORD rec, EdrEventType type,
                                        const char *prov_tag,
                                        EdrSensorInterestEvent *out_event) {
  const GUID *g;
  char tmp[1536];
  if (!rec || !out_event) {
    return 0;
  }
  memset(out_event, 0, sizeof(*out_event));
  out_event->type = type;
  out_event->event_id = rec->EventHeader.EventDescriptor.Id;
  out_event->opcode = rec->EventHeader.EventDescriptor.Opcode;
  out_event->pid = rec->EventHeader.ProcessId;
  snprintf(out_event->provider, sizeof(out_event->provider), "%s", prov_tag ? prov_tag : "unknown");

  static const PCWSTR proc_try[] = {
      L"ImageFileName", L"ImageName", L"Filename", L"ProcessName", L"NewProcessName",
      L"ApplicationName",
  };
  static const PCWSTR parent_proc_try[] = {
      L"ParentProcessName", L"ParentImageName", L"ParentImage", L"ParentProcessPath",
      L"CreatorProcessName",
  };
  static const PCWSTR file_try[] = {
      L"FileName", L"OpenPath", L"Path", L"FileObject",
  };
  static const PCWSTR reg_try[] = {
      L"KeyName", L"RelativeName", L"ValueName", L"CapturedValueName",
  };
  static const PCWSTR port_try[] = {
      L"dport", L"Dport", L"RemotePort", L"rport", L"DestPort", L"DestinationPort",
  };
  static const PCWSTR pid_try[] = {
      L"NewProcessId", L"NewProcessID", L"ProcessId", L"ProcessID", L"PID",
  };
  static const PCWSTR parent_pid_try[] = {
      L"CreatorProcessId", L"ParentProcessId", L"ParentProcessID", L"ParentID", L"ParentId",
  };
  static const PCWSTR cmd_try[] = {
      L"CommandLine", L"Commandline", L"ProcessCommandLine", L"Command", L"ScriptBlockText",
      L"Content", L"Buffer",
  };
  static const PCWSTR dns_qname_try[] = {
      L"QueryName", L"Name", L"HostName",
  };

  (void)edr_prop_first_utf8(rec, proc_try, sizeof(proc_try) / sizeof(proc_try[0]),
                            out_event->process_name, sizeof(out_event->process_name));
  (void)edr_prop_first_utf8(rec, parent_proc_try,
                            sizeof(parent_proc_try) / sizeof(parent_proc_try[0]),
                            out_event->parent_process_name,
                            sizeof(out_event->parent_process_name));
  if (edr_prop_first_utf8(rec, pid_try, sizeof(pid_try) / sizeof(pid_try[0]), tmp, sizeof(tmp))) {
    uint32_t pid = edr_parse_u32_ascii(tmp);
    if (pid != 0u) {
      out_event->pid = pid;
    }
  }
  if (edr_prop_first_utf8(rec, parent_pid_try, sizeof(parent_pid_try) / sizeof(parent_pid_try[0]), tmp, sizeof(tmp))) {
    out_event->parent_pid = edr_parse_u32_ascii(tmp);
  }
  g = &rec->EventHeader.ProviderId;
  if (memcmp(g, &EDR_ETW_GUID_KERNEL_FILE, sizeof(GUID)) == 0) {
    (void)edr_prop_first_utf8(rec, file_try, sizeof(file_try) / sizeof(file_try[0]),
                              out_event->path, sizeof(out_event->path));
  } else if (memcmp(g, &EDR_ETW_GUID_KERNEL_REGISTRY, sizeof(GUID)) == 0 ||
             memcmp(g, &EDR_ETW_GUID_SYSTEM_REGISTRY, sizeof(GUID)) == 0 ||
             memcmp(g, &EDR_ETW_GUID_LEGACY_REGISTRY, sizeof(GUID)) == 0) {
    if (!edr_prop_first_utf8(rec, reg_try, sizeof(reg_try) / sizeof(reg_try[0]),
                             out_event->registry_path, sizeof(out_event->registry_path))) {
      (void)edr_legacy_registry_key_utf8(rec, out_event->registry_path,
                                         sizeof(out_event->registry_path));
    }
    if (!out_event->path[0]) {
      snprintf(out_event->path, sizeof(out_event->path), "%s", out_event->registry_path);
    }
  } else if (type == EDR_EVENT_NET_CONNECT || type == EDR_EVENT_NET_LISTEN ||
             type == EDR_EVENT_NET_DNS_QUERY || type == EDR_EVENT_NET_TLS_HANDSHAKE) {
    if (edr_prop_first_utf8(rec, port_try, sizeof(port_try) / sizeof(port_try[0]), tmp, sizeof(tmp))) {
      out_event->remote_port = edr_parse_u32_ascii(tmp);
    }
    /* DNS 查询：优先把查询名填入 path，供关联引擎按查询名做隧道检测；取不到再回退 cmd_try。 */
    if (type == EDR_EVENT_NET_DNS_QUERY) {
      (void)edr_prop_first_utf8(rec, dns_qname_try, sizeof(dns_qname_try) / sizeof(dns_qname_try[0]),
                                out_event->path, sizeof(out_event->path));
    }
    if (!out_event->path[0]) {
      (void)edr_prop_first_utf8(rec, cmd_try, sizeof(cmd_try) / sizeof(cmd_try[0]),
                                out_event->path, sizeof(out_event->path));
    }
  } else if (type == EDR_EVENT_PROCESS_CREATE || type == EDR_EVENT_SCRIPT_POWERSHELL ||
             type == EDR_EVENT_SCRIPT_WMI) {
    (void)edr_prop_first_utf8(rec, cmd_try, sizeof(cmd_try) / sizeof(cmd_try[0]),
                              out_event->path, sizeof(out_event->path));
  }
  return 1;
}

size_t edr_tdh_build_slot_payload(PEVENT_RECORD rec, const char *prov_tag,
                                  uint8_t *out, size_t out_cap) {
  if (!rec || !out || out_cap < 32) {
    return 0;
  }

  char line[8192];
  size_t off = 0;

  append_utf8((char *)out, out_cap, &off, "ETW1\n");
  append_utf8((char *)out, out_cap, &off, "prov=%s\n",
              prov_tag ? prov_tag : "unknown");
  append_utf8((char *)out, out_cap, &off, "pid=%lu\n",
              (unsigned long)rec->EventHeader.ProcessId);
  append_utf8((char *)out, out_cap, &off, "eid=%u\n",
              (unsigned)rec->EventHeader.EventDescriptor.Id);
  append_utf8((char *)out, out_cap, &off, "op=%u\n",
              (unsigned)rec->EventHeader.EventDescriptor.Opcode);

  const size_t off_after_hdr = off;

  static const EdrPropTry proc_try[] = {
      {L"ImageFileName", "img"}, {L"ImageName", "img"}, {L"Filename", "img"},
      {L"ProcessName", "img"}, {L"NewProcessName", "img"}, {L"ApplicationName", "img"},
      {L"CommandLine", "cmd"}, {L"Commandline", "cmd"},
      {L"ProcessCommandLine", "cmd"}, {L"Command", "cmd"},
      {L"ParentProcessName", "parent_img"}, {L"ParentImageName", "parent_img"},
      {L"ParentImage", "parent_img"}, {L"ParentProcessPath", "parent_img"},
      {L"CreatorProcessName", "parent_img"},
      {L"ParentCommandLine", "parent_cmdline"},
      {L"ParentProcessCommandLine", "parent_cmdline"},
      {L"CreatorCommandLine", "parent_cmdline"},
      {L"CurrentDirectory", "cwd"}, {L"WorkingDirectory", "cwd"},
      {L"ParentProcessId", "ppid"}, {L"ParentProcessID", "ppid"},
      {L"ParentID", "ppid"}, {L"ParentId", "ppid"}, {L"CreatorProcessId", "ppid"},
      {L"ProcessId", "epid"}, {L"ProcessID", "epid"}, {L"PID", "epid"},
      {L"NewProcessId", "epid"}, {L"NewProcessID", "epid"},
  };
  static const EdrPropTry file_try[] = {
      {L"FileName", "file"},
      {L"FileObject", "file"},
      {L"OpenPath", "file"},
  };
  static const EdrPropTry net_try[] = {
      {L"daddr", "dst"}, {L"saddr", "src"}, {L"dport", "dpt"}, {L"sport", "spt"},
      {L"PID", "epid"}, {L"ProcessId", "epid"}, {L"ProcessID", "epid"},
  };
  static const EdrPropTry reg_try[] = {
      {L"PID", "epid"},
      {L"ProcessId", "epid"},
      {L"ProcessID", "epid"},
      {L"KeyName", "regkey"},
      {L"RelativeName", "regpath"},
      {L"ValueName", "regname"},
      {L"CapturedValueName", "regname"},
      {L"ValueData", "regdata"},
  };
  static const EdrPropTry dns_try[] = {
      {L"QueryName", "qname"},
      {L"QueryType", "qtype"},
  };
  static const EdrPropTry ps_try[] = {
      {L"PID", "epid"},
      {L"ProcessId", "epid"},
      {L"ProcessID", "epid"},
      {L"ScriptBlockText", "script"},
      {L"ScriptBlockId", "scriptblock_id"},
      {L"ScriptBlockID", "scriptblock_id"},
      {L"Path", "path"},
  };
  static const EdrPropTry amsi_try[] = {
      {L"PID", "epid"},
      {L"ProcessId", "epid"},
      {L"ProcessID", "epid"},
      {L"ProcessName", "module"},
      {L"ImageName", "module"},
      {L"AppName", "app_name"},
      {L"ApplicationName", "app_name"},
      {L"ContentName", "path"},
      {L"Content", "amsi_content"},
      {L"Buffer", "amsi_content"},
      {L"ScriptContent", "script_content"},
      {L"ScanResult", "amsi_result"},
      {L"Result", "amsi_result"},
      {L"Session", "amsi_session"},
      {L"OriginalSize", "amsi_size"},
      {L"ContentSize", "amsi_size"},
      {L"Hash", "script_hash"},
  };
  static const EdrPropTry schannel_try[] = {
      {L"PID", "epid"},
      {L"ProcessId", "epid"},
      {L"ProcessID", "epid"},
      {L"TargetName", "tls_sni"},
      {L"ServerName", "tls_sni"},
      {L"Sni", "tls_sni"},
      {L"SNI", "tls_sni"},
      {L"HostName", "tls_sni"},
      {L"ErrorCode", "tls_error"},
      {L"Status", "tls_error"},
      {L"AlertDescription", "tls_alert"},
      {L"CertificateHash", "cert_hash"},
      {L"CertHash", "cert_hash"},
      {L"SubjectName", "cert_subject"},
      {L"CertSubjectName", "cert_subject"},
      {L"IssuerName", "cert_issuer"},
      {L"CertIssuerName", "cert_issuer"},
  };
  static const EdrPropTry sec_try[] = {
      {L"SubjectUserName", "user"},
      {L"NewProcessName", "img"},
      {L"ProcessName", "img"},
      {L"CommandLine", "cmd"},
      {L"ParentProcessName", "parent_img"},
      {L"ParentImageName", "parent_img"},
      {L"ParentImage", "parent_img"},
      {L"ParentProcessPath", "parent_img"},
      {L"CreatorProcessName", "parent_img"},
      {L"ParentCommandLine", "parent_cmdline"},
      {L"ParentProcessCommandLine", "parent_cmdline"},
      {L"CreatorCommandLine", "parent_cmdline"},
      {L"CurrentDirectory", "cwd"},
      {L"WorkingDirectory", "cwd"},
      {L"NewProcessId", "epid"},
      {L"NewProcessID", "epid"},
      {L"ProcessId", "epid"},
      {L"ProcessID", "epid"},
      {L"CreatorProcessId", "ppid"},
      {L"ParentProcessId", "ppid"},
      {L"IpAddress", "ip"},
      {L"WorkstationName", "ws"},
  };
  static const EdrPropTry wmi_try[] = {
      {L"Query", "query"},
      {L"Consumer", "consumer"},
  };
  static const EdrPropTry tcpip_try[] = {
      {L"saddr", "src"},       {L"daddr", "dst"}, {L"sport", "spt"}, {L"dport", "dpt"},
      {L"Sport", "spt"},       {L"Dport", "dpt"}, {L"SAddr", "src"}, {L"DAddr", "dst"},
      {L"LocalAddress", "laddr"}, {L"RemoteAddress", "raddr"},
      {L"LocalPort", "lport"},    {L"RemotePort", "rport"},
      {L"PID", "epid"},           {L"ProcessId", "epid"},
  };
  static const EdrPropTry wf_try[] = {
      {L"RuleId", "fw_id"},
      {L"RuleName", "fw_rule"},
      {L"ModifyingApplication", "fw_mod"},
      {L"FilterOrigin", "fw_origin"},
      {L"RemoteAddresses", "fw_remote"},
      {L"LocalPorts", "fw_lports"},
  };

  const GUID *g = &rec->EventHeader.ProviderId;

  if (memcmp(g, &EDR_ETW_GUID_KERNEL_PROCESS, sizeof(GUID)) == 0) {
    edr_try_append_all(rec, proc_try, sizeof(proc_try) / sizeof(proc_try[0]), line,
                       sizeof(line), (char *)out, out_cap, &off);
  } else if (memcmp(g, &EDR_ETW_GUID_KERNEL_FILE, sizeof(GUID)) == 0) {
    edr_try_append_all(rec, file_try, sizeof(file_try) / sizeof(file_try[0]), line,
                       sizeof(line), (char *)out, out_cap, &off);
  } else if (memcmp(g, &EDR_ETW_GUID_KERNEL_NETWORK, sizeof(GUID)) == 0) {
    edr_try_append_all(rec, net_try, sizeof(net_try) / sizeof(net_try[0]), line,
                       sizeof(line), (char *)out, out_cap, &off);
  } else if (memcmp(g, &EDR_ETW_GUID_KERNEL_REGISTRY, sizeof(GUID)) == 0 ||
             memcmp(g, &EDR_ETW_GUID_SYSTEM_REGISTRY, sizeof(GUID)) == 0 ||
             memcmp(g, &EDR_ETW_GUID_LEGACY_REGISTRY, sizeof(GUID)) == 0) {
    edr_try_append_all(rec, reg_try, sizeof(reg_try) / sizeof(reg_try[0]), line,
                       sizeof(line), (char *)out, out_cap, &off);
    if (memcmp(g, &EDR_ETW_GUID_LEGACY_REGISTRY, sizeof(GUID)) == 0 &&
        edr_legacy_registry_key_utf8(rec, line, sizeof(line))) {
      append_utf8((char *)out, out_cap, &off, "regkey=%s\n", line);
    }
  } else if (memcmp(g, &EDR_ETW_GUID_DNS_CLIENT, sizeof(GUID)) == 0) {
    edr_try_append_all(rec, dns_try, sizeof(dns_try) / sizeof(dns_try[0]), line,
                       sizeof(line), (char *)out, out_cap, &off);
  } else if (memcmp(g, &EDR_ETW_GUID_POWERSHELL, sizeof(GUID)) == 0) {
    append_utf8((char *)out, out_cap, &off, "sensor=scriptblock\n");
    append_utf8((char *)out, out_cap, &off, "provider=Microsoft-Windows-PowerShell\n");
    edr_try_append_all(rec, ps_try, sizeof(ps_try) / sizeof(ps_try[0]), line,
                       sizeof(line), (char *)out, out_cap, &off);
  } else if (memcmp(g, &EDR_ETW_GUID_AMSI, sizeof(GUID)) == 0) {
    append_utf8((char *)out, out_cap, &off, "sensor=amsi\n");
    append_utf8((char *)out, out_cap, &off, "provider=Microsoft-Antimalware-Scan-Interface\n");
    edr_try_append_all(rec, amsi_try, sizeof(amsi_try) / sizeof(amsi_try[0]), line,
                       sizeof(line), (char *)out, out_cap, &off);
  } else if (memcmp(g, &EDR_ETW_GUID_SCHANNEL, sizeof(GUID)) == 0) {
    append_utf8((char *)out, out_cap, &off, "sensor=tls_etw\n");
    append_utf8((char *)out, out_cap, &off, "provider=Microsoft-Windows-Schannel\n");
    append_utf8((char *)out, out_cap, &off, "proto=tls\n");
    edr_try_append_all(rec, schannel_try, sizeof(schannel_try) / sizeof(schannel_try[0]), line,
                       sizeof(line), (char *)out, out_cap, &off);
  } else if (memcmp(g, &EDR_ETW_GUID_SECURITY_AUDIT, sizeof(GUID)) == 0) {
    edr_try_append_all(rec, sec_try, sizeof(sec_try) / sizeof(sec_try[0]), line,
                       sizeof(line), (char *)out, out_cap, &off);
  } else if (memcmp(g, &EDR_ETW_GUID_WMI_ACTIVITY, sizeof(GUID)) == 0) {
    edr_try_append_all(rec, wmi_try, sizeof(wmi_try) / sizeof(wmi_try[0]), line,
                       sizeof(line), (char *)out, out_cap, &off);
  } else if (memcmp(g, &EDR_ETW_GUID_MICROSOFT_TCPIP, sizeof(GUID)) == 0) {
    edr_try_append_all(rec, tcpip_try, sizeof(tcpip_try) / sizeof(tcpip_try[0]), line,
                       sizeof(line), (char *)out, out_cap, &off);
  } else if (memcmp(g, &EDR_ETW_GUID_WINFIREWALL_WFAS, sizeof(GUID)) == 0) {
    edr_try_append_all(rec, wf_try, sizeof(wf_try) / sizeof(wf_try[0]), line, sizeof(line),
                       (char *)out, out_cap, &off);
  }

  if (off == off_after_hdr) {
    out[0] = '\0';
    return 0;
  }

  if (off < out_cap) {
    out[off] = '\0';
    return off + 1u;
  }
  out[out_cap - 1] = '\0';
  return out_cap;
}

size_t edr_tdh_extract_ave_net_fields(PEVENT_RECORD rec, EdrEventType ty, char *ip_out, size_t ip_cap,
                                      char *dom_out, size_t dom_cap) {
  if (!rec) {
    return 0;
  }
  if (ip_out && ip_cap) {
    ip_out[0] = '\0';
  }
  if (dom_out && dom_cap) {
    dom_out[0] = '\0';
  }
  char line[1536];

  if (ty == EDR_EVENT_NET_DNS_QUERY) {
    if (dom_out && dom_cap > 1u && edr_prop_utf8(rec, L"QueryName", line, sizeof(line)) == ERROR_SUCCESS &&
        line[0]) {
      snprintf(dom_out, dom_cap, "%s", line);
    }
    return 1;
  }

  static const PCWSTR ip_try[] = {
      L"daddr", L"raddr", L"DAddr", L"RemoteAddress", L"dst", L"saddr", L"LocalAddress",
  };
  if (ip_out && ip_cap > 1u) {
    for (size_t i = 0; i < sizeof(ip_try) / sizeof(ip_try[0]); i++) {
      if (edr_prop_utf8(rec, ip_try[i], line, sizeof(line)) == ERROR_SUCCESS && line[0]) {
        snprintf(ip_out, ip_cap, "%s", line);
        break;
      }
    }
  }
  return 1;
}
