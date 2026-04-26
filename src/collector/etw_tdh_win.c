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

static int looks_like_utf16le_string(const BYTE *buf, ULONG cb) {
  if (!buf || cb < 4 || (cb % 2u) != 0u) {
    return 0;
  }
  ULONG pairs = cb / 2u;
  ULONG inspect = pairs > 512u ? 512u : pairs;
  ULONG ascii_like = 0;
  ULONG has_wide_nul = 0;
  for (ULONG i = 0; i < inspect; i++) {
    BYTE lo = buf[i * 2u];
    BYTE hi = buf[i * 2u + 1u];
    if (lo == 0 && hi == 0) {
      has_wide_nul = 1;
      break;
    }
    if (hi == 0 &&
        ((lo >= 0x20 && lo <= 0x7e) || lo == '\\' || lo == '/' || lo == ':' || lo == '.' || lo == '-' ||
         lo == '_' || lo == ' ' || lo == '\t')) {
      ascii_like++;
    }
  }
  if (has_wide_nul) {
    return 1;
  }
  /* Binary properties are often even-length; require a reasonable UTF-16LE signal before decoding as wide chars. */
  return inspect > 0 && ascii_like >= (inspect / 3u);
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
    return st != ERROR_SUCCESS ? st : ERROR_NOT_FOUND;
  }

  BYTE *tmp = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb);
  if (!tmp) {
    return ERROR_NOT_ENOUGH_MEMORY;
  }

  st = TdhGetProperty(rec, 0, NULL, 1, &pdd, cb, tmp);
  if (st != ERROR_SUCCESS) {
    HeapFree(GetProcessHeap(), 0, tmp);
    return st;
  }

  if (looks_like_utf16le_string(tmp, cb)) {
    int nchars = (int)(cb / sizeof(WCHAR));
    int n = WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)tmp, nchars, out, (int)out_cap - 1,
                                NULL, NULL);
    if (n > 0) {
      out[n] = '\0';
      HeapFree(GetProcessHeap(), 0, tmp);
      return ERROR_SUCCESS;
    }
  }
  if (cb == 4) {
    ULONG v = *(ULONG *)tmp;
    snprintf(out, out_cap, "%lu", (unsigned long)v);
    HeapFree(GetProcessHeap(), 0, tmp);
    return ERROR_SUCCESS;
  }

  HeapFree(GetProcessHeap(), 0, tmp);
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

static void edr_fallback_raw(PEVENT_RECORD rec, uint8_t *out, size_t out_cap,
                             size_t *written) {
  USHORT n = rec->UserDataLength;
  if (n > out_cap) {
    n = (USHORT)out_cap;
  }
  if (n > 0 && rec->UserData) {
    memcpy(out, rec->UserData, n);
  }
  *written = n;
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
      {L"CommandLine", "cmd"}, {L"Commandline", "cmd"},
      {L"ParentProcessId", "ppid"}, {L"ParentProcessID", "ppid"},
      {L"ProcessId", "epid"}, {L"ProcessID", "epid"},
  };
  static const EdrPropTry file_try[] = {
      {L"FileName", "file"},
      {L"FileObject", "file"},
      {L"OpenPath", "file"},
  };
  static const EdrPropTry net_try[] = {
      {L"daddr", "dst"}, {L"saddr", "src"}, {L"dport", "dpt"}, {L"sport", "spt"},
  };
  static const EdrPropTry reg_try[] = {
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
      {L"ScriptBlockText", "script"},
      {L"Path", "path"},
  };
  static const EdrPropTry sec_try[] = {
      {L"SubjectUserName", "user"},
      {L"NewProcessName", "img"},
      {L"CommandLine", "cmd"},
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
  } else if (memcmp(g, &EDR_ETW_GUID_KERNEL_REGISTRY, sizeof(GUID)) == 0) {
    edr_try_append_all(rec, reg_try, sizeof(reg_try) / sizeof(reg_try[0]), line,
                       sizeof(line), (char *)out, out_cap, &off);
  } else if (memcmp(g, &EDR_ETW_GUID_DNS_CLIENT, sizeof(GUID)) == 0) {
    edr_try_append_all(rec, dns_try, sizeof(dns_try) / sizeof(dns_try[0]), line,
                       sizeof(line), (char *)out, out_cap, &off);
  } else if (memcmp(g, &EDR_ETW_GUID_POWERSHELL, sizeof(GUID)) == 0) {
    edr_try_append_all(rec, ps_try, sizeof(ps_try) / sizeof(ps_try[0]), line,
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

  if (off == off_after_hdr && rec->UserDataLength > 0) {
    size_t w = 0;
    edr_fallback_raw(rec, out, out_cap, &w);
    return w;
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
