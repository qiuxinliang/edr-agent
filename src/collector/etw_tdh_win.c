/**
 * TDH：TdhGetPropertySize / TdhGetProperty 提取字段并格式化为 UTF-8（§3.1.3）。
 */

#if !defined(_WIN32)
#error etw_tdh_win.c is Windows-only
#endif

#include <windows.h>

#include <guiddef.h>
#include <basetsd.h>
#include <initguid.h>

#include <evntcons.h>
#include <tdh.h>

#include "edr/etw_guids_win.h"
#include "edr/etw_tdh_win.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef LONG EDR_NTSTATUS;
#define EDR_STATUS_SUCCESS ((EDR_NTSTATUS)0x00000000L)
#define EDR_PROCESS_BASIC_INFORMATION 0

typedef struct _EDR_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} EDR_UNICODE_STRING;

typedef struct _EDR_PROCESS_BASIC_INFORMATION {
    PVOID ExitStatus;
    PVOID PebBaseAddress;
    PVOID AffinityMask;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
} EDR_PROCESS_BASIC_INFORMATION;

/* A3.3：可选轻量 TDH（默认关）。=1 时 Microsoft-Windows-DNS-Client 在已解析出 qname 时跳过 QueryType 试探。 */
static int edr_tdh_light_path_a33_enabled(void) {
  const char *e = getenv("EDR_TDH_LIGHT_PATH");
  if (!e || !e[0]) {
    return 0;
  }
  {
    char *endp = NULL;
    long v = strtol(e, &endp, 10);
    if (endp != e && *endp == 0) {
      return v != 0L;
    }
  }
  return (e[0] | 32) == 'y' || (e[0] | 32) == 't';
}

/* A3.3 扩面：Microsoft-Windows-PowerShell，先 ScriptBlock 再全量；须 v1.1+ 会签/白名单 与 EDR_TDH_LIGHT_PATH_PS=1 */
static int edr_tdh_light_path_ps_p1_enabled(void) {
  const char *e = getenv("EDR_TDH_LIGHT_PATH_PS");
  if (!e || !e[0]) {
    return 0;
  }
  {
    char *endp = NULL;
    long v = strtol(e, &endp, 10);
    if (endp != e && *endp == 0) {
      return v != 0L;
    }
  }
  return (e[0] | 32) == 'y' || (e[0] | 32) == 't';
}

/* A3.3+ P1：Microsoft-Windows-TCPIP、EventId 1002（NET_LISTEN）时先试 Local* / PID 子集，未出槽行再全量；默认关。须 EDR_TDH_LIGHT_PATH_TCPIP=1 与会签/P0 对表。 */
static int edr_tdh_light_path_tcpip_p1_enabled(void) {
  const char *e = getenv("EDR_TDH_LIGHT_PATH_TCPIP");
  if (!e || !e[0]) {
    return 0;
  }
  {
    char *endp = NULL;
    long v = strtol(e, &endp, 10);
    if (endp != e && *endp == 0) {
      return v != 0L;
    }
  }
  return (e[0] | 32) == 'y' || (e[0] | 32) == 't';
}

/* A2.1：Tdh 属性拉取复用 thread-local 缓冲，避免每属性 HeapAlloc/HeapFree（仍保留 realloc 失败时单次 Heap 回退） */
#if defined(_MSC_VER)
#define EDR_TL_BUF __declspec(thread)
#else
#define EDR_TL_BUF __thread
#endif
static EDR_TL_BUF BYTE *s_tdh_prop_scratch;
static EDR_TL_BUF size_t s_tdh_prop_scratch_cap;

static volatile LONG64 s_tdh_api_err;
static volatile LONG64 s_tdh_line_ok;
static volatile LONG64 s_tdh_prop_not_found;

static void tdh_stat_api_err_1(void) { (void)InterlockedAdd64(&s_tdh_api_err, 1); }

static void tdh_stat_line_ok_1(void) { (void)InterlockedAdd64(&s_tdh_line_ok, 1); }

static void tdh_stat_not_found_1(void) { (void)InterlockedAdd64(&s_tdh_prop_not_found, 1); }

void edr_tdh_win_get_property_stats(int64_t *out_tdh_api_err, int64_t *out_tdh_line_ok) {
  if (out_tdh_api_err) {
    *out_tdh_api_err = s_tdh_api_err;
  }
  if (out_tdh_line_ok) {
    *out_tdh_line_ok = s_tdh_line_ok;
  }
}

void edr_tdh_win_get_property_stats_ext(int64_t *out_api_err, int64_t *out_line_ok,
                                        int64_t *out_prop_not_found) {
  if (out_api_err)       *out_api_err       = s_tdh_api_err;
  if (out_line_ok)       *out_line_ok       = s_tdh_line_ok;
  if (out_prop_not_found) *out_prop_not_found = s_tdh_prop_not_found;
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

static int looks_like_utf16le_string(const BYTE *buf, ULONG cb) {
  if (!buf || cb < 4 || (cb % 2u) != 0u) {
    return 0;
  }
  ULONG pairs = cb / 2u;
  ULONG inspect = pairs > 512u ? 512u : pairs;
  ULONG ascii_like = 0;
  ULONG hi_zero = 0;
  ULONG has_wide_nul = 0;
  for (ULONG i = 0; i < inspect; i++) {
    BYTE lo = buf[i * 2u];
    BYTE hi = buf[i * 2u + 1u];
    if (lo == 0 && hi == 0) {
      has_wide_nul = 1;
      break;
    }
    if (hi == 0) {
      hi_zero++;
    }
    if (hi == 0 &&
        ((lo >= 0x20 && lo <= 0x7e) || lo == '\\' || lo == '/' || lo == ':' || lo == '.' || lo == '-' ||
         lo == '_' || lo == ' ' || lo == '\t')) {
      ascii_like++;
    }
  }
  if (inspect == 0u) {
    return 0;
  }
  if (hi_zero < (inspect * 8u) / 10u) {
    return 0;
  }
  if (ascii_like < (inspect / 2u)) {
    return 0;
  }
  (void)has_wide_nul;
  return 1;
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
    if (st == ERROR_NOT_FOUND) {
      tdh_stat_not_found_1();
    } else if (st != ERROR_SUCCESS) {
      tdh_stat_api_err_1();
    }
    return st != ERROR_SUCCESS ? st : ERROR_NOT_FOUND;
  }

  int tmp_is_heap = 0;
  BYTE *tmp = NULL;
  if (s_tdh_prop_scratch && cb <= s_tdh_prop_scratch_cap) {
    tmp = s_tdh_prop_scratch;
  } else {
    void *n = realloc(s_tdh_prop_scratch, cb);
    if (n) {
      s_tdh_prop_scratch = (BYTE *)n;
      s_tdh_prop_scratch_cap = cb;
      tmp = s_tdh_prop_scratch;
    } else {
      tmp = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb);
      tmp_is_heap = 1;
    }
  }
  if (!tmp) {
    return ERROR_NOT_ENOUGH_MEMORY;
  }

  st = TdhGetProperty(rec, 0, NULL, 1, &pdd, cb, tmp);
  if (st != ERROR_SUCCESS) {
    tdh_stat_api_err_1();
    if (tmp_is_heap) {
      HeapFree(GetProcessHeap(), 0, tmp);
    }
    return st;
  }

  if (looks_like_utf16le_string(tmp, cb)) {
    int nchars = (int)(cb / sizeof(WCHAR));
    int n = WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)tmp, nchars, out, (int)out_cap - 1,
                                NULL, NULL);
    if (n > 0) {
      out[n] = '\0';
      if (tmp_is_heap) {
        HeapFree(GetProcessHeap(), 0, tmp);
      }
      tdh_stat_line_ok_1();
      return ERROR_SUCCESS;
    }
  }
  if (cb == 4) {
    ULONG v = *(ULONG *)tmp;
    snprintf(out, out_cap, "%lu", (unsigned long)v);
    if (tmp_is_heap) {
      HeapFree(GetProcessHeap(), 0, tmp);
    }
    tdh_stat_line_ok_1();
    return ERROR_SUCCESS;
  }

  if (tmp_is_heap) {
    HeapFree(GetProcessHeap(), 0, tmp);
  }
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

static void edr_try_append_naux_for_net(PEVENT_RECORD rec, char *out, size_t out_cap, size_t *off,
                                        char *line, size_t line_cap) {
  static const PCWSTR naux_names[] = {
      L"Image", L"Module", L"ProcessImage",
  };
  for (size_t i = 0; i < sizeof(naux_names) / sizeof(naux_names[0]); i++) {
    if (edr_prop_utf8(rec, naux_names[i], line, line_cap) == ERROR_SUCCESS && line[0]) {
      append_utf8(out, out_cap, off, "naux=%s\n", line);
      return;
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

static int edr_get_process_cmdline_by_pid(DWORD pid, char *out, size_t out_cap) {
  if (!out || out_cap < 2) {
    return -1;
  }
  *out = '\0';

  HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
  if (!hProcess) {
    return -1;
  }

  typedef EDR_NTSTATUS (WINAPI *EDR_PNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
  static EDR_PNtQueryInformationProcess pNtQueryInformationProcess = NULL;
  if (!pNtQueryInformationProcess) {
    pNtQueryInformationProcess = (EDR_PNtQueryInformationProcess)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    if (!pNtQueryInformationProcess) {
      CloseHandle(hProcess);
      return -1;
    }
  }

  EDR_PROCESS_BASIC_INFORMATION pbi;
  EDR_NTSTATUS status = pNtQueryInformationProcess(hProcess, EDR_PROCESS_BASIC_INFORMATION, &pbi, sizeof(pbi), NULL);
  if (status != EDR_STATUS_SUCCESS || !pbi.PebBaseAddress) {
    CloseHandle(hProcess);
    return -1;
  }

  uintptr_t peb_addr = (uintptr_t)pbi.PebBaseAddress;
  uintptr_t process_params_addr = 0;
  
  if (!ReadProcessMemory(hProcess, (LPCVOID)(peb_addr + 0x20), &process_params_addr, sizeof(process_params_addr), NULL)) {
    CloseHandle(hProcess);
    return -1;
  }

  if (!process_params_addr) {
    CloseHandle(hProcess);
    return -1;
  }

  EDR_UNICODE_STRING cmdline_us;
  uintptr_t cmdline_us_addr = process_params_addr + 0x70;
  if (!ReadProcessMemory(hProcess, (LPCVOID)cmdline_us_addr, &cmdline_us, sizeof(cmdline_us), NULL)) {
    CloseHandle(hProcess);
    return -1;
  }

  if (!cmdline_us.Buffer || cmdline_us.Length == 0) {
    CloseHandle(hProcess);
    return -1;
  }

  WCHAR *wcmd = (WCHAR *)malloc(cmdline_us.Length + sizeof(WCHAR));
  if (!wcmd) {
    CloseHandle(hProcess);
    return -1;
  }

  if (!ReadProcessMemory(hProcess, cmdline_us.Buffer, wcmd, cmdline_us.Length, NULL)) {
    free(wcmd);
    CloseHandle(hProcess);
    return -1;
  }

  wcmd[cmdline_us.Length / sizeof(WCHAR)] = L'\0';

  int n = WideCharToMultiByte(CP_UTF8, 0, wcmd, -1, out, (int)out_cap - 1, NULL, NULL);
  if (n > 0) {
    out[n] = '\0';
  }

  free(wcmd);
  CloseHandle(hProcess);
  return 0;
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
      {L"CommandLine", "cmd"},
      {L"Commandline", "cmd"},
      {L"ImageFileName", "img"},
      {L"ImageName", "img"},
      {L"Filename", "img"},
      {L"ParentProcessId", "ppid"},
      {L"ParentProcessID", "ppid"},
      {L"ParentImage", "pimg"},
      {L"ParentFileName", "pimg"},
      {L"ProcessId", "epid"},
      {L"ProcessID", "epid"},
  };
  static const EdrPropTry file_try[] = {
      {L"FileName", "file"},
      {L"FileObject", "file"},
      {L"OpenPath", "file"},
  };
  static const EdrPropTry net_try[] = {
      {L"daddr", "dst"},
      {L"saddr", "src"},
      {L"dport", "dpt"},
      {L"sport", "spt"},
      {L"RemoteAddress", "raddr"},
      {L"LocalAddress", "laddr"},
      {L"RemoteIP", "rip"},
      {L"LocalIP", "lip"},
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
      {L"ParentProcessName", "pimg"},
      {L"ProcessId", "epid"},
      {L"ParentProcessId", "ppid"},
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
    edr_try_append_naux_for_net(rec, (char *)out, out_cap, &off, line, sizeof(line));
  } else if (memcmp(g, &EDR_ETW_GUID_KERNEL_REGISTRY, sizeof(GUID)) == 0) {
    edr_try_append_all(rec, reg_try, sizeof(reg_try) / sizeof(reg_try[0]), line,
                       sizeof(line), (char *)out, out_cap, &off);
  } else if (memcmp(g, &EDR_ETW_GUID_DNS_CLIENT, sizeof(GUID)) == 0) {
    if (edr_tdh_light_path_a33_enabled()) {
      static const EdrPropTry dns_qname_only[] = {
          {L"QueryName", "qname"},
      };
      const size_t off_before = off;
      edr_try_append_all(rec, dns_qname_only, sizeof(dns_qname_only) / sizeof(dns_qname_only[0]), line,
                         sizeof(line), (char *)out, out_cap, &off);
      if (off == off_before) {
        edr_try_append_all(rec, dns_try, sizeof(dns_try) / sizeof(dns_try[0]), line,
                           sizeof(line), (char *)out, out_cap, &off);
      }
    } else {
      edr_try_append_all(rec, dns_try, sizeof(dns_try) / sizeof(dns_try[0]), line,
                         sizeof(line), (char *)out, out_cap, &off);
    }
  } else if (memcmp(g, &EDR_ETW_GUID_POWERSHELL, sizeof(GUID)) == 0) {
    if (edr_tdh_light_path_ps_p1_enabled()) {
      static const EdrPropTry ps_script_first[] = {
          {L"ScriptBlockText", "script"},
      };
      const size_t off_ps = off;
      edr_try_append_all(rec, ps_script_first, sizeof(ps_script_first) / sizeof(ps_script_first[0]), line,
                         sizeof(line), (char *)out, out_cap, &off);
      if (off == off_ps) {
        edr_try_append_all(rec, ps_try, sizeof(ps_try) / sizeof(ps_try[0]), line, sizeof(line), (char *)out, out_cap,
                           &off);
      }
    } else {
      edr_try_append_all(rec, ps_try, sizeof(ps_try) / sizeof(ps_try[0]), line,
                         sizeof(line), (char *)out, out_cap, &off);
    }
  } else if (memcmp(g, &EDR_ETW_GUID_SECURITY_AUDIT, sizeof(GUID)) == 0) {
    edr_try_append_all(rec, sec_try, sizeof(sec_try) / sizeof(sec_try[0]), line,
                       sizeof(line), (char *)out, out_cap, &off);
  } else if (memcmp(g, &EDR_ETW_GUID_WMI_ACTIVITY, sizeof(GUID)) == 0) {
    edr_try_append_all(rec, wmi_try, sizeof(wmi_try) / sizeof(wmi_try[0]), line,
                       sizeof(line), (char *)out, out_cap, &off);
  } else if (memcmp(g, &EDR_ETW_GUID_MICROSOFT_TCPIP, sizeof(GUID)) == 0) {
    USHORT tcp_ev = rec->EventHeader.EventDescriptor.Id;
    if (edr_tdh_light_path_tcpip_p1_enabled() && tcp_ev == 1002u) {
      static const EdrPropTry tcpip_listen_light[] = {
          {L"LocalAddress", "laddr"},
          {L"LocalPort", "lport"},
          {L"PID", "epid"},
          {L"ProcessId", "epid"},
      };
      const size_t off_tcp_before = off;
      edr_try_append_all(rec, tcpip_listen_light, sizeof(tcpip_listen_light) / sizeof(tcpip_listen_light[0]), line,
                         sizeof(line), (char *)out, out_cap, &off);
      if (off == off_tcp_before) {
        edr_try_append_all(rec, tcpip_try, sizeof(tcpip_try) / sizeof(tcpip_try[0]), line,
                           sizeof(line), (char *)out, out_cap, &off);
      }
    } else {
      edr_try_append_all(rec, tcpip_try, sizeof(tcpip_try) / sizeof(tcpip_try[0]), line,
                         sizeof(line), (char *)out, out_cap, &off);
    }
    edr_try_append_naux_for_net(rec, (char *)out, out_cap, &off, line, sizeof(line));
  } else if (memcmp(g, &EDR_ETW_GUID_WINFIREWALL_WFAS, sizeof(GUID)) == 0) {
    edr_try_append_all(rec, wf_try, sizeof(wf_try) / sizeof(wf_try[0]), line, sizeof(line),
                       (char *)out, out_cap, &off);
  }

  const GUID *provider_g = &rec->EventHeader.ProviderId;
  if ((memcmp(provider_g, &EDR_ETW_GUID_KERNEL_PROCESS, sizeof(GUID)) == 0 ||
       memcmp(provider_g, &EDR_ETW_GUID_SECURITY_AUDIT, sizeof(GUID)) == 0) &&
      strstr((const char *)out, "\ncmd=") == NULL) {
    char cmd_fallback[8192];
    if (edr_get_process_cmdline_by_pid(rec->EventHeader.ProcessId, cmd_fallback, sizeof(cmd_fallback)) == 0 &&
        cmd_fallback[0]) {
      append_utf8((char *)out, out_cap, &off, "cmd=%s\n", cmd_fallback);
    }
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