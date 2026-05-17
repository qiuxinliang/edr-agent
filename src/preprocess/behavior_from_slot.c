#include "edr/behavior_from_slot.h"
#include "edr/forensic_trigger.h"
#include "edr/process_tree_cache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#include <Sddl.h>
#include <TlHelp32.h>

typedef LONG EDR_NTSTATUS;
#define EDR_STATUS_SUCCESS ((EDR_NTSTATUS)0x00000000L)

typedef struct _EDR_PROCESS_BASIC_INFORMATION_V2 {
  void    *ExitStatus;
  void    *PebBaseAddress;
  void    *AffinityMask;
  LONG     BasePriority;
  void    *UniqueProcessId;
  void    *InheritedFromUniqueProcessId;
} EDR_PROCESS_BASIC_INFORMATION_V2;

static volatile LONG64 s_ppid_zero_events;
static volatile LONG64 s_ppid_total_events;
static volatile LONG64 s_ppid_snapshot_fallback_ok;
static volatile LONG64 s_ppid_ntqi_fallback_ok;
static volatile LONG64 s_ppid_wmi_fallback_ok;
static volatile LONG64 s_ppid_env_fallback_ok;
static volatile LONG64 s_ppid_infer_ok;

void edr_behavior_get_ppid_stats(int64_t *out_zero, int64_t *out_total,
                                 int64_t *out_snap_ok, int64_t *out_ntqi_ok,
                                 int64_t *out_wmi_ok, int64_t *out_env_ok,
                                 int64_t *out_infer_ok) {
  if (out_zero)   *out_zero   = s_ppid_zero_events;
  if (out_total)  *out_total  = s_ppid_total_events;
  if (out_snap_ok) *out_snap_ok = s_ppid_snapshot_fallback_ok;
  if (out_ntqi_ok) *out_ntqi_ok = s_ppid_ntqi_fallback_ok;
  if (out_wmi_ok)  *out_wmi_ok  = s_ppid_wmi_fallback_ok;
  if (out_env_ok)  *out_env_ok  = s_ppid_env_fallback_ok;
  if (out_infer_ok) *out_infer_ok = s_ppid_infer_ok;
}

static int edr_get_ppid_via_ntqi(DWORD pid, DWORD *out_ppid) {
  if (!out_ppid || pid == 0) return -1;
  HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (!h) return -1;
  typedef EDR_NTSTATUS (WINAPI *PNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
  static PNtQueryInformationProcess pNtQIP = NULL;
  if (!pNtQIP) {
    pNtQIP = (PNtQueryInformationProcess)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    if (!pNtQIP) { CloseHandle(h); return -1; }
  }
  EDR_PROCESS_BASIC_INFORMATION_V2 pbi;
  (void)memset(&pbi, 0, sizeof(pbi));
  EDR_NTSTATUS st = pNtQIP(h, 0, &pbi, sizeof(pbi), NULL);
  CloseHandle(h);
  if (st != EDR_STATUS_SUCCESS || !pbi.InheritedFromUniqueProcessId) return -1;
  DWORD ppid = (DWORD)(ULONG_PTR)pbi.InheritedFromUniqueProcessId;
  if (ppid == 0 || ppid == pid) return -1;
  *out_ppid = ppid;
  return 0;
}

static int edr_get_process_path_by_pid(DWORD pid, char *out, size_t out_cap) {
  if (!out || out_cap < 2) {
    return -1;
  }
  *out = '\0';

  HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (!hProcess) {
    return -1;
  }

  WCHAR wpath[MAX_PATH];
  DWORD size = MAX_PATH;
  if (!QueryFullProcessImageNameW(hProcess, 0, wpath, &size)) {
    CloseHandle(hProcess);
    return -1;
  }

  int n = WideCharToMultiByte(CP_UTF8, 0, wpath, -1, out, (int)out_cap - 1, NULL, NULL);
  if (n > 0) {
    out[n] = '\0';
  }

  CloseHandle(hProcess);
  return 0;
}

static int edr_get_process_username_by_pid(DWORD pid, char *out, size_t out_cap) {
  if (!out || out_cap < 2) return -1;
  out[0] = '\0';

  HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (!hProcess) return -1;

  HANDLE hToken = NULL;
  if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
    CloseHandle(hProcess);
    return -1;
  }

  DWORD tokenInfoSize = 0;
  GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoSize);
  if (tokenInfoSize == 0) {
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return -1;
  }

  PTOKEN_USER pTokenUser = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), 0, tokenInfoSize);
  if (!pTokenUser) {
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return -1;
  }

  int result = -1;
  if (GetTokenInformation(hToken, TokenUser, pTokenUser, tokenInfoSize, &tokenInfoSize)) {
    WCHAR wUsername[256] = {0};
    WCHAR wDomain[256] = {0};
    DWORD cchUsername = 256;
    DWORD cchDomain = 256;
    SID_NAME_USE snu;
    if (LookupAccountSidW(NULL, pTokenUser->User.Sid, wUsername, &cchUsername,
                          wDomain, &cchDomain, &snu)) {
      char username[256] = {0};
      WideCharToMultiByte(CP_UTF8, 0, wUsername, -1, username, (int)sizeof(username) - 1, NULL, NULL);
      if (wDomain[0]) {
        char domain[128] = {0};
        WideCharToMultiByte(CP_UTF8, 0, wDomain, -1, domain, (int)sizeof(domain) - 1, NULL, NULL);
        snprintf(out, out_cap, "%s\\%s", domain, username);
      } else {
        snprintf(out, out_cap, "%s", username);
      }
      result = 0;
    }
  }

  HeapFree(GetProcessHeap(), 0, pTokenUser);
  CloseHandle(hToken);
  CloseHandle(hProcess);
  return result;
}

static int edr_get_ppid_via_wmi(DWORD pid, DWORD *out_ppid) {
  if (!out_ppid || pid == 0) return -1;
  
  HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
  if (FAILED(hr)) return -1;
  
  IWbemLocator *pLocator = NULL;
  hr = CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, 
                        &IID_IWbemLocator, (void**)&pLocator);
  if (FAILED(hr)) {
    CoUninitialize();
    return -1;
  }
  
  IWbemServices *pServices = NULL;
  hr = pLocator->lpVtbl->ConnectServer(pLocator, 
                                       (BSTR)L"ROOT\\CIMV2", 
                                       NULL, NULL, NULL, 0, NULL, NULL, 
                                       &pServices);
  pLocator->lpVtbl->Release(pLocator);
  if (FAILED(hr)) {
    CoUninitialize();
    return -1;
  }
  
  hr = CoSetProxyBlanket(pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                         RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                         NULL, EOAC_NONE);
  if (FAILED(hr)) {
    pServices->lpVtbl->Release(pServices);
    CoUninitialize();
    return -1;
  }
  
  WCHAR query[256];
  swprintf(query, sizeof(query)/sizeof(WCHAR), 
           L"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = %lu", pid);
  
  IEnumWbemClassObject *pEnumerator = NULL;
  hr = pServices->lpVtbl->ExecQuery(pServices, (BSTR)L"WQL", (BSTR)query,
                                     WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                     NULL, &pEnumerator);
  pServices->lpVtbl->Release(pServices);
  if (FAILED(hr)) {
    CoUninitialize();
    return -1;
  }
  
  int result = -1;
  IWbemClassObject *pObject = NULL;
  ULONG uReturn = 0;
  
  if (pEnumerator) {
    if (pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pObject, &uReturn) == S_OK && uReturn > 0) {
      VARIANT vtProp;
      VariantInit(&vtProp);
      if (pObject->lpVtbl->Get(pObject, (BSTR)L"ParentProcessId", 0, &vtProp, NULL, NULL) == S_OK) {
        if (vtProp.vt == VT_I4 && vtProp.lVal > 0 && vtProp.lVal != pid) {
          *out_ppid = (DWORD)vtProp.lVal;
          result = 0;
        }
      }
      VariantClear(&vtProp);
      if (pObject) {
        pObject->lpVtbl->Release(pObject);
      }
    }
    pEnumerator->lpVtbl->Release(pEnumerator);
  }
  
  CoUninitialize();
  return result;
}

static int edr_get_ppid_from_environment(DWORD pid, DWORD *out_ppid) {
  if (!out_ppid || pid == 0) return -1;
  
  HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
  if (!hProcess) return -1;
  
  HANDLE hToken = NULL;
  if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
    CloseHandle(hProcess);
    return -1;
  }
  
  const DWORD tokenEnvInfo = 10;
  DWORD needed = 0;
  GetTokenInformation(hToken, tokenEnvInfo, NULL, 0, &needed);
  if (needed == 0) {
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return -1;
  }
  
  LPVOID envBlock = HeapAlloc(GetProcessHeap(), 0, needed);
  if (!envBlock) {
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return -1;
  }
  
  int result = -1;
  if (GetTokenInformation(hToken, tokenEnvInfo, envBlock, needed, &needed)) {
    WCHAR *env = (WCHAR*)envBlock;
    while (*env) {
      size_t len = wcslen(env);
      if (len > 10 && wcsncmp(env, L"PPID=", 5) == 0) {
        DWORD ppid_val = (DWORD)wcstol(env + 5, NULL, 10);
        if (ppid_val > 0 && ppid_val != pid) {
          *out_ppid = ppid_val;
          result = 0;
          break;
        }
      }
      env += len + 1;
    }
  }
  
  HeapFree(GetProcessHeap(), 0, envBlock);
  CloseHandle(hToken);
  CloseHandle(hProcess);
  return result;
}

static int edr_get_ppid_from_system(DWORD pid, DWORD *out_ppid) {
  if (!out_ppid || pid == 0) return -1;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return -1;
  PROCESSENTRY32W pe;
  pe.dwSize = (DWORD)sizeof(pe);
  int found = 0;
  if (Process32FirstW(snap, &pe)) {
    do {
      if (pe.th32ProcessID == pid) {
        *out_ppid = (DWORD)pe.th32ParentProcessID;
        found = 1;
        break;
      }
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  return found ? 0 : -1;
}
#endif

static uint64_t g_event_seq;

static void edr_gen_event_id(char *out, size_t cap, int64_t time_ns) {
  uint64_t s = ++g_event_seq;
  snprintf(out, cap, "e-%llx-%llx", (unsigned long long)(uint64_t)time_ns,
           (unsigned long long)s);
}

static const char *basename_c(const char *path) {
  if (!path || !path[0]) {
    return "";
  }
  const char *p = path;
  for (const char *c = path; *c; c++) {
    if (*c == '\\' || *c == '/') {
      p = c + 1;
    }
  }
  return p;
}

static int is_mostly_printable_ascii(const uint8_t *p, size_t n) {
  if (!p || n == 0u) {
    return 0;
  }
  size_t printable = 0u;
  for (size_t i = 0; i < n; i++) {
    uint8_t c = p[i];
    if ((c >= 0x20 && c <= 0x7eu) || c == '\t' || c == '\r' || c == '\n') {
      printable++;
    }
  }
  return printable >= (n * 8u) / 10u;
}

typedef struct {
  char prov[48];
  char img[EDR_BR_STR_LONG];
  char cmd[EDR_BR_STR_LONG];
  char file[EDR_BR_STR_LONG];
  char qname[EDR_BR_STR_MID];
  char script[EDR_BR_STR_LONG];
  char dst[64];
  char src[64];
  char score[32];
  char proto[48];
  char detector[32];
  char rule[96];
  char mitre[24];
  char forensic_kind[16];
  char pcap_stem[180];
  char ring_trigger_slot[24];
  char ring_oldest_ns[28];
  char ring_newest_ns[28];
  char ring_span_ns[28];
  char shellcode_json[512];
  char fw_id[96];
  char fw_rule[256];
  char fw_mod[512];
  char regkey[1024];
  char regname[512];
  char regdata[8192];
  char regop[64];
  int has_fw;
  unsigned long forensic_frames;
  int has_forensic_frames;
  int has_ring_meta;
  uint8_t cert_revoked_ancestor;
  int has_cert_revoked_ancestor;
  unsigned long pid;
  unsigned long epid;
  unsigned long ppid;
  unsigned long dport;
  unsigned long sport;
  int has_img;
  int has_cmd;
  int has_dport;
  int has_sport;
  char pimg[EDR_BR_STR_LONG];
  int has_pimg;
  char naux[EDR_BR_STR_LONG];
  char user[EDR_BR_STR_SHORT];
  char integ[32];
  unsigned long token_elev;
  unsigned long sess_id;
  int has_user;
  int has_integ;
  int has_token_elev;
  int has_sess_id;
  char query[EDR_BR_STR_LONG];
  char consumer[EDR_BR_STR_LONG];
} Etw1Fields;

static void etw1_clear(Etw1Fields *f) { memset(f, 0, sizeof(*f)); }

static void apply_kv(Etw1Fields *f, const char *key, const char *val) {
  if (!key || !val) {
    return;
  }
  if (strcmp(key, "prov") == 0) {
    snprintf(f->prov, sizeof(f->prov), "%s", val);
  } else if (strcmp(key, "pid") == 0) {
    f->pid = strtoul(val, NULL, 10);
  } else if (strcmp(key, "epid") == 0) {
    f->epid = strtoul(val, NULL, 10);
  } else if (strcmp(key, "hint_pid") == 0) {
    f->epid = strtoul(val, NULL, 10);
  } else if (strcmp(key, "ppid") == 0) {
    f->ppid = strtoul(val, NULL, 10);
  } else if (strcmp(key, "pimg") == 0) {
    snprintf(f->pimg, sizeof(f->pimg), "%s", val);
    f->has_pimg = 1;
  } else if (strcmp(key, "img") == 0) {
    snprintf(f->img, sizeof(f->img), "%s", val);
    f->has_img = 1;
  } else if (strcmp(key, "cmd") == 0) {
    snprintf(f->cmd, sizeof(f->cmd), "%s", val);
    f->has_cmd = 1;
  } else if (strcmp(key, "cert_revoked_ancestor") == 0 || strcmp(key, "cert_ra") == 0) {
    f->cert_revoked_ancestor = (strtoul(val, NULL, 10) != 0u) ? 1u : 0u;
    f->has_cert_revoked_ancestor = 1;
  } else if (strcmp(key, "file") == 0) {
    snprintf(f->file, sizeof(f->file), "%s", val);
  } else if (strcmp(key, "qname") == 0) {
    snprintf(f->qname, sizeof(f->qname), "%s", val);
  } else if (strcmp(key, "script") == 0) {
    snprintf(f->script, sizeof(f->script), "%s", val);
  } else if (strcmp(key, "dst") == 0) {
    snprintf(f->dst, sizeof(f->dst), "%s", val);
  } else if (strcmp(key, "src") == 0) {
    snprintf(f->src, sizeof(f->src), "%s", val);
  } else if (strcmp(key, "dpt") == 0) {
    f->dport = strtoul(val, NULL, 10);
    f->has_dport = 1;
  } else if (strcmp(key, "spt") == 0) {
    f->sport = strtoul(val, NULL, 10);
    f->has_sport = 1;
  } else if (strcmp(key, "laddr") == 0) {
    snprintf(f->src, sizeof(f->src), "%s", val);
  } else if (strcmp(key, "raddr") == 0) {
    snprintf(f->dst, sizeof(f->dst), "%s", val);
  } else if (strcmp(key, "lport") == 0) {
    f->sport = strtoul(val, NULL, 10);
    f->has_sport = 1;
  } else if (strcmp(key, "rport") == 0) {
    f->dport = strtoul(val, NULL, 10);
    f->has_dport = 1;
  } else if (strcmp(key, "fw_id") == 0) {
    snprintf(f->fw_id, sizeof(f->fw_id), "%s", val);
    f->has_fw = 1;
  } else if (strcmp(key, "fw_rule") == 0) {
    snprintf(f->fw_rule, sizeof(f->fw_rule), "%s", val);
    f->has_fw = 1;
  } else if (strcmp(key, "fw_mod") == 0) {
    snprintf(f->fw_mod, sizeof(f->fw_mod), "%s", val);
    f->has_fw = 1;
  } else if (strcmp(key, "fw_origin") == 0 || strcmp(key, "fw_remote") == 0 ||
             strcmp(key, "fw_lports") == 0) {
    f->has_fw = 1;
  } else if (strcmp(key, "score") == 0) {
    snprintf(f->score, sizeof(f->score), "%s", val);
  } else if (strcmp(key, "proto") == 0) {
    snprintf(f->proto, sizeof(f->proto), "%s", val);
  } else if (strcmp(key, "detector") == 0) {
    snprintf(f->detector, sizeof(f->detector), "%s", val);
  } else if (strcmp(key, "rule") == 0) {
    snprintf(f->rule, sizeof(f->rule), "%s", val);
  } else if (strcmp(key, "mitre") == 0) {
    snprintf(f->mitre, sizeof(f->mitre), "%s", val);
  } else if (strcmp(key, "forensic_kind") == 0) {
    snprintf(f->forensic_kind, sizeof(f->forensic_kind), "%s", val);
  } else if (strcmp(key, "pcap_stem") == 0) {
    snprintf(f->pcap_stem, sizeof(f->pcap_stem), "%s", val);
  } else if (strcmp(key, "forensic_frames") == 0) {
    f->forensic_frames = strtoul(val, NULL, 10);
    f->has_forensic_frames = 1;
  } else if (strcmp(key, "ring_trigger_slot") == 0) {
    snprintf(f->ring_trigger_slot, sizeof(f->ring_trigger_slot), "%s", val);
    f->has_ring_meta = 1;
  } else if (strcmp(key, "ring_oldest_ns") == 0) {
    snprintf(f->ring_oldest_ns, sizeof(f->ring_oldest_ns), "%s", val);
    f->has_ring_meta = 1;
  } else if (strcmp(key, "ring_newest_ns") == 0) {
    snprintf(f->ring_newest_ns, sizeof(f->ring_newest_ns), "%s", val);
    f->has_ring_meta = 1;
  } else if (strcmp(key, "ring_span_ns") == 0) {
    snprintf(f->ring_span_ns, sizeof(f->ring_span_ns), "%s", val);
    f->has_ring_meta = 1;
  } else if (strcmp(key, "shellcode_json") == 0) {
    snprintf(f->shellcode_json, sizeof(f->shellcode_json), "%s", val);
  } else if (strcmp(key, "regkey") == 0) {
    snprintf(f->regkey, sizeof(f->regkey), "%s", val);
  } else if (strcmp(key, "regpath") == 0 && !f->regkey[0]) {
    snprintf(f->regkey, sizeof(f->regkey), "%s", val);
  } else if (strcmp(key, "regname") == 0) {
    snprintf(f->regname, sizeof(f->regname), "%s", val);
  } else if (strcmp(key, "regdata") == 0) {
    snprintf(f->regdata, sizeof(f->regdata), "%s", val);
  } else if (strcmp(key, "regop") == 0) {
    snprintf(f->regop, sizeof(f->regop), "%s", val);
  } else if (strcmp(key, "naux") == 0) {
    snprintf(f->naux, sizeof(f->naux), "%s", val);
  } else if (strcmp(key, "user") == 0) {
    snprintf(f->user, sizeof(f->user), "%s", val);
    f->has_user = 1;
  } else if (strcmp(key, "integ") == 0) {
    snprintf(f->integ, sizeof(f->integ), "%s", val);
    f->has_integ = 1;
  } else if (strcmp(key, "token_elev") == 0) {
    f->token_elev = strtoul(val, NULL, 10);
    f->has_token_elev = 1;
  } else if (strcmp(key, "sess_id") == 0) {
    f->sess_id = strtoul(val, NULL, 10);
    f->has_sess_id = 1;
  } else if (strcmp(key, "query") == 0) {
    snprintf(f->query, sizeof(f->query), "%s", val);
  } else if (strcmp(key, "consumer") == 0) {
    snprintf(f->consumer, sizeof(f->consumer), "%s", val);
  }
}

/** 解析 ETW1\\n 文本块（collector TDH 输出） */
static int etw1_parse(const uint8_t *data, uint32_t len, Etw1Fields *f) {
  etw1_clear(f);
  if (!data || len < 5 || memcmp(data, "ETW1", 4) != 0) {
    return -1;
  }
  char *buf = (char *)malloc((size_t)len + 1u);
  if (!buf) {
    return -1;
  }
  memcpy(buf, data, len);
  buf[len] = '\0';

  char *p = buf;
  char *first_nl = strchr(p, '\n');
  if (!first_nl) {
    free(buf);
    return -1;
  }
  *first_nl = '\0';
  if (strcmp(p, "ETW1") != 0) {
    free(buf);
    return -1;
  }
  p = first_nl + 1;
  while (*p) {
    char *line_end = strchr(p, '\n');
    if (line_end) {
      *line_end = '\0';
    }
    char *eq = strchr(p, '=');
    if (eq) {
      *eq = '\0';
      apply_kv(f, p, eq + 1);
      *eq = '=';
    }
    if (!line_end) {
      break;
    }
    p = line_end + 1;
  }
  free(buf);
  return 0;
}

static void apply_mitre_hints(EdrBehaviorRecord *r) {
  r->mitre_ttp_count = 0;
  if (r->type == EDR_EVENT_PROTOCOL_SHELLCODE && r->mitre_ttp_count < (int)EDR_BR_MAX_MITRE) {
    snprintf(r->mitre_ttps[r->mitre_ttp_count], sizeof(r->mitre_ttps[0]), "%s", "T1210");
    r->mitre_ttp_count++;
  }
  if (r->type == EDR_EVENT_WEBSHELL_DETECTED && r->mitre_ttp_count < (int)EDR_BR_MAX_MITRE) {
    snprintf(r->mitre_ttps[r->mitre_ttp_count], sizeof(r->mitre_ttps[0]), "%s", "T1505.003");
    r->mitre_ttp_count++;
  }
  if (r->type == EDR_EVENT_FIREWALL_RULE_CHANGE && r->mitre_ttp_count < (int)EDR_BR_MAX_MITRE) {
    snprintf(r->mitre_ttps[r->mitre_ttp_count], sizeof(r->mitre_ttps[0]), "%s", "T1562.004");
    r->mitre_ttp_count++;
  }
  if (r->type == EDR_EVENT_PMFE_SCAN_RESULT && r->mitre_ttp_count < (int)EDR_BR_MAX_MITRE) {
    snprintf(r->mitre_ttps[r->mitre_ttp_count], sizeof(r->mitre_ttps[0]), "%s", "T1055");
    r->mitre_ttp_count++;
  }
  const char *hay = r->cmdline[0] ? r->cmdline : r->script_snippet;
  if (hay[0] && (strstr(hay, "EncodedCommand") != NULL || strstr(hay, "-Enc") != NULL) &&
      r->mitre_ttp_count < (int)EDR_BR_MAX_MITRE) {
    snprintf(r->mitre_ttps[r->mitre_ttp_count], sizeof(r->mitre_ttps[0]), "%s", "T1059.001");
    r->mitre_ttp_count++;
  }
}

void edr_behavior_from_slot(const EdrEventSlot *slot, EdrBehaviorRecord *r) {
  edr_behavior_record_init(r);
  if (!slot || !r) {
    return;
  }

  r->event_time_ns = (int64_t)slot->timestamp_ns;
  r->type = slot->type;
  r->priority = slot->priority;
  edr_gen_event_id(r->event_id, sizeof(r->event_id), r->event_time_ns);

  Etw1Fields ef;
  if (slot->size > 0 && etw1_parse(slot->data, slot->size, &ef) == 0) {
    if (ef.pid) {
      r->pid = (uint32_t)ef.pid;
    }
    if (ef.epid) {
      r->pid = (uint32_t)ef.epid;
    }
    if (ef.ppid) {
      r->ppid = (uint32_t)ef.ppid;
    }
#if defined(_WIN32)
    if (r->ppid == 0u && r->pid != 0u) {
      DWORD sppid = 0;
      if (edr_get_ppid_via_ntqi((DWORD)r->pid, &sppid) == 0 && sppid > 0) {
        r->ppid = (uint32_t)sppid;
        (void)InterlockedAdd64(&s_ppid_ntqi_fallback_ok, 1);
      } else if (edr_get_ppid_from_system((DWORD)r->pid, &sppid) == 0 && sppid > 0) {
        r->ppid = (uint32_t)sppid;
        (void)InterlockedAdd64(&s_ppid_snapshot_fallback_ok, 1);
      } else if (edr_get_ppid_via_wmi((DWORD)r->pid, &sppid) == 0 && sppid > 0) {
        r->ppid = (uint32_t)sppid;
        (void)InterlockedAdd64(&s_ppid_wmi_fallback_ok, 1);
      } else if (edr_get_ppid_from_environment((DWORD)r->pid, &sppid) == 0 && sppid > 0) {
        r->ppid = (uint32_t)sppid;
        (void)InterlockedAdd64(&s_ppid_env_fallback_ok, 1);
      } else {
        uint64_t event_time = 0;
        if (r->event_time_ns > 0) {
          event_time = (uint64_t)r->event_time_ns;
        } else {
          FILETIME ft;
          GetSystemTimeAsFileTime(&ft);
          event_time = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        }
        
        char inferred_parent_name[64] = {0};
        if (edr_pt_cache_infer_parent(r->pid, event_time, &sppid, inferred_parent_name, sizeof(inferred_parent_name)) == 0 && sppid > 0) {
          r->ppid = (uint32_t)sppid;
          if (inferred_parent_name[0] && !r->parent_name[0]) {
            snprintf(r->parent_name, sizeof(r->parent_name), "%s", inferred_parent_name);
          }
          (void)InterlockedAdd64(&s_ppid_infer_ok, 1);
        } else {
          (void)InterlockedAdd64(&s_ppid_zero_events, 1);
        }
      }
    }
    (void)InterlockedAdd64(&s_ppid_total_events, 1);
#endif
    if (ef.has_img) {
      snprintf(r->exe_path, sizeof(r->exe_path), "%s", ef.img);
      /* DLL/DRIVER 加载事件：img 是模块路径而非进程路径，不应作为 process_name */
      if (r->type != EDR_EVENT_DLL_LOAD && r->type != EDR_EVENT_DRIVER_LOAD) {
        snprintf(r->process_name, sizeof(r->process_name), "%s", basename_c(ef.img));
      }
    }

    if (!r->process_name[0] && r->pid != 0) {
#ifdef _WIN32
      char process_path[MAX_PATH];
      if (edr_get_process_path_by_pid((DWORD)r->pid, process_path, sizeof(process_path)) == 0 && process_path[0]) {
        snprintf(r->process_name, sizeof(r->process_name), "%s", basename_c(process_path));
        snprintf(r->exe_path, sizeof(r->exe_path), "%s", process_path);
      }
#endif
    }
    
    if (ef.has_pimg) {
      snprintf(r->parent_path, sizeof(r->parent_path), "%s", ef.pimg);
      snprintf(r->parent_name, sizeof(r->parent_name), "%s", basename_c(ef.pimg));
    }
    if (ef.has_cmd) {
      snprintf(r->cmdline, sizeof(r->cmdline), "%s", ef.cmd);
    }
    if (ef.file[0]) {
      snprintf(r->file_path, sizeof(r->file_path), "%s", ef.file);
      switch (r->type) {
      case EDR_EVENT_FILE_READ:
        snprintf(r->file_op, sizeof(r->file_op), "read");
        break;
      case EDR_EVENT_FILE_WRITE:
        snprintf(r->file_op, sizeof(r->file_op), "write");
        break;
      case EDR_EVENT_FILE_CREATE:
        snprintf(r->file_op, sizeof(r->file_op), "create");
        break;
      case EDR_EVENT_FILE_DELETE:
        snprintf(r->file_op, sizeof(r->file_op), "delete");
        break;
      case EDR_EVENT_FILE_RENAME:
        snprintf(r->file_op, sizeof(r->file_op), "rename");
        break;
      case EDR_EVENT_FILE_PERMISSION_CHANGE:
        snprintf(r->file_op, sizeof(r->file_op), "permission");
        break;
      default:
        snprintf(r->file_op, sizeof(r->file_op), "event");
        break;
      }
    }
    if (ef.naux[0]) {
      snprintf(r->network_aux_path, sizeof(r->network_aux_path), "%s", ef.naux);
    }
    if (ef.has_user) {
      snprintf(r->username, sizeof(r->username), "%s", ef.user);
    }
#if defined(_WIN32)
    if (!ef.has_user && ef.epid > 0) {
      DWORD pid = (DWORD)ef.epid;
      char ubuf[EDR_BR_STR_SHORT];
      if (edr_get_process_username_by_pid(pid, ubuf, sizeof(ubuf)) == 0 && ubuf[0]) {
        snprintf(r->username, sizeof(r->username), "%s", ubuf);
      }
    }
#endif
    if (ef.has_integ) {
      snprintf(r->integrity_level, sizeof(r->integrity_level), "%s", ef.integ);
    }
    if (ef.has_token_elev) {
      r->token_elevation = (uint32_t)ef.token_elev;
    }
    if (ef.has_sess_id) {
      r->session_id = (uint32_t)ef.sess_id;
    }
    if (ef.query[0]) {
      snprintf(r->wmi_filter, sizeof(r->wmi_filter), "query=%s", ef.query);
    }
    if (ef.consumer[0]) {
      size_t L = strlen(r->wmi_filter);
      if (L > 0) snprintf(r->wmi_filter + L, sizeof(r->wmi_filter) - L, " consumer=%s", ef.consumer);
      else snprintf(r->wmi_filter, sizeof(r->wmi_filter), "consumer=%s", ef.consumer);
    }
    if (ef.qname[0]) {
      snprintf(r->dns_query, sizeof(r->dns_query), "%s", ef.qname);
    }
    if (ef.script[0]) {
      snprintf(r->script_snippet, sizeof(r->script_snippet), "%s", ef.script);
    }
    if (ef.src[0]) {
      snprintf(r->net_src, sizeof(r->net_src), "%s", ef.src);
    }
    if (ef.dst[0]) {
      snprintf(r->net_dst, sizeof(r->net_dst), "%s", ef.dst);
    }
    if (ef.has_dport) {
      r->net_dport = (uint32_t)ef.dport;
    }
    if (ef.has_sport) {
      r->net_sport = (uint32_t)ef.sport;
    }
    if (ef.has_fw) {
      snprintf(r->file_path, sizeof(r->file_path), "WF rule=%s id=%s mod=%s",
               ef.fw_rule[0] ? ef.fw_rule : "-", ef.fw_id[0] ? ef.fw_id : "-",
               ef.fw_mod[0] ? ef.fw_mod : "-");
      snprintf(r->file_op, sizeof(r->file_op), "%s", "firewall_etw");
    }
    if (ef.proto[0]) {
      snprintf(r->net_proto, sizeof(r->net_proto), "%s", ef.proto);
    }
    if (ef.has_cert_revoked_ancestor) {
      r->cert_revoked_ancestor = ef.cert_revoked_ancestor;
    }
    if (ef.regkey[0]) {
      snprintf(r->reg_key_path, sizeof(r->reg_key_path), "%s", ef.regkey);
    }
    if (ef.regname[0]) {
      snprintf(r->reg_value_name, sizeof(r->reg_value_name), "%s", ef.regname);
    }
    if (ef.regdata[0]) {
      snprintf(r->reg_value_data, sizeof(r->reg_value_data), "%s", ef.regdata);
    }
    if (ef.regop[0]) {
      snprintf(r->reg_op, sizeof(r->reg_op), "%s", ef.regop);
    }
    if (r->type == EDR_EVENT_REG_CREATE_KEY && !r->reg_op[0]) {
      snprintf(r->reg_op, sizeof(r->reg_op), "create_key");
    } else if (r->type == EDR_EVENT_REG_SET_VALUE && !r->reg_op[0]) {
      snprintf(r->reg_op, sizeof(r->reg_op), "set_value");
    } else if (r->type == EDR_EVENT_REG_DELETE_KEY && !r->reg_op[0]) {
      snprintf(r->reg_op, sizeof(r->reg_op), "delete_key");
    }
    if (ef.score[0] || ef.proto[0] || ef.detector[0] || ef.rule[0] || ef.mitre[0] || ef.forensic_kind[0] ||
        ef.pcap_stem[0] || ef.has_forensic_frames || ef.has_ring_meta || ef.shellcode_json[0]) {
      if (ef.has_forensic_frames) {
        snprintf(r->script_snippet, sizeof(r->script_snippet),
                 "detector=%s rule=%s score=%s proto=%s mitre=%s forensic=%s stem=%s frames=%lu",
                 ef.detector[0] ? ef.detector : "-", ef.rule[0] ? ef.rule : "-", ef.score[0] ? ef.score : "-",
                 ef.proto[0] ? ef.proto : "-", ef.mitre[0] ? ef.mitre : "-", ef.forensic_kind[0] ? ef.forensic_kind : "-",
                 ef.pcap_stem[0] ? ef.pcap_stem : "-", (unsigned long)ef.forensic_frames);
      } else {
        snprintf(r->script_snippet, sizeof(r->script_snippet),
                 "detector=%s rule=%s score=%s proto=%s mitre=%s forensic=%s stem=%s",
                 ef.detector[0] ? ef.detector : "-", ef.rule[0] ? ef.rule : "-", ef.score[0] ? ef.score : "-",
                 ef.proto[0] ? ef.proto : "-", ef.mitre[0] ? ef.mitre : "-", ef.forensic_kind[0] ? ef.forensic_kind : "-",
                 ef.pcap_stem[0] ? ef.pcap_stem : "-");
      }
      if (ef.has_ring_meta) {
        size_t L = strlen(r->script_snippet);
        snprintf(r->script_snippet + L, sizeof(r->script_snippet) - L, " ring_slot=%s span_ns=%s",
                 ef.ring_trigger_slot[0] ? ef.ring_trigger_slot : "-", ef.ring_span_ns[0] ? ef.ring_span_ns : "-");
      }
      if (ef.shellcode_json[0]) {
        size_t L = strlen(r->script_snippet);
        snprintf(r->script_snippet + L, sizeof(r->script_snippet) - L, " | %s", ef.shellcode_json);
      }
    }
  } else if (slot->size > 0) {
    size_t n = slot->size;
    if (n >= sizeof(r->cmdline)) {
      n = sizeof(r->cmdline) - 1u;
    }
    /* Parsing failed: avoid dumping raw binary bytes into cmdline (causes control-char garbage downstream). */
    if (is_mostly_printable_ascii(slot->data, n)) {
      memcpy(r->cmdline, slot->data, n);
      r->cmdline[n] = '\0';
    } else {
      r->cmdline[0] = '\0';
      snprintf(r->script_snippet, sizeof(r->script_snippet), "raw_etw_payload_bytes=%u parse=failed", (unsigned)slot->size);
    }
  }

  apply_mitre_hints(r);

  if (slot->type == EDR_EVENT_PROCESS_CREATE) {
    edr_pt_cache_put(r->pid, r->ppid,
                     r->process_name, r->cmdline,
                     r->exe_path, r->parent_name,
                     (uint64_t)slot->timestamp_ns);
  } else if (slot->type == EDR_EVENT_PROCESS_TERMINATE) {
    edr_pt_cache_remove(r->pid);
  }

  if (slot->priority == 0) {
    edr_pt_cache_fill_record(r->pid,
                             r->grandparent_name, sizeof(r->grandparent_name),
                             r->grandparent_path, sizeof(r->grandparent_path),
                             r->parent_cmdline,   sizeof(r->parent_cmdline),
                             &r->process_chain_depth);
  }

  edr_forensic_trigger_evaluate(slot, r);

  edr_behavior_record_enrich_system_context(r);
}
