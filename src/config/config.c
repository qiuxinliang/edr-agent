#include "edr/config.h"

#ifdef _WIN32
#include <wchar.h>
#include <windows.h>
#include "edr/listen_table_win.h"

/** 与 Inno `DefaultDirName`（%ProgramFiles%\\EDR Agent）一致；ProgramData 下勿混用裸 `EDR`。 */
#define EDR_WIN_FALLBACK_PROGRAMDATA_MODELS "C:\\ProgramData\\EDR Agent\\models"

/** 将 model_dir 设为与当前 edr_agent.exe 同目录下的 `models`（UTF-8）。失败返回 0。 */
static int edr_win_model_dir_next_to_exe(char *out_utf8, size_t out_cap) {
  wchar_t wpath[MAX_PATH];
  DWORD n = GetModuleFileNameW(NULL, wpath, MAX_PATH);
  if (n == 0 || n >= MAX_PATH) {
    return 0;
  }
  wchar_t *slash = wcsrchr(wpath, L'\\');
  if (!slash) {
    slash = wcsrchr(wpath, L'/');
  }
  if (!slash) {
    return 0;
  }
  *slash = L'\0';
  if (wcslen(wpath) + wcslen(L"\\models") + 1u >= (size_t)MAX_PATH) {
    return 0;
  }
  wcscat(wpath, L"\\models");
  if (WideCharToMultiByte(CP_UTF8, 0, wpath, -1, out_utf8, (int)out_cap, NULL, NULL) <= 1) {
    return 0;
  }
  return 1;
}

/** True if model_dir is the Linux example path (optional trailing slash / spaces). */
static int edr_config_model_dir_is_unix_example(const char *md) {
  if (!md) {
    return 0;
  }
  while (*md == ' ' || *md == '\t') {
    md++;
  }
  size_t n = strlen(md);
  while (n > 0 && (md[n - 1] == ' ' || md[n - 1] == '\t' || md[n - 1] == '/')) {
    n--;
  }
  if (n == strlen("/opt/edr/models") && strncmp(md, "/opt/edr/models", n) == 0) {
    return 1;
  }
  return 0;
}

/** TOML 中仍为 Linux 示例路径时，在 Windows 上改为 exe 同目录\models。 */
static void edr_config_win_fixup_model_dir_from_unix_example(EdrConfig *cfg) {
  if (!edr_config_model_dir_is_unix_example(cfg->ave.model_dir)) {
    return;
  }
  if (!edr_win_model_dir_next_to_exe(cfg->ave.model_dir, sizeof(cfg->ave.model_dir))) {
    snprintf(cfg->ave.model_dir, sizeof(cfg->ave.model_dir), "%s", EDR_WIN_FALLBACK_PROGRAMDATA_MODELS);
  }
}
#endif

#include "edr/emit_rules.h"
#include "edr/types.h"

#include "toml.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>

/** `high_risk_immediate_ports` TOML 数组最多解析条数（防 OOM） */
#define EDR_ATTACK_SURFACE_PORTS_MAX 256
#define EDR_PREPROCESS_RULES_VERSION_DEFAULT "edr-dynamic-rules-v1-r239-97acafca"
#define EDR_PREPROCESS_RULES_BUNDLE_NAME "agent_preprocess_rules_v1.toml"

static const EdrEmitRule kBuiltinPreprocessRules[] = {
    {.name = "r-exec-001_1",
     .cmdline_contains = "EncodedCommand",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-exec-001_2",
     .cmdline_contains = "frombase64string",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-lolbin-001_1",
     .cmdline_contains = "/i:http",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-lolbin-002_1",
     .cmdline_contains = "javascript:",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-lolbin-002_2",
     .cmdline_contains = "mshtml,runhtmlapplication",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-lolbin-003_1",
     .cmdline_contains = "-urlcache",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-lolbin-004_1",
     .cmdline_contains = "vbscript",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-lolbin-005_1",
     .cmdline_contains = "process call create",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-persist-003_1",
     .cmdline_contains = "/create",
     .event_type = EDR_EVENT_SCHEDULED_TASK_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-cred-001_1",
     .cmdline_contains = "save hklm",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-cred-002_1",
     .cmdline_contains = "minidump",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-cred-002_2",
     .cmdline_contains = "sekurlsa::logonpasswords",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-cred-004_1",
     .file_path_contains = "ntds.dit",
     .event_type = EDR_EVENT_FILE_WRITE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_file_path = 1},
    {.name = "r-ransom-001_1",
     .cmdline_contains = "delete shadows",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-ransom-001_2",
     .cmdline_contains = "clear-log",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-ransom-002_1",
     .file_path_contains = "readme",
     .event_type = EDR_EVENT_FILE_WRITE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_file_path = 1},
    {.name = "r-ransom-002_2",
     .file_path_contains = "decrypt",
     .event_type = EDR_EVENT_FILE_WRITE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_file_path = 1},
    {.name = "r-webshell-001_1",
     .file_path_contains = ".php",
     .event_type = EDR_EVENT_FILE_WRITE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_file_path = 1},
    {.name = "r-webshell-001_2",
     .file_path_contains = ".aspx",
     .event_type = EDR_EVENT_FILE_WRITE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_file_path = 1},
    {.name = "r-rmm-001_1",
     .cmdline_contains = "anydesk",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-rmm-001_2",
     .cmdline_contains = "teamviewer",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-rmm-001_3",
     .cmdline_contains = "rustdesk",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-rmm-002_1",
     .cmdline_contains = "unattended",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-rmm-002_2",
     .cmdline_contains = "set-password",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-rmm-002_3",
     .cmdline_contains = "grant-easy-access",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-rmm-003_1",
     .cmdline_contains = "screenconnect",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-rmm-003_2",
     .cmdline_contains = "connectwise",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-rmm-003_3",
     .cmdline_contains = "splashtop",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-rmm-004_1",
     .cmdline_contains = "meshcentral",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-rmm-004_2",
     .cmdline_contains = "atera",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-lolbin-006_1",
     .cmdline_contains = "msiexec",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-lolbin-006_2",
     .cmdline_contains = "/qn",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-lolbin-007_1",
     .cmdline_contains = "cmstp",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-lolbin-007_2",
     .cmdline_contains = ".inf",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-lolbin-008_1",
     .cmdline_contains = "msxsl",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-persist-007_1",
     .cmdline_contains = "sc create",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-persist-007_2",
     .cmdline_contains = "binpath=",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-persist-008_1",
     .file_path_contains = "startup",
     .event_type = EDR_EVENT_FILE_WRITE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_file_path = 1},
    {.name = "r-defense-005_1",
     .cmdline_contains = "advfirewall",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-lmove-004_1",
     .cmdline_contains = "psexec",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-lolbin-009_1",
     .cmdline_contains = "bitsadmin",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-persist-009_1",
     .cmdline_contains = "root\\subscription",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-defense-006_1",
     .cmdline_contains = "wevtutil",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-defense-007_1",
     .cmdline_contains = "sc stop",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-exec-005_1",
     .cmdline_contains = "invoke-webrequest",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-cred-005_1",
     .cmdline_contains = "cmdkey",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-lmove-005_1",
     .cmdline_contains = "net view \\\\",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-disc-001_1",
     .cmdline_contains = "whoami",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-fileless-001_1",
     .cmdline_contains = "invoke-expression",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-fileless-001_2",
     .cmdline_contains = "Assembly]::Load",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-fileless-002_1",
     .cmdline_contains = "scrobj",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-fileless-003_1",
     .cmdline_contains = "installutil",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-fileless-004_1",
     .cmdline_contains = "//e:jscript",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-fileless-005_1",
     .cmdline_contains = "forfiles",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
    {.name = "r-fileless-006_1",
     .cmdline_contains = "odbcconf",
     .event_type = EDR_EVENT_PROCESS_CREATE,
     .action = EdrEmitRuleActionEmitAlways,
     .icase_cmdline = 1},
};

static void apply_builtin_preprocess_rules(EdrConfig *cfg) {
  size_t n = sizeof(kBuiltinPreprocessRules) / sizeof(kBuiltinPreprocessRules[0]);
  size_t bytes = n * sizeof(EdrEmitRule);
  cfg->preprocessing.rules = (EdrEmitRule *)malloc(bytes);
  if (!cfg->preprocessing.rules) {
    cfg->preprocessing.rules_count = 0u;
    return;
  }
  memcpy(cfg->preprocessing.rules, kBuiltinPreprocessRules, bytes);
  cfg->preprocessing.rules_count = (uint32_t)n;
}

static void take_string(toml_datum_t d, char *dst, size_t cap) {
  if (d.ok && d.u.s && cap > 0) {
    snprintf(dst, cap, "%s", d.u.s);
    free(d.u.s);
  }
}

static void load_server(toml_table_t *t, EdrConfig *cfg) {
  take_string(toml_string_in(t, "address"), cfg->server.address, sizeof(cfg->server.address));
  take_string(toml_string_in(t, "ca_cert"), cfg->server.ca_cert, sizeof(cfg->server.ca_cert));
  take_string(toml_string_in(t, "client_cert"), cfg->server.client_cert,
              sizeof(cfg->server.client_cert));
  take_string(toml_string_in(t, "client_key"), cfg->server.client_key, sizeof(cfg->server.client_key));
  {
    toml_datum_t d = toml_int_in(t, "connect_timeout_s");
    if (d.ok) {
      cfg->server.connect_timeout_s = (int)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "keepalive_interval_s");
    if (d.ok) {
      cfg->server.keepalive_interval_s = (int)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "grpc_insecure");
    if (d.ok) {
      cfg->server.grpc_insecure = d.u.b ? true : false;
    } else {
      toml_datum_t n = toml_int_in(t, "grpc_insecure");
      if (n.ok) {
        cfg->server.grpc_insecure = n.u.i != 0;
      }
    }
  }
}

static void load_agent(toml_table_t *t, EdrConfig *cfg) {
  take_string(toml_string_in(t, "endpoint_id"), cfg->agent.endpoint_id,
              sizeof(cfg->agent.endpoint_id));
  take_string(toml_string_in(t, "tenant_id"), cfg->agent.tenant_id, sizeof(cfg->agent.tenant_id));
}

static void load_collection(toml_table_t *t, EdrConfig *cfg) {
  {
    toml_datum_t d = toml_bool_in(t, "etw_enabled");
    if (d.ok) {
      cfg->collection.etw_enabled = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "etw_tcpip_provider");
    if (d.ok) {
      cfg->collection.etw_tcpip_provider = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "etw_firewall_provider");
    if (d.ok) {
      cfg->collection.etw_firewall_provider = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "etw_dns_client_provider");
    if (d.ok) {
      cfg->collection.etw_dns_client_provider = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "etw_powershell_provider");
    if (d.ok) {
      cfg->collection.etw_powershell_provider = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "etw_security_audit_provider");
    if (d.ok) {
      cfg->collection.etw_security_audit_provider = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "etw_wmi_provider");
    if (d.ok) {
      cfg->collection.etw_wmi_provider = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "ebpf_enabled");
    if (d.ok) {
      cfg->collection.ebpf_enabled = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "poll_interval_s");
    if (d.ok) {
      cfg->collection.poll_interval_s = (int)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "max_event_queue_size");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->collection.max_event_queue_size = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "etw_buffer_kb");
    if (d.ok && d.u.i > 0 && d.u.i <= 0x7fffffffLL) {
      cfg->collection.etw_buffer_kb = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "etw_flush_timer_s");
    if (d.ok && d.u.i > 0 && d.u.i <= 0x7fffffffLL) {
      cfg->collection.etw_flush_timer_s = (uint32_t)d.u.i;
    }
  }
}

static void rule_take_str(toml_table_t *rt, const char *key, char *dst, size_t cap) {
  toml_datum_t d = toml_string_in(rt, key);
  if (d.ok && d.u.s && cap > 0) {
    snprintf(dst, cap, "%s", d.u.s);
    free(d.u.s);
  }
}

/** 返回 -1=ANY；-2=未知字符串 */
static int32_t edr_parse_event_type_filter(const char *s) {
  if (!s || !s[0] || strcmp(s, "ANY") == 0) {
    return -1;
  }
  static const struct {
    const char *name;
    int32_t v;
  } tbl[] = {
      {"PROCESS_CREATE", EDR_EVENT_PROCESS_CREATE},
      {"PROCESS_TERMINATE", EDR_EVENT_PROCESS_TERMINATE},
      {"PROCESS_INJECT", EDR_EVENT_PROCESS_INJECT},
      {"DLL_LOAD", EDR_EVENT_DLL_LOAD},
      {"THREAD_CREATE_REMOTE", EDR_EVENT_THREAD_CREATE_REMOTE},
      {"FILE_READ", EDR_EVENT_FILE_READ},
      {"FILE_CREATE", EDR_EVENT_FILE_CREATE},
      {"FILE_WRITE", EDR_EVENT_FILE_WRITE},
      {"FILE_DELETE", EDR_EVENT_FILE_DELETE},
      {"FILE_RENAME", EDR_EVENT_FILE_RENAME},
      {"FILE_PERMISSION_CHANGE", EDR_EVENT_FILE_PERMISSION_CHANGE},
      {"NET_CONNECT", EDR_EVENT_NET_CONNECT},
      {"NET_LISTEN", EDR_EVENT_NET_LISTEN},
      {"NET_DNS_QUERY", EDR_EVENT_NET_DNS_QUERY},
      {"NET_TLS_HANDSHAKE", EDR_EVENT_NET_TLS_HANDSHAKE},
      {"REG_CREATE_KEY", EDR_EVENT_REG_CREATE_KEY},
      {"REG_SET_VALUE", EDR_EVENT_REG_SET_VALUE},
      {"REG_DELETE_KEY", EDR_EVENT_REG_DELETE_KEY},
      {"SCRIPT_POWERSHELL", EDR_EVENT_SCRIPT_POWERSHELL},
      {"SCRIPT_BASH", EDR_EVENT_SCRIPT_BASH},
      {"SCRIPT_PYTHON", EDR_EVENT_SCRIPT_PYTHON},
      {"SCRIPT_WMI", EDR_EVENT_SCRIPT_WMI},
      {"AUTH_LOGIN", EDR_EVENT_AUTH_LOGIN},
      {"AUTH_LOGOUT", EDR_EVENT_AUTH_LOGOUT},
      {"AUTH_FAILED", EDR_EVENT_AUTH_FAILED},
      {"AUTH_PRIVILEGE_ESC", EDR_EVENT_AUTH_PRIVILEGE_ESC},
      {"SERVICE_CREATE", EDR_EVENT_SERVICE_CREATE},
      {"SCHEDULED_TASK_CREATE", EDR_EVENT_SCHEDULED_TASK_CREATE},
      {"DRIVER_LOAD", EDR_EVENT_DRIVER_LOAD},
      {"PROTOCOL_SHELLCODE", EDR_EVENT_PROTOCOL_SHELLCODE},
      {"WEBSHELL_DETECTED", EDR_EVENT_WEBSHELL_DETECTED},
      {"FIREWALL_RULE_CHANGE", EDR_EVENT_FIREWALL_RULE_CHANGE},
  };
  for (size_t i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++) {
    if (strcmp(s, tbl[i].name) == 0) {
      return tbl[i].v;
    }
  }
  return -2;
}

static void load_preprocessing_rules(toml_table_t *t, EdrConfig *cfg) {
  toml_array_t *arr = toml_array_in(t, "rules");
  if (!arr) {
    return;
  }
  free(cfg->preprocessing.rules);
  cfg->preprocessing.rules = NULL;
  cfg->preprocessing.rules_count = 0;
  int n = toml_array_nelem(arr);
  if (n < 0) {
    return;
  }
  EdrEmitRule *block = NULL;
  uint32_t nvalid = 0;
  for (int i = 0; i < n; i++) {
    toml_table_t *rt = toml_table_at(arr, i);
    if (!rt) {
      continue;
    }
    toml_datum_t ac = toml_string_in(rt, "action");
    if (!ac.ok || !ac.u.s) {
      fprintf(stderr, "[config] preprocessing.rules[%d]: missing action, skipped\n", i);
      continue;
    }
    EdrEmitRule R;
    memset(&R, 0, sizeof(R));
    R.event_type = -1;
    rule_take_str(rt, "name", R.name, sizeof(R.name));
    if (!R.name[0]) {
      snprintf(R.name, sizeof(R.name), "rule_%d", i);
    }
    if (strcmp(ac.u.s, "drop") == 0) {
      R.action = EdrEmitRuleActionDrop;
    } else if (strcmp(ac.u.s, "emit_always") == 0) {
      R.action = EdrEmitRuleActionEmitAlways;
    } else {
      fprintf(stderr, "[config] preprocessing.rules[%d]: invalid action=%s\n", i, ac.u.s);
      free(ac.u.s);
      continue;
    }
    free(ac.u.s);

    rule_take_str(rt, "exe_path_contains", R.exe_path_contains, sizeof(R.exe_path_contains));
    rule_take_str(rt, "cmdline_contains", R.cmdline_contains, sizeof(R.cmdline_contains));
    rule_take_str(rt, "file_path_contains", R.file_path_contains, sizeof(R.file_path_contains));
    rule_take_str(rt, "dns_query_contains", R.dns_query_contains, sizeof(R.dns_query_contains));
    rule_take_str(rt, "script_snippet_contains", R.script_snippet_contains,
                  sizeof(R.script_snippet_contains));

    {
      toml_datum_t et = toml_string_in(rt, "event_type");
      if (et.ok && et.u.s) {
        R.event_type = edr_parse_event_type_filter(et.u.s);
        if (R.event_type == -2) {
          fprintf(stderr, "[config] preprocessing.rules[%d]: unknown event_type=%s\n", i, et.u.s);
          free(et.u.s);
          continue;
        }
        free(et.u.s);
      }
    }
    {
      toml_datum_t b;
      b = toml_bool_in(rt, "icase_exe_path");
      if (b.ok) {
        R.icase_exe_path = b.u.b ? 1 : 0;
      }
      b = toml_bool_in(rt, "icase_cmdline");
      if (b.ok) {
        R.icase_cmdline = b.u.b ? 1 : 0;
      }
      b = toml_bool_in(rt, "icase_file_path");
      if (b.ok) {
        R.icase_file_path = b.u.b ? 1 : 0;
      }
      b = toml_bool_in(rt, "icase_dns");
      if (b.ok) {
        R.icase_dns = b.u.b ? 1 : 0;
      }
      b = toml_bool_in(rt, "icase_script");
      if (b.ok) {
        R.icase_script = b.u.b ? 1 : 0;
      }
    }

    {
      int has_pat = R.exe_path_contains[0] || R.cmdline_contains[0] || R.file_path_contains[0] ||
                    R.dns_query_contains[0] || R.script_snippet_contains[0];
      int has_et = (R.event_type >= 0);
      if (!has_pat && !has_et) {
        fprintf(stderr, "[config] preprocessing.rules[%s]: no matchers, skipped\n", R.name);
        continue;
      }
    }

    EdrEmitRule *nb = (EdrEmitRule *)realloc(block, (size_t)(nvalid + 1u) * sizeof(EdrEmitRule));
    if (!nb) {
      fprintf(stderr, "[config] preprocessing.rules: realloc failed at rule %s\n", R.name);
      break;
    }
    block = nb;
    block[nvalid] = R;
    nvalid++;
  }
  cfg->preprocessing.rules = block;
  cfg->preprocessing.rules_count = nvalid;
}

static void load_preprocessing(toml_table_t *t, EdrConfig *cfg) {
  {
    toml_datum_t d = toml_int_in(t, "dedup_window_s");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->preprocessing.dedup_window_s = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "high_freq_threshold");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->preprocessing.high_freq_threshold = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_double_in(t, "sampling_rate_whitelist");
    if (d.ok) {
      cfg->preprocessing.sampling_rate_whitelist = d.u.d;
    }
  }
  take_string(toml_string_in(t, "rules_version"), cfg->preprocessing.rules_version,
              sizeof(cfg->preprocessing.rules_version));
  load_preprocessing_rules(t, cfg);
}

static int edr_file_exists(const char *path) {
  if (!path || !path[0]) {
    return 0;
  }
  FILE *f = fopen(path, "rb");
  if (!f) {
    return 0;
  }
  fclose(f);
  return 1;
}

static void edr_dir_of_path(const char *path, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  if (!path || !path[0]) {
    return;
  }
  size_t n = strlen(path);
  if (n + 1u > cap) {
    n = cap - 1u;
  }
  memcpy(out, path, n);
  out[n] = '\0';
  while (n > 0u) {
    char c = out[n - 1u];
    if (c == '/' || c == '\\') {
      out[n - 1u] = '\0';
      return;
    }
    n--;
  }
  out[0] = '\0';
}

static int load_preprocess_rules_bundle_file(const char *bundle_path, EdrConfig *cfg) {
  if (!bundle_path || !bundle_path[0] || !cfg || !edr_file_exists(bundle_path)) {
    return 0;
  }
  FILE *fp = fopen(bundle_path, "r");
  if (!fp) {
    return 0;
  }
  char errbuf[512];
  memset(errbuf, 0, sizeof(errbuf));
  toml_table_t *root = toml_parse_file(fp, errbuf, (int)sizeof(errbuf));
  fclose(fp);
  if (!root) {
    fprintf(stderr, "[config] preprocess bundle parse failed: %s (%s)\n",
            errbuf[0] ? errbuf : "unknown error", bundle_path);
    return 0;
  }
  toml_table_t *t = toml_table_in(root, "preprocessing");
  if (!t) {
    toml_free(root);
    fprintf(stderr, "[config] preprocess bundle has no [preprocessing]: %s\n", bundle_path);
    return 0;
  }
  load_preprocessing(t, cfg);
  toml_free(root);
  fprintf(stderr, "[config] preprocess bundle loaded: %s rules=%u version=%s\n",
          bundle_path, (unsigned)cfg->preprocessing.rules_count, cfg->preprocessing.rules_version);
  return 1;
}

static void try_auto_load_preprocess_rules_bundle(const char *config_path, int has_user_preprocess_rules,
                                                  EdrConfig *cfg) {
  if (!cfg || has_user_preprocess_rules) {
    return;
  }
  {
    const char *envp = getenv("EDR_PREPROCESS_RULES_BUNDLE_PATH");
    if (envp && envp[0]) {
      (void)load_preprocess_rules_bundle_file(envp, cfg);
      return;
    }
  }
  if (config_path && config_path[0]) {
    char dir[1024];
    char cand[1200];
    edr_dir_of_path(config_path, dir, sizeof(dir));
    if (dir[0]) {
      snprintf(cand, sizeof(cand), "%s/%s", dir, EDR_PREPROCESS_RULES_BUNDLE_NAME);
      (void)load_preprocess_rules_bundle_file(cand, cfg);
    }
  }
}

static void load_ave(toml_table_t *t, EdrConfig *cfg) {
  take_string(toml_string_in(t, "model_dir"), cfg->ave.model_dir, sizeof(cfg->ave.model_dir));
  {
    toml_datum_t d = toml_int_in(t, "scan_threads");
    if (d.ok) {
      cfg->ave.scan_threads = (int)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "max_file_size_mb");
    if (d.ok) {
      cfg->ave.max_file_size_mb = (int)d.u.i;
    }
  }
  take_string(toml_string_in(t, "sensitivity"), cfg->ave.sensitivity, sizeof(cfg->ave.sensitivity));
  {
    toml_datum_t d = toml_bool_in(t, "cert_whitelist_enabled");
    if (d.ok) {
      cfg->ave.cert_whitelist_enabled = d.u.b ? true : false;
    }
  }
  take_string(toml_string_in(t, "cert_whitelist_db_path"), cfg->ave.cert_whitelist_db_path,
              sizeof(cfg->ave.cert_whitelist_db_path));
  take_string(toml_string_in(t, "file_whitelist_db_path"), cfg->ave.file_whitelist_db_path,
              sizeof(cfg->ave.file_whitelist_db_path));
  take_string(toml_string_in(t, "ioc_db_path"), cfg->ave.ioc_db_path, sizeof(cfg->ave.ioc_db_path));
  {
    toml_datum_t d = toml_bool_in(t, "ioc_precheck_enabled");
    if (d.ok) {
      cfg->ave.ioc_precheck_enabled = d.u.b ? true : false;
    }
  }
  take_string(toml_string_in(t, "behavior_policy_db_path"), cfg->ave.behavior_policy_db_path,
              sizeof(cfg->ave.behavior_policy_db_path));
  {
    toml_datum_t d = toml_bool_in(t, "behavior_monitor_enabled");
    if (d.ok) {
      cfg->ave.behavior_monitor_enabled = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "cert_revocation_check");
    if (d.ok) {
      cfg->ave.cert_revocation_check = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "l4_realtime_behavior_link");
    if (d.ok) {
      cfg->ave.l4_realtime_behavior_link = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_double_in(t, "l4_realtime_anomaly_threshold");
    if (d.ok) {
      cfg->ave.l4_realtime_anomaly_threshold = (float)d.u.d;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "static_infer_cache_max_entries");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->ave.static_infer_cache_max_entries = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "static_infer_cache_ttl_s");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->ave.static_infer_cache_ttl_s = (uint32_t)d.u.i;
    }
  }
}

static void load_upload(toml_table_t *t, EdrConfig *cfg) {
  {
    toml_datum_t d = toml_int_in(t, "batch_max_events");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->upload.batch_max_events = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "batch_max_size_mb");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->upload.batch_max_size_mb = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "batch_timeout_s");
    if (d.ok) {
      cfg->upload.batch_timeout_s = (int)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "max_upload_mbps");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->upload.max_upload_mbps = (uint32_t)d.u.i;
    }
  }
}

static void load_offline(toml_table_t *t, EdrConfig *cfg) {
  take_string(toml_string_in(t, "queue_db_path"), cfg->offline.queue_db_path,
              sizeof(cfg->offline.queue_db_path));
  {
    toml_datum_t d = toml_int_in(t, "max_queue_size_mb");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->offline.max_queue_size_mb = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "retention_hours");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->offline.retention_hours = (uint32_t)d.u.i;
    }
  }
}

static void load_resource_limit(toml_table_t *t, EdrConfig *cfg) {
  {
    toml_datum_t d = toml_int_in(t, "cpu_limit_percent");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->resource_limit.cpu_limit_percent = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "memory_limit_mb");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->resource_limit.memory_limit_mb = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "emergency_cpu_limit");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->resource_limit.emergency_cpu_limit = (uint32_t)d.u.i;
    }
  }
}

static void load_logging(toml_table_t *t, EdrConfig *cfg) {
  take_string(toml_string_in(t, "level"), cfg->logging.level, sizeof(cfg->logging.level));
  take_string(toml_string_in(t, "log_dir"), cfg->logging.log_dir, sizeof(cfg->logging.log_dir));
  {
    toml_datum_t d = toml_int_in(t, "max_log_size_mb");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->logging.max_log_size_mb = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "max_log_files");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->logging.max_log_files = (uint32_t)d.u.i;
    }
  }
}

/** 解析 `80,443, 8080` 为去重端口表；成功写入 out_count。 */
static void edr_parse_comma_tcp_ports(const char *in, uint16_t *out, size_t *out_count, size_t max_out) {
  *out_count = 0;
  if (!in || !in[0] || !out || max_out == 0) {
    return;
  }
  const char *p = in;
  while (*p && *out_count < max_out) {
    while (*p == ' ' || *p == '\t' || *p == ',') {
      p++;
    }
    if (!*p) {
      break;
    }
    unsigned long v = 0;
    int any = 0;
    while (*p >= '0' && *p <= '9') {
      any = 1;
      v = v * 10ul + (unsigned long)(*p - '0');
      if (v > 65535ul) {
        v = 65535ul;
      }
      p++;
    }
    if (any && v >= 1ul && v <= 65535ul) {
      uint16_t pv = (uint16_t)v;
      int dup = 0;
      for (size_t i = 0; i < *out_count; i++) {
        if (out[i] == pv) {
          dup = 1;
          break;
        }
      }
      if (!dup) {
        out[(*out_count)++] = pv;
      }
    }
    while (*p && *p != ',') {
      p++;
    }
    if (*p == ',') {
      p++;
    }
  }
}

static void load_shellcode_detector(toml_table_t *t, EdrConfig *cfg) {
  {
    toml_datum_t d = toml_bool_in(t, "enabled");
    if (d.ok) {
      cfg->shellcode_detector.enabled = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "windivert_priority");
    if (d.ok && d.u.i >= -0x7fffffffLL && d.u.i <= 0x7fffffffLL) {
      cfg->shellcode_detector.windivert_priority = (int)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "max_payload_inspect");
    if (d.ok && d.u.i > 0 && d.u.i <= 0x7fffffffLL) {
      cfg->shellcode_detector.max_payload_inspect = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_double_in(t, "alert_threshold");
    if (d.ok) {
      cfg->shellcode_detector.alert_threshold = d.u.d;
    }
  }
  {
    toml_datum_t d = toml_double_in(t, "auto_isolate_threshold");
    if (d.ok) {
      cfg->shellcode_detector.auto_isolate_threshold = d.u.d;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "auto_isolate_execute");
    if (d.ok) {
      cfg->shellcode_detector.auto_isolate_execute = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_double_in(t, "heuristic_score_scale");
    if (d.ok) {
      cfg->shellcode_detector.heuristic_score_scale = d.u.d;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "yara_rules_reload_interval_s");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->shellcode_detector.yara_rules_reload_interval_s = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "monitor_smb");
    if (d.ok) {
      cfg->shellcode_detector.monitor_smb = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "monitor_rdp");
    if (d.ok) {
      cfg->shellcode_detector.monitor_rdp = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "monitor_winrm");
    if (d.ok) {
      cfg->shellcode_detector.monitor_winrm = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "monitor_msrpc");
    if (d.ok) {
      cfg->shellcode_detector.monitor_msrpc = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "monitor_ldap");
    if (d.ok) {
      cfg->shellcode_detector.monitor_ldap = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "detector_threads");
    if (d.ok && d.u.i > 0 && d.u.i <= 0x7fffffffLL) {
      cfg->shellcode_detector.detector_threads = (uint32_t)d.u.i;
    }
  }
  take_string(toml_string_in(t, "yara_rules_dir"), cfg->shellcode_detector.yara_rules_dir,
              sizeof(cfg->shellcode_detector.yara_rules_dir));
  take_string(toml_string_in(t, "forensic_dir"), cfg->shellcode_detector.forensic_dir,
              sizeof(cfg->shellcode_detector.forensic_dir));
  {
    toml_datum_t d = toml_bool_in(t, "forensic_save_pcap");
    if (d.ok) {
      cfg->shellcode_detector.forensic_save_pcap = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "evidence_preview_bytes");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->shellcode_detector.evidence_preview_bytes = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "forensic_ring_slots");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->shellcode_detector.forensic_ring_slots = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "forensic_ring_max_packet_bytes");
    if (d.ok && d.u.i > 0 && d.u.i <= 0x7fffffffLL) {
      cfg->shellcode_detector.forensic_ring_max_packet_bytes = (uint32_t)d.u.i;
    }
  }
  take_string(toml_string_in(t, "windivert_tcp_ports"), cfg->shellcode_detector.windivert_tcp_ports,
              sizeof(cfg->shellcode_detector.windivert_tcp_ports));

  cfg->shellcode_detector.windivert_ports_is_custom = false;
  cfg->shellcode_detector.windivert_tcp_ports_parsed_count = 0;
  if (cfg->shellcode_detector.windivert_tcp_ports[0]) {
    edr_parse_comma_tcp_ports(cfg->shellcode_detector.windivert_tcp_ports,
                              cfg->shellcode_detector.windivert_tcp_ports_parsed,
                              &cfg->shellcode_detector.windivert_tcp_ports_parsed_count,
                              sizeof(cfg->shellcode_detector.windivert_tcp_ports_parsed) /
                                  sizeof(cfg->shellcode_detector.windivert_tcp_ports_parsed[0]));
    if (cfg->shellcode_detector.windivert_tcp_ports_parsed_count > 0) {
      cfg->shellcode_detector.windivert_ports_is_custom = true;
    } else {
      fprintf(stderr, "[config] shellcode_detector.windivert_tcp_ports 无有效端口，使用内置 WinDivert 端口表\n");
    }
  }
}

static void load_webshell_detector(toml_table_t *t, EdrConfig *cfg) {
  {
    toml_datum_t d = toml_bool_in(t, "enabled");
    if (d.ok) {
      cfg->webshell_detector.enabled = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "discovery_interval_s");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->webshell_detector.discovery_interval_s = (uint32_t)d.u.i;
    }
  }
  take_string(toml_string_in(t, "iis_config_path"), cfg->webshell_detector.iis_config_path,
              sizeof(cfg->webshell_detector.iis_config_path));
  {
    toml_datum_t d = toml_int_in(t, "max_watch_dirs");
    if (d.ok && d.u.i > 0 && d.u.i <= 0x7fffffffLL) {
      cfg->webshell_detector.max_watch_dirs = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "monitor_subdirs");
    if (d.ok) {
      cfg->webshell_detector.monitor_subdirs = d.u.b ? true : false;
    }
  }
  take_string(toml_string_in(t, "webshell_rules_dir"), cfg->webshell_detector.webshell_rules_dir,
              sizeof(cfg->webshell_detector.webshell_rules_dir));
  {
    toml_datum_t d = toml_int_in(t, "scan_threads");
    if (d.ok && d.u.i > 0 && d.u.i <= 0x7fffffffLL) {
      cfg->webshell_detector.scan_threads = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "max_file_size_mb");
    if (d.ok && d.u.i > 0 && d.u.i <= 0x7fffffffLL) {
      cfg->webshell_detector.max_file_size_mb = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "defer_retry_ms");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->webshell_detector.defer_retry_ms = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_double_in(t, "alert_threshold");
    if (d.ok) {
      cfg->webshell_detector.alert_threshold = d.u.d;
    }
  }
  {
    toml_datum_t d = toml_double_in(t, "l2_review_threshold");
    if (d.ok) {
      cfg->webshell_detector.l2_review_threshold = d.u.d;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "upload_webshell_files");
    if (d.ok) {
      cfg->webshell_detector.upload_webshell_files = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "upload_timeout_s");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->webshell_detector.upload_timeout_s = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "max_upload_size_mb");
    if (d.ok && d.u.i > 0 && d.u.i <= 0x7fffffffLL) {
      cfg->webshell_detector.max_upload_size_mb = (uint32_t)d.u.i;
    }
  }
}

static int edr_streq_icase(const char *a, const char *b) {
  if (!a || !b) {
    return 0;
  }
  for (; *a && *b; a++, b++) {
    if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
      return 0;
    }
  }
  return *a == 0 && *b == 0;
}

static int edr_has_prefix_icase(const char *s, const char *pre) {
  if (!s || !pre) {
    return 0;
  }
  for (; *pre; s++, pre++) {
    if (!*s) {
      return 0;
    }
    if (tolower((unsigned char)*s) != tolower((unsigned char)*pre)) {
      return 0;
    }
  }
  return 1;
}

void edr_config_log_semantic_warnings(const EdrConfig *cfg) {
  if (!cfg) {
    return;
  }
  const char *e = getenv("EDR_PLATFORM_REST_BASE");
  const char *rest = (e && e[0]) ? e : cfg->platform.rest_base_url;
  if (!rest || !rest[0]) {
    return;
  }
  if (!edr_has_prefix_icase(rest, "http://") && !edr_has_prefix_icase(rest, "https://")) {
    fprintf(stderr, "[config] WARN: EDR_PLATFORM_REST_BASE / [platform].rest_base_url should start with http:// or "
                    "https:// (effective: %.400s)\n",
            rest);
  } else if (!strstr(rest, "/api/")) {
    fprintf(stderr,
            "[config] WARN: rest base has no path segment '/api/' (effective: %.400s). If you only need /healthz, this "
            "is OK; for ingest/attack-surface, use a full API root e.g. http://host:port/api/v1. See "
            "docs/WP3_CONFIG_VALIDATION.md.\n",
            rest);
  }
  if (!cfg->agent.endpoint_id[0] || edr_streq_icase(cfg->agent.endpoint_id, "auto")) {
    fprintf(stderr,
            "[config] WARN: [agent].endpoint_id is empty or 'auto' while platform REST is configured; set a concrete "
            "id registered in the platform. See edr-backend/docs/LOCAL_STACK_INTEGRATION.md and "
            "docs/WP3_CONFIG_VALIDATION.md.\n");
  }
  if (!cfg->agent.tenant_id[0] || edr_streq_icase(cfg->agent.tenant_id, "tenant_default")) {
    fprintf(stderr, "[config] WARN: [agent].tenant_id is empty or still 'tenant_default' (placeholder) while platform "
                    "REST is configured; set your real tenant. See docs/WP3_CONFIG_VALIDATION.md.\n");
  }
}

static void edr_config_clamp(EdrConfig *cfg) {
  if (cfg->collection.max_event_queue_size < 256u) {
    cfg->collection.max_event_queue_size = 4096u;
  }
  if (cfg->collection.max_event_queue_size > 65536u) {
    cfg->collection.max_event_queue_size = 65536u;
  }
  /* A4.2：ETW 实时会话缓冲/刷写；0 表示使用默认。有效区间与 Win32 常见实践对齐。 */
  if (cfg->collection.etw_buffer_kb == 0u) {
    cfg->collection.etw_buffer_kb = 64u;
  }
  if (cfg->collection.etw_buffer_kb < 4u) {
    cfg->collection.etw_buffer_kb = 4u;
  }
  if (cfg->collection.etw_buffer_kb > 1024u) {
    cfg->collection.etw_buffer_kb = 1024u;
  }
  if (cfg->collection.etw_flush_timer_s == 0u) {
    cfg->collection.etw_flush_timer_s = 1u;
  }
  if (cfg->collection.etw_flush_timer_s > 300u) {
    cfg->collection.etw_flush_timer_s = 300u;
  }
#if defined(_WIN32)
  {
    const char *e = getenv("EDR_ETW_BUFFER_KB");
    if (e && e[0]) {
      char *end = NULL;
      unsigned long v = strtoul(e, &end, 10);
      (void)end;
      if (v >= 4ul && v <= 1024ul) {
        cfg->collection.etw_buffer_kb = (uint32_t)v;
      }
    }
  }
  {
    const char *e = getenv("EDR_ETW_FLUSH_TIMER_S");
    if (e && e[0]) {
      char *end = NULL;
      unsigned long v = strtoul(e, &end, 10);
      (void)end;
      if (v >= 1ul && v <= 300ul) {
        cfg->collection.etw_flush_timer_s = (uint32_t)v;
      }
    }
  }
#endif
  if (cfg->upload.batch_max_size_mb < 1u) {
    cfg->upload.batch_max_size_mb = 4u;
  }
  if (cfg->upload.batch_max_size_mb > 64u) {
    cfg->upload.batch_max_size_mb = 64u;
  }
  if (cfg->preprocessing.high_freq_threshold < 1u) {
    cfg->preprocessing.high_freq_threshold = 100u;
  }
  if (cfg->upload.batch_max_events == 0u) {
    cfg->upload.batch_max_events = 500u;
  }
  if (cfg->upload.batch_max_events > 50000u) {
    cfg->upload.batch_max_events = 50000u;
  }
  if (cfg->shellcode_detector.alert_threshold < 0.0) {
    cfg->shellcode_detector.alert_threshold = 0.0;
  }
  if (cfg->shellcode_detector.alert_threshold > 1.0) {
    cfg->shellcode_detector.alert_threshold = 1.0;
  }
  if (cfg->shellcode_detector.auto_isolate_threshold < 0.0) {
    cfg->shellcode_detector.auto_isolate_threshold = 0.0;
  }
  if (cfg->shellcode_detector.auto_isolate_threshold > 1.0) {
    cfg->shellcode_detector.auto_isolate_threshold = 1.0;
  }
  if (cfg->shellcode_detector.heuristic_score_scale < 0.01) {
    cfg->shellcode_detector.heuristic_score_scale = 0.01;
  }
  if (cfg->shellcode_detector.heuristic_score_scale > 3.0) {
    cfg->shellcode_detector.heuristic_score_scale = 3.0;
  }
  if (cfg->shellcode_detector.yara_rules_reload_interval_s > 86400u) {
    cfg->shellcode_detector.yara_rules_reload_interval_s = 86400u;
  }
  if (cfg->shellcode_detector.max_payload_inspect < 256u) {
    cfg->shellcode_detector.max_payload_inspect = 256u;
  }
  if (cfg->shellcode_detector.max_payload_inspect > 65535u) {
    cfg->shellcode_detector.max_payload_inspect = 65535u;
  }
  if (cfg->shellcode_detector.detector_threads < 1u) {
    cfg->shellcode_detector.detector_threads = 1u;
  }
  if (cfg->shellcode_detector.detector_threads > 4u) {
    cfg->shellcode_detector.detector_threads = 4u;
  }
  if (cfg->shellcode_detector.evidence_preview_bytes > 512u) {
    cfg->shellcode_detector.evidence_preview_bytes = 512u;
  }
  if (cfg->shellcode_detector.forensic_ring_slots > 512u) {
    cfg->shellcode_detector.forensic_ring_slots = 512u;
  }
  if (cfg->shellcode_detector.forensic_ring_max_packet_bytes < 256u) {
    cfg->shellcode_detector.forensic_ring_max_packet_bytes = 256u;
  }
  if (cfg->shellcode_detector.forensic_ring_max_packet_bytes > 65535u) {
    cfg->shellcode_detector.forensic_ring_max_packet_bytes = 65535u;
  }
  if (cfg->self_protect.event_bus_pressure_warn_pct > 100u) {
    cfg->self_protect.event_bus_pressure_warn_pct = 100u;
  }
  if (cfg->webshell_detector.max_watch_dirs < 1u) {
    cfg->webshell_detector.max_watch_dirs = 64u;
  }
  if (cfg->webshell_detector.max_watch_dirs > 4096u) {
    cfg->webshell_detector.max_watch_dirs = 4096u;
  }
  if (cfg->webshell_detector.scan_threads < 1u) {
    cfg->webshell_detector.scan_threads = 1u;
  }
  if (cfg->webshell_detector.scan_threads > 8u) {
    cfg->webshell_detector.scan_threads = 8u;
  }
  if (cfg->webshell_detector.max_file_size_mb < 1u) {
    cfg->webshell_detector.max_file_size_mb = 10u;
  }
  if (cfg->webshell_detector.max_file_size_mb > 1024u) {
    cfg->webshell_detector.max_file_size_mb = 1024u;
  }
  if (cfg->webshell_detector.defer_retry_ms > 60000u) {
    cfg->webshell_detector.defer_retry_ms = 60000u;
  }
  if (cfg->webshell_detector.alert_threshold < 0.0) {
    cfg->webshell_detector.alert_threshold = 0.0;
  }
  if (cfg->webshell_detector.alert_threshold > 1.0) {
    cfg->webshell_detector.alert_threshold = 1.0;
  }
  if (cfg->webshell_detector.l2_review_threshold < 0.0) {
    cfg->webshell_detector.l2_review_threshold = 0.0;
  }
  if (cfg->webshell_detector.l2_review_threshold > 1.0) {
    cfg->webshell_detector.l2_review_threshold = 1.0;
  }
  if (cfg->webshell_detector.upload_timeout_s > 3600u) {
    cfg->webshell_detector.upload_timeout_s = 3600u;
  }
  if (cfg->webshell_detector.max_upload_size_mb < 1u) {
    cfg->webshell_detector.max_upload_size_mb = 10u;
  }
  if (cfg->webshell_detector.max_upload_size_mb > 1024u) {
    cfg->webshell_detector.max_upload_size_mb = 1024u;
  }

  if (cfg->fl.min_new_samples < 1) {
    cfg->fl.min_new_samples = 100;
  }
  if (cfg->fl.min_new_samples > 1000000) {
    cfg->fl.min_new_samples = 1000000;
  }
  if (cfg->fl.idle_cpu_threshold < 0.0f) {
    cfg->fl.idle_cpu_threshold = 0.0f;
  }
  if (cfg->fl.idle_cpu_threshold > 1.0f) {
    cfg->fl.idle_cpu_threshold = 1.0f;
  }
  if (cfg->fl.dp_epsilon < 0.01f) {
    cfg->fl.dp_epsilon = 0.01f;
  }
  if (cfg->fl.dp_epsilon > 100.0f) {
    cfg->fl.dp_epsilon = 100.0f;
  }
  if (cfg->fl.dp_clip_norm < 1e-6f) {
    cfg->fl.dp_clip_norm = 1e-6f;
  }
  if (cfg->fl.dp_clip_norm > 1.0e6f) {
    cfg->fl.dp_clip_norm = 1.0e6f;
  }
  if (cfg->fl.max_participated_rounds < 1) {
    cfg->fl.max_participated_rounds = 1;
  }
  if (cfg->fl.max_participated_rounds > 100000) {
    cfg->fl.max_participated_rounds = 100000;
  }
  if (cfg->fl.gradient_chunk_size_kb < 16) {
    cfg->fl.gradient_chunk_size_kb = 16;
  }
  if (cfg->fl.gradient_chunk_size_kb > 4096) {
    cfg->fl.gradient_chunk_size_kb = 4096;
  }
  if (cfg->fl.local_epochs < 1) {
    cfg->fl.local_epochs = 1;
  }
  if (cfg->fl.local_epochs > 100) {
    cfg->fl.local_epochs = 100;
  }
  if (cfg->fl.mock_round_interval_s > 86400u) {
    cfg->fl.mock_round_interval_s = 86400u;
  }
  {
    size_t i;
    if (cfg->fl.model_target[0] == '\0') {
      snprintf(cfg->fl.model_target, sizeof(cfg->fl.model_target), "%s", "static");
    }
    for (i = 0; i < sizeof(cfg->fl.model_target) && cfg->fl.model_target[i]; i++) {
      cfg->fl.model_target[i] = (char)tolower((unsigned char)cfg->fl.model_target[i]);
    }
    if (strcmp(cfg->fl.model_target, "static") != 0 && strcmp(cfg->fl.model_target, "behavior") != 0) {
      snprintf(cfg->fl.model_target, sizeof(cfg->fl.model_target), "%s", "static");
    }
  }
  if (cfg->fl.frozen_layer_count_static > EDR_FL_FROZEN_MAX) {
    cfg->fl.frozen_layer_count_static = EDR_FL_FROZEN_MAX;
  }
  if (cfg->fl.frozen_layer_count_behavior > EDR_FL_FROZEN_MAX) {
    cfg->fl.frozen_layer_count_behavior = EDR_FL_FROZEN_MAX;
  }

  /* §19.8 攻击面：间隔秒数、TOP 上限、防火墙规则枚举上限 */
  {
    uint32_t *iv[] = {
        &cfg->attack_surface.port_interval_s,
        &cfg->attack_surface.conn_interval_s,
        &cfg->attack_surface.service_interval_s,
        &cfg->attack_surface.policy_interval_s,
        &cfg->attack_surface.full_snapshot_interval_s,
    };
    for (size_t i = 0; i < sizeof(iv) / sizeof(iv[0]); i++) {
      if (*iv[i] < 30u) {
        *iv[i] = 30u;
      }
      if (*iv[i] > 604800u) {
        *iv[i] = 604800u;
      }
    }
  }
  if (cfg->attack_surface.outbound_top_n < 1u) {
    cfg->attack_surface.outbound_top_n = 1u;
  }
  if (cfg->attack_surface.outbound_top_n > 8192u) {
    cfg->attack_surface.outbound_top_n = 8192u;
  }
  if (cfg->attack_surface.egress_top_n < 1u) {
    cfg->attack_surface.egress_top_n = 1u;
  }
  if (cfg->attack_surface.egress_top_n > 256u) {
    cfg->attack_surface.egress_top_n = 256u;
  }
  if (cfg->attack_surface.firewall_rule_detail_max < 1u) {
    cfg->attack_surface.firewall_rule_detail_max = 1u;
  }
  if (cfg->attack_surface.firewall_rule_detail_max > 500000u) {
    cfg->attack_surface.firewall_rule_detail_max = 500000u;
  }
  if (cfg->attack_surface.etw_refresh_debounce_s < 1u) {
    cfg->attack_surface.etw_refresh_debounce_s = 1u;
  }
  if (cfg->attack_surface.etw_refresh_debounce_s > 300u) {
    cfg->attack_surface.etw_refresh_debounce_s = 300u;
  }
  if (cfg->attack_surface.win_listen_cache_ttl_ms > 300000u) {
    cfg->attack_surface.win_listen_cache_ttl_ms = 300000u;
  }

  if (cfg->ave.l4_realtime_anomaly_threshold < 0.f) {
    cfg->ave.l4_realtime_anomaly_threshold = 0.f;
  }
  if (cfg->ave.l4_realtime_anomaly_threshold > 1.f) {
    cfg->ave.l4_realtime_anomaly_threshold = 1.f;
  }
  if (cfg->ave.static_infer_cache_max_entries > 4096u) {
    cfg->ave.static_infer_cache_max_entries = 4096u;
  }
  if (cfg->ave.static_infer_cache_ttl_s > 864000u) {
    cfg->ave.static_infer_cache_ttl_s = 864000u;
  }
  {
    const char *e = getenv("EDR_AVE_CERT_REVOCATION");
    if (e && e[0] == '1') {
      cfg->ave.cert_revocation_check = true;
    }
    if (e && e[0] == '0') {
      cfg->ave.cert_revocation_check = false;
    }
  }
}

void edr_config_free_heap(EdrConfig *cfg) {
  if (!cfg) {
    return;
  }
  free(cfg->preprocessing.rules);
  cfg->preprocessing.rules = NULL;
  cfg->preprocessing.rules_count = 0;
  free(cfg->attack_surface.high_risk_immediate_ports);
  cfg->attack_surface.high_risk_immediate_ports = NULL;
  cfg->attack_surface.high_risk_immediate_ports_count = 0;
}

void edr_config_apply_defaults(EdrConfig *cfg) {
  memset(cfg, 0, sizeof(*cfg));
  snprintf(cfg->server.address, sizeof(cfg->server.address), "%s", "127.0.0.1:50051");
  cfg->server.connect_timeout_s = 10;
  cfg->server.keepalive_interval_s = 30;

  snprintf(cfg->agent.endpoint_id, sizeof(cfg->agent.endpoint_id), "%s", "auto");
  snprintf(cfg->agent.tenant_id, sizeof(cfg->agent.tenant_id), "%s", "tenant_default");

  cfg->collection.etw_enabled = true;
  cfg->collection.etw_tcpip_provider = true;
  cfg->collection.etw_firewall_provider = true;
  cfg->collection.etw_dns_client_provider = true;
  cfg->collection.etw_powershell_provider = true;
  cfg->collection.etw_security_audit_provider = true;
  cfg->collection.etw_wmi_provider = true;
  cfg->collection.ebpf_enabled = true;
  cfg->collection.poll_interval_s = 1;
  cfg->collection.max_event_queue_size = 4096u;
  cfg->collection.etw_buffer_kb = 0u;
  cfg->collection.etw_flush_timer_s = 0u;

  cfg->preprocessing.dedup_window_s = 30u;
  cfg->preprocessing.high_freq_threshold = 100u;
  cfg->preprocessing.sampling_rate_whitelist = 0.1;
  snprintf(cfg->preprocessing.rules_version, sizeof(cfg->preprocessing.rules_version), "%s",
           EDR_PREPROCESS_RULES_VERSION_DEFAULT);
  apply_builtin_preprocess_rules(cfg);

#ifdef _WIN32
  if (!edr_win_model_dir_next_to_exe(cfg->ave.model_dir, sizeof(cfg->ave.model_dir))) {
    snprintf(cfg->ave.model_dir, sizeof(cfg->ave.model_dir), "%s", EDR_WIN_FALLBACK_PROGRAMDATA_MODELS);
  }
#else
  snprintf(cfg->ave.model_dir, sizeof(cfg->ave.model_dir), "%s", "/opt/edr/models");
#endif
  cfg->ave.scan_threads = 2;
  cfg->ave.max_file_size_mb = 256;
  snprintf(cfg->ave.sensitivity, sizeof(cfg->ave.sensitivity), "%s", "MEDIUM");
  cfg->ave.enabled = false;
#ifdef _WIN32
  cfg->ave.cert_whitelist_enabled = true;
#else
  cfg->ave.cert_whitelist_enabled = false;
#endif
  cfg->ave.cert_whitelist_db_path[0] = '\0';
  cfg->ave.file_whitelist_db_path[0] = '\0';
  cfg->ave.ioc_db_path[0] = '\0';
  cfg->ave.ioc_precheck_enabled = true;
  cfg->ave.behavior_policy_db_path[0] = '\0';
  cfg->ave.behavior_monitor_enabled = true;
  cfg->ave.cert_revocation_check = false;
  cfg->ave.l4_realtime_behavior_link = false;
  cfg->ave.l4_realtime_anomaly_threshold = 0.65f;
  cfg->ave.static_infer_cache_max_entries = 0u;
  cfg->ave.static_infer_cache_ttl_s = 0u;

  cfg->upload.batch_max_events = 500u;
  cfg->upload.batch_max_size_mb = 4u;
  cfg->upload.batch_timeout_s = 5;
  cfg->upload.max_upload_mbps = 1u;

  snprintf(cfg->offline.queue_db_path, sizeof(cfg->offline.queue_db_path), "%s",
           "edr_queue.db");
  cfg->offline.max_queue_size_mb = 512u;
  cfg->offline.retention_hours = 72u;

  cfg->resource_limit.cpu_limit_percent = 1u;
  cfg->resource_limit.memory_limit_mb = 100u;
  cfg->resource_limit.emergency_cpu_limit = 5u;

  snprintf(cfg->logging.level, sizeof(cfg->logging.level), "%s", "info");
  snprintf(cfg->logging.log_dir, sizeof(cfg->logging.log_dir), "%s", "/var/log/edr");
  cfg->logging.max_log_size_mb = 100u;
  cfg->logging.max_log_files = 10u;

  cfg->shellcode_detector.enabled = false;
  cfg->shellcode_detector.windivert_priority = -1000;
  cfg->shellcode_detector.max_payload_inspect = 16384u;
  cfg->shellcode_detector.alert_threshold = 0.70;
  cfg->shellcode_detector.auto_isolate_threshold = 0.95;
  cfg->shellcode_detector.auto_isolate_execute = false;
  cfg->shellcode_detector.heuristic_score_scale = 1.0;
  cfg->shellcode_detector.yara_rules_reload_interval_s = 0u;
  cfg->shellcode_detector.monitor_smb = true;
  cfg->shellcode_detector.monitor_rdp = true;
  cfg->shellcode_detector.monitor_winrm = true;
  cfg->shellcode_detector.monitor_msrpc = true;
  cfg->shellcode_detector.monitor_ldap = true;
  cfg->shellcode_detector.detector_threads = 2u;
  cfg->shellcode_detector.yara_rules_dir[0] = '\0';
  cfg->shellcode_detector.forensic_dir[0] = '\0';
  cfg->shellcode_detector.forensic_save_pcap = false;
  cfg->shellcode_detector.evidence_preview_bytes = 0u;
  cfg->shellcode_detector.forensic_ring_slots = 0u;
  cfg->shellcode_detector.forensic_ring_max_packet_bytes = 2048u;
  cfg->shellcode_detector.windivert_tcp_ports[0] = '\0';
  cfg->shellcode_detector.windivert_ports_is_custom = false;
  cfg->shellcode_detector.windivert_tcp_ports_parsed_count = 0;

  cfg->webshell_detector.enabled = false;
  cfg->webshell_detector.discovery_interval_s = 1800u;
  cfg->webshell_detector.iis_config_path[0] = '\0';
  cfg->webshell_detector.max_watch_dirs = 64u;
  cfg->webshell_detector.monitor_subdirs = true;
  cfg->webshell_detector.webshell_rules_dir[0] = '\0';
  cfg->webshell_detector.scan_threads = 2u;
  cfg->webshell_detector.max_file_size_mb = 10u;
  cfg->webshell_detector.defer_retry_ms = 1000u;
  cfg->webshell_detector.alert_threshold = 0.50;
  cfg->webshell_detector.l2_review_threshold = 0.80;
  cfg->webshell_detector.upload_webshell_files = true;
  cfg->webshell_detector.upload_timeout_s = 60u;
  cfg->webshell_detector.max_upload_size_mb = 10u;

  cfg->detection.auto_profile = true;
  cfg->detection.shellcode_mode = -1;
  cfg->detection.webshell_mode = -1;
  cfg->detection.pmfe_mode = 0;

  cfg->pmfe.idle_scan_enabled = false;
  cfg->pmfe.idle_scan_interval_min = 15u;
  cfg->pmfe.idle_scan_max_procs = 8u;
  cfg->pmfe.idle_cpu_threshold = 15.0;
  cfg->pmfe.idle_skip_on_battery = true;

  cfg->fl.enabled = false;
  cfg->fl.coordinator_grpc_addr[0] = '\0';
  cfg->fl.coordinator_http_url[0] = '\0';
  cfg->fl.privacy_budget_db_path[0] = '\0';
  cfg->fl.fl_samples_db_path[0] = '\0';
  cfg->fl.min_new_samples = 100;
  cfg->fl.idle_cpu_threshold = 0.3f;
  cfg->fl.local_epochs = 3;
  cfg->fl.dp_epsilon = 1.2f;
  cfg->fl.dp_clip_norm = 1.0f;
  cfg->fl.max_participated_rounds = 50;
  cfg->fl.gradient_chunk_size_kb = 256;
  cfg->fl.mock_round_interval_s = 0u;
  snprintf(cfg->fl.model_target, sizeof(cfg->fl.model_target), "%s", "static");
  cfg->fl.coordinator_secp256r1_pubkey_hex[0] = '\0';
  cfg->fl.coordinator_secp256r1_pub_len = 0u;
  cfg->fl.frozen_layer_count_static = 0;
  cfg->fl.frozen_layer_count_behavior = 0;

  cfg->command.allow_dangerous = false;

  snprintf(cfg->platform.rest_user_id, sizeof(cfg->platform.rest_user_id), "%s", "edr-agent");

  cfg->attack_surface.enabled = false;
  /* min(port, service, policy, full) 驱动周期与 ETW/刷新 POST 共享间隔；默认 2h 降频 */
  cfg->attack_surface.port_interval_s = 7200u;
  cfg->attack_surface.conn_interval_s = 300u;
  cfg->attack_surface.service_interval_s = 7200u;
  cfg->attack_surface.policy_interval_s = 7200u;
  cfg->attack_surface.full_snapshot_interval_s = 7200u;
  cfg->attack_surface.outbound_top_n = 128u;
  cfg->attack_surface.egress_top_n = 32u;
  cfg->attack_surface.outbound_exclude_loopback = true;
  snprintf(cfg->attack_surface.geoip_db_path, sizeof(cfg->attack_surface.geoip_db_path), "%s",
           "/opt/edr/data/GeoLite2-City.mmdb");
  cfg->attack_surface.firewall_rule_detail_max = 500u;
  cfg->attack_surface.high_risk_immediate_ports = NULL;
  cfg->attack_surface.high_risk_immediate_ports_count = 0;
  cfg->attack_surface.etw_refresh_triggers_snapshot = true;
  cfg->attack_surface.etw_refresh_debounce_s = 8u;
  cfg->attack_surface.win_listen_cache_ttl_ms = 2000u;

  cfg->self_protect.anti_debug = false;
  cfg->self_protect.job_object_windows = false;
  cfg->self_protect.watchdog_log_interval_s = 0u;
  cfg->self_protect.event_bus_pressure_warn_pct = 90u;

  cfg->remote.rules_url[0] = '\0';
  cfg->remote.p0_bundle_url[0] = '\0';
  cfg->remote.poll_interval_s = 0;
  cfg->remote.version_url[0] = '\0';
  cfg->remote.download_url[0] = '\0';
  cfg->remote.auto_update = false;
}

static void load_detection(toml_table_t *t, EdrConfig *cfg) {
  {
    toml_datum_t d = toml_bool_in(t, "auto_profile");
    if (d.ok) { cfg->detection.auto_profile = d.u.b ? true : false; }
  }
  {
    toml_datum_t d = toml_int_in(t, "shellcode_mode");
    if (d.ok) { cfg->detection.shellcode_mode = (int)d.u.i; }
  }
  {
    toml_datum_t d = toml_int_in(t, "webshell_mode");
    if (d.ok) { cfg->detection.webshell_mode = (int)d.u.i; }
  }
  {
    toml_datum_t d = toml_int_in(t, "pmfe_mode");
    if (d.ok) { cfg->detection.pmfe_mode = (int)d.u.i; }
  }
}

static void load_pmfe(toml_table_t *t, EdrConfig *cfg) {
  {
    toml_datum_t d = toml_bool_in(t, "idle_scan_enabled");
    if (d.ok) { cfg->pmfe.idle_scan_enabled = d.u.b ? true : false; }
  }
  {
    toml_datum_t d = toml_int_in(t, "idle_scan_interval_min");
    if (d.ok && d.u.i >= 1 && d.u.i <= 1440) { cfg->pmfe.idle_scan_interval_min = (uint32_t)d.u.i; }
  }
  {
    toml_datum_t d = toml_int_in(t, "idle_scan_max_procs");
    if (d.ok && d.u.i >= 1 && d.u.i <= 64) { cfg->pmfe.idle_scan_max_procs = (uint32_t)d.u.i; }
  }
  {
    toml_datum_t d = toml_double_in(t, "idle_cpu_threshold");
    if (d.ok && d.u.d >= 1.0 && d.u.d <= 90.0) { cfg->pmfe.idle_cpu_threshold = d.u.d; }
  }
  {
    toml_datum_t d = toml_bool_in(t, "idle_skip_on_battery");
    if (d.ok) { cfg->pmfe.idle_skip_on_battery = d.u.b ? true : false; }
  }
}

static void load_command(toml_table_t *t, EdrConfig *cfg) {
  toml_datum_t d = toml_bool_in(t, "allow_dangerous");
  if (d.ok) {
    cfg->command.allow_dangerous = d.u.b ? true : false;
  }
}

static void load_platform(toml_table_t *t, EdrConfig *cfg) {
  take_string(toml_string_in(t, "rest_base_url"), cfg->platform.rest_base_url,
              sizeof(cfg->platform.rest_base_url));
  take_string(toml_string_in(t, "rest_user_id"), cfg->platform.rest_user_id,
              sizeof(cfg->platform.rest_user_id));
  take_string(toml_string_in(t, "rest_bearer_token"), cfg->platform.rest_bearer_token,
              sizeof(cfg->platform.rest_bearer_token));
}

static void load_remote(toml_table_t *t, EdrConfig *cfg) {
  take_string(toml_string_in(t, "rules_url"), cfg->remote.rules_url,
              sizeof(cfg->remote.rules_url));
  take_string(toml_string_in(t, "p0_bundle_url"), cfg->remote.p0_bundle_url,
              sizeof(cfg->remote.p0_bundle_url));
  take_string(toml_string_in(t, "version_url"), cfg->remote.version_url,
              sizeof(cfg->remote.version_url));
  take_string(toml_string_in(t, "download_url"), cfg->remote.download_url,
              sizeof(cfg->remote.download_url));
  toml_datum_t d = toml_int_in(t, "poll_interval_s");
  if (d.ok && d.u.i >= 5 && d.u.i <= 86400) {
    cfg->remote.poll_interval_s = (int)d.u.i;
  }
  {
    toml_datum_t b = toml_bool_in(t, "auto_update");
    if (b.ok) {
      cfg->remote.auto_update = b.u.b ? true : false;
    }
  }
}

/** 解析 `[fl] coordinator_secp256r1_pubkey_hex` → SEC1 点（33 或 65 字节） */
static int parse_p256_pubkey_hex(const char *hex, uint8_t *out, size_t out_cap, uint32_t *out_len) {
  const char *p = hex;
  size_t n = 0;
  if (!hex || !out || !out_len) {
    return -1;
  }
  while (*p == ' ' || *p == '\t') {
    p++;
  }
  if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
    p += 2;
  }
  while (*p) {
    unsigned int v;
    if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
      break;
    }
    if (!isxdigit((unsigned char)p[0]) || !isxdigit((unsigned char)p[1])) {
      return -1;
    }
    if (sscanf(p, "%2x", &v) != 1) {
      return -1;
    }
    if (n >= out_cap) {
      return -1;
    }
    out[n++] = (uint8_t)v;
    p += 2;
  }
  *out_len = (uint32_t)n;
  if (n != 33u && n != 65u) {
    return -1;
  }
  return 0;
}

static void sanitize_fl_frozen_name(const char *in, char *out, size_t out_cap) {
  size_t j = 0;
  const char *p = in;
  if (!in || !out || out_cap < 2u) {
    if (out && out_cap > 0u) {
      out[0] = '\0';
    }
    return;
  }
  while (*p && j + 1u < out_cap) {
    unsigned char c = (unsigned char)*p++;
    if (c <= 32u) {
      continue;
    }
    if (strchr("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-", (int)c) != NULL) {
      out[j++] = (char)c;
    } else {
      out[j++] = '_';
    }
  }
  out[j] = '\0';
}

static void load_fl_frozen_array(toml_table_t *fz, const char *key, char buf[][EDR_FL_FROZEN_NAME_MAX], size_t *count) {
  toml_array_t *arr = toml_array_in(fz, key);
  int ni;
  int i;
  *count = 0;
  if (!arr) {
    return;
  }
  ni = toml_array_nelem(arr);
  for (i = 0; i < ni && *count < EDR_FL_FROZEN_MAX; i++) {
    toml_datum_t d = toml_string_at(arr, i);
    if (!d.ok || !d.u.s) {
      continue;
    }
    sanitize_fl_frozen_name(d.u.s, buf[*count], EDR_FL_FROZEN_NAME_MAX);
    free(d.u.s);
    if (buf[*count][0]) {
      (*count)++;
    }
  }
}

static void load_fl(toml_table_t *t, EdrConfig *cfg) {
  {
    toml_datum_t d = toml_bool_in(t, "enabled");
    if (d.ok) {
      cfg->fl.enabled = d.u.b ? true : false;
    }
  }
  take_string(toml_string_in(t, "coordinator_grpc_addr"), cfg->fl.coordinator_grpc_addr,
              sizeof(cfg->fl.coordinator_grpc_addr));
  take_string(toml_string_in(t, "coordinator_http_url"), cfg->fl.coordinator_http_url,
              sizeof(cfg->fl.coordinator_http_url));
  take_string(toml_string_in(t, "coordinator_secp256r1_pubkey_hex"), cfg->fl.coordinator_secp256r1_pubkey_hex,
              sizeof(cfg->fl.coordinator_secp256r1_pubkey_hex));
  if (cfg->fl.coordinator_secp256r1_pubkey_hex[0]) {
    if (parse_p256_pubkey_hex(cfg->fl.coordinator_secp256r1_pubkey_hex, cfg->fl.coordinator_secp256r1_pub,
                              sizeof(cfg->fl.coordinator_secp256r1_pub),
                              &cfg->fl.coordinator_secp256r1_pub_len) != 0) {
      cfg->fl.coordinator_secp256r1_pub_len = 0u;
    }
  } else {
    cfg->fl.coordinator_secp256r1_pub_len = 0u;
  }
  take_string(toml_string_in(t, "privacy_budget_db_path"), cfg->fl.privacy_budget_db_path,
              sizeof(cfg->fl.privacy_budget_db_path));
  take_string(toml_string_in(t, "fl_samples_db_path"), cfg->fl.fl_samples_db_path,
              sizeof(cfg->fl.fl_samples_db_path));
  take_string(toml_string_in(t, "model_target"), cfg->fl.model_target, sizeof(cfg->fl.model_target));
  {
    toml_datum_t d = toml_int_in(t, "min_new_samples");
    if (d.ok && d.u.i >= 1 && d.u.i <= 10000000) {
      cfg->fl.min_new_samples = (int)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_double_in(t, "idle_cpu_threshold");
    if (d.ok) {
      cfg->fl.idle_cpu_threshold = (float)d.u.d;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "local_epochs");
    if (d.ok && d.u.i >= 1 && d.u.i <= 1000) {
      cfg->fl.local_epochs = (int)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_double_in(t, "dp_epsilon");
    if (d.ok) {
      cfg->fl.dp_epsilon = (float)d.u.d;
    }
  }
  {
    toml_datum_t d = toml_double_in(t, "dp_clip_norm");
    if (d.ok) {
      cfg->fl.dp_clip_norm = (float)d.u.d;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "max_participated_rounds");
    if (d.ok && d.u.i >= 1 && d.u.i <= 10000000) {
      cfg->fl.max_participated_rounds = (int)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "gradient_chunk_size_kb");
    if (d.ok && d.u.i >= 1 && d.u.i <= 100000) {
      cfg->fl.gradient_chunk_size_kb = (int)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "mock_round_interval_s");
    if (d.ok && d.u.i >= 0 && d.u.i <= 86400000) {
      cfg->fl.mock_round_interval_s = (uint32_t)d.u.i;
    }
  }
  {
    toml_table_t *fz = toml_table_in(t, "frozen_layers");
    if (fz) {
      load_fl_frozen_array(fz, "static", cfg->fl.frozen_layer_static, &cfg->fl.frozen_layer_count_static);
      load_fl_frozen_array(fz, "behavior", cfg->fl.frozen_layer_behavior, &cfg->fl.frozen_layer_count_behavior);
    }
  }
  }

static void load_attack_surface(toml_table_t *t, EdrConfig *cfg) {
  free(cfg->attack_surface.high_risk_immediate_ports);
  cfg->attack_surface.high_risk_immediate_ports = NULL;
  cfg->attack_surface.high_risk_immediate_ports_count = 0;

  {
    toml_datum_t d = toml_bool_in(t, "enabled");
    if (d.ok) {
      cfg->attack_surface.enabled = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "port_interval_s");
    if (d.ok && d.u.i > 0 && d.u.i <= 0x7fffffffLL) {
      cfg->attack_surface.port_interval_s = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "conn_interval_s");
    if (d.ok && d.u.i > 0 && d.u.i <= 0x7fffffffLL) {
      cfg->attack_surface.conn_interval_s = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "service_interval_s");
    if (d.ok && d.u.i > 0 && d.u.i <= 0x7fffffffLL) {
      cfg->attack_surface.service_interval_s = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "policy_interval_s");
    if (d.ok && d.u.i > 0 && d.u.i <= 0x7fffffffLL) {
      cfg->attack_surface.policy_interval_s = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "full_snapshot_interval_s");
    if (d.ok && d.u.i > 0 && d.u.i <= 0x7fffffffLL) {
      cfg->attack_surface.full_snapshot_interval_s = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "outbound_top_n");
    if (d.ok && d.u.i > 0 && d.u.i <= 0x7fffffffLL) {
      cfg->attack_surface.outbound_top_n = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "egress_top_n");
    if (d.ok && d.u.i > 0 && d.u.i <= 0x7fffffffLL) {
      cfg->attack_surface.egress_top_n = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "outbound_exclude_loopback");
    if (d.ok) {
      cfg->attack_surface.outbound_exclude_loopback = d.u.b ? true : false;
    }
  }
  take_string(toml_string_in(t, "geoip_db_path"), cfg->attack_surface.geoip_db_path,
              sizeof(cfg->attack_surface.geoip_db_path));
  {
    toml_datum_t d = toml_int_in(t, "firewall_rule_detail_max");
    if (d.ok && d.u.i > 0 && d.u.i <= 0x7fffffffLL) {
      cfg->attack_surface.firewall_rule_detail_max = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "etw_refresh_triggers_snapshot");
    if (d.ok) {
      cfg->attack_surface.etw_refresh_triggers_snapshot = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "etw_refresh_debounce_s");
    if (d.ok && d.u.i > 0 && d.u.i <= 0x7fffffffLL) {
      cfg->attack_surface.etw_refresh_debounce_s = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "win_listen_cache_ttl_ms");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->attack_surface.win_listen_cache_ttl_ms = (uint32_t)d.u.i;
    }
  }

  {
    toml_array_t *ap = toml_array_in(t, "high_risk_immediate_ports");
    if (ap) {
      int n = toml_array_nelem(ap);
      if (n > 0) {
        uint16_t tmp[EDR_ATTACK_SURFACE_PORTS_MAX];
        int c = 0;
        for (int i = 0; i < n && c < EDR_ATTACK_SURFACE_PORTS_MAX; i++) {
          toml_datum_t p = toml_int_at(ap, i);
          if (!p.ok) {
            fprintf(stderr,
                    "[config] [attack_surface] high_risk_immediate_ports[%d]: expected integer, skipped\n",
                    i);
            continue;
          }
          if (p.u.i < 1 || p.u.i > 65535) {
            fprintf(stderr,
                    "[config] [attack_surface] high_risk_immediate_ports[%d]: out of uint16 range, "
                    "skipped\n",
                    i);
            continue;
          }
          tmp[c++] = (uint16_t)p.u.i;
        }
        if (c > 0) {
          uint16_t *buf = (uint16_t *)malloc((size_t)c * sizeof(uint16_t));
          if (!buf) {
            fprintf(stderr, "[config] [attack_surface]: malloc high_risk_immediate_ports failed\n");
          } else {
            memcpy(buf, tmp, (size_t)c * sizeof(uint16_t));
            cfg->attack_surface.high_risk_immediate_ports = buf;
            cfg->attack_surface.high_risk_immediate_ports_count = (size_t)c;
          }
        }
      }
    }
  }
}

static void load_self_protect(toml_table_t *t, EdrConfig *cfg) {
  {
    toml_datum_t d = toml_bool_in(t, "anti_debug");
    if (d.ok) {
      cfg->self_protect.anti_debug = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "job_object_windows");
    if (d.ok) {
      cfg->self_protect.job_object_windows = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "watchdog_log_interval_s");
    if (d.ok && d.u.i >= 0 && d.u.i <= 86400) {
      cfg->self_protect.watchdog_log_interval_s = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "event_bus_pressure_warn_pct");
    if (d.ok && d.u.i >= 0 && d.u.i <= 100) {
      cfg->self_protect.event_bus_pressure_warn_pct = (uint32_t)d.u.i;
    }
  }
}

EdrError edr_config_load(const char *path, EdrConfig *cfg) {
  if (!cfg) {
    return EDR_ERR_INVALID_ARG;
  }
  edr_config_free_heap(cfg);
  edr_config_apply_defaults(cfg);
  if (!path || !path[0]) {
#ifdef _WIN32
    edr_win_listen_apply_config(cfg);
#endif
    fprintf(stderr,
            "[config] no TOML file (--config not set); using built-in defaults (server.address=%s). "
            "Install: use --config with agent.toml next to edr_agent.exe.\n",
            cfg->server.address);
    edr_config_log_semantic_warnings(cfg);
    return EDR_OK;
  }

  FILE *fp = fopen(path, "r");
  if (!fp) {
    return EDR_ERR_CONFIG_PARSE;
  }

  char errbuf[512];
  memset(errbuf, 0, sizeof(errbuf));
  toml_table_t *root = toml_parse_file(fp, errbuf, (int)sizeof(errbuf));
  fclose(fp);

  if (!root) {
    if (errbuf[0]) {
      fprintf(stderr, "TOML parse error: %s\n", errbuf);
    }
    return EDR_ERR_CONFIG_PARSE;
  }

  {
    toml_table_t *t = toml_table_in(root, "server");
    if (t) {
      load_server(t, cfg);
    }
  }
  {
    toml_table_t *t = toml_table_in(root, "agent");
    if (t) {
      load_agent(t, cfg);
    }
  }
  {
    toml_table_t *t = toml_table_in(root, "collection");
    if (t) {
      load_collection(t, cfg);
    }
  }
  int has_user_preprocess_rules = 0;
  {
    toml_table_t *t = toml_table_in(root, "preprocessing");
    if (t) {
      if (toml_array_in(t, "rules")) {
        has_user_preprocess_rules = 1;
      }
      load_preprocessing(t, cfg);
    }
  }
  {
    toml_table_t *t = toml_table_in(root, "ave");
    if (t) {
      load_ave(t, cfg);
    }
  }
  {
    toml_table_t *t = toml_table_in(root, "upload");
    if (t) {
      load_upload(t, cfg);
    }
  }
  {
    toml_table_t *t = toml_table_in(root, "offline");
    if (t) {
      load_offline(t, cfg);
    }
  }
  {
    toml_table_t *t = toml_table_in(root, "resource_limit");
    if (t) {
      load_resource_limit(t, cfg);
    }
  }
  {
    toml_table_t *t = toml_table_in(root, "logging");
    if (t) {
      load_logging(t, cfg);
    }
  }
  {
    toml_table_t *t = toml_table_in(root, "shellcode_detector");
    if (t) {
      load_shellcode_detector(t, cfg);
    }
  }
  {
    toml_table_t *t = toml_table_in(root, "command");
    if (t) {
      load_command(t, cfg);
    }
  }
  {
    toml_table_t *t = toml_table_in(root, "platform");
    if (t) {
      load_platform(t, cfg);
    }
  }
  {
    toml_table_t *t = toml_table_in(root, "attack_surface");
    if (t) {
      load_attack_surface(t, cfg);
    }
  }
  {
    toml_table_t *t = toml_table_in(root, "self_protect");
    if (t) {
      load_self_protect(t, cfg);
    }
  }
  {
    toml_table_t *t = toml_table_in(root, "webshell_detector");
    if (t) {
      load_webshell_detector(t, cfg);
    }
  }
  {
    toml_table_t *t = toml_table_in(root, "detection");
    if (t) {
      load_detection(t, cfg);
    }
  }
  {
    toml_table_t *t = toml_table_in(root, "pmfe");
    if (t) {
      load_pmfe(t, cfg);
    }
  }
  {
    toml_table_t *t = toml_table_in(root, "fl");
    if (t) {
      load_fl(t, cfg);
    }
  }
  {
    toml_table_t *t = toml_table_in(root, "remote");
    if (t) {
      load_remote(t, cfg);
    }
  }

  toml_free(root);
  try_auto_load_preprocess_rules_bundle(path, has_user_preprocess_rules, cfg);
#ifdef _WIN32
  edr_config_win_fixup_model_dir_from_unix_example(cfg);
#endif
  edr_config_clamp(cfg);
  edr_config_log_semantic_warnings(cfg);
#ifdef _WIN32
  edr_win_listen_apply_config(cfg);
#endif
  return EDR_OK;
}

EdrError edr_config_reload_if_modified(const char *path, EdrConfig *cfg, time_t *mtime_cache,
                                       int *out_reloaded) {
  if (!cfg || !mtime_cache) {
    return EDR_ERR_INVALID_ARG;
  }
  if (out_reloaded) {
    *out_reloaded = 0;
  }
  if (!path || !path[0]) {
    return EDR_OK;
  }
  struct stat st;
  if (stat(path, &st) != 0) {
    return EDR_OK;
  }
  if (*mtime_cache != (time_t)0 && st.st_mtime == *mtime_cache) {
    return EDR_OK;
  }
  EdrError e = edr_config_load(path, cfg);
  if (e == EDR_OK) {
    *mtime_cache = st.st_mtime;
    if (out_reloaded) {
      *out_reloaded = 1;
    }
  }
  return e;
}

void edr_config_fingerprint(const char *path, char *out_hex, size_t cap) {
  if (!out_hex || cap < 17u) {
    return;
  }
  out_hex[0] = 0;
  if (!path || !path[0]) {
    return;
  }
  FILE *fp = fopen(path, "rb");
  if (!fp) {
    return;
  }
  uint64_t h = 14695981039346656037ULL;
  unsigned char buf[4096];
  size_t n;
  size_t total = 0;
  while (total < 65536u && (n = fread(buf, 1, sizeof(buf), fp)) > 0u) {
    for (size_t i = 0; i < n; i++) {
      h ^= (uint64_t)buf[i];
      h *= 1099511628211ULL;
    }
    total += n;
  }
  fclose(fp);
  snprintf(out_hex, cap, "%016llx", (unsigned long long)h);
}
