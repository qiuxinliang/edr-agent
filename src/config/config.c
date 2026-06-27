#include "edr/config.h"

#ifdef _WIN32
#include "edr/listen_table_win.h"
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
#define EDR_PREPROCESS_RULES_VERSION_DEFAULT "edr-dynamic-rules-v1-r252-086c1be1"

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

static void take_string_array_csv(toml_array_t *arr, char *dst, size_t cap) {
  if (!arr || !dst || cap == 0u) {
    return;
  }
  dst[0] = '\0';
  int n = toml_array_nelem(arr);
  size_t used = 0u;
  for (int i = 0; i < n; i++) {
    toml_datum_t d = toml_string_at(arr, i);
    if (!d.ok || !d.u.s) {
      continue;
    }
    const char *s = d.u.s;
    while (*s && isspace((unsigned char)*s)) {
      s++;
    }
    size_t len = strlen(s);
    while (len > 0u && isspace((unsigned char)s[len - 1u])) {
      len--;
    }
    if (len > 0u) {
      if (used > 0u && used + 1u < cap) {
        dst[used++] = ',';
        dst[used] = '\0';
      }
      size_t room = cap - used - 1u;
      size_t copy = len < room ? len : room;
      if (copy > 0u) {
        memcpy(dst + used, s, copy);
        used += copy;
        dst[used] = '\0';
      }
    }
    free(d.u.s);
    if (used + 1u >= cap) {
      break;
    }
  }
}

static void load_server(toml_table_t *t, EdrConfig *cfg) {
  take_string(toml_string_in(t, "address"), cfg->server.address, sizeof(cfg->server.address));
  {
    toml_datum_t d = toml_bool_in(t, "grpc_enabled");
    if (d.ok) {
      cfg->server.grpc_enabled = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "grpc_insecure");
    if (d.ok) {
      cfg->server.grpc_insecure = d.u.b ? true : false;
    }
  }
  take_string(toml_string_in(t, "ca_cert"), cfg->server.ca_cert, sizeof(cfg->server.ca_cert));
  take_string(toml_string_in(t, "client_cert"), cfg->server.client_cert,
              sizeof(cfg->server.client_cert));
  take_string(toml_string_in(t, "client_key"), cfg->server.client_key, sizeof(cfg->server.client_key));
  take_string(toml_string_in(t, "client_key_provider"), cfg->server.client_key_provider,
              sizeof(cfg->server.client_key_provider));
  take_string(toml_string_in(t, "client_cert_store"), cfg->server.client_cert_store,
              sizeof(cfg->server.client_cert_store));
  take_string(toml_string_in(t, "client_cert_thumbprint"), cfg->server.client_cert_thumbprint,
              sizeof(cfg->server.client_cert_thumbprint));
  take_string(toml_string_in(t, "pkcs11_module"), cfg->server.pkcs11_module,
              sizeof(cfg->server.pkcs11_module));
  take_string(toml_string_in(t, "pkcs11_key_uri"), cfg->server.pkcs11_key_uri,
              sizeof(cfg->server.pkcs11_key_uri));
  take_string(toml_string_in(t, "tpm_key_uri"), cfg->server.tpm_key_uri,
              sizeof(cfg->server.tpm_key_uri));
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
    toml_datum_t d = toml_bool_in(t, "etw_amsi_provider");
    if (d.ok) {
      cfg->collection.etw_amsi_provider = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "etw_schannel_provider");
    if (d.ok) {
      cfg->collection.etw_schannel_provider = d.u.b ? true : false;
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
    toml_datum_t d = toml_bool_in(t, "ebpf_enabled");
    if (d.ok) {
      cfg->collection.ebpf_enabled = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "auditd_enabled");
    if (d.ok) {
      cfg->collection.auditd_enabled = d.u.b ? true : false;
    }
  }
  take_string(toml_string_in(t, "auditd_log_path"), cfg->collection.auditd_log_path,
              sizeof(cfg->collection.auditd_log_path));
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
    toml_datum_t d = toml_bool_in(t, "adaptive_enabled");
    if (d.ok) {
      cfg->collection.adaptive_enabled = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "adaptive_boost_seconds");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->collection.adaptive_boost_seconds = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "adaptive_min_severity");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->collection.adaptive_min_severity = (uint32_t)d.u.i;
    }
  }
}

static void load_event_filter(toml_table_t *t, EdrConfig *cfg) {
  {
    toml_datum_t d = toml_bool_in(t, "enabled");
    if (d.ok) {
      cfg->event_filter.enabled = d.u.b ? true : false;
    }
  }
  take_string(toml_string_in(t, "version"), cfg->event_filter.version,
              sizeof(cfg->event_filter.version));
  {
    toml_datum_t d = toml_bool_in(t, "agent_internal_forensic");
    if (d.ok) {
      cfg->event_filter.agent_internal_forensic = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "low_value_file_process");
    if (d.ok) {
      cfg->event_filter.low_value_file_process = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "low_value_file_suffix");
    if (d.ok) {
      cfg->event_filter.low_value_file_suffix = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "temp_xml");
    if (d.ok) {
      cfg->event_filter.temp_xml = d.u.b ? true : false;
    }
  }
  take_string(toml_string_in(t, "low_value_process_names"),
              cfg->event_filter.low_value_process_names,
              sizeof(cfg->event_filter.low_value_process_names));
  take_string(toml_string_in(t, "low_value_suffixes"),
              cfg->event_filter.low_value_suffixes,
              sizeof(cfg->event_filter.low_value_suffixes));
  take_string(toml_string_in(t, "temp_xml_patterns"),
              cfg->event_filter.temp_xml_patterns,
              sizeof(cfg->event_filter.temp_xml_patterns));
  take_string(toml_string_in(t, "agent_internal_patterns"),
              cfg->event_filter.agent_internal_patterns,
              sizeof(cfg->event_filter.agent_internal_patterns));
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

/* 把 [[detection_policy.suppression]] 数组表序列化为控制符分隔的紧凑串，供检测引擎消费。
 * 规则间 0x1e，字段间 0x1f：target,process,action,reason,contains_all；contains_all token 间 0x1d。 */
static void sup_append(char *out, size_t cap, size_t *len, const char *s) {
  if (!s) {
    return;
  }
  for (; *s && *len + 1u < cap; s++) {
    /* 丢弃控制符，避免破坏分隔结构。 */
    if ((unsigned char)*s >= 0x20u) {
      out[(*len)++] = *s;
    }
  }
  out[*len] = '\0';
}

static void load_detection_policy_suppression(toml_table_t *t, EdrConfig *cfg) {
  cfg->detection_policy.suppression_rules[0] = '\0';
  toml_array_t *arr = toml_array_in(t, "suppression");
  if (!arr) {
    return;
  }
  int n = toml_array_nelem(arr);
  if (n < 0) {
    return;
  }
  char *out = cfg->detection_policy.suppression_rules;
  size_t cap = sizeof(cfg->detection_policy.suppression_rules);
  size_t len = 0u;
  int written = 0;
  for (int i = 0; i < n; i++) {
    toml_table_t *rt = toml_table_at(arr, i);
    if (!rt) {
      continue;
    }
    char target[96] = "";
    char process[128] = "";
    char action[32] = "";
    char reason[96] = "";
    take_string(toml_string_in(rt, "target_rule_id"), target, sizeof(target));
    take_string(toml_string_in(rt, "process_name"), process, sizeof(process));
    take_string(toml_string_in(rt, "action"), action, sizeof(action));
    take_string(toml_string_in(rt, "reason"), reason, sizeof(reason));
    if (!action[0]) {
      snprintf(action, sizeof(action), "%s", "downgrade");
    }
    if (written && len + 1u < cap) {
      out[len++] = '\x1e';
    }
    sup_append(out, cap, &len, target);
    if (len + 1u < cap) out[len++] = '\x1f';
    sup_append(out, cap, &len, process);
    if (len + 1u < cap) out[len++] = '\x1f';
    sup_append(out, cap, &len, action);
    if (len + 1u < cap) out[len++] = '\x1f';
    sup_append(out, cap, &len, reason);
    if (len + 1u < cap) out[len++] = '\x1f';
    toml_array_t *ca = toml_array_in(rt, "contains_all");
    if (ca) {
      int cn = toml_array_nelem(ca);
      int first = 1;
      for (int j = 0; j < cn; j++) {
        toml_datum_t d = toml_string_at(ca, j);
        if (!d.ok || !d.u.s) {
          continue;
        }
        if (!first && len + 1u < cap) {
          out[len++] = '\x1d';
        }
        sup_append(out, cap, &len, d.u.s);
        first = 0;
        free(d.u.s);
      }
    }
    out[len] = '\0';
    written = 1;
  }
}

static void load_detection_policy(toml_table_t *t, EdrConfig *cfg) {
  take_string(toml_string_in(t, "source"), cfg->detection_policy.source, sizeof(cfg->detection_policy.source));
  take_string(toml_string_in(t, "audit_id"), cfg->detection_policy.audit_id, sizeof(cfg->detection_policy.audit_id));
  take_string(toml_string_in(t, "policy_version"), cfg->detection_policy.policy_version,
              sizeof(cfg->detection_policy.policy_version));
  take_string(toml_string_in(t, "rollback_version"), cfg->detection_policy.rollback_version,
              sizeof(cfg->detection_policy.rollback_version));
  take_string(toml_string_in(t, "fp_policy_version"), cfg->detection_policy.fp_policy_version,
              sizeof(cfg->detection_policy.fp_policy_version));
  take_string(toml_string_in(t, "fp_rollback_version"), cfg->detection_policy.fp_rollback_version,
              sizeof(cfg->detection_policy.fp_rollback_version));
  take_string(toml_string_in(t, "rmm_policy_version"), cfg->detection_policy.rmm_policy_version,
              sizeof(cfg->detection_policy.rmm_policy_version));
  take_string(toml_string_in(t, "rmm_rollback_version"), cfg->detection_policy.rmm_rollback_version,
              sizeof(cfg->detection_policy.rmm_rollback_version));
  take_string(toml_string_in(t, "allow_paths"), cfg->detection_policy.allow_paths,
              sizeof(cfg->detection_policy.allow_paths));
  take_string(toml_string_in(t, "script_dirs"), cfg->detection_policy.script_dirs,
              sizeof(cfg->detection_policy.script_dirs));
  take_string(toml_string_in(t, "management_tools"), cfg->detection_policy.management_tools,
              sizeof(cfg->detection_policy.management_tools));
  take_string(toml_string_in(t, "fp_feedback"), cfg->detection_policy.fp_feedback,
              sizeof(cfg->detection_policy.fp_feedback));
  load_detection_policy_suppression(t, cfg);
}

static void config_setenv_if_value(const char *name, const char *value) {
  if (!name || !name[0] || !value || !value[0]) {
    return;
  }
#ifdef _WIN32
  (void)_putenv_s(name, value);
#else
  (void)setenv(name, value, 1);
#endif
}

static void apply_detection_policy_env(const EdrConfig *cfg) {
  if (!cfg) {
    return;
  }
  config_setenv_if_value("EDR_DETECTION_POLICY_SOURCE", cfg->detection_policy.source);
  config_setenv_if_value("EDR_DETECTION_POLICY_AUDIT_ID", cfg->detection_policy.audit_id);
  config_setenv_if_value("EDR_DETECTION_POLICY_VERSION", cfg->detection_policy.policy_version);
  config_setenv_if_value("EDR_DETECTION_ROLLBACK_VERSION", cfg->detection_policy.rollback_version);
  config_setenv_if_value("EDR_DETECTION_FP_POLICY_VERSION", cfg->detection_policy.fp_policy_version);
  config_setenv_if_value("EDR_DETECTION_FP_ROLLBACK_VERSION", cfg->detection_policy.fp_rollback_version);
  config_setenv_if_value("EDR_DETECTION_RMM_POLICY_VERSION", cfg->detection_policy.rmm_policy_version);
  config_setenv_if_value("EDR_DETECTION_RMM_ROLLBACK_VERSION", cfg->detection_policy.rmm_rollback_version);
  config_setenv_if_value("EDR_DETECTION_ALLOW_PATHS", cfg->detection_policy.allow_paths);
  config_setenv_if_value("EDR_DETECTION_SCRIPT_DIRS", cfg->detection_policy.script_dirs);
  config_setenv_if_value("EDR_DETECTION_MGMT_TOOLS", cfg->detection_policy.management_tools);
  config_setenv_if_value("EDR_DETECTION_FP_FEEDBACK", cfg->detection_policy.fp_feedback);
  config_setenv_if_value("EDR_DETECTION_SUPPRESSION_RULES", cfg->detection_policy.suppression_rules);
}

static void load_ave(toml_table_t *t, EdrConfig *cfg) {
  {
    toml_datum_t d = toml_bool_in(t, "enabled");
    if (d.ok) {
      cfg->ave.enabled = d.u.b ? true : false;
    }
  }
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
  {
    toml_datum_t d = toml_bool_in(t, "static_model_enabled");
    if (d.ok) {
      cfg->ave.static_model_enabled = d.u.b ? true : false;
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
  take_string(toml_string_in(t, "evidence_cache_path"), cfg->offline.evidence_cache_path,
              sizeof(cfg->offline.evidence_cache_path));
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
  {
    toml_datum_t d = toml_int_in(t, "evidence_cache_max_size_mb");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->offline.evidence_cache_max_size_mb = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "evidence_cache_retention_hours");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->offline.evidence_cache_retention_hours = (uint32_t)d.u.i;
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
  {
    toml_datum_t d = toml_int_in(t, "ave_infer_per_min");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->resource_limit.ave_infer_per_min = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "behavior_infer_per_min");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->resource_limit.behavior_infer_per_min = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "pmfe_scans_per_min");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->resource_limit.pmfe_scans_per_min = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "webshell_scan_mb_per_min");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->resource_limit.webshell_scan_mb_per_min = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "shellcode_packets_per_sec");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->resource_limit.shellcode_packets_per_sec = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "low_priority_keep_percent_under_pressure");
    if (d.ok && d.u.i >= 0 && d.u.i <= 100) {
      cfg->resource_limit.low_priority_keep_percent_under_pressure = (uint32_t)d.u.i;
    }
  }
}

static void load_health_monitor(toml_table_t *t, EdrConfig *cfg) {
  {
    toml_datum_t d = toml_bool_in(t, "enabled");
    if (d.ok) {
      cfg->health_monitor.enabled = d.u.b ? true : false;
    }
  }
  take_string(toml_string_in(t, "profile"), cfg->health_monitor.profile,
              sizeof(cfg->health_monitor.profile));
  {
    toml_datum_t d = toml_int_in(t, "interval_s");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->health_monitor.interval_s = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "expires_at_unix_ms");
    if (d.ok && d.u.i >= 0) {
      cfg->health_monitor.expires_at_unix_ms = (uint64_t)d.u.i;
    }
  }
  take_string(toml_string_in(t, "request_id"), cfg->health_monitor.request_id,
              sizeof(cfg->health_monitor.request_id));
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
    toml_datum_t d = toml_int_in(t, "flow_scan_first_bytes");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->shellcode_detector.flow_scan_first_bytes = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "scan_tls_appdata");
    if (d.ok) {
      cfg->shellcode_detector.scan_tls_appdata = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "exclude_self_traffic");
    if (d.ok) {
      cfg->shellcode_detector.exclude_self_traffic = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "windivert_queue_length");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->shellcode_detector.windivert_queue_length = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "windivert_queue_size_kb");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->shellcode_detector.windivert_queue_size_kb = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "windivert_queue_time_ms");
    if (d.ok && d.u.i >= 0 && d.u.i <= 0x7fffffffLL) {
      cfg->shellcode_detector.windivert_queue_time_ms = (uint32_t)d.u.i;
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
    toml_datum_t d = toml_bool_in(t, "monitor_tls");
    if (d.ok) {
      cfg->shellcode_detector.monitor_tls = d.u.b ? true : false;
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
      fprintf(stderr, "[config] shellcode_detector.windivert_tcp_ports has no valid port; using built-in WinDivert port table\n");
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

static void edr_config_clamp(EdrConfig *cfg) {
  if (cfg->collection.max_event_queue_size < 256u) {
    cfg->collection.max_event_queue_size = 256u;
  }
  if (cfg->collection.max_event_queue_size > 65536u) {
    cfg->collection.max_event_queue_size = 65536u;
  }
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
  if (cfg->platform.telemetry_sampling_pct < 1u) {
    cfg->platform.telemetry_sampling_pct = 1u;
  }
  if (cfg->platform.telemetry_sampling_pct > 100u) {
    cfg->platform.telemetry_sampling_pct = 100u;
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
  /* P2 #8：WinDivert 队列参数 clamp（0 保留为“用内置默认”，不 clamp）。 */
  if (cfg->shellcode_detector.windivert_queue_length != 0u) {
    if (cfg->shellcode_detector.windivert_queue_length < 32u) {
      cfg->shellcode_detector.windivert_queue_length = 32u;
    } else if (cfg->shellcode_detector.windivert_queue_length > 16384u) {
      cfg->shellcode_detector.windivert_queue_length = 16384u;
    }
  }
  if (cfg->shellcode_detector.windivert_queue_size_kb != 0u) {
    if (cfg->shellcode_detector.windivert_queue_size_kb < 64u) {
      cfg->shellcode_detector.windivert_queue_size_kb = 64u;
    } else if (cfg->shellcode_detector.windivert_queue_size_kb > 32768u) {
      cfg->shellcode_detector.windivert_queue_size_kb = 32768u;
    }
  }
  if (cfg->shellcode_detector.windivert_queue_time_ms != 0u) {
    if (cfg->shellcode_detector.windivert_queue_time_ms < 100u) {
      cfg->shellcode_detector.windivert_queue_time_ms = 100u;
    } else if (cfg->shellcode_detector.windivert_queue_time_ms > 16000u) {
      cfg->shellcode_detector.windivert_queue_time_ms = 16000u;
    }
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
  if (cfg->health_monitor.profile[0] == '\0') {
    snprintf(cfg->health_monitor.profile, sizeof(cfg->health_monitor.profile), "%s", "basic");
  } else {
    for (size_t i = 0; i < sizeof(cfg->health_monitor.profile) && cfg->health_monitor.profile[i]; i++) {
      cfg->health_monitor.profile[i] = (char)tolower((unsigned char)cfg->health_monitor.profile[i]);
    }
    if (strcmp(cfg->health_monitor.profile, "basic") != 0 &&
        strcmp(cfg->health_monitor.profile, "diagnostic") != 0) {
      snprintf(cfg->health_monitor.profile, sizeof(cfg->health_monitor.profile), "%s", "basic");
    }
  }
  if (cfg->health_monitor.interval_s < 30u) {
    cfg->health_monitor.interval_s = 30u;
  }
  if (cfg->health_monitor.interval_s > 3600u) {
    cfg->health_monitor.interval_s = 3600u;
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
  cfg->server.address[0] = '\0';
  cfg->server.grpc_enabled = false;
  cfg->server.grpc_insecure = false;
  snprintf(cfg->server.client_key_provider, sizeof(cfg->server.client_key_provider), "%s", "pem");
  cfg->server.connect_timeout_s = 10;
  cfg->server.keepalive_interval_s = 30;

  snprintf(cfg->agent.endpoint_id, sizeof(cfg->agent.endpoint_id), "%s", "auto");
  snprintf(cfg->agent.tenant_id, sizeof(cfg->agent.tenant_id), "%s", "tenant_default");

  cfg->collection.etw_enabled = true;
  cfg->collection.etw_dns_client_provider = true;
  cfg->collection.etw_powershell_provider = true;
  cfg->collection.etw_amsi_provider = true;
  cfg->collection.etw_schannel_provider = true;
  cfg->collection.etw_security_audit_provider = true;
  cfg->collection.etw_wmi_provider = true;
  cfg->collection.etw_tcpip_provider = true;
  cfg->collection.etw_firewall_provider = true;
  cfg->collection.ebpf_enabled = true;
  cfg->collection.auditd_enabled = false;
  snprintf(cfg->collection.auditd_log_path, sizeof(cfg->collection.auditd_log_path), "%s", "/var/log/audit/audit.log");
  cfg->collection.poll_interval_s = 1;
  cfg->collection.max_event_queue_size = 1024u;
  cfg->collection.adaptive_enabled = true;
  cfg->collection.adaptive_boost_seconds = 180u;
  cfg->collection.adaptive_min_severity = 3u;

  cfg->event_filter.enabled = true;
  snprintf(cfg->event_filter.version, sizeof(cfg->event_filter.version), "%s",
           "agent-event-filter-v1");
  cfg->event_filter.agent_internal_forensic = true;
  cfg->event_filter.low_value_file_process = true;
  cfg->event_filter.low_value_file_suffix = true;
  cfg->event_filter.temp_xml = true;
  snprintf(cfg->event_filter.low_value_process_names,
           sizeof(cfg->event_filter.low_value_process_names), "%s",
           "svchost.exe, runtimebroker.exe, backgroundtaskhost.exe, "
           "microsoftedgeupdate.exe, mousocoreworker.exe");
  snprintf(cfg->event_filter.low_value_suffixes, sizeof(cfg->event_filter.low_value_suffixes),
           "%s", ":wofcompresseddata, .js.map, .tmp, .etl, .blf, .regtrans-ms, .cache");
  snprintf(cfg->event_filter.temp_xml_patterns, sizeof(cfg->event_filter.temp_xml_patterns),
           "%s", "\\appdata\\local\\temp\\xml_file");
  snprintf(cfg->event_filter.agent_internal_patterns,
           sizeof(cfg->event_filter.agent_internal_patterns), "%s",
           "\\edr_forensic\\, /edr_forensic/, cmd_forensic_, auto-forensic_, "
           "forensic_bundle, source=agent_internal");

  cfg->preprocessing.dedup_window_s = 30u;
  cfg->preprocessing.high_freq_threshold = 100u;
  cfg->preprocessing.sampling_rate_whitelist = 0.1;
  snprintf(cfg->preprocessing.rules_version, sizeof(cfg->preprocessing.rules_version), "%s",
           EDR_PREPROCESS_RULES_VERSION_DEFAULT);
  apply_builtin_preprocess_rules(cfg);
  snprintf(cfg->detection_policy.source, sizeof(cfg->detection_policy.source), "%s", "local_default");
  snprintf(cfg->detection_policy.policy_version, sizeof(cfg->detection_policy.policy_version), "%s", "local-default");

#ifdef _WIN32
  /* 与 agent.toml.example / WINDOWS_DEPLOY 约定一致；无配置时仍建议显式写 [ave].model_dir */
  snprintf(cfg->ave.model_dir, sizeof(cfg->ave.model_dir), "%s",
           "C:\\Program Files\\FDSecurity\\models");
#else
  snprintf(cfg->ave.model_dir, sizeof(cfg->ave.model_dir), "%s", "/opt/edr/models");
#endif
  cfg->ave.enabled = true;
  cfg->ave.scan_threads = 2;
  cfg->ave.max_file_size_mb = 256;
  snprintf(cfg->ave.sensitivity, sizeof(cfg->ave.sensitivity), "%s", "MEDIUM");
#ifdef _WIN32
  cfg->ave.cert_whitelist_enabled = true;
#else
  cfg->ave.cert_whitelist_enabled = false;
#endif
  cfg->ave.cert_whitelist_db_path[0] = '\0';
  cfg->ave.file_whitelist_db_path[0] = '\0';
  cfg->ave.ioc_db_path[0] = '\0';
  cfg->ave.ioc_precheck_enabled = true;
  cfg->ave.static_model_enabled = true;
  cfg->ave.behavior_policy_db_path[0] = '\0';
  cfg->ave.behavior_monitor_enabled = false;
  cfg->ave.cert_revocation_check = false;
  cfg->ave.l4_realtime_behavior_link = false;
  cfg->ave.l4_realtime_anomaly_threshold = 0.65f;
  cfg->ave.static_infer_cache_max_entries = 0u;
  cfg->ave.static_infer_cache_ttl_s = 0u;

  cfg->upload.batch_max_events = 500u;
  cfg->upload.batch_max_size_mb = 4u;
  cfg->upload.batch_timeout_s = 5;
  cfg->upload.max_upload_mbps = 1u;

#ifdef _WIN32
  snprintf(cfg->offline.queue_db_path, sizeof(cfg->offline.queue_db_path), "%s",
           "C:\\Program Files\\FDSecurity\\queue\\edr_queue.db");
#else
  snprintf(cfg->offline.queue_db_path, sizeof(cfg->offline.queue_db_path), "%s",
           "edr_queue.db");
#endif
  cfg->offline.max_queue_size_mb = 512u;
  cfg->offline.retention_hours = 72u;
#ifdef _WIN32
  snprintf(cfg->offline.evidence_cache_path, sizeof(cfg->offline.evidence_cache_path), "%s",
           "C:\\Program Files\\FDSecurity\\evidence\\local_evidence_cache.db");
#else
  snprintf(cfg->offline.evidence_cache_path, sizeof(cfg->offline.evidence_cache_path), "%s",
           "local_evidence_cache.db");
#endif
  cfg->offline.evidence_cache_max_size_mb = 128u;
  cfg->offline.evidence_cache_retention_hours = 24u;

  cfg->resource_limit.cpu_limit_percent = 1u;
  cfg->resource_limit.memory_limit_mb = 100u;
  cfg->resource_limit.emergency_cpu_limit = 5u;
  cfg->resource_limit.ave_infer_per_min = 120u;
  cfg->resource_limit.behavior_infer_per_min = 30u;
  cfg->resource_limit.pmfe_scans_per_min = 3u;
  cfg->resource_limit.webshell_scan_mb_per_min = 64u;
  cfg->resource_limit.shellcode_packets_per_sec = 2000u;
  cfg->resource_limit.low_priority_keep_percent_under_pressure = 5u;

  cfg->health_monitor.enabled = false;
  snprintf(cfg->health_monitor.profile, sizeof(cfg->health_monitor.profile), "%s", "basic");
  cfg->health_monitor.interval_s = 60u;
  cfg->health_monitor.expires_at_unix_ms = 0u;
  cfg->health_monitor.request_id[0] = '\0';

  snprintf(cfg->logging.level, sizeof(cfg->logging.level), "%s", "info");
#ifdef _WIN32
  snprintf(cfg->logging.log_dir, sizeof(cfg->logging.log_dir), "%s",
           "C:\\Program Files\\FDSecurity\\logs");
#else
  snprintf(cfg->logging.log_dir, sizeof(cfg->logging.log_dir), "%s", "/var/log/edr");
#endif
  cfg->logging.max_log_size_mb = 100u;
  cfg->logging.max_log_files = 10u;

  cfg->shellcode_detector.enabled = false;
  cfg->shellcode_detector.windivert_priority = -1000;
  cfg->shellcode_detector.max_payload_inspect = 16384u;
  cfg->shellcode_detector.alert_threshold = 0.70;
  cfg->shellcode_detector.auto_isolate_threshold = 0.95;
  cfg->shellcode_detector.auto_isolate_execute = false;
  cfg->shellcode_detector.heuristic_score_scale = 1.0;
  cfg->shellcode_detector.flow_scan_first_bytes = 65536u;
  cfg->shellcode_detector.scan_tls_appdata = false;
  cfg->shellcode_detector.exclude_self_traffic = true;
  cfg->shellcode_detector.yara_rules_reload_interval_s = 300u;
  cfg->shellcode_detector.monitor_smb = true;
  cfg->shellcode_detector.monitor_rdp = true;
  cfg->shellcode_detector.monitor_winrm = true;
  cfg->shellcode_detector.monitor_msrpc = true;
  cfg->shellcode_detector.monitor_ldap = true;
  cfg->shellcode_detector.monitor_tls = true;
  cfg->shellcode_detector.detector_threads = 2u;
  cfg->shellcode_detector.windivert_queue_length = 8192u;
  cfg->shellcode_detector.windivert_queue_size_kb = 8192u;
  cfg->shellcode_detector.windivert_queue_time_ms = 2000u;
  /* 默认指向 bundled 规则目录（开发态相对路径；安装器写入部署绝对路径）。
   * YARA 缺失或目录无规则时，shellcode_known 自动回退内置匹配器。 */
  snprintf(cfg->shellcode_detector.yara_rules_dir, sizeof(cfg->shellcode_detector.yara_rules_dir), "%s",
           "src/shellcode_detector/rules");
  cfg->shellcode_detector.forensic_dir[0] = '\0';
  cfg->shellcode_detector.forensic_save_pcap = false;
  cfg->shellcode_detector.evidence_preview_bytes = 0u;
  cfg->shellcode_detector.forensic_ring_slots = 0u;
  cfg->shellcode_detector.forensic_ring_max_packet_bytes = 2048u;
  cfg->shellcode_detector.windivert_tcp_ports[0] = '\0';
  cfg->shellcode_detector.windivert_ports_is_custom = false;
  cfg->shellcode_detector.windivert_tcp_ports_parsed_count = 0;

  cfg->net_fanout.enabled = false;
  cfg->net_fanout.window_s = 120u;
  cfg->net_fanout.distinct_ip_threshold = 50u;
  cfg->net_fanout.ports[0] = '\0';
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
  cfg->command.allow_rtq_readonly = true;
  cfg->command.rtr_shell_allowlist[0] = '\0';
  cfg->command.rtr_shell_max_timeout_sec = 60u;
  cfg->command.signing_public_key_path[0] = '\0';
  cfg->command.signing_public_key_pem[0] = '\0';
  cfg->forensic_auto.enabled = false;
  cfg->forensic_auto.cooldown_s = 30u;
  cfg->forensic_auto.per_pid_cooldown_s = 300u;
  cfg->forensic_auto.max_per_hour = 20u;
  cfg->forensic_auto.trigger_on_p0 = true;
  cfg->forensic_auto.collect_process_tree = true;

  snprintf(cfg->platform.rest_user_id, sizeof(cfg->platform.rest_user_id), "%s", "edr-agent");
  cfg->config_signing.signature_required = false;
  cfg->config_signing.signing_key_id[0] = '\0';
  cfg->config_signing.public_key_pem[0] = '\0';
  cfg->platform.http2_enabled = false;
  cfg->platform.http2_require = false;
  cfg->platform.control_stream_enabled = true;
  cfg->platform.long_poll_fallback = true;
  cfg->platform.report_events_v2_enabled = true;
  snprintf(cfg->platform.data_plane_encoding, sizeof(cfg->platform.data_plane_encoding), "%s", "protobuf");
  snprintf(cfg->platform.data_plane_compression, sizeof(cfg->platform.data_plane_compression), "%s", "identity");
  snprintf(cfg->platform.control_dict_version, sizeof(cfg->platform.control_dict_version), "%s", "edr-zstd-dict-v1");
  snprintf(cfg->platform.control_schema_version, sizeof(cfg->platform.control_schema_version), "%s", "edr-control-schema-v1");
  snprintf(cfg->platform.control_profile_id, sizeof(cfg->platform.control_profile_id), "%s",
           "default-http1-protobuf");
  snprintf(cfg->platform.qos_dscp, sizeof(cfg->platform.qos_dscp), "%s", "AF21");
  snprintf(cfg->platform.telemetry_threshold, sizeof(cfg->platform.telemetry_threshold), "%s", "medium");
  cfg->platform.telemetry_sampling_pct = 100u;
  cfg->platform.backpressure_enabled = true;
  snprintf(cfg->platform.proxy_mode, sizeof(cfg->platform.proxy_mode), "%s", "auto");

  cfg->attack_surface.enabled = false;
  cfg->attack_surface.port_interval_s = 300u;
  cfg->attack_surface.conn_interval_s = 300u;
  cfg->attack_surface.service_interval_s = 600u;
  cfg->attack_surface.policy_interval_s = 3600u;
  cfg->attack_surface.full_snapshot_interval_s = 1800u;
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
  cfg->self_protect.subsystem_stale_timeout_s = 0u;
  cfg->self_protect.watchdog_process = false;
  cfg->self_protect.watchdog_heartbeat_interval_s = 5u;
  cfg->self_protect.watchdog_stale_timeout_s = 30u;
  cfg->self_protect.watchdog_max_restarts_per_min = 5u;
  cfg->self_protect.watchdog_heartbeat_path[0] = '\0';
}

static void load_command(toml_table_t *t, EdrConfig *cfg) {
  toml_datum_t d = toml_bool_in(t, "allow_dangerous");
  if (d.ok) {
    cfg->command.allow_dangerous = d.u.b ? true : false;
  }
  d = toml_bool_in(t, "allow_rtq_readonly");
  if (d.ok) {
    cfg->command.allow_rtq_readonly = d.u.b ? true : false;
  }
  take_string(toml_string_in(t, "rtr_shell_allowlist"), cfg->command.rtr_shell_allowlist,
              sizeof(cfg->command.rtr_shell_allowlist));
  take_string(toml_string_in(t, "signing_public_key_path"), cfg->command.signing_public_key_path,
              sizeof(cfg->command.signing_public_key_path));
  take_string(toml_string_in(t, "signing_public_key_pem"), cfg->command.signing_public_key_pem,
              sizeof(cfg->command.signing_public_key_pem));
  {
    toml_datum_t mt = toml_int_in(t, "rtr_shell_max_timeout_sec");
    if (mt.ok && mt.u.i >= 1 && mt.u.i <= 300) {
      cfg->command.rtr_shell_max_timeout_sec = (uint32_t)mt.u.i;
    }
  }
  toml_table_t *rt = toml_table_in(t, "rtr_shell");
  if (rt) {
    take_string(toml_string_in(rt, "allowlist"), cfg->command.rtr_shell_allowlist,
                sizeof(cfg->command.rtr_shell_allowlist));
    take_string_array_csv(toml_array_in(rt, "allowlist"), cfg->command.rtr_shell_allowlist,
                          sizeof(cfg->command.rtr_shell_allowlist));
    toml_datum_t mt = toml_int_in(rt, "max_timeout_sec");
    if (mt.ok && mt.u.i >= 1 && mt.u.i <= 300) {
      cfg->command.rtr_shell_max_timeout_sec = (uint32_t)mt.u.i;
    }
  }
}

static void load_forensic_auto(toml_table_t *t, EdrConfig *cfg) {
  {
    toml_datum_t d = toml_bool_in(t, "enabled");
    if (d.ok) {
      cfg->forensic_auto.enabled = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "cooldown_s");
    if (d.ok && d.u.i >= 0 && d.u.i <= 3600) {
      cfg->forensic_auto.cooldown_s = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "per_pid_cooldown_s");
    if (d.ok && d.u.i >= 0 && d.u.i <= 86400) {
      cfg->forensic_auto.per_pid_cooldown_s = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "max_per_hour");
    if (d.ok && d.u.i >= 0 && d.u.i <= 10000) {
      cfg->forensic_auto.max_per_hour = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "trigger_on_p0");
    if (d.ok) {
      cfg->forensic_auto.trigger_on_p0 = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "collect_process_tree");
    if (d.ok) {
      cfg->forensic_auto.collect_process_tree = d.u.b ? true : false;
    }
  }
}

static void load_platform(toml_table_t *t, EdrConfig *cfg) {
  take_string(toml_string_in(t, "rest_base_url"), cfg->platform.rest_base_url,
              sizeof(cfg->platform.rest_base_url));
  take_string(toml_string_in(t, "rest_user_id"), cfg->platform.rest_user_id,
              sizeof(cfg->platform.rest_user_id));
  take_string(toml_string_in(t, "rest_bearer_token"), cfg->platform.rest_bearer_token,
              sizeof(cfg->platform.rest_bearer_token));
  {
    toml_datum_t d = toml_bool_in(t, "http2_enabled");
    if (d.ok) {
      cfg->platform.http2_enabled = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "http2_require");
    if (d.ok) {
      cfg->platform.http2_require = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "control_stream_enabled");
    if (d.ok) {
      cfg->platform.control_stream_enabled = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "long_poll_fallback");
    if (d.ok) {
      cfg->platform.long_poll_fallback = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "report_events_v2_enabled");
    if (d.ok) {
      cfg->platform.report_events_v2_enabled = d.u.b ? true : false;
    }
  }
  take_string(toml_string_in(t, "data_plane_encoding"), cfg->platform.data_plane_encoding,
              sizeof(cfg->platform.data_plane_encoding));
  take_string(toml_string_in(t, "data_plane_compression"), cfg->platform.data_plane_compression,
              sizeof(cfg->platform.data_plane_compression));
  take_string(toml_string_in(t, "control_dict_version"), cfg->platform.control_dict_version,
              sizeof(cfg->platform.control_dict_version));
  take_string(toml_string_in(t, "control_schema_version"), cfg->platform.control_schema_version,
              sizeof(cfg->platform.control_schema_version));
  take_string(toml_string_in(t, "control_profile_id"), cfg->platform.control_profile_id,
              sizeof(cfg->platform.control_profile_id));
  take_string(toml_string_in(t, "qos_dscp"), cfg->platform.qos_dscp,
              sizeof(cfg->platform.qos_dscp));
  take_string(toml_string_in(t, "telemetry_threshold"), cfg->platform.telemetry_threshold,
              sizeof(cfg->platform.telemetry_threshold));
  {
    toml_datum_t d = toml_int_in(t, "telemetry_sampling_pct");
    if (d.ok) {
      cfg->platform.telemetry_sampling_pct = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "backpressure_enabled");
    if (d.ok) {
      cfg->platform.backpressure_enabled = d.u.b ? true : false;
    }
  }
  take_string(toml_string_in(t, "proxy_mode"), cfg->platform.proxy_mode,
              sizeof(cfg->platform.proxy_mode));
  take_string(toml_string_in(t, "proxy_url"), cfg->platform.proxy_url,
              sizeof(cfg->platform.proxy_url));
  take_string(toml_string_in(t, "relay_url"), cfg->platform.relay_url,
              sizeof(cfg->platform.relay_url));
}

static void load_config_signing(toml_table_t *t, EdrConfig *cfg) {
  toml_datum_t d = toml_bool_in(t, "signature_required");
  if (d.ok) {
    cfg->config_signing.signature_required = d.u.b ? true : false;
  }
  take_string(toml_string_in(t, "signing_key_id"), cfg->config_signing.signing_key_id,
              sizeof(cfg->config_signing.signing_key_id));
  take_string(toml_string_in(t, "public_key_pem"), cfg->config_signing.public_key_pem,
              sizeof(cfg->config_signing.public_key_pem));
  if (cfg->config_signing.public_key_pem[0]) {
    char expanded[sizeof(cfg->config_signing.public_key_pem)];
    size_t o = 0u;
    for (size_t i = 0u; cfg->config_signing.public_key_pem[i] && o + 1u < sizeof(expanded); i++) {
      if (cfg->config_signing.public_key_pem[i] == '\\' && cfg->config_signing.public_key_pem[i + 1u] == 'n') {
        expanded[o++] = '\n';
        i++;
      } else {
        expanded[o++] = cfg->config_signing.public_key_pem[i];
      }
    }
    expanded[o] = '\0';
    snprintf(cfg->config_signing.public_key_pem, sizeof(cfg->config_signing.public_key_pem), "%s", expanded);
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
  {
    toml_datum_t d = toml_int_in(t, "subsystem_stale_timeout_s");
    if (d.ok && d.u.i >= 0 && d.u.i <= 86400) {
      cfg->self_protect.subsystem_stale_timeout_s = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_bool_in(t, "watchdog_process");
    if (d.ok) {
      cfg->self_protect.watchdog_process = d.u.b ? true : false;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "watchdog_heartbeat_interval_s");
    if (d.ok && d.u.i >= 1 && d.u.i <= 3600) {
      cfg->self_protect.watchdog_heartbeat_interval_s = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "watchdog_stale_timeout_s");
    if (d.ok && d.u.i >= 2 && d.u.i <= 86400) {
      cfg->self_protect.watchdog_stale_timeout_s = (uint32_t)d.u.i;
    }
  }
  {
    toml_datum_t d = toml_int_in(t, "watchdog_max_restarts_per_min");
    if (d.ok && d.u.i >= 0 && d.u.i <= 1000) {
      cfg->self_protect.watchdog_max_restarts_per_min = (uint32_t)d.u.i;
    }
  }
  take_string(toml_string_in(t, "watchdog_heartbeat_path"), cfg->self_protect.watchdog_heartbeat_path,
              sizeof(cfg->self_protect.watchdog_heartbeat_path));
}

EdrError edr_config_load(const char *path, EdrConfig *cfg) {
  if (!cfg) {
    return EDR_ERR_INVALID_ARG;
  }
  edr_config_free_heap(cfg);
  edr_config_apply_defaults(cfg);
  if (!path || !path[0]) {
    apply_detection_policy_env(cfg);
#ifdef _WIN32
    edr_win_listen_apply_config(cfg);
#endif
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
  {
    toml_table_t *t = toml_table_in(root, "event_filter");
    if (t) {
      load_event_filter(t, cfg);
    }
  }
  {
    toml_table_t *t = toml_table_in(root, "preprocessing");
    if (t) {
      load_preprocessing(t, cfg);
    }
  }
  {
    toml_table_t *t = toml_table_in(root, "detection_policy");
    if (t) {
      load_detection_policy(t, cfg);
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
    toml_table_t *t = toml_table_in(root, "health_monitor");
    if (t) {
      load_health_monitor(t, cfg);
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
    toml_table_t *t = toml_table_in(root, "forensic_auto");
    if (t) {
      load_forensic_auto(t, cfg);
    }
  }
  {
    toml_table_t *t = toml_table_in(root, "platform");
    if (t) {
      load_platform(t, cfg);
    }
  }
  {
    toml_table_t *t = toml_table_in(root, "config_signing");
    if (t) {
      load_config_signing(t, cfg);
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
    toml_table_t *t = toml_table_in(root, "net_fanout");
    if (t) {
      toml_datum_t d = toml_bool_in(t, "enabled");
      if (d.ok) {
        cfg->net_fanout.enabled = d.u.b ? true : false;
      }
      d = toml_int_in(t, "window_s");
      if (d.ok && d.u.i >= 1 && d.u.i <= 3600) {
        cfg->net_fanout.window_s = (uint32_t)d.u.i;
      }
      d = toml_int_in(t, "distinct_ip_threshold");
      if (d.ok && d.u.i >= 1 && d.u.i <= 100000) {
        cfg->net_fanout.distinct_ip_threshold = (uint32_t)d.u.i;
      }
      take_string(toml_string_in(t, "ports"), cfg->net_fanout.ports, sizeof(cfg->net_fanout.ports));
    }
  }
  {
    toml_table_t *t = toml_table_in(root, "fl");
    if (t) {
      load_fl(t, cfg);
    }
  }

  toml_free(root);
  edr_config_clamp(cfg);
  apply_detection_policy_env(cfg);
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
