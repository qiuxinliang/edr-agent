#include "edr/detection_decision.h"
#include "edr/detection_profile.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EDR_RANSOM_CONTROL_VERSION "ransom-control-v2"

static int has_ci(const char *hay, const char *needle) {
  if (!needle || !needle[0]) {
    return 1;
  }
  if (!hay) {
    hay = "";
  }
  for (; *hay; hay++) {
    const char *a = hay;
    const char *b = needle;
    while (*a && *b && tolower((unsigned char)*a) == tolower((unsigned char)*b)) {
      a++;
      b++;
    }
    if (!*b) {
      return 1;
    }
  }
  return 0;
}

static int detail_value(const char *text, const char *key, char *out, size_t cap);
static double detail_number(const char *text, const char *key, double fallback);

static const char *base_name(const char *path) {
  const char *b = path && path[0] ? path : "";
  for (const char *p = b; *p; p++) {
    if (*p == '/' || *p == '\\') {
      b = p + 1;
    }
  }
  return b;
}

static int decision_is_file_event(EdrEventType t) {
  return t == EDR_EVENT_FILE_CREATE || t == EDR_EVENT_FILE_WRITE ||
         t == EDR_EVENT_FILE_DELETE || t == EDR_EVENT_FILE_RENAME ||
         t == EDR_EVENT_FILE_PERMISSION_CHANGE || t == EDR_EVENT_FILE_READ;
}

static int decision_file_path_usable_for_ransom(const char *path) {
  if (!path || !path[0]) {
    return 0;
  }
  if (!(strchr(path, '\\') || strchr(path, '/') ||
        (isalpha((unsigned char)path[0]) && path[1] == ':') ||
        has_ci(path, "\\device\\") || has_ci(path, "\\??\\"))) {
    return 0;
  }
  const char *base = base_name(path);
  return base && strlen(base) >= 3u;
}

static int decision_low_value_ransom_process(const EdrBehaviorRecord *r) {
  if (!r) {
    return 0;
  }
  const char *s = r->process_name[0] ? r->process_name : r->exe_path;
  return has_ci(s, "taskmgr.exe") || has_ci(s, "usoclient.exe") ||
         has_ci(s, "taskhostw.exe") || has_ci(s, "ecagent.exe") ||
         has_ci(s, "checknetisolation.exe") || has_ci(s, "conhost.exe");
}

static int decision_suppress_ransom_file_signal(const EdrBehaviorRecord *r) {
  return r && decision_is_file_event(r->type) &&
         (!decision_file_path_usable_for_ransom(r->file_path) ||
          decision_low_value_ransom_process(r));
}

static int token_list_has_ci(const char *list, const char *value) {
  if (!list || !list[0] || !value || !value[0]) {
    return 0;
  }
  const char *p = list;
  while (*p) {
    while (*p == ',' || *p == ';' || *p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
      p++;
    }
    char tok[256];
    size_t n = 0;
    while (*p && *p != ',' && *p != ';' && *p != '\n' && *p != '\r' && n + 1u < sizeof(tok)) {
      tok[n++] = *p++;
    }
    while (*p && *p != ',' && *p != ';' && *p != '\n' && *p != '\r') {
      p++;
    }
    tok[n] = '\0';
    while (n > 0u && (tok[n - 1u] == ' ' || tok[n - 1u] == '\t' || tok[n - 1u] == '\n' || tok[n - 1u] == '\r')) {
      tok[--n] = '\0';
    }
    if (tok[0] && has_ci(value, tok)) {
      return 1;
    }
  }
  return 0;
}

static int file_token_list_has_ci(const char *path, const char *value) {
  if (!path || !path[0] || !value || !value[0]) {
    return 0;
  }
  FILE *f = fopen(path, "rb");
  if (!f) {
    return 0;
  }
  char buf[4096];
  size_t n = fread(buf, 1u, sizeof(buf) - 1u, f);
  fclose(f);
  buf[n] = '\0';
  return token_list_has_ci(buf, value);
}

static int policy_token_match(const char *env_inline, const char *env_file, const char *fallback, const char *value) {
  const char *list = getenv(env_inline);
  if (list && list[0] && token_list_has_ci(list, value)) {
    return 1;
  }
  const char *file = getenv(env_file);
  if (file && file[0] && file_token_list_has_ci(file, value)) {
    return 1;
  }
  return fallback && fallback[0] && token_list_has_ci(fallback, value);
}

static int env_int_clamped(const char *name, int fallback, int lo, int hi) {
  const char *v = getenv(name);
  long n = v && v[0] ? strtol(v, NULL, 10) : (long)fallback;
  if (n < (long)lo) {
    n = (long)lo;
  }
  if (n > (long)hi) {
    n = (long)hi;
  }
  return (int)n;
}

static int ransom_note_policy_min_files(void) {
  return env_int_clamped("EDR_RANSOM_NOTE_MIN_FILES", 2, 2, 10);
}

static int ransom_note_policy_window_s(void) {
  return env_int_clamped("EDR_RANSOM_NOTE_WINDOW_S", 300, 30, 3600);
}

static int ransom_chain_candidate_threshold(void) {
  return env_int_clamped("EDR_RANSOM_CHAIN_CANDIDATE_SCORE", 50, 30, 90);
}

static int ransom_chain_p0_threshold(void) {
  int candidate = ransom_chain_candidate_threshold();
  int p0 = env_int_clamped("EDR_RANSOM_CHAIN_P0_SCORE", 70, 50, 100);
  return p0 <= candidate ? candidate + 1 : p0;
}

static int has_remote_indicator(const EdrBehaviorRecord *r) {
  if (r && (r->net_dst[0] || r->net_dport != 0u)) {
    return 1;
  }
  const char *fields[] = {r->cmdline, r->dns_query, r->net_dst, r->script_snippet, r->file_path};
  for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
    const char *s = fields[i];
    if (!s || !s[0]) {
      continue;
    }
    if (has_ci(s, "http://") || has_ci(s, "https://") || has_ci(s, "ftp://") || has_ci(s, "\\\\") ||
        has_ci(s, "downloadstring") || has_ci(s, "invoke-webrequest") || has_ci(s, "urlcache")) {
      return 1;
    }
  }
  return 0;
}

static int has_lolbin_script_indicator(const EdrBehaviorRecord *r) {
  const char *s = r->cmdline[0] ? r->cmdline : r->script_snippet;
  return has_ci(s, ".sct") || has_ci(s, "scrobj.dll") || has_ci(s, "javascript:") || has_ci(s, "vbscript:") ||
         has_ci(s, "-enc") || has_ci(s, "-encodedcommand") || has_ci(s, "frombase64string") ||
         has_ci(s, "invoke-expression") || has_ci(s, " iex ") || has_ci(s, " iex(") ||
         has_ci(s, "amsiutils") || has_ci(s, "amsiinitfailed") || has_ci(s, "amsiscanbuffer") ||
         has_ci(s, "disable-amsi");
}

static int has_script_sensor_indicator(const EdrBehaviorRecord *r) {
  const char *s = r->script_snippet[0] ? r->script_snippet : r->cmdline;
  if (r->type == EDR_EVENT_SCRIPT_POWERSHELL || r->type == EDR_EVENT_SCRIPT_WMI ||
      r->type == EDR_EVENT_SCRIPT_BASH || r->type == EDR_EVENT_SCRIPT_PYTHON) {
    return 1;
  }
  return has_ci(s, "sensor=amsi") || has_ci(s, "sensor=scriptblock") || has_ci(s, "sensor=etw") ||
         has_ci(s, "provider=Microsoft-Antimalware-Scan-Interface") ||
         has_ci(s, "provider=Microsoft-Windows-PowerShell") || has_ci(s, "scriptblock_id=") ||
         has_ci(s, "amsi_content=") || has_ci(s, "amsi_result=") ||
         has_ci(s, "script_content=") || has_ci(s, "script_text=");
}

static int has_tls_anomaly_indicator(const EdrBehaviorRecord *r) {
  const char *s = r->script_snippet;
  if (r->type != EDR_EVENT_NET_TLS_HANDSHAKE && !has_ci(s, "ja3=") && !has_ci(s, "ja3_hash=") &&
      !has_ci(s, "ja3_fingerprint=") && !has_ci(s, "sni=") && !has_ci(s, "tls_sni=")) {
    return r->cert_revoked_ancestor ? 1 : 0;
  }
  return r->cert_revoked_ancestor || has_ci(s, "ja3_rare=1") || has_ci(s, "ja3_unknown=1") ||
         has_ci(s, "sni_suspicious=1") || has_ci(s, "sni_mismatch=1") ||
         has_ci(s, "cert_self_signed=1") || has_ci(s, "cert_expired=1") ||
         has_ci(s, "cert_mismatch=1") || has_ci(s, "cert_revoked=1") ||
         has_ci(s, "cert_chain_anomaly=1") || has_ci(s, "cert_untrusted=1") ||
         has_ci(s, "tls_error=") || has_ci(s, "tls_alert=");
}

static int is_lolbin(const char *name) {
  const char *b = base_name(name);
  return has_ci(b, "regsvr32.exe") || has_ci(b, "mshta.exe") || has_ci(b, "rundll32.exe") ||
         has_ci(b, "powershell.exe") || has_ci(b, "pwsh.exe") || has_ci(b, "wscript.exe") ||
         has_ci(b, "cscript.exe") || has_ci(b, "bitsadmin.exe") || has_ci(b, "certutil.exe");
}

static int suspicious_parent(const EdrBehaviorRecord *r) {
  const char *p = r->parent_name[0] ? r->parent_name : r->parent_path;
  const char *c = r->cmdline;
  return has_ci(p, "winword") || has_ci(p, "excel") || has_ci(p, "powerpnt") || has_ci(p, "outlook") ||
         has_ci(p, "acrord") || has_ci(p, "chrome") || has_ci(p, "msedge") || has_ci(p, "iexplore") ||
         has_ci(c, "\\appdata\\") || has_ci(c, "/tmp/") || has_ci(c, "/var/tmp/");
}

static int is_management_tool(const EdrBehaviorRecord *r) {
  const char *name = r->process_name[0] ? r->process_name : base_name(r->exe_path);
  const char *defaults =
      "anydesk,teamviewer,rustdesk,screenconnect,connectwise,splashtop,meshcentral,atera,psexec,paexec";
  return policy_token_match("EDR_DETECTION_MGMT_TOOLS", "EDR_DETECTION_MGMT_TOOLS_FILE", defaults, name) ||
         policy_token_match("EDR_DETECTION_MGMT_TOOLS", "EDR_DETECTION_MGMT_TOOLS_FILE", defaults, r->cmdline);
}

static int allowlisted_path(const EdrBehaviorRecord *r) {
  const char *path = r->exe_path[0] ? r->exe_path : r->file_path;
  if (policy_token_match("EDR_DETECTION_ALLOW_PATHS", "EDR_DETECTION_ALLOW_PATHS_FILE", "", path)) {
    return 1;
  }
  if (policy_token_match("EDR_DETECTION_SCRIPT_DIRS", "EDR_DETECTION_SCRIPT_DIRS_FILE", "", r->cmdline)) {
    return 1;
  }
  if (has_ci(path, "\\program files\\") || has_ci(path, "\\program files (x86)\\") || has_ci(path, "/opt/") ||
      has_ci(path, "/usr/bin/") || has_ci(path, "/usr/sbin/")) {
    return 1;
  }
  return 0;
}

static int has_credential_dump_indicator(const EdrBehaviorRecord *r) {
  const char *s = r->cmdline[0] ? r->cmdline : r->script_snippet;
  return has_ci(s, "lsass") || has_ci(s, "comsvcs.dll") || has_ci(s, "minidump") ||
         has_ci(s, "sekurlsa::logonpasswords") || has_ci(s, "invoke-mimikatz") ||
         has_ci(s, "nanodump") || has_ci(s, "procdump");
}

static int has_ransom_recovery_tamper_indicator(const EdrBehaviorRecord *r) {
  const char *s = r->cmdline[0] ? r->cmdline : r->script_snippet;
  const char *n = r->process_name[0] ? r->process_name : base_name(r->exe_path);
  return has_ci(n, "vssadmin.exe") || has_ci(n, "wbadmin.exe") || has_ci(n, "bcdedit.exe") ||
         has_ci(n, "wevtutil.exe") || has_ci(s, "delete shadows") || has_ci(s, "shadowcopy delete") ||
         has_ci(s, "recoveryenabled no") || has_ci(s, "delete catalog") || has_ci(s, "clear-log");
}

static int has_ransom_note_indicator(const EdrBehaviorRecord *r) {
  const char *path = r->file_path[0] ? r->file_path : r->exe_path;
  const char *s = r->script_snippet[0] ? r->script_snippet : r->cmdline;
  if (decision_suppress_ransom_file_signal(r)) {
    return 0;
  }
  int note_name = has_ci(path, "readme") || has_ci(path, "decrypt") || has_ci(path, "recover") ||
                  has_ci(path, "restore-files") || has_ci(path, "how_to_decrypt") ||
                  has_ci(path, "how-to-decrypt") || has_ci(path, "ransom");
  int note_ext = has_ci(path, ".txt") || has_ci(path, ".hta") || has_ci(path, ".htm") ||
                 has_ci(path, ".html");
  return (note_name && note_ext) || has_ci(s, "ransom_note_burst=1") ||
         has_ci(s, "win_policy=ransomware_note_or_file_burst") ||
         has_ci(s, "win_policy_tags=ransomware_behavior");
}

static int has_ransom_note_burst_indicator(const EdrBehaviorRecord *r) {
  const char *s = r ? (r->script_snippet[0] ? r->script_snippet : r->cmdline) : "";
  return has_ci(s, "ransom_note_burst=1");
}

static int has_ransom_canary_indicator(const EdrBehaviorRecord *r) {
  if (!r) {
    return 0;
  }
  const char *s = r->script_snippet[0] ? r->script_snippet : r->cmdline;
  const char *path = r->file_path[0] ? r->file_path : r->exe_path;
  return has_ci(s, "ransom_canary=1") || has_ci(s, "DETERMINISTIC_ENCRYPTION") ||
         has_ci(path, "~$canary") || has_ci(path, "edr_canary") || has_ci(path, ".edr-canary") ||
         has_ci(path, "edr-canary");
}

static int has_ransom_counter_allowlist_indicator(const EdrBehaviorRecord *r) {
  const char *s = r ? (r->script_snippet[0] ? r->script_snippet : r->cmdline) : "";
  return has_ci(s, "ransom_counter_allowlisted=1");
}

static int has_ransom_signer_allowlist_indicator(const EdrBehaviorRecord *r) {
  const char *s = r ? (r->script_snippet[0] ? r->script_snippet : r->cmdline) : "";
  return has_ci(s, "ransom_signer_allowlisted=1");
}

static int token_list_match_count_ci(const char *list, const char *value) {
  if (!list || !list[0] || !value || !value[0]) {
    return 0;
  }
  int count = 0;
  const char *p = list;
  while (*p) {
    while (*p == ',' || *p == ';' || *p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
      p++;
    }
    char tok[256];
    size_t n = 0;
    while (*p && *p != ',' && *p != ';' && *p != '\n' && *p != '\r' && n + 1u < sizeof(tok)) {
      tok[n++] = *p++;
    }
    while (*p && *p != ',' && *p != ';' && *p != '\n' && *p != '\r') {
      p++;
    }
    tok[n] = '\0';
    while (n > 0u && (tok[n - 1u] == ' ' || tok[n - 1u] == '\t' || tok[n - 1u] == '\n' || tok[n - 1u] == '\r')) {
      tok[--n] = '\0';
    }
    if (tok[0] && has_ci(value, tok)) {
      count++;
    }
  }
  return count;
}

static int has_security_termination_verb(const EdrBehaviorRecord *r) {
  const char *s = r->cmdline[0] ? r->cmdline : r->script_snippet;
  const char *n = r->process_name[0] ? r->process_name : base_name(r->exe_path);
  return has_ci(n, "taskkill.exe") || has_ci(n, "tskill.exe") || has_ci(n, "wmic.exe") ||
         has_ci(n, "powershell.exe") || has_ci(n, "pwsh.exe") || has_ci(s, "taskkill") ||
         has_ci(s, "tskill") || (has_ci(s, "wmic") && has_ci(s, "terminate")) ||
         has_ci(s, "stop-process") || has_ci(s, "kill -processname");
}

static int security_product_target_count(const EdrBehaviorRecord *r) {
  if (!r || !has_security_termination_verb(r)) {
    return 0;
  }
  const char *s = r->cmdline[0] ? r->cmdline : r->script_snippet;
  static const char *const defaults[] = {
      "msmpeng.exe", "windefend", "sense.exe", "senseir.exe", "securityhealthservice.exe",
      "csagent.exe", "falcon", "cybereason", "carbonblack", "cb.exe", "cbdefense",
      "sentinelagent.exe", "sentinelone", "sophos", "mcshield.exe", "mcafee", "avp.exe",
      "kaspersky", "ekrn.exe", "eset", "symantec", "sep.exe", "smc.exe", "ccsvchst.exe",
      "trend", "tmlisten.exe", "pccntmon.exe", "xagt.exe", "elastic-endpoint.exe",
      "cylancesvc.exe", "cylance", "bdservicehost.exe", "bitdefender", "avastsvc.exe",
      "avgsvc.exe", "360tray.exe", "360sd.exe", "hipsdaemon.exe",
  };
  int count = 0;
  for (size_t i = 0; i < sizeof(defaults) / sizeof(defaults[0]); i++) {
    if (has_ci(s, defaults[i])) {
      count++;
    }
  }
  const char *extra = getenv("EDR_RANSOM_SECURITY_PRODUCTS");
  if (extra && extra[0]) {
    count += token_list_match_count_ci(extra, s);
  }
  return count;
}

static int has_security_product_kill_indicator(const EdrBehaviorRecord *r) {
  const char *env = getenv("EDR_RANSOM_SECURITY_KILL_MIN_TARGETS");
  long min_targets = env && env[0] ? strtol(env, NULL, 10) : 3L;
  if (min_targets < 1L) {
    min_targets = 1L;
  }
  if (min_targets > 10L) {
    min_targets = 10L;
  }
  return security_product_target_count(r) >= (int)min_targets;
}

static int has_exfil_indicator(const EdrBehaviorRecord *r) {
  const char *s = r->cmdline[0] ? r->cmdline : r->script_snippet;
  const char *n = r->process_name[0] ? r->process_name : base_name(r->exe_path);
  return has_ci(s, "compress-archive") || has_ci(n, "rar.exe") || has_ci(n, "winrar.exe") ||
         has_ci(n, "7z.exe") || has_ci(n, "7za.exe") || has_ci(n, "rclone.exe") ||
         has_ci(s, "rclone copy") || has_ci(s, "rclone sync") || has_ci(s, "aws s3 cp") ||
         has_ci(s, "az storage blob upload") || has_ci(s, "curl -t") || has_ci(s, "scp ");
}

static int has_silverfox_indicator(const EdrBehaviorRecord *r) {
  if (!r) {
    return 0;
  }
  const char *fields[] = {
      r->process_name,    r->exe_path,       r->cmdline,        r->file_path,
      r->reg_key_path,    r->reg_value_name, r->reg_value_data, r->script_snippet,
  };
  int setup64_seen = 0;
  int silverfox_path_seen = 0;
  for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
    const char *s = fields[i] ? fields[i] : "";
    if (has_ci(s, "\\public\\501\\") || has_ci(s, "/public/501/") ||
        has_ci(s, "\\programdata\\golden\\") || has_ci(s, "/programdata/golden/")) {
      silverfox_path_seen = 1;
    }
    if (has_ci(s, "setup64.exe")) {
      setup64_seen = 1;
    }
    if (has_ci(s, "winos") || has_ci(s, "valleyrat") ||
        has_ci(s, "silverfox") || has_ci(s, "silver fox") ||
        has_ci(s, "wsftprm.sys") || has_ci(s, "amsdk.sys") || has_ci(s, "wamsdk.sys") ||
        has_ci(s, "zam.exe") || has_ci(s, "zemana") || has_ci(s, "watchdog")) {
      return 1;
    }
    if ((has_ci(s, ".ini") || has_ci(s, "nsis")) && (has_ci(s, "srdi") || has_ci(s, "shellcode"))) {
      return 1;
    }
  }
  if (setup64_seen && silverfox_path_seen) {
    return 1;
  }
  if (has_ci(r->process_name, "computerdefaults.exe") &&
      (has_ci(r->cmdline, "debugobject") || has_ci(r->cmdline, "appinfo") ||
       has_ci(r->cmdline, "\\public\\501\\") || has_ci(r->cmdline, "\\programdata\\golden\\"))) {
    return 1;
  }
  return 0;
}

static int has_persistence_change_indicator(const EdrBehaviorRecord *r) {
  const char *key = r->reg_key_path;
  const char *name = r->reg_value_name;
  const char *data = r->reg_value_data;
  const char *cmd = r->cmdline[0] ? r->cmdline : r->script_snippet;
  if (r->type == EDR_EVENT_SERVICE_CREATE || r->type == EDR_EVENT_SCHEDULED_TASK_CREATE ||
      r->type == EDR_EVENT_DRIVER_LOAD) {
    return 1;
  }
  if (r->type == EDR_EVENT_REG_CREATE_KEY || r->type == EDR_EVENT_REG_SET_VALUE) {
    if (has_ci(key, "\\currentversion\\run") || has_ci(key, "\\currentversion\\runonce") ||
        has_ci(key, "\\policies\\explorer\\run") || has_ci(key, "\\windows\\run") ||
        has_ci(key, "\\services\\") || has_ci(key, "\\winlogon") ||
        has_ci(key, "\\image file execution options\\") || has_ci(key, "\\appinit_dlls") ||
        has_ci(key, "\\shellserviceobjectdelayload") || has_ci(key, "\\active setup\\installed components") ||
        has_ci(key, "\\wmi\\") || has_ci(key, "\\subscription") || has_ci(key, "\\eventconsumer")) {
      return 1;
    }
    if (has_ci(name, "shell") || has_ci(name, "userinit") || has_ci(name, "debugger") ||
        has_ci(name, "appinit_dlls") || has_ci(data, "powershell") || has_ci(data, "regsvr32") ||
        has_ci(data, "mshta") || has_ci(data, "rundll32") || has_ci(data, "wscript")) {
      return 1;
    }
  }
  return has_ci(cmd, "schtasks /create") || has_ci(cmd, "sc create") || has_ci(cmd, "new-service") ||
         has_ci(cmd, "set-itemproperty") || has_ci(cmd, "\\currentversion\\run") ||
         (has_ci(cmd, "wmic") && has_ci(cmd, "eventconsumer"));
}

static int is_injection_event(const EdrBehaviorRecord *r) {
  return r->type == EDR_EVENT_PROCESS_INJECT || r->type == EDR_EVENT_THREAD_CREATE_REMOTE;
}

static double detail_number(const char *text, const char *key, double fallback) {
  char tmp[64];
  if (!detail_value(text, key, tmp, sizeof(tmp))) {
    return fallback;
  }
  return strtod(tmp, NULL);
}

static int has_extension_change_indicator(const EdrBehaviorRecord *r) {
  const char *s = r ? (r->script_snippet[0] ? r->script_snippet : r->cmdline) : "";
  return has_ci(s, "ext_changed=1");
}

static int has_high_content_entropy_indicator(const EdrBehaviorRecord *r) {
  const char *s = r ? (r->script_snippet[0] ? r->script_snippet : r->cmdline) : "";
  double ent = detail_number(s, "content_entropy", -1.0);
  double sample = detail_number(s, "content_sample_bytes", 0.0);
  return ent >= 7.20 && sample >= 512.0;
}

static int has_ransom_burst_indicator(const EdrBehaviorRecord *r) {
  const char *s = r->script_snippet[0] ? r->script_snippet : r->cmdline;
  if (has_ransom_canary_indicator(r)) {
    return 1;
  }
  if (decision_suppress_ransom_file_signal(r)) {
    return 0;
  }
  if (has_ransom_counter_allowlist_indicator(r)) {
    return 0;
  }
  double file_rate = detail_number(s, "file_rate", -1.0);
  double ext_burst = detail_number(s, "ext_burst", -1.0);
  double dir_burst = detail_number(s, "dir_burst", -1.0);
  double entropy_delta = detail_number(s, "entropy_delta", -1.0);
  int ext_changed = has_extension_change_indicator(r);
  int high_content_entropy = has_high_content_entropy_indicator(r);
  if (entropy_delta < 0.0) {
    entropy_delta = detail_number(s, "file_entropy_delta", -1.0);
  }
  int recovery = has_ransom_recovery_tamper_indicator(r);
  return has_ci(s, "ransom_counter=1") || has_ci(s, "mass_rename=1") || has_ci(s, "extension_burst=1") ||
         has_ci(s, "rename_burst=1") || has_ci(s, "shadow_delete=1") ||
         has_ci(s, "shadowcopy_delete=1") || file_rate >= 80.0 || ext_burst >= 20.0 ||
         dir_burst >= 4.0 || entropy_delta >= 1.5 || (ext_changed && high_content_entropy) ||
         (recovery && (file_rate >= 20.0 || ext_burst >= 8.0 || dir_burst >= 2.0));
}

static int has_webshell_semantic_indicator(const EdrBehaviorRecord *r) {
  const char *s = r->script_snippet[0] ? r->script_snippet : r->cmdline;
  double ast = detail_number(s, "ast_score", -1.0);
  double tok = detail_number(s, "token_score", -1.0);
  double sem = detail_number(s, "semantic_score", -1.0);
  return r->type == EDR_EVENT_WEBSHELL_DETECTED || ast >= 0.70 || tok >= 0.70 ||
         has_ci(s, "ast=webshell") || has_ci(s, "token=webshell") || has_ci(s, "token_eval") ||
         has_ci(s, "base64_decode") || has_ci(s, "assert(") || has_ci(s, "preg_replace") ||
         has_ci(s, "shell_exec") || has_ci(s, "passthru") || has_ci(s, "cmd=") ||
         has_ci(s, "ast_tokens=") || has_ci(s, "token_features=") || sem >= 0.70 ||
         has_ci(r->file_path, ".php") || has_ci(r->file_path, ".aspx") || has_ci(r->file_path, ".jsp");
}

static int rmm_enterprise_policy_match(const EdrBehaviorRecord *r) {
  const char *policy = getenv("EDR_DETECTION_RMM_ALLOWLIST");
  const char *legacy = getenv("EDR_DETECTION_MGMT_TOOLS");
  const char *list = policy && policy[0] ? policy : legacy;
  const char *file = getenv("EDR_DETECTION_RMM_ALLOWLIST_FILE");
  return (list && list[0] &&
          (token_list_has_ci(list, r->process_name) || token_list_has_ci(list, r->exe_path) ||
           token_list_has_ci(list, r->cmdline))) ||
         (file && file[0] &&
          (file_token_list_has_ci(file, r->process_name) || file_token_list_has_ci(file, r->exe_path) ||
           file_token_list_has_ci(file, r->cmdline)));
}

static int false_positive_feedback_match(const EdrBehaviorRecord *r) {
  return policy_token_match("EDR_DETECTION_FP_FEEDBACK", "EDR_DETECTION_FP_FEEDBACK_FILE", "", r->process_name) ||
         policy_token_match("EDR_DETECTION_FP_FEEDBACK", "EDR_DETECTION_FP_FEEDBACK_FILE", "", r->exe_path) ||
         policy_token_match("EDR_DETECTION_FP_FEEDBACK", "EDR_DETECTION_FP_FEEDBACK_FILE", "", r->cmdline) ||
         policy_token_match("EDR_DETECTION_FP_FEEDBACK", "EDR_DETECTION_FP_FEEDBACK_FILE", "", r->file_path) ||
         policy_token_match("EDR_DETECTION_FP_FEEDBACK", "EDR_DETECTION_FP_FEEDBACK_FILE", "", r->exe_hash);
}

/* 二期条件化 suppression：解析 EDR_DETECTION_SUPPRESSION_RULES（控制符分隔的紧凑串，由
 * config.c 从 [[detection_policy.suppression]] 生成），用 AND 语义匹配：process_name 命中且
 * contains_all 全部出现才命中。命中时输出 reason 与 action（0=downgrade,1=drop）。
 * 相比 fp_feedback 平铺匹配，它保留同进程其它形态（如外链 / 非 localhost）的告警能力。 */
static int record_text_has_ci(const EdrBehaviorRecord *r, const char *needle) {
  if (!r || !needle || !needle[0]) {
    return 0;
  }
  return has_ci(r->cmdline, needle) || has_ci(r->exe_path, needle) ||
         has_ci(r->file_path, needle) || has_ci(r->script_snippet, needle) ||
         has_ci(r->net_dst, needle) || has_ci(r->dns_query, needle) ||
         has_ci(r->process_name, needle) || has_ci(r->reg_key_path, needle);
}

static int conditional_suppression_match(const EdrBehaviorRecord *r, char *reason_out,
                                         size_t reason_cap, int *action_out) {
  if (reason_out && reason_cap) {
    reason_out[0] = '\0';
  }
  if (action_out) {
    *action_out = 0;
  }
  if (!r) {
    return 0;
  }
  const char *rules = getenv("EDR_DETECTION_SUPPRESSION_RULES");
  if (!rules || !rules[0]) {
    return 0;
  }
  const char *p = rules;
  while (*p) {
    /* 一条规则到下一个 0x1e。 */
    const char *rule_end = p;
    while (*rule_end && *rule_end != '\x1e') {
      rule_end++;
    }
    /* 字段：target \x1f process \x1f action \x1f reason \x1f contains_all(\x1d 分隔) */
    char target[96] = "", process[128] = "", action[32] = "", reason[96] = "";
    char *fields[4] = {target, process, action, reason};
    size_t caps[4] = {sizeof(target), sizeof(process), sizeof(action), sizeof(reason)};
    const char *q = p;
    int fi = 0;
    for (; fi < 4 && q < rule_end; fi++) {
      size_t k = 0u;
      while (q < rule_end && *q != '\x1f' && k + 1u < caps[fi]) {
        fields[fi][k++] = *q++;
      }
      fields[fi][k] = '\0';
      while (q < rule_end && *q != '\x1f') {
        q++;
      }
      if (q < rule_end && *q == '\x1f') {
        q++;
      }
    }
    /* q..rule_end 是 contains_all token（0x1d 分隔）。 */
    int ok = 1;
    if (process[0] && !record_text_has_ci(r, process)) {
      ok = 0;
    }
    int any_contains = 0;
    const char *c = q;
    while (ok && c < rule_end) {
      char tok[256];
      size_t k = 0u;
      while (c < rule_end && *c != '\x1d' && k + 1u < sizeof(tok)) {
        tok[k++] = *c++;
      }
      tok[k] = '\0';
      while (c < rule_end && *c != '\x1d') {
        c++;
      }
      if (c < rule_end && *c == '\x1d') {
        c++;
      }
      if (tok[0]) {
        any_contains = 1;
        if (!record_text_has_ci(r, tok)) {
          ok = 0;
          break;
        }
      }
    }
    (void)target;
    /* 至少要有一个收窄条件（进程或 contains），避免空规则全匹配。 */
    if (ok && (process[0] || any_contains)) {
      if (reason_out && reason_cap) {
        snprintf(reason_out, reason_cap, "%s", reason[0] ? reason : "conditional_suppression");
      }
      if (action_out) {
        *action_out = (strcmp(action, "drop") == 0) ? 1 : 0;
      }
      return 1;
    }
    if (*rule_end == '\x1e') {
      rule_end++;
    }
    p = rule_end;
  }
  return 0;
}

#define EDR_PROCESS_CONTEXT_SLOTS 256u
#define EDR_SUPPRESSION_COUNTER_SLOTS 64u

typedef struct {
  uint32_t pid;
  uint32_t ppid;
  int64_t last_ns;
  uint32_t events;
  uint8_t remote;
  uint8_t script_sensor;
  uint8_t tls_anomaly;
  uint8_t ransom_behavior;
  uint8_t ransom_recovery;
  uint8_t ransom_note;
  uint8_t security_product_kill;
  uint8_t webshell_semantic;
  uint8_t credential;
  uint8_t injection;
  uint8_t persistence;
  uint8_t shellcode;
  uint8_t pmfe;
} EdrProcessContextSlot;

typedef struct {
  char reason[96];
  char policy_version[64];
  uint32_t count;
} EdrSuppressionCounterSlot;

static EdrProcessContextSlot g_process_context[EDR_PROCESS_CONTEXT_SLOTS];
static EdrSuppressionCounterSlot g_suppression_counters[EDR_SUPPRESSION_COUNTER_SLOTS];
static uint64_t g_process_context_seq;

typedef struct {
  int score;
  int recovery_tamper;
  int security_product_kill;
  int ransom_file_burst;
  int ransom_note;
  int ransom_note_burst;
  int lolbin_or_script;
  int exfil_or_remote;
  int context_correlated;
} EdrRansomChainSignal;

static int64_t process_context_window_ns(void) {
  const char *env = getenv("EDR_DETECTION_CONTEXT_WINDOW_S");
  long sec = env && env[0] ? strtol(env, NULL, 10) : 900L;
  if (sec <= 0L) {
    sec = 900L;
  }
  if (sec > 3600L) {
    sec = 3600L;
  }
  return (int64_t)sec * 1000000000LL;
}

static int64_t record_time_or_seq(const EdrBehaviorRecord *r) {
  if (r && r->event_time_ns > 0) {
    return r->event_time_ns;
  }
  return (int64_t)(++g_process_context_seq);
}

static const EdrProcessContextSlot *process_context_lookup_pid(uint32_t pid, int64_t now_ns) {
  if (pid == 0u) {
    return NULL;
  }
  int64_t win = process_context_window_ns();
  for (size_t i = 0; i < EDR_PROCESS_CONTEXT_SLOTS; i++) {
    const EdrProcessContextSlot *s = &g_process_context[i];
    if (s->pid != pid || s->events == 0u) {
      continue;
    }
    if (s->last_ns <= 0 || now_ns <= 0 || now_ns - s->last_ns <= win) {
      return s;
    }
  }
  return NULL;
}

static const EdrProcessContextSlot *process_context_lookup(const EdrBehaviorRecord *r, int64_t now_ns) {
  return r ? process_context_lookup_pid(r->pid, now_ns) : NULL;
}

static uint32_t ransomware_tree_root_pid(const EdrBehaviorRecord *r, const EdrProcessContextSlot *parent_ctx) {
  if (!r) {
    return 0u;
  }
  if (r->ppid != 0u && parent_ctx && parent_ctx->events > 0u) {
    return r->ppid;
  }
  if (r->grandparent_pid != 0u) {
    return r->grandparent_pid;
  }
  if (r->ppid != 0u && !has_ci(r->parent_name, "services.exe") && !has_ci(r->parent_name, "svchost.exe")) {
    return r->ppid;
  }
  return r->pid;
}

static void process_context_update(const EdrBehaviorRecord *r, int64_t now_ns, int remote, int script_sensor,
                                   int tls_anomaly, int ransom_behavior, int ransom_recovery, int ransom_note,
                                   int security_product_kill, int webshell_semantic, int credential,
                                   int injection, int persistence) {
  if (!r || r->pid == 0u) {
    return;
  }
  EdrProcessContextSlot *empty = NULL;
  EdrProcessContextSlot *oldest = &g_process_context[0];
  for (size_t i = 0; i < EDR_PROCESS_CONTEXT_SLOTS; i++) {
    EdrProcessContextSlot *s = &g_process_context[i];
    if (s->pid == r->pid) {
      if (r->ppid != 0u) {
        s->ppid = r->ppid;
      }
      s->last_ns = now_ns;
      s->events++;
      s->remote |= remote ? 1u : 0u;
      s->script_sensor |= script_sensor ? 1u : 0u;
      s->tls_anomaly |= tls_anomaly ? 1u : 0u;
      s->ransom_behavior |= ransom_behavior ? 1u : 0u;
      s->ransom_recovery |= ransom_recovery ? 1u : 0u;
      s->ransom_note |= ransom_note ? 1u : 0u;
      s->security_product_kill |= security_product_kill ? 1u : 0u;
      s->webshell_semantic |= webshell_semantic ? 1u : 0u;
      s->credential |= credential ? 1u : 0u;
      s->injection |= injection ? 1u : 0u;
      s->persistence |= persistence ? 1u : 0u;
      s->shellcode |= (r->type == EDR_EVENT_PROTOCOL_SHELLCODE) ? 1u : 0u;
      s->pmfe |= (r->type == EDR_EVENT_PMFE_SCAN_RESULT || r->pmfe_snapshot[0]) ? 1u : 0u;
      return;
    }
    if (s->events == 0u && empty == NULL) {
      empty = s;
    }
    if (s->last_ns < oldest->last_ns) {
      oldest = s;
    }
  }
  EdrProcessContextSlot *s = empty ? empty : oldest;
  memset(s, 0, sizeof(*s));
  s->pid = r->pid;
  s->ppid = r->ppid;
  s->last_ns = now_ns;
  s->events = 1u;
  s->remote = remote ? 1u : 0u;
  s->script_sensor = script_sensor ? 1u : 0u;
  s->tls_anomaly = tls_anomaly ? 1u : 0u;
  s->ransom_behavior = ransom_behavior ? 1u : 0u;
  s->ransom_recovery = ransom_recovery ? 1u : 0u;
  s->ransom_note = ransom_note ? 1u : 0u;
  s->security_product_kill = security_product_kill ? 1u : 0u;
  s->webshell_semantic = webshell_semantic ? 1u : 0u;
  s->credential = credential ? 1u : 0u;
  s->injection = injection ? 1u : 0u;
  s->persistence = persistence ? 1u : 0u;
  s->shellcode = (r->type == EDR_EVENT_PROTOCOL_SHELLCODE) ? 1u : 0u;
  s->pmfe = (r->type == EDR_EVENT_PMFE_SCAN_RESULT || r->pmfe_snapshot[0]) ? 1u : 0u;
}

static EdrRansomChainSignal ransom_chain_signal(const EdrBehaviorRecord *r,
                                                const EdrProcessContextSlot *ctx,
                                                const EdrProcessContextSlot *parent_ctx,
                                                int recovery, int burst, int note, int note_burst,
                                                int security_kill, int remote,
                                                int script, int script_sensor,
                                                int exfil) {
  EdrRansomChainSignal sig;
  memset(&sig, 0, sizeof(sig));
  sig.recovery_tamper = recovery || (ctx && ctx->ransom_recovery) || (parent_ctx && parent_ctx->ransom_recovery);
  sig.security_product_kill =
      security_kill || (ctx && ctx->security_product_kill) || (parent_ctx && parent_ctx->security_product_kill);
  sig.ransom_file_burst = burst || (ctx && ctx->ransom_behavior) || (parent_ctx && parent_ctx->ransom_behavior);
  sig.ransom_note = note || (ctx && ctx->ransom_note) || (parent_ctx && parent_ctx->ransom_note);
  sig.ransom_note_burst = note_burst;
  sig.lolbin_or_script = script || script_sensor || is_lolbin(r->process_name[0] ? r->process_name : r->exe_path) ||
                         (ctx && ctx->script_sensor) || (parent_ctx && parent_ctx->script_sensor);
  sig.exfil_or_remote = exfil || remote || (ctx && ctx->remote) || (parent_ctx && parent_ctx->remote);
  sig.context_correlated = ((ctx && ctx->events > 1u) || (parent_ctx && parent_ctx->events > 0u)) &&
                           ((sig.recovery_tamper && (sig.ransom_file_burst || sig.ransom_note)) ||
                            (sig.security_product_kill && (sig.ransom_file_burst || sig.exfil_or_remote)) ||
                            (sig.ransom_file_burst && sig.ransom_note));

  if (sig.recovery_tamper) {
    sig.score += 40;
  }
  if (sig.security_product_kill) {
    sig.score += 35;
  }
  if (sig.ransom_file_burst) {
    sig.score += 30;
  }
  if (sig.ransom_note_burst) {
    sig.score += 35;
  } else if (sig.ransom_note) {
    sig.score += 20;
  }
  if (sig.ransom_note_burst && sig.ransom_file_burst) {
    sig.score += 10;
  }
  if (sig.ransom_note && !sig.ransom_note_burst && !sig.ransom_file_burst &&
      !sig.recovery_tamper && !sig.security_product_kill) {
    sig.score -= 5;
  }
  if (sig.score < 0) {
    sig.score = 0;
  }
  if (sig.lolbin_or_script) {
    sig.score += 20;
  }
  if (sig.exfil_or_remote) {
    sig.score += 15;
  }
  if (sig.context_correlated) {
    sig.score += 10;
  }
  if (sig.score > 100) {
    sig.score = 100;
  }
  return sig;
}

static void add_reason(char *dst, size_t cap, const char *s) {
  if (!dst || cap == 0u || !s || !s[0]) {
    return;
  }
  size_t l = strlen(dst);
  if (l > 0u && l + 1u < cap) {
    dst[l++] = ',';
    dst[l] = '\0';
  }
  if (l + 1u < cap) {
    snprintf(dst + l, cap - l, "%s", s);
  }
}

/* Event Quality Score: 把 evaluate 累积的 reason 列表分流为 signal/noise，
 * 并归一化出 0~100 的上传价值分与 selection_action。降分（noise）token 取自
 * 各 suppression 分支写入 out->reason 的标签。 */
static int reason_token_is_noise(const char *tok) {
  static const char *kNoise[] = {
      "false_positive_feedback_policy", "management_tool_noise",
      "rmm_enterprise_allowlist_policy", "allowlisted_path",
      "lolbin_without_combo_condition", "conditional_suppression",
  };
  for (size_t i = 0; i < sizeof(kNoise) / sizeof(kNoise[0]); i++) {
    if (strcmp(tok, kNoise[i]) == 0) {
      return 1;
    }
  }
  return 0;
}

static uint8_t reason_token_noise_weight(const char *tok) {
  if (strcmp(tok, "false_positive_feedback_policy") == 0) {
    return 40u;
  }
  if (strcmp(tok, "rmm_enterprise_allowlist_policy") == 0 ||
      strcmp(tok, "allowlisted_path") == 0) {
    return 30u;
  }
  if (strcmp(tok, "management_tool_noise") == 0 ||
      strcmp(tok, "lolbin_without_combo_condition") == 0) {
    return 20u;
  }
  if (strcmp(tok, "conditional_suppression") == 0) {
    return 40u;
  }
  return 0u;
}

static void compute_event_quality(const EdrBehaviorRecord *r, EdrDetectionDecision *out) {
  out->signal_reasons[0] = '\0';
  out->noise_reasons[0] = '\0';
  uint32_t supp = 0u;
  const char *p = out->reason;
  char tok[96];
  while (*p) {
    size_t n = 0u;
    while (*p && *p != ',' && n + 1u < sizeof(tok)) {
      tok[n++] = *p++;
    }
    tok[n] = '\0';
    while (*p && *p != ',') {
      p++; /* 丢弃超长 token 余部，保持 token 边界 */
    }
    if (*p == ',') {
      p++;
    }
    if (tok[0] == '\0' || strcmp(tok, "baseline") == 0) {
      continue;
    }
    if (reason_token_is_noise(tok)) {
      add_reason(out->noise_reasons, sizeof(out->noise_reasons), tok);
      supp += reason_token_noise_weight(tok);
    } else {
      add_reason(out->signal_reasons, sizeof(out->signal_reasons), tok);
    }
  }
  if (supp > 100u) {
    supp = 100u;
  }
  out->suppression_score = (uint8_t)supp;

  long sc = (long)(out->confidence * 100.0f + 0.5f);
  if (sc < 0) {
    sc = 0;
  }
  if (sc > 100) {
    sc = 100;
  }
  out->event_quality_score = (uint8_t)sc;

  const char *action;
  if (out->drop) {
    action = "drop";
  } else if (out->event_quality_score >= 80u) {
    action = "emit_alert";
  } else if (out->event_quality_score >= 50u) {
    action = "emit_context";
  } else if (out->event_quality_score >= 20u) {
    action = "local_only";
  } else {
    action = "drop";
  }
  /* P0(priority==0) 强制至少告警；已 suppress 时不高于 emit_context。 */
  if (!out->drop && r && r->priority == 0u) {
    action = "emit_alert";
  } else if (out->suppress && strcmp(action, "emit_alert") == 0) {
    action = "emit_context";
  }
  snprintf(out->selection_action, sizeof(out->selection_action), "%s", action);
}

static uint32_t next_suppression_hit_count(const char *reason, const char *policy_version) {
  const char *r = reason ? reason : "";
  const char *p = policy_version ? policy_version : "";
  EdrSuppressionCounterSlot *empty = NULL;
  for (size_t i = 0; i < EDR_SUPPRESSION_COUNTER_SLOTS; i++) {
    EdrSuppressionCounterSlot *s = &g_suppression_counters[i];
    if (s->count == 0u) {
      if (!empty) {
        empty = s;
      }
      continue;
    }
    if (strcmp(s->reason, r) == 0 && strcmp(s->policy_version, p) == 0) {
      if (s->count < UINT32_MAX) {
        s->count++;
      }
      return s->count;
    }
  }
  EdrSuppressionCounterSlot *s = empty ? empty : &g_suppression_counters[0];
  memset(s, 0, sizeof(*s));
  snprintf(s->reason, sizeof(s->reason), "%s", r);
  snprintf(s->policy_version, sizeof(s->policy_version), "%s", p);
  s->count = 1u;
  return s->count;
}

static const char *suppression_rollback_env(const char *policy_env) {
  if (policy_env && strcmp(policy_env, "EDR_DETECTION_RMM_POLICY_VERSION") == 0) {
    const char *rmm = getenv("EDR_DETECTION_RMM_ROLLBACK_VERSION");
    if (rmm && rmm[0]) {
      return rmm;
    }
  }
  if (policy_env && strcmp(policy_env, "EDR_DETECTION_FP_POLICY_VERSION") == 0) {
    const char *fp = getenv("EDR_DETECTION_FP_ROLLBACK_VERSION");
    if (fp && fp[0]) {
      return fp;
    }
  }
  return getenv("EDR_DETECTION_ROLLBACK_VERSION");
}

static void set_suppression(EdrDetectionDecision *out, float score_before, const char *reason, const char *policy_env) {
  if (!out) {
    return;
  }
  out->suppress = 1u;
  if (out->suppression_reason[0] == '\0' && reason && reason[0]) {
    snprintf(out->suppression_reason, sizeof(out->suppression_reason), "%s", reason);
  }
  if (out->confidence_before_suppression <= 0.0f) {
    out->confidence_before_suppression = score_before;
  }
  if (out->suppression_policy_version[0] == '\0') {
    const char *version = policy_env && policy_env[0] ? getenv(policy_env) : NULL;
    if ((!version || !version[0]) && strcmp(policy_env ? policy_env : "", "EDR_DETECTION_RMM_POLICY_VERSION") != 0) {
      version = getenv("EDR_DETECTION_POLICY_VERSION");
    }
    if (version && version[0]) {
      snprintf(out->suppression_policy_version, sizeof(out->suppression_policy_version), "%s", version);
    }
  }
  if (out->suppression_rollback_version[0] == '\0') {
    const char *rollback = suppression_rollback_env(policy_env);
    if (rollback && rollback[0]) {
      snprintf(out->suppression_rollback_version, sizeof(out->suppression_rollback_version), "%s", rollback);
    }
  }
  if (out->suppression_hit_count == 0u) {
    out->suppression_hit_count =
        next_suppression_hit_count(out->suppression_reason, out->suppression_policy_version);
  }
}

static void json_cat(char *dst, size_t cap, const char *fmt, ...) {
  if (!dst || cap == 0u) {
    return;
  }
  size_t used = strlen(dst);
  if (used + 1u >= cap) {
    return;
  }
  va_list ap;
  va_start(ap, fmt);
  (void)vsnprintf(dst + used, cap - used, fmt, ap);
  va_end(ap);
}

static void json_char(char *dst, size_t cap, char c) {
  size_t used = strlen(dst);
  if (used + 1u >= cap) {
    return;
  }
  dst[used] = c;
  dst[used + 1u] = '\0';
}

static void json_str(char *dst, size_t cap, const char *s, size_t max_chars) {
  json_char(dst, cap, '"');
  if (!s) {
    s = "";
  }
  size_t emitted = 0u;
  for (; *s && emitted < max_chars; s++, emitted++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') {
      json_char(dst, cap, '\\');
      json_char(dst, cap, (char)c);
    } else if (c < 0x20u) {
      json_char(dst, cap, ' ');
    } else {
      json_char(dst, cap, (char)c);
    }
  }
  json_char(dst, cap, '"');
}

/* 把逗号分隔的 reason 串序列化为 JSON 字符串数组：a,b,c -> ["a","b","c"]。 */
static void json_reason_array(char *dst, size_t cap, const char *csv) {
  json_char(dst, cap, '[');
  const char *p = csv ? csv : "";
  char tok[96];
  int first = 1;
  while (*p) {
    size_t n = 0u;
    while (*p && *p != ',' && n + 1u < sizeof(tok)) {
      tok[n++] = *p++;
    }
    tok[n] = '\0';
    while (*p && *p != ',') {
      p++;
    }
    if (*p == ',') {
      p++;
    }
    if (tok[0] == '\0') {
      continue;
    }
    if (!first) {
      json_char(dst, cap, ',');
    }
    json_str(dst, cap, tok, sizeof(tok));
    first = 0;
  }
  json_char(dst, cap, ']');
}

static int detail_value(const char *text, const char *key, char *out, size_t cap) {
  if (!text || !key || !out || cap == 0u) {
    return 0;
  }
  out[0] = '\0';
  size_t kl = strlen(key);
  if (kl == 0u) {
    return 0;
  }
  for (const char *p = text; *p; p++) {
    if ((p == text || p[-1] == ' ' || p[-1] == '\n' || p[-1] == '|') && strncmp(p, key, kl) == 0 && p[kl] == '=') {
      const char *v = p + kl + 1u;
      size_t n = 0u;
      while (v[n] && v[n] != ' ' && v[n] != '\n' && v[n] != '\r' && v[n] != '|') {
        n++;
      }
      if (n >= cap) {
        n = cap - 1u;
      }
      memcpy(out, v, n);
      out[n] = '\0';
      return out[0] != '\0';
    }
  }
  return 0;
}

static const char *engine_name(const EdrBehaviorRecord *r) {
  if (r->type == EDR_EVENT_PROTOCOL_SHELLCODE) {
    return "shellcode";
  }
  if (r->type == EDR_EVENT_WEBSHELL_DETECTED) {
    return "webshell";
  }
  if (r->type == EDR_EVENT_PMFE_SCAN_RESULT || r->pmfe_snapshot[0]) {
    return "pmfe";
  }
  return "p0_rule";
}

static void build_recommended_forensics(char *dst, size_t cap, const EdrBehaviorRecord *r, const EdrDetectionDecision *d,
                                        const EdrDetectionTrigger *t) {
  int first = 1;
#define ADD_ACTION(name)                          \
  do {                                            \
    json_cat(dst, cap, "%s\"%s\"", first ? "" : ",", name); \
    first = 0;                                    \
  } while (0)
  ADD_ACTION("process_tree");
  ADD_ACTION("timeline_window");
  if (r->file_path[0] || r->exe_path[0]) {
    ADD_ACTION("targeted_files");
  }
  if (r->type == EDR_EVENT_WEBSHELL_DETECTED) {
    ADD_ACTION("webshell_files");
  }
  if (d->has_remote || r->dns_query[0] || r->net_dst[0]) {
    ADD_ACTION("ioc_lookup");
  }
  if (t && t->pmfe_scan) {
    ADD_ACTION("pmfe_scan");
  }
  if (t && t->single_process_minidump) {
    ADD_ACTION("single_process_minidump_if_needed");
  }
  if (has_script_sensor_indicator(r)) {
    ADD_ACTION("script_content");
  }
  if (has_tls_anomaly_indicator(r)) {
    ADD_ACTION("tls_certificate");
  }
  if (has_ransom_burst_indicator(r)) {
    ADD_ACTION("ransom_activity");
  }
  if (has_ransom_recovery_tamper_indicator(r)) {
    ADD_ACTION("recovery_tamper_evidence");
  }
  if (has_security_product_kill_indicator(r)) {
    ADD_ACTION("security_product_termination_evidence");
  }
  if (has_ransom_note_indicator(r)) {
    ADD_ACTION("ransom_note_artifacts");
  }
  if (has_webshell_semantic_indicator(r)) {
    ADD_ACTION("webshell_semantics");
  }
  if (d->persistence_change || has_persistence_change_indicator(r)) {
    ADD_ACTION("persistence_changes");
  }
  if (has_silverfox_indicator(r)) {
    ADD_ACTION("driver_inventory");
    ADD_ACTION("silverfox_artifact_review");
  }
#undef ADD_ACTION
}

static void build_detection_context(EdrBehaviorRecord *r, const EdrDetectionDecision *d, const EdrDetectionTrigger *t) {
  r->detection_context[0] = '\0';
  char evidence_detector[48];
  char evidence_rule[96];
  char evidence_score[32];
  char evidence_proto[48];
  char evidence_mitre[32];
  char evidence_forensic[32];
  int script_sensor = has_script_sensor_indicator(r);
  int tls_anomaly = has_tls_anomaly_indicator(r);
  int ransom_canary = has_ransom_canary_indicator(r);
  int ransom_counter_allowlisted = has_ransom_counter_allowlist_indicator(r);
  int ransom_signer_allowlisted = has_ransom_signer_allowlist_indicator(r);
  int ransom_burst = has_ransom_burst_indicator(r);
  int extension_changed = has_extension_change_indicator(r);
  int high_content_entropy = has_high_content_entropy_indicator(r);
  int ransom_recovery = has_ransom_recovery_tamper_indicator(r);
  int ransom_note = has_ransom_note_indicator(r);
  int ransom_note_burst = has_ransom_note_burst_indicator(r);
  int security_kill = has_security_product_kill_indicator(r);
  int webshell_semantic = has_webshell_semantic_indicator(r);
  int persistence = has_persistence_change_indicator(r);
  int silverfox = has_silverfox_indicator(r);
  int64_t now_ns = r->event_time_ns > 0 ? r->event_time_ns : 0;
  const EdrProcessContextSlot *ctx = process_context_lookup(r, now_ns);
  const EdrProcessContextSlot *parent_ctx = r->ppid ? process_context_lookup_pid(r->ppid, now_ns) : NULL;
  uint32_t tree_root_pid = ransomware_tree_root_pid(r, parent_ctx);
  int chain_candidate_score = ransom_chain_candidate_threshold();
  int chain_p0_score = ransom_chain_p0_threshold();
  EdrRansomChainSignal ransom_chain =
      ransom_chain_signal(r, ctx, parent_ctx, ransom_recovery, ransom_burst, ransom_note, ransom_note_burst, security_kill,
                          d->has_remote ? 1 : 0, has_lolbin_script_indicator(r), script_sensor,
                          has_exfil_indicator(r));
  char note_count_buf[32];
  char file_rate_buf[32];
  char ext_burst_buf[32];
  char dir_burst_buf[32];
  char entropy_delta_buf[32];
  char high_entropy_ratio_buf[32];
  char path_entropy_buf[32];
  char content_entropy_buf[32];
  char content_sample_bytes_buf[32];
  char old_ext_buf[32];
  char new_ext_buf[32];
  char signer_buf[160];
  char signature_status_buf[96];
  char ransomware_kind_buf[64];
  char ransomware_severity_buf[16];
  detail_value(r->script_snippet, "ransom_note_count", note_count_buf, sizeof(note_count_buf));
  detail_value(r->script_snippet, "file_rate", file_rate_buf, sizeof(file_rate_buf));
  detail_value(r->script_snippet, "ext_burst", ext_burst_buf, sizeof(ext_burst_buf));
  detail_value(r->script_snippet, "dir_burst", dir_burst_buf, sizeof(dir_burst_buf));
  detail_value(r->script_snippet, "entropy_delta", entropy_delta_buf, sizeof(entropy_delta_buf));
  detail_value(r->script_snippet, "high_entropy_ratio", high_entropy_ratio_buf, sizeof(high_entropy_ratio_buf));
  detail_value(r->script_snippet, "path_entropy", path_entropy_buf, sizeof(path_entropy_buf));
  detail_value(r->script_snippet, "content_entropy", content_entropy_buf, sizeof(content_entropy_buf));
  detail_value(r->script_snippet, "content_sample_bytes", content_sample_bytes_buf, sizeof(content_sample_bytes_buf));
  detail_value(r->script_snippet, "old_ext", old_ext_buf, sizeof(old_ext_buf));
  detail_value(r->script_snippet, "new_ext", new_ext_buf, sizeof(new_ext_buf));
  detail_value(r->script_snippet, "signer", signer_buf, sizeof(signer_buf));
  detail_value(r->script_snippet, "signature_status", signature_status_buf, sizeof(signature_status_buf));
  detail_value(r->script_snippet, "ransomware_kind", ransomware_kind_buf, sizeof(ransomware_kind_buf));
  detail_value(r->script_snippet, "ransomware_severity", ransomware_severity_buf, sizeof(ransomware_severity_buf));
  int rmm_policy = rmm_enterprise_policy_match(r);
  int fp_feedback = false_positive_feedback_match(r);
  const char *rmm_policy_version = getenv("EDR_DETECTION_RMM_POLICY_VERSION");
  const char *fp_policy_version = getenv("EDR_DETECTION_FP_POLICY_VERSION");
  detail_value(r->script_snippet, "detector", evidence_detector, sizeof(evidence_detector));
  detail_value(r->script_snippet, "rule", evidence_rule, sizeof(evidence_rule));
  detail_value(r->script_snippet, "score", evidence_score, sizeof(evidence_score));
  detail_value(r->script_snippet, "proto", evidence_proto, sizeof(evidence_proto));
  detail_value(r->script_snippet, "mitre", evidence_mitre, sizeof(evidence_mitre));
  detail_value(r->script_snippet, "forensic", evidence_forensic, sizeof(evidence_forensic));
  json_cat(r->detection_context, sizeof(r->detection_context),
           "{\"engine\":");
  json_str(r->detection_context, sizeof(r->detection_context), engine_name(r), 48u);
  json_cat(r->detection_context, sizeof(r->detection_context),
           ",\"rule_id\":\"agent_decision_v1\",\"confidence\":%.3f,\"suppressed\":%s,\"reason\":",
           d->confidence, d->suppress ? "true" : "false");
  json_str(r->detection_context, sizeof(r->detection_context), d->reason, 220u);
  json_cat(r->detection_context, sizeof(r->detection_context),
           ",\"event_quality\":{\"score\":%u,\"suppression_score\":%u,\"selection_action\":",
           (unsigned)d->event_quality_score, (unsigned)d->suppression_score);
  json_str(r->detection_context, sizeof(r->detection_context), d->selection_action, 16u);
  json_cat(r->detection_context, sizeof(r->detection_context), ",\"signal_reasons\":");
  json_reason_array(r->detection_context, sizeof(r->detection_context), d->signal_reasons);
  json_cat(r->detection_context, sizeof(r->detection_context), ",\"noise_reasons\":");
  json_reason_array(r->detection_context, sizeof(r->detection_context), d->noise_reasons);
  json_cat(r->detection_context, sizeof(r->detection_context), "}");
  json_cat(r->detection_context, sizeof(r->detection_context),
           ",\"process\":{\"pid\":%u,\"name\":", r->pid);
  json_str(r->detection_context, sizeof(r->detection_context), r->process_name, 96u);
  json_cat(r->detection_context, sizeof(r->detection_context), ",\"path\":");
  json_str(r->detection_context, sizeof(r->detection_context), r->exe_path, 220u);
  json_cat(r->detection_context, sizeof(r->detection_context), ",\"cmdline\":");
  json_str(r->detection_context, sizeof(r->detection_context), r->cmdline, 360u);
  json_cat(r->detection_context, sizeof(r->detection_context),
           ",\"parent_pid\":%u,\"parent_name\":", r->ppid);
  json_str(r->detection_context, sizeof(r->detection_context), r->parent_name, 96u);
  json_cat(r->detection_context, sizeof(r->detection_context), "},\"file\":{\"path\":");
  json_str(r->detection_context, sizeof(r->detection_context), r->file_path[0] ? r->file_path : r->exe_path, 220u);
  json_cat(r->detection_context, sizeof(r->detection_context), ",\"sha256\":");
  json_str(r->detection_context, sizeof(r->detection_context), r->exe_hash, 80u);
  json_cat(r->detection_context, sizeof(r->detection_context),
           ",\"old_ext\":");
  json_str(r->detection_context, sizeof(r->detection_context), old_ext_buf, 24u);
  json_cat(r->detection_context, sizeof(r->detection_context), ",\"new_ext\":");
  json_str(r->detection_context, sizeof(r->detection_context), new_ext_buf, 24u);
  json_cat(r->detection_context, sizeof(r->detection_context),
           ",\"extension_changed\":%s,\"content_entropy\":%.2f,\"content_sample_bytes\":%ld,"
           "\"path_entropy\":%.2f,\"signed\":null,\"signature_trust\":{\"status\":",
           extension_changed ? "true" : "false",
           content_entropy_buf[0] ? strtod(content_entropy_buf, NULL) : 0.0,
           content_sample_bytes_buf[0] ? strtol(content_sample_bytes_buf, NULL, 10) : 0L,
           path_entropy_buf[0] ? strtod(path_entropy_buf, NULL) : 0.0);
  json_str(r->detection_context, sizeof(r->detection_context),
           signature_status_buf[0] ? signature_status_buf : (r->cert_revoked_ancestor ? "revoked_ancestor" : "unknown"),
           80u);
  json_cat(r->detection_context, sizeof(r->detection_context), ",\"signer\":");
  json_str(r->detection_context, sizeof(r->detection_context), signer_buf, 150u);
  json_cat(r->detection_context, sizeof(r->detection_context),
           ",\"signer_allowlisted\":%s,\"cert_revoked_ancestor\":%s}},\"network\":{\"remote_url\":",
           ransom_signer_allowlisted ? "true" : "false", r->cert_revoked_ancestor ? "true" : "false");
  json_str(r->detection_context, sizeof(r->detection_context), r->dns_query, 180u);
  json_cat(r->detection_context, sizeof(r->detection_context), ",\"remote_ip\":");
  json_str(r->detection_context, sizeof(r->detection_context), r->net_dst, 64u);
  json_cat(r->detection_context, sizeof(r->detection_context),
           ",\"dst_port\":%u},\"registry\":{\"key\":",
           r->net_dport);
  json_str(r->detection_context, sizeof(r->detection_context), r->reg_key_path, 220u);
  json_cat(r->detection_context, sizeof(r->detection_context), ",\"value_name\":");
  json_str(r->detection_context, sizeof(r->detection_context), r->reg_value_name, 120u);
  json_cat(r->detection_context, sizeof(r->detection_context), ",\"value_data\":");
  json_str(r->detection_context, sizeof(r->detection_context), r->reg_value_data, 260u);
  json_cat(r->detection_context, sizeof(r->detection_context), ",\"op\":");
  json_str(r->detection_context, sizeof(r->detection_context), r->reg_op, 48u);
  json_cat(r->detection_context, sizeof(r->detection_context),
           "},\"signals\":{\"remote\":%s,\"suspicious_parent\":%s,\"allowlisted_path\":%s,"
           "\"cert_revoked_ancestor\":%s,\"script_sensor\":%s,\"tls_anomaly\":%s,"
           "\"ransom_behavior\":%s,\"ransom_canary\":%s,\"ransom_counter_allowlisted\":%s,"
           "\"ransom_signer_allowlisted\":%s,\"extension_changed\":%s,\"high_content_entropy\":%s,"
           "\"ransom_recovery_tamper\":%s,\"ransom_note\":%s,\"ransom_note_burst\":%s,"
           "\"security_product_kill\":%s,\"ransom_chain_score\":%d,"
           "\"webshell_semantic\":%s,\"persistence_change\":%s,"
           "\"silverfox_attack_chain\":%s,\"rmm_policy_match\":%s,\"false_positive_feedback\":%s,"
           "\"process_context\":%s},",
           d->has_remote ? "true" : "false", d->suspicious_parent ? "true" : "false",
           d->allowlisted_path ? "true" : "false", r->cert_revoked_ancestor ? "true" : "false",
           script_sensor ? "true" : "false", tls_anomaly ? "true" : "false",
           ransom_burst ? "true" : "false", ransom_canary ? "true" : "false",
           ransom_counter_allowlisted ? "true" : "false", ransom_signer_allowlisted ? "true" : "false",
           extension_changed ? "true" : "false", high_content_entropy ? "true" : "false",
           ransom_recovery ? "true" : "false",
           ransom_note ? "true" : "false", ransom_note_burst ? "true" : "false",
           security_kill ? "true" : "false",
           ransom_chain.score, webshell_semantic ? "true" : "false",
           persistence ? "true" : "false", silverfox ? "true" : "false", rmm_policy ? "true" : "false",
           fp_feedback ? "true" : "false",
           d->context_correlated ? "true" : "false");
  json_cat(r->detection_context, sizeof(r->detection_context),
           "\"ransom_control\":{\"version\":");
  json_str(r->detection_context, sizeof(r->detection_context), EDR_RANSOM_CONTROL_VERSION, 40u);
  json_cat(r->detection_context, sizeof(r->detection_context),
           ",\"phase\":\"%s\",\"kind\":",
           ransom_canary ? "p0" : (ransom_chain.score >= chain_p0_score ? "p0" :
           (ransom_chain.score >= chain_candidate_score ? "candidate" :
            (ransom_note ? "single_note_observed" : "baseline"))));
  if (ransomware_kind_buf[0]) {
    json_str(r->detection_context, sizeof(r->detection_context), ransomware_kind_buf, 64u);
  } else if (ransom_canary) {
    json_str(r->detection_context, sizeof(r->detection_context), "DETERMINISTIC_ENCRYPTION", 64u);
  } else if (ransom_chain.score >= chain_p0_score) {
    json_str(r->detection_context, sizeof(r->detection_context), "ENCRYPTION_CONFIRMED", 64u);
  } else if (ransom_burst || ransom_chain.score >= chain_candidate_score) {
    json_str(r->detection_context, sizeof(r->detection_context), "ENCRYPTION_SUSPECTED", 64u);
  } else {
    json_str(r->detection_context, sizeof(r->detection_context), "", 64u);
  }
  json_cat(r->detection_context, sizeof(r->detection_context),
           ",\"severity\":%ld,\"canary\":%s,\"allowlisted\":%s,\"counter_suppressed\":%s,"
           "\"file_rate_per_min\":%.0f,\"ext_count\":%ld,\"dir_count\":%ld,"
           "\"extension_changed\":%s,\"old_ext\":",
           ransomware_severity_buf[0] ? strtol(ransomware_severity_buf, NULL, 10) :
           (ransom_canary || ransom_chain.score >= chain_p0_score ? 4L :
            (ransom_burst || ransom_chain.score >= chain_candidate_score ? 3L : 0L)),
           ransom_canary ? "true" : "false",
           ransom_counter_allowlisted ? "true" : "false",
           ransom_counter_allowlisted ? "true" : "false",
           file_rate_buf[0] ? strtod(file_rate_buf, NULL) : 0.0,
           ext_burst_buf[0] ? strtol(ext_burst_buf, NULL, 10) : 0L,
           dir_burst_buf[0] ? strtol(dir_burst_buf, NULL, 10) : 0L,
           extension_changed ? "true" : "false");
  json_str(r->detection_context, sizeof(r->detection_context), old_ext_buf, 24u);
  json_cat(r->detection_context, sizeof(r->detection_context), ",\"new_ext\":");
  json_str(r->detection_context, sizeof(r->detection_context), new_ext_buf, 24u);
  json_cat(r->detection_context, sizeof(r->detection_context),
           ",\"entropy_delta\":%.2f,\"high_entropy_ratio\":%.2f,"
           "\"content_entropy\":%.2f,\"content_sample_bytes\":%ld,\"path_entropy\":%.2f,"
           "\"signer_allowlisted\":%s,\"tree_root_pid\":%u,"
           "\"note_count\":%ld,\"note_min_files\":%d,"
           "\"note_window_s\":%d,\"candidate_score\":%d,\"p0_score\":%d,"
           "\"direct_emit_single_note\":false,\"attribution_key\":\"tree:%u\"},",
           entropy_delta_buf[0] ? strtod(entropy_delta_buf, NULL) : 0.0,
           high_entropy_ratio_buf[0] ? strtod(high_entropy_ratio_buf, NULL) : 0.0,
           content_entropy_buf[0] ? strtod(content_entropy_buf, NULL) : 0.0,
           content_sample_bytes_buf[0] ? strtol(content_sample_bytes_buf, NULL, 10) : 0L,
           path_entropy_buf[0] ? strtod(path_entropy_buf, NULL) : 0.0,
           ransom_signer_allowlisted ? "true" : "false",
           (unsigned)tree_root_pid,
           note_count_buf[0] ? strtol(note_count_buf, NULL, 10) : 0L,
           ransom_note_policy_min_files(), ransom_note_policy_window_s(),
           chain_candidate_score, chain_p0_score, (unsigned)tree_root_pid);
  if (d->suppress) {
    float before = d->confidence_before_suppression > 0.0f ? d->confidence_before_suppression : d->confidence;
    json_cat(r->detection_context, sizeof(r->detection_context),
             "\"suppression\":{\"matched\":true,\"reason\":");
    json_str(r->detection_context, sizeof(r->detection_context), d->suppression_reason, 96u);
    json_cat(r->detection_context, sizeof(r->detection_context),
             ",\"confidence_before\":%.3f,\"confidence_after\":%.3f,\"policy_version\":",
             before, d->confidence);
    json_str(r->detection_context, sizeof(r->detection_context), d->suppression_policy_version, 64u);
    json_cat(r->detection_context, sizeof(r->detection_context), ",\"policy_source\":");
    json_str(r->detection_context, sizeof(r->detection_context), getenv("EDR_DETECTION_POLICY_SOURCE"), 64u);
    json_cat(r->detection_context, sizeof(r->detection_context), ",\"audit_id\":");
    json_str(r->detection_context, sizeof(r->detection_context), getenv("EDR_DETECTION_POLICY_AUDIT_ID"), 96u);
    json_cat(r->detection_context, sizeof(r->detection_context),
             ",\"hit_count\":%u,\"rollback_available\":%s,\"rollback_version\":",
             d->suppression_hit_count, d->suppression_rollback_version[0] ? "true" : "false");
    json_str(r->detection_context, sizeof(r->detection_context), d->suppression_rollback_version, 64u);
    json_cat(r->detection_context, sizeof(r->detection_context), "},");
  }
  json_cat(r->detection_context, sizeof(r->detection_context), "\"detection_profile\":{\"name\":");
  json_str(r->detection_context, sizeof(r->detection_context), t ? t->profile_name : "", 48u);
  json_cat(r->detection_context, sizeof(r->detection_context), ",\"rmm_policy_version\":");
  json_str(r->detection_context, sizeof(r->detection_context), rmm_policy_version ? rmm_policy_version : "", 64u);
  json_cat(r->detection_context, sizeof(r->detection_context), ",\"false_positive_policy_version\":");
  json_str(r->detection_context, sizeof(r->detection_context), fp_policy_version ? fp_policy_version : "", 64u);
  json_cat(r->detection_context, sizeof(r->detection_context),
           "},\"detection_trigger\":{\"pmfe_scan\":%s,\"single_process_minidump\":%s,"
           "\"targeted_files\":%s,\"ioc_lookup\":%s,\"reason\":",
           (t && t->pmfe_scan) ? "true" : "false",
           (t && t->single_process_minidump) ? "true" : "false",
           (t && t->targeted_files) ? "true" : "false",
           (t && t->ioc_lookup) ? "true" : "false");
  json_str(r->detection_context, sizeof(r->detection_context), t ? t->reason : "", 180u);
  json_cat(r->detection_context, sizeof(r->detection_context),
           "},\"engine_evidence\":{\"pmfe_snapshot\":");
  json_str(r->detection_context, sizeof(r->detection_context), r->pmfe_snapshot, 360u);
  json_cat(r->detection_context, sizeof(r->detection_context), ",\"detector\":");
  json_str(r->detection_context, sizeof(r->detection_context), evidence_detector, 48u);
  json_cat(r->detection_context, sizeof(r->detection_context), ",\"rule\":");
  json_str(r->detection_context, sizeof(r->detection_context), evidence_rule, 96u);
  json_cat(r->detection_context, sizeof(r->detection_context), ",\"score\":");
  json_str(r->detection_context, sizeof(r->detection_context), evidence_score, 32u);
  json_cat(r->detection_context, sizeof(r->detection_context), ",\"proto\":");
  json_str(r->detection_context, sizeof(r->detection_context), evidence_proto, 48u);
  json_cat(r->detection_context, sizeof(r->detection_context), ",\"mitre\":");
  json_str(r->detection_context, sizeof(r->detection_context), evidence_mitre, 32u);
  json_cat(r->detection_context, sizeof(r->detection_context), ",\"forensic\":");
  json_str(r->detection_context, sizeof(r->detection_context), evidence_forensic, 32u);
  json_cat(r->detection_context, sizeof(r->detection_context), ",\"detail\":");
  json_str(r->detection_context, sizeof(r->detection_context), r->script_snippet, 420u);
  json_cat(r->detection_context, sizeof(r->detection_context), "},\"recommended_forensics\":[");
  build_recommended_forensics(r->detection_context, sizeof(r->detection_context), r, d, t);
  json_cat(r->detection_context, sizeof(r->detection_context), "]}");
}

void edr_detection_decision_evaluate(EdrBehaviorRecord *r, EdrDetectionDecision *out) {
  if (!out) {
    return;
  }
  memset(out, 0, sizeof(*out));
  if (!r) {
    out->drop = 1u;
    return;
  }

  int remote = has_remote_indicator(r);
  int script = has_lolbin_script_indicator(r);
  int lolbin = is_lolbin(r->process_name[0] ? r->process_name : r->exe_path);
  int parent = suspicious_parent(r);
  int mgmt = is_management_tool(r);
  int allow = allowlisted_path(r);
  int cred = has_credential_dump_indicator(r);
  int ransom = has_ransom_recovery_tamper_indicator(r);
  int exfil = has_exfil_indicator(r);
  int inject = is_injection_event(r);
  int script_sensor = has_script_sensor_indicator(r);
  int tls_anomaly = has_tls_anomaly_indicator(r);
  int ransom_canary = has_ransom_canary_indicator(r);
  int ransom_burst = has_ransom_burst_indicator(r);
  int ransom_note = has_ransom_note_indicator(r);
  int ransom_note_burst = has_ransom_note_burst_indicator(r);
  int security_kill = has_security_product_kill_indicator(r);
  int webshell_semantic = has_webshell_semantic_indicator(r);
  int persistence = has_persistence_change_indicator(r);
  int silverfox = has_silverfox_indicator(r);
  int rmm_policy = rmm_enterprise_policy_match(r);
  int fp_feedback = false_positive_feedback_match(r);
  int64_t now_ns = record_time_or_seq(r);
  const EdrProcessContextSlot *ctx = process_context_lookup(r, now_ns);
  const EdrProcessContextSlot *parent_ctx = r->ppid ? process_context_lookup_pid(r->ppid, now_ns) : NULL;
  int chain_candidate_score = ransom_chain_candidate_threshold();
  int chain_p0_score = ransom_chain_p0_threshold();
  EdrRansomChainSignal ransom_chain =
      ransom_chain_signal(r, ctx, parent_ctx, ransom, ransom_burst, ransom_note, ransom_note_burst, security_kill, remote,
                          script, script_sensor, exfil);
  int context_correlated = 0;
  if (decision_suppress_ransom_file_signal(r)) {
    ransom_burst = 0;
    ransom_note = 0;
    ransom_note_burst = 0;
    memset(&ransom_chain, 0, sizeof(ransom_chain));
  }

  float score = 0.20f;
  if (r->type == EDR_EVENT_PROTOCOL_SHELLCODE) {
    score = 0.88f;
    add_reason(out->reason, sizeof(out->reason), "shellcode_signal");
  } else if (r->type == EDR_EVENT_WEBSHELL_DETECTED) {
    score = 0.82f;
    add_reason(out->reason, sizeof(out->reason), "webshell_signal");
  } else if (r->type == EDR_EVENT_PMFE_SCAN_RESULT) {
    score = 0.72f;
    add_reason(out->reason, sizeof(out->reason), "pmfe_memory_evidence");
  } else if (inject) {
    score = 0.74f;
    add_reason(out->reason, sizeof(out->reason), "process_injection_signal");
  } else if (lolbin) {
    score = 0.34f;
    add_reason(out->reason, sizeof(out->reason), "lolbin");
  }

  if (remote) {
    score += 0.22f;
    add_reason(out->reason, sizeof(out->reason), "remote_indicator");
  }
  if (script) {
    score += 0.18f;
    add_reason(out->reason, sizeof(out->reason), "script_or_encoded_payload");
  }
  if (script_sensor && script) {
    score += 0.14f;
    add_reason(out->reason, sizeof(out->reason), "script_sensor_content");
  } else if (script_sensor) {
    score += 0.08f;
    add_reason(out->reason, sizeof(out->reason), "script_sensor_observed");
  }
  if (tls_anomaly) {
    score += remote ? 0.18f : 0.12f;
    add_reason(out->reason, sizeof(out->reason), "tls_ja3_sni_cert_anomaly");
  }
  if (parent) {
    score += 0.12f;
    add_reason(out->reason, sizeof(out->reason), "suspicious_parent_or_user_path");
  }
  if (r->cert_revoked_ancestor) {
    score += 0.12f;
    add_reason(out->reason, sizeof(out->reason), "revoked_certificate_chain");
  }
  if (cred) {
    score += 0.26f;
    add_reason(out->reason, sizeof(out->reason), "credential_dump_indicator");
  }
  if (ransom) {
    score += 0.24f;
    add_reason(out->reason, sizeof(out->reason), "ransom_recovery_tamper");
  }
  if (ransom_canary) {
    score = score < 0.95f ? 0.95f : score;
    context_correlated = 1;
    add_reason(out->reason, sizeof(out->reason), "ransom_canary_deterministic_encryption");
  }
  if (ransom_burst) {
    score += ransom ? 0.18f : 0.28f;
    add_reason(out->reason, sizeof(out->reason), "ransom_behavior_counter");
  }
  if (ransom_note) {
    score += ransom_note_burst ? 0.20f : (ransom_burst ? 0.08f : 0.10f);
    add_reason(out->reason, sizeof(out->reason),
               ransom_note_burst ? "ransom_note_burst" : "ransom_note_indicator");
  }
  if (security_kill) {
    score += 0.20f;
    add_reason(out->reason, sizeof(out->reason), "security_product_termination");
  }
  if (ransom_chain.score >= chain_p0_score) {
    if (score < 0.86f) {
      score = 0.86f;
    }
    context_correlated = 1;
    add_reason(out->reason, sizeof(out->reason), "ransom_kill_chain_p0");
  } else if (ransom_chain.score >= chain_candidate_score) {
    score += 0.18f;
    context_correlated = 1;
    add_reason(out->reason, sizeof(out->reason), "ransom_kill_chain_candidate");
  }
  if (exfil) {
    score += 0.16f;
    add_reason(out->reason, sizeof(out->reason), "exfil_staging_or_upload");
  }
  if (silverfox) {
    score += 0.46f;
    add_reason(out->reason, sizeof(out->reason), "silverfox_attack_chain_indicator");
  }
  if (persistence) {
    score += (remote || script || script_sensor || parent) ? 0.30f : 0.22f;
    add_reason(out->reason, sizeof(out->reason), "persistence_change_indicator");
  }
  if (webshell_semantic && r->type != EDR_EVENT_WEBSHELL_DETECTED) {
    score += 0.38f;
    add_reason(out->reason, sizeof(out->reason), "webshell_ast_token_semantic");
  }
  if (ctx && ctx->events > 0u) {
    if ((ctx->remote && (script || script_sensor)) || (remote && ctx->script_sensor)) {
      score += 0.10f;
      context_correlated = 1;
      add_reason(out->reason, sizeof(out->reason), "process_window_remote_script");
    }
    if ((ctx->tls_anomaly && remote) || (tls_anomaly && ctx->remote)) {
      score += 0.08f;
      context_correlated = 1;
      add_reason(out->reason, sizeof(out->reason), "process_window_tls_remote");
    }
    if ((ctx->ransom_behavior && ransom) || (ransom_burst && ctx->remote)) {
      score += 0.10f;
      context_correlated = 1;
      add_reason(out->reason, sizeof(out->reason), "process_window_ransom_chain");
    }
    if ((ctx->webshell_semantic && remote) || (webshell_semantic && ctx->remote)) {
      score += 0.10f;
      context_correlated = 1;
      add_reason(out->reason, sizeof(out->reason), "process_window_webshell_network");
    }
    if ((ctx->credential && inject) || (cred && ctx->injection) || (ctx->pmfe && inject) || (ctx->shellcode && remote)) {
      score += 0.12f;
      context_correlated = 1;
      add_reason(out->reason, sizeof(out->reason), "process_window_memory_chain");
    }
    if ((ctx->persistence && (remote || script || script_sensor)) ||
        (persistence && (ctx->remote || ctx->script_sensor))) {
      score += 0.10f;
      context_correlated = 1;
      add_reason(out->reason, sizeof(out->reason), "process_window_persistence_chain");
    }
  }
  if (parent_ctx && parent_ctx->events > 0u) {
    if ((parent_ctx->remote || parent_ctx->script_sensor) && (lolbin || script || script_sensor || remote)) {
      score += lolbin ? 0.24f : 0.10f;
      context_correlated = 1;
      add_reason(out->reason, sizeof(out->reason), "process_tree_parent_remote_script");
    }
    if ((parent_ctx->credential || parent_ctx->injection || parent_ctx->pmfe) && (inject || cred || r->type == EDR_EVENT_PMFE_SCAN_RESULT)) {
      score += 0.12f;
      context_correlated = 1;
      add_reason(out->reason, sizeof(out->reason), "process_tree_parent_memory_chain");
    }
    if ((parent_ctx->webshell_semantic || parent_ctx->ransom_behavior) && (remote || script || tls_anomaly)) {
      score += 0.08f;
      context_correlated = 1;
      add_reason(out->reason, sizeof(out->reason), "process_tree_parent_semantic_chain");
    }
  }

  if (fp_feedback && !cred && !ransom && !ransom_burst && !ransom_note && !security_kill && !exfil && !inject && !persistence && !silverfox &&
      r->type != EDR_EVENT_PROTOCOL_SHELLCODE && r->type != EDR_EVENT_WEBSHELL_DETECTED &&
      r->type != EDR_EVENT_PMFE_SCAN_RESULT) {
    set_suppression(out, score, "false_positive_feedback_policy", "EDR_DETECTION_FP_POLICY_VERSION");
    score -= remote ? 0.16f : 0.24f;
    add_reason(out->reason, sizeof(out->reason), "false_positive_feedback_policy");
  }
  if (mgmt && !remote && !script) {
    set_suppression(out, score, "management_tool_noise", "EDR_DETECTION_POLICY_VERSION");
    score -= 0.22f;
    add_reason(out->reason, sizeof(out->reason), "management_tool_noise");
  }
  if (mgmt && rmm_policy && !script && !parent && !cred && !ransom && !ransom_burst && !ransom_note && !security_kill && !exfil && !inject &&
      !silverfox &&
      !r->cert_revoked_ancestor) {
    set_suppression(out, score, "rmm_enterprise_allowlist_policy", "EDR_DETECTION_RMM_POLICY_VERSION");
    score -= remote ? 0.18f : 0.28f;
    add_reason(out->reason, sizeof(out->reason), "rmm_enterprise_allowlist_policy");
  }
  if (allow && !remote && !script && !parent && !silverfox && !ransom_canary && !ransom_burst &&
      !ransom_note && !security_kill && r->type != EDR_EVENT_PROTOCOL_SHELLCODE &&
      r->type != EDR_EVENT_WEBSHELL_DETECTED) {
    set_suppression(out, score, "allowlisted_path", "EDR_DETECTION_POLICY_VERSION");
    score -= 0.18f;
    add_reason(out->reason, sizeof(out->reason), "allowlisted_path");
  }

  /* 二期条件化 suppression：仅在非高危信号时应用，保留同进程其它形态的告警能力。 */
  if (!cred && !ransom && !ransom_canary && !ransom_burst && !ransom_note && !security_kill &&
      !exfil && !inject && !persistence && !silverfox && !r->cert_revoked_ancestor &&
      r->type != EDR_EVENT_PROTOCOL_SHELLCODE && r->type != EDR_EVENT_WEBSHELL_DETECTED &&
      r->type != EDR_EVENT_PMFE_SCAN_RESULT) {
    char cond_reason[96] = "";
    int cond_action = 0;
    if (conditional_suppression_match(r, cond_reason, sizeof(cond_reason), &cond_action)) {
      set_suppression(out, score, cond_reason[0] ? cond_reason : "conditional_suppression",
                      "EDR_DETECTION_FP_POLICY_VERSION");
      if (cond_action == 1) {
        score = 0.f;
        out->drop = 1u;
      } else {
        score -= remote ? 0.20f : 0.30f;
      }
      add_reason(out->reason, sizeof(out->reason), "conditional_suppression");
    }
  }

  if (lolbin && !context_correlated && !remote && !script && !script_sensor && !tls_anomaly && !persistence && !silverfox && !cred && !ransom &&
      !ransom_burst && !ransom_note && !security_kill && !exfil && !inject) {
    set_suppression(out, score, "lolbin_without_combo_condition", "EDR_DETECTION_POLICY_VERSION");
    score = score > 0.32f ? 0.32f : score;
    add_reason(out->reason, sizeof(out->reason), "lolbin_without_combo_condition");
  }

  if (score < 0.f) {
    score = 0.f;
  }
  if (score > 1.f) {
    score = 1.f;
  }
  out->confidence = score;
  out->has_remote = remote ? 1u : 0u;
  out->suspicious_parent = parent ? 1u : 0u;
  out->allowlisted_path = allow ? 1u : 0u;
  out->context_correlated = context_correlated ? 1u : 0u;
  out->persistence_change = persistence ? 1u : 0u;
  if (ransom_canary && r->priority > 0u) {
    r->priority = 0u;
  } else if (ransom_chain.score >= chain_p0_score && r->priority > 0u) {
    r->priority = 0u;
  } else if (ransom_chain.score >= chain_candidate_score && r->priority > 1u) {
    r->priority = 1u;
  }
  if (out->reason[0] == '\0') {
    snprintf(out->reason, sizeof(out->reason), "%s", "baseline");
  }
  if (out->suppress && score < 0.25f && r->priority != 0u) {
    out->drop = 1u;
  }

  compute_event_quality(r, out);

  {
    EdrDetectionTrigger trigger;
    edr_detection_trigger_evaluate(r, out, &trigger);
    out->trigger_pmfe_scan = trigger.pmfe_scan;
    out->trigger_single_process_minidump = trigger.single_process_minidump;
    snprintf(out->detection_profile, sizeof(out->detection_profile), "%s", trigger.profile_name);
    snprintf(out->trigger_reason, sizeof(out->trigger_reason), "%s", trigger.reason);
    build_detection_context(r, out, &trigger);
  }
  if (out->suppress && r->priority > 0u) {
    r->priority = 2u;
  }
  process_context_update(r, now_ns, remote, script_sensor, tls_anomaly, ransom_burst, ransom, ransom_note,
                         security_kill, webshell_semantic, cred, inject, persistence);
}
