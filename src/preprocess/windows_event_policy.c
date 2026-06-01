#include "edr/windows_event_policy.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#define EDR_EVENT_FILTER_VERSION_DEFAULT "agent-event-filter-v1"

static EdrWindowsEventFilterConfig g_event_filter_cfg = {
    1u, 1u, 1u, 1u, 1u, EDR_EVENT_FILTER_VERSION_DEFAULT,
};
static uint64_t g_event_filter_evaluated = 0u;
static uint64_t g_event_filter_dropped = 0u;
static uint64_t g_event_filter_agent_internal = 0u;
static uint64_t g_event_filter_low_value_process = 0u;
static uint64_t g_event_filter_low_value_suffix = 0u;
static uint64_t g_event_filter_temp_xml = 0u;

static void reset_event_filter_counters(void) {
  g_event_filter_evaluated = 0u;
  g_event_filter_dropped = 0u;
  g_event_filter_agent_internal = 0u;
  g_event_filter_low_value_process = 0u;
  g_event_filter_low_value_suffix = 0u;
  g_event_filter_temp_xml = 0u;
}

void edr_windows_event_policy_configure(const EdrWindowsEventFilterConfig *cfg) {
  memset(&g_event_filter_cfg, 0, sizeof(g_event_filter_cfg));
  if (cfg) {
    g_event_filter_cfg.enabled = cfg->enabled ? 1u : 0u;
    g_event_filter_cfg.agent_internal_forensic = cfg->agent_internal_forensic ? 1u : 0u;
    g_event_filter_cfg.low_value_file_process = cfg->low_value_file_process ? 1u : 0u;
    g_event_filter_cfg.low_value_file_suffix = cfg->low_value_file_suffix ? 1u : 0u;
    g_event_filter_cfg.temp_xml = cfg->temp_xml ? 1u : 0u;
    snprintf(g_event_filter_cfg.version, sizeof(g_event_filter_cfg.version), "%s",
             cfg->version[0] ? cfg->version : EDR_EVENT_FILTER_VERSION_DEFAULT);
  } else {
    g_event_filter_cfg.enabled = 1u;
    g_event_filter_cfg.agent_internal_forensic = 1u;
    g_event_filter_cfg.low_value_file_process = 1u;
    g_event_filter_cfg.low_value_file_suffix = 1u;
    g_event_filter_cfg.temp_xml = 1u;
    snprintf(g_event_filter_cfg.version, sizeof(g_event_filter_cfg.version), "%s",
             EDR_EVENT_FILTER_VERSION_DEFAULT);
  }
  reset_event_filter_counters();
}

void edr_windows_event_policy_get_status(EdrWindowsEventFilterStatus *out) {
  if (!out) {
    return;
  }
  memset(out, 0, sizeof(*out));
  out->enabled = g_event_filter_cfg.enabled;
  snprintf(out->version, sizeof(out->version), "%s",
           g_event_filter_cfg.version[0] ? g_event_filter_cfg.version
                                         : EDR_EVENT_FILTER_VERSION_DEFAULT);
  out->evaluated = g_event_filter_evaluated;
  out->dropped = g_event_filter_dropped;
  out->agent_internal_forensic = g_event_filter_agent_internal;
  out->low_value_file_process = g_event_filter_low_value_process;
  out->low_value_file_suffix = g_event_filter_low_value_suffix;
  out->temp_xml = g_event_filter_temp_xml;
}

static int is_file_event(EdrEventType t) {
  return t == EDR_EVENT_FILE_CREATE || t == EDR_EVENT_FILE_WRITE ||
         t == EDR_EVENT_FILE_DELETE || t == EDR_EVENT_FILE_RENAME ||
         t == EDR_EVENT_FILE_PERMISSION_CHANGE || t == EDR_EVENT_FILE_READ;
}

static int is_registry_event(EdrEventType t) {
  return t == EDR_EVENT_REG_CREATE_KEY || t == EDR_EVENT_REG_SET_VALUE ||
         t == EDR_EVENT_REG_DELETE_KEY;
}

static char fold_char(char c) {
  if (c == '/') {
    c = '\\';
  }
  return (char)tolower((unsigned char)c);
}

static int has_ci_path(const char *hay, const char *needle) {
  if (!needle || !needle[0]) {
    return 1;
  }
  if (!hay || !hay[0]) {
    return 0;
  }
  for (; *hay; hay++) {
    const char *a = hay;
    const char *b = needle;
    while (*a && *b && fold_char(*a) == fold_char(*b)) {
      a++;
      b++;
    }
    if (!*b) {
      return 1;
    }
  }
  return 0;
}

static int ends_ci_path(const char *s, const char *suffix) {
  size_t a;
  size_t b;
  if (!s || !suffix) {
    return 0;
  }
  a = strlen(s);
  b = strlen(suffix);
  if (b == 0u || a < b) {
    return 0;
  }
  return has_ci_path(s + (a - b), suffix);
}

static int any_contains(const char *s, const char *const *items, size_t count) {
  for (size_t i = 0; i < count; i++) {
    if (has_ci_path(s, items[i])) {
      return 1;
    }
  }
  return 0;
}

static int any_ends(const char *s, const char *const *items, size_t count) {
  for (size_t i = 0; i < count; i++) {
    if (ends_ci_path(s, items[i])) {
      return 1;
    }
  }
  return 0;
}

static int process_name_is(const EdrBehaviorRecord *r, const char *name) {
  return r && name && name[0] && has_ci_path(r->process_name, name);
}

static void set_reason(EdrWindowsEventPolicy *p, const char *reason);
static void add_tag(EdrWindowsEventPolicy *p, const char *tag);

static void mark_noisy(EdrWindowsEventPolicy *p, const char *reason, const char *tag) {
  p->noisy = 1u;
  p->should_emit = 0u;
  p->should_persist = 0u;
  set_reason(p, reason);
  add_tag(p, tag);
}

static int agent_internal_forensic_activity(const EdrBehaviorRecord *r) {
  if (!r) {
    return 0;
  }
  return has_ci_path(r->file_path, "\\edr_forensic\\") ||
         has_ci_path(r->file_path, "/edr_forensic/") ||
         has_ci_path(r->file_path, "cmd_forensic_") ||
         has_ci_path(r->file_path, "auto-forensic-") ||
         has_ci_path(r->cmdline, "\\edr_forensic\\") ||
         has_ci_path(r->cmdline, "/edr_forensic/") ||
         has_ci_path(r->cmdline, "cmd_forensic_") ||
         has_ci_path(r->cmdline, "auto-forensic-") ||
         has_ci_path(r->script_snippet, "forensic_bundle") ||
         has_ci_path(r->script_snippet, "source=agent_internal") ||
         has_ci_path(r->detection_context, "\"edr_internal\":true") ||
         has_ci_path(r->detection_context, "\"source\":\"agent_internal\"");
}

static int ransom_note_like_path(const char *path) {
  static const char *const note_exts[] = {".txt", ".hta", ".htm", ".html"};
  static const char *const note_tokens[] = {
      "readme", "read_me", "read___me", "decrypt", "encrypted", "recover",
      "restore", "restore-files", "restore_files", "get_your_files_back",
      "help_instruction", "help_to_save_files", "how_to_decrypt", "how_to_back", "how_to_restore",
      "howtobackyourfiles", "howtorestoreyourfiles", "return_files",
      "your_files_back", "use_to_repair", "ransom",
  };
  return any_ends(path, note_exts, sizeof(note_exts) / sizeof(note_exts[0])) &&
         any_contains(path, note_tokens, sizeof(note_tokens) / sizeof(note_tokens[0]));
}

static void set_reason(EdrWindowsEventPolicy *p, const char *reason) {
  if (p && reason && reason[0] && !p->reason[0]) {
    snprintf(p->reason, sizeof(p->reason), "%s", reason);
  }
}

static void add_tag(EdrWindowsEventPolicy *p, const char *tag) {
  size_t n;
  if (!p || !tag || !tag[0]) {
    return;
  }
  if (has_ci_path(p->tags, tag)) {
    return;
  }
  n = strlen(p->tags);
  if (n && n + 1u < sizeof(p->tags)) {
    p->tags[n++] = ',';
    p->tags[n] = '\0';
  }
  (void)snprintf(p->tags + n, sizeof(p->tags) - n, "%s", tag);
}

static void mark_high(EdrWindowsEventPolicy *p, const char *reason, const char *tag) {
  p->high_value = 1u;
  p->should_emit = 1u;
  p->should_persist = 1u;
  set_reason(p, reason);
  add_tag(p, tag);
}

static void mark_suspicious(EdrWindowsEventPolicy *p, const char *reason, const char *tag) {
  mark_high(p, reason, tag);
  p->suspicious = 1u;
}

static void classify_file(const EdrBehaviorRecord *r, EdrWindowsEventPolicy *p) {
  const char *path = r->file_path[0] ? r->file_path : r->exe_path;
  static const char *const web_roots[] = {
      "\\inetpub\\wwwroot\\", "\\wwwroot\\", "\\xampp\\htdocs\\",
      "\\phpstudy\\", "\\tomcat\\webapps\\", "\\nginx\\html\\",
      "\\apache\\htdocs\\", "\\wamp64\\www\\", "\\laragon\\www\\",
  };
  static const char *const script_exts[] = {
      ".php", ".phtml", ".asp", ".aspx", ".ashx", ".asmx", ".jsp",
      ".jspx", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta",
      ".ps1", ".psm1", ".sct", ".cmd", ".bat",
  };
  static const char *const executable_exts[] = {
      ".exe", ".dll", ".scr", ".com", ".msi", ".cpl", ".ocx", ".sys",
  };
  static const char *const user_temp_dirs[] = {
      "\\appdata\\local\\temp\\", "\\appdata\\roaming\\microsoft\\windows\\templates\\",
      "\\windows\\temp\\", "\\users\\public\\", "\\temp\\",
  };
  static const char *const startup_dirs[] = {
      "\\microsoft\\windows\\start menu\\programs\\startup\\",
      "\\windows\\system32\\tasks\\", "\\windows\\tasks\\",
  };
  static const char *const service_driver_dirs[] = {
      "\\windows\\system32\\drivers\\", "\\windows\\system32\\driverstore\\",
      "\\windows\\system32\\spool\\drivers\\", "\\windows\\system32\\tasks\\",
  };
  static const char *const noisy_dirs[] = {
      "\\windows\\prefetch\\", "\\windows\\softwaredistribution\\",
      "\\windows\\logs\\", "\\windows\\temp\\", "\\windows\\system32\\winevt\\logs\\",
      "\\windows\\system32\\config\\systemprofile\\appdata\\local\\",
      "\\programdata\\microsoft\\windows defender\\",
      "\\programdata\\microsoft\\windows\\werm\\",
      "\\appdata\\local\\microsoft\\windows\\inetcache\\",
      "\\appdata\\local\\microsoft\\edge\\user data\\",
      "\\appdata\\local\\google\\chrome\\user data\\",
      "\\appdata\\local\\packages\\", "\\appdata\\local\\crashdumps\\",
      "\\windowsapps\\",
  };
  static const char *const cred_files[] = {
      "\\ntds.dit", "\\config\\sam", "\\config\\system", "\\config\\security",
      "\\config\\software", "lsass.dmp", "\\lsass", "\\sam.save", "\\system.save",
  };
  if (!path || !path[0]) {
    return;
  }
  if (g_event_filter_cfg.agent_internal_forensic && agent_internal_forensic_activity(r)) {
    mark_noisy(p, "agent_internal_forensic", "agent_internal");
    return;
  }

  if (any_contains(path, cred_files, sizeof(cred_files) / sizeof(cred_files[0]))) {
    mark_suspicious(p, "credential_store_or_dump_path", "credential_access");
  }
  if (any_contains(path, web_roots, sizeof(web_roots) / sizeof(web_roots[0]))) {
    mark_high(p, "web_root_file_activity", "web_root");
    if (any_ends(path, script_exts, sizeof(script_exts) / sizeof(script_exts[0]))) {
      mark_suspicious(p, "webshell_script_in_web_root", "webshell_candidate");
    }
  }
  if (any_contains(path, startup_dirs, sizeof(startup_dirs) / sizeof(startup_dirs[0]))) {
    mark_suspicious(p, "startup_or_scheduled_task_path", "persistence_path");
  }
  if (any_contains(path, service_driver_dirs, sizeof(service_driver_dirs) / sizeof(service_driver_dirs[0])) &&
      (any_ends(path, executable_exts, sizeof(executable_exts) / sizeof(executable_exts[0])) ||
       any_ends(path, script_exts, sizeof(script_exts) / sizeof(script_exts[0])) ||
       r->type == EDR_EVENT_FILE_CREATE || r->type == EDR_EVENT_FILE_WRITE ||
       r->type == EDR_EVENT_FILE_PERMISSION_CHANGE)) {
    mark_suspicious(p, "service_or_driver_path_modified", "service_driver_path");
  }
  if (any_contains(path, user_temp_dirs, sizeof(user_temp_dirs) / sizeof(user_temp_dirs[0]))) {
    if (any_ends(path, script_exts, sizeof(script_exts) / sizeof(script_exts[0]))) {
      mark_suspicious(p, "script_drop_in_user_temp_path", "script_temp_staging");
    } else if (any_ends(path, executable_exts, sizeof(executable_exts) / sizeof(executable_exts[0]))) {
      mark_suspicious(p, "executable_drop_in_user_temp_path", "executable_temp_staging");
    }
  }
  if (ransom_note_like_path(path) || has_ci_path(r->script_snippet, "ransom_counter=1") ||
      has_ci_path(r->script_snippet, "ransom_note_burst=1")) {
    mark_suspicious(p, "ransomware_note_or_file_burst", "ransomware_behavior");
  }
  if (has_ci_path(path, "\\users\\public\\") &&
      (any_ends(path, executable_exts, sizeof(executable_exts) / sizeof(executable_exts[0])) ||
       any_ends(path, script_exts, sizeof(script_exts) / sizeof(script_exts[0])))) {
    mark_suspicious(p, "public_directory_execution_artifact", "public_staging");
  }
  if (!p->high_value && any_contains(path, noisy_dirs, sizeof(noisy_dirs) / sizeof(noisy_dirs[0]))) {
    mark_noisy(p, "known_windows_noise_path", "noise_path");
  }
  if (!p->high_value && g_event_filter_cfg.temp_xml &&
      has_ci_path(path, "\\appdata\\local\\temp\\xml_file")) {
    mark_noisy(p, "temp_xml_low_value_file", "noise_temp_xml");
  }
  if (!p->high_value && g_event_filter_cfg.low_value_file_process &&
      (process_name_is(r, "cleanmgr.exe") || process_name_is(r, "taskmgr.exe") ||
       process_name_is(r, "wmiprvse.exe") || process_name_is(r, "trustedinstaller.exe") ||
       process_name_is(r, "tiworker.exe") || process_name_is(r, "searchindexer.exe") ||
       process_name_is(r, "searchprotocolhost.exe") ||
       process_name_is(r, "searchfilterhost.exe") ||
       process_name_is(r, "compattelrunner.exe") || process_name_is(r, "runtimebroker.exe") ||
       process_name_is(r, "backgroundtaskhost.exe") ||
       process_name_is(r, "microsoftedgeupdate.exe") ||
       process_name_is(r, "officeclicktorun.exe") || process_name_is(r, "msmpeng.exe") ||
       process_name_is(r, "nissrv.exe"))) {
    mark_noisy(p, "known_low_value_file_process", "noise_process");
  }
  if (!p->high_value && g_event_filter_cfg.low_value_file_suffix &&
      (has_ci_path(path, ":wofcompresseddata") || has_ci_path(path, ".js.map") ||
       has_ci_path(path, ".tmp") || has_ci_path(path, ".etl") || has_ci_path(path, ".blf") ||
       has_ci_path(path, ".regtrans-ms") || has_ci_path(path, ".cache") ||
       (has_ci_path(path, "\\appdata\\local\\temp\\") &&
        (has_ci_path(path, ".log") || has_ci_path(path, ".dat") ||
         has_ci_path(path, ".json") || has_ci_path(path, ".xml"))))) {
    mark_noisy(p, "known_low_value_file_suffix", "noise_suffix");
  }
}

static int reg_value_is(const EdrBehaviorRecord *r, const char *name) {
  return has_ci_path(r->reg_value_name, name) || has_ci_path(r->reg_value_data, name);
}

static void classify_registry(const EdrBehaviorRecord *r, EdrWindowsEventPolicy *p) {
  const char *key = r->reg_key_path;
  static const char *const noisy_keys[] = {
      "\\software\\classes\\local settings\\software\\microsoft\\windows\\shell\\bags",
      "\\software\\microsoft\\windows\\currentversion\\explorer\\",
      "\\software\\microsoft\\windows\\currentversion\\search\\",
      "\\software\\microsoft\\windows nt\\currentversion\\appcompatflags\\compatibility assistant\\store",
      "\\software\\microsoft\\windows\\currentversion\\internet settings\\connections",
  };

  if (!key || !key[0]) {
    return;
  }

  if (has_ci_path(key, "\\software\\microsoft\\windows\\currentversion\\run") ||
      has_ci_path(key, "\\software\\microsoft\\windows\\currentversion\\runonce") ||
      has_ci_path(key, "\\software\\wow6432node\\microsoft\\windows\\currentversion\\run")) {
    mark_suspicious(p, "autorun_registry_modified", "autorun_persistence");
  }
  if (has_ci_path(key, "\\system\\currentcontrolset\\services\\")) {
    mark_suspicious(p, "service_registry_modified", "service_persistence");
  }
  if (has_ci_path(key, "\\windows nt\\currentversion\\winlogon") &&
      (reg_value_is(r, "shell") || reg_value_is(r, "userinit") || reg_value_is(r, "notify"))) {
    mark_suspicious(p, "winlogon_persistence_modified", "winlogon_persistence");
  }
  if (has_ci_path(key, "\\image file execution options\\") ||
      has_ci_path(key, "\\silentprocessexit\\")) {
    mark_suspicious(p, "ifeo_debugger_persistence_modified", "ifeo_persistence");
  }
  if (has_ci_path(key, "\\windows nt\\currentversion\\windows") &&
      reg_value_is(r, "appinit_dlls")) {
    mark_suspicious(p, "appinit_dlls_modified", "appinit_persistence");
  }
  if (has_ci_path(key, "\\control\\lsa") || has_ci_path(key, "\\securitypackages") ||
      has_ci_path(key, "\\wdigest")) {
    mark_suspicious(p, "lsa_or_wdigest_modified", "credential_access");
  }
  if (has_ci_path(key, "\\windows defender") ||
      has_ci_path(key, "\\policies\\microsoft\\windows defender") ||
      has_ci_path(key, "\\security center")) {
    mark_suspicious(p, "security_product_policy_modified", "defense_evasion");
  }
  if (has_ci_path(key, "\\terminal server") && reg_value_is(r, "fdenytsconnections")) {
    mark_high(p, "rdp_exposure_policy_modified", "rdp_exposure");
  }
  if (has_ci_path(key, "\\firewallpolicy\\") || has_ci_path(key, "\\sharedaccess\\parameters\\firewallpolicy")) {
    mark_high(p, "firewall_policy_modified", "firewall_policy");
  }
  if (has_ci_path(key, "\\software\\microsoft\\office\\") &&
      (has_ci_path(key, "\\security") || reg_value_is(r, "vbawarnings") ||
       reg_value_is(r, "accessvbom"))) {
    mark_high(p, "office_macro_policy_modified", "office_macro_policy");
  }
  if (has_ci_path(key, "\\software\\microsoft\\windows\\currentversion\\policies\\system") &&
      (reg_value_is(r, "enablelua") || reg_value_is(r, "consentpromptbehavioradmin"))) {
    mark_high(p, "uac_policy_modified", "uac_policy");
  }
  if (!p->high_value && any_contains(key, noisy_keys, sizeof(noisy_keys) / sizeof(noisy_keys[0]))) {
    mark_noisy(p, "known_windows_registry_noise", "noise_registry");
  }
}

void edr_windows_event_policy_evaluate(const EdrBehaviorRecord *r,
                                       EdrWindowsEventPolicy *out) {
  if (!out) {
    return;
  }
  memset(out, 0, sizeof(*out));
  out->should_emit = 1u;
  out->should_persist = 1u;
  if (!r) {
    return;
  }
  if (!g_event_filter_cfg.enabled) {
    return;
  }
  if (is_file_event(r->type)) {
    out->applies = 1u;
    out->should_emit = 0u;
    out->should_persist = 0u;
    classify_file(r, out);
  } else if (is_registry_event(r->type)) {
    out->applies = 1u;
    out->should_emit = 0u;
    out->should_persist = 0u;
    classify_registry(r, out);
  } else {
    return;
  }

  if (!out->noisy && (r->priority == 0u || has_ci_path(r->detection_context, "\"confidence\":0.7") ||
      has_ci_path(r->detection_context, "\"confidence\":0.8") ||
      has_ci_path(r->detection_context, "\"confidence\":0.9") ||
      has_ci_path(r->detection_context, "\"confidence\":1"))) {
    out->should_emit = 1u;
    out->should_persist = 1u;
  }
  if (!out->reason[0]) {
    set_reason(out, out->noisy ? "ordinary_windows_noise" : "ordinary_windows_metadata_only");
  }
  if (!out->tags[0]) {
    add_tag(out, out->noisy ? "noise" : "metadata_only");
  }
}

void edr_windows_event_policy_apply(EdrBehaviorRecord *r) {
  EdrWindowsEventPolicy p;
  size_t n;
  if (!r) {
    return;
  }
  edr_windows_event_policy_evaluate(r, &p);
  if (!p.applies) {
    return;
  }
  if (p.suspicious && r->priority > 0u) {
    r->priority = 0u;
  } else if (p.high_value && r->priority > 1u) {
    r->priority = 1u;
  } else if (!p.high_value && r->priority > 0u && r->priority < 2u &&
             (is_file_event(r->type) || is_registry_event(r->type))) {
    r->priority = 2u;
  }
  n = strlen(r->script_snippet);
  if (n + 32u >= sizeof(r->script_snippet)) {
    return;
  }
  (void)snprintf(r->script_snippet + n, sizeof(r->script_snippet) - n,
                 "%swin_policy=%s win_policy_tags=%s",
                 n ? " " : "", p.reason, p.tags);
}

static void record_event_filter_decision(const EdrWindowsEventPolicy *p) {
  if (!p || !p->applies) {
    return;
  }
  g_event_filter_evaluated++;
  if (p->should_emit) {
    return;
  }
  g_event_filter_dropped++;
  if (has_ci_path(p->reason, "agent_internal_forensic")) {
    g_event_filter_agent_internal++;
  } else if (has_ci_path(p->reason, "known_low_value_file_process")) {
    g_event_filter_low_value_process++;
  } else if (has_ci_path(p->reason, "known_low_value_file_suffix")) {
    g_event_filter_low_value_suffix++;
  } else if (has_ci_path(p->reason, "temp_xml_low_value_file")) {
    g_event_filter_temp_xml++;
  }
}

int edr_windows_event_policy_should_emit(const EdrBehaviorRecord *r) {
  EdrWindowsEventPolicy p;
  edr_windows_event_policy_evaluate(r, &p);
  record_event_filter_decision(&p);
  return (!p.applies || p.should_emit) ? 1 : 0;
}

int edr_windows_event_policy_should_persist(const EdrBehaviorRecord *r) {
  EdrWindowsEventPolicy p;
  edr_windows_event_policy_evaluate(r, &p);
  return (!p.applies || p.should_persist) ? 1 : 0;
}
